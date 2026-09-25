# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for the harness no-loss reconcile accounting + the rate-SLO sample floor.

**THE THREE COPIES NO LONGER SHARE ONE INVARIANT, SO READ THE HEADING ABOVE EACH SECTION.** Sections
1, 3 and 4 below cover the connscale and estate copies, which behave as this docstring's first half
describes. Section 2 covers the LOAD copy, which parted from them (BACKLOG #1866) — the paragraph
beginning "THE LOAD COPY NO LONGER CARRIES THAT FLOOR" is the one that governs it, and everything
before it is history for that copy rather than current behaviour.

The rig copies' invariant: a ``timeouts``-counted message (in-flight at a connection close with no
ACK seen) is UNCONFIRMED — the frame may never have left the closed socket — so
``read >= sent - timeouts`` is the honest intake bound, BUT the excusal is BOUNDED: past the bound
the timeout count is a systemic no-ACK fault and NOTHING is excused. With ``timeouts == 0`` (every
healthy run) the check is exactly as strict as ``read >= sent``.

Their systemic-fault threshold is ``max(unconfirmed_budget, 3 * sent // 4)``. It was
``unconfirmed_budget`` alone — "~one stranded in-flight frame per connection" — until that model was
found to be wrong for this sender: ``_inflight`` is an unbounded deque and open-loop sends are paced
by the offered rate, not by an ACK slot, so genuine teardown stranding scales with rate x
ACK-latency rather than the connection count. It false-failed a zero-loss run (14 stranded of 90
against a budget of 4) and red the required windows-2025 leg.

The fraction was then ``sent // 2``, sized against that 14/90 (~16%) worst-observed as "~3x the worst
seen". It was raised to three quarters after windows-2025 produced **46/90 (~51%)** on a run that lost
nothing and red ``main`` at ``9b03057f`` by ONE message over the budget of 45 — a threshold sitting on
the centre of the healthy distribution is a coin flip, not a detector (the same defect as the ubuntu
step cap in #104: a green 775s run against a 780s bound). Three quarters is ~1.5x the worst healthy
value on record while a dead ACK path strands ~100% and still blows it, and it agrees with the sibling
detector in ``tests/test_load_runner.py`` (``acked >= sent // 4``, i.e. tolerate up to 75% stranding),
which previously contradicted this budget.

That ``max()`` does NOT by itself bound the excusal: the connection count is a FLOOR, not a ceiling,
and every call site passes a connection count (connscale and estate pass the step's ``count``
verbatim). Whenever the count exceeds three quarters of the sends — the normal shape of a short,
low-rate step, e.g. connscale-smoke's N=100 cell at ~105 sends against a budget of
``max(100, 78) = 100`` — the bound degrades to ``read >= sent - connections``, i.e. ``read >= 5``;
and since nothing clamps the excusal to ``sent``, ``timeouts > sent`` degrades it to ``read >= 0``
outright. The connscale and estate copies answer that with an unconditional intake floor,
``read >= sent // 2``.

**THE LOAD COPY NO LONGER CARRIES THAT FLOOR, AND THE THREE COPIES NOW DIFFER — this module tests
them separately and the connscale/estate sections below still pin the floor.** With ``nak == 0``
every send resolves to acked or timeouts, so ``sent - timeouts == acked`` and the floor reduces to
``acked >= sent // 2``: a statement about how much of the OFFERED volume this host confirmed, not
about whether the engine lost anything. ``sent`` is set by the offered rate times the phase wall
clock, so the quantity moves with the runner's speed while the bound does not. It ejected two
unrelated pull requests from the MERGE QUEUE inside twenty minutes (windows-2025 ``merge_group`` runs
35656074083 and 35657866239), on heads that were green on the same leg as ``pull_request``.

What replaced it is not a looser number. ``read_short`` is already the exact intake bound and, with
``nak == 0``, IS ``acked - read`` — every accept-ACKed message must have an ingress row, an engine
invariant (``enqueue_ingress`` commits, then the AA is built) that fails at magnitude ONE at any host
speed. The floor added nothing there. What it gestured at — the budget-dominated vacuity — it could
not close either, because a dead ACK path's signature is a HIGH read with no ACKs, which clears a
floor on ``read`` by construction (``test_load_reconcile_dead_ack_path_with_a_high_read_is_caught``
is the control: those counters passed under the floor and fail now). The load copy closes it on the
signature instead: ingested messages plus not one reply, neither accept-ACK nor NAK.

These tests pin every edge the tolerance could silently widen through (the harness has caught real
store bugs with this check — mf-load-test-harness — and that detection must survive the de-flake):
loss beyond the excusal, the floor-binding regime (``unconfirmed_budget >= sent``, which no test
reached before — every case here used a budget of 2 against 36 sends, so ``sent // 2`` always won
the max() and the floor arm was a surviving mutant), and — mutation-tested — that the tolerance
applies to INTAKE ONLY: the delivery/backlog cases use shortfalls EXACTLY EQUAL to the timeout
count, so leaking the subtraction into either check flips the expected verdict.

An over-budget flood (even with zero actual loss) is pinned as a FAILURE for the rig copies and as a
reported-but-passing run for the load copy — the clearest single place the two now diverge, and
``test_the_load_copy_has_deliberately_parted_from_the_rig_copies`` asserts both halves on one set of
counters so the split cannot be mistaken for drift.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from harness.load.connscale.runner import _reconcile as connscale_reconcile
from harness.load.connscale.runner import _ReloadAccount
from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.estate.runner import _reconcile as estate_reconcile
from harness.load.metrics import Counters, Histogram
from harness.load.profile import Phase, Slo
from harness.load.report import (
    _RATE_SLO_MIN_SENT,
    PhaseRecord,
    _phase_slos,
)
from harness.load.report import (
    _reconcile as load_reconcile,
)


def _sample(*, read: int, written: int, pending: int = 0, inflight: int = 0) -> EngineSample:
    return EngineSample(
        elapsed_s=1.0,
        pending=pending,
        inflight=inflight,
        done=written,
        dead=0,
        read=read,
        written=written,
        out_dead=0,
        queue_depth=pending + inflight,
        in_pipeline=pending + inflight,
        db_size_bytes=0,
        journal_mode="wal",
        synchronous="normal",
        uptime_s=1.0,
    )


_BASE = _sample(read=0, written=0)
_BUDGET = 2  # a tiny run's connection count

# connscale-smoke's real shape at the N=100 cell: a fixed_aggregate step offering 35 msg/s for 3s is
# ~105 sends against 100 connections, so `max(unconfirmed_budget, 3 * sent // 4)` is max(100, 78) = 100 —
# the CONNECTION COUNT wins the max() and the excusal alone would allow read >= 5. Every other test
# in this module uses a budget of 2 or 4 against 36/90 sends, where the fraction always wins, so this
# constant is the only thing that exercises the floor arm at all.
_SMOKE_SENT = 105
_SMOKE_BUDGET = 100  # >= 3 * sent // 4 == 78: the regime where the budget stops bounding anything


# --- connscale _reconcile ------------------------------------------------------------------------


def test_connscale_reconcile_clean_run_is_exact() -> None:
    c = Counters(sent=36, acked=36, sink_received=36)
    assert connscale_reconcile(
        c, _BASE, _sample(read=36, written=36), unconfirmed_budget=_BUDGET
    ).ok
    # With timeouts == 0 the bound is exactly read >= sent: one short is loss, full stop.
    result = connscale_reconcile(c, _BASE, _sample(read=35, written=35), unconfirmed_budget=_BUDGET)
    assert not result.ok
    assert "lost 1 on intake" in result.detail


def test_connscale_reconcile_unconfirmed_timeout_is_not_loss() -> None:
    # The windows CI flake: the 36th send was in-flight at the connection close (timeouts=1), never
    # confirmed, never observed at intake. Unconfirmed != lost — and the detail says so explicitly.
    c = Counters(sent=36, acked=35, timeouts=1, sink_received=35)
    result = connscale_reconcile(c, _BASE, _sample(read=35, written=35), unconfirmed_budget=_BUDGET)
    assert result.ok, result.detail
    assert "unconfirmed" in result.detail


def test_connscale_reconcile_loss_beyond_unconfirmed_still_fails() -> None:
    # One unconfirmed timeout excuses exactly one absent message; a second absence is real loss.
    c = Counters(sent=36, acked=35, timeouts=1, sink_received=34)
    result = connscale_reconcile(c, _BASE, _sample(read=34, written=34), unconfirmed_budget=_BUDGET)
    assert not result.ok
    assert "lost 1 on intake" in result.detail


def test_connscale_reconcile_timeout_flood_fails_even_without_shortfall() -> None:
    # A systemic no-ACK fault: timeouts past the budget fail EVEN when every frame demonstrably
    # arrived (read == sent) — an engine that ingests but never ACKs is broken, and excusing an
    # unbounded count would let `timeouts == sent` degrade the intake bound to `read >= 0`.
    #
    # NB the flood must be a REAL one. The budget is max(connections, three quarters of the run), so
    # the old 6-of-36 scenario is ordinary teardown stranding under the current bound, not a fault —
    # it would pass here for the wrong reason. 30 of 36 unconfirmed is unambiguously a dead ACK path
    # (30 > max(2, 27)).
    c = Counters(sent=36, acked=6, timeouts=30, sink_received=36)
    result = connscale_reconcile(c, _BASE, _sample(read=36, written=36), unconfirmed_budget=_BUDGET)
    assert not result.ok
    assert "stranding budget" in result.detail
    # And with the flood masking a real shortfall, nothing is excused: the loss is reported too.
    c2 = Counters(sent=36, acked=6, timeouts=30, sink_received=6)
    result2 = connscale_reconcile(c2, _BASE, _sample(read=6, written=6), unconfirmed_budget=_BUDGET)
    assert not result2.ok
    assert "lost 30 on intake" in result2.detail


def test_connscale_reconcile_teardown_stranding_is_not_a_flood() -> None:
    # The other side of the same boundary: ordinary teardown stranding (6 of 36, ~17% — the shape the
    # old ~one-per-connection cap false-failed) reconciles clean when the engine read everything that
    # was not stranded. This is the case the previous test used to assert FAILED.
    c = Counters(sent=36, acked=30, timeouts=6, sink_received=30)
    result = connscale_reconcile(c, _BASE, _sample(read=30, written=30), unconfirmed_budget=_BUDGET)
    assert result.ok, result.detail


def test_connscale_reconcile_tolerance_is_intake_only() -> None:
    # Mutation pin: the delivery and backlog shortfalls are EXACTLY EQUAL to the timeout count, so
    # leaking the unconfirmed subtraction into either check would flip these verdicts to ok.
    c = Counters(sent=36, acked=35, timeouts=1, sink_received=34)
    result = connscale_reconcile(c, _BASE, _sample(read=35, written=35), unconfirmed_budget=_BUDGET)
    assert not result.ok  # deliver_short == 1 == timeouts: still a lost delivery
    assert "lost 1" in result.detail
    c2 = Counters(sent=36, acked=35, timeouts=1, sink_received=35)
    result2 = connscale_reconcile(
        c2, _BASE, _sample(read=35, written=35, pending=1), unconfirmed_budget=_BUDGET
    )
    assert not result2.ok  # backlog == 1 == timeouts: still not drained
    assert "not drained" in result2.detail


def test_connscale_reconcile_intake_floor_holds_when_the_budget_stops_bounding() -> None:
    # The floor-binding regime, at connscale-smoke's own N=100 shape: 105 sends, 100 connections, a
    # dead ACK path that also cost intake (read 5 of 105). The excusal ALONE passes this — 100
    # unconfirmed is not over max(100, 52), so read_short is 105 - 100 - 5 == 0 — which is exactly the
    # `read >= 5` vacuity the cap was supposed to prevent. The unconditional floor is what fails it.
    c = Counters(sent=_SMOKE_SENT, acked=5, timeouts=100, sink_received=5)
    result = connscale_reconcile(
        c, _BASE, _sample(read=5, written=5), unconfirmed_budget=_SMOKE_BUDGET
    )
    assert not result.ok, result.detail
    assert "intake floor 52" in result.detail
    # And it is genuinely the FLOOR doing the work here, not the stranding budget: 100 unconfirmed is
    # within max(100, 52), so the systemic-fault branch never fires.
    assert "stranding budget" not in result.detail


def test_connscale_reconcile_teardown_stranding_still_passes_at_the_smoke_shape() -> None:
    # The other side of the new floor, same 105-send / 100-connection shape: ordinary teardown
    # stranding (17 of 105, ~16% — the rate x ACK-latency weather PR #17 de-flaked for) still
    # reconciles clean, because the engine read every send that was not stranded and 88 >= 52. The
    # floor must not reintroduce the flake it was added alongside.
    c = Counters(sent=_SMOKE_SENT, acked=88, timeouts=17, sink_received=88)
    result = connscale_reconcile(
        c, _BASE, _sample(read=88, written=88), unconfirmed_budget=_SMOKE_BUDGET
    )
    assert result.ok, result.detail


def test_connscale_reconcile_floor_is_exactly_half_rounded_down() -> None:
    # Boundary pin on an ODD run size: the floor is sent // 2 (52 of 105), never ceil. Exactly at the
    # floor passes; one below fails. Pins the rounding so a later `-(-sent // 2)` "tidy-up" — which
    # would make the floor STRICTER than the documented `read >= sent // 2` — is caught here.
    at_floor = Counters(sent=_SMOKE_SENT, acked=52, timeouts=53, sink_received=52)
    assert connscale_reconcile(
        at_floor, _BASE, _sample(read=52, written=52), unconfirmed_budget=_SMOKE_BUDGET
    ).ok
    below = Counters(sent=_SMOKE_SENT, acked=51, timeouts=54, sink_received=51)
    result = connscale_reconcile(
        below, _BASE, _sample(read=51, written=51), unconfirmed_budget=_SMOKE_BUDGET
    )
    assert not result.ok
    assert "intake floor 52" in result.detail


def test_connscale_reconcile_more_timeouts_than_sends_cannot_go_vacuous() -> None:
    # `excused` is never clamped to `sent`, so timeouts > sent drives read_short NEGATIVE and the
    # intake bound to `read >= 0` — total vacuity, not mere degradation — whenever the budget also
    # covers it. The floor is the only thing standing between that state and a green zero-loss.
    c = Counters(sent=10, acked=0, timeouts=50, sink_received=0)
    result = connscale_reconcile(c, _BASE, _sample(read=0, written=0), unconfirmed_budget=100)
    assert not result.ok, result.detail
    assert "intake floor 5" in result.detail


# --- connscale _reconcile: the reload probe's own stranding (BACKLOG #1292) ---------------------
#
# The mid-hold reload probe closes every inbound connection. What it strands is the harness's doing,
# so the reconcile excuses it by COUNT (`_ReloadAccount.stranded`) and keeps its guards over every
# other send. These pin the three things that must still fail: stranding the reload did NOT cause, an
# accept-ACKed message with no row, and a reload after which the engine answered nothing.


def _reload(
    stranded: int, *, sent: int, acked: int, timeouts: int, not_reconnected: int = 0
) -> _ReloadAccount:
    """A reload account whose `after` snapshot holds the counters at the moment every connection was
    back. The helpers set no send in flight at that moment. The sender does not promise that, but a
    send in flight then was written on a socket opened after the reload, so its reply still counts
    as the engine answering after the reload (see `_ReloadAccount`)."""
    return _ReloadAccount(
        seconds=0.5,
        stranded=stranded,
        not_reconnected=not_reconnected,
        extra_hold_s=0.0,
        after=Counters(sent=sent, acked=acked, timeouts=timeouts),
    )


def test_connscale_reconcile_excuses_what_the_reload_probe_stranded() -> None:
    # 30 of 36 stranded by the reload, all before every connection came back; 6 sends after it, all
    # ACKed. The engine read 18: the 6 confirmed plus 12 stranded sends that committed before the
    # close. Nothing accepted is missing, so the step reconciles and SAYS what it excused.
    c = Counters(sent=36, acked=6, timeouts=30, sink_received=18)
    reload = _reload(30, sent=30, acked=0, timeouts=30)
    result = connscale_reconcile(
        c, _BASE, _sample(read=18, written=18), unconfirmed_budget=12, reload=reload
    )
    assert result.ok, result.detail
    assert "30 send(s) stranded by the reload probe" in result.detail


def test_connscale_reconcile_stranding_the_reload_did_not_cause_still_fails() -> None:
    # THE CONTROL for the test above: the SAME final counters with no reload account. 30 unconfirmed
    # of 36 is over the budget max(12, 27), so the step fails exactly as the CI steps of 2026-09-25
    # did. The excusal comes from the reload account and nowhere else.
    c = Counters(sent=36, acked=6, timeouts=30, sink_received=18)
    result = connscale_reconcile(c, _BASE, _sample(read=18, written=18), unconfirmed_budget=12)
    assert not result.ok
    assert "stranding budget" in result.detail
    # And a reload account that attributes only PART of the stranding leaves the rest budgeted: 10
    # stranded by the reload, 20 more unconfirmed out of a population of 26 is over max(12, 19).
    partial = _reload(10, sent=10, acked=0, timeouts=10)
    result2 = connscale_reconcile(
        c, _BASE, _sample(read=18, written=18), unconfirmed_budget=12, reload=partial
    )
    assert not result2.ok
    # The budget is named over the base it was computed on, 26 sends, so a reader can redo it.
    assert "(19 = max(connections, three quarters of the 26 send(s)" in result2.detail


def test_connscale_reconcile_an_absent_acked_message_fails_despite_the_reload_excusal() -> None:
    # PLANTED LOSS. Same shape as the passing test, but the stranded sends left no rows and one of the
    # 6 accept-ACKed sends has none either: read is 5 against 6 confirmed. The reload excusal forgives
    # the 30 stranded sends and nothing more, so the one accepted-and-absent message is reported.
    c = Counters(sent=36, acked=6, timeouts=30, sink_received=5)
    reload = _reload(30, sent=30, acked=0, timeouts=30)
    result = connscale_reconcile(
        c, _BASE, _sample(read=5, written=5), unconfirmed_budget=12, reload=reload
    )
    assert not result.ok
    assert "lost 1 on intake" in result.detail


def test_connscale_reconcile_a_reload_the_engine_never_answered_after_fails() -> None:
    # The excusal must not hide a reload that broke intake. 6 sends after the reload, no reply to any
    # of them. Every count arm passes here (the 6 fit the budget, read 18 clears the floor of 3), so
    # the reply signature is the only thing that fails it.
    c = Counters(sent=36, acked=0, timeouts=36, sink_received=18)
    reload = _reload(30, sent=30, acked=0, timeouts=30)
    result = connscale_reconcile(
        c, _BASE, _sample(read=18, written=18), unconfirmed_budget=12, reload=reload
    )
    assert not result.ok
    assert "drew no reply" in result.detail


def test_connscale_reconcile_no_traffic_after_the_reload_cannot_pass_on_the_excusal() -> None:
    # The CI shape of 2026-09-25 exactly, had the step offered nothing after the reload: 33 of 36
    # stranded and not one send after it, though every connection came back. Excusing the 33 alone
    # would leave 3 sends to judge, so "nothing was measured after the reload" fails the step
    # instead of passing it on trust. No other guard fires here: the reconnect one is quiet.
    c = Counters(sent=36, acked=3, timeouts=33, sink_received=15)
    reload = _reload(33, sent=36, acked=3, timeouts=33)
    result = connscale_reconcile(
        c, _BASE, _sample(read=15, written=15), unconfirmed_budget=12, reload=reload
    )
    assert not result.ok
    assert "nothing was sent after the reload probe" in result.detail
    assert "never came back" not in result.detail
    # With the connections down as well, both signatures are named.
    down = _reload(33, sent=36, acked=3, timeouts=33, not_reconnected=12)
    result2 = connscale_reconcile(
        c, _BASE, _sample(read=15, written=15), unconfirmed_budget=12, reload=down
    )
    assert "nothing was sent after the reload probe" in result2.detail
    assert "12 connection(s) never came back" in result2.detail


def test_connscale_reload_that_left_a_listener_down_fails_though_the_counts_pass() -> None:
    # 4 of 12 connections never came back. Sends routed to them were queued and never written, so
    # they are in no counter: the other 8 carried 6 answered sends and every count arm passes. Only
    # the reconnect signature can fail this, and it must.
    c = Counters(sent=36, acked=6, timeouts=30, sink_received=18)
    reload = _reload(30, sent=30, acked=0, timeouts=30, not_reconnected=4)
    result = connscale_reconcile(
        c, _BASE, _sample(read=18, written=18), unconfirmed_budget=12, reload=reload
    )
    assert not result.ok
    assert "4 connection(s) never came back" in result.detail


def test_connscale_reload_guards_leave_a_step_that_offered_nothing_alone() -> None:
    # A zero-rate lane sends nothing before or after the reload. There is no intake to measure, so
    # the reload guards do not fail it; the old reconcile passed it too.
    reload = _reload(0, sent=0, acked=0, timeouts=0)
    result = connscale_reconcile(
        Counters(), _BASE, _sample(read=0, written=0), unconfirmed_budget=12, reload=reload
    )
    assert result.ok, result.detail


def test_connscale_reconcile_a_reload_that_stranded_nothing_changes_nothing() -> None:
    # A quick reload strands nothing. The verdict and the text must then be exactly what they are with
    # no reload account at all, so the fast path's readings stay comparable.
    c = Counters(sent=36, acked=35, timeouts=1, sink_received=35)
    reload = _reload(0, sent=18, acked=18, timeouts=0)
    with_reload = connscale_reconcile(
        c, _BASE, _sample(read=35, written=35), unconfirmed_budget=_BUDGET, reload=reload
    )
    without = connscale_reconcile(
        c, _BASE, _sample(read=35, written=35), unconfirmed_budget=_BUDGET
    )
    assert with_reload == without


def test_connscale_reconcile_the_reload_excusal_is_clamped_to_the_unconfirmed_count() -> None:
    # A reload account claiming more stranding than there were unconfirmed sends cannot excuse a
    # confirmed one, and the report must not repeat the inflated count. `stranded` is clamped to
    # `timeouts`: the 1 absent ACKed message still shows, and the note says 6, not 50. Unclamped, the
    # verdict survives by arithmetic (the negative remainder cancels) but the note reads 50, which is
    # more sends than the step left unconfirmed.
    c = Counters(sent=36, acked=30, timeouts=6, sink_received=29)
    reload = _reload(50, sent=10, acked=4, timeouts=6)
    result = connscale_reconcile(
        c, _BASE, _sample(read=29, written=29), unconfirmed_budget=_BUDGET, reload=reload
    )
    assert not result.ok
    assert "lost 1 on intake" in result.detail
    assert "; 6 send(s) stranded by the reload probe" in result.detail


def test_connscale_reconcile_empty_run_clears_the_floor_trivially() -> None:
    # sent == 0 makes the floor 0, so a run that sent nothing is not failed BY the floor (it has
    # nothing to read). Guards against a `sent // 2` -> `max(1, ...)` style edit failing empty runs.
    assert connscale_reconcile(
        Counters(), _BASE, _sample(read=0, written=0), unconfirmed_budget=_SMOKE_BUDGET
    ).ok


# --- load runner _reconcile ----------------------------------------------------------------------


def _poller(final: EngineSample) -> EnginePoller:
    # A stub with just the two attributes _reconcile reads; cast once so call sites stay clean.
    return cast(EnginePoller, SimpleNamespace(baseline=_BASE, final=final))


def test_load_reconcile_clean_run_is_exact() -> None:
    c = Counters(sent=90, acked=90, sink_received=180)
    ok = load_reconcile(
        c, _poller(_sample(read=90, written=180)), 1.0, tolerance=0, unconfirmed_budget=4
    ).ok
    assert ok
    result = load_reconcile(
        c, _poller(_sample(read=89, written=178)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert not result.ok
    assert "lost 1 on intake" in result.detail


def test_load_reconcile_unconfirmed_timeout_is_not_loss() -> None:
    c = Counters(sent=90, acked=89, timeouts=1, sink_received=178)
    result = load_reconcile(
        c, _poller(_sample(read=89, written=178)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert result.ok, result.detail
    assert "unconfirmed" in result.detail


def test_load_reconcile_loss_beyond_unconfirmed_still_fails() -> None:
    c = Counters(sent=90, acked=89, timeouts=1, sink_received=176)
    result = load_reconcile(
        c, _poller(_sample(read=88, written=176)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert not result.ok
    assert "lost 1 on intake" in result.detail


def test_load_reconcile_timeout_flood_fails_even_without_shortfall() -> None:
    # The degenerate ACK-path regression: acked=0, timeouts=sent, but the engine ingested+delivered
    # everything. The excusal is unconditional, so `read_short` passes this — and it still fails,
    # now on the reply-path signature rather than on the stranding count. The budget note rides
    # along because the run IS heavily stranded; it is the "dead ACK path" clause that sets ok.
    c = Counters(sent=90, acked=0, timeouts=90, sink_received=180)
    result = load_reconcile(
        c, _poller(_sample(read=90, written=180)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert not result.ok
    assert "dead ACK path" in result.detail


def test_load_reconcile_ci_teardown_stranding_is_not_a_flood() -> None:
    # Regression for the red windows-2025 leg (2026-07-27): a demonstrably zero-loss run whose
    # teardown left 14 of 90 sends unconfirmed (~16%) against the old connection-count budget of 4.
    # The engine read every send that was not stranded (84 == 90 - 6 never-left-the-socket) and
    # delivered all of them twice (fan-out 2), so this MUST reconcile clean.
    c = Counters(sent=90, acked=76, timeouts=14, sink_received=168)
    result = load_reconcile(
        c, _poller(_sample(read=84, written=168)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert result.ok, result.detail


def test_load_reconcile_stranding_past_the_budget_is_reported_not_failed() -> None:
    # THE THIRD OFFERED-VOLUME DETECTOR, RETIRED. `timeouts > max(connections, 3 * sent // 4)` used
    # to cancel the whole excusal and fail the run as a systemic no-ACK fault. It is the same
    # mistake as the intake floor at a different threshold — a fraction of what the phase OFFERED —
    # and it is what would have ejected PR 1283 (79 timeouts of 90, against a budget of 67) on the
    # next merge-group run even after the floor came out.
    #
    # Both sides of the old cliff must now reconcile clean, because neither lost anything: every
    # message the engine replied to has a row. Past the budget the width is still NAMED, so a poorly
    # confirmed run stays visible to an operator; it just no longer decides the verdict.
    at_old_cap = Counters(sent=90, acked=23, timeouts=67, sink_received=90)
    at_cap_result = load_reconcile(
        at_old_cap, _poller(_sample(read=45, written=90)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert at_cap_result.ok, at_cap_result.detail
    # The ABSENCE at 67 is what keeps `3 * sent // 4` a contract now that it decides no verdict.
    # Without it, mutating the fraction to `sent // 2` (45) passes every other assertion here: both
    # cases stay ok and the 68 case still carries the note. This is the pin that the retired
    # cap-boundary mutation test used to provide.
    assert "exceed the stranding budget" not in at_cap_result.detail
    over = Counters(sent=90, acked=22, timeouts=68, sink_received=90)
    result = load_reconcile(
        over, _poller(_sample(read=45, written=90)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert result.ok, result.detail
    assert "exceed the stranding budget" in result.detail
    assert "not a loss verdict" in result.detail
    # Pin the CLEAN half of the note's conditional clause. Its sibling below pins the other half;
    # between them, inverting the condition flips both and neither can be a surviving mutant. Left
    # unpinned, the note would claim everything was accounted for on a run reporting a loss.
    assert "every message the engine replied to was accounted for" in result.detail


def test_load_reconcile_a_flood_still_cannot_mask_a_confirmed_loss() -> None:
    # THE CONTROL FOR THE TEST ABOVE, and the property the cancel-the-excusal cliff was protecting.
    # Same 68-timeout flood, one message apart: the engine replied to 22 and has only 21 rows. The
    # excusal is unconditional now, so this is the case where "nothing is excused" used to do the
    # work — and it still fails, because `read_short` is `acked + nak - read` and does not depend on
    # the timeout count at all. Magnitude ONE, under the widest flood the run can produce.
    c = Counters(sent=90, acked=22, timeouts=68, sink_received=42)
    result = load_reconcile(
        c, _poller(_sample(read=21, written=42)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert not result.ok, result.detail
    assert "lost 1 on intake" in result.detail
    # The LOSSY half of the note's conditional clause (see the sibling above). Printed
    # unconditionally, the note contradicted the shortfall clause in the same string on the same
    # line: "lost 1 on intake ... every message the engine replied to was accounted for".
    assert "a confirmed message is missing besides" in result.detail
    assert "every message the engine replied to was accounted for" not in result.detail


def test_load_reconcile_teardown_stranding_at_the_old_half_bound_passes() -> None:
    # THE REGRESSION PIN for the windows-2025 flake: the exact observed counters from `main` at
    # 9b03057f — 90 sent, 46 stranded at teardown, 52 read at intake, nothing lost downstream. Under
    # the old `sent // 2` budget this was one message over and failed as a "systemic no-ACK fault"
    # while claiming "lost 38 on intake" for a run that lost nothing. It must pass.
    observed = Counters(sent=90, acked=44, timeouts=46, sink_received=104)
    result = load_reconcile(
        observed, _poller(_sample(read=52, written=104)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert result.ok, result.detail
    # And the run is clean on the check that replaced the floor: 44 replied to, 52 rows, so every
    # message the engine answered has one. Asserted here so the pin survives the floor's retirement
    # rather than resting on the old `read >= sent // 2` reading it used to carry.
    assert result.engine_read >= observed.acked + observed.nak


def test_load_reconcile_loss_beyond_a_large_excusal_still_fails() -> None:
    # The widened bound must not blunt real detection: with 14 legitimately excused, the 15th absent
    # message is still confirmed-then-lost and still fails. This is the assertion that would break if
    # the cap were ever raised to "excuse everything".
    c = Counters(sent=90, acked=76, timeouts=14, sink_received=150)
    result = load_reconcile(
        c, _poller(_sample(read=75, written=150)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert not result.ok
    assert "lost 1 on intake" in result.detail


def test_load_reconcile_tolerance_is_intake_only() -> None:
    # Mutation pin (load copy): delivery and backlog shortfalls EXACTLY EQUAL to the timeout count
    # must fail — this copy had zero delivery-shortfall coverage anywhere in the suite before this
    # test, and a `backlog <= unconfirmed` mutant survived the first version of it.
    c = Counters(sent=90, acked=89, timeouts=1, sink_received=177)
    result = load_reconcile(
        c, _poller(_sample(read=89, written=178)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert not result.ok
    assert "sink_received 177 < engine_written 178" in result.detail
    c2 = Counters(sent=90, acked=89, timeouts=1, sink_received=178)
    result2 = load_reconcile(
        c2,
        _poller(_sample(read=89, written=178, pending=1)),
        1.0,
        tolerance=0,
        unconfirmed_budget=4,
    )
    assert not result2.ok  # backlog == 1 == timeouts: still not drained
    assert "not drained" in result2.detail


def test_load_reconcile_budget_dominated_run_is_judged_on_what_it_confirmed() -> None:
    # The budget-dominated regime, at connscale-smoke's shape: 105 sent, budget 100, 5 acked, 5 read.
    # The retired `read >= sent // 2` floor failed this as loss. It is NOT loss: the engine ACKed 5
    # and has 5 rows, so nothing it confirmed is missing, and the other 100 sends are unconfirmed —
    # frames the harness cannot prove left the socket, since `sent` is counted at write-buffer time.
    # This is the shape the ejecting merge-group runs produced, and failing it is the flake.
    # A throughput verdict on such a run belongs to the drain/rate SLOs, not to the loss reconcile.
    c = Counters(sent=_SMOKE_SENT, acked=5, timeouts=100, sink_received=5)
    result = load_reconcile(
        c, _poller(_sample(read=5, written=5)), 1.0, tolerance=0, unconfirmed_budget=_SMOKE_BUDGET
    )
    assert result.ok, result.detail


def test_load_reconcile_one_acked_message_without_a_row_still_fails() -> None:
    # THE CONTROL FOR THE CASE ABOVE, one message apart from it: the engine ACKed 6 and has only 5
    # rows. An accept-ACK is built only after `enqueue_ingress` commits, so an AA with no row is a
    # real defect — and it must fail at magnitude ONE even here, where the excusal is at its widest
    # (100 timeouts against a budget of 100) and the retired floor was already satisfied by read 5
    # ... it was not: the floor needed 52. That is the point. The floor could not distinguish these
    # two runs AT ALL; it failed both. `read_short` separates them on one message.
    c = Counters(sent=_SMOKE_SENT, acked=6, timeouts=99, sink_received=5)
    result = load_reconcile(
        c, _poller(_sample(read=5, written=5)), 1.0, tolerance=0, unconfirmed_budget=_SMOKE_BUDGET
    )
    assert not result.ok, result.detail
    assert "lost 1 on intake" in result.detail


def test_load_reconcile_dead_ack_path_with_a_high_read_is_caught() -> None:
    # THE HOLE THE RETIRED FLOOR LEFT OPEN, now closed. A dead ACK path in the budget-dominated
    # regime: the engine ingested and delivered EVERYTHING (105 read, 105 written, all received) and
    # returned not one reply. `read_short` is negative and a floor on `read` is cleared twice over
    # by 105 >= 52 — so the retired `read >= sent // 2` floor passed this run as zero-loss. The
    # signature fails it, and a NAK would clear it, because a NAK proves the reply path runs.
    #
    # The counters obey `sent == acked + nak + timeouts`, which the whole `read_short == acked + nak
    # - read` derivation rests on; an earlier draft was off by 5 and exercised this branch under a
    # state the production invariant forbids. `unconfirmed_budget` is set ABOVE the timeout count so
    # `heavily_stranded` cannot fire, which is what makes the absence assertion below meaningful:
    # the verdict is the signature's, with no note riding along to confuse the attribution.
    c = Counters(sent=_SMOKE_SENT, acked=0, timeouts=_SMOKE_SENT, sink_received=105)
    result = load_reconcile(
        c,
        _poller(_sample(read=105, written=105)),
        1.0,
        tolerance=0,
        unconfirmed_budget=200,
    )
    assert not result.ok, result.detail
    assert "dead ACK path" in result.detail
    assert "exceed the stranding budget" not in result.detail  # the budget is NOT what caught it


def test_load_reconcile_a_total_blackout_is_caught() -> None:
    # THE HOLE THE FIRST DRAFT OF THIS CHANGE OPENED, caught in review and closed here. The engine
    # ingested NOTHING, replied to nothing and delivered nothing. Every other arm passes it: the
    # excusal covers the whole run so `read_short` is 0, `deliver_short` is 0 - 0, and an empty
    # pipeline is a drained one. Gating the signature on `read > 0` — which reads as the natural
    # guard — is false in exactly this case, so it was the only thing between a total blackout and a
    # clean zero-loss verdict on the CI smoke gate. `sent > 0` is the correct guard.
    c = Counters(sent=100, acked=0, timeouts=100, sink_received=0)
    result = load_reconcile(
        c, _poller(_sample(read=0, written=0)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert not result.ok, result.detail
    assert "dead ACK path" in result.detail


def test_load_reconcile_a_run_that_sent_nothing_is_not_a_dead_ack_path() -> None:
    # The other side of the `sent > 0` guard: a run that offered nothing has no reply to be missing,
    # so it must not be failed for having none. Pins the guard against a `read >= 0`-style edit.
    c = Counters(sent=0, acked=0, timeouts=0, sink_received=0)
    result = load_reconcile(
        c, _poller(_sample(read=0, written=0)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert result.ok, result.detail


def test_load_reconcile_an_all_nak_run_is_not_a_dead_ack_path() -> None:
    # The discriminator inside the signature: a NAK IS a reply, so an engine rejecting every message
    # has a working ACK path and must not be reported as a dead one. (The run fails elsewhere — a
    # NAK rate SLO, and `max_nak_rate` deliberately has no sample floor — but not here, and not with
    # this detail.) Pins the `acked + nak == 0` form against a `counters.acked == 0` simplification.
    c = Counters(sent=90, acked=0, nak=90, sink_received=0)
    result = load_reconcile(
        c, _poller(_sample(read=90, written=0)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert result.ok, result.detail
    assert "dead ACK path" not in result.detail


def test_load_reconcile_merge_queue_ejection_counters_now_reconcile_clean() -> None:
    # THE TWO REGRESSION PINS for the merge-queue ejections this change repairs. Both are
    # windows-2025 `merge_group` runs whose pull-request heads were green on the same leg.
    #
    # READ THE RECONSTRUCTION RULE BEFORE TRUSTING THESE NUMBERS. Neither run reported a full
    # counter set, so `acked` (1233) and `read` (1283) are reconstructed. The first draft set
    # `acked == read` in both, which forces `read_short` to exactly 0 BY CONSTRUCTION — the test
    # would then assert the invariant on data built to satisfy it and could not fail for the reason
    # it names. Both are now reconstructed with MARGIN, at the ordinary teardown shape: the engine
    # commits a row and the ACK for it is stranded at the close, so `read` sits strictly ABOVE
    # `acked`. A mutation tightening the comparison to `read >= sent` fails these; the equal-valued
    # version passed it.
    #
    # Run 35656074083 (PR 1233): reported `engine_read 36 < intake floor 45`. Everything the engine
    # read was delivered twice (fan-out 2 over 36 read = 72) and every delivery arrived, so the run
    # lost nothing; only the offered-volume floor failed it. 30 acked of 36 read leaves 6 of margin.
    ejected_1233 = Counters(sent=90, acked=30, timeouts=60, sink_received=72)
    result = load_reconcile(
        ejected_1233, _poller(_sample(read=36, written=72)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert result.ok, result.detail
    assert result.engine_read > ejected_1233.acked  # the margin is real, not an equality artifact
    # Run 35657866239 (PR 1283): 90 sent, 11 acked, 79 timeouts — it fired the sibling detector in
    # tests/test_load_runner.py (`acked >= sent // 4`, i.e. 22) before reaching the reconcile, so its
    # read/written were never reported. Read 15 against 11 acked: 4 of margin. Note this also clears
    # the retired stranding budget, which 79 timeouts against max(4, 67) would have failed outright.
    ejected_1283 = Counters(sent=90, acked=11, timeouts=79, sink_received=30)
    result = load_reconcile(
        ejected_1283, _poller(_sample(read=15, written=30)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert result.ok, result.detail
    assert result.engine_read > ejected_1283.acked


def test_load_reconcile_teardown_stranding_still_passes_at_the_smoke_shape() -> None:
    # ~16% teardown stranding at the same budget-dominated shape, fanned out 2x, still reconciles
    # clean: every non-stranded send was observed at intake. (The "88 read >= the 52 floor" half of
    # this note went with the floor; the surviving half is the one that was ever load-bearing.)
    c = Counters(sent=_SMOKE_SENT, acked=88, timeouts=17, sink_received=176)
    result = load_reconcile(
        c,
        _poller(_sample(read=88, written=176)),
        1.0,
        tolerance=0,
        unconfirmed_budget=_SMOKE_BUDGET,
    )
    assert result.ok, result.detail


def test_load_reconcile_tolerance_cannot_excuse_a_dead_ack_path() -> None:
    # `tolerance` is an operator knob on the intake and delivery SHORTFALLS. It is deliberately not
    # wired into the reply-path signature, so no tolerance width makes a dead ACK path read green —
    # the property the retired floor's "the tolerance cannot lower this floor" clause protected,
    # carried over to the check that replaced it. A tolerance far wider than the whole run changes
    # nothing here. The counters obey `sent == acked + nak + timeouts` for the same reason the
    # sibling control does — a draft of this one was off by 5 and exercised the branch under a state
    # the sender cannot produce.
    c = Counters(sent=_SMOKE_SENT, acked=0, timeouts=_SMOKE_SENT, sink_received=105)
    result = load_reconcile(
        c,
        _poller(_sample(read=105, written=105)),
        1.0,
        tolerance=1000,
        unconfirmed_budget=_SMOKE_BUDGET,
    )
    assert not result.ok, result.detail
    assert "dead ACK path" in result.detail


# --- estate _reconcile ---------------------------------------------------------------------------


def test_estate_reconcile_intake_floor_holds_when_the_budget_stops_bounding() -> None:
    # The second RIG copy, still carrying the floor the load copy retired: estate passes
    # `profile.count` as the budget, so a step whose sends
    # are of the same order as its connection count lands in the same degraded regime. Before the
    # floor this returned ok=True — and (see below) said so in a detail claiming read >= sent.
    c = Counters(sent=_SMOKE_SENT, acked=5, timeouts=100, sink_received=5)
    result = estate_reconcile(
        c, _BASE, _sample(read=5, written=5), unconfirmed_budget=_SMOKE_BUDGET
    )
    assert not result.ok, result.detail
    assert "intake floor 52" in result.detail
    assert "stranding budget" not in result.detail


def test_estate_reconcile_teardown_stranding_still_passes_at_the_smoke_shape() -> None:
    c = Counters(sent=_SMOKE_SENT, acked=88, timeouts=17, sink_received=88)
    result = estate_reconcile(
        c, _BASE, _sample(read=88, written=88), unconfirmed_budget=_SMOKE_BUDGET
    )
    assert result.ok, result.detail


def test_estate_reconcile_excused_run_reports_the_gap_instead_of_claiming_read_ge_sent() -> None:
    # This copy had no honest-reporting branch, so a bounded-excused run printed the flat
    # "read>=sent, sink_received>=written, backlog drained" while read (88) was demonstrably below
    # sent (105) — a statement false on its own numbers, on the operator-facing no-loss line.
    c = Counters(sent=_SMOKE_SENT, acked=88, timeouts=17, sink_received=88)
    result = estate_reconcile(
        c, _BASE, _sample(read=88, written=88), unconfirmed_budget=_SMOKE_BUDGET
    )
    assert result.ok, result.detail
    assert "17 unconfirmed send(s)" in result.detail
    assert "read>=sent" not in result.detail


def test_estate_reconcile_clean_run_still_reports_the_flat_claim() -> None:
    # ...and when read really does cover sent, the flat claim is true and still emitted.
    c = Counters(sent=36, acked=36, sink_received=36)
    result = estate_reconcile(c, _BASE, _sample(read=36, written=36), unconfirmed_budget=_BUDGET)
    assert result.ok
    assert result.detail == "read>=sent, sink_received>=written, backlog drained"


# --- the copies, and where they deliberately part ------------------------------------------------


def test_the_two_rig_reconcile_copies_emit_the_same_over_budget_detail() -> None:
    # "The copies are kept in step" is asserted in code comments and the changelog, and nothing
    # enforced it — so it had already drifted: estate's copy omitted the
    # "(possible accepted-and-dropped); nothing excused" suffix its sibling carries, and the SAME
    # systemic fault therefore read differently to an operator depending on which runner caught it.
    #
    # THIS COVERED THREE COPIES AND NOW COVERS TWO. connscale and estate keep the offered-volume
    # detectors unchanged. This comment used to say both run on the benchmark rig and never on the
    # merge queue. That was false for connscale: tests/test_connscale_smoke.py runs it in the
    # required `test` matrix, and it ejected pull requests from the queue on 2026-09-25 (#1292).
    c = Counters(sent=36, acked=6, timeouts=30, sink_received=36)
    full = _sample(read=36, written=36)
    details = {
        connscale_reconcile(c, _BASE, full, unconfirmed_budget=_BUDGET).detail,
        estate_reconcile(c, _BASE, full, unconfirmed_budget=_BUDGET).detail,
    }
    assert len(details) == 1, details
    assert "systemic no-ACK fault (possible accepted-and-dropped); nothing excused" in details.pop()


def test_the_load_copy_has_deliberately_parted_from_the_rig_copies() -> None:
    # THE DIVERGENCE, PINNED, so it reads as a decision rather than as drift. On the same counters
    # the rig copies call a systemic fault, the load copy reports a poorly confirmed run and passes:
    # 30 unconfirmed of 36, and all 36 messages present and delivered, so nothing the engine replied
    # to was lost. Only the load copy was ejecting pull requests from the merge queue. Retiring the
    # rig copies' floor and budget is a separate question and their evidence would have to come
    # from the rig.
    #
    # THE CONNSCALE COPY IS STILL RED ON THE SAME WINDOWS-2025 LEG, VIA
    # tests/test_connscale_smoke.py::test_no_loss_reconciles_at_every_step, AND NOTHING HERE FIXES
    # THAT. Its reported failure is `engine_read 15 < confirmed sent 18` — the EXACT-shortfall arm,
    # which this change leaves alone in every copy — so it is a different defect wearing a similar
    # sentence: either rows genuinely absent, or an `engine_read` sample that read short, which is
    # the discrimination harness/load/connscale/intake_audit.py was built to make per message. Do
    # not read the load copy going green as that sibling being answered.
    #
    # ANSWERED FOR THE 2026-09-25 REDS, BY THE AUDIT (BACKLOG #1292). Both had no accept-ACKed send
    # missing from the store. They were stranding by the harness's own mid-hold reload probe, which
    # closes every connection. The connscale section above now pins how that is excused, and what
    # still fails: stranding the reload did not cause, an absent ACKed message, and no reply after it.
    c = Counters(sent=36, acked=6, timeouts=30, sink_received=36)
    full = _sample(read=36, written=36)
    assert not connscale_reconcile(c, _BASE, full, unconfirmed_budget=_BUDGET).ok
    load = load_reconcile(c, _poller(full), 1.0, tolerance=0, unconfirmed_budget=_BUDGET)
    assert load.ok, load.detail
    assert "not a loss verdict" in load.detail


# --- rate-SLO sample floor -----------------------------------------------------------------------


def _phase_record(*, sent: int, errors: int) -> PhaseRecord:
    return PhaseRecord(
        phase=Phase(name="steady", kind="sustained", loop="open", duration_s=1.0),
        start=Counters(),
        end=Counters(sent=sent, acked=sent - errors, errors=errors),
        ack=Histogram(),
        e2e=Histogram(),
        wall_seconds=1.0,
    )


def test_rate_slo_floor_is_pinned() -> None:
    # The shipped small-phase profiles (smoke at ~100 msgs) sit just below this floor, and the real
    # profiles (thousands per phase) sit above it. Raising the constant would silently disable the
    # error-rate gate for real profiles — anyone changing it must retune it against the shipped
    # profiles and update this pin deliberately.
    assert _RATE_SLO_MIN_SENT == 200


def test_error_rate_slo_not_emitted_below_sample_floor() -> None:
    # ~90-message CI smoke phase: one transport blip is >1%, so any sane threshold gates on runner
    # weather, not behavior. Below the floor the check must not be emitted at all (a mass timeout
    # flood there is still caught by the reconcile's unconfirmed-send budget).
    slos = _phase_slos(_phase_record(sent=199, errors=5), Slo(max_error_rate=0.05))
    assert not [c for c in slos if c.name.endswith("max_error_rate")]


def test_error_rate_slo_enforced_at_volume() -> None:
    # At the floor (literal — NOT derived from the constant, so inflating the constant fails here
    # via the pin above) the gate stays live and still fails on a genuine error flood.
    slos = _phase_slos(_phase_record(sent=200, errors=20), Slo(max_error_rate=0.05))
    checks = [c for c in slos if c.name.endswith("max_error_rate")]
    assert len(checks) == 1
    assert not checks[0].ok
