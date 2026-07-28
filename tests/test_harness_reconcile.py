# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the harness no-loss reconcile accounting + the rate-SLO sample floor.

The reconcile invariant under test (both the load runner's and the connscale runner's copies): a
``timeouts``-counted message (in-flight at a connection close with no ACK seen) is UNCONFIRMED — the
frame may never have left the closed socket — so ``read >= sent - timeouts`` is the honest intake
bound, BUT the excusal is BOUNDED: past the bound the timeout count is a systemic no-ACK fault and
NOTHING is excused. With ``timeouts == 0`` (every healthy run) the check is exactly as strict as
``read >= sent``.

The systemic-fault threshold is ``max(unconfirmed_budget, sent // 2)``. It was ``unconfirmed_budget``
alone — "~one stranded in-flight frame per connection" — until that model was found to be wrong for
this sender: ``_inflight`` is an unbounded deque and open-loop sends are paced by the offered rate,
not by an ACK slot, so genuine teardown stranding scales with rate x ACK-latency rather than the
connection count. It false-failed a zero-loss run (14 stranded of 90 against a budget of 4) and red
the required windows-2025 leg.

That ``max()`` does NOT by itself keep ``read >= sent // 2`` required, though it was once documented
as doing so: the connection count is a FLOOR, not a ceiling, and every call site passes a connection
count (connscale and estate pass the step's ``count`` verbatim). Whenever the count exceeds half the
sends — the normal shape of a short, low-rate step, e.g. connscale-smoke's N=100 cell at ~105 sends
against a budget of ``max(100, 52) = 100`` — the bound degrades to ``read >= sent - connections``,
i.e. ``read >= 5``; and since nothing clamps the excusal to ``sent``, ``timeouts > sent`` degrades it
to ``read >= 0`` outright. So the guarantee is enforced SEPARATELY, as an unconditional intake floor
the excusal cannot lower: ``read >= sent // 2``, in all three copies, at every call site.

These tests pin every edge the tolerance could silently widen through (the harness has caught real
store bugs with this check — mf-load-test-harness — and that detection must survive the de-flake):
loss beyond the excusal, an over-budget flood (even with zero actual loss), the floor-binding regime
(``unconfirmed_budget >= sent``, which no test reached before — every case here used a budget of 2
against 36 sends, so ``sent // 2`` always won the max() and the floor arm was a surviving mutant),
and — mutation-tested — that the tolerance applies to INTAKE ONLY: the delivery/backlog cases use
shortfalls EXACTLY EQUAL to the timeout count, so leaking the subtraction into either check flips the
expected verdict.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from harness.load.connscale.runner import _reconcile as connscale_reconcile
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
# ~105 sends against 100 connections, so `max(unconfirmed_budget, sent // 2)` is max(100, 52) = 100 —
# the CONNECTION COUNT wins the max() and the excusal alone would allow read >= 5. Every other test
# in this module uses a budget of 2 or 4 against 36/90 sends, where sent // 2 always wins, so this
# constant is the only thing that exercises the floor arm at all.
_SMOKE_SENT = 105
_SMOKE_BUDGET = 100  # >= sent // 2 == 52: the regime where the budget stops bounding anything


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
    # NB the flood must now be a REAL one. The budget is max(connections, half the run), so the old
    # 6-of-36 scenario is ordinary teardown stranding under the current bound, not a fault — it would
    # pass here for the wrong reason. 30 of 36 unconfirmed is unambiguously a dead ACK path.
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
    # everything. Unbounded excusal would pass this as zero-loss; the budget fails it loudly.
    c = Counters(sent=90, acked=0, timeouts=90, sink_received=180)
    result = load_reconcile(
        c, _poller(_sample(read=90, written=180)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert not result.ok
    assert "stranding budget" in result.detail


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


def test_load_reconcile_excusal_is_capped_at_half_the_run() -> None:
    # Mutation pin on the NEW bound. Half the run is the most the reconcile will ever forgive, so
    # `read >= sent // 2` is always required and the intake bound can never go vacuous. Exactly at
    # the cap passes; one over flips to a systemic fault with nothing excused.
    at_cap = Counters(sent=90, acked=45, timeouts=45, sink_received=90)
    assert load_reconcile(
        at_cap, _poller(_sample(read=45, written=90)), 1.0, tolerance=0, unconfirmed_budget=4
    ).ok
    over = Counters(sent=90, acked=44, timeouts=46, sink_received=88)
    result = load_reconcile(
        over, _poller(_sample(read=44, written=88)), 1.0, tolerance=0, unconfirmed_budget=4
    )
    assert not result.ok
    assert "stranding budget" in result.detail


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


def test_load_reconcile_intake_floor_holds_when_the_budget_stops_bounding() -> None:
    # The load copy has the same hole: its budget is pool_size x targets, which for a small phase can
    # exceed half the sends just as the connscale connection count does. 105 sent, budget 100, read 5:
    # read_short is 0 under the excusal, so only the unconditional floor fails it.
    c = Counters(sent=_SMOKE_SENT, acked=5, timeouts=100, sink_received=5)
    result = load_reconcile(
        c, _poller(_sample(read=5, written=5)), 1.0, tolerance=0, unconfirmed_budget=_SMOKE_BUDGET
    )
    assert not result.ok, result.detail
    assert "intake floor 52" in result.detail
    assert "stranding budget" not in result.detail


def test_load_reconcile_teardown_stranding_still_passes_at_the_smoke_shape() -> None:
    # ~16% teardown stranding at the same budget-dominated shape, fanned out 2x, still reconciles
    # clean: 88 read >= the 52 floor and every non-stranded send was observed.
    c = Counters(sent=_SMOKE_SENT, acked=88, timeouts=17, sink_received=176)
    result = load_reconcile(
        c,
        _poller(_sample(read=88, written=176)),
        1.0,
        tolerance=0,
        unconfirmed_budget=_SMOKE_BUDGET,
    )
    assert result.ok, result.detail


def test_load_reconcile_tolerance_cannot_lower_the_intake_floor() -> None:
    # `tolerance` is an operator knob on the SHORTFALL; it is deliberately not applied to the floor,
    # so no combination of tolerance and excusal can make "at least half the run was ingested" false
    # while zero_loss reads green. A tolerance wide enough to cover the whole gap changes nothing.
    c = Counters(sent=_SMOKE_SENT, acked=5, timeouts=100, sink_received=5)
    result = load_reconcile(
        c, _poller(_sample(read=5, written=5)), 1.0, tolerance=100, unconfirmed_budget=_SMOKE_BUDGET
    )
    assert not result.ok, result.detail
    assert "intake floor 52" in result.detail


# --- estate _reconcile ---------------------------------------------------------------------------


def test_estate_reconcile_intake_floor_holds_when_the_budget_stops_bounding() -> None:
    # The third copy, kept in step: estate passes `profile.count` as the budget, so a step whose sends
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


# --- the three copies, kept in step --------------------------------------------------------------


def test_the_three_reconcile_copies_emit_the_same_over_budget_detail() -> None:
    # "The three copies are kept in step" is asserted in three code comments and the changelog, and
    # nothing enforced it — so it had already drifted: estate's copy omitted the
    # "(possible accepted-and-dropped); nothing excused" suffix its siblings carry, and the SAME
    # systemic fault therefore read differently to an operator depending on which runner caught it.
    c = Counters(sent=36, acked=6, timeouts=30, sink_received=36)
    full = _sample(read=36, written=36)
    details = {
        connscale_reconcile(c, _BASE, full, unconfirmed_budget=_BUDGET).detail,
        estate_reconcile(c, _BASE, full, unconfirmed_budget=_BUDGET).detail,
        load_reconcile(c, _poller(full), 1.0, tolerance=0, unconfirmed_budget=_BUDGET).detail,
    }
    assert len(details) == 1, details
    assert "systemic no-ACK fault (possible accepted-and-dropped); nothing excused" in details.pop()


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
