# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the harness no-loss reconcile accounting + the rate-SLO sample floor.

The reconcile invariant under test (both the load runner's and the connscale runner's copies): a
``timeouts``-counted message (in-flight at a connection close with no ACK seen) is UNCONFIRMED — the
frame may never have left the closed socket — so ``read >= sent - timeouts`` is the honest intake
bound, BUT the excusal is bounded by ``unconfirmed_budget`` (~one stranded in-flight per connection):
past it the timeout count is a systemic no-ACK fault and NOTHING is excused. With ``timeouts == 0``
(every healthy run) the check is exactly as strict as ``read >= sent``.

These tests pin every edge the tolerance could silently widen through (the harness has caught real
store bugs with this check — mf-load-test-harness — and that detection must survive the de-flake):
loss beyond the excusal, an over-budget flood (even with zero actual loss), and — mutation-tested —
that the tolerance applies to INTAKE ONLY: the delivery/backlog cases use shortfalls EXACTLY EQUAL to
the timeout count, so leaking the subtraction into either check flips the expected verdict.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from harness.load.connscale.runner import _reconcile as connscale_reconcile
from harness.load.enginepoll import EnginePoller, EngineSample
from harness.load.metrics import Counters, Histogram
from harness.load.profile import Phase, Slo
from harness.load.report import (
    _RATE_SLO_MIN_SENT,
    PhaseRecord,
    _phase_slos,
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
    c = Counters(sent=36, acked=30, timeouts=6, sink_received=36)
    result = connscale_reconcile(c, _BASE, _sample(read=36, written=36), unconfirmed_budget=_BUDGET)
    assert not result.ok
    assert "stranding budget" in result.detail
    # And with the flood masking a real shortfall, nothing is excused: the loss is reported too.
    c2 = Counters(sent=36, acked=30, timeouts=6, sink_received=30)
    result2 = connscale_reconcile(
        c2, _BASE, _sample(read=30, written=30), unconfirmed_budget=_BUDGET
    )
    assert not result2.ok
    assert "lost 6 on intake" in result2.detail


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
