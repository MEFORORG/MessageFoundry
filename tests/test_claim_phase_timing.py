# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Bench-gated CLAIM phase timing (``ClaimPhaseTiming``) — the phase PR #842's timer could not see.

#842 timed ``send_ack`` + ``mark_done`` on the premise that the per-delivery wall "is either" one or
the other. The 2026-07-09 rig ladder falsified it: those two accounted for 9-18 ms of a 62-190 ms
per-lane cycle. The residual is the CLAIM round-trip, which sits outside both timed regions. These
tests pin the new accumulator, the two claim call sites (pooled + per_lane), the default-OFF
byte-identity, the PHI rule (counts only — never a lane name), and the ONE regression that would
silently corrupt the rig's numbers: the harness's ``_PHASE_RE`` must not match the new claim line.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from messagefoundry.pipeline.phase_timing import (
    DELIVERY_PHASE_TIMING_ENV,
    ClaimPhaseTiming,
    DeliveryPhaseTiming,
    delivery_phase_timing_enabled,
)
from messagefoundry.pipeline.stage_dispatcher import (
    LaneItemResult,
    LaneResultKind,
    StageDispatcher,
)
from messagefoundry.store import ClaimedHeads, OutboxItem, Stage

_DISPATCHER_LOGGER = "messagefoundry.pipeline.stage_dispatcher"
_PHASE_TIMING_LOGGER = "messagefoundry.pipeline.phase_timing"


# --- accumulator --------------------------------------------------------------------------------


def test_claim_accumulator_bounded_aggregates_and_ratios() -> None:
    acc = ClaimPhaseTiming()
    acc.record_claim(10_000_000, lanes=8, rows=8)  # 10 ms
    acc.record_claim(30_000_000, lanes=4, rows=0)  # 30 ms, empty
    assert acc.claim.count == 2
    assert acc.claim.sum_ns == 40_000_000
    assert acc.claim.max_ns == 30_000_000
    assert acc.claim.mean_ms() == pytest.approx(20.0)
    assert acc.claim.max_ms() == pytest.approx(30.0)
    assert acc.lanes_offered == 12
    assert acc.rows_returned == 8
    assert acc.empty_claims == 1
    assert acc.rearm_lanes == 0


def test_rearm_only_claim_is_work_not_empty_overhead() -> None:
    """A claim that returns no rows but REARMED lanes consumed heads in place (H2 skip-and-complete).
    Booking that as pure overhead would invert the churn metric during a dedup/failover pass."""
    acc = ClaimPhaseTiming()
    acc.record_claim(5_000_000, lanes=4, rows=0, rearm=4)  # H2 completed every head in place
    acc.record_claim(5_000_000, lanes=4, rows=0, rearm=0)  # a genuinely empty poll
    assert acc.rearm_lanes == 4
    assert acc.empty_claims == 1  # only the second one
    assert acc.rows_returned == 0


def test_claim_accumulator_emits_then_resets_then_throttles(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger=_PHASE_TIMING_LOGGER)
    acc = ClaimPhaseTiming()  # _last_emit starts at 0.0 -> the first maybe_emit always emits
    acc.record_claim(5_000_000, lanes=8, rows=8)
    acc.maybe_emit(stage="outbound", claimers=1)

    lines = [m for m in caplog.messages if "claim phase timing" in m]
    assert len(lines) == 1
    assert "stage=outbound" in lines[0]
    assert "claim n=1" in lines[0]
    assert "lanes/claim=8.00" in lines[0]
    assert "rows/claim=8.00" in lines[0]
    assert "rearm=0" in lines[0]
    assert "claimers=1" in lines[0]
    # The window reset after emitting.
    assert acc.claim.count == 0
    assert acc.lanes_offered == 0
    assert acc.rows_returned == 0
    assert acc.empty_claims == 0

    # Immediately re-recording does NOT emit again (5 s throttle).
    acc.record_claim(5_000_000, lanes=8, rows=8)
    acc.maybe_emit(stage="outbound", claimers=1)
    assert len([m for m in caplog.messages if "claim phase timing" in m]) == 1


def test_claim_accumulator_emit_on_zero_claims_does_not_divide_by_zero(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """maybe_emit before any record_claim must not raise — it runs inside the claimer loop, and a
    ZeroDivisionError there would kill the stage's only claimer."""
    caplog.set_level(logging.INFO, logger=_PHASE_TIMING_LOGGER)
    acc = ClaimPhaseTiming()
    acc.maybe_emit(stage="outbound", claimers=1)
    lines = [m for m in caplog.messages if "claim phase timing" in m]
    assert len(lines) == 1
    assert "claim n=0" in lines[0]
    assert "lanes/claim=0.00" in lines[0]


def test_claim_accumulator_logger_is_injectable(caplog: pytest.LogCaptureFixture) -> None:
    """The dispatcher/runner inject their own module logger so the emitted line's logger NAME stays
    where the rig's node-log capture expects it, despite the class living in phase_timing."""
    caplog.set_level(logging.INFO)
    acc = ClaimPhaseTiming(logger=logging.getLogger(_DISPATCHER_LOGGER))
    acc.record_claim(1_000_000, lanes=1, rows=1)
    acc.maybe_emit(stage="outbound", claimers=1)
    rec = [r for r in caplog.records if "claim phase timing" in r.getMessage()]
    assert len(rec) == 1
    assert rec[0].name == _DISPATCHER_LOGGER


def test_delivery_accumulator_logger_defaults_to_phase_timing_module(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    DeliveryPhaseTiming().maybe_emit(stage="outbound")
    rec = [r for r in caplog.records if "delivery phase timing" in r.getMessage()]
    assert len(rec) == 1
    assert rec[0].name == _PHASE_TIMING_LOGGER


def test_claim_line_never_contains_a_lane_name(caplog: pytest.LogCaptureFixture) -> None:
    """PHI rule: an outbound lane IS a destination_name. The claim line carries counts + ratios only —
    a lane name must never reach the log, no matter how many lanes were offered."""
    caplog.set_level(logging.INFO, logger=_PHASE_TIMING_LOGGER)
    acc = ClaimPhaseTiming()
    acc.record_claim(1_000_000, lanes=3, rows=2)
    acc.maybe_emit(stage="outbound", claimers=2)
    line = next(m for m in caplog.messages if "claim phase timing" in m)
    for secret in ("OB_ACME_ADT", "acme", "MRN", "destination"):
        assert secret not in line


# --- the regression that would silently corrupt the rig's numbers --------------------------------


def test_harness_phase_regex_does_not_false_match_the_claim_line() -> None:
    """``harness/load/shardcert_ladder._PHASE_RE`` aggregates the per-shard node logs into the ladder's
    send_ack/mark_done split. If the NEW claim line matched it, every rig rung's phase timing would be
    silently polluted. It must match the delivery line and ONLY the delivery line."""
    from harness.load.shardcert_ladder import _PHASE_RE

    delivery = (
        "delivery phase timing (stage=outbound): send_ack n=12 mean=0.60ms max=24.42ms "
        "| mark_done n=12 mean=16.06ms max=126.73ms"
    )
    claim = (
        "claim phase timing (stage=outbound): claim n=12 mean=62.20ms max=190.10ms "
        "| lanes/claim=8.00 rows/claim=8.00 rearm=0 empty=0 claimers=1"
    )
    assert _PHASE_RE.search(delivery) is not None
    assert _PHASE_RE.search(claim) is None
    # And the delivery line still parses to the same six groups #842 shipped.
    assert _PHASE_RE.search(delivery).groups() == (  # type: ignore[union-attr]
        "12",
        "0.60",
        "24.42",
        "12",
        "16.06",
        "126.73",
    )


# --- the lever -----------------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "YES", "on"])
def test_lever_truthy(monkeypatch: pytest.MonkeyPatch, val: str) -> None:
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, val)
    assert delivery_phase_timing_enabled() is True


def test_lever_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DELIVERY_PHASE_TIMING_ENV, raising=False)
    assert delivery_phase_timing_enabled() is False


# --- pooled claim site (StageDispatcher) ---------------------------------------------------------


class _FakeStore:
    """Minimal QueueStore surface the dispatcher touches on the claim path. Returns EMPTY claims, so
    a lane is offered and re-readied without needing real rows — enough to exercise the claim timer.

    ``list_fifo_lanes`` returns nothing: ``start()`` runs an immediate sweep, and an empty sweep keeps
    the test driving lanes through ``mark_ready`` alone (the sweep interval is set absurdly high)."""

    def __init__(self) -> None:
        self.claim_calls = 0

    async def claim_fifo_heads(
        self, stage: str, lanes: list[str], *, now: float | None = None, per_lane_limit: int = 1
    ) -> ClaimedHeads:
        self.claim_calls += 1
        await asyncio.sleep(0)  # a real store awaits; keep the suspension point honest
        return ClaimedHeads(by_lane={}, rearm=frozenset())

    async def list_fifo_lanes(
        self,
        stage: str,
        now: float | None = None,
        *,
        limit: int = 4096,
        after: str | None = None,
    ) -> list[tuple[str, float]]:
        return []


async def _noop_process(lane: str, item: OutboxItem) -> LaneItemResult:  # pragma: no cover
    return LaneItemResult(kind=LaneResultKind.RESOLVED)


def _dispatcher(store: Any, lanes: set[str], *, claimers: int) -> StageDispatcher:
    return StageDispatcher(
        Stage.OUTBOUND,
        store,
        process_item=_noop_process,
        lane_provider=lambda: set(lanes),
        per_lane_limit=1,  # hard-1, as OUTBOUND forces
        claimers_per_stage=claimers,
        sweep_interval=10_000.0,  # never sweep during the test
    )


async def _drive_one_claim(disp: StageDispatcher, store: _FakeStore, lanes: set[str]) -> None:
    await disp.start()
    try:
        for lane in lanes:
            disp.mark_ready(lane)
        for _ in range(200):
            if store.claim_calls >= 1:
                return
            await asyncio.sleep(0.005)
        raise AssertionError("claimer never issued a claim")
    finally:
        await disp.stop()


@pytest.mark.asyncio
async def test_pooled_claim_emits_timing_when_lever_on(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")  # read at CONSTRUCTION — set it first
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store, lanes = _FakeStore(), {"d0", "d1", "d2"}
    disp = _dispatcher(store, lanes, claimers=1)
    assert disp._claim_phase_timing is True
    await _drive_one_claim(disp, store, lanes)

    lines = [m for m in caplog.messages if "claim phase timing" in m]
    assert lines, "lever ON must emit a claim phase timing line"
    assert "stage=outbound" in lines[0]
    assert "claimers=1" in lines[0]
    # Empty claims still cost a full round-trip (and the tempdb churn) — they must be counted.
    # The fake store rearms nothing, so this claim IS pure overhead.
    assert "empty=1" in lines[0]
    assert "rearm=0" in lines[0]
    assert "rows/claim=0.00" in lines[0]


@pytest.mark.asyncio
async def test_pooled_claim_silent_and_untimed_when_lever_off(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Default-OFF must be byte-identical: no perf_counter, no record, no log line."""
    monkeypatch.delenv(DELIVERY_PHASE_TIMING_ENV, raising=False)
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store, lanes = _FakeStore(), {"d0"}
    disp = _dispatcher(store, lanes, claimers=1)
    assert disp._claim_phase_timing is False
    await _drive_one_claim(disp, store, lanes)

    assert not [m for m in caplog.messages if "claim phase timing" in m]
    assert disp._claim_phase_stats.claim.count == 0


@pytest.mark.asyncio
async def test_pooled_claim_reports_configured_claimer_count(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The emitted ``claimers=K`` is what makes the pooled re-feed bound (K x rows/claim / T_claim)
    readable straight off the node log — a K sweep is unreadable without it."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")
    caplog.set_level(logging.INFO, logger=_DISPATCHER_LOGGER)
    store, lanes = _FakeStore(), {"d0", "d1", "d2", "d3"}
    disp = _dispatcher(store, lanes, claimers=4)
    await _drive_one_claim(disp, store, lanes)

    lines = [m for m in caplog.messages if "claim phase timing" in m]
    assert lines
    assert "claimers=4" in lines[0]


@pytest.mark.asyncio
async def test_claim_error_does_not_record_timing_or_kill_the_claimer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failing claim takes the backoff path and returns early, so no timing is recorded. The loop
    must survive — a raise inside the timer would take the stage's claimer down with it."""
    monkeypatch.setenv(DELIVERY_PHASE_TIMING_ENV, "1")

    class _BoomStore(_FakeStore):
        async def claim_fifo_heads(
            self, stage: str, lanes: list[str], *, now: float | None = None, per_lane_limit: int = 1
        ) -> ClaimedHeads:
            self.claim_calls += 1
            raise RuntimeError("store down")

    store = _BoomStore()
    disp = _dispatcher(store, {"d0"}, claimers=1)
    await disp.start()
    try:
        disp.mark_ready("d0")
        for _ in range(200):
            if store.claim_calls >= 1:
                break
            await asyncio.sleep(0.005)
        assert store.claim_calls >= 1
        assert disp._claim_phase_stats.claim.count == 0  # failed claims are not timed
    finally:
        await disp.stop()
