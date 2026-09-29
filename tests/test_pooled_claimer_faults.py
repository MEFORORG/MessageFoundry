# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a pooled claimer's death costs the rest of its stage (BACKLOG #2075, #2074).

Each test drives one :class:`StageDispatcher` against a small scripted store, so the claim results
and the moment of each injected fault are exact. A lane named ``HOLD`` keeps a slot consumed for
the whole test. That matters for #2075: ``_release_slot`` clamps at the configured maximum, so an
over-release is invisible unless some other lane is holding a slot when it happens."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from messagefoundry.pipeline import stage_dispatcher
from messagefoundry.pipeline.stage_dispatcher import (
    LaneItemResult,
    LaneResultKind,
    StageDispatcher,
    _LanePhase,
)
from messagefoundry.store import ClaimedHeads, Stage
from messagefoundry.store.store import OutboxItem
from tests.test_stage_dispatcher import RecordingAlertSink as _Alerts

_MAX = 4


async def _until(predicate: Any, timeout: float = 5.0) -> None:
    elapsed = 0.0
    while not predicate():
        await asyncio.sleep(0.01)
        elapsed += 0.01
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


class _ScriptStore:
    """Rows per lane, claimed one at a time and released back to the front, in order.

    ``rearm_once`` names lanes whose next claim comes back as a store-side rearm (T10), and
    ``fail_claims_with`` names a lane whose next claim raises, as a store fault would."""

    def __init__(self, rows: dict[str, list[str]]) -> None:
        self.pending: dict[str, list[str]] = {lane: list(ids) for lane, ids in rows.items()}
        self.inflight: set[str] = set()
        self.rearm_once: set[str] = set()
        self.fail_claims_with: set[str] = set()

    async def claim_fifo_heads(
        self, stage: str, lanes: Any, now: float | None = None, *, per_lane_limit: int = 1
    ) -> ClaimedHeads:
        lanes = list(lanes)
        failing = self.fail_claims_with & set(lanes)
        if failing:
            self.fail_claims_with -= failing
            raise RuntimeError("injected store fault on claim")
        by_lane: dict[str, list[OutboxItem]] = {}
        rearm: set[str] = set()
        for lane in lanes:
            if lane in self.rearm_once:
                self.rearm_once.discard(lane)
                rearm.add(lane)
                continue
            if self.pending.get(lane):
                row = self.pending[lane].pop(0)
                self.inflight.add(row)
                by_lane[lane] = [
                    OutboxItem(
                        id=row,
                        message_id=row,
                        channel_id=lane,
                        destination_name=None,
                        payload="x",
                        attempts=1,
                        stage=stage,
                    )
                ]
        return ClaimedHeads(by_lane=by_lane, rearm=frozenset(rearm))

    async def release_claimed(self, ids: Any, now: float | None = None) -> None:
        for row in reversed(list(ids)):
            if row in self.inflight:
                self.inflight.discard(row)
                self.pending.setdefault(row.rsplit("-", 1)[0], []).insert(0, row)

    async def list_fifo_lanes(self, *a: Any, **k: Any) -> list[tuple[str, float]]:
        return []


def _dispatcher(
    store: _ScriptStore,
    lanes: set[str],
    processed: list[str],
    gate: asyncio.Event,
    **kwargs: Any,
) -> StageDispatcher:
    async def process(lane: str, item: OutboxItem) -> LaneItemResult:
        if lane == "HOLD":
            await gate.wait()  # keeps HOLD's slot consumed until the test lets it go
        store.inflight.discard(item.id)
        processed.append(item.id)
        return LaneItemResult(LaneResultKind.RESOLVED)

    return StageDispatcher(
        Stage.INGRESS,
        store,  # type: ignore[arg-type]
        process_item=process,
        lane_provider=lambda: set(lanes),
        per_lane_limit=1,
        sweep_interval=10.0,
        max_processing_lanes=_MAX,
        **kwargs,
    )


def _fast_respawn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_BACKOFF_BASE_SECONDS", 0.001)
    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_BACKOFF_CAP_SECONDS", 0.004)


# --- BACKLOG #2075: a lane's slot is released exactly once, whatever the bookkeeping raises ---------


@pytest.mark.parametrize(
    ("helper", "route", "times"),
    [
        # The EMPTY claim books the drop and goes IDLE.
        ("_drop_lane_episode", "empty", 1),
        # A store-side rearm (T10) books the drop and goes straight back to READY.
        ("_drop_lane_episode", "rearm", 1),
        ("_to_ready", "rearm", 1),
        # The claim-error handler returns the chunk to READY; a raise there kills the claimer.
        ("_drop_lane_episode", "claim_error", 1),
        ("_to_ready", "claim_error", 1),
        # The second raise lands in the replacement's own adoption, so it dies too.
        ("_to_ready", "claim_error", 2),
    ],
)
async def test_a_raising_release_helper_frees_the_lanes_slot_exactly_once(
    helper: str, route: str, times: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fast_respawn(monkeypatch)
    gate = asyncio.Event()
    processed: list[str] = []
    store = _ScriptStore({"HOLD": ["HOLD-1"], "L": []})
    d = _dispatcher(store, {"HOLD"}, processed, gate)
    await d.start()
    try:
        await _until(lambda: d.processing_lanes == 1)  # HOLD now holds one slot for the whole test
        assert d.slots_free == _MAX - 1

        real = getattr(d, helper)
        fired = {"n": 0}

        def raising(*a: Any, **k: Any) -> Any:
            if fired["n"] < times:
                fired["n"] += 1
                raise RuntimeError(f"injected {helper} fault")
            return real(*a, **k)

        monkeypatch.setattr(d, helper, raising)
        if route == "rearm":
            store.rearm_once.add("L")
        elif route == "claim_error":
            store.fail_claims_with.add("L")
        d.mark_ready("L")

        await _until(
            lambda: fired["n"] == times and d.respawns == times and d.phase("L") is _LanePhase.IDLE
        )
        # The conservation law: every slot is free or held by the one live serializer. Before the
        # fix the replacement released L's slot a second time, so this read _MAX free beside HOLD.
        assert d.slots_free + d.processing_lanes == _MAX, (d.slots_free, d.processing_lanes)
        assert d.slots_free == _MAX - 1
        assert d.busy_violations == 0
    finally:
        gate.set()
        await d.stop()


# --- BACKLOG #2074: a lane whose dispatch always kills the claimer is STOPPED, not cycled ------------


def _kill_on(
    d: StageDispatcher, monkeypatch: pytest.MonkeyPatch, script: dict[str, list[bool]]
) -> dict[str, int]:
    """Make ``_spawn_serializer`` kill the claimer for a lane while its script says so. Each dispatch
    of a scripted lane pops one entry: True kills, False lets it through. An empty or absent script
    always lets it through. Returns the running death count per lane."""
    deaths: dict[str, int] = {}

    def spawn(lane: str, items: Any) -> None:
        steps = script.get(lane)
        if steps and steps.pop(0):
            deaths[lane] = deaths.get(lane, 0) + 1
            raise RuntimeError(f"injected claimer death dispatching {lane}")
        # The class attribute, not d's: a second call must wrap the real method, not the first patch.
        StageDispatcher._spawn_serializer(d, lane, items)

    monkeypatch.setattr(d, "_spawn_serializer", spawn)
    return deaths


async def test_a_lane_that_always_kills_its_claimer_is_stopped_and_its_siblings_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fast_respawn(monkeypatch)
    gate = asyncio.Event()
    gate.set()
    processed: list[str] = []
    store = _ScriptStore({"POISON": ["POISON-1"], "A": ["A-1", "A-2"], "B": ["B-1"]})
    alerts = _Alerts()
    d = _dispatcher(
        store,
        {"POISON", "A", "B"},
        processed,
        gate,
        alert_sink=alerts,
        infra_fault_stop_after=3,
    )
    deaths = _kill_on(d, monkeypatch, {"POISON": [True] * 1000})
    await d.start()
    try:
        await _until(
            lambda: (
                d.phase("POISON") is _LanePhase.STOPPED
                and sorted(processed) == ["A-1", "A-2", "B-1"]
            )
        )
        # Stopped at exactly the threshold, with one alert naming the lane.
        assert deaths == {"POISON": 3} and d.respawns == 3
        assert d.claimer_death_streak("POISON") == 0  # the stop spends the streak
        assert len(alerts.stopped) == 1 and alerts.stopped[0][0] == "POISON"
        assert "after 3 consecutive claimer death(s)" in alerts.stopped[0][1]
        # Its row was released, not lost and not dead-lettered: PENDING, at the head of its lane.
        assert store.pending["POISON"] == ["POISON-1"] and not store.inflight
        assert d.slots_free == _MAX and d.processing_lanes == 0 and d.busy_violations == 0

        # It stays stopped: a wake only marks it dirty, so no further claimer dies.
        d.mark_ready("POISON")
        await asyncio.sleep(0.1)
        assert deaths == {"POISON": 3} and d.phase("POISON") is _LanePhase.STOPPED

        # A re-arm (reload or recovery broadcast) resumes it with a fresh streak.
        _kill_on(d, monkeypatch, {})
        d.notify_work()
        await _until(lambda: "POISON-1" in processed)
        assert d.claimer_death_streak("POISON") == 0
    finally:
        await d.stop()


async def test_an_operator_resume_of_a_stopped_lane_starts_a_fresh_death_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stop, then the operator's pause and resume (the stop_outbound/start_outbound path). One
    more death must not re-stop the lane: the budget is fresh, as it is after notify_work."""
    _fast_respawn(monkeypatch)
    gate = asyncio.Event()
    gate.set()
    processed: list[str] = []
    store = _ScriptStore({"P": ["P-1"]})
    alerts = _Alerts()
    d = _dispatcher(store, {"P"}, processed, gate, alert_sink=alerts, infra_fault_stop_after=2)
    deaths = _kill_on(d, monkeypatch, {"P": [True, True, True, False]})
    await d.start()
    try:
        await _until(lambda: d.phase("P") is _LanePhase.STOPPED)
        assert deaths == {"P": 2} and len(alerts.stopped) == 1
        d.pause_lane("P")
        d.resume_lane("P")
        await _until(lambda: processed == ["P-1"])
        assert deaths == {"P": 3} and len(alerts.stopped) == 1  # the third death did not re-stop it
    finally:
        await d.stop()


async def test_a_dispatch_that_survives_resets_the_lanes_claimer_death_streak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Four deaths, never three in a row: the lane is never STOPPED, and both rows go through."""
    _fast_respawn(monkeypatch)
    gate = asyncio.Event()
    gate.set()
    processed: list[str] = []
    store = _ScriptStore({"P": ["P-1", "P-2"]})
    alerts = _Alerts()
    d = _dispatcher(store, {"P"}, processed, gate, alert_sink=alerts, infra_fault_stop_after=3)
    deaths = _kill_on(d, monkeypatch, {"P": [True, True, False, True, True, False]})
    await d.start()
    try:
        await _until(lambda: processed == ["P-1", "P-2"])
        assert deaths == {"P": 4}
        assert d.claimer_death_streak("P") == 0
        assert alerts.stopped == [] and d.phase("P") is not _LanePhase.STOPPED
    finally:
        await d.stop()


async def test_a_claimer_death_outside_any_lanes_dispatch_is_charged_to_no_lane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raise after the claim returned but before the dispatch loop names no lane, so no lane is
    STOPPED for it, however often it happens."""
    _fast_respawn(monkeypatch)
    gate = asyncio.Event()
    gate.set()
    store = _ScriptStore({"L": ["L-1"]})
    alerts = _Alerts()
    d = _dispatcher(store, {"L"}, [], gate, alert_sink=alerts, infra_fault_stop_after=2)
    d._claim_phase_timing = True

    def dying_record(*a: Any, **k: Any) -> None:
        raise RuntimeError("injected fault in the claim timing line")

    monkeypatch.setattr(d._claim_phase_stats, "record_claim", dying_record)
    await d.start()
    try:
        await _until(lambda: d.respawns >= 5)
        assert d.claimer_death_streak("L") == 0
        assert d.phase("L") is not _LanePhase.STOPPED and alerts.stopped == []
    finally:
        await d.stop()
