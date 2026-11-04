# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A worker or serializer killed by a ``BaseException`` mid-handoff no longer strands its row
(BACKLOG #4607, the open remainder of #1611).

The worker loops and the pooled serializer catch ``Exception`` only, so a ``BaseException`` that
is not one kills the task with its claimed row INFLIGHT. Before #4607 a per-lane worker's
replacement then drained the row's successors past it, and a pooled serializer was not replaced at
all: its lane stayed PROCESSING until a restart. Each test kills the task while a SECOND message is
already pending behind the first on the same lane, so a replacement that claimed before re-pending
the first would deliver the second first, and asserts delivery order, nothing left in flight, and
that no restart was involved."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.pipeline import stage_dispatcher, wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage
from tests.test_task_resilience import (
    _control_ids,
    _hl7,
    _inflight_rows,
    _pending_at,
    _start_runner,
    _until,
    _until_async,
    _until_delivered,
)


class _Kill(BaseException):
    """Not an ``Exception``, so no worker's ``except Exception`` arm catches it."""


class _Killer:
    """Wrap one handoff: the first ``kills`` calls carrying message A block on ``gate`` and then
    raise :class:`_Kill`; every other call goes through. Blocking first is what lets the test queue
    message B behind A before A's worker dies."""

    def __init__(self, real: Callable[..., Awaitable[Any]], marker: str, kills: int = 1) -> None:
        self.real = real
        self.marker = marker
        self.kills = kills
        self.fired = 0
        self.reached = asyncio.Event()
        self.gate = asyncio.Event()

    def carries_a(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> bool:
        return self.marker in repr(args) + repr(kwargs)

    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if self.fired < self.kills and self.carries_a(args, kwargs):
            self.fired += 1
            self.reached.set()
            await self.gate.wait()
            raise _Kill("injected kill")  # one message: a changed cause is never held back
        return await self.real(*args, **kwargs)


def _shorten_backoffs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only to keep the tests fast: the re-pend dates the row one backoff ahead."""
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.05)
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 0.05)
    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_BACKOFF_BASE_SECONDS", 0.05)


# (worker kind, the runner dict holding it, its key, the stage B must be pending at, the site).
_PER_LANE_SITES = [
    ("router", "_router_workers", "IB", Stage.INGRESS, "route_handoff"),
    ("transform", "_transform_workers", "IB", Stage.ROUTED, "transform_handoff"),
    ("delivery", "_workers", "OB", Stage.OUTBOUND, "send"),
]


def _install_killer(
    store: MessageStore,
    collector: Any,
    site: str,
    monkeypatch: pytest.MonkeyPatch,
    kills: int,
) -> _Killer:
    # Every handoff carries the payload (route_handoff its handlers' copies, transform_handoff its
    # deliveries, send the frame itself), and only A's carries A's control id.
    target = collector if site == "send" else store
    killer = _Killer(getattr(target, site), "M4607A", kills)
    monkeypatch.setattr(target, site, killer)
    return killer


async def _queue_a_then_b(
    runner: RegistryRunner, store: MessageStore, killer: _Killer, stage: Stage
) -> None:
    """Ingest A, hold it at the kill site, ingest B, and wait until B is pending on A's lane."""
    ib = runner.registry.inbound["IB"]
    await runner._handle_inbound(ib, _hl7("M4607A"))
    await asyncio.wait_for(killer.reached.wait(), timeout=5.0)
    await runner._handle_inbound(ib, _hl7("M4607B"))

    async def _b_waiting() -> bool:
        return await _pending_at(store, stage) >= 1

    await _until_async(_b_waiting, timeout=5.0)


@pytest.mark.parametrize(("kind", "attr", "key", "stage", "site"), _PER_LANE_SITES)
async def test_a_per_lane_worker_killed_mid_handoff_is_replaced_and_its_row_is_not_overtaken(
    kind: str,
    attr: str,
    key: str,
    stage: Stage,
    site: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Closing step 1: the replacement re-pends the row the dead worker held, before its first
    claim. Without it the replacement claims B, delivers it, and A stays INFLIGHT until a restart."""
    _shorten_backoffs(monkeypatch)
    store, runner, collector = await _start_runner(tmp_path, "per_lane")
    try:
        workers = getattr(runner, attr)
        first = workers[key]
        killer = _install_killer(store, collector, site, monkeypatch, kills=1)
        await _queue_a_then_b(runner, store, killer, stage)
        killer.gate.set()

        await _until(first.done, timeout=5.0)
        assert isinstance(first.exception(), _Kill)
        await _until_delivered(store, 2)
        assert _control_ids(collector) == ["M4607A", "M4607B"]
        assert await _inflight_rows(store) == 0
        replacement = workers[key]
        assert replacement is not first and not replacement.done()  # respawned, no restart
        assert runner.running
    finally:
        await runner.stop()
        await store.close()


@pytest.mark.parametrize(("kind", "attr", "key", "stage", "site"), _PER_LANE_SITES[:1])
async def test_a_row_that_kills_each_replacement_holds_its_lane_and_logs_on_a_backoff(
    kind: str,
    attr: str,
    key: str,
    stage: Stage,
    site: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Each replacement inherits the row from the worker before it, so a row that kills four
    workers in a row is still never overtaken. The deaths are one run: its traceback is logged on
    the 1st, 2nd and 4th, not on every death, and a settled pass closes it with a line."""
    caplog.set_level(logging.WARNING, logger="messagefoundry.pipeline.wiring_runner")
    _shorten_backoffs(monkeypatch)
    store, runner, collector = await _start_runner(tmp_path, "per_lane")
    try:
        killer = _install_killer(store, collector, site, monkeypatch, kills=4)
        await _queue_a_then_b(runner, store, killer, stage)
        killer.gate.set()

        await _until_delivered(store, 2, timeout=15.0)
        assert killer.fired == 4
        assert _control_ids(collector) == ["M4607A", "M4607B"]
        assert await _inflight_rows(store) == 0
        deaths = [
            r
            for r in caplog.records
            if "exited unexpectedly; respawning" in r.getMessage() and r.exc_info is not None
        ]
        assert [r.getMessage().rsplit(": ", 1)[-1] for r in deaths] == ["1)", "2)", "4)"]
        assert any("respawn recovered after 4" in r.getMessage() for r in caplog.records)
    finally:
        await runner.stop()
        await store.close()


@pytest.mark.parametrize(
    ("stage", "site"),
    [(Stage.INGRESS, "route_handoff"), (Stage.OUTBOUND, "send")],
    ids=lambda v: getattr(v, "value", v),
)
async def test_a_pooled_serializer_killed_mid_handoff_is_respawned_and_its_lane_drains_in_order(
    stage: Stage, site: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Closing step 2: a serializer killed by a ``BaseException`` is respawned. Without it the lane
    stays PROCESSING with its slot held and A INFLIGHT, so neither message is delivered."""
    _shorten_backoffs(monkeypatch)
    store, runner, collector = await _start_runner(tmp_path, "pooled")
    try:
        dispatcher = runner._dispatchers[stage]
        lane = "IB" if stage is Stage.INGRESS else "OB"
        killer = _install_killer(store, collector, site, monkeypatch, kills=1)
        await _queue_a_then_b(runner, store, killer, stage)
        dead = dispatcher._lane_tasks[lane]
        killer.gate.set()

        await _until(dead.done, timeout=5.0)
        assert isinstance(dead.exception(), _Kill)
        await _until_delivered(store, 2)
        assert _control_ids(collector) == ["M4607A", "M4607B"]
        assert await _inflight_rows(store) == 0
        assert dispatcher.busy_violations == 0
        assert dispatcher.slots_free == dispatcher._max_processing_lanes
        assert dispatcher._states[lane].serializer_deaths.count == 0
    finally:
        await runner.stop()
        await store.close()


async def test_a_row_that_kills_every_pooled_serializer_stops_its_lane_under_the_stop_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A row that kills every serializer at its head is bounded as a T17 fault is: each recovery is
    a zero-progress infra fault, so ``infra_fault_stop_after`` of them STOP the lane with its row
    PENDING, not INFLIGHT, and nothing behind it is delivered."""
    _shorten_backoffs(monkeypatch)
    store, runner, collector = await _start_runner(tmp_path, "pooled")
    try:
        dispatcher = runner._dispatchers[Stage.INGRESS]
        monkeypatch.setattr(dispatcher, "_infra_fault_stop_after", 3)
        killer = _install_killer(store, collector, "route_handoff", monkeypatch, kills=99)
        await _queue_a_then_b(runner, store, killer, Stage.INGRESS)
        killer.gate.set()

        await _until(lambda: dispatcher.stopped("IB"), timeout=10.0)
        assert killer.fired == 3
        assert collector.deliveries == []
        assert await _inflight_rows(store) == 0
        assert await _pending_at(store, Stage.INGRESS) == 2
        assert dispatcher.slots_free == dispatcher._max_processing_lanes
    finally:
        await runner.stop()
        await store.close()


async def test_rows_a_dying_serializer_noted_beyond_its_prefix_are_re_pended_with_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batching outbound claims its coalesced members itself, outside the serializer's prefix.
    When a ``BaseException`` kills it, the body records them (``note_held``) and the replacement
    dates them with the prefix; a fresh claim starts with none."""
    store, runner, _ = await _start_runner(tmp_path, "pooled")
    try:
        dispatcher = runner._dispatchers[Stage.OUTBOUND]
        st = dispatcher._states["OB"]
        dispatcher.note_held("OB", ["extra-1", "extra-2"])
        item: Any = SimpleNamespace(id="head-1")
        _, dated = dispatcher._dead_serializer_outcome("OB", [item])
        assert dated == ["head-1", "extra-1", "extra-2"]
        monkeypatch.setattr(dispatcher, "_start_serializer", lambda *a, **k: None)
        dispatcher._spawn_serializer("OB", [item])
        assert st.held_extra_ids == []
    finally:
        await runner.stop()
        await store.close()
