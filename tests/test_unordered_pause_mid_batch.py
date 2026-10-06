# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An UNORDERED outbound lane stops sending the rows it already claimed once it is paused or halted
(vault BACKLOG #2771, review finding B-5).

An UNORDERED lane claims up to ``claim_limit`` rows at once. ``_delivery_worker`` asked the operator
pause gate and the #122 log-unwritable halt gate only at its loop top, so a pause or a halt that
landed while the first row of a batch was on the wire let the worker send the rest of the batch
first. Now it re-asks both gates before each item and hands the unsent rows back with
``release_claimed``: pending again, with no attempt spent.

THE CONTROL IS THAT THE BATCH WAS REALLY CLAIMED. A row created after the claim is pending anyway and
the loop-top gate would hold it, so "five rows pending afterwards" proves nothing unless all six were
INFLIGHT together while the first send was held. Each test asserts that before it pauses. The rows
are queued behind an ``auto_start=False`` boot park, so the one claim that follows the operator start
sees all six.

Both claim modes are run: under the shipped ``pooled`` default an UNORDERED lane still runs this
worker (ADR 0066 D4), and ``per_lane`` runs it for every lane.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, OrderingMode
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage
from messagefoundry.transports import base as transport_base
from messagefoundry.transports.base import DeliveryResponse, DestinationConnector

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)

_LANE = "OB_UNORD"
_ROWS = 6


class _HeldFirstSend(DestinationConnector):
    """Records every send, and holds the FIRST one open until the test releases it, so the test can
    pause the lane while the rest of the batch is claimed and unsent."""

    def __init__(self, sink: list[str], started: asyncio.Event, release: asyncio.Event) -> None:
        self._sink = sink
        self._started = started
        self._release = release

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:
        self._sink.append(payload)
        if len(self._sink) == 1:
            self._started.set()
            await self._release.wait()
        return None


@pytest.fixture
def rig() -> Iterator[tuple[list[str], asyncio.Event, asyncio.Event]]:
    sink: list[str] = []
    started = asyncio.Event()
    release = asyncio.Event()
    original = transport_base._DESTINATIONS.get(ConnectorType.FILE)

    def _build(config: Any) -> _HeldFirstSend:
        return _HeldFirstSend(sink, started, release)

    transport_base.register_destination(ConnectorType.FILE, _build, replace=True)
    try:
        yield sink, started, release
    finally:
        if original is not None:
            transport_base.register_destination(ConnectorType.FILE, original, replace=True)
        else:  # pragma: no cover - FILE is always registered in practice
            transport_base._DESTINATIONS.pop(ConnectorType.FILE, None)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _registry(inbox: Path) -> Registry:
    """One inbound message fanned out to ``_ROWS`` handlers, each sending one row to the one
    UNORDERED lane, which boots parked (``auto_start=False``) so the rows queue up before any claim."""
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            _LANE,
            ConnectionSpec(ConnectorType.FILE, {"directory": ".", "filename": "{MSH-10}.hl7"}),
            ordering=OrderingMode.UNORDERED,
            auto_start=False,
        )
    )
    for i in range(_ROWS):
        reg.add_handler(f"h{i}", (lambda pl: lambda m: Send(_LANE, pl))(f"p{i}"))
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [f"h{i}" for i in range(_ROWS)])
    inbox.mkdir(exist_ok=True)
    (inbox / "MSG1.hl7").write_bytes(ADT.encode("utf-8"))
    return reg


async def _wait_until(pred: Any, timeout: float = 10.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not await pred():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met within timeout")
        await asyncio.sleep(0.02)


async def _lane_rows(store: MessageStore) -> list[tuple[str, int]]:
    cur = await store._db.execute(
        "SELECT status, attempts FROM queue WHERE stage=? AND destination_name=?",
        (Stage.OUTBOUND.value, _LANE),
    )
    return [(str(r["status"]), int(r["attempts"])) for r in await cur.fetchall()]


async def _claim_whole_batch(
    runner: RegistryRunner, store: MessageStore, started: asyncio.Event
) -> None:
    """Queue all rows behind the boot park, start the lane, and hold its first send. Asserts the
    control: every row is INFLIGHT at once, so the rest of the batch is claimed and unsent."""

    async def _all_pending() -> bool:
        return (await store.pending_depth(_LANE))[0] == _ROWS

    await _wait_until(_all_pending)
    await runner.start_outbound(_LANE)
    await asyncio.wait_for(started.wait(), timeout=10.0)
    inflight = await store.inflight_by_lane(stage=Stage.OUTBOUND.value)
    assert inflight.get(_LANE, (0, 0.0))[0] == _ROWS, (
        "the control failed: one claim did not hold all rows"
    )


async def _assert_tail_released(store: MessageStore, sink: list[str]) -> None:
    async def _settled() -> bool:
        return all(status != "inflight" for status, _ in await _lane_rows(store))

    await _wait_until(_settled)
    # A beat for a send that would wrongly follow the release to show up in the sink.
    await asyncio.sleep(0.2)
    # One send: the held one. Which row it was is not pinned, since an UNORDERED claim does not
    # promise an order.
    assert len(sink) == 1, f"the lane sent claimed rows after it was stopped: {sink}"
    rows = await _lane_rows(store)
    pending = [attempts for status, attempts in rows if status == "pending"]
    assert len(pending) == _ROWS - 1
    # release_claimed undoes the claim's increment: the unsent rows spent no attempt.
    assert pending == [0] * (_ROWS - 1)


@pytest.mark.parametrize("claim_mode", ["pooled", "per_lane"])
async def test_an_operator_pause_mid_batch_releases_the_unsent_claimed_rows(
    store: MessageStore,
    rig: tuple[list[str], asyncio.Event, asyncio.Event],
    tmp_path: Path,
    claim_mode: str,
) -> None:
    sink, started, release = rig
    runner = RegistryRunner(
        _registry(tmp_path / "in"),
        store,
        poll_interval=0.02,
        fifo_claim_batch=8,
        claim_mode=claim_mode,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        assert _LANE in runner._workers  # this lane is drained by _delivery_worker in both modes
        await _claim_whole_batch(runner, store, started)
        await runner.stop_outbound(_LANE)
        release.set()
        await _assert_tail_released(store, sink)

        async def _quiesced() -> bool:
            return runner.outbound_quiesced(_LANE)

        await _wait_until(_quiesced)
        assert not runner._workers[_LANE].done()  # parked at the pause gate, not exited
    finally:
        release.set()
        await runner.stop()


@pytest.mark.parametrize("claim_mode", ["pooled", "per_lane"])
async def test_the_log_unwritable_halt_mid_batch_releases_the_unsent_claimed_rows(
    store: MessageStore,
    rig: tuple[list[str], asyncio.Event, asyncio.Event],
    tmp_path: Path,
    claim_mode: str,
) -> None:
    """The halt alone, with the lane NOT in the pause set, so this arm is the halt check and not the
    pause check. The latch is set directly: how a halt fires is pinned in test_log_write_guard.py."""
    sink, started, release = rig
    runner = RegistryRunner(
        _registry(tmp_path / "in"),
        store,
        poll_interval=0.02,
        fifo_claim_batch=8,
        claim_mode=claim_mode,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        await _claim_whole_batch(runner, store, started)
        runner._log_write_stopped = True
        assert _LANE not in runner._outbound_paused
        release.set()
        await _assert_tail_released(store, sink)

        async def _worker_returned() -> bool:
            return runner._workers[_LANE].done()

        await _wait_until(_worker_returned)
        # outbound_quiesced() also asks for the pause set, which the halt alone does not join, so
        # read the Event the halt gate sets on its way out.
        assert runner._outbound_quiesced[_LANE].is_set()
    finally:
        release.set()
        runner._log_write_stopped = False
        await runner.stop()


async def test_a_failed_release_takes_the_fault_repend_and_not_a_quiescence_signal(
    store: MessageStore,
    rig: tuple[list[str], asyncio.Event, asyncio.Event],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The release raising must not leave the rows INFLIGHT under a lane that reads as quiesced.
    The worker's except arm re-pends them (reschedule_claimed, which also spends no attempt), and
    still sends nothing more."""
    sink, started, release = rig
    runner = RegistryRunner(
        _registry(tmp_path / "in"),
        store,
        poll_interval=0.02,
        fifo_claim_batch=8,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        await _claim_whole_batch(runner, store, started)

        events: list[str] = []
        real_reschedule = store.reschedule_claimed
        real_quiesced = runner._mark_outbound_quiesced

        async def _busy(ids: object, now: float | None = None) -> None:
            events.append("release failed")
            raise RuntimeError("database is locked")

        async def _reschedule(ids: Any, next_attempt_at: float, now: float | None = None) -> None:
            await real_reschedule(ids, next_attempt_at, now)
            events.append("re-pended")

        def _quiesced(name: str) -> None:
            events.append("quiesced")
            real_quiesced(name)

        monkeypatch.setattr(store, "release_claimed", _busy)
        monkeypatch.setattr(store, "reschedule_claimed", _reschedule)
        monkeypatch.setattr(runner, "_mark_outbound_quiesced", _quiesced)
        await runner.stop_outbound(_LANE)
        release.set()
        await _assert_tail_released(store, sink)

        async def _signalled() -> bool:
            return "quiesced" in events

        await _wait_until(_signalled)
        # The rows were back to pending before the lane said it had nothing in flight.
        assert events[:3] == ["release failed", "re-pended", "quiesced"], events
    finally:
        release.set()
        await runner.stop()
