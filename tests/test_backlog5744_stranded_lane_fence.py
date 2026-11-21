# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5744: a pooled lane whose hold ended without landing its re-pend claims nothing past
the rows it left in flight.

BACKLOG #1611 holds the lane while a failed re-pend is retried, so no claim takes a later row past
a stranded one. A stop ends the hold as a teardown. A pause (``ABANDONED``) or the stop policy's
bound (``EXHAUSTED``) ends it with the lane still running and the rows still INFLIGHT, and the
claim reads PENDING rows only, so a resume, a park timer or a re-arm used to claim the next row
ahead of them. The lane now records those rows, and its next chunk assembly re-pends them before
it claims.

An end on a moved lease (``SUPERSEDED``) is not recorded, and a record whose lease moved is
dropped unwritten: another node may hold those rows. Each test drives the dispatcher's own
assembly and then claims with the store, so a claim that passes a stranded row is read off the
row it returns."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.pipeline import stage_dispatcher
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.store import MessageStore, Stage

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG5744A|P|2.5.1\r"
RAW_B = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG5744B|P|2.5.1\r"
RAW_C = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG5744C|P|2.5.1\r"
LANE = "IB"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "stranded.db")
    yield s
    await s.close()


@pytest.fixture(autouse=True)
def _fast_backoffs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 0.01)
    monkeypatch.setattr(stage_dispatcher, "_REPEND_RETRY_CAP_SECONDS", 0.05)


class _Sink(LoggingAlertSink):
    def __init__(self) -> None:
        self.stopped: list[str] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append(detail)


class _Lease:
    def __init__(self) -> None:
        self.held = True
        self.epoch = 7

    def is_leader(self) -> bool:
        return self.held

    def current_epoch(self) -> int | None:
        return self.epoch if self.held else None


def _outage(monkeypatch: pytest.MonkeyPatch, store: MessageStore, attr: str) -> asyncio.Event:
    """``attr`` raises while the returned Event is set: a store down until the test heals it."""
    real = getattr(store, attr)
    down = asyncio.Event()
    down.set()

    async def flaky(*a: Any, **k: Any) -> Any:
        if down.is_set():
            raise RuntimeError(f"simulated store outage in {attr}")
        return await real(*a, **k)

    monkeypatch.setattr(store, attr, flaky)
    return down


def _dispatcher(
    store: MessageStore, lease: _Lease, sink: _Sink, stops: list[str]
) -> stage_dispatcher.StageDispatcher:
    return stage_dispatcher.StageDispatcher(
        Stage.INGRESS,
        store,
        process_item=None,  # type: ignore[arg-type]  # the drain is stubbed; no body runs
        lane_provider=set,
        per_lane_limit=1,
        alert_sink=sink,
        infra_fault_policy="stop",
        infra_fault_stop_after=3,
        on_lane_stopped=stops.append,
        call_later=asyncio.get_running_loop().call_later,
        is_leader=lease.is_leader,
        current_epoch=lease.current_epoch,
    )


async def _status(store: MessageStore, mid: str) -> str | None:
    cur = await store._db.execute(
        "SELECT status FROM queue WHERE stage=? AND message_id=?", (Stage.INGRESS.value, mid)
    )
    row = await cur.fetchone()
    return None if row is None else str(row["status"])


async def _next_claim(store: MessageStore, d: stage_dispatcher.StageDispatcher) -> str | None:
    """Run the dispatcher's own chunk assembly, as its claimer does, and claim what it hands over.
    Any re-pend episode the assembly starts is awaited, and assembly runs again after it. Returns
    the message id of the row the lane's claim took."""
    for _ in range(5):
        lanes = d._assemble_chunk(d._claimers[0])
        if lanes:
            result = await store.claim_fifo_heads(
                Stage.INGRESS.value, lanes, now=time.time() + 3600.0
            )
            items = result.by_lane.get(LANE) or []
            return items[0].message_id if items else None
        task = d._lane_tasks.get(LANE)
        if task is None:
            return None
        await asyncio.wait_for(task, timeout=5.0)
    raise AssertionError("the lane never reached a claim")


async def _enqueue(store: MessageStore, *raws: str) -> None:
    for raw in raws:
        await store.enqueue_ingress(channel_id=LANE, raw=raw, now=1.0)


def _drain_to(
    monkeypatch: pytest.MonkeyPatch,
    d: stage_dispatcher.StageDispatcher,
    kind: stage_dispatcher.LaneResultKind,
    tail: list[str],
    head: tuple[str, float] | None,
) -> None:
    outcome = stage_dispatcher._LaneOutcome(
        kind,
        time.time() if kind is stage_dispatcher.LaneResultKind.RETRY else None,
        is_infra_fault=kind is stage_dispatcher.LaneResultKind.RETRY,
    )

    async def drained(lane: str, items: Any) -> Any:
        return outcome, tail, head

    monkeypatch.setattr(d, "_drain_lane", drained)
    d._states[LANE] = stage_dispatcher._LaneState(phase=stage_dispatcher._LanePhase.PROCESSING)


@pytest.mark.parametrize("end", ["pause", "bound"])
async def test_a_head_left_in_flight_is_re_pended_before_the_lane_claims_again(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, end: str
) -> None:
    """The head's re-pend keeps failing. A pause, or the stop policy's bound, ends the hold with
    the head INFLIGHT, the lane PAUSED or STOPPED. The store heals and the operator resumes the
    lane. Its next claim takes the head, not the row behind it."""
    await _enqueue(store, RAW, RAW_B)
    head = await store.claim_next_fifo(LANE, stage=Stage.INGRESS.value, now=2.0)
    assert head is not None and head.message_id is not None
    down = _outage(monkeypatch, store, "reschedule_claimed")
    lease, sink, stops = _Lease(), _Sink(), list[str]()
    d = _dispatcher(store, lease, sink, stops)
    _drain_to(monkeypatch, d, stage_dispatcher.LaneResultKind.RETRY, [], (head.id, time.time()))
    if end == "pause":
        real = d._land_while_holding

        async def paused_mid_hold(*a: Any, **k: Any) -> Any:
            d.pause_lane(LANE)  # PROCESSING, so the pause is pending and ends the hold
            return await real(*a, **k)

        monkeypatch.setattr(d, "_land_while_holding", paused_mid_hold)
    await asyncio.wait_for(d._run_lane(LANE, [head]), timeout=5.0)
    st = d._states[LANE]
    expected = (
        stage_dispatcher._LanePhase.PAUSED
        if end == "pause"
        else stage_dispatcher._LanePhase.STOPPED
    )
    assert st.phase is expected
    assert await _status(store, head.message_id) == "inflight"
    down.clear()
    if end == "pause":
        monkeypatch.setattr(d, "_land_while_holding", real)
    assert d.resume_lane(LANE) is True
    assert await _next_claim(store, d) == head.message_id


async def test_a_tail_left_in_flight_by_a_stopped_lane_is_released_before_its_next_claim(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A content STOP whose tail release reaches the stop policy's bound leaves the tail INFLIGHT
    and the lane STOPPED. Once a re-arm reaches it, the tail is released first and claimed in
    order, before the row enqueued after it."""
    await _enqueue(store, RAW, RAW_B, RAW_C)
    first, second = await store.claim_next_fifo_batch(
        LANE, stage=Stage.INGRESS.value, limit=2, now=2.0
    )
    down = _outage(monkeypatch, store, "release_claimed")
    lease, sink, stops = _Lease(), _Sink(), list[str]()
    d = _dispatcher(store, lease, sink, stops)
    _drain_to(monkeypatch, d, stage_dispatcher.LaneResultKind.STOP, [first.id, second.id], None)
    await asyncio.wait_for(d._run_lane(LANE, [first, second]), timeout=5.0)
    assert d.stopped_holding_rows(LANE)
    down.clear()
    d.notify_work()  # a re-arm broadcast with no keep_stopped hook
    assert await _next_claim(store, d) == first.message_id
    assert await _status(store, second.message_id) == "pending"


async def test_a_record_whose_lease_moved_is_dropped_unwritten(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another node led while the lane was paused, and this node leads again with no teardown.
    The rows may be the successor's, so the lane re-pends nothing and claims on as it did before
    this fix. This pins the choice the row leaves open; it does not claim FIFO across the move."""
    await _enqueue(store, RAW, RAW_B)
    head = await store.claim_next_fifo(LANE, stage=Stage.INGRESS.value, now=2.0)
    assert head is not None and head.message_id is not None
    down = _outage(monkeypatch, store, "reschedule_claimed")
    lease, sink, stops = _Lease(), _Sink(), list[str]()
    d = _dispatcher(store, lease, sink, stops)
    _drain_to(monkeypatch, d, stage_dispatcher.LaneResultKind.RETRY, [], (head.id, time.time()))
    real = d._land_while_holding

    async def paused_mid_hold(*a: Any, **k: Any) -> Any:
        d.pause_lane(LANE)
        return await real(*a, **k)

    monkeypatch.setattr(d, "_land_while_holding", paused_mid_hold)
    await asyncio.wait_for(d._run_lane(LANE, [head]), timeout=5.0)
    monkeypatch.setattr(d, "_land_while_holding", real)
    down.clear()
    writes: list[Any] = []
    real_reschedule = store.reschedule_claimed

    async def recording(*a: Any, **k: Any) -> Any:
        writes.append(a)
        return await real_reschedule(*a, **k)

    monkeypatch.setattr(store, "reschedule_claimed", recording)
    lease.epoch = 8
    assert d.resume_lane(LANE) is True
    await _next_claim(store, d)
    assert writes == []
    assert await _status(store, head.message_id) == "inflight"
    assert d._states[LANE].stranded is None


async def test_a_record_waits_while_this_node_is_not_the_leader(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not the leader under the same lease, the re-pend episode sends nothing and parks the lane
    with the record kept, so no claim passes the rows; leading again, the next episode lands it."""
    await _enqueue(store, RAW, RAW_B)
    head = await store.claim_next_fifo(LANE, stage=Stage.INGRESS.value, now=2.0)
    assert head is not None and head.message_id is not None
    down = _outage(monkeypatch, store, "reschedule_claimed")
    lease, sink, stops = _Lease(), _Sink(), list[str]()
    d = _dispatcher(store, lease, sink, stops)
    _drain_to(monkeypatch, d, stage_dispatcher.LaneResultKind.RETRY, [], (head.id, time.time()))
    await asyncio.wait_for(d._run_lane(LANE, [head]), timeout=5.0)
    assert d._states[LANE].phase is stage_dispatcher._LanePhase.STOPPED
    down.clear()
    lease.held = False
    assert d.resume_lane(LANE) is True
    assert d._assemble_chunk(d._claimers[0]) == []
    await asyncio.wait_for(d._lane_tasks[LANE], timeout=5.0)
    st = d._states[LANE]
    assert st.phase is stage_dispatcher._LanePhase.PARKED and st.stranded is not None
    assert await _status(store, head.message_id) == "inflight"
    d._cancel_timer(LANE)
    lease.held = True
    d._unpark(LANE, woken=True)
    assert await _next_claim(store, d) == head.message_id
