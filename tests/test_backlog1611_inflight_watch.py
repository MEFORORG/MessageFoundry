# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1611 part B (Fable packet 3, finding P3-03): a row stranded in flight is visible.

A claim is its own committed transaction, so a store fault between the claim and the handoff leaves
the row ``inflight``. Part A (PR 1164) made the per-lane workers re-pend it, and the pooled dispatcher
already did (T17), but both re-pends are store writes that can fail as well. What is left is recovered
by ``reset_stale_inflight`` at the next start and by nothing before it, and it was invisible:
``pending_depth`` counts pending rows only, and the buildup and stall checks run only from a lane's own
processing path, which a strand has stopped.

This file covers the read (``inflight_by_lane``), the runner's in-flight watch that pages on it, and
the two ``pooled`` rows of P3-03's measured table as failure-injection tests:

* ``route_handoff`` raises once: T17 re-pends the head and the message routes, no restart.
* ``route_handoff`` AND ``reschedule_claimed`` each raise once: before step 2 the row stranded until
  a restart, and the in-flight watch paged it.

Step 2 recovers it with no restart and no clock: a holder whose re-pend fails retries it while it
holds the lane, and a worker that dies holding a row has its own lane recovered before its
replacement's first claim. The last tests show both in both claim modes, in FIFO order, with
controls that restore the old behaviour and go red; that no new path re-pends a row a live worker
holds, with an unscoped control that does; the clustered stand-down; and a prompt stop.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import (
    BuildupThreshold,
    ConnectorType,
    RetryPolicy,
    StallThreshold,
)
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
)
from messagefoundry.pipeline import stage_dispatcher, wiring_runner
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.cluster import NullCoordinator
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, Stage

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1611B|P|2.5.1\r"
RAW_B = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1611C|P|2.5.1\r"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "inflight.db")
    yield s
    await s.close()


class _RecordingSink(LoggingAlertSink):
    def __init__(self) -> None:
        self.buildup: list[tuple[str, int, float]] = []
        self.stall: list[tuple[str, float]] = []

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        self.buildup.append((name, depth, oldest_age_seconds))

    def message_stall(self, name: str, *, oldest_age_seconds: float) -> None:
        self.stall.append((name, oldest_age_seconds))


def _registry(tmp_path: Path) -> Registry:
    """Inbound 'IB' -> router 'r' -> handler 'h' (filters); outbound 'OB' for the stall arm. The
    inbox is its own empty directory, so the listener never picks up the store file."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir(exist_ok=True)
    outdir.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection("OB", ConnectionSpec(ConnectorType.FILE, {"directory": str(outdir)}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [])
    return reg


async def _ingress_inflight(store: MessageStore) -> int:
    """Counted with its own SQL, not through ``inflight_by_lane``, so a broken read cannot make a
    stranded row look recovered."""
    cur = await store._db.execute(
        "SELECT COUNT(*) AS c FROM queue WHERE stage=? AND channel_id=? AND status=?",
        (Stage.INGRESS.value, "IB", "inflight"),
    )
    row = await cur.fetchone()
    assert row is not None
    return int(row["c"])


async def _until(pred: Any, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out waiting for condition")


# --- the read ---------------------------------------------------------------------------------------


async def test_inflight_by_lane_reports_claim_time_not_enqueue_time(store: MessageStore) -> None:
    """In-flight rows only, grouped by the stage's lane key, aged from the CLAIM. A pending row is the
    control: it is in ``pending_depth`` and must not be here."""
    assert await store.inflight_by_lane(stage=Stage.OUTBOUND.value) == {}
    await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=10.0)
    await store.enqueue_message(channel_id="c1", raw="y", deliveries=[("d1", "p2")], now=20.0)
    await store.enqueue_message(channel_id="c1", raw="z", deliveries=[("d2", "p3")], now=30.0)
    assert await store.inflight_by_lane(stage=Stage.OUTBOUND.value) == {}  # all pending

    await store.claim_next_fifo("d1", now=500.0)  # enqueued at 10, claimed at 500
    assert await store.inflight_by_lane(stage=Stage.OUTBOUND.value) == {"d1": (1, 500.0)}
    assert await store.pending_depth("d1") == (1, 20.0)  # the pending sibling is not in flight
    # Stage-aware: an outbound claim is not an ingress row, and an ingress lane keys on channel_id.
    assert await store.inflight_by_lane(stage=Stage.INGRESS.value) == {}
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=40.0)
    await store.claim_next_fifo("IB", now=600.0, stage=Stage.INGRESS.value)
    assert await store.inflight_by_lane(stage=Stage.INGRESS.value) == {"IB": (1, 600.0)}
    # A handed-back row leaves the read: reset_stale_inflight is the restart recovery.
    await store.reset_stale_inflight(now=700.0)
    assert await store.inflight_by_lane(stage=Stage.OUTBOUND.value) == {}
    assert await store.inflight_by_lane(stage=Stage.INGRESS.value) == {}


# --- the watch --------------------------------------------------------------------------------------


async def test_watch_pages_an_ingress_row_held_past_the_buildup_age(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The P3-03 shape with no runner machinery in the way: a committed claim and no handoff. Below
    the threshold nothing fires (the control arm); past it, ``queue_buildup`` fires once for the
    inbound and the log names the stage and says in flight."""
    sink = _RecordingSink()
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        alert_sink=sink,
        buildup_default=BuildupThreshold(max_oldest_seconds=60.0),
        egress=EgressSettings(deny_by_default=False),
    )
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    await store.claim_next_fifo("IB", now=100.0, stage=Stage.INGRESS.value)
    assert await store.pending_depth("IB", stage=Stage.INGRESS.value) == (0, None)  # the blind spot

    await runner._check_inflight_strands(now=159.0)
    assert sink.buildup == []  # held 59 s < 60 s

    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner._check_inflight_strands(now=161.0)
    assert sink.buildup == [("IB", 1, 61.0)]
    assert "held in flight on ingress lane 'IB'" in caplog.text

    await runner._check_inflight_strands(now=170.0)
    assert len(sink.buildup) == 1  # throttled with the pending buildup page, not re-fired per tick


async def test_watch_pages_an_outbound_row_on_its_stall_threshold(
    store: MessageStore, tmp_path: Path
) -> None:
    """Outbound lanes page the STALL alert on the lane's resolved threshold. A paused outbound holds
    nothing by design and is skipped, as the pending stall check skips it."""
    sink = _RecordingSink()
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        alert_sink=sink,
        stall_default=StallThreshold(max_oldest_seconds=30.0),
        egress=EgressSettings(deny_by_default=False),
    )
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=100.0)
    await store.claim_next_fifo("OB", now=100.0)

    runner._outbound_paused.add("OB")
    await runner._check_inflight_strands(now=200.0)
    assert sink.stall == []  # paused: skipped

    runner._outbound_paused.discard("OB")
    await runner._check_inflight_strands(now=200.0)
    assert sink.stall == [("OB", 100.0)]
    assert sink.buildup == []  # held 100 s, under the default 300 s buildup age


async def test_a_default_engine_pages_a_strand_through_the_buildup_age(
    store: MessageStore, tmp_path: Path
) -> None:
    """No threshold configured at all. The buildup age defaults on (300 s) and the stall alert off, so
    a default engine still pages an in-flight hold, on both an outbound and an ingress lane."""
    sink = _RecordingSink()
    runner = RegistryRunner(
        _registry(tmp_path), store, alert_sink=sink, egress=EgressSettings(deny_by_default=False)
    )
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=100.0)
    await store.claim_next_fifo("OB", now=100.0)
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    await store.claim_next_fifo("IB", now=100.0, stage=Stage.INGRESS.value)

    await runner._check_inflight_strands(now=399.0)
    assert sink.buildup == []  # 299 s: under the default
    await runner._check_inflight_strands(now=401.0)
    assert sorted(sink.buildup) == [("IB", 1, 301.0), ("OB", 1, 301.0)]
    assert sink.stall == []  # off by default


async def test_watch_reads_nothing_while_every_age_is_off(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With every age turned off the watch returns before any store read. That is an operator
    choice, not the default: the buildup age defaults on."""
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        alert_sink=_RecordingSink(),
        buildup_default=BuildupThreshold(max_oldest_seconds=None),
        egress=EgressSettings(deny_by_default=False),
    )

    async def boom(**_k: Any) -> dict[str, tuple[int, float]]:
        raise AssertionError("the watch read the store with every threshold off")

    monkeypatch.setattr(store, "inflight_by_lane", boom)
    await runner._check_inflight_strands(now=10_000.0)


class _Follower(NullCoordinator):
    """A node that is not the cluster leader."""

    def is_leader(self) -> bool:
        return False


@pytest.mark.parametrize("leader", [True, False])
async def test_only_the_leader_pages(store: MessageStore, tmp_path: Path, leader: bool) -> None:
    """Under active-passive HA the graph runs on the leader alone, so a node that is not the leader
    pages nothing. The leader arm is the control: the same strand does page there."""
    sink = _RecordingSink()
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        alert_sink=sink,
        buildup_default=BuildupThreshold(max_oldest_seconds=60.0),
        coordinator=None if leader else _Follower(),
        egress=EgressSettings(deny_by_default=False),
    )
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    await store.claim_next_fifo("IB", now=100.0, stage=Stage.INGRESS.value)
    await runner._check_inflight_strands(now=200.0)
    assert sink.buildup == ([("IB", 1, 100.0)] if leader else [])


async def test_watch_skips_the_response_read_without_a_loopback_inbound(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-ingress tokens drain only on a loopback lane, so a graph with none reads no RESPONSE rows.
    The other three stages are still read."""
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        alert_sink=_RecordingSink(),
        egress=EgressSettings(deny_by_default=False),
    )
    read: list[str] = []
    real = store.inflight_by_lane

    async def spy(*, stage: str) -> dict[str, tuple[int, float]]:
        read.append(stage)
        return await real(stage=stage)

    monkeypatch.setattr(store, "inflight_by_lane", spy)
    await runner._check_inflight_strands(now=10_000.0)
    assert read == [Stage.OUTBOUND.value, Stage.INGRESS.value, Stage.ROUTED.value]


async def test_watch_reads_and_pages_response_rows_on_loopback_lanes_only(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a loopback inbound the RESPONSE stage is read, and a RESPONSE hold pages on a loopback
    lane. The same hold keyed on a non-loopback inbound is the control: the RESPONSE lane set is the
    loopback inbounds, as the dispatcher's is, so it does not page."""
    reg = _registry(tmp_path)
    reg.add_inbound(InboundConnection("LB", ConnectionSpec(ConnectorType.LOOPBACK, {}), router="r"))
    sink = _RecordingSink()
    runner = RegistryRunner(
        reg,
        store,
        alert_sink=sink,
        buildup_default=BuildupThreshold(max_oldest_seconds=60.0),
        egress=EgressSettings(deny_by_default=False),
    )
    read: list[str] = []

    async def fake(*, stage: str) -> dict[str, tuple[int, float]]:
        read.append(stage)
        return {"LB": (1, 0.0), "IB": (2, 0.0)} if stage == Stage.RESPONSE.value else {}

    monkeypatch.setattr(store, "inflight_by_lane", fake)
    await runner._check_inflight_strands(now=100.0)
    assert Stage.RESPONSE.value in read
    assert sink.buildup == [("LB", 1, 100.0)]


async def test_a_pending_check_and_the_watch_page_a_lane_once_per_window(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pending buildup check passes its throttle, then awaits its store read. If the in-flight
    watch fires the same ``(stage, lane)`` key inside that await, the pending check must not page
    again when it resumes."""
    sink = _RecordingSink()
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        alert_sink=sink,
        buildup_default=BuildupThreshold(max_oldest_seconds=60.0),
        egress=EgressSettings(deny_by_default=False),
    )
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "a")], now=1.0)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "b")], now=1.0)
    await store.claim_next_fifo("OB", now=1.0)  # 'a' held in flight; 'b' pending
    real = store.pending_depth

    async def racing(name: str, *, stage: str = Stage.OUTBOUND.value) -> tuple[int, float | None]:
        await runner._check_inflight_strands()  # the watch ticks inside the pending read
        return await real(name, stage=stage)

    monkeypatch.setattr(store, "pending_depth", racing)
    await runner._maybe_alert_buildup("OB")
    assert len(sink.buildup) == 1, sink.buildup
    assert sink.buildup[0][1] == 1  # the in-flight page won; the pending one was throttled


async def test_an_outbound_hold_past_both_thresholds_logs_once(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Past both its buildup and its stall age, an outbound hold fires both alerts and writes one log
    line, not two identical ones."""
    sink = _RecordingSink()
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        alert_sink=sink,
        buildup_default=BuildupThreshold(max_oldest_seconds=300.0),
        stall_default=StallThreshold(max_oldest_seconds=120.0),
        egress=EgressSettings(deny_by_default=False),
    )
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=100.0)
    await store.claim_next_fifo("OB", now=100.0)
    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner._check_inflight_strands(now=500.0)
    assert sink.buildup == [("OB", 1, 400.0)]
    assert sink.stall == [("OB", 400.0)]
    assert caplog.text.count("held in flight on outbound lane 'OB'") == 1


@pytest.mark.parametrize("stage", [Stage.OUTBOUND.value, Stage.INGRESS.value])
async def test_sqlite_read_seeks_the_ready_index(
    store: MessageStore, stage: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The planner has no statistics here and, left alone, prefers the FIFO index that also covers
    the GROUP BY, seeking on ``stage`` only and walking every row at the stage. The statement
    ``inflight_by_lane`` actually runs must seek ``(stage, status)`` on ``ix_queue_ready``, so its
    cost follows the in-flight rows, not the queue."""
    seen: list[tuple[str, Any]] = []
    real_read = store._read

    class _Recorder:
        def __init__(self, db: Any) -> None:
            self._db = db

        async def execute(self, sql: str, params: Any = ()) -> Any:
            seen.append((sql, params))
            return await self._db.execute(sql, params)

    @contextlib.asynccontextmanager
    async def recording_read() -> AsyncIterator[Any]:
        async with real_read() as db:
            yield _Recorder(db)

    monkeypatch.setattr(store, "_read", recording_read)
    await store.inflight_by_lane(stage=stage)
    assert len(seen) == 1
    sql, params = seen[0]
    cur = await store._db.execute("EXPLAIN QUERY PLAN " + sql, params)
    plan = " ".join(str(r[3]) for r in await cur.fetchall())
    assert "ix_queue_ready (stage=? AND status=?)" in plan, plan


# --- P3-03's two pooled rows, end to end ------------------------------------------------------------


def _fail_once(monkeypatch: pytest.MonkeyPatch, obj: Any, attr: str, calls: dict[str, int]) -> None:
    real = getattr(obj, attr)

    async def flaky(*a: Any, **k: Any) -> Any:
        calls[attr] = calls.get(attr, 0) + 1
        if calls[attr] == 1:
            raise RuntimeError(f"simulated transient store fault in {attr}")
        return await real(*a, **k)

    monkeypatch.setattr(obj, attr, flaky)


async def test_pooled_route_handoff_fault_recovers_through_t17(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P3-03's first pooled row: ``route_handoff`` raises once. T17 re-pends the head not-due, the
    lane re-claims it after the backoff, and the message routes with no restart and no reload."""
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 0.01)
    calls: dict[str, int] = {}
    _fail_once(monkeypatch, store, "route_handoff", calls)
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        claim_mode="pooled",
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
        runner._dispatchers[Stage.INGRESS].mark_ready("IB")

        async def routed() -> bool:
            msg = await store.get_message(mid)
            return msg is not None and msg["status"] != MessageStatus.RECEIVED.value

        await _until(routed)
        assert calls["route_handoff"] >= 2  # the fault fired and the row was re-tried
        assert await _ingress_inflight(store) == 0
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_store_that_stays_down_keeps_the_row_in_flight_and_the_watch_pages_it(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    claim_mode: str,
) -> None:
    """``route_handoff`` raises once and ``reschedule_claimed`` keeps raising. The holder retries its
    re-pend (step 2), and nothing it does hides the strand: the row stays in flight, the lane reads
    empty to ``pending_depth``, and the in-flight watch pages it. Once the store heals, the retry
    lands and the message routes with no restart and no reload.

    Before step 2 this was P3-03's second pooled row and stayed stranded until a restart."""
    _fast_backoffs(monkeypatch)
    calls: dict[str, int] = {}
    _fail_once(monkeypatch, store, "route_handoff", calls)
    down = _fail_while(monkeypatch, store, "reschedule_claimed", calls)
    sink = _RecordingSink()
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        alert_sink=sink,
        buildup_default=BuildupThreshold(max_oldest_seconds=0.3),
        claim_mode=claim_mode,
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
    )
    with caplog.at_level(logging.WARNING):
        await runner.start()
        try:
            mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
            runner.notify_work()

            async def paged() -> bool:
                return "held in flight on ingress lane 'IB'" in caplog.text

            await _until(paged)
            assert calls["reschedule_claimed"] >= 2  # retried, not given up after one
            assert await _status(store, mid) == MessageStatus.RECEIVED.value
            assert await _ingress_inflight(store) == 1
            assert await store.pending_depth("IB", stage=Stage.INGRESS.value) == (0, None)
            assert any(name == "IB" and depth == 1 for name, depth, _ in sink.buildup)
            assert "holding the lane and retrying" in caplog.text
            down.clear()  # the store heals

            async def routed() -> bool:
                return await _status(store, mid) != MessageStatus.RECEIVED.value

            await _until(routed)
            assert await _ingress_inflight(store) == 0
        finally:
            await runner.stop()


# --- step 2: recover without a restart, and never re-pend a held row -------------------------------


def _fast_backoffs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 0.01)
    monkeypatch.setattr(stage_dispatcher, "_REPEND_RETRY_CAP_SECONDS", 0.05)
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.01)
    monkeypatch.setattr(wiring_runner, "_REPEND_RETRY_CAP_SECONDS", 0.05)
    monkeypatch.setattr(wiring_runner, "_INFLIGHT_WATCH_INTERVAL_SECONDS", 0.05)


def _fail_while(
    monkeypatch: pytest.MonkeyPatch, obj: Any, attr: str, calls: dict[str, int]
) -> asyncio.Event:
    """``attr`` raises while the returned Event is set: a store that stays down until the test heals
    it."""
    real = getattr(obj, attr)
    down = asyncio.Event()
    down.set()

    async def flaky(*a: Any, **k: Any) -> Any:
        calls[attr] = calls.get(attr, 0) + 1
        if down.is_set():
            raise RuntimeError(f"simulated store outage in {attr}")
        return await real(*a, **k)

    monkeypatch.setattr(obj, attr, flaky)
    return down


async def _status(store: MessageStore, mid: str) -> str | None:
    msg = await store.get_message(mid)
    return None if msg is None else str(msg["status"])


def _record_handoffs(
    monkeypatch: pytest.MonkeyPatch,
    store: MessageStore,
    handed_off: list[str],
    *,
    before: Any = None,
) -> None:
    """Wrap ``route_handoff``: run ``before(message_id)`` first (it may raise, or hold), then record
    the message id of every handoff that COMMITTED, in commit order. Layered over any ``_fail_once``
    already installed."""
    real = store.route_handoff

    async def recording(*a: Any, **k: Any) -> Any:
        if before is not None:
            await before(k["message_id"])
        result = await real(*a, **k)
        handed_off.append(k["message_id"])
        return result

    monkeypatch.setattr(store, "route_handoff", recording)


def _one_shot_repend(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CONTROL: put back the pre-step-2 behaviour, one re-pend attempt and then move on, in both
    claim modes. A test that cannot tell this from the shipped code proves nothing."""

    async def once_per_lane(
        self: RegistryRunner, worker: str, name: str, ids: Any, *, faults: Any = None
    ) -> bool:
        with contextlib.suppress(Exception):
            await self.store.reschedule_claimed(list(ids), time.time())
        return False

    async def once_pooled(self: Any, lane: str, what: str, write: Any) -> bool:
        with contextlib.suppress(Exception):
            await write()
        return True

    monkeypatch.setattr(RegistryRunner, "_repend_claimed_on_fault", once_per_lane)
    monkeypatch.setattr(stage_dispatcher.StageDispatcher, "_land_while_holding", once_pooled)


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
@pytest.mark.parametrize("variant", ["shipped", "control"])
async def test_a_double_fault_routes_without_a_restart_and_nothing_overtakes_it(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    claim_mode: str,
    variant: str,
) -> None:
    """``route_handoff`` AND the holder's re-pend each raise once, then succeed. Message A is the one
    that faults; B arrives on the same lane while A is stranded. Shipped: the holder retries its
    re-pend while it holds the lane, so A routes first, then B, with no restart and no reload.

    The ``control`` variant restores the one-shot re-pend this step replaced: A stays in flight and
    B overtakes it, which is the defect."""
    _fast_backoffs(monkeypatch)
    if variant == "control":
        _one_shot_repend(monkeypatch)
    calls: dict[str, int] = {}
    _fail_once(monkeypatch, store, "reschedule_claimed", calls)
    second: list[str] = []

    async def fault_a_once(message_id: str) -> None:
        calls["route_handoff"] = calls.get("route_handoff", 0) + 1
        if calls["route_handoff"] == 1:
            # B lands while A is claimed, so only a lane that is held keeps B behind A.
            second.append(await store.enqueue_ingress(channel_id="IB", raw=RAW_B))
            raise RuntimeError("simulated transient store fault in route_handoff")

    handed_off: list[str] = []
    _record_handoffs(monkeypatch, store, handed_off, before=fault_a_once)
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        claim_mode=claim_mode,
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        a = await store.enqueue_ingress(channel_id="IB", raw=RAW)
        runner.notify_work()

        async def b_routed() -> bool:
            return bool(second) and second[0] in handed_off

        await _until(b_routed)
        if variant == "control":
            assert handed_off == [second[0]]  # B overtook A
            assert await _ingress_inflight(store) == 1  # and A is stranded
            return

        async def a_routed() -> bool:
            return a in handed_off

        await _until(a_routed)
        assert handed_off == [a, second[0]]  # FIFO: A, then B
        assert calls["reschedule_claimed"] >= 2  # the first re-pend failed and was retried
        assert await _ingress_inflight(store) == 0
    finally:
        await runner.stop()


class _Killed(BaseException):
    """Not an ``Exception``: the worker loops catch ``Exception`` only, so this kills the worker with
    its claimed row in flight, and the supervisor respawns it."""


@pytest.mark.parametrize("variant", ["shipped", "recovery-fails-once", "control"])
async def test_a_worker_killed_holding_a_row_has_it_recovered_by_its_replacement(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    variant: str,
) -> None:
    """A per-lane router worker dies on a ``BaseException`` while holding A. ``_on_inbound_worker_done``
    respawns it, and the replacement re-pends its own lane before its first claim, so A routes
    first, then B, with no restart and no reload.

    ``recovery-fails-once``: the replacement's reset raises once. It claims nothing until the
    retry lands, so the order still holds. The ``control`` variant spawns the replacement with no
    recovery: A stays in flight and B, which arrived meanwhile, overtakes it."""
    _fast_backoffs(monkeypatch)
    calls: dict[str, int] = {}
    if variant == "control":
        monkeypatch.setattr(wiring_runner, "_left_a_lane", lambda prev: False)
    elif variant == "recovery-fails-once":
        _fail_once(monkeypatch, store, "reset_stale_inflight", calls)
    second: list[str] = []
    kills: list[str] = []

    async def kill_once(message_id: str) -> None:
        if not kills:
            kills.append(message_id)
            second.append(await store.enqueue_ingress(channel_id="IB", raw=RAW_B))
            raise _Killed

    handed_off: list[str] = []
    _record_handoffs(monkeypatch, store, handed_off, before=kill_once)
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        claim_mode="per_lane",
        egress=EgressSettings(deny_by_default=False),
    )
    with caplog.at_level(logging.WARNING):
        await runner.start()
        try:
            a = await store.enqueue_ingress(channel_id="IB", raw=RAW)
            runner.notify_work()

            async def b_routed() -> bool:
                return bool(second) and second[0] in handed_off

            await _until(b_routed)
            if variant == "control":
                assert handed_off == [second[0]]
                assert await _ingress_inflight(store) == 1
                return
            assert handed_off == [a, second[0]]
            assert await _ingress_inflight(store) == 0
            assert "re-pended 1 row(s) a finished worker left in flight" in caplog.text
            if variant == "recovery-fails-once":
                assert calls["reset_stale_inflight"] == 2
        finally:
            await runner.stop()


def _two_inbound_registry(tmp_path: Path) -> Registry:
    reg = _registry(tmp_path)
    inbox2 = tmp_path / "in2"
    inbox2.mkdir(exist_ok=True)
    reg.add_inbound(
        InboundConnection(
            "IB2",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox2), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    return reg


@pytest.mark.parametrize("variant", ["shipped", "unscoped-control"])
async def test_no_new_path_repends_a_row_a_live_worker_holds(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    """THE SAFETY CONDITION. IB's router worker holds A in a slow handoff (gated, not failed) for the
    whole test. Meanwhile IB2's worker is killed holding its own row and respawned, so the respawn
    recovery runs; and every spawn door is tried on IB, whose worker is alive. None of it may re-pend
    A: a second claim would hand it off twice.

    The ``unscoped-control`` variant makes the respawn recovery reset every lane of the stage instead
    of its own, and A is re-pended under its live holder -- so this test can tell a scoped recovery
    from one that merely did nothing."""
    _fast_backoffs(monkeypatch)
    if variant == "unscoped-control":

        async def unscoped(self: RegistryRunner, stage: Stage, name: str) -> int:
            return await self.store.reset_stale_inflight(stage=stage.value)

        monkeypatch.setattr(RegistryRunner, "_recover_respawned_lane", unscoped)
    gate = asyncio.Event()
    held: list[str] = []
    killed: list[str] = []
    ib_ids: list[str] = []

    async def hold_ib_kill_ib2(message_id: str) -> None:
        if message_id in ib_ids:
            held.append(message_id)
            await gate.wait()
        elif not killed:
            killed.append(message_id)
            raise _Killed

    handed_off: list[str] = []
    _record_handoffs(monkeypatch, store, handed_off, before=hold_ib_kill_ib2)
    runner = RegistryRunner(
        _two_inbound_registry(tmp_path),
        store,
        claim_mode="per_lane",
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        ib_ids.append(await store.enqueue_ingress(channel_id="IB", raw=RAW))
        runner.notify_work()

        async def holding() -> bool:
            return bool(held)

        await _until(holding)
        live = runner._router_workers["IB"]
        b = await store.enqueue_ingress(channel_id="IB2", raw=RAW_B)
        runner.notify_work()

        async def ib2_recovered() -> bool:
            return b in handed_off

        await _until(ib2_recovered)  # IB2's worker died, was respawned, recovered and routed b
        assert killed == [b]
        if variant == "unscoped-control":
            assert await _ingress_inflight(store) == 0  # A re-pended under its live holder: RED
            return
        runner._ensure_inbound_workers("IB")  # a re-arm door over a LIVE worker
        assert runner._router_workers["IB"] is live  # nothing spawned, so nothing recovered
        await asyncio.sleep(0.3)  # many backoff and watch ticks while A is still held
        assert await _ingress_inflight(store) == 1
        assert await store.pending_depth("IB", stage=Stage.INGRESS.value) == (0, None)
        gate.set()

        async def a_routed() -> bool:
            return ib_ids[0] in handed_off

        await _until(a_routed)
        assert handed_off.count(ib_ids[0]) == 1  # handed off once, never re-claimed behind it
        assert held == [ib_ids[0]]
    finally:
        gate.set()
        await runner.stop()


class _Clustered(NullCoordinator):
    def reclaims_inflight(self) -> bool:
        return True


@pytest.mark.parametrize(
    ("coordinator", "recovered"),
    [(None, 1), (_Clustered(), 0), (_Follower(), 0)],
    ids=["single-node-control", "clustered", "follower"],
)
async def test_the_respawn_recovery_stands_down_where_the_startup_reset_does(
    store: MessageStore, tmp_path: Path, coordinator: Any, recovered: int
) -> None:
    """Clustered (``reclaims_inflight()``), an ex-leader may still hold a row on the lane, so the
    respawn recovery runs nothing, exactly where ``Engine.start()`` skips its unconditional reset; a
    follower runs nothing either. Single-node is the control: the same row is re-pended. In every
    case a row on ANOTHER lane is out of scope and stays in flight."""
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    await store.enqueue_ingress(channel_id="IB2", raw=RAW_B, now=1.0)
    await store.claim_next_fifo("IB", now=2.0, stage=Stage.INGRESS.value)
    await store.claim_next_fifo("IB2", now=2.0, stage=Stage.INGRESS.value)
    runner = RegistryRunner(
        _two_inbound_registry(tmp_path),
        store,
        coordinator=coordinator,
        egress=EgressSettings(deny_by_default=False),
    )
    assert await runner._recover_respawned_lane(Stage.INGRESS, "IB") == recovered
    assert await _ingress_inflight(store) == 1 - recovered
    assert await store.inflight_by_lane(stage=Stage.INGRESS.value) == (
        {"IB2": (1, 2.0)} if recovered else {"IB": (1, 2.0), "IB2": (1, 2.0)}
    )
    # The wrong stage is out of scope too.
    assert await runner._recover_respawned_lane(Stage.ROUTED, "IB2") == 0


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_stop_during_the_retry_exits_promptly_and_leaves_the_row_in_flight(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, claim_mode: str
) -> None:
    """The re-pend keeps failing and its backoff is long (30 s). A stop must end the retry at once,
    not after the backoff, and leave the row INFLIGHT for the next start's reset, as before."""
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 30.0)
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 30.0)
    calls: dict[str, int] = {}
    _fail_once(monkeypatch, store, "route_handoff", calls)
    _fail_while(monkeypatch, store, "reschedule_claimed", calls)
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        claim_mode=claim_mode,
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    stopped = False
    try:
        await store.enqueue_ingress(channel_id="IB", raw=RAW)
        runner.notify_work()

        async def retrying() -> bool:
            return calls.get("reschedule_claimed", 0) >= 1

        await _until(retrying)
        await asyncio.sleep(0.1)  # now inside the 30 s backoff
        started = time.monotonic()
        await asyncio.wait_for(runner.stop(), timeout=10.0)
        stopped = True
        assert time.monotonic() - started < 5.0  # far inside the 30 s backoff
        assert calls["reschedule_claimed"] == 1  # no retry ran during the stop
        assert await _ingress_inflight(store) == 1
    finally:
        if not stopped:
            await runner.stop()


async def test_the_respawn_recovery_is_scoped_to_its_stage_and_lane_and_reached_by_every_kind(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The OUTBOUND arm scopes on ``destination_name`` and the inbound arms on ``channel_id``, each
    at its own stage. A spawn over a FINISHED worker of each kind recovers that kind's stage and
    lane only; rows on another destination, or another stage of the same inbound, stay in flight.
    A spawn with no predecessor recovers nothing (the startup reset covered it)."""
    runner = RegistryRunner(
        _two_inbound_registry(tmp_path), store, egress=EgressSettings(deny_by_default=False)
    )
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=1.0)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB2", "p")], now=1.0)
    await store.claim_next_fifo("OB", now=2.0)
    await store.claim_next_fifo("OB2", now=2.0)
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    await store.claim_next_fifo("IB", now=2.0, stage=Stage.INGRESS.value)
    out, ingress = Stage.OUTBOUND.value, Stage.INGRESS.value
    assert await runner._recover_respawned_lane(Stage.OUTBOUND, "OB") == 1
    assert await store.inflight_by_lane(stage=out) == {"OB2": (1, 2.0)}
    assert await store.inflight_by_lane(stage=ingress) == {"IB": (1, 2.0)}

    async def idle(name: str) -> None:
        return None

    finished = asyncio.ensure_future(idle("x"))
    await finished
    for attr in ("_router_worker", "_transform_worker", "_response_worker"):
        monkeypatch.setattr(runner, attr, idle)
    runner._transform_workers["IB"] = finished  # a returned transform worker: ROUTED, not INGRESS
    runner._spawn_inbound_worker("transform", "IB")
    await runner._transform_workers["IB"]
    assert await store.inflight_by_lane(stage=ingress) == {"IB": (1, 2.0)}
    runner._spawn_inbound_worker("router", "IB")  # no predecessor: nothing recovered
    await runner._router_workers["IB"]
    assert await store.inflight_by_lane(stage=ingress) == {"IB": (1, 2.0)}
    runner._router_workers["IB"] = finished  # a returned router worker: INGRESS on IB
    runner._spawn_inbound_worker("router", "IB")
    await runner._router_workers["IB"]
    assert await store.inflight_by_lane(stage=ingress) == {}
    assert await store.inflight_by_lane(stage=out) == {"OB2": (1, 2.0)}


def test_a_worker_that_keeps_dying_is_respawned_on_a_doubling_backoff(tmp_path: Path) -> None:
    """Recovery puts the row a worker died holding back at the head, so a row that kills its worker
    every time would otherwise loop with no pause. The first death waits nothing; each death after
    it doubles the wait, up to the cap; another lane keeps its own count."""
    runner = RegistryRunner(_registry(tmp_path), None, egress=EgressSettings(deny_by_default=False))  # type: ignore[arg-type]
    delays = [runner._respawn_delay(Stage.INGRESS, "IB") for _ in range(9)]
    assert delays[:4] == [0.0, 0.5, 1.0, 2.0]
    assert delays[-1] == stage_dispatcher._RESPAWN_BACKOFF_CAP_SECONDS
    assert runner._respawn_delay(Stage.INGRESS, "IB2") == 0.0
    assert runner._respawn_delay(Stage.ROUTED, "IB") == 0.0


# --- step 2: a node that is not the leader sends no re-pend RETRY -----------------------------------
# StageDispatcher._land_while_holding's docstring says why; the first write is always sent.


class _Lease(NullCoordinator):
    """A coordinator whose leadership the test flips."""

    def __init__(self) -> None:
        super().__init__()
        self.held = True

    def is_leader(self) -> bool:
        return self.held


async def _claimed_ingress_row(store: MessageStore) -> str:
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    item = await store.claim_next_fifo("IB", now=2.0, stage=Stage.INGRESS.value)
    assert item is not None
    return item.id


def _bare_dispatcher(store: MessageStore, **kwargs: Any) -> stage_dispatcher.StageDispatcher:
    return stage_dispatcher.StageDispatcher(
        Stage.INGRESS,
        store,
        process_item=None,  # type: ignore[arg-type]  # the retry under test never runs a body
        lane_provider=set,
        per_lane_limit=1,
        **kwargs,
    )


# Each case: (leader at the start, lose the lease during the first write, what the 3rd backoff does).
_LEASE_CASES = {
    "control-kept": (True, False, None),
    "lost-during-the-write-then-stop": (True, True, "stop"),
    "not-the-leader-from-the-start-then-stop": (False, False, "stop"),
    "lost-then-regained-with-no-teardown": (True, True, "regain"),
}


@pytest.mark.parametrize("case", list(_LEASE_CASES))
async def test_the_pooled_repend_retry_sends_nothing_while_not_the_leader(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    case: str,
) -> None:
    """The serializer's first re-pend fails, the store then heals. Kept lease (the control): the
    retry lands after one backoff. Not the leader, from the start or from the failing write on:
    the first write is still sent (ADR 0157 C1), then no retry while it lasts, one WARNING, and the
    stop the demotion teardown sends returns False with the row in flight. Leading again with no
    teardown resumes the retry, which lands."""
    _fast_backoffs(monkeypatch)
    leader, lose_in_write, third_backoff = _LEASE_CASES[case]
    lease = _Lease()
    lease.held = leader
    dispatcher = _bare_dispatcher(store, is_leader=lease.is_leader)
    row = await _claimed_ingress_row(store)
    writes = 0

    async def repend() -> None:
        nonlocal writes
        writes += 1
        if lose_in_write:
            lease.held = False
        if writes == 1:
            raise RuntimeError("simulated store outage in release_claimed")
        await store.release_claimed([row])

    backoffs = 0
    real_sleep = dispatcher._sleep_or_stop

    async def backoff(seconds: float) -> None:
        nonlocal backoffs
        backoffs += 1
        if backoffs == 3 and third_backoff == "regain":
            lease.held = True
        elif backoffs == 3 and third_backoff == "stop":
            dispatcher._stop.set()
        await real_sleep(seconds)

    monkeypatch.setattr(dispatcher, "_sleep_or_stop", backoff)
    with caplog.at_level(logging.WARNING):
        landed = await dispatcher._land_while_holding("IB", "release_claimed of 1 row(s)", repend)
    held_lines = caplog.text.count("this node is not the leader")
    if case == "control-kept":
        assert (landed, writes, backoffs, held_lines) == (True, 2, 1, 0)
    elif third_backoff == "regain":
        assert (landed, writes, backoffs, held_lines) == (True, 2, 3, 1)
    else:
        assert (landed, writes, backoffs, held_lines) == (False, 1, 3, 1)
    assert await _ingress_inflight(store) == (0 if landed else 1)


@pytest.mark.parametrize(
    "case",
    [
        "control-kept",
        "lost-during-the-backoff-then-stop",
        "not-the-leader-from-the-start-then-stop",
        "lost-then-regained",
    ],
)
async def test_the_per_lane_repend_retry_sends_nothing_while_not_the_leader(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """The per-lane twin. The first re-pend fails, on a non-leader too, and the store heals during
    the backoff after it. Kept lease (the control): the retry lands. Not the leader after that
    backoff: no retry is sent, and the teardown's stop returns True, so the caller returns rather
    than claiming past the held row. Lease regained with no teardown: the retry resumes and lands."""
    _fast_backoffs(monkeypatch)
    lease = _Lease()
    lease.held = case != "not-the-leader-from-the-start-then-stop"
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        coordinator=lease,
        egress=EgressSettings(deny_by_default=False),
    )
    row = await _claimed_ingress_row(store)
    calls: dict[str, int] = {}
    down = _fail_while(monkeypatch, store, "reschedule_claimed", calls)
    real_sleep = runner._stop_or_sleep
    backoffs = 0

    async def backoff(delay: float) -> bool:
        nonlocal backoffs
        backoffs += 1
        if backoffs == 1:
            down.clear()  # the store heals
            lease.held = case == "control-kept"
        elif backoffs == 3:
            if case == "lost-then-regained":
                lease.held = True
            else:
                runner._stop.set()
        return await real_sleep(delay)

    monkeypatch.setattr(runner, "_stop_or_sleep", backoff)
    stopped = await runner._repend_claimed_on_fault("router", "IB", [row])
    if case.endswith("-then-stop"):
        assert (stopped, calls["reschedule_claimed"], backoffs) == (True, 1, 3)
        assert await _ingress_inflight(store) == 1
    else:
        expected_backoffs = 1 if case == "control-kept" else 3
        assert (stopped, calls["reschedule_claimed"], backoffs) == (False, 2, expected_backoffs)
        assert await _ingress_inflight(store) == 0


async def test_the_runner_hands_its_coordinators_leadership_to_every_dispatcher(
    store: MessageStore, tmp_path: Path
) -> None:
    """``_make_dispatcher`` wires the coordinator's ``is_leader``, read live, so a demotion reaches a
    pooled serializer's retry. A dispatcher built without one is a single node: always the leader."""
    lease = _Lease()
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        claim_mode="pooled",
        coordinator=lease,
        egress=EgressSettings(deny_by_default=False),
    )
    for stage in Stage:
        dispatcher = runner._make_dispatcher(stage)
        lease.held = True
        assert dispatcher._is_leader() is True
        lease.held = False
        assert dispatcher._is_leader() is False
    assert _bare_dispatcher(store)._is_leader() is True


# --- step 2, review round 4: the respawn loop's ceiling, the stop, the park date, the warning ------


async def _ingress_status(store: MessageStore, mid: str) -> str | None:
    cur = await store._db.execute(
        "SELECT status FROM queue WHERE stage=? AND message_id=?", (Stage.INGRESS.value, mid)
    )
    row = await cur.fetchone()
    return None if row is None else str(row["status"])


@pytest.mark.parametrize("variant", ["capped", "control-uncapped"])
async def test_a_row_that_kills_its_worker_every_time_is_dead_lettered_at_the_g6_ceiling(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    """A's handoff kills the per-lane router worker with a ``BaseException`` EVERY time. Respawn
    recovery re-pends A at the head and the replacement re-claims it, so without a ceiling it dies
    again, forever, with B stuck behind it. The claim's ``attempts`` increment survives the reset,
    and the replacement of a worker that died meets the ADR 0057 G6 ceiling: at a finite cap of 3,
    A is dead-lettered on its third claim, the lane head clears, and B routes.

    ``control-uncapped`` (``max_attempts=None``, the ceiling off): A keeps killing the worker well
    past three deaths, is never dead-lettered, and B never routes."""
    _fast_backoffs(monkeypatch)
    monkeypatch.setattr(wiring_runner, "_RESPAWN_BACKOFF_BASE_SECONDS", 0.01)
    monkeypatch.setattr(wiring_runner, "_RESPAWN_BACKOFF_CAP_SECONDS", 0.02)
    cap = None if variant == "control-uncapped" else 3
    second: list[str] = []
    kills: list[str] = []
    a_box: list[str] = []

    async def kill_a(message_id: str) -> None:
        if not second:
            second.append(await store.enqueue_ingress(channel_id="IB", raw=RAW_B))
        if a_box and message_id == a_box[0]:
            kills.append(message_id)
            raise _Killed

    handed_off: list[str] = []
    _record_handoffs(monkeypatch, store, handed_off, before=kill_a)
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        claim_mode="per_lane",
        delivery_defaults=RetryPolicy(max_attempts=cap),
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        a = await store.enqueue_ingress(channel_id="IB", raw=RAW)
        a_box.append(a)
        runner.notify_work()
        if variant == "control-uncapped":

            async def looping() -> bool:
                return len(kills) >= 6

            await _until(looping)
            assert second and second[0] not in handed_off  # B is still stuck behind A
            assert await _ingress_status(store, a) in ("pending", "inflight")
            return

        async def b_routed() -> bool:
            return bool(second) and second[0] in handed_off

        await _until(b_routed)
        assert len(kills) == 2  # claims 1 and 2 killed the worker; claim 3 met the ceiling
        assert a not in handed_off
        assert await _ingress_status(store, a) == "dead"
        assert await _ingress_inflight(store) == 0
    finally:
        await runner.stop()


async def test_the_ceiling_judges_only_the_first_head_after_a_death_with_each_lanes_own_cap(
    store: MessageStore, tmp_path: Path
) -> None:
    """Unarmed (no death), a head is never judged whatever its attempts. Armed, only the first
    non-empty claim's HEAD is judged, once: the row behind it, which the batch claim charged too,
    is not. The inbound stages take ``retry_max_attempts``; an outbound lane takes its own retry
    policy; an inbound a reload removed keeps its row (its worker's missing-inbound path does)."""
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        delivery_defaults=RetryPolicy(max_attempts=2),
        egress=EgressSettings(deny_by_default=False),
    )
    runner._retry["OB"] = RetryPolicy(max_attempts=5)
    for raw in (RAW, RAW_B):
        await store.enqueue_ingress(channel_id="IB", raw=raw, now=1.0)
    for _ in range(2):  # two claim-and-reset rounds: both rows reach attempts 2
        await store.claim_next_fifo_batch("IB", stage=Stage.INGRESS.value, limit=2)
        await store.reset_stale_inflight(stage=Stage.INGRESS.value)
    items = await store.claim_next_fifo_batch("IB", stage=Stage.INGRESS.value, limit=2)
    assert [it.attempts for it in items] == [3, 3]

    judge = runner._dead_letter_head_after_death
    assert await judge(Stage.INGRESS, "IB", items[0]) is False  # unarmed: never judged
    runner._ceiling_armed.add((Stage.INGRESS.value, "IB"))
    assert await judge(Stage.INGRESS, "IB", items[0]) is True
    assert await _ingress_status(store, items[0].message_id) == "dead"
    assert await judge(Stage.INGRESS, "IB", items[1]) is False  # consumed by the first claim
    assert await _ingress_status(store, items[1].message_id) == "inflight"

    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=1.0)
    head = await store.claim_next_fifo("OB", now=2.0)
    assert head is not None
    under = dataclasses.replace(head, attempts=4)  # under OB's cap of 5, over retry_max_attempts
    runner._ceiling_armed.add((Stage.OUTBOUND.value, "OB"))
    assert await judge(Stage.OUTBOUND, "OB", under) is False
    runner._ceiling_armed.add((Stage.OUTBOUND.value, "OB"))
    assert await judge(Stage.OUTBOUND, "OB", dataclasses.replace(head, attempts=5)) is True

    runner._ceiling_armed.add((Stage.ROUTED.value, "GONE"))
    assert await judge(Stage.ROUTED, "GONE", items[1]) is False  # a removed inbound keeps it


async def test_a_stop_already_set_is_read_before_a_zero_delay(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Python 3.14 ``wait_for(event.wait(), 0)`` raises ``TimeoutError`` even on a SET event, so
    a zero-delay sleep used to report no stop. The first death of a lane waits 0 s, so a replacement
    spawned during shutdown then sent its reset anyway. It now sends nothing and runs no worker."""
    runner = RegistryRunner(
        _registry(tmp_path), store, egress=EgressSettings(deny_by_default=False)
    )
    runner._stop.set()
    assert await runner._stop_or_sleep(0.0) is True
    calls: dict[str, int] = {}
    _fail_once(monkeypatch, store, "reset_stale_inflight", calls)
    ran: list[str] = []

    async def worker(name: str) -> None:
        ran.append(name)

    await runner._recover_then_run(Stage.INGRESS, "IB", worker, died=True)
    assert (calls, ran) == ({}, [])
    dispatcher = _bare_dispatcher(store)
    dispatcher._stop.set()
    await asyncio.wait_for(dispatcher._sleep_or_stop(0.0), timeout=1.0)


def _lane_run(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, head: str, tail: list[str], when: float
) -> tuple[stage_dispatcher.StageDispatcher, list[Any]]:
    """A bare dispatcher whose serializer drained to a T17 RETRY: re-pend ``head`` dated ``when``
    and release ``tail``. Returns it and the list each applied RETRY outcome lands in."""
    dispatcher = _bare_dispatcher(store)
    outcome = stage_dispatcher._LaneOutcome(
        stage_dispatcher.LaneResultKind.RETRY, when, is_infra_fault=True
    )

    async def drained(lane: str, items: Any) -> Any:
        return outcome, tail, (head, when)

    applied: list[Any] = []
    monkeypatch.setattr(dispatcher, "_drain_lane", drained)
    monkeypatch.setattr(dispatcher, "_apply_retry", lambda lane, st, out: applied.append(out))
    dispatcher._states["IB"] = stage_dispatcher._LaneState()
    return dispatcher, applied


async def test_a_stop_during_the_head_retry_still_sends_the_tail_release_once(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The head's re-pend keeps failing and a stop lands during its backoff. Each write is sent at
    least once, so the tail release is still tried, and lands: the tail is pending again for the
    next start, the head stays in flight for its reset. Before, the stop returned first and the
    tail stayed in flight too."""
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    await store.enqueue_ingress(channel_id="IB", raw=RAW_B, now=1.0)
    head, tail = await store.claim_next_fifo_batch(
        "IB", stage=Stage.INGRESS.value, limit=2, now=2.0
    )
    calls: dict[str, int] = {}
    _fail_while(monkeypatch, store, "reschedule_claimed", calls)
    released: list[list[str]] = []
    real_release = store.release_claimed

    async def recording_release(ids: list[str]) -> Any:
        released.append(list(ids))
        return await real_release(ids)

    monkeypatch.setattr(store, "release_claimed", recording_release)
    dispatcher, applied = _lane_run(store, monkeypatch, head.id, [tail.id], time.time() + 60.0)

    async def stop_now(seconds: float) -> None:
        dispatcher._stop.set()

    monkeypatch.setattr(dispatcher, "_sleep_or_stop", stop_now)
    await dispatcher._run_lane("IB", [head, tail])
    assert calls["reschedule_claimed"] == 1
    assert released == [[tail.id]]
    assert await _ingress_status(store, tail.message_id) == "pending"
    assert await _ingress_status(store, head.message_id) == "inflight"
    assert applied == []  # stopped: no terminal transition


async def test_a_head_retry_that_overruns_its_date_parks_the_lane_until_the_date_written(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The head's re-pend fails once and the retry lands after ``when`` has passed, so the head is
    dated from now instead. The lane parks until that date, not the old ``when``, which would wake
    it at once for an empty claim."""
    _fast_backoffs(monkeypatch)
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    head = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value, now=2.0)
    assert head is not None
    calls: dict[str, int] = {}
    _fail_once(monkeypatch, store, "reschedule_claimed", calls)
    when = time.time() + 0.05
    dispatcher, applied = _lane_run(store, monkeypatch, head.id, [], when)
    real_sleep = dispatcher._sleep_or_stop

    async def overrun(seconds: float) -> None:
        await real_sleep(0.1)  # past `when`

    monkeypatch.setattr(dispatcher, "_sleep_or_stop", overrun)
    await dispatcher._run_lane("IB", [head])
    assert calls["reschedule_claimed"] == 2
    (outcome,) = applied
    cur = await store._db.execute("SELECT next_attempt_at FROM queue WHERE id=?", (head.id,))
    row = await cur.fetchone()
    assert row is not None
    assert outcome.park_until == pytest.approx(row["next_attempt_at"])
    assert outcome.park_until > when


async def test_a_second_leadership_loss_in_one_retry_warns_again(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Pooled and per-lane: the re-pend fails, the lease is lost (one WARNING), regained (the retry
    is sent and fails again), and lost again. The second loss warns too; before, it was silent."""
    _fast_backoffs(monkeypatch)
    lease = _Lease()
    dispatcher = _bare_dispatcher(store, is_leader=lease.is_leader)
    backoffs = 0

    def flip(stop: asyncio.Event) -> None:
        nonlocal backoffs
        backoffs += 1
        if backoffs in (1, 3):
            lease.held = False
        elif backoffs == 2:
            lease.held = True
        elif backoffs == 4:
            stop.set()

    async def failing() -> None:
        raise RuntimeError("simulated store outage")

    real_sleep = dispatcher._sleep_or_stop

    async def pooled_backoff(seconds: float) -> None:
        flip(dispatcher._stop)
        await real_sleep(seconds)

    monkeypatch.setattr(dispatcher, "_sleep_or_stop", pooled_backoff)
    with caplog.at_level(logging.WARNING):
        assert await dispatcher._land_while_holding("IB", "release_claimed", failing) is False
    assert caplog.text.count("this node is not the leader") == 2

    caplog.clear()
    backoffs = 0
    lease.held = True
    runner = RegistryRunner(
        _registry(tmp_path), store, coordinator=lease, egress=EgressSettings(deny_by_default=False)
    )
    row = await _claimed_ingress_row(store)
    _fail_while(monkeypatch, store, "reschedule_claimed", {})
    real_runner_sleep = runner._stop_or_sleep

    async def per_lane_backoff(delay: float) -> bool:
        flip(runner._stop)
        return await real_runner_sleep(delay)

    monkeypatch.setattr(runner, "_stop_or_sleep", per_lane_backoff)
    with caplog.at_level(logging.WARNING):
        assert await runner._repend_claimed_on_fault("router", "IB", [row]) is True
    assert caplog.text.count("this node is not the leader") == 2
