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

Step 2 part A recovers it with no restart and no clock: a holder whose re-pend fails retries it
while it holds the lane, leader-gated after the first write. The last tests show it in both claim
modes, in FIFO order, with a control that restores the one-shot re-pend and goes red; the leader
gate; and a prompt stop. A worker killed by a ``BaseException`` still strands its row until the next
start, as before; recovering it at the worker's respawn is part B, not here.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import ANY

import pytest

from messagefoundry.config.models import (
    BatchConfig,
    BuildupThreshold,
    ConnectorType,
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
from messagefoundry.pipeline.stage_dispatcher import HoldResult, RependFence
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
        self: RegistryRunner, worker: str, name: str, ids: Any, **_k: Any
    ) -> HoldResult:
        with contextlib.suppress(Exception):
            await self.store.reschedule_claimed(
                list(ids), time.time() + wiring_runner._WORKER_ERROR_BACKOFF_SECONDS
            )
        return HoldResult.LANDED

    async def once_pooled(self: Any, lane: str, what: str, write: Any, fence: Any) -> HoldResult:
        with contextlib.suppress(Exception):
            await write()
        return HoldResult.LANDED

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


@pytest.mark.parametrize("variant", ["shipped", "control-ignores-stop"])
async def test_a_stop_during_the_batch_extras_hold_ends_the_pass_promptly(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    """The pooled batch guard re-pends the coalesced extras itself, now holding the lane until that
    lands. A stop during its 30 s backoff must end the hold at once: the guard re-raises the batch's
    fault, so the dispatcher's T17 arm still owns the head, and the extras stay in flight for the
    next start. The control makes the backoff deaf to the stop; the pass then outlives it."""
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 30.0)
    runner = RegistryRunner(
        _registry(tmp_path), store, egress=EgressSettings(deny_by_default=False)
    )
    for _ in range(3):
        await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=1.0)
    head = await store.claim_next_fifo("OB", now=2.0)
    assert head is not None
    calls: dict[str, int] = {}
    _fail_while(monkeypatch, store, "reschedule_claimed", calls)

    async def coalesce_then_fault(name: str, cfg: Any, items: list[Any]) -> Any:
        for _ in range(2):
            more = await store.claim_next_fifo(name, now=2.0)
            assert more is not None
            items.append(more)
        raise RuntimeError("simulated store fault after coalescing")

    monkeypatch.setattr(runner, "_deliver_coalesced_batch", coalesce_then_fault)
    if variant == "control-ignores-stop":
        real_sleep = runner._stop_or_sleep

        async def deaf(delay: float) -> bool:
            await asyncio.sleep(delay)
            return await real_sleep(0.0)

        monkeypatch.setattr(runner, "_stop_or_sleep", deaf)
    cfg = BatchConfig(max_count=3, max_wait_ms=1)
    task = asyncio.ensure_future(runner._process_delivery_batch("OB", head, cfg))

    async def holding() -> bool:
        return calls.get("reschedule_claimed", 0) >= 1

    await _until(holding)
    runner._stop.set()
    if variant == "control-ignores-stop":
        done, _ = await asyncio.wait({task}, timeout=0.5)
        assert not done  # the hold outlived the stop: the case this test exists to catch
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return
    with pytest.raises(RuntimeError, match="simulated store fault after coalescing"):
        await asyncio.wait_for(task, timeout=5.0)
    assert calls["reschedule_claimed"] == 1  # no retry ran after the stop
    assert await store.inflight_by_lane(stage=Stage.OUTBOUND.value) == {"OB": (3, 2.0)}


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
    fence = RependFence.capture(lease.is_leader, lease.current_epoch)
    with caplog.at_level(logging.WARNING):
        held = await dispatcher._land_while_holding(
            "IB", "release_claimed of 1 row(s)", repend, fence
        )
    held_lines = caplog.text.count("this node is not the leader")
    landed, stopped = HoldResult.LANDED, HoldResult.STOPPED
    if case == "control-kept":
        assert (held, writes, backoffs, held_lines) == (landed, 2, 1, 0)
    elif third_backoff == "regain":
        assert (held, writes, backoffs, held_lines) == (landed, 2, 3, 1)
    else:
        assert (held, writes, backoffs, held_lines) == (stopped, 1, 3, 1)
    assert await _ingress_inflight(store) == (0 if held is landed else 1)


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
    held = await runner._repend_claimed_on_fault("router", "IB", [row])
    if case.endswith("-then-stop"):
        assert (held, calls["reschedule_claimed"], backoffs) == (HoldResult.STOPPED, 1, 3)
        assert await _ingress_inflight(store) == 1
    else:
        expected_backoffs = 1 if case == "control-kept" else 3
        assert (held, calls["reschedule_claimed"], backoffs) == (
            HoldResult.LANDED,
            2,
            expected_backoffs,
        )
        assert await _ingress_inflight(store) == 0


async def test_the_runner_hands_its_coordinators_leadership_to_every_dispatcher(
    store: MessageStore, tmp_path: Path
) -> None:
    """``_make_dispatcher`` wires the coordinator's ``is_leader`` and ``current_epoch``, read live,
    so a demotion or a new lease reaches a pooled serializer's retry. A dispatcher built without
    them is a single node: always the leader, with no epoch."""
    lease = _EpochLease()
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
        lease.epoch = 12
        assert dispatcher._current_epoch() == 12
        lease.held = False
        assert dispatcher._is_leader() is False
        assert dispatcher._current_epoch() is None
    assert _bare_dispatcher(store)._is_leader() is True
    assert _bare_dispatcher(store)._current_epoch() is None


# --- step 2: the stop, the park date, the warning ------------------------------------------


async def _ingress_status(store: MessageStore, mid: str) -> str | None:
    cur = await store._db.execute(
        "SELECT status FROM queue WHERE stage=? AND message_id=?", (Stage.INGRESS.value, mid)
    )
    row = await cur.fetchone()
    return None if row is None else str(row["status"])


async def test_a_stop_already_set_is_read_before_a_zero_delay(store: MessageStore) -> None:
    """On Python 3.14 ``wait_for(event.wait(), 0)`` raises ``TimeoutError`` even on a SET event,
    so a zero-delay sleep would report no stop. The dispatcher's ``_sleep_or_stop`` reads a set
    stop first, so a held lane's retry ends at once on a stop."""
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


@pytest.mark.parametrize("leader", [True, False])
async def test_a_stop_during_the_head_retry_still_sends_the_tail_release_once(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    leader: bool,
) -> None:
    """The head's re-pend keeps failing and a stop lands during its backoff. On the leader the
    tail release is still sent once, and lands: the tail is pending again for the next start, the
    head stays in flight for its reset. Before, the stop returned first and the tail stayed in
    flight too. Not the leader, the late write is not sent, since a successor may hold the rows.
    Either way a WARNING names the rows left in flight, which quiesce cannot see."""
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
    monkeypatch.setattr(dispatcher, "_is_leader", lambda: leader)
    with caplog.at_level(logging.WARNING):
        await dispatcher._run_lane("IB", [head, tail])
    assert calls["reschedule_claimed"] == 1
    assert released == ([[tail.id]] if leader else [])
    expected_tail = "pending" if leader else "inflight"
    assert await _ingress_status(store, tail.message_id) == expected_tail
    assert await _ingress_status(store, head.message_id) == "inflight"
    assert applied == []  # stopped: no terminal transition
    held = 1 if leader else 2
    assert f"stopped while holding {held} claimed row(s)" in caplog.text


async def test_a_held_lane_pages_lane_stuck_once_at_the_infra_fault_bound(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under ``retry_forever`` a held lane never reaches ``_apply_retry``, so the ADR 0070 streak
    cannot page it. The hold raises one ``lane_stuck`` at ``infra_fault_stop_after`` consecutive
    failures, not one per failure after it, and goes on holding."""
    _fast_backoffs(monkeypatch)
    sink = _RecordingSink()
    stuck: list[str] = []
    monkeypatch.setattr(sink, "lane_stuck", lambda name, *, detail: stuck.append(detail))
    dispatcher = _bare_dispatcher(
        store, alert_sink=sink, infra_fault_stop_after=3, infra_fault_policy="retry_forever"
    )
    fence = RependFence.capture(dispatcher._is_leader, dispatcher._current_epoch)
    landed = HoldResult.LANDED
    failures = 0

    async def failing() -> None:
        nonlocal failures
        failures += 1
        if failures <= 5:
            raise RuntimeError("simulated store outage")

    dispatcher._states["IB"] = stage_dispatcher._LaneState()
    assert await dispatcher._land_while_holding("IB", "release_claimed", failing, fence) is landed
    assert failures == 6
    assert len(stuck) == 1 and "failed 3 consecutive times" in stuck[0]
    # Marked alerted, so _apply_retry's retry_forever page does not repeat it this episode.
    assert dispatcher._states["IB"].lane_stuck_alerted is True

    def broken(name: str, *, detail: str) -> None:
        raise RuntimeError("simulated alert sink fault")

    # A second hold in the same episode (the tail's, after the head's) does not page again.
    failures = 0
    assert await dispatcher._land_while_holding("IB", "release_claimed", failing, fence) is landed
    assert len(stuck) == 1

    monkeypatch.setattr(sink, "lane_stuck", broken)
    failures = 0
    dispatcher._states["IB"].lane_stuck_alerted = False  # a new episode
    # A raising sink is logged, never raised: the serializer still holds the lane.
    assert await dispatcher._land_while_holding("IB", "release_claimed", failing, fence) is landed


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
    is sent and fails again), and lost again. The second loss warns too; before, it was silent.
    Every backoff is one base step, so each sleep below is one backoff."""
    _fast_backoffs(monkeypatch)
    monkeypatch.setattr(stage_dispatcher, "_REPEND_RETRY_CAP_SECONDS", 0.01)
    monkeypatch.setattr(wiring_runner, "_REPEND_RETRY_CAP_SECONDS", 0.01)
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
        fence = RependFence.capture(lease.is_leader, lease.current_epoch)
        held = await dispatcher._land_while_holding("IB", "release_claimed", failing, fence)
    assert held is HoldResult.STOPPED
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
        held = await runner._repend_claimed_on_fault("router", "IB", [row])
    assert held is HoldResult.STOPPED
    assert caplog.text.count("this node is not the leader") == 2


# --- step 2: how a hold ends short of landing (the Lander's hold on PR 2574, F1 F3 F12) -----------


class _EpochLease(_Lease):
    """A lease with an epoch, bumped by the test when another node takes it. ``None`` while not
    held, as the clustered coordinators return after a demotion."""

    def __init__(self) -> None:
        super().__init__()
        self.epoch = 7

    def current_epoch(self) -> int | None:
        return self.epoch if self.held else None


@pytest.mark.parametrize("variant", ["shipped", "control-ignores-the-epoch"])
async def test_a_pooled_retry_after_another_node_led_is_not_sent(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    variant: str,
) -> None:
    """F1. The head's re-pend fails and this node loses the lease during it. Another node leads
    (the epoch moves) and this node leads again with no teardown, under the newer epoch. The
    successor may have claimed these rows, so the retry is not sent, the tail release is skipped,
    and the serializer runs its terminal transition rather than leave the lane held. The control
    ignores the epoch: the retry is sent, the duplicate-send path the fence closes."""
    _fast_backoffs(monkeypatch)
    if variant == "control-ignores-the-epoch":
        monkeypatch.setattr(RependFence, "superseded", lambda self: False)
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    await store.enqueue_ingress(channel_id="IB", raw=RAW_B, now=1.0)
    head, tail = await store.claim_next_fifo_batch(
        "IB", stage=Stage.INGRESS.value, limit=2, now=2.0
    )
    lease = _EpochLease()
    real_reschedule = store.reschedule_claimed
    writes = 0

    async def flapping_write(ids: list[str], when: float) -> Any:
        nonlocal writes
        writes += 1
        if writes == 1:
            lease.held = False  # demoted while the first write hangs, then it fails
            raise RuntimeError("simulated store outage in reschedule_claimed")
        return await real_reschedule(ids, when)

    monkeypatch.setattr(store, "reschedule_claimed", flapping_write)
    released: list[list[str]] = []
    real_release = store.release_claimed

    async def recording_release(ids: list[str]) -> Any:
        released.append(list(ids))
        return await real_release(ids)

    monkeypatch.setattr(store, "release_claimed", recording_release)
    dispatcher, applied = _lane_run(store, monkeypatch, head.id, [tail.id], time.time() + 60.0)
    monkeypatch.setattr(dispatcher, "_is_leader", lease.is_leader)
    monkeypatch.setattr(dispatcher, "_current_epoch", lease.current_epoch)
    real_sleep = dispatcher._sleep_or_stop
    sleeps = 0

    async def backoff(seconds: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps == 2:  # another node led meanwhile; this one leads again, under a newer epoch
            lease.held, lease.epoch = True, 8
        await real_sleep(seconds)

    monkeypatch.setattr(dispatcher, "_sleep_or_stop", backoff)
    with caplog.at_level(logging.WARNING):
        await asyncio.wait_for(dispatcher._run_lane("IB", [head, tail]), timeout=5.0)
    assert len(applied) == 1  # the terminal transition ran: the lane is not left held
    if variant == "control-ignores-the-epoch":
        assert writes == 2  # the retry re-pended rows the successor may hold
        assert released == [[tail.id]]
        return
    assert writes == 1
    assert released == []
    assert await _ingress_status(store, head.message_id) == "inflight"
    assert await _ingress_status(store, tail.message_id) == "inflight"
    assert "stopped holding 2 claimed row(s)" in caplog.text and "(superseded)" in caplog.text


@pytest.mark.parametrize("variant", ["shipped", "control-ignores-the-epoch"])
async def test_a_per_lane_retry_after_another_node_led_is_not_sent(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    """F1, per-lane. As the pooled case: the worker sends no retry after leading again under a
    newer epoch, and returns ``SUPERSEDED`` so its loop goes on, as it did after one failed write.
    A node that was not the leader at the fault cannot tell who led since, and sends none either."""
    _fast_backoffs(monkeypatch)
    if variant == "control-ignores-the-epoch":
        monkeypatch.setattr(RependFence, "superseded", lambda self: False)
    lease = _EpochLease()
    runner = RegistryRunner(
        _registry(tmp_path), store, coordinator=lease, egress=EgressSettings(deny_by_default=False)
    )
    row = await _claimed_ingress_row(store)
    calls: dict[str, int] = {}
    down = _fail_while(monkeypatch, store, "reschedule_claimed", calls)
    real_sleep = runner._stop_or_sleep
    sleeps = 0

    async def backoff(delay: float) -> bool:
        nonlocal sleeps
        sleeps += 1
        if sleeps == 1:
            down.clear()
            lease.held = False
        elif sleeps == 2:
            lease.held, lease.epoch = True, 8
        return await real_sleep(delay)

    monkeypatch.setattr(runner, "_stop_or_sleep", backoff)
    held = await asyncio.wait_for(
        runner._repend_claimed_on_fault("router", "IB", [row]), timeout=5.0
    )
    if variant == "control-ignores-the-epoch":
        assert (held, calls["reschedule_claimed"]) == (HoldResult.LANDED, 2)
        return
    assert (held, calls["reschedule_claimed"]) == (HoldResult.SUPERSEDED, 1)
    assert await _ingress_inflight(store) == 1

    # Not the leader at the fault: no epoch was captured, so regaining any lease sends nothing.
    lease.held, lease.epoch, sleeps = False, 9, 1
    down.set()
    held = await asyncio.wait_for(
        runner._repend_claimed_on_fault("router", "IB", [row]), timeout=5.0
    )
    assert (held, calls["reschedule_claimed"]) == (HoldResult.SUPERSEDED, 2)


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
@pytest.mark.parametrize("variant", ["shipped", "control-deaf-to-the-pause"])
async def test_a_pause_ends_a_held_delivery_lane_so_purge_is_not_refused(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    claim_mode: str,
    variant: str,
) -> None:
    """F3. The delivery of an outbound row faults and its re-pend keeps failing, so the lane is
    held on a 30 s backoff. An operator stop of the outbound must end the hold within about the
    base interval, not when the store heals: the lane quiesces (``outbound_quiesced``, the purge
    precondition) within 2 s, PAUSED in the pooled claim mode, and the per-lane worker keeps
    running, parked at its pause gate. The row stays in flight, as one failed write left it before
    step 2. The control removes the pause check, and the hold outlives the 2 s."""
    _fast_backoffs(monkeypatch)
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 0.05)
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.05)
    # Every backoff 30 s, so only the pause can end the hold inside the test.
    monkeypatch.setattr(stage_dispatcher, "_capped_backoff", lambda base, exp, cap: 30.0)
    monkeypatch.setattr(wiring_runner, "_capped_backoff", lambda base, exp, cap: 30.0)
    if variant == "control-deaf-to-the-pause":
        monkeypatch.setattr(
            stage_dispatcher.StageDispatcher, "_hold_abandoned", lambda self, lane: False
        )
        real_repend = RegistryRunner._repend_claimed_on_fault

        async def deaf(self: RegistryRunner, *a: Any, abandon: Any = None, **k: Any) -> Any:
            return await real_repend(self, *a, **k)

        monkeypatch.setattr(RegistryRunner, "_repend_claimed_on_fault", deaf)
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        claim_mode=claim_mode,
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
    )

    async def faulting_delivery(name: str, item: Any) -> Any:
        raise RuntimeError("simulated store fault in the delivery handoff")

    monkeypatch.setattr(runner, "_process_delivery_item", faulting_delivery)
    calls: dict[str, int] = {}
    _fail_while(monkeypatch, store, "reschedule_claimed", calls)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=1.0)
    await runner.start()
    try:
        runner.notify_work()

        async def holding() -> bool:
            return calls.get("reschedule_claimed", 0) >= 1

        await _until(holding)
        await asyncio.sleep(0.2)  # inside the 30 s backoff
        await runner.stop_outbound("OB")

        async def quiesced() -> bool:
            return runner.outbound_quiesced("OB")

        if variant == "control-deaf-to-the-pause":
            with pytest.raises(AssertionError, match="timed out"):
                await _until(quiesced, timeout=2.0)
            return
        await _until(quiesced, timeout=2.0)
        assert calls["reschedule_claimed"] == 1  # the hold sent no retry after the pause
        assert await store.inflight_by_lane(stage=Stage.OUTBOUND.value) == {"OB": (1, ANY)}
        if claim_mode == "pooled":
            dispatcher = runner._dispatchers[Stage.OUTBOUND]
            assert dispatcher._states["OB"].phase is stage_dispatcher._LanePhase.PAUSED
        else:
            assert not runner._workers["OB"].done()  # the worker lives on, at its pause gate
    finally:
        await runner.stop()


class _StopSink(LoggingAlertSink):
    def __init__(self) -> None:
        self.stopped: list[str] = []
        self.stuck: list[str] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append(detail)

    def lane_stuck(self, name: str, *, detail: str) -> None:
        self.stuck.append(detail)


@pytest.mark.parametrize("made_progress", [False, True])
@pytest.mark.parametrize("policy", ["stop", "retry_forever"])
async def test_the_stop_policy_bounds_a_held_lane_and_retry_forever_pages_it(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, policy: str, made_progress: bool
) -> None:
    """F12. The head's re-pend keeps failing. Under ``stop`` (the default) the hold ends at
    ``infra_fault_stop_after`` failures and the lane reaches STOPPED with ``connection_stopped``,
    as a persistent T17 fault does, and no ``lane_stuck``, whatever progress the prefix made before
    the fault. Under ``retry_forever`` it pages ``lane_stuck`` once and holds on until the store
    heals, then parks; it never STOPs."""
    _fast_backoffs(monkeypatch)
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    head = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value, now=2.0)
    assert head is not None
    calls: dict[str, int] = {}
    down = _fail_while(monkeypatch, store, "reschedule_claimed", calls)
    sink = _StopSink()
    own_stops: list[str] = []
    dispatcher = _bare_dispatcher(
        store,
        alert_sink=sink,
        infra_fault_policy=policy,
        infra_fault_stop_after=3,
        on_lane_stopped=own_stops.append,
        call_later=asyncio.get_running_loop().call_later,  # a park arms its timer
    )
    outcome = stage_dispatcher._LaneOutcome(
        stage_dispatcher.LaneResultKind.RETRY,
        time.time() + 60.0,
        is_infra_fault=True,
        made_progress=made_progress,
    )

    async def drained(lane: str, items: Any) -> Any:
        return outcome, [], (head.id, time.time() + 60.0)

    monkeypatch.setattr(dispatcher, "_drain_lane", drained)
    st = stage_dispatcher._LaneState(phase=stage_dispatcher._LanePhase.PROCESSING)
    dispatcher._states["IB"] = st
    if policy == "retry_forever":
        real_sleep = dispatcher._sleep_or_stop

        async def heal_after_five(seconds: float) -> None:
            if calls["reschedule_claimed"] >= 5:
                down.clear()
            await real_sleep(seconds)

        monkeypatch.setattr(dispatcher, "_sleep_or_stop", heal_after_five)
    await asyncio.wait_for(dispatcher._run_lane("IB", [head]), timeout=5.0)
    if policy == "stop":
        assert calls["reschedule_claimed"] == 3
        assert st.phase is stage_dispatcher._LanePhase.STOPPED
        assert len(sink.stopped) == 1 and own_stops == ["IB"]
        assert sink.stuck == []
        assert await _ingress_status(store, head.message_id) == "inflight"
    else:
        assert calls["reschedule_claimed"] == 6
        assert st.phase is stage_dispatcher._LanePhase.PARKED
        dispatcher._cancel_timer("IB")
        assert sink.stopped == [] and own_stops == []
        assert len(sink.stuck) == 1 and "failed 3 consecutive times" in sink.stuck[0]
        assert await _ingress_status(store, head.message_id) == "pending"


@pytest.mark.parametrize("variant", ["shipped", "control-unfenced-tail"])
async def test_the_tail_release_after_a_landed_head_is_fenced(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    """The head's re-pend hangs while another node takes the lease, then commits. The tail
    release that follows is no longer at fault time, and the successor may hold those rows, so it
    is not sent. The control lets it through, the duplicate-send path."""
    _fast_backoffs(monkeypatch)
    if variant == "control-unfenced-tail":
        monkeypatch.setattr(RependFence, "may_write", lambda self: True)
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    await store.enqueue_ingress(channel_id="IB", raw=RAW_B, now=1.0)
    head, tail = await store.claim_next_fifo_batch(
        "IB", stage=Stage.INGRESS.value, limit=2, now=2.0
    )
    lease = _EpochLease()
    real_reschedule = store.reschedule_claimed

    async def slow_write(ids: list[str], when: float) -> Any:
        lease.epoch = 8  # another node took the lease while the write hung; it then commits
        return await real_reschedule(ids, when)

    monkeypatch.setattr(store, "reschedule_claimed", slow_write)
    released: list[list[str]] = []

    async def recording_release(ids: list[str]) -> Any:
        released.append(list(ids))

    monkeypatch.setattr(store, "release_claimed", recording_release)
    dispatcher, applied = _lane_run(store, monkeypatch, head.id, [tail.id], time.time() + 60.0)
    monkeypatch.setattr(dispatcher, "_is_leader", lease.is_leader)
    monkeypatch.setattr(dispatcher, "_current_epoch", lease.current_epoch)
    await asyncio.wait_for(dispatcher._run_lane("IB", [head, tail]), timeout=5.0)
    assert len(applied) == 1
    assert released == ([[tail.id]] if variant == "control-unfenced-tail" else [])


async def test_a_lease_change_during_the_body_fences_the_retry(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pooled fence is read before the body runs, not at the fault: a lease change while the
    body ran, then a failed first re-pend, sends no retry."""
    _fast_backoffs(monkeypatch)
    head_id = await _claimed_ingress_row(store)
    lease = _EpochLease()
    calls: dict[str, int] = {}
    _fail_while(monkeypatch, store, "reschedule_claimed", calls)
    dispatcher, applied = _lane_run(store, monkeypatch, head_id, [], time.time() + 60.0)
    monkeypatch.setattr(dispatcher, "_is_leader", lease.is_leader)
    monkeypatch.setattr(dispatcher, "_current_epoch", lease.current_epoch)
    drained = dispatcher._drain_lane

    async def body_spans_a_flap(lane: str, items: Any) -> Any:
        lease.epoch = 8
        return await drained(lane, items)

    monkeypatch.setattr(dispatcher, "_drain_lane", body_spans_a_flap)
    await asyncio.wait_for(dispatcher._run_lane("IB", []), timeout=5.0)
    assert calls["reschedule_claimed"] == 1
    assert len(applied) == 1


async def test_a_pause_that_wins_over_the_stop_bound_leaves_the_streak_alone(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under ``stop`` the hold reaches its bound just as an operator pause lands. The lane goes
    PAUSED, not STOPPED, and its infra-fault streak is untouched, so after a resume the next single
    T17 fault does not STOP it at once."""
    _fast_backoffs(monkeypatch)
    head_id = await _claimed_ingress_row(store)
    sink = _StopSink()
    paused: list[str] = []
    dispatcher = stage_dispatcher.StageDispatcher(
        Stage.OUTBOUND,
        store,
        process_item=None,  # type: ignore[arg-type]  # the drain is stubbed
        lane_provider=set,
        per_lane_limit=1,
        alert_sink=sink,
        infra_fault_policy="stop",
        infra_fault_stop_after=3,
        on_lane_paused=paused.append,
    )
    st = stage_dispatcher._LaneState(phase=stage_dispatcher._LanePhase.PROCESSING)
    dispatcher._states["OB"] = st
    outcome = stage_dispatcher._LaneOutcome(
        stage_dispatcher.LaneResultKind.RETRY, time.time() + 60.0, is_infra_fault=True
    )

    async def drained(lane: str, items: Any) -> Any:
        return outcome, [], (head_id, time.time() + 60.0)

    monkeypatch.setattr(dispatcher, "_drain_lane", drained)
    writes = 0

    async def failing(ids: list[str], when: float) -> Any:
        nonlocal writes
        writes += 1
        if writes == 3:
            dispatcher.pause_lane("OB")  # PROCESSING, so it is marked pending
        raise RuntimeError("simulated store outage in reschedule_claimed")

    monkeypatch.setattr(store, "reschedule_claimed", failing)
    await asyncio.wait_for(dispatcher._run_lane("OB", []), timeout=5.0)
    assert writes == 3
    assert st.phase is stage_dispatcher._LanePhase.PAUSED and paused == ["OB"]
    assert sink.stopped == []
    assert st.infra_error_streak == 0
