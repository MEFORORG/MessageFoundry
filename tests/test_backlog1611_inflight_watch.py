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
* ``route_handoff`` AND ``reschedule_claimed`` each raise once: the row strands. It still strands (part
  B ships no reclaim; see ``_check_inflight_strands``), and now the in-flight watch pages it.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import BuildupThreshold, ConnectorType, StallThreshold
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
    runner = RegistryRunner(_registry(tmp_path), store, alert_sink=sink)
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
    runner = RegistryRunner(_registry(tmp_path), store, alert_sink=_RecordingSink())
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
        reg, store, alert_sink=sink, buildup_default=BuildupThreshold(max_oldest_seconds=60.0)
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
        _registry(tmp_path), store, claim_mode="pooled", pooled_sweep_interval=0.05
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


async def test_pooled_double_fault_strands_and_the_watch_pages_it(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """P3-03's second pooled row: ``route_handoff`` AND ``reschedule_claimed`` each raise once. T17's
    own re-pend fails, so the row stays ``inflight``, and ``pending_depth`` reads the lane empty.

    It STILL strands after part B, by design: no reclaim shipped, because the pooled serializer holds
    claimed rows this runner cannot see, and re-pending a held row sends it twice. What changed is that
    the strand now pages. If a safe reclaim ever lands, this test is the one to flip: the row should
    then route instead of staying in flight."""
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 0.01)
    monkeypatch.setattr(wiring_runner, "_INFLIGHT_WATCH_INTERVAL_SECONDS", 0.05)
    calls: dict[str, int] = {}
    _fail_once(monkeypatch, store, "route_handoff", calls)
    _fail_once(monkeypatch, store, "reschedule_claimed", calls)
    sink = _RecordingSink()
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        alert_sink=sink,
        buildup_default=BuildupThreshold(max_oldest_seconds=0.3),
        claim_mode="pooled",
        pooled_sweep_interval=0.05,
    )
    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.start()
        try:
            mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
            runner._dispatchers[Stage.INGRESS].mark_ready("IB")

            async def paged() -> bool:
                return "held in flight on ingress lane 'IB'" in caplog.text

            await _until(paged)
            # Both faults fired, once each, and nothing retried the row after them.
            assert calls == {"route_handoff": 1, "reschedule_claimed": 1}
            msg = await store.get_message(mid)
            assert msg is not None and msg["status"] == MessageStatus.RECEIVED.value
            assert await _ingress_inflight(store) == 1
            assert await store.pending_depth("IB", stage=Stage.INGRESS.value) == (0, None)
            assert any(name == "IB" and depth == 1 for name, depth, _ in sink.buildup)
        finally:
            await runner.stop()
