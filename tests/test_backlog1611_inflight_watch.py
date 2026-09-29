# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1611 part B (Fable packet 3, finding P3-03): a row stranded in flight is visible.

A claim is its own committed transaction, so a store fault between the claim and the handoff leaves
the row ``inflight``. Part A (PR 1164) made the per-lane workers re-pend it, and the pooled dispatcher
already did (T17), but both re-pends are store writes that can fail as well. What is left is recovered
by ``reset_stale_inflight`` at the next start and by nothing before it, and it was invisible:
``pending_depth`` counts pending rows only, and the buildup and stall checks run only from a lane's own
processing path, which a strand has stopped.

This file covers the read (``inflight_by_lane``) and the runner's in-flight watch that pages on it.
"""

from __future__ import annotations

import logging
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
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage

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
