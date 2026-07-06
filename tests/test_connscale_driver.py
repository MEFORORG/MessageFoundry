# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale driver (B11) — the aggregate token bucket fans evenly across the N connections."""

from __future__ import annotations

import asyncio

import pytest

from harness.load.connscale.driver import ConnScaleDriver
from harness.load.corpus import build_corpus
from harness.load.correlator import Correlator
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import LoadProfile, Phase, TypeMix

_MIX = TypeMix({"ADT^A01": 1.0})


def _driver_with_fakes(count: int) -> tuple[ConnScaleDriver, list[list]]:
    """A driver whose N PersistentConnections are replaced by fakes that just record each submission,
    so we can assert the round-robin spread without a real engine/socket."""
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(10_000, metrics)
    driver = ConnScaleDriver(
        host="127.0.0.1",
        base_port=2600,
        count=count,
        correlator=correlator,
        metrics=metrics,
    )

    sent_per_conn: list[list] = [[] for _ in range(count)]

    class _FakeConn:
        def __init__(self, idx: int) -> None:
            self._idx = idx

        def submit_nowait(self, out, on_done=None):  # type: ignore[no-untyped-def]
            sent_per_conn[self._idx].append(out.seq)
            return True

    driver._conns = [_FakeConn(i) for i in range(count)]  # type: ignore[assignment]
    return driver, sent_per_conn


def test_round_robin_spreads_evenly_across_connections() -> None:
    count = 10
    driver, sent = _driver_with_fakes(count)
    ids = ControlIds(prefix="DT")
    corpus = build_corpus(
        LoadProfile(
            name="c",
            description="",
            targets=(),
            phases=(
                Phase(name="h", kind="sustained", loop="open", duration_s=1.0, rate_start=1.0),
            ),
            default_mix=_MIX,
            corpus_count_per_trigger=5,
        ),
        ids,
    )

    async def drive() -> None:
        # A high aggregate rate over a short hold → many sends spread across the 10 connections.
        await driver.run_hold(corpus=corpus, mix=_MIX, aggregate_rate=2000.0, hold_seconds=0.3)

    asyncio.run(drive())

    counts = [len(c) for c in sent]
    total = sum(counts)
    assert total > 0
    # Round-robin: every connection got at least one send, and the spread is even (max-min <= 1 by
    # construction of the round-robin cursor).
    assert all(n > 0 for n in counts), counts
    assert max(counts) - min(counts) <= 1, counts


def test_open_batches_do_not_raise_with_zero_pause() -> None:
    # A driver of a few real (unconnected) connections opens in batches without raising; each
    # connection's reconnect loop just backs off against the closed port. Then stop cleanly.
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(1000, metrics)
    driver = ConnScaleDriver(
        host="127.0.0.1", base_port=59000, count=5, correlator=correlator, metrics=metrics
    )
    assert driver.ports == [59000, 59001, 59002, 59003, 59004]

    async def run() -> None:
        await driver.open(connect_batch=2, batch_pause_s=0.0)
        await asyncio.sleep(0.05)
        await driver.stop(0.1)

    asyncio.run(run())


def test_rejects_zero_count() -> None:
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(1000, metrics)
    with pytest.raises(ValueError, match=">= 1"):
        ConnScaleDriver(
            host="127.0.0.1", base_port=2600, count=0, correlator=correlator, metrics=metrics
        )
