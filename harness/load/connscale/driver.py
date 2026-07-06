# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The connection-scale driver — N persistent MLLP connections, one aggregate token bucket (B11).

Where :class:`~harness.load.sender.Dispatcher` spreads by message *type* across a pool (the wrong
axis for B11), :class:`ConnScaleDriver` owns **N** :class:`~harness.load.sender.PersistentConnection`
s mapped 1:1 onto the N inbound MLLP ports (``base_port + i``), and meters them with a **single
aggregate token bucket** (lifted from :class:`~harness.load.governor.RateGovernor._run_open`) that
emits the total offered rate ``R`` and **round-robins each due send across the N connections** — so
every connection gets ~``R / N`` msg/s on average with O(1) scheduling overhead on the harness side.

Why one bucket, not N timers: N=1500 independent ``sleep(1/rate)`` tasks would swamp the *driver's*
own event loop and confound the measurement. One bucket + round-robin yields the same per-connection
mean rate without the scheduling overhead.

Connections open in **batches** (``connect_batch``) with a short inter-batch pause to avoid a connect
thundering-herd polluting the steady-state measurement; stop is cooperative + graced, mirroring
:meth:`ConnectionPool.stop`.
"""

from __future__ import annotations

import asyncio

from harness.load.corpus import Corpus, Outgoing
from harness.load.correlator import Correlator
from harness.load.metrics import LiveMetrics
from harness.load.profile import TypeMix
from harness.load.sender import PersistentConnection

_BATCH_CAP = 4096  # max sends emitted in one token-bucket tick (bounds catch-up after a stall)
_MAX_TICK_SLEEP = 0.05
_IDLE_SLEEP = 0.02


class ConnScaleDriver:
    """Owns N persistent MLLP connections (one per inbound port) and drives them at an aggregate rate.

    The N connections share one :class:`~harness.load.correlator.Correlator` + :class:`LiveMetrics`,
    so the per-message send→ACK timing and the no-loss reconcile aggregate across all N exactly as the
    load runner does for its pool.
    """

    def __init__(
        self,
        *,
        host: str,
        base_port: int,
        count: int,
        correlator: Correlator,
        metrics: LiveMetrics,
        queue_max: int = 256,
    ) -> None:
        if count < 1:
            raise ValueError("connection count must be >= 1")
        self._host = host
        self._base_port = base_port
        self._count = count
        self._m = metrics
        # One persistent, pipelined connection per inbound port; expect_ack so each send→ACK is timed.
        self._conns = [
            PersistentConnection(
                host,
                base_port + i,
                correlator,
                metrics,
                expect_ack=True,
                queue_max=queue_max,
            )
            for i in range(count)
        ]
        self._rr = 0  # round-robin cursor across connections

    @property
    def count(self) -> int:
        return self._count

    @property
    def ports(self) -> list[int]:
        return [self._base_port + i for i in range(self._count)]

    async def open(self, *, connect_batch: int, batch_pause_s: float) -> None:
        """Start the N connections in BATCHES of ``connect_batch`` (a short ``batch_pause_s`` between
        batches), so opening N sockets is not itself a transient that pollutes the steady-state
        measurement. Each connection's reconnect loop starts immediately; the caller separately waits
        until the engine reports all N inbound rows present before the hold phase."""
        for start in range(0, self._count, max(1, connect_batch)):
            for conn in self._conns[start : start + connect_batch]:
                conn.start()
            if batch_pause_s > 0.0 and start + connect_batch < self._count:
                await asyncio.sleep(batch_pause_s)

    def _emit_one(self, out: Outgoing) -> None:
        """Round-robin one send across the N connections; a full per-connection buffer counts deferred
        (the engine is lagging at this N), surfacing offered ≫ achieved."""
        conn = self._conns[self._rr % self._count]
        self._rr += 1
        if not conn.submit_nowait(out):
            self._m.counters.deferred += 1

    async def run_hold(
        self, *, corpus: Corpus, mix: TypeMix, aggregate_rate: float, hold_seconds: float
    ) -> None:
        """Hold a steady **aggregate** offered rate for ``hold_seconds`` (one token bucket, round-
        robined across the N connections) — the steady-state phase where the connection-scale curve is
        read. A token-bucket schedule (not per-message sleeps), so jitter doesn't drift; at high rates
        it emits the whole batch due since the last tick (bounded by ``_BATCH_CAP``)."""
        sampler = corpus.sampler(mix)
        loop = asyncio.get_running_loop()
        start = loop.time()
        next_due = start
        if aggregate_rate <= 0.0:
            await asyncio.sleep(hold_seconds)
            return
        interval = 1.0 / aggregate_rate
        while True:
            now = loop.time()
            if now - start >= hold_seconds:
                return
            emitted = 0
            while next_due <= now and emitted < _BATCH_CAP:
                self._emit_one(corpus.next(sampler))
                next_due += interval
                emitted += 1
            if next_due <= now:
                # Still behind after the batch cap: the harness/engine couldn't absorb the offered rate
                # this tick. Account the shortfall as deferred and resync the schedule.
                behind = int((now - next_due) / interval) + 1
                self._m.counters.deferred += behind
                next_due = now + interval
            await asyncio.sleep(max(0.0, min(next_due - loop.time(), _MAX_TICK_SLEEP)))

    async def stop(self, grace: float) -> None:
        """Stop offering, grace in-flight ACKs, cancel — identical discipline to ``ConnectionPool.stop``."""
        await asyncio.gather(*(conn.stop(grace) for conn in self._conns))
