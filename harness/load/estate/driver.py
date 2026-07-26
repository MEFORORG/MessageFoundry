# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The estate driver — N persistent MLLP connections, one token bucket, EVENT-calibrated weights (#216).

Where :class:`~harness.load.connscale.driver.ConnScaleDriver` meters every connection UNIFORMLY (~R/N
msg/s each — right for a uniform estate, WRONG for a heterogeneous one: a hub with fan-out F would emit
the same *messages* as a simple feed but ``(1+F)/2``× the *events*, so the total silently overshoots),
:class:`EstateDriver` calibrates each connection to a per-connection **event** budget:

    per_conn_event_rate  =  events/sec every connection should contribute (e.g. 0.347)
    msg_rate_i           =  per_conn_event_rate / events_per_msg(class_i)

A simple feed (2 events/msg) is driven at ``budget/2`` msg/s; a hub (``1+F`` events/msg) at
``budget/(1+F)`` msg/s. So every connection emits ``per_conn_event_rate`` **events**/sec and the
aggregate converges on ``per_conn_event_rate × count`` total events/sec — the demo target.

Scheduling stays "one token bucket, not N timers" (the connscale rationale): a single aggregate bucket
at the total message rate ``R = Σ msg_rate_i`` drives the wall clock, and each due emission is assigned
to a connection by a two-class virtual-time merge (there are only two distinct weights — simple and
hub) plus a round-robin cursor WITHIN the chosen class. That is O(1) per emission, deterministic, and
reproduces each class's message rate exactly, so the harness event loop never becomes the bottleneck.

Connections open in **batches** (``connect_batch``) with a short inter-batch pause to avoid a connect
thundering-herd polluting the steady-state measurement; stop is cooperative + graced.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

from harness.config.estate._shape import events_per_msg
from harness.load.corpus import Corpus, Outgoing
from harness.load.correlator import Correlator
from harness.load.metrics import LiveMetrics
from harness.load.profile import TypeMix
from harness.load.sender import PersistentConnection

_BATCH_CAP = 4096  # max sends emitted in one token-bucket tick (bounds catch-up after a stall)
_MAX_TICK_SLEEP = 0.05


class EstateDriver:
    """Owns N persistent MLLP connections and drives them at EVENT-calibrated per-connection rates.

    The N connections share one :class:`~harness.load.correlator.Correlator` + :class:`LiveMetrics`, so
    the per-message send→ACK timing and the no-loss reconcile aggregate across all N exactly as the load
    runner does for its pool.
    """

    def __init__(
        self,
        *,
        host: str,
        base_port: int,
        hub_flags: Sequence[bool],
        hub_fanout: int,
        per_conn_event_rate: float,
        correlator: Correlator,
        metrics: LiveMetrics,
        queue_max: int = 256,
    ) -> None:
        count = len(hub_flags)
        if count < 1:
            raise ValueError("connection count must be >= 1")
        if hub_fanout < 1:
            raise ValueError("hub_fanout must be >= 1")
        if per_conn_event_rate < 0.0:
            raise ValueError("per_conn_event_rate must be >= 0")
        self._host = host
        self._base_port = base_port
        self._count = count
        self._hub_flags = tuple(bool(f) for f in hub_flags)
        self._hub_fanout = hub_fanout
        self._budget = per_conn_event_rate
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

        # Two classes only (simple / hub), so the per-connection message rate takes one of two values.
        # Split the connection indices and precompute each class's aggregate message rate.
        self._simple_idx = [i for i, is_hub in enumerate(self._hub_flags) if not is_hub]
        self._hub_idx = [i for i, is_hub in enumerate(self._hub_flags) if is_hub]
        self._rate_simple = self._budget / events_per_msg(False, hub_fanout)  # budget / 2
        self._rate_hub = self._budget / events_per_msg(True, hub_fanout)  # budget / (1 + F)
        self._agg_simple = self._rate_simple * len(self._simple_idx)  # class-total msg/s
        self._agg_hub = self._rate_hub * len(self._hub_idx)

        # Two-class virtual-time merge state: each class advances its own virtual clock by 1/rate per
        # emission; the class whose clock is behind emits next. This reproduces the exact simple:hub
        # message split without per-connection timers. Round-robin cursors spread each class's share
        # evenly across that class's connections.
        self._vt_simple = 0.0
        self._vt_hub = 0.0
        self._rr_simple = 0
        self._rr_hub = 0

    @property
    def count(self) -> int:
        return self._count

    @property
    def ports(self) -> list[int]:
        return [self._base_port + i for i in range(self._count)]

    @property
    def aggregate_message_rate(self) -> float:
        """The total offered message rate ``R = Σ msg_rate_i`` the token bucket drives at (msg/s). This
        is DERIVED from the topology + the event budget — it is NOT the calibration target (that is the
        event rate ``per_conn_event_rate × count``), so a test that reads it back is not a valid check."""
        return self._agg_simple + self._agg_hub

    def events_per_msg_for(self, index: int) -> int:
        """Events a message on connection ``index`` produces (2 simple / ``1 + fanout`` hub) — the
        served fan-out, for a caller that wants to convert observed messages to events."""
        return events_per_msg(self._hub_flags[index], self._hub_fanout)

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

    def _pick_index(self) -> int | None:
        """Choose the connection for the next emission by a two-class virtual-time merge, then
        round-robin within the chosen class. Returns ``None`` only when there are no connections to
        drive in either class (both budgets zero)."""
        have_simple = bool(self._simple_idx) and self._agg_simple > 0.0
        have_hub = bool(self._hub_idx) and self._agg_hub > 0.0
        if have_simple and (not have_hub or self._vt_simple <= self._vt_hub):
            self._vt_simple += 1.0 / self._agg_simple
            idx = self._simple_idx[self._rr_simple % len(self._simple_idx)]
            self._rr_simple += 1
            return idx
        if have_hub:
            self._vt_hub += 1.0 / self._agg_hub
            idx = self._hub_idx[self._rr_hub % len(self._hub_idx)]
            self._rr_hub += 1
            return idx
        return None

    def _emit_one(self, out: Outgoing) -> None:
        """Assign one send to the class-and-connection the virtual-time merge selects; a full
        per-connection buffer counts deferred (the engine is lagging), surfacing offered ≫ achieved."""
        idx = self._pick_index()
        if idx is None:
            return
        if not self._conns[idx].submit_nowait(out):
            self._m.counters.deferred += 1

    async def run_hold(self, *, corpus: Corpus, mix: TypeMix, hold_seconds: float) -> None:
        """Hold the calibrated schedule for ``hold_seconds``. A single aggregate token bucket at the
        derived total message rate ``R`` drives the wall clock; each due emission is assigned to a
        connection by the event-weighted two-class merge. A token-bucket schedule (not per-message
        sleeps), so jitter doesn't drift; at high rates it emits the whole batch due since the last tick
        (bounded by ``_BATCH_CAP``)."""
        sampler = corpus.sampler(mix)
        loop = asyncio.get_running_loop()
        start = loop.time()
        rate = self.aggregate_message_rate
        if rate <= 0.0:
            await asyncio.sleep(hold_seconds)
            return
        interval = 1.0 / rate
        next_due = start
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
