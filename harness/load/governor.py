# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The rate governor — turns a profile :class:`~harness.load.profile.Phase` into a stream of sends.

Two loop models share one connection pool, differing only in *when* the next send is admitted:

* **open** — a rate-scheduled producer. It tracks an ideal next-send deadline (a token bucket, not a
  per-message ``sleep(1/rate)``, so jitter doesn't drift) and, at high rates, emits the whole batch
  due since the last tick. If the pool can't accept a send (engine lagging), it's counted as
  *deferred* rather than dropped silently — that's how ``offered ≫ achieved`` becomes visible.
* **closed** — holds exactly ``concurrency`` messages in flight via a semaphore released on each
  ACK/timeout. The achieved rate is whatever the engine drains, so it measures *max sustainable
  throughput* without a local backlog inflating the number.
"""

from __future__ import annotations

import asyncio

from harness.load.corpus import Corpus, Sampler
from harness.load.metrics import Counters
from harness.load.profile import Phase, TypeMix
from harness.load.sender import Dispatcher

_BATCH_CAP = 4096  # max sends emitted in one open-loop tick (bounds catch-up after a stall)
_IDLE_SLEEP = 0.02
_MAX_TICK_SLEEP = 0.05
_ACQUIRE_POLL = 0.1


class RateGovernor:
    """Drives one phase at a time against a shared :class:`Dispatcher` + :class:`Corpus`."""

    def __init__(self, corpus: Corpus, dispatcher: Dispatcher, counters: Counters) -> None:
        self._corpus = corpus
        self._dispatcher = dispatcher
        self._counters = counters

    async def run_phase(self, phase: Phase, mix: TypeMix, stop: asyncio.Event) -> None:
        if phase.loop == "open":
            await self._run_open(phase, mix, stop)
        else:
            await self._run_closed(phase, mix, stop)

    def _emit_one(self, sampler: Sampler) -> None:
        out = self._corpus.next(sampler)
        pool = self._dispatcher.route(out.code)
        if pool is None:
            # No target for this message type — a RIG/config fault. Nothing was offered to any engine.
            self._counters.deferred += 1
            self._counters.deferred_schedule += 1
        elif not pool.submit_nowait(out):
            # The pool's per-connection buffer is FULL. The write loop drains before it pops the next job,
            # so a full buffer means the ENGINE stopped reading the socket — this is BACKPRESSURE, i.e. an
            # engine signal, NOT evidence that the load generator was too small. Counting it as one
            # undifferentiated `deferred` is what let an engine intake bind masquerade as a drive shortfall.
            self._counters.deferred += 1
            self._counters.deferred_backpressure += 1

    async def _run_open(self, phase: Phase, mix: TypeMix, stop: asyncio.Event) -> None:
        sampler = self._corpus.sampler(mix)
        loop = asyncio.get_running_loop()
        start = loop.time()
        next_due = start
        while not stop.is_set():
            now = loop.time()
            elapsed = now - start
            if elapsed >= phase.duration_s:
                return
            rate = phase.rate_at(elapsed)
            if rate <= 0.0:
                await asyncio.sleep(_IDLE_SLEEP)
                continue
            interval = 1.0 / rate
            emitted = 0
            while next_due <= now and emitted < _BATCH_CAP:
                self._emit_one(sampler)
                next_due += interval
                emitted += 1
            if next_due <= now:
                # Still behind after the batch cap: the GENERATOR could not even schedule the sends this
                # tick (it never reached a pool, so no engine ever saw them). This is the genuinely
                # RIG-side deferral — the one a DRIVE SHORTFALL verdict may honestly rest on.
                behind = int((now - next_due) / interval) + 1
                self._counters.deferred += behind
                self._counters.deferred_schedule += behind
                next_due = now + interval
            await asyncio.sleep(max(0.0, min(next_due - loop.time(), _MAX_TICK_SLEEP)))

    async def _run_closed(self, phase: Phase, mix: TypeMix, stop: asyncio.Event) -> None:
        sampler = self._corpus.sampler(mix)
        concurrency = phase.concurrency or 1
        slots = asyncio.Semaphore(concurrency)
        loop = asyncio.get_running_loop()
        start = loop.time()
        while not stop.is_set() and loop.time() - start < phase.duration_s:
            try:
                await asyncio.wait_for(slots.acquire(), timeout=_ACQUIRE_POLL)
            except TimeoutError:
                continue  # all slots in flight — re-check stop/duration
            if stop.is_set() or loop.time() - start >= phase.duration_s:
                slots.release()
                return
            out = self._corpus.next(sampler)
            pool = self._dispatcher.route(out.code)
            if pool is None:
                self._counters.deferred += 1
                self._counters.deferred_schedule += 1  # no target — a RIG/config fault
                slots.release()
                continue
            # The slot is released when this message completes (ACK or timeout), holding exactly
            # `concurrency` in flight. Bound the enqueue so a fully-stalled target (all per-connection
            # buffers full) can't block here indefinitely, overrunning the phase duration and ignoring
            # stop — on timeout, count it deferred and release the slot.
            try:
                await asyncio.wait_for(
                    pool.submit(out, on_done=slots.release), timeout=_ACQUIRE_POLL
                )
            except TimeoutError:
                # Every per-connection buffer stayed full for the whole poll — the ENGINE is not reading.
                # BACKPRESSURE, not a rig limit.
                self._counters.deferred += 1
                self._counters.deferred_backpressure += 1
                slots.release()
