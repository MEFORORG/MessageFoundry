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
        if pool is None or not pool.submit_nowait(out):
            self._counters.deferred += 1  # no target / pool buffers full — offered but not sent

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
                # Still behind after the batch cap: the harness/engine couldn't absorb the offered
                # rate this tick. Account the shortfall as deferred and resync the schedule.
                behind = int((now - next_due) / interval) + 1
                self._counters.deferred += behind
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
                self._counters.deferred += 1
                slots.release()
