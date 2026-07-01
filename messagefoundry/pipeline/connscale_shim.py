# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale executor boot-shim (B11) — a harness-only, env-gated measurement hook.

The router/transform workers run ``route_only``/``transform_one`` via bare ``asyncio.to_thread``,
which dispatches onto the event loop's **default** ``ThreadPoolExecutor`` (lazily created at the
first ``run_in_executor(None, ...)`` with ``max_workers = min(32, (os.cpu_count() or 1) + 4)``). That
default pool is shared by EVERY inbound's workers, so it is the "executor saturation" wall the
connection-scale harness measures — but Python never exposes its submit-queue depth or in-flight
count, and a lazily-created default executor isn't reachable to read.

This shim, **only when the harness sets the gate env var**, installs a *default-sized* executor (the
SAME ``min(32, cpu+4)`` — capacity is NOT changed; the point is to measure the REAL default-pool
wall, not a bound we picked) via ``loop.set_default_executor()`` before any worker runs, and exposes
its queue depth + busy count. Sweeping the executor size is a SEPARATE, explicitly-labelled
experiment, not this default run.

It is **strictly opt-in and harness-only**: with the gate unset (production and every other test) the
function is a no-op returning ``None``, no executor is installed, ``to_thread`` uses the stock lazy
default exactly as before, and ``/stats`` reports ``executor_queue_depth``/``executor_busy`` as
``None`` — byte-identical to an engine that never knew B11 existed.
"""

from __future__ import annotations

import asyncio
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

#: The env var the connection-scale harness sets in the engine subprocess to enable the shim. Any
#: truthy value ("1"/"true"/"yes", case-insensitive) installs the default-sized instrumented executor.
SHIM_ENV = "MEFOR_CONNSCALE_EXECUTOR_SHIM"

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def default_executor_max_workers() -> int:
    """The CPython default ``ThreadPoolExecutor`` size for ``asyncio``'s default executor —
    ``min(32, (os.cpu_count() or 1) + 4)``. The shim installs EXACTLY this so the measured wall is the
    real default pool, not a capacity we chose."""
    return min(32, (os.cpu_count() or 1) + 4)


class InstrumentedThreadPoolExecutor(ThreadPoolExecutor):
    """A ``ThreadPoolExecutor`` that tracks in-flight ("busy") submissions, so the harness can read
    both the submit-queue depth (work waiting for a free thread = saturation) and how many threads are
    actively running a task. Capacity is unchanged — it is a plain executor plus two cheap gauges.

    ``submit`` increments an in-flight counter (guarded by a tiny lock — ``submit`` and the future's
    done-callback can run on different threads) and decrements it when the future completes.
    ``queue_depth`` reads the internal work-queue size (CPython ``_work_queue``). Both are read by the
    ``/stats`` route; neither changes scheduling."""

    def __init__(self, max_workers: int) -> None:
        super().__init__(max_workers=max_workers, thread_name_prefix="connscale-shim")
        self._inflight = 0
        self._busy_peak = 0
        self._gauge_lock = threading.Lock()

    def submit(self, fn: Any, /, *args: Any, **kwargs: Any) -> Any:
        with self._gauge_lock:
            self._inflight += 1
            if self._inflight > self._busy_peak:
                self._busy_peak = self._inflight
        try:
            future = super().submit(fn, *args, **kwargs)
        except BaseException:
            # super().submit() raises after shutdown / on a BrokenThreadPool BEFORE the future exists,
            # so the done-callback that decrements _inflight would never fire — back out the increment
            # under the lock before re-raising so the gauge can't leak +1 per failed submit.
            with self._gauge_lock:
                self._inflight -= 1
            raise
        future.add_done_callback(self._on_done)
        return future

    def _on_done(self, _future: Any) -> None:
        with self._gauge_lock:
            self._inflight -= 1

    @property
    def busy(self) -> int:
        """Tasks currently submitted-but-not-yet-completed (queued + running)."""
        with self._gauge_lock:
            return self._inflight

    @property
    def busy_peak(self) -> int:
        with self._gauge_lock:
            return self._busy_peak

    @property
    def queue_depth(self) -> int:
        """Work items queued but not yet picked up by a thread (the saturation signal)."""
        return self._work_queue.qsize()


def shim_enabled() -> bool:
    return os.environ.get(SHIM_ENV, "").strip().lower() in _TRUTHY


def maybe_install_executor_shim(
    loop: asyncio.AbstractEventLoop,
) -> InstrumentedThreadPoolExecutor | None:
    """Install the default-sized instrumented executor as the loop's default executor **iff** the
    harness gate env var is set; otherwise a no-op returning ``None`` (production/other tests are
    byte-identical). Call once, early in the engine lifespan, before any worker runs. The caller owns
    the returned executor's lifetime (it is shut down with the rest of the lifespan)."""
    if not shim_enabled():
        return None
    executor = InstrumentedThreadPoolExecutor(max_workers=default_executor_max_workers())
    loop.set_default_executor(executor)
    return executor
