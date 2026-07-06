# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Server-store connection-pool observability — a read-only, additive measurement surface (B11).

The connection-scale measurement harness (``harness/load/connscale``) reads the **connection-pool
acquire-wait** as the load-bearing signal for the "server-DB pool wait" wall: with a small pool and
many inbound workers, pool *occupancy* (size/idle) pins at "fully busy" for any large connection
count, so it can't tell 500 connections from 1500 — but the time a worker spends **waiting** for a
pooled connection grows monotonically with contention. This module provides:

* :class:`AcquireWaitHistogram` — a lock-free (loop-only), fixed-bucket histogram of
  ``perf_counter``-measured ``pool.acquire()`` wait times, reporting p50/p95/p99 in milliseconds.
* :class:`PoolStatus` — the snapshot the server stores surface via a **server-only** ``/status``
  field (``None`` on SQLite, where there is no pool). It carries the acquire-wait percentiles
  (PRIMARY) plus pool size/idle occupancy (a secondary "is it saturated" boolean signal).

Everything here is **read-only and additive**: it never alters routing, handoff, claim ordering, or
disposition, and it is byte-identical-when-unused (an instance with no recorded waits reports zeros).
The histogram lives on the store and is updated on the existing ``acquire()`` chokepoint; it adds one
``perf_counter`` pair per acquire and never blocks.
"""

from __future__ import annotations

import bisect
import math
from dataclasses import dataclass

# Fixed log-spaced bucket UPPER bounds in milliseconds. An acquire that waits longer than the last
# bound lands in the implicit overflow bucket (reported at the last bound — the curve is read by its
# SLOPE vs connection count, not an exact tail value). Log-spaced so it spans an uncontended acquire
# (sub-millisecond) through a badly-starved one (seconds) with bounded memory and no per-sample
# allocation. An interior percentile reports the containing bucket's UPPER bound (Prometheus `le`
# convention, no interpolation), so a reading is honest to that bucket's width.
_BUCKET_BOUNDS_MS: tuple[float, ...] = (
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    25.0,
    50.0,
    100.0,
    250.0,
    500.0,
    1000.0,
    2500.0,
    5000.0,
    10000.0,
)


class AcquireWaitHistogram:
    """A fixed-bucket histogram of pooled-connection acquire-wait times (milliseconds).

    Loop-only (no lock): every ``acquire()`` and every ``snapshot()`` runs on the engine's single
    event loop, and ``record``/``snapshot`` do no ``await``, so they are atomic w.r.t. each other —
    no thread ever touches this. Memory is one int per bucket (constant); ``record`` is an O(log n)
    bisect. Percentiles are estimated from the cumulative bucket counts (the bucket's upper bound for
    an interior quantile — the same convention as the engine's Prometheus latency histogram), so the
    curve is honest to a bucket's width and never retains per-sample data.
    """

    __slots__ = ("_counts", "_count", "_sum_ms", "_max_ms")

    def __init__(self) -> None:
        # One overflow bucket past the last bound for waits above the top of the ladder.
        self._counts = [0] * (len(_BUCKET_BOUNDS_MS) + 1)
        self._count = 0
        self._sum_ms = 0.0
        self._max_ms = 0.0

    def record(self, wait_ms: float) -> None:
        """Record one acquire-wait sample (milliseconds). Negative/NaN guarded to 0."""
        if not math.isfinite(wait_ms) or wait_ms < 0.0:
            wait_ms = 0.0
        idx = bisect.bisect_left(_BUCKET_BOUNDS_MS, wait_ms)
        self._counts[idx] += 1
        self._count += 1
        self._sum_ms += wait_ms
        if wait_ms > self._max_ms:
            self._max_ms = wait_ms

    def _percentile_ms(self, q: float) -> float:
        """The ``q``-th percentile (q in [0, 100]) in ms, from the cumulative bucket counts."""
        if self._count == 0:
            return 0.0
        target = q / 100.0 * self._count
        running = 0
        for idx, n in enumerate(self._counts):
            running += n
            if running >= target:
                # Report the bucket's upper bound; the overflow bucket reports the last finite bound
                # (the wall is read by slope, and _max_ms carries the true tail separately).
                if idx < len(_BUCKET_BOUNDS_MS):
                    return _BUCKET_BOUNDS_MS[idx]
                return _BUCKET_BOUNDS_MS[-1]
        return self._max_ms

    @property
    def count(self) -> int:
        return self._count

    def summary(self) -> AcquireWaitSummary:
        return AcquireWaitSummary(
            count=self._count,
            p50_ms=self._percentile_ms(50.0),
            p95_ms=self._percentile_ms(95.0),
            p99_ms=self._percentile_ms(99.0),
            max_ms=self._max_ms,
            mean_ms=(self._sum_ms / self._count) if self._count else 0.0,
        )


@dataclass(frozen=True)
class AcquireWaitSummary:
    """Acquire-wait percentiles in milliseconds (the PRIMARY pool-wait signal)."""

    count: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float


@dataclass(frozen=True)
class PoolStatus:
    """A server-store connection-pool snapshot — the **server-only** ``/status`` field (B11).

    ``None`` on SQLite (no pool). The acquire-wait percentiles are the PRIMARY connection-scale
    signal (they grow monotonically with worker contention once the pool saturates); ``size``/``idle``
    occupancy is the SECONDARY "is it fully busy" boolean (``idle == 0`` at the wall). Read-only and
    additive — surfaced through a server-only field that defaults ``None``, so an older client
    deserializes ``/status`` unchanged.
    """

    backend: str  # "postgres" | "sqlserver"
    max_size: int  # the configured pool maximum
    size: int  # connections currently open in the pool (asyncpg get_size / aioodbc size)
    idle: int  # currently-free connections (asyncpg get_idle_size / aioodbc freesize)
    acquire_wait: AcquireWaitSummary  # PRIMARY: perf_counter-measured acquire() wait percentiles
