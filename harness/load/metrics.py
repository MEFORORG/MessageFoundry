# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Bounded, dependency-free metrics primitives for the load engine.

At very high message counts (millions per run) nothing per-message may be retained, so latencies
stream into a fixed-relative-error :class:`Histogram` (a DDSketch — O(buckets) memory, ~1% quantile
error) and rates into a per-second :class:`RateMeter`. :class:`Counters` are plain monotonic tallies
and :class:`Snapshot` is a cheap point-in-time view the runner logs each interval and the report
consumes. All stdlib — see ``docs/LOAD-TESTING.md``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, replace


class Histogram:
    """A relative-error latency histogram (DDSketch).

    A value ``v > 0`` lands in bucket ``key = ceil(log_gamma(v))`` where
    ``gamma = (1 + accuracy) / (1 - accuracy)``; the reconstructed value for a key is the bucket
    midpoint ``2*gamma**key / (gamma+1)``, which is within ``accuracy`` of *every* value in the
    bucket — so :meth:`percentile` is accurate to the configured relative error regardless of how
    many samples are recorded. Memory is bounded by the number of distinct buckets (≈1350 for
    1 ns…600 s at 1%), never by the sample count, and two histograms :meth:`merge` by summing buckets
    (so a multi-process sender can aggregate results).

    Values are unitless; the load engine records latencies in **nanoseconds**.
    """

    __slots__ = (
        "_gamma",
        "_log_gamma",
        "_mid",
        "_buckets",
        "_zero",
        "_count",
        "_min",
        "_max",
        "_sum",
    )

    def __init__(self, relative_accuracy: float = 0.01) -> None:
        if not 0.0 < relative_accuracy < 1.0:
            raise ValueError("relative_accuracy must be in (0, 1)")
        self._gamma = (1.0 + relative_accuracy) / (1.0 - relative_accuracy)
        self._log_gamma = math.log(self._gamma)
        self._mid = 2.0 / (self._gamma + 1.0)
        self._buckets: dict[int, int] = {}
        self._zero = 0  # samples <= 0 (degenerate; latencies should never be negative)
        self._count = 0
        self._min = math.inf
        self._max = -math.inf
        self._sum = 0.0

    def record(self, value: float) -> None:
        self._count += 1
        self._sum += value
        if value < self._min:
            self._min = value
        if value > self._max:
            self._max = value
        if value <= 0.0:
            self._zero += 1
            return
        key = math.ceil(math.log(value) / self._log_gamma)
        self._buckets[key] = self._buckets.get(key, 0) + 1

    def merge(self, other: Histogram) -> None:
        """Fold ``other`` into this histogram (for aggregating per-process results). Both must use
        the same ``relative_accuracy``."""
        if not math.isclose(self._gamma, other._gamma):
            raise ValueError("cannot merge histograms with different relative_accuracy")
        for key, n in other._buckets.items():
            self._buckets[key] = self._buckets.get(key, 0) + n
        self._zero += other._zero
        self._count += other._count
        self._sum += other._sum
        self._min = min(self._min, other._min)
        self._max = max(self._max, other._max)

    @property
    def count(self) -> int:
        return self._count

    @property
    def min(self) -> float:
        return 0.0 if self._count == 0 else self._min

    @property
    def max(self) -> float:
        return 0.0 if self._count == 0 else self._max

    @property
    def mean(self) -> float:
        return 0.0 if self._count == 0 else self._sum / self._count

    def percentile(self, q: float) -> float:
        """The ``q``-th percentile (``q`` in [0, 100]), accurate to the configured relative error.

        ``min``/``max`` are returned exactly at the extremes; interior quantiles return the bucket
        midpoint estimate."""
        if self._count == 0:
            return 0.0
        if q <= 0.0:
            return self.min
        if q >= 100.0:
            return self.max
        target = q / 100.0 * self._count  # interpolation-free: the item at this 1-based rank
        running = self._zero
        if running >= target:
            return 0.0
        for key in sorted(self._buckets):
            running += self._buckets[key]
            if running >= target:
                return self._mid * (self._gamma**key)
        return self.max

    def summary(self) -> LatencySummary:
        """Percentile snapshot in **milliseconds** (latencies are recorded in ns)."""
        ns_to_ms = 1e-6
        return LatencySummary(
            count=self._count,
            p50_ms=self.percentile(50.0) * ns_to_ms,
            p95_ms=self.percentile(95.0) * ns_to_ms,
            p99_ms=self.percentile(99.0) * ns_to_ms,
            max_ms=self.max * ns_to_ms,
            mean_ms=self.mean * ns_to_ms,
        )


@dataclass(frozen=True)
class LatencySummary:
    """Percentiles in milliseconds, for the report (JSON-friendly)."""

    count: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float


class RateMeter:
    """Per-second event tallies, for plotting offered-vs-achieved rate over the run.

    Bounded by run duration (one int per elapsed second — ~3600 for a 1 h soak), not by event
    count. Timestamps are monotonic seconds (``time.perf_counter()``)."""

    __slots__ = ("_origin", "_seconds")

    def __init__(self, origin: float) -> None:
        self._origin = origin
        self._seconds: dict[int, int] = {}

    def mark(self, now: float, n: int = 1) -> None:
        bucket = int(now - self._origin)
        self._seconds[bucket] = self._seconds.get(bucket, 0) + n

    def total(self) -> int:
        return sum(self._seconds.values())

    def rate_between(self, start: float, end: float) -> float:
        """Mean events/second over the wall-clock window ``[start, end)`` (monotonic seconds)."""
        span = end - start
        if span <= 0.0:
            return 0.0
        lo, hi = int(start - self._origin), int(end - self._origin)
        n = sum(c for b, c in self._seconds.items() if lo <= b < hi)
        return n / span

    def series(self) -> list[tuple[int, int]]:
        """``[(elapsed_second, count), …]`` sorted by second — for the JSON artifact."""
        return sorted(self._seconds.items())


@dataclass
class Counters:
    """Monotonic run tallies. Mutated live by the sender/sink; frozen into a :class:`Snapshot`."""

    sent: int = 0  # frames written to the engine
    acked: int = 0  # ACKs whose MSA-1 is an accept (AA/CA)
    nak: int = 0  # ACKs whose MSA-1 is a reject/error (AE/AR/CE/CR)
    errors: int = 0  # transport failures (connection drop, write error)
    timeouts: int = 0  # in-flight at a connection close with no ACK seen
    deferred: int = 0  # open-loop offers the pool could not accept (engine lagging)
    sink_received: int = (
        0  # frames the correlation sink absorbed (one per delivery, fan-out included)
    )
    correlation_misses: int = 0  # sink arrivals that could not be matched to a send (ring lapped)

    def snapshot(self) -> Counters:
        return replace(self)


@dataclass
class LiveMetrics:
    """The mutable sinks the sender/correlator write to. ``counters`` is cumulative for the whole run;
    ``ack``/``e2e`` are swapped per phase by the runner so each phase gets its own latency
    distribution (warmup/ramp can then be excluded from the steady-state SLO check), while the
    correlator's send-time ring spans the whole run unchanged."""

    counters: Counters
    ack: Histogram
    e2e: Histogram


@dataclass(frozen=True)
class Snapshot:
    """A point-in-time view the runner logs each interval and the report assembles from."""

    elapsed_s: float
    counters: Counters
    offered_rate: float = 0.0
    achieved_rate: float = 0.0
    ack: LatencySummary | None = None
    e2e: LatencySummary | None = None
    extra: dict[str, float] = field(default_factory=dict)
