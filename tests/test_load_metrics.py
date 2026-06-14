"""Unit tests for the load engine's bounded metrics + correlation primitives.

These are pure and fast — no sockets, no engine. They pin the two properties the load report relies
on: percentile accuracy within the histogram's relative error, and E2E correlation that stays
memory-bounded and counts duplicates / misses honestly when the ring laps.
"""

from __future__ import annotations

from harness.load.correlator import Correlator
from harness.load.metrics import Counters, Histogram, LiveMetrics, RateMeter


def _metrics() -> LiveMetrics:
    return LiveMetrics(Counters(), Histogram(), Histogram())


def test_histogram_empty_is_all_zero() -> None:
    h = Histogram()
    assert h.count == 0
    assert h.min == 0.0 and h.max == 0.0 and h.mean == 0.0
    assert h.percentile(50.0) == 0.0
    assert h.summary().count == 0


def test_histogram_percentiles_within_relative_error() -> None:
    h = Histogram(relative_accuracy=0.01)
    for v in range(1, 10_001):  # uniform 1..10000 (ns)
        h.record(float(v))
    assert h.count == 10_000
    # DDSketch guarantees the estimate is within `accuracy` of the true value at that rank; allow a
    # little extra for rank rounding.
    for q, true in [(50.0, 5_000), (90.0, 9_000), (99.0, 9_900)]:
        est = h.percentile(q)
        assert abs(est - true) / true <= 0.03, (q, est, true)
    assert h.percentile(0.0) == h.min == 1.0
    assert h.percentile(100.0) == h.max == 10_000.0


def test_histogram_memory_is_bounded_by_range_not_count() -> None:
    h = Histogram(relative_accuracy=0.01)
    # 1 ns .. ~1 s, a million samples: bucket count is a function of the *range*, not the sample count.
    for i in range(1_000_000):
        h.record(float(1 + (i % 1_000_000_000)))
    assert h.count == 1_000_000
    assert len(h._buckets) < 2_000  # ~log_gamma(1e9) buckets, independent of the million samples


def test_histogram_merge_sums_buckets() -> None:
    a = Histogram(relative_accuracy=0.01)
    b = Histogram(relative_accuracy=0.01)
    for v in range(1, 5_001):
        a.record(float(v))
    for v in range(5_001, 10_001):
        b.record(float(v))
    a.merge(b)
    assert a.count == 10_000
    assert a.max == 10_000.0
    assert abs(a.percentile(50.0) - 5_000) / 5_000 <= 0.03


def test_histogram_summary_converts_ns_to_ms() -> None:
    h = Histogram()
    h.record(2_000_000.0)  # 2 ms in ns
    s = h.summary()
    assert abs(s.p50_ms - 2.0) / 2.0 <= 0.02
    assert abs(s.max_ms - 2.0) / 2.0 <= 0.02


def test_rate_meter_windowed_rate() -> None:
    m = RateMeter(origin=100.0)
    for t in range(100, 110):  # one event per second for 10 s
        m.mark(float(t))
    assert m.total() == 10
    assert m.rate_between(100.0, 110.0) == 1.0
    assert m.rate_between(100.0, 105.0) == 1.0
    assert m.rate_between(100.0, 100.0) == 0.0  # zero-width window
    assert m.series()[0] == (0, 1)


def test_correlator_matches_and_times_end_to_end() -> None:
    m = _metrics()
    c = Correlator(capacity=8, metrics=m)
    for seq in range(4):
        c.on_send(seq, send_ns=seq * 1_000)
    for seq in range(4):
        c.on_recv(seq, recv_ns=seq * 1_000 + 500)  # 500 ns end-to-end each
    assert c.matched == 4
    assert m.counters.sink_received == 4
    assert m.counters.correlation_misses == 0
    assert abs(m.e2e.percentile(50.0) - 500.0) / 500.0 <= 0.02


def test_correlator_records_every_arrival_for_fanout() -> None:
    # Fan-out: one send is delivered to many sink connections, all with the same control id. Each
    # arrival is a genuine end-to-end completion and gets its own sample — not a counted "duplicate".
    m = _metrics()
    c = Correlator(capacity=8, metrics=m)
    c.on_send(0, 1_000)
    c.on_recv(0, 1_500)
    c.on_recv(0, 1_700)
    c.on_recv(0, 1_900)  # three fan-out deliveries of seq 0
    assert m.counters.sink_received == 3
    assert m.counters.correlation_misses == 0
    assert c.matched == 3 and m.e2e.count == 3  # every arrival timed


def test_correlator_counts_misses_when_ring_laps() -> None:
    m = _metrics()
    c = Correlator(capacity=4, metrics=m)
    for seq in range(8):  # seq 4 overwrites slot 0, 5→1, … (more in flight than capacity)
        c.on_send(seq, send_ns=seq)
    c.on_recv(0, recv_ns=100)  # slot 0 now holds seq 4 → cannot match seq 0
    assert m.counters.correlation_misses == 1
    assert c.matched == 0


def test_counters_snapshot_is_independent_copy() -> None:
    counters = Counters(sent=5)
    snap = counters.snapshot()
    counters.sent = 9
    assert snap.sent == 5 and counters.sent == 9
