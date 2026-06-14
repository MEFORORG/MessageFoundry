"""End-to-end latency correlation with bounded memory.

Each message carries a dense, monotonic sequence number ``seq`` (encoded into MSH-10 as the control
id). The sender records ``send_ns`` by ``seq``; the correlation sink, on arrival, looks the send time
up and streams ``recv_ns - send_ns`` into the E2E histogram. Storage is a **fixed-capacity ring**
indexed by ``seq % capacity`` — O(1) per event, memory independent of message count. If the ring laps
(more messages in flight than ``capacity``) the overwritten slot's later arrival is counted as a
correlation miss rather than mis-attributed, so memory is hard-bounded and the report stays honest.

Fan-out (one inbound → many outbound deliveries, all carrying the same control id) means a sent
message arrives at the sink multiple times; the correlator records **each** arrival as its own
end-to-end sample and does not treat the repeats as errors.

The correlator is unit- and format-agnostic: it works in integer sequence numbers and nanoseconds.
The ``seq``↔control-id string mapping lives in :class:`~harness.load.corpus.ControlIds`.
"""

from __future__ import annotations

from array import array

from harness.load.metrics import LiveMetrics

_EMPTY = -1  # sentinel for a never-written ring slot


class Correlator:
    """Join send/recv timestamps by sequence number into an E2E latency histogram.

    ``capacity`` should comfortably exceed the maximum number of messages in flight (sent but not yet
    delivered to the sink) — including any backlog the engine builds during a spike — or legitimately
    in-flight arrivals will be counted as misses. At 16 bytes/slot, a 1-million-slot ring is ~16 MB.
    Records into ``metrics.e2e``, which the runner swaps per phase; the ring itself spans the run.
    """

    __slots__ = ("_cap", "_send_ns", "_seq_at", "_m", "_matched")

    def __init__(self, capacity: int, metrics: LiveMetrics) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._cap = capacity
        self._send_ns: array[int] = array("q", bytes(8 * capacity))  # int64, zero-filled
        self._seq_at: array[int] = array("q", [_EMPTY]) * capacity
        self._m = metrics
        self._matched = 0  # cumulative across phases (metrics.e2e is swapped per phase)

    def on_send(self, seq: int, send_ns: int) -> None:
        i = seq % self._cap
        self._send_ns[i] = send_ns
        self._seq_at[i] = seq

    def on_recv(self, seq: int, recv_ns: int) -> None:
        """Record one delivery's end-to-end latency.

        Fan-out means one sent message is delivered to many sink connections, all carrying the **same**
        control id — so multiple arrivals per ``seq`` are expected, and each is a genuine end-to-end
        completion that gets its own sample. (At-least-once *re*-deliveries are indistinguishable here;
        the report estimates them from ``sink_received`` vs the engine's ``written``.) A mismatch means
        the ring lapped (more in flight than ``capacity``) or the id isn't this run's — a miss."""
        self._m.counters.sink_received += 1
        i = seq % self._cap
        if self._seq_at[i] != seq:
            self._m.counters.correlation_misses += 1
            return
        self._m.e2e.record(float(recv_ns - self._send_ns[i]))
        self._matched += 1

    @property
    def matched(self) -> int:
        """Deliveries correlated to a known send (one E2E sample each), cumulative across phases."""
        return self._matched
