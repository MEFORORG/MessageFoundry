"""The correlation sink absorbs delivered frames, times them end-to-end, and ACKs AA.

Drives a real loopback MLLP connection into the sink (no engine) and asserts: matched messages get an
E2E sample and an AA whose MSA-2 echoes the control id; repeat arrivals (fan-out) each get a sample; a
foreign control id is a correlation miss; malformed input doesn't crash. Async logic is exercised via
``asyncio.run`` so no pytest-asyncio dependency is needed.
"""

from __future__ import annotations

import asyncio
import time

from messagefoundry.transports.mllp import MLLPDecoder, frame

from harness.load.correlator import Correlator
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.sink import CorrelationSink

_IDS = ControlIds(prefix="LX", width=12)


def _metrics() -> LiveMetrics:
    return LiveMetrics(Counters(), Histogram(), Histogram())


def _message(control_id: str) -> str:
    return (
        f"MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A05^ADT_A05|{control_id}|P|2.5.1\r"
        f"EVN|A05|20260101000000\rPID|1||MRN123^^^FAC||DOE^JANE\r"
    )


async def _send_and_collect(port: int, control_ids: list[str]) -> list[bytes]:
    """Send one framed message per control id on a single connection; return the decoded ACKs."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    decoder = MLLPDecoder()
    acks: list[bytes] = []
    for cid in control_ids:
        writer.write(frame(_message(cid)))
        await writer.drain()
    deadline = time.monotonic() + 5.0
    while len(acks) < len(control_ids) and time.monotonic() < deadline:
        chunk = await asyncio.wait_for(reader.read(65536), timeout=5.0)
        if not chunk:
            break
        acks.extend(decoder.feed(chunk))
    writer.close()
    await writer.wait_closed()
    return acks


def test_sink_times_messages_and_acks_aa() -> None:
    m = _metrics()
    correlator = Correlator(capacity=64, metrics=m)

    async def scenario() -> list[bytes]:
        sink = CorrelationSink(_IDS, correlator, m, host="127.0.0.1", ports=(0,))
        await sink.start()
        port = sink.bound_ports[0]
        # Pre-record sends (the sender's job in a real run) so the sink can match them.
        for seq in range(3):
            correlator.on_send(seq, send_ns=time.perf_counter_ns())
        acks = await _send_and_collect(port, [_IDS.format(s) for s in range(3)])
        await sink.stop()
        return acks

    acks = asyncio.run(scenario())
    assert len(acks) == 3
    for seq, ack in enumerate(acks):
        assert b"MSA|AA|" + _IDS.format(seq).encode() in ack  # AA echoing the control id
    assert correlator.matched == 3
    assert m.counters.sink_received == 3
    assert m.counters.correlation_misses == 0
    assert m.e2e.count == 3 and m.e2e.max > 0.0  # positive end-to-end latency recorded


def test_sink_records_each_fanout_arrival() -> None:
    # The same control id arriving twice models a fan-out (two outbound deliveries of one message);
    # each is timed end-to-end, none is rejected.
    m = _metrics()
    correlator = Correlator(capacity=64, metrics=m)

    async def scenario() -> None:
        sink = CorrelationSink(_IDS, correlator, m, host="127.0.0.1", ports=(0,))
        await sink.start()
        port = sink.bound_ports[0]
        correlator.on_send(0, send_ns=time.perf_counter_ns())
        await _send_and_collect(port, [_IDS.format(0), _IDS.format(0)])  # same id twice
        await sink.stop()

    asyncio.run(scenario())
    assert m.counters.sink_received == 2
    assert correlator.matched == 2  # both arrivals timed


def test_sink_counts_foreign_control_id_as_miss() -> None:
    m = _metrics()
    correlator = Correlator(capacity=64, metrics=m)

    async def scenario() -> None:
        sink = CorrelationSink(_IDS, correlator, m, host="127.0.0.1", ports=(0,))
        await sink.start()
        port = sink.bound_ports[0]
        acks = await _send_and_collect(port, ["FOREIGN0001"])  # not one of our ids
        assert len(acks) == 1  # still ACKed
        await sink.stop()

    asyncio.run(scenario())
    assert m.counters.sink_received == 1
    assert m.counters.correlation_misses == 1
    assert correlator.matched == 0


def test_sink_survives_malformed_frame() -> None:
    m = _metrics()
    correlator = Correlator(capacity=64, metrics=m)

    async def scenario() -> int:
        sink = CorrelationSink(_IDS, correlator, m, host="127.0.0.1", ports=(0,))
        await sink.start()
        port = sink.bound_ports[0]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(frame("this is not an HL7 message"))  # parses to no MSH → HL7PeekError
        await writer.drain()
        # Follow with a valid one to prove the connection stayed alive.
        correlator.on_send(0, send_ns=time.perf_counter_ns())
        writer.write(frame(_message(_IDS.format(0))))
        await writer.drain()
        decoder = MLLPDecoder()
        acks: list[bytes] = []
        deadline = time.monotonic() + 5.0
        while not acks and time.monotonic() < deadline:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=5.0)
            acks.extend(decoder.feed(chunk))
        writer.close()
        await writer.wait_closed()
        await sink.stop()
        return len(acks)

    n_acks = asyncio.run(scenario())
    assert m.counters.correlation_misses == 1  # the malformed frame
    assert correlator.matched == 1  # the valid follow-up still timed
    assert n_acks >= 1


def test_sink_requires_at_least_one_port() -> None:
    m = _metrics()
    correlator = Correlator(capacity=4, metrics=m)
    try:
        CorrelationSink(_IDS, correlator, m, ports=())
    except ValueError as exc:
        assert "at least one port" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for empty ports")
