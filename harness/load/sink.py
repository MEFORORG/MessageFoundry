# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The correlation sink — a headless, high-throughput MLLP listener that *is* the engine's outbound
destination.

The load engine points every outbound connection of ``harness/config/load`` at this sink. For each
delivered frame it captures a receive timestamp **before** parsing, recovers the sequence number from
MSH-10, hands ``(seq, recv_ns)`` to the :class:`~harness.load.correlator.Correlator` (which times the
message end-to-end against the sender's send timestamp), and immediately ACKs ``AA``. Speed is the
contract: a slow sink would stall the engine's delivery workers and we'd be measuring the sink, not
the engine — so it does one tolerant :class:`~messagefoundry.parsing.peek.Peek` parse per message
(reused for both the control id and the ACK), batches replies per read, and logs nothing per message.

Runs in the same event loop as the sender, so send and receive timestamps come from one monotonic
clock — no cross-clock skew. Reuses the engine's own framing primitives (``frame`` / ``MLLPDecoder``
/ ``build_ack``); it never touches the store.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Sequence

from messagefoundry.config.models import AckMode
from messagefoundry.parsing import Peek
from messagefoundry.parsing.peek import HL7PeekError
from messagefoundry.transports.mllp import MLLPDecoder, build_ack, frame

from harness.load.correlator import Correlator
from harness.load.failover_track import FailoverTracker
from harness.load.ids import ControlIds
from harness.load.metrics import LiveMetrics

_READ_BYTES = 65536  # larger than the engine's inbound read: the sink only absorbs, never routes


class CorrelationSink:
    """Absorb the engine's outbound fan-out and time each message end-to-end."""

    def __init__(
        self,
        ids: ControlIds,
        correlator: Correlator,
        metrics: LiveMetrics,
        *,
        host: str = "127.0.0.1",
        ports: Sequence[int] = (2700,),
        ack_mode: AckMode = AckMode.ORIGINAL,
        tracker: FailoverTracker | None = None,
    ) -> None:
        if not ports:
            raise ValueError("the sink needs at least one port")
        self._ids = ids
        self._correlator = correlator
        self._m = metrics
        self._host = host
        self._ports = tuple(ports)
        self._ack_mode = ack_mode
        # Failover-only: per-destination delivery/order bookkeeping. The FIFO lane is the engine OUTBOUND
        # DESTINATION (recovered from MSH-6, since the MLLP connector opens a fresh connection per
        # delivery), NOT this TCP connection. None on a steady-state run, so the hot path below is unchanged.
        self._tracker = tracker
        self._servers: list[asyncio.Server] = []
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> None:
        for port in self._ports:
            self._servers.append(await asyncio.start_server(self._on_client, self._host, port))

    @property
    def bound_ports(self) -> tuple[int, ...]:
        """The actually-bound ports (resolves ephemeral ``0`` to the OS-assigned port)."""
        ports: list[int] = []
        for server in self._servers:
            for sock in server.sockets:
                ports.append(int(sock.getsockname()[1]))
        return tuple(ports)

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
        # Close any still-open client connections so a sink-initiated stop doesn't hang on an idle peer.
        for writer in list(self._writers):
            writer.close()
        await asyncio.gather(
            *(server.wait_closed() for server in self._servers), return_exceptions=True
        )
        self._servers.clear()

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        decoder = MLLPDecoder()
        try:
            while True:
                chunk = await reader.read(_READ_BYTES)
                if not chunk:
                    break
                replies = bytearray()
                for payload in decoder.feed(chunk):
                    # Timestamp before parsing so parse cost isn't charged to end-to-end latency.
                    recv_ns = time.perf_counter_ns()
                    self._handle(payload, recv_ns, replies)
                if replies:
                    writer.write(bytes(replies))
                    await writer.drain()
        except (ConnectionError, OSError):
            pass  # peer reset/closed mid-stream — expected when the engine or run stops
        finally:
            self._writers.discard(writer)
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    def _handle(self, payload: bytes, recv_ns: int, replies: bytearray) -> None:
        try:
            peek = Peek.parse(payload)
        except HL7PeekError:
            # Unparseable delivery (should never happen — the engine delivers valid HL7). Count it and
            # skip: without a parseable inbound there's no control id to echo in an ACK.
            self._m.counters.sink_received += 1
            self._m.counters.correlation_misses += 1
            return
        seq = self._ids.parse(peek.control_id)
        if seq is not None:
            self._correlator.on_recv(seq, recv_ns)  # increments sink_received; matches/dups/misses
            if self._tracker is not None:
                # The FIFO lane is the engine outbound DESTINATION (MSH-6 = SINK_{lane}_{index}, stamped
                # by the load graph's `edit` transform), not this fresh-per-delivery TCP connection.
                self._tracker.on_delivery(peek.receiving_facility or "", seq)
        else:
            # A delivery whose control id isn't one of this run's (foreign traffic on the sink port).
            self._m.counters.sink_received += 1
            self._m.counters.correlation_misses += 1
        replies += frame(build_ack(peek, code="AA", ack_mode=self._ack_mode))
