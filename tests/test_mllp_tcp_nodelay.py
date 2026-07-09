# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""TCP_NODELAY is set on every MLLP request-response socket.

MLLP is a small-frame request-response protocol (write one framed message, drain, block on the ACK).
With Nagle's algorithm on, a small write with no unacked data outstanding is held until the peer's
delayed-ACK timer fires — a ~tens-of-ms stall per exchange, crippling on the ADR 0067 persistent path.
These tests drive real loopback connections and assert the option is actually set on the wire on all
three sites: the outbound dial (``MLLPDestination._dial`` → both send modes + reconnects), the inbound
accepted client (``MLLPSource._on_client``), and the harness correlation sink.
"""

from __future__ import annotations

import asyncio
import socket
import time

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.transports import mllp as mllp_mod
from messagefoundry.transports.mllp import (
    MLLPDecoder,
    MLLPDestination,
    MLLPSource,
    build_ack,
    frame,
)

from harness.load.correlator import Correlator
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.sink import CorrelationSink


def _msg(control_id: str) -> str:
    return (
        f"MSH|^~\\&|SNDAPP|SNDFAC|RCVAPP|RCVFAC|20260101||ADT^A01|{control_id}|P|2.5.1\r"
        "PID|1||100||DOE^JANE\r"
    )


def _nodelay(writer: asyncio.StreamWriter) -> int:
    """The TCP_NODELAY value on the socket behind ``writer`` (1 = Nagle disabled)."""
    sock = writer.get_extra_info("socket")
    assert sock is not None
    return int(sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))


async def test_outbound_dial_sets_tcp_nodelay(monkeypatch: pytest.MonkeyPatch) -> None:
    # NOTE: asyncio ALREADY sets TCP_NODELAY=1 on connected CLIENT sockets, so merely asserting the
    # option is 1 on the dialed socket passes whether or not _dial calls _set_tcp_nodelay — vacuous.
    # The outbound call is defense-in-depth (parity with the accepted-socket path, and robustness to a
    # future non-asyncio dial). So prove _dial ACTUALLY invokes _set_tcp_nodelay by spying on it, and
    # separately confirm the wire ends up with Nagle disabled.
    calls: list[asyncio.StreamWriter] = []
    real_set = mllp_mod._set_tcp_nodelay

    def spy(writer: asyncio.StreamWriter) -> None:
        calls.append(writer)
        real_set(writer)  # keep the real effect so the round-trip below is unaffected

    monkeypatch.setattr(mllp_mod, "_set_tcp_nodelay", spy)

    # A persistent destination caches its connection, so after one delivery we can inspect the very
    # socket _dial produced. This covers both send modes + every reconnect (all go through _dial).
    async def handler(raw: bytes) -> str:
        return build_ack(raw, code="AA")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    dest = MLLPDestination(
        Destination(
            name="out",
            type=ConnectorType.MLLP,
            settings={
                "host": "127.0.0.1",
                "port": source.sockport,
                "timeout_seconds": 5,
                "connect_timeout": 5,
                "persistent": True,
            },
        )
    )
    try:
        await dest.send(_msg("OUT0001"))
        assert dest._conn is not None  # the persistent connection is cached
        # Non-vacuous: _dial invoked _set_tcp_nodelay on the very writer it produced (the accepted
        # inbound socket is spied by _on_client too, so filter to the dialed one).
        assert dest._conn[1] in calls
        assert _nodelay(dest._conn[1]) == 1
    finally:
        await dest.aclose()
        await source.stop()


async def test_inbound_accepted_socket_sets_tcp_nodelay() -> None:
    # The engine's ACK reply must not be Nagle-delayed either, so the accepted client socket gets the
    # option in MLLPSource._on_client. Deliver one message, then inspect the source's live client writer.
    received: list[bytes] = []

    async def handler(raw: bytes) -> str:
        received.append(raw)
        return build_ack(raw, code="AA")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
    try:
        writer.write(frame(_msg("IN0001")))
        await writer.drain()
        decoder = MLLPDecoder()
        acks: list[bytes] = []
        deadline = time.monotonic() + 5.0
        while not acks and time.monotonic() < deadline:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=5.0)
            acks.extend(decoder.feed(chunk))
        assert acks  # round-trip completed
        assert source._clients  # the accepted connection is registered
        accepted = next(iter(source._clients))
        assert _nodelay(accepted) == 1
    finally:
        writer.close()
        await source.stop()


async def test_sink_accepted_socket_sets_tcp_nodelay() -> None:
    # The bench sink's AA reply must not be delayed or the rig would measure the sink's stall, not the
    # engine. CorrelationSink._on_client sets TCP_NODELAY on each accepted socket.
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    ids = ControlIds(prefix="LX", width=12)
    correlator = Correlator(capacity=64, metrics=metrics)
    sink = CorrelationSink(ids, correlator, metrics, host="127.0.0.1", ports=(0,))
    await sink.start()
    port = sink.bound_ports[0]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        correlator.on_send(0, send_ns=time.perf_counter_ns())
        writer.write(frame(_msg(ids.format(0)).replace("ADT^A01", "ADT^A05^ADT_A05")))
        await writer.drain()
        decoder = MLLPDecoder()
        acks: list[bytes] = []
        deadline = time.monotonic() + 5.0
        while not acks and time.monotonic() < deadline:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=5.0)
            acks.extend(decoder.feed(chunk))
        assert acks  # round-trip completed
        assert sink._writers  # the accepted connection is registered
        accepted = next(iter(sink._writers))
        assert _nodelay(accepted) == 1
    finally:
        writer.close()
        await sink.stop()
