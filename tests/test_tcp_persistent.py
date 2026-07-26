# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0067 §9 / BACKLOG #97 — persistent ``Tcp()`` outbound connections.

Mirrors the MLLP persistent acceptance suite for the generic raw-TCP destination: one lazily-
established connection reused across deliveries (``persistent=true``, opt-in), a stale socket redialed
once **before any payload byte** (uncharged), a post-write failure charged and the connection
discarded, ``aclose()`` kills the socket with the connector, and a peer that packs extra bytes past its
reply vetoes reuse (desync guard). Loopback ``asyncio.start_server`` peers count accepts, so reuse is
proven on the wire, not inferred from internals.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.framing import STX_ETX_CODEC
from messagefoundry.transports.tcp import TcpDestination


def _dest(port: int, **overrides: object) -> TcpDestination:
    settings: dict[str, object] = {
        "host": "127.0.0.1",
        "port": port,
        "framing": "stx_etx",
        "timeout_seconds": 5,
        "connect_timeout": 5,
        "persistent": True,
    }
    settings.update(overrides)
    return TcpDestination(Destination(name="out", type=ConnectorType.TCP, settings=settings))


async def _until(cond: Callable[[], bool], timeout: float = 2.0) -> None:
    elapsed = 0.0
    while not cond():
        await asyncio.sleep(0.01)
        elapsed += 0.01
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


class _FramedPeer:
    """Loopback raw-TCP receiver (STX/ETX framing): counts accepts, collects received frames, and
    optionally frames back a reply (for ``expect_reply``). ``trailing`` packs extra bytes after the
    reply (desync-guard tests); ``close_clients`` simulates a partner idle-close."""

    def __init__(self, *, reply: bool = False, trailing: bytes = b"") -> None:
        self.reply = reply
        self.trailing = trailing
        self.accepts = 0
        self.received: list[bytes] = []
        self._server: asyncio.Server | None = None
        self._writers: list[asyncio.StreamWriter] = []

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._on_client, "127.0.0.1", 0)

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.accepts += 1
        self._writers.append(writer)
        decoder = STX_ETX_CODEC.decoder()
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                for message in decoder.feed(chunk):
                    self.received.append(message)
                    if self.reply:
                        writer.write(STX_ETX_CODEC.frame("ACK") + self.trailing)
                        await writer.drain()
        except (OSError, ConnectionError):
            pass

    async def close_clients(self) -> None:
        for writer in self._writers:
            writer.close()
        for writer in self._writers:
            try:  # noqa: SIM105
                await asyncio.wait_for(writer.wait_closed(), 2.0)
            except (TimeoutError, OSError):
                pass
        self._writers.clear()

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        await self.close_clients()
        try:  # noqa: SIM105
            await asyncio.wait_for(self._server.wait_closed(), 2.0)
        except (TimeoutError, OSError):
            pass


# --- A9-1/A9-2: reuse + opt-out ------------------------------------------------


async def test_reuses_single_connection_across_sends() -> None:
    peer = _FramedPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        for i in range(3):
            assert await dest.send(f"MSG{i}") is None
        await _until(lambda: len(peer.received) == 3)
        assert peer.accepts == 1  # ONE TCP connection carried all three
        assert dest.reconnects == 0
    finally:
        await dest.aclose()
        await peer.stop()


async def test_opt_out_connect_per_send() -> None:
    peer = _FramedPeer()
    await peer.start()
    dest = _dest(peer.port, persistent=False)
    try:
        for i in range(3):
            assert await dest.send(f"MSG{i}") is None
        await _until(lambda: len(peer.received) == 3)
        assert peer.accepts == 3  # a fresh connection per delivery (byte-identical legacy behavior)
    finally:
        await dest.aclose()
        await peer.stop()


# --- A9-3: reconnect-before-first-byte, uncharged ------------------------------


async def test_reconnect_before_first_byte_uncharged() -> None:
    peer = _FramedPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        assert await dest.send("M1") is None
        conn = dest._conn
        assert conn is not None
        await _until(
            lambda: len(peer.received) == 1
        )  # sync before the idle-close (no reply syncs it)
        await peer.close_clients()
        await _until(lambda: conn[0].at_eof())
        assert await dest.send("M2") is None  # detected before any byte; redialed, uncharged
        await _until(lambda: len(peer.received) == 2)
        assert peer.accepts == 2
        assert dest.reconnects == 1
    finally:
        await dest.aclose()
        await peer.stop()


# --- A9-6: idle timeout ---------------------------------------------------------


async def test_idle_timeout_expires_connection() -> None:
    peer = _FramedPeer()
    await peer.start()
    dest = _dest(peer.port, idle_timeout_seconds=0.05)
    try:
        assert await dest.send("M1") is None
        await _until(lambda: len(peer.received) == 1)
        assert peer.accepts == 1
        await asyncio.sleep(0.12)  # exceed idle_timeout_seconds
        assert await dest.send("M2") is None
        await _until(lambda: len(peer.received) == 2)
        assert peer.accepts == 2  # idle connection not reused
        assert dest.reconnects == 1
    finally:
        await dest.aclose()
        await peer.stop()


# --- A9-7: aclose ---------------------------------------------------------------


async def test_aclose_closes_cached_socket_and_send_fails_loud() -> None:
    peer = _FramedPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        await dest.send("M1")
        assert dest._conn is not None
        await dest.aclose()
        assert dest._conn is None and dest._closed
        with pytest.raises(DeliveryError):
            await dest.send("M2")  # never re-establish a socket the lifecycle can't close
    finally:
        await peer.stop()


# --- expect_reply capture over the reused connection ---------------------------


async def test_expect_reply_capture_reuses_connection() -> None:
    peer = _FramedPeer(reply=True)
    await peer.start()
    dest = _dest(peer.port, expect_reply=True, capture_response=True)
    try:
        r1 = await dest.send("M1")
        assert r1 is not None and r1.outcome == "accepted" and r1.body == "ACK"
        r2 = await dest.send("M2")
        assert r2 is not None and r2.body == "ACK"
        assert peer.accepts == 1  # one connection carried both request/reply round-trips
        assert dest.reconnects == 0
    finally:
        await dest.aclose()
        await peer.stop()


# --- desync guard: extra bytes past the reply veto reuse -----------------------


async def test_desync_guard_extra_bytes_reconnect() -> None:
    # The peer packs a SECOND complete frame after its reply — reusing would misframe the next send.
    # Vetoed either in-transaction (leftover) or at reuse time (buffered bytes) — both cost a reconnect.
    peer = _FramedPeer(reply=True, trailing=STX_ETX_CODEC.frame("EXTRA"))
    await peer.start()
    dest = _dest(peer.port, expect_reply=True, capture_response=True)
    try:
        r1 = await dest.send("M1")
        assert r1 is not None and r1.body == "ACK"
        r2 = await dest.send("M2")
        assert r2 is not None and r2.body == "ACK"
        assert peer.accepts == 2  # reuse vetoed → a fresh connection
        assert dest.reconnects >= 1
    finally:
        await dest.aclose()
        await peer.stop()


# --- A9-4: connect failure charged ---------------------------------------------


async def test_connect_failure_charged() -> None:
    probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = int(probe.sockets[0].getsockname()[1])
    probe.close()
    await probe.wait_closed()
    dest = _dest(port, connect_timeout=0.5)
    try:
        with pytest.raises(DeliveryError):
            await dest.send("M1")
    finally:
        await dest.aclose()
