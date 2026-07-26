# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #117 / ADR 0124 — outbound MLLP fire-and-forward (``no_ack``).

When ``no_ack=true`` the MLLP destination writes + drains and confirms delivery **on the TCP write** —
it reads no ACK and validates no MSA-1, so a NAK or a silent peer never blocks or fails the send
(*at-most-once-confirmation*). A connect/drain failure is still a charged ``DeliveryError`` (the write
path's at-least-once handling is unchanged). ``no_ack`` composes with ``persistent=true`` (no handshake
*and* no ACK wait). The peers here are real loopback ``asyncio.start_server`` receivers that count
accepts + collect received frames — behaviour proven on the wire.

The fail-loud concurrent-``send()`` assert (AC-8) is the *same* ``self._sending`` guard at the top of
``send()`` for every mode (above the ``no_ack`` branch), already covered by
``test_mllp_persistent.test_concurrent_send_raises``; a no-ack drain-*failure*-charged path (AC-4) is
the shared ``_dial``/``_close_bounded`` machinery and cannot be forced deterministically on loopback
(a write into a half-open socket is caught first by the reuse-time ``_stale_reason`` reconnect), so the
reliable reconnect-before-first-byte path is exercised instead. The wiring rejects (AC-5/AC-6) live in
``tests/test_no_ack_wiring.py``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.parsing.peek import Peek
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.mllp import MLLPDecoder, MLLPDestination, build_ack, frame


def _msg(control_id: str) -> str:
    return (
        f"MSH|^~\\&|SNDAPP|SNDFAC|RCVAPP|RCVFAC|20260101||ADT^A01|{control_id}|P|2.5.1\r"
        "PID|1||100||DOE^JANE\r"
    )


def _dest(port: int, **overrides: object) -> MLLPDestination:
    settings: dict[str, object] = {
        "host": "127.0.0.1",
        "port": port,
        "timeout_seconds": 5,
        "connect_timeout": 5,
        "no_ack": True,
    }
    settings.update(overrides)
    return MLLPDestination(Destination(name="out", type=ConnectorType.MLLP, settings=settings))


async def _until(cond: Callable[[], bool], timeout: float = 2.0) -> None:
    elapsed = 0.0
    while not cond():
        await asyncio.sleep(0.01)
        elapsed += 0.01
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


class _Peer:
    """Loopback receiver for the no-ack tests: counts accepts, collects received frames, and by default
    sends **nothing** back (a non-acking peer — a display board / one-way tap). With ``nak`` it returns
    an AR NAK (to prove ``no_ack`` ignores it). ``close_clients`` simulates a partner idle-close."""

    def __init__(self, *, nak: bool = False) -> None:
        self.nak = nak
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
        decoder = MLLPDecoder()
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                for message in decoder.feed(chunk):
                    self.received.append(message)
                    if self.nak:
                        writer.write(frame(build_ack(message, code="AR")))
                        await writer.drain()
        except (OSError, ConnectionError):
            pass  # client went away — nothing to do

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


# --- AC-1: the default still waits for + validates an ACK ----------------------


async def test_default_still_waits_for_ack() -> None:
    peer = _Peer()  # silent — never ACKs
    await peer.start()
    dest = _dest(peer.port, no_ack=False, timeout_seconds=0.3)
    try:
        with pytest.raises(DeliveryError):
            await dest.send(_msg("M1"))  # default reads an ACK that never comes → charged timeout
        assert len(peer.received) == 1  # the frame DID reach the peer
    finally:
        await dest.aclose()
        await peer.stop()


# --- AC-2: no_ack delivers on the write, ignoring a NAK or silence -------------


async def test_no_ack_delivers_when_peer_silent() -> None:
    peer = _Peer()  # silent
    await peer.start()
    dest = _dest(peer.port)  # no_ack=True, persistent=False
    try:
        assert await dest.send(_msg("M1")) is None  # returns on the write — no ACK wait
        await _until(lambda: len(peer.received) == 1)
        assert Peek.parse(peer.received[0]).control_id == "M1"
    finally:
        await dest.aclose()
        await peer.stop()


async def test_no_ack_delivers_ignoring_nak() -> None:
    peer = _Peer(nak=True)
    await peer.start()
    dest = _dest(peer.port)  # no_ack=True
    try:
        assert await dest.send(_msg("M1")) is None  # the NAK is never read → delivered on write
    finally:
        await dest.aclose()
        await peer.stop()
    # Cross-check: the SAME NAKing peer makes an ACK-waiting outbound raise (default unchanged).
    peer2 = _Peer(nak=True)
    await peer2.start()
    waiting = _dest(peer2.port, no_ack=False)
    try:
        with pytest.raises(NegativeAckError):
            await waiting.send(_msg("M2"))
    finally:
        await waiting.aclose()
        await peer2.stop()


# --- AC-3: a connect failure is still charged (at-least-once for the write) -----


async def test_no_ack_connect_failure_charged() -> None:
    probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = int(probe.sockets[0].getsockname()[1])
    probe.close()
    await probe.wait_closed()  # port is now definitely closed
    dest = _dest(port, connect_timeout=0.5)  # no_ack=True
    try:
        with pytest.raises(DeliveryError):
            await dest.send(_msg("M1"))
    finally:
        await dest.aclose()


# --- AC-7: no_ack composes with persistent (reuse + reconnect-before-first-byte)


async def test_no_ack_persistent_reuses_connection() -> None:
    peer = _Peer()
    await peer.start()
    dest = _dest(peer.port, persistent=True)  # no_ack=True + persistent=True
    try:
        for i in range(3):
            assert await dest.send(_msg(f"M{i}")) is None
        await _until(lambda: len(peer.received) == 3)
        assert peer.accepts == 1  # ONE TCP connection carried all three (no handshake per message)
        assert dest.reconnects == 0
    finally:
        await dest.aclose()
        await peer.stop()


async def test_no_ack_persistent_reconnects_before_first_byte() -> None:
    peer = _Peer()
    await peer.start()
    dest = _dest(peer.port, persistent=True)
    try:
        assert await dest.send(_msg("M1")) is None
        conn = dest._conn
        assert conn is not None
        # In no-ack mode send() returns on the WRITE (no ACK read syncs the peer), so wait until the
        # peer has actually consumed M1 before simulating the idle-close — else close_clients() would
        # race the peer's read of M1 off the still-open socket.
        await _until(lambda: len(peer.received) == 1)
        await peer.close_clients()  # the partner idle-closes under us
        await _until(lambda: conn[0].at_eof())  # the FIN reached our reader
        assert await dest.send(_msg("M2")) is None  # detected before any byte; redialed, uncharged
        await _until(lambda: len(peer.received) == 2)
        assert peer.accepts == 2  # a fresh connection
        assert dest.reconnects == 1
    finally:
        await dest.aclose()
        await peer.stop()


# --- AC-8: per-lane send ORDER is preserved ------------------------------------


async def test_no_ack_preserves_send_order() -> None:
    peer = _Peer()
    await peer.start()
    dest = _dest(peer.port, persistent=False)  # connect-per-message, serial sender
    try:
        for i in range(5):
            assert await dest.send(_msg(f"M{i}")) is None
        await _until(lambda: len(peer.received) == 5)
        assert [Peek.parse(m).control_id for m in peer.received] == [f"M{i}" for i in range(5)]
    finally:
        await dest.aclose()
        await peer.stop()
