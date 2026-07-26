# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0067 §9 / BACKLOG #97 — persistent ``X12()`` outbound connections.

Mirrors the MLLP persistent suite for the X12-over-TCP destination: one lazily-established connection
reused across deliveries, reconnect-before-first-byte on a stale socket (uncharged), ``aclose()`` kills
the socket, a peer that packs extra interchanges past its reply vetoes reuse (desync guard). X12's own
twist (A9-9): a returned **TA1** (or business) interchange is a complete request/response on a healthy
transport, so the connection **stays cached** across a captured reply — and even across a TA1\\*R
``NegativeAckError`` dead-letter (mirroring MLLP's NAK-keeps-connection). Loopback peers count accepts.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.parsing.x12.interchange import X12FrameReader
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.x12 import X12Destination


def _isa(*, control: str = "000000001") -> str:
    """A fixed-length (106-char) ISA header with delimiters ``* ^ : ~``, version 00501."""
    el = "*"
    segment = (
        "ISA"
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "00"
        + el
        + " " * 10
        + el
        + "ZZ"
        + el
        + "SENDERID".ljust(15)
        + el
        + "ZZ"
        + el
        + "RECEIVERID".ljust(15)
        + el
        + "240101"
        + el
        + "1200"
        + el
        + "^"
        + el
        + "00501"
        + el
        + control
        + el
        + "0"
        + el
        + "P"
        + el
        + ":"
    )
    assert len(segment) == 105, f"ISA pre-terminator length {len(segment)} (want 105)"
    return segment + "~"


def _interchange(control: str = "000000001") -> str:
    """A complete, synthetic, PHI-free 270 eligibility interchange (one GS, one ST)."""
    return (
        _isa(control=control)
        + "GS*HS*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
        + "ST*270*0001~BHT*0022*13*10001234*20240101*1200~HL*1**20*1~SE*4*0001~GE*1*1~"
        + f"IEA*1*{control}~"
    )


def _ta1(code: str = "A", control: str = "000000009") -> str:
    """A synthetic TA1 interchange acknowledgement (TA1-04 = A/R/E)."""
    return _isa(control=control) + f"TA1*000000001*240101*1200*{code}~" + f"IEA*1*{control}~"


def _dest(port: int, **overrides: object) -> X12Destination:
    settings: dict[str, object] = {
        "host": "127.0.0.1",
        "port": port,
        "timeout_seconds": 5,
        "connect_timeout": 5,
        "persistent": True,
    }
    settings.update(overrides)
    return X12Destination(Destination(name="out", type=ConnectorType.X12, settings=settings))


async def _until(cond: Callable[[], bool], timeout: float = 2.0) -> None:
    elapsed = 0.0
    while not cond():
        await asyncio.sleep(0.01)
        elapsed += 0.01
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


class _X12Peer:
    """Loopback X12 receiver: counts accepts, collects received interchanges, and optionally replies
    with a TA1 interchange (``ta1``). ``trailing`` packs an extra interchange after the reply (desync
    tests); ``close_clients`` simulates a partner idle-close."""

    def __init__(self, *, ta1: str | None = None, trailing: bytes = b"") -> None:
        self.ta1 = ta1
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
        decoder = X12FrameReader()
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                for interchange in decoder.feed(chunk):
                    self.received.append(interchange)
                    if self.ta1 is not None:
                        writer.write(self.ta1.encode() + self.trailing)
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


# --- A9-1/A9-2: reuse + opt-out (fire-and-forward, no reply) --------------------


async def test_reuses_single_connection_across_sends() -> None:
    peer = _X12Peer()  # no TA1 — fire-and-forget
    await peer.start()
    dest = _dest(peer.port)
    try:
        for i in range(3):
            assert await dest.send(_interchange(f"00000000{i}")) is None
        await _until(lambda: len(peer.received) == 3)
        assert peer.accepts == 1
        assert dest.reconnects == 0
    finally:
        await dest.aclose()
        await peer.stop()


async def test_opt_out_connect_per_send() -> None:
    peer = _X12Peer()
    await peer.start()
    dest = _dest(peer.port, persistent=False)
    try:
        for i in range(3):
            assert await dest.send(_interchange(f"00000000{i}")) is None
        await _until(lambda: len(peer.received) == 3)
        assert peer.accepts == 3
    finally:
        await dest.aclose()
        await peer.stop()


# --- A9-3: reconnect-before-first-byte -----------------------------------------


async def test_reconnect_before_first_byte_uncharged() -> None:
    peer = _X12Peer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        assert await dest.send(_interchange()) is None
        conn = dest._conn
        assert conn is not None
        await _until(lambda: len(peer.received) == 1)
        await peer.close_clients()
        await _until(lambda: conn[0].at_eof())
        assert await dest.send(_interchange("000000002")) is None
        await _until(lambda: len(peer.received) == 2)
        assert peer.accepts == 2
        assert dest.reconnects == 1
    finally:
        await dest.aclose()
        await peer.stop()


# --- A9-9: a TA1 (accept) keeps the connection cached --------------------------


async def test_ta1_accept_keeps_connection_cached() -> None:
    peer = _X12Peer(ta1=_ta1("A"))
    await peer.start()
    dest = _dest(peer.port, capture_response=True)
    try:
        r1 = await dest.send(_interchange())
        assert r1 is not None and r1.outcome == "accepted"
        r2 = await dest.send(_interchange("000000002"))
        assert r2 is not None and r2.outcome == "accepted"
        assert peer.accepts == 1  # the TA1 is a complete transaction — connection stays cached
        assert dest.reconnects == 0
    finally:
        await dest.aclose()
        await peer.stop()


async def test_ta1_reject_dead_letters_but_keeps_connection() -> None:
    peer = _X12Peer(ta1=_ta1("R"))
    await peer.start()
    dest = _dest(peer.port, capture_response=True)
    try:
        with pytest.raises(NegativeAckError):
            await dest.send(_interchange())  # TA1*R → permanent reject (dead-letter)
        # A TA1 is a complete request/response on a healthy transport, so the connection stays cached
        # (mirrors MLLP's NAK-keeps-connection) — the reject did not discard it.
        assert dest._conn is not None
        assert peer.accepts == 1
    finally:
        await dest.aclose()
        await peer.stop()


# --- desync guard: extra interchange past the reply vetoes reuse ---------------


async def test_desync_guard_extra_interchange_reconnect() -> None:
    peer = _X12Peer(ta1=_ta1("A"), trailing=_interchange("000000007").encode())
    await peer.start()
    dest = _dest(peer.port, capture_response=True)
    try:
        r1 = await dest.send(_interchange())
        assert r1 is not None and r1.outcome == "accepted"
        r2 = await dest.send(_interchange("000000002"))
        assert r2 is not None
        assert peer.accepts == 2  # reuse vetoed (in-transaction or reuse-time) → fresh connection
        assert dest.reconnects >= 1
    finally:
        await dest.aclose()
        await peer.stop()


# --- A9-7: aclose + connect failure --------------------------------------------


async def test_aclose_closes_cached_socket_and_send_fails_loud() -> None:
    peer = _X12Peer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        await dest.send(_interchange())
        assert dest._conn is not None
        await dest.aclose()
        assert dest._conn is None and dest._closed
        with pytest.raises(DeliveryError):
            await dest.send(_interchange("000000002"))
    finally:
        await peer.stop()


async def test_connect_failure_charged() -> None:
    probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = int(probe.sockets[0].getsockname()[1])
    probe.close()
    await probe.wait_closed()
    dest = _dest(port, connect_timeout=0.5)
    try:
        with pytest.raises(DeliveryError):
            await dest.send(_interchange())
    finally:
        await dest.aclose()
