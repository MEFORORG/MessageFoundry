# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""End-to-end tests for the tee relay over loopback TCP (tee/relay.py)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path

import pytest

from tee import mllp
from tee.relay import Endpoint, RelayConfig, TeeRelay, _MeforItem

SAMPLE = (
    b"MSH|^~\\&|EPIC|SENDFAC|MFOR|RECVFAC|20240101120000||ADT^A01|CTRL123|P|2.5.1\r"
    b"PID|1||MRN001^^^HOSP||DOE^JOHN\r"
)


class FakeMllpServer:
    """A minimal downstream MLLP endpoint: records received payloads and ACKs them."""

    def __init__(self, ack_code: str = "AA", drop: bool = False, drop_first: int = 0) -> None:
        self.ack_code = ack_code
        self.drop = drop  # close without sending an ACK (simulates a half-broken peer)
        self.drop_first = drop_first  # drop the first N connections, then ACK (for retry tests)
        self.received: list[bytes] = []
        self._conns = 0
        self._server: asyncio.Server | None = None

    async def start(self) -> "FakeMllpServer":
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self

    @property
    def address(self) -> Endpoint:
        assert self._server is not None
        host, port = self._server.sockets[0].getsockname()[:2]
        return (host, port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._conns += 1
        drop_this = self.drop or self._conns <= self.drop_first
        decoder = mllp.FrameDecoder()
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                for message in decoder.feed(chunk):
                    self.received.append(message)
                    if drop_this:
                        return  # close the connection without an ACK (half-broken peer)
                    writer.write(mllp.frame(mllp.build_ack(message, code=self.ack_code)))
                    await writer.drain()
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def wait_for(self, count: int = 1, timeout: float = 2.0) -> None:
        async with asyncio.timeout(timeout):
            while len(self.received) < count:
                await asyncio.sleep(0.01)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(OSError):
                await self._server.wait_closed()


async def _send_from_epic(address: Endpoint, payload: bytes, timeout: float = 2.0) -> bytes:
    reader, writer = await asyncio.open_connection(*address)
    try:
        writer.write(mllp.frame(payload))
        await writer.drain()
        decoder = mllp.FrameDecoder()
        async with asyncio.timeout(timeout):
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    raise AssertionError("relay closed before ACK")
                for ack in decoder.feed(chunk):
                    return ack
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()


async def _wait_until(predicate, timeout: float = 2.0) -> None:  # type: ignore[no-untyped-def]
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


async def _wait_until_async(predicate, timeout: float = 2.0) -> None:  # type: ignore[no-untyped-def]
    async with asyncio.timeout(timeout):
        while not await predicate():
            await asyncio.sleep(0.01)


async def _unused_address() -> Endpoint:
    """A 127.0.0.1 address that nothing is listening on (start then stop a server)."""
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    server.close()
    await server.wait_closed()
    return (host, port)


async def test_fans_out_to_both_and_acks(tmp_path: Path) -> None:
    corepoint = await FakeMllpServer().start()
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=corepoint.address,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
        )
    )
    await relay.start()
    try:
        ack = await _send_from_epic(relay.epic_address, SAMPLE)
        # Epic gets an AA from the relay, echoing its control id.
        assert mllp.parse_ack(ack)[0] == "AA"
        assert b"MSA|AA|CTRL123" in ack
        # Corepoint forwarding happens after the ACK, so wait for it; the payload is unchanged.
        await corepoint.wait_for(1)
        assert corepoint.received == [SAMPLE]
        # MEFOR receives the same copy via the decoupled worker.
        await mefor.wait_for(1)
        assert mefor.received == [SAMPLE]
        assert not relay.tripped
        assert relay.store is not None
        naks = await relay.store.recent_naks()
        assert naks == []  # both legs accepted
    finally:
        await relay.stop()
        await corepoint.stop()
        await mefor.stop()


async def test_corepoint_nak_is_logged_not_tripped(tmp_path: Path) -> None:
    corepoint = await FakeMllpServer(ack_code="AE").start()
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=corepoint.address,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
        )
    )
    await relay.start()
    try:
        ack = await _send_from_epic(relay.epic_address, SAMPLE)
        # Epic still gets AA (the relay always accepts); the Corepoint NAK does not propagate.
        assert mllp.parse_ack(ack)[0] == "AA"
        assert not relay.tripped
        assert relay.store is not None
        store = relay.store

        async def _corepoint_nak_logged() -> bool:
            naks = await store.recent_naks()
            return any(n.leg == "corepoint" and n.ack_code == "AE" for n in naks)

        # The Corepoint leg records after the ACK is sent, so wait for the NAK row to land.
        await _wait_until_async(_corepoint_nak_logged)
        assert not relay.tripped  # a NAK is logged, not a fail-closed trip
    finally:
        await relay.stop()
        await corepoint.stop()
        await mefor.stop()


async def test_fail_closed_when_corepoint_unreachable(tmp_path: Path) -> None:
    down = await _unused_address()  # nothing is listening here
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=down,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
            corepoint_attempts=2,
            corepoint_retry_delay=0.01,
            connect_timeout=0.5,  # bound each connect so a refused-port hang can't exceed the wait
        )
    )
    await relay.start()
    try:
        epic_addr = relay.epic_address
        # The relay AA's on receipt, then the Corepoint forward fails and it trips fail-closed.
        ack = await _send_from_epic(epic_addr, SAMPLE)
        assert mllp.parse_ack(ack)[0] == "AA"
        await _wait_until(lambda: relay.tripped, timeout=5.0)
        assert relay.store is not None
        naks = await relay.store.recent_naks()
        assert any(n.leg == "corepoint" and n.outcome == "transport_error" for n in naks)
        # Listener A is closed — a new Epic connection is refused.
        with pytest.raises(OSError):
            reader, writer = await asyncio.open_connection(*epic_addr)
            writer.write(mllp.frame(SAMPLE))
            await writer.drain()
            await asyncio.wait_for(reader.read(4096), 1.0)
            writer.close()
    finally:
        await relay.stop()
        await mefor.stop()


async def test_copy_listener_forwards_to_mefor_only(tmp_path: Path) -> None:
    corepoint = await FakeMllpServer().start()
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=corepoint.address,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
            listen_corepoint_copy=("127.0.0.1", 0),
        )
    )
    await relay.start()
    try:
        copy_addr = relay.copy_address
        assert copy_addr is not None
        ack = await _send_from_epic(copy_addr, SAMPLE)
        assert mllp.parse_ack(ack)[0] == "AA"
        await mefor.wait_for(1)
        assert mefor.received == [SAMPLE]
        # The copy feed goes only to MEFOR — never to Corepoint.
        assert corepoint.received == []
        assert relay.store is not None
        store = relay.store

        async def _copy_leg_logged() -> bool:
            cur = await store._db.execute(  # noqa: SLF001 — test introspection
                "SELECT 1 FROM relay_log WHERE direction='corepoint_copy' AND leg='mefor'"
                " AND outcome='accepted'"
            )
            return await cur.fetchone() is not None

        await _wait_until_async(_copy_leg_logged)
    finally:
        await relay.stop()
        await corepoint.stop()
        await mefor.stop()


async def test_capture_bodies_persists_body(tmp_path: Path) -> None:
    corepoint = await FakeMllpServer().start()
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=corepoint.address,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
            capture_bodies=True,
        )
    )
    await relay.start()
    try:
        await _send_from_epic(relay.epic_address, SAMPLE)
        await corepoint.wait_for(1)
        assert relay.store is not None
        store = relay.store

        async def _body_captured() -> bool:
            cur = await store._db.execute(  # noqa: SLF001 — test introspection
                "SELECT raw FROM relay_capture WHERE direction='epic_to_corepoint'"
            )
            row = await cur.fetchone()
            return row is not None and bytes(row["raw"]) == SAMPLE

        await _wait_until_async(_body_captured)
    finally:
        await relay.stop()
        await corepoint.stop()
        await mefor.stop()


async def test_corepoint_drops_without_ack_trips(tmp_path: Path) -> None:
    # A peer that accepts the connection + message but closes without an ACK (half-broken) is a
    # transport failure → fail-closed (distinct from connection-refused).
    corepoint = await FakeMllpServer(drop=True).start()
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=corepoint.address,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
            corepoint_attempts=2,
            corepoint_retry_delay=0.01,
        )
    )
    await relay.start()
    try:
        ack = await _send_from_epic(relay.epic_address, SAMPLE)
        assert mllp.parse_ack(ack)[0] == "AA"  # Epic is still ACK'd on receipt
        await _wait_until(lambda: relay.tripped, timeout=5.0)
        assert corepoint.received  # the peer did receive the message before closing
        assert relay.store is not None
        naks = await relay.store.recent_naks()
        assert any(n.leg == "corepoint" and n.outcome == "transport_error" for n in naks)
    finally:
        await relay.stop()
        await corepoint.stop()
        await mefor.stop()


async def test_corepoint_retry_then_succeeds(tmp_path: Path) -> None:
    # First connection is dropped without an ACK; the retry succeeds — no trip.
    corepoint = await FakeMllpServer(drop_first=1).start()
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=corepoint.address,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
            corepoint_attempts=3,
            corepoint_retry_delay=0.01,
        )
    )
    await relay.start()
    try:
        ack = await _send_from_epic(relay.epic_address, SAMPLE)
        assert mllp.parse_ack(ack)[0] == "AA"
        assert relay.store is not None
        store = relay.store

        async def _corepoint_accepted() -> bool:
            cur = await store._db.execute(  # noqa: SLF001 — test introspection
                "SELECT 1 FROM relay_log WHERE leg='corepoint' AND outcome='accepted'"
            )
            return await cur.fetchone() is not None

        await _wait_until_async(_corepoint_accepted)
        assert not relay.tripped  # the retry recovered, so no fail-closed
    finally:
        await relay.stop()
        await corepoint.stop()
        await mefor.stop()


async def test_idle_epic_connection_is_closed(tmp_path: Path) -> None:
    corepoint = await FakeMllpServer().start()
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=corepoint.address,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
            receive_timeout=0.2,
        )
    )
    await relay.start()
    try:
        reader, writer = await asyncio.open_connection(*relay.epic_address)
        try:
            # Send nothing; the relay should close the idle connection after receive_timeout.
            data = await asyncio.wait_for(reader.read(100), 3.0)
            assert data == b""  # EOF — relay closed it
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
    finally:
        await relay.stop()
        await corepoint.stop()
        await mefor.stop()


async def test_store_error_does_not_crash_handler(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    corepoint = await FakeMllpServer().start()
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=corepoint.address,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
        )
    )
    await relay.start()
    try:
        await _send_from_epic(relay.epic_address, SAMPLE)  # first message works
        await corepoint.wait_for(1)
        # Break the store; the ACK still goes out (it's sent before the store write), and the handler
        # must log + close the connection rather than crash with an unhandled exception.
        assert relay.store is not None
        await relay.store.close()
        with caplog.at_level(logging.WARNING):
            ack = await _send_from_epic(relay.epic_address, SAMPLE)
            assert mllp.parse_ack(ack)[0] == "AA"  # always-ACK held despite the store error
            # The handler logs+closes asynchronously after the ACK returns, so wait for it.
            await _wait_until(
                lambda: any(
                    "error processing an Epic message" in r.getMessage() for r in caplog.records
                ),
                timeout=3.0,
            )
    finally:
        await relay.stop()  # store.close() is idempotent
        await corepoint.stop()
        await mefor.stop()


async def test_enqueue_mefor_drops_oldest_with_log(caplog: pytest.LogCaptureFixture) -> None:
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=("127.0.0.1", 1),
            mefor=("127.0.0.1", 2),
            db_path=":memory:",
            mefor_queue_max=2,
        )
    )
    relay._mefor_queue = asyncio.Queue(maxsize=2)  # noqa: SLF001 — exercising the bounded queue
    with caplog.at_level(logging.WARNING):
        for i in range(4):
            relay._enqueue_mefor(  # noqa: SLF001
                _MeforItem(SAMPLE, f"C{i}", "ADT^A01", "epic_to_corepoint")
            )
    assert relay._mefor_queue.qsize() == 2  # noqa: SLF001 — bounded; never blocks
    drops = [r for r in caplog.records if "queue full" in r.getMessage()]
    assert len(drops) == 2  # two oldest copies dropped, each logged


async def test_capture_corepoint_copy_only(tmp_path: Path) -> None:
    # #14 parity posture: capture ONLY Corepoint's output (the copy feed), NOT the Epic->Corepoint
    # input stream — so a compare run persists the minimum PHI.
    corepoint = await FakeMllpServer().start()
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=corepoint.address,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
            listen_corepoint_copy=("127.0.0.1", 0),
            capture_corepoint_copy=True,
        )
    )
    await relay.start()
    try:
        assert relay.store is not None
        store = relay.store
        copy_addr = relay.copy_address
        assert copy_addr is not None
        # Drive both feeds: an Epic input and a Corepoint-copy output.
        await _send_from_epic(relay.epic_address, SAMPLE)
        await corepoint.wait_for(
            1
        )  # epic processing reached the corepoint forward (capture decided)
        await _send_from_epic(copy_addr, SAMPLE)

        async def _copy_captured() -> bool:
            cur = await store._db.execute(  # noqa: SLF001 — test introspection
                "SELECT raw FROM relay_capture WHERE direction='corepoint_copy'"
            )
            row = await cur.fetchone()
            return row is not None and bytes(row["raw"]) == SAMPLE

        await _wait_until_async(_copy_captured)
        # The Epic input was NOT captured (minimal-PHI posture).
        cur = await store._db.execute(  # noqa: SLF001 — test introspection
            "SELECT COUNT(*) AS n FROM relay_capture WHERE direction='epic_to_corepoint'"
        )
        assert (await cur.fetchone())["n"] == 0
    finally:
        await relay.stop()
        await corepoint.stop()
        await mefor.stop()


async def test_capture_bodies_also_captures_copy(tmp_path: Path) -> None:
    # Backward compat: the all-feeds flag still captures the Corepoint-copy feed.
    corepoint = await FakeMllpServer().start()
    mefor = await FakeMllpServer().start()
    relay = TeeRelay(
        RelayConfig(
            listen_epic=("127.0.0.1", 0),
            corepoint=corepoint.address,
            mefor=mefor.address,
            db_path=str(tmp_path / "tee.db"),
            listen_corepoint_copy=("127.0.0.1", 0),
            capture_bodies=True,
        )
    )
    await relay.start()
    try:
        assert relay.store is not None
        store = relay.store
        copy_addr = relay.copy_address
        assert copy_addr is not None
        await _send_from_epic(copy_addr, SAMPLE)

        async def _copy_captured() -> bool:
            cur = await store._db.execute(  # noqa: SLF001 — test introspection
                "SELECT 1 FROM relay_capture WHERE direction='corepoint_copy'"
            )
            return await cur.fetchone() is not None

        await _wait_until_async(_copy_captured)
    finally:
        await relay.stop()
        await corepoint.stop()
        await mefor.stop()
