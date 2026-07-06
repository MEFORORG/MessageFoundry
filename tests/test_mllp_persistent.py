# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0067 — persistent outbound MLLP connections: the 12 EARS acceptance criteria.

One lazily-established connection is reused across deliveries (``persistent=true`` — the opt-in reuse
path; ADR 0067 ships ``persistent=false`` as the default this release, so these reuse-mode tests set
the flag explicitly via the ``_dest`` helper); a stale cached connection is redialed once **before any
payload byte is written** (uncharged); any failure after the payload was written discards the connection
and is charged; ``aclose()`` kills the socket with the connector. The peers here are real loopback
``asyncio.start_server`` ACK servers (the existing MLLP-test style) that **count accepts** — reuse is
proven on the wire, not inferred from internals.

AC-12 note: the existing MLLP suites (``test_transports``/``test_mllp_tls``/``test_response_capture``/
``test_mllp_encoding_override``/``test_ed_documents_e2e``) run under the shipped default
``persistent=False``; the representative round-trip/NAK/connect-failure, TLS round-trip, and
on-the-wire encoding-override tests are additionally parametrized over ``persistent`` — including the
explicit ``persistent=True`` mode — in their own files rather than wholesale-parametrizing every suite
(runtime).
``test_fifo_ordering`` exercises store-level lane FIFO with non-MLLP fakes, so the flag does not
apply there — the cross-reconnect order guarantee is covered here instead
(:func:`test_fifo_order_preserved_across_reconnect`).
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
import ssl
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import MLLP, Registry
from messagefoundry.parsing.peek import Peek
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.mllp import (
    MLLPDecoder,
    MLLPDestination,
    MLLPSource,
    _mllp_ssl_context,
    build_ack,
    frame,
)


def _msg(control_id: str) -> str:
    return (
        f"MSH|^~\\&|SNDAPP|SNDFAC|RCVAPP|RCVFAC|20260101||ADT^A01|{control_id}|P|2.5.1\r"
        "PID|1||100||DOE^JANE\r"
    )


def _dest(port: int, **overrides: object) -> MLLPDestination:
    # This file is the persistent-connection acceptance suite, so the helper sets ``persistent=True``
    # EXPLICITLY (ADR 0067 ships ``persistent=false`` as the default this release — the reuse-mode
    # tests must opt in, they can no longer rely on the old implicit-True default). A test that
    # exercises the opt-out / connect-per-message default passes ``persistent=False`` to override.
    settings: dict[str, object] = {
        "host": "127.0.0.1",
        "port": port,
        "timeout_seconds": 5,
        "connect_timeout": 5,
        "persistent": True,
    }
    settings.update(overrides)
    return MLLPDestination(Destination(name="out", type=ConnectorType.MLLP, settings=settings))


async def _until(cond: Callable[[], bool], timeout: float = 2.0) -> None:
    """Poll ``cond`` until true or timeout (avoids fixed sleeps in async tests)."""
    elapsed = 0.0
    while not cond():
        await asyncio.sleep(0.01)
        elapsed += 0.01
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


class _AckPeer:
    """Loopback MLLP receiver that counts accepts and ACKs each frame — behavior scriptable so
    tests can simulate a NAKing partner, a mid-send close, extra bytes after the ACK, or a
    stalled ACK (to hold a send in flight)."""

    def __init__(
        self,
        *,
        ack_code: str = "AA",
        trailing: bytes = b"",
        close_without_ack: bool = False,
        raw_ack: bytes | None = None,
        ssl_ctx: ssl.SSLContext | None = None,
    ) -> None:
        self.ack_code = ack_code
        self.trailing = trailing  # extra bytes packed after each ACK frame (desync-guard tests)
        self.raw_ack = (
            raw_ack  # verbatim reply frame instead of a built ACK (unparseable-ACK tests)
        )
        self.close_without_ack = close_without_ack
        self.hold_acks: asyncio.Event | None = None  # unset event = stall every ACK until set
        self.accepts = 0
        self.received: list[bytes] = []
        self._ssl = ssl_ctx
        self._server: asyncio.Server | None = None
        self._writers: list[asyncio.StreamWriter] = []

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._on_client, "127.0.0.1", 0, ssl=self._ssl)

    @property
    def port(self) -> int:
        assert self._server is not None
        port: int = self._server.sockets[0].getsockname()[1]
        return port

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
                    if self.close_without_ack:
                        writer.close()
                        return
                    if self.hold_acks is not None:
                        await self.hold_acks.wait()
                    reply = (
                        self.raw_ack
                        if self.raw_ack is not None
                        else frame(build_ack(message, code=self.ack_code))
                    )
                    writer.write(reply + self.trailing)
                    await writer.drain()
        except (OSError, ConnectionError):
            pass  # client went away — nothing to do

    async def send_stray(self, data: bytes) -> None:
        """Write bytes to the most recent client unprompted — a duplicate/late reply frame arriving
        in its own TCP segment while the client sits idle (the desync-guard reuse-time case)."""
        writer = self._writers[-1]
        writer.write(data)
        await writer.drain()

    async def close_clients(self) -> None:
        """Peer-side idle-close of every established connection (the partner-timeout case)."""
        for writer in self._writers:
            writer.close()
        for writer in self._writers:
            try:
                await asyncio.wait_for(writer.wait_closed(), 2.0)
            except (OSError, asyncio.TimeoutError):
                pass
        self._writers.clear()

    async def stop(self) -> None:
        if self.hold_acks is not None:
            self.hold_acks.set()  # release any handler stalled mid-ACK so its task can finish
        assert self._server is not None
        self._server.close()
        await self.close_clients()
        try:
            await asyncio.wait_for(self._server.wait_closed(), 2.0)
        except (OSError, asyncio.TimeoutError):
            pass


# --- AC-1: lazy establish + reuse ---------------------------------------------


async def test_reuses_single_connection_across_sends() -> None:
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        for i in range(3):
            assert await dest.send(_msg(f"M{i}")) is None
        assert peer.accepts == 1  # ONE TCP connection carried all three deliveries
        assert len(peer.received) == 3
        assert dest.reconnects == 0
    finally:
        await dest.aclose()
        await peer.stop()


async def test_no_connection_until_first_send() -> None:
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        await asyncio.sleep(0.05)  # give a would-be eager connect time to show up
        assert peer.accepts == 0 and dest._conn is None  # nothing at connector build
        await dest.send(_msg("M1"))
        assert peer.accepts == 1 and dest._conn is not None  # established lazily, then cached
    finally:
        await dest.aclose()
        await peer.stop()


# --- AC-2: opt-out reproduces connect-per-send --------------------------------


async def test_opt_out_opens_connection_per_send() -> None:
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port, persistent=False)
    try:
        for i in range(3):
            assert await dest.send(_msg(f"M{i}")) is None
        assert peer.accepts == 3  # one connection per delivery, closed after each
        assert dest._conn is None and dest.reconnects == 0  # nothing ever cached
    finally:
        await dest.aclose()
        await peer.stop()


# --- AC-3: reconnect-before-first-byte on partner idle-close -------------------


async def test_peer_idle_close_reconnects_before_first_byte() -> None:
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        await dest.send(_msg("M1"))
        conn = dest._conn
        assert conn is not None
        await peer.close_clients()  # the partner idle-closes under us
        await _until(lambda: conn[0].at_eof())  # the FIN has reached our reader
        await dest.send(_msg("M2"))  # detected before any payload byte; transparently redialed
        assert peer.accepts == 2
        assert [Peek.parse(m).control_id for m in peer.received] == ["M1", "M2"]
        assert dest.reconnects == 1
    finally:
        await dest.aclose()
        await peer.stop()


async def test_reconnect_before_first_byte_not_charged() -> None:
    # "Not charged" at the connector boundary = send() returns normally (no DeliveryError reaches
    # the delivery worker, so no mark_failed / attempt consumed / connection_lost event) AND the
    # message is delivered exactly once (the internal reconnect is not a resend).
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        await dest.send(_msg("M1"))
        conn = dest._conn
        assert conn is not None
        await peer.close_clients()
        await _until(lambda: conn[0].at_eof())
        assert await dest.send(_msg("M2")) is None  # completes normally — nothing charged
        assert [Peek.parse(m).control_id for m in peer.received] == ["M1", "M2"]  # no duplicate
    finally:
        await dest.aclose()
        await peer.stop()


# --- AC-4: a failed reconnect dial is charged, with detail, and never loops ----


async def test_reconnect_failure_charged_with_describe_error_detail() -> None:
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    port = peer.port
    await dest.send(_msg("M1"))
    conn = dest._conn
    assert conn is not None
    await peer.stop()  # the partner is now fully gone — the redial must fail
    await _until(lambda: conn[0].at_eof())
    with pytest.raises(DeliveryError) as ei:
        await dest.send(_msg("M2"))
    assert not isinstance(ei.value, NegativeAckError)
    text = str(ei.value)
    assert f"MLLP connect to 127.0.0.1:{port} failed: " in text
    tail = text.split("failed: ", 1)[1]  # _describe_error detail: type + errno/winerror
    assert tail.strip(), f"cause missing after 'failed:': {text!r}"
    assert "Error" in tail or "errno" in tail or "refused" in tail.lower()
    await dest.aclose()


async def test_exactly_one_internal_reconnect_per_send(monkeypatch: pytest.MonkeyPatch) -> None:
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    await dest.send(_msg("M1"))
    conn = dest._conn
    assert conn is not None
    await peer.stop()
    await _until(lambda: conn[0].at_eof())

    dials = 0

    async def _refusing_open(*args: object, **kwargs: object) -> object:
        nonlocal dials
        dials += 1
        raise ConnectionRefusedError(10061, "refused")

    monkeypatch.setattr(asyncio, "open_connection", _refusing_open)
    with pytest.raises(DeliveryError):
        await dest.send(_msg("M2"))
    assert dials == 1  # one dial attempt per send — never an internal connect-retry loop
    await dest.aclose()


# --- AC-5: post-write failures are charged, discard, and the next send redials -


async def test_midsend_failure_charged_no_internal_retry() -> None:
    peer = _AckPeer(close_without_ack=True)  # reads the frame, closes before any ACK
    await peer.start()
    dest = _dest(peer.port)
    try:
        with pytest.raises(DeliveryError) as ei:
            await dest.send(_msg("M1"))
        assert not isinstance(ei.value, NegativeAckError)
        assert "ACK" in str(ei.value)  # the failing phase (ACK read) is in the detail
        assert peer.accepts == 1  # charged and surfaced — no internal redial/resend
        assert dest._conn is None  # the failed connection was discarded, never cached
    finally:
        await dest.aclose()
        await peer.stop()


async def test_failed_connection_discarded_next_send_redials() -> None:
    peer = _AckPeer(close_without_ack=True)
    await peer.start()
    dest = _dest(peer.port)
    try:
        with pytest.raises(DeliveryError):
            await dest.send(_msg("M1"))
        peer.close_without_ack = False  # the partner recovers
        assert await dest.send(_msg("M1")) is None  # the retry (per policy) dials fresh
        assert peer.accepts == 2
    finally:
        await dest.aclose()
        await peer.stop()


# --- AC-6: idle / age expiry --------------------------------------------------


async def test_idle_timeout_expires_connection() -> None:
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port, idle_timeout_seconds=0.05)
    try:
        await dest.send(_msg("M1"))
        await asyncio.sleep(0.2)  # idle past the timeout
        await dest.send(_msg("M2"))  # not reused: closed + redialed (uncharged)
        assert peer.accepts == 2
        assert dest.reconnects == 1
    finally:
        await dest.aclose()
        await peer.stop()


async def test_max_age_recycles_connection() -> None:
    peer = _AckPeer()
    await peer.start()
    # idle_timeout 0 = never-expire-on-idle, so only age can drive the recycle here.
    dest = _dest(peer.port, idle_timeout_seconds=0, max_connection_age_seconds=0.05)
    try:
        await dest.send(_msg("M1"))
        await asyncio.sleep(0.2)  # older than max age
        await dest.send(_msg("M2"))
        assert peer.accepts == 2
        assert dest.reconnects == 1
    finally:
        await dest.aclose()
        await peer.stop()


# --- AC-7: aclose / reload lifecycle -------------------------------------------


async def test_aclose_closes_cached_socket() -> None:
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        await dest.send(_msg("M1"))
        conn = dest._conn
        assert conn is not None
        await asyncio.wait_for(dest.aclose(), 5.0)  # bounded — never hangs (#55 pattern)
        assert dest._conn is None
        assert conn[1].is_closing()
        await dest.aclose()  # idempotent — second close is a no-op, no raise
    finally:
        await peer.stop()


async def test_reload_swap_closes_old_socket_no_leak() -> None:
    # The reload reconcile builds the replacement connector then aclose()s the old one
    # (wiring_runner._reconcile_outbound); connector-level equivalent: the old instance's cached
    # socket dies with it while the replacement keeps delivering.
    peer = _AckPeer()
    await peer.start()
    old = _dest(peer.port)
    new = _dest(peer.port)
    try:
        await old.send(_msg("M1"))
        old_conn = old._conn
        assert old_conn is not None
        await new.send(_msg("M2"))  # the replacement takes over
        await old.aclose()
        assert old_conn[1].is_closing()  # the old socket died with the old connector — no leak
        assert await new.send(_msg("M3")) is None  # replacement unaffected
        assert peer.accepts == 2  # one connection per connector instance, no extras
    finally:
        await new.aclose()
        await peer.stop()


async def test_aclose_racing_inflight_send_fails_loud() -> None:
    peer = _AckPeer()
    peer.hold_acks = asyncio.Event()  # stall the ACK so the send stays in flight
    await peer.start()
    dest = _dest(peer.port)
    try:
        task = asyncio.create_task(dest.send(_msg("M1")))
        await _until(lambda: len(peer.received) == 1)  # payload written; awaiting the held ACK
        await asyncio.wait_for(dest.aclose(), 5.0)  # must not hang on the in-flight send
        with pytest.raises(DeliveryError):  # the racing send fails loud (charged, retried) —
            await asyncio.wait_for(task, 5.0)  # never hangs; the documented reload race
    finally:
        peer.hold_acks.set()
        await peer.stop()


# --- AC-8: concurrent send is a fail-loud invariant violation ------------------


async def test_concurrent_send_raises() -> None:
    peer = _AckPeer()
    peer.hold_acks = asyncio.Event()
    await peer.start()
    dest = _dest(peer.port)
    try:
        task = asyncio.create_task(dest.send(_msg("M1")))
        await _until(lambda: len(peer.received) == 1)  # first send is mid-flight
        with pytest.raises(RuntimeError, match="single serial sender"):
            await dest.send(_msg("M2"))  # never interleaves a second frame on the socket
        peer.hold_acks.set()
        assert await asyncio.wait_for(task, 5.0) is None  # the in-flight send is undisturbed
    finally:
        peer.hold_acks.set()
        await dest.aclose()
        await peer.stop()


# --- AC-9: TLS reconnect re-handshakes with unchanged verification -------------


def _cert(tmp_path: Path) -> tuple[str, str]:
    """A self-signed EC cert (SAN 127.0.0.1, CA:TRUE so it doubles as the trust anchor) + key PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cp, kp = tmp_path / "c.pem", tmp_path / "k.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cp), str(kp)


async def test_tls_reconnect_rehandshakes_and_verifies(tmp_path: Path) -> None:
    cert, key = _cert(tmp_path)
    server_ctx = _mllp_ssl_context(
        {"tls": True, "tls_cert_file": cert, "tls_key_file": key}, server=True
    )
    peer = _AckPeer(ssl_ctx=server_ctx)
    await peer.start()
    dest = _dest(peer.port, tls=True, tls_ca_file=cert, tls_check_hostname=True)
    try:
        await dest.send(_msg("M1"))
        conn1 = dest._conn
        assert conn1 is not None
        first_ssl = conn1[1].get_extra_info("ssl_object")
        assert first_ssl is not None and conn1[1].get_extra_info("peercert")  # verified channel
        await peer.close_clients()
        await _until(lambda: conn1[0].at_eof())
        await dest.send(_msg("M2"))  # reconnect: full handshake through the SAME prebuilt context
        conn2 = dest._conn
        assert conn2 is not None and peer.accepts == 2 and dest.reconnects == 1
        second_ssl = conn2[1].get_extra_info("ssl_object")
        assert second_ssl is not None and second_ssl is not first_ssl  # a fresh handshake
        assert conn2[1].get_extra_info("peercert")  # cert verification applied on the reconnect
        assert dest._ssl is not None and dest._ssl.check_hostname  # posture unchanged
    finally:
        await dest.aclose()
        await peer.stop()


# --- AC-10: NAK is a complete transaction on a healthy transport ---------------


async def test_nak_semantics_unchanged_connection_retained() -> None:
    peer = _AckPeer(ack_code="AR")
    await peer.start()
    dest = _dest(peer.port)
    try:
        with pytest.raises(NegativeAckError) as ei:
            await dest.send(_msg("M1"))
        assert ei.value.code == "AR" and ei.value.permanent is True  # AR dead-letters, unchanged
        assert dest._conn is not None and dest.reconnects == 0  # NAK keeps the connection cached
        peer.ack_code = "AE"
        with pytest.raises(NegativeAckError) as ei2:
            await dest.send(_msg("M2"))
        assert ei2.value.code == "AE" and ei2.value.permanent is False  # AE retries, unchanged
        peer.ack_code = "AA"
        assert await dest.send(_msg("M3")) is None
        assert peer.accepts == 1  # all three transactions rode ONE connection
    finally:
        await dest.aclose()
        await peer.stop()


# --- AC-11: reconnects logged (metadata only) + counted -------------------------


async def test_reconnect_logged_with_detail_no_payload(caplog: pytest.LogCaptureFixture) -> None:
    # Clean idle-close reconnect → INFO with the detected reason.
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    with caplog.at_level(logging.INFO, logger="messagefoundry.transports.mllp"):
        await dest.send(_msg("M1"))
        conn = dest._conn
        assert conn is not None
        await peer.close_clients()
        await _until(lambda: conn[0].at_eof())
        await dest.send(_msg("M2"))
    await dest.aclose()
    await peer.stop()
    info_text = "\n".join(r.getMessage() for r in caplog.records)
    assert "peer closed while idle (EOF)" in info_text  # the detected reason
    assert dest.reconnects == 1
    caplog.clear()

    # Error-path discard → WARNING with the failure detail.
    peer2 = _AckPeer(close_without_ack=True)
    await peer2.start()
    dest2 = _dest(peer2.port)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.mllp"):
        with pytest.raises(DeliveryError):
            await dest2.send(_msg("M1"))
    await dest2.aclose()
    await peer2.stop()
    warn_text = "\n".join(r.getMessage() for r in caplog.records)
    assert "discarded after delivery failure" in warn_text
    assert dest2.reconnects == 1
    # Never payload bytes in either class of reconnect log — socket/OS metadata only.
    for text in (info_text, warn_text):
        assert "MSH|" not in text and "DOE" not in text and "PID" not in text


# --- AC-12: order + behavior observably unchanged under the flag ----------------


async def test_fifo_order_preserved_across_reconnect() -> None:
    # A reconnect happens INSIDE one send, so it can never reorder the lane: the wire order the
    # peer observes matches the send order even when the connection dies mid-sequence.
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        await dest.send(_msg("M1"))
        await dest.send(_msg("M2"))
        conn = dest._conn
        assert conn is not None
        await peer.close_clients()  # connection dies between M2 and M3
        await _until(lambda: conn[0].at_eof())
        await dest.send(_msg("M3"))
        await dest.send(_msg("M4"))
        assert [Peek.parse(m).control_id for m in peer.received] == ["M1", "M2", "M3", "M4"]
        assert peer.accepts == 2
    finally:
        await dest.aclose()
        await peer.stop()


# --- desync guard: extra bytes after the ACK ------------------------------------


async def test_extra_bytes_after_ack_close_instead_of_reuse() -> None:
    # A peer that packs a second frame after its ACK would desync the next transaction's framing;
    # the delivery still succeeds (one ACK was read) but the connection is not reused (§2.2).
    peer = _AckPeer(trailing=frame("MSH|^~\\&|X|X|X|X|20260101||ACK|EXTRA|P|2.5.1"))
    await peer.start()
    dest = _dest(peer.port)
    try:
        assert await dest.send(_msg("M1")) is None  # the delivery itself is fine
        assert dest._conn is None  # but the desynced connection was closed, not cached
        assert dest.reconnects == 1
        assert await dest.send(_msg("M2")) is None  # next send dials fresh
        assert peer.accepts == 2
    finally:
        await dest.aclose()
        await peer.stop()


async def test_unsolicited_bytes_while_idle_close_instead_of_reuse() -> None:
    # The reuse-time half of the desync guard (§2.2): a duplicate/late frame that arrives in its
    # OWN segment after the ACK read returned is invisible to the in-transaction leftover flag —
    # it buffers in the StreamReader while the connection sits idle. Reusing would parse that stale
    # frame as the NEXT send's ACK (misattributed dispositions, a perpetuating off-by-one); the
    # stale check must veto reuse instead.
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        assert await dest.send(_msg("M1")) is None
        conn = dest._conn
        assert conn is not None  # cached: the stray frame was NOT in the ACK's read run
        await peer.send_stray(frame("MSH|^~\\&|X|X|X|X|20260101||ACK|STALE|P|2.5.1\rMSA|AA|M1\r"))
        # Wait for the stray bytes to land in the client's reader buffer (the surface the
        # production check peeks — asyncio exposes no public buffered-data probe).
        await _until(lambda: bool(getattr(conn[0], "_buffer", b"")))
        assert await dest.send(_msg("M2")) is None  # fresh dial — never the stale frame as M2's ACK
        assert peer.accepts == 2
        assert dest.reconnects == 1
        assert [Peek.parse(m).control_id for m in peer.received] == ["M1", "M2"]
    finally:
        await dest.aclose()
        await peer.stop()


async def test_cancelled_send_discards_connection() -> None:
    # "ANY failed transaction discards the connection" (§2.2) must include cancellation: a send
    # cancelled between write and ACK-read leaves the socket mid-transaction — its late ACK must
    # never be read as the next send's reply.
    peer = _AckPeer()
    await peer.start()
    dest = _dest(peer.port)
    try:
        await dest.send(_msg("M1"))
        assert dest._conn is not None
        peer.hold_acks = asyncio.Event()  # stall the ACK so M2 stays in flight
        task = asyncio.create_task(dest.send(_msg("M2")))
        await _until(lambda: len(peer.received) == 2)  # payload written; awaiting the held ACK
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert dest._conn is None  # the half-complete transaction's socket was discarded
        assert dest.reconnects == 1
        peer.hold_acks.set()
        peer.hold_acks = None
        assert await dest.send(_msg("M3")) is None  # fresh dial; M2's late ACK never read as M3's
        assert peer.accepts == 2
    finally:
        await dest.aclose()
        await peer.stop()


async def test_captured_unparseable_ack_discards_connection() -> None:
    # capture_response turns an unparseable ACK into outcome='unparseable' instead of a raise
    # (ADR 0013), but the wire behavior is identical garbage — the §2.2 cache condition ("one ACK
    # read AND parsed") must fail the same way in both modes.
    peer = _AckPeer(raw_ack=frame("not an hl7 ack at all"))
    await peer.start()
    dest = _dest(peer.port, capture_response=True)
    try:
        response = await dest.send(_msg("M1"))
        assert response is not None and response.outcome == "unparseable"
        assert dest._conn is None  # the garbage-talking peer's connection was not kept
        assert dest.reconnects == 1
        peer.raw_ack = None  # the partner recovers
        ok = await dest.send(_msg("M2"))
        assert ok is not None and ok.outcome == "accepted"
        assert peer.accepts == 2  # next send dialed fresh
    finally:
        await dest.aclose()
        await peer.stop()


async def test_unparseable_ack_discards_connection() -> None:
    # "One ACK read AND PARSED" (§2.2): a reply frame that won't parse is a plain DeliveryError —
    # discard like any other failed transaction (only a NAK keeps the connection, AC-10).
    peer = _AckPeer(raw_ack=frame("not an hl7 ack at all"))
    await peer.start()
    dest = _dest(peer.port)
    try:
        with pytest.raises(DeliveryError, match="unparseable ACK"):
            await dest.send(_msg("M1"))
        assert dest._conn is None
        assert dest.reconnects == 1
    finally:
        await dest.aclose()
        await peer.stop()


# --- config plumbing (factory knobs → connector; inbound ignores; TOML rides) ---


def test_factory_carries_persistence_knobs_and_defaults() -> None:
    s = MLLP(port=1).settings
    assert (
        s["persistent"] is False
    )  # connect-per-message is the shipped default this release (opt-in reuse)
    assert s["idle_timeout_seconds"] == 60.0
    assert s["max_connection_age_seconds"] is None
    # Connector-side coercion mirrors sibling settings (receive_timeout convention): present-but-
    # falsy (None/0) disables a freshness check; values are validated/coerced at build, not per send.
    dest = MLLPDestination(
        Destination(
            name="o",
            type=ConnectorType.MLLP,
            settings=MLLP(
                host="h",
                port=1,
                persistent=False,
                idle_timeout_seconds=0,
                max_connection_age_seconds=30,
            ).settings,
        )
    )
    assert dest.persistent is False
    assert dest.idle_timeout_seconds is None  # 0 = never expire on idle
    assert dest.max_connection_age_seconds == 30.0


async def test_inbound_ignores_persistence_knobs() -> None:
    # Outbound-only, like timeout_seconds: an inbound with the knobs present builds + listens fine.
    src = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={
                "port": 0,
                "persistent": False,
                "idle_timeout_seconds": 5,
                "max_connection_age_seconds": 5,
            },
        )
    )

    async def _noop(raw: bytes) -> str | None:
        return None

    await src.start(_noop)
    try:
        assert src.sockport > 0
    finally:
        await src.stop()


def test_connections_toml_desugars_persistence_knobs(tmp_path: Path) -> None:
    # ADR 0007: the TOML loader calls the same MLLP() factory, so the new knobs ride for free —
    # no special-casing anywhere in the desugar path.
    path = tmp_path / "connections.toml"
    path.write_text(
        "[[outbound]]\n"
        'name = "OB_TEST_ADT"\n'
        'transport = "mllp"\n'
        "[outbound.settings]\n"
        'host = "127.0.0.1"\n'
        "port = 12575\n"
        "persistent = false\n"
        "idle_timeout_seconds = 30.0\n",
        encoding="utf-8",
    )
    registry = Registry()
    load_connections_file(path, registry)
    settings = registry.outbound["OB_TEST_ADT"].spec.settings
    assert settings["persistent"] is False
    assert settings["idle_timeout_seconds"] == 30.0
    assert settings["max_connection_age_seconds"] is None  # factory default applies
