# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What the DICOM C-STORE SCP does with a connection before it has an association (vault BACKLOG
#2712, limb 1): a peer the allowlist admits, which never finishes asking for one.

Every listener here binds ``127.0.0.1`` on an ephemeral port, and every certificate is a throwaway
written under ``tmp_path``.

**These tests need the ``[dicom]`` extra and SKIP without it.** A skipped test is not evidence: see
the note at the top of ``tests/test_dicom_scp_admission.py``.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import socket
import ssl
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydicom", reason="DICOM SCP tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCP tests need the [dicom] extra")

from messagefoundry.transports import dicom as dicom_module  # noqa: E402
from tests._dicom_sample import make_sr_part10  # noqa: E402
from tests.test_dicom_scp import _SCP_AE, _scu_cstore  # noqa: E402
from tests.test_dicom_scp_admission import (  # noqa: E402
    _LOG,
    _closed_after,
    _running_scp,
    _scu_cstore_tls,
    _send_slowly,
    _tls_settings,
    _until,
    _unverified_client_context,
    _warnings,
)
from tests.test_dicom_scp_admission import (  # noqa: E402
    _handshakes_in_flight as _pending_count,  # counts every connection with no association yet
)

_BOTH_TRANSPORTS = pytest.mark.parametrize("tls", [False, True], ids=["cleartext", "tls"])

_ASSOCIATE_AC = b"\x02"
_RELEASE_RQ = b"\x05\x00\x00\x00\x00\x04\x00\x00\x00\x00"
_RELEASE_RP = b"\x06"
#: What a peer has sent when it stalls: each is a read pynetdicom's own loop would never come back
#: from, except the first, which only its timers can end.
_STALLS = {
    "silent": b"",
    "one-byte": b"\x01",
    "header": b"\x01\x00\x00\x00\x10\x00",
    "header-and-body": b"\x01\x00\x00\x00\x10\x00" + b"\x00" * 10,
}


def _threads_outside_the_test() -> list[threading.Thread]:
    """Every live thread but the event loop's ``to_thread`` pool, which keeps its idle workers."""
    return [t for t in threading.enumerate() if not t.name.startswith("asyncio_")]


def _open(
    port: int, *, tls: bool = False, timeout: float = 5.0, source: str = "127.0.0.1"
) -> socket.socket:
    """A connection to the SCP. On a TLS listener its handshake has finished, so what the peer does
    next is the pre-association stage, not the handshake."""
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout, source_address=(source, 0))
    if not tls:
        return raw
    wrapped: ssl.SSLSocket = _unverified_client_context().wrap_socket(raw)
    return wrapped


def _stall(
    port: int, sends: bytes, *, tls: bool = False, source: str = "127.0.0.1"
) -> socket.socket:
    """A peer that sends ``sends`` and then nothing more, and stays connected."""
    sock = _open(port, tls=tls, source=source)
    if sends:
        sock.sendall(sends)
    return sock


def _closed_within(sock: socket.socket, wait: float) -> bool:
    """Whether the SCP ends this connection within ``wait`` seconds. Bytes it sends first, such as
    an A-ABORT, are read and ignored."""
    sock.settimeout(wait)
    deadline = time.monotonic() + wait
    try:
        while time.monotonic() < deadline:
            if sock.recv(4096) == b"":
                return True
    except TimeoutError:
        return False
    except OSError:
        return True  # a reset is a close too
    return False


def _a_real_association_request() -> bytes:
    """The A-ASSOCIATE-RQ bytes a pynetdicom SCU sends, addressed to the SCP under test."""
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]

    captured = bytearray()
    with socket.create_server(("127.0.0.1", 0)) as listener:

        def take_one_request() -> None:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5.0)
                while len(captured) < 6 or len(captured) < 6 + int.from_bytes(captured[2:6], "big"):
                    captured.extend(conn.recv(4096))

        taker = threading.Thread(target=take_one_request)
        taker.start()
        ae = AE(ae_title="MODALITY1")
        ae.add_requested_context(Verification)
        ae.associate("127.0.0.1", listener.getsockname()[1], ae_title=_SCP_AE)
        taker.join()
    return bytes(captured)


def _dribble(port: int, *, tls: bool, gap: float, give_up: float) -> float | None:
    """Send an A-ASSOCIATE-RQ that never finishes, one byte every ``gap`` seconds. Returns the seconds
    until the SCP closed the connection, or ``None`` if it was still open at ``give_up``.

    Every gap is far shorter than any idle bound, so only a deadline can end this peer. The bytes
    are a plausible opening: PDU type 1 and a length of 4096, then body bytes that never reach it.
    """
    sock = _open(port, tls=tls)
    sock.settimeout(gap)  # only now: a TLS handshake takes longer than a gap may on a slow runner
    return _send_slowly(sock, _STALLS["header"] + b"\x00" * 4096, give_up=give_up)


@_BOTH_TRANSPORTS
async def test_a_one_byte_dribble_is_ended_on_time_and_leaves_no_thread(
    tls: bool, tmp_path: Path
) -> None:
    extra = _tls_settings(tmp_path) if tls else {}
    settings = {"timeout_seconds": 2.0, "max_associations": 2, **extra}
    async with _running_scp(settings) as scp:
        await asyncio.to_thread(lambda: None)  # so the loop's worker is up before the baseline
        baseline = len(_threads_outside_the_test())

        took = await asyncio.to_thread(_dribble, scp.sockport, tls=tls, gap=0.1, give_up=8.0)

        assert took is not None, "a peer dribbling its association request was never ended"
        assert 1.5 <= took < 4.0, f"ended after {took:.2f}s against a 2.0s deadline"
        await _until(lambda: len(_threads_outside_the_test()) <= baseline)


async def test_sixty_silent_peers_at_two_associations_take_no_association_and_are_capped() -> None:
    # The reading the row was filed on: 60 connections at max_associations=2. On the unfixed code
    # active_associations reached 60, with 120 threads added.
    held: list[socket.socket] = []
    settings: dict[str, object] = {"max_associations": 2, "timeout_seconds": 30.0}
    async with _running_scp(settings) as scp:
        await asyncio.to_thread(lambda: None)  # so the loop's worker is up before the baseline
        baseline = len(_threads_outside_the_test())
        try:
            for _ in range(60):
                held.append(_open(scp.sockport))

            def all_sixty_met_a_control() -> bool:
                settled = _pending_count(scp) + scp._refusal_log.refusals
                return settled == 60 or len(scp._server.active_associations) > 2

            await _until(all_sixty_met_a_control)
            assert scp._server.active_associations == [], "a silent peer has an association"
            host_cap = dicom_module._MAX_PENDING_CONNECTIONS_PER_HOST
            assert scp._server._pending == {"127.0.0.1": host_cap}
            assert scp._refusal_log.refusals == 60 - host_cap
            added = len(_threads_outside_the_test()) - baseline
            assert added <= host_cap, f"{added} threads for {host_cap} held connections"
        finally:
            for sock in held:
                sock.close()


@_BOTH_TRANSPORTS
@pytest.mark.parametrize("stall", list(_STALLS))
async def test_a_real_sender_is_served_while_stalled_peers_are_held(
    stall: str, tls: bool, tmp_path: Path
) -> None:
    # The acceptance test. On the unfixed code a stalled peer had an Association thread, which
    # counts at pynetdicom's maximum_associations check whatever it has sent.
    captured: list[bytes] = []
    extra = _tls_settings(tmp_path) if tls else {}
    settings = {"max_associations": 2, "timeout_seconds": 30.0, **extra}
    held: list[socket.socket] = []
    async with _running_scp(settings, captured=captured) as scp:
        port = scp.sockport
        try:
            for _ in range(3):
                held.append(await asyncio.to_thread(_stall, port, _STALLS[stall], tls=tls))
            await _until(lambda: _pending_count(scp) == 3)

            if tls:
                ca_file = str(extra["tls_cert_file"])
                result = await asyncio.to_thread(
                    _scu_cstore_tls, port, make_sr_part10(), ca_file=ca_file
                )
            else:
                result = await asyncio.to_thread(_scu_cstore, port, make_sr_part10())

            assert result == (True, 0x0000), "a real sender was turned away"
            assert len(captured) == 1
            assert _pending_count(scp) == 3, "CONTROL: the stalled peers were still being held"
        finally:
            for sock in held:
                sock.close()


async def test_a_peer_that_connects_and_closes_holds_nothing() -> None:
    # On the unfixed code four of these held four slots for timeout_seconds, and a real sender 0.3 s
    # later failed. They are what a TCP health check does, so they are not refusals either.
    captured: list[bytes] = []
    settings: dict[str, object] = {"max_associations": 2, "timeout_seconds": 5.0}
    async with _running_scp(settings, captured=captured) as scp:
        for _ in range(4):
            _open(scp.sockport).close()
        await _until(lambda: scp._server._pending == {}, within=2.0)
        result = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert result == (True, 0x0000)
        assert scp._refusal_log.refusals == 0


async def test_a_silent_peer_is_refused_at_the_deadline_and_says_why(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with _running_scp({"timeout_seconds": 1.0}) as scp:
        with caplog.at_level(logging.WARNING, logger=_LOG):
            took = await asyncio.to_thread(_closed_after, scp.sockport, wait=5.0)
        assert took is not None, "a silent peer must be ended"
        assert took >= 0.8, f"closed after {took:.2f}s, before the 1.0s deadline"
        await _until(lambda: scp._server._pending == {})
        assert scp._server.active_associations == []
    lines = [m for m in _warnings(caplog) if "no complete association request within 1s" in m]
    assert len(lines) == 1, _warnings(caplog)
    assert "127.0.0.1" in lines[0]


async def test_a_peer_over_the_per_host_cap_is_closed_and_another_address_is_not(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(dicom_module, "_MAX_PENDING_CONNECTIONS_PER_HOST", 2)
    captured: list[bytes] = []
    held: list[socket.socket] = []
    async with _running_scp({"timeout_seconds": 30.0}, captured=captured) as scp:
        port = scp.sockport
        try:
            for _ in range(2):
                held.append(_open(port, source="127.0.0.2"))
            await _until(lambda: scp._server._pending == {"127.0.0.2": 2})

            over = _open(port, source="127.0.0.2")
            with caplog.at_level(logging.WARNING, logger=_LOG):
                closed = await asyncio.to_thread(_closed_within, over, 3.0)
            over.close()
            assert closed, "a connection over the per-host cap must be closed"
            assert any("from this address" in m for m in _warnings(caplog)), _warnings(caplog)

            # CONTROL: the cap is per address, so a sender on another one is not touched.
            result = await asyncio.to_thread(_scu_cstore, port, make_sr_part10())
            assert result == (True, 0x0000)
        finally:
            for sock in held:
                sock.close()


async def test_a_full_listener_serves_a_real_sender_once_the_deadline_expires(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The residual docs/DICOM.md states: at the cap, a sender waits for the deadline, not for the
    # stalled peers to go away.
    monkeypatch.setattr(dicom_module, "_MAX_PENDING_CONNECTIONS", 2)
    held: list[socket.socket] = []
    async with _running_scp({"timeout_seconds": 1.5}) as scp:
        port = scp.sockport
        try:
            for _ in range(2):
                held.append(_stall(port, _STALLS["one-byte"]))
            await _until(lambda: _pending_count(scp) == 2)
            with caplog.at_level(logging.WARNING, logger=_LOG):
                refused = await asyncio.to_thread(_scu_cstore, port, make_sr_part10())
            assert refused == (False, None), "CONTROL: the cap was full"
            assert any("already in progress" in m for m in _warnings(caplog)), _warnings(caplog)

            await _until(lambda: _pending_count(scp) == 0)  # the stalled peers are STILL connected
            result = await asyncio.to_thread(_scu_cstore, port, make_sr_part10())
            assert result == (True, 0x0000)
        finally:
            for sock in held:
                sock.close()


@_BOTH_TRANSPORTS
async def test_a_request_sent_in_pieces_inside_the_deadline_gets_its_association(
    tls: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The first PDU is read ahead of pynetdicom and handed on. The pieces outlast the read's poll
    # slice, and the release that follows proves the association reads the wire after the replay.
    monkeypatch.setattr(dicom_module, "_STOP_POLL_SECONDS", 0.05)
    request = await asyncio.to_thread(_a_real_association_request)
    extra = _tls_settings(tmp_path) if tls else {}
    async with _running_scp({"timeout_seconds": 10.0, **extra}) as scp:
        sock = await asyncio.to_thread(_open, scp.sockport, tls=tls)
        try:
            for piece in (request[:1], request[1:6], request[6:20], request[20:]):
                sock.sendall(piece)
                await asyncio.sleep(0.1)
            assert await asyncio.to_thread(sock.recv, 1) == _ASSOCIATE_AC
            await asyncio.to_thread(lambda: sock.recv(4096))  # the rest of the A-ASSOCIATE-AC
            sock.sendall(_RELEASE_RQ)
            assert await asyncio.to_thread(sock.recv, 1) == _RELEASE_RP
        finally:
            sock.close()


@pytest.mark.parametrize(
    "opening",
    [b"\x16\x03\x01", b"\x04\x00\x00\x00\x00\x00"],
    ids=["not-a-pdu", "a-pdu-that-is-not-a-request"],
)
async def test_a_peer_that_opens_with_anything_else_is_closed_at_once(
    opening: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        sock = _stall(scp.sockport, opening)
        try:
            with caplog.at_level(logging.WARNING, logger=_LOG):
                assert await asyncio.to_thread(_closed_within, sock, 3.0)
            assert any("not an association request" in m for m in _warnings(caplog))
            await _until(lambda: scp._server._pending == {})
            assert scp._server.active_associations == []
        finally:
            sock.close()


async def test_a_request_past_the_size_limit_is_closed_before_its_body_is_read(
    caplog: pytest.LogCaptureFixture,
) -> None:
    limit = dicom_module._MAX_ASSOCIATE_RQ_BYTES

    def header(total: int) -> bytes:
        return b"\x01\x00" + (total - dicom_module._PDU_HEADER_BYTES).to_bytes(4, "big")

    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        # CONTROL: one exactly at the limit is still being read.
        at_limit = _stall(scp.sockport, header(limit))
        over = _stall(scp.sockport, header(limit + 1))
        try:
            with caplog.at_level(logging.WARNING, logger=_LOG):
                assert await asyncio.to_thread(_closed_within, over, 3.0)
            assert any(f"over {limit} bytes" in m for m in _warnings(caplog)), _warnings(caplog)
            assert not await asyncio.to_thread(_closed_within, at_limit, 0.5)
        finally:
            at_limit.close()
            over.close()


async def test_the_deadline_is_the_timeout_the_ae_resolved() -> None:
    # pynetdicom turns a negative timeout into 30 s, so the raw setting would refuse every peer.
    async with _running_scp({"timeout_seconds": -1.0}) as scp:
        assert scp._ae.acse_timeout == 30
        assert await asyncio.to_thread(_closed_after, scp.sockport, wait=0.3) is None


def _wrong_protocol(request: bytes) -> bytes:
    return request[:6] + b"\x00\x02" + request[8:]


@pytest.mark.parametrize(
    ("build", "reason"),
    [
        (lambda _request: b"\x01\x00\x00\x00\x00\x00", "does not decode"),
        (_wrong_protocol, "wrong protocol"),
    ],
    ids=["no-body", "wrong-protocol"],
)
async def test_a_request_the_dul_would_not_pass_on_starts_no_association(
    build: Callable[[bytes], bytes], reason: str, caplog: pytest.LogCaptureFixture
) -> None:
    # pynetdicom's DUL answers each of these and gives the association nothing, so a started
    # Association waited out timeout_seconds with its socket already closed, counted against
    # max_associations and outside every cap here. Repeating one would go round the slots.
    opening = build(await asyncio.to_thread(_a_real_association_request))
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        sock = _stall(scp.sockport, opening)
        try:
            with caplog.at_level(logging.WARNING, logger=_LOG):
                assert await asyncio.to_thread(_closed_within, sock, 3.0)
            assert any(reason in m for m in _warnings(caplog)), _warnings(caplog)
            await _until(lambda: scp._server._pending == {})
            assert scp._server.active_associations == [], "the request started an association"
        finally:
            sock.close()


async def test_a_rate_wait_does_not_spend_the_peers_deadline() -> None:
    # EVT_CONN_OPEN still fires before the request is read, so the engine's own wait is not the
    # peer being slow. The first two associations spend the bucket, so the third waits past a
    # deadline that a clock started at accept would already have run out.
    captured: list[bytes] = []
    settings: dict[str, object] = {
        "timeout_seconds": 0.5,
        "max_associations_per_second": 0.5,
        "association_burst": 1,
    }
    async with _running_scp(settings, captured=captured) as scp:
        data = make_sr_part10()
        for _ in range(2):
            assert await asyncio.to_thread(_scu_cstore, scp.sockport, data) == (True, 0x0000)
        started = time.monotonic()
        assert await asyncio.to_thread(_scu_cstore, scp.sockport, data) == (True, 0x0000)
        took = time.monotonic() - started
        assert took > 0.5, f"CONTROL: the wait ({took:.2f}s) did not outlast the deadline"
        assert len(captured) == 3


async def test_a_fault_before_the_association_gives_the_slot_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pynetdicom.transport import RequestHandler

    def broken(self: Any) -> Any:
        raise RuntimeError("no association for this connection")

    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        with monkeypatch.context() as patched:
            patched.setattr(RequestHandler, "_create_association", broken)
            took = await asyncio.to_thread(_closed_after, scp.sockport, wait=3.0)
            assert took is not None, "socketserver closes a connection whose handler raised"
        await _until(lambda: scp._server._pending == {})
        # CONTROL: the listener goes on serving.
        result = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert result == (True, 0x0000)


@_BOTH_TRANSPORTS
async def test_stop_does_not_wait_out_a_peer_with_no_association(tls: bool, tmp_path: Path) -> None:
    extra = _tls_settings(tmp_path) if tls else {}
    async with _running_scp({"timeout_seconds": 30.0, **extra}) as scp:
        silent = await asyncio.to_thread(_stall, scp.sockport, _STALLS["one-byte"], tls=tls)
        try:
            await _until(lambda: _pending_count(scp) == 1)
            started = time.monotonic()
            await scp.stop()
            took = time.monotonic() - started
            assert took < 5.0, f"stop() took {took:.1f}s"
        finally:
            silent.close()


async def test_a_stall_mid_pdu_on_an_established_association_is_not_bounded_yet() -> None:
    """PINS A GAP, so that it is on the record and cannot close unnoticed. Measured at pynetdicom
    3.0.4: the peer finishes its association, starts a PDU and stops. It was still open 10 s later
    at ``timeout_seconds`` 2, and it holds a ``max_associations`` slot until it closes.

    The first-request read covers the path up to the association only. After it, reading is the
    DUL thread's blocking ``recv``, for the reason ``_admitting_server_class`` gives. Vault BACKLOG
    #2712 limb 1 closes the connections before an association, so this is not that limb's to fix,
    and docs/DICOM.md states the residual. When this test fails because the peer WAS ended, the gap
    has closed: replace this test with one that asserts so, and correct docs/DICOM.md.
    """
    request = await asyncio.to_thread(_a_real_association_request)
    settings: dict[str, object] = {"max_associations": 2, "timeout_seconds": 1.0}
    async with _running_scp(settings) as scp:
        sock = await asyncio.to_thread(_open, scp.sockport)
        try:
            sock.sendall(request)
            assert await asyncio.to_thread(sock.recv, 1) == _ASSOCIATE_AC
            await asyncio.to_thread(lambda: sock.recv(4096))
            sock.sendall(b"\x04\x00\x00\x00\x10\x00" + b"\x00" * 10)  # P-DATA-TF, 4096 announced
            assert not await asyncio.to_thread(_closed_within, sock, 2.0)
            assert len(scp._server.active_associations) == 1
        finally:
            sock.close()
        await _until(lambda: scp._server.active_associations == [])


def test_the_pynetdicom_seams_the_first_request_read_relies_on_are_still_there() -> None:
    """What ``_admitting_server_class`` assumes about pynetdicom, past the server hooks that
    ``test_the_scp_runs_its_own_server_class_over_the_pinned_hooks`` pins. Read against 3.0.4; the
    ``[dicom]`` comment in ``pyproject.toml`` says to re-read these before raising the cap.
    """
    from pynetdicom.acse import ACSE
    from pynetdicom.association import Association
    from pynetdicom.dul import DULServiceProvider
    from pynetdicom.fsm import AE_6
    from pynetdicom.transport import AssociationSocket, RequestHandler

    # The replaced handle() does what the stock one does, in the order the stock one does it, with
    # the read added between the last two steps.
    stock = inspect.getsource(RequestHandler.handle)
    opened = stock.index("_create_association()")
    assert opened < stock.index("EVT_CONN_OPEN") < stock.index("assoc.start()")
    assert "AssociationSocket(assoc, client_socket=self.request)" in inspect.getsource(
        RequestHandler._create_association
    )
    # A second socket is refused, which is why the socket is converted rather than replaced.
    assert "already has a socket set" in inspect.getsource(Association.set_socket)
    # ready and recv are what the replay overrides, and ready is what tells the DUL to read.
    assert isinstance(vars(AssociationSocket)["ready"], property)
    assert callable(vars(AssociationSocket)["recv"])
    reader = inspect.getsource(DULServiceProvider._read_pdu_data)
    assert "recv(6)" in reader and "recv(pdu_length)" in reader
    # _check_association_request repeats these steps, so that the two cannot disagree on a request.
    assert "pdu.decode(b)" in inspect.getsource(DULServiceProvider._decode_pdu)
    indication = inspect.getsource(AE_6)
    assert "to_primitive()" in indication and "protocol_version != 0x0001" in indication
    # A started Association is what counts at the check, whatever it has read. That is the reason
    # a stalled peer must not have one.
    negotiate = inspect.getsource(ACSE._negotiate_as_acceptor)
    assert "active_associations" in negotiate and "maximum_associations" in negotiate


def test_the_doc_states_the_bounds_of_the_first_request_read() -> None:
    doc = (Path(__file__).resolve().parents[1] / "docs" / "DICOM.md").read_text(encoding="utf-8")
    assert f"at most {dicom_module._MAX_PENDING_CONNECTIONS} connections" in doc
    assert f"at most {dicom_module._MAX_ASSOCIATE_RQ_BYTES // 1024} KiB" in doc
    assert "`timeout_seconds`" in doc
