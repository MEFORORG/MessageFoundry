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
import contextlib
import inspect
import logging
import socket
import ssl
import struct
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
from tests.test_dicom_scp import _SCP_AE, _build_scp, _scu_cstore  # noqa: E402
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
_PEER_CLOSES_OR_STAYS = pytest.mark.parametrize(
    "peer_closes", [True, False], ids=["peer-closes", "peer-stays"]
)

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


async def _thread_baseline() -> int:
    """The thread count to come back to. The loop's worker is started first, so it is not in the
    baseline for one test and out of it for another."""
    await asyncio.to_thread(lambda: None)
    return len(_threads_outside_the_test())


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
        baseline = await _thread_baseline()

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
        baseline = await _thread_baseline()
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
    # stalled peers to leave. These peers do not reconnect; one that did could take the slot again.
    monkeypatch.setattr(dicom_module, "_MAX_PENDING_CONNECTIONS", 2)
    held: list[socket.socket] = []
    async with _running_scp({"timeout_seconds": 3.0}) as scp:
        port = scp.sockport
        try:
            for _ in range(2):
                held.append(_stall(port, _STALLS["one-byte"]))
            await _until(lambda: _pending_count(scp) == 2)
            with caplog.at_level(logging.WARNING, logger=_LOG):
                refused = await asyncio.to_thread(_scu_cstore, port, make_sr_part10())
            assert refused == (False, None), "CONTROL: the cap was full"
            assert any("already in progress" in m for m in _warnings(caplog)), _warnings(caplog)

            await _until(lambda: _pending_count(scp) == 0)  # the SCP closed them; they never left
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
            sock.sendall(_RELEASE_RQ[:3])  # a later PDU in pieces is served too
            await asyncio.sleep(0.1)
            sock.sendall(_RELEASE_RQ[3:])
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


@pytest.mark.parametrize("seconds", [0, 0.0, -1.0])
def test_a_timeout_that_would_close_every_peer_is_refused_at_build(seconds: float) -> None:
    with pytest.raises(ValueError, match="timeout_seconds must be at least 1 second"):
        _build_scp([], timeout_seconds=seconds)
    assert _build_scp([], timeout_seconds=1.0)._timeout == 1.0  # CONTROL


def _wrong_protocol(request: bytes) -> bytes:
    return request[:6] + b"\x00\x02" + request[8:]


def _rj(result: int, source: int, diagnostic: int) -> bytes:
    """The A-ASSOCIATE-RJ PDU (PS3.8 section 9.3.4) carrying these three fields."""
    return b"\x03\x00" + (4).to_bytes(4, "big") + bytes((0, result, source, diagnostic))


@pytest.mark.parametrize(
    ("build", "reason", "answer"),
    [
        # An invalid PDU in Sta2 is Evt19, and AA-1 answers it with an A-ABORT, source and reason 0.
        (
            lambda _request: b"\x01\x00\x00\x00\x00\x00",
            "does not decode",
            b"\x07\x00" + (4).to_bytes(4, "big") + bytes(4),
        ),
        # Rejected-permanent, service provider (ACSE), protocol version not supported.
        (_wrong_protocol, "wrong protocol", _rj(0x01, 0x02, 0x02)),
    ],
    ids=["no-body", "wrong-protocol"],
)
async def test_a_request_the_dul_would_not_pass_on_starts_no_association(
    build: Callable[[bytes], bytes], reason: str, answer: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    # pynetdicom's DUL answers each of these and gives the association nothing, so a started
    # Association waited out timeout_seconds with its socket already closed, counted against
    # max_associations and outside every cap here. Repeating one would go round the slots.
    opening = build(await asyncio.to_thread(_a_real_association_request))
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        sock = _stall(scp.sockport, opening)
        try:
            with caplog.at_level(logging.WARNING, logger=_LOG):
                sock.settimeout(3.0)
                assert await asyncio.to_thread(sock.recv, 64) == answer
                assert await asyncio.to_thread(_closed_within, sock, 3.0)
            assert any(reason in m for m in _warnings(caplog)), _warnings(caplog)
            await _until(lambda: scp._server._pending == {})
            assert scp._server.active_associations == [], "the request started an association"
        finally:
            sock.close()


async def _a_held_association(port: int, *, tls: bool = False) -> socket.socket:
    """A peer that has its association, and keeps it."""
    request = await asyncio.to_thread(_a_real_association_request)
    sock = await asyncio.to_thread(_open, port, tls=tls)
    try:
        sock.sendall(request)
        assert await asyncio.to_thread(sock.recv, 1) == _ASSOCIATE_AC
        await asyncio.to_thread(lambda: sock.recv(4096))
    except BaseException:
        sock.close()  # the caller's own try has not started yet
        raise
    return sock


def _p_data_header() -> bytes:
    """The head of a P-DATA-TF that announces 4096 bytes."""
    return b"\x04\x00\x00\x00\x10\x00"


@_BOTH_TRANSPORTS
@pytest.mark.parametrize(
    "stray",
    [b"\x07", _p_data_header(), _p_data_header() + b"\x00" * 10],
    ids=["one-byte", "header", "header-and-body"],
)
async def test_a_stall_mid_pdu_on_an_established_association_is_ended(
    stray: bytes, tls: bool, tmp_path: Path
) -> None:
    # Measured on the first build of this row, which read only the first PDU: still open 10 s later
    # at timeout_seconds 2, holding a max_associations slot until the peer closed. The DUL was
    # blocked in recv, so its timers could not run, and kill() would not return.
    extra = _tls_settings(tmp_path) if tls else {}
    settings = {"max_associations": 2, "timeout_seconds": 1.0, **extra}
    async with _running_scp(settings) as scp:
        baseline = await _thread_baseline()
        sock = await _a_held_association(scp.sockport, tls=tls)
        try:
            sock.sendall(stray)
            assert await asyncio.to_thread(_closed_within, sock, 5.0), (
                "the stalled peer was not ended"
            )
            await _until(lambda: len(_threads_outside_the_test()) <= baseline)
            assert scp._server.active_associations == []
        finally:
            sock.close()


async def test_a_dribble_mid_pdu_on_an_established_association_is_ended_on_time() -> None:
    # A deadline, not an idle timer: every gap here is far shorter than timeout_seconds.
    async with _running_scp({"timeout_seconds": 1.0}) as scp:
        sock = await _a_held_association(scp.sockport)
        sock.settimeout(0.1)
        pending = _p_data_header() + b"\x00" * 4096
        took = await asyncio.to_thread(_send_slowly, sock, pending, give_up=6.0)
        assert took is not None, "a peer dribbling a PDU was never ended"
        assert took < 4.0, f"ended after {took:.2f}s against a 1.0s deadline"


async def test_a_refused_peer_that_stalls_after_its_request_goes_round_nothing() -> None:
    # Found by review of this row's first build. Each peer sends a whole request, so it spends no
    # slot, plus one stray byte. Over max_associations it is rejected, then the DUL blocked reading
    # the byte and kill() never returned: six peers at max_associations=1 held 12 threads for as
    # long as they stayed connected, and a real sender was turned away.
    request = await asyncio.to_thread(_a_real_association_request)
    settings: dict[str, object] = {"max_associations": 1, "timeout_seconds": 1.0}
    held: list[socket.socket] = []
    async with _running_scp(settings) as scp:
        baseline = await _thread_baseline()
        try:
            for _ in range(6):
                held.append(await asyncio.to_thread(_stall, scp.sockport, request + b"\x07"))
            # A peer still in the listen backlog, or accepted with its thread not yet started, is
            # no thread and no association, so the count below can pass while that peer waits. It
            # then starts and takes the one slot, and the sender is rightly refused. So each peer's
            # close is awaited first: it shows the SCP has reached that peer, and a blocked DUL
            # never sends it.
            closed = [await asyncio.to_thread(_closed_within, sock, 8.0) for sock in held]
            assert all(closed), f"{closed.count(False)} of {len(held)} peers not closed within 8 s"
            # An Association thread outlives the close its peer reads, and the baseline can hold a
            # dying thread of the test before, so the count below may not wait for this one. A slot
            # still held here runs this wait out, as a slot held for good always has.
            await _until(lambda: scp._server.active_associations == [], within=8.0)
            await _until(lambda: len(_threads_outside_the_test()) <= baseline, within=8.0)
            assert scp._server.active_associations == []
            assert await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10()) == (
                True,
                0x0000,
            )
        finally:
            for sock in held:
                sock.close()


async def test_a_stray_byte_behind_a_request_does_not_delay_the_association_check() -> None:
    # The DUL reads before it takes its next event, so this byte used to hold the request unanswered
    # for a whole deadline, with the slot already given back. Review of this row's second build
    # measured 300 such peers at max_associations=2: active_associations 300, 601 threads, 0 refusals.
    request = await asyncio.to_thread(_a_real_association_request)
    settings: dict[str, object] = {"max_associations": 2, "timeout_seconds": 30.0}
    held: list[socket.socket] = []
    async with _running_scp(settings) as scp:
        baseline = await _thread_baseline()
        try:
            for _ in range(40):
                held.append(await asyncio.to_thread(_stall, scp.sockport, request + b"\x07"))

            def only_the_two_accepted_are_left() -> bool:
                return len(scp._server.active_associations) <= 2

            await _until(only_the_two_accepted_are_left)  # well inside the 30 s deadline
            # Every peer over the limit is answered before the threads are counted, so the count is
            # the settled state, not one read while the last connections sat in the listen backlog.
            rejected = [await asyncio.to_thread(_closed_within, sock, 0.2) for sock in held]
            assert rejected.count(True) >= 38, f"{rejected.count(True)} of 40 peers closed at once"

            # Awaited, not read once: a rejected peer's own connection thread outlives the close
            # its peer reads by a moment. Measured on Windows: a lone process_request_thread as a
            # fifth thread. The wait is well inside the 30 s deadline a delayed check would take.
            last: list[tuple[int, int]] = []

            def settled() -> bool:
                reading = (
                    len(scp._server.active_associations),
                    len(_threads_outside_the_test()) - baseline,
                )
                last[:] = [reading]
                return reading[0] <= 2 and reading[1] <= 4

            try:
                await _until(settled)
            except AssertionError:
                associations, added = last[0]
                raise AssertionError(
                    f"{associations} associations and {added} threads for two associations"
                ) from None
        finally:
            for sock in held:
                sock.close()


#: The most a shrunk send buffer may read back as. Linux doubles the 4096 asked for; Windows does not.
_SMALL_SEND_BUFFER_CEILING = 65536


def _shrink_accepted_send_buffers(scp: Any, monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Make the send buffer of each connection ``scp`` accepts from now on small, and return the
    list each one's size, as read back, is appended to.

    A test that floods requests at a peer that never reads relies on the SCP's sends blocking. On
    Linux loopback the stock send buffer grows to megabytes, and the SCP answers each C-ECHO slower
    than the peer sends them, so the SCP could go on answering for longer than such a test waits
    with no send ever blocked. Measured as a red on ubuntu-latest."""
    accept = scp._server.get_request
    shrunk: list[int] = []

    def accept_with_a_small_send_buffer() -> tuple[socket.socket, Any]:
        conn, address = accept()
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            shrunk.append(conn.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
        except BaseException:
            conn.close()
            raise
        return conn, address

    monkeypatch.setattr(scp._server, "get_request", accept_with_a_small_send_buffer)
    return shrunk


def _c_echo_rq(message_id: int) -> bytes:
    """A P-DATA-TF PDU carrying a whole C-ECHO-RQ command, implicit VR little endian, on context 1."""

    def element(tag: tuple[int, int], value: bytes) -> bytes:
        return struct.pack("<HHI", *tag, len(value)) + value

    rest = (
        element((0x0000, 0x0002), b"1.2.840.10008.1.1\x00")
        + element((0x0000, 0x0100), struct.pack("<H", 0x0030))
        + element((0x0000, 0x0110), struct.pack("<H", message_id & 0xFFFF))
        + element((0x0000, 0x0800), struct.pack("<H", 0x0101))
    )
    command = element((0x0000, 0x0000), struct.pack("<I", len(rest))) + rest
    item = struct.pack(">IBB", len(command) + 2, 1, 0x03) + command
    return b"\x04\x00" + struct.pack(">I", len(item)) + item


async def test_a_peer_that_never_reads_cannot_block_the_association_for_good(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The DUL sends on its own thread, so a blocked send stops it reaching anything else. Review of
    # this row's second build measured it still blocked 12 s on at timeout_seconds 1, and alive
    # after stop().
    request = await asyncio.to_thread(_a_real_association_request)
    settings: dict[str, object] = {"max_associations": 2, "timeout_seconds": 1.0}
    async with _running_scp(settings) as scp:
        # A red on ubuntu-latest, where the association outlived the 15 s wait below: see
        # _shrink_accepted_send_buffers.
        shrunk = _shrink_accepted_send_buffers(scp, monkeypatch)
        baseline = await _thread_baseline()
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sock.settimeout(5.0)
        sock.connect(("127.0.0.1", scp.sockport))
        try:
            sock.sendall(request)
            assert await asyncio.to_thread(sock.recv, 1) == _ASSOCIATE_AC
            assert len(shrunk) == 1 and shrunk[0] <= _SMALL_SEND_BUFFER_CEILING, shrunk

            def flood() -> None:
                # Far more responses than the two socket buffers hold, and none of them read.
                pending = memoryview(b"".join(_c_echo_rq(n) for n in range(1, 40000)))
                sock.settimeout(1.0)
                with contextlib.suppress(OSError):
                    while pending:
                        pending = pending[sock.send(pending[:65536]) :]

            with caplog.at_level(logging.WARNING, logger=_LOG):
                await asyncio.to_thread(flood)
                await _until(lambda: len(_threads_outside_the_test()) <= baseline, within=15.0)
            assert scp._server.active_associations == []
            # The send's own deadline ended it, not an idle timer after every request was served.
            ended = [m for m in _warnings(caplog) if "a send did not finish within 1s" in m]
            assert ended, _warnings(caplog)
        finally:
            sock.close()


async def test_stop_ends_a_reader_stalled_mid_pdu() -> None:
    # The DUL thread is not a daemon, so one left blocked would keep the process from exiting.
    request = await asyncio.to_thread(_a_real_association_request)
    settings: dict[str, object] = {"timeout_seconds": 30.0}
    baseline = 0
    async with _running_scp(settings) as scp:
        await asyncio.to_thread(lambda: None)
        baseline = len(_threads_outside_the_test())
        sock = await asyncio.to_thread(_open, scp.sockport)
        try:
            sock.sendall(request + _p_data_header())
            await _until(lambda: len(scp._server.active_associations) == 1)
            await scp.stop()
            await _until(lambda: len(_threads_outside_the_test()) < baseline)
        finally:
            sock.close()


def _without_sub_items(kind: str) -> Callable[[bytes], bytes]:
    """A builder that takes every ``kind`` sub-item, a class name in ``pynetdicom.pdu_items``, out
    of each presentation context of a request."""

    def build(request: bytes) -> bytes:
        from pynetdicom import pdu_items
        from pynetdicom.pdu import A_ASSOCIATE_RQ

        dropped = getattr(pdu_items, kind)
        pdu = A_ASSOCIATE_RQ()
        pdu.decode(request)
        for context in pdu.presentation_context:
            context.abstract_transfer_syntax_sub_items = [
                item
                for item in context.abstract_transfer_syntax_sub_items
                if not isinstance(item, dropped)
            ]
        encoded: bytes = pdu.encode()
        return encoded

    return build


_without_transfer_syntaxes = _without_sub_items("TransferSyntaxSubItem")
_without_abstract_syntaxes = _without_sub_items("AbstractSyntaxSubItem")


async def _ends_with_no_thread(
    scp: Any, sock: socket.socket, baseline: int, *, peer_closes: bool
) -> None:
    """The SCP's side of ``sock`` ends, with no thread and no association left: after the peer has
    gone, or, where it stays connected, by the SCP closing it."""
    try:
        if peer_closes:
            sock.close()
        else:
            assert await asyncio.to_thread(_closed_within, sock, 5.0), "the SCP left it open"
        await _until(lambda: len(_threads_outside_the_test()) <= baseline)
        assert scp._server.active_associations == []
    finally:
        sock.close()


async def test_fifty_requests_with_a_context_of_no_transfer_syntax_leave_no_thread(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The shape the review measured. Each passed the first checks and then killed its Association
    # thread in negotiation, and the DUL stayed for good in Sta3: 5 threads went to 55 with nothing
    # counted anywhere, and 52 non-daemon DUL threads outlived stop().
    opening = _without_transfer_syntaxes(await asyncio.to_thread(_a_real_association_request))
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        baseline = await _thread_baseline()
        with caplog.at_level(logging.WARNING, logger=_LOG):
            for _ in range(50):
                await asyncio.to_thread(lambda: _stall(scp.sockport, opening).close())
            await _until(lambda: len(_threads_outside_the_test()) <= baseline)
        assert scp._server.active_associations == []
        assert any("does not negotiate" in m for m in _warnings(caplog)), _warnings(caplog)
        await scp.stop()
        await _until(lambda: len(_threads_outside_the_test()) < baseline)


async def test_fifty_requests_with_a_context_of_no_abstract_syntax_are_refused_and_answered(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Review round f695486699 measured this shape on the previous head: it got past the transfer
    # syntax check, and its Association thread died in negotiation with a TypeError, 20 times in 20.
    # The peer saw a bare close and nothing was counted, and under serve each death would write one
    # unthrottled CRITICAL line. The pre-check now runs the negotiation itself.
    opening = _without_abstract_syntaxes(await asyncio.to_thread(_a_real_association_request))
    deaths: list[threading.ExceptHookArgs] = []
    previous_hook = threading.excepthook
    threading.excepthook = deaths.append
    try:
        async with _running_scp({"timeout_seconds": 30.0}) as scp:
            baseline = await _thread_baseline()

            def one_peer() -> bytes:
                sock = _stall(scp.sockport, opening)
                try:
                    sock.settimeout(3.0)
                    return sock.recv(64)
                finally:
                    sock.close()

            with caplog.at_level(logging.WARNING, logger=_LOG):
                answers = [await asyncio.to_thread(one_peer) for _ in range(50)]
                await _until(lambda: len(_threads_outside_the_test()) <= baseline)
            assert scp._refusal_log.refusals == 50, (
                "a request that cannot negotiate was not refused"
            )
            assert answers == [_rj(0x01, 0x01, 0x01)] * 50
            assert scp._server.active_associations == []
            assert any("does not negotiate" in m for m in _warnings(caplog)), _warnings(caplog)
    finally:
        threading.excepthook = previous_hook
    assert deaths == [], [str(d.exc_value) for d in deaths]


@pytest.mark.parametrize(
    "build",
    [lambda request: request, _without_abstract_syntaxes],
    ids=["over-max-associations", "does-not-negotiate"],
)
async def test_a_refused_request_with_a_stray_byte_behind_it_still_gets_its_rejection(
    build: Callable[[bytes], bytes],
) -> None:
    # Review round f695486699 measured the first case on the previous head, on Windows loopback:
    # a request alone got its A-ASSOCIATE-RJ 25 times in 25, and the same request with one stray
    # byte behind it got a reset and no rejection 25 times in 25. The DUL closed in Sta13 over the
    # unread byte. The second case is the same close on the connection's own thread. The peer reads
    # only after the SCP has closed, as a busy sender may: a reset that arrives first discards the
    # answer on Windows. Whether it does on Linux was not measured, so there this may pass either way.
    opening = build(await asyncio.to_thread(_a_real_association_request)) + b"\x07"
    async with _running_scp({"max_associations": 1, "timeout_seconds": 30.0}) as scp:
        held = await _a_held_association(scp.sockport)
        try:
            for _ in range(10):
                sock = await asyncio.to_thread(_stall, scp.sockport, opening)
                try:
                    await asyncio.sleep(0.3)
                    sock.settimeout(3.0)
                    assert await asyncio.to_thread(sock.recv, 1) == b"\x03"
                    assert await asyncio.to_thread(_closed_within, sock, 3.0)
                finally:
                    sock.close()
        finally:
            held.close()


async def test_a_peer_the_allowlist_refuses_is_closed_with_nothing_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Review round b1622800ef: be3bc3e030 drained in the server's shutdown_request, which
    # socketserver also calls on the accept loop for an allowlist refusal, so that peer's bytes were
    # read. docs/DICOM.md says such a peer is closed before anything is read from it.
    drained: list[object] = []
    real = dicom_module._drain_readable

    def recorded(sock: socket.socket) -> None:
        drained.append(sock)
        real(sock)

    monkeypatch.setattr(dicom_module, "_drain_readable", recorded)
    async with _running_scp({"source_ip_allowlist": ["127.0.0.1"]}) as scp:
        sock = _stall(scp.sockport, _STALLS["header-and-body"], source="127.0.0.2")
        try:
            assert await asyncio.to_thread(_closed_within, sock, 3.0)
        finally:
            sock.close()
        await _until(lambda: scp._refusal_log.refusals == 1)
    assert drained == []


async def test_a_read_deadline_on_an_accepted_association_is_logged_as_an_end_not_a_refusal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # On the previous head this logged "refused a connection" and spent the address's refusal line,
    # though the SCP had accepted the association.
    async with _running_scp({"timeout_seconds": 1.0}) as scp:
        sock = await _a_held_association(scp.sockport)
        try:
            with caplog.at_level(logging.WARNING, logger=_LOG):
                sock.sendall(_p_data_header())
                assert await asyncio.to_thread(_closed_within, sock, 5.0)
                await _until(lambda: scp._ended_log.refusals == 1)
        finally:
            sock.close()
        assert scp._refusal_log.refusals == 0, "an accepted association was counted as refused"
    ended = [m for m in _warnings(caplog) if "ended an association with 127.0.0.1" in m]
    assert len(ended) == 1, _warnings(caplog)
    assert "no complete PDU within 1s" in ended[0]
    assert not any("refused" in m for m in _warnings(caplog)), _warnings(caplog)


async def test_a_connection_refused_before_its_association_fires_conn_close() -> None:
    # pynetdicom pairs every EVT_CONN_OPEN with an EVT_CONN_CLOSE when its DUL closes the connection.
    # On the previous head a connection that ended in the first read fired only the open.
    from pynetdicom import evt

    opened: list[Any] = []
    closed: list[Any] = []
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        scp._server.bind(evt.EVT_CONN_OPEN, opened.append)
        scp._server.bind(evt.EVT_CONN_CLOSE, closed.append)
        for opening in (b"\x04\x00\x00\x00\x00\x00", b"\x01\x00\x00\x00\x00\x00"):
            sock = _stall(scp.sockport, opening)
            try:
                assert await asyncio.to_thread(_closed_within, sock, 3.0)
            finally:
                sock.close()
        await _until(lambda: len(closed) == 2)
        assert len(opened) == 2
        assert [e.address for e in closed] == [e.address for e in opened]


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
@_PEER_CLOSES_OR_STAYS
async def test_a_dul_whose_association_died_before_it_answered_is_ended(
    peer_closes: bool,
) -> None:
    # Whatever kills the Association thread, nobody is left to answer or to read the idle timer. The
    # check is switched off here so that the crash happens: the crash is the subject.
    opening = _without_transfer_syntaxes(await asyncio.to_thread(_a_real_association_request))
    async with _running_scp({"max_associations": 2, "timeout_seconds": 30.0}) as scp:
        baseline = await _thread_baseline()
        scp._server._check_association_request = lambda _sock, _pdu: None
        sock = _stall(scp.sockport, opening)
        await _ends_with_no_thread(scp, sock, baseline, peer_closes=peer_closes)


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
async def test_a_dul_whose_association_died_after_it_was_established_is_ended(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pynetdicom.association import Association

    def dies(self: Any) -> None:
        raise RuntimeError("the association's reactor failed")

    request = await asyncio.to_thread(_a_real_association_request)
    async with _running_scp({"timeout_seconds": 30.0}) as scp:
        baseline = await _thread_baseline()
        monkeypatch.setattr(Association, "_run_reactor", dies)
        sock = _stall(scp.sockport, request)
        await _ends_with_no_thread(scp, sock, baseline, peer_closes=False)


def _held_on_the_dul_thread_until_the_wait_runs_out() -> Callable[[Any], Any]:
    """A stand-in for ``A_ASSOCIATE_RQ.to_primitive`` that holds AE-6 on the DUL thread until the
    association's wait for the request has run out and killed it, so the order is fixed by the
    event. The pre-check on the connection's own thread is not held."""
    from pynetdicom.dul import DULServiceProvider
    from pynetdicom.pdu import A_ASSOCIATE_RQ

    real = A_ASSOCIATE_RQ.to_primitive

    def held(self: Any) -> Any:
        thread = threading.current_thread()
        if isinstance(thread, DULServiceProvider):
            deadline = time.monotonic() + 5.0
            while not thread.assoc._kill and time.monotonic() < deadline:
                time.sleep(0.001)
        return real(self)

    return held


@_PEER_CLOSES_OR_STAYS
async def test_a_wait_that_runs_out_during_ae_6_leaves_no_association_counted(
    peer_closes: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The review measured this with timeout_seconds tuned to fall inside a real decode. Here the DUL
    # is held instead, so the order is fixed: the wait runs out, then AE-6 moves to Sta3. On
    # a9101dbdb4 ready was then False for good, kill() spun, and a live AcceptorThread stayed
    # counted against max_associations after the peer had gone and after stop().
    from pynetdicom.pdu import A_ASSOCIATE_RQ

    request = await asyncio.to_thread(_a_real_association_request)
    held = _held_on_the_dul_thread_until_the_wait_runs_out()
    monkeypatch.setattr(A_ASSOCIATE_RQ, "to_primitive", held)
    async with _running_scp({"max_associations": 2, "timeout_seconds": 1.0}) as scp:
        baseline = await _thread_baseline()
        sock = _stall(scp.sockport, request)
        await _ends_with_no_thread(scp, sock, baseline, peer_closes=peer_closes)


@_PEER_CLOSES_OR_STAYS
async def test_a_kill_before_the_answer_ends_the_dul_at_the_default_timeout(
    peer_closes: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The same path at the shipped 30 s timeout, with its expiry forced rather than waited for: the
    # association's wait for the request returns nothing, as it does when the wait runs out, while
    # the request's primitive is already on its queue and the DUL is in Sta3. docs/DICOM.md's
    # default is what this runs with.
    from pynetdicom.dul import DULServiceProvider

    real_wait = DULServiceProvider.receive_pdu
    request = await asyncio.to_thread(_a_real_association_request)

    def wait_runs_out(self: Any, wait: bool = False, timeout: float | None = None) -> Any:
        if not wait:
            return real_wait(self, wait, timeout)
        deadline = time.monotonic() + 5.0
        while self.state_machine.current_state != "Sta3" and time.monotonic() < deadline:
            time.sleep(0.001)
        return None

    monkeypatch.setattr(DULServiceProvider, "receive_pdu", wait_runs_out)
    async with _running_scp({"max_associations": 2}) as scp:
        assert scp._ae.acse_timeout == 30.0
        baseline = await _thread_baseline()
        sock = _stall(scp.sockport, request)
        await _ends_with_no_thread(scp, sock, baseline, peer_closes=peer_closes)


async def test_a_rejection_queued_before_the_kill_still_goes_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A rejection queues its answer and then kills, so a DUL can find the kill set before it has
    # looked at its queue. Held in that window here: ending the connection then would drop the
    # A-ASSOCIATE-RJ, and the peer would see an SCP that hung up.
    from pynetdicom.dul import DULServiceProvider

    real = DULServiceProvider._process_recv_primitive
    held: set[int] = set()

    def looks_late(self: Any) -> bool:
        if self.to_provider_queue.empty() or id(self) in held:
            return real(self)
        held.add(id(self))
        deadline = time.monotonic() + 5.0
        while not self.assoc._kill and time.monotonic() < deadline:
            time.sleep(0.001)
        return False

    request = await asyncio.to_thread(_a_real_association_request)
    monkeypatch.setattr(DULServiceProvider, "_process_recv_primitive", looks_late)
    async with _running_scp({"calling_ae_allowlist": ["SOMEONE_ELSE"]}) as scp:
        sock = _stall(scp.sockport, request)
        try:
            assert await asyncio.to_thread(sock.recv, 1) == b"\x03", "no A-ASSOCIATE-RJ was sent"
        finally:
            sock.close()


async def test_a_rate_wait_does_not_spend_the_peers_deadline() -> None:
    # EVT_CONN_OPEN still fires before the request is read, so the engine's own wait is not the
    # peer being slow. The first two associations spend the bucket, so the third waits past a
    # deadline that a clock started at accept would already have run out.
    captured: list[bytes] = []
    settings: dict[str, object] = {
        "timeout_seconds": 1.0,
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
        assert took > 1.0, f"CONTROL: the wait ({took:.2f}s) did not outlast the deadline"
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


def test_a_pynetdicom_without_the_association_seams_is_refused() -> None:
    # Without them the SCP would start and then fail every connection. So it does not start.
    from pynetdicom.transport import AssociationSocket, RequestHandler

    dicom_module._require_association_seams(RequestHandler, AssociationSocket)  # CONTROL: 3.0.4

    class NoFactory:
        pass

    class SocketReadsElsewhere(NoFactory):
        pass

    for handler, sock in ((NoFactory, AssociationSocket), (RequestHandler, SocketReadsElsewhere)):
        with pytest.raises(RuntimeError, match="does not have the association hooks"):
            dicom_module._require_association_seams(handler, sock)


def test_the_pynetdicom_seams_the_first_request_read_relies_on_are_still_there() -> None:
    """What ``_admitting_server_class`` assumes about pynetdicom, past the server hooks that
    ``test_the_scp_runs_its_own_server_class_over_the_pinned_hooks`` pins. Read against 3.0.4; the
    ``[dicom]`` comment in ``pyproject.toml`` says to re-read these before moving the pin.
    """
    from pynetdicom.acse import ACSE
    from pynetdicom.association import Association
    from pynetdicom.dul import DULServiceProvider
    from pynetdicom.fsm import ACTIONS, AE_6, TRANSITION_TABLE, StateMachine
    from pynetdicom.presentation import negotiate_as_acceptor
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
    assert "self.socket.ready" in inspect.getsource(DULServiceProvider._is_transport_event)
    # A raise from recv is what ends a stalled reader, so the DUL must still catch it as a closed
    # connection, on both reads.
    assert reader.count("except (OSError, TimeoutError)") == 2 and '"Evt17"' in reader
    # A short header read is a silent closed connection, which is why a deadline returns one, and
    # the stock send turns a timeout into the same thing.
    assert "except struct.error" in reader
    assert "except Exception" in inspect.getsource(AssociationSocket.send)
    # _check_association_request repeats these steps, so that the two cannot disagree on a request.
    assert "pdu.decode(b)" in inspect.getsource(DULServiceProvider._decode_pdu)
    indication = inspect.getsource(AE_6)
    assert "to_primitive()" in indication and "protocol_version != 0x0001" in indication
    # _AdmittedSocket.ready reads these FSM names and these transitions: an unanswered request
    # goes through Sta2 and Sta3, Sta13 closes, and the event for a closed connection works in each.
    dul: Any = object()
    assert StateMachine(dul).current_state == "Sta1"
    assert {"Sta2", "Sta3"} == dicom_module._STATES_BEFORE_THE_ANSWER
    assert dicom_module._STATE_CLOSING == "Sta13"
    assert TRANSITION_TABLE[("Evt6", "Sta2")] == "AE-6"
    assert ACTIONS["AE-6"][2] == ("Sta3", "Sta13")
    assert TRANSITION_TABLE[("Evt7", "Sta3")] == "AE-7"
    assert TRANSITION_TABLE[("Evt8", "Sta3")] == "AE-8"
    assert ACTIONS["AE-8"][2] == "Sta13"
    assert {TRANSITION_TABLE[("Evt17", s)] for s in ("Sta2", "Sta3", "Sta6", "Sta13")} == {
        "AA-5",
        "AA-4",
        "AR-5",
    }
    # kill() sets the flag ready reads, then waits for Sta1, which is why ready has to end the DUL.
    kill = inspect.getsource(Association.kill)
    assert "self._kill = True" in kill and "stop_dul()" in kill
    assert "Sta1" in inspect.getsource(DULServiceProvider.stop_dul)
    # close() is how ready ends it: it queues the event for a closed connection, once.
    close = inspect.getsource(AssociationSocket.close)
    assert '"Evt17"' in close and "self.socket = None" in close
    # Negotiation takes each context's first transfer syntax without looking.
    assert "rq_context.transfer_syntax[0]" in inspect.getsource(negotiate_as_acceptor)
    # A started Association is what counts at the check, whatever it has read. That is the reason
    # a stalled peer must not have one.
    negotiate = inspect.getsource(ACSE._negotiate_as_acceptor)
    assert "active_associations" in negotiate and "maximum_associations" in negotiate
    # The pre-check runs the presentation-context negotiation on what the association passes it:
    # the request's contexts, the server's contexts and the request's role selection items.
    assert "UNRESTRICTED_STORAGE_SERVICE" in negotiate and "negotiate_unrestricted(" in negotiate
    assert "negotiate_as_acceptor(" in negotiate
    assert "assoc_rq.presentation_context_definition_list" in negotiate
    assert "self.acceptor.supported_contexts" in negotiate and "role_selection" in negotiate
    assert "supported_contexts = deepcopy(self.server.contexts)" in inspect.getsource(
        RequestHandler._create_association
    )
    # In Sta13 the DUL reads while ready is True and closes once it is False, which is why ready
    # says False there and close reads off what has arrived first.
    transport_event = inspect.getsource(DULServiceProvider._is_transport_event)
    sta13 = transport_event.index('"Sta13"')
    assert transport_event.index("self.socket.close()", sta13) > transport_event.index(
        "self.socket.ready", sta13
    )


def test_the_doc_states_the_bounds_of_the_first_request_read() -> None:
    doc = (Path(__file__).resolve().parents[1] / "docs" / "DICOM.md").read_text(encoding="utf-8")
    assert f"at most {dicom_module._MAX_PENDING_CONNECTIONS} connections" in doc
    assert f"at most {dicom_module._MAX_ASSOCIATE_RQ_BYTES // 1024} KiB" in doc
    assert "A peer has `timeout_seconds` to deliver its whole association request." in doc
    assert "each read has `timeout_seconds`" in doc
