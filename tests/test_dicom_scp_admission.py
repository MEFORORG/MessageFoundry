# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Admission tests for the DICOM C-STORE SCP (vault BACKLOG #2583): the peer-address allowlist is
applied when a connection is accepted, before anything is read from it, and an inbound TLS
handshake is bounded, capped and off the accept loop.

Every listener here binds ``127.0.0.1`` on an ephemeral port, and every certificate is a throwaway
written under ``tmp_path``.

**These tests need the ``[dicom]`` extra and SKIP without it.** A skipped test is not evidence, so
read the result on a leg that installs the extra: the ``test`` job in ``.github/workflows/ci.yml``
does (``-e ".[dev,harness,fhir,dicom,...]"``), on each of its matrix legs.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import logging
import socket
import socketserver
import ssl
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydicom", reason="DICOM SCP tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCP tests need the [dicom] extra")

from messagefoundry import netaddr  # noqa: E402
from messagefoundry.transports import dicom as dicom_module  # noqa: E402
from messagefoundry.transports.dicom import DicomScpSource  # noqa: E402
from messagefoundry.transports.mllp import _TLS_HANDSHAKE_TIMEOUT  # noqa: E402
from tests._dicom_sample import make_sr_part10  # noqa: E402
from tests.test_dicom_scp import (  # noqa: E402
    _SCP_AE,
    _build_scp,
    _FakeStoreEvent,
    _scu_cstore,
    _server_cert,
)

_LOG = "messagefoundry.transports.dicom"
#: An allowlist that does not contain the loopback address every test client connects from.
_NOT_LOOPBACK = ["10.0.0.0/8"]
_LOOPBACK = ["127.0.0.1"]


@contextlib.asynccontextmanager
async def _running_scp(
    settings: dict[str, object], *, captured: list[bytes] | None = None
) -> AsyncIterator[DicomScpSource]:
    """A started SCP whose handler commits into ``captured``. Stopped on the way out."""
    sink: list[bytes] = [] if captured is None else captured

    async def handler(data: bytes) -> str | None:
        sink.append(data)
        return f"mid-{len(sink)}"

    scp = _build_scp(sink, **settings)
    await scp.start(handler)
    try:
        yield scp
    finally:
        await scp.stop()


def _closed_after(port: int, *, wait: float) -> float | None:
    """Connect, send NOTHING, and return the seconds until the listener closed the connection.

    ``None`` means the socket was still open when ``wait`` ran out: the listener was waiting to
    read from this peer. Sending nothing is the point. A listener that closes a peer which has sent
    no byte cannot have read an association request, or a TLS ClientHello, from it.
    """
    sock = socket.create_connection(("127.0.0.1", port), timeout=wait)
    started = time.monotonic()
    try:
        try:
            if sock.recv(1) != b"":
                raise AssertionError("the listener sent bytes to a peer that sent none")
        except TimeoutError:
            return None
        except OSError:
            pass  # a reset is a close too
        return time.monotonic() - started
    finally:
        sock.close()


def _unverified_client_context() -> ssl.SSLContext:
    """A TLS client context for the throwaway server certificate. Loopback tests only."""
    ctx = ssl.create_default_context()
    # The floor is stated, not inherited from the interpreter's default, as the engine's other TLS
    # tests state it: see _verifying_client_ctx in tests/test_api_tls.py.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _tls_handshake(port: int, *, budget: float) -> tuple[bool, float]:
    """Run a client TLS handshake against the listener. Returns ``(completed, seconds)``."""
    started = time.monotonic()
    raw = socket.create_connection(("127.0.0.1", port), timeout=budget)
    try:
        tls = _unverified_client_context().wrap_socket(raw, do_handshake_on_connect=False)
        tls.settimeout(budget)
        try:
            tls.do_handshake()
            return True, time.monotonic() - started
        except OSError:  # a timeout and an ssl.SSLError are both OSError
            return False, time.monotonic() - started
        finally:
            tls.close()
    finally:
        raw.close()


def _scu_cstore_tls(port: int, data: bytes, *, ca_file: str) -> tuple[bool, int | None]:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # stated floor; see _unverified_client_context
    return _scu_cstore(port, data, tls_args=(ctx, "127.0.0.1"))


def _tls_settings(tmp_path: Path) -> dict[str, object]:
    cert, key = _server_cert(tmp_path)
    return {"tls": True, "tls_cert_file": cert, "tls_key_file": key}


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


async def _until(condition: Callable[[], bool], *, within: float = 5.0) -> None:
    """Wait for ``condition``, so a test does not sleep a fixed time for another thread."""
    deadline = time.monotonic() + within
    while not condition():
        assert time.monotonic() < deadline, "the awaited state was never reached"
        await asyncio.sleep(0.01)


def _handshakes_in_flight(scp: DicomScpSource) -> int:
    return sum(scp._server._pending.values())


# --- The peer-address allowlist applies at accept ------------------------------------------------


@pytest.mark.parametrize("tls", [False, True], ids=["cleartext", "tls"])
async def test_a_peer_outside_the_allowlist_is_closed_before_anything_is_read(
    tls: bool, tmp_path: Path
) -> None:
    captured: list[bytes] = []
    extra = _tls_settings(tmp_path) if tls else {}

    refusing = {"source_ip_allowlist": _NOT_LOOPBACK, **extra}
    async with _running_scp(refusing, captured=captured) as scp:
        took = await asyncio.to_thread(_closed_after, scp.sockport, wait=3.0)
        assert took is not None, "a peer outside source_ip_allowlist must be closed, unread"
        assert scp._server.active_associations == [], "no association may exist for it"

    # CONTROL: the same silent connection from an ALLOWED address is left open, because the listener
    # is waiting to read from it. Without this, a listener that closed every peer would pass above.
    admitting = {"source_ip_allowlist": _LOOPBACK, **extra}
    async with _running_scp(admitting, captured=captured) as scp:
        took = await asyncio.to_thread(_closed_after, scp.sockport, wait=0.5)
        assert took is None, "an allowed peer must be left open for its association request"
    assert captured == []


async def test_a_peer_outside_the_allowlist_gets_no_association() -> None:
    captured: list[bytes] = []
    async with _running_scp({"source_ip_allowlist": _NOT_LOOPBACK}, captured=captured) as scp:
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert established is False, "the connection is closed before any association forms"
        assert status is None
        assert captured == []

    # CONTROL: an allowed peer associates and its object is committed.
    async with _running_scp({"source_ip_allowlist": _LOOPBACK}, captured=captured) as scp:
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert (established, status) == (True, 0x0000)
        assert len(captured) == 1


def test_the_c_store_check_still_refuses_a_peer_the_accept_gate_did_not_see(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The accept gate rides on hooks in a third-party server class. The per-C-STORE check stays behind
    # it, so an object from a peer outside the allowlist is never committed even if that gate is not
    # run. _FakeStoreEvent's requestor address is 127.0.0.1.
    captured: list[bytes] = []
    event = _FakeStoreEvent(transfer_syntax="1.2.840.10008.1.2.1", data_set=b"\x00" * 32)
    refused = _build_scp(captured, source_ip_allowlist=_NOT_LOOPBACK)
    with caplog.at_level(logging.WARNING, logger=_LOG):
        for _ in range(3):
            assert refused._on_c_store(event) == 0x0124  # Not Authorized, before any decode
    # Each of these is an object the SCP received and refused, so each one is logged, with the
    # calling AE. The per-address throttle is for refused connections, which carry no object.
    lines = [m for m in _warnings(caplog) if "C-STORE from 127.0.0.1 (AE 'MODALITY1')" in m]
    assert len(lines) == 3, _warnings(caplog)
    # CONTROL: the same event from an allowed address goes on to the decode trap (0xC000).
    allowed = _build_scp(captured, source_ip_allowlist=_LOOPBACK)
    assert allowed._on_c_store(event) == 0xC000
    assert captured == []


async def test_a_fault_in_the_accept_gate_refuses_the_peer_and_keeps_the_listener_up(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The gate runs on the accept loop, and an exception there would end the loop for every sender.
    def broken(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("matcher fault")

    captured: list[bytes] = []
    async with _running_scp({"source_ip_allowlist": _LOOPBACK}, captured=captured) as scp:
        monkeypatch.setattr(dicom_module, "peer_ip_allowed", broken)
        with caplog.at_level(logging.WARNING, logger=_LOG):
            took = await asyncio.to_thread(_closed_after, scp.sockport, wait=3.0)
        assert took is not None, "a gate that cannot decide must refuse"
        assert any("check failed" in m for m in _warnings(caplog)), "and the refusal must say why"
        monkeypatch.setattr(dicom_module, "peer_ip_allowed", netaddr.peer_ip_allowed)
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert (established, status) == (True, 0x0000), "the listener must still be accepting"


async def test_a_fault_in_the_refusal_path_is_logged_once_and_still_refuses(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The last line of defence on the accept loop. It must refuse, and say so once per window, not
    # once per connection, because in this state every connection is refused.
    def broken(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("refusal path fault")

    async with _running_scp({"source_ip_allowlist": _NOT_LOOPBACK}) as scp:
        monkeypatch.setattr(scp, "_log_refused_peer", broken)
        with caplog.at_level(logging.DEBUG, logger=_LOG):
            for _ in range(3):
                assert await asyncio.to_thread(_closed_after, scp.sockport, wait=3.0) is not None

            def faults() -> list[str]:
                return [m for m in _warnings(caplog) if "admission check itself failed" in m]

            assert len(faults()) == 1, faults()
            # A later window logs it again, so a fault that returns is not silent for good. The
            # line is due again no later than one window from now; move that time here, not the clock.
            window = dicom_module._REFUSAL_LOG_WINDOW_SECONDS
            assert scp._server._gate_fault_log_after <= time.monotonic() + window
            scp._server._gate_fault_log_after = 0.0
            assert await asyncio.to_thread(_closed_after, scp.sockport, wait=3.0) is not None
            assert len(faults()) == 2, faults()


# --- Refusals are logged per peer, not per connection --------------------------------------------


async def test_repeated_refusals_from_one_peer_log_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with _running_scp({"source_ip_allowlist": _NOT_LOOPBACK}) as scp:
        with caplog.at_level(logging.DEBUG, logger=_LOG):
            for _ in range(6):
                # CONTROL, inside the loop: every one of the six really was refused.
                assert await asyncio.to_thread(_closed_after, scp.sockport, wait=3.0) is not None
        lines = [m for m in _warnings(caplog) if "source_ip_allowlist" in m]
        assert len(lines) == 1, lines
        assert "127.0.0.1" in lines[0]


def test_the_refusal_log_is_per_peer_and_capped_across_peers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    scp = _build_scp([], source_ip_allowlist=_NOT_LOOPBACK)
    ceiling = dicom_module._REFUSAL_LOG_MAX_PER_WINDOW
    with caplog.at_level(logging.WARNING, logger=_LOG):
        for _ in range(3):  # three refusals each, from two addresses
            assert scp._admit_connection(("192.0.2.1", 40000)) is False
            assert scp._admit_connection(("192.0.2.2", 40000)) is False
        assert len(_warnings(caplog)) == 2, "one line for each address, not one for each refusal"
        # Many distinct addresses cannot each earn a line: the window has an overall ceiling.
        for n in range(ceiling * 3):
            assert scp._admit_connection((f"198.51.100.{n % 250}", 40000 + n)) is False
    assert len(_warnings(caplog)) == ceiling
    # CONTROL: an allowed address is admitted and logs nothing.
    allowed = _build_scp([], source_ip_allowlist=["192.0.2.0/24"])
    before = len(caplog.records)
    assert allowed._admit_connection(("192.0.2.1", 40000)) is True
    assert len(caplog.records) == before


def test_a_later_refusal_line_carries_the_running_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    scp = _build_scp([], source_ip_allowlist=_NOT_LOOPBACK)
    with caplog.at_level(logging.WARNING, logger=_LOG):
        for _ in range(5):
            scp._admit_connection(("192.0.2.1", 40000))
        assert len(_warnings(caplog)) == 1
        # Age this address's line past the window, in place of sleeping through one.
        scp._refusal_logged["192.0.2.1"] -= dicom_module._REFUSAL_LOG_WINDOW_SECONDS + 1
        scp._admit_connection(("192.0.2.1", 40000))
    lines = _warnings(caplog)
    assert len(lines) == 2
    assert "1 refused in all" in lines[0], lines[0]
    assert "6 refused in all" in lines[1], lines[1]


def test_the_refusal_table_stays_bounded_whatever_arrives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An entry exists only for a line written inside the current window, so a stream of addresses
    # that are each seen once cannot grow the table past the per-window ceiling.
    monkeypatch.setattr(dicom_module, "_REFUSAL_LOG_WINDOW_SECONDS", 0.05)
    scp = _build_scp([], source_ip_allowlist=_NOT_LOOPBACK)
    ceiling = dicom_module._REFUSAL_LOG_MAX_PER_WINDOW
    seen = 0
    for window in range(4):
        for n in range(ceiling * 2):
            scp._admit_connection((f"198.51.{window}.{n}", 40000))
            seen += 1
            assert len(scp._refusal_logged) <= ceiling
        time.sleep(0.08)
    assert scp._refusals == seen, "every refusal is counted, logged or not"
    # CONTROL: the table was really in use, and aged entries really left it.
    scp._admit_connection(("203.0.113.9", 40000))
    assert list(scp._refusal_logged) == ["203.0.113.9"]


# --- The TLS handshake is bounded, capped and off the accept loop --------------------------------


async def test_stock_pynetdicom_runs_the_handshake_on_its_accept_loop(tmp_path: Path) -> None:
    """CONTROL for the test below, and the pin on why the SCP supplies its own server class.

    With pynetdicom's own server, one connected peer that sends nothing holds the accept loop inside
    its handshake, so a second peer's handshake does not finish. Measured at pynetdicom 3.0.4. If
    this test FAILS after a pynetdicom upgrade, upstream has moved the handshake off the accept
    loop: re-read ``_admitting_server_class`` in ``transports/dicom.py`` against the new source
    before deleting anything.
    """
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]

    ctx = dicom_module._server_ssl_context(_tls_settings(tmp_path))
    ae = AE(ae_title=_SCP_AE)
    ae.add_supported_context(Verification)
    server = ae.start_server(("127.0.0.1", 0), block=False, ssl_context=ctx)
    assert server is not None and server.socket is not None
    silent: socket.socket | None = None
    try:
        port = server.socket.getsockname()[1]
        silent = socket.create_connection(("127.0.0.1", port), timeout=3)
        await asyncio.sleep(0.3)  # let the accept loop take the silent peer
        completed, _ = await asyncio.to_thread(_tls_handshake, port, budget=1.0)
        assert not completed, "stock pynetdicom no longer stalls: see this test's docstring"
    finally:
        if silent is not None:
            silent.close()  # frees the accept loop, which shutdown() waits for
        await asyncio.to_thread(server.shutdown)


async def test_a_silent_peer_does_not_delay_another_peers_handshake(tmp_path: Path) -> None:
    # The control is test_stock_pynetdicom_runs_the_handshake_on_its_accept_loop: the same two
    # connections against pynetdicom's own server do NOT complete. The budget here is generous, so
    # a slow runner cannot fail it; what it asserts is completion, which the control never reaches.
    silent: list[socket.socket] = []
    async with _running_scp(_tls_settings(tmp_path)) as scp:
        try:
            port = scp.sockport
            for _ in range(3):
                silent.append(socket.create_connection(("127.0.0.1", port), timeout=3))
            await _until(lambda: _handshakes_in_flight(scp) == 3)
            completed, took = await asyncio.to_thread(_tls_handshake, port, budget=8.0)
            assert completed, f"a second peer's handshake did not complete ({took:.1f}s)"
            assert took < _TLS_HANDSHAKE_TIMEOUT, "it waited out a silent peer's bound"
        finally:
            for sock in silent:
                sock.close()


async def test_a_handshake_that_does_not_finish_is_dropped_at_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(dicom_module, "_TLS_HANDSHAKE_TIMEOUT", 0.5)
    async with _running_scp(_tls_settings(tmp_path)) as scp:
        with caplog.at_level(logging.DEBUG, logger=_LOG):
            took = await asyncio.to_thread(_closed_after, scp.sockport, wait=5.0)
        assert took is not None, "a peer that never starts its handshake must be dropped"
        # CONTROL on the cause: it was dropped AT the bound, not refused on arrival.
        assert took >= 0.4, f"closed after {took:.2f}s, before the 0.5s bound"
        assert scp._server.active_associations == []
        # A flood of silent sockets must not fill the log: the drop is a DEBUG line, never a WARNING.
        assert _warnings(caplog) == []
        assert any("handshake" in r.getMessage() for r in caplog.records)


def _send_a_handshake_slowly(port: int, *, gap: float, give_up: float) -> float | None:
    """Open a TLS record and feed it one byte every ``gap`` seconds, so the listener's handshake
    always has a read pending and is never idle for longer than ``gap``. Returns the seconds until
    the listener closed the connection, or ``None`` if it was still open at ``give_up``."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=gap)
    started = time.monotonic()
    try:
        # A TLS handshake record header announcing 512 bytes; far fewer are ever sent.
        pending = b"\x16\x03\x01\x02\x00" + b"\x00" * 400
        for offset in range(len(pending)):
            if time.monotonic() - started > give_up:
                return None
            try:
                sock.sendall(pending[offset : offset + 1])
                if sock.recv(1) == b"":
                    return time.monotonic() - started
            except TimeoutError:
                continue  # nothing back yet, and still open: this wait is the gap
            except OSError:
                return time.monotonic() - started
        return None
    finally:
        sock.close()


async def test_the_handshake_bound_is_a_deadline_for_the_whole_handshake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An idle timer would restart on every byte and never fire for this peer, whose gaps (0.1 s) are
    # far shorter than the bound. A deadline drops it at the bound however steadily it sends.
    monkeypatch.setattr(dicom_module, "_TLS_HANDSHAKE_TIMEOUT", 1.0)
    async with _running_scp(_tls_settings(tmp_path)) as scp:
        took = await asyncio.to_thread(_send_a_handshake_slowly, scp.sockport, gap=0.1, give_up=6.0)
        assert took is not None, "a slowly sent handshake was still open long after the bound"
        assert 0.8 <= took < 4.0, f"dropped after {took:.2f}s against a 1.0s bound"


async def test_a_handshake_that_starts_late_but_inside_the_bound_completes(
    tmp_path: Path,
) -> None:
    # The handshake is read in slices of _HANDSHAKE_POLL_SECONDS. A slice is a poll interval, not a
    # bound: a peer that starts after several empty slices must still be served.
    async with _running_scp(_tls_settings(tmp_path)) as scp:

        def late_handshake() -> bool:
            raw = socket.create_connection(("127.0.0.1", scp.sockport), timeout=5)
            try:
                time.sleep(dicom_module._HANDSHAKE_POLL_SECONDS * 3)
                with _unverified_client_context().wrap_socket(raw) as tls:
                    return tls.version() is not None
            finally:
                raw.close()

        assert await asyncio.to_thread(late_handshake)


@pytest.mark.parametrize(
    "cap", ["_MAX_PENDING_HANDSHAKES_PER_HOST", "_MAX_PENDING_HANDSHAKES"], ids=["host", "listener"]
)
async def test_handshakes_in_flight_are_capped_and_the_slots_come_back(
    cap: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    held: list[socket.socket] = []
    async with _running_scp(_tls_settings(tmp_path)) as scp:  # the shipped 10 s handshake bound
        try:
            port = scp.sockport
            # CONTROL, at the shipped caps: a connection that sends nothing stays open in its handshake.
            assert await asyncio.to_thread(_closed_after, port, wait=0.5) is None
            await _until(lambda: _handshakes_in_flight(scp) == 0)

            monkeypatch.setattr(dicom_module, cap, 2)
            for _ in range(2):
                held.append(socket.create_connection(("127.0.0.1", port), timeout=3))
            await _until(lambda: _handshakes_in_flight(scp) == 2)  # both slots are held
            with caplog.at_level(logging.WARNING, logger=_LOG):
                took = await asyncio.to_thread(_closed_after, port, wait=5.0)
            assert took is not None, "a handshake over the cap must be closed"
            assert took < _TLS_HANDSHAKE_TIMEOUT / 2, f"closed after {took:.1f}s: that is the bound"
            assert any("already in progress" in m for m in _warnings(caplog))

            # The slots come back when their handshakes end, so the cap is not a one-way door.
            for sock in held:
                sock.close()
            held.clear()
            await _until(lambda: _handshakes_in_flight(scp) == 0)
            completed, _ = await asyncio.to_thread(_tls_handshake, port, budget=5.0)
            assert completed, "a handshake after the slots were freed must be served"
            # The client can finish its side first, so wait for the listener to give its slot back.
            await _until(lambda: scp._server._pending == {})
        finally:
            for sock in held:
                sock.close()


async def test_a_slot_is_given_back_when_no_thread_could_be_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The slot is taken on the accept loop, before the connection's thread exists. If that thread
    # cannot be started, nothing else would ever give the slot back.
    start_thread = socketserver.ThreadingMixIn.process_request

    async with _running_scp(_tls_settings(tmp_path)) as scp:

        def cannot_start(self: Any, request: Any, client_address: Any) -> None:
            if self is not scp._server:  # any other server in this process is left alone
                return start_thread(self, request, client_address)
            raise RuntimeError("no thread for this connection")

        with monkeypatch.context() as patched:
            patched.setattr(socketserver.ThreadingMixIn, "process_request", cannot_start)
            took = await asyncio.to_thread(_closed_after, scp.sockport, wait=3.0)
            assert took is not None, "socketserver closes a connection whose dispatch raised"
        assert scp._server._pending == {}, "the slot must not stay held"
        # CONTROL: with the dispatch restored, the same listener serves a handshake.
        completed, _ = await asyncio.to_thread(_tls_handshake, scp.sockport, budget=5.0)
        assert completed


async def test_a_connection_that_times_out_ends_its_handshake_at_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A poll slice that finds nothing to read raises a TimeoutError with no errno, and the handshake
    # goes on. The transport itself timing out raises one WITH an errno. That one must end the
    # handshake, not be retried until the bound.
    handshake = ssl.SSLSocket.do_handshake

    async with _running_scp(_tls_settings(tmp_path)) as scp:  # the shipped 10 s handshake bound
        port = scp.sockport

        def transport_timed_out(self: ssl.SSLSocket, block: bool = False) -> None:
            if not (self.server_side and self.getsockname()[1] == port):
                return handshake(self, block)  # any other TLS socket in this process
            raise TimeoutError(errno.ETIMEDOUT, "connection timed out")

        monkeypatch.setattr(ssl.SSLSocket, "do_handshake", transport_timed_out)
        took = await asyncio.to_thread(_closed_after, scp.sockport, wait=4.0)
        assert took is not None, "the handshake was retried instead of ended"
        assert took < _TLS_HANDSHAKE_TIMEOUT / 2


async def test_stop_does_not_wait_out_a_pending_handshake(tmp_path: Path) -> None:
    async with _running_scp(_tls_settings(tmp_path)) as scp:  # the shipped 10 s handshake bound
        silent = socket.create_connection(("127.0.0.1", scp.sockport), timeout=3)
        try:
            await _until(lambda: _handshakes_in_flight(scp) == 1)
            started = time.monotonic()
            await scp.stop()
            took = time.monotonic() - started
            assert took < _TLS_HANDSHAKE_TIMEOUT / 2, f"stop() took {took:.1f}s"
        finally:
            silent.close()


async def test_a_tls_association_still_stores_an_object(tmp_path: Path) -> None:
    # The handshake moved to the connection's own thread. This is the end-to-end proof that an
    # association over the socket it hands on still works, with the timeout restored afterwards.
    captured: list[bytes] = []
    timeouts: list[float | None] = []
    settings = _tls_settings(tmp_path)
    scp = _build_scp(captured, **settings)

    async def handler(data: bytes) -> str | None:
        # Runs while the association is live: read the timeout on the socket it was handed.
        for assoc in scp._server.active_associations:
            timeouts.append(assoc.dul.socket.socket.gettimeout())
        captured.append(data)
        return "mid-1"

    await scp.start(handler)
    try:
        established, status = await asyncio.to_thread(
            _scu_cstore_tls, scp.sockport, make_sr_part10(), ca_file=str(settings["tls_cert_file"])
        )
        assert (established, status) == (True, 0x0000)
        assert len(captured) == 1
        # pynetdicom reads an accepted socket in blocking mode. The handshake's own timeout must
        # not be left on the socket it hands on.
        assert timeouts == [None]
    finally:
        await scp.stop()


async def test_an_mtls_listener_still_refuses_a_peer_with_no_client_certificate(
    tmp_path: Path,
) -> None:
    captured: list[bytes] = []
    settings = _tls_settings(tmp_path)
    ca = str(settings["tls_cert_file"])
    async with _running_scp({**settings, "tls_ca_file": ca}, captured=captured) as scp:
        established, _ = await asyncio.to_thread(
            _scu_cstore_tls, scp.sockport, make_sr_part10(), ca_file=ca
        )
        assert established is False, "mTLS must still require a client certificate"
        assert captured == []


# --- The pins ------------------------------------------------------------------------------------


def test_the_doc_states_the_bounds_the_code_ships() -> None:
    # docs/DICOM.md section 3 quotes these numbers. Each is read from its constant here, so the
    # page cannot keep an old one after the constant moves.
    doc = (Path(__file__).resolve().parents[1] / "docs" / "DICOM.md").read_text(encoding="utf-8")
    window = dicom_module._REFUSAL_LOG_WINDOW_SECONDS
    ceiling = dicom_module._REFUSAL_LOG_MAX_PER_WINDOW
    assert f"within {_TLS_HANDSHAKE_TIMEOUT:g} seconds" in doc
    assert f"The {_TLS_HANDSHAKE_TIMEOUT:g} second handshake bound" in doc
    assert f"per refused address per {window:g} seconds" in doc
    assert f"at most {ceiling} such lines per {window:g} seconds" in doc
    listener_cap = dicom_module._MAX_PENDING_HANDSHAKES
    host_cap = dicom_module._MAX_PENDING_HANDSHAKES_PER_HOST
    assert (
        f"at most {listener_cap} TLS handshakes at once, and at most {host_cap} from one peer"
        in doc
    )


def test_the_scp_runs_its_own_server_class_over_the_pinned_hooks() -> None:
    """What the admitting server relies on in pynetdicom and ``socketserver`` must still be there.

    A pynetdicom that stopped routing an accepted connection through these hooks would leave the
    overrides defined and never called, and the address check and the handshake bound would
    silently lapse. ``start_serving`` also uses two names ``AE.start_server`` uses itself.
    """
    from pynetdicom import AE
    from pynetdicom.transport import AssociationServer, ThreadedAssociationServer
    from pynetdicom.utils import make_target

    cls = dicom_module._admitting_server_class()
    assert issubclass(cls, ThreadedAssociationServer)
    assert issubclass(ThreadedAssociationServer, socketserver.TCPServer)
    assert "get_request" in vars(AssociationServer)
    assert "process_request_thread" in vars(ThreadedAssociationServer)
    for name in (
        "get_request",
        "verify_request",
        "process_request",
        "process_request_thread",
        "start_serving",
    ):
        assert name in vars(cls), f"the admitting server no longer defines {name}"
    assert AE()._servers == [], "start_serving records the server on AE._servers"
    assert make_target(print) is print, "start_serving wraps its target as AE.start_server does"


def test_a_pynetdicom_that_left_the_socketserver_routing_is_refused() -> None:
    # The overrides are only called because socketserver's own loop calls them. A server class
    # that drove its own accept loop would leave them defined and unused, so the SCP refuses to
    # start on one.
    from pynetdicom.transport import ThreadedAssociationServer

    dicom_module._require_socketserver_routing(ThreadedAssociationServer)  # CONTROL: 3.0.4 passes

    class OwnLoop(ThreadedAssociationServer):
        def serve_forever(self, poll_interval: float = 0.5) -> None:
            raise NotImplementedError

    class OwnDispatch(ThreadedAssociationServer):
        def process_request(self, request: object, client_address: object) -> None:
            raise NotImplementedError

    class OwnPerConnectionStep(ThreadedAssociationServer):
        def _handle_request_noblock(self) -> None:
            raise NotImplementedError

    class NotThreaded(socketserver.TCPServer):
        pass

    for left in (OwnLoop, OwnDispatch, OwnPerConnectionStep, NotThreaded):
        with pytest.raises(RuntimeError, match="does not route an accepted connection"):
            dicom_module._require_socketserver_routing(left)


def test_the_dicom_extra_admits_only_the_pynetdicom_line_the_server_was_read_against() -> None:
    """The ``[dicom]`` extra must not admit a pynetdicom the admitting server was not read against.

    ``_admitting_server_class`` was read against pynetdicom 3.0.4. The routing guard above refuses a
    release that left the hooks, but only when the listener starts. The cap in ``pyproject.toml``
    stops one at install time (vault BACKLOG #2713). RED when someone widens that cap. Before you
    change the versions below, re-read ``_admitting_server_class`` against the new release; the
    comment above the extra in ``pyproject.toml`` has the steps.
    """
    import tomllib
    from importlib.metadata import version

    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    extra = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"][
        "optional-dependencies"
    ]["dicom"]
    specs = [
        req.specifier
        for req in map(Requirement, extra)
        if canonicalize_name(req.name) == "pynetdicom"
    ]
    assert len(specs) == 1, f"expected one pynetdicom requirement in [dicom], found {extra}"
    (spec,) = specs

    # CONTROL: the release the server was read against, and the one these tests ran on, are admitted.
    assert spec.contains("3.0.4", prereleases=True)
    assert spec.contains(version("pynetdicom"), prereleases=True), (
        f"these tests ran on pynetdicom {version('pynetdicom')}, which [dicom] ({spec}) refuses"
    )
    # 3.1.0.dev0 is a real development release on PyPI, so pre-releases are checked too.
    for unread in ("3.1.0.dev0", "3.1.0", "4.0.0"):
        assert not spec.contains(unread, prereleases=True), (
            f"[dicom] ({spec}) admits pynetdicom {unread}, which the admitting server was never "
            "read against"
        )
