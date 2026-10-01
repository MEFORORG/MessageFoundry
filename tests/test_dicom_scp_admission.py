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
import logging
import socket
import ssl
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path

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


def test_the_c_store_check_still_refuses_a_peer_the_accept_gate_did_not_see() -> None:
    # The accept gate rides on hooks in a third-party server class. The per-C-STORE check stays behind
    # it, so an object from a peer outside the allowlist is never committed even if that gate is not
    # run. _FakeStoreEvent's requestor address is 127.0.0.1.
    captured: list[bytes] = []
    event = _FakeStoreEvent(transfer_syntax="1.2.840.10008.1.2.1", data_set=b"\x00" * 32)
    refused = _build_scp(captured, source_ip_allowlist=_NOT_LOOPBACK)
    assert refused._on_c_store(event) == 0x0124  # Refused: Not Authorized, before any decode
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


def test_a_later_refusal_line_counts_the_ones_that_were_not_logged(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dicom_module, "_REFUSAL_LOG_WINDOW_SECONDS", 0.2)
    scp = _build_scp([], source_ip_allowlist=_NOT_LOOPBACK)  # the window is read at construction
    with caplog.at_level(logging.WARNING, logger=_LOG):
        for _ in range(5):
            scp._admit_connection(("192.0.2.1", 40000))
        assert len(_warnings(caplog)) == 1
        time.sleep(0.3)  # the window has passed, so the next refusal is logged again
        scp._admit_connection(("192.0.2.1", 40000))
    lines = _warnings(caplog)
    assert len(lines) == 2
    assert "4 other refused" in lines[1], lines[1]


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
    import socketserver

    from pynetdicom import AE
    from pynetdicom.transport import AssociationServer, ThreadedAssociationServer
    from pynetdicom.utils import make_target

    cls = dicom_module._admitting_server_class()
    assert issubclass(cls, ThreadedAssociationServer)
    assert issubclass(ThreadedAssociationServer, socketserver.TCPServer)
    assert "get_request" in vars(AssociationServer)
    assert "process_request_thread" in vars(ThreadedAssociationServer)
    assert callable(socketserver.BaseServer.verify_request)
    for name in ("get_request", "verify_request", "process_request_thread", "start_serving"):
        assert name in vars(cls), f"the admitting server no longer defines {name}"
    assert AE()._servers == [], "start_serving records the server on AE._servers"
    assert callable(make_target)
