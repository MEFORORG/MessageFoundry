# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The HTTP intake listener bounds a TLS handshake, and admits a socket before it (BACKLOG #2479).

The shape BACKLOG #1606 fixed on the MLLP listener. Before #2479 the ``Http()`` listener let the
event loop run every handshake with asyncio's 60 s default and applied ``source_ip_allowlist``,
``max_connections`` and ``max_connections_per_host`` only after it. So on a first deployment a
peer opening sockets that never sent a ClientHello would have held each one for a minute outside
both caps, and a peer the allowlist excludes would have been given a handshake first.

Engine PR 2655 fixed that on the stdlib loop only. On every other loop, uvloop among them, the loop
still ran the handshake, with the caps and the allowlist after it. Since then the listener runs the
MLLP listener's own accept loop there (`_AcceptingServer`), so each test runs on both paths
(`tls_path`): ``start_tls`` is the stdlib loop, and ``accept_loop`` forces the path every other
loop takes, so it runs on every platform. The uvloop tests at the end run it on the real loop.

Each test waits on an event under a generous deadline, and no real client has to beat a shortened
bound, so a slow runner makes these slower, not red. The handshake bound is pinned far above every
wait in the count tests, so only the cap or the allowlist can close the socket in time.
"""

from __future__ import annotations

import asyncio
import ssl
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from messagefoundry.transports import http_listener as http_module
from messagefoundry.transports import mllp as mllp_module
from messagefoundry.transports.http_listener import HttpSource
from messagefoundry.transports.receipt import IngressReceipt, receipt_handler
from tests.test_mllp_tls import _close_raw, _closed_by_listener, _Events, _until
from tests.test_tls_handshake_failures import _client_hello, _pinned_client, _plaintext_peer
from tests.test_tls_handshake_failures import _http_tls_source as _tls_source


class _Intake:
    """An inbound handler that records each body and returns a message id."""

    def __init__(self) -> None:
        self.received: list[bytes] = []

    async def __call__(self, raw: bytes) -> IngressReceipt:
        self.received.append(raw)
        return IngressReceipt.accepted(f"m{len(self.received)}")


@pytest.fixture(params=["start_tls", "accept_loop"])
def tls_path(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Both ways the listener admits a socket before its handshake: upgrading it with
    ``start_tls`` on the stdlib loop, and `_AcceptingServer`, which every other loop gets, forced
    here. Before the accept loop, the forced path was the loop's own handshake."""
    if request.param == "accept_loop":
        monkeypatch.setattr(http_module, "_upgrades_tls_itself", lambda _loop: False)
    return str(request.param)


def _on_path(source: HttpSource, tls_path: str) -> None:
    """Fail unless ``source`` started on ``tls_path``; ``uvloop`` is the accept loop, unforced."""
    upgrades = tls_path == "start_tls"
    assert source._upgrade_tls is upgrades
    assert isinstance(source._server, mllp_module._AcceptingServer) is not upgrades


async def _https_post(port: int, cert: str, *, client_key: Path | None = None) -> int | None:
    """POST one body over a verified TLS connection and return the response status, or ``None``
    when the listener closed the connection without answering. ``client_key`` presents ``cert``
    as the client certificate too, for mutual TLS."""
    ctx = _pinned_client(cert)
    if client_key is not None:
        ctx.load_cert_chain(cert, client_key)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname="127.0.0.1"),
        timeout=5.0,
    )
    try:
        writer.write(b"POST /ingest HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\nhi")
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(-1), timeout=5.0)
        except (ConnectionError, ssl.SSLError):
            data = b""  # a close with the request unread may arrive as a reset
    finally:
        await _close_raw(writer)
    return int(data.split(b" ", 2)[1]) if data else None


async def test_a_socket_that_never_handshakes_is_closed_at_the_handshake_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tls_path: str
) -> None:
    """Both paths carry the bound. Before #2479 neither had one, so the read below hit its 5 s
    deadline. The socket was admitted first, so the bound must free both counters, or a handful of
    silent sockets would lock a peer out. It counts as one failed handshake, named with its peer:
    the listener runs or hands over the handshake itself on both paths, so it sees the bound fire.
    Before the accept loop, the forced path counted nothing here. It is never a session."""
    monkeypatch.setattr(http_module, "_TLS_HANDSHAKE_TIMEOUT", 0.3)
    source, cert = _tls_source(tmp_path, max_connections_per_host=4)
    events = _Events()
    source.on_connection_event = events
    intake = _Intake()
    await source.start(receipt_handler(intake))
    try:
        _on_path(source, tls_path)
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            await _closed_by_listener(reader, within=5.0)
        finally:
            await _close_raw(writer)
        await _until(lambda: source._admission.active == 0, "the slot was not released")
        assert source._admission.per_host == {}
        assert source._admission.handshaking == {}
        await _until(lambda: source.tls_handshake_failures == 1, "the failure not counted")
        (_kind, peer, reason) = events.seen[0]
        assert peer == "127.0.0.1"
        assert reason is not None and reason.startswith("1 failed handshake(s)")
        assert events.kinds() == ["tls_handshake_failed"]
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)
    # The same listener, restarted with the real bound, still serves a real TLS client. Restarted
    # rather than reused so that client never races the 0.3 s bound set above.
    monkeypatch.setattr(http_module, "_TLS_HANDSHAKE_TIMEOUT", 10.0)
    await source.start(receipt_handler(intake))
    try:
        _on_path(source, tls_path)
        assert await _https_post(source.sockport, cert) == 202
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)
    assert intake.received == [b"hi"]


@pytest.mark.parametrize(
    ("caps", "reason"),
    [
        ({"max_connections": 1}, None),
        ({"max_connections": 0, "max_connections_per_host": 1}, "max_connections_per_host"),
    ],
    ids=["max_connections", "max_connections_per_host"],
)
async def test_an_unhandshaken_socket_spends_a_connection_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caps: dict[str, int],
    reason: str | None,
    tls_path: str,
) -> None:
    monkeypatch.setattr(http_module, "_TLS_HANDSHAKE_TIMEOUT", 60.0)
    source, _cert_path = _tls_source(tmp_path, **caps)
    events = _Events()
    source.on_connection_event = events
    await source.start(receipt_handler(_Intake()))
    try:
        _on_path(source, tls_path)
        _r1, w1 = await asyncio.open_connection("127.0.0.1", source.sockport)
        w2: asyncio.StreamWriter | None = None
        try:
            # Before the fix a socket that sent no ClientHello was outside the count entirely.
            await _until(
                lambda: source._admission.active == 1,
                "a socket still in its TLS handshake was not counted against the caps",
            )
            r2, w2 = await asyncio.open_connection("127.0.0.1", source.sockport)
            # Closed with no bytes: a plaintext 503 is no answer a TLS client can read.
            await _closed_by_listener(r2, within=5.0)
            await _until(lambda: "at_capacity" in events.kinds(), "no at_capacity event")
            assert events.seen == [("at_capacity", "127.0.0.1", reason)]
        finally:
            await _close_raw(w1)
            if w2 is not None:
                await _close_raw(w2)
        # The slot comes back when the unhandshaken socket goes. It never became a session, so no
        # `established` or `closed` was emitted for it.
        await _until(lambda: source._admission.active == 0, "the slot was not released")
        assert source._admission.per_host == {}
        assert events.kinds() == ["at_capacity"]
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_a_peer_outside_the_allowlist_is_refused_before_any_tls_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tls_path: str
) -> None:
    monkeypatch.setattr(http_module, "_TLS_HANDSHAKE_TIMEOUT", 60.0)
    source, _cert_path = _tls_source(tmp_path, source_ip_allowlist=["10.0.0.1"])
    events = _Events()
    source.on_connection_event = events
    await source.start(receipt_handler(_Intake()))
    try:
        _on_path(source, tls_path)
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            # Before the fix the loop answered this with a ServerHello, and the allowlist ran only
            # once a handshake had completed.
            writer.write(_client_hello())
            await writer.drain()
            await _closed_by_listener(reader, within=5.0)
        finally:
            await _close_raw(writer)
        await _until(
            lambda: "peer_not_allowlisted" in events.kinds(), "no peer_not_allowlisted event"
        )
        assert events.kinds() == ["peer_not_allowlisted"]
        assert source._admission.active == 0
        assert source.tls_handshake_failures == 0  # no handshake was attempted to fail
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_stop_closes_a_socket_still_in_its_handshake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tls_path: str
) -> None:
    """The listener tracks a socket from its accept, so stop() closes one still in its handshake
    at once: on ``start_tls`` its writer is in ``_clients``, and under the accept loop its task is in
    ``_handshakes``, which stop() cancels. The bound is pinned far above the shutdown grace, so only
    stop() can close it."""
    monkeypatch.setattr(http_module, "_TLS_HANDSHAKE_TIMEOUT", 60.0)
    source, _cert_path = _tls_source(tmp_path)
    await source.start(receipt_handler(_Intake()))
    stopped = False
    try:
        _on_path(source, tls_path)
        tracked = source._clients if tls_path == "start_tls" else source._handshakes
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            # Before the fix the listener saw a socket only once the loop's handshake was done.
            await _until(
                lambda: len(tracked) == 1 and source._admission.active == 1,
                "a socket still in its TLS handshake is not tracked by the listener",
            )
            await asyncio.wait_for(source.stop(), timeout=http_module._CLIENT_SHUTDOWN_GRACE)
            stopped = True
            await _closed_by_listener(reader, within=http_module._CLIENT_SHUTDOWN_GRACE)
        finally:
            await _close_raw(writer)
        assert source._admission.active == 0
        assert source.tls_handshake_failures == 0  # stop() aborting a handshake is no failure
    finally:
        if not stopped:
            await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_a_handshake_finishing_after_stop_began_is_refused_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tls_path: str
) -> None:
    """The 2026-10-02 residual, kept fixed on both paths: a handshake that completes once stop()
    has begun must not have its request read or handled. stop() is stood in for by setting the
    flag as the handshake ends, so the interleaving is pinned without a timing race. Under the
    accept loop the handshake ends just before `_handshake_accepted` hands the socket over."""
    source, cert = _tls_source(tmp_path)
    events = _Events()
    source.on_connection_event = events
    intake = _Intake()
    if tls_path == "start_tls":
        real_start_tls = source._start_tls

        async def finish_then_stop(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer_host: str | None
        ) -> bool:
            ok = await real_start_tls(reader, writer, peer_host)
            source._admission.stopping = True
            return ok

        monkeypatch.setattr(source, "_start_tls", finish_then_stop)
    else:
        real_on_client = source._on_client

        async def stop_then_hand_over(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            *,
            slot: tuple[str | None, int] | None = None,
        ) -> None:
            assert slot is not None  # admitted before its handshake
            source._admission.stopping = True
            await real_on_client(reader, writer, slot=slot)

        monkeypatch.setattr(source, "_on_client", stop_then_hand_over)
    await source.start(receipt_handler(intake))
    try:
        _on_path(source, tls_path)
        assert await _https_post(source.sockport, cert) is None  # closed with no response
        await _until(lambda: source._admission.active == 0, "the slot was not released")
        assert intake.received == []
        assert "established" not in events.kinds()
    finally:
        source._admission.stopping = False
        await asyncio.wait_for(source.stop(), timeout=10.0)


async def test_a_listener_running_its_own_handshake_counts_each_failure_once(
    tmp_path: Path, tls_path: str
) -> None:
    """The listener counts a failed handshake itself on both paths, with the peer, and never hooks
    its context (`HandshakeFailures.watch`), which would count each failure a second time. Before
    the accept loop, the forced path counted through that hook alone, with no peer."""
    source, _cert_path = _tls_source(tmp_path)
    assert source._ssl is not None
    events = _Events()
    source.on_connection_event = events
    await source.start(receipt_handler(_Intake()))
    try:
        _on_path(source, tls_path)
        assert source._ssl.sslobject_class is ssl.SSLObject
        await _plaintext_peer(source.sockport)
        await _until(lambda: source.tls_handshake_failures >= 1, "the failure was not counted")
        await asyncio.sleep(0.1)  # room for a second count, which must not come
        assert source.tls_handshake_failures == 1
        (_kind, peer, _reason) = events.seen[0]
        assert peer == "127.0.0.1"
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)


@pytest.mark.parametrize(("subject", "status"), [("CN:127.0.0.1", 202), ("CN:other", 403)])
async def test_mtls_subject_reads_the_certificate_after_either_handshake(
    tmp_path: Path, tls_path: str, subject: str, status: int
) -> None:
    """``mtls_subject`` reads the verified peer certificate from the writer. On ``start_tls`` that
    writer's transport was swapped by the upgrade, and under the accept loop the writer is built
    by `_handshake_accepted`, so this pins that the certificate is there on both: a listed subject
    is served, and an unlisted one gets the 403. Either way the slot is given back."""
    source, cert = _tls_source(
        tmp_path,
        tls_ca_file=str(tmp_path / "c.pem"),
        intake_auth="mtls_subject",
        # Keyed by the issuing CA's DN (vault BACKLOG #2287). The client presents the self-signed
        # c.pem, which is also the loaded anchor, so it is its own issuer.
        intake_client_subjects={"CN=127.0.0.1": [subject]},
    )
    intake = _Intake()
    await source.start(receipt_handler(intake))
    try:
        _on_path(source, tls_path)
        assert await _https_post(source.sockport, cert, client_key=tmp_path / "k.pem") == status
        await _until(lambda: source._admission.active == 0, "the slot was not released")
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)
    assert intake.received == ([b"hi"] if status == 202 else [])


async def test_a_socket_the_tls_layer_never_took_is_closed_and_its_slot_given_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Under the accept loop, ``connect_accepted_socket`` can fail before its transport holds the
    socket. That is no handshake failure, so it is not counted, and the socket is still the
    listener's: the done callback closes it, and the slot comes back. A real client served next
    is the control."""
    monkeypatch.setattr(http_module, "_upgrades_tls_itself", lambda _loop: False)
    loop_class = type(asyncio.get_running_loop())
    real_connect_accepted = loop_class.connect_accepted_socket
    refused: list[bool] = []

    async def refuse(self: asyncio.AbstractEventLoop, *args: object, **kwargs: object) -> object:
        refused.append(True)
        raise OSError("refused before the transport took the socket")

    source, cert = _tls_source(tmp_path)
    intake = _Intake()
    monkeypatch.setattr(loop_class, "connect_accepted_socket", refuse)
    await source.start(receipt_handler(intake))
    try:
        _on_path(source, "accept_loop")
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            await _closed_by_listener(reader, within=5.0)
        finally:
            await _close_raw(writer)
        assert refused == [True]
        await _until(lambda: source._admission.active == 0, "the slot was not released")
        assert source._client_tasks == set() and source._handshakes == set()
        assert source.tls_handshake_failures == 0
        monkeypatch.setattr(loop_class, "connect_accepted_socket", real_connect_accepted)
        assert await _https_post(source.sockport, cert) == 202
    finally:
        await asyncio.wait_for(source.stop(), timeout=10.0)
    assert intake.received == [b"hi"]


# --- the accept loop on the real uvloop (BACKLOG #2479) -------------------------------------------
#
# The tests above run `_AcceptingServer` on the stdlib loop, forced. These run them on uvloop, the
# loop it exists for, where nothing has to force it. Each skips where uvloop is not installed, so
# they run on CI's Linux legs only.


_Scenario = Callable[[Path, pytest.MonkeyPatch], Awaitable[None]]


@pytest.mark.skipif(sys.platform == "win32", reason="uvloop does not run on Windows")
@pytest.mark.parametrize(
    "scenario",
    [
        pytest.param(
            lambda p, m: test_a_socket_that_never_handshakes_is_closed_at_the_handshake_timeout(
                p, m, "uvloop"
            ),
            id="handshake_bound",
        ),
        pytest.param(
            lambda p, m: test_an_unhandshaken_socket_spends_a_connection_slot(
                p, m, {"max_connections": 1}, None, "uvloop"
            ),
            id="max_connections",
        ),
        pytest.param(
            lambda p, m: test_an_unhandshaken_socket_spends_a_connection_slot(
                p,
                m,
                {"max_connections": 0, "max_connections_per_host": 1},
                "max_connections_per_host",
                "uvloop",
            ),
            id="max_connections_per_host",
        ),
        pytest.param(
            lambda p, m: test_a_peer_outside_the_allowlist_is_refused_before_any_tls_byte(
                p, m, "uvloop"
            ),
            id="allowlist",
        ),
        pytest.param(
            lambda p, m: test_stop_closes_a_socket_still_in_its_handshake(p, m, "uvloop"),
            id="stop",
        ),
        pytest.param(
            lambda p, _m: test_mtls_subject_reads_the_certificate_after_either_handshake(
                p, "uvloop", "CN:127.0.0.1", 202
            ),
            id="mtls_subject",
        ),
    ],
)
def test_admission_runs_before_the_handshake_on_uvloop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scenario: _Scenario
) -> None:
    uvloop = pytest.importorskip("uvloop")

    async def run() -> None:
        assert http_module._upgrades_tls_itself(asyncio.get_running_loop()) is False
        await scenario(tmp_path, monkeypatch)

    asyncio.run(run(), loop_factory=uvloop.new_event_loop)
