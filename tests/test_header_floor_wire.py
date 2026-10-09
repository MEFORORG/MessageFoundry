# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The security header floor, measured ON THE WIRE through a real uvicorn (BACKLOG #1120).

In-process tests see ASGI messages. They cannot see what the server does with them, and the server
is where the gap was: uvicorn turns a bare pre-accept ``websocket.close`` into an HTTP 403 of its own
making. So this suite starts the locked uvicorn on a loopback socket, speaks raw HTTP/1.1 to it, and
reads the response bytes a browser would read.

**Every family is paired with a vacuity control in the same run.** The same probe, against a bare
ASGI app with no floor, must find the headers ABSENT. A suite whose probe cannot report absence
proves nothing by reporting presence.

**Two families, two layers.** The WebSocket refusal is the ASGI app's response, so it carries the
whole floor. The protocol families are responses the server writes BELOW the app; the list,
and its known gaps, live in :mod:`messagefoundry.api.protocol_headers`. Those carry ``nosniff`` and
``frame-ancestors 'none'`` only, and never HSTS: the protocol layer cannot see the HSTS gate's
inputs, and the default posture is a self-signed pair where HSTS must stay absent.

**The uvicorn version is pinned here on purpose.** The population of responses uvicorn writes itself
changes with its version, and no first-party inventory can enumerate it
(``tests/test_response_emitter_inventory.py`` pins only the first-party population). A version bump
turns this suite red until someone re-reads uvicorn's protocol modules for every response they write
below the app, extends the families here, and moves the pin.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import sys
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
import uvicorn
from starlette.types import Receive, Scope, Send
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
from uvicorn.protocols.websockets.websockets_impl import WebSocketProtocol
from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol
from websockets.version import version as websockets_version

from messagefoundry.api import create_app, protocol_headers
from messagefoundry.api.header_floor import (
    BASE_URI_CSP,
    BASELINE_SECURITY_HEADERS,
    CSP_HEADER,
    FRAME_ANCESTORS_CSP,
    HSTS_HEADER,
)
from messagefoundry.api.protocol_headers import (
    ProtocolFloorUnavailable,
    floored_http_protocol_class,
    floored_ws_protocol_class,
)
from messagefoundry.api.tls_client_cert import client_cert_http_protocol_class
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine

#: The uvicorn this suite was measured against. See the module docstring before moving it.
_MEASURED_UVICORN = "0.54.0"
#: The websockets library writes both WebSocket protocols' own handshake rejections, so it is
#: pinned too.
_MEASURED_WEBSOCKETS = "17.2"

_HANDSHAKE = (
    "GET {path} HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "wire.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


@asynccontextmanager
async def _served(app: Any, **config: Any) -> AsyncIterator[int]:
    """Serve ``app`` on an ephemeral loopback port for the duration of the block."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(app, lifespan="off", log_config=None, server_header=False, **config)
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(500):
            if server.started or task.done():
                break
            await asyncio.sleep(0.01)
        assert server.started, "uvicorn did not start"
        yield port
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10.0)
        sock.close()


async def _exchange(port: int, request: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
    """Send raw bytes and read the whole response until the server closes the connection."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(request)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(), 10.0)
    finally:
        writer.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers = []
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.append((name.strip().lower(), value.strip()))
    return status, headers, body


def _floored(headers: list[tuple[str, str]]) -> bool:
    """Whether a response carries the whole baseline and denies framing and ``<base>`` (BACKLOG
    #2341) in EVERY policy it sends that names either."""
    baseline = all((n.lower(), v) in headers for n, v in BASELINE_SECURITY_HEADERS)
    return baseline and _csp_floored(headers)


def _directives(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [
        d.strip()
        for n, policy in headers
        if n == CSP_HEADER.lower()
        for d in policy.split(";")
        if d.strip().casefold().startswith(name)
    ]


def _frame_ancestors(headers: list[tuple[str, str]]) -> list[str]:
    return _directives(headers, "frame-ancestors")


def _csp_floored(headers: list[tuple[str, str]]) -> bool:
    framing = _frame_ancestors(headers)
    base = _directives(headers, "base-uri")
    return (
        bool(framing)
        and all(d == FRAME_ANCESTORS_CSP for d in framing)
        and bool(base)
        and all(d == BASE_URI_CSP for d in base)
    )


def _protocol_floored(headers: list[tuple[str, str]]) -> bool:
    """The protocol layer's set: ``nosniff`` exactly once, and framing and base-uri denied."""
    names = [n for n, _ in headers]
    return (
        names.count("x-content-type-options") == 1
        and ("x-content-type-options", "nosniff") in headers
        and _csp_floored(headers)
    )


async def _bare_ws_refusal(scope: Scope, receive: Receive, send: Send) -> None:
    """The vacuity control: a pre-accept refusal with no floor anywhere in the stack."""
    assert scope["type"] == "websocket"
    await receive()
    await send({"type": "websocket.close", "code": 1008})


def test_the_suite_is_measuring_the_uvicorn_it_was_written_against() -> None:
    assert websockets_version == _MEASURED_WEBSOCKETS, (
        f"websockets is {websockets_version}, and this suite measured {_MEASURED_WEBSOCKETS}. "
        "Re-read the handshake responses it writes itself, then move the pin."
    )
    assert uvicorn.__version__ == _MEASURED_UVICORN, (
        f"uvicorn is {uvicorn.__version__}, and this suite measured {_MEASURED_UVICORN}. The set of "
        "responses uvicorn writes itself may have changed: re-read its protocol modules for every "
        "response it emits below the ASGI app, extend the families here, then move the pin."
    )


async def test_a_refused_handshake_on_the_wire_carries_the_floor(engine: Engine) -> None:
    async with _served(_bare_ws_refusal) as port:
        control = await _exchange(port, _HANDSHAKE.format(path="/ws/stats").encode())
    assert control[0] == 403
    assert not _floored(control[1]), f"the probe cannot see absence: {control[1]}"

    async with _served(create_app(engine)) as port:
        route = await _exchange(port, _HANDSHAKE.format(path="/ws/stats").encode())
        framework = await _exchange(port, _HANDSHAKE.format(path="/ws/no-such-route").encode())
    for status, headers, _ in (route, framework):
        assert status == 403
        assert _floored(headers), headers


# --- the protocol families: responses uvicorn writes below the ASGI app --------------------------

_MALFORMED = b"NOT A REQUEST LINE\r\n\r\n"
_GET = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
_GET_CLOSE = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


async def _raises(scope: Scope, receive: Receive, send: Send) -> None:
    """An app error before any response starts. Bare ASGI on purpose: Starlette's own
    ServerErrorMiddleware would answer first, and this family is what uvicorn sends when nothing did."""
    raise RuntimeError("synthetic app error")


async def _returns_without_a_response(scope: Scope, receive: Receive, send: Send) -> None:
    return None


def _http_arms() -> list[Any]:
    """Both HTTP implementations uvicorn can resolve, each with the client-cert shim off and on,
    because ``serve`` composes that shim on top of the floored protocol when mTLS is configured."""
    arms = []
    for base in (HttpToolsProtocol, H11Protocol):
        arms.append(pytest.param(base, False, id=f"{base.__name__}"))
        arms.append(pytest.param(base, True, id=f"{base.__name__}-client-cert"))
    return arms


def _shipped_http(base: type[Any], client_cert: bool) -> type[Any]:
    floored = floored_http_protocol_class(base=base)
    return client_cert_http_protocol_class(base=floored) if client_cert else floored


def _assert_protocol_family(
    control: tuple[int, list[tuple[str, str]], bytes],
    shipped: tuple[int, list[tuple[str, str]], bytes],
    status: int,
) -> None:
    assert control[0] == status, control
    assert not _protocol_floored(control[1]), f"the probe cannot see absence: {control[1]}"
    assert shipped[0] == status, shipped
    assert shipped[2] == control[2], "the header addition changed the body"
    assert _protocol_floored(shipped[1]), shipped[1]
    assert HSTS_HEADER.lower() not in [n for n, _ in shipped[1]]


@pytest.mark.parametrize(("base", "client_cert"), _http_arms())
async def test_the_malformed_request_400_carries_nosniff(
    base: type[Any], client_cert: bool
) -> None:
    async with _served(_raises, http=base) as port:
        control = await _exchange(port, _MALFORMED)
    async with _served(_raises, http=_shipped_http(base, client_cert)) as port:
        shipped = await _exchange(port, _MALFORMED)
    _assert_protocol_family(control, shipped, 400)


@pytest.mark.parametrize("app", [_raises, _returns_without_a_response])
@pytest.mark.parametrize(("base", "client_cert"), _http_arms())
async def test_the_app_error_500_carries_nosniff(
    base: type[Any], client_cert: bool, app: Any
) -> None:
    async with _served(app, http=base) as port:
        control = await _exchange(port, _GET)
    async with _served(app, http=_shipped_http(base, client_cert)) as port:
        shipped = await _exchange(port, _GET)
    _assert_protocol_family(control, shipped, 500)


#: Both WebSocket protocols the floor covers: the sans-I/O one ``ws="auto"`` resolves to at the
#: measured uvicorn, and the legacy server ``ws="websockets"`` still names.
_WS_BASES = [WebSocketsSansIOProtocol, WebSocketProtocol]


async def _ws_family(base: type[Any], app: Any, request: bytes, status: int) -> None:
    """One WebSocket handshake answer, on the bare protocol and on the floored one."""
    async with _served(app, ws=base) as port:
        control = await _exchange(port, request)
    async with _served(app, ws=floored_ws_protocol_class(base=base)) as port:
        shipped = await _exchange(port, request)
    _assert_protocol_family(control, shipped, status)


@pytest.mark.parametrize("base", _WS_BASES)
async def test_the_websocket_500_carries_nosniff(base: type[Any]) -> None:
    await _ws_family(base, _raises, _HANDSHAKE.format(path="/ws/stats").encode(), 500)


async def test_a_websocket_app_that_returns_without_answering_gets_a_floored_500() -> None:
    """The sans-I/O protocol only: the legacy server answers this case twice on one connection,
    so its bytes are not one response to compare."""
    request = _HANDSHAKE.format(path="/ws/stats").encode()
    await _ws_family(WebSocketsSansIOProtocol, _returns_without_a_response, request, 500)


@pytest.mark.parametrize("base", _WS_BASES)
async def test_the_servers_own_403_for_a_bare_close_carries_nosniff(base: type[Any]) -> None:
    """An app with no floor of its own closes before accepting, and the SERVER writes the 403. The
    API's apps never do this bare: the ASGI floor answers first. This is the protocol layer alone."""
    await _ws_family(base, _bare_ws_refusal, _HANDSHAKE.format(path="/ws/stats").encode(), 403)


async def _denies_with_a_response(scope: Scope, receive: Receive, send: Send) -> None:
    """A pre-accept denial through the ``websocket.http.response`` extension, with no header of
    its own: the answer the server builds from the app's status and body."""
    await receive()
    await send({"type": "websocket.http.response.start", "status": 401, "headers": []})
    await send({"type": "websocket.http.response.body", "body": b"denied"})


@pytest.mark.parametrize("base", _WS_BASES)
async def test_an_apps_bare_denial_response_carries_nosniff(base: type[Any]) -> None:
    await _ws_family(
        base, _denies_with_a_response, _HANDSHAKE.format(path="/ws/stats").encode(), 401
    )


async def _accepts_then_closes(scope: Scope, receive: Receive, send: Send) -> None:
    await receive()
    await send({"type": "websocket.accept"})
    await send({"type": "websocket.close", "code": 1000})


@pytest.mark.parametrize("base", _WS_BASES)
async def test_an_accepted_handshake_is_still_a_101_with_each_header_once(base: type[Any]) -> None:
    """Adding to the conn must not break the answer that is not a rejection. The 101 has no body
    for these headers to act on; what matters is that the upgrade still completes."""
    request = _HANDSHAKE.format(path="/ws/stats").encode()
    async with _served(_accepts_then_closes, ws=floored_ws_protocol_class(base=base)) as port:
        # An accepted connection stays open for the closing handshake, so read the head only.
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(request)
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10.0)
        finally:
            writer.close()
    lines = head.decode("latin-1").split("\r\n")
    assert lines[0].startswith("HTTP/1.1 101 "), lines[0]
    names = [line.partition(":")[0].strip().lower() for line in lines[1:] if line]
    assert "sec-websocket-accept" in names
    for name, _ in protocol_headers.PROTOCOL_SECURITY_HEADERS:
        assert names.count(name.lower()) == 1, names


#: A request line longer than the 8192 bytes the websockets parser reads, and a header block with
#: more lines than it accepts. Both pass uvicorn's HTTP protocol and reach the WebSocket one.
_LONG_LINE_UPGRADE = _HANDSHAKE.format(path="/" + "a" * 9000).encode()
_PARSER_REJECTED = [
    pytest.param(_LONG_LINE_UPGRADE, 414, id="long-request-line"),
    pytest.param(
        _HANDSHAKE.format(path="/ws/stats")
        .replace("\r\n\r\n", "\r\n" + "".join(f"X-{n}: 1\r\n" for n in range(200)) + "\r\n")
        .encode(),
        431,
        id="too-many-headers",
    ),
]


@pytest.mark.parametrize(("request_bytes", "status"), _PARSER_REJECTED)
async def test_a_parser_rejected_upgrade_is_answered_floored_and_closed(
    request_bytes: bytes, status: int
) -> None:
    """The one answer the floor writes itself. Leaving the block also stops the server, which
    must not raise: the control below shows it does on the bare class."""
    floored = floored_ws_protocol_class(base=WebSocketsSansIOProtocol)
    async with _served(_raises, ws=floored) as port:
        shipped = await _exchange(port, request_bytes)
    assert shipped[0] == status, shipped
    assert _protocol_floored(shipped[1]), shipped[1]


async def test_a_parse_error_with_no_queued_answer_is_closed_with_nothing_written() -> None:
    """The parser's third branch: a request it cannot parse at all (here, one that declares a
    body). It queues an end-of-stream and no answer. The floor closes and writes nothing: it never
    makes up an answer the library did not queue."""
    request = (
        _HANDSHAKE.format(path="/ws/stats").replace("\r\n\r\n", "\r\nContent-Length: 5\r\n\r\n")
        + "hello"
    ).encode()
    floored = floored_ws_protocol_class(base=WebSocketsSansIOProtocol)
    async with _served(_raises, ws=floored) as port:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(request)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(), 10.0)
        finally:
            writer.close()
    assert raw == b""


def test_a_second_answer_on_an_ended_conn_is_dropped_not_asserted() -> None:
    """What uvicorn does at server stop to a connection it already answered: a second
    send_response. On websockets' own ServerProtocol that asserts, which is the control. With the
    floor's hook it returns, and queues nothing more."""
    from websockets.server import ServerProtocol

    def _answered() -> Any:
        conn = ServerProtocol()
        conn.send_response(conn.reject(500, "first"))
        assert conn.eof_sent
        return conn

    bare = _answered()
    with pytest.raises(AssertionError):
        bare.send_response(bare.reject(500, "second"))

    floored = ServerProtocol()
    protocol_headers._floor_the_conn_responses(floored)
    floored.send_response(floored.reject(500, "first"))
    first = floored.data_to_send()
    assert b"nosniff" in first[0] and floored.eof_sent
    floored.send_response(floored.reject(500, "second"))
    assert floored.data_to_send() == []


class _NeverLostTransport(asyncio.Transport):
    """A transport whose close is never acknowledged: connection_lost is not delivered, as with a
    TLS peer that withholds its close. The protocol stays in the server's connection set."""

    def __init__(self) -> None:
        super().__init__()
        self.written = bytearray()
        self.closing = False

    def write(self, data: bytes | bytearray | memoryview) -> None:
        self.written += data

    def close(self) -> None:
        self.closing = True

    def is_closing(self) -> bool:
        return self.closing

    def pause_reading(self) -> None:
        pass

    def resume_reading(self) -> None:
        pass


async def _answered_and_still_open(ws_class: type[Any]) -> tuple[Any, _NeverLostTransport]:
    """A WebSocket protocol that has written uvicorn's pre-handshake 500 and asked its transport
    to close, with the close not yet acknowledged."""
    from uvicorn.server import ServerState

    config = uvicorn.Config(_raises, ws=ws_class, lifespan="off", log_config=None)
    protocol = ws_class(config=config, server_state=ServerState(), app_state={})
    transport = _NeverLostTransport()
    protocol.connection_made(transport)
    protocol.data_received(_HANDSHAKE.format(path="/ws/stats").encode())
    for _ in range(50):
        if transport.closing:
            break
        await asyncio.sleep(0)
    assert transport.written.startswith(b"HTTP/1.1 500 "), bytes(transport.written[:40])
    assert transport.closing
    return protocol, transport


async def test_shutdown_of_an_answered_still_open_connection_does_not_raise() -> None:
    """What uvicorn's Server.shutdown does to each connection still in its set: call
    ``shutdown()``. On the bare sans-I/O class, for a connection it already answered, that sends
    a second 500 and websockets asserts, which is the control. On the floored class the second
    answer is dropped, nothing more is written, and the call returns."""
    bare, _ = await _answered_and_still_open(WebSocketsSansIOProtocol)
    with pytest.raises(AssertionError):
        bare.shutdown()

    floored_class = floored_ws_protocol_class(base=WebSocketsSansIOProtocol)
    assert floored_class is not None
    floored, transport = await _answered_and_still_open(floored_class)
    assert b"nosniff" in transport.written
    written = bytes(transport.written)
    floored.shutdown()
    assert bytes(transport.written) == written


async def test_the_bare_sans_io_protocol_leaves_a_parser_rejection_unanswered() -> None:
    """The control, and a pin on uvicorn's own behaviour at the measured version: no answer, the
    connection left open, and a server stop that raises from inside websockets. If this fails,
    uvicorn has changed that path: re-read it, and remove the floor's ``data_received`` step if it
    is no longer needed."""
    request_bytes = _LONG_LINE_UPGRADE
    answered: bool | None = None
    reading: asyncio.Future[bytes] | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        # The connection must still be open when the block ends, because the raise comes from the
        # 500 uvicorn tries to send it at server stop. Nothing in the block asserts: an assertion
        # there would satisfy pytest.raises on its own.
        with pytest.raises(AssertionError) as stopped:
            async with _served(_raises, ws=WebSocketsSansIOProtocol) as port:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(request_bytes)
                await writer.drain()
                reading = asyncio.ensure_future(reader.read())
                done, _ = await asyncio.wait({reading}, timeout=1.0)
                answered = bool(done)
    finally:
        if reading is not None:
            reading.cancel()
        if writer is not None:
            writer.close()
    assert answered is False, "the bare protocol answered; uvicorn changed this path"
    raised_in = str(stopped.traceback[-1].path)
    assert "websockets" in raised_in, f"the stop raised somewhere else: {raised_in}"


def test_the_sans_io_websocket_protocol_is_floored() -> None:
    """It was refused until BACKLOG #1120 floored it: uvicorn 0.50 and later resolve
    ``ws="auto"`` to it, so on the measured uvicorn every start goes through this class."""
    floored = floored_ws_protocol_class(base=WebSocketsSansIOProtocol)
    assert floored is not None and issubclass(floored, WebSocketsSansIOProtocol)
    assert isinstance(vars(floored)["conn"], property)
    assert "write_http_response" not in vars(floored)
    resolved = floored_ws_protocol_class()
    assert resolved is not None and issubclass(resolved, WebSocketsSansIOProtocol)


def test_a_protocol_with_neither_hook_set_is_refused_not_served_bare() -> None:
    """wsproto's shape: it keeps a ``conn`` and has no ``write_http_response``, but its module has
    no websockets ``ServerProtocol`` for the floor to wrap. Built from parts, since wsproto is not
    a dependency and is not installed."""
    base = _fake_sansio_ws("ServerProtocol")
    with pytest.raises(ProtocolFloorUnavailable) as refused:
        floored_ws_protocol_class(base=base)
    assert refused.value.hook == "ServerProtocol in its module"


def test_no_websocket_library_means_no_websocket_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("uvicorn.protocols.websockets.auto.AutoWebSocketsProtocol", None)
    assert floored_ws_protocol_class() is None


@pytest.mark.parametrize("base", _WS_BASES)
async def test_the_librarys_own_handshake_rejection_carries_nosniff(base: type[Any]) -> None:
    """The websockets library answers a malformed handshake itself (here, no Sec-WebSocket-Key)
    before the app runs, under both protocols."""
    request = _HANDSHAKE.format(path="/ws/stats").replace(
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", ""
    )
    await _ws_family(base, _raises, request.encode(), 400)


# --- per-response steps degrade: a failure on the header path never changes a status -----------


async def _ok(scope: Scope, receive: Receive, send: Send) -> None:
    await send(
        {"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]}
    )
    await send({"type": "http.response.body", "body": b"ok"})


class _Boom:
    """An iterable that raises a NON-TypeError, standing in for an internal a new uvicorn moved."""

    def __iter__(self) -> Any:
        raise RuntimeError("synthetic header-path failure")


def _boom(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("synthetic header-path failure")


def _one_warning(caplog: pytest.LogCaptureFixture, step: str) -> None:
    hits = [r for r in caplog.records if r.name == protocol_headers.__name__]
    assert len(hits) == 1, [r.getMessage() for r in hits]
    assert step in hits[0].getMessage() and "RuntimeError" in hits[0].getMessage()


@pytest.mark.parametrize("base", [HttpToolsProtocol, H11Protocol])
async def test_a_broken_500_hook_still_serves_every_request_with_its_normal_status(
    base: type[Any], monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The per-request hook raises a non-TypeError on EVERY request. A normal request must still get
    its 200, an app error must still get uvicorn's 500, and the failure is logged once."""
    monkeypatch.setattr(protocol_headers, "_WARNED", set())
    monkeypatch.setattr(protocol_headers, "weakref", SimpleNamespace(ref=_boom))
    caplog.set_level(logging.WARNING, logger=protocol_headers.__name__)
    floored = floored_http_protocol_class(base=base)
    async with _served(_ok, http=floored) as port:
        first = await _exchange(port, _GET_CLOSE)
        second = await _exchange(port, _GET_CLOSE)
    async with _served(_raises, http=floored) as port:
        error = await _exchange(port, _GET)
    assert (first[0], first[2], second[0]) == (200, b"ok", 200)
    assert error[0] == 500
    _one_warning(caplog, "http-500: hook")


@pytest.mark.parametrize(
    ("target", "value", "step", "app", "request_bytes", "status", "config"),
    [
        pytest.param(
            "_after_status_line",
            _boom,
            "status-line header injection",
            _raises,
            _MALFORMED,
            400,
            lambda: {"http": floored_http_protocol_class(base=HttpToolsProtocol)},
            id="http-400",
        ),
        pytest.param(
            "_HEADER_PAIRS",
            _Boom(),
            "http-500: header extension",
            _raises,
            _GET,
            500,
            lambda: {"http": floored_http_protocol_class(base=H11Protocol)},
            id="http-500",
        ),
        pytest.param(
            "_after_status_line",
            _boom,
            "status-line header injection",
            _raises,
            _MALFORMED,
            400,
            lambda: {"http": floored_http_protocol_class(base=H11Protocol)},
            id="h11-400",
        ),
        pytest.param(
            "_after_status_line",
            _boom,
            "status-line header injection",
            _raises,
            _HANDSHAKE.format(path="/ws").encode(),
            500,
            lambda: {"ws": floored_ws_protocol_class(base=WebSocketProtocol)},
            id="ws-500",
        ),
        pytest.param(
            "_HeaderInjectingTransport",
            _boom,
            "transport swap",
            _raises,
            _MALFORMED,
            400,
            lambda: {"http": floored_http_protocol_class(base=H11Protocol)},
            id="transport-swap",
        ),
        pytest.param(
            "PROTOCOL_SECURITY_HEADERS",
            _Boom(),
            "ws-handshake: header addition",
            _raises,
            _HANDSHAKE.format(path="/ws")
            .replace("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "")
            .encode(),
            400,
            lambda: {"ws": floored_ws_protocol_class(base=WebSocketProtocol)},
            id="legacy-handshake-400",
        ),
        pytest.param(
            "PROTOCOL_SECURITY_HEADERS",
            _Boom(),
            "ws-sansio: header addition",
            _raises,
            _HANDSHAKE.format(path="/ws")
            .replace("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "")
            .encode(),
            400,
            lambda: {"ws": floored_ws_protocol_class(base=WebSocketsSansIOProtocol)},
            id="sansio-handshake-400",
        ),
        pytest.param(
            "weakref",
            SimpleNamespace(ref=_boom),
            "ws-sansio: hook",
            _raises,
            _HANDSHAKE.format(path="/ws").encode(),
            500,
            lambda: {"ws": floored_ws_protocol_class(base=WebSocketsSansIOProtocol)},
            id="sansio-conn-hook",
        ),
    ],
)
async def test_every_per_response_header_step_degrades(
    target: str,
    value: Any,
    step: str,
    app: Any,
    request_bytes: bytes,
    status: int,
    config: Callable[[], dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Built here, not at collection: a hook drift then fails these arms alone, rather than refusing
    # the whole module at import and hiding the version-pin test that explains it.
    protocols = config()
    monkeypatch.setattr(protocol_headers, "_WARNED", set())
    monkeypatch.setattr(protocol_headers, target, value)
    caplog.set_level(logging.WARNING, logger=protocol_headers.__name__)
    async with _served(app, **protocols) as port:
        response = await _exchange(port, request_bytes)
    assert response[0] == status
    _one_warning(caplog, step)


@pytest.mark.parametrize("cycle_module", ["h11_impl", "httptools_impl"])
def test_a_hooked_cycle_is_still_freed_by_refcount(cycle_module: str) -> None:
    """The weakref is load-bearing: a hook that held the cycle strongly would keep each request's
    scope and body alive until a GC pass. Measured on uvicorn's REAL cycle class, GC off."""
    import gc
    import importlib
    import weakref

    cls = importlib.import_module(f"uvicorn.protocols.http.{cycle_module}").RequestResponseCycle
    cycle = cls.__new__(cls)
    protocol_headers._floor_the_cycle_500(cycle)
    assert "send_500_response" in vars(cycle)  # the hook is installed, so the check is not vacuous
    ref = weakref.ref(cycle)
    enabled = gc.isenabled()
    gc.disable()
    try:
        del cycle
        assert ref() is None
    finally:
        if enabled:
            gc.enable()


def test_a_hooked_conn_is_still_freed_by_refcount() -> None:
    """The same weakref rule as the cycle hook, GC off. On a stand-in: websockets' real
    ServerProtocol holds itself through its own parser, so it is never freed by refcount, hooked
    or not, and could not show what the hook adds."""
    import gc
    import weakref

    class _Conn:
        def send_response(self, response: Any) -> None:
            pass

    conn = _Conn()
    protocol_headers._floor_the_conn_responses(conn)
    assert "send_response" in vars(conn)  # the hook is installed, so the check is not vacuous
    ref = weakref.ref(conn)
    enabled = gc.isenabled()
    gc.disable()
    try:
        del conn
        assert ref() is None
    finally:
        if enabled:
            gc.enable()


def test_a_changed_conn_writer_signature_reaches_the_library_unchanged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Degrade on a signature change: called with no response at all, the wrapper still calls the
    library's method with what it was given, and logs once."""
    seen: list[tuple[Any, ...]] = []

    class _Conn:
        def send_response(self, *args: Any) -> None:
            seen.append(args)

    monkeypatch.setattr(protocol_headers, "_WARNED", set())
    caplog.set_level(logging.WARNING, logger=protocol_headers.__name__)
    conn = _Conn()
    protocol_headers._floor_the_conn_responses(conn)
    conn.send_response()
    assert seen == [()]
    hits = [r.getMessage() for r in caplog.records if r.name == protocol_headers.__name__]
    assert len(hits) == 1 and "ws-sansio: header addition" in hits[0], hits


def test_a_changed_handshake_writer_signature_reaches_the_server_unchanged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Degrade on a signature change: a writer called with one argument, where 16.0, 17.1 and 17.2
    pass (status, headers, body), must still write, not raise inside the override."""
    written: list[tuple[Any, ...]] = []

    class _Stub(asyncio.Protocol):
        def connection_made(self, transport: Any) -> None:
            self.transport = transport

        def send_500_response(self) -> None:
            pass

        def write_http_response(self, response: Any) -> None:
            written.append((response,))

    monkeypatch.setattr(protocol_headers, "_WARNED", set())
    caplog.set_level(logging.WARNING, logger=protocol_headers.__name__)
    floored = floored_ws_protocol_class(base=_Stub)
    assert floored is not None
    floored().write_http_response("a single response object")  # type: ignore[attr-defined]
    assert written == [("a single response object",)]
    hits = [r.getMessage() for r in caplog.records if r.name == protocol_headers.__name__]
    assert len(hits) == 1 and "ws-handshake: header addition" in hits[0], hits


# --- fail closed at class build: a missing hook refuses, it never falls back ---------------------
#
# Each fake is built from parts, so an arm drops exactly one hook. The complete fakes must BUILD in
# the same run, or a refusal could be the fixture's fault rather than the missing hook's.

_FAKE_MODULE = "tests._fake_uvicorn_protocol_module"


def _sets_cycle_and_transport(self: Any) -> None:
    self.cycle = None
    self.transport = None


def _sets_cycle(self: Any) -> None:
    self.cycle = None


def _sets_transport(self: Any) -> None:
    self.transport = None


def _sets_default_headers(self: Any) -> None:
    self.default_headers = []


def _sets_nothing(self: Any) -> None:
    pass


def _writes(self: Any, *args: Any) -> None:
    pass


async def _sends_500(self: Any) -> None:
    pass


def _fake_http(monkeypatch: pytest.MonkeyPatch, drop: str | None) -> type[Any]:
    """An HTTP protocol shaped like uvicorn's with ``drop`` removed, in a registered module, so the
    floor looks up its cycle class the way it looks up uvicorn's."""
    cycle_members: dict[str, Any] = {
        "__module__": _FAKE_MODULE,
        "__init__": _sets_nothing if drop == "default_headers" else _sets_default_headers,
        # uvicorn's is a coroutine; a plain method in its place is the moved hook.
        "send_500_response": _writes if drop == "send_500_response" else _sends_500,
    }
    module = ModuleType(_FAKE_MODULE)
    if drop != "RequestResponseCycle":
        module.RequestResponseCycle = type("RequestResponseCycle", (), cycle_members)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, _FAKE_MODULE, module)
    init = {"cycle": _sets_transport, "transport": _sets_cycle}.get(
        drop or "", _sets_cycle_and_transport
    )
    members: dict[str, Any] = {"__module__": _FAKE_MODULE, "__init__": init}
    if drop != "send_400_response":
        members["send_400_response"] = _writes
    return type("FakeHTTPProtocol", (asyncio.Protocol,), members)


def _fake_ws(drop: str | None) -> type[Any]:
    members: dict[str, Any] = {
        "__module__": _FAKE_MODULE,
        "__init__": _sets_nothing if drop == "transport" else _sets_transport,
    }
    for name in ("send_500_response", "write_http_response"):
        if drop != name:
            members[name] = _writes
    return type("FakeWebSocketProtocol", (asyncio.Protocol,), members)


def _sets_conn(self: Any) -> None:
    self.conn = None


def _sets_conn_and_handshake_initiated(self: Any) -> None:
    self.conn = None
    self.handshake_initiated = False


def _sets_eof_sent(self: Any) -> None:
    self.eof_sent = False


def _sets_handshake_exc(self: Any) -> None:
    self.handshake_exc = None


def _sets_eof_sent_and_handshake_exc(self: Any) -> None:
    self.eof_sent = False
    self.handshake_exc = None


_FAKE_SANSIO_MODULE = "tests._fake_uvicorn_sansio_module"


def _fake_sansio_ws(drop: str | None, monkeypatch: pytest.MonkeyPatch | None = None) -> type[Any]:
    """A WebSocket protocol shaped like uvicorn's sans-I/O one with ``drop`` removed: it keeps a
    ``conn``, has no ``write_http_response``, and its module names a ``ServerProtocol`` whose
    ``send_response`` is synchronous. ``monkeypatch`` registers that module; without it the class
    lives in a module that was never imported, which is the ``ServerProtocol`` drop."""
    conn_init = {"eof_sent": _sets_handshake_exc, "handshake_exc": _sets_eof_sent}.get(
        drop or "", _sets_eof_sent_and_handshake_exc
    )
    conn_members: dict[str, Any] = {"__module__": _FAKE_SANSIO_MODULE, "__init__": conn_init}
    if drop != "send_response":
        conn_members["send_response"] = _async_hook if drop == "sync send_response" else _writes
    if drop != "data_to_send":
        conn_members["data_to_send"] = _writes
    if monkeypatch is not None:
        module = ModuleType(_FAKE_SANSIO_MODULE)
        if drop != "ServerProtocol":
            module.ServerProtocol = type("ServerProtocol", (), conn_members)  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, _FAKE_SANSIO_MODULE, module)
    # No send_500_response: the sans-I/O floor does not use it, so it must not be required.
    init = _sets_conn if drop == "handshake_initiated" else _sets_conn_and_handshake_initiated
    members: dict[str, Any] = {"__module__": _FAKE_SANSIO_MODULE, "__init__": init}
    if drop == "sync data_received":
        members["data_received"] = _async_hook
    return type("FakeSansIOProtocol", (asyncio.Protocol,), members)


def test_the_complete_fakes_build(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for every refusal below: with nothing dropped, every fake is floored."""
    assert floored_http_protocol_class(base=_fake_http(monkeypatch, None)) is not None
    assert floored_ws_protocol_class(base=_fake_ws(None)) is not None
    floored = floored_ws_protocol_class(base=_fake_sansio_ws(None, monkeypatch))
    assert floored is not None and isinstance(vars(floored)["conn"], property)


@pytest.mark.parametrize(
    ("drop", "named"),
    [
        ("sync data_received", "synchronous data_received method"),
        ("ServerProtocol", "ServerProtocol in its module"),
        ("send_response", "synchronous send_response method"),
        ("sync send_response", "synchronous send_response method"),
        ("data_to_send", "synchronous data_to_send method"),
        # The flags the two uvicorn-0.54 workarounds read. A rename would otherwise turn a
        # workaround off with no error: the drop of a second answer reads eof_sent.
        ("eof_sent", "eof_sent attribute"),
        ("handshake_exc", "handshake_exc attribute"),
        ("handshake_initiated", "handshake_initiated attribute"),
    ],
)
def test_a_sans_io_base_missing_a_hook_is_refused(
    drop: str, named: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ProtocolFloorUnavailable) as refused:
        floored_ws_protocol_class(base=_fake_sansio_ws(drop, monkeypatch))
    assert refused.value.hook == named
    assert f"has no {named}" in str(refused.value), str(refused.value)


@pytest.mark.parametrize(
    ("drop", "named"),
    [
        ("send_400_response", "synchronous send_400_response method"),
        ("cycle", "cycle attribute"),
        ("transport", "transport attribute"),
        ("RequestResponseCycle", "RequestResponseCycle in its module"),
        ("send_500_response", "send_500_response coroutine"),
        ("default_headers", "default_headers attribute"),
    ],
)
def test_an_http_base_missing_a_hook_is_refused(
    drop: str, named: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _fake_http(monkeypatch, drop)
    with pytest.raises(ProtocolFloorUnavailable) as refused:
        floored_http_protocol_class(base=base)
    message = str(refused.value)
    assert f"has no {named}" in message, message
    assert f"uvicorn {uvicorn.__version__}" in message, message
    assert f"websockets {websockets_version}" in message, message


@pytest.mark.parametrize(
    ("drop", "named"),
    [
        ("send_500_response", "synchronous send_500_response method"),
        ("transport", "transport attribute"),
        ("write_http_response", "synchronous write_http_response method"),
    ],
)
def test_a_websocket_base_missing_a_hook_is_refused(drop: str, named: str) -> None:
    with pytest.raises(ProtocolFloorUnavailable) as refused:
        floored_ws_protocol_class(base=_fake_ws(drop))
    assert f"has no {named}" in str(refused.value), str(refused.value)
    assert refused.value.hook == named
    assert f"uvicorn {uvicorn.__version__}" in str(refused.value)


async def _async_hook(self: Any, *args: Any) -> None:
    pass


@pytest.mark.parametrize("hook", ["send_500_response", "write_http_response"])
def test_a_websocket_hook_that_became_a_coroutine_is_refused(hook: str) -> None:
    """The floor calls these synchronously. A coroutine in their place would build, then hand the
    server an unawaited coroutine instead of a written response."""
    base = type("AsyncHookWebSocketProtocol", (_fake_ws(None),), {hook: _async_hook})
    with pytest.raises(ProtocolFloorUnavailable, match=f"synchronous {hook} method"):
        floored_ws_protocol_class(base=base)


def test_an_http_400_hook_that_became_a_coroutine_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = type("AsyncHookHTTPProtocol", (_fake_http(monkeypatch, None),), {})
    base.send_400_response = _async_hook  # type: ignore[attr-defined]
    with pytest.raises(ProtocolFloorUnavailable, match="synchronous send_400_response method"):
        floored_http_protocol_class(base=base)


def test_a_third_party_base_assigning_transport_does_not_satisfy_the_check() -> None:
    """websockets' own protocol assigns ``transport`` too. Only the class defining the hook that
    uses it, or a subclass, counts, so a rename in uvicorn's class is still refused."""
    third_party = type("ThirdPartyProtocol", (asyncio.Protocol,), {"__init__": _sets_transport})
    members = {"__module__": _FAKE_MODULE, "__init__": _sets_nothing}
    members.update(send_500_response=_writes, write_http_response=_writes)
    base = type("RenamedTransportProtocol", (third_party,), members)
    with pytest.raises(ProtocolFloorUnavailable, match="transport attribute"):
        floored_ws_protocol_class(base=base)


def _sets_transport_in_a_closure(self: Any) -> None:
    def assign() -> None:
        self.transport = None

    assign()


def test_an_assignment_moved_into_a_nested_function_still_counts() -> None:
    """The check reads nested code too, so moving an assignment into a helper closure is not an
    outage caused by the checker."""
    members = {"__module__": _FAKE_MODULE, "__init__": _sets_transport_in_a_closure}
    members.update(send_500_response=_writes, write_http_response=_writes)
    base = type("ClosureTransportProtocol", (asyncio.Protocol,), members)
    assert floored_ws_protocol_class(base=base) is not None


def test_the_installed_uvicorn_passes_the_check() -> None:
    """The control that matters for serve: the protocols the lock installs, and the ones
    ``http="auto"`` and ``ws="auto"`` resolve to, all build."""
    for base in (HttpToolsProtocol, H11Protocol, None):
        assert floored_http_protocol_class(base=base) is not None
    for ws_base in (WebSocketsSansIOProtocol, WebSocketProtocol, None):
        assert floored_ws_protocol_class(base=ws_base) is not None


def test_a_wrapper_over_uvicorns_hook_still_sees_uvicorns_assignments() -> None:
    """A subclass that wraps the hook, or a class floored twice, must not hide the assignments in
    uvicorn's own class: the check scans up to the base-most class that defines the hook."""

    class Wrapped(H11Protocol):
        def send_400_response(self, msg: str) -> None:
            super().send_400_response(msg)

    assert floored_http_protocol_class(base=Wrapped) is not None
    assert floored_http_protocol_class(base=floored_http_protocol_class(base=H11Protocol))
    assert floored_ws_protocol_class(base=floored_ws_protocol_class(base=WebSocketProtocol))
    assert floored_ws_protocol_class(base=floored_ws_protocol_class(base=WebSocketsSansIOProtocol))


def _serve_captured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str = "serve"
) -> tuple[int, dict[str, Any], set[Path]]:
    """Run ``command`` against a fixture that starts clean. Returns the exit code, what reached
    ``uvicorn.run``, and the files the command itself created (a TLS pair, a store)."""
    from messagefoundry.__main__ import main
    from tests._phi_gate_provisions import (
        PHI_GATE_PROVISIONS_TOML,
        make_syslog_ca_and_crl,
        setenv_verified_log_forwarding,
    )

    captured: dict[str, Any] = {}
    monkeypatch.chdir(tmp_path)
    setenv_verified_log_forwarding(monkeypatch, make_syslog_ca_and_crl(tmp_path))
    (tmp_path / "messagefoundry.toml").write_text(PHI_GATE_PROVISIONS_TOML, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: captured.update(k))
    samples = Path(__file__).resolve().parents[1] / "samples" / "config"
    before = set(tmp_path.rglob("*"))
    rc = main([command, "--config", str(samples), "--env", "dev"])
    return rc, captured, set(tmp_path.rglob("*")) - before


def test_serve_hands_uvicorn_the_floored_protocols(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the refusal below: the same fixture starts, serves the floor, and creates
    files, so the refusal's empty set is not a probe that cannot see creation."""
    rc, captured, created = _serve_captured(tmp_path, monkeypatch)
    assert rc == 0
    assert captured["http"].__name__ == "_FlooredHTTPProtocol"
    assert captured["ws"].__name__ == "_FlooredWebSocketProtocol"
    assert created, "serve created nothing, so the refusal's empty set would prove nothing"


def test_serve_refuses_to_start_when_uvicorn_lacks_a_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "uvicorn.protocols.http.auto.AutoHTTPProtocol",
        _fake_http(monkeypatch, "send_400_response"),
    )
    rc, captured, created = _serve_captured(tmp_path, monkeypatch)
    assert rc == 2
    assert captured == {}, "uvicorn.run was reached"
    assert created == set(), f"serve refused only after a side effect: {created}"
    err = capsys.readouterr().err
    assert "send_400_response method" in err and "refusing to start." in err, err


def test_supervise_refuses_the_fleet_before_spawning_or_renewing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Every shard would refuse, and the supervisor restarts a refused shard at once, so the fleet
    is refused once, up front, before the shared TLS pair is renewed."""

    def _no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("supervise spawned shards")

    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", _no_spawn)
    monkeypatch.setattr(
        "uvicorn.protocols.http.auto.AutoHTTPProtocol",
        _fake_http(monkeypatch, "send_400_response"),
    )
    rc, _, created = _serve_captured(tmp_path, monkeypatch, command="supervise")
    assert rc == 2
    assert created == set(), f"supervise refused only after a side effect: {created}"
    err = capsys.readouterr().err
    assert "send_400_response method" in err and "refusing to start the fleet" in err, err


# --- the startup self-test: a floor that builds but does not add its headers still refuses ------
#
# The structural refusals above knock out a hook's SHAPE. These leave every shape in place and stop
# one hook working, which only the behavioural self-test (api/protocol_floor_selftest.py) can see.
# test_serve_hands_uvicorn_the_floored_protocols is their control: the same fixture, nothing knocked
# out, starts.


def _cycle_500_hook_does_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(protocol_headers, "_floor_the_cycle_500", lambda cycle: None)


def test_serve_refuses_to_start_when_a_built_floor_leaves_a_response_bare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _cycle_500_hook_does_nothing(monkeypatch)
    rc, captured, created = _serve_captured(tmp_path, monkeypatch)
    assert rc == 2
    assert captured == {}, "uvicorn.run was reached"
    assert created == set(), f"serve refused only after a side effect: {created}"
    err = capsys.readouterr().err
    assert "failed its startup self-test: the app-error 500 lacked" in err, err
    assert "refusing to start." in err, err


def test_supervise_refuses_the_fleet_when_a_built_floor_leaves_a_response_bare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("supervise spawned shards")

    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", _no_spawn)
    _cycle_500_hook_does_nothing(monkeypatch)
    rc, _, created = _serve_captured(tmp_path, monkeypatch, command="supervise")
    assert rc == 2
    assert created == set(), f"supervise refused only after a side effect: {created}"
    err = capsys.readouterr().err
    assert "failed its startup self-test: the app-error 500 lacked" in err, err
    assert "refusing to start the fleet" in err, err
