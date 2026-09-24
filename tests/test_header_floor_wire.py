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
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import uvicorn
import websockets
from starlette.types import Receive, Scope, Send
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
from uvicorn.protocols.websockets.websockets_impl import WebSocketProtocol
from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol

from messagefoundry.api import create_app, protocol_headers
from messagefoundry.api.header_floor import (
    BASELINE_SECURITY_HEADERS,
    CSP_HEADER,
    FRAME_ANCESTORS_CSP,
    HSTS_HEADER,
)
from messagefoundry.api.protocol_headers import (
    floored_http_protocol_class,
    floored_ws_protocol_class,
)
from messagefoundry.api.tls_client_cert import client_cert_http_protocol_class
from messagefoundry.pipeline import Engine

#: The uvicorn this suite was measured against. See the module docstring before moving it.
_MEASURED_UVICORN = "0.49.0"
#: The websockets library writes the legacy protocol's own handshake rejections, so it is pinned too.
_MEASURED_WEBSOCKETS = "16.0"

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
    eng = await Engine.create(tmp_path / "wire.db", poll_interval=0.02)
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
    """Whether a response carries the whole baseline and denies framing in EVERY policy it sends."""
    baseline = all((n.lower(), v) in headers for n, v in BASELINE_SECURITY_HEADERS)
    directives = _frame_ancestors(headers)
    return baseline and bool(directives) and all(d == FRAME_ANCESTORS_CSP for d in directives)


def _frame_ancestors(headers: list[tuple[str, str]]) -> list[str]:
    return [
        d.strip()
        for n, policy in headers
        if n == CSP_HEADER.lower()
        for d in policy.split(";")
        if d.strip().casefold().startswith("frame-ancestors")
    ]


def _protocol_floored(headers: list[tuple[str, str]]) -> bool:
    """The protocol layer's set: ``nosniff`` exactly once, and framing denied in every policy."""
    names = [n for n, _ in headers]
    directives = _frame_ancestors(headers)
    return (
        names.count("x-content-type-options") == 1
        and ("x-content-type-options", "nosniff") in headers
        and bool(directives)
        and all(d == FRAME_ANCESTORS_CSP for d in directives)
    )


async def _bare_ws_refusal(scope: Scope, receive: Receive, send: Send) -> None:
    """The vacuity control: a pre-accept refusal with no floor anywhere in the stack."""
    assert scope["type"] == "websocket"
    await receive()
    await send({"type": "websocket.close", "code": 1008})


def test_the_suite_is_measuring_the_uvicorn_it_was_written_against() -> None:
    assert websockets.__version__ == _MEASURED_WEBSOCKETS, (
        f"websockets is {websockets.__version__}, and this suite measured {_MEASURED_WEBSOCKETS}. "
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


@pytest.mark.parametrize("base", [WebSocketProtocol, WebSocketsSansIOProtocol])
async def test_the_websocket_500_carries_nosniff(base: type[Any]) -> None:
    request = _HANDSHAKE.format(path="/ws/stats").encode()
    async with _served(_raises, ws=base) as port:
        control = await _exchange(port, request)
    async with _served(_raises, ws=floored_ws_protocol_class(base=base)) as port:
        shipped = await _exchange(port, request)
    _assert_protocol_family(control, shipped, 500)


def test_no_websocket_library_means_no_websocket_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("uvicorn.protocols.websockets.auto.AutoWebSocketsProtocol", None)
    assert floored_ws_protocol_class() is None


async def test_the_legacy_websocket_handshake_rejection_carries_nosniff() -> None:
    """The legacy websockets server answers a malformed handshake itself (here, no
    Sec-WebSocket-Key) before the app runs. The sans-I/O protocol's equivalent is NOT covered and
    is not what ``ws="auto"`` resolves to at the locked versions; see protocol_headers."""
    request = _HANDSHAKE.format(path="/ws/stats").replace(
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", ""
    )
    async with _served(_raises, ws=WebSocketProtocol) as port:
        control = await _exchange(port, request.encode())
    async with _served(_raises, ws=floored_ws_protocol_class(base=WebSocketProtocol)) as port:
        shipped = await _exchange(port, request.encode())
    _assert_protocol_family(control, shipped, 400)


# --- fail open: a failure on the header path never changes a status ---------------------------


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
            {"http": floored_http_protocol_class(base=HttpToolsProtocol)},
            id="http-400",
        ),
        pytest.param(
            "_HEADER_PAIRS",
            _Boom(),
            "http-500: header extension",
            _raises,
            _GET,
            500,
            {"http": floored_http_protocol_class(base=H11Protocol)},
            id="http-500",
        ),
        pytest.param(
            "_after_status_line",
            _boom,
            "status-line header injection",
            _raises,
            _MALFORMED,
            400,
            {"http": floored_http_protocol_class(base=H11Protocol)},
            id="h11-400",
        ),
        pytest.param(
            "_after_status_line",
            _boom,
            "status-line header injection",
            _raises,
            _HANDSHAKE.format(path="/ws").encode(),
            500,
            {"ws": floored_ws_protocol_class(base=WebSocketProtocol)},
            id="ws-500",
        ),
        pytest.param(
            "_HeaderInjectingTransport",
            _boom,
            "transport swap",
            _raises,
            _MALFORMED,
            400,
            {"http": floored_http_protocol_class(base=H11Protocol)},
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
            {"ws": floored_ws_protocol_class(base=WebSocketProtocol)},
            id="legacy-handshake-400",
        ),
    ],
)
async def test_every_header_step_fails_open(
    target: str,
    value: Any,
    step: str,
    app: Any,
    request_bytes: bytes,
    status: int,
    config: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(protocol_headers, "_WARNED", set())
    monkeypatch.setattr(protocol_headers, target, value)
    caplog.set_level(logging.WARNING, logger=protocol_headers.__name__)
    async with _served(app, **config) as port:
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
