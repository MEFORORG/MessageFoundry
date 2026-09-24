# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A refused WebSocket handshake is an HTTP response, and it carries the header floor (BACKLOG #1120).

A browser opening ``/ws/stats`` sends an ordinary HTTP GET with an ``Upgrade`` header. When the app
refuses it with a bare ``websocket.close`` before ``accept``, uvicorn answers with an HTTP 403 of its
own making, and no application header can reach it. So the header floor's old premise -- "websockets
carry no HTTP response headers" -- was false on the one message that matters: the refusal.

These tests drive the real ASGI callable with a hand-built WebSocket scope, so both arms of the
``websocket.http.response`` extension can be exercised: a server that offers it (uvicorn does) must
get a real HTTP denial carrying the floor, and a server that does not must still get the bare close,
refused exactly as strictly as before. ``tests/test_header_floor_wire.py`` measures the same property
on the wire through a real uvicorn.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.types import Message, Receive, Scope, Send

from messagefoundry.api import create_app
from messagefoundry.api.client_networks import DENIAL_HEADER, DENIAL_MARKER
from messagefoundry.api.header_floor import (
    BASELINE_SECURITY_HEADERS,
    CSP_HEADER,
    FRAME_ANCESTORS_CSP,
    HSTS_HEADER,
    WEBSOCKET_DENIAL_EXTENSION,
    SecurityHeaderFloorMiddleware,
)
from messagefoundry.config.settings import SecuritySettings
from messagefoundry.pipeline import Engine

_DNS_HOST = "ops.example.com"


@pytest.fixture(scope="module")
async def engine(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[Engine]:
    # Module-scoped: every refusal here happens before the route touches the engine, so one
    # never-started engine serves the whole file (the session loop makes this safe).
    eng = await Engine.create(tmp_path_factory.mktemp("wsfloor") / "wsfloor.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _scope(
    *,
    path: str = "/ws/stats",
    client: tuple[str, int] = ("127.0.0.1", 50000),
    extension: bool = True,
    scheme: str = "ws",
    host: str = _DNS_HOST,
    app: Any = None,
) -> Scope:
    return {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "headers": [(b"host", host.encode())],
        "query_string": b"",
        "subprotocols": [],
        "client": client,
        "server": ("127.0.0.1", 8765),
        "scheme": scheme,
        "extensions": {WEBSOCKET_DENIAL_EXTENSION: {}} if extension else {},
        "app": app,
    }


async def _drive(app: Any, scope: Scope) -> list[Message]:
    """Run one handshake to completion and return every message the app sent."""
    sent: list[Message] = []
    inbox: asyncio.Queue[Message] = asyncio.Queue()
    await inbox.put({"type": "websocket.connect"})

    async def receive() -> Message:
        return await inbox.get()

    async def send(message: Message) -> None:
        sent.append(message)

    await asyncio.wait_for(app(scope, receive, send), 5.0)
    return sent


def _headers(message: Message) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, value in message.get("headers") or ():
        out.setdefault(bytes(name).decode("latin-1").lower(), []).append(
            bytes(value).decode("latin-1")
        )
    return out


def _assert_floor(message: Message) -> dict[str, list[str]]:
    headers = _headers(message)
    for name, value in BASELINE_SECURITY_HEADERS:
        assert headers.get(name.lower()) == [value], (name, headers)
    # The EFFECTIVE value, not presence: every policy naming frame-ancestors must deny, since a
    # second, permissive policy would also "contain" the directive.
    directives = [
        d.strip()
        for policy in headers.get(CSP_HEADER.lower(), [])
        for d in policy.split(";")
        if d.strip().casefold().startswith("frame-ancestors")
    ]
    assert directives and all(d == FRAME_ANCESTORS_CSP for d in directives), headers
    return headers


def _denial(sent: list[Message]) -> tuple[Message, bytes]:
    """The single HTTP denial a refused handshake must produce, and its body."""
    kinds = [m["type"] for m in sent]
    assert kinds[0] == "websocket.http.response.start", kinds
    assert "websocket.close" not in kinds and "websocket.accept" not in kinds, kinds
    body = b"".join(
        bytes(m.get("body", b"")) for m in sent if m["type"] == "websocket.http.response.body"
    )
    assert sent[-1]["type"] == "websocket.http.response.body"
    assert not sent[-1].get("more_body", False)
    return sent[0], body


# --- the four first-party pre-accept refusals --------------------------------------------------


async def test_an_unauthenticated_handshake_is_a_403_carrying_the_floor(engine: Engine) -> None:
    app = create_app(engine)
    start, body = _denial(await _drive(app, _scope()))
    assert start["status"] == 403
    headers = _assert_floor(start)
    assert HSTS_HEADER.lower() not in headers  # ws:// is cleartext; HSTS is never set over it
    assert "detail" in json.loads(body)


async def test_an_absent_engine_is_a_503_carrying_the_floor(engine: Engine) -> None:
    app = create_app(engine, allow_no_auth=True)
    app.state.engine = None
    start, _ = _denial(await _drive(app, _scope()))
    assert start["status"] == 503
    _assert_floor(start)


async def test_the_socket_cap_is_a_503_carrying_the_floor(engine: Engine) -> None:
    app = create_app(engine, allow_no_auth=True)
    app.state.ws_count = 10_000
    start, _ = _denial(await _drive(app, _scope()))
    assert start["status"] == 503
    _assert_floor(start)


async def test_a_network_denial_is_a_403_carrying_the_floor_and_the_marker(
    engine: Engine,
) -> None:
    app = create_app(
        engine, security_settings=SecuritySettings(allowed_client_networks=["10.0.0.0/8"])
    )
    start, body = _denial(await _drive(app, _scope(client=("192.168.9.9", 40000))))
    assert start["status"] == 403
    headers = _assert_floor(start)
    assert headers[DENIAL_HEADER.lower()] == [DENIAL_MARKER]
    assert json.loads(body)["denied"] == DENIAL_MARKER
    assert app.state.client_denials == 1


# --- the fallback: a server without the extension is refused exactly as before -----------------


async def test_without_the_extension_every_refusal_is_still_a_bare_close(engine: Engine) -> None:
    """The negative arm. A server that does not offer ``websocket.http.response`` cannot carry a
    denial response, so the refusal must degrade to the bare close and never to an accept."""
    netapp = create_app(
        engine, security_settings=SecuritySettings(allowed_client_networks=["10.0.0.0/8"])
    )
    capped = create_app(engine, allow_no_auth=True)
    capped.state.ws_count = 10_000
    engineless = create_app(engine, allow_no_auth=True)
    engineless.state.engine = None
    for app, client, code in (
        (create_app(engine), ("127.0.0.1", 1), 1008),
        (netapp, ("192.168.9.9", 2), 1008),
        (capped, ("127.0.0.1", 3), 1013),
        (engineless, ("127.0.0.1", 4), 1011),
    ):
        sent = await _drive(app, _scope(client=client, extension=False))
        assert [m["type"] for m in sent] == ["websocket.close"]
        assert sent[0]["code"] == code
    assert netapp.state.client_denials == 1


# --- the floor itself, on emitters no route controls ------------------------------------------


async def test_a_framework_close_to_an_unknown_path_becomes_a_403_carrying_the_floor(
    engine: Engine,
) -> None:
    """Starlette's router refuses a WebSocket to an unmatched path with its own bare close. No
    first-party code runs, so only the floor can put headers on that refusal."""
    start, body = _denial(await _drive(create_app(engine), _scope(path="/ws/nope")))
    assert start["status"] == 403
    assert body == b""
    _assert_floor(start)


async def _accept_then_close(scope: Scope, receive: Receive, send: Send) -> None:
    await receive()
    await send({"type": "websocket.accept"})
    await send({"type": "websocket.close", "code": 1008})


async def test_the_accept_carries_the_floor_and_a_post_accept_close_is_untouched() -> None:
    sent = await _drive(SecurityHeaderFloorMiddleware(_accept_then_close), _scope())
    assert [m["type"] for m in sent] == ["websocket.accept", "websocket.close"]
    _assert_floor(sent[0])
    assert sent[1] == {"type": "websocket.close", "code": 1008}


async def _bare_close(scope: Scope, receive: Receive, send: Send) -> None:
    await receive()
    await send({"type": "websocket.close", "code": 1008})


async def test_a_bare_close_without_the_extension_passes_through_unchanged() -> None:
    sent = await _drive(SecurityHeaderFloorMiddleware(_bare_close), _scope(extension=False))
    assert sent == [{"type": "websocket.close", "code": 1008}]


@pytest.mark.parametrize(
    ("scheme", "exposure_protected", "host", "want_hsts"),
    [
        ("wss", True, _DNS_HOST, True),  # operator chain over TLS: a UA may note it
        ("wss", False, _DNS_HOST, False),  # the engine's own minted self-signed pair
        ("wss", True, "127.0.0.1", False),  # IP-literal host (RFC 6797 section 8.1.1)
        ("ws", False, _DNS_HOST, False),  # cleartext
    ],
)
async def test_hsts_on_the_handshake_follows_the_same_gate_as_http(
    scheme: str, exposure_protected: bool, host: str, want_hsts: bool
) -> None:
    fake_app = SimpleNamespace(state=SimpleNamespace(exposure_protected=exposure_protected))
    for inner in (_bare_close, _accept_then_close):
        scope = _scope(scheme=scheme, host=host, app=fake_app)
        first = (await _drive(SecurityHeaderFloorMiddleware(inner), scope))[0]
        assert (HSTS_HEADER.lower() in _headers(first)) is want_hsts, (scheme, first)


async def test_lifespan_passes_through_the_floor_untouched() -> None:
    seen: dict[str, Any] = {}

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        seen["send"] = send
        seen["receive"] = receive

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    async def send(message: Message) -> None:
        return None

    await SecurityHeaderFloorMiddleware(inner)({"type": "lifespan"}, receive, send)
    assert seen["send"] is send and seen["receive"] is receive
