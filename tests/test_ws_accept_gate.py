# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An in-body WebSocket is accepted only after a gate admitted its caller (vault BACKLOG #2955).

Engine PR 2390 note 1: the route walk reads an ``authorizes_in_body`` socket's gate as a CALL in its
body, which is not proof the body acts on it. ``WebSocketAcceptGate`` closes that gap at run time:
``authorize_ws`` and the web console's ``authorize_ui_ws`` mark the handshake admitted when they admit
the caller, and the gate refuses ``websocket.accept`` on a socket that carries no mark, unless the
route declares its authorization by a gate dependency or a ``public_route`` mark.

Each socket here is driven through the whole app, middleware included, by an in-memory ASGI peer on
the test's own loop, which records every message the app sends. The harness offers no denial-response
extension, so a refusal before accept is a bare 1008 close, and an accept is the
``websocket.accept`` message itself."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import Depends, FastAPI, WebSocket, WebSocketException
from starlette.responses import PlainTextResponse
from starlette.websockets import WebSocketDisconnect

import messagefoundry.api.security as security_module
from messagefoundry.api import app as app_module
from messagefoundry.api import create_app
from messagefoundry.api.header_floor import SecurityHeaderFloorMiddleware
from messagefoundry.api.security import (
    WebSocketAcceptGate,
    authorize_ws,
    authorizes_in_body,
    mark_route_gate,
    public_route,
    record_ws_gate,
    ws_accept_allowed,
)
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen

PW = "Sup3rSecret!!"
_ACCEPT = "websocket.accept"
_CLOSE = "websocket.close"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "ws_accept_gate.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


async def _token(service: AuthService, username: str, *roles: Role) -> str:
    """Sign in a provisioned user holding ``roles`` (none at all is allowed) and return the token."""
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )
    token = (await service.login(username, PW)).token
    assert token is not None
    return token


class _Peer:
    """An in-memory ASGI WebSocket peer. It records every message the app sends, and drops the
    connection on the first data frame, so a feed that streams forever ends: Starlette turns the
    ``OSError`` a send raises into ``WebSocketDisconnect``, as for a peer that went away."""

    def __init__(
        self, app: object, path: str, token: str | None, *, denial_extension: bool = False
    ) -> None:
        self._app = app
        self._path = path
        self._token = token
        self._denial_extension = denial_extension
        self._to_server: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self.sent: list[dict[str, Any]] = []

    @property
    def kinds(self) -> list[str]:
        return [str(m["type"]) for m in self.sent]

    async def _receive(self) -> dict[str, object]:
        return await self._to_server.get()

    async def _send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)
        if message["type"] == "websocket.send":
            raise OSError("the peer went away")

    async def run(self) -> None:
        headers = [(b"authorization", f"Bearer {self._token}".encode())] if self._token else []
        scope: dict[str, Any] = {
            "type": "websocket",
            "path": self._path,
            "headers": headers,
            "query_string": b"",
            "subprotocols": [],
            "client": ("127.0.0.1", 9999),
            "scheme": "ws",
        }
        if self._denial_extension:
            scope["extensions"] = {"websocket.http.response": {}}
        await self._to_server.put({"type": "websocket.connect"})
        await asyncio.wait_for(self._app(scope, self._receive, self._send), 20.0)  # type: ignore[operator]


def _assert_refused_before_accept(peer: _Peer) -> None:
    assert _ACCEPT not in peer.kinds, peer.sent
    assert peer.sent and peer.sent[0]["type"] == _CLOSE, peer.sent
    assert peer.sent[0].get("code") == 1008, peer.sent
    assert "websocket.send" not in peer.kinds, peer.sent


# --- /ws/stats, the engine's only WebSocket route -----------------------------------------------------


@pytest.mark.parametrize(
    ("roles", "accepted"),
    [(None, False), ((), False), ((Role.OPERATOR,), True)],
    ids=["unauthenticated", "no-permission", "authorized"],
)
async def test_ws_stats_is_accepted_only_for_an_authorized_caller(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    roles: tuple[Role, ...] | None,
    accepted: bool,
) -> None:
    """``roles`` None sends no token; ``()`` signs in a user with no role, so no monitoring:read."""
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.01)
    service = await _service(engine)
    token = None if roles is None else await _token(service, "caller", *roles)
    peer = _Peer(create_app(engine, auth=service), "/ws/stats", token)
    await peer.run()
    if accepted:
        assert peer.kinds[:2] == [_ACCEPT, "websocket.send"], peer.sent
    else:
        _assert_refused_before_accept(peer)


# --- planted sockets: the accept gate itself ----------------------------------------------------------


class _Outcome:
    """What a planted endpoint saw: the exception its accept raised, if any."""

    def __init__(self) -> None:
        self.accept_error: BaseException | None = None
        self.send_error: BaseException | None = None


def _planted(engine: Engine, service: AuthService | None, outcome: _Outcome) -> FastAPI:
    app = create_app(engine, auth=service) if service else create_app(allow_no_auth=True)

    async def accept_then_send(websocket: WebSocket) -> None:
        try:
            await websocket.accept()
        except WebSocketException as exc:  # the refusal; recorded so the test can name it
            outcome.accept_error = exc
            try:
                await websocket.send_json({"leaked": True})
            except WebSocketException as again:
                outcome.send_error = again
            raise
        try:
            await websocket.send_json({"ok": True})
        except WebSocketDisconnect:
            return

    @app.websocket("/zz/no-gate")
    @authorizes_in_body("a synthetic socket that never calls its gate")
    async def no_gate(websocket: WebSocket) -> None:
        await accept_then_send(websocket)

    @app.websocket("/zz/ignores-refusal")
    @authorizes_in_body("a synthetic socket that calls its gate and ignores a refusal")
    async def ignores_refusal(websocket: WebSocket) -> None:
        await authorize_ws(websocket, Permission.MONITORING_READ)
        await accept_then_send(websocket)

    @app.websocket("/zz/public")
    @public_route("a synthetic socket anonymous by design")
    async def public(websocket: WebSocket) -> None:
        await accept_then_send(websocket)

    @app.websocket("/zz/denial-200")
    @authorizes_in_body("a synthetic socket that answers with a denial response and no gate")
    async def denial_200(websocket: WebSocket) -> None:
        await websocket.send_denial_response(PlainTextResponse("synthetic-body", status_code=200))

    @app.websocket("/zz/denial-403")
    @authorizes_in_body("a synthetic socket that refuses with a denial response")
    async def denial_403(websocket: WebSocket) -> None:
        await websocket.send_denial_response(PlainTextResponse("refused", status_code=403))

    @app.websocket("/zz/lax-then-strict")
    @authorizes_in_body("a synthetic socket whose stricter gate's refusal is ignored")
    async def lax_then_strict(websocket: WebSocket) -> None:
        await authorize_ws(websocket)
        await authorize_ws(websocket, Permission.MONITORING_READ)
        await accept_then_send(websocket)

    async def admit(websocket: WebSocket) -> None:
        return None

    @app.websocket("/zz/dependency-gated", dependencies=[Depends(mark_route_gate(admit))])
    async def dependency_gated(websocket: WebSocket) -> None:
        await accept_then_send(websocket)

    @app.websocket(
        "/zz/dependency-gated-ignores-refusal", dependencies=[Depends(mark_route_gate(admit))]
    )
    async def dependency_gated_ignores_refusal(websocket: WebSocket) -> None:
        await authorize_ws(websocket, Permission.MONITORING_READ)
        await accept_then_send(websocket)

    return app


async def test_an_in_body_socket_that_never_calls_its_gate_is_refused_at_accept(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """Even on the open embedding path, where every gate would admit the caller: no gate ran."""
    outcome = _Outcome()
    peer = _Peer(_planted(engine, None, outcome), "/zz/no-gate", None)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.api.security"):
        await peer.run()
    _assert_refused_before_accept(peer)
    assert peer.kinds == [_CLOSE], peer.sent  # one close: Starlette's own close after it is dropped
    assert outcome.accept_error is not None and "1008" in repr(outcome.accept_error)
    assert outcome.send_error is not None, "a frame after the refused accept was not refused"
    lines = [r.getMessage() for r in caplog.records if "refused accept" in r.getMessage()]
    assert lines == [
        "refused accept on WebSocket route /zz/no-gate: no gate admitted the caller before accept() "
        "(1 refusals since the last log line, 1 in all)"
    ], lines


@pytest.mark.parametrize(
    ("roles", "accepted"),
    [(None, False), ((), False), ((Role.OPERATOR,), True)],
    ids=["unauthenticated", "wrong-permission", "authorized"],
)
async def test_an_in_body_socket_that_ignores_its_gate_is_accepted_only_when_the_gate_admitted(
    engine: Engine, roles: tuple[Role, ...] | None, accepted: bool
) -> None:
    service = await _service(engine)
    token = None if roles is None else await _token(service, "caller", *roles)
    outcome = _Outcome()
    peer = _Peer(_planted(engine, service, outcome), "/zz/ignores-refusal", token)
    await peer.run()
    if accepted:
        assert peer.kinds[:2] == [_ACCEPT, "websocket.send"], peer.sent
        assert outcome.accept_error is None
    else:
        _assert_refused_before_accept(peer)


async def test_a_non_refusal_denial_response_needs_an_admitted_caller(engine: Engine) -> None:
    """A denial response is an HTTP answer the body chooses, so one below 400 would hand a caller no
    gate admitted whatever the body sends. A 403 is how a gate refuses, and still goes out."""
    refused = _Peer(
        _planted(engine, None, _Outcome()), "/zz/denial-200", None, denial_extension=True
    )
    await refused.run()
    assert refused.sent and refused.sent[0]["type"] == "websocket.http.response.start", refused.sent
    assert [m for m in refused.sent if m["type"] == "websocket.http.response.start"] == [
        m for m in refused.sent[:1] if m.get("status") == 403
    ], refused.sent
    assert not any(b"synthetic-body" in m.get("body", b"") for m in refused.sent), refused.sent
    allowed = _Peer(
        _planted(engine, None, _Outcome()), "/zz/denial-403", None, denial_extension=True
    )
    await allowed.run()
    assert any(b"refused" in m.get("body", b"") for m in allowed.sent), allowed.sent


async def test_a_later_refusal_clears_an_earlier_admission(engine: Engine) -> None:
    """The body asks a lax gate, then ignores a stricter gate's refusal: the latest answer stands."""
    service = await _service(engine)
    token = await _token(service, "norole")  # signed in, but no monitoring:read
    peer = _Peer(_planted(engine, service, _Outcome()), "/zz/lax-then-strict", token)
    await peer.run()
    _assert_refused_before_accept(peer)


@pytest.mark.parametrize(
    ("roles", "accepted"),
    [((), False), ((Role.OPERATOR,), True)],
    ids=["wrong-permission", "authorized"],
)
async def test_a_refusal_the_body_ignores_stands_on_a_dependency_gated_socket(
    engine: Engine, roles: tuple[Role, ...], accepted: bool
) -> None:
    """A gate dependency admitted the caller, then the body's own stricter gate refused and the body
    accepted anyway: the recorded refusal stands, as the latest answer does on an in-body socket."""
    service = await _service(engine)
    token = await _token(service, "caller", *roles)
    peer = _Peer(
        _planted(engine, service, _Outcome()), "/zz/dependency-gated-ignores-refusal", token
    )
    await peer.run()
    if accepted:
        assert peer.kinds[:2] == [_ACCEPT, "websocket.send"], peer.sent
    else:
        _assert_refused_before_accept(peer)


async def test_a_gate_that_raises_leaves_no_earlier_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``authorize_ws`` records a refusal before it asks, so a raise inside it clears an earlier
    gate's admission rather than leaving it standing."""

    async def boom(websocket: WebSocket, *permissions: Permission) -> None:
        raise RuntimeError("synthetic failure inside the gate")

    monkeypatch.setattr(security_module, "_authorize_ws", boom)

    class _Handshake:
        def __init__(self) -> None:
            self.scope: dict[str, Any] = {}

    handshake = _Handshake()
    record_ws_gate(handshake, admitted=True)  # type: ignore[arg-type]
    assert ws_accept_allowed(handshake.scope)  # control: the earlier admission reads as admitted
    with pytest.raises(RuntimeError, match="synthetic failure"):
        await authorize_ws(handshake, Permission.MONITORING_READ)  # type: ignore[arg-type]
    assert not ws_accept_allowed(handshake.scope)


async def test_the_refusal_gets_the_header_floors_403(engine: Engine) -> None:
    """With the denial extension offered, the floor outside turns the refusal close into a 403
    carrying the baseline headers, as for a gate's own refusal."""
    peer = _Peer(_planted(engine, None, _Outcome()), "/zz/no-gate", None, denial_extension=True)
    await peer.run()
    start = peer.sent[0]
    assert start["type"] == "websocket.http.response.start" and start["status"] == 403, peer.sent
    names = {bytes(n).lower() for n, _ in start.get("headers", [])}
    assert b"x-content-type-options" in names, start
    assert _ACCEPT not in peer.kinds, peer.sent


@pytest.mark.parametrize("path", ["/zz/public", "/zz/dependency-gated"])
async def test_a_socket_declared_another_way_needs_no_mark(engine: Engine, path: str) -> None:
    """A public socket has no gate by design, and a dependency gate ran before the body did."""
    outcome = _Outcome()
    peer = _Peer(_planted(engine, None, outcome), path, None)
    await peer.run()
    assert peer.kinds[:2] == [_ACCEPT, "websocket.send"], peer.sent


def test_create_app_installs_the_accept_gate_inside_the_header_floor() -> None:
    """Index 0 is outermost. Inside the floor, so its refusal close gets the floor's 403."""
    registered: list[object] = [m.cls for m in create_app().user_middleware]
    assert registered.count(WebSocketAcceptGate) == 1, registered
    assert registered.index(SecurityHeaderFloorMiddleware) < registered.index(WebSocketAcceptGate)


def test_the_latest_recorded_answer_decides_an_in_body_scope() -> None:
    assert not ws_accept_allowed({})

    class _Handshake:
        def __init__(self) -> None:
            self.scope: dict[str, Any] = {}

    handshake = _Handshake()
    record_ws_gate(handshake, admitted=True)  # type: ignore[arg-type]
    assert ws_accept_allowed(handshake.scope)
    record_ws_gate(handshake, admitted=False)  # type: ignore[arg-type]
    assert not ws_accept_allowed(handshake.scope)


def test_a_plain_route_with_no_route_in_scope_is_read_by_its_endpoint() -> None:
    """FastAPI's router sets no ``route`` for a plain Starlette WebSocket route, so its endpoint's
    public mark decides. The scope is built by hand here, not routed."""

    @public_route("a synthetic public socket")
    async def public(websocket: WebSocket) -> None:
        return None

    @authorizes_in_body("a synthetic in-body socket")
    async def in_body(websocket: WebSocket) -> None:
        return None

    assert ws_accept_allowed({"endpoint": public})
    assert not ws_accept_allowed({"endpoint": in_body})
