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
from fastapi import Depends, FastAPI, WebSocket
from starlette.websockets import WebSocketDisconnect

from messagefoundry.api import app as app_module
from messagefoundry.api import create_app
from messagefoundry.api.security import (
    WebSocketAcceptGate,
    authorize_ws,
    authorizes_in_body,
    mark_route_gate,
    mark_ws_gate_admitted,
    public_route,
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

    def __init__(self, app: object, path: str, token: str | None) -> None:
        self._app = app
        self._path = path
        self._token = token
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
        scope = {
            "type": "websocket",
            "path": self._path,
            "headers": headers,
            "query_string": b"",
            "subprotocols": [],
            "client": ("127.0.0.1", 9999),
            "scheme": "ws",
        }
        await self._to_server.put({"type": "websocket.connect"})
        await asyncio.wait_for(self._app(scope, self._receive, self._send), 20.0)  # type: ignore[operator]


def _assert_refused_before_accept(peer: _Peer) -> None:
    assert _ACCEPT not in peer.kinds, peer.sent
    assert peer.sent and peer.sent[0]["type"] == _CLOSE, peer.sent
    assert peer.sent[0].get("code") == 1008, peer.sent
    assert "websocket.send" not in peer.kinds, peer.sent


# --- /ws/stats, the engine's only WebSocket route -----------------------------------------------------


async def test_ws_stats_refuses_an_unauthenticated_caller_before_accept(engine: Engine) -> None:
    app = create_app(engine, auth=await _service(engine))
    peer = _Peer(app, "/ws/stats", None)
    await peer.run()
    _assert_refused_before_accept(peer)


async def test_ws_stats_refuses_a_caller_without_the_permission_before_accept(
    engine: Engine,
) -> None:
    service = await _service(engine)
    token = await _token(service, "norole")  # no role, so no monitoring:read
    peer = _Peer(create_app(engine, auth=service), "/ws/stats", token)
    await peer.run()
    _assert_refused_before_accept(peer)


async def test_ws_stats_accepts_an_authorized_caller(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "_WS_FRAME_SECONDS", 0.01)
    service = await _service(engine)
    token = await _token(service, "op", Role.OPERATOR)
    peer = _Peer(create_app(engine, auth=service), "/ws/stats", token)
    await peer.run()
    assert peer.kinds[:2] == [_ACCEPT, "websocket.send"], peer.sent


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
        except Exception as exc:  # the refusal; recorded so the test can name it
            outcome.accept_error = exc
            try:
                await websocket.send_json({"leaked": True})
            except Exception as again:
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

    async def admit(websocket: WebSocket) -> None:
        return None

    @app.websocket("/zz/dependency-gated", dependencies=[Depends(mark_route_gate(admit))])
    async def dependency_gated(websocket: WebSocket) -> None:
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
        "refused accept on WebSocket route /zz/no-gate: no gate admitted the caller before accept()"
    ], lines


@pytest.mark.parametrize(
    ("roles", "accepted"),
    [((), False), ((Role.OPERATOR,), True)],
    ids=["wrong-permission", "authorized"],
)
async def test_an_in_body_socket_that_ignores_its_gate_is_accepted_only_when_the_gate_admitted(
    engine: Engine, roles: tuple[Role, ...], accepted: bool
) -> None:
    service = await _service(engine)
    token = await _token(service, "caller", *roles)
    outcome = _Outcome()
    peer = _Peer(_planted(engine, service, outcome), "/zz/ignores-refusal", token)
    await peer.run()
    if accepted:
        assert peer.kinds[:2] == [_ACCEPT, "websocket.send"], peer.sent
        assert outcome.accept_error is None
    else:
        _assert_refused_before_accept(peer)


async def test_an_in_body_socket_that_ignores_its_gate_refuses_an_unauthenticated_caller(
    engine: Engine,
) -> None:
    outcome = _Outcome()
    peer = _Peer(_planted(engine, await _service(engine), outcome), "/zz/ignores-refusal", None)
    await peer.run()
    _assert_refused_before_accept(peer)


@pytest.mark.parametrize("path", ["/zz/public", "/zz/dependency-gated"])
async def test_a_socket_declared_another_way_needs_no_mark(engine: Engine, path: str) -> None:
    """A public socket has no gate by design, and a dependency gate ran before the body did."""
    outcome = _Outcome()
    peer = _Peer(_planted(engine, None, outcome), path, None)
    await peer.run()
    assert peer.kinds[:2] == [_ACCEPT, "websocket.send"], peer.sent


def test_create_app_installs_the_accept_gate() -> None:
    registered: list[object] = [m.cls for m in create_app().user_middleware]
    assert WebSocketAcceptGate in registered


def test_the_mark_is_the_only_way_an_in_body_scope_is_allowed() -> None:
    class _NoScope:
        pass

    mark_ws_gate_admitted(_NoScope())  # type: ignore[arg-type]  # a double with no scope: no raise
    assert not ws_accept_allowed({})

    class _Handshake:
        def __init__(self) -> None:
            self.scope: dict[str, Any] = {}

    handshake = _Handshake()
    mark_ws_gate_admitted(handshake)  # type: ignore[arg-type]
    assert ws_accept_allowed(handshake.scope)
