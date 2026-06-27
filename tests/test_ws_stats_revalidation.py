# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SEC-018 — /ws/stats must stop streaming promptly after a session is revoked/downgraded.

The feed authorizes once at handshake then revalidates the session on an elapsed-time cadence
(``_WS_REVALIDATE_SECONDS``) AND once before the first post-accept send. These tests drive the real
ASGI ``/ws/stats`` route through a tiny in-memory websocket harness on the test's own event loop (so
the engine/store stay loop-consistent), monkeypatch the cadence small for determinism, and assert a
1008 close lands within ~the new cadence rather than waiting a full window."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.api import app as app_module
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "Sup3rSecret!!"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "ws.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    return user_id


class _WSHarness:
    """A minimal in-memory ASGI websocket peer that drives the real /ws/stats route on this loop.

    Collects every frame the server sends and exposes the close code; ``run`` returns once the server
    half closes the connection (a 1008 revocation close or a disconnect)."""

    def __init__(self, app: object, token: str) -> None:
        self._app = app
        self._token = token
        self._to_server: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        self.frames: list[dict[str, object]] = []
        self.close_code: int | None = None

    async def _receive(self) -> dict[str, object]:
        return await self._to_server.get()

    async def _send(self, message: dict[str, object]) -> None:
        kind = message["type"]
        if kind == "websocket.accept":
            return
        if kind == "websocket.send":
            import json

            self.frames.append(json.loads(message["text"]))  # type: ignore[arg-type]
            return
        if kind == "websocket.close":
            self.close_code = int(message.get("code", 1000))  # type: ignore[arg-type]
            return

    async def run(self, timeout: float) -> None:
        scope = {
            "type": "websocket",
            "path": "/ws/stats",
            "headers": [(b"authorization", f"Bearer {self._token}".encode())],
            "query_string": b"",
            "subprotocols": [],
            "client": ("127.0.0.1", 9999),
            "scheme": "ws",
            "app": None,
        }
        # The handshake connect message; the server accepts then streams until it closes.
        await self._to_server.put({"type": "websocket.connect"})
        await asyncio.wait_for(self._app(scope, self._receive, self._send), timeout)  # type: ignore[operator]


async def _login_token(service: AuthService, username: str) -> str:
    return (await service.login(username, PW)).token


async def test_revoked_session_is_closed_promptly(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "_WS_REVALIDATE_SECONDS", 0.1)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    task = asyncio.create_task(harness.run(timeout=5.0))
    # let the first frame land, then revoke the session server-side
    await asyncio.sleep(0.05)
    assert harness.frames, "expected at least one stats frame before revocation"
    await service.revoke_sessions_for_user(uid, actor="admin")
    await task
    assert harness.close_code == 1008


async def test_disabled_account_is_closed(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "_WS_REVALIDATE_SECONDS", 0.1)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    task = asyncio.create_task(harness.run(timeout=5.0))
    await asyncio.sleep(0.05)
    # disable the account mid-stream → identity_for_token returns None → the feed must close
    await engine.store.set_user_disabled(uid, disabled=True)
    await task
    assert harness.close_code == 1008


async def test_revoke_before_first_send_yields_no_frames(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A token revoked between handshake-authorize and the pre-first-send re-check must get NO frame.
    monkeypatch.setattr(app_module, "_WS_REVALIDATE_SECONDS", 0.1)
    service = await _service(engine)
    uid = await _add(service, "op", Role.OPERATOR)
    token = await _login_token(service, "op")
    app = create_app(engine, auth=service)
    harness = _WSHarness(app, token)
    # Revoke BEFORE running so the pre-first-send revalidation closes it with zero frames.
    await service.revoke_sessions_for_user(uid, actor="admin")
    await harness.run(timeout=5.0)
    assert harness.frames == []
    assert harness.close_code == 1008
