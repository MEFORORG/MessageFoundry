"""Console client auth against a real server: login, token injection, permission gating, logout."""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn

from messagefoundry.api import create_managed_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.console.client import ApiError, EngineClient
from messagefoundry.store.store import MessageStore

PW = "Sup3rSecret!!"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


async def _seed(db_path: Path) -> None:
    store = await MessageStore.open(db_path)
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()  # seeds roles + a bootstrap admin we ignore
        for username, role in (("root", "administrator"), ("vw", "viewer")):
            await service.create_local_user(
                username=username,
                password=PW,
                display_name=None,
                email=None,
                roles=[role],
                actor="seed",
            )
    finally:
        await store.close()


@pytest.fixture
def auth_server(tmp_path: Path) -> Iterator[str]:
    db_path = tmp_path / "auth_console.db"
    asyncio.run(_seed(db_path))
    app = create_managed_app(db_path=db_path, auth_settings=AuthSettings(), poll_interval=0.05)
    port = _free_port()
    uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not uv.started:
        time.sleep(0.05)
        if time.time() > deadline:
            raise RuntimeError("server did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        uv.should_exit = True
        thread.join(timeout=10)


def test_protected_calls_need_login_then_logout_revokes(auth_server: str) -> None:
    with EngineClient(auth_server) as client:
        assert client.health().status == "ok"  # health is open
        with pytest.raises(ApiError) as unauth:
            client.stats()
        assert unauth.value.status == 401
        result = client.login("root", PW)
        assert result.user.username == "root"
        assert client.can("users:manage") and client.can("monitoring:read")
        client.stats()  # authorized now
        assert {u.username for u in client.list_users()} >= {"root", "vw"}
        client.logout()
        with pytest.raises(ApiError) as after:
            client.stats()
        assert after.value.status == 401


def test_viewer_is_permission_limited(auth_server: str) -> None:
    with EngineClient(auth_server) as client:
        client.login("vw", PW)
        assert client.can("monitoring:read") and not client.can("users:manage")
        with pytest.raises(ApiError) as forbidden:
            client.list_users()
        assert forbidden.value.status == 403


def test_bad_password_is_401(auth_server: str) -> None:
    with EngineClient(auth_server) as client:
        with pytest.raises(ApiError) as exc:
            client.login("root", "wrong")
        assert exc.value.status == 401
