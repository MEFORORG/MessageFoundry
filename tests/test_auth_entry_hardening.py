# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Phase-3a auth entry-surface hardening: fail-closed (SYS-1), rate limiting (AUTH-RATE),
input/body caps (API-INPUT)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth.ratelimit import SlidingWindowRateLimiter
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "entry.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine, settings: AuthSettings | None = None) -> AuthService:
    service = AuthService(engine.store, settings or AuthSettings())
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _login(c: httpx.AsyncClient, username: str, password: str) -> httpx.Response:
    return await c.post(
        "/auth/login", json={"username": username, "password": password, "provider": "local"}
    )


# --- SYS-1: fail-closed when no auth is attached -----------------------------


async def test_no_auth_fails_closed(engine: Engine) -> None:
    # create_app without an auth service AND without the opt-in must deny protected routes.
    transport = httpx.ASGITransport(app=create_app(engine))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/health")).status_code == 200  # liveness stays open
        assert (await c.get("/channels")).status_code == 503  # fail-closed, not full access


async def test_no_auth_opt_in_allows_access(engine: Engine) -> None:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/channels")).status_code == 200  # explicit embedding/dev opt-in


# --- AUTH-RATE: sliding-window limiter ---------------------------------------


def test_rate_limiter_per_key() -> None:
    rl = SlidingWindowRateLimiter(per_key=2, glob=0, window_seconds=60)
    assert rl.allow("a")
    assert rl.allow("a")
    assert not rl.allow("a")  # third attempt from the same key is blocked
    assert rl.allow("b")  # a different key is unaffected


def test_rate_limiter_global() -> None:
    rl = SlidingWindowRateLimiter(per_key=0, glob=2, window_seconds=60)
    assert rl.allow("a")
    assert rl.allow("b")
    assert not rl.allow("c")  # global cap hit regardless of key


async def test_login_rate_limited_per_ip(engine: Engine) -> None:
    service = await _service(
        engine, AuthSettings(login_rate_limit_per_ip=2, login_rate_limit_global=1000)
    )
    async with _client(engine, service) as c:
        assert (await _login(c, "nobody", "x")).status_code == 401  # 1 — invalid creds
        assert (await _login(c, "nobody", "x")).status_code == 401  # 2
        assert (await _login(c, "nobody", "x")).status_code == 429  # 3 — rate limited


# --- API-INPUT: length + body-size caps --------------------------------------


async def test_login_password_length_capped(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await _login(c, "u", "p" * 2000)  # over the password max_length
        assert r.status_code == 422  # rejected by request validation before any hashing


async def test_oversized_request_body_rejected(engine: Engine) -> None:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/config/reload", json={"config_dir": "x" * 1_200_000})
        assert r.status_code == 413  # body exceeds the 1 MiB cap
