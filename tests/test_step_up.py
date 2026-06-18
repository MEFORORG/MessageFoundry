# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Step-up re-verification on highly sensitive operations (WP-L3-16, ASVS 7.5.3).

A session must have re-proved its credential — at login or via ``POST /me/reauth`` — within
``[auth].step_up_max_age_seconds`` before it may perform a sensitive admin / replay / config flow.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)
NEW_USER = {"username": "newbie", "password": PW, "roles": ["viewer"]}


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "stepup.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine, settings: AuthSettings | None = None) -> AuthService:
    service = AuthService(engine.store, settings or AuthSettings())
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _add_admin(service: AuthService, username: str) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    # Admin-created accounts force first-login rotation (WP-L3-12); clear it for a usable test login.
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login(
    c: httpx.AsyncClient, username: str, password: str = PW, provider: str = "local"
) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": password, "provider": provider}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _make_stale(service: AuthService, token: str) -> None:
    """Simulate the step-up window having elapsed by back-dating the session's reauth_at."""
    await service.store.mark_session_reauthed(hash_token(token), now=0.0)


# --- API enforcement ---------------------------------------------------------
async def test_fresh_login_may_perform_sensitive_op(engine: Engine) -> None:
    service = await _service(engine)
    await _add_admin(service, "boss")
    async with _client(engine, service) as c:
        token = await _login(c, "boss")
        # The login itself is the first verification, so a sensitive op right after is within window.
        r = await c.post("/users", headers=_auth(token), json=NEW_USER)
        assert r.status_code == 201, r.text


async def test_stale_session_blocked_then_reauth_refreshes(engine: Engine) -> None:
    service = await _service(engine)
    await _add_admin(service, "boss")
    async with _client(engine, service) as c:
        token = await _login(c, "boss")
        await _make_stale(service, token)
        blocked = await c.post("/users", headers=_auth(token), json=NEW_USER)
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"
        # A non-sensitive route is unaffected by a stale step-up window.
        assert (await c.get("/auth/me", headers=_auth(token))).status_code == 200
        # Wrong password does NOT refresh the window.
        bad = await c.post(
            "/me/reauth", headers=_auth(token), json={"password": "not-the-password"}
        )
        assert bad.status_code == 403
        assert (await c.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 403
        # Correct password refreshes it; the sensitive op now succeeds.
        ok = await c.post("/me/reauth", headers=_auth(token), json={"password": PW})
        assert ok.status_code == 200
        assert (await c.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201


async def test_app_replay_route_is_also_step_up_gated(engine: Engine) -> None:
    service = await _service(engine)
    await _add_admin(service, "boss")
    async with _client(engine, service) as c:
        token = await _login(c, "boss")
        await _make_stale(service, token)
        # The message doesn't exist, but step-up fires first → 403, not 404.
        blocked = await c.post("/messages/nonexistent/replay", headers=_auth(token))
        assert blocked.status_code == 403
        await c.post("/me/reauth", headers=_auth(token), json={"password": PW})
        # Past the gate now: a missing message is a normal 404 (anything but the step-up 403).
        passed = await c.post("/messages/nonexistent/replay", headers=_auth(token))
        assert passed.status_code != 403


async def test_ad_user_reauth_uses_a_live_rebind(engine: Engine) -> None:
    principal = AdPrincipal(
        username="jdoe",
        display_name="J Doe",
        email=None,
        dn="CN=jdoe,DC=x",
        groups=frozenset({"cn=mf-admins,dc=x"}),
    )

    class _FakeLdap:
        def authenticate(self, username: str, password: str) -> AdPrincipal | None:
            return principal if (username == "jdoe" and password == "ad-pw") else None

        def resolve_principal(self, username: str) -> AdPrincipal | None:
            return principal if username == "jdoe" else None

    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    service = AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()
    await service.set_ad_group_map([("CN=MF-Admins,DC=x", Role.ADMINISTRATOR.value)], actor="admin")
    async with _client(engine, service) as c:
        token = await _login(c, "jdoe", "ad-pw", provider="ad")
        await _make_stale(service, token)
        assert (await c.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 403
        # Wrong AD password fails the live re-bind.
        assert (
            await c.post("/me/reauth", headers=_auth(token), json={"password": "wrong"})
        ).status_code == 403
        # Correct AD password re-binds and refreshes the window.
        assert (
            await c.post("/me/reauth", headers=_auth(token), json={"password": "ad-pw"})
        ).status_code == 200
        assert (await c.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201


# --- service / store unit ----------------------------------------------------
async def test_has_recent_step_up_tracks_the_window(engine: Engine) -> None:
    service = await _service(engine, AuthSettings(step_up_max_age_seconds=300))
    await _add_admin(service, "boss")
    async with _client(engine, service) as c:
        token = await _login(c, "boss")
    th = hash_token(token)
    assert await service.has_recent_step_up(token) is True  # login stamped reauth_at
    assert await service.has_recent_step_up(None) is False
    assert await service.has_recent_step_up("not-a-real-token") is False
    await service.store.mark_session_reauthed(th, now=0.0)  # back-date past the window
    assert await service.has_recent_step_up(token) is False
    await service.store.mark_session_reauthed(th)  # now
    assert await service.has_recent_step_up(token) is True


async def test_create_session_stamps_reauth_at(engine: Engine) -> None:
    service = await _service(engine)
    uid = await service.create_local_user(
        username="u",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="t",
    )
    await engine.store.create_session(
        token_hash="deadbeef", user_id=uid, expires_at=2e12, client="t"
    )
    session = await engine.store.get_session("deadbeef")
    assert session is not None and session.reauth_at is not None  # stamped at creation
    await engine.store.mark_session_reauthed("deadbeef", now=123.0)
    refreshed = await engine.store.get_session("deadbeef")
    assert refreshed is not None and refreshed.reauth_at == 123.0
