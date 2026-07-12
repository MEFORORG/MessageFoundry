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
    # Step-up-recency tests, not MFA tests: pin require_mfa=False so the admin's step-up path isn't
    # first blocked by the BACKLOG #187 secure default (require_mfa now ON for the Administrator role).
    # Tests that DO exercise require_mfa pass it explicitly.
    service = AuthService(engine.store, settings or AuthSettings(require_mfa=False))
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
    # require_mfa=False: this test pins the step-up RECENCY window, not the MFA gate (BACKLOG #187
    # secure default now ON — an explicit AuthSettings bypasses the helper's opt-out, so set it here).
    service = await _service(engine, AuthSettings(step_up_max_age_seconds=300, require_mfa=False))
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


# --- ADR 0077: action-bound step-up for the durable-takeover routes ----------
async def _reauth(
    c: httpx.AsyncClient, token: str, *, purpose: str | None = None, password: str = PW
) -> httpx.Response:
    body: dict[str, str] = {"password": password}
    if purpose is not None:
        body["purpose"] = purpose
    return await c.post("/me/reauth", headers=_auth(token), json=body)


async def test_login_window_does_not_unlock_factor_binding(engine: Engine) -> None:
    """AC-1: a session INSIDE the login-seeded window is 403'd on the factor-binding routes until a
    fresh per-action reauth — login seeds the session window but NOT a per-action grant (ADR 0077)."""
    service = await _service(engine)
    await _add_admin(service, "boss")
    async with _client(engine, service) as c:
        token = await _login(c, "boss")
        # Fresh login: the session window is fresh (a broad admin op would pass), but the factor-binding
        # routes now demand a proof bound to THEIR action, which login never mints.
        assert (await c.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201
        for path, body, action in [
            ("/me/mfa/enroll", None, "mfa_enroll"),
            ("/me/mfa/confirm", {"code": "000000"}, "mfa_confirm"),
        ]:
            r = await c.post(path, headers=_auth(token), json=body)
            assert r.status_code == 403, (path, r.text)
            assert r.headers.get("X-Step-Up-Required") == "1"
            assert r.headers.get("X-Step-Up-Action") == action  # the 403 names the action to reauth
        # A per-action reauth for enroll unlocks exactly enroll (the staged secret is returned).
        assert (await _reauth(c, token, purpose="mfa_enroll")).status_code == 200
        enrolled = await c.post("/me/mfa/enroll", headers=_auth(token))
        assert enrolled.status_code == 200 and enrolled.json()["secret"]


async def test_action_grant_is_single_use_and_bound(engine: Engine) -> None:
    """AC-2: a fresh reauth grants EXACTLY the bound action, once. A second sensitive action re-prompts,
    and a grant for one action never unlocks another."""
    service = await _service(engine)
    await _add_admin(service, "boss")
    async with _client(engine, service) as c:
        token = await _login(c, "boss")
        # One reauth → one enroll.
        assert (await _reauth(c, token, purpose="mfa_enroll")).status_code == 200
        assert (await c.post("/me/mfa/enroll", headers=_auth(token))).status_code == 200
        # Single-use: the grant was consumed, so a second enroll re-prompts.
        again = await c.post("/me/mfa/enroll", headers=_auth(token))
        assert again.status_code == 403 and again.headers.get("X-Step-Up-Action") == "mfa_enroll"
        # Bound: an enroll grant does NOT unlock confirm (a different action).
        assert (await _reauth(c, token, purpose="mfa_enroll")).status_code == 200
        confirm = await c.post("/me/mfa/confirm", headers=_auth(token), json={"code": "000000"})
        assert (
            confirm.status_code == 403 and confirm.headers.get("X-Step-Up-Action") == "mfa_confirm"
        )


async def test_login_and_verify_mfa_never_grant_an_action(engine: Engine) -> None:
    """AC-3: neither login nor verify_mfa mints a per-action grant — only reauth(purpose=…) does."""
    from messagefoundry.auth import totp

    service = await _service(engine)
    await _add_admin(service, "boss")
    async with _client(engine, service) as c:
        token = await _login(c, "boss")
        identity = await service.identity_for_token(token)
        assert identity is not None
        # Login stamped the session window but no action grant.
        assert await service.has_recent_step_up(token) is True
        assert await service.has_action_step_up(token, "mfa_enroll") is False
        # Enroll + confirm TOTP (drives the service directly, past the HTTP step-up).
        enroll = await service.begin_mfa_enrollment(identity)
        await service.confirm_mfa_enrollment(identity, totp.totp(enroll.secret), token=token)
        # A fresh MFA-required login, then verify_mfa: it seeds the session window but NOT an action grant.
        token2 = (await service.login("boss", PW)).token
        assert token2 is not None
        assert await service.verify_mfa(token2, totp.totp(enroll.secret)) is True
        assert await service.has_recent_step_up(token2) is True  # verify_mfa re-anchored the window
        assert await service.has_action_step_up(token2, "mfa_disable") is False  # but no grant
        # Only reauth(purpose=…) mints one — and it is single-use.
        assert await service.reauth(identity, PW, token=token2, purpose="mfa_disable") is True
        assert await service.has_action_step_up(token2, "mfa_disable") is True  # consumes it
        assert await service.has_action_step_up(token2, "mfa_disable") is False  # gone


async def test_opt_out_restores_session_window(engine: Engine) -> None:
    """AC-4: with [auth].require_action_step_up=False the legacy session-window step-up returns, so a
    fresh login can enroll without a per-action reauth."""
    # require_mfa=False: this test pins the session-window step-up opt-out, not the MFA gate (an
    # explicit AuthSettings bypasses the helper's BACKLOG #187 opt-out, so set it here too).
    service = await _service(engine, AuthSettings(require_action_step_up=False, require_mfa=False))
    await _add_admin(service, "boss")
    async with _client(engine, service) as c:
        token = await _login(c, "boss")
        # Legacy behaviour: the login-seeded window satisfies the enroll step-up (no per-action reauth).
        enrolled = await c.post("/me/mfa/enroll", headers=_auth(token))
        assert enrolled.status_code == 200, enrolled.text
        # And a stale window still blocks it (the session-window gate is intact), unlocked by a plain
        # reauth carrying no purpose.
        await _make_stale(service, token)
        assert (await c.post("/me/mfa/enroll", headers=_auth(token))).status_code == 403
        assert (await _reauth(c, token)).status_code == 200
        assert (await c.post("/me/mfa/enroll", headers=_auth(token))).status_code == 200


async def test_mfa_pending_and_ad_do_not_deadlock(engine: Engine) -> None:
    """AC-5: an MFA-pending session (required-but-unenrolled admin) can still reach enrollment — the
    factor-binding routes are password-only (no MFA gate), so a per-action reauth unlocks them without
    a second factor the session can't yet produce."""
    service = await _service(engine, AuthSettings(require_mfa=True))
    # A require_mfa admin who has not enrolled: login leaves the session MFA-pending.
    await _add_admin(service, "boss")
    async with _client(engine, service) as c:
        token = await _login(c, "boss")
        # Enroll is gated on the per-action step-up, NOT the MFA gate — so the 403 asks for a step-up,
        # never an (unsatisfiable) MFA code.
        blocked = await c.post("/me/mfa/enroll", headers=_auth(token))
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"
        assert blocked.headers.get("X-MFA-Required") is None  # no MFA deadlock
        # The password-only per-action reauth unlocks enrollment for the MFA-pending session.
        assert (await _reauth(c, token, purpose="mfa_enroll")).status_code == 200
        assert (await c.post("/me/mfa/enroll", headers=_auth(token))).status_code == 200


async def test_ad_reauth_mints_action_grant_via_live_rebind(engine: Engine) -> None:
    """AC-5 (AD arm): an AD account's per-action reauth rides the live directory re-bind and still mints
    the single-use grant (no deadlock, no password-hash path)."""
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
        identity = await service.identity_for_token(token)
        assert identity is not None
        # Wrong AD password: the live re-bind fails and mints nothing.
        assert await service.reauth(identity, "wrong", token=token, purpose="mfa_disable") is False
        assert await service.has_action_step_up(token, "mfa_disable") is False
        # Correct AD password: the re-bind succeeds and the single-use grant is minted.
        assert await service.reauth(identity, "ad-pw", token=token, purpose="mfa_disable") is True
        assert await service.has_action_step_up(token, "mfa_disable") is True


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
