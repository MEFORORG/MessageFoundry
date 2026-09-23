# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 7.2.4, login side: a console sign-in ends the session the browser held (BACKLOG #1146).

Every console sign-in leg answers with a ``Set-Cookie`` that replaces the browser's session cookie.
Before this change the old session stayed valid on the server, unreachable from that browser, until
it idled or hit its absolute cap. These tests drive each leg -- the password form, Windows SSO and
the federated callback -- with a live prior session cookie, and assert on the SERVER record, because
a cookie jar that dropped the old value proves nothing about whether the old token still works.

Each leg also has its inverse: a sign-in that FAILS must leave the prior session alive, and a success
must not touch the user's other sessions. Without those, "revoke the user's sessions on sign-in"
would pass every positive case here.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService, LoginOutcome
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)
_SAME = {"Sec-Fetch-Site": "same-origin"}

_PRINCIPAL = AdPrincipal(
    username="jdoe",
    display_name="J Doe",
    email="j@x",
    dn="CN=jdoe,DC=x",
    groups=frozenset({"cn=mf-admins,dc=x"}),
)


class _FakeLdap:
    """The duck-typed directory the /ui SSO and OIDC suites use. No AD exists in any test infra."""

    def authenticate(self, username: str, password: str) -> AdPrincipal | None:
        return _PRINCIPAL if username == "jdoe" else None

    def resolve_principal(self, username: str) -> AdPrincipal | None:
        return _PRINCIPAL if username == "jdoe" else None


def _directory_settings(**over: object) -> AuthSettings:
    base: dict[str, object] = {
        "require_mfa": False,
        "ad_enabled": True,
        "kerberos_enabled": True,
        "ad_server": "ldaps://x",
        "ad_user_search_base": "DC=x",
        "ad_bind_dn": "CN=svc,DC=x",
        "ad_bind_password": "x",
        "ad_domain": "corp.example",
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "mefor-console",
        "oidc_client_secret": "shhh",
        "oidc_authorization_endpoint": "https://idp.example/authorize",
        "oidc_token_endpoint": "https://idp.example/token",
        "oidc_jwks_uri": "https://idp.example/jwks",
        "oidc_allowed_endpoints": ["idp.example"],
    }
    base.update(over)
    return AuthSettings(**base)  # type: ignore[arg-type]


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, _directory_settings(), ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()
    await service.set_ad_group_map([("cn=mf-admins,dc=x", "administrator")], actor="admin")
    user_id = await service.create_local_user(
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, serve_ui=True, public_origin="https://ops.example")
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _prior_session(service: AuthService, c: httpx.AsyncClient) -> str:
    """Sign this browser in once, so it holds a LIVE session cookie the way a returning one does."""
    r = await c.post("/ui/login", data={"username": "op", "password": PW}, headers=_SAME)
    assert r.status_code == 303
    token = c.cookies.get("mf_session")
    assert token and await _live(service, token)
    return token


async def _live(service: AuthService, token: str) -> bool:
    return await service.identity_for_token(token, activity=False) is not None


async def _superseded_rows(engine: Engine) -> list[dict[str, object]]:
    rows = await engine.store.list_audit()
    out: list[dict[str, object]] = []
    for row in rows:
        if row["action"] != "auth.session_revoked" or not row["detail"]:
            continue
        detail = json.loads(str(row["detail"]))
        if detail.get("scope") == "superseded":
            out.append(detail)
    return out


# --- leg 1: the password form, POST /ui/login ------------------------------------------------------


async def test_ui_login_revokes_the_session_the_browser_presented(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        prior = await _prior_session(service, c)
        # A second, unrelated session for the same user -- another device. It must survive.
        elsewhere = await service.login("op", PW)
        assert elsewhere.token is not None
        r = await c.post("/ui/login", data={"username": "op", "password": PW}, headers=_SAME)
        assert r.status_code == 303 and r.headers["location"] == "/ui"
        new = c.cookies.get("mf_session")
        assert new and new != prior
        assert not await _live(service, prior), "the presented session is still valid"
        assert await _live(service, new)
        assert await _live(service, elsewhere.token), "a sign-in signed out another device"
    rows = await _superseded_rows(engine)
    assert len(rows) == 1
    assert rows[0]["session"] == hash_token(prior)[:12]


async def test_a_failed_ui_login_leaves_the_prior_session_alive(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        prior = await _prior_session(service, c)
        r = await c.post(
            "/ui/login", data={"username": "op", "password": "not-the-password"}, headers=_SAME
        )
        assert r.headers["location"] == "/ui/login?e=bad"
        assert await _live(service, prior), "a FAILED sign-in ended the prior session"
    assert await _superseded_rows(engine) == []


async def test_ui_login_with_no_prior_cookie_revokes_nothing(engine: Engine) -> None:
    service = await _service(engine)
    elsewhere = await service.login("op", PW)
    assert elsewhere.token is not None
    async with _client(engine, service) as c:
        r = await c.post("/ui/login", data={"username": "op", "password": PW}, headers=_SAME)
        assert r.status_code == 303
    assert await _live(service, elsewhere.token)
    assert await _superseded_rows(engine) == []


# --- leg 2: Windows SSO, GET /ui/sso ---------------------------------------------------------------


async def test_ui_sso_revokes_the_session_the_browser_presented(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "jdoe")
    async with _client(engine, service) as c:
        prior = await _prior_session(service, c)
        r = await c.get("/ui/sso", headers={"Authorization": "Negotiate c3BuZWdvLXRva2Vu"})
        assert r.status_code == 303 and r.headers["location"] == "/ui", r.headers
        assert c.cookies.get("mf_session") != prior
        assert not await _live(service, prior)
    rows = await _superseded_rows(engine)
    assert [r["session"] for r in rows] == [hash_token(prior)[:12]]


async def test_a_failed_ui_sso_leaves_the_prior_session_alive(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: None)
    async with _client(engine, service) as c:
        prior = await _prior_session(service, c)
        r = await c.get("/ui/sso", headers={"Authorization": "Negotiate c3BuZWdvLXRva2Vu"})
        assert r.headers["location"] == "/ui/login?e=sso_failed"
        assert await _live(service, prior)
    assert await _superseded_rows(engine) == []


# --- leg 3: federated sign-in, POST /ui/oidc/start then GET /ui/oidc/callback ----------------------


async def _oidc_round_trip(
    service: AuthService, c: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch, *, ok: bool
) -> httpx.Response:
    """Start with the prior cookie present, then call back WITHOUT it.

    The session cookie is SameSite=Strict and the IdP's redirect back is a cross-site navigation, so
    a real browser withholds it on the callback. Dropping it here is what makes the test able to fail
    if the engine only looked for the prior session at the callback.
    """

    async def _authenticated(*_a: object, **_k: object) -> LoginOutcome:
        if not ok:
            return LoginOutcome(ok=False, error="federated sign-in failed", reason="claim_aud")
        return await service.login("op", PW)

    monkeypatch.setattr(service, "authenticate_oidc", _authenticated)
    start = await c.post("/ui/oidc/start", headers=_SAME, follow_redirects=False)
    assert start.status_code == 303, start.headers
    state = dict(parse_qsl(urlsplit(start.headers["location"]).query))["state"]
    c.cookies.delete("mf_session")
    return await c.get(
        "/ui/oidc/callback",
        params={"code": "authcode", "state": state},
        headers={
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        },
        follow_redirects=False,
    )


async def test_ui_oidc_revokes_the_session_the_start_leg_saw(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        prior = await _prior_session(service, c)
        r = await _oidc_round_trip(service, c, monkeypatch, ok=True)
        assert r.status_code == 200, r.headers
        assert c.cookies.get("mf_session") not in (None, prior)
        assert not await _live(service, prior), "the federated leg left the prior session valid"
    rows = await _superseded_rows(engine)
    assert [r["session"] for r in rows] == [hash_token(prior)[:12]]


async def test_a_failed_ui_oidc_callback_leaves_the_prior_session_alive(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        prior = await _prior_session(service, c)
        r = await _oidc_round_trip(service, c, monkeypatch, ok=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/ui/login?e=")
        assert await _live(service, prior), "a FAILED federated sign-in ended the prior session"
    assert await _superseded_rows(engine) == []
