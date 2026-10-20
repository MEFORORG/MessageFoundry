# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The federated step-up leg through the real console routes (BACKLOG #296, ADR 0142 Amendment B).

A session the federated login minted steps up at the IdP, never by a password. These tests sign a
browser in through ``/ui/oidc/start`` and ``/ui/oidc/callback``, then drive ``/ui/reauth``,
``POST /ui/reauth/oidc`` and the callback's step-up branch, asserting on the SERVER record.

The session cookie is SameSite=Strict and the IdP's redirect back is a cross-site navigation, so a
real browser withholds it on the callback. Each callback here drops it first, which is what makes
the step-up able to fail if the engine looked for the session anywhere but the staged flow.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

import httpx
import pytest
from _ui_clients import SAME_ORIGIN as _SAME
from _ui_clients import issue_continuation

from messagefoundry.api import create_app
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryBind
from messagefoundry.auth.oidc import FederatedPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole.routes.oidc import _step_up_return_key

_SUB = "S-1-5-21-fed"
_NEXT = "/ui/config/reload"
_CROSS_SITE_NAV = {
    "Sec-Fetch-Site": "cross-site",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Dest": "document",
}
_PRINCIPAL = AdPrincipal(
    username="jdoe",
    display_name="J Doe",
    email="j@x",
    dn="CN=jdoe,DC=x",
    groups=frozenset({"cn=mf-admins,dc=x"}),
    directory_object_id="guid-jdoe",
)


class _FakeLdap:
    """No AD exists in any test infra. ``binds`` proves no password reached the directory."""

    def __init__(self) -> None:
        self.binds: list[str] = []

    def authenticate(self, username: str, password: str, **_: object) -> DirectoryBind:
        self.binds.append(username)
        if username != "jdoe":
            return DirectoryBind(DirectoryAnswer.NOT_FOUND)
        return DirectoryBind(DirectoryAnswer.FOUND, _PRINCIPAL)

    def resolve_principal(
        self, username: str, *, object_id: str | None = None
    ) -> AdPrincipal | None:
        return _PRINCIPAL if username == "jdoe" else None


def _settings(*, require_mfa: bool = False) -> AuthSettings:
    return AuthSettings(
        oidc_callback_min_elapsed_seconds=0,
        require_mfa=require_mfa,
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
        ad_domain="corp.example",
        oidc_enabled=True,
        oidc_issuer="https://idp.example",
        oidc_client_id="mefor-console",
        oidc_client_secret="shhh",
        oidc_authorization_endpoint="https://idp.example/authorize",
        oidc_token_endpoint="https://idp.example/token",
        oidc_jwks_uri="https://idp.example/jwks",
        oidc_allowed_endpoints=["idp.example"],
    )


async def _service(engine: Engine, ldap: _FakeLdap, *, require_mfa: bool = False) -> AuthService:
    service = AuthService(  # type: ignore[arg-type]
        engine.store, _settings(require_mfa=require_mfa), ldap=ldap
    )
    await service.initialize()
    await service.set_ad_group_map([("cn=mf-admins,dc=x", "administrator")], actor="admin")
    user_id = uuid4().hex
    await service.store.create_user(
        user_id=user_id,
        username="jdoe",
        auth_provider="ad",
        directory_object_id="guid-jdoe",
        password_generated=False,
    )
    await service.bind_federated_subject(
        user_id, _SUB, expected_issuer=None, expected_subject=None, actor="admin"
    )
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, serve_ui=True, public_origin="https://ops.example")
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


def _idp_answers(
    service: AuthService, monkeypatch: pytest.MonkeyPatch, *, subject: str = _SUB
) -> None:
    """Replace the IdP round trip at the one seam the service calls. Everything after it is real."""

    def _exchange(*_a: object, **_k: object) -> FederatedPrincipal:
        now = time.time()
        return FederatedPrincipal(
            username="jdoe",
            subject=subject,
            issuer="https://idp.example",
            amr=("pwd", "mfa"),
            acr=None,
            expires_at=now + 600,
            auth_time=now,  # a fresh IdP sign-in: after the flow was staged
        )

    monkeypatch.setattr(service, "_exchange_and_validate", _exchange)


async def _callback(c: httpx.AsyncClient, location: str) -> httpx.Response:
    state = dict(parse_qsl(urlsplit(location).query))["state"]
    c.cookies.delete("mf_session")  # SameSite=Strict: withheld on the IdP's cross-site return
    return await c.get(
        "/ui/oidc/callback",
        params={"code": "authcode", "state": state},
        headers=_CROSS_SITE_NAV,
        follow_redirects=False,
    )


async def _federated_sign_in(
    service: AuthService, c: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> str:
    _idp_answers(service, monkeypatch)
    start = await c.post("/ui/oidc/start", headers=_SAME, follow_redirects=False)
    assert start.status_code == 303, start.headers
    r = await _callback(c, start.headers["location"])
    assert r.status_code == 200, r.headers
    token = c.cookies.get("mf_session")
    assert token and await service.session_steps_up_at_idp(token)
    return token


async def _start_step_up(c: httpx.AsyncClient) -> httpx.Response:
    return await c.post(
        "/ui/reauth/oidc", data={"next": _NEXT}, headers=_SAME, follow_redirects=False
    )


async def test_the_reauth_page_for_an_oidc_session_has_no_password_field(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine, _FakeLdap())
    async with _client(engine, service) as c:
        await _federated_sign_in(service, c, monkeypatch)
        r = await c.get("/ui/reauth", params={"next": _NEXT}, follow_redirects=False)
        assert r.status_code == 200
        assert 'action="/ui/reauth/oidc"' in r.text
        assert 'name="password"' not in r.text, "an OIDC session was offered a password step-up"


async def test_an_idp_mfa_session_with_no_engine_factor_is_not_sent_to_enroll(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the enroll-first bounce runs before the IdP branch. Under the shipped default,
    require_mfa is on, and an OIDC session minted with the IdP's MFA claim has met its factor
    without enrolling one in the engine, so it must reach the IdP leg, not the enrollment page."""
    service = await _service(engine, _FakeLdap(), require_mfa=True)
    async with _client(engine, service) as c:
        token = await _federated_sign_in(service, c, monkeypatch)
        assert await service.mfa_satisfied(token)
        r = await c.get("/ui/reauth", params={"next": _NEXT}, follow_redirects=False)
        assert r.status_code == 200, r.headers
        assert 'action="/ui/reauth/oidc"' in r.text


async def test_a_password_post_for_an_oidc_session_is_sent_to_the_idp_leg(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: POST /ui/reauth re-binds a password for an OIDC session. The directory would
    accept it, so a redirect here is the refusal and not a wrong password."""
    ldap = _FakeLdap()
    service = await _service(engine, ldap)
    async with _client(engine, service) as c:
        token = await _federated_sign_in(service, c, monkeypatch)
        r = await c.post(
            "/ui/reauth",
            data={"next": _NEXT, "password": "accepted-by-the-directory"},
            headers=_SAME,
            follow_redirects=False,
        )
        assert r.status_code == 303 and r.headers["location"].startswith("/ui/reauth?next=")
        assert ldap.binds == []
        assert not await service.has_recent_step_up(token)


async def test_the_json_reauth_names_the_idp_leg_for_an_oidc_session(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    ldap = _FakeLdap()
    service = await _service(engine, ldap)
    async with _client(engine, service) as c:
        token = await _federated_sign_in(service, c, monkeypatch)
        r = await c.post(
            "/me/reauth",
            json={"password": "accepted-by-the-directory"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403 and "/ui/reauth" in r.json()["detail"]
        assert ldap.binds == []


async def test_a_code_at_the_mfa_gate_for_a_satisfied_oidc_session_opens_nothing(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2142, ADR 0142 Amendment F: an OIDC session that already met its factor owes no
    code, and a code opens no window for it. POST /ui/mfa sends it to /ui, as the GET does for any
    satisfied session, with nothing rotated and no window opened."""
    service = await _service(engine, _FakeLdap())
    async with _client(engine, service) as c:
        token = await _federated_sign_in(service, c, monkeypatch)
        identity = await service.identity_for_token(token, activity=False)
        assert identity is not None and await service.mfa_satisfied(token)
        staged_cell = await service.store.set_totp_secret(
            identity.user_id, secret="JBSWY3DPEHPK3PXP"
        )
        assert await service.store.enable_totp(
            identity.user_id, expected_secret_cell=staged_cell, recovery_code_hashes=[]
        )
        r = await c.post("/ui/mfa", data={"code": "000000"}, headers=_SAME, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/ui", r.headers
        assert c.cookies.get("mf_session") == token, "nothing rotated, so the cookie must not move"
        assert await service.identity_for_token(token, activity=False) is not None
        assert not await service.has_recent_step_up(token)


async def test_a_fresh_idp_sign_in_steps_the_session_up(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine, _FakeLdap())
    async with _client(engine, service) as c:
        old = await _federated_sign_in(service, c, monkeypatch)
        issue_continuation(c, _NEXT)  # what the step-up gate's refusal of the click records
        start = await _start_step_up(c)
        assert start.status_code == 303
        query = dict(parse_qsl(urlsplit(start.headers["location"]).query))
        assert query["max_age"] == "0" and query["prompt"] == "login"

        r = await _callback(c, start.headers["location"])

        assert r.status_code == 200, r.text
        assert f'action="{_NEXT}"' in r.text  # the auto-retry of the action the operator started
        assert "data-autosubmit" in r.text and "Reload the engine configuration" in r.text
        new = c.cookies.get("mf_session")
        assert new and new != old
        assert await service.identity_for_token(old) is None
        assert await service.has_recent_step_up(new)
        assert await service.session_steps_up_at_idp(new), "rotation lost the mechanism"


async def test_an_unissued_next_steps_up_at_the_idp_and_continues_to_nothing(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #2764 on the federated leg: a ``next`` no step-up gate issued to this session
    still re-proves at the IdP, but the flow is staged for the console, so the callback lands there
    with no auto-submit."""
    service = await _service(engine, _FakeLdap())
    async with _client(engine, service) as c:
        await _federated_sign_in(service, c, monkeypatch)
        page = await c.get("/ui/reauth", params={"next": _NEXT}, follow_redirects=False)
        assert page.status_code == 200 and "nothing will run" in page.text
        start = await _start_step_up(c)
        assert start.status_code == 303

        r = await _callback(c, start.headers["location"])

        assert r.status_code == 200, r.text
        assert "data-autosubmit" not in r.text
        assert f'action="{_NEXT}"' not in r.text
        new = c.cookies.get("mf_session")
        assert new and await service.has_recent_step_up(new)


async def test_a_different_idp_account_is_refused_and_changes_nothing(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine, _FakeLdap())
    async with _client(engine, service) as c:
        token = await _federated_sign_in(service, c, monkeypatch)
        start = await _start_step_up(c)
        _idp_answers(service, monkeypatch, subject="S-1-5-21-someone-else")

        r = await _callback(c, start.headers["location"])

        assert r.status_code == 403
        assert "different account" in r.text
        assert 'name="password"' not in r.text
        assert await service.identity_for_token(token) is not None
        assert not await service.has_recent_step_up(token)


async def test_a_forged_callback_does_not_cancel_the_step_up_in_flight(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: a callback without the flow's own state consumes the flow or clears its cookie.
    The flow cookie is SameSite=Lax, so any page can send the browser to the callback."""
    service = await _service(engine, _FakeLdap())
    async with _client(engine, service) as c:
        await _federated_sign_in(service, c, monkeypatch)
        start = await _start_step_up(c)
        session = c.cookies.get("mf_session")
        c.cookies.delete("mf_session")
        forged = await c.get(
            "/ui/oidc/callback",
            params={"error": "access_denied", "state": "forged"},
            headers=_CROSS_SITE_NAV,
            follow_redirects=False,
        )
        assert forged.status_code == 403
        assert session is not None
        c.cookies.set("mf_session", session)
        real = await _callback(c, start.headers["location"])
        assert real.status_code == 200, real.text
        new = c.cookies.get("mf_session")
        assert new and await service.has_recent_step_up(new)


async def test_a_cancel_at_the_idp_returns_to_the_step_up_page(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine, _FakeLdap())
    async with _client(engine, service) as c:
        token = await _federated_sign_in(service, c, monkeypatch)
        start = await _start_step_up(c)
        state = dict(parse_qsl(urlsplit(start.headers["location"]).query))["state"]
        c.cookies.delete("mf_session")
        r = await c.get(
            "/ui/oidc/callback",
            params={"error": "access_denied", "state": state},
            headers=_CROSS_SITE_NAV,
            follow_redirects=False,
        )
        assert r.status_code == 403
        assert 'action="/ui/reauth/oidc"' in r.text
        assert "did not complete the confirmation" in r.text  # BACKLOG #3221: a step-up word
        assert await service.identity_for_token(token) is not None


def _flow_id(c: httpx.AsyncClient) -> str:
    """The flow cookie's value, under whichever of its prefixed names this origin uses."""
    value = next((v for k, v in c.cookies.items() if k.endswith("mf_oidc_flow")), None)
    assert value is not None, "the browser holds no flow cookie"
    return value


def _drain_sign_in_window(service: AuthService) -> None:
    """Spend the sign-in window's GLOBAL budget from many addresses, as a flood would. The sign-in
    before it already spent some, so the loop stops at the first refusal."""
    for i in range(_settings().login_rate_limit_global):
        if not service.allow_login_attempt(f"203.0.113.{i}"):
            break
    assert not service.allow_login_attempt("127.0.0.1"), "fixture: the window is not spent"


def _forbid_sign_in_charge(service: AuthService, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any charge of the sign-in window during the callback fail the test."""

    def _charged(_client: str | None) -> bool:
        raise AssertionError("a step-up return charged the sign-in window")

    monkeypatch.setattr(service, "allow_login_attempt", _charged)


def _ceremony_budget_left(service: AuthService, key: str) -> bool:
    """Whether the ceremony limiter would admit ``key``, read WITHOUT recording an attempt."""
    limiter = service._reauth_limiter
    assert limiter is not None
    return limiter.would_allow(key)


async def test_a_spent_sign_in_window_does_not_refuse_an_idp_step_up_return(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3374. RED when: the callback charges the sign-in window before it tells a step-up
    return from a sign-in. A flood that spends that window's global budget then refuses every IdP
    step-up return, while a password step-up, on the per-actor budget, keeps working."""
    service = await _service(engine, _FakeLdap())
    async with _client(engine, service) as c:
        old = await _federated_sign_in(service, c, monkeypatch)
        issue_continuation(c, _NEXT)
        start = await _start_step_up(c)
        assert start.status_code == 303
        _drain_sign_in_window(service)
        _forbid_sign_in_charge(service, monkeypatch)

        r = await _callback(c, start.headers["location"])

        assert r.status_code == 200, r.text
        assert f'action="{_NEXT}"' in r.text
        new = c.cookies.get("mf_session")
        assert new and new != old
        assert await service.has_recent_step_up(new)


async def test_an_idp_step_up_return_is_still_rate_limited_per_actor(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3374. RED when: the step-up return draws no budget at all once it left the sign-in
    window. It draws a per-user key of the ceremony limiter, and a spent key refuses it with a 429
    that writes no audit row and consumes nothing. That key is the return's own, so the user's
    other ceremonies keep their budget."""
    service = await _service(engine, _FakeLdap())
    async with _client(engine, service) as c:
        token = await _federated_sign_in(service, c, monkeypatch)
        identity = await service.identity_for_token(token)
        assert identity is not None
        issue_continuation(c, _NEXT)
        start = await _start_step_up(c)
        assert start.status_code == 303
        flow_id = _flow_id(c)
        return_key = _step_up_return_key(identity.user_id)
        for _ in range(_settings().login_rate_limit_per_ip):
            assert service.allow_reauth_attempt(return_key), "fixture: refused before the cap"
        assert not _ceremony_budget_left(service, return_key), "fixture: budget not spent"
        assert _ceremony_budget_left(service, identity.user_id)
        _forbid_sign_in_charge(service, monkeypatch)
        rows_before = await service.store.count_audit(limit=None)

        r = await _callback(c, start.headers["location"])

        assert r.status_code == 429, r.text
        assert "Too many attempts" in r.text
        assert "Reload the engine configuration" in r.text  # the action the operator started from
        assert 'action="/ui/reauth/oidc"' in r.text and 'name="password"' not in r.text
        assert "retry-after" not in r.headers
        assert await service.store.count_audit(limit=None) == rows_before
        assert await service.identity_for_token(token) is not None
        assert not await service.has_recent_step_up(token)
        assert _ceremony_budget_left(service, identity.user_id), "the user's own key was spent"
        # Nothing was consumed: the flow and its cookie wait for a retry of the real return.
        staged = service.oidc_step_up_flow(flow_id)
        assert staged is not None and staged.user_id == identity.user_id
        assert _flow_id(c) == flow_id
        monkeypatch.setattr(service, "_reauth_limiter", None)  # the budget refilled
        retry = await _callback(c, start.headers["location"])
        assert retry.status_code == 200, retry.text
        new = c.cookies.get("mf_session")
        assert new and await service.has_recent_step_up(new)


@pytest.mark.parametrize("flow_id", [b"not-a-live-flow", b"caf\xe9"])
async def test_a_return_naming_no_live_step_up_flow_still_draws_the_sign_in_window(
    engine: Engine, flow_id: bytes
) -> None:
    """BACKLOG #3374. RED when: a forged flow cookie reaches the ceremony budget, or a cookie the
    flow cache cannot key raises before any limiter. The callback reads the flow before it charges
    anything, so a non-ASCII id once answered an unthrottled 500 here."""
    service = await _service(engine, _FakeLdap())
    _drain_sign_in_window(service)
    names = (b"mf_oidc_flow", b"__Secure-mf_oidc_flow", b"__Host-mf_oidc_flow")
    cookie = b"; ".join(name + b"=" + flow_id for name in names)
    async with _client(engine, service) as c:
        r = await c.get(
            "/ui/oidc/callback",
            params={"code": "authcode", "state": "s"},
            headers=[
                (b"cookie", cookie),
                *((k.encode(), v.encode()) for k, v in _CROSS_SITE_NAV.items()),
            ],
            follow_redirects=False,
        )
    assert r.status_code == 303, r.text
    assert r.headers["location"] == "/ui/login?e=rate_limited"
