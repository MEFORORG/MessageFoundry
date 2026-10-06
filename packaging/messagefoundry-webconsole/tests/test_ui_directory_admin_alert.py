# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2610, limb 3, the console half: the two console directory sign-in routes page.

``GET /ui/sso`` and the ``/ui/oidc`` callback complete a directory sign-in exactly as the engine's
``POST /auth/negotiate`` does, so each must raise ``administrator_granted`` when the sign-in's role
sync newly gives the account the Administrator role, raise it when the sign-in is refused after the
role write, and raise nothing when it already held it. The engine route, the non-admin control and
the engine's refused-after-sync case are in ``tests/test_directory_sign_in_admin_alert.py``.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

import httpx
import pytest
from _ui_clients import SAME_ORIGIN as _SAME

from messagefoundry.api import create_app
from messagefoundry.api.security import DIRECTORY_GRANTED_BY
from messagefoundry.auth import Role
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.oidc import FederatedPrincipal
from messagefoundry.auth.service import AuthService, _BindingChangedMidLogin
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alerts import LoggingAlertSink

ADMINS = "cn=mf-admins,dc=x"
_OBJECT_ID = "guid-jdoe"
_SUBJECT = "S-1-5-21-fed"
_PRINCIPAL = AdPrincipal(
    username="jdoe",
    display_name="J Doe",
    email="j@x",
    dn="CN=jdoe,DC=x",
    groups=frozenset({ADMINS}),
    directory_object_id=_OBJECT_ID,
)


class _FakeLdap:
    def resolve_principal(
        self, username: str, *, object_id: str | None = None
    ) -> AdPrincipal | None:
        return _PRINCIPAL if username == "jdoe" else None


class _Sink(LoggingAlertSink):
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def administrator_granted(self, name: str, *, via: str, granted_by: str) -> None:
        self.events.append(("administrator_granted", name, {"via": via, "granted_by": granted_by}))


def _grant(via: str) -> tuple[str, str, dict[str, Any]]:
    return ("administrator_granted", "user:jdoe", {"via": via, "granted_by": DIRECTORY_GRANTED_BY})


async def _service(engine: Engine, *, held: Role | None, bind: bool) -> AuthService:
    """A directory-backed service whose ``jdoe`` already has a mirror row holding ``held`` (or no
    role). ``bind`` binds it to the federated subject, which the OIDC leg needs to select it (ADR
    0184) and which the Windows SSO leg refuses before its role sync (vault BACKLOG #2609)."""
    settings = AuthSettings(
        require_mfa=False,
        ad_enabled=True,
        kerberos_enabled=True,
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
        oidc_callback_min_elapsed_seconds=0,
    )
    service = AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()
    await service.set_ad_group_map([(ADMINS, Role.ADMINISTRATOR.value)], actor="admin")
    user_id = uuid4().hex
    await engine.store.create_user(
        user_id=user_id,
        username="jdoe",
        auth_provider="ad",
        directory_object_id=_OBJECT_ID,
        password_generated=False,
    )
    if held is not None:
        await engine.store.set_user_roles(user_id, [held.value], assigned_by="ad-sync")
    if bind:
        await service.bind_federated_subject(
            user_id, _SUBJECT, expected_issuer=None, expected_subject=None, actor="admin"
        )
    return service


def _client(engine: Engine, service: AuthService, sink: _Sink) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, serve_ui=True, public_origin="https://ops.example")
    app.state.notifier = sink
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _sso(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    *,
    held: Role | None,
    bind_lands_mid_login: bool = False,
) -> _Sink:
    """``bind_lands_mid_login`` makes the mint fail after the role write, as in :func:`_oidc`."""
    service = await _service(engine, held=held, bind=False)
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "jdoe")
    if bind_lands_mid_login:

        async def _bind_landed(*_a: object, **_k: object) -> str:
            raise _BindingChangedMidLogin

        monkeypatch.setattr(service, "_issue_session", _bind_landed)
    sink = _Sink()
    async with _client(engine, service, sink) as c:
        r = await c.get("/ui/sso", headers={"Authorization": "Negotiate c3BuZWdvLXRva2Vu"})
    expected = "/ui/login?e=sso_failed" if bind_lands_mid_login else "/ui"
    assert r.status_code == 303 and r.headers["location"] == expected, r.headers
    return sink


async def _oidc(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    *,
    held: Role | None,
    bind_lands_mid_login: bool = False,
) -> _Sink:
    """``bind_lands_mid_login`` makes the mint fail as an admin unbind landing after the role write
    would, so the callback refuses the sign-in after the grant was written."""
    service = await _service(engine, held=held, bind=True)
    if bind_lands_mid_login:

        async def _bind_landed(*_a: object, **_k: object) -> str:
            raise _BindingChangedMidLogin

        monkeypatch.setattr(service, "_issue_session", _bind_landed)

    def _exchange(*_a: object, **_k: object) -> FederatedPrincipal:
        return FederatedPrincipal(
            username="jdoe",
            subject=_SUBJECT,
            issuer="https://idp.example",
            amr=("pwd", "mfa"),
            acr=None,
            expires_at=time.time() + 600,
            auth_time=time.time(),
        )

    monkeypatch.setattr(service, "_exchange_and_validate", _exchange)
    sink = _Sink()
    async with _client(engine, service, sink) as c:
        start = await c.post("/ui/oidc/start", headers=_SAME, follow_redirects=False)
        assert start.status_code == 303, start.headers
        state = dict(parse_qsl(urlsplit(start.headers["location"]).query))["state"]
        r = await c.get(
            "/ui/oidc/callback",
            params={"code": "authcode", "state": state},
            headers={
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            },
            follow_redirects=False,
        )
        if bind_lands_mid_login:
            assert r.status_code == 303 and r.headers["location"].startswith("/ui/login?e=")
        else:
            assert r.status_code == 200, r.headers
    return sink


async def test_ui_sso_that_newly_grants_administrator_raises_one_alert(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = await _sso(engine, monkeypatch, held=Role.OPERATOR)
    assert sink.events == [_grant("directory_sign_in_sso")]


async def test_ui_sso_by_an_existing_administrator_raises_none(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = await _sso(engine, monkeypatch, held=Role.ADMINISTRATOR)
    assert sink.events == []


async def test_ui_sso_refused_after_the_role_write_still_raises_the_alert(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the alert call moves below the ``if not outcome.ok`` redirect. The role was written
    before the mint failed, and a later sign-in gains nothing, so this refusal is the one chance to
    page."""
    sink = await _sso(engine, monkeypatch, held=Role.OPERATOR, bind_lands_mid_login=True)
    assert sink.events == [_grant("directory_sign_in_sso")]


async def test_ui_oidc_that_newly_grants_administrator_raises_one_alert(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = await _oidc(engine, monkeypatch, held=None)
    assert sink.events == [_grant("directory_sign_in_oidc")]


async def test_ui_oidc_by_an_existing_administrator_raises_none(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = await _oidc(engine, monkeypatch, held=Role.ADMINISTRATOR)
    assert sink.events == []


async def test_ui_oidc_refused_after_the_role_write_still_raises_the_alert(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The federated arm of the refused-after-sync path: the role was written before the mint
    failed, and a later sign-in gains nothing, so this refusal is the one chance to page."""
    sink = await _oidc(engine, monkeypatch, held=None, bind_lands_mid_login=True)
    assert sink.events == [_grant("directory_sign_in_oidc")]
