# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2610, limb 3: a directory sign-in that newly grants Administrator pages.

The directory can make an account an Administrator by adding it to a group already mapped to that
role. The sign-in's role sync wrote ``auth.ad_roles_resynced`` and notified the holder, but raised
no ``administrator_granted`` alert, so the one page every other Administrator grant raises was
missing here. ``auth/`` raises no alert (CLAUDE.md section 4), so the sync reports what it gained on
``LoginOutcome.roles_gained`` and each sign-in route raises the alert.

This file drives ``POST /auth/negotiate``. The console's two routes, ``GET /ui/sso`` and the
``/ui/oidc`` callback, are driven in
``packaging/messagefoundry-webconsole/tests/test_ui_directory_admin_alert.py``.
"""

from __future__ import annotations

import base64
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.security import DIRECTORY_GRANTED_BY
from messagefoundry.auth import Role
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService, RolesGained, _BindingChangedMidLogin
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alerts import LoggingAlertSink

ADMINS = "cn=mf-admins,dc=x"
OPERATORS = "cn=mf-operators,dc=x"
_NEGOTIATE = {"Authorization": "Negotiate " + base64.b64encode(b"tok").decode()}
_GRANT = (
    "administrator_granted",
    "user:jdoe",
    {"via": "directory_sign_in_negotiate", "granted_by": DIRECTORY_GRANTED_BY},
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "directory_admin_alert.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


class _Sink(LoggingAlertSink):
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def administrator_granted(self, name: str, *, via: str, granted_by: str) -> None:
        self.events.append(("administrator_granted", name, {"via": via, "granted_by": granted_by}))


def _object_id(username: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, username))


class _FakeLdap:
    """A directory whose ``jdoe`` sits in whichever groups the test names."""

    def __init__(self, groups: frozenset[str]) -> None:
        self.groups = groups

    def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
        return AdPrincipal(
            username=username,
            display_name="J Doe",
            email=None,
            dn=f"CN={username},DC=x",
            groups=self.groups,
            directory_object_id=_object_id(username),
        )


async def _service(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, groups: frozenset[str]
) -> AuthService:
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "jdoe")
    settings = AuthSettings(
        ad_enabled=True,
        kerberos_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
        login_rate_limit_enabled=False,
        require_mfa=False,
    )
    service = AuthService(engine.store, settings, ldap=_FakeLdap(groups))  # type: ignore[arg-type]
    await service.initialize()
    await engine.store.set_ad_group_role_map(
        [(ADMINS, Role.ADMINISTRATOR.value), (OPERATORS, Role.OPERATOR.value)]
    )
    return service


async def _existing_directory_account(engine: Engine, *roles: Role) -> None:
    """The mirror row an earlier sign-in would have left, holding ``roles``. Called after
    :func:`_service`, whose ``initialize`` seeds the role rows the assignment refers to."""
    user_id = uuid.uuid4().hex
    await engine.store.create_user(
        user_id=user_id,
        username="jdoe",
        auth_provider="ad",
        directory_object_id=_object_id("jdoe"),
        password_generated=False,
    )
    await engine.store.set_user_roles(user_id, [r.value for r in roles], assigned_by="ad-sync")


def _client(engine: Engine, service: AuthService, sink: _Sink) -> httpx.AsyncClient:
    app = create_app(engine, auth=service)
    app.state.notifier = sink
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _negotiate(c: httpx.AsyncClient) -> httpx.Response:
    return await c.post("/auth/negotiate", headers=_NEGOTIATE)


async def test_a_first_sign_in_that_yields_administrator_raises_exactly_one_alert(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the negotiate route stops reading ``roles_gained``, or the sync stops setting it."""
    service = await _service(engine, monkeypatch, frozenset({ADMINS}))
    sink = _Sink()
    async with _client(engine, service, sink) as c:
        r = await _negotiate(c)
        assert r.status_code == 200, r.text
    assert sink.events == [_GRANT]


async def test_a_directory_promotion_of_an_existing_account_raises_the_alert(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The case the row names: the directory added a known operator to the admin group."""
    service = await _service(engine, monkeypatch, frozenset({ADMINS, OPERATORS}))
    await _existing_directory_account(engine, Role.OPERATOR)
    sink = _Sink()
    async with _client(engine, service, sink) as c:
        r = await _negotiate(c)
        assert r.status_code == 200, r.text
    assert sink.events == [_GRANT]


async def test_an_account_that_already_held_administrator_raises_none(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a returning Administrator's sign-in gains nothing, so it must not page."""
    service = await _service(engine, monkeypatch, frozenset({ADMINS}))
    await _existing_directory_account(engine, Role.ADMINISTRATOR)
    sink = _Sink()
    async with _client(engine, service, sink) as c:
        r = await _negotiate(c)
        assert r.status_code == 200, r.text
        # And a second sign-in by the account the first one made pages nothing either.
        r = await _negotiate(c)
        assert r.status_code == 200, r.text
    assert sink.events == []


async def test_a_sign_in_that_gains_only_a_non_admin_role_raises_none(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine, monkeypatch, frozenset({OPERATORS}))
    sink = _Sink()
    async with _client(engine, service, sink) as c:
        r = await _negotiate(c)
        assert r.status_code == 200, r.text
    assert sink.events == []


async def test_a_non_admin_gain_is_reported_and_a_repeat_sign_in_reports_none(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gain IS reported whatever the role; it is the route that decides only Administrator
    pages. A second sign-in gained nothing, so it reports nothing."""
    service = await _service(engine, monkeypatch, frozenset({OPERATORS}))
    first = await service.authenticate_kerberos(b"tok")
    assert first.ok
    assert first.roles_gained == RolesGained("jdoe", frozenset({Role.OPERATOR.value}))
    second = await service.authenticate_kerberos(b"tok")
    assert second.ok and second.roles_gained is None


async def test_the_outcome_names_the_account_and_only_the_roles_it_gained(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine, monkeypatch, frozenset({ADMINS, OPERATORS}))
    await _existing_directory_account(engine, Role.OPERATOR)
    outcome = await service.authenticate_kerberos(b"tok")
    assert outcome.ok
    assert outcome.roles_gained == RolesGained("jdoe", frozenset({Role.ADMINISTRATOR.value}))


async def test_a_sign_in_refused_after_the_sync_still_raises_the_alert(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bind landing between the role write and the mint refuses the session, but the role was
    written all the same. A later sign-in would gain nothing, so this refusal is the one chance to
    page."""
    service = await _service(engine, monkeypatch, frozenset({ADMINS}))

    async def _bind_landed(*_a: object, **_k: object) -> str:
        raise _BindingChangedMidLogin

    monkeypatch.setattr(service, "_issue_session", _bind_landed)
    sink = _Sink()
    async with _client(engine, service, sink) as c:
        r = await _negotiate(c)
        assert r.status_code == 401, r.text
    assert sink.events == [_GRANT]
    jdoe = await engine.store.get_user_by_username("jdoe")
    assert jdoe is not None
    assert Role.ADMINISTRATOR.value in await engine.store.get_user_role_ids(jdoe.id)


class _RaisingSink(_Sink):
    def administrator_granted(self, name: str, *, via: str, granted_by: str) -> None:
        raise RuntimeError("sink broke its never-raise contract")


async def test_a_sink_that_raises_does_not_break_the_sign_in(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the try/except in ``alert_administrator_granted`` goes. The sign-in must still
    succeed: a 500 here would leave the role written and the retry gaining nothing to page on."""
    service = await _service(engine, monkeypatch, frozenset({ADMINS}))
    async with _client(engine, service, _RaisingSink()) as c:
        r = await _negotiate(c)
        assert r.status_code == 200, r.text
