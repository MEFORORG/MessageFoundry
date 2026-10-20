# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3401 (ASVS 7.5.2) on the console plane: the four group-wide saves.

``/ui/ad-groups/map``, ``/ui/ad-groups/scope-map``, ``/ui/roles/custom/{id}/update`` and
``/ui/roles/custom/{id}/delete`` end the sessions of every account they reach. A save that reaches
the caller's own account now spends the single-use ``save_ends_own_sessions`` grant, which a
re-auth toward the route's tagged continuation mints, and lands on the sign-in page once the save
ended the caller's session. Any other save keeps the window. Per route: an unaffected caller with
no live window is sent to re-auth (a), an affected caller with a live window and no grant is sent
to re-auth (b), and an affected caller with the grant saves and lands on sign-in (c). The JSON
twin is ``tests/test_group_save_step_up.py``.

The AD maps reach every enabled directory account, so the affected caller is a directory
Administrator signed in through ``/ui/sso``; a custom role reaches its holders.
"""

from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass
from urllib.parse import quote

import httpx
import pytest
from _ui_clients import PW, SAME_ORIGIN, cookie_login, mint_bound_proof, provision
from _webui_support import _client

from messagefoundry.auth import Role
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryBind
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

AD_PW = "directory-pw"
ADMINS = "cn=mf-admins,dc=x"
GROUP = "CN=Lab-Ops,OU=Groups,DC=example,DC=invalid"
LANDING = "/ui/login?e=own_sessions_ended"


def _principal(username: str) -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name=None,
        email=None,
        dn=f"CN={username},DC=x",
        groups=frozenset({ADMINS}),
        directory_object_id=str(uuid.uuid5(uuid.NAMESPACE_URL, username)),
    )


class _FakeLdap:
    def authenticate(self, username: str, password: str, **_: object) -> DirectoryBind:
        return DirectoryBind(
            DirectoryAnswer.FOUND, _principal(username) if password == AD_PW else None
        )

    def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
        return _principal(username)


async def _service(engine: Engine) -> AuthService:
    settings = AuthSettings(
        ad_enabled=True,
        kerberos_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
        login_rate_limit_enabled=False,
        admin_write_min_interval_seconds=0,
        require_mfa=False,
    )
    service = AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()
    await engine.store.set_ad_group_role_map([(ADMINS, Role.ADMINISTRATOR.value)])
    return service


def _cookie(c: httpx.AsyncClient) -> str:
    token = c.cookies.get("mf_session")
    assert token, "no session cookie"
    return token


async def _sso_login(c: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """A directory Administrator's cookie session. Born with no window (BACKLOG #1144)."""
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda t, s: "jdoe")
    r = await c.get(
        "/ui/sso",
        headers={"Authorization": "Negotiate " + base64.b64encode(b"spnego").decode()},
    )
    assert r.status_code == 303, r.text


@dataclass
class _Case:
    route: str
    #: True for the AD maps: the affected caller signs in through the directory.
    directory: bool

    async def setup(self, service: AuthService) -> str | None:
        if self.directory:
            return None
        role = await service.create_custom_role(
            display_name="Lab readers", description=None, permissions=["messages:read"], actor="t"
        )
        return role.id

    def post(self, role_id: str | None) -> tuple[str, dict[str, str]]:
        if self.route == "map":
            return "/ui/ad-groups/map", {"ad_group": GROUP, "role": "operator"}
        if self.route == "scope-map":
            return "/ui/ad-groups/scope-map", {"ad_group": GROUP, "channel": "IB_A"}
        if self.route == "role-update":
            form = {"display_name": "Lab readers 2", "permissions": "messages:read"}
            return f"/ui/roles/custom/{role_id}/update", form
        return f"/ui/roles/custom/{role_id}/delete", {}

    def continuation(self, role_id: str | None) -> str:
        """The page a stale request is sent back to, whose re-auth mints the grant."""
        if self.directory:
            return "/ui/ad-groups"
        if self.route == "role-update":
            return f"/ui/roles/{role_id}/edit"
        return f"/ui/roles/custom/{role_id}/delete"

    def done(self) -> str:
        return "/ui/ad-groups" if self.directory else "/ui/roles"

    async def saved(self, service: AuthService, role_id: str | None) -> bool:
        if self.route == "map":
            return any(g == GROUP.lower() for g, _r in await service.list_ad_group_role_map())
        if self.route == "scope-map":
            return any(g == GROUP.lower() for g, _c in await service.list_ad_group_scope_map())
        roles = {r.id: r for r in await service.list_custom_roles()}
        if self.route == "role-update":
            return roles[str(role_id)].display_name == "Lab readers 2"
        return role_id not in roles


CASES = [
    _Case("map", directory=True),
    _Case("scope-map", directory=True),
    _Case("role-update", directory=False),
    _Case("role-delete", directory=False),
]
IDS = [c.route for c in CASES]


def _reauth_location(case: _Case, role_id: str | None) -> str:
    return "/ui/reauth?next=" + quote(case.continuation(role_id), safe="/")


async def _sign_in_affected(
    c: httpx.AsyncClient,
    case: _Case,
    service: AuthService,
    role_id: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> str:
    """Sign in a caller whose own sessions the save ends; returns the password it re-proves with."""
    if case.directory:
        await _sso_login(c, monkeypatch)
        return AD_PW
    await provision(service, "holder", [Role.ADMINISTRATOR.value, str(role_id)])
    await cookie_login(c, "holder")
    return PW


@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_a_an_unaffected_save_with_a_lapsed_window_goes_to_re_auth(
    engine: Engine, case: _Case
) -> None:
    """(a) RED when: the gate's unaffected branch stops checking the window."""
    service = await _service(engine)
    role_id = await case.setup(service)
    me = await provision(service, "root", [Role.ADMINISTRATOR.value])
    path, form = case.post(role_id)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        ended = (
            await service.sessions_ended_by_ad_map_save()
            if case.directory
            else await service.sessions_ended_by_custom_role_save(str(role_id))
        )
        assert me not in ended, "the control caller is affected, so this tests the other branch"
        await engine.store.mark_session_reauthed(hash_token(_cookie(c)), now=0.0)
        r = await c.post(path, data=form, headers=SAME_ORIGIN)
        assert r.status_code == 303, r.text
        assert r.headers["location"] == _reauth_location(case, role_id)
        assert not await case.saved(service, role_id)

        # The control: a live window saves, with no grant, and the session stays.
        await engine.store.mark_session_reauthed(hash_token(_cookie(c)), now=time.time())
        r = await c.post(path, data=form, headers=SAME_ORIGIN)
        assert r.status_code == 303, r.text
        assert r.headers["location"] == case.done()
        assert await case.saved(service, role_id)
        assert await service.identity_for_token(_cookie(c), activity=False) is not None


@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_b_an_affected_save_with_only_the_window_goes_to_re_auth(
    engine: Engine, case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(b) RED when: a save that ends the caller's own sessions takes the window again."""
    service = await _service(engine)
    role_id = await case.setup(service)
    path, form = case.post(role_id)
    async with _client(engine, service) as c:
        await _sign_in_affected(c, case, service, role_id, monkeypatch)
        await engine.store.mark_session_reauthed(hash_token(_cookie(c)), now=time.time())
        assert await service.has_recent_step_up(_cookie(c)) is True  # the window is live
        r = await c.post(path, data=form, headers=SAME_ORIGIN)
        assert r.status_code == 303, r.text
        assert r.headers["location"] == _reauth_location(case, role_id)
        assert not await case.saved(service, role_id)
        assert await service.identity_for_token(_cookie(c), activity=False) is not None


@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_c_an_affected_save_with_the_grant_lands_on_sign_in(
    engine: Engine, case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(c) RED when: the re-auth toward the route's continuation stops minting the grant, the
    grant stops admitting the save, or the console reads the session the save ended."""
    service = await _service(engine)
    role_id = await case.setup(service)
    path, form = case.post(role_id)
    async with _client(engine, service) as c:
        password = await _sign_in_affected(c, case, service, role_id, monkeypatch)
        # Through the real refusal, so the continuation is the one the gate issued.
        r = await c.post(path, data=form, headers=SAME_ORIGIN)
        assert r.headers["location"] == _reauth_location(case, role_id)
        r = await c.post(
            "/ui/reauth",
            data={"next": case.continuation(role_id), "password": password},
            headers=SAME_ORIGIN,
        )
        assert r.status_code in (200, 303), r.text
        token = _cookie(c)
        r = await c.post(path, data=form, headers=SAME_ORIGIN)
        assert r.status_code == 303, r.text
        assert r.headers["location"] == LANDING
        assert "clear-site-data" in r.headers
        assert await case.saved(service, role_id)
        assert await service.identity_for_token(token, activity=False) is None
        landing = await c.get(LANDING)
        assert landing.status_code == 200
        assert "The change ended your own sessions" in landing.text


async def test_a_holder_proof_minted_by_the_helper_also_admits_the_delete(engine: Engine) -> None:
    """The shared fixture path: ``mint_bound_proof`` toward the delete's own continuation."""
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="Lab readers", description=None, permissions=["messages:read"], actor="t"
    )
    await provision(service, "holder", [Role.ADMINISTRATOR.value, role.id])
    async with _client(engine, service) as c:
        await cookie_login(c, "holder")
        await mint_bound_proof(c, f"/ui/roles/custom/{role.id}/delete")
        r = await c.post(f"/ui/roles/custom/{role.id}/delete", headers=SAME_ORIGIN)
        assert r.status_code == 303 and r.headers["location"] == LANDING
    assert role.id not in {r.id for r in await service.list_custom_roles()}
