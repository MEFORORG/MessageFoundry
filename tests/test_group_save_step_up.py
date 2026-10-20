# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3401 (ASVS 7.5.2, a #1149 follow-up) on the JSON plane: the four group-wide saves.

``PUT /ad-group-map``, ``PUT /ad-group-scope-map``, ``PUT /roles/custom/{id}`` and
``DELETE /roles/custom/{id}`` end the sessions of every account they reach. Before this, each took
the login window, so a save that reached the caller's own account was a mass terminate with no
fresh proof. Now such a save spends the single-use ``save_ends_own_sessions`` grant, and any other
save keeps the window. For each route this pins three cases: an unaffected caller with no live
window is refused (a), an affected caller with a live window and no grant is refused (b), and an
affected caller with the grant saves and loses its own session cleanly (c). The console plane is
``packaging/messagefoundry-webconsole/tests/test_ui_group_save_step_up.py``.

The AD maps reach every enabled directory account, so the affected caller is a directory
Administrator signed in through Kerberos, and the unaffected one a local Administrator. A custom
role reaches its holders, so the affected caller holds the role beside Administrator.
"""

from __future__ import annotations

import ast
import base64
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryBind
from messagefoundry.auth.service import (
    STEP_UP_ACTION_SAVE_ENDS_OWN_SESSIONS,
    STEP_UP_ACTION_SESSION_TERMINATE,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen
from tests.test_api_auth import PW, _clear_must_change
from tests.test_mfa_access_gate import _enroll_totp_out_of_band

ACTION = STEP_UP_ACTION_SAVE_ENDS_OWN_SESSIONS
AD_PW = "directory-pw"
ADMINS = "cn=mf-admins,dc=x"
GROUP = "CN=Lab-Ops,OU=Groups,DC=example,DC=invalid"


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "group_save.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


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
    """``authenticate`` is the live re-bind ``POST /me/reauth`` makes for a directory account."""

    def authenticate(self, username: str, password: str, **_: object) -> DirectoryBind:
        return DirectoryBind(
            DirectoryAnswer.FOUND, _principal(username) if password == AD_PW else None
        )

    def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
        return _principal(username)


async def _service(engine: Engine, **overrides: Any) -> AuthService:
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
        **overrides,
    )
    service = AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
    await service.initialize()
    await engine.store.set_ad_group_role_map([(ADMINS, Role.ADMINISTRATOR.value)])
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service), client=("127.0.0.1", 123))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _local(service: AuthService, username: str, roles: list[str]) -> str:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=roles,
        actor="test",
    )
    await _clear_must_change(service, user_id)
    return user_id


async def _local_login(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def _directory_login(c: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> str:
    """A directory Administrator's session, through ``POST /auth/negotiate``. Born with no window
    (BACKLOG #1144)."""
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda t, s: "jdoe")
    r = await c.post(
        "/auth/negotiate",
        headers={"Authorization": "Negotiate " + base64.b64encode(b"tok").decode()},
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def _reauth(
    c: httpx.AsyncClient, token: str, password: str, purpose: str | None = None
) -> str:
    body = {"password": password} if purpose is None else {"password": password, "purpose": purpose}
    r = await c.post("/me/reauth", json=body, headers=_auth(token))
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


@dataclass
class _Case:
    """One route, with the request it makes and how to read whether it saved."""

    route: str
    method: str
    #: True for the AD maps: the affected caller signs in through the directory.
    directory: bool

    async def setup(self, service: AuthService) -> str | None:
        """Build the custom role the role routes act on; returns its id."""
        if self.directory:
            return None
        role = await service.create_custom_role(
            display_name="Lab readers", description=None, permissions=["messages:read"], actor="t"
        )
        return role.id

    def request(self, role_id: str | None) -> tuple[str, str, Any]:
        if self.route == "ad-group-map":
            return "PUT", "/ad-group-map", {"entries": [{"ad_group": GROUP, "role": "operator"}]}
        if self.route == "ad-group-scope-map":
            return (
                "PUT",
                "/ad-group-scope-map",
                {"entries": [{"ad_group": GROUP, "channel": "IB_A"}]},
            )
        body = {"display_name": "Lab readers 2", "permissions": ["messages:read"]}
        if self.route == "role-update":
            return "PUT", f"/roles/custom/{role_id}", body
        return "DELETE", f"/roles/custom/{role_id}", None

    async def saved(self, engine: Engine, service: AuthService, role_id: str | None) -> bool:
        if self.route == "ad-group-map":
            return any(g == GROUP.lower() for g, _r in await service.list_ad_group_role_map())
        if self.route == "ad-group-scope-map":
            return any(g == GROUP.lower() for g, _c in await service.list_ad_group_scope_map())
        roles = {r.id: r for r in await service.list_custom_roles()}
        if self.route == "role-update":
            return roles[str(role_id)].display_name == "Lab readers 2"
        return role_id not in roles


CASES = [
    _Case("ad-group-map", "PUT", directory=True),
    _Case("ad-group-scope-map", "PUT", directory=True),
    _Case("role-update", "PUT", directory=False),
    _Case("role-delete", "DELETE", directory=False),
]
IDS = [c.route for c in CASES]


async def _affected(
    c: httpx.AsyncClient,
    case: _Case,
    service: AuthService,
    role_id: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[str, str]:
    """A signed-in caller whose own sessions the save ends, and the password it re-proves with."""
    if case.directory:
        return await _directory_login(c, monkeypatch), AD_PW
    await _local(service, "holder", [Role.ADMINISTRATOR.value, str(role_id)])
    return await _local_login(c, "holder"), PW


@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_a_an_unaffected_save_with_a_lapsed_window_is_refused(
    engine: Engine, case: _Case
) -> None:
    """(a) RED when: the unaffected branch stops checking the window. ``proof_in_route`` drops the
    gate's own window check, so without ``refuse_unless_step_up_window_live`` a local
    Administrator whose window lapsed would save with no step-up at all."""
    service = await _service(engine)
    role_id = await case.setup(service)
    await _local(service, "root", [Role.ADMINISTRATOR.value])
    method, path, body = case.request(role_id)
    async with _client(engine, service) as c:
        tok = await _local_login(c, "root")
        me = await engine.store.get_user_by_username("root")
        assert me is not None
        assert me.id not in (
            await service.sessions_ended_by_ad_map_save()
            if case.directory
            else await service.sessions_ended_by_custom_role_save(str(role_id))
        ), "the control caller is affected, so this would test the other branch"
        await engine.store.mark_session_reauthed(hash_token(tok), now=0.0)  # lapse the window
        r = await c.request(method, path, json=body, headers=_auth(tok))
        assert r.status_code == 403, r.text
        assert r.headers.get("X-Step-Up-Required") == "1"
        # The window refusal, not the bound one: a plain POST /me/reauth clears it.
        assert "X-Step-Up-Action" not in r.headers
        assert not await case.saved(engine, service, role_id)

        # The control: the same caller with a live window saves with no grant.
        tok = await _reauth(c, tok, PW)
        r = await c.request(method, path, json=body, headers=_auth(tok))
        assert r.status_code == 200, r.text
        assert await case.saved(engine, service, role_id)
        assert (await c.get("/auth/me", headers=_auth(tok))).status_code == 200


@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_b_an_affected_save_with_only_the_window_is_refused(
    engine: Engine, case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(b) RED when: a save that ends the caller's own sessions takes the window again. The window
    is live here, so only the bound grant can tell the two apart. A ``session_terminate`` grant
    must not pass either: that one is minted for ``DELETE /me/sessions``."""
    service = await _service(engine)
    role_id = await case.setup(service)
    method, path, body = case.request(role_id)
    async with _client(engine, service) as c:
        tok, password = await _affected(c, case, service, role_id, monkeypatch)
        for purpose in (None, STEP_UP_ACTION_SESSION_TERMINATE):
            tok = await _reauth(c, tok, password, purpose)
            assert await service.has_recent_step_up(tok) is True  # the window is live
            r = await c.request(method, path, json=body, headers=_auth(tok))
            assert r.status_code == 403, (purpose, r.text)
            assert r.headers.get("X-Step-Up-Action") == ACTION
            assert not await case.saved(engine, service, role_id)
            assert (await c.get("/auth/me", headers=_auth(tok))).status_code == 200


@pytest.mark.parametrize("case", CASES, ids=IDS)
async def test_c_an_affected_save_with_the_grant_saves_and_ends_the_session(
    engine: Engine, case: _Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(c) RED when: the bound grant stops admitting the save, or the save stops ending the
    caller's own session (BACKLOG #1154 needs it ended), or the response reads the dead session."""
    service = await _service(engine)
    role_id = await case.setup(service)
    method, path, body = case.request(role_id)
    async with _client(engine, service) as c:
        tok, password = await _affected(c, case, service, role_id, monkeypatch)
        tok = await _reauth(c, tok, password, ACTION)
        r = await c.request(method, path, json=body, headers=_auth(tok))
        assert r.status_code == 200, r.text
        assert await case.saved(engine, service, role_id)
        assert (await c.get("/auth/me", headers=_auth(tok))).status_code == 401


async def test_a_pending_sessions_password_re_proof_mints_no_grant(engine: Engine) -> None:
    """The owner's #1149 Reading B: an MFA-pending password re-proof does not count as
    authenticating again. A password holder on a pending session of an enrolled holder of the role
    re-proves for the save; no grant is minted, and the save is refused at the MFA gate."""
    service = await _service(engine, mfa_verify_min_elapsed_seconds=0)
    role = await service.create_custom_role(
        display_name="Lab readers", description=None, permissions=["messages:read"], actor="t"
    )
    await _local(service, "holder", [Role.ADMINISTRATOR.value, role.id])
    await _enroll_totp_out_of_band(service, "holder")
    async with _client(engine, service) as c:
        tok = await _local_login(c, "holder")
        assert await service.mfa_satisfied(tok) is False
        tok = await _reauth(c, tok, PW, ACTION)
        assert await service.holds_action_step_up(tok, ACTION) is False
        r = await c.delete(f"/roles/custom/{role.id}", headers=_auth(tok))
        assert r.status_code == 403, r.text
        assert r.headers.get("X-MFA-Required") == "1"
    assert role.id in {r.id for r in await service.list_custom_roles()}


async def test_the_check_reads_the_set_the_revoke_ends(engine: Engine) -> None:
    """The route's question and the revoke's answer come from one enumeration. A disabled
    directory account is in neither; a local account is in neither AD set."""
    service = await _service(engine)
    for user_id, provider in (("ada", "ad"), ("dis", "ad"), ("len", "local")):
        await engine.store.create_user(
            user_id=user_id, username=user_id, auth_provider=provider, password_generated=False
        )
    await engine.store.set_user_disabled("dis", disabled=True)
    assert await service.sessions_ended_by_ad_map_save() == frozenset({"ada"})
    assert await service._ad_session_targets() == ["ada"]


_ROUTES = {
    "set_ad_group_map",
    "set_ad_group_scope_map",
    "update_custom_role",
    "delete_custom_role",
}


def test_each_route_proves_before_it_saves() -> None:
    """RED when: one of the four routes reaches its core before ``_prove_group_save``, or reads
    anything before it but the set of accounts its save ends."""
    source = Path(__file__).resolve().parents[1] / "messagefoundry" / "api" / "auth_routes.py"
    found: set[str] = set()
    for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.AsyncFunctionDef) or node.name not in _ROUTES:
            continue
        found.add(node.name)
        # Per top-level statement of the body, in source order (ast.walk is breadth-first).
        calls = [
            {
                n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", "")
                for n in ast.walk(stmt)
                if isinstance(n, ast.Call)
            }
            for stmt in node.body
        ]
        prove = next(i for i, names in enumerate(calls) if "_prove_group_save" in names)
        core = next(i for i, names in enumerate(calls) if any(n.endswith("_core") for n in names))
        assert prove < core, node.name
        before = set().union(*calls[:prove], calls[prove]) - {"_prove_group_save"}
        assert before <= {"sessions_ended_by_custom_role_save", "sessions_ended_by_ad_map_save"}, (
            node.name,
            before,
        )
    assert found == _ROUTES, "the walk lost a route, so the check above proves nothing for it"
