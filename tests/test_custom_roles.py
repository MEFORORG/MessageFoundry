# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Custom (admin-defined) RBAC roles — ADR 0045.

A custom role is a named SUBSET of the EXISTING ``Permission`` catalog (no new permission kinds),
persisted as the additive ``roles.permissions`` column and resolved as an overlay on the six fixed
built-ins. These tests cover the acceptance criteria: exact-subset grant, deny-by-default decode,
the escalation carve-out, built-in immutability, narrowing-revokes-sessions, the USERS_MANAGE gate,
and store-layer backend parity for the migration + CRUD.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Identity, Permission, Role
from messagefoundry.auth.permissions import (
    CUSTOM_ROLE_ID_PREFIX,
    CustomRoleError,
    decode_custom_role_permissions,
    validate_custom_role_permissions,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def _service(store: MessageStore) -> AuthService:
    service = AuthService(store, AuthSettings())
    await service.initialize()  # seeds the six built-in roles
    return service


async def _make_user(service: AuthService, username: str, *role_ids: str) -> str:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=list(role_ids),
        actor="test",
    )
    return user_id


async def _identity_for(service: AuthService, store: MessageStore, user_id: str) -> Identity:
    user = await store.get_user(user_id)
    assert user is not None
    return await service._build_identity(user)


# --- pure validator / decoder (the single deny-by-default chokepoint) --------


def test_validate_rejects_non_catalog_permission() -> None:
    with pytest.raises(CustomRoleError):
        validate_custom_role_permissions(["monitoring:read", "not:a:real:perm"])


def test_validate_rejects_empty_set() -> None:
    with pytest.raises(CustomRoleError):
        validate_custom_role_permissions([])


def test_validate_rejects_escalation_permissions() -> None:
    # AC-3: users:manage and approvals:approve are carved out (privilege-escalation primitives).
    with pytest.raises(CustomRoleError):
        validate_custom_role_permissions(["monitoring:read", "users:manage"])
    with pytest.raises(CustomRoleError):
        validate_custom_role_permissions(["approvals:approve"])


def test_validate_accepts_and_sorts_catalog_subset() -> None:
    perms = validate_custom_role_permissions(["messages:replay", "monitoring:read"])
    assert perms == [Permission.MESSAGES_REPLAY, Permission.MONITORING_READ]


def test_decode_drops_unknown_and_forbidden() -> None:
    # AC-2: a hand-edited DB row is untrusted — unknown and carved-out values are dropped on read.
    raw = json.dumps(["monitoring:read", "bogus:perm", "users:manage", "messages:replay"])
    assert decode_custom_role_permissions(raw) == frozenset(
        {Permission.MONITORING_READ, Permission.MESSAGES_REPLAY}
    )


def test_decode_malformed_or_empty_is_empty() -> None:
    assert decode_custom_role_permissions(None) == frozenset()
    assert decode_custom_role_permissions("") == frozenset()
    assert decode_custom_role_permissions("not json") == frozenset()
    assert decode_custom_role_permissions(json.dumps({"a": 1})) == frozenset()


# --- service: create + resolve (AC-1) ----------------------------------------


async def test_custom_role_grants_exact_subset() -> None:
    store = await _store()
    try:
        service = await _service(store)
        role = await service.create_custom_role(
            display_name="Lab-Ops",
            description="monitor + replay, no raw PHI",
            permissions=["monitoring:read", "messages:replay"],
            actor="admin",
        )
        assert role.id.startswith(CUSTOM_ROLE_ID_PREFIX)
        user_id = await _make_user(service, "lab", role.id)
        user = await store.get_user(user_id)
        assert user is not None
        identity = await service._build_identity(user)
        assert identity.permissions == frozenset(
            {Permission.MONITORING_READ, Permission.MESSAGES_REPLAY}
        )
        # exactly that subset — nothing the catalog gates elsewhere leaked in
        assert not identity.has(Permission.MESSAGES_VIEW_RAW)
        assert not identity.has(Permission.USERS_MANAGE)
    finally:
        await store.close()


async def test_custom_role_unions_with_builtin() -> None:
    # AC-1: a user holding a built-in AND a custom role gets the union.
    store = await _store()
    try:
        service = await _service(store)
        role = await service.create_custom_role(
            display_name="Replay",
            description=None,
            permissions=["messages:replay"],
            actor="admin",
        )
        user_id = await _make_user(service, "v", Role.VIEWER.value, role.id)
        identity = await _identity_for(service, store, user_id)
        # VIEWER gives monitoring:read + messages:read; custom adds messages:replay
        assert identity.has(Permission.MONITORING_READ)
        assert identity.has(Permission.MESSAGES_READ)
        assert identity.has(Permission.MESSAGES_REPLAY)
    finally:
        await store.close()


async def test_escalation_permissions_rejected_at_service() -> None:
    # AC-3 at the service boundary.
    store = await _store()
    try:
        service = await _service(store)
        with pytest.raises(CustomRoleError):
            await service.create_custom_role(
                display_name="Sneaky",
                description=None,
                permissions=["users:manage"],
                actor="admin",
            )
        # nothing was persisted
        assert await service.list_custom_roles() == []
    finally:
        await store.close()


async def test_unknown_permission_dropped_on_resolve() -> None:
    # AC-2: a stored role whose JSON contains an unknown perm grants only the recognized ones.
    store = await _store()
    try:
        service = await _service(store)
        role_id = CUSTOM_ROLE_ID_PREFIX + "handwritten"
        await store.upsert_role(
            role_id=role_id,
            display_name="Handwritten",
            builtin=False,
            permissions=json.dumps(["monitoring:read", "ghost:perm"]),
        )
        user_id = await _make_user(service, "h", role_id)
        identity = await _identity_for(service, store, user_id)
        assert identity.permissions == frozenset({Permission.MONITORING_READ})
    finally:
        await store.close()


# --- built-ins immutable (AC-4 / AC-5) ---------------------------------------


async def test_builtin_only_unchanged() -> None:
    # AC-4: with no custom role, every roles row is builtin with NULL permissions and resolution is
    # byte-identical (an ADMINISTRATOR still holds every permission).
    store = await _store()
    try:
        service = await _service(store)
        for row in await store.list_roles():
            assert bool(row["builtin"]) is True
            assert row["permissions"] is None
        assert await service.list_custom_roles() == []
        admin_id = await _make_user(service, "adm", Role.ADMINISTRATOR.value)
        identity = await _identity_for(service, store, admin_id)
        assert identity.permissions == frozenset(Permission)
    finally:
        await store.close()


async def test_builtins_immutable_under_custom_crud() -> None:
    # AC-5: defining/deleting custom roles never mutates a built-in row.
    store = await _store()
    try:
        service = await _service(store)
        before = {r["id"]: dict(r) for r in await store.list_roles()}
        role = await service.create_custom_role(
            display_name="X", description=None, permissions=["monitoring:read"], actor="admin"
        )
        # editing/deleting a "built-in" id is refused
        with pytest.raises(ValueError):
            await service.update_custom_role(
                Role.OPERATOR.value,
                display_name="hijack",
                description=None,
                permissions=["monitoring:read"],
                actor="admin",
            )
        with pytest.raises(ValueError):
            await service.delete_custom_role(Role.ADMINISTRATOR.value, actor="admin")
        await service.delete_custom_role(role.id, actor="admin")
        after = {r["id"]: dict(r) for r in await store.list_roles()}
        assert after == before  # built-in rows byte-identical; custom row gone
    finally:
        await store.close()


# --- narrowing / deletion revokes live sessions (AC-6) -----------------------


async def test_edit_narrowing_revokes_sessions_and_audits() -> None:
    store = await _store()
    try:
        service = await _service(store)
        role = await service.create_custom_role(
            display_name="Wide",
            description=None,
            permissions=["monitoring:read", "messages:replay"],
            actor="admin",
        )
        user_id = await _make_user(service, "u", role.id)
        # a live session for that user
        out = await service.login("u", PW)
        # must_change forces a flag but login still issues a token
        assert out.token is not None
        token = out.token
        assert await service.identity_for_token(token) is not None

        await service.update_custom_role(
            role.id,
            display_name="Narrow",
            description=None,
            permissions=["monitoring:read"],
            actor="admin",
        )
        # session revoked → token no longer resolves
        assert await service.identity_for_token(token) is None
        # next identity reflects the narrowed set
        identity = await _identity_for(service, store, user_id)
        assert identity.permissions == frozenset({Permission.MONITORING_READ})

        # an audit row was written with the resulting permission names (no PHI)
        audit = await store.list_audit(limit=50)
        actions = [a["action"] for a in audit]
        assert "role.updated" in actions
        updated = next(a for a in audit if a["action"] == "role.updated")
        assert "monitoring:read" in (updated["detail"] or "")
    finally:
        await store.close()


async def test_delete_revokes_and_removes_assignments() -> None:
    store = await _store()
    try:
        service = await _service(store)
        role = await service.create_custom_role(
            display_name="Temp", description=None, permissions=["monitoring:read"], actor="admin"
        )
        user_id = await _make_user(service, "u", role.id)
        out = await service.login("u", PW)
        token = out.token
        assert token is not None

        await service.delete_custom_role(role.id, actor="admin")
        # session revoked, role gone, user assignment removed
        assert await service.identity_for_token(token) is None
        assert role.id not in await store.get_user_role_ids(user_id)
        assert await store.get_role(role.id) is None
        # a deleted custom role grants nothing on a fresh identity build
        identity = await _identity_for(service, store, user_id)
        assert identity.permissions == frozenset()
    finally:
        await store.close()


# --- API: USERS_MANAGE gate (AC-7) -------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "custom_roles.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def test_crud_requires_users_manage(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    # a VIEWER has neither USERS_MANAGE nor USERS_READ
    viewer_id = await service.create_local_user(
        username="viewer",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="test",
    )
    u = await engine.store.get_user(viewer_id)
    assert u is not None and u.password_hash is not None
    await engine.store.set_password(
        viewer_id, password_hash=u.password_hash, must_change_password=False
    )
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        login = await c.post(
            "/auth/login", json={"username": "viewer", "password": PW, "provider": "local"}
        )
        token = login.json()["token"]
        h = {"Authorization": f"Bearer {token}"}
        # create / update / delete are all denied for a non-USERS_MANAGE caller
        r = await c.post(
            "/roles/custom",
            headers=h,
            json={"display_name": "X", "permissions": ["monitoring:read"]},
        )
        assert r.status_code == 403
        r = await c.put(
            "/roles/custom/custom:abc",
            headers=h,
            json={"display_name": "X", "permissions": ["monitoring:read"]},
        )
        assert r.status_code == 403
        r = await c.delete("/roles/custom/custom:abc", headers=h)
        assert r.status_code == 403
        # listing custom roles needs USERS_READ — also denied for VIEWER
        assert (await c.get("/roles/custom", headers=h)).status_code == 403


# --- store: backend migration + CRUD parity (AC-8) ---------------------------


async def test_roles_migration_backend_parity() -> None:
    # AC-8: the SQLite backend persists+resolves roles.permissions through the additive migration.
    # The SAME contract (`_assert_roles_contract`) is invoked against the real Postgres and SQL Server
    # backends by their gated mirror suites (tests/test_postgres_store.py::test_roles_permissions_contract
    # and tests/test_sqlserver_store.py::test_roles_permissions_contract), which the live-server CI legs
    # run for real. Here we assert the SQLite path end-to-end.
    store = await _store()
    try:
        await _assert_roles_contract(store)
    finally:
        await store.close()


async def _assert_roles_contract(store: MessageStore) -> None:
    """The roles-table contract every backend must satisfy (ADR 0045): a built-in row has NULL
    permissions; a custom row round-trips its JSON; get_role/list_roles/delete_custom_role agree;
    delete_custom_role refuses a built-in."""
    await store.upsert_role(role_id="administrator", display_name="Administrator", builtin=True)
    builtin = await store.get_role("administrator")
    assert builtin is not None and builtin["permissions"] is None and bool(builtin["builtin"])

    perms_json = json.dumps(["monitoring:read", "messages:replay"])
    await store.upsert_role(
        role_id="custom:r1",
        display_name="Lab-Ops",
        description="d",
        builtin=False,
        permissions=perms_json,
    )
    row = await store.get_role("custom:r1")
    assert row is not None
    assert bool(row["builtin"]) is False
    assert decode_custom_role_permissions(row["permissions"]) == frozenset(
        {Permission.MONITORING_READ, Permission.MESSAGES_REPLAY}
    )
    # update via upsert
    await store.upsert_role(
        role_id="custom:r1",
        display_name="Lab-Ops-2",
        description="d2",
        builtin=False,
        permissions=json.dumps(["monitoring:read"]),
    )
    row = await store.get_role("custom:r1")
    assert row is not None and str(row["display_name"]) == "Lab-Ops-2"
    assert decode_custom_role_permissions(row["permissions"]) == frozenset(
        {Permission.MONITORING_READ}
    )
    # a built-in is never deletable via delete_custom_role
    assert await store.delete_custom_role("administrator") is False
    assert await store.get_role("administrator") is not None
    # the custom role deletes
    assert await store.delete_custom_role("custom:r1") is True
    assert await store.get_role("custom:r1") is None
    assert await store.delete_custom_role("custom:r1") is False  # idempotent
