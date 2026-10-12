# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.permissions import (
    BUILTIN_ROLE_PERMISSIONS,
    CUSTOM_ROLE_ID_PREFIX,
    CustomRoleError,
    decode_custom_role_permissions,
    raw_body_without_summary,
    validate_custom_role_permissions,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_local_user_chosen
from tests._role_pairing import bypass_view_raw_pairing_rule

PW = "a-strong-test-passphrase"


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def _service(store: MessageStore) -> AuthService:
    service = AuthService(store, AuthSettings())
    await service.initialize()  # seeds the six built-in roles
    return service


async def _make_user(service: AuthService, username: str, *role_ids: str) -> str:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=list(role_ids),
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
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


# --- view_raw needs view_summary (ASVS 14.2.6, vault BACKLOG #1187) ----------------------------------


def test_validate_refuses_view_raw_without_view_summary() -> None:
    with pytest.raises(CustomRoleError, match="messages:view_raw needs messages:view_summary"):
        validate_custom_role_permissions(["messages:read", "messages:view_raw"])
    with pytest.raises(CustomRoleError, match="messages:view_raw needs messages:view_summary"):
        validate_custom_role_permissions(["messages:view_raw"])


def test_validate_accepts_view_raw_with_view_summary_and_summary_alone() -> None:
    # Control arms: the rule is the pair, not view_raw itself, and view_summary alone is fine.
    assert validate_custom_role_permissions(
        ["messages:read", "messages:view_raw", "messages:view_summary"]
    ) == [Permission.MESSAGES_READ, Permission.MESSAGES_VIEW_RAW, Permission.MESSAGES_VIEW_SUMMARY]
    assert validate_custom_role_permissions(["messages:view_summary"]) == [
        Permission.MESSAGES_VIEW_SUMMARY
    ]


def test_decode_drops_view_raw_from_a_stored_row_without_view_summary() -> None:
    # A row of the refused shape (hand-edited, or written before the rule) keeps everything but the
    # body read. The control row, holding both, keeps both.
    assert decode_custom_role_permissions(
        json.dumps(["messages:read", "messages:view_raw"])
    ) == frozenset({Permission.MESSAGES_READ})
    assert decode_custom_role_permissions(
        json.dumps(["messages:view_raw", "messages:view_summary"])
    ) == frozenset({Permission.MESSAGES_VIEW_RAW, Permission.MESSAGES_VIEW_SUMMARY})


def test_no_builtin_role_has_the_refused_shape() -> None:
    assert not [
        r for r, perms in BUILTIN_ROLE_PERMISSIONS.items() if raw_body_without_summary(perms)
    ]
    # Control: the predicate does fire on the shape it exists for.
    assert raw_body_without_summary({Permission.MESSAGES_VIEW_RAW})


def test_the_predicate_answers_an_iterator_correctly() -> None:
    # view_summary comes first on purpose. A predicate written as two `in` tests on the argument
    # would use up an iterator while finding view_raw, then report view_summary missing. With
    # view_raw first that defect would not show.
    pair = [Permission.MESSAGES_VIEW_SUMMARY, Permission.MESSAGES_VIEW_RAW]
    assert not raw_body_without_summary(iter(pair))
    assert raw_body_without_summary(iter([Permission.MESSAGES_VIEW_RAW]))


def test_the_test_bypass_lifts_only_the_pairing_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    bypass_view_raw_pairing_rule(monkeypatch)
    # Lifted: the pairing rule, at both mint and decode.
    assert validate_custom_role_permissions(["messages:view_raw"]) == [Permission.MESSAGES_VIEW_RAW]
    assert decode_custom_role_permissions(json.dumps(["messages:view_raw"])) == frozenset(
        {Permission.MESSAGES_VIEW_RAW}
    )
    # Kept: at least these other rules, each arm able to fail on its own rule.
    with pytest.raises(CustomRoleError, match="at least one permission"):
        validate_custom_role_permissions([])
    with pytest.raises(CustomRoleError, match="not assignable"):
        validate_custom_role_permissions(["messages:view_raw", "users:manage"])
    with pytest.raises(CustomRoleError, match="unknown permission"):
        validate_custom_role_permissions(["messages:view_raw", "not:a:real:perm"])
    assert decode_custom_role_permissions(
        json.dumps(["messages:view_raw", "users:manage", "bogus:perm"])
    ) == frozenset({Permission.MESSAGES_VIEW_RAW})


async def test_service_refuses_to_mint_or_edit_into_view_raw_without_view_summary() -> None:
    store = await _store()
    try:
        service = await _service(store)
        with pytest.raises(CustomRoleError):
            await service.create_custom_role(
                display_name="Raw only",
                description=None,
                permissions=["messages:read", "messages:view_raw"],
                actor="admin",
            )
        assert await service.list_custom_roles() == []
        role = await service.create_custom_role(
            display_name="Raw and summary",
            description=None,
            permissions=["messages:read", "messages:view_raw", "messages:view_summary"],
            actor="admin",
        )
        with pytest.raises(CustomRoleError):
            await service.update_custom_role(
                role.id,
                display_name="Raw and summary",
                description=None,
                permissions=["messages:read", "messages:view_raw"],
                actor="admin",
            )
        (kept,) = await service.list_custom_roles()
        assert Permission.MESSAGES_VIEW_SUMMARY in kept.permissions
    finally:
        await store.close()


async def test_the_pairing_rule_is_judged_per_role_not_on_the_merged_identity() -> None:
    """vault BACKLOG #2727 records the decision: the rule is per role. A ``view_raw`` role meant to
    pair with another role's ``view_summary`` is refused at minting. A stored row of that shape
    loses ``view_raw`` even for a user who also holds a ``view_summary`` role. The control user
    holds one role with both permissions and keeps both."""
    store = await _store()
    try:
        service = await _service(store)
        summary_half = await service.create_custom_role(
            display_name="Summary half",
            description=None,
            permissions=["messages:read", "messages:view_summary"],
            actor="admin",
        )
        # Minting: refused although the partner role exists.
        with pytest.raises(CustomRoleError, match="messages:view_raw needs messages:view_summary"):
            await service.create_custom_role(
                display_name="Raw half",
                description=None,
                permissions=["messages:view_raw", "messages:replay"],
                actor="admin",
            )
        # Decoding: the same shape written straight to the store, held beside the partner role.
        raw_half = CUSTOM_ROLE_ID_PREFIX + "rawhalf"
        await store.upsert_role(
            role_id=raw_half,
            display_name="Raw half",
            builtin=False,
            permissions=json.dumps(["messages:view_raw", "messages:replay"]),
        )
        split = await _identity_for(
            service, store, await _make_user(service, "split", summary_half.id, raw_half)
        )
        # The stored row still resolves, and the partner role still grants the summary.
        assert split.has(Permission.MESSAGES_REPLAY) and split.has(Permission.MESSAGES_VIEW_SUMMARY)
        assert not split.has(Permission.MESSAGES_VIEW_RAW)
        # Control: one role holding both keeps both, so the drop above is the per-role rule.
        whole_role = await service.create_custom_role(
            display_name="Whole",
            description=None,
            permissions=["messages:view_raw", "messages:view_summary"],
            actor="admin",
        )
        whole = await _identity_for(
            service, store, await _make_user(service, "whole", whole_role.id)
        )
        assert whole.has(Permission.MESSAGES_VIEW_RAW) and whole.has(
            Permission.MESSAGES_VIEW_SUMMARY
        )
    finally:
        await store.close()


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
    eng = await Engine.create(
        tmp_path / "custom_roles.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _onboarded(service: AuthService, username: str, role: Role) -> None:
    """A user who can sign in over HTTP. Admin-created accounts force a password change at first
    login (WP-L3-12), so clear that flag and keep the hash."""
    user_id = await _make_user(service, username, role.value)
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _bearer(client: httpx.AsyncClient, username: str) -> dict[str, str]:
    login = await client.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['token']}"}


async def test_crud_requires_users_manage(engine: Engine) -> None:
    # require_mfa=False: under the default, the MFA gate answers 403 first, to an administrator
    # as well, so the refusals below would not show the permission gate (vault BACKLOG #2727).
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    # a VIEWER has neither USERS_MANAGE nor USERS_READ
    await _onboarded(service, "viewer", Role.VIEWER)
    await _onboarded(service, "adm", Role.ADMINISTRATOR)
    async with _client(engine, service) as c:
        h = await _bearer(c, "viewer")
        # create / update / delete are all denied for a non-USERS_MANAGE caller
        r = await c.post(
            "/roles/custom",
            headers=h,
            json={"display_name": "X", "permissions": ["monitoring:read"]},
        )
        assert r.status_code == 403 and r.json()["detail"] == "missing permission: users:manage"
        r = await c.put(
            "/roles/custom/custom:abc",
            headers=h,
            json={"display_name": "X", "permissions": ["monitoring:read"]},
        )
        assert r.status_code == 403 and r.json()["detail"] == "missing permission: users:manage"
        r = await c.delete("/roles/custom/custom:abc", headers=h)
        assert r.status_code == 403 and r.json()["detail"] == "missing permission: users:manage"
        # listing custom roles needs USERS_READ — also denied for VIEWER
        r = await c.get("/roles/custom", headers=h)
        assert r.status_code == 403 and r.json()["detail"] == "missing permission: users:read"
        # Control: the same listing answers an administrator, so the 403s are the permission.
        assert (await c.get("/roles/custom", headers=await _bearer(c, "adm"))).status_code == 200


async def test_role_routes_refuse_view_raw_without_view_summary(engine: Engine) -> None:
    """vault BACKLOG #1187: the admin's own surface, POST and PUT /roles/custom, answers 400 with the
    pairing message. Controls: a POST and a PUT keeping view_summary are accepted. A final listing
    shows neither refusal wrote anything, name included.

    Moved here from tests/test_api_auth.py (vault BACKLOG #2727), beside the other custom-role
    route test."""
    # require_mfa=False and no write interval: this is a role-rule test. The administrator makes
    # four writes in a row, and neither the MFA gate nor the admin write limiter is its subject.
    service = AuthService(
        engine.store, AuthSettings(admin_write_min_interval_seconds=0, require_mfa=False)
    )
    await service.initialize()
    await _onboarded(service, "adm", Role.ADMINISTRATOR)
    both = ["messages:read", "messages:view_raw", "messages:view_summary"]
    raw_only = ["messages:read", "messages:view_raw"]
    async with _client(engine, service) as c:
        h = await _bearer(c, "adm")  # a fresh login is step-up fresh
        refused = await c.post(
            "/roles/custom", headers=h, json={"display_name": "Raw", "permissions": raw_only}
        )
        assert refused.status_code == 400, refused.text
        assert "messages:view_raw needs messages:view_summary" in refused.json()["detail"]
        made = await c.post(
            "/roles/custom",
            headers=h,
            json={"display_name": "Raw and summary", "permissions": both},
        )
        assert made.status_code == 201, made.text
        role_url = f"/roles/custom/{made.json()['id']}"
        # PUT control: the same edit keeping view_summary is accepted.
        kept = await c.put(role_url, headers=h, json={"display_name": "R", "permissions": both})
        assert kept.status_code == 200, kept.text
        # The refused edit drops view_summary and also renames; the 400's detail ties it to the
        # pairing rule, and the listing below shows the rename did not land either.
        edited = await c.put(
            role_url, headers=h, json={"display_name": "Changed", "permissions": raw_only}
        )
        assert edited.status_code == 400, edited.text
        assert "messages:view_raw needs messages:view_summary" in edited.json()["detail"]
        # Neither refusal wrote anything: one role, with the accepted name and permissions.
        listed = (await c.get("/roles/custom", headers=h)).json()
        assert [(r["display_name"], r["permissions"]) for r in listed] == [("R", sorted(both))]


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
