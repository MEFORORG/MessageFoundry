# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2221 and #3018 step 4: each account write's audit row commits in the write's own
transaction, on SQLite, through the service paths that write them.

The store half is ``tests/_account_write_audit_contract.py``, run here on SQLite and on the server
backends by their own suites. Each test below drives one service site twice: once with the store
refusing that site's row, which must leave no row and no change, and once with the row landing,
which must leave exactly one. The refusal is the store's own append raising, inside the write, so
a row written after the commit, as these sites used to write it, would not be refused at all.
Synthetic accounts only.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import AsyncIterator, Sequence
from typing import Any

import pytest

from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryBind
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import AppendedAuditRow, AuditAppend, MessageStore
from tests._account_write_audit_contract import assert_account_write_audit_contract, sign_in
from tests._last_admin_store_contract import ADMIN, VIEWER, seed


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


async def test_the_store_contract_on_sqlite(store: MessageStore) -> None:
    await assert_account_write_audit_contract(store)


async def _service(store: MessageStore, settings: AuthSettings | None = None, **kw: Any) -> Any:
    service = AuthService(store, settings or AuthSettings(), **kw)
    await service.initialize()
    return service


def _refuse(monkeypatch: pytest.MonkeyPatch, store: MessageStore, action: str) -> list[str]:
    """Make the store's in-write append refuse any batch holding an ``action`` row. Returns the
    actions it refused, so a test can show the refusal ran."""
    real = store._append_audits
    refused: list[str] = []

    async def refusing(audits: Sequence[AuditAppend], *, now: float) -> list[AppendedAuditRow]:
        if any(a.action == action for a in audits):
            refused.append(action)
            raise sqlite3.OperationalError("synthetic: disk I/O error")
        return await real(audits, now=now)

    monkeypatch.setattr(store, "_append_audits", refusing)
    return refused


async def _details(store: MessageStore, action: str) -> list[dict[str, Any]]:
    return [json.loads(r["detail"] or "{}") for r in await store.list_audit(action=action)]


async def test_create_local_user_commits_user_created_with_its_roles(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row names the roles, so it commits with the role write. Refused, the roles roll back
    with it: the INSERT before stays, holding no role, and its credential is never returned."""
    service = await _service(store)
    refused = _refuse(monkeypatch, store, "user.created")
    with pytest.raises(sqlite3.OperationalError):
        await service.create_local_user(
            username="lost", display_name=None, email=None, roles=[VIEWER], actor="admin"
        )
    assert refused == ["user.created"]
    lost = await store.get_user_by_username("lost")
    assert lost is not None and await store.get_user_role_ids(lost.id) == []
    assert await _details(store, "user.created") == []

    monkeypatch.undo()
    made = await service.create_local_user(
        username="kept", display_name=None, email=None, roles=[VIEWER], actor="admin"
    )
    assert await store.get_user_role_ids(made.user_id) == [VIEWER]
    assert await _details(store, "user.created") == [{"username": "kept", "roles": [VIEWER]}]


@pytest.mark.parametrize("disabled", [None, False])
async def test_a_save_that_does_not_disable_commits_with_its_profile_write(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, disabled: bool | None
) -> None:
    service = await _service(store)
    await seed(store, ("a", "b"))
    _refuse(monkeypatch, store, "user.updated")
    with pytest.raises(sqlite3.OperationalError):
        await service.update_user(
            "b", display_name="lost", email=None, disabled=disabled, actor="admin"
        )
    b = await store.get_user("b")
    assert b is not None and b.display_name is None, "the profile edit outlived its row"
    assert await _details(store, "user.updated") == []

    monkeypatch.undo()
    await service.update_user("b", display_name="kept", email=None, disabled=disabled, actor="a")
    b = await store.get_user("b")
    assert b is not None and b.display_name == "kept"
    assert await _details(store, "user.updated") == [{"user_id": "b"}]


async def test_a_disabling_save_commits_its_row_with_the_disable(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The disable carries the row, so a lock-out never lands without it, and its revoke does not
    run. The profile edit before it is its own transaction, so it stands either way."""
    service = await _service(store)
    await seed(store, ("a", "b"))
    await sign_in(store, "b")
    _refuse(monkeypatch, store, "user.updated")
    with pytest.raises(sqlite3.OperationalError):
        await service.update_user("b", display_name="x", email=None, disabled=True, actor="a")
    b = await store.get_user("b")
    assert b is not None and not b.disabled, "the disable outlived its row"
    assert len(await store.list_sessions("b")) == 1
    assert await _details(store, "user.updated") == []

    monkeypatch.undo()
    await service.update_user("b", display_name="x", email=None, disabled=True, actor="a")
    b = await store.get_user("b")
    assert b is not None and b.disabled
    assert await store.list_sessions("b") == []
    assert await _details(store, "user.updated") == [{"user_id": "b"}]


async def test_delete_user_commits_user_deleted_with_the_delete(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(store)
    await seed(store, ("a",), ("c",))
    _refuse(monkeypatch, store, "user.deleted")
    with pytest.raises(sqlite3.OperationalError):
        await service.delete_user("c", actor="a")
    assert await store.get_user("c") is not None, "the delete outlived its row"
    assert await _details(store, "user.deleted") == []

    monkeypatch.undo()
    await service.delete_user("c", actor="a")
    assert await store.get_user("c") is None
    assert await _details(store, "user.deleted") == [{"user_id": "c"}]


async def test_set_roles_commits_user_roles_changed_with_the_role_write(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row records the roles, so it commits with them, ahead of the revoke. Refused, the roles
    roll back and the revoke does not run."""
    service = await _service(store)
    await seed(store, ("a",), ("c",))
    await sign_in(store, "c")
    _refuse(monkeypatch, store, "user.roles_changed")
    with pytest.raises(sqlite3.OperationalError):
        await service.set_roles("c", [ADMIN], actor="a")
    assert await store.get_user_role_ids("c") == [VIEWER], "the roles outlived their row"
    assert len(await store.list_sessions("c")) == 1
    assert await _details(store, "user.roles_changed") == []

    monkeypatch.undo()
    await service.set_roles("c", [ADMIN], actor="a")
    assert await store.get_user_role_ids("c") == [ADMIN]
    assert await store.list_sessions("c") == []
    assert await _details(store, "user.roles_changed") == [{"user_id": "c", "roles": [ADMIN]}]


_PRINCIPAL = AdPrincipal(
    username="jdoe",
    display_name="J Doe",
    email="j@x",
    dn="CN=jdoe,DC=x",
    groups=frozenset({"cn=mf-ops,dc=x"}),
    directory_object_id="75920276-799f-51a3-9e67-4e4b9c43fd0c",
)


class _FakeLdap:
    def authenticate(self, username: str, password: str, **_: object) -> DirectoryBind:
        if username != "jdoe":
            return DirectoryBind(DirectoryAnswer.NOT_FOUND)
        return DirectoryBind(DirectoryAnswer.FOUND, _PRINCIPAL)

    def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
        return _PRINCIPAL if username == "jdoe" else None


async def test_a_directory_sign_in_commits_ad_roles_resynced_with_the_role_write(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The login sync's row commits with its role write. Refused there, the directory's roles still
    land and the stale sessions still end, since the directory is authoritative, and the row is
    written on its own, so the sign-in goes on. Refused on its own too, the sign-in fails, as it
    did when the row was written after the revoke. Landed, it leaves one."""
    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    service = await _service(store, settings, ldap=_FakeLdap())
    await service.set_ad_group_map([("cn=mf-ops,dc=x", "operator")], actor="admin")
    first = (await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=True)).token
    assert first is not None
    # The account's first sign-in wrote its first roles, with their row.
    assert await _details(store, "auth.ad_roles_resynced") == [{"from": [], "to": ["operator"]}]
    # Refused in the role write's transaction only: the row is then written on its own.
    await service.set_ad_group_map([("cn=mf-ops,dc=x", "viewer")], actor="admin")
    refused = _refuse(monkeypatch, store, "auth.ad_roles_resynced")
    second = (await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=True)).token
    assert second is not None
    assert refused == ["auth.ad_roles_resynced"]
    user = await store.get_user_by_username("jdoe")
    assert user is not None and await store.get_user_role_ids(user.id) == ["viewer"]
    assert await service.identity_for_token(first) is None, "a refused row kept a stale session"
    assert await _details(store, "auth.ad_roles_resynced") == [
        {"from": ["operator"], "to": ["viewer"]},
        {"from": [], "to": ["operator"]},
    ]
    monkeypatch.undo()

    # Refused on its own too: the roles and the revoke still land, and the sign-in fails.
    await service.set_ad_group_map([("cn=mf-ops,dc=x", "operator")], actor="admin")
    real = store._append_audit_row

    async def refusing(name: str, **kwargs: Any) -> Any:
        if name == "auth.ad_roles_resynced":
            raise sqlite3.OperationalError("synthetic: disk I/O error")
        return await real(name, **kwargs)

    monkeypatch.setattr(store, "_append_audit_row", refusing)
    with pytest.raises(sqlite3.OperationalError):
        await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=True)
    assert await store.get_user_role_ids(user.id) == ["operator"]
    assert await service.identity_for_token(second) is None, "a refused row kept a stale session"
    assert len(await _details(store, "auth.ad_roles_resynced")) == 2
    monkeypatch.undo()

    # Landed: one more row, written with the roles.
    await service.set_ad_group_map([("cn=mf-ops,dc=x", "viewer")], actor="admin")
    assert (await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=True)).token
    assert (await _details(store, "auth.ad_roles_resynced"))[0] == {
        "from": ["operator"],
        "to": ["viewer"],
    }
    assert len(await _details(store, "auth.ad_roles_resynced")) == 3


async def test_a_defect_in_the_sign_in_role_row_still_lands_the_roles_and_ends_the_sessions(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A defect, not a store refusal, in the sign-in's in-transaction row: the directory stays
    authoritative, so the roles still land and the stale sessions still end before it is raised,
    as the reconciler's role write does. No row is written for it."""
    settings = AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    service = await _service(store, settings, ldap=_FakeLdap())
    await service.set_ad_group_map([("cn=mf-ops,dc=x", "operator")], actor="admin")
    first = (await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=True)).token
    assert first is not None
    await service.set_ad_group_map([("cn=mf-ops,dc=x", "viewer")], actor="admin")
    real = store._append_audits

    async def defective(audits: Sequence[AuditAppend], *, now: float) -> list[AppendedAuditRow]:
        if any(a.action == "auth.ad_roles_resynced" for a in audits):
            raise NotImplementedError("synthetic defect")
        return await real(audits, now=now)

    monkeypatch.setattr(store, "_append_audits", defective)
    with pytest.raises(NotImplementedError):
        await service._complete_ad_login(_PRINCIPAL, None, mfa_verified=True)
    user = await store.get_user_by_username("jdoe")
    assert user is not None and await store.get_user_role_ids(user.id) == ["viewer"]
    assert await service.identity_for_token(first) is None, "a defect kept a stale session"
    assert await _details(store, "auth.ad_roles_resynced") == [{"from": [], "to": ["operator"]}]
