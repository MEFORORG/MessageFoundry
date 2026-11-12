# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5725: a custom role is saved or deleted only under its EXACT id.

SQL Server's default collation folds case and ignores trailing spaces, so its ``get_role`` finds a
stored custom role from a case or trailing-space variant of the id, while its
``delete_custom_role`` refuses that variant and returns ``False``. A service that took the variant
as the role would revoke sessions, write a ``role.deleted`` row and answer success for a delete
that removed nothing, and an edit would seal the stored row under another id.

The instrument is the SQLite store with ``get_role`` and ``delete_custom_role`` replaced by
versions that fold case and trailing spaces, as SQL Server's default collation does at least; the
first test is the positive control that they really find the variants. Its ``upsert_role`` stays
SQLite's, so an edit the service let through would add a second row here rather than re-seal the
stored one; the service's refusal is what both tests pin. The SQL Server live leg is not run by
this file. The last test pins the service on a store that refuses the exact id.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"


def _fold(role_id: str) -> str:
    """SQL Server's default comparison, near enough: case folded, trailing spaces ignored."""
    return role_id.rstrip(" ").casefold()


def _collated(store: MessageStore, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``store``'s role lookup and delete compare ids as SQL Server's do."""
    exact_delete = store.delete_custom_role

    async def get_role(role_id: str) -> Any:
        for row in await store.list_roles():
            if _fold(str(row["id"])) == _fold(role_id):
                return row
        return None

    async def delete_custom_role(role_id: str) -> bool:
        # As SqlServerStore.delete_custom_role: found in the collation, refused unless exact.
        found = await get_role(role_id)
        if found is None or int(found["builtin"]) != 0 or str(found["id"]) != role_id:
            return False
        return await exact_delete(role_id)

    monkeypatch.setattr(store, "get_role", get_role)
    monkeypatch.setattr(store, "delete_custom_role", delete_custom_role)


async def _setup(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MessageStore, AuthService, str, str, str]:
    """A store comparing as SQL Server's, a custom role, its holder, and the holder's token."""
    store = await MessageStore.open(":memory:")
    try:
        _collated(store, monkeypatch)
        service = AuthService(store, AuthSettings())
        await service.initialize()
        role = await service.create_custom_role(
            display_name="Exact", description=None, permissions=["monitoring:read"], actor="admin"
        )
        user_id = await create_local_user_chosen(
            service,
            username="u",
            password=PW,
            display_name=None,
            email=None,
            roles=[role.id],
            actor="test",
        )
        await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
        out = await service.login("u", PW)
        assert out.token is not None
    except BaseException:
        await store.close()  # the callers' finally starts only once this returns
        raise
    return store, service, role.id, user_id, out.token


def _case_variant(role_id: str) -> str:
    prefix = "custom:"
    assert role_id.startswith(prefix)
    variant = prefix + role_id[len(prefix) :].upper()
    assert variant != role_id  # a uuid hex with no letter would make no variant
    return variant


_VARIANTS: dict[str, Callable[[str], str]] = {
    "case": _case_variant,
    "trailing-space": lambda role_id: role_id + " ",
}


async def _assert_untouched(
    store: MessageStore, service: AuthService, role_id: str, user_id: str, token: str
) -> None:
    """The role, its grant and the holder's session all stand, and no role row was written."""
    actions = [a["action"] for a in await store.list_audit(limit=200)]
    assert "role.deleted" not in actions
    assert "role.updated" not in actions
    assert await service.identity_for_token(token) is not None
    assert role_id in await store.get_user_role_ids(user_id)
    assert [
        str(r["id"]) for r in await store.list_roles() if str(r["id"]).startswith("custom:")
    ] == [role_id]
    held = await service._load_role(role_id)
    assert held is not None and held.display_name == "Exact"


@pytest.mark.parametrize("kind", sorted(_VARIANTS))
async def test_the_instrument_finds_the_variant(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive control: the lookup really finds the stored role from the variant, and the delete
    really refuses it, or the cases below prove nothing."""
    store, _service, role_id, _user, _token = await _setup(monkeypatch)
    try:
        variant = _VARIANTS[kind](role_id)
        found = await store.get_role(variant)
        assert found is not None and found["id"] == role_id
        assert await store.delete_custom_role(variant) is False
    finally:
        await store.close()


@pytest.mark.parametrize("kind", sorted(_VARIANTS))
async def test_a_delete_by_a_variant_id_is_not_found(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, service, role_id, user_id, token = await _setup(monkeypatch)
    try:
        with pytest.raises(ValueError, match="no such custom role"):
            await service.delete_custom_role(_VARIANTS[kind](role_id), actor="admin")
        await _assert_untouched(store, service, role_id, user_id, token)
        # Control: the exact id still deletes.
        await service.delete_custom_role(role_id, actor="admin")
        assert await store.get_role(role_id) is None
    finally:
        await store.close()


@pytest.mark.parametrize("kind", sorted(_VARIANTS))
async def test_an_update_by_a_variant_id_is_not_found(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, service, role_id, user_id, token = await _setup(monkeypatch)
    try:
        with pytest.raises(ValueError, match="no such custom role"):
            await service.update_custom_role(
                _VARIANTS[kind](role_id),
                display_name="Renamed",
                description=None,
                permissions=["monitoring:read"],
                actor="admin",
            )
        await _assert_untouched(store, service, role_id, user_id, token)
    finally:
        await store.close()


async def test_a_delete_the_store_refuses_records_no_deletion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A store answering ``False`` for the exact id, as one that lost a race to another delete
    would, deleted nothing: the service answers not found and writes no ``role.deleted`` row."""
    store, service, role_id, _user, _token = await _setup(monkeypatch)

    async def refuse(role_id: str) -> bool:
        return False

    monkeypatch.setattr(store, "delete_custom_role", refuse)
    try:
        with pytest.raises(ValueError, match="no such custom role"):
            await service.delete_custom_role(role_id, actor="admin")
        actions = [a["action"] for a in await store.list_audit(limit=200)]
        assert "role.deleted" not in actions
        assert await store.get_role(role_id) is not None
    finally:
        await store.close()
