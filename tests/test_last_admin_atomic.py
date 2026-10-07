# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2779: the last-administrator guard and its write are one transaction.

The store contract is in ``tests/_last_admin_store_contract.py``, which says why. This file runs it
on SQLite and drives the three service paths the admin routes call, concurrently. Synthetic
accounts only.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import pytest

from messagefoundry.auth.service import AuthService, LastAdministratorRefused
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._last_admin_store_contract import (
    ADMIN,
    VIEWER,
    assert_concurrent_removals_leave_one,
    assert_last_admin_contract,
    enabled_admins,
    seed,
)


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


async def test_the_store_guard_refuses_only_the_last_removal(store: MessageStore) -> None:
    await assert_last_admin_contract(store)


async def test_two_concurrent_removals_leave_one_administrator(store: MessageStore) -> None:
    await assert_concurrent_removals_leave_one(store)


async def _service(store: MessageStore) -> AuthService:
    service = AuthService(store, AuthSettings())
    await service.initialize()
    return service


async def _disable(service: AuthService, user_id: str, *, display_name: str | None = None) -> None:
    await service.update_user(
        user_id, display_name=display_name, email=None, disabled=True, actor="t"
    )


async def test_concurrent_service_removals_leave_one_administrator(store: MessageStore) -> None:
    """Through the service paths the routes call: whichever lands second is refused."""
    service = await _service(store)
    await seed(store, ("a", "b"))
    outcomes = await asyncio.gather(
        service.set_roles("a", [VIEWER], actor="t"),
        _disable(service, "b"),
        return_exceptions=True,
    )
    refused = [o for o in outcomes if isinstance(o, LastAdministratorRefused)]
    assert len(refused) == 1 and [o for o in outcomes if o is None] == [None], outcomes
    assert len(await enabled_admins(store)) == 1


async def test_concurrent_deletes_leave_one_administrator(store: MessageStore) -> None:
    service = await _service(store)
    await seed(store, ("a", "b"))
    outcomes = await asyncio.gather(
        service.delete_user("a", actor="t"),
        service.delete_user("b", actor="t"),
        return_exceptions=True,
    )
    assert sum(isinstance(o, LastAdministratorRefused) for o in outcomes) == 1, outcomes
    assert len(await enabled_admins(store)) == 1


async def test_a_refused_disable_writes_nothing_else(store: MessageStore) -> None:
    """The ordinary refusal comes before the save's first write, so the profile edit is undone too."""
    service = await _service(store)
    await seed(store, ("a",))
    with pytest.raises(LastAdministratorRefused, match="cannot disable the last administrator"):
        await _disable(service, "a", display_name="renamed")
    a = await store.get_user("a")
    assert a is not None and not a.disabled and a.display_name is None
    with pytest.raises(LastAdministratorRefused, match="cannot delete the last administrator"):
        await service.delete_user("a", actor="t")
    with pytest.raises(LastAdministratorRefused, match="cannot remove the last administrator"):
        await service.set_roles("a", [VIEWER], actor="t")
    assert await store.get_user_role_ids("a") == [ADMIN]


async def test_the_disable_write_still_refuses_when_the_early_read_is_passed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The early read is a convenience, not the guard. With it answering "not last" -- what a
    removal racing this one would make it answer -- the store write still refuses. The profile
    edit that landed first is audited, marked as a save whose disable was refused."""
    service = await _service(store)
    await seed(store, ("a",))

    async def not_last(_user_id: str) -> bool:
        return False

    monkeypatch.setattr(service, "is_last_enabled_admin", not_last)
    with pytest.raises(LastAdministratorRefused):
        await _disable(service, "a", display_name="renamed")
    assert await enabled_admins(store) == {"a"}
    a = await store.get_user("a")
    assert a is not None and a.display_name == "renamed"
    [row] = [r for r in await store.list_audit(limit=50) if r["action"] == "user.updated"]
    assert json.loads(row["detail"]) == {"user_id": "a", "disable_refused": True}
