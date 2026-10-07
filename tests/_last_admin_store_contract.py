# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for the last-administrator guard (vault BACKLOG #2779).

The guard used to be ``is_last_enabled_admin`` in the route, then the write in a separate await.
Two removals that interleaved each saw two administrators and both passed, so one administrator
could remove its own role while disabling the only other one and leave the engine with none. The
guard is now inside the store write, ``remove_unless_last_admin``: SQLite under its writer lock,
Postgres under an advisory lock, SQL Server under an applock.

``tests/test_last_admin_atomic.py`` runs these against SQLite; ``tests/test_postgres_store.py`` and
``tests/test_sqlserver_store.py`` run them against the server backends, which only the live-server
CI legs do. :func:`assert_concurrent_removals_leave_one` is the discriminating one: a guard that read
in one step and wrote in the next lets both removals through (measured against SQLite with such a
guard patched in: it left no administrator). Synthetic accounts only.
"""

from __future__ import annotations

import asyncio
from typing import Any

from messagefoundry.auth.permissions import Role
from messagefoundry.store.store import AdminRemoval

ADMIN = Role.ADMINISTRATOR.value
VIEWER = Role.VIEWER.value


async def seed(store: Any, admins: tuple[str, ...], others: tuple[str, ...] = ()) -> None:
    """Enabled local accounts: ``admins`` hold Administrator, ``others`` hold Viewer."""
    for role in (ADMIN, VIEWER):
        await store.upsert_role(role_id=role, display_name=role, description=None, builtin=True)
    for user_id in (*admins, *others):
        await store.create_user(
            user_id=user_id,
            username=f"name-{user_id}",
            auth_provider="local",
            now=1.0,
            password_generated=False,
        )
        await store.set_user_roles(user_id, [ADMIN if user_id in admins else VIEWER])


async def enabled_admins(store: Any) -> set[str]:
    found: set[str] = set()
    for user in await store.list_users():
        if not user.disabled and ADMIN in await store.get_user_role_ids(user.id):
            found.add(user.id)
    return found


async def assert_last_admin_contract(store: Any) -> None:
    """Each removal is refused, writing nothing, exactly when it would empty the set."""
    guard = store.remove_unless_last_admin
    await seed(store, ("a", "b"), ("c",))
    assert await guard("b", AdminRemoval.DISABLE, admin_role_id=ADMIN) is True
    assert await enabled_admins(store) == {"a"}
    # "a" is now the last one: every removal is refused and leaves it as it was.
    assert await guard("a", AdminRemoval.DISABLE, admin_role_id=ADMIN) is False
    assert await guard("a", AdminRemoval.DELETE, admin_role_id=ADMIN) is False
    assert await guard("a", AdminRemoval.SET_ROLES, admin_role_id=ADMIN, role_ids=[VIEWER]) is False
    a = await store.get_user("a")
    assert a is not None and not a.disabled
    assert await store.get_user_role_ids("a") == [ADMIN]
    # A role write that KEEPS the role is not a removal, last administrator or not.
    keeps = [ADMIN, VIEWER]
    assert await guard("a", AdminRemoval.SET_ROLES, admin_role_id=ADMIN, role_ids=keeps) is True
    assert sorted(await store.get_user_role_ids("a")) == sorted(keeps)
    # A non-administrator is never protected.
    assert await guard("c", AdminRemoval.SET_ROLES, admin_role_id=ADMIN, role_ids=[]) is True
    assert await guard("c", AdminRemoval.DISABLE, admin_role_id=ADMIN) is True
    assert await guard("c", AdminRemoval.DELETE, admin_role_id=ADMIN) is True
    assert await store.get_user("c") is None
    # Paired control for the refusals above: with a second enabled administrator back, the same
    # removal of "a" goes through.
    await store.set_user_disabled("b", disabled=False)
    assert await guard("a", AdminRemoval.SET_ROLES, admin_role_id=ADMIN, role_ids=[VIEWER]) is True
    assert await store.get_user_role_ids("a") == [VIEWER]
    assert await enabled_admins(store) == {"b"}


async def assert_concurrent_removals_leave_one(store: Any) -> None:
    """The finding's own scenario: one administrator removes its own role while disabling the only
    other one, both at once. Exactly one goes through."""
    await seed(store, ("a", "b"))
    results = await asyncio.gather(
        store.remove_unless_last_admin(
            "a", AdminRemoval.SET_ROLES, admin_role_id=ADMIN, role_ids=[VIEWER]
        ),
        store.remove_unless_last_admin("b", AdminRemoval.DISABLE, admin_role_id=ADMIN),
    )
    assert sorted(results) == [False, True]
    assert len(await enabled_admins(store)) == 1
