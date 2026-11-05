# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for ``set_user_roles_unless_held`` (vault BACKLOG #3085).

The directory reconciler read an account's roles, then wrote its planned roles unconditionally. Two
reconcilers that both read the old roles both wrote, both counted a change, and both reported it.
The write is now a compare-and-set on the roles it carries: it writes only while the record does
not already hold exactly that set, so of two writers carrying one set only the first writes.

``tests/test_role_write_unless_held.py`` runs these against SQLite; ``tests/test_postgres_store.py``
and ``tests/test_sqlserver_store.py`` run them against the server backends, which only the
live-server CI legs do. :func:`assert_concurrent_role_writes_write_once` is the discriminating one:
a write that compared in one step and wrote in the next would let both writers through. Synthetic
accounts only.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from messagefoundry.auth.permissions import Role
from messagefoundry.store.store import UnknownRoleError

ADMIN = Role.ADMINISTRATOR.value
OPERATOR = Role.OPERATOR.value
VIEWER = Role.VIEWER.value


async def seed(store: Any, user_id: str, roles: tuple[str, ...]) -> None:
    """An enabled directory account holding ``roles``, with the three built-in roles defined."""
    for role in (ADMIN, OPERATOR, VIEWER):
        await store.upsert_role(role_id=role, display_name=role, description=None, builtin=True)
    await store.create_user(
        user_id=user_id,
        username=f"name-{user_id}",
        auth_provider="ad",
        now=1.0,
        password_generated=False,
        audits=(),
    )
    await store.set_user_roles(user_id, list(roles), assigned_by="seed", now=2.0)


async def _grants(store: Any, user_id: str) -> list[tuple[str, float, str | None]]:
    return sorted(
        (g.role_id, g.assigned_at, g.assigned_by) for g in await store.get_user_role_grants(user_id)
    )


async def assert_role_write_unless_held_contract(store: Any) -> None:
    """It writes and reports what it replaced, and writes nothing over the set it carries."""
    write = store.set_user_roles_unless_held
    await seed(store, "u1", (VIEWER,))
    assert await write("u1", [OPERATOR, VIEWER], assigned_by="ad-reconcile", now=3.0) == (VIEWER,)
    assert await _grants(store, "u1") == [
        (OPERATOR, 3.0, "ad-reconcile"),
        (VIEWER, 3.0, "ad-reconcile"),
    ]
    # The same set again, in another order and with a duplicate: nothing is written, so the grants
    # keep their first stamp.
    assert await write("u1", [VIEWER, OPERATOR, VIEWER], assigned_by="other", now=4.0) is None
    assert await _grants(store, "u1") == [
        (OPERATOR, 3.0, "ad-reconcile"),
        (VIEWER, 3.0, "ad-reconcile"),
    ]
    # Any other set is replaced, a narrower one and the empty one included; the replaced set is
    # returned sorted, as the record holds it.
    assert await write("u1", [VIEWER], now=5.0) == (OPERATOR, VIEWER)
    assert await store.get_user_role_ids("u1") == [VIEWER]
    assert await write("u1", [], now=6.0) == (VIEWER,)
    assert await store.get_user_role_ids("u1") == []
    assert await write("u1", [], now=7.0) is None
    # A record that held no role reports the empty tuple it replaced, which is not None.
    assert await write("u1", [ADMIN], now=8.0) == ()
    assert await store.get_user_role_ids("u1") == [ADMIN]
    # A gone row writes nothing.
    assert await write("nobody", [VIEWER], now=9.0) is None
    # An unknown role is refused, writing nothing, as set_user_roles refuses it.
    with pytest.raises(UnknownRoleError):
        await write("u1", ["no-such-role"], now=10.0)
    assert await store.get_user_role_ids("u1") == [ADMIN]


async def assert_concurrent_role_writes_write_once(store: Any) -> None:
    """Two writers carrying one set, started at once against a record holding another: exactly
    one writes and reports what it replaced, and the other reports None."""
    await seed(store, "u2", (ADMIN,))
    results = await asyncio.gather(
        store.set_user_roles_unless_held("u2", [OPERATOR], assigned_by="ad-reconcile"),
        store.set_user_roles_unless_held("u2", [OPERATOR], assigned_by="ad-reconcile"),
    )
    assert sorted(results, key=lambda r: r is None) == [(ADMIN,), None], results
    assert await store.get_user_role_ids("u2") == [OPERATOR]
