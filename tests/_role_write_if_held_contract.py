# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for ``set_user_roles_if_held`` (vault BACKLOG #3085).

The directory reconciler read an account's roles, then wrote its planned roles unconditionally. Two
reconcilers that both read the old roles both wrote, both counted a change, and both reported it;
and a plan could write a stale set over a sign-in's newer one. The write is now a compare-and-set
on the roles the caller read: it writes only while the record still holds exactly that set, so of
two writers that read one set only the first writes.

``tests/test_role_write_if_held.py`` runs these against SQLite; ``tests/test_postgres_store.py``
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


async def assert_role_write_if_held_contract(store: Any) -> None:
    """It writes while the record holds the expected set, and writes nothing once it does not."""
    write = store.set_user_roles_if_held
    await seed(store, "u1", (VIEWER,))
    assert await write(
        "u1", [OPERATOR, VIEWER], expected_role_ids=[VIEWER], assigned_by="ad-reconcile", now=3.0
    )
    assert await _grants(store, "u1") == [
        (OPERATOR, 3.0, "ad-reconcile"),
        (VIEWER, 3.0, "ad-reconcile"),
    ]
    # The record moved off the expected set, so nothing is written and the grants keep their stamp.
    assert not await write("u1", [ADMIN], expected_role_ids=[VIEWER], now=4.0)
    assert await _grants(store, "u1") == [
        (OPERATOR, 3.0, "ad-reconcile"),
        (VIEWER, 3.0, "ad-reconcile"),
    ]
    # Compared as sets: order and a duplicate in the expectation do not matter.
    assert await write("u1", [VIEWER], expected_role_ids=[VIEWER, OPERATOR, VIEWER], now=5.0)
    assert await store.get_user_role_ids("u1") == [VIEWER]
    # The empty set is a set like any other, on both sides.
    assert await write("u1", [], expected_role_ids=[VIEWER], now=6.0)
    assert await store.get_user_role_ids("u1") == []
    assert not await write("u1", [ADMIN], expected_role_ids=[VIEWER], now=7.0)
    assert await write("u1", [ADMIN], expected_role_ids=[], now=8.0)
    assert await store.get_user_role_ids("u1") == [ADMIN]
    # A gone row writes nothing.
    assert not await write("nobody", [VIEWER], expected_role_ids=[], now=9.0)
    # An unknown role is refused, writing nothing, as set_user_roles refuses it.
    with pytest.raises(UnknownRoleError):
        await write("u1", ["no-such-role"], expected_role_ids=[ADMIN], now=10.0)
    assert await store.get_user_role_ids("u1") == [ADMIN]


async def assert_concurrent_role_writes_write_once(store: Any) -> None:
    """Two writers that read one set, started at once: exactly one writes."""
    await seed(store, "u2", (ADMIN,))
    results = await asyncio.gather(
        store.set_user_roles_if_held("u2", [OPERATOR], expected_role_ids=[ADMIN]),
        store.set_user_roles_if_held("u2", [VIEWER], expected_role_ids=[ADMIN]),
    )
    assert sorted(results) == [False, True], results
    assert await store.get_user_role_ids("u2") == [OPERATOR if results[0] else VIEWER]
