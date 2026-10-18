# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for the first-administrator grant (BACKLOG #3078).

``provision_first_administrator`` refused when ``has_enabled_administrator`` was true, then wrote
the account in later awaits, so two runs with different usernames could each pass the read and
each grant the role. The grant is now ``grant_first_admin_unless_admin_exists``: the guard and the
role write in one transaction, under the last-administrator guard's lock on the server backends.

``tests/test_first_admin_grant.py`` runs these against SQLite; ``tests/test_postgres_store.py`` and
``tests/test_sqlserver_store.py`` run them against the server backends, which only the live-server
CI legs do. :func:`assert_concurrent_grants_leave_one` is the discriminating one. Synthetic accounts
and synthetic hash strings only: nothing here verifies a password.
"""

from __future__ import annotations

import asyncio
from typing import Any

from messagefoundry.store.store import AdminGrant
from tests._last_admin_store_contract import ADMIN, VIEWER, enabled_admins

__all__ = ["enabled_admins"]

TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def hash_of(user_id: str) -> str:
    """A synthetic stand-in for the argon2 hash a run wrote. The grant compares it byte for byte."""
    return f"synthetic-hash-{user_id}"


async def seed_roles(store: Any) -> None:
    for role in (ADMIN, VIEWER):
        await store.upsert_role(role_id=role, display_name=role, description=None, builtin=True)


async def provisioned_row(store: Any, user_id: str, *, totp: bool) -> str | None:
    """A roleless local account holding the password, and optionally the TOTP, a run wrote.
    Returns the staged TOTP cell, or ``None`` with no TOTP."""
    await store.create_user(
        user_id=user_id,
        username=f"name-{user_id}",
        auth_provider="local",
        now=1.0,
        password_hash=None,
        password_generated=False,
    )
    await store.set_password(
        user_id,
        password_hash=hash_of(user_id),
        password_generated=False,
        must_change_password=False,
    )
    if not totp:
        return None
    cell = await store.set_totp_secret(user_id, secret=TOTP_SECRET)
    assert cell is not None
    assert await store.enable_totp(user_id, recovery_code_hashes=[], expected_secret_cell=cell)
    return str(cell)


async def grant(store: Any, user_id: str, cell: str | None, **overrides: Any) -> AdminGrant:
    kwargs: dict[str, Any] = {
        "admin_role_id": ADMIN,
        "expected_password_hash": hash_of(user_id),
        "expected_totp_secret_cell": cell,
        "assigned_by": "test",
    }
    kwargs.update(overrides)
    result: AdminGrant = await store.grant_first_admin_unless_admin_exists(user_id, **kwargs)
    return result


async def assert_first_admin_grant_contract(store: Any) -> None:
    """Granted only with no other enabled administrator, and only over the caller's credentials."""
    await seed_roles(store)
    a_cell = await provisioned_row(store, "a", totp=True)
    b_cell = await provisioned_row(store, "b", totp=False)
    await provisioned_row(store, "c", totp=False)

    # Credentials that are not the ones on the row write nothing.
    assert (
        await grant(store, "a", a_cell, expected_password_hash="other")
        is AdminGrant.ACCOUNT_CHANGED
    )
    assert await grant(store, "a", None) is AdminGrant.ACCOUNT_CHANGED  # TOTP is on
    assert await grant(store, "a", "not-the-cell") is AdminGrant.ACCOUNT_CHANGED
    assert await grant(store, "b", "a-cell-it-never-had") is AdminGrant.ACCOUNT_CHANGED
    # A secret another run staged but has not enabled is a secret: a TOTP-less grant is refused.
    staged = await store.set_totp_secret("c", secret=TOTP_SECRET)
    assert staged is not None
    assert await grant(store, "c", None) is AdminGrant.ACCOUNT_CHANGED
    await store.disable_totp("c")
    assert await grant(store, "absent", None) is AdminGrant.ACCOUNT_CHANGED
    assert await enabled_admins(store) == set()

    # Paired control: the same account with its own credentials is granted, holding exactly the role.
    assert await grant(store, "a", a_cell) is AdminGrant.GRANTED
    assert await store.get_user_role_ids("a") == [ADMIN]
    # A row that already holds a role is refused: a second run on a row the first already granted
    # is not granted over it. The target is still left out of the count, so it is not ADMIN_EXISTS.
    assert await grant(store, "a", a_cell) is AdminGrant.ACCOUNT_CHANGED

    # Another enabled administrator now exists: refused, writing nothing, whatever the credentials.
    assert await grant(store, "b", b_cell) is AdminGrant.ADMIN_EXISTS
    assert await store.get_user_role_ids("b") == []

    # A disabled administrator is no administrator, so it does not refuse a grant.
    await store.set_user_disabled("a", disabled=True)
    assert await grant(store, "b", b_cell) is AdminGrant.GRANTED
    assert await enabled_admins(store) == {"b"}

    # A disabled target is not granted.
    await store.set_user_disabled("b", disabled=True)
    await store.set_user_disabled("c", disabled=True)
    assert await grant(store, "c", None) is AdminGrant.ACCOUNT_CHANGED
    assert await store.get_user_role_ids("c") == []


async def assert_concurrent_grants_leave_one(store: Any) -> None:
    """The finding's own scenario at the store: two accounts, two grants at once, no administrator
    before either. Exactly one is granted."""
    await seed_roles(store)
    await provisioned_row(store, "a", totp=False)
    await provisioned_row(store, "b", totp=False)
    results = await asyncio.gather(grant(store, "a", None), grant(store, "b", None))
    assert sorted(results) == sorted([AdminGrant.GRANTED, AdminGrant.ADMIN_EXISTS]), results
    assert len(await enabled_admins(store)) == 1
