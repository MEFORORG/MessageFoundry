# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Give a test an enabled Administrator without leaning on the first-run bootstrap account.

ADR 0183 Amendment A retires the bootstrap account that ``AuthService.initialize()`` mints on an
empty store (BACKLOG #1136). Wave 1a moves the tests that merely NEEDED an administrator off it,
before Wave 2 deletes it, so this helper must behave the same with and without the bootstrap.

**Why the store and not the service.** ``create_local_user`` ends by running the WP-3 sweep, which
disables the bootstrap when a second administrator appears -- so it would change the store in one
mode only. ``provision_first_administrator`` refuses while the bootstrap exists. The store writes
below (``create_user``, ``set_password``, ``set_user_roles``) trigger neither.

**Why the bootstrap row is deleted.** Left in place it is a second enabled Administrator, and every
last-admin guard, user count and admin enumeration would then see a different store in each mode.
Deleting it makes the user table identical either way. It does not touch the audit log, so a test
that asserts audit rows must still filter to its own. This branch dies with the bootstrap in Wave 2.

Call it AFTER ``initialize()``: the role rows it assigns are seeded there.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import uuid4

from messagefoundry.auth.identity import AuthProvider, Identity
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import BOOTSTRAP_USERNAME, AuthService

__all__ = ["ADMIN_PASSWORD", "ADMIN_USERNAME", "AdminAccount", "create_admin", "login_admin"]

# Not "admin": that name is the bootstrap's, and a test must never be able to reach it by accident.
ADMIN_USERNAME = "test-admin"
# Synthetic, and clears the default policy, whose context screen refuses the word "admin". Kept
# low-entropy on purpose: a random-looking literal trips the leak gate's generic-api-key rule.
ADMIN_PASSWORD = "a-strong-operator-passphrase"


@dataclass(frozen=True)
class AdminAccount:
    """The account :func:`create_admin` wrote, and the password that signs into it."""

    user_id: str
    username: str
    password: str


async def create_admin(
    service: AuthService,
    *,
    username: str = ADMIN_USERNAME,
    password: str = ADMIN_PASSWORD,
    display_name: str | None = None,
    email: str | None = None,
    must_change_password: bool = True,
) -> AdminAccount:
    """Write an enabled local Administrator through the store, and remove any bootstrap row.

    ``must_change_password`` defaults to True because that is the row shape of the bootstrap account
    every moved test was written against: an admin-issued, unclaimed credential. Pass False for an
    account whose holder already set their own password, which also stamps ``password_claimed_at``.
    """
    if username.casefold() == BOOTSTRAP_USERNAME:
        raise ValueError(f"{username!r} is the bootstrap account's name; choose another")
    store = service.store
    boot = await store.get_user_by_username(BOOTSTRAP_USERNAME)
    if boot is not None:
        await store.delete_user(boot.id)
    user_id = uuid4().hex
    await store.create_user(
        user_id=user_id,
        username=username,
        auth_provider=AuthProvider.LOCAL.value,
        display_name=display_name,
        email=email,
    )
    await store.set_password(
        user_id,
        password_hash=await asyncio.to_thread(hash_password, password),
        must_change_password=must_change_password,
    )
    await store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], assigned_by="test")
    return AdminAccount(user_id=user_id, username=username, password=password)


async def login_admin(service: AuthService) -> tuple[Identity, str, str]:
    """Initialize, create the default Administrator, sign it in, return ``(identity, token, password)``.

    This is what the per-file ``_bootstrap_login`` helpers did, in the same tuple shape, so a caller
    moves by changing one name. ``initialize()`` is idempotent, so an already-initialized service is
    fine.
    """
    await service.initialize()
    admin = await create_admin(service)
    out = await service.login(admin.username, admin.password)
    assert out.ok and out.identity is not None and out.token is not None
    return out.identity, out.token, admin.password
