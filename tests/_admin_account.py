# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Give a test an enabled Administrator without leaning on the first-run bootstrap account.

ADR 0183 Amendment A retires the bootstrap account that ``AuthService.initialize()`` mints on an
empty store (BACKLOG #1136). Wave 1a moves the tests that merely NEEDED an administrator off it,
before Wave 2 deletes it, so this helper must behave the same with and without the bootstrap.

**Why the store and not the service.** ``create_local_user`` ends by running the WP-3 sweep, which
disables the bootstrap when a second administrator appears -- so it would change the store in one
mode only. ``provision_first_administrator`` refuses while the bootstrap exists.

**Why the user row goes in BEFORE ``initialize()``.** ``initialize()`` mints the bootstrap only on
an empty users table, so writing the row first means it is never minted. The user table and the
audit log then come out the same in both modes, with nothing to delete afterwards. The role is
assigned after ``initialize()``, because that is where the role rows are seeded.

So call :func:`create_admin` INSTEAD of ``initialize()``, not after it. It refuses a store that
already holds the bootstrap, which is what a call after ``initialize()`` would find.
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
    service: AuthService, *, username: str = ADMIN_USERNAME, email: str | None = None
) -> AdminAccount:
    """Write an enabled local Administrator, then run ``initialize()``.

    The credential is admin-issued and unclaimed (``must_change_password`` set, no
    ``password_claimed_at``), which is how the bootstrap row was stored. It is not the bootstrap,
    though: branches keyed on the bootstrap's NAME, such as the WP-3 gate in the login path, do not
    fire for it. ``email`` also seeds the notification address, as ``create_user`` always does.
    """
    if username.casefold() == BOOTSTRAP_USERNAME:
        raise ValueError(f"{username!r} is the bootstrap account's name; choose another")
    store = service.store
    if await store.get_user_by_username(BOOTSTRAP_USERNAME) is not None:
        raise RuntimeError(
            "the bootstrap account already exists: call create_admin() instead of initialize()"
        )
    user_id = uuid4().hex
    await store.create_user(
        user_id=user_id,
        username=username,
        auth_provider=AuthProvider.LOCAL.value,
        email=email,
        password_hash=await asyncio.to_thread(hash_password, ADMIN_PASSWORD),
        must_change_password=True,
    )
    await service.initialize()  # seeds the roles; mints no bootstrap, since the table is not empty
    await store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], assigned_by="test")
    return AdminAccount(user_id=user_id, username=username, password=ADMIN_PASSWORD)


async def login_admin(service: AuthService) -> tuple[Identity, str, str]:
    """Create the default Administrator, sign it in, and return ``(identity, token, password)``.

    This is what the per-file ``_bootstrap_login`` helpers did, in the same tuple shape, so a caller
    moves by changing one name. Like :func:`create_admin`, call it instead of ``initialize()``.
    """
    admin = await create_admin(service)
    out = await service.login(admin.username, admin.password)
    assert out.ok and out.identity is not None and out.token is not None
    return out.identity, out.token, admin.password
