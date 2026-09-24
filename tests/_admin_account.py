# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Give a test an enabled Administrator without leaning on the first-run bootstrap account.

ADR 0183 Amendment A retires the bootstrap account that ``AuthService.initialize()`` mints on an
empty store (BACKLOG #1136). Wave 1a moves the tests that merely NEEDED an administrator off it,
before Wave 2 deletes it, so this helper must behave the same with and without the bootstrap.

**Why the store and not a service method.** The moved tests were written against the bootstrap's
credential state: admin-issued, must change, never claimed. ``provision_first_administrator``
builds the opposite state, claimed at birth. ``create_local_user`` ends by running the WP-3 sweep,
which would disable the bootstrap in one mode only.

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
from messagefoundry.auth.service import AuthService

__all__ = ["ADMIN_PASSWORD", "ADMIN_USERNAME", "AdminAccount", "create_admin", "login_admin"]

# Not "admin": that name is the bootstrap's, and a test must never be able to reach it by accident.
ADMIN_USERNAME = "test-admin"
# Synthetic, and clears the default policy, whose context screen refuses the word "admin". Kept
# low-entropy on purpose: a random-looking literal trips the leak gate's generic-api-key rule.
ADMIN_PASSWORD = "a-strong-operator-passphrase"

# A literal, not the product's BOOTSTRAP_USERNAME: Wave 2 deletes that constant, and this module
# must still import afterwards. Once no bootstrap exists the guard below simply never fires.
_BOOTSTRAP_USERNAME = "admin"


@dataclass(frozen=True)
class AdminAccount:
    """The account :func:`create_admin` wrote, and the password that signs into it."""

    user_id: str
    username: str
    password: str


async def create_admin(service: AuthService) -> AdminAccount:
    """Write an enabled local Administrator named ``test-admin``, then run ``initialize()``.

    The credential state matches the bootstrap row's: ``must_change_password`` set and
    ``password_claimed_at`` empty. The account is not the bootstrap, though. Branches keyed on the
    bootstrap's NAME do not fire for it, so the WP-3 login gate skips it, and the pending-credential
    deadline that the API reports is a real instant rather than None.
    """
    store = service.store
    if await store.get_user_by_username(_BOOTSTRAP_USERNAME) is not None:
        raise RuntimeError(
            "the bootstrap account already exists: call create_admin() instead of initialize()"
        )
    user_id = uuid4().hex
    await store.create_user(
        user_id=user_id,
        username=ADMIN_USERNAME,
        auth_provider=AuthProvider.LOCAL.value,
        password_hash=await asyncio.to_thread(hash_password, ADMIN_PASSWORD),
        must_change_password=True,
    )
    await service.initialize()  # seeds the roles; mints no bootstrap, since the table is not empty
    await store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], assigned_by="test")
    return AdminAccount(user_id=user_id, username=ADMIN_USERNAME, password=ADMIN_PASSWORD)


async def login_admin(service: AuthService) -> tuple[Identity, str, str]:
    """Create the Administrator, sign it in, and return ``(identity, token, password)``.

    This is what the per-file ``_bootstrap_login`` helpers did, in the same tuple shape, so a caller
    moves by changing one name. Like :func:`create_admin`, call it instead of ``initialize()``.
    """
    admin = await create_admin(service)
    out = await service.login(admin.username, admin.password)
    assert out.ok and out.identity is not None and out.token is not None
    # Pins the hand-written role write. Several callers test require_mfa, whose default scope covers
    # every local account, so without this they would pass even if the role never landed.
    assert Role.ADMINISTRATOR in out.identity.roles
    return out.identity, out.token, admin.password
