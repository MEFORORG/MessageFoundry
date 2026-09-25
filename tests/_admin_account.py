# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Give a test an enabled Administrator, since the engine creates none on its own.

ADR 0183 Amendment A retired the first-run bootstrap account that ``AuthService.initialize()`` used
to mint on an empty store (BACKLOG #1136). Waves 1a and 1b moved the tests that merely NEEDED an
administrator onto this helper before Wave 2 deleted the account.

**Why the store and not a service method.** The moved tests were written against the bootstrap's
credential state: admin-issued, must change, never claimed. ``provision_first_administrator``
builds the opposite state, claimed at birth, and ``create_local_user`` audits a ``user.created`` row
the moved tests do not expect. Writing through the store keeps both the user table and the audit
log as the tests were written against.

:func:`create_admin` runs ``initialize()`` itself, because that is where the role rows it assigns
are seeded. Calling ``initialize()`` again before or after it is harmless: it only re-seeds roles.

Wave 2 dropped the guard that refused a store already holding a row named ``admin``. It existed so
a test could not reach the bootstrap by accident while the bootstrap still existed; nothing creates
that row now, and a test that makes an account named ``admin`` on purpose is making an ordinary one.
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

# Not "admin": a distinct name cannot collide with a test that makes an account named "admin" on
# purpose, and keeps a failure message unambiguous about which account it means.
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


async def create_admin(service: AuthService) -> AdminAccount:
    """Write an enabled local Administrator named ``test-admin``, then run ``initialize()``.

    The credential state is an admin-issued one: ``must_change_password`` set and
    ``password_claimed_at`` empty, so the pending-credential deadline the API reports is a real
    instant.
    """
    store = service.store
    user_id = uuid4().hex
    await store.create_user(
        user_id=user_id,
        username=ADMIN_USERNAME,
        auth_provider=AuthProvider.LOCAL.value,
        password_hash=await asyncio.to_thread(hash_password, ADMIN_PASSWORD),
        must_change_password=True,
    )
    await service.initialize()  # seeds the roles the assignment below refers to
    await store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], assigned_by="test")
    return AdminAccount(user_id=user_id, username=ADMIN_USERNAME, password=ADMIN_PASSWORD)


async def login_admin(service: AuthService) -> tuple[Identity, str, str]:
    """Create the Administrator, sign it in, and return ``(identity, token, password)``.

    This is what the per-file ``_bootstrap_login`` helpers did, in the same tuple shape, so a caller
    moved by changing one name.
    """
    admin = await create_admin(service)
    out = await service.login(admin.username, admin.password)
    assert out.ok and out.identity is not None and out.token is not None
    # Pins the hand-written role write. Several callers test require_mfa, whose default scope covers
    # every local account, so without this they would pass even if the role never landed.
    assert Role.ADMINISTRATOR in out.identity.roles
    return out.identity, out.token, admin.password
