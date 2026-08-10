# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Stand up the first Administrator the way an operator does, for tests that used to lean on the
implicit first-run bootstrap account.

That account was retired under BACKLOG #1020 (ASVS 6.3.2 — no default accounts), so
``AuthService.initialize()`` now seeds roles and creates nothing. The replacement route is the
``messagefoundry admin-create`` CLI, whose one privileged step is the ``create_local_user`` call
reproduced here. Tests call this helper rather than the CLI so they exercise the auth service
directly; ``tests/test_admin_create_cli.py`` is what proves the CLI itself drives a fresh store to a
usable administrator, and is therefore the test that must fail if this helper drifts from it.

``must_change_password=False`` matches the CLI: the operator standing at the box chooses their own
password, so there is no second party a forced rotation would protect.
"""

from __future__ import annotations

from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService

#: Satisfies the shipped policy (>=15 chars, no app/vendor terms) so it works under stock settings.
FIRST_ADMIN_PW = "a-strong-test-passphrase"
FIRST_ADMIN = "admin"


async def create_first_admin(
    service: AuthService,
    *,
    username: str = FIRST_ADMIN,
    password: str = FIRST_ADMIN_PW,
    email: str | None = None,
) -> str:
    """Seed the built-in roles (idempotent) and create ``username`` as an Administrator."""
    await service.initialize()
    return await service.create_local_user(
        username=username,
        password=password,
        display_name="Administrator",
        email=email,
        roles=[Role.ADMINISTRATOR.value],
        actor="cli",
        must_change_password=False,
    )
