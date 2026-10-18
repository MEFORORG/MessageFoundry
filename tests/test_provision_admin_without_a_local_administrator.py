# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``provision-admin`` runs whenever no enabled local Administrator has a usable password.

Vault BACKLOG #2711 step 1, owner ruling B258-R4, ADR 0183 Amendment E. Before it, the command
refused while ANY enabled Administrator existed, so a site whose every Administrator signs in
through the directory or a federated identity provider had no host command to get back in while
that service was down. The refusal now reads the same computation as the start notice of step 2
(``administrators_needing_an_outside_service``), and ``test_the_refusal_and_the_start_notice_agree``
pins that the two agree.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a deploying site
would inherit.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable

import pytest

from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import (
    AuthService,
    FirstAdministratorRefused,
    ProvisionedAdministrator,
)
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, create_admin, provision_totp

_PASSWORD = "a-long-enough-operator-passphrase"
_EMAIL = "operator@example.org"


async def _admin_row(service: AuthService, username: str, *, provider: AuthProvider) -> str:
    """An enabled Administrator with no password hash, written through the store. On a local row
    that is the state a hand-edited or older store can leave: the role, and no credential. Use
    :func:`create_admin` for a local Administrator with a password."""
    user_id = f"id-{username}"
    await service.store.create_user(
        user_id=user_id,
        username=username,
        auth_provider=provider.value,
        password_hash=None,
        password_generated=False,
    )
    await service.initialize()  # seeds the role the assignment refers to
    await service.store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], assigned_by="test")
    return user_id


async def _directory_only(service: AuthService, _mp: pytest.MonkeyPatch) -> None:
    await _admin_row(service, "dir-a", provider=AuthProvider.AD)


async def _federated_only(service: AuthService, _mp: pytest.MonkeyPatch) -> None:
    # A federated binding is only ever on a directory account.
    user_id = await _admin_row(service, "fed-a", provider=AuthProvider.AD)
    await service.store.set_user_federated_subject(user_id, "https://idp.example.org", "sub-1")


async def _directory_and_hashless_local(service: AuthService, _mp: pytest.MonkeyPatch) -> None:
    await _admin_row(service, "dir-a", provider=AuthProvider.AD)
    await _admin_row(service, "local-nohash", provider=AuthProvider.LOCAL)


async def _directory_and_expired_local(service: AuthService, mp: pytest.MonkeyPatch) -> None:
    await _admin_row(service, "dir-a", provider=AuthProvider.AD)
    await create_admin(service)  # a must-change credential
    mp.setattr(service, "initial_credential_deadline", lambda _changed_at: 0.0)


async def _directory_and_usable_local(service: AuthService, _mp: pytest.MonkeyPatch) -> None:
    await _admin_row(service, "dir-a", provider=AuthProvider.AD)
    await create_admin(service)


async def _directory_and_disabled_local(service: AuthService, _mp: pytest.MonkeyPatch) -> None:
    await _admin_row(service, "dir-a", provider=AuthProvider.AD)
    local = await create_admin(service)
    await service.store.set_user_disabled(local.user_id, disabled=True)


async def _directory_and_locked_local(service: AuthService, _mp: pytest.MonkeyPatch) -> None:
    """A sign-in lockout still blocks the command: ``admin-unlock`` is that case's recovery, and
    the refusal text says so."""
    await _admin_row(service, "dir-a", provider=AuthProvider.AD)
    local = await create_admin(service)
    await service.store.record_login_failure(
        local.user_id, failed_attempts=5, locked_until=time.time() + 3600.0
    )


_Setup = Callable[[AuthService, pytest.MonkeyPatch], Awaitable[None]]

#: (setup, provision-admin accepts). Every case holds at least one enabled Administrator.
_CASES: list[tuple[_Setup, bool]] = [
    (_directory_only, True),
    (_federated_only, True),
    (_directory_and_hashless_local, True),
    (_directory_and_expired_local, True),
    (_directory_and_disabled_local, True),
    (_directory_and_usable_local, False),
    (_directory_and_locked_local, False),
]
_IDS = [setup.__name__.lstrip("_") for setup, _ in _CASES]


@pytest.mark.parametrize(("setup", "accepts"), _CASES, ids=_IDS)
async def test_provision_admin_runs_exactly_when_no_local_administrator_can_sign_in(
    setup: _Setup, accepts: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await setup(service, monkeypatch)
        assert await service.has_enabled_administrator() is True  # control: one is there

        refusal = await service.provision_refusal("site-admin", notify_email=_EMAIL)

        async def provision() -> ProvisionedAdministrator:
            return await service.provision_first_administrator(
                username="site-admin",
                password=_PASSWORD,
                notify_email=_EMAIL,
                actor="test",
                **provision_totp(),
            )

        if not accepts:
            assert refusal is not None and "already has an enabled Administrator" in refusal
            with pytest.raises(
                FirstAdministratorRefused, match="already has an enabled Administrator"
            ):
                await provision()
            assert await store.get_user_by_username("site-admin") is None
            return

        assert refusal is None
        named_before = await service.administrators_needing_an_outside_service()
        outcome = await provision()
        rows = await store.list_audit(limit=10, action="auth.first_administrator_provisioned")
        assert len(rows) == 1
        detail = rows[0]["detail"]
        at_check = (json.loads(detail) if isinstance(detail, str) else detail)[
            "administrators_at_check"
        ]
        # The accounts the start notice named before the run, so a disabled one is left out.
        assert at_check == list(named_before) and at_check
        assert ADMIN_USERNAME not in at_check or setup is not _directory_and_disabled_local
        assert outcome.repaired is False
        login = await service.login("site-admin", _PASSWORD)
        assert login.ok and login.identity is not None
        assert Role.ADMINISTRATOR in login.identity.roles
        # The new local Administrator closes the gap: a second run now refuses, and the notice is
        # silent.
        assert await service.provision_refusal("second", notify_email=_EMAIL) is not None
        assert await service.administrators_needing_an_outside_service() == ()
    finally:
        await store.close()


@pytest.mark.parametrize(("setup", "accepts"), _CASES, ids=_IDS)
async def test_the_refusal_and_the_start_notice_agree(
    setup: _Setup, accepts: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ruling's condition: the command refuses exactly where the notice is silent, on every
    store that holds an enabled Administrator."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await setup(service, monkeypatch)
        named = await service.administrators_needing_an_outside_service()
        refusal = await service.provision_refusal("site-admin", notify_email=_EMAIL)
        assert bool(named) is accepts
        assert (refusal is None) is bool(named)
        assert await service.has_self_sufficient_administrator() is not accepts
    finally:
        await store.close()


async def test_a_directory_administrators_row_is_still_never_promoted() -> None:
    """The widening opens the command, not the directory row: naming the directory Administrator
    itself is still refused by ``_existing_row_refusal``, so a local account is made beside it."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await _admin_row(service, "dir-a", provider=AuthProvider.AD)
        refusal = await service.provision_refusal("dir-a", notify_email=_EMAIL)
        assert refusal is not None and "ad account" in refusal
    finally:
        await store.close()


async def test_a_local_administrator_without_a_password_is_not_taken_over() -> None:
    """A local Administrator with no usable password no longer blocks the command, but its own
    row holds a role, so it is refused by name and a new account is made under another."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await _admin_row(service, "local-nohash", provider=AuthProvider.LOCAL)
        refusal = await service.provision_refusal("local-nohash", notify_email=_EMAIL)
        assert refusal is not None and "holds roles" in refusal
        assert await service.provision_refusal("site-admin", notify_email=_EMAIL) is None
    finally:
        await store.close()
