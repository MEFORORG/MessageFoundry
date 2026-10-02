# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The start notice when no enabled Administrator can sign in without an outside service.

Vault BACKLOG #2711, step 2. ``provision-admin`` refuses while any enabled Administrator exists,
whichever kind. So a site whose every Administrator signs in through the directory or a federated
identity provider has no host command to get back in while that service is down. The engine says so
at start, and does nothing more: it never refuses.
"""

from __future__ import annotations

import pytest

from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, create_admin

_ACTION = "auth.no_local_administrator"


async def _directory_admin(service: AuthService, username: str) -> str:
    user_id = f"dir-{username}"
    await service.store.create_user(
        user_id=user_id,
        username=username,
        auth_provider=AuthProvider.AD.value,
        password_generated=False,
    )
    await service.initialize()  # seeds the role the assignment refers to
    await service.store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], assigned_by="test")
    return user_id


async def test_every_administrator_on_the_directory_is_named_warned_and_audited(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await _directory_admin(service, "dir-b")
        await _directory_admin(service, "dir-a")
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            await service.report_lockable_account_census()  # the call the lifespan makes
        assert await service.administrators_needing_an_outside_service() == ("dir-a", "dir-b")
        warned = [
            r.getMessage() for r in caplog.records if "outside identity service" in r.getMessage()
        ]
        assert len(warned) == 1 and "dir-a, dir-b" in warned[0]
        assert "provision-admin" in warned[0]
        rows = await store.list_audit(limit=10, action=_ACTION)
        assert len(rows) == 1 and "dir-a" in str(rows[0]["detail"])
    finally:
        await store.close()


async def test_one_local_administrator_with_a_password_silences_it() -> None:
    """CONTROL: the same directory Administrators beside one local Administrator that holds a
    password. That account can sign in with no outside service, so there is nothing to say."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await _directory_admin(service, "dir-a")
        await create_admin(service)
        assert await service.administrators_needing_an_outside_service() == ()
        assert await service.report_administrators_needing_an_outside_service() == ()
        assert await store.list_audit(limit=10, action=_ACTION) == []
    finally:
        await store.close()


async def test_a_local_administrator_whose_temporary_password_expired_does_not_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``create_admin`` writes a must-change credential. Once its deadline has passed the login gate
    refuses it, so it is no way back in either. Before its deadline it counts (the control)."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await _directory_admin(service, "dir-a")
        await create_admin(service)
        assert await service.administrators_needing_an_outside_service() == ()
        monkeypatch.setattr(service, "initial_credential_deadline", lambda _changed_at: 0.0)
        assert await service.administrators_needing_an_outside_service() == (
            "dir-a",
            ADMIN_USERNAME,
        )
    finally:
        await store.close()


async def test_a_disabled_local_administrator_does_not_count() -> None:
    """A disabled local Administrator cannot sign in, so it is no way back in."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await _directory_admin(service, "dir-a")
        local = await create_admin(service)
        await store.set_user_disabled(local.user_id, disabled=True)
        assert await service.administrators_needing_an_outside_service() == ("dir-a",)
    finally:
        await store.close()


async def test_no_administrator_at_all_is_left_to_the_first_run_notices() -> None:
    """ADR 0183's first-run path already speaks when there is no Administrator; this notice does
    not repeat it."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        assert await service.report_administrators_needing_an_outside_service() == ()
        assert await store.list_audit(limit=10, action=_ACTION) == []
    finally:
        await store.close()


async def test_a_failing_notice_costs_neither_the_census_nor_the_start(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await create_admin(service)

        async def broken() -> tuple[str, ...]:
            raise RuntimeError("synthetic: the notice failed")

        monkeypatch.setattr(service, "report_administrators_needing_an_outside_service", broken)
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            census = await service.report_lockable_account_census()
        # The census still ran and still named the chosen-password Administrator.
        assert census.no_way_past == (ADMIN_USERNAME,)
        assert any(
            "local-Administrator notice could not run" in r.getMessage() for r in caplog.records
        )
    finally:
        await store.close()
