# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The start notice when no enabled Administrator can sign in without an outside service.

Vault BACKLOG #2711, step 2. A site whose every Administrator signs in through the directory or a
federated identity provider cannot reach the web console while that service is down. The engine
says so at start, and does nothing more: it never refuses. Since step 1, ``provision-admin`` reads
the same check: whenever this notice names accounts, they do not block it
(``tests/test_provision_admin_without_a_local_administrator.py``). It also runs on a store with no
enabled Administrator, where this notice names nobody, and it can refuse for its own reasons.
"""

from __future__ import annotations

import logging

import pytest

from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, create_admin
from tests._phi_log_capture import filtered_sink

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


#: The wording before BACKLOG #3282, kept only as the control below: the list followed a credential
#: label, so the shipped credential scrub masked the first name.
_OLD_WORDING = (
    "no enabled Administrator can sign in without an outside identity service (the directory or a "
    "federated identity provider); each is a directory account or a local one with no usable "
    "password: %s. If that service is down, no Administrator can sign in to manage this engine."
)


_LOGGER = "messagefoundry.auth.service"


async def test_every_named_administrator_survives_the_shipped_log_filters() -> None:
    """BACKLOG #3282. The notice exists to name the accounts, so each name must reach the log
    through the filter chain the engine installs. The control sends the old wording through the
    same chain and loses the first name, so this test can tell the two wordings apart."""
    names = ("dir-a", "dir-b", "ops.lead")
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        for name in names:
            await _directory_admin(service, name)
        # filtered_sink carries the filters every engine handler carries. caplog sees records
        # before any handler filter, so it cannot measure this.
        with filtered_sink(_LOGGER) as written:
            assert await service.report_administrators_needing_an_outside_service() == names
    finally:
        await store.close()
    assert "outside identity service" in written.text, "the notice did not reach the handler"
    assert "dir-a, dir-b, ops.lead" in written.text, written.text

    with filtered_sink(_LOGGER) as control:
        logging.getLogger(_LOGGER).warning(_OLD_WORDING, ", ".join(names))
    assert "dir-b, ops.lead" in control.text, "the control wording did not reach the handler"
    assert "dir-a" not in control.text, "the old wording keeps every name: this measures nothing"
