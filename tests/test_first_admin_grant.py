# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3078: two provision-admin runs with different usernames cannot both create an
Administrator.

``provision_first_administrator`` refused when ``has_enabled_administrator`` was true and wrote the
account in later awaits, so two runs held past that read each granted the role. The grant is now
``grant_first_admin_unless_admin_exists``: the guard and the write in one transaction. The run whose
grant commits second is refused, prints no recovery codes and writes no
``auth.first_administrator_provisioned`` row; its account holds no role (ADR 0183).

The grant is also bound to the credentials the run wrote (the #3025 fold-in): two runs on one row
can interleave so that one run's password sits beside the other's TOTP, and then nothing is granted.

The store contract is in ``tests/_first_admin_grant_store_contract.py``; this file runs it on
SQLite. The race is made deterministic as ``tests/test_create_user_name_race.py`` makes its own: a
barrier holds both runs after the read until both have made it. Two stores opened on one file stand
in for two ``provision-admin`` processes, because SQLite answers their collision with
``SQLITE_BUSY_SNAPSHOT`` rather than a wait. Synthetic accounts only.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.service import AuthService, FirstAdministratorRefused
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store import store as store_module
from messagefoundry.store.store import AdminGrant, MessageStore
from tests._admin_account import provision_totp
from tests._first_admin_grant_store_contract import (
    assert_concurrent_grants_leave_one,
    assert_first_admin_grant_contract,
    enabled_admins,
    grant,
    provisioned_row,
    seed_roles,
)

_PASSWORD = "a-long-enough-operator-passphrase"
_PROVISIONED = "auth.first_administrator_provisioned"


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


# --- the store primitive ---------------------------------------------------------------------------


async def test_the_grant_contract_holds_on_sqlite(store: MessageStore) -> None:
    await assert_first_admin_grant_contract(store)


async def test_two_concurrent_grants_leave_one_administrator(store: MessageStore) -> None:
    await assert_concurrent_grants_leave_one(store)


def _busy() -> sqlite3.OperationalError:
    exc = sqlite3.OperationalError("database is locked")
    exc.sqlite_errorcode = sqlite3.SQLITE_BUSY_SNAPSHOT
    return exc


async def test_a_busy_grant_runs_again_rather_than_answering(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A busy write is not a refusal: the transaction runs again from its read. The end-to-end
    case, where the re-read finds another process's committed Administrator, is
    :func:`test_a_grant_that_loses_to_another_process_is_refused_through_sqlite_busy`."""
    await seed_roles(store)
    await provisioned_row(store, "a", totp=False)
    monkeypatch.setattr(store_module, "_ADMIN_GRANT_BUSY_BACKOFF_SECONDS", 0.0)
    real = store._write_user
    calls = 0

    async def busy_once(user_id: str, change: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise _busy()
        return await real(user_id, change)

    monkeypatch.setattr(store, "_write_user", busy_once)
    result = await grant(store, "a", None)
    assert result is AdminGrant.GRANTED
    assert calls == 2
    assert await enabled_admins(store) == {"a"}


async def test_a_busy_that_outlasts_the_bound_is_raised_not_read_as_a_refusal(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await seed_roles(store)
    await provisioned_row(store, "a", totp=False)
    monkeypatch.setattr(store_module, "_ADMIN_GRANT_BUSY_BACKOFF_SECONDS", 0.0)
    calls = 0

    async def always_busy(user_id: str, change: Any) -> Any:
        nonlocal calls
        calls += 1
        raise _busy()

    monkeypatch.setattr(store, "_write_user", always_busy)
    with pytest.raises(sqlite3.OperationalError):
        await grant(store, "a", None)
    assert calls == store_module._ADMIN_GRANT_BUSY_ATTEMPTS
    monkeypatch.undo()
    assert await enabled_admins(store) == set()


async def test_an_error_that_is_not_busy_is_raised_at_once(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await seed_roles(store)
    await provisioned_row(store, "a", totp=False)
    calls = 0

    async def broken(user_id: str, change: Any) -> Any:
        nonlocal calls
        calls += 1
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store, "_write_user", broken)
    with pytest.raises(sqlite3.OperationalError, match="disk I/O"):
        await grant(store, "a", None)
    assert calls == 1


# --- the provisioning race -------------------------------------------------------------------------


def _unguarded_grant(store: MessageStore) -> Callable[..., Awaitable[AdminGrant]]:
    """The check-then-write this item removes: the role written with no re-check. The mutation
    control patches it back in."""

    async def unguarded(
        user_id: str, *, admin_role_id: str, assigned_by: str | None = None, **_: Any
    ) -> AdminGrant:
        await store.set_user_roles(user_id, [admin_role_id], assigned_by=assigned_by)
        return AdminGrant.GRANTED

    return unguarded


def _hold_both_after_the_read(services: list[AuthService], monkeypatch: pytest.MonkeyPatch) -> None:
    """Hold each run after ``has_enabled_administrator`` until both have read it, so each has seen
    no administrator before either writes. That is the race itself."""
    arrived = 0
    both_read = asyncio.Event()
    for service in services:
        original = service.has_enabled_administrator

        async def held(original: Callable[[], Awaitable[bool]] = original) -> bool:
            nonlocal arrived
            found = await original()
            arrived += 1
            if arrived >= 2:
                both_read.set()
            await asyncio.wait_for(both_read.wait(), timeout=10)
            return found

        monkeypatch.setattr(service, "has_enabled_administrator", held)


async def _provision(service: AuthService, username: str) -> Any:
    return await service.provision_first_administrator(
        username=username, password=_PASSWORD, actor="test", **provision_totp()
    )


async def _provisioned_rows(store: MessageStore) -> list[dict[str, Any]]:
    return [
        json.loads(r["detail"]) for r in await store.list_audit() if r["action"] == _PROVISIONED
    ]


async def _open_pair(tmp_path: Path, shared: bool) -> list[MessageStore]:
    if not shared:
        one = await MessageStore.open(":memory:")
        return [one, one]
    db = str(tmp_path / "provision.db")
    first = await MessageStore.open(db)
    return [first, await MessageStore.open(db)]


async def _close_pair(stores: list[MessageStore]) -> None:
    for s in dict.fromkeys(stores):
        await s.close()


@pytest.mark.parametrize("shared", [False, True], ids=["one-store", "two-stores-one-file"])
async def test_two_runs_with_different_usernames_make_one_administrator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shared: bool
) -> None:
    stores = await _open_pair(tmp_path, shared)
    try:
        services = [AuthService(s, AuthSettings()) for s in stores]
        for service in services:
            await service.initialize()
        _hold_both_after_the_read(services, monkeypatch)
        outcomes = await asyncio.gather(
            _provision(services[0], "site-admin-one"),
            _provision(services[1], "site-admin-two"),
            return_exceptions=True,
        )
        refused = [o for o in outcomes if isinstance(o, FirstAdministratorRefused)]
        won = [o for o in outcomes if not isinstance(o, BaseException)]
        assert len(refused) == 1 and len(won) == 1, outcomes
        assert "another enabled Administrator was created while this command ran" in str(refused[0])
        assert "remove any authenticator entry" in str(refused[0])
        # One enabled Administrator, and it is the winner's account.
        assert await enabled_admins(stores[0]) == {won[0].user_id}
        assert won[0].recovery_codes
        # The loser wrote no provisioned row; its account holds no role.
        [row] = await _provisioned_rows(stores[0])
        assert row["username"] == won[0].username
        loser_name = ({"site-admin-one", "site-admin-two"} - {won[0].username}).pop()
        loser = await stores[0].get_user_by_username(loser_name)
        assert loser is not None
        assert await stores[0].get_user_role_ids(loser.id) == []
    finally:
        await _close_pair(stores)


async def test_a_grant_that_loses_to_another_process_is_refused_through_sqlite_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two stores on one file, as two ``provision-admin`` processes. The second run's grant reads
    before the first commits and writes after, so SQLite fails its write with
    ``SQLITE_BUSY_SNAPSHOT``. The re-run reads the committed Administrator and refuses."""
    stores = await _open_pair(tmp_path, True)
    try:
        monkeypatch.setattr(store_module, "_ADMIN_GRANT_BUSY_BACKOFF_SECONDS", 0.0)
        services = [AuthService(s, AuthSettings()) for s in stores]
        for service in services:
            await service.initialize()
        _hold_both_after_the_read(services, monkeypatch)
        b_read = asyncio.Event()
        a_granted = asyncio.Event()
        in_grant = False
        held_once = False
        busy_seen = 0
        real_write = stores[1]._write_user
        real_grant_b = stores[1].grant_first_admin_unless_admin_exists
        real_grant_a = stores[0].grant_first_admin_unless_admin_exists

        async def write_b(user_id: str, change: Any) -> Any:
            nonlocal held_once, busy_seen
            if in_grant and not held_once:
                held_once = True
                b_read.set()
                await asyncio.wait_for(a_granted.wait(), timeout=10)
            try:
                return await real_write(user_id, change)
            except sqlite3.OperationalError as exc:
                busy_seen += store_module._is_sqlite_busy(exc)
                raise

        async def grant_b(*a: Any, **k: Any) -> AdminGrant:
            nonlocal in_grant
            in_grant = True
            return await real_grant_b(*a, **k)

        async def grant_a(*a: Any, **k: Any) -> AdminGrant:
            await asyncio.wait_for(b_read.wait(), timeout=10)
            try:
                return await real_grant_a(*a, **k)
            finally:
                a_granted.set()

        monkeypatch.setattr(stores[1], "_write_user", write_b)
        monkeypatch.setattr(stores[1], "grant_first_admin_unless_admin_exists", grant_b)
        monkeypatch.setattr(stores[0], "grant_first_admin_unless_admin_exists", grant_a)
        outcomes: tuple[Any, ...] = await asyncio.gather(
            _provision(services[0], "site-admin-one"),
            _provision(services[1], "site-admin-two"),
            return_exceptions=True,
        )
        first, second = outcomes
        assert not isinstance(first, BaseException), first
        assert isinstance(second, FirstAdministratorRefused), second
        assert busy_seen >= 1, "the losing write must have met SQLite's busy answer"
        assert await enabled_admins(stores[0]) == {first.user_id}
        assert len(await _provisioned_rows(stores[0])) == 1
    finally:
        await _close_pair(stores)


async def test_mutation_control_an_unguarded_grant_lets_both_runs_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the check-then-write patched back in, the race above makes two Administrators. This is
    what makes the race test's one-Administrator assertion discriminating."""
    store = await MessageStore.open(":memory:")
    try:
        services = [AuthService(store, AuthSettings()) for _ in range(2)]
        for service in services:
            await service.initialize()
        monkeypatch.setattr(store, "grant_first_admin_unless_admin_exists", _unguarded_grant(store))
        _hold_both_after_the_read(services, monkeypatch)
        outcomes = await asyncio.gather(
            _provision(services[0], "site-admin-one"),
            _provision(services[1], "site-admin-two"),
            return_exceptions=True,
        )
        assert not any(isinstance(o, BaseException) for o in outcomes), outcomes
        assert len(await enabled_admins(store)) == 2
        assert len(await _provisioned_rows(store)) == 2
    finally:
        await store.close()


# --- the #3025 fold-in: no Administrator over another run's credential -----------------------------


async def test_a_password_beside_another_runs_totp_is_never_granted(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two runs on ONE row: after this run enabled its TOTP, the other run's ``set_password`` lands.
    The row then holds a password this run did not write beside a TOTP the other run did not
    stage, so this run is refused and the row stays roleless. A re-run completes it."""
    service = AuthService(store, AuthSettings())
    await service.initialize()
    real_enable = store.enable_totp

    async def then_a_rival_password(user_id: str, **kwargs: Any) -> bool:
        enabled = await real_enable(user_id, **kwargs)
        await store.set_password(
            user_id,
            password_hash="synthetic-hash-of-the-other-run",
            password_generated=False,
            must_change_password=False,
        )
        return enabled

    monkeypatch.setattr(store, "enable_totp", then_a_rival_password)
    with pytest.raises(FirstAdministratorRefused, match="granted no role") as refusal:
        await _provision(service, "site-admin")
    assert "remove any authenticator entry" in str(refusal.value)
    row = await store.get_user_by_username("site-admin")
    assert row is not None
    assert await store.get_user_role_ids(row.id) == []
    assert await enabled_admins(store) == set()
    assert await _provisioned_rows(store) == []

    # Paired control: with the rival gone, the same command completes the row.
    monkeypatch.undo()
    outcome = await _provision(service, "site-admin")
    assert outcome.repaired is True
    assert await enabled_admins(store) == {row.id}
