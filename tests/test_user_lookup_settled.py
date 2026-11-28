# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5520 items 4 and 12: a lookup by username or by directory id that races a write is
read again rather than refused.

``_lookup_by_username`` and ``_lookup_by_directory_object_id`` back provision-admin and the AD
sign-in. Each took one check and dropped whether it had established anything, so a check that
raced a delete, rename or re-key read as a record that fails its seal (``refused``): the honest
race refused the caller. They now read again while the check raced, up to
``_CHECKED_READ_PASSES`` reads, as ``_lookup_user_settled`` does for the id. Each test stands a
raced check in for the contention by making ``_verified`` settle nothing on its first calls.
Synthetic accounts only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.service import AuthService, _SealCheck, _UserLookup
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

_OBJECT_ID = "6f1c2a4e-0000-4000-8000-000000000001"
#: The keys :func:`_lookups` reads by, one parametrized case each.
_KEYS = ("username", "directory-object-id")


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


def _race_first(service: AuthService, monkeypatch: pytest.MonkeyPatch, races: int) -> list[int]:
    """Make ``service._verified`` answer its first ``races`` calls on a row as a check that raced a
    write (nothing settled), and run the real check after that. Returns the call counter."""
    real = service._verified
    calls = [0]

    async def verified(user: Any) -> _SealCheck:
        if user is None:
            return await real(user)
        calls[0] += 1
        if calls[0] <= races:
            return _SealCheck()
        return await real(user)

    monkeypatch.setattr(service, "_verified", verified)
    return calls


async def _account(store: MessageStore) -> None:
    await store.create_user(
        user_id="u1",
        username="jdoe",
        auth_provider="ad",
        password_generated=False,
        directory_object_id=_OBJECT_ID,
        audits=(),
    )


def _lookups(service: AuthService) -> dict[str, Callable[[], Awaitable[_UserLookup]]]:
    return {
        "username": lambda: service._lookup_by_username("jdoe"),
        "directory-object-id": lambda: service._lookup_by_directory_object_id(_OBJECT_ID),
    }


@pytest.mark.parametrize("key", _KEYS)
async def test_a_raced_check_is_read_again_not_refused(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """RED when: the lookup takes one check and reads a raced one as refused. Two raced checks
    are contention, not a failing seal."""
    await _account(store)
    service = AuthService(store, AuthSettings())
    _race_first(service, monkeypatch, races=service_module._CHECKED_READ_PASSES - 1)
    found = await _lookups(service)[key]()
    assert found.user is not None and found.user.id == "u1"
    assert found.held and not found.refused


@pytest.mark.parametrize("key", _KEYS)
async def test_a_check_that_races_every_pass_fails_closed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """Control: a row whose every check raced is still refused, never read as passing or gone, so
    a writer that keeps racing the read cannot buy the account a pass."""
    await _account(store)
    service = AuthService(store, AuthSettings())
    calls = _race_first(service, monkeypatch, races=service_module._CHECKED_READ_PASSES)
    found = await _lookups(service)[key]()
    assert found.refused
    assert calls[0] == service_module._CHECKED_READ_PASSES


@pytest.mark.parametrize("key", _KEYS)
async def test_a_failing_record_is_refused_on_its_first_check(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """Control: a check that established a failing record is refused at once, not read again."""
    await _account(store)
    service = AuthService(store, AuthSettings())
    calls = [0]

    async def failing(user: Any) -> _SealCheck:
        calls[0] += 1
        return _SealCheck(failed=user is not None)

    monkeypatch.setattr(service, "_verified", failing)
    found = await _lookups(service)[key]()
    assert found.refused
    assert calls[0] == 1


@pytest.mark.parametrize("key", _KEYS)
async def test_an_account_gone_is_not_held(store: MessageStore, key: str) -> None:
    """Control: no row reads as gone, not as a record that fails its seal."""
    service = AuthService(store, AuthSettings())
    found = await _lookups(service)[key]()
    assert found.user is None and not found.held
