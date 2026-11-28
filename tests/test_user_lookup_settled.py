# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5520 items 4 and 12: a lookup by a key other than the id whose check raced a write is
read again rather than refused.

``_lookup_by_username`` and ``_lookup_by_directory_object_id`` back at least provision-admin, the
AD sign-in, the local sign-in's read by name and the directory rename refresh, and
``_load_user_by_federated_subject`` the federated sign-in. Each took one check and dropped whether
it had established anything, so a check that raced a delete, rename or re-key read as a record
that fails its seal (``refused``): the honest race refused the caller. They now read again while
the check raced, up to ``_CHECKED_READ_PASSES`` checks, then refuse and report the row the last
check read if it still holds the key, as ``_checked_by_id`` does for a row that raced every check;
another row holding the key by then is checked once instead. Each test stands a raced or failed
check in for the contention by stubbing ``_verified``.
Synthetic accounts only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.service import (
    AUTHORITY_SEAL_FAILED_ACTION,
    AUTHORITY_SEAL_UNVERIFIABLE_ACTION,
    AuthService,
    _SealCheck,
    _UserLookup,
)
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.row_seal import USER_KIND, TransitSealUnverifiableError
from messagefoundry.store.store import MessageStore

_OBJECT_ID = "6f1c2a4e-0000-4000-8000-000000000001"
_ISSUER = "https://idp.example.test"
_SUBJECT = "sub-0001"
_PASSES = service_module._CHECKED_READ_PASSES
#: The store reader behind each key, counted to prove a raced check reads the store again.
_READERS = {
    "username": "get_user_by_username",
    "directory-object-id": "get_user_by_directory_object_id",
    "federated-subject": "get_user_by_federated_subject",
}
_KEYS = tuple(_READERS)
#: The keys whose lookup reports ``held``; the federated loader returns the account alone.
_HELD_KEYS = ("username", "directory-object-id")


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


def _stub_verified(
    service: AuthService,
    monkeypatch: pytest.MonkeyPatch,
    answer: Callable[[int], _SealCheck | None],
) -> list[int]:
    """Make ``service._verified`` answer its n-th call on a row with ``answer(n)``, or run the real
    check where that is ``None``. Returns the call counter."""
    real = service._verified
    calls = [0]

    async def verified(user: Any) -> _SealCheck:
        if user is None:
            return await real(user)
        calls[0] += 1
        stubbed = answer(calls[0])
        return await real(user) if stubbed is None else stubbed

    monkeypatch.setattr(service, "_verified", verified)
    return calls


def _race_first(service: AuthService, monkeypatch: pytest.MonkeyPatch, races: int) -> list[int]:
    """The first ``races`` checks race a write (nothing settled); the real check after that."""
    return _stub_verified(service, monkeypatch, lambda n: _SealCheck() if n <= races else None)


def _wrap_reader(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str, *, gone_after: int | None = None
) -> list[int]:
    """Count the store reads behind ``key``; past ``gone_after`` reads, the row reads as gone."""
    name = _READERS[key]
    original = getattr(store, name)
    reads = [0]

    async def counted(*args: Any, **kw: Any) -> Any:
        reads[0] += 1
        if gone_after is not None and reads[0] > gone_after:
            return None
        return await original(*args, **kw)

    monkeypatch.setattr(store, name, counted)
    return reads


async def _account(store: MessageStore) -> None:
    await store.create_user(
        user_id="u1",
        username="jdoe",
        auth_provider="ad",
        password_generated=False,
        directory_object_id=_OBJECT_ID,
        audits=(),
    )
    await store.set_user_federated_subject("u1", _ISSUER, _SUBJECT)


async def _lookup(service: AuthService, key: str) -> _UserLookup:
    """The lookup by ``key``. The federated loader returns the account alone, so its ``held`` here
    is whether it returned one; only the tests over ``_HELD_KEYS`` ask ``held`` of a refusal."""
    if key == "username":
        return await service._lookup_by_username("jdoe")
    if key == "directory-object-id":
        return await service._lookup_by_directory_object_id(_OBJECT_ID)
    user = await service._load_user_by_federated_subject(_ISSUER, _SUBJECT)
    return _UserLookup(user, user is not None)


@pytest.mark.parametrize("key", _KEYS)
async def test_a_raced_check_is_read_again_not_refused(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """RED when: the lookup takes one check and reads a raced one as refused. Two raced checks
    are contention, not a failing seal, and each is answered by a new read of the store."""
    await _account(store)
    service = AuthService(store, AuthSettings())
    _race_first(service, monkeypatch, races=_PASSES - 1)
    reads = _wrap_reader(store, monkeypatch, key)
    found = await _lookup(service, key)
    assert found.user is not None and found.user.id == "u1"
    assert found.held and not found.refused
    assert reads[0] == _PASSES


@pytest.mark.parametrize("key", _HELD_KEYS)
async def test_a_check_that_races_every_pass_fails_closed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """Control: a row still there after every check raced is refused and reported, as
    ``_checked_by_id`` reports it, never read as passing or gone, so a writer that keeps racing the
    read cannot buy the account a pass or hide it from the integrity report."""
    await _account(store)
    service = AuthService(store, AuthSettings())
    calls = _race_first(service, monkeypatch, races=_PASSES)
    found = await _lookup(service, key)
    assert found.refused
    assert calls[0] == _PASSES
    rows = await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION, limit=100)
    assert any("u1" in str(row["detail"]) for row in rows), rows


@pytest.mark.parametrize("key", _HELD_KEYS)
async def test_a_row_gone_after_every_pass_raced_is_not_held(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """Where the last check raced and the row is then gone from the key, it reads as gone, not as
    a refused holder of a name nobody holds."""
    await _account(store)
    service = AuthService(store, AuthSettings())
    _race_first(service, monkeypatch, races=_PASSES)
    _wrap_reader(store, monkeypatch, key, gone_after=_PASSES)
    found = await _lookup(service, key)
    assert found.user is None and not found.held


@pytest.mark.parametrize("key", _HELD_KEYS)
async def test_a_failing_record_is_refused_on_its_first_check(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """Control: a check that established a failing record is refused at once, not read again, so
    a row moved off the key after a failed check cannot read as gone and have a second row minted
    beside it."""
    await _account(store)
    service = AuthService(store, AuthSettings())
    calls = _stub_verified(service, monkeypatch, lambda n: _SealCheck(failed=True))
    _wrap_reader(store, monkeypatch, key, gone_after=1)
    found = await _lookup(service, key)
    assert found.refused
    assert calls[0] == 1


@pytest.mark.parametrize("key", _KEYS)
async def test_an_account_gone_is_not_held(store: MessageStore, key: str) -> None:
    """Control: no row reads as gone, not as a record that fails its seal."""
    service = AuthService(store, AuthSettings())
    found = await _lookup(service, key)
    assert found.user is None and not found.held


async def _second_account(store: MessageStore) -> None:
    """Another account, ``u2``, which the tests below put behind the first account's key."""
    await store.create_user(
        user_id="u2",
        username="asmith",
        auth_provider="ad",
        password_generated=False,
        directory_object_id="6f1c2a4e-0000-4000-8000-000000000002",
        audits=(),
    )


def _other_row_at_final_read(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """Past the raced passes, the key's reader answers ``u2``: the first account was renamed off
    the key and another account took it before the lookup's final read."""
    name = _READERS[key]
    original = getattr(store, name)
    reads = [0]

    async def swapped(*args: Any, **kw: Any) -> Any:
        reads[0] += 1
        if reads[0] > _PASSES:
            return await store.get_user("u2")
        return await original(*args, **kw)

    monkeypatch.setattr(store, name, swapped)


@pytest.mark.parametrize("key", _KEYS)
async def test_a_different_row_at_the_final_read_is_checked_not_reported(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """RED when: after every check raced, the lookup reports whichever row now holds the key. That
    row was never checked, so an intact account that took the name after a rename would be filed
    under ``integrity.authority_seal_failed`` and its sign-in refused. It is checked once instead,
    and served when it passes."""
    await _account(store)
    await _second_account(store)
    service = AuthService(store, AuthSettings())
    calls = _race_first(service, monkeypatch, races=_PASSES)
    _other_row_at_final_read(store, monkeypatch, key)
    found = await _lookup(service, key)
    assert found.user is not None and found.user.id == "u2"
    assert not found.refused
    assert calls[0] == _PASSES + 1
    assert await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION, limit=100) == []


@pytest.mark.parametrize("key", _HELD_KEYS)
async def test_a_different_row_whose_one_check_races_is_refused_unreported(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """Control: where the different row's one check races too, nothing established anything about
    either record, so the key is refused, held, and nobody is reported."""
    await _account(store)
    await _second_account(store)
    service = AuthService(store, AuthSettings())
    _race_first(service, monkeypatch, races=_PASSES + 1)
    _other_row_at_final_read(store, monkeypatch, key)
    found = await _lookup(service, key)
    assert found.refused
    assert await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION, limit=100) == []


@pytest.mark.parametrize("key", _KEYS)
async def test_an_unverifiable_answer_propagates_unreported(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    """Pins what the lookup's docstring states: it has none of ``_checked_by_id``'s Vault transit
    arms, so an Unverifiable answer reaches the caller unreported here. The directory reconciler's
    rename reads rely on that (``test_a_transit_answer_at_a_rename_read``). RED when: the lookup
    swallows the answer, or reports it."""
    await _account(store)
    service = AuthService(store, AuthSettings())

    async def unverifiable(user: Any) -> _SealCheck:
        raise TransitSealUnverifiableError(USER_KIND, 1, 2)

    monkeypatch.setattr(service, "_verified", unverifiable)
    with pytest.raises(TransitSealUnverifiableError):
        await _lookup(service, key)
    assert await store.list_audit(action=AUTHORITY_SEAL_UNVERIFIABLE_ACTION, limit=100) == []
