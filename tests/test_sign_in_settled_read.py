# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3085 item 7: the directory sign-in's settled read is as strong as
``_checked_by_id``.

``AuthService._lookup_user_settled`` backs the sign-in role sync's re-read, its read-back, and the
pre-mint read. It read the account twice and took a record whose seal check raced a write on both
reads as a record that fails its seal: the sign-in was refused ``account_refused`` for contention
alone. ``_checked_by_id``, which the admin reads use, checks up to ``_CHECKED_READ_PASSES`` times
and fails closed only once every pass raced, reporting it. Each test stands a raced check in for
the contention by making ``_verified`` settle nothing on its first calls. Synthetic accounts only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.service import AuthService, _SealCheck
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


def _race_first(service: AuthService, monkeypatch: pytest.MonkeyPatch, races: int) -> list[int]:
    """Make ``service._verified`` answer its first ``races`` calls as a check that raced a write
    (nothing settled), and run the real check after that. Returns the call counter."""
    real = service._verified
    calls = [0]

    async def verified(user: Any) -> _SealCheck:
        calls[0] += 1
        if calls[0] <= races:
            return _SealCheck()
        return await real(user)

    monkeypatch.setattr(service, "_verified", verified)
    return calls


async def _account(store: MessageStore) -> None:
    await store.create_user(
        user_id="u1", username="jdoe", auth_provider="ad", password_generated=False, audits=()
    )


async def test_two_raced_checks_still_settle_on_the_account(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: ``_lookup_user_settled`` reads twice and calls a record whose two checks both
    raced refused, as a seal failure. Two raced checks are contention, not a failing seal."""
    await _account(store)
    service = AuthService(store, AuthSettings())
    _race_first(service, monkeypatch, races=2)
    stored = await service._lookup_user_settled("u1")
    assert stored.user is not None and stored.user.username == "jdoe"
    assert stored.held and not stored.refused


async def test_a_check_that_races_every_pass_fails_closed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: a record whose every check raced is still refused, never read as passing or gone,
    so the stronger read cannot be bought by a writer that keeps racing it."""
    await _account(store)
    service = AuthService(store, AuthSettings())
    _race_first(service, monkeypatch, races=service_module._CHECKED_READ_PASSES)
    stored = await service._lookup_user_settled("u1")
    assert stored.refused


async def test_an_account_gone_is_not_held(store: MessageStore) -> None:
    """Control: no row reads as gone, not as a record that fails its seal."""
    service = AuthService(store, AuthSettings())
    stored = await service._lookup_user_settled("absent")
    assert stored.user is None and not stored.held
