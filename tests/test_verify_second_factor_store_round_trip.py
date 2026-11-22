# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 11.2.4 (vault BACKLOG #1167 item 3): the store calls ``_verify_second_factor`` makes.

A wrong TOTP code and a replayed one both answer False after the same recovery-code walk, but
they do not make the same store round trips: a wrong code matched no step, so it never reaches
``consume_totp_step``, while a replay reaches it once and is refused there. This file records
that difference, so a change to either path shows up here rather than only in a comment.

Synthetic data only: a test administrator and a fixed synthetic TOTP secret.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from messagefoundry.auth import totp
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_admin

_SLOTS = 3  # a small recovery-code slot count, so the walk's length is easy to read


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    yield s
    await s.close()


async def _round_trips(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore, step: int | None, *, consumed: bool
) -> tuple[list[str], int]:
    """Run ``_verify_second_factor`` once for a code whose TOTP check resolves to ``step`` (``None``
    is a wrong code). ``consumed`` marks the step as already spent, so a matched code is a replay.
    Returns the store calls it made, in order, and how many argon2 verifies the walk ran."""
    service = AuthService(store, AuthSettings(mfa_recovery_code_count=_SLOTS))
    admin = await create_admin(service)

    async def secret(_user: object) -> str:
        return "SYNTHETICSECRET"

    monkeypatch.setattr(service, "_totp_secret", secret)
    monkeypatch.setattr(totp, "verify_totp_step", lambda *a, **k: step)
    if consumed and step is not None:
        assert await store.consume_totp_step(admin.user_id, step)

    calls: list[str] = []
    real_consume = store.consume_totp_step
    real_spend = store.consume_recovery_code_hash

    async def consume(user_id: str, matched: int) -> bool:
        calls.append(f"consume_totp_step({matched})")
        return await real_consume(user_id, matched)

    async def spend(user_id: str, code_hash: str) -> bool:
        calls.append("consume_recovery_code_hash")
        return await real_spend(user_id, code_hash)

    monkeypatch.setattr(store, "consume_totp_step", consume)
    monkeypatch.setattr(store, "consume_recovery_code_hash", spend)
    verifies = 0

    async def argon2(_fn: object, *_args: object) -> bool:
        nonlocal verifies
        verifies += 1
        return False  # no recovery code matches: the walk's length is what is recorded

    monkeypatch.setattr(service, "_argon2", argon2)
    user = await service._load_user(admin.user_id)
    assert user is not None
    opened = await service._opened_totp_enrolment(user)
    assert opened is not None

    assert not await service._verify_second_factor(user, "123456", opened=opened)
    return calls, verifies


async def test_a_wrong_code_makes_no_totp_store_call(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore
) -> None:
    """RED when: a code that matched no step reaches ``consume_totp_step``."""
    calls, verifies = await _round_trips(monkeypatch, store, None, consumed=False)

    assert calls == []
    assert verifies == _SLOTS


async def test_a_replay_makes_one_refused_totp_store_call_and_the_same_walk(
    monkeypatch: pytest.MonkeyPatch, store: MessageStore
) -> None:
    """RED when: a replay skips ``consume_totp_step``, or skips the recovery-code walk a wrong code
    runs, or spends a recovery code."""
    calls, verifies = await _round_trips(monkeypatch, store, 4242, consumed=True)

    assert calls == ["consume_totp_step(4242)"]
    assert verifies == _SLOTS
