# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every consumer of ``list_users`` that reports or acts on account state checks ``unreadable``
(BACKLOG #5505): the list's stand-in for a row that does not parse (``listed_users`` says which)
carries invented fields.

The lockout census and ``verify`` name such an account as failing its integrity check rather than
omit it, and the credential-reminder pass skips it and says so. Each case has a healthy twin.
Synthetic accounts only.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from pathlib import Path

import pytest

from messagefoundry.api.app import _remind_expiring_initial_credentials
from messagefoundry.auth.service import lockable_account_census
from messagefoundry.config.settings import AuthSettings, StoreSettings
from messagefoundry.store.store import MessageStore
from messagefoundry.verify import checks
from messagefoundry.verify.model import Status
from tests.test_initial_credential_reminder import (
    _HOUR,
    _issue,
    _RecordingSink,
    _service,
    _shift_deadline_to,
)


async def _user(store: MessageStore, user_id: str) -> None:
    await store.create_user(
        user_id=user_id,
        username=user_id,
        auth_provider="local",
        password_generated=False,
        audits=(),
    )


def _corrupt(path: Path, user_id: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute("UPDATE users SET failed_attempts=? WHERE id=?", ("garbage", user_id))
        conn.commit()
    finally:
        conn.close()


@pytest.mark.parametrize("corrupt", [True, False])
async def test_the_census_names_an_unreadable_account_as_failing(
    tmp_path: Path, corrupt: bool
) -> None:
    path = tmp_path / "census.db"
    store = await MessageStore.open(path)
    try:
        await _user(store, "u-healthy")
        await _user(store, "u-corrupt")
        if corrupt:
            _corrupt(path, "u-corrupt")
        census = await lockable_account_census(store, AuthSettings())
    finally:
        await store.close()
    if corrupt:
        assert census.integrity_failed == ("u-corrupt",)
        assert not census.clean
    else:  # the twin: neither account holds a password, so nothing is lockable
        assert census.integrity_failed == ()
        assert census.clean
    # Never judged on invented fields.
    assert "u-corrupt" not in census.no_way_past + census.undecryptable_totp


@pytest.mark.parametrize("corrupt", [True, False])
def test_verify_fails_and_names_an_unreadable_account(tmp_path: Path, corrupt: bool) -> None:
    """Sync, as ``verify`` is: the check runs its own event loop."""
    path = tmp_path / "verify.db"

    async def seed() -> None:
        store = await MessageStore.open(path)
        try:
            await _user(store, "u-healthy")
            await _user(store, "u-corrupt")
        finally:
            await store.close()

    asyncio.run(seed())
    if corrupt:
        _corrupt(path, "u-corrupt")
    result = checks.check_lockable_accounts(StoreSettings(path=str(path)), AuthSettings())
    if corrupt:
        assert result.status is Status.FAIL, result.detail
        assert "integrity check" in result.detail and "u-corrupt" in result.detail
        # Finding 5 of round 69e8364ab4: an unreadable account can neither enrol nor have its
        # factors reset, so an integrity-only failure offers neither remedy.
        assert "reset-mfa" not in result.detail and "enrol" not in result.detail
    else:
        assert result.status is Status.PASS, result.detail


@pytest.mark.parametrize("corrupt", [True, False])
async def test_the_reminder_pass_skips_an_unreadable_account_and_says_so(
    caplog: pytest.LogCaptureFixture, corrupt: bool
) -> None:
    store, service = await _service()
    try:
        alice, _ = await _issue(service, "alice")
        bob, _ = await _issue(service, "bob")
        for user_id in (alice, bob):
            await _shift_deadline_to(store, user_id, time.time() + 2 * _HOUR)
        if corrupt:
            await store._db.execute(
                "UPDATE users SET failed_attempts=? WHERE id=?", ("garbage", bob)
            )
            await store._db.commit()
        sink = _RecordingSink()
        with caplog.at_level(logging.WARNING, logger="messagefoundry.api.app"):
            await _remind_expiring_initial_credentials(
                service, sink, lead=24 * _HOUR, warned={}, now=time.time()
            )
    finally:
        await store.close()
    said = [r.getMessage() for r in caplog.records if "fails its integrity check" in r.getMessage()]
    names = sorted(e["name"] for e in sink.events)
    # The pass reached both accounts, so the count of skip lines below is read over a real walk:
    # the healthy account is reminded either way, and bob too when his record reads.
    assert names == (["user:alice"] if corrupt else ["user:alice", "user:bob"])
    assert len(said) == (1 if corrupt else 0)
    if corrupt:
        assert bob in said[0]
