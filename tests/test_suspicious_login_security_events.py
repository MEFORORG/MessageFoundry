# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1138, ASVS 6.3.5: the two suspicious-sign-in events reach the user's own pull feed.

``GET /me/security-events`` is the one channel that reaches an account with no notification address,
and the only one a site with no mail relay has. It reads ``AuthService.security_events_for``, which
selects audit rows whose ACTOR is the user and whose action starts ``auth.``.

Before this change neither 6.3.5 event wrote an audit row of its own. The attempt that crossed the
lockout threshold left only an ordinary ``auth.login_failed``, and a success after a run of failures
left only an ordinary ``auth.login_success``. The classification existed only inside the out-of-band
notice, which is dropped for an account with no address. So each test below asserts on the feed
itself, with NO notifier wired, which is the case the feed exists for. One test wires a notifier, to
pin that the row does not depend on its absence and that the notice still carries the count.

Every test also pins the negative arm, so a fix that audited on every attempt would fail here too.
"""

from __future__ import annotations

from typing import Any

import pytest
from _totp_clock import fresh_totp

from messagefoundry.auth.notifications import (
    ACCOUNT_LOCKED,
    SUSPICIOUS_LOGIN_FAILURE_THRESHOLD,
    SecurityEvent,
)
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

GOOD_PASSWORD = "Synth3tic-Pass!!"
WRONG_PASSWORD = "not-the-password"


@pytest.fixture(autouse=True)
def _no_failure_pad(monkeypatch: pytest.MonkeyPatch) -> None:
    # The failure-equalizing pad is real time, and tests/test_asvs_login_deadline.py owns that
    # property. Nothing here asserts on timing, so the one sleep site is replaced.
    async def _no_sleep(deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_sleep)


class _FakeNotifier:
    """Captures security events instead of emailing them."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def _local_user(store: MessageStore) -> None:
    # Created WITHOUT an address on purpose: the feed is the arm that must work when mail cannot.
    await store.upsert_role(role_id="viewer", display_name="Viewer")
    await store.create_user(
        user_id="u1",
        username="bob",
        auth_provider="local",
        email=None,
        password_hash=hash_password(GOOD_PASSWORD),
    )


def _actions(feed: list[dict[str, Any]], action: str) -> list[dict[str, Any]]:
    return [e for e in feed if e["action"] == action]


async def test_the_attempt_that_crosses_the_lockout_threshold_is_in_the_users_feed() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=3, require_mfa=False))
        await _local_user(store)

        for _ in range(2):
            await service.login("bob", WRONG_PASSWORD, client="10.0.0.9")
        feed = await service.security_events_for("bob")
        assert not _actions(feed, "auth.account_locked"), "no lockout row below the threshold"

        await service.login("bob", WRONG_PASSWORD, client="10.0.0.9")  # the crossing attempt
        feed = await service.security_events_for("bob")
        locked = _actions(feed, "auth.account_locked")
        assert len(locked) == 1, "the crossing attempt must leave a lockout row in the user's feed"
        # No double audit: the crossing attempt still writes exactly one ordinary failure row.
        assert len(_actions(feed, "auth.login_failed")) == 3
        # Exactly the adjacent auth.login_failed row's provider, and nothing from the notice: the
        # failure count is mailed, never written here.
        assert locked[0]["detail"] == '{"provider": "local"}'

        # A further attempt against the already-locked account is the existing auth.login_locked
        # row, never a second lockout event.
        refused = await service.login("bob", GOOD_PASSWORD, client="10.0.0.9")
        assert not refused.ok and refused.error == "account locked"
        feed = await service.security_events_for("bob")
        assert len(_actions(feed, "auth.account_locked")) == 1
        assert len(_actions(feed, "auth.login_locked")) == 1

        rows = [r for r in await store.list_audit(limit=50) if r["action"] == "auth.account_locked"]
        assert len(rows) == 1
        assert rows[0]["actor"] == "bob"
        assert rows[0]["client"] == "10.0.0.9"
    finally:
        await store.close()


async def test_a_success_after_repeated_failures_is_in_the_users_feed() -> None:
    store = await _store()
    try:
        # A high lockout threshold, so three failures do not lock and the success can happen. MFA is
        # off so the password step IS the whole sign-in: under the default, the counter clears only
        # when the second factor completes, so every password-step success until then re-flags.
        # That repeat predates this change (it sent a repeat notice before it wrote a repeat row) and
        # is reported on BACKLOG #1138 rather than pinned here.
        service = AuthService(store, AuthSettings(lockout_threshold=10, require_mfa=False))
        await _local_user(store)

        for _ in range(SUSPICIOUS_LOGIN_FAILURE_THRESHOLD):
            await service.login("bob", WRONG_PASSWORD)
        out = await service.login("bob", GOOD_PASSWORD, client="10.0.0.4")
        assert out.ok

        feed = await service.security_events_for("bob")
        flagged = _actions(feed, "auth.login_after_failures")
        assert len(flagged) == 1, "a success after failures must be labelled in the user's feed"
        assert len(_actions(feed, "auth.login_success")) == 1  # the success itself, audited once
        assert flagged[0]["detail"] == '{"provider": "local"}'

        rows = [
            r
            for r in await store.list_audit(limit=50)
            if r["action"] == "auth.login_after_failures"
        ]
        assert len(rows) == 1
        assert rows[0]["actor"] == "bob"
        assert rows[0]["client"] == "10.0.0.4"

        # The counter was cleared by that success, so the next clean sign-in is not flagged again.
        assert (await service.login("bob", GOOD_PASSWORD)).ok
        feed = await service.security_events_for("bob")
        assert len(_actions(feed, "auth.login_after_failures")) == 1
    finally:
        await store.close()


async def test_a_success_one_failure_short_of_the_threshold_is_not_flagged() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=10, require_mfa=False))
        await _local_user(store)
        for _ in range(SUSPICIOUS_LOGIN_FAILURE_THRESHOLD - 1):  # the boundary, not just "fewer"
            await service.login("bob", WRONG_PASSWORD)
        assert (await service.login("bob", GOOD_PASSWORD)).ok
        feed = await service.security_events_for("bob")
        assert not _actions(feed, "auth.login_after_failures")
    finally:
        await store.close()


async def test_a_lockout_crossed_on_the_second_factor_is_in_the_users_feed() -> None:
    """Wrong TOTP codes feed the same lockout counter, so the crossing there is the same event."""
    store = await _store()
    try:
        threshold = 3
        service = AuthService(
            store, AuthSettings(lockout_threshold=threshold, mfa_recovery_code_count=2)
        )
        boot = await service.initialize()
        assert boot is not None
        first = await service.login("admin", boot.password)
        assert first.ok and first.identity is not None and first.token is not None
        enroll = await service.begin_mfa_enrollment(first.identity)
        confirmed = await service.confirm_mfa_enrollment(
            first.identity, fresh_totp(enroll.secret), token=first.token
        )
        assert confirmed.ok

        live = fresh_totp(enroll.secret)
        wrong_code = f"{(int(live[0]) + 1) % 10}{live[1:]}"  # never the current step's code
        pending = await service.login("admin", boot.password)
        assert pending.ok and pending.token is not None
        for _ in range(threshold - 1):
            assert not (await service.verify_mfa(pending.token, wrong_code)).ok
        feed = await service.security_events_for("admin")
        assert not _actions(feed, "auth.account_locked")

        assert not (await service.verify_mfa(pending.token, wrong_code, client="10.0.0.5")).ok
        feed = await service.security_events_for("admin")
        assert len(_actions(feed, "auth.account_locked")) == 1
        # Mirrors the auth.mfa_failed row beside it, which carries no detail.
        assert _actions(feed, "auth.account_locked")[0]["detail"] is None
    finally:
        await store.close()


async def test_the_lockout_row_is_written_when_a_notifier_is_wired_too() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(lockout_threshold=3, require_mfa=False), security_notifier=notifier
        )
        await _local_user(store)
        for _ in range(3):
            await service.login("bob", WRONG_PASSWORD)
        feed = await service.security_events_for("bob")
        assert len(_actions(feed, "auth.account_locked")) == 1
        notices = [e for e in notifier.events if e.event_type == ACCOUNT_LOCKED]
        assert len(notices) == 1
        assert notices[0].detail == {"failed_attempts": 3}  # the count stays in the notice
    finally:
        await store.close()
