# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The combined sign-in must not leave a password oracle in the audit trail (BACKLOG #1131).

ADR 0197's "no oracle" property (section 4) is about what the *caller* learns: every refused
combined sign-in answers the same string, status and padded time. But the audit trail is read by a
SEPARATE, lower-privileged reader. The built-in ``AUDITOR`` role holds ``audit:read`` (+
``monitoring:read`` + ``audit:export``) and is **not** an administrator, so it cannot see the
per-account lock-state surface, only ``GET /audit`` and the monitoring stream.

If a refused combined sign-in records a different ``auth.login_failed`` reason when the password was
right (code wrong) than when both factors were wrong, that reader can tell a right candidate
password from a wrong one, one audit row per attempt. Since the sign-in lock does not refuse a
combined sign-in, an ``audit:read`` holder could arm a target's sign-in lock, send candidate
passwords with any six digits, and read the answer off the trail -- one request per candidate, up to
the global sign-in ceiling of about 86,400 a day, against ADR 0197's design bound of 35.

These tests read the audit trail through the exact store query ``GET /audit`` runs
(``list_audit(actor=..., action=...)``) and assert an ``audit:read`` holder cannot separate the two
outcomes on the ``auth.login_failed`` reason. The counting is ADR 0197's and stays unchanged: a
right password with a wrong code still charges the second-step counter; both wrong still charges the
sign-in counter (asserted below).

**A coarser residual is documented, not closed** (the final xfail). The second-step counter is fed
only by a right factor, so sending one candidate ``lockout_threshold`` times locks it iff the
password was right, and that lock's ``auth.account_locked`` / ``auth.lock_notice`` /
``auth.login_locked`` rows are audit-visible while a live sign-in lock keeps the sign-in counter
silent. Removing them drops the ``auth.account_locked`` row AC-10 requires, so it is an owner/ADR
decision, tracked as the lock-event limb of #1131.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from _totp_clock import pin_totp_clock

from messagefoundry.auth import totp
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, login_admin

_LOCK_THRESHOLD = 3


def _lock_settings() -> AuthSettings:
    return AuthSettings(
        lockout_threshold=_LOCK_THRESHOLD, lockout_minutes=15, mfa_recovery_code_count=1
    )


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


class _Steps:
    """Pins the TOTP clock and hands out a code from a fresh step on every call."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, secret: str, start: float = 3_000_000.0
    ) -> None:
        self._monkeypatch = monkeypatch
        self._secret = secret
        self.now = start

    def next_code(self) -> str:
        self.now += totp.DEFAULT_PERIOD
        pin_totp_clock(self._monkeypatch, self.now)
        return totp.totp(self._secret, now=self.now)

    def wrong_code(self) -> str:
        live = totp.totp(self._secret, now=self.now)
        return f"{(int(live[0]) + 1) % 10}{live[1:]}"


async def _totp_admin(
    service: AuthService, monkeypatch: pytest.MonkeyPatch
) -> tuple[Identity, str, _Steps]:
    """An Administrator with TOTP active. Returns ``(identity, password, steps)``."""
    identity, token, password = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    steps = _Steps(monkeypatch, enroll.secret)
    assert (await service.confirm_mfa_enrollment(identity, steps.next_code(), token=token)).ok
    return identity, password, steps


async def _set_sign_in_lock(store: MessageStore, user_id: str) -> None:
    await store.record_login_failure(user_id, failed_attempts=3, locked_until=time.time() + 900)


async def _failed_login_details(store: MessageStore) -> list[dict[str, Any]]:
    """Every ``auth.login_failed`` detail an ``audit:read`` holder would read, newest first."""
    rows = await store.list_audit(actor=ADMIN_USERNAME, action="auth.login_failed")
    return [json.loads(r["detail"] or "{}") for r in rows]


async def test_a_refused_combined_sign_in_leaves_no_password_oracle_in_the_audit_trail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The core oracle. Under a live sign-in lock, a right-password/wrong-code attempt and a
    both-wrong attempt must record byte-identical ``auth.login_failed`` details."""
    store = await _store()
    try:
        service = AuthService(store, _lock_settings())
        identity, password, steps = await _totp_admin(service, monkeypatch)
        await _set_sign_in_lock(store, identity.user_id)

        # Attempt 1: the RIGHT candidate password, with a wrong code.
        steps.next_code()
        out = await service.login(ADMIN_USERNAME, password, totp_code=steps.wrong_code())
        assert not out.ok and out.error == "invalid credentials"

        # Attempt 2: a WRONG candidate password, with a wrong code.
        steps.next_code()
        out = await service.login(
            ADMIN_USERNAME, "not-the-passphrase", totp_code=steps.wrong_code()
        )
        assert not out.ok and out.error == "invalid credentials"

        details = await _failed_login_details(store)
        assert len(details) == 2, details
        # ``list_audit`` is newest-first, so index 0 is attempt 2 (both wrong) and index 1 is
        # attempt 1 (right password).
        both_wrong, right_password = details[0], details[1]
        assert right_password == both_wrong, (
            "the audit trail distinguishes a right candidate password from a wrong one: "
            f"right-password={right_password} both-wrong={both_wrong}"
        )
    finally:
        await store.close()


async def test_the_wrong_password_right_code_outcome_matches_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The third combined-failure shape (wrong password, right code) must record the same detail as
    the other two, so no arm of the routing table is separable in the trail."""
    store = await _store()
    try:
        service = AuthService(store, _lock_settings())
        identity, password, steps = await _totp_admin(service, monkeypatch)
        await _set_sign_in_lock(store, identity.user_id)

        code = steps.next_code()
        out = await service.login(ADMIN_USERNAME, "not-the-passphrase", totp_code=code)
        assert not out.ok

        steps.next_code()
        out = await service.login(ADMIN_USERNAME, password, totp_code=steps.wrong_code())
        assert not out.ok

        details = await _failed_login_details(store)
        assert len(details) == 2
        assert details[0] == details[1], details
    finally:
        await store.close()


async def test_a_single_refused_combined_attempt_emits_no_lock_row_visible_to_audit_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SINGLE refused combined attempt writes only ``auth.login_failed`` -- no
    ``auth.account_locked`` and no ``auth.lock_notice`` -- whichever factor was wrong, so an
    ``audit:read`` holder sees the identical single row per attempt. This covers only the one-attempt
    case; the multi-attempt lock-event residual is the xfail below."""
    for label, use_right_password in (("right-password", True), ("both-wrong", False)):
        store = await _store()
        try:
            service = AuthService(store, _lock_settings())
            identity, password, steps = await _totp_admin(service, monkeypatch)
            await _set_sign_in_lock(store, identity.user_id)
            steps.next_code()
            sent_pw = password if use_right_password else "not-the-passphrase"
            out = await service.login(ADMIN_USERNAME, sent_pw, totp_code=steps.wrong_code())
            assert not out.ok, label
            for action in ("auth.account_locked", "auth.lock_notice"):
                rows = await store.list_audit(actor=ADMIN_USERNAME, action=action)
                assert rows == [], f"{label}: unexpected {action} row: {rows}"
        finally:
            await store.close()


async def test_counting_is_unchanged_right_password_charges_the_second_step_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ADR 0197's counting must survive the fix: a right password with a wrong code charges the
    SECOND-STEP counter, and both wrong charges the SIGN-IN counter."""
    store = await _store()
    try:
        service = AuthService(store, _lock_settings())
        identity, password, steps = await _totp_admin(service, monkeypatch)

        steps.next_code()
        assert not (await service.login(ADMIN_USERNAME, password, totp_code=steps.wrong_code())).ok
        user = await store.get_user(identity.user_id)
        assert user is not None
        assert user.second_step_failed_attempts == 1, (
            "right password/wrong code left second-step alone"
        )
        assert user.failed_attempts == 0, "right password/wrong code touched the sign-in counter"

        steps.next_code()
        assert not (await service.login(ADMIN_USERNAME, "wrong", totp_code=steps.wrong_code())).ok
        user = await store.get_user(identity.user_id)
        assert user is not None
        assert user.failed_attempts == 1, "both wrong left the sign-in counter alone"
        assert user.second_step_failed_attempts == 1, "both wrong touched the second-step counter"
    finally:
        await store.close()


class _FakeNotifier:
    """Captures out-of-band security events instead of emailing them, so ``_lock_notice_due`` sees a
    wired notifier and writes its ``auth.lock_notice`` row."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    async def notify(self, event: Any) -> None:
        self.events.append(event)


async def _audit_actions(store: MessageStore) -> list[str]:
    """The audit ACTIONS an ``audit:read`` holder would see for the target, newest first."""
    rows = await store.list_audit(actor=ADMIN_USERNAME, limit=200)
    return [r["action"] for r in rows]


@pytest.mark.xfail(
    reason=(
        "Lock-event residual, the lock-event limb of BACKLOG #1131. Sending one candidate "
        "lockout_threshold times locks the second-step counter only when the password was right, "
        "and the lock's auth.account_locked / auth.lock_notice / auth.login_locked rows are "
        "audit:read-visible while a live sign-in lock keeps the sign-in counter silent. Closing it "
        "drops the auth.account_locked row ADR 0197 AC-10 requires, so it is an owner/ADR decision."
    ),
    strict=True,
)
async def test_the_lock_events_do_not_leak_which_factor_was_right_RESIDUAL(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Documents the residual: over ``lockout_threshold`` attempts, a right-password campaign and a
    both-wrong campaign must show the same audit actions to an ``audit:read`` holder. They do not
    today, so this xfails until the lock-event limb of #1131 is decided."""

    async def _campaign(use_right_password: bool) -> list[str]:
        store = await _store()
        try:
            notifier = _FakeNotifier()
            service = AuthService(store, _lock_settings(), security_notifier=notifier)
            identity, password, steps = await _totp_admin(service, monkeypatch)
            await store.set_user_notify_email(identity.user_id, email="owner@example.test")
            await _set_sign_in_lock(store, identity.user_id)
            for _ in range(_LOCK_THRESHOLD + 1):
                steps.next_code()
                sent_pw = password if use_right_password else "not-the-passphrase"
                assert not (
                    await service.login(ADMIN_USERNAME, sent_pw, totp_code=steps.wrong_code())
                ).ok
            return sorted(set(await _audit_actions(store)))
        finally:
            await store.close()

    right_actions = await _campaign(True)
    both_wrong_actions = await _campaign(False)
    assert right_actions == both_wrong_actions, (
        f"lock events leak the right factor: right-password={right_actions} "
        f"both-wrong={both_wrong_actions}"
    )
