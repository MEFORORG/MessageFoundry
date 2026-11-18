# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5900: a correct re-auth password on a session that is lost before its rotation lands
clears nothing.

``AuthService.reauth`` re-proves the password, stamps the session, and rotates it. A success clears
the account's lockout counters and, after a run of failures, raises ``auth.login_after_failures``.
Before this change the clear was written inside the re-proof, before the stamp, so a session
revoked underneath the ceremony, one whose stamp failed its seal, and one whose rotation failed
still cleared the counters and raised the notice, though the caller was told to sign in again. Each
arm below must leave the counter where the failures put it and raise no notice.

All credentials here are synthetic.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from messagefoundry.auth.identity import Identity
from messagefoundry.auth.notifications import (
    LOGIN_AFTER_FAILURES,
    SUSPICIOUS_LOGIN_FAILURE_THRESHOLD,
    SecurityEvent,
)
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.row_seal import SESSION_KIND, RowSealError
from messagefoundry.store.store import MessageStore

GOOD = "Synth3tic-Pass-Phrase!!"
WRONG = "not-the-password"


@pytest.fixture(autouse=True)
def _no_failure_pad(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_sleep(deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_sleep)


class _FakeNotifier:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> bool:
        self.events.append(event)
        return True


async def _setup(store: MessageStore) -> tuple[AuthService, _FakeNotifier, Identity, str]:
    notifier = _FakeNotifier()
    service = AuthService(
        store, AuthSettings(lockout_threshold=10, require_mfa=False), security_notifier=notifier
    )
    await store.upsert_role(role_id="viewer", display_name="Viewer")
    await store.create_user(
        user_id="u-bob",
        username="bob",
        auth_provider="local",
        email=None,
        password_hash=hash_password(GOOD),
        password_generated=False,
        audits=(),
    )
    out = await service.login("bob", GOOD, client="10.0.0.7")
    assert out.ok and out.identity is not None and out.token is not None, out.error
    for _ in range(SUSPICIOUS_LOGIN_FAILURE_THRESHOLD):
        bad = await service.reauth(out.identity, WRONG, token=out.token)
        assert not bad.ok and not bad.session_lost
    return service, notifier, out.identity, out.token


def _revoke_before_stamp(service: AuthService, store: MessageStore) -> None:
    real = store.mark_session_reauthed

    async def revoked_then_stamp(token_hash: str, **kwargs: Any) -> Any:
        await store.revoke_session(token_hash)
        return await real(token_hash, **kwargs)

    store.mark_session_reauthed = revoked_then_stamp  # type: ignore[method-assign]


def _stamp_fails_its_seal(service: AuthService, store: MessageStore) -> None:
    async def refused(token_hash: str, **kwargs: Any) -> Any:
        raise RowSealError(SESSION_KIND, "synthetic")

    store.mark_session_reauthed = refused  # type: ignore[method-assign]


def _rotation_fails(service: AuthService, store: MessageStore) -> None:
    async def no_rotation(old_hash: str, *, unverifiable: list[bool] | None = None) -> None:
        return None

    service._rotate_session_hash = no_rotation  # type: ignore[method-assign]


@pytest.mark.parametrize(
    "lose", [_revoke_before_stamp, _stamp_fails_its_seal, _rotation_fails], ids=lambda f: f.__name__
)
async def test_a_correct_reauth_on_a_lost_session_clears_nothing_and_raises_no_notice(
    lose: Callable[[AuthService, MessageStore], None],
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        lose(service, store)
        out = await service.reauth(identity, GOOD, token=token, client="10.0.0.4")
        assert out.session_lost and not out.ok and out.token is None

        user = await store.get_user("u-bob")
        assert user is not None
        assert user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD, (
            "a re-auth that lost its session cleared the account's lockout counter"
        )
        feed = await service.security_events_for("bob")
        assert not [e for e in feed if e["action"] == "auth.login_after_failures"]
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()


async def test_control_a_correct_reauth_on_a_kept_session_clears_and_raises_the_notice() -> None:
    """The control for the arms above: the same setup with the session intact clears the counter
    and raises one notice, so their absences are not an artefact of the setup."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        out = await service.reauth(identity, GOOD, token=token, client="10.0.0.4")
        assert out.ok and out.token is not None
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == 0
        feed = await service.security_events_for("bob")
        assert len([e for e in feed if e["action"] == "auth.login_after_failures"]) == 1
        assert len([e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]) == 1
    finally:
        await store.close()


@pytest.mark.parametrize("locks", [False, True], ids=["failure", "lock"])
async def test_state_another_leg_writes_before_the_deferred_clear_is_kept(
    monkeypatch: pytest.MonkeyPatch, locks: bool
) -> None:
    """The clear now waits for the rotation, so it re-reads the row and writes only when the row
    still holds the lockout state the proof decided on. A failure or a lock another leg wrote at the
    rotation is kept, and the success raises no notice."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        real_elevated: Callable[..., Awaitable[Any]] = service._elevated
        attempts = SUSPICIOUS_LOGIN_FAILURE_THRESHOLD + 1
        locked_until = 9e12 if locks else None

        async def state_lands_at_rotation(*args: Any, **kwargs: Any) -> Any:
            await store.record_login_failure(
                "u-bob", failed_attempts=attempts, locked_until=locked_until
            )
            return await real_elevated(*args, **kwargs)

        monkeypatch.setattr(service, "_elevated", state_lands_at_rotation)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok
        user = await store.get_user("u-bob")
        assert user is not None
        assert (user.failed_attempts, user.locked_until) == (attempts, locked_until)
        feed = await service.security_events_for("bob")
        assert not [e for e in feed if e["action"] == "auth.login_after_failures"]
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()


async def test_a_refused_clear_after_the_rotation_still_hands_back_the_new_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The clear runs after the rotation, so a store refusal there is logged and clears nothing,
    and the caller still gets the rotated token rather than a 500 on a session it cannot reach."""
    store = await MessageStore.open(":memory:")
    try:
        service, _, identity, token = await _setup(store)

        async def refused(user_id: str, **kwargs: Any) -> None:
            raise OSError("synthetic store refusal")

        monkeypatch.setattr(store, "record_login_success", refused)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok and out.token is not None
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
    finally:
        await store.close()
