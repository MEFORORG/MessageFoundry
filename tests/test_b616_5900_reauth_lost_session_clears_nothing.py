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

On a kept session the clear is the store's compare-and-set (``record_login_success`` with
``expected``), carrying the ``auth.reauth`` row in its own transaction: an account changed between
the proof and the clear is kept or denied, and a raise after the proof still writes that row. The
compare itself, on all three backends, is ``tests/_lockout_store_contract.py``.

All credentials here are synthetic.
"""

from __future__ import annotations

import asyncio
import json
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
from messagefoundry.auth.service import (
    AUTHORITY_SEAL_FAILED_ACTION,
    AUTHORITY_SEAL_UNVERIFIABLE_ACTION,
    AuthService,
)
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.row_seal import (
    SESSION_KIND,
    USER_KIND,
    RowSealError,
    RowSealUnverifiableError,
    TransitSealUnavailableError,
)
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


async def test_two_concurrent_correct_reauths_flag_one_run_of_failures_once() -> None:
    """Both proofs decide the clear against the same row, so the deferred clears are serialized and
    the second finds the row changed: one reset, one ``auth.login_after_failures`` row."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        second = await service.login("bob", GOOD, client="10.0.0.8")
        assert second.ok and second.identity is not None and second.token is not None
        # The second sign-in cleared the run, so plant it again on the shared row.
        await store.record_login_failure(
            "u-bob", failed_attempts=SUSPICIOUS_LOGIN_FAILURE_THRESHOLD, locked_until=None
        )
        # That sign-in flagged the run it cleared; count only what the re-auths add.
        flagged_before = len(
            [
                e
                for e in await service.security_events_for("bob")
                if e["action"] == "auth.login_after_failures"
            ]
        )
        notices_before = len([e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES])
        outs = await asyncio.gather(
            service.reauth(identity, GOOD, token=token),
            service.reauth(second.identity, GOOD, token=second.token),
        )
        assert all(o.ok for o in outs)
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == 0
        feed = await service.security_events_for("bob")
        flagged = len([e for e in feed if e["action"] == "auth.login_after_failures"])
        notices = len([e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES])
        assert (flagged - flagged_before, notices - notices_before) == (1, 1)
    finally:
        await store.close()


def _forged(user_id: str) -> Exception:
    return RowSealError(USER_KIND, user_id)


def _unverifiable(user_id: str) -> Exception:
    return RowSealUnverifiableError(USER_KIND, user_id)


def _outage(user_id: str) -> Exception:
    return TransitSealUnavailableError("synthetic outage")


@pytest.mark.parametrize(
    ("raised", "reported"),
    [
        (_forged, AUTHORITY_SEAL_FAILED_ACTION),
        (_unverifiable, AUTHORITY_SEAL_UNVERIFIABLE_ACTION),
    ],
    ids=["forged", "unverifiable"],
)
async def test_a_refused_record_at_the_deferred_clear_is_reported_and_grants_nothing(
    monkeypatch: pytest.MonkeyPatch,
    raised: Callable[[str], Exception],
    reported: str | None,
) -> None:
    """The clear's write is refused because the account's record fails its seal or cannot be
    verified. Before the clear was deferred that raise granted nothing; now the answer is reported,
    the rotated session is ended, and the caller is told to sign in again, with no token handed
    back."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)

        async def refused(user_id: str, **kwargs: Any) -> None:
            raise raised(user_id)

        monkeypatch.setattr(store, "record_login_success", refused)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.session_lost and not out.ok and out.token is None
        for action in (AUTHORITY_SEAL_FAILED_ACTION, AUTHORITY_SEAL_UNVERIFIABLE_ACTION):
            assert len(await store.list_audit(action=action)) == (action == reported)
        assert await store.list_sessions("u-bob") == [], "the rotated session was left live"
        rows = [str(dict(r)["detail"]) for r in await store.list_audit(action="auth.reauth")]
        refused_rows = [json.loads(d) for d in rows if "clear_denied" in d]
        assert len(refused_rows) == 1
        assert refused_rows[0]["session_lost"] is True
        assert refused_rows[0]["session_ended"] is True
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()


async def test_an_outage_at_the_deferred_clear_pages_and_ends_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Vault transit Outage at the clear's write ends nothing (ADR 0217's Outage row): it is
    paged, no seal row is written, nothing is cleared, and the caller keeps its rotated token."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        paged: list[str] = []

        async def outage(user_id: str, **kwargs: Any) -> None:
            raise _outage(user_id)

        monkeypatch.setattr(store, "record_login_success", outage)
        monkeypatch.setattr(service, "_user_seal_outage", paged.append)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok and out.token is not None
        assert paged == ["re-auth's lockout reset"]
        for action in (AUTHORITY_SEAL_FAILED_ACTION, AUTHORITY_SEAL_UNVERIFIABLE_ACTION):
            assert await store.list_audit(action=action) == []
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()


async def _rebind(store: MessageStore, column: str, value: object) -> None:
    """Write one column straight to the row: the store here is keyless, so the seal is empty and the
    write stands for a re-bind another writer committed."""
    await store._db.execute(f"UPDATE users SET {column}=? WHERE id='u-bob'", (value,))
    await store._db.commit()


async def _delete(store: MessageStore) -> None:
    await store.delete_user("u-bob")


async def _disable(store: MessageStore) -> None:
    await store.set_user_disabled("u-bob", disabled=True)


async def _rebind_directory(store: MessageStore) -> None:
    await _rebind(store, "directory_object_id", "synthetic-guid-0001")


async def _rebind_provider(store: MessageStore) -> None:
    await _rebind(store, "auth_provider", "ad")


async def _end_every_session(store: MessageStore) -> None:
    # An end-every-session raise moves the account's session epoch.
    await _rebind(store, "session_epoch", 7)


@pytest.mark.parametrize(
    "change",
    [_delete, _disable, _rebind_directory, _rebind_provider, _end_every_session],
    ids=lambda f: f.__name__.lstrip("_"),
)
async def test_an_account_changed_between_proof_and_clear_is_denied(
    monkeypatch: pytest.MonkeyPatch, change: Callable[[MessageStore], Awaitable[None]]
) -> None:
    """The account is deleted, disabled or re-bound once the session has rotated and before the
    clear. The store's compare-and-set finds the row gone or changed, so nothing is cleared, the
    rotated session is asked to end, and the re-auth grants nothing."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        real_elevated: Callable[..., Awaitable[Any]] = service._elevated

        async def change_after_rotation(*args: Any, **kwargs: Any) -> Any:
            out = await real_elevated(*args, **kwargs)
            await change(store)
            return out

        monkeypatch.setattr(service, "_elevated", change_after_rotation)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.session_lost and not out.ok and out.token is None
        assert await store.list_sessions("u-bob") == [], "the rotated session was left live"
        user = await store.get_user("u-bob")
        if user is not None:
            assert user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
        rows = [
            json.loads(str(dict(r)["detail"])) for r in await store.list_audit(action="auth.reauth")
        ]
        denied = [r for r in rows if r.get("clear_denied")]
        assert len(denied) == 1 and denied[0]["session_lost"] is True
        assert not await store.list_audit(action="auth.login_after_failures")
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()


async def test_the_clear_and_its_rows_commit_together(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ``auth.reauth`` row and the ``auth.login_after_failures`` row are appended in the reset's
    own transaction. Refused there, the reset rolls back, so the counters are never reset with no
    row; the re-auth keeps its token and writes its row itself."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        reauth_rows = len(await store.list_audit(action="auth.reauth"))

        async def refuse_append(*_a: object, **_k: object) -> object:
            raise RuntimeError("synthetic audit append refusal")

        monkeypatch.setattr(store, "_append_audits", refuse_append)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok and out.token is not None
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
        assert len(await store.list_audit(action="auth.reauth")) == reauth_rows + 1
        assert not await store.list_audit(action="auth.login_after_failures")
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()


async def test_a_cleared_reauth_writes_its_row_once() -> None:
    """The control for the transaction arm: a clear that lands writes exactly one ``auth.reauth``
    row, the one committed with the reset, and one ``auth.login_after_failures`` row after it."""
    store = await MessageStore.open(":memory:")
    try:
        service, _, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok
        rows = await store.list_audit(action="auth.reauth")
        assert len(rows) == before + 1
        detail = json.loads(str(dict(rows[0])["detail"]))
        assert detail["ok"] is True and detail["session_lost"] is False
        assert "interrupted" not in detail, "a re-auth that finished reads as interrupted"
        assert len(await store.list_audit(action="auth.login_after_failures")) == 1
    finally:
        await store.close()


async def _clear_raises(service: AuthService, store: MessageStore, mp: pytest.MonkeyPatch) -> None:
    async def defect(user_id: str, **kwargs: Any) -> Any:
        raise KeyError("synthetic-defect-5900")

    mp.setattr(store, "record_login_success", defect)


async def _revoke_raises(service: AuthService, store: MessageStore, mp: pytest.MonkeyPatch) -> None:
    async def denied(decided: Any, audits: Any) -> str:
        return "denied"

    async def defect(rotated_token: str, actor: str) -> bool:
        raise KeyError("synthetic-defect-5900")

    mp.setattr(service, "_clear_after_reauth", denied)
    mp.setattr(service, "_end_reauth_rotated_session", defect)


@pytest.mark.parametrize("fault", [_clear_raises, _revoke_raises], ids=lambda f: f.__name__)
async def test_a_raise_after_the_rotation_still_writes_the_reauth_row(
    monkeypatch: pytest.MonkeyPatch,
    fault: Callable[[AuthService, MessageStore, pytest.MonkeyPatch], Awaitable[None]],
) -> None:
    """A defect raised by the clear or by the revoke of a denied clear propagates, and the rotated
    session's ``auth.reauth`` row is still written, marked interrupted, with nothing cleared."""
    store = await MessageStore.open(":memory:")
    try:
        service, _, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))
        await fault(service, store, monkeypatch)
        with pytest.raises(KeyError, match="synthetic-defect-5900"):
            await service.reauth(identity, GOOD, token=token)
        rows = await store.list_audit(action="auth.reauth")
        assert len(rows) == before + 1, "a raise after the rotation skipped the auth.reauth row"
        detail = json.loads(str(dict(rows[0])["detail"]))
        assert detail["ok"] is True and detail["interrupted"] is True
        # No token reached the caller, so the row reads the session as lost.
        assert detail["session_lost"] is True
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
    finally:
        await store.close()


async def test_a_refused_clear_and_a_refused_row_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The store refuses the clear and then the row too, as one fault would. The row is written
    hard, so the step-up is never granted unaudited: the re-auth raises, no token is handed back,
    and nothing is cleared."""
    store = await MessageStore.open(":memory:")
    try:
        service, _, identity, token = await _setup(store)
        real_audit = store.record_audit

        async def refused(user_id: str, **kwargs: Any) -> None:
            raise OSError("synthetic store refusal")

        async def refuse_reauth_row(action: str, **kwargs: Any) -> Any:
            if action == "auth.reauth":
                raise OSError("synthetic row refusal")
            return await real_audit(action, **kwargs)

        monkeypatch.setattr(store, "record_login_success", refused)
        monkeypatch.setattr(store, "record_audit", refuse_reauth_row)
        with pytest.raises(OSError, match="synthetic row refusal"):
            await service.reauth(identity, GOOD, token=token)
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
    finally:
        await store.close()


async def test_a_raise_after_a_committed_clear_adds_an_interrupted_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The clear and its rows committed, then the address record raises. The notice was already
    sent with the rows, and an interrupted ``auth.reauth`` row records the raise."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))

        async def defect(*args: Any, **kwargs: Any) -> None:
            raise KeyError("synthetic-defect-5900")

        monkeypatch.setattr(service, "_mark_login_address_known", defect)
        with pytest.raises(KeyError, match="synthetic-defect-5900"):
            await service.reauth(identity, GOOD, token=token)
        rows = [
            json.loads(str(dict(r)["detail"])) for r in await store.list_audit(action="auth.reauth")
        ]
        assert len(rows) == before + 2
        assert sorted(bool(r.get("interrupted")) for r in rows[:2]) == [False, True]
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == 0
        assert len(await store.list_audit(action="auth.login_after_failures")) == 1
        assert len([e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]) == 1
    finally:
        await store.close()


async def test_a_connection_lost_after_the_clear_committed_reads_as_cleared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reset and its rows committed, then the store raised ``OSError``, the way a connection
    lost at the socket after the commit answers. The outcome is unknown, so it is read back: the
    rows are in, so the re-auth writes no second ``auth.reauth`` row and the notice is sent."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))
        real = store.record_login_success

        async def committed_then_lost(user_id: str, **kwargs: Any) -> Any:
            await real(user_id, **kwargs)
            raise OSError("synthetic connection lost after the commit")

        monkeypatch.setattr(store, "record_login_success", committed_then_lost)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok and out.token is not None
        assert len(await store.list_audit(action="auth.reauth")) == before + 1
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == 0
        assert len(await store.list_audit(action="auth.login_after_failures")) == 1
        assert len([e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]) == 1
    finally:
        await store.close()


async def test_a_connection_lost_before_the_clear_committed_reads_as_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: the same ``OSError`` with nothing committed. The read-back finds no row, so the
    re-auth writes its one ``auth.reauth`` row itself, clears nothing and sends no notice."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))

        async def lost(user_id: str, **kwargs: Any) -> Any:
            raise OSError("synthetic connection lost before the commit")

        monkeypatch.setattr(store, "record_login_success", lost)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok and out.token is not None
        assert len(await store.list_audit(action="auth.reauth")) == before + 1
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
        assert not await store.list_audit(action="auth.login_after_failures")
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()
