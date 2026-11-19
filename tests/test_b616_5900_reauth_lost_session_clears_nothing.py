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
    STEP_UP_ACTION_MFA_ENROLL,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.row_seal import (
    SESSION_KIND,
    USER_KIND,
    RowSealer,
    RowSealError,
    RowSealUnverifiableError,
    TransitSealUnavailableError,
)
from messagefoundry.store.store import AuditAppend, MessageStore, full_authentication_snapshot

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


async def test_a_store_error_at_the_clear_raises_and_grants_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The clear runs after the rotation. A store error there that the read-back cannot settle
    leaves the compare-and-set's answer on the account unknown, so the re-auth fails closed: it
    raises, mints no purpose grant, marks no address known and hands back no rotated token, and
    clears nothing. Its ``auth.reauth`` row is the interrupted one."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))

        async def refused(user_id: str, **kwargs: Any) -> None:
            raise OSError("synthetic store refusal")

        marked: list[str | None] = []

        async def mark(user_id: str, client: str | None, **kwargs: Any) -> None:
            marked.append(client)

        monkeypatch.setattr(store, "record_login_success", refused)
        monkeypatch.setattr(service, "_mark_login_address_known", mark)
        monkeypatch.setattr("messagefoundry.auth.service._REAUTH_READBACK_PAUSES", (0.0,))
        with pytest.raises(OSError, match="synthetic store refusal"):
            await service.reauth(identity, GOOD, token=token, purpose=STEP_UP_ACTION_MFA_ENROLL)
        assert not service._action_step_up_grants
        assert marked == []
        rows = [json.loads(r["detail"]) for r in await store.list_audit(action="auth.reauth")]
        assert len(rows) == before + 1
        assert rows[0]["interrupted"] is True and rows[0]["session_lost"] is True
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
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
    """A Vault transit Outage at the account record's seal ends no session (ADR 0217's Outage
    row): it is paged, no seal row is written, nothing is cleared, and the caller keeps its rotated
    token."""
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
    row; the re-auth raises, hands back no token, and writes its interrupted row itself."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        reauth_rows = len(await store.list_audit(action="auth.reauth"))

        async def refuse_append(*_a: object, **_k: object) -> object:
            raise RuntimeError("synthetic audit append refusal")

        monkeypatch.setattr(store, "_append_audits", refuse_append)
        monkeypatch.setattr("messagefoundry.auth.service._REAUTH_READBACK_PAUSES", (0.0,))
        with pytest.raises(RuntimeError, match="synthetic audit append refusal"):
            await service.reauth(identity, GOOD, token=token)
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
    """The store refuses the clear and then the row too, as one fault would. The clear's error
    propagates, the row being written softly beside it: no token is handed back, and nothing is
    cleared."""
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
        monkeypatch.setattr("messagefoundry.auth.service._REAUTH_READBACK_PAUSES", (0.0,))
        with pytest.raises(OSError, match="synthetic store refusal"):
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
        teed = _record_tees(monkeypatch)

        async def committed_then_lost(user_id: str, **kwargs: Any) -> Any:
            # The raise comes at the commit, so the store's own tee after it never runs.
            with monkeypatch.context() as m:
                m.setattr("messagefoundry.store.store.tee_audits", lambda *a, **k: None)
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
        # The committed rows are teed off-box once each, by their own anchors, so the off-box log
        # has no gap where the store's tee did not run.
        committed = [
            dict(r)
            for action in ("auth.reauth", "auth.login_after_failures")
            for r in (await store.list_audit(action=action, limit=1))
        ]
        wanted = sorted(
            (r["action"], r["actor"], r["detail"], r["ts"], r["id"], r["seq"], r["row_hash"])
            for r in committed
        )
        got = sorted(
            (t["action"], t["actor"], t["detail"], t["ts"], t["row_id"], t["seq"], t["row_hash"])
            for t in teed
            if t["action"] in ("auth.reauth", "auth.login_after_failures")
        )
        assert got == wanted
    finally:
        await store.close()


def _record_tees(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    teed: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "messagefoundry.store.store.emit_audit_tee", lambda **kwargs: teed.append(kwargs)
    )
    return teed


async def test_a_decoy_row_at_the_same_instant_does_not_read_as_cleared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The write raised with nothing committed, but rows another writer committed share its
    timestamp and action: one with the same actor and another detail, as another engine shard's
    re-auth writes, and one with a case-variant actor and the very detail. Neither is this write's
    row, so the clear's outcome is not settled: the re-auth raises and writes its own row."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)

        async def decoys_then_lost(user_id: str, **kwargs: Any) -> Any:
            now = kwargs["now"]
            mine = kwargs["audits"][0]
            await store.record_audit(
                mine.action, actor=mine.actor, detail='{"another": "shard"}', now=now
            )
            await store.record_audit(mine.action, actor="BOB", detail=mine.detail, now=now)
            raise OSError("synthetic connection lost before the commit")

        real_read = store.list_audit

        async def loose_actor_filter(**kwargs: Any) -> Any:
            # SQL Server's collation compares the actor case-insensitively; this drops the filter
            # so the case-variant decoy reaches the service's own comparison on SQLite too.
            kwargs.pop("actor", None)
            return await real_read(**kwargs)

        monkeypatch.setattr(store, "record_login_success", decoys_then_lost)
        monkeypatch.setattr(store, "list_audit", loose_actor_filter)
        monkeypatch.setattr("messagefoundry.auth.service._REAUTH_READBACK_PAUSES", (0.0,))
        before = len(await store.list_audit(action="auth.reauth"))
        with pytest.raises(OSError, match="before the commit"):
            await service.reauth(identity, GOOD, token=token)
        # The two decoys and the re-auth's own interrupted row.
        assert len(await store.list_audit(action="auth.reauth")) == before + 3
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()


async def test_a_commit_made_visible_late_still_reads_as_cleared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The write raised and its commit is not yet visible at the first read-back; it lands before
    a later one. The read-back is retried, so it still reads as cleared: one row, one notice."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))
        real_write = store.record_login_success
        real_read = store.list_audit
        pending: dict[str, Any] = {}

        async def lost(user_id: str, **kwargs: Any) -> Any:
            pending.update(user_id=user_id, kwargs=kwargs)
            raise OSError("synthetic connection lost during the commit")

        async def commit_lands_after_first_read(**kwargs: Any) -> Any:
            rows = await real_read(**kwargs)
            if pending:
                found = dict(pending)
                pending.clear()
                await real_write(found["user_id"], **found["kwargs"])
            return rows

        monkeypatch.setattr(store, "record_login_success", lost)
        monkeypatch.setattr(store, "list_audit", commit_lands_after_first_read)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok and out.token is not None
        assert len(await real_read(action="auth.reauth")) == before + 1
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == 0
        assert len([e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]) == 1
    finally:
        await store.close()


async def test_a_read_back_missing_a_later_row_still_reads_as_cleared(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The reset and both rows committed, then the store raised, and the read-back finds the
    ``auth.reauth`` row carrying this write's ``clear_id`` but not the
    ``auth.login_after_failures`` row. That row commits only with the reset, so the clear reads as
    cleared: one ``auth.reauth`` row, the counter cleared, one notice, the row found teed, and a
    warning naming how many rows were read back."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))
        real_write = store.record_login_success
        real_read = store.list_audit
        teed = _record_tees(monkeypatch)

        async def committed_then_lost(user_id: str, **kwargs: Any) -> Any:
            with monkeypatch.context() as m:
                m.setattr("messagefoundry.store.store.tee_audits", lambda *a, **k: None)
                await real_write(user_id, **kwargs)
            raise OSError("synthetic connection lost after the commit")

        async def hides_the_flag_row(**kwargs: Any) -> Any:
            if kwargs.get("action") == "auth.login_after_failures":
                return []
            return await real_read(**kwargs)

        monkeypatch.setattr(store, "record_login_success", committed_then_lost)
        monkeypatch.setattr(store, "list_audit", hides_the_flag_row)
        caplog.set_level("WARNING", logger="messagefoundry.auth.service")
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok and out.token is not None
        reauth_rows = await real_read(action="auth.reauth")
        assert len(reauth_rows) == before + 1
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == 0
        assert len([e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]) == 1
        found = dict(reauth_rows[0])
        assert [
            (t["action"], t["detail"], t["seq"], t["row_hash"])
            for t in teed
            if t["action"] in ("auth.reauth", "auth.login_after_failures")
        ] == [(found["action"], found["detail"], found["seq"], found["row_hash"])]
        assert "read back only 1 of the 2 rows" in caplog.text
    finally:
        await store.close()


def _commit_then_lose(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> Callable[..., Awaitable[Any]]:
    real_write = store.record_login_success

    async def committed_then_lost(user_id: str, **kwargs: Any) -> Any:
        # The raise comes at the commit, so the store's own tee after it never runs.
        with monkeypatch.context() as m:
            m.setattr("messagefoundry.store.store.tee_audits", lambda *a, **k: None)
            await real_write(user_id, **kwargs)
        raise OSError("synthetic connection lost after the commit")

    return committed_then_lost


async def test_a_later_row_read_that_raises_keeps_the_found_row(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The reset and both rows committed, then the store raised. The read-back finds the
    ``clear_id`` ``auth.reauth`` row, and the read of the ``auth.login_after_failures`` row raises.
    The clear reads as cleared: one ``auth.reauth`` row, the counter cleared, one notice, the row
    found teed, and a warning naming how many rows were read back."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))
        real_read = store.list_audit
        teed = _record_tees(monkeypatch)

        async def flag_row_read_raises(**kwargs: Any) -> Any:
            if kwargs.get("action") == "auth.login_after_failures":
                raise OSError("synthetic read refused")
            return await real_read(**kwargs)

        monkeypatch.setattr(store, "record_login_success", _commit_then_lose(store, monkeypatch))
        monkeypatch.setattr(store, "list_audit", flag_row_read_raises)
        caplog.set_level("WARNING", logger="messagefoundry.auth.service")
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok and out.token is not None
        reauth_rows = await real_read(action="auth.reauth")
        assert len(reauth_rows) == before + 1
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == 0
        assert len([e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]) == 1
        found = dict(reauth_rows[0])
        assert [
            (t["action"], t["detail"], t["seq"], t["row_hash"])
            for t in teed
            if t["action"] in ("auth.reauth", "auth.login_after_failures")
        ] == [(found["action"], found["detail"], found["seq"], found["row_hash"])]
        assert "read back only 1 of the 2 rows" in caplog.text
    finally:
        await store.close()


async def test_a_first_read_that_raises_does_not_end_the_read_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reset and both rows committed, then the store raised, and the first read-back raises
    too. A later read finds the rows, so the clear reads as cleared: one ``auth.reauth`` row, the
    counter cleared, one notice, and both committed rows teed."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))
        real_read = store.list_audit
        teed = _record_tees(monkeypatch)
        calls: list[object] = []

        async def first_read_raises(**kwargs: Any) -> Any:
            calls.append(kwargs)
            if len(calls) == 1:
                raise OSError("synthetic read refused")
            return await real_read(**kwargs)

        monkeypatch.setattr(store, "record_login_success", _commit_then_lose(store, monkeypatch))
        monkeypatch.setattr(store, "list_audit", first_read_raises)
        out = await service.reauth(identity, GOOD, token=token)
        assert out.ok and out.token is not None
        assert len(await real_read(action="auth.reauth")) == before + 1
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == 0
        assert len([e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]) == 1
        committed = []
        for action in ("auth.reauth", "auth.login_after_failures"):
            for row in await real_read(action=action, limit=1):
                r = dict(row)
                committed.append((r["action"], r["seq"], r["row_hash"]))
        committed.sort()
        assert (
            sorted(
                (t["action"], t["seq"], t["row_hash"])
                for t in teed
                if t["action"] in ("auth.reauth", "auth.login_after_failures")
            )
            == committed
        )
    finally:
        await store.close()


async def test_a_failed_read_back_logs_the_outcome_as_unknown(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The write raised and the read-back raised too, so whether the reset committed is unknown.
    The re-auth raises, and the log says it could not be read back, never that the reset wrote
    nothing."""
    store = await MessageStore.open(":memory:")
    try:
        service, _, identity, token = await _setup(store)

        async def lost(user_id: str, **kwargs: Any) -> Any:
            raise OSError("synthetic connection lost")

        async def unreadable(**kwargs: Any) -> Any:
            raise OSError("synthetic read refused")

        monkeypatch.setattr(store, "record_login_success", lost)
        monkeypatch.setattr(store, "list_audit", unreadable)
        monkeypatch.setattr("messagefoundry.auth.service._REAUTH_READBACK_PAUSES", (0.0,))
        caplog.set_level("WARNING", logger="messagefoundry.auth.service")
        with pytest.raises(OSError, match="synthetic connection lost"):
            await service.reauth(identity, GOOD, token=token)
        text = caplog.text
        assert "could not be read back" in text
        assert "wrote nothing" not in text
    finally:
        await store.close()


async def test_a_connection_lost_before_the_clear_committed_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: the same ``OSError`` with nothing committed. The read-back finds no row, which
    does not say what the compare-and-set found on the account, so the re-auth raises, writes its
    one interrupted ``auth.reauth`` row itself, clears nothing and sends no notice."""
    store = await MessageStore.open(":memory:")
    try:
        service, notifier, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))

        async def lost(user_id: str, **kwargs: Any) -> Any:
            raise OSError("synthetic connection lost before the commit")

        monkeypatch.setattr(store, "record_login_success", lost)
        monkeypatch.setattr("messagefoundry.auth.service._REAUTH_READBACK_PAUSES", (0.0,))
        with pytest.raises(OSError, match="before the commit"):
            await service.reauth(identity, GOOD, token=token)
        assert len(await store.list_audit(action="auth.reauth")) == before + 1
        user = await store.get_user("u-bob")
        assert user is not None and user.failed_attempts == SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
        assert not await store.list_audit(action="auth.login_after_failures")
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()


class _LockProbeSealer:
    """Delegates to the store's own sealer, recording, at each seal and verify, whether the
    store's writer lock or a transaction on its writer connection was held: the Vault transit
    round trips a Transit sealer makes there must never hold either (BACKLOG #5900)."""

    def __init__(self, store: MessageStore, on_seal: Callable[[], Awaitable[None]] | None) -> None:
        self._store = store
        self._inner = store._row_sealer
        self._on_seal = on_seal
        self.calls: list[tuple[str, bool, bool]] = []

    def _note(self, name: str) -> None:
        self.calls.append((name, self._store._lock.locked(), self._store._db.in_transaction))

    async def seal_async(self, kind: str, fields: Any) -> str:
        self._note("seal")
        if self._on_seal is not None:
            on_seal, self._on_seal = self._on_seal, None
            await on_seal()
        assert self._inner is not None
        return await self._inner.seal_async(kind, fields)

    async def verify_held_async(self, kind: str, fields: Any, stored: Any) -> bool:
        self._note("verify")
        assert self._inner is not None
        return await self._inner.verify_held_async(kind, fields, stored)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


async def _conditional_reset_store(
    tmp_path: Any,
) -> tuple[MessageStore, tuple[object, ...]]:
    store = await MessageStore.open(str(tmp_path / "reset.db"))
    store._row_sealer = RowSealer(bytes(32))
    await store.create_user(
        user_id="u-carol",
        username="carol",
        auth_provider="local",
        email=None,
        password_hash=hash_password(GOOD),
        password_generated=False,
        audits=(),
    )
    await store.record_login_failure("u-carol", failed_attempts=3, locked_until=None)
    user = await store.get_user("u-carol")
    assert user is not None and store._row_sealer is not None
    return store, full_authentication_snapshot(user)


async def test_the_conditional_reset_holds_no_lock_across_its_transit_work(tmp_path: Any) -> None:
    """The seal verify and the new seal, each a Vault round trip under a Transit sealer, run with
    neither the writer lock nor a writer transaction held, so a hung Transit at the user seal
    stalls no ingress commit. The reset still lands with its row."""
    store, expected = await _conditional_reset_store(tmp_path)
    try:
        probe = _LockProbeSealer(store, None)
        store._row_sealer = probe  # type: ignore[assignment]
        answer = await store.record_login_success(
            "u-carol", expected=expected, audits=[AuditAppend("auth.reauth", actor="carol")]
        )
        assert answer == "written"
        assert {name for name, _, _ in probe.calls} == {"seal", "verify"}
        assert all(not locked and not txn for _, locked, txn in probe.calls), probe.calls
        user = await store.get_user("u-carol")
        assert user is not None and user.failed_attempts == 0
        assert len(await store.list_audit(action="auth.reauth")) == 1
    finally:
        await store.close()


async def test_a_write_landing_during_the_transit_work_is_kept(tmp_path: Any) -> None:
    """A failure another writer commits between the reset's read and its locked write, here while
    the reset's seal is computed, is found by the re-read under the lock: nothing is written, the
    answer is the one that row gives, and no row is appended."""
    store, expected = await _conditional_reset_store(tmp_path)
    try:

        async def another_failure() -> None:
            if store._lock.locked():
                return  # Sealing under the lock, the defect: a write here would deadlock.
            await store.record_login_failure("u-carol", failed_attempts=4, locked_until=None)

        store._row_sealer = _LockProbeSealer(store, another_failure)  # type: ignore[assignment]
        answer = await store.record_login_success(
            "u-carol", expected=expected, audits=[AuditAppend("auth.reauth", actor="carol")]
        )
        assert answer == "lockout_changed"
        user = await store.get_user("u-carol")
        assert user is not None and user.failed_attempts == 4
        assert not await store.list_audit(action="auth.reauth")
    finally:
        await store.close()


async def test_a_write_outside_the_guard_during_the_transit_work_redoes_it(tmp_path: Any) -> None:
    """A write that leaves every guarded column as it was, here the login-time rehash, landing
    while the reset's seal is computed, makes the reset redo its seal work rather than read as the
    account changing: the reset lands over the rehash, which it keeps."""
    store, expected = await _conditional_reset_store(tmp_path)
    try:
        before = await store.get_user("u-carol")
        assert before is not None

        async def a_rehash() -> None:
            if store._lock.locked():
                return
            await store.set_password_hash("u-carol", password_hash=hash_password(WRONG))

        store._row_sealer = _LockProbeSealer(store, a_rehash)  # type: ignore[assignment]
        answer = await store.record_login_success(
            "u-carol", expected=expected, audits=[AuditAppend("auth.reauth", actor="carol")]
        )
        assert answer == "written"
        user = await store.get_user("u-carol")
        assert user is not None and user.failed_attempts == 0
        assert user.password_hash != before.password_hash
        assert len(await store.list_audit(action="auth.reauth")) == 1
    finally:
        await store.close()


async def test_a_store_error_at_the_clear_ends_the_rotated_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The raise path grants nothing, so the session the ceremony rotated is ended, as on the
    denied path, rather than left live with its token never handed back. The interrupted row says
    the session is lost and that its revoke landed."""
    store = await MessageStore.open(":memory:")
    try:
        service, _, identity, token = await _setup(store)
        before = len(await store.list_audit(action="auth.reauth"))
        real_revoke = store.revoke_session
        revoked: list[str] = []

        async def refused(user_id: str, **kwargs: Any) -> None:
            raise OSError("synthetic store refusal")

        async def spy_revoke(token_hash: str, *args: Any, **kwargs: Any) -> Any:
            revoked.append(token_hash)
            return await real_revoke(token_hash, *args, **kwargs)

        monkeypatch.setattr(store, "record_login_success", refused)
        monkeypatch.setattr(store, "revoke_session", spy_revoke)
        monkeypatch.setattr("messagefoundry.auth.service._REAUTH_READBACK_PAUSES", (0.0,))
        with pytest.raises(OSError, match="synthetic store refusal"):
            await service.reauth(identity, GOOD, token=token)
        assert len(revoked) == 1 and revoked[0] != hash_token(token)
        rotated = await store.get_session(revoked[0])
        assert rotated is not None and rotated.revoked_at is not None
        rows = [json.loads(r["detail"]) for r in await store.list_audit(action="auth.reauth")]
        assert len(rows) == before + 1
        assert rows[0]["interrupted"] is True and rows[0]["session_lost"] is True
        assert rows[0]["session_ended"] is True
        assert rows[0]["clear_raised"] is True and "clear_denied" not in rows[0]
    finally:
        await store.close()


async def test_a_refused_revoke_on_the_raise_path_is_logged_and_recorded(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The revoke on the raise path refused twice is logged as the denied path logs it, and the
    interrupted row says the session was not ended."""
    store = await MessageStore.open(":memory:")
    try:
        service, _, identity, token = await _setup(store)

        async def refused(*args: Any, **kwargs: Any) -> None:
            raise OSError("synthetic store refusal")

        monkeypatch.setattr(store, "record_login_success", refused)
        monkeypatch.setattr(store, "revoke_session", refused)
        monkeypatch.setattr("messagefoundry.auth.service._REAUTH_READBACK_PAUSES", (0.0,))
        caplog.set_level("WARNING", logger="messagefoundry.auth.service")
        with pytest.raises(OSError, match="synthetic store refusal"):
            await service.reauth(identity, GOOD, token=token)
        assert "and could not end the session it rotated" in caplog.text
        row = json.loads((await store.list_audit(action="auth.reauth"))[0]["detail"])
        assert row["session_lost"] is True and row["session_ended"] is False
    finally:
        await store.close()


async def _forge_after_preseal(store: MessageStore) -> None:
    """Rewrite a lockout column of ``u-bob`` with no seal, once, between the reset's seal work and
    its lock: a row changed outside the store, so its seal no longer holds."""
    real = store._preseal_user
    done: list[bool] = []

    async def preseal_then_forge(user_id: str, change: Any) -> Any:
        out = await real(user_id, change)
        if not done:
            done.append(True)
            async with store._lock:
                await store._db.execute("UPDATE users SET failed_attempts=9 WHERE id=?", (user_id,))
                await store._db.commit()
        return out

    store._preseal_user = preseal_then_forge  # type: ignore[method-assign]


async def test_a_row_forged_between_the_seal_work_and_the_lock_is_reported_and_denied(
    tmp_path: Any,
) -> None:
    """The locked re-read finds a row other than the one the seal work verified. Nothing decides on
    that unverified row: the seal work is redone, which verifies it, so a forged row raises its seal
    failure, which is reported, and the re-auth is denied with nothing granted."""
    store = await MessageStore.open(str(tmp_path / "forged.db"))
    store._row_sealer = RowSealer(bytes(32))
    try:
        service, notifier, identity, token = await _setup(store)
        await _forge_after_preseal(store)
        out = await service.reauth(identity, GOOD, token=token, purpose=STEP_UP_ACTION_MFA_ENROLL)
        assert out.session_lost and not out.ok and out.token is None
        assert not service._action_step_up_grants
        assert len(await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)) == 1
        assert await store.list_sessions("u-bob") == [], "the rotated session was left live"
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()


async def test_a_cancel_during_the_clear_ends_the_rotated_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancellation that lands while the clear runs grants nothing, so the rotated session is
    ended, run to completion through the cancel, and the cancellation propagates."""
    store = await MessageStore.open(":memory:")
    try:
        service, _, identity, token = await _setup(store)
        entered = asyncio.Event()

        async def hangs(user_id: str, **kwargs: Any) -> None:
            entered.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(store, "record_login_success", hangs)
        task = asyncio.ensure_future(service.reauth(identity, GOOD, token=token))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await store.list_sessions("u-bob") == [], "the rotated session was left live"
        rows = [json.loads(r["detail"]) for r in await store.list_audit(action="auth.reauth")]
        assert rows[0]["interrupted"] is True and rows[0]["session_lost"] is True
        assert rows[0]["clear_raised"] is True and rows[0]["session_ended"] is True
    finally:
        await store.close()


async def test_an_outage_at_the_clear_and_a_refused_row_end_the_rotated_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Transit Outage at the account record's seal answers refused, and the same Outage refuses
    the hard ``auth.reauth`` row. The re-auth raises, its rotated token never handed back, and the
    session it rotated is ended rather than left live with its purpose grant."""
    store = await MessageStore.open(":memory:")
    try:
        service, _, identity, token = await _setup(store)
        real_audit = store.record_audit

        async def outage(user_id: str, **kwargs: Any) -> None:
            raise _outage(user_id)

        async def refuse_reauth_row(action: str, **kwargs: Any) -> Any:
            if action == "auth.reauth":
                raise OSError("synthetic row refusal")
            return await real_audit(action, **kwargs)

        monkeypatch.setattr(store, "record_login_success", outage)
        monkeypatch.setattr(service, "_user_seal_outage", lambda refused: None)
        monkeypatch.setattr(store, "record_audit", refuse_reauth_row)
        with pytest.raises(OSError, match="synthetic row refusal"):
            await service.reauth(identity, GOOD, token=token, purpose=STEP_UP_ACTION_MFA_ENROLL)
        assert await store.list_sessions("u-bob") == [], "the rotated session was left live"
        assert not service._action_step_up_grants
    finally:
        await store.close()
