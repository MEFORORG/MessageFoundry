# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1141 slice 2 and BACKLOG #2007 (ASVS 6.4.5): the reminders before an admin-issued
temporary password lapses unclaimed.

The operator gets the ``[alerts]`` event (#1141). The holder and the administrator who issued the
credential each get a security notice at their own address (#2007). The item's own trap is a
reminder loop that can never observe an unclaimed credential: it would silence the cell's absence
checks and change nothing anyone sees. So every test below drives a REAL issued credential through a
real store and asserts what reached the sink or the notifier, and the instant it names is pinned
against the login gate.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import pytest

from messagefoundry.api.app import (
    _initial_credential_expiry_reminder,
    _initial_credential_warn_lead,
    _remind_expiring_initial_credentials,
)
from messagefoundry.api.security import deadline_utc
from messagefoundry.auth import hash_password
from messagefoundry.auth import service as service_module
from messagefoundry.auth.notifications import (
    TEMPORARY_CREDENTIAL_EXPIRING,
    TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
    SecurityEvent,
)
from messagefoundry.auth.service import AuthService, IssuedCredential
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.store.store import MessageStore

_HOUR = 3600.0


class _RecordingSink(LoggingAlertSink):
    """Records the one event under test; every other AlertSink method logs as the fallback does."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def initial_credential_expiring(
        self, name: str, *, expires_at: str, hours_remaining: int
    ) -> None:
        self.events.append(
            {"name": name, "expires_at": expires_at, "hours_remaining": hours_remaining}
        )


async def _service(hours: int = 72) -> tuple[MessageStore, AuthService]:
    store = await MessageStore.open(":memory:")
    service = AuthService(store, AuthSettings(initial_password_expiry_hours=hours))
    await service.initialize()  # seeds the built-in roles; it creates no account (ADR 0183)
    await store.upsert_role(role_id="viewer", display_name="Viewer")
    return store, service


async def _issue(service: AuthService, username: str = "alice") -> tuple[str, IssuedCredential]:
    """Create a user, then admin-reset it: an unclaimed must-change credential off a stored stamp."""
    user_id = await service.create_local_user(
        username=username,
        password="a-long-enough-original-passphrase",
        display_name=None,
        email=None,
        roles=["viewer"],
        actor="admin",
    )
    return user_id, await service.admin_reset_password(user_id, actor="admin")


async def _deadline(store: MessageStore, service: AuthService, user_id: str) -> float:
    user = await store.get_user(user_id)
    assert user is not None
    deadline = service.initial_credential_deadline(user.password_changed_at)
    assert deadline is not None
    return deadline


async def _shift_deadline_to(store: MessageStore, user_id: str, deadline: float) -> None:
    """Move the stored stamp so the 72-hour deadline lands on ``deadline`` (the gate reads a clock)."""
    await store._db.execute(
        "UPDATE users SET password_changed_at=? WHERE id=?", (deadline - 72 * _HOUR, user_id)
    )
    await store._db.commit()


async def test_the_reminder_names_the_instant_the_login_gate_refuses_at() -> None:
    store, service = await _service()
    try:
        user_id, issued = await _issue(service)
        sink = _RecordingSink()
        # A real clock, so the gate below and the reminder read the same "now".
        await _shift_deadline_to(store, user_id, time.time() + 2 * _HOUR)
        deadline = await _deadline(store, service, user_id)

        await _remind_expiring_initial_credentials(
            service, sink, lead=24 * _HOUR, warned={}, now=time.time()
        )
        assert sink.events == [
            {"name": "user:alice", "expires_at": deadline_utc(deadline), "hours_remaining": 1}
        ]

        # Pin the stated instant against the gate: it works just before, and is refused just after.
        await _shift_deadline_to(store, user_id, time.time() + 1)
        assert (await service.login("alice", issued.password)).ok
        await _shift_deadline_to(store, user_id, time.time() - 1)
        assert not (await service.login("alice", issued.password)).ok
    finally:
        await store.close()


async def test_nothing_before_the_window_and_nothing_at_the_deadline() -> None:
    store, service = await _service()
    try:
        user_id, _ = await _issue(service)
        deadline = await _deadline(store, service, user_id)
        sink = _RecordingSink()
        lead = 24 * _HOUR
        for now in (deadline - lead - 1, deadline, deadline + 1):
            await _remind_expiring_initial_credentials(service, sink, lead=lead, warned={}, now=now)
        assert sink.events == []
        # POSITIVE CONTROL: the window's leading edge fires, so the zero above is not a dead loop.
        await _remind_expiring_initial_credentials(
            service, sink, lead=lead, warned={}, now=deadline - lead
        )
        assert [e["name"] for e in sink.events] == ["user:alice"]
    finally:
        await store.close()


async def test_one_reminder_per_credential_and_a_new_credential_is_reminded_again() -> None:
    store, service = await _service()
    try:
        user_id, _ = await _issue(service)
        first = await _deadline(store, service, user_id)
        sink = _RecordingSink()
        warned: dict[str, float] = {}
        for now in (first - 5 * _HOUR, first - 4 * _HOUR, first - _HOUR):
            await _remind_expiring_initial_credentials(
                service, sink, lead=24 * _HOUR, warned=warned, now=now
            )
        assert len(sink.events) == 1  # three passes inside the window, one reminder

        # A real second reset issues a new credential with a new deadline, so it is reminded about too.
        await service.admin_reset_password(user_id, actor="admin")
        second = await _deadline(store, service, user_id)
        assert second > first
        await _remind_expiring_initial_credentials(
            service, sink, lead=24 * _HOUR, warned=warned, now=second - _HOUR
        )
        assert len(sink.events) == 2
        assert sink.events[1]["expires_at"] == deadline_utc(second)
    finally:
        await store.close()


async def test_a_claimed_or_disabled_account_gets_no_reminder() -> None:
    store, service = await _service()
    try:
        claimed_id, _ = await _issue(service, "carol")
        disabled_id, _ = await _issue(service, "dave")
        live_id, _ = await _issue(service, "erin")
        # carol set her own password, so must_change_password is cleared: nothing is unclaimed.
        await store.set_password(
            claimed_id,
            password_hash=hash_password("carol-chose-this-passphrase"),
            must_change_password=False,
            password_generated=False,
        )
        await store.set_user_disabled(disabled_id, disabled=True)
        now = await _deadline(store, service, live_id) - _HOUR
        sink = _RecordingSink()
        await _remind_expiring_initial_credentials(
            service, sink, lead=24 * _HOUR, warned={}, now=now
        )
        # Only erin: carol claimed hers and the third account is disabled.
        assert [e["name"] for e in sink.events] == ["user:erin"]
    finally:
        await store.close()


async def test_the_warn_lead_is_the_last_third_capped_at_a_day_and_none_when_off() -> None:
    for hours, expected in ((72, 24 * _HOUR), (8760, 24 * _HOUR), (6, 2 * _HOUR), (0, None)):
        store, service = await _service(hours)
        try:
            assert _initial_credential_warn_lead(service) == expected, hours
        finally:
            await store.close()


async def test_the_task_reminds_on_its_first_pass_and_ends_at_once_when_off() -> None:
    store, service = await _service()
    try:
        user_id, _ = await _issue(service)
        await _shift_deadline_to(store, user_id, time.time() + _HOUR)
        sink = _RecordingSink()
        task = asyncio.create_task(_initial_credential_expiry_reminder(service, sink))
        for _ in range(200):
            if sink.events:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert [e["name"] for e in sink.events] == ["user:alice"]
    finally:
        await store.close()

    off_store, off = await _service(0)
    try:
        # No deadline, no loop: the task returns rather than polling forever for nothing.
        await asyncio.wait_for(_initial_credential_expiry_reminder(off, _RecordingSink()), 1.0)
    finally:
        await off_store.close()


# --- BACKLOG #2007: the holder and the issuing administrator ------------------------------------


class _RecordingNotifier:
    """Records every notice. The real notifier drops one whose ``email`` is None, so a None here is
    a notice nobody receives."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)

    def reminders(self, holder: str) -> list[tuple[str, str, str | None, dict[str, Any]]]:
        """The reminders about ``holder``'s credential: its own, and its issuer's naming it. Other
        accounts in a test hold unclaimed credentials too, and their reminders are left out."""
        return [
            (e.event_type, e.username, e.email, dict(e.detail))
            for e in self.events
            if (e.event_type == TEMPORARY_CREDENTIAL_EXPIRING and e.username == holder)
            or (
                e.event_type == TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER
                and e.detail.get("holder") == holder
            )
        ]


async def _notified_service() -> tuple[MessageStore, AuthService, _RecordingNotifier]:
    store = await MessageStore.open(":memory:")
    notifier = _RecordingNotifier()
    service = AuthService(
        store, AuthSettings(initial_password_expiry_hours=72), security_notifier=notifier
    )
    await service.initialize()
    await store.upsert_role(role_id="viewer", display_name="Viewer")
    return store, service, notifier


async def _account(
    service: AuthService, username: str, *, email: str | None, actor: str, admin: bool = False
) -> str:
    return await service.create_local_user(
        username=username,
        password="a-long-enough-original-passphrase",
        display_name=None,
        email=email,
        roles=["administrator" if admin else "viewer"],
        actor=actor,
    )


async def _age_audit_rows(store: MessageStore, action: str, seconds: float) -> None:
    """Move every ``action`` audit row back in time, standing in for a create done long before a
    later reset. The hash chain is not verified by anything these tests run."""
    await store._db.execute("UPDATE audit_log SET ts = ts - ? WHERE action = ?", (seconds, action))
    await store._db.commit()


async def _move_created_row_to_the_stamp(store: MessageStore, user_id: str) -> None:
    """Put the account's ``user.created`` row one second after its CURRENT credential stamp, so it
    falls in the issue window whatever the wall clock did between the create and a later reset."""
    user = await store.get_user(user_id)
    assert user is not None and user.password_changed_at is not None
    await store._db.execute(
        "UPDATE audit_log SET ts = ? WHERE action = 'user.created' AND detail LIKE ?",
        (user.password_changed_at + 1, f'%"username": "{user.username}"%'),
    )
    await store._db.commit()


async def _pass(
    store: MessageStore,
    service: AuthService,
    user_id: str,
    warned: dict[str, float] | None = None,
) -> float:
    """One reminder pass an hour before ``user_id``'s deadline. Returns the deadline."""
    deadline = await _deadline(store, service, user_id)
    await _remind_expiring_initial_credentials(
        service,
        _RecordingSink(),
        lead=24 * _HOUR,
        warned={} if warned is None else warned,
        now=deadline - _HOUR,
    )
    return deadline


async def test_a_created_account_reminds_the_holder_and_the_creating_administrator() -> None:
    store, service, notifier = await _notified_service()
    try:
        await _account(service, "root", email="root@example.org", actor="provision", admin=True)
        alice = await _account(service, "alice", email="alice@example.org", actor="root")
        deadline = await _pass(store, service, alice)
        assert notifier.reminders("alice") == [
            (TEMPORARY_CREDENTIAL_EXPIRING, "alice", "alice@example.org", {"expires_at": deadline}),
            (
                TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
                "root",
                "root@example.org",
                {"expires_at": deadline, "holder": "alice"},
            ),
        ]
        # Each reminder is audited with its recipient as the actor, so each feed shows it.
        assert await _reminder_rows(store) == {
            "auth.temporary_credential_expiring": "alice",
            "auth.temporary_credential_expiring_issuer": "root",
        }
        assert [e["action"] for e in await service.security_events_for("alice")] == [
            "auth.temporary_credential_expiring"
        ]
    finally:
        await store.close()


async def test_two_rows_from_one_administrator_still_name_that_administrator() -> None:
    """A create and an immediate reset by the SAME administrator both fall in the window. They
    agree on who issued it, so that administrator is told."""
    store, service, notifier = await _notified_service()
    try:
        await _account(service, "root", email="root@example.org", actor="provision", admin=True)
        alice = await _account(service, "alice", email="alice@example.org", actor="root")
        await service.admin_reset_password(alice, actor="root")
        await _move_created_row_to_the_stamp(store, alice)
        deadline = await _pass(store, service, alice)
        assert notifier.reminders("alice")[1:] == [
            (
                TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
                "root",
                "root@example.org",
                {"expires_at": deadline, "holder": "alice"},
            )
        ]
    finally:
        await store.close()


async def test_a_reset_reminds_the_resetting_administrator_not_the_creator() -> None:
    """The issuer is whoever issued the CURRENT credential. ``user_roles.assigned_by`` still names
    the creator here, which is why the audit row is read instead."""
    store, service, notifier = await _notified_service()
    try:
        await _account(service, "root", email="root@example.org", actor="provision", admin=True)
        await _account(service, "sam", email="sam@example.org", actor="provision", admin=True)
        alice = await _account(service, "alice", email="alice@example.org", actor="root")
        await _age_audit_rows(store, "user.created", 2 * _HOUR)
        await service.admin_reset_password(alice, actor="sam")
        deadline = await _pass(store, service, alice)
        reminders = notifier.reminders("alice")
        issuer = [r for r in reminders if r[0] == TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER]
        assert issuer == [
            (
                TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
                "sam",
                "sam@example.org",
                {"expires_at": deadline, "holder": "alice"},
            )
        ]
    finally:
        await store.close()


async def test_each_recipient_is_reminded_once_per_credential() -> None:
    store, service, notifier = await _notified_service()
    try:
        await _account(service, "root", email="root@example.org", actor="provision", admin=True)
        alice = await _account(service, "alice", email="alice@example.org", actor="root")
        warned: dict[str, float] = {}
        deadline = await _deadline(store, service, alice)
        for now in (deadline - 5 * _HOUR, deadline - 4 * _HOUR, deadline - _HOUR):
            await _remind_expiring_initial_credentials(
                service, _RecordingSink(), lead=24 * _HOUR, warned=warned, now=now
            )
        assert [(r[0], r[1]) for r in notifier.reminders("alice")] == [
            (TEMPORARY_CREDENTIAL_EXPIRING, "alice"),
            (TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER, "root"),
        ]
    finally:
        await store.close()


async def test_an_account_with_no_address_is_not_redirected_and_the_issuer_is_still_told() -> None:
    store, service, notifier = await _notified_service()
    try:
        await _account(service, "root", email="root@example.org", actor="provision", admin=True)
        alice = await _account(service, "alice", email=None, actor="root")
        deadline = await _pass(store, service, alice)
        assert notifier.reminders("alice") == [
            # No address: the notifier drops it. It must not borrow the issuer's address.
            (TEMPORARY_CREDENTIAL_EXPIRING, "alice", None, {"expires_at": deadline}),
            (
                TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
                "root",
                "root@example.org",
                {"expires_at": deadline, "holder": "alice"},
            ),
        ]
    finally:
        await store.close()


@pytest.mark.parametrize(
    "case",
    [
        "no_account",
        "ambiguous",
        "demoted",
        "renamed_onto",
        "blank_actor",
        "read_fails",
        "page_full",
        "disabled",
        "self_issued",
        "name_reused",
        "no_audit_row",
    ],
)
async def test_an_unresolvable_issuer_is_skipped_and_the_reason_logged(
    case: str, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, service, notifier = await _notified_service()
    try:
        root = await _account(
            service, "root", email="root@example.org", actor="provision", admin=True
        )
        await _account(service, "sam", email="sam@example.org", actor="provision", admin=True)
        holder = "alice"
        if case == "no_account":
            alice = await _account(service, "alice", email="alice@example.org", actor="ghost")
            reason = "names no current account"
        elif case == "ambiguous":
            # Created by root, then reset by sam moments later: two rows could have issued it.
            alice = await _account(service, "alice", email="alice@example.org", actor="root")
            await service.admin_reset_password(alice, actor="sam")
            await _move_created_row_to_the_stamp(store, alice)
            reason = "more than one administrator"
        elif case == "demoted":
            alice = await _account(service, "alice", email="alice@example.org", actor="root")
            await store.set_user_roles(root, ["viewer"], assigned_by="sam")
            reason = "no longer holds users:manage"
        elif case == "renamed_onto":
            # A directory rename landed the name "root" on an account after the row was written.
            alice = await _account(service, "alice", email="alice@example.org", actor="root")
            await store.record_audit(
                "auth.ad_username_refreshed",
                actor="root",
                detail='{"source": "directory", "user_id": "x"}',
            )
            reason = "has moved to an account since"
        elif case == "blank_actor":
            alice = await _account(service, "alice", email="alice@example.org", actor="root")
            await store.record_audit("user.created", actor=None, detail='{"username": "alice"}')
            reason = "names no actor"
        elif case == "read_fails":
            alice = await _account(service, "alice", email="alice@example.org", actor="root")

            async def _refuse(**_kw: Any) -> Any:
                raise RuntimeError("synthetic store failure")

            monkeypatch.setattr(store, "list_audit", _refuse)
            reason = "the issuer read failed"
        elif case == "page_full":
            alice = await _account(service, "alice", email="alice@example.org", actor="root")
            # All three creates in the window whatever the clock did, then a page of three.
            stamp = (await _deadline(store, service, alice)) - 72 * _HOUR
            await store._db.execute(
                "UPDATE audit_log SET ts = ? WHERE action = 'user.created'", (stamp + 1,)
            )
            await store._db.commit()
            monkeypatch.setattr(service_module, "_ISSUE_ROW_PAGE", 3)
            reason = "too many accounts"
        elif case == "disabled":
            alice = await _account(service, "alice", email="alice@example.org", actor="root")
            await store.set_user_disabled(root, disabled=True)
            reason = "is disabled"
        elif case == "self_issued":
            await _age_audit_rows(store, "user.created", 2 * _HOUR)
            await service.admin_reset_password(root, actor="root")
            alice, holder = root, "root"
            reason = "the holder issued it"
        elif case == "name_reused":
            alice = await _account(service, "alice", email="alice@example.org", actor="root")
            await store.delete_user(root)
            # A later account takes the freed name; it did not exist when the row was written.
            await _account(service, "root", email="new-root@example.org", actor="sam", admin=True)
            reason = "names no current account"
        else:  # no_audit_row: the issuing row is far outside the window
            alice = await _account(service, "alice", email="alice@example.org", actor="root")
            await _age_audit_rows(store, "user.created", 2 * _HOUR)
            reason = "no audit row"
        with caplog.at_level(logging.INFO, logger="messagefoundry.auth.service"):
            deadline = await _pass(store, service, alice)
        assert notifier.reminders(holder) == [
            (
                TEMPORARY_CREDENTIAL_EXPIRING,
                holder,
                f"{holder}@example.org",
                {"expires_at": deadline},
            )
        ]
        # The line for THIS holder names this reason. Other accounts in the test log their own.
        lines = [
            r.getMessage()
            for r in caplog.records
            if r.getMessage().startswith(f"temporary credential reminder for {holder}: ")
        ]
        assert len(lines) == 1
        assert "the issuing administrator was not told" in lines[0]
        assert reason in lines[0]
    finally:
        await store.close()


async def test_a_failing_notice_neither_repeats_the_alert_nor_stops_the_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, service, _ = await _notified_service()
    try:
        first = await _account(service, "alice", email="alice@example.org", actor="root")
        await _account(service, "bob", email="bob@example.org", actor="root")
        told: list[str] = []

        async def _flaky(user: Any, *, deadline: float) -> None:
            told.append(user.username)
            if user.username == "alice":
                raise RuntimeError("synthetic notice failure")

        monkeypatch.setattr(service, "remind_expiring_initial_credential", _flaky)
        sink = _RecordingSink()
        warned: dict[str, float] = {}
        deadline = await _deadline(store, service, first)
        for _ in range(2):
            await _remind_expiring_initial_credentials(
                service, sink, lead=24 * _HOUR, warned=warned, now=deadline - _HOUR
            )
        assert sorted(told) == ["alice", "bob"]
        assert sorted(e["name"] for e in sink.events) == ["user:alice", "user:bob"]
    finally:
        await store.close()


async def _reminder_rows(store: MessageStore) -> dict[str, str]:
    return {
        str(r["action"]): str(r["actor"])
        for r in await store.list_audit(limit=50)
        if str(r["action"]).startswith("auth.temporary_credential_expiring")
    }


async def test_with_no_notifier_both_reminders_still_reach_the_feeds() -> None:
    """A pull-only site has no mail relay, so the audit rows are the only channel. The issuer's
    row is written there too, not only the holder's."""
    store, service = await _service()
    try:
        await _account(service, "root", email="root@example.org", actor="provision", admin=True)
        alice = await _account(service, "alice", email="alice@example.org", actor="root")
        await _pass(store, service, alice)
        assert await _reminder_rows(store) == {
            "auth.temporary_credential_expiring": "alice",
            "auth.temporary_credential_expiring_issuer": "root",
        }
    finally:
        await store.close()


async def test_a_credential_claimed_after_the_pass_read_it_is_not_reminded() -> None:
    """The pass reads every account first; the method reads the row again before it tells anyone."""
    store, service, notifier = await _notified_service()
    try:
        await _account(service, "root", email="root@example.org", actor="provision", admin=True)
        alice = await _account(service, "alice", email="alice@example.org", actor="root")
        stale = await store.get_user(alice)
        assert stale is not None
        deadline = await _deadline(store, service, alice)
        await store.set_password(
            alice,
            password_hash=hash_password("alice-chose-this-passphrase"),
            must_change_password=False,
            password_generated=False,
        )
        await service.remind_expiring_initial_credential(stale, deadline=deadline)
        assert notifier.reminders("alice") == []
        assert await _reminder_rows(store) == {}
        # POSITIVE CONTROL: the same call on a live credential does remind.
        await service.admin_reset_password(alice, actor="root")
        live = await store.get_user(alice)
        assert live is not None
        await service.remind_expiring_initial_credential(
            live, deadline=await _deadline(store, service, alice)
        )
        assert [r[0] for r in notifier.reminders("alice")][:1] == [TEMPORARY_CREDENTIAL_EXPIRING]
    finally:
        await store.close()
