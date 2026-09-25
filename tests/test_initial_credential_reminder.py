# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1141 slice 2 (ASVS 6.4.5): the operator reminder before an admin-issued temporary
password lapses unclaimed.

The engine hands that credential to an ADMINISTRATOR and has no channel to its holder, so the
reminder goes to the ``[alerts]`` sink. The item's own trap is a reminder loop that can never observe
an unclaimed credential: it would silence the cell's absence checks and change nothing anyone sees.
So every test below drives a REAL issued credential through a real store and asserts what reached
the sink, and the instant it names is pinned against the login gate.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from messagefoundry.api.app import (
    _initial_credential_expiry_reminder,
    _initial_credential_warn_lead,
    _remind_expiring_initial_credentials,
)
from messagefoundry.api.security import deadline_utc
from messagefoundry.auth import hash_password
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
    await service.initialize()  # the never-claimed bootstrap admin exists from here on
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
        )
        await store.set_user_disabled(disabled_id, disabled=True)
        now = await _deadline(store, service, live_id) - _HOUR
        sink = _RecordingSink()
        await _remind_expiring_initial_credentials(
            service, sink, lead=24 * _HOUR, warned={}, now=now
        )
        # Only erin. The never-claimed bootstrap "admin" is in the same window too, and is left to
        # its own reminder, which states the EARLIER of its two bounds.
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
