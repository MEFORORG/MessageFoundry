# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1139, slice 3 (ASVS 6.3.7, ADR 0182 Amendment A): an admin save moves the notification
address only when the administrator names a new one.

``update_user`` used to set ``notify_email`` from any non-blank profile ``email``, and sent a notice
only when the profile email changed. Both admin surfaces post the stored profile email back on every
save: ``PATCH /users/{id}`` fills an omitted field from the stored row, and the console form is
pre-filled with it. So any unrelated save -- a display-name edit, a disable -- silently copied the
profile address, which on a directory account is the directory's ``mail``, into the engine-owned
column. That is the directory repoint ADR 0182 exists to block, and on an account with no address
it is the auto-fill the Manager rejected on PR 1522.

The address now moves only through the explicit ``notify_email`` field. The profile ``email`` never
touches it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role, hash_password
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.notifications import EMAIL_CHANGED, NOTIFY_EMAIL_SET, SecurityEvent
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore

PW = "a-strong-test-passphrase"
_ACTION = "user.notify_email_changed"


class _FakeNotifier:
    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _account(store: MessageStore, *, notify: str | None, profile: str | None) -> None:
    """``u1``/``bob`` holding ``notify`` as its notification address and ``profile`` as its profile
    email. The profile is written the way the directory sync writes it, through
    ``update_user_profile``, so the two columns can differ exactly as they do on a directory account
    whose ``mail`` has moved."""
    await store.upsert_role(role_id="viewer", display_name="Viewer")
    await store.create_user(
        user_id="u1",
        username="bob",
        auth_provider="local",
        email=notify,
        password_hash=hash_password(PW),
    )
    await store.update_user_profile("u1", display_name="Bob", email=profile)


async def _rows(store: MessageStore) -> list[Any]:
    return [r for r in await store.list_audit(limit=200) if r["action"] == _ACTION]


def _address_events(notifier: _FakeNotifier) -> list[SecurityEvent]:
    return [e for e in notifier.events if e.event_type in (EMAIL_CHANGED, NOTIFY_EMAIL_SET)]


# --- the service contract ----------------------------------------------------------------------


async def test_an_unrelated_save_does_not_fill_a_blank_notification_address() -> None:
    """The PR 1522 arm: an account with no notification address and a directory-supplied profile
    email. A display-name edit posts that email back, and must not fill the address from it."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _account(store, notify=None, profile="dir@example.org")

        await service.update_user(
            "u1", display_name="Renamed", email="dir@example.org", disabled=None, actor="admin"
        )

        user = await store.get_user("u1")
        assert user is not None
        assert user.display_name == "Renamed"  # the save itself landed
        assert user.notify_email is None
        assert _address_events(notifier) == []
        assert await _rows(store) == []
    finally:
        await store.close()


async def test_an_unrelated_save_does_not_move_the_notification_address() -> None:
    """The ADR 0182 arm: the directory moved the profile email to Y while notices still go to X.
    Saving the profile with Y posted back must leave X, and must not send anything."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _account(store, notify="owner@example.org", profile="dir@example.org")

        await service.update_user(
            "u1", display_name="Renamed", email="dir@example.org", disabled=True, actor="admin"
        )

        user = await store.get_user("u1")
        assert user is not None and user.disabled  # the save itself landed
        assert user.notify_email == "owner@example.org"
        assert _address_events(notifier) == []
        assert await _rows(store) == []
    finally:
        await store.close()


async def test_changing_the_profile_email_alone_leaves_the_notification_address() -> None:
    """The profile email is a contact field. Changing it is announced to the notification address,
    as before, and the notification address stays where it was."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _account(store, notify="owner@example.org", profile="owner@example.org")

        await service.update_user(
            "u1", display_name=None, email="other@example.org", disabled=None, actor="admin"
        )

        user = await store.get_user("u1")
        assert user is not None
        assert user.email == "other@example.org"
        assert user.notify_email == "owner@example.org"
        changed = [e for e in notifier.events if e.event_type == EMAIL_CHANGED]
        assert len(changed) == 1
        assert changed[0].email == "owner@example.org"
        assert changed[0].detail == {"new_email": "other@example.org"}
        assert await _rows(store) == []
    finally:
        await store.close()


async def test_an_explicit_change_moves_the_address_and_tells_the_old_one() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _account(store, notify="owner@example.org", profile="dir@example.org")

        await service.update_user(
            "u1",
            display_name="Bob",
            email="dir@example.org",
            disabled=None,
            notify_email="  new@example.org  ",
            actor="admin",
        )

        user = await store.get_user("u1")
        assert user is not None
        assert user.notify_email == "new@example.org"  # stripped, as every write of it is
        assert user.email == "dir@example.org"  # and the profile is untouched by it

        # The notice about the move goes to the address it moves AWAY from, which is the one the
        # legitimate holder still reads if the move was hostile or mistaken.
        [event] = _address_events(notifier)
        assert event.event_type == EMAIL_CHANGED
        assert event.email == "owner@example.org"
        assert event.detail == {"new_email": "new@example.org", "field": "notify_email"}

        [row] = await _rows(store)
        assert row["actor"] == "admin"
        # The address stays out of the row, as every other write of the column records it.
        assert "new@example.org" not in (row["detail"] or "")
        assert "owner@example.org" not in (row["detail"] or "")
        assert '"had_address": true' in row["detail"]

        # And the next notice goes to the new address.
        before = len(notifier.events)
        await service.set_roles("u1", ["viewer"], actor="admin")
        assert notifier.events[before].email == "new@example.org"
    finally:
        await store.close()


async def test_an_explicit_fill_tells_the_address_it_set() -> None:
    """An account with no address has nobody earlier to tell, so the notice goes to the new one,
    as the holder's own fill does (``fill_own_notify_email``)."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _account(store, notify=None, profile="dir@example.org")

        await service.update_user(
            "u1",
            display_name="Bob",
            email="dir@example.org",
            disabled=None,
            notify_email="typed@example.org",
            actor="admin",
        )

        user = await store.get_user("u1")
        assert user is not None and user.notify_email == "typed@example.org"
        [event] = _address_events(notifier)
        assert event.event_type == NOTIFY_EMAIL_SET
        assert event.email == "typed@example.org"
        [row] = await _rows(store)
        assert '"had_address": false' in row["detail"]
    finally:
        await store.close()


async def test_naming_the_stored_address_again_writes_and_sends_nothing() -> None:
    """The console posts the stored address back on every save, so this is the unrelated save on
    that surface."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _account(store, notify="owner@example.org", profile="dir@example.org")

        await service.update_user(
            "u1",
            display_name="Renamed",
            email="dir@example.org",
            disabled=None,
            notify_email="owner@example.org",
            actor="admin",
        )

        user = await store.get_user("u1")
        assert user is not None and user.notify_email == "owner@example.org"
        assert _address_events(notifier) == []
        assert await _rows(store) == []
    finally:
        await store.close()


@pytest.mark.parametrize("bad", ["", "   ", "x", "a@example.org, b@example.org"])
async def test_a_blank_or_malformed_address_is_refused_before_anything_is_written(
    bad: str,
) -> None:
    """Refused whole: a profile write that landed before the refusal would be a partial save the
    administrator was told failed."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _account(store, notify="owner@example.org", profile="dir@example.org")

        with pytest.raises(ValueError):
            await service.update_user(
                "u1",
                display_name="Renamed",
                email="other@example.org",
                disabled=True,
                notify_email=bad,
                actor="admin",
            )

        user = await store.get_user("u1")
        assert user is not None
        assert user.display_name == "Bob" and user.email == "dir@example.org"
        assert not user.disabled
        assert user.notify_email == "owner@example.org"
        assert notifier.events == []
    finally:
        await store.close()


# --- the JSON admin surface: PATCH /users/{id} --------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "b1139.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _api(engine: Engine) -> tuple[AuthService, str]:
    """An administrator ``boss``, and a target account holding notify X and profile Y. Per-action
    step-up binding is off, so one sign-in covers every PATCH here."""
    service = AuthService(
        engine.store, AuthSettings(require_mfa=False, require_action_step_up=False)
    )
    await service.initialize()
    boss = await service.create_local_user(
        username="boss",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    await service.set_channel_scope(boss, [ALL_CHANNELS], actor="test")
    row = await service.store.get_user(boss)
    assert row is not None and row.password_hash is not None
    await service.store.set_password(
        boss, password_hash=row.password_hash, must_change_password=False
    )
    target = await service.create_local_user(
        username="target",
        password=PW,
        display_name=None,
        email="owner@example.org",
        roles=[Role.VIEWER.value],
        actor="test",
    )
    await service.store.update_user_profile(target, display_name=None, email="dir@example.org")
    return service, target


async def _patch(
    engine: Engine, service: AuthService, target: str, body: dict[str, Any]
) -> httpx.Response:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post(
            "/auth/login", json={"username": "boss", "password": PW, "provider": "local"}
        )
        assert r.status_code == 200, r.text
        h = {"Authorization": f"Bearer {r.json()['token']}"}
        return await c.patch(f"/users/{target}", headers=h, json=body)


async def test_patch_without_the_field_leaves_the_notification_address(engine: Engine) -> None:
    """The route fills the omitted ``email`` from the stored profile. That value must not reach the
    notification address."""
    service, target = await _api(engine)
    r = await _patch(engine, service, target, {"display_name": "Renamed"})
    assert r.status_code == 200, r.text
    user = await service.store.get_user(target)
    assert user is not None
    assert user.display_name == "Renamed"
    assert user.notify_email == "owner@example.org"


async def test_patch_with_the_field_moves_the_notification_address(engine: Engine) -> None:
    service, target = await _api(engine)
    r = await _patch(engine, service, target, {"notify_email": "new@example.org"})
    assert r.status_code == 200, r.text
    user = await service.store.get_user(target)
    assert user is not None
    assert user.notify_email == "new@example.org"
    assert user.email == "dir@example.org"


@pytest.mark.parametrize("bad", [None, "", "  ", "not-an-address"])
async def test_patch_refuses_a_clear_or_a_malformed_address(
    engine: Engine, bad: str | None
) -> None:
    service, target = await _api(engine)
    r = await _patch(engine, service, target, {"display_name": "Renamed", "notify_email": bad})
    assert r.status_code == 400, r.text
    user = await service.store.get_user(target)
    assert user is not None
    assert user.notify_email == "owner@example.org"
    assert user.display_name is None  # refused whole, not half-applied
