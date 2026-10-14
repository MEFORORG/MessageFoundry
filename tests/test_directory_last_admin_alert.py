# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3229: a directory-driven demotion of the last enabled Administrator alerts.

The console's last-administrator guard refuses a disable, delete or role change that would leave
no enabled Administrator (vault BACKLOG #2779). Two writes the directory drives never went through
it: a directory sign-in's role sync and the session reconciler. Owner ruling 2026-10-13 (#3229),
option "Apply, with alert": the directory stays authoritative, so both writes are still applied and
never refused, and a removed or compromised Administrator loses the role at once. What they add is
the ``no_enabled_administrator`` alert and an ``auth.no_enabled_administrator`` audit row when the
write leaves no enabled Administrator. The ruling accepts the cost that an all-directory
Administrator set can end up with none, noted with vault BACKLOG #2711.

Each case runs on both paths. Negative controls: another ENABLED Administrator keeps both quiet,
a DISABLED one does not, and a demotion of an account that never held Administrator is quiet.
All directory data is synthetic.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest

from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryProbe
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import NO_ENABLED_ADMINISTRATOR_ACTION, AuthService
from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    AuthSettings,
)
from messagefoundry.pipeline.alerts import LoggingAlertSink, no_enabled_administrator_alert
from messagefoundry.store.store import MessageStore

ADMINS = "cn=mf-admins,dc=test,dc=invalid"
OPERATORS = "cn=mf-operators,dc=test,dc=invalid"
#: The two directory-driven paths, by the ``via`` each reports (the role write's ``assigned_by``).
PATHS = ["ad-sync", "ad-reconcile"]


def _principal(username: str, *groups: str) -> AdPrincipal:
    return AdPrincipal(
        username=username,
        display_name=username.title(),
        email=None,
        dn=f"CN={username},OU=Staff,DC=test,DC=invalid",
        groups=frozenset(groups),
        directory_object_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{username}.test.invalid")),
    )


class _FakeLdap:
    """A directory whose ``present`` entries the test edits between passes."""

    def __init__(self) -> None:
        self.present: dict[str, AdPrincipal] = {}

    def resolve_principal(
        self, username: str, *, object_id: str | None = None
    ) -> AdPrincipal | None:
        if object_id is None:
            return self.present.get(username)
        return next((p for p in self.present.values() if p.directory_object_id == object_id), None)

    def probe_principal(self, username: str, *, object_id: str | None = None) -> DirectoryProbe:
        principal = self.resolve_principal(username, object_id=object_id)
        if principal is None:
            return DirectoryProbe(DirectoryAnswer.NOT_FOUND)
        return DirectoryProbe(DirectoryAnswer.FOUND, principal)


class _Rig:
    def __init__(self, store: MessageStore) -> None:
        self.store = store
        self.ldap = _FakeLdap()
        self.alerts: list[tuple[str, str]] = []
        settings = AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://dc.test.invalid",
            ad_user_search_base="OU=Staff,DC=test,DC=invalid",
            ad_bind_dn="CN=svc-mefor,OU=Service,DC=test,DC=invalid",
            ad_bind_password="synthetic",
            ad_session_recheck_seconds=60,
        )
        self.service = AuthService(
            store,
            settings,
            ldap=self.ldap,  # type: ignore[arg-type]
            admin_loss_alert=lambda username, via: self.alerts.append((username, via)),
        )

    async def start(self) -> None:
        await self.service.initialize()
        await self.service.set_ad_group_map(
            [(ADMINS, Role.ADMINISTRATOR.value), (OPERATORS, Role.OPERATOR.value)], actor="admin"
        )

    async def sign_in(self, username: str) -> None:
        principal = self.ldap.present[username]
        outcome = await self.service._complete_ad_login(principal, None, mfa_verified=True)
        assert outcome.ok, outcome.error

    async def directory_change(self, username: str, *groups: str, via: str) -> None:
        """The directory moves ``username`` into ``groups``; ``via`` picks the path that applies it."""
        self.ldap.present[username] = _principal(username, *groups)
        if via == "ad-sync":
            await self.sign_in(username)
        else:
            plan = await self.service.reconcile_directory_sessions()
            revoked = [(r.username, r.reason) for r in plan.revocations]
            assert revoked == [(username, "roles_changed")]

    async def local_admin(self, *, disabled: bool) -> None:
        user_id = uuid.uuid4().hex
        await self.store.create_user(
            user_id=user_id, username="admin2", auth_provider="local", password_generated=False
        )
        await self.store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], assigned_by="admin")
        if disabled:
            await self.store.set_user_disabled(user_id, disabled=True)

    async def roles(self, username: str) -> list[str]:
        user = await self.store.get_user_by_username(username)
        assert user is not None
        return list(await self.store.get_user_role_ids(user.id))

    async def rows(self) -> list[Any]:
        audit = await self.store.list_audit()
        return [r for r in audit if r["action"] == NO_ENABLED_ADMINISTRATOR_ACTION]


@pytest.fixture
async def rig() -> AsyncIterator[_Rig]:
    store = await MessageStore.open(":memory:")
    try:
        r = _Rig(store)
        await r.start()
        yield r
    finally:
        await store.close()


@pytest.mark.parametrize("via", PATHS)
async def test_demoting_the_last_enabled_administrator_is_applied_and_alerts(
    rig: _Rig, via: str
) -> None:
    """Owner ruling 2026-10-13 (#3229): applied, not refused, and the operators are told."""
    rig.ldap.present["jdoe"] = _principal("jdoe", ADMINS)
    await rig.sign_in("jdoe")
    assert await rig.roles("jdoe") == [Role.ADMINISTRATOR.value]

    await rig.directory_change("jdoe", via=via)

    assert await rig.roles("jdoe") == []  # the directory stays authoritative: nothing refused
    assert rig.alerts == [("jdoe", via)]
    rows = await rig.rows()
    assert len(rows) == 1
    assert rows[0]["actor"] == "jdoe"
    assert json.loads(rows[0]["detail"]) == {"via": via}


@pytest.mark.parametrize("via", PATHS)
async def test_another_enabled_administrator_keeps_it_quiet(rig: _Rig, via: str) -> None:
    """Negative control (#3229): the same demotion, but an enabled Administrator remains."""
    await rig.local_admin(disabled=False)
    rig.ldap.present["jdoe"] = _principal("jdoe", ADMINS)
    await rig.sign_in("jdoe")

    await rig.directory_change("jdoe", via=via)

    assert await rig.roles("jdoe") == []
    assert rig.alerts == []
    assert await rig.rows() == []


@pytest.mark.parametrize("via", PATHS)
async def test_a_disabled_administrator_does_not_count(rig: _Rig, via: str) -> None:
    """The count is of ENABLED Administrators, as the console guard's is (#3229)."""
    await rig.local_admin(disabled=True)
    rig.ldap.present["jdoe"] = _principal("jdoe", ADMINS)
    await rig.sign_in("jdoe")

    await rig.directory_change("jdoe", via=via)

    assert rig.alerts == [("jdoe", via)]
    assert len(await rig.rows()) == 1


@pytest.mark.parametrize("via", PATHS)
async def test_a_demotion_that_never_held_administrator_is_quiet(rig: _Rig, via: str) -> None:
    """No enabled Administrator exists at all here, but this write did not take one away (#3229)."""
    rig.ldap.present["jdoe"] = _principal("jdoe", OPERATORS)
    await rig.sign_in("jdoe")

    await rig.directory_change("jdoe", via=via)

    assert await rig.roles("jdoe") == []
    assert rig.alerts == []
    assert await rig.rows() == []


@pytest.mark.parametrize("via", PATHS)
async def test_a_refused_audit_row_neither_raises_nor_drops_the_alert(
    rig: _Rig, via: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The role write has happened, so a store fault in the report must not end the sign-in or the
    reconcile pass (BACKLOG #2137), and the alert goes before the row (#3229)."""
    rig.ldap.present["jdoe"] = _principal("jdoe", ADMINS)
    await rig.sign_in("jdoe")
    real = rig.store.record_audit

    async def refusing(action: str, **kwargs: Any) -> None:
        if action == NO_ENABLED_ADMINISTRATOR_ACTION:
            raise sqlite3.OperationalError("synthetic: disk I/O error")
        await real(action, **kwargs)

    monkeypatch.setattr(rig.store, "record_audit", refusing)

    await rig.directory_change("jdoe", via=via)  # completes: the sign-in or pass returns

    assert await rig.roles("jdoe") == []
    assert rig.alerts == [("jdoe", via)]
    assert await rig.rows() == []
    # The steps after the report still ran.
    actions = [r["action"] for r in await rig.store.list_audit()]
    after = "auth.ad_roles_resynced" if via == "ad-sync" else "auth.ad_session_revoked"
    assert after in actions


@pytest.mark.parametrize("via", PATHS)
async def test_a_raising_alert_callable_still_writes_the_row(rig: _Rig, via: str) -> None:
    """Only the production wrapper promises not to raise, so the service contains a raise (#3229)."""

    def raising(username: str, via: str) -> None:
        raise RuntimeError("synthetic: the alert path is down")

    rig.service._admin_loss_alert = raising
    rig.ldap.present["jdoe"] = _principal("jdoe", ADMINS)
    await rig.sign_in("jdoe")

    await rig.directory_change("jdoe", via=via)

    assert await rig.roles("jdoe") == []
    assert len(await rig.rows()) == 1


@pytest.mark.parametrize("via", PATHS)
async def test_an_unreadable_count_raises_no_alert_and_no_error(
    rig: _Rig, via: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the count cannot be read, no alert can be stated truly, and nothing raises (#3229)."""
    rig.ldap.present["jdoe"] = _principal("jdoe", ADMINS)
    await rig.sign_in("jdoe")

    async def unreadable() -> bool:
        raise sqlite3.OperationalError("synthetic: database is locked")

    monkeypatch.setattr(rig.service, "has_enabled_administrator", unreadable)

    await rig.directory_change("jdoe", via=via)

    assert await rig.roles("jdoe") == []
    assert rig.alerts == []
    assert await rig.rows() == []


def test_the_alert_callable_keys_on_the_account_and_never_raises() -> None:
    raised: list[tuple[str, str]] = []

    class _Sink(LoggingAlertSink):
        def no_enabled_administrator(self, name: str, *, via: str) -> None:
            raised.append((name, via))

    no_enabled_administrator_alert(_Sink())("jdoe", "ad-sync")
    assert raised == [("user:jdoe", "ad-sync")]

    class _Broken(LoggingAlertSink):
        def no_enabled_administrator(self, name: str, *, via: str) -> None:
            raise RuntimeError("synthetic: the sink is down")

    no_enabled_administrator_alert(_Broken())("jdoe", "ad-reconcile")  # swallowed, logged


def test_the_alert_type_is_routable_and_takes_no_control_action() -> None:
    assert "no_enabled_administrator" in _ALERT_EVENT_TYPES
    assert "no_enabled_administrator" not in _ALERT_CONTROL_EVENT_TYPES


async def test_a_loss_after_a_regrant_is_not_held_back_by_the_cooldown() -> None:
    """A sign-in's Administrator grant ends the account's cooldown, so a second loss is paged.

    Both keys come from the real producers, so a drift in either one's key grammar fails here."""
    from types import SimpleNamespace

    from messagefoundry.api.security import alert_directory_administrator_granted
    from messagefoundry.auth.service import LoginOutcome, RolesGained
    from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
    from tests.test_alert_sinks import _drain, _RecordingTransport

    transport = _RecordingTransport("webhook")
    sink = NotifierAlertSink([transport])  # the default cooldown, far longer than this test
    lose = no_enabled_administrator_alert(sink)
    state = SimpleNamespace(notifier=sink)
    regrant = LoginOutcome(
        ok=True, roles_gained=RolesGained("jdoe", frozenset({Role.ADMINISTRATOR.value}))
    )

    lose("jdoe", "ad-sync")
    alert_directory_administrator_granted(state, regrant, via="directory_sign_in_negotiate")
    lose("jdoe", "ad-sync")
    # The control: with no grant between them, the second loss is throttled.
    lose("asmith", "ad-reconcile")
    lose("asmith", "ad-reconcile")
    await _drain(sink)

    losses = [e["connection"] for e in transport.events if e["type"] == "no_enabled_administrator"]
    assert losses.count("user:jdoe") == 2
    assert losses.count("user:asmith") == 1
