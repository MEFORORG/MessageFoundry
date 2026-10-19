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

from messagefoundry.api.security import DIRECTORY_GRANTED_BY
from messagefoundry.auth.ldap import AdPrincipal, DirectoryAnswer, DirectoryProbe
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.reconcile import SessionRevocation
from messagefoundry.auth.service import (
    NO_ENABLED_ADMINISTRATOR_ACTION,
    AuthService,
    _AuditWatermark,
    _RevocationApplied,
)
from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    AuthSettings,
)
from messagefoundry.pipeline.alerts import (
    LoggingAlertSink,
    administrator_granted_alert,
    no_enabled_administrator_alert,
)
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
    def __init__(self, store: MessageStore, **overrides: Any) -> None:
        self.store = store
        self.ldap = _FakeLdap()
        self.alerts: list[tuple[str, str]] = []
        #: What the vault BACKLOG #3141 grant callable was handed, ``(username, via)``.
        self.grants: list[tuple[str, str]] = []
        settings = AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://dc.test.invalid",
            ad_user_search_base="OU=Staff,DC=test,DC=invalid",
            ad_bind_dn="CN=svc-mefor,OU=Service,DC=test,DC=invalid",
            ad_bind_password="synthetic",
            ad_session_recheck_seconds=60,
            **overrides,
        )
        self.service = AuthService(
            store,
            settings,
            ldap=self.ldap,  # type: ignore[arg-type]
            admin_loss_alert=lambda username, via: self.alerts.append((username, via)),
            admin_grant_alert=lambda username, via: self.grants.append((username, via)),
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
    """A sign-in's Administrator grant ends the account's cooldown in this sink, so a second loss is sent.

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
    # The control: asmith's first loss comes BEFORE jdoe's grant, so a grant that cleared every
    # account's cooldown would let asmith's second loss through and fail the count below.
    lose("asmith", "ad-reconcile")
    alert_directory_administrator_granted(state, regrant, via="directory_sign_in_negotiate")
    lose("jdoe", "ad-sync")
    lose("asmith", "ad-reconcile")
    await _drain(sink)

    losses = [e["connection"] for e in transport.events if e["type"] == "no_enabled_administrator"]
    assert losses.count("user:jdoe") == 2
    assert losses.count("user:asmith") == 1


# --- vault BACKLOG #3141: a reconcile pass that newly grants Administrator pages ----------------
#
# The reconciler's role re-diff can give an account Administrator. It raised only
# ad_session_revoked, and the account's next sign-in then found the role already written and
# gained nothing, so no administrator_granted ever fired. The pass now raises it right after the
# role write, judged on the roles read through the account's seal at apply time.

#: The ``via`` a reconcile pass's grant reports.
RECONCILE_VIA = "directory_reconcile"


async def test_a_reconcile_pass_that_newly_grants_administrator_pages_once(rig: _Rig) -> None:
    """RED before #3141: the pass raised no grant, and the next sign-in gains nothing."""
    rig.ldap.present["jdoe"] = _principal("jdoe", OPERATORS)
    await rig.sign_in("jdoe")

    await rig.directory_change("jdoe", ADMINS, via="ad-reconcile")

    assert await rig.roles("jdoe") == [Role.ADMINISTRATOR.value]
    assert rig.grants == [("jdoe", RECONCILE_VIA)]
    assert rig.alerts == []
    # Why the pass must page: the account's next sign-in finds the role written and gains nothing.
    outcome = await rig.service._complete_ad_login(
        rig.ldap.present["jdoe"], None, mfa_verified=True
    )
    assert outcome.ok and outcome.roles_gained is None
    assert rig.grants == [("jdoe", RECONCILE_VIA)]


async def test_a_reconcile_change_to_an_account_that_held_administrator_is_quiet(
    rig: _Rig,
) -> None:
    """Negative control: Administrator held before the write, so nothing was granted."""
    rig.ldap.present["jdoe"] = _principal("jdoe", ADMINS)
    await rig.sign_in("jdoe")

    await rig.directory_change("jdoe", ADMINS, OPERATORS, via="ad-reconcile")

    assert sorted(await rig.roles("jdoe")) == sorted(
        [Role.ADMINISTRATOR.value, Role.OPERATOR.value]
    )
    assert rig.grants == []


async def test_a_reconcile_gain_of_another_role_only_is_quiet(rig: _Rig) -> None:
    """Negative control: a role was gained, but not Administrator."""
    rig.ldap.present["jdoe"] = _principal("jdoe")
    await rig.sign_in("jdoe")

    await rig.directory_change("jdoe", OPERATORS, via="ad-reconcile")

    assert await rig.roles("jdoe") == [Role.OPERATOR.value]
    assert rig.grants == []


async def test_the_grant_is_judged_on_the_roles_read_at_apply_time_not_the_plans(
    rig: _Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sign-in that lands between the pass's read and its write has already written
    Administrator, and paged for it. The write then adds nothing, so the pass must not page again.
    RED when the before-set is taken from the plan, which read the roles before that sign-in.

    The sign-in writes Operator beside Administrator, which the pass's write then removes. Were the
    stored roles equal to the pass's target, #3085's apply-time check would skip the write and the
    grant check with it, and this test would pass whatever before-set the service used."""
    rig.ldap.present["jdoe"] = _principal("jdoe", OPERATORS)
    await rig.sign_in("jdoe")
    rig.ldap.present["jdoe"] = _principal("jdoe", ADMINS)
    real = rig.service._apply_reconcile_revocation

    async def a_sign_in_lands_first(
        revocation: SessionRevocation, *, watermark: _AuditWatermark | None
    ) -> _RevocationApplied:
        await rig.store.set_user_roles(
            revocation.user_id,
            [Role.ADMINISTRATOR.value, Role.OPERATOR.value],
            assigned_by="ad-sync",
        )
        return await real(revocation, watermark=watermark)

    monkeypatch.setattr(rig.service, "_apply_reconcile_revocation", a_sign_in_lands_first)

    plan = await rig.service.reconcile_directory_sessions()

    assert [(r.username, r.reason) for r in plan.revocations] == [("jdoe", "roles_changed")]
    # The control: the pass's own write ran (Operator is gone), so the grant check was reached.
    assert await rig.roles("jdoe") == [Role.ADMINISTRATOR.value]
    assert rig.grants == []


async def test_a_pass_the_breaker_aborts_grants_nothing_and_pages_nothing() -> None:
    """An aborted pass writes no roles, so there is no grant to page (ADR 0079 mechanism 2)."""
    store = await MessageStore.open(":memory:")
    try:
        # One revocation of one probed account trips a breaker this tight.
        rig = _Rig(store, ad_session_revoke_max=0, ad_session_revoke_max_fraction=0.01)
        await rig.start()
        rig.ldap.present["jdoe"] = _principal("jdoe", OPERATORS)
        await rig.sign_in("jdoe")
        rig.ldap.present["jdoe"] = _principal("jdoe", ADMINS)

        plan = await rig.service.reconcile_directory_sessions()

        assert plan.aborted == "mass_revoke_breaker"
        assert await rig.roles("jdoe") == [Role.OPERATOR.value]
        assert rig.grants == []
    finally:
        await store.close()


async def test_a_raising_grant_callable_still_ends_the_sessions(rig: _Rig) -> None:
    """Only the production wrapper promises not to raise, so the service contains a raise: the
    session revocation after the role write still runs."""

    def raising(username: str, via: str) -> None:
        raise RuntimeError("synthetic: the alert path is down")

    rig.service._admin_grant_alert = raising
    rig.ldap.present["jdoe"] = _principal("jdoe", OPERATORS)
    await rig.sign_in("jdoe")

    await rig.directory_change("jdoe", ADMINS, via="ad-reconcile")

    assert await rig.roles("jdoe") == [Role.ADMINISTRATOR.value]
    actions = [r["action"] for r in await rig.store.list_audit()]
    assert "auth.ad_session_revoked" in actions


def test_the_grant_callable_keys_on_the_account_and_never_raises() -> None:
    raised: list[tuple[str, str, str]] = []

    class _Sink(LoggingAlertSink):
        def administrator_granted(self, name: str, *, via: str, granted_by: str) -> None:
            raised.append((name, via, granted_by))

    administrator_granted_alert(_Sink(), granted_by=DIRECTORY_GRANTED_BY)("jdoe", RECONCILE_VIA)
    assert raised == [("user:jdoe", RECONCILE_VIA, DIRECTORY_GRANTED_BY)]

    class _Broken(LoggingAlertSink):
        def administrator_granted(self, name: str, *, via: str, granted_by: str) -> None:
            raise RuntimeError("synthetic: the sink is down")

    administrator_granted_alert(_Broken(), granted_by=DIRECTORY_GRANTED_BY)("jdoe", RECONCILE_VIA)


async def test_a_loss_after_a_reconciler_regrant_is_not_held_back_by_the_cooldown() -> None:
    """The #3229 cooldown pop, through the reconciler's own grant callable: the second loss is
    sent."""
    from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
    from tests.test_alert_sinks import _drain, _RecordingTransport

    transport = _RecordingTransport("webhook")
    sink = NotifierAlertSink([transport])  # the default cooldown, far longer than this test
    lose = no_enabled_administrator_alert(sink)
    regrant = administrator_granted_alert(sink, granted_by=DIRECTORY_GRANTED_BY)

    lose("jdoe", "ad-reconcile")
    # The control: a grant that cleared every account's cooldown would let asmith's second loss
    # through and fail the count below.
    lose("asmith", "ad-reconcile")
    regrant("jdoe", RECONCILE_VIA)
    lose("jdoe", "ad-reconcile")
    lose("asmith", "ad-reconcile")
    await _drain(sink)

    losses = [e["connection"] for e in transport.events if e["type"] == "no_enabled_administrator"]
    assert losses.count("user:jdoe") == 2
    assert losses.count("user:asmith") == 1
