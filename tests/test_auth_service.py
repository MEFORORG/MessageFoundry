# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""AuthService unit tests: bootstrap, local login + lockout, sessions, AD group->role mapping."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from messagefoundry.auth import Role, hash_password, hash_token
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.notifications import (
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    EMAIL_CHANGED,
    LOGIN_AFTER_FAILURES,
    PASSWORD_CHANGED,
    PASSWORD_RESET,
    ROLES_CHANGED,
    SecurityEvent,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

GOOD_PASSWORD = "Sup3rSecret!!"
NEW_PASSWORD = "An0ther-Str0ng-Pass!!"


class _FakeNotifier:
    """Captures security events instead of emailing — for the WP-L3-05 notifier-firing tests."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def _claim_bootstrap(service: AuthService, boot_password: str) -> str:
    """Claim the bootstrap admin the way an operator actually would: log in with the printed one-time
    credential, then rotate it through :meth:`AuthService.change_password`. Returns the claimed
    password.

    Deliberately NOT a direct ``store.set_password``. Self-service rotation is the ONE path that
    records the claim (``users.password_claimed_at``), so a store-level shortcut produces a row that
    merely LOOKS claimed and leaves the suite blind to any later writer that moves the state it does
    set. That shortcut is why BACKLOG #1245 was invisible to a green suite.
    """
    out = await service.login("admin", boot_password)
    assert out.ok and out.identity is not None
    assert await service.change_password(out.identity, NEW_PASSWORD) == []
    return NEW_PASSWORD


async def test_bootstrap_admin_created_once_and_can_log_in() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        boot = await service.initialize()
        assert boot is not None and boot.username == "admin" and len(boot.password) >= 15
        out = await service.login("admin", boot.password)
        assert out.ok and out.must_change_password is True
        assert out.identity is not None and Role.ADMINISTRATOR in out.identity.roles
        # a second service over the same (now non-empty) store does not re-bootstrap
        assert await AuthService(store, AuthSettings()).initialize() is None
    finally:
        await store.close()


async def test_bootstrap_password_satisfies_active_policy() -> None:
    # The printed bootstrap credential is generated *through* the active policy (WP-3), even a strict one.
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(password_min_length=20, password_require_symbol=True)
        )
        boot = await service.initialize()
        assert boot is not None
        assert service.policy.violations(boot.password) == [] and len(boot.password) >= 20
    finally:
        await store.close()


async def test_bootstrap_auto_disabled_when_second_admin_created() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        boot = await service.initialize()
        assert boot is not None
        await service.create_local_user(
            username="alice",
            password="a-long-unguessable-passphrase",
            display_name=None,
            email=None,
            roles=[Role.ADMINISTRATOR.value],
            actor="admin",
        )
        # the unclaimed bootstrap admin is retired the moment a real second admin exists
        assert not (await service.login("admin", boot.password)).ok
        retired = await store.get_user_by_username("admin")
        assert retired is not None and retired.disabled
    finally:
        await store.close()


async def test_bootstrap_expires_when_left_unclaimed() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        boot = await service.initialize()
        assert boot is not None
        assert (await service.login("admin", boot.password)).ok  # within the window: usable
        # age the account past the expiry window
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        await store._db.execute(
            "UPDATE users SET created_at=? WHERE id=?", (time.time() - 73 * 3600, admin.id)
        )
        await store._db.commit()
        assert not (await service.login("admin", boot.password)).ok  # expired → refused
        expired = await store.get_user_by_username("admin")
        assert expired is not None and expired.disabled
    finally:
        await store.close()


async def test_claimed_bootstrap_is_not_retired() -> None:
    # Once the operator claims the bootstrap account it is a normal admin account; neither
    # supersession nor expiry may disable it (no single-admin lockout).
    #
    # REWRITTEN for BACKLOG #1245: the previous form claimed the account with a direct
    # store.set_password, which pinned the PROXY (must_change_password) instead of the PROPERTY
    # (the holder set their own credential). Claiming through the real service path is the point of
    # the test, not collateral damage from the fix.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        boot = await service.initialize()
        assert boot is not None
        claimed = await _claim_bootstrap(service, boot.password)
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        # age it past expiry AND add a second admin — still must not be disabled
        await store._db.execute(
            "UPDATE users SET created_at=? WHERE id=?", (time.time() - 99 * 3600, admin.id)
        )
        await store._db.commit()
        await service.create_local_user(
            username="alice",
            password="another-long-passphrase",
            display_name=None,
            email=None,
            roles=[Role.ADMINISTRATOR.value],
            actor="admin",
        )
        still = await store.get_user_by_username("admin")
        assert still is not None and not still.disabled
        assert (await service.login("admin", claimed)).ok
    finally:
        await store.close()


# --- BACKLOG #1245: an ADMIN RESET of a claimed bootstrap must not re-arm its retirement ----------
#
# The retirement gate asks "was this account ever claimed?", which is monotonic. It used to answer
# with must_change_password, which is not: admin_reset_password legitimately re-raises that flag
# (ASVS 6.4.6 wants an admin-issued credential to be a one-time temp), so a reset made a long-claimed
# account read as never-claimed and the next trigger would disable it. Each test below drives one
# trigger. All of them claim through the service, never through the store.


async def test_admin_reset_does_not_re_arm_retirement_of_a_claimed_bootstrap() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        boot = await service.initialize()
        assert boot is not None
        claimed = await _claim_bootstrap(service, boot.password)
        await service.create_local_user(
            username="alice",
            password="another-long-passphrase",
            display_name=None,
            email=None,
            roles=[Role.ADMINISTRATOR.value],
            actor="admin",
        )
        # NEGATIVE CONTROL: the claim held across supersession. Without it, a red below could just as
        # well mean the fixture was never claimed in the first place.
        assert (await service.login("admin", claimed)).ok
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        temp = await service.admin_reset_password(admin.id, actor="alice")
        # The reset re-raises must_change_password — that write is correct and must stay; what must
        # not follow from it is a retirement.
        after_reset = await store.get_user_by_username("admin")
        assert after_reset is not None and after_reset.must_change_password
        out = await service.login("admin", temp)  # this login is itself a retirement trigger
        assert out.ok and out.must_change_password
        still = await store.get_user_by_username("admin")
        assert still is not None and not still.disabled
    finally:
        await store.close()


async def test_claimed_bootstrap_survives_restart_after_an_admin_reset() -> None:
    # The restart trigger: initialize() retires on the way up, so a site that reset the password and
    # restarted the service before anyone logged in would find the account disabled at boot, with no
    # login attempt to correlate the audit line against.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        boot = await service.initialize()
        assert boot is not None
        await _claim_bootstrap(service, boot.password)
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        await store._db.execute(  # arm the expiry arm: older than the window
            "UPDATE users SET created_at=? WHERE id=?", (time.time() - 99 * 3600, admin.id)
        )
        await store._db.commit()
        temp = await service.admin_reset_password(admin.id, actor="admin")
        restarted = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        assert await restarted.initialize() is None  # non-empty store: no re-bootstrap
        still = await store.get_user_by_username("admin")
        assert still is not None and not still.disabled
        assert (await restarted.login("admin", temp)).ok
    finally:
        await store.close()


async def test_claimed_bootstrap_survives_user_creation_after_an_admin_reset() -> None:
    # The create_local_user trigger, and note it fires for ANY new account — the retirement check
    # there is unconditional, and an aged store satisfies the expiry arm on its own, so creating a
    # read-only user is enough.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        boot = await service.initialize()
        assert boot is not None
        await _claim_bootstrap(service, boot.password)
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        await store._db.execute(
            "UPDATE users SET created_at=? WHERE id=?", (time.time() - 99 * 3600, admin.id)
        )
        await store._db.commit()
        temp = await service.admin_reset_password(admin.id, actor="admin")
        await service.create_local_user(
            username="bob",
            password="a-third-long-enough-passphrase",
            display_name=None,
            email=None,
            roles=[Role.VIEWER.value],
            actor="admin",
        )
        still = await store.get_user_by_username("admin")
        assert still is not None and not still.disabled
        assert (await service.login("admin", temp)).ok
    finally:
        await store.close()


async def test_the_upgrade_backfill_restores_a_claim_a_pre_column_database_cannot_carry(
    tmp_path: Path,
) -> None:
    # BACKLOG #1245: the one-time backfill is the arm that can disable the only administrator of an
    # UPGRADED database, and until this test it was executed by nothing. Every other test opens
    # ``:memory:``, which creates ``users`` WITH the column from _SCHEMA, so the guarded migration
    # branch is never entered and deleting the backfill outright reds no test at all.
    #
    # This drives the real path: claim the bootstrap, drop the column to manufacture a pre-#1245
    # database, reopen, and assert the claim came back. Without the backfill the reopened row reads
    # NULL, which the gate reads as "never claimed", and the next trigger disables an account whose
    # holder claimed it long ago -- the defect, re-introduced by its own fix.
    db = tmp_path / "mefor.db"
    store = await MessageStore.open(str(db))
    try:
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        boot = await service.initialize()
        assert boot is not None
        await _claim_bootstrap(service, boot.password)
        claimed = await store.get_user_by_username("admin")
        assert claimed is not None and claimed.password_claimed_at is not None
    finally:
        await store.close()

    # Manufacture the legacy shape, and PROVE it was manufactured -- a green below would otherwise be
    # consistent with the column never having been dropped.
    # Rebuilt rather than ALTER ... DROP COLUMN: SQLite re-parses the stored CREATE TABLE text after
    # a drop, and the trailing ``--`` comment this change puts on the final column makes that
    # reconstruction "incomplete input". The column list is DERIVED from the live table, so this does
    # not hard-code a schema that will drift.
    con = sqlite3.connect(db)
    try:
        keep = [
            row[1]
            for row in con.execute("PRAGMA table_info(users)")
            if row[1] != "password_claimed_at"
        ]
        assert "password_changed_at" in keep  # the column the backfill reads from
        cols = ", ".join(keep)
        con.executescript(
            "PRAGMA foreign_keys=OFF;\n"
            f"CREATE TABLE users_legacy AS SELECT {cols} FROM users;\n"
            "DROP TABLE users;\n"
            "ALTER TABLE users_legacy RENAME TO users;\n"
        )
        con.commit()
        after = {row[1] for row in con.execute("PRAGMA table_info(users)")}
        assert "password_claimed_at" not in after  # the legacy shape really was manufactured
        assert "password_changed_at" in after
    finally:
        con.close()

    reopened = await MessageStore.open(str(db))
    try:
        healed = await reopened.get_user_by_username("admin")
        assert healed is not None
        assert healed.password_claimed_at is not None  # the backfill ran on open
        # And it restored the ORIGINAL claim instant, not "now" -- the stamp is evidence about when
        # the holder took the account, so a backfill that merely wrote a non-NULL value would satisfy
        # a not-None assertion while destroying the fact.
        assert healed.password_claimed_at == healed.password_changed_at
    finally:
        await reopened.close()

    # SCOPE, stated rather than implied: this pins that the backfill RESTORES THE STAMP on an
    # upgraded database. The consequence of a restored stamp -- the account surviving a retirement
    # trigger -- is pinned by the sibling tests above and is deliberately not re-tested here, because
    # the rebuilt legacy table is created without its primary key and cannot carry the user_roles
    # foreign key a second administrator needs.


async def test_a_directory_provisioned_admin_is_not_retired_by_wp3() -> None:
    # BACKLOG #1245, the regression the claimed-ness fix would otherwise INTRODUCE. WP-3 governs the
    # LOCAL first-run account. The retired ``must_change_password`` test excluded a directory row BY
    # ACCIDENT -- such a row has no password, so it carries the flag False and the old predicate
    # returned early on it. ``password_claimed_at`` has no such side effect: a federated row has no
    # stamp either, which reads as "never claimed". Without the auth_provider guard this test reds
    # with the AD administrator DISABLED and its sessions revoked, audited as a bootstrap retirement
    # -- the same lockout class #1245 exists to prevent, on a different row shape.
    store = await _store()
    try:
        # Reachable because the bootstrap is minted only when the store is EMPTY: a directory-first
        # install or a DR restore leaves the username free for the directory to claim.
        await store.create_user(
            user_id="ad-admin-row",
            username="admin",
            auth_provider=AuthProvider.AD.value,
            display_name="Directory Administrator",
            email=None,
        )
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        # Starting the engine against a non-empty store seeds the built-in roles and runs the
        # retirement pass, but mints NO bootstrap -- that is what leaves the username to the
        # directory, and it is trigger :518 firing on this row before any login happens.
        assert await service.initialize() is None
        seeded = await store.get_user_by_username("admin")
        assert seeded is not None
        # POSITIVE CONTROL: the row really is in the shape that used to be protected by accident --
        # no password, flag clear, no stamp. Without this, a green below could mean the fixture never
        # built the interesting row rather than that the guard held.
        assert seeded.auth_provider == AuthProvider.AD.value
        assert seeded.password_hash is None
        assert seeded.must_change_password is False
        assert seeded.password_claimed_at is None

        # Supersession: a second enabled administrator is the arm that fires without a time window.
        await service.create_local_user(
            username="alice",
            password="another-long-passphrase",
            display_name=None,
            email=None,
            roles=[Role.ADMINISTRATOR.value],
            actor="system",
        )
        survivor = await store.get_user_by_username("admin")
        assert survivor is not None and not survivor.disabled
        # And the advisory warner must be silent about it too -- it asks the same question.
        assert await service.bootstrap_expiry_warning(now=time.time() + 71 * 3600) is None
    finally:
        await store.close()


async def test_unclaimed_bootstrap_is_still_retired_after_an_admin_reset() -> None:
    # The other half of #1245, and the reason the fix could not simply be a carve-out on the reset
    # path: an admin reset does not claim the account, so a bootstrap NOBODY ever claimed stays
    # retirable. This test reds if anyone makes admin_reset_password special-case the bootstrap or
    # record a claim, which would delete the WP-3 auto-retirement entirely.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        boot = await service.initialize()
        assert boot is not None
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        temp = await service.admin_reset_password(admin.id, actor="admin")
        await service.create_local_user(
            username="alice",
            password="another-long-passphrase",
            display_name=None,
            email=None,
            roles=[Role.ADMINISTRATOR.value],
            actor="admin",
        )
        retired = await store.get_user_by_username("admin")
        assert retired is not None and retired.disabled
        assert not (await service.login("admin", temp)).ok  # the fresh temp is refused too
    finally:
        await store.close()


# --- ASVS 6.4.5 arm 1: the bootstrap credential carries its own expiry deadline ------------------


async def test_bootstrap_admin_carries_its_expiry_deadline() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        boot = await service.initialize()
        assert boot is not None and boot.expires_at is not None
        admin = await store.get_user_by_username("admin")
        # exactly created_at + window (same base _retire_superseded_bootstrap uses) — not a fresh clock
        assert abs(boot.expires_at - (admin.created_at + 72 * 3600)) < 1.0
    finally:
        await store.close()


async def test_bootstrap_admin_deadline_is_none_when_expiry_off() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=0))
        boot = await service.initialize()
        assert boot is not None and boot.expires_at is None
    finally:
        await store.close()


# --- ASVS 6.4.5 arm 2: an unclaimed bootstrap admin is reminded BEFORE it is auto-disabled --------


async def test_bootstrap_expiry_warning_fires_once_in_window() -> None:
    # An unclaimed bootstrap 24h from auto-disable draws exactly ONE reminder: the in-memory latch
    # collapses a periodic caller to a single emit per process (the runner re-checks hourly).
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(bootstrap_expiry_hours=72, bootstrap_warn_hours=24)
        )
        boot = await service.initialize()
        assert boot is not None
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        expires_at = admin.created_at + 72 * 3600
        at_t_minus_24h = expires_at - 24 * 3600  # exactly the window's leading edge
        first = await service.bootstrap_expiry_warning(now=at_t_minus_24h)
        assert first is not None
        surfaced_expires, hours_remaining = first
        assert (
            abs(surfaced_expires - expires_at) < 1.0
        )  # the exact retirement instant, not a fresh clock
        assert hours_remaining == 24
        # a second pass anywhere in the window is latched → no second reminder
        assert await service.bootstrap_expiry_warning(now=at_t_minus_24h + 3600) is None
    finally:
        await store.close()


async def test_bootstrap_expiry_warning_silent_before_the_window() -> None:
    # Before [expires_at - warn_hours, expires_at): nothing — and a pre-window pass does NOT consume the
    # latch, so the real window still fires afterwards.
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(bootstrap_expiry_hours=72, bootstrap_warn_hours=24)
        )
        await service.initialize()
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        expires_at = admin.created_at + 72 * 3600
        assert await service.bootstrap_expiry_warning(now=expires_at - 25 * 3600) is None  # before
        assert (
            await service.bootstrap_expiry_warning(now=expires_at - 12 * 3600) is not None
        )  # inside
    finally:
        await store.close()


async def test_bootstrap_expiry_warning_silent_when_claimed() -> None:
    # "claimed fires nothing": once the operator claims the account it is a normal admin account and
    # draws no retirement reminder, even inside what would be the window.
    #
    # REWRITTEN for BACKLOG #1245, for the same reason as test_claimed_bootstrap_is_not_retired: the
    # previous form claimed with a direct store.set_password, so it pinned must_change_password
    # rather than the recorded claim the warner actually has to read.
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(bootstrap_expiry_hours=72, bootstrap_warn_hours=24)
        )
        boot = await service.initialize()
        assert boot is not None
        await _claim_bootstrap(service, boot.password)
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        expires_at = admin.created_at + 72 * 3600
        assert await service.bootstrap_expiry_warning(now=expires_at - 1 * 3600) is None
    finally:
        await store.close()


async def test_bootstrap_expiry_warning_silent_after_an_admin_reset_of_a_claimed_bootstrap() -> (
    None
):
    # BACKLOG #1245, second reader: the warner asks the same claimed-ness question as the retirement
    # and used to answer it the same wrong way. A fix scoped to the retirement gate alone greens the
    # tests above while this path still tells an operator that a claimed, in-use admin account
    # expires in N hours — advice that is both false and actively misleading.
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(bootstrap_expiry_hours=72, bootstrap_warn_hours=24)
        )
        boot = await service.initialize()
        assert boot is not None
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        inside_window = admin.created_at + 50 * 3600  # within [expires_at - 24h, expires_at)
        # POSITIVE CONTROL: this instant DOES warn while the account is unclaimed, so the None below
        # is the claim being read, not a window/latch/config mistake silently returning None.
        assert await service.bootstrap_expiry_warning(now=inside_window) is not None
        await _claim_bootstrap(service, boot.password)
        await service.admin_reset_password(admin.id, actor="admin")
        # A fresh service: the warn latch is per-process, and this also models the restart that would
        # re-arm the reminder.
        restarted = AuthService(
            store, AuthSettings(bootstrap_expiry_hours=72, bootstrap_warn_hours=24)
        )
        assert await restarted.bootstrap_expiry_warning(now=inside_window) is None
    finally:
        await store.close()


async def test_bootstrap_expiry_warning_silent_when_expiry_off() -> None:
    # No time-expiry configured → the credential is never auto-disabled, so there is nothing to warn of,
    # however far past the (non-existent) deadline the clock is pushed.
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(bootstrap_expiry_hours=0, bootstrap_warn_hours=24)
        )
        await service.initialize()
        assert await service.bootstrap_expiry_warning(now=time.time() + 999 * 3600) is None
    finally:
        await store.close()


async def test_bootstrap_expiry_warning_silent_after_the_deadline() -> None:
    # At/after expires_at, retirement itself takes over (_retire_superseded_bootstrap); the pre-warning
    # does not fire past the deadline.
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(bootstrap_expiry_hours=72, bootstrap_warn_hours=24)
        )
        await service.initialize()
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        expires_at = admin.created_at + 72 * 3600
        assert await service.bootstrap_expiry_warning(now=expires_at + 1) is None
    finally:
        await store.close()


# --- ASVS 6.4.1: an admin-issued initial/reset credential expires when unclaimed -----------------


async def _make_reset_temp(store, service, *, username: str = "alice") -> str:
    """Create a local user, then admin-reset it → a must_change temp with password_changed_at=now."""
    await store.upsert_role(role_id="viewer", display_name="Viewer")
    await service.create_local_user(
        username=username,
        password="a-long-enough-original-passphrase",
        display_name=None,
        email=None,
        roles=["viewer"],
        actor="admin",
    )
    user = await store.get_user_by_username(username)
    assert user is not None
    return await service.admin_reset_password(user.id, actor="admin")


async def test_a_reset_temp_on_a_CLAIMED_bootstrap_still_expires() -> None:
    # BACKLOG #1245: the 6.4.1 carve-out for the bootstrap rests on WP-3 giving that account its own
    # deadline, and that is true only while it is UNCLAIMED. Once claimed, WP-3 deliberately stops
    # covering it -- so before this narrowing, an admin-issued temp on the highest-privilege account
    # name in the system never expired at all.
    #
    # The gap was MASKED BY THE DEFECT ITSELF: pre-#1245 the reset re-armed retirement and the
    # account got disabled, so nobody noticed the temp had no deadline. Fixing #1245 removed that
    # accidental bound, which is why the bound has to be put back deliberately here.
    store = await _store()
    try:
        # bootstrap_expiry_hours=0 turns the WP-3 time arm OFF, so this test isolates the 6.4.1 gate
        # and cannot pass by the account being retired for an unrelated reason.
        service = AuthService(
            store, AuthSettings(initial_password_expiry_hours=72, bootstrap_expiry_hours=0)
        )
        boot = await service.initialize()
        assert boot is not None
        await _claim_bootstrap(service, boot.password)

        admin = await store.get_user_by_username("admin")
        assert admin is not None and admin.password_claimed_at is not None  # genuinely claimed
        temp = await service.admin_reset_password(admin.id, actor="admin")

        # POSITIVE CONTROL: inside the window the temp WORKS. Without this, the refusal below is
        # equally consistent with the reset having produced an unusable credential.
        assert (await service.login("admin", temp)).ok

        await store._db.execute(
            "UPDATE users SET password_changed_at=? WHERE id=?",
            (time.time() - 73 * 3600, admin.id),
        )
        await store._db.commit()

        out = await service.login("admin", temp)
        assert not out.ok  # aged past 6.4.1 -> refused even with the CORRECT temp
        assert out.error == "invalid credentials"  # generic, as for any other account
        # And it is refused by EXPIRY, not by retirement -- the claimed account is still enabled.
        still = await store.get_user_by_username("admin")
        assert still is not None and not still.disabled
    finally:
        await store.close()


async def test_an_unclaimed_bootstrap_temp_keeps_its_carve_out() -> None:
    # The other side of the narrowing, and the reason it is a narrowing rather than a deletion: an
    # UNCLAIMED bootstrap still has its own WP-3 deadline, so the 6.4.1 gate must stay carved out for
    # it. This reds if anyone "simplifies" the condition by removing the carve-out entirely.
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(initial_password_expiry_hours=72, bootstrap_expiry_hours=0)
        )
        boot = await service.initialize()
        assert boot is not None
        admin = await store.get_user_by_username("admin")
        assert admin is not None and admin.password_claimed_at is None  # never claimed
        await store._db.execute(
            "UPDATE users SET password_changed_at=? WHERE id=?",
            (time.time() - 73 * 3600, admin.id),
        )
        await store._db.commit()
        # Aged well past 6.4.1, but never claimed: WP-3 owns this account's lifecycle, so the
        # original bootstrap credential is still accepted here.
        assert (await service.login("admin", boot.password)).ok
    finally:
        await store.close()


async def test_reset_temp_password_expires_when_unclaimed() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(initial_password_expiry_hours=72))
        await service.initialize()
        temp = await _make_reset_temp(store, service)
        assert (await service.login("alice", temp)).ok  # within the window: usable
        # age the temp past its expiry window (password_changed_at, not created_at)
        alice = await store.get_user_by_username("alice")
        assert alice is not None
        await store._db.execute(
            "UPDATE users SET password_changed_at=? WHERE id=?",
            (time.time() - 73 * 3600, alice.id),
        )
        await store._db.commit()
        out = await service.login("alice", temp)
        assert not out.ok  # expired → refused, even with the CORRECT temp password
        assert out.error == "invalid credentials"  # generic — not distinguishable from a wrong pw
        # the account is NOT disabled (unlike bootstrap) — an admin can re-issue a fresh temp
        assert (await store.get_user_by_username("alice")).disabled is False
    finally:
        await store.close()


async def test_claimed_temp_password_is_not_gated() -> None:
    # Once the user claims the temp (change → must_change False), it is a normal credential and the
    # 6.4.1 expiry no longer applies, however old password_changed_at becomes.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(initial_password_expiry_hours=72))
        await service.initialize()
        await _make_reset_temp(store, service)
        alice = await store.get_user_by_username("alice")
        await store.set_password(
            alice.id,
            password_hash=hash_password("the-users-own-chosen-passphrase"),
            must_change_password=False,
        )
        await store._db.execute(
            "UPDATE users SET password_changed_at=? WHERE id=?",
            (time.time() - 999 * 3600, alice.id),
        )
        await store._db.commit()
        assert (await service.login("alice", "the-users-own-chosen-passphrase")).ok
    finally:
        await store.close()


async def test_initial_password_expiry_zero_disables_the_gate() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(initial_password_expiry_hours=0))
        await service.initialize()
        temp = await _make_reset_temp(store, service)
        alice = await store.get_user_by_username("alice")
        await store._db.execute(
            "UPDATE users SET password_changed_at=? WHERE id=?",
            (time.time() - 9999 * 3600, alice.id),
        )
        await store._db.commit()
        assert (await service.login("alice", temp)).ok  # gate off → an aged temp still works
    finally:
        await store.close()


async def test_bootstrap_admin_is_not_gated_by_initial_password_expiry() -> None:
    # The bootstrap admin is must_change + carries password_changed_at, but is CARVED OUT of the
    # 6.4.1 gate (it has its own bootstrap_expiry_hours path). With bootstrap expiry off, an aged,
    # unclaimed bootstrap still logs in — the initial-password gate must not catch it.
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(initial_password_expiry_hours=1, bootstrap_expiry_hours=0)
        )
        boot = await service.initialize()
        assert boot is not None
        admin = await store.get_user_by_username("admin")
        await store._db.execute(
            "UPDATE users SET password_changed_at=? WHERE id=?",
            (time.time() - 500 * 3600, admin.id),
        )
        await store._db.commit()
        assert (await service.login("admin", boot.password)).ok  # not gated by the 6.4.1 expiry
    finally:
        await store.close()


async def test_local_login_lockout_after_threshold() -> None:
    store = await _store()
    try:
        settings = AuthSettings(lockout_threshold=3, lockout_minutes=15)
        service = AuthService(store, settings)
        await store.upsert_role(role_id="viewer", display_name="Viewer")
        await store.create_user(
            user_id="u1",
            username="bob",
            auth_provider="local",
            password_hash=hash_password(GOOD_PASSWORD),
        )
        for _ in range(3):
            assert not (await service.login("bob", "wrong")).ok
        # correct password is now rejected because the account is locked
        locked = await service.login("bob", GOOD_PASSWORD)
        assert not locked.ok and locked.error == "account locked"
    finally:
        await store.close()


async def test_session_validation_idle_and_absolute_timeout() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(session_idle_timeout_minutes=30))
        await store.upsert_role(role_id="viewer", display_name="Viewer")
        await store.create_user(
            user_id="u1", username="amy", auth_provider="local", password_hash=hash_password("x")
        )
        await store.set_user_roles("u1", ["viewer"])
        now = time.time()
        # a fresh session resolves to an identity
        await store.create_session(
            token_hash=hash_token("fresh"), user_id="u1", expires_at=now + 9999, now=now
        )
        ident = await service.identity_for_token("fresh")
        assert ident is not None and ident.username == "amy"
        # an idle session (last_used long ago) is rejected and revoked
        await store.create_session(
            token_hash=hash_token("idle"), user_id="u1", expires_at=now + 9999, now=0.0
        )
        assert await service.identity_for_token("idle") is None
        # an absolutely-expired session is rejected
        await store.create_session(
            token_hash=hash_token("old"), user_id="u1", expires_at=1.0, now=now
        )
        assert await service.identity_for_token("old") is None
        # an unknown token is rejected
        assert await service.identity_for_token("nope") is None
    finally:
        await store.close()


async def test_ad_login_syncs_roles_from_group_map() -> None:
    store = await _store()
    try:
        principal = AdPrincipal(
            username="jdoe",
            display_name="J Doe",
            email="j@x",
            dn="CN=jdoe,DC=x",
            groups=frozenset({"cn=mf-ops,dc=x"}),
        )

        class _FakeLdap:
            def authenticate(self, username: str, password: str) -> AdPrincipal | None:
                return principal if (username == "jdoe" and password == "pw") else None

            def resolve_principal(self, username: str) -> AdPrincipal | None:
                return principal if username == "jdoe" else None

        settings = AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
        service = AuthService(store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]
        await service.initialize()
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")

        out = await service.login("jdoe", "pw", provider=AuthProvider.AD)
        assert out.ok and out.identity is not None
        assert out.identity.auth_provider is AuthProvider.AD
        assert out.identity.roles == frozenset({Role.OPERATOR})
        # bad AD password is rejected
        assert not (await service.login("jdoe", "bad", provider=AuthProvider.AD)).ok
    finally:
        await store.close()


# --- WP-L3-05: security-event notifications (ASVS 6.3.5 / 6.3.7) --------------


async def _local_user(store: MessageStore, *, email: str = "bob@example.org") -> None:
    await store.upsert_role(role_id="viewer", display_name="Viewer")
    await store.create_user(
        user_id="u1",
        username="bob",
        auth_provider="local",
        email=email,
        password_hash=hash_password(GOOD_PASSWORD),
    )


async def test_notifier_fires_once_on_account_lockout() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(lockout_threshold=3), security_notifier=notifier)
        await _local_user(store)
        for _ in range(3):
            await service.login("bob", "wrong", client="10.0.0.9")
        locked = [e for e in notifier.events if e.event_type == ACCOUNT_LOCKED]
        assert len(locked) == 1  # exactly one notice on the attempt that crosses the threshold
        assert locked[0].username == "bob"
        assert locked[0].email == "bob@example.org"
        assert locked[0].client_ip == "10.0.0.9"
    finally:
        await store.close()


async def test_notifier_fires_on_success_after_failures() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        # High lockout threshold so 3 failures don't lock — we want the success path to fire.
        service = AuthService(store, AuthSettings(lockout_threshold=10), security_notifier=notifier)
        await _local_user(store)
        for _ in range(3):
            await service.login("bob", "wrong")
        out = await service.login("bob", GOOD_PASSWORD, client="10.0.0.4")
        assert out.ok
        after = [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
        assert len(after) == 1
        assert after[0].detail.get("failed_attempts") == 3 and after[0].client_ip == "10.0.0.4"
    finally:
        await store.close()


async def test_no_success_notice_below_threshold() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(lockout_threshold=10), security_notifier=notifier)
        await _local_user(store)
        await service.login("bob", "wrong")  # one failure (< SUSPICIOUS threshold of 3)
        assert (await service.login("bob", GOOD_PASSWORD)).ok
        assert not [e for e in notifier.events if e.event_type == LOGIN_AFTER_FAILURES]
    finally:
        await store.close()


async def test_notifier_fires_on_password_change() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _local_user(store)
        out = await service.login("bob", GOOD_PASSWORD)
        assert out.identity is not None
        assert await service.change_password(out.identity, NEW_PASSWORD, client="10.0.0.5") == []
        ev = next(e for e in notifier.events if e.event_type == PASSWORD_CHANGED)
        assert ev.email == "bob@example.org" and ev.client_ip == "10.0.0.5"
    finally:
        await store.close()


async def test_notifier_fires_on_admin_email_role_and_disable_changes() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _local_user(store, email="old@example.org")
        # Email change → notify the OLD address, carrying the new one.
        await service.update_user(
            "u1", display_name=None, email="new@example.org", disabled=None, actor="admin"
        )
        ec = next(e for e in notifier.events if e.event_type == EMAIL_CHANGED)
        assert ec.email == "old@example.org" and ec.detail.get("new_email") == "new@example.org"
        # Role change → ROLES_CHANGED.
        await service.set_roles("u1", ["viewer"], actor="admin")
        assert any(e.event_type == ROLES_CHANGED for e in notifier.events)
        # Disable → ACCOUNT_DISABLED (no email change this call).
        await service.update_user("u1", display_name=None, email=None, disabled=True, actor="admin")
        assert any(e.event_type == ACCOUNT_DISABLED for e in notifier.events)
    finally:
        await store.close()


async def test_notifier_absent_does_not_break_auth() -> None:
    # With no notifier injected, every event site is a no-op and auth still works.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(lockout_threshold=2))  # no security_notifier
        await _local_user(store)
        await service.login("bob", "wrong")
        await service.login("bob", "wrong")  # locks — must not raise
        assert (await service.login("bob", GOOD_PASSWORD)).error == "account locked"
    finally:
        await store.close()


class _BoomNotifier:
    """A notifier whose notify() always raises — exercises AuthService's best-effort guard."""

    async def notify(self, event: SecurityEvent) -> None:
        raise RuntimeError("notifier down")


async def test_notifier_failure_is_isolated_from_the_auth_op() -> None:
    # A notifier whose notify() RAISES must never propagate into the auth/admin operation —
    # _notify_security swallows it (the change is still audited / in the feed). This guards the
    # service-side try/except, distinct from the notifier's own background-loop error handling.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(), security_notifier=_BoomNotifier())  # type: ignore[arg-type]
        await _local_user(store)
        out = await service.login("bob", GOOD_PASSWORD)
        assert out.ok and out.identity is not None
        # change_password fires PASSWORD_CHANGED → notifier raises → password change still succeeds
        assert await service.change_password(out.identity, NEW_PASSWORD, client="10.0.0.9") == []
        # admin role change fires ROLES_CHANGED → notifier raises → role change still applied
        await service.set_roles("u1", ["viewer"], actor="admin")
        assert await store.get_user_role_ids("u1") == ["viewer"]
    finally:
        await store.close()


async def test_notifier_fires_on_ad_driven_role_change() -> None:
    # WP-L3-05 follow-up (ASVS 6.3.7): a role change pushed from the directory on login notifies the
    # affected user out-of-band, just like the local set_roles() path — not only the local one.
    store = await _store()
    try:
        principal = AdPrincipal(
            username="jdoe",
            display_name="J Doe",
            email="jdoe@example.org",
            dn="CN=jdoe,DC=x",
            groups=frozenset({"cn=mf-ops,dc=x"}),
        )

        class _FakeLdap:
            def authenticate(self, username: str, password: str) -> AdPrincipal | None:
                return principal if (username == "jdoe" and password == "pw") else None

            def resolve_principal(self, username: str) -> AdPrincipal | None:
                return principal if username == "jdoe" else None

        settings = AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://x",
            ad_user_search_base="DC=x",
            ad_bind_dn="CN=svc,DC=x",
            ad_bind_password="x",
        )
        notifier = _FakeNotifier()
        service = AuthService(store, settings, ldap=_FakeLdap(), security_notifier=notifier)  # type: ignore[arg-type]
        await service.initialize()

        def role_changes() -> list[SecurityEvent]:
            return [e for e in notifier.events if e.event_type == ROLES_CHANGED]

        # First login provisions the role (none → operator): a change, so it notifies.
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")
        assert (await service.login("jdoe", "pw", provider=AuthProvider.AD)).ok
        assert len(role_changes()) == 1

        # A repeat login with the SAME mapping is not a change → no new notice (silent when unchanged).
        assert (await service.login("jdoe", "pw", provider=AuthProvider.AD)).ok
        assert len(role_changes()) == 1

        # Re-mapping the group resyncs the role on the next login (operator → viewer) → a fresh notice.
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "viewer")], actor="admin")
        assert (await service.login("jdoe", "pw", provider=AuthProvider.AD)).ok
        changes = role_changes()
        assert len(changes) == 2
        assert changes[-1].username == "jdoe" and changes[-1].email == "jdoe@example.org"
        assert changes[-1].detail.get("roles") == ["viewer"]
    finally:
        await store.close()


# --- WP-L3-12: admin password reset (ASVS 6.4.6) -----------------------------


async def test_admin_reset_password_issues_one_time_must_change_credential() -> None:
    # ASVS 6.4.6: the reset returns a one-time temp (the admin never sets a lasting password), forces
    # rotation, changes the stored credential, notifies the affected user, and audits the action.
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _local_user(store)  # bob / u1 / GOOD_PASSWORD / bob@example.org
        assert (await service.login("bob", GOOD_PASSWORD)).ok

        temp = await service.admin_reset_password("u1", actor="admin")
        assert temp and temp != GOOD_PASSWORD  # a fresh, non-empty one-time credential

        user = await store.get_user("u1")
        assert user is not None and user.must_change_password is True
        assert (await service.login("bob", GOOD_PASSWORD)).ok is False  # old password is dead
        again = await service.login("bob", temp)
        assert again.ok and again.must_change_password is True  # temp works, forces rotation

        ev = next(e for e in notifier.events if e.event_type == PASSWORD_RESET)
        assert ev.username == "bob" and ev.email == "bob@example.org"
        actions = [r["action"] for r in await store.list_audit(limit=50)]
        assert "auth.password_reset" in actions
    finally:
        await store.close()


async def test_admin_reset_password_rejects_ad_and_unknown_users() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        await store.create_user(user_id="ad1", username="ad", auth_provider="ad")
        with pytest.raises(ValueError, match="local"):  # AD users have no local credential to reset
            await service.admin_reset_password("ad1", actor="admin")
        with pytest.raises(ValueError, match="no such user"):
            await service.admin_reset_password("nope", actor="admin")
    finally:
        await store.close()
