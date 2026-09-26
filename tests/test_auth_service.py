# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""AuthService unit tests: local login + lockout, sessions, AD group->role mapping.

The first-run bootstrap account and its WP-3 lifecycle were retired by ADR 0183 Amendment A,
Wave 2 (BACKLOG #1136), and their tests went with them. What a fresh store holds now is pinned in
``tests/test_first_run_default_account.py``."""

from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api.security import pending_credential_deadline
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
from messagefoundry.auth.service import AuthService, IssuedCredential, UsernameTaken
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, create_admin

GOOD_PASSWORD = "Sup3rSecret!!"
NEW_PASSWORD = "An0ther-Str0ng-Pass!!"

# The service's own logger, named once so the capture filter and the module cannot drift apart
# (matching tests/test_security_notify.py, which names its module's logger the same way).
_AUTH_LOGGER = "messagefoundry.auth.service"


class _FakeNotifier:
    """Captures security events instead of emailing — for the WP-L3-05 notifier-firing tests."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def _claim(service: AuthService, username: str, one_time_password: str) -> str:
    """Claim an account the way an operator actually would: log in with the one-time credential,
    then rotate it through :meth:`AuthService.change_password`. Returns the claimed password.

    Deliberately NOT a direct ``store.set_password``. Self-service rotation is the ONE path that
    records the claim (``users.password_claimed_at``), so a store-level shortcut produces a row that
    merely LOOKS claimed and leaves the suite blind to any later writer that moves the state it does
    set. That shortcut is why BACKLOG #1245 was invisible to a green suite.
    """
    out = await service.login(username, one_time_password)
    assert out.ok and out.identity is not None
    assert await service.change_password(out.identity, NEW_PASSWORD) == []
    return NEW_PASSWORD


async def test_an_issued_temporary_password_satisfies_active_policy() -> None:
    # The credential an administrator hands out is generated *through* the active policy, even a
    # strict one. This was the bootstrap credential's test until ADR 0183 retired that account; the
    # generator it pinned now serves only admin resets.
    store = await _store()
    try:
        service = AuthService(
            store, AuthSettings(password_min_length=20, password_require_symbol=True)
        )
        await service.initialize()
        issued = await _make_reset_temp(store, service)
        assert service.policy.violations(issued.password) == [] and len(issued.password) >= 20
    finally:
        await store.close()


# --- BACKLOG #1245 / ADR 0164: the recorded claim stamp -------------------------------------------
#
# ``users.password_claimed_at`` records that the holder set their own credential. Its reader, the WP-3
# retirement sweep, went with the first-run account (ADR 0183); the column and its writers stay,
# because the fact it records is still true. These pin the writer's two properties.


async def test_the_claim_stamp_is_write_once_across_a_second_rotation() -> None:
    # BACKLOG #1245: ``set_password`` writes ``password_claimed_at=COALESCE(password_claimed_at, ?)``,
    # so the FIRST claim stands for the life of the account and a later rotation cannot move it.
    # store.py calls that monotonicity "the whole point" and ADR 0164 states it as a design
    # commitment -- yet nothing pinned it. Replacing the COALESCE with a bare assignment left every
    # other #1245 test green, because they all read the column through the NULL / not-NULL gate and
    # never look at its VALUE.
    #
    # The stamp is evidence about WHEN the holder took the account. A later rotation that overwrote
    # it would satisfy every not-None assertion in this file while destroying that fact.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        admin = await create_admin(service)  # unclaimed until the holder rotates it below
        await _claim(service, admin.username, admin.password)

        first = await store.get_user_by_username(ADMIN_USERNAME)
        assert first is not None
        assert first.password_claimed_at is not None and first.password_changed_at is not None
        # The claiming write stamped its OWN instant (one ``now`` per UPDATE feeds both columns).
        # Pinning that here is what makes the comparison below a statement about the claim INSTANT
        # rather than about "some non-NULL value survived".
        assert first.password_claimed_at == first.password_changed_at
        original_stamp = first.password_claimed_at

        # Rotate a SECOND time, through the real service path, as the holder.
        out = await service.login(ADMIN_USERNAME, NEW_PASSWORD)
        assert out.ok and out.identity is not None
        third_password = "A-third-Str0ng-Passphrase!!"
        assert await service.change_password(out.identity, third_password) == []

        again = await store.get_user_by_username(ADMIN_USERNAME)
        assert again is not None and again.password_claimed_at is not None

        # POSITIVE CONTROLS: the second rotation really happened and really wrote THIS row. Without
        # them an unmoved stamp is equally consistent with the rotation never occurring, which is the
        # failure mode most likely to make this test lie. The credential check is clock-independent;
        # the timestamp check proves the UPDATE carrying the claim term ran with a fresh ``now``, so
        # a stamp that stayed put did so because of the COALESCE and not because nothing was written.
        assert (await service.login(ADMIN_USERNAME, third_password)).ok
        assert not (await service.login(ADMIN_USERNAME, NEW_PASSWORD)).ok
        assert again.password_changed_at is not None
        assert again.password_changed_at > first.password_changed_at

        # THE PROPERTY: the claim instant did not move.
        assert again.password_claimed_at == original_stamp
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
    # This drives the real path: claim an account, drop the column to manufacture a pre-#1245
    # database, reopen, and assert the claim came back. Without the backfill the reopened row reads
    # NULL, which the gate reads as "never claimed", and the next trigger disables an account whose
    # holder claimed it long ago -- the defect, re-introduced by its own fix.
    db = tmp_path / "mefor.db"
    store = await MessageStore.open(str(db))
    try:
        service = AuthService(store, AuthSettings())
        admin = await create_admin(service)  # unclaimed until the holder rotates it below
        await _claim(service, admin.username, admin.password)
        claimed = await store.get_user_by_username(ADMIN_USERNAME)
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
        healed = await reopened.get_user_by_username(ADMIN_USERNAME)
        assert healed is not None
        assert healed.password_claimed_at is not None  # the backfill ran on open
        # And it restored the ORIGINAL claim instant, not "now" -- the stamp is evidence about when
        # the holder took the account, so a backfill that merely wrote a non-NULL value would satisfy
        # a not-None assertion while destroying the fact.
        assert healed.password_claimed_at == healed.password_changed_at
    finally:
        await reopened.close()

    # SCOPE, stated rather than implied: this pins that the backfill RESTORES THE STAMP on an
    # upgraded database. The consequence a restored stamp used to have -- the account surviving a
    # WP-3 retirement trigger -- went with that sweep (ADR 0183).


# --- ASVS 6.4.1: an admin-issued initial/reset credential expires when unclaimed -----------------


async def _make_reset_temp(store, service, *, username: str = "alice") -> IssuedCredential:
    """Create a local user, then admin-reset it → a must_change temp with password_changed_at=now.

    Returns the whole :class:`IssuedCredential` (BACKLOG #1141), not just the password, so a caller
    can assert what the ISSUING SURFACE said as well as what the gate does.
    """
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


async def _shift_deadline_to(store, user_id: str, deadline: float, *, hours: int) -> None:
    """Move ``password_changed_at`` so the 6.4.1 deadline lands exactly on ``deadline``.

    The gate reads the wall clock, so the only way to drive it to a chosen boundary is to move the
    stamp it measures from. Writing the stamp (rather than patching ``time.time``) keeps the test on
    the same real arithmetic the engine runs.
    """
    await store._db.execute(
        "UPDATE users SET password_changed_at=? WHERE id=?", (deadline - hours * 3600, user_id)
    )
    await store._db.commit()


async def test_reset_temp_password_expires_when_unclaimed() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(initial_password_expiry_hours=72))
        await service.initialize()
        temp = (await _make_reset_temp(store, service)).password
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
        # the account is NOT disabled — an admin can re-issue a fresh temp
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
        temp = (await _make_reset_temp(store, service)).password
        alice = await store.get_user_by_username("alice")
        await store._db.execute(
            "UPDATE users SET password_changed_at=? WHERE id=?",
            (time.time() - 9999 * 3600, alice.id),
        )
        await store._db.commit()
        assert (await service.login("alice", temp)).ok  # gate off → an aged temp still works
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

        # The subject is the GROUP MAP, not the login mechanism. The simple-bind pathway that used
        # to mint this session is retired (BACKLOG #1137), so this goes through _complete_ad_login
        # -- the shared tail Kerberos and OIDC both end at, and where the group map is applied.
        out = await service._complete_ad_login(principal, None, mfa_verified=True)
        assert out.ok and out.identity is not None
        assert out.identity.auth_provider is AuthProvider.AD
        assert out.identity.roles == frozenset({Role.OPERATOR})
        # The retired pathway is refused regardless of the password; that it refuses at all, and
        # never reaches the directory, is pinned in tests/test_ad_login_pathway_split.py.
        assert not (await service.login("jdoe", "pw", provider=AuthProvider.AD)).ok
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
        # Disable → ACCOUNT_DISABLED. This call ALSO clears the address: update_user_profile's write
        # is unconditional and `email` is the intended final state, so email=None is a real clear.
        # The comment here used to read "no email change this call", which was false in exactly the
        # direction BACKLOG #1139 found — the transition was walked under a comment denying it.
        before_clear = len(notifier.events)
        await service.update_user("u1", display_name=None, email=None, disabled=True, actor="admin")
        assert any(e.event_type == ACCOUNT_DISABLED for e in notifier.events)
        cleared = await store.get_user("u1")
        assert cleared is not None and cleared.email is None  # the write really did clear it
        assert any(
            e.event_type == EMAIL_CHANGED for e in notifier.events[before_clear:]
        )  # and the clear is announced
    finally:
        await store.close()


async def test_notifier_fires_when_the_admin_clears_the_address() -> None:
    """BACKLOG #1139 (ASVS 6.3.7): removing an account's address is an update to its authentication
    details, and it is the LAST moment the old address is reachable — after it,
    ``SecurityEventNotifier.notify`` returns early and the account is excluded from every later
    notice. Reachable from ``PATCH /users/{id}`` with an explicit null and from the console form,
    which posts a blanked field as ``None``."""
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _local_user(store, email="old@example.org")
        await service.update_user("u1", display_name=None, email=None, disabled=None, actor="admin")
        cleared = [e for e in notifier.events if e.event_type == EMAIL_CHANGED]
        assert len(cleared) == 1
        # Addressed to the address being removed — the only one the engine can still reach.
        assert cleared[0].email == "old@example.org"
        assert cleared[0].detail.get("new_email") is None  # a removal, not a repoint
        stored = await store.get_user("u1")
        assert stored is not None and stored.email is None
    finally:
        await store.close()


async def test_notifier_silent_when_the_address_did_not_change() -> None:
    """Negative control for the test above: the emission is keyed on the address actually changing,
    not on ``update_user`` being called. Without this, widening the guard to ``True`` would pass."""
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _local_user(store, email="same@example.org")
        await service.update_user(
            "u1", display_name="Renamed", email="same@example.org", disabled=None, actor="admin"
        )
        assert [e for e in notifier.events if e.event_type == EMAIL_CHANGED] == []
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


async def test_missing_notifier_reports_the_drop_rather_than_swallowing_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #1139 (ASVS 6.3.7): with no notifier wired, ``_notify_security`` returned on
    ``self._security_notifier is None`` without a word, while its own docstring three lines above
    said a missing notifier was logged. Only the FAILURE arm logged, which
    ``test_notifier_failure_is_isolated_from_the_auth_op`` above already covers.

    THIS DROP IS WIDER THAN THE SIBLING IN ``pipeline/security_notify.py``, which loses one account.
    ``security_notifier_from_settings`` returns ``None`` whenever ``[alerts]`` names no SMTP host or
    sender, so an instance running with ``notify_security_events`` on and no relay configured would
    drop every notice for every account on a first deployment, with the lifespan wiring reporting
    nothing either.
    """
    store = await _store()
    try:
        # No ``security_notifier=`` -- exactly what the factory hands the lifespan with no SMTP host.
        service = AuthService(store, AuthSettings())
        await _local_user(store)
        with caplog.at_level(logging.WARNING, logger=_AUTH_LOGGER):
            # EMAIL_CHANGED rather than any other event, because ITS DETAIL CARRIES AN ADDRESS -- so
            # this one case pins the never-log-detail rule as well as the drop itself.
            await service.update_user(
                "u1",
                display_name=None,
                email="repointed@example.net",
                disabled=None,
                actor="admin",
            )
        dropped = [r for r in caplog.records if r.name == _AUTH_LOGGER]
        assert len(dropped) == 1, "a dropped notice must be reported, not silently swallowed"
        message = dropped[0].getMessage()
        # Names WHICH notice and WHOSE account, so an operator can act on it.
        assert EMAIL_CHANGED in message
        assert "bob" in message
        # Never the event detail: on this event type it holds an email address.
        assert "repointed@example.net" not in message
    finally:
        await store.close()


async def test_a_deliberate_notices_off_setting_is_not_reported_as_a_drop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``[auth].notify_security_events = false`` is a documented choice, and the lifespan wires no
    notifier for it. A warning per event there would report the setting working as a fault."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(notify_security_events=False))
        await _local_user(store)
        with caplog.at_level(logging.WARNING, logger=_AUTH_LOGGER):
            await service.update_user(
                "u1",
                display_name=None,
                email="repointed@example.net",
                disabled=None,
                actor="admin",
            )
        assert [r for r in caplog.records if r.name == _AUTH_LOGGER] == []
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
        # Each "login" here goes through _complete_ad_login: the simple-bind pathway is retired
        # (BACKLOG #1137) and this test is about ROLE RESYNC ON LOGIN, which is that tail's job and
        # is reached identically by Kerberos and OIDC.
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")
        assert (await service._complete_ad_login(principal, None, mfa_verified=True)).ok
        assert len(role_changes()) == 1

        # A repeat login with the SAME mapping is not a change → no new notice (silent when unchanged).
        assert (await service._complete_ad_login(principal, None, mfa_verified=True)).ok
        assert len(role_changes()) == 1

        # Re-mapping the group resyncs the role on the next login (operator → viewer) → a fresh notice.
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "viewer")], actor="admin")
        assert (await service._complete_ad_login(principal, None, mfa_verified=True)).ok
        changes = role_changes()
        assert len(changes) == 2
        assert changes[-1].username == "jdoe" and changes[-1].email == "jdoe@example.org"
        assert changes[-1].detail.get("roles") == ["viewer"]
    finally:
        await store.close()


# ---------------------------------------------------------------------------------------------
# BACKLOG #1139 (ASVS 6.3.7): the notification address is engine-owned, and the directory cannot
# reach it. Every test below fails before the split, because before it there was one column and the
# directory's write landed on it.
# ---------------------------------------------------------------------------------------------


async def test_a_directory_repoint_cannot_redirect_the_accounts_notices() -> None:
    """THE DEFECT THIS ITEM WAS FILED AGAINST, end to end.

    ``_upsert_ad_user`` runs on every AD/OIDC login and writes the account's address straight from the
    directory's ``mail`` attribute. While one column served as both the mirror and the notification
    target, a repointed attribute silently became the destination of every later notice on that
    account -- so the question the item poses, "which address do we notify when the directory owns the
    attribute", had no answer: the operation replacing the address was the one the notice was about.

    After the split there is an address the repoint is not replacing, and the question dissolves.
    """
    store = await _store()
    try:
        original = AdPrincipal(
            username="jdoe",
            display_name="J Doe",
            email="jdoe@example.org",
            dn="CN=jdoe,DC=x",
            groups=frozenset({"cn=mf-ops,dc=x"}),
        )
        # The same account, after someone repoints the directory's mail attribute.
        repointed = AdPrincipal(
            username="jdoe",
            display_name="J Doe",
            email="attacker@evil.example",
            dn="CN=jdoe,DC=x",
            groups=frozenset({"cn=mf-ops,dc=x"}),
        )

        class _FakeLdap:
            def authenticate(self, username: str, password: str) -> AdPrincipal | None:
                return None  # simple bind is retired (BACKLOG #1137); logins go through the tail

            def resolve_principal(self, username: str) -> AdPrincipal | None:
                return original if username == "jdoe" else None

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
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "operator")], actor="admin")

        # First login provisions the account and seeds the notification address once.
        assert (await service._complete_ad_login(original, None, mfa_verified=True)).ok
        user = await store.get_user_by_username("jdoe")
        assert user is not None and user.notify_email == "jdoe@example.org"

        # The directory now says something else, and the account logs in again.
        assert (await service._complete_ad_login(repointed, None, mfa_verified=True)).ok
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        assert user.email == "attacker@evil.example"  # the mirror tracks the directory
        assert user.notify_email == "jdoe@example.org"  # the notification target does not

        # Now make the account emit a notice and check where it is addressed. A role resync is the
        # cheapest trigger that runs on the same directory path the repoint came in on.
        await service.set_ad_group_map([("CN=MF-Ops,DC=x", "viewer")], actor="admin")
        assert (await service._complete_ad_login(repointed, None, mfa_verified=True)).ok
        roles_changed = [e for e in notifier.events if e.event_type == ROLES_CHANGED]
        assert roles_changed[-1].email == "jdoe@example.org"
        assert all(e.email != "attacker@evil.example" for e in notifier.events)
    finally:
        await store.close()


async def test_clearing_the_profile_address_leaves_the_account_still_notifiable() -> None:
    """THE DURABILITY RULE, end to end, and the limb the item says the build owes itself.

    Making an address required at creation does not make it durable: an explicit null still clears it
    afterwards, and after the clear ``SecurityEventNotifier.notify`` returns early and the account is
    structurally excluded from every later notice. So the clear must not be able to reach the
    notification address at all -- ``set_user_notify_email`` takes a non-empty ``str``, and the admin
    profile path simply does not call it with a blank.

    Reachable exactly as the item describes: ``PATCH /users/{id}`` with an explicit null, and the
    console form, which posts a blanked field as ``None``.
    """
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _local_user(store, email="bob@example.org")

        await service.update_user("u1", display_name=None, email=None, disabled=None, actor="admin")
        cleared = await store.get_user("u1")
        assert cleared is not None
        assert cleared.email is None  # the profile mirror really did clear
        assert cleared.notify_email == "bob@example.org"  # the notification address stood

        # The account is NOT excluded from later notices, which is the whole point of the limb.
        before = len(notifier.events)
        await service.set_roles("u1", ["viewer"], actor="admin")
        later = notifier.events[before:]
        assert [e.event_type for e in later] == [ROLES_CHANGED]
        assert later[0].email == "bob@example.org"
    finally:
        await store.close()


async def test_an_admin_can_still_repoint_where_notices_go() -> None:
    """Negative control for the test above: the address is durable, not frozen. Without this, making
    ``set_user_notify_email`` a no-op would pass every other test in this block.

    ADR 0182 Amendment A (BACKLOG #1139, slice 3): the repoint is the explicit ``notify_email``
    value now. Setting the profile ``email`` no longer moves it; ``tests/test_admin_notify_email_update.py``
    holds that half."""
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, AuthSettings(), security_notifier=notifier)
        await _local_user(store, email="old@example.org")

        await service.update_user(
            "u1",
            display_name=None,
            email="old@example.org",
            disabled=None,
            notify_email="new@example.org",
            actor="admin",
        )
        moved = await store.get_user("u1")
        assert moved is not None and moved.notify_email == "new@example.org"

        # The notice about the repoint itself still goes to the address on file BEFORE it -- the
        # legitimate owner is alerted even when it was a mistaken or hostile admin who moved it.
        changed = next(e for e in notifier.events if e.event_type == EMAIL_CHANGED)
        assert changed.email == "old@example.org"

        # And the NEXT notice goes to the new one.
        before = len(notifier.events)
        await service.set_roles("u1", ["viewer"], actor="admin")
        assert notifier.events[before].email == "new@example.org"
    finally:
        await store.close()


async def test_the_deliverability_gate_reads_the_notification_address() -> None:
    """``has_notifiable_admin`` decides whether a PHI instance may start. It must ask about the column
    a notice is actually addressed to: an administrator whose profile mirror the directory had just
    repointed would otherwise read as notifiable on an address no notice uses -- the instrument
    answering the adjacent question (SDS-3.8)."""
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        admin = await store.get_user((await create_admin(service)).user_id)
        assert admin is not None
        assert not await service.has_notifiable_admin()  # minted with no address at all

        # A profile-only write -- the shape of a directory sync -- must NOT satisfy the gate.
        await store.update_user_profile(admin.id, display_name=None, email="admin@example.org")
        assert not await service.has_notifiable_admin()

        # Setting the engine-owned address does.
        await store.set_user_notify_email(admin.id, email="admin@example.org")
        assert await service.has_notifiable_admin()
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

        temp = (await service.admin_reset_password("u1", actor="admin")).password
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


# --- BACKLOG #1139 / ASVS 6.3.7: the directory-driven profile write ------------
#
# ``_upsert_ad_user`` sits on the SHARED directory completion path, so it serves the simple-bind,
# Kerberos and federated legs alike. It wrote the account's email from the directory ``mail``
# attribute on every login with neither an audit row nor a notice, and an ABSENT attribute erased
# the stored address -- which is also the account's only notification target, so that erase removed
# the account from every later notice as well.


def _ad_settings() -> AuthSettings:
    return AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )


def _principal(email: str | None, *, display_name: str | None = "J Doe") -> AdPrincipal:
    return AdPrincipal(
        username="jdoe",
        display_name=display_name,
        email=email,
        dn="CN=jdoe,DC=x",
        groups=frozenset(),
    )


async def test_directory_email_repoint_is_audited_and_notified_to_the_old_address() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, _ad_settings(), security_notifier=notifier)
        await service.initialize()

        # The first directory login CREATES the account. Creation is not a change, so it announces
        # nothing -- without this the assertion below could pass on the wrong event.
        assert (await service._complete_ad_login(_principal("old@x"), None, mfa_verified=True)).ok
        assert [e for e in notifier.events if e.event_type == EMAIL_CHANGED] == []

        # The directory now returns a DIFFERENT address for the same principal.
        out = await service._complete_ad_login(_principal("new@x"), "10.0.0.9", mfa_verified=True)
        assert out.ok

        changed = [e for e in notifier.events if e.event_type == EMAIL_CHANGED]
        assert len(changed) == 1
        ev = changed[0]
        # Addressed to the OLD address: the holder of the address being replaced is the party who
        # needs to hear about the replacement.
        assert ev.email == "old@x"
        assert ev.username == "jdoe"
        assert ev.detail["new_email"] == "new@x"
        assert ev.detail["source"] == "directory"
        assert ev.client_ip == "10.0.0.9"

        rows = [
            r
            for r in await store.list_audit(limit=50)
            if r["action"] == "auth.ad_profile_email_changed"
        ]
        assert len(rows) == 1
        assert rows[0]["actor"] == "jdoe"
        assert rows[0]["client"] == "10.0.0.9"
        assert '"source": "directory"' in rows[0]["detail"]

        user = await store.get_user_by_username("jdoe")
        assert user is not None and user.email == "new@x"
    finally:
        await store.close()


async def test_a_second_directory_repoint_notifies_the_engine_owned_address() -> None:
    """BACKLOG #1139. The repoint notice is addressed to ``notify_email``, not to the mirror.

    **A SINGLE REPOINT CANNOT SEE THIS.** On the first one the mirror and the notification address
    still hold the same value, so reading either produces the same string and the test above passes
    against both the right column and the wrong one. The second repoint separates them: the mirror
    now holds whatever the FIRST repoint installed, and addressing the notice there sends it to the
    party who performed the change being announced -- ADR 0182 option 3, rejected in terms.

    The engine-owned address is untouched by both repoints, which is the entire point of the split,
    so it is the target while it exists.
    """
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, _ad_settings(), security_notifier=notifier)
        await service.initialize()

        assert (await service._complete_ad_login(_principal("owner@x"), None, mfa_verified=True)).ok
        assert (
            await service._complete_ad_login(_principal("attacker@evil"), None, mfa_verified=True)
        ).ok
        assert (
            await service._complete_ad_login(_principal("attacker2@evil"), None, mfa_verified=True)
        ).ok

        user = await store.get_user_by_username("jdoe")
        assert user is not None
        assert user.email == "attacker2@evil"  # the mirror tracks the directory
        assert user.notify_email == "owner@x"  # the notification target does not

        changed = [e for e in notifier.events if e.event_type == EMAIL_CHANGED]
        assert len(changed) == 2
        assert changed[-1].email == "owner@x"
        assert changed[-1].detail["new_email"] == "attacker2@evil"
        # The address the first repoint installed must never be a notice target.
        assert all(e.email != "attacker@evil" for e in notifier.events)
    finally:
        await store.close()


async def test_a_repoint_after_a_profile_clear_still_notifies_the_engine_owned_address() -> None:
    """BACKLOG #1139, the other way the two columns come apart -- with no second repoint at all.

    ADR 0182 AC-4 says clearing the PROFILE address leaves the account notifiable. It does. But the
    next directory login then finds an empty mirror, and a fallback that reaches for the mirror
    first falls through to the directory's NEW value -- announcing the change to whoever made it
    while a deliverable engine-owned address sits on the account untouched.
    """
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, _ad_settings(), security_notifier=notifier)
        await service.initialize()

        assert (await service._complete_ad_login(_principal("owner@x"), None, mfa_verified=True)).ok
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        await service.update_user(
            user.id, display_name="J Doe", email=None, disabled=None, actor="admin"
        )
        user = await store.get_user_by_username("jdoe")
        assert user is not None and user.email is None and user.notify_email == "owner@x"

        before = len(notifier.events)
        assert (
            await service._complete_ad_login(_principal("attacker@evil"), None, mfa_verified=True)
        ).ok

        changed = [e for e in notifier.events[before:] if e.event_type == EMAIL_CHANGED]
        assert len(changed) == 1
        assert changed[0].email == "owner@x"
        assert changed[0].detail["new_email"] == "attacker@evil"
    finally:
        await store.close()


async def test_an_absent_directory_attribute_does_not_erase_the_stored_address() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, _ad_settings(), security_notifier=notifier)
        await service.initialize()

        assert (await service._complete_ad_login(_principal("keep@x"), None, mfa_verified=True)).ok

        # A directory returning no ``mail`` is not a site saying "remove this address" -- it covers
        # an unset attribute, one the bind account cannot read, and one trimmed from the search
        # attribute list. The stored value survives, and nothing is announced because nothing moved.
        before = len(notifier.events)
        assert (
            await service._complete_ad_login(
                _principal(None, display_name=None), None, mfa_verified=True
            )
        ).ok

        user = await store.get_user_by_username("jdoe")
        assert user is not None
        assert user.email == "keep@x"
        assert user.display_name == "J Doe"
        assert [e for e in notifier.events[before:] if e.event_type == EMAIL_CHANGED] == []
        assert [
            r
            for r in await store.list_audit(limit=50)
            if r["action"] == "auth.ad_profile_email_changed"
        ] == []
    finally:
        await store.close()


async def test_a_directory_login_that_changes_nothing_announces_nothing() -> None:
    # The store write is unconditional, so the guard has to be the COMPARISON rather than the write.
    # Without it the fix would notify on every single directory login.
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, _ad_settings(), security_notifier=notifier)
        await service.initialize()

        assert (await service._complete_ad_login(_principal("same@x"), None, mfa_verified=True)).ok
        before = len(notifier.events)
        assert (await service._complete_ad_login(_principal("same@x"), None, mfa_verified=True)).ok

        assert [e for e in notifier.events[before:] if e.event_type == EMAIL_CHANGED] == []
    finally:
        await store.close()


async def test_a_first_directory_address_notifies_the_only_reachable_party() -> None:
    # The account carries no address, so there is no earlier holder to protect and the new address is
    # the only party the engine can reach. Notifying nobody is the alternative.
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(store, _ad_settings(), security_notifier=notifier)
        await service.initialize()

        assert (await service._complete_ad_login(_principal(None), None, mfa_verified=True)).ok
        assert [e for e in notifier.events if e.event_type == EMAIL_CHANGED] == []

        assert (await service._complete_ad_login(_principal("first@x"), None, mfa_verified=True)).ok
        changed = [e for e in notifier.events if e.event_type == EMAIL_CHANGED]
        assert len(changed) == 1
        assert changed[0].email == "first@x" and changed[0].detail["new_email"] == "first@x"
    finally:
        await store.close()


async def test_the_directory_repoint_reaches_the_users_own_pull_feed() -> None:
    # The mailbox is the arm that can be absent; ``GET /me/security-events`` is the arm that cannot.
    # It selects ``auth.%`` rows whose ACTOR is the user, so an action named or attributed any other
    # way would be invisible to exactly the accounts the address gate already excludes.
    store = await _store()
    try:
        service = AuthService(store, _ad_settings())
        await service.initialize()

        assert (await service._complete_ad_login(_principal("old@x"), None, mfa_verified=True)).ok
        assert (await service._complete_ad_login(_principal("new@x"), None, mfa_verified=True)).ok

        feed = await service.security_events_for("jdoe")
        assert [e for e in feed if e["action"] == "auth.ad_profile_email_changed"]
    finally:
        await store.close()


# --- BACKLOG #1141 (ASVS 6.4.5): the issued credential CARRIES its deadline -----------------------
#
# The requirement wants the renewal instruction SENT in time to act on. Asserting that the reset
# response merely HAS an expires_at field would be an absence check wearing a positive shape: a
# plausible-looking instant computed from a fresh clock, or from the wrong setting, would satisfy it
# and tell the holder a date the gate does not honour. So each test below pins the surfaced instant
# AGAINST THE GATE — the credential works up to it and is refused after it.


async def test_the_issued_reset_deadline_is_the_instant_the_login_gate_refuses_at() -> None:
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(initial_password_expiry_hours=72))
        await service.initialize()
        issued = await _make_reset_temp(store, service)
        alice = await store.get_user_by_username("alice")
        assert alice is not None and alice.password_changed_at is not None

        # The surfaced instant is derived from the STORED stamp the gate reads, not a fresh clock.
        assert issued.expires_at == alice.password_changed_at + 72 * 3600

        # POSITIVE CONTROL: one second BEFORE the surfaced instant the credential still works.
        # Without it, the refusal below is equally consistent with a reset that produced garbage.
        await _shift_deadline_to(store, alice.id, time.time() + 1, hours=72)
        assert (await service.login("alice", issued.password)).ok

        # One second AFTER it, the gate refuses — so the response named the real boundary.
        await _shift_deadline_to(store, alice.id, time.time() - 1, hours=72)
        out = await service.login("alice", issued.password)
        assert not out.ok and out.error == "invalid credentials"
    finally:
        await store.close()


async def test_no_deadline_is_surfaced_when_the_expiry_setting_is_off() -> None:
    # `initial_password_expiry_hours = 0` is a documented, supported value that removes the deadline
    # outright. The honest surface then states NOTHING, and it must agree with the gate: the two come
    # apart exactly when one of them is a second computation, which is what this pins shut.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(initial_password_expiry_hours=0))
        await service.initialize()
        issued = await _make_reset_temp(store, service)
        assert issued.expires_at is None

        alice = await store.get_user_by_username("alice")
        assert alice is not None
        await store._db.execute(
            "UPDATE users SET password_changed_at=? WHERE id=?",
            (time.time() - 9999 * 3600, alice.id),
        )
        await store._db.commit()
        assert (
            await service.login("alice", issued.password)
        ).ok  # no deadline stated, none enforced
    finally:
        await store.close()


async def test_initial_credential_deadline_is_the_single_source_every_surface_reads() -> None:
    # The surfaces that state or enforce this deadline used to open-code the same arithmetic, which
    # is how BACKLOG #1245 reached the warn path unnoticed. Pin the ones left to one function: the
    # issuing administrator's response and the route layer's statement (the gate itself is pinned by
    # test_the_issued_reset_deadline_is_the_instant_the_login_gate_refuses_at).
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(initial_password_expiry_hours=72))
        await service.initialize()
        issued = await _make_reset_temp(store, service)
        alice = await store.get_user_by_username("alice")
        assert alice is not None

        expected = service.initial_credential_deadline(alice.password_changed_at)
        assert expected is not None
        assert issued.expires_at == expected  # the issuing administrator is told it
        assert pending_credential_deadline(service, alice) == expected  # the route layer states it

        # And the off case returns None rather than a bogus instant, on both inputs that can cause it.
        assert service.initial_credential_deadline(None) is None
        off = AuthService(store, AuthSettings(initial_password_expiry_hours=0))
        assert off.initial_credential_deadline(alice.password_changed_at) is None
    finally:
        await store.close()


# --- BACKLOG #1141 slice 2, limb (b): the out-of-band reset notice CARRIES the deadline ----------
#
# The PASSWORD_RESET notice is the one surface that reaches the HOLDER rather than the issuing
# administrator, so it is where "renewal instructions are sent" is most literally true. It shipped
# with no deadline because the notice fired before the stored stamp was read back. The test pins the
# instant it carries AGAINST THE GATE, the same shape as the reset-response test above, so neither a
# fresh clock nor a gate that drifted from `initial_credential_deadline` can pass it.


async def test_the_reset_notice_states_the_instant_the_login_gate_refuses_at() -> None:
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(initial_password_expiry_hours=72), security_notifier=notifier
        )
        await service.initialize()
        issued = await _make_reset_temp(store, service)
        alice = await store.get_user_by_username("alice")
        assert alice is not None and alice.password_changed_at is not None

        notice = next(e for e in notifier.events if e.event_type == PASSWORD_RESET)
        noticed = notice.detail["expires_at"]
        # Off the STORED stamp the gate reads, exactly. A fresh clock read after the write differs
        # from the stamp by the audit and revoke round-trips, so equality is what catches it.
        assert noticed == alice.password_changed_at + 72 * 3600
        # The holder and the issuing administrator are told the SAME instant.
        assert noticed == issued.expires_at

        # POSITIVE CONTROL: one second before the noticed instant the credential still works.
        await _shift_deadline_to(store, alice.id, time.time() + 1, hours=72)
        assert (await service.login("alice", issued.password)).ok
        # One second after it, the gate refuses, so the notice named the real boundary.
        await _shift_deadline_to(store, alice.id, time.time() - 1, hours=72)
        out = await service.login("alice", issued.password)
        assert not out.ok and out.error == "invalid credentials"
    finally:
        await store.close()


async def test_the_reset_notice_carries_no_deadline_when_the_expiry_setting_is_off() -> None:
    # Control for the test above: at 0 the credential genuinely does not expire, so a notice stating
    # an instant would be the false deadline this item exists to prevent.
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(initial_password_expiry_hours=0), security_notifier=notifier
        )
        await service.initialize()
        await _make_reset_temp(store, service)
        notice = next(e for e in notifier.events if e.event_type == PASSWORD_RESET)
        assert "expires_at" not in notice.detail
    finally:
        await store.close()


async def test_the_reset_notice_to_a_disabled_account_carries_no_deadline() -> None:
    # The deadline line tells the holder to sign in before it, and a disabled account cannot sign
    # in. The issuing administrator's return value still states the instant.
    store = await _store()
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(initial_password_expiry_hours=72), security_notifier=notifier
        )
        await service.initialize()
        await store.upsert_role(role_id="viewer", display_name="Viewer")
        user_id = await service.create_local_user(
            username="alice",
            password="a-long-enough-original-passphrase",
            display_name=None,
            email=None,
            roles=["viewer"],
            actor="admin",
        )
        await store.set_user_disabled(user_id, disabled=True)
        issued = await service.admin_reset_password(user_id, actor="admin")
        notice = next(e for e in notifier.events if e.event_type == PASSWORD_RESET)
        assert "expires_at" not in notice.detail
        assert issued.expires_at is not None
    finally:
        await store.close()


async def _race_for_the_name(store: MessageStore, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the next ``create_user`` lose the BACKLOG #1808 race: a rival row takes the name first,
    then the real insert runs and meets the UNIQUE index, as a concurrent create would."""
    original = store.create_user

    async def racing(**kwargs: Any) -> None:
        monkeypatch.setattr(store, "create_user", original)
        await original(user_id="rival", username=kwargs["username"], auth_provider="local")
        await original(**kwargs)

    monkeypatch.setattr(store, "create_user", racing)


async def test_a_lost_username_race_raises_username_taken(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # BACKLOG #1808: the caller's check passed, then a concurrent create took the name. The store's
    # UNIQUE refusal must come back as UsernameTaken, not as the driver's own integrity error.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        await _race_for_the_name(store, monkeypatch)
        with pytest.raises(UsernameTaken, match="username already exists") as raised:
            await service.create_local_user(
                username="carol",
                password="a-long-enough-original-passphrase",
                display_name=None,
                email=None,
                roles=[],
                actor="admin",
            )
        assert isinstance(raised.value.__cause__, sqlite3.IntegrityError)
        holder = await store.get_user_by_username("carol")
        assert holder is not None and holder.id == "rival"
    finally:
        await store.close()


async def test_an_integrity_refusal_with_no_holder_is_not_called_a_username_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The handler re-reads before it names the conflict. An integrity refusal while no row holds the
    # name is some other fault, so it re-raises untouched rather than being reported as taken.
    store = await _store()
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()

        async def refused(**_kwargs: object) -> None:
            raise sqlite3.IntegrityError("some other constraint")

        monkeypatch.setattr(store, "create_user", refused)
        with pytest.raises(sqlite3.IntegrityError, match="some other constraint"):
            await service.create_local_user(
                username="dave",
                password="a-long-enough-original-passphrase",
                display_name=None,
                email=None,
                roles=[],
                actor="admin",
            )
    finally:
        await store.close()
