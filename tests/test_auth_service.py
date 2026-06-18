# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""AuthService unit tests: bootstrap, local login + lockout, sessions, AD group->role mapping."""

from __future__ import annotations

import time

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
    # Once the operator changes the bootstrap password (must_change → False) it's a normal admin
    # account; neither supersession nor expiry may disable it (no single-admin lockout).
    store = await _store()
    try:
        service = AuthService(store, AuthSettings(bootstrap_expiry_hours=72))
        await service.initialize()
        admin = await store.get_user_by_username("admin")
        assert admin is not None
        await store.set_password(
            admin.id,
            password_hash=hash_password("a-claimed-real-passphrase"),
            must_change_password=False,
        )
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
