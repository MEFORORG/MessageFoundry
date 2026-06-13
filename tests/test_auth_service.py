"""AuthService unit tests: bootstrap, local login + lockout, sessions, AD group->role mapping."""

from __future__ import annotations

import time

from messagefoundry.auth import Role, hash_password, hash_token
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore

GOOD_PASSWORD = "Sup3rSecret!!"


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
