# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Store-layer tests for the auth tables (SQLite backend; SQL Server is covered by the CI job)."""

from __future__ import annotations

from messagefoundry.store.store import MessageStore


async def _store() -> MessageStore:
    return await MessageStore.open(":memory:")


async def _seed_roles(store: MessageStore) -> None:
    for rid in ("administrator", "operator", "viewer"):
        await store.upsert_role(role_id=rid, display_name=rid.title(), description=None)


async def test_create_get_and_list_users() -> None:
    store = await _store()
    try:
        await store.create_user(
            user_id="u1",
            username="alice",
            auth_provider="local",
            display_name="Alice",
            email="a@example.org",
            password_hash="hash",
            now=1000.0,
        )
        assert await store.count_users() == 1
        u = await store.get_user_by_username("alice")
        assert u is not None and u.id == "u1" and u.auth_provider == "local"
        assert u.password_hash == "hash" and u.disabled is False
        assert u.password_changed_at == 1000.0
        assert [r.username for r in await store.list_users()] == ["alice"]
        assert await store.get_user_by_username("nobody") is None
    finally:
        await store.close()


async def test_role_assignment_replace_and_resolution() -> None:
    store = await _store()
    try:
        await _seed_roles(store)
        await store.create_user(user_id="u1", username="alice", auth_provider="local", now=1.0)
        await store.set_user_roles("u1", ["operator", "viewer"], assigned_by="admin", now=2.0)
        assert set(await store.get_user_role_ids("u1")) == {"operator", "viewer"}
        await store.set_user_roles("u1", ["viewer"], now=3.0)  # replace
        assert await store.get_user_role_ids("u1") == ["viewer"]
    finally:
        await store.close()


async def test_security_events_for_user_scopes_to_actor() -> None:
    # The /me/security-events source: only the target actor's auth.* audit rows, newest-first,
    # honoring limit; other actors' rows and non-auth.* rows are excluded.
    store = await _store()
    try:
        await store.record_audit("auth.login_success", actor="alice", detail="1")
        await store.record_audit("auth.login_failed", actor="bob", detail="b")  # other actor
        await store.record_audit("message_view", actor="alice", detail="x")  # not auth.*
        await store.record_audit("auth.password_changed", actor="alice", detail="2")
        rows = await store.security_events_for_user("alice")
        assert [r["action"] for r in rows] == ["auth.password_changed", "auth.login_success"]
        assert len(await store.security_events_for_user("alice", limit=1)) == 1
        assert await store.security_events_for_user("carol") == []  # no events → empty feed
    finally:
        await store.close()


async def test_ad_group_role_map_normalizes_and_resolves() -> None:
    store = await _store()
    try:
        await _seed_roles(store)
        await store.set_ad_group_role_map(
            [("CN=MF-Admins,OU=G,DC=x", "administrator"), ("CN=MF-Ops,OU=G,DC=x", "operator")]
        )
        roles = await store.roles_for_ad_groups(["cn=mf-admins,ou=g,dc=x", "CN=Unknown"])
        assert roles == {"administrator"}  # case-insensitive match; unknown group ignored
        assert await store.roles_for_ad_groups([]) == set()
        assert len(await store.list_ad_group_role_map()) == 2
    finally:
        await store.close()


async def test_login_failure_lockout_and_success_reset() -> None:
    store = await _store()
    try:
        await store.create_user(user_id="u1", username="alice", auth_provider="local", now=1.0)
        await store.record_login_failure("u1", failed_attempts=3, locked_until=500.0, now=10.0)
        u = await store.get_user("u1")
        assert u is not None and u.failed_attempts == 3 and u.locked_until == 500.0
        await store.record_login_success("u1", now=20.0)
        u = await store.get_user("u1")
        assert u is not None and u.failed_attempts == 0 and u.locked_until is None
        assert u.last_login_at == 20.0
    finally:
        await store.close()


async def test_sessions_lifecycle_and_purge() -> None:
    store = await _store()
    try:
        await store.create_user(user_id="u1", username="alice", auth_provider="local", now=1.0)
        await store.create_session(
            token_hash="abc", user_id="u1", expires_at=1000.0, client="console", now=10.0
        )
        s = await store.get_session("abc")
        assert s is not None and s.user_id == "u1" and s.revoked_at is None
        await store.touch_session("abc", now=20.0)
        s = await store.get_session("abc")
        assert s is not None and s.last_used_at == 20.0
        await store.revoke_session("abc", now=30.0)
        s = await store.get_session("abc")
        assert s is not None and s.revoked_at == 30.0
        await store.create_session(token_hash="old", user_id="u1", expires_at=5.0, now=1.0)
        assert await store.purge_expired_sessions(now=100.0) == 1
        assert await store.get_session("old") is None
    finally:
        await store.close()


async def test_delete_user_cascades_roles_and_sessions() -> None:
    store = await _store()
    try:
        await _seed_roles(store)
        await store.create_user(user_id="u1", username="alice", auth_provider="local", now=1.0)
        await store.set_user_roles("u1", ["viewer"], now=2.0)
        await store.create_session(token_hash="t", user_id="u1", expires_at=1000.0, now=2.0)
        await store.delete_user("u1")
        assert await store.get_user("u1") is None
        assert await store.get_user_role_ids("u1") == []
        assert await store.get_session("t") is None
    finally:
        await store.close()
