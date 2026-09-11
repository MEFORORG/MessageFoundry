# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Store-layer tests for the auth tables (SQLite backend; SQL Server is covered by the CI job)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from messagefoundry.store.store import MessageStore
from tests._directory_identity_store_contract import (
    BOUND_GUID,
    CASE_GUID,
    OTHER_GUID,
    _assert_directory_id_compare_is_byte_exact,
    _assert_directory_identity_contract,
    _assert_the_binding_column_is_unconstrained_and_username_is_not,
)


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


# ---------------------------------------------------------------------------------------------
# BACKLOG #1139 (ASVS 6.3.7): ``users.email`` is the PROFILE MIRROR, ``users.notify_email`` is the
# ENGINE-OWNED NOTIFICATION ADDRESS, and the two are separate columns so a directory repoint cannot
# replace the address the resulting notice has to reach.
#
# Every test below fails on the pre-split schema, three of them on a column and a method that did
# not exist. That is the point: there was one column, so there was nothing to assert about a second.
# ---------------------------------------------------------------------------------------------


async def test_create_user_seeds_the_notification_address_from_the_one_it_is_given() -> None:
    """Account birth is the one moment the engine adopts an address without a separate decision --
    there is exactly one in hand. An account created with none carries none, and NULL is the honest
    encoding: the notifier drops such a notice rather than sending to an empty string."""
    store = await _store()
    try:
        await store.create_user(
            user_id="u1", username="alice", auth_provider="local", email="a@example.org"
        )
        await store.create_user(user_id="u2", username="bob", auth_provider="local")
        await store.create_user(user_id="u3", username="carol", auth_provider="local", email="   ")
        alice = await store.get_user("u1")
        assert alice is not None
        assert alice.email == "a@example.org" and alice.notify_email == "a@example.org"
        bob = await store.get_user("u2")
        assert bob is not None and bob.notify_email is None
        # Blank normalises to NULL rather than entering the column as an address that is present
        # and undeliverable.
        carol = await store.get_user("u3")
        assert carol is not None and carol.notify_email is None
    finally:
        await store.close()


async def test_the_directory_sync_write_cannot_move_the_notification_address() -> None:
    """THE DEFECT, at the store layer. ``update_user_profile`` is the ONLY call ``_upsert_ad_user``
    makes against an existing account, and it runs on every AD/OIDC login with whatever the
    directory's ``mail`` attribute says. Before the split it wrote the notification target, so a
    repointed directory attribute would silently become the destination of every later notice on the
    account -- including the notice about the repoint itself."""
    store = await _store()
    try:
        await store.create_user(
            user_id="u1", username="alice", auth_provider="ad", email="a@corp.example"
        )
        # The directory now says something else. This is exactly the shape of a repoint.
        await store.update_user_profile("u1", display_name="Alice A", email="attacker@evil.example")
        user = await store.get_user("u1")
        assert user is not None
        assert user.email == "attacker@evil.example"  # the mirror follows the directory
        assert user.notify_email == "a@corp.example"  # the notification target does not
        # An absent directory attribute is the same story: it clears the mirror, never the target.
        await store.update_user_profile("u1", display_name="Alice A", email=None)
        user = await store.get_user("u1")
        assert user is not None and user.email is None
        assert user.notify_email == "a@corp.example"
    finally:
        await store.close()


async def test_the_notification_address_is_repointable_but_not_erasable() -> None:
    """THE DURABILITY RULE. Requiring an address at creation would not have made it durable, because
    an explicit null still strips it afterwards -- and a stripped account is excluded from every
    later notice, since ``SecurityEventNotifier.notify`` returns early on an empty address. So the
    setter takes a non-empty ``str``: a repoint is allowed and an erasure is refused."""
    store = await _store()
    try:
        await store.create_user(
            user_id="u1", username="alice", auth_provider="local", email="a@example.org"
        )
        await store.set_user_notify_email("u1", email="new@example.org")
        user = await store.get_user("u1")
        assert user is not None and user.notify_email == "new@example.org"
        # The whitespace-only string is the clear the ``str`` type cannot refuse on its own, so the
        # implementation refuses it. Without this arm, "" enters the column and reads as present.
        for blank in ("", "   ", "\t\n"):
            with pytest.raises(ValueError, match="non-empty"):
                await store.set_user_notify_email("u1", email=blank)
        user = await store.get_user("u1")
        assert user is not None and user.notify_email == "new@example.org"  # still standing
    finally:
        await store.close()


async def test_the_schema_upgrade_seeds_the_new_column_on_a_pre_split_database(
    tmp_path: Path,
) -> None:
    """A database opened before the split has no ``notify_email``, and NULL on every row would mean
    every existing account silently stopped receiving notices. The ADD is therefore paired with a
    one-time seed from the column that IS the notification target on that schema.

    Driven against a REAL pre-split table rather than a fresh open: a fresh open runs the CREATE
    TABLE, which already carries the column, so it would exercise nothing.
    """
    db = tmp_path / "pre-split.db"
    store = await MessageStore.open(str(db))
    try:
        await store.create_user(
            user_id="u1", username="alice", auth_provider="local", email="a@example.org"
        )
        await store.create_user(user_id="u2", username="bob", auth_provider="local")
    finally:
        await store.close()
    # Drop the column to reproduce the pre-split shape (SQLite supports DROP COLUMN since 3.35).
    with sqlite3.connect(db) as raw:
        raw.execute("ALTER TABLE users DROP COLUMN notify_email")
        cols = {r[1] for r in raw.execute("PRAGMA table_info(users)")}
        assert "notify_email" not in cols  # positive control: the column really is gone
    store = await MessageStore.open(str(db))
    try:
        alice = await store.get_user("u1")
        assert alice is not None and alice.notify_email == "a@example.org"
        bob = await store.get_user("u2")
        assert bob is not None and bob.notify_email is None  # nothing to seed from
    finally:
        await store.close()


# --- directory-immutable identity binding (BACKLOG #1471) ---------------------


async def test_the_directory_id_lookup_finds_a_bound_row_and_never_an_unbound_one() -> None:
    """``get_user_by_directory_object_id`` on the SQLite backend.

    The shared body is what the PostgreSQL and SQL Server suites also run, so a backend that drifts
    from the other two fails against the same assertions rather than against its own wording.
    """
    store = await _store()
    try:
        await _assert_directory_identity_contract(store)
    finally:
        await store.close()


async def test_the_directory_id_comparison_is_byte_exact_on_sqlite() -> None:
    """SQLite compares the column under its default BINARY collation, so case is significant.

    PostgreSQL agrees. SQL Server takes the database's collation instead and pins its own behaviour
    in its own suite -- a real cross-backend divergence, recorded at ``store/sqlserver.py``.
    """
    store = await _store()
    try:
        await _assert_directory_id_compare_is_byte_exact(store)
    finally:
        await store.close()


async def test_the_binding_column_is_unconstrained_and_username_is_not_on_sqlite() -> None:
    """The layer under the lookup: ``directory_object_id`` has no uniqueness constraint, and
    ``UNIQUE(username)`` is the control the schema comments name as the reason it needs none."""
    store = await _store()
    try:
        await _assert_the_binding_column_is_unconstrained_and_username_is_not(store)
    finally:
        await store.close()


async def test_the_directory_id_column_upgrade_carries_no_backfill_and_reruns_clean(
    tmp_path: Path,
) -> None:
    """A database opened before BACKLOG #1471 has no ``directory_object_id``, and the ALTER that
    adds it deliberately seeds NOTHING: nothing in the store has ever held the directory's
    identifier, so the only value on that schema to backfill from is the recyclable username --
    which is the adoption the item exists to refuse.

    Driven against a REAL pre-binding table rather than a fresh open, which runs the CREATE TABLE
    that already carries the column and would exercise the guarded ALTER not at all. The later
    opens are the idempotence arm: ``_migrate`` runs on EVERY open, so a guard that stopped
    skipping a present column would raise ``duplicate column name`` on the next start of every
    upgraded engine.
    """
    db = tmp_path / "pre-binding.db"
    store = await MessageStore.open(str(db))
    try:
        await store.create_user(
            user_id="u1",
            username="jsmith",
            auth_provider="ad",
            directory_object_id=BOUND_GUID,
        )
    finally:
        await store.close()
    # Drop the column to reproduce the pre-#1471 shape (SQLite supports DROP COLUMN since 3.35).
    with sqlite3.connect(db) as raw:
        raw.execute("ALTER TABLE users DROP COLUMN directory_object_id")
        cols = {r[1] for r in raw.execute("PRAGMA table_info(users)")}
        assert "directory_object_id" not in cols  # positive control: the column really is gone

    store = await MessageStore.open(str(db))
    try:
        # The ALTER ran: the row survives and the column is back, holding NULL.
        row = await store.get_user("u1")
        assert row is not None and row.username == "jsmith"
        assert row.directory_object_id is None
        # An upgraded-but-unbound row is not adopted by the id it used to carry.
        assert await store.get_user_by_directory_object_id(BOUND_GUID) is None
    finally:
        await store.close()

    # Re-opening twice more must neither error nor undo the column, and a freshly-bound account has
    # to resolve through the ALTER-ed column afterwards -- otherwise "idempotent" would be
    # satisfied by a migration that quietly stopped working.
    for pass_no, guid in enumerate((OTHER_GUID, CASE_GUID)):
        store = await MessageStore.open(str(db))
        try:
            await store.create_user(
                user_id=f"u-rebind-{pass_no}",
                username=f"rebound{pass_no}",
                auth_provider="ad",
                directory_object_id=guid,
            )
            found = await store.get_user_by_directory_object_id(guid)
            assert found is not None and found.id == f"u-rebind-{pass_no}"
            # The earlier pass's binding is still readable, so each open preserved the column
            # rather than re-adding an empty one.
            assert (await store.get_user("u1")).directory_object_id is None
        finally:
            await store.close()
