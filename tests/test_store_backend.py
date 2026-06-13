"""Backend-agnostic store: the open_store() factory + Store protocol conformance."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from messagefoundry.config.settings import SqliteSync, StoreBackend, StoreSettings
from messagefoundry.store import MessageStore, Store, open_store, sqlite_settings


async def test_open_store_sqlite_returns_working_store(tmp_path: Path) -> None:
    store = await open_store(
        StoreSettings(path=str(tmp_path / "s.db"), synchronous=SqliteSync.FULL)
    )
    try:
        assert isinstance(store, Store)  # runtime_checkable protocol
        assert isinstance(store, MessageStore)
        cur = await store._db.execute("PRAGMA synchronous")  # the FULL setting flowed through
        assert (await cur.fetchone())[0] == 2
        # a write round-trips through the protocol surface
        mid = await store.enqueue_message(channel_id="c", raw="MSH|^~\\&|", deliveries=[])
        row = await store.get_message(mid)
        assert row is not None and row["channel_id"] == "c"
    finally:
        await store.close()


@pytest.mark.skipif(
    importlib.util.find_spec("aioodbc") is not None,
    reason="aioodbc installed; the missing-extra path isn't exercisable here",
)
async def test_open_store_sqlserver_requires_extra() -> None:
    # Without the 'sqlserver' extra, opening the SQL Server backend gives a clear install error.
    settings = StoreSettings(backend=StoreBackend.SQLSERVER, server="s", database="d", username="u")
    with pytest.raises(RuntimeError, match="sqlserver"):
        await open_store(settings)


def test_sqlite_settings_helper() -> None:
    s = sqlite_settings("a.db", synchronous="FULL")
    assert s.backend is StoreBackend.SQLITE
    assert s.path == "a.db"
    assert s.synchronous is SqliteSync.FULL


def test_messagestore_satisfies_store_protocol() -> None:
    # Every method the Store contract requires must exist on the concrete backend.
    required = [
        "close",
        "enqueue_message",
        "record_received",
        "claim_ready",
        "mark_done",
        "mark_failed",
        "reset_stale_inflight",
        "replay",
        "replay_dead",
        "cancel_queued",
        "get_message",
        "list_messages",
        "count_messages",
        "list_dead",
        "count_dead",
        "outbox_for",
        "events_for",
        "record_view",
        "record_audit",
        "list_audit",
        "create_user",
        "get_user",
        "get_user_by_username",
        "list_users",
        "count_users",
        "set_password",
        "set_user_disabled",
        "update_user_profile",
        "delete_user",
        "record_login_success",
        "record_login_failure",
        "upsert_role",
        "list_roles",
        "get_user_role_ids",
        "set_user_roles",
        "roles_for_ad_groups",
        "list_ad_group_role_map",
        "set_ad_group_role_map",
        "create_session",
        "get_session",
        "touch_session",
        "revoke_session",
        "revoke_user_sessions",
        "purge_expired_sessions",
        "db_status",
        "integrity_check",
        "connection_metrics",
    ]
    for name in required:
        assert callable(getattr(MessageStore, name)), name
