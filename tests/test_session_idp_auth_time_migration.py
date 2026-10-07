# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A SQLite store from before ``sessions.idp_auth_time`` gains the column on open (BACKLOG #2143).

The column is what the IdP step-up compares a new ``auth_time`` with. A store opened over an older
file must add it, and an ``oidc`` row already there must read NULL, which the step-up refuses as not
fresh (``tests/test_oidc_step_up.py`` pins that refusal).

SQLite only. This file does not exercise the Postgres or SQL Server column additions. Their hosted
legs run ``tests/_session_rotation_contract.py`` against a schema whose CREATE TABLE already carries
the column, so the gated ``ADD COLUMN`` and the ``COL_LENGTH`` ``ALTER`` do nothing there.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from messagefoundry.store.store import MessageStore


@pytest.mark.skipif(
    sqlite3.sqlite_version_info < (3, 35, 0),
    reason="rebuilding the older shape needs ALTER TABLE ... DROP COLUMN (SQLite 3.35)",
)
async def test_an_older_store_gains_the_column_and_an_existing_row_reads_null(
    tmp_path: Path,
) -> None:
    db = tmp_path / "older.db"
    store = await MessageStore.open(str(db))
    try:
        now = time.time()
        await store.create_user(
            user_id="u1",
            username="jdoe",
            auth_provider="ad",
            directory_object_id="guid-jdoe",
            password_generated=False,
        )
        await store.create_session(
            token_hash="a" * 64,
            user_id="u1",
            expires_at=now + 3600,
            now=now,
            auth_mechanism="oidc",
            idp_auth_time=now - 10,
        )
    finally:
        await store.close()

    # Take the file back to the shape it had before the column existed.
    conn = sqlite3.connect(db)
    try:
        conn.execute("ALTER TABLE sessions DROP COLUMN idp_auth_time")
        conn.commit()
        cols = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
    finally:
        conn.close()
    assert "auth_mechanism" in cols and "idp_auth_time" not in cols

    store = await MessageStore.open(str(db))
    try:
        older = await store.get_session("a" * 64)
        assert older is not None and older.auth_mechanism == "oidc"
        assert older.idp_auth_time is None
        await store.mark_session_reauthed("a" * 64, idp_auth_time=now + 1.5)
        moved = await store.get_session("a" * 64)
        assert moved is not None and moved.idp_auth_time == now + 1.5
    finally:
        await store.close()
