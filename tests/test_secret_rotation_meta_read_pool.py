# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5665: the SQLite ``get_secret_rotation_meta`` reads through the read pool.

It used to run its SELECT on the writer connection, outside the writer lock, so it saw whatever
transaction the writer had open at that instant. A file-backed store is needed: only there does
``_read`` borrow a pooled connection with its own committed snapshot."""

from __future__ import annotations

from pathlib import Path

from messagefoundry.store.store import MessageStore


async def test_rotation_meta_read_never_sees_the_writers_uncommitted_row(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "meta.db")
    try:
        assert store._read_pool is not None  # the pooled path this test exists for
        async with store._lock:
            # Auto-begins a transaction on the writer connection and leaves it open.
            await store._db.execute(
                "INSERT INTO secret_rotation_meta"
                " (secret_key, fingerprint, tracked_since, last_rotated) VALUES (?, ?, ?, ?)",
                ("MEFOR_TEST_KEY", "fp", "2026-01-01", "2026-01-01"),
            )
            try:
                assert await store.get_secret_rotation_meta() == {}
            finally:
                await store._db.rollback()
    finally:
        await store.close()
