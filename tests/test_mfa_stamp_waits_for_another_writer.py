# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2964 item 23: SQLite's second-factor stamp waits for another process's writer.

``MessageStore.mark_session_mfa_verified`` reads the session row and writes its stamp in one
transaction. Opened with a deferred ``BEGIN``, the transaction took SQLite's write lock only at the
write, and a read transaction's upgrade waits for nobody: while a writer in another process held
the lock, the stamp failed busy at once, and a factor the user had just proved was answered as a
store error. ``BEGIN IMMEDIATE`` takes the lock at the ``BEGIN``, waiting out the other writer under
``busy_timeout``, so the stamp lands once it commits. A second connection on the same file stands
in for the other process. Synthetic accounts only.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import aiosqlite
import pytest

from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.store.store import MessageStore


async def test_the_mfa_stamp_waits_for_another_processs_writer(tmp_path: Path) -> None:
    """RED when: the stamp's ``_writer_txn`` opens with a deferred ``BEGIN``. Its read then runs
    while the other connection holds the write lock, and its write raises
    ``sqlite3.OperationalError`` at once rather than wait."""
    path = tmp_path / "stamp.db"
    store = await MessageStore.open(path)
    other: aiosqlite.Connection | None = None
    try:
        await store.create_user(
            user_id="u", username="u", auth_provider="local", password_generated=False, audits=()
        )
        token_hash = hash_token(mint_token())
        await store.create_session(
            token_hash=token_hash, user_id="u", expires_at=time.time() + 3600
        )
        other = await aiosqlite.connect(path, isolation_level=None)
        await other.execute("PRAGMA busy_timeout=5000")
        await other.execute("CREATE TABLE stand_in_for_another_process (n INTEGER)")
        await other.execute("BEGIN IMMEDIATE")
        await other.execute("INSERT INTO stand_in_for_another_process VALUES (1)")
        stamp = asyncio.create_task(store.mark_session_mfa_verified(token_hash))
        # The stamp holds the store's writer lock from before its BEGIN, so once it does the stamp
        # has started; the sleep then gives a deferred BEGIN time to reach its write.
        async with asyncio.timeout(10):
            while not store._lock.locked():
                await asyncio.sleep(0.01)
        await asyncio.sleep(0.3)
        if stamp.done():
            await stamp  # raises the stamp's own error, if it failed
            pytest.fail("the stamp finished while another writer held the lock")
        await other.execute("COMMIT")
        await asyncio.wait_for(stamp, timeout=10)
        row = await store.get_session(token_hash)
        assert row is not None and row.mfa_verified_at is not None
    finally:
        if other is not None:
            await other.close()
        await store.close()
