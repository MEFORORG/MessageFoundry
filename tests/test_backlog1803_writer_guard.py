# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1803: the SQLite short-writer guard, and what it closes.

A short writer takes the writer lock, issues its DML with no ``BEGIN`` of its own and calls
``_commit()``. sqlite3's ``isolation_level=''`` auto-begins before the first DML, so anything raised
between that DML and the commit used to leave the implicit transaction open on the ONE writer
connection. The next ``_writer_txn`` writer then failed its own ``BEGIN``; the next short writer
joined the stranger's transaction and its ``COMMIT`` made the partial work durable.

The CONTRACT tests drive :func:`_writer_guard` on a bare connection, so they prove the helper itself
and not whichever writer happens to use it.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import aiosqlite
import pytest

from messagefoundry.store.store import UncommittedWriteError, _writer_guard

# Bound on every handshake with a parked writer, so a wedged case fails as a timeout, not a hang.
WAIT = 5.0


class _Boom(Exception):
    """An ordinary failure raised after the block's first DML."""


async def _fresh(tmp_path: Path) -> aiosqlite.Connection:
    db = await aiosqlite.connect(str(tmp_path / "guard.db"))
    await db.execute("CREATE TABLE t (k TEXT PRIMARY KEY)")
    await db.commit()
    return db


async def _keys(db: aiosqlite.Connection) -> list[str]:
    cur = await db.execute("SELECT k FROM t ORDER BY k")
    return [row[0] for row in await cur.fetchall()]


# --- the guard's own contract --------------------------------------------------------------------


async def test_clean_exit_with_an_uncommitted_write_raises_and_rolls_back(tmp_path: Path) -> None:
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()
    try:
        with pytest.raises(UncommittedWriteError, match="without committing"):
            async with _writer_guard(db, lock):
                await db.execute("INSERT INTO t VALUES ('forgot-to-commit')")
        assert not db.in_transaction, "the guard let a block leave its write open"
        assert not lock.locked()
        assert await _keys(db) == []
    finally:
        await db.close()


async def test_a_read_only_early_exit_passes_and_opens_nothing(tmp_path: Path) -> None:
    """The reason the guard is not ``_writer_txn``: a block that only read must exit for free. A
    guard that BEGINs would leave this exit holding an open, empty transaction and raise on it."""
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()

    async def consume(key: str) -> bool:
        async with _writer_guard(db, lock):
            cur = await db.execute("SELECT 1 FROM t WHERE k=?", (key,))
            if await cur.fetchone() is None:
                return False  # the early exit: nothing written, nothing to commit
            await db.execute("DELETE FROM t WHERE k=?", (key,))
            await db.commit()
            return True

    try:
        assert await consume("absent") is False
        assert not db.in_transaction
        # ... and the committing path is untouched by the clean-exit check.
        await db.execute("INSERT INTO t VALUES ('present')")
        await db.commit()
        assert await consume("present") is True
        assert not db.in_transaction
        assert await _keys(db) == []
    finally:
        await db.close()


async def test_an_ordinary_failure_after_a_write_rolls_back_and_propagates(tmp_path: Path) -> None:
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()
    try:
        with pytest.raises(_Boom):
            async with _writer_guard(db, lock):
                await db.execute("INSERT INTO t VALUES ('half')")
                raise _Boom("the second statement's cipher call failed")
        assert not db.in_transaction
        assert await _keys(db) == []
    finally:
        await db.close()


async def test_a_cancellation_after_a_write_rolls_back(tmp_path: Path) -> None:
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()
    wrote = asyncio.Event()

    async def writer() -> None:
        async with _writer_guard(db, lock):
            await db.execute("INSERT INTO t VALUES ('cancelled')")
            wrote.set()
            await asyncio.Event().wait()  # parked mid-block until cancelled

    try:
        task = asyncio.create_task(writer())
        await asyncio.wait_for(wrote.wait(), WAIT)
        assert db.in_transaction  # the write really is open at the cancel point
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, WAIT)
        assert not db.in_transaction
        assert not lock.locked()
        assert await _keys(db) == []
    finally:
        await db.close()


async def test_a_cancel_during_the_clean_exit_rollback_wins(tmp_path: Path) -> None:
    """The clean-exit rollback goes through the same shared unwind as a failure, so a cancellation
    landing inside it is honoured, and the uncommitted-write error rides along as its cause."""
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()
    real_rollback = db.rollback
    rollback_started = asyncio.Event()

    async def slow_rollback() -> None:
        rollback_started.set()
        await asyncio.sleep(0.2)
        await real_rollback()

    db.rollback = slow_rollback  # type: ignore[method-assign]

    async def writer() -> None:
        async with _writer_guard(db, lock):
            await db.execute("INSERT INTO t VALUES ('forgot-to-commit')")

    try:
        task = asyncio.create_task(writer())
        await asyncio.wait_for(rollback_started.wait(), WAIT)
        task.cancel()
        with pytest.raises(asyncio.CancelledError) as caught:
            await asyncio.wait_for(task, WAIT)
        assert isinstance(caught.value.__cause__, UncommittedWriteError)
        assert not db.in_transaction
        assert not lock.locked()
        assert await _keys(db) == []
    finally:
        db.rollback = real_rollback  # type: ignore[method-assign]
        await db.close()


async def test_a_transaction_left_open_by_another_block_is_rolled_back_on_entry(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Defence in depth. A transaction open when the guard takes the lock was abandoned by a block
    that already let go. The guard must neither commit it with this writer's work nor fail this
    writer for it: it logs at ERROR and rolls the stranger's work back."""
    db = await _fresh(tmp_path)
    lock = asyncio.Lock()
    try:
        await db.execute("INSERT INTO t VALUES ('stranger')")  # left open, as a leaking block would
        assert db.in_transaction
        with caplog.at_level(logging.ERROR, logger="messagefoundry.store.store"):
            async with _writer_guard(db, lock):
                await db.execute("INSERT INTO t VALUES ('mine')")
                await db.commit()
        assert await _keys(db) == ["mine"], "the stranger's write rode out on this writer's COMMIT"
        assert any("already open" in r.getMessage() for r in caplog.records), caplog.text

        # A read-only exit after a leak must not raise on the stranger's behalf either.
        await db.execute("INSERT INTO t VALUES ('stranger-2')")
        async with _writer_guard(db, lock):
            await db.execute("SELECT 1 FROM t")
        assert not db.in_transaction
        assert await _keys(db) == ["mine"]
    finally:
        await db.close()
