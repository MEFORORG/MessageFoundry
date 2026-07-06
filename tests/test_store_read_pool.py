# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Lockfree-reads: the dedicated read-only WAL connection pool.

Reads run on a small bounded pool of read-only connections instead of serializing behind the single
writer's lock. WAL gives each reader a consistent snapshot concurrent with the writer, so a read
takes no write lock and can't interleave between a write's BEGIN and commit on the shared connection
(the "cannot commit - SQL statements in progress" hazard). For ``:memory:`` — where a second
connection is a *different* database — reads fall back to the writer connection under the lock.
"""

from __future__ import annotations

import asyncio

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.store import _READ_POOL_SIZE


@pytest.fixture
async def file_store(tmp_path):
    s = await MessageStore.open(tmp_path / "pool.db")
    yield s
    await s.close()


async def _enqueue(store: MessageStore, n: int, *, channel: str = "c1") -> str:
    return await store.enqueue_message(
        channel_id=channel,
        raw=f"MSH|^~\\&|S|F|R|F|202606170000||ADT^A01|MSG{n:05d}|P|2.5",
        deliveries=[("archive", "MSH|payload")],
        control_id=f"MSG{n:05d}",
        message_type="ADT^A01",
        now=100.0 + n,
    )


# --- pool presence / fallback ------------------------------------------------


async def test_file_store_opens_a_read_pool(file_store: MessageStore) -> None:
    assert file_store._read_pool is not None
    assert file_store._read_pool.qsize() == _READ_POOL_SIZE
    assert len(file_store._read_conns) == _READ_POOL_SIZE


async def test_memory_store_has_no_pool_and_reads_still_work() -> None:
    # A second connection to ":memory:" is a different empty DB and WAL doesn't apply, so the pool is
    # skipped and reads serialize on the writer under the lock (the pre-pool behaviour) — but the
    # read surface must still behave identically.
    store = await MessageStore.open(":memory:")
    try:
        assert store._read_pool is None
        assert store._read_conns == []
        assert await store.list_messages() == []
        mid = await _enqueue(store, 1)
        assert (await store.get_message(mid))["control_id"] == "MSG00001"
        assert await store.count_messages() == 1
    finally:
        await store.close()


async def test_pooled_connections_are_read_only(file_store: MessageStore) -> None:
    conn = file_store._read_conns[0]
    cur = await conn.execute("PRAGMA query_only")
    assert (await cur.fetchone())[0] == 1
    # query_only is defence in depth: a write on a pooled connection must be refused.
    with pytest.raises(Exception, match="readonly|read-only|read only"):
        await conn.execute("CREATE TABLE should_not_exist (x INTEGER)")


# --- the lockfree property ---------------------------------------------------


async def test_reads_do_not_block_on_a_held_write_lock(file_store: MessageStore) -> None:
    """The core guarantee: a read completes even while the write lock is held. Reads route through the
    pool, not ``self._lock``, so holding the lock in this very task can't deadlock them (it would if a
    read tried to re-acquire the non-reentrant lock)."""
    mid = await _enqueue(file_store, 1)
    async with file_store._lock:  # simulate a long-running write holding the lock
        msgs = await asyncio.wait_for(file_store.list_messages(), timeout=5.0)
        assert [m["id"] for m in msgs] == [mid]
        status = await asyncio.wait_for(file_store.db_status(), timeout=5.0)
        assert status.journal_mode.lower() == "wal"
        depth = await asyncio.wait_for(file_store.stats(), timeout=5.0)
        assert isinstance(depth, dict)


# --- concurrency & snapshot freshness ----------------------------------------


async def test_concurrent_reads_and_writes_do_not_error(file_store: MessageStore) -> None:
    """Many writers (each on the serialized writer) interleaved with many readers (each on its own
    pooled connection) must all succeed — no 'cannot commit - SQL statements in progress', no
    readonly errors, and every committed write is eventually counted."""
    n_writes = 40

    async def writer(i: int) -> None:
        await _enqueue(file_store, i)

    async def reader() -> None:
        # Exercise the de-serialized metrics reads + the message reads together.
        await file_store.list_messages(limit=100)
        await file_store.db_status()
        await file_store.stats()
        await file_store.in_pipeline_depth()
        await file_store.count_messages()
        await file_store.connection_metrics(since=0.0)

    tasks = [writer(i) for i in range(n_writes)] + [reader() for _ in range(30)]
    await asyncio.gather(*tasks)

    assert await file_store.count_messages() == n_writes


async def test_each_pooled_read_sees_the_latest_commit(file_store: MessageStore) -> None:
    """A pooled read must start a fresh snapshot every call — never pin a stale one — so a write is
    visible to the very next read even when both reuse the same pooled connection."""
    assert await file_store.count_messages() == 0
    mid1 = await _enqueue(file_store, 1)
    assert await file_store.count_messages() == 1
    assert await file_store.get_message(mid1) is not None
    await _enqueue(file_store, 2)
    assert await file_store.count_messages() == 2


async def test_outbox_payloads_for_decrypts_through_pool(file_store: MessageStore) -> None:
    # The #14 parity read path (decrypts the transformed payload) must work through the pool too.
    mid = await _enqueue(file_store, 1)
    rows = await file_store.outbox_payloads_for(mid)
    assert [r["payload"] for r in rows] == ["MSH|payload"]


async def test_close_shuts_down_every_pooled_connection(tmp_path) -> None:
    store = await MessageStore.open(tmp_path / "close.db")
    conns = list(store._read_conns)
    assert conns
    await store.close()
    assert store._read_conns == []
    assert store._read_pool is None
    # Every pooled connection is closed: a use-after-close raises rather than silently working.
    with pytest.raises(Exception):
        await conns[0].execute("SELECT 1")
