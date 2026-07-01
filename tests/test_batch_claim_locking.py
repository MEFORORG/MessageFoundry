# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0058 — server-DB locking + failover cases (T6, T9). Gated on a real SQL Server / Postgres.

**T6 (no-READPAST / #285 — locked head BLOCKS, never skips)** is the PR-blocking #285 gate:

* SQL Server (the production scale-path store, ``supports_ingest_stage = True``) — a concurrent producer
  holding the lane-head row lock must make ``claim_next_fifo_batch`` **BLOCK** (wait), not skip the head
  and return a later seq ahead of it. This proves the ``UPDLOCK, ROWLOCK`` **no-READPAST** cutoff-CTE
  preserves per-lane FIFO. Runs on the ``sql-server`` CI leg.
* Postgres — the inner ``FOR UPDATE`` (no ``SKIP LOCKED``) must likewise BLOCK on a producer-locked head.
  Runs on the ``postgres`` CI leg.

**T9 (Postgres failover stranded-head reclaim under batch)** — an expired-lease INFLIGHT head present;
the in-txn reclaim runs before the window so the recovered head is the (due) prefix head and blocks N+1.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, AsyncIterator

import pytest

from messagefoundry.store import OutboxStatus, Stage

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))


async def _seed_ingress(store: Any, channel: str, times: list[float]) -> list[str]:
    return [await store.enqueue_ingress(channel_id=channel, raw=RAW, now=t) for t in times]


# --- Postgres fixtures -------------------------------------------------------


@pytest.fixture
async def pg_store() -> AsyncIterator[Any]:
    if not _POSTGRES_ON:
        pytest.skip(
            "set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres locking case"
        )
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    async with s._pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE message_events, queue, response, delivered_keys, messages"
            " RESTART IDENTITY CASCADE"
        )
    await s._load_state_cache()
    await s._load_reference_cache()
    try:
        yield s
    finally:
        await s.close()


@pytest.fixture
async def ss_store() -> AsyncIterator[Any]:
    if not _SQLSERVER_ON:
        pytest.skip(
            "set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the SQL Server locking case"
        )
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    async with s._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in (
            "message_events",
            "queue",
            "response",
            "delivered_keys",
            "outbox",
            "messages",
        ):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    try:
        yield s
    finally:
        await s.close()


# --- T6 Postgres: locked head BLOCKS, never skips ----------------------------


async def test_t6_postgres_locked_head_blocks_not_skips(pg_store: Any) -> None:
    """A concurrent txn holds the lane HEAD's row lock (SELECT ... FOR UPDATE). The batch claim must
    BLOCK (no SKIP LOCKED) — it must NOT return a later seq ahead of the locked head. Once the lock is
    released, the batch returns the head FIRST (FIFO preserved)."""
    channel = "IB_T6PG"
    mids = await _seed_ingress(pg_store, channel, [100.0, 101.0, 102.0])
    head_id = mids[0]

    # Hold the HEAD row's lock in a separate connection/txn (simulates a producer mid-insert/commit).
    # NB: enqueue_ingress returns the *message_id*; the queue row's PK `id` is a SEPARATE uuid — lock the
    # head by (message_id, stage), never by `id` (that matches no row, holds no lock, and the claim then
    # never contends — the bug this assertion now guards against).
    lock_conn = await pg_store._pool.acquire()
    tx = lock_conn.transaction()
    await tx.start()
    locked = await lock_conn.fetch(
        "SELECT id FROM queue WHERE message_id=$1 AND stage=$2 FOR UPDATE",
        head_id,
        Stage.INGRESS.value,
    )
    assert len(locked) == 1  # the lock MUST land on the head row, or the test proves nothing
    try:
        # The batch claim must BLOCK on the locked head — it cannot complete while the lock is held.
        claim = asyncio.ensure_future(
            pg_store.claim_next_fifo_batch(channel, now=200.0, stage=Stage.INGRESS.value, limit=8)
        )
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(asyncio.shield(claim), timeout=1.0)
        assert not claim.done()  # still blocked — it did NOT skip the head and grab a later seq
    finally:
        await tx.rollback()  # release the head lock
        await pg_store._pool.release(lock_conn)

    # Now unblocked: the batch returns the head FIRST (and the contiguous due prefix after it), in order.
    items = await asyncio.wait_for(claim, timeout=5.0)
    assert items and items[0].message_id == head_id
    assert [it.message_id for it in items] == mids  # the whole due prefix, head-first


# --- T6 SQL Server: locked head BLOCKS, never skips (PR-blocking #285 gate) ---


async def test_t6_sqlserver_locked_head_blocks_not_skips(ss_store: Any) -> None:
    """SQL Server is the production scale-path store. A concurrent txn holding the lane HEAD's row lock
    (UPDLOCK, ROWLOCK) must make the TOP(N) no-READPAST cutoff-CTE BLOCK, never skip the head and return
    a later seq ahead of it (#285). Once released, the batch returns the head FIRST."""
    channel = "IB_T6SS"
    mids = await _seed_ingress(ss_store, channel, [100.0, 101.0, 102.0])
    head_id = mids[0]

    # Hold the HEAD row's lock in a separate connection/txn. An explicit UPDLOCK,ROWLOCK SELECT inside an
    # open transaction holds an exclusive-intent lock on exactly that row until commit/rollback. NB:
    # enqueue_ingress returns the *message_id*; the queue PK `id` is a SEPARATE uuid — lock by
    # (message_id, stage) so the U-lock lands on the actual head row (locking by `id`=message_id matches
    # no row, holds no lock, and the claim never contends — the bug this assertion now guards against).
    lock_conn = await ss_store._pool.acquire()
    lock_cur = await lock_conn.cursor()
    await lock_cur.execute("BEGIN TRAN")
    await lock_cur.execute(
        "SELECT id FROM queue WITH (UPDLOCK, ROWLOCK) WHERE message_id=? AND stage=?",
        (head_id, Stage.INGRESS.value),
    )
    assert len(await lock_cur.fetchall()) == 1  # the U-lock MUST land on the head row
    try:
        claim = asyncio.ensure_future(
            ss_store.claim_next_fifo_batch(channel, now=200.0, stage=Stage.INGRESS.value, limit=8)
        )
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(asyncio.shield(claim), timeout=1.0)
        assert not claim.done()  # BLOCKED on the locked head — did NOT skip to a later seq
    finally:
        await lock_cur.execute("ROLLBACK TRAN")  # release the head lock
        await lock_cur.close()
        await ss_store._pool.release(lock_conn)

    items = await asyncio.wait_for(claim, timeout=10.0)
    assert items and items[0].message_id == head_id
    assert [it.message_id for it in items] == mids  # head-first, whole due prefix, FIFO preserved


# --- T9 Postgres: failover stranded-head reclaim under batch ------------------


async def test_t9_postgres_stranded_head_reclaimed_under_batch(pg_store: Any) -> None:
    """An expired-lease INFLIGHT head (a crashed/fenced predecessor's stranded row) is reclaimed in the
    SAME txn BEFORE the window, so the recovered head is reconsidered as the (due) prefix head — the
    batch returns it FIRST, never a later seq ahead of it."""
    channel = "IB_T9"
    mids = await _seed_ingress(pg_store, channel, [100.0, 101.0, 102.0])
    head_id = mids[0]

    # Strand the HEAD as INFLIGHT under an EXPIRED lease (simulate a crashed prior leader). Target the
    # head by (message_id, stage): enqueue_ingress returns the message_id, but the queue PK `id` is a
    # SEPARATE uuid, so `WHERE id=head_id` would strand NOTHING and the test would falsely pass.
    async with pg_store._pool.acquire() as conn:
        status = await conn.execute(
            "UPDATE queue SET status=$1, owner='dead-node', lease_expires_at=$2"
            " WHERE message_id=$3 AND stage=$4",
            OutboxStatus.INFLIGHT.value,
            50.0,  # lease expired well before `now`
            head_id,
            Stage.INGRESS.value,
        )
        assert status == "UPDATE 1"  # the strand MUST hit exactly the head row

    # The batch claim reclaims the stranded head first (lease_expires_at < now), then claims the prefix:
    # the recovered head leads, the rest follow, in FIFO order.
    items = await pg_store.claim_next_fifo_batch(
        channel, now=200.0, stage=Stage.INGRESS.value, limit=8
    )
    assert items and items[0].message_id == head_id
    assert [it.message_id for it in items] == mids
