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

**ADR 0066 pooled rows (claim_fifo_heads — the §8 external-lock schedules)** live below the per-lane
cases: the pooled claim inverts the contract — a locked head must make the lane **EMPTY without
blocking** (never ``[N+1, ...]``, never a pinned pooled connection), the uncommitted-producer head is
snapshot-invisible (EMPTY-or-committed-successor per the documented fan-in semantics), a mid-prefix
lock truncates the kept prefix with the gap-tail never UPDATEd, and a wedged head is attempts-neutral
across repeated claims. The SQLite analog is vacuous (asserted in ``test_claim_fifo_heads.py``).
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, AsyncIterator

import pytest

from messagefoundry.store import MessageStatus, OutboxStatus, Stage

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


# =============================================================================
# ADR 0066 — pooled claim_fifo_heads external-lock schedules (§8 rows 1a/1b/1c/1e/1f)
# =============================================================================


async def _pg_hold_row_lock(pg_store: Any, message_id: str, stage: str) -> tuple[Any, Any]:
    """Open a second connection/txn holding the FOR UPDATE row lock on one queue row (simulates a
    producer/admin txn mid-commit). NB: lock by (message_id, stage) — the queue PK ``id`` is a
    SEPARATE uuid (see the per-lane T6 comments above). Returns (conn, tx) for the caller to
    rollback + release."""
    conn = await pg_store._pool.acquire()
    tx = conn.transaction()
    await tx.start()
    locked = await conn.fetch(
        "SELECT id FROM queue WHERE message_id=$1 AND stage=$2 FOR UPDATE",
        message_id,
        stage,
    )
    assert len(locked) == 1  # the lock MUST land on the intended row, or the test proves nothing
    return conn, tx


async def _ss_hold_row_lock(ss_store: Any, message_id: str, stage: str) -> tuple[Any, Any]:
    """SQL Server twin of :func:`_pg_hold_row_lock` — an open ``BEGIN TRAN`` holding a
    ``(UPDLOCK, ROWLOCK)`` U-lock on exactly one queue row until rollback.

    The U-lock is taken via the row's ``ix_queue_fifo_in_seq`` key (predicate on
    ``stage, channel_id, status, seq`` — a covered INGRESS-lane seek), NOT via ``message_id``.
    This matches how EVERY real contender touches a queue head (a producer INSERT locks all
    indexes; a sibling claimer's STEP-3 fifo-scan UPDLOCKs the fifo key; a finalizer / delivery
    worker / reset_stale_inflight UPDATEs status/next_attempt_at — all in the fifo index). A
    ``message_id=?`` UPDLOCK instead pins only the clustered key + ix_queue_message — a lock shape
    no production writer holds, and one the store's STEP-3 READPAST fifo-scan CANNOT skip: it reads
    the (unlocked) fifo-index leaf, then WAITS on the clustered-key bookmark lock -> LOCK_TIMEOUT 0
    -> spurious 1222 -> EMPTY-all (the 1c/1e failure). Locking the fifo key makes the store's scan
    READPAST-skip this row via the PROVEN path (the uncommitted-INSERT fan-in test already exercises
    that skip on CI). All callers are INGRESS (channel_id lane)."""
    conn = await ss_store._pool.acquire()
    cur = await conn.cursor()
    # Resolve the row's fifo-index coordinates first (a plain read via ix_queue_message); seq is
    # globally unique (IDENTITY), so (stage, channel_id, status, seq) pins exactly one row. Fully
    # drained before BEGIN TRAN (no-MARS).
    await cur.execute(
        "SELECT channel_id, status, seq FROM queue WHERE message_id=? AND stage=?",
        (message_id, stage),
    )
    coords = await cur.fetchall()
    assert len(coords) == 1  # the target row must exist, or the test proves nothing
    channel_id, status, seq = coords[0]
    await cur.execute("BEGIN TRAN")
    await cur.execute(
        # INDEX hint pins the seek to ix_queue_fifo_in_seq so the U-lock lands on that NC key
        # (the scan site the store's STEP-3 READPAST probe skips), not the clustered key.
        "SELECT id FROM queue WITH (INDEX(ix_queue_fifo_in_seq), UPDLOCK, ROWLOCK)"
        " WHERE stage=? AND channel_id=? AND status=? AND seq=?",
        (stage, channel_id, status, seq),
    )
    assert len(await cur.fetchall()) == 1  # the U-lock MUST land on the intended row
    return conn, cur


async def _pg_lane_pending(pg_store: Any, channel: str) -> list[dict[str, Any]]:
    rows = await pg_store._fetchall(
        "SELECT status, attempts FROM queue WHERE channel_id=$1 AND stage=$2 ORDER BY seq",
        channel,
        Stage.INGRESS.value,
    )
    return [dict(r) for r in rows]


async def _ss_lane_pending(ss_store: Any, channel: str) -> list[dict[str, Any]]:
    return await ss_store._fetchall(
        "SELECT status, attempts FROM queue WHERE channel_id=? AND stage=? ORDER BY seq",
        (channel, Stage.INGRESS.value),
    )


async def _claim_heads_no_block(
    store: Any, *args: Any, timeout: float = 10.0, **kwargs: Any
) -> Any:
    """Run ``claim_fifo_heads`` under a bounded timeout WITHOUT the cancel-corrupts-the-connection
    hazard, then return its result. Mirrors the proven shield pattern of
    :func:`test_t6_sqlserver_locked_head_blocks_not_skips`: the claim runs as a real task wrapped in
    ``asyncio.wait_for(asyncio.shield(task), ...)`` so the timeout's cancellation lands on the SHIELD,
    never on the underlying task.

    Why this matters here: several of these tests hold a lock/uncommitted txn while claiming, and the
    claim MUST return EMPTY promptly (the never-block guarantee — SET LOCK_TIMEOUT 0 → 1222 → EMPTY).
    If a regression ever makes it BLOCK, a bare ``wait_for(store.claim_fifo_heads(...))`` would cancel
    the coroutine mid-``pyodbc.execute`` and tear down the ``async with self._acquire()`` connection
    while the aioodbc worker thread is still executing on it — at command_timeout pyodbc then segfaults
    raising the timeout on a released connection (the exit-139 CI crash this test file guards).

    CRITICAL — we NEVER cancel the task on timeout. Cancelling is itself the segfault vector: it
    delivers ``CancelledError`` into the in-flight ``await cur.execute``, unwinding ``_cursor.__aexit__``
    (``cur.close()``) and ``_acquire.__aexit__`` (releases the pooled connection) while the aioodbc
    executor thread may still be running the blocked ``pyodbc`` statement on that same connection — the
    exact torn-down-connection crash. The reference
    :func:`test_t6_sqlserver_locked_head_blocks_not_skips` does the opposite: it shields, detects the
    block, asserts ``not task.done()`` for a LOUD failure, and lets the task run to completion after the
    caller's ``finally`` releases the lock — precisely what keeps pyodbc from being torn down
    mid-execute. So on a block we surface a clean ``TimeoutError`` (a loud test failure) and leave the
    shielded task pending on its live connection; the caller's ``finally`` then releases the external
    lock, after which the abandoned task's ``execute`` completes and unwinds cleanly on its own. Every
    call site here holds the external lock in a ``try``/``finally``, so this contract holds. This only
    ever runs on a regression — in green CI the claim returns EMPTY promptly and no timeout fires."""
    task = asyncio.ensure_future(store.claim_fifo_heads(*args, **kwargs))
    try:
        return await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
    except (TimeoutError, asyncio.CancelledError):
        # A real block (or an outer cancel). Do NOT cancel `task`: delivering CancelledError into the
        # in-flight `cur.execute` is exactly the torn-down-connection segfault this helper guards
        # against (see the docstring). Assert the block LOUDLY, then re-raise; the shielded task stays
        # pending on its live connection and unwinds after the caller's `finally` releases the lock.
        assert not task.done(), "claim_fifo_heads finished within the timeout — no block to guard"
        raise


# --- 1a: true T6 — locked head => lane EMPTY, no lock-wait, N claimed first after


async def test_pooled_1a_pg_locked_head_lane_empty_never_blocks(pg_store: Any) -> None:
    """Committed N, N+1, N+2; an external txn holds N's row lock → claim_fifo_heads returns EMPTY
    for the lane (never [N+1, N+2] — #285) and completes promptly (SKIP LOCKED probes, never a
    lock-wait: no pinned pooled connection); the tail is never UPDATEd; after release, N leads."""
    channel = "IB_P1APG"
    mids = await _seed_ingress(pg_store, channel, [100.0, 101.0, 102.0])
    conn, tx = await _pg_hold_row_lock(pg_store, mids[0], Stage.INGRESS.value)
    try:
        # EMPTY-on-locked-head must not block (cf. the per-lane T6 above); the shield keeps a
        # regression's block from segfaulting the process (see _claim_heads_no_block).
        res = await _claim_heads_no_block(
            pg_store, Stage.INGRESS.value, [channel], now=200.0, per_lane_limit=8
        )
        assert res.by_lane == {} and res.rearm == frozenset()
        rows = await _pg_lane_pending(pg_store, channel)
        assert all(
            r["status"] == OutboxStatus.PENDING.value and r["attempts"] == 0 for r in rows
        )  # probe-then-claim: nothing was UPDATEd, attempts untouched
    finally:
        await tx.rollback()
        await pg_store._pool.release(conn)
    after = await pg_store.claim_fifo_heads(
        Stage.INGRESS.value, [channel], now=201.0, per_lane_limit=8
    )
    assert [it.message_id for it in after.by_lane[channel]] == mids  # N first, whole prefix


async def test_pooled_1a_ss_locked_head_lane_empty_never_blocks(ss_store: Any) -> None:
    """SQL Server twin of the pooled 1a: RCSI snapshot discovery sees committed N; the READPAST
    probe drops it; the head-pin empties the lane — never [N+1, N+2], never a lock-wait."""
    channel = "IB_P1ASS"
    mids = await _seed_ingress(ss_store, channel, [100.0, 101.0, 102.0])
    conn, cur = await _ss_hold_row_lock(ss_store, mids[0], Stage.INGRESS.value)
    try:
        # The SET LOCK_TIMEOUT 0 never-block guarantee must yield EMPTY promptly here; the shield
        # turns any regression's ~command_timeout block into a clean failure, not the exit-139 pyodbc
        # segfault this file guards (see _claim_heads_no_block).
        res = await _claim_heads_no_block(
            ss_store, Stage.INGRESS.value, [channel], now=200.0, per_lane_limit=8
        )
        assert res.by_lane == {} and res.rearm == frozenset()
        rows = await _ss_lane_pending(ss_store, channel)
        assert all(r["status"] == OutboxStatus.PENDING.value and r["attempts"] == 0 for r in rows)
    finally:
        await cur.execute("ROLLBACK TRAN")
        await cur.close()
        await ss_store._pool.release(conn)
    after = await ss_store.claim_fifo_heads(
        Stage.INGRESS.value, [channel], now=201.0, per_lane_limit=8
    )
    assert [it.message_id for it in after.by_lane[channel]] == mids


# --- 1b: uncommitted-producer head (single-writer lane) + the fan-in disclosure


async def test_pooled_1b_pg_uncommitted_head_invisible_then_claimed(pg_store: Any) -> None:
    """Single-writer lane: an UNCOMMITTED insert is snapshot-invisible → the lane is EMPTY (no
    committed successor exists in a single-writer lane, so nothing can be reached past it) and the
    claim never blocks; after the producer commits, the next claim returns it."""
    channel = "IB_P1BPG"
    mid = await pg_store.record_received(channel_id=channel, raw=RAW, status=MessageStatus.FILTERED)
    conn = await pg_store._pool.acquire()
    tx = conn.transaction()
    await tx.start()
    await conn.execute(
        "INSERT INTO queue (id, message_id, stage, channel_id, payload, status, attempts,"
        " next_attempt_at, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,0,$7,$7,$7)",
        "q-p1b-pg",
        mid,
        Stage.INGRESS.value,
        channel,
        RAW,
        OutboxStatus.PENDING.value,
        100.0,
    )
    try:
        res = await _claim_heads_no_block(pg_store, Stage.INGRESS.value, [channel], now=200.0)
        assert res.by_lane == {}  # invisible head — EMPTY, no block
        await tx.commit()
    finally:
        await pg_store._pool.release(conn)
    res2 = await pg_store.claim_fifo_heads(Stage.INGRESS.value, [channel], now=201.0)
    assert [it.id for it in res2.by_lane[channel]] == ["q-p1b-pg"]


async def test_pooled_1b_ss_uncommitted_head_invisible_then_claimed(ss_store: Any) -> None:
    """SQL Server twin: under RCSI the uncommitted insert is snapshot-invisible (the shipped
    per-lane claim would BLOCK on it — the documented pooled semantic shift, ADR 0066 §3.2)."""
    channel = "IB_P1BSS"
    mid = await ss_store.record_received(channel_id=channel, raw=RAW, status=MessageStatus.FILTERED)
    conn = await ss_store._pool.acquire()
    cur = await conn.cursor()
    await cur.execute(
        "INSERT INTO queue (id, message_id, stage, channel_id, payload, status, attempts,"
        " next_attempt_at, created_at, updated_at) VALUES (?,?,?,?,?,?,0,?,?,?)",
        (
            "q-p1b-ss",
            mid,
            Stage.INGRESS.value,
            channel,
            RAW,
            OutboxStatus.PENDING.value,
            100.0,
            100.0,
            100.0,
        ),
    )
    try:
        res = await _claim_heads_no_block(ss_store, Stage.INGRESS.value, [channel], now=200.0)
        assert res.by_lane == {}
        # Driver-level commit (autocommit=False pool): a SQL `COMMIT TRAN` only decrements the
        # nested @@TRANCOUNT the implicit txn already opened, so the row never durably commits and
        # res2's RCSI snapshot would miss it. conn.commit() is the store's own commit primitive.
        await conn.commit()
    finally:
        await cur.close()
        await ss_store._pool.release(conn)
    res2 = await ss_store.claim_fifo_heads(Stage.INGRESS.value, [channel], now=201.0)
    assert [it.id for it in res2.by_lane[channel]] == ["q-p1b-ss"]


async def test_pooled_1b_pg_fanin_committed_successor_claimable(pg_store: Any) -> None:
    """The DOCUMENTED multi-writer fan-in semantics (ADR 0066 §3.2, verdict A4): on an outbound
    ``destination_name`` lane, writer A's *uncommitted* seq-N row is invisible while writer B's
    *committed* N+1 is discovered and claimable. A's row is claimed on the NEXT pass once committed
    — per-source order preserved."""
    dest = "OB_P1BFPG"
    mid_a = await pg_store.record_received(channel_id="IB", raw=RAW, status=MessageStatus.FILTERED)
    conn = await pg_store._pool.acquire()
    tx = conn.transaction()
    await tx.start()
    await conn.execute(
        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, payload,"
        " status, attempts, next_attempt_at, created_at, updated_at)"
        " VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8,$8,$8)",
        "q-p1bf-pg",
        mid_a,
        Stage.OUTBOUND.value,
        "IB",
        dest,
        "pa",
        OutboxStatus.PENDING.value,
        100.0,
    )
    try:
        # Writer B commits AFTER A's uncommitted insert → B's row carries the HIGHER seq.
        mid_b = await pg_store.enqueue_message(
            channel_id="IB", raw=RAW, deliveries=[(dest, "pb")], now=101.0
        )
        res = await _claim_heads_no_block(pg_store, Stage.OUTBOUND.value, [dest], now=200.0)
        # The committed successor is the visible head — claimed while A's row is still invisible.
        assert [it.message_id for it in res.by_lane[dest]] == [mid_b]
        await tx.commit()
    finally:
        await pg_store._pool.release(conn)
    # A's now-committed row (lower seq, still pending) is claimed on the next pass.
    res2 = await pg_store.claim_fifo_heads(Stage.OUTBOUND.value, [dest], now=201.0)
    assert [it.id for it in res2.by_lane[dest]] == ["q-p1bf-pg"]


async def test_pooled_1b_ss_fanin_committed_successor_claimable(ss_store: Any) -> None:
    """SQL Server twin of the fan-in disclosure: RCSI snapshot discovery adopts Postgres visibility
    on multi-writer ``destination_name`` lanes — writer B's committed N+1 is claimable where the
    shipped per-lane claim would BLOCK until writer A commits N (ADR 0066 §3.2, verdict A4)."""
    dest = "OB_P1BFSS"
    mid_a = await ss_store.record_received(channel_id="IB", raw=RAW, status=MessageStatus.FILTERED)
    conn = await ss_store._pool.acquire()
    cur = await conn.cursor()
    await cur.execute(
        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, payload,"
        " status, attempts, next_attempt_at, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,?,0,?,?,?)",
        (
            "q-p1bf-ss",
            mid_a,
            Stage.OUTBOUND.value,
            "IB",
            dest,
            "pa",
            OutboxStatus.PENDING.value,
            100.0,
            100.0,
            100.0,
        ),
    )
    try:
        # Writer B commits AFTER A's uncommitted insert → B's row carries the HIGHER seq.
        mid_b = await ss_store.enqueue_message(
            channel_id="IB", raw=RAW, deliveries=[(dest, "pb")], now=101.0
        )
        res = await _claim_heads_no_block(ss_store, Stage.OUTBOUND.value, [dest], now=200.0)
        assert [it.message_id for it in res.by_lane[dest]] == [mid_b]
        # Driver-level commit (autocommit=False pool): a SQL `COMMIT TRAN` only decrements the
        # nested @@TRANCOUNT the implicit txn already opened, so A's row never durably commits and
        # res2's RCSI snapshot would miss it. conn.commit() is the store's own commit primitive.
        await conn.commit()
    finally:
        await cur.close()
        await ss_store._pool.release(conn)
    res2 = await ss_store.claim_fifo_heads(Stage.OUTBOUND.value, [dest], now=201.0)
    assert [it.id for it in res2.by_lane[dest]] == ["q-p1bf-ss"]


# --- 1c: multi-lane isolation — lane A's head locked, lane B free → B only


async def test_pooled_1c_pg_multilane_isolation(pg_store: Any) -> None:
    channel_a, channel_b = "IB_P1CPGA", "IB_P1CPGB"
    a = await _seed_ingress(pg_store, channel_a, [100.0, 101.0])
    b = await _seed_ingress(pg_store, channel_b, [100.0])
    conn, tx = await _pg_hold_row_lock(pg_store, a[0], Stage.INGRESS.value)
    try:
        res = await _claim_heads_no_block(
            pg_store, Stage.INGRESS.value, [channel_a, channel_b], now=200.0, per_lane_limit=8
        )
        assert set(res.by_lane) == {channel_b}  # B drains; A is EMPTY, not [N+1]
        assert [it.message_id for it in res.by_lane[channel_b]] == b
        rows = await _pg_lane_pending(pg_store, channel_a)
        assert all(r["status"] == OutboxStatus.PENDING.value and r["attempts"] == 0 for r in rows)
    finally:
        await tx.rollback()
        await pg_store._pool.release(conn)


async def test_pooled_1c_ss_multilane_isolation(ss_store: Any) -> None:
    channel_a, channel_b = "IB_P1CSSA", "IB_P1CSSB"
    a = await _seed_ingress(ss_store, channel_a, [100.0, 101.0])
    b = await _seed_ingress(ss_store, channel_b, [100.0])
    conn, cur = await _ss_hold_row_lock(ss_store, a[0], Stage.INGRESS.value)
    try:
        res = await _claim_heads_no_block(
            ss_store, Stage.INGRESS.value, [channel_a, channel_b], now=200.0, per_lane_limit=8
        )
        assert set(res.by_lane) == {channel_b}
        assert [it.message_id for it in res.by_lane[channel_b]] == b
        rows = await _ss_lane_pending(ss_store, channel_a)
        assert all(r["status"] == OutboxStatus.PENDING.value and r["attempts"] == 0 for r in rows)
    finally:
        await cur.execute("ROLLBACK TRAN")
        await cur.close()
        await ss_store._pool.release(conn)


# --- 1e: mid-prefix gap — only the contiguous head prefix; gap-tail never UPDATEd


async def test_pooled_1e_pg_midprefix_gap_truncates_tail_untouched(pg_store: Any) -> None:
    channel = "IB_P1EPG"
    mids = await _seed_ingress(pg_store, channel, [100.0, 101.0, 102.0])
    conn, tx = await _pg_hold_row_lock(pg_store, mids[1], Stage.INGRESS.value)
    try:
        res = await _claim_heads_no_block(
            pg_store, Stage.INGRESS.value, [channel], now=200.0, per_lane_limit=8
        )
        # Only the contiguous head prefix [N]; the locked N+1 truncates; N+2 is NOT pulled forward.
        assert [it.message_id for it in res.by_lane[channel]] == [mids[0]]
        rows = await pg_store._fetchall(
            "SELECT message_id, status, attempts FROM queue"
            " WHERE channel_id=$1 AND stage=$2 AND message_id <> $3 ORDER BY seq",
            channel,
            Stage.INGRESS.value,
            mids[0],
        )
        assert all(
            r["status"] == OutboxStatus.PENDING.value and r["attempts"] == 0 for r in rows
        )  # the gap-tail rows were never UPDATEd (probe-then-claim)
    finally:
        await tx.rollback()
        await pg_store._pool.release(conn)


async def test_pooled_1e_ss_midprefix_gap_truncates_tail_untouched(ss_store: Any) -> None:
    channel = "IB_P1ESS"
    mids = await _seed_ingress(ss_store, channel, [100.0, 101.0, 102.0])
    conn, cur = await _ss_hold_row_lock(ss_store, mids[1], Stage.INGRESS.value)
    try:
        res = await _claim_heads_no_block(
            ss_store, Stage.INGRESS.value, [channel], now=200.0, per_lane_limit=8
        )
        assert [it.message_id for it in res.by_lane[channel]] == [mids[0]]
        rows = await ss_store._fetchall(
            "SELECT message_id, status, attempts FROM queue"
            " WHERE channel_id=? AND stage=? AND message_id <> ? ORDER BY seq",
            (channel, Stage.INGRESS.value, mids[0]),
        )
        assert all(r["status"] == OutboxStatus.PENDING.value and r["attempts"] == 0 for r in rows)
    finally:
        await cur.execute("ROLLBACK TRAN")
        await cur.close()
        await ss_store._pool.release(conn)


# --- 1f: attempts-neutrality under a wedged head across repeated claim attempts


async def test_pooled_1f_pg_wedged_head_attempts_neutral(pg_store: Any) -> None:
    """Hold the head lock across REPEATED claim attempts (the sweep re-trying a wedged lane): every
    pass is EMPTY, tail ``attempts`` stay 0 (no G6 inflation), nothing dead-letters; after release
    the whole prefix is claimed in order at attempts=1."""
    channel = "IB_P1FPG"
    mids = await _seed_ingress(pg_store, channel, [100.0, 101.0, 102.0])
    conn, tx = await _pg_hold_row_lock(pg_store, mids[0], Stage.INGRESS.value)
    try:
        for i in range(5):
            res = await _claim_heads_no_block(
                pg_store, Stage.INGRESS.value, [channel], now=200.0 + i, per_lane_limit=8
            )
            assert res.by_lane == {}
        rows = await _pg_lane_pending(pg_store, channel)
        assert [(r["status"], r["attempts"]) for r in rows] == [
            (OutboxStatus.PENDING.value, 0)
        ] * 3  # attempts-neutral: nothing inflated, nothing dead-lettered
    finally:
        await tx.rollback()
        await pg_store._pool.release(conn)
    after = await pg_store.claim_fifo_heads(
        Stage.INGRESS.value, [channel], now=300.0, per_lane_limit=8
    )
    assert [it.message_id for it in after.by_lane[channel]] == mids
    assert [it.attempts for it in after.by_lane[channel]] == [1, 1, 1]


async def test_pooled_1f_ss_wedged_head_attempts_neutral(ss_store: Any) -> None:
    channel = "IB_P1FSS"
    mids = await _seed_ingress(ss_store, channel, [100.0, 101.0, 102.0])
    conn, cur = await _ss_hold_row_lock(ss_store, mids[0], Stage.INGRESS.value)
    try:
        for i in range(5):
            res = await _claim_heads_no_block(
                ss_store, Stage.INGRESS.value, [channel], now=200.0 + i, per_lane_limit=8
            )
            assert res.by_lane == {}
        rows = await _ss_lane_pending(ss_store, channel)
        assert [(r["status"], r["attempts"]) for r in rows] == [(OutboxStatus.PENDING.value, 0)] * 3
    finally:
        await cur.execute("ROLLBACK TRAN")
        await cur.close()
        await ss_store._pool.release(conn)
    after = await ss_store.claim_fifo_heads(
        Stage.INGRESS.value, [channel], now=300.0, per_lane_limit=8
    )
    assert [it.message_id for it in after.by_lane[channel]] == mids
    assert [it.attempts for it in after.by_lane[channel]] == [1, 1, 1]


# --- T9-pooled: Postgres lane-array stranded-lease reclaim ---------------------


async def test_pooled_t9_pg_lane_array_stranded_heads_reclaimed(pg_store: Any) -> None:
    """Two lanes, each with an expired-lease INFLIGHT head (a crashed predecessor): the lane-ARRAY
    reclaim runs FIRST in the claim txn, so BOTH recovered heads lead their lanes in one call —
    failover FIFO preserved per lane (the multi-lane twin of the per-lane T9 above)."""
    a = await _seed_ingress(pg_store, "IB_P9A", [100.0, 101.0])
    b = await _seed_ingress(pg_store, "IB_P9B", [100.0, 101.0])
    for head_mid in (a[0], b[0]):
        async with pg_store._pool.acquire() as conn:
            status = await conn.execute(
                "UPDATE queue SET status=$1, owner='dead-node', lease_expires_at=$2"
                " WHERE message_id=$3 AND stage=$4",
                OutboxStatus.INFLIGHT.value,
                50.0,  # lease expired well before `now`
                head_mid,
                Stage.INGRESS.value,
            )
            assert status == "UPDATE 1"  # the strand MUST hit exactly the head row
    res = await pg_store.claim_fifo_heads(
        Stage.INGRESS.value, ["IB_P9A", "IB_P9B"], now=200.0, per_lane_limit=8
    )
    assert [it.message_id for it in res.by_lane["IB_P9A"]] == a  # recovered head FIRST
    assert [it.message_id for it in res.by_lane["IB_P9B"]] == b


# --- 1b fan-in SOAK: multi-writer per-source order (ADR 0066 §8 row 1b merge rider) -----------


async def _fanin_soak(store: Any) -> None:
    """Randomized multi-writer fan-in on ONE outbound ``destination_name`` lane: N source inbounds each
    enqueue a strict-ascending sequence of deliveries to ``dest``, all racing a concurrent drainer. The
    documented §3.2 semantic is that CROSS-source order is NOT honored (a committed successor is
    claimable while a peer's earlier row is still uncommitted), but PER-source order MUST be intact
    end-to-end — each source enqueues sequentially, so its rows carry strictly ascending ``seq`` and are
    claimed in that order regardless of interleaving. Asserts: every produced delivery claimed EXACTLY
    once (no loss, no duplicate), and each source's claimed subsequence == its production order. On
    SQLite the process-wide lock serializes writers+drainer so the race is unobservable (still a valid
    per-source check); the interesting concurrency lives on the SS/PG legs (this file is SS/PG-gated)."""
    import random

    dest = "OB_FANIN_SOAK"
    n_sources = 6
    n_per = 10
    rng = random.Random(0xF0F0)  # fixed seed — reproducible interleave
    produced: dict[int, list[str]] = {s: [] for s in range(n_sources)}
    claimed: list[str] = []
    writers_done = asyncio.Event()

    async def writer(s: int) -> None:
        for k in range(n_per):
            payload = f"{s}:{k}"  # source-tagged, ascending within the source
            await store.enqueue_message(
                channel_id=f"IBSOAK{s}", raw=RAW, deliveries=[(dest, payload)], now=100.0 + k
            )
            produced[s].append(payload)
            await asyncio.sleep(rng.random() * 0.001)  # jitter the interleave

    async def drainer() -> None:
        empties = 0
        counting_quiescence = False
        for _ in range(5000):  # bounded — a real drain finishes in well under this
            if writers_done.is_set():
                if not counting_quiescence:
                    # Writers just finished. The pooled claim NEVER blocks: a contended head yields
                    # EMPTY-all and self-heals on retry (ADR 0066 §9), so ``empties`` racked up while
                    # writers were still committing is NOT evidence the lane drained. Restart the
                    # quiescence count HERE so the ``>= 4`` window measures only genuinely-empty passes
                    # over the fully-committed lane. Without this, a slow/contended backend (observed on
                    # the SQL Server 2025 CI runner) strands the drainer: it hits ``writers_done`` with
                    # stale pre-completion empties already >= 4 and returns BEFORE claiming a single
                    # committed row — claimed == [] though every row is durably present and claimable.
                    empties = 0
                    counting_quiescence = True
                if empties >= 4:
                    return
            res = await store.claim_fifo_heads(
                Stage.OUTBOUND.value, [dest], now=1_000_000.0, per_lane_limit=8
            )
            items = res.by_lane.get(dest, [])
            if not items:
                empties += 1
                await asyncio.sleep(0.001)
                continue
            empties = 0
            for it in items:
                claimed.append(it.payload)
                await store.mark_done(it.id)
        raise AssertionError("drainer did not reach quiescence — the lane never fully drained")

    async def run_writers() -> None:
        await asyncio.gather(*(writer(s) for s in range(n_sources)))
        writers_done.set()

    await asyncio.gather(run_writers(), drainer())

    # No loss, no duplicate: every produced delivery is claimed exactly once.
    all_produced = sorted(p for ps in produced.values() for p in ps)
    assert sorted(claimed) == all_produced, "fan-in lost or duplicated a delivery"
    # Per-source FIFO end-to-end: each source's claimed subsequence is exactly its production order.
    for s in range(n_sources):
        sub = [p for p in claimed if p.split(":", 1)[0] == str(s)]
        assert sub == produced[s], f"source {s} per-source order broken: {sub} != {produced[s]}"


async def test_pooled_1b_ss_fanin_soak_per_source_order(ss_store: Any) -> None:
    """SQL Server merge-rider soak (ADR 0066 §8 row 1b): committed successors claimable, each writer's
    later-committed rows claimed on a later pass, per-inbound order intact under concurrent writers."""
    await _fanin_soak(ss_store)


async def test_pooled_1b_pg_fanin_soak_per_source_order(pg_store: Any) -> None:
    """Postgres merge-rider soak (ADR 0066 §8 row 1b) — the FOR UPDATE SKIP LOCKED twin."""
    await _fanin_soak(pg_store)
