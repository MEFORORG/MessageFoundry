# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared helpers for the live claim tests that hold a queue head's lock (BACKLOG #1270).

Shared here rather than imported as a private name from one test module.
``tests/test_batch_claim_locking.py`` built them for the pooled external-lock schedules, and
``tests/test_adr0114_claim_proc_live.py`` uses them to lock a head and CALL the ``_v2`` claim proc."""

from __future__ import annotations

import asyncio
from typing import Any

from messagefoundry.store import Stage


async def ss_hold_row_lock(ss_store: Any, message_id: str, stage: str) -> tuple[Any, Any]:
    """An open ``BEGIN TRAN`` holding a ``(UPDLOCK, ROWLOCK)`` U-lock on exactly one queue row until
    rollback. The SQL Server twin of ``_pg_hold_row_lock`` in ``tests/test_batch_claim_locking.py``.

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
    try:
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
    except Exception:
        # The callers' try/finally starts only once this returns, so a failure here must release
        # what it took itself: a leaked open transaction would hold its lock against the next
        # test's cleanup DELETE, which waits at the default LOCK_TIMEOUT -1.
        try:
            await conn.rollback()
        finally:
            await cur.close()
            await ss_store._pool.release(conn)
        raise
    return conn, cur


async def ss_lane_pending(ss_store: Any, channel: str) -> list[dict[str, Any]]:
    """The INGRESS lane's rows in seq order, status and attempts only: what a held-head claim must
    leave untouched (probe-then-claim UPDATEs nothing it skipped)."""
    return await ss_store._fetchall(
        "SELECT status, attempts FROM queue WHERE channel_id=? AND stage=? ORDER BY seq",
        (channel, Stage.INGRESS.value),
    )


async def claim_heads_no_block(store: Any, *args: Any, timeout: float = 10.0, **kwargs: Any) -> Any:
    """Run ``claim_fifo_heads`` under a bounded timeout WITHOUT the cancel-corrupts-the-connection
    hazard, then return its result. Mirrors the proven shield pattern of
    ``test_t6_sqlserver_locked_head_blocks_not_skips`` in ``tests/test_batch_claim_locking.py``: the
    claim runs as a real task wrapped in ``asyncio.wait_for(asyncio.shield(task), ...)`` so the
    timeout's cancellation lands on the SHIELD, never on the underlying task.

    Why this matters: the callers hold a lock/uncommitted txn while claiming, and the claim MUST
    return EMPTY promptly (the never-block guarantee — SET LOCK_TIMEOUT 0 → 1222 → EMPTY). If a
    regression ever makes it BLOCK, a bare ``wait_for(store.claim_fifo_heads(...))`` would cancel
    the coroutine mid-``pyodbc.execute`` and tear down the ``async with self._acquire()`` connection
    while the aioodbc worker thread is still executing on it — at command_timeout pyodbc then segfaults
    raising the timeout on a released connection (the exit-139 CI crash this helper guards).

    CRITICAL — we NEVER cancel the task on timeout. Cancelling is itself the segfault vector: it
    delivers ``CancelledError`` into the in-flight ``await cur.execute``, unwinding ``_cursor.__aexit__``
    (``cur.close()``) and ``_acquire.__aexit__`` (releases the pooled connection) while the aioodbc
    executor thread may still be running the blocked ``pyodbc`` statement on that same connection — the
    exact torn-down-connection crash. The reference T6 test does the opposite: it shields, detects the
    block, asserts ``not task.done()`` for a LOUD failure, and lets the task run to completion after the
    caller's ``finally`` releases the lock — precisely what keeps pyodbc from being torn down
    mid-execute. So on a block we surface a clean ``TimeoutError`` (a loud test failure) and leave the
    shielded task pending on its live connection; the caller's ``finally`` then releases the external
    lock, after which the abandoned task's ``execute`` completes and unwinds cleanly on its own. Every
    call site holds the external lock in a ``try``/``finally``, so this contract holds. This only
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


def assert_skip_named(res: Any, lane: str, *, abort_ok: bool) -> None:
    """BACKLOG #1270: a lane EMPTY behind a held head must NAME its route, never read as "no work".

    The completed claim names the lane in ``head_skipped``. On SQL Server alone the whole attempt may
    instead abort on 1222 (``lock_timeout``) and read no row, which names the route without the lane;
    ``abort_ok`` admits that, and only that. Either way a silent EMPTY fails here."""
    if abort_ok and res.lock_timeout is not None:
        assert res.head_skipped == frozenset()  # an aborted claim read no row, so it names none
        return
    assert res.head_skipped == frozenset({lane}), (
        f"the locked head's lane came back EMPTY without being named: {res.head_skipped!r}"
    )
