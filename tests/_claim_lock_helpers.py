# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared helpers for the live claim tests that hold a queue head's lock (BACKLOG #1270).

Shared here rather than imported as a private name from one test module. At least these use them:
``tests/test_batch_claim_locking.py``, which built them for the pooled external-lock schedules, and
``tests/test_adr0114_claim_proc_live.py``, which locks a head and CALLs the ``_v2`` claim proc.
``claim_past_empty_yield`` is the one copy of the EMPTY-all retry that several claim test files each
carried (BACKLOG #4915); grep for its importers rather than trust a list here."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from messagefoundry.odbc_call_gate import abandon_one_shot, close_one_shot, install_call_gate
from messagefoundry.store import ClaimAbortPhase, ClaimedHeads, Stage

# The cap and backoff of claim_past_empty_yield.
_CLAIM_YIELD_RETRIES = 16
_CLAIM_YIELD_BACKOFF = 0.01


def _did_something(res: ClaimedHeads) -> bool:
    return bool(res.by_lane or res.rearm)


async def claim_past_empty_yield(
    claim: Callable[[], Awaitable[ClaimedHeads]],
    *,
    done: Callable[[ClaimedHeads], bool] = _did_something,
) -> ClaimedHeads:
    """Run ``claim`` and re-issue it past a transient EMPTY-all, for a site asserting a NON-empty
    outcome. Returns as soon as ``done`` holds, by default once the claim did anything: a non-empty
    ``by_lane`` or ``rearm``. A site with another goal, such as a claim that did not abort on 1222,
    passes its own ``done``; the result is the last attempt either way. The argument below is for
    the default ``done``.

    Why it is needed: ``claim_fifo_heads`` on SQL Server runs under ``SET LOCK_TIMEOUT 0`` (ADR 0066
    section 9, never-block), so a transient lock can fail the WHOLE claim closed to EMPTY-all, rolled
    back with nothing consumed. That yield is contract-legal but flakes a single-shot assertion; on
    the SQL Server leg it was once a 1-in-40 ``KeyError`` on ``res.by_lane[...]``.

    Why it masks nothing: EMPTY-all is a full rollback, so a retry cannot double-claim, and a claim
    that did anything never retries. A GENUINELY unclaimable head stays EMPTY-all on every pass and
    still fails the caller's assertion after the cap. A real BLOCK raised through
    :func:`claim_heads_no_block` is an exception, not a return, so it is never retried. A site whose
    assertion IS the EMPTY-all calls the claim once, directly: that answer is immune to the yield.
    SQLite serializes and Postgres skips locked rows, so neither yields and the loop is a no-op there."""
    res = await claim()
    for _ in range(_CLAIM_YIELD_RETRIES):
        if done(res):
            break
        await asyncio.sleep(_CLAIM_YIELD_BACKOFF)
        res = await claim()
    return res


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
    cur: Any = None
    try:
        # The store's own call gate (BACKLOG #2049), so a discard never frees a handle under a
        # statement a cancellation left running. Idempotent: a connection the store has lent is gated.
        install_call_gate(conn)
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
    except BaseException:
        # The callers' try/finally starts only once this returns, so a failure here must release
        # what it took itself: a leaked open transaction would hold its lock against the next
        # test's cleanup DELETE, which waits at the default LOCK_TIMEOUT -1.
        await _ss_discard(ss_store, conn, cur)
        raise
    return conn, cur


async def ss_release_row_lock(ss_store: Any, conn: Any, cur: Any) -> None:
    """The other half of :func:`ss_hold_row_lock`, for each caller's ``finally``: roll the held
    transaction back and return the connection to the pool. If the rollback or the cursor close
    raises, or a cancellation lands in either, the connection is discarded instead, so the release
    still happens and nothing reaches the pool with the lock held (BACKLOG #4915).

    It installs the call gate first when the connection has none, so the discard above goes through
    the gate rather than ``close_one_shot``, which would close the handles beside a statement still
    running on an executor thread (BACKLOG #2049). That makes it safe on a connection a caller took
    straight from the pool. It does NOT gate a call already running when it is installed, so a
    caller that may be cancelled mid-statement gates its own connection before its first statement,
    as :func:`ss_hold_row_lock` does. A ``cur`` of ``None`` means no statement ran, so no transaction
    is open: the connection is discarded, the cheap safe answer on a path that already failed."""
    install_call_gate(conn)
    if cur is None:
        await _ss_discard(ss_store, conn, cur)
        return
    try:
        await cur.execute("ROLLBACK TRAN")
        await cur.close()
    except BaseException:
        await _ss_discard(ss_store, conn, cur)
        raise
    await ss_store._pool.release(conn)


async def _ss_discard(ss_store: Any, conn: Any, cur: Any) -> None:
    """Throw a held connection away rather than roll it back and recycle it (BACKLOG #4915).

    Closing the connection ends the session, which rolls its transaction back server-side and frees
    the lock. On a gated connection the cursor and the connection go to the call gate, cursor first,
    and close once no pyodbc call is running on them, so a statement a cancellation left on an
    executor thread never has its handles freed under it, no cursor outlives its connection, and
    nothing here waits on the close, so a cancellation arriving now is never swallowed.

    Both callers install the gate before they get here, so a connection reaching this ungated is
    either a stand-in with no bound ``_execute`` or a real aioodbc one ``install_call_gate`` could not
    wrap, which it logged at ERROR. That one is closed through ``close_one_shot`` instead, which
    does wait for its close and does not serialize it against a running statement. A failing path
    pays one reconnect."""
    try:
        if not abandon_one_shot(conn, cur):
            await close_one_shot(conn, cur)
    finally:
        # A connection whose handle is gone reads closed, and the pool drops it instead of re-lending.
        await ss_store._pool.release(conn)


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


def assert_skip_named(res: Any, lane: str, *, abort_ok: bool, stage: str) -> None:
    """BACKLOG #1270: a lane EMPTY behind a held head must NAME its route, never read as "no work".

    The completed claim names the lane in ``head_skipped``. On SQL Server alone the whole attempt may
    instead abort on 1222 (``lock_timeout``), which names the route; ``abort_ok`` admits a HEAD-phase
    abort, and only that. A FINALIZE-phase abort always comes after the fetch, so the lane must still
    be named (BACKLOG #4915). Either way a silent EMPTY fails here.

    WHICH LANES A HEAD-PHASE ABORT MAY NAME DEPENDS ON ``stage`` (BACKLOG #4915). At INGRESS and
    ROUTED the abort comes before the fetch, reads no row, and must name none: a ``{lane}`` there is
    the request list echoed back, the first-fix defect of BACKLOG #1270. Only an OUTBOUND claim stays
    in the HEAD phase past its fetch, through the ``delivered_keys`` probe, so only there may the skip
    it read ride out, and the lane is admitted beside nothing."""
    timeout = res.lock_timeout
    if abort_ok and timeout is not None and timeout.phase is ClaimAbortPhase.HEAD:
        legal: set[frozenset[str]] = {frozenset()}
        if stage == Stage.OUTBOUND.value:
            legal.add(frozenset({lane}))
        assert res.head_skipped in legal, (
            f"a HEAD-phase 1222 at stage {stage!r} named {res.head_skipped!r}; it may name"
            f" only {sorted(map(sorted, legal))!r}"
        )
        return
    assert res.head_skipped == frozenset({lane}), (
        f"the locked head's lane came back EMPTY without being named: {res.head_skipped!r}"
    )
