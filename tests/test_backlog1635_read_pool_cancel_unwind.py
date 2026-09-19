# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1635 - a cancelled pooled read must not return an open transaction to the read pool.

``MessageStore._read`` borrows a connection from a fixed ``asyncio.Queue`` and wraps the block in one
deferred read transaction. Its rollback arm used to start AFTER the ``BEGIN``, so the ``BEGIN``'s own
await was outside it. aiosqlite runs that statement on a worker thread, so it lands whether or not
the awaiting task survives: a cancellation delivered there unwound straight to the ``finally`` that
puts the connection back, and the connection re-entered the pool INSIDE an open transaction.

Nothing would have healed it. Every later borrower's ``BEGIN`` raises "cannot start a transaction
within a transaction", and that failing ``BEGIN`` sat in the same unguarded position, so the
connection went back dirty again. With the shipped pool of four, one such cancellation would
permanently fail one read in four on a deploying site - which is why the assertions below run TWO
full cycles of the pool rather than one. A single clean read afterwards is equally consistent with a
poisoned sibling nobody has borrowed yet.

The second hazard is the rollback itself. ``await conn.execute("ROLLBACK")`` is an ordinary await, so
a SECOND cancellation landing on it kills the rollback and returns the very connection the first
cancellation's unwind was cleaning. The fix routes both roles through the shared shielded, bounded
``_unwind_txn``; ``test_pooled_read_survives_a_second_cancellation`` is what distinguishes the two.

The ORDINARY-EXCEPTION control arm is not padding, and it is not a weaker copy of the cancel arm: at
the ``begin`` point it fails on the unfixed code for exactly the same reason, because the gap was the
handler's POSITION, not its exception type. Running both through the same assertions shows the two
paths agree.

Every store here is FILE-backed. ``_open_read_pool`` returns early for ``:memory:``, leaving
``_read`` on the pre-pool path with no ``BEGIN`` at all, so a ``:memory:`` fixture would pass whether
or not any of this holds.

Modelled on ``tests/test_backlog1548_writer_txn_cancel_unwind.py``, which does the same job for the
single writer connection.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.store import _READ_POOL_SIZE, MessageStore

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"
CH = "IB_TEST_ADT"
# Bound on every handshake with the trapped reader. Generous (these are sub-millisecond in practice)
# but finite, so a wedged case fails as a timeout instead of hanging the suite.
WAIT = 5.0

# The three cancel points, named by the await the failure lands on.
BEGIN, BODY, COMMIT = "begin", "body", "commit"
CANCEL_POINTS = [BEGIN, BODY, COMMIT]
ARMS = ["cancel", "control"]


class _Boom(Exception):
    """The control arm's ordinary exception."""


class _ReadTrap:
    """Stall (or fail) a pooled read at ONE chosen await inside its snapshot transaction.

    Installed on EVERY pooled connection, because which one a read borrows depends on queue order and
    the test must not silently depend on that. It is one-shot: the first trip disarms it, so the
    recovery reads that follow run untouched.

    ``arm(point)`` selects the await:

    * ``begin``  - just after ``BEGIN`` landed: the read transaction is open, nothing read yet;
    * ``body``   - just after the block's ``SELECT`` ran: the snapshot is taken and in use;
    * ``commit`` - just BEFORE ``COMMIT``: the snapshot is still open and about to be closed.

    ``stall_rollback`` holds the unwind's ``ROLLBACK`` open for a beat, which is the window the
    cancel-twice cases need to land a SECOND cancellation inside the shielded rollback.
    """

    def __init__(self, conns: list[Any]) -> None:
        self.point: str | None = None
        self.raise_instead = False
        self.stall_rollback = 0.0
        self.reached = asyncio.Event()
        self.release = asyncio.Event()
        self.rollback_started = asyncio.Event()
        self.rollback_finished = asyncio.Event()
        for conn in conns:
            self._install(conn)

    def _install(self, conn: Any) -> None:
        real_execute = conn.execute
        real_rollback = conn.rollback

        async def execute(sql: Any, *args: Any, **kwargs: Any) -> Any:
            text = str(sql).lstrip().upper()
            if self.point == COMMIT and text.startswith("COMMIT"):
                await self._trip()  # before the COMMIT lands: the snapshot is still open
            if text.startswith("ROLLBACK"):
                # Watched here as well as on `rollback()` so the probe measures whether the
                # transaction was CLOSED, not which spelling closed it. Watching only the aiosqlite
                # method would red every arm of a store that rolls back with a statement instead -
                # a failure attributed to the leak this file is about, but caused by the route.
                return await self._rolling_back(lambda: real_execute(sql, *args, **kwargs))
            cur = await real_execute(sql, *args, **kwargs)
            # Trip AFTER the statement really ran: a cancellation delivered at this await leaves the
            # worker thread's work applied, which is the state the unwind has to clean up.
            if (self.point == BEGIN and text.startswith("BEGIN")) or (
                self.point == BODY and text.startswith("SELECT")
            ):
                await self._trip()
            return cur

        async def rollback() -> Any:
            return await self._rolling_back(real_rollback)

        conn.execute = execute
        conn.rollback = rollback

    async def _rolling_back(self, run: Callable[[], Awaitable[Any]]) -> Any:
        """Run the unwind's rollback, optionally stalled, and record that it FINISHED.

        ``rollback_finished`` is set only after the call returns - never from a ``finally``. A
        cancellation that kills the rollback must leave it clear, or the cancel-twice cases would
        pass against exactly the unshielded rollback they exist to reject."""
        self.rollback_started.set()
        if self.stall_rollback:
            await asyncio.sleep(self.stall_rollback)
        result = await run()
        self.rollback_finished.set()
        return result

    def arm(self, point: str, *, raise_instead: bool = False) -> None:
        self.point = point
        self.raise_instead = raise_instead
        self.reached.clear()

    async def _trip(self) -> None:
        self.point = None  # one shot: the recovery reads must not trip it again
        self.reached.set()
        if self.raise_instead:
            raise _Boom("injected at the cancel point")
        await self.release.wait()


async def _open(tmp_path: Path, name: str) -> MessageStore:
    """A file-backed store with one message in it, so a read has something to return."""
    store = await MessageStore.open(tmp_path / f"{name}.db")
    assert store._read_pool is not None, "no pool: a :memory: store would prove nothing here"
    await store.enqueue_message(channel_id=CH, raw=RAW, deliveries=[("OB", "p")], now=0.0)
    return store


async def _assert_pool_is_clean_and_reusable(store: MessageStore) -> None:
    """The invariant itself, and the probe that detects its absence.

    Three checks, in order, because each catches something the next would mask:

    1. every connection came BACK - a borrowed connection stranded outside the queue shrinks the pool
       permanently, which is the failure mode a ``_release_dirty``-style quarantine would introduce
       here and the reason this fix heals a connection instead of dropping it;
    2. none of them is still in a transaction - the state assertion, read directly;
    3. TWO full cycles of reads all succeed - the behavioural probe. The queue is FIFO and each read
       returns its connection to the tail, so ``2 * _READ_POOL_SIZE`` consecutive reads borrow every
       connection twice. One cycle would prove only that the dirty connection was not first in line;
       two prove it is not re-dirtying itself on each pass.
    """
    pool = store._read_pool
    assert pool is not None
    assert pool.qsize() == _READ_POOL_SIZE, "a borrowed connection never came back to the pool"
    for i, conn in enumerate(store._read_conns):
        assert not conn.in_transaction, f"pooled connection {i} went back inside a transaction"
    for i in range(2 * _READ_POOL_SIZE):
        assert await store.count_messages() == 1, f"read {i} saw the wrong data"


@pytest.mark.parametrize("arm", ARMS)
@pytest.mark.parametrize("point", CANCEL_POINTS)
async def test_pooled_read_unwinds(tmp_path: Path, point: str, arm: str) -> None:
    """A failure at any of the three points closes the read transaction before the connection goes
    back, and an ordinary exception at the same await does exactly what a cancellation does."""
    store = await _open(tmp_path, f"unwind-{point}-{arm}")
    try:
        trap = _ReadTrap(store._read_conns)
        trap.arm(point, raise_instead=arm == "control")

        if arm == "cancel":
            task = asyncio.create_task(store.count_messages())
            await asyncio.wait_for(trap.reached.wait(), WAIT)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(_Boom):
                await store.count_messages()

        assert trap.rollback_finished.is_set(), "the failed read never rolled its transaction back"
        await _assert_pool_is_clean_and_reusable(store)
    finally:
        await store.close()


@pytest.mark.parametrize("point", CANCEL_POINTS)
async def test_pooled_read_survives_a_second_cancellation(tmp_path: Path, point: str) -> None:
    """A SECOND cancellation landing inside the shielded rollback corrupts nothing.

    This is the arm a bare ``await conn.execute("ROLLBACK")`` could never pass: the second cancel
    kills an unshielded rollback outright, and the connection goes back to the pool still holding the
    transaction the first cancel's unwind was closing."""
    store = await _open(tmp_path, f"twice-{point}")
    try:
        trap = _ReadTrap(store._read_conns)
        trap.stall_rollback = 0.05  # hold the ROLLBACK open long enough to cancel into it
        trap.arm(point)

        task = asyncio.create_task(store.count_messages())
        await asyncio.wait_for(trap.reached.wait(), WAIT)
        task.cancel()
        await asyncio.wait_for(trap.rollback_started.wait(), WAIT)
        task.cancel()  # lands while the unwind is parked on the shielded rollback
        with pytest.raises(asyncio.CancelledError):
            await task

        assert trap.rollback_finished.is_set(), "the second cancellation killed the rollback"
        await _assert_pool_is_clean_and_reusable(store)
    finally:
        await store.close()


async def test_a_cancellation_mid_begin_leaves_the_next_borrower_a_usable_connection(
    tmp_path: Path,
) -> None:
    """The filed defect, stated as an operator would meet it, and pinned on ONE connection.

    The parametrized cases above prove the pool as a whole is clean. This one narrows to the exact
    reported symptom: cancel a read at its ``BEGIN``, then borrow THAT SAME connection again and
    require the read to succeed. Before the fix it raised ``sqlite3.OperationalError: cannot start a
    transaction within a transaction``, and it would have kept raising it for the life of the
    process."""
    store = await _open(tmp_path, "same-connection")
    try:
        pool = store._read_pool
        assert pool is not None
        # Drain the pool to ONE connection so the borrow is not a guess about queue order.
        parked = [await pool.get() for _ in range(_READ_POOL_SIZE - 1)]
        [only] = [c for c in store._read_conns if all(c is not p for p in parked)]
        assert pool.qsize() == 1

        trap = _ReadTrap([only])
        trap.arm(BEGIN)
        task = asyncio.create_task(store.count_messages())
        await asyncio.wait_for(trap.reached.wait(), WAIT)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert pool.qsize() == 1, "the connection never came back"
        assert not only.in_transaction, "the connection went back inside a transaction"
        # The next borrower is necessarily this same connection - it is the only one in the queue.
        assert await store.count_messages() == 1
        assert await store.count_messages() == 1  # ...and it did not re-dirty itself

        for conn in parked:
            pool.put_nowait(conn)
    finally:
        await store.close()
