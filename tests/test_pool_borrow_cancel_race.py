# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5686 remainder: a pooled borrow abandoned by its caller is returned to the pool exactly
once, whatever loop turn the cancel and the pool's hand-over land in.

Driver-free and deterministic: a fake pool hands each connection over through a plain future and
marks it in use at that instant (``checked_out`` is the ground truth for a stranded connection), and
every test drives the loop turn by turn with ``asyncio.sleep(0)``. No timed sleep decides an outcome.
Synthetic connection names only.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest

from messagefoundry.store import base as base_module
from messagefoundry.store.base import acquire_pooled, warm_pool_connections


class _HandOffPool:
    """``acquire()`` parks on a hand-off future. ``deaf=True`` models a driver whose acquire swallows
    a cancel and keeps waiting, so a borrow stays stuck until the test hands a connection over."""

    def __init__(self, *, deaf: bool = False) -> None:
        self.deaf = deaf
        self.handoffs: list[asyncio.Future[str]] = []
        self.checked_out: list[str] = []
        self.released: list[str] = []
        self.issued: list[str] = []

    def acquire(self) -> object:
        fut: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        self.handoffs.append(fut)
        if not self.deaf:
            return fut

        async def _deaf() -> str:
            while True:
                try:
                    return await asyncio.shield(fut)
                except asyncio.CancelledError:
                    continue  # a driver that ignores the cancel

        return _deaf()

    def hand_over(self, index: int = 0) -> None:
        fut = self.handoffs[index]
        if fut.done():
            return  # the borrow was cancelled first: a correct pool hands nothing over
        conn = f"conn-{len(self.issued) + 1}"
        self.issued.append(conn)
        self.checked_out.append(conn)  # in use atomically with the hand-off
        fut.set_result(conn)

    async def release(self, conn: str) -> None:
        self.released.append(conn)
        self.checked_out.remove(conn)

    async def unstick(self) -> None:
        """Resolve every hand-off still pending, so no deaf borrow outlives a failed test and hangs
        the loop's teardown."""
        for index, fut in enumerate(self.handoffs):
            if not fut.done():
                self.hand_over(index)
        await _turns()


async def _turns(n: int = 50) -> None:
    for _ in range(n):
        await asyncio.sleep(0)


async def _until(cond: Callable[[], bool], n: int = 200) -> bool:
    for _ in range(n):
        if cond():
            return True
        await asyncio.sleep(0)
    return cond()


async def test_warm_hand_over_queued_behind_the_borrow_cancel_strands_nothing() -> None:
    # The warm-up's cancel reaches the acquire task in the next turn; the pool's hand-over is queued
    # to run in that same turn, AFTER the acquire task has given up on its borrow. A borrow cancel
    # put off by one turn then runs before the borrow's wake-up and throws the cancel into the
    # resolved hand-off, so nobody holds the connection. Either the cancel reaches the pool before
    # the hand-over, or whatever the pool hands over is returned.
    pool = _HandOffPool()
    task = asyncio.create_task(warm_pool_connections(pool, target=1, timeout=30.0, backend="stub"))
    await _turns()
    assert len(pool.handoffs) == 1  # the borrow is parked on the hand-off

    task.cancel()
    asyncio.get_running_loop().call_soon(pool.hand_over)
    with pytest.raises(asyncio.CancelledError):
        await task
    assert pool.checked_out == [], "a connection the pool handed over was stranded"
    assert pool.released == pool.issued


async def test_acquire_pooled_cancelled_in_the_turn_the_borrow_resolves_strands_nothing() -> None:
    # The caller is cancelled in the same turn the pool hands the connection over. acquire_pooled
    # must not cancel a borrow whose hand-off has already resolved: the cancel would be thrown in
    # place of the connection, and the salvage would then find nothing to return.
    pool = _HandOffPool()
    caller = asyncio.create_task(acquire_pooled(pool, timeout=30.0, backend="stub"))
    await _turns()
    assert len(pool.handoffs) == 1

    caller.cancel()
    pool.hand_over()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert await _until(lambda: not pool.checked_out), "the caller's borrow was stranded"
    assert pool.released == ["conn-1"]


async def test_acquire_pooled_cancel_still_stops_a_parked_borrow() -> None:
    # The cancel is deferred only while a hand-over is in flight: a borrow still parked on the pool
    # is cancelled at once, so a wedged pool does not keep one detached borrow per abandoned caller.
    pool = _HandOffPool()
    caller = asyncio.create_task(acquire_pooled(pool, timeout=30.0, backend="stub"))
    await _turns()
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert await _until(lambda: pool.handoffs[0].cancelled())
    assert pool.checked_out == [] and pool.released == []


async def test_warm_landed_borrow_is_released_while_a_sibling_borrow_is_stuck() -> None:
    # Two abandoned borrows: one lands, the other stays stuck on a pool that ignores the cancel. The
    # landed one must be returned at once, not after the stuck sibling or the cleanup bound, where it
    # would get no release budget left.
    pool = _HandOffPool(deaf=True)
    try:
        task = asyncio.create_task(
            warm_pool_connections(pool, target=2, timeout=30.0, backend="stub")
        )
        await _turns()
        assert len(pool.handoffs) == 2

        task.cancel()
        await _turns()  # the acquire tasks give up; both borrows keep waiting (deaf pool)
        assert not task.done()
        pool.hand_over(0)
        assert await _until(lambda: pool.released == ["conn-1"]), (
            "the landed borrow's release waited on its stuck sibling"
        )
        assert not task.done()  # the stuck sibling is still being waited for, inside the bound

        pool.hand_over(1)  # the sibling lands inside the bound and the cleanup returns it too
        with pytest.raises(asyncio.CancelledError):
            await task
        assert pool.checked_out == []
        assert sorted(pool.released) == ["conn-1", "conn-2"]
    finally:
        await pool.unstick()


async def test_warm_borrow_landing_after_the_bound_is_released_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A zero bound ends the cleanup with the borrow still pending; the salvage owns it from then on.
    # It is released once, not by both the cleanup and the salvage.
    monkeypatch.setattr("messagefoundry.store.base._CLEANUP_TIMEOUT_SECONDS", 0.0)
    pool = _HandOffPool(deaf=True)
    try:
        parked_before = set(base_module._LATE_RELEASES)
        task = asyncio.create_task(
            warm_pool_connections(pool, target=1, timeout=30.0, backend="stub")
        )
        await _turns()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert pool.checked_out == [] and pool.released == []

        pool.hand_over(0)
        assert await _until(lambda: pool.released == ["conn-1"])
        await _turns()
        assert pool.released == ["conn-1"] and pool.checked_out == []
        assert base_module._LATE_RELEASES - parked_before == set()
    finally:
        await pool.unstick()


async def test_the_task_exposes_the_waiter_the_borrow_cancel_reads() -> None:
    # _cancel_borrow reads Task._fut_waiter to tell a borrow parked on the pool from one whose
    # hand-over is in flight. Without the attribute it stops cancelling borrows at all, so a Python
    # that drops it fails here rather than changing the behaviour unseen.
    fut: asyncio.Future[str] = asyncio.get_running_loop().create_future()

    async def _parked() -> str:
        return await fut

    task = asyncio.ensure_future(_parked())
    await asyncio.sleep(0)
    assert getattr(task, "_fut_waiter", None) is fut
    fut.set_result("synthetic")
    assert await task == "synthetic"
