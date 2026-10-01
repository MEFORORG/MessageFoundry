# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The cluster coordinators' waits on a hung pool are bounded (BACKLOG #2523).

``DbCoordinator`` used to send its statements through the asyncpg pool's own ``execute`` /
``fetchrow`` / ``fetch``. Those borrow a connection with no acquire timeout, and asyncpg 0.31.0's pool
release, which is shielded from a cancel, waits for a cancelled statement's server acknowledgement for
as long as that timeout, so for ever. A partitioned server never acknowledges. That wait held a
``stop()`` behind its cancelled heartbeat task, and a stepdown behind a tick holding the leadership
lock or behind its own release write.

The stand-in here models asyncpg in the one way the bound depends on. Its pool-level statement methods
borrow with ``timeout=None`` exactly as asyncpg's do, so a coordinator that calls them reproduces the
defect, and the same statement sent through ``acquire(timeout=...)`` does not. That pairing is what
lets each test below go red when its bound is removed. No live server is used. The hosted failover
suites run a healthy server, and none of them partitions one.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Iterator
from contextlib import asynccontextmanager

import pytest

from messagefoundry.pipeline.cluster import (
    DbCoordinator,
    StepdownLockTimeout,
    StepdownReleaseUnconfirmed,
)
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator

_TTL = 30.0
# Small real-time bounds, so a bounded wait finishes in well under a second. The guard is far above
# all of them: it turns an unbounded wait into a clean failure instead of a hung test run.
_RENEW = 0.05
_STOP_BOUND = 0.1
_FENCE = 0.6
_GUARD = 5.0
_SLACK = 1.0  # what a loaded runner may add to a bound before a test calls it unbounded

_CLAIM_SQL = "INSERT INTO leader_lease"
_RELEASE_SQL = "UPDATE leader_lease"
_HEARTBEAT_SQL = "UPDATE nodes SET last_seen"
_TOMBSTONE_SQL = "UPDATE nodes SET status"
_OWNER_SQL = "SELECT owner FROM leader_lease"


class _Row:
    """The shared ``leader_lease`` row. The DB clock never moves, so a released row is takeable at
    once by a delay-0 sibling and these tests measure only wall-clock bounds."""

    def __init__(self) -> None:
        self.owner: str | None = None
        self.live = False

    def claim(self, node: str) -> dict[str, object] | None:
        if self.owner in (None, node) or not self.live:
            self.owner, self.live = node, True
            return {"owner": node, "leader_epoch": 1}
        return None

    def release(self, node: str) -> int:
        if self.owner == node:
            self.live = False
            return 1
        return 0


class _Server:
    """What both stand-ins share: the row, and which statements hang in flight or fail at once."""

    def __init__(self) -> None:
        self.row = _Row()
        self.hang: set[str] = set()
        self.fail: set[str] = set()
        self.hung = asyncio.Event()  # set once a statement is hanging, so a test can act then
        self.answer = asyncio.Event()  # a partitioned server answers only if a test sets this

    async def run(self, sql: str, node: str) -> object:
        if any(fragment in sql for fragment in self.hang):
            self.hung.set()
            await self.answer.wait()
        if any(fragment in sql for fragment in self.fail):
            raise ConnectionError("connection was closed in the middle of operation")
        if _CLAIM_SQL in sql or "MERGE leader_lease" in sql:
            return self.row.claim(node)
        if _RELEASE_SQL in sql:
            return self.row.release(node)
        if _OWNER_SQL in sql:
            return None if self.row.owner is None else {"owner": self.row.owner}
        return 1  # the nodes-table writes, which carry no lease semantics


class _Conn:
    def __init__(self, server: _Server) -> None:
        self._server = server
        self.in_flight = False

    async def _run(self, sql: str, node: str) -> object:
        self.in_flight = True
        result = await self._server.run(sql, node)
        self.in_flight = False
        return result

    async def execute(self, sql: str, *args: object) -> str:
        # Lease writes carry (lease_key, owner); the nodes writes carry the node id last.
        node = str(args[1] if "leader_lease" in sql else args[-1])
        return f"UPDATE {await self._run(sql, node)}"

    async def fetchrow(self, sql: str, *args: object) -> object:
        return await self._run(sql, str(args[1]) if len(args) > 1 else "")


class _AsyncpgPool:
    """asyncpg 0.31.0's pool, reduced to the behaviour the bound depends on.

    ``acquire(timeout=t)`` lends a connection. When the borrower is cancelled while a statement is in
    flight, the release waits ``t`` for the server to acknowledge the cancel, then raises
    ``TimeoutError`` (asyncpg terminates the connection and re-raises). ``t=None`` waits for ever.
    The pool-level ``execute``/``fetchrow`` borrow with ``timeout=None``, as asyncpg's do."""

    def __init__(self, server: _Server) -> None:
        self._server = server
        self.acquire_timeouts: list[float | None] = []
        # The connection dies under the cancel: asyncpg's reset then raises at once, and re-raises
        # that error over the CancelledError the borrower was unwinding with.
        self.release_fails = False

    @asynccontextmanager
    async def acquire(self, *, timeout: float | None = None) -> AsyncIterator[_Conn]:
        self.acquire_timeouts.append(timeout)
        con = _Conn(self._server)
        try:
            yield con
        except asyncio.CancelledError:
            if con.in_flight:
                if self.release_fails:
                    raise ConnectionError(
                        "connection was closed in the middle of operation"
                    ) from None
                await asyncio.wait_for(asyncio.Event().wait(), timeout)
            raise

    async def execute(self, sql: str, *args: object) -> str:
        async with self.acquire() as con:
            return await con.execute(sql, *args)

    async def fetchrow(self, sql: str, *args: object) -> object:
        async with self.acquire() as con:
            return await con.fetchrow(sql, *args)


class _SqlStore:
    """The SQL Server store's ``_fetchone``/``_execute``. Its cancel unwinds at once: the real store
    quarantines the cancelled connection without waiting on a running statement."""

    _settings = None

    def __init__(self, server: _Server) -> None:
        self._server = server

    async def _fetchone(self, sql: str, params: tuple[object, ...]) -> object:
        return await self._server.run(sql, str(params[1]) if len(params) > 1 else "")

    async def _execute(self, sql: str, params: tuple[object, ...]) -> int:
        node = str(params[1] if "leader_lease" in sql else params[-1])
        result = await self._server.run(sql, node)
        assert isinstance(result, int)
        return result


@pytest.fixture
def server() -> Iterator[_Server]:
    """The shared stand-in server, which answers every hung statement at teardown.

    Without that, a test whose bound was removed leaves a task waiting in an unbounded release, and
    the event loop's own shutdown then waits on it for ever instead of reporting the failure."""
    instance = _Server()
    yield instance
    instance.answer.set()


def _pg(server: _Server, node: str = "A", **kw: float) -> tuple[DbCoordinator, _AsyncpgPool]:
    pool = _AsyncpgPool(server)
    coord = DbCoordinator(
        pool,
        node,
        heartbeat_seconds=kw.get("heartbeat", 10.0),
        leader_lease_ttl_seconds=_TTL,
        leader_fence_timeout_seconds=kw.get("fence", _FENCE),
        lease_renew_timeout_seconds=kw.get("renew", _RENEW),
        stop_write_timeout_seconds=_STOP_BOUND,
        run_schema_ddl=False,
    )
    return coord, pool


def _ss(server: _Server, node: str = "A") -> SqlServerCoordinator:
    return SqlServerCoordinator(
        _SqlStore(server),
        node,
        heartbeat_seconds=10.0,
        leader_lease_ttl_seconds=_TTL,
        leader_fence_timeout_seconds=_FENCE,
        stop_write_timeout_seconds=_STOP_BOUND,
        run_schema_ddl=False,
    )


async def _timed[T](aw: Awaitable[T]) -> tuple[float, T]:
    """Await ``aw`` under the guard, and return how long it took.

    Not ``asyncio.wait_for``: on expiry that cancels the call and then WAITS for the cancel to
    finish, which is exactly the wait an unbounded release never ends. ``asyncio.wait`` returns at
    the guard and leaves the call behind, so a missing bound fails the test instead of hanging it."""
    started = time.monotonic()
    task = asyncio.ensure_future(aw)
    await asyncio.wait({task}, timeout=_GUARD)
    if not task.done():
        task.cancel()
        pytest.fail(f"the call was still waiting after the {_GUARD}s guard: it is unbounded")
    return time.monotonic() - started, task.result()


# --- stop() -------------------------------------------------------------------------------------


async def test_a_heartbeat_cancelled_in_flight_unwinds_within_the_borrow_bound(
    server: _Server,
) -> None:
    """stop() cancels the maintenance task while its heartbeat UPDATE is hung on the server. The
    task must FINISH, not merely be left behind by stop()'s own bound: its connection goes back to the
    pool within the renew clamp.

    MUTATION ARM, measured: send the statement through the pool's own ``execute`` (as before #2523)
    and the task is still running when stop() returns, because the release waits for ever."""
    # A clamp long enough that stop()'s cancel lands well inside it on a loaded runner. If the
    # coordinator's own deadline fired first, the loop would move on to a claim before stop() ran.
    renew = 0.3
    server.hang.add(_HEARTBEAT_SQL)
    a, pool = _pg(server, renew=renew)
    await a.start()
    await asyncio.wait_for(server.hung.wait(), _GUARD)
    heartbeat = a._heartbeat_task
    assert heartbeat is not None

    elapsed, _ = await _timed(a.stop())

    assert elapsed < _STOP_BOUND + _SLACK
    # stop() did not wait for it (its own bound is shorter), but the task finishes within the
    # clamp, because the release it is waiting in was borrowed with that timeout.
    await asyncio.wait({heartbeat}, timeout=2 * renew + _SLACK)
    assert heartbeat.done(), "the cancelled heartbeat is still waiting on its connection's release"
    # And it finished CANCELLED. The stand-in's release raises TimeoutError over the cancel, as
    # asyncpg's does; without _call_within restoring the cancel, the loop logs that as a failed
    # heartbeat and goes on to send a claim after stop() had cancelled it.
    assert heartbeat.cancelled(), "the cancel was swallowed by the release's TimeoutError"
    assert server.row.owner is None, "the cancelled loop went on to claim the lease"
    assert renew in pool.acquire_timeouts
    assert None not in pool.acquire_timeouts, "a statement borrowed with no acquire timeout"


async def test_a_cancel_survives_a_release_that_raises_over_it(server: _Server) -> None:
    """The bound has a side effect, and this pins its repair. asyncpg's release re-raises its own
    error over the cancel the borrower was unwinding with, and the maintenance loop catches
    ``Exception``. Here the connection dies under the cancel, so the release raises at once.

    The renew clamp is set long on purpose. With a short one the coordinator's own deadline fires
    inside the release and cancels it, which hides the swallow, so the test above cannot see it.

    MUTATION ARM, measured: drop the restore in ``_call_within`` and the loop logs a failed heartbeat,
    then sends a claim and takes the lease after stop() had cancelled it."""
    server.hang.add(_HEARTBEAT_SQL)
    a, pool = _pg(server, renew=_GUARD)
    pool.release_fails = True
    await a.start()
    await asyncio.wait_for(server.hung.wait(), _GUARD)
    heartbeat = a._heartbeat_task
    assert heartbeat is not None

    await _timed(a.stop())

    assert heartbeat.done() and heartbeat.cancelled(), "the cancel was swallowed"
    assert server.row.owner is None, "the cancelled loop went on to claim the lease"


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_stop_is_bounded_when_a_background_task_never_unwinds(
    backend: str, server: _Server
) -> None:
    """The backstop under the borrow bound: a background task that does not finish when cancelled,
    whatever the reason, cannot hold stop() past its own bound.

    MUTATION ARM, measured: put the plain ``asyncio.gather`` back in stop() and this trips the guard."""
    coord: DbCoordinator | SqlServerCoordinator = (
        _pg(server)[0] if backend == "postgres" else _ss(server)
    )
    unwound = asyncio.Event()

    async def _never_unwinds() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await unwound.wait()  # a driver release that never returns
            raise

    stuck = asyncio.create_task(_never_unwinds())
    await asyncio.sleep(0)
    coord._heartbeat_task = stuck

    elapsed, _ = await _timed(coord.stop())

    assert elapsed < _STOP_BOUND + _SLACK, f"{backend}: stop() took {elapsed:.2f}s"
    assert not stuck.done()  # control: the task really was still unwinding
    assert server.row.owner is None  # nothing to release; the writes still ran and matched nothing
    unwound.set()
    with pytest.raises(asyncio.CancelledError):
        await stuck


# --- a stepdown ---------------------------------------------------------------------------------


async def test_a_stepdown_whose_release_write_hangs_returns_within_the_bound(
    server: _Server,
) -> None:
    """The stepdown's own write used to have no bound at all: the request deadline is an
    asyncio.timeout around the handler, which cannot cut asyncpg's shielded release short.

    MUTATION ARM, measured: send the stepdown's write through the pool's own ``execute`` and this
    trips the guard instead of refusing with StepdownReleaseUnconfirmed."""
    a, _pool = _pg(server)
    await a._maintain_leadership()
    assert a.is_leader() is True
    server.hang.add(_RELEASE_SQL)

    started = time.monotonic()
    with pytest.raises(StepdownReleaseUnconfirmed):
        await _timed(a.step_down_leadership(sibling_acquire_delay_seconds=0.0))
    elapsed = time.monotonic() - started

    assert elapsed < 2 * _RENEW + _SLACK
    assert a.is_leader() is False and a._lease_release_owed is True  # a retry re-sends it


async def test_a_stepdown_queued_behind_a_hung_claim_gets_the_lock(server: _Server) -> None:
    """A tick holds the leadership lock across its claim. With the claim hung in flight, the tick
    used to hold the lock for ever and every stepdown answered 503 lock-timeout.

    MUTATION ARM, measured: send the claim through the pool's own ``fetchrow`` and this raises
    StepdownLockTimeout at the fence timeout."""
    a, _pool = _pg(server)
    await a._maintain_leadership()  # leads
    server.hang.add(_CLAIM_SQL)
    tick = asyncio.create_task(a._maintain_leadership())  # the renew hangs, holding the lock
    await asyncio.wait_for(server.hung.wait(), _GUARD)
    server.hang.clear()

    elapsed, outcome = await _timed(a.step_down_leadership(sibling_acquire_delay_seconds=0.0))

    assert elapsed < _FENCE, f"the stepdown waited {elapsed:.2f}s for the lock"
    assert getattr(outcome, "drained", False) is True
    with pytest.raises(TimeoutError):
        await tick  # the hung renew failed at its bound; the loop would log it and retry


async def test_a_lock_timeout_is_still_the_answer_when_the_tick_outlasts_the_fence(
    server: _Server,
) -> None:
    """CONTROL for the test above: the bound is what lets the stepdown in, not some property of the
    stand-in. A renew clamp longer than the fence keeps the lock past it, and the stepdown refuses."""
    a, _pool = _pg(server, renew=_GUARD)
    await a._maintain_leadership()
    server.hang.add(_CLAIM_SQL)
    tick = asyncio.create_task(a._maintain_leadership())
    await asyncio.wait_for(server.hung.wait(), _GUARD)

    with pytest.raises(StepdownLockTimeout):
        await a.step_down_leadership(sibling_acquire_delay_seconds=0.0)
    server.answer.set()  # the server answers at last, and the tick renews
    await _timed(tick)
    assert a.is_leader() is True
