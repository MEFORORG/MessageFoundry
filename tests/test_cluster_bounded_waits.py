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
from collections.abc import Awaitable, Iterator

import pytest

from messagefoundry.pipeline.cluster import (
    DbCoordinator,
    StepdownLockTimeout,
    StepdownReleaseUnconfirmed,
    paused_read_budget_seconds,
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
    """asyncpg 0.31.0's pool, reduced to the behaviour the bounds depend on.

    ``await acquire(timeout=t)`` lends a connection and records ``t``. ``release(con, timeout=r)``
    models the shielded release: when a statement on ``con`` was cancelled in flight, it waits ``r``
    for the server to acknowledge the cancel, then raises ``TimeoutError`` (asyncpg terminates the
    connection and re-raises). ``r=None`` waits for ever. The pool-level ``execute``/``fetchrow``
    borrow and release with no timeout, as asyncpg's do."""

    def __init__(self, server: _Server) -> None:
        self._server = server
        self.acquire_timeouts: list[float | None] = []
        self.release_timeouts: list[float | None] = []
        # The connection dies under the cancel: asyncpg's reset then raises at once, and re-raises
        # that error over the CancelledError the borrower was unwinding with.
        self.release_fails = False
        # A busy pool: the borrow waits this long, or fails at its own timeout if that is shorter.
        self.borrow_delay = 0.0

    async def acquire(self, *, timeout: float | None = None) -> _Conn:
        self.acquire_timeouts.append(timeout)
        if self.borrow_delay:
            if timeout is not None and self.borrow_delay > timeout:
                await asyncio.sleep(timeout)
                raise TimeoutError
            await asyncio.sleep(self.borrow_delay)
        return _Conn(self._server)

    async def release(self, con: _Conn, *, timeout: float | None = None) -> None:
        self.release_timeouts.append(timeout)
        if con.in_flight:  # a statement on it was cancelled before it returned
            con.in_flight = False
            if self.release_fails:
                raise ConnectionError("connection was closed in the middle of operation")
            await asyncio.wait_for(asyncio.Event().wait(), timeout)

    async def execute(self, sql: str, *args: object) -> str:
        con = await self.acquire()
        try:
            return await con.execute(sql, *args)
        finally:
            await self.release(con)

    async def fetchrow(self, sql: str, *args: object) -> object:
        con = await self.acquire()
        try:
            return await con.fetchrow(sql, *args)
        finally:
            await self.release(con)


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


def _ss(server: _Server, node: str = "A", fence: float = _FENCE) -> SqlServerCoordinator:
    return SqlServerCoordinator(
        _SqlStore(server),
        node,
        heartbeat_seconds=10.0,
        leader_lease_ttl_seconds=_TTL,
        leader_fence_timeout_seconds=fence,
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
    pool within the release's timeout, which for a statement other than a lease one is the fence.

    MUTATION ARM, measured: send the statement through the pool's own ``execute`` (as before #2523)
    and the task is still running after stop() returns, because the release waits for ever."""
    # A fence long enough that stop()'s cancel lands well inside it on a loaded runner. If the
    # coordinator's own deadline fired first, the loop would move on to a claim before stop() ran.
    fence = 1.0
    server.hang.add(_HEARTBEAT_SQL)
    a, pool = _pg(server, fence=fence)
    await a.start()
    await asyncio.wait_for(server.hung.wait(), _GUARD)
    heartbeat = a._heartbeat_task
    assert heartbeat is not None

    elapsed, _ = await _timed(a.stop())

    assert elapsed < _STOP_BOUND + _SLACK
    # stop() did not wait for it (its own bound is shorter), but the task finishes within the
    # release's timeout.
    await asyncio.wait({heartbeat}, timeout=fence + _SLACK)
    assert heartbeat.done(), "the cancelled heartbeat is still waiting on its connection's release"
    # And it finished CANCELLED. The stand-in's release raises TimeoutError over the cancel, as
    # asyncpg's does; without _call_within restoring the cancel, the loop logs that as a failed
    # heartbeat and goes on to send a claim after stop() had cancelled it.
    assert heartbeat.cancelled(), "the cancel was swallowed by the release's TimeoutError"
    assert server.row.owner is None, "the cancelled loop went on to claim the lease"
    assert fence in pool.release_timeouts
    assert None not in pool.acquire_timeouts, "a statement borrowed with no timeout"
    assert None not in pool.release_timeouts, "a statement released with no timeout"


async def test_a_cancel_survives_a_release_that_raises_over_it(server: _Server) -> None:
    """The bound has a side effect, and this pins its repair. asyncpg's release re-raises its own
    error over the cancel the borrower was unwinding with, and the maintenance loop catches
    ``Exception``. Here the connection dies under the cancel, so the release raises at once.

    The fence is set long on purpose, so the coordinator's own deadline cannot fire first and turn
    the hung heartbeat into an ordinary timeout before stop() cancels it.

    MUTATION ARM, measured: drop the restore in ``_call_within`` and the loop logs a failed heartbeat,
    then sends a claim and takes the lease after stop() had cancelled it."""
    server.hang.add(_HEARTBEAT_SQL)
    a, pool = _pg(server, fence=_GUARD)
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


# --- the lease statements -----------------------------------------------------------------------


async def test_a_busy_pool_does_not_fail_the_renew(server: _Server) -> None:
    """Review finding on the first cut of #2523: the renew clamp also bounded the wait for a pool
    connection. The coordinator shares the store's pool, so a leader whose pool was merely busy
    failed every renew and self-fenced under load. The borrow now waits up to the fence, apart from
    the clamp, which still bounds the statement.

    MUTATION ARM, measured: make the claim's borrow share the statement's deadline again and this
    renew raises TimeoutError."""
    a, pool = _pg(server, renew=0.05, fence=_GUARD)
    pool.borrow_delay = 0.3  # longer than the clamp, well inside the fence

    await asyncio.wait_for(a._maintain_leadership(), _GUARD)

    assert a.is_leader() is True
    assert pool.acquire_timeouts[-1] == _GUARD and pool.release_timeouts[-1] == 0.05


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
    assert outcome.drained is True
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


# --- the paused tick's owner read (BACKLOG #2540) ----------------------------------------------

# Longer than the other tests' fence, so the margin between the read's budget (three quarters of
# this) and the lock wait is wide enough for a loaded runner.
_PAUSED_FENCE = 3.0


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_stalled_paused_read_still_lets_a_retried_stepdown_in(
    backend: str, server: _Server
) -> None:
    """The case the item names. A stepdown's write did not return, so the node is paused and owes
    the write. Its next tick sends the pause's owner read under the leadership lock, and the store
    stalls. The operator retries the stepdown, which waits for that lock only up to the fence.

    The stall outlasts the fence on both backends: the Postgres renew clamp is set longer than the
    fence, and the SQL Server stand-in has no statement timeout, as ``command_timeout = 0`` has none
    and the shipped 30 s exceeds the 20 s fence. So only the read's own bound can let the retry in.

    MUTATION ARMS, measured: on Postgres send the read at the renew clamp, and on SQL Server drop
    its ``asyncio.timeout``; each retry then answers StepdownLockTimeout, the 503."""
    if backend == "postgres":
        coord: DbCoordinator | SqlServerCoordinator = _pg(
            server, renew=_GUARD, fence=_PAUSED_FENCE
        )[0]
    else:
        coord = _ss(server, fence=_PAUSED_FENCE)
    await coord._maintain_leadership()
    assert coord.is_leader() is True

    server.fail.add(_RELEASE_SQL)
    with pytest.raises(StepdownReleaseUnconfirmed):
        await coord.step_down_leadership(sibling_acquire_delay_seconds=0.0)
    server.fail.clear()
    assert coord._lease_release_owed is True and coord._no_claim_until > 0.0

    server.hang.add(_OWNER_SQL)
    tick = asyncio.create_task(coord._maintain_leadership())
    await asyncio.wait_for(server.hung.wait(), _GUARD)

    elapsed, outcome = await _timed(coord.step_down_leadership(sibling_acquire_delay_seconds=0.0))

    assert elapsed < _PAUSED_FENCE, f"{backend}: the retry waited {elapsed:.2f}s for the lock"
    assert outcome.lease_released is True and coord._lease_release_owed is False, backend
    with pytest.raises(TimeoutError):
        await tick  # the stalled read failed at its bound; the loop logs it and the pause holds
    assert coord.is_leader() is False


def test_the_paused_read_budget_and_how_each_backend_spends_it() -> None:
    # The whole-call budget: three quarters of the fence, so always under it.
    assert paused_read_budget_seconds(20.0) == 15.0
    for fence in (0.5, 5.0, 20.0, 120.0):
        assert paused_read_budget_seconds(fence) < fence
    server = _Server()
    # Postgres at the shipped settings: the 4.5 s clamp is already the smaller term, so the read
    # keeps it rather than half of it. Twice 4.5 is still under the 15 s budget.
    assert _pg(server, fence=20.0, renew=4.5)[0]._paused_read_timeout == 4.5
    # A clamp longer than half the budget is cut to half, because the call costs twice its timeout.
    assert _pg(server, fence=20.0, renew=9.0)[0]._paused_read_timeout == 7.5
    # SQL Server spends the whole budget; the store's own command_timeout ends the read first when
    # it is shorter, which keeps the client-side cancel for the case it is needed.
    assert _ss(server, fence=20.0)._paused_read_budget == 15.0
