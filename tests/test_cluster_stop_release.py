# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1987: ``stop()`` releases a self-fenced node's lease row, under a per-write time bound.

The self-fence clears the in-memory gate on the node's own clock while the lease row stays live on the
DB clock. Before this fix ``stop()`` gated its release on that gate, so a self-fenced node that was then
stopped sent nothing and a standby waited out the whole TTL. Forcing the write was once tried and
reverted because it had no per-call bound, and a self-fenced node's pool is the one most likely to hang.

Both coordinators run here against in-memory stand-ins, so no database is needed. The stand-ins model
only the statements ``stop()`` and the claim send, plus the one piece of asyncpg behaviour the bound
depends on (see :class:`_PgAcquired`). What they cannot show is a real driver under a real partition;
no suite here does that, including the live-server ones (``test_cluster_failover_postgres.py``,
``test_cluster_failover_sqlserver.py``), which exercise a healthy server.
"""

from __future__ import annotations

import asyncio
import time
from types import TracebackType

from messagefoundry.pipeline.cluster import (
    STOP_WRITE_TIMEOUT_SECONDS,
    DbCoordinator,
    _execute_within,
)
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator

_TTL = 30.0
_FENCE = 20.0
# A realistic DB clock. The release stamps the DB clock's now (BACKLOG #1986), and a clock that
# starts at 0.0 could not tell that apart from the epoch the release used to write.
_DB_NOW = 1_700_000_000.0
# The bound the hang tests run with, and an outer guard far above it. The guard turns an unbounded
# stop() into a clean failure rather than a hang that pytest-timeout ends by killing the whole run.
_BOUND = 0.05
_HANG_GUARD = 10.0
_LEASE_SQL = "UPDATE leader_lease"
_NODES_SQL = "UPDATE nodes"


class _Clock:
    """A settable clock, used for both the DB clock and each node's monotonic clock."""

    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class _LeaseRow:
    """The one shared ``leader_lease`` row and the two mutations both backends' statements make."""

    def __init__(self, db_clock: _Clock) -> None:
        self._db_clock = db_clock
        self.row: dict[str, object] | None = None

    def claim(self, owner: object) -> dict[str, object] | None:
        now = self._db_clock()
        row = self.row
        if row is None:
            self.row = {"owner": owner, "lease_expires_at": now + _TTL, "leader_epoch": 1}
            return {"owner": owner, "leader_epoch": 1}
        if row["owner"] == owner or float(row["lease_expires_at"]) < now:  # type: ignore[arg-type]
            if row["owner"] != owner:
                row["leader_epoch"] = int(row["leader_epoch"]) + 1  # type: ignore[call-overload]
            row["owner"] = owner
            row["lease_expires_at"] = now + _TTL
            return {"owner": owner, "leader_epoch": row["leader_epoch"]}
        return None  # another node holds a live lease

    def release(self, owner: object) -> int:
        row = self.row
        if row is not None and row["owner"] == owner:
            # The DB clock's now, never later than the row's own expiry (BACKLOG #1986).
            row["lease_expires_at"] = min(float(row["lease_expires_at"]), self._db_clock())  # type: ignore[arg-type]
            return 1
        return 0

    def is_live(self) -> bool:
        row = self.row
        return row is not None and float(row["lease_expires_at"]) > self._db_clock()  # type: ignore[arg-type]


class _Writes:
    """What both stand-ins share: which statements hang or fail, and a count of those that landed.

    ``hang_on`` models the realistic self-fence case: the statement is already in flight when the
    server stops answering, so it never returns. ``fail_on`` raises at once, the way a dead pooled
    connection does."""

    def __init__(self, lease: _LeaseRow) -> None:
        self._lease = lease
        self.hang_on: str | None = None
        self.fail_on: str | None = None
        self.hung_in_flight = False
        self.lease_writes = 0
        self.node_writes = 0

    async def run(self, sql: str, owner: object) -> int:
        if self.hang_on is not None and self.hang_on in sql:
            self.hung_in_flight = True
            await asyncio.Event().wait()  # nothing ever sets it
        if self.fail_on is not None and self.fail_on in sql:
            raise ConnectionError("connection was closed in the middle of operation")
        if _LEASE_SQL in sql:
            self.lease_writes += 1
            return self._lease.release(owner)
        assert _NODES_SQL in sql, sql
        self.node_writes += 1
        return 1


class _PgAcquired:
    """``pool.acquire(timeout=...)`` as asyncpg 0.31.0 shapes it, for one write."""

    def __init__(self, pool: _PgPool, timeout: float | None) -> None:
        self._pool = pool
        self._timeout = timeout

    async def __aenter__(self) -> _PgPool:
        self._pool.acquire_timeouts.append(self._timeout)
        return self._pool

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        writes = self._pool.writes
        cancelled = exc_type is not None and issubclass(exc_type, asyncio.CancelledError)
        if cancelled and writes.hung_in_flight:
            # asyncpg: a statement cancelled in flight leaves the protocol cancelling, and the pool's
            # shielded release waits for the server to acknowledge that cancel for as long as the
            # ACQUIRE's timeout, then terminates the connection and re-raises. None waits forever. A
            # partitioned server never acknowledges, so this wait is the whole question.
            writes.hung_in_flight = False
            await asyncio.wait_for(asyncio.Event().wait(), self._timeout)


class _PgPool:
    """One node's asyncpg-shaped view of the shared row. ``execute`` serves both ``pool.execute`` (the
    stepdown's unbounded path) and ``con.execute`` (stop()'s path through ``acquire``)."""

    def __init__(self, lease: _LeaseRow) -> None:
        self._lease = lease
        self.writes = _Writes(lease)
        self.acquire_timeouts: list[float | None] = []

    async def fetchrow(
        self, sql: str, *args: object, timeout: float | None = None
    ) -> dict[str, object] | None:
        assert "INSERT INTO leader_lease" in sql
        return self._lease.claim(args[1])

    def acquire(self, *, timeout: float | None = None) -> _PgAcquired:
        return _PgAcquired(self, timeout)

    async def execute(self, sql: str, *args: object) -> str:
        # Lease release args: (lease_key, owner). Tombstone args: ("left", last_seen, node_id).
        owner = args[1] if _LEASE_SQL in sql else args[2]
        return f"UPDATE {await self.writes.run(sql, owner)}"


class _SqlStore:
    """The SQL Server sibling of :class:`_PgPool`, shaped like the store's ``_fetchone``/``_execute``.
    Its hang cancels cleanly: the real store quarantines the cancelled connection, and what that can
    still cost is on STOP_WRITE_TIMEOUT_SECONDS, not modelled here."""

    _settings = None

    def __init__(self, lease: _LeaseRow) -> None:
        self._lease = lease
        self.writes = _Writes(lease)

    async def _fetchone(self, sql: str, params: tuple[object, ...]) -> dict[str, object] | None:
        assert "MERGE leader_lease" in sql
        return self._lease.claim(params[1])

    async def _execute(self, sql: str, params: tuple[object, ...]) -> int:
        owner = params[1] if _LEASE_SQL in sql else params[2]
        return await self.writes.run(sql, owner)


def _pg(pool: _PgPool, node: str, mono: _Clock) -> DbCoordinator:
    return DbCoordinator(
        pool,
        node,
        heartbeat_seconds=10.0,
        leader_lease_ttl_seconds=_TTL,
        leader_fence_timeout_seconds=_FENCE,
        monotonic=mono,
        stop_write_timeout_seconds=_BOUND,
    )


def _ss(store: _SqlStore, node: str, mono: _Clock) -> SqlServerCoordinator:
    return SqlServerCoordinator(
        store,
        node,
        heartbeat_seconds=10.0,
        leader_lease_ttl_seconds=_TTL,
        leader_fence_timeout_seconds=_FENCE,
        monotonic=mono,
        stop_write_timeout_seconds=_BOUND,
    )


def _backends(lease: _LeaseRow) -> list[tuple[str, _Writes, DbCoordinator | SqlServerCoordinator]]:
    """One self-contained node "A" per backend over the same kind of row, so each scenario below runs
    against both coordinators without a copy of its body."""
    pool = _PgPool(lease)
    store = _SqlStore(lease)
    return [
        ("postgres", pool.writes, _pg(pool, "A", _Clock(0.0))),
        ("sqlserver", store.writes, _ss(store, "A", _Clock(0.0))),
    ]


async def _lead_then_self_fence(coord: DbCoordinator | SqlServerCoordinator) -> None:
    """Acquire the lease, then let the watchdog fence the node on its own clock. The DB clock does not
    move, so the row is still live when the test stops the node: exactly the window #1987 names."""
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    coord._monotonic.t = _FENCE + 0.1  # type: ignore[attr-defined]
    coord._check_fence()
    assert coord.is_leader() is False, "the fence did not fire, so this test proves nothing"
    assert coord.may_own_lease_row() is True


async def _timed_stop(coord: DbCoordinator | SqlServerCoordinator) -> float:
    started = time.monotonic()
    await asyncio.wait_for(coord.stop(), timeout=_HANG_GUARD)
    return time.monotonic() - started


# --- the release lands --------------------------------------------------------


async def test_stop_of_a_self_fenced_node_expires_its_lease_row() -> None:
    for name, writes, a in _backends(lease := _LeaseRow(_Clock(_DB_NOW))):
        lease.row = None
        await _lead_then_self_fence(a)
        assert lease.is_live(), f"{name}: control: the row must still be live after the fence"

        await a.stop()

        assert (writes.lease_writes, writes.node_writes) == (1, 1), name
        assert lease.row is not None and lease.row["owner"] == "A", name
        assert lease.row["lease_expires_at"] == _DB_NOW, name  # stamped at the DB clock's now
        assert a._lease_release_owed is False, name
        # A standby takes the row on its next tick instead of waiting out the TTL.
        lease._db_clock.t = _DB_NOW + 1.0
        b = _pg(_PgPool(lease), "B", _Clock(0.0))
        await b._maintain_leadership()
        assert b.is_leader() is True, name
        lease._db_clock.t = _DB_NOW


async def test_pg_stop_writes_go_through_a_bounded_acquire() -> None:
    # The acquire's timeout is what bounds asyncpg's release wait; a bare pool.execute leaves it None.
    lease = _LeaseRow(_Clock(_DB_NOW))
    pool = _PgPool(lease)
    a = _pg(pool, "A", _Clock(0.0))
    await _lead_then_self_fence(a)
    await a.stop()
    assert pool.acquire_timeouts == [_BOUND, _BOUND]


async def test_stop_of_a_follower_leaves_the_leaders_row_alone() -> None:
    # The force is unconditional, because a claim the gather cancelled after the server committed it
    # is invisible in memory. So the write must be owner-scoped: sent, and matching nothing here.
    lease = _LeaseRow(_Clock(_DB_NOW))
    leader = _pg(_PgPool(lease), "L", _Clock(0.0))
    await leader._maintain_leadership()
    for name, writes, b in _backends(lease):
        await b._maintain_leadership()
        assert b.is_leader() is False and b.may_own_lease_row() is False, name

        await b.stop()

        assert (writes.lease_writes, writes.node_writes) == (1, 1), name
        assert lease.is_live() and lease.row is not None and lease.row["owner"] == "L", name


# --- the bound ------------------------------------------------------------------


async def test_stop_is_bounded_when_the_release_hangs_in_flight() -> None:
    for name, writes, a in _backends(lease := _LeaseRow(_Clock(_DB_NOW))):
        lease.row = None
        await _lead_then_self_fence(a)
        writes.hang_on = _LEASE_SQL

        elapsed = await _timed_stop(a)

        # One write at most twice the bound, and the tombstone skipped. Generous slack for a loaded
        # runner; an unbounded wait trips the outer guard instead.
        assert elapsed < 2.0, f"{name}: stop() took {elapsed:.2f}s against a {_BOUND}s bound"
        assert (writes.lease_writes, writes.node_writes) == (0, 0), name
        assert a._lease_release_owed is True, name  # still owed, not silently dropped
        assert lease.is_live(), name  # so the row ages out at its TTL, the pre-existing fallback


async def test_stop_is_bounded_when_only_the_tombstone_hangs() -> None:
    for name, writes, a in _backends(lease := _LeaseRow(_Clock(_DB_NOW))):
        lease.row = None
        await _lead_then_self_fence(a)
        writes.hang_on = _NODES_SQL

        elapsed = await _timed_stop(a)

        assert elapsed < 2.0, f"{name}: stop() took {elapsed:.2f}s against a {_BOUND}s bound"
        assert (writes.lease_writes, writes.node_writes) == (1, 0), name
        assert not lease.is_live(), name  # the release landed before the tombstone hung


async def test_a_release_that_fails_fast_still_sends_the_tombstone() -> None:
    # Only a release that spent its whole bound says the pool is not answering. A fast failure says
    # nothing about it, and skipping the tombstone would leave the row reading active and fresh.
    for name, writes, a in _backends(lease := _LeaseRow(_Clock(_DB_NOW))):
        lease.row = None
        await _lead_then_self_fence(a)
        writes.fail_on = _LEASE_SQL

        await _timed_stop(a)

        assert (writes.lease_writes, writes.node_writes) == (0, 1), name
        assert a._lease_release_owed is True, name


# --- _execute_within ------------------------------------------------------------


class _ReleaseFailsAfterCommit:
    """A connection whose statement returns and whose return to the pool then fails, as asyncpg's
    release does when its reset round trip misses the acquire budget."""

    def acquire(self, *, timeout: float | None = None) -> _ReleaseFailsAfterCommit:
        return self

    async def __aenter__(self) -> _ReleaseFailsAfterCommit:
        return self

    async def __aexit__(self, *exc: object) -> None:
        raise TimeoutError

    async def execute(self, sql: str, *args: object) -> str:
        return "UPDATE 1"


async def test_a_write_that_committed_is_not_reported_failed_by_its_release() -> None:
    status = await _execute_within(_ReleaseFailsAfterCommit(), _BOUND, "UPDATE leader_lease")
    assert status == "UPDATE 1"


def test_the_default_bound_reaches_both_coordinators() -> None:
    lease = _LeaseRow(_Clock(_DB_NOW))
    assert DbCoordinator(_PgPool(lease), "A")._stop_write_timeout == STOP_WRITE_TIMEOUT_SECONDS
    assert SqlServerCoordinator(_SqlStore(lease), "A")._stop_write_timeout == (
        STOP_WRITE_TIMEOUT_SECONDS
    )
