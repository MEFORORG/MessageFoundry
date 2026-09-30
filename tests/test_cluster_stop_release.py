# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1987: ``stop()`` releases a self-fenced node's lease row, under a per-write time bound.

The self-fence clears the in-memory gate on the node's own clock while the lease row stays live on the
DB clock. Before this fix ``stop()`` gated its release on that gate, so a self-fenced node that was then
stopped sent nothing and a standby waited out the whole TTL. Forcing the write was once tried and
reverted because it had no per-call bound, and a self-fenced node's pool is the one most likely to hang.

Both coordinators run here against in-memory stand-ins, so no database is needed. The stand-ins model
only the statements ``stop()`` and the claim send, plus the one piece of asyncpg behaviour the bound
depends on (see :class:`_PgPool`). What they cannot show is a real driver under a real partition; no
suite here does that, including the live-server ones (``test_cluster_failover_postgres.py``,
``test_cluster_failover_sqlserver.py``), which exercise a healthy server.
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from types import TracebackType

from messagefoundry.pipeline.cluster import STOP_WRITE_TIMEOUT_SECONDS, DbCoordinator
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator
from messagefoundry.store.sqlserver import _DIRTY_CLOSE_TIMEOUT

_TTL = 30.0
_FENCE = 20.0
# A realistic DB clock. The release writes the epoch, 0.0, so against a DB clock that also starts at
# 0.0 a released row still reads live and the standby check below would fail for the wrong reason.
_DB_NOW = 1_700_000_000.0
# The bound the hang tests run with, and an outer guard far above it. The guard turns an unbounded
# stop() into a clean failure rather than a hang that pytest-timeout ends by killing the whole run.
_BOUND = 0.05
_HANG_GUARD = 10.0
_INSTALL_SERVICE = (
    Path(__file__).resolve().parents[1] / "scripts" / "service" / "install-service.ps1"
)


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
            row["lease_expires_at"] = 0.0
            return 1
        return 0

    def is_live(self) -> bool:
        row = self.row
        return row is not None and float(row["lease_expires_at"]) > self._db_clock()  # type: ignore[arg-type]


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
        if (
            exc_type is not None
            and issubclass(exc_type, asyncio.CancelledError)
            and self._pool.hang
        ):
            # asyncpg: a statement cancelled in flight leaves the protocol cancelling, and the pool's
            # shielded release waits for the server to acknowledge that cancel for as long as the
            # ACQUIRE's timeout, then terminates the connection and re-raises. None waits forever. A
            # partitioned server never acknowledges, so this wait is the whole question.
            await asyncio.wait_for(asyncio.Event().wait(), self._timeout)


class _PgPool:
    """One node's asyncpg-shaped view of the shared row.

    ``hang`` models the realistic self-fence case: the statement is already in flight when the server
    stops answering, so it never returns and its cancel is never acknowledged. A stall BEFORE the
    statement would cancel cleanly and prove much less, because it skips the pool release wait."""

    def __init__(self, lease: _LeaseRow) -> None:
        self._lease = lease
        self.hang = False
        self.lease_writes = 0
        self.node_writes = 0
        self.acquire_timeouts: list[float | None] = []

    async def fetchrow(
        self, sql: str, *args: object, timeout: float | None = None
    ) -> dict[str, object] | None:
        assert "INSERT INTO leader_lease" in sql
        return self._lease.claim(args[1])

    def acquire(self, *, timeout: float | None = None) -> _PgAcquired:
        return _PgAcquired(self, timeout)

    async def execute(self, sql: str, *args: object) -> str:
        # Serves both pool.execute (the stepdown's unbounded path) and con.execute (stop()'s path).
        if self.hang:
            await asyncio.Event().wait()  # in flight; the server never answers
        if "UPDATE leader_lease" in sql:
            self.lease_writes += 1
            return f"UPDATE {self._lease.release(args[1])}"
        assert "UPDATE nodes" in sql, sql
        self.node_writes += 1
        return "UPDATE 1"


class _SqlStore:
    """The SQL Server sibling of :class:`_PgPool`, shaped like the store's ``_fetchone``/``_execute``.
    Its hang cancels cleanly: the real store's quarantine wait is bounded separately, by
    ``_DIRTY_CLOSE_TIMEOUT``, and the budget test below counts it."""

    _settings = None

    def __init__(self, lease: _LeaseRow) -> None:
        self._lease = lease
        self.hang = False
        self.lease_writes = 0
        self.node_writes = 0

    async def _fetchone(self, sql: str, params: tuple[object, ...]) -> dict[str, object] | None:
        assert "MERGE leader_lease" in sql
        return self._lease.claim(params[1])

    async def _execute(self, sql: str, params: tuple[object, ...]) -> int:
        if self.hang:
            await asyncio.Event().wait()
        if "UPDATE leader_lease" in sql:
            self.lease_writes += 1
            return self._lease.release(params[1])
        assert "UPDATE nodes" in sql, sql
        self.node_writes += 1
        return 1


def _pg(pool: _PgPool, node: str, mono: _Clock, bound: float = _BOUND) -> DbCoordinator:
    return DbCoordinator(
        pool,
        node,
        heartbeat_seconds=10.0,
        leader_lease_ttl_seconds=_TTL,
        leader_fence_timeout_seconds=_FENCE,
        monotonic=mono,
        stop_write_timeout_seconds=bound,
    )


def _ss(store: _SqlStore, node: str, mono: _Clock, bound: float = _BOUND) -> SqlServerCoordinator:
    return SqlServerCoordinator(
        store,
        node,
        heartbeat_seconds=10.0,
        leader_lease_ttl_seconds=_TTL,
        leader_fence_timeout_seconds=_FENCE,
        monotonic=mono,
        stop_write_timeout_seconds=bound,
    )


async def _lead_then_self_fence(coord: DbCoordinator | SqlServerCoordinator, mono: _Clock) -> None:
    """Acquire the lease, then let the watchdog fence the node on its own clock. The DB clock does not
    move, so the row is still live when the test stops the node: exactly the window #1987 names."""
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    mono.t = _FENCE + 0.1
    coord._check_fence()
    assert coord.is_leader() is False, "the fence did not fire, so this test proves nothing"
    assert coord.may_own_lease_row() is True


async def _timed_stop(coord: DbCoordinator | SqlServerCoordinator) -> float:
    started = time.monotonic()
    await asyncio.wait_for(coord.stop(), timeout=_HANG_GUARD)
    return time.monotonic() - started


# --- Postgres / SQLite-shaped coordinator (DbCoordinator) --------------------


async def test_pg_stop_of_a_self_fenced_node_expires_its_lease_row() -> None:
    lease = _LeaseRow(_Clock(_DB_NOW))
    pool = _PgPool(lease)
    mono = _Clock(0.0)
    a = _pg(pool, "A", mono)
    await _lead_then_self_fence(a, mono)
    assert lease.is_live(), "control: the row must still be live after the fence"

    await a.stop()

    assert pool.lease_writes == 1 and pool.node_writes == 1
    assert lease.row is not None and lease.row["owner"] == "A"
    assert lease.row["lease_expires_at"] == 0.0
    assert a._lease_release_owed is False
    # Both writes went through acquire(timeout=bound), which is what bounds asyncpg's release wait.
    assert pool.acquire_timeouts == [_BOUND, _BOUND]
    # A standby takes the row on its next tick instead of waiting out the TTL.
    b = _pg(_PgPool(lease), "B", _Clock(0.0))
    await b._maintain_leadership()
    assert b.is_leader() is True


async def test_pg_stop_of_a_node_that_never_owned_the_row_sends_no_release() -> None:
    # Control arm: the force is gated on may_own_lease_row, not sent unconditionally. B saw A's live
    # lease, which clears B's baseline, so B's stop must leave A's row alone and send nothing for it.
    lease = _LeaseRow(_Clock(_DB_NOW))
    a = _pg(_PgPool(lease), "A", _Clock(0.0))
    await a._maintain_leadership()
    b_pool = _PgPool(lease)
    b = _pg(b_pool, "B", _Clock(0.0))
    await b._maintain_leadership()
    assert b.is_leader() is False and b.may_own_lease_row() is False

    await b.stop()

    assert b_pool.lease_writes == 0
    assert b_pool.node_writes == 1
    assert lease.is_live() and lease.row is not None and lease.row["owner"] == "A"


async def test_pg_stop_is_bounded_when_the_release_hangs_in_flight() -> None:
    lease = _LeaseRow(_Clock(_DB_NOW))
    pool = _PgPool(lease)
    mono = _Clock(0.0)
    a = _pg(pool, "A", mono)
    await _lead_then_self_fence(a, mono)
    pool.hang = True

    elapsed = await _timed_stop(a)

    # One write at most twice the bound (statement, then the release wait), and the tombstone is
    # skipped. Generous slack for a loaded runner; an unbounded wait trips the outer guard instead.
    assert elapsed < 2.0, f"stop() took {elapsed:.2f}s against a {_BOUND}s per-write bound"
    assert pool.acquire_timeouts == [_BOUND], "the tombstone must be skipped after a hung release"
    assert pool.lease_writes == 0 and pool.node_writes == 0
    assert a._lease_release_owed is True  # still owed, not silently dropped
    assert lease.is_live()  # so the row ages out at its TTL, the pre-existing fallback


# --- SQL Server coordinator ---------------------------------------------------


async def test_sqlserver_stop_of_a_self_fenced_node_expires_its_lease_row() -> None:
    lease = _LeaseRow(_Clock(_DB_NOW))
    store = _SqlStore(lease)
    mono = _Clock(0.0)
    a = _ss(store, "A", mono)
    await _lead_then_self_fence(a, mono)
    assert lease.is_live(), "control: the row must still be live after the fence"

    await a.stop()

    assert store.lease_writes == 1 and store.node_writes == 1
    assert lease.row is not None and lease.row["owner"] == "A"
    assert lease.row["lease_expires_at"] == 0.0
    assert a._lease_release_owed is False
    b = _ss(_SqlStore(lease), "B", _Clock(0.0))
    await b._maintain_leadership()
    assert b.is_leader() is True


async def test_sqlserver_stop_of_a_node_that_never_owned_the_row_sends_no_release() -> None:
    lease = _LeaseRow(_Clock(_DB_NOW))
    a = _ss(_SqlStore(lease), "A", _Clock(0.0))
    await a._maintain_leadership()
    b_store = _SqlStore(lease)
    b = _ss(b_store, "B", _Clock(0.0))
    await b._maintain_leadership()
    assert b.is_leader() is False and b.may_own_lease_row() is False

    await b.stop()

    assert b_store.lease_writes == 0
    assert b_store.node_writes == 1
    assert lease.is_live() and lease.row is not None and lease.row["owner"] == "A"


async def test_sqlserver_stop_is_bounded_when_the_release_hangs() -> None:
    lease = _LeaseRow(_Clock(_DB_NOW))
    store = _SqlStore(lease)
    mono = _Clock(0.0)
    a = _ss(store, "A", mono)
    await _lead_then_self_fence(a, mono)
    store.hang = True

    elapsed = await _timed_stop(a)

    assert elapsed < 2.0, f"stop() took {elapsed:.2f}s against a {_BOUND}s per-write bound"
    assert store.lease_writes == 0 and store.node_writes == 0
    assert a._lease_release_owed is True
    assert lease.is_live()


# --- the shipped bound against the service stop budget ------------------------


def test_the_shipped_bound_fits_the_service_stop_budget() -> None:
    # Read the budget from the installer rather than restating it here, so lowering it there fails
    # this test. Worst case per backend, from STOP_WRITE_TIMEOUT_SECONDS's own comment: a release that
    # returns just inside the bound, then a tombstone that misses it. Postgres pays twice the bound per
    # missed write (asyncpg's release wait), SQL Server the bound plus the store's quarantine close.
    found = re.search(r"AppStopMethodConsole\s+(\d+)", _INSTALL_SERVICE.read_text(encoding="utf-8"))
    assert found is not None, "install-service.ps1 no longer sets AppStopMethodConsole"
    budget = int(found.group(1)) / 1000.0
    bound = STOP_WRITE_TIMEOUT_SECONDS
    postgres_worst = bound + 2 * bound
    sqlserver_worst = bound + (bound + _DIRTY_CLOSE_TIMEOUT)
    assert 0.0 < max(postgres_worst, sqlserver_worst) < budget
    # And the default reaches both coordinators when nobody passes one.
    lease = _LeaseRow(_Clock(_DB_NOW))
    assert DbCoordinator(_PgPool(lease), "A")._stop_write_timeout == bound
    assert SqlServerCoordinator(_SqlStore(lease), "A")._stop_write_timeout == bound
