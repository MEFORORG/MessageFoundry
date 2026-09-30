# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1987: ``stop()`` releases a self-fenced node's lease row, under a per-call time bound.

The self-fence clears the in-memory gate on the node's own clock while the lease row stays live on the
DB clock. Before this fix ``stop()`` gated its release on that gate, so a self-fenced node that was then
stopped sent nothing and a standby waited out the whole TTL. Forcing the write was once tried and
reverted because it had no per-call bound, and a self-fenced node's pool is the one most likely to hang.

Both coordinators run here against in-memory stand-ins, so no database is needed. The stand-ins model
only the statements ``stop()`` and the claim send. The live-server suites
(``test_cluster_failover_postgres.py``, ``test_cluster_failover_sqlserver.py``) cover the SQL itself.
"""

from __future__ import annotations

import asyncio
import time

from messagefoundry.pipeline.cluster import STOP_WRITE_TIMEOUT_SECONDS, DbCoordinator
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator

_TTL = 30.0
_FENCE = 20.0
# A realistic DB clock. The release writes the epoch, 0.0, so against a DB clock that also starts at
# 0.0 a released row still reads live and the standby check below would fail for the wrong reason.
_DB_NOW = 1_700_000_000.0
_HANG_GUARD = 10.0


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
        return self.row is not None and float(self.row["lease_expires_at"]) > self._db_clock()  # type: ignore[arg-type]


class _PgPool:
    """One node's asyncpg-shaped view of the shared row. ``hang`` suspends EVERY write forever, before it
    touches anything, which is what a stuck pool acquire looks like to the caller."""

    def __init__(self, lease: _LeaseRow) -> None:
        self._lease = lease
        self.hang = False
        self.lease_writes = 0
        self.node_writes = 0

    async def fetchrow(
        self, sql: str, *args: object, timeout: float | None = None
    ) -> dict[str, object] | None:
        assert "INSERT INTO leader_lease" in sql
        return self._lease.claim(args[1])

    async def execute(self, sql: str, *args: object) -> str:
        if self.hang:
            await asyncio.Event().wait()  # nothing ever sets it
        if "UPDATE leader_lease" in sql:
            self.lease_writes += 1
            return f"UPDATE {self._lease.release(args[1])}"
        assert "UPDATE nodes" in sql, sql
        self.node_writes += 1
        return "UPDATE 1"


class _SqlStore:
    """The SQL Server sibling of :class:`_PgPool`, shaped like the store's ``_fetchone``/``_execute``."""

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


def _pg(pool: _PgPool, node: str, mono: _Clock) -> DbCoordinator:
    return DbCoordinator(
        pool,
        node,
        heartbeat_seconds=10.0,
        leader_lease_ttl_seconds=_TTL,
        leader_fence_timeout_seconds=_FENCE,
        monotonic=mono,
    )


def _ss(store: _SqlStore, node: str, mono: _Clock) -> SqlServerCoordinator:
    return SqlServerCoordinator(
        store,
        node,
        heartbeat_seconds=10.0,
        leader_lease_ttl_seconds=_TTL,
        leader_fence_timeout_seconds=_FENCE,
        monotonic=mono,
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


# --- Postgres / SQLite-shaped coordinator (DbCoordinator) --------------------


async def test_pg_stop_of_a_self_fenced_node_expires_its_lease_row() -> None:
    lease = _LeaseRow(_Clock(_DB_NOW))
    pool = _PgPool(lease)
    mono = _Clock(0.0)
    a = _pg(pool, "A", mono)
    await _lead_then_self_fence(a, mono)
    assert lease.is_live(), "control: the row must still be live after the fence"

    await a.stop()

    assert pool.lease_writes == 1
    assert lease.row is not None and lease.row["owner"] == "A"
    assert lease.row["lease_expires_at"] == 0.0
    assert a._lease_release_owed is False
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


async def test_pg_stop_is_bounded_when_every_write_hangs() -> None:
    lease = _LeaseRow(_Clock(_DB_NOW))
    pool = _PgPool(lease)
    mono = _Clock(0.0)
    a = _pg(pool, "A", mono)
    await _lead_then_self_fence(a, mono)
    pool.hang = True
    a._stop_write_timeout = 0.05

    started = time.monotonic()
    # The outer guard turns an unbounded stop() into a clean failure here, rather than a hang that
    # pytest-timeout ends by killing the whole run. It is far above the bound, so it never decides a pass.
    await asyncio.wait_for(a.stop(), timeout=_HANG_GUARD)
    elapsed = time.monotonic() - started

    # Two bounded writes: the release and the `left` tombstone. Generous slack for a loaded runner;
    # the unbounded version never returns, so the outer guard fails it instead.
    assert elapsed < 2.0, f"stop() took {elapsed:.2f}s against a 0.05s per-write bound"
    assert pool.lease_writes == 0 and pool.node_writes == 0  # neither write got through
    assert a._lease_release_owed is True  # the release is still owed, not silently dropped
    assert lease.is_live()  # so the row ages out at its TTL, the pre-existing fallback


def test_the_shipped_bound_fits_the_service_stop_budget() -> None:
    # NSSM gives the process 15 s after Ctrl+C (install-service.ps1, AppStopMethodConsole 15000), and
    # stop() makes two bounded writes. A bound that ate that budget would be no bound at all.
    assert 0.0 < 2 * STOP_WRITE_TIMEOUT_SECONDS < 15.0
    assert _pg(_PgPool(_LeaseRow(_Clock(_DB_NOW))), "A", _Clock())._stop_write_timeout == (
        STOP_WRITE_TIMEOUT_SECONDS
    )
    assert _ss(_SqlStore(_LeaseRow(_Clock(_DB_NOW))), "A", _Clock())._stop_write_timeout == (
        STOP_WRITE_TIMEOUT_SECONDS
    )


# --- SQL Server coordinator ---------------------------------------------------


async def test_sqlserver_stop_of_a_self_fenced_node_expires_its_lease_row() -> None:
    lease = _LeaseRow(_Clock(_DB_NOW))
    store = _SqlStore(lease)
    mono = _Clock(0.0)
    a = _ss(store, "A", mono)
    await _lead_then_self_fence(a, mono)
    assert lease.is_live(), "control: the row must still be live after the fence"

    await a.stop()

    assert store.lease_writes == 1
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


async def test_sqlserver_stop_is_bounded_when_every_write_hangs() -> None:
    lease = _LeaseRow(_Clock(_DB_NOW))
    store = _SqlStore(lease)
    mono = _Clock(0.0)
    a = _ss(store, "A", mono)
    await _lead_then_self_fence(a, mono)
    store.hang = True
    a._stop_write_timeout = 0.05

    started = time.monotonic()
    await asyncio.wait_for(a.stop(), timeout=_HANG_GUARD)  # see the Postgres twin
    elapsed = time.monotonic() - started

    assert elapsed < 2.0, f"stop() took {elapsed:.2f}s against a 0.05s per-write bound"
    assert store.lease_writes == 0 and store.node_writes == 0
    assert a._lease_release_owed is True
    assert lease.is_live()
