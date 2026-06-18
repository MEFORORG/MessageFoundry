# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SQL Server-backed cluster coordinator for **active-passive HA** (SQL Server store, Phase 4).

The Postgres :class:`~messagefoundry.pipeline.cluster.DbCoordinator` drives an asyncpg pool; the SQL
Server store's pool is aioodbc (cursor-based, ``?`` params, tuple rows). This class is the SQL Server
sibling: it implements the same :class:`~messagefoundry.pipeline.cluster.ClusterCoordinator` contract so
a hot standby can take over when the primary dies, but on aioodbc + T-SQL.

**Scope = active-passive ONLY.** It provides leader election (the self-fencing ``leader_lease``) +
membership/observability + the cross-node config-version token. It does NOT provide the active-active
per-lane row leases — :meth:`lane_owner` returns ``None`` and :meth:`owns_lane` returns ``True`` (the
single active node, the leader, drains every lane on the unchanged no-owner claim path). Per-lane FIFO
ownership across many active nodes stays Postgres-only (0.2 scale-out).

The leadership lease, self-fence watchdog, and cached cheap/synchronous gates are identical in *design*
to :class:`DbCoordinator` (see that module's docstring) — the in-memory pieces (fence math, ``is_leader``
caching) are copied verbatim and only the DB layer differs:

- **DB clock:** ``DATEDIFF_BIG(millisecond, '1970-01-01', SYSUTCDATETIME()) / 1000.0`` (epoch seconds) —
  the SQL Server analog of PG ``EXTRACT(EPOCH FROM clock_timestamp())``; computed in T-SQL so all nodes
  share one logical clock and inter-node skew is irrelevant to lease correctness.
- **Atomic acquire/renew:** ``MERGE leader_lease WITH (HOLDLOCK)`` with the take-over predicate
  ``owner = me OR lease_expires_at < @now`` — the single-statement, serializable analog of PG's
  ``INSERT ... ON CONFLICT ... WHERE``.
- **DDL race guard:** the store's transaction-scoped ``sp_getapplock`` (``store._applock``), the T-SQL
  analog of PG's ``pg_advisory_xact_lock``.

It is duck-typed on the store (``store._acquire`` / ``store._applock`` / ``store._fetchone`` /
``store._fetchall`` / ``store._execute`` / ``store._settings``) so this module imports cleanly without
the optional ``aioodbc`` extra and never hard-imports the concrete store.

.. note::
   FAILOVER IN-FLIGHT RECOVERY is unresolved here (see :meth:`reclaims_inflight`). A standby becomes
   leader WITHOUT a restart, so the engine's startup ``reset_stale_inflight`` never re-fires for it. The
   planned fix is an **on-acquire** ``Store.reset_stale_inflight`` hook (run once when this node flips
   non-leader→leader, before it drains). That engine-seam wiring + :func:`build_coordinator` dispatch +
   the ``[cluster]``-requires-postgres relaxation are DEFERRED until the cluster.py observability work
   (branch ``ha-cluster-status-failover``) lands on main, to avoid editing cluster.py in parallel.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from messagefoundry.pipeline.cluster import ClusterMember, default_node_id
from messagefoundry.redaction import safe_exc

log = logging.getLogger(__name__)

__all__ = ["SqlServerCoordinator"]

if TYPE_CHECKING:
    from messagefoundry.pipeline.cluster import ClusterCoordinator

    def _assert_satisfies_protocol(c: "SqlServerCoordinator") -> "ClusterCoordinator":
        # Compile-time guard (mypy, every PR): SqlServerCoordinator MUST satisfy the ClusterCoordinator
        # Protocol owned by cluster.py. If a future increment adds a contract method (as #257 added
        # leadership_lease), this assignment fails mypy until it's implemented here too.
        return c


# epoch seconds from the DB's own UTC clock — the SQL Server analog of PG clock_timestamp().
_DB_NOW = "DATEDIFF_BIG(millisecond, '1970-01-01', SYSUTCDATETIME()) / 1000.0"

_logged_cluster_enabled = False


class SqlServerCoordinator:
    """Active-passive leader election + membership on the SQL Server store (aioodbc + T-SQL).

    Mirrors :class:`~messagefoundry.pipeline.cluster.DbCoordinator` minus the active-active lane leases.
    On :meth:`start` it idempotently creates the ``nodes`` / ``leader_lease`` / ``cluster_config`` tables
    (under the store's ``sp_getapplock`` DDL guard), upserts this node, and spawns a **maintenance** task
    (heartbeat + lease acquire/renew + config-version refresh each tick) and a DB-free **fence watchdog**
    that demotes this node if it cannot renew within ``leader_fence_timeout`` (< the lease TTL) — so a
    partitioned old leader stops reporting :meth:`is_leader` ``True`` before any standby can acquire the
    lease (the split-brain guard).
    """

    def __init__(
        self,
        store: Any,
        node_id: str,
        *,
        heartbeat_seconds: float = 10.0,
        node_timeout_seconds: float = 30.0,
        leader_lease_ttl_seconds: float = 30.0,
        leader_fence_timeout_seconds: float = 20.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self.node_id = node_id
        self._heartbeat_seconds = heartbeat_seconds
        self._node_timeout_seconds = node_timeout_seconds
        self._lease_ttl = leader_lease_ttl_seconds
        self._fence_timeout = leader_fence_timeout_seconds
        # Small relative to the fence timeout so a fence fires promptly (well before the lease TTL).
        self._fence_tick = max(0.05, min(1.0, leader_fence_timeout_seconds / 5.0))
        self._monotonic = monotonic
        # Schema-namespace the DDL applock + the lease key, exactly as DbCoordinator does, so two
        # deployments sharing one database via different schemas don't contend / co-elect.
        schema = getattr(getattr(store, "_settings", None), "db_schema", None) or "dbo"
        self._lock_key = f"{schema}:mefor_cluster_nodes"
        self._lease_key = f"{schema}:mefor_cluster_leader"
        self._host = socket.gethostname()
        self._pid = os.getpid()
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._fence_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        # Cached leadership state read by the cheap/synchronous is_leader() gate (no DB on the hot path).
        self._is_leader: bool = False
        # Monotonic time of the last CONFIRMED lease hold; the fence demotes when now - this > timeout.
        self._last_renew_ok: float | None = None
        self._config_version: int = 0

    # --- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Register this node and begin heartbeating. Idempotent (a second call is a no-op while the
        heartbeat already runs; the row upsert is idempotent too)."""
        if self._heartbeat_task is not None:
            return
        self._log_cluster_enabled_once()
        await self._ensure_tables()
        await self._register()
        self._stop.clear()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        # Separate from the maintenance loop and does NO DB I/O, so a hung DB can never block fencing.
        self._fence_task = asyncio.create_task(self._fence_watchdog_loop())

    async def stop(self) -> None:
        """Release leadership, cancel both tasks, mark this node left. Idempotent and never raises."""
        self._stop.set()
        tasks = [t for t in (self._heartbeat_task, self._fence_task) if t is not None]
        self._heartbeat_task = None
        self._fence_task = None
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        # Demote the cached gate FIRST (a concurrent is_leader() reader sees "not leader" at once), then
        # expire the lease row so a standby can take over immediately on a clean shutdown.
        await self._release_leadership()
        try:
            await self._store._execute(
                "UPDATE nodes SET status=?, last_seen=?, is_leader=0 WHERE node_id=?",
                ("left", time.time(), self.node_id),
            )
        except Exception as exc:  # pool may already be closing on shutdown — log, don't raise
            log.warning("cluster: failed to mark node %s left: %s", self.node_id, safe_exc(exc))

    # --- cheap/synchronous gates --------------------------------------------

    def is_leader(self) -> bool:
        return self._is_leader  # cached; no DB. The active-passive gate.

    def owns_lane(self, lane_key: str) -> bool:
        return True  # active-passive: the single active node (leader) owns every lane.

    def lane_owner(self) -> str | None:
        return None  # no per-lane leasing → claim_next_fifo takes its unchanged no-owner path.

    def reclaims_inflight(self) -> bool:
        # OPEN (deferred to wiring): a standby is promoted WITHOUT a restart, so startup
        # reset_stale_inflight never re-fires. The planned fix is an on-acquire reset_stale_inflight hook
        # (run when _is_leader flips False->True). Reported True (clustered, leader-driven recovery) to
        # match the clustered contract; the exact engine seam is resolved with the cluster.py work.
        return True

    def is_clustered(self) -> bool:
        return True

    def config_version_cached(self) -> int:
        return self._config_version

    # --- config version (cross-node convergence token) ----------------------

    async def config_version(self) -> int:
        """Read (seeding to 0 if absent) and cache the cluster-wide config-reload version."""
        row = await self._store._fetchone(
            "SET NOCOUNT ON;"
            " MERGE cluster_config WITH (HOLDLOCK) AS t USING (SELECT 1 AS id) AS s ON t.id = s.id"
            " WHEN MATCHED THEN UPDATE SET id = t.id"  # no-op update so OUTPUT yields the current row
            " WHEN NOT MATCHED THEN INSERT (id, config_version, updated_at) VALUES (1, 0, ?)"
            " OUTPUT inserted.config_version AS config_version;",
            (time.time(),),
        )
        assert row is not None, "cluster_config upsert returned no row"
        self._config_version = int(row["config_version"])
        return self._config_version

    async def bump_config_version(self) -> int:
        """Atomically increment + cache the cluster config version (operator reload on THIS node)."""
        now = time.time()
        row = await self._store._fetchone(
            "SET NOCOUNT ON;"
            " MERGE cluster_config WITH (HOLDLOCK) AS t USING (SELECT 1 AS id) AS s ON t.id = s.id"
            " WHEN MATCHED THEN UPDATE SET config_version = t.config_version + 1, updated_at = ?"
            " WHEN NOT MATCHED THEN INSERT (id, config_version, updated_at) VALUES (1, 1, ?)"
            " OUTPUT inserted.config_version AS config_version;",
            (now, now),
        )
        assert row is not None, "cluster_config upsert returned no row"
        self._config_version = int(
            row["config_version"]
        )  # feedback-avoidance: see our own new value
        return self._config_version

    # --- observability -------------------------------------------------------

    async def cluster_members(self) -> list[ClusterMember]:
        """One :class:`ClusterMember` per node; ``is_leader`` derived as the single freshest fresh
        ``is_leader``-flagged node (so a crashed ex-leader's stale flag is never the live leader)."""
        rows = await self._store._fetchall(
            "SELECT node_id, host, pid, started_at, last_seen, status, is_leader"
            " FROM nodes ORDER BY node_id"
        )
        now = time.time()
        leader_node_id: str | None = None
        leader_last_seen: float = -1.0
        for r in rows:
            last_seen = r["last_seen"]
            fresh = last_seen is not None and (now - last_seen) <= self._node_timeout_seconds
            if bool(r["is_leader"]) and fresh and last_seen > leader_last_seen:
                leader_last_seen = last_seen
                leader_node_id = r["node_id"]
        return [
            ClusterMember(
                node_id=r["node_id"],
                host=r["host"],
                pid=int(r["pid"]) if r["pid"] is not None else None,
                started_at=r["started_at"],
                last_seen=r["last_seen"],
                status=r["status"],
                is_leader=(r["node_id"] == leader_node_id),
            )
            for r in rows
        ]

    async def leadership_lease(self) -> tuple[str | None, float | None]:
        """The authoritative lease state ``(owner, DB-clock expiry)`` for the observability API;
        ``(None, None)`` before any lease row exists."""
        row = await self._store._fetchone(
            "SELECT owner, lease_expires_at FROM leader_lease WHERE lease_key = ?",
            (self._lease_key,),
        )
        if row is None:
            return (None, None)
        return (row["owner"], row["lease_expires_at"])

    # --- internals -----------------------------------------------------------

    def _log_cluster_enabled_once(self) -> None:
        global _logged_cluster_enabled
        if _logged_cluster_enabled:
            return
        _logged_cluster_enabled = True
        log.info(
            "cluster: SQL Server active-passive coordination enabled for node %s — exactly one node "
            "holds the leadership lease and drains the graph; standbys stay leader-gated until failover",
            self.node_id,
        )

    async def _ensure_tables(self) -> None:
        """Create the nodes / leader_lease / cluster_config tables under the store's transaction-scoped
        applock (serializes concurrent first-opens so two nodes can't race the CREATE TABLEs)."""
        async with self._store._acquire() as conn:
            cur = await conn.cursor()
            try:
                # A real statement MUST precede sp_getapplock @LockOwner='Transaction', or it does not
                # release on commit (the Phase-1 audit-chain gotcha). This benign SELECT is that statement.
                await cur.execute("SELECT 1")
                await cur.fetchone()
                await self._store._applock(cur, self._lock_key)
                await cur.execute(
                    "IF OBJECT_ID(N'nodes', N'U') IS NULL"
                    " CREATE TABLE nodes ("
                    " node_id NVARCHAR(256) NOT NULL PRIMARY KEY, host NVARCHAR(256) NULL,"
                    " pid INT NULL, started_at FLOAT NULL, last_seen FLOAT NULL,"
                    " status NVARCHAR(32) NULL,"
                    " is_leader BIT NOT NULL CONSTRAINT DF_nodes_is_leader DEFAULT 0);"
                )
                await cur.execute(
                    "IF OBJECT_ID(N'leader_lease', N'U') IS NULL"
                    " CREATE TABLE leader_lease ("
                    " lease_key NVARCHAR(256) NOT NULL PRIMARY KEY, owner NVARCHAR(256) NULL,"
                    " lease_expires_at FLOAT NOT NULL);"
                )
                await cur.execute(
                    "IF OBJECT_ID(N'cluster_config', N'U') IS NULL"
                    " CREATE TABLE cluster_config ("
                    " id INT NOT NULL PRIMARY KEY, config_version INT NOT NULL,"
                    " updated_at FLOAT NOT NULL);"
                )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def _register(self) -> None:
        now = time.time()
        await self._store._execute(
            "SET NOCOUNT ON;"
            " MERGE nodes WITH (HOLDLOCK) AS t USING (SELECT ? AS node_id) AS s"
            " ON t.node_id = s.node_id"
            " WHEN MATCHED THEN UPDATE SET host=?, pid=?, started_at=?, last_seen=?, status=?,"
            " is_leader=0"
            " WHEN NOT MATCHED THEN INSERT (node_id, host, pid, started_at, last_seen, status,"
            " is_leader) VALUES (?, ?, ?, ?, ?, ?, 0);",
            (
                self.node_id,
                self._host,
                self._pid,
                now,
                now,
                "active",
                self.node_id,
                self._host,
                self._pid,
                now,
                now,
                "active",
            ),
        )

    async def heartbeat_once(self) -> None:
        # Refresh last_seen (wall clock, like DbCoordinator) and fold the current is_leader flag — the
        # flag lags by at most one tick (the loop beats before _maintain_leadership). Zero extra writes.
        await self._store._execute(
            "UPDATE nodes SET last_seen=?, status=?, is_leader=? WHERE node_id=?",
            (time.time(), "active", 1 if self._is_leader else 0, self.node_id),
        )

    async def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            for step in (self.heartbeat_once, self._maintain_leadership, self.config_version):
                try:
                    await step()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.warning(
                        "cluster: %s failed for node %s; will retry: %s",
                        step.__name__,
                        self.node_id,
                        safe_exc(exc),
                    )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._heartbeat_seconds)
            except asyncio.TimeoutError:
                continue

    async def _maintain_leadership(self) -> None:
        held = await self._claim_or_renew_lease()
        if held:
            self._last_renew_ok = self._monotonic()  # stamp for the fence watchdog
            if not self._is_leader:
                self._is_leader = True
                log.info("cluster: node %s acquired leadership (lease)", self.node_id)
        elif self._is_leader:
            self._is_leader = False
            log.info("cluster: node %s lost leadership (lease taken or expired)", self.node_id)

    async def _claim_or_renew_lease(self) -> bool:
        """Atomically acquire (fresh / expired) or renew (already ours) the single leadership lease, all
        against the DB clock. Held iff the OUTPUT row exists AND names us. ``HOLDLOCK`` makes the
        take-over race serializable on the lease key (the analog of PG's single-statement upsert)."""
        row = await self._store._fetchone(
            "SET NOCOUNT ON;"
            f" DECLARE @now FLOAT = {_DB_NOW};"
            " MERGE leader_lease WITH (HOLDLOCK) AS t USING (SELECT ? AS lease_key) AS s"
            " ON t.lease_key = s.lease_key"
            " WHEN MATCHED AND (t.owner = ? OR t.lease_expires_at < @now)"
            " THEN UPDATE SET owner = ?, lease_expires_at = @now + ?"
            " WHEN NOT MATCHED"
            " THEN INSERT (lease_key, owner, lease_expires_at) VALUES (?, ?, @now + ?)"
            " OUTPUT inserted.owner AS owner;",
            (
                self._lease_key,
                self.node_id,
                self.node_id,
                self._lease_ttl,
                self._lease_key,
                self.node_id,
                self._lease_ttl,
            ),
        )
        return row is not None and row["owner"] == self.node_id

    async def _fence_watchdog_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._fence_tick)
                return  # stop requested
            except asyncio.TimeoutError:
                pass
            self._check_fence()

    def _check_fence(self) -> None:
        if not self._is_leader:
            return
        last = self._last_renew_ok
        if last is None:
            return  # defensive: _is_leader is only set alongside _last_renew_ok
        if self._monotonic() - last > self._fence_timeout:
            self._is_leader = False
            log.warning(
                "cluster: node %s SELF-FENCED — leadership lease not renewed within %.1fs (fence "
                "timeout); halting leader work before the lease (TTL %.1fs) can expire",
                self.node_id,
                self._fence_timeout,
                self._lease_ttl,
            )

    async def _release_leadership(self) -> None:
        was_leader = self._is_leader
        self._is_leader = False
        self._last_renew_ok = None
        if not was_leader:
            return
        try:
            await self._store._execute(
                "UPDATE leader_lease SET lease_expires_at = 0 WHERE lease_key = ? AND owner = ?",
                (self._lease_key, self.node_id),
            )
        except Exception as exc:
            log.warning(
                "cluster: node %s failed to release the leadership lease (it will expire on its "
                "own): %s",
                self.node_id,
                safe_exc(exc),
            )


def default_sqlserver_node_id() -> str:
    """Convenience re-export shim so callers can build a node id without importing cluster.py directly."""
    return default_node_id()
