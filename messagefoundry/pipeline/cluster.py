# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Cluster coordination seam (active-passive HA — Track B Steps 3-7).

Active-passive HA runs the engine as a leader plus one or more hot standbys against one shared
server-DB store: exactly one node ("the leader") binds listeners and drains the graph, and a standby
takes over on failover. The coordination question is which node runs the **singleton** work that must
not double-execute (the wired graph itself, retention purges, the lease-reclaim sweep — *leader
election*, Step 4). This module answers it. Single-node operation (SQLite and single-node Postgres
alike) stays byte-identical: :class:`NullCoordinator` reports leader ``True``, so the engine runs the
graph directly.

The contract is deliberately tiny and the hot-path gate (:meth:`ClusterCoordinator.is_leader`) is
**synchronous and cheap** — it reads cached in-memory state so a per-message gate check adds no
``await``. :class:`NullCoordinator` is the default used everywhere on a single node; :class:`DbCoordinator`
is the Postgres-backed implementation that registers the node in a ``nodes`` table, heartbeats, runs
(Step 4) **real leader election** via a **self-fencing leadership lease** (a single ``leader_lease``
row with a DB-clock TTL) so exactly one node reports ``is_leader()`` at a time — and, for active-passive
HA (Workstream A2), a partitioned old leader **self-fences** before a standby can acquire it.
:func:`build_coordinator` picks between them defensively — a non-Postgres or not-``[cluster].enabled``
store always gets the :class:`NullCoordinator`.

**Steps 4 + 4b add leader election and leader-gated poll-source intake:** ``is_leader()`` reflects the
held leadership lease, the engine gates its leader-only WRITE singletons (retention, the lease-reclaim
sweep) on it, and the runner threads ``is_leader`` as a plain predicate into each source so only the
leader polls a **shared external resource** (a directory / DB table / remote dir) — listen sources
(MLLP/TCP) ignore it and run on every node, but only the leader binds them (the graph runs on the
leader only). Single-node operation stays byte-identical because :class:`NullCoordinator`'s
``is_leader()`` is always ``True``.

**Step 6 / 6b add cross-node CONVERGENCE.** :meth:`is_clustered` (``True`` on :class:`DbCoordinator`,
``False`` on :class:`NullCoordinator`) gates the engine's config-convergence loop and whether an
operator reload bumps the shared config version. :meth:`config_version` / :meth:`config_version_cached`
/ :meth:`bump_config_version` carry a single-row ``cluster_config`` version token: an operator reload
on one node bumps it and every other node's convergence loop reloads its own config dir to converge.
Reference-set convergence is the runner's job (the leader materializes from source; followers
read-through the shared snapshot). Transform-STATE convergence (Step 6b) follows the same shape: a
clustered write bumps a per-namespace ``state_version`` token in-txn and every node's
``StateConvergenceRunner`` read-throughs newer namespaces into its own state cache, so a sibling's
transform-state write reaches all nodes.

**Step 7 adds the read-only OBSERVABILITY API.** The active-passive HA feature set is now complete, so
the coordinator no longer hides behind an "experimental" banner. :meth:`cluster_members` returns one
:class:`ClusterMember` per known node (liveness + derived leadership) for the engine's ``/cluster/nodes``
endpoint; ``/cluster/status`` reads the cheap in-memory gates (:meth:`node_id` / :meth:`is_clustered` /
:meth:`is_leader` / :meth:`config_version_cached`). Cluster-wide leadership is derived from a per-node
``is_leader`` flag folded into the existing ``nodes`` heartbeat (one extra column, zero extra writes):
``cluster_members`` reports leader on the **single freshest** node whose flag is set and whose
``last_seen`` is within the node timeout, so a crashed ex-leader's lingering flag is never reported as
the live leader and a failover window (an old leader's flag not yet cleared while a new leader's flag is
already set) can never surface two leaders — the live, still-beating node wins. Leadership itself is the
``leader_lease`` row (Workstream A2's self-fencing lease); the ``nodes.is_leader`` flag mirrors it for
the observability API. :class:`NullCoordinator` synthesizes a single self-entry (single node, always leader).

Backend-agnostic by design: :class:`DbCoordinator` takes a raw asyncpg pool (typed ``Any``,
duck-typed) and never imports :class:`~messagefoundry.store.postgres.PostgresStore`, so this module
stays importable without the optional ``asyncpg`` extra.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from messagefoundry.redaction import safe_exc

log = logging.getLogger(__name__)

__all__ = [
    "ClusterCoordinator",
    "ClusterMember",
    "NullCoordinator",
    "DbCoordinator",
    "build_coordinator",
    "default_node_id",
]

# Advisory-lock classid for the nodes-table DDL, gated the same way PostgresStore._migrate_lease_columns
# is: serialize concurrent opens so two nodes can't race the CREATE TABLE. A distinct integer
# `classid` keeps this key in its own hashtext namespace, never colliding with the store's audit/
# schema/finalize lock families (which use 1/2/3 — see store/postgres.py). The text key is
# schema-namespaced per node (see DbCoordinator._lock_key), matching PostgresStore._lock_key.
_LOCK_CLASS_CLUSTER = 4

# Leader election (Track B Step 4 / Workstream A2) is a **self-fencing lease**, not an advisory lock.
# A single ``leader_lease`` row carries ``(lease_key, owner, lease_expires_at)``; the leader renews it
# every heartbeat to ``DB_now + leader_lease_ttl`` and a standby may acquire ONLY once the lease has
# expired (per the DB's own clock — ``clock_timestamp()`` — so inter-node clock skew is irrelevant to
# correctness). A leader that cannot renew within ``leader_fence_timeout`` (measured on its own
# monotonic clock, with no DB I/O) halts its leader work BEFORE the lease can expire, so a partitioned
# old leader stops processing before any standby can take over (the split-brain guard). The lease
# replaces the earlier session-level advisory lock, which gave fast crash-release but could not enforce
# the "wait out the TTL" fence a standby needs to be safe.


def default_node_id() -> str:
    """This node's stable identity: ``host:pid:hex`` — the same shape as
    :attr:`PostgresStore._owner`, so when the factory reuses ``store._owner`` the cluster node-id and
    the row-lease owner-id are one value (a useful invariant for Step 4 / failover recovery)."""
    return f"{socket.gethostname()}:{os.getpid()}:{uuid4().hex[:8]}"


@dataclass(frozen=True)
class ClusterMember:
    """One node's membership snapshot for the observability API (Track B Step 7). A plain frozen
    dataclass (no API import) so the coordinator stays free of FastAPI/Pydantic — the API maps it to a
    :class:`~messagefoundry.api.models.ClusterNode` at the boundary. ``is_leader`` is the DERIVED
    leadership: at most one member carries it — the single freshest node whose durable ``nodes.is_leader``
    heartbeat flag is set AND is fresh (``last_seen`` within ``node_timeout_seconds``) — so a crashed
    ex-leader's stale flag is never reported as the live leader and a failover window cannot surface two
    leaders. ``last_seen``/``started_at`` are epoch seconds, ``None`` only on the
    :class:`NullCoordinator` synthetic self-entry (no DB)."""

    node_id: str
    host: str | None
    pid: int | None
    started_at: float | None
    last_seen: float | None
    status: str
    is_leader: bool
    # Leader-preference config (ADR 0096), surfaced for the observability API so an operator can SEE a
    # node's handicap / promotability across the cluster. Defaulted so existing constructors (and the
    # single-node self-entry) stay valid; the DB coordinators read the durable per-node columns.
    acquire_delay_seconds: float = 0.0
    promotable: bool = True


@runtime_checkable
class ClusterCoordinator(Protocol):
    """The coordination contract every backend (null today, DB-backed later) implements.

    :attr:`node_id` is this node's stable identity. :meth:`start`/:meth:`stop` own any background
    membership task (idempotent — safe to call twice). :meth:`is_leader` is the **cheap, synchronous**
    gate Step 4 consults on the hot path — it must read cached state and never block or ``await``.
    """

    node_id: str

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def is_leader(self) -> bool:
        """Whether this node runs the leader-only singletons (the wired graph, retention, lease
        reclaim). Cheap/cached — never an ``await`` or a DB round-trip. Always ``True`` on
        :class:`NullCoordinator` (single-node)."""
        ...

    def current_epoch(self) -> int | None:
        """This node's currently-held **leader epoch** (the monotonic fencing token, H1), or ``None``
        when this node is not a fenced leader.

        The epoch is bumped **only on a fresh acquire** (a node taking the lease — not a renew), so a
        superseded ex-leader holds a strictly *older* epoch than the live leader. The engine reads this
        synchronously on promotion and pushes it into the store (:meth:`Store.set_leader_epoch`), where
        the FIFO claim validates ``held_epoch >= leader_lease.leader_epoch`` inside the single claim
        transaction so a paused/superseded ex-leader's stale claim affects **0 rows** (Kleppmann fencing
        token; store ↔ coordinator import direction is one-way — the engine pushes, the store never
        imports the coordinator, ARCH-6). Cheap + synchronous (cached state). :class:`NullCoordinator`
        returns ``None`` — single-node is unfenced (there is no second writer to fence)."""
        ...

    def lease_key(self) -> str | None:
        """The schema-namespaced ``leader_lease`` row key whose ``leader_epoch`` the store validates the
        held epoch against (H1), or ``None`` on the single-node :class:`NullCoordinator` (no lease row).
        The engine pushes it alongside :meth:`current_epoch` so the store can locate the authoritative
        epoch row without importing the coordinator (ARCH-6)."""
        ...

    def reclaims_inflight(self) -> bool:
        """Whether crashed-node in-flight recovery is the **leader's periodic reclaim sweep** (True) or
        the engine's **unconditional startup reset** (False).

        This decides which recovery path the engine runs at startup (and whether it spawns the leader
        lease-reclaim task), and it is a property of the *backend*, not of who is currently leader:

        * :class:`DbCoordinator` → ``True``. In a cluster the engine must NOT run the unconditional
          :meth:`Store.reset_stale_inflight` at startup — it ignores leases and would steal a live
          sibling's in-flight rows. Recovery instead comes from the leader periodically calling
          :meth:`Store.reclaim_expired_leases`, which only reclaims rows whose lease has expired.
        * :class:`NullCoordinator` → ``False``. Single-node keeps the unconditional startup reset —
          immediate self-recovery of its own crash residue, byte-identical to before this seam.
        """
        ...

    def is_clustered(self) -> bool:
        """Whether this is a real multi-node deployment (``True`` on :class:`DbCoordinator`) or the
        single-node no-op (``False`` on :class:`NullCoordinator`). The engine consults it to decide
        whether to spawn the config-convergence loop (Track B Step 6) and whether an operator reload
        should bump the cluster-wide config version — so single-node never spawns the loop and never
        touches the version token. Cheap + synchronous (a plain backend property, not who-is-leader)."""
        ...

    async def config_version(self) -> int:
        """The current cluster-wide config-reload version (Track B Step 6). :class:`DbCoordinator` reads
        ``cluster_config`` (initializing the single row to 0 if absent) and caches it; the engine reads
        it once at startup to seed ``_applied_config_version`` so a fresh node doesn't self-reload.
        :class:`NullCoordinator` returns 0 (single-node has no shared token)."""
        ...

    def config_version_cached(self) -> int:
        """The cached cluster-wide config version for the convergence loop to poll cheaply each tick
        (no DB round-trip). :class:`DbCoordinator` refreshes it every maintenance tick; reads of a value
        bumped on THIS node are immediate (:meth:`bump_config_version` updates the cache). Cheap +
        synchronous. :class:`NullCoordinator` returns 0."""
        ...

    async def bump_config_version(self) -> int:
        """Atomically increment the cluster-wide config version and return the new value (Track B
        Step 6). Called when an OPERATOR reload succeeds on this node, so every OTHER node's convergence
        loop sees the higher version and reloads its own config dir. :class:`DbCoordinator` does an
        ``INSERT ... ON CONFLICT DO UPDATE ... RETURNING`` and updates its cache; :class:`NullCoordinator`
        is a no-op returning 0 (single-node has nothing to coordinate)."""
        ...

    async def cluster_members(self) -> list[ClusterMember]:
        """Cluster membership for the observability API (Track B Step 7): one entry per known node with
        its liveness + derived leadership. :class:`DbCoordinator` reads the shared ``nodes`` table;
        :class:`NullCoordinator` returns a single synthetic self-entry (single node, always leader). One
        DB read on the clustered path, none single-node — off the message hot path (operator-driven)."""
        ...

    async def leadership_lease(self) -> tuple[str | None, float | None]:
        """The current leadership-lease state for the observability API (Workstream A5): ``(owner,
        lease_expires_at)`` — who holds the self-fencing leadership lease and the DB-clock epoch at which
        it expires (when a standby could acquire if the leader stops renewing). :class:`DbCoordinator`
        reads the single ``leader_lease`` row (one DB read, off the hot path); ``(None, None)`` before any
        lease exists. :class:`NullCoordinator` returns ``(node_id, None)`` — single-node is permanently
        leader with no lease/expiry."""
        ...


class NullCoordinator:
    """The single-node default (SQLite and single-node Postgres). Every gate is ``True``, there is no
    DB and no background task, so the engine behaves exactly as it did before this seam existed.

    :meth:`start`/:meth:`stop` are no-ops and idempotent.
    """

    def __init__(self, node_id: str | None = None) -> None:
        self.node_id = node_id or default_node_id()

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def is_leader(self) -> bool:
        return True

    def current_epoch(self) -> int | None:
        # Single-node: unfenced. There is no second writer to fence, so the store's epoch guard stays
        # disabled (set_leader_epoch(None) is the byte-identical no-op). Returning None — NOT 0 — keeps
        # the "is there a fence to enforce?" question distinct from any real epoch value.
        return None

    def lease_key(self) -> str | None:
        # Single-node: no leader_lease row to validate against.
        return None

    def reclaims_inflight(self) -> bool:
        # Single-node: the engine keeps the unconditional startup reset (immediate self-recovery of
        # this node's own crash residue). Byte-identical to before this seam existed.
        return False

    def is_clustered(self) -> bool:
        # Single-node: NOT a cluster, so the engine spawns no config-convergence loop and an operator
        # reload never bumps a shared version token. Byte-identical to before Step 6.
        return False

    async def config_version(self) -> int:
        # Single-node: no shared config token.
        return 0

    def config_version_cached(self) -> int:
        # Single-node: no shared config token.
        return 0

    async def bump_config_version(self) -> int:
        # Single-node: nothing to coordinate (no other node converges), so this is a no-op.
        return 0

    async def cluster_members(self) -> list[ClusterMember]:
        # Single-node: synthesize one self-entry so /cluster/nodes is byte-identical to a real cluster's
        # shape. No DB, always leader; started_at/last_seen are None (there is no heartbeat to record).
        return [
            ClusterMember(
                node_id=self.node_id,
                host=socket.gethostname(),
                pid=os.getpid(),
                started_at=None,
                last_seen=None,
                status="active",
                is_leader=True,
            )
        ]

    async def leadership_lease(self) -> tuple[str | None, float | None]:
        # Single-node: permanently leader, no lease row / expiry. Report self as the holder with no
        # expiry so /cluster/nodes is byte-identical in shape to a real cluster's.
        return (self.node_id, None)


# One-time-per-process info guard: the active-passive HA feature set is COMPLETE — election (Step 4),
# leader-gated WRITE singletons, leader-gated poll-source intake (Step 4b), cross-node convergence
# (Step 6 — leader-materialized reference sets read-through by followers + a config-reload version
# token; Step 6b — transform-STATE writes read-through by followers via a per-namespace version token),
# and the read-only observability API (Step 7 — /cluster/status + /cluster/nodes). So a standby no
# longer double-runs singletons, double-ingests a shared poll source, or starts on stale reference/
# config/state when it takes over, and an operator can SEE membership + leadership. The banner is
# therefore a one-time INFO (not a WARNING) that states the feature set is built and summarizes the
# operational assumptions operators must honor. Logged once so the log isn't spammed when several
# stores/coordinators open in one process (e.g. tests).
_logged_cluster_enabled = False


class DbCoordinator:
    """Postgres-backed cluster membership + **leader election** (Track B Steps 3-7).

    On :meth:`start` it idempotently creates the ``nodes`` + ``leader_lease`` tables, upserts this
    node's row, and spawns two cooperatively-cancellable tasks: a **maintenance** task that each tick
    (a) refreshes ``last_seen`` and (b) maintains leadership via a **self-fencing lease** (the single
    ``leader_lease`` row, renewed to ``DB_now + leader_lease_ttl``; a standby acquires only once that
    lease has expired per the DB clock), and a **fence watchdog** task that does NO DB I/O and demotes
    this node if it has not renewed within ``leader_fence_timeout`` (< the TTL) — so a partitioned old
    leader stops reporting :meth:`is_leader` ``True`` before any standby can acquire the lease (the
    split-brain guard, Workstream A2). Exactly one node holds the lease, so exactly one reports
    :meth:`is_leader` ``True``. :meth:`stop` releases the lease, cancels both tasks, and marks this node
    left.

    Leader-gated poll-source intake (Step 4b) IS built: the runner threads :meth:`is_leader` into each
    source as a plain predicate and the poll sources skip their scan on a follower, so a shared
    directory / DB table / remote dir is ingested by exactly one node (and the graph runs on the leader
    only). Cross-node CONVERGENCE (Steps 6 + 6b) IS built: :meth:`is_clustered` gates the engine's
    config-convergence loop, :meth:`config_version` / :meth:`config_version_cached` /
    :meth:`bump_config_version` carry the ``cluster_config`` version token so an operator reload on one
    node propagates cluster-wide, and transform-STATE writes bump a per-namespace ``state_version`` token
    that every node's ``StateConvergenceRunner`` read-throughs into its own cache. The read-only
    OBSERVABILITY API (Step 7) IS built: a per-node ``is_leader`` flag is folded into the ``nodes``
    heartbeat (one column, zero extra writes) and :meth:`cluster_members` reads the table and derives the
    **single live** leader (the freshest fresh-flagged node) for the engine's ``/cluster/nodes``
    endpoint — so the active-passive HA feature set is complete and a one-time INFO (not a warning)
    records the operational assumptions operators must honor.

    Backend-agnostic: it holds a raw asyncpg ``pool`` (duck-typed ``Any``) and never imports the
    concrete store, so this module imports cleanly without the optional ``asyncpg`` extra.
    """

    def __init__(
        self,
        pool: Any,
        node_id: str,
        *,
        heartbeat_seconds: float = 10.0,
        node_timeout_seconds: float = 30.0,
        leader_lease_ttl_seconds: float = 30.0,
        leader_fence_timeout_seconds: float = 20.0,
        acquire_delay_seconds: float = 0.0,
        promotable: bool = True,
        db_schema: str | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._pool = pool
        self.node_id = node_id
        self._heartbeat_seconds = heartbeat_seconds
        # A node is considered dead when its last_seen is older than this. Consulted by
        # cluster_members() (Step 7) as the freshness filter that discards a crashed ex-leader's stale
        # is_leader flag (and bounds the failover-overlap window). It is NOT what transfers leadership —
        # the leadership lease is (a standby acquires only once the lease has expired); lowering this
        # shrinks the window in which a just-beaten node can still count toward the derived leader,
        # raising it lets a just-crashed ex-leader's row stay "fresh" (and thus a leader candidate) longer.
        self._node_timeout_seconds = node_timeout_seconds
        # The leadership LEASE TTL (Workstream A2): the leader renews the lease to DB_now + this every
        # heartbeat; a standby may acquire only once the lease has expired (per the DB clock), so it
        # always waits out the full TTL before taking over.
        self._lease_ttl = leader_lease_ttl_seconds
        # The SELF-FENCE timeout: a leader that has not renewed within this many seconds (its own
        # monotonic clock, no DB I/O) demotes itself. MUST be < the TTL so the old leader stops before
        # the lease can expire and a standby acquire — the split-brain guard.
        self._fence_timeout = leader_fence_timeout_seconds
        # The fence watchdog polls this often; small relative to the fence timeout so a fence fires
        # promptly (well before the lease TTL). Pure in-memory check — no DB.
        self._fence_tick = max(0.05, min(1.0, leader_fence_timeout_seconds / 5.0))
        # Leader-preference (ADR 0096). `acquire_delay` handicaps ONLY the take-over-of-an-EXPIRED-lease
        # path (added to the lease-expiry time on the DB clock), never a renew; `promotable=False` makes
        # this node never claim/hold the lease at all. Default (0.0, True) = byte-identical to before.
        self._acquire_delay = acquire_delay_seconds
        self._promotable = promotable
        # Monotonic clock for the fence (injectable for deterministic tests). Distinct from the DB clock
        # the lease uses: the fence measures a node-local elapsed duration (skew-free by construction),
        # the lease compares against the DB's own clock_timestamp() (so inter-node skew is irrelevant).
        self._monotonic = monotonic
        # Namespace the nodes-DDL advisory lock by schema, exactly as PostgresStore._lock_key does:
        # advisory locks are database-scoped (not schema-scoped), so two deployments sharing one
        # database via different db_schema values must not contend on this lock. The nodes table
        # itself lands in the right schema via the pool's search_path; the lock key must match.
        self._lock_key = f"{db_schema or 'public'}:mefor_cluster_nodes"
        # The leadership-lease KEY (the single leader_lease row's primary key). Schema-namespaced so two
        # deployments sharing one database via different schemas elect leaders independently.
        self._lease_key = f"{db_schema or 'public'}:mefor_cluster_leader"
        self._host = socket.gethostname()
        self._pid = os.getpid()
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._fence_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        # Cached leadership state read by the cheap/synchronous is_leader() gate (no DB round-trip on
        # the hot path). Maintained by the maintenance task (acquire/renew/lose) and the fence watchdog
        # (self-fence on a stalled renew).
        self._is_leader: bool = False
        # The monotonic time of the last CONFIRMED lease hold (acquire or successful renew), or None if
        # this node has never held the lease. The fence watchdog demotes when now - this > fence_timeout.
        self._last_renew_ok: float | None = None
        # H1 fencing token: the leader epoch this node currently holds, or None when not a fenced leader.
        # Bumped in the DB only on a FRESH acquire (a take-over of a free/expired/foreign lease), NOT on a
        # renew, so a superseded ex-leader keeps its now-stale older epoch while the live leader's epoch
        # advances. The claim/renew statement RETURNS the row's leader_epoch; on a confirmed hold we cache
        # it here, and current_epoch() exposes it for the engine to push into the store on promotion.
        self._leader_epoch: int | None = None
        # Cached cluster-wide config-reload version (Track B Step 6), read by the cheap/synchronous
        # config_version_cached() the engine's convergence loop polls. Refreshed once per maintenance
        # tick and updated immediately by bump_config_version() (so the node that bumps sees its own new
        # value at once and does not re-converge). 0 until the first read/refresh.
        self._config_version: int = 0

    async def start(self) -> None:
        """Register this node and begin heartbeating. Idempotent: a second call is a no-op while the
        heartbeat is already running (the row upsert is also idempotent on its own)."""
        if self._heartbeat_task is not None:
            return  # already started — don't spawn a second heartbeat
        self._log_cluster_enabled_once()
        await self._ensure_nodes_table()
        await self._register()
        self._stop.clear()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        # The fence watchdog runs SEPARATELY from the maintenance loop and does NO DB I/O, so a hung DB
        # (which would block the maintenance loop mid-await) can never block self-fencing.
        self._fence_task = asyncio.create_task(self._fence_watchdog_loop())

    async def stop(self) -> None:
        """Release leadership, cancel both background tasks, and mark this node left. Idempotent and
        safe even if :meth:`start` raised before the tasks existed (then there's nothing to tear down).
        Ordered so the tasks are stopped BEFORE the lease is released, so a still-running tick can't
        re-acquire after we release."""
        self._stop.set()
        tasks = [t for t in (self._heartbeat_task, self._fence_task) if t is not None]
        self._heartbeat_task = None
        self._fence_task = None
        for t in tasks:
            t.cancel()
        if tasks:
            # Absorb the cancellation (and any error a loop stored) so stop() never raises.
            await asyncio.gather(*tasks, return_exceptions=True)
        # Drop leadership: demote the cached gate FIRST so any concurrent is_leader() reader sees "not
        # leader" the instant we begin releasing, then expire the lease row so a standby can take over
        # immediately on a clean shutdown (best-effort — a failed release just lets the lease age out).
        await self._release_leadership()
        # Mark the row left rather than DELETE it: keeping a 'left' tombstone gives an operator a
        # visible "this node shut down cleanly" signal (vs a crashed node whose row goes stale), which
        # Step 4's election/diagnostics will distinguish. The row is re-activated by the next start().
        try:
            # Also clear is_leader so a clean shutdown immediately stops reporting this node as leader
            # (Step 7). A hard crash skips this UPDATE and leaves the flag stale — the freshness filter in
            # cluster_members() handles that case by AND-ing the flag with a live last_seen.
            await self._pool.execute(
                "UPDATE nodes SET status=$1, last_seen=$2, is_leader=FALSE WHERE node_id=$3",
                "left",
                time.time(),
                self.node_id,
            )
        except Exception as exc:  # the pool may already be closing on shutdown — log, don't raise
            # safe_exc keeps the exception type + a redacted/bounded message: this is a connectivity
            # error (no PHI), but route it through the same redactor used everywhere for consistency.
            log.warning("cluster: failed to mark node %s left: %s", self.node_id, safe_exc(exc))

    def is_leader(self) -> bool:
        # Cheap + synchronous: read the cached state the maintenance loop + fence watchdog maintain (no
        # DB round-trip on the hot path). True only while this node holds the leadership lease.
        return self._is_leader

    def current_epoch(self) -> int | None:
        # Cheap + synchronous: the leader epoch captured on the last confirmed hold. None until first
        # acquire (or after a demotion/fence clears it), so the store's epoch guard stays off until this
        # node is genuinely a fenced leader. The engine reads this on promotion (H1).
        return self._leader_epoch

    def lease_key(self) -> str | None:
        # The schema-namespaced leader_lease key whose leader_epoch the store validates against (H1).
        return self._lease_key

    def reclaims_inflight(self) -> bool:
        # Clustered: the leader's periodic reclaim_expired_leases sweep recovers crashed nodes' in-
        # flight rows. The engine must therefore NOT run the unconditional startup reset_stale_inflight,
        # which ignores leases and would steal a live sibling's in-flight rows. See the Protocol method.
        return True

    def is_clustered(self) -> bool:
        # A real multi-node deployment: the engine spawns the config-convergence loop and an operator
        # reload bumps the shared config version so siblings converge. Cheap + synchronous.
        return True

    def config_version_cached(self) -> int:
        # Cheap + synchronous: read the value the maintenance loop refreshes each tick (and that
        # bump_config_version updates immediately on this node). No DB round-trip on the poll path.
        return self._config_version

    async def config_version(self) -> int:
        """Read (and cache) the current shared config version, initializing the single ``cluster_config``
        row to 0 if absent. Used at engine startup to seed ``_applied_config_version`` so a fresh node
        doesn't immediately self-reload, and as the maintenance-tick refresh of the cached value."""
        row = await self._pool.fetchrow(
            "INSERT INTO cluster_config (id, config_version, updated_at) VALUES (1, 0, $1) "
            "ON CONFLICT (id) DO UPDATE SET id = cluster_config.id "  # no-op update → RETURNING current
            "RETURNING config_version",
            time.time(),
        )
        # An INSERT ... ON CONFLICT ... RETURNING always yields a row; a None here is an impossible
        # state. Assert rather than fall back to 0 — a silent 0 would RESET the cached version
        # mid-cluster (worse than raising, since it could trigger redundant follower reloads).
        assert row is not None, "cluster_config upsert returned no row"
        self._config_version = int(row["config_version"])
        return self._config_version

    async def bump_config_version(self) -> int:
        """Atomically increment the shared config version and return the new value. Called when an
        operator reload succeeds on THIS node, so every other node's convergence loop sees the higher
        version and reloads its own config dir. Updates the cache immediately so this node's own loop
        sees no change (feedback-avoidance — the initiator does not re-reload)."""
        row = await self._pool.fetchrow(
            "INSERT INTO cluster_config (id, config_version, updated_at) VALUES (1, 1, $1) "
            "ON CONFLICT (id) DO UPDATE SET "
            "config_version = cluster_config.config_version + 1, updated_at = excluded.updated_at "
            "RETURNING config_version",
            time.time(),
        )
        # RETURNING always yields a row; assert rather than fall back to 0 (a silent 0 would reset the
        # cached version mid-cluster — see :meth:`config_version`).
        assert row is not None, "cluster_config upsert returned no row"
        self._config_version = int(row["config_version"])
        return self._config_version

    async def cluster_members(self) -> list[ClusterMember]:
        """Read the shared ``nodes`` table and return one :class:`ClusterMember` per node (Track B
        Step 7). Leadership is DERIVED so that **at most one** node is ever reported as leader, and it is
        always a *live* one:

        * A freshness filter (``last_seen`` within ``node_timeout_seconds``) discards a fully-stale
          crashed ex-leader's lingering ``is_leader=true`` flag outright.
        * Among the rows that still carry ``is_leader=true`` AND are fresh, only the **single freshest**
          (largest ``last_seen``) is reported as leader. During a failover window two rows can briefly
          both be fresh-and-flagged — the crashed ex-leader whose ``last_seen`` is frozen at the crash
          instant, and the newly-promoted leader whose ``last_seen`` keeps advancing. Picking the
          freshest collapses that overlap to the one node that is actually beating (the live leader), so
          ``/cluster/nodes`` never shows two leaders and never names the dead node as leader.

        One DB read, returned ordered by ``node_id`` for a stable listing; off the message hot path
        (operator-driven)."""
        rows = await self._pool.fetch(
            "SELECT node_id, host, pid, started_at, last_seen, status, is_leader, "
            "acquire_delay_seconds, promotable FROM nodes ORDER BY node_id"
        )
        now = time.time()
        # First pass: which rows carry a *fresh* leader flag, and which of those is the freshest. The
        # freshest fresh-flagged row is the single derived leader (it is the one still heartbeating).
        leader_node_id: str | None = None
        leader_last_seen: float = -1.0
        for r in rows:
            last_seen = r["last_seen"]
            fresh = last_seen is not None and (now - last_seen) <= self._node_timeout_seconds
            if r["is_leader"] and fresh and last_seen > leader_last_seen:
                leader_last_seen = last_seen
                leader_node_id = r["node_id"]
        members: list[ClusterMember] = []
        for r in rows:
            members.append(
                ClusterMember(
                    node_id=r["node_id"],
                    host=r["host"],
                    pid=r["pid"],
                    started_at=r["started_at"],
                    last_seen=r["last_seen"],
                    status=r["status"],
                    # Single derived leader: the freshest fresh-flagged node only. A stale ex-leader's
                    # flag is filtered out (not fresh), and a not-yet-cleared ex-leader that overlaps a
                    # new leader loses to the new leader's more recent last_seen.
                    is_leader=(r["node_id"] == leader_node_id),
                    acquire_delay_seconds=float(r["acquire_delay_seconds"]),
                    promotable=bool(r["promotable"]),
                )
            )
        return members

    async def leadership_lease(self) -> tuple[str | None, float | None]:
        """Read the single ``leader_lease`` row — (owner, DB-clock expiry) — for the observability API
        (Workstream A5). One DB read, off the message hot path; ``(None, None)`` before any lease row
        exists. This is the AUTHORITATIVE lease state (the source of truth for who may process), distinct
        from the ``nodes.is_leader`` heartbeat flag :meth:`cluster_members` derives from."""
        row = await self._pool.fetchrow(
            "SELECT owner, lease_expires_at FROM leader_lease WHERE lease_key = $1",
            self._lease_key,
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
            "cluster coordination is ENABLED ([cluster].enabled); the active-passive HA feature set is "
            "BUILT: leader election (Track B Step 4 — exactly one node holds the leadership lease and "
            "drains the graph; a standby takes over on failover), the leader-gated WRITE singletons "
            "(retention, lease reclaim), leader-gated poll-source intake (Step 4b — only the leader polls "
            "a shared directory / DB table / remote dir), cross-node CONVERGENCE (Step 6 — the leader "
            "materializes each reference set from its source and followers read-through the shared "
            "snapshot; an operator config reload propagates cluster-wide via a version token; Step 6b — "
            "transform-STATE writes bump a per-namespace version token and every node read-throughs newer "
            "namespaces into its own state cache), and the read-only observability API (Step 7 — "
            "/cluster/status + /cluster/nodes). OPERATIONAL ASSUMPTIONS to honor: (a) keep node clocks "
            "reasonably synced (NTP) — the row leases used for failover recovery are wall-clock; (b) run "
            "IDENTICAL config dirs on every node; (c) apply config changes via a COORDINATED (not "
            "rolling) restart. See docs/CLUSTERING.md."
        )

    async def _ensure_nodes_table(self) -> None:
        """Create the ``nodes`` + ``leader_lease`` tables IF NOT EXISTS, serialized across concurrent
        opens by a transaction-scoped advisory lock (auto-released at commit) — the same guard the store
        uses for its own schema DDL, so two nodes opening at once can't race the CREATE. The lock key is
        schema-namespaced (see :attr:`_lock_key`), matching :meth:`PostgresStore._lock_key`, so two
        deployments sharing one database via different schemas don't contend on it."""
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "SELECT pg_advisory_xact_lock($1, hashtext($2))",
                    _LOCK_CLASS_CLUSTER,
                    self._lock_key,
                )
                await conn.execute(
                    "CREATE TABLE IF NOT EXISTS nodes ("
                    " node_id    TEXT PRIMARY KEY,"
                    " host       TEXT,"
                    " pid        INTEGER,"
                    " started_at DOUBLE PRECISION,"
                    " last_seen  DOUBLE PRECISION,"
                    " status     TEXT,"
                    " is_leader  BOOLEAN NOT NULL DEFAULT FALSE,"  # Step 7: derived-leader observability
                    # ADR 0096 leader-preference config, mirrored per-node for the /cluster/nodes API.
                    " acquire_delay_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,"
                    " promotable BOOLEAN NOT NULL DEFAULT TRUE"
                    ")"
                )
                # Idempotent migration for a pre-Step-7 nodes table created without is_leader (a cluster
                # upgraded in place): add the column if it is absent. Still under the DDL advisory lock,
                # so two nodes opening at once can't race it. ADD COLUMN IF NOT EXISTS is a no-op on the
                # fresh CREATE above and on any node that already migrated.
                await conn.execute(
                    "ALTER TABLE nodes ADD COLUMN IF NOT EXISTS is_leader BOOLEAN NOT NULL DEFAULT FALSE"
                )
                # ADR 0096: additively migrate a pre-existing nodes table (cluster upgraded in place) to
                # carry the leader-preference config columns. Same DDL advisory lock; ADD COLUMN IF NOT
                # EXISTS is a no-op on the fresh CREATE above and on any already-migrated node.
                await conn.execute(
                    "ALTER TABLE nodes ADD COLUMN IF NOT EXISTS acquire_delay_seconds "
                    "DOUBLE PRECISION NOT NULL DEFAULT 0"
                )
                await conn.execute(
                    "ALTER TABLE nodes ADD COLUMN IF NOT EXISTS promotable BOOLEAN NOT NULL DEFAULT TRUE"
                )
                # The self-fencing leadership lease (Workstream A2): a single row per cluster (keyed by
                # the schema-namespaced lease_key) holding the current leader + its DB-clock expiry. The
                # leader renews lease_expires_at every heartbeat; a standby acquires only once it has
                # expired. Created under the same DDL lock so concurrent opens can't race it.
                await conn.execute(
                    "CREATE TABLE IF NOT EXISTS leader_lease ("
                    " lease_key        TEXT PRIMARY KEY,"
                    " owner            TEXT,"
                    " lease_expires_at DOUBLE PRECISION NOT NULL,"
                    " leader_epoch     BIGINT NOT NULL DEFAULT 0"  # H1: monotonic fencing token
                    ")"
                )
                # H1 (owner-gated live ALTER): additively add leader_epoch to a pre-existing
                # leader_lease (a cluster upgraded in place). ADD COLUMN IF NOT EXISTS is a no-op on the
                # fresh CREATE above and on any node that already migrated, and runs under the same DDL
                # advisory lock so two nodes opening at once can't race it (REL-1 additive migration).
                # DEFAULT 0 backfills the existing single row, so the first fresh acquire after the
                # upgrade bumps it to 1 — a strictly-increasing epoch from the legacy baseline.
                await conn.execute(
                    "ALTER TABLE leader_lease ADD COLUMN IF NOT EXISTS leader_epoch BIGINT NOT NULL "
                    "DEFAULT 0"
                )

    async def _register(self) -> None:
        """Upsert this node's row as ``active`` (a restart re-activates a prior 'left' tombstone). The
        ``is_leader`` flag is reset to FALSE on both insert and the conflict-update: a freshly
        (re)registered node holds no leadership until it acquires the advisory lock on its first
        maintenance tick (the heartbeat then folds the true value in)."""
        now = time.time()
        # acquire_delay_seconds / promotable are static per-node config (read once at construction), so
        # they are written on register — including a restart's conflict-update, which re-applies any
        # config change — and never touched by the heartbeat (ADR 0096).
        await self._pool.execute(
            "INSERT INTO nodes (node_id, host, pid, started_at, last_seen, status, is_leader,"
            " acquire_delay_seconds, promotable)"
            " VALUES ($1,$2,$3,$4,$5,$6,FALSE,$7,$8)"
            " ON CONFLICT (node_id) DO UPDATE SET"
            " host=excluded.host, pid=excluded.pid, started_at=excluded.started_at,"
            " last_seen=excluded.last_seen, status=excluded.status, is_leader=FALSE,"
            " acquire_delay_seconds=excluded.acquire_delay_seconds, promotable=excluded.promotable",
            self.node_id,
            self._host,
            self._pid,
            now,
            now,
            "active",
            self._acquire_delay,
            self._promotable,
        )

    async def heartbeat_once(self) -> None:
        """Refresh this node's ``last_seen`` (the membership liveness signal Step 4's election reads)
        and fold this node's current leadership into ``is_leader`` for the Step-7 observability API. A
        discrete coroutine (the loop's single beat) so a test can advance the heartbeat deterministically
        without racing the loop's sleep.

        The folded flag rides the EXISTING heartbeat UPDATE — zero extra writes. It lags by at most one
        tick because the loop beats BEFORE :meth:`_maintain_leadership` runs, so a just-acquired/just-lost
        leadership is reflected on the next beat; that one-tick lag is fine for an observability endpoint
        (and a clean :meth:`stop` clears the flag immediately, while a crash leaves it stale for the
        freshness filter in :meth:`cluster_members` to discard)."""
        await self._pool.execute(
            "UPDATE nodes SET last_seen=$1, status=$2, is_leader=$3 WHERE node_id=$4",
            time.time(),
            "active",
            self._is_leader,
            self.node_id,
        )

    async def _heartbeat_loop(self) -> None:
        """The unified per-tick maintenance loop: each ``heartbeat_seconds`` it (1) refreshes
        ``last_seen`` and (2) maintains leadership (acquire when not leader, liveness-check when
        leader). A DB error in either is logged and the loop keeps going (a transient blip mustn't kill
        membership); it exits promptly on stop by waiting on the stop event rather than a bare sleep."""
        while not self._stop.is_set():
            try:
                await self.heartbeat_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A heartbeat miss is recoverable (the leader sweep tolerates a late beat within the
                # node_timeout); log and retry next tick rather than tearing down membership. Include
                # the redacted exception so a persistent failure (pool closed, auth) is diagnosable;
                # the message is bounded by the configured interval.
                log.warning(
                    "cluster: heartbeat failed for node %s; will retry: %s",
                    self.node_id,
                    safe_exc(exc),
                )
            try:
                await self._maintain_leadership()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Lease maintenance is best-effort per tick (e.g. a momentary pool hiccup). We do NOT
                # demote here on a DB error — _last_renew_ok simply isn't advanced, so the fence
                # watchdog demotes us if the failure persists past the fence timeout. Just log + retry.
                log.warning(
                    "cluster: leadership maintenance failed for node %s; will retry: %s",
                    self.node_id,
                    safe_exc(exc),
                )
            try:
                # Track B Step 6: refresh the cached cluster-wide config version so the engine's
                # convergence loop polls it cheaply (config_version_cached) without a DB round-trip. A
                # stale tick just delays a follower's reload by one interval (harmless), so log + retry.
                await self.config_version()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "cluster: config-version refresh failed for node %s; will retry: %s",
                    self.node_id,
                    safe_exc(exc),
                )
            try:
                # Wake immediately on stop() instead of sleeping out the full interval — cooperative
                # cancellation without relying on Task.cancel alone.
                await asyncio.wait_for(self._stop.wait(), timeout=self._heartbeat_seconds)
            except asyncio.TimeoutError:
                continue  # interval elapsed — beat again

    # --- leader election: self-fencing lease (Track B Step 4 / Workstream A2) ----

    async def _maintain_leadership(self) -> None:
        """One tick of leadership maintenance: try to acquire-or-renew the lease, then reconcile the
        cached gate. A single atomic statement either takes a free/expired lease, renews ours, or no-ops
        if another node holds a live lease (see :meth:`_claim_or_renew_lease`).

        On hold: stamp ``_last_renew_ok`` (monotonic) so the fence watchdog knows we are fresh, and
        promote if we weren't already leader. On not-hold: demote if we were leader (someone else holds
        it / our lease expired). A DB error propagates to the loop, which logs and retries — we do NOT
        demote on an error here; ``_last_renew_ok`` simply isn't advanced, so the fence watchdog demotes
        us only if the failure persists past the fence timeout (and always before the lease can expire).
        """
        held = await self._claim_or_renew_lease()
        if held:
            self._last_renew_ok = self._monotonic()
            if not self._is_leader:
                self._is_leader = True
                log.info("cluster: node %s acquired leadership (lease)", self.node_id)
        elif self._is_leader:
            # The lease is held by another node (or expired and taken over) — we are no longer leader.
            self._is_leader = False
            # Drop the held epoch: we are no longer a fenced leader, and the next acquire will read the
            # (now-higher) epoch the successor bumped. Leaving a stale epoch cached would be harmless
            # (the store guard already lost when the graph stopped) but clearing it keeps current_epoch()
            # honest.
            self._leader_epoch = None
            log.info("cluster: node %s lost leadership (lease taken or expired)", self.node_id)

    async def _claim_or_renew_lease(self) -> bool:
        """Atomically acquire OR renew the leadership lease and return whether this node now holds it.

        One statement covers all cases against the DB's own clock (``clock_timestamp()`` — so node
        clock skew never affects who may hold the lease): INSERT the row if absent (we acquire); on
        conflict, UPDATE owner + expiry **only if** we already own it (renew) OR the existing lease has
        expired (take over a dead leader). If another node holds a live lease the WHERE is false, the
        UPDATE no-ops, ``RETURNING`` yields nothing, and we report not-held.

        **H1 fencing token.** The same statement maintains ``leader_epoch`` so the store can fence a
        superseded ex-leader. The epoch is bumped **only on a FRESH acquire** — the INSERT (epoch 1) or a
        take-over of an *expired/foreign* lease (``leader_epoch + 1``) — and **left unchanged on a renew**
        (``owner = me``). So a paused/partitioned ex-leader that comes back keeps its now-stale older
        epoch, while a standby that took over advanced it; the store's claim guard
        (``held >= leader_lease.leader_epoch``) then rejects the ex-leader. ``RETURNING leader_epoch``
        carries the held value back so :meth:`_maintain_leadership` can cache it. (Renew keeps it because
        ``owner = me`` can only be reached when no other node took over in between — a take-over would
        have changed ``owner`` and routed us through the bump branch.)

        **Leader preference (ADR 0096).** A ``promotable=False`` node short-circuits to not-held BEFORE
        touching the DB, so it never inserts, takes over, or renews — it can neither become nor remain
        leader (a node that somehow already holds the lease is demoted by :meth:`_maintain_leadership` on
        this tick; the fence watchdog is the backstop). ``acquire_delay_seconds`` handicaps ONLY the
        take-over-of-an-EXPIRED-lease predicate — the expiry is compared against ``clock_timestamp() -
        delay`` (equivalently ``lease_expires_at + delay < now``) — so a delayed node must wait ``delay``
        seconds PAST the un-handicapped expiry before it may claim, letting a preferred (delay=0) node win
        the routine race. The delay is added to the *expiry* side only, so it is a STRICTLY stricter
        predicate than the base one: it can only make this node claim LATER, never earlier, so it cannot
        open a two-leader window (the split-brain guarantee is preserved). The renew branch
        (``owner = me``) carries NO delay term, so the current leader always renews at ``now`` regardless
        of its own configured delay."""
        if not self._promotable:
            # NON-PROMOTABLE: never acquire (insert / take-over) and never renew, so this node can never
            # become or remain leader. Touch no DB row — returning not-held makes _maintain_leadership
            # demote a node that was somehow already leader (a clean step-down), and the fence watchdog is
            # the backstop. At least one promotable node must exist or the cluster elects no leader.
            return False
        row = await self._pool.fetchrow(
            "INSERT INTO leader_lease (lease_key, owner, lease_expires_at, leader_epoch) "
            "VALUES ($1, $2, EXTRACT(EPOCH FROM clock_timestamp()) + $3, 1) "
            "ON CONFLICT (lease_key) DO UPDATE SET "
            "owner = EXCLUDED.owner, lease_expires_at = EXCLUDED.lease_expires_at, "
            "leader_epoch = CASE WHEN leader_lease.owner = EXCLUDED.owner "
            "THEN leader_lease.leader_epoch ELSE leader_lease.leader_epoch + 1 END "
            "WHERE leader_lease.owner = $2 "
            # Take-over-of-EXPIRED is handicapped by acquire_delay ($4): add the delay to the expiry so a
            # delayed node only claims once the lease has been expired for `delay` seconds (DB clock). The
            # owner=me renew branch above is NOT delayed. delay=0 → byte-identical to `expires_at < now`.
            "OR leader_lease.lease_expires_at + $4 < EXTRACT(EPOCH FROM clock_timestamp()) "
            "RETURNING owner, leader_epoch",
            self._lease_key,
            self.node_id,
            self._lease_ttl,
            self._acquire_delay,
        )
        if row is None or row["owner"] != self.node_id:
            return False
        # Cache the epoch we now hold (fresh-acquire bump or renew's unchanged value). The engine reads it
        # on promotion and pushes it into the store; a renew leaves it identical so no push churn.
        self._leader_epoch = int(row["leader_epoch"])
        return True

    async def _fence_watchdog_loop(self) -> None:
        """Self-fence watchdog (Workstream A2). Wakes every ``_fence_tick`` and, doing **no DB I/O**,
        demotes this node if it has not confirmed a lease hold within ``_fence_timeout`` (monotonic).
        Because it never awaits the pool, a hung/partitioned DB — which would block the maintenance loop
        mid-await — cannot stop it from fencing. ``_fence_timeout < lease_ttl`` guarantees a partitioned
        old leader stops reporting leader BEFORE its lease can expire and a standby acquire it."""
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._fence_tick)
                return  # stop requested
            except asyncio.TimeoutError:
                pass
            self._check_fence()

    def _check_fence(self) -> None:
        """Demote (self-fence) if we are leader but haven't confirmed a lease hold within the fence
        timeout. Pure in-memory; called by the watchdog (and directly by tests)."""
        if not self._is_leader:
            return
        last = self._last_renew_ok
        if last is None:
            return  # leader is only set alongside _last_renew_ok; defensive no-op
        if self._monotonic() - last > self._fence_timeout:
            self._is_leader = False
            # Drop the held epoch on self-fence too: a fenced node must not present a (now-stale) token.
            self._leader_epoch = None
            log.warning(
                "cluster: node %s SELF-FENCED — leadership lease not renewed within %.1fs (fence "
                "timeout); halting leader work before the lease (TTL %.1fs) can expire",
                self.node_id,
                self._fence_timeout,
                self._lease_ttl,
            )

    async def _release_leadership(self) -> None:
        """Best-effort clean release: demote the cached gate first (so a concurrent is_leader() reader
        never sees a stale True), then expire our lease row so a standby can acquire immediately on a
        clean shutdown. Safe to call when never elected (the UPDATE simply matches no owned row)."""
        was_leader = self._is_leader
        self._is_leader = False
        self._last_renew_ok = None
        self._leader_epoch = None  # released: no longer a fenced leader
        if not was_leader:
            return
        try:
            # Expire the lease (set it to the epoch) only if we still own it, so a standby's next
            # acquire tick takes over at once instead of waiting out the full TTL.
            await self._pool.execute(
                "UPDATE leader_lease SET lease_expires_at = 0 WHERE lease_key = $1 AND owner = $2",
                self._lease_key,
                self.node_id,
            )
        except Exception as exc:  # the pool may already be closing on shutdown — log, don't raise
            log.warning(
                "cluster: node %s failed to release the leadership lease (it will expire on its "
                "own): %s",
                self.node_id,
                safe_exc(exc),
            )


def build_coordinator(store: Any, cluster_settings: Any) -> ClusterCoordinator:
    """Pick the coordinator for ``store`` + ``cluster_settings`` — defensively.

    Returns a :class:`NullCoordinator` (the byte-identical single-node default) whenever
    ``cluster_settings`` is ``None`` / not ``enabled``, or the store is not a Postgres-backed store
    (no ``_pool`` to drive a :class:`DbCoordinator`). Only an **enabled** ``[cluster]`` on a Postgres
    store yields a :class:`DbCoordinator`.

    Postgres detection is duck-typed (``getattr(store, "_pool", None)``) so this never hard-imports
    ``asyncpg`` — a SQLite-only install with no extra still imports and runs this fine.
    """
    if cluster_settings is None or not getattr(cluster_settings, "enabled", False):
        return NullCoordinator()
    pool = getattr(store, "_pool", None)
    if pool is None:
        # [cluster].enabled is gated to backend=postgres by ServiceSettings, but stay defensive: a
        # non-Postgres store (or one without a pool) can't run the DB coordinator, so fall back to the
        # safe single-node null rather than crash.
        log.warning(
            "cluster coordination is enabled but the store has no Postgres pool; using the "
            "single-node null coordinator"
        )
        return NullCoordinator()
    # Reuse store._owner as the node-id so the cluster node-id == the row-lease owner-id (Track B
    # Step 2's identity), unless the operator pinned [cluster].node_id (stable identity / tests). That
    # shared id lets Step 4 / failover recovery correlate a node's membership row with the leases it holds.
    node_id = (
        getattr(cluster_settings, "node_id", None)
        or getattr(store, "_owner", None)
        or default_node_id()
    )
    # Reach the store's configured schema (duck-typed) so the coordinator's nodes-DDL advisory lock is
    # namespaced identically to the store's own lock keys. Defaults to 'public' inside DbCoordinator
    # when the store has no _settings (a non-Postgres path never reaches here).
    settings = getattr(store, "_settings", None)
    db_schema = getattr(settings, "db_schema", None)
    # The SQL Server store ALSO exposes a `_pool` (aioodbc), but DbCoordinator drives the asyncpg API, so
    # dispatch a SQL Server store to its own active-passive coordinator instead. Backend is duck-typed off
    # the settings enum's value (no StoreBackend import → no config dependency here); the import is local
    # to avoid a cluster.py <-> cluster_sqlserver.py cycle (cluster_sqlserver imports this module).
    backend = getattr(settings, "backend", None)
    if getattr(backend, "value", backend) == "sqlserver":
        from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator

        return SqlServerCoordinator(
            store,
            node_id,
            heartbeat_seconds=getattr(cluster_settings, "heartbeat_seconds", 10.0),
            node_timeout_seconds=getattr(cluster_settings, "node_timeout_seconds", 30.0),
            leader_lease_ttl_seconds=getattr(cluster_settings, "leader_lease_ttl_seconds", 30.0),
            leader_fence_timeout_seconds=getattr(
                cluster_settings, "leader_fence_timeout_seconds", 20.0
            ),
            acquire_delay_seconds=getattr(cluster_settings, "acquire_delay_seconds", 0.0),
            promotable=getattr(cluster_settings, "promotable", True),
        )
    return DbCoordinator(
        pool,
        node_id,
        heartbeat_seconds=getattr(cluster_settings, "heartbeat_seconds", 10.0),
        node_timeout_seconds=getattr(cluster_settings, "node_timeout_seconds", 30.0),
        leader_lease_ttl_seconds=getattr(cluster_settings, "leader_lease_ttl_seconds", 30.0),
        leader_fence_timeout_seconds=getattr(
            cluster_settings, "leader_fence_timeout_seconds", 20.0
        ),
        acquire_delay_seconds=getattr(cluster_settings, "acquire_delay_seconds", 0.0),
        promotable=getattr(cluster_settings, "promotable", True),
        db_schema=db_schema,
    )
