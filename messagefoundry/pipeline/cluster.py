"""Cluster coordination seam (Track B Steps 3-7).

Horizontal scale-out runs the engine as several nodes against one shared server-DB store. Two
coordination questions arise once there is more than one node: (1) which node runs the **singleton**
tasks that must not double-execute (retention purges, the lease-reclaim sweep — *leader election*,
Step 4), and (2) which node may **claim a given FIFO lane** so per-lane order survives across nodes
(*lane ownership*, Step 5). This module answers both. Single-node operation (SQLite and single-node
Postgres alike) stays byte-identical: :class:`NullCoordinator` reports leader ``True`` and
``lane_owner()`` ``None``, so the claim path takes its unchanged no-owner branch.

The contract is deliberately tiny and the hot-path gates (:meth:`ClusterCoordinator.is_leader` /
:meth:`ClusterCoordinator.owns_lane` / :meth:`ClusterCoordinator.lane_owner`) are **synchronous and
cheap** — they read cached in-memory state / a plain attribute so a per-message gate check adds no
``await``. :class:`NullCoordinator` is the default used everywhere on a single node; :class:`DbCoordinator`
is the Postgres-backed implementation that registers the node in a ``nodes`` table, heartbeats, runs
(Step 4) **real leader election** via a session-level advisory lock so exactly one node reports
``is_leader()`` at a time, and (Step 5) maintains a cached owned-lane set. :func:`build_coordinator`
picks between them defensively — a non-Postgres or not-``[cluster].enabled`` store always gets the
:class:`NullCoordinator`.

**Steps 4 + 4b + 5 add leader election, leader-gated poll-source intake, and per-lane FIFO ownership:**
``is_leader()`` reflects a contended advisory lock, the engine gates its leader-only WRITE singletons
(retention, the lease-reclaim sweep) on it, and the runner threads ``is_leader`` as a plain predicate
into each source so only the leader polls a **shared external resource** (a directory / DB table /
remote dir) — listen sources (MLLP/TCP) ignore it and run on every node. For ordering, the runner
threads :meth:`lane_owner` into each FIFO claim so :meth:`Store.claim_next_fifo` atomically leases the
lane to a single node at claim time — a FIFO lane is processed by exactly one node at a time, so strict
per-lane FIFO holds ACROSS nodes with **zero reorder window** (the claim, not the cached
:meth:`owns_lane` hint, is the authority). Single-node operation stays byte-identical because
:class:`NullCoordinator`'s ``is_leader()`` is always ``True`` and its ``lane_owner()`` is always
``None`` (no lane leasing → the claim takes its unchanged no-owner path).

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

**Step 7 adds the read-only OBSERVABILITY API.** The scale-out feature set is now complete, so the
coordinator no longer hides behind an "experimental" banner. :meth:`cluster_members` returns one
:class:`ClusterMember` per known node (liveness + derived leadership) for the engine's ``/cluster/nodes``
endpoint; ``/cluster/status`` reads the cheap in-memory gates (:meth:`node_id` / :meth:`is_clustered` /
:meth:`is_leader` / :meth:`config_version_cached`). Cluster-wide leadership is derived from a per-node
``is_leader`` flag folded into the existing ``nodes`` heartbeat (one extra column, zero extra writes):
``cluster_members`` reports leader on the **single freshest** node whose flag is set and whose
``last_seen`` is within the node timeout, so a crashed ex-leader's lingering flag is never reported as
the live leader and a failover window (an old leader's flag not yet cleared while a new leader's flag is
already set) can never surface two leaders — the live, still-beating node wins. Leadership itself is a
session advisory lock recorded nowhere else, so the flag is the only durable signal of it.
:class:`NullCoordinator` synthesizes a single self-entry (single node, always leader).

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

# Advisory-lock classid for **leader election** (Track B Step 4). Distinct from every other family
# (1=AUDIT/2=SCHEMA/3=FINALIZE in the store, 4=cluster-nodes above) so its hashtext namespace can't
# collide. Unlike the store's xact-scoped locks, the leader lock is **session-level**: held on a
# dedicated pooled connection for the leader's lifetime and only released when the leader stops or its
# connection drops — that "the lock follows the connection" is precisely what makes a crashed leader's
# lock auto-release server-side so a follower can take over.
_LOCK_CLASS_LEADER = 5


def default_node_id() -> str:
    """This node's stable identity: ``host:pid:hex`` — the same shape as
    :attr:`PostgresStore._owner`, so when the factory reuses ``store._owner`` the cluster node-id and
    the row-lease owner-id are one value (a useful invariant for Steps 4/5)."""
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


@runtime_checkable
class ClusterCoordinator(Protocol):
    """The coordination contract every backend (null today, DB-backed later) implements.

    :attr:`node_id` is this node's stable identity. :meth:`start`/:meth:`stop` own any background
    membership task (idempotent — safe to call twice). :meth:`is_leader` and :meth:`owns_lane` are the
    **cheap, synchronous** gates Steps 4/5 will consult on the hot path — they must read cached state
    and never block or ``await``.
    """

    node_id: str

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def is_leader(self) -> bool:
        """Whether this node runs the leader-only singletons (retention, lease reclaim). Cheap/cached
        — never an ``await`` or a DB round-trip. Always ``True`` until Step 4 builds election."""
        ...

    def owns_lane(self, lane_key: str) -> bool:
        """Whether this node currently holds the FIFO lane ``lane_key`` (a stage:destination/channel
        lease). Cheap/cached. **An eventually-consistent HINT for observability/reporting, NOT the
        correctness gate** — the authoritative single-owner-per-lane enforcement is the claim-time
        atomic lease acquire in :meth:`Store.claim_next_fifo` (Track B Step 5, Deliverable 2). On
        :class:`DbCoordinator` it reflects a per-tick cache refresh; ``True`` everywhere on
        :class:`NullCoordinator` (single-node owns every lane)."""
        ...

    def lane_owner(self) -> str | None:
        """The owner identity to gate a FIFO claim by (Track B Step 5): this node's ``node_id`` when
        clustered (so :meth:`Store.claim_next_fifo` atomically leases the lane to this node), or
        ``None`` single-node (no lane leasing → the byte-identical claim path). The runner threads this
        into every FIFO claim. Cheap/synchronous — a plain attribute read, no DB."""
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

    def owns_lane(self, lane_key: str) -> bool:
        # Single-node owns every lane (and there are no lane leases). Byte-identical to before.
        return True

    def lane_owner(self) -> str | None:
        # Single-node: no lane leasing — claim_next_fifo runs its byte-identical no-owner path.
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


# One-time-per-process info guard: the scale-out feature set is COMPLETE — election (Step 4),
# leader-gated WRITE singletons, leader-gated poll-source intake (Step 4b), per-lane FIFO ownership
# (Step 5), cross-node convergence (Step 6 — leader-materialized reference sets read-through by
# followers + a config-reload version token; Step 6b — transform-STATE writes read-through by followers
# via a per-namespace version token), and the read-only observability API (Step 7 — /cluster/status +
# /cluster/nodes). So a cluster no longer double-runs singletons, double-ingests a shared poll source,
# interleaves a FIFO lane across nodes, or leaves followers on stale reference/config/state, and an
# operator can now SEE membership + leadership. The banner is therefore a one-time INFO (not a WARNING)
# that states the feature set is built and summarizes the operational assumptions operators must honor.
# Logged once so the log isn't spammed when several stores/coordinators open in one process (e.g. tests).
_logged_cluster_enabled = False


class DbCoordinator:
    """Postgres-backed cluster membership + **leader election** (Track B Steps 3-7).

    On :meth:`start` it idempotently creates a ``nodes`` table, upserts this node's row, and spawns a
    cooperatively-cancellable maintenance task that each tick (a) refreshes ``last_seen`` and (b)
    maintains leadership via a **session-level** advisory lock held on a dedicated pooled connection.
    Exactly one node across the cluster holds that lock, so exactly one reports :meth:`is_leader`
    ``True``; if the leader stops or its connection drops, the lock is released and a follower acquires
    it on its next tick. :meth:`stop` releases leadership, cancels the loop, and marks this node left.

    Lane ownership (Track B Step 5) IS built: :meth:`lane_owner` returns this node's identity, the
    runner threads it into each FIFO claim, and :meth:`Store.claim_next_fifo` atomically leases the
    lane to a single node at claim time — so cross-node per-lane FIFO order is preserved with zero
    reorder window. :meth:`owns_lane` is the eventually-consistent observability hint over a per-tick
    cache of the lanes this node holds (NOT the correctness gate — the claim is). Leader-gated
    poll-source intake (Step 4b) IS built: the runner threads :meth:`is_leader` into each source as a
    plain predicate and the poll sources skip their scan on a follower, so a shared directory / DB table
    / remote dir is ingested by exactly one node. Cross-node CONVERGENCE (Steps 6 + 6b) IS built:
    :meth:`is_clustered` gates the engine's config-convergence loop, :meth:`config_version` /
    :meth:`config_version_cached` / :meth:`bump_config_version` carry the ``cluster_config`` version token so
    an operator reload on one node propagates cluster-wide, and transform-STATE writes bump a per-namespace
    ``state_version`` token that every node's ``StateConvergenceRunner`` read-throughs into its own cache. The
    read-only OBSERVABILITY API (Step 7) IS built: a per-node ``is_leader`` flag is folded into the
    ``nodes`` heartbeat (one column, zero extra writes) and :meth:`cluster_members` reads the table and
    derives the **single live** leader (the freshest fresh-flagged node) for the engine's
    ``/cluster/nodes`` endpoint — so the scale-out feature set is complete and a one-time INFO (not a
    warning) records the operational assumptions operators must honor.

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
        db_schema: str | None = None,
    ) -> None:
        self._pool = pool
        self.node_id = node_id
        self._heartbeat_seconds = heartbeat_seconds
        # A node is considered dead when its last_seen is older than this. Consulted by
        # cluster_members() (Step 7) as the freshness filter that discards a crashed ex-leader's stale
        # is_leader flag (and bounds the failover-overlap window). It is NOT what transfers leadership —
        # the session-level advisory lock is (a crashed leader's lock auto-releases server-side); lowering
        # this shrinks the window in which a just-beaten node can still count toward the derived leader,
        # raising it lets a just-crashed ex-leader's row stay "fresh" (and thus a leader candidate) longer.
        self._node_timeout_seconds = node_timeout_seconds
        # Namespace the nodes-DDL advisory lock by schema, exactly as PostgresStore._lock_key does:
        # advisory locks are database-scoped (not schema-scoped), so two deployments sharing one
        # database via different db_schema values must not contend on this lock. The nodes table
        # itself lands in the right schema via the pool's search_path; the lock key must match.
        self._lock_key = f"{db_schema or 'public'}:mefor_cluster_nodes"
        # A DISTINCT key for the leader lock so leadership contention never collides with the nodes-DDL
        # lock (different classid too). Schema-namespaced for the same reason: two deployments sharing a
        # database via different schemas must elect leaders independently.
        self._leader_lock_key = f"{db_schema or 'public'}:mefor_cluster_leader"
        self._host = socket.gethostname()
        self._pid = os.getpid()
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        # Cached leadership state read by the cheap/synchronous is_leader() gate (no DB round-trip on
        # the hot path). Maintained only by the single maintenance task.
        self._is_leader: bool = False
        # Cached set of FIFO lanes this node currently holds, read by the cheap/synchronous owns_lane()
        # HINT (Track B Step 5). Refreshed once per maintenance tick from lane_leases; it is NOT the
        # correctness gate (the claim-time atomic lease acquire in claim_next_fifo is) — just an
        # eventually-consistent observability signal, so a tick of staleness is harmless.
        self._owned_lanes: set[str] = set()
        # The dedicated pooled connection the SESSION-LEVEL leader lock lives on. A session lock is
        # bound to its connection, so the lock must be held on one connection kept out of the store's
        # pool rotation for the leader's lifetime (hence the pool_size >= 2 requirement). Duck-typed
        # ``Any`` (like the pool); ``None`` until the maintenance task acquires it (and after stop / on a
        # connection error). Compared against None at every use, so the invariant "_is_leader ⇒ conn set"
        # need not be expressed in the type.
        self._leader_conn: Any = None
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

    async def stop(self) -> None:
        """Release leadership, cancel the maintenance loop, and mark this node left. Idempotent and
        safe even if :meth:`start` raised before the task/connection existed (then there's nothing to
        tear down). Ordered so the loop is stopped BEFORE the leader connection is released, so the
        loop can't touch a connection that's been handed back to the pool (no use-after-release)."""
        self._stop.set()
        task = self._heartbeat_task
        self._heartbeat_task = None
        if task is not None:
            task.cancel()
            # Absorb the cancellation (and any error the loop stored) so stop() never raises.
            await asyncio.gather(task, return_exceptions=True)
        # Drop leadership and hand the dedicated connection back. Demote the cached gate FIRST so any
        # concurrent is_leader() reader sees "not leader" the instant we begin releasing. Releasing the
        # advisory lock is best-effort: closing/returning the connection releases a session lock
        # server-side anyway, so a failed unlock is harmless.
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
        # Cheap + synchronous: read the cached state the maintenance loop maintains (no DB round-trip
        # on the hot path). True only while this node holds the session-level leader advisory lock.
        return self._is_leader

    def owns_lane(self, lane_key: str) -> bool:
        # Cheap + synchronous set membership on the per-tick lane-lease cache (no DB on the call). This
        # is an eventually-consistent HINT for observability — the AUTHORITATIVE single-owner-per-lane
        # enforcement is the claim-time atomic lease acquire in claim_next_fifo (Track B Step 5).
        return lane_key in self._owned_lanes

    def lane_owner(self) -> str | None:
        # Clustered: gate FIFO claims by this node's identity so claim_next_fifo atomically leases the
        # lane to us (one node per lane → strict FIFO across nodes). Cheap + synchronous attribute read.
        return self.node_id

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
            "SELECT node_id, host, pid, started_at, last_seen, status, is_leader "
            "FROM nodes ORDER BY node_id"
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
                )
            )
        return members

    # --- internals -----------------------------------------------------------

    def _log_cluster_enabled_once(self) -> None:
        global _logged_cluster_enabled
        if _logged_cluster_enabled:
            return
        _logged_cluster_enabled = True
        log.info(
            "cluster coordination is ENABLED ([cluster].enabled); the scale-out feature set is BUILT: "
            "leader election (Track B Step 4), the leader-gated WRITE singletons (retention, lease "
            "reclaim), leader-gated poll-source intake (Step 4b — only the leader polls a shared "
            "directory / DB table / remote dir), per-lane FIFO ownership (Step 5 — a FIFO lane is "
            "claimed by exactly one node at a time via an atomic claim-time lane lease, so cross-node "
            "per-lane FIFO ORDER is PRESERVED), cross-node CONVERGENCE (Step 6 — the leader materializes "
            "each reference set from its source and followers read-through the shared snapshot; an "
            "operator config reload propagates cluster-wide via a version token; Step 6b — transform-"
            "STATE writes bump a per-namespace version token and every node read-throughs newer "
            "namespaces into its own state cache), and the read-only observability API (Step 7 — "
            "/cluster/status + /cluster/nodes). OPERATIONAL ASSUMPTIONS to honor: (a) keep node clocks "
            "reasonably synced (NTP) — lane/row leases are wall-clock; (b) run IDENTICAL config dirs on "
            "every node; (c) apply config changes via a COORDINATED (not rolling) restart. See "
            "docs/CLUSTERING.md."
        )

    async def _ensure_nodes_table(self) -> None:
        """Create the ``nodes`` table IF NOT EXISTS, serialized across concurrent opens by a
        transaction-scoped advisory lock (auto-released at commit) — the same guard the store uses for
        its own schema DDL, so two nodes opening at once can't race the CREATE. The lock key is
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
                    " is_leader  BOOLEAN NOT NULL DEFAULT FALSE"  # Step 7: derived-leader observability
                    ")"
                )
                # Idempotent migration for a pre-Step-7 nodes table created without is_leader (a cluster
                # upgraded in place): add the column if it is absent. Still under the DDL advisory lock,
                # so two nodes opening at once can't race it. ADD COLUMN IF NOT EXISTS is a no-op on the
                # fresh CREATE above and on any node that already migrated.
                await conn.execute(
                    "ALTER TABLE nodes ADD COLUMN IF NOT EXISTS is_leader BOOLEAN NOT NULL DEFAULT FALSE"
                )

    async def _register(self) -> None:
        """Upsert this node's row as ``active`` (a restart re-activates a prior 'left' tombstone). The
        ``is_leader`` flag is reset to FALSE on both insert and the conflict-update: a freshly
        (re)registered node holds no leadership until it acquires the advisory lock on its first
        maintenance tick (the heartbeat then folds the true value in)."""
        now = time.time()
        await self._pool.execute(
            "INSERT INTO nodes (node_id, host, pid, started_at, last_seen, status, is_leader)"
            " VALUES ($1,$2,$3,$4,$5,$6,FALSE)"
            " ON CONFLICT (node_id) DO UPDATE SET"
            " host=excluded.host, pid=excluded.pid, started_at=excluded.started_at,"
            " last_seen=excluded.last_seen, status=excluded.status, is_leader=FALSE",
            self.node_id,
            self._host,
            self._pid,
            now,
            now,
            "active",
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
                # Election maintenance is best-effort per tick (e.g. a momentary pool hiccup acquiring
                # the dedicated connection); _maintain_leadership already demotes + drops a bad
                # connection on a connection error, so just log and retry next tick.
                log.warning(
                    "cluster: leadership maintenance failed for node %s; will retry: %s",
                    self.node_id,
                    safe_exc(exc),
                )
            try:
                await self._refresh_owned_lanes()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # The owned-lane cache feeds the owns_lane() HINT only (not the correctness gate, which
                # is the claim-time atomic lease) — a stale tick is harmless, so log and retry.
                log.warning(
                    "cluster: owned-lane refresh failed for node %s; will retry: %s",
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

    # --- lane-ownership cache (Track B Step 5) -------------------------------

    async def _refresh_owned_lanes(self) -> None:
        """Refresh the cached set of lanes this node currently holds (unexpired), read by owns_lane().
        Once per maintenance tick (bounded, off the message hot path). This is the eventually-consistent
        observability HINT only — the AUTHORITATIVE single-owner-per-lane enforcement is the claim-time
        atomic lane-lease acquire in :meth:`PostgresStore.claim_next_fifo`."""
        rows = await self._pool.fetch(
            "SELECT lane FROM lane_leases WHERE owner=$1 AND lease_expires_at > $2",
            self.node_id,
            time.time(),
        )
        self._owned_lanes = {r["lane"] for r in rows}

    # --- leader election (Track B Step 4) ------------------------------------

    async def _maintain_leadership(self) -> None:
        """One tick of leadership maintenance on the dedicated session connection.

        Not leader: acquire a fresh dedicated connection if needed, then try the session-level advisory
        lock **exactly once** (advisory locks are re-entrant/counted, so we must not re-try while held —
        that would stack the lock count and a single unlock wouldn't release it). On success, cache
        leader = True.

        Already leader: do a cheap liveness ping on the dedicated connection. A dropped connection
        releases the session lock server-side, so a failed ping means we've silently lost leadership —
        demote, drop the bad connection, and re-acquire a fresh one next tick.
        """
        if not self._is_leader:
            if self._leader_conn is None:
                self._leader_conn = await self._pool.acquire()
            try:
                got = await self._leader_conn.fetchval(
                    "SELECT pg_try_advisory_lock($1, hashtext($2))",
                    _LOCK_CLASS_LEADER,
                    self._leader_lock_key,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                # The try-lock failed (e.g. a stale/broken connection). Drop it so the next tick
                # re-acquires a fresh one rather than retrying forever on a dead connection; re-raise so
                # the loop logs it once via safe_exc.
                await self._drop_leader_conn()
                raise
            if got:
                self._is_leader = True
                log.info("cluster: node %s acquired leadership", self.node_id)
            return
        # Already leader — verify the dedicated connection (and thus the session lock) is still live.
        try:
            await self._leader_conn.execute("SELECT 1")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # The connection (and the session lock it carried) is gone — we are no longer leader.
            # Demote, drop the bad connection so the pool can discard it, and let the next tick
            # re-acquire a fresh connection and contend for the lock again.
            self._is_leader = False
            log.warning(
                "cluster: node %s lost its leader connection; demoting: %s",
                self.node_id,
                safe_exc(exc),
            )
            await self._drop_leader_conn()

    async def _release_leadership(self) -> None:
        """Best-effort: demote, release the advisory lock, and return the dedicated connection. Demotes
        the cached gate first so a concurrent is_leader() reader never sees a stale True while we tear
        down. Safe to call when never elected (no connection → nothing to do)."""
        was_leader = self._is_leader
        self._is_leader = False
        conn = self._leader_conn
        if conn is None:
            return
        if was_leader:
            try:
                await conn.execute(
                    "SELECT pg_advisory_unlock($1, hashtext($2))",
                    _LOCK_CLASS_LEADER,
                    self._leader_lock_key,
                )
            except Exception as exc:
                # Returning/closing the connection releases the session lock server-side regardless, so
                # a failed explicit unlock is harmless — log and continue to the release below.
                log.warning(
                    "cluster: node %s failed to release the leader lock (it releases on connection "
                    "return anyway): %s",
                    self.node_id,
                    safe_exc(exc),
                )
        await self._drop_leader_conn()

    async def _drop_leader_conn(self) -> None:
        """Return the dedicated leader connection to the pool (best-effort) and forget it."""
        conn = self._leader_conn
        self._leader_conn = None
        if conn is None:
            return
        try:
            await self._pool.release(conn)
        except Exception as exc:  # the pool may already be closing on shutdown — log, don't raise
            log.warning(
                "cluster: node %s failed to release its leader connection: %s",
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
    # shared id lets Steps 4/5 correlate a node's membership row with the leases it holds.
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
    return DbCoordinator(
        pool,
        node_id,
        heartbeat_seconds=getattr(cluster_settings, "heartbeat_seconds", 10.0),
        node_timeout_seconds=getattr(cluster_settings, "node_timeout_seconds", 30.0),
        db_schema=db_schema,
    )
