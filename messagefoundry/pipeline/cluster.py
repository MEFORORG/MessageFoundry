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
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.redaction import safe_exc

log = logging.getLogger(__name__)

__all__ = [
    "ClusterCoordinator",
    "ClusterMember",
    "NullCoordinator",
    "DbCoordinator",
    "StepdownUnavailable",
    "StepdownLockTimeout",
    "StepdownReleaseUnconfirmed",
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
    heartbeat flag is set AND is fresh (``last_seen`` within ``node_timeout_seconds``). At most one
    leader is reported; that it is the *live* one holds only while node clocks agree (see
    :func:`members_from_node_rows`). ``last_seen``/``started_at`` are epoch seconds, ``None`` only
    on the :class:`NullCoordinator` synthetic self-entry (no DB)."""

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
    # Whether ``last_seen`` passed :func:`heartbeat_is_fresh` at the read: the same test the derived
    # ``is_leader`` ANDs with the flag, published so "is this sibling alive" reuses it rather than
    # picking a second window (BACKLOG #1509). Defaults to False so a coordinator that never sets it
    # makes the stepdown refuse rather than count a node it did not check. The single-node self-entry
    # leaves it False: no heartbeat was read, and the stepdown refuses that deployment earlier.
    fresh: bool = False


def heartbeat_is_fresh(last_seen: float | None, now: float, node_timeout_seconds: float) -> bool:
    """Whether a ``nodes`` row heartbeated within ``node_timeout_seconds`` of ``now``.

    The one freshness rule. It decides the derived leader and, since BACKLOG #1509, whether a stepdown
    is refused, so it is applied in one place, :func:`members_from_node_rows`, which both DB
    coordinators call. Upper bound only, so a row stamped by a fast clock stays fresh for longer;
    that function's docstring spells out what that costs."""
    return last_seen is not None and (now - last_seen) <= node_timeout_seconds


def members_from_node_rows(
    rows: Sequence[Any], now: float, node_timeout_seconds: float
) -> list[ClusterMember]:
    """Turn ``nodes`` rows into :class:`ClusterMember` entries, for both DB coordinators.

    Shared for the reason :func:`stepdown_pause_seconds` is: the freshness verdict, the derived-leader
    pick that reads it and the published ``fresh`` field have to change together, and a per-class copy
    is two files that can drift apart with nothing failing. The coordinators differ only in how they
    run the SELECT that fetches ``rows``. ``pid`` and the two flags are coerced, which changes
    nothing on Postgres.

    Leadership is DERIVED so that **at most one** node is ever reported as leader, and it is always a
    *live* one:

    * A freshness filter (``last_seen`` within ``node_timeout_seconds``) discards a fully-stale
      crashed ex-leader's lingering ``is_leader=true`` flag outright.
    * Among the rows that still carry ``is_leader=true`` AND are fresh, only the **single freshest**
      (largest ``last_seen``) is reported as leader. During a failover window two rows can briefly
      both be fresh-and-flagged — the crashed ex-leader whose ``last_seen`` is frozen at the crash
      instant, and the newly-promoted leader whose ``last_seen`` keeps advancing. Picking the
      freshest collapses that overlap to a single reported leader.

    **This is a cross-node WALL-CLOCK comparison, and it is one-sided.** ``last_seen`` is stamped by
    the beating node's ``time.time()`` and compared against the *reading* node's ``time.time()`` with
    an upper bound only — there is no ``now - last_seen >= 0`` guard — so a row stamped by a node
    whose clock runs ahead has a NEGATIVE age, trivially passes the freshness test, and (being the
    largest ``last_seen``) wins the pick. A fast-clocked node therefore wins the derived-leader pick
    for as long as it is alive, and keeps winning after it hard-crashes until the live successor's
    advancing ``last_seen`` overtakes the frozen stamp (~the skew), while its row stays *eligible*
    for skew + ``node_timeout_seconds``.

    Two consequences a reader must not be surprised by. The derived ``is_leader`` can name a DEAD
    node as leader while the sibling ``lease_owner`` on the same ``/cluster/nodes`` response
    correctly names the live one — the lease, not this field, is authoritative for who processes.
    And because the web console raises engine health to ``down``/"cluster has no leader" only when
    the derived ``leader_node_id`` is ``None``, a skew-frozen row keeps that non-``None`` and can
    mask a genuinely leaderless cluster for that same interval. Do not gate operational decisions on
    the derived leader; gate them on the lease."""
    fresh = {
        r["node_id"]: heartbeat_is_fresh(r["last_seen"], now, node_timeout_seconds) for r in rows
    }
    leader_node_id: str | None = None
    leader_last_seen: float = -1.0
    for r in rows:
        if bool(r["is_leader"]) and fresh[r["node_id"]] and r["last_seen"] > leader_last_seen:
            leader_last_seen = r["last_seen"]
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
            acquire_delay_seconds=float(r["acquire_delay_seconds"]),
            promotable=bool(r["promotable"]),
            fresh=fresh[r["node_id"]],
        )
        for r in rows
    ]


def has_promotable_sibling(members: Iterable[ClusterMember], node_id: str) -> bool:
    """Whether some node other than ``node_id`` could take the lease if ``node_id`` stepped down.

    The check behind the stepdown's no-promotable-sibling refusal (BACKLOG #1509), and the value its
    ``new_leader_eligible`` reports. A member counts when it is another node, ``active`` (not a
    clean-shutdown ``left`` tombstone), ``promotable`` (ADR 0096) and ``fresh``. No window is chosen
    here: ``fresh`` is the rule :meth:`ClusterCoordinator.cluster_members` already applied.

    **A point-in-time read, not a promise.** A sibling that dies after the read still counted, and
    ``acquire_delay_seconds`` is not weighed, so a sibling handicapped past the stepdown pause counts
    too and the drained node can win its own lease back (BACKLOG #1507)."""
    return any(
        m.node_id != node_id and m.status == "active" and m.promotable and m.fresh for m in members
    )


_DEMOTE_BUDGET_FRACTION = 0.5
_DEMOTE_BUDGET_FLOOR = 1.0
_DEMOTE_BUDGET_CEILING = 10.0


class StepdownUnavailable(RuntimeError):
    """Base class for the two ENVIRONMENT conditions that stop a planned failover (ADR 0056 slice 1).
    Both are mapped to ``503`` by ``POST /cluster/stepdown``, the status the ADR's contract and the
    neighbouring DR endpoints already give environment conditions.

    **Never raised directly — raise one of the two subclasses.** They differ in what the operator may
    conclude, and an earlier build lost that difference by mapping both to one message and one audit
    reason. :class:`StepdownLockTimeout` fires BEFORE anything is attempted, on whatever node was
    addressed, leader or not. :class:`StepdownReleaseUnconfirmed` fires only AFTER this node has
    demoted itself, and only about a write whose fate it cannot see. A sentence true of one is false
    of the other, so this class carries no operator-facing wording of its own.

    **Why either exists rather than a best-effort success.** The release write is best-effort on
    :meth:`stop`, where the node is leaving anyway and a lease that ages out costs nothing. It is not
    best-effort on a stepdown, where an operator reads the answer and then starts maintenance.
    """


class StepdownLockTimeout(StepdownUnavailable):
    """A stepdown could not take the coordinator's ``_leadership_lock`` inside the fence timeout, so
    **nothing ran**: no lease row was read or written, and no in-memory state changed.

    **Says nothing about who leads.** The endpoint takes no ``is_leader()`` pre-read, so this can fire
    on a node that never held leadership — a caller who addressed the wrong node, on a box whose lock
    happens to be busy. Any wording here that asserts "it is still the leader" would be a guess.

    **Do not name the holder either.** The lock is taken in exactly two places, ``_maintain_leadership``
    and :meth:`ClusterCoordinator.step_down_leadership`, so a concurrent stepdown holds it as readily
    as a maintenance tick does. What is known is the lock and the bound, and that is what this says.
    """


class StepdownReleaseUnconfirmed(StepdownUnavailable):
    """A stepdown demoted this node, then could not confirm that the write expiring its lease row
    landed. **The outcome is genuinely unknown**: a lost response to a committed ``UPDATE`` is
    indistinguishable here from an ``UPDATE`` that never ran.

    **So the wording is conditional, and that is the whole point of the class.** On the did-not-commit
    branch this node still owns a live lease no standby can take, and it renews itself back in when the
    claim pause ends. On the committed-but-lost-response branch the lease is already expired and a
    sibling is promoting while the operator reads the refusal. Telling the operator "it is still the
    leader" is right in one branch and wrong in the other, and the wrong branch sends them to fix a
    cluster that is already failing over correctly.

    **A row count cannot settle it, which is why one is not read.** The driver reports rows affected
    only on the path where it returns at all, and this class exists precisely for the path where it
    raised instead. On the returning path both outcomes — the row expired, or no row matched because
    the lease is not ours — leave no live lease owned by this node, so neither is a refusal.

    The in-memory demotion, the demote edge and the claim pause are already done by the time this
    raises: they are the conservative direction on both branches. What the caller must NOT conclude is
    that leadership definitely did, or definitely did not, move.
    """


async def acquire_leadership_lock(
    lock: asyncio.Lock, fence_timeout_seconds: float, node_id: str
) -> None:
    """Take a coordinator's ``_leadership_lock`` for a stepdown, or raise :class:`StepdownLockTimeout`.

    Module-level and shared by both coordinators for the reason :func:`stepdown_pause_seconds` is: the
    BOUND is a safety-relevant timing policy, and a per-class copy is two files that can be retuned
    independently with nothing failing.

    The bound is ``leader_fence_timeout_seconds``, derived rather than picked. That is exactly the
    interval after which the node's own watchdog concludes its DB access is not working and demotes on
    the node-local clock, so a stepdown still queued past it is racing a self-fence and can no longer
    report a drain the operator can act on. Refusing leaves leadership exactly as it was found.

    Not an ``async with``: the acquire has to be wrapped in :func:`asyncio.wait_for` and the caller holds
    the lock across work this function does not see, so it releases in its own ``finally``.
    """
    try:
        await asyncio.wait_for(lock.acquire(), timeout=fence_timeout_seconds)
    except TimeoutError:
        # Name the LOCK and the bound, and stop there. Both coordinators take this lock in
        # _maintain_leadership and in step_down_leadership, so the holder is not knowably a maintenance
        # tick; and the caller may have addressed a node that leads nothing, so leadership is not
        # knowably "unchanged for the leader". Both of those were asserted here and neither was earned.
        raise StepdownLockTimeout(
            f"node {node_id}: this coordinator's leadership lock was still held after the "
            f"{fence_timeout_seconds:.1f}s fence timeout, so the stepdown never ran — nothing was "
            "read, written or demoted"
        ) from None


def lease_release_unconfirmed(node_id: str) -> str:
    """The message for a stepdown whose lease-row write did not return. Shared for the reason above:
    both coordinators run the same owner-scoped expiring ``UPDATE`` and owe the operator the same
    sentence.

    Conditional on purpose — see :class:`StepdownReleaseUnconfirmed`. The node demoted itself either
    way; what nobody here can see is whether the write committed."""
    return (
        f"node {node_id}: this node demoted itself, then the write expiring its leadership lease row "
        "did not return, so whether it committed is unknown — if it did not, this node still owns a "
        "live lease no standby can take; if it did, a standby is already promoting"
    )


def fence_tick_seconds(fence_timeout_seconds: float) -> float:
    """The self-fence watchdog tick. Shared by both coordinators AND by the demotion budget below, so
    the budget and the watchdog it is derived from cannot drift apart."""
    return max(0.05, min(1.0, fence_timeout_seconds / 5.0))


def stepdown_pause_seconds(heartbeat_seconds: float) -> float:
    """How long a node declines to claim after a VOLUNTARY stepdown (ADR 0056 slice 1).

    Module-level, and shared by both coordinators, for the reason :func:`fence_tick_seconds` is: it is
    pure arithmetic on a constructor argument with no backend in it, and a per-class copy is a
    safety-relevant timing constant that two files can retune independently with nothing failing.

    Two heartbeats, and read that as a floor rather than a guarantee. A sibling's acquire runs once per
    ``heartbeat_seconds`` at an unrelated phase, so a full interval can elapse before it even looks at
    the expired lease and a second gives it one whole interval in which to look. **That holds only for
    a sibling carrying no ADR 0096 ``acquire_delay_seconds``.** A sibling handicapped by more than this
    pause is still refused when the pause ends, and the drained node then wins its own lease back. This
    function reads ``heartbeat_seconds`` alone, so it cannot see the handicap it is being compared
    against; the gap is real, unfixed, and recorded on the stepdown's backlog item.

    **This pause covers the ticks that come AFTER the release. It does not order the release against a
    tick already in flight** — :attr:`DbCoordinator._leadership_lock` does that, and the two are not
    interchangeable. Reading a bounded pause as if it were mutual exclusion is exactly what left the
    two-leader window this pause was once credited with closing.

    Deliberately short rather than lease-length: the cost of the pause is that a cluster with no other
    promotable node is leaderless for it, which is the operator's own request but should not linger.
    """
    return 2.0 * heartbeat_seconds


def demote_stop_budget(
    *, lease_ttl_seconds: float, fence_timeout_seconds: float
) -> tuple[float, float]:
    """``(budget, raw_headroom)`` for a bounded demotion teardown (ADR 0157 C6).

    A STATIC duration cap on two phases — NOT a lease-anchored absolute deadline: it reads no DB clock,
    compares against no ``lease_expires_at``, makes the Windows monotonic clock load-bearing for
    nothing, and cannot degrade to zero.

    The renew round trip is NOT subtracted, because it is not observable here. It is bounded only by
    ``[store].command_timeout`` (30.0 by default) — which equals the stock lease TTL — so until that is
    clamped separately the real margin can be zero and this budget is nominal rather than guaranteed.
    Say that plainly rather than implying the budget is met.
    """
    headroom = lease_ttl_seconds - fence_timeout_seconds - fence_tick_seconds(fence_timeout_seconds)
    return (
        max(_DEMOTE_BUDGET_FLOOR, min(_DEMOTE_BUDGET_CEILING, _DEMOTE_BUDGET_FRACTION * headroom)),
        headroom,
    )


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
        transaction so a paused/superseded ex-leader **claims 0 rows** (Kleppmann fencing token; store ↔
        coordinator import direction is one-way — the engine pushes, the store never
        imports the coordinator, ARCH-6). Cheap + synchronous (cached state). :class:`NullCoordinator`
        returns ``None`` — single-node is unfenced (there is no second writer to fence).

        **Scope of the fence — read this before relying on it. It differs BY BACKEND (ADR 0157).**

        On **Postgres**: every claim path is guarded fail-CLOSED (an unvalidatable claim declines, which
        is free — the row stays PENDING), and every TERMINAL resolve is guarded fail-OPEN with a re-pend
        fallback (a rejected resolve rolls the whole disposition back and returns the row to PENDING, so
        the residue is a duplicate rather than a strand). Deliberately UNGUARDED there: writes that
        return a row to PENDING (``release_claimed`` / ``reschedule_claimed`` — fencing those would turn
        a permitted duplicate into a forbidden strand), the cross-owner stranded-lease reclaim that runs
        as the first statement of the same claim transaction, the bring-up dead-letter sweeps, and the
        operator paths.

        On **SQL Server**: only the three FIFO claim paths carry the guard. ``claim_ready`` and every
        terminal resolve are still unfenced there (ADR 0157 Inc 3 closes that), so a demoted SQL Server
        node stops claiming FIFO lanes but can still drain an UNORDERED lane and still write over a row
        the live leader has resolved.

        The residual case that passes on **both** backends: promote → demote → re-promote *in the same
        process*. ``leader_epoch`` bumps only on a fresh acquire, so the re-promoted node's held epoch
        equals the current one and every guard passes. Only a per-claim token would close that.

        Do not read this token as a general write fence."""
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

    async def step_down_leadership(self) -> tuple[bool, float | None]:
        """Voluntarily release this node's leadership lease and **keep running** as a standby — the
        planned-failover / maintenance-drain control plane behind ``POST /cluster/stepdown``
        (ADR 0056, slice 1).

        Returns ``(was_leader, released_at)``: whether this node actually held leadership at the moment
        the release ran, and the epoch-seconds instant it was demoted (``None`` when it held none). **The
        caller audits this return value, never a prior** :meth:`is_leader` **read** — a fence or a
        lost-lease tick can flip leadership between the read and the release, and auditing the pre-read
        would record ``was_leader=true`` for an action that released nothing.

        This is a **visibility lift** of the release the coordinators already run on a clean
        :meth:`stop`, not a new election mechanism: the lease, the self-fence and the epoch token are
        unchanged. The one difference from :meth:`stop` is that the node stays up and keeps
        heartbeating, so it reports itself a standby rather than leaving. :class:`NullCoordinator`
        returns ``(False, None)`` — single-node has no lease to release (and the endpoint refuses a
        single-node caller before reaching here).

        **Raises one of two** :class:`StepdownUnavailable` **subclasses**, which say different things:
        :class:`StepdownLockTimeout` when the coordinator's leadership lock was still held at the fence
        timeout, so nothing ran at all; :class:`StepdownReleaseUnconfirmed` when this node demoted
        itself but the write expiring its lease row did not return. The DB coordinators raise them;
        :class:`NullCoordinator` never does.

        **A returned tuple does NOT mean a release wrote to the lease row**, and an earlier version of
        this line said it did. ``(False, None)`` is the ordinary answer from a node that holds no
        leadership and owes no write — nothing is sent to the DB, and :class:`NullCoordinator` returns
        it with no DB at all. What a returned tuple does mean is that nothing is left unresolved:
        either a write ran and returned, or there was none to run.

        **A retry re-attempts a write left unconfirmed**, so re-calling this is the remedy for
        :class:`StepdownReleaseUnconfirmed`. The DB coordinators remember that a release is owed, and
        the next stepdown re-sends the owner-scoped ``UPDATE`` even though the in-memory gate already
        reads False — without that, the retry took an early return, sent nothing, and answered
        ``(False, None)`` while the lease row was still live and still owned by this node.
        """
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

    async def step_down_leadership(self) -> tuple[bool, float | None]:
        # Single-node: there is no lease to release and no standby to promote, so this releases
        # nothing and reports so. Unreachable through the API — POST /cluster/stepdown refuses a
        # single-node caller with 400 before it touches the coordinator (ADR 0056) — but a truthful
        # answer here keeps the Protocol honest for any direct caller.
        return (False, None)


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
        alert_sink: AlertSink | None = None,
    ) -> None:
        self._pool = pool
        self.node_id = node_id
        # #145: emit an alert on every leadership transition (acquire / lose / self-fence / release) so a
        # failover is never silent. None → the default LoggingAlertSink (logs the transition). Threaded in
        # lockstep with SqlServerCoordinator; NullCoordinator (single node) never transitions, so byte-identical.
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
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
        # ADR 0157 Inc 5: optional demotion edge-trigger. None unless the engine registered
        # one; deliberately NOT part of the ClusterCoordinator Protocol (that Protocol is
        # @runtime_checkable and a standalone test stand-in isinstance-checks against it, so
        # widening it is a multi-site enumeration — the exact defect class this avoids).
        self._on_demote: Callable[[], None] | None = None
        # The SELF-FENCE timeout: a leader that has not renewed within this many seconds (its own
        # monotonic clock, no DB I/O) demotes itself. MUST be < the TTL — but note what that ordering
        # does and does not buy. It bounds when this node stops *calling itself* leader; it does NOT
        # bound when this node stops *acting*. Two terms sit outside the validator (settings.py
        # _fence_ordering, which checks ordering only, never margin): the fence baseline is stamped
        # AFTER the renew round trip returns while the lease expiry is stamped on the DB clock at
        # statement execution, so the real margin is short by that round trip; and detection lands up to
        # one _fence_tick late. Graph teardown is not budgeted against the remainder at all. Treat this
        # as the split-brain DETECTION bound, not a proof that the old leader has stopped.
        self._fence_timeout = leader_fence_timeout_seconds
        # The fence watchdog polls this often; small relative to the fence timeout so a fence fires
        # promptly (well before the lease TTL). Pure in-memory check — no DB.
        self._fence_tick = max(0.05, min(1.0, leader_fence_timeout_seconds / 5.0))
        # Leader-preference (ADR 0096). `acquire_delay` handicaps ONLY the take-over-of-an-EXPIRED-lease
        # path (added to the lease-expiry time on the DB clock), never a renew; `promotable=False` makes
        # this node never claim/hold the lease at all. Default (0.0, True) = byte-identical to before.
        self._acquire_delay = acquire_delay_seconds
        self._promotable = promotable
        # ADR 0056 slice 1: monotonic instant before which this node declines to claim or renew, set by
        # step_down_leadership() so a voluntarily-drained node does not immediately re-arm itself via the
        # renew branch. 0.0 = no pause, which is every path but a stepdown.
        self._no_claim_until: float = 0.0
        # ADR 0056 slice 1: a lease-expiring write did not return, so this node may still own a live
        # lease row it has already stopped claiming in memory. _release_leadership ARMS it before the
        # write and clears it only when one returns, so neither a raise nor a cancellation can leave it
        # clear. Read by step_down_leadership ALONE, to force the retry's write past the not-a-leader
        # early return — without it a retry sends nothing and answers "not the leader" over a lease row
        # that is still live and still ours.
        self._lease_release_owed = False
        # ADR 0056 slice 1: mutual exclusion between _maintain_leadership and the stepdown's release.
        # BOTH of them decide leadership across an await on the pool, and a stepdown runs from an API
        # handler with the maintenance loop LIVE — unlike stop(), which cancels and gathers both loops
        # before it releases. Without this, a maintenance tick interleaving with the release re-promotes
        # the node it just drained, in either order: a tick that STARTS in the release's await window
        # renews the lease the release is expiring, and a tick already suspended inside its claim
        # round-trip returns True afterwards and flips _is_leader back on. The pause above cannot close
        # either — it is checked BEFORE the claim's await, so a claim already in flight has passed it.
        # Held ONLY by those two coroutines: the fence watchdog stays lock-free (it must fence during a
        # DB hang, and it only ever demotes), and stop() releases without it so a shutdown is never
        # blocked behind an in-flight stepdown waiting on a hung pool.
        self._leadership_lock = asyncio.Lock()
        # Monotonic clock for the fence (injectable for deterministic tests). Distinct from the DB clock
        # the lease uses: the fence measures a node-local elapsed duration (free of INTER-NODE skew —
        # that is the property being bought), the lease compares against the DB's own clock_timestamp().
        # Caveat, because "monotonic" is not the same as "always advancing in real time": this measures
        # elapsed AWAKE time on platforms whose monotonic source excludes suspend (CLOCK_MONOTONIC on
        # Linux does; QueryPerformanceCounter on the Windows/NSSM target does not), while the lease it
        # races runs on the DB clock, which never suspends. Where the two differ, the fence is late by
        # the suspended interval and the node keeps reporting leader until its next maintenance tick.
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
        # Deliberately NOT under _leadership_lock. The gather above retired the maintenance loop, but
        # NOT step_down_leadership(), which runs from an API handler this method never sees — so a
        # shutdown concurrent with a stepdown is genuinely unserialized here. That is the trade taken
        # on purpose: taking the lock would queue a shutdown behind a stepdown stalled on a hung pool,
        # and the unserialized case is benign because both coroutines only ever DEMOTE (each sets
        # _is_leader False and issues the same owner-scoped expiring UPDATE, which is idempotent), so
        # no interleaving of the two can leave this node reporting leader. The maintenance tick was the
        # dangerous competitor precisely because it can promote.
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
        Step 7). :func:`members_from_node_rows` builds them, and its docstring explains how the single
        derived leader is picked and what node clock skew does to that pick.

        One DB read, returned ordered by ``node_id`` for a stable listing; off the message hot path
        (operator-driven)."""
        rows = await self._pool.fetch(
            "SELECT node_id, host, pid, started_at, last_seen, status, is_leader, "
            "acquire_delay_seconds, promotable FROM nodes ORDER BY node_id"
        )
        return members_from_node_rows(rows, time.time(), self._node_timeout_seconds)

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
        async with self._pool.acquire() as conn:  # noqa: SIM117
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
            except TimeoutError:
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

        The whole tick — the claim AND the bookkeeping that reads its result — runs under
        :attr:`_leadership_lock`, because the promotion decision is made on a value that crossed an
        await. A stepdown that interleaved here would be undone by the tick's own stale result; see the
        lock's comment in ``__init__``.
        """
        async with self._leadership_lock:
            held = await self._claim_or_renew_lease()
            if held:
                self._last_renew_ok = self._monotonic()
                if not self._is_leader:
                    self._is_leader = True
                    log.info("cluster: node %s acquired leadership (lease)", self.node_id)
                    # #145: a non-leader→leader transition is a failover / election edge — alert
                    # (never-raise).
                    self._alert_leadership_acquired()
            elif self._is_leader:
                # The lease is held by another node (or expired and taken over) — we are no longer leader.
                self._is_leader = False
                # Drop the held epoch: we are no longer a fenced leader, and the next acquire will read
                # the (now-higher) epoch the successor bumped. Leaving a stale epoch cached would be
                # harmless (the store guard already lost when the graph stopped) but clearing it keeps
                # current_epoch() honest.
                self._leader_epoch = None
                log.info("cluster: node %s lost leadership (lease taken or expired)", self.node_id)
                self._alert_leadership_lost(
                    "lease taken or expired"
                )  # #145 (inverse → auto-resolves)
                self._fire_on_demote()  # ADR 0157 Inc 5

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
        if self._monotonic() < self._no_claim_until:
            # JUST STEPPED DOWN (ADR 0056 slice 1): decline for a bounded window so a sibling wins the
            # expired lease instead of us renewing it straight back. Same shape as the check above —
            # touch no DB row, report not-held — and strictly stricter than the base predicate, so it
            # can only delay a claim, never advance one.
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
        mid-await — cannot stop it from fencing.

        ``_fence_timeout < lease_ttl`` is what makes a partitioned old leader stop *reporting* leader
        before its lease can expire — and that is the whole of it. Two caveats, both load-bearing for
        anyone deriving a safety argument from this ordering. The margin is smaller than
        ``lease_ttl - _fence_timeout``: the baseline this compares against is stamped after the renew
        round trip RETURNS while the lease expiry is stamped on the DB clock at statement execution, and
        detection lands up to one ``_fence_tick`` late. And demotion here flips a boolean — it cancels
        no listener, worker, or in-flight send. Nothing budgets graph teardown against the remainder, so
        **"fenced" does not imply "stopped processing"**; do not use this as a premise for a write that
        assumes the prior leader is quiescent."""
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._fence_tick)
                return  # stop requested
            except TimeoutError:
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
            self._alert_leadership_lost("self-fenced")  # #145 (inverse → auto-resolves)
            self._fire_on_demote()  # ADR 0157 Inc 5

    async def step_down_leadership(self) -> tuple[bool, float | None]:
        """Release leadership and stay up as a standby (ADR 0056 slice 1). See the Protocol method.

        It calls the same :meth:`_release_leadership` ``stop()`` does, but **the ordering inside that
        method is not what makes either call safe, and reading it that way is the mistake this
        docstring used to make.** ``stop()`` cancels and gathers BOTH loops before it releases, so
        nothing is running concurrently by the time it touches the lease. A stepdown arrives from an
        API handler with both loops LIVE, so it has to supply that exclusion itself. Three things
        ``stop()`` therefore does not need:

        * **Serialize against the maintenance tick** with :attr:`_leadership_lock`. Held across the
          release AND the pause below, so a tick can neither start inside the release's await window
          nor deliver a claim result it obtained before the release began. Both interleavings
          re-promoted the node this endpoint had just drained, one of them into a two-leader window
          against a sibling that had already taken the expired lease.
        * **Fire the demotion edge** so the graph tears down at once instead of waiting out a whole
          ``_graph_reconcile_interval`` poll (ADR 0157 Inc 5). Every other True->False transition
          (``_maintain_leadership``, ``_check_fence``) fires it; a stepdown the node SURVIVES would
          otherwise be the one demotion the engine learns about late.
        * **Pause our own claim** for :func:`stepdown_pause_seconds`. Without it the stepdown is a
          coin flip: :meth:`_release_leadership` expires ``lease_expires_at`` but leaves ``owner``
          naming us, so the renew branch (``owner = me``, which carries no expiry test) matches on our
          very next maintenance tick and hands leadership straight back — a drained node re-arming
          itself while the endpoint reported 200. The pause is a strictly STRICTER claim predicate on
          this node only (the same shape as ADR 0096's ``acquire_delay``), so it can only make us claim
          LATER, never earlier. It changes nothing about the lease, the self-fence or the epoch token.
          **It is a claim predicate, not mutual exclusion**: it is evaluated before the claim's await,
          so it says nothing about a claim already in flight — that is the lock's job, above. It is
          armed TWICE, before the release AND again after it, taking whichever expiry is later. The
          first arm is what a cancellation landing inside the pool write cannot skip; the second is
          what keeps the write's own unbounded duration from being spent out of the pause, since the
          lease row does not become takeable until that write commits. Neither arm buys anything
          against either interleaving above and neither is credited with doing so.

        Deadlock, since the lock is new: it is taken in exactly two coroutines, neither of which calls
        the other, so there is no ordering to invert. A cancelled tick releases it on the way out
        (``async with`` unwinds), and ``stop()`` deliberately does not take it, so a shutdown never
        queues behind a stepdown stalled on a hung pool.

        **What the lock COSTS, stated because a control resting on a false premise is worse than no
        control.** An earlier draft of this docstring said waiting for an in-flight tick "adds no new
        stall to this method either — it already awaits the same pool inside the release". That is
        false, and in the one direction that matters: the first line of :meth:`_release_leadership` is
        the SYNCHRONOUS in-memory demotion, so before this lock that demotion happened immediately and
        now it happens behind a tick's DB round trip. A tick suspended in ``fetchrow`` holds the lock,
        and while this call waits, the node an operator is draining still answers :meth:`is_leader`
        ``True`` and still binds listeners. Nothing bounds that round trip from here either:
        ``[store].command_timeout`` is the only ceiling, ``PostgresStore`` passes ``command_timeout or
        None`` so the documented zero-disables value makes it unbounded, and the pool ``acquire()``
        carries no timeout at all.

        So the wait is bounded, and a timeout refuses with ``503`` rather than demoting anything —
        :func:`acquire_leadership_lock` holds that bound and the reasoning behind it.

        **Retrying a stepdown whose write did not return re-sends that write.** ``_release_leadership``
        demotes the in-memory gate BEFORE the write, so on the retry its not-a-leader early return
        fired, the ``UPDATE`` was never re-attempted, and the caller was told "not the current leader"
        over a lease row still live and still owned by this node — with the endpoint's own remedy for
        that answer pointing back at this same node. :attr:`_lease_release_owed` records the owed write
        so this method can force it past that early return. "Did not return" covers a CANCELLED write
        as well as a raised one — the request deadline can cancel this call mid-write — which is why
        :meth:`_release_leadership` arms that flag *before* the write rather than in its ``except``.
        """
        await acquire_leadership_lock(self._leadership_lock, self._fence_timeout, self.node_id)
        try:
            # Arm the claim pause BEFORE the release's await, not after it. Cancelling the request task
            # while the release is suspended in the pool write unwinds this method correctly but would
            # skip an assignment placed after the await, leaving _no_claim_until at 0.0 on a node whose
            # lease row may already be expired — the very re-arm the pause exists to prevent. Reading
            # _is_leader here is exact rather than a "pre-read" of the kind the endpoint refuses to
            # make: nothing suspends between this read and _release_leadership's own read of the same
            # attribute (awaiting a coroutine does not yield to the loop), and the only other writers
            # are _maintain_leadership, which is holding-lock-excluded, and _check_fence, which is
            # synchronous and therefore cannot run in that gap.
            owed = self._lease_release_owed
            # Held across the await because the second arm below needs the SAME predicate, and
            # `self._is_leader` is already False by then — _release_leadership clears it on its first
            # line, so re-reading it there would silently arm nothing.
            arming = self._is_leader or owed
            if arming:
                # Stand down long enough that every sibling has had a full tick at the expired lease.
                # The retry needs this as much as the first call does: the release expires
                # `lease_expires_at` but leaves `owner` naming us, so a successful retry with no pause
                # re-arms this node through the unfenced `owner = me` branch on its very next tick.
                self._no_claim_until = self._monotonic() + stepdown_pause_seconds(
                    self._heartbeat_seconds
                )
            was_leader, released_at, wrote = await self._release_leadership(force_write=owed)
            if arming:
                # ARMED A SECOND TIME, from the instant the write RETURNED, taking whichever expiry is
                # LATER. The arm above is measured from before the write, so the write's own duration
                # comes out of the pause — and nothing bounds that duration from here: the pool
                # acquire() carries no timeout and `[store].command_timeout` (30s by default) is the
                # only ceiling on the statement, already longer than the 20s pause at the shipped
                # heartbeat. The window that matters starts when the row becomes takeable, which is the
                # commit, not the call: measuring from before it would hand a sibling (2 * heartbeat -
                # write duration), which can reach zero, and the drained node's own queued tick — which
                # waits on this lock for the whole call — would then fall straight through the pause
                # gate and renew itself back in through the unfenced `owner = me` branch, milliseconds
                # after the endpoint answered 200.
                #
                # max(), not a replacement: the pause may only ever move LATER. A real monotonic clock
                # makes the second value the larger one by construction, but an injected or coarse
                # clock must not be able to SHORTEN a pause this call already promised.
                self._no_claim_until = max(
                    self._no_claim_until,
                    self._monotonic() + stepdown_pause_seconds(self._heartbeat_seconds),
                )
            if was_leader:
                self._fire_on_demote()
            # NOT nested under `was_leader`. A retry re-sending an owed write has already demoted, so it
            # reports was_leader=False and would otherwise swallow a second failure into a 409.
            if not wrote:
                raise StepdownReleaseUnconfirmed(lease_release_unconfirmed(self.node_id))
        finally:
            self._leadership_lock.release()
        return (was_leader, released_at)

    async def _release_leadership(
        self, *, force_write: bool = False
    ) -> tuple[bool, float | None, bool]:
        """Clean release: demote the cached gate first (so a concurrent is_leader() reader never sees a
        stale True), then expire our lease row so a standby can acquire immediately. Safe to call when
        never elected (the UPDATE simply matches no owned row).

        Returns ``(was_leader, released_at, wrote)`` — whether this node held leadership when the
        release ran, the epoch-seconds instant it was demoted, and whether the lease row's ``UPDATE``
        returned. ``released_at`` is stamped at the in-memory demotion, not after the DB round trip:
        that instant is when this node stopped answering :meth:`is_leader` ``True``, which is the fact
        the audit trail is recording.

        **``wrote`` exists because the two callers want opposite things from a failed write.**
        :meth:`stop` is best-effort — the node is leaving, so a lease that ages out at its TTL costs
        nothing and a raise would break shutdown. :meth:`step_down_leadership` is not: the node stays
        up possibly holding a live lease no sibling can take, so it turns ``wrote=False`` into
        :class:`StepdownReleaseUnconfirmed`. The exception is raised there rather than here so this
        method keeps exactly one behaviour for both callers.

        **``wrote=True`` means the driver returned, NOT that a row changed**, and the difference does
        not matter to either caller: the ``UPDATE`` is owner-scoped, so it either expired our live
        lease or matched nothing because the lease is not ours, and neither leaves a live lease owned
        by this node. What no row count can answer is the raising path, where the driver returns no
        count at all — see :class:`StepdownReleaseUnconfirmed`.

        ``force_write`` sends the ``UPDATE`` even when this node's in-memory gate already reads False.
        Only :meth:`step_down_leadership` passes it, and only when :attr:`_lease_release_owed` says an
        earlier write did not return. :meth:`stop` never does: it is best-effort by design, and a
        no-op ``UPDATE`` from every departing follower would log a warning on a pool that is closing."""
        was_leader = self._is_leader
        self._is_leader = False
        self._last_renew_ok = None
        self._leader_epoch = None  # released: no longer a fenced leader
        if not was_leader and not force_write:
            return (False, None, True)
        released_at = time.time() if was_leader else None
        # #145: clean step-down (inverse -> auto-resolves). Guarded, because a forced retry alerted on
        # its first pass: it is re-sending a write, not demoting a second time.
        if was_leader:
            self._alert_leadership_lost("released")
        # OWED BEFORE THE WRITE, cleared only on a write that returned. The obvious placement — set it
        # in the except arm — leaks on CANCELLATION: `asyncio.CancelledError` derives from
        # BaseException, so `except Exception` below does not see it, and the method unwinds with the
        # in-memory `self._is_leader = False` above already done and nothing owed. The next stepdown
        # would then read owed=False, take the `not was_leader and not force_write` early return above,
        # send no UPDATE, and answer "not the current leader" over a lease row that may still be live
        # and still ours — with no audit row of either kind on that path.
        #
        # Reachable in the shipped configuration, not just in theory: `create_app` registers
        # RequestTimeoutMiddleware unconditionally and its asyncio.timeout cancels the handler at
        # api.request_timeout.DEFAULT_REQUEST_TIMEOUT_SECONDS (120.0), over a pool acquire
        # step_down_leadership's own docstring documents as unbounded.
        self._lease_release_owed = True
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
            return (was_leader, released_at, False)
        self._lease_release_owed = False
        return (was_leader, released_at, True)

    # --- #145 leadership-transition alerts (never-raise) ---------------------

    def _alert_leadership_acquired(self) -> None:
        """Emit a ``leadership_acquired`` alert (this node became leader). Never-raise: an alert failure
        must never break the maintenance loop. The emit itself is synchronous + non-blocking (the
        NotifierAlertSink only enqueues); the epoch is the H1 token this node just cached."""
        try:
            self._alert_sink.leadership_acquired(
                self.node_id, role="leader", epoch=self._leader_epoch
            )
        except Exception:  # pragma: no cover - defensive; a sink must never break leadership
            log.warning("cluster: leadership_acquired alert failed", exc_info=True)

    def set_on_demote(self, callback: Callable[[], None] | None) -> None:
        """Register an edge-trigger fired the instant this node stops being leader (ADR 0157 Inc 5).

        The engine uses it to start the graph teardown immediately instead of waiting up to a whole
        ``_graph_reconcile_interval`` poll. The callback MUST be synchronous, never-raise, and PURE
        IN-MEMORY: it fires from ``_check_fence``, which runs during a DB partition precisely because
        renews are failing, so touching the store or the pool there would hang the fence itself.
        """
        self._on_demote = callback

    def _fire_on_demote(self) -> None:
        """Never-raise, never touch the pool. Both properties are load-bearing — see set_on_demote."""
        callback = self._on_demote
        if callback is None:
            return
        try:
            callback()
        except Exception:  # pragma: no cover - defensive; a hook must never break demotion
            log.warning("cluster: on_demote hook failed", exc_info=True)

    def _alert_leadership_lost(self, reason: str) -> None:
        """Emit a ``leadership_lost`` inverse (this node is no longer leader) — auto-resolves the open
        ``leadership_acquired`` instance. Never-raise (as :meth:`_alert_leadership_acquired`)."""
        try:
            self._alert_sink.leadership_lost(self.node_id, role="follower", reason=reason)
        except Exception:  # pragma: no cover - defensive
            log.warning("cluster: leadership_lost alert failed", exc_info=True)


def build_coordinator(
    store: Any, cluster_settings: Any, *, alert_sink: AlertSink | None = None
) -> ClusterCoordinator:
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
            alert_sink=alert_sink,  # #145: failover-transition alerts (lockstep with DbCoordinator)
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
        alert_sink=alert_sink,  # #145: failover-transition alerts
    )
