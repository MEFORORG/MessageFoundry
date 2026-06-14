"""Leader-only store-maintenance tasks (Track B Step 4).

In a cluster, crashed-node recovery is the **leader's** job: instead of the single-node unconditional
``reset_stale_inflight`` (which ignores leases and would steal a live sibling's in-flight rows), the
leader periodically calls :meth:`Store.reclaim_expired_leases`, which returns to ``pending`` only rows
whose lease has actually **expired** — so a crashed node's work is recovered without disturbing a live
node's. :class:`LeaderMaintenanceRunner` is the engine-owned task that runs that sweep on cadence,
**gated on leadership each pass** (a follower no-ops while the loop keeps ticking, so when it later
becomes leader the next pass acts).

It mirrors :class:`~messagefoundry.pipeline.retention.RetentionRunner`'s shape: construct with the
store + coordinator, call :meth:`start`/:meth:`stop` for the supervised loop, or :meth:`sweep_once`
for a single deterministic pass (tests). The engine only spawns it in clustered mode (when the
coordinator's ``reclaims_inflight()`` is True), so single-node / SQLite never pays for it.

Engine-side and dependency-light (stdlib + the store/cluster seams only), so it never pulls the API or
console into the engine.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Protocol

from messagefoundry.pipeline.cluster import ClusterCoordinator

__all__ = ["LeaderMaintenanceRunner", "ReclaimingStore"]

log = logging.getLogger(__name__)


class ReclaimingStore(Protocol):
    """The narrow store surface this runner needs: the multi-node-safe expired-lease reclaim.

    ``reclaim_expired_leases`` is a Postgres-only method (NOT on the base :class:`Store` protocol —
    SQLite is single-node and never leases), and this runner is only ever spawned in clustered mode
    against a Postgres store, so it depends on just this method rather than the whole store contract.
    Backend-agnostic by structural typing: it never imports the concrete ``PostgresStore``."""

    async def reclaim_expired_leases(
        self, now: float | None = ..., *, stage: str | None = ...
    ) -> int: ...


class LeaderMaintenanceRunner:
    """Runs the leader's periodic lease-reclaim sweep on cadence, gated on :meth:`is_leader` each pass.

    Construct with the store + coordinator + interval; call :meth:`start`/:meth:`stop` for the
    supervised loop, or :meth:`sweep_once` for a single deterministic pass (tests). A non-leader pass
    is a no-op (the gate short-circuits before any store write), so it is safe to run on every node —
    only the current leader actually reclaims.
    """

    def __init__(
        self,
        store: ReclaimingStore,
        coordinator: ClusterCoordinator,
        *,
        interval_seconds: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._coordinator = coordinator
        self._interval_seconds = interval_seconds
        self._clock = clock
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Spawn the supervised reclaim loop (idempotent: a second call while running is a no-op)."""
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info(
            "cluster leader maintenance enabled: lease-reclaim sweep every %gs (leader-gated)",
            self._interval_seconds,
        )

    async def stop(self) -> None:
        """Signal the loop and await its exit (idempotent)."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        # One isolated pass per interval; an error in a pass is logged and the loop continues (a
        # reclaim hiccup must never take the engine down). Cooperatively cancellable via _stop.
        while not self._stop.is_set():
            try:
                await self.sweep_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("cluster: leader reclaim sweep failed; will retry next interval")
            await self._sleep(self._interval_seconds)

    async def _sleep(self, delay: float) -> None:
        """Sleep up to ``delay``, waking immediately on stop (so shutdown isn't held by the interval)."""
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
        except asyncio.TimeoutError:
            pass

    # --- one pass ------------------------------------------------------------

    async def sweep_once(self, now: float | None = None) -> int:
        """Run one reclaim sweep IF this node is the leader; otherwise no-op. Returns the number of
        expired-lease rows returned to ``pending`` (0 when a follower or nothing was expired)."""
        if not self._coordinator.is_leader():
            return 0
        now = self._clock() if now is None else now
        # reclaim_expired_leases is multi-node-safe by construction: it only reclaims rows whose lease
        # has expired (lease_expires_at < now), never a live sibling's in-flight row.
        reclaimed = await self._store.reclaim_expired_leases(now=now)
        if reclaimed:
            log.info("cluster: leader reclaimed %d expired-lease row(s)", reclaimed)
        return reclaimed
