# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Cluster-wide config-reload convergence (Track B Step 6).

When an operator reloads config on ONE clustered node, that node bumps a shared
``cluster_config.config_version`` token (see :class:`~messagefoundry.pipeline.cluster.DbCoordinator`).
:class:`ConfigConvergenceRunner` is the engine-owned background loop on every node that polls the
coordinator's *cached* version each tick and, when it observes a version higher than the one this node
has applied, re-reads **this node's own** (identically-deployed) startup config dir and applies it — so
a single operator reload propagates to the whole cluster without per-node operator action.

**Feedback-avoidance.** The node that initiated the reload already advanced its applied version (the
engine sets ``_applied_config_version`` right after bumping), so its own loop sees no change and does
NOT re-reload — only the OTHER nodes, whose applied version is behind, converge.

**Homogeneous-config assumption.** The version token coordinates *when* nodes reload; each node reloads
its OWN config dir. Skewed config dirs would diverge — the same assumption as Step 4's
dead-letter-missing-destinations/handlers sweeps (clustered nodes run identical config).

It mirrors :class:`~messagefoundry.pipeline.leader_tasks.LeaderMaintenanceRunner`'s shape: construct
with the engine convergence callbacks + coordinator + interval, call :meth:`start`/:meth:`stop` for the
supervised loop, or :meth:`converge_once` for a single deterministic pass (tests). The engine only
spawns it in clustered mode (``coordinator.is_clustered()``), so single-node / SQLite never pays for it.

Engine-side and dependency-light (stdlib + the cluster seam only), so it never pulls the API or console
into the engine.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from messagefoundry.pipeline.cluster import ClusterCoordinator

__all__ = ["ConfigConvergenceRunner"]

log = logging.getLogger(__name__)


class ConfigConvergenceRunner:
    """Polls the shared config version each tick and reloads this node's config when it falls behind.

    Construct with: ``applied_version`` (a getter for this node's currently-applied config version),
    ``set_applied_version`` (a setter the runner calls after a successful convergence reload), and
    ``reload`` (an awaitable that re-applies this node's local startup config, NON-propagating). The
    runner never imports the engine — it takes these as plain callbacks so the dependency direction
    stays one-way (pipeline only).
    """

    def __init__(
        self,
        coordinator: ClusterCoordinator,
        *,
        applied_version: Callable[[], int],
        set_applied_version: Callable[[int], None],
        reload: Callable[[], Awaitable[None]],
        interval_seconds: float,
    ) -> None:
        self._coordinator = coordinator
        self._applied_version = applied_version
        self._set_applied_version = set_applied_version
        self._reload = reload
        self._interval_seconds = interval_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Spawn the supervised convergence loop (idempotent: a second call while running is a no-op)."""
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info(
            "cluster config convergence enabled: polling the shared config version every %gs",
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
        # One isolated pass per interval; an error in a pass (e.g. a bad local config) is logged and the
        # loop continues — a convergence hiccup must never take the node down. Cooperatively cancellable.
        while not self._stop.is_set():
            try:
                await self.converge_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("cluster: config convergence pass failed; will retry next interval")
            await self._sleep(self._interval_seconds)

    async def _sleep(self, delay: float) -> None:
        """Sleep up to ``delay``, waking immediately on stop (so shutdown isn't held by the interval)."""
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
        except asyncio.TimeoutError:
            pass

    # --- one pass ------------------------------------------------------------

    async def converge_once(self) -> bool:
        """If the shared config version is ahead of this node's applied version, reload this node's own
        config dir to converge and advance the applied version. Returns whether a reload happened.

        The poll reads the coordinator's CACHED version (cheap/synchronous, refreshed on the
        coordinator's maintenance tick). The node that initiated the reload already advanced its applied
        version (feedback-avoidance), so only nodes that are behind reload."""
        shared = self._coordinator.config_version_cached()
        if shared <= self._applied_version():
            return False
        log.info(
            "cluster: shared config version %d is ahead of this node's applied %d; converging",
            shared,
            self._applied_version(),
        )
        # Re-read THIS node's own startup config dir (NON-propagating: convergence, not initiation — it
        # must not bump the token again, or nodes would chase each other's reloads). A bad local config
        # raises here; the loop isolates it (logged, the node keeps running its current graph).
        await self._reload()
        # Only advance the applied version after a clean reload, so a failed convergence retries next
        # tick rather than silently skipping the version it couldn't apply.
        self._set_applied_version(shared)
        return True
