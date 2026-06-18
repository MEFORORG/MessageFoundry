# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Cluster-wide transform-state read-through convergence (Track B Step 6b).

Transform state (ADR 0005) is written inside ``PostgresStore.transform_handoff`` and published into the
**writing node's** own ``_state_cache`` only. A sibling node never sees it, so ``state_get(ns, key)`` on a
follower returns stale/missing data for keys another node wrote. ``state_get`` is on the hot path of
**every** transform and must stay a pure synchronous dict lookup (no ``await``, no per-read DB), so
convergence is a background, off-path refresh of the local cache — exactly mirroring the reference-cache
convergence Step 6 ships (:class:`~messagefoundry.pipeline.reference_sync.ReferenceSyncRunner`).

:class:`StateConvergenceRunner` is the engine-owned background loop on every clustered node that, each
interval, calls a converge callable (``store.converge_state_cache``) which read-throughs any namespace
whose shared per-namespace version is newer than the one this node reflects, and logs the refreshed
namespace **names** (never keys/values — those may be PHI). The engine only spawns it in clustered mode
(``coordinator.is_clustered()``), so single-node / SQLite never pays for it.

It mirrors :class:`~messagefoundry.pipeline.config_convergence.ConfigConvergenceRunner`'s shape
(``start``/``stop``/``_run``/``_sleep``/``converge_once``, supervised + cooperatively cancellable) and
copies the **PHI/error discipline** of
:class:`~messagefoundry.pipeline.reference_sync.ReferenceSyncRunner`: on a convergence/decrypt failure log
the exception **class only** (``type(exc).__name__``), NEVER ``str(exc)`` and NEVER ``log.exception`` (a
decrypt failure can carry snapshot bytes / a PHI-bearing key), keep the last-good cache, retry next
interval, and alert via the AlertSink.

Decoupled from the store: it takes a plain converge callback (like
:class:`~messagefoundry.pipeline.config_convergence.ConfigConvergenceRunner` takes ``reload``) so the
dependency direction stays one-way (pipeline only — it never pulls the API or console into the engine).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink

__all__ = ["StateConvergenceRunner"]

log = logging.getLogger(__name__)


class StateConvergenceRunner:
    """Polls the shared transform-state versions each tick and read-throughs newer namespaces locally.

    Construct with ``converge`` (an awaitable that read-throughs any newer shared state into this node's
    local cache and returns the refreshed namespace names, e.g. ``store.converge_state_cache``) and the
    poll ``interval_seconds``. The runner never imports the store — it takes ``converge`` as a plain
    callback so the dependency direction stays one-way (pipeline only).
    """

    def __init__(
        self,
        *,
        converge: Callable[[], Awaitable[list[str]]],
        interval_seconds: float,
        alert_sink: AlertSink | None = None,
    ) -> None:
        self._converge = converge
        self._interval_seconds = interval_seconds
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
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
            "cluster transform-state convergence enabled: read-through every %gs",
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
        # One isolated pass per interval; converge_once already swallows + alerts a pass error (NOT
        # log.exception — a decrypt failure can carry PHI), so the loop just keeps going. Cooperatively
        # cancellable via _stop.
        while not self._stop.is_set():
            await self.converge_once()
            await self._sleep(self._interval_seconds)

    async def _sleep(self, delay: float) -> None:
        """Sleep up to ``delay``, waking immediately on stop (so shutdown isn't held by the interval)."""
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
        except asyncio.TimeoutError:
            pass

    # --- one pass ------------------------------------------------------------

    async def converge_once(self) -> list[str]:
        """Read-through any newer shared transform-state into this node's local cache. Returns the
        refreshed namespace names (``[]`` when nothing advanced).

        Errors are isolated: on any ``Exception`` (but ``CancelledError`` re-raises so shutdown isn't
        swallowed) log the error CLASS only — never ``str(exc)`` and never ``log.exception`` (a decrypt
        failure can carry snapshot bytes / a PHI-bearing key, CLAUDE.md §9) — alert, keep the last-good
        cache, and return ``[]`` so the loop retries next interval rather than dying."""
        try:
            refreshed = await self._converge()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            kind = type(exc).__name__
            log.warning(
                "cluster: transform-state cache convergence failed (keeping current): %s", kind
            )
            self._alert(f"state cache convergence failed ({kind})")
            return []
        if refreshed:
            # Names only (a namespace name is operator config, not PHI) at INFO so an operator can see a
            # follower converge; never the keys/values (which may be PHI).
            log.info(
                "cluster: transform-state cache converged %d namespace(s): %s",
                len(refreshed),
                ", ".join(refreshed),
            )
        return refreshed

    def _alert(self, detail: str) -> None:
        # The AlertSink has no state-specific event; reuse connection_stopped as the generic "a named
        # component degraded" signal (never raises — be defensive anyway).
        try:
            self._alert_sink.connection_stopped("transform-state", detail=detail)
        except Exception:
            log.warning("transform-state convergence alert sink failed", exc_info=True)
