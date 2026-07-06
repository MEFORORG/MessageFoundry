# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Timer / scheduled source — emit a configured body on a schedule (ADR 0011).

Unlike every other source, a timer reads **no external resource**: it *fires* on a clock and hands
an operator-configured ``body`` to the pipeline handler. It follows the File/Database poll skeleton
(a cooperatively-cancellable :mod:`asyncio` loop that logs-and-continues on error, never crashing the
connection) but drops the resource scan, content validation, and mark/move — each tick just emits the
body.

A timer is **leader-gated** (:attr:`polls_shared_resource` ``True``): the schedule is a *shared
trigger*, so in a cluster only the leader fires it — otherwise every node would emit each message. On
a single node ``NullCoordinator.is_leader()`` is always ``True``, so behaviour is byte-identical to an
ungated loop (the runner already passes ``leader_gate=is_leader`` to every source). See ADR 0011 for
the at-least-once / re-run contract: the body is committed to the ingress stage and frozen there, so
downstream re-runs stay pure; only the *timing* boundary is at-least-once (a clock, not a queue).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports.base import InboundHandler, SourceConnector, register_source

logger = logging.getLogger(__name__)

# How often a not-yet-fired ``run_once`` timer re-checks leadership when no interval is configured
# (so a follower that wins leadership fires reasonably promptly). On a single node it fires on the
# first tick regardless, so this only matters in a cluster.
DEFAULT_RUN_ONCE_POLL_SECONDS = 1.0


class TimerSource(SourceConnector):
    """Emit a configured ``body`` on an interval (or exactly once), feeding it to the pipeline handler."""

    # A schedule is a shared trigger — leader-gate it so exactly one node fires (see module docstring).
    polls_shared_resource = True

    def __init__(self, config: Source) -> None:
        s = config.settings
        if "body" not in s:
            raise ValueError("timer source requires a 'body' setting")
        self.body = str(s["body"])
        self.encoding = str(s.get("encoding", "utf-8"))
        # Pre-encode once: the emitted bytes are deterministic across fires (re-run-stable, ADR 0011 §5).
        self._body_bytes = self.body.encode(self.encoding)
        self.run_once = bool(s.get("run_once", False))
        iv = s.get("interval_seconds")
        self.interval_seconds: float | None = float(iv) if iv is not None else None
        if self.interval_seconds is not None and self.interval_seconds <= 0:
            raise ValueError("timer source 'interval_seconds' must be > 0")
        if s.get("cron_expression"):
            # The loop is cron-shaped, but the schedule calculation is a deliberate follow-up — the MVP
            # is interval + run_once with no scheduling dependency (ADR 0011 §2). Reserve the setting
            # name and fail loud so a config asking for cron is caught at wiring / `messagefoundry check`.
            raise ValueError(
                "timer source 'cron_expression' is not yet implemented "
                "(use 'interval_seconds' or 'run_once')"
            )
        if self.interval_seconds is None and not self.run_once:
            raise ValueError("timer source requires 'interval_seconds' or 'run_once'")
        # The loop's sleep cadence: the interval when set, else a short re-check for a run_once follower.
        self._tick_seconds = (
            self.interval_seconds
            if self.interval_seconds is not None
            else DEFAULT_RUN_ONCE_POLL_SECONDS
        )
        self._handler: InboundHandler | None = None
        # Leader-gate (Track B Step 4b): when set, only fire while it returns True so exactly one node
        # emits. None = always fire (single-node / direct callers / tests) — byte-identical.
        self._leader_gate: Callable[[], bool] | None = None
        self._skipping = False  # whether the last tick was gated out (for a single transition log)
        self._fired = False  # has run_once already fired? (so it fires once, then idles until stop)
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        """Begin firing in the background. Returns once the source is set up so the caller can rely
        on it being live (consistent with the other sources)."""
        self._handler = handler
        self._leader_gate = leader_gate
        self._stop.clear()
        self._fired = False
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            # return_exceptions: a faulted timer task must not re-raise here — stop() runs during reload
            # quiesce, outside its rollback. _run already guards each fire; this is belt-and-suspenders.
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def _run(self) -> None:
        # Fire immediately on start (a heartbeat starts at t=0), then every interval. The first tick of
        # each pass checks the leader gate; a follower skips and re-checks next tick (reactive-by-polling).
        while not self._stop.is_set():
            try:
                if self._may_fire():
                    await self._fire()
                    self._fired = True
            except asyncio.CancelledError:
                raise
            except Exception:
                # A fire failure is an infrastructure error (the durable ingress write failed — DB
                # locked, disk full): the handler records every message-level outcome itself. It must
                # NOT kill the source (that would silently stop intake while still reporting running).
                # Log and retry on the next tick (at-least-once). _fired stays False, so a run_once timer
                # retries until it lands.
                logger.exception("timer source fire failed; retrying next tick")
            if self.run_once and self._fired:
                # Single-shot done: idle until stop so the task joins cleanly rather than busy-ticking.
                await self._stop.wait()
                return
            try:
                await asyncio.wait_for(self._stop.wait(), self._tick_seconds)
            except asyncio.TimeoutError:
                pass  # tick elapsed; fire / re-check again

    def _may_fire(self) -> bool:
        """Whether this tick may fire. False on a follower (leader-gated, Step 4b): a non-leader must
        not emit, since the schedule is shared and two nodes firing would duplicate the message. The
        loop still ticks, so a node that becomes leader fires on its next tick (no restart). When the
        gate is None or True, behaves exactly as an ungated loop. Logged once per transition (never per
        skipped tick — that would spam a follower's log every tick)."""
        if self._leader_gate is None or self._leader_gate():
            if self._skipping:
                self._skipping = False
                logger.debug("timer source resuming (now leader)")
            return True
        if not self._skipping:
            self._skipping = True
            logger.debug("timer source skipping fire (not leader; another node emits it)")
        return False

    async def _fire(self) -> None:
        assert self._handler is not None
        await self._handler(self._body_bytes)


register_source(ConnectorType.TIMER, TimerSource)
