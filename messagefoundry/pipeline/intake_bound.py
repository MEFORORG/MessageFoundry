# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runtime intake pause (BACKLOG #290, slice 2, ASVS 15.2.2).

One :class:`IntakeBoundMonitor` per engine process measures two things and holds or releases the
shared :class:`~messagefoundry.transports.base.IntakeGate` the runner injects into every inbound
source. The tcp, x12, http, mllp, dimse (at the association level) and timer inbounds honour it, and
so do the file, remotefile and database pollers. ``docs/CONFIGURATION.md``, under
``[inbound].max_staged_depth``, is the record of which sources pause.

* **Staged-backlog depth** -- not-done ingress + routed rows in the ONE unified store, against
  ``[inbound].max_staged_depth``. Opt-in (0 = off), per owner ruling R1 of 2026-09-27. Store-global,
  so N engine shards sharing a store share one budget.
* **Free disk** on the volume holding a SQLite store, against ``[retention].min_free_disk_mb`` --
  slice 1's floor, which ships on, so this pause is on by default for SQLite. SQL Server and
  Postgres are out of the floor (their disk is the database server's), and an in-memory store has
  no disk.

The pause is backpressure only. A source checks the gate BEFORE it reads; nothing already read is
NAKed, dropped or left uncommitted, and the ACK still follows the durable ingress commit. The
router, transform and delivery workers keep running, which is how a depth pause clears. Each
condition resumes past a hysteresis band rather than at its trip line, so intake does not flap.

**The depth budget is shared, and that is its cost.** One feed whose router or transform stalls, or
the crash residue of a dead engine shard, counts against every other feed's budget, and can hold all
intake paused until an operator acts. That is what a store-global bound means, and it is why the
bound is opt-in and should be sized well above a normal backlog.

A WARNING marks the start of each pause and an INFO its end. Slice 3 adds the AlertSink pair on the
same two edges: ``intake_paused`` when a pause starts and ``intake_resumed``, its auto-resolving
inverse, when it ends. Neither fires on a measurement that changes nothing.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from messagefoundry.config.settings import StoreBackend
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.retention import read_disk_floor, sqlite_store_file
from messagefoundry.store import Store
from messagefoundry.transports.base import IntakeGate

__all__ = [
    "DEPTH_REASON",
    "DISK_REASON",
    "IntakeBoundMonitor",
    "depth_resume_at",
    "disk_resume_at",
    "intake_alert_subject",
]

log = logging.getLogger(__name__)

#: The two reasons this monitor holds the gate for. Separate, so a drained backlog cannot reopen
#: intake while the disk is still low, or the reverse.
DEPTH_REASON = "staged_depth"
DISK_REASON = "disk_floor"

#: How often the monitor measures. Bounds how far intake can run past a bound before the pause
#: lands (one interval of intake, plus at most one poll batch a poll source had already started).
DEFAULT_CHECK_SECONDS = 1.0

#: How long one probe may take before it counts as failed. A hung read must not freeze the loop.
PROBE_TIMEOUT_SECONDS = 10.0


def depth_resume_at(max_staged_depth: int) -> int:
    """The depth at or below which a depth pause ends: 90% of the bound, and always at least one row
    below it, so a bound of 1 resumes only at 0. The gap is what stops the pause flapping on a
    backlog hovering at the bound."""
    return max(0, min(max_staged_depth - 1, (max_staged_depth * 9) // 10))


def disk_resume_at(floor_bytes: int) -> int:
    """The free bytes at or above which a disk pause ends: the floor plus a tenth of it."""
    return floor_bytes + floor_bytes // 10


def intake_alert_subject(reason: str) -> str:
    """The alert subject for one bound: ``intake:<reason>``. One per bound, so a drained backlog
    cannot resolve a low-disk pause. The colon keeps it out of the connection-name grammar, so a
    rule's ``control_action`` dispatched at it can never restart a real connection."""
    return f"intake:{reason}"


class IntakeBoundMonitor:
    """Measure the two intake bounds and hold or release the shared gate. See the module docstring.

    Not leader-gated. Every node that runs the graph (every engine shard, the active node of an HA
    pair) pauses its own listeners against the one shared backlog. A standby runs the check too, with
    nothing to pause; the count is capped, so that costs one bounded read per interval."""

    def __init__(
        self,
        store: Store,
        gate: IntakeGate,
        *,
        max_staged_depth: int = 0,
        min_free_disk_mb: int = 0,
        check_seconds: float = DEFAULT_CHECK_SECONDS,
        alert_sink: AlertSink | None = None,
    ) -> None:
        self._store = store
        self._gate = gate
        self._alert_sink: AlertSink = alert_sink if alert_sink is not None else LoggingAlertSink()
        # The payload's store_kind. A store with no ``backend`` attribute is SQLite, as in
        # sqlite_store_file.
        self._store_kind: str = getattr(store, "backend", StoreBackend.SQLITE).value
        # The pause state last reported to the sink, per reason. Empty at first, so the first
        # measurement of each bound that is paused, or clear of its resume line, reports it. A clear
        # raises intake_resumed once, which resolves a pause left open by a run that stopped while
        # paused. A first measurement inside the hysteresis band reports nothing until it leaves the
        # band (see _sync_alert). After that, only a change is reported.
        self._reported: dict[str, bool] = {}
        # Reasons whose report the sink is refusing: one WARNING per failing streak, not per tick.
        self._sink_failing: set[str] = set()
        self._max_depth = max(0, max_staged_depth)
        # The floor applies to a file-backed SQLite store only, by the same rule as slice 1's
        # retention warning (one helper, so the two cannot disagree).
        self._floor_path: str | None = sqlite_store_file(store) if min_free_disk_mb > 0 else None
        self._floor_mb = min_free_disk_mb
        self._check_seconds = check_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        # One WARNING per failing streak per probe, not one per interval.
        self._depth_failing = False
        self._disk_failing = False
        # Whether check_once has run, so the loop does not repeat Engine.start's first measurement.
        self._measured = False

    @property
    def depth_bound_on(self) -> bool:
        return self._max_depth > 0

    @property
    def disk_floor_on(self) -> bool:
        return self._floor_path is not None

    @property
    def enabled(self) -> bool:
        """True when either bound applies. When False, :meth:`start` spawns no task."""
        return self.depth_bound_on or self.disk_floor_on

    def start(self) -> None:
        if self._task is not None or not self.enabled:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run(), name="intake-bound-monitor")
        log.info(
            "intake bounds on: [inbound].max_staged_depth=%d (resume at %d), "
            "[retention].min_free_disk_mb=%d on %s (every %gs)",
            self._max_depth,
            depth_resume_at(self._max_depth) if self.depth_bound_on else 0,
            self._floor_mb if self.disk_floor_on else 0,
            self._floor_path or "no SQLite store file",
            self._check_seconds,
        )

    async def stop(self) -> None:
        """Stop measuring and OPEN the gate. A stopped monitor can no longer see a condition clear,
        so it must not leave intake paused behind it: that would be a stall with nothing to end it."""
        self._stop.set()
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for reason in (DEPTH_REASON, DISK_REASON):
            self._gate.release(reason)
        # No intake_resumed here: the condition has not cleared, only stopped being watched.

    async def _run(self) -> None:
        # Engine.start measures once before the graph comes up, so the loop waits first rather
        # than repeating that read at once.
        skip_first = self._measured
        while not self._stop.is_set():
            if not skip_first:
                await self.check_once()
            skip_first = False
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), self._check_seconds)

    async def check_once(self) -> None:
        """One measurement of each enabled bound. A probe that fails, or hangs past
        :data:`PROBE_TIMEOUT_SECONDS`, leaves its reason as it was: an unmeasured backlog or disk is
        not evidence either way. The timeout is what keeps one hung probe from freezing the loop, and
        with it every later release.

        A bound that is OFF is reported clear once, so a pause left open by an earlier run is
        resolved after the operator turns that bound off or moves the store to a server backend."""
        self._measured = True
        if self.depth_bound_on:
            await self._check_depth()
        else:
            self._sync_alert(DEPTH_REASON, value=0, limit=0)
        if self.disk_floor_on:
            await self._check_disk()
        else:
            self._sync_alert(DISK_REASON, value=0, limit=0)

    async def _check_depth(self) -> None:
        try:
            # Capped one past the bound: the answer needed is "over it or not", and an uncapped
            # count would cost the most exactly when the backlog is largest.
            depth = await asyncio.wait_for(
                self._store.staged_intake_depth(limit=self._max_depth + 1), PROBE_TIMEOUT_SECONDS
            )
        except Exception:
            # Broad on purpose, like the retention floor check: this is an advisory read, and one
            # that raised must not kill the monitor task. Logged, with the cause, once per streak.
            if not self._depth_failing:
                self._depth_failing = True
                log.warning(
                    "intake pause: the staged-backlog depth read failed; the pause state is left "
                    "as it was until a read succeeds",
                    exc_info=True,
                )
            return
        self._depth_failing = False
        held = DEPTH_REASON in self._gate.reasons
        # One predicate for both the release and the alert, so the two cannot disagree.
        settled = depth <= depth_resume_at(self._max_depth)
        if not held and depth > self._max_depth:
            self._gate.hold(DEPTH_REASON)
            log.warning(
                "intake PAUSED: more than [inbound].max_staged_depth=%d staged messages (ingress + "
                "routed). The tcp, x12, http, mllp, dimse and timer inbounds stop reading and the "
                "file, remotefile and database pollers skip their poll (docs/CONFIGURATION.md); "
                "nothing already received is dropped or NAKed. Intake resumes at %d.",
                self._max_depth,
                depth_resume_at(self._max_depth),
            )
        elif held and settled:
            self._gate.release(DEPTH_REASON)
            self._log_resumed(
                "the staged backlog drained to %d (resume line %d)",
                depth,
                depth_resume_at(self._max_depth),
            )
        self._sync_alert(DEPTH_REASON, value=depth, limit=self._max_depth, settled=settled)

    async def _check_disk(self) -> None:
        assert self._floor_path is not None  # disk_floor_on
        failure: BaseException | None = None
        try:
            # A hung stat leaves its worker thread behind; the loop moves on regardless.
            reading = await asyncio.wait_for(
                asyncio.to_thread(read_disk_floor, self._floor_path, self._floor_mb),
                PROBE_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            # Broad on purpose, as in _check_depth; the cause is logged below, not swallowed.
            reading, failure = None, exc
        if reading is None or reading.free_bytes is None:
            if not self._disk_failing:
                self._disk_failing = True
                log.warning(
                    "intake pause: free space on the SQLite store's volume could not be measured; "
                    "the pause state is left as it was until a probe succeeds",
                    exc_info=failure,
                )
            return
        self._disk_failing = False
        held = DISK_REASON in self._gate.reasons
        resume_bytes = disk_resume_at(reading.floor_bytes)
        # One predicate for both the release and the alert, so the two cannot disagree.
        settled = reading.free_bytes >= resume_bytes
        if not held and reading.below:
            self._gate.hold(DISK_REASON)
            log.warning(
                "intake PAUSED: %s MiB free on the volume holding the SQLite store (%s), below the "
                "[retention].min_free_disk_mb floor of %d MiB. The tcp, x12, http, mllp, dimse and "
                "timer inbounds stop reading and the file, remotefile and database pollers skip "
                "their poll (docs/CONFIGURATION.md); nothing already received is dropped or NAKed. "
                "Intake resumes at %d MiB free. Free disk space or move the store to a larger "
                "volume.",
                reading.free_mib,
                reading.probed,
                reading.floor_mib,
                resume_bytes >> 20,
            )
        elif held and settled:
            self._gate.release(DISK_REASON)
            self._log_resumed(
                "free space on the SQLite store's volume is back to %s MiB (resume line %d MiB)",
                reading.free_mib,
                resume_bytes >> 20,
            )
        free_mib = reading.free_mib
        assert free_mib is not None  # free_bytes was measured, checked above
        self._sync_alert(DISK_REASON, value=free_mib, limit=reading.floor_mib, settled=settled)

    def _sync_alert(self, reason: str, *, value: int, limit: int, settled: bool = True) -> None:
        """Report ``reason``'s pause state to the sink if it differs from the last one reported:
        ``intake_paused`` on a pause, ``intake_resumed`` on a clear.

        ``settled`` is False while an unpaused measurement sits inside the hysteresis band, between
        the resume line and the bound. No clear is reported from there. The alert subject is shared
        by every node on the store, and another node may still hold its pause in that band, so a
        restarting node must not resolve it until the band is cleared. The cost falls on a single
        node that starts inside the band: a pause alert left open by its last run stays open until
        the measurement leaves the band. A missing page is worse than a late clear.

        A sink must never raise, but a broken one must not kill the monitor either: that would freeze
        every later release. A failed report is not recorded, so the next measurement the monitor
        takes retries it, with that measurement's value. A monitor with both bounds off measures
        only once, at start, so it does not retry."""
        paused = reason in self._gate.reasons
        if self._reported.get(reason) == paused:
            # Nothing to report. A failed report this state change made moot ends its streak, so
            # the next outage is logged again.
            self._sink_failing.discard(reason)
            return
        if not paused and not settled:
            return
        try:
            sink = self._alert_sink
            emit = sink.intake_paused if paused else sink.intake_resumed
            emit(
                intake_alert_subject(reason),
                reason=reason,
                value=value,
                limit=limit,
                store_kind=self._store_kind,
            )
        except Exception:
            if reason not in self._sink_failing:
                self._sink_failing.add(reason)
                log.warning(
                    "intake pause alert for %s could not be raised; the next measurement retries it",
                    reason,
                    exc_info=True,
                )
            return
        self._sink_failing.discard(reason)
        self._reported[reason] = paused

    def _log_resumed(self, what: str, *args: object) -> None:
        still = sorted(self._gate.reasons)
        if still:
            log.info("intake pause cleared: " + what + "; intake stays PAUSED by %s", *args, still)
        else:
            log.info("intake RESUMED: " + what, *args)
