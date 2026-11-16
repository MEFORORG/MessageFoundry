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

A WARNING marks the start of each pause and an INFO its end. Slice 3 adds the AlertSink pair, in the
house pattern of ``queue_buildup``: ``intake_paused`` when a pause starts, and again at most every
:data:`REALERT_SECONDS` while it holds, so a notifier's re-alert, escalation and suspend logic see a
condition that persists. ``intake_resumed``, its auto-resolving inverse, fires once when it ends.

**A subject nobody reminds about expires (BACKLOG #3269).** Each process names itself in its
subjects, so a subject whose process never comes back under that name has nobody left to clear it.
At least these do that: an unpinned cluster node that crashed while paused, a lone engine that
became several engine shards, an engine shard dropped from a shrinking engine shard count, and a
renamed or retired ``[cluster].node_id``. Every
monitor with a sink therefore sweeps the store's open ``intake_paused`` instances for subjects that
are not its own. One whose occurrence count has not moved for :data:`STALE_SECONDS` of this
monitor's own clock is resolved, bounded by the count it saw; a failed sweep read stretches that by
the gap and up to :data:`GAP_GRACE_SECONDS`, as :meth:`IntakeBoundMonitor.sweep_once` says. A live paused process raises a
reminder every :data:`REALERT_SECONDS`, which moves the count, so its alert stays open while those
writes land. A paused process cut off from the store cannot remind, so another process's sweep
expires its alert while it is still paused; its first reminder that lands again opens a new
instance. No monitor expires its own subjects, so a lone process sweeps only the subjects other
labels left behind, and a pause of its own whose clear did not land stays open for an operator. No
clock is compared across processes.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time

from messagefoundry.config.settings import StoreBackend
from messagefoundry.pipeline.alerts import (
    INTAKE_DEPTH_REASON,
    INTAKE_DISK_REASON,
    REMINDER_SECONDS,
    AlertSink,
)
from messagefoundry.pipeline.retention import read_disk_floor, sqlite_store_file
from messagefoundry.store import Store
from messagefoundry.subject_checksum import (  # re-exported: its callers import it from here
    shorten_with_checksum as shorten_with_checksum,
)
from messagefoundry.transports.base import IntakeGate

__all__ = [
    "DEPTH_REASON",
    "DISK_REASON",
    "GAP_GRACE_SECONDS",
    "INTAKE_SUBJECT_MAX_LENGTH",
    "PAUSE_EFFECT",
    "STALE_SECONDS",
    "SWEEP_SECONDS",
    "IntakeBoundMonitor",
    "depth_resume_at",
    "disk_resume_at",
    "intake_alert_subject",
    "process_alert_subject",
    "shorten_with_checksum",
]

log = logging.getLogger(__name__)

#: The two reasons this monitor holds the gate for. Separate, so a drained backlog cannot reopen
#: intake while the disk is still low, or the reverse.
DEPTH_REASON = INTAKE_DEPTH_REASON
DISK_REASON = INTAKE_DISK_REASON

#: How often the monitor measures. Bounds how far intake can run past a bound before the pause
#: lands (one interval of intake, plus at most one poll batch a poll source had already started).
DEFAULT_CHECK_SECONDS = 1.0

#: How long one probe may take before it counts as failed. A hung read must not freeze the loop.
PROBE_TIMEOUT_SECONDS = 10.0

#: While a pause holds, ``intake_paused`` fires again at most this often per bound: the reminder
#: spacing ``queue_buildup`` uses too, from one shared constant. Without it a one-second measurement
#: loop would write an alert-state row every second.
REALERT_SECONDS = REMINDER_SECONDS

#: What a pause does to each inbound family, shared by both pause WARNINGs (BACKLOG #2324). A dimse
#: inbound refuses only a NEW association (``transports/dicom.py``,
#: ``_refuse_association_while_paused``); one already open runs until its peer releases it, which is
#: the contract ``docs/CONFIGURATION.md`` states. Not a ``%`` template: it is passed as an argument.
PAUSE_EFFECT = (
    "The tcp, x12, http and mllp inbounds stop reading; the dimse inbounds refuse new associations, "
    "and an association already open keeps running until it ends; the timer, file, remotefile and "
    "database inbounds skip their tick (docs/CONFIGURATION.md). Nothing already received is dropped "
    "or NAKed."
)

#: The alert type the sweep expires (the event ``AlertSink.intake_paused`` records).
_PAUSED_EVENT = "intake_paused"

#: How long an open ``intake_paused`` subject that is not this process's may go with no new raise
#: before the sweep resolves it (BACKLOG #3269). A live paused process raises one every
#: :data:`REALERT_SECONDS`, and each raise is tried once, so four intervals leave a live alert open
#: through two failed reminders in a row, with a full interval left for drift and sweep spacing.
STALE_SECONDS = 4 * REALERT_SECONDS

#: How often a monitor sweeps for expired subjects. Coarse on purpose: the read is store-wide.
SWEEP_SECONDS = 60.0

#: What a failed sweep read leaves a watch, at least, once reads succeed again: its counted
#: staleness is held to :data:`STALE_SECONDS` minus this. A live process whose reminder the outage
#: ate raises its next within one reminder interval, and a sweep sees it within one sweep spacing;
#: twice the probe timeout covers a slow read on each side. Without it, staleness counted before the
#: outage could expire a live alert before that next reminder lands.
GAP_GRACE_SECONDS = REALERT_SECONDS + SWEEP_SECONDS + 2 * PROBE_TIMEOUT_SECONDS

#: The reminder clock, a module name so a test can move it without moving the event loop's.
_monotonic = time.monotonic


def depth_resume_at(max_staged_depth: int) -> int:
    """The depth at or below which a depth pause ends: 90% of the bound, and always at least one row
    below it, so a bound of 1 resumes only at 0. The gap is what stops the pause flapping on a
    backlog hovering at the bound."""
    return max(0, min(max_staged_depth - 1, (max_staged_depth * 9) // 10))


def disk_resume_at(floor_bytes: int) -> int:
    """The free bytes at or above which a disk pause ends: the floor plus a tenth of it."""
    return floor_bytes + floor_bytes // 10


#: The longest subject :func:`process_alert_subject` returns. Under the SQL Server store's 256-character
#: ``alert_instance.connection`` column, with room to spare. ``[cluster].node_id`` has no length limit,
#: so a node label too long to fit is shortened to a prefix plus a checksum of the whole label.
INTAKE_SUBJECT_MAX_LENGTH = 200


def intake_alert_subject(reason: str, node: str | None = None) -> str:
    """The alert subject for one bound on one engine process: ``intake:<reason>@<node>``, or
    ``intake:<reason>`` for a lone engine (``node`` None).

    One per bound, so a drained backlog cannot resolve a low-disk pause. One per process too
    (BACKLOG #2272 defects 4 to 6): every process on a store pauses its own listeners, so each raises
    and clears only its own alert, and one node's clear cannot resolve another node's pause. ``node``
    is :attr:`~messagefoundry.pipeline.engine.Engine.instance_identity` (``node:<id>`` or
    ``shard:<id>``).

    ``intake_paused`` is not connection-scoped, so no rule's ``control_action`` fires on it (BACKLOG
    #1898). The colon also keeps the subject out of the connection-name grammar, which guards only the
    default target, never a ``control_target``. The length cap is :func:`process_alert_subject`'s."""
    return process_alert_subject(f"intake:{reason}", node)


def process_alert_subject(base: str, node: str | None = None) -> str:
    """``base`` with this engine process appended: ``<base>@<node>``, or ``base`` alone for a lone
    engine (``node`` None). For an alert each process on a shared store raises about itself, so two
    processes never share one alert row. ``node`` is
    :attr:`~messagefoundry.pipeline.engine.Engine.instance_identity`.

    The result is at most :data:`INTAKE_SUBJECT_MAX_LENGTH` characters when ``base`` is short, as
    every caller's is, and the same inputs always give the same subject."""
    if node is None:
        return base
    return f"{base}@{shorten_with_checksum(node, INTAKE_SUBJECT_MAX_LENGTH - len(base) - len('@'))}"


class IntakeBoundMonitor:
    """Measure the two intake bounds and hold or release the shared gate. See the module docstring.

    Not leader-gated. Every node that runs the graph (every engine shard, the active node of an HA
    pair) pauses its own listeners against the one shared backlog. A standby runs the check too, with
    nothing to pause; the count is capped, so that costs one bounded read per interval.

    ``node`` names this process in its alert subjects (see :func:`intake_alert_subject`), so each
    process reports only its own gate. ``resolve_on_stop`` is for a process whose ``node`` changes
    on every start, an unpinned cluster node: its next start reports under a new subject and can
    never clear the old one, so :meth:`stop` clears it on the way out."""

    def __init__(
        self,
        store: Store,
        gate: IntakeGate,
        *,
        max_staged_depth: int = 0,
        min_free_disk_mb: int = 0,
        check_seconds: float = DEFAULT_CHECK_SECONDS,
        alert_sink: AlertSink | None = None,
        node: str | None = None,
        resolve_on_stop: bool = False,
    ) -> None:
        self._store = store
        self._gate = gate
        # The alert subject per reason, fixed for this monitor's life so a raise and its clear always
        # name the same instance.
        self._subjects = {r: intake_alert_subject(r, node) for r in (DEPTH_REASON, DISK_REASON)}
        self._own_subjects = frozenset(self._subjects.values())
        self._resolve_on_stop = resolve_on_stop
        # None = no notifier configured. Then nothing is raised: the monitor's own WARNING and INFO
        # lines are the log record, and a LoggingAlertSink would only repeat them.
        self._alert_sink = alert_sink
        # Per reason, the earliest monotonic time a held pause may raise intake_paused again.
        self._next_realert: dict[str, float] = {}
        # Per reason, the (value, limit) of the last measurement that succeeded. A reminder raised
        # while the probe keeps failing carries it, since there is no newer reading.
        self._last_reading: dict[str, tuple[int, int]] = {}
        # The payload's store_kind. A store with no ``backend`` attribute is SQLite, as in
        # sqlite_store_file. A backend that is present but not a StoreBackend (None, or a future
        # backend) is "unknown"; sqlite_store_file already keeps the disk floor off for it.
        backend = getattr(store, "backend", StoreBackend.SQLITE)
        self._store_kind = backend.value if isinstance(backend, StoreBackend) else "unknown"
        # The pause state last reported to the sink, per reason. Empty at first, so the first
        # measurement of each bound reports this process's state. A clear raises intake_resumed once,
        # which resolves a pause left open by a run that stopped while paused. After that, only a
        # change is reported.
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
        self._check_failing = False
        # Whether check_once has run, so the loop does not repeat Engine.start's first measurement.
        self._measured = False
        # BACKLOG #3269, the expiry sweep: per instance id, the count it last saw and the monotonic
        # time it first saw that count.
        self._watched: dict[int, tuple[int, float]] = {}
        # The monotonic time of the last sweep whose read succeeded, and whether a read has failed
        # since: the next good read moves every watch's start forward by the whole gap.
        self._last_read: float | None = None
        self._read_gap = False
        self._sweep_task: asyncio.Task[None] | None = None
        # The sweep steps ("read", "resolve") in a failing streak: one WARNING per step per streak.
        self._sweep_failing: set[str] = set()

    @property
    def depth_bound_on(self) -> bool:
        return self._max_depth > 0

    @property
    def disk_floor_on(self) -> bool:
        return self._floor_path is not None

    @property
    def _sweep_on(self) -> bool:
        """Whether the expiry sweep runs (BACKLOG #3269): wherever a sink is wired, bounds on or
        off, since a stale subject can outlive the config that raised it."""
        return self._alert_sink is not None

    @property
    def enabled(self) -> bool:
        """True when either bound applies. When False, :meth:`start` spawns no measuring task; the
        expiry sweep runs on its own task whenever a sink is wired."""
        return self.depth_bound_on or self.disk_floor_on

    def start(self) -> None:
        """Spawn the measuring loop when either bound applies, and the expiry sweep, in a task of
        its own, when a sink is wired. A slow sweep therefore never delays a measurement."""
        self._stop.clear()
        if self._sweep_on and self._sweep_task is None:
            self._sweep_task = asyncio.create_task(self._sweep_loop(), name="intake-alert-sweep")
        if self._task is not None or not self.enabled:
            return
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
        so it must not leave intake paused behind it: that would be a stall with nothing to end it.

        No ``intake_resumed`` is raised, because the condition has not cleared, only stopped being
        watched; the next start reports under the same subject. The exception is ``resolve_on_stop``,
        a process whose next start uses a different subject: it clears its open pauses here, since
        nothing else ever will. A process that dies without stopping still leaves them open, and so
        does one that stops: another process's sweep resolves them once nobody has raised them for
        :data:`STALE_SECONDS`, longer after a failed sweep read (:meth:`sweep_once`; BACKLOG
        #3269). A process stopped for longer than that therefore
        finds its pause resolved, and a pause that still holds at its next start opens a new
        instance."""
        self._stop.set()
        tasks = (self._task, self._sweep_task)
        self._task = self._sweep_task = None
        me = asyncio.current_task()
        # A count, not a flag: a caller that already took a cancel before calling stop() must not
        # make the tasks' own expected cancels read as a new one.
        baseline = me.cancelling() if me is not None else 0
        cancelled = False
        for task in tasks:
            if task is None:
                continue
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                # The task's own cancel is expected; a cancel of the caller is passed on once the
                # gate below has opened.
                cancelled = cancelled or (me is not None and me.cancelling() > baseline)
            except Exception:
                cancelled = cancelled or (me is not None and me.cancelling() > baseline)
                # A task that died must not stop the stop: the gate below still opens.
                log.warning("intake monitor task %s had failed", task.get_name(), exc_info=True)
        held = set(self._gate.reasons)
        for reason in (DEPTH_REASON, DISK_REASON):
            self._gate.release(reason)
        if self._resolve_on_stop:
            for reason in (DEPTH_REASON, DISK_REASON):
                if reason in held or self._reported.get(reason):
                    self._report_clear_on_stop(reason)
        if cancelled:
            raise asyncio.CancelledError

    def _report_clear_on_stop(self, reason: str) -> None:
        sink = self._alert_sink
        if sink is None:
            return
        value, limit = self._last_reading.get(reason, (0, 0))
        try:
            sink.intake_resumed(
                self._subjects[reason],
                reason=reason,
                value=value,
                limit=limit,
                store_kind=self._store_kind,
            )
        except Exception:
            # Broad on purpose, as in _sync_alert: a sink must never raise, and a broken one must not
            # break the stop. Logged with the cause.
            log.warning(
                "intake pause alert for %s could not be cleared at stop; resolve it in the alert list",
                reason,
                exc_info=True,
            )
            return
        self._reported[reason] = False

    async def _run(self) -> None:
        # Engine.start measures once before the graph comes up, so the loop waits first rather
        # than repeating that read at once.
        skip_first = self._measured
        while not self._stop.is_set():
            if not skip_first:
                try:
                    await self.check_once()
                except Exception:
                    # A defect in one check must not end measuring, and with it the gate's
                    # release, for the life of the process. Once per failing streak, as the
                    # class's other failure paths log, with the traceback.
                    if not self._check_failing:
                        self._check_failing = True
                        log.exception("intake bound check raised; it runs again each interval")
                else:
                    self._check_failing = False
            skip_first = False
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), self._check_seconds)

    async def _sweep_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.sweep_once()
            except Exception:
                # Broad on purpose: sweep_once guards its store calls, so this is a defect, and it
                # must not end expiry for the life of the process. Logged every time it happens.
                log.exception("intake pause alert sweep raised; it runs again next interval")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), SWEEP_SECONDS)

    async def sweep_once(self) -> int:
        """Resolve each open ``intake_paused`` subject of another process that has taken no raise
        for :data:`STALE_SECONDS` (BACKLOG #3269). Returns how many it resolved.

        Staleness is judged on this monitor's own monotonic clock, from the first sweep that saw
        the instance at its current count, so no other process's clock enters it. The resolve is
        bounded by that count (``resolve_alert_generation``): a reminder that lands between the read
        and the write moves the count past it, and the row stays open. A subject this process owns
        is skipped, since its own measurement raises and clears it. A failed read counts none of
        the time from the last good read to the next one, and keeps every watch: what a watch had
        counted stays counted, held to at most :data:`STALE_SECONDS` minus
        :data:`GAP_GRACE_SECONDS` at that next good read, so a live process whose reminder the
        outage ate has the grace to land its next one. Graces do not stack: a second failure
        inside one holds the watch to the same bound again. So a dead subject still expires once
        a run of good reads spans the grace, and stays open while reads fail more often than
        that. A failed
        resolve keeps that instance watched and the pass goes on to the rest. Each step's failure
        is logged once per failing streak.

        The resolve goes straight to the store, not through a sink: the subject is another
        process's, so this process's sink holds no state for it."""
        try:
            generations = await asyncio.wait_for(
                self._store.open_alert_generations(event_type=_PAUSED_EVENT), PROBE_TIMEOUT_SECONDS
            )
        except Exception:
            # Broad on purpose, as in _check_depth: an advisory read must not kill the sweep task.
            self._read_gap = True
            self._sweep_failed("read")
            return 0
        self._sweep_failing.discard("read")
        now = _monotonic()
        # The time since the last good read, when a read failed in between: none of it counts.
        gap = now - self._last_read if self._read_gap and self._last_read is not None else None
        self._last_read, self._read_gap = now, False
        watched: dict[int, tuple[int, float]] = {}
        expired = 0
        failed = False
        for gen in generations:
            if gen.connection in self._own_subjects:
                continue
            prev = self._watched.get(gen.id)
            if prev is None or prev[0] != gen.count:
                since = now
            elif gap is None:
                since = prev[1]
            else:
                # Held, not stacked: a second failure inside an earlier grace cannot push the
                # watch's start past where one grace would put it.
                since = max(prev[1] + gap, now + GAP_GRACE_SECONDS - STALE_SECONDS)
            if now - since < STALE_SECONDS:
                watched[gen.id] = (gen.count, since)
                continue
            try:
                # No wait_for: cancelling a write on SQLite's one writer connection would leave a
                # transaction to unwind. The store's own busy and command timeouts bound it.
                resolved = await self._store.resolve_alert_generation(
                    alert_id=gen.id, through_count=gen.count
                )
            except Exception:
                # Broad, as above. Kept watched, so the next sweep tries this instance again.
                watched[gen.id] = (gen.count, since)
                failed = True
                self._sweep_failed("resolve")
                continue
            if resolved:
                expired += resolved
                # The subject names the operator's own node or engine shard, never message content.
                log.info(
                    "intake pause alert %s expired: no process has raised it for at least %ds",
                    gen.connection,
                    int(now - since),
                )
        self._watched = watched
        if not failed:
            self._sweep_failing.discard("resolve")
        return expired

    def _sweep_failed(self, step: str) -> None:
        """One WARNING per failing streak. Called from inside the ``except`` so the cause is logged."""
        if step not in self._sweep_failing:
            self._sweep_failing.add(step)
            log.warning(
                "intake pause alert sweep: the %s failed; stale subjects stay open until a sweep "
                "succeeds",
                step,
                exc_info=True,
            )

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
            self._remind_unmeasured(DEPTH_REASON)
            return
        self._depth_failing = False
        held = DEPTH_REASON in self._gate.reasons
        if not held and depth > self._max_depth:
            self._gate.hold(DEPTH_REASON)
            log.warning(
                "intake PAUSED: more than [inbound].max_staged_depth=%d staged messages (ingress + "
                "routed). %s Intake resumes at %d.",
                self._max_depth,
                PAUSE_EFFECT,
                depth_resume_at(self._max_depth),
            )
        elif held and depth <= depth_resume_at(self._max_depth):
            self._gate.release(DEPTH_REASON)
            self._log_resumed(
                "the staged backlog drained to %d (resume line %d)",
                depth,
                depth_resume_at(self._max_depth),
            )
        self._sync_alert(DEPTH_REASON, value=depth, limit=self._max_depth)

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
            self._remind_unmeasured(DISK_REASON)
            return
        self._disk_failing = False
        held = DISK_REASON in self._gate.reasons
        resume_bytes = disk_resume_at(reading.floor_bytes)
        if not held and reading.below:
            self._gate.hold(DISK_REASON)
            log.warning(
                "intake PAUSED: %s MiB free on the volume holding the SQLite store (%s), below the "
                "[retention].min_free_disk_mb floor of %d MiB. %s Intake resumes at %d MiB free. "
                "Free disk space or move the store to a larger volume.",
                reading.free_mib,
                reading.probed,
                reading.floor_mib,
                PAUSE_EFFECT,
                resume_bytes >> 20,
            )
        elif held and reading.free_bytes >= resume_bytes:
            self._gate.release(DISK_REASON)
            self._log_resumed(
                "free space on the SQLite store's volume is back to %s MiB (resume line %d MiB)",
                reading.free_mib,
                resume_bytes >> 20,
            )
        free_mib = reading.free_mib
        assert free_mib is not None  # free_bytes was measured, checked above
        self._sync_alert(DISK_REASON, value=free_mib, limit=reading.floor_mib)

    def _sync_alert(self, reason: str, *, value: int, limit: int) -> None:
        """Report ``reason``'s pause state to the sink: ``intake_paused`` when a pause starts and
        again every :data:`REALERT_SECONDS` while it holds, and ``intake_resumed`` once when it
        clears. A new pause always reports at once, so one that starts soon after the last is never
        held back here; the notifier's own throttle decides whether it pages.

        The alert mirrors THIS process's gate, not the store's: the subject names the process, so no
        other node's pause rides on it (#2272 defects 5 and 6). A process that starts with its gate
        open therefore reports the clear at once, even inside the hysteresis band between the resume
        line and the bound, and a pause its own last run left open resolves at its first measurement.

        A sink must never raise, but a broken one must not kill the monitor either: that would freeze
        every later release. A failed report is not recorded, so the next measurement the monitor
        takes retries it, with that measurement's value. A monitor with both bounds off measures
        only once, at start, so it does not retry. With no sink there is nothing to report."""
        self._last_reading[reason] = (value, limit)
        sink = self._alert_sink
        if sink is None:
            return
        paused = reason in self._gate.reasons
        now = _monotonic()
        reminder_due = paused and now >= self._next_realert.get(reason, 0.0)
        if self._reported.get(reason) == paused and not reminder_due:
            # Nothing to report. A failed report this state change made moot ends its streak, so
            # the next outage is logged again.
            self._sink_failing.discard(reason)
            return
        try:
            emit = sink.intake_paused if paused else sink.intake_resumed
            emit(
                self._subjects[reason],
                reason=reason,
                value=value,
                limit=limit,
                store_kind=self._store_kind,
            )
            raised = True
        except Exception:
            raised = False
            if reason not in self._sink_failing:
                self._sink_failing.add(reason)
                log.warning(
                    "intake pause alert for %s could not be raised; the next measurement retries it",
                    reason,
                    exc_info=True,
                )
        if paused:
            # Spaced from the ATTEMPT, so a sink that refuses a reminder is not called again every
            # second. A refused pause edge is still retried at once: _reported was not set for it.
            # Read AFTER the call returns (#2272): the notifier stamps its own cooldown inside the
            # call, so a window measured from before it could close a moment early and land the
            # next reminder inside that cooldown, where it is throttled for a whole interval.
            self._next_realert[reason] = _monotonic() + REALERT_SECONDS
        if not raised:
            return
        self._sink_failing.discard(reason)
        self._reported[reason] = paused

    def _remind_unmeasured(self, reason: str) -> None:
        """Keep reminding about a held pause while its probe fails (#2272). The gate stays held, so
        intake stays paused, and silence would read as a pause that ended. The reminder carries the
        last reading taken. A pause that is not held reports nothing: an unmeasured bound is neither
        paused nor clear."""
        last = self._last_reading.get(reason)
        if last is not None and reason in self._gate.reasons:
            self._sync_alert(reason, value=last[0], limit=last[1])

    def _log_resumed(self, what: str, *args: object) -> None:
        still = sorted(self._gate.reasons)
        if still:
            log.info("intake pause cleared: " + what + "; intake stays PAUSED by %s", *args, still)
        else:
            log.info("intake RESUMED: " + what, *args)
