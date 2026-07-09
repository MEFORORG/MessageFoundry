# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The pooled-mode per-stage runner — ``StageDispatcher`` (ADR 0066 §4).

One dispatcher per stage replaces the per-inbound router/transform + per-outbound delivery workers
when ``[pipeline].claim_mode = pooled``. It multiplexes *many* lanes onto a small pool of **claimer**
tasks (default one) that batch-claim contiguous head-prefixes across lanes in a single
:meth:`~messagefoundry.store.base.QueueStore.claim_fifo_heads` round-trip, a clock-driven **sweep**
that is the bounded at-least-once backstop, and an ephemeral per-lane **serializer** task that
processes each claimed prefix strictly oldest-first. Correctness rests on a small per-lane **state
machine** (this module) that permits *at most one* outstanding claim-or-processing episode per lane —
so per-lane FIFO holds by construction and the pooled claimer is every lane's single logical consumer,
time-multiplexed (ADR 0066 §4.5 / §7). This is the FIFO guard leaving the SQL layer and becoming
application code, so the machine is deliberately small, exhaustively unit-tested, and guarded by a
``busy_violations`` tripwire.

**Unwired in this PR (ADR 0066 PR3).** Nothing in production constructs a ``StageDispatcher`` yet — it
is imported only by its tests. ``RegistryRunner`` wiring, the ``claim_mode`` flag, and adapting the
four ``_process_*_item`` bodies to return :class:`LaneItemResult` are PR4. The dispatcher depends only
on injected callables/values (a store, a ``process_item`` body-callable, a ``lane_provider``, plain
knobs) — never on ``RegistryRunner`` — which keeps this module free of an import cycle and makes the
PR4 wiring a typed constructor contract rather than a coupling.

**Concurrency discipline.** All dispatcher state is mutated **only on the event loop, never under a
lock** (mirroring the runner's ``_lane_events`` / ``EmptyClaimCounters``): every transition is
synchronous except a claimer's single ``await claim_fifo_heads`` and a serializer's ``await
process_item`` / ``await release_claimed``. A state read must never be separated from its mutation by an
``await`` — the conservation law (``slots_free + processing_lanes + reserved == max_processing_lanes``)
and the ``busy_violations`` counter assert this holds.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Protocol

from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.phase_timing import ClaimPhaseTiming, delivery_phase_timing_enabled
from messagefoundry.store import ClaimedHeads, OutboxItem, QueueStore, Stage

log = logging.getLogger(__name__)

# Per-lane re-arm delay after an UNEXPECTED serializer exception — parity with the runner's worker
# backoff (wiring_runner._WORKER_ERROR_BACKOFF_SECONDS). Only the faulting lane pauses; siblings and
# the claimer are untouched.
_LANE_ERROR_BACKOFF_SECONDS = 1.0
# Claimer store-error backoff: the whole chunk's lanes return to READY and this claimer's partition
# pauses ~this long (chunk-scoped; raise K to shrink the blast radius). ADR 0066 §11 item 1.
_CLAIM_ERROR_BACKOFF_SECONDS = 1.0


class LaneResultKind(Enum):
    """How the injected ``process_item`` body resolved one claimed row — the pooled analog of the
    per_lane loop's control flow, carrying the park deadline the ``_ItemOutcome`` two-member enum
    deliberately cannot (wiring_runner ``_ItemOutcome`` docstring)."""

    # terminal for this pass (handed off / delivered / dead-lettered) — advance to the next item.
    RESOLVED = auto()
    # re-pended with backoff (the body already called mark_failed) — PARK the lane until retry_until.
    RETRY = auto()
    # the lane must halt (a STOP internal-error policy / missing-inbound exit) — STOP the lane.
    STOP = auto()


@dataclass(frozen=True)
class LaneItemResult:
    """The dispatcher's input contract (ADR 0066 §4.5). The body owns the *head's* terminal store write
    per outcome BEFORE returning — RETRY: it has already ``mark_failed``'d the head and returns that
    additive ``next_attempt_at`` as ``retry_until``; RESOLVED: it has marked the head done /
    dead-lettered; STOP: it has ``mark_failed``'d (or left) the head per policy. The dispatcher only
    handles the unprocessed *tail* (``release_claimed``) and the lane state transition."""

    kind: LaneResultKind
    retry_until: float | None = None

    def __post_init__(self) -> None:
        # retry_until is meaningful iff RETRY (the park deadline). Guard the contract so a mis-built
        # result fails loudly in tests rather than silently parking forever / not at all.
        if (self.kind is LaneResultKind.RETRY) != (self.retry_until is not None):
            raise ValueError("retry_until must be set iff kind is RETRY")


class _LanePhase(Enum):
    """The per-lane phase. A slot is held by CLAIMING (reserved) and PROCESSING (consumed); never by
    IDLE / READY / PARKED / STOPPED / PAUSED (those hold zero decrypted bodies)."""

    IDLE = auto()  # no work known; not queued
    READY = auto()  # queued on its claimer's ready-deque, awaiting a claim
    CLAIMING = auto()  # in the current claim_fifo_heads batch (slot reserved)
    PROCESSING = auto()  # a live serializer is draining its claimed prefix (slot consumed)
    PARKED = auto()  # head backing off until park_until; unpark by timer / sweep-due / notify_work
    STOPPED = auto()  # deliberately halted; re-armed only by reload / notify_work
    # Operator PAUSE (connection controls): delivery halted by an operator; queued rows RETAINED PENDING.
    # A NEW distinct phase — NOT STOPPED, which notify_work/reload deliberately resurrect and which means
    # content-STOP. PAUSED is reload-surviving: only pause_lane's counterpart resume_lane re-arms it; a
    # /config/reload or DR broadcast must never bring a deliberately-paused lane back (see notify_work).
    PAUSED = auto()


@dataclass
class _LaneState:
    phase: _LanePhase = _LanePhase.IDLE
    # "a wake landed while this lane could not claim-me-now; re-arm at the end of the episode." Set by
    # mark_ready in CLAIMING/PROCESSING/PARKED/STOPPED; cleared on entry to READY and CLAIMING. A
    # no-op/harmless in IDLE/READY (nothing reads it there).
    dirty: bool = False
    # Whether the wake(s) that set ``dirty`` included a PRODUCER wake (sticky-OR) vs only the clock-driven
    # sweep. The dirty re-arm (T14) passes this as ``ready_woken`` so a sweep-only dirty stays
    # sweep-sourced — otherwise a sweep racing a serializer would flip a backlog-draining lane to
    # wake-sourced and silently defeat T13b's greedy drain. Meaningful only while ``dirty`` is True.
    dirty_woken: bool = False
    park_until: float | None = None
    # D5: how this lane was last made READY (a producer wake vs the clock-driven sweep), so an EMPTY
    # claim is attributed to the right EmptyClaimCounters bucket (wake-fanout vs idle-poll).
    ready_woken: bool = True
    # ADR 0070 fix B: consecutive zero-progress (i==0) T17 infra faults for this lane. Incremented on
    # each such fault, reset to 0 on clean drain / forward-progress-or-non-infra RETRY / the STOPPED→
    # READY notify_work resume (NEVER on a PARKED park-timer/sweep unpark — the sharp edge, §3). Reaches
    # infra_fault_stop_after → STOP (stop policy). In-memory only; intentionally lost on restart.
    infra_error_streak: int = 0
    # ADR 0070 retry_forever: True once the throttled lane_stuck alert has fired for the current stuck
    # episode (so it fires once per horizon crossing, not per fault). Cleared alongside the streak.
    lane_stuck_alerted: bool = False
    # Connection controls: an operator pause_lane landed while the lane was mid-episode
    # (CLAIMING/PROCESSING) and so could not go PAUSED immediately (a slot is reserved / a serializer is
    # draining its <=1 in-flight head). Set here; the terminal transition (PROCESSING) or the next empty
    # claim (CLAIMING) routes the now-quiesced lane to PAUSED and fires on_lane_paused — letting the head
    # finish first (COOPERATIVE, never a task.cancel). Meaningful only in CLAIMING/PROCESSING.
    pause_pending: bool = False


@dataclass
class _Claimer:
    """One claimer partition: a ready-deque (FIFO fairness across lanes) + a companion membership set
    for O(1) coalescing (never enqueue a lane twice) + a wake Event. ``task`` is filled at start()."""

    ready: deque[str] = field(default_factory=deque)
    ready_set: set[str] = field(default_factory=set)
    event: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task[None] | None = None


@dataclass(frozen=True)
class _LaneOutcome:
    """Internal: how a serializer's whole prefix resolved, computed inside the task, applied
    synchronously after the (async) tail release so the final state transition is atomic on the loop."""

    kind: LaneResultKind | None  # None == every item RESOLVED (clean lane_done)
    park_until: float | None = None
    # ADR 0070 fix B: True ONLY when set by the :540 T17 machinery except-branch (a store/handoff/infra
    # fault) — the per-item body RETRY (:534) and every content STOP/dead-letter path stay False. This
    # is the single discriminator that drives the infra-fault streak; a wrong True here would let a
    # content poison trip the STOP-the-lane bound (sharp edge §2).
    is_infra_fault: bool = False
    # (i > 0): the prefix made forward progress (>=1 item RESOLVED) before the fault, so this is NOT a
    # head-of-line-blocked zero-progress fault — it resets the streak rather than accruing it.
    made_progress: bool = False


# Timer scheduler seam (injectable for deterministic tests). Mirrors loop.call_later's shape.
_CallLater = Callable[[float, Callable[[], object]], asyncio.TimerHandle]
# The body-callable the serializer invokes per claimed row (PR4 binds the real _process_*_item).
_ProcessItem = Callable[[str, OutboxItem], Awaitable[LaneItemResult]]


class _EmptyClaimObserver(Protocol):
    """The empty-claim accounting sink the dispatcher delegates to (ADR 0066 PR4, B11 split). PR4
    injects the runner's ``EmptyClaimCounters`` here so a dispatcher empty claim lands in the SAME
    ``/stats`` counters the per_lane workers feed — a **structural** contract (record_empty only), so
    the dispatcher never imports ``EmptyClaimCounters`` (no PR4 import cycle). When ``None`` is passed
    the dispatcher uses a private :class:`_LocalEmptyCounter`, so PR3 stays self-contained."""

    def record_empty(self, *, woken: bool) -> None: ...


@dataclass
class _LocalEmptyCounter:
    """The private default empty-claim counter when no ``empty_counter`` is injected (PR3 / tests) —
    the same (total, wake_fanout, idle_poll) split the runner's ``EmptyClaimCounters`` exposes, so the
    :attr:`StageDispatcher.empty_claims` accessor works identically either way."""

    total: int = 0
    idle_poll: int = 0
    wake_fanout: int = 0

    def record_empty(self, *, woken: bool) -> None:
        self.total += 1
        if woken:
            self.wake_fanout += 1
        else:
            self.idle_poll += 1


class StageDispatcher:
    """The pooled-mode runner for ONE stage. See the module docstring for the topology. Construct one
    per stage; call :meth:`mark_ready` from every producer (sync, await-free, ``Event.set()``-shaped),
    :meth:`notify_work` for recovery broadcasts, and :meth:`start` / :meth:`stop` for lifecycle."""

    def __init__(
        self,
        stage: Stage,
        store: QueueStore,
        *,
        process_item: _ProcessItem,
        lane_provider: Callable[[], set[str]],
        per_lane_limit: int,
        claimers_per_stage: int = 1,
        sweep_interval: float = 0.25,
        claim_lane_chunk: int = 200,
        max_processing_lanes: int = 256,
        sweep_page_limit: int = 4096,
        stop_event: asyncio.Event | None = None,
        alert_sink: AlertSink | None = None,
        on_lane_paused: Callable[[str], None] | None = None,
        empty_counter: _EmptyClaimObserver | None = None,
        clock: Callable[[], float] | None = None,
        call_later: _CallLater | None = None,
        infra_fault_policy: str = "stop",
        infra_fault_stop_after: int = 10,
        infra_fault_backoff_cap: float = 60.0,
    ) -> None:
        assert claimers_per_stage >= 1
        assert max_processing_lanes >= 1
        assert infra_fault_policy in ("stop", "retry_forever")
        assert infra_fault_stop_after >= 1
        assert infra_fault_backoff_cap > 0
        # claim_lane_chunk stays <= the SMALLEST backend claim clamp (SQLite _FIFO_HEADS_LANE_CHUNK=200;
        # SS/PG=500) so the store never silently drops clamped-off lanes (its "caller covers the
        # remainder" contract is honored by the deque holding the excess for the next claimer pass, not
        # by over-sending). PR4 may raise it per-backend once wired.
        assert claim_lane_chunk >= 1
        assert per_lane_limit >= 1
        self._stage = stage
        self._store = store
        self._process_item = process_item
        self._lane_provider = lane_provider
        # OUTBOUND/RESPONSE are hard-1 in the store (H2 atomicity); keep the caller's knob honest so the
        # claim's per-lane prefix and the serializer agree on batch size.
        self._per_lane_limit = 1 if stage in (Stage.OUTBOUND, Stage.RESPONSE) else per_lane_limit
        self._sweep_interval = sweep_interval
        self._claim_lane_chunk = claim_lane_chunk
        self._max_processing_lanes = max_processing_lanes
        self._sweep_page_limit = sweep_page_limit
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        # Connection controls: fired (if set) whenever a lane REACHES the PAUSED phase — the runner wires
        # this to set its per-outbound quiescence Event, so 'stopped' means zero in-flight (not merely
        # pause-requested). None keeps PR3/tests self-contained.
        self._on_lane_paused = on_lane_paused
        self._clock: Callable[[], float] = clock or time.time
        self._call_later = call_later  # resolved to loop.call_later at start() when None
        # Pooled T17 (infra/machinery-fault) bound (ADR 0070 fix B). Policy "stop" STOPs a persistently
        # head-of-line-blocked lane after this many consecutive zero-progress infra faults; "retry_forever"
        # never STOPs (alert-only). The backoff cap bounds fix A's exponential head re-pend.
        self._infra_fault_policy = infra_fault_policy
        self._infra_fault_stop_after = infra_fault_stop_after
        self._infra_fault_backoff_cap = infra_fault_backoff_cap

        self._states: dict[str, _LaneState] = {}
        self._claimers: list[_Claimer] = [_Claimer() for _ in range(claimers_per_stage)]
        # Bench-gated claim-phase timing (default OFF, read ONCE here — never per claim). A claimer's
        # loop is serial, so this stage's lanes are re-fed at most K times per claim round-trip; timing
        # the round-trip makes that bound measurable instead of inferred (see phase_timing.py).
        self._claim_phase_timing = delivery_phase_timing_enabled()
        self._claim_phase_stats = ClaimPhaseTiming(logger=log)
        self._sweep_task: asyncio.Task[None] | None = None
        self._sweep_now = asyncio.Event()
        # Per-lane coalesced timer handles + their armed deadlines (earliest-wins refresh).
        self._timers: dict[str, asyncio.TimerHandle] = {}
        self._timer_deadline: dict[str, float] = {}
        # Live serializer tasks; len == number of PROCESSING lanes.
        self._lane_tasks: dict[str, asyncio.Task[None]] = {}
        self._slots_free = max_processing_lanes
        self._stop = stop_event or asyncio.Event()
        self._running = False

        # Empty-claim accounting (B11 split). Delegated to the injected observer so a dispatcher empty
        # claim lands in the SAME /stats counters the per_lane workers feed (PR4 passes the runner's
        # EmptyClaimCounters); the structural _EmptyClaimObserver contract keeps this import-cycle-free.
        # None -> a private _LocalEmptyCounter, so PR3 / tests stay self-contained.
        self._empty: _EmptyClaimObserver = empty_counter or _LocalEmptyCounter()
        # Debug tripwire: the one-consumer-per-lane invariant. Must stay 0 (the 200-lane soak asserts).
        self._busy_violations = 0

    # --- lane -> claimer partition ------------------------------------------

    def _owning_claimer(self, lane: str) -> _Claimer:
        """Stable lane->claimer assignment (K=1 default: everything to claimer 0). ``hash`` is the
        builtin (process-stable), never hashlib — no crypto-inventory surface."""
        if len(self._claimers) == 1:
            return self._claimers[0]
        return self._claimers[hash(lane) % len(self._claimers)]

    def _enqueue(self, lane: str) -> None:
        """Append the lane to its claimer's ready-deque (dedup via the companion set) and wake it."""
        claimer = self._owning_claimer(lane)
        if lane not in claimer.ready_set:
            claimer.ready.append(lane)
            claimer.ready_set.add(lane)
        claimer.event.set()

    # --- wake surface (T1-T7) ------------------------------------------------

    def mark_ready(self, key: str, *, woken: bool = True) -> None:
        """Signal that lane ``key`` may have work — SYNC and await-free (``Event.set()`` shape), so
        every producer call site is unchanged in cost. Applies the state machine by current phase
        (ADR 0066 §4.2). Create-or-stick on an unknown key (never drop): a wake to a not-yet-registered
        lane must stick, covering the reload window and a loopback RESPONSE lane's first wake — the
        exact contract of the runner's ``_lane_event`` get-or-create. ``woken`` is False when the
        clock-driven sweep is the source (D5), so an ensuing EMPTY claim is booked as idle-poll, not
        wake-fanout."""
        st = self._states.get(key)
        if st is None:  # T1: create-or-stick
            self._states[key] = _LaneState(phase=_LanePhase.READY, ready_woken=woken)
            self._enqueue(key)
            return
        phase = st.phase
        if phase is _LanePhase.IDLE:  # T2
            st.phase = _LanePhase.READY
            st.dirty = False
            st.ready_woken = woken
            self._enqueue(key)
        elif phase is _LanePhase.READY:  # T3 — coalesced (already queued)
            return
        else:  # T4 CLAIMING / T5 PROCESSING / T6 PARKED / T7 STOPPED / PAUSED — remember, don't claim
            # PAUSED lands here too: the transform-handoff wake-leak (_wake_lane -> mark_ready keeps
            # firing on a paused outbound whose routing/transform still produces rows) sets dirty but
            # NEVER enqueues, so a wake can never re-arm a paused lane — resume_lane clears dirty (via the
            # IDLE->READY mark_ready) when the operator resumes. This is THE pooled pause wake-leak fix.
            # Track the wake source for the dirty re-arm (T14): fresh on this episode's first wake, then
            # sticky-OR (any producer wake ⇒ wake-sourced). Self-initializing — no reset needed at the
            # dirty=False sites, since a new episode's first wake (st.dirty is False) overwrites it.
            st.dirty_woken = (st.dirty and st.dirty_woken) or woken
            st.dirty = True

    def notify_work(self) -> None:
        """Recovery broadcast (replay, DR failback, reload tail, post-recovery nudge): mark every known
        + registry lane READY, UNPARK every PARKED lane and re-arm every STOPPED lane (the broadcast
        overrides a park/stop), then request an immediate sweep. Snapshots the lane set before iterating
        so a concurrent producer can't raise 'set changed size during iteration' (mirrors ``_wake_all``,
        wiring_runner:487)."""
        lanes = set(self._states) | self._lane_provider()
        for lane in lanes:
            st = self._states.get(lane)
            if st is not None and st.phase is _LanePhase.PAUSED:
                # Reload-survival (connection controls): a recovery broadcast must NEVER resurrect a
                # deliberately operator-PAUSED lane (only resume_lane re-arms it). Skip it entirely —
                # BEFORE the PARKED/STOPPED unpark or the else mark_ready would re-ready it.
                continue
            if st is not None and st.phase in (_LanePhase.PARKED, _LanePhase.STOPPED):
                self._unpark(lane, woken=True)  # override the park/stop (T18/T19)
            else:
                self.mark_ready(lane, woken=True)
        self._sweep_now.set()

    # --- operator pause / resume (connection controls) -----------------------

    def _fire_paused(self, lane: str) -> None:
        """Notify the runner (if wired) that ``lane`` has REACHED the PAUSED phase — the quiescence
        signal the runner's per-outbound ``outbound_quiesced`` Event keys on (delivery halted, zero
        in-flight). Fired exactly once per pause episode, at whichever site drives the lane to PAUSED."""
        if self._on_lane_paused is not None:
            self._on_lane_paused(lane)

    def pause_lane(self, key: str) -> None:
        """Operator PAUSE for one lane (sync, await-free). PAUSED is a NEW distinct phase from STOPPED
        (which notify_work/reload resurrect and which means content-STOP): it RETAINS the lane's queued
        rows PENDING (no drop / no reorder) and halts delivery; only :meth:`resume_lane` re-arms it.

        COOPERATIVE — NEVER ``task.cancel`` a serializer: a cancelled mid-delivery row strands its
        claimed row INFLIGHT forever (``reset_stale_inflight`` is startup/DR-only), which purge's
        PENDING-only ``cancel_queued`` could never clear. So a lane mid-episode (CLAIMING/PROCESSING) is
        marked ``pause_pending`` and reaches PAUSED at the terminal transition / next empty claim, after
        its <=1 in-flight OUTBOUND head finishes (delivered, or re-pended PENDING by a FIFO RETRY) —
        leaving zero rows INFLIGHT, which is exactly the require-stopped-before-purge precondition."""
        st = self._states.get(key)
        if st is None:  # not yet registered — create it already PAUSED so a first wake can't arm it
            self._states[key] = _LaneState(phase=_LanePhase.PAUSED)
            self._fire_paused(key)
            return
        phase = st.phase
        if phase is _LanePhase.PAUSED:  # idempotent — already paused (and already fired)
            return
        if phase in (_LanePhase.IDLE, _LanePhase.READY, _LanePhase.PARKED):
            # No slot held, no live serializer: pause NOW. A stale ready-deque entry (READY) is skipped
            # at _assemble_chunk (phase != READY); a PARKED backoff timer is cancelled here.
            self._cancel_timer(key)
            st.phase = _LanePhase.PAUSED
            st.pause_pending = False
            st.dirty = False
            self._fire_paused(key)
        elif phase in (_LanePhase.CLAIMING, _LanePhase.PROCESSING):
            # Mid-episode: defer (a slot is held / a serializer is draining). The terminal transition
            # (PROCESSING) or the empty-claim branch (CLAIMING) routes it to PAUSED and fires. Do NOT
            # touch phase here — the reserved/consumed slot is released at that quiesce point.
            st.pause_pending = True
        else:  # STOPPED — operator intent overrides a content-STOP
            st.phase = _LanePhase.PAUSED
            st.pause_pending = False
            self._fire_paused(key)

    def resume_lane(self, key: str) -> None:
        """Operator RESUME for a paused lane (sync). Re-arm a fully-PAUSED lane from the head via
        ``mark_ready`` AND request an immediate sweep, so a head that backed off while paused is
        re-evaluated promptly (never stranded until the next periodic sweep) — folds the low finding on a
        resumed-lane RETRY head. An unknown lane is a no-op.

        CANCEL A STILL-PENDING PAUSE: a lane paused while mid-episode (CLAIMING/PROCESSING) carries
        ``pause_pending`` and has NOT yet reached PAUSED. A ``restart_outbound`` calls stop+start in ONE
        synchronous lock span, so resume can land in that window — just clear ``pause_pending`` and let
        the in-flight episode continue normally (never route to PAUSED). Without this the lane would
        quiesce to PAUSED after resume returned, with nothing left to re-arm it (a wedged lane)."""
        st = self._states.get(key)
        if st is None:
            return
        if st.phase in (_LanePhase.CLAIMING, _LanePhase.PROCESSING):
            st.pause_pending = (
                False  # cancel the not-yet-landed pause; the episode resumes normally
            )
            return
        if st.phase is not _LanePhase.PAUSED:
            return
        st.pause_pending = False
        st.phase = _LanePhase.IDLE
        self.mark_ready(key, woken=True)  # IDLE -> READY + enqueue (T2)
        self._sweep_now.set()

    # --- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Spawn the K claimer tasks + the sweep task, SEED every registry lane READY, and run ONE
        immediate sweep — the claim-first parity that makes ``reset_stale_inflight``-recovered rows
        (re-pended with ``next_attempt_at ~= now``) reachable with no wake at all (ADR 0066 §4.4)."""
        if self._running:
            return
        self._running = True
        self._stop.clear()
        # Clear the latched teardown signals so a start()-after-stop() (a PR4 restart-in-place) begins
        # clean — stop() SETs these to break the tasks out of their waits; a stale set would otherwise
        # spuriously wake a fresh claimer / trigger one extra immediate sweep.
        self._sweep_now.clear()
        for claimer in self._claimers:
            claimer.event.clear()
        if self._call_later is None:
            self._call_later = asyncio.get_running_loop().call_later
        for lane in self._lane_provider():
            self.mark_ready(lane, woken=False)  # seed-all-READY (recovery-source, not a wake)
        for i, claimer in enumerate(self._claimers):
            claimer.task = asyncio.create_task(self._claimer_loop(claimer), name=f"claimer-{i}")
            claimer.task.add_done_callback(functools.partial(self._on_task_done, f"claimer-{i}"))
        self._sweep_task = asyncio.create_task(self._sweep_loop(), name="sweep")
        self._sweep_task.add_done_callback(functools.partial(self._on_task_done, "sweep"))
        await self._run_sweep_once()  # immediate first sweep (arms due lanes / not-due timers)

    async def stop(self) -> None:
        """Tear down: signal stop, wake every claimer + the sweep, cancel all tasks + timers, gather,
        then clear state POST-gather (never mid-run). Idempotent (mirrors ``_teardown_unsafe``). A
        cancelled serializer leaves its claimed rows INFLIGHT — ``reset_stale_inflight`` re-pends them
        on restart; we deliberately do NOT release_claimed on cancellation (crash-safety, ADR 0066)."""
        self._stop.set()
        self._sweep_now.set()
        for claimer in self._claimers:
            claimer.event.set()
        tasks: list[asyncio.Task[None]] = []
        for claimer in self._claimers:
            if claimer.task is not None:
                claimer.task.cancel()
                tasks.append(claimer.task)
        if self._sweep_task is not None:
            self._sweep_task.cancel()
            tasks.append(self._sweep_task)
        for task in list(self._lane_tasks.values()):
            task.cancel()
            tasks.append(task)
        for handle in self._timers.values():
            handle.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # POST-gather clear — safe now that every task is done (mirrors _teardown_unsafe:1187-1204).
        self._states.clear()
        self._timers.clear()
        self._timer_deadline.clear()
        self._lane_tasks.clear()
        for claimer in self._claimers:
            claimer.ready.clear()
            claimer.ready_set.clear()
            claimer.task = None
        self._slots_free = self._max_processing_lanes
        self._running = False

    def _on_task_done(self, name: str, task: asyncio.Task[None]) -> None:
        """Claimer/sweep supervision — these should only finish on shutdown (their loops swallow +
        back off). If one dies unexpectedly while running, log; respawning the whole loop is a PR4
        concern (the dispatcher is unwired here), so PR3 surfaces it loudly rather than silently
        stalling a stage. Expected cancellation/stop is a no-op."""
        if self._stop.is_set() or not self._running or task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.error(
                "StageDispatcher %s task %r exited unexpectedly",
                self._stage.value,
                name,
                exc_info=exc,
            )

    # --- claimer loop (T8-T12) ----------------------------------------------

    async def _claimer_loop(self, claimer: _Claimer) -> None:
        """Drain up to ``min(slots_free, claim_lane_chunk)`` READY lanes, claim their head-prefixes in
        ONE ``claim_fifo_heads`` round-trip, and dispatch by outcome. Never awaits processing — a slow
        lane cannot stall its siblings' claim service (ADR 0066 §4.3). Backpressure is claim-gated: when
        no slots are free the claimer parks on its Event until a serializer frees one."""
        while not self._stop.is_set():
            # Wait for BOTH ready work AND a free slot (re-checked at the top, so a dropped Event.set()
            # between wait() and clear() can never lose a wakeup — state, not the event, is the truth).
            if not claimer.ready or self._slots_free <= 0:
                await claimer.event.wait()
                claimer.event.clear()
                continue
            lanes = self._assemble_chunk(claimer)
            if not lanes:
                continue
            await self._claim_and_dispatch(claimer, lanes)

    def _assemble_chunk(self, claimer: _Claimer) -> list[str]:
        """Pop READY lanes into a claim chunk, reserving one processing slot per lane as it is added
        (T8). Skips stale ready entries (a lane already advanced past READY). Slots reserved here are
        released for any lane the claim does not turn into PROCESSING (§4.3 exact-reservation)."""
        budget = min(self._slots_free, self._claim_lane_chunk)
        lanes: list[str] = []
        while claimer.ready and len(lanes) < budget:
            lane = claimer.ready.popleft()
            claimer.ready_set.discard(lane)
            st = self._states.get(lane)
            if st is None or st.phase is not _LanePhase.READY:
                continue  # stale: the lane already left READY (e.g. teardown, or a double entry)
            st.phase = _LanePhase.CLAIMING  # T8
            st.dirty = False
            self._slots_free -= 1  # reserve
            lanes.append(lane)
        return lanes

    async def _claim_and_dispatch(self, claimer: _Claimer, lanes: list[str]) -> None:
        # perf_counter_ns ONLY when the bench lever is on — otherwise a single bool check, no syscall.
        # A claim that RAISES is not timed: it takes the backoff path below (logged with a traceback),
        # and its timeout-capped duration would distort the very claim-latency figure this measures.
        # The tempdb signature is slow-but-SUCCESSFUL claims, which are recorded.
        _claim_t0 = time.perf_counter_ns() if self._claim_phase_timing else 0
        try:
            # Pass the dispatcher's clock so claim due-ness uses the SAME time base as the sweep +
            # park timers (one coherent clock). In production clock is time.time(), so this is
            # identical to now=None; it only matters under an injected clock (deterministic tests).
            result: ClaimedHeads = await self._store.claim_fifo_heads(
                self._stage.value, lanes, now=self._clock(), per_lane_limit=self._per_lane_limit
            )
        except Exception:  # noqa: BLE001 — a store error must not kill the claimer loop
            # Return the whole chunk to READY, release the reserved slots, back off this partition.
            for lane in lanes:
                self._release_slot()
                self._to_ready(lane, woken=self._states[lane].ready_woken)
            log.warning(
                "StageDispatcher %s claim failed for %d lane(s); backing off %.1fs",
                self._stage.value,
                len(lanes),
                _CLAIM_ERROR_BACKOFF_SECONDS,
                exc_info=True,
            )
            await self._sleep_or_stop(_CLAIM_ERROR_BACKOFF_SECONDS)
            return
        if self._claim_phase_timing:
            # Recorded synchronously (no await between the read and the counter writes), so a sibling
            # claimer at K>1 can never interleave a partial update. Counts only — a lane is a
            # destination_name, so lane NAMES never reach the log (PHI rule). `rearm` lanes were
            # consumed in place by the H2 skip-and-complete: real work, so booking them as empty
            # overhead would invert the churn metric during a dedup/failover pass.
            self._claim_phase_stats.record_claim(
                time.perf_counter_ns() - _claim_t0,
                lanes=len(lanes),
                rows=sum(len(v) for v in result.by_lane.values()),
                rearm=len(result.rearm),
            )
            self._claim_phase_stats.maybe_emit(
                stage=self._stage.value, claimers=len(self._claimers)
            )
        for lane in lanes:
            st = self._states[lane]
            items = result.by_lane.get(lane)
            if items:  # T9: claimed a prefix -> PROCESSING (the reserved slot is now consumed)
                if st.phase is not _LanePhase.CLAIMING:
                    self._busy_violations += 1  # invariant break — claimed a non-CLAIMING lane
                st.phase = _LanePhase.PROCESSING
                self._spawn_serializer(lane, items)
                # A pause_pending lane that claimed items carries pause_pending into the serializer's
                # terminal transition, which routes it to PAUSED after this <=1 head finishes.
            elif st.pause_pending:
                # An operator pause landed while CLAIMING and the claim came back EMPTY (or rearm-only):
                # the lane is already quiesced (no row claimed, the reserved slot never consumed), so
                # route it STRAIGHT to PAUSED — a pause must never drop to a claimable IDLE / re-ready.
                self._release_slot()
                st.phase = _LanePhase.PAUSED
                st.pause_pending = False
                st.dirty = False
                self._fire_paused(lane)
            elif (
                lane in result.rearm
            ):  # T10: head consumed in-store (H2/poison) -> immediate re-claim
                self._release_slot()
                self._to_ready(lane, woken=st.ready_woken)
            else:  # EMPTY
                self._release_slot()
                self._record_empty(woken=st.ready_woken)
                if st.dirty:  # T11: a wake raced the claim -> re-claim now, no sweep wait
                    self._to_ready(lane, woken=True)
                else:  # T12
                    st.phase = _LanePhase.IDLE

    # --- lane serializer (T9, T13-T17) --------------------------------------

    def _spawn_serializer(self, lane: str, items: list[OutboxItem]) -> None:
        if lane in self._lane_tasks:
            self._busy_violations += 1  # a live serializer already owns this lane — invariant break
        task = asyncio.create_task(self._run_lane(lane, items), name=f"lane:{lane}")
        task.add_done_callback(functools.partial(self._on_lane_task_done, lane))
        self._lane_tasks[lane] = task

    def _on_lane_task_done(self, lane: str, task: asyncio.Task[None]) -> None:
        """Supervise the serializer — the one otherwise-unsupervised task class. ``_run_lane`` pops
        ``_lane_tasks`` itself on the normal path; this is an idempotent safety net that also SURFACES a
        swallowed terminal-transition bug (the synchronous transition in ``_run_lane`` runs outside a
        try, so a stray error there would otherwise vanish and wedge the lane in PROCESSING)."""
        if self._lane_tasks.get(lane) is task:
            self._lane_tasks.pop(lane, None)
        if task.cancelled() or self._stop.is_set():
            return
        exc = task.exception()
        if exc is not None:
            log.error(
                "StageDispatcher %s lane %s serializer task crashed (state may be inconsistent)",
                self._stage.value,
                lane,
                exc_info=exc,
            )

    async def _run_lane(self, lane: str, items: list[OutboxItem]) -> None:
        """Drain the claimed prefix strictly oldest-first (K fully resolved before K+1 — ADR 0058's
        in-batch head-of-line), then apply the terminal transition. The unprocessed tail is
        ``release_claimed``'d (attempts restored, FIFO-neutral) on a park/stop/exception. The final
        state mutation runs synchronously after the (async) tail release so it is atomic on the loop
        (no double-dispatch window)."""
        outcome, tail_ids, head_reschedule = await self._drain_lane(lane, items)
        # Fix A (ADR 0070): re-pend the T17 head with a DURABLE backoff BEFORE the tail release — a
        # store write, best-effort (a failure leaves it INFLIGHT for reset_stale_inflight/the sweep).
        # This is NOT release_claimed: it dates the head into the future so it reads not-due (collapsing
        # the ~4×/s spin) rather than past-due (which re-readies it at the sweep cadence).
        if head_reschedule is not None:
            head_id, when = head_reschedule
            try:
                await self._store.reschedule_claimed([head_id], when)
            except Exception:  # noqa: BLE001 — recovery covers a failed reschedule; don't stall the lane
                log.warning(
                    "StageDispatcher %s reschedule_claimed failed for lane %s head",
                    self._stage.value,
                    lane,
                    exc_info=True,
                )
        # Async tail release BEFORE the synchronous transition. Best-effort: a release failure leaves
        # the tail INFLIGHT for reset_stale_inflight/the sweep to recover — never blocks the transition.
        if tail_ids:
            try:
                await self._store.release_claimed(tail_ids)
            except Exception:  # noqa: BLE001 — recovery covers a failed release; do not stall the lane
                log.warning(
                    "StageDispatcher %s release_claimed failed for lane %s (%d rows)",
                    self._stage.value,
                    lane,
                    len(tail_ids),
                    exc_info=True,
                )
        # --- synchronous terminal transition (NO await below) -------------------------------------
        self._lane_tasks.pop(lane, None)
        self._release_slot()
        st = self._states.get(lane)
        if st is None:  # torn down under us
            return
        if st.pause_pending:
            # An operator pause landed mid-PROCESSING: the <=1 claimed OUTBOUND row just finished
            # (delivered, or re-pended PENDING by a FIFO RETRY / a T17 re-pend), so the lane is quiesced
            # with ZERO INFLIGHT. Route it to PAUSED and fire — SKIPPING _lane_done/_apply_retry (no
            # re-ready, no park). The slot is already released above (conservation + busy_violations
            # intact). resume_lane later re-arms from the head (a backed-off head is re-swept promptly).
            st.pause_pending = False
            st.phase = _LanePhase.PAUSED
            st.dirty = False
            self._fire_paused(lane)
            return
        if (
            outcome.kind is None
        ):  # every item RESOLVED — a clean drain resets the infra-fault streak
            st.infra_error_streak = 0
            st.lane_stuck_alerted = False
            # A full batch (claim hit per_lane_limit) ⇒ more due rows likely remain — feeds T13b's greedy
            # sweep/seed backlog drain (a wake-less residue must not throttle to one row per sweep).
            self._lane_done(
                lane, st, claimed_full=len(items) >= self._per_lane_limit
            )  # T13/T13b/T14
        elif outcome.kind is LaneResultKind.RETRY:  # T15
            self._apply_retry(lane, st, outcome)
        else:  # T16 STOP (content-policy STOP — the InternalErrorPolicy path, untouched by ADR 0070)
            st.infra_error_streak = 0
            st.lane_stuck_alerted = False
            st.phase = _LanePhase.STOPPED
            self._alert_sink.connection_stopped(lane, detail=f"{self._stage.value} lane stopped")

    def _apply_retry(self, lane: str, st: _LaneState, outcome: _LaneOutcome) -> None:
        """Apply a RETRY outcome under the ADR 0070 infra-fault bound (fix B). A T17 zero-progress
        (``i==0``) infra fault accrues the per-lane ``infra_error_streak``; under ``stop`` it STOPs the
        head-of-line-blocked lane at ``infra_fault_stop_after`` (reusing the T16 STOP — phase + alert,
        **no** store write since fix A already re-pended the head PENDING); under ``retry_forever`` it
        never STOPs (throttled ``lane_stuck`` alert past the horizon). Every OTHER RETRY — a
        forward-progress (``i>0``) infra fault or a content (non-infra) body RETRY — **resets** the
        streak and parks normally."""
        if outcome.is_infra_fault and not outcome.made_progress:
            # Zero-progress head-of-line-blocked machinery fault: the escalation-less spin case.
            st.infra_error_streak += 1
            if (
                self._infra_fault_policy == "stop"
                and st.infra_error_streak >= self._infra_fault_stop_after
            ):
                # Bound the persistent fault: STOP the lane (reuse T16). NO store mutation — fix A has
                # already re-pended the head PENDING (preserved, never dead-lettered); no park.
                st.phase = _LanePhase.STOPPED
                self._alert_sink.connection_stopped(
                    lane,
                    detail=(
                        f"{self._stage.value} lane stopped after {st.infra_error_streak} consecutive "
                        f"infra faults (ADR 0070 T17)"
                    ),
                )
                return
            if self._infra_fault_policy == "retry_forever":
                self._maybe_lane_stuck_alert(lane, st)
            self._park(lane, st, outcome.park_until)  # T15 — retry the head at capped backoff
        else:
            # Forward-progress infra fault (i>0) OR a content (non-infra) body RETRY: reset the streak.
            st.infra_error_streak = 0
            st.lane_stuck_alerted = False
            self._park(lane, st, outcome.park_until)  # T15

    def _maybe_lane_stuck_alert(self, lane: str, st: _LaneState) -> None:
        """``retry_forever`` throttle: emit the ``lane_stuck`` alert ONCE per stuck episode — the first
        time the streak crosses ``infra_fault_stop_after`` — never per fault. Re-armable: the flag (and
        streak) reset on the next clean head, so a lane that gets stuck again pages again."""
        if st.infra_error_streak >= self._infra_fault_stop_after and not st.lane_stuck_alerted:
            st.lane_stuck_alerted = True
            self._alert_sink.lane_stuck(
                lane,
                detail=(
                    f"{self._stage.value} lane retrying a persistent infra fault "
                    f"({st.infra_error_streak} consecutive, retry_forever)"
                ),
            )

    def _infra_backoff(self, streak: int) -> float:
        """Fix A's exponential-capped head re-pend backoff: ``base * 2**streak`` capped at
        ``infra_fault_backoff_cap`` (base = :data:`_LANE_ERROR_BACKOFF_SECONDS`). The exponent is
        clamped so a never-resetting ``retry_forever`` streak can't blow up ``2**streak`` (base * 2**6
        already exceeds the ~60 s cap). 10 consecutive zero-progress faults span ~4 min of wall clock —
        the count is really a duration gate."""
        exp = min(max(streak, 0), 20)
        # float(...) pins the type: int ** (variable int) is typed Any by mypy (negative-exponent
        # overload), which would otherwise leak Any out of this float-returning function.
        backoff = float(_LANE_ERROR_BACKOFF_SECONDS * (2**exp))
        return min(backoff, self._infra_fault_backoff_cap)

    async def _drain_lane(
        self, lane: str, items: list[OutboxItem]
    ) -> tuple[_LaneOutcome, list[str], tuple[str, float] | None]:
        """Run each item's body oldest-first. Returns ``(outcome, tail-ids-to-release,
        head-reschedule-or-None)``. On an UNEXPECTED body exception (T17 — a store/handoff/infra fault
        or any raise from OUTSIDE the per-item body) at item ``i``: the head ``items[i]`` was NOT
        resolved, so it is **re-pended with a durable exponential backoff** (fix A — the returned
        ``(head_id, next_attempt_at)``; the caller performs the store write) and its unprocessed tail
        ``items[i+1:]`` is released; the already-RESOLVED prefix ``items[0:i]`` is left alone. Together
        that returns the whole failed set ``items[i:]`` to PENDING (never ``items[1:]``, which stranded
        ``items[0]`` INFLIGHT — invisible to ``claim_fifo_heads``/``list_fifo_lanes`` — and let
        ``items[1]`` overtake it, a per-lane FIFO break with no SQL guard; ADR 0066 §7 neg-1). The head
        is **re-pended not-due** (not plain-released past-due), so ``list_fifo_lanes`` reports it not-due
        and the sweep arms an exact re-claim timer instead of re-readying it ~4×/s — the ADR 0070 fix A
        spin collapse. The body-owned RETRY/STOP paths (``:534``) are UNCHANGED — the body already
        wrote the head's terminal state, so ``is_infra_fault`` stays False there (never trips fix B)."""
        i = 0
        try:
            for i, item in enumerate(items):
                result = await self._process_item(lane, item)
                if result.kind is LaneResultKind.RESOLVED:
                    continue
                tail = [it.id for it in items[i + 1 :]]
                made_progress = i > 0
                if result.kind is LaneResultKind.RETRY:
                    return (
                        _LaneOutcome(
                            LaneResultKind.RETRY, result.retry_until, made_progress=made_progress
                        ),
                        tail,
                        None,  # the body already re-pended the head (mark_failed); no reschedule here
                    )
                return (
                    _LaneOutcome(LaneResultKind.STOP, made_progress=made_progress),
                    tail,
                    None,  # content STOP: the body owns the head per InternalErrorPolicy — untouched
                )
            return _LaneOutcome(None), [], None  # all RESOLVED
        except asyncio.CancelledError:
            raise  # teardown: leave the whole prefix INFLIGHT for reset_stale_inflight (crash-safety)
        except Exception:  # noqa: BLE001 — T17 machinery fault: re-pend head w/ backoff, release tail
            # Fix A: re-pend the UNHANDLED head items[i] at an exponential-capped backoff so it reads
            # NOT-due (collapsing the spin). A zero-progress (i==0) fault escalates the backoff by the
            # lane's streak; a fault that made forward progress (i>0) resets the streak (fix B terminal
            # block), so it retries at the base backoff.
            st = self._states.get(lane)
            streak = st.infra_error_streak if (st is not None and i == 0) else 0
            park_until = self._clock() + self._infra_backoff(streak)
            log.error(
                "StageDispatcher %s lane %s serializer failed at item %d (T17 infra fault); "
                "re-pending head with backoff until %.3f",
                self._stage.value,
                lane,
                i,
                park_until,
                exc_info=True,
            )
            head_id = items[i].id
            tail = [
                it.id for it in items[i + 1 :]
            ]  # tail only — the head is re-pended, not released
            return (
                _LaneOutcome(
                    LaneResultKind.RETRY, park_until, is_infra_fault=True, made_progress=(i > 0)
                ),
                tail,
                (head_id, park_until),
            )

    # --- lane state transition helpers --------------------------------------

    def _to_ready(self, lane: str, *, woken: bool) -> None:
        """Move a lane to READY and enqueue it (clearing dirty). Used by T10/T11 and the claim-error
        return path — the caller has already released the slot."""
        st = self._states[lane]
        st.phase = _LanePhase.READY
        st.dirty = False
        st.ready_woken = woken
        self._enqueue(lane)

    def _lane_done(self, lane: str, st: _LaneState, *, claimed_full: bool) -> None:
        """Every item resolved. Re-arm if a wake raced processing (T14); else, for a FULL batch claimed
        off the sweep/seed rather than a producer wake, re-arm greedily to keep draining (T13b); else go
        IDLE (T13).

        T13b — greedy backlog drain (failover-recovery fix): a lane readied by the sweep/seed
        (``ready_woken is False``) has NO producer driving it, so absent this it advances only one claim
        per ``sweep_interval`` — a large wake-less residue (e.g. a promoted node's recovered routed
        backlog) then can't clear a bounded drain window, stranding acknowledged messages. When such a
        claim came back FULL (``len(items) == per_lane_limit`` ⇒ more due rows likely remain) re-arm at
        once (woken=False, so it stays sweep-sourced). Bounded, not a spin: the first non-full/empty claim
        returns the lane to IDLE. A producer wake mid-drain sets ``dirty`` and takes the T14 path instead,
        so steady-state (wake-driven) behavior is byte-unchanged."""
        if (
            st.dirty
        ):  # T14 — a wake raced processing; re-arm, preserving whether it was a PRODUCER wake
            self._to_ready(lane, woken=st.dirty_woken)
        elif claimed_full and not st.ready_woken:  # T13b
            self._to_ready(lane, woken=False)
        else:  # T13
            st.phase = _LanePhase.IDLE

    def _park(self, lane: str, st: _LaneState, until: float | None) -> None:
        """Retryable head failure (T15): park until the head's re-pended ``next_attempt_at`` and arm an
        exact coalesced timer. A wake meanwhile keeps the lane parked (T6) — the row behind a backing-off
        head is head-of-line blocked; only the timer / a sweep-due / notify_work unparks."""
        st.phase = _LanePhase.PARKED
        st.dirty = False
        st.park_until = until
        if until is not None:
            self._arm_timer(lane, until)

    def _unpark(self, lane: str, *, woken: bool) -> None:
        """PARKED/STOPPED -> READY (T18/T19): cancel the park timer, clear dirty, enqueue.

        Sharp edge (ADR 0070 fix B, test 3): reset ``infra_error_streak`` ONLY on the STOPPED→READY
        resume — a ``notify_work`` reload re-arm of a deliberately-STOPPED lane, keyed on the lane
        being STOPPED at entry (the sole caller that unparks a STOPPED lane). NEVER reset on the shared
        PARKED park-timer / sweep unpark (which keeps ``phase is PARKED`` here): if a still-faulting
        head's park-timer unpark reset the streak, the ``stop`` threshold would never accrue and the
        original ~4×/s spin would silently return. Guard it on the pre-transition phase, not on
        ``woken`` (``notify_work`` unparks a PARKED lane with ``woken=True`` too, and that must NOT
        reset)."""
        self._cancel_timer(lane)
        st = self._states[lane]
        if (
            st.phase is _LanePhase.STOPPED
        ):  # STOPPED→READY resume only — reset the infra-fault streak
            st.infra_error_streak = 0
            st.lane_stuck_alerted = False
        st.phase = _LanePhase.READY
        st.dirty = False
        st.park_until = None
        st.ready_woken = woken
        self._enqueue(lane)

    def _release_slot(self) -> None:
        """Return one processing slot to the budget and wake any starved claimer that has queued work
        (so a claimer blocked on budget re-checks). Conservation: slots_free never exceeds the max."""
        if self._slots_free < self._max_processing_lanes:
            self._slots_free += 1
        for claimer in self._claimers:
            if claimer.ready:
                claimer.event.set()

    def _record_empty(self, *, woken: bool) -> None:
        self._empty.record_empty(woken=woken)

    async def _sleep_or_stop(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    # --- timers (coalesced, earliest-wins) ----------------------------------

    def _arm_timer(self, lane: str, when: float) -> None:
        """Arm (or refresh) the lane's coalesced timer to fire at ``when`` — EARLIEST-WINS: keep an
        existing earlier deadline, replace a later one. On fire, ``_on_lane_timer`` unparks the lane."""
        existing = self._timer_deadline.get(lane)
        if existing is not None and existing <= when:
            return  # an earlier (or equal) timer already covers it
        self._cancel_timer(lane)
        delay = max(0.0, when - self._clock())
        assert self._call_later is not None  # set in start()
        self._timers[lane] = self._call_later(delay, functools.partial(self._on_lane_timer, lane))
        self._timer_deadline[lane] = when

    def _cancel_timer(self, lane: str) -> None:
        handle = self._timers.pop(lane, None)
        if handle is not None:
            handle.cancel()
        self._timer_deadline.pop(lane, None)

    def _on_lane_timer(self, lane: str) -> None:
        """A park / not-due-sweep / backoff timer fired. Clear it, then unpark a PARKED lane or ready an
        IDLE one (the head's backoff has elapsed). STOPPED/PAUSED/PROCESSING/CLAIMING/READY are left
        alone (a stale fire is a harmless no-op — mark_ready is idempotent by phase; a PAUSED lane in
        particular is never re-armed by a timer, only by resume_lane)."""
        self._timers.pop(lane, None)
        self._timer_deadline.pop(lane, None)
        st = self._states.get(lane)
        if st is None:
            return
        if st.phase is _LanePhase.PARKED:  # T18
            self._unpark(lane, woken=False)  # a due head is a sweep-class readiness, not a wake
        elif st.phase is _LanePhase.IDLE:  # a not-due head became due while the lane was idle
            self.mark_ready(lane, woken=False)

    # --- sweep (T18-T21) — the bounded, clock-driven at-least-once backstop ---

    async def _sweep_loop(self) -> None:
        """Run one sweep every ``sweep_interval`` OR immediately when ``sweep_now`` is set (recovery).
        An independent task, so sustained wake traffic can never starve the backstop (ADR 0066 §4.4)."""
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._sweep_now.wait(), timeout=self._sweep_interval)
            except asyncio.TimeoutError:
                pass
            self._sweep_now.clear()
            if self._stop.is_set():
                break
            try:
                await self._run_sweep_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — a sweep error must not kill the backstop
                log.warning("StageDispatcher %s sweep failed", self._stage.value, exc_info=True)

    async def _run_sweep_once(self) -> None:
        """Page ``list_fifo_lanes`` (after-cursor), intersect EACH page with this engine's registry lanes
        (the shard filter — a single capped call could let a foreign shard's earlier lanes crowd owned
        lanes out of the window, silently failing their backstop; D1), and per owned lane: a DUE head ->
        make ready (unparking a PARKED lane whose backoff elapsed — the backstop for a lost park timer);
        a NOT-DUE head -> arm/refresh the lane's coalesced timer at the head's due time (T21)."""
        owned = self._lane_provider()
        now = self._clock()
        after: str | None = None
        while not self._stop.is_set():
            page = await self._store.list_fifo_lanes(
                self._stage.value, now=now, limit=self._sweep_page_limit, after=after
            )
            if not page:
                break
            for lane, head_next_attempt in page:
                if lane not in owned:
                    continue
                if head_next_attempt <= now:
                    self._sweep_ready_due(lane)
                else:  # T21 — not due: arm the exact re-claim timer (unparks when the head becomes due)
                    self._arm_timer(lane, head_next_attempt)
            if len(page) < self._sweep_page_limit:
                break
            after = page[-1][0]  # resume strictly after the last lane

    def _sweep_ready_due(self, lane: str) -> None:
        """The sweep found an owned lane's HEAD due. Ready it per phase (T20), including UNPARKING a
        PARKED lane whose backoff has elapsed (the bounded backstop for a lost park timer — a due head
        is legitimately re-claimable, distinct from a wake behind a still-backing-off head which stays
        parked). A deliberately STOPPED lane is left halted (only reload/notify_work re-arms it)."""
        st = self._states.get(lane)
        if st is None:  # T1 create-or-stick, sweep-sourced
            self.mark_ready(lane, woken=False)
            return
        phase = st.phase
        if phase in (_LanePhase.IDLE, _LanePhase.READY):
            self.mark_ready(lane, woken=False)  # T20
        elif phase is _LanePhase.PARKED:
            self._unpark(lane, woken=False)  # T18 — backoff elapsed; the backstop
        elif phase in (_LanePhase.CLAIMING, _LanePhase.PROCESSING):
            st.dirty = True  # the in-flight episode re-claims at its end (T4/T5)
        # STOPPED: leave halted (deliberate). PAUSED: leave halted too — a due head must NEVER wake a
        # deliberately operator-paused lane (only resume_lane re-arms it); the sweep is a no-op here.

    # --- read accessors (test-facing; also the PR4 /stats seam) --------------

    @property
    def running(self) -> bool:
        return self._running

    @property
    def slots_free(self) -> int:
        return self._slots_free

    @property
    def busy_violations(self) -> int:
        return self._busy_violations

    @property
    def processing_lanes(self) -> int:
        return len(self._lane_tasks)

    @property
    def paused_count(self) -> int:
        """Number of lanes currently in the operator-PAUSED phase — a PR4 /stats gauge (test-facing)."""
        return sum(1 for st in self._states.values() if st.phase is _LanePhase.PAUSED)

    @property
    def empty_claims(self) -> tuple[int, int, int]:
        """(total, wake_fanout, idle_poll) — the B11 split. Reads the delegated counter: the injected
        observer (PR4's runner ``EmptyClaimCounters``) or the private :class:`_LocalEmptyCounter`
        default. The observer Protocol only pins ``record_empty``, so read the triple defensively."""
        e = self._empty
        return (getattr(e, "total", 0), getattr(e, "wake_fanout", 0), getattr(e, "idle_poll", 0))

    def phase(self, key: str) -> _LanePhase | None:
        st = self._states.get(key)
        return st.phase if st is not None else None

    def paused(self, key: str) -> bool:
        """Whether ``key`` is in the operator-PAUSED phase (mirrors :meth:`phase`; the runner reads it
        to gate outbound status/purge). False for an unknown lane."""
        st = self._states.get(key)
        return st is not None and st.phase is _LanePhase.PAUSED

    def is_dirty(self, key: str) -> bool:
        st = self._states.get(key)
        return st.dirty if st is not None else False

    def park_until(self, key: str) -> float | None:
        st = self._states.get(key)
        return st.park_until if st is not None else None

    def infra_error_streak(self, key: str) -> int:
        """The lane's consecutive zero-progress T17 infra-fault count (ADR 0070 fix B) — test/stats
        facing. 0 for an unknown lane."""
        st = self._states.get(key)
        return st.infra_error_streak if st is not None else 0
