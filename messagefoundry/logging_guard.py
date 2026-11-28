# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fail-closed guard for the **application log** (BACKLOG #122, ADR 0162).

CLAUDE.md section 1's count-and-log invariant says every message a connection takes in or puts out is
counted and **logged** — nothing is silently dropped. Applied to the application log that is: *the
engine must not keep processing what it cannot log.* Durability and visibility of the log (NSSM
rotation, the RFC 5425 off-box forwarder, the ``GET /status`` disk metering) all answer "can an
operator SEE that the log broke"; none of them answers "does the engine STOP when it breaks". This
module is that second half.

**Two stages, and the split is the whole safety story:**

* **Stage 1 — RECOVER.** On a write failure the sink is rolled: the broken file is renamed aside
  (``<name>.broken-<UTC>-<n>``), a fresh file is opened at the live path, the **rollover event is
  recorded** into it, and the record whose write failed, or the notice standing in for it, is
  re-written. A transient condition — a
  momentary lock, an antivirus scan, a rotation race — heals here and stops nothing.
* **Stage 2 — STOP.** :meth:`LogWriteGuard.record_unwritable` records the sink unwritable and
  decides whether to ask for the stop. Its docstring names its callers. A write failure reaches it
  only after a roll was tried: a single-stage stop would take feeds down on a hiccup; that is an
  outage generator, not an invariant.

**And a third thing, which is not a stage but is half the enforcement: UN-stopping.** Recovery is an
operator assertion — *"I fixed the disk"* — and a fail-closed control that simply believes it is a
control with an off switch. :meth:`LogWriteGuard.revalidate` therefore re-tests dead sinks, as
its docstring says: *repaired* and *still broken* are
indistinguishable from memory, which is exactly the distinction recovery has to make. The engine
gates every re-arm path on that answer.

**Scope of the stop is the PROCESS, and the code says so rather than pretending otherwise.** The
application log is a process-global handler set on the root logger — a write failure is a property of
the *sink*, not of any one connection, and no per-connection attribution exists to narrow it with. So
the escalation stops **every connection this process owns**: on a single-process engine that is all of
them; under engine sharding (ADR 0037) it is that shard's connections, which is the narrowest honest
scope available. See ADR 0162 section 4.

**Boundaries this module must never cross:**

* **The message store is untouched.** The store (SQLite/SQL Server/Postgres) is a *different* durable
  record from the application log and is unaffected by an application-log failure. A message already
  committed to the ingress stage has been ACKed (ACK-on-receipt); stopping intake leaves that row
  exactly where it is — un-ACKed nothing, lost nothing, re-delivered nothing. This module performs **no
  store I/O at all**.
* **No PHI on the error path.** :meth:`_GuardedSinkMixin.handleError` never reads ``record.msg`` or
  ``record.args``; the only rendering of a record it performs is ``self.format(record)`` — the record
  has already passed the handler's :class:`~messagefoundry.logging_setup.RedactionFilter` chain by then
  (filters run in ``Handler.handle``, before ``emit``) — and that rendering is written only to the
  sink's own stream, never to the last-resort channel. When that rendering raises, the guard writes
  in the record's place, where the formatter can format it, a notice that renders only the record's
  logger and level names, escaped, and the exception's type (BACKLOG #5813). The stderr
  last-resort line carries the sink label, a :func:`~messagefoundry.redaction.safe_exc` reason or
  an exception's type, and **nothing from the record**. The guard also never raises the service
  level to DEBUG.
* **The guard scrubs its OWN diagnostics, because nothing downstream reliably will (BACKLOG
  #1591).** THE CONSUMER LIST, stated here once and referred to rather than repeated: a failure
  reason travels to (1) the notice written onto the rolled sink, (2) ``GET /status``'s
  ``last_event``, (3) the ``AlertSink`` page, and (4) the stderr last-resort line. **Not one of them
  is guaranteed the handler filter chain.** (1) is written by ``_write_notice``, which formats it
  and writes it straight to the sink's stream through ``_write_line``, deliberately below
  ``Handler.handle``; (2) and (4) never touch the logging tree at all; (3) reaches the tree only in
  the DEFAULT sink, which happens to ``log.warning`` it — the email/webhook notifier an operator
  configures for exactly this failure does not. So the scrub belongs **where the string is built**
  (:func:`_safe_reason`, :func:`_escape_only`), which serves all four at once — never at the notice
  writer, which would close (1) and leave three open. It is NOT repeated at
  :class:`LogWriteGuard`'s boundary: :func:`_safe_diagnostic` is not idempotent, and that function
  measures what a second pass costs.
* **Stdlib, plus LEAVES only — never ``pipeline``/``store``/``api``.** The guard is reachable from
  ``logging_setup``, which every process configures, and must not drag the engine in behind it. The
  engine modules it does import are imported for their definitions and import nothing from this
  package in turn: :mod:`~messagefoundry.redaction`, :mod:`~messagefoundry.controlchars`,
  :mod:`~messagefoundry.secretscrub`. None imports ``logging_setup``, which imports THIS module;
  :mod:`~messagefoundry.controlchars` records why the escape table had to move down rather than be
  reached upwards from here. A new import here has to clear the same bar: a leaf, for a definition.
"""

from __future__ import annotations

import codecs
import contextlib
import logging
import logging.handlers
import os
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Literal, TextIO

# Bound at MODULE scope, not inlined: that is what lets a test force the scrubber itself to raise
# and assert the notice is emitted anyway, with no production test hook (BACKLOG #1591).
from messagefoundry.controlchars import (
    escape_lone_surrogates,
    json_unicode_escape,
    scrub_control_chars,
)
from messagefoundry.redaction import redact_binary_carriage, safe_exc
from messagefoundry.secretscrub import scrub_credentials

__all__ = [
    "GuardedFileHandler",
    "GuardedStreamHandler",
    "LogSinkEvent",
    "LogSinkStatus",
    "LogWriteGuard",
    "active_guard",
    "set_active_guard",
]

#: The synthetic logger name the guard stamps on the rollover notices it writes DIRECTLY to a sink
#: (bypassing the logging tree, which is what just failed).
_NOTICE_LOGGER = "messagefoundry.logging_guard"

#: ``rolled`` — Stage 1 healed the sink. ``unwritable`` — Stage 2: the replacement failed too, the
#: sink needed rolling past the flap bound, or its formatter could not format the guard's notice.
LogSinkStage = Literal["rolled", "unwritable"]

#: Anti-flap bound on stage 1 (see :meth:`LogWriteGuard.record_rollover`). Generous enough that a real
#: transient — one lock, one rotation race, one antivirus pass — never trips it, and tight enough that
#: a sink failing every few records is declared unwritable instead of rolled forever.
_ROLL_FLAP_WINDOW_SECONDS = 60.0
_MAX_ROLLS_PER_WINDOW = 5


@dataclass(frozen=True, slots=True)
class LogSinkEvent:
    """One two-stage transition on one application-log sink. PHI-free by construction: it carries the
    sink label, the stage, a :func:`safe_exc` reason and a filesystem path — never record content."""

    sink: str
    stage: LogSinkStage
    reason: str
    rolled_aside: str | None = None
    #: The configured ``[logging].on_write_failure`` policy, carried ON the event rather than looked up
    #: by the responder, so the engine side is a pure function of what it is handed and never reaches
    #: back into process-global state to decide whether to stop. Always False for ``rolled`` — stage 1
    #: stops nothing, ever.
    stop_requested: bool = False


@dataclass(frozen=True, slots=True)
class LogSinkStatus:
    """The guard's current view of one sink, for ``GET /status`` and operator triage."""

    sink: str
    state: Literal["healthy", "rolled", "unwritable"]
    rollovers: int
    last_event: str | None = None
    last_event_at: str | None = None
    rolled_aside: str | None = None


#: Called (synchronously, from whatever thread was logging) on every stage transition. It MUST be
#: cheap, non-blocking and never raise — the guard is already handling a failure. It returns False
#: when it could not hand the event on, so that the guard can fire an owed stage-2 event again
#: (see :meth:`LogWriteGuard.record_unwritable`); a raise counts as that too, and any other return
#: counts as delivered. An event handed on and lost later, as the engine's responder can lose one
#: it scheduled when the runner tears down, counts as delivered.
EscalationCallback = Callable[[LogSinkEvent], bool | None]

#: One sink's "are you writable again?" self-test. Writes a real record to itself and RAISES if the
#: sink still refuses it — see :meth:`LogWriteGuard.revalidate`.
SinkProbe = Callable[[], None]


class LogWriteGuard:
    """Process-wide state + escalation seam for the guarded application-log sinks.

    Thread-safe: log records are emitted from the event loop, from handler worker threads and from
    connector threads alike, so every mutation is under one lock. Escalation is **latched per sink**:
    :meth:`record_unwritable` says when a sink already ``unwritable`` fires again.

    **The FLAP latch is a different thing**, an overlay on what this class reports (BACKLOG #5812,
    ADR 0162 amendment B). :meth:`record_rollover` says when it holds."""

    def __init__(self, *, stop_on_unwritable: bool = True) -> None:
        self._lock = threading.RLock()
        self._sinks: dict[str, LogSinkStatus] = {}
        #: sink -> (window start, rolls in window) — the anti-flap bound, see :meth:`record_rollover`.
        self._roll_flap: dict[str, tuple[float, int]] = {}
        #: sink -> the flap latch, present only while it holds the sink; see :meth:`record_rollover`.
        #: The value is the ``time.monotonic()`` of the roll that set the latch, or of the sink's
        #: latest roll or stage-2 failure since. Kept apart from ``_roll_flap`` so that nothing the
        #: latch does, and nothing that clears it, can move the bound; what the bound and the paging
        #: decisions compute does not depend on it (BACKLOG #5812).
        self._flap_latch: dict[str, float] = {}
        #: Sinks whose current break fired a stage-2 event that was not delivered, so the event is
        #: fired again later; see :meth:`record_unwritable`.
        self._unanswered: set[str] = set()
        #: Sinks whose current break already wrote the stderr line for a stage-2 event whose
        #: responder raised, so an owed event fired again on every later failure writes no more.
        self._escalation_failure_said: set[str] = set()
        #: sink -> "write one record to yourself and raise if you still cannot", see :meth:`revalidate`.
        self._probes: dict[str, SinkProbe] = {}
        self._escalation: EscalationCallback | None = None
        #: ``[logging].on_write_failure == "stop"``. Stamped onto every stage-2 event.
        self.stop_on_unwritable = stop_on_unwritable

    # --- registration / wiring ------------------------------------------------

    def register(self, sink: str, probe: SinkProbe | None = None) -> None:
        """Declare a guarded sink as healthy so ``GET /status`` can report it before anything breaks.

        ``probe`` is how this sink answers "can you accept a record again?" — see :meth:`revalidate`."""
        with self._lock:
            self._sinks.setdefault(sink, LogSinkStatus(sink=sink, state="healthy", rollovers=0))
            if probe is not None:
                self._probes[sink] = probe

    def set_escalation(self, callback: EscalationCallback | None) -> None:
        """Wire (or clear) the engine-side responder. Cleared by default, so a CLI/test process that
        configures logging without an engine degrades to the stderr last-resort line and stops
        nothing.

        ONE RESPONDER, and a second one SAYS SO. A process runs one engine, so this is a single-slot
        seam by design — but a second `RegistryRunner` starting in the same process would take the
        slot and leave the first silently unguarded, which is the shape where a fail-closed control
        disappears with every check still green. It is not made an error (a test process legitimately
        starts runners back to back), so the honest handling is to be loud about it. The last-resort
        channel rather than ``logging``: this class must not depend on the tree it guards.

        Wiring a responder also fires each stage-2 event already owed (see
        :meth:`record_unwritable`) for a sink whose own state is still unwritable, without waiting
        for that sink's next failure."""
        with self._lock:
            previous = self._escalation
            self._escalation = callback
            if callback != previous:
                # A new responder's first raise in a break is said, whatever the old one did.
                self._escalation_failure_said.clear()
            owed = self._take_owed_events() if callback is not None else []
        if callback is not None and previous is not None and previous != callback:
            _last_resort(
                "a second log-sink escalation responder replaced the first; the engine that "
                "registered first is no longer guarded by this process's log write guard"
            )
        for event in owed:
            self._fire_stage2(event)

    def _take_owed_events(self) -> list[LogSinkEvent]:
        """Clear every owed stage-2 event and return those of sinks still unwritable, rebuilt from
        each sink's recorded status. Called under the lock, so one owed event is taken once."""
        owed = sorted(self._unanswered)
        self._unanswered.clear()
        all_down = all(s.state == "unwritable" for s in self._sinks.values())
        events: list[LogSinkEvent] = []
        for sink in owed:
            status = self._sinks.get(sink)
            if status is None or status.state != "unwritable":
                continue
            events.append(
                LogSinkEvent(
                    sink=sink,
                    stage="unwritable",
                    # Already scrubbed: every reason the guard records arrives scrubbed.
                    reason=status.last_event or "log write failed (no reason recorded)",
                    stop_requested=self.stop_on_unwritable and all_down,
                )
            )
        return events

    def clear_escalation(self, callback: EscalationCallback) -> None:
        """Unwire ``callback`` — but ONLY if it is still the installed one. A runner tearing down must
        not silently unwire a *different* runner that registered after it (the second engine in a test
        process would then be unguarded, and nothing would say so)."""
        with self._lock:
            if self._escalation == callback:
                self._escalation = None

    def status(self) -> list[LogSinkStatus]:
        """Each sink as ``GET /status`` shows it. A sink the flap latch holds reads ``unwritable``;
        every other field, the cause and the rolled-aside path included, is what the guard records
        with or without the latch."""
        with self._lock:
            return sorted((self._reported(s) for s in self._sinks.values()), key=lambda s: s.sink)

    def _reported(self, status: LogSinkStatus) -> LogSinkStatus:
        """``status`` with the latch applied. The latch only ever adds an ``unwritable`` reading."""
        if status.state != "unwritable" and self._reads_unwritable(status):
            return replace(status, state="unwritable")
        return status

    # --- stage transitions ----------------------------------------------------

    def record_rollover(self, sink: str, *, reason: str, rolled_aside: str | None) -> None:
        """Stage 1 rolled ``sink``, and its replacement took the notice and the re-written record.

        **Bounded, because "heals" and "keeps needing to be healed" are not the same sink.** A roll
        past :data:`_MAX_ROLLS_PER_WINDOW` rolls inside :data:`_ROLL_FLAP_WINDOW_SECONDS` is passed
        on to :meth:`record_unwritable`: a log you must replace every few seconds is not a working
        log, and stage 2 is the honest verdict on it. Such a roll on a sink already ``unwritable``
        keeps it so and passes ``repeat`` (ADR 0162 Amendment C).

        **The flap latch holds what the bound declared unwritable** (BACKLOG #5812). The bound's
        window restarts a minute after its first roll, so a sink still rolling every few seconds
        would otherwise read ``rolled`` again, and :meth:`can_log` True with no probe, until the
        bound trips again. So the roll that trips the bound also latches the sink, in the same hold
        of the lock that writes the bound's state. A later roll keeps the latch while it comes
        within :data:`_ROLL_FLAP_WINDOW_SECONDS` of the sink's last roll or stage-2 failure, and
        the first roll after a longer gap releases it; :meth:`revalidate` and
        :meth:`record_healthy` release it too. The latch is an overlay in its own field and never
        touches a sink. The bound, the events this method and :meth:`record_unwritable` fire, their
        stop requests and the recorded status do not read it; :meth:`status`, :meth:`can_log`,
        :meth:`revalidate` and the stage-2 stderr line do.

        **PRECONDITION: ``reason`` and ``rolled_aside`` arrive ALREADY SCRUBBED** (BACKLOG #1591).
        Build them with :func:`_safe_reason` and :func:`_escape_only`, as
        :meth:`_GuardedSinkMixin.handleError` does. This method cannot enforce it by re-scrubbing:
        :func:`_safe_diagnostic` is **not idempotent** and its own docstring measures what a second
        pass costs — the value published here would then disagree with the notice already written on
        the sink. A scrub that damages correct input is not a safety net."""
        with self._lock:
            previous = self._sinks.get(sink)
            now = time.monotonic()
            first_at, streak = self._roll_flap.get(sink, (now, 0))
            if now - first_at > _ROLL_FLAP_WINDOW_SECONDS:
                first_at, streak = now, 0
            streak += 1
            self._roll_flap[sink] = (first_at, streak)
            tripped = streak > _MAX_ROLLS_PER_WINDOW
            # A roll past the bound on a sink already unwritable keeps it so in this same hold of
            # the lock, so no other thread reads it ``rolled`` in between.
            repeat = tripped and previous is not None and previous.state == "unwritable"
            self._sinks[sink] = LogSinkStatus(
                sink=sink,
                state="unwritable" if repeat else "rolled",
                rollovers=(previous.rollovers if previous else 0) + 1,
                last_event=reason,
                last_event_at=_utc_now(),
                rolled_aside=rolled_aside,
            )
            self._latch_after_roll(sink, now=now, tripped=tripped)
            if self._sinks[sink].state == "rolled":
                self._unanswered.discard(sink)  # the break is over, owed event or not
                self._escalation_failure_said.discard(sink)
        if tripped:
            # The precondition holds through this join: ``reason`` arrived scrubbed and everything
            # appended is a literal plus two formatted numbers, so nothing new needs escaping.
            self.record_unwritable(
                sink,
                reason=(
                    f"{reason}; the sink needed rolling {streak} times in "
                    f"{_ROLL_FLAP_WINDOW_SECONDS:.0f}s, which is a failing log rather than a transient"
                ),
                repeat=repeat,
            )
            return
        self._fire(
            LogSinkEvent(sink=sink, stage="rolled", reason=reason, rolled_aside=rolled_aside)
        )

    def record_unwritable(
        self,
        sink: str,
        *,
        reason: str,
        cause: str = "after a rollover attempt",
        repeat: bool = False,
    ) -> None:
        """Stage 2: record ``sink`` unwritable. Called when a roll's replacement could not be
        written, by :meth:`record_rollover` past the flap bound, and by
        :meth:`_GuardedSinkMixin.handleError`, with no roll, when the sink's formatter cannot
        format the notice standing in for an unformattable record. ``cause`` is a literal phrase
        for the stderr line saying how the sink came to be unwritable.

        A sink not already unwritable gets the stderr line and a stage-2 event. A sink already
        unwritable gets neither, with two exceptions. With ``repeat``, which
        :meth:`record_rollover` passes, it gets both. And when its last stage-2 event was not
        delivered (see :meth:`_fire`), that event is owed: the sink's next call here fires one.
        A roll that heals the sink, and :meth:`record_healthy`, clear the debt.
        :meth:`set_escalation` also fires the owed events when it wires a responder.

        **The STOP is asked for only when EVERY guarded sink is unwritable, and that is a
        correctness point, not a softening.** The ruling is *"we never want to process stuff if the
        processing cannot be logged"* — so the question the halt must answer is "can this process
        still log?", not "did a sink break?". With ``[logging].file`` configured there are two sinks;
        one of them failing while the other keeps accepting writes means the processing IS still
        logged, and halting there would be a control resting on a false premise. When there is only
        one sink (the default, stdout-only) the two questions coincide and the halt fires exactly as
        before. The sink is still recorded unwritable, still alerted and still shown on
        ``/status`` — visibility is unconditional; only the ENFORCEMENT is conditioned on the thing
        the enforcement is about.

        ``reason`` arrives already scrubbed; :meth:`record_rollover` states that precondition."""
        with self._lock:
            previous = self._sinks.get(sink)
            already_down = previous is not None and previous.state == "unwritable"
            self._sinks[sink] = LogSinkStatus(
                sink=sink,
                state="unwritable",
                rollovers=previous.rollovers if previous else 0,
                last_event=reason,
                last_event_at=_utc_now(),
                rolled_aside=previous.rolled_aside if previous else None,
            )
            all_down = all(s.state == "unwritable" for s in self._sinks.values())
            # The stop decision above reads each sink's own state. Whether the latch holds every
            # other sink only changes what the stderr line says about them.
            all_reported_down = all(self._reads_unwritable(s) for s in self._sinks.values())
            self._latch_after_failure(sink)
            # An owed event (BACKLOG #5812) is taken here, under the lock, so one owed event is
            # fired by one call, not by every thread failing at once.
            owed = already_down and sink in self._unanswered
            if owed:
                self._unanswered.discard(sink)
        event = LogSinkEvent(
            sink=sink,
            stage="unwritable",
            reason=reason,
            stop_requested=self.stop_on_unwritable and all_down,
        )
        if already_down and not repeat:
            # Latched: one page per break, not one per dropped record. Without this a broken disk
            # turns every subsequent log line into an alert AND a stderr line, and the storm buries
            # the one message that mattered.
            if owed:
                self._fire_stage2(event)
            return
        if all_down:
            others = ""
        elif all_reported_down:
            others = (
                "; every other sink is reported unwritable, but at least one only by the flap "
                "latch, after a roll that landed, and a stop needs every sink's own write to have "
                "failed, so nothing is being stopped"
            )
        else:
            others = "; another sink is still writable, so nothing is being stopped"
        _last_resort(
            f"LOG SINK {_escape_only(sink, fallback=_LABEL_DROPPED)} IS UNWRITABLE "
            f"{cause}: {reason}{others}"
        )
        self._fire_stage2(event)

    def _fire_stage2(self, event: LogSinkEvent) -> None:
        """Fire a stage-2 event, and remember the break as owed one when the event was not
        delivered and the sink is still unwritable."""
        if self._fire(event):
            return
        with self._lock:
            current = self._sinks.get(event.sink)
            if current is not None and current.state == "unwritable":
                self._unanswered.add(event.sink)

    def record_healthy(self, sink: str) -> None:
        """``sink`` accepted a record again — clear the unwritable latch so a LATER break pages afresh.

        Without this the ``unwritable`` state is terminal for the life of the process: nothing else
        ever moves a sink out of it, so a repaired disk would still read as broken and (worse) a
        genuine second break would be swallowed by :meth:`record_unwritable`'s ``already_down``
        return. The rollover COUNT is deliberately kept — it is the sink's history, and an operator
        triaging a flapping disk needs to see that it has been rolled before."""
        with self._lock:
            previous = self._sinks.get(sink)
            self._sinks[sink] = LogSinkStatus(
                sink=sink,
                state="healthy",
                rollovers=previous.rollovers if previous else 0,
                last_event="the sink accepted a record again",
                last_event_at=_utc_now(),
                rolled_aside=previous.rolled_aside if previous else None,
            )
            # The flap window is about a sink that keeps needing rescue. One that is writable again
            # starts a fresh window, or a slow drip of unrelated transients would eventually trip it.
            self._roll_flap.pop(sink, None)
            # A record landed, so the flap latch has nothing left to hold either.
            self._flap_latch.pop(sink, None)
            self._unanswered.discard(sink)
            self._escalation_failure_said.discard(sink)

    def _latch_after_roll(self, sink: str, *, now: float, tripped: bool) -> None:
        """Move the flap latch for one roll. Called under the lock, after the bound has run.

        ``tripped`` is the bound's own verdict on this roll. It latches the sink; a roll the bound
        calls a heal keeps a held latch while it comes within :data:`_ROLL_FLAP_WINDOW_SECONDS` of
        the last failure the latch saw, and releases it otherwise. Reads and writes the latch only."""
        last_failure_at = self._flap_latch.get(sink)
        if tripped or (
            last_failure_at is not None and now - last_failure_at <= _ROLL_FLAP_WINDOW_SECONDS
        ):
            self._flap_latch[sink] = now
        elif last_failure_at is not None:
            del self._flap_latch[sink]

    def _latch_after_failure(self, sink: str) -> None:
        """A stage-2 failure keeps a held latch from reading as a quiet sink. Called under the lock.
        It never starts a latch: only the bound does that."""
        if sink in self._flap_latch:
            self._flap_latch[sink] = time.monotonic()

    def _reads_unwritable(self, status: LogSinkStatus) -> bool:
        return status.state == "unwritable" or status.sink in self._flap_latch

    def can_log(self) -> bool:
        """Can this PROCESS still write a log record anywhere, as :meth:`status` reports the sinks?

        Not "did a sink break" — with two sinks configured, one dead beside one healthy still means
        the processing IS logged. A guard with no registered sinks (a process that never called
        ``configure_logging``) answers True: it has nothing to say about a log it does not own, and
        answering False would fail closed on a premise it cannot support. A sink the flap latch holds
        counts as unwritable here, as it does on :meth:`status`.

        The #122 halt's stop request is decided from each sink's own state without the latch, when
        a stage-2 event is built. Its re-arms ask :meth:`revalidate`, which answers as this does."""
        with self._lock:
            return self._process_can_log()

    def _process_can_log(self) -> bool:
        """:meth:`can_log`'s answer. Called under the lock."""
        if not self._sinks:
            return True
        return not all(self._reads_unwritable(s) for s in self._sinks.values())

    def revalidate(self) -> bool:
        """Re-test sinks whose own state is unwritable, and report whether the
        process can log, as :meth:`can_log` answers after the probes. The loop's comments say which
        such sinks are probed.

        **A cached state cannot answer this, and that is the whole reason this exists.** *Repaired*
        and *still broken* are indistinguishable from memory, which is exactly the distinction the
        fail-closed recovery path has to make. Each sink's probe is :meth:`_GuardedSinkMixin._probe_write`,
        so "writable" means *a record landed*, not *a stat call succeeded*.

        This is NOT the timer polling ADR 0162 rejected: it runs once, on an explicit operator recovery
        action, at the moment the decision is made — never on a schedule and never on the hot path.

        **A sink the flap latch alone holds is released here WITHOUT being written to** (BACKLOG
        #5812). Its own state is not ``unwritable``: the last thing recorded on it was a roll whose
        notice and re-written record landed, and this method answers for it from that, as it would
        with no latch. Writing to it instead would make this guard weaker than the bound alone,
        whatever the write: :meth:`record_healthy` resets the bound's window and streak; a roll heals
        a broken handle the next record would otherwise have rolled through
        :meth:`_GuardedSinkMixin.handleError`, where the bound counts it; and even one plain write
        can take a one-shot fault the next record would have met. Each of those lets a sink still
        flapping trip the bound later. The loop's comment says which sinks whose own state IS
        ``unwritable`` are probed and marked healthy. The answer is :meth:`can_log`'s, read under
        the lock after the probes."""
        with self._lock:
            # Every record_* call replaces a sink's status object, so the object itself tells
            # whether anything was recorded on the sink since this snapshot.
            dead = {
                name: status for name, status in self._sinks.items() if status.state == "unwritable"
            }
            for latched in [sink for sink in self._flap_latch if sink not in dead]:
                del self._flap_latch[latched]
        for name, seen in dead.items():
            # A sink is probed only if nothing was recorded on it since the snapshot, and marked
            # healthy only if nothing was recorded on it by the time its probe ends. Probing a
            # changed sink could write to one the latch alone now holds, and marking it healthy
            # would drop a latch or a failure recorded meanwhile. The lock is not held across a
            # sink's I/O, so a change between this check and the probe's write still meets the
            # probe.
            with self._lock:
                if self._sinks.get(name) is not seen:
                    continue
                probe = self._probes.get(name)
            # A sink registered without a self-test stays exactly as it is: we cannot ask it, and
            # guessing on its behalf is how a fail-closed control gets talked out of failing closed.
            if probe is None or not _probe_lands(probe):
                continue
            with self._lock:
                if self._sinks.get(name) is seen:
                    self.record_healthy(name)
        with self._lock:
            return self._process_can_log()

    def _fire(self, event: LogSinkEvent) -> bool:
        """Hand ``event`` to the responder, and report whether it was delivered: False when no
        responder is wired, the responder returned False, which it does when it dropped the
        event, or the responder raised. A raise writes a stderr line, for a stage-2 event at most
        once per break of the sink and responder."""
        with self._lock:
            callback = self._escalation
        if callback is None:
            return False
        try:
            delivered = callback(event)
        except Exception as exc:  # never-raise: we are already handling a logging failure
            if event.stage == "unwritable":
                # An owed event is fired again on every later failure of the break, so a
                # responder that keeps raising would otherwise write one line per dropped record.
                with self._lock:
                    if event.sink in self._escalation_failure_said:
                        return False
                    current = self._sinks.get(event.sink)
                    if current is not None and current.state == "unwritable":
                        self._escalation_failure_said.add(event.sink)
            # Scrubbed for the reason the stage strings are: this line goes straight to stderr,
            # below every handler filter (BACKLOG #1591).
            _last_resort(
                f"log-sink escalation for {_escape_only(event.sink, fallback=_LABEL_DROPPED)} "
                f"failed: {_safe_reason(exc)}"
            )
            return False
        return delivered is not False


#: The guard the current process's handlers are wired to. Installed by ``configure_logging``.
_ACTIVE: LogWriteGuard | None = None
_ACTIVE_LOCK = threading.Lock()


def active_guard() -> LogWriteGuard | None:
    """The process's installed guard, or None when logging was never configured through it."""
    with _ACTIVE_LOCK:
        return _ACTIVE


def set_active_guard(guard: LogWriteGuard | None) -> None:
    global _ACTIVE
    with _ACTIVE_LOCK:
        _ACTIVE = guard


def _probe_lands(probe: SinkProbe) -> bool:
    """Run one sink's self-test and report whether the record LANDED.

    A raise is the answer, not an error: "this sink still refuses writes" is exactly what
    :meth:`LogWriteGuard.revalidate` needs to learn, and it is called from a recovery path that has
    to survive every sink being dead. Catching broadly is deliberate and bounded — the probe reaches
    the filesystem through a handler the guard does not own, so the failure set is whatever the OS
    and that handler can raise, and any of them mean the same thing here."""
    try:
        probe()
    except Exception:
        return False
    return True


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _last_resort(message: str) -> None:
    """Write one PHI-free line to stderr — the only channel left when a sink is unwritable.

    Deliberately NOT a ``logging`` call: the logging tree is what just failed, and re-entering it is
    how a broken sink becomes an infinite loop. Carries the sink label and reason only; **no record
    content ever reaches this line.**

    **The scrub is at the callers, not in here, and that is not an oversight.**
    :func:`_guarded` reports its own failure through THIS function, so calling it from here would
    make a permanently-raising scrubber recurse without bound — the same shape as re-entering the
    logging tree. Every caller escapes what it interpolates, the sink label included."""
    stream = sys.stderr
    if stream is None:  # a pythonw.exe-style process with no stderr
        return
    with contextlib.suppress(Exception):
        # stderr is the floor. If it is gone too there is nowhere left to say so, and raising here
        # would turn a logging failure into an application crash.
        stream.write(f"messagefoundry: {message}\n")
        stream.flush()


#: Ceiling on what the guard stores in :class:`LogSinkStatus` and publishes over ``GET /status``.
#: Applied LAST, after both scrubs, and that ordering is the correctness point rather than a detail:
#: slicing BEFORE the credential pass can cut the terminator a pattern needs -- truncating
#: ``postgres://u:pw@host`` mid-password leaves ``_DSN_PASSWORD`` no trailing ``@`` to match, and the
#: prefix of the secret is then published unmasked. Slicing an already-escaped string can at worst
#: cut one backslash escape short, which cannot produce a control character.
_DIAGNOSTIC_LIMIT = 1000

#: Returned when the scrubbers themselves raise. A literal, with nothing at all from the input and
#: no ``len()`` or other call that could raise a second time inside the handler for the first.
_DIAGNOSTIC_DROPPED = "<diagnostic dropped: the scrubbers raised>"


#: The fallback for a PATH, kept distinct from :data:`_DIAGNOSTIC_DROPPED` because ``GET /status``
#: presents ``rolled_aside`` as the file an operator opens to recover the broken log. A sentence
#: about scrubbers reads like a filename there and is not one. Same reasoning for the sink LABEL,
#: which names the row on ``/status`` and in the alert.
_PATH_DROPPED = "<rolled-aside path unavailable>"
_LABEL_DROPPED = "<unnameable sink>"


def _guarded(scrub: Callable[[str], str], text: str, *, fallback: str) -> str:
    """Run ``scrub``, bound the result, and NEVER raise — the shared never-raise core (BACKLOG #1591).

    **Emit anyway if the scrub itself fails.** A guard that goes silent because its own scrubber
    raised is worse than one reporting a degraded string: the operator would lose the fact that a log
    sink broke at all. The degradation is reported rather than swallowed — ``fallback`` reaches every
    consumer of the string, and the stderr last-resort channel names the exception type. That call is
    itself suppressed, because a never-raise contract that formats an f-string first is not one; and
    every ``fallback`` is a bare literal for the same reason, so a caller passing something that is
    not a ``str`` cannot turn a log-write failure into an application crash.

    The slice is applied AFTER the scrub, and that ordering is a correctness point rather than a
    detail: slicing BEFORE the credential pass can cut the terminator a pattern needs — truncating
    ``postgres://u:pw@host`` mid-password leaves ``_DSN_PASSWORD`` no trailing ``@`` to match, and
    the prefix of the secret is then published unmasked. Slicing an already-escaped string can at
    worst cut one backslash escape short, which cannot produce a control character."""
    try:
        return scrub(text)[:_DIAGNOSTIC_LIMIT]
    except Exception as exc:
        with contextlib.suppress(Exception):
            # ascii() renders the class name with every control character escaped, so even a
            # pathological type cannot put a raw newline on the last-resort channel.
            _last_resort(
                f"a log-sink diagnostic could not be scrubbed ({ascii(type(exc).__name__)}); "
                "a placeholder was substituted"
            )
        return fallback


def _scrub_diagnostic(text: str) -> str:
    """Mask credential values, then escape control characters — **in the handler chain's order**.

    ``_install_phi_filters`` installs ``CredentialScrubFilter`` BEFORE ``ControlCharScrubFilter``,
    and reversing it here would not merely diverge, it would DEFEAT the credential pass: the patterns
    are whitespace-delimited, so ``bearer<LF>tok...`` matches while the escaped ``bearer\\ntok...``
    does not — the token would then reach every consumer in plaintext. The order this module needs is
    the order the chain already uses, for the same reason. The carriage pass sits between them, as
    ``BinaryCarriageScrubFilter`` does in the chain: after the credential pass, so a label joined to a
    carriage run keeps its value hidden (BACKLOG #5378)."""
    return scrub_control_chars(redact_binary_carriage(scrub_credentials(text)))


def _safe_diagnostic(text: str) -> str:
    """Make an exception-derived string safe to publish to the guard's consumers (BACKLOG #1591).

    **CALL IT EXACTLY ONCE, WHERE THE STRING IS BUILT. IT IS NOT IDEMPOTENT**, and the reason is the
    same coupling that fixes the order above: escaping removes the whitespace the credential value
    class terminates on. ``password=hunter2<LF>rest of it`` scrubs to
    ``password=<placeholder>\\nrest of it``; run that through again and ``_CREDENTIAL_KV`` sees no
    whitespace after the placeholder, so it swallows the escape and everything up to the next real
    space. A second pass therefore EATS the diagnostic rather than costing nothing. An earlier
    revision of this row scrubbed again at :meth:`LogWriteGuard.record_rollover` as belt and braces;
    that made ``/status`` disagree with the notice already written on the sink, so the belt was
    removed and the precondition written down instead.

    **What it adds to :func:`safe_exc`.** ``safe_exc`` redacts HL7-shaped PHI and truncates; it does
    **not** touch control characters and does not know the credential vocabulary. On the ordinary
    logging path those two are handler filters (``_install_phi_filters``), and the guard's own
    strings do not reliably reach them — see the module docstring's consumer list. So an ``OSError``
    whose message carried a CR LF pair used to forge a whole log line on the rolled sink.

    **Which filters of that chain this stands in for, and which it does not.**
    ``RedactionFilter`` is covered by :func:`safe_exc`, which :func:`_safe_reason` applies with it;
    ``CredentialScrubFilter``, ``BinaryCarriageScrubFilter`` and ``ControlCharScrubFilter`` are
    composed by :func:`_scrub_diagnostic`. ``CredentialQueryScrubFilter`` is scoped to a URL query string (OIDC
    ``code``/``state``), and the sinks this module guards are stdout and a local file, neither of
    which yields a diagnostic containing a request URL. **A guarded sink that could — an HTTP or
    syslog-collector sink — must revisit this.** The composition is not derived from the chain, so
    ``test_the_guards_scrub_composition_still_covers_the_installed_filter_chain`` pins the membership
    rather than leaving the next divergence to be noticed.

    **The input is bounded by construction, not by trust.** ``scrub_credentials`` runs regular
    expressions that are super-linear in the worst case, and this is the one code path in the engine
    that executes while logging is already broken. Every call site reaches this through
    :func:`_safe_reason`, so the input is always :func:`safe_exc` output and already truncated."""
    return _guarded(_scrub_diagnostic, text, fallback=_DIAGNOSTIC_DROPPED)


def _escape_only(text: str, *, fallback: str) -> str:
    """Escape the log alphabet and nothing else — for the two strings that are NOT diagnostics.

    The rolled-aside PATH and the SINK LABEL both reach the notice, ``GET /status`` and the stderr
    last-resort line, and both can carry the forged-line hazard: a newline is a legal filename
    character on POSIX, ``_roll`` is a documented subclass seam, and ``register`` takes an arbitrary
    label. Neither may go through the credential patterns. A path is not a credential-bearing
    diagnostic and those patterns would rewrite a legitimate one — a directory segment ending in a
    credential word followed by ``:`` or ``=`` has the rest of the path replaced by the placeholder,
    so ``/status`` would name a file that does not exist, during the incident this guard is for.

    Unlike :func:`_safe_diagnostic` this IS idempotent: escaping adds no control characters, so a
    second pass finds nothing to do. When a value IS hostile the escaped form deliberately stops
    being the literal: an operator un-escaping one path beats a notice that can forge a log line.

    THE ESCAPE IS THE WHOLE LOG ALPHABET, NOT ONLY THE NEWLINE, AND THAT COST IS ACCEPTED (BACKLOG
    #2976 item 4). Since vault BACKLOG #2815, :func:`scrub_control_chars` escapes the whole log
    alphabet, which ``controlchars._escapes_in_a_log_line`` states once. So a legitimate
    rolled-aside file name holding a character from it shows
    escaped on ``GET /status``, in the notice and in the stderr line. At least these could appear in
    a real name: a zero-width joiner or non-joiner, a soft hyphen and a byte-order mark. Most
    escapes are JSON's own spelling, such as ``\\u200d``, which an operator can read back to the
    name on disk. A lone surrogate is the exception: it shows as its hex after a doubled backslash,
    so it reads as text naming the code point (``controlchars._log_escape`` says why). A
    bidirectional override in a path is the same kind of hazard as a newline: it changes what a
    reader sees. So the path takes the log's alphabet rather than a narrower one of its own."""
    return _guarded(scrub_control_chars, text, fallback=fallback)


def _escape_unencodable(exc: UnicodeError) -> tuple[str, int]:
    """The codecs error handler behind :func:`_encodable`: each character the codec refused, as
    the log escapes one (:func:`~messagefoundry.controlchars.json_unicode_escape`, and a lone
    surrogate as :func:`~messagefoundry.controlchars.escape_lone_surrogates` spells it)."""
    if not isinstance(exc, UnicodeEncodeError):
        raise exc
    refused = exc.object[exc.start : exc.end]
    return (
        "".join(
            escaped
            if (escaped := escape_lone_surrogates(ch)) != ch
            else json_unicode_escape(ord(ch))
            for ch in refused
        ),
        exc.end,
    )


_ESCAPE_HANDLER = "messagefoundry.logging_guard.escape"
codecs.register_error(_ESCAPE_HANDLER, _escape_unencodable)


def _encodable(line: str, encoding: object) -> str:
    """``line`` with each character ``encoding`` cannot encode, ASCII ones included, spelled as a
    JSON ``\\uXXXX`` escape, a surrogate pair for one outside the BMP, and a lone surrogate as the
    log spells it (:func:`~messagefoundry.controlchars.escape_lone_surrogates`) (BACKLOG #5813). An
    ``encoding`` that is not a known text codec, or that cannot encode the escapes themselves,
    reads as ASCII. Never raises."""
    codec = encoding if isinstance(encoding, str) else "ascii"
    try:
        return line.encode(codec, _ESCAPE_HANDLER).decode(codec)
    except (LookupError, ValueError, UnicodeError, TypeError):
        # LookupError: unknown, or not a text encoding; ValueError: a name codecs refuses (an
        # embedded NUL); UnicodeError: a codec that cannot encode the escapes or decode itself.
        return line.encode("ascii", _ESCAPE_HANDLER).decode("ascii")


#: The stderr format-fault line's entry for a line the sink's stream could not encode, written
#: escaped (BACKLOG #5813). The record formatted; it is counted on that line all the same.
_ESCAPED_FAULT = (
    "a line held characters the sink's stream cannot encode; it was written with them escaped"
)


#: The fallback for a record's logger or level name, or an exception's type name, in the
#: unformattable-record notice and the formatter-fault line.
_RECORD_LABEL_DROPPED = "<unnameable>"

#: The formatter-fault line on stderr is written at most once per this many seconds per sink; the
#: faults in between are only counted, into the next line written (BACKLOG #5813).
_FORMAT_FAULT_REPORT_SECONDS = 60.0

#: The most distinct kinds of format fault one sink counts between two such lines; a new kind past
#: it is counted under :data:`_FORMAT_FAULT_OTHER`.
_FORMAT_FAULT_KINDS = 16
_FORMAT_FAULT_OTHER = "format faults of other kinds"


def _type_name(exc: BaseException) -> str:
    """``exc``'s type name through ``ascii()``, or a placeholder, which is said on the stderr
    last-resort line. Never raises."""
    try:
        return ascii(type(exc).__name__)
    except Exception:
        _last_resort(
            "an exception's type name could not be rendered for the log write guard; "
            "a placeholder was substituted"
        )
        return _RECORD_LABEL_DROPPED


def _safe_reason(exc: BaseException | None) -> str:
    """The guard's one way to turn a caught exception into a publishable reason string.

    Written once so the pairing cannot be half-applied: :func:`safe_exc` alone leaves the control
    characters and the credentials, :func:`_safe_diagnostic` alone leaves the PHI and the length
    unbounded, and a fifth diagnostic added later gets both by reaching for this name."""
    if exc is None:
        return "log write failed (no exception recorded)"
    return _safe_diagnostic(safe_exc(exc))


# The mixin needs ``stream`` / ``terminator`` / ``format`` from the concrete handler it is mixed into.
# Re-DECLARING them on the mixin collides with the real definitions (a mixin listed first wins the MRO,
# so a stub there would shadow the actual formatter); inheriting the stdlib base only WHEN TYPE CHECKING
# gives mypy the real signatures while leaving the runtime MRO exactly as if the mixin were plain.
if TYPE_CHECKING:
    _SinkBase = logging.StreamHandler[TextIO]
else:
    _SinkBase = object


class _GuardedSinkMixin(_SinkBase):
    """The two-stage ``handleError`` shared by every guarded sink.

    Subclasses supply :meth:`_roll` — how *this* kind of sink is rolled. Everything after the roll
    (write the rollover notice, re-write the record whose emit failed or its stand-in) is identical,
    because "is the replacement writable?" is answered the same way for every sink: by writing to
    it and seeing whether that raises."""

    _guard: LogWriteGuard
    _sink_label: str
    _reentry: threading.local

    def _init_guard(self, guard: LogWriteGuard, sink: str) -> None:
        self._guard = guard
        self._sink_label = sink
        # Per-thread re-entrancy latch. A failure raised WHILE handling a failure must not recurse:
        # the inner call returns immediately and the outer one converts the raise into Stage 2.
        self._reentry = threading.local()
        #: Format faults since the last stderr line about them, by kind, and when that line was
        #: written.
        self._format_faults: dict[str, int] = {}
        self._format_fault_reported_at: float | None = None
        guard.register(sink, probe=self._probe_write)

    # --- subclass seam --------------------------------------------------------

    def _roll(self) -> str | None:
        """Roll this sink and leave a writable stream in place. Return the path the previous file was
        renamed to, or None when this sink has no file to rename. Raise to force Stage 2."""
        raise NotImplementedError

    # --- the guard ------------------------------------------------------------

    def handleError(self, record: logging.LogRecord) -> None:
        """Two-stage response to a failed ``emit`` — the stdlib override that IS this control.

        Replaces :meth:`logging.Handler.handleError`, which prints a traceback, the call stack AND the
        failing record's message/arguments to stderr, and which is a complete no-op when the process
        global ``logging.raiseExceptions`` is False. Neither behaviour is acceptable here: a
        fail-closed control an ambient setting can switch off is not a control, and no record content
        leaves this method except through the sink's own (post-redaction-filter) formatter."""
        if getattr(self._reentry, "active", False):
            return
        self._reentry.active = True
        try:
            failure = sys.exception()
            # A record that cannot be formatted is no reason to roll a healthy sink (BACKLOG
            # #5813). When the formatter can format the stand-in, it is written in the record's
            # place: if the sink takes it, neither stage runs and the fault is reported on the
            # stderr line only, with no alert and nothing on /status; if the sink refuses it, the
            # two stages below decide. When the formatter
            # cannot format the stand-in either, the sink is recorded unwritable without a roll,
            # because a roll cannot clear a formatter fault.
            formatted, stand_in = self._stand_in_for(record)
            stand_in_line: str | None = None
            if stand_in is not None:
                notice, kind = stand_in
                try:
                    stand_in_line = self._notice_line(notice)
                except Exception as format_exc:
                    notice_kind = _type_name(format_exc)
                    self._note_format_fault(
                        f"could not format a record ({kind}), nor the notice standing in for it "
                        f"({notice_kind}); nothing was written for it"
                    )
                    self._report_format_faults()
                    # Built from literals and ``ascii()`` type names, so already scrubbed.
                    self._guard.record_unwritable(
                        self._sink_label,
                        reason=(
                            f"formatter fault: the sink's formatter could not format a record "
                            f"({kind}) nor the guard's notice ({notice_kind}); the sink was not "
                            "rolled and nothing was written to it"
                        ),
                        cause="because its formatter fails",
                    )
                    return
                self._note_format_fault(
                    f"could not format a record ({kind}); a notice naming its logger is written "
                    "in its place unless the sink refuses it"
                )
                self._report_format_faults()
                try:
                    self._write_line(stand_in_line)
                    return
                except Exception as sink_exc:
                    # The sink refused the stand-in too, so ITS failure is the reason now.
                    failure = sink_exc
            elif isinstance(failure, UnicodeEncodeError) and formatted is not None:
                # The record formats, and the stream has no byte for a character in the line (a
                # strict UTF-8 file and a lone surrogate, say; the stdout sink's emit already
                # escapes through _write_line). That is the line's fault, not the sink's, so the
                # line already formatted is written again escaped, and neither stage runs. A roll
                # would only re-resolve to the same stream and fail the same way (BACKLOG #5813).
                try:
                    self._write_line(formatted + self.terminator)
                    return
                except Exception as sink_exc:
                    failure = sink_exc
            # SCRUBBED HERE, WHERE IT IS BUILT, AND NOWHERE ELSE (BACKLOG #1591). The notice below is
            # written by ``_write_notice`` straight to the sink's stream through ``_write_line``, so
            # no handler filter will ever see it, and the three other consumers of this string take
            # it from the guard unchanged. See the module docstring.
            reason = _safe_reason(failure)
            try:
                # The path is the notice's OTHER interpolated limb, so it is escaped on the same
                # terms -- a half-scrubbed notice is a control resting on a false premise.
                rolled_aside = self._roll()
                if rolled_aside:
                    rolled_aside = _escape_only(rolled_aside, fallback=_PATH_DROPPED)
                # STAGE 1 is only complete once the REPLACEMENT has actually accepted a write. Both
                # writes below go to the fresh stream; either raising means the replacement is no
                # better than the file it replaced, which is precisely the Stage 2 condition.
                self._write_notice(
                    f"application log sink {self._sink_label!r} was rolled after a write failure "
                    f"({reason})"
                    + (f"; previous file renamed to {rolled_aside}" if rolled_aside else "")
                )
                if stand_in_line is None:
                    self._rewrite(record)
                else:
                    self._write_line(stand_in_line)
            except Exception as roll_exc:
                # ``_safe_reason``, not a bare ``safe_exc``: the guard scrubs nothing of its own, so
                # each limb of the join has to arrive scrubbed. Bounding them SEPARATELY is also
                # what keeps the stage-2 cause -- the operationally important half -- from being the
                # part a single bound on the composed string would cut.
                self._guard.record_unwritable(
                    self._sink_label,
                    reason=f"{reason}; the replacement failed too: {_safe_reason(roll_exc)}",
                )
                return
            self._guard.record_rollover(self._sink_label, reason=reason, rolled_aside=rolled_aside)
        finally:
            self._reentry.active = False

    def _stand_in_for(
        self, record: logging.LogRecord
    ) -> tuple[str, None] | tuple[None, tuple[str, str]]:
        """``(the formatted record, None)`` when ``record`` formats; otherwise ``(None, (notice,
        kind))``, the notice to write in its place with the formatting exception's type name
        (BACKLOG #5813). Never raises.

        A record this handler cannot format is the record's fault, not the sink's: the stand-in is
        a notice naming its logger, its level and the exception's type, never its content or the
        exception's message. It goes through the sink's own formatter and stream. The rule for
        each outcome is ADR 0162 Amendment C's. On the handlers ``configure_logging`` builds,
        ``RedactionFilter`` already replaces a record whose message cannot be rendered, so this is
        reached only by a formatter that fails where the filter did not."""
        try:
            formatted = self.format(record)
        except Exception as exc:
            # The exception's TYPE only: its message can quote the record's format string or an
            # argument, and this notice goes below every handler filter.
            kind = _type_name(exc)
            # Quoted by hand, not with ``!r``: the label is already escaped, and ``repr`` would
            # escape its backslashes a second time.
            notice = (
                f"a log record from logger '{self._record_label(record, 'name')}' at level "
                f"{self._record_label(record, 'levelname')} could not be formatted ({kind}); it "
                "was not written"
            )
            return None, (notice, kind)
        return formatted, None

    def _record_label(self, record: logging.LogRecord, attribute: str) -> str:
        """A record's logger or level name, escaped for a notice. Never raises: a caller can delete
        either attribute or set it to any object, and that object's ``str`` may raise, often for
        the same reason the record did not format. ``attribute`` is a literal from the caller. A
        failure is counted as a format fault, so it is said on stderr at that line's rate."""
        try:
            return _escape_only(str(getattr(record, attribute)), fallback=_RECORD_LABEL_DROPPED)
        except Exception:
            self._note_format_fault(
                f"could not render a log record's {attribute}; a placeholder was substituted"
            )
            return _RECORD_LABEL_DROPPED

    def _note_format_fault(self, detail: str) -> None:
        """Count one format fault of the kind ``detail`` names, for :meth:`_report_format_faults`.
        ``detail`` is built from literals and :func:`_type_name` output, and carries nothing from
        the record. Past :data:`_FORMAT_FAULT_KINDS` distinct kinds, a new kind is counted under
        one catch-all kind, so a burst of varied faults cannot grow this without bound."""
        faults = self._format_faults
        if detail not in faults and len(faults) >= _FORMAT_FAULT_KINDS:
            detail = _FORMAT_FAULT_OTHER
        faults[detail] = faults.get(detail, 0) + 1

    def _report_format_faults(self, *, force: bool = False) -> None:
        """Say on the stderr last-resort line the format faults counted since the last such line,
        each kind with its count, at most once per :data:`_FORMAT_FAULT_REPORT_SECONDS` unless
        ``force``. Faults counted inside that interval wait for the next call after it: the next
        fault, the next ``flush`` (every record a stream handler emits ends in one) or ``close``,
        which forces it. Called under the handler's lock. Never raises."""
        # ``getattr``: logging can flush or close a handler whose constructor raised before
        # ``_init_guard`` ran.
        faults: dict[str, int] | None = getattr(self, "_format_faults", None)
        if not faults:
            return
        now = time.monotonic()
        last = self._format_fault_reported_at
        if not force and last is not None and now - last < _FORMAT_FAULT_REPORT_SECONDS:
            return
        self._format_faults = {}
        self._format_fault_reported_at = now
        kinds = "; ".join(f"{detail} (x{count})" for detail, count in faults.items())
        _last_resort(
            f"log sink {_escape_only(self._sink_label, fallback=_LABEL_DROPPED)} format faults "
            f"since its last such line: {kinds}"
        )

    def flush(self) -> None:
        """Flush the sink, and first say any format faults whose report interval has passed."""
        self.acquire()
        try:
            self._report_format_faults()
        finally:
            self.release()
        super().flush()

    def close(self) -> None:
        """Say any format faults not yet said, then close the sink."""
        self.acquire()
        try:
            self._report_format_faults(force=True)
        finally:
            self.release()
        super().close()

    def _probe_write(self) -> None:
        """:data:`SinkProbe` for this sink: answer "can you take a record again?" BY TAKING ONE.

        Raises when the sink still refuses, which is what :meth:`LogWriteGuard.revalidate` reads. The
        roll on the retry is load-bearing rather than defensive: after a genuinely repaired
        destination the handler is still holding the CLOSED handle it died with, so a bare re-write
        would report the sink dead forever and a fixed disk would never recover. Rolling re-opens at
        the live path — and if the destination is still broken the roll or the second write raises,
        which is the correct answer. Deliberately :meth:`_write_line`, a direct stream write, never
        ``emit``: an ``emit`` failure would route into :meth:`handleError` and be converted into a
        stage-1/stage-2 transition, so the probe would silently mutate the very state it is trying
        to measure. The notice is formatted before the write and outside the retry, so a formatter
        that cannot format it raises here without rolling the sink: a formatter fault is not a fault
        a roll can clear."""
        line = self._notice_line(
            f"application log sink {self._sink_label!r} accepted a record again"
        )
        # Under the handler's lock, as emit's writes are: revalidate() calls this from another
        # thread, and the escape in _write_line counts a format fault the lock guards.
        with self.lock if self.lock is not None else contextlib.nullcontext():
            try:
                self._write_line(line)
            except Exception:
                self._roll()
                self._write_line(line)

    def _write_notice(self, message: str) -> None:
        """Record the rollover event ON the rolled sink, through the sink's own formatter so a JSON
        sink stays one-object-per-line. Built here from a fixed string, so it carries no PHI."""
        self._write_line(self._notice_line(message))

    def _notice_line(self, message: str) -> str:
        """``message`` as a guard notice, formatted by the sink's own formatter, terminator included.
        Raises what the formatter raises; writes nothing."""
        notice = logging.LogRecord(
            name=_NOTICE_LOGGER,
            level=logging.WARNING,
            pathname=__file__,
            lineno=0,
            msg=message,
            args=(),
            exc_info=None,
        )
        return self.format(notice) + self.terminator

    def _rewrite(self, record: logging.LogRecord) -> None:
        """Re-write the record whose emit failed, so the roll does not cost a log line (count-and-log).
        ``record`` already passed this handler's redaction/scrub filters — they run in
        ``Handler.handle`` and mutate the record in place — so formatting it here yields the redacted
        rendering, never the raw one."""
        self._emit_direct(record)

    def _emit_direct(self, record: logging.LogRecord) -> None:
        """Format + write + flush WITHOUT going through ``emit`` — an ``emit`` failure would re-enter
        ``handleError`` and be swallowed by the latch, hiding the very Stage 2 we are trying to detect.
        Here the exception propagates to :meth:`handleError`'s caller and becomes Stage 2."""
        self._write_line(self.format(record) + self.terminator)

    def _write_line(self, line: str) -> None:
        """Write and flush an already formatted line; a sink failure propagates.

        Every write the guard makes comes here, the stdout sink's own record writes included
        (:meth:`GuardedStreamHandler.emit`), so a line the stream has no byte for is escaped for
        every one of them, the roll notice and the probe included (BACKLOG #5813). When the stream
        names its ``encoding``, each character that codec cannot encode is escaped
        (:func:`_encodable`) BEFORE the write, so the escape wins over a stream that would replace
        the character itself, as serve's hardened stdout does (``errors="replace"``,
        ``console_streams.harden_console_streams``), and a stream that writes in chunks never takes
        a prefix twice. When the write still raises ``UnicodeEncodeError``, as a stream with no
        ``encoding`` or one that does not name the encoder it uses can, the line is written again
        with everything outside ASCII escaped; if that changes nothing, or raises, that error
        propagates. A write whose line was escaped is counted for the stderr format-fault line.
        Called under the handler's lock, which that count needs."""
        encoding = getattr(self.stream, "encoding", None)
        written = _encodable(line, encoding) if isinstance(encoding, str) else line
        try:
            self._write_raw(written)
        except UnicodeEncodeError:
            ascii_only = _encodable(line, None)
            if ascii_only == written:
                raise
            self._write_raw(ascii_only)
            written = ascii_only
        if written != line:
            self._note_format_fault(_ESCAPED_FAULT)
            self._report_format_faults()

    def _write_raw(self, line: str) -> None:
        self.stream.write(line)
        self.stream.flush()


class GuardedStreamHandler(_GuardedSinkMixin, logging.StreamHandler[TextIO]):
    """The guarded **stdout** sink (the engine's default, captured to disk by NSSM).

    Stage 1 here has **no file to rename** — the engine does not own the file NSSM captures stdout
    into, and renaming a supervisor's file out from under it is how two rotation owners corrupt one
    log. The roll is instead a **RE-RESOLVE**: rebind to whatever ``sys.stdout`` is *now* and write
    to that.

    **A bare re-attempt on the SAME object was the original design and it could never heal, which
    made this sink a hair trigger on the fail-closed halt.** The handler holds a reference to the
    stream object it was constructed with; when that object is closed or replaced, every subsequent
    write raises ``ValueError: I/O operation on closed file`` — including stage 1's own notice write,
    so stage 1 failed by construction and *every* stdout write failure escalated to stage 2 and
    stopped the engine. Measured, in the full test suite: a supervisor-like stream swap (pytest's
    capture teardown) halted a running load engine's seven connections and the run sent zero
    messages. The same shape in production is an NSSM capture-file swap or a closed pipe — routine
    events that must not take feeds down.

    Re-resolving is the honest roll for a stream we did not open, and it is what "a re-attempt
    clears the transient" was always claiming to do: the replacement handle is the live one. If
    ``sys.stdout`` is itself gone or also refuses the write, the notice write raises and stage 2
    fires with exactly the fail-closed meaning it should have."""

    def __init__(self, stream: TextIO, *, guard: LogWriteGuard, sink: str = "stdout") -> None:
        super().__init__(stream)
        self._init_guard(guard, sink)

    def emit(self, record: logging.LogRecord) -> None:
        """:meth:`logging.StreamHandler.emit` with the write routed through :meth:`_write_line`,
        so the record's own line is escaped before the stream sees it (BACKLOG #5813). serve sets
        its stdout to ``errors="replace"``, which never raises, so an escape made only after a
        failed write would never run there and the line would carry ``?``. A failure still reaches
        :meth:`handleError`, which is this control."""
        try:
            self._emit_direct(record)
        except RecursionError:  # as the stdlib does: see CPython issue 36272
            raise
        except Exception:
            self.handleError(record)

    def _roll(self) -> str | None:
        # No rename: nothing here is the engine's file. Rebind to the CURRENT sys.stdout, which is a
        # different object from the one we were built with precisely in the case worth recovering
        # from. `is not None` rather than truthiness: a stream object's __bool__ is not a liveness
        # test. Nothing to return — there is no rolled-aside path for a stream.
        live = sys.stdout
        if live is not None and live is not self.stream:
            self.stream = live
        return None


class GuardedFileHandler(_GuardedSinkMixin, logging.handlers.RotatingFileHandler):
    """The guarded **engine-managed** application-log file (``[logging].file``, opt-in).

    The engine is the *sole* rotation owner of this path (size-based, ``file_max_bytes`` /
    ``file_backup_count``); NSSM keeps owning the captured stdout files, and the settings validator
    refuses a ``file`` inside ``[logging].log_dir`` so the two can never fight over one file
    (docs/SERVICE.md). Stage 1 is the real rename-and-roll: close, rename the broken file aside, open
    a fresh file at the live path, write the rollover event, re-write the failed record."""

    def __init__(
        self,
        filename: str,
        *,
        guard: LogWriteGuard,
        sink: str = "file",
        max_bytes: int = 0,
        backup_count: int = 0,
    ) -> None:
        # delay=False: an unopenable path must fail HERE, at configuration time, rather than at the
        # first record — the engine refusing to start beats an engine that starts unable to log.
        super().__init__(
            filename,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
            delay=False,
        )
        self._init_guard(guard, sink)
        self._roll_seq = 0

    def _roll(self) -> str | None:
        stream = self.stream
        if stream is not None:
            # Best-effort BY DEFINITION: we are here because this handle is broken, so closing it is
            # allowed to fail. Suppressing is the point, not an oversight.
            with contextlib.suppress(Exception):
                stream.close()
            # FileHandler.stream is Optional in practice (close() nulls it); typeshed agrees.
            self.stream = None
        self._roll_seq += 1
        aside = f"{self.baseFilename}.broken-{_utc_now().replace(':', '')}-{self._roll_seq}"
        rolled: str | None = aside
        try:
            os.replace(self.baseFilename, aside)
        except FileNotFoundError:
            # Deleted out from under us (an over-eager cleaner, a shared mount): there is nothing to
            # move aside and a fresh open IS the roll.
            rolled = None
        # Any OTHER OSError (locked, permission denied, the parent is no longer a directory) means we
        # could NOT get the broken file out of the way. It propagates: rolling onto a file we could not
        # move is a false recovery, and reporting a heal that did not happen is worse than stopping.
        self.stream = self._open()
        return rolled
