# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
  recorded** into it, and the record whose write failed is re-written. A transient condition — a
  momentary lock, an antivirus scan, a rotation race — heals here and stops nothing.
* **Stage 2 — STOP.** Only when the **replacement** also cannot be written does the guard escalate.
  A single-stage stop would take feeds down on a hiccup; that is an outage generator, not an invariant.

**And a third thing, which is not a stage but is half the enforcement: UN-stopping.** Recovery is an
operator assertion — *"I fixed the disk"* — and a fail-closed control that simply believes it is a
control with an off switch. :meth:`LogWriteGuard.revalidate` therefore re-tests a dead sink **by
writing a real record to it**, because ``unwritable`` is only ever set by a failed write and nothing
clears it on its own: *repaired* and *still broken* are indistinguishable from memory, which is
exactly the distinction recovery has to make. The engine gates every re-arm path on that answer.

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
  sink's own stream, never to the last-resort channel. The stderr last-resort line carries the sink
  label and a :func:`~messagefoundry.redaction.safe_exc` reason and **nothing from the record**. The
  guard also never raises the service level to DEBUG.
* **Stdlib only, no engine imports.** The guard is reachable from ``logging_setup`` (which every
  process configures) and must not drag ``pipeline``/``store``/``api`` in behind it.
"""

from __future__ import annotations

import contextlib
import logging
import logging.handlers
import os
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TextIO

from messagefoundry.redaction import safe_exc

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

#: ``rolled`` — Stage 1 healed the sink. ``unwritable`` — Stage 2, the replacement failed too.
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
#: cheap, non-blocking and never raise — the guard is already handling a failure.
EscalationCallback = Callable[[LogSinkEvent], None]

#: One sink's "are you writable again?" self-test. Writes a real record to itself and RAISES if the
#: sink still refuses it — see :meth:`LogWriteGuard.revalidate`.
SinkProbe = Callable[[], None]


class LogWriteGuard:
    """Process-wide state + escalation seam for the guarded application-log sinks.

    Thread-safe: log records are emitted from the event loop, from handler worker threads and from
    connector threads alike, so every mutation is under one lock. Escalation is **latched per sink** —
    a sink that is already ``unwritable`` does not re-fire on every subsequent record (that would turn
    one broken disk into an unbounded alert storm), and a later successful Stage-1 roll clears the
    latch so a genuine re-break pages again."""

    def __init__(self, *, stop_on_unwritable: bool = True) -> None:
        self._lock = threading.RLock()
        self._sinks: dict[str, LogSinkStatus] = {}
        #: sink -> (window start, rolls in window) — the anti-flap bound, see :meth:`record_rollover`.
        self._roll_flap: dict[str, tuple[float, int]] = {}
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
        channel rather than ``logging``: this class must not depend on the tree it guards."""
        with self._lock:
            previous = self._escalation
            self._escalation = callback
        if callback is not None and previous is not None and previous != callback:
            _last_resort(
                "a second log-sink escalation responder replaced the first; the engine that "
                "registered first is no longer guarded by this process's log write guard"
            )

    def clear_escalation(self, callback: EscalationCallback) -> None:
        """Unwire ``callback`` — but ONLY if it is still the installed one. A runner tearing down must
        not silently unwire a *different* runner that registered after it (the second engine in a test
        process would then be unguarded, and nothing would say so)."""
        with self._lock:
            if self._escalation == callback:
                self._escalation = None

    def status(self) -> list[LogSinkStatus]:
        with self._lock:
            return sorted(self._sinks.values(), key=lambda s: s.sink)

    # --- stage transitions ----------------------------------------------------

    def record_rollover(self, sink: str, *, reason: str, rolled_aside: str | None) -> None:
        """Stage 1 succeeded: ``sink`` was rolled and is writable again.

        **Bounded, because "heals" and "keeps needing to be healed" are not the same sink.** A sink
        that accepts the notice and the re-written record and then fails again on the next one would
        otherwise roll forever — one rename, one fresh file and one escalation per log record. Past
        :data:`_MAX_ROLLS_PER_WINDOW` rolls inside :data:`_ROLL_FLAP_WINDOW_SECONDS` the sink is
        declared unwritable instead: a log you must replace every few seconds is not a working log,
        and stage 2 is the honest verdict on it."""
        with self._lock:
            previous = self._sinks.get(sink)
            now = time.monotonic()
            first_at, streak = self._roll_flap.get(sink, (now, 0))
            if now - first_at > _ROLL_FLAP_WINDOW_SECONDS:
                first_at, streak = now, 0
            streak += 1
            self._roll_flap[sink] = (first_at, streak)
            self._sinks[sink] = LogSinkStatus(
                sink=sink,
                state="rolled",
                rollovers=(previous.rollovers if previous else 0) + 1,
                last_event=reason,
                last_event_at=_utc_now(),
                rolled_aside=rolled_aside,
            )
        if streak > _MAX_ROLLS_PER_WINDOW:
            self.record_unwritable(
                sink,
                reason=(
                    f"{reason}; the sink needed rolling {streak} times in "
                    f"{_ROLL_FLAP_WINDOW_SECONDS:.0f}s, which is a failing log rather than a transient"
                ),
            )
            return
        self._fire(
            LogSinkEvent(sink=sink, stage="rolled", reason=reason, rolled_aside=rolled_aside)
        )

    def record_unwritable(self, sink: str, *, reason: str) -> None:
        """Stage 2: the replacement could not be written either. Escalates ONCE per break.

        **The STOP is asked for only when EVERY guarded sink is unwritable, and that is a
        correctness point, not a softening.** The ruling is *"we never want to process stuff if the
        processing cannot be logged"* — so the question the halt must answer is "can this process
        still log?", not "did a sink break?". With ``[logging].file`` configured there are two sinks;
        one of them failing while the other keeps accepting writes means the processing IS still
        logged, and halting there would be a control resting on a false premise. When there is only
        one sink (the default, stdout-only) the two questions coincide and the halt fires exactly as
        before. The sink is still recorded unwritable, still alerted and still shown on
        ``/status`` — visibility is unconditional; only the ENFORCEMENT is conditioned on the thing
        the enforcement is about."""
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
        if already_down:
            # Latched: one page per break, not one per dropped record. Without this a broken disk
            # turns every subsequent log line into an alert AND a stderr line, and the storm buries
            # the one message that mattered.
            return
        _last_resort(
            f"LOG SINK {sink} IS UNWRITABLE after a rollover attempt: {reason}"
            + ("" if all_down else "; another sink is still writable, so nothing is being stopped")
        )
        self._fire(
            LogSinkEvent(
                sink=sink,
                stage="unwritable",
                reason=reason,
                stop_requested=self.stop_on_unwritable and all_down,
            )
        )

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

    def can_log(self) -> bool:
        """Can this PROCESS still write a log record anywhere? The question the #122 halt is about.

        Not "did a sink break" — with two sinks configured, one dead beside one healthy still means
        the processing IS logged. A guard with no registered sinks (a process that never called
        ``configure_logging``) answers True: it has nothing to say about a log it does not own, and
        answering False would fail closed on a premise it cannot support."""
        with self._lock:
            if not self._sinks:
                return True
            return not all(s.state == "unwritable" for s in self._sinks.values())

    def revalidate(self) -> bool:
        """Re-test every unwritable sink BY WRITING TO IT, and report whether the process can log.

        **A cached state cannot answer this, and that is the whole reason this exists.** ``unwritable``
        is only ever set by a failed write, and nothing clears it on its own — so after an operator
        fixes the disk the guard still reads "broken", and before they fix it the guard reads "broken"
        too. The two situations are indistinguishable from memory, which is exactly the distinction the
        fail-closed recovery path has to make. Each sink's probe writes a real record through the real
        formatter, rolling the sink first if its live handle is stale (a repaired directory still leaves
        the old handle closed), so "writable" means *a record landed*, not *a stat call succeeded*.

        This is NOT the timer polling ADR 0162 rejected: it runs once, on an explicit operator recovery
        action, at the moment the decision is made — never on a schedule and never on the hot path."""
        with self._lock:
            dead = [name for name, status in self._sinks.items() if status.state == "unwritable"]
            probes = [(name, self._probes.get(name)) for name in dead]
        for name, probe in probes:
            # A sink registered without a self-test stays exactly as it is: we cannot ask it, and
            # guessing on its behalf is how a fail-closed control gets talked out of failing closed.
            if probe is not None and _probe_lands(probe):
                self.record_healthy(name)
        return self.can_log()

    def _fire(self, event: LogSinkEvent) -> None:
        with self._lock:
            callback = self._escalation
        if callback is None:
            return
        try:
            callback(event)
        except Exception as exc:  # never-raise: we are already handling a logging failure
            _last_resort(f"log-sink escalation for {event.sink} failed: {safe_exc(exc)}")


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
    content ever reaches this line.**"""
    stream = sys.stderr
    if stream is None:  # a pythonw.exe-style process with no stderr
        return
    with contextlib.suppress(Exception):
        # stderr is the floor. If it is gone too there is nowhere left to say so, and raising here
        # would turn a logging failure into an application crash.
        stream.write(f"messagefoundry: {message}\n")
        stream.flush()


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
    (write the rollover notice, re-write the record whose emit failed, decide stage 1 vs stage 2) is
    identical, because "is the replacement writable?" is answered the same way for every sink: by
    writing to it and seeing whether that raises."""

    _guard: LogWriteGuard
    _sink_label: str
    _reentry: threading.local

    def _init_guard(self, guard: LogWriteGuard, sink: str) -> None:
        self._guard = guard
        self._sink_label = sink
        # Per-thread re-entrancy latch. A failure raised WHILE handling a failure must not recurse:
        # the inner call returns immediately and the outer one converts the raise into Stage 2.
        self._reentry = threading.local()
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
            exc = sys.exception()
            reason = (
                safe_exc(exc) if exc is not None else "log write failed (no exception recorded)"
            )
            try:
                rolled_aside = self._roll()
                # STAGE 1 is only complete once the REPLACEMENT has actually accepted a write. Both
                # writes below go to the fresh stream; either raising means the replacement is no
                # better than the file it replaced, which is precisely the Stage 2 condition.
                self._write_notice(
                    f"application log sink {self._sink_label!r} was rolled after a write failure "
                    f"({reason})"
                    + (f"; previous file renamed to {rolled_aside}" if rolled_aside else "")
                )
                self._rewrite(record)
            except Exception as roll_exc:
                self._guard.record_unwritable(
                    self._sink_label,
                    reason=f"{reason}; the replacement failed too: {safe_exc(roll_exc)}",
                )
                return
            self._guard.record_rollover(self._sink_label, reason=reason, rolled_aside=rolled_aside)
        finally:
            self._reentry.active = False

    def _probe_write(self) -> None:
        """:data:`SinkProbe` for this sink: answer "can you take a record again?" BY TAKING ONE.

        Raises when the sink still refuses, which is what :meth:`LogWriteGuard.revalidate` reads. The
        roll on the retry is load-bearing rather than defensive: after a genuinely repaired
        destination the handler is still holding the CLOSED handle it died with, so a bare re-write
        would report the sink dead forever and a fixed disk would never recover. Rolling re-opens at
        the live path — and if the destination is still broken the roll or the second write raises,
        which is the correct answer. Deliberately :meth:`_emit_direct`, never ``emit``: an ``emit``
        failure would route into :meth:`handleError` and be converted into a stage-1/stage-2
        transition, so the probe would silently mutate the very state it is trying to measure."""
        message = f"application log sink {self._sink_label!r} accepted a record again"
        try:
            self._write_notice(message)
        except Exception:
            self._roll()
            self._write_notice(message)

    def _write_notice(self, message: str) -> None:
        """Record the rollover event ON the rolled sink, through the sink's own formatter so a JSON
        sink stays one-object-per-line. Built here from a fixed string, so it carries no PHI."""
        notice = logging.LogRecord(
            name=_NOTICE_LOGGER,
            level=logging.WARNING,
            pathname=__file__,
            lineno=0,
            msg=message,
            args=(),
            exc_info=None,
        )
        self._emit_direct(notice)

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
        self.stream.write(self.format(record) + self.terminator)
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
