# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Back off the logging of a failure that repeats on a fixed cadence (BACKLOG #1844).

A supervisory loop that survives an unexpected error, sleeps, and tries again is doing the right
thing. Logging a full traceback on every one of those passes is not: a fault that lasts an hour
writes thousands of near-identical records into a sink that is bounded one way or another. A
rotating file such as ``tray.log`` drops what came FIRST, which is the record naming the original
cause. The engine's off-box forward queue drops what arrives once it is full (which record it
drops, and why, is on ``logging_setup._ForwardQueueHandler.enqueue``), so the flood would push out
everything after it: a different fault, a security event, the recovery line.

:class:`FailureRun` is the one shape for that problem. It was first written for the tray poller
(``messagefoundry/tray/poller.py``, BACKLOG #1712) and lifted here so the engine's pipeline workers
share it rather than carry another copy.

Stdlib only, on purpose: the pipeline and the tray both import it, and the tray may import neither
the engine runtime nor a web framework (ADR 0113 section 1, ``tests/test_dependency_boundaries.py``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

__all__ = ["CONSECUTIVE", "FailureRun", "is_emission"]

#: The default name for what :attr:`FailureRun.count` counts, as it appears in every record.
CONSECUTIVE = "consecutive failures"

#: How much of an exception's message the cause signature keeps. A run holds its signature for as
#: long as it lasts and compares it on every failure, and a message can carry a peer-sized payload.
_CAUSE_TEXT_LIMIT = 1024


def is_emission(n: int) -> bool:
    """True on the 1st, 2nd, 4th, 8th ... of something -- that is, when ``n`` is a power of two."""
    return n > 0 and n & (n - 1) == 0


def _signature(exc: BaseException) -> tuple[str, str]:
    kind = type(exc)
    # Module-qualified, so two drivers' same-named OperationalError with the same text stay apart.
    name = f"{kind.__module__}.{kind.__qualname__}"
    # An exception whose __str__ raises must not turn the caller's except arm into a second fault:
    # a supervisory loop that dies while LOGGING a survivable error is the defect it guards against.
    # The record still carries the exception, and its traceback renders it as
    # "<exception str() failed>", so the reader sees that the text could not be had.
    try:
        text = str(exc)[:_CAUSE_TEXT_LIMIT]
    except Exception:  # noqa: BLE001 -- any failure here only costs the cause text
        text = "<unprintable>"
    return name, text


@dataclass(frozen=True)
class FailureRun:
    """A run of failures of one thing, logged with a backoff. Immutable.

    Emissions go on the 1st, 2nd, 4th, 8th ... failure *of a cause*. Geometric, because the loop
    retries on a fixed cadence: a thing that stays broken for a day at one pass a second logs
    about seventeen records instead of eighty-six thousand, and the first record -- the one naming
    the original cause -- is never pushed out by its own repeats. Every emission carries the
    traceback.

    The run's count rides in every message, which is what makes the suppression legible: a record
    reading ``consecutive failures: 512`` says on its face that 511 went unwritten, so a reader is
    never misled into treating the log as a complete list of attempts. The count is the WHOLE run,
    not the current cause's share, because the reader needs to know how long the thing has been
    failing, not just since it changed how. What ends a run is the caller's decision; a caller
    whose run can span healthy passes names its count with ``count_label`` rather than calling it
    consecutive.

    A *changed* cause is never held back, because it is the only record in a long run carrying
    anything the reader does not already have. It also starts its own schedule rather than
    inheriting the old cause's position, which would log it once and then go silent for as many
    passes again. **That bounds what the backoff can promise**: the cause is keyed on the
    exception's module-qualified type and its message (the first :data:`_CAUSE_TEXT_LIMIT`
    characters), so one whose message varies every pass (an embedded handle, address or errno
    detail) reads as a new cause each time and is not throttled at all. That is the deliberate
    trade -- a bound that holds under a churning message can only be had by suppressing a changed
    cause, and a backoff that hides a new fault behind an old one is worth less than no backoff.

    :meth:`clear` writes one recovery line when a run closes. Without it an absence of recent
    tracebacks has two readings -- recovered, or still failing and merely gone quiet -- and nothing
    in the log tells them apart. A caller that filters at WARNING should log it at WARNING, or the
    ambiguity comes back for that reader.

    A value object: three pieces of cross-call memory only ever meaningful together, so one rebind
    is the whole state change and one default is the whole reset. Not thread-safe by itself; each
    loop owns its own run.

    ``message`` in both methods is a ``%``-style format string with ``args``, as for
    :meth:`logging.Logger.log`, so a caller on a hot path pays for no formatting while the run is
    healthy. ``stacklevel`` works as it does there, counted from the caller of the method: 1 (the
    default) names the caller in the record's ``funcName``/``lineno``, 2 names that caller's caller.
    """

    count: int = 0  # failures in the run, whatever the cause; 0 whenever the thing is healthy
    signature: tuple[str, str] | None = None  # exception type and message of the current cause
    cause_run: int = 0  # failures since the cause last changed -- what the schedule counts

    def record(
        self,
        logger: logging.Logger,
        exc: BaseException,
        message: str,
        *args: object,
        level: int = logging.ERROR,
        count_label: str = CONSECUTIVE,
        stacklevel: int = 1,
    ) -> FailureRun:
        """The run after one more failure, having logged it unless the backoff holds it back.

        Logs ``message % args`` followed by ``(<count_label>: N)``, with ``exc``'s traceback.
        """
        signature = _signature(exc)
        cause_run = self.cause_run + 1 if signature == self.signature else 1
        count = self.count + 1
        if is_emission(cause_run):
            logger.log(
                level,
                message + " (" + count_label + ": %d)",
                *args,
                count,
                exc_info=exc,
                stacklevel=stacklevel + 1,
            )
        return FailureRun(count, signature, cause_run)

    def clear(
        self,
        logger: logging.Logger,
        message: str,
        *args: object,
        level: int = logging.INFO,
        count_label: str = CONSECUTIVE,
        stacklevel: int = 1,
    ) -> FailureRun:
        """The healthy run, logging ``message % args`` followed by ``recovered after N
        <count_label>`` if a run was open. One line per run, so it cannot itself become the flood.
        A healthy run returns itself; a hot caller can skip even the call by testing :attr:`count`
        first."""
        if not self.count:
            return self
        logger.log(
            level,
            message + " recovered after %d " + count_label,
            *args,
            self.count,
            stacklevel=stacklevel + 1,
        )
        return FailureRun()
