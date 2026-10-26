# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Count failed inbound TLS handshakes and report them, throttled (vault BACKLOG #2613, #3302).

Two parts, shared by the MLLP listener, the HTTP intake listener and the API:

* :class:`HandshakeFailures` is the counter and the throttle, one per listener, and the DICOM
  C-STORE SCP's too since #3784. It was the MLLP listener's own until #3302 lifted it here. What
  it throttles, and how, is stated once, in ``docs/PHI.md`` section 7, row 7 (vault BACKLOG #3785
  item 2).
* :func:`watch_loop_handshakes` sees a failure the EVENT LOOP had, where no listener code runs.

**Why the second part exists.** Where the loop runs the handshake, through
``asyncio.start_server(ssl=...)`` or ``loop.create_server(ssl=...)`` as uvicorn calls it, a failed
handshake never reaches the application: its protocol is built but never connected. The stdlib
loop logs the failure at DEBUG, and uvloop at DEBUG too (0.23.0 ``sslproto.pyx``,
``_fatal_error``), and the loop's exception handler is called only in debug mode. So the HTTP intake
listener and the API had no record on any loop, and the MLLP listener none on uvloop, which the
engine installs outside Windows.

**The hook is the context's ``sslobject_class``.** Both loops build the TLS object for every
connection through ``SSLContext.wrap_bio`` (CPython 3.14 ``asyncio/sslproto.py``; uvloop 0.23.0
``sslproto.pyx`` ``_start_handshake``), which instantiates ``sslobject_class``, and both drive it
with ``do_handshake()``. Both treat any ``ssl.SSLError`` from it as a failed handshake except
``SSLWantReadError`` and ``SSLSyscallError``, which they read as "call again". The subclass reports
exactly that set and re-raises unchanged, so the loop's own handling does not move. No server or
protocol class is replaced.

**What it cannot see, at least, stated so it is not over-read.**

* **The peer's address.** A TLS object holds two memory buffers and no socket, so these reports
  name no peer. A trailing report for several failures names none anyway.
* **A handshake past its bound, where the loop runs it. A known limit, declined by owner ruling
  2026-10-26 (vault BACKLOG #3785 item 7).** The loop aborts the transport and never calls
  ``do_handshake`` again, so nothing raises, and a peer that opens sockets and stays silent is not
  counted there. Where a listener runs its own handshakes, it still counts that case itself: the
  MLLP listener on the stdlib loop, and the DICOM SCP always. A certificate the client refuses
  with a TLS alert, a missing client certificate, a protocol downgrade and plaintext on a TLS
  port all raise, so all are counted. A client that refuses a certificate by closing the socket
  with no alert, as asyncio's own client does, looks like a hang-up and is not counted.
* **A peer that hangs up mid-handshake. A known limit, declined by owner ruling 2026-10-26 (vault
  BACKLOG #3785 item 8).** Not counted on any surface, as on MLLP since #2613: that is what a load
  balancer's TCP health check does.
* **A failure outside ``do_handshake``**, such as one in ``wrap_bio`` itself, and any context driven
  through ``wrap_socket`` rather than by an event loop. The DICOM SCP drives its handshakes that way,
  so the hook never sees them; its ``_handshake`` counts them itself, on the connection's thread,
  and hands each to the loop (vault BACKLOG #3784).

Stdlib only, so the API can import it without pulling in a transport.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import ssl
import time
import weakref
from collections.abc import Callable, Coroutine
from typing import Any

__all__ = [
    "EVENT_SECONDS",
    "HUNG_UP",
    "HandshakeFailures",
    "handshake_cause",
    "watch_loop_handshakes",
]

logger = logging.getLogger(__name__)

# Whether a fault in a recorder has been logged at WARNING yet. Later ones go to DEBUG, so a recorder
# that fails on every call cannot turn a handshake flood into the log flood the throttle prevents.
_recorder_fault_logged = False

#: Seconds between two reports from one listener. Per listener, not per peer: the peer's address
#: is the caller's choice, so a per-peer window would let one host rotating addresses write a row
#: per address. Read at each failure, so a test shortens it for every surface by patching it
#: here (vault BACKLOG #3785 item 4).
EVENT_SECONDS = 60.0


def _weakly[**P, R](fn: Callable[P, R]) -> Callable[P, R | None]:
    """``fn``, held weakly when it is a bound method, so the counter it is handed to does not keep
    the method's object, its listener, alive (vault BACKLOG #3785 item 1).

    Without it, a listener and its counter made a reference cycle (listener, counter, bound emit,
    listener), and so did a listener and its context (context, hooked class, a bound method of the
    listener). Only the cyclic collector freed either. The context's hook now holds the counter
    (:meth:`HandshakeFailures.watch`), so with this no cycle runs through the listener. A plain
    function owns no object, and ``weakref.WeakMethod`` refuses one, so it is held as it is.
    Once the object is gone the call does nothing and returns ``None``. So a method of an object
    nothing else holds, such as a temporary, reports nothing: hand in the listener's own method."""
    if not inspect.ismethod(fn):
        return fn
    ref = weakref.WeakMethod(fn)

    def call(*args: P.args, **kwargs: P.kwargs) -> R | None:
        method = ref()
        return None if method is None else method(*args, **kwargs)

    return call


#: What both event loops treat as "call do_handshake again" rather than as a failed handshake. The
#: same tuple as CPython's ``asyncio.sslproto.SSLAgainErrors`` and uvloop's ``ssl_SSLAgainErrors``.
_AGAIN = (ssl.SSLWantReadError, ssl.SSLSyscallError)

#: What a listener running its own handshakes sees when the peer hangs up before finishing one,
#: which is what a load balancer's TCP health check does. Not counted on any surface (vault
#: BACKLOG #2613; owner ruling 2026-10-26, #3785 item 8). A reset is how the Windows Proactor
#: reports a hang-up to the MLLP listener. A blocking handshake, the DICOM SCP's, sees a close as
#: ``SSLEOFError`` and a reset as ``ConnectionResetError`` (measured 2026-10-26, CPython 3.14 for
#: Windows). The loop's TLS object raises ``SSLZeroReturnError`` from ``do_handshake`` when a
#: peer sends close_notify after its ClientHello (measured 2026-10-26 over memory buffers), so
#: the loop's hook skips this set too.
HUNG_UP: tuple[type[OSError], ...] = (
    ConnectionResetError,
    BrokenPipeError,
    ssl.SSLEOFError,
    ssl.SSLZeroReturnError,
)

#: An OpenSSL reason mnemonic such as ``WRONG_VERSION_NUMBER``. Matched in full before it is kept,
#: so a cause can never carry anything a peer chose.
_REASON = re.compile(r"[A-Z0-9_]{1,64}")


def handshake_cause(exc: BaseException) -> str:
    """The exception's class name, then OpenSSL's reason mnemonic when it has one.

    The mnemonic is what tells a downgrade (``UNSUPPORTED_PROTOCOL``) from a wrong certificate
    (``TLSV1_ALERT_UNKNOWN_CA``) or plaintext on a TLS port (``HTTP_REQUEST``). It comes from
    OpenSSL's fixed table, never from the peer's bytes, and is kept only if it looks like one.
    """
    name = type(exc).__name__
    reason = getattr(exc, "reason", None)
    if isinstance(reason, str) and _REASON.fullmatch(reason):
        return f"{name} {reason}"
    return name


class HandshakeFailures:
    """One listener's failed-handshake counter and its throttled report. The throttle, and what a
    report names, are stated once, in ``docs/PHI.md`` section 7, row 7.

    ``emit(peer_host, reason)`` sends one report: a coroutine function for a connection event, or a
    plain function for a log line, which then runs at once rather than on a task a closing loop
    could cancel. It is held weakly when it is a bound method (see :func:`_weakly`), so the
    listener keeps its counter alive and not the other way round. The reason is
    a count and a cause from :func:`handshake_cause`, never the peer's bytes.

    Each method that counts or reports runs on the listener's event loop, as does :meth:`open`.
    A caller on another thread hands a failure over with ``loop.call_soon_threadsafe``.
    :meth:`close` and :meth:`take_held` need no running loop, so the API can log what was held
    after uvicorn's loop is gone.
    """

    def __init__(self, emit: Callable[[str | None, str], Coroutine[Any, Any, None] | None]) -> None:
        self._emit = _weakly(emit)
        # Between close() and open(): a listener's stop(). Nothing is counted then, so no report
        # outlives stop() (vault BACKLOG #3785 item 5: this guard lived in each listener).
        self._closed = False
        #: Failed handshakes seen since this object was built, outside its listener's stop()s.
        self.count = 0
        # The count already reported, and when that report went.
        self._reported = 0
        self._reported_at: float | None = None
        # The latest failure's peer and cause, the trailing report's timer, and its tasks.
        self._last: tuple[str | None, str] = (None, "")
        self._timer: asyncio.TimerHandle | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    def _count(self, peer_host: str | None, cause: str) -> bool:
        """Count one failure; True when a report is due now, else arm the trailing timer.

        A report due now also carries whatever a trailing timer held, so that timer is disarmed
        here. Left armed, it could fire a second report inside the new window, since asyncio runs
        a due I/O callback before a due timer in the same loop iteration."""
        self.count += 1
        self._last = (peer_host, cause)
        now = time.monotonic()
        last = self._reported_at
        if last is None or now - last >= EVENT_SECONDS:
            self._disarm()
            return True
        self._arm(last, now)
        return False

    def _arm(self, last: float, now: float) -> None:
        """Arm the trailing timer for the window that started at ``last``, unless it is armed."""
        if self._timer is None:
            self._timer = asyncio.get_running_loop().call_later(
                max(0.0, last + EVENT_SECONDS - now), self._on_timer
            )

    def take_held(self) -> tuple[str | None, str] | None:
        """Mark the failures not yet reported as reported, and return the report for them.

        Synchronous, so a caller with no running loop left can still log what was held."""
        since = self.count - self._reported
        if since <= 0:
            return None
        self._reported = self.count
        self._reported_at = time.monotonic()
        peer_host, cause = self._last
        # "report", not "event": the API and the DICOM SCP write this as a log line, and no event
        # carries it there (vault BACKLOG #3785 item 3).
        return (
            peer_host if since == 1 else None,
            f"{since} failed handshake(s) since the last report; last cause {cause}",
        )

    async def note(self, peer_host: str | None, cause: str) -> None:
        """Count one failure from a coroutine, reporting it before returning if a report is due."""
        if not self._closed and self._count(peer_host, cause):
            await self.report()

    def note_soon(self, peer_host: str | None, cause: str) -> None:
        """Count one failure from a plain callback on the loop, such as inside a handshake. The
        report, if one is due, goes on a tracked task."""
        if not self._closed and self._count(peer_host, cause):
            self._report_soon()

    def watch(self, ctx: ssl.SSLContext) -> None:
        """Count each handshake the event loop fails on ``ctx``. The peer is not known there. The
        hook holds this counter, never the listener, since this counter holds its listener only
        weakly. So ``ctx`` and the listener form no cycle."""
        watch_loop_handshakes(ctx, self._note_loop_failure)

    def unwatch(self, ctx: ssl.SSLContext) -> None:
        """Count nothing more on ``ctx`` through the loop: the listener runs its handshakes itself
        now and counts them there. Left hooked, its context would count each failure twice, since
        ``loop.start_tls`` builds its TLS object from the same context."""
        ctx.sslobject_class = ssl.SSLObject

    def _note_loop_failure(self, cause: str) -> None:
        self.note_soon(None, cause)

    def open(self) -> None:
        """At a listener's start(): count again. A failure still held, because the stop() before
        it never flushed, gets its trailing timer back, so it is not stranded until the next
        failure. That needs the running loop, which start() has."""
        self._closed = False
        if self.count > self._reported and self._reported_at is not None:
            self._arm(self._reported_at, time.monotonic())

    def close(self) -> None:
        """First thing in a listener's stop(): count nothing more, so stop() aborting a handshake is
        no failure and no report outlives stop(), and disarm the trailing timer. What that timer
        held stays held for :meth:`flush`. Nothing can arm a new one until :meth:`open`."""
        self._closed = True
        self._disarm()

    def _on_timer(self) -> None:
        """The trailing report's timer."""
        self._timer = None
        self._report_soon()

    def _report_soon(self) -> None:
        # Taken here, not in the task, so the window starts now: a second failure in the same loop
        # turn is held for the trailing report, as under `note`, rather than reported twice.
        held = self.take_held()
        if held is None:
            return
        sent = self._emit(*held)
        if sent is not None:
            task = asyncio.get_running_loop().create_task(sent)
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def report(self) -> None:
        """Send one report for the failures not yet reported, if there are any."""
        held = self.take_held()
        if held is not None:
            sent = self._emit(*held)
            if sent is not None:
                await sent

    def _disarm(self) -> None:
        """Disarm the trailing timer. What it held stays held, for :meth:`flush` or
        :meth:`take_held`."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    async def flush(self) -> None:
        """At the end of a listener's stop(), after :meth:`close`: wait for any report in flight,
        then send what the trailing timer still held. The emitters are fail-soft, so this cannot
        fail a stop().

        It does nothing once :meth:`open` has run again, since the failures from then on are the
        restarted listener's to report. That needs a restart while an earlier stop() still runs,
        which the engine's runner never does: it joins an abandoned stop() before it starts the
        listener again (``_settle_pending_source_stops`` in ``pipeline/wiring_runner.py``). The
        check is kept anyway (vault BACKLOG #3785 item 5). It costs one flag test, and without it
        this class would depend on its caller's ordering. It is checked again after the wait,
        since :meth:`open` can run during it. Called without :meth:`close` first, it sends
        nothing, for the same reason."""
        if not self._closed:
            return
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._closed:
            await self.report()


def watch_loop_handshakes(ctx: ssl.SSLContext, on_failure: Callable[[str], None]) -> None:
    """Call ``on_failure(cause)`` for each handshake on ``ctx`` that the event loop fails.

    ``ctx`` must be a server context this caller owns, since it is changed in place. A second call
    replaces the first callback. ``on_failure`` runs inside the loop's handshake, so it must not
    block; a fault in it is logged and never changes the handshake's outcome. ``ctx`` holds
    ``on_failure`` for as long as it lives, so a callback that holds ``ctx``'s owner makes a
    reference cycle; :meth:`HandshakeFailures.watch` hands it a counter, which holds none.
    """
    ctx.sslobject_class = type(
        "_WatchedSSLObject",
        (_WatchedSSLObject,),
        {"_on_failure": staticmethod(on_failure)},
    )


class _WatchedSSLObject(ssl.SSLObject):
    """An ``SSLObject`` that reports a failed handshake before the loop sees it."""

    _on_failure: Callable[[str], None]

    def do_handshake(self) -> None:
        try:
            super().do_handshake()
        except _AGAIN:
            raise
        except HUNG_UP:  # a peer's close_notify after its ClientHello raises SSLZeroReturnError
            raise
        except ssl.SSLError as exc:
            try:
                self._on_failure(handshake_cause(exc))
            # A recording fault must never turn a failed handshake into a different error inside
            # the loop's protocol, so it is logged and the handshake's own error goes on.
            except Exception as fault:  # noqa: BLE001
                _log_recorder_fault(fault)
            raise


def _log_recorder_fault(fault: Exception) -> None:
    global _recorder_fault_logged
    level = logging.DEBUG if _recorder_fault_logged else logging.WARNING
    _recorder_fault_logged = True
    logger.log(level, "recording a failed TLS handshake failed: %s", type(fault).__name__)
