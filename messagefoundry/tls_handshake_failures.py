# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Count failed inbound TLS handshakes and report them, throttled (vault BACKLOG #2613, #3302).

Two parts, shared by the MLLP listener, the HTTP intake listener and the API:

* :class:`HandshakeFailures` is the counter and the throttle, one per listener. It was the MLLP
  listener's own until #3302 lifted it here. The first failure is reported at once. Later ones
  inside :data:`EVENT_SECONDS` are held, and one trailing report at the window's end says how many,
  so a peer that fails handshakes as fast as it connects writes one row a minute, not one per try.
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
* **A handshake past its bound.** The loop aborts the transport and never calls ``do_handshake``
  again, so nothing raises. Where the MLLP listener runs its own handshakes, the stdlib loop, it
  still counts that case itself. Elsewhere a peer that opens sockets and stays silent is not
  counted. A wrong certificate, a missing client certificate, a protocol downgrade and plaintext on
  a TLS port all raise, so all are counted.
* **A peer that hangs up mid-handshake.** Not counted, deliberately, as on MLLP since #2613: that is
  what a load balancer's TCP health check does.
* **A failure outside ``do_handshake``**, such as one in ``wrap_bio`` itself, and any context driven
  through ``wrap_socket`` rather than by an event loop, which is how the DICOM SCP runs its
  handshakes.

Stdlib only, so the API can import it without pulling in a transport.
"""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
import time
from collections.abc import Callable, Coroutine
from typing import Any

__all__ = [
    "EVENT_SECONDS",
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
#: per address.
EVENT_SECONDS = 60.0

#: What both event loops treat as "call do_handshake again" rather than as a failed handshake. The
#: same tuple as CPython's ``asyncio.sslproto.SSLAgainErrors`` and uvloop's ``ssl_SSLAgainErrors``.
_AGAIN = (ssl.SSLWantReadError, ssl.SSLSyscallError)

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
    """One listener's failed-handshake counter and its throttled report.

    ``emit(peer_host, reason)`` sends one report: a coroutine function for a connection event, or a
    plain function for a log line, which then runs at once rather than on a task a closing loop
    could cancel. A report for one failure names its peer; a report for several names none, since
    they may come from many peers. The reason is a count and a cause from :func:`handshake_cause`,
    never the peer's bytes.
    """

    def __init__(
        self,
        emit: Callable[[str | None, str], Coroutine[Any, Any, None] | None],
        *,
        window: float = EVENT_SECONDS,
    ) -> None:
        self._emit = emit
        self._window = window
        #: Failed handshakes seen since this object was built.
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
        if last is None or now - last >= self._window:
            self.cancel()
            return True
        if self._timer is None:
            self._timer = asyncio.get_running_loop().call_later(
                last + self._window - now, self._on_timer
            )
        return False

    def take_held(self) -> tuple[str | None, str] | None:
        """Mark the failures not yet reported as reported, and return the report for them.

        Synchronous, so a caller with no running loop left can still log what was held."""
        since = self.count - self._reported
        if since <= 0:
            return None
        self._reported = self.count
        self._reported_at = time.monotonic()
        peer_host, cause = self._last
        return (
            peer_host if since == 1 else None,
            f"{since} failed handshake(s) since the last event; last cause {cause}",
        )

    async def note(self, peer_host: str | None, cause: str) -> None:
        """Count one failure from a coroutine, reporting it before returning if a report is due."""
        if self._count(peer_host, cause):
            await self.report()

    def note_soon(self, peer_host: str | None, cause: str) -> None:
        """Count one failure from a plain callback on the loop, such as inside a handshake. The
        report, if one is due, goes on a tracked task."""
        if self._count(peer_host, cause):
            self._report_soon()

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

    def cancel(self) -> None:
        """Disarm the trailing timer. What it held stays held, for :meth:`flush` or :meth:`take_held`."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    async def flush(self) -> None:
        """At a listener's stop, once no handshake can add to the count: wait for any report in
        flight, then send what the trailing timer still held. The emitters are fail-soft, so this
        cannot fail a stop()."""
        self.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.report()


def watch_loop_handshakes(ctx: ssl.SSLContext, on_failure: Callable[[str], None]) -> None:
    """Call ``on_failure(cause)`` for each handshake on ``ctx`` that the event loop fails.

    ``ctx`` must be a server context this caller owns, since it is changed in place. A second call
    replaces the first callback. ``on_failure`` runs inside the loop's handshake, so it must not
    block; a fault in it is logged and never changes the handshake's outcome.
    """
    ctx.sslobject_class = type(
        "_WatchedSSLObject", (_WatchedSSLObject,), {"_on_failure": staticmethod(on_failure)}
    )


class _WatchedSSLObject(ssl.SSLObject):
    """An ``SSLObject`` that reports a failed handshake before the loop sees it."""

    _on_failure: Callable[[str], None]

    def do_handshake(self) -> None:
        try:
            super().do_handshake()
        except _AGAIN:
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
