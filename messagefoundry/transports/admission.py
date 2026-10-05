# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Listener admission: what a socket listener decides about a connection before it reads a byte.

The MLLP, raw-TCP, X12 and HTTP listeners each run their own accept handler, and each used to
enforce the same pre-read controls by convention. They drifted: only MLLP had a per-host cap, a
frame deadline and a refuse-while-stopping check, and every listener wrote one WARNING per allowlist
refusal (vault BACKLOG #2606). This module holds those controls once.

* :class:`ListenerAdmission` makes the pre-read decision, in order: refuse while stopping, the source
  allowlist, the global connection cap and the per-host cap. It owns the live-connection counts and
  the throttled refusal log. Each listener keeps its own read loop; only the admission is shared.
* :class:`RefusalLog` is the per-address, windowed log throttle the DICOM server introduced, moved here
  so the four socket listeners and the DICOM server share one.
* :class:`FrameClock` is the frame deadline: the bound on one frame from its first byte to its last.
  The MLLP, raw-TCP and X12 read loops all run it (vault BACKLOG #2847 moved MLLP onto it).

Everything here runs before ingress, so no message is read, persisted or acknowledged by it. The
ACK-on-receipt and count-and-log invariants are untouched: a refused connection has delivered
nothing, and the sender retries.

**TLS is not in the helper.** The MLLP listener is the only one that upgrades a socket to TLS itself,
after admission, so that step stays in its accept handler. The HTTP listener's handshake is run by the
event loop before admission; that is a separate item.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass

from messagefoundry.netaddr import peer_ip_allowed

__all__ = [
    "REFUSAL_LOG_MAX_PER_WINDOW",
    "REFUSAL_LOG_WINDOW_SECONDS",
    "FrameClock",
    "ListenerAdmission",
    "Refusal",
    "RefusalLog",
]

logger = logging.getLogger(__name__)

#: A refused peer address earns one WARNING per this many seconds, however often it is refused.
#: A refused connection costs the peer nothing, so a line per refusal would let a peer the allowlist
#: turns away fill the service log, which NSSM captures to files.
REFUSAL_LOG_WINDOW_SECONDS = 60.0

#: The most refusal lines one listener writes per window over every address together. The
#: per-address bound alone would still let many addresses earn a line each.
REFUSAL_LOG_MAX_PER_WINDOW = 20


class RefusalLog:
    """Decide whether a refusal for an address earns a log line: at most one per address per window,
    and at most ``max_per_window`` per window across all addresses.

    The table holds an entry only for a line written inside the current window, so it never holds
    more than ``max_per_window`` addresses, whatever arrives. Every refusal is counted, logged or
    not, and :meth:`note` returns that running count for the line, so the volume behind a quiet log
    shows in the next line written. It is thread-safe: the DICOM server reaches it from its accept
    loop and from its association threads.
    """

    def __init__(
        self,
        *,
        window_seconds: float = REFUSAL_LOG_WINDOW_SECONDS,
        max_per_window: int = REFUSAL_LOG_MAX_PER_WINDOW,
    ) -> None:
        self.window_seconds = window_seconds
        self.max_per_window = max_per_window
        #: Addresses logged inside the current window, mapped to when.
        self.logged: dict[str, float] = {}
        #: Every refusal noted since this log was built.
        self.refusals = 0
        self._lock = threading.Lock()

    def note(self, address: str) -> int | None:
        """Count one refusal for ``address``. Return the running total when a line is due, else None."""
        now = time.monotonic()
        with self._lock:
            self.refusals += 1
            logged = self.logged
            cutoff = now - self.window_seconds
            for aged in [a for a, at in logged.items() if at <= cutoff]:
                del logged[aged]
            if address in logged or len(logged) >= self.max_per_window:
                return None
            logged[address] = now
            return self.refusals


@dataclass(frozen=True, slots=True)
class Refusal:
    """Why admission refused a connection.

    ``kind`` is the connection event to emit, or ``None`` for a refusal that emits none (the listener
    is stopping, so nobody is reading the stream for it). ``reason`` goes on the event.
    """

    kind: str | None
    reason: str | None = None


# Written with `kind=` on purpose: the connection-event vocabulary guard in
# tests/test_phi_logging_inventory.py reads the literal kinds from these constructions, as it reads
# them from each `_emit_event("...")` call. A positional kind here would hide two kinds from it.
_STOPPING = Refusal(kind=None)
_NOT_ALLOWLISTED = Refusal(kind="peer_not_allowlisted")
_AT_CAPACITY = Refusal(kind="at_capacity")
_AT_HOST_CAPACITY = Refusal(kind="at_capacity", reason="max_connections_per_host")


class ListenerAdmission:
    """The pre-read admission decision for one socket listener, and the counts it rests on.

    Call :meth:`check` first. ``None`` means admit: call :meth:`admit`, and pair it with exactly one
    :meth:`release` in a ``finally``. A :class:`Refusal` means close the socket unread; nothing was
    taken, so nothing is released.

    ``max_connections`` counts sockets on this listener. ``max_connections_per_host`` counts sockets
    from one peer address, so one address cannot take the whole listener. It keys on the source IP,
    so behind a source-NAT proxy every partner is one peer and the per-host cap becomes the whole
    capacity; switch it off there.
    """

    def __init__(
        self,
        *,
        transport: str,
        max_connections: int | None,
        max_connections_per_host: int | None,
        source_ip_allowlist: list[str] | None,
    ) -> None:
        self.transport = transport
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        self.source_ip_allowlist = source_ip_allowlist
        #: Set from the start of the listener's stop() until its next start().
        self.stopping = False
        self.active = 0
        #: Live connections per peer address. A host is DROPPED at zero rather than left at 0: the
        #: key is attacker-chosen, so a peer cycling source addresses would otherwise grow the table
        #: without bound. Dropping at zero holds it to the live connections, which `max_connections`
        #: bounds. A peer with many source addresses gets a fresh budget for each one.
        self.per_host: dict[str, int] = {}
        #: Hosts already warned about their per-host cap this episode, cleared with the count above.
        self.host_capacity_warned: set[str] = set()
        self.refusal_log = RefusalLog()

    def check(self, writer: asyncio.StreamWriter, peer_host: str | None) -> Refusal | None:
        """Decide whether to admit this connection. Logs a refusal, throttled; emits no event."""
        if self.stopping:
            logger.debug("%s connection refused: the listener is stopping", self.transport)
            return _STOPPING
        if self.source_ip_allowlist is not None:
            peer = writer.get_extra_info("peername")
            if not peer_ip_allowed(peer, self.source_ip_allowlist):
                self._log_not_allowlisted(peer_host)
                return _NOT_ALLOWLISTED
        if self.max_connections is not None and self.active >= self.max_connections:
            # No line: a refused connection is free to the peer, and this budget is the listener's
            # whole capacity. The `at_capacity` event records each one.
            return _AT_CAPACITY
        if self._at_host_capacity(peer_host):
            assert peer_host is not None  # _at_host_capacity is False without an address
            self._log_host_capacity_once(peer_host)
            return _AT_HOST_CAPACITY
        return None

    def admit(self, peer_host: str | None) -> None:
        """Take one connection slot, globally and (when the peer has an address) for that host."""
        self.active += 1
        if peer_host is not None:
            self.per_host[peer_host] = self.per_host.get(peer_host, 0) + 1

    def release(self, peer_host: str | None) -> None:
        """Give both slots back. One place for both counters, so they cannot drift: a per-host count
        left behind by a missed release would lock that peer out until restart."""
        self.active -= 1
        if peer_host is None:
            return
        remaining = self.per_host.get(peer_host, 0) - 1
        if remaining > 0:
            self.per_host[peer_host] = remaining
        else:
            self.per_host.pop(peer_host, None)
            # Dropped with the count, so the next episode for this host warns again and neither
            # table outlives the connections it describes.
            self.host_capacity_warned.discard(peer_host)

    def reset(self) -> None:
        """Forget the per-host tables, at stop. ``active`` is left to the releases still running.

        A no-op once the listener has started again: a stop() that finishes after a restart must
        not wipe the counts of connections the restarted listener has admitted. Call it from a
        ``finally`` so a cancelled stop() still clears the tables."""
        if not self.stopping:
            return
        self.per_host.clear()
        self.host_capacity_warned.clear()

    def _at_host_capacity(self, peer_host: str | None) -> bool:
        # A cap that cannot name its subject must not refuse anybody.
        if self.max_connections_per_host is None or peer_host is None:
            return False
        return self.per_host.get(peer_host, 0) >= self.max_connections_per_host

    def _log_not_allowlisted(self, peer_host: str | None) -> None:
        address = peer_host or "an unknown address"
        total = self.refusal_log.note(address)
        if total is None:
            return
        logger.warning(
            "%s connection from %s refused: not in source_ip_allowlist. An address is logged at most "
            "once every %gs. %d refused in all since this listener was built.",
            self.transport,
            address,
            self.refusal_log.window_seconds,
            total,
        )

    def _log_host_capacity_once(self, peer_host: str) -> None:
        """Warn the FIRST time a host hits its cap, then stay quiet until it has no connections left.

        Clearing at zero rather than when the host drops back under the cap is deliberate: a peer
        oscillating on the boundary would otherwise earn a line per cycle. A per-refusal line would
        let a peer looping ``connect()`` fill the log volume. The `at_capacity` event still records
        every refusal. The warned set is keyed and cleared exactly like :attr:`per_host`, so it
        inherits that table's bound.
        """
        if peer_host in self.host_capacity_warned:
            return
        self.host_capacity_warned.add(peer_host)
        logger.warning(
            "%s connections from %s refused: it holds max_connections_per_host (%d). Further "
            "refusals for this host are not logged until it has no connections left.",
            self.transport,
            peer_host,
            self.max_connections_per_host,
        )


def _frame_seconds_left(opened_at: float | None, max_frame_seconds: float | None) -> float | None:
    """Seconds left on the open frame's deadline, or ``None`` when no deadline is running.

    ``None`` means the bound has nothing to say: it is off, or no frame is open. The result may be
    negative, and the sign is the answer: at or below zero the frame has outlived its budget.
    """
    if opened_at is None or max_frame_seconds is None:
        return None
    return max_frame_seconds - (time.monotonic() - opened_at)


def _read_budget(receive_timeout: float | None, frame_left: float | None) -> float | None:
    """How long the next read may block: the idle bound, the open frame's remaining life, or the
    smaller of the two. ``None`` only when neither bound is configured."""
    if frame_left is None:
        return receive_timeout
    if receive_timeout is None:
        return frame_left
    return min(receive_timeout, frame_left)


class FrameClock:
    """The frame deadline for one connection's read loop.

    ``receive_timeout`` resets on every byte, so it bounds silence and never reaches a peer that
    trickles one byte at a time inside a frame. ``max_frame_seconds`` bounds the frame itself, from
    the first read that carried bytes to the read that completed a frame. It restarts for each
    frame, from the decoder's ``in_frame`` signal after a completed one.

    Use: :meth:`withhold` around any wait the ENGINE imposes (pacing, an intake pause), since that is
    not the peer being slow; :meth:`read` for each read; :meth:`after_read` after each read the
    decoder consumed.
    """

    def __init__(
        self, *, transport: str, max_frame_seconds: float | None, receive_timeout: float | None
    ) -> None:
        self.transport = transport
        self.max_frame_seconds = max_frame_seconds
        self.receive_timeout = receive_timeout
        #: Monotonic stamp of the read that carried the current frame's first byte, or None.
        self.opened_at: float | None = None
        #: True while the running clock was started by bytes outside any frame and no frame has
        #: opened since, so the drop line can say that rather than "a frame did not complete".
        self._noise_only = False

    def withhold(self, since: float) -> None:
        """Push the open frame's start forward by the time the engine declined to read since
        ``since``, so engine back-pressure never spends the peer's frame budget."""
        if self.opened_at is not None:
            self.opened_at += time.monotonic() - since

    async def read(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> tuple[bytes, str | None]:
        """Read one chunk under the idle bound and the frame deadline together.

        Returns ``(chunk, None)``, where an empty chunk is the peer's EOF, or ``(b"", reason)`` when a
        bound closed the read: ``frame_deadline`` or ``idle_timeout``. Which bound armed the wait is
        decided before it, never re-measured after a timeout: at the boundary a re-measure would read
        a small positive remainder and misname a frame deadline as an idle timeout.
        """
        left = _frame_seconds_left(self.opened_at, self.max_frame_seconds)
        if left is not None and left <= 0.0:
            # Spent while we were not waiting on the socket: bytes arrived at or past the deadline.
            self._log_frame_deadline(writer)
            return b"", "frame_deadline"
        budget = _read_budget(self.receive_timeout, left)
        if budget is None:
            return await reader.read(4096), None
        try:
            return await asyncio.wait_for(reader.read(4096), budget), None
        except TimeoutError:
            if left is not None and left == budget:
                self._log_frame_deadline(writer)
                return b"", "frame_deadline"
            return b"", "idle_timeout"

    def _log_frame_deadline(self, writer: asyncio.StreamWriter) -> None:
        """Say which bound dropped the connection; the `closed` event lands only when capture is on.
        Socket metadata only, never frame bytes. One line per dropped connection, like
        `frame_oversize`: reaching it costs the peer a connection held for `max_frame_seconds`, so
        the connection caps bound its rate."""
        if self._noise_only:
            logger.warning(
                "%s peer %s sent bytes outside any frame and completed no frame within "
                "max_frame_seconds (%.1fs); dropping the connection",
                self.transport,
                writer.get_extra_info("peername"),
                self.max_frame_seconds,
            )
            return
        logger.warning(
            "%s frame from %s did not complete within max_frame_seconds (%.1fs); "
            "dropping the connection",
            self.transport,
            writer.get_extra_info("peername"),
            self.max_frame_seconds,
        )

    def after_read(self, *, in_frame: bool, decoded: int, trailer_only: bool) -> None:
        """Restamp after the decoder consumed a non-empty read.

        A read that completed a frame restarts the clock: a NEW frame if one is open after it, none
        otherwise. ``decoded`` is what makes this per frame, since a pipelined sender's reads rarely
        end on a frame boundary. A read that completed nothing starts the clock if it is not already
        running, WHETHER OR NOT the decoder counts a frame as open: bytes the decoder discards
        outside a frame reset the idle bound just as frame bytes do, so a deadline that waited for
        ``in_frame`` would never reach a peer trickling them. So any bytes must lead to a completed
        frame within ``max_frame_seconds`` of read time; the engine's own waits are withheld.

        ``trailer_only`` (:attr:`~messagefoundry.framing.FrameDecoder.trailer_only`) is the one
        exception: a read holding only the line-end bytes that end the frame before it, such as
        MLLP's CR arriving after its FS, belongs to that completed frame and starts nothing (vault
        BACKLOG #2847). Without it a healthy peer that went quiet after such a read would be cut
        here. It is required, so a new caller cannot leave it out by accident.
        """
        if decoded:
            self.opened_at = time.monotonic() if in_frame else None
        elif self.opened_at is None and not trailer_only:
            self.opened_at = time.monotonic()
            self._noise_only = True
        if in_frame:
            self._noise_only = False
