# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""In-process rendezvous for the synchronous captured-downstream reply (ADR 0154 D3).

**Every signal here is a LATENCY HINT and never an answer.** A woken waiter re-reads the store and
decides from the committed row; nothing that arrives through this module is treated as data. That is
the property the whole design rests on, and it is what makes the module safe to be wrong: a hint that
never fires costs latency (the poll still finds the reply), and a hint that fires spuriously costs one
extra read. Neither can produce an incorrect HTTP response.

Because of that, :meth:`ReplyRendezvous.signal` and :meth:`ReplyRendezvous.fail` are **deliberately
indistinguishable to the waiter**. They differ only in what the caller is reporting. If they resolved
the wait differently, the signal would have become data — the exact mistake this design exists to
avoid — so the asymmetry is in the names and the docs, not the behaviour.

**Thread-affinity, and it is load-bearing.** ``asyncio.Event.set()`` is *not* thread-safe, and neither
is the ``call_soon`` that schedules a waiter's wakeup. Every method here must be called from the event
loop thread. The engine has real off-loop paths that look like tempting hook sites — the fused
route/transform bodies run in a ``ThreadPoolExecutor`` — and calling in from one usually *appears* to
work while intermittently dropping wakeups, which is the worst failure signature available: silent,
rare, and load-dependent. Hook the loop-side marshalling instead.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Final

__all__ = ["ReplyRendezvous", "ReplyWaiter", "RendezvousFull"]

#: Default cap on simultaneously armed waiters. A backstop against a leak or a deliberate flood, not
#: a second refusal point for ordinary load — the listener's own ``max_connections`` bounds that, and
#: an arm refused here resolves to the ``degraded`` outcome rather than an error.
DEFAULT_MAX_WAITERS: Final = 512


class RendezvousFull(RuntimeError):
    """Raised by :meth:`ReplyRendezvous.arm` when the waiter cap is reached, or while draining.

    The caller maps this to the ``degraded`` outcome. It is deliberately not a timeout: a timeout
    means "the partner did not answer in time", which would be a lie about the partner and would
    corrupt the ``rate(timeout)/rate(total)`` SLO series that an operator pages on.
    """


class ReplyWaiter:
    """One armed wait. Obtained from :meth:`ReplyRendezvous.arm`, never constructed directly."""

    __slots__ = ("_event", "_drain_reason")

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._drain_reason: str | None = None

    @property
    def drain_reason(self) -> str | None:
        """The reason this waiter was drained (listener shutdown), or ``None``.

        The caller checks this after every :meth:`hint` and stops waiting when it is set — it is the
        one condition that is *not* re-derived from the store, because it describes **us**, not the
        message.
        """
        return self._drain_reason

    async def hint(self, timeout: float) -> None:
        """Sleep up to ``timeout`` seconds, returning early if a hint arrived.

        Returns nothing on purpose: there is no outcome to report. The caller always re-reads the
        store afterwards, whether it woke early, timed out, or was drained.

        **The hint is consumed before returning.** An ``asyncio.Event`` stays set once set, so a
        waiter that looped on an unconsumed Event would stop sleeping entirely and spin at full CPU
        for the rest of ``reply_timeout`` — and it would do so precisely in the legitimate case that
        drives repeated wakes: a message fanned out to several handlers, where every sibling's
        progress wakes us and the store correctly says "keep waiting".

        A drained waiter returns immediately and never blocks again.
        """
        if self._drain_reason is not None:
            return
        try:
            await asyncio.wait_for(self._event.wait(), timeout)
        except TimeoutError:
            return
        finally:
            # Consume it even on the timeout path: a hint that landed in the race between wait_for
            # expiring and this line would otherwise survive to skip the NEXT sleep for free.
            self._event.clear()

    def _wake(self) -> None:
        self._event.set()

    def _drain(self, reason: str) -> None:
        self._drain_reason = reason
        self._event.set()


class ReplyRendezvous:
    """Wakes HTTP turns blocked on a captured downstream reply, keyed by ``(message_id, dest)``.

    Owned by the runner and injected into the resolver, so ``transports/`` never imports it.
    """

    __slots__ = ("_waiters", "_max_waiters", "_draining")

    def __init__(self, *, max_waiters: int = DEFAULT_MAX_WAITERS) -> None:
        self._waiters: dict[tuple[str, str], set[ReplyWaiter]] = {}
        self._max_waiters = max_waiters
        self._draining: str | None = None

    @property
    def waiters(self) -> int:
        """Currently armed waiters. Tested to return to zero — see :meth:`arm`."""
        return sum(len(group) for group in self._waiters.values())

    @contextmanager
    def arm(self, message_id: str, destination_name: str) -> Iterator[ReplyWaiter]:
        """Arm a waiter for the duration of the ``with`` block.

        **A context manager rather than an arm/disarm pair, structurally.** An entry that outlives its
        turn — a missed disarm, a cancellation landing between arm and ``try``, an early return —
        accumulates silently until :data:`DEFAULT_MAX_WAITERS`, after which *every* subsequent caller
        resolves ``degraded`` while the store is perfectly healthy and no error appears anywhere. A
        slow-motion listener outage with no signal is not a failure mode worth leaving to caller
        discipline, so the release is not the caller's to forget.

        Raises :class:`RendezvousFull` when the cap is reached or the listener is draining.
        """
        if self._draining is not None:
            raise RendezvousFull(f"listener is draining ({self._draining})")
        if self.waiters >= self._max_waiters:
            raise RendezvousFull(f"reply rendezvous at capacity ({self._max_waiters} waiters)")

        key = (message_id, destination_name)
        waiter = ReplyWaiter()
        self._waiters.setdefault(key, set()).add(waiter)
        try:
            yield waiter
        finally:
            group = self._waiters.get(key)
            if group is not None:
                group.discard(waiter)
                if not group:  # drop the empty bucket so the dict tracks live keys, not history
                    del self._waiters[key]

    def signal(self, message_id: str, destination_name: str) -> None:
        """Hint that a reply for this key **may** have committed. Never raises.

        Must be called only **after** the capturing transaction has returned normally. Signalling
        from a ``finally``, or before the await, fires on a transaction that may have rolled back —
        harmless here only because the waiter re-reads, but it wastes the wake and misleads anyone
        reading the code into thinking the signal carries information.
        """
        self._wake(message_id, destination_name)

    def fail(self, message_id: str, destination_name: str) -> None:
        """Hint that this message **may** have reached a state where no reply will arrive.

        Behaviourally identical to :meth:`signal`, and that is deliberate — see the module docstring.
        In particular a *sibling* handler's terminal outcome legitimately fires this while the awaited
        destination is still perfectly healthy; the waiter re-reads, sees the message is still
        flowing, and keeps waiting. Nothing here may shortcut that.
        """
        self._wake(message_id, destination_name)

    def _wake(self, message_id: str, destination_name: str) -> None:
        # An unknown key is the normal case, not an error: almost no message is being awaited, and
        # every delivery calls this. Silence is the contract.
        for waiter in self._waiters.get((message_id, destination_name), ()):
            waiter._wake()

    def drain(self, reason: str) -> None:
        """Wake every waiter for listener shutdown and refuse further arms.

        Called from ``stop()`` **before** client writers are closed, so each woken turn can still
        write its ``503`` through a live socket. Idempotent.
        """
        self._draining = reason
        for group in list(self._waiters.values()):
            for waiter in list(group):
                waiter._drain(reason)
