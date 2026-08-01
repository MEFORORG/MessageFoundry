# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The synchronous-reply resolver (ADR 0154 D3) — the wait loop behind a ``reply_from`` HTTP turn.

**The committed row is the sole authority.** Every in-process signal is a latency hint; this loop
decides only from what the store says. A hint that never fires costs latency, a hint that fires
spuriously costs one extra read, and neither can produce an incorrect response. That is what makes
the design correct under engine sharding, HA failover, every claim mode, and any race between the
capturing worker and this reader.

Runner-owned, injected into the listener as a plain callable, so ``transports/`` keeps its
CI-enforced freedom from ``store/`` and ``pipeline/`` imports (AC-17) while still returning bytes that
came out of the store.
"""

from __future__ import annotations

import logging
import time
from typing import Final

from messagefoundry.pipeline.reply_wait import RendezvousFull, ReplyRendezvous
from messagefoundry.store.base import QueueStore
from messagefoundry.store.store import OutboxStatus
from messagefoundry.transports.base import InboundReply, ReplyOutcome

log = logging.getLogger(__name__)

#: Fastest a single waiter may re-read. Deliberately not zero: the hint already collapses the common
#: case to ~one read, so a tighter floor buys latency nobody notices and costs pooled reads everyone
#: shares.
_POLL_FLOOR_SECONDS: Final = 0.025
#: Slowest a waiter backs off to. Bounds worst-case added latency when hints are unavailable — the
#: engine-shard case, where the delivery signal fires in the process that owns the lane, not ours.
_POLL_CEILING_SECONDS: Final = 0.25
#: Live-waiter count past which the floor is widened. On SQLite, reads share a FIXED pool of four
#: connections with the admin API, console, retention and alert sweeps, so N waiters spinning at the
#: floor is a self-inflicted denial of service against the very store they are waiting on. The period
#: therefore scales with load rather than being a constant an operator has to reason about.
_POLL_SCALE_AFTER_WAITERS: Final = 8

#: Terminal delivery states for the awaited destination's row: no reply can still arrive.
_TERMINAL_ROW_STATES: Final = frozenset({OutboxStatus.DEAD.value, OutboxStatus.CANCELLED.value})


def poll_period(waiters: int) -> float:
    """Seconds to wait before the next re-read, given the number of live waiters.

    Floored as an explicit function of load, which the ADR asserts is necessary without specifying
    it. The alternative — a constant — is what turns 256 blocked callers into ~1,000 pooled reads a
    second against a four-connection pool.
    """
    if waiters <= _POLL_SCALE_AFTER_WAITERS:
        return _POLL_FLOOR_SECONDS
    scaled = _POLL_FLOOR_SECONDS * (waiters / _POLL_SCALE_AFTER_WAITERS)
    return min(scaled, _POLL_CEILING_SECONDS)


#: Outcomes that count as "a reply came back", so they get a ``reply_returned`` row. ``rejected`` and
#: ``empty`` belong here: the partner answered, and the answer is what the caller was waiting for even
#: when it is negative or deliberately blank.
_RETURNED_OUTCOMES: Final = frozenset(
    {ReplyOutcome.REPLY, ReplyOutcome.REJECTED, ReplyOutcome.EMPTY}
)


class SyncReplyMetrics:
    """In-process counters for one inbound's sync-reply path (ADR 0154 D8).

    **Labelled ``status``, not ``outcome``.** ``api/metrics.py`` states a CLOSED label allowlist as a
    PHI contract — ``connection``/``destination``/``status``/``version``/``le`` — and
    ``tests/test_metrics_exporter.py`` asserts it. The outcome enum is a fixed, non-PHI constant set,
    so reusing ``status`` is honest rather than a workaround, and it keeps a contract that was
    deliberately closed from being widened for a label that adds no new information.

    Counters live here rather than in ``api/metrics.py`` because that module builds every family
    per-scrape from ``engine.store`` alone and has no view of the runner — and ``transports/`` may not
    import ``api/`` (AC-17). The runner owns these and exposes them; the exporter reads them.
    """

    __slots__ = ("connection", "totals", "wait_seconds_sum", "wait_count")

    def __init__(self, connection: str) -> None:
        self.connection = connection
        #: ``{status: count}`` — the SLO series. ``rate(timeout)/rate(total)`` is the proxy API's
        #: error budget, which is exactly why ``degraded`` is a distinct label rather than folded in.
        self.totals: dict[str, int] = {}
        self.wait_seconds_sum = 0.0
        self.wait_count = 0

    def record(self, outcome: ReplyOutcome, waited_ms: int) -> None:
        self.totals[outcome.value] = self.totals.get(outcome.value, 0) + 1
        self.wait_seconds_sum += waited_ms / 1000.0
        self.wait_count += 1

    @property
    def mean_wait_seconds(self) -> float:
        """Mean blocked time. Answers *"is p99 approaching reply_timeout?"* before the pager does."""
        return self.wait_seconds_sum / self.wait_count if self.wait_count else 0.0


class SyncReplyResolverImpl:
    """Resolves one blocked HTTP turn into an :class:`InboundReply`. Never raises."""

    __slots__ = (
        "_store",
        "_rendezvous",
        "_destination",
        "_timeout",
        "_content_type",
        "_on_timeout",
        "_metrics",
    )

    def __init__(
        self,
        store: QueueStore,
        rendezvous: ReplyRendezvous,
        *,
        destination: str,
        timeout: float,
        content_type: str,
        on_timeout: str = "504",
        metrics: SyncReplyMetrics | None = None,
    ) -> None:
        self._store = store
        self._rendezvous = rendezvous
        self._destination = destination
        self._timeout = timeout
        self._content_type = content_type
        self._on_timeout = on_timeout
        self._metrics = metrics

    async def __call__(self, message_id: str) -> InboundReply:
        reply = await self._resolve(message_id)
        await self._observe(message_id, reply)
        return reply

    async def _observe(self, message_id: str, reply: InboundReply) -> None:
        """Record the outcome (ADR 0154 D8/AC-18) — names, counts and timings only.

        **Fail-soft, and that is a decision rather than caution.** This runs after the wait has
        already resolved, so a store hiccup here must not turn a perfectly good partner reply into a
        ``500``: the caller's answer is already determined, and losing a diagnostic row is strictly
        better than losing the reply it describes.

        **No fragment of the partner's body reaches ``detail``.** The structural rule is that
        reply-derived bytes never leave the resolver's return value, so the only things interpolated
        here are the destination name, the sequence number, the outcome enum and a duration —
        every one of which is config metadata or a count.
        """
        if self._metrics is not None:
            self._metrics.record(reply.outcome, reply.waited_ms)

        if reply.outcome in _RETURNED_OUTCOMES:
            event, detail = (
                "reply_returned",
                f"dest={self._destination} seq={reply.response_seq} "
                f"outcome={reply.outcome.value} waited_ms={reply.waited_ms}",
            )
        elif reply.outcome is ReplyOutcome.TIMEOUT:
            event, detail = (
                "reply_timeout",
                f"dest={self._destination} waited_ms={reply.waited_ms} fallback={self._on_timeout}",
            )
        else:
            # Every other outcome already has its own disposition trail — a dead/cancelled row, an
            # UNROUTED message, or (for degraded) the metric label. Minting a second record of the
            # same fact would make the timeline read as two events where one thing happened.
            return

        try:
            await self._store.record_message_event(
                message_id, event, destination=self._destination, detail=detail
            )
        except Exception as exc:  # noqa: BLE001 - observability must never fail the turn
            log.warning(
                "sync reply: could not record %s for %s: %s",
                event,
                message_id,
                exc.__class__.__name__,
            )

    async def _resolve(self, message_id: str) -> InboundReply:
        """Block until the awaited reply commits, the message goes terminal, or the budget expires.

        **Total by construction.** Every exit is an :class:`InboundReply`; nothing propagates. A
        store error resolves ``degraded`` rather than raising, because a raise here would surface as
        a ``500`` and lose the committed message's disposition from the operator's view — and because
        ``degraded`` is deliberately distinct from ``timeout``, which means "the partner did not
        answer" and drives an SLO an operator pages on.
        """
        started = time.monotonic()
        deadline = started + self._timeout

        def elapsed_ms() -> int:
            return int((time.monotonic() - started) * 1000)

        try:
            with self._rendezvous.arm(message_id, self._destination) as waiter:
                while True:
                    try:
                        state = await self._store.reply_wait_state(message_id, self._destination)
                    except Exception as exc:  # noqa: BLE001 - total by contract; see the docstring
                        # safe_exc is not used: this is our own error text, never reply-derived.
                        log.warning(
                            "sync reply: state read failed for %s/%s: %s",
                            message_id,
                            self._destination,
                            exc.__class__.__name__,
                        )
                        return self._done(ReplyOutcome.DEGRADED, elapsed_ms())

                    if state.latest_response_seq is not None:
                        return await self._read_committed_reply(
                            message_id, state.latest_response_seq, elapsed_ms()
                        )

                    # Fail fast on a PROVEN-terminal delivery, but only on the row's own state —
                    # never on the ABSENCE of rows. A sibling handler still upstream leaves this
                    # empty (routed rows carry a NULL destination_name), and reading that as
                    # exclusion is the 502-for-a-message-we-then-delivered defect.
                    if any(s in _TERMINAL_ROW_STATES for s in state.row_states):
                        return self._done(ReplyOutcome.FAILED, elapsed_ms())

                    if state.message_is_terminal:
                        # Terminal with no reply and no dead row: nothing routed here at all.
                        return self._done(ReplyOutcome.NO_ROUTE, elapsed_ms())

                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return self._done(ReplyOutcome.TIMEOUT, elapsed_ms())

                    await waiter.hint(min(poll_period(self._rendezvous.waiters), remaining))
                    if waiter.drain_reason is not None:
                        return self._done(ReplyOutcome.SHUTTING_DOWN, elapsed_ms())
        except RendezvousFull:
            # Capacity or shutdown — OUR condition, not the partner's. Never a timeout.
            return self._done(ReplyOutcome.DEGRADED, elapsed_ms())

    async def _read_committed_reply(
        self, message_id: str, seq: int, waited_ms: int
    ) -> InboundReply:
        """Fetch the committed reply once and map it onto the wire outcome."""
        try:
            captured = [
                row
                for row in await self._store.correlate_response(message_id)
                if row.kind == "response" and row.destination_name == self._destination
            ]
        except Exception as exc:  # noqa: BLE001 - total by contract
            log.warning(
                "sync reply: reply read failed for %s/%s: %s",
                message_id,
                self._destination,
                exc.__class__.__name__,
            )
            return self._done(ReplyOutcome.DEGRADED, waited_ms)

        if not captured:  # raced with retention, or the seq belonged to a purged row
            return self._done(ReplyOutcome.PURGED, waited_ms, response_seq=seq)

        # Highest seq wins: a replay appends seq=N+1 rather than overwriting, so the latest capture
        # is the authoritative reply for this destination.
        row = max(captured, key=lambda r: r.response_seq)
        if row.body is None:
            # The row exists but retention nulled the body in place. Distinct from "no reply".
            return self._done(ReplyOutcome.PURGED, waited_ms, response_seq=row.response_seq)

        if row.outcome == "no_reply":
            return self._done(ReplyOutcome.EMPTY, waited_ms, response_seq=row.response_seq)

        outcome = ReplyOutcome.REPLY if row.outcome == "accepted" else ReplyOutcome.REJECTED
        return InboundReply(
            outcome=outcome,
            body=row.body,
            content_type=self._resolve_content_type(row),
            destination=self._destination,
            response_seq=row.response_seq,
            waited_ms=waited_ms,
        )

    def _resolve_content_type(self, row: object) -> str | None:
        """The Content-Type to echo, or ``None`` to let the caller use its own default.

        ``passthrough`` reads the partner's own captured header — which ``reply_from`` implies
        capturing, so it is normally present. It can still be absent when retention has nulled the
        captured headers, and that must degrade to the caller's default rather than fail the turn:
        the body is still perfectly good.
        """
        if self._content_type != "passthrough":
            return self._content_type
        headers = getattr(row, "headers", None) or {}
        for name, value in headers.items():
            if str(name).strip().lower() == "content-type":
                return str(value)
        return None

    def _done(
        self, outcome: ReplyOutcome, waited_ms: int, *, response_seq: int | None = None
    ) -> InboundReply:
        return InboundReply(
            outcome=outcome,
            destination=self._destination,
            response_seq=response_seq,
            waited_ms=waited_ms,
        )
