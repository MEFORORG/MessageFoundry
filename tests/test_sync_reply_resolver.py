# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The synchronous-reply resolver (ADR 0154 D3) — the wait loop's outcome matrix.

Driven through a store double so every branch is deterministic, including the ones a real store
reaches only under a race: a sibling handler still upstream, a body nulled by retention mid-wait, and
a read that raises. The resolver is **total** — every exit is an ``InboundReply`` — so "it raised" is
itself a failure these tests can catch.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from messagefoundry.pipeline.reply_wait import ReplyRendezvous
from messagefoundry.pipeline.sync_reply import (
    SyncReplyMetrics,
    SyncReplyResolverImpl,
    poll_period,
)
from messagefoundry.store.store import MessageStatus, ReplyWaitState
from messagefoundry.transports.base import ReplyOutcome

DEST = "OB_PARTNER"
BODY = '{"status":"accepted","mrn":"100"}'


@dataclass
class _Row:
    kind: str = "response"
    destination_name: str = DEST
    response_seq: int = 1
    outcome: str = "accepted"
    body: str | None = BODY
    headers: dict[str, str] | None = None


class _Store:
    """A store double: a scripted sequence of wait states, then a fixed set of captured rows."""

    def __init__(self, states: list[Any], rows: list[_Row] | None = None) -> None:
        self._states = list(states)
        self._rows = rows or []
        self.state_reads = 0

    async def reply_wait_state(self, message_id: str, destination_name: str) -> Any:
        self.state_reads += 1
        state = self._states[0] if len(self._states) == 1 else self._states.pop(0)
        if isinstance(state, Exception):
            raise state
        return state

    async def correlate_response(self, message_id: str) -> list[Any]:
        if isinstance(self._rows, Exception):
            raise self._rows
        return list(self._rows)


def _flowing(**kw: Any) -> ReplyWaitState:
    return ReplyWaitState(
        message_status=kw.pop("status", MessageStatus.ROUTED.value),
        row_states=kw.pop("row_states", ("pending",)),
        latest_response_seq=kw.pop("seq", None),
    )


def _resolver(store: Any, **kw: Any) -> SyncReplyResolverImpl:
    return SyncReplyResolverImpl(
        store,
        kw.pop("rendezvous", ReplyRendezvous()),
        destination=DEST,
        timeout=kw.pop("timeout", 2.0),
        content_type=kw.pop("content_type", "passthrough"),
        metrics=kw.pop("metrics", None),
    )


async def test_a_committed_accepted_reply_is_returned_verbatim() -> None:
    store = _Store([_flowing(seq=1)], [_Row(headers={"Content-Type": "application/json"})])
    reply = await _resolver(store)("m1")
    assert reply.outcome is ReplyOutcome.REPLY
    assert reply.body == BODY
    assert reply.content_type == "application/json"
    assert reply.destination == DEST and reply.response_seq == 1


async def test_a_rejected_reply_still_returns_the_partners_body() -> None:
    # A partner <Fault> is the answer the caller needs to see; swallowing it would be worse than a
    # 502 with no detail.
    store = _Store([_flowing(seq=1)], [_Row(outcome="rejected", body="<Fault>nope</Fault>")])
    reply = await _resolver(store)("m1")
    assert reply.outcome is ReplyOutcome.REJECTED
    assert reply.body == "<Fault>nope</Fault>"


async def test_an_empty_partner_reply_is_its_own_outcome() -> None:
    store = _Store([_flowing(seq=1)], [_Row(outcome="no_reply", body="")])
    assert (await _resolver(store)("m1")).outcome is ReplyOutcome.EMPTY


async def test_a_purged_body_is_distinct_from_no_reply() -> None:
    # Retention nulled the body in place. The row exists, so this is not "the partner said nothing".
    store = _Store([_flowing(seq=1)], [_Row(body=None)])
    reply = await _resolver(store)("m1")
    assert reply.outcome is ReplyOutcome.PURGED
    assert reply.body is None


async def test_the_highest_seq_wins_and_ack_sent_is_ignored() -> None:
    store = _Store(
        [_flowing(seq=2)],
        [
            _Row(response_seq=1, body="first"),
            _Row(response_seq=2, body="second"),
            _Row(kind="ack_sent", response_seq=99, body="OUR OWN ACK"),
            _Row(destination_name="OB_OTHER", response_seq=98, body="someone else's reply"),
        ],
    )
    reply = await _resolver(store)("m1")
    assert reply.body == "second", "a replay appends seq=N+1; the latest capture is authoritative"


async def test_a_dead_row_fails_fast_rather_than_waiting_out_the_budget() -> None:
    store = _Store([_flowing(row_states=("dead",))])
    reply = await _resolver(store, timeout=30.0)("m1")
    assert reply.outcome is ReplyOutcome.FAILED
    assert reply.waited_ms < 5000, "it waited instead of failing fast on a proven-terminal row"


async def test_a_sibling_handler_upstream_does_not_look_like_exclusion() -> None:
    # AC-6. The awaited destination has NO rows yet because a sibling is still upstream — routed rows
    # carry a NULL destination_name. Reading that as "excluded" is the 502-for-a-delivered-message
    # defect. The loop must keep waiting, then return the reply once it commits.
    store = _Store(
        [
            _flowing(row_states=()),  # sibling upstream: no rows for us at all
            _flowing(row_states=()),
            _flowing(row_states=("pending",), seq=1),
        ],
        [_Row()],
    )
    reply = await _resolver(store)("m1")
    assert reply.outcome is ReplyOutcome.REPLY
    assert store.state_reads >= 3


async def test_a_terminal_message_with_no_reply_is_no_route() -> None:
    store = _Store([_flowing(status=MessageStatus.UNROUTED.value, row_states=())])
    assert (await _resolver(store, timeout=30.0)("m1")).outcome is ReplyOutcome.NO_ROUTE


async def test_processed_is_terminal_too() -> None:
    # The member an ENUMERATED terminal list forgets: a sibling handler delivered and the finalizer
    # set PROCESSED while our destination's Send was never emitted. Enumeration would hang here for
    # the full reply_timeout.
    store = _Store([_flowing(status=MessageStatus.PROCESSED.value, row_states=())])
    reply = await _resolver(store, timeout=30.0)("m1")
    assert reply.outcome is ReplyOutcome.NO_ROUTE
    assert reply.waited_ms < 5000, "PROCESSED was not treated as terminal — it waited"


async def test_the_budget_expires_into_a_timeout() -> None:
    store = _Store([_flowing()])  # never resolves
    reply = await _resolver(store, timeout=0.2)("m1")
    assert reply.outcome is ReplyOutcome.TIMEOUT
    assert reply.waited_ms >= 150


async def test_a_store_error_is_degraded_not_timeout() -> None:
    # rate(timeout)/rate(total) is the proxy API's error budget. Counting OUR store failure as the
    # partner failing to answer would silently corrupt the one number an operator pages on.
    store = _Store([RuntimeError("db is gone")])
    reply = await _resolver(store)("m1")
    assert reply.outcome is ReplyOutcome.DEGRADED
    assert reply.body is None


async def test_a_full_rendezvous_is_degraded_not_timeout() -> None:
    rv = ReplyRendezvous(max_waiters=1)
    with rv.arm("other", DEST):
        reply = await _resolver(_Store([_flowing()]), rendezvous=rv)("m1")
    assert reply.outcome is ReplyOutcome.DEGRADED


async def test_a_drain_mid_wait_resolves_shutting_down() -> None:
    rv = ReplyRendezvous()
    store = _Store([_flowing()])
    resolver = _resolver(store, rendezvous=rv, timeout=30.0)

    task = asyncio.create_task(resolver("m1"))
    await asyncio.sleep(0.1)
    rv.drain("shutting_down")
    reply = await asyncio.wait_for(task, 5.0)

    assert reply.outcome is ReplyOutcome.SHUTTING_DOWN
    assert reply.waited_ms < 5000, "a drained waiter was still paced by the poll period"


async def test_a_literal_content_type_overrides_passthrough() -> None:
    store = _Store([_flowing(seq=1)], [_Row(headers={"Content-Type": "text/plain"})])
    reply = await _resolver(store, content_type="application/json")("m1")
    assert reply.content_type == "application/json"


async def test_passthrough_degrades_to_the_callers_default_when_headers_are_gone() -> None:
    # Retention can null captured headers while leaving the body. The body is still good, so the
    # turn must not fail — the caller falls back to its own default content type.
    store = _Store([_flowing(seq=1)], [_Row(headers={})])
    assert (await _resolver(store)("m1")).content_type is None


async def test_the_rendezvous_entry_is_always_released() -> None:
    rv = ReplyRendezvous()
    for store in (_Store([_flowing(seq=1)], [_Row()]), _Store([RuntimeError("x")])):
        await _resolver(store, rendezvous=rv, timeout=0.2)("m1")
    assert rv.waiters == 0


def test_the_poll_period_widens_with_load() -> None:
    # On SQLite, reads share a FIXED pool of four with the admin API, console and sweeps, so a
    # constant period turns 256 blocked callers into a self-inflicted denial of service.
    assert poll_period(1) == poll_period(8)  # light load: the floor
    assert poll_period(64) > poll_period(8)  # heavier: backs off
    assert poll_period(10_000) <= 0.25  # ... but bounded, so latency stays predictable


# --- AC-18: observability ------------------------------------------------------------------------


class _RecordingStore(_Store):
    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.events: list[tuple[str, str, str | None, str | None]] = []
        self.event_error: Exception | None = None

    async def record_message_event(
        self,
        message_id: str,
        event: str,
        *,
        destination: str | None = None,
        detail: str | None = None,
        now: float | None = None,
    ) -> None:
        if self.event_error is not None:
            raise self.event_error
        self.events.append((message_id, event, destination, detail))


async def test_a_returned_reply_records_reply_returned_without_any_body() -> None:
    store = _RecordingStore([_flowing(seq=1)], [_Row()])
    metrics = SyncReplyMetrics("IB_HTTP")
    await _resolver(store, metrics=metrics)("m1")

    assert len(store.events) == 1
    message_id, event, destination, detail = store.events[0]
    assert (message_id, event, destination) == ("m1", "reply_returned", DEST)
    assert "seq=1" in detail and "outcome=reply" in detail and "waited_ms=" in detail
    # The PHI property: names, counts and timings only — never a fragment of the partner's body.
    for leak in ("mrn", "100", BODY):
        assert leak not in detail

    assert metrics.totals == {"reply": 1}


async def test_rejected_and_empty_also_count_as_a_reply_returned() -> None:
    # The partner answered; a negative or deliberately blank answer is still the thing the caller
    # was waiting for, so it belongs in the same row rather than looking like nothing happened.
    for outcome, row in (
        ("rejected", _Row(outcome="rejected")),
        ("no_reply", _Row(outcome="no_reply", body="")),
    ):
        store = _RecordingStore([_flowing(seq=1)], [row])
        await _resolver(store)("m1")
        assert [e[1] for e in store.events] == ["reply_returned"], outcome


async def test_a_timeout_records_reply_timeout_with_its_fallback() -> None:
    store = _RecordingStore([_flowing()])
    await _resolver(store, timeout=0.15)("m1")

    assert len(store.events) == 1
    _, event, destination, detail = store.events[0]
    assert (event, destination) == ("reply_timeout", DEST)
    assert "fallback=504" in detail, "an operator reading this needs to know what the caller got"
    assert "waited_ms=" in detail


async def test_outcomes_with_their_own_disposition_trail_mint_no_second_row() -> None:
    # A dead row, an UNROUTED message and a degraded read each already leave their own record.
    # Duplicating them here would make the timeline read as two events where one thing happened.
    for states in (
        _flowing(row_states=("dead",)),
        _flowing(status=MessageStatus.UNROUTED.value, row_states=()),
    ):
        store = _RecordingStore([states])
        await _resolver(store, timeout=0.2)("m1")
        assert store.events == []

    store = _RecordingStore([RuntimeError("db gone")])
    await _resolver(store)("m1")
    assert store.events == []


async def test_observability_failure_never_costs_the_caller_their_reply() -> None:
    # The wait has already resolved by this point, so losing a diagnostic row is strictly better
    # than turning a perfectly good partner reply into a 500.
    store = _RecordingStore([_flowing(seq=1)], [_Row()])
    store.event_error = RuntimeError("message_events write failed")

    reply = await _resolver(store)("m1")
    assert reply.outcome is ReplyOutcome.REPLY
    assert reply.body == BODY


async def test_the_metrics_separate_degraded_from_timeout() -> None:
    # rate(timeout)/rate(total) IS the proxy API's error budget, so our own failures must not be
    # counted as the partner failing to answer.
    metrics = SyncReplyMetrics("IB_HTTP")
    await _resolver(_RecordingStore([RuntimeError("x")]), metrics=metrics)("m1")
    await _resolver(_RecordingStore([_flowing()]), metrics=metrics, timeout=0.1)("m2")

    assert metrics.totals == {"degraded": 1, "timeout": 1}
    assert metrics.wait_count == 2
    assert metrics.mean_wait_seconds > 0


def test_the_metric_labels_stay_inside_the_closed_allowlist() -> None:
    # api/metrics.py states a CLOSED label allowlist as a PHI contract and a test asserts it. The
    # outcome enum is a fixed non-PHI constant set, so it rides `status` rather than widening it.
    from tests.test_metrics_exporter import ALLOWED_LABELS

    assert "status" in ALLOWED_LABELS
    assert "outcome" not in ALLOWED_LABELS, "the allowlist was widened — re-check the PHI contract"
