# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The sync-reply resolver settles a turn on the awaited outbound's row SET, and only once the
message itself is terminal (ADR 0154 D3, amended 2026-11-18, BACKLOG #5895).

Driven through the resolver suite's store double so each state is deterministic:

* While the message is RECEIVED or ROUTED, no row set settles the turn: a sibling handler still
  upstream may yet emit a row to the same outbound that captures the reply, and routed rows carry a
  NULL ``destination_name``, so the row set cannot rule that out. ``mark_failed``, cancel and
  ``complete_with_response`` each finalize in the same transaction as the row flip, so a lone
  failed row still answers at once, beside a terminal status.
* On a terminal message, every row dead or cancelled is ``failed``; any ``done`` row with no capture
  (a plain ``mark_done``, as shadow or simulate mode performs) is ``empty``, "delivered, no reply",
  never ``failed``, whose ``502 delivery_failed`` would invite a resend of a delivered message.
* A live row keeps the turn waiting even on a terminal message.

The waiting cases run on a short budget, so they read as ``timeout`` at once.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from messagefoundry.pipeline.sync_reply import SyncReplyMetrics
from messagefoundry.store.store import MessageStatus
from messagefoundry.transports.base import InboundReply, ReplyOutcome
from messagefoundry.transports.http_listener import HttpSource
from tests.test_sync_reply_resolver import DEST, _flowing, _RecordingStore, _resolver, _Row, _Store

_SHORT = 0.2
_ROUTED = MessageStatus.ROUTED.value
_PROCESSED = MessageStatus.PROCESSED.value
_ERROR = MessageStatus.ERROR.value


async def _outcome(*states: Any, timeout: float = _SHORT) -> ReplyOutcome:
    return (await _resolver(_Store(list(states)), timeout=timeout)("m1")).outcome


# --- ROUTED: no row set settles the turn -----------------------------------------------------------


async def test_dead_beside_done_waits_while_the_message_is_still_routed() -> None:
    # origin/main failed this at once with 502. A sibling handler upstream may still emit a row that
    # captures the reply, so the turn waits for the finalizer instead.
    assert await _outcome(_flowing(row_states=("dead", "done"))) is ReplyOutcome.TIMEOUT


async def test_every_row_failed_waits_while_the_message_is_still_routed() -> None:
    for rows in (("dead",), ("cancelled",), ("dead", "cancelled")):
        assert await _outcome(_flowing(row_states=rows)) is ReplyOutcome.TIMEOUT, rows


async def test_a_done_row_with_no_reply_waits_while_the_message_is_still_routed() -> None:
    assert await _outcome(_flowing(row_states=("done",))) is ReplyOutcome.TIMEOUT


async def test_a_sibling_capture_after_a_settled_set_is_returned() -> None:
    # The case the guard exists for: the set read settled while ROUTED, then a sibling handler's
    # row to the same outbound captured the reply.
    store = _Store(
        [
            _flowing(row_states=("dead", "done")),
            _flowing(row_states=("dead", "done", "pending")),
            _flowing(status=_PROCESSED, row_states=("dead", "done", "done"), seq=1),
        ],
        [_Row()],
    )
    reply = await _resolver(store)("m1")
    assert reply.outcome is ReplyOutcome.REPLY
    assert reply.response_seq == 1


async def test_a_dead_row_does_not_fail_the_turn_while_a_sibling_row_is_live() -> None:
    store = _Store(
        [
            _flowing(row_states=("dead", "inflight")),
            _flowing(row_states=("cancelled", "pending")),
            _flowing(row_states=("cancelled", "done"), seq=1),
        ],
        [_Row()],
    )
    reply = await _resolver(store)("m1")
    assert reply.outcome is ReplyOutcome.REPLY
    assert reply.response_seq == 1


# --- terminal: the settled set decides --------------------------------------------------------------


async def test_dead_beside_done_answers_once_the_message_goes_terminal() -> None:
    # Not a timeout: the finalizer's terminal status answers on the next tick.
    store = _Store(
        [
            _flowing(row_states=("dead", "done")),
            _flowing(status=_PROCESSED, row_states=("dead", "done")),
        ]
    )
    reply = await _resolver(store, timeout=30.0)("m1")
    assert reply.outcome is ReplyOutcome.EMPTY
    assert reply.waited_ms < 5000


async def test_every_row_failed_on_a_terminal_message_fails_fast() -> None:
    for rows in (("dead",), ("cancelled",), ("dead", "cancelled")):
        assert await _outcome(_flowing(status=_ERROR, row_states=rows), timeout=30.0) is (
            ReplyOutcome.FAILED
        ), rows


async def test_a_delivered_row_with_no_capture_is_empty_not_delivery_failed() -> None:
    for status, rows in ((_PROCESSED, ("done",)), (_ERROR, ("dead", "done"))):
        reply = await _resolver(_Store([_flowing(status=status, row_states=rows)]), timeout=30.0)(
            "m1"
        )
        assert reply.outcome is ReplyOutcome.EMPTY, rows
        assert reply.response_seq is None and reply.body is None


async def test_a_delivered_row_with_no_capture_answers_no_reply_on_the_wire() -> None:
    listener: Any = SimpleNamespace(reply_on_empty="204", reply_on_timeout="504")
    reply = await _resolver(_Store([_flowing(status=_PROCESSED, row_states=("done",))]))("m1")
    status, body, _ = HttpSource._reply_to_wire(listener, reply, "m1")
    assert (status, body) == (204, "")
    failed = HttpSource._reply_to_wire(listener, InboundReply(outcome=ReplyOutcome.FAILED), "m1")
    assert failed[0] == 502 and "delivery_failed" in failed[1]


async def test_a_delivered_row_with_no_capture_records_a_message_event() -> None:
    store = _RecordingStore([_flowing(status=_PROCESSED, row_states=("done",))])
    metrics = SyncReplyMetrics("IB_HTTP")
    await _resolver(store, metrics=metrics)("m1")
    assert len(store.events) == 1
    message_id, event, destination, detail = store.events[0]
    assert (message_id, event, destination) == ("m1", "reply_returned", DEST)
    assert detail is not None and "outcome=empty" in detail
    assert metrics.totals == {"empty": 1}


async def test_a_terminal_message_with_a_live_row_keeps_waiting() -> None:
    for rows in (("pending",), ("done", "inflight"), ("dead", "pending"), ("dead", "unknown")):
        assert await _outcome(_flowing(status=_PROCESSED, row_states=rows)) is (
            ReplyOutcome.TIMEOUT
        ), rows


async def test_no_rows_on_a_terminal_message_is_still_no_route() -> None:
    assert await _outcome(_flowing(status=_PROCESSED, row_states=())) is ReplyOutcome.NO_ROUTE
