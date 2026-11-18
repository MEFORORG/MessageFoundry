# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The sync-reply resolver reads the awaited destination's row set as a whole (ADR 0154 D3).

Two mis-mappings, both driven through the resolver suite's store double so each state is
deterministic:

* a delivered (``done``) row with no captured reply -- a plain ``mark_done``, as shadow mode
  performs -- on a terminal message resolved ``no_route``, which tells the caller nothing was routed
  to a destination that in fact took the message. ADR 0154 D3 maps it to ``failed``.
* one dead or cancelled row failed the turn while a sibling row to the SAME destination was still
  pending or inflight and could yet capture the reply.

The fast-fail cases run on a short budget, so a regression into waiting reads as ``timeout`` at once
rather than costing the suite the full default budget.
"""

from __future__ import annotations

from messagefoundry.store.store import MessageStatus
from messagefoundry.transports.base import ReplyOutcome
from tests.test_sync_reply_resolver import _flowing, _resolver, _Row, _Store

_SHORT = 0.2
_PROCESSED = MessageStatus.PROCESSED.value
_ERROR = MessageStatus.ERROR.value


async def test_a_delivered_row_with_no_captured_reply_is_failed_not_no_route() -> None:
    store = _Store([_flowing(status=_PROCESSED, row_states=("done",))])
    assert (await _resolver(store, timeout=_SHORT)("m1")).outcome is ReplyOutcome.FAILED


async def test_done_beside_dead_with_no_reply_is_failed_once_terminal() -> None:
    store = _Store([_flowing(status=_ERROR, row_states=("dead", "done"))])
    assert (await _resolver(store, timeout=_SHORT)("m1")).outcome is ReplyOutcome.FAILED


async def test_a_done_row_with_no_reply_waits_while_the_message_is_still_routed() -> None:
    # A sibling handler still upstream may yet emit a row to this destination that captures the
    # reply, so a settled set holding a done row is not proof of failure until the message is final.
    store = _Store([_flowing(row_states=("done",))])
    assert (await _resolver(store, timeout=_SHORT)("m1")).outcome is ReplyOutcome.TIMEOUT


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


async def test_every_row_dead_or_cancelled_still_fails_fast() -> None:
    store = _Store([_flowing(row_states=("dead", "cancelled"))])
    assert (await _resolver(store, timeout=_SHORT)("m1")).outcome is ReplyOutcome.FAILED


async def test_no_rows_on_a_terminal_message_is_still_no_route() -> None:
    store = _Store([_flowing(status=_PROCESSED, row_states=())])
    assert (await _resolver(store, timeout=_SHORT)("m1")).outcome is ReplyOutcome.NO_ROUTE
