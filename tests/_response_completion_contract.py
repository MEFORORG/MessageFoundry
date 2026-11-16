# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: completing an outbound row with a captured reply (BACKLOG #5752).

``complete_with_response`` writes the reply artifact and, for a loopback, a ``Stage.RESPONSE``
re-ingress work-row. Two defects are pinned here on every backend:

* a completion of a row that is not ``inflight`` (already ``DONE``, or never claimed) wrote a second
  artifact and a second re-ingress child;
* two rows of one message to one destination (two handlers) read ``MAX(response_seq)`` unlocked on
  the server backends, so a concurrent pair collided on the ``response`` primary key and rolled back
  a delivery the partner had already accepted.

Extra-free on the ``_erased_reply_contract`` precedent, so the gated Postgres and SQL Server suites
run the same body. ``fetch`` runs one ``?``-placeholder query outside the store.

Every refusal has a control beside it: the first completion must write exactly one artifact, or
"one artifact after two calls" would also pass for a completion that writes nothing.
"""

from __future__ import annotations

import asyncio
from typing import Any

from messagefoundry.store import OutboxStatus, Stage
from tests._queue_tag_contract import RawFetch, RawSql, _row_id

LOOP = "IB_LOOP_5752"
DEST = "OB_REPLY_5752"
RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|RC1|P|2.5.1\rPID|1||SYNTH-5752||DOE^JANE\r"
REPLY = "MSH|^~\\&|PARTNER|||||20260101||ACK^A01|RSP1|P|2.5.1\rMSA|AA|RC1\r"


async def _seqs(fetch: RawFetch, message_id: str) -> list[int]:
    rows = await fetch(
        "SELECT response_seq FROM response WHERE message_id=? AND destination_name=?",
        (message_id, DEST),
    )
    return sorted(int(r["response_seq"]) for r in rows)


async def _reingress_rows(fetch: RawFetch, message_id: str) -> int:
    rows = await fetch(
        "SELECT id FROM queue WHERE message_id=? AND stage=?", (message_id, Stage.RESPONSE.value)
    )
    return len(rows)


async def _status(fetch: RawFetch, outbox_id: str) -> str:
    rows = await fetch("SELECT status FROM queue WHERE id=?", (outbox_id,))
    return str(rows[0]["status"])


async def assert_a_second_completion_writes_nothing(
    store: Any, fetch: RawFetch, _raw: RawSql
) -> None:
    mid = await store.enqueue_message(
        channel_id="IB_SRC", raw=RAW, deliveries=[(DEST, RAW)], now=1.0
    )
    items = await store.claim_ready(destination_name=DEST, now=1.0)
    assert len(items) == 1
    await store.complete_with_response(
        items[0].id, body=REPLY, outcome="accepted", reingress_to=LOOP, now=2.0
    )
    # Control: the first completion wrote one artifact and one re-ingress work-row.
    assert await _seqs(fetch, mid) == [1]
    assert await _reingress_rows(fetch, mid) == 1
    assert await _status(fetch, items[0].id) == OutboxStatus.DONE.value

    await store.complete_with_response(
        items[0].id, body=REPLY, outcome="accepted", reingress_to=LOOP, now=3.0
    )
    assert await _seqs(fetch, mid) == [1]
    assert await _reingress_rows(fetch, mid) == 1
    assert await _status(fetch, items[0].id) == OutboxStatus.DONE.value


async def assert_an_unclaimed_row_does_not_complete(
    store: Any, fetch: RawFetch, _raw: RawSql
) -> None:
    mid = await store.enqueue_message(
        channel_id="IB_SRC", raw=RAW, deliveries=[(DEST, RAW)], now=1.0
    )
    row_id = await _row_id(fetch, mid, Stage.OUTBOUND.value)
    await store.complete_with_response(
        row_id, body=REPLY, outcome="accepted", reingress_to=LOOP, now=2.0
    )
    assert await _seqs(fetch, mid) == []
    assert await _reingress_rows(fetch, mid) == 0
    # Still deliverable: the row is untouched, so the worker claims and sends it as before.
    assert await _status(fetch, row_id) == OutboxStatus.PENDING.value


async def assert_concurrent_completions_to_one_destination_both_capture(
    store: Any, fetch: RawFetch, _raw: RawSql
) -> None:
    for attempt in range(5):
        mid = await store.enqueue_message(
            channel_id="IB_SRC",
            raw=RAW,
            deliveries=[(DEST, RAW), (DEST, RAW)],
            now=10.0 + attempt,
        )
        items = [
            i
            for i in await store.claim_ready(destination_name=DEST, now=10.0 + attempt)
            if i.message_id == mid
        ]
        assert len(items) == 2, attempt
        await asyncio.gather(
            *(
                store.complete_with_response(
                    i.id, body=REPLY, outcome="accepted", now=11.0 + attempt
                )
                for i in items
            )
        )
        assert await _seqs(fetch, mid) == [1, 2], attempt
        for i in items:
            assert await _status(fetch, i.id) == OutboxStatus.DONE.value, attempt


CASES = (
    assert_a_second_completion_writes_nothing,
    assert_an_unclaimed_row_does_not_complete,
    assert_concurrent_completions_to_one_destination_both_capture,
)
