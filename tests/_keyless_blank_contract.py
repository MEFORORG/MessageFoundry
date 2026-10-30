# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: a keyless store's live empty queue row at the first keyed open (BACKLOG #3495).

A keyless store writes an empty body as ``payload=''``. Retention writes the same thing, so the keyed
sweep skipped every blank, and ``open_queue_cell`` refuses a blank on a keyed store. An operator who
added a key while such a row was still owed work would have seen it dead-lettered with a false
``integrity_drift`` alarm.

Extra-free on the ``_finalize_race_contract`` precedent, so the gated Postgres and SQL Server suites
run the same body on legs that install only their own driver extra.

``keyless`` is a store opened with no key on a database no keyed open has touched. ``open_keyed`` opens
a new keyed handle on the same database, and the contract closes it. ``fetch`` and ``raw`` run one
statement outside the store, with ``?`` placeholders, and each backend's adapter respells them.

**The refusal is a control, and this contract pins that it did not move.** A blank on a surface that
is already keyed is what a plant looks like, so the second case keeps refusing it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from messagefoundry.store import MessageStatus, OutboxStatus, Stage
from messagefoundry.store.crypto import MARKER_PREFIX
from messagefoundry.store.queue_tag import QUEUE_TAG_SELECT, open_queue_cell
from tests._erased_reply_contract import status_of
from tests._queue_tag_contract import RawFetch, RawSql

OpenKeyed = Callable[[], Awaitable[Any]]

RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|KB1|P|2.5.1\rPID|1||SYNTH-100||DOE^JANE\r"
BODY = "SYNTH-BODY"


async def row_of(
    fetch: RawFetch, message_id: str, stage: str = Stage.OUTBOUND.value
) -> dict[str, Any]:
    rows = await fetch(
        f"SELECT {QUEUE_TAG_SELECT}, payload, status FROM queue WHERE message_id=? AND stage=?",
        (message_id, stage),
    )
    assert len(rows) == 1, rows
    return rows[0]


async def marked(fetch: RawFetch) -> bool:
    """Whether ``queue.payload`` has its ``keyed_surface`` marker."""
    return bool(
        await fetch(
            "SELECT surface_table FROM keyed_surface WHERE surface_table=? AND surface_column=?",
            ("queue", "payload"),
        )
    )


async def outbound(store: Any, lane: str, body: str) -> str:
    return str(await store.enqueue_message(channel_id="IB_KB", raw=RAW, deliveries=[(lane, body)]))


async def terminal(store: Any, lane: str, *, dead: bool) -> str:
    """A delivery with an empty body, driven to a terminal status on the keyless store."""
    mid = await outbound(store, lane, "")
    [item] = await store.claim_ready(destination_name=lane)
    if dead:
        await store.dead_letter_now(item.id, "permanent reject")
    else:
        await store.mark_done(item.id)
    return mid


async def assert_first_keyed_open_seals_a_live_empty_row(
    keyless: Any, open_keyed: OpenKeyed, fetch: RawFetch, _raw: RawSql
) -> None:
    """A live empty row becomes a real sealed row, delivered once with no alarm. A terminal blank
    stays blank, because it may be an erasure. Each kind sits beside the others on one surface."""
    pending = await outbound(keyless, "OB_KB_LIVE", "")
    inflight = await outbound(keyless, "OB_KB_CLAIMED", "")
    assert await keyless.claim_next_fifo("OB_KB_CLAIMED") is not None
    legacy = await outbound(keyless, "OB_KB_BODY", BODY)
    done = await terminal(keyless, "OB_KB_DONE", dead=False)
    dead = await terminal(keyless, "OB_KB_DEAD", dead=True)
    for mid in (pending, inflight, done, dead):
        assert (await row_of(fetch, mid))["payload"] == ""  # the premise: all blank at rest

    keyed = await open_keyed()
    try:
        alarms: list[str] = []
        cipher = keyed.cipher()
        cipher.set_tag_failure_hook(lambda _table, reason: alarms.append(reason))
        assert await marked(fetch)

        # The sweep and the claim agree: both read each live row as a real, empty row.
        for mid in (pending, inflight):
            row = await row_of(fetch, mid)
            assert str(row["payload"]).startswith(MARKER_PREFIX), row["status"]
            assert open_queue_cell(cipher, row) == ""
        assert str((await row_of(fetch, legacy))["payload"]).startswith(MARKER_PREFIX)

        # A terminal blank stays blank, and both refuse it as an erasure.
        for mid in (done, dead):
            assert (await row_of(fetch, mid))["payload"] == ""
            assert await keyed.replay(mid) == 0

        # Its disposition: still owed work, delivered as an empty body, finalized PROCESSED.
        item = await keyed.claim_next_fifo("OB_KB_LIVE")
        assert item is not None and item.payload == ""
        await keyed.mark_done(item.id)
        assert await status_of(keyed, pending) == MessageStatus.PROCESSED.value

        # The unfixed code's symptom, stated: no dead-letter and no false alarm.
        assert (await row_of(fetch, pending))["status"] == OutboxStatus.DONE.value
        assert alarms == []

        item = await keyed.claim_next_fifo("OB_KB_BODY")  # the control: a real body still delivers
        assert item is not None and item.payload == BODY
    finally:
        await keyed.close()


async def assert_a_live_empty_ingress_row_is_sealed(
    keyless: Any, open_keyed: OpenKeyed, fetch: RawFetch, _raw: RawSql
) -> None:
    """The sweep reads the row's status, not its stage. Blank is a real ingress body here too."""
    mid = await keyless.enqueue_ingress(channel_id="IB_KB", raw="")
    keyed = await open_keyed()
    try:
        row = await row_of(fetch, mid, Stage.INGRESS.value)
        assert str(row["payload"]).startswith(MARKER_PREFIX)
        item = await keyed.claim_next_fifo("IB_KB", stage=Stage.INGRESS.value)
        assert item is not None and item.payload == ""
    finally:
        await keyed.close()


async def assert_terminal_blanks_alone_seal_nothing(
    keyless: Any, open_keyed: OpenKeyed, fetch: RawFetch, _raw: RawSql
) -> None:
    """The "nothing to seal" path still runs when every blank is terminal: the marker is written and
    no blank is turned into ciphertext-of-empty, which would make an erased row replayable."""
    done = await terminal(keyless, "OB_KB_DONE", dead=False)
    assert not await marked(fetch)
    keyed = await open_keyed()
    try:
        assert await marked(fetch)
        assert (await row_of(fetch, done))["payload"] == ""
    finally:
        await keyed.close()


async def assert_a_blank_on_a_keyed_surface_stays_refused(
    keyless: Any, open_keyed: OpenKeyed, fetch: RawFetch, raw: RawSql
) -> None:
    """The control this fix must not loosen. Nothing a keyed writer does leaves a live blank, so one
    on a marked surface is a plant. A second keyed open leaves it, the claim dead-letters it and
    alarms, and the next row on the lane is delivered. The same holds when the marker row is gone and
    the surface's own ciphertext is the only signal it is sealed."""
    keyed = await open_keyed()
    try:
        mid = await outbound(keyed, "OB_KB_PLANT", BODY)
        unmarked = await outbound(keyed, "OB_KB_LOST", BODY)
        witness = await outbound(keyed, "OB_KB_WITNESS", BODY)
    finally:
        await keyed.close()
    await raw("UPDATE queue SET payload='' WHERE message_id=?", (mid,))
    await raw("UPDATE queue SET payload='' WHERE message_id=?", (unmarked,))
    await raw(
        "DELETE FROM keyed_surface WHERE surface_table=? AND surface_column=?", ("queue", "payload")
    )

    keyed = await open_keyed()
    try:
        alarms: list[str] = []
        keyed.cipher().set_tag_failure_hook(lambda _table, reason: alarms.append(reason))
        assert await marked(fetch)  # the open restored the marker
        # Neither blank was sealed: the witness's ciphertext kept the surface sealed.
        assert (await row_of(fetch, mid))["payload"] == ""
        assert (await row_of(fetch, unmarked))["payload"] == ""
        assert str((await row_of(fetch, witness))["payload"]).startswith(MARKER_PREFIX)

        assert await keyed.claim_next_fifo("OB_KB_PLANT") is None
        row = await row_of(fetch, mid)
        assert row["status"] == OutboxStatus.DEAD.value
        assert await status_of(keyed, mid) == MessageStatus.ERROR.value
        assert any(str(row["id"])[:12] in reason for reason in alarms), alarms
        item = await keyed.claim_next_fifo("OB_KB_WITNESS")
        assert item is not None and item.payload == BODY  # the control
    finally:
        await keyed.close()


#: Every case, for ``pytest.mark.parametrize``. Each takes ``(keyless, open_keyed, fetch, raw)`` and
#: needs a database no keyed open has touched, so each runs on its own clean store.
CASES = (
    assert_first_keyed_open_seals_a_live_empty_row,
    assert_a_live_empty_ingress_row_is_sealed,
    assert_terminal_blanks_alone_seal_nothing,
    assert_a_blank_on_a_keyed_surface_stays_refused,
)
