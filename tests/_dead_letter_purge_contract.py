# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: the dead-letter purge releases a store-once body (BACKLOG #5740).

The server backends write no store-once row, but a restored dead outbound row carries a
``body_ref`` naming a ``shared_body``. ``purge_dead_letters`` blanked its payload and left the
``body_ref`` set, so the row still read as replayable: the shared body (PHI) outlived its retention
window, and so did the attachment of a message whose last replayable row it was. SQLite always
released both; every backend must.

Extra-free on the ``_erased_reply_contract`` precedent, so the gated Postgres and SQL Server suites
run the same body. ``fetch`` and ``raw`` run one ``?``-placeholder statement outside the store.

Every release has an unpurged control beside it: a row inside its window keeps its body, its
``body_ref`` and its attachment, since "nothing left" is also what a purge of everything looks like.
"""

from __future__ import annotations

from typing import Any

from messagefoundry.store import Stage
from tests._queue_tag_contract import RawFetch, RawSql, _row_id

DAY = 86_400.0
DEST = "OB_DL_5740"
RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|DL1|P|2.5.1\rPID|1||SYNTH-5740||DOE^JANE\r"
#: Synthetic document chunks, never a real document.
DOC = ("JVBERi0xLjQK", "U1lOVEhFVElDIDU3NDA=")


async def _restored_dead_row(
    store: Any, fetch: RawFetch, raw: RawSql, *, now: float, tag: str
) -> tuple[str, str, str]:
    """A dead outbound row carrying a ``body_ref`` and a held attachment, as a restore leaves one.

    Returns ``(row_id, body_hash, attachment_ref)``."""
    mid = await store.enqueue_message(
        channel_id="IB_SRC", raw=RAW, deliveries=[(DEST, RAW)], control_id=tag, now=now
    )
    row_id = await _row_id(fetch, mid, Stage.OUTBOUND.value)
    items = [i for i in await store.claim_ready(destination_name=DEST, now=now) if i.id == row_id]
    assert len(items) == 1
    await store.dead_letter_now(row_id, "partner rejected", now=now)
    body_hash = f"{tag.lower():0<64}"[:64]
    await raw(
        "INSERT INTO shared_body (hash, body, refcount, created_at) VALUES (?,?,?,?)",
        (body_hash, RAW, 1, now),
    )
    await raw("UPDATE queue SET body_ref=? WHERE id=?", (body_hash, row_id))
    ref = await store.put_attachment(iter((*DOC, tag)), "application/pdf")
    await raw("UPDATE attachment SET refcount=1 WHERE id=?", (ref,))
    await raw("INSERT INTO message_attachment (message_id, attachment_id) VALUES (?,?)", (mid, ref))
    return row_id, body_hash, ref


async def _state(fetch: RawFetch, row_id: str, body_hash: str, ref: str) -> tuple[Any, ...]:
    (row,) = await fetch("SELECT body_ref FROM queue WHERE id=?", (row_id,))
    shared = await fetch("SELECT 1 FROM shared_body WHERE hash=?", (body_hash,))
    held = await fetch("SELECT 1 FROM message_attachment WHERE attachment_id=?", (ref,))
    header = await fetch("SELECT 1 FROM attachment WHERE id=?", (ref,))
    return row["body_ref"], len(shared), len(held), len(header)


async def assert_a_restored_dead_row_releases_its_shared_body_and_attachment(
    store: Any, fetch: RawFetch, raw: RawSql
) -> None:
    try:
        old_row, old_hash, old_ref = await _restored_dead_row(
            store, fetch, raw, now=0.0, tag="DL-PURGED"
        )
        new_row, new_hash, new_ref = await _restored_dead_row(
            store, fetch, raw, now=100 * DAY, tag="DL-KEPT"
        )
        await store.purge_dead_letters(older_than=10 * DAY, now=101 * DAY)

        # Control: the row inside its window keeps everything it holds.
        assert await _state(fetch, new_row, new_hash, new_ref) == (new_hash, 1, 1, 1)
        # The purged row lets go of its body_ref, its shared body and its message's attachment.
        assert await _state(fetch, old_row, old_hash, old_ref) == (None, 0, 0, 0)

        # A re-run releases nothing more and leaves the control alone.
        await store.purge_dead_letters(older_than=10 * DAY, now=102 * DAY)
        assert await _state(fetch, new_row, new_hash, new_ref) == (new_hash, 1, 1, 1)
    finally:
        # The server suites' clean slate does not truncate shared_body, and another test there
        # counts its rows, so this case removes the rows it planted.
        await raw("DELETE FROM shared_body WHERE hash LIKE ?", ("dl-%",))


CASES = (assert_a_restored_dead_row_releases_its_shared_body_and_attachment,)
