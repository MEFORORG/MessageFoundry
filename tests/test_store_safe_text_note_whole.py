# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The store keeps :func:`safe_text`'s bounded output whole, note and all (BACKLOG #1797).

Three SQLite writers stored ``safe_text(x)[:200]``: ``response.detail`` (``record_ack_sent``),
``connection_event.reason`` and ``alert_instance.reason``. While :func:`safe_text` cut at exactly its
limit, the outer slice dropped the ``(+N chars)`` note whole. Since #1797 the cut goes back to a
whole token, so the head can be shorter than the limit and the outer slice kept part of the note:
``...(+13`` for a true count of 132. That is a wrong number in the store. Each writer now passes the
bound to :func:`safe_text` instead. Postgres and SQL Server carry the same three call sites in the
same shape; their suites skip without a server, so only SQLite is exercised here.

The columns are ``TEXT`` on SQLite and Postgres and ``NVARCHAR(MAX)`` on SQL Server, so the note
cannot overflow a declared width. The bound pinned here is the one :func:`safe_text` itself gives
below its 64 KiB scan window: at most the limit, plus the note. That is no longer a hard
200-character cap, which the old slice gave by dropping the note.

The count is per call, as :func:`safe_text` documents. A value an emit site already bounded with
``safe_exc`` and then prefixed is cut again here, and the stored count is what THIS call held back,
inner note included, not what the first call dropped. The old slice lost that inner note too.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from messagefoundry.redaction import safe_text
from messagefoundry.store.store import MessageStore

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
LIMIT = 200
# 30 lowercase ten-letter tokens, one space apart: 329 characters. Token 18 spans 198 to 208, so it
# straddles the 200 bound and is dropped whole, leaving a 197-character head and a count of 132.
TOKEN = "abcdefghij"
STRADDLING = " ".join([TOKEN] * 30)
_NOTE = re.compile(r"…\(\+(\d+) chars\)\Z")


def _stored(db: Path, sql: str) -> str:
    con = sqlite3.connect(db)
    try:
        row = con.execute(sql).fetchone()
    finally:
        con.close()
    assert row is not None and isinstance(row[0], str)
    return row[0]


async def _ack_detail(store: MessageStore, db: Path, text: str) -> str:
    mid = await store.enqueue_message(channel_id="IB_X", raw=ADT, deliveries=[("d", ADT)])
    await store.record_ack_sent(
        message_id=mid,
        inbound_name="IB_X",
        ack_body=None,
        ack_code="AE",
        ack_phase="parse",
        outcome="rejected",
        detail=text,
    )
    return _stored(db, "SELECT detail FROM response WHERE kind='ack_sent'")


async def _event_reason(store: MessageStore, db: Path, text: str) -> str:
    await store.record_connection_event(
        connection="IB_X",
        transport="mllp",
        direction="inbound",
        kind="framing_error",
        reason=text,
        now=1.0,
    )
    return _stored(db, "SELECT reason FROM connection_event")


async def _alert_reason(store: MessageStore, db: Path, text: str) -> str:
    await store.upsert_alert_instance(
        event_type="delivery_failed", connection="OB_X", severity="error", reason=text, now=1.0
    )
    return _stored(db, "SELECT reason FROM alert_instance")


Writer = Callable[[MessageStore, Path, str], Awaitable[str]]
WRITERS: list[Writer] = [_ack_detail, _event_reason, _alert_reason]


@pytest.mark.parametrize("write", WRITERS, ids=lambda w: w.__name__.lstrip("_"))
async def test_a_straddling_value_is_stored_with_an_intact_note(
    tmp_path: Path, write: Writer
) -> None:
    db = tmp_path / "note.db"
    store = await MessageStore.open(db)
    try:
        stored = await write(store, db, STRADDLING)
    finally:
        await store.close()
    note = _NOTE.search(stored)
    assert note is not None, f"the (+N chars) note was cut: {stored[-20:]!r}"
    head = stored[: note.start()]
    # The count is every character held back, exactly, so head plus count is the whole input.
    assert len(head) + int(note.group(1)) == len(STRADDLING)
    assert int(note.group(1)) == 132
    # The straddling token went whole: every kept token is complete.
    assert head.split(" ") == [TOKEN] * 18
    # Whole, not re-cut: the store holds exactly safe_text's own answer.
    assert stored == safe_text(STRADDLING, limit=LIMIT)
    assert len(stored) <= LIMIT + len(note.group(0))


@pytest.mark.parametrize("write", WRITERS, ids=lambda w: w.__name__.lstrip("_"))
async def test_a_short_value_is_stored_unchanged(tmp_path: Path, write: Writer) -> None:
    # The control: below the bound there is no note and nothing to cut.
    db = tmp_path / "short.db"
    store = await MessageStore.open(db)
    try:
        stored = await write(store, db, "connect refused")
    finally:
        await store.close()
    assert stored == "connect refused"
