# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``record_message_event`` — the public message-event writer (ADR 0154 D8).

``_event`` is private to each backend and only ever called inside a store-owned transaction, so
before this neither ``pipeline/`` nor ``transports/`` could record a disposition event at all.

The load-bearing test here is ``test_an_unknown_kind_is_refused``. The shipped static guard
(``test_message_event_constant_matches_the_literal_emit_sites``) AST-walks the backends for a
*constant* first argument to ``_event``; this method forwards a **variable**, so that guard is blind
to every kind written through it and passes vacuously. The runtime check is what actually keeps the
vocabulary closed on this path.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from messagefoundry.store.store import MessageStore

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def _events(db_path: Path) -> list[tuple]:
    con = sqlite3.connect(db_path)
    try:
        return con.execute(
            "SELECT event, destination, detail FROM message_events ORDER BY id"
        ).fetchall()
    finally:
        con.close()


async def test_writes_a_row_with_the_given_kind(tmp_path: Path) -> None:
    db = tmp_path / "ev.db"
    store = await MessageStore.open(db)
    try:
        mid = await store.enqueue_message(channel_id="IB_HTTP", raw=ADT, deliveries=[])
        await store.record_message_event(
            mid, "reply_returned", destination="OB_PARTNER", detail="seq=1 waited_ms=42"
        )
        await store.record_message_event(mid, "reply_timeout", destination="OB_PARTNER")
    finally:
        await store.close()

    written = [row for row in _events(db) if row[0].startswith("reply_")]
    assert written == [
        ("reply_returned", "OB_PARTNER", "seq=1 waited_ms=42"),
        ("reply_timeout", "OB_PARTNER", None if written[1][2] is None else ""),
    ]


async def test_an_unknown_kind_is_refused(tmp_path: Path) -> None:
    # The guard the static AST check cannot provide for this path.
    store = await MessageStore.open(tmp_path / "bad.db")
    try:
        mid = await store.enqueue_message(channel_id="IB_HTTP", raw=ADT, deliveries=[])
        with pytest.raises(ValueError, match="unknown message_events kind"):
            await store.record_message_event(mid, "reply_retruned")  # typo
        with pytest.raises(ValueError, match="unknown message_events kind"):
            await store.record_message_event(mid, "something_invented")
    finally:
        await store.close()


async def test_the_reply_kinds_are_declared(tmp_path: Path) -> None:
    from messagefoundry.store.store import _AUDIT_FLOOR_EVENTS, MESSAGE_EVENT_KINDS

    assert {"reply_returned", "reply_timeout"} <= MESSAGE_EVENT_KINDS
    # reply_timeout is compliance-floor: it is the row that explains a "we called you and got a 504"
    # complaint, so it must survive an operator thinning message_events to "errors" or "off".
    assert "reply_timeout" in _AUDIT_FLOOR_EVENTS
    # reply_returned is the routine happy-path counterpart and is deliberately thinnable.
    assert "reply_returned" not in _AUDIT_FLOOR_EVENTS


async def test_the_floor_kind_survives_verbosity_off(tmp_path: Path) -> None:
    # The whole point of the floor. `off` drops the routine kind and keeps the diagnostic one.
    db = tmp_path / "off.db"
    store = await MessageStore.open(db, message_events="off")
    try:
        mid = await store.enqueue_message(channel_id="IB_HTTP", raw=ADT, deliveries=[])
        await store.record_message_event(mid, "reply_returned", destination="OB_PARTNER")
        await store.record_message_event(mid, "reply_timeout", destination="OB_PARTNER")
    finally:
        await store.close()

    kinds = [row[0] for row in _events(db)]
    assert "reply_timeout" in kinds, "the floor kind was thinned away — the floor is not holding"
    assert "reply_returned" not in kinds, "a routine kind survived verbosity=off"


async def test_detail_is_scrubbed_at_the_store_boundary(tmp_path: Path) -> None:
    # Defence in depth only. The real control is structural: reply-derived bytes never reach a
    # detail argument in the first place. This asserts the store's own PHI chokepoint still applies
    # to this new writer, so it is not a hole around safe_text.
    db = tmp_path / "scrub.db"
    store = await MessageStore.open(db)
    try:
        mid = await store.enqueue_message(channel_id="IB_HTTP", raw=ADT, deliveries=[])
        await store.record_message_event(mid, "reply_timeout", detail=ADT)
    finally:
        await store.close()

    detail = next(row[2] for row in _events(db) if row[0] == "reply_timeout")
    assert detail is not None
    assert "DOE^JANE" not in detail, "an HL7 field value reached message_events.detail unscrubbed"
