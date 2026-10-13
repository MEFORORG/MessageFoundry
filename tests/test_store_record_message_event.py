# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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


async def test_the_reply_dropped_kind_is_declared_and_kept_at_every_verbosity() -> None:
    """vault BACKLOG #3040 item 5: ``mark_done`` writes it on a delivered row whose 2xx reply body
    was dropped. The delivery worker's WARNING says it was written, so a thinned instance must
    still write it, as it writes ``reply_timeout``."""
    from messagefoundry.store.store import _AUDIT_FLOOR_EVENTS, MESSAGE_EVENT_KINDS

    assert "reply_dropped" in MESSAGE_EVENT_KINDS
    assert "reply_dropped" in _AUDIT_FLOOR_EVENTS


async def test_only_mark_done_writes_reply_dropped(tmp_path: Path) -> None:
    """A floor row nobody can thin, so the public writer may not plant one."""
    store = await MessageStore.open(tmp_path / "only.db")
    try:
        mid = await store.enqueue_message(channel_id="IB_HTTP", raw=ADT, deliveries=[])
        with pytest.raises(ValueError, match="written only by the store itself"):
            await store.record_message_event(mid, "reply_dropped", detail="HTTP 200")
    finally:
        await store.close()


@pytest.mark.parametrize("verbosity", ["all", "errors", "off"])
async def test_mark_done_writes_reply_dropped_with_the_delivery(
    tmp_path: Path, verbosity: str
) -> None:
    """The drop rides the DONE flip, so it commits or rolls back with it. ``delivered`` is the
    control: it is thinned below ``all``, and ``reply_dropped`` is not."""
    from messagefoundry.store.store import Stage

    db = tmp_path / "drop.db"
    store = await MessageStore.open(db, message_events=verbosity)
    try:
        mid = await store.enqueue_message(channel_id="IB_HTTP", raw=ADT, deliveries=[("OB_A", ADT)])
        item = await store.claim_next_fifo("OB_A", stage=Stage.OUTBOUND.value)
        assert item is not None
        wrote = await store.mark_done(
            item.id, reply_dropped="HTTP 200; reply body over the 64-byte bound"
        )
        # A vanished row writes nothing and says so.
        gone = await store.mark_done("no-such-row", reply_dropped="HTTP 200")
        plain = await store.enqueue_message(
            channel_id="IB_HTTP", raw=ADT, deliveries=[("OB_A", ADT)]
        )
        other = await store.claim_next_fifo("OB_A", stage=Stage.OUTBOUND.value)
        assert other is not None
        await store.mark_done(other.id)
    finally:
        await store.close()

    con = sqlite3.connect(db)
    try:
        rows = con.execute(
            "SELECT message_id, event, destination, detail FROM message_events"
            " WHERE event IN ('delivered', 'reply_dropped') ORDER BY id"
        ).fetchall()
    finally:
        con.close()
    assert (wrote, gone) == (True, False)
    dropped = [(m, d, x) for m, e, d, x in rows if e == "reply_dropped"]
    assert dropped == [(mid, "OB_A", "HTTP 200; reply body over the 64-byte bound")]
    delivered = sorted(m for m, e, _, _ in rows if e == "delivered")
    assert delivered == (sorted([mid, plain]) if verbosity == "all" else [])


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


async def test_the_viewed_kind_is_refused_and_record_view_still_writes_it(tmp_path: Path) -> None:
    """BACKLOG #2440. ``get_message``'s audit leaves ``viewed`` rows out of ``events.detail`` because
    their detail is the viewer's username. A caller-written ``viewed`` row could carry anything, and
    the error reveal would unmask it unrecorded, so only ``record_view`` may write the kind. The
    record_view leg is the control: the kind is refused on this path, not dead."""
    from messagefoundry.store.store import VIEWED_EVENT

    db = tmp_path / "viewed.db"
    store = await MessageStore.open(db)
    try:
        mid = await store.enqueue_message(channel_id="IB_HTTP", raw=ADT, deliveries=[])
        with pytest.raises(ValueError, match="written only by the store"):
            await store.record_message_event(mid, VIEWED_EVENT, detail="not a username")
        await store.record_view(mid, actor="alice")
    finally:
        await store.close()

    assert [row for row in _events(db) if row[0] == VIEWED_EVENT] == [(VIEWED_EVENT, None, "alice")]


def test_every_backend_validates_through_the_shared_check() -> None:
    """The refusal lives in ONE function so the three backends cannot drift. This pins that each
    backend's ``record_message_event`` calls it rather than an inline copy."""
    import ast

    from messagefoundry.store.store import check_caller_event_kind

    with pytest.raises(ValueError, match="written only by the store"):
        check_caller_event_kind("viewed")
    root = Path(__file__).resolve().parents[1] / "messagefoundry" / "store"
    for name in ("store.py", "postgres.py", "sqlserver.py"):
        tree = ast.parse((root / name).read_text(encoding="utf-8"))
        methods = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.AsyncFunctionDef) and n.name == "record_message_event"
        ]
        assert len(methods) == 1, name
        called = {
            c.func.id
            for c in ast.walk(methods[0])
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
        }
        assert "check_caller_event_kind" in called, name
