# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract for the queue payload's routing tag (BACKLOG #2593).

Extra-free, on the ``_session_seal_contract`` precedent: it imports nothing optional, so the live
Postgres and SQL Server suites import it inside their test functions and run the same assertions on
legs that install only their own driver extra.

The caller passes a store opened with a store key under the cell-bound writer (``write_v2=True``),
and two adapters for the same database that bypass the store: ``raw`` runs one statement and commits,
and ``fetch`` runs one query and returns its rows as dicts. Both take SQL written with ``?``
placeholders; each backend's adapter respells them for its driver.

Every refused row has a control beside it: the same kind of row, left alone, is delivered. A tag that
refused everything, or bound nothing, fails this contract.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from messagefoundry.store.queue_tag import QUEUE_TAG_FAILED_ACTION
from messagefoundry.store.store import MessageStatus, OutboxStatus, Stage

#: Runs one statement with ``?`` placeholders against the store's database, outside the store.
RawSql = Callable[[str, tuple[Any, ...]], Awaitable[None]]
#: Runs one query with ``?`` placeholders outside the store and returns its rows as dicts.
RawFetch = Callable[[str, tuple[Any, ...]], Awaitable[list[dict[str, Any]]]]

_RAW = "MSH|^~\\&|SYNTH|F|R|RF|20260101||ADT^A01|QT1|P|2.5.1\rPID|1||SYNTH-100||DOE^JANE\r"


class _Hook:
    """Records each tag-failure alert the store's cipher raises."""

    def __init__(self) -> None:
        self.reasons: list[str] = []

    def __call__(self, table: str, reason: str) -> None:
        assert table == "queue"
        self.reasons.append(reason)


async def _row_id(fetch: RawFetch, message_id: str, stage: str) -> str:
    rows = await fetch("SELECT id FROM queue WHERE message_id=? AND stage=?", (message_id, stage))
    assert len(rows) == 1, rows
    return str(rows[0]["id"])


async def _status(fetch: RawFetch, row_id: str) -> tuple[str, str | None]:
    rows = await fetch("SELECT status, payload FROM queue WHERE id=?", (row_id,))
    assert len(rows) == 1, rows
    return str(rows[0]["status"]), rows[0]["payload"]


async def _assert_refused(
    store: Any, fetch: RawFetch, hook: _Hook, *, message_id: str, row_id: str, label: str
) -> None:
    """The row is dead, its error says integrity, the message is ERROR, and it was audited and
    alerted once."""
    status, _ = await _status(fetch, row_id)
    assert status == OutboxStatus.DEAD.value, (label, status)
    outbox = {r["id"]: r for r in await store.outbox_for(message_id)}
    if row_id in outbox:  # outbound rows only; outbox_for lists no ingress or routed row
        assert "integrity" in str(outbox[row_id]["last_error"]), (label, outbox[row_id])
    message = await store.get_message(message_id)
    assert message is not None and message["status"] == MessageStatus.ERROR.value, (label, message)
    audited = await fetch(
        "SELECT detail FROM audit_log WHERE action=? AND detail LIKE ?",
        (QUEUE_TAG_FAILED_ACTION, f"%{row_id[:12]}%"),
    )
    assert len(audited) == 1, (label, audited)
    assert any(row_id[:12] in reason for reason in hook.reasons), (label, hook.reasons)


async def _outbound(store: Any, fetch: RawFetch, lane: str, body: str) -> tuple[str, str]:
    mid = await store.enqueue_message(channel_id="IB_QT", raw=_RAW, deliveries=[(lane, body)])
    return mid, await _row_id(fetch, mid, Stage.OUTBOUND.value)


async def assert_queue_tag_contract(
    store: Any, raw: RawSql, fetch: RawFetch, *, store_once: bool, claim_reads_body_ref: bool = True
) -> None:
    """Drive the queue tag through its whole contract on ``store``'s backend.

    ``store_once`` is True on a backend that writes shared-body fan-out rows (SQLite today).
    ``claim_reads_body_ref`` is False on a backend whose claim output carries no ``body_ref`` (SQL
    Server): its claims build the inline tag and deliver only the row's own body."""
    cipher = store.cipher()
    assert cipher.encrypts, "the contract needs a store opened with a store key"
    hook = _Hook()
    cipher.set_tag_failure_hook(hook)

    # --- control: an untouched outbound row delivers on its own lane, and only there ----------
    mid, rid = await _outbound(store, fetch, "OB_QT_A", "SYNTH-BODY-A")
    assert await store.claim_next_fifo("OB_QT_B") is None
    item = await store.claim_next_fifo("OB_QT_A")
    assert item is not None and item.id == rid and item.payload == "SYNTH-BODY-A"

    # --- a destination changed outside the store is not delivered to the new destination -------
    mid, rid = await _outbound(store, fetch, "OB_QT_C", "SYNTH-BODY-C")
    await raw("UPDATE queue SET destination_name=? WHERE id=?", ("OB_QT_D", rid))
    assert await store.claim_next_fifo("OB_QT_D") is None
    await _assert_refused(store, fetch, hook, message_id=mid, row_id=rid, label="destination")
    # The body view leaves the refused, dead row out rather than failing the whole read.
    assert all(v["id"] != rid for v in await store.outbox_payloads_for(mid))
    # The lane keeps moving: the next row on it delivers.
    _, nxt = await _outbound(store, fetch, "OB_QT_D", "SYNTH-BODY-D")
    item = await store.claim_next_fifo("OB_QT_D")
    assert item is not None and item.id == nxt and item.payload == "SYNTH-BODY-D"

    # --- the body view refuses a live row whose tag fails, and alerts --------------------------
    mid, rid = await _outbound(store, fetch, "OB_QT_V", "SYNTH-BODY-V")
    views = await store.outbox_payloads_for(mid)
    assert [v["payload"] for v in views] == ["SYNTH-BODY-V"]  # control
    await raw("UPDATE queue SET destination_name=? WHERE id=?", ("OB_QT_W", rid))
    try:
        await store.outbox_payloads_for(mid)
    except Exception as exc:  # noqa: BLE001 -- the refusal type is the cipher's, asserted below
        assert "integrity" in str(exc), exc
    else:
        raise AssertionError("a body view of a row whose tag fails was not refused")
    assert any(rid[:12] in reason for reason in hook.reasons)

    # --- a message_id moved onto another message is refused ------------------------------------
    other, _ = await _outbound(store, fetch, "OB_QT_E0", "SYNTH-BODY-E0")
    mid, rid = await _outbound(store, fetch, "OB_QT_E", "SYNTH-BODY-E")
    await raw("UPDATE queue SET message_id=? WHERE id=?", (other, rid))
    assert await store.claim_next_fifo("OB_QT_E") is None
    status, _ = await _status(fetch, rid)
    assert status == OutboxStatus.DEAD.value

    # --- control: swapping two rows' ciphertext still dead-letters both ------------------------
    mid1, r1 = await _outbound(store, fetch, "OB_QT_F", "SYNTH-BODY-F1")
    mid2, r2 = await _outbound(store, fetch, "OB_QT_F", "SYNTH-BODY-F2")
    _, p1 = await _status(fetch, r1)
    _, p2 = await _status(fetch, r2)
    await raw("UPDATE queue SET payload=? WHERE id=?", (p2, r1))
    await raw("UPDATE queue SET payload=? WHERE id=?", (p1, r2))
    assert await store.claim_next_fifo("OB_QT_F") is None
    assert await store.claim_next_fifo("OB_QT_F") is None
    await _assert_refused(store, fetch, hook, message_id=mid1, row_id=r1, label="swap 1")
    await _assert_refused(store, fetch, hook, message_id=mid2, row_id=r2, label="swap 2")

    # --- an ingress row moved to another inbound is not routed there ---------------------------
    ctl = await store.enqueue_ingress(channel_id="IB_QT_G", raw=_RAW)
    item = await store.claim_next_fifo("IB_QT_G", stage=Stage.INGRESS.value)
    assert item is not None and item.message_id == ctl and item.payload == _RAW  # control
    mid = await store.enqueue_ingress(channel_id="IB_QT_H", raw=_RAW)
    rid = await _row_id(fetch, mid, Stage.INGRESS.value)
    await raw("UPDATE queue SET channel_id=? WHERE id=?", ("IB_QT_I", rid))
    assert await store.claim_next_fifo("IB_QT_I", stage=Stage.INGRESS.value) is None
    await _assert_refused(store, fetch, hook, message_id=mid, row_id=rid, label="channel")

    # --- an ingress row moved to the routed stage is refused -----------------------------------
    mid = await store.enqueue_ingress(channel_id="IB_QT_J", raw=_RAW)
    rid = await _row_id(fetch, mid, Stage.INGRESS.value)
    await raw("UPDATE queue SET stage=?, handler_name=? WHERE id=?", ("routed", "H_QT", rid))
    assert await store.claim_next_fifo("IB_QT_J", stage=Stage.ROUTED.value) is None
    await _assert_refused(store, fetch, hook, message_id=mid, row_id=rid, label="stage")

    # --- a routed row pointed at another handler is refused ------------------------------------
    mid = await store.enqueue_ingress(channel_id="IB_QT_K", raw=_RAW)
    ingress = await store.claim_next_fifo("IB_QT_K", stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB_QT_K",
        handlers=[("H_QT_1", _RAW)],
        disposition=MessageStatus.ROUTED,
    )
    rid = await _row_id(fetch, mid, Stage.ROUTED.value)
    await raw("UPDATE queue SET handler_name=? WHERE id=?", ("H_QT_2", rid))
    assert await store.claim_next_fifo("IB_QT_K", stage=Stage.ROUTED.value) is None
    await _assert_refused(store, fetch, hook, message_id=mid, row_id=rid, label="handler")

    # --- a row inserted outside the store, with no sealed payload, is never delivered ----------
    mid, rid = await _outbound(store, fetch, "OB_QT_L0", "SYNTH-BODY-L0")
    _, sealed = await _status(fetch, rid)
    for new_id, payload, body_ref in (
        ("qt-planted-blank", "", "0" * 64),
        ("qt-planted-copy", sealed, None),
    ):
        await raw(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, payload,"
            " body_ref, status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,0,?,?,?)",
            (
                new_id,
                mid,
                Stage.OUTBOUND.value,
                "IB_QT",
                "OB_QT_L",
                payload,
                body_ref,
                OutboxStatus.PENDING.value,
                0.0,
                0.0,
                0.0,
            ),
        )
        assert await store.claim_next_fifo("OB_QT_L") is None
        status, _ = await _status(fetch, new_id)
        assert status == OutboxStatus.DEAD.value, new_id

    # --- a body_ref set on an inline row never reaches another body ---------------------------
    mid, rid = await _outbound(store, fetch, "OB_QT_M", "SYNTH-BODY-M")
    await raw("UPDATE queue SET body_ref=? WHERE id=?", ("1" * 64, rid))
    if claim_reads_body_ref:
        assert await store.claim_next_fifo("OB_QT_M") is None
        await _assert_refused(store, fetch, hook, message_id=mid, row_id=rid, label="body_ref")
    else:
        # This backend's claims never read body_ref, so the row delivers its own sealed body to
        # its own destination, and nothing else. The resend source below still refuses it.
        item = await store.claim_next_fifo("OB_QT_M")
        assert item is not None and item.id == rid and item.payload == "SYNTH-BODY-M"

    mid, rid = await _outbound(store, fetch, "OB_QT_N", "SYNTH-BODY-N")
    item = await store.claim_next_fifo("OB_QT_N")
    assert item is not None
    await store.mark_done(rid)
    outcome = await store.resend_to(
        message_id=mid, to="OB_QT_N2", from_="OB_QT_N", idempotency_key="qt-resend-ctl"
    )
    assert outcome.status == "resent"  # control: the untouched source resends
    await raw("UPDATE queue SET body_ref=? WHERE id=?", ("2" * 64, rid))
    try:
        await store.resend_to(
            message_id=mid, to="OB_QT_N3", from_="OB_QT_N", idempotency_key="qt-resend-bent"
        )
    except Exception as exc:  # noqa: BLE001 -- the refusal type is the cipher's, asserted below
        assert "integrity" in str(exc), exc
    else:
        raise AssertionError("a resend from a source with a changed body_ref was not refused")
    # A blank payload that still names a shared body is not what retention leaves (it nulls
    # body_ref in the same write), so a resend refuses it rather than reporting a purged body.
    await raw("UPDATE queue SET payload='' WHERE id=?", (rid,))
    try:
        await store.resend_to(
            message_id=mid, to="OB_QT_N4", from_="OB_QT_N", idempotency_key="qt-resend-blank"
        )
    except Exception as exc:  # noqa: BLE001 -- the refusal type is the cipher's, asserted below
        assert "integrity" in str(exc), exc
    else:
        raise AssertionError("a resend from a blank source that names a shared body went ahead")

    # --- control: a dead-lettered row whose tag is intact replays and delivers ----------------
    mid, rid = await _outbound(store, fetch, "OB_QT_O", "SYNTH-BODY-O")
    item = await store.claim_next_fifo("OB_QT_O")
    assert item is not None
    await store.dead_letter_now(rid, "synthetic permanent reject")
    assert await store.replay(mid) == 1
    item = await store.claim_next_fifo("OB_QT_O")
    assert item is not None and item.id == rid and item.payload == "SYNTH-BODY-O"

    if store_once:
        await _assert_store_once(store, raw, fetch, hook)


async def _assert_store_once(store: Any, raw: RawSql, fetch: RawFetch, hook: _Hook) -> None:
    """The fan-out half: a shared-body row's sealed reference decides which body it reads."""
    # Two messages, each fanned out to two lanes, so each has its own shared body.
    m1 = await store.enqueue_message(
        channel_id="IB_QT",
        raw=_RAW,
        deliveries=[("OB_QT_P1", "SYNTH-SHARED-1"), ("OB_QT_P2", "SYNTH-SHARED-1")],
    )
    m2 = await store.enqueue_message(
        channel_id="IB_QT",
        raw=_RAW,
        deliveries=[("OB_QT_Q1", "SYNTH-SHARED-2"), ("OB_QT_Q2", "SYNTH-SHARED-2")],
    )
    rows1 = await fetch(
        "SELECT id, destination_name, body_ref, payload FROM queue WHERE message_id=?", (m1,)
    )
    rows2 = await fetch("SELECT id, body_ref FROM queue WHERE message_id=?", (m2,))
    by_lane = {r["destination_name"]: r for r in rows1}
    ref1, ref2 = by_lane["OB_QT_P1"]["body_ref"], rows2[0]["body_ref"]
    assert ref1 is not None and ref2 is not None and ref1 != ref2
    assert by_lane["OB_QT_P1"]["payload"] != ""  # the reference is sealed, not a blank sentinel

    # Control: an untouched fan-out row delivers its own shared body.
    item = await store.claim_next_fifo("OB_QT_P2")
    assert item is not None and item.payload == "SYNTH-SHARED-1"
    await store.mark_done(item.id)  # so the message's disposition settles once its sibling does

    # A fan-out row re-pointed at another message's shared body is refused.
    bent = by_lane["OB_QT_P1"]["id"]
    await raw("UPDATE queue SET body_ref=? WHERE id=?", (ref2, bent))
    assert await store.claim_next_fifo("OB_QT_P1") is None
    await _assert_refused(store, fetch, hook, message_id=m1, row_id=bent, label="re-pointed ref")

    # A new row naming an existing shared body is refused, blank or carrying a copied reference.
    sealed = by_lane["OB_QT_P1"]["payload"]
    for new_id, payload in (("qt-fanout-blank", ""), ("qt-fanout-copy", sealed)):
        await raw(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, payload,"
            " body_ref, status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,0,?,?,?)",
            (
                new_id,
                m2,
                Stage.OUTBOUND.value,
                "IB_QT",
                "OB_QT_R",
                payload,
                ref2,
                OutboxStatus.PENDING.value,
                0.0,
                0.0,
                0.0,
            ),
        )
        assert await store.claim_next_fifo("OB_QT_R") is None
        status, _ = await _status(fetch, new_id)
        assert status == OutboxStatus.DEAD.value, new_id

    # Control: the other message's own fan-out rows still deliver their own body.
    item = await store.claim_next_fifo("OB_QT_Q1")
    assert item is not None and item.payload == "SYNTH-SHARED-2"
