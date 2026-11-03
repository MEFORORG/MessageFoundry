# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A document handle a sender wrote never resolves, and never holds a lane (BACKLOG #5099).

Only the engine's ingress detach writes a live ``mfdoc:v1:ref:`` handle (ADR 0105). These tests
pin what happens to one that arrives some other way:

* a handle the sender put in ``OBX-5.5`` of a streaming inbound's body is refused at the detach,
  before the ACK, with an ``ERROR`` row and an ``AR``, rather than skipped as already detached;
* at delivery a handle resolves only to an attachment its own message holds, so a well-formed
  handle naming another message's document is refused, and that document is never delivered;
* a handle delivery cannot resolve, malformed or unbound, is a permanent refusal of that row alone,
  so it dead-letters at once rather than re-pending on a strict-FIFO lane;
* a payload whose MSH-2 escapes the engine's own handle is re-attached, not sent with it;
* a handle a Handler copied into ``NTE-3`` or a second ``OBX-5.5`` repetition is refused;
* a ``mfdoc:v1:pruned:`` tombstone the sender wrote resolves nothing and is carried as text.

Synthetic HL7 only.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from messagefoundry.config.models import (
    AckMode,
    ConnectorType,
    ContentType,
    RetryPolicy,
    Validation,
)
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing.binary import (
    DOC_REF_MARKER,
    DOC_TOMBSTONE_MARKER,
    InboundDocRefError,
    chunk_b64,
    is_doc_ref,
    iter_obx_documents,
    make_doc_ref,
    may_hold_doc_ref,
    parse_doc_ref,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus

DEST = "OB_PARTNER"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "handle.db")
    yield s
    await s.close()


def _b64(nbytes: int, fill: bytes = b"P") -> str:
    return base64.b64encode(fill * nbytes).decode("ascii")


def _hl7(obx5_5: str, *, msh2: str = "^~\\&") -> str:
    """A minimal synthetic MDM^T02 with one OBX-5 ED Base64 value, in the delimiters ``msh2``
    names. The OBX-5 components are joined with that MSH-2's component separator."""
    comp = msh2[0]
    obx5 = comp.join(["", "Application", "PDF", "Base64", obx5_5])
    return (
        f"MSH|{msh2}|APP|FAC|RCV|RCVF|20260101120000||MDM{comp}T02|MSGID001|P|2.5\r"
        "EVN|T02|20260101120000\r"
        f"OBX|1|ED|PDF||{obx5}||||||F\r"
    )


def _streaming_ic() -> InboundConnection:
    return InboundConnection(
        name="IB_STREAM",
        spec=ConnectionSpec(ConnectorType.MLLP, {"port": 0}),
        router="r",
        ack_mode=AckMode.ORIGINAL,
        content_type=ContentType.HL7V2,
        validation=Validation(strict=False),
        stream_threshold_bytes=500,
    )


def _runner(store: MessageStore, ic: InboundConnection | None = None) -> RegistryRunner:
    reg = Registry()
    if ic is not None:
        reg.add_inbound(ic)
        reg.add_router(ic.router, lambda m: [])
    return RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))


def _ack_code(ack: str | None) -> str | None:
    if ack is None:
        return None
    for seg in ack.replace("\n", "\r").split("\r"):
        if seg.startswith("MSA|"):
            return seg.split("|")[1]
    return None


class _Collector:
    def __init__(self) -> None:
        self.deliveries: list[str] = []

    async def send(self, payload: str) -> None:
        self.deliveries.append(payload)

    async def aclose(self) -> None:
        return None


async def _held_document(store: MessageStore, b64: str) -> tuple[str, str]:
    """Store ``b64`` as an attachment that one message holds, as the ingress commit links it.
    Returns ``(message_id, ref)``."""
    ref = await store.put_attachment(chunk_b64(b64), "application/pdf")
    mid = await store.enqueue_ingress(
        channel_id="IB_OTHER", raw=_hl7(make_doc_ref(ref, "Application")), attachment_refs=[ref]
    )
    return mid, ref


async def _deliver(store: MessageStore, runner: RegistryRunner, payload: str) -> tuple[str, list]:
    """Queue ``payload`` as its own message's one outbound row, deliver it once, and return
    ``(message_id, outbound rows)``."""
    mid = await store.enqueue_message(
        channel_id="IB_SENDER", raw=payload, deliveries=[(DEST, payload)], now=100.0
    )
    await _deliver_queued(store, runner, mid)
    return mid, list(await store.outbox_for(mid))


def _dead_lettered_at_once(rows: list) -> bool:
    return [str(r["status"]) for r in rows] == [OutboxStatus.DEAD.value]


# --- closing step 1: refused at the detach, and bound to its own message at delivery ----------


async def test_a_handle_in_a_streaming_body_is_refused_at_the_detach_with_ar(
    store: MessageStore,
) -> None:
    _other, ref = await _held_document(store, _b64(2000))
    body = _hl7(make_doc_ref(ref, "Application")) + "NTE|1||" + "x" * 600 + "\r"
    ic = _streaming_ic()
    runner = _runner(store, ic)

    ack = await runner._handle_inbound(ic, body.encode("utf-8"))

    assert _ack_code(ack) == "AR"
    cur = await store._db.execute(
        "SELECT status, error FROM messages WHERE channel_id=?", (ic.name,)
    )
    rows = [dict(r) for r in await cur.fetchall()]
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]
    assert "already holds a document handle" in rows[0]["error"]
    assert ref not in rows[0]["error"]  # the refusal names the OBX, never the value


async def test_the_http_listener_refuses_a_handle_in_a_streaming_body_too(
    store: MessageStore,
) -> None:
    _other, ref = await _held_document(store, _b64(2000))
    body = _hl7(make_doc_ref(ref, "Application")) + "NTE|1||" + "x" * 600 + "\r"
    ic = _streaming_ic()
    runner = _runner(store, ic)

    receipt = await runner._handle_inbound_http(ic, body.encode("utf-8"))

    assert receipt.refusal is not None
    cur = await store._db.execute("SELECT status FROM messages WHERE channel_id=?", (ic.name,))
    assert [r["status"] for r in await cur.fetchall()] == [MessageStatus.ERROR.value]


def test_the_detach_scan_refuses_a_handle_in_any_obx_not_only_an_ed_one() -> None:
    handle = make_doc_ref(hashlib.sha256(b"x").hexdigest(), "Application")
    text = _hl7(_b64(10)) + f"OBX|2|TX|NOTE||^^^^{handle}||||||F\r"
    with pytest.raises(InboundDocRefError):
        list(iter_obx_documents(Message.parse(text)))


async def test_a_handle_naming_another_messages_document_is_never_delivered(
    store: MessageStore,
) -> None:
    secret = _b64(1500, b"S")
    _other, ref = await _held_document(store, secret)
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    _mid, rows = await _deliver(store, runner, _hl7(make_doc_ref(ref, "Application")))

    assert col.deliveries == []
    assert all(secret not in str(r["last_error"]) for r in rows)
    assert _dead_lettered_at_once(rows)


async def test_a_handle_its_own_message_holds_still_resolves(store: MessageStore) -> None:
    """The control for the binding: the engine's own detach round-trips through delivery."""
    doc = _b64(2000)
    ic = _streaming_ic()
    runner = _runner(store, ic)
    assert _ack_code(await runner._handle_inbound(ic, _hl7(doc).encode("utf-8"))) == "AA"
    cur = await store._db.execute("SELECT raw FROM messages WHERE channel_id=?", (ic.name,))
    row = await cur.fetchone()
    assert row is not None
    skeleton = str(row[0])
    obx5_5 = Message.parse(skeleton).field("OBX-5.5") or ""
    assert is_doc_ref(obx5_5)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    await _deliver_holding(store, runner, skeleton, parse_doc_ref(obx5_5)[0])

    assert [Message.parse(d).field("OBX-5.5") for d in col.deliveries] == [doc]


# --- closing step 2: an unresolvable sender handle does not hold the lane --------------------


@pytest.mark.parametrize(
    "value",
    [
        DOC_REF_MARKER + "not-a-content-address:Application",
        make_doc_ref(hashlib.sha256(b"never stored").hexdigest(), "Application"),
    ],
    ids=["malformed", "unknown-address"],
)
async def test_an_unresolvable_sender_handle_dead_letters_at_once(
    store: MessageStore, value: str
) -> None:
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]
    runner._retry[DEST] = RetryPolicy(max_attempts=50, backoff_seconds=60.0)

    _mid, rows = await _deliver(store, runner, _hl7(value))

    assert col.deliveries == []
    # Dead-lettered on the first attempt, not re-pended behind a 60 s backoff holding the lane.
    assert _dead_lettered_at_once(rows)
    assert "document re-attach failed" in str(rows[0]["last_error"])


# --- closing step 3: the MSH-2 ':' fail-open and the copied-handle cases ----------------------


def test_the_gate_opens_when_msh2_escapes_the_marker() -> None:
    handle = make_doc_ref(hashlib.sha256(b"x").hexdigest(), "Application")
    msg = Message.parse(_hl7(_b64(10), msh2=":~\\&"))
    msg.set("OBX-5.5", handle)
    skeleton = msg.encode()
    assert DOC_REF_MARKER not in skeleton  # the engine's own handle is escaped here
    assert may_hold_doc_ref(skeleton)
    assert not may_hold_doc_ref(_hl7(_b64(10)))


async def test_a_handle_escaped_by_msh2_is_reattached_not_sent(store: MessageStore) -> None:
    doc = _b64(1200)
    ref = await store.put_attachment(chunk_b64(doc), "application/pdf")
    msg = Message.parse(_hl7(_b64(10), msh2=":~\\&"))
    msg.set("OBX-5.5", make_doc_ref(ref, "Application"))
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    await _deliver_holding(store, runner, msg.encode(), ref)

    assert len(col.deliveries) == 1
    assert Message.parse(col.deliveries[0]).field("OBX-5.5") == doc
    assert "mfdoc" not in col.deliveries[0]


async def _deliver_holding(
    store: MessageStore, runner: RegistryRunner, payload: str, ref: str
) -> list:
    """Queue ``payload`` as a message that holds ``ref``, linked by the ingress commit itself as the
    detach links a document, route and transform it to ``DEST``, deliver that row once, and return
    its outbound rows."""
    mid = await store.enqueue_ingress(channel_id="IB_HOLDER", raw=payload, attachment_refs=[ref])
    await _route_to_dest(store, mid, "IB_HOLDER", payload)
    await _deliver_queued(store, runner, mid)
    return list(await store.outbox_for(mid))


async def _route_to_dest(
    store: MessageStore, mid: str, channel: str, body: str, *, into_pt: str | None = None
) -> None:
    """Drain ``mid``'s ingress row through the router and transform stages to one ``DEST`` row,
    or, with ``into_pt``, into that pass-through inbound as a Handler's ``Send`` does."""
    ingress = await store.claim_next_fifo(channel, stage="ingress")
    assert ingress is not None and ingress.message_id == mid
    assert await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id=channel,
        handlers=[("h", body)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo(channel, stage="routed")
    assert routed is not None and routed.message_id == mid
    await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id=channel,
        deliveries=[] if into_pt else [(DEST, body)],
        pt_deliveries=[(into_pt, body)] if into_pt else [],
    )


def _with_copy_in_nte(skeleton: str, handle: str) -> str:
    msg = Message.parse(skeleton)
    msg.add_segment("NTE|1")
    msg.set("NTE-3", handle)
    return msg.encode()


def _with_copy_in_second_repetition(skeleton: str, handle: str) -> str:
    msg = Message.parse(skeleton)
    msg.set("OBX-5.5", handle, repetition=2)
    return msg.encode()


@pytest.mark.parametrize(
    "copy", [_with_copy_in_nte, _with_copy_in_second_repetition], ids=["nte-3", "obx-5.5-rep-2"]
)
async def test_a_copied_handle_is_refused_never_sent(store: MessageStore, copy) -> None:
    doc = _b64(1200)
    ref = await store.put_attachment(chunk_b64(doc), "application/pdf")
    handle = make_doc_ref(ref, "Application")
    skeleton = copy(_hl7(handle), handle)
    assert skeleton.count(DOC_REF_MARKER) == 2
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    rows = await _deliver_holding(store, runner, skeleton, ref)

    assert col.deliveries == []
    assert _dead_lettered_at_once(rows)


async def test_a_sender_tombstone_resolves_nothing_and_rides_as_text(store: MessageStore) -> None:
    tombstone = f"{DOC_TOMBSTONE_MARKER}100:Application:20260101T000000Z"
    body = _hl7(tombstone) + "NTE|1||" + "x" * 600 + "\r"
    ic = _streaming_ic()
    runner = _runner(store, ic)
    assert _ack_code(await runner._handle_inbound(ic, body.encode("utf-8"))) == "AA"
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    _mid, _rows = await _deliver(store, runner, body)

    assert col.deliveries == [body]


# --- a child the engine makes holds the documents its body names ------------------------------
#
# A pass-through child, an edit-and-resubmit child and an edit-and-resend child each carry an
# earlier message's skeleton under a NEW message id. The binding resolves a handle only against
# the row's own message, so each child must hold the documents its body names, or every detached
# document routed through such a path dead-letters at delivery.


async def _detached_parent(store: MessageStore, doc: str) -> tuple[str, str, str]:
    """A message the ingress detach made: it holds ``doc`` as an attachment and its raw is the
    skeleton. Returns ``(message_id, ref, skeleton)``."""
    ref = await store.put_attachment(chunk_b64(doc), "application/pdf")
    skeleton = _hl7(make_doc_ref(ref, "Application"))
    mid = await store.enqueue_ingress(channel_id="IB_STREAM", raw=skeleton, attachment_refs=[ref])
    return mid, ref, skeleton


async def _refcount(store: MessageStore, ref: str) -> int | None:
    cur = await store._db.execute("SELECT refcount FROM attachment WHERE id=?", (ref,))
    row = await cur.fetchone()
    return None if row is None else int(row[0])


async def _deliver_queued(store: MessageStore, runner: RegistryRunner, message_id: str) -> None:
    item = await store.claim_next_fifo(DEST)
    assert item is not None and item.message_id == message_id
    await runner._process_delivery_item(DEST, item)


async def _passthrough_child(store: MessageStore, parent: str, body: str) -> str:
    """Hand ``body`` from ``parent`` into a pass-through inbound, as a Handler's ``Send`` does,
    then route and transform the child to ``DEST``. Returns the child's message id."""
    await _route_to_dest(store, parent, "IB_STREAM", body, into_pt="PT_NEXT")
    children = await store.list_messages(channel_id="PT_NEXT", allowed_channels=None)
    assert len(children) == 1
    child = str(children[0]["id"])
    await _route_to_dest(store, child, "PT_NEXT", body)
    return child


async def test_a_passthrough_child_delivers_the_document_its_parent_detached(
    store: MessageStore,
) -> None:
    doc = _b64(1500)
    parent, ref, skeleton = await _detached_parent(store, doc)
    child = await _passthrough_child(store, parent, skeleton)
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    await _deliver_queued(store, runner, child)

    assert [Message.parse(d).field("OBX-5.5") for d in col.deliveries] == [doc]
    assert [r["attachment_id"] for r in await store.attachments_for(child)] == [ref]


async def test_a_child_holds_its_own_reference_so_either_purge_keeps_the_count(
    store: MessageStore,
) -> None:
    parent, ref, skeleton = await _detached_parent(store, _b64(1500))
    child = await _passthrough_child(store, parent, skeleton)
    assert await _refcount(store, ref) == 2

    await store.release_message_attachments(parent)
    assert await _refcount(store, ref) == 1  # the child still holds the document
    assert [r["attachment_id"] for r in await store.attachments_for(child)] == [ref]

    await store.release_message_attachments(child)
    assert await _refcount(store, ref) is None  # the last holder gone, the document is collected


async def test_a_passthrough_child_holds_only_the_documents_its_body_names(
    store: MessageStore,
) -> None:
    parent, _ref, _skeleton = await _detached_parent(store, _b64(1500))
    # The Handler dropped the document: the child's body names none, so the child holds none.
    child = await _passthrough_child(store, parent, _hl7("plain text"))
    assert list(await store.attachments_for(child)) == []


async def test_an_edit_and_resubmit_child_holds_only_the_document_its_obx_names(
    store: MessageStore,
) -> None:
    from tests._store_audit import no_operator_audit

    ref = await store.put_attachment(chunk_b64(_b64(1500)), "application/pdf")
    other = await store.put_attachment(chunk_b64(_b64(1500, b"S")), "application/pdf")
    skeleton = _hl7(make_doc_ref(ref, "Application"))
    origin = await store.enqueue_ingress(
        channel_id="IB_STREAM", raw=skeleton, attachment_refs=[ref, other]
    )
    # The origin holds both. The operator's body names ``other`` only as text outside OBX-5.5,
    # which delivery never resolves, so the child must not hold it.
    edited = skeleton + f"NTE|1||{other}\r"

    outcome = await store.reingress(
        origin_message_id=origin, raw=edited, idempotency_key="k-5099", audit=no_operator_audit
    )

    assert outcome.status == "resubmitted"
    assert [r["attachment_id"] for r in await store.attachments_for(outcome.new_message_id)] == [
        ref
    ]
    assert await _refcount(store, other) == 1  # the origin's reference alone


async def test_a_child_holds_no_document_its_body_names_outside_obx_5_5(
    store: MessageStore,
) -> None:
    """A content address the sender knows, written bare or as a copied handle into a field the
    Handler passes through, names nothing delivery resolves, so the child must not hold it: its
    channel could then download a document the Handler dropped."""
    parent, ref, _skeleton = await _detached_parent(store, _b64(1500))
    handle = make_doc_ref(ref, "Application")
    body = _with_copy_in_nte(_hl7("plain text") + f"NTE|1||{ref}\r", handle)

    child = await _passthrough_child(store, parent, body)

    assert list(await store.attachments_for(child)) == []
    assert await _refcount(store, ref) == 1


def test_a_child_inherits_a_handle_its_delimiters_escape() -> None:
    from messagefoundry.store.store import attachments_named

    ref = hashlib.sha256(b"x").hexdigest()
    msg = Message.parse(_hl7(_b64(10), msh2=":~\\&"))
    msg.set("OBX-5.5", make_doc_ref(ref, "Application"))
    escaped = msg.encode()
    assert DOC_REF_MARKER not in escaped

    assert attachments_named([ref], escaped) == [ref]
    assert attachments_named([ref], _hl7("plain") + f"NTE|1||{ref}\r") == []
    assert attachments_named([ref], f'{{"doc": "{make_doc_ref(ref, "x")}"}}') == []


async def test_a_child_links_no_document_whose_header_a_purge_collected(
    store: MessageStore,
) -> None:
    """The parent's linkage row was read, then a purge collected the header before the incref. A
    link to no header would leave refcount below the live linkage rows."""
    from tests._store_audit import no_operator_audit

    origin, ref, skeleton = await _detached_parent(store, _b64(1500))
    await store._db.execute("DELETE FROM attachment_chunk WHERE attachment_id=?", (ref,))
    await store._db.execute("DELETE FROM attachment WHERE id=?", (ref,))
    await store._db.commit()

    outcome = await store.resend_to(
        message_id=origin,
        to=DEST,
        idempotency_key="k-5099-gone",
        body_override=skeleton,
        audit=no_operator_audit,
    )

    assert outcome.status == "resent" and outcome.new_message_id is not None
    cur = await store._db.execute(
        "SELECT COUNT(*) FROM message_attachment WHERE message_id=?", (outcome.new_message_id,)
    )
    row = await cur.fetchone()
    assert row is not None and int(row[0]) == 0


async def test_an_edit_and_resend_child_delivers_the_origins_document(
    store: MessageStore,
) -> None:
    from tests._store_audit import no_operator_audit

    doc = _b64(1500)
    origin, ref, skeleton = await _detached_parent(store, doc)
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    outcome = await store.resend_to(
        message_id=origin,
        to=DEST,
        idempotency_key="k-5099-direct",
        body_override=skeleton,
        audit=no_operator_audit,
    )
    item = await store.claim_next_fifo(DEST)
    assert item is not None and item.message_id != origin
    await runner._process_delivery_item(DEST, item)

    assert outcome.status == "resent"
    assert [Message.parse(d).field("OBX-5.5") for d in col.deliveries] == [doc]


# --- review findings on the gate, the copied-handle guard and an empty read --------------------


def _batch(msh2: str, obx5_5: str) -> str:
    """An FHS/BHS-led batch whose header keeps the default delimiters while its one MSH names
    ``msh2``. ``Message.set`` escapes a value by the MSH's delimiters, not the batch header's."""
    return (
        "FHS|^~\\&|APP|FAC|RCV|RCVF|20260101120000\r"
        "BHS|^~\\&|APP|FAC|RCV|RCVF|20260101120000\r" + _hl7(obx5_5, msh2=msh2)
    )


def test_the_gate_opens_when_a_batch_msh2_escapes_the_marker() -> None:
    handle = make_doc_ref(hashlib.sha256(b"x").hexdigest(), "Application")
    msg = Message.parse(_batch(":~\\&", _b64(10)))
    msg.set("OBX-5.5", handle)
    payload = msg.encode()
    assert payload.startswith("FHS")
    assert DOC_REF_MARKER not in payload  # the engine's own handle is escaped here
    assert may_hold_doc_ref(payload)
    assert not may_hold_doc_ref(_batch("^~\\&", _b64(10)))


async def test_a_hex_escaped_handle_cannot_offset_a_copy_left_live(store: MessageStore) -> None:
    """The copy guard compared marker counts, so a handle written with hex escapes, which the
    parser reads as a handle but the raw text does not hold as the marker, let one literal copy
    elsewhere pass and reach the wire after the splice."""
    doc = _b64(1200)
    ref = await store.put_attachment(chunk_b64(doc), "application/pdf")
    handle = make_doc_ref(ref, "Application")
    hexed = "\\X" + DOC_REF_MARKER[:1].encode("ascii").hex().upper() + "\\" + handle[1:]
    payload = _hl7(hexed) + f"NTE|1||{handle}\r"
    assert payload.count(DOC_REF_MARKER) == 1
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    rows = await _deliver_holding(store, runner, payload, ref)

    assert all(DOC_REF_MARKER not in d for d in col.deliveries)
    assert col.deliveries == []
    assert _dead_lettered_at_once(rows)


async def test_a_held_document_whose_chunks_are_gone_is_never_sent_empty(
    store: MessageStore,
) -> None:
    doc = _b64(1200)
    ref = await store.put_attachment(chunk_b64(doc), "application/pdf")
    await store._db.execute("DELETE FROM attachment_chunk WHERE attachment_id=?", (ref,))
    await store._db.commit()
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    rows = await _deliver_holding(store, runner, _hl7(make_doc_ref(ref, "Application")), ref)

    assert col.deliveries == []  # never an empty OBX-5.5 on the wire
    assert [str(r["status"]) for r in rows] != [OutboxStatus.DONE.value]
    assert "document re-attach failed" in str(rows[0]["last_error"])


async def test_a_handle_free_payload_whose_msh2_names_a_marker_char_is_delivered_unchanged(
    store: MessageStore,
) -> None:
    """The gate opens on a header naming a marker character. With MSH-2 too short to name the
    separators, no handle can be escaped in it, so the payload is carried as it was before the
    gate read headers, not refused."""
    payload = "MSH|:~|APP|FAC|RCV|RCVF|20260101120000||ADT:A01|MSGID002|P|2.5\rPID|1||123\r"
    assert may_hold_doc_ref(payload)
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    _mid, rows = await _deliver(store, runner, payload)

    assert col.deliveries == [payload]
    assert [str(r["status"]) for r in rows] == [OutboxStatus.DONE.value]


async def test_a_short_msh2_payload_carrying_the_marker_is_still_refused(
    store: MessageStore,
) -> None:
    """The control: the same header with the marker in the raw text keeps its permanent refusal."""
    handle = make_doc_ref(hashlib.sha256(b"x").hexdigest(), "Application")
    payload = f"MSH|:~|APP|FAC|RCV|RCVF|20260101120000||ADT:A01|MSGID003|P|2.5\rNTE|1||{handle}\r"
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    _mid, rows = await _deliver(store, runner, payload)

    assert col.deliveries == []
    assert _dead_lettered_at_once(rows)


async def test_a_child_whose_only_handle_is_a_copy_never_sends_it(store: MessageStore) -> None:
    """The child inherits nothing, since its handle sits outside OBX-5.5, so it holds no document.
    The copy guard must still refuse the engine's handle rather than send it with no document."""
    parent, ref, _skeleton = await _detached_parent(store, _b64(1500))
    handle = make_doc_ref(ref, "Application")
    child = await _passthrough_child(store, parent, _with_copy_in_nte(_hl7("plain text"), handle))
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    await _deliver_queued(store, runner, child)

    assert col.deliveries == []
    assert _dead_lettered_at_once(list(await store.outbox_for(child)))


def test_a_handle_the_delivery_gate_passes_over_is_not_inherited() -> None:
    """A handle hex-escaped in OBX-5.5 under default delimiters never opens delivery's gate, so it
    is sent as text and resolves nothing. A child must not hold the document it seems to name."""
    from messagefoundry.store.store import attachments_named

    ref = hashlib.sha256(b"x").hexdigest()
    handle = make_doc_ref(ref, "Application")
    hexed = "\\X" + DOC_REF_MARKER[:1].encode("ascii").hex().upper() + "\\" + handle[1:]
    body = _hl7(hexed)
    assert Message.parse(body).field("OBX-5.5") == handle  # the parser reads it as the handle
    assert not may_hold_doc_ref(body)

    assert attachments_named([ref], body) == []
