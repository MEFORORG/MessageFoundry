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
    item = await store.claim_next_fifo(DEST)
    assert item is not None and item.message_id == mid
    await runner._process_delivery_item(DEST, item)
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
    runner._destinations[DEST] = col

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
    runner._destinations[DEST] = col

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
    runner._destinations[DEST] = col
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
    runner._destinations[DEST] = col

    await _deliver_holding(store, runner, msg.encode(), ref)

    assert len(col.deliveries) == 1
    assert Message.parse(col.deliveries[0]).field("OBX-5.5") == doc
    assert "mfdoc" not in col.deliveries[0]


async def _deliver_holding(
    store: MessageStore, runner: RegistryRunner, payload: str, ref: str
) -> list:
    """Queue ``payload`` as a message that holds ``ref``, as the ingress commit links a detached
    document, deliver its one outbound row once, and return its outbound rows."""
    mid = await store.enqueue_message(
        channel_id="IB_STREAM", raw=payload, deliveries=[(DEST, payload)], now=100.0
    )
    await store._db.execute(
        "INSERT INTO message_attachment (message_id, attachment_id) VALUES (?,?)", (mid, ref)
    )
    await store._db.commit()
    await store.attachment_incref(ref)
    item = await store.claim_next_fifo(DEST)
    assert item is not None and item.message_id == mid
    await runner._process_delivery_item(DEST, item)
    return list(await store.outbox_for(mid))


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
    runner._destinations[DEST] = col

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
    runner._destinations[DEST] = col

    _mid, _rows = await _deliver(store, runner, body)

    assert col.deliveries == [body]
