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
        list(iter_obx_documents(Message.parse(text), received=text))


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
    assert [
        r["attachment_id"] for r in await store.attachments_for(child, include_inherited=True)
    ] == [ref]


async def test_a_child_holds_its_own_reference_so_either_purge_keeps_the_count(
    store: MessageStore,
) -> None:
    parent, ref, skeleton = await _detached_parent(store, _b64(1500))
    child = await _passthrough_child(store, parent, skeleton)
    assert await _refcount(store, ref) == 2

    await store.release_message_attachments(parent)
    assert await _refcount(store, ref) == 1  # the child still holds the document
    assert [
        r["attachment_id"] for r in await store.attachments_for(child, include_inherited=True)
    ] == [ref]

    await store.release_message_attachments(child)
    assert await _refcount(store, ref) is None  # the last holder gone, the document is collected


def test_the_inheritance_plan_takes_every_childs_documents_in_one_sorted_pass() -> None:
    """Several pass-through children made in one transaction are linked in one pass: each
    document once, in content-address order, with every child that names it. Per child, a second
    child naming a lower address would take that header lock after the first child's higher one,
    the opposite of the order the ingress increfs and the retention decrefs take."""
    from messagefoundry.store.store import inheritance_plan

    low, high, children = _three_children()

    assert inheritance_plan([high, low], children) == [(low, ["c2", "c3"]), (high, ["c1", "c2"])]


def _three_children() -> tuple[str, str, list[tuple[str, str]]]:
    """Two content addresses, and three children: one names the higher, one both, one the lower,
    plus a fourth whose body carries no handle."""
    low, high = sorted(hashlib.sha256(s).hexdigest() for s in (b"one", b"two"))
    names_high = _hl7(make_doc_ref(high, "Application"))
    names_both = names_high + f"OBX|2|ED|PDF||^Application^PDF^Base64^{make_doc_ref(low, 'x')}\r"
    names_low = _hl7(make_doc_ref(low, "Application"))
    children = [("c1", names_high), ("c2", names_both), ("c3", names_low), ("c4", _hl7("plain"))]
    return low, high, children


def _expected_passes(low: str, high: str, collected: bool) -> list[tuple[str, tuple]]:
    """The calls one inheritance pass over :func:`_three_children` makes, the lower document's
    links left out where a purge collected its header first, one link per call."""
    low_links = [] if collected else [("link", ("c2", low)), ("link", ("c3", low))]
    return [
        ("fetch", ("parent",)),
        ("incref", (2, low)),
        *low_links,
        ("incref", (2, high)),
        ("link", ("c1", high)),
        ("link", ("c2", high)),
    ]


@pytest.mark.parametrize("collected", [False, True], ids=["held", "header-collected"])
async def test_postgres_links_every_child_in_one_sorted_pass(collected: bool) -> None:
    """The Postgres inheritance, offline: one incref per document, by the number of children that
    name it, in content-address order, then that document's links, none where the incref found no
    header. A handle-free body reads nothing."""
    from messagefoundry.store.postgres import PostgresStore

    low, high, children = _three_children()
    calls: list[tuple[str, tuple]] = []

    class _Conn:
        async def fetch(self, sql: str, *args: object) -> list[dict[str, str]]:
            calls.append(("fetch", args))
            return [{"attachment_id": high}, {"attachment_id": low}]

        async def execute(self, sql: str, *args: object) -> str:
            assert sql.startswith("UPDATE attachment SET refcount = refcount + $1")
            calls.append(("incref", args))
            return "UPDATE 0" if collected and args[1] == low else "UPDATE 1"

        async def executemany(self, sql: str, rows: list[tuple[str, str]]) -> None:
            assert "inherited" in sql
            calls.extend(("link", tuple(row)) for row in rows)

    store = object.__new__(PostgresStore)
    await store._inherit_attachments(_Conn(), "parent", [("c4", _hl7("plain"))])
    assert calls == []

    await store._inherit_attachments(_Conn(), "parent", children)

    assert calls == _expected_passes(low, high, collected)


@pytest.mark.parametrize("collected", [False, True], ids=["held", "header-collected"])
@pytest.mark.parametrize("sync", [False, True], ids=["async", "sync"])
async def test_sql_server_links_every_child_in_one_sorted_pass(sync: bool, collected: bool) -> None:
    """The SQL Server inheritance and its synchronous twin, offline, as the Postgres one."""
    from messagefoundry.store.sqlserver import SqlServerStore

    low, high, children = _three_children()
    calls: list[tuple[str, tuple]] = []

    class _Cursor:
        def __init__(self) -> None:
            self.last: tuple = ()

        def _execute(self, sql: str, params: tuple = ()) -> None:
            kind = "fetch" if sql.startswith("SELECT") else "incref"
            kind = "link" if sql.startswith("INSERT") else kind
            calls.append((kind, tuple(params)))
            self.last = tuple(params)

        def _fetchall(self) -> list[tuple[str]]:
            return [(high,), (low,)]

        def _fetchone(self) -> tuple[str] | None:
            if collected and self.last[1] == low:
                return None  # a purge collected the header first
            return (self.last[1],)

    class _AsyncCursor(_Cursor):
        async def execute(self, sql: str, params: tuple = ()) -> None:
            self._execute(sql, params)

        async def fetchall(self) -> list[tuple[str]]:
            return self._fetchall()

        async def fetchone(self) -> tuple[str] | None:
            return self._fetchone()

    class _SyncCursor(_Cursor):
        def execute(self, sql: str, params: tuple = ()) -> None:
            self._execute(sql, params)

        def fetchall(self) -> list[tuple[str]]:
            return self._fetchall()

        def fetchone(self) -> tuple[str] | None:
            return self._fetchone()

    store = object.__new__(SqlServerStore)
    for batch in ([("c4", _hl7("plain"))], children):
        if sync:
            store._inherit_attachments_sync(_SyncCursor(), "parent", batch)
        else:
            await store._inherit_attachments(_AsyncCursor(), "parent", batch)
        if batch is not children:
            assert calls == []  # a handle-free body reads nothing

    assert calls == _expected_passes(low, high, collected)


async def test_server_retention_decrefs_in_python_order_whatever_the_collation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Postgres and SQL Server retention decrefs take the header locks in the order the
    inheritance and ingress increfs take them, sorted in Python, even where the database's
    collation returned the rows in another order."""
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    low, high, _children = _three_children()
    released: list[tuple[str, int]] = []

    async def _decref(_conn: object, ref: str, count: int = 1) -> None:
        released.append((ref, count))

    class _PgConn:
        async def fetch(self, sql: str, *args: object) -> list[dict[str, object]]:
            return [{"attachment_id": high, "n": 1}, {"attachment_id": low, "n": 2}]

        async def execute(self, sql: str, *args: object) -> str:
            return "DELETE 3"

    class _MsCursor:
        description = (("attachment_id",), ("n",))

        async def execute(self, sql: str, params: object = ()) -> None:
            return None

        async def fetchall(self) -> list[tuple[str, int]]:
            return [(high, 1), (low, 2)]

    pg = object.__new__(PostgresStore)
    monkeypatch.setattr(pg, "_decref_attachment", _decref)
    await pg._release_message_attachments(_PgConn(), "message_id=$1", ["m"])
    ms = object.__new__(SqlServerStore)
    monkeypatch.setattr(ms, "_decref_attachment", _decref)
    await ms._release_message_attachments(_MsCursor(), "message_id=?", ("m",))

    assert released == [(low, 2), (high, 1)] * 2


async def test_several_passthrough_children_of_one_transform_each_hold_their_documents(
    store: MessageStore,
) -> None:
    doc_a, doc_b = _b64(1500, b"A"), _b64(1500, b"B")
    ref_a = await store.put_attachment(chunk_b64(doc_a), "application/pdf")
    ref_b = await store.put_attachment(chunk_b64(doc_b), "application/pdf")
    names_a = _hl7(make_doc_ref(ref_a, "Application"))
    names_both = names_a + (
        f"OBX|2|ED|PDF||^Application^PDF^Base64^{make_doc_ref(ref_b, 'Application')}||||||F\r"
    )
    parent = await store.enqueue_ingress(
        channel_id="IB_STREAM", raw=names_both, attachment_refs=[ref_a, ref_b]
    )
    ingress = await store.claim_next_fifo("IB_STREAM", stage="ingress")
    assert ingress is not None
    assert await store.route_handoff(
        ingress_id=ingress.id,
        message_id=parent,
        channel_id="IB_STREAM",
        handlers=[("h", names_both)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo("IB_STREAM", stage="routed")
    assert routed is not None

    await store.transform_handoff(
        routed_id=routed.id,
        message_id=parent,
        channel_id="IB_STREAM",
        deliveries=[],
        pt_deliveries=[("PT_ONE", names_both), ("PT_TWO", names_a)],
    )

    held: dict[str, list[str]] = {}
    for channel in ("PT_ONE", "PT_TWO"):
        children = await store.list_messages(channel_id=channel, allowed_channels=None)
        assert len(children) == 1
        rows = await store.attachments_for(str(children[0]["id"]), include_inherited=True)
        held[channel] = [str(r["attachment_id"]) for r in rows]
    assert held == {"PT_ONE": sorted([ref_a, ref_b]), "PT_TWO": [ref_a]}
    # The parent's reference plus one per child that names the document.
    assert await _refcount(store, ref_a) == 3
    assert await _refcount(store, ref_b) == 2


async def test_a_passthrough_child_holds_only_the_documents_its_body_names(
    store: MessageStore,
) -> None:
    parent, _ref, _skeleton = await _detached_parent(store, _b64(1500))
    # The Handler dropped the document: the child's body names none, so the child holds none.
    child = await _passthrough_child(store, parent, _hl7("plain text"))
    assert list(await store.attachments_for(child, include_inherited=True)) == []


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
    assert [
        r["attachment_id"]
        for r in await store.attachments_for(outcome.new_message_id, include_inherited=True)
    ] == [ref]
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

    assert list(await store.attachments_for(child, include_inherited=True)) == []
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


# --- repair round 4: download scope, the raw-marker copy, and a marker in a received document --


async def test_an_inherited_link_grants_no_download_through_the_child(tmp_path: Path) -> None:
    """A user scoped only to the pass-through channel must not read, through the child, a document
    the parent's channel stored: the inherited link serves delivery only. The parent's channel
    still downloads it, and the child still delivers it."""
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.auth import Role
    from messagefoundry.pipeline import Engine
    from tests.test_attachment_download_api import _add, _login, _service

    engine = await Engine.create(
        tmp_path / "scope.db", poll_interval=0.02, egress_settings=EgressSettings()
    )
    try:
        store = engine.store
        assert isinstance(store, MessageStore)
        raw_doc = b"%PDF-1.4\nsynthetic inherited document, not real PHI\n%%EOF\n"
        doc = base64.b64encode(raw_doc).decode("ascii")
        parent, ref, skeleton = await _detached_parent(store, doc)
        child = await _passthrough_child(store, parent, skeleton)
        service = await _service(engine)
        await service.set_channel_scope(
            await _add(service, "child_op", Role.OPERATOR), ["PT_NEXT"], actor="admin"
        )
        await service.set_channel_scope(
            await _add(service, "parent_op", Role.OPERATOR), ["IB_STREAM"], actor="admin"
        )
        transport = httpx.ASGITransport(app=create_app(engine, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            child_op = await _login(c, "child_op")
            parent_op = await _login(c, "parent_op")
            via_child = await c.get(f"/messages/{child}/attachments/{ref}", headers=child_op)
            detail = await c.get(f"/messages/{child}", headers=child_op)
            via_parent = await c.get(f"/messages/{parent}/attachments/{ref}", headers=parent_op)

        assert via_child.status_code == 404
        assert detail.status_code == 200 and detail.json()["attachments"] == []
        assert via_parent.status_code == 200 and via_parent.content == raw_doc
        # The link is still there for delivery and retention.
        assert [r["attachment_id"] for r in await store.attachments_for(child)] == []
        assert [
            r["attachment_id"] for r in await store.attachments_for(child, include_inherited=True)
        ] == [ref]
        runner = _runner(store)
        col = _Collector()
        runner._destinations[DEST] = col  # type: ignore[assignment]
        await _deliver_queued(store, runner, child)
        assert [Message.parse(d).field("OBX-5.5") for d in col.deliveries] == [doc]
    finally:
        await engine.stop()


def _colon_delimited_with_copy(handle: str, *, in_obx: bool) -> str:
    """A payload in MSH-2 ``:~\\&``, whose component separator is a character of the marker, with
    a whole-field ``set`` copy of ``handle`` in ``NTE-3``. A whole-field set leaves the component
    separator unescaped, so the copy keeps the marker raw while ``OBX-5.5`` holds it escaped."""
    msg = Message.parse(_hl7(_b64(10), msh2=":~\\&"))
    if in_obx:
        msg.set("OBX-5.5", handle)
    else:
        msg.set("OBX-5.5", "plain text")
    msg.add_segment("NTE|1")
    msg.set("NTE-3", handle)
    return msg.encode()


@pytest.mark.parametrize("in_obx", [True, False], ids=["after-the-splice", "no-handle-to-splice"])
async def test_a_raw_copy_under_delimiters_that_escape_the_marker_is_refused(
    store: MessageStore, in_obx: bool
) -> None:
    doc = _b64(1200)
    ref = await store.put_attachment(chunk_b64(doc), "application/pdf")
    handle = make_doc_ref(ref, "Application")
    payload = _colon_delimited_with_copy(handle, in_obx=in_obx)
    assert DOC_REF_MARKER in payload  # the copy is raw, not escaped
    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    rows = await _deliver_holding(store, runner, payload, ref)

    assert col.deliveries == []
    assert _dead_lettered_at_once(rows)


async def _no_read(_sha256: str) -> str | None:
    raise AssertionError("nothing is bound, so no attachment may be read")


def _copy_in_nte_component(field_sep: str, msh2: str, value: str) -> str:
    """A well-formed MDM^T02 under MSH-1 ``field_sep`` and MSH-2 ``msh2``, with a small ED Base64
    document in ``OBX-5.5`` and ``value`` set into ``NTE-3.1``. Every value is a component set,
    which escapes every delimiter in it, so a delimiter that is a letter or digit is escaped in the
    fixed text too and each field reads back as written."""
    msg = Message.parse(f"MSH{field_sep}{msh2}{field_sep}\rOBX{field_sep}1{field_sep}ED\r")
    fields = [
        ("MSH-7.1", "20260101120000"),
        ("MSH-9.1", "MDM"),
        ("MSH-9.2", "T02"),
        ("MSH-10.1", "MSGID001"),
        ("MSH-12.1", "2.5"),
        ("OBX-3.1", "PDF"),
        ("OBX-5.2", "Application"),
        ("OBX-5.3", "PDF"),
        ("OBX-5.4", "Base64"),
        ("OBX-5.5", _b64(10)),
        ("OBX-11.1", "F"),
    ]
    for path, text in fields:
        msg.set(path, text)
    msg.add_segment(f"NTE{field_sep}1")
    msg.set("NTE-3.1", value)
    payload = msg.encode()
    parsed = Message.parse(payload)
    assert [parsed.field(path) for path, _ in fields] == [text for _, text in fields]
    assert parsed.field("NTE-3.1") == value
    return payload


@pytest.mark.parametrize(
    ("field_sep", "msh2"),
    [
        ("a", "^~\\&"),
        ("|", "a~\\&"),
        ("|", "d~\\&"),
        ("|", "^a\\&"),
        ("|", "^~0&"),
        ("|", "^~\\a"),
    ],
    ids=["field-a", "component-a", "component-d", "repetition-a", "escape-0", "subcomponent-a"],
)
async def test_a_copy_whose_delimiters_escape_its_address_is_refused(
    field_sep: str, msh2: str
) -> None:
    """A separator or escape character that is a lowercase hex digit is escaped inside the copied
    content address too, so the address no longer reads as 64 hex. With nothing bound the copy
    must still be refused, never carried to the partner as text (BACKLOG #5099)."""
    from messagefoundry.parsing.binary import (
        UnreattachableDocumentError,
        _copy_names_address,
        reattach_documents_in_hl7,
    )

    handle = make_doc_ref(hashlib.sha256(b"copied").hexdigest(), "Application")
    payload = _copy_in_nte_component(field_sep, msh2, handle)
    escaped = Message._escape_leaf(DOC_REF_MARKER, *Message.parse(payload)._encoding_chars())
    # The leak's premise: the copy is in the payload, but neither marker reads an address after it.
    assert not any(_copy_names_address(payload, m) for m in (escaped, DOC_REF_MARKER))

    with pytest.raises(UnreattachableDocumentError):
        await reattach_documents_in_hl7(payload, _no_read, bound=frozenset())


@pytest.mark.parametrize("msh2", ["a~\\&", "^~0&"], ids=["component-a", "escape-0"])
async def test_a_bare_marker_under_a_lowercase_hex_delimiter_is_refused(
    store: MessageStore, msh2: str
) -> None:
    """Fail closed: under such delimiters no address after a marker can be read, so even a marker
    that names none counts as a copy. Through the delivery gate it dead-letters at once, rather
    than re-pending on the lane, and nothing reaches the partner."""
    from messagefoundry.parsing.binary import UnreattachableDocumentError, reattach_documents_in_hl7

    payload = _copy_in_nte_component("|", msh2, DOC_REF_MARKER + "x")
    assert may_hold_doc_ref(payload)
    with pytest.raises(UnreattachableDocumentError):
        await reattach_documents_in_hl7(payload, _no_read, bound=frozenset())

    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]
    _mid, rows = await _deliver(store, runner, payload)

    assert col.deliveries == []
    assert _dead_lettered_at_once(rows)


@pytest.mark.parametrize(
    "msh2",
    ["^~\\&", ":~\\&", "m~\\&", "^g\\&", "A~\\&", "^~\\B"],
    ids=[
        "default",
        "colon-component",
        "marker-letter-component",
        "lowercase-non-hex-repetition",
        "uppercase-component",
        "uppercase-subcomponent",
    ],
)
async def test_a_bare_marker_under_delimiters_with_no_lowercase_hex_is_carried_as_text(
    msh2: str,
) -> None:
    """The control: no delimiter is a lowercase hex digit, nothing is bound, and the marker names
    no address, so the payload is carried unchanged. A lowercase letter outside a-f, a marker
    letter included, and an uppercase hex letter escape nothing in a lowercase address, so they
    do not count."""
    from messagefoundry.parsing.binary import reattach_documents_in_hl7

    payload = _copy_in_nte_component("|", msh2, DOC_REF_MARKER + "x")
    escaped = Message._escape_leaf(DOC_REF_MARKER, *Message.parse(payload)._encoding_chars())
    assert escaped in payload  # the marker the guard looks for is there

    assert await reattach_documents_in_hl7(payload, _no_read, bound=frozenset()) == payload


def _with_marker_mid_document(doc: str) -> str:
    """A streaming body whose one ED Base64 value carries the handle marker past its start. Not
    base64, since base64 has no ':', but nothing at ingress validated the value before."""
    half = len(doc) // 2
    return _hl7(doc[:half] + DOC_REF_MARKER + doc[half:])


def _with_marker_in_nte(doc: str) -> str:
    return _hl7(doc) + f"NTE|1||see {DOC_REF_MARKER}x\r"


@pytest.mark.parametrize(
    "shape", [_with_marker_mid_document, _with_marker_in_nte], ids=["mid-document", "in-nte"]
)
async def test_a_streaming_body_holding_the_marker_is_refused_before_the_ack(
    store: MessageStore, shape
) -> None:
    """Detached and ACKed AA, such a body would dead-letter on every outbound after the splice,
    where the guard refuses any marker left. It is refused at the detach instead, counted as an
    ERROR row, with an AR on MLLP and a permanent refusal on HTTP."""
    from messagefoundry.transports.receipt import RefusalKind

    body = shape(_b64(2000))
    ic = _streaming_ic()
    runner = _runner(store, ic)

    ack = await runner._handle_inbound(ic, body.encode("utf-8"))
    receipt = await runner._handle_inbound_http(ic, body.encode("utf-8"))

    assert _ack_code(ack) == "AR"
    assert receipt.refusal is RefusalKind.PERMANENT
    cur = await store._db.execute(
        "SELECT status, error FROM messages WHERE channel_id=?", (ic.name,)
    )
    rows = [dict(r) for r in await cur.fetchall()]
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value] * 2
    assert all("handle marker" in str(r["error"]) for r in rows)
    cur = await store._db.execute("SELECT COUNT(*) FROM attachment")
    count = await cur.fetchone()
    assert count is not None and int(count[0]) == 0  # nothing stored for a refused body


def test_the_detach_refuses_a_marker_its_delimiters_escape_in_the_received_text() -> None:
    msg = Message.parse(_hl7(_b64(10), msh2=":~\\&"))
    msg.add_segment("NTE|1")
    msg.set("NTE-3.1", DOC_REF_MARKER + "x")  # a component set escapes the separator
    received = msg.encode()
    assert DOC_REF_MARKER not in received
    parsed = Message.parse(received)
    with pytest.raises(InboundDocRefError):
        list(iter_obx_documents(parsed, received=received))
    # The control: without the copy the same body yields its one document.
    plain = _hl7(_b64(10), msh2=":~\\&")
    assert len(list(iter_obx_documents(Message.parse(plain), received=plain))) == 1


def test_the_detach_scan_holds_one_document_value_at_a_time() -> None:
    """The caller's in-flight budget assumes the scan holds one document at a time. Each
    ``OBX-5.5`` value the scan reads is wrapped so a weak reference sees when it is freed. When
    the scan starts each read, no earlier value is alive; at every yield, with the consumer's own
    reference dropped as the ingress loop drops it, only the yielded value is. A scan that kept
    every value until it finished holds all of them at the first yield."""
    import weakref

    class _Tracked(str):
        pass

    live: list[weakref.ref[_Tracked]] = []
    held_at_each_read: list[int] = []

    def _alive() -> int:
        return sum(1 for ref in live if ref() is not None)

    class _TrackingMessage(Message):
        def field(
            self, path: str, *, occurrence: int = 1, repetition: int | None = None
        ) -> str | None:
            if path == "OBX-5.5":
                held_at_each_read.append(_alive())
            value = super().field(path, occurrence=occurrence, repetition=repetition)
            if path != "OBX-5.5" or not value:
                return value
            tracked = _Tracked(value)
            live.append(weakref.ref(tracked))
            return tracked

    count = 6
    text = _hl7(_b64(4000, b"A")) + "".join(
        f"OBX|{n}|ED|PDF||^Application^PDF^Base64^{_b64(4000, bytes([65 + n]))}||||||F\r"
        for n in range(2, count + 1)
    )
    scan = iter_obx_documents(_TrackingMessage.parse(text), received=text)
    held_at_each_yield: list[int] = []
    occurrences: list[int] = []
    for document in scan:
        occurrences.append(document[0])
        del document
        held_at_each_yield.append(_alive())
    assert occurrences == list(range(1, count + 1))
    assert max(held_at_each_yield) == 1, held_at_each_yield
    assert len(held_at_each_read) >= 2 * count
    assert max(held_at_each_read) == 0, held_at_each_read


def test_the_detach_scan_cannot_be_called_without_the_received_text() -> None:
    """``received`` is required: a caller that left it out would skip the whole-body marker check
    (BACKLOG #5099), so the call is refused instead."""
    text = _hl7(_b64(10))
    with pytest.raises(TypeError):
        iter_obx_documents(Message.parse(text))  # type: ignore[call-arg]
