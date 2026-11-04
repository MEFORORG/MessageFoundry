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
* a ``mfdoc:v1:pruned:`` tombstone the sender wrote resolves nothing and is carried as text;
* under a delimiter in the base64 alphabet, a document is refused at the detach, a marker at
  both listeners, and a handle or marker at delivery, while ordinary delimiters are untouched.

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
from messagefoundry.pipeline.dryrun import dry_run
from messagefoundry.pipeline.ingress_guards import DOC_REF_MARKER_REFUSED_REASON
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


def _well_formed(
    field_sep: str, msh2: str, obx5_5: str, nte: str | None = None, *, obx2: str = "ED"
) -> str:
    """A well-formed MDM^T02 under MSH-1 ``field_sep`` and MSH-2 ``msh2``, with ``obx5_5`` in an
    ED Base64 ``OBX-5.5`` and, unless it is None, ``nte`` set into ``NTE-3.1``. Every value is a
    component set, which escapes every delimiter in it, so a delimiter that is a letter or digit is
    escaped in the fixed text too and each field reads back as written."""
    msg = Message.parse(f"MSH{field_sep}{msh2}{field_sep}\rOBX{field_sep}1{field_sep}{obx2}\r")
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
        ("OBX-5.5", obx5_5),
        ("OBX-11.1", "F"),
    ]
    for path, text in fields:
        msg.set(path, text)
    if nte is not None:
        msg.add_segment(f"NTE{field_sep}1")
        msg.set("NTE-3.1", nte)
    payload = msg.encode()
    parsed = Message.parse(payload)
    assert [parsed.field(path) for path, _ in fields] == [text for _, text in fields]
    assert nte is None or parsed.field("NTE-3.1") == nte
    return payload


def _copy_in_nte_component(field_sep: str, msh2: str, value: str) -> str:
    """:func:`_well_formed` with a small document in ``OBX-5.5`` and ``value`` in ``NTE-3.1``."""
    return _well_formed(field_sep, msh2, _b64(10), value)


@pytest.mark.parametrize(
    ("field_sep", "msh2", "address_readable"),
    [
        ("a", "^~\\&", False),
        ("|", "a~\\&", False),
        ("|", "d~\\&", False),
        ("|", "^a\\&", False),
        ("|", "^~0&", True),
        ("|", "^~\\a", False),
        ("|", "^~\\/", True),
        ("|", "A~\\&", True),
    ],
    ids=[
        "field-a",
        "component-a",
        "component-d",
        "repetition-a",
        "escape-0",
        "subcomponent-a",
        "subcomponent-slash",
        "component-A",
    ],
)
async def test_a_copy_whose_delimiters_escape_its_address_is_refused(
    field_sep: str, msh2: str, address_readable: bool
) -> None:
    """A delimiter that is a base64 character may be escaped inside the copied content address
    too, so the address may no longer read as 64 hex. With nothing bound the copy must still be
    refused, never carried to the partner as text (BACKLOG #5099). Where an escape leaves a run of
    hex behind, the address scan reads one too; elsewhere only the delimiter rule refuses it."""
    from messagefoundry.parsing.binary import (
        UnreattachableDocumentError,
        _copy_names_address,
        reattach_documents_in_hl7,
    )

    handle = make_doc_ref(hashlib.sha256(b"copied").hexdigest(), "Application")
    payload = _copy_in_nte_component(field_sep, msh2, handle)
    escaped = Message._escape_leaf(DOC_REF_MARKER, *Message.parse(payload)._encoding_chars())
    reads = any(_copy_names_address(payload, m) for m in (escaped, DOC_REF_MARKER))
    assert reads is address_readable

    with pytest.raises(UnreattachableDocumentError):
        await reattach_documents_in_hl7(payload, _no_read, bound=frozenset())


@pytest.mark.parametrize(
    "msh2",
    ["a~\\&", "^~0&", "m~\\&", "^g\\&", "A~\\&", "^~\\B", "^~\\/", "+~\\&", "^=\\&"],
    ids=[
        "component-a",
        "escape-0",
        "marker-letter-component",
        "lowercase-non-hex-repetition",
        "uppercase-component",
        "uppercase-subcomponent",
        "slash-subcomponent",
        "plus-component",
        "equals-repetition",
    ],
)
async def test_a_bare_marker_under_a_base64_delimiter_is_refused(
    store: MessageStore, msh2: str
) -> None:
    """Fail closed: under a delimiter in the base64 alphabet no address after a marker can be
    read, so even a marker that names none counts as a copy (BACKLOG #5099). Through the delivery
    gate it dead-letters at once, rather than re-pending on the lane, and nothing reaches the
    partner."""
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
    ["^~\\&", ":~\\&", "^~\\&#", "^~\\&/", "!~\\&"],
    ids=["default", "colon-component", "truncation-hash", "fifth-char-slash", "bang-component"],
)
async def test_a_bare_marker_under_delimiters_with_no_base64_character_is_carried_as_text(
    msh2: str,
) -> None:
    """The control: no delimiter is a base64 character, nothing is bound, and the marker names no
    address, so the payload is carried unchanged. A fifth MSH-2 character is not a delimiter, as
    ``Message._encoding_chars`` reads them, so one in the base64 alphabet does not count."""
    from messagefoundry.parsing.binary import reattach_documents_in_hl7

    payload = _copy_in_nte_component("|", msh2, DOC_REF_MARKER + "x")
    escaped = Message._escape_leaf(DOC_REF_MARKER, *Message.parse(payload)._encoding_chars())
    assert escaped in payload  # the marker the guard looks for is there

    assert await reattach_documents_in_hl7(payload, _no_read, bound=frozenset()) == payload


@pytest.mark.parametrize("msh2", ["^~\\&", "A~\\&"], ids=["ordinary", "uppercase-hex-component"])
async def test_a_copy_with_an_uppercase_address_and_nothing_bound_is_refused(msh2: str) -> None:
    """``parse_doc_ref`` lowercases a content address before it reads it, so a copy whose address
    a Handler uppercased names the same document. Under ordinary delimiters the copy scan reads
    it as one; under an uppercase hex delimiter the delimiter rule refuses it too (BACKLOG
    #5099)."""
    from messagefoundry.parsing.binary import UnreattachableDocumentError, reattach_documents_in_hl7

    sha = hashlib.sha256(b"copied, uppercased").hexdigest()
    copy = f"{DOC_REF_MARKER}{sha.upper()}:Application"
    assert parse_doc_ref(copy)[0] == sha
    payload = _copy_in_nte_component("|", msh2, copy)

    with pytest.raises(UnreattachableDocumentError):
        await reattach_documents_in_hl7(payload, _no_read, bound=frozenset())


class _Reader:
    """An attachment reader that records each content address it is asked for."""

    def __init__(self, documents: dict[str, str]) -> None:
        self.documents = documents
        self.calls: list[str] = []

    async def __call__(self, sha256: str) -> str | None:
        self.calls.append(sha256)
        return self.documents.get(sha256)


#: A base64 document holding every character a base64 delimiter below could name.
_EVERY_BASE64_CHARACTER = base64.b64encode(bytes(range(256)) * 3 + b"x").decode("ascii")


@pytest.mark.parametrize(
    ("field_sep", "msh2"),
    [("|", "^~\\/"), ("|", "+~\\&"), ("|", "^=\\&"), ("|", "^~\\a"), ("|", "^~\\A")],
    ids=[
        "slash-subcomponent",
        "plus-component",
        "equals-repetition",
        "a-subcomponent",
        "A-subcomponent",
    ],
)
async def test_a_bound_handle_under_a_base64_delimiter_is_refused_before_any_read(
    field_sep: str, msh2: str
) -> None:
    """The splice sets the stored base64 back with ``Message.set``, which would escape a delimiter
    in it, so the partner would get a document that is not the sender's. A handle the message
    holds is refused before ``reader`` runs (BACKLOG #5099). Pinned on the reader's calls, so a
    check moved after the splice turns this red."""
    from messagefoundry.parsing.binary import UnreattachableDocumentError, reattach_documents_in_hl7

    sha = hashlib.sha256(_EVERY_BASE64_CHARACTER.encode("ascii")).hexdigest()
    payload = _well_formed(field_sep, msh2, make_doc_ref(sha, "Application"))
    assert Message.parse(payload).field("OBX-5.5") == make_doc_ref(sha, "Application")
    reader = _Reader({sha: _EVERY_BASE64_CHARACTER})

    with pytest.raises(UnreattachableDocumentError, match="base64 character"):
        await reattach_documents_in_hl7(payload, reader, bound=frozenset({sha}))
    assert reader.calls == []


@pytest.mark.parametrize("msh2", ["^~\\&", "^~\\&#", "^~\\&/"])
async def test_a_bound_handle_under_ordinary_delimiters_is_spliced_verbatim(msh2: str) -> None:
    """The control: no delimiter is a base64 character, a fifth MSH-2 character in the alphabet
    included, so the stored document is set back byte for byte and the result is the original
    body."""
    from messagefoundry.parsing.binary import reattach_documents_in_hl7

    original = _well_formed("|", msh2, _EVERY_BASE64_CHARACTER)
    sha = hashlib.sha256(_EVERY_BASE64_CHARACTER.encode("ascii")).hexdigest()
    msg = Message.parse(original)
    msg.set("OBX-5.5", make_doc_ref(sha, "Application"))
    reader = _Reader({sha: _EVERY_BASE64_CHARACTER})

    spliced = await reattach_documents_in_hl7(msg.encode(), reader, bound=frozenset({sha}))

    assert reader.calls == [sha]
    assert spliced == original


async def test_a_handler_that_moves_msh2_into_the_base64_alphabet_never_sends_the_handle(
    store: MessageStore,
) -> None:
    """The detach wrote the handle under ordinary delimiters; a Handler then set MSH-2 so the
    subcomponent separator is ``/``. Setting the stored base64 back would escape every ``/`` in
    it, so the row is refused before any read and dead-letters at once (BACKLOG #5099)."""
    from messagefoundry.parsing.binary import UnreattachableDocumentError, reattach_documents_in_hl7

    ref = await store.put_attachment(chunk_b64(_EVERY_BASE64_CHARACTER), "application/pdf")
    msg = Message.parse(_hl7(make_doc_ref(ref, "Application")))
    msg.set("MSH-2", "^~\\/")
    payload = msg.encode()
    assert Message.parse(payload)._encoding_chars()[4] == "/"
    reader = _Reader({ref: _EVERY_BASE64_CHARACTER})
    with pytest.raises(UnreattachableDocumentError):
        await reattach_documents_in_hl7(payload, reader, bound=frozenset({ref}))
    assert reader.calls == []

    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]
    rows = await _deliver_holding(store, runner, payload, ref)

    assert col.deliveries == []
    assert _dead_lettered_at_once(rows)


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


# --- the delimiter-class rule at ingress (BACKLOG #5099) --------------------------------------


def _plain_ic() -> InboundConnection:
    """An MLLP inbound with no streaming threshold: nothing is ever detached from its bodies."""
    return InboundConnection(
        name="IB_PLAIN",
        spec=ConnectionSpec(ConnectorType.MLLP, {"port": 0}),
        router="r",
        ack_mode=AckMode.ORIGINAL,
        content_type=ContentType.HL7V2,
        validation=Validation(strict=False),
    )


async def _rows(store: MessageStore, channel: str) -> list[dict]:
    cur = await store._db.execute(
        "SELECT status, error FROM messages WHERE channel_id=? ORDER BY received_at", (channel,)
    )
    return [dict(r) for r in await cur.fetchall()]


async def _attachment_count(store: MessageStore) -> int:
    cur = await store._db.execute("SELECT COUNT(*) FROM attachment")
    count = await cur.fetchone()
    assert count is not None
    return int(count[0])


async def _ingress_count(store: MessageStore, channel: str) -> int:
    cur = await store._db.execute(
        "SELECT COUNT(*) FROM queue WHERE channel_id=? AND stage='ingress'", (channel,)
    )
    count = await cur.fetchone()
    assert count is not None
    return int(count[0])


#: A streaming body under MSH-2 ``^~\\/``: the subcomponent separator is ``/``, which the base64
#: document holds. Stored as-is and set back at delivery, every ``/`` would arrive as ``\\T\\``.
_SLASH_DELIMITED_DOCUMENT = _hl7(_b64(2000, b"\xff"), msh2="^~\\/")


def test_the_detach_scan_refuses_a_document_under_a_base64_delimiter() -> None:
    from messagefoundry.parsing.binary import Base64DelimiterError

    assert "/" in _b64(2000, b"\xff")
    message = Message.parse(_SLASH_DELIMITED_DOCUMENT)
    scan = iter_obx_documents(message, received=_SLASH_DELIMITED_DOCUMENT)
    with pytest.raises(Base64DelimiterError):
        next(scan)  # refused before the first document is yielded, so none is stored


async def test_a_streaming_document_under_a_base64_delimiter_is_refused_before_the_ack(
    store: MessageStore,
) -> None:
    """The reviewer's repro: a streaming body at or over the threshold, MSH-2 ``^~\\/``, and a
    base64 document holding ``/``. Detached and ACKed AA, delivery would escape every ``/`` in
    it; it is refused at the detach instead, with nothing stored, an ERROR row, an AR on MLLP and
    a permanent refusal on HTTP (BACKLOG #5099)."""
    from messagefoundry.transports.receipt import RefusalKind

    body = _SLASH_DELIMITED_DOCUMENT
    ic = _streaming_ic()
    assert len(body) >= (ic.stream_threshold_bytes or 0)
    runner = _runner(store, ic)

    ack = await runner._handle_inbound(ic, body.encode("utf-8"))
    receipt = await runner._handle_inbound_http(ic, body.encode("utf-8"))

    assert _ack_code(ack) == "AR"
    assert ack is not None and "document under base64 delimiters" in ack
    assert receipt.refusal is RefusalKind.PERMANENT
    rows = await _rows(store, ic.name)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value] * 2
    # The detach refused it, not the listener's marker check: the body holds no marker.
    assert all("streaming detach failed: Base64DelimiterError" in str(r["error"]) for r in rows)
    assert await _attachment_count(store) == 0
    assert await _ingress_count(store, ic.name) == 0


@pytest.mark.parametrize(
    ("msh2", "streaming"),
    [("^~\\/", False), ("m~\\&", False), ("^~\\/", True), ("m~\\&", True)],
    ids=["slash-raw-marker", "m-escaped-marker", "slash-streaming", "m-streaming"],
)
async def test_a_marker_under_a_base64_delimiter_is_refused_at_both_listeners(
    store: MessageStore, msh2: str, streaming: bool
) -> None:
    """At any size, a body holding the handle marker under a delimiter in the base64 alphabet is
    refused before the ACK: delivery refuses any marker under such delimiters, so it would be
    ACKed and then dead-letter on every outbound (BACKLOG #5099). Under ``m~\\&`` the marker is
    escaped, so the escaped form is what the listener finds. The body has no document big enough
    to matter: the streaming case is over the threshold by its NTE alone."""
    from messagefoundry.transports.receipt import RefusalKind

    body = _copy_in_nte_component("|", msh2, DOC_REF_MARKER + "x")
    if streaming:
        msg = Message.parse(body)
        msg.add_segment("NTE|2")
        msg.set("NTE-3.1", "y" * 600, occurrence=2)
        body = msg.encode()
        assert Message.parse(body).field("NTE-3.1") == DOC_REF_MARKER + "x"
    ic = _streaming_ic() if streaming else _plain_ic()
    assert (len(body) >= 500) is streaming
    runner = _runner(store, ic)

    ack = await runner._handle_inbound(ic, body.encode("utf-8"))
    receipt = await runner._handle_inbound_http(ic, body.encode("utf-8"))

    assert _ack_code(ack) == "AR"
    if "/" in msh2:  # a lowercase delimiter splits the echoed text; "/" leaves it whole
        assert ack is not None and "handle marker refused by its delimiters" in ack
    assert receipt.refusal is RefusalKind.PERMANENT
    rows = await _rows(store, ic.name)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value] * 2
    # The listener's marker check refused it, before any detach could.
    assert all(DOC_REF_MARKER_REFUSED_REASON in str(r["error"]) for r in rows)
    assert await _ingress_count(store, ic.name) == 0
    assert await _attachment_count(store) == 0


@pytest.mark.parametrize("msh2", ["^~\\&", "^~\\&#", "^~\\&/", "!~\\&"])
@pytest.mark.parametrize("marker", [False, True], ids=["no-marker", "bare-marker"])
async def test_ordinary_delimiters_are_accepted_at_both_listeners_as_before(
    store: MessageStore, msh2: str, marker: bool
) -> None:
    """The control: no delimiter is a base64 character, a fifth MSH-2 character in the alphabet
    included, so a small body is accepted AA with or without a bare marker, stored byte for byte.
    Reserving the marker under ordinary delimiters is a policy left to the owner."""
    body = _copy_in_nte_component("|", msh2, (DOC_REF_MARKER + "x") if marker else "plain")
    ic = _plain_ic()
    runner = _runner(store, ic)

    ack = await runner._handle_inbound(ic, body.encode("utf-8"))
    receipt = await runner._handle_inbound_http(ic, body.encode("utf-8"))

    assert _ack_code(ack) == "AA"
    assert receipt.refusal is None
    cur = await store._db.execute(
        "SELECT payload FROM queue WHERE channel_id=? AND stage='ingress'", (ic.name,)
    )
    assert [r[0] for r in await cur.fetchall()] == [body, body]


@pytest.mark.parametrize("msh2", ["^~\\&", "^~\\&#", "^~\\&/"])
async def test_a_streaming_document_under_ordinary_delimiters_is_still_detached(
    store: MessageStore, msh2: str
) -> None:
    """The control for the detach refusal: the same base64 document holding ``/``, under
    delimiters with no base64 character, is detached and ACKed AA as before."""
    body = _hl7(_b64(2000, b"\xff"), msh2=msh2)
    ic = _streaming_ic()
    runner = _runner(store, ic)

    ack = await runner._handle_inbound(ic, body.encode("utf-8"))

    assert _ack_code(ack) == "AA"
    assert await _attachment_count(store) == 1
    assert await _ingress_count(store, ic.name) == 1


@pytest.mark.parametrize(
    ("msh2", "refused"),
    [("^~\\/", True), ("m~\\&", True), ("^~\\&", False), ("^~\\&/", False)],
    ids=["slash", "m-escaped", "ordinary", "fifth-char-slash"],
)
def test_the_dry_run_refuses_the_marker_as_the_listeners_do(msh2: str, refused: bool) -> None:
    """``messagefoundry check`` and the Test Bench preview what the listener answers: the marker
    refusal is pure, so the dry-run runs the same check with the same reason (BACKLOG #5099)."""
    body = _copy_in_nte_component("|", msh2, DOC_REF_MARKER + "x")
    reg = Registry()
    reg.add_inbound(_plain_ic())
    reg.add_router("r", lambda m: [])

    result = dry_run(reg, body.encode("utf-8"))

    if refused:
        assert result.disposition is MessageStatus.ERROR
        assert result.error == DOC_REF_MARKER_REFUSED_REASON
    else:
        assert result.error != DOC_REF_MARKER_REFUSED_REASON


async def test_a_raw_marker_under_a_short_msh2_is_refused_at_both_listeners(
    store: MessageStore,
) -> None:
    """``Message._encoding_chars`` names no delimiters for a three-character MSH-2, though the
    parser fills the fourth in. Delivery refuses a raw marker under such a header, so the
    listeners refuse it before the ACK rather than ACK it and dead-letter it (BACKLOG #5099). The
    same header with no marker is accepted as before."""
    from messagefoundry.transports.receipt import RefusalKind

    head = "MSH|^~\\|APP|FAC|RCV|RCVF|20260101120000||ADT^A01|MSGID003|P|2.5\r"
    ic = _plain_ic()
    runner = _runner(store, ic)

    marked = (head + f"NTE|1||{DOC_REF_MARKER}x\r").encode("utf-8")
    assert _ack_code(await runner._handle_inbound(ic, marked)) == "AR"
    assert (await runner._handle_inbound_http(ic, marked)).refusal is RefusalKind.PERMANENT
    plain = (head + "NTE|1||plain\r").encode("utf-8")
    assert _ack_code(await runner._handle_inbound(ic, plain)) == "AA"

    rows = await _rows(store, ic.name)
    errors = [str(r["error"]) for r in rows if r["status"] == MessageStatus.ERROR.value]
    assert len(errors) == 2
    assert all(e.endswith(DOC_REF_MARKER_REFUSED_REASON) for e in errors)
    assert await _ingress_count(store, ic.name) == 1


# --- a document is detached only if the splice sets it back verbatim (BACKLOG #5099) ----------

#: A streaming body whose ED Base64 value is not base64 and holds ``&``, the subcomponent
#: separator under ``^~\\&``. A component read takes the whole component, ``&`` included, so the
#: detach would store it, and delivery's ``Message.set`` would send it back as ``\\T\\``.
_AMP_DOCUMENT = _hl7("Q" * 400 + "&" + "R" * 400)


@pytest.mark.parametrize("odd", ["&", "\x01"], ids=["subcomponent-separator", "control"])
def test_the_detach_scan_refuses_a_document_the_splice_would_alter(odd: str) -> None:
    from messagefoundry.parsing.binary import Base64DelimiterError, NonVerbatimDocumentError

    body = _hl7("Q" * 400 + odd + "R" * 400)
    message = Message.parse(body)
    value = message.field("OBX-5.5") or ""
    assert odd in value
    assert Message._escape_leaf(value, *message._encoding_chars()) != value
    scan = iter_obx_documents(message, received=body, min_b64_len=500)
    with pytest.raises(NonVerbatimDocumentError) as caught:
        next(scan)  # refused before the first document is yielded, so none is stored
    assert not isinstance(caught.value, Base64DelimiterError)
    assert value not in str(caught.value)
    # Below the threshold nothing is detached, so the value rides inline as the sender sent it.
    assert list(iter_obx_documents(message, received=body, min_b64_len=10_000)) == []


async def test_a_streaming_document_the_splice_would_alter_is_refused_before_the_ack(
    store: MessageStore,
) -> None:
    """Under ordinary delimiters, a non-base64 value holding ``&`` over the threshold is refused
    at the detach, with nothing stored, an ERROR row, an AR on MLLP and a permanent refusal on
    HTTP, rather than ACKed AA and delivered with ``&`` turned into ``\\T\\`` (BACKLOG #5099)."""
    from messagefoundry.transports.receipt import RefusalKind

    body = _AMP_DOCUMENT
    ic = _streaming_ic()
    assert len(body) >= (ic.stream_threshold_bytes or 0)
    runner = _runner(store, ic)

    ack = await runner._handle_inbound(ic, body.encode("utf-8"))
    receipt = await runner._handle_inbound_http(ic, body.encode("utf-8"))

    assert _ack_code(ack) == "AR"
    assert ack is not None and "OBX-5.5 document holds a delimiter or control" in ack
    assert receipt.refusal is RefusalKind.PERMANENT
    rows = await _rows(store, ic.name)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value] * 2
    assert all("streaming detach failed: NonVerbatimDocumentError" in str(r["error"]) for r in rows)
    assert await _attachment_count(store) == 0
    assert await _ingress_count(store, ic.name) == 0


async def test_a_non_ed_value_holding_the_separator_is_carried_as_before(
    store: MessageStore,
) -> None:
    """The control for the value check: only an ED Base64 value is ever detached, so a large
    ``TX`` value holding ``&`` in a streaming body over the threshold is accepted AA and stored
    as it came, with nothing detached."""
    body = (
        "MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||MDM^T02|MSGID002|P|2.5\r"
        f"OBX|1|TX|NOTE||^^^^{'Q' * 400}&{'R' * 400}||||||F\r"
    )
    assert "&" in (Message.parse(body).field("OBX-5.5") or "")
    ic = _streaming_ic()
    assert len(body) >= (ic.stream_threshold_bytes or 0)
    runner = _runner(store, ic)

    assert _ack_code(await runner._handle_inbound(ic, body.encode("utf-8"))) == "AA"
    assert await _attachment_count(store) == 0
    cur = await store._db.execute(
        "SELECT payload FROM queue WHERE channel_id=? AND stage='ingress'", (ic.name,)
    )
    assert [r[0] for r in await cur.fetchall()] == [body]


async def test_a_stored_control_character_is_an_engine_fault_at_egress() -> None:
    """The detach refuses a control character under any delimiters, so a stored one is store
    corruption or an engine bug: a plain ``ValueError`` for the outbound's internal-error policy,
    as a stored CR or LF is, never the payload's permanent refusal, and nothing is sent."""
    from messagefoundry.parsing.binary import UnreattachableDocumentError, reattach_documents_in_hl7

    stored = "Q" * 400 + "\x01" + "R" * 400
    sha = hashlib.sha256(stored.encode("ascii")).hexdigest()
    reader = _Reader({sha: stored})
    with pytest.raises(ValueError, match="control character") as caught:
        await reattach_documents_in_hl7(
            _hl7(make_doc_ref(sha, "Application")), reader, bound=frozenset({sha})
        )
    assert not isinstance(caught.value, UnreattachableDocumentError)
    assert reader.calls == [sha]


async def test_a_stored_document_the_splice_would_alter_is_refused_at_egress(
    store: MessageStore,
) -> None:
    """The backstop for a value the detach did not check under these delimiters: the stored
    value holds a delimiter the splice escapes, so setting it back would alter it. The re-attach
    refuses it once the read returns it, and the row dead-letters at once with nothing sent
    (BACKLOG #5099)."""
    from messagefoundry.parsing.binary import UnreattachableDocumentError, reattach_documents_in_hl7

    stored = "Q" * 400 + "&" + "R" * 400
    ref = await store.put_attachment(chunk_b64(stored), "application/pdf")
    payload = _hl7(make_doc_ref(ref, "Application"))
    reader = _Reader({ref: stored})
    with pytest.raises(UnreattachableDocumentError, match="would escape") as caught:
        await reattach_documents_in_hl7(payload, reader, bound=frozenset({ref}))
    assert reader.calls == [ref]
    assert stored not in str(caught.value)

    runner = _runner(store)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]
    rows = await _deliver_holding(store, runner, payload, ref)

    assert col.deliveries == []
    assert _dead_lettered_at_once(rows)
    assert stored not in str(rows[0]["last_error"])


#: Separator sets in ``Message._encoding_chars`` order, ``(field, component, repetition, escape,
#: subcomponent)``: the ordinary five, and unusual ones, with letters, digits, base64 characters,
#: a control character and a non-ASCII character among them.
_SEPARATOR_SETS: list[tuple[str, str, str, str, str]] = [
    ("|", "^", "~", "\\", "&"),
    ("#", "F", "~", "\\", "&"),
    ("|", "A", "1", "/", "="),
    ("|", "^", "~", "\x01", "&"),
    ("\x1f", "^", "~", "\\", "&"),
    ("\u00a7", "^", "\u00b6", "\\", "&"),
    ("|", "+", "~", "!", "\u4e00"),
]

#: Non-ASCII characters the equivalence is also checked on: Latin-1 controls and letters, CJK,
#: and a character outside the Basic Multilingual Plane.
_NON_ASCII_SAMPLE = [chr(cp) for cp in (0x80, 0x85, 0x9F, 0xA0, 0xA7, 0xB6, 0xE9, 0xFF)] + [
    "\u0394",
    "\u4e00",
    "\ufeff",
    "\U0001f600",
]


@pytest.mark.parametrize("separators", _SEPARATOR_SETS)
def test_the_splice_check_agrees_with_the_escape_on_every_character(
    separators: tuple[str, str, str, str, str],
) -> None:
    """The linear check answers exactly what comparing ``Message._escape_leaf``'s output with its
    input answers, character by character and on whole strings, under ordinary and unusual
    delimiters (BACKLOG #5099)."""
    from messagefoundry.parsing.binary import _splice_alters

    singles = [chr(cp) for cp in range(0x80)] + _NON_ASCII_SAMPLE
    strings = [
        "",
        _EVERY_BASE64_CHARACTER,
        "Q" * 50 + separators[4] + "R" * 50,
        "plain text \u4e00\U0001f600",
        "".join(separators),
        "\t" * 3 + "x",
        "AB" + separators[3] + "E" + separators[3],
    ]
    for value in singles + strings:
        assert _splice_alters(value, separators) is (
            Message._escape_leaf(value, *separators) != value
        ), (separators, value)


def test_the_splice_check_is_linear_on_a_hostile_value() -> None:
    """The detach runs the check on a sender's value before the ACK. The escape it replaces took
    about 10 s on 4 MiB of ``\\x01``; the check must answer 16 MiB of a control or a delimiter,
    and clear 16 MiB of base64, well inside a bound no linear scan comes near (BACKLOG #5099)."""
    import time

    from messagefoundry.parsing.binary import _splice_alters

    separators = ("|", "^", "~", "\\", "&")
    size = 16 * 1024 * 1024
    clean = (_EVERY_BASE64_CHARACTER * (size // len(_EVERY_BASE64_CHARACTER) + 1))[:size]
    for value, alters in (("\x01" * size, True), ("&" * size, True), (clean, False)):
        started = time.perf_counter()
        assert _splice_alters(value, separators) is alters
        assert time.perf_counter() - started < 2.0


#: A streaming body with a document under a three-character MSH-2, ``^~\\``. ``Message`` reads
#: no delimiters from it, so every ``OBX-5.5`` read raises.
_SHORT_MSH2_DOCUMENT = _hl7(_b64(2000), msh2="^~\\")


def test_the_detach_scan_refuses_a_body_whose_header_names_no_delimiters() -> None:
    from messagefoundry.parsing.binary import UnreadableDelimitersError

    message = Message.parse(_SHORT_MSH2_DOCUMENT)
    with pytest.raises(ValueError, match="cannot determine HL7 separators"):
        message._encoding_chars()
    scan = iter_obx_documents(message, received=_SHORT_MSH2_DOCUMENT)
    with pytest.raises(UnreadableDelimitersError) as caught:
        next(scan)
    assert "^~" not in str(caught.value)
    # The separator read's refusal quotes MSH-1 and MSH-2; none of it rides on the chain.
    assert caught.value.__cause__ is None and caught.value.__context__ is None


async def test_a_streaming_body_whose_header_names_no_delimiters_is_refused_before_the_ack(
    store: MessageStore,
) -> None:
    """A streaming body over the threshold whose MSH-2 is shorter than four characters, with no
    marker for the listener's check to find: the detach's OBX reads raised a plain ValueError
    that neither listener records. It is refused by name instead, with an ERROR row, an AR on
    MLLP, a permanent refusal on HTTP and nothing stored (BACKLOG #5099)."""
    from messagefoundry.transports.receipt import RefusalKind

    body = _SHORT_MSH2_DOCUMENT
    assert DOC_REF_MARKER not in body
    ic = _streaming_ic()
    assert len(body) >= (ic.stream_threshold_bytes or 0)
    runner = _runner(store, ic)

    ack = await runner._handle_inbound(ic, body.encode("utf-8"))
    receipt = await runner._handle_inbound_http(ic, body.encode("utf-8"))

    assert _ack_code(ack) == "AR"
    assert ack is not None and "MSH-1 and MSH-2 name no delimiters" in ack
    assert receipt.refusal is RefusalKind.PERMANENT
    rows = await _rows(store, ic.name)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value] * 2
    assert all(
        "streaming detach failed: UnreadableDelimitersError" in str(r["error"]) for r in rows
    )
    assert await _attachment_count(store) == 0
    assert await _ingress_count(store, ic.name) == 0


async def test_an_ordinary_base64_document_is_detached_and_spliced_back_byte_identical(
    store: MessageStore,
) -> None:
    """The control: a base64 document under ``^~\\&`` holds no character the splice escapes, so
    it is detached, ACKed AA, and delivered as the very body the sender sent."""
    body = _hl7(_EVERY_BASE64_CHARACTER)
    ic = _streaming_ic()
    runner = _runner(store, ic)
    assert _ack_code(await runner._handle_inbound(ic, body.encode("utf-8"))) == "AA"
    assert await _attachment_count(store) == 1
    cur = await store._db.execute("SELECT raw FROM messages WHERE channel_id=?", (ic.name,))
    row = await cur.fetchone()
    assert row is not None
    skeleton = str(row[0])
    handle = Message.parse(skeleton).field("OBX-5.5") or ""
    assert is_doc_ref(handle)
    col = _Collector()
    runner._destinations[DEST] = col  # type: ignore[assignment]

    await _deliver_holding(store, runner, skeleton, parse_doc_ref(handle)[0])

    assert col.deliveries == [body]


# --- a fault in the marker check's read is a peek fault (BACKLOG #1594, #5099) ----------------


async def test_a_fault_in_the_marker_check_records_error_and_naks_at_both_listeners(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The marker check reads the parsed header after the peek. A parser fault there is recorded
    ERROR and refused like any other peek read fault, never an exception that drops the
    connection with no row (count-and-log)."""
    from messagefoundry.pipeline import ingress_guards
    from messagefoundry.transports.receipt import RefusalKind

    def _fault(*_args: object) -> bool:
        raise IndexError("parser fault in the marker read")

    monkeypatch.setattr(ingress_guards, "marker_under_base64_delimiters", _fault)
    body = _copy_in_nte_component("|", "^~\\&", "plain").encode("utf-8")
    ic = _plain_ic()
    runner = _runner(store, ic)

    ack = await runner._handle_inbound(ic, body)
    receipt = await runner._handle_inbound_http(ic, body)

    assert _ack_code(ack) == "AR"
    assert ack is not None and "peek read failed" in ack
    assert receipt.refusal is RefusalKind.PERMANENT
    rows = await _rows(store, ic.name)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value] * 2
    assert all("peek read failed (IndexError)" in str(r["error"]) for r in rows)
    assert await _ingress_count(store, ic.name) == 0
