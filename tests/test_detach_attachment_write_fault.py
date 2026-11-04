# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1619: a ``put_attachment`` fault in a streaming detach propagates, and the label is bounded.

A streaming inbound detaches its large documents with ``put_attachment`` before the ingress commit.
No fault from that write is classed as the document's (Manager decision d20261104T042552411-c23337,
as amended): every one propagates to the transport with no message row, so the input is kept for a
resend, and the tests below pin what each source then does with it. A fault answered as a refusal
would charge the refused-body allowance, and a body whose text no backend can encode would then fail
the ``ERROR`` write as well, so each resend of it would drain the allowance for every other refused
body on that inbound.

What the detach does decide is the OBX-5.2 label, the one sender-controlled value a column could
refuse: a label some backend's ``attachment.content_type`` cannot hold is stored as
``application/octet-stream``, so it no longer fails the write on every resend.

Synthetic HL7 only, never real PHI.
"""

from __future__ import annotations

import base64
import sqlite3
from collections.abc import AsyncIterator, Callable, Iterable
from functools import partial
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.transports.base as base_mod
from messagefoundry.config.models import AckMode, ConnectorType, ContentType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.refused_body import RefusedBodyAllowance, RefusedBodyPolicy
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, StreamingAttachmentsUnsupported
from messagefoundry.store.crypto import CipherError
from messagefoundry.transports.file import FileSource
from messagefoundry.transports.receipt import RefusalKind
from tests.test_database_transport import _src, _SrcConn, _SrcCursor, _SrcPool
from tests.test_ingress_document_detach import _ack_code
from tests.test_tcp_x12_handler_failure import _ThenEof
from tests.test_x12_connection_events import _drive, _kinds, _Peer, _tcp


class _ServerDriverError(RuntimeError):
    """Shaped like a server driver's error: it carries a ``sqlstate``, as asyncpg's do."""

    def __init__(self, sqlstate: str, text: str) -> None:
        super().__init__(text)
        self.sqlstate = sqlstate


class _PyodbcDataError(RuntimeError):
    """Shaped like ``pyodbc.DataError``: the SQLSTATE is ``args[0]``, with no ``sqlstate``."""


#: SQL Server's 2628 truncation text, which quotes the value it refused.
_TRUNCATED = "String or binary data would be truncated. Truncated value: 'DOE^JANE'. (2628)"


def _locked() -> Exception:
    return sqlite3.OperationalError("database is locked")


def _deadlock() -> Exception:
    return _ServerDriverError("40001", "deadlock victim (1205)")


#: Every fault class the write can raise, a fault the same body meets again included: each propagates.
FAULTS = [
    pytest.param(lambda: sqlite3.DataError("string or blob too big"), id="sqlite-data"),
    pytest.param(
        lambda: UnicodeEncodeError("utf-8", "\udcff", 0, 1, "surrogates not allowed"),
        id="unicode-encode",
    ),
    pytest.param(lambda: _ServerDriverError("22001", _TRUNCATED), id="sqlstate-22001"),
    pytest.param(lambda: _PyodbcDataError("22001", f"[22001] {_TRUNCATED}"), id="pyodbc-22001"),
    pytest.param(_locked, id="sqlite-locked"),
    pytest.param(
        lambda: sqlite3.IntegrityError("UNIQUE constraint failed: attachment.id"),
        id="sqlite-integrity",
    ),
    pytest.param(lambda: ConnectionResetError("connection reset by peer"), id="conn-reset"),
    # aiosqlite on a closed connection
    pytest.param(lambda: ValueError("no active connection"), id="closed-conn"),
    pytest.param(_deadlock, id="sqlstate-40001"),
    pytest.param(
        lambda: _ServerDriverError("08S01", "communication link failure"), id="sqlstate-08S01"
    ),
    pytest.param(lambda: _ServerDriverError("HYT00", "query timeout expired"), id="sqlstate-HYT00"),
    pytest.param(
        lambda: _ServerDriverError("23000", "duplicate key in attachment"), id="sqlstate-23000"
    ),
    pytest.param(lambda: CipherError("vault transit unreachable"), id="cipher"),
    pytest.param(
        lambda: UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"), id="decode"
    ),
    # A programming error in the store code
    pytest.param(lambda: TypeError("a bug in put_attachment"), id="type-error"),
    pytest.param(lambda: AttributeError("a bug in put_attachment"), id="attribute-error"),
]


def _doc_hl7(*, type_of_data: str = "Application", b64: str | None = None) -> str:
    if b64 is None:
        b64 = base64.b64encode(b"P" * 2000).decode("ascii")
    return (
        f"MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||MDM^T02|MSGID001|P|2.5\r"
        "EVN|T02|20260101120000\r"
        "PID|1||MRN123^^^FAC||DOE^JANE\r"
        f"OBX|1|ED|PDF^Report||^{type_of_data}^PDF^Base64^{b64}||||||F\r"
    )


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


@pytest.fixture(autouse=True)
def _no_retry_pauses(monkeypatch: pytest.MonkeyPatch) -> None:
    # The TCP hold's schedule without its real pauses, as tests/test_tcp_x12_handler_failure.py does.
    monkeypatch.setattr(base_mod, "HANDLER_RETRY_DELAYS", (0.0,))


def _runner(
    store: MessageStore,
    connector: ConnectorType,
    *,
    ack_mode: AckMode = AckMode.ORIGINAL,
    allowance: RefusedBodyAllowance | None = None,
    settings: dict[str, Any] | None = None,
) -> tuple[RegistryRunner, InboundConnection]:
    ic = InboundConnection(
        name="IB_STREAM",
        spec=ConnectionSpec(connector, settings or {}),
        router="r",
        ack_mode=ack_mode,
        content_type=ContentType.HL7V2,
        stream_threshold_bytes=500,
    )
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_router("r", lambda m: [])  # no worker runs, so routing is never reached
    runner = RegistryRunner(
        reg,
        store,
        egress=EgressSettings(deny_by_default=False),
        refused_body_allowance=allowance,
    )
    return runner, ic


class _FaultingPut:
    """Stand in for ``put_attachment``: raise ``fault()`` on every call, or on the first ``faults``
    calls and then store for real, so one run can show the fault and the recovery."""

    def __init__(
        self, store: MessageStore, *, fault: Callable[[], Exception], faults: int | None = None
    ) -> None:
        self._real = store.put_attachment
        self._fault = fault
        self.faults = faults
        self.calls = 0

    async def __call__(self, chunks: Iterable[str], content_type: str) -> str:
        self.calls += 1
        if self.faults is None or self.calls <= self.faults:
            raise self._fault()
        return await self._real(chunks, content_type)


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    cur = await store._db.execute("SELECT id, status, error, raw FROM messages")
    return [dict(r) for r in await cur.fetchall()]


async def _attachment_types(store: MessageStore) -> list[str]:
    cur = await store._db.execute("SELECT content_type FROM attachment")
    return [str(r[0]) for r in await cur.fetchall()]


# --- every put_attachment fault propagates with no row --------------------------------------------


@pytest.mark.parametrize("fault", FAULTS)
async def test_every_put_attachment_fault_propagates_with_no_row(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, fault: Callable[[], Exception]
) -> None:
    # The transport answers the fault, and nothing records the body as finished. The control below,
    # on the same body, shows the injection reaches the detach.
    runner, ic = _runner(store, ConnectorType.MLLP)
    put = _FaultingPut(store, fault=fault)
    monkeypatch.setattr(store, "put_attachment", put)

    with pytest.raises(type(fault())):
        await runner._handle_inbound(ic, _doc_hl7().encode("utf-8"))

    assert put.calls == 1, "the injection never fired"
    assert await _rows(store) == []
    assert runner._stream_inflight_bytes == 0  # the budget reservation is released


async def test_control_the_same_body_is_accepted_when_the_write_succeeds(
    store: MessageStore,
) -> None:
    # Anti-vacuity for the test above: without the fault this body detaches and is ACKed AA.
    runner, ic = _runner(store, ConnectorType.MLLP)

    ack = await runner._handle_inbound(ic, _doc_hl7().encode("utf-8"))

    assert _ack_code(ack) == "AA"
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.RECEIVED.value]
    assert await _attachment_types(store) == ["Application"]


async def test_a_receipt_source_lets_the_fault_propagate(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.HTTP)
    put = _FaultingPut(store, fault=_locked)
    monkeypatch.setattr(store, "put_attachment", put)

    with pytest.raises(sqlite3.OperationalError):
        await runner._handle_inbound_http(ic, _doc_hl7().encode("utf-8"))

    assert put.calls == 1, "the injection never fired"
    assert await _rows(store) == []


async def test_an_unsupported_backend_is_still_a_permanent_refusal(store: MessageStore) -> None:
    # A refusal put_attachment raises itself stays one of the detach's refusals.
    runner, ic = _runner(store, ConnectorType.HTTP)
    store.supports_streaming_attachments = False

    receipt = await runner._handle_inbound_http(ic, _doc_hl7().encode("utf-8"))

    assert receipt.refusal is RefusalKind.PERMANENT
    error = (await _rows(store))[0]["error"]
    assert StreamingAttachmentsUnsupported.__name__ in error


async def test_a_fault_on_a_later_document_propagates_and_leaves_the_first_unreferenced(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The first document stores, the second faults: nothing increfs the first document, and the
    # budget is released. That stored document waits at refcount 0 for the startup orphan sweep, as
    # after a crash between the detach and the ingress commit.
    runner, ic = _runner(store, ConnectorType.MLLP)
    real = store.put_attachment
    calls: list[str] = []

    async def second_faults(chunks: Iterable[str], content_type: str) -> str:
        calls.append(content_type)
        if len(calls) == 2:
            raise _locked()
        return await real(chunks, content_type)

    monkeypatch.setattr(store, "put_attachment", second_faults)
    other = base64.b64encode(b"Q" * 2000).decode("ascii")
    body = _doc_hl7() + f"OBX|2|ED|PDF^Report||^Application^PDF^Base64^{other}||||||F\r"

    with pytest.raises(sqlite3.OperationalError):
        await runner._handle_inbound(ic, body.encode("utf-8"))

    assert len(calls) == 2, "the second document was never written"
    assert await _rows(store) == []
    cur = await store._db.execute("SELECT refcount FROM attachment")
    assert [r[0] for r in await cur.fetchall()] == [0]
    assert runner._stream_inflight_bytes == 0


# --- a real lone surrogate in OBX-5.5 propagates before any allowance charge ---------------------


#: A fixed clock, so the allowance never refills between the attempt and the read-back.
_ALLOWANCE = RefusedBodyPolicy(allowance_bytes=100_000, window_seconds=60.0, head_bytes=64)


def _utf7_runner(
    store: MessageStore,
) -> tuple[RegistryRunner, InboundConnection, RefusedBodyAllowance]:
    allowance = RefusedBodyAllowance(_ALLOWANCE, clock=lambda: 0.0)
    runner, ic = _runner(
        store, ConnectorType.MLLP, allowance=allowance, settings={"encoding": "utf-7"}
    )
    return runner, ic, allowance


async def test_a_lone_surrogate_document_propagates_with_no_allowance_charge(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # UTF-7 "+2D8-" decodes to the lone surrogate U+D83F, which no backend's driver can encode, so the
    # real put_attachment fails on it. It propagates before the refused-body allowance is charged:
    # recording it would charge the allowance and then fail the ERROR write on the same text, so
    # each resend would drain the allowance for every other refused body on the inbound.
    assert b"+2D8-".decode("utf-7") == "\ud83f"
    runner, ic, allowance = _utf7_runner(store)
    b64 = base64.b64encode(b"P" * 2000).decode("ascii")
    body = _doc_hl7(b64=b64[:100] + "+2D8-" + b64[100:]).encode("ascii")
    real = store.put_attachment
    raised: list[BaseException] = []

    async def spy(chunks: Iterable[str], content_type: str) -> str:
        try:
            return await real(chunks, content_type)
        except UnicodeEncodeError as exc:
            raised.append(exc)
            raise

    monkeypatch.setattr(store, "put_attachment", spy)

    with pytest.raises(UnicodeEncodeError) as escaped:
        await runner._handle_inbound(ic, body)

    assert raised == [escaped.value], "the fault did not come from the real put_attachment"
    assert await _rows(store) == []
    assert runner._stream_inflight_bytes == 0
    # The whole allowance is still there: nothing was charged.
    assert allowance.try_charge(ic.name, _ALLOWANCE.allowance_bytes)


async def test_control_a_refused_body_on_that_inbound_charges_the_allowance(
    store: MessageStore,
) -> None:
    # Anti-vacuity for the read-back above: an escaped document on the same inbound is refused and
    # recorded, and its body is charged to the allowance, so the whole allowance no longer fits.
    runner, ic, allowance = _utf7_runner(store)
    b64 = base64.b64encode(b"P" * 2000).decode("ascii")
    body = _doc_hl7(b64=b64[:100] + "\\X0D\\" + b64[100:]).encode("ascii")

    ack = await runner._handle_inbound(ic, body)

    assert _ack_code(ack) == "AR"
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.ERROR.value]
    assert not allowance.try_charge(ic.name, _ALLOWANCE.allowance_bytes)


# --- a sender-controlled OBX-5.2 label is bounded to the narrowest column ------------------------


@pytest.mark.parametrize(
    ("label", "stored"),
    [
        ("X" * 256, "X" * 256),  # the boundary is kept as declared
        ("X" * 257, "application/octet-stream"),
        # 129 characters, but 258 UTF-16 code units, which is what NVARCHAR(256) counts.
        ("\U0001d400" * 129, "application/octet-stream"),
        ("\U0001d400" * 128, "\U0001d400" * 128),
        # An HL7 \X00\ escape decodes to a NUL, which PostgreSQL TEXT refuses on every resend.
        ("Applic\\X00\\ation", "application/octet-stream"),
    ],
    ids=["256-kept", "257-downgraded", "non-bmp-258-units", "non-bmp-256-units", "nul"],
)
async def test_a_label_no_backend_column_takes_is_downgraded_before_the_write(
    store: MessageStore, label: str, stored: str
) -> None:
    # SQL Server's attachment.content_type is NVARCHAR(256): a longer label would fail with error
    # 2628 on every resend. Such a label is downgraded to the generic type, as a mislabelled one is.
    runner, ic = _runner(store, ConnectorType.MLLP)

    ack = await runner._handle_inbound(ic, _doc_hl7(type_of_data=label).encode("utf-8"))

    assert _ack_code(ack) == "AA"
    assert await _attachment_types(store) == [stored]
    (row,) = await _rows(store)
    assert f":{stored}" in row["raw"]  # the skeleton's handle names the same type


@pytest.mark.parametrize(
    ("label", "fits"),
    [("Application", True), ("Ap\x00p", False), ("X" * 300, False), ("Ap\udcffp", True)],
    ids=["plain", "nul", "long", "lone-surrogate-not-tested"],
)
def test_the_label_rule_names_what_no_backend_column_takes(label: str, fits: bool) -> None:
    assert wiring_runner._label_fits_every_backend(label) is fits


async def test_a_lone_surrogate_label_propagates_and_stores_nothing(store: MessageStore) -> None:
    # A UTF-7 inbound decodes "+2D8-" in OBX-5.2 to a lone surrogate, which stays in the skeleton too,
    # so the ingress write would fail on it whatever the label. The label is not downgraded, so the
    # real put_attachment fails first and no unreferenced attachment is left behind.
    runner, ic, allowance = _utf7_runner(store)

    with pytest.raises(UnicodeEncodeError):
        await runner._handle_inbound(ic, _doc_hl7(type_of_data="Ap+2D8-p").encode("ascii"))

    assert await _rows(store) == []
    assert await _attachment_types(store) == []
    assert runner._stream_inflight_bytes == 0
    assert allowance.try_charge(ic.name, _ALLOWANCE.allowance_bytes)


def test_the_content_type_bound_is_the_narrowest_backend_column() -> None:
    # The bound copies the stores' DDL, so a change to any backend's column must move it too.
    from messagefoundry.store import postgres, sqlserver
    from messagefoundry.store import store as sqlite_store

    def ddl(path: str) -> str:
        return Path(path).read_text(encoding="utf-8")

    width = wiring_runner._ATTACHMENT_CONTENT_TYPE_MAX
    assert f"content_type NVARCHAR({width}) NOT NULL" in ddl(sqlserver.__file__)
    assert "content_type TEXT NOT NULL" in ddl(postgres.__file__)
    assert "content_type TEXT NOT NULL" in ddl(sqlite_store.__file__)


# --- what each retrying source does with the propagated fault ------------------------------------


async def test_the_file_source_leaves_the_file_until_the_fault_clears(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.FILE)
    put = _FaultingPut(store, fault=_locked, faults=2)
    monkeypatch.setattr(store, "put_attachment", put)
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "doc.hl7"
    drop.write_bytes(_doc_hl7().encode("utf-8"))
    source = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "pattern": "*.hl7"})
    )
    source._prepare_subdirs()
    source._handler = partial(runner._handle_inbound, ic)
    # The settle poll records the stat (BACKLOG #1811); the next one reads the file.
    await source._scan_once()
    await source._scan_once()

    assert put.calls == 1, "the injection never fired"
    assert drop.exists(), "a propagated fault consumed the file"
    assert await _rows(store) == []

    for _ in range(4):  # the next scans retry until the fault clears
        if not drop.exists():
            break
        await source._scan_once()
    assert not drop.exists()
    assert put.calls == 3
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.RECEIVED.value]


async def test_the_database_source_leaves_the_row_on_a_fault(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.DATABASE)
    put = _FaultingPut(store, fault=_deadlock)
    monkeypatch.setattr(store, "put_attachment", put)
    src = _src(body_column="payload")
    cur = _SrcCursor(["id", "payload"], [(1, _doc_hl7())])
    src._pool = _SrcPool(_SrcConn(cur))
    src._handler = partial(runner._handle_inbound, ic)

    await src._poll_once()

    assert put.calls == 1, "the injection never fired"
    assert cur.marks == [], "a propagated fault marked the row, so no later poll reads it"
    assert await _rows(store) == []


async def test_a_tcp_inbound_with_no_reply_holds_the_frame_through_the_fault(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.TCP, ack_mode=AckMode.NONE)
    put = _FaultingPut(store, fault=_locked, faults=2)
    monkeypatch.setattr(store, "put_attachment", put)
    source = _tcp()
    source.ack_mode = AckMode.NONE
    source.content_type = ContentType.HL7V2
    wire = b"\x02" + _doc_hl7().encode("utf-8") + b"\x03"

    kinds = _kinds(
        await _drive(source, _ThenEof(wire), _Peer(), handler=partial(runner._handle_inbound, ic))
    )

    assert put.calls == 3, "the frame was not held and retried (BACKLOG #5022)"
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.RECEIVED.value]
    assert kinds == ["established", "closed"]
