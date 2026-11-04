# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1619 step 2, as re-cut: a ``put_attachment`` fault in the DOCUMENT is a TEMPORARY refusal.

A streaming inbound detaches its large documents with ``put_attachment`` before the ingress commit.
A fault there used to escape the runner with no message row. For a fault that recurs for the same
body, every retrying source then live-locked on it: the file source left the file for its next
scan, and MLLP answered AE and closed on every resend.

Such a fault, one ``wiring_runner._attachment_body_fault`` names (its docstring is the rule), is now
recorded as ONE ``ERROR`` row and answered as a temporary refusal: ``AE`` from the MLLP path, a
temporary refusal from a receipt source. Every other fault, a store fault that may clear among them,
still propagates exactly as before, and the tests below pin what each source then does with it.

If the ``ERROR`` write fails too, the store is down, and the failure propagates to the transport
exactly as BACKLOG #1608 pins for the ingress commit (``tests/test_ack_after_commit_invariant.py``).

Synthetic HL7 only, never real PHI.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import sqlite3
from collections.abc import AsyncIterator, Callable, Iterable
from functools import partial
from pathlib import Path
from typing import Any, NoReturn

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
from messagefoundry.transports.mllp import CR, EB, MLLPSource, frame
from messagefoundry.transports.receipt import RefusalKind
from tests.test_database_transport import _src, _SrcConn, _SrcCursor, _SrcPool
from tests.test_tcp_x12_handler_failure import _ThenEof
from tests.test_x12_connection_events import _drive, _kinds, _Peer, _tcp

# A driver message that quotes a value, as SQL Server's 2628 truncation does. It must reach neither
# the stored error nor the log.
_DRIVER_TEXT = "string or blob too big writing chunk DOE^JANE"


class _ServerDriverError(RuntimeError):
    """Shaped like a server driver's error: it carries a ``sqlstate``, as asyncpg's do, which
    ``driver_sqlstate`` reads. A ``RuntimeError`` keeps it inside ``store_call_errors``."""

    def __init__(self, sqlstate: str, text: str) -> None:
        super().__init__(text)
        self.sqlstate = sqlstate


class _PyodbcDataError(RuntimeError):
    """Shaped like ``pyodbc.DataError``: the SQLSTATE is ``args[0]``, with no ``sqlstate``."""


class _ErrorWriteFailed(RuntimeError):
    """The injected failure of the ``ERROR`` write that follows the attachment fault."""


def _deterministic() -> Exception:
    """A fault in the document: SQLite's "string or blob too big", which the same body meets again."""
    return sqlite3.DataError(_DRIVER_TEXT)


def _sqlstate_22001() -> Exception:
    return _ServerDriverError(
        "22001", "String or binary data would be truncated. Truncated value: 'DOE^JANE'. (2628)"
    )


def _locked() -> Exception:
    return sqlite3.OperationalError("database is locked")


def _deadlock() -> Exception:
    return _ServerDriverError("40001", "deadlock victim (1205)")


#: Faults in the document, each recorded and refused.
DETERMINISTIC = [
    pytest.param(_deterministic, id="sqlite-data"),
    pytest.param(
        lambda: UnicodeEncodeError("utf-8", "\udcff", 0, 1, "surrogates not allowed"),
        id="unicode",
    ),
    pytest.param(_sqlstate_22001, id="sqlstate-22001"),
]

#: Faults that may clear, or that say nothing about the document: each must propagate.
TRANSIENT = [
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
    # A decode failure is a driver's or a service's reply, not the document being written.
    pytest.param(
        lambda: UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"), id="decode"
    ),
]


def _doc_hl7(control_id: str = "MSGID001", *, type_of_data: str = "Application") -> str:
    b64 = base64.b64encode(b"P" * 2000).decode("ascii")
    return (
        f"MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||MDM^T02|{control_id}|P|2.5\r"
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
) -> tuple[RegistryRunner, InboundConnection]:
    ic = InboundConnection(
        name="IB_STREAM",
        spec=ConnectionSpec(connector, {}),
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
        self,
        store: MessageStore,
        *,
        fault: Callable[[], Exception] = _deterministic,
        faults: int | None = None,
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


def _msa_code(ack: str | None) -> str | None:
    if ack is None:
        return None
    for seg in ack.replace("\n", "\r").split("\r"):
        if seg.startswith("MSA|"):
            return seg.split("|")[1]
    return None


async def _fail_error_write(*args: Any, **kwargs: Any) -> NoReturn:
    raise _ErrorWriteFailed("injected failure of the ERROR write")


# --- the MLLP path: a fault in the document is one ERROR row and an AE ---------------------------


@pytest.mark.parametrize("fault", DETERMINISTIC)
async def test_a_fault_in_the_document_is_one_error_row_and_an_ae(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fault: Callable[[], Exception],
) -> None:
    runner, ic = _runner(store, ConnectorType.MLLP)
    put = _FaultingPut(store, fault=fault)
    monkeypatch.setattr(store, "put_attachment", put)

    with caplog.at_level(logging.WARNING, logger=wiring_runner.__name__):
        ack = await runner._handle_inbound(ic, _doc_hl7().encode("utf-8"))

    assert put.calls == 1, "the injection never fired"
    assert _msa_code(ack) == "AE"
    assert ack is not None and "streaming detach failed" in ack
    rows = await _rows(store)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]
    error = rows[0]["error"]
    assert "attachment write failed" in error and type(fault()).__qualname__ in error
    assert await store.in_pipeline_depth() == 0  # refused, never handed to the ingress stage
    assert runner._stream_inflight_bytes == 0  # the budget reservation is released
    # The driver's text, which can quote a value, reaches neither the row nor the log.
    assert "DOE^JANE" not in error and "too big" not in error and "Truncated" not in error
    logged = [r.getMessage() for r in caplog.records if "attachment write failed" in r.getMessage()]
    assert len(logged) == 1 and "IB_STREAM" in logged[0]
    assert "DOE^JANE" not in caplog.text and "Truncated" not in caplog.text


async def test_a_sqlstate_class_22_fault_keeps_its_sqlstate_in_the_row(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.MLLP)
    monkeypatch.setattr(store, "put_attachment", _FaultingPut(store, fault=_sqlstate_22001))

    await runner._handle_inbound(ic, _doc_hl7().encode("utf-8"))

    assert "SQLSTATE 22001" in (await _rows(store))[0]["error"]


@pytest.mark.parametrize("fault", TRANSIENT)
async def test_any_other_fault_propagates_with_no_row(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, fault: Callable[[], Exception]
) -> None:
    # A fault that may clear, or that says nothing about the document, propagates exactly as before
    # #1619's first commit: the transport answers it, and nothing records the body as finished. The
    # test above, on the same body, is the control that the injection reaches the detach.
    runner, ic = _runner(store, ConnectorType.MLLP)
    put = _FaultingPut(store, fault=fault)
    monkeypatch.setattr(store, "put_attachment", put)

    with pytest.raises(type(fault())):
        await runner._handle_inbound(ic, _doc_hl7().encode("utf-8"))

    assert put.calls == 1
    assert await _rows(store) == []
    assert runner._stream_inflight_bytes == 0


async def test_control_the_same_body_is_accepted_when_the_write_succeeds(
    store: MessageStore,
) -> None:
    # Anti-vacuity for the tests above: without the fault this body detaches and is ACKed AA.
    runner, ic = _runner(store, ConnectorType.MLLP)

    ack = await runner._handle_inbound(ic, _doc_hl7().encode("utf-8"))

    assert _msa_code(ack) == "AA"
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.RECEIVED.value]
    assert await _attachment_types(store) == ["Application"]


# --- a sender-controlled OBX-5.2 label is bounded to the narrowest column ------------------------


@pytest.mark.parametrize(
    ("label", "stored"),
    [
        ("X" * 256, "X" * 256),  # the boundary is kept as declared
        ("X" * 257, "application/octet-stream"),
        # 129 characters, but 258 UTF-16 code units, which is what NVARCHAR(256) counts.
        ("\U0001d400" * 129, "application/octet-stream"),
        ("\U0001d400" * 128, "\U0001d400" * 128),
    ],
    ids=["256-kept", "257-downgraded", "non-bmp-258-units", "non-bmp-256-units"],
)
async def test_a_long_content_type_is_bounded_before_the_write(
    store: MessageStore, label: str, stored: str
) -> None:
    # SQL Server's attachment.content_type is NVARCHAR(256): a longer label would fail with error
    # 2628 on every resend. It is downgraded to the generic type, as a mislabelled one is.
    runner, ic = _runner(store, ConnectorType.MLLP)

    ack = await runner._handle_inbound(ic, _doc_hl7(type_of_data=label).encode("utf-8"))

    assert _msa_code(ack) == "AA"
    assert await _attachment_types(store) == [stored]
    (row,) = await _rows(store)
    assert f":{stored}" in row["raw"]  # the skeleton's handle names the same type


async def test_a_label_holding_a_nul_is_downgraded_before_the_write(store: MessageStore) -> None:
    # An HL7 \X00\ escape decodes to a NUL, which PostgreSQL TEXT refuses on every resend.
    runner, ic = _runner(store, ConnectorType.MLLP)

    ack = await runner._handle_inbound(
        ic, _doc_hl7(type_of_data="Applic\\X00\\ation").encode("utf-8")
    )

    assert _msa_code(ack) == "AA"
    assert await _attachment_types(store) == ["application/octet-stream"]


def test_the_content_type_bound_is_the_sql_server_column_width() -> None:
    # The bound copies the store's DDL, so a change to the column must move it too.
    from messagefoundry.store import sqlserver

    source = Path(sqlserver.__file__).read_text(encoding="utf-8")
    width = wiring_runner._ATTACHMENT_CONTENT_TYPE_MAX
    assert f"content_type NVARCHAR({width}) NOT NULL" in source


async def test_a_pyodbc_shaped_class_22_fault_is_the_documents(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SQL Server's driver carries the SQLSTATE in args[0], read only for a server driver's own
    # error. The stand-in joins the production list, as tests/test_keyless_chain_every_command.py
    # does for drivers a leg may not have installed; a RuntimeError keeps it inside the catch.
    from messagefoundry.store import base as store_base

    drivers = store_base.store_driver_errors()
    monkeypatch.setattr(store_base, "store_driver_errors", lambda: (*drivers, _PyodbcDataError))
    runner, ic = _runner(store, ConnectorType.MLLP)
    text = "[22001] String or binary data would be truncated. Truncated value: 'DOE^JANE'. (2628)"
    monkeypatch.setattr(
        store, "put_attachment", _FaultingPut(store, fault=lambda: _PyodbcDataError("22001", text))
    )

    ack = await runner._handle_inbound(ic, _doc_hl7().encode("utf-8"))

    assert _msa_code(ack) == "AE"
    error = (await _rows(store))[0]["error"]
    assert "SQLSTATE 22001" in error and "DOE^JANE" not in error


# --- a receipt source: a TEMPORARY refusal that names the row ------------------------------------


async def test_a_receipt_source_gets_a_temporary_refusal_naming_the_error_row(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.HTTP)
    monkeypatch.setattr(store, "put_attachment", _FaultingPut(store))

    receipt = await runner._handle_inbound_http(ic, _doc_hl7().encode("utf-8"))

    assert receipt.refusal is RefusalKind.TEMPORARY
    rows = await _rows(store)
    assert [(r["id"], r["status"]) for r in rows] == [
        (receipt.message_id, MessageStatus.ERROR.value)
    ]
    assert rows[0]["error"].startswith("[refusal kind: temporary] ")


async def test_a_receipt_source_lets_a_transient_fault_propagate(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.HTTP)
    monkeypatch.setattr(store, "put_attachment", _FaultingPut(store, fault=_locked))

    with pytest.raises(sqlite3.OperationalError):
        await runner._handle_inbound_http(ic, _doc_hl7().encode("utf-8"))

    assert await _rows(store) == []


async def test_an_unsupported_backend_is_still_a_permanent_refusal(store: MessageStore) -> None:
    # A refusal put_attachment raises itself is re-raised untouched, so it is not relabelled.
    runner, ic = _runner(store, ConnectorType.HTTP)
    store.supports_streaming_attachments = False

    receipt = await runner._handle_inbound_http(ic, _doc_hl7().encode("utf-8"))

    assert receipt.refusal is RefusalKind.PERMANENT
    error = (await _rows(store))[0]["error"]
    assert StreamingAttachmentsUnsupported.__name__ in error
    assert "attachment write failed" not in error


async def test_a_fault_on_a_later_document_refuses_the_whole_body(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The first document stores, the second faults: the body is refused, nothing increfs the first
    # document, and the budget is released. That stored document waits at refcount 0 for the
    # startup orphan sweep, as after a crash between the detach and the ingress commit.
    runner, ic = _runner(store, ConnectorType.MLLP)
    real = store.put_attachment
    calls: list[str] = []

    async def second_faults(chunks: Iterable[str], content_type: str) -> str:
        calls.append(content_type)
        if len(calls) == 2:
            raise _deterministic()
        return await real(chunks, content_type)

    monkeypatch.setattr(store, "put_attachment", second_faults)
    other = base64.b64encode(b"Q" * 2000).decode("ascii")
    body = _doc_hl7() + f"OBX|2|ED|PDF^Report||^Application^PDF^Base64^{other}||||||F\r"

    ack = await runner._handle_inbound(ic, body.encode("utf-8"))

    assert len(calls) == 2, "the second document was never written"
    assert _msa_code(ack) == "AE"
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.ERROR.value]
    cur = await store._db.execute("SELECT refcount FROM attachment")
    assert [r[0] for r in await cur.fetchall()] == [0]
    assert runner._stream_inflight_bytes == 0


@pytest.mark.parametrize("bug", [TypeError, AttributeError])
async def test_a_bug_in_the_store_code_still_propagates(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, bug: type[Exception]
) -> None:
    # A programming error is not a fault in the document, so it is not answered as one.
    runner, ic = _runner(store, ConnectorType.MLLP)

    async def broken(*args: Any, **kwargs: Any) -> NoReturn:
        raise bug("a bug in put_attachment")

    monkeypatch.setattr(store, "put_attachment", broken)

    with pytest.raises(bug):
        await runner._handle_inbound(ic, _doc_hl7().encode("utf-8"))

    assert await _rows(store) == []
    assert runner._stream_inflight_bytes == 0


# --- the store is down: the ERROR write fails too, and that propagates ----------------------------


@pytest.mark.parametrize(
    ("connector", "entry"),
    [(ConnectorType.MLLP, "_handle_inbound"), (ConnectorType.HTTP, "_handle_inbound_http")],
)
async def test_a_failed_error_write_after_the_fault_propagates(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, connector: ConnectorType, entry: str
) -> None:
    runner, ic = _runner(store, connector)
    monkeypatch.setattr(store, "put_attachment", _FaultingPut(store))
    monkeypatch.setattr(store, "record_received", _fail_error_write)

    # No frame or receipt comes back from the runner: the transport answers the propagated fault
    # (BACKLOG #1608).
    with pytest.raises(_ErrorWriteFailed) as raised:
        await getattr(runner, entry)(ic, _doc_hl7().encode("utf-8"))

    # The driver's error, whose text can quote a value, is not chained onto what the transport
    # renders: only the content-free _AttachmentWriteFailed is.
    chain: list[BaseException] = []
    link: BaseException | None = raised.value
    while link is not None:
        chain.append(link)
        link = link.__cause__ or link.__context__
    assert not any(isinstance(e, sqlite3.Error) for e in chain), chain
    assert any(isinstance(e, wiring_runner._AttachmentWriteFailed) for e in chain), chain
    assert await _rows(store) == []
    assert runner._stream_inflight_bytes == 0


# --- the file source: archive on a fault in the document, leave the file on any other ------------


async def _drop_and_read(
    runner: RegistryRunner, ic: InboundConnection, tmp_path: Path, body: str | None = None
) -> tuple[FileSource, Path]:
    """Drop one body in a fresh inbox, then scan until the file source has read it once: the
    settle poll records the stat (BACKLOG #1811), the next one reads the file and hands it off."""
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "doc.hl7"
    drop.write_bytes((body or _doc_hl7()).encode("utf-8"))
    source = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "pattern": "*.hl7"})
    )
    source._prepare_subdirs()
    source._handler = partial(runner._handle_inbound, ic)
    if source.polls_shared_resource:
        runner._refusals_kept_whole.add(ic.name)  # what binding a poll source sets
    await source._scan_once()
    await source._scan_once()
    return source, drop


async def test_the_file_source_archives_a_file_whose_document_write_failed(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.FILE)
    monkeypatch.setattr(store, "put_attachment", _FaultingPut(store))
    source, drop = await _drop_and_read(runner, ic, tmp_path)

    assert not drop.exists(), "the file was left in place to be re-read on every scan"
    assert len(list((drop.parent / ".processed").iterdir())) == 1
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.ERROR.value]

    # A further scan finds nothing, so no second ERROR row: the source does not live-lock.
    await source._scan_once()
    assert len(await _rows(store)) == 1


async def test_the_file_source_leaves_the_file_on_a_transient_fault(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.FILE)
    put = _FaultingPut(store, fault=_locked, faults=2)
    monkeypatch.setattr(store, "put_attachment", put)
    source, drop = await _drop_and_read(runner, ic, tmp_path)  # the first read faults

    assert put.calls == 1, "the injection never fired"
    assert drop.exists(), "a transient fault consumed the file"
    assert await _rows(store) == []

    for _ in range(4):  # the next scans retry until the fault clears
        if not drop.exists():
            break
        await source._scan_once()
    assert not drop.exists()
    assert put.calls == 3
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.RECEIVED.value]


async def test_a_poll_sources_error_row_keeps_the_whole_body_past_the_allowance(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The file source deletes the only copy, so its ERROR row must hold the whole body even when
    # the refused-body allowance is spent; a listener's row would keep only a head (the control).
    policy = RefusedBodyPolicy(allowance_bytes=0, window_seconds=60.0, head_bytes=512)
    body = _doc_hl7()
    assert len(body.encode("utf-8")) > policy.head_bytes

    runner, ic = _runner(store, ConnectorType.FILE, allowance=RefusedBodyAllowance(policy))
    monkeypatch.setattr(store, "put_attachment", _FaultingPut(store))
    await _drop_and_read(runner, ic, tmp_path, body)
    (row,) = await _rows(store)
    assert row["status"] == MessageStatus.ERROR.value
    assert row["raw"] == body

    listener, lic = _runner(store, ConnectorType.MLLP, allowance=RefusedBodyAllowance(policy))
    await listener._handle_inbound(lic, body.encode("utf-8"))
    head = [r for r in await _rows(store) if r["id"] != row["id"]]
    assert len(head) == 1 and head[0]["raw"] != body and len(head[0]["raw"]) <= policy.head_bytes


# --- the DATABASE source: mark on a fault in the document, leave the row on any other ------------


def _db_source(runner: RegistryRunner, ic: InboundConnection, body: str) -> tuple[Any, _SrcCursor]:
    src = _src(body_column="payload")
    cur = _SrcCursor(["id", "payload"], [(1, body)])
    src._pool = _SrcPool(_SrcConn(cur))
    src._handler = partial(runner._handle_inbound, ic)
    if src.polls_shared_resource:
        runner._refusals_kept_whole.add(ic.name)  # what binding a poll source sets
    return src, cur


async def test_the_database_source_marks_a_row_whose_document_write_failed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.DATABASE)
    monkeypatch.setattr(store, "put_attachment", _FaultingPut(store))
    body = _doc_hl7()
    src, cur = _db_source(runner, ic, body)

    await src._poll_once()

    assert len(cur.marks) == 1, "the row was left to be re-read on every poll"
    (row,) = await _rows(store)
    assert row["status"] == MessageStatus.ERROR.value and row["raw"] == body


async def test_the_database_source_leaves_the_row_on_a_transient_fault(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.DATABASE)
    put = _FaultingPut(store, fault=_deadlock)
    monkeypatch.setattr(store, "put_attachment", put)
    src, cur = _db_source(runner, ic, _doc_hl7())

    await src._poll_once()

    assert put.calls == 1, "the injection never fired"
    assert cur.marks == [], "a transient fault marked the row, so no later poll reads it"
    assert await _rows(store) == []


# --- a TCP inbound with no reply: a transient fault keeps the #5022 hold -------------------------


async def _drive_tcp_none(runner: RegistryRunner, ic: InboundConnection) -> list[str]:
    source = _tcp()
    source.ack_mode = AckMode.NONE
    source.content_type = ContentType.HL7V2
    wire = b"\x02" + _doc_hl7().encode("utf-8") + b"\x03"
    return _kinds(
        await _drive(source, _ThenEof(wire), _Peer(), handler=partial(runner._handle_inbound, ic))
    )


async def test_a_tcp_inbound_with_no_reply_holds_the_frame_through_a_transient_fault(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.TCP, ack_mode=AckMode.NONE)
    put = _FaultingPut(store, fault=_locked, faults=2)
    monkeypatch.setattr(store, "put_attachment", put)

    kinds = await _drive_tcp_none(runner, ic)

    assert put.calls == 3, "the frame was not held and retried"
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.RECEIVED.value]
    assert kinds == ["established", "closed"]


async def test_control_a_fault_in_the_document_on_that_inbound_is_one_error_row(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The same inbound and frame with a fault the body meets every time: recorded at once, with no
    # hold, so the sender is not stalled on a frame no retry can store.
    runner, ic = _runner(store, ConnectorType.TCP, ack_mode=AckMode.NONE)
    put = _FaultingPut(store)
    monkeypatch.setattr(store, "put_attachment", put)

    kinds = await _drive_tcp_none(runner, ic)

    assert put.calls == 1
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.ERROR.value]
    assert kinds == ["established", "closed"]


# --- MLLP over a socket: AE, and the connection stays up for the next frame ----------------------


async def _read_reply(reader: asyncio.StreamReader, timeout: float = 3.0) -> bytes:
    with contextlib.suppress(ConnectionResetError, asyncio.IncompleteReadError):
        return await asyncio.wait_for(reader.readuntil(bytes([EB, CR])), timeout)
    return b""


async def test_the_mllp_listener_answers_ae_and_keeps_the_connection(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.MLLP)
    monkeypatch.setattr(store, "put_attachment", _FaultingPut(store, faults=1))
    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0},
            ack_mode=AckMode.ORIGINAL,
        )
    )

    await source.start(partial(runner._handle_inbound, ic))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
        try:
            writer.write(frame(_doc_hl7("MSG1")))
            await writer.drain()
            assert b"MSA|AE|MSG1|" in await _read_reply(reader)
            # The same socket takes the next frame: a refusal, not a handler fault, so the listener
            # does not close the connection after it (PR 1583 closes only on a fault).
            writer.write(frame(_doc_hl7("MSG2")))
            await writer.drain()
            assert b"MSA|AA|MSG2\r" in await _read_reply(reader)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
    finally:
        await source.stop()

    assert sorted(r["status"] for r in await _rows(store)) == [
        MessageStatus.ERROR.value,
        MessageStatus.RECEIVED.value,
    ]
