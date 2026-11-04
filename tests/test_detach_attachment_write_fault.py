# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1619 step 2, as re-cut: a ``put_attachment`` fault is a TEMPORARY refusal.

A streaming inbound detaches its large documents with ``put_attachment`` before the ingress commit.
A driver or cipher fault there used to escape the runner with no message row. With the store UP and
a fault that recurs for the same body, every retrying source then live-locked on it: the file source
left the file for its next scan, and MLLP answered AE and closed on every resend.

The fault is now recorded as ONE ``ERROR`` row and answered as a temporary refusal: ``AE`` from the
MLLP path, a temporary refusal from a receipt source. If that ``ERROR`` write fails too, the store
is down, and the failure propagates to the transport exactly as BACKLOG #1608 pins for the ingress
commit (``tests/test_ack_after_commit_invariant.py``).

Synthetic HL7 only, never real PHI.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import sqlite3
from collections.abc import AsyncIterator, Iterable
from functools import partial
from pathlib import Path
from typing import Any, NoReturn

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, ContentType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, StreamingAttachmentsUnsupported
from messagefoundry.transports.file import FileSource
from messagefoundry.transports.mllp import CR, EB, MLLPSource, frame
from messagefoundry.transports.receipt import RefusalKind

# A driver message that quotes a value, as SQL Server's 2628 truncation does. It must reach neither
# the stored error nor the log.
_DRIVER_TEXT = "disk I/O error writing chunk DOE^JANE"


class _ErrorWriteFailed(RuntimeError):
    """The injected failure of the ``ERROR`` write that follows the attachment fault."""


def _doc_hl7(control_id: str = "MSGID001") -> str:
    b64 = base64.b64encode(b"P" * 2000).decode("ascii")
    return (
        f"MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||MDM^T02|{control_id}|P|2.5\r"
        "EVN|T02|20260101120000\r"
        "PID|1||MRN123^^^FAC||DOE^JANE\r"
        f"OBX|1|ED|PDF^Report||^Application^PDF^Base64^{b64}||||||F\r"
    )


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _runner(
    store: MessageStore, connector: ConnectorType
) -> tuple[RegistryRunner, InboundConnection]:
    ic = InboundConnection(
        name="IB_STREAM",
        spec=ConnectionSpec(connector, {}),
        router="r",
        ack_mode=AckMode.ORIGINAL,
        content_type=ContentType.HL7V2,
        stream_threshold_bytes=500,
    )
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_router("r", lambda m: [])  # no worker runs, so routing is never reached
    return RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False)), ic


class _FaultingPut:
    """Stand in for ``put_attachment``: raise a driver error on every call, or on the first ``faults``
    calls and then store for real, so one run can show the fault and the recovery."""

    def __init__(self, store: MessageStore, *, faults: int | None = None) -> None:
        self._real = store.put_attachment
        self.faults = faults
        self.calls = 0

    async def __call__(self, chunks: Iterable[str], content_type: str) -> str:
        self.calls += 1
        if self.faults is None or self.calls <= self.faults:
            raise sqlite3.OperationalError(_DRIVER_TEXT)
        return await self._real(chunks, content_type)


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    cur = await store._db.execute("SELECT id, status, error FROM messages")
    return [dict(r) for r in await cur.fetchall()]


async def _attachment_count(store: MessageStore) -> int:
    cur = await store._db.execute("SELECT COUNT(*) FROM attachment")
    row = await cur.fetchone()
    assert row is not None
    return int(row[0])


def _msa_code(ack: str | None) -> str | None:
    if ack is None:
        return None
    for seg in ack.replace("\n", "\r").split("\r"):
        if seg.startswith("MSA|"):
            return seg.split("|")[1]
    return None


async def _fail_error_write(*args: Any, **kwargs: Any) -> NoReturn:
    raise _ErrorWriteFailed("injected failure of the ERROR write")


# --- the MLLP path: one ERROR row and an AE ------------------------------------------------------


async def test_a_put_attachment_fault_is_one_error_row_and_an_ae(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    runner, ic = _runner(store, ConnectorType.MLLP)
    put = _FaultingPut(store)
    monkeypatch.setattr(store, "put_attachment", put)

    with caplog.at_level(logging.WARNING, logger=wiring_runner.__name__):
        ack = await runner._handle_inbound(ic, _doc_hl7().encode("utf-8"))

    assert put.calls == 1, "the injection never fired"
    assert _msa_code(ack) == "AE"
    assert ack is not None and "streaming detach failed" in ack
    rows = await _rows(store)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]
    error = rows[0]["error"]
    assert "attachment write failed" in error and "sqlite3.OperationalError" in error
    assert await store.in_pipeline_depth() == 0  # refused, never handed to the ingress stage
    assert runner._stream_inflight_bytes == 0  # the budget reservation is released
    # The driver's text, which can quote a value, reaches neither the row nor the log.
    assert "DOE" not in error and "disk I/O" not in error
    logged = [r.getMessage() for r in caplog.records if "attachment write failed" in r.getMessage()]
    assert len(logged) == 1 and "IB_STREAM" in logged[0]
    assert "DOE" not in caplog.text and "disk I/O" not in caplog.text


async def test_control_the_same_body_is_accepted_when_the_write_succeeds(
    store: MessageStore,
) -> None:
    # Anti-vacuity for the test above: without the fault this body detaches and is ACKed AA.
    runner, ic = _runner(store, ConnectorType.MLLP)

    ack = await runner._handle_inbound(ic, _doc_hl7().encode("utf-8"))

    assert _msa_code(ack) == "AA"
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.RECEIVED.value]
    assert await _attachment_count(store) == 1


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


async def test_an_unsupported_backend_is_still_a_permanent_refusal(store: MessageStore) -> None:
    # The wrap re-raises a refusal put_attachment raises itself, so it is not relabelled temporary.
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
            raise sqlite3.OperationalError(_DRIVER_TEXT)
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
    # A programming error is not a store fault, so it is not answered as one a resend may clear.
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


# --- the file source archives the refused file instead of re-reading it ---------------------------


async def test_the_file_source_archives_a_file_whose_attachment_write_failed(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store, ConnectorType.FILE)
    monkeypatch.setattr(store, "put_attachment", _FaultingPut(store))
    inbox = tmp_path / "in"
    inbox.mkdir()
    drop = inbox / "doc.hl7"
    drop.write_bytes(_doc_hl7().encode("utf-8"))
    source = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "pattern": "*.hl7"})
    )
    source._prepare_subdirs()
    source._handler = partial(runner._handle_inbound, ic)
    await source._scan_once()  # the settle poll records the stat (BACKLOG #1811)
    await source._scan_once()  # this one reads the file and hands it off

    assert not drop.exists(), "the file was left in place to be re-read on every scan"
    assert len(list((inbox / ".processed").iterdir())) == 1
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.ERROR.value]

    # A further scan finds nothing, so no second ERROR row: the source does not live-lock.
    await source._scan_once()
    assert len(await _rows(store)) == 1


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
            # The same socket takes the resend once the fault clears: a refusal, not a handler fault,
            # so the listener does not close the connection after it (PR 1583 closes only on a fault).
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
