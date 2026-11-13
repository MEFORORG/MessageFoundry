# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Embedded-document (base64 attachment) pruning (#47, ADR 0042).

A per-connection ``prune_documents_after`` window drives an in-place strip of bulky base64 embedded
documents: on a ``RetentionRunner`` pass past the window, each ``mfb64:v1:`` carriage value / HL7 OBX-5
ED embed is replaced by a small self-describing tombstone (size + content-type + ``pruned <ts>``) while
the surrounding message stays byte-stable and parseable, the row is never deleted, and the message's
``documents_pruned`` flag is set (orthogonal to its disposition). One audit row per pass records the
windows + counts + bytes reclaimed (no content). Codec-driven (never raw string-slicing): the strip
goes through :mod:`messagefoundry.parsing.binary` / the parsed :class:`Message` model.

These cover the ADR 0042 EARS criteria AC-1..AC-7. The store-level cases run on **all three backends**
for parity (AC-4): SQLite always; Postgres / SQL Server skipif-gated on ``MEFOR_TEST_POSTGRES`` /
``MEFOR_TEST_SQLSERVER`` (+ ``MEFOR_STORE_*`` connection env), exactly like the sibling
``tests/test_per_connection_retention.py``."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sqlite3
import sys
import threading
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from messagefoundry.config.settings import RetentionSettings
from messagefoundry.config.wiring import (
    MLLP,
    Registry,
    build_inbound_connection,
)
from messagefoundry.parsing import binary
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.retention import RetentionRunner
from messagefoundry.store import MessageStore, document_strip
from messagefoundry.store.cell_tag import CellTagError
from messagefoundry.store.crypto import CipherUnavailableError, IdentityCipher
from messagefoundry.store.document_strip import StripResult
from messagefoundry.store.store import OutboxStatus

DAY = 86_400.0
PRUNED_AT = 1_700_000_000.0

# A bulky synthetic document (no PHI — repeated ASCII), big enough to dwarf the tombstone.
DOC = b"SYNTHETIC-DOCUMENT-BYTES " * 400  # ~10 KB
MFB64_BODY = binary.encode(DOC)  # a whole-body mfb64:v1: carriage value
# An HL7 message carrying the same document as an OBX-5 ED embed.
_BASE_HL7 = "MSH|^~\\&|SEND|FAC|RECV|FAC|20240101000000||ORU^R01|MSG0001|P|2.5\rOBX|1|ED|||"


def _hl7_with_ed() -> str:
    msg = Message.parse(_BASE_HL7)
    binary.embed_obx_document(msg, DOC, data_subtype="PDF")
    return msg.encode()


HL7_ED_BODY = _hl7_with_ed()
_DB_NAME = "embedded_doc_pruning.db"


# --- backend fixtures (SQLite always; PG/SQLServer skipif-gated) ---------------

_PG = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres parity case",
)
_MSSQL = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the SQL Server parity case",
)


async def _open_sqlite(tmp_path) -> MessageStore:
    return await MessageStore.open(tmp_path / _DB_NAME)


async def _open_postgres(_tmp_path):  # pragma: no cover - only runs when gated on
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    async with s._pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE message_events, audit_log, queue, response, delivered_keys, messages "
            "RESTART IDENTITY CASCADE"
        )
    return s


async def _open_sqlserver(_tmp_path):  # pragma: no cover - only runs when gated on
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    async with s._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in (
            "message_events",
            "audit_log",
            "queue",
            "response",
            "delivered_keys",
            "messages",
        ):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    return s


@pytest.fixture(
    params=[
        pytest.param(_open_sqlite, id="sqlite"),
        pytest.param(_open_postgres, id="postgres", marks=_PG),
        pytest.param(_open_sqlserver, id="sqlserver", marks=_MSSQL),
    ]
)
async def store(request, tmp_path) -> AsyncIterator[MessageStore]:
    s = await request.param(tmp_path)
    yield s
    await s.close()


# --- helpers: drive a message on a NAMED connection to a terminal state --------


async def _delivered(
    store: MessageStore, *, channel_id: str, raw: str, now: float, control: str
) -> str:
    """Enqueue → claim → mark_done so the message is fully terminal (no in-flight row)."""
    mid = await store.enqueue_message(
        channel_id=channel_id,
        raw=raw,
        deliveries=[("OB", "OUT|delivered")],
        control_id=control,
        now=now,
    )
    [row] = await store.outbox_for(mid)
    await store.claim_ready(now=now)
    await store.mark_done(row["id"], now=now)
    return mid


async def _get(store: MessageStore, mid: str) -> dict:
    rec = await store.get_message(mid)
    assert rec is not None
    return rec


# --- AC-1: mfb64 whole-body blob stripped to a tombstone -----------------------


async def test_mfb64_blob_stripped_to_tombstone(store: MessageStore) -> None:
    """AC-1: a connection past its ``prune_documents_after`` window has its ``mfb64:v1:`` embedded
    document replaced by a tombstone (size + content-type + pruned ts), and the rest of the body is
    left byte-stable (here the whole body WAS the blob)."""
    mid = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-MFB64")

    now = 5 * DAY
    result = await store.strip_embedded_documents(
        older_than=float("-inf"),  # no global default
        now=PRUNED_AT,
        connection_cutoffs={"IB": now - 1 * DAY},  # 1-day window, elapsed
        content_types={"IB": "application/pdf"},
    )

    assert (result.messages_stripped, result.documents_stripped) == (1, 1)
    assert result.bytes_reclaimed > 0
    stripped = (await _get(store, mid))["raw"]
    assert binary.is_document_tombstone(stripped)
    assert not binary.is_marked(stripped)  # no longer a binary-carriage value
    assert f"{len(DOC)}" in stripped and "application/pdf" in stripped  # self-describing
    assert DOC.decode() not in stripped  # the actual document bytes are gone


# --- AC-2: OBX-5 ED stripped via the parsed model and re-parses ----------------


async def test_obx5_ed_stripped_and_reparses(store: MessageStore) -> None:
    """AC-2: an HL7 OBX-5 ED embedded document is stripped via the parsed model (no raw string-slicing)
    and the stripped message re-parses cleanly — the surrounding segments survive, OBX-5.5 carries the
    tombstone, and OBX-5.4 (the Base64 encoding marker) is cleared so it is no longer decodable."""
    mid = await _delivered(store, channel_id="IB", raw=HL7_ED_BODY, now=0.0, control="C-ED")

    now = 5 * DAY
    result = await store.strip_embedded_documents(
        older_than=float("-inf"),
        now=PRUNED_AT,
        connection_cutoffs={"IB": now - 1 * DAY},
        content_types={"IB": "hl7v2"},
    )

    assert (result.messages_stripped, result.documents_stripped) == (1, 1)
    stripped = (await _get(store, mid))["raw"]
    msg = Message.parse(stripped)  # re-parses cleanly
    assert msg.segments() == ["MSH", "OBX"]
    assert binary.is_document_tombstone(msg.field("OBX-5.5") or "")
    assert msg.field("OBX-5.4") is None  # encoding marker dropped
    assert DOC.decode() not in stripped


# --- AC-3: an in-flight body is never stripped ---------------------------------


async def test_in_flight_body_not_stripped(store: MessageStore) -> None:
    """AC-3: a body still pending/inflight is NOT stripped even when its per-connection window has
    elapsed — the cutoff AND-s the never-strip-an-in-flight-body guard (at-least-once preserved)."""
    mid = await store.enqueue_message(
        channel_id="IB", raw=MFB64_BODY, deliveries=[("OB", "p")], control_id="C-INF", now=0.0
    )  # left PENDING (never claimed/delivered)

    now = 100 * DAY
    result = await store.strip_embedded_documents(
        older_than=float("-inf"),
        now=PRUNED_AT,
        connection_cutoffs={"IB": now - 1 * DAY},  # aggressive, long-elapsed window
    )

    assert result.messages_stripped == 0
    rec = await _get(store, mid)
    assert rec["raw"] == MFB64_BODY  # untouched
    assert rec["documents_pruned"] is None  # flag not set


# --- AC-4: three-backend parity (store cases run on each backend) --------------


async def test_three_backend_parity(store: MessageStore) -> None:
    """AC-4: the in-place strip produces identical results across SQLite / Postgres / SQL Server. The
    ``store`` fixture is parametrized over all three backends (PG/SQL Server skipif-gated), so this runs
    the combined mfb64 + OBX-5 ED scenario on each and a divergence in any backend's strip fails."""
    a = await _delivered(store, channel_id="IB_A", raw=MFB64_BODY, now=0.0, control="P-A")
    b = await _delivered(store, channel_id="IB_B", raw=HL7_ED_BODY, now=0.0, control="P-B")
    # An inheriting sibling with NO window (not in the cutoff map) is never stripped.
    c = await _delivered(store, channel_id="IB_NONE", raw=MFB64_BODY, now=0.0, control="P-C")

    now = 5 * DAY
    result = await store.strip_embedded_documents(
        older_than=float("-inf"),
        now=PRUNED_AT,
        connection_cutoffs={"IB_A": now - 1 * DAY, "IB_B": now - 1 * DAY},
    )

    assert (result.messages_stripped, result.documents_stripped) == (2, 2)
    assert binary.is_document_tombstone((await _get(store, a))["raw"])
    assert binary.is_document_tombstone(
        Message.parse((await _get(store, b))["raw"]).field("OBX-5.5") or ""
    )
    assert (await _get(store, c))["raw"] == MFB64_BODY  # no window → untouched


# --- AC-6: no window configured → nothing stripped (back-compat) ---------------


async def test_no_window_no_strip(store: MessageStore) -> None:
    """AC-6: with NO ``prune_documents_after`` (empty/omitted cutoff map), no document is stripped — a
    deployment that never opts in is byte-identical."""
    mid = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-NONE")

    result = await store.strip_embedded_documents(older_than=float("-inf"), now=PRUNED_AT)

    assert result.messages_stripped == 0
    rec = await _get(store, mid)
    assert rec["raw"] == MFB64_BODY and rec["documents_pruned"] is None


# --- AC-7: sets the documents_pruned flag; disposition/count unchanged ---------


async def test_sets_pruned_flag_disposition_unchanged(store: MessageStore) -> None:
    """AC-7: a stripped message gets its distinct ``documents_pruned`` timestamp set (evicted vs never
    present) and its row is NOT deleted and its ``status`` (disposition) is unchanged."""
    mid = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-FLAG")
    before = await _get(store, mid)

    now = 5 * DAY
    await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": now - 1 * DAY}
    )

    after = await _get(store, mid)
    assert after["documents_pruned"] == PRUNED_AT  # flag set to the prune timestamp
    assert after["status"] == before["status"]  # disposition unchanged
    assert after["id"] == mid  # row not deleted


async def test_below_threshold_not_stripped(store: MessageStore) -> None:
    """A document smaller than ``min_bytes`` is left intact — the size threshold (ADR 0042 D1)."""
    small = binary.encode(b"tiny")
    mid = await _delivered(store, channel_id="IB", raw=small, now=0.0, control="C-SMALL")

    now = 5 * DAY
    result = await store.strip_embedded_documents(
        older_than=float("-inf"),
        now=PRUNED_AT,
        connection_cutoffs={"IB": now - 1 * DAY},
        min_bytes=1024,  # the 4-byte doc is far below
    )

    assert result.messages_stripped == 0
    assert (await _get(store, mid))["raw"] == small


async def test_unreadable_delimiters_skip_is_logged_once_per_strip_call(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """A row whose HL7 delimiters cannot be read (an MSH-2 shorter than four characters) is left
    as stored, so its document outlives the window; the pass logs that at WARNING, once, naming
    the count and an unreadable row's message id and no byte of a body (BACKLOG #5099). A
    readable row stripped in the same pass is the control: it is stripped, and adds nothing to
    the record."""
    short = HL7_ED_BODY.replace("MSH|^~\\&|", "MSH|^~\\|", 1)
    assert short != HL7_ED_BODY
    first = await _delivered(store, channel_id="IB", raw=short, now=0.0, control="C-UNR1")
    second = await _delivered(store, channel_id="IB", raw=short, now=0.0, control="C-UNR2")
    readable = await _delivered(store, channel_id="IB", raw=HL7_ED_BODY, now=0.0, control="C-READ")

    now = 5 * DAY
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.document_strip"):
        result = await store.strip_embedded_documents(
            older_than=float("-inf"),
            now=PRUNED_AT,
            connection_cutoffs={"IB": now - 1 * DAY},
        )

    assert (result.messages_stripped, result.documents_stripped) == (1, 1)
    assert (await _get(store, first))["raw"] == short
    records = [r for r in caplog.records if r.name == "messagefoundry.store.document_strip"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING and records[0].exc_info is None
    text = records[0].getMessage()
    assert "skipped 2 stored HL7 bodies" in text
    # The id it names is an unreadable row's, never the readable one stripped beside them.
    assert f"message {first}" in text or f"message {second}" in text
    assert str(readable) not in text
    for piece in ("SEND", "RECV", "MSG0001", "ORU", "^~", DOC.decode()[:20], "C-UNR"):
        assert piece not in text, piece


# --- BACKLOG #5651: the write-back is guarded, batched, and off the loop --------


def _spy_strip(monkeypatch: pytest.MonkeyPatch, before: Callable[[], None]) -> list[int]:
    """Wrap ``strip_documents`` so ``before`` runs ahead of each call, on whatever thread the strip
    runs it on, and return the thread idents the calls ran on."""
    real = binary.strip_documents
    threads: list[int] = []

    def spy(*args: Any, **kwargs: Any) -> tuple[str, int, int]:
        threads.append(threading.get_ident())
        before()
        return real(*args, **kwargs)

    monkeypatch.setattr(document_strip, "strip_documents", spy)
    return threads


_RESEALED = binary.encode(b"RE-SEALED-SYNTHETIC " * 300)
_PENDING = OutboxStatus.PENDING.value


def _change(kind: str, mid: str) -> tuple[str, tuple[Any, ...]]:
    """Another writer's statement, in ``?`` form, for one kind of concurrent change to ``mid``."""
    if kind == "body-purged":
        return "UPDATE messages SET raw=? WHERE id=?", ("", mid)
    if kind == "body-re-sealed":
        return "UPDATE messages SET raw=? WHERE id=?", (_RESEALED, mid)
    return "UPDATE queue SET status=? WHERE message_id=?", (_PENDING, mid)  # re-pended (replay)


async def _run_sql_on_server(store: Any, sql: str, params: tuple[Any, ...]) -> None:
    """Run one other writer's statement on a server backend, committed."""
    async with store._pool.acquire() as conn:
        if type(store).__name__ == "PostgresStore":
            await conn.execute(sql.replace("?", "$1", 1).replace("?", "$2", 1), *params)
            return
        cur = await conn.cursor()
        await cur.execute(sql, params)
        await conn.commit()


def _concurrent_writer(
    store: Any, tmp_path: Any, sql: str, params: tuple[Any, ...], loop: asyncio.AbstractEventLoop
) -> Callable[[], None]:
    """A callable that, the first time it runs, commits ``sql`` as a separate writer: called from
    inside the strip's transform, it lands between the strip's read of a row and its write-back."""
    done: list[bool] = []
    loop_thread = threading.get_ident()

    def write() -> None:
        if done:
            return
        done.append(True)
        if isinstance(store, MessageStore):
            with contextlib.closing(sqlite3.connect(tmp_path / _DB_NAME, timeout=30)) as db, db:
                db.execute(sql, params)
            return
        if threading.get_ident() == loop_thread:
            pytest.fail("the strip ran its transform on the event loop thread")
        asyncio.run_coroutine_threadsafe(_run_sql_on_server(store, sql, params), loop).result(30)

    return write


@pytest.mark.parametrize(
    ("kind", "raw_after"),
    [
        pytest.param("body-purged", "", id="body-purged"),
        pytest.param("body-re-sealed", _RESEALED, id="body-re-sealed"),
        pytest.param("re-pended", MFB64_BODY, id="re-pended"),
    ],
)
async def test_a_write_between_the_strips_read_and_write_back_wins(
    store: MessageStore,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    raw_after: str,
) -> None:
    """BACKLOG #5651: a body purge (``raw`` emptied), a key rotation (``raw`` re-sealed) or a replay
    (a queue row pending again) that commits after the strip read a row and before it writes the
    row back wins. The strip must not write the stripped copy of the old body over it, must not set
    the row's ``documents_pruned`` flag, and must not count it. The other writer runs from inside
    the strip's own transform, so the interleaving is forced rather than left to a scheduler."""
    mid = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-RACE")
    sql, params = _change(kind, mid)
    _spy_strip(
        monkeypatch, _concurrent_writer(store, tmp_path, sql, params, asyncio.get_running_loop())
    )

    result = await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
    )

    assert result == StripResult()
    rec = await _get(store, mid)
    assert rec["raw"] == raw_after  # the other writer's state stands
    assert rec["documents_pruned"] is None


async def test_the_transform_runs_off_the_event_loop(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: the decrypt, strip and encrypt of a pass run in a worker thread, never on the
    event loop thread."""
    await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-THREAD")
    threads = _spy_strip(monkeypatch, lambda: None)

    result = await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
    )

    assert result.messages_stripped == 1
    assert threads and threading.get_ident() not in threads


async def test_the_scan_reads_candidates_in_bounded_keyset_batches(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: the pass reads at most ``STRIP_BATCH_ROWS`` candidates at a time and walks the
    whole candidate set by ``(received_at, id)``, ties across a batch boundary included, so every
    eligible row is still stripped and counted once. An in-flight row and a row on a keep-forever
    connection, among them, stay as stored."""
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 2)
    batches: list[int] = []
    real = document_strip.transform_strip_batch

    def spy(cipher: Any, rows: Any, **kwargs: Any) -> Any:
        batches.append(len(rows))
        return real(cipher, rows, **kwargs)

    monkeypatch.setattr(document_strip, "transform_strip_batch", spy)
    eligible = [
        await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=at, control=f"C-B{i}")
        for i, at in enumerate((0.0, 0.0, 0.0, 1.0, 2.0))  # three tie on received_at
    ]
    in_flight = await store.enqueue_message(
        channel_id="IB", raw=MFB64_BODY, deliveries=[("OB", "p")], control_id="C-BINF", now=0.0
    )
    kept = await _delivered(store, channel_id="IB_KEEP", raw=MFB64_BODY, now=0.0, control="C-BK")

    result = await store.strip_embedded_documents(
        older_than=float("-inf"),
        now=PRUNED_AT,
        connection_cutoffs={"IB": 4 * DAY, "IB_KEEP": float("-inf")},
    )

    assert (result.messages_stripped, result.documents_stripped) == (5, 5)
    # Five eligible rows and the keep-forever row pass the loose scan bound; the in-flight row never.
    assert batches and max(batches) <= 2 and sum(batches) == 6
    for mid in eligible:
        assert binary.is_document_tombstone((await _get(store, mid))["raw"])
    for mid in (in_flight, kept):
        rec = await _get(store, mid)
        assert rec["raw"] == MFB64_BODY and rec["documents_pruned"] is None


async def test_a_pass_that_fails_part_way_logs_what_it_had_committed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5651: each batch commits on its own, so when a later batch raises, the earlier
    batches' strips stay committed and the runner writes no audit row for them. The pass says so at
    WARNING, with the counts and no byte of a body, and re-raises."""
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 1)
    real = document_strip.transform_strip_batch
    calls: list[int] = []

    def flaky(cipher: Any, rows: Any, **kwargs: Any) -> Any:
        calls.append(len(rows))
        if len(calls) == 2:
            raise RuntimeError("synthetic transform failure")
        return real(cipher, rows, **kwargs)

    monkeypatch.setattr(document_strip, "transform_strip_batch", flaky)
    first = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-F1")
    second = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=1.0, control="C-F2")

    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.store.document_strip"),
        pytest.raises(RuntimeError, match="synthetic"),
    ):
        await store.strip_embedded_documents(
            older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
        )

    assert binary.is_document_tombstone((await _get(store, first))["raw"])  # batch one committed
    assert (await _get(store, second))["raw"] == MFB64_BODY
    [record] = [r for r in caplog.records if "failed part way" in r.getMessage()]
    assert "1 documents in 1 messages" in record.getMessage()
    assert DOC.decode()[:20] not in record.getMessage()


async def test_a_failed_audit_of_refused_cells_still_logs_what_was_committed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5651: when auditing the refused cells, the pass's last step, raises after its
    batches committed, the part-way WARNING still names what was stripped, and the error
    propagates."""
    mid = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-AUD")

    async def broken_report(*_args: Any) -> None:
        raise RuntimeError("synthetic audit failure")

    backend = sys.modules[type(store).__module__]
    monkeypatch.setattr(backend, "report_cell_tag_failures", broken_report)

    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.store.document_strip"),
        pytest.raises(RuntimeError, match="synthetic audit"),
    ):
        await store.strip_embedded_documents(
            older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
        )

    assert binary.is_document_tombstone((await _get(store, mid))["raw"])
    [record] = [r for r in caplog.records if "failed part way" in r.getMessage()]
    assert "1 documents in 1 messages" in record.getMessage()


async def test_a_key_service_outage_stops_the_pass(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: a decrypt the key service gave no verdict on ends the strip call at the first
    row, rather than failing, and timing out, once per row. The call returns, flagged
    ``ended_early``, instead of raising."""
    for i in range(3):
        await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=float(i), control=f"C-O{i}")
    calls: list[str] = []

    def unavailable(*_args: Any, message_id: str, **_kwargs: Any) -> str:
        calls.append(message_id)
        raise CipherUnavailableError("synthetic: the key service is unreachable")

    monkeypatch.setattr(document_strip, "open_message_cell", unavailable)

    result = await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
    )

    assert result == StripResult(ended_early=True)
    assert len(calls) == 1


async def test_a_key_service_outage_ends_only_the_strip_phase_of_a_retention_pass(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: an outage in the strip phase does not fail the retention pass: the pass
    completes and still writes its single ``retention_purge`` audit row, here for a body purge the
    same pass made."""
    # Two days old: past its one-day strip window, inside the three-day body window.
    kept = await _delivered(store, channel_id="IB_PRUNE", raw=MFB64_BODY, now=3 * DAY, control="O1")
    # Five days old: its body is purged by the same pass.
    await _delivered(store, channel_id="IB_KEEP", raw=MFB64_BODY, now=0.0, control="O2")
    calls: list[str] = []

    def unavailable(*_args: Any, message_id: str, **_kwargs: Any) -> str:
        calls.append(message_id)
        raise CipherUnavailableError("synthetic: the key service is unreachable")

    monkeypatch.setattr(document_strip, "open_message_cell", unavailable)
    reg = _registry()
    runner = RetentionRunner(
        store,
        RetentionSettings(messages_days=3),
        clock=lambda: 5 * DAY,
        registry_source=lambda: reg,
    )

    result = await runner.run_once()

    assert calls == [kept]  # the strip phase ran, and stopped at its first row
    assert result.messages_purged == 1 and result.documents_messages_stripped == 0
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1


_LOCK_ROW = {"id": "M-LOCK", "channel_id": "IB", "raw": MFB64_BODY, "received_at": 0.0}


async def test_the_postgres_write_locks_messages_then_queue_inside_its_transaction() -> None:
    """BACKLOG #5651: the Postgres write takes ``FOR UPDATE`` on the batch's message rows, then
    ``FOR SHARE`` on their queue rows, both inside the batch transaction and before any guarded
    UPDATE. No server runs here, so a recording connection stands in for one; deleting either lock
    statement, or moving it out of the transaction, fails this."""
    from messagefoundry.store.postgres import PostgresStore

    calls: list[tuple[str, bool]] = []
    state = {"in_txn": False}

    class Txn:
        async def __aenter__(self) -> None:
            state["in_txn"] = True

        async def __aexit__(self, *_exc: object) -> None:
            state["in_txn"] = False

    class Conn:
        def transaction(self) -> Txn:
            return Txn()

        async def execute(self, sql: str, *_args: Any) -> str:
            calls.append((sql, state["in_txn"]))
            return "UPDATE 1" if sql.startswith("UPDATE") else "SELECT 1"

    @contextlib.asynccontextmanager
    async def acquire(**_kwargs: Any) -> AsyncIterator[Conn]:
        yield Conn()

    pages = [[_LOCK_ROW], []]

    async def fetchall(_sql: str, *_args: Any) -> list[Any]:
        return pages.pop(0)

    store: Any = object.__new__(PostgresStore)
    store._cipher = IdentityCipher()
    store._timed_acquire = acquire
    store._fetchall = fetchall

    result = await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
    )

    assert result.messages_stripped == 1
    kinds = [
        (
            "messages-lock"
            if "FROM messages" in s and "FOR UPDATE" in s
            else "queue-lock"
            if "FROM queue" in s and "FOR SHARE" in s
            else "update"
            if s.startswith("UPDATE messages")
            else s,
            txn,
        )
        for s, txn in calls
    ]
    assert kinds == [("messages-lock", True), ("queue-lock", True), ("update", True)]


async def test_the_sqlserver_write_locks_messages_then_clustered_queue_rows_before_commit() -> None:
    """BACKLOG #5651: the SQL Server write takes ``UPDLOCK`` on the batch's message rows, then on
    their queue rows by a column outside ``ix_queue_message``, both before any guarded UPDATE and
    before the commit, and its guard's subquery reads under ``READCOMMITTEDLOCK``. No server runs
    here, so a recording cursor stands in for one; deleting either lock fails this."""
    from messagefoundry.store.sqlserver import SqlServerStore

    events: list[str] = []

    class Cur:
        def __init__(self) -> None:
            self.last = ""

        async def execute(self, sql: str, _params: Any = ()) -> None:
            self.last = sql
            events.append(sql)

        async def fetchall(self) -> list[Any]:
            return [("M-LOCK",)] if self.last.startswith("UPDATE") else []

    @contextlib.asynccontextmanager
    async def acquire() -> AsyncIterator[object]:
        yield object()

    @contextlib.asynccontextmanager
    async def cursor(_conn: object) -> AsyncIterator[Cur]:
        yield Cur()

    async def commit(_conn: object) -> None:
        events.append("COMMIT")

    pages = [[dict(_LOCK_ROW)], []]

    async def fetchall(_sql: str, _params: Any = ()) -> list[dict[str, Any]]:
        return pages.pop(0)

    store: Any = object.__new__(SqlServerStore)
    store._cipher = IdentityCipher()
    store._acquire = acquire
    store._cursor = cursor
    store._commit = commit
    store._fetchall = fetchall

    result = await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
    )

    assert result.messages_stripped == 1
    assert len(events) == 4 and events[3] == "COMMIT"
    messages_lock, queue_lock, update = events[:3]
    assert "FROM messages m WITH (UPDLOCK" in messages_lock
    assert "SELECT q.status FROM queue q WITH (UPDLOCK" in queue_lock
    assert update.startswith("UPDATE messages") and "READCOMMITTEDLOCK" in update


def test_a_refused_cell_is_returned_with_its_traceback_cleared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5651: a refused cell's error is returned, not raised, so its traceback is cleared;
    its frames would otherwise keep the batch's bodies alive until the pass ends."""

    def refused(*_args: Any, message_id: str, channel_id: str, **_kwargs: Any) -> str:
        raise CellTagError("messages", "raw", message_id, channel_id)

    monkeypatch.setattr(document_strip, "open_message_cell", refused)
    rows = [{"id": "M-1", "channel_id": "IB", "raw": "sealed", "received_at": 0.0}]

    updates, failures, unreadable = document_strip.transform_strip_batch(
        IdentityCipher(),
        rows,
        now=PRUNED_AT,
        older_than=1.0,
        connection_cutoffs=None,
        min_bytes=0,
        content_types={},
    )

    assert (updates, unreadable) == ([], [])
    [failure] = failures
    assert failure.__traceback__ is None


# --- AC-5: one audit row per pass via the runner, recording counts -------------


def _registry(min_bytes: int | None = None) -> Registry:
    """A registry with one inbound that opts into document pruning (1-day window) and one that does not
    (None = never strip) — resolved each pass by the runner."""
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "IB_PRUNE",
            MLLP(port=2700),
            router="r",
            prune_documents_after=1,
            prune_documents_min_bytes=min_bytes,
        )
    )
    reg.add_inbound(build_inbound_connection("IB_KEEP", MLLP(port=2701), router="r"))  # never
    return reg


async def test_audit_records_strip_counts(store: MessageStore) -> None:
    """AC-5: a strip pass writes EXACTLY ONE ``retention_purge`` audit row recording the per-connection
    windows + counts (documents stripped / bytes reclaimed) and NO message content (no PHI)."""
    pruned = await _delivered(store, channel_id="IB_PRUNE", raw=MFB64_BODY, now=0.0, control="A-P")
    kept = await _delivered(store, channel_id="IB_KEEP", raw=MFB64_BODY, now=0.0, control="A-K")

    reg = _registry()
    runner = RetentionRunner(
        store,
        RetentionSettings(),  # NO global retention — document pruning is purely per-connection
        clock=lambda: 5 * DAY,
        registry_source=lambda: reg,
    )

    result = await runner.run_once()

    assert result.documents_messages_stripped == 1 and result.documents_stripped == 1
    assert result.documents_bytes_reclaimed > 0
    # IB_PRUNE stripped on its 1-day window; IB_KEEP (no window) untouched.
    assert binary.is_document_tombstone((await _get(store, pruned))["raw"])
    assert (await _get(store, kept))["raw"] == MFB64_BODY

    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1  # exactly one row per pass
    detail = json.loads(audit[0]["detail"])
    assert detail["document_prune_overrides"] == {"IB_PRUNE": 1}  # the per-connection window
    assert detail["documents_stripped"] == 1 and detail["documents_messages_stripped"] == 1
    assert detail["documents_bytes_reclaimed"] > 0
    # No message content / PHI in the audit detail.
    assert DOC.decode() not in audit[0]["detail"]


async def test_runner_enabled_for_document_pruning_only(store: MessageStore) -> None:
    """The runner starts (``enabled``) when an inbound sets ``prune_documents_after`` even with NO
    ``[retention]`` settings — document pruning has no global window."""
    reg = _registry()
    # The low-disk floor (BACKLOG #290) is turned off here: it ships on and enables the runner on a
    # SQLite store by itself, which would make both assertions below say nothing about pruning. The
    # hourly WAL truncate ships on too since vault BACKLOG #2619, and is turned off for the same reason.
    # So does the audit-log growth warning since BACKLOG #1421, on every backend.
    no_floor = RetentionSettings(
        min_free_disk_mb=0, wal_checkpoint_seconds=0, audit_log_warn_rows=0
    )
    runner = RetentionRunner(store, no_floor, clock=lambda: 5 * DAY, registry_source=lambda: reg)
    assert runner.enabled is True

    # And with neither global retention nor any document-prune window, it is disabled.
    empty = Registry()
    empty.add_inbound(build_inbound_connection("IB", MLLP(port=2702), router="r"))
    off = RetentionRunner(store, no_floor, clock=lambda: 5 * DAY, registry_source=lambda: empty)
    assert off.enabled is False
