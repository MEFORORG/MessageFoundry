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
from messagefoundry.store.store import OutboxStatus, load_audit_chain

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
#
# The server cases run on the shared live databases of at least the postgres-store,
# postgres-store-windows and sqlserver-store CI legs (BACKLOG #5651). As in the sibling store
# suites, a setup failure closes the pool (BACKLOG #1629), and a close that fails too is logged
# rather than raised, so the setup error is the one reported. The audit chain is read again from
# the emptied log, because a keyed chain an earlier file left would make this keyless handle
# refuse every append.


async def _close_after_failed_setup(s: Any) -> None:
    """Close a server store whose fixture setup failed. A close error is logged, not raised: it
    would replace the setup error the run reports (BACKLOG #5651)."""
    try:
        await s.close()
    except Exception as close_exc:
        logging.getLogger(__name__).warning(
            "closing the store after its setup failed failed too: %r", close_exc
        )


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


async def _open_postgres(_tmp_path):
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    try:
        async with s._pool.acquire() as conn:
            await conn.execute(
                "TRUNCATE message_events, audit_log, queue, response, delivered_keys, messages "
                "RESTART IDENTITY CASCADE"
            )
        await load_audit_chain(s, read_only=False)
    except BaseException:
        await _close_after_failed_setup(s)
        raise
    return s


async def _open_sqlserver(_tmp_path):
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    try:
        async with s._pool.acquire() as conn:
            cur = await conn.cursor()
            try:
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
            finally:
                # Closed before the pool is, so no statement handle outlives its connection.
                await cur.close()
        await load_audit_chain(s, read_only=False)
    except BaseException:
        await _close_after_failed_setup(s)
        raise
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
        # Closed and, on a failure, rolled back here: the connection goes back to the shared pool.
        cur = await conn.cursor()
        try:
            await cur.execute(sql, params)
            await conn.commit()
        except BaseException:
            try:
                await conn.rollback()
            except Exception as rollback_exc:  # the writer's own error is the one to raise
                logging.getLogger(__name__).warning(
                    "the concurrent writer's rollback failed too: %r", rollback_exc
                )
            raise
        finally:
            await cur.close()


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
    caplog: pytest.LogCaptureFixture,
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

    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.document_strip"):
        result = await store.strip_embedded_documents(
            older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
        )

    assert result == StripResult()
    # The guard refused the write; no batch failed and was contained with the same end state.
    assert not [r for r in caplog.records if "passed over a batch" in r.getMessage()]
    rec = await _get(store, mid)
    assert rec["raw"] == raw_after  # the other writer's state stands
    assert rec["documents_pruned"] is None
    if kind == "re-pended":
        # raw is unchanged in this case, so prove the other writer committed rather than failed,
        # which the strip would have contained as a skipped row with the same end state.
        [row] = await store.outbox_for(mid)
        assert row["status"] == _PENDING


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


async def test_a_batch_that_fails_is_passed_over_and_the_scan_goes_on(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5651: a batch whose transform fails is logged and passed over, and the keyset goes
    on past it, so no row can stall the strip for good. The WARNING names the error's type, never
    its text or a byte of a body."""
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 1)
    real = document_strip.transform_strip_batch
    calls: list[int] = []

    def flaky(cipher: Any, rows: Any, **kwargs: Any) -> Any:
        calls.append(len(rows))
        if len(calls) == 1:
            raise RuntimeError("synthetic transform failure SECRET-TEXT")
        return real(cipher, rows, **kwargs)

    monkeypatch.setattr(document_strip, "transform_strip_batch", flaky)
    first = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-F1")
    second = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=1.0, control="C-F2")

    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.document_strip"):
        result = await store.strip_embedded_documents(
            older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
        )

    assert (result.messages_stripped, result.ended_early) == (1, False)
    assert (await _get(store, first))["raw"] == MFB64_BODY  # its batch failed
    assert binary.is_document_tombstone((await _get(store, second))["raw"])  # the scan went on
    [record] = [r for r in caplog.records if "passed over a batch" in r.getMessage()]
    text = record.getMessage()
    assert "RuntimeError" in text and "SECRET-TEXT" not in text and DOC.decode()[:20] not in text


async def test_a_write_that_fails_rolls_back_its_batch_and_the_scan_goes_on(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5651: a batch whose write fails is rolled back whole and counts nothing; the
    keyset moves past it and the next batch is stripped. The ERROR names the error's type, and
    the traceback goes to DEBUG."""
    if not isinstance(store, MessageStore) or type(store) is not MessageStore:
        pytest.skip("drives the SQLite write path")
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 1)
    first = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-W1")
    second = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=1.0, control="C-W2")
    real_commit = store._commit
    commits: list[int] = []

    async def failing_once() -> None:
        # The first batch's commit fails after its UPDATE ran, so the writer transaction must
        # roll that UPDATE back.
        commits.append(1)
        if len(commits) == 1:
            raise RuntimeError("synthetic write failure")
        await real_commit()

    monkeypatch.setattr(store, "_commit", failing_once)

    with caplog.at_level(logging.DEBUG, logger="messagefoundry.store.document_strip"):
        result = await store.strip_embedded_documents(
            older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
        )

    assert (result.messages_stripped, result.ended_early) == (1, False)
    rec = await _get(store, first)
    assert rec["raw"] == MFB64_BODY and rec["documents_pruned"] is None  # rolled back
    assert binary.is_document_tombstone((await _get(store, second))["raw"])
    warned = [r for r in caplog.records if "passed over a batch" in r.getMessage()]
    assert len(warned) == 1 and "RuntimeError" in warned[0].getMessage()
    assert warned[0].levelno == logging.ERROR
    assert any(r.levelno == logging.DEBUG and r.exc_info for r in caplog.records)


async def test_one_row_that_fails_to_strip_is_skipped(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: a row whose own strip raises is logged and skipped; the rows around it are
    still stripped."""
    bad = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-SB1")
    good = await _delivered(store, channel_id="IB", raw=HL7_ED_BODY, now=1.0, control="C-SB2")
    real = binary.strip_documents

    def one_bad(raw: str, **kwargs: Any) -> tuple[str, int, int]:
        if raw == MFB64_BODY:
            raise ValueError("synthetic strip failure")
        return real(raw, **kwargs)

    monkeypatch.setattr(document_strip, "strip_documents", one_bad)

    result = await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
    )

    assert (result.messages_stripped, result.ended_early) == (1, False)
    assert (await _get(store, bad))["raw"] == MFB64_BODY
    assert (await _get(store, good))["raw"] != HL7_ED_BODY


async def test_a_batch_with_any_verdict_does_not_end_the_call(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: the call ends early only when every row of a batch got no verdict. A batch
    where some rows got one (here refused cells) is not an outage: its no-verdict rows are skipped,
    and the scan goes on."""
    ids = [
        await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=float(i), control=f"C-RS{i}")
        for i in range(5)
    ]
    calls: list[str] = []

    def alternate(*_args: Any, message_id: str, channel_id: str, **_kwargs: Any) -> str:
        calls.append(message_id)
        if ids.index(message_id) % 2:
            raise CellTagError("messages", "raw", message_id, channel_id)
        raise CipherUnavailableError("synthetic: no verdict")

    monkeypatch.setattr(document_strip, "open_message_cell", alternate)
    backend = sys.modules[type(store).__module__]

    async def no_audit(*_args: Any) -> None:
        return None

    monkeypatch.setattr(backend, "report_cell_tag_failures", no_audit)

    result = await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
    )

    assert result == StripResult()  # not ended early
    assert calls == ids


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
    """BACKLOG #5651: a batch where at least ``OUTAGE_MIN_ROWS`` rows reached the key service and
    none got a verdict is an outage: the strip call ends after it, rather than failing, and timing
    out, once per row of every later batch. The call returns, flagged ``ended_early``, instead of
    raising."""
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 3)
    for i in range(5):
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
    assert len(calls) == 3  # the first batch only


async def test_one_row_the_key_service_gives_no_verdict_on_is_skipped(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: one row that always gets no verdict (an oversized cell, say) is skipped like
    any unreadable row. It must not end the call, or every later pass would stop at it."""
    bad = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-NV1")
    good = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=1.0, control="C-NV2")
    from messagefoundry.store.cell_tag import open_message_cell as real

    def one_bad(cipher: Any, column: str, stored: Any, **kwargs: Any) -> Any:
        if kwargs["message_id"] == bad:
            raise CipherUnavailableError("synthetic: no verdict on this one cell")
        return real(cipher, column, stored, **kwargs)

    monkeypatch.setattr(document_strip, "open_message_cell", one_bad)

    result = await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
    )

    assert (result.messages_stripped, result.ended_early) == (1, False)
    assert (await _get(store, bad))["raw"] == MFB64_BODY
    assert binary.is_document_tombstone((await _get(store, good))["raw"])


async def test_a_row_refused_alone_in_its_batch_is_skipped_and_does_not_end_the_call(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: a row the key service always gives no verdict on is skipped, even when it is
    the only row of its batch to reach the service. Fewer than
    ``OUTAGE_MIN_ROWS`` such rows are not an outage, so the scan goes on to the rows after it."""
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 1)
    bad = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-AL1")
    good = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=1.0, control="C-AL2")
    from messagefoundry.store.cell_tag import open_message_cell as real

    def one_bad(cipher: Any, column: str, stored: Any, **kwargs: Any) -> Any:
        if kwargs["message_id"] == bad:
            raise CipherUnavailableError("synthetic: no verdict on this one cell")
        return real(cipher, column, stored, **kwargs)

    monkeypatch.setattr(document_strip, "open_message_cell", one_bad)

    result = await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
    )

    assert (result.messages_stripped, result.ended_early) == (1, False)
    assert binary.is_document_tombstone((await _get(store, good))["raw"])


async def test_a_store_wide_cipher_error_from_encrypt_propagates(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: a store-wide fail-closed :class:`CipherError` from ``encrypt``, the AES-GCM
    invocation ceiling here, is not swallowed as one row's failure: it propagates out of the strip,
    so its instruction to rotate the store key reaches the operator."""
    from messagefoundry.store.crypto import CipherError

    mid = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-CEIL")

    def ceiling(*_args: Any, **_kwargs: Any) -> str:
        raise CipherError(
            "AES-GCM invocation ceiling reached for this store's data key; rotate the store "
            "encryption key (`messagefoundry rotate-key`) and restart before encrypting further"
        )

    monkeypatch.setattr(store._cipher, "encrypt", ceiling)

    with pytest.raises(CipherError, match="rotate the store encryption key"):
        await store.strip_embedded_documents(
            older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
        )

    assert (await _get(store, mid))["raw"] == MFB64_BODY


async def test_a_failed_batch_read_ends_the_call_and_counts_as_audited_work() -> None:
    """BACKLOG #5651: a batch read that fails ends the call with ``read_failed`` set. Unlike an
    outage, a database fault is work for the retention audit row, so a pass whose only event it
    was still writes that row, recording it."""
    from messagefoundry.pipeline.retention import RetentionPass

    async def fetch(*_args: Any) -> list[Any]:
        raise RuntimeError("synthetic read failure")

    async def never(*_args: Any) -> list[Any]:
        raise AssertionError("no batch to write")

    async def report(_failures: Any) -> None:
        return None

    result = await document_strip.run_strip_pass(
        IdentityCipher(),
        fetch=fetch,
        write=never,
        report=report,
        now=PRUNED_AT,
        older_than=float("-inf"),
        connection_cutoffs={"IB": 4 * DAY},
        min_bytes=0,
        content_types={},
    )

    assert (result.ended_early, result.read_failed) == (True, True)
    quiet: dict[str, Any] = {
        "messages_purged": 0,
        "dead_purged": 0,
        "state_purged": 0,
        "conn_events_purged": 0,
        "wal_checkpointed": False,
        "vacuumed": False,
        "size_bytes": None,
        "over_limit": False,
    }
    assert RetentionPass(**quiet, documents_strip_read_failed=True).did_work
    assert not RetentionPass(**quiet, documents_strip_ended_early=True).did_work


async def test_a_key_service_outage_ends_only_the_strip_phase_of_a_retention_pass(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: an outage in the strip phase does not fail the retention pass: the pass
    completes and still writes its single ``retention_purge`` audit row, here for a body purge the
    same pass made."""
    # Two days old: past their one-day strip window, inside the three-day body window.
    kept = [
        await _delivered(
            store, channel_id="IB_PRUNE", raw=MFB64_BODY, now=3 * DAY, control=f"O1{i}"
        )
        for i in range(3)
    ]
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

    assert sorted(calls) == sorted(kept)  # the strip phase ran, and ended at the outage
    assert result.messages_purged == 1 and result.documents_messages_stripped == 0
    assert result.documents_strip_ended_early
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1  # written for the body purge
    assert json.loads(audit[0]["detail"])["documents_strip_ended_early"] is True


async def test_an_outage_alone_writes_no_retention_audit_row(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: an early end is not work for the audit row: a pass whose only event is a
    key-service outage in its strip phase writes no audit row, since that row would go through the
    failing key service too. The strip logs the early end at WARNING."""
    for i in range(3):
        await _delivered(store, channel_id="IB_PRUNE", raw=MFB64_BODY, now=0.0, control=f"OA{i}")

    def unavailable(*_args: Any, **_kwargs: Any) -> str:
        raise CipherUnavailableError("synthetic: the key service is unreachable")

    monkeypatch.setattr(document_strip, "open_message_cell", unavailable)
    reg = _registry()
    no_floor = RetentionSettings(
        min_free_disk_mb=0, wal_checkpoint_seconds=0, audit_log_warn_rows=0
    )
    runner = RetentionRunner(store, no_floor, clock=lambda: 5 * DAY, registry_source=lambda: reg)

    result = await runner.run_once()

    assert result.documents_strip_ended_early and not result.did_work
    assert not [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]


def _plain_rows(n: int) -> list[dict[str, Any]]:
    return [
        {"id": f"M-{i}", "channel_id": "IB", "raw": MFB64_BODY, "received_at": float(i)}
        for i in range(n)
    ]


def _keyset_fetch(rows: list[dict[str, Any]]) -> Callable[..., Any]:
    async def fetch(_cutoff: float, after: Any, limit: int) -> list[dict[str, Any]]:
        start = 0 if after is None else [r["id"] for r in rows].index(after[1]) + 1
        return rows[start : start + limit]

    return fetch


async def _run_pass(fetch: Any, write: Any, report: Any, cipher: Any = None) -> StripResult:
    return await document_strip.run_strip_pass(
        IdentityCipher() if cipher is None else cipher,
        fetch=fetch,
        write=write,
        report=report,
        now=PRUNED_AT,
        older_than=float("-inf"),
        connection_cutoffs={"IB": 4 * DAY},
        min_bytes=0,
        content_types={},
    )


async def _no_report(_failures: Any) -> None:
    return None


async def test_two_adjacent_batches_whose_writes_fail_do_not_stop_the_rows_after_them(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5651: writes that fail for reasons of their own rows (a lock timeout on the two
    oldest batches, say) are passed over, and the pass still strips the rows after them: a fault on
    particular rows cannot stop the rows after the failing batch, so a fault at the head of the
    keyset cannot stop every pass at the same place. Each failure is logged at
    ERROR with its type only, and the call is flagged ``write_failed``."""
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 1)
    writes: list[str] = []

    async def locked_head(updates: Any) -> list[Any]:
        writes.append(updates[0].message_id)
        if updates[0].message_id in ("M-0", "M-1"):
            raise sqlite3.OperationalError("lock timeout on this row SECRET-TEXT")
        return list(updates)

    with caplog.at_level(logging.DEBUG, logger="messagefoundry.store.document_strip"):
        result = await _run_pass(_keyset_fetch(_plain_rows(5)), locked_head, _no_report)

    assert writes == ["M-0", "M-1", "M-2", "M-3", "M-4"]
    assert result == StripResult(
        messages_stripped=3,
        documents_stripped=3,
        bytes_reclaimed=result.bytes_reclaimed,
        write_failed=True,
    )
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 2
    assert all("OperationalError" in r.getMessage() for r in errors)
    assert not any("SECRET-TEXT" in r.getMessage() for r in caplog.records)


async def test_a_cipher_error_from_a_batch_write_propagates() -> None:
    """BACKLOG #5651: a store-wide :class:`CipherError` raised by a backend's write is not passed
    over as a failed write: it propagates, so its instruction reaches the operator."""
    from messagefoundry.store.crypto import CipherError

    async def sealing_write(_updates: Any) -> list[Any]:
        raise CipherError("AES-GCM invocation ceiling reached; rotate the store key")

    with pytest.raises(CipherError, match="rotate the store key"):
        await _run_pass(_keyset_fetch(_plain_rows(2)), sealing_write, _no_report)


async def test_a_write_that_returns_none_is_passed_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5651: a backend write that returns something malformed is passed over like any
    other failed batch, and the scan goes on, rather than failing the whole pass."""
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 1)
    writes: list[int] = []

    async def none_once(updates: Any) -> Any:
        writes.append(len(updates))
        return None if len(writes) == 1 else list(updates)

    result = await _run_pass(_keyset_fetch(_plain_rows(3)), none_once, _no_report)

    assert len(writes) == 3
    assert (result.messages_stripped, result.ended_early) == (2, False)


async def test_a_failed_batch_write_is_flagged_but_is_not_audited_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5651: a failed write is passed over and the scan goes on, but the call says a write
    failed. A retention pass records the flag in an audit row it writes, but does not write one for
    it alone: on a read-only store or a full disk that row's insert would fail too."""
    from messagefoundry.pipeline.retention import RetentionPass

    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 1)
    writes: list[int] = []

    async def failing_once(updates: Any) -> list[Any]:
        writes.append(len(updates))
        if len(writes) == 1:
            raise RuntimeError("synthetic write failure")
        return list(updates)

    result = await _run_pass(_keyset_fetch(_plain_rows(3)), failing_once, _no_report)

    assert len(writes) == 3
    assert (result.messages_stripped, result.ended_early, result.write_failed) == (2, False, True)
    quiet: dict[str, Any] = {
        "messages_purged": 0,
        "dead_purged": 0,
        "state_purged": 0,
        "conn_events_purged": 0,
        "wal_checkpointed": False,
        "vacuumed": False,
        "size_bytes": None,
        "over_limit": False,
    }
    assert not RetentionPass(**quiet, documents_strip_write_failed=True).did_work


async def test_refused_cells_of_a_batch_whose_transform_raises_are_still_audited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5651: a refused cell found before a store-wide cipher error in the same batch is
    still handed to the audit, not lost with the batch."""
    from messagefoundry.store.crypto import CipherError

    def first_refused(
        _cipher: Any, _column: str, stored: Any, *, message_id: str, channel_id: str
    ) -> str:
        if message_id == "M-0":
            raise CellTagError("messages", "raw", message_id, channel_id)
        return str(stored)

    class Ceiling(IdentityCipher):
        def encrypt(self, *_args: Any, **_kwargs: Any) -> str:
            raise CipherError("AES-GCM invocation ceiling reached; rotate the store key")

    monkeypatch.setattr(document_strip, "open_message_cell", first_refused)
    reported: list[list[Any]] = []

    async def report(failures: list[Any]) -> None:
        reported.append(list(failures))

    async def never(_updates: Any) -> list[Any]:
        raise AssertionError("no batch to write")

    with pytest.raises(CipherError, match="rotate the store key"):
        await _run_pass(_keyset_fetch(_plain_rows(2)), never, report, cipher=Ceiling())

    assert [[f.row_ref for f in r] for r in reported] == [["M-0"]]


async def test_a_failed_batch_read_logs_its_traceback_at_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #5651: the early end on a failed read names the error's type at WARNING, and its
    traceback goes to DEBUG for diagnosis, as a failed batch write's does."""

    async def fetch(*_args: Any) -> list[Any]:
        raise RuntimeError("synthetic read failure")

    async def never(_updates: Any) -> list[Any]:
        raise AssertionError("no batch to write")

    with caplog.at_level(logging.DEBUG, logger="messagefoundry.store.document_strip"):
        result = await _run_pass(fetch, never, _no_report)

    assert result.read_failed
    assert any(r.levelno == logging.DEBUG and r.exc_info for r in caplog.records)


_LOCK_ROW = {"id": "M-LOCK", "channel_id": "IB", "raw": MFB64_BODY, "received_at": 0.0}


async def test_the_postgres_write_is_only_guarded_updates_inside_one_transaction() -> None:
    """BACKLOG #5651: the Postgres write takes no row locks; it is the guarded UPDATEs alone, all in
    one transaction with no savepoint, so a failure rolls back the whole batch. Each UPDATE carries
    the compare-and-swap guard. No server runs here, so a recording connection stands in for one."""
    from messagefoundry.store.postgres import PostgresStore

    calls: list[tuple[str, int]] = []
    depth = {"n": 0, "max": 0}

    class Txn:
        async def __aenter__(self) -> None:
            depth["n"] += 1
            depth["max"] = max(depth["max"], depth["n"])

        async def __aexit__(self, *_exc: object) -> None:
            depth["n"] -= 1

    class Conn:
        def transaction(self) -> Txn:
            return Txn()

        async def execute(self, sql: str, *_args: Any) -> str:
            calls.append((sql, depth["n"]))
            return "UPDATE 1"

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
    [(sql, in_txn)] = calls
    assert sql.startswith("UPDATE messages") and in_txn == 1 and depth["max"] == 1
    for part in ("documents_pruned IS NULL", "raw=$4", "NOT EXISTS (SELECT 1 FROM queue"):
        assert part in sql


async def test_the_sqlserver_write_rolls_back_the_whole_batch_on_a_failure() -> None:
    """BACKLOG #5651: the SQL Server write takes no row locks and catches no per-row error: a
    failed UPDATE rolls back the whole batch and counts nothing, and the pass goes on. No server
    runs here, so a recording cursor stands in for one."""
    from messagefoundry.store.sqlserver import SqlServerStore

    events: list[str] = []

    class Cur:
        async def execute(self, sql: str, _params: Any = ()) -> None:
            events.append(sql)
            raise RuntimeError("synthetic write failure")

        async def fetchall(self) -> list[Any]:
            return []

    @contextlib.asynccontextmanager
    async def acquire() -> AsyncIterator[object]:
        yield object()

    @contextlib.asynccontextmanager
    async def cursor(_conn: object) -> AsyncIterator[Cur]:
        yield Cur()

    async def commit(_conn: object) -> None:
        events.append("COMMIT")

    async def rollback(_conn: object, **_kwargs: Any) -> None:
        events.append("ROLLBACK")

    pages = [[dict(_LOCK_ROW), {**_LOCK_ROW, "id": "M-LOCK-2"}], []]

    async def fetchall(_sql: str, _params: Any = ()) -> list[dict[str, Any]]:
        return pages.pop(0)

    store: Any = object.__new__(SqlServerStore)
    store._cipher = IdentityCipher()
    store._acquire = acquire
    store._cursor = cursor
    store._commit = commit
    store._rollback_or_discard = rollback
    store._fetchall = fetchall

    result = await store.strip_embedded_documents(
        older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
    )

    assert result == StripResult(write_failed=True)
    assert len(events) == 2 and events[0].startswith("UPDATE messages") and events[1] == "ROLLBACK"


def test_a_refused_cell_is_returned_with_its_traceback_cleared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5651: a refused cell's error is returned, not raised, so its traceback is cleared;
    its frames would otherwise keep the batch's bodies alive until the pass ends."""

    def refused(*_args: Any, message_id: str, channel_id: str, **_kwargs: Any) -> str:
        raise CellTagError("messages", "raw", message_id, channel_id)

    monkeypatch.setattr(document_strip, "open_message_cell", refused)
    rows = [{"id": "M-1", "channel_id": "IB", "raw": "sealed", "received_at": 0.0}]

    batch = document_strip.transform_strip_batch(
        IdentityCipher(),
        rows,
        now=PRUNED_AT,
        older_than=1.0,
        connection_cutoffs=None,
        min_bytes=0,
        content_types={},
    )

    assert (batch.updates, batch.unreadable, batch.outage) == ([], [], False)
    [failure] = batch.refused
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


async def test_a_failed_strip_write_reaches_the_audit_row_across_threshold_groups(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #5651: ``write_failed`` from any strip call of the pass, not only the last, reaches
    the pass result and the audit row it writes."""
    parts = iter(
        [StripResult(messages_stripped=1, documents_stripped=1, write_failed=True), StripResult()]
    )

    async def strip(**_kwargs: Any) -> StripResult:
        return next(parts)

    monkeypatch.setattr(store, "strip_embedded_documents", strip)
    reg = Registry()
    for port, (name, min_bytes) in enumerate((("IB_A", 0), ("IB_B", 10)), start=2702):
        reg.add_inbound(
            build_inbound_connection(
                name,
                MLLP(port=port),
                router="r",
                prune_documents_after=1,
                prune_documents_min_bytes=min_bytes,
            )
        )
    runner = RetentionRunner(
        store, RetentionSettings(), clock=lambda: 5 * DAY, registry_source=lambda: reg
    )

    result = await runner.run_once()

    assert result.documents_strip_write_failed
    audit = [r for r in await store.list_audit(limit=10) if r["action"] == "retention_purge"]
    assert len(audit) == 1
    assert json.loads(audit[0]["detail"])["documents_strip_write_failed"] is True


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


# --- BACKLOG #5651, PR 2922's closing steps 1 (the breaker), 10, 17 and 21 --------------------


async def test_batch_writes_failing_in_a_row_end_the_call(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """RED when: a write fault that hits every batch (a full disk, a read-only store) has no
    breaker, so the call re-seals every candidate in the store for nothing and logs one ERROR per
    batch (closing step 1). It ends after ``WRITE_FAULT_MAX_BATCHES`` failed writes in a row."""
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 1)
    writes: list[str] = []

    async def read_only(updates: Any) -> list[Any]:
        writes.append(updates[0].message_id)
        raise sqlite3.OperationalError("attempt to write a readonly database")

    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.document_strip"):
        result = await _run_pass(_keyset_fetch(_plain_rows(8)), read_only, _no_report)

    assert len(writes) == document_strip.WRITE_FAULT_MAX_BATCHES
    assert result == StripResult(ended_early=True, write_failed=True)
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == document_strip.WRITE_FAULT_MAX_BATCHES
    [early] = [r.getMessage() for r in caplog.records if "ended early" in r.getMessage()]
    assert "batch writes in a row failed" in early and "OperationalError" in early


async def test_a_write_that_lands_resets_the_breaker(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the breaker: failures on particular rows, broken up by writes that land,
    never add up to it, so the scan reaches the end of the keyset."""
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 1)
    below = document_strip.WRITE_FAULT_MAX_BATCHES - 1
    failing = {f"M-{i}" for i in range(8) if i % (below + 1) != below}
    writes: list[str] = []

    async def some_rows_locked(updates: Any) -> list[Any]:
        writes.append(updates[0].message_id)
        if updates[0].message_id in failing:
            raise sqlite3.OperationalError("lock timeout on this row")
        return list(updates)

    result = await _run_pass(_keyset_fetch(_plain_rows(8)), some_rows_locked, _no_report)

    assert len(writes) == 8
    assert (result.ended_early, result.write_failed) == (False, True)
    assert result.messages_stripped == 8 - len(failing)


class _Row(dict[str, Any]):
    """A candidate row a weak reference can watch."""


async def test_a_call_holds_one_batch_of_bodies_at_a_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """RED when: the previous batch's rows and write-backs are still referenced while the next
    batch is read, so a call holds two batches of bodies at once (closing step 10)."""
    import gc
    import weakref

    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 2)
    watched: list[weakref.ref[Any]] = []
    alive_at_each_read: list[int] = []

    async def fetch(_cutoff: float, after: Any, limit: int) -> list[_Row]:
        # A real backend's read gives the loop turns, which drop asyncio's own hold on the last
        # worker thread's result; only the strip's own references are left to measure.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        gc.collect()
        alive_at_each_read.append(sum(ref() is not None for ref in watched))
        start = 0 if after is None else int(after[1].removeprefix("M-")) + 1
        rows = [
            _Row(id=f"M-{i}", channel_id="IB", raw=MFB64_BODY, received_at=float(i))
            for i in range(start, min(start + limit, 6))
        ]
        watched.extend(weakref.ref(row) for row in rows)
        return rows

    async def write(updates: Any) -> list[Any]:
        watched.extend(weakref.ref(u) for u in updates)
        return list(updates)

    result = await _run_pass(fetch, write, _no_report)

    assert result.messages_stripped == 6
    # Rows and write-backs were watched from the first batch on; none outlived its batch.
    assert len(alive_at_each_read) == 4 and len(watched) == 12
    assert alive_at_each_read == [0, 0, 0, 0]


async def test_the_guard_compares_sealed_cells_on_a_keyed_store(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the compare-and-swap is only ever run keyless, comparing plaintext (closing step
    17). On a keyed store every cell is sealed under its row's AAD with a fresh nonce, so a key
    rotation that re-seals the same body leaves a different cell. The guard must refuse the
    strip's write-back over it, and with no concurrent writer it must still strip."""
    from messagefoundry.store.cell_tag import message_cell_aad
    from messagefoundry.store.crypto import generate_key, make_cipher

    store = await MessageStore.open(tmp_path / _DB_NAME, cipher=make_cipher(generate_key()))
    try:
        raced = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=0.0, control="C-K1")
        alone = await _delivered(store, channel_id="IB", raw=MFB64_BODY, now=1.0, control="C-K2")
        with contextlib.closing(sqlite3.connect(tmp_path / _DB_NAME)) as db:
            [sealed_before] = db.execute("SELECT raw FROM messages WHERE id=?", (raced,)).fetchone()
        assert sealed_before != MFB64_BODY  # sealed, so the guard compares ciphertext
        aad = message_cell_aad("raw", message_id=raced, channel_id="IB")
        resealed = store.cipher().encrypt(MFB64_BODY, aad=aad)  # same body, fresh nonce
        assert resealed != sealed_before
        resealed_once = _concurrent_writer(
            store,
            tmp_path,
            "UPDATE messages SET raw=? WHERE id=?",
            (resealed, raced),
            asyncio.get_running_loop(),
        )
        _spy_strip(monkeypatch, resealed_once)

        result = await store.strip_embedded_documents(
            older_than=float("-inf"), now=PRUNED_AT, connection_cutoffs={"IB": 4 * DAY}
        )

        assert result.messages_stripped == 1  # the row nobody else touched
        with contextlib.closing(sqlite3.connect(tmp_path / _DB_NAME)) as db:
            [raw_after] = db.execute("SELECT raw FROM messages WHERE id=?", (raced,)).fetchone()
        assert raw_after == resealed  # the rotation's cell stands
        rec = await _get(store, raced)
        assert rec["raw"] == MFB64_BODY and rec["documents_pruned"] is None
        stripped = await _get(store, alone)
        assert stripped["documents_pruned"] == PRUNED_AT and stripped["raw"] != MFB64_BODY
    finally:
        await store.close()


class _FailingSetupStore:
    """A server store whose setup fails, and whose close then fails too."""

    def __init__(self) -> None:
        self.close_calls = 0
        self._pool = self

    @contextlib.asynccontextmanager
    async def acquire(self) -> AsyncIterator[Any]:
        raise RuntimeError("SETUP-FAILED")
        yield  # pragma: no cover - makes this an async generator

    async def close(self) -> None:
        self.close_calls += 1
        raise RuntimeError("CLOSE-FAILED")


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_failed_server_fixture_setup_closes_and_raises_the_setup_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, backend: str
) -> None:
    """RED when: a server fixture's setup fails and its close then fails too, and the close error
    replaces the setup error the run reports (closing step 21). Runs with no server: the store's
    ``open`` is replaced, so only the fixture's own failure branch is exercised."""
    from messagefoundry.store import postgres, sqlserver

    fake = _FailingSetupStore()

    async def fake_open(_settings: Any) -> _FailingSetupStore:
        return fake

    if backend == "postgres":
        monkeypatch.setattr(postgres.PostgresStore, "open", fake_open)
        opener = _open_postgres
    else:
        monkeypatch.setattr(sqlserver.SqlServerStore, "open", fake_open)
        opener = _open_sqlserver
    with caplog.at_level(logging.WARNING), pytest.raises(RuntimeError, match="SETUP-FAILED"):
        await opener(None)
    assert fake.close_calls == 1
    assert any("CLOSE-FAILED" in r.getMessage() for r in caplog.records)


async def test_the_breaker_does_not_trip_on_the_last_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    """A third failed write on a short, last batch: the scan did reach its end, so the call does
    not report an early end, and a retention pass goes on to its other thresholds."""
    monkeypatch.setattr(document_strip, "STRIP_BATCH_ROWS", 2)
    writes: list[int] = []

    async def read_only(updates: Any) -> list[Any]:
        writes.append(len(updates))
        raise sqlite3.OperationalError("attempt to write a readonly database")

    result = await _run_pass(_keyset_fetch(_plain_rows(5)), read_only, _no_report)

    assert writes == [2, 2, 1]
    assert result == StripResult(write_failed=True)
