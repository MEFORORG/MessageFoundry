# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

import json
import os
from typing import AsyncIterator

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
from messagefoundry.store import MessageStore

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
    return await MessageStore.open(tmp_path / "embedded_doc_pruning.db")


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
    runner = RetentionRunner(
        store, RetentionSettings(), clock=lambda: 5 * DAY, registry_source=lambda: reg
    )
    assert runner.enabled is True

    # And with neither global retention nor any document-prune window, it is disabled.
    empty = Registry()
    empty.add_inbound(build_inbound_connection("IB", MLLP(port=2702), router="r"))
    off = RetentionRunner(
        store, RetentionSettings(), clock=lambda: 5 * DAY, registry_source=lambda: empty
    )
    assert off.enabled is False
