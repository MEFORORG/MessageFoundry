# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SEC-017 (CWE-770): engine-level ingress size guard for NON-HL7 content types.

The HL7 path enforces a 16 MiB ceiling via ``Peek.parse`` → ``enforce_size_limits``. The non-HL7
binary and text branches of ``_handle_inbound`` previously relied solely on the per-transport frame
cap (each individually disable-able). These tests prove the engine now applies the same ceiling as a
second layer of defense: an over-cap body is recorded ``ERROR`` (count-and-log, no ACK, no crash) and
an at/under-cap body is committed ``RECEIVED``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing import RawMessage
from messagefoundry.parsing.binary import is_marked
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore


def _is_ar_nak(ack: str | None) -> bool:
    """An ORIGINAL-mode AR reject carries ``MSA|AR`` (see transports/mllp.build_ack)."""
    return ack is not None and "MSA|AR" in ack


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _registry(name: str, content_type: ContentType) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name=name,
            spec=ConnectionSpec(ConnectorType.FILE, {}),
            router="r",
            content_type=content_type,
        )
    )
    reg.add_router("r", lambda m: [])  # no-op router; we never reach routing here
    return reg


async def _rows(store: MessageStore) -> list[dict]:
    cur = await store._db.execute("SELECT status, error, raw, message_type FROM messages")
    return [dict(r) for r in await cur.fetchall()]


# --- TEXT branch (JSON) -------------------------------------------------------


async def test_text_over_cap_records_error(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_JSON", ContentType.JSON)
    runner = RegistryRunner(reg, store)

    body = ("x" * 100).encode("utf-8")  # 100 chars > 64 cap
    ack = await runner._handle_inbound(reg.inbound["IB_JSON"], body)

    assert ack is None  # no HL7 ACK for non-HL7
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert "exceeds max size" in rows[0]["error"]
    assert rows[0]["raw"] == "x" * 100  # raw preserved
    assert rows[0]["message_type"] == ContentType.JSON.value


async def test_text_under_cap_received(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_JSON", ContentType.JSON)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_JSON"], b"hello")
    assert ack is None
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.RECEIVED.value
    assert rows[0]["raw"] == "hello"


async def test_text_boundary_exact_cap_accepted(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_JSON", ContentType.JSON)
    runner = RegistryRunner(reg, store)

    # exactly len == cap is accepted (RECEIVED); cap + 1 is ERROR
    await runner._handle_inbound(reg.inbound["IB_JSON"], ("a" * 64).encode("utf-8"))
    await runner._handle_inbound(reg.inbound["IB_JSON"], ("b" * 65).encode("utf-8"))

    rows = sorted(await _rows(store), key=lambda r: len(r["raw"]))
    assert rows[0]["status"] == MessageStatus.RECEIVED.value  # 64 chars
    assert rows[1]["status"] == MessageStatus.ERROR.value  # 65 chars
    assert "exceeds max size" in rows[1]["error"]


# --- BINARY branch (DICOM) ----------------------------------------------------


async def test_binary_over_cap_records_error(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_DICOM", ContentType.DICOM)
    runner = RegistryRunner(reg, store)

    # INGEST-4: a NUL-bearing over-cap body must NOT be stored as a latin-1 view (a stored U+0000 is
    # rejected by Postgres at bind / truncated by SQLite/SQL Server). The over-cap ERROR raw is now the
    # ADR 0028 mfb64:v1: byte-carriage — NUL-free, byte-for-byte recoverable via RawMessage.raw_bytes.
    body = b"\x00\xff" * 50  # 100 bytes > 64 cap, carries a NUL
    ack = await runner._handle_inbound(reg.inbound["IB_DICOM"], body)

    assert ack is None
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert "exceeds max size" in rows[0]["error"]
    assert is_marked(rows[0]["raw"])  # escalated to base64 carriage because of the NUL
    assert "\x00" not in rows[0]["raw"]  # nothing store-hostile reaches the column
    assert RawMessage(rows[0]["raw"], "dicom").raw_bytes == body  # exact bytes recoverable
    assert rows[0]["message_type"] == ContentType.DICOM.value


async def test_binary_over_cap_nul_free_stays_plain_latin1(
    store: MessageStore, monkeypatch
) -> None:
    # INGEST-4 anti-over-rejection: a NUL-FREE byte view is store-safe (U+0001..U+00FF ride TEXT/NVARCHAR
    # intact), so the helper must keep the faithful, human-readable latin-1 view — NOT base64 everything.
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_DICOM", ContentType.DICOM)
    runner = RegistryRunner(reg, store)

    body = b"\xff\xfe" * 50  # 100 bytes > 64 cap, NO NUL
    ack = await runner._handle_inbound(reg.inbound["IB_DICOM"], body)

    assert ack is None
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert not is_marked(rows[0]["raw"])  # NOT base64 — kept the readable byte view
    assert rows[0]["raw"].encode("latin-1") == body


async def test_binary_under_cap_received(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_DICOM", ContentType.DICOM)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_DICOM"], b"\x00\x01\x02\x03")
    assert ack is None
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.RECEIVED.value  # base64-carried, not ERROR


async def test_binary_boundary_measured_on_raw_bytes(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_DICOM", ContentType.DICOM)
    runner = RegistryRunner(reg, store)

    # The cap is measured on the RAW bytes (pre-base64-inflation): 64 raw bytes is accepted even though
    # its base64 carriage form is larger; 65 raw bytes is rejected.
    await runner._handle_inbound(reg.inbound["IB_DICOM"], b"a" * 64)
    await runner._handle_inbound(reg.inbound["IB_DICOM"], b"b" * 65)

    rows = await _rows(store)
    statuses = sorted(r["status"] for r in rows)
    assert statuses == sorted([MessageStatus.RECEIVED.value, MessageStatus.ERROR.value])


# --- INGEST-4: NUL (U+0000) in a decoded body — decode-error path + post-decode guard --------------
#
# A NUL is valid UTF-8, so it does NOT always trip the decode-error branch; it rides the HAPPY path too
# (an HL7 field value, a JSON string). Left un-guarded it reaches the store column, where Postgres
# REJECTS it at bind (uncaught → the whole TCP connection is dropped with NO ERROR row: a count-and-log
# violation, CLAUDE.md §2) and SQLite/SQL Server TRUNCATE at the first NUL. The fix records ERROR (raw as
# ADR 0028 base64 carriage, exact bytes recoverable) and — for HL7 — NAKs AR, on EVERY backend.

# Synthetic HL7 only (never real PHI). \xff makes the first body invalid UTF-8 (decode-error path); the
# happy bodies are valid UTF-8 so they reach the post-decode NUL guard.
_HL7_DECODE_ERR_NUL = b"MSH|^~\\&|S|F|R|F|20260101||ADT^A01|MSG1|P|2.5\rPID|1||X\x00Y\xff\r"
_HL7_DECODE_ERR_NO_NUL = b"MSH|^~\\&|S|F|R|F|20260101||ADT^A01|MSG1|P|2.5\rPID|1||caf\xe9\r"
_HL7_HAPPY_NUL = b"MSH|^~\\&|S|F|R|F|20260101||ADT^A01|MSG1|P|2.5\rPID|1||X\x00Y\r"
_JSON_HAPPY_NUL = b'{"patient":"X\x00Y"}'
_JSON_NO_NUL = b'{"patient":"XY"}'


async def test_hl7_decode_error_nul_dead_letters_mfb64_and_naks(store: MessageStore) -> None:
    # NUL + invalid-UTF-8 → the decode-error branch. Its raw view carries the NUL, so the helper escalates
    # to base64 carriage; an AR NAK is returned (a malformed body, exactly like the decode/parse errors).
    reg = _registry("IB_HL7", ContentType.HL7V2)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_HL7"], _HL7_DECODE_ERR_NUL)

    assert _is_ar_nak(ack)
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert is_marked(rows[0]["raw"]) and "\x00" not in rows[0]["raw"]
    assert RawMessage(rows[0]["raw"], "hl7v2").raw_bytes == _HL7_DECODE_ERR_NUL


async def test_hl7_decode_error_no_nul_stays_plain_latin1(store: MessageStore) -> None:
    # NUL-FREE invalid-UTF-8 → decode-error branch, but the byte view has no NUL, so it stays the readable
    # latin-1 view (anti-over-rejection: only U+0000 escalates to base64).
    reg = _registry("IB_HL7", ContentType.HL7V2)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_HL7"], _HL7_DECODE_ERR_NO_NUL)

    assert _is_ar_nak(ack)
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert not is_marked(rows[0]["raw"])
    assert rows[0]["raw"].encode("latin-1") == _HL7_DECODE_ERR_NO_NUL


async def test_hl7_happy_body_with_nul_is_dead_lettered_not_received(store: MessageStore) -> None:
    # The load-bearing happy-path case: a VALID, parseable HL7 body whose PID field carries a NUL. Pre-fix
    # this routed on SQLite (Python round-trip) and dropped the connection on Postgres. Now: ERROR + AR NAK
    # BEFORE any routing, on every backend; the exact bytes survive as base64 carriage.
    reg = _registry("IB_HL7", ContentType.HL7V2)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_HL7"], _HL7_HAPPY_NUL)

    assert _is_ar_nak(ack)
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value  # NOT RECEIVED
    assert "NUL" in rows[0]["error"]
    assert is_marked(rows[0]["raw"]) and "\x00" not in rows[0]["raw"]
    assert RawMessage(rows[0]["raw"], "hl7v2").raw_bytes == _HL7_HAPPY_NUL


async def test_json_happy_body_with_nul_is_dead_lettered_no_ack(store: MessageStore) -> None:
    # Twin for a non-HL7 text body: a JSON string value carrying a NUL. Same guard, but no HL7 ACK for a
    # non-HL7 content type (return None), consistent with the other non-HL7 error branches.
    reg = _registry("IB_JSON", ContentType.JSON)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_JSON"], _JSON_HAPPY_NUL)

    assert ack is None
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert is_marked(rows[0]["raw"]) and "\x00" not in rows[0]["raw"]
    assert RawMessage(rows[0]["raw"], "json").raw_bytes == _JSON_HAPPY_NUL


async def test_json_no_nul_still_received_not_over_rejected(store: MessageStore) -> None:
    # Regression: a NUL-FREE JSON body is unaffected — still RECEIVED, stored verbatim, not base64.
    reg = _registry("IB_JSON", ContentType.JSON)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_JSON"], _JSON_NO_NUL)

    assert ack is None
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.RECEIVED.value
    assert rows[0]["raw"] == _JSON_NO_NUL.decode("utf-8")
    assert not is_marked(rows[0]["raw"])


# --- INGEST-4: the two HTTP-listener sites (_handle_inbound_http) — genuine new coverage -----------
#
# Nothing drives _handle_inbound_http directly today, so its decode-error latin-1 site and its post-decode
# NUL guard were unexercised. HTTP owns its own 202/4xx receipt, so both branches record ERROR and return
# None (no HL7 ACK).


async def test_http_decode_error_nul_dead_letters_mfb64_returns_none(store: MessageStore) -> None:
    reg = _registry("IB_HL7", ContentType.HL7V2)
    runner = RegistryRunner(reg, store)

    result = await runner._handle_inbound_http(reg.inbound["IB_HL7"], _HL7_DECODE_ERR_NUL)

    assert result is None  # 202-without-id receipt
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert is_marked(rows[0]["raw"]) and "\x00" not in rows[0]["raw"]
    assert RawMessage(rows[0]["raw"], "hl7v2").raw_bytes == _HL7_DECODE_ERR_NUL


async def test_http_happy_body_with_nul_dead_letters_returns_none(store: MessageStore) -> None:
    reg = _registry("IB_HL7", ContentType.HL7V2)
    runner = RegistryRunner(reg, store)

    result = await runner._handle_inbound_http(reg.inbound["IB_HL7"], _HL7_HAPPY_NUL)

    assert result is None
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert "NUL" in rows[0]["error"]
    assert is_marked(rows[0]["raw"]) and "\x00" not in rows[0]["raw"]
    assert RawMessage(rows[0]["raw"], "hl7v2").raw_bytes == _HL7_HAPPY_NUL


# --- INGEST-4: PHI-no-log regression (FEATURE-COVERAGE-PLAN.md:759) --------------------------------

# The shared canary stands in for PHI in the dead-lettered body; it must never surface in a log record
# or the persisted messages.error text (which carries only the fixed reason string).
_PHI_CANARY = "Secretpatient^Phicanary^DoNotLog"


async def test_nul_dead_letter_does_not_log_or_persist_phi(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    reg = _registry("IB_HL7", ContentType.HL7V2)
    runner = RegistryRunner(reg, store)
    body = (
        f"MSH|^~\\&|S|F|R|F|20260101||ADT^A01|MSG1|P|2.5\rPID|1||MRN1^^^H^MR||{_PHI_CANARY}\x00\r"
    ).encode("utf-8")

    with caplog.at_level(logging.DEBUG):
        await runner._handle_inbound(reg.inbound["IB_HL7"], body)

    rows = await _rows(store)
    assert len(rows) == 1 and rows[0]["status"] == MessageStatus.ERROR.value  # anti-vacuity
    assert _PHI_CANARY not in caplog.text and "Secretpatient" not in caplog.text
    assert _PHI_CANARY not in (rows[0]["error"] or "")
    assert "Secretpatient" not in (rows[0]["error"] or "")
