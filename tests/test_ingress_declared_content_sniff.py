# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 5.2.2 (BACKLOG #1109): the declared-content-type sniff on the NETWORK-LISTENER sources.

The file sources have run ``_content_matches_declared`` since the 5.2.2 hardening
(``transports/file.py``, ``transports/remotefile.py``), quarantining a body that contradicts its
inbound's declared ``content_type`` to the ``.error`` directory before it reaches the pipeline. The
network listeners -- MLLP, TCP, the HTTP listener and the database poll -- got only the size ceiling,
the declared-encoding decode and the NUL check, so a ``content_type=json`` inbound committed a body
that was not JSON.

These tests pin the same check on the shared ingress handlers those listeners funnel through, with the
disposition a socket can actually take: a persisted ``ERROR`` row (count-and-log -- recorded, never
accepted-and-dropped), because there is no ``.error`` directory on a socket. Three properties carry the
weight, and the second and third are the controls:

* a body contradicting its declared type is dead-lettered, on every network source and content type
  that has a signature;
* a CONFORMANT body of the same type still reaches ``RECEIVED`` -- without this, a blanket reject
  passes the first property and breaks every feed;
* the ``hl7v2`` branch is UNCHANGED. ``Peek.parse`` already rejects every body this sniff would (it
  additionally rejects an FHS/BHS batch header the sniff accepts), so the sniff was deliberately not
  wired there; the test that an HL7 mismatch still reports a *parse* error is what tells the two apart.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing import RawMessage
from messagefoundry.parsing.binary import is_marked
from messagefoundry.parsing.sniff import text_sniff_head
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore

#: The four network-listener sources BACKLOG #1109 names. MLLP/TCP/DATABASE reach the pipeline through
#: ``_handle_inbound``; HTTP has its own receipt-returning twin, ``_handle_inbound_http`` (exercised
#: separately below), so it is not in this list.
_HANDLE_INBOUND_SOURCES = (ConnectorType.MLLP, ConnectorType.TCP, ConnectorType.DATABASE)

#: Synthetic only -- never real PHI. A valid HL7 v2 message, used as a body that is CONFORMANT for an
#: ``hl7v2`` inbound and a MISMATCH for an ``x12`` one.
_HL7_BODY = b"MSH|^~\\&|SND|FAC|RCV|FAC|20260101||ADT^A01|MSG1|P|2.5\rPID|1||MRN1\r"

#: A DICOM Part-10 stub: 128-byte preamble + the ``DICM`` magic (the whole signature the sniff checks).
_DICOM_BODY = b"\x00" * 128 + b"DICM" + b"payload"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _registry(
    content_type: ContentType,
    *,
    source: ConnectorType = ConnectorType.MLLP,
    settings: dict | None = None,
) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name="IB_TEST",
            spec=ConnectionSpec(source, settings or {}),
            router="r",
            content_type=content_type,
        )
    )
    reg.add_router("r", lambda m: [])  # no-op router; routing is never reached in these tests
    return reg


async def _rows(store: MessageStore) -> list[dict]:
    cur = await store._db.execute("SELECT status, error, raw, message_type FROM messages")
    return [dict(r) for r in await cur.fetchall()]


async def _one_row(store: MessageStore) -> dict:
    rows = await _rows(store)
    assert len(rows) == 1  # anti-vacuity: exactly one disposition was recorded
    return rows[0]


def _is_mismatch(row: dict) -> bool:
    return row[
        "status"
    ] == MessageStatus.ERROR.value and "does not match its declared content type" in (
        row["error"] or ""
    )


# --- the four named sources: a mismatch is dead-lettered, not committed ----------------------------


@pytest.mark.parametrize("source", _HANDLE_INBOUND_SOURCES)
async def test_mismatch_dead_letters_on_every_network_source(
    store: MessageStore, source: ConnectorType
) -> None:
    # The residual BACKLOG #1109 names, on each source that reaches the shared handler: a
    # content_type=json inbound handed a body that is not JSON.
    reg = _registry(ContentType.JSON, source=source)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_TEST"], b"%PDF-1.7 not json at all")

    assert ack is None  # no HL7 ACK for a non-HL7 content type
    row = await _one_row(store)
    assert _is_mismatch(row)
    assert "json" in row["error"]
    assert row["message_type"] == ContentType.JSON.value
    assert row["raw"] == "%PDF-1.7 not json at all"  # body preserved, never a silent drop


async def test_http_listener_mismatch_dead_letters_and_returns_no_receipt(
    store: MessageStore,
) -> None:
    # The HTTP listener's own handler (ADR 0023): the same guard, but the receipt is None (the source
    # maps that to a 202 without an id) rather than a wire ACK.
    reg = _registry(ContentType.JSON, source=ConnectorType.HTTP)
    runner = RegistryRunner(reg, store)

    result = await runner._handle_inbound_http(reg.inbound["IB_TEST"], b"<not>json</not>")

    assert result is None
    assert _is_mismatch(await _one_row(store))


# --- per-content-type coverage --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        (ContentType.JSON, b"%PDF-1.7 not json"),
        (ContentType.FHIR, b"<Patient/>"),  # FHIR is HL7 FHIR JSON, so XML contradicts it
        (ContentType.XML, b'{"a":1}'),
        (ContentType.X12, _HL7_BODY),  # an HL7 message on an x12 inbound: no leading ISA
    ],
)
async def test_text_content_types_reject_a_contradicting_body(
    store: MessageStore, content_type: ContentType, body: bytes
) -> None:
    reg = _registry(content_type)
    runner = RegistryRunner(reg, store)

    assert await runner._handle_inbound(reg.inbound["IB_TEST"], body) is None
    row = await _one_row(store)
    assert _is_mismatch(row)
    assert row["message_type"] == content_type.value


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        (ContentType.JSON, b'{"patient":"synthetic"}'),
        (ContentType.JSON, b"[1,2,3]"),  # a top-level array is JSON too
        (ContentType.FHIR, b'{"resourceType":"Patient"}'),
        (ContentType.XML, b'<?xml version="1.0"?><root/>'),
        (ContentType.X12, b"ISA*00*          *00*"),
    ],
)
async def test_conformant_text_body_is_still_received(
    store: MessageStore, content_type: ContentType, body: bytes
) -> None:
    # The anti-over-rejection control. Without it a blanket reject would satisfy every test above.
    reg = _registry(content_type)
    runner = RegistryRunner(reg, store)

    assert await runner._handle_inbound(reg.inbound["IB_TEST"], body) is None
    row = await _one_row(store)
    assert row["status"] == MessageStatus.RECEIVED.value
    assert row["raw"] == body.decode("utf-8")


async def test_leading_whitespace_does_not_cause_a_false_reject(store: MessageStore) -> None:
    # text_sniff_head strips leading whitespace/BOM in str space before it takes its head, so a body
    # padded far past the head length still sniffs on its first SIGNIFICANT character.
    reg = _registry(ContentType.JSON)
    runner = RegistryRunner(reg, store)

    await runner._handle_inbound(reg.inbound["IB_TEST"], (" " * 500 + '{"a":1}').encode("utf-8"))

    assert (await _one_row(store))["status"] == MessageStatus.RECEIVED.value


# --- the binary branch (DICOM carries a signature; BINARY does not) --------------------------------


async def test_dicom_inbound_rejects_a_body_without_the_part10_magic(store: MessageStore) -> None:
    reg = _registry(ContentType.DICOM)
    runner = RegistryRunner(reg, store)
    body = b"%PDF-1.7 " + b"a" * 200  # long enough to clear the 132-byte length floor, wrong magic

    assert await runner._handle_inbound(reg.inbound["IB_TEST"], body) is None
    row = await _one_row(store)
    assert _is_mismatch(row)
    assert row["raw"].encode("latin-1") == body  # NUL-free, so the readable byte view is kept


async def test_dicom_mismatch_with_a_nul_is_carried_as_base64(store: MessageStore) -> None:
    # INGEST-4: the ERROR raw for a rejected BINARY body must never put a U+0000 in the store column.
    reg = _registry(ContentType.DICOM)
    runner = RegistryRunner(reg, store)
    body = b"\x00\xff" * 100  # 200 bytes, no DICM magic, carries NULs

    await runner._handle_inbound(reg.inbound["IB_TEST"], body)
    row = await _one_row(store)
    assert _is_mismatch(row)
    assert is_marked(row["raw"]) and "\x00" not in row["raw"]
    assert RawMessage(row["raw"], "dicom").raw_bytes == body  # exact bytes still recoverable


async def test_conformant_dicom_is_still_received(store: MessageStore) -> None:
    reg = _registry(ContentType.DICOM)
    runner = RegistryRunner(reg, store)

    await runner._handle_inbound(reg.inbound["IB_TEST"], _DICOM_BODY)

    assert (await _one_row(store))["status"] == MessageStatus.RECEIVED.value


@pytest.mark.parametrize("content_type", [ContentType.BINARY, ContentType.TEXT])
async def test_signatureless_types_stay_accepted_unchecked(
    store: MessageStore, content_type: ContentType
) -> None:
    # The stated policy in parsing/sniff.py: binary is opaque bytes and text is arbitrary, so neither
    # has a reliable leading signature and both are admitted as-is. Pinned so the sniff cannot quietly
    # grow a rule for them.
    reg = _registry(content_type)
    runner = RegistryRunner(reg, store)

    await runner._handle_inbound(reg.inbound["IB_TEST"], b"%PDF-1.7 arbitrary bytes")

    assert (await _one_row(store))["status"] == MessageStatus.RECEIVED.value


# --- the hl7v2 branch is deliberately UNCHANGED ----------------------------------------------------


async def test_hl7_inbound_still_reports_a_parse_error_not_a_content_mismatch(
    store: MessageStore,
) -> None:
    # The discriminator for "the sniff was NOT wired into the HL7 branch". Peek.parse already rejects a
    # non-HL7 body (measured: it also rejects an FHS/BHS batch header the sniff accepts, so it is
    # strictly stronger), and it NAKs. A mismatch reason appearing here would mean a weaker duplicate
    # check had been added in front of it.
    reg = _registry(ContentType.HL7V2)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_TEST"], b'{"a":1}')

    assert ack is not None and "MSA|AR" in ack  # still NAKed, as before
    row = await _one_row(store)
    assert row["status"] == MessageStatus.ERROR.value
    assert "parse error" in (row["error"] or "")
    assert not _is_mismatch(row)


async def test_conformant_hl7_is_unaffected(store: MessageStore) -> None:
    reg = _registry(ContentType.HL7V2)
    runner = RegistryRunner(reg, store)

    await runner._handle_inbound(reg.inbound["IB_TEST"], _HL7_BODY)

    assert (await _one_row(store))["status"] == MessageStatus.RECEIVED.value


# --- encoding independence: the reason the network path sniffs the DECODED head --------------------


async def test_utf16_json_inbound_is_not_falsely_quarantined(store: MessageStore) -> None:
    # A network listener decodes with the connection's declared encoding before anything else. Sniffing
    # the ORIGINAL bytes (what the file sources do, having no declared encoding) would reject this
    # legitimate body, whose first bytes are a BOM and an interleaved NUL rather than "{".
    reg = _registry(ContentType.JSON, settings={"encoding": "utf-16"})
    runner = RegistryRunner(reg, store)

    await runner._handle_inbound(reg.inbound["IB_TEST"], '{"a":1}'.encode("utf-16"))

    row = await _one_row(store)
    assert row["status"] == MessageStatus.RECEIVED.value
    assert row["raw"] == '{"a":1}'


async def test_utf16_non_json_body_is_still_rejected(store: MessageStore) -> None:
    # The control for the test above: encoding-independence must not become encoding-blindness.
    reg = _registry(ContentType.JSON, settings={"encoding": "utf-16"})
    runner = RegistryRunner(reg, store)

    await runner._handle_inbound(reg.inbound["IB_TEST"], "plain prose, not json".encode("utf-16"))

    assert _is_mismatch(await _one_row(store))


def test_text_sniff_head_strips_leading_noise_and_is_bounded() -> None:
    assert text_sniff_head('{"a":1}') == b'{"a":1}'[:8]
    assert text_sniff_head("\ufeff  \r\n{}") == b"{}"  # decoded BOM + whitespace stripped
    assert text_sniff_head(" " * 10_000 + "ISA*00*") == b"ISA*00*"
    assert len(text_sniff_head("x" * 10_000)) == 8  # bounded, never the whole body


# --- PHI: a rejected body must not reach the log or the persisted reason ---------------------------

_PHI_CANARY = "Secretpatient^Phicanary^DoNotLog"


async def test_mismatch_does_not_log_or_persist_phi(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    reg = _registry(ContentType.JSON)
    runner = RegistryRunner(reg, store)
    body = f"PID|1||MRN1^^^H^MR||{_PHI_CANARY}".encode()  # not JSON -> rejected

    with caplog.at_level(logging.DEBUG):
        await runner._handle_inbound(reg.inbound["IB_TEST"], body)

    row = await _one_row(store)
    assert _is_mismatch(row)  # anti-vacuity

    # Scoped to MessageFoundry's OWN loggers on purpose. The rejected body is stored (count-and-log
    # requires it), so the aiosqlite driver's DEBUG statement echo necessarily repeats the bound
    # parameters -- that is the driver's debug channel, not engine logging, and asserting over it would
    # test aiosqlite. What CLAUDE.md section 9 binds is what the ENGINE writes to the log, and the
    # answer here is nothing: the mismatch reason names the declared type only.
    engine_log = "\n".join(
        r.getMessage() for r in caplog.records if r.name.startswith("messagefoundry")
    )
    assert _PHI_CANARY not in engine_log and "Secretpatient" not in engine_log
    assert _PHI_CANARY not in (row["error"] or "")
