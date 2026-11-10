# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""base64 binary-carriage codec (ADR 0028) — the pure codec, the RawMessage contract, the OBX-5 ED
helpers, the ingress seam, and the load-bearing proof: NUL-bearing binary survives the str/TEXT store
(identity + AES-GCM) where the latin-1 round-trip it supersedes would be rejected/truncated."""

from __future__ import annotations

import pathlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing import Message, RawMessage
from messagefoundry.parsing.binary import (
    MARKER,
    BinaryCarriageError,
    decode,
    embed_obx_document,
    encode,
    extract_obx_document,
    is_marked,
    strip_documents_in_hl7,
)
from messagefoundry.pipeline.dryrun import route_only, transform_one
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.crypto import MARKER_PREFIX, generate_key, make_cipher
from messagefoundry.store.store import MessageStore

# Byte fixtures that break a latin-1/TEXT round-trip: every value 0x00–0xFF (incl. NUL + high bytes),
# and a DICOM-Part-10-like body whose mandatory 128-byte all-zero preamble guarantees NUL.
ALL_BYTES = bytes(range(256)) * 4
DICOM_LIKE = bytes(128) + b"DICM" + bytes(range(256))

OBX_HL7 = "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|1|P|2.5.1\rOBX|1||||\r"


# --- pure codec --------------------------------------------------------------


@pytest.mark.parametrize("data", [b"", b"hello", ALL_BYTES, DICOM_LIKE, b"\x00" * 200])
def test_encode_decode_round_trip(data: bytes) -> None:
    assert decode(encode(data)) == data


def test_encode_is_marked_ascii_and_unbroken() -> None:
    s = encode(ALL_BYTES)
    assert s.startswith(MARKER)
    assert s.isascii()  # safe for a TEXT column on every backend
    assert "\x00" not in s  # the whole point — no NUL to reject/truncate
    assert "\n" not in s and "\r" not in s  # unbroken: b64encode, never encodebytes


def test_is_marked() -> None:
    assert is_marked(encode(b"x"))
    assert not is_marked("plain text")
    assert not is_marked("mfenc:v1:something")  # the cipher envelope is not a carriage marker


def test_decode_requires_marker() -> None:
    with pytest.raises(BinaryCarriageError, match="marker"):
        decode("aGVsbG8=")  # valid base64 but no mfb64: marker — must not silently decode


def test_decode_rejects_corrupt_base64() -> None:
    with pytest.raises(BinaryCarriageError, match="invalid base64"):
        decode(MARKER + "not valid base64 !!!")


def test_decode_tolerates_incidental_whitespace() -> None:
    # A partner (or a copy/paste) may wrap the base64; decode strips whitespace before validating.
    body = encode(ALL_BYTES)[len(MARKER) :]
    wrapped = MARKER + "\r\n".join(body[i : i + 76] for i in range(0, len(body), 76))
    assert decode(wrapped) == ALL_BYTES


# --- RawMessage contract -----------------------------------------------------


def test_rawmessage_from_bytes_round_trip() -> None:
    rm = RawMessage.from_bytes(DICOM_LIKE, "dicom")
    assert rm.is_binary
    assert rm.raw.startswith(MARKER)
    assert "\x00" not in rm.raw  # carriage form is NUL-free, so the TEXT store accepts it
    assert rm.raw_bytes == DICOM_LIKE
    assert rm.binary() == DICOM_LIKE  # method alias
    assert rm.content_type == "dicom"


def test_rawmessage_plain_text_is_not_binary() -> None:
    rm = RawMessage('{"a": 1}', "json")
    assert not rm.is_binary
    with pytest.raises(BinaryCarriageError):
        _ = rm.raw_bytes  # fail loud rather than return mojibake


# --- OBX-5 ED embedding (secondary) ------------------------------------------


def test_obx_ed_embed_extract_round_trip() -> None:
    msg = Message.parse(OBX_HL7)
    pdf = b"%PDF-1.4\n" + bytes(range(256))  # arbitrary binary incl. NUL/high bytes
    embed_obx_document(msg, pdf, data_subtype="PDF")
    encoded = msg.encode()
    assert "\n" not in encoded  # unbroken base64 — no LF planted into the segment stream

    back = Message.parse(encoded)
    assert back.field("OBX-2") == "ED"
    assert back.field("OBX-5.4") == "Base64"
    assert extract_obx_document(back) == pdf


def test_extract_rejects_non_ed_segment() -> None:
    msg = Message.parse("MSH|^~\\&|A|B|C|D|20260101||ORU^R01|1|P|2.5.1\rOBX|1|ST|||hi\r")
    with pytest.raises(BinaryCarriageError, match="not 'ED'"):
        extract_obx_document(msg)


_UNREADABLE_DELIMITER_BODIES = [
    (
        "MSH|^~|A|B|C|D|20260101||ORU^R01|1|P|2.5\rOBX|1|ED|X||^Application^pdf^Base64^JVBERi0=\r",
        "its first MSH's MSH-2 is shorter than four characters",
    ),
    (
        "FHS|^~\\&|A|B\rOBX|1|ED|X||^Application^pdf^Base64^JVBERi0=\r",
        "the body has no MSH",
    ),
]

#: The three Handler-facing OBX readers and writers that refuse unreadable delimiters (BACKLOG #2873).
_DELIMITER_GUARDED: dict[str, Any] = {
    "extract": lambda msg: extract_obx_document(msg),
    "embed": lambda msg: embed_obx_document(msg, b"data", data_subtype="PDF"),
    "strip": lambda msg: strip_documents_in_hl7(msg, pruned_at=0.0),
}


@pytest.mark.parametrize("op", sorted(_DELIMITER_GUARDED))
@pytest.mark.parametrize(("raw", "cause"), _UNREADABLE_DELIMITER_BODIES)
def test_obx_helpers_refuse_unreadable_delimiters_as_binary_carriage_error(
    op: str, raw: str, cause: str
) -> None:
    """BACKLOG #2873: a message whose delimiters cannot be read is refused by name, not with the
    bare ``ValueError`` that quotes MSH-1 and MSH-2, and the message is left as it was."""
    msg = Message.parse(raw)
    before = msg.encode()
    with pytest.raises(BinaryCarriageError) as caught:
        _DELIMITER_GUARDED[op](msg)
    assert str(caught.value).startswith(cause + ",")
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    # The bare refusal's text carries both labels on either body, so this holds on both rows.
    assert "MSH-1=" not in str(caught.value) and "MSH-2=" not in str(caught.value)
    assert msg.encode() == before


@pytest.mark.parametrize("raw", [raw for raw, _ in _UNREADABLE_DELIMITER_BODIES])
def test_unreadable_delimiters_leave_the_callers_own_errors_alone(raw: str) -> None:
    """An occurrence below one, and an embed into an absent OBX, stay the caller's errors, as they
    are on a readable message."""
    msg = Message.parse(raw)
    with pytest.raises(ValueError, match="1-based") as wrong:
        extract_obx_document(msg, occurrence=0)
    assert not isinstance(wrong.value, BinaryCarriageError)
    with pytest.raises(ValueError, match="1-based") as wrong:
        embed_obx_document(msg, b"data", data_subtype="PDF", occurrence=0)
    assert not isinstance(wrong.value, BinaryCarriageError)
    with pytest.raises(KeyError):
        embed_obx_document(msg, b"data", data_subtype="PDF", occurrence=2)


@pytest.mark.parametrize(
    "raw",
    [
        "MSH|^~|A|B|C|D|20260101||ORU^R01|1|P|2.5\rPID|1\r",
        "FHS|^~\\&|A|B\rPID|1\r",
    ],
)
def test_strip_in_hl7_with_no_obx_strips_nothing_on_unreadable_delimiters(raw: str) -> None:
    """With no OBX there is nothing to read, so an unreadable header is no refusal there."""
    assert strip_documents_in_hl7(Message.parse(raw), pruned_at=0.0) == (0, 0)


def test_extract_still_reads_a_segment_group() -> None:
    """The delimiter check does not stop a group-scoped extract, which reads fields only."""
    msg = Message.parse(
        "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|1|P|2.5.1\r"
        "OBR|1\rOBX|1|ED|X||^Application^pdf^Base64^QUFB\r"
        "OBR|2\rOBX|1|ED|X||^Application^pdf^Base64^QkJC\r"
    )
    # Typed for Message, but an untyped Handler script may pass a group, which only needs .field.
    docs = [extract_obx_document(g) for g in msg.groups("OBR")]  # type: ignore[arg-type]
    assert docs == [b"AAA", b"BBB"]


def test_extract_refuses_a_segment_group_of_an_unreadable_message() -> None:
    """A group reads through its parent, so the parent's unreadable MSH-2 is refused by name."""
    msg = Message.parse(
        "MSH|^~|A|B|C|D|20260101||ORU^R01|1|P|2.5\rOBR|1\rOBX|1|ED|X||^Application^pdf^Base64^QUFB\r"
    )
    (group,) = msg.groups("OBR")
    with pytest.raises(BinaryCarriageError, match="^its first MSH's MSH-2 is shorter") as caught:
        extract_obx_document(group)  # type: ignore[arg-type]
    assert "MSH-1=" not in str(caught.value) and "MSH-2=" not in str(caught.value)


@pytest.mark.parametrize("op", sorted(_DELIMITER_GUARDED))
def test_obx_helpers_name_a_handler_written_msh_1_as_the_cause(op: str) -> None:
    """BACKLOG #2873: a Handler that writes a two-character MSH-1 gets the MSH-1 cause named."""
    msg = Message.parse(OBX_HL7)
    embed_obx_document(msg, b"data", data_subtype="PDF")
    msg.set("MSH-1", "##")
    with pytest.raises(BinaryCarriageError, match="^its first MSH's MSH-1 is not one character,"):
        _DELIMITER_GUARDED[op](msg)


def test_extract_rejects_wrong_encoding() -> None:
    msg = Message.parse(OBX_HL7)
    embed_obx_document(msg, b"data", data_subtype="PDF")
    msg.set("OBX-5.4", "Hex")  # corrupt the Encoding component
    with pytest.raises(BinaryCarriageError, match="not 'Base64'"):
        extract_obx_document(msg)


# --- ContentType classification ----------------------------------------------


def test_content_type_is_binary_only_for_binary() -> None:
    assert ContentType.BINARY.is_binary
    for ct in (
        ContentType.HL7V2,
        ContentType.JSON,
        ContentType.XML,
        ContentType.TEXT,
        ContentType.X12,
        ContentType.FHIR,
    ):
        assert not ct.is_binary


# --- the load-bearing proof: NUL-bearing binary survives the str/TEXT store --


def _raw_at_rest(db_path: Path, column: str = "raw", table: str = "messages") -> str:
    """Read a column straight from the DB file, bypassing the store's decryption."""
    con = sqlite3.connect(db_path)
    try:
        return str(con.execute(f"SELECT {column} FROM {table}").fetchone()[0])
    finally:
        con.close()


async def test_binary_carriage_survives_sqlite_store(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "t.db")
    try:
        carried = RawMessage.from_bytes(ALL_BYTES, "binary").raw
        mid = await store.enqueue_ingress(channel_id="IB", raw=carried, message_type="binary")
        record = await store.get_message(mid)
    finally:
        await store.close()
    assert record is not None
    assert "\x00" not in record["raw"]  # stored intact in TEXT — no NUL truncation
    assert RawMessage(record["raw"], "binary").raw_bytes == ALL_BYTES


async def test_binary_carriage_survives_encrypted_store(tmp_path: Path) -> None:
    # The carriage marker is an independent INNER layer beneath the mfenc: cipher envelope: at rest the
    # column is ciphertext; the store decrypts to the mfb64: form on read; .raw_bytes then recovers the
    # bytes. No double-decode, NUL-safe end to end.
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        carried = RawMessage.from_bytes(DICOM_LIKE, "dicom").raw
        mid = await store.enqueue_ingress(channel_id="IB", raw=carried, message_type="dicom")
        record = await store.get_message(mid)
    finally:
        await store.close()
    assert _raw_at_rest(db).startswith(MARKER_PREFIX)  # outer layer: encrypted on disk
    assert record is not None and record["raw"] == carried  # decrypts to the inner mfb64: form
    assert RawMessage(record["raw"], "dicom").raw_bytes == DICOM_LIKE


# --- the ingress seam: _handle_inbound base64-carries a binary content type --


class _RecordingStore:
    """Captures the ingress row the source boundary commits (we only exercise enqueue_ingress)."""

    def __init__(self) -> None:
        self.ingress: list[dict[str, Any]] = []

    async def enqueue_ingress(self, **kwargs: Any) -> str:
        self.ingress.append(kwargs)
        return "mid-1"


async def test_handle_inbound_base64_carries_binary() -> None:
    reg = Registry()
    ic = InboundConnection(
        name="IB_BIN",
        spec=ConnectionSpec(ConnectorType.FILE, {}),
        router="r",
        content_type=ContentType.BINARY,
    )
    reg.add_inbound(ic)
    store = _RecordingStore()
    runner = RegistryRunner(reg, store=store, egress=EgressSettings(deny_by_default=False))  # type: ignore[arg-type]

    ack = await runner._handle_inbound(ic, DICOM_LIKE)

    assert ack is None  # non-HL7: the source owns its own response, no MLLP ACK
    assert len(store.ingress) == 1
    row = store.ingress[0]
    assert row["raw"].startswith(MARKER) and "\x00" not in row["raw"]  # carried, never latin-1
    assert row["message_type"] == "binary"
    assert RawMessage(row["raw"], "binary").raw_bytes == DICOM_LIKE


async def test_handle_inbound_does_not_carry_non_binary() -> None:
    # Pin the .is_binary guard at the seam: a non-HL7, non-binary content type is committed VERBATIM,
    # never mfb64-wrapped. A regression that dropped/inverted the guard would base64-wrap JSON ingress.
    reg = Registry()
    ic = InboundConnection(
        name="IB_JSON",
        spec=ConnectionSpec(ConnectorType.FILE, {}),
        router="r",
        content_type=ContentType.JSON,
    )
    reg.add_inbound(ic)
    store = _RecordingStore()
    runner = RegistryRunner(reg, store=store, egress=EgressSettings(deny_by_default=False))  # type: ignore[arg-type]

    await runner._handle_inbound(ic, b'{"a": 1}')

    assert store.ingress[0]["raw"] == '{"a": 1}'  # verbatim text
    assert not store.ingress[0]["raw"].startswith(MARKER)


# --- the consumer side through the normal routing machinery ------------------


def _binary_registry() -> tuple[Registry, InboundConnection, list[type]]:
    reg = Registry()
    ic = InboundConnection(
        name="IB_BIN",
        spec=ConnectionSpec(ConnectorType.FILE, {}),
        router="r",
        content_type=ContentType.BINARY,
    )
    reg.add_inbound(ic)
    reg.add_outbound(OutboundConnection(name="OUT", spec=ConnectionSpec(ConnectorType.FILE, {})))
    seen: list[type] = []

    def route(msg: Any) -> list[str]:
        seen.append(type(msg))
        return ["h"]

    def handle(msg: Any) -> Send:
        return Send("OUT", str(len(msg.raw_bytes)))  # codec recovers bytes via the accessor

    reg.add_router("r", route)
    reg.add_handler("h", handle)
    return reg, ic, seen


def test_router_and_handler_recover_bytes_via_raw_bytes() -> None:
    reg, ic, seen = _binary_registry()
    carried = RawMessage.from_bytes(ALL_BYTES, "binary").raw
    assert route_only(reg, ic, carried) == ["h"]
    assert seen == [RawMessage]
    previews, _state, _meta, _ = transform_one(reg, "h", carried, "binary")
    assert len(previews) == 1 and previews[0].to == "OUT"
    assert previews[0].payload == str(len(ALL_BYTES))  # 1024 bytes recovered, never hand-rolled


# --- purity (parsing/ console carve-out) -------------------------------------


def test_binary_module_imports_no_engine_packages() -> None:
    """parsing.binary must import zero engine packages so the console can import it (CLAUDE.md §4)."""
    import messagefoundry.parsing.binary as pkg

    forbidden = (
        "messagefoundry.config",
        "messagefoundry.transports",
        "messagefoundry.pipeline",
        "messagefoundry.store",
        "messagefoundry.api",
        "messagefoundry.console",
    )
    offenders = [
        line.strip()
        for line in pathlib.Path(pkg.__file__).read_text(encoding="utf-8").splitlines()
        if any(line.strip().startswith((f"import {p}", f"from {p}")) for p in forbidden)
    ]
    assert not offenders, "parsing.binary imports engine packages:\n" + "\n".join(offenders)
