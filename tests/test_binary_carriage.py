# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
)
from messagefoundry.pipeline.dryrun import route_only, transform_one
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.crypto import PREFIX, generate_key, make_cipher
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
    assert _raw_at_rest(db).startswith(PREFIX)  # outer layer: encrypted on disk
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
    runner = RegistryRunner(reg, store=store)  # type: ignore[arg-type]

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
    runner = RegistryRunner(reg, store=store)  # type: ignore[arg-type]

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
    previews, _state = transform_one(reg, "h", carried, "binary")
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
