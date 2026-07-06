# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Message split (Tier 2.2): batch file-ingress split + per-OBR message split.

Two parts:
* the pure splitters in :mod:`messagefoundry.parsing.split` (``split_batch`` / ``split_by_obr``); and
* the File source emitting one pipeline hand-off per message in a batch file, in file order, while
  preserving at-least-once (the file is moved only after every message is handed off).

All HL7 here is synthetic (fake MSH/PID/OBR/OBX), never real PHI.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.parsing import Message, split_batch, split_by_obr
from messagefoundry.transports import build_source

# --- synthetic fixtures ------------------------------------------------------

ADT_A01 = (
    "MSH|^~\\&|SENDAPP|SENDFAC|RECVAPP|RECVFAC|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^HOSP^MR||DOE^JANE^Q||19800101|F\r"
)
ADT_A02 = ADT_A01.replace("A01", "A02").replace("MSG1", "MSG2")
ADT_A03 = ADT_A01.replace("A01", "A03").replace("MSG1", "MSG3")

# An ORU with two OBR order groups, each carrying its own OBX results, sharing one PID header.
ORU_TWO_OBR = (
    "MSH|^~\\&|LAB|LABFAC|EHR|HOSP|20260101||ORU^R01|OBS1|P|2.5.1\r"
    "PID|1||500^^^HOSP^MR||SMITH^JOHN^Q||19750505|M\r"
    "OBR|1|PLAC1|FILL1|CBC^Complete Blood Count\r"
    "OBX|1|NM|WBC^White Blood Cells||7.2|10*3/uL\r"
    "OBX|2|NM|RBC^Red Blood Cells||4.8|10*6/uL\r"
    "OBR|2|PLAC2|FILL2|BMP^Basic Metabolic Panel\r"
    "OBX|1|NM|GLU^Glucose||95|mg/dL\r"
)
ORU_ONE_OBR = (
    "MSH|^~\\&|LAB|LABFAC|EHR|HOSP|20260101||ORU^R01|OBS9|P|2.5.1\r"
    "PID|1||500^^^HOSP^MR||SMITH^JOHN^Q||19750505|M\r"
    "OBR|1|PLAC1|FILL1|CBC^Complete Blood Count\r"
    "OBX|1|NM|WBC^White Blood Cells||7.2|10*3/uL\r"
)


# --- split_batch -------------------------------------------------------------


def test_split_batch_single_message_unchanged() -> None:
    msgs = split_batch(ADT_A01.encode("utf-8"))
    assert len(msgs) == 1
    # Round-trips to the same normalized message.
    assert Message.parse(msgs[0]).control_id == "MSG1"


def test_split_batch_splits_n_messages_in_file_order() -> None:
    batch = (ADT_A01 + ADT_A02 + ADT_A03).encode("utf-8")
    msgs = split_batch(batch)
    assert [Message.parse(m).control_id for m in msgs] == ["MSG1", "MSG2", "MSG3"]  # FIFO
    # Each split message re-parses cleanly into a standalone message.
    assert [Message.parse(m).trigger_event for m in msgs] == ["A01", "A02", "A03"]


def test_split_batch_tolerates_trailing_newline_and_mixed_endings() -> None:
    # \n / \r\n line endings and a trailing newline must not produce empty/short messages.
    mixed = (ADT_A01 + ADT_A02).replace("\r", "\r\n") + "\n"
    msgs = split_batch(mixed.encode("utf-8"))
    assert [Message.parse(m).control_id for m in msgs] == ["MSG1", "MSG2"]


def test_split_batch_drops_fhs_bhs_envelope() -> None:
    # A batch wrapped in FHS/BHS...BTS/FTS: each message is split out on its MSH; the envelope lines
    # (which carry no per-message meaning once split) are dropped.
    enveloped = (
        "FHS|^~\\&|SEND|FAC\rBHS|^~\\&|SEND|FAC\r" + ADT_A01 + ADT_A02 + "BTS|2\rFTS|1\r"
    ).encode("utf-8")
    msgs = split_batch(enveloped)
    assert [Message.parse(m).control_id for m in msgs] == ["MSG1", "MSG2"]
    assert all(m.startswith("MSH") for m in msgs)  # no FHS/BHS leftover at the head of a message


def test_split_batch_custom_separators() -> None:
    # A batch whose MSH-1 isn't `|` must still split per-message (not be read as one giant message).
    batch = (
        "MSH^~|\\&^A^B^C^D^20260101^^ADT~A01^M1^P^2.5.1\r"
        "MSH^~|\\&^A^B^C^D^20260101^^ADT~A02^M2^P^2.5.1\r"
    ).encode("utf-8")
    msgs = split_batch(batch)
    assert len(msgs) == 2
    assert msgs[0].startswith("MSH^~|\\&^A^B^C^D^20260101^^ADT~A01")
    assert msgs[1].startswith("MSH^~|\\&^A^B^C^D^20260101^^ADT~A02")


def test_split_batch_empty_payload_returns_itself() -> None:
    # An empty/whitespace payload yields the (normalized) text as the sole element — never a silent
    # drop; the parser then reports it malformed.
    assert split_batch(b"   ") == ["   "]


# --- split_by_obr ------------------------------------------------------------


def test_split_by_obr_splits_each_order_group_with_shared_header() -> None:
    parts = split_by_obr(ORU_TWO_OBR)
    assert len(parts) == 2

    first = Message.parse(parts[0])
    second = Message.parse(parts[1])
    # Each part carries the shared header (MSH + PID) plus exactly its own OBR group.
    assert first.segments() == ["MSH", "PID", "OBR", "OBX", "OBX"]
    assert second.segments() == ["MSH", "PID", "OBR", "OBX"]
    # The order group travels with its OBR — group 1's OBX (WBC/RBC) vs group 2's (GLU).
    assert first.field("OBR-4.1") == "CBC"
    assert first.field("OBX-3.1", occurrence=2) == "RBC"
    assert second.field("OBR-4.1") == "BMP"
    assert second.field("OBX-3.1") == "GLU"
    # Shared header (PID) is identical on both.
    assert first.field("PID-5.1") == second.field("PID-5.1") == "SMITH"


def test_split_by_obr_suffixes_control_id_per_index() -> None:
    parts = split_by_obr(ORU_TWO_OBR)
    # Documented MSH-10 contract: each split is suffixed with its 1-based order index so the N
    # messages stay individually correlatable downstream.
    assert [Message.parse(p).control_id for p in parts] == ["OBS1-1", "OBS1-2"]


def test_split_by_obr_single_obr_returns_one_with_suffix() -> None:
    parts = split_by_obr(ORU_ONE_OBR)
    assert len(parts) == 1
    m = Message.parse(parts[0])
    assert m.segments() == ["MSH", "PID", "OBR", "OBX"]
    assert m.control_id == "OBS9-1"  # 1-OBR is still suffixed -1 (documented, not special-cased)


def test_split_by_obr_zero_obr_returns_message_unchanged() -> None:
    # A non-order message (no OBR) is not splittable: returned as-is, control id UNCHANGED (no -1).
    parts = split_by_obr(ADT_A01)
    assert len(parts) == 1
    assert Message.parse(parts[0]).control_id == "MSG1"


def test_split_by_obr_accepts_message_object_and_str_and_bytes() -> None:
    # Match how the other parsing helpers accept input (Message | str | bytes).
    from_msg = split_by_obr(Message.parse(ORU_TWO_OBR))
    from_str = split_by_obr(ORU_TWO_OBR)
    from_bytes = split_by_obr(ORU_TWO_OBR.encode("utf-8"))
    assert from_msg == from_str == from_bytes


def test_split_by_obr_custom_separators() -> None:
    # Separators are read from MSH-1/MSH-2: a `^`-field-separator message still splits per OBR and
    # the control id (MSH-10) suffix is written through the Message primitive, not raw slicing.
    oru = (
        "MSH^~|\\&^LAB^FAC^EHR^HOSP^20260101^^ORU~R01^C1^P^2.5.1\r"
        "PID^1^^500~~~HOSP~MR^^SMITH~JOHN\r"
        "OBR^1^PLAC1^FILL1^CBC\r"
        "OBX^1^NM^WBC^^7.2\r"
        "OBR^2^PLAC2^FILL2^BMP\r"
        "OBX^1^NM^GLU^^95\r"
    )
    parts = split_by_obr(oru)
    assert len(parts) == 2
    assert [Message.parse(p).control_id for p in parts] == ["C1-1", "C1-2"]
    # Group association preserved with the custom component separator.
    assert Message.parse(parts[0]).field("OBR-4.1") == "CBC"
    assert Message.parse(parts[1]).field("OBR-4.1") == "BMP"


def test_split_by_obr_no_control_id_left_untouched() -> None:
    # MSH-10 empty → nothing to suffix; the split still happens, header still shared.
    oru = (
        "MSH|^~\\&|LAB|FAC|EHR|HOSP|20260101||ORU^R01||P|2.5.1\r"
        "PID|1||500^^^HOSP^MR||SMITH^JOHN\r"
        "OBR|1|PLAC1|FILL1|CBC\r"
        "OBR|2|PLAC2|FILL2|BMP\r"
    )
    parts = split_by_obr(oru)
    assert len(parts) == 2
    assert all(Message.parse(p).control_id is None for p in parts)
    assert Message.parse(parts[1]).field("OBR-4.1") == "BMP"


# --- File source: batch split at ingress -------------------------------------


def _source(inbox: Path, **extra: object) -> object:
    return build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(inbox),
                "pattern": "*.hl7",
                "poll_seconds": 0.01,
                **extra,
            },
        )
    )


async def _until(cond, timeout: float = 2.0) -> None:  # type: ignore[no-untyped-def]
    elapsed = 0.0
    while not cond():
        await asyncio.sleep(0.01)
        elapsed += 0.01
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


async def test_file_source_splits_batch_into_n_handoffs_in_order(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "batch.hl7").write_bytes((ADT_A01 + ADT_A02 + ADT_A03).encode("utf-8"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = _source(inbox)
    task = asyncio.create_task(src.start(handler))  # type: ignore[attr-defined]
    try:
        await _until(lambda: len(received) == 3)
    finally:
        await src.stop()  # type: ignore[attr-defined]
        await task
    # Three hand-offs, in file order (FIFO).
    assert [Message.parse(r).control_id for r in received] == ["MSG1", "MSG2", "MSG3"]
    # The file is moved only AFTER all three are emitted.
    assert (inbox / ".processed" / "batch.hl7").exists()
    assert not (inbox / "batch.hl7").exists()


async def test_file_source_single_message_handed_off_verbatim(tmp_path: Path) -> None:
    # A single-message file must be byte-identical to pre-split behavior: one hand-off of the exact
    # on-disk bytes (no normalization / re-encode round-trip).
    inbox = tmp_path / "in"
    inbox.mkdir()
    raw = ADT_A01.encode("utf-8")
    (inbox / "one.hl7").write_bytes(raw)
    received: list[bytes] = []

    async def handler(payload: bytes) -> None:
        received.append(payload)

    src = _source(inbox)
    task = asyncio.create_task(src.start(handler))  # type: ignore[attr-defined]
    try:
        await _until(lambda: bool(received))
    finally:
        await src.stop()  # type: ignore[attr-defined]
        await task
    assert received == [raw]  # exact bytes, not a re-encode
    assert (inbox / ".processed" / "one.hl7").exists()


async def test_file_source_batch_not_moved_when_a_handoff_fails(tmp_path: Path) -> None:
    # at-least-once / no-partial-move: if a hand-off raises (infra/store failure) part-way through a
    # batch, the file stays put and the WHOLE batch is re-emitted next scan — never a file moved with
    # only some messages handed off.
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "batch.hl7").write_bytes((ADT_A01 + ADT_A02 + ADT_A03).encode("utf-8"))
    received: list[bytes] = []
    fail_once = {"armed": True}

    async def handler(raw: bytes) -> None:
        # Fail on the 2nd message of the FIRST scan only; succeed everywhere afterwards.
        if fail_once["armed"] and Message.parse(raw).control_id == "MSG2":
            fail_once["armed"] = False
            raise RuntimeError("store write failed mid-batch")
        received.append(raw)

    src = _source(inbox)
    task = asyncio.create_task(src.start(handler))  # type: ignore[attr-defined]
    try:
        # Eventually a clean scan re-reads the whole file and emits all three.
        await _until(lambda: (inbox / ".processed" / "batch.hl7").exists())
    finally:
        await src.stop()  # type: ignore[attr-defined]
        await task
    # The full batch is delivered (the tail is never dropped). MSG1 is re-emitted (duplicate from the
    # first, aborted scan), which is acceptable at-least-once.
    ids = [Message.parse(r).control_id for r in received]
    assert ids[-3:] == ["MSG1", "MSG2", "MSG3"]  # a clean run of the whole batch, in order
    assert ids.count("MSG1") >= 2  # MSG1 was re-emitted after the mid-batch failure
    assert "MSG3" in ids  # the tail was never accept-and-dropped


async def test_file_source_batch_split_honors_encoding(tmp_path: Path) -> None:
    # A non-UTF-8 batch: split messages are re-encoded with the connection's declared encoding.
    inbox = tmp_path / "in"
    inbox.mkdir()
    m1 = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||1||café\r"
    m2 = "MSH|^~\\&|A|B|C|D|20260101||ADT^A02|MSG2|P|2.5.1\rPID|1||2||naïve\r"
    (inbox / "b.hl7").write_bytes((m1 + m2).encode("latin-1"))
    received: list[bytes] = []

    async def handler(raw: bytes) -> None:
        received.append(raw)

    src = _source(inbox, encoding="latin-1")
    task = asyncio.create_task(src.start(handler))  # type: ignore[attr-defined]
    try:
        await _until(lambda: len(received) == 2)
    finally:
        await src.stop()  # type: ignore[attr-defined]
        await task
    # Each hand-off decodes back with the declared encoding without mojibake (the é/ï survive the
    # split's decode→re-encode round-trip, which would have corrupted them under a UTF-8 assumption).
    # Parse from the latin-1-decoded str (Message.parse would otherwise assume UTF-8 on the bytes).
    assert Message.parse(received[0].decode("latin-1")).field("PID-5") == "café"
    assert Message.parse(received[1].decode("latin-1")).field("PID-5") == "naïve"
