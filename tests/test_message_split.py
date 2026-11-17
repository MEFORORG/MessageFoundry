# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Message split (Tier 2.2): batch file-ingress split + per-OBR message split.

Two parts:
* the pure splitters in :mod:`messagefoundry.parsing.split` (``split_batch`` / ``split_by_obr``); and
* the File source emitting one pipeline hand-off per message in a batch file, in file order, while
  preserving at-least-once (the file is moved only after every message is handed off).

All HL7 here is synthetic (fake MSH/PID/OBR/OBX), never real PHI.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

import messagefoundry.parsing._builtin_hl7 as _builtin_hl7
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.parsing import Message, split_batch, split_by_obr
from messagefoundry.parsing import split as split_module
from messagefoundry.parsing.sniff import _LEADING_WS_STR
from messagefoundry.parsing.split import encode_batch, split_batch_bytes
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
    # BACKLOG #5806: nor a BTS/FTS trailer at the end of the last one.
    assert msgs[-1] == ADT_A02


def test_split_batch_drops_every_envelope_line_of_a_multi_batch_file() -> None:
    """BACKLOG #5806: the trailer and the next batch's header ended the message before them, so the
    last message of each batch carried envelope lines into the pipeline as segments. Mutation: drop
    the ``_without_trailer`` pass in split_batch. Red: the members end with BTS/BHS/FTS."""
    filed = (
        "FHS|^~\\&|SEND|FAC\rBHS|^~\\&|SEND|FAC\r"
        + ADT_A01
        + "BTS|1\rBHS|^~\\&|SEND|FAC\r"
        + ADT_A02
        + ADT_A03
        + "BTS|2\r\rFTS|2\r"
    )
    # A member cut at the next MSH loses the CR before it, as every batch member always has.
    assert split_batch(filed) == [ADT_A01, ADT_A02.rstrip("\r"), ADT_A03]


def test_split_batch_and_encode_batch_round_trip_a_batch_with_its_trailer() -> None:
    """BACKLOG #5806: the encode side writes a BTS trailer, and the split gave it back as a segment
    of the last member. Mutation as above. Red: the last member ends with ``BTS|3``."""
    members = [ADT_A01, ADT_A02, ADT_A03]
    envelope = encode_batch([*members], control_id="1", timestamp="20260101120000")
    split = split_batch(envelope)
    # A member cut at the next MSH loses the CR before it; the last keeps its own.
    assert split == [ADT_A01.rstrip("\r"), ADT_A02.rstrip("\r"), ADT_A03]


BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"


@pytest.mark.parametrize(
    "tail",
    [
        "BTS|1\rFTS|1\r" + BOM + "FHS|^~\\&|SEND|FAC\r" + BOM + "BHS|^~\\&|SEND|FAC\r",
        "BTS|1\rFTS|1\r  \t\r",
        "BTS|1\r\x0c\r" + BOM + "\rFTS|1\r",
    ],
    ids=["marked-next-file-header", "trailing-whitespace-line", "noise-lines-between"],
)
def test_split_batch_reads_an_envelope_run_past_tolerated_noise(tail: str) -> None:
    """Round-one review of BACKLOG #5806: a mark-led envelope line (two marked batch files
    concatenated, a boundary since #5918) or a line of whitespace alone stopped the run, so the
    trailer before it stayed on the member. Mutation: match the envelope ids without the noise
    class, or skip only empty lines. Red: the first member ends with ``BTS|1``."""
    assert split_batch(ADT_A01 + tail + ADT_A02)[0] == ADT_A01


def test_the_split_noise_classes_are_the_ones_they_name() -> None:
    """The leading class is spelled out for the ReDoS scanner and must stay the content sniff's one
    definition of tolerated noise. Every other class is :data:`split._NOISE`: the run the leading
    walk reads past after an envelope line, the class an envelope line opens with (line breaks
    aside), and, as bytes, the class the fast path reads before an envelope id. Round two of
    BACKLOG #5806's review: the walk read the sniff's class where the end of a message read every
    space, so a first chunk of envelope lines could become a message."""
    chars = [chr(c) for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF]
    leading = {ch for ch in chars if split_module._LEADING_NOISE.fullmatch(ch)}
    assert leading == set(_LEADING_WS_STR)
    noise = set(split_module._NOISE)
    assert {ch for ch in chars if split_module._NOISE_RUN.fullmatch(ch)} == noise
    in_line = {ch for ch in chars if split_module._ENVELOPE_ID.match(ch + "BTS")}
    assert in_line == noise - {"\r", "\n"}
    assert {ch for ch in chars if split_module._IN_LINE_NOISE_ONLY.fullmatch(ch)} == in_line
    # The byte class: each ASCII noise byte, and the mark's three bytes.
    pattern = split_module._ENVELOPE_ID_BYTES
    in_bytes = {b for b in range(256) if pattern.fullmatch(b"\r" + bytes([b]) + b"BTS")}
    assert in_bytes == {ord(ch) for ch in in_line if ch.isascii()} | set(b"\xef\xbb\xbf")
    # Every noise character reads the same in a latin-1 view and a UTF-8 decode (BACKLOG #5806
    # round two, finding 2): ASCII, and the mark, which the dry run spells as itself.
    assert all(ch.isascii() for ch in noise - {BOM})


@pytest.mark.parametrize(
    "data",
    ["FHS 140 bpm regular", "BTSX|1", "FTS_LIKE", "FHS: 140 bpm", "BTS-1", "FHS^1"],
    ids=["space", "letter", "underscore", "colon", "hyphen", "other-separator"],
)
def test_a_data_line_that_only_begins_with_an_envelope_id_is_kept(data: str) -> None:
    """Round-two and round-three review of BACKLOG #5806: any line beginning with the letters, and
    then any one beginning with them and a punctuation mark, was dropped, so a wrapped text line
    such as a fetal heart rate note was cut from the stored message. An envelope line takes the
    message's own field separator (MSH-1). Mutation: accept any non-word character after the id.
    Red: the colon, hyphen and caret lines are gone."""
    body = ADT_A01 + data + "\r"
    assert split_batch(body) == [body]
    assert split_batch_bytes(body.encode("utf-8"), "utf-8") == [body.encode("utf-8")]


def test_an_envelope_line_reads_the_members_own_separator() -> None:
    """Control: a member whose MSH-1 is ``^`` loses a ``BTS^`` trailer and keeps a ``BTS|`` line,
    and the header run before it is read with the same separator."""
    member = "MSH^~|\\&^A^B\rPID^1\r"
    assert split_batch("FHS^x\rBHS^x\r" + member + "BTS|1\rBTS^1\rFTS^1\r") == [member + "BTS|1\r"]


def test_a_trailer_followed_by_a_frame_end_byte_is_still_dropped() -> None:
    """Round-two review of BACKLOG #5806: an MLLP capture can end with ``\\x1c``, which
    ``str.isspace`` reads as whitespace, and the sniff's noise class kept the trailer before it.
    Red with the sniff's class: the member ends with ``BTS|1``."""
    assert split_batch(ADT_A01 + "BTS|1\rFTS|1\r\x1c\r" + ADT_A02)[0] == ADT_A01


def test_base64_data_holding_an_envelope_id_stays_on_the_fast_path() -> None:
    """Round-three review of BACKLOG #5806, finding 5: the byte scan took an envelope id anywhere,
    so a one-message file carrying an embedded document whose base64 text holds ``BHS`` paid a
    decode and a split. Mutation: search ``[BF][HT]S`` anywhere. Red: the file needs a decode."""
    document = "JVBERi0xLjQKBHSx" + "QUJD" * 64  # synthetic base64 text, "BHS" inside it
    raw = (ADT_A01 + "OBX|1|ED|DOC^Doc||^AP^PDF^Base64^" + document + "\r").encode("utf-8")
    assert b"BHS" in raw
    assert split_module._needs_a_decode(raw, "utf-8") is False
    assert split_batch_bytes(raw, "utf-8") == [raw]


@pytest.mark.parametrize(
    "line", [b"BTS|1", b"  BTS|1", b"\xef\xbb\xbfFHS|", b"\x0b\x1cBHS|"], ids=str
)
@pytest.mark.parametrize("brk", [b"\r", b"\n"], ids=["cr", "lf"])
def test_an_envelope_id_at_a_line_start_still_needs_a_decode(line: bytes, brk: bytes) -> None:
    """Control: an envelope id at a line start, past the noise and marks the split reads past,
    still sends the file to the decode, at the start of the file too."""
    body = ADT_A01.encode("utf-8")
    assert split_module._needs_a_decode(body + brk + line + brk, "utf-8") is True
    assert split_module._needs_a_decode(line + brk + body, "latin-1") is True


@pytest.mark.parametrize("noise", ["\x1c", "\x0b ", BOM, "\t"])
def test_a_first_chunk_of_envelope_lines_and_noise_lines_is_no_message(noise: str) -> None:
    """Round-three review of BACKLOG #5806, finding 3: the leading walk read past the sniff's noise
    class after an envelope line, where the end of a message reads past every noise character, so
    a line of other noise between two header lines made the rest of the first chunk a spurious
    non-``MSH`` message, recorded as an ERROR. Mutation: read past ``_LEADING_NOISE`` after each
    envelope line. Red: a first element of ``\\x1c\\rBHS|...``."""
    filed = "FHS|^~\\&\r" + noise + "\rBHS|^~\\&\r" + ADT_A01 + "BTS|1\rFTS|1\r"
    assert split_batch(filed) == [ADT_A01]


@pytest.mark.parametrize("where", ["head", "tail"])
def test_many_envelope_lines_split_in_linear_time(where: str) -> None:
    """Round-two review of BACKLOG #5806: the first chunk was copied once per envelope line, so a
    file of many such lines took time quadratic in its size (33 s measured at 1.6 MB before the
    walk by index). Mutation: walk the first chunk with ``partition`` and ``lstrip`` again. Red:
    the call outlasts the bound."""
    lines = "BTS|\r" * 400_000
    text = "FHS|\r" + lines + ADT_A01 if where == "head" else ADT_A01 + lines
    began = time.perf_counter()
    assert split_batch(text)[0].startswith("MSH")
    assert time.perf_counter() - began < 10


def test_split_batch_drops_an_empty_leading_batch() -> None:
    """Round-one review of BACKLOG #5806: the first chunk was read past header lines only, so an
    empty first batch became a message of envelope lines, recorded as an ERROR. Mutation: read the
    first chunk past FHS/BHS only. Red: a first element of ``BTS|0`` and ``BHS``."""
    filed = "FHS|^~\\&\rBHS|^~\\&\rBTS|0\rBHS|^~\\&\r" + ADT_A01 + "BTS|1\rFTS|2\r"
    assert split_batch(filed) == [ADT_A01]


@pytest.mark.parametrize("lead", ["", "\r\n"], ids=["msh-led", "whitespace-led"])
def test_one_message_file_with_a_trailer_goes_over_as_a_batch_member_would(lead: str) -> None:
    """Round-one review of BACKLOG #5806: a one-message file led by MSH was handed over as its own
    bytes, trailer included, where the same message led by a header lost it. Mutation: return
    ``raw`` whenever the text starts with MSH. Red: the trailer reaches the Handler."""
    raw = (lead + ADT_A01 + "BTS|1\rFTS|1\r").encode("utf-8")
    assert split_batch_bytes(raw, "utf-8") == [ADT_A01.encode("utf-8")]
    # Control: with no envelope line the file is still handed over as its own bytes.
    clean = (lead + ADT_A01).encode("utf-8")
    assert split_batch_bytes(clean, "utf-8") == [clean]


def test_split_batch_keeps_a_segment_that_only_follows_an_envelope_line() -> None:
    """Control: only the run of envelope lines that ENDS a message goes. A BTS line inside a
    message, before its own segments, is the parser's to read, and a lone MSH line is kept."""
    inner = ADT_A01 + "BTS|1\rNTE|1||note\r"
    assert split_batch(inner) == [inner]
    assert split_batch("MSH|^~\\&|A\r") == ["MSH|^~\\&|A\r"]


def test_split_batch_custom_separators() -> None:
    # A batch whose MSH-1 isn't `|` must still split per-message (not be read as one giant message).
    batch = (
        b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A01^M1^P^2.5.1\r"
        b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A02^M2^P^2.5.1\r"
    )
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


# BACKLOG #1597: the ledger row's seven-segment shape. The blank line sits in the header, before any
# OBR, so a slice that loses it shifts EVERY group: v2 used to land under order 1.
_BLANK_BEFORE_ORDERS = "MSH|^~\\&|LAB|FAC|EHR|HOSP|20260101||ORU^R01|B1|P|2.5.1\rPID|1||500\r\r"
_TWO_ORDERS = "OBR|1|O1\rOBX|1|ST|T||v1\rOBR|2|O2\rOBX|1|ST|T||v2\r"


def _holding_blank_segments(text: str) -> Message:
    """A Message built straight from a parse tree, so it keeps its empty segments.

    ``Message.parse`` drops empty lines (BACKLOG #1594), so since that fix a ``str`` or ``bytes``
    input never reaches ``split_by_obr`` with one. A Message constructed from a parse tree still can,
    and that is the shape #1597 lives in; asserting the blank is really there keeps this honest.
    """
    msg = Message(_builtin_hl7.parse(text))
    assert "\r\r" not in text or "" in msg.segments(), "the fixture lost its blank segment"
    return msg


@pytest.mark.parametrize("via", ["tree", "text"])
@pytest.mark.parametrize(
    "oru",
    [
        _BLANK_BEFORE_ORDERS + _TWO_ORDERS,
        _BLANK_BEFORE_ORDERS.replace("\r\r", "\r") + _TWO_ORDERS,  # control: no blank line
        # A blank line INSIDE an order group, between OBR 1 and its OBX.
        _BLANK_BEFORE_ORDERS.replace("\r\r", "\r") + _TWO_ORDERS.replace("O1\r", "O1\r\r"),
    ],
    ids=["blank-in-header", "control", "blank-in-group"],
)
def test_split_by_obr_keeps_each_observation_with_its_own_order(oru: str, via: str) -> None:
    source = _holding_blank_segments(oru) if via == "tree" else oru
    parts = [Message.parse(p) for p in split_by_obr(source)]
    assert [p.segments() for p in parts] == [["MSH", "PID", "OBR", "OBX"]] * 2
    assert [(p.field("OBR-2"), p.field("OBX-5")) for p in parts] == [("O1", "v1"), ("O2", "v2")]
    assert [p.control_id for p in parts] == ["B1-1", "B1-2"]


def test_split_by_obr_returns_a_zero_obr_message_unsplit_without_its_blank_line() -> None:
    # Message.parse drops the empty line (BACKLOG #1594); nothing else about the message changes.
    adt = ADT_A01.replace("EVN", "\rEVN", 1)  # MSH, blank, EVN, PID
    assert split_by_obr(adt) == [ADT_A01]


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
        ),
        egress=EgressSettings(deny_by_default=False),
    )


async def _until(cond, timeout: float = 2.0) -> None:
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
