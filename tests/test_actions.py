# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The typed action vocabulary (ADR 0076 phase 1): behavior + purity (gate 5)."""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Literal

import pytest

import messagefoundry.actions as actions_mod
import messagefoundry_toolkit.lens as lens_mod
from messagefoundry import (
    append_to_field,
    arith_field,
    code_lookup,
    convert_case,
    copy_field,
    copy_segment,
    date_diff_field,
    delete_segment,
    format_date,
    pad_field,
    replace_literal,
    set_field,
    split_field,
    substring_field,
    trim_field,
)
from messagefoundry.config.code_sets import CodeSet
from messagefoundry.parsing.message import Message

ADT = (
    "MSH|^~\\&|SENDAPP|SENDFAC|RECVAPP|RECVFAC|20260101120000||ADT^A01^ADT_A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^HOSP^MR||doe^jane^q||19800101|F\r"
    "NK1|1|SMITH^JOHN\r"
)


def _msg() -> Message:
    return Message.parse(ADT)


# --- behavior ----------------------------------------------------------------


def test_copy_field_copies_value() -> None:
    m = _msg()
    copy_field(m, "PID-5.1", "NK1-2.1")
    assert m["NK1-2.1"] == "doe"
    assert m["NK1-2.2"] == "JOHN"  # sibling component preserved


def test_copy_field_absent_source_clears_dest() -> None:
    m = _msg()
    copy_field(m, "PID-99.1", "NK1-2.1")  # PID-99 absent
    assert m["NK1-2.1"] is None


def test_set_field() -> None:
    m = _msg()
    set_field(m, "PID-3.1", "999")
    assert m["PID-3.1"] == "999"


def test_append_to_field() -> None:
    m = _msg()
    append_to_field(m, "PID-5.1", "-JR")
    assert m["PID-5.1"] == "doe-JR"


def test_append_to_absent_field_is_just_suffix() -> None:
    m = _msg()
    append_to_field(m, "NK1-3.1", "X")
    assert m["NK1-3.1"] == "X"


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("upper", "DOE"), ("lower", "doe"), ("title", "Doe")],
)
def test_convert_case(mode: Literal["upper", "lower", "title"], expected: str) -> None:
    m = _msg()
    convert_case(m, "PID-5.1", mode)
    assert m["PID-5.1"] == expected


def test_convert_case_absent_is_noop() -> None:
    m = _msg()
    convert_case(m, "NK1-9.1", "upper")  # absent -> no-op, no raise
    assert m["NK1-9.1"] is None


def test_convert_case_unknown_mode_raises() -> None:
    m = _msg()
    with pytest.raises(ValueError, match="convert_case mode"):
        convert_case(m, "PID-5.1", "sentence")  # type: ignore[arg-type]  # outside the declared set: the refusal is the subject


def test_format_date_hl7_default() -> None:
    m = _msg()
    format_date(m, "PID-7", "%Y-%m-%d")  # 19800101 (HL7 TS) -> reformatted
    assert m["PID-7"] == "1980-01-01"


def test_format_date_with_input_format() -> None:
    m = _msg()
    set_field(m, "PID-6", "01/15/2026")
    format_date(m, "PID-6", "%Y%m%d", in_fmt="%m/%d/%Y")
    assert m["PID-6"] == "20260115"


def test_format_date_absent_is_noop() -> None:
    m = _msg()
    format_date(m, "NK1-4", "%Y")
    assert m["NK1-4"] is None


def test_format_date_malformed_raises() -> None:
    m = _msg()
    set_field(m, "PID-6", "not-a-date")
    with pytest.raises(ValueError):
        format_date(m, "PID-6", "%Y")


def test_split_field() -> None:
    m = _msg()
    set_field(m, "PID-2", "AAA_BBB")
    split_field(m, "PID-2", "_", ["PID-2", "PID-4"])
    assert m["PID-2"] == "AAA"
    assert m["PID-4"] == "BBB"


def test_split_field_fewer_parts_clears_trailing() -> None:
    m = _msg()
    set_field(m, "PID-2", "ONLYONE")
    split_field(m, "PID-2", "_", ["PID-2", "PID-4"])
    assert m["PID-2"] == "ONLYONE"
    assert m["PID-4"] is None  # trailing dest cleared


def test_code_lookup_hit_with_dict() -> None:
    m = _msg()
    code_lookup(m, "PID-8", {"F": "Female", "M": "Male"})
    assert m["PID-8"] == "Female"


def test_code_lookup_hit_with_codeset() -> None:
    m = _msg()
    table = CodeSet("gender", {"F": "Female", "M": "Male"})  # a CodeSet is a Mapping — stays pure
    code_lookup(m, "PID-8", table)
    assert m["PID-8"] == "Female"


def test_code_lookup_miss_with_default() -> None:
    m = _msg()
    code_lookup(m, "PID-8", {"M": "Male"}, default="Unknown")
    assert m["PID-8"] == "Unknown"


def test_code_lookup_miss_no_default_leaves_unchanged() -> None:
    m = _msg()
    code_lookup(m, "PID-8", {"M": "Male"})
    assert m["PID-8"] == "F"  # untouched


def test_copy_segment_appends_duplicate() -> None:
    m = _msg()
    assert m.count_segments("NK1") == 1
    copy_segment(m, "NK1")
    assert m.count_segments("NK1") == 2
    assert m.field("NK1-2.1", occurrence=2) == "SMITH"  # the copy carries the same content


def test_copy_segment_at_index() -> None:
    m = _msg()
    copy_segment(m, "NK1", index=1)  # insert just after MSH
    assert m.segments() == ["MSH", "NK1", "EVN", "PID", "NK1"]


def test_copy_segment_absent_raises() -> None:
    m = _msg()
    with pytest.raises(KeyError, match="ZZZ"):
        copy_segment(m, "ZZZ")


def test_delete_segment_returns_count() -> None:
    m = _msg()
    copy_segment(m, "NK1")  # now two
    removed = delete_segment(m, "NK1")
    assert removed == 2
    assert m.count_segments("NK1") == 0


def test_vocabulary_mutates_in_place_and_reencodes() -> None:
    m = _msg()
    set_field(m, "PID-3.1", "555")
    again = Message.parse(m.encode())
    assert again["PID-3.1"] == "555"  # the edit survives a round-trip


# --- ADR 0106 palette additions --------------------------------------------


def test_trim_field() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "  X42  ")
    trim_field(m, "PID-4.1")
    assert m["PID-4.1"] == "X42"


MSH_ONLY = "MSH|^~\\&|SENDAPP|SENDFAC|RECVAPP|RECVFAC|20260101120000||ADT^A01|MSG1|P|2.5.1\r"


def test_copy_field_decodes_a_whole_field_into_a_component() -> None:
    # BACKLOG #5821. A whole field's read is raw text; a component write escapes it again, so the
    # destination read back the escape sequence. NEGATIVE CONTROL: on the unfixed code NK1-2.1 read
    # back "O\S\Brien".
    m = Message.parse(MSH_ONLY + "PID|1||1||O\\S\\Brien\rNK1|1|X^Y\r")
    copy_field(m, "PID-5", "NK1-2.1")
    assert m["NK1-2.1"] == "O^Brien"
    assert m["NK1-2"] == "O\\S\\Brien^Y"
    copy_field(m, "PID-5", "NK1-2.2.1")
    assert m["NK1-2.2"] == "O^Brien"
    # A whole-field destination still takes the raw text as it is.
    copy_field(m, "PID-5", "NK1-3")
    assert m["NK1-3"] == "O\\S\\Brien"


def test_copy_field_keeps_a_whole_fields_escapes_in_a_component() -> None:
    # BACKLOG #5821. The whole field's escapes are kept as sent rather than decoded and written
    # back, so a line break is carried rather than refused and a highlight is not lost.
    m = Message.parse(MSH_ONLY + "PID|1||1||a\\.br\\b\\H\\c\\N\\^d\\\rNK1|1|X^Y\r")
    copy_field(m, "PID-5", "NK1-2.1")
    assert m["NK1-2"] == "a\\.br\\b\\H\\c\\N\\\\S\\d\\E\\^Y"
    assert m["NK1-2.1"] == "a\rb_c_^d\\"


def test_copy_field_refuses_a_component_of_a_delimiter_field() -> None:
    m = Message.parse(MSH_ONLY + "PID|1||1||doe\r")
    with pytest.raises(ValueError, match="delimiters"):
        copy_field(m, "PID-5", "MSH-2.1")
    with pytest.raises(ValueError, match="delimiters"):
        copy_field(m, "PID-5.1", "MSH-2.1")
    with pytest.raises(ValueError, match="delimiters"):
        split_field(m, "PID-5.1", "-", ["MSH-1.1"])
    with pytest.raises(ValueError, match="delimiters"):
        append_to_field(m, "MSH-2.1", "X")
    assert m.encode().startswith("MSH|^~\\&|")


def test_copy_field_into_a_component_of_an_absent_segment_raises_key_error() -> None:
    m = Message.parse(MSH_ONLY + "PID|1||1||doe\r")
    with pytest.raises(KeyError):
        copy_field(m, "PID-5", "NK1-2.1")


@pytest.mark.parametrize("path", ["PID-5", "PID-5.1"])
def test_trim_field_strips_whitespace_an_escape_decodes_to_at_an_end(path: str) -> None:
    # Round-6f70971d finding 5: the whitespace an escape decodes to at an edge is trimmed, as
    # origin/main's component trim did. NEGATIVE CONTROL: on d97051786 the leading space was kept.
    m = Message.parse(MSH_ONLY + "PID|1||1||\\X2041\\x  \r")
    trim_field(m, path)
    assert m["PID-5"] == "Ax"
    m = Message.parse(MSH_ONLY + "PID|1||1||y\\X4120\\\r")
    trim_field(m, path)
    assert m["PID-5"] == "yA"


def test_trim_field_keeps_an_escape_whose_kept_part_holds_a_cr() -> None:
    m = Message.parse(MSH_ONLY + "PID|1||1||\\X0D410D42\\x|F\r")
    trim_field(m, "PID-5")  # the escape's CR is not cut out, so nothing raises
    assert m["PID-5"] == "\\X0D410D42\\x"


def test_split_field_decodes_each_whole_field_piece_into_a_component() -> None:
    # BACKLOG #5821. NEGATIVE CONTROL: on the unfixed code NK1-2.1 read back "O\S\Brien".
    m = Message.parse(MSH_ONLY + "PID|1||1||O\\S\\Brien^John\rNK1|1|X^Y\r")
    split_field(m, "PID-5", "^", ["NK1-2.1", "NK1-2.2", "NK1-3"])
    assert m["NK1-2.1"] == "O^Brien"
    assert m["NK1-2.2"] == "John"
    assert m["NK1-3"] is None


def test_trim_field_keeps_escapes_on_a_component_path() -> None:
    # BACKLOG #5928 step 3. The component was read decoded and written back, so its \.br\ became a
    # CR that the write refused. NEGATIVE CONTROL: on the unfixed code this raised ValueError.
    m = Message.parse(MSH_ONLY + "PID|1||1||  doe\\.br\\x\\S\\  ^jane\r")
    trim_field(m, "PID-5.1")
    assert m["PID-5"] == "doe\\.br\\x\\S\\^jane"


def test_trim_field_strips_only_the_ends_of_a_structured_value() -> None:
    m = Message.parse(MSH_ONLY + "PID|1||1||  doe & x ^ jane  |F\r")
    trim_field(m, "PID-5.1")
    assert m["PID-5"] == "doe & x^ jane  "
    trim_field(m, "PID-5")
    assert m["PID-5"] == "doe & x^ jane"


def test_trim_field_strips_an_escape_that_decodes_to_whitespace_at_an_end() -> None:
    m = Message.parse(MSH_ONLY + "PID|1||1||\\.fi\\ doe\\.br\\\r")
    trim_field(m, "PID-5")
    assert m["PID-5"] == "\\.fi\\doe"


def test_append_to_field_keeps_escapes_on_a_component_path() -> None:
    # BACKLOG #5928 step 3. NEGATIVE CONTROL: on the unfixed code the decoded \.br\ raised ValueError,
    # and a component holding \S\ came back escaped twice.
    m = Message.parse(MSH_ONLY + "PID|1||1||doe\\.br\\x^jane\r")
    append_to_field(m, "PID-5.1", "^Z")
    assert m["PID-5"] == "doe\\.br\\x\\S\\Z^jane"
    assert m["PID-5.1"] == "doe\rx^Z"
    m = Message.parse(MSH_ONLY + "PID|1||1||O\\S\\B&a\r")
    append_to_field(m, "PID-5.1", "!")
    assert m["PID-5"] == "O\\S\\B&a!"


def test_append_to_field_does_not_let_an_unclosed_escape_pair_with_the_suffix() -> None:
    m = Message.parse(MSH_ONLY + "PID|1||1||doe\\\r")
    append_to_field(m, "PID-5.1", "&x")
    assert m["PID-5.1"] == "doe\\&x"


def test_append_to_field_with_an_empty_suffix_changes_nothing() -> None:
    m = Message.parse(MSH_ONLY + "PID|1||1||doe\\^Y\r")
    before = m.encode()
    append_to_field(m, "PID-5.1", "")
    assert m.encode() == before


def test_append_to_field_whole_field_appends_structure() -> None:
    m = Message.parse(MSH_ONLY + "PID|1||1||doe\r")
    append_to_field(m, "PID-5", "^jane")
    assert m["PID-5.2"] == "jane"


def test_transforms_decode_with_the_separators_a_read_uses() -> None:
    # BACKLOG #5928 step 2. A read decodes with the first header's encoding characters, here BHS-2;
    # the edit used MSH-2's, whose escape character is "#", so it lower-cased the "S" of \S\.
    # NEGATIVE CONTROL: on the unfixed code PID-5 became "doe\s\x".
    batch = "BHS|^~\\&\r" + MSH_ONLY.replace("^~\\&", "^~#&", 1)
    m = Message.parse(batch + "PID|1||1||DOE\\S\\X\r")
    assert m["PID-5.1"] == "DOE^X"
    convert_case(m, "PID-5.1", "lower")
    assert m["PID-5"] == "doe\\S\\x"
    assert m["PID-5.1"] == "doe^x"


def test_trim_field_absent_is_noop() -> None:
    m = _msg()
    trim_field(m, "PID-99.1")  # absent
    assert m["PID-99.1"] is None


@pytest.mark.parametrize("path", ["BHS-1", "BHS-2", "FHS-1", "FHS-2.1"])
def test_trim_field_on_a_delimiter_field_of_an_absent_header_is_a_noop(path: str) -> None:
    # Round-6f70971d finding 9. NEGATIVE CONTROL: on d97051786 this raised ValueError.
    m = Message.parse(MSH_ONLY + "PID|1||1||doe\r")
    before = m.encode()
    trim_field(m, path)
    assert m.encode() == before
    with pytest.raises(ValueError, match="delimiters"):
        trim_field(m, "MSH-2")


def test_copy_field_never_writes_a_raw_control_into_a_component() -> None:
    # Round-6f70971d finding 3 (ADR 0205 rule 2). An escape sequence holding a raw control was kept
    # as sent. origin/main hex-escaped such a control rather than refusing the copy, so it is still
    # written, as the data the sequence decodes to, or as its raw text where that decodes to a CR.
    # NEGATIVE CONTROL: on d97051786 NK1-2 held 0x01.
    m = Message.parse(MSH_ONLY + "PID|1||1||x\rNK1|1|X^Y\r")
    m.set("PID-5", "a\\X" + chr(1) + "41\\b")
    copy_field(m, "PID-5", "NK1-2.1")
    nk1 = m.field("NK1-2") or ""
    assert chr(1) not in nk1
    assert nk1 == "ab^Y"
    m.set("PID-5", "a" + chr(1) + "\\Z" + chr(0x7F) + "\\")
    copy_field(m, "PID-5", "NK1-2.2")
    assert m.field("NK1-2") == "ab^a\\X01\\"
    # A sequence decoding to a CR is written as its raw text, so the copy does not raise.
    m.set("PID-5", "a\\X0D" + chr(1) + "\\b")
    copy_field(m, "PID-5", "NK1-2.1")
    assert m.field("NK1-2.1") == "a\\X0D" + chr(1) + "\\b"
    assert chr(1) not in (m.field("NK1-2") or "")


def test_substring_field() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "ABCDEF")
    substring_field(m, "PID-4.1", 0, 3)
    assert m["PID-4.1"] == "ABC"


def test_substring_field_open_end() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "ABCDEF")
    substring_field(m, "PID-4.1", 2)
    assert m["PID-4.1"] == "CDEF"


def test_pad_field_left_default() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "42")
    pad_field(m, "PID-4.1", 5)  # default fill "0", side "left"
    assert m["PID-4.1"] == "00042"


def test_pad_field_right() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "42")
    pad_field(m, "PID-4.1", 5, fill="x", side="right")
    assert m["PID-4.1"] == "42xxx"


def test_pad_field_unknown_side_raises() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "42")
    with pytest.raises(ValueError):
        pad_field(m, "PID-4.1", 5, side="middle")  # type: ignore[arg-type]  # outside the declared set: the refusal is the subject


def test_replace_literal() -> None:
    m = _msg()
    set_field(m, "PID-5.1", "MRS SMITH")
    replace_literal(m, "PID-5.1", "MRS", "MS")
    assert m["PID-5.1"] == "MS SMITH"


# --- decoded values: escapes survive, structure is kept (BACKLOG #5928) -------
#
# Each helper below used to transform the field's raw wire text, so an escape sequence was cased,
# sliced, counted or matched as if it were data. Every case reads the raw text back with a
# whole-field read, which returns the wire form, so the assertion sees the escapes themselves.


_MSH = "MSH|^~\\&|SENDAPP|SENDFAC|RECVAPP|RECVFAC|20260101120000||ADT^A01|MSG1|P|2.5.1\r"


def _with_pid(pid5: str, pid4: str = "", *, msh18: str | None = None) -> Message:
    """A message whose MSH-18 is ``msh18`` as sent, or which ends before MSH-18 where it is None."""
    msh = _MSH if msh18 is None else _MSH.replace("2.5.1\r", f"2.5.1||||||{msh18}\r")
    return Message.parse(f"{msh}PID|1||100^^^HOSP^MR|{pid4}|{pid5}\r")


def test_convert_case_keeps_a_rich_text_escape_on_a_whole_field() -> None:
    m = _with_pid("line\\.br\\two^x")
    convert_case(m, "PID-5", "upper")
    # Upper-casing the raw text made ``\.br\`` into ``\.BR\``, which no decoder maps.
    assert m["PID-5"] == "LINE\\.br\\TWO^X"


def test_convert_case_on_a_leaf_with_a_line_break_escape_does_not_raise() -> None:
    m = _with_pid("line\\.br\\two")
    # The decoded value holds a CR, which a write refuses, so the old helper raised.
    convert_case(m, "PID-5.1", "upper")
    assert m["PID-5"] == "LINE\\.br\\TWO"


def test_convert_case_keeps_a_highlight_escape() -> None:
    m = _with_pid("mc\\H\\donald")
    convert_case(m, "PID-5.1", "upper")
    # ``\H\`` decodes to "_"; writing the decoded value back lost the escape.
    assert m["PID-5"] == "MC\\H\\DONALD"


def test_convert_case_keeps_subcomponents_of_a_component_path() -> None:
    m = _with_pid("doe&van^jane")
    convert_case(m, "PID-5.1", "upper")
    # The decoded component read is "doe&van"; writing it back as data escaped the "&".
    assert m["PID-5"] == "DOE&VAN^jane"
    assert m["PID-5.1.2"] == "VAN"


def test_convert_case_title_reads_case_across_an_escape() -> None:
    m = _with_pid("o\\S\\brien \\X41\\bc")
    convert_case(m, "PID-5.1", "title")
    assert m["PID-5.1"] == "O^Brien Abc"
    assert m["PID-5"] == "O\\S\\Brien \\X41\\bc"


@pytest.mark.parametrize(
    ("sent", "path", "mode", "expected"),
    [
        # BACKLOG #5928 step 1's own case: upper case leaves the hex escape, so the letter it
        # carries keeps the case the sender sent.
        ("jos\\XE9\\", "PID-5.1", "upper", "JOS\\XE9\\"),
        # Lower-case hex digits tell "kept as sent" from upper-casing the wire text, on every path.
        # Literal text after the escape is still cased, and the field keeps its components.
        ("jos\\Xe9\\", "PID-5.1.1", "upper", "JOS\\Xe9\\"),
        ("jos\\Xe9\\", "PID-5", "upper", "JOS\\Xe9\\"),
        ("jos\\Xe9\\ab^x", "PID-5", "upper", "JOS\\Xe9\\AB^X"),
        # e-acute is two bytes in UTF-8 (C3 A9). The decoder reads each byte as its own
        # character, so casing that text byte by byte would write different bytes ("\xc3"
        # lower-cased is "\xe3"). Kept as sent, the bytes stay intact.
        ("ren\\Xc3a9\\", "PID-5.1", "upper", "REN\\Xc3a9\\"),
        ("JOS\\XC389\\", "PID-5", "lower", "jos\\XC389\\"),
        ("JOS\\XC389\\", "PID-5.1", "lower", "jos\\XC389\\"),
        ("JOS\\XC389\\", "PID-5", "title", "Jos\\XC389\\"),
        ("JOS\\XC389\\", "PID-5.1", "title", "Jos\\XC389\\"),
    ],
)
def test_convert_case_keeps_a_hex_escape_as_the_bytes_sent(
    sent: str, path: str, mode: Literal["upper", "lower", "title"], expected: str
) -> None:
    # Pins the "escapes kept as sent" rule (engine PR 2936) that BACKLOG #5928 step 1 questions.
    # What a hex escape's bytes mean is ADR 0205's, *The hex escape's meaning*; the decoder maps
    # each byte to one character and reads no MSH-18, so casing the letter would mean guessing its
    # character set. Keeping the escape as sent writes no byte the sender did not send.
    # NEGATIVE CONTROL: on 17f42069782^, which cased the wire text or wrote a decoded value back,
    # every row here fails.
    m = _with_pid(sent)
    convert_case(m, path, mode)
    assert m["PID-5"] == expected


@pytest.mark.parametrize("path", ["PID-5", "PID-5.1", "PID-5.1.1"])
@pytest.mark.parametrize(
    ("sent", "expected"),
    [
        # The last byte of UTF-8 e-acute, A9, decodes on its own to an uncased character, so a
        # per-byte read capitalized the "e" after it mid-word.
        ("ren\\XC3A9\\e", "Ren\\XC3A9\\e"),
        ("REN\\Xc3a9\\E", "Ren\\Xc3a9\\e"),
        # The mirror: AA, the last byte of the new shekel sign (E2 82 AA), decodes on its own to a
        # cased character, so a per-byte read kept the next word's first letter lower case.
        ("a \\XE282AA\\b", "A \\XE282AA\\B"),
        # The run's bytes are read together, however the sender split them into escapes, and a
        # stray byte before the last character does not hide it.
        ("ren\\XC3\\\\XA9\\e", "Ren\\XC3\\\\XA9\\e"),
        ("ren\\XFFC3A9\\e", "Ren\\XFFC3A9\\e"),
        # Any other unit ends the run, so a byte after it starts afresh: literal text, a
        # charset switch, an escape that decodes to nothing and a malformed hex escape.
        ("a\\XC3\\b\\XA9\\c", "A\\XC3\\b\\XA9\\C"),
        ("ren\\XC3\\\\C2842\\\\XA9\\e", "Ren\\XC3\\\\C2842\\\\XA9\\E"),
        ("ren\\XC3\\\\.fi\\\\XA9\\e", "Ren\\XC3\\\\.fi\\\\XA9\\E"),
        ("ren\\XC3\\\\XZZ\\\\XA9\\e", "Ren\\XC3\\\\XZZ\\\\XA9\\E"),
        # Not valid UTF-8, so each byte is its own character: E9 is a Latin-1 e-acute, cased.
        ("jos\\XE9\\e", "Jos\\XE9\\e"),
        # An ASCII byte reads the same either way.
        ("o\\X41\\b", "O\\X41\\b"),
    ],
)
def test_convert_case_title_reads_a_utf8_hex_escape_as_one_character(
    sent: str, expected: str, path: str
) -> None:
    # BACKLOG #5928: title case decides whether a letter starts a word from the character before
    # it, and under a UTF-8 MSH-18 a run of hex escapes is read as UTF-8 where its bytes end in a
    # UTF-8 character. NEGATIVE CONTROL: on d055c0e8590, which read each byte as its own character,
    # the first five rows fail on every path.
    m = _with_pid(sent, msh18="UNICODE UTF-8")
    convert_case(m, path, "title")
    assert m["PID-5"] == expected


# Read as UTF-8, the run C3 A9 is one character, e-acute, which is cased, so the "e" after it stays
# lower case. Read per byte, its last byte A9 is an uncased character, so the "e" starts a word.
_UTF8_READ = "Ren\\XC3A9\\e"
_PER_BYTE_READ = "Ren\\XC3A9\\E"


@pytest.mark.parametrize(
    ("msh18", "expected"),
    [
        # HL7 table 0211 spells UTF-8 "UNICODE UTF-8". The match ignores case and surrounding
        # spaces, and "UTF-8" alone is taken too, as the owner ruled on 2026-11-27.
        ("UNICODE UTF-8", _UTF8_READ),
        ("unicode utf-8", _UTF8_READ),
        ("  Unicode UTF-8 ", _UTF8_READ),
        ("UTF-8", _UTF8_READ),
        ("utf-8", _UTF8_READ),
        (" Utf-8  ", _UTF8_READ),
        # Only spaces are stripped, so a tab around the name is part of it.
        ("\tUTF-8", _PER_BYTE_READ),
        # The value read is MSH-18.1, the first component, so a later component is not read.
        ("UNICODE UTF-8^", _UTF8_READ),
        ("UTF-8^x", _UTF8_READ),
        # Only the first repetition names the message's own character set; a later one names an
        # alternate set a \C..\ escape may switch to.
        ("UNICODE UTF-8~8859/1", _UTF8_READ),
        ("UTF-8~UNICODE UTF-16", _UTF8_READ),
        ("8859/1~UNICODE UTF-8", _PER_BYTE_READ),
        # An empty MSH-18.1 reads as UTF-8 too (owner ruling 2026-11-27, corrected): an empty
        # first repetition, a blank value, an empty or an absent MSH-18.
        ("~8859/1", _UTF8_READ),
        ("", _UTF8_READ),
        ("   ", _UTF8_READ),
        (None, _UTF8_READ),
        # ISO 8859-1 maps each byte to the character unescape decodes it to, so C3 A9 is two
        # characters. Every other declared set is read per byte too, as unescape reads it.
        ("8859/1", _PER_BYTE_READ),
        ("ASCII", _PER_BYTE_READ),
        ("ISO IR87", _PER_BYTE_READ),
        ("UNICODE UTF-16", _PER_BYTE_READ),
        ("UTF-8X", _PER_BYTE_READ),
        ("UNICODE", _PER_BYTE_READ),
    ],
)
def test_convert_case_title_reads_hex_as_utf8_only_where_msh18_allows(
    msh18: str | None, expected: str
) -> None:
    # BACKLOG #5928, owner ruling 2026-11-27 (corrected): the UTF-8 reading of a hex escape's
    # bytes is taken where MSH-18.1 is empty or names UTF-8; the rule is convert_case's docstring.
    # NEGATIVE CONTROL: on f46051350ea, which read the whole first repetition, stripped any
    # whitespace and read an empty MSH-18 per byte, the rows for a tab, for a later component,
    # and for an empty MSH-18.1 fail.
    m = _with_pid("ren\\XC3A9\\e", msh18=msh18)
    assert m["MSH-18"] == (msh18 or None)
    convert_case(m, "PID-5", "title")
    assert m["PID-5"] == expected


@pytest.mark.parametrize(
    ("sent", "mode", "expected"),
    [
        # Lower-case hex digits: a casing of the escape's wire text would upper-case them.
        ("ren\\Xc3a9\\e", "upper", "REN\\Xc3a9\\E"),
        # UTF-8 E-acute (C3 89): a casing of the letter the escape carries would write C3 A9, and
        # a casing of the wire text would lower-case the X and the digits.
        ("REN\\XC389\\E", "lower", "ren\\XC389\\e"),
    ],
)
@pytest.mark.parametrize("msh18", ["UNICODE UTF-8", "UTF-8", None, "8859/1"])
def test_convert_case_upper_and_lower_keep_hex_as_sent_whatever_msh18(
    sent: str, mode: Literal["upper", "lower"], expected: str, msh18: str | None
) -> None:
    # Owner ruling 2026-11-27: escapes stay as sent for upper and lower case, as PR 2936 ruled, so
    # MSH-18 changes nothing there; only literal text is cased. NEGATIVE CONTROL: a mutation that
    # cases a hex escape's wire text in every mode wherever MSH-18 reads as UTF-8 fails every row
    # but the 8859/1 ones.
    m = _with_pid(sent, msh18=msh18)
    convert_case(m, "PID-5", mode)
    assert m["PID-5"] == expected


def test_substring_field_indexes_the_decoded_whole_field() -> None:
    m = _with_pid("doe", pid4="A\\S\\BC")
    substring_field(m, "PID-4", 2)
    # The raw slice "S\BC" cut the escape in half.
    assert m["PID-4"] == "BC"


def test_substring_field_keeps_an_escape_inside_the_slice() -> None:
    m = _with_pid("AB\\.br\\CD")
    substring_field(m, "PID-5.1", 1)
    assert m["PID-5"] == "B\\.br\\CD"
    substring_field(m, "PID-5.1", 0, 2)
    assert m["PID-5"] == "B\\.br\\"


def test_substring_field_cutting_inside_a_multi_character_escape_keeps_the_data() -> None:
    m = _with_pid("\\X4142\\C")
    substring_field(m, "PID-5.1", 1)
    assert m["PID-5.1"] == "BC"


def test_substring_field_refuses_a_field_with_structure() -> None:
    m = _with_pid("doe^jane")
    with pytest.raises(ValueError, match="separator"):
        substring_field(m, "PID-5", 0, 2)
    assert m["PID-5"] == "doe^jane"


def test_substring_field_refuses_a_component_with_subcomponents() -> None:
    m = _with_pid("doe&van^jane")
    with pytest.raises(ValueError, match="separator"):
        substring_field(m, "PID-5.1", 0, 2)


def test_pad_field_counts_the_decoded_length() -> None:
    m = _with_pid("doe", pid4="4\\S\\2")
    pad_field(m, "PID-4", 5)
    # The raw text is five characters long, so the old helper padded nothing.
    assert m["PID-4"] == "004\\S\\2"


def test_pad_field_writes_a_separator_fill_as_data() -> None:
    m = _with_pid("doe", pid4="4")
    pad_field(m, "PID-4", 3, fill="^")
    assert m["PID-4"] == "\\S\\\\S\\4"
    assert m["PID-4.1"] == "^^4"


def test_pad_field_refuses_a_field_with_structure() -> None:
    m = _with_pid("doe^jane")
    with pytest.raises(ValueError, match="separator"):
        pad_field(m, "PID-5", 12)


def test_replace_literal_does_not_match_inside_an_escape() -> None:
    m = _with_pid("a\\.br\\b")
    replace_literal(m, "PID-5.1", "br", "X")
    # The raw replace turned ``\.br\`` into ``\.X\``.
    assert m["PID-5"] == "a\\.br\\b"


def test_replace_literal_writes_new_as_data() -> None:
    m = _with_pid("doe^jane")
    replace_literal(m, "PID-5", "doe", "o^b")
    assert m["PID-5"] == "o\\S\\b^jane"
    assert m["PID-5.1"] == "o^b"
    assert m["PID-5.2"] == "jane"


def test_replace_literal_old_with_a_separator_does_not_match_across_leaves() -> None:
    m = _with_pid("doe^jane")
    replace_literal(m, "PID-5", "e^j", "X")
    assert m["PID-5"] == "doe^jane"


def test_replace_literal_matches_an_escaped_separator_within_a_leaf() -> None:
    m = _with_pid("A\\S\\B^C")
    replace_literal(m, "PID-5", "^", "-")
    assert m["PID-5"] == "A-B^C"


def test_replace_literal_refuses_a_line_break_in_new() -> None:
    m = _with_pid("doe")
    with pytest.raises(ValueError, match="CR/LF"):
        replace_literal(m, "PID-5.1", "doe", "a\rb")


def test_transforms_refuse_the_delimiter_fields() -> None:
    m = _with_pid("doe")
    with pytest.raises(ValueError, match="MSH-2"):
        replace_literal(m, "MSH-2", "^", "#")
    assert m["MSH-9.1"] == "ADT"


def test_convert_case_keeps_a_hex_escaped_cr_escaped_and_never_raw() -> None:
    m = _with_pid("doe\\X0D\\evn^jane")
    convert_case(m, "PID-5.1", "upper")
    # The escape is kept as sent, so no raw CR reaches the wire and no new segment opens.
    assert m["PID-5"] == "DOE\\X0D\\EVN^jane"
    assert m.encode().count("\r") == 2
    assert m.count_segments("EVN") == 0


def test_replace_literal_keeps_a_zero_width_escape_at_a_match() -> None:
    m = _with_pid("a\\.fi\\bc")
    replace_literal(m, "PID-5.1", "bc", "X")
    assert m["PID-5"] == "a\\.fi\\X"


def test_substring_field_keeps_a_zero_width_escape_outside_the_slice() -> None:
    m = _with_pid("\\C2842\\abc\\.fi\\")
    substring_field(m, "PID-5.1", 1, 2)
    assert m["PID-5"] == "\\C2842\\b\\.fi\\"


def test_an_edit_that_removes_all_text_leaves_the_field_empty() -> None:
    m = _with_pid("doe", pid4="\\.fi\\abc")
    replace_literal(m, "PID-4", "abc", "")
    assert m["PID-4"] is None
    m = _with_pid("doe", pid4="\\.fi\\abc")
    substring_field(m, "PID-4", 0, 0)
    assert m["PID-4"] is None


def test_replace_literal_crlf_in_new_raises_only_on_a_match() -> None:
    m = _with_pid("doe")
    replace_literal(m, "PID-5.1", "zzz", "a\rb")  # nothing matches: a no-op, as before
    replace_literal(m, "ZZZ-1", "x", "a\rb")  # absent segment: a no-op, as before
    assert m["PID-5"] == "doe"


def test_replace_literal_replaces_a_decoded_line_break() -> None:
    m = _with_pid("line one\\.br\\line two")
    replace_literal(m, "PID-5.1", "\r", " ")
    assert m["PID-5"] == "line one line two"


def test_substring_field_refuses_a_cut_that_leaves_a_bare_cr() -> None:
    m = _with_pid("\\.sp2\\z")
    with pytest.raises(ValueError, match="CR/LF"):
        substring_field(m, "PID-5.1", 1)
    assert m["PID-5"] == "\\.sp2\\z"


def test_transforms_refuse_a_batch_header_delimiter_field() -> None:
    m = Message.parse("BHS|^~\\&|SENDAPP\r" + _MSH + "PID|1||X\r")
    with pytest.raises(ValueError, match="delimiters"):
        replace_literal(m, "BHS-2", "", "x")


def test_convert_case_unhashable_mode_raises_value_error() -> None:
    m = _msg()
    with pytest.raises(ValueError, match="convert_case mode"):
        convert_case(m, "PID-5.1", ["upper"])  # type: ignore[arg-type]  # outside the declared set: the refusal is the subject


@pytest.mark.parametrize(
    "raw",
    ["plain", "a\\.br\\b", "\\X4142\\C", "x\\\\y", "SMITH\\", "JO\\E", "\\H\\hi\\N\\", "\\.in3\\z"],
)
def test_leaf_units_decode_exactly_as_unescape(raw: str) -> None:
    # The tokenizer the transforms use must decode a leaf as the read side does, or every length
    # and match they compute drifts from what Message.field returns.
    from messagefoundry.parsing import _builtin_hl7

    seps = ("|", "^", "~", "&", "\\")
    units = actions_mod._leaf_units(raw, seps)
    assert "".join(raw_part for raw_part, _decoded, _kind in units) == raw
    assert actions_mod._decoded(units) == _builtin_hl7.unescape(raw, seps)


def test_copy_segment_skips_a_fieldless_bare_line() -> None:
    m = Message.parse(f"{_MSH}PID\rPID|1||X\r")
    assert m.count_segments("PID") == 1
    copy_segment(m, "PID")
    # The bare line is no occurrence, so occurrence 1 is the populated PID, as Peek and Message agree.
    assert m.count_segments("PID") == 2
    assert m.field("PID-3", occurrence=2) == "X"


def test_arith_field_multiply_rounds() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "70")  # kg
    arith_field(m, "PID-4.1", "*", 2.20462, ndigits=1)  # -> lb
    assert m["PID-4.1"] == "154.3"


def test_arith_field_integer_default() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "70")
    arith_field(m, "PID-4.1", "*", 2)
    assert m["PID-4.1"] == "140"


def test_arith_field_unknown_op_raises() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "70")
    with pytest.raises(ValueError):
        # Not an eval: a closed op set, so "**" is refused.
        arith_field(m, "PID-4.1", "**", 2)  # type: ignore[arg-type]  # outside the declared set: the refusal is the subject


def test_arith_field_divide_by_zero_raises() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "70")
    with pytest.raises(ValueError):
        arith_field(m, "PID-4.1", "/", 0)


def test_arith_field_non_numeric_raises() -> None:
    m = _msg()
    with pytest.raises(ValueError):
        arith_field(m, "PID-5.1", "+", 1)  # PID-5.1 = "doe"


def test_date_diff_field_years() -> None:
    m = _msg()  # PID-7 = 19800101 (DOB), MSH-7 = 20260101120000
    date_diff_field(m, "PID-7", "MSH-7", "PID-4.1", unit="years")
    assert m["PID-4.1"] == "46"


def test_date_diff_field_hours() -> None:
    m = _msg()  # EVN-2 = 20260101 (00:00), MSH-7 = 20260101120000 (12:00)
    date_diff_field(m, "EVN-2", "MSH-7", "PID-4.1", unit="hours")
    assert m["PID-4.1"] == "12"


def test_date_diff_field_absent_is_noop() -> None:
    m = _msg()
    date_diff_field(m, "PID-99", "MSH-7", "PID-4.1", unit="days")
    assert m["PID-4.1"] is None


def test_date_diff_field_unparseable_raises() -> None:
    m = _msg()
    set_field(m, "PID-4.1", "notadate")
    with pytest.raises(ValueError):
        date_diff_field(m, "PID-4.1", "MSH-7", "PID-13.1", unit="days")


def _two_stamps(start: str, end: str) -> Message:
    # Synthetic: the two stamps ride in ZTS-1 and ZTS-2, with ZTS-3 the destination.
    return Message.parse(ADT + f"ZTS|{start}|{end}\r")


def test_date_diff_field_applies_both_offsets() -> None:
    # BACKLOG #5822. 08:00 at -0500 is 13:00Z; 14:00 at +0000 is 14:00Z, one hour later. NEGATIVE
    # CONTROL: the unfixed code discarded both offsets and wrote the wall-clock gap, 6.
    m = _two_stamps("202603010800-0500", "202603011400+0000")
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="hours")
    assert m["ZTS-3"] == "1"


def test_date_diff_field_offsets_move_the_day_count() -> None:
    # 23:00 at -0500 on the 1st is 04:00Z on the 2nd, so 03:00Z on the 3rd is 23 hours on: 0 days.
    # NEGATIVE CONTROL: the wall-clock reading, 1st 23:00 to 3rd 03:00, is 28 hours and wrote 1.
    m = _two_stamps("202603012300-0500", "202603030300+0000")
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] == "0"
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="minutes")
    assert m["ZTS-3"] == str(23 * 60)


def test_date_diff_field_years_counts_each_stamps_own_date() -> None:
    # An age is counted on the local calendar: an evening before the birthday, in the birth zone, is
    # still the year before, even though in UTC it is already the birthday. Either way round.
    m = _two_stamps("198006150800-0500", "202606141930-0500")
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="years")
    assert m["ZTS-3"] == "45"
    date_diff_field(m, "ZTS-2", "ZTS-1", "ZTS-3", unit="years")
    assert m["ZTS-3"] == "-45"


@pytest.mark.parametrize(
    ("start", "end"),
    [
        ("202603010800", "202603011400+0000"),  # a time of day beside an offset
        ("202603010800+0000", "202603011400"),  # the other way round
    ],
)
def test_date_diff_field_one_offset_raises_for_a_clock_unit(start: str, end: str) -> None:
    # Only one stamp has an offset: there is no instant to compare the other with, so a wall-clock
    # gap would be a guess. Either way round.
    m = _two_stamps(start, end)
    units: tuple[Literal["hours", "minutes", "days"], ...] = ("hours", "minutes", "days")
    for unit in units:
        with pytest.raises(ValueError, match="cannot be compared as instants"):
            date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit=unit)
        with pytest.raises(ValueError, match="cannot be compared as instants"):
            date_diff_field(m, "ZTS-2", "ZTS-1", "ZTS-3", unit=unit)
    assert m["ZTS-3"] is None


def test_date_diff_field_a_date_only_stamp_beside_an_offset_is_an_age() -> None:
    # Age at an event: a date-only date of birth beside an event time that carries an offset.
    m = _two_stamps("19800615", "202606150200-0500")
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="years")
    assert m["ZTS-3"] == "46"


@pytest.mark.parametrize(("unit", "expected"), [("days", "4"), ("hours", "108")])
def test_date_diff_field_a_date_only_stamp_beside_an_offset_keeps_mains_count(
    unit: Literal["days", "hours"], expected: str
) -> None:
    # BACKLOG #5822, review finding 3. Age in days or hours from a date-only date of birth to an
    # event time with an offset is the calendar count main wrote, exempted the way "years" is.
    # NEGATIVE CONTROL: at 8de4d951d this raised "only one ... carries an offset".
    m = _two_stamps("20260101", "202601051200-0500")
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit=unit)
    assert m["ZTS-3"] == expected


def test_date_diff_field_two_dates_are_a_calendar_difference_whatever_their_offsets() -> None:
    # Midnight at +1200 and midnight at -1200 are 48 hours apart in UTC, but the dates the sender
    # wrote are one day apart.
    m = _two_stamps("20260301+1200", "20260302-1200")
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] == "1"


@pytest.mark.parametrize(
    ("start", "end"),
    [
        ("202603010800-0500", "202603011400+0060"),  # minutes of 60
        ("202603010800-0500", "202603011400+2500"),  # a day or more
        ("202603010800", "20260302+0060"),  # beside a stamp with no offset
    ],
)
def test_date_diff_field_out_of_range_offset_raises(start: str, end: str) -> None:
    m = _two_stamps(start, end)
    with pytest.raises(ValueError, match="offset"):
        date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="hours")


def test_date_diff_field_reads_a_composite_ts_by_its_first_component() -> None:
    # BACKLOG #5822. A v2.3 TS carries its degree of precision as component 2. NEGATIVE CONTROL: the
    # unfixed code parsed the whole field, "20260101^D", and raised ValueError.
    m = _two_stamps("20260101^D", "20260104120000^S")
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] == "3"
    # A component path is read as addressed.
    date_diff_field(m, "ZTS-1.1", "ZTS-2.1", "ZTS-3", unit="hours")
    assert m["ZTS-3"] == "84"


@pytest.mark.parametrize("start", ["^D", "^20260101", "~20270101"])
def test_date_diff_field_a_ts_field_with_an_empty_first_value_raises(start: str) -> None:
    # BACKLOG #5822, review finding 4. A field whose first component or repetition is empty but which
    # holds something else is unparseable, as on main, rather than a silent no-op. NEGATIVE CONTROL:
    # at 8de4d951d each of these wrote nothing and raised nothing.
    m = _two_stamps(start, "20260104")
    with pytest.raises(ValueError):
        date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] is None


@pytest.mark.parametrize(
    ("start", "end", "unit"),
    [
        ("20260101^20260201", "20260104", "days"),  # a range, not a timestamp
        ("20260101^S", "20260104", "days"),  # second precision on a date
        ("20260101^Q", "20260104", "days"),  # not a degree-of-precision code
        ("20260101^D^X", "20260104", "days"),  # a third component
        ("20260101^^^X", "20260104", "days"),  # a fourth component, review round e99482de
        ("20260101^D^^X", "20260104", "days"),  # a fourth component after a code
        ("2026\\X3031\\01", "20260104", "days"),  # an escape that decodes to a valid stamp
        ("20260101~~20270101", "20260104", "days"),  # a later repetition after an empty one
    ],
)
def test_date_diff_field_a_whole_field_holding_more_than_one_timestamp_raises(
    start: str, end: str, unit: Literal["days", "hours"]
) -> None:
    # BACKLOG #5822, review round 4. Main refused each of these whole fields as unparseable; reading
    # component 1 must not turn them into a silent number. NEGATIVE CONTROL: at 375a4aa8e the first
    # and last wrote 3 and 3. A code coarser than its time is no longer here: it reads at that
    # precision (test_date_diff_field_a_coarser_precision_code_reads_at_its_precision).
    m = _two_stamps(start, end)
    with pytest.raises(ValueError):
        date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit=unit)
    assert m["ZTS-3"] is None


@pytest.mark.parametrize("start", ["20260101~~20270101", "~20270101"])
@pytest.mark.parametrize("path", ["ZTS-1", "ZTS-1.1"])
def test_date_diff_field_any_second_repetition_raises_on_either_path(start: str, path: str) -> None:
    # BACKLOG #5822 added item 2. A component path refused "a~b" but read "a~~b" as "a", since its
    # second repetition is empty, and "~b" as nothing. NEGATIVE CONTROL: on the unfixed code the
    # component path wrote 3 for the first value and nothing for the second, raising neither time.
    m = _two_stamps(start, "20260104")
    with pytest.raises(ValueError, match="repeats"):
        date_diff_field(m, path, "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] is None


@pytest.mark.parametrize("start", ["20260101~", "20260101~^", "20260101~~^&"])
@pytest.mark.parametrize("path", ["ZTS-1", "ZTS-1.1"])
def test_date_diff_field_ignores_a_trailing_empty_repetition(start: str, path: str) -> None:
    # A trailing empty repetition holds nothing, as a trailing empty component does. NEGATIVE
    # CONTROL: on the unfixed code the whole-field path raised ValueError.
    m = _two_stamps(start, "20260104")
    date_diff_field(m, path, "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] == "3"


@pytest.mark.parametrize(
    ("start", "end", "unit", "expected"),
    [
        ("198807051200^D", "19890705", "days", "365"),  # the noon is dropped, not counted
        ("198807052359^D", "198807060001", "hours", "24"),  # read as midnight on its date
        ("198807052359^H", "198807060001", "minutes", "61"),  # read as 23:00
        ("19880705^L", "19880801", "days", "31"),  # read as 1 July
        ("19880705^Y", "19890101", "years", "1"),  # read as 1 January
    ],
)
def test_date_diff_field_a_coarser_precision_code_reads_at_its_precision(
    start: str, end: str, unit: Literal["days", "years", "hours", "minutes"], expected: str
) -> None:
    # BACKLOG #5822 added item 1. HL7 v2.3's TS gives the time's degree of precision in component
    # 2, and a code coarser than the digits sent says which digits hold. NEGATIVE CONTROL: on the
    # unfixed code each of these raised ValueError.
    m = _two_stamps(start, end)
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit=unit)
    assert m["ZTS-3"] == expected


@pytest.mark.parametrize("start", ["20260101^", "20260101^D^", "20260101^D^^"])
def test_date_diff_field_ignores_trailing_empty_components(start: str) -> None:
    # BACKLOG #5822 added item 3. A trailing empty component holds nothing. NEGATIVE CONTROL: on the
    # unfixed code each of these raised ValueError.
    m = _two_stamps(start, "20260104")
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] == "3"


@pytest.mark.parametrize(
    "start",
    ["20260101^&", "20260101^&&", "20260101^^&", "20260101^&^", "20260101^D&", "20260101^D^&"],
)
def test_date_diff_field_ignores_a_trailing_subcomponent_separator(start: str) -> None:
    # BACKLOG #5822 added item 3, PR 2975 open finding 6: "20260101^&" raised. A trailing empty
    # subcomponent holds nothing, as a trailing empty component does. NEGATIVE CONTROL: on the
    # unfixed code each of these raised ValueError.
    m = _two_stamps(start, "20260104")
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] == "3"


@pytest.mark.parametrize("start", ["20260101^&D", "20260101^D&S", "20260101^S&"])
def test_date_diff_field_still_refuses_a_code_beside_a_subcomponent(start: str) -> None:
    # Only trailing EMPTY subcomponents are dropped: a code after one, a second code, or a finer
    # code still raises.
    m = _two_stamps(start, "20260104")
    with pytest.raises(ValueError, match="degree of precision"):
        date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] is None


def test_date_diff_field_shares_timezones_time_precisions() -> None:
    # BACKLOG #5822 added item 4 ("`_TIME_PRECISIONS` repeats a tuple from timezone.py"): the
    # helper reads the one tuple timezone.py defines rather than keeping its own copy. NEGATIVE
    # CONTROL: this fails on 3681393c4ac^, where actions.py defined its own copy.
    import messagefoundry.timezone as timezone_mod

    assert vars(actions_mod)["_TIME_PRECISIONS"] is timezone_mod._TIME_PRECISIONS


@pytest.mark.parametrize("path", ["ZTS-1", "ZTS-1.1"])
def test_date_diff_field_refuses_a_repeating_ts_field(path: str) -> None:
    # A timestamp field holds one value, so a second repetition raises however it is addressed.
    m = _two_stamps("20260101~20270101", "20260104")
    with pytest.raises(ValueError, match="repeats"):
        date_diff_field(m, path, "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] is None


def test_date_diff_field_a_repeating_field_beside_an_empty_one_is_a_no_op() -> None:
    # An open encounter (no end yet) stays the no-op the docstring promises, even beside a bad start.
    m = _two_stamps("20260101~20270101", "")
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit="days")
    assert m["ZTS-3"] is None


@pytest.mark.parametrize(
    ("start", "end", "unit", "forward"),
    [
        ("20250616", "20260615", "years", "0"),  # a day short of a year
        ("20250614", "20260615", "years", "1"),
        ("19800101", "20260101", "years", "46"),
        ("202603010000", "202603011200", "days", "0"),
        ("202603010000", "202603031200", "days", "2"),
        ("202603010000", "202603010030", "hours", "0"),
        ("20260301000000", "20260301000030", "minutes", "0"),
    ],
)
def test_date_diff_field_is_symmetric(
    start: str, end: str, unit: Literal["days", "years", "hours", "minutes"], forward: str
) -> None:
    # BACKLOG #5822. Swapping the fields negates the interval exactly, in every unit. NEGATIVE
    # CONTROL: the unfixed code floored, so the reversed "a day short of a year" was -1 years and
    # the reversed 12 hours was -1 days.
    m = _two_stamps(start, end)
    date_diff_field(m, "ZTS-1", "ZTS-2", "ZTS-3", unit=unit)
    assert m["ZTS-3"] == forward
    date_diff_field(m, "ZTS-2", "ZTS-1", "ZTS-3", unit=unit)
    assert m["ZTS-3"] == ("0" if forward == "0" else f"-{forward}")


def test_date_diff_field_unknown_unit_raises() -> None:
    m = _msg()
    with pytest.raises(ValueError):
        date_diff_field(m, "PID-7", "MSH-7", "PID-4.1", unit="fortnights")  # type: ignore[arg-type]  # outside the declared set: the refusal is the subject


# --- purity + no-new-dependency (ADR 0076 §6 gate 5) -------------------------


def _top_level_imports(path: str) -> set[str]:
    """The top-level package name of every import in a module's source (AST — no execution)."""
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.add(node.module.split(".")[0])
    return mods


# I/O-capable modules the pure vocabulary must never import (proves helpers do no I/O).
_IO_MODULES = frozenset(
    {
        "os",
        "io",
        "socket",
        "subprocess",
        "http",
        "urllib",
        "sqlite3",
        "asyncio",
        "selectors",
        "shutil",
        "tempfile",
        "requests",
        "aiohttp",
        "aiosqlite",
        "pyodbc",
        "aioodbc",
        "ssl",
        "smtplib",
        "ftplib",
    }
)


def test_actions_imports_nothing_doing_io() -> None:
    imports = _top_level_imports(actions_mod.__file__)
    offenders = imports & _IO_MODULES
    assert not offenders, f"actions.py must do no I/O; forbidden imports: {sorted(offenders)}"


def test_actions_and_lens_add_no_runtime_dependency() -> None:
    # Every import must be stdlib or first-party — no new third-party dependency (stdlib `ast` only).
    for mod in (actions_mod, lens_mod):
        assert mod.__file__ is not None
        for top in _top_level_imports(mod.__file__):
            assert top in sys.stdlib_module_names or top == "messagefoundry", (
                f"{Path(mod.__file__).name} imports non-stdlib, non-first-party {top!r} "
                "(would add a runtime dependency)"
            )
