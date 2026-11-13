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


def test_trim_field_absent_is_noop() -> None:
    m = _msg()
    trim_field(m, "PID-99.1")  # absent
    assert m["PID-99.1"] is None


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


def _with_pid(pid5: str, pid4: str = "") -> Message:
    return Message.parse(f"{_MSH}PID|1||100^^^HOSP^MR|{pid4}|{pid5}\r")


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
