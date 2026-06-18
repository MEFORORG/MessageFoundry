# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the vendored HL7 field reader (tee/hl7_fields.py)."""

from __future__ import annotations

from tee.hl7_fields import Separators, parse, split_segments

A = (
    "MSH|^~\\&|MEFOR|RFAC|RECV|RFAC|20260604120000||ADT^A01|MSG1|P|2.5.1\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def test_separators_default() -> None:
    seps = Separators.from_message(A)
    assert (seps.field, seps.component, seps.repetition, seps.escape, seps.subcomponent) == (
        "|",
        "^",
        "~",
        "\\",
        "&",
    )


def test_separators_custom() -> None:
    seps = Separators.from_message("MSH!*~\\&!APP!FAC\r")
    assert seps.field == "!"
    assert seps.component == "*"


def test_separators_fallback_for_non_msh() -> None:
    # A body that doesn't start with MSH falls back to the HL7 defaults rather than misreading.
    assert Separators.from_message("PID|1||X") == Separators()


def test_parse_msh_field_numbering() -> None:
    msh = parse(A)[0]
    assert msh.id == "MSH"
    assert msh.field(1) == "|"  # MSH-1 is the field separator (normalized back in)
    assert msh.field(2) == "^~\\&"  # MSH-2 encoding characters
    assert msh.field(3) == "MEFOR"  # MSH-3 sending application
    assert msh.field(7) == "20260604120000"  # MSH-7 datetime
    assert msh.field(9) == "ADT^A01"  # MSH-9 message type
    assert msh.field(10) == "MSG1"  # MSH-10 control id


def test_parse_non_msh_field_numbering() -> None:
    pid = parse(A)[1]
    assert pid.id == "PID"
    assert pid.field(1) == "1"
    assert pid.field(5) == "DOE^JANE"


def test_field_out_of_range_is_empty() -> None:
    assert parse(A)[1].field(99) == ""


def test_split_segments_tolerates_line_endings() -> None:
    assert split_segments("A\rB\nC\r\nD\r") == ["A", "B", "C", "D"]


def test_parse_uses_custom_separators() -> None:
    msg = "MSH!*~\\&!MEFOR!RFAC!RECV!RFAC!20260604!!ADT*A01!MSG1!P!2.5.1\rPID!1!!100!!DOE*JANE\r"
    segs = parse(msg)
    assert segs[0].field(3) == "MEFOR"
    assert segs[0].field(10) == "MSG1"
    assert segs[1].field(5) == "DOE*JANE"


def test_separators_found_behind_leading_blank_segment() -> None:
    # A leading CR/blank segment must not hide the MSH separators (would otherwise mis-read a custom
    # encoding as the defaults and garble every field).
    seps = Separators.from_message("\rMSH!*~\\&!APP!FAC\r")
    assert seps.field == "!"
    assert seps.component == "*"


def test_parse_custom_separators_behind_leading_cr() -> None:
    msg = "\rMSH!*~\\&!MEFOR!SFAC!DOWN!DFAC!20260604!!ADT*A01!MSG1!P!2.5.1\rPID!1!!100!!DOE*JANE\r"
    segs = parse(msg)
    assert segs[0].id == "MSH"
    assert segs[0].field(10) == "MSG1"
    assert segs[1].field(5) == "DOE*JANE"
