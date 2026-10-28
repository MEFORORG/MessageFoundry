# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A dashed SSN or punctuated phone cut across fields by the message's own field separator is
refused (vault BACKLOG #3465).

The leak-check's shape detectors read one field at a time, after the message is split on the
separator its header declares. Under a field separator of ``-``, ``ZZZ-1-123-45-6789`` holds the
dashed number as three fields, none of which holds the shape, so ``anonymize_checked`` emitted it
on both anonymizers. Under ``|`` the same value is refused. The walk now also reads each line as
written, and refuses a shape that holds the separator when it reaches a field no rule rewrites.

Every value here is synthetic: made-up numbers in the shapes the detectors match.
"""

from __future__ import annotations

from types import ModuleType

import pytest

import messagefoundry.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry.anon import leak as engine_leak
from tee.anon import leak as tee_leak
from tests.test_anon_core import _NO_SCANNER

_SALT = "b455-3465-salt-0123456789abcdef"
_SSN = "123-45-6789"
#: The header and a PID under a field separator of ``-``. MSH-7 is a date, MSH-12 the version.
_DASH_HEAD = "MSH-^~\\&-A-B-C-D-20260101--ORU^R01-M1-P-2.5.1\rPID-1--1^^^H^MR--X^Y"
#: The same number with its two dashes escaped as ``\F\``, as HL7 writes a field separator in a value.
_ESCAPED = r"123\F\45\F\6789"
_PIPE_HEAD = "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"

_SIDES = pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])
_LEAKS = pytest.mark.parametrize("leak", [engine_leak, tee_leak], ids=["engine", "tee"])


def _checked(anon: ModuleType, message: str) -> str:
    result: str = anon.anonymize_checked(message, salt=_SALT)
    return result


@_NO_SCANNER
@_SIDES
def test_a_parenthesised_phone_cut_by_a_space_separator_is_refused(anon: ModuleType) -> None:
    """The separator need not be a dash: a space cuts a parenthesised phone the same way."""
    message = (
        "MSH ^~\\& A B C D 20260101  ORU^R01 M1 P 2.5.1\rPID 1  1^^^H^MR  X^Y\rZZZ 1 (555) 555-0100"
    )
    with pytest.raises(anon.LeakError, match="phone-shaped value across ZZZ-2 to ZZZ-3"):
        _checked(anon, message)


@_NO_SCANNER
@_SIDES
def test_a_numeric_obx5_cut_into_unmapped_obx6_and_obx7_is_refused(anon: ModuleType) -> None:
    """``000`` is a valid number, so the numeric OBX-5 guard keeps it, and OBX-6 and OBX-7 carry
    the rest of the shape. The output holds it whole, so the check refuses, naming the two
    fields no rule rewrites."""
    message = f"{_DASH_HEAD}\rOBX-1-NM-8480^S^LN--000-12-3456"
    with pytest.raises(anon.LeakError, match="SSN-shaped value across OBX-6 to OBX-7"):
        _checked(anon, message)


@_NO_SCANNER
@_SIDES
def test_the_same_value_under_a_pipe_is_refused_as_before(anon: ModuleType) -> None:
    """The per-field read is unchanged: under ``|`` the hit names one field, as it always did."""
    with pytest.raises(anon.LeakError, match="unmapped SSN-shaped value in ZZZ-2") as exc:
        _checked(anon, f"{_PIPE_HEAD}\rZZZ|1|{_SSN}")
    assert "cut by the field separator" not in str(exc.value)


@_NO_SCANNER
@_SIDES
def test_a_dash_separated_message_with_no_shape_passes(anon: ModuleType) -> None:
    """The negative control: a dash separator alone refuses nothing. Numbers in adjacent fields
    that do not make up a shape pass."""
    message = f"{_DASH_HEAD}\rOBX-1-NM-8480^S^LN--128-mm[Hg]-60-200\rZZZ-1-12-345-67"
    out = _checked(anon, message)
    assert out.split("\r")[-1] == "ZZZ-1-12-345-67"


@_NO_SCANNER
@_SIDES
def test_a_header_type_line_names_its_fields_the_header_way(anon: ModuleType) -> None:
    """On a ``BHS`` line field N sits at split index N-1, and the hit counts the same way."""
    with pytest.raises(anon.LeakError, match="SSN-shaped value across BHS-3 to BHS-5"):
        _checked(anon, f"{_DASH_HEAD}\rBHS-^~\\&-{_SSN}")


@_NO_SCANNER
@_SIDES
def test_adjacent_numeric_fields_that_read_as_a_shape_are_refused(anon: ModuleType) -> None:
    """The cost docs/PHI.md states: under ``-``, three numeric fields of the right widths read as a
    dashed SSN whatever they hold, so an order line like this one is refused."""
    with pytest.raises(anon.LeakError, match="SSN-shaped value across OBR-2 to OBR-4"):
        _checked(anon, f"{_DASH_HEAD}\rOBR-1-{_SSN}")


#: The dash header with a field separator of ``4`` (the version holds no ``4``).
_DIGIT_HEAD = "MSH4^~\\&4A4B4C4D42026010144ORU^R014M14P42.5.1\rPID414411^^^H^MR44X^Y"


@_NO_SCANNER
@_SIDES
@pytest.mark.parametrize(
    ("message", "line"),
    [
        # A rule scrubbed the first part: the OBX-5 free-text rule redacts 123.
        (f"{_DASH_HEAD}\rOBX-1-ST-8480^S^LN--{_SSN}", "OBX-1-ST-8480^S^LN--[REDACTED]-45-6789"),
        # A rule scrubbed the last part: 6789 lands in OBX-5.
        (f"{_DASH_HEAD}\rOBX-1-ST-{_SSN}", "OBX-1-ST-123-45-[REDACTED]"),
        # The sender escaped the separator, as HL7 asks: no detector decodes an escape.
        (f"{_DASH_HEAD}\rZZZ-1-{_ESCAPED}", f"ZZZ-1-{_ESCAPED}"),
        # A digit separator: the shapes' digit boundaries read it as part of the number.
        (f"{_DIGIT_HEAD}\rZZZ414{_SSN}", f"ZZZ414{_SSN}"),
    ],
    ids=["first-part-scrubbed", "last-part-scrubbed", "escaped", "digit-separator"],
)
def test_what_still_passes(anon: ModuleType, message: str, line: str) -> None:
    """The limits docs/PHI.md section 9 states, pinned so that a change here moves the docs with
    it. Every one of these lines leaves the anonymizer as shown, and nothing refuses it."""
    assert _checked(anon, message).split("\r")[-1] == line


@_NO_SCANNER
@_SIDES
def test_a_shape_in_the_header_line_passes_even_under_full_coverage(anon: ModuleType) -> None:
    """The header limit docs/PHI.md section 9 states: the check and ``require_full_coverage``
    both skip the header line whole, so a shape cut across MSH-4 to MSH-6 leaves as it came."""
    header = "MSH-^~\\&-A-123-45-6789-20260101--ORU^R01-M1-P-2.5.1"
    message = f"{header}\rPID-1--1^^^H^MR--X^Y"
    out = anon.anonymize_checked(message, salt=_SALT, require_full_coverage=True)
    assert _SSN in out.split("\r")[0]


@_LEAKS
def test_a_shape_wholly_in_rewritten_fields_is_not_a_hit(leak: ModuleType) -> None:
    """A rewritten field is never re-flagged, so a match whose every field a rule rewrote is no
    hit. The same match is one with a field left unmapped."""
    message = f"{_DASH_HEAD}\rZZZ-1-{_SSN}"
    assert leak.structural_phi_hits(message, {"PID-3", "ZZZ-2", "ZZZ-3", "ZZZ-4"}) == []
    assert leak.structural_phi_hits(message, {"PID-3", "ZZZ-2", "ZZZ-3"}) == [
        "unmapped SSN-shaped value across ZZZ-4, cut by the field separator"
    ]


@_LEAKS
def test_a_malformed_line_names_its_fields_without_its_id(leak: ModuleType) -> None:
    """A line no rule can reach is refused by itself. A shape cut across it is named by the
    stand-in address, never by the line's text."""
    hits = leak.structural_phi_hits(f"{_DASH_HEAD}\rzz-{_SSN}", set())
    assert leak.MALFORMED_LINE_HIT in hits
    assert (
        "unmapped SSN-shaped value across (malformed segment)-1 to (malformed segment)-3, "
        "cut by the field separator"
    ) in hits
