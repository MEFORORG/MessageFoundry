# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Strict validation refuses a line hl7apy drops while grouping (BACKLOG #5920).

hl7apy's grouping parse silently skips a line it cannot place in the message structure, and
validates only the tree it built, so ``validate()`` once returned ``ok`` for a message carrying an
unknown segment, a known segment with no place in the structure, or a line that is not a segment
at all. The tolerant parser keeps and forwards every such line. The ruling: any dropped line is a
refusal, except a Z-segment, which is tolerated as a site extension and listed in
``ValidationResult.unvalidated_segments``. Every message names at most a three-character segment
ID and a 1-based line number, never the line's text.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from messagefoundry.parsing import validate
from messagefoundry.parsing.peek import normalize
from messagefoundry.parsing.validate import _dropped_lines, _split_lines, _tolerant_parse
from messagefoundry_toolkit.generators import (
    _core,
    all_types,  # noqa: F401  (registers every built-in type)
)

# By module path: the package re-exports the function under the module's own name.
validate_module = importlib.import_module("messagefoundry.parsing.validate")

_MSH = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|N1|P|2.5.1"
_EVN = "EVN|A01|20260101"
_PID = "PID|1||100001^^^HOSP^MR||DOE^JANE||19700101|F"
_PV1 = "PV1|1|I"


def _adt(*segments: str) -> str:
    return "\r".join(segments)


def test_the_baseline_message_is_conformant_and_lists_nothing() -> None:
    result = validate(_adt(_MSH, _EVN, _PID, _PV1))
    assert result.ok, result.errors
    assert result.unvalidated_segments == ()


@pytest.mark.parametrize(
    ("extra", "error"),
    [
        pytest.param("FOO|1", "unknown segment at line 3", id="unknown-segment"),
        pytest.param(
            "ORC|NW|ORD1",
            "segment ORC at line 3 has no place in this message's structure",
            id="misplaced-known-segment",
        ),
        pytest.param(
            "PRT|1",
            "unknown segment at line 3",
            id="segment-of-a-later-version-prints-no-id",
        ),
        pytest.param("ZOE", "unknown segment at line 3", id="bare-z-id-without-separator"),
        pytest.param(
            "BHS", "segment BHS at line 3 has no place in this message's structure", id="bare-bhs"
        ),
        pytest.param("hello world", "unrecognised line 3", id="non-hl7-text"),
        pytest.param("zxx|1", "unrecognised line 3", id="lowercase-z-is-not-a-z-segment"),
        pytest.param("ZXXX|1", "unrecognised line 3", id="four-character-id"),
        pytest.param("FO|1", "unrecognised line 3", id="two-character-id"),
        pytest.param("   ", "unrecognised line 3", id="whitespace-only-line"),
    ],
)
def test_a_dropped_line_is_refused(extra: str, error: str) -> None:
    result = validate(_adt(_MSH, _EVN, extra, _PID, _PV1))
    assert not result.ok
    assert result.errors == [error]


@pytest.mark.parametrize("z", ["ZXX|1", "Z01|1|2", "ZPI|"])
def test_a_z_segment_is_tolerated_and_listed(z: str) -> None:
    result = validate(_adt(_MSH, _EVN, z, _PID, _PV1))
    assert result.ok, result.errors
    assert result.unvalidated_segments == ((z[:3], 3),)


_ADT_INSURANCE = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|N1|P|2.5.1\rEVN|A01|20260101\r" + _PID + "\r" + _PV1
)
_ORU = "MSH|^~\\&|A|B|C|D|20260101||ORU^R01^ORU_R01|N1|P|2.5.1\r" + _PID


@pytest.mark.parametrize(
    "message",
    [
        pytest.param(
            _ADT_INSURANCE + "\rIN1|1|PLAN^Plan|INS1\rZIN|1\rIN2|1", id="inside-adt-insurance"
        ),
        pytest.param(
            _ORU + "\rZPI|1\rOBR|1|X||PANEL^Panel\rOBX|1|ST|A||v||||||F", id="after-oru-pid"
        ),
        pytest.param(
            _ORU + "\rOBR|1|X||PANEL^Panel\rOBX|1|ST|A||v||||||F\rZOB|1\rOBX|2|ST|B||v||||||F",
            id="between-obxs",
        ),
    ],
)
def test_a_z_segment_inside_a_group_does_not_break_the_grouping(message: str) -> None:
    result = validate(message)
    assert result.ok, result.errors
    assert len(result.unvalidated_segments) == 1


def test_a_message_type_hl7apy_has_no_structure_for_is_refused() -> None:
    """hl7apy builds an empty tree for ZZZ^Z01 and its validator passes it: nothing was checked."""
    result = validate("MSH|^~\\&|A|B|C|D|20260101||ZZZ^Z01|N1|P|2.5.1\r" + _EVN)
    assert not result.ok
    assert result.errors == [
        "no segment could be validated: hl7apy has no structure for this message type"
    ]


_MFN_M01 = (
    "MSH|^~\\&|A|B|C|D|20260101||MFN^M01^MFN_M01|N1|P|2.5.1\r"
    "MFI|LOC^Location||UPD|||NE\rMFE|MAD|1||LOC1^Loc|CE"
)
_QVR_Q17 = "MSH|^~\\&|A|B|C|D|20260101||QVR^Q17^QVR_Q17|N1|P|2.5.1\rQPD|Q17^Query|T1"


@pytest.mark.parametrize(
    "message",
    [
        pytest.param(_MFN_M01 + "\rLOC|LOC1^Loc||C", id="mfn-m01-with-loc"),
        pytest.param(_QVR_Q17 + "\rPID|1\rRCP|I", id="qvr-q17-with-pid"),
        # The ruling exempts per structure, not per slot, so the slot's cardinality is not held.
        pytest.param(_MFN_M01 + "\rLOC|LOC1^Loc||C\rLOC|LOC2^Loc||C", id="past-the-slot-bound"),
    ],
)
def test_a_defined_segment_in_an_any_hl7_segment_slot_is_not_refused(message: str) -> None:
    """hl7apy marks the "any HL7 segment" slot ANYHL7SEGMENT and its grouping never fills it."""
    result = validate(message)
    assert result.ok, result.errors
    assert result.unvalidated_segments == ()  # not listed: only Z-segments are


@pytest.mark.parametrize(
    ("extra", "error"),
    [
        pytest.param("FOO|1", "unknown segment at line 4", id="undefined-id"),
        pytest.param("PRT|1", "unknown segment at line 4", id="id-of-a-later-version"),
        pytest.param("hello world", "unrecognised line 4", id="non-hl7-text"),
    ],
)
def test_a_wildcard_message_still_refuses_what_its_version_does_not_define(
    extra: str, error: str
) -> None:
    result = validate(_MFN_M01 + "\r" + extra)
    assert not result.ok
    assert result.errors == [error]


def test_a_structure_borrowed_through_msh_9_3_gets_no_exemption() -> None:
    """hl7apy groups ``ADT^A01^MFN_M01`` as MFN_M01; its slot must not admit an ADT body."""
    borrowed = _MFN_M01.replace("MFN^M01^MFN_M01", "ADT^A01^MFN_M01")
    result = validate(borrowed + "\r" + _EVN + "\r" + _PID + "\r" + _PV1)
    assert not result.ok
    assert result.errors == [
        "segment EVN at line 4 has no place in this message's structure (and 2 more)"
    ]


def test_a_version_whose_structure_has_no_slot_still_refuses() -> None:
    """hl7apy's 2.4 MFN_M01 has no any-segment slot, so LOC there is still misplaced."""
    message = _MFN_M01.replace("|2.5.1", "|2.4") + "\rLOC|LOC1^Loc||C"
    result = validate(message)
    assert not result.ok
    assert result.errors == ["segment LOC at line 4 has no place in this message's structure"]


def test_a_comparison_that_raises_is_logged_and_refused(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(*_args: object) -> list[str]:
        raise RuntimeError("synthetic")

    monkeypatch.setattr(validate_module, "_dropped_lines", boom)
    monkeypatch.setattr(validate_module, "_compare_failures", set())  # logged once per structure
    with caplog.at_level("WARNING", logger=validate_module.logger.name):
        result = validate(_adt(_MSH, _EVN, _PID, _PV1))
        again = validate(_adt(_MSH, _EVN, _PID, _PV1))
    assert not result.ok and not again.ok
    assert result.errors == ["could not compare the parsed tree with the message (RuntimeError)"]
    [record] = [r for r in caplog.records if "dropped-segment check" in r.getMessage()]
    assert record.levelname == "WARNING"
    assert record.exc_info is not None


def test_z_segments_do_not_mask_a_refusal() -> None:
    result = validate(_adt(_MSH, "ZAA|1", _EVN, _PID, "FOO|1", _PV1, "ZBB|1", "BAR|1"))
    assert not result.ok
    assert result.errors == ["unknown segment at line 5 (and 1 more)"]
    assert result.unvalidated_segments == (("ZAA", 2), ("ZBB", 7))


def test_empty_lines_are_not_counted() -> None:
    result = validate(_adt(_MSH, "", _EVN, "", _PID, "FOO|1", _PV1))
    assert result.errors == ["unknown segment at line 4"]


@pytest.mark.parametrize("tail", ["   ", "\t", "\xa0"])
def test_trailing_whitespace_the_tolerant_parser_strips_is_not_refused(tail: str) -> None:
    result = validate(_adt(_MSH, _EVN, _PID, _PV1, tail))
    assert result.ok, result.errors


def test_a_line_hl7apy_reads_by_its_first_three_characters_is_still_compared() -> None:
    """hl7apy files ``PIDX|`` as a PID; the tolerant parser forwards it as ``PIDX``, with no PID."""
    # hl7apy skips four characters, then the separator, so PID-3 lands where hl7apy wants it.
    result = validate(_adt(_MSH, _EVN, "PIDX|a|100001^^^HOSP^MR|b|DOE^JANE", _PV1))
    assert not result.ok
    assert result.errors == ["unrecognised line 3"]


@pytest.mark.parametrize(
    "line",
    [
        "Jane Q Doe 555-12-3456",
        "FOO|Jane Q Doe 555-12-3456",
        "ORC|Jane Q Doe 555-12-3456",
        "Z1|Jane Q Doe 555-12-3456",
        "KIM|F",  # a wrapped name fragment that looks like a segment ID
        "DOE|JANE",
    ],
)
def test_the_error_never_echoes_the_dropped_line(line: str) -> None:
    """A dropped line can carry PHI, so the refusal names an ID only when HL7 defines it."""
    result = validate(_adt(_MSH, _EVN, line, _PID, _PV1))
    assert not result.ok, line
    for fragment in ("Jane", "Doe", "555", "KIM", "DOE", "JANE"):
        assert all(fragment not in error for error in result.errors), result.errors


def test_an_earlier_hl7apy_error_is_not_joined_by_a_dropped_line_error() -> None:
    """One conformance error is enough to refuse, as the module docstring says."""
    result = validate(_adt(_MSH, _EVN, "FOO|1", _PV1))
    assert not result.ok
    assert len(result.errors) == 1
    assert "Missing required child ADT_A01.PID" in result.errors[0]


def test_the_generated_valid_corpus_drops_no_line() -> None:
    """No false refusal on any shipped generator's message, two message indexes per trigger.

    Read straight from the tree comparison, so a type whose message hl7apy refuses for another
    reason (the two-block ADT structures, RDE's known mis-grouping) is checked too.
    """
    count = 0
    for code in _core.message_codes():
        for trigger in _core.triggers_for(code):
            for index in (1, 2):
                norm = normalize(_core.generate_message(code, trigger, index)).strip("\r")
                lines = _split_lines(norm)
                parsed = _tolerant_parse(lines.strict_text)
                assert (_dropped_lines(lines, parsed), lines.z_segments) == ([], []), (
                    code,
                    trigger,
                    index,
                )
                count += 1
    assert count > 50  # a positive control: the corpus was actually generated


_ROOT = Path(__file__).resolve().parents[1]


def test_the_docs_state_the_z_segment_position() -> None:
    doc = (_ROOT / "docs" / "HL7-VALIDATION.md").read_text(encoding="utf-8")
    assert "**Z-segments are tolerated, unvalidated, and listed.**" in doc
    assert "unvalidated_segments" in doc
    assert "unvalidated_segments" in (validate_module.__doc__ or "")
