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
from messagefoundry.parsing.validate import _dropped_lines, _tolerant_parse
from messagefoundry_toolkit.generators import (
    _core,
    all_types,  # noqa: F401  (registers every built-in type)
)

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
        pytest.param("FOO|1", "segment FOO at line 3 is not an HL7 segment", id="unknown-segment"),
        pytest.param(
            "ORC|NW|ORD1",
            "segment ORC at line 3 has no place in this message structure",
            id="misplaced-known-segment",
        ),
        pytest.param("hello world", "unrecognised line 3", id="non-hl7-text"),
        pytest.param("zxx|1", "unrecognised line 3", id="lowercase-z-is-not-a-z-segment"),
        pytest.param("ZXXX|1", "unrecognised line 3", id="four-character-id"),
        pytest.param("FO|1", "unrecognised line 3", id="two-character-id"),
    ],
)
def test_a_dropped_line_is_refused(extra: str, error: str) -> None:
    result = validate(_adt(_MSH, _EVN, extra, _PID, _PV1))
    assert not result.ok
    assert result.errors == [error]


@pytest.mark.parametrize("z", ["ZXX|1", "Z01|1|2", "ZPI"])
def test_a_z_segment_is_tolerated_and_listed(z: str) -> None:
    result = validate(_adt(_MSH, _EVN, z, _PID, _PV1))
    assert result.ok, result.errors
    assert result.unvalidated_segments == (f"{z[:3]} at line 3",)


def test_z_segments_do_not_mask_a_refusal() -> None:
    result = validate(_adt(_MSH, "ZAA|1", _EVN, _PID, "FOO|1", _PV1, "ZBB|1", "BAR|1"))
    assert not result.ok
    assert result.errors == ["segment FOO at line 5 is not an HL7 segment (and 1 more)"]
    assert result.unvalidated_segments == ("ZAA at line 2", "ZBB at line 7")


def test_empty_lines_are_not_counted() -> None:
    result = validate(_adt(_MSH, "", _EVN, "", _PID, "FOO|1", _PV1))
    assert result.errors == ["segment FOO at line 4 is not an HL7 segment"]


def test_a_whitespace_only_line_is_refused() -> None:
    """The tolerant parser keeps a whitespace-only line (peek.drop_blank_segments), so it counts."""
    result = validate(_adt(_MSH, _EVN, "   ", _PID, _PV1))
    assert result.errors == ["unrecognised line 3"]


def test_the_error_never_echoes_the_dropped_line() -> None:
    """A dropped line can carry PHI, so the refusal names its position only."""
    secret = "Jane Q Doe 555-12-3456 1970-01-01"
    for line in (secret, f"FOO|{secret}", f"ORC|{secret}", f"Z1|{secret}"):
        result = validate(_adt(_MSH, _EVN, line, _PID, _PV1))
        assert not result.ok, line
        assert all(secret not in error for error in result.errors), result.errors
        assert all("Jane" not in error and "Doe" not in error for error in result.errors)


def test_an_earlier_hl7apy_error_is_not_joined_by_a_dropped_line_error() -> None:
    """One conformance error is enough to refuse, as the module docstring says."""
    result = validate(_adt(_MSH, _EVN, "FOO|1", _PV1))
    assert not result.ok
    assert len(result.errors) == 1
    assert "Missing required child ADT_A01.PID" in result.errors[0]


def test_the_generated_valid_corpus_drops_no_line() -> None:
    """No false 'no place' refusal on any shipped generator's message, two seeds per trigger.

    Read straight from the tree comparison, so a type whose message hl7apy refuses for another
    reason (the two-block ADT structures, RDE's known mis-grouping) is checked too.
    """
    count = 0
    for code in _core.message_codes():
        for trigger in _core.triggers_for(code):
            for seed in (1, 2):
                norm = normalize(_core.generate_message(code, trigger, seed)).strip("\r")
                assert _dropped_lines(norm, _tolerant_parse(norm)) == ([], []), (
                    code,
                    trigger,
                    seed,
                )
                count += 1
    assert count > 50  # a positive control: the corpus was actually generated


_ROOT = Path(__file__).resolve().parents[1]


def test_the_docs_state_the_z_segment_position() -> None:
    doc = (_ROOT / "docs" / "HL7-VALIDATION.md").read_text(encoding="utf-8")
    assert "**Z-segments are tolerated, unvalidated, and listed.**" in doc
    assert "unvalidated_segments" in doc
    # By module path: the package re-exports the function under the module's own name.
    module = importlib.import_module("messagefoundry.parsing.validate")
    assert "unvalidated_segments" in (module.__doc__ or "")
