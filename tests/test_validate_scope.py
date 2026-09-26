# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin what strict HL7 validation checks, and what it does not (BACKLOG #1602).

``parsing/validate.py`` and ``parsing/consistency.py`` once said the strict tier checks
"datatypes, table values and lengths". Measured, it checks structure, cardinality and required
fields, and lets field content through, because it parses at hl7apy's TOLERANT level. A Handler
author who believed the old wording would skip a content check they need.

Both halves are pinned. If the parse level changes, or an ``hl7apy`` upgrade starts enforcing
lengths, the "passes" half goes red and the docstrings must change with it. If validation stops
checking anything, the "rejects" half goes red. That half is also the control that makes the
"passes" half mean something: a ``validate()`` that returned ``ok=True`` for everything would
pass the first half alone.
"""

from __future__ import annotations

import pytest

from messagefoundry.parsing import validate

_MSH = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|N1|P|2.5.1"
_EVN = "EVN|A01|20260101"
_PV1 = "PV1|1|I"
_PID = "PID|1||100001^^^HOSP^MR||DOE^JANE||19700101|F"


def _adt(*segments: str) -> str:
    return "\r".join(segments)


def test_the_baseline_message_is_conformant() -> None:
    """Every case below differs from this one in one place, so this must pass first."""
    result = validate(_adt(_MSH, _EVN, _PID, _PV1))
    assert result.ok, result.errors


# Field CONTENT: none of these is checked. The docstrings say so; this pins it.
@pytest.mark.parametrize(
    "pid",
    [
        pytest.param("PID|1||100001^^^HOSP^MR||DOE^JANE||NOTADATE|F", id="malformed-PID-7-date"),
        pytest.param("PID|1||" + "9" * 300 + "||DOE^JANE||19700101|F", id="300-char-PID-3"),
        pytest.param("PID|1||100001^^^HOSP^MR||DOE^JANE||19700101|ZZZ", id="PID-8-not-in-table"),
    ],
)
def test_strict_validation_does_not_check_field_content(pid: str) -> None:
    result = validate(_adt(_MSH, _EVN, pid, _PV1))
    assert result.ok, result.errors


# STRUCTURE, CARDINALITY and REQUIRED FIELDS: each of these is rejected, and each needle is the
# error hl7apy gives for that defect, so a different failure cannot satisfy the case.
@pytest.mark.parametrize(
    ("message", "needle"),
    [
        pytest.param(
            _adt(_MSH, _EVN, _PV1),
            "Missing required child ADT_A01.PID",
            id="missing-required-segment",
        ),
        pytest.param(
            _adt(_MSH, _EVN, _EVN, _PID, _PV1),
            "Child limit exceeded ADT_A01.EVN",
            id="duplicate-EVN",
        ),
        pytest.param(
            _adt(_MSH, _EVN, "PID|1||||DOE^JANE", _PV1),
            "Missing required child PID.PID_3",
            id="empty-PID-3",
        ),
        pytest.param(
            _adt(_MSH, _EVN, _PID, "PV1|1"),
            "Missing required child PV1.PV1_2",
            id="empty-PV1-2",
        ),
        pytest.param(
            _adt(_MSH, _EVN, "PID|1||1||D^J" + "|" * 60 + "X", _PV1),
            "Invalid children detected for <Segment PID>",
            id="field-past-segment-end",
        ),
        pytest.param(
            _adt(_MSH, _EVN, "PID|1||1^2^3^4^5^6^7^8^9^10^11^12^13||D^J", _PV1),
            "Invalid children detected for <Field PID_3",
            id="component-past-datatype-end",
        ),
    ],
)
def test_strict_validation_rejects_structural_defects(message: str, needle: str) -> None:
    result = validate(message)
    assert not result.ok
    assert any(needle in e for e in result.errors), result.errors


def test_the_scope_does_not_follow_hl7apys_process_wide_default() -> None:
    """``validate`` names the TOLERANT level instead of inheriting hl7apy's default.

    That default is process-wide and anything in the process may set it. If ``validate`` inherited
    it, one call elsewhere would change what every strict inbound accepts."""
    import hl7apy
    from hl7apy.consts import VALIDATION_LEVEL

    malformed_date = _adt(_MSH, _EVN, "PID|1||100001^^^HOSP^MR||DOE^JANE||NOTADATE|F", _PV1)
    previous = hl7apy.get_default_validation_level()
    hl7apy.set_default_validation_level(VALIDATION_LEVEL.STRICT)
    try:
        result = validate(malformed_date)
    finally:
        hl7apy.set_default_validation_level(previous)
    assert result.ok, result.errors
