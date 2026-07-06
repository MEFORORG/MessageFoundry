# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Cross-field HL7 consistency primitives (WP-7b, ASVS 2.2.3/2.1.2/2.2.1).

Each primitive takes a parsed Message + field paths and returns PHI-safe Violations (path + rule,
never the value). The Handler decides what to do with them; these tests pin the detection + the
PHI-safety guarantee."""

from __future__ import annotations

from messagefoundry.parsing.consistency import (
    ConsistencyError,
    check,
    dates_in_order,
    matches,
    required,
    same_across,
    valid_date,
)
from messagefoundry.parsing.message import Message

MSH = "MSH|^~\\&|S|F|R|F|20240101120000||ADT^A01|MSG1|P|2.5"


def _msg(*segments: str) -> Message:
    return Message.parse("\r".join((MSH, *segments)))


def _pv1(admit: str = "", discharge: str = "") -> str:
    # PV1-44 = Admit Date/Time, PV1-45 = Discharge Date/Time (1-based field positions).
    fields = [""] * 45
    fields[43] = admit
    fields[44] = discharge
    return "PV1|" + "|".join(fields)


def test_required_flags_only_missing_fields() -> None:
    msg = _msg("PID|1||PID123^^^MR||DOE^JOHN")
    v = required(msg, "PID-3", "PID-5", "PID-99")
    assert [x.paths for x in v] == [("PID-99",)]  # 3 and 5 present; 99 absent


def test_required_all_present_no_violation() -> None:
    assert required(_msg("PID|1||PID123||DOE^JOHN"), "MSH-10", "PID-3") == []


def test_same_across_detects_disagreement() -> None:
    msg = _msg("EVN|A02|20240101")  # MSH-9.2 is A01, EVN-1 is A02 → disagree
    assert len(same_across(msg, "MSH-9.2", "EVN-1")) == 1


def test_same_across_match_ok() -> None:
    assert same_across(_msg("EVN|A01|20240101"), "MSH-9.2", "EVN-1") == []


def test_same_across_present_vs_absent_is_violation() -> None:
    msg = _msg("PID|1||X")  # EVN absent → EVN-1 None while MSH-9.2 present
    assert len(same_across(msg, "MSH-9.2", "EVN-1")) == 1


def test_same_across_all_absent_is_consistent() -> None:
    assert same_across(_msg("PID|1||X"), "ZZ1-1", "ZZ2-1") == []


def test_valid_date_accepts_hl7_precisions() -> None:
    for d in (
        "2024",
        "202401",
        "20240131",
        "2024013112",
        "20240131120000",
        "20240131120000.5+0100",
    ):
        assert valid_date(_msg(f"PID|1||X||Y||{d}"), "PID-7") == [], d


def test_valid_date_rejects_malformed_and_impossible() -> None:
    for d in ("notadate", "20241301", "20240230", "2024013", "abc20240101"):
        assert len(valid_date(_msg(f"PID|1||X||Y||{d}"), "PID-7")) == 1, d


def test_valid_date_absent_not_flagged() -> None:
    assert valid_date(_msg("PID|1||X||Y"), "PID-7") == []


def test_dates_in_order_ok_and_violation() -> None:
    assert dates_in_order(_msg(_pv1("20240101", "20240105")), "PV1-44", "PV1-45") == []
    assert len(dates_in_order(_msg(_pv1("20240105", "20240101")), "PV1-44", "PV1-45")) == 1


def test_dates_in_order_equal_ok() -> None:
    msg = _msg(_pv1("20240101120000", "20240101120000"))
    assert dates_in_order(msg, "PV1-44", "PV1-45") == []


def test_dates_in_order_skips_when_absent_or_invalid() -> None:
    assert dates_in_order(_msg(_pv1("20240105", "")), "PV1-44", "PV1-45") == []  # discharge absent
    assert dates_in_order(_msg(_pv1("oops", "20240101")), "PV1-44", "PV1-45") == []  # admit invalid


def test_matches_full_anchored() -> None:
    msg = _msg("PID|1||0001234")
    assert matches(msg, "PID-3", r"\d{7}") == []
    assert len(matches(msg, "PID-3", r"\d{3}")) == 1  # fullmatch: 7 digits ≠ 3


def test_matches_absent_not_flagged() -> None:
    assert matches(_msg("PID|1"), "PID-99", r"\d+") == []


def test_check_flattens_groups() -> None:
    msg = _msg("PID|1")  # PID-3 / PID-5 absent; PID-7 absent (date skipped)
    violations = check(required(msg, "PID-3", "PID-5"), valid_date(msg, "PID-7"))
    assert len(violations) == 2


def test_violation_message_never_contains_the_value() -> None:
    v = valid_date(_msg("PID|1||X||Y||garbage-dob-value"), "PID-7")[0]
    assert "PID-7" in v.message and "garbage" not in v.message


def test_consistency_error_string_is_phi_safe() -> None:
    err = ConsistencyError(required(_msg("PID|1"), "PID-3", "MSH-10"))
    assert "PID-3" in str(err)
    assert len(err.violations) == 1  # MSH-10 present (from MSH); only PID-3 missing
