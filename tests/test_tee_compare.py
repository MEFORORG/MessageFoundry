# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Unit tests for the pure HL7 parity diff (tee/compare.py)."""

from __future__ import annotations

from tee.compare import SEGMENT_ORDER, CompareConfig, compare

A = (
    "MSH|^~\\&|MEFOR|RFAC|RECV|RFAC|20260604120000||ADT^A01|MSG1|P|2.5.1\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def test_exact_identical() -> None:
    r = compare(A, A)
    assert r.kind == "exact"
    assert r.diffs == ()


def test_exact_ignores_line_ending_trivia() -> None:
    assert compare(A, A.replace("\r", "\r\n")).kind == "exact"


def test_semantic_when_only_ignored_fields_differ() -> None:
    # Differs only in MSH sending app (3), datetime (7), control id (10) — all legitimately divergent.
    b = (
        "MSH|^~\\&|COREPOINT|RFAC|RECV|RFAC|20260604120530||ADT^A01|XYZ9|P|2.5.1\r"
        "PID|1||100^^^H^MR||DOE^JANE\r"
    )
    r = compare(A, b)
    assert r.kind == "semantic"
    assert r.material_diffs == ()
    assert {d.location for d in r.diffs} == {"MSH-3", "MSH-7", "MSH-10"}
    assert all(d.ignored for d in r.diffs)


def test_mismatch_on_material_field() -> None:
    c = (
        "MSH|^~\\&|MEFOR|RFAC|RECV|RFAC|20260604120000||ADT^A01|MSG1|P|2.5.1\r"
        "PID|1||100^^^H^MR||DOE^JOHN\r"
    )
    r = compare(A, c)
    assert r.kind == "mismatch"
    [diff] = r.material_diffs
    assert (diff.location, diff.left, diff.right, diff.ignored) == (
        "PID-5",
        "DOE^JANE",
        "DOE^JOHN",
        False,
    )


def test_mismatch_on_added_segment() -> None:
    # A Z-segment present on only one side is a structural (material) difference.
    r = compare(A, A + "ZID|extra\r")
    assert r.kind == "mismatch"
    assert any(diff.location == "ZID" for diff in r.material_diffs)


def test_custom_ignore_fields_makes_it_semantic() -> None:
    c = (
        "MSH|^~\\&|MEFOR|RFAC|RECV|RFAC|20260604120000||ADT^A01|MSG1|P|2.5.1\r"
        "PID|1||100^^^H^MR||DOE^JOHN\r"
    )
    r = compare(A, c, CompareConfig(ignore_fields=frozenset({("PID", 5)})))
    assert r.kind == "semantic"
    assert r.material_diffs == ()


def test_custom_separators_field_addressing() -> None:
    # Two messages with non-standard encoding chars differing only in PID-5 — the "PID-5" location
    # proves the field split used the MSH-declared "!" separator (else it'd be a whole-segment diff).
    e1 = "MSH!*~\\&!MEFOR!RFAC!RECV!RFAC!20260604!!ADT*A01!MSG1!P!2.5.1\rPID!1!!100!!DOE*JANE\r"
    e2 = "MSH!*~\\&!MEFOR!RFAC!RECV!RFAC!20260604!!ADT*A01!MSG1!P!2.5.1\rPID!1!!100!!DOE*JOHN\r"
    r = compare(e1, e2)
    assert r.kind == "mismatch"
    assert any(diff.location == "PID-5" for diff in r.material_diffs)


# Synthetic ORU with two OBR groups. Moving a segment from group 1 to group 2 keeps every segment's
# (id, occurrence) key and every field, so only the order shows the regrouping (BACKLOG #5403).
_ORU_HEAD = (
    "MSH|^~\\&|MEFOR|RFAC|RECV|RFAC|20260604120000||ORU^R01|MSG1|P|2.5.1\rPID|1||100^^^H^MR\r"
)
_GROUP_1 = "OBR|1|||CBC\rOBX|1|NM|WBC||7.1\r"
_NTE = "NTE|1||Specimen hemolyzed\r"
_GROUP_2 = "OBR|2|||BMP\rOBX|1|NM|NA||140\r"


def test_mismatch_when_an_nte_moves_between_obr_groups() -> None:
    left = _ORU_HEAD + _GROUP_1 + _NTE + _GROUP_2
    right = _ORU_HEAD + _GROUP_1 + _GROUP_2 + _NTE
    r = compare(left, right)
    assert r.kind == "mismatch"
    [diff] = r.material_diffs
    assert diff.location == SEGMENT_ORDER
    assert diff.left == "MSH PID OBR OBX NTE OBR OBX"
    assert diff.right == "MSH PID OBR OBX OBR OBX NTE"


def test_mismatch_when_an_obx_moves_between_obr_groups() -> None:
    obx2 = "OBX|2|NM|HGB||13.9\r"
    left = _ORU_HEAD + _GROUP_1 + obx2 + "OBR|2|||BMP\r"
    right = _ORU_HEAD + _GROUP_1 + "OBR|2|||BMP\r" + obx2
    r = compare(left, right)
    assert r.kind == "mismatch"
    assert [d.location for d in r.material_diffs] == [SEGMENT_ORDER]


def test_same_order_reports_no_order_diff() -> None:
    oru = _ORU_HEAD + _GROUP_1 + _NTE + _GROUP_2
    assert compare(oru, oru).kind == "exact"
    # A segment on one side only is a presence diff alone; the shared segments keep their order.
    r = compare(oru, oru + "ZID|extra\r")
    assert [d.location for d in r.material_diffs] == ["ZID"]


def test_an_inserted_repeated_segment_reports_no_reorder() -> None:
    # One extra OBX in group 1 renumbers the later OBX occurrence. That is a presence diff and a
    # mismatch, not a regrouping, so no order diff names a sequence neither message has.
    left = _ORU_HEAD + _GROUP_1 + _GROUP_2
    right = _ORU_HEAD + _GROUP_1 + "OBX|2|NM|HGB||13.9\r" + _GROUP_2
    r = compare(left, right)
    assert r.kind == "mismatch"
    assert SEGMENT_ORDER not in {d.location for d in r.diffs}


def test_a_regrouping_is_reported_beside_an_unrelated_extra_segment() -> None:
    left = _ORU_HEAD + _GROUP_1 + _NTE + _GROUP_2
    right = _ORU_HEAD + _GROUP_1 + _GROUP_2 + _NTE + "ZID|extra\r"
    r = compare(left, right)
    order = [d for d in r.material_diffs if d.location == SEGMENT_ORDER]
    assert [(d.left, d.right) for d in order] == [
        ("MSH PID OBR OBX NTE OBR OBX", "MSH PID OBR OBX OBR OBX NTE")
    ]
    assert "ZID" in {d.location for d in r.material_diffs}
