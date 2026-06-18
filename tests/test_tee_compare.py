# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the pure HL7 parity diff (tee/compare.py)."""

from __future__ import annotations

from tee.compare import CompareConfig, compare

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
