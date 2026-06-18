# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the parallel-run reconcile core (harness/reconcile/normalize.py).

All fixtures are SYNTHETIC HL7 (no real PHI). They exercise the normalize+diff comparison that the
migration shadow phase rests on: engine-non-deterministic fields must NOT show as differences, while
real content differences must.
"""

from __future__ import annotations

import pytest

from harness.reconcile import Difference, NormalizeRules, Separators, diff, normalize
from harness.reconcile.normalize import ReconcileError

# A small synthetic ADT^A01. \r segment separators (as MLLP delivers).
BASE = (
    "MSH|^~\\&|MEFOR|MMH|EPIC|MMH|20240101120000||ADT^A01|CTRL0001|P|2.5.1\r"
    "EVN|A01|20240101120000\r"
    "PID|1||MRN123^^^MMH^MR||DOE^JOHN^Q||19800101|M\r"
    "PV1|1|I|WEST^101^A"
)


def _with(msg: str, old: str, new: str) -> str:
    return msg.replace(old, new)


def test_identical_messages_reconcile_clean() -> None:
    assert diff(BASE, BASE) == []


def test_separators_read_from_msh_not_hardcoded() -> None:
    sep = Separators.from_message(BASE)
    assert (sep.field, sep.component, sep.repetition, sep.escape, sep.subcomponent) == (
        "|",
        "^",
        "~",
        "\\",
        "&",
    )


def test_non_msh_message_raises() -> None:
    with pytest.raises(ReconcileError):
        Separators.from_message("PID|||x")


def test_stamped_timestamp_and_control_id_are_ignored() -> None:
    # MSH-7 (datetime) and MSH-10 (control id) differ between engines — must NOT be a difference.
    other = BASE.replace("20240101120000||ADT^A01|CTRL0001", "20240101120559||ADT^A01|CTRL9999", 1)
    assert other != BASE
    assert diff(other, BASE) == []


def test_real_field_difference_is_reported() -> None:
    other = _with(BASE, "DOE^JOHN^Q", "DOE^JANE^Q")  # PID-5 given name changed
    diffs = diff(BASE, other)
    assert len(diffs) == 1
    d = diffs[0]
    assert (d.segment, d.field_no, d.kind) == ("PID", 5, "field")
    assert d.left == "DOE^JOHN^Q" and d.right == "DOE^JANE^Q"


def test_blank_fields_can_be_extended_per_connection() -> None:
    # Simulate a db_lookup-derived field (PV1-7 attending doctor) differing between engines.
    # PV1-7 is the 7th field: PV1|1|I|WEST^101^A||||<here> (4 empties for PV1-4..6 then PV1-7).
    left = _with(BASE, "PV1|1|I|WEST^101^A", "PV1|1|I|WEST^101^A||||9911^WELBY")
    right = _with(BASE, "PV1|1|I|WEST^101^A", "PV1|1|I|WEST^101^A||||9922^STRANGE")
    assert len(diff(left, right)) == 1  # differs by default
    rules = NormalizeRules().with_blanks(("PV1", 7))
    assert diff(left, right, rules) == []  # blanked → reconciled


def test_repetition_order_normalized_only_when_configured() -> None:
    left = _with(BASE, "MRN123^^^MMH^MR", "MRN123^^^MMH^MR~ALT9^^^MMH^MR")
    right = _with(BASE, "MRN123^^^MMH^MR", "ALT9^^^MMH^MR~MRN123^^^MMH^MR")
    assert len(diff(left, right)) == 1  # order matters by default
    rules = NormalizeRules(sort_repetition_fields=frozenset({("PID", 3)}))
    assert diff(left, right, rules) == []  # sorted → equal


def test_extra_segment_is_left_or_right_only() -> None:
    extra = BASE + "\rNK1|1|DOE^JANE|SPO"
    diffs = diff(extra, BASE)
    assert len(diffs) == 1
    assert diffs[0].kind == "left-only-segment" and diffs[0].segment == "NK1"
    # mirror image
    assert diff(BASE, extra)[0].kind == "right-only-segment"


def test_non_semantic_segment_order_normalized_when_configured() -> None:
    a = BASE + "\rNK1|1|AAA|SPO\rNK1|2|BBB|CHD"
    b = BASE + "\rNK1|2|BBB|CHD\rNK1|1|AAA|SPO"
    assert diff(a, b) != []  # positional by default (SetID differs per position)
    rules = NormalizeRules(sort_segments=frozenset({"NK1"}))
    assert diff(a, b, rules) == []  # whole NK1 occurrences sorted → equal


def test_ignore_segments_dropped_from_both_sides() -> None:
    a = BASE + "\rZZZ|debug-left"
    b = BASE + "\rZZZ|debug-right"
    assert diff(a, b) != []
    assert diff(a, b, NormalizeRules(ignore_segments=frozenset({"ZZZ"}))) == []


def test_alternate_separators_are_honored() -> None:
    # Same message re-encoded with '#' field sep and '@' component sep — diff must still see them equal
    # to itself and read the separators from MSH (not assume |^).
    alt = BASE.replace("|", "#").replace("^", "@")
    assert diff(alt, alt) == []
    sep = Separators.from_message(alt)
    assert sep.field == "#" and sep.component == "@"


def test_difference_describe_is_readable() -> None:
    d = Difference("PID", 1, 5, "DOE^JOHN", "DOE^JANE", "field")
    assert "PID[1]-5" in d.describe() and "field" in d.describe()


def test_normalize_blanks_in_place_returns_canonical() -> None:
    canon = normalize(BASE)
    msh = canon[0]
    # MSH-7 (split idx 6) and MSH-10 (split idx 9) blanked by default.
    assert msh[6] == "" and msh[9] == ""
    # MSH-9 (type, split idx 8) preserved.
    assert msh[8] == "ADT^A01"
