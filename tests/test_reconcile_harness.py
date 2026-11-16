# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the parallel-run reconcile core (harness/reconcile/normalize.py).

All fixtures are SYNTHETIC HL7 (no real PHI). They exercise the normalize+diff comparison that the
migration shadow phase rests on: engine-non-deterministic fields must NOT show as differences, while
real content differences must.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from harness.reconcile import Difference, NormalizeRules, Separators, diff, normalize
from harness.reconcile.__main__ import main as reconcile_main
from harness.reconcile.normalize import ReconcileError

# The package re-exports the `normalize` FUNCTION under the module's name, so name the module itself.
normalize_module = importlib.import_module("harness.reconcile.normalize")

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


def test_a_different_declared_field_separator_is_a_difference() -> None:
    """BACKLOG #5425: MSH-1 is the field separator itself, so splitting each side on its own separator
    lost it, and two messages that differed only there normalized to equal rows. It is a real output
    difference: a receiver that hardcodes ``|`` reads the other side's message as one field."""
    alt = BASE.replace("|", "#")
    [d] = diff(BASE, alt)
    assert (d.segment, d.occurrence, d.field_no, d.left, d.right, d.kind) == (
        "MSH",
        1,
        1,
        "|",
        "#",
        "field",
    )
    assert normalize(BASE) != normalize(alt)
    # The rows now index every segment by its HL7 field number, MSH included.
    assert normalize(BASE)[0][1:3] == ["|", "^~\\&"]


def test_difference_describe_is_readable() -> None:
    d = Difference("PID", 1, 5, "DOE^JOHN", "DOE^JANE", "field")
    assert "PID[1]-5" in d.describe() and "field" in d.describe()


def test_normalize_blanks_in_place_returns_canonical() -> None:
    canon = normalize(BASE)
    msh = canon[0]
    # MSH-7 and MSH-10 blanked by default; the row holds MSH-1, so each sits at its field number.
    assert msh[7] == "" and msh[10] == ""
    # MSH-9 (type) preserved.
    assert msh[9] == "ADT^A01"


# --- BACKLOG #5569: a segment moved between parent groups must not compare equal -------------------

# A synthetic two-order ORU^R01. Each OBR opens a group, and the OBX/NTE after it belong to that order.
ORU = (
    "MSH|^~\\&|LAB|MMH|EPIC|MMH|20240101120000||ORU^R01|CTRL0002|P|2.5.1\r"
    "PID|1||MRN123^^^MMH^MR||DOE^JOHN^Q||19800101|M\r"
    "OBR|1|ORD1||CBC^COMPLETE BLOOD COUNT\r"
    "OBX|1|NM|WBC^WHITE CELLS||7.1|10*3/uL\r"
    "NTE|1||HEMOLYZED SAMPLE\r"
    "OBR|2|ORD2||BMP^BASIC METABOLIC PANEL\r"
    "OBX|1|NM|NA^SODIUM||140|mmol/L"
)

_NTE = "NTE|1||HEMOLYZED SAMPLE"
_NA = "OBX|1|NM|NA^SODIUM||140|mmol/L"


def _nte_moved_to_bmp(extra: str = "") -> str:
    """The CBC's comment moved under the BMP order: same segments, same count of each."""
    return ORU.replace(_NTE + "\r", "").replace(_NA, _NA + "\r" + _NTE + extra)


def test_an_nte_moved_to_another_order_is_a_difference() -> None:
    moved = _nte_moved_to_bmp()
    assert sorted(moved.split("\r")) == sorted(ORU.split("\r")), "the fixture must only reorder"
    diffs = diff(ORU, moved)
    assert diffs, "a segment moved to another OBR group compared equal"
    assert {d.kind for d in diffs} == {"segment-order"}, [d.describe() for d in diffs]
    assert diff(moved, ORU), "the mirror image must be a difference too"


def test_an_obx_moved_to_another_order_is_a_difference() -> None:
    # The WBC result now belongs to the BMP order. The OBX set ids are equal, so only position tells.
    wbc = "OBX|1|NM|WBC^WHITE CELLS||7.1|10*3/uL\r"
    bmp = "OBR|2|ORD2||BMP^BASIC METABOLIC PANEL\r"
    moved = ORU.replace(wbc, "").replace(bmp, bmp + wbc)
    assert sorted(moved.split("\r")) == sorted(ORU.split("\r")), "the fixture must only reorder"
    assert diff(ORU, moved) != []


def test_the_order_difference_names_the_moved_segment_with_its_content() -> None:
    (d,) = diff(ORU, _nte_moved_to_bmp())
    # The moved segment is named, and left/right carry its content on each side, as a whole-segment
    # row does.
    assert (d.segment, d.occurrence, d.field_no) == ("NTE", 1, None)
    assert d.left == _NTE and d.right == _NTE, d.describe()


def test_a_surplus_segment_alone_is_not_also_an_order_difference() -> None:
    # An extra trailing NTE is right-only and nothing more: the shared segments still line up.
    extra = ORU + "\rNTE|2||ADDED"
    assert [d.kind for d in diff(ORU, extra)] == ["right-only-segment"]


def test_a_segment_inserted_mid_message_is_not_a_move() -> None:
    # A second NTE under the CBC: nothing moved, so whatever else the ordinal pairing reports, no row
    # claims a reorder.
    inserted = ORU.replace(_NTE, _NTE + "\rNTE|2||ADDED")
    kinds = {d.kind for d in diff(ORU, inserted)}
    assert "right-only-segment" in kinds and "segment-order" not in kinds, kinds
    # The mirror image, a segment deleted mid-message, is not a move either.
    assert "segment-order" not in {d.kind for d in diff(inserted, ORU)}


def test_a_move_far_from_an_insertion_is_still_found() -> None:
    # An NTE added under the CBC AND the WBC result moved to the BMP: the insertion must not hide
    # the move.
    wbc = "OBX|1|NM|WBC^WHITE CELLS||7.1|10*3/uL\r"
    bmp = "OBR|2|ORD2||BMP^BASIC METABOLIC PANEL\r"
    both = ORU.replace(_NTE, _NTE + "\rNTE|2||ADDED").replace(wbc, "").replace(bmp, bmp + wbc)
    orders = [d for d in diff(ORU, both) if d.kind == "segment-order"]
    assert len(orders) == 1, [d.describe() for d in diff(ORU, both)]


def test_any_position_segments_waives_the_place_but_not_the_content() -> None:
    zpd = "\rZPD|1|SITE-A"
    left = BASE.replace("\rPV1", zpd + "\rPV1")  # before PV1
    right = BASE + zpd  # after PV1
    assert [d.kind for d in diff(left, right)] == ["segment-order"]
    rules = NormalizeRules(any_position_segments=frozenset({"ZPD"}))
    assert diff(left, right, rules) == []
    # The content is still compared.
    changed = BASE + "\rZPD|1|SITE-B"
    assert [d.kind for d in diff(left, changed, rules)] == ["field"]


def test_the_cli_flag_reaches_the_rule(tmp_path: Path) -> None:
    # The flag, upper-cased as its siblings are, is what an operator actually uses.
    zpd = "\rZPD|1|SITE-A"
    mefor = tmp_path / "mefor.hl7"
    corepoint = tmp_path / "corepoint.hl7"
    mefor.write_text(BASE.replace("\rPV1", zpd + "\rPV1") + "\r", encoding="latin-1")
    corepoint.write_text(BASE + zpd + "\r", encoding="latin-1")
    argv = ["compare", "--mefor", str(mefor), "--corepoint", str(corepoint)]
    assert reconcile_main(argv) == 1
    assert reconcile_main([*argv, "--any-position-segment", "zpd"]) == 0


def test_a_move_beside_a_new_segment_of_the_same_id_is_found() -> None:
    # The BMP's comment X moves to the CBC, and a new comment Y is added under the BMP. Aligned on
    # ids alone, X would pair with Y and read as one comment appended.
    left = (
        "MSH|^~\\&|LAB|MMH|EPIC|MMH|20240101120000||ORU^R01|CTRL0003|P|2.5.1\r"
        "PID|1||MRN123\rOBR|1|ORD1\rOBX|1|NM|WBC\rOBR|2|ORD2\rNTE|1||X"
    )
    right = (
        "MSH|^~\\&|LAB|MMH|EPIC|MMH|20240101120000||ORU^R01|CTRL0003|P|2.5.1\r"
        "PID|1||MRN123\rOBR|1|ORD1\rNTE|1||X\rOBX|1|NM|WBC\rOBR|2|ORD2\rNTE|1||Y"
    )
    orders = [d for d in diff(left, right) if d.kind == "segment-order"]
    assert [(d.segment, d.left, d.right) for d in orders] == [("NTE", "NTE|1||X", "NTE|1||X")]


def test_a_move_is_reported_with_its_own_content_never_a_deleted_neighbours() -> None:
    # Comment A deleted, and the WBC result and comment B moved under the BMP. The alignment names
    # the fewest segments that explain the reorder -- here OBR|2 moving ahead of them -- and each
    # row carries that segment's own content, never A's beside B's.
    left = (
        "MSH|^~\\&|LAB|MMH|EPIC|MMH|20240101120000||ORU^R01|CTRL0004|P|2.5.1\r"
        "PID|1||MRN123\rNTE|1||A\rOBR|1|ORD1\rOBX|1|NM|WBC\rNTE|1||B\rOBR|2|ORD2"
    )
    right = (
        "MSH|^~\\&|LAB|MMH|EPIC|MMH|20240101120000||ORU^R01|CTRL0004|P|2.5.1\r"
        "PID|1||MRN123\rOBR|1|ORD1\rOBR|2|ORD2\rOBX|1|NM|WBC\rNTE|1||B"
    )
    orders = [d for d in diff(left, right) if d.kind == "segment-order"]
    assert [(d.segment, d.occurrence, d.left, d.right) for d in orders] == [
        ("OBR", 2, "OBR|2|ORD2", "OBR|2|ORD2")
    ], [d.describe() for d in orders]


def test_two_independent_moves_are_both_reported() -> None:
    # Two separate moves in one message: both rows appear at once, not the second only after the
    # first is fixed.
    wbc = "OBX|1|NM|WBC^WHITE CELLS||7.1|10*3/uL\r"
    pid = "PID|1||MRN123^^^MMH^MR||DOE^JOHN^Q||19800101|M\r"
    both = _nte_moved_to_bmp().replace(pid, "").replace(wbc, wbc + pid)
    orders = [d for d in diff(ORU, both) if d.kind == "segment-order"]
    assert {d.segment for d in orders} == {"PID", "NTE"}, [d.describe() for d in orders]


def test_any_position_does_not_split_a_sorted_run() -> None:
    rules = NormalizeRules(
        sort_segments=frozenset({"NK1"}), any_position_segments=frozenset({"ZPD"})
    )
    left = BASE.replace("\rPV1", "\rNK1|2|A\rZPD|1\rNK1|1|B\rPV1")
    right = BASE.replace("\rPV1", "\rNK1|2|A\rNK1|1|B\rPV1") + "\rZPD|1"
    assert diff(left, right, rules) == []


def test_a_message_too_large_to_align_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Past the alignment's size cap the order is not checked, and the comparison says so rather
    # than pass a move it did not look for.
    monkeypatch.setattr(normalize_module, "_LCS_MAX_CELLS", 1)
    (d,) = diff(ORU, _nte_moved_to_bmp())
    assert d.kind == "order-unchecked", d.describe()
    # A pure insertion is still proved in order cheaply, so it is not flagged.
    inserted = ORU.replace(_NTE, _NTE + "\rNTE|2||ADDED")
    assert "order-unchecked" not in {d.kind for d in diff(ORU, inserted)}


def test_any_position_segments_are_left_out_of_the_order_check_entirely() -> None:
    # Two different any-position ids that swap places: every segment's content is the same, so the
    # pair reconciles, rather than the two being compared against each other at the end.
    rules = NormalizeRules(any_position_segments=frozenset({"ZA", "ZB"}))
    left = BASE.replace("\rPV1", "\rZA|1\rPV1") + "\rZB|1"
    right = BASE.replace("\rPV1", "\rZB|1\rPV1") + "\rZA|1"
    assert diff(left, right, rules) == []
    # The same with an any-position id that is also sort_segments, split by the other.
    rules = NormalizeRules(
        sort_segments=frozenset({"ZA"}), any_position_segments=frozenset({"ZA", "ZB"})
    )
    left = BASE.replace("\rPV1", "\rZA|1\rZB|1\rPV1") + "\rZA|2"
    right = BASE.replace("\rPV1", "\rZA|2\rZA|1\rPV1") + "\rZB|1"
    assert diff(left, right, rules) == []


def test_with_blanks_keeps_every_other_rule() -> None:
    rules = NormalizeRules(
        sort_segments=frozenset({"NK1"}), any_position_segments=frozenset({"ZPD"})
    ).with_blanks(("PV1", 7))
    assert rules.sort_segments == {"NK1"} and rules.any_position_segments == {"ZPD"}
    assert ("PV1", 7) in rules.blank_fields and ("MSH", 7) in rules.blank_fields


def test_a_move_beside_a_surplus_is_still_an_order_difference() -> None:
    # The NTE moves to the BMP group AND the right gains a second NTE. The surplus must not hide
    # the move.
    kinds = {d.kind for d in diff(ORU, _nte_moved_to_bmp("\rNTE|2||ADDED"))}
    assert kinds == {"segment-order", "right-only-segment"}, kinds


def test_sort_segments_still_reconciles_a_reordered_run_inside_one_group() -> None:
    # sort_segments sorts a CONTIGUOUS run, so reordered OBX inside one OBR stays clean when asked
    # for, and the order check does not undo that.
    wbc = "OBX|1|NM|WBC^WHITE CELLS||7.1|10*3/uL\r"
    hgb = "OBX|2|NM|HGB^HEMOGLOBIN||13.5|g/dL\r"
    two_obx = ORU.replace(wbc, wbc + hgb)
    swapped = ORU.replace(wbc, hgb + wbc)
    assert diff(two_obx, swapped) != []
    assert diff(two_obx, swapped, NormalizeRules(sort_segments=frozenset({"OBX"}))) == []
