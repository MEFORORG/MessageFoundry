# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Group-scoped structural editing (Tier 2.1): the SegmentGroup view over Message.

An ORU carries a header (MSH/PID) followed by repeating OBR order groups, each owning its OBX
results. These tests use only SYNTHETIC HL7 (fake data; MSH-9 is a real type, OBR/OBX shaped
realistically) and assert that grouping, group-scoped reads, and clear/delete/append/rebuild edit
exactly one order without disturbing siblings or the header.
"""

from __future__ import annotations

import pytest

from messagefoundry.parsing import Message, SegmentGroup

# Two OBR order groups: the first owns two OBX, the second owns one. PID is header (no group).
ORU_2OBR = (
    "MSH|^~\\&|LAB|LABFAC|EHR|HOSP|20260101||ORU^R01^ORU_R01|MSG1|P|2.5.1\r"
    "PID|1||100^^^HOSP^MR||DOE^JANE^Q||19800101|F\r"
    "OBR|1|PLAC1|FILL1|CBC^Complete Blood Count\r"
    "OBX|1|NM|WBC^White Cells||7.5|10*9/L\r"
    "OBX|2|NM|HGB^Hemoglobin||14.0|g/dL\r"
    "OBR|2|PLAC2|FILL2|LIPID^Lipid Panel\r"
    "OBX|1|NM|CHOL^Cholesterol||190|mg/dL\r"
)


def test_groups_split_on_boundary_and_exclude_header() -> None:
    m = Message.parse(ORU_2OBR)
    groups = m.groups()  # default boundary OBR
    assert len(groups) == 2
    # Header (MSH, PID) belongs to NO group — only the OBR runs are returned.
    assert groups[0].segment_ids() == ["OBR", "OBX", "OBX"]
    assert groups[1].segment_ids() == ["OBR", "OBX"]
    assert all(isinstance(g, SegmentGroup) for g in groups)
    assert groups[0].boundary == "OBR"
    assert (groups[0].ordinal, groups[1].ordinal) == (1, 2)
    assert len(groups[0]) == 3 and len(groups[1]) == 2


def test_group_scoped_count_and_field() -> None:
    m = Message.parse(ORU_2OBR)
    g1, g2 = m.groups()
    # count is scoped to the group, unlike the whole-message Message.count_segments.
    assert g1.count("OBX") == 2
    assert g2.count("OBX") == 1
    assert m.count_segments("OBX") == 3  # contrast: flat count sees all orders
    # occurrence is group-local: occurrence 1 of g2 is the SECOND OBR's first OBX.
    assert g1.field("OBR-4.1") == "CBC"
    assert g2.field("OBR-4.1") == "LIPID"
    assert g1.field("OBX-3.1", occurrence=1) == "WBC"
    assert g1.field("OBX-3.1", occurrence=2) == "HGB"
    assert g2.field("OBX-3.1", occurrence=1) == "CHOL"  # NOT the message-wide 3rd OBX
    assert g2.field("OBX-3.1", occurrence=2) is None  # group has only one OBX
    assert g1.field("OBX-5", occurrence=1) == "7.5"


def test_group_field_one_based_occurrence() -> None:
    m = Message.parse(ORU_2OBR)
    g1 = m.groups()[0]
    with pytest.raises(ValueError):
        g1.field("OBX-5", occurrence=0)


def test_clear_keeps_boundary_drops_body() -> None:
    # Corepoint ItemClear: empty an order's observations, keep the order header.
    m = Message.parse(ORU_2OBR)
    g1, g2 = m.groups()
    removed = g1.clear()
    assert removed == 2
    assert g1.segment_ids() == ["OBR"]  # boundary survives, OBX gone
    # The OTHER group and the header are untouched.
    assert g2.segment_ids() == ["OBR", "OBX"]
    assert m.segments() == ["MSH", "PID", "OBR", "OBR", "OBX"]
    again = Message.parse(m.encode())  # round-trips
    assert again.segments() == ["MSH", "PID", "OBR", "OBR", "OBX"]


def test_delete_removes_whole_group() -> None:
    m = Message.parse(ORU_2OBR)
    g1, g2 = m.groups()
    removed = g1.delete()
    assert removed == 3  # OBR + its two OBX
    # The second order is now the only group; header preserved.
    assert m.segments() == ["MSH", "PID", "OBR", "OBX"]
    survivors = m.groups()
    assert len(survivors) == 1
    assert survivors[0].field("OBR-4.1") == "LIPID"


def test_groups_are_addressed_by_ordinal_and_reindex_after_delete() -> None:
    # A SegmentGroup is a POSITIONAL view (the Nth boundary), not a stable handle to a specific
    # order. After deleting group 1, ordinal 1 now resolves to what was group 2 — and the old
    # ordinal-2 view raises LookupError because only one boundary remains. Re-fetch groups() after a
    # structural delete rather than reusing stale views.
    m = Message.parse(ORU_2OBR)
    g1, g2 = m.groups()
    g1.delete()
    assert g1.field("OBR-4.1") == "LIPID"  # ordinal 1 now points at the former group 2
    with pytest.raises(LookupError):
        g2.segment_ids()  # ordinal 2 no longer exists


def test_append_segment_lands_in_this_group_not_the_next() -> None:
    m = Message.parse(ORU_2OBR)
    g1, g2 = m.groups()
    # A new OBX appended to the FIRST order must land before the second OBR, not drift into it.
    g1.append_segment("OBX|3|NM|PLT^Platelets||250|10*9/L")
    assert g1.segment_ids() == ["OBR", "OBX", "OBX", "OBX"]
    assert g2.segment_ids() == ["OBR", "OBX"]  # untouched
    assert m.segments() == ["MSH", "PID", "OBR", "OBX", "OBX", "OBX", "OBR", "OBX"]
    assert g1.field("OBX-3.1", occurrence=3) == "PLT"
    again = Message.parse(m.encode())
    assert again.segments() == ["MSH", "PID", "OBR", "OBX", "OBX", "OBX", "OBR", "OBX"]


def test_append_to_last_group_goes_to_end() -> None:
    m = Message.parse(ORU_2OBR)
    g2 = m.groups()[1]
    g2.append_segment("OBX|2|NM|TRIG^Triglycerides||120|mg/dL")
    assert g2.segment_ids() == ["OBR", "OBX", "OBX"]
    assert m.segments()[-1] == "OBX"
    assert g2.field("OBX-3.1", occurrence=2) == "TRIG"


def test_rebuild_replaces_body_keeps_boundary_and_siblings() -> None:
    # Per-OBR rebuild: swap one order's OBX block wholesale, leave the OBR and the other order alone.
    m = Message.parse(ORU_2OBR)
    g1, g2 = m.groups()
    g1.rebuild(
        [
            "OBX|1|NM|RBC^Red Cells||4.8|10*12/L",
            "OBX|2|NM|HCT^Hematocrit||42|%",
            "OBX|3|NM|MCV^Mean Cell Vol||90|fL",
        ]
    )
    assert g1.segment_ids() == ["OBR", "OBX", "OBX", "OBX"]
    assert g1.field("OBR-4.1") == "CBC"  # boundary preserved
    assert [g1.field("OBX-3.1", occurrence=i) for i in (1, 2, 3)] == ["RBC", "HCT", "MCV"]
    assert g2.segment_ids() == ["OBR", "OBX"]  # sibling order intact
    assert g2.field("OBX-3.1") == "CHOL"
    again = Message.parse(m.encode())
    assert again.groups()[0].field("OBX-3.1", occurrence=2) == "HCT"
    assert again.groups()[1].field("OBX-3.1") == "CHOL"


def test_rebuild_to_empty_body() -> None:
    m = Message.parse(ORU_2OBR)
    g1 = m.groups()[0]
    g1.rebuild([])  # equivalent to clear()
    assert g1.segment_ids() == ["OBR"]


# --- custom boundary ----------------------------------------------------------

ORU_ORC = (
    "MSH|^~\\&|LAB|LABFAC|EHR|HOSP|20260101||ORU^R01|MSG1|P|2.5.1\r"
    "PID|1||100^^^HOSP^MR||DOE^JANE\r"
    "ORC|RE|PLAC1|FILL1\r"
    "OBR|1|PLAC1|FILL1|CBC^Complete Blood Count\r"
    "OBX|1|NM|WBC^White Cells||7.5|10*9/L\r"
    "ORC|RE|PLAC2|FILL2\r"
    "OBR|2|PLAC2|FILL2|LIPID^Lipid Panel\r"
    "OBX|1|NM|CHOL^Cholesterol||190|mg/dL\r"
)


def test_custom_boundary_orc() -> None:
    m = Message.parse(ORU_ORC)
    # Grouping on ORC pulls the OBR+OBX of each order under one group.
    orc_groups = m.groups(boundary="ORC")
    assert len(orc_groups) == 2
    assert orc_groups[0].segment_ids() == ["ORC", "OBR", "OBX"]
    assert orc_groups[1].segment_ids() == ["ORC", "OBR", "OBX"]
    # The same message grouped on OBR (default) splits differently — boundary choice matters.
    # A group runs to the next SAME-boundary segment, so the first OBR group swallows the trailing
    # ORC (it is not an OBR), demonstrating that only the chosen boundary delimits groups.
    obr_groups = m.groups()
    assert len(obr_groups) == 2
    assert obr_groups[0].segment_ids() == ["OBR", "OBX", "ORC"]
    assert obr_groups[1].segment_ids() == ["OBR", "OBX"]
    assert obr_groups[0].field("OBR-4.1") == "CBC"


def test_custom_boundary_clear_within_orc_group() -> None:
    m = Message.parse(ORU_ORC)
    g1 = m.groups(boundary="ORC")[0]
    g1.clear()  # removes OBR + OBX of the first order, keeps the ORC boundary
    assert g1.segment_ids() == ["ORC"]
    assert m.segments() == ["MSH", "PID", "ORC", "ORC", "OBR", "OBX"]


# --- edge cases ---------------------------------------------------------------


def test_no_boundary_segment_yields_no_groups() -> None:
    m = Message.parse(
        "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\rEVN|A01|20260101\rPID|1||X||DOE\r"
    )
    assert m.groups() == []  # no OBR at all
    assert m.groups(boundary="ORC") == []


def test_single_group() -> None:
    m = Message.parse(
        "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|MSG1|P|2.5.1\r"
        "PID|1||X||DOE\r"
        "OBR|1|P|F|GLU^Glucose\r"
        "OBX|1|NM|GLU^Glucose||100|mg/dL\r"
    )
    groups = m.groups()
    assert len(groups) == 1
    assert groups[0].segment_ids() == ["OBR", "OBX"]
    assert groups[0].field("OBX-5") == "100"


def test_empty_body_group_is_boundary_only() -> None:
    # A boundary with no following members (a bare order) is a group of length 1.
    m = Message.parse(
        "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|MSG1|P|2.5.1\r"
        "PID|1||X||DOE\r"
        "OBR|1|P|F|GLU^Glucose\r"
        "OBR|2|P|F|NA^Sodium\r"
        "OBX|1|NM|NA^Sodium||140|mmol/L\r"
    )
    g1, g2 = m.groups()
    assert g1.segment_ids() == ["OBR"]  # first OBR has no OBX before the next OBR
    assert len(g1) == 1
    assert g1.clear() == 0  # nothing to clear
    assert g1.count("OBX") == 0
    assert g2.segment_ids() == ["OBR", "OBX"]


def test_msh_boundary_refused() -> None:
    m = Message.parse(ORU_2OBR)
    with pytest.raises(ValueError, match="MSH"):
        m.groups(boundary="MSH")


def test_custom_separators_grouping() -> None:
    # Group resolution must read the message's own separators (here component '@'), never |^~\&.
    m = Message.parse(
        "MSH|@#%&|LAB|LABFAC|EHR|HOSP|20260101||ORU^R01|MSG1|P|2.5.1\r"
        "PID|1||X||DOE\r"
        "OBR|1|P|F|CBC@Complete Blood Count\r"
        "OBX|1|NM|WBC@White Cells||7.5\r"
    )
    g1 = m.groups()[0]
    assert g1.segment_ids() == ["OBR", "OBX"]
    assert g1.field("OBR-4.1") == "CBC"  # split on '@', not '^'
    g1.append_segment("OBX|2|NM|HGB@Hemoglobin||14.0")
    assert g1.field("OBX-3.2", occurrence=2) == "Hemoglobin"
    assert Message.parse(m.encode()).groups()[0].field("OBX-3.1", occurrence=2) == "HGB"


def test_appending_to_earlier_group_does_not_stale_later_group_view() -> None:
    # Robustness property: a SegmentGroup re-derives its span on each call, so a NON-deleting edit to
    # an earlier group (which shifts later rows) does not leave a later group's view pointing at the
    # wrong rows. (A delete that removes a whole group re-indexes ordinals — see the dedicated test.)
    m = Message.parse(ORU_2OBR)
    g1, g2 = m.groups()
    g1.append_segment("OBX|3|NM|PLT^Platelets||250|10*9/L")  # shifts g2 down by one row
    assert g2.segment_ids() == ["OBR", "OBX"]  # still correct after the shift
    assert g2.field("OBR-4.1") == "LIPID"
    g1.clear()  # shrink the first order; g2 shifts up, ordinal 2 still exists
    assert g2.field("OBR-4.1") == "LIPID"  # g2 still resolves correctly
