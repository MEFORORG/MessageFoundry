# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""HL7 parse-tree builder used by the console viewer."""

from __future__ import annotations

import pytest

from messagefoundry.parsing import HL7PeekError, TreeNode, _builtin_hl7, parse_tree
from messagefoundry.parsing.tree import (
    MAX_TREE_NODES,
    MAX_TREE_VALUE_CHARS,
    ParseTreeTooLargeError,
)


def _find(nodes: list[TreeNode], label: str) -> TreeNode:
    for n in nodes:
        if n.label == label:
            return n
    raise AssertionError(f"no node {label!r}")


ADT = "MSH|^~\\&|APP|FAC|RAPP|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE^Q\r"


def test_top_level_is_segments() -> None:
    tree = parse_tree(ADT)
    assert [n.label for n in tree] == ["MSH", "PID"]


def test_msh_1_and_2_are_literal_fields() -> None:
    msh = _find(parse_tree(ADT), "MSH")
    assert _find(msh.children, "MSH-1").value == "|"
    assert _find(msh.children, "MSH-2").value == "^~\\&"
    # Numbering continues at 3, aligned with the spec.
    assert _find(msh.children, "MSH-3").value == "APP"


def test_field_with_components_expands() -> None:
    msh = _find(parse_tree(ADT), "MSH")
    msh9 = _find(msh.children, "MSH-9")
    assert [c.label for c in msh9.children] == ["MSH-9.1", "MSH-9.2"]
    assert _find(msh9.children, "MSH-9.1").value == "ADT"
    assert _find(msh9.children, "MSH-9.2").value == "A01"


def test_atomic_field_is_a_leaf() -> None:
    msh = _find(parse_tree(ADT), "MSH")
    msh10 = _find(msh.children, "MSH-10")
    assert msh10.value == "MSG1"
    assert msh10.children == []


def test_subcomponents_expand() -> None:
    raw = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5\rPID|||a&b&c\r"
    pid3 = _find(_find(parse_tree(raw), "PID").children, "PID-3")
    # one component with three subcomponents
    comp = _find(pid3.children, "PID-3.1")
    assert [s.label for s in comp.children] == ["PID-3.1.1", "PID-3.1.2", "PID-3.1.3"]
    assert [s.value for s in comp.children] == ["a", "b", "c"]


def test_repetitions_expand_with_index() -> None:
    raw = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5\rPID|||X^1~Y^2\r"
    pid3 = _find(_find(parse_tree(raw), "PID").children, "PID-3")
    assert [c.label for c in pid3.children] == ["PID-3[1]", "PID-3[2]"]
    assert _find(pid3.children[0].children, "PID-3[1].1").value == "X"


def test_empty_message_raises() -> None:
    with pytest.raises(HL7PeekError):
        parse_tree("   ")


def test_non_msh_raises() -> None:
    with pytest.raises(HL7PeekError):
        parse_tree("PID|||x")


def _count(nodes: list[TreeNode]) -> int:
    return sum(1 + _count(n.children) for n in nodes)


# --- vault BACKLOG #2762: the node cap and the MSH-2 read --------------------


def test_a_tree_at_the_cap_builds_and_one_past_it_is_refused() -> None:
    # The cap counts every node, so a tree of exactly max_nodes builds and the next node refuses.
    size = _count(parse_tree(ADT))
    assert _count(parse_tree(ADT, max_nodes=size)) == size
    with pytest.raises(ParseTreeTooLargeError, match=f"more than {size - 1:,} nodes") as ei:
        parse_tree(ADT, max_nodes=size - 1)
    # A subclass of HL7PeekError, so a caller that knows only that error still degrades.
    assert isinstance(ei.value, HL7PeekError)


def test_one_field_of_component_separators_is_refused_at_the_default_cap() -> None:
    # One segment, a few bytes per node: the byte and segment caps let it through, the node cap
    # does not. The control below the cap builds.
    head = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5\rPID|1||"
    below = parse_tree(head + "^" * (MAX_TREE_NODES // 2))
    assert _count(below) <= MAX_TREE_NODES
    with pytest.raises(ParseTreeTooLargeError):
        parse_tree(head + "^" * MAX_TREE_NODES)
    with pytest.raises(ParseTreeTooLargeError):
        parse_tree(head + "&" * MAX_TREE_NODES)  # the subcomponent arm
    with pytest.raises(ParseTreeTooLargeError):
        parse_tree(head + "~" * MAX_TREE_NODES)  # the repetition arm


def test_a_few_large_fields_are_refused_on_value_size() -> None:
    # A node keeps its own raw text, so one large component field is held twice (field and
    # component) with only a handful of nodes; the node cap alone would let it through.
    head = "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|1|P|2.5\rOBX|1|ED|X||"
    doc = "^AP^PDF^Base64^" + "Q" * 1000
    held = _count(parse_tree(head + doc))
    assert held < 30
    with pytest.raises(ParseTreeTooLargeError, match="characters of labels and values"):
        parse_tree(head + doc, max_value_chars=1500)
    parse_tree(head + doc, max_value_chars=2400)  # control: field + component fit
    with pytest.raises(ParseTreeTooLargeError, match="characters of labels and values"):
        parse_tree(head + "^" + '"' * (MAX_TREE_VALUE_CHARS // 2 + 1))


def test_a_long_segment_id_is_counted_in_every_label() -> None:
    # Every label repeats the segment id, so a long id over many fields would hold the id once per
    # node: 200 fields of a 100,000-character id is 20 million characters from a 100 KB body.
    raw = "MSH|^~\\&|A\r" + "Z" * 100_000 + "|" * 200
    with pytest.raises(ParseTreeTooLargeError, match="characters of labels and values"):
        parse_tree(raw)


def test_the_byte_and_segment_caps_also_read_as_too_large() -> None:
    with pytest.raises(ParseTreeTooLargeError, match="max segments"):
        parse_tree("MSH|^~\\&|A\r" + "NTE|1\r" * 10_000)
    # A large body that is not HL7 at all still reads as not HL7.
    with pytest.raises(HL7PeekError, match="does not start with an MSH") as ei:
        parse_tree("ISA*00\r" * 10_001)
    assert not isinstance(ei.value, ParseTreeTooLargeError)


def test_msh_2_ends_at_the_next_field_separator() -> None:
    # MSH-2 is "^~" here and "A" is MSH-3, as the parser reads it; a fixed msh[4:8] slice took
    # "A" as the subcomponent separator, so "xAy" split.
    raw = "MSH|^~|A|B|C|D|20260101||ADT^A01|1|P|2.5\rPID|||xAy&z\r"
    tree = parse_tree(raw)
    msh = _find(tree, "MSH")
    assert _find(msh.children, "MSH-2").value == "^~"
    assert _find(msh.children, "MSH-3").value == "A"
    pid3 = _find(_find(tree, "PID").children, "PID-3")
    assert [s.value for s in _find(pid3.children, "PID-3.1").children] == ["xAy", "z"]
    # The parser reads the same header the same way: subcomponent "&" by default.
    assert _builtin_hl7.parse(raw)["seps"] == ("|", "^", "~", "&", "\\")


def test_a_header_too_short_for_the_parser_still_renders() -> None:
    assert [n.label for n in _find(parse_tree("MSH|"), "MSH").children] == ["MSH-1", "MSH-2"]
