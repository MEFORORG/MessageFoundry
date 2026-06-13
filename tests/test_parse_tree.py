"""HL7 parse-tree builder used by the console viewer."""

from __future__ import annotations

import pytest

from messagefoundry.parsing import HL7PeekError, TreeNode, parse_tree


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
