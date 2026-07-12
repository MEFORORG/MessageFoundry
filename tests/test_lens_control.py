# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Recognition-first lens (ADR 0089 Phase C) — native CONTROL-FLOW idioms render as RECOGNIZED
``control`` rows with a descriptive ``label`` + a captured, READ-ONLY ``operand``, instead of the
UNRECOGNIZED badge.

Two properties, mirroring the ADR 0076/0089 lens tests:

* **Recognition** — each of the four Phase-C forms (``for i in range(1, msg.count_segments("SEG") + 1)``,
  ``if current_environment() in (...)``, ``if msg.field("X") <cmp> ...``, ``if <name>.search(...)``)
  becomes a control row with ``recognized=True`` + the expected label + operand; the control ``kind`` is
  unchanged (structure stays read-only).
* **No false positives** — a plain ``for``/``if``, a ``range()`` not over ``count_segments``, a
  non-``msg.field`` condition, and a ``.search`` that is not an if-guard carry NO label and are never
  mislabeled; the coverage partition still holds on mixed bodies; Phase A recognition + the existing
  ``msg.groups()`` iteration are unchanged.
"""

from __future__ import annotations

import ast
from typing import Any

import pytest

from messagefoundry.lens import parse_source


def _handler_def_ranges(source: str) -> dict[str, tuple[int, int]]:
    """Independently (of the lens) derive each ``@handler`` def body's ``(first_stmt_line, end_line)``."""
    tree = ast.parse(source)
    out: dict[str, tuple[int, int]] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and getattr(dec.func, "id", None) == "handler":
                name = (
                    dec.args[0].value
                    if dec.args and isinstance(dec.args[0], ast.Constant)
                    else node.name
                )
                assert node.end_lineno is not None
                out[name] = (node.body[0].lineno, node.end_lineno)
    return out


def _assert_partition(rows: list[dict[str, Any]], body_start: int, body_end: int) -> None:
    """The rows exactly partition ``[body_start, body_end]`` — ordered, contiguous, non-overlapping."""
    assert rows, "expected at least one row for a non-empty def body"
    assert rows == sorted(rows, key=lambda r: r["line_start"]), "rows must be in source order"
    assert rows[0]["line_start"] == body_start
    assert rows[-1]["line_end"] == body_end
    for prev, nxt in zip(rows, rows[1:], strict=False):
        assert prev["line_end"] + 1 == nxt["line_start"], f"gap/overlap between {prev} and {nxt}"


def _rows(source: str, handler: str) -> list[dict[str, Any]]:
    """Parse ``source``, assert the coverage partition for ``handler``, and return its rows."""
    contract = next(c for c in parse_source(source, module="control.py") if c["handler"] == handler)
    body_start, body_end = _handler_def_ranges(source)[handler]
    _assert_partition(contract["rows"], body_start, body_end)
    return contract["rows"]


def _one_control(header: str, handler: str = "h") -> dict[str, Any]:
    """A handler whose only block is ``header:`` with a ``pass`` body + a trailing send; the header row."""
    src = (
        "from messagefoundry import handler, Send\n\n\n"
        f'@handler("{handler}")\n'
        f"def {handler}(msg):\n"
        f"    {header}:\n"
        "        pass\n"
        '    return Send("OB", msg)\n'
    )
    row = _rows(src, handler)[0]
    assert row["kind"] == "control", f"{header!r} did not project a control row: {row}"
    return row


# --- recognition: the four Phase-C control forms -----------------------------


def test_for_range_count_segments_is_recognized_with_label_and_operand() -> None:
    # Form 1 (the dominant estate loop): for i in range(1, msg.count_segments("SEG") + 1).
    row = _one_control('for i in range(1, msg.count_segments("OBX") + 1)')
    assert row["control"] == "for"
    assert row["recognized"] is True
    assert row["label"] == "for each OBX segment"
    assert row["operand"] == "OBX"


def test_environment_gate_membership_is_recognized() -> None:
    # Form 2: if current_environment() in (...) -> environment gate, operand = the values.
    row = _one_control('if current_environment() in ("prod", "staging")')
    assert row["control"] == "if"
    assert row["recognized"] is True
    assert row["label"] == "environment gate"
    assert row["operand"] == ["prod", "staging"]


def test_environment_gate_equality_is_recognized() -> None:
    # Form 2 with `== "x"` -> the single value captured as a one-element list.
    row = _one_control('if current_environment() == "prod"')
    assert row["recognized"] is True
    assert row["label"] == "environment gate"
    assert row["operand"] == ["prod"]


def test_field_condition_is_recognized_with_path_operand() -> None:
    # Form 3: if msg.field("X") <cmp> ... -> "when field X", operand = the field path.
    row = _one_control('if msg.field("PID-8") == "M"')
    assert row["control"] == "if"
    assert row["recognized"] is True
    assert row["label"] == "when field PID-8"
    assert row["operand"] == "PID-8"


def test_field_condition_bare_truthiness_is_recognized() -> None:
    # A bare `if msg.field("X"):` truthiness test is also a field condition.
    row = _one_control('if msg.field("PV1-44")')
    assert row["label"] == "when field PV1-44"
    assert row["operand"] == "PV1-44"


def test_regex_filter_guard_is_recognized() -> None:
    # Form 4: if <name>.search(...) -> filter guard (no single key operand).
    row = _one_control("if MRN_RE.search(mrn)")
    assert row["control"] == "if"
    assert row["recognized"] is True
    assert row["label"] == "filter guard"
    assert row["operand"] is None


@pytest.mark.parametrize(
    "header",
    [
        "if not MRN_RE.match(mrn)",  # negated guard (paired with return None)
        "if MRN_RE.fullmatch(mrn) is None",  # `is None` comparison guard
        "if re.search(pat, value)",  # module-qualified re.search
    ],
)
def test_regex_guard_variants_are_recognized(header: str) -> None:
    row = _one_control(header)
    assert row["recognized"] is True
    assert row["label"] == "filter guard"


# --- no false positives ------------------------------------------------------


def test_plain_range_for_is_not_recognized() -> None:
    # A plain counting loop (not over msg.count_segments) stays UNRECOGNIZED, no label.
    row = _one_control("for i in range(3)")
    assert row["recognized"] is False
    assert row["label"] is None
    assert row["operand"] is None


def test_range_over_len_is_not_a_segment_loop() -> None:
    # range(1, len(items) + 1) has the same 1..n+1 shape but is NOT over msg.count_segments -> unrecognized.
    row = _one_control("for i in range(1, len(items) + 1)")
    assert row["recognized"] is False
    assert row["label"] is None


def test_range_count_wrong_lower_bound_is_not_matched() -> None:
    # range(0, msg.count_segments("OBX")) is a different shape -> not the recognized form.
    row = _one_control('for i in range(0, msg.count_segments("OBX"))')
    assert row["recognized"] is False
    assert row["label"] is None


def test_non_field_bare_call_condition_is_unrecognized() -> None:
    # A bare function-call condition (not msg.field, not current_environment, not a regex guard) is not
    # bounded and carries no Phase-C label -> stays UNRECOGNIZED.
    row = _one_control("if should_drop(msg)")
    assert row["recognized"] is False
    assert row["label"] is None


def test_non_msg_field_receiver_is_not_a_field_gate() -> None:
    # other.field("X") is NOT a msg field read -> no "when field" label (though it may be bounded).
    row = _one_control('if other.field("X") == "M"')
    assert row["label"] is None
    assert row["operand"] is None


def test_search_lookalike_attribute_is_not_a_guard() -> None:
    # `.search_index` is an attribute, not a `.search(...)` call -> not a filter guard. It IS a bounded
    # comparison (recognized pre-Phase-C), but must NOT be mislabeled as a guard.
    row = _one_control("if obj.search_index > 0")
    assert row["label"] is None


def test_search_call_outside_an_if_is_not_a_control_row() -> None:
    # A `.search` used as an assignment value is a plain (code) row, never a labeled filter guard.
    src = (
        "from messagefoundry import handler, Send\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        "    m = MRN_RE.search(mrn)\n"
        '    return Send("OB", msg)\n'
    )
    rows = _rows(src, "h")
    assert rows[0]["kind"] == "code"
    assert "label" not in rows[0]


# --- Phase A + existing iteration unchanged; mixed-body partition ------------


def test_msg_groups_iteration_still_recognized_without_a_label() -> None:
    # The existing native iteration recognition (ADR 0089 Phase A) is unchanged: recognized, no Phase-C
    # label/operand (KEEP unchanged per the ADR).
    row = _one_control("for seg in msg.groups('OBX')")
    assert row["control"] == "for"
    assert row["recognized"] is True
    assert row["label"] is None
    assert row["operand"] is None


def test_bounded_subscript_if_still_recognized_without_a_label() -> None:
    # A bounded msg[...] comparison (recognized pre-Phase-C via _is_bounded) stays recognized and, because
    # it is not one of the four native forms, carries no Phase-C label.
    row = _one_control('if msg["MSH-9.1"] == "ADT"')
    assert row["recognized"] is True
    assert row["label"] is None


MIXED = """\
from messagefoundry import handler, Send


@handler("mixed")
def mixed(msg):
    if current_environment() in ("prod",):
        msg.set("MSH-11.1", "P")
    for i in range(1, msg.count_segments("OBX") + 1):
        msg.set("OBX-1", str(i), occurrence=i)
    if msg.field("PID-8") == "M":
        msg.set("PID-8", "Male")
    if RE.search(msg.field("PID-3.1")):
        msg.delete_segments("Z01")
    return Send("OB", msg)
"""


def test_mixed_control_body_partitions_and_labels() -> None:
    rows = _rows(MIXED, "mixed")
    summary = [
        (
            r["kind"],
            r.get("label") or r.get("action"),
            r["recognized"] if r["kind"] == "control" else None,
            r["nesting"],
        )
        for r in rows
    ]
    assert summary == [
        ("control", "environment gate", True, 0),
        ("action", "set_field", None, 1),
        ("control", "for each OBX segment", True, 0),
        ("action", "set_field", None, 1),
        ("control", "when field PID-8", True, 0),
        ("action", "set_field", None, 1),
        ("control", "filter guard", True, 0),
        ("action", "delete_segment", None, 1),
        ("send", None, None, 0),
    ]
    # operands captured for display (read-only).
    assert rows[0]["operand"] == ["prod"]
    assert rows[2]["operand"] == "OBX"
    assert rows[4]["operand"] == "PID-8"
