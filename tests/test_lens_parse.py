# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The static Steps view (ADR 0076 §3–§4) — coverage-partition property (gate 1) + static-only
(gate 4), over every ``samples/config`` handler plus adversarial hand-written handlers."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.lens import LensParseError, parse_module, parse_source

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples" / "config"


# --- the coverage invariant (gate 1) ----------------------------------------


def _handler_def_ranges(source: str) -> dict[str, tuple[int, int]]:
    """Independently (of the lens) derive each ``@handler`` def body's ``(first_stmt_line, end_line)``."""
    tree = ast.parse(source)
    out: dict[str, tuple[int, int]] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and getattr(dec.func, "id", None) == "handler":
                if dec.args and isinstance(dec.args[0], ast.Constant):
                    name = dec.args[0].value
                else:
                    name = node.name
                assert node.end_lineno is not None
                out[name] = (node.body[0].lineno, node.end_lineno)
    return out


def _assert_partition(rows: list[dict[str, Any]], body_start: int, body_end: int) -> None:
    """The rows exactly partition ``[body_start, body_end]``: ordered, contiguous, non-overlapping,
    covering every line exactly once — nothing dropped, reordered, or synthesized."""
    assert rows, "expected at least one row for a non-empty def body"
    assert rows == sorted(rows, key=lambda r: r["line_start"]), "rows must be in source order"
    assert rows[0]["line_start"] == body_start
    assert rows[-1]["line_end"] == body_end
    for row in rows:
        assert row["line_start"] <= row["line_end"], f"degenerate range: {row}"
        assert row["nesting"] >= 0
    for prev, nxt in zip(rows, rows[1:], strict=False):
        assert prev["line_end"] + 1 == nxt["line_start"], f"gap/overlap between {prev} and {nxt}"


@pytest.mark.parametrize("module", sorted(SAMPLES.glob("*.py")), ids=lambda p: p.name)
def test_samples_partition(module: Path) -> None:
    source = module.read_text(encoding="utf-8")
    ranges = _handler_def_ranges(source)
    contracts = parse_module(module)
    # Every @handler in the file appears exactly once (routers excluded).
    assert sorted(c["handler"] for c in contracts) == sorted(ranges)
    for contract in contracts:
        body_start, body_end = ranges[contract["handler"]]
        _assert_partition(contract["rows"], body_start, body_end)
        assert contract["def_line"] >= 1
        assert contract["module"] == module.as_posix()


# --- adversarial handlers ----------------------------------------------------


def _rows(source: str, handler: str) -> list[dict[str, Any]]:
    """Parse ``source``, assert the coverage partition for ``handler``, and return its rows."""
    contracts = parse_source(source, module="adversarial.py")
    contract = next(c for c in contracts if c["handler"] == handler)
    body_start, body_end = _handler_def_ranges(source)[handler]
    _assert_partition(contract["rows"], body_start, body_end)
    return contract["rows"]


MIXED = """\
from messagefoundry import handler, Send, copy_field, set_field, format_date


@handler("mixed")
def mixed(msg):
    copy_field(msg, "PID-5.1", "NK1-2.1")
    x = compute_something(msg)
    set_field(msg, "PID-3.1", "NEW")
    # a standalone hand-written comment
    format_date(msg, "PID-7", "%Y-%m-%d")
    return Send("OB_X", msg)
"""


def test_mixed_recognized_and_unrecognized() -> None:
    rows = _rows(MIXED, "mixed")
    kinds = [(r["kind"], r.get("action") or r.get("call")) for r in rows]
    assert kinds == [
        ("action", "copy_field"),
        ("code", None),  # x = compute_something(msg) — one hand-written line, in place
        ("action", "set_field"),
        ("code", None),  # the standalone comment
        ("action", "format_date"),
        ("send", None),
    ]
    # A single unrecognized line does NOT eject the whole handler from the lens (degradation ladder).
    copy = rows[0]
    assert copy["params"] == {"src": "PID-5.1", "dst": "NK1-2.1"}  # msg dropped; literals rendered
    assert rows[-1]["outbounds"] == ["OB_X"]


NESTED = """\
from messagefoundry import handler, Send, set_field, delete_segment


@handler("nested")
def nested(msg):
    if msg["MSH-9.1"] == "ADT":
        for grp in msg.groups("OBR"):
            set_field(msg, "OBR-1", "1")
    else:
        delete_segment(msg, "ZZZ")
    return Send("OB_Y", msg)
"""


def test_nested_if_for_else() -> None:
    rows = _rows(NESTED, "nested")
    summary = [
        (r["kind"], r.get("control") or r.get("action") or r.get("call"), r["nesting"])
        for r in rows
    ]
    assert summary == [
        ("control", "if", 0),
        ("control", "for", 1),
        ("action", "set_field", 2),
        ("control", "else", 0),
        ("action", "delete_segment", 1),
        ("send", None, 0),
    ]
    # the for over msg.groups(...) is a recognized Message iteration
    for_row = rows[1]
    assert for_row["recognized"] is True
    assert rows[0]["recognized"] is True  # bounded `msg[...] == "ADT"` test


def test_unrecognized_control_still_shows_structure() -> None:
    src = """\
from messagefoundry import handler, Send


@handler("weird_loop")
def weird_loop(msg):
    for i in range(3):
        pass
    return Send("OB_Z", msg)
"""
    rows = _rows(src, "weird_loop")
    for_row = rows[0]
    assert for_row["kind"] == "control"
    assert for_row["control"] == "for"
    assert for_row["recognized"] is False  # not a Message iteration -> flagged, structure preserved


LOOKUPS = """\
from messagefoundry import handler, Send, code_lookup, db_lookup


@handler("lookups")
def lookups(msg):
    code_lookup(msg, "PID-8", GENDER, default="U")
    row = db_lookup("MPI", "select 1", {"id": msg["PID-3.1"]})
    return Send("OB_L", msg)
"""


def test_lookup_rows() -> None:
    rows = _rows(LOOKUPS, "lookups")
    code_lk, db_lk, send = rows
    assert code_lk["kind"] == "lookup"
    assert code_lk["call"] == "code_lookup"
    assert code_lk["params"] == {"path": "PID-8", "table": "GENDER", "default": "U"}
    assert db_lk["kind"] == "lookup"
    assert db_lk["call"] == "db_lookup"
    assert db_lk["assign_to"] == "row"
    assert db_lk["params"]["connection"] == "MPI"
    assert db_lk["params"]["statement"] == "select 1"
    assert send["kind"] == "send"


def test_literal_params_flag_marks_only_constant_args() -> None:
    # F6: `lens parse` emits `literal_params` — the subset of params whose arg is a Python literal — so
    # the IDE offers ONLY those as editable (an expression/list slot always refuses a scalar edit).
    code_lk, db_lk, _send = _rows(LOOKUPS, "lookups")
    # code_lookup(msg, "PID-8", GENDER, default="U"): path + default are literals; table (GENDER) is not.
    assert code_lk["literal_params"] == ["path", "default"]
    # db_lookup("MPI", "select 1", {"id": msg[...]}): connection + statement literal; params (a dict) not.
    assert db_lk["literal_params"] == ["connection", "statement"]

    # An action: copy_field's two literal path args are both flagged.
    copy = _rows(MIXED, "mixed")[0]
    assert copy["action"] == "copy_field"
    assert copy["literal_params"] == ["src", "dst"]

    # split_field(..., dests=[...]) — the list arg is an expression (ast.List), so NOT a literal param.
    split_src = """\
from messagefoundry import handler, Send, split_field


@handler("h")
def h(msg):
    split_field(msg, "PID-5", "^", ["PID-5.1", "PID-5.2"])
    return Send("OB", msg)
"""
    split_row = _rows(split_src, "h")[0]
    assert split_row["action"] == "split_field"
    assert split_row["literal_params"] == ["src", "sep"]  # dests excluded


ELIF_CHAIN = """\
from messagefoundry import handler, Send, set_field


@handler("chain")
def chain(msg):
    if msg["PID-8"] == "M":
        set_field(msg, "PID-8", "Male")
    elif msg["PID-8"] == "F":
        set_field(msg, "PID-8", "Female")
    else:
        set_field(msg, "PID-8", "U")
    return Send("OB_C", msg)
"""


def test_elif_else_chain() -> None:
    rows = _rows(ELIF_CHAIN, "chain")
    kinds = [(r["kind"], r.get("control") or r.get("action")) for r in rows]
    assert kinds == [
        ("control", "if"),
        ("action", "set_field"),
        ("control", "elif"),
        ("action", "set_field"),
        ("control", "else"),
        ("action", "set_field"),
        ("send", None),
    ]
    assert rows[4]["test_src"] is None  # else has no test


def test_list_of_sends_outbounds() -> None:
    src = """\
from messagefoundry import handler, Send


@handler("fanout")
def fanout(msg):
    return [Send("OB_A", msg), Send("OB_B", msg)]
"""
    rows = _rows(src, "fanout")
    assert rows[0]["kind"] == "send"
    assert rows[0]["outbounds"] == ["OB_A", "OB_B"]


def test_return_none_is_a_code_row() -> None:
    src = """\
from messagefoundry import handler


@handler("filtered")
def filtered(msg):
    return None
"""
    rows = _rows(src, "filtered")
    assert len(rows) == 1
    assert rows[0]["kind"] == "code"  # `return None` (filter) is not a Send -> code row


# --- semicolon-compound & inline suites (statements sharing ONE physical line) -----------------------
# Each shape below puts >1 statement on ONE line (a ``;``-compound line, or an inline ``if x: y`` suite).
# The bounded grammar does not cover these, so each run of shared-line statements must degrade to a
# SINGLE in-place ``code`` row — otherwise the emitted rows double-count the shared physical line and the
# coverage partition (ADR 0076 §6 gate 1) breaks. All FAIL before the ``_partition_suite`` coalescing fix
# (they emit overlapping rows) and pass after. ``_rows`` asserts the full partition (order + contiguity +
# non-overlap + full coverage) on every one.

SEMI_TWO_ACTIONS = """\
from messagefoundry import handler, Send, set_field


@handler("semi_two_actions")
def semi_two_actions(msg):
    set_field(msg, "A", "1"); set_field(msg, "B", "2")
    return Send("OB", msg)
"""

SEMI_TWO_ASSIGNS = """\
from messagefoundry import handler, Send


@handler("semi_two_assigns")
def semi_two_assigns(msg):
    x = 1; y = 2
    return Send("OB", msg)
"""

SEMI_NESTED_BODY = """\
from messagefoundry import handler, Send


@handler("semi_nested_body")
def semi_nested_body(msg):
    if msg["A"]:
        a(msg); b(msg)
    return Send("OB", msg)
"""

SEMI_ACTION_THEN_SEND = """\
from messagefoundry import handler, Send, set_field


@handler("semi_action_then_send")
def semi_action_then_send(msg):
    set_field(msg, "A", "1"); return Send("OB", msg)
"""

SEMI_SEND_THEN_CODE = """\
from messagefoundry import handler, Send


@handler("semi_send_then_code")
def semi_send_then_code(msg):
    return Send("OB", msg); x = 1
"""

INLINE_IF = """\
from messagefoundry import handler, Send, set_field


@handler("inline_if")
def inline_if(msg):
    if msg["A"]: set_field(msg, "A", "1")
    return Send("OB", msg)
"""

MIXED_SEMI_SEND = """\
from messagefoundry import handler, Send, copy_field, set_field


@handler("mixed_semi_send")
def mixed_semi_send(msg):
    copy_field(msg, "PID-5.1", "NK1-2.1")
    set_field(msg, "A", "1"); return Send("OB", msg)
"""


@pytest.mark.parametrize(
    ("src", "handler_name", "expected_kinds"),
    [
        # set_field(...); set_field(...) -> ONE code row (was [action 6-6][action 6-6] overlap)
        (SEMI_TWO_ACTIONS, "semi_two_actions", ["code", "send"]),
        # x = 1; y = 2 -> ONE code row (was [code 6-6][code 6-6] overlap)
        (SEMI_TWO_ASSIGNS, "semi_two_assigns", ["code", "send"]),
        # nested a(msg); b(msg) -> control header + ONE nested code row (was [action][action] overlap)
        (SEMI_NESTED_BODY, "semi_nested_body", ["control", "code", "send"]),
        # set_field(...); return Send(...) -> ONE code row (was [action 6-6][send 6-6] overlap)
        (SEMI_ACTION_THEN_SEND, "semi_action_then_send", ["code"]),
        # return Send(...); x = 1 -> ONE code row (was [send 7-7][code 7-7] overlap)
        (SEMI_SEND_THEN_CODE, "semi_send_then_code", ["code"]),
        # inline `if x: y` -> ONE code row for the whole header+body line
        (INLINE_IF, "inline_if", ["code", "send"]),
        # a clean recognized action, then `action; return Send` sharing a line -> [action][code]
        (MIXED_SEMI_SEND, "mixed_semi_send", ["action", "code"]),
    ],
)
def test_shared_line_statements_coalesce_to_one_code_row(
    src: str, handler_name: str, expected_kinds: list[str]
) -> None:
    # `_rows` re-runs `_assert_partition` (order + contiguity + NON-OVERLAP + full coverage) — the shape
    # that broke before the fix.
    rows = _rows(src, handler_name)
    assert [r["kind"] for r in rows] == expected_kinds
    # Belt-and-suspenders for the phase-3 splice concern: no two rows own the same physical line.
    covered: set[int] = set()
    for row in rows:
        lines = set(range(row["line_start"], row["line_end"] + 1))
        assert not (covered & lines), (
            f"{handler_name}: rows share a physical line ({sorted(covered & lines)})"
        )
        covered |= lines


# --- static-only (gate 4) ----------------------------------------------------


def test_static_only_module_with_toplevel_raise_still_parses() -> None:
    # A module whose top level would RAISE at import must still parse — proving the lens never imports
    # or executes the config module (ADR 0076 §5, gate 4).
    src = """\
from messagefoundry import handler, Send

raise RuntimeError("this would abort at import time")


@handler("survivor")
def survivor(msg):
    return Send("OB_S", msg)
"""
    contracts = parse_source(src, module="raises.py")
    assert [c["handler"] for c in contracts] == ["survivor"]
    assert contracts[0]["rows"][0]["kind"] == "send"


def test_static_only_unresolvable_imports_still_parse() -> None:
    # References to symbols that don't exist / can't import are irrelevant to a static parse.
    src = """\
from this_package_does_not_exist import mystery


@handler("uses_missing")
def uses_missing(msg):
    mystery(msg)
    return Send("OB_M", msg)
"""
    contracts = parse_source(src, module="badimports.py")
    assert [c["handler"] for c in contracts] == ["uses_missing"]


def test_unparseable_file_is_a_lens_refusal() -> None:
    with pytest.raises(LensParseError):
        parse_source("def broken(:\n    pass\n", module="broken.py")


def test_routers_are_out_of_scope() -> None:
    src = """\
from messagefoundry import router, handler, Send


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_H", msg)
"""
    contracts = parse_source(src, module="mixed_router.py")
    assert [c["handler"] for c in contracts] == ["h"]  # router excluded


def test_module_with_no_handlers_returns_empty() -> None:
    contracts = parse_source("x = 1\n", module="empty.py")
    assert contracts == []


# --- Corepoint import round-trip (ADR 0086 AC-4) -----------------------------


def test_generated_handler_round_trips_through_lens(tmp_path: Path) -> None:
    """A ``messagefoundry import corepoint`` module round-trips through the lens with no whole-file
    refusal: every mapped vocabulary call classifies into an ``action``/``lookup`` row, the return into
    a ``send`` row, and an unmapped-action TODO stub degrades in place to a ``code`` row (ADR 0086 AC-4;
    the correctness gate that closes the import ↔ lens loop)."""
    from messagefoundry.corepoint_import import import_corepoint

    fixture = REPO_ROOT / "tests" / "fixtures" / "corepoint" / "acme_adt.json"
    import_corepoint(fixture, tmp_path)
    module = tmp_path / "IB_ACME_ADT.py"

    contracts = parse_module(
        module
    )  # raises LensParseError on a whole-file refusal — none expected
    assert [c["handler"] for c in contracts] == ["acme_adt_transform"]
    rows = contracts[0]["rows"]
    kinds = [r["kind"] for r in rows]

    # The nine mapped vocabulary calls become eight action rows + one lookup row (code_lookup).
    actions = [r for r in rows if r["kind"] == "action"]
    assert {r["action"] for r in actions} == {
        "copy_field",
        "set_field",
        "append_to_field",
        "format_date",
        "convert_case",
        "split_field",
        "copy_segment",
        "delete_segment",
    }
    assert [r["call"] for r in rows if r["kind"] == "lookup"] == ["code_lookup"]
    # The unmapped ItemCustomScript TODO + stub is exactly one in-place code row, never a refusal.
    assert kinds.count("code") == 1
    # The handler still ends in a recognized send row.
    sends = [r for r in rows if r["kind"] == "send"]
    assert sends and sends[-1]["outbounds"] == ["OB_ACME_ADT"]
