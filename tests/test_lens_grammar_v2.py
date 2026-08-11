# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The CONTRACT_V2 Steps grammar — the ``note`` kind (ADR 0076 Amendment A, BACKLOG #248) and the
``route`` kind + ``@router`` projection (Amendment D, BACKLOG #232).

Four invariants are asserted here as build gates rather than described as caveats:

1. **The coverage partition is total** — every source line of a def body maps to exactly ONE row, over
   the real ``samples/config`` corpus and an adversarial one, for handlers AND routers.
2. **The splice is byte-stable** — parse then rewrite with no effective change returns the file
   byte-identically, including through the two new op classes (note text, route handler list).
3. **The ``.py`` stays the only artifact and the only execution path** — the lens writes no sidecar and
   never imports or executes the module; a route edit produces Python, not a declarative artifact.
4. **Contract-version skew is handled** — an older consumer asking for CONTRACT_V1 never receives a v2
   kind, and a newer consumer asking for a version this parser cannot emit gets a clean refusal.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.lens import (
    CONTRACT_LATEST,
    CONTRACT_V1,
    CONTRACT_V2,
    LensParseError,
    LensRewriteError,
    parse_module,
    parse_source,
    rewrite_module,
    rewrite_source,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples" / "config"
#: The sample modules that actually declare elements. ``_``-prefixed files are shared transform helpers
#: the loader skips (CLAUDE.md §4), so they project nothing — excluded here so a per-module
#: "this scan saw something" guard means what it says instead of firing on an empty helper.
ELEMENT_MODULES = [p for p in sorted(SAMPLES.glob("*.py")) if not p.name.startswith("_")]

#: The row kinds the shipped (pre-amendment) contract could emit. A CONTRACT_V1 payload must never carry
#: anything outside this set — that is the whole "an older IDE cannot meet a kind it cannot render" story.
V1_KINDS = frozenset({"action", "lookup", "control", "send", "diagnostic", "code"})


# --- an INDEPENDENT derivation of each def body's line range ------------------
#
# Deliberately NOT `lens._body_end`: the coverage test must tile a range it derived for itself, else it
# only proves the parser agrees with itself.


def _decorator_name(node: ast.FunctionDef | ast.AsyncFunctionDef, want: str) -> str | None:
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        func = dec.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        if name != want:
            continue
        if (
            dec.args
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            return dec.args[0].value
        return node.name
    return None


def _element_ranges(source: str, *, contract: int) -> dict[str, tuple[int, int]]:
    """``{registered name: (first_body_line, last_body_line)}`` for every projectable element."""
    lines = source.splitlines()
    tree = ast.parse(source)
    out: dict[str, tuple[int, int]] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        name = _decorator_name(node, "handler")
        if name is None and contract >= CONTRACT_V2:
            name = _decorator_name(node, "router")
        if name is None:
            continue
        assert node.end_lineno is not None
        start, end = node.body[0].lineno, node.end_lineno
        if contract >= CONTRACT_V2:
            body_indent = len(lines[start - 1]) - len(lines[start - 1].lstrip())
            for lineno in range(end + 1, len(lines) + 1):
                text = lines[lineno - 1]
                if not text.strip():
                    continue
                if not text.strip().startswith("#"):
                    break
                if len(text) - len(text.lstrip()) < body_indent:
                    break
                end = lineno
        out[name] = (start, end)
    return out


def _assert_total_partition(rows: list[dict[str, Any]], lo: int, hi: int) -> None:
    """Every line in ``[lo, hi]`` is covered by EXACTLY one row, in order, with no gap or overlap."""
    assert rows, "expected at least one row for a non-empty def body"
    seen: Counter[int] = Counter()
    for row in rows:
        assert row["line_start"] <= row["line_end"], f"degenerate range: {row}"
        seen.update(range(row["line_start"], row["line_end"] + 1))
    doubled = sorted(ln for ln, n in seen.items() if n > 1)
    assert not doubled, f"lines covered by more than one row: {doubled}"
    assert sorted(seen) == list(range(lo, hi + 1)), (
        f"rows cover {sorted(seen)[:3]}..{sorted(seen)[-3:]}, expected {lo}..{hi}"
    )
    assert rows == sorted(rows, key=lambda r: r["line_start"]), "rows must be in source order"


def _rows(source: str, element: str, *, contract: int = CONTRACT_V2) -> list[dict[str, Any]]:
    """Parse, assert the total coverage partition, and return one element's rows."""
    contracts = parse_source(source, module="adversarial.py", contract=contract)
    contract_entry = next(c for c in contracts if c["handler"] == element)
    lo, hi = _element_ranges(source, contract=contract)[element]
    _assert_total_partition(contract_entry["rows"], lo, hi)
    return contract_entry["rows"]


def _only(rows: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [r for r in rows if r["kind"] == kind]


# --- fixtures ----------------------------------------------------------------

HANDLER_PREAMBLE = "from messagefoundry import Send, handler\n\n\n"
ROUTER_PREAMBLE = "from messagefoundry import router\n\n\n"

TRAILING_COMMENT = (
    HANDLER_PREAMBLE
    + '@handler("h")\ndef h(msg):\n    msg.set("PID-3.1", "X")\n    # a trailing note\n'
)

ADJACENT_COMMENT = (
    HANDLER_PREAMBLE + '@handler("h")\ndef h(msg):\n    total = compute()\n    # an adjacent note\n'
    '    msg.set("PID-3.1", str(total))\n'
)

LEADING_IN_BLOCK = (
    HANDLER_PREAMBLE
    + '@handler("h")\ndef h(msg):\n    if msg["MSH-9.1"] == "ADT":\n        # why we do this\n'
    '        msg.set("PID-3.1", "X")\n'
)

NOTE_CORPUS = (
    HANDLER_PREAMBLE + '@handler("wide")\n'
    "def wide(msg):\n"
    '    """The docstring is a statement, not a note."""\n'
    "    # first prose line\n"
    "    # second prose line\n"
    "\n"
    "    # noqa: E501\n"
    "    ## a banner\n"
    '    msg.set("PID-3.1", "X")  # a trailing comment stays inside the action row\n'
    '    if msg["MSH-9.1"] == "ADT":\n'
    "        # a note leading a block body\n"
    '        msg.set("PID-3.2", "Y")\n'
    "        # a note trailing a block body\n"
    "    else:\n"
    "        # a note leading an else body\n"
    "        return []\n"
    "    # a note after the last statement\n"
)

ROUTER_CORPUS = (
    ROUTER_PREAMBLE + '@router("wide")\n'
    "def wide(msg):\n"
    "    # a routing note\n"
    '    if msg["MSH-9.1"] == "ORU":\n'
    '        return ["oru_relay", "oru_archive"]\n'
    '    if msg["MSH-9.1"] == "ADT":\n'
    '        return "adt_relay"\n'
    '    if msg.count_segments("OBX") > 3:\n'
    "        return [pick(msg)]\n"
    '    if msg.count_segments("NK1") > 0:\n'
    "        return\n"
    '    if msg.count_segments("PV1") > 0:\n'
    "        return None\n"
    "    return []\n"
)


# =============================================================================
# INVARIANT 1 — the coverage partition is TOTAL
# =============================================================================


@pytest.mark.parametrize("module", sorted(SAMPLES.glob("*.py")), ids=lambda p: p.name)
@pytest.mark.parametrize("contract", [CONTRACT_V1, CONTRACT_V2])
def test_samples_partition_is_total_at_every_contract(module: Path, contract: int) -> None:
    """Every line of every projected def body in the real samples corpus lands in exactly one row."""
    source = module.read_text(encoding="utf-8")
    ranges = _element_ranges(source, contract=contract)
    contracts = parse_module(module, contract=contract)
    assert sorted(c["handler"] for c in contracts) == sorted(ranges)
    for entry in contracts:
        lo, hi = ranges[entry["handler"]]
        _assert_total_partition(entry["rows"], lo, hi)


@pytest.mark.parametrize(
    "source,element",
    [
        (TRAILING_COMMENT, "h"),
        (ADJACENT_COMMENT, "h"),
        (LEADING_IN_BLOCK, "h"),
        (NOTE_CORPUS, "wide"),
        (ROUTER_CORPUS, "wide"),
    ],
)
def test_adversarial_partition_is_total(source: str, element: str) -> None:
    _rows(source, element)  # _rows asserts the total partition


def test_the_samples_corpus_is_actually_a_corpus() -> None:
    """State what the corpus scan SCANNED, so a green from an empty glob is impossible."""
    assert len(ELEMENT_MODULES) >= 5, [p.name for p in ELEMENT_MODULES]
    rows = sum(
        len(e["rows"]) for m in ELEMENT_MODULES for e in parse_module(m, contract=CONTRACT_V2)
    )
    # 67 rows across 12 modules as measured 2026-08-10; the floor is a tripwire against an empty or
    # silently-narrowed scan, not a target.
    assert rows >= 50, f"only {rows} rows across {len(ELEMENT_MODULES)} modules"


def test_samples_routers_are_projected_and_partitioned() -> None:
    """At least one real sample is a @router, and its projection tiles its body exactly."""
    projected = 0
    for module in sorted(SAMPLES.glob("*.py")):
        source = module.read_text(encoding="utf-8")
        for entry in parse_module(module, contract=CONTRACT_V2):
            if entry.get("role") != "router":
                continue
            projected += 1
            lo, hi = _element_ranges(source, contract=CONTRACT_V2)[entry["handler"]]
            _assert_total_partition(entry["rows"], lo, hi)
    assert projected >= 1, "expected at least one @router in samples/config"


# =============================================================================
# AC-N1 / AC-N2 / AC-N5 / AC-N6 — the note kind
# =============================================================================


def test_comment_after_the_last_statement_projects_as_a_note_row() -> None:
    """AC-N2 — the vanishing-comment defect (Amendment A §A.3 defect 1).

    The Add-palette's Comment step, inserted after a handler's last statement, used to fall outside every
    row: the partition stopped at ``FunctionDef.end_lineno``, so it rendered nowhere at all."""
    rows = _rows(TRAILING_COMMENT, "h")
    notes = _only(rows, "note")
    assert [(n["line_start"], n["line_end"]) for n in notes] == [(7, 7)]
    assert notes[0]["text"] == " a trailing note"
    assert notes[0]["raw"] == "    # a trailing note"
    assert notes[0]["pragma"] is False
    # ... and at CONTRACT_V1 the line is still outside the partition, unchanged.
    v1 = _rows(TRAILING_COMMENT, "h", contract=CONTRACT_V1)
    assert max(r["line_end"] for r in v1) == 6


def test_comment_adjacent_to_an_opaque_line_is_its_own_row() -> None:
    """AC-N1 — Amendment A §A.3 defect 2: ``_merge_code_rows`` used to absorb it into the code row."""
    rows = _rows(ADJACENT_COMMENT, "h")
    assert [(r["kind"], r["line_start"], r["line_end"]) for r in rows] == [
        ("code", 6, 6),
        ("note", 7, 7),
        ("action", 8, 8),
    ]
    # The shipped contract still merges them into one opaque row.
    v1 = _rows(ADJACENT_COMMENT, "h", contract=CONTRACT_V1)
    assert [(r["kind"], r["line_start"], r["line_end"]) for r in v1][0] == ("code", 6, 7)


def test_comment_leading_a_block_body_leaves_the_control_header() -> None:
    """Amendment A §A.4 — the control header span shrinks so the comment tiles INSIDE the body."""
    rows = _rows(LEADING_IN_BLOCK, "h")
    header = _only(rows, "control")[0]
    assert (header["line_start"], header["line_end"]) == (6, 6)
    note = _only(rows, "note")[0]
    assert (note["line_start"], note["line_end"], note["nesting"]) == (7, 7, 1)
    assert note["suite"] == "6", "the note belongs to the if's body suite, not the def body"


def test_note_runs_split_on_blank_indent_and_pragma() -> None:
    """AC-N1 + AC-N4 — a run of same-indent comments is ONE note; a pragma is always alone."""
    rows = _rows(NOTE_CORPUS, "wide")
    notes = _only(rows, "note")
    spans = [(n["line_start"], n["line_end"], n["pragma"]) for n in notes]
    assert (7, 8, False) in spans, "the two contiguous prose lines coalesce into one note"
    assert (10, 10, True) in spans, "the pragma stands alone and is flagged"
    assert (11, 11, False) in spans, "the banner after the pragma is a separate, non-pragma note"


def test_note_never_covers_the_docstring_module_scope_or_a_trailing_comment() -> None:
    """AC-N5 — the three negatives."""
    rows = _rows(NOTE_CORPUS, "wide")
    note_lines = {
        ln for n in _only(rows, "note") for ln in range(n["line_start"], n["line_end"] + 1)
    }
    # The docstring is `body[0]`, a real statement — it stays a code row (§A.4).
    docstring_row = next(r for r in rows if r["line_start"] == 6)
    assert docstring_row["kind"] == "code"
    assert 6 not in note_lines
    # The module preamble is outside every partition.
    assert min(note_lines) >= 7
    # A comment SHARING a line with a statement is not extracted; it stays in the statement's row.
    action = next(r for r in rows if r["kind"] == "action" and r["line_start"] == 12)
    assert action["line_end"] == 12 and 12 not in note_lines


def test_module_scope_comment_after_a_handler_is_not_a_note() -> None:
    """AC-N5 — a dedented comment below the def belongs to module scope, never to the handler."""
    source = TRAILING_COMMENT + "\n\n# a module-scope banner\nX = 1\n"
    rows = _rows(source, "h")
    assert max(r["line_end"] for r in rows) == 7, "the partition stops at the indented comment"


def test_unrecognized_construct_is_still_a_code_row_and_only_a_syntax_error_refuses() -> None:
    """AC-N6 — the §4 degradation ladder is unchanged by the widening."""
    source = (
        HANDLER_PREAMBLE
        + '@handler("h")\ndef h(msg):\n    weird = [x for x in msg.raw]\n    # note\n'
    )
    rows = _rows(source, "h")
    assert [r["kind"] for r in rows] == ["code", "note"]
    with pytest.raises(LensParseError):
        parse_source("def (:\n", module="broken.py", contract=CONTRACT_V2)


# =============================================================================
# AC-N3 / AC-N4 — note editing
# =============================================================================


def test_note_edit_preserves_indent_and_hash_form_and_round_trips() -> None:
    """AC-N3 — the edit takes indentation and the ``#`` prefix form from the EXISTING line."""
    source = NOTE_CORPUS
    banner = next(r for r in _rows(source, "wide") if r["line_start"] == 11)
    assert banner["kind"] == "note" and banner["text"] == "# a banner"

    # Setting the text to its current value is byte-identical.
    same = rewrite_source(
        source,
        {"line_start": 11, "line_end": 11, "op": "set_params", "params": {"text": banner["text"]}},
        contract=CONTRACT_V2,
    )
    assert same == source

    # A real edit keeps the `##` run and the 4-space indent, and changes only that line.
    changed = rewrite_source(
        source,
        {"line_start": 11, "line_end": 11, "op": "set_params", "params": {"text": "# RENAMED"}},
        contract=CONTRACT_V2,
    )
    assert changed.splitlines()[10] == "    ## RENAMED"
    assert changed.splitlines()[:10] == source.splitlines()[:10]
    assert changed.splitlines()[11:] == source.splitlines()[11:]

    # ... and it re-parses to the same kind, span, nesting and suite.
    after = next(r for r in _rows(changed, "wide") if r["line_start"] == 11)
    assert {k: after[k] for k in ("kind", "line_start", "line_end", "nesting", "suite")} == {
        k: banner[k] for k in ("kind", "line_start", "line_end", "nesting", "suite")
    }


def test_note_edit_refuses_a_line_count_change() -> None:
    changed = {"line_start": 7, "line_end": 8, "op": "set_params", "params": {"text": "one line"}}
    with pytest.raises(LensRewriteError, match="may not change the file's line count"):
        rewrite_source(NOTE_CORPUS, changed, contract=CONTRACT_V2)


def test_multi_line_note_edit_rewrites_each_line_in_place() -> None:
    edit = {"line_start": 7, "line_end": 8, "op": "set_params", "params": {"text": " A\n B"}}
    changed = rewrite_source(NOTE_CORPUS, edit, contract=CONTRACT_V2)
    assert changed.splitlines()[6:8] == ["    # A", "    # B"]


def test_note_delete_removes_exactly_its_lines() -> None:
    changed = rewrite_source(
        NOTE_CORPUS, {"line_start": 11, "line_end": 11, "op": "delete_row"}, contract=CONTRACT_V2
    )
    assert changed.splitlines() == source_without(NOTE_CORPUS, 11)


def source_without(source: str, lineno: int) -> list[str]:
    lines = source.splitlines()
    del lines[lineno - 1]
    return lines


def test_pragma_note_refuses_edit_delete_and_move() -> None:
    """AC-N4 — a pragma is functional code: read-only in all three ops."""
    for edit in (
        {"line_start": 10, "line_end": 10, "op": "set_params", "params": {"text": " prose"}},
        {"line_start": 10, "line_end": 10, "op": "delete_row"},
        {"line_start": 10, "line_end": 10, "op": "move_row", "direction": "up"},
    ):
        with pytest.raises(LensRewriteError):
            rewrite_source(NOTE_CORPUS, edit, contract=CONTRACT_V2)


def test_no_note_is_movable_in_v1() -> None:
    edit = {"line_start": 11, "line_end": 11, "op": "move_row", "direction": "up"}
    with pytest.raises(LensRewriteError, match="notes are not movable"):
        rewrite_source(NOTE_CORPUS, edit, contract=CONTRACT_V2)


def test_trailing_pragma_on_a_statement_survives_a_param_edit_byte_for_byte() -> None:
    """AC-N5 — the note kind must not touch inline/trailing comment extraction."""
    source = (
        HANDLER_PREAMBLE + '@handler("h")\ndef h(msg):\n    msg.set("PID-3.1", "X")  # noqa: E501\n'
    )
    changed = rewrite_source(
        source,
        {"line_start": 6, "line_end": 6, "op": "set_params", "params": {"value": "Y"}},
        contract=CONTRACT_V2,
    )
    assert changed.splitlines()[5] == '    msg.set("PID-3.1", "Y")  # noqa: E501'


# =============================================================================
# AC-R1 / AC-R2 / AC-R3 — the route kind
# =============================================================================


def test_router_return_classification() -> None:
    """AC-R2 — the whole §D.4 table, in one place."""
    rows = _rows(ROUTER_CORPUS, "wide")
    routes = {r["line_start"]: r for r in _only(rows, "route")}
    assert routes[8]["handlers"] == ["oru_relay", "oru_archive"] and "unrouted" not in routes[8]
    assert routes[10]["handlers"] == ["adt_relay"] and "unrouted" not in routes[10]
    # a non-literal element is DYNAMIC: empty, and explicitly NOT flagged unrouted
    assert routes[12]["handlers"] == [] and "unrouted" not in routes[12]
    assert routes[14]["handlers"] == [] and routes[14]["unrouted"] is True  # bare return
    assert routes[16]["handlers"] == [] and routes[16]["unrouted"] is True  # return None
    assert routes[17]["handlers"] == [] and routes[17]["unrouted"] is True  # return []


def test_handler_return_empty_list_is_unchanged_by_the_role_branch() -> None:
    """AC-R3 — asserted FIRST as the guard: the role branch must never regress the handler path."""
    source = HANDLER_PREAMBLE + '@handler("h")\ndef h(msg):\n    return []\n'
    for contract in (CONTRACT_V1, CONTRACT_V2):
        rows = _rows(source, "h", contract=contract)
        assert len(rows) == 1
        assert rows[0]["kind"] == "send"
        assert rows[0]["filtered"] is True
        assert rows[0]["outbounds"] == []
        assert "unrouted" not in rows[0]
    # and the two contracts' handler payloads are identical
    assert (
        parse_source(source, module="m.py", contract=CONTRACT_V1)[0]["rows"]
        == parse_source(source, module="m.py", contract=CONTRACT_V2)[0]["rows"]
    )


def test_router_entry_carries_its_role_and_a_router_is_absent_at_v1() -> None:
    entries = parse_source(ROUTER_CORPUS, module="r.py", contract=CONTRACT_V2)
    assert [(e["handler"], e["role"]) for e in entries] == [("wide", "router")]
    assert entries[0]["contract_version"] == CONTRACT_V2
    assert parse_source(ROUTER_CORPUS, module="r.py", contract=CONTRACT_V1) == []


def test_router_body_recognizes_routing_constructs_only() -> None:
    """AC-R5 — no transform verb, no lookup row; a lookup call degrades to a code row (§D.6)."""
    source = (
        ROUTER_PREAMBLE + '@router("r")\ndef r(msg):\n    msg.set("PID-3.1", "X")\n'
        '    row = db_lookup("DB", "select 1", {})\n    log_note("hi")\n    return ["h"]\n'
    )
    rows = _rows(source, "r")
    assert [r["kind"] for r in rows] == ["code", "route"], (
        "the three transform/lookup/diagnostic statements coalesce into one opaque code row"
    )


def test_router_refuses_ops_that_author_transform_verbs_or_sends() -> None:
    """AC-R5, engine-side: the palette does not OFFER them and the engine does not ACCEPT them."""
    source = ROUTER_PREAMBLE + '@router("r")\ndef r(msg):\n    return ["h"]\n'
    for edit in (
        {
            "line_start": 6,
            "line_end": 6,
            "op": "insert_row",
            "position": "before",
            "action": "set_field",
            "params": {"path": "MSH-3", "value": "MEFOR"},
        },
        {"line_start": 6, "line_end": 6, "op": "insert_send", "destination": "OB_X"},
        {"line_start": 6, "line_end": 6, "op": "add_destination", "destination": "OB_X"},
        {
            "line_start": 6,
            "line_end": 6,
            "op": "template",
            "template": "send",
            "destination": "OB_X",
        },
    ):
        with pytest.raises(LensRewriteError, match="pure destination-selection"):
            rewrite_source(source, edit, contract=CONTRACT_V2)


# =============================================================================
# INVARIANT 2 — the splice is byte-stable (AC-R4 + AC-N3 + gate 2)
# =============================================================================


#: Kinds the §4 ladder keeps read-only. A ``set_params`` against one is REFUSED with zero change — which
#: is byte-stability's other half: the lens never half-applies an edit it cannot round-trip.
READ_ONLY_KINDS = frozenset({"code", "control"})


@pytest.mark.parametrize("module", ELEMENT_MODULES, ids=lambda p: p.name)
def test_noop_rewrite_is_byte_identical_for_every_row_of_the_samples_corpus(module: Path) -> None:
    """Parse then rewrite-with-no-change returns the file BYTE-identically, for every projected row.

    Read-only rows are asserted the other way round — refused with zero change — so no row of the corpus
    is skipped and the two halves of gate 2 are both covered."""
    source = module.read_bytes().decode("utf-8")
    projected = 0
    for entry in parse_source(source, module=module.as_posix(), contract=CONTRACT_V2):
        for row in entry["rows"]:
            projected += 1
            edit: dict[str, Any] = {
                "line_start": row["line_start"],
                "line_end": row["line_end"],
                "op": "set_params",
                "params": {},
                "handler": entry["handler"],
            }
            where = f"{module.name} row {row['kind']} {row['line_start']}-{row['line_end']}"
            if row["kind"] in READ_ONLY_KINDS:
                with pytest.raises(LensRewriteError):
                    rewrite_source(source, edit, contract=CONTRACT_V2)
                continue
            assert rewrite_source(source, edit, contract=CONTRACT_V2) == source, where
    assert projected > 0, f"{module.name} projected no rows — the corpus scan proved nothing"


@pytest.mark.parametrize("source,element", [(NOTE_CORPUS, "wide"), (ROUTER_CORPUS, "wide")])
def test_setting_a_row_to_its_current_value_is_byte_identical(source: str, element: str) -> None:
    """AC-N3 + AC-R4 — including the two NEW op classes, and including a dynamic route return."""
    for row in _rows(source, element):
        params: dict[str, Any]
        if row["kind"] == "note":
            params = {"text": row["text"]}
        elif row["kind"] == "route":
            params = {"handlers": row["handlers"]}
        else:
            params = {}
        edit = {
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "op": "set_params",
            "params": params,
        }
        if row.get("pragma") or row["kind"] in READ_ONLY_KINDS:
            with pytest.raises(LensRewriteError):
                rewrite_source(source, edit, contract=CONTRACT_V2)
            continue
        assert rewrite_source(source, edit, contract=CONTRACT_V2) == source, row


def test_route_edit_changes_only_its_own_line_and_reparses_the_same() -> None:
    """AC-R4 — a real change touches only that row's line range."""
    before = next(r for r in _rows(ROUTER_CORPUS, "wide") if r["line_start"] == 8)
    changed = rewrite_source(
        ROUTER_CORPUS,
        {
            "line_start": 8,
            "line_end": 8,
            "op": "set_params",
            "params": {"handlers": ["oru_relay"]},
        },
        contract=CONTRACT_V2,
    )
    assert changed.splitlines()[7] == '        return ["oru_relay"]'
    assert changed.splitlines()[:7] == ROUTER_CORPUS.splitlines()[:7]
    assert changed.splitlines()[8:] == ROUTER_CORPUS.splitlines()[8:]
    after = next(r for r in _rows(changed, "wide") if r["line_start"] == 8)
    assert after["handlers"] == ["oru_relay"]
    for key in ("kind", "line_start", "line_end", "nesting", "suite"):
        assert after[key] == before[key]


def test_route_edit_never_flattens_a_dynamic_return() -> None:
    """A dynamic ``return [pick(msg)]`` projects handlers ``[]``; re-setting ``[]`` must NOT rewrite it."""
    edit = {"line_start": 12, "line_end": 12, "op": "set_params", "params": {"handlers": []}}
    assert rewrite_source(ROUTER_CORPUS, edit, contract=CONTRACT_V2) == ROUTER_CORPUS


def test_bare_return_route_edit_is_refused_rather_than_guessed() -> None:
    edit = {"line_start": 14, "line_end": 14, "op": "set_params", "params": {"handlers": ["h"]}}
    with pytest.raises(LensRewriteError, match="bare 'return'"):
        rewrite_source(ROUTER_CORPUS, edit, contract=CONTRACT_V2)


def test_byte_stability_survives_crlf_and_a_bom() -> None:
    source = "﻿" + NOTE_CORPUS.replace("\n", "\r\n")
    rows = parse_source(source, module="m.py", contract=CONTRACT_V2)[0]["rows"]
    note = next(r for r in rows if r["kind"] == "note" and r["line_start"] == 11)
    edit = {"line_start": 11, "line_end": 11, "op": "set_params", "params": {"text": note["text"]}}
    assert rewrite_source(source, edit, contract=CONTRACT_V2) == source
    changed = rewrite_source(
        source,
        {"line_start": 11, "line_end": 11, "op": "set_params", "params": {"text": "# X"}},
        contract=CONTRACT_V2,
    )
    assert changed.startswith("﻿")
    # Only line 11 changed, and it kept its CRLF terminator and its `##` prefix form.
    before_lines = source.split("\r\n")
    after_lines = changed.split("\r\n")
    assert len(after_lines) == len(before_lines), "no line was added, split or lost"
    assert after_lines[10] == "    ## X"
    assert [
        i for i, (a, b) in enumerate(zip(before_lines, after_lines, strict=True)) if a != b
    ] == [10]


# =============================================================================
# INVARIANT 3 — the .py stays the only artifact and the only execution path
# =============================================================================


def test_route_edit_produces_python_and_writes_no_second_artifact(tmp_path: Path) -> None:
    """A route edit yields plain Python in the SAME file; no sidecar, no declarative artifact.

    This is the entire licence for the Steps view under CLAUDE.md §12 / BACKLOG #26 — widening the
    grammar to routers must not introduce a second execution path."""
    module = tmp_path / "IB_X_router.py"
    module.write_text(ROUTER_CORPUS, encoding="utf-8")
    before = {p.name for p in tmp_path.iterdir()}

    rewritten = rewrite_module(
        module,
        {"line_start": 8, "line_end": 8, "op": "set_params", "params": {"handlers": ["only"]}},
        contract=CONTRACT_V2,
    )
    # It is Python, and it is the file's own text — not a serialized row list.
    ast.parse(rewritten)
    assert '        return ["only"]' in rewritten.splitlines()
    # Nothing was written anywhere: `rewrite_module` RETURNS the text, the caller owns the write.
    assert {p.name for p in tmp_path.iterdir()} == before
    assert module.read_text(encoding="utf-8") == ROUTER_CORPUS


def test_router_parse_and_rewrite_never_import_or_execute_the_module() -> None:
    """Gate 4 — static-only, now for the router path too: a top-level ``raise`` still parses."""
    source = (
        ROUTER_PREAMBLE + 'raise RuntimeError("importing me would explode")\n\n\n'
        '@router("r")\ndef r(msg):\n    return ["h"]\n'
    )
    entries = parse_source(source, module="explosive.py", contract=CONTRACT_V2)
    assert [e["handler"] for e in entries] == ["r"]
    assert "messagefoundry_explosive_probe" not in sys.modules
    row = entries[0]["rows"][0]
    assert row["kind"] == "route"
    edit = {
        "line_start": row["line_start"],
        "line_end": row["line_end"],
        "op": "set_params",
        "params": {"handlers": ["other"]},
    }
    assert 'return ["other"]' in rewrite_source(source, edit, contract=CONTRACT_V2)


def test_the_router_route_template_renders_python_not_a_declarative_row() -> None:
    """The router palette's "route to handler(s)" item emits a real ``return [...]`` statement."""
    source = ROUTER_PREAMBLE + '@router("r")\ndef r(msg):\n    return []\n'
    changed = rewrite_source(
        source,
        {
            "line_start": 6,
            "line_end": 6,
            "op": "template",
            "template": "route",
            "handlers": ["a", "b"],
            "position": "before",
        },
        contract=CONTRACT_V2,
    )
    ast.parse(changed)
    assert '    return ["a", "b"]' in changed.splitlines()


# =============================================================================
# INVARIANT 4 — contract-version skew, BOTH directions
# =============================================================================


@pytest.mark.parametrize(
    "source", [NOTE_CORPUS, ROUTER_CORPUS, TRAILING_COMMENT, ADJACENT_COMMENT, LEADING_IN_BLOCK]
)
def test_an_older_consumer_never_receives_a_v2_kind(source: str) -> None:
    """Direction 1 — an older IDE asks for nothing and gets the shipped contract, exactly."""
    for entry in parse_source(source, module="m.py", contract=CONTRACT_V1):
        assert "role" not in entry and "contract_version" not in entry
        for row in entry["rows"]:
            assert row["kind"] in V1_KINDS, row


@pytest.mark.parametrize("module", sorted(SAMPLES.glob("*.py")), ids=lambda p: p.name)
def test_the_v1_payload_is_unchanged_across_the_whole_samples_corpus(module: Path) -> None:
    """Direction 1, over the real corpus: nothing outside the shipped enum, no new entry fields."""
    for entry in parse_module(module, contract=CONTRACT_V1):
        assert set(entry) <= {
            "handler",
            "module",
            "def_line",
            "rows",
            "accepts_types",
            "inferred_type",
        }
        assert all(row["kind"] in V1_KINDS for row in entry["rows"])


def test_a_newer_consumer_asking_for_an_unemittable_contract_is_refused_cleanly() -> None:
    """Direction 2 — a newer IDE meeting an older engine gets a clean refusal, never a partial parse."""
    with pytest.raises(LensParseError, match="unknown contract version"):
        parse_source(NOTE_CORPUS, module="m.py", contract=CONTRACT_LATEST + 1)
    with pytest.raises(LensParseError, match="unknown contract version"):
        rewrite_source(
            NOTE_CORPUS,
            {"line_start": 7, "line_end": 8, "op": "set_params", "params": {}},
            contract=CONTRACT_LATEST + 1,
        )


def test_cli_contract_flag_gates_the_new_kinds_and_refuses_an_unknown_version(
    tmp_path: Path,
) -> None:
    """The gate the IDE actually meets: ``lens parse --contract``.

    Direction 2's IDE-side fallback (retry without the flag when an OLDER CLI rejects it) is asserted in
    ``ide/src/test/suite/steps-contract.test.ts``; this asserts the engine end of the same contract."""
    module = tmp_path / "IB_X_router.py"
    module.write_text(ROUTER_CORPUS, encoding="utf-8")
    argv = [sys.executable, "-m", "messagefoundry", "lens", "parse", str(module), "--json"]

    default = subprocess.run(argv, capture_output=True, text=True, cwd=REPO_ROOT, check=False)
    assert default.returncode == 0
    assert '"route"' not in default.stdout, "a router must not project without the flag"

    v2 = subprocess.run(
        [*argv, "--contract", "2"], capture_output=True, text=True, cwd=REPO_ROOT, check=False
    )
    assert v2.returncode == 0
    assert '"route"' in v2.stdout and '"role": "router"' in v2.stdout.replace(
        '"role":"router"', '"role": "router"'
    )

    bad = subprocess.run(
        [*argv, "--contract", "99"], capture_output=True, text=True, cwd=REPO_ROOT, check=False
    )
    assert bad.returncode != 0
    assert "unknown contract version" in (bad.stdout + bad.stderr)
    assert "Traceback" not in (bad.stdout + bad.stderr)
