# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``lens rewrite`` v2 — STRUCTURAL edits (delete/insert/move) + multi-line-call param edits (ADR 0076
§2 phase 3 v2 / BACKLOG #222).

The hard gates (task spec):

* **gate 2 — structural byte-preservation:** for delete/insert/move, every line OTHER than the
  inserted/deleted/moved span is byte-identical to the input — verified against an **independent oracle**
  (a regex-driven physical-line splitter, NOT the lens's own char-loop math).
* **gate 3 — first-class output:** after ANY op the result re-parses (:mod:`ast`), is
  ``ruff format --check``-clean, and ``messagefoundry check`` accepts it (spot-checked).
* **gate 4 — coverage-partition holds** on the rewritten source (re-parse → rows still exactly partition
  each def body).
* **gate 5 — refusal boundary extended:** code/control/msg rows, sole-statement deletes, moves across
  nesting/intervening lines, inserts that would not parse or would over-run the line limit — all refuse
  (``LensRewriteError``) with ZERO change.
* **gate 6 — adversarial:** each op over sources with non-ASCII on the edited AND adjacent lines, CRLF,
  deep nesting, and a multi-line call — assert gates 2-4.

Static-only throughout: the module is never imported/executed."""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.lens import LensRewriteError, parse_source, rewrite_source

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples" / "config"


# =============================================================================
# Independent oracles (regex-driven — NOT the lens's char-loop byte math, gate 2)
# =============================================================================


def _keepends(s: str) -> list[str]:
    """Split ``s`` into physical lines WITH terminators, on CRLF/CR/LF only — ``"".join`` is the identity.

    Implemented with :func:`re.split` (a *different* mechanism than the lens's char loop), so a byte-
    preservation assertion against it is genuinely independent of the code under test."""
    parts = re.split(r"(\r\n|\r|\n)", s)
    lines: list[str] = []
    for i in range(0, len(parts) - 1, 2):
        lines.append(parts[i] + parts[i + 1])
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def _oracle_delete(src: str, ls: int, le: int) -> str:
    lines = _keepends(src)
    return "".join(lines[: ls - 1] + lines[le:])


def _oracle_insert(src: str, target: int, position: str, new_line: str) -> str:
    lines = _keepends(src)
    idx = (target - 1) if position == "before" else target
    return "".join(lines[:idx] + [new_line] + lines[idx:])


def _oracle_swap(src: str, first: tuple[int, int], second: tuple[int, int]) -> str:
    lines = _keepends(src)
    f_ls, f_le = first
    s_ls, s_le = second
    block_first = lines[f_ls - 1 : f_le]
    block_second = lines[s_ls - 1 : s_le]
    return "".join(lines[: f_ls - 1] + block_second + block_first + lines[s_le:])


def _ruff_format_clean(source: str) -> bool:
    """Whether ``source`` is already ``ruff format --check``-clean (gate 3). Skips if ruff is missing."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "ruff", "format", "--check", "-"],
            input=source.encode("utf-8"),
            capture_output=True,
        )
    except (OSError, ValueError) as exc:  # pragma: no cover - environment guard
        pytest.skip(f"ruff not runnable: {exc}")
    return proc.returncode == 0


def _ruff_check_clean(source: str) -> bool:
    """Whether ``source`` passes ``ruff check`` (catches an F821 undefined name). Skips if ruff is missing.

    Used to prove a NATIVE-form insert (``msg.set(...)``) lints clean without any vocabulary import —
    the wrapper form would raise F821 in a module that never imported the name."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "ruff", "check", "--select", "F", "-"],
            input=source.encode("utf-8"),
            capture_output=True,
        )
    except (OSError, ValueError) as exc:  # pragma: no cover - environment guard
        pytest.skip(f"ruff not runnable: {exc}")
    return proc.returncode == 0


def _assert_partition(source: str) -> None:
    """gate 4: on the REWRITTEN source, every handler's rows still exactly partition its def body."""
    tree = ast.parse(source)
    ranges: dict[str, tuple[int, int]] = {}
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
                ranges[name] = (node.body[0].lineno, node.end_lineno)
    for contract in parse_source(source):
        rows = contract["rows"]
        body_start, body_end = ranges[contract["handler"]]
        assert rows, "expected at least one row"
        assert rows == sorted(rows, key=lambda r: r["line_start"]), "rows must be in source order"
        assert rows[0]["line_start"] == body_start
        assert rows[-1]["line_end"] == body_end
        for prev, nxt in zip(rows, rows[1:], strict=False):
            assert prev["line_end"] + 1 == nxt["line_start"], f"gap/overlap: {prev} {nxt}"


def _assert_first_class(source: str) -> None:
    """gate 3: the rewritten source re-parses AND stays ruff-format-clean."""
    ast.parse(source)
    assert _ruff_format_clean(source), "rewritten source is not ruff-format-clean (gate 3)"


# A dense, ruff-clean handler (the vocabulary target shape) reused across the structural tests.
DENSE = (
    "from messagefoundry import handler, Send, copy_field, set_field, convert_case\n\n\n"
    '@handler("enrich")\n'
    "def enrich(msg):\n"
    '    copy_field(msg, "PID-5.1", "NK1-2.1")\n'  # line 6
    '    set_field(msg, "PID-3.1", "NEW")\n'  # line 7
    '    convert_case(msg, "PID-5.1", "upper")\n'  # line 8
    '    return Send("OB_X", msg)\n'  # line 9
)


# =============================================================================
# delete_row
# =============================================================================


def test_delete_row_byte_preserves_via_oracle() -> None:
    out = rewrite_source(DENSE, {"op": "delete_row", "line_start": 7, "line_end": 7})
    assert out == _oracle_delete(DENSE, 7, 7)  # gate 2: independent oracle
    _assert_first_class(out)  # gate 3
    _assert_partition(out)  # gate 4
    # The set_field row is gone; the surrounding rows are intact.
    assert 'set_field(msg, "PID-3.1", "NEW")' not in out
    assert 'copy_field(msg, "PID-5.1", "NK1-2.1")' in out


def test_delete_first_action_row() -> None:
    out = rewrite_source(DENSE, {"op": "delete_row", "line_start": 6, "line_end": 6})
    assert out == _oracle_delete(DENSE, 6, 6)
    _assert_first_class(out)
    _assert_partition(out)


def test_delete_sole_statement_is_refused() -> None:
    # An if-body whose only statement is the target — deleting it would leave an empty suite.
    src = (
        "from messagefoundry import handler, Send, copy_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    if msg["A"]:\n'
        '        copy_field(msg, "A", "B")\n'
        '    return Send("OB", msg)\n'
    )
    with pytest.raises(LensRewriteError, match="only statement"):
        rewrite_source(src, {"op": "delete_row", "line_start": 7, "line_end": 7})
    # ...and the sole return of a handler is likewise undeletable.
    lone = (
        "from messagefoundry import handler, Send\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    return Send("OB", msg)\n'
    )
    with pytest.raises(LensRewriteError, match="only statement"):
        rewrite_source(lone, {"op": "delete_row", "line_start": 6, "line_end": 6})


def test_delete_code_and_control_rows_refused() -> None:
    src = (SAMPLES / "adt.py").read_bytes().decode("utf-8")
    # A code row is still read-only — deleting it is refused (only if/for HEADERS became deletable).
    with pytest.raises(LensRewriteError, match="'code' row"):
        rewrite_source(src, {"op": "delete_row", "line_start": 49, "line_end": 50})
    # ADR 0089 block-cut: deleting an ``if`` HEADER now removes the WHOLE block (lines 47-48 of adt.py).
    # (The def suite keeps ≥3 siblings, so the sole-statement guard does not fire.)
    out = rewrite_source(src, {"op": "delete_row", "line_start": 47, "line_end": 47})
    assert 'if msg["MSH-9.2"] not in EVENT_LABELS:' not in out  # the header went
    assert "only events in the code set" not in out  # ...and its body (the return None) with it
    ast.parse(out)
    # An ``elif``/``else`` header is NOT independently deletable (it is part of its ``if``) — still refused.
    elif_src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    if msg["A"]:\n'  # 6
        '        set_field(msg, "B", "C")\n'  # 7
        "    else:\n"  # 8 else header
        '        set_field(msg, "D", "E")\n'  # 9
        '    return Send("OB", msg)\n'  # 10
    )
    with pytest.raises(LensRewriteError, match="'control' row"):
        rewrite_source(elif_src, {"op": "delete_row", "line_start": 8, "line_end": 8})


# =============================================================================
# insert_row
# =============================================================================


def test_insert_row_after_byte_preserves_via_oracle() -> None:
    edit = {
        "op": "insert_row",
        "line_start": 6,
        "line_end": 6,
        "position": "after",
        "action": "convert_case",
        "params": {"path": "PID-5.1", "mode": "upper"},
    }
    out = rewrite_source(DENSE, edit)
    expected_line = '    convert_case(msg, "PID-5.1", "upper")\n'
    assert out == _oracle_insert(DENSE, 6, "after", expected_line)  # gate 2
    _assert_first_class(out)  # gate 3
    _assert_partition(out)  # gate 4


def test_insert_row_before_target() -> None:
    edit = {
        "op": "insert_row",
        "line_start": 9,
        "line_end": 9,
        "position": "before",
        "action": "set_field",
        "params": {"path": "MSH-3", "value": "MEFOR"},
    }
    out = rewrite_source(DENSE, edit)
    # ADR 0089: set_field inserts in its NATIVE Message-API form (no wrapper import needed).
    expected_line = '    msg.set("MSH-3", "MEFOR")\n'
    assert out == _oracle_insert(DENSE, 9, "before", expected_line)
    _assert_first_class(out)
    _assert_partition(out)


def test_insert_lookup_with_assign_to() -> None:
    src = (
        "from messagefoundry import handler, Send, db_lookup\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    return Send("OB", msg)\n'
    )
    edit = {
        "op": "insert_row",
        "line_start": 6,
        "line_end": 6,
        "position": "before",
        "action": "db_lookup",
        "assign_to": "row",
        "params": {
            "connection": "MPI",
            "statement": "select 1",
            "params": {"expr": '{"id": msg["PID-3.1"]}'},
        },
    }
    out = rewrite_source(src, edit)
    assert '    row = db_lookup("MPI", "select 1", {"id": msg["PID-3.1"]})\n' in out
    _assert_first_class(out)
    _assert_partition(out)


def test_insert_at_nesting_indentation() -> None:
    # Inserting after a row inside an if body copies the body's (deeper) indentation.
    src = (
        "from messagefoundry import handler, Send, copy_field, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    if msg["MSH-9.1"] == "ADT":\n'
        '        copy_field(msg, "A", "B")\n'
        '    return Send("OB", msg)\n'
    )
    edit = {
        "op": "insert_row",
        "line_start": 7,
        "line_end": 7,
        "position": "after",
        "action": "set_field",
        "params": {"path": "C", "value": "D"},
    }
    out = rewrite_source(src, edit)
    # Native set_field form at the deeper (8-space) indent inside the if.
    assert '        msg.set("C", "D")\n' in out
    _assert_first_class(out)
    _assert_partition(out)


def test_insert_unknown_action_and_missing_param_refused() -> None:
    base = {"op": "insert_row", "line_start": 6, "line_end": 6, "position": "after"}
    with pytest.raises(LensRewriteError, match="not a recognized vocabulary"):
        rewrite_source(DENSE, {**base, "action": "no_such_helper", "params": {}})
    # The missing-required-param refusal is a WRAPPER-render guard (convert_case is not one of the three
    # NATIVE-form actions, whose missing params instead render as empty string literals — see the native
    # insert tests). convert_case requires `mode`.
    with pytest.raises(LensRewriteError, match="requires parameter 'mode'"):
        rewrite_source(DENSE, {**base, "action": "convert_case", "params": {"path": "A"}})


def test_insert_over_line_length_refused() -> None:
    # A rendered call wider than ruff's 100-col limit is refused (so the output stays format-clean).
    long_value = "X" * 120
    with pytest.raises(LensRewriteError, match="column"):
        rewrite_source(
            DENSE,
            {
                "op": "insert_row",
                "line_start": 6,
                "line_end": 6,
                "position": "after",
                "action": "set_field",
                "params": {"path": "MSH-3", "value": long_value},
            },
        )


def test_insert_malformed_expr_refused() -> None:
    with pytest.raises(LensRewriteError, match="not a valid Python expression"):
        rewrite_source(
            DENSE,
            {
                "op": "insert_row",
                "line_start": 6,
                "line_end": 6,
                "position": "after",
                "action": "set_field",
                "params": {"path": "A", "value": {"expr": "msg[["}},
            },
        )


# =============================================================================
# move_row
# =============================================================================


def test_move_up_byte_preserves_via_oracle() -> None:
    out = rewrite_source(
        DENSE, {"op": "move_row", "line_start": 7, "line_end": 7, "direction": "up"}
    )
    assert out == _oracle_swap(DENSE, (6, 6), (7, 7))  # gate 2: swap rows 6 & 7
    _assert_first_class(out)  # gate 3
    _assert_partition(out)  # gate 4


def test_move_down_byte_preserves_via_oracle() -> None:
    out = rewrite_source(
        DENSE, {"op": "move_row", "line_start": 7, "line_end": 7, "direction": "down"}
    )
    assert out == _oracle_swap(DENSE, (7, 7), (8, 8))  # swap rows 7 & 8
    _assert_first_class(out)
    _assert_partition(out)


def test_move_up_then_down_round_trips() -> None:
    up = rewrite_source(
        DENSE, {"op": "move_row", "line_start": 7, "line_end": 7, "direction": "up"}
    )
    # After moving line 7 up it sits on line 6; move it back down.
    back = rewrite_source(
        up, {"op": "move_row", "line_start": 6, "line_end": 6, "direction": "down"}
    )
    assert back == DENSE


def test_move_first_and_last_refused() -> None:
    with pytest.raises(LensRewriteError, match="already first"):
        rewrite_source(DENSE, {"op": "move_row", "line_start": 6, "line_end": 6, "direction": "up"})
    with pytest.raises(LensRewriteError, match="already last"):
        rewrite_source(
            DENSE, {"op": "move_row", "line_start": 9, "line_end": 9, "direction": "down"}
        )


def test_move_across_intervening_blank_reorders_comment_tolerantly() -> None:
    # A reorder cuts the moved statement's lines and reinserts them — a blank/comment between siblings is
    # NOT part of any statement span, so it stays at its physical position (the move is comment-tolerant,
    # ADR 0089 block-move). Every non-moved line is byte-preserved (gate 2).
    src = (
        "from messagefoundry import handler, Send, copy_field, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    copy_field(msg, "A", "B")\n'  # 6
        "\n"  # 7 blank
        '    set_field(msg, "C", "D")\n'  # 8
        '    return Send("OB", msg)\n'  # 9
    )
    out = rewrite_source(src, {"op": "move_row", "line_start": 8, "line_end": 8, "direction": "up"})
    ast.parse(out)  # gate 3
    _assert_partition(out)  # gate 4
    # set_field moved above copy_field; the blank line survived (byte-preserved), just relocated.
    assert out.index('set_field(msg, "C", "D")') < out.index('copy_field(msg, "A", "B")')
    # byte-stable: the EXACT same set of lines (blank ones included), only their order changed — nothing
    # mangled, dropped, or duplicated.
    assert sorted(out.splitlines()) == sorted(src.splitlines())


def test_move_control_block_reorders_as_a_unit() -> None:
    # A control row now MOVES ITS WHOLE BLOCK (header + body) within its suite — the ADR 0089 block-move.
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    if msg["A"]:\n'  # 6 control header (def suite, idx 0)
        '        set_field(msg, "B", "C")\n'  # 7 body of the if
        '    set_field(msg, "D", "E")\n'  # 8 def suite, idx 1
        '    return Send("OB", msg)\n'  # 9 def suite, idx 2
    )
    out = rewrite_source(
        src, {"op": "move_row", "line_start": 6, "line_end": 6, "direction": "down"}
    )
    ast.parse(out)
    _assert_partition(out)
    # The entire if block (header + its body line) now sits AFTER set_field D, still one contiguous block.
    assert (
        out.index('set_field(msg, "D", "E")')
        < out.index('if msg["A"]:')
        < out.index('set_field(msg, "B", "C")')
        < out.index("return Send")
    )


def test_move_does_not_cross_nesting() -> None:
    # The ↑/↓ DIRECTION path stays suite-confined: a row inside an if body has no earlier SIBLING (the if
    # header is at the outer nesting), so "up" refuses — the arrows never lift a statement out of its block.
    # (The DRAG-to-target path DOES allow a cross-suite move now, re-indenting the block — see
    # tests/test_lens_dnd.py::test_move_cross_suite_reindents; only the arrow direction path is confined.)
    src = (
        "from messagefoundry import handler, Send, copy_field, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "Z", "Z")\n'  # 6 (outer sibling, but a comment/gap would still not merge)
        '    if msg["A"]:\n'  # 7 control header
        '        copy_field(msg, "A", "B")\n'  # 8 first (and only) stmt in the if body
        '    return Send("OB", msg)\n'  # 9
    )
    with pytest.raises(LensRewriteError, match="already first"):
        rewrite_source(src, {"op": "move_row", "line_start": 8, "line_end": 8, "direction": "up"})


# =============================================================================
# cross-suite drag-to-target move (#222 cross-suite) — re-indent, gates 2/3/4, adversarial
# =============================================================================


def _oracle_reindent_move(
    src: str,
    ls: int,
    le: int,
    to_ls: int,
    to_le: int,
    position: str,
    src_prefix: str,
    dst_prefix: str,
    frozen_rel: set[int],
) -> str:
    """Independent oracle for a cross-suite re-indenting move (gate 2) — regex line split + prefix swap +
    a caller-supplied interior-freeze set (a DIFFERENT mechanism than the lens char loop / ast.walk)."""

    def term(line: str) -> str:
        for t in ("\r\n", "\n", "\r"):
            if line.endswith(t):
                return t
        return ""

    lines = _keepends(src)
    block = lines[ls - 1 : le]
    reblock: list[str] = []
    for i, line in enumerate(block):
        t = term(line)
        content = line[: len(line) - len(t)]
        if i in frozen_rel:
            reblock.append(line)
        elif content.strip() == "":
            reblock.append(t)
        elif content.startswith(src_prefix):
            reblock.append(dst_prefix + content[len(src_prefix) :] + t)
        else:
            reblock.append(line)
    n = le - ls + 1
    del lines[ls - 1 : le]
    # After deleting [ls, le], an original line > le shifts up by n; "after" inserts past original line to_le
    # (correct for a disjoint sibling AND for the moved-line-inside-dest-block overlap case).
    if position == "before":
        idx = (to_ls - 1) - (n if le < to_ls else 0)
    else:
        idx = to_le - (n if to_le >= le else 0)
    lines[idx:idx] = reblock
    return "".join(lines)


def test_cross_suite_deep_nesting_reindents() -> None:
    # A def-level action dragged THREE suites deep (into an if→for→if body) re-indents 4→16 spaces; every
    # non-moved line (the nested headers + siblings + return) stays byte-identical (gate 2), the result is
    # ruff-format-clean (gate 3), and the coverage partition still holds (gate 4).
    src = (
        "from messagefoundry import handler, Send, copy_field, set_field\n\n\n"
        '@handler("h")\n'  # 4
        "def h(msg):\n"  # 5
        '    set_field(msg, "TOP", "1")\n'  # 6 def level (moves IN, 4→16)
        '    if msg["MSH-9.1"] == "ORU":\n'  # 7
        "        for grp in msg.groups():\n"  # 8
        '            if grp["OBX-2"] == "NM":\n'  # 9
        '                copy_field(msg, "A", "B")\n'  # 10 (anchor, 16-space)
        '    return Send("OB", msg)\n'  # 11
    )
    out = rewrite_source(
        src,
        {
            "op": "move_row",
            "line_start": 6,
            "line_end": 6,
            "to_line_start": 10,
            "to_line_end": 10,
            "to_position": "after",
        },
    )
    assert out == _oracle_reindent_move(
        src, 6, 6, 10, 10, "after", "    ", "                ", set()
    )  # gate 2
    _assert_first_class(out)  # gate 3 (re-parses + ruff-format-clean)
    _assert_partition(out)  # gate 4
    assert '                set_field(msg, "TOP", "1")\n' in out  # 16-space depth
    assert '            if grp["OBX-2"] == "NM":\n' in out  # nested header byte-identical


def test_cross_suite_crlf_non_ascii_reindents() -> None:
    # Adversarial: CRLF terminators + a multi-byte char on the MOVED line AND an adjacent non-moved line.
    # The moved line re-indents 4→8 while the CRLF terminators + the non-ASCII neighbours are byte-preserved.
    src = (
        "from messagefoundry import handler, Send, copy_field, set_field\r\n\r\n\r\n"
        '@handler("h")\r\n'  # 4
        "def h(msg):\r\n"  # 5
        '    if msg["X"]:\r\n'  # 6 if header
        '        copy_field(msg, "PID-3.1", "NK1-2.1")  # ünïcödé\r\n'  # 7 if body (anchor, non-ASCII)
        '    set_field(msg, "PID-5.1", "François")  # café — arrow →\r\n'  # 8 def level (moves IN, non-ASCII)
        '    return Send("OB", msg)\r\n'  # 9
    )
    out = rewrite_source(
        src,
        {
            "op": "move_row",
            "line_start": 8,
            "line_end": 8,
            "to_line_start": 7,
            "to_line_end": 7,
            "to_position": "after",
        },
    )
    assert out == _oracle_reindent_move(
        src, 8, 8, 7, 7, "after", "    ", "        ", set()
    )  # gate 2
    assert re.search(r"(?<!\r)\n", out) is None, "a bare LF leaked into a CRLF file"
    _assert_first_class(out)  # gate 3
    _assert_partition(out)  # gate 4
    assert (
        '        set_field(msg, "PID-5.1", "François")  # café — arrow →\r\n' in out
    )  # re-indented, raw
    assert "ünïcödé" in out  # the non-ASCII neighbour survived byte-for-byte


# =============================================================================
# multi-line-call param edits (the v2 set_params extension)
# =============================================================================


def test_multiline_call_edit_literal_arg() -> None:
    # A ruff-clean (magic-trailing-comma) multi-line split_field call; its `sep` ("^") literal is on its
    # own line 9. v2 edits that single-line literal even though the CALL spans lines 6-11.
    out = rewrite_source(
        _MULTILINE, {"op": "set_params", "line_start": 6, "line_end": 11, "params": {"sep": "~"}}
    )
    bl, al = _MULTILINE.splitlines(), out.splitlines()
    assert [i + 1 for i in range(len(bl)) if bl[i] != al[i]] == [9]
    assert al[8] == '        "~",'
    _assert_first_class(out)
    _assert_partition(out)


# =============================================================================
# gate 6 — adversarial: non-ASCII (edited+adjacent), CRLF, deep nesting, multi-line call
# =============================================================================

# Each source is dense + ruff-clean, carries a multi-byte char on the edited row AND an adjacent row,
# and exercises one op. The independent oracle uses the SAME newline set (CRLF/CR/LF) as the lens, so a
# multi-byte non-boundary char (é, —, →, François) is not a line split in either — the oracle stays valid.
_NON_ASCII = (
    "from messagefoundry import handler, Send, copy_field, set_field\n\n\n"
    '@handler("h")\n'
    "def h(msg):\n"
    '    set_field(msg, "PID-5.1", "François")  # café — arrow →\n'  # 6 non-ASCII edited/adjacent
    '    copy_field(msg, "PID-3.1", "NK1-2.1")  # ünïcödé\n'  # 7 non-ASCII adjacent
    '    set_field(msg, "MSH-3", "MEFOR")\n'  # 8
    '    return Send("OB", msg)\n'  # 9
)


def test_adversarial_delete_non_ascii_neighbors() -> None:
    out = rewrite_source(_NON_ASCII, {"op": "delete_row", "line_start": 7, "line_end": 7})
    assert out == _oracle_delete(_NON_ASCII, 7, 7)  # gate 2
    _assert_first_class(out)  # gate 3
    _assert_partition(out)  # gate 4
    assert "François" in out and "MEFOR" in out  # the non-ASCII neighbor survived byte-for-byte


def test_adversarial_insert_non_ascii_neighbors() -> None:
    # The inserted value here is ASCII ("B"); the point of the case is that the multi-byte NEIGHBOUR
    # lines (François / ünïcödé) are byte-preserved around the insertion. (Non-ASCII VALUES are emitted
    # raw now — see test_insert_non_ascii_value_is_raw below.)
    edit = {
        "op": "insert_row",
        "line_start": 6,
        "line_end": 6,
        "position": "after",
        "action": "set_field",
        "params": {"path": "A", "value": "B"},
    }
    out = rewrite_source(_NON_ASCII, edit)
    assert out == _oracle_insert(_NON_ASCII, 6, "after", '    msg.set("A", "B")\n')
    assert "François" in out and "ünïcödé" in out  # neighbours survived byte-for-byte
    _assert_first_class(out)
    _assert_partition(out)


def test_adversarial_move_non_ascii_neighbors() -> None:
    out = rewrite_source(
        _NON_ASCII, {"op": "move_row", "line_start": 6, "line_end": 6, "direction": "down"}
    )
    assert out == _oracle_swap(_NON_ASCII, (6, 6), (7, 7))
    _assert_first_class(out)
    _assert_partition(out)


_CRLF = _NON_ASCII.replace("\n", "\r\n")


@pytest.mark.parametrize(
    "edit,oracle",
    [
        ({"op": "delete_row", "line_start": 7, "line_end": 7}, "delete"),
        (
            {
                "op": "insert_row",
                "line_start": 6,
                "line_end": 6,
                "position": "after",
                "action": "set_field",
                "params": {"path": "A", "value": "B"},
            },
            "insert",
        ),
        ({"op": "move_row", "line_start": 6, "line_end": 6, "direction": "down"}, "move"),
    ],
    ids=["delete", "insert", "move"],
)
def test_adversarial_crlf(edit: dict[str, Any], oracle: str) -> None:
    out = rewrite_source(_CRLF, edit)
    # CRLF preserved throughout: no bare LF outside a CRLF pair.
    assert "\r\n" in out
    assert re.search(r"(?<!\r)\n", out) is None, "a bare LF leaked into a CRLF file"
    if oracle == "delete":
        assert out == _oracle_delete(_CRLF, 7, 7)
    elif oracle == "insert":
        assert out == _oracle_insert(_CRLF, 6, "after", '    msg.set("A", "B")\r\n')
    else:
        assert out == _oracle_swap(_CRLF, (6, 6), (7, 7))
    ast.parse(out)  # re-parses (gate 3)
    _assert_partition(out)  # gate 4


# Deep nesting: an action three suites deep (if → for → if). Imports convert_case too so the insert
# case below (which adds one) passes the import-scope guard.
_DEEP = (
    "from messagefoundry import handler, Send, copy_field, set_field, convert_case\n\n\n"
    '@handler("h")\n'
    "def h(msg):\n"
    '    if msg["MSH-9.1"] == "ORU":\n'  # 6
    "        for grp in msg.groups():\n"  # 7
    '            if grp["OBX-2"] == "NM":\n'  # 8
    '                copy_field(msg, "A", "B")\n'  # 9 (edited)
    '                set_field(msg, "C", "D")\n'  # 10 (sibling)
    '    return Send("OB", msg)\n'  # 11
)


def test_adversarial_deep_nesting_delete() -> None:
    out = rewrite_source(_DEEP, {"op": "delete_row", "line_start": 10, "line_end": 10})
    assert out == _oracle_delete(_DEEP, 10, 10)
    _assert_first_class(out)
    _assert_partition(out)


def test_adversarial_deep_nesting_move() -> None:
    out = rewrite_source(
        _DEEP, {"op": "move_row", "line_start": 9, "line_end": 9, "direction": "down"}
    )
    assert out == _oracle_swap(_DEEP, (9, 9), (10, 10))
    _assert_first_class(out)
    _assert_partition(out)


def test_adversarial_deep_nesting_insert() -> None:
    edit = {
        "op": "insert_row",
        "line_start": 9,
        "line_end": 9,
        "position": "after",
        "action": "convert_case",
        "params": {"path": "A", "mode": "lower"},
    }
    out = rewrite_source(_DEEP, edit)
    # 16-space indent (four levels deep).
    assert out == _oracle_insert(
        _DEEP, 9, "after", '                convert_case(msg, "A", "lower")\n'
    )
    _assert_first_class(out)
    _assert_partition(out)


# A multi-line recognized call as the structural target.
_MULTILINE = (
    "from messagefoundry import handler, Send, split_field, set_field\n\n\n"
    '@handler("h")\n'
    "def h(msg):\n"
    "    split_field(\n"  # 6
    "        msg,\n"  # 7
    '        "PID-5",\n'  # 8
    '        "^",\n'  # 9
    '        ["PID-5.1", "PID-5.2"],\n'  # 10
    "    )\n"  # 11
    '    set_field(msg, "MSH-3", "MEFOR")\n'  # 12
    '    return Send("OB", msg)\n'  # 13
)


def test_adversarial_delete_multiline_call() -> None:
    out = rewrite_source(_MULTILINE, {"op": "delete_row", "line_start": 6, "line_end": 11})
    assert out == _oracle_delete(_MULTILINE, 6, 11)  # the whole 6-line call span removed
    _assert_first_class(out)
    _assert_partition(out)
    assert "    split_field(" not in out  # the call is gone (the import line still names it)


def test_adversarial_move_multiline_call_down() -> None:
    # Move the multi-line split_field (6-11) down past the single-line set_field (12).
    out = rewrite_source(
        _MULTILINE, {"op": "move_row", "line_start": 6, "line_end": 11, "direction": "down"}
    )
    assert out == _oracle_swap(_MULTILINE, (6, 11), (12, 12))
    _assert_first_class(out)
    _assert_partition(out)


def test_adversarial_insert_after_multiline_call() -> None:
    edit = {
        "op": "insert_row",
        "line_start": 6,
        "line_end": 11,
        "position": "after",
        "action": "set_field",
        "params": {"path": "A", "value": "B"},
    }
    out = rewrite_source(_MULTILINE, edit)
    # "after" a multi-line call inserts past its LAST line (line 11); indent from the call's FIRST line.
    assert out == _oracle_insert(_MULTILINE, 11, "after", '    msg.set("A", "B")\n')
    _assert_first_class(out)
    _assert_partition(out)


# =============================================================================
# BOM + stale-coordinate guard across the structural ops
# =============================================================================


def test_structural_ops_preserve_leading_bom() -> None:
    src = "\ufeff" + DENSE
    for edit in (
        {"op": "delete_row", "line_start": 7, "line_end": 7},
        {
            "op": "insert_row",
            "line_start": 6,
            "line_end": 6,
            "position": "after",
            "action": "set_field",
            "params": {"path": "A", "value": "B"},
        },
        {"op": "move_row", "line_start": 7, "line_end": 7, "direction": "up"},
    ):
        out = rewrite_source(src, edit)
        assert out.startswith("\ufeff"), f"{edit['op']} dropped the BOM"
        assert out.count("\ufeff") == 1, f"{edit['op']} duplicated the BOM"
        ast.parse(out.removeprefix("\ufeff"))


def test_structural_stale_coordinate_guard() -> None:
    # A structural op carrying the projected row's source is refused when the buffer's row differs (F7).
    good = rewrite_source(
        DENSE,
        {
            "op": "delete_row",
            "line_start": 7,
            "line_end": 7,
            "expect_src": '    set_field(msg, "PID-3.1", "NEW")',
        },
    )
    assert 'set_field(msg, "PID-3.1", "NEW")' not in good
    with pytest.raises(LensRewriteError, match="stale coordinates"):
        rewrite_source(
            DENSE,
            {
                "op": "move_row",
                "line_start": 7,
                "line_end": 7,
                "direction": "up",
                "expect_src": '    set_field(msg, "STALE", "NEW")',
            },
        )


# =============================================================================
# gate 3 spot-check — messagefoundry check accepts a structurally-rewritten sample
# =============================================================================


def test_messagefoundry_check_accepts_rewritten_sample(tmp_path: Path) -> None:
    """Apply a structural edit to a real sample handler, then run ``messagefoundry check`` on it (gate 3).

    ``adt.py``'s handler is fully typed (``# type: ignore`` on the def) so the edit adds no mypy noise;
    the blocking legs (validate + ruff) must still pass — exit 0."""
    cfg = tmp_path / "config"
    shutil.copytree(SAMPLES, cfg)
    adt = cfg / "adt.py"
    src = adt.read_bytes().decode("utf-8")
    # ADR 0089: set_field inserts in its NATIVE msg.set(...) form, which references only `msg` — so it
    # needs NO vocabulary import (unlike the wrapper form, which the F821 import-scope guard would refuse
    # here). The output must still lint/validate cleanly (no unused import added).
    # Insert a set_field just before the send (locate the return line dynamically).
    contract = next(c for c in parse_source(src) if c["handler"] == "archive")
    send = next(r for r in contract["rows"] if r["kind"] == "send")
    edit = {
        "op": "insert_row",
        "line_start": send["line_start"],
        "line_end": send["line_end"],
        "position": "before",
        "action": "set_field",
        "params": {"path": "MSH-3", "value": "MEFOR"},
    }
    out = rewrite_source(src, edit)
    assert '    msg.set("MSH-3", "MEFOR")' in out
    adt.write_bytes(out.encode("utf-8"))
    proc = subprocess.run(
        [sys.executable, "-m", "messagefoundry", "check", "--config", str(cfg), "--env", "dev"],
        capture_output=True,
    )
    assert proc.returncode == 0, proc.stdout.decode("utf-8", "replace") + proc.stderr.decode(
        "utf-8", "replace"
    )


# =============================================================================
# CLI surface for the new ops
# =============================================================================


def test_cli_structural_ops_over_stdin(
    monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    import io

    for edit, needle in [
        ({"op": "delete_row", "line_start": 7, "line_end": 7}, None),
        (
            {
                "op": "insert_row",
                "line_start": 6,
                "line_end": 6,
                "position": "after",
                "action": "convert_case",
                "params": {"path": "A", "mode": "upper"},
            },
            "convert_case",
        ),
        ({"op": "move_row", "line_start": 7, "line_end": 7, "direction": "up"}, None),
    ]:

        class _Stdin:
            buffer = io.BytesIO(DENSE.encode("utf-8"))

        monkeypatch.setattr("sys.stdin", _Stdin())
        rc = main(["lens", "rewrite", "-", "--edit", json.dumps(edit)])
        assert rc == 0
        out = capsysbinary.readouterr().out.decode("utf-8")
        ast.parse(out)
        if needle:
            assert needle in out


def test_cli_structural_refusal_emits_json_error(
    monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    import io

    class _Stdin:
        buffer = io.BytesIO(DENSE.encode("utf-8"))

    monkeypatch.setattr("sys.stdin", _Stdin())
    rc = main(
        [
            "lens",
            "rewrite",
            "-",
            "--edit",
            json.dumps({"op": "move_row", "line_start": 6, "line_end": 6, "direction": "up"}),
        ]
    )
    assert rc == 1
    payload = json.loads(capsysbinary.readouterr().out.decode("utf-8"))
    assert "already first" in payload["error"]


# =============================================================================
# adversarial-review fold-ins (L4 v2): non-ASCII value fidelity + insert refusal boundary
# =============================================================================


def _literal_str_with(out: str, needle: str) -> str:
    """The single ``str`` Constant in ``out`` whose value contains ``needle`` (re-parsed from the output)."""
    return next(
        node.value
        for node in ast.walk(ast.parse(out))
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and needle in node.value
    )


def test_set_params_astral_value_is_value_preserving() -> None:
    # U+1F6F0 (🛰) is an ASTRAL (non-BMP) char. json.dumps(ensure_ascii=True) would emit a UTF-16
    # SURROGATE PAIR (🛰) that Python re-parses as TWO lone surrogates — a corrupted value
    # (len 7 not 6) that raises UnicodeEncodeError when the engine later encodes the outbound. The fix
    # emits the raw UTF-8 char, so the emitted literal round-trips to the intended string and encodes.
    value = "\U0001f6f0orbit"  # 🛰 + "orbit"
    out = rewrite_source(
        DENSE, {"op": "set_params", "line_start": 7, "line_end": 7, "params": {"value": value}}
    )
    emitted = _literal_str_with(out, "orbit")
    assert emitted == value, f"astral value corrupted: {emitted!r} != {value!r}"
    assert len(emitted) == len("orbit") + 1, (
        "the astral char must be ONE code point, not a surrogate pair"
    )
    out.encode("utf-8")  # must not raise UnicodeEncodeError (no lone surrogates leaked)
    _assert_first_class(out)  # gate 3 (ruff-format-clean)
    _assert_partition(out)  # gate 4


def test_set_params_bmp_non_ascii_value_is_raw_not_escaped() -> None:
    # A BMP non-ASCII value (新, U+65B0) must emit the RAW char — pre-fix json.dumps(ensure_ascii=True)
    # emitted the ASCII-escaped "新" (value-correct but non-canonical vs ruff, which never escapes
    # string contents, and unreadable to the analyst).
    value = "新"  # 新
    out = rewrite_source(
        DENSE, {"op": "set_params", "line_start": 7, "line_end": 7, "params": {"value": value}}
    )
    expected_line = '    set_field(msg, "PID-3.1", "' + value + '")'
    assert expected_line in out, "the BMP non-ASCII value must be emitted raw"
    assert "\\u65b0" not in out, "the value must NOT be ASCII-escaped (\\uXXXX diverges from ruff)"
    assert _literal_str_with(out, "新") == value
    _assert_first_class(out)  # ruff-format-clean (the escaped form is not canonical)
    _assert_partition(out)


def test_insert_non_ascii_value_is_raw() -> None:
    # insert_row shares _render_literal, so an inserted non-ASCII value is likewise raw + value-preserving.
    edit = {
        "op": "insert_row",
        "line_start": 6,
        "line_end": 6,
        "position": "after",
        "action": "set_field",
        "params": {"path": "MSH-3", "value": "café\U0001f6f0"},
    }
    out = rewrite_source(DENSE, edit)
    assert _literal_str_with(out, "caf") == "café\U0001f6f0"
    out.encode("utf-8")
    _assert_first_class(out)
    _assert_partition(out)


def test_insert_injects_import_when_vocab_not_imported() -> None:
    # ADR 0106 §6 (H): a module that imports only Send/handler — inserting a bare WRAPPER call (here
    # format_date, NOT one of the three native-form actions) would be an F821 undefined name. Rather than
    # refuse, the lens INJECTS ``from messagefoundry import format_date`` among the module's imports, so the
    # result re-parses and lints clean (import lines are a §6-sanctioned exception to the row-scoped splice).
    # (set_field/copy_field/delete_segment are exempt — native msg.* form, no import — see
    # test_insert_native_form_needs_no_import.)
    src = (
        "from messagefoundry import handler, Send\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    return Send("OB", msg)\n'
    )
    edit = {
        "op": "insert_row",
        "line_start": 6,
        "line_end": 6,
        "position": "before",
        "action": "format_date",
        "params": {"path": "PID-7", "out_fmt": "%Y%m%d"},
    }
    out = rewrite_source(src, edit)
    assert "from messagefoundry import format_date" in out  # import injected
    assert '    format_date(msg, "PID-7", "%Y%m%d")' in out
    assert (
        out.count("from messagefoundry import") == 2
    )  # original + injected (rewrite_source re-parses)
    # A module that ALREADY imports the wrapper inserts fine, with NO duplicate import (idempotent).
    imports_it = src.replace(
        "from messagefoundry import handler, Send",
        "from messagefoundry import handler, Send, format_date",
    )
    out2 = rewrite_source(imports_it, edit)
    assert '    format_date(msg, "PID-7", "%Y%m%d")' in out2
    assert out2.count("from messagefoundry import") == 1  # not injected again


def test_insert_allowed_with_wildcard_import() -> None:
    # A wildcard `from messagefoundry import *` binds an unknown set, so inserting a WRAPPER call (here
    # convert_case) is permitted (never a false refusal) — the name IS in scope at runtime. (The three
    # native-form actions don't consult import scope at all.)
    src = (
        'from messagefoundry import *\n\n\n@handler("h")\ndef h(msg):\n    return Send("OB", msg)\n'
    )
    out = rewrite_source(
        src,
        {
            "op": "insert_row",
            "line_start": 6,
            "line_end": 6,
            "position": "before",
            "action": "convert_case",
            "params": {"path": "A", "mode": "upper"},
        },
    )
    assert '    convert_case(msg, "A", "upper")' in out


def test_insert_assign_to_on_mutating_action_refused() -> None:
    # copy_field mutates in place and returns None; `x = copy_field(...)` would bind None AND re-parse as
    # a `code` row (an assignment is not a recognized action) — a silent recognized→code reclassification.
    # Only db/fhir/code_lookup return a value, so assign_to on an action is refused.
    with pytest.raises(LensRewriteError, match="cannot be assigned|returns no value"):
        rewrite_source(
            DENSE,
            {
                "op": "insert_row",
                "line_start": 6,
                "line_end": 6,
                "position": "after",
                "action": "copy_field",
                "assign_to": "x",
                "params": {"src": "A", "dst": "B"},
            },
        )
    # A lookup, by contrast, may still be assigned (Fix 4 must not over-refuse).
    src = (
        "from messagefoundry import handler, Send, db_lookup\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    return Send("OB", msg)\n'
    )
    out = rewrite_source(
        src,
        {
            "op": "insert_row",
            "line_start": 6,
            "line_end": 6,
            "position": "before",
            "action": "db_lookup",
            "assign_to": "row",
            "params": {"connection": "MPI", "statement": "select 1", "params": {"expr": "{}"}},
        },
    )
    assert '    row = db_lookup("MPI", "select 1", {})' in out


def test_insert_param_named_msg_refused() -> None:
    # `msg` is supplied automatically as the first positional arg; passing it as a param would splice a
    # duplicate `msg=` kwarg (`set_field(msg, "A", "B", msg="X")`) — a runtime TypeError. Refused.
    with pytest.raises(LensRewriteError, match="'msg' is supplied automatically"):
        rewrite_source(
            DENSE,
            {
                "op": "insert_row",
                "line_start": 6,
                "line_end": 6,
                "position": "after",
                "action": "set_field",
                "params": {"path": "A", "value": "B", "msg": "X"},
            },
        )


def test_set_params_bare_tuple_expr_refused() -> None:
    # `{"expr": "1, 2"}` is a bare tuple: spliced into one arg slot it injects an extra positional arg
    # (`set_field(msg, "PID-3.1", 1, 2)`) — arity-broken code that re-parses (so the syntax gate misses
    # it) but fails mypy-strict (gate 3). Refused.
    with pytest.raises(LensRewriteError, match="single argument"):
        rewrite_source(
            DENSE,
            {
                "op": "set_params",
                "line_start": 7,
                "line_end": 7,
                "params": {"value": {"expr": "1, 2"}},
            },
        )
    # A PARENTHESIZED single tuple stays one argument and is allowed (no over-refusal).
    ok = rewrite_source(
        DENSE,
        {
            "op": "set_params",
            "line_start": 7,
            "line_end": 7,
            "params": {"value": {"expr": "(1, 2)"}},
        },
    )
    assert 'set_field(msg, "PID-3.1", (1, 2))' in ok
    _assert_first_class(ok)


def test_insert_bare_tuple_expr_refused() -> None:
    with pytest.raises(LensRewriteError, match="single argument"):
        rewrite_source(
            DENSE,
            {
                "op": "insert_row",
                "line_start": 6,
                "line_end": 6,
                "position": "after",
                "action": "set_field",
                "params": {"path": "A", "value": {"expr": "1, 2"}},
            },
        )


def test_cli_lens_parse_stdin(
    monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    # The IDE re-projects the live buffer via `lens parse - --json` (source over stdin) after a
    # structural edit; assert the CLI reads the buffer and emits the row contract for it.
    import io

    class _Stdin:
        buffer = io.BytesIO(DENSE.encode("utf-8"))

    monkeypatch.setattr("sys.stdin", _Stdin())
    rc = main(["lens", "parse", "-", "--json"])
    assert rc == 0
    payload = json.loads(capsysbinary.readouterr().out.decode("utf-8"))
    assert payload["module"] == "<stdin>"
    assert payload["handlers"][0]["handler"] == "enrich"
    kinds = [r["kind"] for r in payload["handlers"][0]["rows"]]
    assert kinds == ["action", "action", "action", "send"]


# =============================================================================
# ADR 0089 — NATIVE-form insert (recognition-first) + insert-adjacency guard fix
# =============================================================================

# A handler importing ONLY handler/Send — no action vocabulary. A NATIVE-form insert
# (set_field/copy_field/delete_segment) needs no import (it references only `msg`), so it succeeds here
# where a wrapper insert would be refused (see test_insert_refused_when_vocab_not_imported).
_NO_VOCAB = (
    "from messagefoundry import handler, Send\n\n\n"
    '@handler("h")\n'
    "def h(msg):\n"
    '    return Send("OB", msg)\n'  # line 6
)


def _insert_before_send(action: str, params: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """Insert ``action`` before ``_NO_VOCAB``'s send, assert gates 3/4, and return (output, reparsed rows).

    The reparsed rows are the round-trip contract: the inserted native line must be recognized back as
    the SAME editable action row (ADR 0089 Phase A)."""
    edit = {
        "op": "insert_row",
        "line_start": 6,
        "line_end": 6,
        "position": "before",
        "action": action,
        "params": params,
    }
    out = rewrite_source(_NO_VOCAB, edit)
    _assert_first_class(out)  # gate 3 (re-parses + ruff-format-clean)
    _assert_partition(out)  # gate 4
    assert _ruff_check_clean(out), f"{action} native insert is not ruff-check-clean (F821?)"
    assert out.count("import") == _NO_VOCAB.count("import"), "native insert must add no import"
    return out, parse_source(out)[0]["rows"]


def test_insert_native_set_field_round_trips() -> None:
    out, rows = _insert_before_send("set_field", {"path": "PID-3.1", "value": "NEW"})
    assert '    msg.set("PID-3.1", "NEW")\n' in out  # native form, no wrapper name
    assert "set_field(" not in out
    assert (rows[0]["kind"], rows[0]["action"]) == ("action", "set_field")
    assert rows[0]["params"] == {"path": "PID-3.1", "value": "NEW"}
    assert rows[0]["literal_params"] == ["path", "value"]


def test_insert_native_copy_field_round_trips() -> None:
    out, rows = _insert_before_send("copy_field", {"src": "PID-5.1", "dst": "NK1-2.1"})
    assert '    msg.set("NK1-2.1", msg.field("PID-5.1") or "")\n' in out
    assert (rows[0]["kind"], rows[0]["action"]) == ("action", "copy_field")
    assert rows[0]["params"] == {"src": "PID-5.1", "dst": "NK1-2.1"}
    assert rows[0]["literal_params"] == ["src", "dst"]


def test_insert_native_delete_segment_round_trips() -> None:
    out, rows = _insert_before_send("delete_segment", {"segment_id": "Z01"})
    assert '    msg.delete_segments("Z01")\n' in out  # rendered as the plural method
    assert (rows[0]["kind"], rows[0]["action"]) == ("action", "delete_segment")
    assert rows[0]["params"] == {"segment_id": "Z01"}
    assert rows[0]["literal_params"] == ["segment_id"]


def test_insert_native_empty_params_render_empty_string_literals() -> None:
    # ADR 0089: a native insert with missing params renders empty string literals — a valid, Phase-A-
    # recognized, editable row (the analyst then fills the paths in).
    out, rows = _insert_before_send("set_field", {})
    assert '    msg.set("", "")\n' in out
    assert (rows[0]["kind"], rows[0]["action"]) == ("action", "set_field")
    assert rows[0]["params"] == {"path": "", "value": ""}
    assert rows[0]["literal_params"] == ["path", "value"]


def test_insert_native_expr_value_round_trips() -> None:
    # A native set_field whose value is a non-copy expression: the expr is spliced verbatim and reparses
    # as a set_field whose `value` is read-only (only `path` is an editable literal). (A value that is
    # itself `msg.field(...)` would instead round-trip as copy_field — that IS the copy idiom.)
    out, rows = _insert_before_send(
        "set_field", {"path": "PID-3.1", "value": {"expr": 'msg["PID-5.1"]'}}
    )
    assert '    msg.set("PID-3.1", msg["PID-5.1"])\n' in out
    assert (rows[0]["kind"], rows[0]["action"]) == ("action", "set_field")
    assert rows[0]["params"] == {"path": "PID-3.1", "value": 'msg["PID-5.1"]'}
    assert rows[0]["literal_params"] == ["path"]


# A body with a read-only code row (line 6) and a control header (line 7) — the guard-fix targets.
_CODE_AND_CONTROL = (
    "from messagefoundry import handler, Send\n\n\n"
    '@handler("h")\n'
    "def h(msg):\n"
    "    x = compute(msg)\n"  # 6 code row (read-only)
    '    if msg["MSH-9.1"] == "ADT":\n'  # 7 control header (read-only)
    '        msg.set("A", "B")\n'  # 8 nested action
    '    return Send("OB", msg)\n'  # 9 send
)


def test_insert_after_code_row_succeeds_and_round_trips() -> None:
    # guard fix: an insert uses the anchor only as a POSITION, so it may sit next to a read-only CODE row.
    out = rewrite_source(
        _CODE_AND_CONTROL,
        {
            "op": "insert_row",
            "line_start": 6,
            "line_end": 6,
            "position": "after",
            "action": "set_field",
            "params": {"path": "C", "value": "D"},
        },
    )
    assert out == _oracle_insert(_CODE_AND_CONTROL, 6, "after", '    msg.set("C", "D")\n')  # gate 2
    _assert_first_class(out)
    _assert_partition(out)
    rows = parse_source(out)[0]["rows"]
    assert ("action", "set_field") in [(r["kind"], r.get("action")) for r in rows]  # round-trip


def test_insert_before_control_row_succeeds_and_round_trips() -> None:
    # guard fix: an insert may also sit next to a read-only CONTROL row. Insert BEFORE the if header so
    # the new statement lands at the header's (outer) indent — well-formed Python.
    out = rewrite_source(
        _CODE_AND_CONTROL,
        {
            "op": "insert_row",
            "line_start": 7,
            "line_end": 7,
            "position": "before",
            "action": "delete_segment",
            "params": {"segment_id": "Z9"},
        },
    )
    assert out == _oracle_insert(
        _CODE_AND_CONTROL, 7, "before", '    msg.delete_segments("Z9")\n'
    )  # gate 2
    _assert_first_class(out)
    _assert_partition(out)
    rows = parse_source(out)[0]["rows"]
    assert ("action", "delete_segment") in [(r["kind"], r.get("action")) for r in rows]


def test_insert_after_blank_first_code_row_indents_to_code_not_blank() -> None:
    # Regression: a code row can span a leading BLANK line + a comment (common in real handlers); the
    # insert must indent to the CODE (suite level), not the blank line's 0-indent — else the new call
    # dedents out of the suite and Python raises "unexpected indent" on the next line (refused, no change).
    src = (
        '@handler("h")\n'
        "def h(msg):\n"
        '    msg.set("MSH-12.1", "2.3")\n'
        "\n"
        "    # ITM: clear ITM-1-2 on each ITM segment\n"
        '    for i in range(1, msg.count_segments("ITM") + 1):\n'
        '        msg.set("ITM-1.2", "", occurrence=i)\n'
        "    return Send(OB, msg)\n"
    )
    code = next(r for r in parse_source(src)[0]["rows"] if r["kind"] == "code")
    out = rewrite_source(
        src,
        {
            "op": "insert_row",
            "line_start": code["line_start"],
            "line_end": code["line_end"],
            "position": "after",
            "action": "set_field",
            "params": {"path": "P", "value": "V"},
        },
    )
    assert '\n    msg.set("P", "V")\n' in out  # indented to the suite (4 spaces)
    assert '\nmsg.set("P", "V")\n' not in out  # NOT dedented to column 0 (the bug)
    _assert_partition(out)
    rows = parse_source(out)[0]["rows"]
    assert ("action", "set_field") in [(r["kind"], r.get("action")) for r in rows]


def test_mutating_ops_still_refuse_code_control_rows() -> None:
    # set_params/delete_row MUTATE the row itself, so they still refuse a read-only code/control row (only
    # insert_row — position anchor — and move_row — a same-suite reposition, ADR 0089 block-move — may
    # target them).
    with pytest.raises(LensRewriteError, match="'code' row"):
        rewrite_source(_CODE_AND_CONTROL, {"op": "delete_row", "line_start": 6, "line_end": 6})
    with pytest.raises(LensRewriteError, match="'control' row"):
        rewrite_source(
            _CODE_AND_CONTROL,
            {"op": "set_params", "line_start": 7, "line_end": 7, "params": {}},
        )


# A native row carrying occurrence=, a trailing comment, non-ASCII, and CRLF terminators — the inserted
# native step must leave every one of these bytes untouched (byte-stability, gate 2).
_NATIVE_ADVERSARIAL = (
    "from messagefoundry import handler, Send\r\n\r\n\r\n"
    '@handler("h")\r\n'
    "def h(msg):\r\n"
    '    msg.set("PID-5.1", "François", occurrence=i)  # café — arrow →\r\n'  # 6
    '    msg.delete_segments("Z01")\r\n'  # 7
    '    return Send("OB", msg)\r\n'  # 8
)


def test_insert_native_adversarial_neighbors_byte_preserved() -> None:
    edit = {
        "op": "insert_row",
        "line_start": 6,
        "line_end": 6,
        "position": "after",
        "action": "copy_field",
        "params": {"src": "PID-5.1", "dst": "NK1-2.1"},
    }
    out = rewrite_source(_NATIVE_ADVERSARIAL, edit)
    # gate 2: only the inserted line is added; the CRLF terminator matches the anchor row.
    assert out == _oracle_insert(
        _NATIVE_ADVERSARIAL, 6, "after", '    msg.set("NK1-2.1", msg.field("PID-5.1") or "")\r\n'
    )
    # occurrence=, the comment, and the non-ASCII neighbour survived byte-for-byte.
    assert "occurrence=i)  # café — arrow →" in out
    assert re.search(r"(?<!\r)\n", out) is None, "a bare LF leaked into a CRLF file"
    ast.parse(out)  # re-parses (gate 3)
    _assert_partition(out)  # gate 4
    rows = parse_source(out)[0]["rows"]
    assert ("action", "copy_field") in [(r["kind"], r.get("action")) for r in rows]
    # the occurrence-carrying set is still an editable set_field with occurrence bound read-only.
    occ = next(r for r in rows if r.get("params", {}).get("occurrence") == "i")
    assert occ["action"] == "set_field"
    assert "occurrence" not in occ["literal_params"]
