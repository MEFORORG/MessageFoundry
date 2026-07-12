# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``lens rewrite`` — the Steps view BLOCK paste op (``paste_block``) + the CUT delete-broadening (ADR
0076 §5 / ADR 0089 block-cut).

The hard gates (task spec), verified against **independent oracles** (regex line split / multiset — a
different mechanism than the lens's char-loop math):

* **byte-stability (gate 2):** every line OUTSIDE the newly-inserted paste region is byte-identical —
  checked by removing the inserted run from the output (regex ``_keepends`` split) and comparing to the
  input, and by a multiset line check for same-depth pastes.
* **first-class output (gate 3):** after a paste the result re-parses (:mod:`ast`) and is
  ``ruff format --check``-clean — enforced per-op by construction (the reindent guards), NOT a ruff
  subprocess in the code under test.
* **coverage-partition holds (gate 4):** on the rewritten source, rows still exactly partition each def
  body.
* **refusal boundary (gate 5):** empty/multi-statement/unparseable clipboard, a deeper re-indent over the
  column limit, a shallower one that would collapse a wrapped call, a stale anchor, a paste ``after`` a
  control header — all refuse (``LensRewriteError``) with ZERO change.
* **adversarial (gate 6):** non-ASCII on the pasted AND adjacent lines, CRLF, tabs, deep nesting, a
  multi-line triple-quoted interior.

Static-only throughout: the module is never imported/executed."""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

from messagefoundry.lens import LensRewriteError, parse_source, rewrite_source

REPO_ROOT = Path(__file__).resolve().parents[1]


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


def _oracle_paste_non_inserted(src: str, out: str, insert_idx: int, n_block: int) -> str:
    """Byte-stability oracle: remove the ``n_block`` inserted lines at ``insert_idx`` from ``out`` (regex
    line split) and return the remainder — it must equal the original ``src`` for a middle paste into a
    newline-terminated file (gate 2, independent of the lens char loop)."""
    out_lines = _keepends(out)
    remaining = out_lines[:insert_idx] + out_lines[insert_idx + n_block :]
    return "".join(remaining)


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


def _literal_str_with(out: str, needle: str) -> str:
    """The single ``str`` Constant in ``out`` whose value contains ``needle`` (re-parsed from the output)."""
    return next(
        node.value
        for node in ast.walk(ast.parse(out))
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and needle in node.value
    )


# A dense, ruff-clean handler (the vocabulary target shape) reused across the paste tests.
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
# E1-E3 — paste a leaf at same / deeper / shallower depth
# =============================================================================


def test_paste_leaf_same_depth_byte_stable() -> None:
    block = '    set_field(msg, "AAA", "BBB")'  # a 4-space leaf (distinct from any DENSE line)
    out = rewrite_source(
        DENSE,
        {"op": "paste_block", "line_start": 7, "line_end": 7, "position": "after", "block": block},
    )
    # inserted after line 7 → insert_idx = 7, one block line
    assert _oracle_paste_non_inserted(DENSE, out, 7, 1) == DENSE  # gate 2 (independent, remove-run)
    assert sorted(out.splitlines()) == sorted(DENSE.splitlines() + block.splitlines())  # multiset
    _assert_first_class(out)  # gate 3
    _assert_partition(out)  # gate 4
    assert '    set_field(msg, "AAA", "BBB")\n' in out  # verbatim at 4-space depth


def test_paste_leaf_deeper_reindents() -> None:
    src = (
        "from messagefoundry import handler, Send, copy_field, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    if msg["A"]:\n'  # 6
        '        copy_field(msg, "A", "B")\n'  # 7 (8-space body, anchor)
        '    return Send("OB", msg)\n'  # 8
    )
    block = '    set_field(msg, "C", "D")'  # captured at 4-space
    out = rewrite_source(
        src,
        {"op": "paste_block", "line_start": 7, "line_end": 7, "position": "after", "block": block},
    )
    assert '        set_field(msg, "C", "D")\n' in out  # reindented 4→8
    assert _oracle_paste_non_inserted(src, out, 7, 1) == src  # gate 2
    _assert_first_class(out)
    _assert_partition(out)


def test_paste_leaf_shallower_reindents() -> None:
    src = (
        "from messagefoundry import handler, Send, copy_field, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    copy_field(msg, "A", "B")\n'  # 6 (4-space anchor)
        '    if msg["Z"]:\n'  # 7
        '        set_field(msg, "C", "D")\n'  # 8
        '    return Send("OB", msg)\n'  # 9
    )
    block = '        set_field(msg, "E", "F")'  # captured at 8-space
    out = rewrite_source(
        src,
        {"op": "paste_block", "line_start": 6, "line_end": 6, "position": "after", "block": block},
    )
    assert '    set_field(msg, "E", "F")\n' in out  # dedented 8→4
    assert _oracle_paste_non_inserted(src, out, 6, 1) == src
    _assert_first_class(out)
    _assert_partition(out)


# =============================================================================
# E4 — paste a WHOLE if/for block (header + body re-indent uniformly)
# =============================================================================


def test_paste_whole_if_block_dedents() -> None:
    # Capture an if block nested inside a for (8-space header + 12-space body), paste at def level (4-space).
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "TOP", "1")\n'  # 6 (4-space anchor)
        "    for grp in msg.groups():\n"  # 7
        '        if grp["OBX-2"] == "NM":\n'  # 8 (8-space if header — captured)
        '            set_field(msg, "A", "B")\n'  # 9 (12-space body)
        '    return Send("OB", msg)\n'  # 10
    )
    # the captured if block = header (8-space) + body (12-space), LF-joined (the clipboard model)
    block = '        if grp["OBX-2"] == "NM":\n            set_field(msg, "A", "B")'
    out = rewrite_source(
        src,
        {"op": "paste_block", "line_start": 6, "line_end": 6, "position": "after", "block": block},
    )
    # dedent 8→4: header at 4-space, body at 8-space — the uniform shift preserves relative structure.
    assert '    if grp["OBX-2"] == "NM":\n' in out
    assert '        set_field(msg, "A", "B")\n' in out
    assert _oracle_paste_non_inserted(src, out, 6, 2) == src  # 2 block lines
    _assert_first_class(out)
    _assert_partition(out)


# =============================================================================
# E5 — paste a SEND row (the def-wrapper parse admits `return`)
# =============================================================================


def test_paste_send_row_parses_return() -> None:
    # A copied ``return Send(...)`` is valid only inside a function body — the ``def _f():`` wrapper is why
    # it parses (an ``if True:`` wrapper would raise "'return' outside function").
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "A", "B")\n'  # 6 anchor
        '    return Send("OB", msg)\n'  # 7 send
    )
    block = '    return Send("OB2", msg)'  # a captured send row
    out = rewrite_source(
        src,
        {"op": "paste_block", "line_start": 6, "line_end": 6, "position": "after", "block": block},
    )
    assert '    return Send("OB2", msg)\n' in out
    assert _oracle_paste_non_inserted(src, out, 6, 1) == src
    _assert_first_class(
        out
    )  # gate 3 — the `return` block parsed + spliced (dead code is format-clean)
    _assert_partition(out)


# =============================================================================
# E6/E7 — a multi-line triple-quoted interior is frozen; CRLF re-terminates faithfully
# =============================================================================


@pytest.mark.parametrize("term", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_paste_multiline_string_interior_preserved(term: str) -> None:
    src = (
        "from messagefoundry import handler, Send, db_lookup\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "A", "B")\n'  # 6 anchor (4-space)
        '    return Send("OB", msg)\n'  # 7
    ).replace("\n", term)
    # a captured db_lookup with a multi-line triple-quoted SQL interior (4-space, magic-trailing-comma).
    block = (
        "    row = db_lookup(\n"
        '        "MPI",\n'
        '        """\n'
        "        SELECT mrn FROM patients\n"
        '        """,\n'
        "        {},\n"
        "    )"
    )
    out = rewrite_source(
        src,
        {"op": "paste_block", "line_start": 6, "line_end": 6, "position": "after", "block": block},
    )
    # the SQL string VALUE is unchanged (re-parse; Python universal-newline-normalizes the interior).
    assert _literal_str_with(out, "SELECT mrn") == "\n        SELECT mrn FROM patients\n        "
    if term == "\r\n":
        assert re.search(r"(?<!\r)\n", out) is None, "a bare LF leaked into a CRLF file"
    n_block = block.count("\n") + 1
    assert (
        _oracle_paste_non_inserted(src, out, 6, n_block) == src
    )  # gate 2 (same depth, no reindent)
    _assert_first_class(out)
    _assert_partition(out)


def test_paste_multiline_string_reindent_freezes_interior() -> None:
    # DEEPER paste of a multi-line-string block: the OPENING/code lines shift, the string INTERIOR is frozen
    # (byte-preserved), so the value is unchanged after a depth change (E6 in the reindent path).
    src = (
        "from messagefoundry import handler, Send, db_lookup\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    if msg["A"]:\n'  # 6
        '        set_field(msg, "Z", "Z")\n'  # 7 (8-space anchor)
        '    return Send("OB", msg)\n'  # 8
    )
    block = (
        "    row = db_lookup(\n"
        '        "MPI",\n'
        '        """\n'
        "        SELECT mrn\n"
        '        """,\n'
        "        {},\n"
        "    )"
    )
    out = rewrite_source(
        src,
        {"op": "paste_block", "line_start": 7, "line_end": 7, "position": "after", "block": block},
    )
    assert _literal_str_with(out, "SELECT mrn") == "\n        SELECT mrn\n        "  # value frozen
    assert (
        "        row = db_lookup(\n" in out
    )  # the opening code line shifted 4→8 (anchor is 8-space)
    assert '            "MPI",\n' in out  # a non-frozen continuation shifted with it (8→12)
    n_block = block.count("\n") + 1
    assert _oracle_paste_non_inserted(src, out, 7, n_block) == src  # gate 2
    ast.parse(out)  # gate 3 (valid)
    _assert_partition(out)


# =============================================================================
# E8/E9 — EOF without a trailing newline; tab-indented source
# =============================================================================


def test_paste_eof_no_newline_appends() -> None:
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    return Send("OB", msg)'  # 6 — NO trailing newline
    )
    block = '    set_field(msg, "A", "B")'
    out = rewrite_source(
        src,
        {"op": "paste_block", "line_start": 6, "line_end": 6, "position": "after", "block": block},
    )
    # the formerly-final line is terminated first, the block appended, a ruff-clean trailing newline kept.
    assert '    return Send("OB", msg)\n    set_field(msg, "A", "B")\n' in out
    assert out.endswith('    set_field(msg, "A", "B")\n')
    _assert_first_class(out)
    _assert_partition(out)


def test_paste_tab_indented_source() -> None:
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '\tset_field(msg, "A", "B")\n'  # 6 tab-indented anchor
        '\treturn Send("OB", msg)\n'  # 7 tab
    )
    block = '\tset_field(msg, "C", "D")'  # tab-indented leaf (same tab depth)
    out = rewrite_source(
        src,
        {"op": "paste_block", "line_start": 6, "line_end": 6, "position": "after", "block": block},
    )
    assert '\tset_field(msg, "C", "D")\n' in out  # tab preserved (real-whitespace-string copy)
    assert _oracle_paste_non_inserted(src, out, 6, 1) == src  # gate 2
    ast.parse(out)  # gate 3 (ruff format would convert tabs → not asserted format-clean here)
    _assert_partition(out)


# =============================================================================
# gate 6 — non-ASCII on the pasted AND adjacent lines
# =============================================================================


def test_paste_non_ascii_neighbors_and_value() -> None:
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "PID-5.1", "François")  # café — arrow →\n'  # 6 non-ASCII adjacent
        '    return Send("OB", msg)\n'  # 7
    )
    block = '    set_field(msg, "PID-3.1", "naïve")  # ünïcödé'  # non-ASCII pasted
    out = rewrite_source(
        src,
        {"op": "paste_block", "line_start": 6, "line_end": 6, "position": "after", "block": block},
    )
    assert "François" in out and "café — arrow →" in out  # the neighbour survived byte-for-byte
    assert '    set_field(msg, "PID-3.1", "naïve")  # ünïcödé\n' in out
    assert _oracle_paste_non_inserted(src, out, 6, 1) == src
    out.encode("utf-8")  # no lone surrogates
    _assert_first_class(out)
    _assert_partition(out)


# =============================================================================
# gate 5 — refusals, each ZERO change (E10-E12)
# =============================================================================


def test_paste_empty_block_refused() -> None:
    with pytest.raises(LensRewriteError, match="non-empty 'block'"):
        rewrite_source(DENSE, {"op": "paste_block", "line_start": 7, "line_end": 7, "block": ""})


def test_paste_multi_statement_clipboard_refused() -> None:
    block = '    set_field(msg, "A", "B")\n    set_field(msg, "C", "D")'
    with pytest.raises(LensRewriteError, match="exactly one step or block"):
        rewrite_source(
            DENSE,
            {
                "op": "paste_block",
                "line_start": 7,
                "line_end": 7,
                "position": "after",
                "block": block,
            },
        )


def test_paste_unparseable_clipboard_refused() -> None:
    with pytest.raises(LensRewriteError, match="not valid Python"):
        rewrite_source(
            DENSE,
            {
                "op": "paste_block",
                "line_start": 7,
                "line_end": 7,
                "position": "after",
                "block": "    msg.set([",
            },
        )


def test_paste_deeper_over_line_length_refused() -> None:
    # A 4-space leaf that FITS at 4-space (99 cols) but overflows at the deeper 8-space depth (103) — the
    # DEEPER over-run refusal (:func:`_reindent_block`).
    long_val = "X" * 72  # 27 + 72 = 99 at 4-space; 31 + 72 = 103 at 8-space
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    if msg["A"]:\n'  # 6
        '        set_field(msg, "Z", "Z")\n'  # 7 (8-space anchor)
        '    return Send("OB", msg)\n'  # 8
    )
    block = '    set_field(msg, "P", "' + long_val + '")'
    with pytest.raises(LensRewriteError, match="column"):
        rewrite_source(
            src,
            {
                "op": "paste_block",
                "line_start": 7,
                "line_end": 7,
                "position": "after",
                "block": block,
            },
        )


def test_paste_shallower_collapsible_wrapped_refused() -> None:
    # A bracket-wrapped call captured DEEP (12-space); pasting it SHALLOWER (4-space) would let ruff collapse
    # it to one line — refuse (a length check can't see it: every wrapped line is short).
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "TOP", "1")\n'  # 6 (4-space anchor)
        '    if msg["A"]:\n'  # 7
        "        for grp in msg.groups():\n"  # 8
        "            set_field(\n"  # 9 (12-space, bracket-wrapped — captured)
        '                "PATH",\n'  # 10
        '                "value",\n'  # 11
        "            )\n"  # 12
        '    return Send("OB", msg)\n'  # 13
    )
    block = (
        '            set_field(\n                "PATH",\n                "value",\n            )'
    )
    with pytest.raises(LensRewriteError, match="collapse"):
        rewrite_source(
            src,
            {
                "op": "paste_block",
                "line_start": 6,
                "line_end": 6,
                "position": "after",
                "block": block,
            },
        )


def test_paste_stale_coordinate_refused() -> None:
    block = '    set_field(msg, "A", "B")'
    with pytest.raises(LensRewriteError, match="stale coordinates"):
        rewrite_source(
            DENSE,
            {
                "op": "paste_block",
                "line_start": 7,
                "line_end": 7,
                "position": "after",
                "block": block,
                "expect_src": '    set_field(msg, "STALE", "X")',
            },
        )


def test_paste_after_control_header_refused_by_reparse() -> None:
    # Pasting AFTER an if HEADER lands at the header's OUTER (4-space) indent between the header and its
    # 8-space body → an IndentationError → the reparse gate refuses (zero change). Same limit as toolbar Add.
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    if msg["A"]:\n'  # 6 control header
        '        set_field(msg, "B", "C")\n'  # 7
        '    return Send("OB", msg)\n'  # 8
    )
    block = '    set_field(msg, "D", "E")'
    with pytest.raises(LensRewriteError, match="invalid Python"):
        rewrite_source(
            src,
            {
                "op": "paste_block",
                "line_start": 6,
                "line_end": 6,
                "position": "after",
                "block": block,
            },
        )


def test_paste_before_position_leaf() -> None:
    # A "before" paste inserts at line_start - 1 (the toolbar-Add rule for a send anchor).
    block = '    set_field(msg, "NEW", "V")'
    out = rewrite_source(
        DENSE,
        {"op": "paste_block", "line_start": 9, "line_end": 9, "position": "before", "block": block},
    )
    # before line 9 → insert_idx = 8
    assert _oracle_paste_non_inserted(DENSE, out, 8, 1) == DENSE
    assert '    set_field(msg, "NEW", "V")\n    return Send("OB_X", msg)\n' in out
    _assert_first_class(out)
    _assert_partition(out)


def test_paste_bad_position_refused() -> None:
    with pytest.raises(LensRewriteError, match="'before' or 'after'"):
        rewrite_source(
            DENSE,
            {
                "op": "paste_block",
                "line_start": 7,
                "line_end": 7,
                "position": "sideways",
                "block": '    set_field(msg, "A", "B")',
            },
        )


# =============================================================================
# P7 — the CUT delete-broadening (whole if/for block by header)
# =============================================================================


def test_delete_whole_if_block_by_header() -> None:
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "A", "B")\n'  # 6
        '    if msg["Z"]:\n'  # 7 if header
        '        set_field(msg, "C", "D")\n'  # 8 body
        '    return Send("OB", msg)\n'  # 9
    )
    out = rewrite_source(src, {"op": "delete_row", "line_start": 7, "line_end": 7})
    assert out == _oracle_delete(
        src, 7, 8
    )  # gate 2 (whole block removed; other lines byte-identical)
    assert 'if msg["Z"]:' not in out and 'set_field(msg, "C", "D")' not in out
    assert 'set_field(msg, "A", "B")' in out
    _assert_first_class(out)
    _assert_partition(out)


def test_delete_whole_for_block_by_header() -> None:
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "A", "B")\n'  # 6
        "    for grp in msg.groups():\n"  # 7 for header
        '        set_field(msg, "C", "D")\n'  # 8
        '        set_field(msg, "E", "F")\n'  # 9
        '    return Send("OB", msg)\n'  # 10
    )
    out = rewrite_source(src, {"op": "delete_row", "line_start": 7, "line_end": 7})
    assert out == _oracle_delete(src, 7, 9)  # the whole for block (7-9) removed
    _assert_first_class(out)
    _assert_partition(out)


def test_delete_sole_block_of_suite_refused() -> None:
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        "    for grp in msg.groups():\n"  # 6 the SOLE statement of the def body
        '        set_field(msg, "C", "D")\n'  # 7
    )
    with pytest.raises(LensRewriteError, match="only statement"):
        rewrite_source(src, {"op": "delete_row", "line_start": 6, "line_end": 6})


def test_delete_leaf_unchanged_by_broadening() -> None:
    out = rewrite_source(DENSE, {"op": "delete_row", "line_start": 7, "line_end": 7})
    assert out == _oracle_delete(DENSE, 7, 7)  # byte-identical to today (leaf delete)
    _assert_first_class(out)
    _assert_partition(out)


def test_delete_code_and_elif_else_still_refused() -> None:
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        "    x = compute(msg)\n"  # 6 code row
        '    if msg["A"]:\n'  # 7 if header
        '        set_field(msg, "B", "C")\n'  # 8
        "    else:\n"  # 9 else header
        '        set_field(msg, "D", "E")\n'  # 10
        '    return Send("OB", msg)\n'  # 11
    )
    with pytest.raises(LensRewriteError, match="'code' row"):
        rewrite_source(src, {"op": "delete_row", "line_start": 6, "line_end": 6})
    with pytest.raises(LensRewriteError, match="'control' row"):
        rewrite_source(src, {"op": "delete_row", "line_start": 9, "line_end": 9})
