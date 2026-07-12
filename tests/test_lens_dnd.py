# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Drag-and-drop reorder — ``move_row`` to an ARBITRARY sibling position (to_line_start/to_position).

Byte-stability (gate 2) is asserted against an INDEPENDENT regex-driven line oracle, not the lens's own
splice math. Cross-nesting + non-recognized moves are refused; the re-parse gate backstops a bad drop."""

from __future__ import annotations

import ast
import re

import pytest

from messagefoundry.lens import LensRewriteError, parse_source, rewrite_source


def _lines(s: str) -> list[str]:
    parts = re.split(r"(\r\n|\r|\n)", s)
    out: list[str] = []
    for i in range(0, len(parts) - 1, 2):
        out.append(parts[i] + parts[i + 1])
    if parts[-1]:
        out.append(parts[-1])
    return out


def _oracle_move(src: str, ls: int, le: int, to_ls: int, to_le: int, position: str) -> str:
    lines = _lines(src)
    block = lines[ls - 1 : le]
    n = le - ls + 1
    del lines[ls - 1 : le]
    if ls < to_ls:
        to_ls, to_le = to_ls - n, to_le - n
    idx = (to_ls - 1) if position == "before" else to_le
    lines[idx:idx] = block
    return "".join(lines)


def _term(line: str) -> str:
    for t in ("\r\n", "\n", "\r"):
        if line.endswith(t):
            return t
    return ""


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
    """Independent oracle for a CROSS-suite move that re-indents the moved block.

    A DIFFERENT mechanism than the lens char loop: regex line-splitting (:func:`_lines`) + an explicit
    prefix-string swap + a caller-supplied interior-freeze set. For an equal-depth move (``src_prefix ==
    dst_prefix``, empty ``frozen_rel``) it degenerates to :func:`_oracle_move`. The test author supplies the
    prefixes + frozen indices by inspection, so this never calls the code under test (gate 2 stays honest)."""
    lines = _lines(src)
    block = lines[ls - 1 : le]
    reblock: list[str] = []
    for i, line in enumerate(block):
        term = _term(line)
        content = line[: len(line) - len(term)]
        if i in frozen_rel:
            reblock.append(line)  # frozen string/f-string interior — byte-identical
        elif content.strip() == "":
            reblock.append(term)  # blank line — drop any trailing ws, keep position
        elif content.startswith(src_prefix):
            reblock.append(dst_prefix + content[len(src_prefix) :] + term)
        else:
            reblock.append(line)  # not expected in an accepted case
    n = le - ls + 1
    del lines[ls - 1 : le]
    # Independent index math: after deleting [ls, le], any original line > le shifts up by n. Insert "before"
    # → before original line to_ls; "after" → after original line to_le. Correct for a disjoint sibling AND
    # for the overlap case (the moved line inside the dest BLOCK's span — "move a body stmt out of its loop").
    if position == "before":
        idx = (to_ls - 1) - (n if le < to_ls else 0)
    else:
        idx = to_le - (n if to_le >= le else 0)
    lines[idx:idx] = reblock
    return "".join(lines)


def _ruff_clean(source: str) -> bool:
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--check", "-"],
        input=source.encode("utf-8"),
        capture_output=True,
    )
    if proc.returncode not in (0, 1):  # pragma: no cover - environment guard
        pytest.skip("ruff not runnable")
    return proc.returncode == 0


def _nonblank(s: str) -> list[str]:
    return sorted(ln for ln in _lines(s) if ln.strip())


H = (
    "from messagefoundry import handler, Send, set_field\n\n\n"
    '@handler("h")\n'
    "def h(msg):\n"
    '    set_field(msg, "A", "1")\n'  # 6
    '    set_field(msg, "B", "2")\n'  # 7
    '    set_field(msg, "C", "3")\n'  # 8
    '    return Send("OUT", msg)\n'  # 9
)


def test_move_action_down_after_nonadjacent() -> None:
    out = rewrite_source(
        H,
        {
            "op": "move_row",
            "line_start": 6,
            "line_end": 6,
            "to_line_start": 8,
            "to_line_end": 8,
            "to_position": "after",
        },
    )
    assert out == _oracle_move(H, 6, 6, 8, 8, "after")  # gate 2 (independent oracle)
    ast.parse(out)  # gate 3
    assert _nonblank(out) == _nonblank(H)  # same lines, reordered
    assert out.index('"B"') < out.index('"C"') < out.index('"A"') < out.index('Send("OUT"')


def test_move_action_up_before_nonadjacent() -> None:
    out = rewrite_source(
        H,
        {
            "op": "move_row",
            "line_start": 8,
            "line_end": 8,
            "to_line_start": 6,
            "to_line_end": 6,
            "to_position": "before",
        },
    )
    assert out == _oracle_move(H, 8, 8, 6, 6, "before")
    ast.parse(out)
    assert out.index('"C"') < out.index('"A"') < out.index('"B"') < out.index('Send("OUT"')


def test_move_onto_self_is_noop() -> None:
    out = rewrite_source(
        H,
        {
            "op": "move_row",
            "line_start": 6,
            "line_end": 6,
            "to_line_start": 6,
            "to_line_end": 6,
            "to_position": "after",
        },
    )
    assert out == H


# A source where BOTH the def suite and the if body keep ≥1 sibling after a cross-suite move (so neither
# refusal-triggering "empty suite" case fires) — the estate for the headline cross-suite re-indent move.
_CROSS = (
    "from messagefoundry import handler, Send, set_field\n\n\n"
    '@handler("h")\n'  # 4
    "def h(msg):\n"  # 5
    '    set_field(msg, "A", "1")\n'  # 6 def level (moves IN)
    '    if msg.field("X"):\n'  # 7 if header (def suite)
    '        set_field(msg, "B", "2")\n'  # 8 if body
    '        set_field(msg, "C", "3")\n'  # 9 if body sibling (moves OUT)
    '    return Send("OUT", msg)\n'  # 10 def level
)


def test_move_cross_suite_reindents() -> None:
    # (a) a def-level leaf (A@6) dragged INTO the 2-statement if body, after B@8 → re-indents 4→8 spaces.
    out_a = rewrite_source(
        _CROSS,
        {
            "op": "move_row",
            "line_start": 6,
            "line_end": 6,
            "to_line_start": 8,
            "to_line_end": 8,
            "to_position": "after",
        },
    )
    assert out_a == _oracle_reindent_move(_CROSS, 6, 6, 8, 8, "after", "    ", "        ", set())
    ast.parse(out_a)  # gate 3
    assert _ruff_clean(out_a)  # gate 3 (ruff-format-clean)
    assert '        set_field(msg, "A", "1")\n' in out_a  # A now at body depth
    # every NON-moved line is byte-identical (gate 2): the header, B, C, the return, the imports.
    for ln in (
        '    if msg.field("X"):\n',
        '        set_field(msg, "B", "2")\n',
        '        set_field(msg, "C", "3")\n',
        '    return Send("OUT", msg)\n',
    ):
        assert ln in out_a

    # (b) a non-sole if-body leaf (C@9) dragged OUT to def level, after A@6 → re-indents 8→4 spaces.
    out_b = rewrite_source(
        _CROSS,
        {
            "op": "move_row",
            "line_start": 9,
            "line_end": 9,
            "to_line_start": 6,
            "to_line_end": 6,
            "to_position": "after",
        },
    )
    assert out_b == _oracle_reindent_move(_CROSS, 9, 9, 6, 6, "after", "        ", "    ", set())
    ast.parse(out_b)
    assert _ruff_clean(out_b)
    assert '    set_field(msg, "C", "3")\n' in out_b  # C now at def depth
    # B stays the sole remaining if-body statement (not emptied) and is byte-identical.
    assert '        set_field(msg, "B", "2")\n' in out_b


def test_move_comment_only_row_not_locatable() -> None:
    # A pure-comment "code" row is not an AST statement, so it has no header line to locate — a move is
    # refused, not silently applied. (The webview never offers it: code rows are not draggable. This is
    # the engine backstop.)
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'
        "def h(msg):\n"
        '    set_field(msg, "A", "1")\n'  # 6 first stmt
        "    # just a comment\n"  # 7 comment-only code row (a gap between statements)
        '    set_field(msg, "B", "2")\n'  # 8
        '    return Send("OUT", msg)\n'  # 9
    )
    with pytest.raises(LensRewriteError, match="could not locate"):
        rewrite_source(
            src,
            {
                "op": "move_row",
                "line_start": 7,
                "line_end": 7,
                "to_line_start": 8,
                "to_line_end": 8,
                "to_position": "after",
            },
        )


# A nested handler: a def-level suite (the if header, a def-level set_field, the return) + an if-body suite.
_NESTED = (
    "from messagefoundry import handler, Send, set_field\n\n\n"
    '@handler("h")\n'  # 4
    "def h(msg):\n"  # 5
    '    if msg.field("X"):\n'  # 6 if header (def suite)
    '        set_field(msg, "A", "1")\n'  # 7 in the if body (its own suite)
    '    set_field(msg, "B", "2")\n'  # 8 def suite
    '    return Send("OUT", msg)\n'  # 9 def suite
)


def test_parse_stamps_suite_id_grouping_siblings() -> None:
    rows = {r["line_start"]: r for r in parse_source(_NESTED)[0]["rows"]}
    # The def-level rows (if@6, set_field B@8, send@9) share one suite id; the if-body row (@7) has its own,
    # so the webview offers a reorder drop only among true siblings.
    assert rows[6]["suite"] == rows[8]["suite"] == rows[9]["suite"]
    assert rows[7]["suite"] != rows[6]["suite"]


def test_drag_whole_if_block_to_a_sibling() -> None:
    # Drag the if BLOCK (its header row @6) to AFTER the def-level set_field B @8 — the whole block (header
    # + its body) moves as one contiguous unit, byte-stably.
    out = rewrite_source(
        _NESTED,
        {
            "op": "move_row",
            "line_start": 6,
            "line_end": 6,
            "to_line_start": 8,
            "to_line_end": 8,
            "to_position": "after",
        },
    )
    ast.parse(out)
    assert _nonblank(out) == _nonblank(_NESTED)  # same lines, reordered
    assert (
        out.index('set_field(msg, "B", "2")')
        < out.index('if msg.field("X")')
        < out.index('set_field(msg, "A", "1")')
        < out.index('Send("OUT"')
    )


def test_drag_cross_suite_reindents() -> None:
    # Drag def-level set_field B (@8) onto the if body, after set_field A (@7) — a CROSS-suite move: B
    # re-indents 4→8 spaces and joins the if body. The header + A + return are byte-identical (gate 2).
    out = rewrite_source(
        _NESTED,
        {
            "op": "move_row",
            "line_start": 8,
            "line_end": 8,
            "to_line_start": 7,
            "to_line_end": 7,
            "to_position": "after",
        },
    )
    assert out == _oracle_reindent_move(_NESTED, 8, 8, 7, 7, "after", "    ", "        ", set())
    ast.parse(out)  # gate 3
    assert _ruff_clean(out)
    assert '        set_field(msg, "B", "2")\n' in out  # B re-indented to body depth
    for ln in (
        '    if msg.field("X"):\n',
        '        set_field(msg, "A", "1")\n',
        '    return Send("OUT", msg)\n',
    ):
        assert ln in out  # non-moved lines byte-identical


def test_move_sole_body_stmt_out_refused() -> None:
    # Constraint 4: the SOLE statement of an if body dragged to def level would leave an empty suite (invalid
    # Python) — refused with ZERO change. (_NESTED's if body has only set_field A@7.)
    with pytest.raises(LensRewriteError, match="only statement"):
        rewrite_source(
            _NESTED,
            {
                "op": "move_row",
                "line_start": 7,
                "line_end": 7,
                "to_line_start": 8,
                "to_line_end": 8,
                "to_position": "after",
            },
        )


def test_move_block_into_itself_refused() -> None:
    # A whole if block dropped onto a row in its OWN body would reinsert the block inside the span it cuts —
    # refused, zero change. (And drop-onto-EXACT-self stays a no-op returning src.)
    with pytest.raises(LensRewriteError, match="into its own body"):
        rewrite_source(
            _NESTED,
            {
                "op": "move_row",
                "line_start": 6,  # the if header (whole block)
                "line_end": 6,
                "to_line_start": 7,  # a row inside its own body
                "to_line_end": 7,
                "to_position": "after",
            },
        )
    # onto exact self → no-op (byte-identical).
    noop = rewrite_source(
        _NESTED,
        {
            "op": "move_row",
            "line_start": 6,
            "line_end": 6,
            "to_line_start": 6,
            "to_line_end": 6,
            "to_position": "after",
        },
    )
    assert noop == _NESTED


def test_move_cross_suite_equal_depth_no_reindent() -> None:
    # Two sibling bodies at the SAME depth: a for-body leaf moved into an if-body at the same depth. src_prefix
    # == dst_prefix, so NO reindent runs — byte-identical to a plain reorder (the oracle move). The SOURCE
    # (for) body keeps a sibling so no empty-suite refusal fires.
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'  # 4
        "def h(msg):\n"  # 5
        '    if msg.field("X"):\n'  # 6
        '        set_field(msg, "A", "1")\n'  # 7 if body
        "    for seg in msg.groups():\n"  # 8
        '        set_field(msg, "B", "2")\n'  # 9 for body (moves)
        '        set_field(msg, "C", "3")\n'  # 10 for body sibling (stays)
        '    return Send("OUT", msg)\n'  # 11
    )
    out = rewrite_source(
        src,
        {
            "op": "move_row",
            "line_start": 9,
            "line_end": 9,
            "to_line_start": 7,
            "to_line_end": 7,
            "to_position": "after",
        },
    )
    assert out == _oracle_move(src, 9, 9, 7, 7, "after")
    ast.parse(out)
    assert _ruff_clean(out)
    assert '        set_field(msg, "C", "3")\n' in out  # for body not emptied


def test_move_crlf_and_nonascii_byte_preserved() -> None:
    src = (
        "from messagefoundry import handler, Send, set_field\r\n\r\n\r\n"
        '@handler("h")\r\n'
        "def h(msg):\r\n"
        '    set_field(msg, "A", "é✓")\r\n'  # 6 non-ASCII value
        '    set_field(msg, "B", "2")\r\n'  # 7
        '    set_field(msg, "C", "3")\r\n'  # 8
        '    return Send("OUT", msg)\r\n'  # 9
    )
    out = rewrite_source(
        src,
        {
            "op": "move_row",
            "line_start": 6,
            "line_end": 6,
            "to_line_start": 8,
            "to_line_end": 8,
            "to_position": "after",
        },
    )
    assert out == _oracle_move(src, 6, 6, 8, 8, "after")  # bytes preserved
    assert (
        "\r\n" in out and "é✓" in out and "\n" not in out.replace("\r\n", "")
    )  # CRLF intact, no bare LF
    ast.parse(out)


# =============================================================================
# cross-suite: string-freeze, whole-block, tabs/CRLF, underflow-refuse, to_suite guard
# =============================================================================


def test_move_cross_suite_freezes_multiline_string() -> None:
    # A db_lookup whose triple-quoted SQL interior COINCIDENTALLY starts with 4 spaces is moved across
    # suites: the SQL interior stays byte-identical (frozen) while the `row = db_lookup(` header + its
    # continuation lines re-indent 4→8. A plain prefix-swap that touched the interior would corrupt the SQL.
    src = (
        "from messagefoundry import handler, Send, db_lookup\n\n\n"
        '@handler("h")\n'  # 4
        "def h(msg):\n"  # 5
        '    if msg.field("X"):\n'  # 6 if header
        "        set_field = 1\n"  # 7 if body (keeps the body non-empty as a drop anchor)
        "    row = db_lookup(\n"  # 8 def-level multi-line lookup (moves IN)  ← block start
        '        "MPI",\n'  # 9
        '        """\n'  # 10 triple-quote OPEN (real indentation — re-based)
        "    SELECT 1\n"  # 11 SQL interior, 4-space (FROZEN — never shifted)
        '        """,\n'  # 12 triple-quote CLOSE (frozen — interior)
        "        {},\n"  # 13
        "    )\n"  # 14  ← block end
        '    return Send("OUT", msg)\n'  # 15
    )
    # block spans lines 8..14; block-relative frozen interior lines are 11 and 12 → indices 3 and 4.
    out = rewrite_source(
        src,
        {
            "op": "move_row",
            "line_start": 8,
            "line_end": 14,
            "to_line_start": 7,
            "to_line_end": 7,
            "to_position": "after",
        },
    )
    assert out == _oracle_reindent_move(src, 8, 14, 7, 7, "after", "    ", "        ", {3, 4})
    ast.parse(out)  # gate 3
    assert _ruff_clean(out)  # gate 3 (ruff-format-clean)
    assert "    SELECT 1\n" in out  # the SQL interior is frozen byte-identical
    assert "        row = db_lookup(\n" in out  # the call header re-indented to body depth


def test_move_cross_suite_whole_block_reindents() -> None:
    # A whole for block (header + body incl. an inner if/else) moved into another body → a UNIFORM shift:
    # the relative internal indentation + the else: header are preserved, ruff-clean, oracle-matched.
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'  # 4
        "def h(msg):\n"  # 5
        '    if msg.field("Z"):\n'  # 6 outer if (def suite)
        '        set_field(msg, "P", "0")\n'  # 7 if body (anchor)
        "    for seg in msg.groups():\n"  # 8 for header (def suite) ← MOVE whole block (8..12)
        "        if seg:\n"  # 9 inner if (for-body suite)
        '            set_field(msg, "A", "1")\n'  # 10
        "        else:\n"  # 11
        '            set_field(msg, "B", "2")\n'  # 12
        '    return Send("OUT", msg)\n'  # 13
    )
    # The control ROW is identified by its HEADER line (line_start == line_end == 8); the move relocates the
    # WHOLE block (its real span 8..12), which the oracle models directly.
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
    assert out == _oracle_reindent_move(src, 8, 12, 7, 7, "after", "    ", "        ", set())
    ast.parse(out)
    assert _ruff_clean(out)  # uniform shift keeps it format-clean
    assert "        for seg in msg.groups():\n" in out  # header +4
    assert "            if seg:\n" in out  # inner if +4 (relative depth preserved)
    assert '                set_field(msg, "A", "1")\n' in out  # +4
    assert "            else:\n" in out  # else re-based off the inner-if column


def test_move_cross_suite_tabs() -> None:
    # A tab-indented source: prefixes are copied real strings (no width math), so a tab-indented block
    # re-indents by swapping ONE-tab for TWO-tab prefixes — correct with tabs (constraint 6).
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'  # 4
        "def h(msg):\n"  # 5
        '\tif msg.field("X"):\n'  # 6 one-tab if header
        '\t\tset_field(msg, "A", "1")\n'  # 7 two-tab if body
        '\tset_field(msg, "B", "2")\n'  # 8 one-tab def suite (moves IN)
        '\treturn Send("OUT", msg)\n'  # 9
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
    assert out == _oracle_reindent_move(src, 8, 8, 7, 7, "after", "\t", "\t\t", set())
    ast.parse(out)
    assert '\t\tset_field(msg, "B", "2")\n' in out  # B now two-tab indented


def test_move_cross_suite_crlf() -> None:
    # A CRLF source re-indents across suites with terminators preserved (no bare LF leaks).
    src = (
        "from messagefoundry import handler, Send, set_field\r\n\r\n\r\n"
        '@handler("h")\r\n'  # 4
        "def h(msg):\r\n"  # 5
        '    if msg.field("X"):\r\n'  # 6
        '        set_field(msg, "A", "1")\r\n'  # 7 if body
        '    set_field(msg, "B", "2")\r\n'  # 8 def suite (moves IN)
        '    return Send("OUT", msg)\r\n'  # 9
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
    assert out == _oracle_reindent_move(src, 8, 8, 7, 7, "after", "    ", "        ", set())
    assert "\r\n" in out and "\n" not in out.replace("\r\n", "")  # CRLF intact, no bare LF
    assert '        set_field(msg, "B", "2")\r\n' in out
    ast.parse(out)


def test_move_cross_suite_underflow_refused() -> None:
    # A moved block carrying an exotic BACKSLASH-continuation line that does not start with src_prefix (it is
    # deliberately dedented) can't be cleanly prefix-swapped → refused (step 5d), ZERO change.
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'  # 4
        "def h(msg):\n"  # 5
        '    if msg.field("X"):\n'  # 6 if header
        '        set_field(msg, "A", "1")\n'  # 7 if body (anchor)
        "    x = 1 + \\\n"  # 8 def-level backslash continuation (moves IN)  ← block start
        "1\n"  # 9 continuation dedented to column 0 (won't prefix-match "    ") ← block end
        '    return Send("OUT", msg)\n'  # 10
    )
    with pytest.raises(LensRewriteError, match="re-indent"):
        rewrite_source(
            src,
            {
                "op": "move_row",
                "line_start": 8,
                "line_end": 9,
                "to_line_start": 7,
                "to_line_end": 7,
                "to_position": "after",
            },
        )


def test_move_body_stmt_out_after_enclosing_for_header() -> None:
    # The OWNER's use case: a Set Field UNDER a for-each loop, dragged OUT to top level (dropped on the for
    # HEADER's bottom third → "after the whole block at the outer level"). The moved line lies INSIDE the for
    # block's span, so it must land AFTER the loop at def depth (re-indent 8→4) — NOT after the return (the
    # overlap splice bug). The loop keeps a sibling (not emptied). Byte-stable via the (overlap-aware) oracle.
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'  # 4
        "def h(msg):\n"  # 5
        "    for seg in msg.groups():\n"  # 6 for header (def suite)
        '        set_field(msg, "A", "1")\n'  # 7 for body (moves OUT)  ← inside the block span [6,8]
        '        set_field(msg, "B", "2")\n'  # 8 for body sibling (stays)
        '    return Send("OUT", msg)\n'  # 9 def suite
    )
    out = rewrite_source(
        src,
        {
            "op": "move_row",
            "line_start": 7,  # the Set Field inside the loop
            "line_end": 7,
            "to_line_start": 6,  # anchor on the FOR HEADER
            "to_line_end": 6,
            "to_position": "after",  # → after the whole loop, at the OUTER (def) level
            "to_suite": "5",  # the for header's own (def) suite
        },
    )
    # Oracle uses the for block's REAL span [6, 8] as the dest (the header row projects only line 6).
    assert out == _oracle_reindent_move(src, 7, 7, 6, 8, "after", "        ", "    ", set())
    ast.parse(out)
    assert _ruff_clean(out)
    lines = out.splitlines()
    # A@1 landed at DEF depth AFTER the loop and BEFORE the return — not after the return (the bug).
    a_idx = lines.index('    set_field(msg, "A", "1")')
    ret_idx = lines.index('    return Send("OUT", msg)')
    assert a_idx < ret_idx, (
        "the moved Set Field must precede the return, not become dead code after it"
    )
    assert '        set_field(msg, "B", "2")' in out  # the loop kept its sibling (not emptied)


def test_move_to_suite_stale_guard() -> None:
    # The destination stale-guard: an OPTIONAL to_suite that disagrees with the dest contract row's real
    # suite is refused (zero change); the CORRECT to_suite — and omitting it — both succeed (backward compat).
    base = {
        "op": "move_row",
        "line_start": 8,
        "line_end": 8,
        "to_line_start": 7,
        "to_line_end": 7,
        "to_position": "after",
    }
    # The if-body anchor (@7) lives in the suite keyed by the if header line (6) — correct to_suite = "6".
    ok = rewrite_source(_NESTED, {**base, "to_suite": "6"})
    assert '        set_field(msg, "B", "2")\n' in ok  # succeeded + re-indented
    # A disagreeing to_suite → refused, zero change.
    with pytest.raises(LensRewriteError, match="scope changed"):
        rewrite_source(_NESTED, {**base, "to_suite": "999"})
    # Omitted to_suite → still succeeds (the guard is skipped).
    assert rewrite_source(_NESTED, base) == ok


# =============================================================================
# gate 3 (ruff-format-clean): a DEPTH-changing move must not silently emit a block ruff would re-wrap /
# collapse. A byte-stable re-indent preserves the moved block's line layout, but ruff's canonical wrapping
# depends on the column depth — so a near-100-col or already-wrapped call can diverge from ruff after a
# depth change. The engine's only OUTPUT gate is ast.parse (valid, but format-blind), so these hazards are
# refused at the move path (mirroring _apply_insert_row's line-length guard). Each line's column count is
# `indent + 27 + len(value)` for `set_field(msg, "PID-3", "<value>")`; ruff wraps a line at 101+ columns.
# =============================================================================


def test_move_cross_suite_deeper_over_line_length_refused() -> None:
    # Repro A (deeper OVERFLOW): a def-level Set Field that is ruff-clean at its 4-space depth (97 cols) is
    # dragged INTO an if body (8-space depth), where it would be 101 cols — ruff would WRAP it, so the byte-
    # preserved (un-wrapped) re-indent is NOT format-clean. REFUSED with a clear message, ZERO change.
    val = "z" * 66  # 4-indent → 97 cols (clean); 8-indent → 101 cols (over the limit)
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'  # 4
        "def h(msg):\n"  # 5
        '    if msg.field("X"):\n'  # 6 if header
        '        set_field(msg, "A", "1")\n'  # 7 if body (anchor)
        f'    set_field(msg, "PID-3", "{val}")\n'  # 8 def-level (moves IN, 4→8)
        '    return Send("OUT", msg)\n'  # 9
    )
    assert len(_lines(src)[7].rstrip("\n")) == 97  # ruff-clean at the source depth
    assert _ruff_clean(src)
    with pytest.raises(LensRewriteError, match="over the 100-column limit"):
        rewrite_source(
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
    # ZERO change: the refusal is raised before any splice, so a caught refusal leaves the buffer untouched
    # (the caller re-uses `src`). Assert the boundary is EXACT — one column narrower lands at exactly 100
    # (ruff's limit, still clean) and is ACCEPTED, so the guard is not over-eager (off-by-one).
    val_ok = "z" * 65  # 8-indent → 100 cols exactly (== limit, ruff keeps it)
    src_ok = src.replace(val, val_ok)
    out = rewrite_source(
        src_ok,
        {
            "op": "move_row",
            "line_start": 8,
            "line_end": 8,
            "to_line_start": 7,
            "to_line_end": 7,
            "to_position": "after",
        },
    )
    moved = next(line for line in _lines(out) if val_ok in line).rstrip("\n")
    assert len(moved) == 100  # at the limit, re-indented into the body
    ast.parse(out)
    assert _ruff_clean(out)  # accepted output IS ruff-format-clean (gate 3)


def test_move_cross_suite_shallower_collapse_refused() -> None:
    # Repro B (shallower COLLAPSE): a Set Field ruff WRAPPED inside a loop (its one-line form is 103 cols at
    # the 8-space body depth) is dragged OUT to def level (4-space), where the one-line form is 99 cols —
    # ruff would COLLAPSE it back to a single line. A pure length check can't see this (every wrapped line is
    # short), so the collapsible-wrapped-call guard refuses it. ZERO change; the loop keeps a sibling.
    # one-line form: 8-indent → 103 cols (ruff wraps it); 4-indent → 99 cols (ruff would collapse it back).
    val = "z" * 68
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'  # 4
        "def h(msg):\n"  # 5
        "    for seg in msg.groups():\n"  # 6 for header
        "        set_field(\n"  # 7 wrapped call start ← block [7, 9]
        f'            msg, "PID-3", "{val}"\n'  # 8 wrapped continuation
        "        )\n"  # 9 wrapped call close
        '        set_field(msg, "B", "2")\n'  # 10 sibling (keeps the loop non-empty)
        '    return Send("OUT", msg)\n'  # 11 def level
    )
    assert _ruff_clean(src)  # the wrapped source IS ruff-clean at the loop depth
    with pytest.raises(LensRewriteError, match="collapse to one line"):
        rewrite_source(
            src,
            {
                "op": "move_row",
                "line_start": 7,
                "line_end": 9,
                "to_line_start": 11,
                "to_line_end": 11,
                "to_position": "before",
            },
        )


def test_move_cross_suite_shallower_wrapped_string_allowed() -> None:
    # The guard is NOT a blanket "no multi-line statement moves shallower": a statement multi-line ONLY
    # because of a triple-quoted string is string-FORCED (ruff keeps it multi-line at any depth), so it is
    # EXCLUDED from the collapse guard. Moving such a block OUT of a loop re-indents the code lines, freezes
    # the string interior, and stays ruff-format-clean.
    src = (
        "from messagefoundry import handler, Send, set_field\n\n\n"
        '@handler("h")\n'  # 4
        "def h(msg):\n"  # 5
        "    for seg in msg.groups():\n"  # 6 for header
        '        note = """\n'  # 7 assign start ← block [7, 9]
        "        hello\n"  # 8 string interior (frozen)
        '        """\n'  # 9 string close (frozen)
        '        set_field(msg, "B", "2")\n'  # 10 sibling (keeps the loop non-empty)
        '    return Send("OUT", msg)\n'  # 11 def level
    )
    out = rewrite_source(
        src,
        {
            "op": "move_row",
            "line_start": 7,
            "line_end": 9,
            "to_line_start": 11,
            "to_line_end": 11,
            "to_position": "before",
        },
    )
    # The string interior lines (8, 9) are frozen byte-identical; only the `note = """` header re-indents 8→4.
    assert out == _oracle_reindent_move(src, 7, 9, 11, 11, "before", "        ", "    ", {1, 2})
    ast.parse(out)
    assert _ruff_clean(out)  # gate 3 — the string-forced move stays format-clean
    assert '    note = """\n' in out  # header re-based to def depth
    assert "        hello\n" in out  # interior frozen (byte-identical)
