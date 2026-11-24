# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391 item 1, S19-73 and S19-74: two comments in ``_serve`` that stated false things.

Each pin reads one comment block of the one ``def _serve`` in ``messagefoundry/__main__.py``,
from the file, lower-cased with comment markers and runs of whitespace collapsed, so a revert
that reflows a line is still caught; the control below shows that. Each block is found by an
anchor, so a pin whose comment moved fails rather than reading nothing. A pin bans the false
wording it names, and a reworded revert can pass it.

* S19-73, the block above ``_serve``'s ``install_remote_debug_guard()`` call. Before engine PR
  3019 it said this module's imports and argument parsing come before the hook; the
  module-level call (vault BACKLOG #2742) runs ahead of both. PR 3019's wording said the call
  covers a caller that reached ``_serve`` some other way; every route imports the module first.
  The block now points at the guard's own docs instead. The finding's other half, function-local
  re-imports of ``sys`` and ``Path``, was already gone before PR 3019, so that pin guards a
  return only; its control shows it can fail.
* S19-74, the posture-B gate's loopback-arm paragraph. Before PR 3019 it justified the arm by
  upgrade breakage on working deployments, a cost ``CLAUDE.md`` section 0 makes vacuous.
"""

from __future__ import annotations

import ast
import functools
import importlib.util
import io
import re
import tokenize
from pathlib import Path

from tests._ast_sites import call_sites, named_func, parse_source


def _comment_lines(source: str, first: int, last: int) -> dict[int, str]:
    """The comment text on each line from ``first`` to ``last``, marker stripped."""
    return {
        tok.start[0]: tok.string.lstrip("#")
        for tok in tokenize.generate_tokens(io.StringIO(source).readline)
        if tok.type == tokenize.COMMENT and first <= tok.start[0] <= last
    }


def _block(comments: dict[int, str], line: int) -> str:
    """The run of comment lines around ``line``, joined, lower-cased, whitespace collapsed."""
    first = last = line
    while first - 1 in comments:
        first -= 1
    while last + 1 in comments:
        last += 1
    text = " ".join(comments[n] for n in range(first, last + 1))
    return re.sub(r"\s+", " ", text).lower().strip()


def _block_above_call(source: str, func: str, callee: str) -> str:
    node = named_func(parse_source(source), func)
    comments = _comment_lines(source, node.lineno, node.end_lineno or node.lineno)
    call_line = call_sites(node, callee)[0].lineno
    assert call_line - 1 in comments, f"no comment directly above {callee}() in {func}"
    return _block(comments, call_line - 1)


def _block_holding(source: str, func: str, anchor: str) -> str:
    node = named_func(parse_source(source), func)
    comments = _comment_lines(source, node.lineno, node.end_lineno or node.lineno)
    hits = [n for n, text in comments.items() if anchor in text.lower()]
    assert len(hits) == 1, f"{anchor!r} is on {len(hits)} comment lines of {func}; re-anchor"
    return _block(comments, hits[0])


@functools.cache
def _main_source() -> str:
    spec = importlib.util.find_spec("messagefoundry.__main__")
    assert spec is not None and spec.origin is not None
    return Path(spec.origin).read_text(encoding="utf-8")


def _guard_block() -> str:
    return _block_above_call(_main_source(), "_serve", "install_remote_debug_guard")


def _loopback_arm_block() -> str:
    return _block_holding(_main_source(), "_serve", "loopback arm warns rather than refuses")


def _reimports(func: ast.AST) -> list[str]:
    """``sys`` or ``Path`` imported inside ``func``, which the module already binds."""
    return [
        alias.name
        for node in ast.walk(func)
        if isinstance(node, ast.Import | ast.ImportFrom)
        and (not isinstance(node, ast.ImportFrom) or node.module == "pathlib")
        for alias in node.names
        if alias.name in ("sys", "Path")
    ]


def test_s19_73_the_guard_comment_states_neither_false_order() -> None:
    block = _guard_block()
    assert block.startswith("vault backlog #2700: first in this function"), block
    assert "argument parsing come before it" not in block, block
    assert "some other way" not in block, block


def test_s19_73_serve_does_not_re_import_sys_or_path() -> None:
    assert _reimports(named_func(parse_source(_main_source()), "_serve")) == []


def test_s19_73_control_the_re_import_check_flags_both_names() -> None:
    func = parse_source(
        "def f():\n    import sys\n    from pathlib import Path\n    from os import path\n"
    )
    assert _reimports(func) == ["sys", "Path"]


def test_s19_74_the_loopback_arm_paragraph_cites_no_upgrade_breakage() -> None:
    block = _loopback_arm_block()
    assert "upgrade" not in block, block


def test_control_a_reflowed_phrase_in_the_block_is_still_found() -> None:
    source = (
        "def f():\n"
        "    x = 1\n"
        "    # Vault BACKLOG #2700: first in this function. A caller that reached it some\n"
        "    #   other WAY.\n"
        "    g()\n"
        "    # The loopback arm WARNS rather than refuses: refusing would break it on\n"
        "    # UPGRADE.\n"
        "    return x\n"
    )
    guard = _block_above_call(source, "f", "g")
    assert guard.startswith("vault backlog #2700: first in this function")
    assert "some other way" in guard
    assert "upgrade" in _block_holding(source, "f", "loopback arm warns rather than refuses")
