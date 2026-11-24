# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391 item 1, S19-73 and S19-74: comments in ``_serve`` that stated false things.

Engine PR 3019 corrected both; this file pins them. Each pin reads the comments of the one
``def _serve`` in ``messagefoundry/__main__.py``, from the file, lower-cased with runs of
whitespace and comment markers collapsed, so a revert that reflows a line is still caught.
Each also asserts an anchor it must find first, so a refactor that moves the comments out of
``_serve`` fails here rather than leaving the pins reading nothing.

* S19-73: the comment above ``_serve``'s ``install_remote_debug_guard()`` call said the hook was
  not first in the process and that the window before it stays open; the module-level call
  (vault BACKLOG #2742) closes it, and ``tests/test_remote_debug_guard.py`` pins that order. A
  later wording said the call covers a caller that reached ``_serve`` some other way; every
  route imports the module first, and the call's job is the retry ``install_remote_debug_guard``
  documents. The finding's second half, function-local re-imports of ``sys`` and ``Path``, was
  already gone before PR 3019, so that pin guards a return only; its control shows it can fail.
* S19-74: a comment justified the posture-B gate's loopback arm by upgrade breakage on working
  deployments, a cost ``CLAUDE.md`` section 0 makes vacuous.
"""

from __future__ import annotations

import ast
import functools
import io
import re
import tokenize
from pathlib import Path

import messagefoundry.__main__ as cli
from tests._ast_sites import named_func, parse_source


@functools.cache
def _serve_node_and_source() -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, str]:
    source = Path(cli.__file__).read_text(encoding="utf-8")
    return named_func(parse_source(source), "_serve"), source


@functools.cache
def _serve_comments() -> str:
    """Every comment inside ``def _serve``, joined, lower-cased, whitespace collapsed."""
    node, source = _serve_node_and_source()
    end = node.end_lineno or node.lineno
    texts = [
        tok.string.lstrip("#")
        for tok in tokenize.generate_tokens(io.StringIO(source).readline)
        if tok.type == tokenize.COMMENT and node.lineno <= tok.start[0] <= end
    ]
    return re.sub(r"\s+", " ", " ".join(texts)).lower()


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


def test_s19_73_the_guard_comment_names_neither_an_open_window_nor_another_caller() -> None:
    comments = _serve_comments()
    # The anchor: the guard comment is still in _serve. Re-anchor this test if it moves.
    assert "vault backlog #2700: first in this function" in comments
    assert "window stays open" not in comments
    assert "not first in the process" not in comments
    assert "some other way" not in comments


def test_s19_73_serve_does_not_re_import_sys_or_path() -> None:
    node, _source = _serve_node_and_source()
    assert _reimports(node) == []


def test_s19_73_control_the_re_import_check_flags_both_names() -> None:
    func = parse_source(
        "def f():\n    import sys\n    from pathlib import Path\n    from os import path\n"
    )
    assert _reimports(func) == ["sys", "Path"]


def test_s19_74_no_serve_comment_cites_upgrade_breakage_on_working_deployments() -> None:
    comments = _serve_comments()
    # The anchor: the posture-B gate's loopback-arm comment is still in _serve.
    assert "the loopback arm warns rather than refuses (owner decision)" in comments
    assert "deployments on upgrade" not in comments
    assert "working deployments" not in comments
