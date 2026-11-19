# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No arm of the verifier, or of the acceptance harness's report rows, quotes an exception raw
(BACKLOG #5395).

A verify or acceptance report is written to a file an operator pastes into a ticket, and an
exception's text can quote a DSN, a ``password=`` pair or a path. Each caught exception must reach a
row through :mod:`messagefoundry.verify_leaf`'s scrub. This walk refuses AT LEAST these raw shapes
inside an ``except ... as NAME`` arm: ``NAME`` or ``NAME.attr`` in an f-string, and ``str(NAME)``,
``repr(NAME)`` or ``codec_safe_str(NAME)`` whose result is not passed straight to a scrub. A shape it
does not name, such as an exception copied to another variable first, is not proven scrubbed. A
``raise`` is skipped: what it builds is a new exception, scrubbed where it is caught, and a log call
is skipped because a log line is not a report row."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCANNED = [
    *sorted((_REPO / "messagefoundry" / "verify").glob("*.py")),
    _REPO / "messagefoundry" / "verify_leaf.py",
    _REPO / "harness" / "acceptance" / "probes.py",
    _REPO / "harness" / "acceptance" / "runner.py",
]
_SCRUBS = frozenset({"safe_detail_text", "safe_exc_text", "safe_exc_detail", "safe_exc"})
_RAW_CALLS = frozenset({"str", "repr", "codec_safe_str"})
_LOG_METHODS = frozenset({"debug", "info", "warning", "error", "exception", "critical", "log"})


def _callee(node: ast.Call) -> str:
    f = node.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _raw_uses(tree: ast.AST) -> list[str]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def exempt(node: ast.AST) -> bool:
        while node in parents:
            node = parents[node]
            if isinstance(node, ast.Raise):
                return True
            if isinstance(node, ast.Call) and (
                _callee(node) in _LOG_METHODS or _callee(node) in _SCRUBS
            ):
                return True
        return False

    def is_name(node: ast.AST, name: str) -> bool:
        if isinstance(node, ast.Attribute):
            node = node.value
        return isinstance(node, ast.Name) and node.id == name

    found: list[str] = []
    for handler in ast.walk(tree):
        if not isinstance(handler, ast.ExceptHandler) or handler.name is None:
            continue
        name = handler.name
        for node in ast.walk(handler):
            raw = (isinstance(node, ast.FormattedValue) and is_name(node.value, name)) or (
                isinstance(node, ast.Call)
                and _callee(node) in _RAW_CALLS
                and any(is_name(a, name) for a in node.args)
            )
            if raw and not exempt(node):
                found.append(f"line {getattr(node, 'lineno', '?')}: {ast.unparse(node)}")
    return found


@pytest.mark.parametrize("path", _SCANNED, ids=lambda p: p.relative_to(_REPO).as_posix())
def test_no_arm_quotes_an_exception_raw(path: Path) -> None:
    assert path.is_file(), path
    found = _raw_uses(ast.parse(path.read_text(encoding="utf-8")))
    assert not found, f"{path.name} quotes an exception raw: {found}"


def test_the_walk_sees_every_raw_shape_it_names() -> None:
    # Positive control: a walk that sees nothing passes the test above for the wrong reason.
    planted = """
def f():
    try:
        pass
    except OSError as exc:
        a = f"x {exc}"
        b = f"x {exc.filename}"
        c = str(exc)
        d = repr(exc)
        e = codec_safe_str(exc)
        ok1 = safe_exc_text(exc)
        ok2 = f"{safe_detail_text(codec_safe_str(exc))}"
        ok3 = type(exc).__name__
        _log.debug("x %s", str(exc))
        raise ValueError(f"wrapped {exc}") from exc
"""
    found = _raw_uses(ast.parse(planted))
    assert len(found) == 5, found


def test_the_walk_covers_the_files_it_names() -> None:
    # The verify package glob must find its modules, or the census reads clean over nothing.
    names = {p.name for p in _SCANNED}
    assert {"checks.py", "cipher_policy.py", "federation.py", "smoke.py", "runner.py"} <= names
