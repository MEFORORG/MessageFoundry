# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every by-id message read under ``messagefoundry/api/`` goes through one scoped helper (BACKLOG #2627).

``messagefoundry/api/message_scope.py`` owns the only ``.get_message(`` call in the API package. A
route that opened a message by id with its own call could forget the channel-scope test, and on a
first deployment would hand a scoped operator another channel's message with nothing going red. This
guard reads the CODE, so a call in a comment or docstring does not count and a real call does.

The walk flags every ``.get_message(`` attribute call, whatever the receiver is named. A narrower
match on a ``store`` receiver would miss ``s = engine.store; s.get_message(...)``, which is the
same read.

A call site that cannot use the helper without changing behaviour goes in :data:`_ALLOWED` with a
one-line reason. It is empty: all nine call sites moved.
"""

from __future__ import annotations

import ast
from pathlib import Path

from messagefoundry.api import message_scope

_API = Path(message_scope.__file__).resolve().parent
_HELPER = Path(message_scope.__file__).resolve()

#: ``(path relative to messagefoundry/api, enclosing function)`` -> why it may read by id itself.
_ALLOWED: dict[tuple[str, str], str] = {}


def _get_message_calls(tree: ast.AST) -> list[tuple[str, int]]:
    """``(innermost enclosing function, line)`` for each ``<anything>.get_message(`` call."""
    found: list[tuple[str, int]] = []

    def visit(node: ast.AST, func: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = func
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = child.name
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "get_message"
            ):
                found.append((func, child.lineno))
            visit(child, inner)

    visit(tree, "<module>")
    return found


def _api_sites() -> dict[Path, list[tuple[str, int]]]:
    return {
        path: _get_message_calls(ast.parse(path.read_text(encoding="utf-8")))
        for path in sorted(_API.rglob("*.py"))
    }


def test_no_api_module_reads_a_message_by_id_itself() -> None:
    offenders = [
        f"{path.relative_to(_API).as_posix()}:{line} in {func}"
        for path, sites in _api_sites().items()
        if path != _HELPER
        for func, line in sites
        if (path.relative_to(_API).as_posix(), func) not in _ALLOWED
    ]
    assert not offenders, (
        "read a message by id through messagefoundry.api.message_scope.get_scoped_message (or "
        "read_scoped_message), which applies the caller's channel scope; or add the site to "
        f"_ALLOWED with the reason it cannot: {offenders}"
    )


def test_the_helper_holds_the_one_read() -> None:
    """The positive control: the walk finds the helper's own call, so a clean result elsewhere is
    the absence of calls and not a walk that finds nothing."""
    sites = _api_sites()
    assert [func for func, _line in sites[_HELPER]] == ["read_scoped_message"]
    assert len(sites) > 10, "the API package walk found almost no modules"


def test_every_allowlisted_site_still_exists() -> None:
    present = {
        (path.relative_to(_API).as_posix(), func)
        for path, sites in _api_sites().items()
        for func, _line in sites
    }
    assert set(_ALLOWED) <= present, f"stale _ALLOWED entries: {sorted(set(_ALLOWED) - present)}"


def test_the_walk_finds_a_call_and_ignores_a_mention() -> None:
    """A planted call is found under any receiver name; the same words in a comment or a docstring
    are not, because the walk reads the tree and not the text."""
    planted = '''
async def route(engine, other):
    """engine.store.get_message(message_id) in prose is not a call."""
    # engine.store.get_message(message_id)
    row = await engine.store.get_message("m")
    s = other
    return await s.get_message("n")
'''
    assert _get_message_calls(ast.parse(planted)) == [("route", 5), ("route", 7)]
