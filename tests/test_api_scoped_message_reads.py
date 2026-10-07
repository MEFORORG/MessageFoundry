# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every by-id message read under ``messagefoundry/api/`` goes through one scoped helper (BACKLOG #2627).

``messagefoundry/api/message_scope.py`` owns the only ``.get_message(`` call in the API package. A
route that opened a message by id with its own call could forget the channel-scope test, and on a
first deployment would hand a scoped operator another channel's message with nothing going red. This
guard reads the CODE, so a call in a comment or docstring does not count and a real call does.

The walk flags any load of a ``.get_message`` attribute, called or not, and
``getattr(..., "get_message")``, whatever the receiver is named. A narrower match on a ``store``
receiver would miss ``s = engine.store; s.get_message(...)``, which is the same read.

The guard covers ``get_message`` only. The other by-id reads (``outbox_for``, ``events_for``,
``attachments_for``, ``correlate_response`` and the rest) are reached today only after the scoped
fetch, and nothing here enforces that order.

A second guard refuses a literal ``allowed_channels=None`` under ``messagefoundry/api/``: the store
keyword is required, and a route that writes None reads every channel on purpose-looking terms.

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
    """``(innermost enclosing function, line)`` for each read of a ``.get_message`` attribute.

    Any attribute load counts, not only a call, so ``fetch = engine.store.get_message`` is caught
    as well as the call; so is ``getattr(x, "get_message")``."""
    found: list[tuple[str, int]] = []

    def visit(node: ast.AST, func: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = func
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = child.name
            if (
                isinstance(child, ast.Attribute)
                and child.attr == "get_message"
                and isinstance(child.ctx, ast.Load)
            ) or (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "getattr"
                and any(
                    isinstance(a, ast.Constant) and a.value == "get_message" for a in child.args
                )
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
    api_sites = _api_sites()
    assert len(api_sites) >= 10, "the API package walk found almost no modules"
    offenders = [
        f"{path.relative_to(_API).as_posix()}:{line} in {func}"
        for path, sites in api_sites.items()
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
    fetch = s.get_message
    return await getattr(s, "get_message")("n")
'''
    assert _get_message_calls(ast.parse(planted)) == [("route", 5), ("route", 7), ("route", 8)]


#: The store reads whose ``allowed_channels`` is required (store/base.py). ``Identity.build`` also
#: takes an ``allowed_channels``, and the system identity passes None to it on purpose, so the guard
#: looks only at these calls.
_SCOPED_STORE_READS = frozenset(
    {
        "list_messages",
        "count_messages",
        "search_messages",
        "list_dead",
        "count_dead",
        "list_replay_targets",
        "list_connection_events",
        "count_connection_events",
        "list_active_alert_instances",
        "summarize_active_alert_instances",
        "get_alert_instance",
    }
)


def _literal_none_scopes(tree: ast.AST) -> list[int]:
    """Lines where a scoped store read is passed ``allowed_channels=None`` as a literal."""
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _SCOPED_STORE_READS
        for kw in node.keywords
        if kw.arg == "allowed_channels"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is None
    ]


def test_no_api_module_passes_a_literal_every_channel_scope() -> None:
    """The store keyword is required so a route cannot read every channel by leaving it out. A
    route that writes ``allowed_channels=None`` gets the same estate-wide read and still
    type-checks. Engine-internal callers do write it; an API route takes the caller's scope
    instead, from ``_scope(identity)`` or the identity itself."""
    modules = sorted(_API.rglob("*.py"))
    assert len(modules) >= 10, "the API package walk found almost no modules"
    offenders = [
        f"{path.relative_to(_API).as_posix()}:{line}"
        for path in modules
        for line in _literal_none_scopes(ast.parse(path.read_text(encoding="utf-8")))
    ]
    assert not offenders, f"pass the caller's channel scope, not None: {offenders}"


def test_the_scoped_read_list_matches_the_store_protocol() -> None:
    """The list above is the protocol's own set: every store method whose ``allowed_channels`` is a
    required keyword, read from store/base.py, so a new scoped read joins the guard or reds here."""
    base = _API.parent / "store" / "base.py"
    required = {
        fn.name
        for fn in ast.walk(ast.parse(base.read_text(encoding="utf-8")))
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        for arg, default in zip(fn.args.kwonlyargs, fn.args.kw_defaults, strict=True)
        if arg.arg == "allowed_channels" and default is None
    }
    assert required == _SCOPED_STORE_READS


def test_the_none_scope_walk_finds_a_planted_literal() -> None:
    planted = "async def r(store, scope):\n    await store.list_messages(allowed_channels=None)\n"
    assert _literal_none_scopes(ast.parse(planted)) == [2]
    assert _literal_none_scopes(ast.parse(planted.replace("None", "scope"))) == []
