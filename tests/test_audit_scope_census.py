# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The census behind :data:`messagefoundry.auth.audit_visibility.CHANNEL_LIST_ACTIONS` is checked, not
kept by hand (vault BACKLOG #3748 item 6).

The narrowing fails open per action: an action it does not name is served whole to every
``audit:read`` holder. So this test reads every audit write in ``messagefoundry/`` (a call with a
literal or named action first and a ``detail=`` keyword), collects the keys of the dict literals in
that detail, and fails when a key that can carry a channel list or a scope's source appears on an
action that is neither narrowed nor on :data:`_WHOLE_ROW`, the named list of actions checked and
left whole, each with its reason.

**What it does not see, at least:** a detail built outside the call (a variable, a helper's
return), a scope written under a key not in :data:`_SCOPE_KEYS`, a key not spelled as a string
literal, an action passed by keyword or as an expression other than a string or a module-level
string constant, and a writer outside ``messagefoundry/``. Each of those passes silently. The
``missing`` check catches such a move only on one of the four narrowed writers.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from functools import cache
from pathlib import Path

from messagefoundry.auth import audit_visibility
from messagefoundry.auth.audit_visibility import CHANNEL_LIST_ACTIONS

_ROOT = Path(__file__).resolve().parents[1] / "messagefoundry"

#: Detail keys that can carry a channel list or a scope's source.
_SCOPE_KEYS = frozenset(
    {
        "channels",
        "withdrawn",
        "scope_from",
        "scope_to",
        "channel_scope",
        "channel_scope_source",
        "owner",
        "read_source",
        "expected_source",
        "scope",
    }
)

#: Actions whose detail holds a scope-looking key but no channel list or scope source, checked and
#: left whole, each with the reason it was cleared.
_WHOLE_ROW: dict[str, str] = {
    "auth.session_revoked": "``scope`` says which sessions ended (cap, self, admin, all), not channels",
    "auth.mfa_disabled": "``scope`` is ``self``: who disabled the factor, not channels",
    "connection_purge": "``scope`` is the purge's queue scope on one named outbound, not an account's",
    "upload.list": "``scope`` is ``own`` or ``any_owner``, the listing's file reach, not channels",
}


def _string_constants(tree: ast.Module) -> dict[str, str]:
    """One module's top-level ``NAME = "..."`` and ``NAME: Final = "..."``, so an action held in a
    constant beside its writer resolves as one imported from audit_visibility does."""
    found: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            target, value = stmt.target, stmt.value
        else:
            continue
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            found[target.id] = value.value
    return found


def _dict_keys(node: ast.AST) -> set[str]:
    return {
        key.value
        for sub in ast.walk(node)
        if isinstance(sub, ast.Dict)
        for key in sub.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }


@cache
def _census() -> tuple[dict[str, set[str]], int]:
    shared = {
        name: value
        for name, value in vars(audit_visibility).items()
        if name.endswith("_ACTION") and isinstance(value, str)
    }
    found: dict[str, set[str]] = defaultdict(set)
    scanned = 0
    for path in sorted(_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants = {**shared, **_string_constants(tree)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            detail = next((k.value for k in node.keywords if k.arg == "detail"), None)
            if detail is None:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                action: str | None = first.value
            elif isinstance(first, ast.Name):
                action = constants.get(first.id)
            else:
                action = None
            if action is None:
                continue
            scanned += 1
            keys = _dict_keys(detail) & _SCOPE_KEYS
            if keys:
                found[action] |= keys
    return found, scanned


def test_every_audit_write_with_a_scope_key_is_narrowed_or_named_whole() -> None:
    found, scanned = _census()
    # Positive controls. The count is of every call with a resolvable first argument and a
    # ``detail=`` keyword, audit writes and others (``CheckResult`` among them), so it shows only
    # that the scan ran over the tree. The ``missing`` check is what shows it still sees audit
    # writers: each narrowed action is written with a scope key in a literal detail.
    assert scanned > 100, f"the scan saw only {scanned} calls; the instrument is broken"
    # The population the ``unclassified`` walk below draws from: the four narrowed actions and the
    # four _WHOLE_ROW names, eight measured on 2026-11-10.
    assert len(found) >= 8, f"the census found only {sorted(found)}; the instrument is broken"
    missing = CHANNEL_LIST_ACTIONS - set(found)
    assert not missing, f"the census no longer sees these narrowed writers: {sorted(missing)}"
    unclassified = {
        action: sorted(keys)
        for action, keys in found.items()
        if action not in CHANNEL_LIST_ACTIONS and action not in _WHOLE_ROW
    }
    assert not unclassified, (
        "these audit actions write a key that can carry a channel scope or its source, and are "
        "neither narrowed in audit_visibility._NARROWED nor named in _WHOLE_ROW here: "
        f"{unclassified}"
    )


def test_the_whole_row_list_names_no_stale_or_narrowed_action() -> None:
    found, _ = _census()
    assert not set(_WHOLE_ROW) & CHANNEL_LIST_ACTIONS
    stale = sorted(set(_WHOLE_ROW) - set(found))
    assert not stale, f"_WHOLE_ROW names actions the census no longer finds: {stale}"
