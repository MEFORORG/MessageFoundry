# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every identity is built from whole roles (vault BACKLOG #3474, item 11).

The rule that a ``messages:view_raw`` role also holds ``messages:view_summary`` is judged per role
(``raw_body_without_summary``, vault BACKLOG #2727). It reaches a user only if each identity is
the union of whole roles: the built-in ones, plus each custom role's decoded set. This file holds
both halves of that premise:

* ``Identity.build`` refuses a built set holding the first without the second, which whole roles
  cannot produce.
* Its callers in the engine are pinned, each passing whole roles, and nothing in the engine
  constructs an ``Identity`` directly, which would skip that check.

The caller pin reads the code's shape, so it says nothing about a narrowed set that a new caller
assembles and that happens to stay coherent. A new caller fails here and has to be read.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

import pytest

import messagefoundry
from messagefoundry.auth.identity import AuthProvider, Identity
from messagefoundry.auth.permissions import (
    Permission,
    Role,
    permissions_for_roles,
    raw_body_without_summary,
)
from tests._ast_sites import named_func, parse_source

_PKG = Path(messagefoundry.__file__).resolve().parent

#: Each engine function that calls ``Identity.build``, as ``(module, function)``. ``<module>`` is a
#: call at module level. Each passes whole roles: built-in roles by name, and custom-role
#: permissions only as ``_custom_permissions_for_ids``' union of whole decoded rows.
_REVIEWED_BUILD_CALLERS = frozenset(
    {
        # The embedder's system identity: every built-in role, no custom one.
        ("api/security.py", "<module>"),
        # A directory sign-in, with the custom roles its groups map to.
        ("auth/service.py", "_complete_ad_login"),
        # Every other resolve of an account.
        ("auth/service.py", "_build_identity"),
    }
)

#: The one function whose result an ``extra_permissions=`` argument may carry.
_CUSTOM_UNION = "_custom_permissions_for_ids"


def _build(roles: Iterable[Role], extra_permissions: Iterable[Permission] = ()) -> Identity:
    return Identity.build(
        user_id="u1",
        username="synthetic-user",
        auth_provider=AuthProvider.LOCAL,
        roles=roles,
        extra_permissions=extra_permissions,
    )


def test_build_refuses_view_raw_without_view_summary() -> None:
    with pytest.raises(ValueError, match="whole roles"):
        _build(roles=(), extra_permissions={Permission.MESSAGES_VIEW_RAW})


def test_build_accepts_a_whole_custom_role_and_every_built_in_role() -> None:
    whole = {Permission.MESSAGES_VIEW_RAW, Permission.MESSAGES_VIEW_SUMMARY}
    assert Permission.MESSAGES_VIEW_RAW in _build(roles=(), extra_permissions=whole).permissions
    # A built-in role's summary pairs with a custom role's raw read: both are whole roles.
    summary_roles = [
        r for r in Role if Permission.MESSAGES_VIEW_SUMMARY in permissions_for_roles({r})
    ]
    assert summary_roles, "no built-in role grants view_summary: the case below is vacuous"
    _build(roles=summary_roles[:1], extra_permissions={Permission.MESSAGES_VIEW_RAW})
    for role in Role:
        # Control for the refusal above: no built-in role has the refused shape on its own.
        assert not raw_body_without_summary(permissions_for_roles({role})), role
        _build(roles=(role,))


_Func = ast.FunctionDef | ast.AsyncFunctionDef


def _engine_trees() -> dict[str, ast.Module]:
    """Every engine module that names ``Identity``, parsed. The screen only skips the parse."""
    trees = {}
    for path in sorted(_PKG.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if "Identity" in source:
            trees[path.relative_to(_PKG).as_posix()] = parse_source(source)
    return trees


def _enclosing(tree: ast.Module) -> dict[ast.AST, _Func | None]:
    """Each node's innermost enclosing function, or ``None`` at module level."""
    owner: dict[ast.AST, _Func | None] = {}

    def visit(node: ast.AST, func: _Func | None) -> None:
        for child in ast.iter_child_nodes(node):
            inner = child if isinstance(child, _Func) else func
            owner[child] = inner
            visit(child, inner)

    visit(tree, None)
    return owner


def _identity_calls(tree: ast.Module) -> list[tuple[ast.Call, str]]:
    """Each call to ``Identity.build`` (``"build"``) or ``Identity(...)`` (``"direct"``)."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "Identity":
            found.append((node, "direct"))
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "build"
            and isinstance(func.value, ast.Name)
            and func.value.id == "Identity"
        ):
            found.append((node, "build"))
    return found


def _extra_permissions_source(call: ast.Call, function: ast.AST | None) -> str | None:
    """What a call's ``extra_permissions=`` names: the function its value was assigned from, or
    ``None`` when the call passes no such keyword. Anything else reads as ``"<unreviewed>"``."""
    value = next((kw.value for kw in call.keywords if kw.arg == "extra_permissions"), None)
    if value is None:
        return None
    if not isinstance(value, ast.Name) or function is None:
        return "<unreviewed>"
    sources = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == value.id for t in node.targets
        ):
            rhs = node.value.value if isinstance(node.value, ast.Await) else node.value
            if (
                isinstance(rhs, ast.Call)
                and isinstance(rhs.func, ast.Attribute)
                and isinstance(rhs.func.value, ast.Name)
                and rhs.func.value.id == "self"
            ):
                sources.add(rhs.func.attr)
            else:
                sources.add("<unreviewed>")
    return sources.pop() if len(sources) == 1 else "<unreviewed>"


def test_identity_build_callers_are_the_reviewed_ones() -> None:
    callers: set[tuple[str, str]] = set()
    direct: list[str] = []
    unreviewed: list[str] = []
    for rel, tree in _engine_trees().items():
        owner = _enclosing(tree)
        for call, kind in _identity_calls(tree):
            if rel == "auth/identity.py":
                continue  # Identity.build itself constructs the instance
            func = owner.get(call)
            if kind == "direct":
                direct.append(f"{rel}:{call.lineno}")
                continue
            callers.add((rel, "<module>" if func is None else func.name))
            source = _extra_permissions_source(call, func)
            if source not in (None, _CUSTOM_UNION):
                unreviewed.append(f"{rel}:{call.lineno} extra_permissions from {source}")
    assert not direct, f"an Identity built directly skips Identity.build's check: {direct}"
    assert callers == _REVIEWED_BUILD_CALLERS, (
        f"Identity.build's callers changed: {sorted(callers ^ _REVIEWED_BUILD_CALLERS)}. Read the "
        "new one: it must pass whole roles. Then register it here."
    )
    assert not unreviewed, unreviewed


def test_the_custom_role_union_adds_whole_decoded_rows_only() -> None:
    """``_custom_permissions_for_ids`` grows its result only by a whole decoded row."""
    source = (_PKG / "auth" / "service.py").read_text(encoding="utf-8")
    # Exactly one, or it raises: a renamed or doubled union is not the reviewed one.
    function = named_func(parse_source(source), _CUSTOM_UNION)
    grows = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.AugAssign | ast.Call)
        and (
            isinstance(node, ast.AugAssign)
            or (isinstance(node.func, ast.Attribute) and node.func.attr in {"add", "update"})
        )
    ]
    assert grows, "the union is never grown: the scan is dead"
    for node in grows:
        assert isinstance(node, ast.AugAssign) and isinstance(node.op, ast.BitOr), ast.dump(node)
        value = node.value
        assert (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "decode_custom_role_permissions"
        ), ast.unparse(node)


def test_the_caller_pin_fires_on_a_narrowed_set() -> None:
    """A caller passing anything but the reviewed union reads as unreviewed."""
    tree = ast.parse(
        "async def f(self):\n"
        "    picked = {Permission.MESSAGES_VIEW_RAW}\n"
        "    return Identity.build(roles=(), extra_permissions=picked)\n"
    )
    ((call, kind),) = _identity_calls(tree)
    assert kind == "build"
    assert _extra_permissions_source(call, named_func(tree, "f")) == "<unreviewed>"
    good = ast.parse(
        "async def f(self):\n"
        "    perms = await self._custom_permissions_for_ids(ids)\n"
        "    return Identity.build(roles=(), extra_permissions=perms)\n"
    )
    ((call, _kind),) = _identity_calls(good)
    assert _extra_permissions_source(call, named_func(good, "f")) == _CUSTOM_UNION
