# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One definition of the AST walks the static guards kept re-deriving.

The guards under ``tests/`` read engine source with ``ast`` to assert things a functional test
cannot reach: that a call is INSIDE a particular function, that a thread-unsafe object is not
named in an off-loop frame, that a rate limiter is applied on a route. **At least** three walks
recur, and each had been written out by hand in module after module:

1. **the name a call resolves to** -- ``f()`` to "f", ``obj.f()`` to "f" (:func:`callee_name`);
2. **the function a guard is about**, located by name rather than by line number
   (:func:`find_funcs`, and :func:`named_func` for the single-subject case);
3. **the calls to a named target** under some node (:func:`calls_to` for which names are called,
   :func:`call_sites` for the nodes themselves).

*At least* is meant literally, not as hedging: route-decorator extraction recurs too and is **not**
covered here, so do not read this list as a census of what ``tests/`` repeats. Nor is every
surviving copy a defect -- several are deliberately narrower than anything below (a receiver-
qualified ``etree.<parse>`` matcher, a class-scoped method lookup, an ``ast.Attribute``-only name
set whose positive assertion :func:`calls_to` would silently weaken). Widening one of those onto a
helper here makes its guard weaker while looking like cleanup.

**The copies were not identical, on two axes, and only one of them is a parameter here.** Say what
happened to each, because a reader who assumes symmetry will mis-read a call site:

- **Name-only against Name-or-Attribute is ``bare_only=``.** It defaults to ``False`` -- the
  permissive spelling -- because that is what most of the replaced copies did, so the default
  preserves their behaviour rather than expressing a preference. A reader at a bare
  ``calls_to(node, {"_register_failure"})`` therefore cannot see from the call alone whether
  ``anything._register_failure()`` satisfies it. It does. Pass ``bare_only=True`` where the guard is
  about a module-level function imported by name, so an unrelated method cannot stand in for it.
- **``def`` against ``async def`` is NOT a parameter: both always match.** Six call sites were
  widened onto that when they were collapsed, five from ``def``-only and one
  (``reauth``) from ``async def``-only. That is safe today and was checked rather than assumed --
  every collapsed name resolves to exactly one def -- but it is a widening, and
  :func:`named_func`'s exactly-one assertion is what keeps it honest: a second definition arriving
  on either axis reds instead of being silently preferred.

A copy that quietly matches more than its author meant turns an ``assert not ...`` green for the
wrong reason, and a copy that matches less makes a guard vacuous. Both failures are silent, which
is why the choice belongs at the call site rather than inside a walk nobody re-reads.

``named_func`` additionally **asserts there is exactly one match**, which the hand-inlined
``next(n for n in ast.walk(tree) if ...)`` did not: ``next`` silently takes the first of several,
so a guard aimed at a module-level function can end up reading a same-named method instead and
still pass. Every call site collapsed onto it here had exactly one match when it was collapsed,
measured, so the assertion is a guard against future drift rather than a change of behaviour.

**Scope: this module is for ``tests/`` only, and the reason is packaging, not taste.**
``messagefoundry/`` and ``scripts/`` carry their own callee-name helpers. They *cannot* be collapsed
onto this one: ``pyproject.toml``'s ``only-include`` ships ``messagefoundry`` alone, and there is no
``tests/__init__.py``, so nothing under ``messagefoundry/`` can import ``_ast_sites`` at all. The
dependency would have to run the other way -- production importing a test helper -- which is why
this is a hard constraint and not a judgement to revisit.

**Do not read that as "a guard may not import a private engine symbol".** Guards here do exactly
that, on purpose, and should keep doing it: ``test_relocated_key_messages.py`` imports
``_RELOCATED_TO_SECURITY`` from the module it checks, which is the point -- the guard and its subject
share one definition instead of two. Reading a private import as the defect would break working
guards. Of the copies left outside ``tests/``, only
``scripts/quality/username_access_key_screen.py`` genuinely differs in behaviour (it returns a
placeholder string where this returns ``None``); the others are equivalent and simply unreachable
from here.
"""

from __future__ import annotations

import ast

__all__ = ["call_sites", "callee_name", "calls_to", "find_funcs", "named_func"]

#: Hoisted: ``A | B`` builds a fresh ``types.UnionType`` per evaluation, and :func:`find_funcs`
#: tests it once per walked node. Measured on the largest tree these guards parse
#: (``pipeline/wiring_runner.py``, about 30k nodes): 27.6 ms inline against 21.2 ms hoisted.
_FUNC_DEF = ast.FunctionDef | ast.AsyncFunctionDef


def callee_name(call: ast.Call, *, bare_only: bool = False) -> str | None:
    """The name ``call`` invokes: ``f()`` to "f", ``obj.f()`` to "f", anything else to ``None``.

    ``bare_only=True`` restricts the match to ``f()`` and returns ``None`` for ``obj.f()``. Use it
    where the guard is about a module-level function that was imported by name, so that an
    unrelated method of the same name cannot satisfy the check.
    """
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and not bare_only:
        return func.attr
    return None


def calls_to(
    node: ast.AST, names: set[str] | frozenset[str], *, bare_only: bool = False
) -> set[str]:
    """Which of ``names`` are called anywhere under ``node``.

    Returns the names found, not the call sites -- use :func:`call_sites` when the nodes matter.
    """
    found: set[str] = set()
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        name = callee_name(sub, bare_only=bare_only)
        if name is not None and name in names:
            found.add(name)
    return found


def call_sites(node: ast.AST, name: str, *, bare_only: bool = False) -> list[ast.Call]:
    """Every call to ``name`` under ``node``, as nodes, in ``ast.walk`` order."""
    return [
        sub
        for sub in ast.walk(node)
        if isinstance(sub, ast.Call) and callee_name(sub, bare_only=bare_only) == name
    ]


def find_funcs(tree: ast.AST, name: str) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Every ``def`` and ``async def`` named ``name`` under ``tree``, nested ones and methods too.

    Returns a list so a caller can tell "absent" from "present" without an exception, which is what
    a liveness receipt needs: a guard whose subject was renamed must report the rename, not raise.
    """
    return [node for node in ast.walk(tree) if isinstance(node, _FUNC_DEF) and node.name == name]


def named_func(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """The one ``def`` or ``async def`` named ``name`` under ``tree``.

    Raises ``AssertionError`` unless there is exactly one. Both failures are real: none means the
    guard's subject was renamed or deleted and the guard is now aimed at nothing, and more than one
    means the name no longer identifies a single function, so whichever the walk reached first is
    an arbitrary choice rather than the subject.
    """
    found = find_funcs(tree, name)
    if len(found) == 1:
        return found[0]
    # Two different failures, so two different diagnoses. Printing the rename story for a
    # duplicate sends the reader hunting a rename that did not happen, and alert_sinks.py -- a
    # live subject here -- already carries three methods named ``send`` across nine classes.
    if not found:
        raise AssertionError(
            f"no function named {name!r} in this tree. The guard that asked for it is aimed at a "
            "subject that has been renamed or removed, so it is now checking nothing: re-derive "
            "which function it means rather than deleting the check."
        )
    at = ", ".join(f"line {f.lineno}" for f in found)
    raise AssertionError(
        f"{len(found)} functions named {name!r} in this tree ({at}), expected exactly one. The "
        "subject has not necessarily moved -- a second same-named def (often a method on another "
        "class) now shadows it, so whichever the walk reaches first is an arbitrary choice. Name "
        "the one meant, by class or by enclosing scope; do not fall back to the first match."
    )
