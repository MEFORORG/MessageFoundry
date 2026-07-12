# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The authoritative static wiring graph over a loaded :class:`Registry` (ADR 0091 D1).

One derivation of the inbound → router → handler → outbound edges, consumed by the ``graph`` CLI
(the IDE's CONNECTIONS view), the reverse-reachability index (#152/#176), and the ``send-target``
advisory check — previously three divergent extractors. Edges are **AST-first** (the ADR 0076 static
discipline: parse the defining module, never re-import it) with the compiled-``co_consts`` string
scan retained as a fallback tier, and every edge carries its **provenance**:

* ``declared`` — the structured ``inbound -> router`` binding on the Registry;
* ``literal`` — AST-proven: a string literal, a module-level ``NAME = "..."`` constant (validated
  against the WHOLE module: a ``global NAME`` in any function or any second module-scope binding —
  ``NAME += ...``, ``for NAME in ...``, an import alias — disqualifies it), or a
  **conservatively-proven function-local** (single-name assignments, branch reassignment,
  ``append``/``extend``/``+=`` accumulation of proven lists, ``list()``/``sorted()`` copies, list
  ``+`` concatenation, multi-``return`` unions) in a Router ``return`` or a ``Send(...)`` target —
  any aliasing/mutation escape the dataflow cannot replay (a bare-name alias, a call argument, a
  closure, a walrus/container capture, a possible *str* concatenation) poisons the local back to
  unresolvable;
* ``heuristic`` — the name appears as a string constant somewhere in the function's compiled code
  (the pre-ADR-0091 signal: right for names written literally, blind to intent), or the function
  references a **demoted** module constant — a disqualified ``NAME = "..."`` candidate keeps its
  once-literal value at this tier rather than vanishing (edges must never shrink below the
  ``co_consts`` tier: a dropped edge is a false dead-config report).

A Router return / ``Send`` target the AST cannot resolve to a string (a computed name) marks the
element **dynamic** — surfaced explicitly, never silently dropped (AC-3); so does a **generator**
Router (its *yielded* values route at runtime) and a Handler ``return`` expression that is not
provably ``Send``-free (the runtime partitions by ``isinstance``, so a helper-built ``Send`` —
``return _mk(msg)`` — still delivers; ``Send`` calls themselves are recognized through
``import ... as`` aliases). A **literal** target
that names nothing registered is reported as **dangling** (the ``send-target`` advisory, AC-2). The
runtime fail-closed path (``transform_one``; a ``Send`` may target an outbound **or** a pass-through
(PT) inbound) remains the authority — this module is tooling, pure and stdlib-only (no I/O beyond
reading the already-loaded modules' source, no engine state)."""

from __future__ import annotations

import ast
import inspect
from collections.abc import Iterator
from dataclasses import dataclass, field
from types import CodeType
from typing import Literal

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import Registry

__all__ = [
    "DanglingRef",
    "EdgeProvenance",
    "WiringEdge",
    "WiringGraph",
    "build_wiring_graph",
]

EdgeProvenance = Literal["declared", "literal", "heuristic"]


@dataclass(frozen=True)
class WiringEdge:
    """One directed wiring edge: ``source`` (a ``source_kind``) names ``target`` (a ``target_kind``)."""

    source_kind: str
    source: str
    target_kind: str
    target: str
    provenance: EdgeProvenance


@dataclass(frozen=True)
class DanglingRef:
    """A **literal** target that resolves to nothing registered (a typo the runtime would dead-letter)."""

    source_kind: str
    source: str
    target: str
    expected: str  # "handler" | "outbound/pass-through"


@dataclass(frozen=True)
class WiringGraph:
    """The whole estate's static wiring: edges + the elements whose targets are not fully static."""

    edges: tuple[WiringEdge, ...]
    # Elements ("router"/"handler", name) with at least one statically-unresolvable target — their
    # edge list may be incomplete and MUST be rendered with an explicit dynamic marker (AC-3).
    dynamic: frozenset[tuple[str, str]]
    dangling: tuple[DanglingRef, ...]
    _fwd: dict[tuple[str, str], list[WiringEdge]] = field(
        default_factory=dict, repr=False, compare=False
    )
    _rev: dict[tuple[str, str], list[WiringEdge]] = field(
        default_factory=dict, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        for e in self.edges:
            self._fwd.setdefault((e.source_kind, e.source), []).append(e)
            self._rev.setdefault((e.target_kind, e.target), []).append(e)

    def targets(self, source_kind: str, source: str) -> list[WiringEdge]:
        """Every edge out of ``(source_kind, source)`` — its forward wiring."""
        return list(self._fwd.get((source_kind, source), ()))

    def referrers(self, target_kind: str, target: str) -> list[WiringEdge]:
        """Every edge into ``(target_kind, target)`` — its fan-in (who feeds / sends to it)."""
        return list(self._rev.get((target_kind, target), ()))

    def is_dynamic(self, kind: str, name: str) -> bool:
        """True when this element has a statically-unresolvable target (edge list may be incomplete)."""
        return (kind, name) in self.dynamic


# ---------------------------------------------------------------------------
# AST tier
# ---------------------------------------------------------------------------


def _string_consts(code: CodeType) -> set[str]:
    """Every ``str`` constant in a code object, recursing into nested code — the heuristic tier."""
    out: set[str] = set()
    for const in code.co_consts:
        if isinstance(const, str):
            out.add(const)
        elif isinstance(const, CodeType):
            out |= _string_consts(const)
    return out


def _code_of(fn: object) -> CodeType | None:
    """The ``__code__`` of a registered Router/Handler (unwrapping decorators), or ``None``."""
    target = inspect.unwrap(fn) if callable(fn) else fn
    return getattr(target, "__code__", None)


class _ModuleInfo:
    """One parsed defining module: function defs by name, proven-constant str names, demoted
    constants, every module-scope binding, and the local names the wiring constructors go by.

    A *constant* means proven single-binding: bound exactly once in module scope (the WHOLE module
    scope — compound statements included, function/class bodies excluded) by a top-level
    ``NAME = "literal"``, and never declared ``global`` in any function. A module-level
    ``NAME += ...``, ``for NAME in ...``, ``import ... as NAME``, ``del NAME`` or a same-named
    ``def``/``class`` all disqualify it — the "constant" would be stale at runtime. A disqualified
    candidate is **demoted**, not dropped: its once-literal value survives as a heuristic edge
    candidate for any function referencing the name (a dropped edge = a false dead-config report)."""

    def __init__(self, tree: ast.Module) -> None:
        self.functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        global_decls: set[str] = set()
        send_locals: set[str] = {"Send"}
        ctor_locals: set[str] = {"Send", "SetState", "SetMeta"}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                self.functions.setdefault(node.name, []).append(node)
            elif isinstance(node, ast.Global):
                global_decls.update(node.names)
            elif isinstance(node, ast.ImportFrom):
                # `from messagefoundry import Send as _S` still builds real Sends (the runtime
                # partitions by isinstance, not by call-site name) — track the aliases.
                for a in node.names:
                    if a.name in ("Send", "SetState", "SetMeta"):
                        ctor_locals.add(a.asname or a.name)
                        if a.name == "Send":
                            send_locals.add(a.asname or a.name)
        # Top-level NAME = "literal" candidates. This is the common miss of the co_consts tier:
        # the constant lives in the MODULE's code object, not the function's, so the old scan
        # never saw it (the truncated-chain defect).
        str_values: dict[str, set[str]] = {}
        for stmt in tree.body:
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(stmt, ast.Assign):
                targets, value = stmt.targets, stmt.value
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                targets, value = [stmt.target], stmt.value
            if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
                continue
            for t in targets:
                if isinstance(t, ast.Name):
                    str_values.setdefault(t.id, set()).add(value.value)
        counts: dict[str, int] = {}
        _count_module_bindings(tree, counts)
        # EVERY module-scope binding, whatever bound it — an Assign of a non-str value or an
        # import alias still shadows a builtin (`sorted = _evil`), which .constants can't see.
        self.bindings: frozenset[str] = frozenset(counts)
        self.constants: dict[str, str] = {
            name: next(iter(values))
            for name, values in str_values.items()
            if len(values) == 1 and counts.get(name, 0) == 1 and name not in global_decls
        }
        self.demoted: dict[str, frozenset[str]] = {
            name: frozenset(values)
            for name, values in str_values.items()
            if name not in self.constants
        }
        self.send_names: frozenset[str] = frozenset(send_locals)
        self.result_ctors: frozenset[str] = frozenset(ctor_locals)


def _count_module_bindings(node: ast.AST, counts: dict[str, int]) -> None:
    """Count every binding of each name in MODULE scope (descending into compound statements but
    not into function/lambda/class bodies, which bind their own scopes)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            counts[child.name] = counts.get(child.name, 0) + 1  # the def/class name itself binds
            continue
        if isinstance(child, ast.Lambda):
            continue
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store | ast.Del):
            counts[child.id] = counts.get(child.id, 0) + 1
        elif isinstance(child, ast.alias):
            base = (child.asname or child.name).split(".")[0]
            counts[base] = counts.get(base, 0) + 1
        elif isinstance(child, ast.ExceptHandler) and child.name is not None:
            counts[child.name] = counts.get(child.name, 0) + 1
        elif isinstance(child, ast.MatchAs | ast.MatchStar) and child.name is not None:
            counts[child.name] = counts.get(child.name, 0) + 1
        elif isinstance(child, ast.MatchMapping) and child.rest is not None:
            counts[child.rest] = counts.get(child.rest, 0) + 1
        _count_module_bindings(child, counts)


def _parse_module(path: str, cache: dict[str, _ModuleInfo | None]) -> _ModuleInfo | None:
    """Parse + cache a defining module; ``None`` when unreadable/unparseable (heuristic tier only)."""
    if path not in cache:
        try:
            with open(path, encoding="utf-8") as f:
                cache[path] = _ModuleInfo(ast.parse(f.read()))
        except (OSError, SyntaxError, ValueError):
            cache[path] = None
    return cache[path]


def _locate(
    fn: object, cache: dict[str, _ModuleInfo | None]
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, _ModuleInfo] | None:
    """Find the AST ``def`` of a registered function: by name, nearest to its ``co_firstlineno``."""
    code = _code_of(fn)
    name = getattr(fn, "__name__", None)
    if code is None or not isinstance(name, str):
        return None
    info = _parse_module(code.co_filename, cache)
    if info is None:
        return None
    candidates = info.functions.get(name, [])
    if not candidates:
        return None
    best = min(candidates, key=lambda n: abs(n.lineno - code.co_firstlineno))
    return best, info


# ---------------------------------------------------------------------------
# Function-local dataflow (conservative may-route union)
# ---------------------------------------------------------------------------


@dataclass
class _Entry:
    """One tracked local: the union of string names it may hold + the value *kinds* seen.

    ``kinds`` ⊆ {"str", "list"} — kind-awareness is what keeps the union sound: ``+``/``+=`` are
    replayed as element union only between proven lists (str concatenation composes CHARACTERS,
    not names), and only immutable (str-only) locals are exempt from aliasing escapes."""

    names: set[str] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)


# name -> _Entry, or ``None`` (POISONED — an escape/mutation the analysis cannot replay).
_LocalEnv = dict[str, _Entry | None]

# The only list mutations the value scan can replay; everything else on a local poisons it.
_LIST_GROW = frozenset({"append", "extend"})
# Builtin copy/materialize calls the dataflow may see through (``list(x)`` copies — no alias
# survives); honored only when the name is not shadowed by a local, constant, or module function.
_COPY_CALLS = frozenset({"list", "tuple", "set", "sorted", "frozenset"})

_STR_KIND = frozenset({"str"})
_LIST_KIND = frozenset({"list"})

# (names, kinds, saw_dynamic) — the static resolution of one expression.
_Resolution = tuple[set[str], frozenset[str], bool]

# Escape-scan consumption modes for an expression's value:
#   capture — the value is stored/kept (an alias to a mutable local would go stale invisibly);
#   consume — only the value's ELEMENTS are copied out (extend/+=/list-concat/copy-call operand);
#   read    — the value is read and discarded (a test, an iterable, a comparison).
_Mode = Literal["capture", "consume", "read"]


def _called_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _send_target(call: ast.Call) -> ast.expr | None:
    """The target expression of a ``Send(...)`` call: positional arg 0 or the ``to=`` keyword."""
    if call.args:
        arg0 = call.args[0]
        return None if isinstance(arg0, ast.Starred) else arg0
    return next((kw.value for kw in call.keywords if kw.arg == "to"), None)


def _is_copy_call(call: ast.Call, bindings: frozenset[str], env: _LocalEnv | None) -> bool:
    """True for an unshadowed builtin copy call (``list(x)``, ``sorted(x)``, …) of ≤ 1 argument.

    *Unshadowed* is checked against EVERY module-scope binding — ``sorted = _evil`` or
    ``from helpers import evil as sorted`` rebinds the name without being a str constant or a
    ``def`` — plus the function's own locals."""
    func = call.func
    return (
        isinstance(func, ast.Name)
        and func.id in _COPY_CALLS
        and len(call.args) <= 1
        and not call.keywords
        and not any(isinstance(a, ast.Starred) for a in call.args)
        and func.id not in bindings
        and (env is None or func.id not in env)
    )


def _ifexp_test_safe(
    test: ast.expr, env: _LocalEnv | None, tracked: frozenset[str] = frozenset()
) -> bool:
    """True when an ``IfExp`` test cannot invalidate resolution of the branches.

    The escape scan exempts ``Return`` subtrees, so a mutating call in a returned conditional's
    TEST position (``targets if targets.append(X) else targets``) is invisible to both passes —
    the one place a call can silently touch a name resolution depends on. A test is unsafe when
    it binds anything (walrus) or contains a call whose subtree names a value-tracked local or a
    ``tracked`` (send-plumbing) local; calls over untracked names (``msg.field(...)``) cannot
    alias a fresh, never-escaping local and stay safe."""
    for sub in ast.walk(test):
        if isinstance(sub, ast.NamedExpr | ast.Await | ast.Yield | ast.YieldFrom):
            return False
        if isinstance(sub, ast.Call):
            for n in ast.walk(sub):
                if isinstance(n, ast.Name) and (
                    n.id in tracked or (env is not None and env.get(n.id) is not None)
                ):
                    return False
    return True


def _resolve_value(
    expr: ast.expr,
    constants: dict[str, str],
    bindings: frozenset[str],
    env: _LocalEnv | None,
) -> _Resolution:
    """Statically resolve an expression: ``(names, kinds, saw_dynamic)``.

    ``env`` is the enclosing function's local-dataflow environment: locals shadow module constants,
    and a POISONED local resolves to nothing (``saw_dynamic``) — it never contributes literal names."""

    def rec(e: ast.expr) -> _Resolution:
        return _resolve_value(e, constants, bindings, env)

    if isinstance(expr, ast.Constant):
        if expr.value is None:
            return set(), frozenset(), False
        if isinstance(expr.value, str):
            return {expr.value}, _STR_KIND, False
        return set(), frozenset(), True
    if isinstance(expr, ast.Name):
        if env is not None and expr.id in env:
            entry = env[expr.id]
            if entry is None:
                return set(), frozenset(), True
            return set(entry.names), frozenset(entry.kinds), False
        resolved = constants.get(expr.id)
        if resolved is not None:
            return {resolved}, _STR_KIND, False
        return set(), frozenset(), True
    if isinstance(expr, ast.List | ast.Tuple | ast.Set):
        names: set[str] = set()
        dynamic = False
        for elt in expr.elts:
            got, kinds, dyn = rec(elt)
            names |= got
            # A nested container is not a flat list of names — never flatten it into edges.
            dynamic = dynamic or dyn or "list" in kinds
        return names, _LIST_KIND, dynamic
    if isinstance(expr, ast.IfExp):
        # The test never contributes names, but it can MUTATE them (`targets if
        # targets.append(X) else targets`) — resolution is only sound over a safe test.
        if not _ifexp_test_safe(expr.test, env):
            return set(), frozenset(), True
        a_names, a_kinds, a_dyn = rec(expr.body)
        b_names, b_kinds, b_dyn = rec(expr.orelse)
        return a_names | b_names, a_kinds | b_kinds, a_dyn or b_dyn
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        l_names, l_kinds, l_dyn = rec(expr.left)
        r_names, r_kinds, r_dyn = rec(expr.right)
        # Element union is only sound for list + list; str concatenation composes characters
        # ("h_one" + "x" routes to "h_onex", not to h_one) — anything else is unresolvable.
        if l_dyn or r_dyn or l_kinds != _LIST_KIND or r_kinds != _LIST_KIND:
            return set(), frozenset(), True
        return l_names | r_names, _LIST_KIND, False
    if isinstance(expr, ast.Call) and _is_copy_call(expr, bindings, env):
        if not expr.args:
            return set(), _LIST_KIND, False
        names_a, kinds_a, dyn_a = rec(expr.args[0])
        # list("ab") splits characters — only a proven list may be copied through.
        if dyn_a or kinds_a != _LIST_KIND:
            return set(), frozenset(), True
        return names_a, _LIST_KIND, False
    return set(), frozenset(), True


def _iter_own_stmts(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Every statement of ONE function scope, in source order — compound statements (``if``/``for``/
    ``while``/``try``/``with``/``match``) are descended into; nested ``def``/``class`` bodies are
    their own scope and are not."""
    for stmt in body:
        yield stmt
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        for _fname, value in ast.iter_fields(stmt):
            if not isinstance(value, list):
                continue
            for item in value:
                if isinstance(item, ast.stmt):
                    yield from _iter_own_stmts([item])
                elif isinstance(item, ast.ExceptHandler | ast.match_case):
                    yield from _iter_own_stmts(item.body)


def _binding_poisons(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names the dataflow can never track: every binding the VALUE scan does not replay.

    That is every ``Name`` Store/Del anywhere in the subtree (``for``/``with``-as/walrus/tuple/
    comprehension targets, nested-scope assignments — a nested binding conservatively shadows the
    outer name) EXCEPT the own-body single-``Name`` assign/ann-assign/aug-assign targets the value
    scan replays; plus ``global``/``nonlocal`` declarations, import aliases, ``except``-as and
    ``match`` captures, nested ``def``/``class`` names, and every function parameter (its value is
    caller-chosen, and it must shadow a same-named module constant)."""
    poisoned: set[str] = set()
    replayed_targets: set[int] = set()
    for stmt in _iter_own_stmts(node.body):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            replayed_targets.add(id(stmt.targets[0]))
        elif isinstance(stmt, ast.AnnAssign | ast.AugAssign) and isinstance(stmt.target, ast.Name):
            replayed_targets.add(id(stmt.target))

    def poison_params(args: ast.arguments) -> None:
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            poisoned.add(a.arg)
        if args.vararg is not None:
            poisoned.add(args.vararg.arg)
        if args.kwarg is not None:
            poisoned.add(args.kwarg.arg)

    poison_params(node.args)
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            if isinstance(sub.ctx, ast.Store | ast.Del) and id(sub) not in replayed_targets:
                poisoned.add(sub.id)
        elif isinstance(sub, ast.Global | ast.Nonlocal):
            poisoned.update(sub.names)
        elif isinstance(sub, ast.FunctionDef | ast.AsyncFunctionDef):
            if sub is not node:
                poisoned.add(sub.name)
                poison_params(sub.args)
        elif isinstance(sub, ast.Lambda):
            poison_params(sub.args)
        elif isinstance(sub, ast.ClassDef):
            poisoned.add(sub.name)
        elif isinstance(sub, ast.alias):
            poisoned.add((sub.asname or sub.name).split(".")[0])
        elif isinstance(sub, ast.ExceptHandler):
            if sub.name is not None:
                poisoned.add(sub.name)
        elif isinstance(sub, ast.MatchAs | ast.MatchStar):
            if sub.name is not None:
                poisoned.add(sub.name)
        elif isinstance(sub, ast.MatchMapping):
            if sub.rest is not None:
                poisoned.add(sub.rest)
    return poisoned


class _EscapeScan:
    """The aliasing/mutation escape pass: poison any tracked MUTABLE local whose reference the
    value scan cannot account for.

    A str-only local is immutable — no Load of it can invalidate its entry, so it is never
    escape-poisoned. A may-be-list local is poisoned on ANY Load whose reference is *captured*
    (assigned bare / via walrus / boolop / ifexp, embedded in a container, passed to a call,
    reached from a nested scope) — mutation through the captured alias is invisible to the value
    scan. Loads whose value is only *consumed element-wise* (extend/+= RHS, ``list()`` copies,
    list ``+`` operands) or *read and discarded* (tests, iterables, comparisons, subscript reads)
    are exempt — but a container DISPLAY's elements are always captures, whatever position the
    display sits in (iterating/subscripting it hands the element references out), and so are a
    ``match`` subject (a bare capture pattern binds the subject itself) and an ``assert`` message
    (a failing assert captures it into ``AssertionError.args``, catchable and mutable). Two
    whole-subtree exemptions are safe by exit-or-dynamic: a ``return`` expression
    (any mutation-capable subexpression also fails resolution, marking the element dynamic; and
    execution exits, so no later statement sees a stale value) and — for handlers — a ``Send``
    target expression (resolved the same way, with a proven-list target counted dynamic)."""

    def __init__(
        self,
        env: _LocalEnv,
        bindings: frozenset[str],
        send_names: frozenset[str],
        sends_are_sinks: bool,
    ) -> None:
        self._env = env
        self._bindings = bindings
        self._send_names = send_names
        self._sends_are_sinks = sends_are_sinks

    def _may_list(self, name: str) -> bool:
        entry = self._env.get(name)
        return entry is not None and "list" in entry.kinds

    def _poison(self, name: str) -> None:
        if self._env.get(name) is not None:
            self._env[name] = None

    def _poison_all(self, node: ast.AST) -> None:
        """Poison every may-list Load in a subtree (skipping ``Send`` target sinks)."""
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if self._may_list(node.id):
                self._poison(node.id)
            return
        if (
            self._sends_are_sinks
            and isinstance(node, ast.Call)
            and _called_name(node) in self._send_names
        ):
            target = _send_target(node)
            self._poison_all(node.func)
            for a in node.args:
                if a is not target:
                    self._poison_all(a)
            for kw in node.keywords:
                if kw.value is not target:
                    self._poison_all(kw.value)
            return
        for child in ast.iter_child_nodes(node):
            self._poison_all(child)

    def scan_expr(self, expr: ast.expr, mode: _Mode) -> None:
        if isinstance(expr, ast.Constant):
            return
        if isinstance(expr, ast.Name):
            if isinstance(expr.ctx, ast.Load) and mode == "capture" and self._may_list(expr.id):
                self._poison(expr.id)
            return
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            self.scan_expr(expr.left, "consume")  # concatenation copies both operands
            self.scan_expr(expr.right, "consume")
            return
        if isinstance(expr, ast.IfExp):
            self.scan_expr(expr.test, "read")
            self.scan_expr(expr.body, mode)  # the result may BE either arm — mode propagates
            self.scan_expr(expr.orelse, mode)
            return
        if isinstance(expr, ast.BoolOp):
            for v in expr.values:
                self.scan_expr(v, mode)  # `a or b` yields one operand itself — mode propagates
            return
        if isinstance(expr, ast.List | ast.Tuple | ast.Set):
            # Display elements are ALWAYS captured — even in a read position the display hands out
            # element REFERENCES (`for lst in (adt, oru): lst.append(...)`, `[t][0].append(...)`),
            # so the mutation through the alias would be invisible. A Constant capture is a no-op,
            # so the proven-literal idioms (extend([...]) / += [...]) are unaffected.
            for elt in expr.elts:
                self.scan_expr(elt, "capture")
            return
        if isinstance(expr, ast.Starred):
            self.scan_expr(expr.value, "read" if mode == "read" else "consume")
            return
        if isinstance(expr, ast.Dict):
            # Same as the sequence displays: `{0: t}[0].append(...)` reaches t through a
            # read-position display — keys and values are always captures.
            for key in expr.keys:
                if key is not None:
                    self.scan_expr(key, "capture")
            for value in expr.values:
                self.scan_expr(value, "capture")
            return
        if isinstance(expr, ast.Call):
            if self._sends_are_sinks and _called_name(expr) in self._send_names:
                self._poison_all(expr)  # sink-aware: skips the target, poisons the other args
                return
            if _is_copy_call(expr, self._bindings, self._env):
                for a in expr.args:
                    self.scan_expr(a, "consume")  # list(x) copies — no alias survives
                return
            self._poison_all(expr)  # any other call may mutate/alias every argument
            return
        if isinstance(expr, ast.Compare):
            self.scan_expr(expr.left, "read")
            for comp in expr.comparators:
                self.scan_expr(comp, "read")
            return
        if isinstance(expr, ast.UnaryOp):
            self.scan_expr(expr.operand, "read")
            return
        if isinstance(expr, ast.Subscript):
            self.scan_expr(expr.value, "read")  # an element read/slice copy, not the list itself
            self.scan_expr(expr.slice, "read")
            return
        if isinstance(expr, ast.Slice):
            for part in (expr.lower, expr.upper, expr.step):
                if part is not None:
                    self.scan_expr(part, "read")
            return
        if isinstance(expr, ast.JoinedStr):
            for value in expr.values:
                self.scan_expr(value, "read")
            return
        if isinstance(expr, ast.FormattedValue):
            self.scan_expr(expr.value, "read")
            if expr.format_spec is not None:
                self.scan_expr(expr.format_spec, "read")
            return
        if isinstance(expr, ast.NamedExpr):
            self.scan_expr(expr.value, "capture")  # a walrus captures the reference
            return
        # Lambdas, comprehensions (lazily capture), await/yield, attribute reads (bound-method
        # capture: `f = targets.append`), and anything unrecognized — conservative.
        self._poison_all(expr)

    def scan_stmts(self, stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            self.scan_stmt(stmt)

    def scan_stmt(self, stmt: ast.stmt) -> None:  # noqa: PLR0911, PLR0912
        if isinstance(stmt, ast.Return):
            return  # exit-or-dynamic: safe whole-subtree exemption (see the class docstring)
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            self._poison_all(stmt)  # nested scope: closures read/mutate invisibly
            return
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                if not isinstance(t, ast.Name):
                    self._poison_all(t)  # targets[0] = ... / (a, b) = ... mutates/aliases
            self.scan_expr(stmt.value, "capture")
            return
        if isinstance(stmt, ast.AnnAssign):
            if not isinstance(stmt.target, ast.Name):
                self._poison_all(stmt.target)
            if stmt.value is not None:
                self.scan_expr(stmt.value, "capture")
            return
        if isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name) and isinstance(stmt.op, ast.Add):
                self.scan_expr(stmt.value, "consume")  # += copies the RHS's elements
            else:
                if not isinstance(stmt.target, ast.Name):
                    self._poison_all(stmt.target)
                self.scan_expr(stmt.value, "capture")
            return
        if isinstance(stmt, ast.Expr):
            call = stmt.value
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.attr in _LIST_GROW
                and len(call.args) == 1
                and not call.keywords
                # The exemption holds only for a receiver the value scan actually replays (a live
                # env entry): a poisoned/untracked receiver may alias a tracked list, so its
                # un-replayed mutation must fall through to the conservative call handling.
                and self._env.get(call.func.value.id) is not None
            ):
                # The replayed own-body append/extend: the receiver is exempt; append CAPTURES
                # its argument (it becomes an element), extend copies the elements (consume).
                self.scan_expr(call.args[0], "capture" if call.func.attr == "append" else "consume")
                return
            self.scan_expr(stmt.value, "read")
            return
        if isinstance(stmt, ast.If | ast.While):
            self.scan_expr(stmt.test, "read")
            self.scan_stmts(stmt.body)
            self.scan_stmts(stmt.orelse)
            return
        if isinstance(stmt, ast.For | ast.AsyncFor):
            self.scan_expr(stmt.iter, "read")  # iterating reads; the target is binding-poisoned
            self.scan_stmts(stmt.body)
            self.scan_stmts(stmt.orelse)
            return
        if isinstance(stmt, ast.With | ast.AsyncWith):
            for item in stmt.items:
                self.scan_expr(item.context_expr, "read")
            self.scan_stmts(stmt.body)
            return
        if isinstance(stmt, ast.Try | ast.TryStar):
            self.scan_stmts(stmt.body)
            for handler in stmt.handlers:
                if handler.type is not None:
                    self.scan_expr(handler.type, "read")
                self.scan_stmts(handler.body)
            self.scan_stmts(stmt.orelse)
            self.scan_stmts(stmt.finalbody)
            return
        if isinstance(stmt, ast.Match):
            # A bare capture pattern (`case whole:`) binds the SUBJECT object itself — the
            # binding-poisoned alias then mutates it invisibly, so the subject is a capture.
            self.scan_expr(stmt.subject, "capture")
            for case in stmt.cases:
                self._poison_all(case.pattern)
                if case.guard is not None:
                    self.scan_expr(case.guard, "read")
                self.scan_stmts(case.body)
            return
        if isinstance(stmt, ast.Assert):
            self.scan_expr(stmt.test, "read")
            if stmt.msg is not None:
                # A failing assert captures the message into AssertionError.args — an enclosing
                # `except AssertionError as e:` can mutate it (mirrors the Raise handling below).
                self.scan_expr(stmt.msg, "capture")
            return
        if isinstance(stmt, ast.Raise):
            if stmt.exc is not None:
                self._poison_all(stmt.exc)  # the exception object may capture the reference
            if stmt.cause is not None:
                self._poison_all(stmt.cause)
            return
        if isinstance(stmt, ast.Delete):
            for t in stmt.targets:
                if not isinstance(t, ast.Name):
                    self._poison_all(t)  # del targets[0] mutates; del targets is a binding
            return
        if isinstance(
            stmt,
            ast.Global
            | ast.Nonlocal
            | ast.Import
            | ast.ImportFrom
            | ast.Pass
            | ast.Break
            | ast.Continue,
        ):
            return
        self._poison_all(stmt)  # anything unrecognized — conservative


def _local_env(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    info: _ModuleInfo,
    *,
    sends_are_sinks: bool,
) -> _LocalEnv:
    """Conservative may-route dataflow over ONE function body: name -> union of possible names.

    Iterated to a FIXPOINT (loop-carried values converge; entries only grow toward finite literal
    unions or poison, so it terminates): each round runs the VALUE pass (replay single-``Name``
    assignments, ``append``/``extend`` expression statements and list ``+=``, unioning every
    resolvable value — branch reassignment is the union of both branches) and then the ESCAPE pass
    (:class:`_EscapeScan` — any aliasing/mutation the replay cannot see poisons the local).
    A poisoned name never recovers."""
    constants = info.constants
    bindings = info.bindings

    # Own-body replay sites, in source order: ("assign", name, expr) / ("aug", name, AugAssign) /
    # ("grow", receiver, Call).
    replays: list[tuple[str, str, ast.AST]] = []
    tracked: set[str] = set()
    for stmt in _iter_own_stmts(node.body):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            tracked.add(stmt.targets[0].id)
            replays.append(("assign", stmt.targets[0].id, stmt.value))
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            tracked.add(stmt.target.id)  # even a bare annotation makes the name function-local
            if stmt.value is not None:
                replays.append(("assign", stmt.target.id, stmt.value))
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            tracked.add(stmt.target.id)
            replays.append(("aug", stmt.target.id, stmt))
        elif (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Attribute)
            and isinstance(stmt.value.func.value, ast.Name)
            and stmt.value.func.attr in _LIST_GROW
        ):
            replays.append(("grow", stmt.value.func.value.id, stmt.value))

    env: _LocalEnv = dict.fromkeys(_binding_poisons(node), None)
    for name in tracked:
        env.setdefault(name, _Entry())

    def run_value_pass() -> None:
        for kind, name, payload in replays:
            if kind == "grow" and name not in env:
                env[name] = None  # growing an untracked name still shadows a module constant
                continue
            entry = env[name]
            if entry is None:
                continue  # poisoned stays poisoned
            if kind == "assign":
                assert isinstance(payload, ast.expr)
                got, kinds, dyn = _resolve_value(payload, constants, bindings, env)
                if dyn:
                    env[name] = None
                else:
                    entry.names |= got
                    entry.kinds |= kinds
            elif kind == "aug":
                assert isinstance(payload, ast.AugAssign)
                if not isinstance(payload.op, ast.Add):
                    env[name] = None
                    continue
                got, kinds, dyn = _resolve_value(payload.value, constants, bindings, env)
                # Only list += list is element union; a possible str RHS concatenates characters.
                if dyn or kinds != _LIST_KIND or entry.kinds != {"list"}:
                    env[name] = None
                else:
                    entry.names |= got
            else:  # grow: name.append(x) / name.extend(x)
                assert isinstance(payload, ast.Call)
                if len(payload.args) != 1 or payload.keywords:
                    env[name] = None
                    continue
                got, kinds, dyn = _resolve_value(payload.args[0], constants, bindings, env)
                assert isinstance(payload.func, ast.Attribute)
                required = _STR_KIND if payload.func.attr == "append" else _LIST_KIND
                if dyn or kinds != required or entry.kinds != {"list"}:
                    env[name] = None
                else:
                    entry.names |= got

    escape = _EscapeScan(env, bindings, info.send_names, sends_are_sinks)

    def snapshot() -> dict[str, tuple[frozenset[str], frozenset[str]] | None]:
        return {
            k: None if v is None else (frozenset(v.names), frozenset(v.kinds))
            for k, v in env.items()
        }

    while True:
        before = snapshot()
        run_value_pass()
        escape.scan_stmts(node.body)
        if snapshot() == before:
            return env


class _ReturnCollector(ast.NodeVisitor):
    """The ``return`` expressions of ONE function body — nested defs/lambdas are not its returns —
    plus whether the body ``yield``s (a generator's behavior is its YIELDED values, which the
    return union does not model)."""

    def __init__(self) -> None:
        self.returns: list[ast.expr] = []
        self.saw_yield = False

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self.returns.append(node.value)
            self.generic_visit(node)  # a `return (yield x)` still flags the generator

    def visit_Yield(self, node: ast.Yield) -> None:
        self.saw_yield = True
        self.generic_visit(node)

    def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
        self.saw_yield = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass  # a nested def's returns belong to it, not to the router

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass


def _own_body_collector(node: ast.FunctionDef | ast.AsyncFunctionDef) -> _ReturnCollector:
    collector = _ReturnCollector()
    for stmt in node.body:
        collector.visit(stmt)
    return collector


def _demoted_loads(node: ast.AST, info: _ModuleInfo) -> set[str]:
    """Heuristic candidates from DEMOTED module constants the function references.

    A disqualified ``NAME = "literal"`` lives in the MODULE's code object, so the function-level
    ``co_consts`` scan can never recover its value — dropping it entirely would SHRINK the graph
    below the pre-ADR-0091 tier and create false dead-config reports. The once-literal value(s)
    stay heuristic edges for any function that reads the name."""
    if not info.demoted:
        return set()
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
            values = info.demoted.get(sub.id)
            if values:
                out |= values
    return out


def _send_plumbing_locals(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    info: _ModuleInfo,
    env: _LocalEnv,
    returns: list[ast.expr],
) -> frozenset[str]:
    """Locals that provably hold ONLY this function's own constructor results (a built-up list of
    ``Send(...)``\\ s) — the ``sends = [Send(...)]; sends.append(Send(...)); return sends`` idiom.

    Every ``Send`` such a local carries was a call site the walk already extracted, so returning it
    contributes nothing foreign and must NOT mark the handler dynamic. Qualification is strict:
    every binding is an own-body single-name assign / ``+=`` / statement-level ``append``/``extend``
    of **ctor-safe** values (constants, constructor calls, proven str/list locals or module
    constants, containers/conditionals of those with side-effect-free tests), the name is never
    bound by anything the value scan does not replay (params, nested scopes, loop targets …), and
    it is never READ outside its own mutations and the ``return`` expressions — any alias, call
    argument, or nested-scope read disqualifies it."""

    def ctor_safe(e: ast.expr) -> bool:
        if isinstance(e, ast.Constant):
            return True
        if isinstance(e, ast.Call) and _called_name(e) in info.result_ctors:
            return True
        if isinstance(e, ast.List | ast.Tuple | ast.Set):
            return all(ctor_safe(x) for x in e.elts)
        if isinstance(e, ast.Starred):
            return ctor_safe(e.value)
        if isinstance(e, ast.IfExp):
            return _ifexp_test_safe(e.test, env) and ctor_safe(e.body) and ctor_safe(e.orelse)
        if isinstance(e, ast.Name):
            if e.id in env:
                return env[e.id] is not None
            return e.id in info.constants
        return False

    candidates: dict[str, bool] = {}
    initialized: set[str] = set()
    allowed_loads: set[int] = set()
    for stmt in _iter_own_stmts(node.body):
        name: str | None = None
        ok = False
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            name, ok = stmt.targets[0].id, ctor_safe(stmt.value)
            initialized.add(name)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.value is not None:
                name, ok = stmt.target.id, ctor_safe(stmt.value)
                initialized.add(name)
        elif (
            isinstance(stmt, ast.AugAssign)
            and isinstance(stmt.target, ast.Name)
            and isinstance(stmt.op, ast.Add)
        ):
            name, ok = stmt.target.id, ctor_safe(stmt.value)
        elif (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Attribute)
            and isinstance(stmt.value.func.value, ast.Name)
            and stmt.value.func.attr in ("append", "extend")
        ):
            receiver = stmt.value.func.value
            call = stmt.value
            name = receiver.id
            ok = len(call.args) == 1 and not call.keywords and ctor_safe(call.args[0])
            allowed_loads.add(id(receiver))
        if name is not None:
            candidates[name] = candidates.get(name, True) and ok
    for r in returns:
        for sub in ast.walk(r):
            if isinstance(sub, ast.Name):
                allowed_loads.add(id(sub))
    unreplayed = _binding_poisons(node)
    plumbing: set[str] = set()
    for name, all_safe in candidates.items():
        # A name that is ONLY an append/extend receiver (never assigned in this body) is a module
        # global or closure accumulator — it can carry Sends constructed OUTSIDE this function
        # (verified counterexample: SENDS = [Send(...)] at module level; hh appends + returns it),
        # so it must fall through to the env check (poisoned) and mark the handler dynamic.
        if not all_safe or name in unreplayed or name not in initialized:
            continue
        reads = [
            sub
            for sub in ast.walk(node)
            if isinstance(sub, ast.Name) and sub.id == name and isinstance(sub.ctx, ast.Load)
        ]
        if all(id(read) in allowed_loads for read in reads):
            plumbing.add(name)
    return frozenset(plumbing)


def _send_free_return(
    expr: ast.expr, info: _ModuleInfo, env: _LocalEnv, plumbing: frozenset[str]
) -> bool:
    """True when a handler ``return`` expression provably contributes no ``Send`` beyond the ones
    the call-site walk already extracted.

    ``transform_one`` partitions the returned value by ``isinstance`` — a ``Send`` built by a
    module helper (``return _mk(msg)``) or held in an unproven local still DELIVERS at runtime,
    invisibly to a call-site-name scan. Recognized wiring-constructor calls (``Send``/``SetState``/
    ``SetMeta``, import aliases included), constants, proven str/list locals and module constants,
    **send-plumbing locals** (:func:`_send_plumbing_locals` — a local list of this function's own
    ``Send`` calls), and containers/conditionals of those (side-effect-free tests only) are safe;
    anything else must mark the handler dynamic (AC-3: a possibly-incomplete edge list is
    surfaced, never silent)."""
    if isinstance(expr, ast.Constant):
        return True
    if isinstance(expr, ast.Call) and _called_name(expr) in info.result_ctors:
        return True  # a real constructor call — its Send target was extracted by the walk
    if isinstance(expr, ast.List | ast.Tuple | ast.Set):
        return all(_send_free_return(e, info, env, plumbing) for e in expr.elts)
    if isinstance(expr, ast.Starred):
        return _send_free_return(expr.value, info, env, plumbing)
    if isinstance(expr, ast.IfExp):
        return (
            _ifexp_test_safe(expr.test, env, plumbing)
            and _send_free_return(expr.body, info, env, plumbing)
            and _send_free_return(expr.orelse, info, env, plumbing)
        )
    if isinstance(expr, ast.BoolOp):
        return all(_send_free_return(v, info, env, plumbing) for v in expr.values)
    if isinstance(expr, ast.Name):
        if expr.id in plumbing:
            return True  # holds only this function's own extracted Send calls
        # A PROVEN str/list-of-strs local (or module str constant) cannot hold a Send object.
        if expr.id in env:
            return env[expr.id] is not None
        return expr.id in info.constants
    return False


def _router_returns(
    fn: object, cache: dict[str, _ModuleInfo | None]
) -> tuple[set[str], bool, set[str]] | None:
    """AST tier for a Router: ``(literal names, dynamic, demoted heuristic names)``, or ``None``
    (no AST — heuristic tier only).

    Literal names are the union over its ``return`` statements. A generator router (any ``yield``
    in its own body) is DYNAMIC with NO literal names: ``route_only`` routes the *yielded* values
    (``list(result)``), and a generator's ``return`` value never routes — return-derived "literal"
    edges would be phantoms."""
    located = _locate(fn, cache)
    if located is None:
        return None
    node, info = located
    env = _local_env(node, info, sends_are_sinks=False)
    collector = _own_body_collector(node)
    extra = _demoted_loads(node, info)
    if collector.saw_yield:
        return set(), True, extra
    names: set[str] = set()
    dynamic = False
    for expr in collector.returns:
        got, _kinds, dyn = _resolve_value(expr, info.constants, info.bindings, env)
        names |= got
        dynamic = dynamic or dyn
    return names, dynamic, extra


def _handler_sends(
    fn: object, cache: dict[str, _ModuleInfo | None]
) -> tuple[set[str], bool, set[str]] | None:
    """AST tier for a Handler: ``(Send targets, dynamic, demoted heuristic names)``, or ``None``
    (no AST — heuristic tier only).

    Unlike returns, ``Send`` calls inside nested helpers/comprehensions still belong to this
    handler, so the whole subtree is walked — recognized through import aliases too
    (``from messagefoundry import Send as _S``). The walk is call-site-name-based while the
    runtime partitions by ``isinstance``, so every ``return`` expression must additionally be
    provably Send-free (:func:`_send_free_return`) or the handler is dynamic; a generator handler
    is dynamic too (its yields are collected but never delivered by ``transform_one``, so its
    static story is uncertain either way)."""
    located = _locate(fn, cache)
    if located is None:
        return None
    node, info = located
    # The OUTER function's env; a Send target name bound only inside a nested def was poisoned by
    # the binding scan (nested bindings are never imported as values), so it resolves dynamic.
    env = _local_env(node, info, sends_are_sinks=True)
    names: set[str] = set()
    dynamic = False
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call) or _called_name(sub) not in info.send_names:
            continue
        target = _send_target(sub)
        if target is None:
            dynamic = True
            continue
        got, kinds, dyn = _resolve_value(target, info.constants, info.bindings, env)
        if "list" in kinds:
            dynamic = True  # a Send target must be ONE name; a proven list is a config bug
            continue
        names |= got
        dynamic = dynamic or dyn
    collector = _own_body_collector(node)
    plumbing = _send_plumbing_locals(node, info, env, collector.returns)
    if collector.saw_yield or any(
        not _send_free_return(expr, info, env, plumbing) for expr in collector.returns
    ):
        dynamic = True
    return names, dynamic, _demoted_loads(node, info)


# ---------------------------------------------------------------------------
# The graph
# ---------------------------------------------------------------------------


def _pt_inbound_names(registry: Registry) -> frozenset[str]:
    """Inbound connections that are valid ``Send`` targets (pass-through re-ingress, ADR 0013)."""
    return frozenset(
        name for name, c in registry.inbound.items() if c.spec.type is ConnectorType.PT
    )


def build_wiring_graph(registry: Registry) -> WiringGraph:
    """Build the static wiring graph for ``registry`` (see the module docstring for the tiers)."""
    cache: dict[str, _ModuleInfo | None] = {}
    edges: list[WiringEdge] = []
    dynamic: set[tuple[str, str]] = set()
    dangling: list[DanglingRef] = []
    handler_names = frozenset(registry.handlers)
    outbound_names = frozenset(registry.outbound)
    pt_names = _pt_inbound_names(registry)

    for conn in registry.inbound.values():
        edges.append(WiringEdge("inbound", conn.name, "router", conn.router, "declared"))

    for rname, rfn in sorted(registry.routers.items()):
        ast_result = _router_returns(rfn, cache)
        literal: set[str] = set()
        extra: set[str] = set()  # demoted-constant values — heuristic tier, never dangling
        if ast_result is None:
            dynamic.add(("router", rname))  # unprovable — the heuristic tier may be incomplete
        else:
            literal, saw_dynamic, extra = ast_result
            if saw_dynamic:
                dynamic.add(("router", rname))
        for name in sorted(literal):
            if name in handler_names:
                edges.append(WiringEdge("router", rname, "handler", name, "literal"))
            else:
                dangling.append(DanglingRef("router", rname, name, "handler"))
        code = _code_of(rfn)
        consts = _string_consts(code) if code is not None else set()
        for name in sorted(((consts | extra) & handler_names) - literal):
            edges.append(WiringEdge("router", rname, "handler", name, "heuristic"))

    for hname, hfn in sorted(registry.handlers.items()):
        ast_result = _handler_sends(hfn, cache)
        literal = set()
        extra = set()
        if ast_result is None:
            dynamic.add(("handler", hname))
        else:
            literal, saw_dynamic, extra = ast_result
            if saw_dynamic:
                dynamic.add(("handler", hname))
        for name in sorted(literal):
            if name in outbound_names:
                edges.append(WiringEdge("handler", hname, "outbound", name, "literal"))
            elif name in pt_names:
                edges.append(WiringEdge("handler", hname, "inbound", name, "literal"))
            else:
                dangling.append(DanglingRef("handler", hname, name, "outbound/pass-through"))
        code = _code_of(hfn)
        consts = _string_consts(code) if code is not None else set()
        for name in sorted(((consts | extra) & outbound_names) - literal):
            edges.append(WiringEdge("handler", hname, "outbound", name, "heuristic"))
        for name in sorted(((consts | extra) & pt_names) - literal):
            edges.append(WiringEdge("handler", hname, "inbound", name, "heuristic"))

    return WiringGraph(edges=tuple(edges), dynamic=frozenset(dynamic), dangling=tuple(dangling))
