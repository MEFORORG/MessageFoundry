# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Reverse-reachability / reference index over a loaded :class:`Registry` (#176 dead-config
detection, #152 reverse-dependency / impact analysis).

``validate`` resolves the FORWARD ``inbound -> router`` edge; this module resolves the REVERSE: which
registered objects reference a given one (:meth:`ReferenceIndex.referrers`, #152), and which are
unreachable from the inbound roots (:meth:`ReferenceIndex.unreferenced`, #176 — dead config an author
can delete). Edges come from two sources:

* the **structured** ``inbound -> router`` binding carried on the :class:`Registry`; and
* the **string literals** a Router/Handler function names in its code — a router names its handlers,
  a handler names its ``Send()`` outbounds and its ``code_set()`` / ``reference()`` / ``db_lookup()``
  / ``fhir_lookup()`` tables. Table names are read from the compiled ``co_consts`` (recursing into
  nested comprehensions/closures) of the function, of its ``accepts=`` predicate, and of every
  config-authored helper function either reaches through its globals; a ``CodeSet`` captured at a
  module's top level (``DIET = code_set("diets")``) and read through that global is an edge too
  (BACKLOG #5621). A literal naming tables of two kinds (a code set and a reference both called
  ``"x"``) is attributed by the accessor call it is passed to, and to every such kind when that
  cannot be read.

The literal signal is a **heuristic**: a name mentioned only in a docstring counts as a reference (so
a genuinely-dead object can be missed — a safe false negative), and a dynamically-computed name is
invisible. Both callers are therefore **advisory** and never fail a build. Pure + stdlib-only,
engine-side (no engine state; the only I/O is reading an already-loaded module's source to tell two
same-named tables apart)."""

from __future__ import annotations

import ast
import inspect
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import CellType, CodeType, FunctionType, ModuleType

from messagefoundry.config.code_sets import CodeSet
from messagefoundry.config.wiring import _CONFIG_MODULE_PREFIX, Registry

__all__ = [
    "Reference",
    "ReferenceIndex",
    "SourceCache",
    "build_reference_index",
    "config_module_files",
    "loaded_names",
    "reached_functions",
    "table_kinds",
]

#: The run-time call each table kind is read through, keyed by the simple name the call resolves to
#: (``code_set(...)`` and ``mod.code_set(...)`` alike). Its first positional argument is the table name.
_TABLE_ACCESSORS: dict[str, str] = {
    "code_set": "code_set",
    "reference": "reference",
    "db_lookup": "lookup",
    "fhir_lookup": "fhir_lookup",
}


def _string_consts(code: CodeType) -> set[str]:
    """Every ``str`` constant in a code object, recursing into nested code (comprehensions, closures,
    nested defs) — the heuristic edge signal (a Router/Handler names referenced objects as literals)."""
    out: set[str] = set()
    for const in code.co_consts:
        if isinstance(const, str):
            out.add(const)
        elif isinstance(const, CodeType):
            out |= _string_consts(const)
    return out


def loaded_names(code: CodeType) -> set[str]:
    """Every global or attribute name a code object loads, recursing into nested code."""
    out = set(code.co_names)
    for const in code.co_consts:
        if isinstance(const, CodeType):
            out |= loaded_names(const)
    return out


def _code_of(fn: object) -> CodeType | None:
    """The ``__code__`` of a registered Router/Handler (unwrapping decorators), or ``None`` for a
    callable with no analyzable code object (e.g. a callable instance) — which is then skipped."""
    target = inspect.unwrap(fn) if callable(fn) else fn
    return getattr(target, "__code__", None)


def _is_config_module(name: object, root_module: str) -> bool:
    """Whether ``name`` is a config-authored module: one the loader ran (its mangled prefix), or the
    module the root callable itself was defined in (a registry built in-process)."""
    return isinstance(name, str) and (name.startswith(_CONFIG_MODULE_PREFIX) or name == root_module)


def _cell_value(cell: CellType) -> object:
    try:
        return cell.cell_contents
    except ValueError:  # an empty cell: a free variable not bound yet
        return None


def _reached(fn: object) -> Iterator[FunctionType | CodeSet]:
    """The root function, then every config-authored helper function it reaches through its globals,
    closure cells and imported config modules (transitively), and every ``CodeSet`` those hold.

    Helpers outside config code (the ``messagefoundry`` package, the standard library) are not
    followed: their constants are not the author's table names."""
    root = inspect.unwrap(fn) if callable(fn) else fn
    if not isinstance(root, FunctionType):
        return
    root_module = root.__module__
    seen: set[int] = set()
    stack: list[FunctionType] = [root]
    while stack:
        func = stack.pop()
        if id(func) in seen:
            continue
        seen.add(id(func))
        yield func
        names = loaded_names(func.__code__)
        values: list[object] = [func.__globals__.get(n) for n in names]
        values += [_cell_value(cell) for cell in func.__closure__ or ()]
        values += [
            getattr(value, n, None)
            for value in list(values)
            if isinstance(value, ModuleType) and _is_config_module(value.__name__, root_module)
            for n in names
        ]
        for value in values:
            if isinstance(value, CodeSet):
                if id(value) not in seen:
                    seen.add(id(value))
                    yield value
            elif callable(value):
                target = inspect.unwrap(value)
                if isinstance(target, FunctionType) and _is_config_module(
                    target.__module__, root_module
                ):
                    stack.append(target)


def reached_functions(fn: object) -> list[FunctionType]:
    """``fn`` (unwrapped) and every config-authored helper function it reaches through its globals,
    closure cells and imported config modules, transitively. A non-function callable yields ``[]``."""
    return [f for f in _reached(fn) if isinstance(f, FunctionType)]


def config_module_files(func: FunctionType) -> set[str]:
    """``func``'s own source file and the file of every config module it reads an attribute of
    (``_consts.TARGET``) -- the files whose module-level bindings ``func`` can read."""
    files = {func.__code__.co_filename}
    for name in loaded_names(func.__code__):
        value = func.__globals__.get(name)
        if isinstance(value, ModuleType) and _is_config_module(value.__name__, func.__module__):
            module_file = getattr(value, "__file__", None)
            if isinstance(module_file, str):
                files.add(module_file)
    return files


def table_kinds(registry: Registry) -> dict[str, list[str]]:
    """Every table name -> each table kind that holds it. A name may denote tables of several kinds
    at once (a code set and a reference both called "x"), and each is its own object."""
    out: dict[str, list[str]] = {}
    for kind, names in (
        ("code_set", registry.code_sets),
        ("reference", registry.references),
        ("lookup", registry.lookups),
        ("fhir_lookup", registry.fhir_lookups),
    ):
        for name in names:
            out.setdefault(name, []).append(kind)
    return out


def _accessor_kind(node: ast.Constant, parents: dict[int, ast.AST]) -> str | None:
    """The table kind whose accessor call takes ``node`` as its first positional argument
    (``code_set("x")`` -> ``"code_set"``), or ``None`` when ``node`` sits anywhere else."""
    from messagefoundry.config.graph import _called_name

    parent = parents.get(id(node))
    if not isinstance(parent, ast.Call) or not parent.args or parent.args[0] is not node:
        return None
    name = _called_name(parent)
    return _TABLE_ACCESSORS.get(name) if name is not None else None


class SourceCache:
    """Parsed config sources by file name, for one index build or rename plan."""

    def __init__(self) -> None:
        self._parsed: dict[str, tuple[ast.Module, list[str]] | None] = {}
        self._occurrences: dict[tuple[str, str], dict[tuple[int, int], str | None]] = {}

    def parse(self, file: str) -> tuple[ast.Module, list[str]] | None:
        """``file``'s module tree and its lines, or ``None`` when unreadable or unparseable."""
        if file not in self._parsed:
            try:
                text = Path(file).read_text(encoding="utf-8")
                self._parsed[file] = (ast.parse(text), text.splitlines(keepends=True))
            except (OSError, SyntaxError, ValueError, MemoryError, RecursionError):
                # MemoryError and RecursionError are the parser's width and depth walls (BACKLOG #1858).
                self._parsed[file] = None
        return self._parsed[file]

    def occurrences(self, file: str, value: str) -> dict[tuple[int, int], str | None]:
        """Each place ``file`` spells the string ``value``, as ``(line, char col)`` -> the table kind
        whose accessor takes it as its first argument (``None`` elsewhere).

        A plain literal sits where its token does, so a rename edit at that position covers it. An
        implicit concatenation that folds to ``value``, and an f-string with no interpolation that
        reads ``value``, are occurrences too, at positions no edit can take; a fragment of an f-string
        that interpolates is not, since its value is not ``value``."""
        key = (file, value)
        if key not in self._occurrences:
            self._occurrences[key] = self._find(file, value)
        return self._occurrences[key]

    def _find(self, file: str, value: str) -> dict[tuple[int, int], str | None]:
        parsed = self.parse(file)
        if parsed is None:
            return {}
        tree, lines = parsed
        parents: dict[int, ast.AST] = {}
        out: dict[tuple[int, int], str | None] = {}
        stack: list[ast.AST] = [tree]
        while stack:
            node = stack.pop()
            kind: str | None
            if isinstance(node, ast.JoinedStr):
                # Never descend: a fragment of an f-string is not the string's value.
                parts = node.values
                if not all(isinstance(v, ast.Constant) for v in parts):
                    continue
                if "".join(str(v.value) for v in parts if isinstance(v, ast.Constant)) != value:
                    continue
                kind = None
            elif isinstance(node, ast.Constant) and node.value == value:
                kind = _accessor_kind(node, parents)
            else:
                for child in ast.iter_child_nodes(node):
                    parents[id(child)] = node
                    stack.append(child)
                continue
            line_text = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
            # ast columns are UTF-8 byte offsets; tokenize (and so every rename edit) counts characters.
            col = len(
                line_text.encode("utf-8")[: node.col_offset].decode("utf-8", errors="replace")
            )
            out[(node.lineno, col)] = kind
        return out


def _source_kinds(func: FunctionType, literal: str, sources: SourceCache) -> set[str] | None:
    """The table kinds ``literal`` is read as inside ``func``'s source, by accessor call. ``None`` when
    the source cannot be read, or when any occurrence is not an accessor's first argument (a constant,
    a list, a helper's argument), so the caller falls back to every kind the name could be."""
    try:
        lines, start = inspect.getsourcelines(func)
    except (OSError, TypeError):
        return None
    end = start + len(lines) - 1
    kinds: set[str | None] = {
        kind
        for (line, _col), kind in sources.occurrences(func.__code__.co_filename, literal).items()
        if start <= line <= end
    }
    if not kinds or None in kinds:
        return None
    return {k for k in kinds if k is not None}


@dataclass(frozen=True)
class Reference:
    """One reverse edge — ``referrer`` (a ``referrer_kind``) names ``target`` (a ``target_kind``)."""

    referrer_kind: str
    referrer: str
    target_kind: str
    target: str


@dataclass(frozen=True)
class ReferenceIndex:
    """A reverse-reference index over a :class:`Registry` (its edges, newest-agnostic)."""

    edges: tuple[Reference, ...]

    def referrers(self, target_kind: str, target: str) -> list[Reference]:
        """Every edge whose target is ``(target_kind, target)`` — who references this object (#152)."""
        return [e for e in self.edges if e.target_kind == target_kind and e.target == target]

    def unreferenced(self, registry: Registry) -> list[tuple[str, str]]:
        """Registered objects unreachable from the inbound roots — dead config (#176), as sorted
        ``(kind, name)`` pairs. Inbound connections are the roots and are never reported."""
        adj: dict[tuple[str, str], set[tuple[str, str]]] = {}
        for e in self.edges:
            adj.setdefault((e.referrer_kind, e.referrer), set()).add((e.target_kind, e.target))
        reachable: set[tuple[str, str]] = {
            (e.target_kind, e.target) for e in self.edges if e.referrer_kind == "inbound"
        }
        stack = list(reachable)
        while stack:
            for nxt in adj.get(stack.pop(), ()):
                if nxt not in reachable:
                    reachable.add(nxt)
                    stack.append(nxt)
        registered: list[tuple[str, str]] = [
            *(("router", n) for n in registry.routers),
            *(("handler", n) for n in registry.handlers),
            *(("outbound", n) for n in registry.outbound),
            *(("code_set", n) for n in registry.code_sets),
            *(("reference", n) for n in registry.references),
            *(("lookup", n) for n in registry.lookups),
            *(("fhir_lookup", n) for n in registry.fhir_lookups),
        ]
        return sorted(obj for obj in registered if obj not in reachable)


def build_reference_index(registry: Registry) -> ReferenceIndex:
    """Build the reverse-reference index from the authoritative static wiring graph (ADR 0091 D1 —
    the inbound/router/handler/outbound edges, AST-first with the ``co_consts`` heuristic as a
    fallback tier) plus the ``code_set()``/``reference()``/lookup-table edges this module reads from
    each referrer's reached functions (see the module docstring)."""
    from messagefoundry.config.graph import build_wiring_graph

    kinds_by_name = table_kinds(registry)

    # Wiring edges (inbound -> router -> handler -> outbound/PT): the shared extractor. Reachability
    # wants MAXIMAL edges (a missed edge = a false "dead" report), so every provenance tier counts.
    edges: list[Reference] = [
        Reference(e.source_kind, e.source, e.target_kind, e.target)
        for e in build_wiring_graph(registry).edges
    ]
    # Table edges. A referrer's callables are its own function and, for a handler, its accepts=
    # predicate (ADR 0084): a predicate runs on EVERY message, so a table read only there is
    # load-bearing, and it is attributed to the HANDLER it gates (deleting it would dead-letter every
    # message at routing time). Each callable brings the config-authored helpers it reaches and the
    # CodeSets captured in the globals it reads (BACKLOG #5621). A predicate does not Send, so it
    # contributes table edges only.
    roots: list[tuple[str, str, object]] = [
        *(("router", n, fn) for n, fn in registry.routers.items()),
        *(("handler", n, fn) for n, fn in registry.handlers.items()),
        *(("handler", n, pred) for n, pred in registry.handler_accepts.items()),
    ]
    sources = SourceCache()
    # Helpers shared by many referrers are read once: targets are cached per reached object.
    targets_of: dict[int, list[tuple[str, str]]] = {}
    seen: set[Reference] = set(edges)
    for kind, name, fn in roots:
        for reached in _reached(fn):
            if id(reached) not in targets_of:
                targets_of[id(reached)] = _table_targets(reached, kinds_by_name, sources)
            for target_kind, target in targets_of[id(reached)]:
                edge = Reference(kind, name, target_kind, target)
                if edge not in seen:
                    seen.add(edge)
                    edges.append(edge)
    return ReferenceIndex(edges=tuple(edges))


def _table_targets(
    reached: FunctionType | CodeSet,
    kinds_by_name: dict[str, list[str]],
    sources: SourceCache,
) -> list[tuple[str, str]]:
    """The ``(kind, name)`` tables one reached function names as literals, or the code set a captured
    ``CodeSet`` global is. A literal several kinds share is narrowed by the accessor it is passed to;
    when that cannot be read, every kind holding the name counts, so a live table is never reported
    dead (a safe over-report)."""
    if isinstance(reached, CodeSet):
        return (
            [("code_set", reached.name)]
            if "code_set" in kinds_by_name.get(reached.name, ())
            else []
        )
    out: list[tuple[str, str]] = []
    for t in sorted(_string_consts(reached.__code__) & kinds_by_name.keys()):
        kinds = kinds_by_name[t]
        if len(kinds) > 1:
            narrowed = _source_kinds(reached, t, sources)
            if narrowed is not None:
                kinds = [k for k in kinds if k in narrowed] or kinds
        out.extend((k, t) for k in kinds)
    return out
