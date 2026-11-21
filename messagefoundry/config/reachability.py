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
import dis
import inspect
import io
import logging
import tokenize
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import CellType, CodeType, FunctionType, MethodType, ModuleType
from typing import cast

from messagefoundry.config.code_sets import CodeSet
from messagefoundry.config.graph import DATA_FLOW_RELATIONS
from messagefoundry.config.wiring import _CONFIG_MODULE_PREFIX, EnvRef, Registry

__all__ = [
    "SETTING_REFERENCES",
    "Reference",
    "ReferenceIndex",
    "SourceCache",
    "build_reference_index",
    "Captured",
    "captured_values",
    "code_names",
    "reached_functions",
    "source_lines",
    "table_kinds",
]

_log = logging.getLogger(__name__)

#: The connection settings that name another connection: (referrer kind, setting, target kind).
#: Each referrer's edge carries the setting as its relation.
SETTING_REFERENCES: tuple[tuple[str, str, str], ...] = (
    ("outbound", "reingress_to", "inbound"),
    ("inbound", "reply_from", "outbound"),
)

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


def code_names(code: CodeType) -> tuple[set[str], set[tuple[str, str]]]:
    """The global names a code object loads, and the ``(global, attribute)`` pairs it loads as
    ``global.attribute`` (``_consts.TARGET``), recursing into nested code.

    Read from the bytecode rather than ``co_names``, which mixes globals with every attribute name: a
    method call such as ``cs.get(x)`` must not be read as a reference to a module function ``get``."""
    global_names: set[str] = set()
    module_attrs: set[tuple[str, str]] = set()
    previous: dis.Instruction | None = None
    for ins in dis.get_instructions(code):
        if ins.opname in _GLOBAL_LOADS and isinstance(ins.argval, str):
            global_names.add(ins.argval)
        elif (
            ins.opname in _ATTR_LOADS
            and isinstance(ins.argval, str)
            and previous is not None
            and previous.opname in _GLOBAL_LOADS
            and isinstance(previous.argval, str)
        ):
            module_attrs.add((previous.argval, ins.argval))
        previous = ins
    for const in code.co_consts:
        if isinstance(const, CodeType):
            inner_globals, inner_attrs = code_names(const)
            global_names |= inner_globals
            module_attrs |= inner_attrs
    return global_names, module_attrs


_GLOBAL_LOADS = frozenset({"LOAD_GLOBAL", "LOAD_NAME"})
_ATTR_LOADS = frozenset({"LOAD_ATTR", "LOAD_METHOD"})


def _function_of(obj: object) -> FunctionType | None:
    """The plain function behind ``obj``: a bound method's ``__func__``, and any ``__wrapped__`` chain
    (``functools.wraps``, ``update_wrapper`` on a class-based decorator, ``functools.cache``)
    followed to its end, or ``None`` for anything else (a callable instance, a builtin, a
    ``partial``). The chain is read statically, so a captured object's own ``__getattr__`` or
    ``__getattribute__`` never runs."""
    # type() and inspect.getattr_static only: isinstance() falls back to obj.__class__, and getattr()
    # runs the object's own __getattr__ / __getattribute__, either of which is author code.
    seen: set[int] = set()
    while id(obj) not in seen:
        seen.add(id(obj))
        if issubclass(type(obj), MethodType):
            obj = cast("MethodType", obj).__func__
        if issubclass(type(obj), FunctionType):
            func = cast("FunctionType", obj)
            if "__wrapped__" not in func.__dict__:
                return func
            obj = func.__dict__["__wrapped__"]
            continue
        # A wrapper that is not a function (a class-based decorator using functools.update_wrapper,
        # a functools.cache wrapper): follow its __wrapped__, as inspect.unwrap did before.
        try:
            obj = inspect.getattr_static(obj, "__wrapped__")
        except AttributeError:
            return None
    return None


def _is_config_module(name: object, root_module: str) -> bool:
    """Whether ``name`` is a config-authored module: one the loader ran (its mangled prefix), or the
    module the root callable itself was defined in (a registry built in-process)."""
    return isinstance(name, str) and (name.startswith(_CONFIG_MODULE_PREFIX) or name == root_module)


def _cell_value(cell: CellType) -> object:
    try:
        return cell.cell_contents
    except ValueError:  # an empty cell: a free variable not bound yet
        return None


@dataclass(frozen=True)
class Captured:
    """One value a function reads without computing it, and where it reads it from.

    ``source`` is ``"global"`` (bound in ``func``'s own module), ``"attribute"`` (``module_file``'s
    module-level ``name``), ``"closure"`` (a free variable of an enclosing function) or
    ``"default"`` (a default argument, written in ``func``'s own signature)."""

    source: str
    name: str
    value: object
    module_file: str | None = None


def captured_values(func: FunctionType, root_module: str) -> list[Captured]:
    """What ``func`` can read without computing it: the globals it loads, the attributes it loads
    off a config module, its closure cells and its default arguments.

    A module attribute is read from the module's ``__dict__``, so a module ``__getattr__`` never runs."""
    global_names, module_attrs = code_names(func.__code__)
    out = [Captured("global", n, func.__globals__.get(n)) for n in sorted(global_names)]
    for module_name, attr in sorted(module_attrs):
        module = func.__globals__.get(module_name)
        if not isinstance(module, ModuleType) or not _is_config_module(
            module.__name__, root_module
        ):
            continue
        module_file = module.__dict__.get("__file__")
        if attr in module.__dict__:
            out.append(
                Captured(
                    "attribute",
                    attr,
                    module.__dict__[attr],
                    module_file if isinstance(module_file, str) else None,
                )
            )
    out += [
        Captured("closure", name, _cell_value(cell))
        for name, cell in zip(func.__code__.co_freevars, func.__closure__ or (), strict=False)
    ]
    out += [Captured("default", "", value) for value in func.__defaults__ or ()]
    out += [Captured("default", name, value) for name, value in (func.__kwdefaults__ or {}).items()]
    return out


def _reached(fn: object) -> Iterator[FunctionType | CodeSet | str]:
    """The root function, then every config-authored helper function it reaches through what it can
    read (:func:`captured_values`), transitively, and every ``CodeSet`` or ``str`` those hold.

    Helpers outside config code (the ``messagefoundry`` package, the standard library) are not
    followed: their constants are not the author's table names."""
    root = _function_of(fn)
    if root is None:
        return
    root_module = root.__module__
    seen: set[int] = set()
    seen_values: set[str] = set()
    stack: list[FunctionType] = [root]
    while stack:
        func = stack.pop()
        if id(func) in seen:
            continue
        seen.add(id(func))
        yield func
        for captured in captured_values(func, root_module):
            value = captured.value
            if isinstance(value, CodeSet):
                key = "code_set:" + value.name
                if key not in seen_values:
                    seen_values.add(key)
                    yield value
            elif isinstance(value, str):
                if "str:" + value not in seen_values:
                    seen_values.add("str:" + value)
                    yield value
            else:
                target = _function_of(value)
                if target is not None and _is_config_module(target.__module__, root_module):
                    stack.append(target)


def reached_functions(fn: object) -> list[FunctionType]:
    """``fn`` (unwrapped) and every config-authored helper function it reaches through its globals,
    closure cells, defaults and imported config modules, transitively. A non-function yields ``[]``."""
    return [f for f in _reached(fn) if isinstance(f, FunctionType)]


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


def source_lines(text: str) -> list[str]:
    """``text``'s lines, ends kept, split on \\n, \\r\\n and \\r only, as ``ast`` and a universal-newline
    read count them. ``str.splitlines`` also breaks on a form feed, U+2028, U+0085 and others, so a line
    number taken from it can name a different line than the one an edit or a token means. The
    tokenizer, fed through ``io.StringIO(text).readline``, does not break on a lone \\r, so it agrees
    with this split only on text already read with universal newlines (``Path.read_text``)."""
    return io.StringIO(text, newline="").readlines()


class SourceCache:
    """Parsed config sources by file name, for one index build or rename plan."""

    def __init__(self) -> None:
        self._parsed: dict[str, tuple[ast.Module, list[str]] | None] = {}
        self._occurrences: dict[tuple[str, str], dict[tuple[int, int], str | None]] = {}

    def parse(self, file: str) -> tuple[ast.Module, list[str]] | None:
        """``file``'s module tree and its lines, or ``None`` when unreadable or unparseable."""
        if file not in self._parsed:
            try:
                # utf-8-sig: a BOM-encoded module (common from Windows editors) parses too.
                text = Path(file).read_text(encoding="utf-8-sig")
                lines = source_lines(text)
                self._parsed[file] = (ast.parse(text), lines)
            except (OSError, SyntaxError, ValueError, MemoryError, RecursionError) as exc:
                # MemoryError and RecursionError are the parser's width and depth walls (BACKLOG #1858).
                _log.debug("reference analysis could not parse %s: %s", file, type(exc).__name__)
                self._parsed[file] = None
        return self._parsed[file]

    def position(self, file: str, node: ast.expr) -> tuple[int, int]:
        """``node``'s ``(line, char col)``: ast counts the column in UTF-8 bytes, while tokenize, and
        so every rename edit, counts characters."""
        parsed = self.parse(file)
        lines = parsed[1] if parsed is not None else []
        line_text = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
        prefix = line_text.encode("utf-8")[: node.col_offset]
        return node.lineno, len(prefix.decode("utf-8", errors="replace"))

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
        from messagefoundry.config.graph import _called_name

        tree = parsed[0]
        parents: dict[int, ast.AST] = {}
        out: dict[tuple[int, int], str | None] = {}
        stack: list[ast.AST] = [tree]
        while stack:
            node = stack.pop()
            kind: str | None
            if isinstance(node, ast.JoinedStr):
                parts = node.values
                if all(isinstance(v, ast.Constant) for v in parts):
                    if "".join(str(v.value) for v in parts if isinstance(v, ast.Constant)) == value:
                        out[self.position(file, node)] = None
                    continue
                # A constant piece of an interpolating f-string is not the string's value, but an
                # expression inside a replacement field (f"{code_set('x')}") is ordinary code.
                for part in parts:
                    if isinstance(part, ast.FormattedValue):
                        parents[id(part)] = node
                        stack.append(part)
                continue
            if isinstance(node, ast.TemplateStr):
                # A t-string's value is a Template, never a str, so only its interpolations count.
                for part in node.values:
                    if isinstance(part, ast.Interpolation):
                        parents[id(part)] = node
                        stack.append(part)
                continue
            if isinstance(node, ast.Constant) and node.value == value:
                parent = parents.get(id(node))
                kind = None
                if isinstance(parent, ast.Call) and parent.args and parent.args[0] is node:
                    called = _called_name(parent)
                    kind = _TABLE_ACCESSORS.get(called) if called is not None else None
                out[self.position(file, node)] = kind
                continue
            for child in ast.iter_child_nodes(node):
                parents[id(child)] = node
                stack.append(child)
        return out


def _source_kinds(func: FunctionType, literal: str, sources: SourceCache) -> set[str] | None:
    """The table kinds ``literal`` is read as inside ``func``'s source, by accessor call. ``None`` when
    the source cannot be read, or when any occurrence is not an accessor's first argument (a constant,
    a list, a helper's argument), so the caller falls back to every kind the name could be."""
    try:
        lines, start = inspect.getsourcelines(func)
    except (OSError, TypeError, SyntaxError, tokenize.TokenError) as exc:
        # A helper whose file changed since it loaded: fall back to every kind the name could be.
        _log.debug(
            "reference analysis could not read the source of %s: %s",
            func.__qualname__,
            type(exc).__name__,
        )
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
    """One reverse edge — ``referrer`` (a ``referrer_kind``) names ``target`` (a ``target_kind``).

    ``relation`` is what the naming means: a wiring edge's
    :data:`~messagefoundry.config.graph.EdgeRelation` (``reply_from`` among them, which names an
    outbound but sends it nothing), ``"reads"`` for a table a Router or Handler reads, or ``None``
    when the constructor did not say. It is left out of equality, so a caller can still look an edge
    up by its four names."""

    referrer_kind: str
    referrer: str
    target_kind: str
    target: str
    relation: str | None = field(default=None, compare=False)

    @property
    def carries_data(self) -> bool:
        """Whether the reachability walk follows this edge: a table read, and every wiring relation
        but a name reference such as ``reply_from``. An untagged edge counts, so a missed tag can
        only hide dead config, never report a live object dead."""
        return self.relation in (None, "reads") or self.relation in DATA_FLOW_RELATIONS


@dataclass(frozen=True)
class ReferenceIndex:
    """A reverse-reference index over a :class:`Registry` (its edges, newest-agnostic)."""

    edges: tuple[Reference, ...]

    def referrers(self, target_kind: str, target: str) -> list[Reference]:
        """Every edge whose target is ``(target_kind, target)`` — who references this object (#152)."""
        return [e for e in self.edges if e.target_kind == target_kind and e.target == target]

    def unreferenced(self, registry: Registry) -> list[tuple[str, str]]:
        """Registered objects unreachable from the inbound roots — dead config (#176), as sorted
        ``(kind, name)`` pairs. Inbound connections are the roots and are never reported.

        The walk follows data flow, so a wiring edge no message travels along (an inbound's
        ``reply_from``) is skipped: an outbound only a ``reply_from`` names, that nothing sends to,
        never produces the reply, and is reported (BACKLOG #5966)."""
        flow = [e for e in self.edges if e.carries_data]
        adj: dict[tuple[str, str], set[tuple[str, str]]] = {}
        for e in flow:
            adj.setdefault((e.referrer_kind, e.referrer), set()).add((e.target_kind, e.target))
        reachable: set[tuple[str, str]] = {
            (e.target_kind, e.target) for e in flow if e.referrer_kind == "inbound"
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


def build_reference_index(registry: Registry, sources: SourceCache | None = None) -> ReferenceIndex:
    """Build the reverse-reference index from the authoritative static wiring graph (ADR 0091 D1 —
    the inbound/router/handler/outbound edges, AST-first with the ``co_consts`` heuristic as a
    fallback tier) plus the ``code_set()``/``reference()``/lookup-table edges this module reads from
    each referrer's reached functions (see the module docstring). ``sources`` lets a caller that parses
    the same files afterwards share one parse."""
    from messagefoundry.config.graph import build_wiring_graph

    kinds_by_name = table_kinds(registry)

    # Wiring edges (inbound -> router -> handler -> outbound/PT): the shared extractor. Reachability
    # wants MAXIMAL edges (a missed edge = a false "dead" report), so every provenance tier counts.
    edges: list[Reference] = [
        Reference(e.source_kind, e.source, e.target_kind, e.target, e.relation)
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
    sources = sources if sources is not None else SourceCache()
    # Helpers shared by many referrers are read once: targets are cached per reached object.
    targets_of: dict[int, list[tuple[str, str]]] = {}
    seen: set[Reference] = set(edges)
    # A setting the wiring graph has no edge for still names its target: one written as an env()
    # whose default names it, and a reingress_to naming an inbound that is no Loopback (dangling in
    # the graph). Delete impact and rename must see both (BACKLOG #5966).
    settings_of = {
        "inbound": {n: c.spec.settings for n, c in registry.inbound.items()},
        "outbound": {n: c.spec.settings for n, c in registry.outbound.items()},
    }
    for kind, setting, target_kind in SETTING_REFERENCES:
        for name, settings in sorted(settings_of[kind].items()):
            value = settings.get(setting)
            named = value.default if isinstance(value, EnvRef) else value
            if isinstance(named, str) and named in settings_of[target_kind]:
                edge = Reference(kind, name, target_kind, named, setting)
                if edge not in seen:
                    seen.add(edge)
                    edges.append(edge)
    for kind, name, fn in roots:
        for reached in _reached(fn):
            if id(reached) not in targets_of:
                targets_of[id(reached)] = _table_targets(reached, kinds_by_name, sources)
            for target_kind, target in targets_of[id(reached)]:
                edge = Reference(kind, name, target_kind, target, "reads")
                if edge not in seen:
                    seen.add(edge)
                    edges.append(edge)
    return ReferenceIndex(edges=tuple(edges))


def _table_targets(
    reached: FunctionType | CodeSet | str,
    kinds_by_name: dict[str, list[str]],
    sources: SourceCache,
) -> list[tuple[str, str]]:
    """The ``(kind, name)`` tables one reached function names as literals, the code set a captured
    ``CodeSet`` is, or the tables a captured ``str`` names. A literal several kinds share is narrowed by the accessor it is passed to;
    when that cannot be read, every kind holding the name counts, so a live table is never reported
    dead (a safe over-report)."""
    if isinstance(reached, str):
        # A global the referrer reads that holds a table name (DIET_TABLE = "diets"; code_set(DIET_TABLE)).
        return [(k, reached) for k in kinds_by_name.get(reached, ())]
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
