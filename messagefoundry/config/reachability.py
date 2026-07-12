# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Reverse-reachability / reference index over a loaded :class:`Registry` (#176 dead-config
detection, #152 reverse-dependency / impact analysis).

``validate`` resolves the FORWARD ``inbound -> router`` edge; this module resolves the REVERSE: which
registered objects reference a given one (:meth:`ReferenceIndex.referrers`, #152), and which are
unreachable from the inbound roots (:meth:`ReferenceIndex.unreferenced`, #176 — dead config an author
can delete). Edges come from two sources:

* the **structured** ``inbound -> router`` binding carried on the :class:`Registry`; and
* the **string literals** a Router/Handler function names in its code — a router names its handlers,
  a handler names its ``Send()`` outbounds and its ``code_set()`` / ``reference()`` / ``db_lookup()``
  / ``fhir_lookup()`` tables. Those are read from the function's compiled ``co_consts`` (recursing
  into nested comprehensions/closures), so no source re-parse is needed.

The literal signal is a **heuristic**: a name mentioned only in a docstring counts as a reference (so
a genuinely-dead object can be missed — a safe false negative), and a dynamically-computed name is
invisible. Both callers are therefore **advisory** and never fail a build. Pure + stdlib-only,
engine-side (no I/O, no engine state)."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from types import CodeType

from messagefoundry.config.wiring import Registry

__all__ = ["Reference", "ReferenceIndex", "build_reference_index"]


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


def _code_of(fn: object) -> CodeType | None:
    """The ``__code__`` of a registered Router/Handler (unwrapping decorators), or ``None`` for a
    callable with no analyzable code object (e.g. a callable instance) — which is then skipped."""
    target = inspect.unwrap(fn) if callable(fn) else fn
    return getattr(target, "__code__", None)


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
    fallback tier) plus the string-literal ``code_set()``/``reference()``/lookup-table edges this
    module still reads from each function's compiled ``co_consts``."""
    from messagefoundry.config.graph import build_wiring_graph

    table_kind: dict[str, str] = {}
    for name in registry.code_sets:
        table_kind[name] = "code_set"
    for name in registry.references:
        table_kind[name] = "reference"
    for name in registry.lookups:
        table_kind[name] = "lookup"
    for name in registry.fhir_lookups:
        table_kind[name] = "fhir_lookup"
    table_names = set(table_kind)

    # Wiring edges (inbound -> router -> handler -> outbound/PT): the shared extractor. Reachability
    # wants MAXIMAL edges (a missed edge = a false "dead" report), so every provenance tier counts.
    edges: list[Reference] = [
        Reference(e.source_kind, e.source, e.target_kind, e.target)
        for e in build_wiring_graph(registry).edges
    ]
    # Literal: router/handler -> code_set/reference/lookup tables (unchanged heuristic).
    for kind, members in (("router", registry.routers), ("handler", registry.handlers)):
        for name, fn in members.items():
            code = _code_of(fn)
            if code is None:
                continue
            for t in sorted(_string_consts(code) & table_names):
                edges.append(Reference(kind, name, table_kind[t], t))
    # Literal: accepts= predicate -> code_set/reference/lookup tables (ADR 0084). A predicate is a THIRD
    # callable (beyond router/handler bodies) that names config tables, and it runs on EVERY message — so a
    # table read only inside a predicate is load-bearing, not dead. Attribute it to the HANDLER the predicate
    # gates (already reachable via the router that selects it), so #176 dead-config + #152 impact analysis do
    # not mis-report a live predicate table as deletable-with-zero-referrers (deleting which would dead-letter
    # every message at routing time). The handler's own outbounds come structurally from build_wiring_graph;
    # a predicate does not Send, so it contributes table edges only.
    for hname, pred in registry.handler_accepts.items():
        code = _code_of(pred)
        if code is None:
            continue
        for t in sorted(_string_consts(code) & table_names):
            edges.append(Reference("handler", hname, table_kind[t], t))
    return ReferenceIndex(edges=tuple(edges))
