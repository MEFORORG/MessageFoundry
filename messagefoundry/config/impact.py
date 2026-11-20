# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rename / delete PRE-FLIGHT over a loaded :class:`Registry` (#152 impact analysis, CLI surface).

:mod:`messagefoundry.config.reachability` computes the reverse-reference index (from ``co_consts``, with
source reads only to tell same-named tables apart) and writes nothing; this module is its I/O twin — it turns that index into the concrete source
edits needed to rename a registered object and rewrite every referent, and applies them to disk.

Two authoring surfaces are covered:

* config-dir ``*.py`` modules — a Router/Handler names its handlers / ``Send()`` outbounds /
  ``code_set()`` (etc.) tables as **string literals**, and an ``inbound(..., router="r")`` names its
  router. These are rewritten with :mod:`tokenize`, so a match is a *plain* ``str`` literal whose
  decoded value is exactly the old name — never a substring, an identifier, a comment, an f-string, a
  bytes literal, or a fragment of an implicit adjacent-string concatenation.
* ``connections.toml`` — a data-authored inbound's ``router = "r"`` binding (and a connection's own
  ``name`` definition) is edited as **text** (no TOML round-trip, so hand-authored formatting/comments
  survive byte-for-byte outside the one edited value).

The rewrite is **site-scoped**: only literals at a referrer's sites (its own body, a handler's ``accepts=``
predicate, a module-level statement binding a name it reads, and, for a table rename, the accessor call
in a config helper it reaches) or in the object's own definition statement are touched, so an unrelated
data literal that merely happens to equal the old name — living in a different function — is left alone
(BACKLOG #5620).

``plan_rename`` is a pure computation (it reads files but writes nothing); ``apply_rename`` performs the
writes, preserving each file's exact bytes outside the replaced spans (newline style and the original
quote delimiter of every literal are kept). A dry-run followed by ``--apply`` on an unchanged tree
produces identical edits, and re-applying a plan is idempotent (a span already carrying the new literal
is skipped)."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import FunctionType

from messagefoundry.config.code_sets import CodeSet
from messagefoundry.config.connections_file import CONNECTIONS_FILE_NAME
from messagefoundry.config.reachability import (
    Reference,
    ReferenceIndex,
    SourceCache,
    build_reference_index,
    captured_values,
    reached_functions,
    source_lines,
    table_kinds,
)
from messagefoundry.config.wiring import (
    CASE_TWIN_TABLES,
    Registry,
    WiringError,
    case_twins,
    config_py_files,
)
from messagefoundry.connection_names import CONNECTION_NAME_PATTERN, is_connection_name
from messagefoundry.controlchars import has_control_char
from messagefoundry.redaction import safe_exc

__all__ = [
    "LiteralEdit",
    "RenamePlan",
    "apply_rename",
    "delete_impact",
    "plan_rename",
]

#: The object kinds a rename/delete can target (the registry tables reachability indexes).
RENAMEABLE_KINDS = frozenset(
    {"inbound", "router", "handler", "outbound", "code_set", "reference", "lookup", "fhir_lookup"}
)

#: The rename kinds whose table refuses case twins at load (BACKLOG #5392).
_CASE_TWIN_KINDS = frozenset(kind for kind, _attribute, _label in CASE_TWIN_TABLES)

#: Kinds whose rename implies renaming a file on disk (a ``codesets/<name>.csv`` table), so ``new`` gets
#: the stricter file-stem name-safety codeset_edit enforces. Only ``code_set`` is file-backed: a
#: ``reference`` is declared code-first (``Reference("name", …)`` in a ``.py`` module) — no file moves for
#: it, and its definition literal is rewritten like any other code-first declaration (see
#: :data:`_DECLARATION_FACTORIES`).
_FILE_BACKED_KINDS = frozenset({"code_set"})

#: The registry table kinds, which may share a name with one another (a code set and a reference).
_TABLE_KINDS = frozenset({"code_set", "reference", "lookup", "fhir_lookup"})

#: Code-first declaration factories whose first positional arg is the object's name literal. These specs
#: carry no ``source_file``/``source_line`` (unlike inbound/outbound), so their definition statement is
#: located by parsing config-dir ``.py`` modules (:func:`_scan_declaration_span`). ``code_set`` is absent
#: (file-backed, no ``.py`` definition); inbound/outbound carry their own source line.
_DECLARATION_FACTORIES: dict[str, frozenset[str]] = {
    "reference": frozenset({"Reference"}),
    "lookup": frozenset({"DatabaseLookup"}),
    "fhir_lookup": frozenset({"FhirLookup"}),
}

#: tokenize types that carry no lexical value for adjacent-string-concat detection.
_TRIVIA = frozenset(
    {
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.COMMENT,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENCODING,
        tokenize.ENDMARKER,
    }
)

#: Token types that begin/end a *string-like* literal for adjacent-concat detection. A plain ``str``
#: (``STRING``) implicitly concatenates with an f-string too — on 3.12+ an f-string is not a ``STRING``
#: token but an ``FSTRING_START``…``FSTRING_END`` run, so a ``STRING`` fragment sitting next to one must
#: still be recognized as a concat (``"a" f"{x}"``) and left un-rewritten, or its runtime value corrupts.
_STRING_LIKE = frozenset({tokenize.STRING, tokenize.FSTRING_START, tokenize.FSTRING_END})

# Prefix + opening delimiter of a string literal (e.g. ``r"``, ``'''``). A bytes/f prefix is rejected
# before this ever runs; the group split lets us preserve an r/u prefix and the exact quote style.
_STRING_OPEN = re.compile(r"^(?P<prefix>[A-Za-z]*)(?P<quote>'''|\"\"\"|'|\")")


@dataclass(frozen=True)
class LiteralEdit:
    """One concrete source edit: replace the literal spanning ``[start, end)`` with ``new_literal``.

    Positions are ``tokenize``/text coordinates — ``start_line``/``end_line`` are 1-based, the columns
    0-based, ``end_col`` exclusive. ``old_literal`` is the exact source text being replaced (including
    its quotes), so :func:`apply_rename` can assert the span before writing and no-op if it already
    carries ``new_literal`` (idempotency)."""

    file: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    old_literal: str
    new_literal: str

    @property
    def line(self) -> int:
        """The 1-based line the edit anchors to (its start)."""
        return self.start_line

    def as_dict(self) -> dict[str, object]:
        """JSON-friendly view for the CLI (``messagefoundry-toolkit impact --rename-to``)."""
        return {
            "file": self.file,
            "line": self.start_line,
            "col": self.start_col,
            "end_line": self.end_line,
            "end_col": self.end_col,
            "old": self.old_literal,
            "new": self.new_literal,
        }


@dataclass(frozen=True)
class RenamePlan:
    """The edits needed to rename ``(target_kind, old)`` to ``new`` and rewrite its referents.

    ``edits`` are the concrete literal rewrites (the definition + every referent that could be safely
    rewritten). ``unresolved`` names any *real* referrer the reverse index found that carries no covering
    edit — a referent expressed as a form the tokenizer refuses to split (an implicit adjacent-string
    concat like ``Send("OB_" "OLD")`` that folds to the name, a no-interpolation f-string, or a
    dynamically-built name). The definition still renames, so these referents would dangle; surfacing them
    keeps the pre-flight honest instead of silently under-reporting."""

    target_kind: str
    old: str
    new: str
    edits: tuple[LiteralEdit, ...] = ()
    unresolved: tuple[Reference, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "op": "rename",
            "kind": self.target_kind,
            "name": self.old,
            "to": self.new,
            "edits": [e.as_dict() for e in self.edits],
            "unresolved": [
                {"referrer_kind": r.referrer_kind, "referrer": r.referrer} for r in self.unresolved
            ],
        }


@dataclass
class _Span:
    """A closed 1-based line range in one file to search for literals (a referrer or a definition)."""

    start: int
    end: int


# --- public API --------------------------------------------------------------


def plan_rename(
    registry: Registry, config_dir: str | Path, target_kind: str, old: str, new: str
) -> RenamePlan:
    """Compute the edits to rename ``(target_kind, old)`` to ``new`` and rewrite every referent.

    Reads source files but writes nothing (the dry-run). Raises :class:`WiringError` on an unknown
    kind, an unsafe ``new`` name, or an ``old`` the registry doesn't hold."""
    if target_kind not in RENAMEABLE_KINDS:
        raise WiringError(
            f"cannot rename kind {target_kind!r}; expected one of {', '.join(sorted(RENAMEABLE_KINDS))}"
        )
    config_dir = Path(config_dir)
    _validate_new_name(config_dir, target_kind, new)
    if not _is_registered(registry, target_kind, old):
        raise WiringError(f"no such {target_kind} {old!r} in the loaded config")
    # Reject a rename onto a name that already denotes a DIFFERENT registered object of the same kind:
    # applying it would write a second definition and load_config would fail loud (e.g. "duplicate
    # outbound connection name"). The file-backed code_set path guards this via a file-existence check in
    # codeset_edit, but the direct CLI rename (and every non-file-backed kind) has no other guard.
    if new != old and _is_registered(registry, target_kind, new):
        raise WiringError(
            f"cannot rename {target_kind} {old!r} to {new!r}: {new!r} already names a "
            f"registered {target_kind}"
        )
    # And onto a case twin of another name in a table graph_problems refuses case twins in
    # (BACKLOG #5392).
    # The same fold, through case_twins: `new` goes last, so a pair naming it is (twin, new).
    if target_kind in _CASE_TWIN_KINDS:
        others = [name for name in _table(registry, target_kind) if name != old]
        twin = next((first for first, second in case_twins([*others, new]) if second == new), None)
        if twin is not None:
            raise WiringError(
                f"cannot rename {target_kind} {old!r} to {new!r}: it differs only in case, width "
                f"or trailing spaces from the registered {target_kind} {twin!r}"
            )

    sources = SourceCache()
    index = build_reference_index(registry, sources)
    # file -> the line spans of the object's own definition, every literal in which is rewritten.
    def_spans: dict[str, list[_Span]] = {}
    # (toml-path, key) pairs whose value == old must be rewritten (router binding / name definition).
    toml_targets: set[tuple[str, str]] = set()

    def add_def_span(file: str | None, span: _Span | None) -> None:
        if file is None or span is None:
            return
        resolved = _under_config_dir(config_dir, file)
        if resolved is not None:
            def_spans.setdefault(resolved, []).append(span)

    # The object's own definition (so the name is actually changed, not only its referents).
    _add_definition_span(registry, config_dir, target_kind, old, add_def_span, toml_targets)

    # Every referent edge: rewrite the literal at each site the referrer reads it from (or its toml
    # binding). Keep each py referrer's sites, so a referrer we could not rewrite is surfaced, not
    # dropped -- including one whose source, or one of whose captured values, could not be located.
    referrers: list[tuple[Reference, list[_Site], bool]] = []
    for ref in index.referrers(target_kind, old):
        found = _referrer_sites(registry, ref, old, target_kind, sources, toml_targets)
        if found is None:
            continue
        sites, complete = found
        in_dir = [
            _Site(resolved, site.span, site.allowed)
            for site in sites
            if (resolved := _under_config_dir(config_dir, site.file)) is not None
        ]
        referrers.append((ref, in_dir, complete and len(in_dir) == len(sites)))

    # A table name another table kind also holds (a code set and a reference both called "x"): a
    # referrer's own body may read either, so only a literal passed to this kind's accessor is ours.
    shared_kind = (
        target_kind
        if target_kind in _TABLE_KINDS and len(table_kinds(registry).get(old, [])) > 1
        else None
    )
    ref_sites = [site for _ref, sites, _complete in referrers for site in sites]
    edits: list[LiteralEdit] = []
    files = set(def_spans) | {site.file for site in ref_sites}
    for file in sorted(files):
        file_def = def_spans.get(file, [])
        file_sites = [site for site in ref_sites if site.file == file]
        spans = file_def + [site.span for site in file_sites]
        kinds = sources.occurrences(file, old)
        for edit in _py_literal_edits(file, old, new, spans):
            pos = (edit.start_line, edit.start_col)
            if _in_any_span(edit.start_line, file_def) or any(
                site.rewrites(pos, kinds, shared_kind) for site in file_sites
            ):
                edits.append(edit)
    for toml_path, key in toml_targets:
        edits.extend(_toml_value_edits(toml_path, key, old, new))

    # Deterministic, de-duplicated (a literal reachable from two overlapping spans appears once).
    unique = {(e.file, e.start_line, e.start_col): e for e in edits}
    ordered = sorted(unique.values(), key=lambda e: (e.file, e.start_line, e.start_col))
    unresolved = _unresolved_referrers(referrers, ordered, old, sources, shared_kind)
    return RenamePlan(
        target_kind=target_kind, old=old, new=new, edits=tuple(ordered), unresolved=unresolved
    )


def apply_rename(plan: RenamePlan) -> list[LiteralEdit]:
    """Write ``plan``'s edits to disk and return the edits actually applied.

    Each file is rewritten byte-for-byte outside the replaced spans (newline style preserved). Edits
    are applied bottom-to-top / right-to-left so earlier offsets stay valid, and a span that no longer
    carries ``old_literal`` (already renamed) is skipped, so re-applying a plan is a safe no-op."""
    applied: list[LiteralEdit] = []
    by_file: dict[str, list[LiteralEdit]] = {}
    for edit in plan.edits:
        by_file.setdefault(edit.file, []).append(edit)

    for file, file_edits in by_file.items():
        raw = Path(file).read_bytes()
        text = raw.decode("utf-8")
        # Split on \n, \r\n and \r only: the plan numbered lines by tokenizing a universal-newline read,
        # which breaks on exactly those, so an edit's line is the line it names here too.
        lines = source_lines(text)
        # Bottom-to-top, right-to-left: a multi-line edit changes the line count below it, so applying
        # in descending (start_line, start_col) keeps every not-yet-applied edit's indices valid.
        for edit in sorted(file_edits, key=lambda e: (e.start_line, e.start_col), reverse=True):
            if _apply_one(lines, edit):
                applied.append(edit)
        Path(file).write_bytes("".join(lines).encode("utf-8"))
    return applied


def delete_impact(index: ReferenceIndex, target_kind: str, name: str) -> list[Reference]:
    """The live referrers that would dangle if ``(target_kind, name)`` were deleted — the delete
    pre-flight warning. A thin, honest reuse of :meth:`ReferenceIndex.referrers`."""
    return index.referrers(target_kind, name)


# --- span collection ---------------------------------------------------------


def _add_definition_span(
    registry: Registry,
    config_dir: Path,
    target_kind: str,
    old: str,
    add_py_span: object,
    toml_targets: set[tuple[str, str]],
) -> None:
    """Scope the object's own definition (``@router("old")`` / ``outbound("old", …)`` /
    ``DatabaseLookup("old", …)`` / a TOML ``name = "old"``). The file-backed ``code_set`` kind has no
    ``.py`` definition — its file move is the caller's job — so nothing is added for it here."""
    assert callable(add_py_span)
    if target_kind in ("router", "handler"):
        table = registry.routers if target_kind == "router" else registry.handlers
        fn = table.get(old)
        if fn is not None:
            file, span = _fn_span(fn)
            add_py_span(file, span)
        return
    if target_kind in ("inbound", "outbound"):
        conn = (registry.inbound if target_kind == "inbound" else registry.outbound).get(old)
        if conn is None:
            return
        if conn.source_line is not None and conn.source_file:
            add_py_span(conn.source_file, _statement_span(conn.source_file, conn.source_line))
        elif conn.source_file and _is_connections_toml(conn.source_file):
            toml_targets.add((conn.source_file, "name"))
        return
    if target_kind in _DECLARATION_FACTORIES:
        # lookup/fhir_lookup/reference are code-first declarations (``DatabaseLookup("old", …)`` etc.)
        # whose spec records no source line — locate the declaring statement by parsing the modules.
        file, span = _scan_declaration_span(config_dir, _DECLARATION_FACTORIES[target_kind], old)
        add_py_span(file, span)


@dataclass(frozen=True)
class _Site:
    """One place a referrer reads the old name from: a line span in one file.

    ``allowed`` is ``None`` for a site whose every literal equal to the old name is a referent (the
    referrer's own body, an inbound's statement, a non-table binding such as ``TARGET = "OB_X"``). A
    site the referrer only reaches (a helper, a module-level binding) for a table rename names its
    referent positions instead: the literals passed to that table kind's accessor, or a bare
    ``NAME = "old"`` value, so an unrelated equal literal there (a dict key, a label) is left alone."""

    file: str
    span: _Span
    allowed: frozenset[tuple[int, int]] | None

    def rewrites(
        self,
        pos: tuple[int, int],
        kinds: Mapping[tuple[int, int], str | None],
        shared_kind: str | None,
    ) -> bool:
        """Whether the literal at ``pos`` is one of this site's referents."""
        if self.allowed is not None:
            return pos in self.allowed
        if not self.span.start <= pos[0] <= self.span.end:
            return False
        return shared_kind is None or kinds.get(pos) == shared_kind

    def occurrences(
        self, kinds: Mapping[tuple[int, int], str | None], shared_kind: str | None
    ) -> set[tuple[str, int, int]]:
        """Every referent position at this site that a complete rename must edit. With
        ``shared_kind`` set, a literal passed to another table kind's accessor belongs to that table
        and is not counted; any other literal is, since it may read either."""
        if self.allowed is not None:
            return {(self.file, line, col) for line, col in self.allowed}
        return {
            (self.file, line, col)
            for (line, col), kind in kinds.items()
            if self.span.start <= line <= self.span.end
            and not (shared_kind is not None and kind is not None and kind != shared_kind)
        }


def _referrer_sites(
    registry: Registry,
    ref: Reference,
    old: str,
    target_kind: str,
    sources: SourceCache,
    toml_targets: set[tuple[str, str]],
) -> tuple[list[_Site], bool] | None:
    """The ``.py`` sites one referent edge reads ``old`` from, and whether every value the referrer
    captures holding ``old`` was located; ``None`` for a ``connections.toml`` router binding
    (recorded in ``toml_targets`` instead).

    A router/handler's sites are its own body and, for a handler, its ``accepts=`` predicate's; for a
    table rename, the config-authored helpers either reaches; and each module-level statement that
    binds a global or module attribute one of them reads and holds ``old`` (``TARGET = "OB_X"``,
    ``DIET = code_set("diets")``), in its own module or a config module it reads through (BACKLOG
    #5620). An inbound's site is its definition statement. A referrer with no sites, or one that
    captures ``old`` through a binding no site holds (``from _consts import TARGET``, a closure), is
    reported unresolved by the caller."""
    table_kind = target_kind if target_kind in _TABLE_KINDS else None
    if ref.referrer_kind in ("router", "handler"):
        table = registry.routers if ref.referrer_kind == "router" else registry.handlers
        fn = table.get(ref.referrer)
        if fn is None:
            return [], False
        roots: list[object] = [fn]
        if ref.referrer_kind == "handler" and ref.referrer in registry.handler_accepts:
            roots.append(registry.handler_accepts[ref.referrer])
        sites: list[_Site] = []
        # A referrer whose own function cannot be read is unresolved. A predicate that is not a plain
        # function (a partial, a callable instance) is not: the index cannot read it either, so no
        # edge came from it.
        complete = bool(reached_functions(fn))
        for root in roots:
            for depth, func in enumerate(reached_functions(root)):
                file, span = _fn_span(func)
                if file is None or span is None:
                    complete = complete and depth > 0
                elif depth == 0 or table_kind is None:
                    sites.append(_Site(file, span, None))
                else:
                    allowed = _accessor_positions(sources, file, span, old, table_kind)
                    allowed |= _default_positions(sources, func, file, span, old)
                    sites.append(_Site(file, span, frozenset(allowed)))
                bound_sites, located = _module_binding_sites(func, old, table_kind, sources)
                sites.extend(bound_sites)
                complete = complete and located
        return sites, complete
    if ref.referrer_kind == "inbound":
        conn = registry.inbound.get(ref.referrer)
        if conn is None:
            return [], False
        if conn.source_line is not None and conn.source_file:
            span = _statement_span(conn.source_file, conn.source_line)
            return (
                ([_Site(conn.source_file, span, None)], True) if span is not None else ([], False)
            )
        if conn.source_file and _is_connections_toml(conn.source_file):
            # The referent edge is the router binding; rewrite only the `router = "..."` value.
            toml_targets.add((conn.source_file, "router"))
            return None
        return [], False
    return None


def _accessor_positions(
    sources: SourceCache, file: str, span: _Span, old: str, table_kind: str
) -> set[tuple[int, int]]:
    """The positions in ``span`` where ``old`` is passed to ``table_kind``'s accessor."""
    return {
        pos
        for pos, kind in sources.occurrences(file, old).items()
        if kind == table_kind and span.start <= pos[0] <= span.end
    }


def _default_positions(
    sources: SourceCache, func: FunctionType, file: str, span: _Span, old: str
) -> set[tuple[int, int]]:
    """The positions of ``old`` written as a default argument in ``func``'s own signature
    (``def _lookup(code, table="diets")``), which the function reads as a captured value."""
    parsed = sources.parse(file)
    if parsed is None:
        return set()
    out: set[tuple[int, int]] = set()
    for node in ast.walk(parsed[0]):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if not span.start <= node.lineno <= span.end:
            continue
        if not isinstance(node, ast.Lambda) and node.name != func.__name__:
            continue
        defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]
        out |= {
            sources.position(file, c)
            for d in defaults
            for c in ast.walk(d)
            if isinstance(c, ast.Constant) and c.value == old
        }
    return out


def _module_binding_sites(
    func: FunctionType, old: str, table_kind: str | None, sources: SourceCache
) -> tuple[list[_Site], bool]:
    """The module-level statements that bind a name ``func`` reads and hold ``old`` -- a global in
    ``func``'s own module, or an attribute of a config module it reads (``_consts.TARGET``) in that
    module -- and whether every such captured value whose value is ``old`` (or a code set named
    ``old``) is bound by a statement this plan can rewrite.

    A default argument is written in ``func``'s own signature, so it is located by the function's
    site, never here. A closure's binding lives in an enclosing function, and an imported name's in
    another module, so neither is ever located: such a referrer is unresolved."""
    names_by_file: dict[str, set[str]] = {}
    required: set[tuple[str | None, str]] = set()
    for captured in captured_values(func, func.__module__):
        if captured.source == "default":
            continue
        own_file = func.__code__.co_filename
        file = own_file if captured.source == "global" else captured.module_file
        if file is not None and captured.source != "closure":
            names_by_file.setdefault(file, set()).add(captured.name)
        value = captured.value
        if (isinstance(value, str) and value == old) or (
            isinstance(value, CodeSet) and value.name == old and table_kind == "code_set"
        ):
            required.add((file if captured.source != "closure" else None, captured.name))
    sites: list[_Site] = []
    bound: set[tuple[str | None, str]] = set()
    for file in sorted(names_by_file):
        for stmt, stmt_names in _module_bindings(sources, file, names_by_file[file]):
            span = _Span(stmt.lineno, stmt.end_lineno or stmt.lineno)
            if table_kind is None:
                allowed: set[tuple[int, int]] | None = None
                found = any(span.start <= p[0] <= span.end for p in sources.occurrences(file, old))
            else:
                allowed = _accessor_positions(sources, file, span, old, table_kind)
                value = stmt.value
                if isinstance(value, ast.Constant) and value.value == old:
                    allowed.add(sources.position(file, value))
                found = bool(allowed)
            if not found:
                # A statement holding old only where this plan will not rewrite it does not locate
                # the binding: A, B = "diets", "x" stays a capture of the old name.
                continue
            bound |= {(file, name) for name in stmt_names}
            sites.append(_Site(file, span, frozenset(allowed) if allowed is not None else None))
    return sites, required <= bound


def _module_bindings(
    sources: SourceCache, file: str, names: set[str]
) -> list[tuple[ast.Assign | ast.AnnAssign | ast.AugAssign, set[str]]]:
    """``file``'s module-scope assignments that bind one of ``names``, with the names each binds.
    Module scope includes the bodies of top-level ``if``/``try``/``with``/``for``/``while``
    statements, but never a ``def`` or ``class`` body."""
    parsed = sources.parse(file)
    if parsed is None:
        return []
    out: list[tuple[ast.Assign | ast.AnnAssign | ast.AugAssign, set[str]]] = []
    stack: list[ast.stmt] = list(parsed[0].body)
    while stack:
        stmt = stack.pop()
        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
            stack.extend(stmt.body)
            stack.extend(getattr(stmt, "orelse", []))
            continue
        if isinstance(stmt, (ast.Try, ast.TryStar)):
            stack.extend(stmt.body + stmt.orelse + stmt.finalbody)
            for handler in stmt.handlers:
                stack.extend(handler.body)
            continue
        if isinstance(stmt, ast.Assign):
            targets: list[ast.expr] = list(stmt.targets)
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            targets = [stmt.target]
        else:
            continue
        stmt_names = {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)} & names
        if stmt_names:
            out.append((stmt, stmt_names))
    return out


def _fn_span(fn: object) -> tuple[str | None, _Span | None]:
    """The source file + closed line span of a registered Router/Handler (decorators included), or
    ``(None, None)`` when its source can't be located (a callable with no on-disk source)."""
    import inspect

    if not callable(fn):
        return None, None
    target = inspect.unwrap(fn)
    code = getattr(target, "__code__", None)
    if code is None:
        return None, None
    try:
        fn_lines, start = inspect.getsourcelines(target)
    except (OSError, TypeError, SyntaxError, tokenize.TokenError):
        # A file that changed since it loaded (an editor mid-save) cannot be located either.
        return None, None
    file = str(code.co_filename)
    return file, _Span(start, start + len(fn_lines) - 1)


def _statement_span(file: str, start_line: int) -> _Span | None:
    """The closed line span of the logical statement that begins at ``start_line`` in ``file``.

    A code-first ``inbound(...)`` / ``outbound(...)`` call may wrap across physical lines; ``tokenize``
    marks the logical end with a ``NEWLINE`` (bracketed continuations emit ``NL``), so the span runs to
    the first ``NEWLINE`` at or after ``start_line``. Best-effort: an unreadable/odd file yields the
    single start line."""
    try:
        text = Path(file).read_text(encoding="utf-8")
    except OSError:
        return _Span(start_line, start_line)
    end = start_line
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.NEWLINE and tok.start[0] >= start_line:
                end = tok.start[0]
                break
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return _Span(start_line, start_line)
    return _Span(start_line, max(end, start_line))


def _scan_declaration_span(
    config_dir: Path, factories: frozenset[str], old: str
) -> tuple[str | None, _Span | None]:
    """Locate the code-first declaration of ``old`` (``Reference("old", …)`` / ``DatabaseLookup("old",
    …)`` / ``FhirLookup("old", …)``) and return its ``(source_file, statement span)``.

    lookup/fhir_lookup/reference specs carry no source line (unlike inbound/outbound), so the declaring
    statement is found by parsing each config-dir ``.py`` module and matching a call to one of
    ``factories`` whose first positional arg is the string literal ``old``. Best-effort: an unparseable
    module is skipped; the first match wins (a loaded graph holds the name once). Returns ``(None, None)``
    when nothing matches — the definition simply isn't rewritten, exactly as before this branch existed.
    Raises :class:`WiringError` when ``config_dir`` cannot be listed, which is not "nothing matches"."""
    # The loader's own file rule: a dot-named backup of a module (vault BACKLOG #2781) or a file in a
    # subdirectory is never run, so a declaration in one must not take the definition edit.
    try:
        modules = config_py_files(config_dir)
    except OSError as exc:
        # Read as an empty directory, this left the definition out of the plan unremarked, and an
        # apply renamed only the referents (vault BACKLOG #5117).
        raise WiringError(f"could not list the config dir {config_dir}: {safe_exc(exc)}") from exc
    for path in modules:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError, MemoryError, RecursionError):
            # MemoryError and RecursionError are the parser's width and depth walls, not SyntaxError
            # subclasses (BACKLOG #1858); a module past either is as unparseable as a broken one.
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            if _call_name(node.func) not in factories:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and first.value == old:
                return str(path), _statement_span(str(path), node.lineno)
    return None, None


def _call_name(func: ast.expr) -> str | None:
    """The simple name a call target resolves to — ``Reference`` for both ``Reference(...)`` and
    ``mod.Reference(...)`` — or ``None`` for anything else (a subscription, a lambda, …)."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _unresolved_referrers(
    referrers: list[tuple[Reference, list[_Site], bool]],
    edits: list[LiteralEdit],
    old: str,
    sources: SourceCache,
    shared_kind: str | None,
) -> tuple[Reference, ...]:
    """The referrers that would still read ``old`` after the edits — a real referent the tokenizer
    safely refused to touch (a folded adjacent-string concat / no-interpolation f-string), or a name
    the planner cannot see at any of the referrer's sites (a dynamic name, an imported constant, a
    closure). Reported so a ``--apply`` that renames the definition doesn't silently leave a
    dangling referent.

    Coverage is per occurrence, not per span: every referent position at every site must carry an
    edit (BACKLOG #5620), so one rewritten literal no longer vouches for a second one beside it."""
    edited = {(e.file, e.start_line, e.start_col) for e in edits}
    out: list[Reference] = []
    for ref, sites, complete in referrers:
        occurrences: set[tuple[str, int, int]] = set()
        for site in sites:
            occurrences |= site.occurrences(sources.occurrences(site.file, old), shared_kind)
        if not complete or not occurrences or not occurrences <= edited:
            out.append(ref)
    return tuple(out)


# --- python literal rewriting (tokenize) -------------------------------------


def _py_literal_edits(file: str, old: str, new: str, spans: list[_Span]) -> list[LiteralEdit]:
    """Every plain-``str`` literal whose decoded value == ``old`` inside one of ``spans`` in ``file``.

    tokenize is the authority: an f-string (its own token kinds), a bytes literal, or a fragment of an
    implicit adjacent-string concatenation is never matched — only a lone plain ``str`` whose value is
    exactly ``old``."""
    try:
        text = Path(file).read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []

    edits: list[LiteralEdit] = []
    for i, tok in enumerate(toks):
        if tok.type != tokenize.STRING:
            continue
        if not _in_any_span(tok.start[0], spans):
            continue
        if _is_adjacent_concat(toks, i):
            continue
        parsed = _parse_plain_str(tok.string)
        if parsed is None or parsed != old:
            continue
        prefix, quote = _split_open(tok.string)
        if prefix is None or quote is None:
            continue
        new_literal = f"{prefix}{quote}{new}{quote}"
        edits.append(
            LiteralEdit(
                file=file,
                start_line=tok.start[0],
                start_col=tok.start[1],
                end_line=tok.end[0],
                end_col=tok.end[1],
                old_literal=tok.string,
                new_literal=new_literal,
            )
        )
    return edits


def _parse_plain_str(source: str) -> str | None:
    """Decode a STRING token's source to its ``str`` value, or ``None`` if it is a bytes/f-string (or
    otherwise not a plain ``str``). f-strings don't reach here as a single STRING token on 3.12+, but a
    bytes prefix does — reject it so ``b"old"`` never matches a name."""
    prefix, _quote = _split_open(source)
    if prefix is None:
        return None
    low = prefix.lower()
    if "b" in low or "f" in low:
        return None
    try:
        value = ast.literal_eval(source)
    except (ValueError, SyntaxError):
        return None
    return value if isinstance(value, str) else None


def _split_open(source: str) -> tuple[str | None, str | None]:
    """Split a string-literal token into its ``(prefix, opening-quote)`` (e.g. ``("r", '"')``)."""
    m = _STRING_OPEN.match(source)
    if m is None:
        return None, None
    return m.group("prefix"), m.group("quote")


def _is_adjacent_concat(toks: list[tokenize.TokenInfo], i: int) -> bool:
    """Whether the STRING token at ``i`` is part of an implicit adjacent-string concatenation.

    ``"a" "b"`` tokenizes as two back-to-back STRING tokens (trivia — NL/COMMENT — may sit between when
    the pair is bracketed); ``"a" f"{x}"`` puts an ``FSTRING_START`` next to the STRING. Rewriting one
    fragment would corrupt the combined value, so such a token is never matched even if its own fragment
    happens to equal ``old``."""
    return _neighbor_is_string(toks, i, -1) or _neighbor_is_string(toks, i, +1)


def _neighbor_is_string(toks: list[tokenize.TokenInfo], i: int, step: int) -> bool:
    j = i + step
    while 0 <= j < len(toks):
        if toks[j].type in _TRIVIA:
            j += step
            continue
        # STRING *or* an f-string boundary (FSTRING_START ahead / FSTRING_END behind): an implicit concat
        # with an f-string is just as unsafe to split as a plain string-string concat.
        return toks[j].type in _STRING_LIKE
    return False


def _in_any_span(line: int, spans: list[_Span]) -> bool:
    return any(span.start <= line <= span.end for span in spans)


# --- connections.toml text rewriting -----------------------------------------


def _toml_value_edits(toml_path: str, key: str, old: str, new: str) -> list[LiteralEdit]:
    """Rewrite a ``connections.toml`` ``<key> = "old"`` assignment as text (no TOML round-trip).

    Matches only a line whose value is exactly ``old`` between matching quotes (no escapes), so a
    substring or a differently-keyed value is never touched. The quote style is preserved."""
    try:
        text = Path(toml_path).read_text(encoding="utf-8")
    except OSError:
        return []
    pattern = re.compile(
        r"^(?P<pre>\s*"
        + re.escape(key)
        + r"\s*=\s*)(?P<lit>(?P<q>[\"'])"
        + re.escape(old)
        + r"(?P=q))"
    )
    edits: list[LiteralEdit] = []
    # Number lines exactly as apply_rename splits them: a TOML string may hold U+2028 or U+0085, and a
    # split on those would shift every later edit's line.
    for lineno, line in enumerate(source_lines(text), start=1):
        line = line.rstrip("\r\n")
        m = pattern.match(line)
        if m is None:
            continue
        # Guard against a trailing non-comment token that would make this not a bare scalar assignment.
        rest = line[m.end("lit") :].lstrip()
        if rest and not rest.startswith("#"):
            continue
        lit = m.group("lit")
        quote = m.group("q")
        col = len(m.group("pre"))
        edits.append(
            LiteralEdit(
                file=toml_path,
                start_line=lineno,
                start_col=col,
                end_line=lineno,
                end_col=col + len(lit),
                old_literal=lit,
                new_literal=f"{quote}{new}{quote}",
            )
        )
    return edits


# --- apply -------------------------------------------------------------------


def _apply_one(lines: list[str], edit: LiteralEdit) -> bool:
    """Apply one edit in place, returning whether it was applied (``False`` = span already renamed)."""
    if edit.start_line == edit.end_line:
        idx = edit.start_line - 1
        if idx >= len(lines):
            return False
        line = lines[idx]
        current = line[edit.start_col : edit.end_col]
        if current == edit.old_literal:
            lines[idx] = line[: edit.start_col] + edit.new_literal + line[edit.end_col :]
            return True
        # Idempotent no-op: the span already carries the new literal (a re-applied plan).
        if line[edit.start_col : edit.start_col + len(edit.new_literal)] == edit.new_literal:
            return False
        return False
    # Multi-line (triple-quoted) literal: reconstruct the region across the affected lines.
    lo, hi = edit.start_line - 1, edit.end_line - 1
    if hi >= len(lines):
        return False
    region_lines = lines[lo : hi + 1]
    region = "".join(region_lines)
    inner_start = edit.start_col
    inner_end = len(region) - (len(region_lines[-1]) - edit.end_col)
    if region[inner_start:inner_end] != edit.old_literal:
        return False
    new_region = region[:inner_start] + edit.new_literal + region[inner_end:]
    # Re-split as apply_rename split the file, so an earlier edit on line ``lo`` still indexes its line.
    lines[lo : hi + 1] = source_lines(new_region)
    return True


# --- name safety + registry helpers ------------------------------------------


def _validate_new_name(config_dir: Path, target_kind: str, new: str) -> None:
    """Reject a ``new`` name that is unsafe to embed in a source literal, and — for a file-backed kind —
    that would escape the ``codesets/`` directory (reusing codeset_edit's traversal/drive checks)."""
    if not isinstance(new, str) or not new:
        raise WiringError("the new name must be a non-empty string")
    # A name is embedded verbatim into a Python/TOML string literal; a quote, backslash, or control
    # char would break out of the literal (or the value). Names are simple identifiers-in-practice —
    # refuse anything that could corrupt the rewrite.
    if has_control_char(new):
        raise WiringError(f"the new name {new!r} must not contain control characters")
    if any(ch in new for ch in ("'", '"', "\\")):
        raise WiringError(f"the new name {new!r} must not contain a quote or backslash")
    # A renamed connection must still load (BACKLOG #1107): refuse here, before any file is rewritten.
    # A FhirLookup name passes the same rule at registration (Registry.add_fhir_lookup).
    if target_kind in ("inbound", "outbound", "fhir_lookup") and not is_connection_name(new):
        raise WiringError(
            f"the new name {new!r} is not a valid connection name: it must match "
            f"{CONNECTION_NAME_PATTERN}"
        )
    if target_kind in _FILE_BACKED_KINDS:
        # Reuse the exact traversal/drive/containment rules the codeset writer enforces on a file stem.
        from messagefoundry.config.code_sets import CODESETS_DIR_NAME
        from messagefoundry.config.codeset_edit import _validate_name

        _validate_name(config_dir / CODESETS_DIR_NAME, new)


def _is_registered(registry: Registry, target_kind: str, name: str) -> bool:
    return name in _table(registry, target_kind)


def _table(registry: Registry, target_kind: str) -> Mapping[str, object]:
    tables: dict[str, Mapping[str, object]] = {
        "inbound": registry.inbound,
        "outbound": registry.outbound,
        "router": registry.routers,
        "handler": registry.handlers,
        "code_set": registry.code_sets,
        "reference": registry.references,
        "lookup": registry.lookups,
        "fhir_lookup": registry.fhir_lookups,
    }
    return tables[target_kind]


def _is_connections_toml(source_file: str) -> bool:
    return Path(source_file).name == CONNECTIONS_FILE_NAME


def _under_config_dir(config_dir: Path, file: str) -> str | None:
    """Return ``file`` if it resolves at or under ``config_dir`` (so we never rewrite a module imported
    from site-packages), else ``None``. Best-effort; an unresolvable path is dropped."""
    try:
        resolved = Path(file).resolve()
        if resolved.is_relative_to(config_dir.resolve()):
            return str(resolved)
    except (OSError, ValueError):
        return None
    return None
