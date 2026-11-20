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
* ``connections.toml`` — a data-authored inbound's ``router = "r"`` binding, a connection's own
  ``name`` definition, and an outbound's ``reingress_to`` or an inbound's ``reply_from`` naming the
  renamed connection, are edited as **text** (no TOML round-trip, so hand-authored formatting/comments
  survive byte-for-byte outside the one edited value). Only the value at that key path in a
  connection entry is touched, and the edited text must parse to the original with exactly those
  values changed, or the referrer is reported unresolved (BACKLOG #5980).

The rewrite is **site-scoped**: only literals at a referrer's sites (its own body, a handler's ``accepts=``
predicate, a module-level statement binding a name it reads, and, for a table rename, the accessor call
in a config helper it reaches) or in the object's own definition statement are touched, so an unrelated
data literal that merely happens to equal the old name — living in a different function — is left alone
(BACKLOG #5620).

Within a site the rewrite is also **role-scoped** (BACKLOG #5980): a literal is rewritten only where it
is the name-bearing argument of its role — the definition's own name argument, a ``Send()`` target, a
router's returned handler names, an inbound's ``router=`` value, a table accessor's first argument, or a
value any of those reads through a local variable or a module binding. An equal literal anywhere else
at the site (a field comparison, a lookup key, a sibling argument) is left alone, and its referrer is
reported unresolved, since it still reads the old name.

``plan_rename`` is a pure computation (it reads files but writes nothing); ``apply_rename`` performs the
writes, preserving each file's exact bytes outside the replaced spans (newline style and the original
quote delimiter of every literal are kept). A dry-run followed by ``--apply`` on an unchanged tree
produces identical edits, and re-applying a plan is idempotent (a span already carrying the new literal
is skipped)."""

from __future__ import annotations

import ast
import codecs
import copy
import io
import logging
import os
import re
import tokenize
import tomllib
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import FunctionType

from messagefoundry.config.code_sets import CodeSet
from messagefoundry.config.connections_file import CONNECTIONS_FILE_NAME
from messagefoundry.config.reachability import (
    _TABLE_ACCESSORS,
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

_log = logging.getLogger(__name__)

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
    # file -> the line spans of the object's own definition, scanned for literals, and the positions in
    # them of its name argument, the only literals there that are rewritten (BACKLOG #5980).
    def_spans: dict[str, list[_Span]] = {}
    def_positions: dict[str, set[_Pos]] = {}
    # (file, literal position) -> the declaring arguments reading a module constant's literal.
    def_readers: dict[tuple[str, _Pos], frozenset[_Pos]] = {}
    # A definition that exists but that this plan cannot read: outside the config dir, with no
    # source, or not found by the declaration scan. Its name would stay old, so the plan refuses.
    unlocated: list[str] = []
    # connections.toml values equal to old that must be rewritten (the name definition, a router
    # binding, a reingress_to / reply_from setting), each with the referrers it carries.
    toml_targets: dict[_TomlTarget, list[Reference]] = {}

    def add_def_span(
        file: str | None, span: _Span | None, positions: Mapping[_Pos, frozenset[_Pos]]
    ) -> None:
        resolved = _under_config_dir(config_dir, file) if file is not None else None
        if resolved is None or span is None:
            unlocated.append(file or "an unreadable source")
            return
        def_spans.setdefault(resolved, []).append(span)
        def_positions.setdefault(resolved, set()).update(positions)
        for pos, args in positions.items():
            if args:
                def_readers[(resolved, pos)] = def_readers.get((resolved, pos), frozenset()) | args
        # A name given through a module constant sits on that constant's line, outside the span.
        def_spans[resolved].extend(
            _Span(line, line) for line, _col in positions if not span.start <= line <= span.end
        )

    # The object's own definition (so the name is actually changed, not only its referents).
    _add_definition_span(
        registry, config_dir, target_kind, old, sources, add_def_span, toml_targets
    )
    toml_defs = {path for path, _table, keys in toml_targets if keys == ("name",)}

    # Every referent edge: rewrite the literal at each site the referrer reads it from (or its toml
    # binding). Keep each py referrer's sites, so a referrer we could not rewrite is surfaced, not
    # dropped -- including one whose source, or one of whose captured values, could not be located.
    # A connection naming another in its settings (an outbound's reingress_to, an inbound's
    # reply_from) is a referrer too (BACKLOG #5966).
    referrers: list[tuple[Reference, list[_Site], bool]] = []
    for ref, setting in _all_referrers(registry, index, target_kind, old):
        found = (
            _referrer_sites(registry, ref, old, target_kind, sources, toml_targets)
            if setting is None
            else _setting_sites(registry, ref, setting, old, sources, toml_targets)
        )
        if found is None:
            continue
        sites, complete = found
        in_dir = [
            replace(site, file=resolved)
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
    # The config modules, listed once on the first module-binding literal: ``None`` inside it when
    # the listing failed, so no binding literal is rewritten.
    listed: list[tuple[str, ...] | None] = []
    files = set(def_spans) | {site.file for site in ref_sites}
    bom_files = frozenset(file for file in files if _has_bom(file))
    for file in sorted(files):
        file_def = def_spans.get(file, [])
        file_sites = [site for site in ref_sites if site.file == file]
        spans = file_def + [site.span for site in file_sites]
        kinds = sources.occurrences(file, old)
        for edit in _py_literal_edits(file, old, new, spans):
            pos = _source_position(edit, bom_files)
            is_def = pos in def_positions.get(file, ())
            if not is_def and not any(
                site.rewrites(pos, kinds, shared_kind) for site in file_sites
            ):
                continue
            # A literal a module binding holds changes every read of that name, so each read must
            # be one this rename means to change. Two literals no reader sees as a string are
            # exempt: a definition's own name argument, and a table accessor's argument
            # (``DIET = code_set("diets")`` still reads the same, renamed table). A definition's
            # constant is checked against the declaring argument that reads it.
            if (is_def and (file, pos) not in def_readers) or (
                target_kind in _TABLE_KINDS and kinds.get(pos) == target_kind
            ):
                edits.append(edit)
                continue
            covering = [
                site
                for _ref, sites, _complete in referrers
                if any(s.file == file and s.rewrites(pos, kinds, shared_kind) for s in sites)
                for site in sites
            ]
            declaring = def_readers.get((file, pos), frozenset())
            if not listed:
                listed.append(_config_modules(config_dir))
            if _binding_read_only_by_referents(sources, listed[0], file, pos, declaring, covering):
                edits.append(edit)
    # A connections.toml referrer whose value could not be rewritten exactly is unresolved.
    toml_unresolved: list[Reference] = []
    for toml_path, table, keys in sorted(toml_targets):
        toml_refs = toml_targets[(toml_path, table, keys)]
        toml_edits = _toml_edits(toml_path, table, keys, old, new)
        if keys == ("name",) and not toml_edits:
            unlocated.append(toml_path)
        elif toml_edits is None or (toml_refs and not toml_edits):
            toml_unresolved.extend(toml_refs)
        edits.extend(toml_edits or ())

    # Deterministic, de-duplicated (a literal reachable from two overlapping spans appears once).
    unique = {(e.file, e.start_line, e.start_col): e for e in edits}
    ordered = sorted(unique.values(), key=lambda e: (e.file, e.start_line, e.start_col))
    edited = {(e.file, *_source_position(e, bom_files)) for e in ordered}
    # The definition's name literal must be among the edits, or --apply would rename every referent
    # and leave the object under its old name: a name that reaches the call through a loop or a
    # comprehension, say, one the tokenizer refused, a constant other code also reads, or a
    # definition this plan cannot read at all. Refuse rather than plan half a rename. A code set's
    # definition is its file, which `codeset rename` moves.
    wanted = {(file, *pos) for file, positions in def_positions.items() for pos in positions}
    if target_kind != "code_set" and (
        unlocated or (not toml_defs and not wanted) or not wanted <= edited
    ):
        where = ", ".join(sorted(set(def_spans) | set(unlocated))) or "the loaded config"
        raise WiringError(
            f"cannot rename {target_kind} {old!r}: the name literal of its definition in {where} "
            "could not be located, or other code reads it too, so the rename would leave the "
            "definition under its old name or change what that code reads; rename it by hand"
        )
    unresolved = tuple(
        dict.fromkeys(
            (*_unresolved_referrers(referrers, edited, old, sources, shared_kind), *toml_unresolved)
        )
    )
    return RenamePlan(
        target_kind=target_kind, old=old, new=new, edits=tuple(ordered), unresolved=unresolved
    )


def apply_rename(plan: RenamePlan) -> list[LiteralEdit]:
    """Write ``plan``'s edits to disk and return the edits actually applied.

    Each file is rewritten byte-for-byte outside the replaced spans (newline style preserved). Edits
    are applied bottom-to-top / right-to-left so earlier offsets stay valid. A file whose every span
    already carries the new literal (a re-applied plan) is left alone, so re-applying is a no-op.

    Any other state -- a span carrying neither literal, or a file only partly renamed -- means the
    file changed after the plan was made, and writing the rest would leave a half-renamed config
    while reporting success. That raises :class:`WiringError` before any file is written (BACKLOG
    #5980)."""
    by_file: dict[str, list[LiteralEdit]] = {}
    for edit in plan.edits:
        by_file.setdefault(edit.file, []).append(edit)

    rewritten: dict[str, list[str]] = {}
    applied: list[LiteralEdit] = []
    stale: list[LiteralEdit] = []
    for file, file_edits in by_file.items():
        # Split on \n, \r\n and \r only: the plan numbered lines by tokenizing a universal-newline read,
        # which breaks on exactly those, so an edit's line is the line it names here too.
        lines = source_lines(Path(file).read_bytes().decode("utf-8"))
        missing = [e for e in file_edits if _span_text(lines, e) != e.old_literal]
        if not missing:
            # Bottom-to-top, right-to-left: a multi-line edit changes the line count below it, so
            # applying in descending (start_line, start_col) keeps every later edit's indices valid.
            for edit in sorted(file_edits, key=lambda e: (e.start_line, e.start_col), reverse=True):
                _apply_one(lines, edit)
            rewritten[file] = lines
            applied.extend(file_edits)
        elif len(missing) < len(file_edits) or not _already_renamed(lines, file_edits):
            stale.extend(missing)
    if stale:
        where = ", ".join(f"{e.file}:{e.start_line}" for e in stale)
        raise WiringError(
            f"cannot apply the rename of {plan.target_kind} {plan.old!r}: {len(stale)} edit(s) no "
            f"longer match the file, which changed after the plan was made ({where}). Nothing was "
            "written; plan the rename again"
        )
    for file, lines in rewritten.items():
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
    sources: SourceCache,
    add_py_span: Callable[[str | None, _Span | None, Mapping[_Pos, frozenset[_Pos]]], None],
    toml_targets: dict[_TomlTarget, list[Reference]],
) -> None:
    """Scope the object's own definition (``@router("old")`` / ``outbound("old", …)`` /
    ``DatabaseLookup("old", …)`` / a TOML ``name = "old"``), with the position of its name argument,
    the one literal there a rename rewrites: a sibling argument equal to the old name (an inbound's
    ``router=`` naming a router of the same name) is another object's (BACKLOG #5980). The file-backed
    ``code_set`` kind has no ``.py`` definition — its file move is the caller's job — so nothing is
    added for it here."""
    if target_kind in ("router", "handler"):
        table = registry.routers if target_kind == "router" else registry.handlers
        fn = table.get(old)
        if fn is not None:
            file, span = _fn_span(fn)
            positions = (
                _decorator_positions(sources, file, span, fn, old, target_kind)
                if file is not None and span is not None
                else {}
            )
            add_py_span(file, span, positions)
        return
    if target_kind in ("inbound", "outbound"):
        conn = (registry.inbound if target_kind == "inbound" else registry.outbound).get(old)
        if conn is None:
            return
        if conn.source_line is not None and conn.source_file:
            add_py_span(
                conn.source_file,
                _statement_span(conn.source_file, conn.source_line),
                _call_line_positions(sources, conn.source_file, conn.source_line, old, target_kind),
            )
        elif conn.source_file and _is_connections_toml(conn.source_file):
            toml_targets.setdefault((conn.source_file, target_kind, ("name",)), [])
        else:
            # Declared somewhere this plan cannot read, so its name cannot be rewritten.
            add_py_span(None, None, {})
        return
    if target_kind in _DECLARATION_FACTORIES:
        # lookup/fhir_lookup/reference are code-first declarations (``DatabaseLookup("old", …)`` etc.)
        # whose spec records no source line — locate the declaring statement by parsing the modules.
        # The scan found the declaring call itself, so its name argument is taken from it, never
        # re-found by line: a declaration wrapped in another call (with_smart_backend(...)) is
        # still the one renamed.
        add_py_span(
            *_scan_declaration_span(config_dir, _DECLARATION_FACTORIES[target_kind], old, sources)
        )


@dataclass(frozen=True)
class _Site:
    """One place a referrer reads the old name from: a line span in one file.

    ``allowed`` is ``None`` for a site whose every literal equal to the old name is a referent (the
    referrer's own body, an inbound's statement, a non-table binding such as ``TARGET = "OB_X"``). A
    site the referrer only reaches (a helper, a module-level binding) for a table rename names its
    referent positions instead: the literals passed to that table kind's accessor, or a bare
    ``NAME = "old"`` value, so an unrelated equal literal there (a dict key, a label) is left alone.

    ``rewritable``, when set, narrows the rewrite to the literals in a referent role (BACKLOG #5980): a
    site whose every equal literal is counted still rewrites only a ``Send()`` target, a returned
    handler name and the like, so an equal literal in another role is left alone and, being still
    counted, reports its referrer unresolved. ``ignored`` holds the literals at the site that are not
    a referent at all and so are neither rewritten nor counted: the referrer's own registering
    ``@handler("name")`` argument, when the referrer is named like the target."""

    file: str
    span: _Span
    allowed: frozenset[tuple[int, int]] | None
    rewritable: frozenset[tuple[int, int]] | None = None
    ignored: frozenset[tuple[int, int]] = frozenset()

    def rewrites(
        self,
        pos: tuple[int, int],
        kinds: Mapping[tuple[int, int], str | None],
        shared_kind: str | None,
    ) -> bool:
        """Whether the literal at ``pos`` is one of this site's referents."""
        if pos in self.ignored or (self.rewritable is not None and pos not in self.rewritable):
            return False
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
            and (line, col) not in self.ignored
            and not (shared_kind is not None and kind is not None and kind != shared_kind)
        }


def _referrer_sites(
    registry: Registry,
    ref: Reference,
    old: str,
    target_kind: str,
    sources: SourceCache,
    toml_targets: dict[_TomlTarget, list[Reference]],
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
        # The registering decorator's name argument names the referrer, not a referent: counting it
        # would report a handler named like its outbound unresolved, at its own site and at an
        # accepts= lambda's, which spans the same decorator. Its other decorators stay in the
        # site, so an equal literal there is still counted.
        own_file, own_span = _fn_span(fn)
        ignored = (
            frozenset(
                _decorator_positions(
                    sources, own_file, own_span, fn, old, ref.referrer_kind, registering_only=True
                )
            )
            if own_file is not None and own_span is not None
            else frozenset()
        )
        funcs: list[tuple[int, FunctionType, str, _Span]] = []
        reached: list[FunctionType] = []
        for root in roots:
            for depth, func in enumerate(reached_functions(root)):
                reached.append(func)
                file, span = _fn_span(func)
                if file is None or span is None:
                    complete = complete and depth > 0
                else:
                    funcs.append((depth, func, file, span))
        scans = _scan_referrer(sources, funcs, old, ref.referrer_kind, table_kind)
        role_globals = {name for scan in scans for name in scan.globals}
        role_attrs = {name for scan in scans for name in scan.attrs}
        for (depth, func, file, span), scan in zip(funcs, scans, strict=True):
            rewritable = set(scan.positions)
            # A non-table rename rewrites a default only for a parameter that reaches a referent
            # role; a table rename rewrites every default equal to the old name.
            role_params = (
                None if table_kind is not None else {name for _i, name in scan.slots | scan.passes}
            )
            rewritable |= _default_positions(sources, func, file, span, old, role_params)
            if table_kind is None or depth == 0:
                # ``ignored`` holds bare positions in the decorator's own file; a helper elsewhere
                # at the same (line, col) is a referent and must stay counted.
                own = ignored if file == own_file else frozenset()
                sites.append(_Site(file, span, None, frozenset(rewritable), own))
            else:
                allowed = _accessor_positions(sources, file, span, old, table_kind) | rewritable
                sites.append(_Site(file, span, frozenset(allowed)))
        for func in reached:
            bound_sites, located = _module_binding_sites(
                func, old, table_kind, sources, role_globals, role_attrs
            )
            sites.extend(bound_sites)
            complete = complete and located
        return sites, complete
    if ref.referrer_kind == "inbound":
        conn = registry.inbound.get(ref.referrer)
        if conn is None:
            return [], False
        if conn.source_line is not None and conn.source_file:
            span = _statement_span(conn.source_file, conn.source_line)
            if span is None:
                return [], False
            # The statement is a declaration, not logic: only its router= value is the referent, and
            # the inbound's own name or a sibling argument equal to the router's is another value
            # (BACKLOG #5980). A router= the statement does not spell leaves the site empty, which
            # reports the inbound unresolved.
            binding = _keyword_value_positions(sources, conn.source_file, span, old, "router")
            return [_Site(conn.source_file, span, binding)], True
        if conn.source_file and _is_connections_toml(conn.source_file):
            # The referent edge is the router binding; rewrite only the `router = "..."` value.
            toml_targets.setdefault((conn.source_file, "inbound", ("router",)), []).append(ref)
            return None
        return [], False
    return None


def _all_referrers(
    registry: Registry, index: ReferenceIndex, target_kind: str, old: str
) -> list[tuple[Reference, str | None]]:
    """Every referrer of ``(target_kind, old)``, each with the connection setting it names the
    target in, or ``None`` for a referrer read from its code or its router binding.

    The index carries an outbound's ``reingress_to`` as an ``outbound -> inbound`` edge, and has no
    edge for an inbound's ``reply_from`` (an ``Http`` inbound naming the outbound whose reply it
    returns), so that one is read from the registry here (BACKLOG #5966); should the graph gain
    that edge, the registry's reading replaces the index's rather than adding a second."""
    out: dict[Reference, str | None] = {
        ref: "reingress_to" if ref.referrer_kind == "outbound" else None
        for ref in index.referrers(target_kind, old)
    }
    if target_kind == "outbound":
        for name, conn in sorted(registry.inbound.items()):
            if conn.spec.settings.get("reply_from") == old:
                out[Reference("inbound", name, "outbound", old)] = "reply_from"
    return list(out.items())


def _setting_sites(
    registry: Registry,
    ref: Reference,
    setting: str,
    old: str,
    sources: SourceCache,
    toml_targets: dict[_TomlTarget, list[Reference]],
) -> tuple[list[_Site], bool] | None:
    """The site a connection names ``old`` at in its ``setting`` (``reingress_to`` / ``reply_from``):
    the ``setting=`` value in its declaring statement, or ``None`` for a ``connections.toml`` entry,
    recorded in ``toml_targets`` instead. A setting the statement does not spell as a literal leaves
    the site empty, which reports the referrer unresolved (BACKLOG #5966)."""
    table = registry.inbound if ref.referrer_kind == "inbound" else registry.outbound
    conn = table.get(ref.referrer)
    if conn is None:
        return [], False
    if conn.source_line is not None and conn.source_file:
        span = _statement_span(conn.source_file, conn.source_line)
        if span is None:
            return [], False
        binding = _keyword_value_positions(sources, conn.source_file, span, old, setting)
        return [_Site(conn.source_file, span, binding)], True
    if conn.source_file and _is_connections_toml(conn.source_file):
        key = (conn.source_file, ref.referrer_kind, ("settings", setting))
        toml_targets.setdefault(key, []).append(ref)
        return None
    return [], False


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
    sources: SourceCache,
    func: FunctionType,
    file: str,
    span: _Span,
    old: str,
    params: set[str] | None = None,
) -> set[tuple[int, int]]:
    """The positions of ``old`` written as a default argument in ``func``'s own signature
    (``def _lookup(code, table="diets")``), which the function reads as a captured value; with
    ``params``, only the defaults of those parameters."""
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
        if params is not None and isinstance(node, ast.Lambda) != (func.__name__ == "<lambda>"):
            # A lambda nested in the function is not the function: its parameter is another.
            continue
        args = node.args
        positional = [*args.posonlyargs, *args.args]
        # Defaults fill the last positional parameters; kw_defaults pair one-to-one with kwonlyargs.
        pairs = [
            *zip(positional[len(positional) - len(args.defaults) :], args.defaults, strict=True),
            *(
                (a, d)
                for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=True)
                if d is not None
            ),
        ]
        defaults = [d for a, d in pairs if params is None or a.arg in params]
        out |= {
            sources.position(file, c)
            for d in defaults
            for c in ast.walk(d)
            if isinstance(c, ast.Constant) and c.value == old
        }
    return out


# --- referent roles (BACKLOG #5980) -------------------------------------------

#: Calls that hand back their first argument's elements, so a name inside it is still the value.
_COPY_CALLS = frozenset({"list", "tuple", "set", "frozenset", "sorted", "reversed"})

#: The keyword each table accessor takes its table name under (``code_set(name="diets")``).
_ACCESSOR_NAME_PARAMS = {
    "code_set": "name",
    "reference": "name",
    "db_lookup": "connection",
    "fhir_lookup": "connection",
}

#: Methods through which a local list or set collects names (``handlers.append("h")``).
_COLLECTOR_METHODS = frozenset({"append", "extend", "add", "insert"})

_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda

#: A ``(line, char col)`` source position, as :meth:`SourceCache.position` gives it.
_Pos = tuple[int, int]


@dataclass
class _Flow:
    """What one function's role expressions are made of: the string constants they carry, and the
    names they read them through that the function does not bind itself -- its own parameters,
    module globals, module attributes, and the helpers whose return value they take."""

    params: frozenset[str] = frozenset()
    modules: frozenset[str] = frozenset()
    # A pass-through helper's parameters that reach only its return value: a call to it carries
    # those arguments only where the call itself is carried into a role.
    passes: Mapping[str, set[tuple[int, str]]] = field(default_factory=dict)
    consts: list[ast.Constant] = field(default_factory=list)
    unbound: set[str] = field(default_factory=set)
    attrs: set[str] = field(default_factory=set)
    calls: set[str] = field(default_factory=set)


@dataclass
class _Scan:
    """One reached function's referent positions, the module names (bare, and as attributes of a
    module) its roles read, and the parameters (as ``(index, name)``, index -1 for keyword-only)
    whose value reaches a role. ``passes`` are the parameters whose value reaches only this
    function's return value, which an argument fills only where the call is itself in a role."""

    positions: set[tuple[int, int]]
    globals: set[str]
    attrs: set[str]
    calls: set[str]
    slots: set[tuple[int, str]]
    passes: set[tuple[int, str]] = field(default_factory=set)


@dataclass(frozen=True)
class _Names:
    """How one config module spells what the role scan matches by name: ``Send`` and any alias it
    is imported under, the table accessors it imports under an alias (``code_set as cs``, mapped to
    the accessor's own name), and the modules it imports (so ``_shared.label(...)`` is a helper call
    while ``LABELS.get(...)`` is a method)."""

    send: frozenset[str]
    modules: frozenset[str]
    accessors: Mapping[str, str] = field(default_factory=dict)


def _module_names(sources: SourceCache, file: str) -> _Names:
    parsed = sources.parse(file)
    send = {"Send"}
    modules: set[str] = set()
    accessors: dict[str, str] = {}
    for node in ast.walk(parsed[0]) if parsed is not None else ():
        if isinstance(node, ast.ImportFrom):
            send |= {a.asname for a in node.names if a.name == "Send" and a.asname}
            accessors |= {
                a.asname: a.name for a in node.names if a.name in _TABLE_ACCESSORS and a.asname
            }
        elif isinstance(node, ast.Import):
            modules |= {a.asname or a.name.split(".")[0] for a in node.names}
    return _Names(frozenset(send), frozenset(modules), accessors)


def _helper_name(func: ast.expr, modules: frozenset[str]) -> str | None:
    """The config helper a call reaches by name: ``helper(...)`` or ``module.helper(...)`` -- never
    a method on a value, whose name says nothing about which function runs."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.attr if func.value.id in modules else None
    return None


def _scan_referrer(
    sources: SourceCache,
    funcs: list[tuple[int, FunctionType, str, _Span]],
    old: str,
    referrer_kind: str,
    table_kind: str | None,
) -> list[_Scan]:
    """Scan each reached function of one referrer for the literals equal to ``old`` in a referent
    role: a ``Send()`` target for a handler, a returned name for a router, the accessor's first
    argument for a table rename, the return value of a helper whose result one of those reads, and
    an argument passed to a helper parameter that reaches one. Helpers feed each other, so the scan
    runs until neither the helpers read for their return value nor their role parameters grow."""
    prepared = [
        (depth, func, file, span, node, _local_values(node) if node is not None else {}, names)
        for depth, func, file, span in funcs
        for node in (_function_node(sources, file, span, func),)
        for names in (_module_names(sources, file),)
    ]
    send = table_kind is None and referrer_kind == "handler"
    returns: set[str] = set()
    slots: dict[str, set[tuple[int, str]]] = {}
    passes: dict[str, set[tuple[int, str]]] = {}
    while True:
        scans: list[_Scan] = []
        for depth, func, file, span, node, values, names in prepared:
            if depth == 0:
                give_back = referrer_kind == "router" and table_kind is None
            else:
                give_back = func.__name__ in returns
            role = _Role(send, give_back, table_kind, slots, names, passes)
            scans.append(_scan_function(sources, file, span, node, values, old, role))
        new_returns = returns | {name for scan in scans for name in scan.calls}
        new_slots = {name: set(found) for name, found in slots.items()}
        new_passes = {name: set(found) for name, found in passes.items()}
        for (depth, func, *_rest), scan in zip(prepared, scans, strict=True):
            if scan.slots:
                new_slots.setdefault(func.__name__, set()).update(scan.slots)
            # The referrer's own return is no helper's, so it gives no call a pass-through.
            if scan.passes and depth > 0:
                new_passes.setdefault(func.__name__, set()).update(scan.passes)
        # All three only grow and are bounded by the helpers' names and parameters, so this ends.
        if new_returns == returns and new_slots == slots and new_passes == passes:
            return scans
        returns, slots, passes = new_returns, new_slots, new_passes


@dataclass(frozen=True)
class _Role:
    """Which referent roles one function is scanned for (see :func:`_scan_referrer`)."""

    send: bool
    give_back: bool
    accessor: str | None
    slots: Mapping[str, set[tuple[int, str]]]
    names: _Names
    passes: Mapping[str, set[tuple[int, str]]] = field(default_factory=dict)


def _function_node(
    sources: SourceCache, file: str, span: _Span, func: FunctionType
) -> _FunctionNode | None:
    """The ``def`` (or lambda) node for ``func``: a ``def`` of its name inside ``span``, or a lambda
    on the line its code starts on, so a lambda in a decorated function's body is never taken for a
    predicate written in the decorator."""
    parsed = sources.parse(file)
    if parsed is None:
        return None
    if func.__name__ == "<lambda>":
        line = func.__code__.co_firstlineno
        return next(
            (n for n in ast.walk(parsed[0]) if isinstance(n, ast.Lambda) and n.lineno == line),
            None,
        )
    return next(
        (
            n
            for n in ast.walk(parsed[0])
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == func.__name__
            and span.start <= n.lineno <= span.end
        ),
        None,
    )


def _scan_function(
    sources: SourceCache,
    file: str,
    span: _Span,
    node: _FunctionNode | None,
    values: Mapping[str, list[ast.expr]],
    old: str,
    role: _Role,
) -> _Scan:
    """The referent literals in ``node``'s body, per :func:`_scan_referrer`'s roles. A call in a
    nested function or lambda counts (``key=lambda k: code_set("t").get(k)``); a nested function's
    return value does not, since it is not this function's."""
    if node is None:
        return _Scan(set(), set(), set(), set(), set())
    args = node.args
    positional = [a.arg for a in (*args.posonlyargs, *args.args)]
    keyword_only = {a.arg for a in args.kwonlyargs}
    params = frozenset(positional) | keyword_only
    # Two flows: what reaches a role inside this function (``sink``), and what reaches only its
    # return value (``back``). A parameter in ``sink`` makes every call's argument a referent; one
    # only in ``back`` does so only for a call that is itself carried into a role (BACKLOG #5980).
    sink = _Flow(params=params, modules=role.names.modules, passes=role.passes)
    back = _Flow(params=params, modules=role.names.modules, passes=role.passes)
    returned: list[ast.expr] = []
    if role.give_back:
        if isinstance(node, ast.Lambda):
            returned.append(node.body)
        returned.extend(
            child.value
            for child in _own_nodes(node)
            if isinstance(child, (ast.Return, ast.Yield, ast.YieldFrom)) and child.value is not None
        )
    body: list[ast.AST] = [node.body] if isinstance(node, ast.Lambda) else list(node.body)
    for stmt in body:
        for child in ast.walk(stmt):
            if isinstance(child, ast.Call):
                for root in _call_roots(child, role):
                    _carried(root, values, set(), sink)
    for root in returned:
        _carried(root, values, set(), back)
    positions = {
        pos
        for const in (*sink.consts, *back.consts)
        if const.value == old
        and span.start <= (pos := sources.position(file, const))[0] <= span.end
    }

    def slots_of(unbound: set[str]) -> set[tuple[int, str]]:
        found = {(positional.index(p), p) for p in unbound if p in positional}
        return found | {(-1, p) for p in unbound if p in keyword_only}

    own_slots = slots_of(sink.unbound)
    return _Scan(
        positions,
        (sink.unbound | back.unbound) - params,
        sink.attrs | back.attrs,
        sink.calls | back.calls,
        own_slots,
        slots_of(back.unbound) - own_slots,
    )


def _call_roots(call: ast.Call, role: _Role) -> list[ast.expr]:
    """The arguments ``call`` reads as a referent name: a ``Send()`` target, a table accessor's
    first argument, or an argument bound to a helper parameter that reaches a role."""
    out: list[ast.expr] = []
    called = _call_name(call.func)
    if role.send and called in role.names.send:
        target = _first_or_keyword(call, "to")
        if target is not None:
            out.append(target)
    accessor = role.names.accessors.get(called or "", called)
    if (
        role.accessor is not None
        and accessor is not None
        and _TABLE_ACCESSORS.get(accessor) == role.accessor
        and (table := _first_or_keyword(call, _ACCESSOR_NAME_PARAMS[accessor])) is not None
    ):
        out.append(table)
    helper = _helper_name(call.func, role.names.modules)
    out.extend(_slot_arguments(call, role.slots.get(helper or "", ())))
    return out


def _first_or_keyword(call: ast.Call, keyword: str) -> ast.expr | None:
    """``call``'s first positional argument, or its ``keyword=`` value when it has none."""
    if call.args:
        first = call.args[0]
        return None if isinstance(first, ast.Starred) else first
    return next((kw.value for kw in call.keywords if kw.arg == keyword), None)


def _own_nodes(scope: _FunctionNode) -> Iterator[ast.AST]:
    """The nodes a function evaluates itself: a nested function's or class's body is not one, while
    a nested function's decorators and defaults are."""
    stack: list[ast.AST] = [scope.body] if isinstance(scope, ast.Lambda) else list(scope.body)
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, _FUNCTION_NODES):
            if not isinstance(node, ast.Lambda):
                stack.extend(node.decorator_list)
            stack.extend(node.args.defaults)
            stack.extend(d for d in node.args.kw_defaults if d is not None)
        elif not isinstance(node, ast.ClassDef):
            stack.extend(ast.iter_child_nodes(node))


def _local_values(scope: _FunctionNode) -> dict[str, list[ast.expr]]:
    """The values each local name of a function is given: assigned (a tuple target paired with a
    tuple value), extended with a list (``names += ["h"]``), taken in turn from a ``for`` or
    comprehension iterable, or collected through a list or set method. Flow-insensitive: every
    value a name is ever given counts."""
    values: dict[str, list[ast.expr]] = {}
    for node in _own_nodes(scope):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                _bind(target, node.value, values, element=False)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            if node.value is not None:
                _bind(node.target, node.value, values, element=False)
        elif isinstance(node, ast.AugAssign):
            # names += ["h"] extends a list; dest += "x" builds a string, which is not the name.
            if isinstance(node.op, ast.Add) and isinstance(node.value, (ast.List, ast.Tuple)):
                _bind(node.target, node.value, values, element=False)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            _bind(node.target, node.iter, values, element=True)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.attr in _COLLECTOR_METHODS
            and node.args
        ):
            values.setdefault(node.func.value.id, []).append(node.args[-1])
    return values


def _bind(
    target: ast.expr, value: ast.expr, values: dict[str, list[ast.expr]], *, element: bool
) -> None:
    """Record ``value`` (or, with ``element``, each element of it) for the names ``target`` binds.
    A tuple target over a value it cannot pair element by element binds nothing, so a name read
    through it stays unresolved rather than taking a sibling's value."""
    if element and isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        for elt in value.elts:
            _bind(target, elt, values, element=False)
        return
    if isinstance(target, ast.Name):
        values.setdefault(target.id, []).append(value)
        return
    if (
        not element
        and isinstance(target, (ast.Tuple, ast.List))
        and isinstance(value, (ast.Tuple, ast.List))
        and len(target.elts) == len(value.elts)
        and not any(isinstance(e, ast.Starred) for e in (*target.elts, *value.elts))
    ):
        for sub_target, sub_value in zip(target.elts, value.elts, strict=True):
            _bind(sub_target, sub_value, values, element=False)


def _carried(
    expr: ast.expr, values: Mapping[str, list[ast.expr]], seen: set[str], flow: _Flow
) -> None:
    """Add to ``flow`` what ``expr``'s value is made of: a ``str`` constant itself, an element of a
    list, tuple, set or comprehension, a branch of a conditional or a boolean operator, a dict value
    (never its key), a concatenated list, the argument of a copying call, a ``.get()`` default, or a
    value a local name was given. A constant inside a comparison, another call, a string being built
    with ``+`` or an f-string is not carried, since the value there is not the constant."""
    if isinstance(expr, ast.Constant):
        if isinstance(expr.value, str):
            flow.consts.append(expr)
    elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        for elt in expr.elts:
            _carried(elt, values, seen, flow)
    elif isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        _carried(expr.elt, values, seen, flow)
    elif isinstance(expr, (ast.DictComp, ast.Starred)):
        _carried(expr.value, values, seen, flow)
    elif isinstance(expr, ast.IfExp):
        _carried(expr.body, values, seen, flow)
        _carried(expr.orelse, values, seen, flow)
    elif isinstance(expr, (ast.BoolOp, ast.Dict)):
        for value in expr.values:
            _carried(value, values, seen, flow)
    elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        # Only a visible list on one side makes this a list concatenation; otherwise it may be a
        # string being built, whose parts are not the name.
        if any(
            isinstance(op, (ast.List, ast.Tuple, ast.ListComp)) for op in (expr.left, expr.right)
        ):
            _carried(expr.left, values, seen, flow)
            _carried(expr.right, values, seen, flow)
    elif isinstance(expr, ast.Subscript):
        # A value read out of a table carries that table's values.
        _carried(expr.value, values, seen, flow)
    elif isinstance(expr, ast.Call):
        _carried_call(expr, values, seen, flow)
    elif isinstance(expr, ast.Name):
        if expr.id not in values or expr.id in flow.params:
            # A parameter (even one reassigned locally) or a module global; the caller sorts which.
            flow.unbound.add(expr.id)
        if expr.id in values and expr.id not in seen:
            seen.add(expr.id)
            for value in values[expr.id]:
                _carried(value, values, seen, flow)
    elif isinstance(expr, ast.Attribute):
        flow.attrs.add(expr.attr)


def _carried_call(
    call: ast.Call, values: Mapping[str, list[ast.expr]], seen: set[str], flow: _Flow
) -> None:
    """A call's share of :func:`_carried`: a copying call or ``.get()``/``.copy()`` passes its
    container through; any other call's return value is recorded as a helper's to scan."""
    called = _call_name(call.func)
    if called in _COPY_CALLS and isinstance(call.func, ast.Name) and call.args:
        _carried(call.args[0], values, seen, flow)
    elif isinstance(call.func, ast.Attribute) and called in ("get", "copy"):
        _carried(call.func.value, values, seen, flow)
        if called == "get" and len(call.args) > 1:
            _carried(call.args[1], values, seen, flow)
    elif (helper := _helper_name(call.func, flow.modules)) is not None:
        flow.calls.add(helper)
        # This call's value is in a role, so a pass-through helper's argument is too.
        for root in _slot_arguments(call, flow.passes.get(helper, ())):
            _carried(root, values, seen, flow)


def _slot_arguments(call: ast.Call, slots: Iterable[tuple[int, str]]) -> list[ast.expr]:
    """The arguments ``call`` binds to ``slots``, each ``(index, name)``."""
    out: list[ast.expr] = []
    for index, name in slots:
        if 0 <= index < len(call.args) and not isinstance(call.args[index], ast.Starred):
            out.append(call.args[index])
        else:
            out.extend(kw.value for kw in call.keywords if kw.arg == name)
    return out


def _keyword_value_positions(
    sources: SourceCache, file: str, span: _Span, old: str, keyword: str
) -> frozenset[tuple[int, int]]:
    """The ``<keyword>=`` values equal to ``old`` in a connection's declaring statement at ``span``
    (an inbound's ``router=`` or ``reply_from=``, an outbound's ``reingress_to=``)."""
    parsed = sources.parse(file)
    if parsed is None:
        return frozenset()
    flow = _Flow()
    for node in ast.walk(parsed[0]):
        if isinstance(node, ast.Call) and span.start <= node.lineno <= span.end:
            for kw in node.keywords:
                if kw.arg == keyword:
                    _carried(kw.value, {}, set(), flow)
    return frozenset(sources.position(file, c) for c in flow.consts if c.value == old)


def _name_argument_position(
    sources: SourceCache, file: str, call: ast.Call, old: str
) -> tuple[int, int] | None:
    """The position of ``call``'s name argument (its first positional, or ``name=``) when it is the
    literal ``old``."""
    arg = _first_or_keyword(call, "name")
    if isinstance(arg, ast.Constant) and arg.value == old:
        return sources.position(file, arg)
    return None


def _definition_positions(
    sources: SourceCache, file: str, calls: list[ast.Call], spelled: set[str], old: str
) -> dict[_Pos, frozenset[_Pos]]:
    """The name argument of each call among ``calls`` spelled as one of ``spelled``
    (:func:`_factory_spellings`), each mapped to the declaring arguments that read it: none for a
    literal, the ``NAME`` argument for a module constant's literal."""
    out: dict[_Pos, frozenset[_Pos]] = {}
    for call in calls:
        if _call_name(call.func) not in spelled:
            continue
        pos = _name_argument_position(sources, file, call, old)
        if pos is not None:
            out.setdefault(pos, frozenset())
            continue
        constant = _module_constant_position(sources, file, call, old)
        if constant is not None:
            literal, arg = constant
            out[literal] = out.get(literal, frozenset()) | {arg}
    return out


def _module_constant_position(
    sources: SourceCache, file: str, call: ast.Call, old: str
) -> tuple[_Pos, _Pos] | None:
    """Where a name argument spelled as a module constant (``outbound(OB_ADT, ...)``) is given
    ``old``: the literal of the module's one top-level ``OB_ADT = "old"``, and the position of the
    argument that reads it. ``None`` when the call is not evaluated in module scope (in a ``def``,
    a class body or a comprehension a parameter or a local may shadow the module's name), or the
    module binds the name any other way or more than once, so the definition counts as not
    located. Who else reads the constant is checked once the referrers are known
    (:func:`_binding_read_only_by_referents`)."""
    arg = _first_or_keyword(call, "name")
    parsed = sources.parse(file)
    if not isinstance(arg, ast.Name) or parsed is None:
        return None
    tree = parsed[0]
    if id(arg) not in _module_scope_ids(tree):
        return None
    bindings = [node for node in ast.walk(tree) if _binds(node, arg.id)]
    if len(bindings) != 1:
        return None
    stmt = next(
        (
            s
            for s in tree.body
            if isinstance(s, ast.Assign) and any(t is bindings[0] for t in s.targets)
        ),
        None,
    )
    if stmt is None or not isinstance(stmt.value, ast.Constant) or stmt.value.value != old:
        return None
    return sources.position(file, stmt.value), sources.position(file, arg)


def _module_scope_ids(tree: ast.Module) -> set[int]:
    """The ids of ``tree``'s nodes evaluated in module scope: a ``def``'s decorators and defaults
    are, its body is not, and nor is a class body or any part of a comprehension."""
    out: set[int] = set()
    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        out.add(id(node))
        if isinstance(node, _FUNCTION_NODES):
            if not isinstance(node, ast.Lambda):
                stack.extend(node.decorator_list)
            stack.extend(node.args.defaults)
            stack.extend(d for d in node.args.kw_defaults if d is not None)
        elif isinstance(node, ast.ClassDef):
            stack.extend(node.decorator_list + node.bases + [kw.value for kw in node.keywords])
        elif not isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            stack.extend(ast.iter_child_nodes(node))
    return out


def _binds(node: ast.AST, name: str) -> bool:
    """Whether ``node`` binds ``name`` in some scope, or may (a star import, a ``global``)."""
    if isinstance(node, ast.Name):
        return node.id == name and not isinstance(node.ctx, ast.Load)
    if isinstance(node, ast.alias):
        return node.name == "*" or (node.asname or node.name.split(".")[0]) == name
    if isinstance(
        node,
        (
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.ClassDef,
            ast.ExceptHandler,
            ast.MatchAs,
            ast.MatchStar,
        ),
    ):
        return node.name == name
    if isinstance(node, ast.MatchMapping):
        return node.rest == name
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return name in node.names
    return False


def _decorator_positions(
    sources: SourceCache,
    file: str,
    span: _Span,
    fn: object,
    old: str,
    kind: str,
    *,
    registering_only: bool = False,
) -> dict[_Pos, frozenset[_Pos]]:
    """The name argument of the ``@router("old")`` / ``@handler("old")`` call registering ``fn``, or
    of ``router("old")(lambda ...)``: a call spelled ``kind`` or an alias the module imports it
    under, and nothing when there is none, so a stacked decorator's equal argument is never taken
    for the definition's. The function's body is not part of its definition. With
    ``registering_only``, only a literal argument is taken, never a module constant's."""
    import inspect

    parsed = sources.parse(file)
    if parsed is None or not callable(fn):
        return {}
    fn_name = getattr(inspect.unwrap(fn), "__name__", None)
    calls: list[ast.Call] = []
    for node in ast.walk(parsed[0]):
        if not span.start <= getattr(node, "lineno", 0) <= span.end:
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == fn_name:
            calls.extend(d for d in node.decorator_list if isinstance(d, ast.Call))
        elif (
            fn_name == "<lambda>"
            and isinstance(node, ast.Call)
            and isinstance(node.func, ast.Call)
            and any(isinstance(arg, ast.Lambda) for arg in node.args)
        ):
            calls.append(node.func)
    spelled = _factory_spellings(parsed[0], {kind})
    if registering_only:
        return {
            pos: frozenset()
            for call in calls
            if _call_name(call.func) in spelled
            and (pos := _name_argument_position(sources, file, call, old))
        }
    return _definition_positions(sources, file, calls, spelled, old)


def _factory_spellings(tree: ast.Module, factories: Iterable[str]) -> set[str]:
    """The names a call to one of ``factories`` may be spelled by in ``tree``: each factory's own
    name (``outbound(...)``, ``mf.outbound(...)``) and any alias a ``from`` import binds it to."""
    names = set(factories)
    return names | {
        a.asname
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for a in node.names
        if a.name in names and a.asname
    }


def _call_line_positions(
    sources: SourceCache, file: str, line: int, old: str, kind: str
) -> dict[_Pos, frozenset[_Pos]]:
    """The name argument of the ``inbound("old", …)`` / ``outbound("old", …)`` call on ``line``,
    which may sit inside another call (``_keep(outbound("old", …))``), spelled ``kind`` or an alias
    the module imports it under. A factory reached any other way (``ob = outbound``) is not found,
    so the definition counts as not located rather than guessed among the line's calls."""
    parsed = sources.parse(file)
    if parsed is None:
        return {}
    calls = [n for n in ast.walk(parsed[0]) if isinstance(n, ast.Call) and n.lineno == line]
    return _definition_positions(sources, file, calls, _factory_spellings(parsed[0], {kind}), old)


def _module_binding_sites(
    func: FunctionType,
    old: str,
    table_kind: str | None,
    sources: SourceCache,
    role_names: set[str],
    role_attrs: set[str],
) -> tuple[list[_Site], bool]:
    """The module-level statements that bind a name ``func`` reads and hold ``old`` -- a global in
    ``func``'s own module, or an attribute of a config module it reads (``_consts.TARGET``) in that
    module -- and whether every such captured value whose value is ``old`` (or a code set named
    ``old``) is bound by a statement this plan can rewrite.

    A default argument is written in ``func``'s own signature, so it is located by the function's
    site, never here. A closure's binding lives in an enclosing function, and an imported name's in
    another module, so neither is ever located: such a referrer is unresolved.

    For a non-table rename only a binding of a name the referrer reads in a referent role is
    rewritten, and only in its bound value: a bare global (``role_names``) in ``func``'s own module,
    a module attribute (``role_attrs``) in another, as :func:`_scan_referrer` found them.
    ``SKIP = "h"`` read only in a comparison is left, and counted (BACKLOG #5980)."""
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
            rewritable: frozenset[tuple[int, int]] | None = None
            if table_kind is None:
                allowed: set[tuple[int, int]] | None = None
                found = any(span.start <= p[0] <= span.end for p in sources.occurrences(file, old))
                # The bound value is the referent, not a dict key or a comparison beside it.
                flow = _Flow()
                read = role_names if file == func.__code__.co_filename else role_attrs
                if stmt.value is not None and stmt_names & read:
                    _carried(stmt.value, {}, set(), flow)
                rewritable = frozenset(
                    sources.position(file, c) for c in flow.consts if c.value == old
                )
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
            sites.append(
                _Site(file, span, frozenset(allowed) if allowed is not None else None, rewritable)
            )
    return sites, required <= bound


def _binding_read_only_by_referents(
    sources: SourceCache,
    modules: tuple[str, ...] | None,
    file: str,
    pos: _Pos,
    declaring: frozenset[_Pos],
    covering: list[_Site],
) -> bool:
    """Whether every read of the names bound by the module-scope statement holding the literal at
    ``pos`` is one the rename means to change; ``True`` when no such statement holds it.

    Rewriting ``NAME = "old"`` changes every read of ``NAME``, so a read is allowed only if it is
    the definition's own declaring argument (``declaring``, at most one), or it sits in the body of
    a function scanned at one of ``covering``, the sites of the referrers that rewrite this literal
    as a referent. Any other read -- a second declaration (``inbound(NAME, router=NAME)``), another
    object's decorator (``@handler(NAME)``), module-level code, a function no referrer covers, a
    config module that imports it -- would change with it, so the literal is not rewritten: the
    definition then counts as not located, and a referrer as unresolved (BACKLOG #5980)."""
    names: set[str] = set()
    for stmt, stmt_names in _module_bindings(sources, file, None):
        if stmt.value is not None and any(
            isinstance(node, ast.Constant) and sources.position(file, node) == pos
            for node in ast.walk(stmt.value)
        ):
            names |= stmt_names
    if not names:
        return True
    if len(declaring) > 1 or modules is None:
        return False
    for reader_file, node in _name_readers(sources, modules, file, names):
        if reader_file == file and sources.position(file, node) in declaring:
            continue
        if not _in_covered_body(sources, reader_file, node, covering):
            return False
    return True


def _config_modules(config_dir: Path) -> tuple[str, ...] | None:
    """Every ``.py`` under ``config_dir`` (subdirectories too, since a helper package is importable
    from a config module), as resolved paths. A dot-named directory or file is skipped, and so is a
    virtual environment (a directory holding ``pyvenv.cfg``), whose installed code is no config
    module. ``None`` when the directory cannot be walked, so no reader can be ruled out."""
    root = config_dir.resolve()
    found: list[str] = []
    failed: list[OSError] = []
    for folder, dirs, names in os.walk(root, onerror=failed.append):
        dirs[:] = sorted(
            d
            for d in dirs
            if not d.startswith(".") and not (Path(folder, d, "pyvenv.cfg")).exists()
        )
        found.extend(
            str(Path(folder, n))
            for n in sorted(names)
            if n.endswith(".py") and not n.startswith(".")
        )
    if failed:
        _log.debug("rename could not list %s for readers: %s", config_dir, type(failed[0]).__name__)
        return None
    return tuple(found)


def _name_readers(
    sources: SourceCache, modules: tuple[str, ...], file: str, names: set[str]
) -> list[tuple[str, ast.expr]]:
    """Every read of one of ``names``, bound at module scope in ``file``: in ``file`` itself, and in
    any other of ``modules`` that imports any config module, by any spelling, since a name can
    reach it through a re-export as well as from ``file``'s own module. A module that cannot be
    parsed cannot have been run, so it is skipped."""
    out: list[tuple[str, ast.expr]] = []
    parsed = sources.parse(file)
    if parsed is not None:
        out.extend(
            (file, node)
            for node in ast.walk(parsed[0])
            if isinstance(node, ast.Name) and node.id in names and isinstance(node.ctx, ast.Load)
        )
    stems = {Path(module).stem for module in modules}
    for other in modules:
        other_parsed = sources.parse(other) if other != file else None
        if other_parsed is None:
            continue
        tree = other_parsed[0]
        imports = any(
            stems.intersection(
                ((node.module or "").split(".") if isinstance(node, ast.ImportFrom) else [])
                + [part for a in node.names for part in a.name.split(".")]
            )
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        )
        if imports:
            # ``from _consts import DIET as D`` reads DIET as D.
            spelled = _factory_spellings(tree, names)
            out.extend(
                (other, node)
                for node in ast.walk(tree)
                if (isinstance(node, ast.Name) and node.id in spelled)
                or (isinstance(node, ast.Attribute) and node.attr in names)
            )
    return out


def _in_covered_body(
    sources: SourceCache, file: str, node: ast.expr, covering: list[_Site]
) -> bool:
    """Whether ``node`` sits in the body of a function in ``file`` that lies wholly in one of
    ``covering``'s spans. A decorator, a default or a signature is not the body: it is evaluated
    where the function is defined, so it is not one of the referrer's reads."""
    parsed = sources.parse(file)
    if parsed is None:
        return False
    at = (node.lineno, node.col_offset)
    for scope in ast.walk(parsed[0]):
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body: ast.stmt | ast.expr = scope.body[0]
        elif isinstance(scope, ast.Lambda):
            body = scope.body
        else:
            continue
        end = (scope.end_lineno or scope.lineno, scope.end_col_offset or 0)
        if not (body.lineno, body.col_offset) <= at <= end:
            continue
        if any(
            site.file == file and site.span.start <= scope.lineno and end[0] <= site.span.end
            for site in covering
        ):
            return True
    return False


def _module_bindings(
    sources: SourceCache, file: str, names: set[str] | None
) -> list[tuple[ast.Assign | ast.AnnAssign | ast.AugAssign, set[str]]]:
    """``file``'s module-scope assignments that bind one of ``names`` (any name, for ``None``),
    with the names each binds. Module scope includes the bodies of top-level
    ``if``/``try``/``with``/``for``/``while`` statements, but never a ``def`` or ``class`` body."""
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
        stmt_names = {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}
        if names is not None:
            stmt_names &= names
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
    config_dir: Path, factories: frozenset[str], old: str, sources: SourceCache
) -> tuple[str | None, _Span | None, dict[_Pos, frozenset[_Pos]]]:
    """Locate the code-first declaration of ``old`` (``Reference("old", …)`` / ``DatabaseLookup("old",
    …)`` / ``FhirLookup("old", …)``) and return its ``(source_file, statement span, name positions)``,
    as :func:`_definition_positions` maps them.

    lookup/fhir_lookup/reference specs carry no source line (unlike inbound/outbound), so the declaring
    statement is found by parsing each config-dir ``.py`` module (``utf-8-sig``, as the loader reads
    it) and matching a call to one of ``factories``, or an alias the module imports one under, whose
    name argument (first positional or ``name=``) is the literal ``old`` or a module constant holding
    it. Returns ``(None, None, {})`` unless exactly one call matches, so a definition this scan cannot
    see, or sees twice (a second branch, a dead copy), counts as not located and the rename is
    refused rather than leaving the declaration under its old name. An unparseable module is skipped.
    Raises :class:`WiringError` when ``config_dir`` cannot be listed, which is not "nothing matches"."""
    # The loader's own file rule: a dot-named backup of a module (vault BACKLOG #2781) or a file in a
    # subdirectory is never run, so a declaration in one must not take the definition edit.
    try:
        modules = config_py_files(config_dir)
    except OSError as exc:
        # Read as an empty directory, this left the definition out of the plan unremarked, and an
        # apply renamed only the referents (vault BACKLOG #5117).
        raise WiringError(f"could not list the config dir {config_dir}: {safe_exc(exc)}") from exc
    found: list[tuple[str, ast.Call, dict[_Pos, frozenset[_Pos]]]] = []
    for path in modules:
        file = str(path)
        # SourceCache reads utf-8-sig and skips a module past the parser's walls (BACKLOG #1858).
        parsed = sources.parse(file)
        if parsed is None:
            continue
        tree = parsed[0]
        spelled = _factory_spellings(tree, factories)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                positions = _definition_positions(sources, file, [node], spelled, old)
                if positions:
                    found.append((file, node, positions))
    if len(found) != 1:
        return None, None, {}
    file, call, positions = found[0]
    return file, _statement_span(file, call.lineno), positions


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
    edited: set[tuple[str, int, int]],
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
    edit (BACKLOG #5620), so one rewritten literal no longer vouches for a second one beside it.
    ``edited`` holds each edit's position as :func:`_source_position` gives it."""
    out: list[Reference] = []
    for ref, sites, complete in referrers:
        occurrences: set[tuple[str, int, int]] = set()
        for site in sites:
            occurrences |= site.occurrences(sources.occurrences(site.file, old), shared_kind)
        if not complete or not occurrences or not occurrences <= edited:
            out.append(ref)
    return tuple(out)


# --- python literal rewriting (tokenize) -------------------------------------


def _has_bom(file: str) -> bool:
    """Whether ``file`` starts with a UTF-8 byte-order mark."""
    try:
        with open(file, "rb") as fh:
            return fh.read(3) == codecs.BOM_UTF8
    except OSError as exc:
        # The tokenizer cannot read it either, so it yields no edit for the shift to apply to.
        _log.debug("rename could not read %s for a byte-order mark: %s", file, type(exc).__name__)
        return False


def _source_position(edit: LiteralEdit, bom_files: frozenset[str]) -> tuple[int, int]:
    """``edit``'s position as the AST positions count it. An edit is tokenized from a plain UTF-8
    read, which keeps a byte-order mark as the first character of line 1, while ``SourceCache``
    reads ``utf-8-sig`` and drops it, so on line 1 of a BOM file the two differ by one column."""
    if edit.start_line == 1 and edit.file in bom_files:
        return 1, edit.start_col - 1
    return edit.start_line, edit.start_col


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


#: A ``connections.toml`` value a rename rewrites: the file, the connection table (``inbound`` /
#: ``outbound``) and the key path inside an entry (``("name",)``, ``("settings", "reply_from")``).
_TomlTarget = tuple[str, str, tuple[str, ...]]

#: A table header line: ``[[inbound]]``, ``[outbound.settings]``. A quoted key part is not matched,
#: so the lines under it are attributed to no table and are never rewritten.
_TOML_HEADER = re.compile(
    r"^\s*\[\[?\s*(?P<path>[A-Za-z0-9_-]+(?:\s*\.\s*[A-Za-z0-9_-]+)*)\s*\]\]?\s*(?:#.*)?$"
)

#: A bare or dotted key assigned a one-line string with no escape: ``router = "r"``.
_TOML_STRING_KEY = re.compile(
    r"^(?P<pre>\s*(?P<key>[A-Za-z0-9_-]+(?:\s*\.\s*[A-Za-z0-9_-]+)*)\s*=\s*)"
    r"(?P<lit>(?P<q>[\"'])(?P<value>[^\"'\\\r\n]*)(?P=q))\s*(?:#.*)?$"
)


def _toml_edits(
    toml_path: str, table: str, keys: tuple[str, ...], old: str, new: str
) -> list[LiteralEdit] | None:
    """Rewrite, as text (no TOML round-trip), every ``<table>`` entry's value at ``keys`` equal to
    ``old`` in ``toml_path``: ``[]`` when no entry holds it, ``None`` when the edits cannot be proved.

    A candidate is a string assignment of ``old`` whose key path, under the table header above it,
    is exactly ``(table, *keys)``, so a ``name`` under ``[inbound.metadata]``, or an outbound named
    like the inbound being renamed, is not one. The candidates are then applied in memory and the
    file parsed again: the result must equal the original with exactly those values changed. A value
    spelled another way (an inline table, a quoted key, an escape) fails that check, so its referrer
    is reported rather than left reading the old name (BACKLOG #5980). The quote style and every
    other byte survive."""
    try:
        # Decoded as apply_rename decodes it, so line numbers agree.
        text = Path(toml_path).read_bytes().decode("utf-8")
        before = tomllib.loads(text)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        _log.debug("rename could not read %s: %s", toml_path, type(exc).__name__)
        return None
    expected = copy.deepcopy(before)
    entries = expected.get(table)
    held = 0
    for entry in entries if isinstance(entries, list) else ():
        parent: object = entry
        for key in keys[:-1]:
            parent = parent.get(key) if isinstance(parent, dict) else None
        if isinstance(parent, dict) and parent.get(keys[-1]) == old:
            parent[keys[-1]] = new
            held += 1
    if not held:
        return []
    wanted = (table, *keys)
    header: tuple[str, ...] | None = ()
    edits: list[LiteralEdit] = []
    lines = source_lines(text)
    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\r\n")
        if line.lstrip().startswith("["):
            m = _TOML_HEADER.match(line)
            header = _toml_key_path(m.group("path")) if m is not None else None
            continue
        m = _TOML_STRING_KEY.match(line)
        if m is None or m.group("value") != old or header is None:
            continue
        if (*header, *_toml_key_path(m.group("key"))) != wanted:
            continue
        lit, quote, col = m.group("lit"), m.group("q"), len(m.group("pre"))
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
    for edit in edits:
        _apply_one(lines, edit)
    try:
        after = tomllib.loads("".join(lines))
    except tomllib.TOMLDecodeError:
        return None
    return edits if after == expected else None


def _toml_key_path(key: str) -> tuple[str, ...]:
    """A bare dotted TOML key's parts (``settings . reply_from`` -> ``("settings", "reply_from")``)."""
    return tuple(part.strip() for part in key.split("."))


# --- apply -------------------------------------------------------------------


def _region(lines: list[str], edit: LiteralEdit) -> tuple[str, int]:
    """The text of ``edit``'s lines joined, and the offset in it where the edit's span ends."""
    region_lines = lines[edit.start_line - 1 : edit.end_line]
    region = "".join(region_lines)
    return region, len(region) - (len(region_lines[-1]) - edit.end_col)


def _apply_one(lines: list[str], edit: LiteralEdit) -> None:
    """Replace ``edit``'s span, which carries its old literal, in place."""
    region, end = _region(lines, edit)
    new_region = region[: edit.start_col] + edit.new_literal + region[end:]
    # Re-split as apply_rename split the file, so an earlier edit on its first line still indexes it.
    lines[edit.start_line - 1 : edit.end_line] = source_lines(new_region)


def _span_text(lines: list[str], edit: LiteralEdit) -> str | None:
    """The text ``edit`` spans in ``lines``, or ``None`` past the end."""
    if edit.end_line > len(lines):
        return None
    region, end = _region(lines, edit)
    return region[edit.start_col : end]


def _already_renamed(lines: list[str], edits: list[LiteralEdit]) -> bool:
    """Whether every edit's new literal sits where applying the edits would have put it.

    A new literal is one line (a name holds no line break), so an edit moves the text after it on
    its last line by the literal's change in length, and every later line up by the lines it spanned."""
    line_shift = 0
    prev: tuple[int, int, int, int] | None = None  # the last edit's old end, and where it now ends
    for edit in sorted(edits, key=lambda e: (e.start_line, e.start_col)):
        if prev is not None and edit.start_line == prev[0]:
            at = (prev[2], prev[3] + edit.start_col - prev[1])
        else:
            at = (edit.start_line + line_shift, edit.start_col)
        line, col = at
        if (
            line > len(lines)
            or lines[line - 1][col : col + len(edit.new_literal)] != edit.new_literal
        ):
            return False
        line_shift += edit.start_line - edit.end_line
        prev = (edit.end_line, edit.end_col, at[0], at[1] + len(edit.new_literal))
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
