# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Rename / delete PRE-FLIGHT over a loaded :class:`Registry` (#152 impact analysis, CLI surface).

:mod:`messagefoundry.config.reachability` stays **pure** (it computes the reverse-reference index from
``co_consts`` with no I/O); this module is its I/O twin — it turns that index into the concrete source
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

The rewrite is **span-scoped**: only literals inside a referrer function's source span (or the object's
own definition statement) are touched, so an unrelated data literal that merely happens to equal the
old name — living in a different function — is left alone.

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

from messagefoundry.config.connections_file import CONNECTIONS_FILE_NAME
from messagefoundry.config.reachability import (
    Reference,
    ReferenceIndex,
    build_reference_index,
)
from messagefoundry.config.wiring import Registry, WiringError

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

#: Kinds whose rename implies renaming a file on disk (a ``codesets/<name>.csv`` table), so ``new`` gets
#: the stricter file-stem name-safety codeset_edit enforces. Only ``code_set`` is file-backed: a
#: ``reference`` is declared code-first (``Reference("name", …)`` in a ``.py`` module) — no file moves for
#: it, and its definition literal is rewritten like any other code-first declaration (see
#: :data:`_DECLARATION_FACTORIES`).
_FILE_BACKED_KINDS = frozenset({"code_set"})

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
        """JSON-friendly view for the CLI (``messagefoundry impact --rename-to``)."""
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

    index = build_reference_index(registry)
    # file -> the line spans within it we may rewrite (definition + referrers).
    py_spans: dict[str, list[_Span]] = {}
    # (toml-path, key) pairs whose value == old must be rewritten (router binding / name definition).
    toml_targets: set[tuple[str, str]] = set()

    def add_py_span(file: str | None, span: _Span | None) -> None:
        if file is None or span is None:
            return
        resolved = _under_config_dir(config_dir, file)
        if resolved is not None:
            py_spans.setdefault(resolved, []).append(span)

    # The object's own definition (so the name is actually changed, not only its referents).
    _add_definition_span(registry, config_dir, target_kind, old, add_py_span, toml_targets)

    # Every referent edge: rewrite the literal in the referrer's source (or its toml binding). Keep each
    # py referrer's (resolved-file, span) so a referrer we could not rewrite is surfaced, not dropped.
    referrer_spans: list[tuple[Reference, str, _Span]] = []
    for ref in index.referrers(target_kind, old):
        loc = _add_referrer_span(registry, target_kind, ref, add_py_span, toml_targets)
        if loc is not None:
            resolved = _under_config_dir(config_dir, loc[0])
            if resolved is not None:
                referrer_spans.append((ref, resolved, loc[1]))

    edits: list[LiteralEdit] = []
    for file, spans in py_spans.items():
        edits.extend(_py_literal_edits(file, old, new, spans))
    for toml_path, key in toml_targets:
        edits.extend(_toml_value_edits(toml_path, key, old, new))

    # Deterministic, de-duplicated (a literal reachable from two overlapping spans appears once).
    unique = {(e.file, e.start_line, e.start_col): e for e in edits}
    ordered = sorted(unique.values(), key=lambda e: (e.file, e.start_line, e.start_col))
    unresolved = _unresolved_referrers(referrer_spans, ordered)
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
        lines = text.splitlines(keepends=True)
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


def _add_referrer_span(
    registry: Registry,
    target_kind: str,
    ref: Reference,
    add_py_span: object,
    toml_targets: set[tuple[str, str]],
) -> tuple[str, _Span] | None:
    """Scope one referent edge: a router/handler body naming ``old`` (rewrite in its function span), or
    an inbound's ``router="old"`` binding (its definition statement, or its ``connections.toml`` line).

    Returns the referrer's ``(source_file, span)`` when it maps to a ``.py`` span (so the caller can
    later check whether an edit actually landed in it), or ``None`` for a TOML binding / an unlocatable
    referrer."""
    assert callable(add_py_span)
    if ref.referrer_kind in ("router", "handler"):
        table = registry.routers if ref.referrer_kind == "router" else registry.handlers
        fn = table.get(ref.referrer)
        if fn is not None:
            file, span = _fn_span(fn)
            add_py_span(file, span)
            if file is not None and span is not None:
                return file, span
        return None
    if ref.referrer_kind == "inbound":
        conn = registry.inbound.get(ref.referrer)
        if conn is None:
            return None
        if conn.source_line is not None and conn.source_file:
            span = _statement_span(conn.source_file, conn.source_line)
            add_py_span(conn.source_file, span)
            if span is not None:
                return conn.source_file, span
        elif conn.source_file and _is_connections_toml(conn.source_file):
            # The referent edge is the router binding; rewrite only the `router = "..."` value.
            toml_targets.add((conn.source_file, "router"))
    return None


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
        source_lines, start = inspect.getsourcelines(target)
    except (OSError, TypeError):
        return None, None
    file = str(code.co_filename)
    return file, _Span(start, start + len(source_lines) - 1)


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
    when nothing matches — the definition simply isn't rewritten, exactly as before this branch existed."""
    for path in sorted(config_dir.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
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
    referrer_spans: list[tuple[Reference, str, _Span]], edits: list[LiteralEdit]
) -> tuple[Reference, ...]:
    """The referrers whose ``.py`` span carries no rewrite — a real referent the tokenizer safely refused
    to touch (a folded adjacent-string concat / no-interpolation f-string / dynamic name). Reported so a
    ``--apply`` that renames the definition doesn't silently leave a dangling referent behind."""
    out: list[Reference] = []
    for ref, file, span in referrer_spans:
        covered = any(
            edit.file == file and span.start <= edit.start_line <= span.end for edit in edits
        )
        if not covered:
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
    for lineno, line in enumerate(text.splitlines(), start=1):
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
    lines[lo : hi + 1] = new_region.splitlines(keepends=True)
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
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in new):
        raise WiringError(f"the new name {new!r} must not contain control characters")
    if any(ch in new for ch in ("'", '"', "\\")):
        raise WiringError(f"the new name {new!r} must not contain a quote or backslash")
    if target_kind in _FILE_BACKED_KINDS:
        # Reuse the exact traversal/drive/containment rules the codeset writer enforces on a file stem.
        from messagefoundry.config.codeset_edit import _validate_name
        from messagefoundry.config.code_sets import CODESETS_DIR_NAME

        _validate_name(config_dir / CODESETS_DIR_NAME, new)


def _is_registered(registry: Registry, target_kind: str, name: str) -> bool:
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
    return name in tables[target_kind]


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
