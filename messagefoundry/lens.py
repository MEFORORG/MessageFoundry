# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Structured Steps view over Python Handlers — the static ``ast`` parser (ADR 0076 §3–§4).

:func:`parse_module` classifies each ``@handler`` body in a config module into the **row contract** of
ADR 0076 §3: ordered, nested rows of kind ``action`` / ``lookup`` / ``control`` / ``send`` / ``code``.
It is a **static parse** — it uses only the stdlib :mod:`ast` and **never imports or executes** the
config module, so a module whose top level would raise (or whose imports are unavailable) still parses
(ADR 0076 §5, gate 4). Routers are **out of v1 scope** (handlers only).

The load-bearing property (ADR 0076 §6, gate 1 — the **coverage invariant**): the emitted rows'
line ranges **exactly partition** each handler's def body (the statement suite from the first body
statement through the function's last line) — every line is in exactly one row; nothing is dropped,
reordered, or synthesized. Unrecognized constructs become in-place ``code`` rows (the degradation
ladder: typed row → code row → whole-file refusal only on parse failure).

Two contract details worth stating for L3 consumers: a ``lookup`` row may carry an extra ``assign_to``
field (the assignment target of e.g. ``row = db_lookup(...)`` — within §3's contract, optional). And a
trailing comment *after the last statement* in a def lives **outside** the partition (beyond the def's
``node.end_lineno``, which the AST fixes to the last statement's last line), by design — the partition
covers ``[first_stmt_line, node.end_lineno]``, so nothing after it is a row (safe for phase-3 splices).

The engine owns the grammar so it lives beside the vocabulary; the IDE consumes the JSON contract
only (``messagefoundry lens parse <module.py> --json``). This module adds **no runtime dependency** —
stdlib ``ast`` only.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, NamedTuple

__all__ = [
    "LensParseError",
    "LensRewriteError",
    "parse_module",
    "parse_source",
    "rewrite_module",
    "rewrite_source",
]


class LensParseError(ValueError):
    """The module file could not be parsed (a syntax error) — a whole-file lens refusal (ADR 0076 §4).

    A subclass of :class:`ValueError`; the CLI turns it into a clean error + non-zero exit, and the IDE
    steps aside to the plain text editor."""


class LensRewriteError(ValueError):
    """A row edit the lens refuses to apply (ADR 0076 §5) — it will not guess a rewrite it can't round-trip.

    Raised by :func:`rewrite_source` when the edit targets a line range that is not a recognized
    ``action``/``lookup``/``send`` row (``code``/``control`` rows are read-only), names a parameter the
    call does not take, would turn a literal into an expression (or vice-versa) unsafely, or is otherwise
    outside the v1 param-edit scope. A subclass of :class:`ValueError`; the CLI turns it into a clean
    ``{"error": …}`` + non-zero exit, exactly like :class:`LensParseError`, so the caller never applies a
    partial or lossy rewrite. Byte-preservation is the contract: an editable row is regenerated **only**
    within its own line range, every other byte untouched (gate 2)."""


# --- vocabulary registries ---------------------------------------------------
#
# Parameter names INCLUDING the leading ``msg`` where the helper takes one, so a positional arg maps to
# its name by index (``msg`` is then dropped from the emitted params — §3 shows params without it).
# Widening this roster is an ordinary addition (ADR 0076 §2); widening the *grammar* below requires an
# ADR amendment.
_ACTION_PARAMS: dict[str, list[str]] = {
    "copy_field": ["msg", "src", "dst"],
    "set_field": ["msg", "path", "value"],
    "append_to_field": ["msg", "path", "suffix"],
    "format_date": ["msg", "path", "out_fmt"],  # in_fmt is keyword-only
    "convert_case": ["msg", "path", "mode"],
    "split_field": ["msg", "src", "sep", "dests"],
    "copy_segment": ["msg", "segment_id"],  # occurrence / index are keyword-only
    "delete_segment": ["msg", "segment_id"],
}
# The sanctioned read-only lookups (ADR 0010/0043) + the ``code_lookup`` vocabulary helper are rendered
# as DBSelect-style ``lookup`` rows (ADR 0076 §3). db_lookup/fhir_lookup take no ``msg`` argument.
_LOOKUP_PARAMS: dict[str, list[str]] = {
    "db_lookup": ["connection", "statement", "params"],
    "fhir_lookup": ["connection", "query"],
    "code_lookup": ["msg", "path", "table"],  # default is keyword-only
}

_ACTIONS = frozenset(_ACTION_PARAMS)
_LOOKUPS = frozenset(_LOOKUP_PARAMS)


# --- native Message-API idiom recognition (ADR 0089 Phase A) ------------------
#
# ADR 0076's lens recognized only the ``messagefoundry.actions`` *wrapper* calls (``set_field(msg,
# …)``). The migrated estate is written entirely in the **native** ``Message`` API (``msg.set(path,
# value)``, ``msg.field(path)``, ``msg.delete_segments(id)``), so ADR 0089 Phase A teaches the parser to
# recognize those native method-call idioms as the SAME editable ``action`` rows (``set_field`` /
# ``copy_field`` / ``delete_segment``), reusing every ADR 0076 row contract and the byte-space splice
# below — the ``.py`` is never rewritten into wrappers.
#
# A native method call is NOT the wrapper form: ``msg`` is the receiver, so a native ``msg.set(a, b)``
# has NO ``msg`` positional (arg0 = path, arg1 = value) unlike ``set_field(msg, path, value)``
# (arg0 = msg). The recognizer below is the SINGLE source of truth for which native forms are actions
# and which argument node each editable parameter maps to — both the parser (row emission) and the
# rewriter (arg-locating for :func:`_splice_slots`) consult it, so they can never diverge.


class _NativeAction(NamedTuple):
    """A recognized native ``Message``-API write statement (ADR 0089 Phase A).

    ``action`` is the reused ADR 0076 vocabulary name (``set_field`` / ``copy_field`` /
    ``delete_segment``). ``slots`` maps each **editable** parameter, in canonical order, to the exact
    :class:`ast.expr` node whose byte span an edit splices (a positional arg, or — for ``copy_field`` —
    the inner ``msg.field(src)`` argument). ``display`` carries read-only, byte-preserved keyword args
    (``occurrence=``/``repetition=``) that are shown on the row but are never editable in Phase A and
    are never dropped or reordered on a rewrite."""

    action: str
    slots: list[tuple[str, ast.expr]]
    display: list[tuple[str, ast.expr]]


def _is_msg_method(func: ast.expr, name: str) -> bool:
    """Whether ``func`` is the attribute ``msg.<name>`` (the receiver must be the bare ``msg`` name).

    Guards against false positives on a non-``msg`` receiver (``other.set(...)``) and on a lookalike
    attribute (``msg.setState`` — ``attr`` must equal ``name`` exactly, not merely start with it)."""
    return (
        isinstance(func, ast.Attribute)
        and func.attr == name
        and isinstance(func.value, ast.Name)
        and func.value.id == "msg"
    )


def _msg_field_source(value: ast.expr) -> ast.Call | None:
    """The inner ``msg.field(src)`` call of a copy value, or None if ``value`` is not that idiom.

    Recognizes both ``msg.field(src)`` and the common ``msg.field(src) or ""`` default idiom (an
    ``Or`` whose right operand is the empty string). The inner call must have at least one positional
    argument (``src``) and no ``*`` splat in that slot — otherwise there is no field to copy from and
    the caller falls back to treating the whole expression as an opaque ``set_field`` value."""
    if (
        isinstance(value, ast.BoolOp)
        and isinstance(value.op, ast.Or)
        and len(value.values) == 2
        and isinstance(value.values[1], ast.Constant)
        and value.values[1].value == ""
    ):
        candidate: ast.expr = value.values[0]
    else:
        candidate = value
    if (
        isinstance(candidate, ast.Call)
        and _is_msg_method(candidate.func, "field")
        and candidate.args
        and not isinstance(candidate.args[0], ast.Starred)
    ):
        return candidate
    return None


def _recognize_native_method(call: ast.Call) -> _NativeAction | None:
    """Classify a native ``msg.<method>(...)`` call into a :class:`_NativeAction`, or None (→ ``code``).

    Recognizes exactly the ADR 0089 Phase A forms:

    * ``msg.set(path, value)`` → ``set_field`` (path + value editable slots).
    * ``msg.set(dst, msg.field(src))`` / ``msg.set(dst, msg.field(src) or "")`` → ``copy_field``.
    * ``msg.delete_segments("SEG")`` / ``msg.delete_segment("SEG")`` → ``delete_segment``.

    A ``*args`` / ``**kwargs`` splat, the wrong positional arity (``msg.set`` with != 2, ``delete`` with
    != 1), a non-``msg`` receiver, or any other method makes it unrecognized (→ a read-only ``code`` row):
    when unsure the lens degrades rather than risk a corrupting edit. ``occurrence=``/other keyword args
    are preserved as read-only ``display`` fields (never dropped, never editable in Phase A)."""
    func = call.func
    if not isinstance(func, ast.Attribute) or not _is_msg_method(func, func.attr):
        return None
    # A ``*args`` positional or ``**kwargs`` splat defeats static arity/keyword reasoning — refuse it so
    # a splice never mis-targets a hidden argument (fall back to a code row).
    if any(isinstance(a, ast.Starred) for a in call.args):
        return None
    if any(kw.arg is None for kw in call.keywords):
        return None
    display: list[tuple[str, ast.expr]] = [(kw.arg, kw.value) for kw in call.keywords if kw.arg]
    if func.attr == "set":
        if len(call.args) != 2:
            return None
        dst_or_path, value = call.args[0], call.args[1]
        field_call = _msg_field_source(value)
        if field_call is not None:
            # ``msg.set(dst, msg.field(src)[ or ""])`` — a field-to-field copy. ``src`` is the inner
            # field call's first argument; ``dst`` is the outer ``set``'s first argument.
            return _NativeAction(
                "copy_field", [("src", field_call.args[0]), ("dst", dst_or_path)], display
            )
        return _NativeAction("set_field", [("path", dst_or_path), ("value", value)], display)
    if func.attr in ("delete_segments", "delete_segment"):
        if len(call.args) != 1:
            return None
        return _NativeAction("delete_segment", [("segment_id", call.args[0])], display)
    return None


def _native_action_row(
    native: _NativeAction, s: ast.stmt, nesting: int, source: str
) -> dict[str, Any]:
    """Build the ADR 0076 ``action`` row contract for a recognized native write (ADR 0089 Phase A).

    ``params`` renders each editable slot (a literal → its value; an expression → verbatim source) then
    each read-only keyword (``occurrence=``), so the row carries the same shape as the wrapper form.
    ``literal_params`` is the subset of *slot* params whose argument is a string/scalar literal — the
    IDE offers only those as editable, exactly as for wrapper actions (a keyword like ``occurrence`` is
    never listed, so it stays a bound read-only field)."""
    params: dict[str, Any] = {}
    for name, node in native.slots:
        params[name] = _render_value(node, source)
    for name, node in native.display:
        params[name] = _render_value(node, source)
    literal_params = [name for name, node in native.slots if isinstance(node, ast.Constant)]
    return {
        "kind": "action",
        "action": native.action,
        "params": params,
        "literal_params": literal_params,
        "line_start": s.lineno,
        "line_end": s.end_lineno or s.lineno,
        "nesting": nesting,
    }


# --- public entry points -----------------------------------------------------


def parse_module(path: str | Path) -> list[dict[str, Any]]:
    """Parse the config module file at ``path`` and return its ``@handler`` row contracts (ADR 0076 §3).

    Statically parses the file text with :mod:`ast` — the module is **never imported or executed**.
    Returns one contract dict per handler, ``{"handler", "module", "def_line", "rows"}``; a module with
    no handlers returns ``[]``. Raises :class:`LensParseError` if the file cannot be read or parsed."""
    p = Path(path)
    try:
        source = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise LensParseError(f"{p}: cannot read ({exc})") from exc
    # posix slashes keep the emitted contract (and the committed L3 fixtures) OS-neutral.
    return parse_source(source, module=p.as_posix())


def parse_source(source: str, *, module: str = "<source>") -> list[dict[str, Any]]:
    """Parse Python ``source`` text and return the ``@handler`` row contracts (see :func:`parse_module`).

    The file-free entry point (used by tests). ``module`` is echoed into each contract's ``module``
    field. Raises :class:`LensParseError` on a syntax error."""
    # A leading UTF-8 BOM (U+FEFF) is invalid in a ``str`` handed to :func:`ast.parse` (it is only
    # stripped on the *bytes* path), so drop it up front; line numbers are unaffected (it sits on line 1).
    source = source.removeprefix("\ufeff")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise LensParseError(f"{module}: cannot parse ({exc.msg} at line {exc.lineno})") from exc
    # Split on \r\n / \r / \n only (the tokenizer's line model) so a form-feed / NEL / U+2028 never
    # desyncs an AST line number from its text (F2); everything mapping a line number to text uses this.
    lines = _physical_lines(source)
    handlers: list[dict[str, Any]] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        name = _handler_name(node)
        if name is None:
            continue  # not a @handler (router or plain def) — out of v1 scope
        body_start = node.body[0].lineno
        body_end = node.end_lineno or body_start
        # The def body is the top suite; its id is the def line (unique per module, so sibling handlers
        # never share a suite id in the flat webview row list).
        rows = _partition_suite(node.body, body_start, body_end, 0, source, lines, str(node.lineno))
        rows = _merge_code_rows(rows)
        handlers.append({"handler": name, "module": module, "def_line": node.lineno, "rows": rows})
    return handlers


# --- handler discovery -------------------------------------------------------


def _handler_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """The registered name of a ``@handler("name")`` def, or None if it is not a handler.

    A ``@router`` (or any other decoration) returns None — routers are out of v1 scope. A ``@handler``
    with a non-literal name falls back to the def name so the handler still appears."""
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        if _callee_name(dec.func) != "handler":
            continue
        if (
            dec.args
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            return dec.args[0].value
        return node.name
    return None


def _callee_name(func: ast.expr) -> str | None:
    """The bare callable name of a call target: ``handler`` for ``@handler`` and ``@mf.handler``."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


# --- partition (the coverage invariant) --------------------------------------


def _partition_suite(
    stmts: list[ast.stmt], lo: int, hi: int, nesting: int, source: str, lines: list[str], suite: str
) -> list[dict[str, Any]]:
    """Tile the inclusive line range ``[lo, hi]`` occupied by ``stmts`` into contiguous rows.

    Every line in ``[lo, hi]`` lands in exactly one row: each statement contributes its own row(s), and
    any gap between them (blank lines, standalone comments) becomes a ``code`` row in place.

    Statements that **share a physical line** (a semicolon-compound line such as ``a; b``, or a
    multi-line statement whose last line carries a ``;``-joined sibling) are outside the bounded grammar,
    so a run of them degrades to a **single** ``code`` row over the run's whole line span — otherwise each
    would emit a row over the shared line and double-count it, breaking the coverage partition (§6).

    ``suite`` is this suite's stable id (the enclosing block's header line as a string; the def body uses
    the def line): every row that lives DIRECTLY in this suite is stamped with it, so the webview can group
    siblings — offering a drag-reorder drop only among true siblings and greying an ↑/↓ at a suite edge (a
    reorder never crosses into/out of an if/for body). A nested block's body/else recurses with its OWN id,
    so the header row (this suite) and the body rows (the child suite) are correctly partitioned. The
    engine's move op re-derives the real AST suite and stays authoritative; ``suite`` is a display aid."""
    rows: list[dict[str, Any]] = []
    cursor = lo
    for group in _group_shared_lines(stmts):
        g_start = group[0].lineno
        g_end = max((s.end_lineno or s.lineno) for s in group)
        if g_start > cursor:
            rows.append(_code_row(cursor, g_start - 1, nesting))
        if len(group) == 1:
            emitted = _emit_stmt(group[0], nesting, source, lines)
            # The first row is the statement's OWN row (a control header for a block, else the simple/code
            # row) — it lives in THIS suite. Any further rows are a block's body/else, stamped by their own
            # recursive `_partition_suite` with the child suite id, so only stamp `emitted[0]` here.
            if emitted:
                emitted[0]["suite"] = suite
            rows.extend(emitted)
        else:
            # Semicolon-compound line(s): honestly degrade the whole run to one code row (§4 ladder).
            rows.append(_code_row(g_start, g_end, nesting))
        cursor = g_end + 1
    if cursor <= hi:
        rows.append(_code_row(cursor, hi, nesting))
    # Stamp the in-suite code rows (gaps/trailing) that were appended directly, not via `_emit_stmt`.
    for row in rows:
        row.setdefault("suite", suite)
    return rows


def _group_shared_lines(stmts: list[ast.stmt]) -> list[list[ast.stmt]]:
    """Group consecutive ``stmts`` that share a physical line into runs; singletons otherwise.

    A statement joins the current run when it **starts on or before** the run's last line so far
    (``s.lineno <= run_end`` — the overlap test) — i.e. it is on a line the run already occupies, which
    (for sibling statements in a suite) only happens across a semicolon. A statement that merely spans
    several of its own lines and is followed by one on a *later* line starts a fresh run, so a legitimate
    multi-line statement is never mis-coalesced with the next statement."""
    groups: list[list[ast.stmt]] = []
    run_end = 0
    for s in stmts:
        if groups and s.lineno <= run_end:
            groups[-1].append(s)
        else:
            groups.append([s])
            run_end = s.end_lineno or s.lineno
            continue
        run_end = max(run_end, s.end_lineno or s.lineno)
    return groups


def _emit_stmt(s: ast.stmt, nesting: int, source: str, lines: list[str]) -> list[dict[str, Any]]:
    """Rows tiling exactly ``[s.lineno, s.end_lineno]`` for one statement (recursing into control blocks)."""
    if isinstance(s, ast.If):
        return _emit_if(s, nesting, "if", source, lines)
    if isinstance(s, ast.For | ast.AsyncFor):
        return _emit_for(s, nesting, source, lines)
    recognized = _classify_simple(s, nesting, source)
    if recognized is not None:
        return [recognized]
    return [_code_row(s.lineno, s.end_lineno or s.lineno, nesting)]


def _emit_if(
    node: ast.If, nesting: int, kind: str, source: str, lines: list[str]
) -> list[dict[str, Any]]:
    """Rows for an ``if``/``elif`` block: a control header row, the nested body, then its ``elif``/``else``."""
    first = node.body[0].lineno
    if first <= node.lineno:
        # Inline suite (``if x: y``) — the bounded grammar does not cover it; degrade to one code row.
        return [_code_row(node.lineno, node.end_lineno or node.lineno, nesting)]
    match = _classify_if_control(node.test, source)
    recognized = _is_bounded(node.test) or match is not None
    rows = [
        _control_row(
            kind,
            _src(node.test, source),
            recognized,
            node.lineno,
            first - 1,
            nesting,
            match.label if match else None,
            match.operand if match else None,
        )
    ]
    body_end = node.body[-1].end_lineno or first
    # The body is a child suite keyed by this block's header line (unique per module).
    rows.extend(
        _partition_suite(node.body, first, body_end, nesting + 1, source, lines, str(node.lineno))
    )
    rows.extend(_emit_orelse(node, body_end, nesting, source, lines))
    return rows


def _emit_orelse(
    node: ast.If, body_end: int, nesting: int, source: str, lines: list[str]
) -> list[dict[str, Any]]:
    """Rows tiling ``(body_end, node.end_lineno]`` — the ``elif``/``else`` tail of an ``if`` (or ``[]``)."""
    orelse = node.orelse
    if not orelse:
        return []
    rows: list[dict[str, Any]] = []
    first_or = orelse[0]
    # ``elif`` and ``else: if`` are structurally identical in the AST; the elif keyword keeps the outer
    # if's column, an indented ``else: if`` does not.
    if len(orelse) == 1 and isinstance(first_or, ast.If) and first_or.col_offset == node.col_offset:
        if first_or.lineno > body_end + 1:
            rows.append(_code_row(body_end + 1, first_or.lineno - 1, nesting))
        rows.extend(_emit_if(first_or, nesting, "elif", source, lines))
        return rows

    # Plain ``else`` block. Locate the ``else:`` header line in the region before the else body.
    end_lineno = node.end_lineno or body_end
    else_body_first = first_or.lineno
    else_line = _find_keyword(lines, body_end + 1, else_body_first - 1, "else")
    if else_line is None or else_body_first <= else_line:
        # No locatable header, or an inline ``else: y`` — degrade the whole tail to one code row.
        return [_code_row(body_end + 1, end_lineno, nesting)]
    if else_line > body_end + 1:
        rows.append(_code_row(body_end + 1, else_line - 1, nesting))
    rows.append(_control_row("else", None, True, else_line, else_body_first - 1, nesting))
    else_body_end = orelse[-1].end_lineno or else_body_first
    # The else body is its own suite, keyed by the ``else:`` header line.
    rows.extend(
        _partition_suite(
            orelse, else_body_first, else_body_end, nesting + 1, source, lines, str(else_line)
        )
    )
    return rows


def _emit_for(
    node: ast.For | ast.AsyncFor, nesting: int, source: str, lines: list[str]
) -> list[dict[str, Any]]:
    """Rows for a ``for`` block: a control header row (recognized iff a Message iteration) + nested body.

    A ``for ... else`` tail (rare) is emitted as a trailing ``code`` row so the partition stays exact."""
    first = node.body[0].lineno
    if first <= node.lineno:
        return [_code_row(node.lineno, node.end_lineno or node.lineno, nesting)]
    test_src = f"{_src(node.target, source)} in {_src(node.iter, source)}"
    match = _classify_for_control(node)
    recognized = _is_message_iteration(node.iter) or match is not None
    rows = [
        _control_row(
            "for",
            test_src,
            recognized,
            node.lineno,
            first - 1,
            nesting,
            match.label if match else None,
            match.operand if match else None,
        )
    ]
    body_end = node.body[-1].end_lineno or first
    rows.extend(
        _partition_suite(node.body, first, body_end, nesting + 1, source, lines, str(node.lineno))
    )
    end_lineno = node.end_lineno or body_end
    if node.orelse and body_end < end_lineno:
        rows.append(_code_row(body_end + 1, end_lineno, nesting))
    return rows


# --- simple-statement classification -----------------------------------------


def _classify_simple(s: ast.stmt, nesting: int, source: str) -> dict[str, Any] | None:
    """A recognized ``action`` / ``lookup`` / ``send`` row for a simple statement, or None (→ ``code``)."""
    line_start = s.lineno
    line_end = s.end_lineno or s.lineno

    # ``return Send(...)`` / ``return [Send(...), ...]`` — a send row.
    if isinstance(s, ast.Return) and s.value is not None:
        outbounds = _send_outbounds(s.value)
        if outbounds is not None:
            return {
                "kind": "send",
                "outbounds": outbounds,
                "line_start": line_start,
                "line_end": line_end,
                "nesting": nesting,
            }
        return None

    # A vocabulary/lookup call — as a bare expression statement (mutating action / code_lookup) or as an
    # assignment whose value is a lookup call (db_lookup/fhir_lookup return a value).
    call: ast.Call | None = None
    assign_to: str | None = None
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
        call = s.value
    elif isinstance(s, ast.Assign) and isinstance(s.value, ast.Call):
        call = s.value
        assign_to = ", ".join(_src(t, source) or "" for t in s.targets)
    elif isinstance(s, ast.AnnAssign) and isinstance(s.value, ast.Call):
        call = s.value
        assign_to = _src(s.target, source)
    if call is None:
        return None

    # ADR 0089 Phase A: a native ``msg.set(...)`` / ``msg.delete_segments(...)`` statement (a mutating
    # method call, so always a bare expression statement — never an assignment) becomes the SAME editable
    # action row as its wrapper equivalent, without the module being rewritten.
    if isinstance(s, ast.Expr):
        native = _recognize_native_method(call)
        if native is not None:
            return _native_action_row(native, s, nesting, source)

    name = _callee_name(call.func)
    if name in _ACTIONS and isinstance(s, ast.Expr):
        return {
            "kind": "action",
            "action": name,
            "params": _render_params(call, _ACTION_PARAMS[name], source),
            "literal_params": _literal_param_names(call, _ACTION_PARAMS[name]),
            "line_start": line_start,
            "line_end": line_end,
            "nesting": nesting,
        }
    if name in _LOOKUPS:
        row: dict[str, Any] = {
            "kind": "lookup",
            "call": name,
            "params": _render_params(call, _LOOKUP_PARAMS[name], source),
            "literal_params": _literal_param_names(call, _LOOKUP_PARAMS[name]),
            "line_start": line_start,
            "line_end": line_end,
            "nesting": nesting,
        }
        if assign_to:
            row["assign_to"] = assign_to
        return row
    return None


def _send_outbounds(value: ast.expr) -> list[str] | None:
    """Destination names for a ``Send(...)`` or non-empty list/tuple of ``Send``/``SetState`` calls.

    Returns the (possibly empty — a non-literal destination) list for a send return, or None when the
    return is not a send construct (e.g. ``return None`` / ``return []`` → a ``code`` row)."""
    sends: list[ast.Call]
    if isinstance(value, ast.Call) and _callee_name(value.func) == "Send":
        sends = [value]
    elif isinstance(value, ast.List | ast.Tuple) and value.elts:
        # A pure list/tuple of Send/SetState returns; anything else in it makes the whole return a
        # code row (not a recognized send).
        sends = []
        for elt in value.elts:
            if not isinstance(elt, ast.Call):
                return None
            callee = _callee_name(elt.func)
            if callee == "Send":
                sends.append(elt)
            elif callee != "SetState":
                return None
    else:
        return None
    outbounds: list[str] = []
    for call in sends:
        if (
            call.args
            and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str)
        ):
            outbounds.append(call.args[0].value)
    return outbounds


# --- parameter rendering -----------------------------------------------------


def _render_params(call: ast.Call, param_names: list[str], source: str) -> dict[str, Any]:
    """Map a call's positional + keyword args to ``{param: value}``, dropping the leading ``msg``.

    A literal arg renders to its Python value (JSON scalar or list of scalars); anything else renders to
    its verbatim source text (a bounded ``Message`` read such as ``msg["PID-5"]``)."""
    params: dict[str, Any] = {}
    for i, arg in enumerate(call.args):
        if isinstance(arg, ast.Starred):
            params[f"*{param_names[i] if i < len(param_names) else f'arg{i}'}"] = _render_value(
                arg.value, source
            )
            continue
        name = param_names[i] if i < len(param_names) else f"arg{i}"
        if name == "msg":
            continue
        params[name] = _render_value(arg, source)
    for kw in call.keywords:
        if kw.arg is None:
            params["**kwargs"] = _render_value(kw.value, source)
        else:
            params[kw.arg] = _render_value(kw.value, source)
    return params


def _literal_param_names(call: ast.Call, param_names: list[str]) -> list[str]:
    """The subset of a call's editable param names whose argument is a Python **literal** (``ast.Constant``).

    Only a literal-valued param can be safely edited in place from a scalar (ADR 0076 §5): the lens
    refuses to rewrite an expression slot from a bare scalar. The IDE gates its enabled input on this
    list, so it never offers an expression/list-valued param (e.g. ``db_lookup(..., params={...})`` or
    ``split_field(..., dests=[...])``) as editable — which would guarantee a refused edit + error toast
    (F6). Mirrors :func:`_render_params`' name mapping (leading ``msg`` and ``*args``/``**kwargs`` are
    never editable, so they are excluded)."""
    literal: list[str] = []
    for i, arg in enumerate(call.args):
        if isinstance(arg, ast.Starred):
            continue
        name = param_names[i] if i < len(param_names) else f"arg{i}"
        if name == "msg":
            continue
        if isinstance(arg, ast.Constant):
            literal.append(name)
    for kw in call.keywords:
        if kw.arg is not None and isinstance(kw.value, ast.Constant):
            literal.append(kw.arg)
    return literal


def _render_value(node: ast.expr, source: str) -> Any:
    """A literal's Python value (or list of literal values), else the node's verbatim source text."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List | ast.Tuple) and all(
        isinstance(e, ast.Constant) for e in node.elts
    ):
        return [e.value for e in node.elts if isinstance(e, ast.Constant)]
    return _src(node, source)


# --- bounded-expression checks (the ``recognized`` flag) ---------------------


def _is_bounded(node: ast.expr) -> bool:
    """Whether an ``if``/``elif`` test is a bounded expression (ADR 0076 §4).

    Bounded = Message reads (``msg[...]`` / ``msg.field(...)``), name references, comparisons, boolean
    ops, string/mapping method calls over those, and literals. Any lambda/comprehension/walrus/await, or
    a call to a bare function name (not a method), makes the test unrecognized — it still renders as a
    control row (structure preserved), just flagged ``recognized: false``."""
    for sub in ast.walk(node):
        if isinstance(
            sub,
            ast.Lambda
            | ast.ListComp
            | ast.SetComp
            | ast.DictComp
            | ast.GeneratorExp
            | ast.Await
            | ast.NamedExpr
            | ast.Yield
            | ast.YieldFrom,
        ):
            return False
        # Calls must be method calls (``x.get(...)``, ``msg.field(...)``) — a bare ``f(...)`` is
        # arbitrary behavior, outside the bounded subset.
        if isinstance(sub, ast.Call) and not isinstance(sub.func, ast.Attribute):
            return False
    return True


def _is_message_iteration(node: ast.expr) -> bool:
    """Whether a ``for`` iterates a Message structure (``msg.groups(...)`` / ``.segments()`` / ``.repetitions(...)``)."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in ("groups", "segments", "repetitions"):
        return False
    return isinstance(node.func.value, ast.Name) and node.func.value.id == "msg"


# --- native control-flow idiom recognition (ADR 0089 Phase C) -----------------
#
# ADR 0089 §5 found the estate's control flow is idiomatic native Python (``for i in range(1,
# msg.count_segments("SEG") + 1)``, ``if current_environment() in (...)``, field-value guards, regex
# filters), which the ADR 0076 lens rendered as UNRECOGNIZED ``control`` rows. Phase C teaches the
# classifier to recognize exactly those shapes so they render as RECOGNIZED control rows with a
# descriptive **label** and a captured **operand** (the segment id / environment values / field path)
# for display. The control STRUCTURE stays read-only — the lens still only edits the ACTIONS inside a
# block, never the if/for logic — so this is recognition + a label + an operand, never a new edit path.
#
# Recognition is deliberately TIGHT (ADR 0089 §4 — no false positives): a for/if that does not match one
# of the exact shapes below carries no label and keeps its prior ``recognized`` flag (bounded ifs /
# ``msg.groups(...)`` iteration stay recognized via the Phase-A checks above; anything else stays
# UNRECOGNIZED). ``_classify_*_control`` is the single source of truth for the four Phase-C forms.


_REGEX_GUARD_METHODS = frozenset({"search", "match", "fullmatch"})


class _ControlMatch(NamedTuple):
    """A recognized Phase-C control idiom: a descriptive ``label`` + a captured display ``operand``.

    ``operand`` is JSON-serializable (a string, a list of strings, or None for a form with no single key
    operand, e.g. a regex filter guard). It is READ-ONLY (recognition + display only) — Phase C never
    edits the control header."""

    label: str
    operand: Any


def _is_one_int_literal(node: ast.expr, value: int) -> bool:
    """Whether ``node`` is exactly the int literal ``value`` (a ``bool`` — ``True``/``False`` — is not)."""
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
        and node.value == value
    )


def _range_count_segment(node: ast.expr) -> str | None:
    """The literal segment id of a ``range(1, msg.count_segments("SEG") + 1)`` iterator, or None.

    Guards the exact dominant estate loop shape (ADR 0089 §5, form 1): a bare ``range`` with exactly two
    positional args, a literal ``1`` lower bound, and an upper bound of ``msg.count_segments(<str
    literal>) + 1``. Any other range (a different bound, a non-``count_segments`` / non-``msg`` receiver,
    a ``*args`` splat, a non-literal segment id) returns None so the loop stays unrecognized rather than
    be mislabeled."""
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "range"
        and len(node.args) == 2
        and not any(isinstance(a, ast.Starred) for a in node.args)
    ):
        return None
    low, high = node.args
    if not _is_one_int_literal(low, 1):
        return None
    if not (
        isinstance(high, ast.BinOp)
        and isinstance(high.op, ast.Add)
        and _is_one_int_literal(high.right, 1)
    ):
        return None
    count_call = high.left
    if (
        isinstance(count_call, ast.Call)
        and _is_msg_method(count_call.func, "count_segments")
        and len(count_call.args) == 1
        and isinstance(count_call.args[0], ast.Constant)
        and isinstance(count_call.args[0].value, str)
    ):
        return count_call.args[0].value
    return None


def _classify_for_control(node: ast.For | ast.AsyncFor) -> _ControlMatch | None:
    """A Phase-C control label + operand for a recognized ``for`` idiom, or None (kept unlabeled).

    Recognizes the segment-count loop (form 1). ``for x in msg.groups()/segments()/repetitions(...)``
    stays handled by :func:`_is_message_iteration` (recognized native iteration, no Phase-C label)."""
    seg = _range_count_segment(node.iter)
    if seg is not None:
        return _ControlMatch(f"for each {seg} segment", seg)
    return None


def _environment_gate(test: ast.expr, source: str) -> list[Any] | None:
    """The environment values of a ``current_environment() in (...)`` / ``== "x"`` test, or None.

    Form 2: a single-comparison test whose left operand is a ``current_environment()`` call. ``in``/``not
    in`` against a tuple/list/set and ``==``/``!=`` against a scalar are recognized; each captured value
    is its literal (a non-literal element falls back to its verbatim source text) so the operand is always
    a JSON-serializable list for display."""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1):
        return None
    if not (
        isinstance(test.left, ast.Call) and _callee_name(test.left.func) == "current_environment"
    ):
        return None
    op, comp = test.ops[0], test.comparators[0]
    if isinstance(op, ast.In | ast.NotIn) and isinstance(comp, ast.Tuple | ast.List | ast.Set):
        return [e.value if isinstance(e, ast.Constant) else _src(e, source) for e in comp.elts]
    if isinstance(op, ast.Eq | ast.NotEq) and isinstance(comp, ast.Constant):
        return [comp.value]
    return None


def _field_condition(test: ast.expr) -> str | None:
    """The literal field path of a ``msg.field("X") <cmp> ...`` (or bare ``if msg.field("X"):``) test.

    Form 3: the condition's left operand (or the whole test, for a bare truthiness check) is a
    ``msg.field(<str literal>)`` read. Returns the path literal, else None. A non-literal path, a
    ``msg.field`` splat, or a receiver that is not ``msg`` is not matched (guard tightly — a
    ``other.field(...)`` / dynamic path is not a Phase-C field gate)."""
    candidate = test.left if isinstance(test, ast.Compare) else test
    if (
        isinstance(candidate, ast.Call)
        and _is_msg_method(candidate.func, "field")
        and candidate.args
        and not isinstance(candidate.args[0], ast.Starred)
        and isinstance(candidate.args[0], ast.Constant)
        and isinstance(candidate.args[0].value, str)
    ):
        return candidate.args[0].value
    return None


def _is_regex_guard(test: ast.expr) -> bool:
    """Whether a test is a regex filter guard: a ``<name>.search/.match/.fullmatch(...)`` call (form 4).

    Recognizes the direct call, a ``not <call>`` negation, and a ``<call> is [not] None`` comparison —
    the three shapes the estate pairs with a ``return None`` drop. A method whose name is not one of
    ``search``/``match``/``fullmatch`` is not a guard."""
    node = test
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        node = node.operand
    if isinstance(node, ast.Compare) and len(node.comparators) == 1:
        node = node.left
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _REGEX_GUARD_METHODS
    )


def _classify_if_control(test: ast.expr, source: str) -> _ControlMatch | None:
    """A Phase-C control label + operand for a recognized ``if``/``elif`` test, or None (kept unlabeled).

    Checks the three Phase-C ``if`` forms in order — environment gate (form 2), field-value condition
    (form 3), regex filter guard (form 4) — and returns the first match. A test matching none keeps its
    prior ``recognized`` flag (:func:`_is_bounded`) and carries no label (never mislabeled)."""
    env = _environment_gate(test, source)
    if env is not None:
        return _ControlMatch("environment gate", env)
    field = _field_condition(test)
    if field is not None:
        return _ControlMatch(f"when field {field}", field)
    if _is_regex_guard(test):
        return _ControlMatch("filter guard", None)
    return None


# --- row + source helpers ----------------------------------------------------


def _code_row(line_start: int, line_end: int, nesting: int) -> dict[str, Any]:
    return {"kind": "code", "line_start": line_start, "line_end": line_end, "nesting": nesting}


def _control_row(
    control: str,
    test_src: str | None,
    recognized: bool,
    line_start: int,
    line_end: int,
    nesting: int,
    label: str | None = None,
    operand: Any = None,
) -> dict[str, Any]:
    """A ``control`` row (ADR 0076 §3 + ADR 0089 Phase C ``label``/``operand``).

    ``label`` is a descriptive header for a recognized Phase-C idiom (``for each SEG segment`` /
    ``environment gate`` / ``when field X`` / ``filter guard``) — None for a plain/unrecognized control.
    ``operand`` is the captured, READ-ONLY display value (segment id / environment values / field path);
    None for a form with no single key operand. Both are additive contract fields (older consumers ignore
    them); the emitted ``kind`` stays ``control`` and the control structure stays read-only."""
    return {
        "kind": "control",
        "control": control,
        "test_src": test_src,
        "recognized": recognized,
        "label": label,
        "operand": operand,
        "line_start": line_start,
        "line_end": line_end,
        "nesting": nesting,
    }


def _src(node: ast.expr, source: str) -> str | None:
    """The verbatim source text of ``node`` (its exact slice), falling back to :func:`ast.unparse`."""
    seg = ast.get_source_segment(source, node)
    if seg is not None:
        return seg
    return ast.unparse(node)


def _find_keyword(lines: list[str], start: int, end: int, keyword: str) -> int | None:
    """The 1-based line number in ``[start, end]`` whose stripped text begins with ``keyword`` (or None).

    Used to locate an ``else:`` header, which has no dedicated AST node. ``lines`` is 0-indexed."""
    for lineno in range(start, end + 1):
        if 1 <= lineno <= len(lines) and lines[lineno - 1].strip().startswith(keyword):
            return lineno
    return None


def _merge_code_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Coalesce consecutive, line-contiguous ``code`` rows at the same nesting into one (in place, in order).

    Keeps the partition exact (contiguity preserved) while collapsing spurious blank-line/comment splits
    so a run of unrecognized lines renders as a single opaque step."""
    merged: list[dict[str, Any]] = []
    for row in rows:
        if (
            merged
            and row["kind"] == "code"
            and merged[-1]["kind"] == "code"
            and merged[-1]["nesting"] == row["nesting"]
            and merged[-1]["line_end"] + 1 == row["line_start"]
        ):
            merged[-1]["line_end"] = row["line_end"]
        else:
            merged.append(row)
    return merged


# =============================================================================
# lens rewrite — row-scoped param edits (ADR 0076 §2 phase 3 / §5)
# =============================================================================
#
# The load-bearing correctness property (ADR 0076 §5 + §6 gate 2 — **byte-stability**): a rewrite
# regenerates **only** the edited row's line range from the vocabulary call's template and splices it
# into that exact span; every other byte — untouched rows, blank lines, comments, indentation, line
# terminators — is byte-preserved. A **no-op** rewrite (an edit that changes no parameter) is therefore
# byte-identical to the input across the whole corpus, and a single-parameter edit changes only that
# row's line range. The template reuses each *unchanged* argument's **verbatim source segment**, so the
# reconstruction reproduces canonical (ruff-formatted) source exactly and never disturbs a bounded
# ``Message`` read or an expression it cannot round-trip.
#
# Only RECOGNIZED rows are editable — ``action`` / ``lookup`` / ``send`` rows whose parameters the
# grammar understands. ``code`` (unrecognized) and ``control`` (if/elif/else/for) rows are read-only:
# the lens refuses them rather than regenerate something it cannot reproduce faithfully. Like
# :func:`parse_source`, this is **static** — it uses only :mod:`ast` over the source text and **never
# imports or executes** the module (a module whose top level would raise still rewrites).

# The synthetic parameter name a ``send`` row exposes for its (single) destination — the Corepoint
# "to" field. It maps to the first positional argument of ``Send(destination, message)``.
_SEND_TO = "to"

_EDITABLE_KINDS = frozenset({"action", "lookup", "send"})

# v2 adds three STRUCTURAL ops (delete/insert/move) + multi-line param edits to v1's ``set_params``
# (ADR 0076 §2 phase 3 v2); ``paste_block`` adds the Steps block-paste (re-indenting a captured block into
# the anchor's suite, reusing the cross-suite move helpers). Anything else is refused (zero change).
_SUPPORTED_OPS = frozenset({"set_params", "delete_row", "insert_row", "move_row", "paste_block"})

# ruff's configured line length (pyproject ``[tool.ruff] line-length``). Two paths refuse rather than emit a
# line ruff would re-wrap, so the structural output stays ``ruff format --check``-clean (gate 3): an INSERTED
# call whose rendered line exceeds it (:func:`_apply_insert_row`), and a cross-suite move whose re-indent
# pushes a line past it at a DEEPER depth (:func:`_reindent_block`). The lens never wraps a line itself — it
# only refuses one it cannot emit as a single clean line.
_MAX_LINE_LENGTH = 100


def rewrite_module(path: str | Path, edit: dict[str, Any]) -> str:
    """Apply one row edit to the config module at ``path`` and return the rewritten source (ADR 0076 §5).

    Statically parses the file text with :mod:`ast` — the module is **never imported or executed**. The
    returned source is **byte-identical outside the edited row's line range** (gate 2). Raises
    :class:`LensParseError` if the file cannot be read/parsed, or :class:`LensRewriteError` if the edit
    is refused (unrecognized/absent row, unknown parameter, out-of-scope edit)."""
    p = Path(path)
    try:
        # Read raw bytes (NOT read_text, which universal-newline-translates \r\n → \n): byte-stability
        # (gate 2) requires the on-disk line terminators survive the round-trip untouched.
        source = p.read_bytes().decode("utf-8")
    except OSError as exc:
        raise LensParseError(f"{p}: cannot read ({exc})") from exc
    return rewrite_source(source, edit, module=p.as_posix())


def rewrite_source(source: str, edit: dict[str, Any], *, module: str = "<source>") -> str:
    """Apply one row edit to ``source`` text and return the rewritten source (see :func:`rewrite_module`).

    ``edit`` is the **edit spec** (ADR 0076 §5):

    ``{"line_start": int, "line_end": int, "op": "set_params", "params": {name: value, …},
    "handler": str?}``

    It identifies the row by its ``[line_start, line_end]`` span (the same range :func:`parse_source`
    emits — optionally disambiguated by ``handler``) and, for ``op="set_params"``, sets the named
    parameters. A parameter *value* is either a JSON scalar (rendered as a Python **literal** — only when
    the current argument is itself a literal) or ``{"expr": "<python source>"}`` (spliced **verbatim** as
    an expression, e.g. a bounded ``Message`` read). ``params={}`` is a valid **no-op** and returns the
    source byte-identically. Raises :class:`LensParseError` on a syntax error, :class:`LensRewriteError`
    on any refusal."""
    op = edit.get("op", "set_params")
    if op not in _SUPPORTED_OPS:
        raise LensRewriteError(f"unsupported op {op!r} (supported: {sorted(_SUPPORTED_OPS)})")
    line_start = edit.get("line_start")
    line_end = edit.get("line_end")
    if not isinstance(line_start, int) or not isinstance(line_end, int):
        raise LensRewriteError("edit must carry integer 'line_start' and 'line_end'")
    handler_filter = edit.get("handler")

    # Carry a leading UTF-8 BOM across the round-trip: strip it for parsing (it is invalid in a ``str``
    # given to :func:`ast.parse` and would shift every line-1 byte offset), then re-prepend it to the
    # spliced result. A no-op returns the original ``source`` (BOM included), so it stays byte-identical.
    bom = source.startswith("\ufeff")
    src = source.removeprefix("\ufeff")

    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        raise LensRewriteError(f"{module}: cannot parse ({exc.msg} at line {exc.lineno})") from exc

    # Stale-coordinate guard (F7): the row coords came from a prior *disk*-based ``lens parse``, but the
    # edit runs on the *live* buffer. When the caller carries the projected row's source text, verify it
    # still matches this buffer's row before splicing — otherwise a coincidental same-shape single-line
    # row (e.g. two ``return Send(...)``) could be edited in the wrong place.
    _check_expect_src(edit, src, line_start, line_end)

    # Locate the row via the SAME grammar the parser emits, so an edit can only target what parse shows.
    contracts = parse_source(src, module=module)
    row = _find_contract_row(contracts, line_start, line_end, handler_filter)
    if row is None:
        raise LensRewriteError(
            f"no editable row at lines {line_start}-{line_end}"
            + (f" in handler {handler_filter!r}" if handler_filter else "")
        )
    kind = row["kind"]
    # ``insert_row``/``move_row``/``paste_block`` use the target only as a POSITION (an anchor to insert/
    # paste before/after, or the block a move repositions), re-indenting across nesting as needed — so they
    # may target a read-only code/control row (moving a whole if/for block is exactly a control-row move).
    # ``set_params``/``delete_row`` MUTATE the row, so they refuse a non-editable kind — EXCEPT that
    # ``delete_row`` additionally accepts a whole ``if``/``for`` control BLOCK (its header row removes the
    # block, the ADR 0089 block-cut a Steps CUT reuses); ``set_params`` and code/elif/else rows stay refused.
    if op in ("set_params", "delete_row") and kind not in _EDITABLE_KINDS:
        if not (op == "delete_row" and kind == "control" and row.get("control") in ("if", "for")):
            raise LensRewriteError(
                f"row at lines {line_start}-{line_end} is a {kind!r} row — only action/lookup/send rows are "
                "editable (code and control rows are read-only, ADR 0076 §5)"
            )

    handler_node = _handler_def(tree, row["_handler"])
    if handler_node is None:
        raise LensRewriteError(
            f"internal: could not locate handler {row['_handler']!r} for lines {line_start}-{line_end}"
        )

    if op == "set_params":
        result = _apply_set_params(src, handler_node, row, edit, line_start, line_end)
    elif op == "delete_row":
        result = _apply_delete_row(src, handler_node, line_start, line_end)
    elif op == "insert_row":
        result = _apply_insert_row(src, tree, handler_node, edit, line_start, line_end)
    elif op == "paste_block":
        result = _apply_paste_block(src, line_start, line_end, edit)
    else:  # move_row
        _check_to_suite(edit, contracts, row["_handler"])
        result = _apply_move_row(src, handler_node, edit, line_start, line_end)

    # Safety gate (gate 3): a real change must re-parse to valid Python, else refuse with zero change. A
    # no-op returns ``src`` unchanged (already parsed above), so it skips the re-parse and stays identical.
    if result != src:
        _assert_reparses(result, module)
    return ("\ufeff" + result) if bom else result


def _check_expect_src(edit: dict[str, Any], src: str, line_start: int, line_end: int) -> None:
    """Refuse a stale-coordinate edit (F7): if ``expect_src`` is present it must match the buffer's row.

    ``expect_src`` is the row's PROJECTION-TIME source (the row as the user saw it). We recompute the live
    buffer's ``[line_start, line_end]`` slice with the engine newline model (:func:`_physical_lines`) and
    refuse when they differ, so a coincidental same-shape row, or a target shifted by an unsaved edit, is
    never mutated in the wrong place. Applies uniformly across every op (structural ops shift line counts,
    so a stale target is especially unsafe)."""
    expect_src = edit.get("expect_src")
    if expect_src is None:
        return
    if not isinstance(expect_src, str):
        raise LensRewriteError("edit 'expect_src' must be a string")
    actual = "\n".join(_physical_lines(src)[line_start - 1 : line_end])
    if actual != expect_src:
        raise LensRewriteError(
            "the row's source no longer matches the editor buffer (stale coordinates) - "
            "re-project the Steps view and retry"
        )


def _check_to_suite(
    edit: dict[str, Any], contracts: list[dict[str, Any]], handler_name: str
) -> None:
    """Refuse a stale/mis-targeted cross-suite drop (the destination analog of ``expect_src``).

    Optional and backward-compatible: when the client carries ``to_suite`` (the landing suite id it intended
    — a header line number as a string, or the def line for top level) we re-derive the DESTINATION anchor's
    real suite from the SAME ``parse_source`` contract the client saw (located by its exact ``[to_line_start,
    to_line_end]`` span) and refuse if they disagree — so a drop whose scope shifted under an unsaved edit is
    rejected, never mis-applied. Absent ``to_suite`` skips the check entirely (existing callers unaffected)."""
    to_suite = edit.get("to_suite")
    if to_suite is None:
        return
    if not isinstance(to_suite, str):
        raise LensRewriteError("move_row 'to_suite' must be a string")
    to_ls = edit.get("to_line_start")
    to_le = edit.get("to_line_end")
    if not isinstance(to_ls, int) or not isinstance(to_le, int):
        raise LensRewriteError(
            "move_row 'to_suite' requires integer 'to_line_start' and 'to_line_end'"
        )
    dest_row = _find_contract_row(contracts, to_ls, to_le, handler_name)
    if dest_row is None or dest_row.get("suite") != to_suite:
        raise LensRewriteError(
            "the drop target's scope changed (stale destination) - re-project the Steps view and retry"
        )


def _assert_reparses(result: str, module: str) -> None:
    """Refuse (with zero change) a rewrite whose output is not valid Python — the VALIDITY half of gate 3.

    A last-line defense: every op is engineered to preserve validity, but re-parsing the result and
    refusing on a :class:`SyntaxError` guarantees the lens never writes broken Python into a user's file.
    This is ``ast.parse`` ONLY — it does not run ``ruff format --check``. The complementary format-
    cleanliness half of gate 3 is enforced per-op *before* emission (each op only ever produces canonical
    text): :func:`_apply_insert_row` refuses a rendered line over the column limit, and the reindent path
    refuses a depth change that would over-run (:func:`_reindent_block`) or collapse
    (:func:`_has_collapsible_wrapped_stmt`) a line — so the output ``ruff format`` would produce is the
    output the lens already wrote. Static-only: this parses (it never imports/executes) the result."""
    try:
        ast.parse(result)
    except SyntaxError as exc:
        raise LensRewriteError(
            f"{module}: the rewrite would produce invalid Python ({exc.msg} at line {exc.lineno}) - "
            "refused (no change made)"
        ) from exc


def _apply_set_params(
    src: str,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    row: dict[str, Any],
    edit: dict[str, Any],
    line_start: int,
    line_end: int,
) -> str:
    """v1 + v2 ``set_params``: splice edited argument values in place; return the bom-stripped result.

    v2 lifts v1's whole-call single-line restriction: a **single-line literal argument of a multi-line
    call** is now editable (:func:`_splice_slots` enforces the per-argument single-line invariant so the
    file's line count is preserved). A no-op (``params={}`` / an uneditable-but-unchanged shape) returns
    ``src`` unchanged (byte-identical round-trip)."""
    params = edit.get("params", {})
    if not isinstance(params, dict):
        raise LensRewriteError("edit 'params' must be an object of {name: value}")
    stmt = _find_stmt(handler_node.body, line_start, line_end)
    if stmt is None:
        raise LensRewriteError(
            f"internal: could not locate the statement at lines {line_start}-{line_end}"
        )
    slots = _editable_slots(stmt, row["kind"])
    if slots is None:
        # A recognized-but-not-single-call shape (e.g. a list-of-Sends return). Editing is out of scope,
        # but a no-op must still round-trip byte-identically.
        if params:
            raise LensRewriteError(
                f"row at lines {line_start}-{line_end} is not a single editable call "
                "(list-of-sends / dynamic return editing is out of scope)"
            )
        return src
    return _splice_slots(src, slots, params)


# --- rewrite helpers ---------------------------------------------------------


def _find_contract_row(
    contracts: list[dict[str, Any]], line_start: int, line_end: int, handler_filter: str | None
) -> dict[str, Any] | None:
    """The contract row whose span is exactly ``[line_start, line_end]`` (annotated with ``_handler``)."""
    for contract in contracts:
        if handler_filter is not None and contract["handler"] != handler_filter:
            continue
        for row in contract["rows"]:
            if row["line_start"] == line_start and row["line_end"] == line_end:
                return {**row, "_handler": contract["handler"]}
    return None


def _handler_def(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """The ``@handler`` FunctionDef registered as ``name`` (or None)."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _handler_name(node) == name:
            return node
    return None


def _find_stmt(stmts: list[ast.stmt], line_start: int, line_end: int) -> ast.stmt | None:
    """The statement whose ``[lineno, end_lineno]`` is exactly ``[line_start, line_end]`` (recursing
    into ``if``/``for`` bodies), or None."""
    for s in stmts:
        if s.lineno == line_start and (s.end_lineno or s.lineno) == line_end:
            return s
        # Recurse into control-block bodies so a nested action/send row is reachable.
        if isinstance(s, ast.If | ast.For | ast.AsyncFor):
            found = _find_stmt(s.body, line_start, line_end)
            if found is not None:
                return found
            if isinstance(s, ast.If):
                found = _find_stmt(s.orelse, line_start, line_end)
                if found is not None:
                    return found
    return None


def _editable_slots(stmt: ast.stmt, kind: str) -> dict[str, ast.expr] | None:
    """Map each editable parameter of an ``action``/``lookup``/``send`` row to the arg node an edit splices.

    Returns None for a recognized row that is not a single editable call (a list-of-``Send`` return),
    which the caller round-trips unchanged for a no-op and refuses for a real edit. The mapping is the
    SAME grammar the parser emits: for a **native** ``msg.set(...)`` (ADR 0089 Phase A) it consults
    :func:`_recognize_native_method` so the splice targets the native method-call args (``path``=arg0,
    ``value``=arg1 — no leading ``msg`` positional; ``copy_field``'s ``src`` is the inner
    ``msg.field(src)`` arg), and read-only keywords (``occurrence=``) are deliberately absent so a splice
    never touches them. For a **wrapper** call (``set_field(msg, …)``) the leading ``msg`` positional is
    dropped and each named positional + keyword value becomes a slot, exactly as before."""
    if kind == "send":
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            send = stmt.value
            return {_SEND_TO: send.args[0]} if send.args else {}
        return None
    # action / lookup — a bare call, or an assignment whose value is the call.
    call: ast.Call | None = None
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        call = stmt.value
    elif isinstance(stmt, ast.Assign | ast.AnnAssign) and isinstance(stmt.value, ast.Call):
        call = stmt.value
    if call is None:
        return None
    # Native ``msg.set(...)`` / ``msg.delete_segments(...)`` (a bare mutating statement): the recognizer
    # is the single source of truth for the editable arg nodes (never the read-only ``occurrence=`` kwarg).
    if isinstance(stmt, ast.Expr):
        native = _recognize_native_method(call)
        if native is not None:
            return dict(native.slots)
    name = _callee_name(call.func)
    param_names = _ACTION_PARAMS.get(name or "") or _LOOKUP_PARAMS.get(name or "")
    if param_names is None:
        return None
    slots: dict[str, ast.expr] = {}
    for i, arg in enumerate(call.args):
        if isinstance(arg, ast.Starred) or i >= len(param_names):
            continue  # a ``*args`` splat / an unnamed extra positional is not an editable parameter
        pname = param_names[i]
        if pname != "msg":  # the injected receiver is never editable
            slots[pname] = arg
    for kw in call.keywords:
        if kw.arg is not None:  # ``**kwargs`` (arg is None) is not an editable named parameter
            slots[kw.arg] = kw.value
    return slots


def _splice_slots(
    source: str,
    slots: dict[str, ast.expr],
    params: dict[str, Any],
) -> str:
    """Replace ONLY each edited parameter's exact byte-span (its arg node in ``slots``) with the newly-
    rendered value; every other byte — the callee, parens, commas, unedited args, a read-only
    ``occurrence=`` kwarg, a trailing comment, the indent/``return ``/``row =`` prefix — is preserved
    verbatim (gate 2).

    ``slots`` maps each editable parameter name to the exact :class:`ast.expr` node whose bytes an edit
    replaces (resolved by :func:`_editable_slots` for both the wrapper and native forms). Works entirely
    in **UTF-8 byte space**: the AST's ``col_offset``/``end_col_offset`` are *byte* offsets into a line, so
    mixing them with ``str`` indexing mis-slices whenever a non-ASCII char precedes the arg and eats bytes
    (F1). And because it never rebuilds the argument list, a no-op replaces nothing (byte-identical) and a
    single-arg edit touches only that arg's bytes — no separator canonicalization on non-ruff-formatted
    source (F3), and a co-located ``occurrence=`` kwarg (not in ``slots``) survives untouched."""
    source_bytes = source.encode("utf-8")
    line_starts = _line_byte_starts(source_bytes)

    def _byte_span(node: ast.expr) -> tuple[int, int]:
        """The absolute ``[start, end)`` byte offsets of ``node`` in ``source_bytes`` (byte ``col_offset``
        composed with the physical line's byte start)."""
        end_lineno = node.end_lineno or node.lineno
        end_col = node.end_col_offset if node.end_col_offset is not None else node.col_offset
        return (
            line_starts[node.lineno - 1] + node.col_offset,
            line_starts[end_lineno - 1] + end_col,
        )

    def _refuse_multiline_arg(node: ast.expr, pname: str) -> None:
        """Refuse editing an argument that itself spans multiple physical lines.

        v2 edits a single-line argument even when the whole CALL spans several lines — but the *argument
        value being replaced* must be single-line, else swapping it for a single-line value would change
        the file's line count (breaking the IDE's row-coordinate alignment). A multi-line literal (a
        triple-quoted string) is therefore refused; edit it as text."""
        if (node.end_lineno or node.lineno) != node.lineno:
            raise LensRewriteError(
                f"parameter {pname!r}: the current argument spans multiple physical lines — editing it "
                "would change the file's line count; edit it as text"
            )

    edits: list[tuple[int, int, bytes]] = []  # (start_byte, end_byte, replacement) — disjoint spans
    consumed: set[str] = set()
    for pname, node in slots.items():
        if pname not in params:
            continue
        _refuse_multiline_arg(node, pname)
        rendered = _render_new_value(params[pname], isinstance(node, ast.Constant), pname)
        start, end = _byte_span(
            node
        )  # for a keyword slot this is the value node, never the ``name=``
        edits.append((start, end, rendered.encode("utf-8")))
        consumed.add(pname)

    unknown = set(params) - consumed
    if unknown:
        raise LensRewriteError(
            f"unknown or absent parameter(s) {sorted(unknown)!r} for this call "
            "(the lens edits only parameters the call already passes)"
        )

    # Apply the disjoint span replacements right-to-left so earlier byte offsets stay valid.
    for start, end, replacement in sorted(edits, key=lambda e: e[0], reverse=True):
        source_bytes = source_bytes[:start] + replacement + source_bytes[end:]
    return source_bytes.decode("utf-8")


def _render_new_value(value: Any, original_is_literal: bool, pname: str) -> str:
    """Render an edit's new parameter value to Python source text.

    A JSON scalar renders to a Python **literal** — but only when the argument it replaces was itself a
    literal, so the lens never silently turns an expression slot into a literal (or the reverse). An
    ``{"expr": "<source>"}`` object splices verbatim (validated to parse as a single expression), which
    is how a bounded ``Message`` read (``msg["PID-5"]``) or any non-literal is edited."""
    if isinstance(value, dict):
        expr = value.get("expr")
        if set(value) != {"expr"} or not isinstance(expr, str):
            raise LensRewriteError(
                f"parameter {pname!r}: an object value must be {{'expr': <source>}}"
            )
        rendered = _validated_expr(expr, pname)
    elif not original_is_literal:
        raise LensRewriteError(
            f"parameter {pname!r} is currently an expression, not a literal — supply "
            "{'expr': <source>} to change it (the lens will not guess a literal for an expression slot)"
        )
    else:
        rendered = _render_literal(value, pname)
    # F4: the rewritten value must stay on ONE physical line. A value carrying a real newline (only a
    # hand-crafted ``{"expr": ...}`` can — scalar ``json.dumps`` escapes ``\n``) would splice extra lines
    # and break the line-count-preserving invariant the IDE relies on to keep row coordinates aligned.
    if "\n" in rendered or "\r" in rendered:
        raise LensRewriteError(
            f"parameter {pname!r}: the rewritten value spans multiple lines — a row edit must stay on a "
            "single line (a line break would change the file's line count)"
        )
    return rendered


def _render_literal(value: Any, pname: str) -> str:
    """Render a JSON **scalar** as a ruff-canonical Python literal (double-quoted str).

    Only reached for a param whose current argument is a literal scalar (``ast.Constant``), so a list
    value never arrives here (a list-valued arg is an ``ast.List`` — an expression slot refused upstream
    in :func:`_render_new_value`); a list therefore falls through to the type refusal below."""
    if value is None:
        return "None"
    if isinstance(value, bool):  # before int — bool is an int subclass
        return "True" if value else "False"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        # ``ensure_ascii=False`` is load-bearing: the DEFAULT ``ensure_ascii=True`` \u-escapes every
        # non-ASCII char, which (a) for an ASTRAL (non-BMP) char like U+1F6F0 emits a UTF-16 SURROGATE
        # PAIR (``🛰``) that Python re-parses as two lone surrogates — a corrupted value that
        # then raises UnicodeEncodeError when the engine encodes the outbound — and (b) for a BMP char
        # emits a ``\uXXXX`` escape that diverges from ruff's canonical raw-char form (gate 3). Emitting
        # the raw UTF-8 char is value-preserving and ruff-canonical; control chars < U+0020 stay escaped.
        return json.dumps(value, ensure_ascii=False)
    raise LensRewriteError(
        f"parameter {pname!r}: cannot render value of type {type(value).__name__} as a literal"
    )


def _validated_expr(expr: str, pname: str) -> str:
    """Validate an ``{"expr": <source>}`` splice value and return it verbatim.

    Two checks the syntax-only re-parse gate (:func:`_assert_reparses`) cannot make on its own, because
    both re-parse cleanly yet corrupt the call:

    * The expr must parse as a single **standalone** Python expression.
    * It must read as **exactly one call argument** when spliced into the arg slot. A bare tuple / top-
      level comma (``1, 2``) would inject extra positional args (``set_field(msg, "P", 1, 2)``), and a
      keyword (``a=1``) or ``*`` splat would change the call's shape — an arity break mypy-strict rejects
      (gate 3) but the re-parse gate misses. We probe the expr in a real argument position to catch it.

    A parenthesized single tuple (``(1, 2)``) IS one argument and is accepted."""
    try:
        ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise LensRewriteError(
            f"parameter {pname!r}: expression {expr!r} is not a valid Python expression ({exc.msg})"
        ) from exc
    try:
        probe: ast.expr | None = ast.parse(f"_f({expr})", mode="eval").body
    except SyntaxError:
        probe = None
    if (
        not isinstance(probe, ast.Call)
        or len(probe.args) != 1
        or bool(probe.keywords)
        or isinstance(probe.args[0], ast.Starred)
    ):
        raise LensRewriteError(
            f"parameter {pname!r}: expression {expr!r} must be a single argument expression — a bare "
            "tuple / extra comma (or a keyword/`*` splat) would inject additional call arguments"
        )
    return expr


# --- structural rewrites: delete / insert / move (ADR 0076 §2 phase 3 v2) ----
#
# All three operate on the source split into physical lines WITH their terminators preserved
# (:func:`_physical_lines_keepends`, whose ``"".join`` is the identity), so every untouched line is
# byte-preserved by construction (gate 2) and the newline style (LF/CRLF) survives. A structural result
# is re-parsed by :func:`_assert_reparses` before it is returned, so an op can never write invalid Python.


def _locate_stmt(
    stmts: list[ast.stmt], line_start: int, line_end: int
) -> tuple[list[ast.stmt], int] | None:
    """The (containing suite list, index) of the statement whose span is exactly ``[line_start, line_end]``.

    Recurses into ``if``/``for`` bodies and their ``orelse`` suites so a nested action/send row is
    reachable and its *sibling* statements (the suite it lives in) are available for delete/move. Returns
    the actual AST suite list (a reference into ``node.body``/``node.orelse``), so ``len(suite)`` is the
    real statement count (comments and blank lines are not statements)."""
    for idx, s in enumerate(stmts):
        if s.lineno == line_start and (s.end_lineno or s.lineno) == line_end:
            return stmts, idx
        if isinstance(s, ast.If | ast.For | ast.AsyncFor):
            found = _locate_stmt(s.body, line_start, line_end)
            if found is not None:
                return found
            found = _locate_stmt(s.orelse, line_start, line_end)
            if found is not None:
                return found
    return None


def _locate_stmt_by_header(
    stmts: list[ast.stmt], header_line: int
) -> tuple[list[ast.stmt], int] | None:
    """The (containing suite list, index) of the statement whose HEADER line is ``header_line``.

    Matches by ``s.lineno`` alone — unlike :func:`_locate_stmt` (exact span), which cannot resolve a
    control row whose projected span is its header line only (``if …:``) yet whose statement spans the
    whole ``if``/``for`` block. Locating by header line lets a move reorder the ENTIRE compound statement
    (header + body/else) as one unit. Recurses into if/for bodies + their orelse so a nested statement is
    reachable. A ``header_line`` that is not a statement start (a bare ``else:``, a comment/blank) has no
    matching statement and returns None."""
    for idx, s in enumerate(stmts):
        if s.lineno == header_line:
            return stmts, idx
        if isinstance(s, ast.If | ast.For | ast.AsyncFor):
            found = _locate_stmt_by_header(s.body, header_line)
            if found is not None:
                return found
            found = _locate_stmt_by_header(s.orelse, header_line)
            if found is not None:
                return found
    return None


def _apply_delete_row(
    src: str,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    line_start: int,
    line_end: int,
) -> str:
    """Remove the target statement's full physical line span; every other line is byte-preserved (gate 2).

    For a LEAF (action/lookup/send) row the span IS ``[line_start, line_end]``, so this is byte-identical to
    removing that row. For an ``if``/``for`` control HEADER row (projected span = the header line only) the
    delete is broadened to the WHOLE compound statement ``[header .. end_lineno]`` — the ADR 0089 block-cut a
    Steps CUT of a whole block reuses (located by header line when :func:`_locate_stmt`'s exact-span match
    misses). Refuses the SOLE statement of a suite (deleting it would leave an empty ``if``/``for``/def body,
    which is invalid Python). Blank lines and comments adjacent to the row are separate rows, preserved
    verbatim (predictable: deleting a step removes exactly that step's — or that block's — lines)."""
    located = _locate_stmt(handler_node.body, line_start, line_end)
    if located is None:
        # A control HEADER row's projected span is its header line only, so the exact-span match above
        # misses; locate the compound statement by its header line and remove the whole block.
        located = _locate_stmt_by_header(handler_node.body, line_start)
    if located is None:
        raise LensRewriteError(
            f"internal: could not locate the statement to delete at lines {line_start}-{line_end}"
        )
    suite, idx = located
    if len(suite) == 1:
        raise LensRewriteError(
            f"row at lines {line_start}-{line_end} is the only statement in its block — deleting it would "
            "leave an empty suite (invalid Python); edit it as text"
        )
    stmt = suite[idx]
    lines = _physical_lines_keepends(src)
    del lines[stmt.lineno - 1 : (stmt.end_lineno or stmt.lineno)]
    return "".join(lines)


def _paste_anchor_indent(lines: list[str], line_start: int, line_end: int, position: str) -> str:
    """The suite indent an insert/paste adopts at its anchor — the anchor row's first non-blank line's
    leading whitespace, scanned from the side nearest the insertion point (ADR 0076 §5 v2).

    A ``code`` row can span a leading/trailing BLANK line + a comment; indenting to the blank line's
    0-indent would dedent the new step/block out of its suite (an "unexpected indent" on the following line,
    or a reparse refusal). Scanning from the insertion side for the first non-blank line finds the suite's
    real indent; a fully-blank row (defensive — a real row always has a non-blank line) falls back to
    ``line_start``. Shared by :func:`_apply_insert_row` and :func:`_apply_paste_block` so the two derive the
    landing indent identically."""
    scan = (
        range(line_end, line_start - 1, -1)
        if position == "after"
        else range(line_start, line_end + 1)
    )
    ref = next(
        (lines[ln - 1] for ln in scan if 0 <= ln - 1 < len(lines) and lines[ln - 1].strip()),
        lines[line_start - 1] if 0 <= line_start - 1 < len(lines) else "",
    )
    return _leading_ws(ref)


def _module_bound_names(tree: ast.Module) -> tuple[set[str], bool]:
    """Names bound at module scope (imports, assignments, def/class) + whether a wildcard import exists.

    Used by :func:`_name_in_scope` to decide whether an inserted vocabulary call would resolve. A
    ``from m import *`` binds an unknown set, so the second element is ``True`` and the caller treats any
    name as in scope (permissive — never a false refusal)."""
    names: set[str] = set()
    star = False
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    star = True
                else:
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                names.update(sub.id for sub in ast.walk(target) if isinstance(sub, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names, star


def _name_in_scope(tree: ast.Module, name: str) -> bool:
    """Whether a BARE ``name(...)`` call would resolve at module scope (an import, def, or a wildcard).

    Note it is deliberately the *bare* name: the lens inserts ``set_field(...)``, never ``mf.set_field``,
    so a module that only ``import messagefoundry`` (aliased or not) does NOT put ``set_field`` in scope
    and the insert is refused — inserting a bare undefined name would be an F821 ``ruff check`` failure."""
    names, star = _module_bound_names(tree)
    return star or name in names


def _apply_insert_row(
    src: str,
    module_tree: ast.Module,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    edit: dict[str, Any],
    line_start: int,
    line_end: int,
) -> str:
    """Insert a NEW recognized action before/after the target row, at the target's indentation.

    The three actions the ADR 0089 Phase A recognizer reads back (``set_field``/``copy_field``/
    ``delete_segment``) are emitted in their NATIVE Message-API form (``msg.set`` / ``msg.delete_segments``
    via :func:`_render_native_insert_call`) — no vocabulary import needed, and the inserted line round-
    trips to the same editable row. Every OTHER action/lookup is rendered as its wrapper call from the
    ``actions.py`` signature + ``params``; every existing line is byte-preserved (gate 2). Refuses an
    unknown vocabulary name, a missing required parameter (wrapper actions), a rendered line that would
    exceed ruff's line length, or — for a WRAPPER action — a name the module does not import (which would
    emit an F821 undefined name) — so the output stays ``ruff check`` / ``ruff format --check``-clean
    (gate 3). The target may be a read-only code/control row: an insert uses it only as a position."""
    position = edit.get("position", "after")
    if position not in ("before", "after"):
        raise LensRewriteError("insert_row 'position' must be 'before' or 'after'")
    action = edit.get("action")
    if not isinstance(action, str):
        raise LensRewriteError(
            "insert_row requires a string 'action' naming the vocabulary call to insert"
        )
    params = edit.get("params", {})
    if not isinstance(params, dict):
        raise LensRewriteError("insert_row 'params' must be an object of {name: value}")
    if action in _NATIVE_INSERT_ACTIONS:
        # ADR 0089: the three actions the Phase A recognizer reads back are inserted in their NATIVE
        # Message-API form (``msg.set`` / ``msg.delete_segments``). That references only ``msg`` — no
        # vocabulary import — so it matches a native estate AND skips the import-scope check below
        # (there is no bare wrapper name to resolve). The inserted line round-trips: re-parsing it
        # recognizes the SAME editable action row.
        rendered = _render_native_insert_call(action, params, edit.get("assign_to"))
    else:
        # Render first — an unknown vocabulary name / missing param is refused with that (more specific)
        # message before the import-scope check below.
        rendered = _render_insert_call(action, params, edit.get("assign_to"))
        # gate 3: refuse inserting a vocabulary call the module does not import — a BARE ``set_field(...)``
        # in a module that never imported ``set_field`` is an F821 undefined name (``ruff check`` failure)
        # reachable through the IDE's "add step" affordance. Import lines are out of the row-scoped
        # splice's scope by design (§5), so the honest move is to refuse rather than emit code that won't
        # lint.
        if not _name_in_scope(module_tree, action):
            raise LensRewriteError(
                f"insert_row: {action!r} is not imported in this module — inserting it would raise an "
                f"F821 undefined name (`ruff check` failure). Add `from messagefoundry import {action}` "
                "first, then add the step."
            )

    lines = _physical_lines_keepends(src)
    # Indent the inserted line to match the anchor's CODE, not a leading/trailing BLANK line within the row
    # (a ``code`` row can span a blank line + a comment). :func:`_paste_anchor_indent` scans the anchor's own
    # physical lines from the side nearest the insertion point for the first non-blank line's indent — the
    # SAME anchor-indent rule :func:`_apply_paste_block` reuses (so a new step joins its suite, never dedents
    # out of it and produces an "unexpected indent" on the following line).
    indent = _paste_anchor_indent(lines, line_start, line_end, position)
    term = _dominant_terminator(src)
    physical = indent + rendered
    if len(physical) > _MAX_LINE_LENGTH:
        raise LensRewriteError(
            f"the inserted call would be {len(physical)} columns — over the {_MAX_LINE_LENGTH}-column "
            "limit (ruff would wrap it); add it as text"
        )
    new_line = physical + term
    insert_idx = (line_start - 1) if position == "before" else line_end
    if insert_idx >= len(lines):
        # Appending past the last physical line: if the current last line has no terminator (a file with
        # no trailing newline), terminate it first so the two lines do not glue together.
        if lines and _line_terminator(lines[-1]) == "":
            lines[-1] = lines[-1] + term
        lines.append(new_line)
    else:
        lines.insert(insert_idx, new_line)
    return "".join(lines)


def _apply_move_row(
    src: str,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    edit: dict[str, Any],
    line_start: int,
    line_end: int,
) -> str:
    """Reorder a whole statement — an action/lookup/send row OR an entire ``if``/``for`` block — within
    its own suite (cut + reinsert), byte-preserving every non-moved line (gate 2).

    The row is located by its HEADER line (``line_start``), so a *control* row (whose projected span is
    the header only) moves its ENTIRE block (header + body/else) as one unit. Two forms:

    * drag-and-drop (``to_line_start`` + ``to_position``): reinsert before/after an arbitrary anchor,
      including one in a DIFFERENT suite — the moved block adopts the anchor's suite + indent, re-indenting
      across nesting (see :func:`_move_to_target`);
    * ``direction`` ``"up"``/``"down"``: reinsert before the previous / after the next sibling statement.

    The DRAG path may cross a suite boundary (the headline cross-suite move); the ``direction`` ↑/↓ path
    never does — a statement can't step out of its if/for body via the arrows (the first/last guards here).
    Comments/blank lines between siblings stay at their physical position (they are not part of any
    statement's span), so the reorder is comment-tolerant. Validity is backstopped by the re-parse gate
    (:func:`_assert_reparses`); ruff-format-cleanliness (gate 3) across a depth change is enforced by the
    reindent guards — a per-line length refusal (:func:`_reindent_block`, the deeper-overflow case) and a
    collapsible-wrapped-call refusal (:func:`_move_to_target`, the shallower-collapse case)."""
    located = _locate_stmt_by_header(handler_node.body, line_start)
    if located is None:
        raise LensRewriteError(
            f"internal: could not locate the statement to move at line {line_start}"
        )
    suite, idx = located
    if edit.get("to_line_start") is not None:
        # Drag-and-drop: reinsert at an arbitrary same-suite sibling position. Without a ``to_line_start``
        # the ``direction`` adjacent-sibling reorder below runs (backward-compatible with the ↑/↓ buttons).
        return _move_to_target(src, handler_node, edit, suite, idx)
    direction = edit.get("direction")
    if direction == "up":
        if idx == 0:
            raise LensRewriteError("row is already first among its siblings — cannot move up")
        return _reorder_stmt(src, suite[idx], suite[idx - 1], "before")
    if direction == "down":
        if idx == len(suite) - 1:
            raise LensRewriteError("row is already last among its siblings — cannot move down")
        return _reorder_stmt(src, suite[idx], suite[idx + 1], "after")
    raise LensRewriteError("move_row 'direction' must be 'up' or 'down'")


def _reorder_stmt(
    src: str,
    moved: ast.stmt,
    dest: ast.stmt,
    position: str,
    reindent: tuple[str, str, set[int]] | None = None,
) -> str:
    """Cut ``moved``'s full physical line span and reinsert it ``"before"``/``"after"`` ``dest``'s span.

    Every line outside the moved span keeps its exact bytes (terminators included) — the block simply
    changes position. With ``reindent=None`` (the same-suite reorder / ↑↓ path / an equal-depth cross-suite
    move) the MOVED block is byte-identical too, so the whole result is byte-stable. ``reindent`` (a
    ``(src_prefix, dst_prefix, frozen_rel)`` tuple) is set only for a CROSS-suite move to a different depth:
    the moved block's non-frozen code lines are prefix-shifted from ``src_prefix`` to ``dst_prefix`` (see
    :func:`_reindent_block`) so the block joins the destination's suite at its indent — the ONLY lines whose
    bytes change. The line COUNT is unchanged either way, so the splice math below is identical.

    The trailing-newline fix-up terminates the moved block's last line when it was the file-final line (it no
    longer is after the move) and re-terminates a formerly-final destination line, both yielding a ruff-clean
    trailing newline."""
    lines = _physical_lines_keepends(src)
    ms, me = moved.lineno, moved.end_lineno or moved.lineno
    ds, de = dest.lineno, dest.end_lineno or dest.lineno
    block = lines[ms - 1 : me]
    if reindent is not None:
        src_prefix, dst_prefix, frozen_rel = reindent
        block = _reindent_block(block, src_prefix, dst_prefix, frozen_rel)
    if block and _line_terminator(block[-1]) == "":
        block = block[:-1] + [block[-1] + _dominant_terminator(src)]
    n = me - ms + 1
    del lines[ms - 1 : me]
    # After deleting the moved block [ms, me], any ORIGINAL line > me shifts up by n. Compute the insert
    # index directly against the post-deletion list, per endpoint, so BOTH the disjoint-sibling case (the
    # ↑/↓ + same-suite reorder) AND the cross-suite "move a body statement OUT, anchored on its enclosing
    # control header" case (where the moved line lies INSIDE the dest block's span, so de — not ds — is what
    # shifts) are correct. "before dest" → before original line ds; "after dest" → after original line de.
    if position == "before":
        insert_idx = (ds - 1) - (n if me < ds else 0)
    else:
        insert_idx = de - (n if de >= me else 0)
    lines[insert_idx:insert_idx] = block
    if lines and _line_terminator(lines[-1]) == "":  # keep a trailing newline (ruff-clean)
        lines[-1] = lines[-1] + _dominant_terminator(src)
    return "".join(lines)


def _frozen_relative_lines(moved: ast.stmt) -> set[int]:
    """Block-relative indices of the moved block's lines that must NOT be re-indented (string interiors).

    A multi-line ``str``/``bytes`` literal or f-string carries its value in its interior lines; shifting
    their leading whitespace would corrupt the value (e.g. a triple-quoted SQL literal inside a moved
    ``db_lookup``). We freeze the CONTINUATION lines ``[node.lineno + 1 .. node.end_lineno]`` — the OPENING
    line ``node.lineno`` is real code indentation and is re-based normally. Indices are relative to the
    block start (``abs_line - moved.lineno``), matching the block list :func:`_reindent_block` walks."""
    frozen: set[int] = set()
    for node in ast.walk(moved):
        if not isinstance(node, ast.Constant | ast.JoinedStr):
            continue
        # A str/bytes literal (an f-string is a JoinedStr and always textual). A numeric/None Constant has no
        # protectable interior, so skip it — only its own (single) line ever carries code indentation.
        if isinstance(node, ast.Constant) and not isinstance(node.value, str | bytes):
            continue
        end = node.end_lineno
        if end is None or end <= node.lineno:
            continue  # single-line literal: its one line is real code indentation, never frozen
        for abs_line in range(node.lineno + 1, end + 1):
            frozen.add(abs_line - moved.lineno)
    return frozen


# Compound (block-header) statements are multi-line by STRUCTURE — a uniform indent shift preserves them
# (ruff never collapses a body onto its header), so they are exempt from the collapse guard below. Only
# SIMPLE statements wrap onto continuation lines via brackets, where a depth change can flip ruff's
# one-line-vs-wrapped decision.
_COMPOUND_STMT_TYPES: tuple[type[ast.stmt], ...] = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.TryStar,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Match,
)


def _has_collapsible_wrapped_stmt(moved: ast.stmt) -> bool:
    """Whether ``moved`` contains a SIMPLE statement ruff wrapped across lines via *brackets* (a collapse
    hazard when moving to a shallower depth).

    A bracket-wrapped call is multi-line only because its one-line form did not fit ``ruff``'s line length
    at its CURRENT indent. Move it to a SHALLOWER depth and the one-line form may fit — ruff would COLLAPSE
    it to a single line, diverging from our byte-preserved (still-wrapped) output, so the result would not
    be ``ruff format --check``-clean (gate 3). A pure line-length check cannot see this: every wrapped line
    is short. We therefore REFUSE such a shallower move (zero change; "edit it as text").

    A statement that is multi-line only because of a triple-quoted string / f-string interior is NOT a
    hazard — ruff keeps it multi-line at any depth — so a continuation line that is a frozen string interior
    is excluded (matching :func:`_frozen_relative_lines`). Compound block statements are exempt
    (:data:`_COMPOUND_STMT_TYPES`); we walk their nested simple statements, so a wrapped call INSIDE a moved
    ``if``/``for`` block is caught too."""
    frozen_abs = {moved.lineno + rel for rel in _frozen_relative_lines(moved)}
    for node in ast.walk(moved):
        if not isinstance(node, ast.stmt) or isinstance(node, _COMPOUND_STMT_TYPES):
            continue
        end = node.end_lineno
        if end is None or end <= node.lineno:
            continue  # a single-line simple statement — a depth change never rewraps it
        # A multi-line simple statement. If every continuation line is a frozen multi-line-string interior
        # the wrapping is string-FORCED (safe); any OTHER continuation line means it is bracket-wrapped and
        # ruff's wrap decision depends on the collapsed width at the new (shallower) depth.
        if set(range(node.lineno + 1, end + 1)) - frozen_abs:
            return True
    return False


def _reindent_block(
    block: list[str], src_prefix: str, dst_prefix: str, frozen_rel: set[int]
) -> list[str]:
    """Re-base a moved block's indentation from ``src_prefix`` to ``dst_prefix`` (cross-suite depth change).

    Copies real leading-whitespace STRINGS (tab/space/CRLF-correct by construction, constraint 6). Per line
    (``i`` = block index, ``term`` = its terminator, ``content`` = the rest):

    * ``i in frozen_rel`` → emitted byte-identical (a string/f-string interior, never shifted);
    * blank (whitespace-only ``content``) → ``"" + term`` (drop trailing whitespace, keep the position — the
      shift would otherwise refuse it below, and a blank has no code indentation to re-base);
    * ``content`` starts with ``src_prefix`` → ``dst_prefix + content[len(src_prefix):] + term`` — this moves
      a whole ``if``/``for`` block's header + body UNIFORMLY (each deeper body/continuation line keeps its
      EXTRA indent, so relative structure is preserved, and ``else:``/``elif:`` headers re-base off the same
      column). Moving DEEPER grows every such line by ``len(dst_prefix) - len(src_prefix)`` columns; if a
      re-based code line would exceed :data:`_MAX_LINE_LENGTH` it is REFUSED (zero change) — mirroring
      :func:`_apply_insert_row`'s guard, because ``ruff`` would wrap that line at the new depth and the
      byte-preserved (un-wrapped) output would no longer be ``ruff format --check``-clean (gate 3). The
      symmetric SHALLOWER hazard — a bracket-wrapped call that ``ruff`` would COLLAPSE at a smaller indent —
      is caught upstream in :func:`_move_to_target` (a length check cannot see it: its lines are all short);
    * otherwise (a non-blank line that does not start with ``src_prefix`` — an exotic backslash continuation
      or unfrozen string interior) → REFUSE (zero change), keeping every accepted result valid + ruff-clean."""
    out: list[str] = []
    for i, line in enumerate(block):
        term = _line_terminator(line)
        content = line[: len(line) - len(term)]
        if i in frozen_rel:
            out.append(line)
        elif content.strip() == "":
            out.append(term)
        elif content.startswith(src_prefix):
            rebased = dst_prefix + content[len(src_prefix) :]
            if len(rebased) > _MAX_LINE_LENGTH:
                # gate 3: a line that fit at the source depth overflows ruff's line length at the (deeper)
                # destination depth — ruff would wrap it, so the un-wrapped output is not format-clean.
                raise LensRewriteError(
                    f"the moved step would be {len(rebased)} columns at the new depth — over the "
                    f"{_MAX_LINE_LENGTH}-column limit (ruff would wrap it); edit it as text"
                )
            out.append(rebased + term)
        else:
            raise LensRewriteError(
                "cannot re-indent this block across nesting (an exotic continuation line) — edit it as text"
            )
    return out


# =============================================================================
# paste_block — paste a captured Steps block into the anchor's suite (ADR 0076 §5)
# =============================================================================
#
# A Steps COPY/CUT captures a movable block's SOURCE TEXT (webview-owned clipboard, ``vscode.setState``);
# PASTE re-inserts it at an anchor row, re-indented to the anchor's suite through the SAME audited helpers a
# cross-suite move uses (:func:`_reindent_block` / :func:`_frozen_relative_lines` /
# :func:`_has_collapsible_wrapped_stmt`). Only NEW lines are inserted — every existing line is byte-preserved
# (gate 2) — and the result is re-parsed by :func:`_assert_reparses` before it is returned.


def _parse_pasted_block(block: str) -> ast.stmt:
    """Parse a pasted clipboard ``block`` into its single statement — a FUNCTION-wrapped parse (ADR 0076 §5).

    Wraps the block in ``def _f():\\n`` (fallback ``async def _f():\\n``) so a copied ``return Send(...)`` /
    ``await ...`` / ``yield`` — valid only inside a function body — parses (an ``if True:`` wrapper would
    raise ``SyntaxError: 'return' outside function`` on every send-row paste). The wrapper is EXACTLY one
    physical line, so the sole statement lands at ``lineno == 2`` and every block line sits at wrapped-lineno
    ``block_index + 2`` — hence :func:`_frozen_relative_lines` / :func:`_has_collapsible_wrapped_stmt` (which
    subtract the statement's own lineno) yield block-relative 0-based indices that align with the
    reconstructed block lines the reindent walks. Handler-body rows are always indented, so the wrapped body
    is always validly indented. Refuses a clipboard that is not exactly one parseable statement/block."""
    for header in ("def _f():\n", "async def _f():\n"):
        try:
            wrapped = ast.parse(header + block)
        except SyntaxError:
            continue
        func = wrapped.body[0]
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue  # defensive — the wrapper is a def, so body[0] is always a function
        body = func.body
        if len(body) != 1:
            raise LensRewriteError(
                "the clipboard must be exactly one step or block — nothing pasted"
            )
        stmt = body[0]
        if stmt.lineno != 2:
            raise LensRewriteError(
                "the clipboard block is malformed (unexpected leading content) — nothing pasted"
            )
        return stmt
    raise LensRewriteError("the clipboard is not valid Python — nothing pasted")


def _apply_paste_block(src: str, line_start: int, line_end: int, edit: dict[str, Any]) -> str:
    """Paste a captured Steps ``block`` before/after the anchor row, re-indented to the anchor's suite.

    The clipboard ``block`` is LF-joined source (the webview stores it via ``vscode.setState``); it is
    re-terminated to the destination's dominant newline (byte-faithful for a same-document paste — the file
    is single-newline-style) and, when the anchor sits at a different depth than the block was captured,
    re-indented through the cross-suite move helpers. Only NEW lines are inserted, so every existing line is
    byte-preserved (gate 2) — the sole mutation of an existing line is terminating a formerly-final line in
    the EOF-append case (identical to :func:`_apply_insert_row` / :func:`_reorder_stmt`). Refuses an empty /
    multi-statement / unparseable clipboard, a DEEPER re-indent that would over-run the column limit
    (:func:`_reindent_block`), and a SHALLOWER one that would let ``ruff`` collapse a wrapped call
    (:func:`_has_collapsible_wrapped_stmt`). The anchor's stale-coordinate guard (``expect_src``) runs in
    :func:`rewrite_source`; :func:`_assert_reparses` backstops validity (it catches, e.g., pasting ``after`` a
    control header, where the block lands at the header's outer indent inside the body — an IndentationError)."""
    block = edit.get("block")
    if not isinstance(block, str) or block == "":
        raise LensRewriteError("paste_block requires a non-empty 'block' string")
    position = edit.get("position", "after")
    if position not in ("before", "after"):
        raise LensRewriteError("paste_block 'position' must be 'before' or 'after'")
    term = _dominant_terminator(src)
    logical = block.split("\n")  # LF clipboard → logical lines
    block_lines = [
        ln + term for ln in logical
    ]  # keepends, re-terminated to the dest's dominant newline
    src_prefix = _leading_ws(logical[0])
    stmt = _parse_pasted_block(block)  # function-wrapper parse; exactly one statement
    lines = _physical_lines_keepends(src)
    dst_prefix = _paste_anchor_indent(lines, line_start, line_end, position)
    if src_prefix != dst_prefix:
        if len(dst_prefix) < len(src_prefix) and _has_collapsible_wrapped_stmt(stmt):
            raise LensRewriteError(
                "pasting this to a shallower level would change ruff's line wrapping (a wrapped call would "
                "collapse to one line) — edit it as text"
            )
        # A DEEPER re-indent that overflows the column limit is refused inside :func:`_reindent_block`.
        block_lines = _reindent_block(
            block_lines, src_prefix, dst_prefix, _frozen_relative_lines(stmt)
        )
    insert_idx = (line_start - 1) if position == "before" else line_end
    if insert_idx >= len(lines):
        # Appending past the last line: terminate a formerly-final line that has no newline first.
        if lines and _line_terminator(lines[-1]) == "":
            lines[-1] = lines[-1] + term
        lines.extend(block_lines)
    else:
        lines[insert_idx:insert_idx] = block_lines
    if lines and _line_terminator(lines[-1]) == "":  # keep a ruff-clean trailing newline
        lines[-1] = lines[-1] + term
    return "".join(lines)


# The three ADR 0076 actions the ADR 0089 Phase A recognizer reads back from their NATIVE Message-API
# idiom. An insert of one of these emits that native form (no vocabulary import needed) so a new step
# matches an estate authored in the native API and round-trips through :func:`_recognize_native_method`.
_NATIVE_INSERT_ACTIONS = frozenset({"set_field", "copy_field", "delete_segment"})


def _render_native_insert_call(name: str, params: dict[str, Any], assign_to: Any) -> str:
    """Render the NATIVE Message-API form of an inserted ``set_field``/``copy_field``/``delete_segment``.

    The single source of truth for the inserted native text — chosen so that re-parsing the line
    recognizes the SAME editable action row (:func:`_recognize_native_method`):

    * ``set_field {path, value}``     → ``msg.set(<path>, <value>)``
    * ``copy_field {src, dst}``       → ``msg.set(<dst>, msg.field(<src>) or "")``
    * ``delete_segment {segment_id}`` → ``msg.delete_segments(<segment_id>)``

    Values are rendered via :func:`_render_insert_value` (literal-vs-``{"expr"}`` handling + the single-
    line invariant are identical to the wrapper path). A missing/empty param renders as an empty string
    literal (``msg.set("", "")`` — still a valid, Phase-A-recognized, editable row). ``msg`` is the
    receiver (never a param) and these actions return ``None``, so a ``msg`` param or an ``assign_to`` is
    refused with the SAME messages as :func:`_render_insert_call`."""
    if "msg" in params:
        # ``msg`` is the message receiver, not an argument; there is no slot for it (mirrors the wrapper
        # path, which would splice a duplicate ``msg=`` kwarg).
        raise LensRewriteError(
            "insert_row: 'msg' is supplied automatically and cannot be passed as a parameter"
        )
    if assign_to is not None:
        # set_field/copy_field/delete_segment mutate the message in place and return ``None``; assigning
        # that both binds ``None`` and reclassifies the row as ``code`` (only a bare call is recognized).
        raise LensRewriteError(
            f"insert_row: {name!r} returns no value, so it cannot be assigned "
            "(only db_lookup/fhir_lookup/code_lookup return a value to assign)"
        )
    if name == "set_field":
        path = _render_insert_value(params.get("path", ""), "path")
        value = _render_insert_value(params.get("value", ""), "value")
        return f"msg.set({path}, {value})"
    if name == "copy_field":
        src = _render_insert_value(params.get("src", ""), "src")
        dst = _render_insert_value(params.get("dst", ""), "dst")
        return f'msg.set({dst}, msg.field({src}) or "")'
    # delete_segment — the recognizer reads back both ``delete_segments`` and ``delete_segment``.
    segment_id = _render_insert_value(params.get("segment_id", ""), "segment_id")
    return f"msg.delete_segments({segment_id})"


def _move_to_target(
    src: str,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    edit: dict[str, Any],
    target_suite: list[ast.stmt],
    target_idx: int,
) -> str:
    """Reinsert the moved statement before/after an arbitrary sibling — the drag-and-drop drop.

    ``to_line_start`` names the DESTINATION anchor by its HEADER line; ``to_position`` (``"before"`` /
    ``"after"``) which side of it the block lands. The anchor's own suite (as :func:`_locate_stmt_by_header`
    resolves it) IS the landing suite, so a CROSS-suite move is exactly "adopt the anchor's suite + indent":
    the moved block re-indents to the anchor's depth (:func:`_reindent_block`) and joins it. Refusals (zero
    change): dropping onto self is a no-op; dropping a block onto a row in its OWN body; moving the SOLE
    statement out of a suite (would leave an empty ``if``/``for`` body — invalid Python); and a depth change
    that would not stay ruff-format-clean — a re-based line over the column limit (:func:`_reindent_block`,
    deeper) or a bracket-wrapped call ruff would collapse at a shallower depth (:func:`_has_collapsible_wrapped_stmt`,
    below). An equal-depth move (same-suite, or two sibling bodies at the same nesting) reindents nothing and
    stays byte-identical. ``target_suite``/``target_idx`` are the moved statement's already-resolved suite +
    index (from :func:`_apply_move_row`). The re-parse gate (:func:`_assert_reparses`) backstops validity."""
    to_ls = edit.get("to_line_start")
    position = edit.get("to_position", "after")
    if position not in ("before", "after"):
        raise LensRewriteError("move_row 'to_position' must be 'before' or 'after'")
    if not isinstance(to_ls, int):
        raise LensRewriteError("move_row 'to_line_start' must be an integer")
    dest = _locate_stmt_by_header(handler_node.body, to_ls)
    if dest is None:
        raise LensRewriteError(f"could not locate the drop target at line {to_ls}")
    dest_suite, dest_idx = dest
    # Dropped exactly onto itself — a no-op (preserves today's drop-onto-self behavior). Must precede the
    # into-self / empty-source guards (a sole leaf dropped onto itself is a no-op, not an "empty suite").
    if dest_suite is target_suite and dest_idx == target_idx:
        return src
    moved = target_suite[target_idx]
    # A control BLOCK dropped onto a row inside its OWN body would try to reinsert the block within the span
    # it is cutting — refuse. (A leaf onto itself already returned above; this catches only the descendant
    # case, where the anchor line falls strictly inside the moved block's span.)
    if moved.lineno <= to_ls <= (moved.end_lineno or moved.lineno):
        raise LensRewriteError("cannot drop a block into its own body — edit it as text")
    # Constraint 4: moving the ONLY statement out of an if/for body leaves an empty suite (invalid Python).
    # Same-suite moves are exempt (the statement stays in its suite; the sole-same-suite case returned above
    # as the drop-onto-self no-op). Mirrors _apply_delete_row's len==1 guard.
    if target_suite is not dest_suite and len(target_suite) == 1:
        raise LensRewriteError(
            "this row is the only statement in its block — moving it out would leave an empty suite "
            "(invalid Python); edit it as text"
        )
    dest_stmt = dest_suite[dest_idx]
    lines = _physical_lines_keepends(src)
    src_prefix = _leading_ws(lines[moved.lineno - 1])
    # The moved block adopts the anchor's indent — the anchor is a direct member of the landing suite, so its
    # leading whitespace IS the suite's indent (constraint 1). Equal prefixes (same-suite, or an equal-depth
    # sibling-body cross-suite move) reindent nothing and stay byte-identical to a plain reorder.
    dst_prefix = _leading_ws(lines[dest_stmt.lineno - 1])
    if src_prefix == dst_prefix:
        return _reorder_stmt(src, moved, dest_stmt, position)
    # gate 3 (SHALLOWER hazard): a bracket-wrapped call is wrapped only because its one-line form overflowed
    # ruff's line length at its CURRENT depth; at a shallower depth it may fit, so ruff would COLLAPSE it and
    # our byte-preserved (still-wrapped) output would not be format-clean. Refuse (zero change) — the DEEPER
    # overflow hazard is caught in _reindent_block's per-line length guard, but a length check cannot see a
    # collapse (the wrapped lines are all short).
    if len(dst_prefix) < len(src_prefix) and _has_collapsible_wrapped_stmt(moved):
        raise LensRewriteError(
            "moving this to a shallower level would change ruff's line wrapping (a wrapped call would "
            "collapse to one line) — edit it as text"
        )
    reindent = (src_prefix, dst_prefix, _frozen_relative_lines(moved))
    return _reorder_stmt(src, moved, dest_stmt, position, reindent=reindent)


def _render_insert_call(name: str, params: dict[str, Any], assign_to: Any) -> str:
    """Render a NEW vocabulary action/lookup call ``name(...)`` (optionally ``target = name(...)``).

    Positional arguments are emitted in the helper's signature order (the leading ``msg`` verbatim where
    the helper takes one); a parameter not in the positional signature is emitted as a keyword argument
    (e.g. a keyword-only ``default=`` / ``in_fmt=``). A scalar value renders as a Python literal, an
    ``{"expr": <source>}`` object verbatim. Refuses an unknown vocabulary name, a missing required
    positional parameter, a ``msg`` parameter (it is supplied automatically — passing it would emit a
    duplicate ``msg=`` kwarg), ``assign_to`` on a mutating action (only db/fhir/code_lookup return a
    value — assigning an action's ``None`` reclassifies the row as ``code``), or a non-identifier
    ``assign_to`` / keyword name."""
    param_names = _ACTION_PARAMS.get(name) or _LOOKUP_PARAMS.get(name)
    if param_names is None:
        raise LensRewriteError(
            f"insert_row: {name!r} is not a recognized vocabulary action/lookup "
            f"(known: {sorted(_ACTIONS | _LOOKUPS)})"
        )
    if "msg" in params:
        # ``msg`` is the injected message, emitted automatically as the first positional arg; passing it
        # as a param would splice a duplicate ``msg=`` keyword (``set_field(msg, …, msg="X")``) — a
        # TypeError at runtime. Refuse it (it is never an editable parameter, mirroring _splice_slots).
        raise LensRewriteError(
            "insert_row: 'msg' is supplied automatically and cannot be passed as a parameter"
        )
    args: list[str] = []
    used: set[str] = set()
    for pn in param_names:
        if pn == "msg":
            args.append("msg")
            continue
        if pn not in params:
            raise LensRewriteError(f"insert_row: {name!r} requires parameter {pn!r}")
        args.append(_render_insert_value(params[pn], pn))
        used.add(pn)
    for pn, val in params.items():
        if pn in used:
            continue
        if not (isinstance(pn, str) and pn.isidentifier()):
            raise LensRewriteError(f"insert_row: {pn!r} is not a valid keyword parameter name")
        args.append(f"{pn}={_render_insert_value(val, pn)}")
    call = f"{name}({', '.join(args)})"
    if assign_to is not None:
        if name not in _LOOKUPS:
            # copy_field/set_field/… mutate the message in place and return ``None``; ``x = set_field(…)``
            # both binds ``None`` (nonsensical) and RE-CLASSIFIES the row as ``code`` (only a bare-call
            # action is recognized, not an assignment) — an uneditable row the analyst can't recover.
            raise LensRewriteError(
                f"insert_row: {name!r} returns no value, so it cannot be assigned "
                "(only db_lookup/fhir_lookup/code_lookup return a value to assign)"
            )
        if not (isinstance(assign_to, str) and assign_to.isidentifier()):
            raise LensRewriteError("insert_row 'assign_to' must be a simple identifier")
        call = f"{assign_to} = {call}"
    return call


def _render_insert_value(value: Any, pname: str) -> str:
    """Render a NEW call argument value: a scalar as a Python literal, an ``{"expr": …}`` verbatim.

    Unlike :func:`_render_new_value` (which guards an existing literal-vs-expression slot), an inserted
    call has no existing argument, so a scalar always renders as a literal and an object must be
    ``{"expr": <source>}`` (validated to parse as one expression). The rendered value must stay on a
    single physical line (a newline would change the file's line count)."""
    if isinstance(value, dict):
        expr = value.get("expr")
        if set(value) != {"expr"} or not isinstance(expr, str):
            raise LensRewriteError(
                f"parameter {pname!r}: an object value must be {{'expr': <source>}}"
            )
        rendered = _validated_expr(expr, pname)
    else:
        rendered = _render_literal(value, pname)
    if "\n" in rendered or "\r" in rendered:
        raise LensRewriteError(
            f"parameter {pname!r}: the value must stay on a single line (a line break would change the "
            "file's line count)"
        )
    return rendered


def _physical_lines_keepends(source: str) -> list[str]:
    """``source`` split into physical lines WITH their terminators, on CRLF / CR / LF only.

    ``"".join(_physical_lines_keepends(s)) == s`` exactly (byte-preserving), and element ``L-1`` is the
    full text (content + terminator) of 1-based physical line ``L`` — the coordinate system the AST/parser
    use. Deliberately NOT :meth:`str.splitlines` with ``keepends=True``, whose wider Unicode boundary set
    would desync the line indexing from the AST (the same reason as :func:`_physical_lines`)."""
    lines: list[str] = []
    i = 0
    n = len(source)
    start = 0
    while i < n:
        ch = source[i]
        if ch == "\r":
            i += 2 if i + 1 < n and source[i + 1] == "\n" else 1
            lines.append(source[start:i])
            start = i
        elif ch == "\n":
            i += 1
            lines.append(source[start:i])
            start = i
        else:
            i += 1
    if start < n:
        lines.append(source[start:n])
    return lines


def _line_terminator(line: str) -> str:
    """The trailing newline of a keepends line (CRLF / LF / CR), or ``""`` when it has none."""
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n"):
        return "\n"
    if line.endswith("\r"):
        return "\r"
    return ""


def _dominant_terminator(source: str) -> str:
    """The file's first newline sequence (CRLF / CR / LF), defaulting to LF.

    Used to pick the terminator for a synthesized line (insert) or to terminate a formerly-final line, so
    a CRLF file stays CRLF and an LF file stays LF."""
    m = re.search(r"\r\n|\r|\n", source)
    return m.group(0) if m else "\n"


def _leading_ws(line: str) -> str:
    """The leading whitespace (spaces/tabs) of ``line`` — a synthesized line copies the target's indent."""
    stripped = line.lstrip(" \t")
    return line[: len(line) - len(stripped)]


def _physical_lines(source: str) -> list[str]:
    """``source`` split into physical lines on ``\\r\\n`` / ``\\r`` / ``\\n`` only — the newline set the
    CPython tokenizer (hence AST line numbers) recognizes.

    Deliberately NOT :meth:`str.splitlines`, whose wider Unicode boundary set (vertical tab, form feed,
    NEL ``\\x85``, U+2028/U+2029, …) would insert phantom line breaks and desync AST line numbers from the
    text — mis-locating (and corrupting) a splice (F2). Every place that maps an AST line number to text
    uses this, so the parse partition and the rewrite splice agree on what "line N" is."""
    return re.split(r"\r\n|\r|\n", source)


def _line_byte_starts(source_bytes: bytes) -> list[int]:
    """Byte offset in ``source_bytes`` where each 1-based physical line begins (``starts[L-1]`` = line L).

    Splits on ``\\r\\n`` / ``\\r`` / ``\\n`` only (the tokenizer's line model, matching :func:`_physical_lines`),
    so a form-feed / NEL / U+2028 in the source never shifts a line boundary. Returns *byte* offsets (not
    code-point offsets) so they compose directly with the AST's byte ``col_offset`` (F1)."""
    starts = [0]
    i = 0
    n = len(source_bytes)
    while i < n:
        b = source_bytes[i]
        if b == 0x0D:  # \r, optionally \r\n
            i += 2 if i + 1 < n and source_bytes[i + 1] == 0x0A else 1
            starts.append(i)
        elif b == 0x0A:  # \n
            i += 1
            starts.append(i)
        else:
            i += 1
    return starts
