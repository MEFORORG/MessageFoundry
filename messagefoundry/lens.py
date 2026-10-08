# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Structured Steps view over Python Handlers and Routers — the static ``ast`` parser (ADR 0076 §3–§4).

:func:`parse_module` classifies each ``@handler`` (and, at contract v2, each ``@router``) body in a
config module into the **row contract** of ADR 0076 §3: ordered, nested rows of kind ``action`` /
``lookup`` / ``control`` / ``send`` / ``diagnostic`` / ``code``, plus ``note`` (Amendment A) and
``route`` (Amendment D). It is a **static parse** — it uses only the stdlib :mod:`ast` and **never
imports or executes** the config module, so a module whose top level would raise (or whose imports are
unavailable) still parses (ADR 0076 §5, gate 4).

The load-bearing property (ADR 0076 §6, gate 1 — the **coverage invariant**): the emitted rows'
line ranges **exactly partition** each element's def body (the statement suite from the first body
statement through the function's last line) — every line is in exactly one row; nothing is dropped,
reordered, or synthesized. Unrecognized constructs become in-place ``code`` rows (the degradation
ladder: typed row → code row → whole-file refusal only on parse failure).

**Contract versions (ADR 0076 §A.7 / §D.7 — skew is handled, not discovered).** ``parse_source`` emits
no schema version of its own, and the IDE shells whatever ``messagefoundry`` is on ``PATH``, so a NEW
row kind reaching an OLD consumer renders a blank, titleless row. Both new kinds are therefore gated
behind an explicit ``contract`` argument (``lens parse --contract N``):

* :data:`CONTRACT_V1` (the default) is the shipped contract — no ``note`` rows, no ``route`` rows, no
  ``@router`` projection, no ``role``/``contract_version`` fields, no ``param_modes``. A consumer that
  passes nothing gets **byte-identical** output to the pre-amendment parser.
* :data:`CONTRACT_V2` adds the ``note`` and ``route`` kinds, projects ``@router`` defs, stamps each
  entry with ``role`` + ``contract_version`` so a consumer can tell the two projections apart, and
  carries Amendment E's per-argument ``param_modes`` map on every row with typed arguments.

``param_modes`` is a new FIELD rather than a new kind, so it cannot render a blank row at an older
consumer — it rides v2 instead of minting a version of its own, and an older consumer simply ignores a
key it does not read (§E.8).

Two contract details worth stating for L3 consumers: a ``lookup`` row, and the ``read_field`` action
row (ADR 0089 row 4), may carry an extra read-only ``assign_to`` field (the assignment target of e.g.
``row = db_lookup(...)`` or ``name = msg.field(...)`` — within §3's contract, optional). And at
:data:`CONTRACT_V1` a trailing comment *after the last statement* in a def lives **outside** the
partition (beyond the def's ``node.end_lineno``, which the AST fixes to the last statement's last
line); at :data:`CONTRACT_V2` the partition is extended over that trailing comment run so it projects
as a ``note`` row instead of vanishing (Amendment A §A.3 defect 1).

The engine owns the grammar so it lives beside the vocabulary; the IDE consumes the JSON contract
only (``messagefoundry lens parse <module.py> --json``). This module adds **no runtime dependency** —
stdlib ``ast`` only.
"""

from __future__ import annotations

import ast
import builtins
import copy
import json
import keyword
import math
import re
import unicodedata
import warnings
from collections import Counter, deque
from pathlib import Path
from typing import Any, NamedTuple, NoReturn

__all__ = [
    "CONTRACT_LATEST",
    "CONTRACT_V1",
    "CONTRACT_V2",
    "LensParseError",
    "LensRewriteError",
    "parse_module",
    "parse_source",
    "rewrite_module",
    "rewrite_source",
]

#: The shipped ADR 0076 §3 contract — ``action``/``lookup``/``control``/``send``/``diagnostic``/``code``
#: rows for ``@handler`` defs only. The DEFAULT, so a consumer that asks for nothing (an IDE older than
#: the grammar amendments) can never be handed a kind it has no renderer for (§A.7 / §D.7).
CONTRACT_V1 = 1
#: Adds the ``note`` kind (Amendment A) and the ``route`` kind + ``@router`` projection (Amendment D),
#: stamps each entry with ``role`` ("handler"/"router") + ``contract_version``, and carries the
#: per-argument ``param_modes`` map (Amendment E).
CONTRACT_V2 = 2
#: The newest contract this parser can emit. A consumer asks for the version it can RENDER, never this.
CONTRACT_LATEST = CONTRACT_V2

_CONTRACTS = frozenset({CONTRACT_V1, CONTRACT_V2})

# What ``ast.parse`` raises, besides ``SyntaxError``, on source it cannot turn into a tree (BACKLOG
# #1858). Each lens site converts these to its own error type, so the CLI's ``except`` sees a clean
# refusal instead of an uncaught traceback. At least these are reachable, each measured by
# tests/test_parser_refusal_guards.py; the classes mirror ``corepoint_import._verify_compilable``.
#
# * ``MemoryError`` -- the parser's width wall ("Parser stack overflowed"), a bounded parser limit
#   rather than heap exhaustion, so the interpreter is fully usable afterwards.
# * ``RecursionError`` -- the depth wall, raised while the parse builds a deeply nested tree.
# * ``ValueError`` -- covers ``UnicodeEncodeError``, which a lone surrogate raises. One reaches these
#   sites through the edit JSON, whose ``\ud800`` escape decodes to exactly that. A base class rather
#   than a leaf, because enumerating leaves is how this defect was written.
#
# ``SyntaxError`` stays its own ``except`` at each site, because only it carries ``msg`` and ``lineno``.
_PARSER_REFUSALS = (MemoryError, RecursionError, ValueError)


def _refusal_reason(exc: Exception) -> str:
    """Say why the parser refused, naming the class, since none of these carries a line number."""
    if isinstance(exc, MemoryError | RecursionError):
        return f"source too complex for the Python parser: {type(exc).__name__}: {exc}"
    return f"{type(exc).__name__}: {exc}"


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
    within its own line range, every other byte untouched (gate 2).

    ``code`` is a stable machine-readable slug for the refusal FAMILY, which ``lens rewrite`` emits
    beside the message as ``{"error": ..., "code": ...}``. The IDE keys on it, so a message can be
    reworded without breaking a consumer. The families with their own code are the ``REFUSAL_*``
    constants below; any other refusal carries :data:`REFUSAL_GENERIC`. Changing a code's string is a
    contract change for the IDE."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code if code is not None else REFUSAL_GENERIC


#: A dynamic-mode argument: editing one (AC-M5), or an ``expr`` that would write one (E.6.4).
REFUSAL_DYNAMIC_MODE = "dynamic-mode"
#: A malformed value object on a moded argument: ``parts`` not a list, a part without exactly one
#: key, no path part, an empty or unusable path, an unencodable character, a template sent as an
#: ``expr``, or an object that is neither ``{"parts": [...]}`` nor ``{"expr": <string>}``.
REFUSAL_TEMPLATE_SHAPE = "template-shape"
#: A template sent to a param outside the row's ``template_params`` (a literal-only param).
REFUSAL_LITERAL_ONLY = "literal-only"
#: A template write that pushes a line past the column limit.
REFUSAL_COLUMN_LIMIT = "column-limit"
#: Every other ``lens rewrite`` refusal.
REFUSAL_GENERIC = "refused"


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
    "trim_field": ["msg", "path"],  # ADR 0106
    "substring_field": ["msg", "path", "start", "end"],  # ADR 0106
    "pad_field": ["msg", "path", "width"],  # ADR 0106 — fill / side are keyword-only
    "replace_literal": ["msg", "path", "old", "new"],  # ADR 0106
    "convert_case": ["msg", "path", "mode"],
    "arith_field": ["msg", "path", "op", "operand"],  # ADR 0106 — ndigits is keyword-only
    "format_date": ["msg", "path", "out_fmt"],  # in_fmt is keyword-only
    "date_diff_field": ["msg", "start_path", "end_path", "dst"],  # ADR 0106 — unit is keyword-only
    "split_field": ["msg", "src", "sep", "dests"],
    "copy_segment": ["msg", "segment_id"],  # occurrence / index are keyword-only
    "delete_segment": ["msg", "segment_id"],
}
# The sanctioned read-only lookups (ADR 0010/0043) + the ``code_lookup`` vocabulary helper are rendered
# as DBSelect-style ``lookup`` rows (ADR 0076 §3). db_lookup/fhir_lookup take no ``msg`` argument.
_LOOKUP_PARAMS: dict[str, list[str]] = {
    "db_lookup": ["connection", "statement", "params"],
    # ``params`` is not optional garnish here: since #1243 removed the flat '?'-query, the structured
    # params= form is the ONLY way to express a fhir_lookup SEARCH, so without it a Steps row could
    # only ever emit a read-by-id. Same shape db_lookup already uses.
    "fhir_lookup": ["connection", "query", "params"],
    "code_lookup": ["msg", "path", "table"],  # default is keyword-only
}

_ACTIONS = frozenset(_ACTION_PARAMS)
_LOOKUPS = frozenset(_LOOKUP_PARAMS)
# The lookups whose call RETURNS a value to bind (``row = db_lookup(...)``). ``code_lookup`` is a lookup
# ROW too, but it mutates the message in place and returns ``None`` (actions.py) — so an inserted
# ``x = code_lookup(...)`` would bind ``None`` and re-classify as a read-only ``code`` row. An insert may
# assign ONLY these; ``code_lookup`` is inserted bare (ADR 0106 §5 J).
_ASSIGNABLE_LOOKUPS = frozenset({"db_lookup", "fhir_lookup"})

# Diagnostic helpers (ADR 0106, ``messagefoundry.diagnostics``) — the one output-independent side effect
# (DEBUG-only, redact-by-default logging). Recognized as read-only ``diagnostic`` rows for now; only the
# ``template`` / ``label`` literal is meaningful, the ``log_note`` operands are recognized-only extra
# positionals. Making them insertable/editable is the ADR 0106 insert-side work.
_DIAGNOSTIC_PARAMS: dict[str, list[str]] = {
    "log_note": ["template"],
    "checkpoint": ["msg", "label"],
}
_DIAGNOSTICS = frozenset(_DIAGNOSTIC_PARAMS)


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
    """A recognized native ``Message``-API statement (ADR 0089 Phase A): a write, or a bound read.

    ``action`` is the reused ADR 0076 vocabulary name (``set_field`` / ``copy_field`` /
    ``delete_segment``), or ``read_field`` for ``name = msg.field(path)``. ``slots`` maps each
    **editable** parameter, in canonical order, to the exact :class:`ast.expr` node whose byte span an edit splices (a positional arg, or — for ``copy_field`` —
    the inner ``msg.field(src)`` argument). ``display`` carries read-only, byte-preserved keyword args
    (``occurrence=``/``repetition=``) that are shown on the row but are never editable in Phase A and
    are never dropped or reordered on a rewrite. ``assign_to`` is the bound name of a ``read_field``,
    emitted read-only on the row; it is None for every write."""

    action: str
    slots: list[tuple[str, ast.expr]]
    display: list[tuple[str, ast.expr]]
    assign_to: str | None = None


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


def _native_display(call: ast.Call) -> list[tuple[str, ast.expr]] | None:
    """The read-only keyword ``display`` fields of a native call, or None when it carries a splat.

    A ``*args`` positional or ``**kwargs`` splat defeats static arity/keyword reasoning, so both native
    recognizers refuse it (it falls to a ``code`` row), and a splice never mis-targets a hidden
    argument."""
    if any(isinstance(a, ast.Starred) for a in call.args):
        return None
    display: list[tuple[str, ast.expr]] = []
    for kw in call.keywords:
        if kw.arg is None:
            return None
        display.append((kw.arg, kw.value))
    return display


def _recognize_native_method(call: ast.Call) -> _NativeAction | None:
    """Classify a native ``msg.<method>(...)`` call into a :class:`_NativeAction`, or None (→ ``code``).

    Recognizes exactly the ADR 0089 Phase A forms:

    * ``msg.set(path, value)`` reads as ``set_field`` (path + value editable slots).
    * ``msg.set(dst, msg.field(src))`` / ``msg.set(dst, msg.field(src) or "")`` read as ``copy_field``, and
      the same two shapes through ``msg.set_data``, the write a copy from a leaf uses (ADR 0206).
    * ``msg.delete_segments("SEG")`` / ``msg.delete_segment("SEG")`` read as ``delete_segment``.

    A ``*args`` / ``**kwargs`` splat, the wrong positional arity (``msg.set`` with != 2, ``delete`` with
    != 1), a non-``msg`` receiver, or any other method makes it unrecognized (→ a read-only ``code`` row):
    when unsure the lens degrades rather than risk a corrupting edit. ``occurrence=``/other keyword args
    are preserved as read-only ``display`` fields (never dropped, never editable in Phase A). A
    ``msg.set_data`` call that is not a copy is a ``set_field`` when its destination is a literal
    component or subcomponent path, where it writes what ``msg.set`` writes, or when its value is a
    template the lens itself would write with ``set_data`` (:func:`_template_is_data`). Any other
    one is a ``code`` row, because ``set_field`` otherwise means :meth:`Message.set`."""
    func = call.func
    if not isinstance(func, ast.Attribute) or not _is_msg_method(func, func.attr):
        return None
    display = _native_display(call)
    if display is None:
        return None
    if func.attr in ("set", "set_data"):
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
        # At a literal leaf set_data writes what set writes, so any value there reads back as the
        # Set Field it is; elsewhere only a template the lens itself writes with set_data does.
        if (
            func.attr == "set_data"
            and not _is_leaf_literal(getattr(dst_or_path, "value", None))
            and not _template_is_data(value)
        ):
            return None
        return _NativeAction("set_field", [("path", dst_or_path), ("value", value)], display)
    if func.attr in ("delete_segments", "delete_segment"):
        if len(call.args) != 1:
            return None
        return _NativeAction("delete_segment", [("segment_id", call.args[0])], display)
    if func.attr == "add_segment":
        # ``msg.add_segment(<line>)`` — the arg is a WHOLE segment line ("ODS|R|^ODS123"), the one
        # editable slot; ``index=`` is a read-only display kwarg (never editable in Phase A).
        if len(call.args) != 1:
            return None
        return _NativeAction("add_segment", [("line", call.args[0])], display)
    if func.attr == "add_repetition":
        # ``msg.add_repetition(<path>, <value>)`` — two editable slots; ``occurrence=`` is display-only.
        if len(call.args) != 2:
            return None
        return _NativeAction(
            "add_repetition", [("path", call.args[0]), ("value", call.args[1])], display
        )
    return None


def _recognize_native_read(s: ast.stmt) -> _NativeAction | None:
    """Classify ``name = msg.field(path[, occurrence=...])`` as a ``read_field`` row, or None (``code``).

    ADR 0089 Phase A row 4 ("Read Field to var"). The bound name rides on ``assign_to``.
    Only a plain ``ast.Assign`` to ONE bare name qualifies. A tuple, attribute, subscript or chained
    target, an annotated assignment, and a ``msg.field(...) or ""`` default all stay ``code``. So do a
    splat, any positional arity but one, and a target named ``msg``: rebinding the receiver every
    native row reads would shadow the message, so ``msg = msg.field(...)`` is left as text. ``path`` is the one editable slot, and only while it is a
    literal, exactly as on ``set_field``. Keyword args are read-only ``display`` fields, preserved
    byte-for-byte as on the write rows.

    The bound name is emitted read-only as ``assign_to``, the field the ``lookup`` rows already use. A
    rename of the target alone would leave every later use of the old name dangling, so the lens does
    not offer one. A rename that follows the uses is a design question ADR 0089 does not settle. For
    the same reason :func:`rewrite_source` refuses ``delete_row`` and ``move_row`` on this row.

    A bare ``msg.field(...)`` expression statement never reaches here. It binds nothing, so it stays a
    ``code`` row, and :func:`_recognize_native_method` keeps no ``field`` branch."""
    if not (
        isinstance(s, ast.Assign)
        and len(s.targets) == 1
        and isinstance(s.targets[0], ast.Name)
        and s.targets[0].id != "msg"
        and isinstance(s.value, ast.Call)
        and _is_msg_method(s.value.func, "field")
    ):
        return None
    call = s.value
    display = _native_display(call)
    if display is None or len(call.args) != 1:
        return None
    return _NativeAction("read_field", [("path", call.args[0])], display, s.targets[0].id)


def _recognize_native_stmt(s: ast.stmt) -> _NativeAction | None:
    """The native row a statement projects as, or None.

    This is the ONE entry point the parser and the rewriter share, so a new native statement shape is
    added here once and the two can never diverge. A mutating method call is a bare expression
    statement; a read is a single-name assignment."""
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
        return _recognize_native_method(s.value)
    return _recognize_native_read(s)


def _native_action_row(
    native: _NativeAction, s: ast.stmt, nesting: int, source: str, contract: int
) -> dict[str, Any]:
    """Build the ADR 0076 ``action`` row contract for a recognized native statement (ADR 0089 Phase A).

    ``params`` renders each editable slot (a literal → its value; an expression → verbatim source) then
    each read-only keyword (``occurrence=``), so the row carries the same shape as the wrapper form.
    ``literal_params`` is the subset of *slot* params whose argument is a string/scalar literal — the
    IDE offers only those as editable, exactly as for wrapper actions (a keyword like ``occurrence`` is
    never listed, so it stays a bound read-only field).

    ``param_modes`` (Amendment E) covers the display keywords too, because AC-M1 makes it total over
    ``params``. A constant ``occurrence=`` is therefore ``static`` while staying out of
    ``literal_params`` — a LITERAL THAT IS NOT EDITABLE, which is a coherent state only because the two
    fields answer different questions, and is exactly why AC-M2 is scoped to editable params (E.10)."""
    slots_and_display = [*native.slots, *native.display]
    params = {name: _render_value(node, source) for name, node in slots_and_display}
    literal_params = [name for name, node in native.slots if isinstance(node, ast.Constant)]
    row = _attach_param_modes(
        {
            "kind": "action",
            "action": native.action,
            "params": params,
            "literal_params": literal_params,
            "line_start": s.lineno,
            "line_end": s.end_lineno or s.lineno,
            "nesting": nesting,
        },
        slots_and_display,
        contract,
    )
    if native.assign_to is not None:
        row["assign_to"] = native.assign_to
    return row


# --- public entry points -----------------------------------------------------


def parse_module(path: str | Path, *, contract: int = CONTRACT_V1) -> list[dict[str, Any]]:
    """Parse the config module file at ``path`` and return its element row contracts (ADR 0076 §3).

    Statically parses the file text with :mod:`ast` — the module is **never imported or executed**.
    Returns one contract dict per element, ``{"handler", "module", "def_line", "rows"}``; a module with
    no handlers returns ``[]``. ``contract`` selects the emitted grammar (:data:`CONTRACT_V1` default —
    see the module docstring). Raises :class:`LensParseError` if the file cannot be read or parsed."""
    p = Path(path)
    try:
        source = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        unreadable = f"{p}: cannot read ({exc})"
    else:
        # posix slashes keep the emitted contract (and the committed L3 fixtures) OS-neutral.
        return parse_source(source, module=p.as_posix(), contract=contract)
    # After the handler: a UnicodeDecodeError's .object is the whole file (BACKLOG #2085).
    raise LensParseError(unreadable)


def parse_source(
    source: str, *, module: str = "<source>", contract: int = CONTRACT_V1
) -> list[dict[str, Any]]:
    """Parse Python ``source`` text and return the element row contracts (see :func:`parse_module`).

    The file-free entry point (used by tests). ``module`` is echoed into each contract's ``module``
    field. ``contract`` selects the emitted grammar — :data:`CONTRACT_V1` (the default) is the shipped
    handler-only contract, :data:`CONTRACT_V2` adds ``note`` + ``route`` rows and ``@router``
    projection. Raises :class:`LensParseError` on source the parser refuses (a syntax error, or one of
    ``_PARSER_REFUSALS``) or an unknown ``contract``."""
    if contract not in _CONTRACTS:
        raise LensParseError(
            f"unknown contract version {contract!r} (supported: {sorted(_CONTRACTS)})"
        )
    # A leading UTF-8 BOM (U+FEFF) is invalid in a ``str`` handed to :func:`ast.parse` (it is only
    # stripped on the *bytes* path), so drop it up front; line numbers are unaffected (it sits on line 1).
    source = source.removeprefix("\ufeff")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise LensParseError(f"{module}: cannot parse ({exc.msg} at line {exc.lineno})") from exc
    except _PARSER_REFUSALS as exc:
        raise LensParseError(f"{module}: cannot parse ({_refusal_reason(exc)})") from exc
    # Split on \r\n / \r / \n only (the tokenizer's line model) so a form-feed / NEL / U+2028 never
    # desyncs an AST line number from its text (F2); everything mapping a line number to text uses this.
    lines = _physical_lines(source)
    handlers: list[dict[str, Any]] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        found = _element_name(node, contract)
        if found is None:
            continue  # not a projectable element (a plain def, or a @router below CONTRACT_V2)
        name, role = found
        ctx = _Ctx(source=source, lines=lines, role=role, contract=contract)
        body_start = node.body[0].lineno
        body_end = _body_end(node, ctx)
        # The def body is the top suite; its id is the def line (unique per module, so sibling handlers
        # never share a suite id in the flat webview row list).
        rows = _partition_suite(node.body, body_start, body_end, 0, ctx, str(node.lineno))
        if role == "handler":
            # ADR 0104 fan-out: an append-send only counts when its collector is a DELIVERING accumulator;
            # demote the orphans to code rows BEFORE merge (so they coalesce), then (post-merge) tag the
            # ``sends = []`` init + ``return sends`` footer of the accumulators that kept a visible append.
            # A router has no send rows at all (§D.6), so the whole fan-out pass is handler-only.
            delivering = _delivering_accumulators(node)
            used = _demote_orphan_appends(rows, node, delivering)
            # Tag scaffold BEFORE merge (the init/footer are still their own single-statement code rows),
            # then merge — which leaves scaffold rows standalone — so a `sends = []` preceded by another
            # statement still renders as its own muted row instead of blending into a code block.
            _tag_scaffold(rows, node, used)
        rows = _merge_code_rows(rows)
        entry: dict[str, Any] = {
            # The key stays ``handler`` for a router too: it carries the ELEMENT's registered name and is
            # also the rewrite addressing key (``lens rewrite --edit {"handler": …}``). Renaming it would
            # fork every locator in the rewrite half for no gain; ``role`` is what discriminates.
            "handler": name,
            "module": module,
            "def_line": node.lineno,
            "rows": rows,
        }
        if contract >= CONTRACT_V2:
            # Additive discriminators, emitted only where a consumer asked for the newer grammar, so a
            # CONTRACT_V1 payload stays byte-identical to the pre-amendment parser (§A.7 / §D.7).
            entry["role"] = role
            entry["contract_version"] = contract
        if role == "handler":
            # ADR 0104 §2.3 P2: the handler's recognized message type, for the field-picker scope. Emitted
            # only when present, so a typeless handler / an older contract is byte-identical (→ generic
            # scope). A router selects destinations rather than editing fields — it has no field picker to
            # scope and no transform verbs in its palette (§D.6) — so no type hint is emitted for one.
            accepts = _handler_accepts(node)
            if accepts is not None:
                entry["accepts_types"] = accepts
            inferred = _handler_inferred_type(node)
            if inferred is not None:
                entry["inferred_type"] = inferred
        handlers.append(entry)
    return handlers


# --- element discovery (handler / router) ------------------------------------


class _Ctx(NamedTuple):
    """The per-def parse context threaded through the partition.

    ``role`` is the enclosing def's decorator role ("handler" / "router") — it is what disambiguates a
    ``return []`` (an explicit FILTER in a handler, ROUTED NOWHERE in a router; ADR 0076 §D.4).
    ``contract`` is the requested grammar version, so a v1 consumer never receives a v2 row kind."""

    source: str
    lines: list[str]
    role: str
    contract: int


def _element_name(
    node: ast.FunctionDef | ast.AsyncFunctionDef, contract: int
) -> tuple[str, str] | None:
    """``(registered name, role)`` for a projectable def, or None for anything else.

    A ``@router`` is projectable only at :data:`CONTRACT_V2` and above (ADR 0076 Amendment D); below it
    the parser behaves exactly as the shipped one did and skips routers entirely."""
    name = _handler_name(node)
    if name is not None:
        return name, "handler"
    if contract >= CONTRACT_V2:
        name = _router_name(node)
        if name is not None:
            return name, "router"
    return None


def _decorated_name(node: ast.FunctionDef | ast.AsyncFunctionDef, decorator: str) -> str | None:
    """The registered name of a ``@<decorator>("name")`` def, or None if it carries no such decorator.

    A decoration with a non-literal name falls back to the def name so the element still appears."""
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        if _callee_name(dec.func) != decorator:
            continue
        if (
            dec.args
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            return dec.args[0].value
        return node.name
    return None


def _handler_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """The registered name of a ``@handler("name")`` def, or None if it is not a handler."""
    return _decorated_name(node, "handler")


def _router_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """The registered name of a ``@router("name")`` def, or None if it is not a router (Amendment D)."""
    return _decorated_name(node, "router")


def _callee_name(func: ast.expr) -> str | None:
    """The bare callable name of a call target: ``handler`` for ``@handler`` and ``@mf.handler``."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


# --- handler message type (ADR 0104 §2.3 P2 — field-picker scope) -------------

#: The message-type attribute a name access contributes to an inferred type.
_TYPE_ATTRS: dict[str, str] = {
    "message_code": "code",
    "trigger_event": "trigger",
    "message_type": "type",
}


def _handler_accepts(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str] | None:
    """The literal specs from ``accepts=message_type_of("ADT^A01", …)`` on the ``@handler`` decorator, or
    None. **Authoritative** — it IS the enforced predicate, so it cannot drift from what the handler
    accepts; and ``message_type_of`` returns an opaque runtime predicate, so the decorator AST is the only
    place the specs are readable."""
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call) or _callee_name(dec.func) != "handler":
            continue
        for kw in dec.keywords:
            if (
                kw.arg == "accepts"
                and isinstance(kw.value, ast.Call)
                and _callee_name(kw.value.func) == "message_type_of"
            ):
                specs = [
                    a.value
                    for a in kw.value.args
                    if isinstance(a, ast.Constant) and isinstance(a.value, str)
                ]
                return specs or None
    return None


def _type_attr(expr: ast.expr) -> str | None:
    """The message-type attribute of ``<name>.message_code`` / ``.trigger_event`` / ``.message_type`` (the
    handler's message param, any receiver name), or None."""
    if (
        isinstance(expr, ast.Attribute)
        and isinstance(expr.value, ast.Name)
        and expr.attr in _TYPE_ATTRS
    ):
        return expr.attr
    return None


def _handler_inferred_type(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str] | None:
    """A best-effort ``{"code"?, "trigger"?}`` from a LEADING type guard. **Advisory only** (a handler fed
    mixed types makes it wrong), so the picker ranks-not-removes and always keeps an All-segments escape.
    Conservative: only the first non-docstring statement, only a direct
    ``msg.message_code``/``.trigger_event``/``.message_type`` compare to a string constant — a
    ``msg["MSH-9.2"]`` subscript or a computed value is NOT inferred (the ``accepts=`` decorator is the
    authoritative source)."""
    body = [
        s
        for s in node.body
        if not (
            isinstance(s, ast.Expr)
            and isinstance(s.value, ast.Constant)
            and isinstance(s.value.value, str)
        )
    ]
    if not body or not isinstance(body[0], ast.If):
        return None
    found: dict[str, str] = {}
    for cmp in ast.walk(body[0].test):
        if not isinstance(cmp, ast.Compare) or not cmp.comparators:
            continue
        left, right = cmp.left, cmp.comparators[0]
        attr = _type_attr(left)
        const = (
            right.value
            if isinstance(right, ast.Constant) and isinstance(right.value, str)
            else None
        )
        if attr is None:
            attr = _type_attr(right)
            const = (
                left.value
                if isinstance(left, ast.Constant) and isinstance(left.value, str)
                else None
            )
        if attr is None or const is None:
            continue
        key = _TYPE_ATTRS[attr]
        if key == "type":  # message_type is the whole MSH-9 ("CODE^TRIGGER" or a bare "CODE")
            code, _sep, trig = const.partition("^")
            if code:
                found.setdefault("code", code)
            if trig:
                found.setdefault("trigger", trig)
        else:
            found.setdefault(key, const)
    return found or None


# --- partition (the coverage invariant) --------------------------------------


def _body_end(node: ast.FunctionDef | ast.AsyncFunctionDef, ctx: _Ctx) -> int:
    """The last line of the def body the partition covers.

    At :data:`CONTRACT_V1` this is ``node.end_lineno`` — the AST fixes it to the last *statement's* last
    line, so a comment written after it falls outside every row and is not rendered at all (Amendment A
    §A.3 defect 1: the Add-palette's own Comment step, inserted after the last statement, disappears).
    At :data:`CONTRACT_V2` the range is extended over the trailing run of blank/comment lines that are
    indented **into the def body**, so that comment projects as a ``note`` row.

    The indent test is what keeps the extension inside the def: a comment at column 0 (or shallower than
    the body) belongs to module scope — a section banner above the next element — and is left outside,
    as are the shebang/SPDX/import lines the partition has never covered (§A.5 "no module scope")."""
    end = node.end_lineno or node.body[0].lineno
    if ctx.contract < CONTRACT_V2:
        return end
    body_indent = len(_leading_ws(ctx.lines[node.body[0].lineno - 1]).expandtabs())
    last = end
    for lineno in range(end + 1, len(ctx.lines) + 1):
        text = ctx.lines[lineno - 1]
        stripped = text.strip()
        if not stripped:
            continue  # a blank line is carried only if a qualifying comment follows it
        if not stripped.startswith("#"):
            break
        if len(_leading_ws(text).expandtabs()) < body_indent:
            break  # dedented out of the body — module scope
        last = lineno
    return last


def _partition_suite(
    stmts: list[ast.stmt], lo: int, hi: int, nesting: int, ctx: _Ctx, suite: str
) -> list[dict[str, Any]]:
    """Tile the inclusive line range ``[lo, hi]`` occupied by ``stmts`` into contiguous rows.

    Every line in ``[lo, hi]`` lands in exactly one row: each statement contributes its own row(s), and
    any gap between them (blank lines, standalone comments) is tiled by :func:`_tile_gap` — one ``code``
    row at :data:`CONTRACT_V1`, split into ``note``/``code`` sub-rows at :data:`CONTRACT_V2`.

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
            rows.extend(_tile_gap(cursor, g_start - 1, nesting, ctx))
        if len(group) == 1:
            emitted = _emit_stmt(group[0], nesting, ctx)
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
        rows.extend(_tile_gap(cursor, hi, nesting, ctx))
    # Stamp the in-suite code rows (gaps/trailing) that were appended directly, not via `_emit_stmt`.
    for row in rows:
        row.setdefault("suite", suite)
    return rows


def _tile_gap(lo: int, hi: int, nesting: int, ctx: _Ctx) -> list[dict[str, Any]]:
    """Tile a statement-free line range ``[lo, hi]`` — blank lines and standalone comments.

    At :data:`CONTRACT_V1` the whole range is one ``code`` row, exactly as the shipped parser emitted it.
    At :data:`CONTRACT_V2` a **run of standalone comment lines at the same indent** becomes a ``note``
    row (ADR 0076 §A.1) and everything else stays a ``code`` row; the sub-rows are contiguous and
    exhaustive over the same exact range, so the coverage partition (§6 gate 1) is preserved by
    construction (§A.4).

    A **pragma** comment (``# noqa``, ``# fmt: off``, …) always forms its OWN note row rather than
    joining a neighbouring run: it is functional code and must stay individually read-only, and folding
    it into an editable run would let one text edit relocate or destroy it (§A.4)."""
    if ctx.contract < CONTRACT_V2 or hi < lo:
        return [_code_row(lo, hi, nesting)]
    rows: list[dict[str, Any]] = []
    run: list[int] = []  # the comment lines accumulated for the pending note row

    def flush() -> None:
        if run:
            rows.append(_note_row(run[0], run[-1], nesting, ctx.lines))
            run.clear()

    for lineno in range(lo, hi + 1):
        text = ctx.lines[lineno - 1] if lineno - 1 < len(ctx.lines) else ""
        if not text.strip().startswith("#"):
            flush()
            # Blank / unclassifiable lines stay code rows; `_merge_code_rows` coalesces the run later.
            rows.append(_code_row(lineno, lineno, nesting))
            continue
        pragma = _is_pragma(text)
        # Break the run when the indent changes (a different suite reading) or a pragma is involved on
        # either side — a pragma is always alone.
        if run and (
            pragma
            or _is_pragma(ctx.lines[run[-1] - 1])
            or _leading_ws(ctx.lines[run[-1] - 1]) != _leading_ws(text)
        ):
            flush()
        run.append(lineno)
    flush()
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


def _emit_stmt(s: ast.stmt, nesting: int, ctx: _Ctx) -> list[dict[str, Any]]:
    """Rows tiling exactly ``[s.lineno, s.end_lineno]`` for one statement (recursing into control blocks)."""
    if isinstance(s, ast.If):
        return _emit_if(s, nesting, "if", ctx)
    if isinstance(s, ast.For | ast.AsyncFor):
        return _emit_for(s, nesting, ctx)
    if isinstance(s, ast.Raise):
        # ``raise ...`` — a recognized single-line control row (ADR 0106); no nested body. It maps to the
        # post-ACK ERROR/dead-letter + AlertSink path and does NOT NAK the already-ACKed sender.
        return [
            _control_row(
                "raise",
                _src(s.exc, ctx.source) if s.exc is not None else None,
                True,
                s.lineno,
                s.end_lineno or s.lineno,
                nesting,
            )
        ]
    recognized = _classify_simple(s, nesting, ctx)
    if recognized is not None:
        return [recognized]
    return [_code_row(s.lineno, s.end_lineno or s.lineno, nesting)]


def _header_end(header_line: int, body_first: int, ctx: _Ctx) -> int:
    """The last line of a control HEADER, shrunk off any comment/blank lines that lead its body.

    The shipped parser emits a control header as ``[node.lineno, body_first - 1]``, so a comment written
    as the FIRST line of an ``if``/``for``/``else`` body is swallowed into the header row (Amendment A
    §A.4 — "control-header spans must shrink, and that is a fixture-visible contract change"). At
    :data:`CONTRACT_V2` the trailing run of comment/blank lines is handed back to the BODY suite, where
    it tiles at the body's nesting as ``note``/``code`` rows.

    Scanning backwards is safe for a multi-line header (``if (\\n  a\\n):``): the header's own last line
    ends in ``:`` — never a bare comment — so the scan stops there. The header keeps at least its own
    first line, so the span can never invert."""
    if ctx.contract < CONTRACT_V2:
        return body_first - 1
    end = body_first - 1
    while end > header_line:
        text = ctx.lines[end - 1] if end - 1 < len(ctx.lines) else ""
        if text.strip() and not text.strip().startswith("#"):
            break
        end -= 1
    return end


def _emit_if(node: ast.If, nesting: int, kind: str, ctx: _Ctx) -> list[dict[str, Any]]:
    """Rows for an ``if``/``elif`` block: a control header row, the nested body, then its ``elif``/``else``."""
    first = node.body[0].lineno
    if first <= node.lineno:
        # Inline suite (``if x: y``) — the bounded grammar does not cover it; degrade to one code row.
        return [_code_row(node.lineno, node.end_lineno or node.lineno, nesting)]
    match = _classify_if_control(node.test, ctx.source)
    recognized = _is_bounded(node.test) or match is not None
    header_end = _header_end(node.lineno, first, ctx)
    rows = [
        _control_row(
            kind,
            _src(node.test, ctx.source),
            recognized,
            node.lineno,
            header_end,
            nesting,
            match.label if match else None,
            match.operand if match else None,
        )
    ]
    body_end = node.body[-1].end_lineno or first
    # The body is a child suite keyed by this block's header line (unique per module). It starts at the
    # line after the (possibly shrunk) header, so a leading comment tiles INSIDE the body, at its nesting.
    rows.extend(
        _partition_suite(node.body, header_end + 1, body_end, nesting + 1, ctx, str(node.lineno))
    )
    rows.extend(_emit_orelse(node, body_end, nesting, ctx))
    return rows


def _emit_orelse(node: ast.If, body_end: int, nesting: int, ctx: _Ctx) -> list[dict[str, Any]]:
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
            rows.extend(_tile_gap(body_end + 1, first_or.lineno - 1, nesting, ctx))
        rows.extend(_emit_if(first_or, nesting, "elif", ctx))
        return rows

    # Plain ``else`` block. Locate the ``else:`` header line in the region before the else body.
    end_lineno = node.end_lineno or body_end
    else_body_first = first_or.lineno
    else_line = _find_keyword(ctx.lines, body_end + 1, else_body_first - 1, "else")
    if else_line is None or else_body_first <= else_line:
        # No locatable header, or an inline ``else: y`` — degrade the whole tail to one code row.
        return [_code_row(body_end + 1, end_lineno, nesting)]
    if else_line > body_end + 1:
        rows.extend(_tile_gap(body_end + 1, else_line - 1, nesting, ctx))
    else_header_end = _header_end(else_line, else_body_first, ctx)
    rows.append(_control_row("else", None, True, else_line, else_header_end, nesting))
    else_body_end = orelse[-1].end_lineno or else_body_first
    # The else body is its own suite, keyed by the ``else:`` header line.
    rows.extend(
        _partition_suite(
            orelse, else_header_end + 1, else_body_end, nesting + 1, ctx, str(else_line)
        )
    )
    return rows


def _emit_for(node: ast.For | ast.AsyncFor, nesting: int, ctx: _Ctx) -> list[dict[str, Any]]:
    """Rows for a ``for`` block: a control header row (recognized iff a Message iteration) + nested body.

    A ``for ... else`` tail (rare) is emitted as a trailing ``code`` row so the partition stays exact."""
    first = node.body[0].lineno
    if first <= node.lineno:
        return [_code_row(node.lineno, node.end_lineno or node.lineno, nesting)]
    test_src = f"{_src(node.target, ctx.source)} in {_src(node.iter, ctx.source)}"
    match = _classify_for_control(node)
    recognized = _is_message_iteration(node.iter) or match is not None
    header_end = _header_end(node.lineno, first, ctx)
    rows = [
        _control_row(
            "for",
            test_src,
            recognized,
            node.lineno,
            header_end,
            nesting,
            match.label if match else None,
            match.operand if match else None,
        )
    ]
    body_end = node.body[-1].end_lineno or first
    rows.extend(
        _partition_suite(node.body, header_end + 1, body_end, nesting + 1, ctx, str(node.lineno))
    )
    end_lineno = node.end_lineno or body_end
    if node.orelse and body_end < end_lineno:
        rows.append(_code_row(body_end + 1, end_lineno, nesting))
    return rows


# --- simple-statement classification -----------------------------------------


def _classify_simple(s: ast.stmt, nesting: int, ctx: _Ctx) -> dict[str, Any] | None:
    """A recognized ``action`` / ``lookup`` / ``send`` / ``route`` row for a simple statement, or None."""
    line_start = s.lineno
    line_end = s.end_lineno or s.lineno
    source = ctx.source

    if ctx.role == "router":
        # A router SELECTS DESTINATIONS; it does not mutate ``msg`` (ADR 0076 §D.6). Its only recognized
        # simple statement is the routing return — every transform verb, lookup and diagnostic stays a
        # read-only ``code`` row, which is also why a ``db_lookup``/``fhir_lookup`` in a router body never
        # projects as a ``lookup`` row (those RAISE outside a live Handler, ADR 0010/0043).
        if isinstance(s, ast.Return):
            return _route_row(s.value, line_start, line_end, nesting)
        return None

    # ``return Send(...)`` / ``return [Send(...), ...]`` — a send row.
    if isinstance(s, ast.Return) and s.value is not None:
        # ``return []`` / ``return ()`` — an explicit filter (drop the message → FILTERED). It also yields
        # empty outbounds, so it is distinguished from a dynamic-destination ``Send`` (which likewise has
        # empty outbounds) by an additive ``filtered`` flag; the store-finalizer keys on ``filtered``,
        # never on emptiness of ``outbounds`` (ADR 0106). Older consumers ignore the extra field.
        if isinstance(s.value, ast.List | ast.Tuple) and not s.value.elts:
            return {
                "kind": "send",
                "outbounds": [],
                "filtered": True,
                "line_start": line_start,
                "line_end": line_end,
                "nesting": nesting,
            }
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

    # ``sends.append(Send(...))`` — an accumulator fan-out send (ADR 0104 copy-on-Send). It is the SAME
    # editable ``send`` row as a returned ``Send``, but positioned AT the append statement, not at the
    # return — so a handler can deliver to several outbounds and interleave transforms between sends
    # ("send earlier"). Owner: the ``Send`` is never authored inside a ``return`` (the accumulator's
    # ``sends = []`` init and bare ``return sends`` footer are read-only scaffold, tagged post-partition).
    # Sits AFTER the Return block so ``return Send``/``return [..]``/``return []`` still match first and
    # are byte-identical; it strictly upgrades what is otherwise a ``code`` row (``append`` is in no
    # vocabulary set and the receiver is not ``msg``, so the generic path below already yields None).
    append_outbounds = _append_send_outbounds(s)
    if append_outbounds is not None:
        return {
            "kind": "send",
            "outbounds": append_outbounds,
            # An additive discriminator: this send is a mid-body ``sends.append(...)`` action, NOT a
            # terminal ``return Send(...)``. The webview keys insert-after / return-ness on it (an append
            # is a normal middle-of-body step; a returned send suppresses insert-after). Absent on every
            # returned send + older contract, so estate rows are byte-identical.
            "appended": True,
            "line_start": line_start,
            "line_end": line_end,
            "nesting": nesting,
        }

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

    # ADR 0089 Phase A: a native ``msg.set(...)`` / ``msg.delete_segments(...)`` write (a bare expression
    # statement) becomes the SAME editable action row as its wrapper equivalent, without the module being
    # rewritten. The one native assignment recognized is row 4's read, ``name = msg.field(path)``.
    native = _recognize_native_stmt(s)
    if native is not None:
        return _native_action_row(native, s, nesting, source, ctx.contract)

    name = _callee_name(call.func)
    if name in _ACTIONS and isinstance(s, ast.Expr):
        return _attach_param_modes(
            {
                "kind": "action",
                "action": name,
                "params": _render_params(call, _ACTION_PARAMS[name], source),
                "literal_params": _literal_param_names(call, _ACTION_PARAMS[name]),
                "line_start": line_start,
                "line_end": line_end,
                "nesting": nesting,
            },
            _rendered_param_nodes(call, _ACTION_PARAMS[name]),
            ctx.contract,
        )
    if name in _DIAGNOSTICS and isinstance(s, ast.Expr):
        return _attach_param_modes(
            {
                "kind": "diagnostic",
                "call": name,
                "params": _render_params(call, _DIAGNOSTIC_PARAMS[name], source),
                "literal_params": _literal_param_names(call, _DIAGNOSTIC_PARAMS[name]),
                "line_start": line_start,
                "line_end": line_end,
                "nesting": nesting,
            },
            _rendered_param_nodes(call, _DIAGNOSTIC_PARAMS[name]),
            ctx.contract,
        )
    if name in _LOOKUPS:
        row: dict[str, Any] = _attach_param_modes(
            {
                "kind": "lookup",
                "call": name,
                "params": _render_params(call, _LOOKUP_PARAMS[name], source),
                "literal_params": _literal_param_names(call, _LOOKUP_PARAMS[name]),
                "line_start": line_start,
                "line_end": line_end,
                "nesting": nesting,
            },
            _rendered_param_nodes(call, _LOOKUP_PARAMS[name]),
            ctx.contract,
        )
        if assign_to:
            row["assign_to"] = assign_to
        return row
    return None


def _route_row(
    value: ast.expr | None, line_start: int, line_end: int, nesting: int
) -> dict[str, Any]:
    """The ``route`` row for a ``@router``'s return statement (ADR 0076 §D.3 / §D.4).

    ``handlers`` carries the selected **handler** names — a different namespace from a ``send`` row's
    ``outbounds`` (outbound-connection names, a different pipeline stage), which is why this is a new
    kind rather than a widened ``send`` (§D.5). Its literal-or-empty rule mirrors ``send``'s: a
    non-literal element yields ``handlers: []``.

    ``unrouted: true`` is the additive discriminator for a **routed-nowhere** return (``return []`` /
    ``()`` / ``None`` / a bare ``return``) — the store disposition **UNROUTED**: logged, never dropped,
    and distinct from a handler's ``filtered``. A DYNAMIC return (``return [pick(msg)]``) also yields an
    empty list but carries **no** ``unrouted``, because the lens cannot see whether it routes."""
    row: dict[str, Any] = {
        "kind": "route",
        "handlers": [],
        "line_start": line_start,
        "line_end": line_end,
        "nesting": nesting,
    }
    if value is None or (isinstance(value, ast.Constant) and value.value is None):
        row["unrouted"] = True
        return row
    if isinstance(value, ast.List | ast.Tuple):
        if not value.elts:
            row["unrouted"] = True
            return row
        names = [
            e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ]
        # Partial literalness is NOT partially captured: one dynamic element makes the whole selection
        # unknowable, so the row degrades to "dynamic" rather than asserting the names it happened to see.
        if len(names) == len(value.elts):
            row["handlers"] = names
        return row
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        row["handlers"] = [value.value]
    return row


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


def _match_append_send(s: ast.stmt) -> tuple[str, ast.Call] | None:
    """``(receiver_name, inner Send call)`` for a ``NAME.append(Send(...))`` statement, or None.

    Recognizes the accumulator copy-on-Send fan-out idiom (ADR 0104): a bare
    ``sends.append(Send("OB", msg))`` expression statement whose receiver is a **plain name** (never
    ``self.sends`` / ``d["k"]`` — matched TIGHTLY so an escaped/aliased collector honestly degrades to a
    ``code`` row), with a single positional argument that is a ``Send(...)`` call and no keyword args.
    Returns None for anything outside that shape."""
    if not isinstance(s, ast.Expr):
        return None
    call = s.value
    if not isinstance(call, ast.Call):
        return None
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == "append"):
        return None
    if not isinstance(func.value, ast.Name):  # bare-name receiver only (no subscript/attribute)
        return None
    if call.keywords or len(call.args) != 1 or isinstance(call.args[0], ast.Starred):
        return None
    send = call.args[0]
    if not (isinstance(send, ast.Call) and _callee_name(send.func) == "Send"):
        return None
    return func.value.id, send


def _append_send_outbounds(s: ast.stmt) -> list[str] | None:
    """Destination names for a ``NAME.append(Send(...))`` accumulator send, or None (→ ``code`` row).

    A literal string destination yields ``[dest]``; a non-literal (dynamic) destination yields ``[]`` —
    the SAME literal check as :func:`_send_outbounds`, so a constructed send has parity with a returned
    one. Returns the list (never None) once the append-Send shape matches; None for any non-match."""
    match = _match_append_send(s)
    if match is None:
        return None
    send = match[1]
    if send.args and isinstance(send.args[0], ast.Constant) and isinstance(send.args[0].value, str):
        return [send.args[0].value]
    return []


def _own_scope_nodes(node: ast.AST) -> list[ast.AST]:
    """Every descendant of ``node`` in its OWN scope — recursing through control blocks (if/for/while/
    with/try) but NOT into nested ``def``/``lambda`` scopes (a different scope). Mirrors what the
    partitioner classifies, so accumulator analysis matches the visible rows (a closure-local append is
    neither a visible send row nor evidence of the handler's own accumulator)."""
    out: list[ast.AST] = []
    for child in ast.iter_child_nodes(node):
        out.append(child)
        if not isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            out.extend(_own_scope_nodes(child))
    return out


def _delivering_accumulators(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names that form a clean, DELIVERING fan-out accumulator in this handler's own scope: exactly one
    top-level ``NAME = []`` init, a top-level bare ``return NAME``, ``NAME`` assigned nowhere else in the
    own scope, and not a parameter. Only such a name genuinely delivers what is appended to it — so only
    its appends are recognized as send rows and only its init/footer are tagged scaffold; an append into a
    discarded, aliased, rebound, or closure-local list honestly degrades to a read-only code row (ADR 0089
    §4). Purely static (never imports/executes)."""
    inits: dict[str, int] = {}
    returned: set[str] = set()
    for s in node.body:
        if (
            isinstance(s, ast.Assign)
            and len(s.targets) == 1
            and isinstance(s.targets[0], ast.Name)
            and isinstance(s.value, ast.List)
            and not s.value.elts
        ):
            inits[s.targets[0].id] = inits.get(s.targets[0].id, 0) + 1
        elif isinstance(s, ast.Return) and isinstance(s.value, ast.Name):
            returned.add(s.value.id)
    if not inits:
        return set()
    a = node.args
    params = {
        arg.arg
        for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg)
        if arg is not None
    }
    assigned: dict[str, int] = {}
    for n in _own_scope_nodes(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            assigned[n.id] = assigned.get(n.id, 0) + 1
    return {
        name
        for name, count in inits.items()
        if count == 1 and name in returned and name not in params and assigned.get(name, 0) == 1
    }


# --- parameter rendering -----------------------------------------------------


def _rendered_param_nodes(call: ast.Call, param_names: list[str]) -> list[tuple[str, ast.expr]]:
    """``(emitted param name, the node its value comes from)`` for every param the row will carry.

    ONE name mapping, consumed by :func:`_render_params` and :func:`_attach_param_modes` alike. AC-M1
    requires ``param_modes`` to be TOTAL over ``params``, and a second copy of this walk would make that
    totality a coincidence that holds until one copy learns a name the other does not."""
    mapped: list[tuple[str, ast.expr]] = []
    for i, arg in enumerate(call.args):
        if isinstance(arg, ast.Starred):
            mapped.append((f"*{param_names[i] if i < len(param_names) else f'arg{i}'}", arg.value))
            continue
        name = param_names[i] if i < len(param_names) else f"arg{i}"
        if name == "msg":
            continue
        mapped.append((name, arg))
    for kw in call.keywords:
        mapped.append(("**kwargs" if kw.arg is None else kw.arg, kw.value))
    return mapped


def _render_params(call: ast.Call, param_names: list[str], source: str) -> dict[str, Any]:
    """Map a call's positional + keyword args to ``{param: value}``, dropping the leading ``msg``.

    A literal arg renders to its Python value (JSON scalar or list of scalars); anything else renders to
    its verbatim source text (a bounded ``Message`` read such as ``msg["PID-5"]``)."""
    return {
        name: _render_value(node, source) for name, node in _rendered_param_nodes(call, param_names)
    }


def _attach_param_modes(
    row: dict[str, Any], nodes: list[tuple[str, ast.expr]], contract: int
) -> dict[str, Any]:
    """Add Amendment E's ``param_modes``, ``param_parts`` and ``template_params`` at :data:`CONTRACT_V2`.

    ``nodes`` is ``(emitted param name, argument node)`` for EVERY param the row's ``params`` carries --
    :func:`_rendered_param_nodes` for a wrapper call, slots plus display keywords for a native one -- so
    the map is total over ``params`` (AC-M1). That covers the synthetic ``*arg1`` / ``**kwargs`` keys and
    the extra positionals past the signature that ``literal_params`` deliberately skips. That widening is
    correct rather than sloppy because the two fields answer DIFFERENT questions (E.4, E.10):
    ``literal_params`` answers *is this argument editable*, ``param_modes`` answers *what shape is it* —
    and a shape exists for an argument no edit may splice.

    ``param_parts`` maps every ``templated`` param, and only those, to its structured parts
    (:func:`_template_parts`), or to ``None`` when the interpolation has no parts form. It is the READ
    half of the templated edit spec (``{"parts": [...]}`` in ``set_params``), and it exists so the IDE
    never has to take an f-string apart itself: a TypeScript reading of Python source would be the second
    grammar E.5 refuses. Total over the templated params, so a consumer never interprets a missing key.

    ``template_params`` lists the params a ``{"parts": [...]}`` write is accepted into: a value
    parameter (:data:`_TEMPLATE_PARAMS`) whose current mode is ``static`` or ``templated``. It is the
    templated counterpart of ``literal_params`` -- the engine's own answer to "may the IDE offer this",
    so the IDE never re-derives the rule. A param with parts that is NOT listed (a lookup statement, a
    ``log_note`` template) still shows its parts; it just cannot be written as a template.

    GATED, because AC-M7 requires a contract version that emits none of the three: :data:`CONTRACT_V1` stays
    byte-identical to the pre-amendment parser exactly as it does across Amendments A and D (§A.7 /
    §D.7). Both ride :data:`CONTRACT_V2` rather than minting a version of their own because E.8 puts the
    FORWARD skew on the consumer — an older IDE keeps reading ``params``/``literal_params`` and ignores
    the keys it does not know — and the shipped extension asks for contract 2, so that is a live consumer
    rather than a hypothetical one. A version of its own would instead make an OLDER engine refuse a NEWER
    IDE outright, which is the other skew direction and not the one E.8 describes."""
    if contract >= CONTRACT_V2:
        modes = {name: _param_mode(node) for name, node in nodes}
        row["param_modes"] = modes
        row["param_parts"] = {
            name: _template_parts(node) for name, node in nodes if modes[name] == MODE_TEMPLATED
        }
        # A multi-line argument is left out: every set_params splice refuses one (it would change the
        # line count), so listing it would offer an edit certain to fail.
        row["template_params"] = [
            name
            for name, node in nodes
            if modes[name] != MODE_DYNAMIC
            and (node.end_lineno or node.lineno) == node.lineno
            and _template_ok(row["kind"], row.get("action"), name)
        ]
    return row


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
        if i >= len(param_names):
            # An extra positional beyond the signature (e.g. log_note's *values operands) is
            # recognized-only, never inline-editable — don't advertise it to the IDE (ADR 0106 §5 K),
            # which would offer an operand as editable then hit the rewrite-layer refusal (F6).
            continue
        name = param_names[i]
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


# --- ADR 0076 Amendment E: per-argument value classes (BACKLOG #237) ----------

#: The three per-argument modes of ADR 0076 Amendment E, section E.4. ``static`` is a literal,
#: ``templated`` is the bounded interpolation E.5 admits, and ``dynamic`` is everything else -- an
#: OPEN set, which is why E.3 keeps it read-only: a rewriter cannot round-trip an open set.
MODE_STATIC = "static"
MODE_TEMPLATED = "templated"
MODE_DYNAMIC = "dynamic"


def _is_bounded_message_read(node: ast.expr) -> bool:
    """Whether ``node`` is a bounded ``Message`` read -- ``msg["LIT"]`` or ``msg.field(LIT, ...)``.

    STRICTER THAN :func:`_is_bounded`, deliberately. That one walks a tree asking whether anything
    forbidden appears, which is an OPEN predicate: it admits every shape nobody thought to exclude.
    ADR 0076 E.5 requires a CLOSED set, for the same reason ``scripts/quality/lens_coverage.py``
    refuses to reimplement recognition -- an open predicate is a second grammar that drifts from the
    first.

    Erring strict is the safe direction and the asymmetry is the point. A read this WRONGLY REJECTS
    is classified ``dynamic``, which renders read-only exactly as it does today (E.5: "not a
    degradation and not an error"). A read it wrongly ACCEPTED would license the rewriter to emit
    something it cannot round-trip, which is what E.6.3 exists to forbid.
    """
    if isinstance(node, ast.Subscript):
        return _is_msg_subscript(node)
    if isinstance(node, ast.Call):
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "field":
            return False
        if not (isinstance(func.value, ast.Name) and func.value.id == "msg"):
            return False
        if node.keywords or not node.args:
            return False
        return all(isinstance(a, ast.Constant) for a in node.args)
    return False


def _is_msg_subscript(node: ast.expr) -> bool:
    """Whether ``node`` is exactly ``msg["LIT"]``, a subscript read with one constant string path."""
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "msg"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    )


def _is_empty_fallback_read(node: ast.expr) -> bool:
    """Whether ``node`` is exactly ``msg["LIT"] or ""`` -- a subscript read that renders an absent field
    as empty text.

    ADMITTED BY THE 2026-09-29 AMENDMENT NOTE (ADR 0076 E.11), and nothing wider. A bare read renders an
    absent field as the text ``None`` inside an f-string, because ``Message.field`` returns None; the
    ``or ""`` fallback is the one ``copy_field`` already writes. The operand must be the empty string
    and nothing else: ``or "N/A"`` or ``or other`` is a second value source the parts form cannot
    express, so it stays ``dynamic``. Only the subscript spelling is admitted, because it is the one
    the renderer writes."""
    return (
        isinstance(node, ast.BoolOp)
        and isinstance(node.op, ast.Or)
        and len(node.values) == 2
        and _is_msg_subscript(node.values[0])
        and isinstance(node.values[1], ast.Constant)
        and isinstance(node.values[1].value, str)
        and node.values[1].value == ""
    )


def _is_bounded_interpolation(node: ast.expr) -> bool:
    """Whether ``node`` is the ONE interpolation shape ADR 0076 E.5 admits as writable.

    An f-string whose every ``FormattedValue`` is a bounded ``Message`` read, or a subscript read with
    an empty-string fallback (:func:`_is_empty_fallback_read`, E.11), carrying **no format spec and no
    conversion**, and whose every remaining part is a constant string.

    A format spec or a conversion (``!r``/``!s``/``!a``) is excluded because each is a second rendering
    step the lens does not model: reading the emitted text back would not recover the same parts, and
    round-trip totality is a BUILD GATE under E.6.3, not a test wish.

    An f-string with no placeholders is admitted, vacuously -- E.5's condition is universally
    quantified over parts that are not there. It cannot be ``static`` (it is not ``ast.Constant``, and
    AC-M2 ties ``static`` to ``literal_params``, which tests exactly that), and it round-trips
    trivially, so ``templated`` is both the literal reading of E.5 and the harmless one.
    """
    if not isinstance(node, ast.JoinedStr):
        return False
    for part in node.values:
        if isinstance(part, ast.Constant):
            if not isinstance(part.value, str):
                return False
            continue
        if isinstance(part, ast.FormattedValue):
            # ``conversion`` is -1 when absent; 114/115/97 are !r/!s/!a.
            if part.conversion != -1 or part.format_spec is not None:
                return False
            if not (_is_bounded_message_read(part.value) or _is_empty_fallback_read(part.value)):
                return False
            continue
        return False
    return True


def _param_mode(node: ast.expr) -> str:
    """The ADR 0076 E.4 mode of one argument: ``static``, ``templated`` or ``dynamic``.

    ORDER MATTERS. ``static`` is tested first so it stays exactly ``isinstance(node, ast.Constant)`` --
    AC-M2 requires it to agree with ``literal_params`` in BOTH directions, and ``literal_params`` is
    that same test. Any looser definition here makes the newer field a second, drifting truth about
    which arguments are literals.
    """
    if isinstance(node, ast.Constant):
        return MODE_STATIC
    if _is_bounded_interpolation(node):
        return MODE_TEMPLATED
    return MODE_DYNAMIC


# --- the templated edit spec: structured parts (ADR 0076 E.4-E.6, BACKLOG #237) ----------------------
#
# A templated argument travels in BOTH directions as a list of parts, never as Python source:
#
#     [{"text": "MRN: "}, {"path": "PID-3.1"}, {"text": " / "}, {"path": "PID-5.1"}]
#
# ``lens parse`` emits it (``param_parts``) and ``set_params`` accepts it (``{"parts": [...]}``). The
# engine alone renders it to an f-string and reads an f-string back to it, and the rendered text must
# pass the EXISTING classifier (:func:`_is_bounded_interpolation`) before it is spliced. So the IDE
# never builds or re-classifies Python source, which is what keeps this from becoming the second
# grammar E.5 refuses.

#: The two part kinds. ``text`` is literal text; ``path`` is one bounded read, written as
#: ``msg[...] or ""`` so an absent field is empty text (ADR 0076 E.11).
PART_TEXT = "text"
PART_PATH = "path"

#: The ``(action, param)`` pairs a templated value may be WRITTEN into: the parameters that carry a
#: field VALUE. A CLOSED list, for the reason E.5 closes its admitted set, and strict on purpose. Every
#: other argument is a locator or a setting -- a path, a segment id, a separator, an index, a width, a
#: mode, a date format -- and a template there lets inbound message content choose WHICH field is
#: overwritten or feed a string where an int belongs. A lookup or diagnostic argument is never here:
#: :func:`_refuse_templated_write` says why. ``lens parse`` reports the result per row as
#: ``template_params``, so the IDE offers the mode only where the engine will accept it.
_TEMPLATE_PARAMS = frozenset(
    {
        ("set_field", "value"),
        ("add_repetition", "value"),
        ("append_to_field", "suffix"),
        ("replace_literal", "new"),
    }
)


def _template_ok(kind: str, action: str | None, pname: str) -> bool:
    """Whether a templated value may be written into ``pname`` of a ``kind`` row (see above)."""
    return kind == "action" and (action, pname) in _TEMPLATE_PARAMS


def _read_path(node: ast.expr) -> str | None:
    """The path a bounded read names, when the read is exactly a path read, else None.

    ``msg["X"] or ""``, ``msg["X"]`` and ``msg.field("X")`` all name path ``X``. The renderer writes
    the first (E.11), which renders an absent field as empty text. The other two are older spellings a
    hand-written template may carry: ``Message.__getitem__`` is ``self.field(path)``, so they read the
    same value, but an absent field renders as the text ``None``. Any template write, including one
    that resends the same parts, rewrites them to the fallback form, which is the fix E.11 was ruled
    for. Only a template whose reads are ALL already in the fallback form is left alone when its
    parts are resent unchanged. A ``msg.field`` call with any other argument list has no parts form."""
    if isinstance(node, ast.BoolOp) and _is_empty_fallback_read(node):
        node = node.values[0]
    if (
        isinstance(node, ast.Subscript)
        and _is_msg_subscript(node)
        and isinstance(node.slice, ast.Constant)
    ):
        return str(node.slice.value)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "field"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "msg"
        and not node.keywords
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return node.args[0].value
    return None


def _normalize_parts(parts: list[dict[str, str]]) -> list[dict[str, str]]:
    """``parts`` with adjacent text runs merged and empty text runs dropped -- the canonical form.

    Two part lists that render the same source are equal after this, so it is the equality round-trip
    totality (E.6.3, AC-M4) is stated over. The parser needs it too: CPython may split one literal run
    of an f-string into several ``Constant`` nodes around an escaped brace."""
    out: list[dict[str, str]] = []
    for part in parts:
        if PART_TEXT in part:
            if not part[PART_TEXT]:
                continue
            if out and PART_TEXT in out[-1]:
                out[-1] = {PART_TEXT: out[-1][PART_TEXT] + part[PART_TEXT]}
                continue
        out.append(dict(part))
    return out


def _template_parts(node: ast.expr) -> list[dict[str, str]] | None:
    """The structured parts of a ``templated`` argument, or None when it has no parts form.

    None for anything :func:`_is_bounded_interpolation` rejects, and for an admitted shape the edit spec
    could not send back: a ``msg.field(...)`` read whose arguments are not exactly one path string, a
    path :func:`_check_parts_spec` refuses, or an f-string with no read at all. Such an argument is
    still ``templated`` (E.5 admits it), so it keeps its mode; it is just not editable as parts. So a
    non-None result is always a WELL-FORMED ``{"parts": ...}`` value. Whether the argument accepts a
    template write at all is a separate question, answered by the row's ``template_params``."""
    if not isinstance(node, ast.JoinedStr) or not _is_bounded_interpolation(node):
        return None
    parts: list[dict[str, str]] = []
    for value in node.values:
        if isinstance(value, ast.Constant):
            # A str by construction: _is_bounded_interpolation refused any other constant part.
            parts.append({PART_TEXT: str(value.value)})
            continue
        path = _read_path(value.value) if isinstance(value, ast.FormattedValue) else None
        if path is None:
            return None
        parts.append({PART_PATH: path})
    try:
        return _check_parts_spec(parts, "")
    except LensRewriteError:
        return None


def _is_encodable(text: str) -> bool:
    """Whether ``text`` survives UTF-8 encoding (a lone surrogate from a JSON ``\\udXXX`` does not)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _escape_template_text(text: str, quote: str) -> str:
    """``text`` as the body of an f-string literal run delimited by ``quote``, value-preserving.

    Braces double, a backslash and the delimiting quote are escaped, and every character Python would not
    print raw -- controls, line and paragraph separators, format characters -- becomes an escape. That
    keeps the argument on ONE physical line under both the engine's newline model and an editor's, and
    the value the f-string evaluates to is exactly ``text``."""
    out: list[str] = []
    for ch in text:
        if ch in "{}":
            out.append(ch * 2)
        elif ch == "\\":
            out.append("\\\\")
        elif ch == quote:
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch.isprintable():
            out.append(ch)
        elif ord(ch) <= 0xFF:
            out.append(f"\\x{ord(ch):02x}")
        elif ord(ch) <= 0xFFFF:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(f"\\U{ord(ch):08x}")
    return "".join(out)


#: Characters a ``path`` part may not carry. Each would need escaping inside the ``msg['...']`` read, and
#: an HL7 path never contains one, so refusing is cheaper and clearer than a second escaping scheme.
_PATH_FORBIDDEN = frozenset("'\"\\{}")


def _check_parts_spec(parts: Any, pname: str) -> list[dict[str, str]]:
    """Validate a ``{"parts": [...]}`` value's list and return it normalized, or refuse.

    Each part is an object with exactly one key, ``text`` or ``path``, whose value is a string. A path
    is non-empty, printable, and free of quotes, backslashes and braces. Its GRAMMAR is not checked here:
    ``msg`` may be an HL7, X12 or other payload's message, each with its own path syntax, and a
    malformed path already fails that message on the error path at runtime. At least one path is required:
    a template with no read is plain text, which ``static`` mode writes as a literal, and an f-string with
    no placeholder is dead weight a linter flags."""
    if not isinstance(parts, list):
        raise LensRewriteError(
            f"parameter {pname!r}: 'parts' must be a list of part objects",
            code=REFUSAL_TEMPLATE_SHAPE,
        )
    checked: list[dict[str, str]] = []
    for i, part in enumerate(parts):
        if not isinstance(part, dict) or len(part) != 1:
            raise LensRewriteError(
                f"parameter {pname!r}: part {i} must be an object with exactly one key, "
                f"{PART_TEXT!r} or {PART_PATH!r}",
                code=REFUSAL_TEMPLATE_SHAPE,
            )
        ((key, value),) = part.items()
        if key not in (PART_TEXT, PART_PATH) or not isinstance(value, str):
            raise LensRewriteError(
                f"parameter {pname!r}: part {i} must be {{{PART_TEXT!r}: <string>}} or "
                f"{{{PART_PATH!r}: <string>}}",
                code=REFUSAL_TEMPLATE_SHAPE,
            )
        if not _is_encodable(value):
            raise LensRewriteError(
                f"parameter {pname!r}: part {i} carries a character that cannot be encoded as UTF-8",
                code=REFUSAL_TEMPLATE_SHAPE,
            )
        if key == PART_PATH and (
            not value or not value.isprintable() or any(c in _PATH_FORBIDDEN for c in value)
        ):
            raise LensRewriteError(
                f"parameter {pname!r}: part {i} path {value!r} must be non-empty, with no quote, "
                "backslash, brace or non-printable character",
                code=REFUSAL_TEMPLATE_SHAPE,
            )
        checked.append({key: value})
    normalized = _normalize_parts(checked)
    if not any(PART_PATH in part for part in normalized):
        raise LensRewriteError(
            f"parameter {pname!r}: a template needs at least one {PART_PATH!r} part - plain text is "
            "static mode, so send it as a literal value instead",
            code=REFUSAL_TEMPLATE_SHAPE,
        )
    return normalized


def _render_parts(parts: Any, pname: str) -> str:
    """Render a templated edit's structured parts to f-string source, or refuse (ADR 0076 E.5, E.6.3).

    The output is ``f"...{msg['PATH'] or ''}..."``: double quotes outside, and inside the subscript read
    with its empty-string fallback, so an absent field writes empty text rather than ``None`` (E.11).
    When the text carries more double quotes than single ones the two swap
    (``f'...{msg["PATH"] or ""}...'``), which is the choice ``ruff format`` makes, so the spliced line
    stays format-clean. Before it is returned, the EXISTING classifier must call it ``templated`` and
    read back exactly the parts that were sent.
    That is round-trip totality (E.6.3) checked on every write rather than trusted, so a renderer
    defect refuses an edit instead of splicing a shape the lens cannot read back."""
    normalized = _check_parts_spec(parts, pname)
    text = "".join(part.get(PART_TEXT, "") for part in normalized)
    outer, inner = ("'", '"') if text.count('"') > text.count("'") else ('"', "'")
    body = "".join(
        _escape_template_text(part[PART_TEXT], outer)
        if PART_TEXT in part
        else "{msg[" + inner + part[PART_PATH] + inner + "] or " + inner * 2 + "}"
        for part in normalized
    )
    rendered = "f" + outer + body + outer
    try:
        node: ast.expr | None = ast.parse(rendered, mode="eval").body
    except (SyntaxError, *_PARSER_REFUSALS):
        node = None
    if node is None or _param_mode(node) != MODE_TEMPLATED or _template_parts(node) != normalized:
        raise LensRewriteError(
            f"parameter {pname!r}: the template did not render to a bounded interpolation that reads "
            "back to the same parts - refused (no change made)",
            code=REFUSAL_TEMPLATE_SHAPE,
        )
    return rendered


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
    """Whether a ``for`` iterates a Message structure with the CORRECT arity — ``msg.segments()`` (no
    arg), ``msg.groups(boundary)`` / ``msg.repetitions(path)`` (one arg).

    A wrong-arity call such as ``msg.segments("OBX")`` (which would ``TypeError`` at runtime) is NOT a
    recognized iteration and degrades to a read-only ``code`` row instead of a false-green control row
    (ADR 0106 — the arity check the review caught was missing)."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "msg"):
        return False
    if node.keywords:
        return False
    attr = node.func.attr
    if attr == "segments":
        return not node.args
    if attr in ("groups", "repetitions"):
        return len(node.args) == 1
    return False


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


# A comment matching this allowlist is FUNCTIONAL CODE, not prose: it changes what ruff/mypy do to the
# file. Such a note is emitted with ``pragma: true`` and is read-only (ADR 0076 §A.4) — without that, a
# text edit could turn a ``fmt: off`` pragma into prose and break gate 3 (``ruff format --check``), or a
# delete could drop a standalone lint-suppression pragma and turn lint red. The list is a prefix
# allowlist, deliberately small; anything not on it is ordinary prose and stays editable.
# (The pragma spellings are written WITHOUT their leading hash in this comment on purpose: ruff reads a
# hash-prefixed suppression token inside ANY comment as a directive on that line, so naming one literally
# here would emit a lint warning about this very comment. The regex itself carries the real spellings.)
_PRAGMA_RE = re.compile(
    r"^#\s*(?:fmt\s*:\s*(?:off|on|skip)\b"
    r"|noqa\b|ruff\s*:\s*noqa\b|type\s*:\s*ignore\b"
    r"|region\b|endregion\b)"
)


def _is_pragma(line: str) -> bool:
    """Whether a standalone-comment physical ``line`` is a read-only pragma (see :data:`_PRAGMA_RE`)."""
    return _PRAGMA_RE.match(line.strip()) is not None


def _note_body(line: str) -> str:
    """The comment body of a standalone-comment physical ``line`` — everything AFTER its first ``#``.

    Verbatim (§A.1): the indent, the ``#`` run and any interior spacing are all preserved, so ``## banner``
    reads back as ``# banner`` and re-renders byte-identically. This is deliberately NOT the
    ``insert_comment`` normalizer (``text.strip().lstrip("#").strip()``), which is correct for AUTHORING
    and lossy for EDITING — it would rewrite ``## banner`` to ``# banner`` and ``#region Setup`` to
    ``# region Setup`` (§A.4)."""
    return line[line.index("#") + 1 :]


def _note_row(line_start: int, line_end: int, nesting: int, lines: list[str]) -> dict[str, Any]:
    """A ``note`` row over a run of standalone comment lines (ADR 0076 §A.1).

    ``raw`` is the physical line(s) verbatim and ``text`` is the same lines with their leading ``#``
    dropped; both join a multi-line run with ``\\n``. A note is a LEAF row with no membership semantics —
    no grouping, no collapse, no ``#region`` folding (§A.5, which is the line between this and the
    owner-declined BACKLOG #231)."""
    raws = [lines[ln - 1] if ln - 1 < len(lines) else "" for ln in range(line_start, line_end + 1)]
    return {
        "kind": "note",
        "text": "\n".join(_note_body(r) for r in raws),
        "raw": "\n".join(raws),
        "pragma": any(_is_pragma(r) for r in raws),
        "line_start": line_start,
        "line_end": line_end,
        "nesting": nesting,
    }


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
    so a run of unrecognized lines renders as a single opaque step.

    **Kind-aware (ADR 0076 §A.4).** The merge tests ``kind == "code"`` on BOTH sides, so a ``note`` row
    can never be absorbed into a neighbouring code row — which is Amendment A §A.3 defect 2 (an inserted
    Comment adjacent to any other opaque or blank line produced no row at all, the existing Code row
    silently growing by one line). It is also what keeps a note off the handler DOCSTRING: the docstring
    is ``body[0]``, a real ``ast.Expr(Constant)`` statement, so it stays its own ``code`` row (which
    ``_apply_delete_row`` already handles correctly) and a comment beneath it stays a separate note."""
    merged: list[dict[str, Any]] = []
    for row in rows:
        if (
            merged
            and row["kind"] == "code"
            # ADR 0104: keep a tagged fan-out scaffold row (sends = [] / return sends) standalone so it stays
            # muted — never coalesce it with an adjacent code statement.
            and "scaffold" not in row
            and "scaffold" not in merged[-1]
            and merged[-1]["kind"] == "code"
            and merged[-1]["nesting"] == row["nesting"]
            and merged[-1]["line_end"] + 1 == row["line_start"]
        ):
            merged[-1]["line_end"] = row["line_end"]
        else:
            merged.append(row)
    return merged


def _is_collector_init(s: ast.stmt, collectors: set[str]) -> bool:
    """Whether ``s`` is a ``NAME = []`` accumulator init for a NAME in ``collectors``.

    A LIST only (never ``()``): a tuple has no ``.append``, so a tuple collector cannot be an
    accumulator — it stays a plain code row. (The runtime no longer narrows on ``list`` at all —
    ``_partition`` accepts any non-``str`` iterable, BACKLOG #341 — but ``.append`` is the reason that
    governs here, and it is unchanged.)"""
    return (
        isinstance(s, ast.Assign)
        and len(s.targets) == 1
        and isinstance(s.targets[0], ast.Name)
        and s.targets[0].id in collectors
        and isinstance(s.value, ast.List)
        and not s.value.elts
    )


def _is_return_collector(s: ast.stmt, collectors: set[str]) -> bool:
    """Whether ``s`` is a bare ``return NAME`` footer for a NAME in ``collectors``."""
    return isinstance(s, ast.Return) and isinstance(s.value, ast.Name) and s.value.id in collectors


def _demote_orphan_appends(
    rows: list[dict[str, Any]],
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    delivering: set[str],
) -> set[str]:
    """Demote append-send rows whose collector is NOT a delivering accumulator to read-only code rows;
    return the delivering names that keep at least one visible append (their scaffold is taggable).

    A ``NAME.append(Send(...))`` is only an honest send row when NAME actually delivers what is appended
    (:func:`_delivering_accumulators`). An append into a discarded / aliased / rebound / closure-local
    list constructs a Send that never leaves the handler, so it degrades to a ``code`` row — mutated in
    place (kind→code, drop the send fields), BEFORE :func:`_merge_code_rows` so it coalesces with its
    neighbours. The row's span/nesting/suite are preserved, so the coverage partition is untouched."""
    stmt_by_span: dict[tuple[int, int], ast.stmt] = {}
    for n in _own_scope_nodes(node):
        if isinstance(n, ast.stmt):
            stmt_by_span.setdefault((n.lineno, n.end_lineno or n.lineno), n)
    used: set[str] = set()
    for row in rows:
        if row["kind"] != "send" or not row.get("appended"):
            continue
        stmt = stmt_by_span.get((row["line_start"], row["line_end"]))
        match = _match_append_send(stmt) if isinstance(stmt, ast.stmt) else None
        if match is not None and match[0] in delivering:
            used.add(match[0])
            continue
        ls, le, nest, suite = row["line_start"], row["line_end"], row["nesting"], row.get("suite")
        row.clear()
        row.update(_code_row(ls, le, nest))
        if suite is not None:
            row["suite"] = suite
    return used


def _tag_scaffold(
    rows: list[dict[str, Any]],
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    used: set[str],
) -> None:
    """Tag the accumulator's ``sends = []`` init and bare ``return sends`` footer as read-only scaffold.

    An additive ``scaffold`` marker (``'collector_init'`` / ``'return_collector'``) on the code row so the
    webview renders it muted; the ``kind`` stays ``code`` (already read-only — no rewrite path). Scoped to
    ``used`` — delivering accumulators (:func:`_delivering_accumulators`) that carry a visible append — so a
    discarded ``buf = []``, a ``return other``, or an accumulator whose only append is closure-local stays
    an untagged code row. Runs BEFORE :func:`_merge_code_rows` (on the still-single-statement init/footer
    rows, matched by exact span) — merge then keeps a tagged scaffold row standalone, so a ``sends = []``
    preceded by another statement stays its own muted row; the coverage partition is untouched (ADR 0076
    §6, spans never change)."""
    if not used:
        return
    code_by_span = {(r["line_start"], r["line_end"]): r for r in rows if r["kind"] == "code"}
    for s in node.body:
        row = code_by_span.get((s.lineno, s.end_lineno or s.lineno))
        if row is None or "scaffold" in row:
            continue
        if _is_collector_init(s, used):
            row["scaffold"] = "collector_init"
        elif _is_return_collector(s, used):
            row["scaffold"] = "return_collector"


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

# ``diagnostic`` rows (log_note/checkpoint) are editable too (ADR 0106 §5 K) — but only their template/
# label LITERAL: their operands fall past the signature and are skipped by _editable_slots/literal_params.
# ``note`` (ADR 0076 Amendment A) and ``route`` (Amendment D) join them at CONTRACT_V2: a note's text and
# a route's handler list are both editable, each through its own splice path (a note has no ``ast`` node,
# so no existing locator applies; a route splices the return's value expression).
_EDITABLE_KINDS = frozenset({"action", "lookup", "send", "diagnostic", "note", "route"})

# The editable kinds whose ``set_params`` obeys ADR 0076 Amendment E's per-argument modes: the rows that
# carry typed arguments and emit ``param_modes``. A send row's destination and a route row's handler
# list carry no mode, and the route path splices its own ``{"expr": ...}``, so neither is mode-gated.
# An ``{"expr": ...}`` on either still passes :func:`_refuse_active_expr` (Theia review finding R1).
_MODED_KINDS = frozenset({"action", "lookup", "diagnostic"})

# Ops that AUTHOR a transform verb, a lookup or an outbound send. They are refused inside a ``@router``
# (ADR 0076 §D.6 / AC-R5): a router stays pure destination-selection, and ``db_lookup``/``fhir_lookup``
# RAISE outside a live Handler. The IDE's router Add-palette does not offer them; this is the engine-side
# half of the same rule, so a hand-built edit spec cannot smuggle one in either.
_HANDLER_ONLY_OPS = frozenset(
    {"insert_row", "insert_code_lookup", "insert_send", "add_destination"}
)

# v2 adds three STRUCTURAL ops (delete/insert/move) + multi-line param edits to v1's ``set_params``
# (ADR 0076 §2 phase 3 v2); ``paste_block`` adds the Steps block-paste (re-indenting a captured block into
# the anchor's suite, reusing the cross-suite move helpers). Anything else is refused (zero change).
_SUPPORTED_OPS = frozenset(
    {
        "set_params",
        "delete_row",
        "insert_row",
        "move_row",
        "paste_block",
        "template",
        "insert_clause",
        "insert_comment",
        "insert_code_lookup",
        "insert_send",
        "add_destination",
    }
)

# ruff's configured line length (pyproject ``[tool.ruff] line-length``). Two paths refuse rather than emit a
# line ruff would re-wrap, so the structural output stays ``ruff format --check``-clean (gate 3): an INSERTED
# call whose rendered line exceeds it (:func:`_apply_insert_row`), and a cross-suite move whose re-indent
# pushes a line past it at a DEEPER depth (:func:`_reindent_block`). The lens never wraps a line itself — it
# only refuses one it cannot emit as a single clean line.
_MAX_LINE_LENGTH = 100


def _refuse_raw_source(op: str, edit: dict[str, Any]) -> None:
    """Refuse, in ``typed_only`` mode, the edits known to carry raw Python source (owner ruling
    2026-10-07, Theia review finding R1).

    This refuses at least a ``paste_block`` (the clipboard text) and a rendered ``if``/``elif`` raw
    ``test`` (the ADR 0106 escape hatch); :func:`_refuse_untyped_structure` adds the move and delete
    limits. Both stay available by default, for a developer and today's IDE. An analyst-facing editor
    must set ``typed_only`` (nothing in this repository sets it yet), with its role-based access as the
    primary control. Refused with the generic code, so the IDE contract gains no new refusal family."""
    if op == "paste_block":
        raise LensRewriteError(
            "paste_block carries raw source and is refused in typed-only mode - edit it as text"
        )
    test = edit.get("test")
    renders_test = (op == "template" and edit.get("template") == "if") or (
        op == "insert_clause" and edit.get("clause") == "elif"
    )
    if renders_test and isinstance(test, str) and test:
        raise LensRewriteError(
            "a raw 'test' carries raw source and is refused in typed-only mode - use a field, "
            "operator and value instead"
        )


def _is_typed_if_test(test: ast.expr) -> bool:
    """Whether ``test`` is one the ``if`` template renders from typed inputs (:func:`_render_if_test`):
    ``msg.field(F)``, ``msg.field(F) == V``, ``msg.field(F) != V`` or ``V in (msg.field(F) or "")``."""

    def _field(n: ast.expr) -> bool:
        return (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "field"
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id == "msg"
            and len(n.args) == 1
            and not n.keywords
            and isinstance(n.args[0], ast.Constant)
            and isinstance(n.args[0].value, str)
        )

    def _str(n: ast.expr) -> bool:
        return isinstance(n, ast.Constant) and isinstance(n.value, str)

    if _field(test):
        return True
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1):
        return False
    op, right = test.ops[0], test.comparators[0]
    if isinstance(op, ast.Eq | ast.NotEq):
        return _field(test.left) and _str(right)
    return (
        isinstance(op, ast.In)
        and _str(test.left)
        and isinstance(right, ast.BoolOp)
        and isinstance(right.op, ast.Or)
        and len(right.values) == 2
        and _field(right.values[0])
        and isinstance(right.values[1], ast.Constant)
        and right.values[1].value == ""
    )


def _is_typed_for(node: ast.For) -> bool:
    """Whether ``node`` is the For-Each header the template renders from a typed segment id:
    ``for i in range(1, msg.count_segments(SEG) + 1):``."""
    segment = _range_count_segment(node.iter)
    if segment is None:
        return False
    try:
        rendered = ast.parse(
            _render_template({"template": "for_each", "segment_id": segment}).strip()
        )
    except (SyntaxError, ValueError):
        return False  # a segment id no typed input renders (a newline, a NUL)
    expected = rendered.body[0]
    return (
        isinstance(expected, ast.For)
        and ast.dump(node.target) == ast.dump(expected.target)
        and ast.dump(node.iter) == ast.dump(expected.iter)
        and not node.orelse
    )


class _TypedCtx(NamedTuple):
    """What :func:`_is_typed_simple` needs to know about the handler around a statement."""

    scope: _Scope
    accumulators: frozenset[str]
    router: bool
    code_spans: tuple[tuple[int, int], ...] = ()
    bindings: tuple[tuple[int, int], ...] = ()


def _typed_ctx(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.Module,
    role: str,
    rows: list[dict[str, Any]] | None = None,
) -> _TypedCtx:
    """The :class:`_TypedCtx` of ``func``; ``rows``, when given, adds the projection's code rows and
    binding rows, which only the precondition in :func:`_refuse_untyped_structure` uses."""
    rows = rows or []
    return _TypedCtx(
        scope=_message_scope(func, tree),
        accumulators=frozenset(_delivering_accumulators(func)),
        router=role == "router",
        code_spans=tuple((r["line_start"], r["line_end"]) for r in rows if r["kind"] == "code"),
        bindings=tuple(
            (r["line_start"], r["line_end"])
            for r in rows
            if r.get("action") == "read_field" or r.get("assign_to")
        ),
    )


def _typed_only_refusal(op: str, line_start: int, line_end: int, why: str) -> LensRewriteError:
    """The refusal every typed-only structure limit raises, with the generic ``refused`` code."""
    return LensRewriteError(
        f"{op} of the rows at lines {line_start}-{line_end} is refused in typed-only mode - {why}; "
        "edit it as text"
    )


_UNTYPED = "it would move or remove code the Steps view does not show as typed steps"


def _refuse_untyped_structure(
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    row: dict[str, Any],
    ctx: _TypedCtx,
    op: str,
    line_start: int,
    line_end: int,
) -> None:
    """In ``typed_only`` mode, refuse a move or delete of a row that is not wholly typed (Manager
    decision 2026-10-07, Theia review finding R1).

    This is the precondition, about the row itself: the moved or deleted statement must be typed
    (:func:`_is_typed_stmt`). A ``note`` row is a comment and runs nothing, so it passes (Lander review
    of PR 2155, finding 8). What the row may cross is :func:`_refuse_typed_only_result`'s job, checked
    on the result."""
    if row["kind"] == "note":
        return
    if row["kind"] == "code":
        raise _typed_only_refusal(op, line_start, line_end, _UNTYPED)
    located = _locate_stmt_by_header(handler_node.body, line_start)
    if located is None or not _is_typed_stmt(located[0][located[1]], ctx, top=True):
        raise _typed_only_refusal(op, line_start, line_end, _UNTYPED)


def _is_typed_stmt(stmt: ast.stmt, ctx: _TypedCtx, *, top: bool) -> bool:
    """Whether ``stmt`` and everything nested in it is what typed Steps edits produce.

    A simple statement is typed when :func:`_is_typed_simple` says so and it sits in no ``code`` row
    (``pass`` excepted: the templates seed it). An ``if`` or ``for`` is typed when its header is one
    the templates render from typed inputs (:func:`_is_typed_if_test`, :func:`_is_typed_for`) and its
    whole body is typed. Any other block is not. Inside a block (``top`` False), a row that binds a
    name (a Read Field, an assigned lookup) is not typed either: moving or removing the block would
    strand a later use of that name."""
    if isinstance(stmt, ast.If):
        if not _is_typed_if_test(stmt.test):
            return False
    elif isinstance(stmt, ast.For):
        if not _is_typed_for(stmt):
            return False
    elif isinstance(stmt, _COMPOUND_STMT_TYPES):
        return False
    else:
        if isinstance(stmt, ast.Pass):
            return True
        line = stmt.lineno
        if not _is_typed_simple(stmt, ctx) or any(lo <= line <= hi for lo, hi in ctx.code_spans):
            return False
        return top or not any(lo <= line <= hi for lo, hi in ctx.bindings)
    children = [*stmt.body, *stmt.orelse]
    return all(_is_typed_stmt(c, ctx, top=False) for c in children)


def _is_typed_simple(stmt: ast.stmt, ctx: _TypedCtx) -> bool:
    """Whether simple ``stmt`` is one a typed Steps edit writes, with nothing in it that runs code.

    The row KIND is not enough (Lander review of PR 2155, finding 2): ``msg.set("PID-5", os.system(
    "x"))`` is an action row and ``return Send(pick(msg), msg)`` a send row. So every argument must
    be inert (:func:`_is_inert_value`, or a lookup's :func:`_is_inert_params_dict`). The callee must
    be a bare vocabulary name the handler does not shadow, or a method of ``msg``, and a vocabulary
    call's message argument must be the name ``msg`` (spike S-4): ``os.set_field(msg, ...)`` and
    ``set_field(other, ...)`` project as the same row as ``set_field(msg, ...)``.

    Typed: ``pass``; a templated ``raise``; a filter, a route with literal handlers (in a router), or
    a ``Send`` or list of them; a vocabulary or native ``msg`` call; a lookup assigned to one name; a
    native Read Field; an append to the handler's delivering accumulator."""
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Return):
        return _is_typed_return(stmt.value, ctx)
    if isinstance(stmt, ast.Raise):
        exc = stmt.exc
        return (
            stmt.cause is None
            and isinstance(exc, ast.Call)
            and isinstance(exc.func, ast.Name)
            and exc.func.id in ("ValueError", "RuntimeError")
            and not _is_shadowed(exc.func.id, ctx.scope)
            and not exc.keywords
            and len(exc.args) <= 1
            and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in exc.args)
        )
    if ctx.router:
        return False  # a router's only typed step is its route
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        match = _match_append_send(stmt)
        if match is not None:
            return match[0] in ctx.accumulators and _is_typed_send(match[1], ctx)
        return _is_typed_call(stmt.value, ctx, native=_recognize_native_stmt(stmt) is not None)
    if (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and isinstance(stmt.value, ast.Call)
    ):
        if _recognize_native_stmt(stmt) is not None:
            return _is_field_call(stmt.value, scope=ctx.scope)  # ``name = msg.field("LIT")``
        return _callee_name(stmt.value.func) in _ASSIGNABLE_LOOKUPS and _is_typed_call(
            stmt.value, ctx, native=False
        )
    return False


def _is_typed_return(value: ast.expr | None, ctx: _TypedCtx) -> bool:
    """Whether a ``return`` of ``value`` is a typed route (router) or filter or send (handler)."""
    if ctx.router:
        if value is None or isinstance(value, ast.Constant):
            return value is None or value.value is None or isinstance(value.value, str)
        return isinstance(value, ast.List | ast.Tuple) and all(
            isinstance(e, ast.Constant) and isinstance(e.value, str) for e in value.elts
        )
    if isinstance(value, ast.List | ast.Tuple):
        return all(isinstance(e, ast.Call) and _is_typed_send(e, ctx) for e in value.elts)
    return isinstance(value, ast.Call) and _is_typed_send(value, ctx)


def _is_typed_send(call: ast.Call, ctx: _TypedCtx) -> bool:
    """Whether ``call`` is ``Send(<inert destination>, msg)``."""
    return (
        isinstance(call.func, ast.Name)
        and call.func.id == "Send"
        and not _is_shadowed("Send", ctx.scope)
        and len(call.args) == 2
        and not call.keywords
        and isinstance(call.args[1], ast.Name)
        and call.args[1].id == "msg"
        and _is_inert_value(call.args[0], reads_ok=False, scope=ctx.scope)
    )


def _is_typed_call(call: ast.Call, ctx: _TypedCtx, *, native: bool) -> bool:
    """Whether a vocabulary or native ``msg`` call has a typed callee and only inert arguments."""
    if native:
        func = call.func
        if not (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "msg"
        ):
            return False
        if any(kw.arg is None for kw in call.keywords):
            return False
        values = [*call.args, *(kw.value for kw in call.keywords)]
        return all(_is_inert_value(v, reads_ok=True, scope=ctx.scope) for v in values)
    if not isinstance(call.func, ast.Name) or _is_shadowed(call.func.id, ctx.scope):
        return False
    name = call.func.id
    params = _ACTION_PARAMS.get(name) or _LOOKUP_PARAMS.get(name) or _DIAGNOSTIC_PARAMS.get(name)
    if params is None or ("msg" in params and _call_message_node(call, params) is None):
        return False
    args: list[tuple[str | None, ast.expr]] = []
    for i, arg in enumerate(call.args):
        if isinstance(arg, ast.Starred):
            return False
        args.append((params[i] if i < len(params) else None, arg))
    for kw in call.keywords:
        if kw.arg is None:
            return False
        args.append((kw.arg, kw.value))
    for pname, arg in args:
        if pname == "msg":
            continue
        if pname == "params" and name in _LOOKUPS:
            if not _is_inert_params_dict(arg, scope=ctx.scope, fhir=True):
                return False
        elif not _is_inert_value(arg, reads_ok=True, scope=_param_scope(name, pname, ctx.scope)):
            return False
    return True


# --- typed-only postconditions (Lander review of PR 2155, design note 12) ----------------------
#
# The rules above judge the row being moved or deleted. What it may cross is judged on the RESULT:
# re-read the handler and require every statement that is not typed to keep its text, its nesting,
# everything before it and everything inside it, and require no read of a local to lose its binding.
# One rule over the result covers the swap, the drop and the delete alike, so a new move shape cannot
# reopen the gap the per-operation rules left (findings 1, 3 and 9).


class _Item(NamedTuple):
    """One statement of a handler in source order (:func:`_linear_items`)."""

    node: ast.stmt
    key: str  # what the statement says, without its position or its nested suites
    path: tuple[str, ...]  # the keys of the blocks it sits in, with the suite it is in
    protected: bool  # not typed: it may not move, go, or have anything cross it
    end: int  # the index one past its last nested statement
    terminal: bool = False  # a ``return`` or ``raise``: it keeps its nesting


def _stmt_key(stmt: ast.stmt) -> str:
    """``ast.dump`` of ``stmt`` without its nested suites, so a block's key is its header."""
    if not isinstance(stmt, _COMPOUND_STMT_TYPES):
        return ast.dump(stmt)
    shell = copy.copy(stmt)
    for field in ("body", "orelse", "finalbody", "handlers", "cases"):
        if hasattr(shell, field):
            setattr(shell, field, [])
    return ast.dump(shell)


def _suites(stmt: ast.stmt) -> list[tuple[str, list[ast.stmt], set[str]]]:
    """``(label, statements, names bound on entry)`` for each suite nested directly in ``stmt``."""
    out: list[tuple[str, list[ast.stmt], set[str]]] = []
    for field in ("body", "orelse", "finalbody"):
        value = getattr(stmt, field, None)
        if isinstance(value, list) and value:
            out.append((field, value, set()))
    for i, handler in enumerate(getattr(stmt, "handlers", [])):
        shell = copy.copy(handler)
        shell.body = []
        names = {handler.name} if handler.name else set()
        out.append((f"handler{i}:{ast.dump(shell)}", handler.body, names))
    for i, case in enumerate(getattr(stmt, "cases", [])):
        label = f"case{i}:{ast.dump(case.pattern)}:{ast.dump(case.guard) if case.guard else ''}"
        out.append((label, case.body, set(_bound_names(case.pattern))))
    return out


def _is_typed_unit(stmt: ast.stmt, ctx: _TypedCtx) -> bool:
    """Whether ``stmt``'s own part (its header, for a block) is typed. The fan-out init ``sends = []``
    counts: it is the lens's own scaffold, a typed row may cross it, and :func:`_unbound_reads` stops
    an append from crossing above it (Lander review of PR 2155, finding 9)."""
    if isinstance(stmt, ast.If):
        return _is_typed_if_test(stmt.test)
    if isinstance(stmt, ast.For):
        return _is_typed_for(stmt)
    if isinstance(stmt, _COMPOUND_STMT_TYPES):
        return False
    if (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and stmt.targets[0].id in ctx.accumulators
        and isinstance(stmt.value, ast.List)
        and not stmt.value.elts
    ):
        return True
    return _is_typed_simple(stmt, ctx)


def _linear_items(func: ast.FunctionDef | ast.AsyncFunctionDef, ctx: _TypedCtx) -> list[_Item]:
    """Every statement of ``func`` in source order, as :class:`_Item` s."""
    items: list[_Item] = []

    seen: Counter[str] = Counter()

    def visit(stmts: list[ast.stmt], path: tuple[str, ...]) -> None:
        for stmt in stmts:
            key = _stmt_key(stmt)
            seen[key] += 1
            # Which block with this header: a raise may not move into another guard with the same
            # test (review of head bd5843dbd4, finding 3). A move that renumbers same-header
            # blocks changes the path of any protected or terminal statement inside them, so such
            # a move may be refused; the safe direction.
            nth = seen[key]
            at = len(items)
            terminal = isinstance(stmt, ast.Return | ast.Raise)
            items.append(_Item(stmt, key, path, not _is_typed_unit(stmt, ctx), at + 1, terminal))
            for label, suite, _ in _suites(stmt):
                visit(suite, (*path, f"{key}#{nth}|{label}"))
            items[at] = items[at]._replace(end=len(items))

    visit(func.body, ())
    return items


def _refuse_shifted_code(
    before: list[_Item], after: list[_Item], deleted: set[int], refusal: LensRewriteError
) -> None:
    """Refuse unless every protected statement of ``before`` is in ``after`` unchanged in place.

    A protected statement is matched to the same-keyed statement at the same occurrence. It must keep
    its nesting, the statements before it and the statements inside it, as a multiset of keys. So a
    typed row may not be dropped or swapped past code, into or out of an untyped block, or past a
    ``return sends``, and a delete may remove typed statements only. ``deleted`` holds the ``id`` of
    each statement the delete removed.

    Two more limits, from the review of head 513797260a. A typed ``return`` or ``raise`` keeps its
    nesting: lifted out of its guard, a filter or raise runs on every message (finding 1). And a
    typed block that holds a protected statement keeps its contents: a typed row dropped into it
    would otherwise run only when its guard holds, with no protected statement's predecessors
    changing (finding 6)."""
    kept = [i for i, item in enumerate(before) if id(item.node) not in deleted]
    if any(item.protected for item in before if id(item.node) in deleted):
        raise refusal
    if Counter(before[i].key for i in kept) != Counter(item.key for item in after):
        raise refusal

    def positions(indexes: list[int], items: list[_Item]) -> dict[tuple[str, int], int]:
        seen: Counter[str] = Counter()
        out: dict[tuple[str, int], int] = {}
        for i in indexes:
            out[(items[i].key, seen[items[i].key])] = i
            seen[items[i].key] += 1
        return out

    after_at = positions(list(range(len(after))), after)
    for (key, n), b in positions(kept, before).items():
        item = before[b]
        a = after_at[(key, n)]
        holds_code = any(before[j].protected for j in range(b + 1, item.end))
        if holds_code:
            before_inner = Counter(before[j].key for j in kept if b < j < item.end)
            if before_inner != Counter(x.key for x in after[a + 1 : after[a].end]):
                raise refusal
        if (item.protected or item.terminal) and after[a].path != item.path:
            raise refusal
        if not item.protected:
            continue
        before_preds = Counter(before[j].key for j in kept if j < b)
        if before_preds != Counter(x.key for x in after[:a]):
            raise refusal
        before_inner = Counter(before[j].key for j in kept if b < j < item.end)
        if before_inner != Counter(x.key for x in after[a + 1 : after[a].end]):
            raise refusal


def _unbound_reads(
    func: ast.FunctionDef | ast.AsyncFunctionDef, local: set[str]
) -> Counter[tuple[str, str, int]]:
    """The read SITES of handler locals that no earlier binding is sure to have run, as a multiset.

    Compared as sites rather than per-name counts (ADR 0076 G.6 rule 6): with counts, a read the base
    already over-counts could hide a new real one. A site is :func:`_stmt_key` of the statement (or
    the header expression) holding the read, the name, and which read of that name it is there.

    A binding counts for the statements after it in its own suite and inside them; one made inside a
    block does not count after the block unless every path binds it (:func:`_bound_after`). That
    over-counts by design. It is not proven never to under-count: this is hand-written scoping, and
    :func:`_reads_before_any_binding` backs it up. Compared before
    and after a typed-only move or delete, a rise means a read the result leaves unbound, which raises
    NameError or UnboundLocalError on every message (Lander review of PR 2155, finding 3). ``local``
    is the names to count (:func:`_handler_locals`), taken from BOTH versions of the handler: a delete
    that removes a name's only binding leaves its reads unbound."""
    a = func.args
    params = {
        arg.arg
        for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg)
        if arg is not None
    }
    out: Counter[tuple[str, str, int]] = Counter()

    def count(node: ast.AST, defined: set[str]) -> None:
        out.update(_read_sites(node, local, defined))

    def visit(stmts: list[ast.stmt], entry: set[str]) -> set[str]:
        """Count the suite's reads; return the names surely bound once it falls through. A suite
        that ends in ``return`` or ``raise`` never falls through, so it binds everything."""
        defined = set(entry)
        for stmt in stmts:
            if not isinstance(stmt, _COMPOUND_STMT_TYPES):
                count(stmt, defined)
                defined |= _own_scope_bindings(stmt)
                continue
            header = [
                value
                for field, value in ast.iter_fields(stmt)
                if field not in ("body", "orelse", "finalbody", "handlers", "cases")
            ]
            inner = set(defined)
            for value in header:
                for node in value if isinstance(value, list) else [value]:
                    if isinstance(node, ast.AST):
                        count(node, defined)
                        inner |= _own_scope_bindings(node)
            ends = {label: visit(suite, inner | names) for label, suite, names in _suites(stmt)}
            defined |= _bound_after(stmt, inner, ends)
        if stmts and isinstance(stmts[-1], ast.Return | ast.Raise):
            return defined | local
        return defined

    visit(func.body, params)
    return out


def _read_sites(node: ast.AST, local: set[str], defined: set[str]) -> list[tuple[str, str, int]]:
    """The read sites in ``node`` of names in ``local`` but not in ``defined``.

    A site is (the statement's key, the name, which read of it in that statement), so a moved
    statement keeps its sites and a read that newly loses its binding is a new site."""
    where = _stmt_key(node) if isinstance(node, ast.stmt) else ast.dump(node)
    nth: Counter[str] = Counter()
    out: list[tuple[str, str, int]] = []
    pending: deque[tuple[ast.AST, frozenset[str]]] = deque([(node, frozenset())])
    while pending:
        n, own = pending.popleft()
        inner = _inner_scope(n, own)
        if inner is not None:
            pending.extend(inner)
            continue
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            nth[n.id] += 1
            if n.id in local and n.id not in defined and n.id not in own:
                out.append((where, n.id, nth[n.id]))
        pending.extend((child, own) for child in ast.iter_child_nodes(n))
    return out


def _inner_scope(n: ast.AST, own: frozenset[str]) -> list[tuple[ast.AST, frozenset[str]]] | None:
    """For a comprehension or ``lambda``, each child paired with the names bound where it runs;
    None for any other node.

    A comprehension's targets and a lambda's parameters are bound in a scope of their own, so
    ``[seg for seg in rows]`` reads no handler ``seg`` (review of head bd5843dbd4, finding 5). But
    the comprehension's FIRST iterable and the lambda's default values run in the enclosing scope,
    so their reads count there (Lander review of 71fe1207f4). Only a plain-name target binds; the
    names inside a subscript or attribute target are reads."""
    if isinstance(n, ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp):
        bound = own | {
            t.id
            for g in n.generators
            for t in ast.walk(g.target)
            if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store)
        }
        first, *rest = n.generators
        children: list[tuple[ast.AST, frozenset[str]]] = [(first.iter, own)]
        for g in n.generators:
            children.append((g.target, bound))
            children.extend((cond, bound) for cond in g.ifs)
        children.extend((g.iter, bound) for g in rest)
        results = [n.key, n.value] if isinstance(n, ast.DictComp) else [n.elt]
        children.extend((r, bound) for r in results)
        return children
    if isinstance(n, ast.Lambda):
        a = n.args
        defaults = [*a.defaults, *(d for d in a.kw_defaults if d is not None)]
        params = {x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg) if x}
        lambda_children: list[tuple[ast.AST, frozenset[str]]] = [(d, own) for d in defaults]
        lambda_children.append((n.body, own | params))
        return lambda_children
    return None


def _reads_before_any_binding(
    func: ast.FunctionDef | ast.AsyncFunctionDef, local: set[str]
) -> Counter[tuple[str, str, int]]:
    """The read sites with no binding of the name ANYWHERE earlier in source order.

    :func:`_unbound_reads` over-counts on purpose (a binding inside a loop or a one-armed ``if`` is
    not sure to run), so a read it already counts keeps its site wherever it moves. This weaker
    test closes that: a read that had some binding above it and has none after the edit is
    refused too, such as a read of a loop's last value, or an ``occurrence=i`` row, moved above the
    loop (review of head 6259fb97a2, finding 1)."""
    a = func.args
    defined = {
        arg.arg
        for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg)
        if arg is not None
    }
    out: Counter[tuple[str, str, int]] = Counter()

    def visit(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            if not isinstance(stmt, _COMPOUND_STMT_TYPES):
                out.update(_read_sites(stmt, local, defined))
                defined.update(_own_scope_bindings(stmt))
                continue
            for field, value in ast.iter_fields(stmt):
                if field in ("body", "orelse", "finalbody", "handlers", "cases"):
                    continue
                for node in value if isinstance(value, list) else [value]:
                    if isinstance(node, ast.AST):
                        out.update(_read_sites(node, local, defined))
                        defined.update(_own_scope_bindings(node))
            for _, suite, names in _suites(stmt):
                defined.update(names)
                visit(suite)
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                defined.add(stmt.name)

    visit(func.body)
    return out


def _bound_after(stmt: ast.stmt, header: set[str], ends: dict[str, set[str]]) -> set[str]:
    """The names surely bound after compound ``stmt`` falls through (:func:`_unbound_reads`).

    ``header`` is what is bound on entry plus the header's own bindings, and ``ends`` maps each
    suite label (:func:`_suites`) to what is bound at its end. An ``if`` binds what every branch
    binds, with a missing ``else`` binding nothing. A ``with`` binds nothing new, because a context
    manager such as ``contextlib.suppress`` may skip the rest of its body. A loop binds
    nothing new, because its body may not run: so a For-Each index is unbound after its loop
    (Manager decision 2026-10-07). A ``try`` binds what its body and every handler bind, plus what
    its ``finally`` binds. A ``match``, a ``def`` and a ``class`` are judged conservatively."""
    if isinstance(stmt, ast.If):
        return ends.get("body", header) & ends.get("orelse", header)
    if isinstance(stmt, ast.Try | ast.TryStar):
        caught = [v for k, v in ends.items() if k.startswith("handler")]
        out = ends.get("body", header)
        for names in caught:
            out = out & names
        return out | ends.get("finalbody", set())
    if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return {stmt.name}
    return set()


def _own_scope_bindings(node: ast.AST) -> set[str]:
    """The names ``node`` binds in the handler's own scope.

    Unlike :func:`_bound_names`, a comprehension target and the parameters of a nested ``lambda`` or
    ``def`` do not count, because each binds in a scope of its own: ``[r for r in rows]`` leaves ``r``
    unbound for a later ``msg.set("A", r)`` (review of head 513797260a, finding 2). A nested ``def``
    or ``class`` binds its own name only. A walrus inside a comprehension, which does bind in the
    handler, is left out too: that over-counts an unbound read rather than hiding one."""
    out: set[str] = set()
    pending: list[ast.AST] = [node]
    while pending:
        n = pending.pop()
        if n is not node and isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            out.add(n.name)
            continue
        if isinstance(n, ast.Lambda | ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp):
            continue
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            out.add(n.id)
        elif isinstance(n, ast.ExceptHandler | ast.MatchAs | ast.MatchStar) and n.name:
            out.add(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            out.add(n.rest)
        elif isinstance(n, ast.Import | ast.ImportFrom):
            out.update((al.asname or al.name).split(".")[0] for al in n.names)
        pending.extend(ast.iter_child_nodes(n))
    return out


def _refuse_new_unbound_reads(
    tree: ast.Module, result: str, row: dict[str, Any], role: str, what: str
) -> None:
    """Refuse a result in which some read of a handler local has lost its binding
    (:func:`_unbound_reads`), comparing the handler before and after."""
    before_func = _element_def(tree, row["_handler"], role)
    after_func = _element_def(ast.parse(result), row["_handler"], role)
    if before_func is None or after_func is None:
        raise LensRewriteError(f"{what} is refused - internal: the handler was not found again")
    local = _handler_locals(before_func) | _handler_locals(after_func)
    before, after = _unbound_reads(before_func, local), _unbound_reads(after_func, local)
    early_before = _reads_before_any_binding(before_func, local)
    early_after = _reads_before_any_binding(after_func, local)
    stranded = sorted(site[1] for site in (after - before) + (early_after - early_before))
    if stranded:
        raise LensRewriteError(
            f"{what} is refused - it would leave a read of {stranded[0]!r} before anything binds "
            "it, which fails on every message; edit it as text"
        )


def _handler_locals(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """The names ``func`` binds, less any it declares ``global`` or ``nonlocal``."""
    declared = {
        n for x in ast.walk(func) if isinstance(x, ast.Global | ast.Nonlocal) for n in x.names
    }
    return set(_bound_names(func)) - declared


def _refuse_typed_only_result(
    tree: ast.Module,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    result: str,
    row: dict[str, Any],
    role: str,
    op: str,
    line_start: int,
    line_end: int,
) -> None:
    """The typed-only postconditions on a move or delete (:func:`_refuse_shifted_code`,
    :func:`_unbound_reads`). ``result`` has already re-parsed (:func:`_assert_reparses`)."""
    after_tree = ast.parse(result)
    after_func = _element_def(after_tree, row["_handler"], role)
    refusal = _typed_only_refusal(op, line_start, line_end, _UNTYPED)
    if after_func is None:
        raise refusal
    deleted: set[int] = set()
    if op == "delete_row":
        located = _locate_stmt(handler_node.body, line_start, line_end) or _locate_stmt_by_header(
            handler_node.body, line_start
        )
        if located is None:
            raise refusal
        deleted = {id(n) for n in ast.walk(located[0][located[1]]) if isinstance(n, ast.stmt)}
    _refuse_shifted_code(
        _linear_items(handler_node, _typed_ctx(handler_node, tree, role)),
        _linear_items(after_func, _typed_ctx(after_func, after_tree, role)),
        deleted,
        refusal,
    )
    _refuse_new_unbound_reads(
        tree,
        result,
        row,
        role,
        f"{op} of the rows at lines {line_start}-{line_end} in typed-only mode",
    )


def rewrite_module(
    path: str | Path,
    edit: dict[str, Any],
    *,
    contract: int = CONTRACT_V1,
    typed_only: bool = False,
) -> str:
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
    except (OSError, UnicodeDecodeError) as exc:
        # UnicodeDecodeError too, so a non-UTF-8 module is the documented LensParseError rather than
        # an escape; raised after the handler, since its .object is the whole file (BACKLOG #2085).
        unreadable = f"{p}: cannot read ({exc})"
    else:
        return rewrite_source(
            source, edit, module=p.as_posix(), contract=contract, typed_only=typed_only
        )
    raise LensParseError(unreadable)


def rewrite_source(
    source: str,
    edit: dict[str, Any],
    *,
    module: str = "<source>",
    contract: int = CONTRACT_V1,
    typed_only: bool = False,
) -> str:
    """Apply one row edit to ``source`` text and return the rewritten source (see :func:`rewrite_module`).

    ``edit`` is the **edit spec** (ADR 0076 §5):

    ``{"line_start": int, "line_end": int, "op": "set_params", "params": {name: value, …},
    "handler": str?}``

    It identifies the row by its ``[line_start, line_end]`` span (the same range :func:`parse_source`
    emits — optionally disambiguated by ``handler``) and, for ``op="set_params"``, sets the named
    parameters. ``params={}`` is a valid **no-op** and returns the source byte-identically.

    On an ``action``, ``lookup`` or ``diagnostic`` row a parameter obeys ADR 0076 Amendment E's modes
    (:func:`_render_moded_value`). An argument whose current mode is ``dynamic`` is **read-only** and any
    edit of it is refused (AC-M5). A ``static`` or ``templated`` argument takes one of:

    * a JSON scalar, written as a Python **literal** (``static``);
    * ``{"parts": [{"text": "..."}, {"path": "PID-3.1"}, ...]}``, written as the bounded interpolation
      ``f"...{msg['PID-3.1'] or ''}..."`` (``templated``). At least one ``path`` part is required, and only a
      param ``lens parse`` lists in the row's ``template_params`` accepts it;
    * ``{"expr": "<python source>"}``, spliced verbatim only if it classifies ``static``. An ``expr``
      that is ``dynamic`` (a bare ``msg["X"]`` read included) is refused, and so is one that is
      ``templated``: a template is written as parts, so every templated write passes the round-trip
      gate in :func:`_render_parts`.

    On a ``send`` row a value is a JSON scalar (only when the current argument is a literal) or
    ``{"expr": ...}`` spliced verbatim, but only when it runs no code (:func:`_is_inert_value`, Theia
    review finding R1). The same holds for every ``{"expr": ...}`` an ``insert_row`` or
    ``insert_code_lookup`` takes. A ``route`` row takes ``{"handlers":
    [names]}`` and a ``note`` row ``{"text": str}``. ``contract`` must match the version the caller
    PROJECTED with
    (:data:`CONTRACT_V1` default): the row is located through the same grammar the client saw, so a v1
    client's coordinates resolve against the v1 partition and a v2 client's against the v2 one.
    ``typed_only`` refuses at least a ``paste_block``, a raw ``test``, and a move or delete of code the
    Steps view does not show as typed (:func:`_refuse_raw_source`, :func:`_refuse_untyped_structure`),
    and checks a move or delete's result (:func:`_refuse_typed_only_result`). Raises :class:`LensParseError` on a syntax error,
    :class:`LensRewriteError` on any refusal."""
    op = edit.get("op", "set_params")
    if op not in _SUPPORTED_OPS:
        raise LensRewriteError(f"unsupported op {op!r} (supported: {sorted(_SUPPORTED_OPS)})")
    if typed_only:
        _refuse_raw_source(op, edit)
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
    except _PARSER_REFUSALS as exc:
        raise LensRewriteError(f"{module}: cannot parse ({_refusal_reason(exc)})") from exc

    # Stale-coordinate guard (F7): the row coords came from a prior *disk*-based ``lens parse``, but the
    # edit runs on the *live* buffer. When the caller carries the projected row's source text, verify it
    # still matches this buffer's row before splicing — otherwise a coincidental same-shape single-line
    # row (e.g. two ``return Send(...)``) could be edited in the wrong place.
    _check_expect_src(edit, src, line_start, line_end)

    # Locate the row via the SAME grammar the parser emits, so an edit can only target what parse shows.
    contracts = parse_source(src, module=module, contract=contract)
    row = _find_contract_row(contracts, line_start, line_end, handler_filter)
    if row is None:
        raise LensRewriteError(
            f"no editable row at lines {line_start}-{line_end}"
            + (f" in handler {handler_filter!r}" if handler_filter else "")
        )
    kind = row["kind"]
    role = row.get("_role", "handler")
    if role == "router" and (
        op in _HANDLER_ONLY_OPS or (op == "template" and edit.get("template") == "send")
    ):
        raise LensRewriteError(
            f"op {op!r} authors a transform verb, lookup or outbound send — refused inside the "
            f"@router {row['_handler']!r}, which stays pure destination-selection (ADR 0076 §D.6)"
        )
    if kind == "note":
        _check_note_op(row, op, line_start, line_end)
    # ``insert_row``/``move_row``/``paste_block`` use the target only as a POSITION (an anchor to insert/
    # paste before/after, or the block a move repositions), re-indenting across nesting as needed — so they
    # may target a read-only code/control row (moving a whole if/for block is exactly a control-row move).
    # ``set_params``/``delete_row`` MUTATE the row, so they refuse a non-editable kind — EXCEPT that
    # ``delete_row`` additionally accepts a whole ``if``/``for`` control BLOCK (its header row removes the
    # block, the ADR 0089 block-cut a Steps CUT reuses); ``set_params`` and code/elif/else rows stay refused.
    if op in ("set_params", "delete_row") and kind not in _EDITABLE_KINDS:  # noqa: SIM102
        if not (op == "delete_row" and kind == "control" and row.get("control") in ("if", "for")):
            raise LensRewriteError(
                f"row at lines {line_start}-{line_end} is a {kind!r} row — only action/lookup/send/"
                "diagnostic/note/route rows are editable (code and control rows are read-only, "
                "ADR 0076 §5)"
            )

    # A Read Field row binds a name later statements use (ADR 0089 row 4, BACKLOG #1505). Deleting it, or
    # moving it below a use or into a block, would leave that use unbound, and the lens does not track
    # uses. So its STRUCTURE stays as read-only as the code row it used to be; only its path is editable.
    # A Steps cut is a delete and a drag or up/down is a move, so this one gate covers all of them.
    if op in ("delete_row", "move_row") and row.get("action") == "read_field":
        raise LensRewriteError(
            f"row at lines {line_start}-{line_end} is a read_field row binding "
            f"{row.get('assign_to')!r} - {op} is refused because a later use of that name could be left "
            "unbound; delete or move it in the text editor"
        )

    handler_node = _element_def(tree, row["_handler"], role)
    if handler_node is None:
        raise LensRewriteError(
            f"internal: could not locate {role} {row['_handler']!r} for lines {line_start}-{line_end}"
        )
    if typed_only and op in ("move_row", "delete_row"):
        rows = next(
            c["rows"]
            for c in contracts
            if c["handler"] == row["_handler"] and c.get("role", "handler") == role
        )
        ctx = _typed_ctx(handler_node, tree, role, rows)
        _refuse_untyped_structure(handler_node, row, ctx, op, line_start, line_end)

    if op == "set_params" and kind == "note":
        # A note has no ``ast`` node, so every statement locator is unusable — this is the lens's only
        # whole-physical-line regeneration, and it takes the indent + ``#`` form from the EXISTING line.
        result = _apply_set_note(src, row, edit, line_start, line_end)
    elif op == "delete_row" and kind == "note":
        result = _apply_delete_note(src, line_start, line_end)
    elif op == "set_params" and kind == "route":
        result = _apply_set_route(src, handler_node, row, edit, line_start, line_end)
    elif op == "set_params":
        result = _apply_set_params(
            src,
            handler_node,
            row,
            edit,
            line_start,
            line_end,
            scope=_message_scope(handler_node, tree),
        )
    elif op == "delete_row":
        result = _apply_delete_row(src, handler_node, line_start, line_end)
    elif op == "insert_row":
        result = _apply_insert_row(src, tree, handler_node, edit, line_start, line_end)
    elif op == "paste_block":
        result = _apply_paste_block(src, line_start, line_end, edit)
    elif op == "template":
        # ADR 0106 structure/flow insert (If / For Each / Filter / Raise / Send) — render native Python and
        # route through the paste path; uses the target only as a position, like insert_row/paste_block.
        result = _apply_insert_template(
            src,
            tree,
            line_start,
            line_end,
            edit,
            is_async=isinstance(handler_node, ast.AsyncFunctionDef),
        )
    elif op == "insert_clause":
        # ADR 0106 Else If / Else — append an ``elif``/``else`` clause to the ``if`` chain anchored at the
        # target row. A pure line-insert (no existing byte is touched), so only re-parse validity is at risk.
        result = _apply_insert_clause(src, handler_node, line_start, edit)
    elif op == "insert_comment":
        # ADR 0106 Comment — splice a ``# <text>`` line at the anchor indent; a raw-line insert (a comment
        # is not an ast statement), position-only like insert_row, so it can anchor on any row kind.
        result = _apply_insert_comment(src, line_start, line_end, edit)
    elif op == "insert_code_lookup":
        # ADR 0106 Code Lookup — insert code_lookup(msg, path, VAR) AND inject the module-level
        # ``VAR = code_set("<name>")`` capture (ADR 0033 tables); position-only, anchors any row kind.
        result = _apply_insert_code_lookup(src, tree, handler_node, line_start, line_end, edit)
    elif op in ("insert_send", "add_destination"):
        # ADR 0104 fan-out — add a ``sends.append(Send(dest, msg))`` accumulator send: lay the scaffold
        # in a fresh handler, append into an existing accumulator, or convert a legacy ``return Send(...)``
        # up to the accumulator idiom. Never authors a Send inside a ``return``. Position-only anchor
        # (any row kind), so it flows here rather than through the set_params/delete_row edit gate.
        result = _apply_add_send(src, tree, handler_node, edit, line_start, line_end)
    else:  # move_row
        _check_to_suite(edit, contracts, row["_handler"])
        result = _apply_move_row(src, handler_node, edit, line_start, line_end)

    # Safety gate (gate 3): a real change must re-parse to valid Python, else refuse with zero change. A
    # no-op returns ``src`` unchanged (already parsed above), so it skips the re-parse and stays identical.
    if result != src:
        _assert_reparses(result, module, before=src)
        if op in ("insert_row", "insert_code_lookup", "move_row"):
            # An inserted value may name a local above its binding, or a loop index outside its
            # loop (review of head 513797260a, finding 3), and a move may carry an
            # ``occurrence=i`` row out of its loop (Manager decision 2026-10-07). Every mode refuses.
            _refuse_new_unbound_reads(
                tree, result, row, role, f"{op} at lines {line_start}-{line_end}"
            )
        if typed_only and op in ("move_row", "delete_row") and kind != "note":
            _refuse_typed_only_result(
                tree, handler_node, result, row, role, op, line_start, line_end
            )
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


def _assert_reparses(result: str, module: str, *, before: str | None = None) -> None:
    """Refuse (with zero change) a rewrite whose output is not valid Python — the VALIDITY half of gate 3.

    A last-line defense: every op is engineered to preserve validity, but re-parsing the result and
    refusing on a :class:`SyntaxError` guarantees the lens never writes broken Python into a user's file.
    This is ``ast.parse`` plus ``compile`` ONLY — it does not run ``ruff format --check``. The complementary format-
    cleanliness half of gate 3 is enforced per-op *before* emission (each op only ever produces canonical
    text): :func:`_apply_insert_row` refuses a rendered line over the column limit, and the reindent path
    refuses a depth change that would over-run (:func:`_reindent_block`) or collapse
    (:func:`_has_collapsible_wrapped_stmt`) a line — so the output ``ruff format`` would produce is the
    output the lens already wrote. Static-only: this parses and compiles (it never imports or executes) the result."""
    try:
        # `compile` too: it runs nothing, and it refuses what parses but cannot compile -- an
        # `await` in a sync handler, a walrus rebinding a comprehension variable (Theia review R1).
        with warnings.catch_warnings():
            # A SyntaxWarning in code the user already had is not this rewrite's to report.
            warnings.simplefilter("ignore", SyntaxWarning)
            compile(ast.parse(result), module, "exec", dont_inherit=True)
    except SyntaxError as exc:
        existing = None if before is None else _compile_error(before, module)
        if existing is not None:
            # The module already fails to compile, so the edit is not the cause (review of head
            # 513797260a, finding 8).
            raise LensRewriteError(
                f"{module}: the module does not compile as it stands ({existing.msg} at line "
                f"{existing.lineno}) - fix it in the text editor first; refused (no change made)"
            ) from exc
        raise LensRewriteError(
            f"{module}: the rewrite would produce invalid Python ({exc.msg} at line {exc.lineno}) - "
            "refused (no change made)"
        ) from exc
    except _PARSER_REFUSALS as exc:
        raise LensRewriteError(
            f"{module}: the rewrite would produce source the parser refuses "
            f"({_refusal_reason(exc)}) - refused (no change made)"
        ) from exc


def _compile_error(source: str, module: str) -> SyntaxError | None:
    """The :class:`SyntaxError` compiling ``source`` raises, or None. It runs nothing."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            compile(ast.parse(source), module, "exec", dont_inherit=True)
    except SyntaxError as exc:
        return exc
    except _PARSER_REFUSALS:
        return None  # the edit's own refusal is reported instead
    return None


def _apply_set_params(
    src: str,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    row: dict[str, Any],
    edit: dict[str, Any],
    line_start: int,
    line_end: int,
    *,
    scope: _Scope,
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
    if (
        row["kind"] in _MODED_KINDS
        and params
        and not _message_argument_is_msg(stmt, _message_param(handler_node))
    ):
        # ``set_field(other, "A", "B")`` projects exactly like ``set_field(msg, "A", "B")``, because the
        # projection drops the message argument, so an edit would keep writing to ``other`` while the
        # Steps view says ``msg`` (spike S-4's review of PR 2155). Every mode refuses.
        raise LensRewriteError(
            f"row at lines {line_start}-{line_end}: its message argument is not 'msg', which the "
            "Steps view does not show - editing it would keep that hidden argument; edit it as text"
        )
    _refuse_non_text_set_params(row, params)
    if row["kind"] == "send":
        for pname, node in slots.items():
            literal = isinstance(node, ast.Constant) or (
                isinstance(node, ast.Name) and _is_free_name(node.id, scope)
            )
            if pname in params and isinstance(params[pname], dict) and not literal:
                # ``Send(pick(msg), msg)`` projects with no destination value, so a Steps edit
                # would silently overwrite logic a developer wrote (Theia review finding R1). A
                # name counts as code too unless it is inert: ``dest = msg.field("MSH-5")`` makes
                # ``Send(dest, msg)`` route by the message (Lander review of PR 2155, finding 5).
                raise LensRewriteError(
                    f"row at lines {line_start}-{line_end}: the send's {pname!r} is computed by code "
                    "the Steps view does not show - editing it would overwrite that code; edit it as "
                    "text"
                )
    if row["kind"] not in _MODED_KINDS:
        return _splice_slots(src, slots, params, scope=scope)
    result = _splice_slots(src, slots, params, moded=(row["kind"], row.get("action")), scope=scope)
    if any(isinstance(v, dict) and set(v) == {"parts"} for v in params.values()):
        _refuse_overlong_template_lines(src, result, line_start, line_end)
    action = row.get("action")
    if result != src and (
        (action == "copy_field" and ("src" in params or "dst" in params))
        or (action == "set_field" and ("value" in params or "path" in params))
    ):
        before = stmt.value if isinstance(stmt, ast.Expr) else stmt
        repicked = _repick_write(result, line_start, line_end, before)
        if repicked != result:
            _refuse_overlong_repick(result, repicked, line_start, line_end)
        result = repicked
    return result


def _message_param(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """The name of the handler's message parameter: its first, ``msg`` by convention."""
    args = [*func.args.posonlyargs, *func.args.args]
    return args[0].arg if args else "msg"


def _message_argument_is_msg(stmt: ast.stmt, msg_name: str = "msg") -> bool:
    """Whether a vocabulary call's message argument is the name ``msg``.

    True for a native ``msg.<method>(...)`` row, which has no message argument, and for a call whose
    signature takes none. :func:`_rendered_param_nodes` drops this argument from ``params``, so a row
    whose message is ``other`` looks the same as one whose message is ``msg``."""
    if _recognize_native_stmt(stmt) is not None:
        return True
    call = stmt.value if isinstance(stmt, ast.Expr | ast.Assign | ast.AnnAssign) else None
    if not isinstance(call, ast.Call):
        return True
    name = _callee_name(call.func) or ""
    params = _ACTION_PARAMS.get(name) or _LOOKUP_PARAMS.get(name) or _DIAGNOSTIC_PARAMS.get(name)
    if params is None or "msg" not in params:
        return True
    return _call_message_node(call, params, msg_name) is not None


def _call_message_node(call: ast.Call, params: list[str], msg_name: str = "msg") -> ast.Name | None:
    """The ``msg`` argument of a vocabulary ``call`` whose signature names ``msg``, or None when that
    argument is missing, starred, given twice, or anything but the plain name ``msg``."""
    index = params.index("msg")
    found = [kw.value for kw in call.keywords if kw.arg == "msg"]
    if index < len(call.args):
        found.append(call.args[index])
    if any(isinstance(a, ast.Starred) for a in call.args[: index + 1]) or len(found) != 1:
        return None
    node = found[0]
    return node if isinstance(node, ast.Name) and node.id == msg_name else None


def _refuse_overlong_repick(result: str, repicked: str, line_start: int, line_end: int) -> None:
    """Refuse a write re-pick that pushes one of the row's lines past the column limit.

    ``set`` to ``set_data`` adds five columns, and the lens never wraps a line itself, so a line it
    would push past the limit is refused rather than left for ``ruff format`` to re-wrap, as
    :func:`_refuse_overlong_template_lines` refuses a template."""
    old_lines, new_lines = _physical_lines(result), _physical_lines(repicked)
    for i in range(line_start - 1, line_end):
        new = _display_width(new_lines[i])
        if new > _MAX_LINE_LENGTH and new > _display_width(old_lines[i]):
            raise LensRewriteError(
                f"this edit would make line {i + 1} {new} columns wide, past the "
                f"{_MAX_LINE_LENGTH}-column limit: a value copied from a component or subcomponent "
                "writes with msg.set_data (ADR 0206), which is longer than msg.set - shorten the "
                "paths, or edit it as text",
                code=REFUSAL_COLUMN_LIMIT,
            )


def _argument_dump(node: ast.AST) -> str:
    """``ast.dump`` of ``node`` with every constant's ``kind`` left out.

    ``kind`` records a ``u`` prefix, which is spelling and not a value. So an edit that only drops
    one compares equal, as an edit that only respells a string's quotes already does."""
    kinds = [(sub, sub.kind) for sub in ast.walk(node) if isinstance(sub, ast.Constant)]
    try:
        for sub, _ in kinds:
            sub.kind = None
        return ast.dump(node)
    finally:
        for sub, kind in kinds:
            sub.kind = kind


def _repick_write(source: str, line_start: int, line_end: int, before: ast.AST) -> str:
    """Re-pick the write of the native Copy Field or Set Field at ``line_start``-``line_end`` of
    ``source``, after an edit of a copy's ``src`` or ``dst`` or of a Set Field's ``path`` or ``value``
    (ADR 0206 rule 1).

    The write is the one an insert picks (:func:`_native_write_method`). Splicing only the arguments
    would keep the old method: a leaf read left on ``set`` into a whole field turns its decoded
    separators into structure, and authored text moved to ``set_data`` escapes the structure it
    meant into one component. For a copy the two writes are the same at a literal leaf destination,
    so there the method is left as written, and a source that is not a literal keeps its method. A
    Set Field always takes the picked method, so the row keeps reading back as ``set_field``.
    ``source`` is the already-spliced text, so the arguments read here are the ones the edit
    wrote. ``before`` is the call before the edit, compared by :func:`_argument_dump`: an edit
    that changed no argument, such as one that only respelled a string's quotes or dropped a ``u``
    prefix, leaves the write as written.

    A Set Field edit that moves its path off a literal leaf into a whole field and keeps its value
    is refused when the picked write is ``set`` and the value is not plain text. At the leaf either
    write escaped the value, so it was data, and ``set`` into a whole field would turn its
    separators into structure. Keeping ``set_data`` instead would leave a line the recognizer reads
    as code, so the edit is refused rather than guessed. Whether the value was kept is read from
    the arguments, not from which parameters the edit named."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    # The write statement spanning exactly the row's lines. Two writes sharing those lines (``;``)
    # cannot be told apart here, so neither is touched. The recognizer is not used to find it: a
    # Set Field still spelled ``set_data`` around a value just edited to plain text reads as code.
    found = [
        stmt.value
        for stmt in ast.walk(tree)
        if isinstance(stmt, ast.Expr)
        and stmt.lineno == line_start
        and stmt.end_lineno == line_end
        and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Attribute)
        and stmt.value.func.attr in ("set", "set_data")
        and _is_msg_method(stmt.value.func, stmt.value.func.attr)
        and len(stmt.value.args) == 2
        and _native_display(stmt.value) is not None
    ]
    if len(found) != 1:
        return source
    call = found[0]
    if _argument_dump(call) == _argument_dump(before):
        return source
    func = call.func
    assert isinstance(func, ast.Attribute)
    dst, value = call.args
    field_call = _msg_field_source(value)
    if field_call is None:
        want = _template_write_method(value, dst)
        if want == "set" and _moves_data_off_a_leaf(before, dst, value):
            raise LensRewriteError(
                "this path edit would move a value written as data at a component or "
                "subcomponent into a whole field, where msg.set would make its separators "
                "structure - edit it as text"
            )
    else:
        src = getattr(field_call.args[0], "value", None)
        if not isinstance(src, str) or _is_leaf_literal(getattr(dst, "value", None)):
            return source
        want = _copy_write_method(src)
    if func.attr == want or func.end_col_offset is None:
        return source
    data = source.encode("utf-8")
    end = _line_byte_starts(data)[(func.end_lineno or func.lineno) - 1] + func.end_col_offset
    return (data[: end - len(func.attr)] + want.encode("ascii") + data[end:]).decode("utf-8")


def _moves_data_off_a_leaf(before: ast.AST, dst: ast.expr, value: ast.expr) -> bool:
    """Whether an edit of a write ``before`` moved its destination off a literal leaf into a whole
    field, to ``dst``, and kept a ``value`` that is not plain text.

    Plain text is a string literal holding no character in :data:`_AUTHORED_STRUCTURE`, nor ``|``;
    ``set`` writes it the same at a leaf and in a whole field, so moving it changes nothing."""
    if not isinstance(before, ast.Call) or len(before.args) != 2:
        return False
    old_dst, old_value = before.args
    if not _is_leaf_literal(getattr(old_dst, "value", None)):
        return False
    if _is_leaf_literal(getattr(dst, "value", None)):
        return False
    if _argument_dump(old_value) != _argument_dump(value):
        return False
    text = getattr(value, "value", None) if isinstance(value, ast.Constant) else None
    plain = isinstance(text, str) and not any(
        char in _AUTHORED_STRUCTURE or char == "|" for char in text
    )
    return not plain


def _refuse_overlong_template_lines(src: str, result: str, line_start: int, line_end: int) -> None:
    """Refuse a template write that pushes one of the row's lines past the column limit (gate 3).

    A template is usually longer than the literal it replaces, and ``ruff format`` would re-wrap an
    over-long call across lines -- output the lens did not write. The lens never wraps a line itself, so
    it refuses, as :func:`_apply_insert_row` does. A line that was already over the limit and did not
    grow is left alone: the refusal is about what this edit did. Width is measured as ruff measures it,
    in display columns (:func:`_display_width`), so wide CJK text cannot slip under the limit."""
    old_lines = _physical_lines(src)
    new_lines = _physical_lines(result)
    for i in range(line_start - 1, line_end):
        old, new = _display_width(old_lines[i]), _display_width(new_lines[i])
        if new > _MAX_LINE_LENGTH and new > old:
            raise LensRewriteError(
                f"this edit would make line {i + 1} {new} columns wide, past the "
                f"{_MAX_LINE_LENGTH}-column limit - shorten the template's text, or edit it as text "
                "(every field read is written with an empty-text fallback, so an older bare read "
                "grows by 6 columns when the template is rewritten)",
                code=REFUSAL_COLUMN_LIMIT,
            )


def _display_width(line: str) -> int:
    """``line``'s width in terminal columns, the unit ruff's ``line-length`` counts.

    An East Asian wide or fullwidth character takes two columns and a combining mark none. Everything
    else takes one. This approximates ruff's width table rather than copying it. Where the two are
    known to differ (a zero-width joiner, for one) it over-counts, which errs toward a refusal near the
    limit rather than a line ruff re-wraps."""
    width = 0
    for ch in line:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


# --- note rows (ADR 0076 Amendment A) ----------------------------------------


def _check_note_op(row: dict[str, Any], op: str, line_start: int, line_end: int) -> None:
    """Refuse the note operations the v1 grammar does not support (ADR 0076 §A.4 / §A.6).

    Two refusals, for two different reasons:

    * **A pragma note is read-only.** ``# fmt: off`` / ``# noqa`` / ``# type: ignore`` are functional
      code: editing one to prose, moving it, or deleting it changes what ruff and mypy do to the file, so
      it would break §6 gate 3 (``ruff format --check``) or turn lint red.
    * **No note is movable in v1.** A comment is not an ``ast`` statement, so the move path has nothing to
      relocate — and §A.6 records that move/delete of a *recognized* row already re-attaches neighbouring
      comments to the wrong step. Making notes movable on top of that would render a confidently
      mis-positioned caption; the honest v1 answer is that a note holds its place in the file."""
    if op == "move_row":
        raise LensRewriteError(
            f"row at lines {line_start}-{line_end} is a note row — notes are not movable in v1 "
            "(a comment is not a statement); edit it as text to relocate it"
        )
    if row.get("pragma") and op in ("set_params", "delete_row"):
        raise LensRewriteError(
            f"row at lines {line_start}-{line_end} is a PRAGMA note ({row.get('text', '').strip()!r}) — "
            "it is functional code (it changes what ruff/mypy do to this file) and is read-only"
        )


def _apply_set_note(
    src: str, row: dict[str, Any], edit: dict[str, Any], line_start: int, line_end: int
) -> str:
    """Set a ``note`` row's text, preserving each line's indentation and ``#`` prefix form (§A.3 / AC-N3).

    This is the lens's first regeneration of a whole physical line — a comment has no ``ast`` node, so
    there is no verbatim argument segment to reuse the way :func:`_splice_slots` does. The compensating
    rule is that only the text AFTER the first ``#`` is replaced: the leading whitespace, the ``#`` run
    (``##``, ``#region``) and the line terminator all come from the EXISTING line, never from the
    ``insert_comment`` authoring normalizer (which is deliberately lossy: ``## banner`` → ``# banner``).

    Setting the text to its current value therefore returns the source byte-identically, and the line
    COUNT is fixed — a text with a different number of lines is refused rather than silently shifting
    every row coordinate below it."""
    params = edit.get("params", {})
    if not isinstance(params, dict):
        raise LensRewriteError("edit 'params' must be an object of {name: value}")
    if not params:
        return src  # a no-op edit round-trips byte-identically
    unknown = set(params) - {"text"}
    if unknown:
        raise LensRewriteError(
            f"unknown parameter(s) {sorted(unknown)!r} for a note row (it exposes only 'text')"
        )
    text = params["text"]
    if not isinstance(text, str):
        raise LensRewriteError("a note row's 'text' must be a string")
    if text == row.get("text"):
        return src  # unchanged → byte-identical (AC-N3)
    if "\r" in text:
        raise LensRewriteError("a note row's 'text' must not contain a carriage return")
    new_bodies = text.split("\n")
    span = line_end - line_start + 1
    if len(new_bodies) != span:
        raise LensRewriteError(
            f"the note spans {span} line(s) but the new text has {len(new_bodies)} — editing a note "
            "may not change the file's line count; insert or delete a note row instead"
        )
    lines = _physical_lines_keepends(src)
    for offset, body in enumerate(new_bodies):
        original = lines[line_start - 1 + offset]
        term = _line_terminator(original)
        content = original[: len(original) - len(term)]
        prefix = content[: content.index("#") + 1]  # indent + the '#' run's first hash
        physical = prefix + body
        if len(physical) > _MAX_LINE_LENGTH:
            raise LensRewriteError(
                f"the edited comment would be {len(physical)} columns — over the {_MAX_LINE_LENGTH}-"
                "column limit; shorten it"
            )
        lines[line_start - 1 + offset] = physical + term
    return "".join(lines)


def _apply_delete_note(src: str, line_start: int, line_end: int) -> str:
    """Remove a ``note`` row's physical lines; every other byte is preserved (gate 2).

    A comment is never a statement, so unlike :func:`_apply_delete_row` this can never empty a suite."""
    lines = _physical_lines_keepends(src)
    del lines[line_start - 1 : line_end]
    return "".join(lines)


# --- route rows (ADR 0076 Amendment D) ---------------------------------------


def _apply_set_route(
    src: str,
    element_node: ast.FunctionDef | ast.AsyncFunctionDef,
    row: dict[str, Any],
    edit: dict[str, Any],
    line_start: int,
    line_end: int,
) -> str:
    """Set a ``route`` row's handler list — a byte-splice of the return's value expression (AC-R4).

    Setting the list to its current value returns the source byte-identically, which also means a
    DYNAMIC return (``return [pick(msg)]``, projected as ``handlers: []`` with no ``unrouted``) is never
    silently flattened to ``[]``: an edit that "changes nothing" changes nothing."""
    params = edit.get("params", {})
    if not isinstance(params, dict):
        raise LensRewriteError("edit 'params' must be an object of {name: value}")
    if not params:
        return src
    unknown = set(params) - {"handlers"}
    if unknown:
        raise LensRewriteError(
            f"unknown parameter(s) {sorted(unknown)!r} for a route row (it exposes only 'handlers')"
        )
    handlers = params["handlers"]
    if not isinstance(handlers, list) or not all(isinstance(h, str) for h in handlers):
        raise LensRewriteError("a route row's 'handlers' must be a list of handler-name strings")
    if handlers == row.get("handlers"):
        return src  # unchanged → byte-identical (AC-R4)
    stmt = _find_stmt(element_node.body, line_start, line_end)
    if not isinstance(stmt, ast.Return):
        raise LensRewriteError(
            f"internal: could not locate the routing return at lines {line_start}-{line_end}"
        )
    if stmt.value is None:
        raise LensRewriteError(
            f"row at lines {line_start}-{line_end} is a bare 'return' — there is no destination list to "
            "splice; edit it as text"
        )
    base = stmt.value
    literal = (
        isinstance(base, ast.Constant) and (base.value is None or isinstance(base.value, str))
    ) or (
        isinstance(base, ast.List | ast.Tuple)
        and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in base.elts)
    )
    if not literal:
        # ``return [pick(msg)]`` projects as ``handlers: []``, so writing a list over it would silently
        # destroy routing logic a developer wrote (Theia review finding R1). Every mode refuses.
        raise LensRewriteError(
            f"row at lines {line_start}-{line_end}: the route's handler list is computed by code the "
            "Steps view does not show - editing it would overwrite that code; edit it as text"
        )
    rendered = "[" + ", ".join(_str_lit(h) for h in handlers) + "]"
    # Route through the audited slot splice: it works in UTF-8 byte space, refuses a multi-line value
    # (which would change the line count), and validates the rendered expression parses.
    return _splice_slots(
        src, {"handlers": stmt.value}, {"handlers": {"expr": rendered}}, scope=_NO_NAMES
    )


# --- rewrite helpers ---------------------------------------------------------


def _find_contract_row(
    contracts: list[dict[str, Any]], line_start: int, line_end: int, handler_filter: str | None
) -> dict[str, Any] | None:
    """The contract row whose span is exactly ``[line_start, line_end]``, annotated with its element.

    ``_handler`` is the enclosing element's registered name and ``_role`` its decorator role — the pair
    the rewrite half needs to re-locate the def (a router is looked up by ``@router``, not ``@handler``)."""
    for contract in contracts:
        if handler_filter is not None and contract["handler"] != handler_filter:
            continue
        for row in contract["rows"]:
            if row["line_start"] == line_start and row["line_end"] == line_end:
                return {
                    **row,
                    "_handler": contract["handler"],
                    "_role": contract.get("role", "handler"),
                }
    return None


def _element_def(
    tree: ast.Module, name: str, role: str
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """The ``@handler``/``@router`` FunctionDef registered as ``name`` for ``role`` (or None)."""
    resolve = _router_name if role == "router" else _handler_name
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and resolve(node) == name:
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
    :func:`_recognize_native_stmt` so the splice targets the native method-call args (``path``=arg0,
    ``value``=arg1 — no leading ``msg`` positional; ``copy_field``'s ``src`` is the inner
    ``msg.field(src)`` arg), and read-only keywords (``occurrence=``) are deliberately absent so a splice
    never touches them. For a **wrapper** call (``set_field(msg, …)``) the leading ``msg`` positional is
    dropped and each named positional + keyword value becomes a slot, exactly as before."""
    if kind == "send":
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            send = stmt.value
            return {_SEND_TO: send.args[0]} if send.args else {}
        # ``sends.append(Send(dest, msg))`` — edit the INNER Send's destination (arg0), NOT the append's
        # own argument; the byte-splice then replaces only the destination literal.
        match = _match_append_send(stmt)
        if match is not None:
            send = match[1]
            return {_SEND_TO: send.args[0]} if send.args else {}
        return None
    # action / lookup — a bare call, or an assignment whose value is the call.
    call: ast.Call | None = None
    if (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Call)
        or isinstance(stmt, ast.Assign | ast.AnnAssign)
        and isinstance(stmt.value, ast.Call)
    ):
        call = stmt.value
    if call is None:
        return None
    # A native write, or row 4's ``name = msg.field(path)`` read: the recognizer is the single source of
    # truth for the editable arg nodes. The read-only ``occurrence=`` kwarg and a read's bound name are
    # never slots.
    native = _recognize_native_stmt(stmt)
    if native is not None:
        return dict(native.slots)
    name = _callee_name(call.func)
    param_names = (
        _ACTION_PARAMS.get(name or "")
        or _LOOKUP_PARAMS.get(name or "")
        or _DIAGNOSTIC_PARAMS.get(
            name or ""
        )  # log_note→[template], checkpoint→[msg,label] (ADR 0106 §5 K)
    )
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
    *,
    moded: tuple[str, str | None] | None = None,
    scope: _Scope,
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
    source (F3), and a co-located ``occurrence=`` kwarg (not in ``slots``) survives untouched.

    ``moded`` (the row's kind and action name) applies ADR 0076 Amendment E's per-argument modes
    (:func:`_render_moded_value`). Only ``set_params`` on an action, lookup or diagnostic row passes it:
    a route row's handler list and a send row's destination have no mode, and route editing splices its
    own ``{"expr": ...}`` through here."""
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
        if moded is not None:
            # Before the multi-line check, so a dynamic argument always reports dynamic-mode.
            _refuse_dynamic_argument(node, pname)
        _refuse_multiline_arg(node, pname)
        consumed.add(pname)
        rendered: str | None
        if moded is not None:
            kind, action = moded
            rendered = _render_moded_value(
                params[pname], node, pname, kind, _template_ok(kind, action, pname)
            )
        else:
            rendered = _render_new_value(params[pname], isinstance(node, ast.Constant), pname)
            if isinstance(params[pname], dict):
                # A send row's destination, or the route list this module renders itself: an ``expr``
                # here must run no code either (Theia review finding R1). The moded branch above is
                # stricter already -- it takes a literal only.
                _refuse_active_expr(rendered, pname, scope=scope)
        if rendered is None:
            continue  # unchanged template: leave the argument's bytes exactly as they are
        start, end = _byte_span(
            node
        )  # for a keyword slot this is the value node, never the ``name=``
        edits.append((start, end, rendered.encode("utf-8")))

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
    ``{"expr": "<source>"}`` object splices verbatim (validated to parse as a single expression). On a
    send row that is how a non-literal destination is edited, and :func:`_splice_slots` then refuses
    one that runs code (Theia review finding R1). On an action, lookup or diagnostic row
    :func:`_render_moded_value` calls this and then refuses any ``expr`` that is not a literal."""
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


def _refuse_dynamic_argument(node: ast.expr, pname: str) -> None:
    """Refuse any edit of an argument whose mode is ``dynamic`` (AC-M5, E.6.4)."""
    if _param_mode(node) == MODE_DYNAMIC:
        raise LensRewriteError(
            f"parameter {pname!r} is in dynamic mode (an expression the lens cannot write back "
            "faithfully) - it is read-only here; edit it as text (ADR 0076 E.6.4)",
            code=REFUSAL_DYNAMIC_MODE,
        )


def _all_reads_fallback(node: ast.expr) -> bool:
    """Whether every read in the f-string ``node`` is already the E.11 ``msg["X"] or ""`` form."""
    return isinstance(node, ast.JoinedStr) and all(
        _is_empty_fallback_read(v.value) for v in node.values if isinstance(v, ast.FormattedValue)
    )


def _render_moded_value(
    value: Any, node: ast.expr, pname: str, kind: str, template_ok: bool
) -> str | None:
    """Render a ``set_params`` value for a moded argument (ADR 0076 Amendment E), or refuse.

    Returns None when the value is the parts the argument already has and every read is already in
    the E.11 form, so the caller leaves its bytes alone.

    The CURRENT argument's mode decides what may happen to it:

    * ``dynamic`` -- refused, whatever the value (AC-M5, E.6.4). Its source is an open-set expression the
      lens does not round-trip, so it is read-only, and passing it through would look like success.
    * ``static`` or ``templated`` -- writable, and the value picks the NEW mode. A JSON scalar writes a
      literal (``static``); ``{"parts": [...]}`` writes a bounded interpolation (``templated``,
      :func:`_render_parts`) where ``template_ok`` allows it. Switching between the two bounded modes is
      allowed in both directions, because each is a shape the lens can write and read back (E.3).

    ``{"expr": <source>}`` is still accepted, but only when the expression is a literal. A ``dynamic``
    one would author the open-set shape E.7 keeps read-only; a bare ``msg["X"]`` read is ``dynamic``
    (only an f-string is ``templated``), so a path pick writes ``{"parts": [{"path": "X"}]}``, which
    renders ``f"{msg['X'] or ''}"``. A ``templated`` one is refused too, so that every templated write goes
    through the parts renderer and its round-trip gate: E.5 admits ``msg.field`` reads that no parts
    list can express, and one of them, ``msg.field("OBX-5", 2)``, raises at runtime."""
    _refuse_dynamic_argument(node, pname)
    if isinstance(value, dict):
        if set(value) == {"parts"}:
            if not template_ok:
                _refuse_templated_write(kind, pname)
            rendered_parts = _render_parts(value["parts"], pname)
            if _template_parts(node) == _normalize_parts(value["parts"]) and _all_reads_fallback(
                node
            ):
                # The parts the argument already has, every read already in the E.11 form: an edit
                # that changes nothing changes nothing, so an F-prefix or triple quotes is not
                # respelled. An older bare or msg.field read is NOT left alone, because resending
                # its parts is the only way the IDE can apply the E.11 fix to it.
                return None
            return rendered_parts
        if set(value) != {"expr"} or not isinstance(value["expr"], str):
            raise LensRewriteError(
                f"parameter {pname!r}: an object value must be {{'parts': [...]}} or "
                "{'expr': <source string>}",
                code=REFUSAL_TEMPLATE_SHAPE,
            )
    rendered = _render_new_value(value, True, pname)
    if isinstance(value, dict):
        new_node = ast.parse(rendered, mode="eval").body
        if isinstance(new_node, ast.Constant):
            # Re-render through the literal renderer: that canonicalizes the spelling (gate 3) and
            # refuses a constant JSON cannot carry (bytes, ``...``, a complex number).
            return _render_literal(new_node.value, pname)
        new_mode = _param_mode(new_node)
        if new_mode == MODE_DYNAMIC:
            raise LensRewriteError(
                f"parameter {pname!r}: the expression would write a dynamic-mode argument, which is "
                "read-only - only a literal or a template may be written here (ADR 0076 E.6.4)",
                code=REFUSAL_DYNAMIC_MODE,
            )
        if new_mode == MODE_TEMPLATED:
            raise LensRewriteError(
                f"parameter {pname!r}: write a template as {{'parts': [...]}}, not as an expression, "
                "so the engine renders it and checks it reads back",
                code=REFUSAL_TEMPLATE_SHAPE,
            )
    return rendered


def _refuse_templated_write(kind: str, pname: str) -> NoReturn:
    """Refuse to WRITE a templated value into an argument outside :data:`_TEMPLATE_PARAMS`. Always raises.

    A template puts message content into the argument, and outside a value parameter that content lands
    somewhere it must not. A lookup's connection, statement or query built from inbound HL7 is an
    injection path: the SQL or FHIR search would carry attacker-influenceable text. A diagnostic's
    template or label is logged UNREDACTED -- ``log_note`` redacts only its operands and ``checkpoint``
    logs its label verbatim -- so a field read interpolated there would put PHI into the log (CLAUDE.md
    section 9). An action's path, segment id, index or setting would let the message choose which field
    is overwritten, or put a string where an int belongs.

    Only the write is refused. An existing templated argument still reads as ``templated`` and may be
    switched to a literal."""
    if kind == "lookup":
        reason = (
            "a template would build the connection, statement or query from message content "
            "(an injection path)"
        )
    elif kind == "diagnostic":
        reason = (
            "a template would log message field values unredacted (log_note redacts only its "
            "operands)"
        )
    else:
        reason = (
            "only a value parameter takes a template (set_field or add_repetition value, "
            "append_to_field suffix, replace_literal new); a path, segment id, index or setting "
            "chosen by message content is refused"
        )
    raise LensRewriteError(
        f"parameter {pname!r} takes a literal only: {reason}", code=REFUSAL_LITERAL_ONLY
    )


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
        # ``repr`` of inf / nan is ``inf`` / ``nan``, a bare NAME, so the spliced call would raise
        # NameError on every message. There is no literal spelling of either, so refuse.
        if not math.isfinite(value):
            raise LensRewriteError(
                f"parameter {pname!r}: {value!r} has no Python literal form - use a finite number"
            )
        return repr(value)
    if isinstance(value, str):
        # ``ensure_ascii=False`` is load-bearing: the DEFAULT ``ensure_ascii=True`` \u-escapes every
        # non-ASCII char, which (a) for an ASTRAL (non-BMP) char like U+1F6F0 emits a UTF-16 SURROGATE
        # PAIR (``🛰``) that Python re-parses as two lone surrogates — a corrupted value that
        # then raises UnicodeEncodeError when the engine encodes the outbound — and (b) for a BMP char
        # emits a ``\uXXXX`` escape that diverges from ruff's canonical raw-char form (gate 3). Emitting
        # the raw UTF-8 char is value-preserving and ruff-canonical; control chars < U+0020 stay escaped.
        # A lone surrogate (a JSON "\udXXX" escape) has no UTF-8 form, so the splice would raise
        # UnicodeEncodeError instead of refusing; refuse it here.
        if not _is_encodable(value):
            raise LensRewriteError(
                f"parameter {pname!r}: the value carries a character that cannot be encoded as UTF-8"
            )
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
    except _PARSER_REFUSALS as exc:
        # The expression is left out: only very long source reaches the parser walls.
        raise LensRewriteError(
            f"parameter {pname!r}: the expression is not a valid Python expression "
            f"({_refusal_reason(exc)})"
        ) from exc
    try:
        probe: ast.expr | None = ast.parse(f"_f({expr})", mode="eval").body
    except SyntaxError:
        probe = None
    except _PARSER_REFUSALS as exc:
        # One call deeper than the parse above, so it can trip the wall that parse cleared. Refuse for
        # that reason, not as the extra-argument refusal below, which would name the wrong cause.
        raise LensRewriteError(
            f"parameter {pname!r}: the expression is not a valid call argument "
            f"({_refusal_reason(exc)})"
        ) from exc
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


def _is_dunder(name: str) -> bool:
    """Whether ``name`` is a ``__dunder__`` name, which no Steps edit writes or binds."""
    return name.startswith("__") and name.endswith("__")


#: How much an inserted ``{"expr": ...}`` value may carry (:func:`_insert_value_policy`).
#: ``literal``: no message content. ``value``: a message read or template is fine. ``db_params`` /
#: ``fhir_params``: a dict whose keys are literal and whose values may read; a FHIR one may also hold
#: ``FhirToken(system, code)``, the documented ``system|code`` search value.
_POLICY_LITERAL = "literal"
_POLICY_VALUE = "value"
_POLICY_DB_PARAMS = "db_params"
_POLICY_FHIR_PARAMS = "fhir_params"


def _insert_value_policy(call: str, pname: str) -> str:
    """The :data:`_POLICY_LITERAL` family an inserted ``call``'s ``pname`` falls in.

    Message content is admitted only in the value parameters :data:`_TEMPLATE_PARAMS` lists and in the
    VALUES of a live lookup's ``params`` mapping, which are bound as query parameters rather than spliced
    into the statement or query text. Everywhere else it is the injection or PHI path
    :func:`_refuse_templated_write` names."""
    if (call, pname) in _TEMPLATE_PARAMS:
        return _POLICY_VALUE
    if pname == "params" and call == "db_lookup":
        return _POLICY_DB_PARAMS
    if pname == "params" and call == "fhir_lookup":
        return _POLICY_FHIR_PARAMS
    return _POLICY_LITERAL


def _is_field_call(node: ast.expr, *, scope: _Scope) -> bool:
    """Whether ``node`` is ``msg.field("LIT")`` with only ``occurrence=``/``repetition=`` keywords whose
    values are 1 or more on every message (:func:`_is_index_value`: int arithmetic, a 1-based
    For-Each index such as ``occurrence=i``, or that index added on either side to int-literal
    arithmetic that comes to 0 or more, such as ``i + 1`` or ``2 + i``), or a
    ``repetition=None``.

    Stricter than :func:`_is_bounded_message_read`, which also admits extra POSITIONAL constants:
    ``Message.field`` takes ``occurrence`` and ``repetition`` keyword-only, so ``msg.field("X", 2)``
    raises TypeError on every message. That classifier is left alone because AC-M3 pins what it reads
    as ``templated``; this one decides only what a Steps insert may write."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "field"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "msg"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and all(
            kw.arg in ("occurrence", "repetition")
            and (
                # The same 1-or-more rule as a top-level occurrence (Lander review of PR 2154):
                # ``occurrence=0`` raises ValueError on every message. ``occurrence=OCC`` is
                # refused because the lens does not bound a module name's value, not because it
                # always raises (Manager decision 2026-10-07: conservative, fails closed).
                _is_index_value(kw.value, scope)
                or (
                    kw.arg == "repetition"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is None
                )
            )
            for kw in node.keywords
        )
    )


def _is_field_read(node: ast.expr, *, scope: _Scope) -> bool:
    """Whether ``node`` is a message read that runs as written: ``msg["LIT"]``, an admitted
    ``msg.field(...)`` call (:func:`_is_field_call`), or either one with an ``or ""`` fallback -- the
    form the lens itself writes for ``copy_field``."""
    if _is_msg_subscript(node) or _is_field_call(node, scope=scope):
        return True
    return (
        isinstance(node, ast.BoolOp)
        and isinstance(node.op, ast.Or)
        and len(node.values) == 2
        and (_is_msg_subscript(node.values[0]) or _is_field_call(node.values[0], scope=scope))
        and isinstance(node.values[1], ast.Constant)
        and node.values[1].value == ""
    )


def _is_free_name(name: str, scope: _Scope) -> bool:
    """Whether a plain name may appear where message content may not: one :func:`_message_scope`
    lists as inert, and nothing else."""
    return name in scope.inert


#: The constant types a Steps edit writes. Bytes, complex numbers and ``...`` are left out: no
#: vocabulary parameter takes one, and a typed form cannot produce one.
_INERT_CONSTANT_TYPES = (str, int, float, bool, type(None))

#: The deepest expression tree the inert check walks. A typed value is a few levels deep; a
#: thousand-term ``1+1+...`` would otherwise exhaust the recursion limit (Theia review finding R1).
_MAX_INERT_DEPTH = 40


def _expr_depth(node: ast.AST) -> int:
    """The depth of ``node``'s tree, measured without recursion."""
    deepest = 0
    pending: list[tuple[ast.AST, int]] = [(node, 1)]
    while pending:
        current, depth = pending.pop()
        deepest = max(deepest, depth)
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(current))
    return deepest


def _is_inert_value(node: ast.expr, *, reads_ok: bool, scope: _Scope) -> bool:
    """Whether ``node`` is a value a typed Steps edit may write as ``{"expr": ...}``.

    Theia review finding R1: an ``{"expr": ...}`` on ``insert_row`` (and its occurrence kwargs and the
    code-lookup ``default``) or on a send row's destination was spliced verbatim, so a typed edit could
    write ``__import__("os").system(...)`` into a handler. A ``set_params`` on an action, lookup or
    diagnostic row was already closed by ADR 0076 Amendment E (only a literal); this closes at least
    those other paths. The caller bounds the tree's depth first (:data:`_MAX_INERT_DEPTH`).

    A CLOSED set, built on the existing classifiers. Always admitted:

    * a ``str``, ``int``, ``float``, ``bool`` or ``None`` literal, and a sign on a number (``-1``);
    * ``+`` and ``-`` over numbers and names bound to a number (``i + 1``, ``LIMIT - 1``); ``*``,
      ``/`` and ``//`` over number literals only, with a non-zero divisor. No ``%`` and no ``**``;
    * a plain name :func:`_is_free_name` admits: an unmutated module-level name bound only to an
      immutable literal or a ``code_set`` capture, or a For-Each ``range`` loop index
      (:func:`_message_scope`). Neither can hold message content;
    * a list, tuple, set or dict built only from admitted values, with no ``*``/``**`` splat.

    Admitted only where ``reads_ok``:

    * a message read (:func:`_is_field_read`), or a ``templated`` f-string whose every read is one;
    * any other non-dunder plain name except ``msg``: a local may hold message content, which is
      exactly what ``reads_ok`` allows.

    Everything else is refused: any other call, any attribute access, a subscript of anything but
    ``msg``, any other operator, a lambda, a comprehension. Nothing admitted here calls anything."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, _INERT_CONSTANT_TYPES)
    if _param_mode(node) == MODE_TEMPLATED and isinstance(node, ast.JoinedStr):
        reads = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
        return not reads or (reads_ok and all(_is_field_read(r, scope=scope) for r in reads))
    if _is_field_read(node, scope=scope):
        return reads_ok
    if isinstance(node, ast.Name):
        if node.id in scope.code_sets:
            return False  # a CodeSet is admitted only as code_lookup's table (:func:`_table_scope`)
        if reads_ok and node.id != "msg" and node.id in scope.handler_locals:
            return True  # a handler local may hold message content, which a value may carry
        # Otherwise only an inert name, on the reads_ok path too: a mutable module name such as
        # ``SEEN``, an import, a builtin or an unbound name is refused everywhere (Manager decision
        # 2026-10-07, review of PR 2154).
        return _is_free_name(node.id, scope)
    if isinstance(node, ast.UnaryOp | ast.BinOp):
        return _is_arithmetic(node, reads_ok=reads_ok, scope=scope, names_ok=True)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(
            _is_inert_value(e, reads_ok=reads_ok, scope=scope)
            and (not isinstance(node, ast.Set) or _is_hashable_shape(e))
            for e in node.elts
        )
    if isinstance(node, ast.Dict):
        return all(
            k is not None
            and _is_hashable_shape(k)
            and _is_inert_value(k, reads_ok=reads_ok, scope=scope)
            and _is_inert_value(v, reads_ok=reads_ok, scope=scope)
            for k, v in zip(node.keys, node.values, strict=True)
        )
    return False


def _is_hashable_shape(node: ast.expr) -> bool:
    """Whether `node` can be a set member or dict key: not a list, dict or set, nor a tuple holding
    one (`{[1]}` runs nothing, but raises TypeError on every message)."""
    if isinstance(node, ast.List | ast.Dict | ast.Set):
        return False
    if isinstance(node, ast.Tuple):
        return all(_is_hashable_shape(e) for e in node.elts)
    return True


def _is_arithmetic(node: ast.expr, *, reads_ok: bool, scope: _Scope, names_ok: bool) -> bool:
    """Admitted arithmetic (see :func:`_is_inert_value`). ``names_ok`` is False under ``*``, ``/`` and
    ``//``: a name may hold a string, and ``s * 2000000000`` repeats it into gigabytes per message."""
    if isinstance(node, ast.Constant):
        return type(node.value) in (int, float)
    if isinstance(node, ast.Name):
        # A local may hold message text, and ``-text`` or ``text + 1`` raises TypeError on every
        # message, so only a name bound to a number is admitted (Lander review of PR 2155, finding 11).
        return names_ok and node.id in scope.numeric
    if isinstance(node, ast.UnaryOp):
        return isinstance(node.op, ast.USub | ast.UAdd) and _is_arithmetic(
            node.operand, reads_ok=reads_ok, scope=scope, names_ok=names_ok
        )
    if not isinstance(node, ast.BinOp):
        return False
    if isinstance(node.op, ast.Add | ast.Sub):
        return _is_arithmetic(
            node.left, reads_ok=reads_ok, scope=scope, names_ok=names_ok
        ) and _is_arithmetic(node.right, reads_ok=reads_ok, scope=scope, names_ok=names_ok)
    if not isinstance(node.op, ast.Mult | ast.Div | ast.FloorDiv):
        return False
    if isinstance(node.op, ast.Div | ast.FloorDiv) and not (
        isinstance(node.right, ast.Constant)
        and type(node.right.value) in (int, float)
        and node.right.value != 0
    ):
        return False  # a divisor that is zero, or could be, raises ZeroDivisionError per message
    return _is_arithmetic(
        node.left, reads_ok=reads_ok, scope=scope, names_ok=False
    ) and _is_arithmetic(node.right, reads_ok=reads_ok, scope=scope, names_ok=False)


#: The FHIR search value classes an inserted `fhir_lookup` may construct; their import is injected.
_FHIR_VALUE_OBJECTS = frozenset({"FhirToken", "FhirRaw"})


def _is_fhir_value_object(v: ast.expr, *, scope: _Scope) -> bool:
    """``FhirToken(system, code)`` with a literal system and a code that may read the message, or
    ``FhirRaw(<string literal>)``: the documented FHIR search value objects. ``FhirRaw`` is author
    syntax passed through unscreened, and its own docstring says never to build one from message
    data, so it takes a literal only."""
    if not (isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and not v.keywords):
        return False
    if _is_shadowed(v.func.id, scope):
        return False  # a local or module binding of that name shadows the class
    if v.func.id == "FhirToken":
        return (
            len(v.args) == 2
            and _is_inert_value(v.args[0], reads_ok=False, scope=scope)
            and _is_inert_value(v.args[1], reads_ok=True, scope=scope)
        )
    return (
        v.func.id == "FhirRaw"
        and len(v.args) == 1
        and isinstance(v.args[0], ast.Constant)
        and isinstance(v.args[0].value, str)
    )


def _is_inert_params_dict(node: ast.expr, *, scope: _Scope, fhir: bool) -> bool:
    """Whether ``node`` is a lookup ``params`` value: a dict with literal keys and values that may read
    the message, or ``None``. Both lookups take ``params: Mapping[str, ...] | None``, so a list is
    refused. A FHIR one may also hold :func:`_is_fhir_value_object` values, alone or in a list (a
    repeated search parameter)."""
    if isinstance(node, ast.Constant) and node.value is None:
        return True  # the signature's own default
    if not isinstance(node, ast.Dict):
        return False

    def _value_ok(v: ast.expr, *, top: bool) -> bool:
        if _is_inert_value(v, reads_ok=True, scope=scope):
            return True
        if fhir and top and isinstance(v, ast.List):
            return all(_value_ok(e, top=False) for e in v.elts)
        return fhir and _is_fhir_value_object(v, scope=scope)

    # A key is a string literal: both lookups take ``Mapping[str, ...]``, and an unhashable key such
    # as ``[1]`` raises TypeError on every message (Lander review of PR 2155, finding 6).
    return all(
        isinstance(k, ast.Constant) and isinstance(k.value, str) and _value_ok(v, top=True)
        for k, v in zip(node.keys, node.values, strict=True)
    )


def _bound_names(node: ast.AST) -> list[str]:
    """Every name ``node``'s subtree binds, once per binding site.

    Assignment, ``for``, ``with`` and comprehension targets (``ast.Name`` in a Store context), ``except
    ... as`` names, ``match`` captures, imports, nested ``def``/``class`` names, and the parameters of a
    nested ``def`` or ``lambda``. A ``from m import *`` contributes ``*``."""
    out: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            out.append(n.id)
        elif isinstance(n, ast.ExceptHandler | ast.MatchAs | ast.MatchStar) and n.name:
            out.append(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            out.append(n.rest)
        elif isinstance(n, ast.Import | ast.ImportFrom):
            out.extend((al.asname or al.name).split(".")[0] for al in n.names)
        elif isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and n is not node:
            out.append(n.name)
        elif isinstance(n, ast.arg):
            out.append(n.arg)
    return out


class _Scope(NamedTuple):
    """What an ``{"expr": ...}`` in one handler may name (:func:`_message_scope`).

    ``locals`` are the names that may hold message content. ``inert`` are the only names admitted
    where message content may not go, and ``numeric`` is the subset bound to a number: the only names
    arithmetic takes. ``code_sets`` are the ``code_set("<literal>")`` captures, which are in neither:
    a ``CodeSet`` keeps shared mutable storage, so one is admitted ONLY as ``code_lookup``'s ``table``
    (Manager decision 2026-10-07; :func:`_table_scope`)."""

    locals: frozenset[str]
    inert: frozenset[str]
    numeric: frozenset[str]
    code_sets: frozenset[str] = frozenset()
    loop_indexes: frozenset[str] = frozenset()
    shadows: frozenset[str] = frozenset()
    #: Names the handler itself binds that no function declares ``global``: the only names a
    #: value may carry beyond ``inert`` (ADR 0076 G.7). A ``global`` name is module state.
    handler_locals: frozenset[str] = frozenset()
    #: Names known to hold text: a module ``str`` literal, or a handler local every binding of which
    #: is a string literal, an f-string or a message read (:func:`_text_locals`).
    text: frozenset[str] = frozenset()


def _is_shadowed(name: str, scope: _Scope) -> bool:
    """Whether ``name`` is bound in the handler, or at module level by anything but an import from
    ``messagefoundry``: then ``set_field`` or ``FhirToken`` may be the module's own code (review of
    PR 2155 head 513797260a, finding 4)."""
    return name in scope.locals or name in scope.shadows


def _module_shadows(tree: ast.Module) -> frozenset[str]:
    """Names bound at module scope by anything other than ``from messagefoundry... import``."""
    out: set[str] = set()
    pending: list[ast.AST] = list(tree.body)
    while pending:
        node = pending.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            out.add(node.name)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.ImportFrom):
            if node.level or (node.module or "").split(".")[0] != "messagefoundry":
                out.update(al.asname or al.name for al in node.names)
        elif isinstance(node, ast.Import):
            out.update((al.asname or al.name).split(".")[0] for al in node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            out.add(node.id)
        elif isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar) and node.name:
            out.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            out.add(node.rest)
        pending.extend(ast.iter_child_nodes(node))
    return frozenset(out)


def _param_scope(call: str, pname: str | None, scope: _Scope) -> _Scope:
    """The scope for argument ``pname`` of vocabulary ``call``: :func:`_table_scope` for
    ``code_lookup``'s ``table``, ``scope`` itself everywhere else."""
    return _table_scope(scope) if (call, pname) == ("code_lookup", "table") else scope


def _table_scope(scope: _Scope) -> _Scope:
    """``scope`` with its ``code_set`` captures admitted, for ``code_lookup``'s ``table`` only."""
    return scope._replace(inert=scope.inert | scope.code_sets, code_sets=frozenset())


#: The scope of a value the lens renders itself from literals (a route's handler list).
_NO_NAMES = _Scope(frozenset({"msg"}), frozenset(), frozenset())

#: Builtins that let a module rebind its own globals where :func:`_inert_module_literals` cannot see.
_GLOBALS_WRITERS = frozenset({"globals", "locals", "vars", "exec", "eval", "setattr", "__import__"})

#: Attributes that reach a module's globals: ``h.__globals__``, ``sys.modules``, ``mod.__dict__``.
_GLOBALS_ATTRS = frozenset(
    {
        "__globals__",
        "__dict__",
        "__builtins__",
        "modules",
        "f_globals",
        "f_locals",
        "f_builtins",
        "__getattribute__",
        "attrgetter",
    }
)


def _message_scope(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.Module,
    *,
    extra_inert: str | None = None,
) -> _Scope:
    """The names an ``{"expr": ...}`` in ``func`` may reference, as a :class:`_Scope`.

    ``locals`` is every name the handler binds (:func:`_bound_names`; its parameters, ``msg`` above
    all), except a For-Each ``range`` loop index, plus every name any function in the module declares
    ``global``: any of those may have been read from the message (``pid5 = msg.field("PID-5")``).

    ``inert`` is an ALLOW list (Manager decision 2026-10-07; Lander review of PR 2155, finding 7). It
    holds a For-Each loop index and an unmutated module-level literal the handler does not shadow
    (:func:`_inert_module_literals`), and nothing else: not an import, not a builtin, not a name bound
    to a list. ``extra_inert`` adds the ``code_set`` capture an insert is about to write.

    A loop index is admitted only when every binding of the name is a ``for <name> in range(...)``
    target, and only while ``range`` is the builtin: rebound in the handler or module, or possibly
    supplied by a star import, voids the exemption. Its bounds may come from the message
    (``range(int(msg[...]))``), but the builtin yields only ints, so the index carries a number and
    never message text."""
    bound = _bound_names(func)
    range_targets = [
        n.target.id
        for n in ast.walk(func)
        if isinstance(n, ast.For | ast.AsyncFor)
        and isinstance(n.target, ast.Name)
        and isinstance(n.iter, ast.Call)
        and isinstance(n.iter.func, ast.Name)
        and n.iter.func.id == "range"
    ]
    loop_indexes = {x for x in set(range_targets) if bound.count(x) == range_targets.count(x)}
    # ``occurrence=i`` is 1 or more only when every loop binding ``i`` starts at 1 or more.
    # Every loop binding the name must qualify: ``range(k, n)`` or ``range(k, n, step)`` with literal
    # ``k >= 1`` and literal ``step >= 1`` (review of head bd5843dbd4, findings 1 and 2).
    zero_based = {
        n.target.id
        for n in ast.walk(func)
        if isinstance(n, ast.For | ast.AsyncFor)
        and isinstance(n.target, ast.Name)
        and not _is_one_based_range(n.iter)
    }
    module_names, star = _module_bound_names(tree)
    globals_ = {name for n in ast.walk(tree) if isinstance(n, ast.Global) for name in n.names}
    # A ``global range`` in any function can rebind the builtin from inside that function, which
    # :func:`_module_bound_names` does not see (Lander review of 2558f17928, finding B).
    if star or "range" in bound or "range" in module_names or "range" in globals_:
        loop_indexes = set()
    # A ``global``-declared index is module state, so it may carry one message's text into the next
    # (Lander review of 2558f17928, finding A).
    loop_indexes -= globals_
    locals_ = frozenset((set(bound) - loop_indexes) | globals_ | {"msg"})
    literals = _inert_module_literals(tree)
    if extra_inert is not None:
        literals[extra_inert] = "code_set"
    unshadowed = {n: kind for n, kind in literals.items() if n not in locals_}
    code_sets = {n for n, kind in unshadowed.items() if kind == "code_set"}
    inert = (set(unshadowed) - code_sets) | loop_indexes
    numeric = {n for n, kind in unshadowed.items() if kind == "number"} | loop_indexes
    return _Scope(
        locals_,
        frozenset(inert),
        frozenset(numeric),
        frozenset(code_sets),
        frozenset(loop_indexes - zero_based),
        _module_shadows(tree),
        frozenset(set(bound) - loop_indexes - globals_ - {"msg"}),
        frozenset(
            {n for n, kind in unshadowed.items() if kind == "text"}
            | (_text_locals(func, frozenset(loop_indexes - zero_based)) - globals_ - {"msg"})
        ),
    )


def _text_locals(
    func: ast.FunctionDef | ast.AsyncFunctionDef, loop_indexes: frozenset[str]
) -> set[str]:
    """The handler names every binding of which is ``NAME = <text>``: a string literal, an f-string
    or an admitted message read (:func:`_is_field_read`, so ``msg.field("X", occurrence=i)`` in a
    For-Each counts; ``loop_indexes`` are the 1-based indexes it may name). Any other binding of the
    name, such as a lookup result, a loop target, an import, a nested ``def`` or an augmented
    assignment, leaves it out (review of 1d7340b2d6, findings 1 and 2)."""
    reads = _Scope(frozenset(), frozenset(), loop_indexes, loop_indexes=loop_indexes)
    text: dict[str, bool] = {}
    for n in ast.walk(func):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            v = n.value
            is_text = (
                (isinstance(v, ast.Constant) and isinstance(v.value, str))
                or isinstance(v, ast.JoinedStr)
                or _is_field_read(v, scope=reads)
            )
            name = n.targets[0].id
            text[name] = text.get(name, True) and is_text
    # Every binding of every kind, not only plain-name stores: ``import json as v`` or ``def v()``
    # rebinds ``v`` as surely as an assignment does.
    stores = Counter(_bound_names(func))
    assigns = Counter(
        n.targets[0].id
        for n in ast.walk(func)
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
    )
    return {name for name, ok in text.items() if ok and stores[name] == assigns[name]}


def _is_one_based_range(node: ast.expr) -> bool:
    """Whether ``node`` is ``range(k, n)`` or ``range(k, n, step)`` with int literals ``k >= 1`` and
    ``step >= 1``, so every index it yields is 1 or more."""

    def at_least_one(n: ast.expr) -> bool:
        return isinstance(n, ast.Constant) and type(n.value) is int and n.value >= 1

    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "range"
        and not node.keywords
        and not any(isinstance(a, ast.Starred) for a in node.args)
        and len(node.args) in (2, 3)
        and at_least_one(node.args[0])
        and (len(node.args) == 2 or at_least_one(node.args[2]))
    )


def _literal_kind(node: ast.expr, *, frozenset_ok: bool) -> str | None:
    """``"number"``, ``"text"`` (a ``str``), ``"code_set"`` or ``"other"`` for a literal of an
    immutable type, else None.

    Admitted, as ADR 0076 G.7 words the ceiling: a ``str``, ``int``, ``float``, ``bool`` or ``None``
    constant, a sign on a number, a tuple of those scalars, ``frozenset(...)`` over a set, tuple or
    list of those scalars while ``frozenset`` is the builtin, and ``code_set("<literal>")``. So
    ``frozenset()`` with no argument, a nested tuple and a tuple holding a ``frozenset`` are refused.
    Bytes are left out (Manager decision 2026-10-07)."""
    if isinstance(node, ast.Constant):
        if type(node.value) in (int, float):
            return "number"
        if isinstance(node.value, str):
            return "text"
        return "other" if isinstance(node.value, _INERT_CONSTANT_TYPES) else None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub | ast.UAdd):
        operand = node.operand
        is_number = isinstance(operand, ast.Constant) and type(operand.value) in (int, float)
        return "number" if is_number else None
    if isinstance(node, ast.Tuple):
        return "other" if all(_is_scalar_literal(e) for e in node.elts) else None
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.keywords):
        return None
    if node.func.id == "code_set":
        arg = node.args[0] if len(node.args) == 1 else None
        is_code_set = isinstance(arg, ast.Constant) and isinstance(arg.value, str)
        return "code_set" if is_code_set else None
    if node.func.id != "frozenset" or not frozenset_ok or len(node.args) != 1:
        return None
    arg = node.args[0]
    elts_ok = isinstance(arg, ast.Set | ast.Tuple | ast.List) and all(
        _is_scalar_literal(e) for e in arg.elts
    )
    return "other" if elts_ok else None


def _is_scalar_literal(node: ast.expr) -> bool:
    """A ``str``, number, ``bool`` or ``None`` constant, or a sign on a number."""
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub | ast.UAdd):
        node = node.operand
        return isinstance(node, ast.Constant) and type(node.value) in (int, float)
    return isinstance(node, ast.Constant) and isinstance(node.value, _INERT_CONSTANT_TYPES)


def _imported_from_messagefoundry(tree: ast.Module, name: str) -> bool:
    """Whether a top-level ``from messagefoundry import <name>`` binds ``name`` unaliased. A
    ``code_set`` capture counts only then (Manager decision 2026-10-07): a local ``def code_set`` or a
    helper module's ``code_set`` is not the vocabulary's."""
    return any(
        isinstance(node, ast.ImportFrom)
        and not node.level
        and node.module == "messagefoundry"
        and any(al.name == name and al.asname in (None, name) for al in node.names)
        for node in tree.body
    )


#: Modules and names through which code can reach a builtin such as ``globals`` under another name.
_BUILTINS_ROUTES = frozenset({"builtins", "__builtins__", "importlib"})


def _reaches_globals(n: ast.AST, safe_getattr: set[int]) -> bool:
    """Whether ``n`` is one of the routes this check knows by which a module could rebind its own
    globals where the inert check cannot see.

    It catches at least these shapes:

    * a bare name in :data:`_GLOBALS_WRITERS` (``globals``, ``locals``, ``exec`` and the like) or in
      :data:`_BUILTINS_ROUTES` (``builtins``, ``__builtins__``, ``importlib``);
    * an attribute named in :data:`_GLOBALS_ATTRS` (``h.__globals__``, ``sys.modules``, a frame's
      ``f_globals``, ``operator.attrgetter``);
    * ``import builtins`` or ``importlib`` under any alias, and an absolute ``from X import <name>``
      where ``X`` is one of those modules or ``<name>`` is in any of the three sets
      (``from sys import modules``, ``from inspect import builtins as b``);
    * a ``getattr`` name used any way but a direct call whose attribute name is a non-dunder string
      literal outside those sets (``safe_getattr`` holds the ``id`` of each such safe call).

    It is a deny list and does NOT catch every route. Known to pass, at least:
    ``inspect.builtins.globals()`` and any other attribute named ``builtins`` or ``importlib``,
    a ``match`` class pattern capturing ``__globals__``, ``pkgutil.resolve_name`` and other
    resolver strings, ``inspect.getmodule``, ``gc.get_referrers``, a self-import, a re-export under
    another name, and a relative import. Each needs hand-written code that deliberately hides a
    module global; that is outside this guard's scope, which is analyst edits through the lens and
    accidental flows (Manager decision 2026-10-07, on PR 2155)."""
    if isinstance(n, ast.Name):
        if n.id == "getattr":
            return id(n) not in safe_getattr
        return n.id in _GLOBALS_WRITERS or n.id in _BUILTINS_ROUTES
    if isinstance(n, ast.Attribute):
        return n.attr in _GLOBALS_ATTRS
    if isinstance(n, ast.Import):
        return any(al.name.split(".")[0] in _BUILTINS_ROUTES for al in n.names)
    if isinstance(n, ast.ImportFrom):
        if n.level:
            return False
        # ``from sys import modules`` or ``from inspect import builtins`` binds a plain name that
        # the attribute check never sees (review of b0beb2f930, findings 2 and 3; Lander review of
        # 21159e57d6).
        imported = {al.name for al in n.names}
        return (n.module or "").split(".")[0] in _BUILTINS_ROUTES or bool(
            imported & _GLOBALS_ROUTE_NAMES
        )
    return False


#: Every name :func:`_reaches_globals` treats as a route when it is imported or fetched by name.
_GLOBALS_ROUTE_NAMES = _GLOBALS_ATTRS | _GLOBALS_WRITERS | _BUILTINS_ROUTES


def _safe_getattr_names(tree: ast.Module) -> set[int]:
    """The ``id`` of each ``getattr`` name that is called directly with a string literal attribute
    name that is not a dunder and not in :data:`_GLOBALS_ROUTE_NAMES`, so
    ``getattr(inspect, "builtins")`` is not safe (:func:`_reaches_globals`)."""
    out: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr":
            name = n.args[1] if len(n.args) >= 2 else None
            if (
                isinstance(name, ast.Constant)
                and isinstance(name.value, str)
                and not _is_dunder(name.value)
                and name.value not in _GLOBALS_ROUTE_NAMES
            ):
                out.add(id(n.func))
    return out


def _root_name(node: ast.expr) -> str | None:
    """The name at the root of an attribute or subscript chain: ``BOX`` for ``BOX["a"].b``."""
    while isinstance(node, ast.Attribute | ast.Subscript):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _inert_module_literals(tree: ast.Module) -> dict[str, str]:
    """Every module-level name that cannot carry message content, mapped to its kind: ``"number"``,
    ``"text"`` (a ``str``), ``"code_set"`` (when any binding is a ``code_set`` capture) or
    ``"other"``.

    Manager decision 2026-10-07 (Lander review of PR 2155, finding 7; PR 2154 F6). A name qualifies
    only when it has exactly ONE binding at module scope, ``NAME = <literal>`` of an immutable type
    (:func:`_literal_kind`), and nothing in the module mutates it: no attribute call on it, no
    attribute or subscript store or delete through it, no augmented assignment. This function does
    not look at ``global`` declarations: a function that rebinds the name through ``global`` is
    caught by its caller, :func:`_message_scope`, which leaves every ``global``-declared name out
    of each name set it admits, loop indexes included. So ``SEEN = []``
    never qualifies: ``SEEN.append(msg.field("PID-3"))`` fills it from the message. A star import,
    or any route :func:`_reaches_globals` knows, leaves no name inert. That check is a deny list:
    hand-written code that deliberately rebinds a global by a route it does not know is outside its
    scope (Manager decision 2026-10-07, on PR 2155)."""
    values: dict[str, list[ast.expr | None]] = {}
    binds: dict[str, int] = {}
    pending: list[ast.AST] = list(tree.body)
    while pending:
        node = pending.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            binds[node.name] = binds.get(node.name, 0) + 1
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            if isinstance(node.targets[0], ast.Name):
                values.setdefault(node.targets[0].id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            values.setdefault(node.target.id, []).append(node.value)
        names: list[str] = []
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            names.append(node.id)
        elif isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar) and node.name:
            names.append(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.append(node.rest)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            names.extend((al.asname or al.name).split(".")[0] for al in node.names)
        for name in names:
            binds[name] = binds.get(name, 0) + 1
        pending.extend(ast.iter_child_nodes(node))
    mutated: set[str] = set()
    safe_getattr = _safe_getattr_names(tree)
    for n in ast.walk(tree):
        if _reaches_globals(n, safe_getattr):
            return {}
        if isinstance(n, ast.ImportFrom) and any(al.name == "*" for al in n.names):
            return {}
        root: str | None = None
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            root = _root_name(n.func.value)
        elif isinstance(n, ast.Attribute | ast.Subscript) and isinstance(
            n.ctx, ast.Store | ast.Del
        ):
            root = _root_name(n.value)
        elif isinstance(n, ast.AugAssign):
            root = _root_name(n.target)
        if root is not None:
            mutated.add(root)
    frozenset_ok = "frozenset" not in binds
    code_set_ok = _imported_from_messagefoundry(tree, "code_set") and binds.get("code_set") == 1
    out: dict[str, str] = {}
    for name, found in values.items():
        # Exactly one binding (Manager decision 2026-10-07): a second one, even to a literal, is
        # refused rather than reasoned about.
        if name in mutated or name == "msg" or _is_dunder(name) or len(found) != 1:
            continue
        if binds.get(name) != 1:
            continue
        kinds = [None if v is None else _literal_kind(v, frozenset_ok=frozenset_ok) for v in found]
        if all(kinds):
            if "code_set" in kinds:
                if code_set_ok:
                    out[name] = "code_set"
            else:
                same = set(kinds)
                out[name] = (
                    "number" if same == {"number"} else "text" if same == {"text"} else "other"
                )
    return out


def _is_reserved_binding(name: str) -> bool:
    """Whether binding ``name`` would break the handler: ``msg``, a keyword, a dunder, or a builtin
    (``range = ...`` makes ``range`` local for the whole body, so a For-Each loop above it raises
    UnboundLocalError on every message)."""
    return name == "msg" or keyword.iskeyword(name) or _is_dunder(name) or name in _BUILTIN_NAMES


#: ``dir(builtins)`` plus the names the ``site`` module adds, which ``python -S`` leaves out, so the
#: set does not depend on how the engine was started.
_BUILTIN_NAMES = frozenset(dir(builtins)) | {
    "copyright",
    "credits",
    "exit",
    "help",
    "license",
    "quit",
}


def _refuse_active_expr(
    rendered: str,
    pname: str,
    *,
    policy: str = _POLICY_LITERAL,
    scope: _Scope,
) -> None:
    """Refuse an ``{"expr": ...}`` value the ``policy`` does not admit (Theia review finding R1).

    ``rendered`` has already passed :func:`_validated_expr`, so it parses as one expression."""
    node = ast.parse(rendered, mode="eval").body
    if _expr_depth(node) > _MAX_INERT_DEPTH:
        raise LensRewriteError(
            f"parameter {pname!r}: the expression is nested too deeply for a Steps edit; "
            "edit it as text"
        )
    if policy in (_POLICY_DB_PARAMS, _POLICY_FHIR_PARAMS):
        ok = _is_inert_params_dict(node, scope=scope, fhir=policy == _POLICY_FHIR_PARAMS)
        allowed = (
            "None, or a dict with literal keys whose values are literals, names or message reads"
        )
    else:
        reads_ok = policy == _POLICY_VALUE
        ok = _is_inert_value(node, reads_ok=reads_ok, scope=scope)
        allowed = (
            "a literal, a name, a message read, simple arithmetic, or a list or dict of those"
            if reads_ok
            else "a literal, a module-level name or loop index, simple arithmetic, or a list or "
            "dict of those"
        )
    if not ok:
        raise LensRewriteError(
            f"parameter {pname!r}: the expression is not a value a Steps edit may write here - only "
            f"{allowed} is accepted (a call, an attribute access, other operators, or message "
            "content where it must not go is refused); edit it as text"
        )


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
    real indent. Shared by :func:`_apply_insert_row` and :func:`_apply_paste_block` so the two derive the
    landing indent identically.

    A **fully blank** anchor row used to fall back to ``line_start`` — i.e. to indent ``""`` — which
    dedented the insert out of its suite and refused with "unexpected indent". ADR 0076 §A.4 records that
    as already broken before ``note`` rows existed (its own docstring called the case "defensive", which
    was already untrue); splitting notes away from adjacent blanks makes blank-only rows common, so it is
    fixed here. The fallback now scans OUTWARD from the row for the nearest non-blank line — backwards
    first, since the preceding statement is what establishes the suite — and only an entirely blank file
    yields ``""``."""
    scan = (
        range(line_end, line_start - 1, -1)
        if position == "after"
        else range(line_start, line_end + 1)
    )

    def _text(ln: int) -> str | None:
        """The physical line ``ln`` when it has content, else None (so ``next`` skips blanks)."""
        return lines[ln - 1] if 0 <= ln - 1 < len(lines) and lines[ln - 1].strip() else None

    within = next((t for ln in scan if (t := _text(ln)) is not None), None)
    if within is not None:
        return _leading_ws(within)
    outward = next(
        (t for ln in range(line_start - 1, 0, -1) if (t := _text(ln)) is not None),
        next((t for ln in range(line_end + 1, len(lines) + 1) if (t := _text(ln)) is not None), ""),
    )
    return _leading_ws(outward)


def _module_bound_names(tree: ast.Module, *, runtime_only: bool = False) -> tuple[set[str], bool]:
    """Names bound at MODULE scope + whether a wildcard import exists.

    Any depth of ``if``/``try``/``with``/``for``/``match`` nesting counts (a ``try``-guarded import binds
    its name), but not the body of a ``def``, ``class`` or ``lambda``: their own names count, their
    locals do not. A ``from m import *`` binds an unknown set, so the second element is ``True``; for
    :func:`_name_in_scope` that means any name may be in scope (permissive, never a false refusal),
    and for :func:`_message_scope` that ``range`` may not be the builtin.

    ``runtime_only`` leaves out the body of an ``if TYPE_CHECKING:`` block, which never runs: a name
    imported only there is not in scope when a handler runs, so an insert that calls it must still
    inject its import (Lander review of PR 2155, finding 4). The other callers keep it, because for
    them counting a name is the stricter answer."""
    names: set[str] = set()
    star = False
    pending: list[ast.AST] = list(tree.body)
    while pending:
        node = pending.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if runtime_only and isinstance(node, ast.If) and _is_type_checking_test(node.test):
            pending.extend(node.orelse)
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.add(node.rest)
        elif isinstance(node, ast.Import):
            names.update(al.asname or al.name.split(".")[0] for al in node.names)
        elif isinstance(node, ast.ImportFrom):
            for al in node.names:
                if al.name == "*":
                    star = True
                else:
                    names.add(al.asname or al.name)
        pending.extend(ast.iter_child_nodes(node))
    return names, star


def _is_type_checking_test(test: ast.expr) -> bool:
    """Whether ``test`` is ``TYPE_CHECKING`` or ``<module>.TYPE_CHECKING``, which is False at run time."""
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _name_in_scope(tree: ast.Module, name: str) -> bool:
    """Whether a BARE ``name(...)`` call would resolve at module scope (an import, def, or a wildcard).

    Note it is deliberately the *bare* name: the lens inserts ``set_field(...)``, never ``mf.set_field``,
    so a module that only ``import messagefoundry`` (aliased or not) does NOT put ``set_field`` in scope
    and the insert is refused — inserting a bare undefined name would be an F821 ``ruff check`` failure."""
    names, star = _module_bound_names(tree, runtime_only=True)
    return star or name in names


def _last_import_line(tree: ast.Module) -> int:
    """1-based line number of the last top-level ``import``/``from`` (0 if the module has none).

    Used as the 0-based ``lines`` index at which to inject a new import AFTER the existing block (ADR
    0106 §6 import injection). A ``@handler`` module always imports at least ``handler``, so 0
    (top-of-file) is a rare fallback."""
    last = 0
    for node in tree.body:
        if isinstance(node, ast.Import | ast.ImportFrom):
            last = node.end_lineno or node.lineno
    return last


def _leading_import_end(tree: ast.Module) -> int:
    """1-based end line of the LEADING contiguous import block (after an optional module docstring), or
    the docstring's end, or 0.

    Unlike :func:`_last_import_line` (the last import ANYWHERE), this is always ABOVE every handler body,
    so it is the index-stable, canonical point to inject a module-level code-set binding — even when a
    stray top-level import trails the handlers (where ``_last_import_line`` would point below the anchor
    and, after the row splice, land the binding mid-file or inside a later import's parentheses)."""
    last = 0
    body = tree.body
    start = 0
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        last = (
            body[0].end_lineno or body[0].lineno
        )  # inject after a leading module docstring at least
        start = 1
    for node in body[start:]:
        if isinstance(node, ast.Import | ast.ImportFrom):
            last = node.end_lineno or node.lineno
        else:
            break  # first non-import ends the leading block
    return last


def _function_binds(func: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> bool:
    """Whether ``name`` is a parameter or an assignment target anywhere in ``func``.

    Such a name is a function LOCAL for the whole body (Python scoping), so a module-level binding of the
    same name would be shadowed — the reason :func:`_apply_insert_code_lookup` refuses it."""
    a = func.args
    for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg):
        if arg is not None and arg.arg == name:
            return True
    return any(
        isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id == name
        for n in ast.walk(func)
    )


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
    scope = _message_scope(handler_node, module_tree)
    needs_import = False
    if action in _NATIVE_INSERT_ACTIONS:
        # ADR 0089: the three actions the Phase A recognizer reads back are inserted in their NATIVE
        # Message-API form (``msg.set`` / ``msg.delete_segments``). That references only ``msg`` — no
        # vocabulary import — so it matches a native estate AND skips the import-scope check below
        # (there is no bare wrapper name to resolve). The inserted line round-trips: re-parsing it
        # recognizes the SAME editable action row.
        rendered = _render_native_insert_call(action, params, edit.get("assign_to"), scope=scope)
    else:
        # Render first — an unknown vocabulary name / missing param is refused with that (more specific)
        # message before the import-scope check below.
        rendered = _render_insert_call(action, params, edit.get("assign_to"), scope=scope)
        # ADR 0106 §6 (H): a wrapper call the module does not import would be a BARE ``trim_field(...)``
        # F821 undefined name. Rather than refuse, INJECT ``from messagefoundry import <action>`` among the
        # module's imports (below). Idempotent — only reached when the name is not already in scope — and a
        # §6-sanctioned exception to the row-scoped byte-splice (imports sit outside the target row's range);
        # the caller's re-parse + ruff gates still bracket the whole result. (``_render_insert_call`` above
        # already refused an unknown name / missing param with a more specific message.)
        needs_import = not _name_in_scope(module_tree, action)
        assign_to = edit.get("assign_to")
        handler_names = set(_bound_names(handler_node)) | {
            n.id for n in ast.walk(handler_node) if isinstance(n, ast.Name)
        }
        handler_names |= {
            name
            for n in ast.walk(handler_node)
            if isinstance(n, ast.Global | ast.Nonlocal)
            for name in n.names
        }
        # The inserted line's own reads: the callee and the import it may inject (``db_lookup =
        # db_lookup(...)`` raises UnboundLocalError), and any name in its arguments (``FhirToken``).
        handler_names |= {
            n.id
            for n in ast.walk(ast.parse(rendered))
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
        } | {action}
        if isinstance(assign_to, str) and (
            assign_to in handler_names or assign_to in _module_bound_names(module_tree)[0]
        ):
            # A name the handler binds or reads anywhere would change under it: ``sends``, a loop
            # index, an earlier result, or a module or star-imported name (``Send``, a ``code_set``
            # capture), which would turn LOCAL for the whole body so an earlier read raises
            # UnboundLocalError. A module-level binding anywhere (a ``try``-guarded import included)
            # is refused too (Theia review finding R1). So a second lookup into the same variable is
            # refused; it needs a new name.
            raise LensRewriteError(
                f"insert_row 'assign_to' {assign_to!r} is already bound in this handler or module - "
                "choose a new variable name"
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
    if needs_import:
        # Inject the vocabulary import after the module's existing import block. Placed above the body, so
        # the just-inserted row stays between its intended neighbors; the whole result is re-parse + ruff
        # gated by the caller (§6-sanctioned exception to the row-scoped byte-splice).
        lines.insert(_last_import_line(module_tree), f"from messagefoundry import {action}" + term)
    # A FHIR search value object the params use needs its import too, or the line raises NameError.
    # Only the names the line READS: an ``assign_to`` named like one is a target, not a use
    # (Lander review of PR 2155, finding 10).
    used = {
        n.id
        for n in ast.walk(ast.parse(rendered))
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    }
    for name in sorted(_FHIR_VALUE_OBJECTS & used):
        if not _name_in_scope(module_tree, name):
            lines.insert(
                _last_import_line(module_tree), f"from messagefoundry import {name}" + term
            )
    return "".join(lines)


# The accumulator collector variable name (ADR 0104 fan-out). Hard-coded (owner fork): it is the estate
# convention (``test_graph_static.py`` / ``config/graph.py``) and the runtime never reads the name, so a
# fixed name keeps recognition tight and codegen deterministic.
_ACCUMULATOR = "sends"


def _accumulator_footer(
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.Return | None:
    """The top-level ``return sends`` footer of an accumulator handler, or None."""
    for s in handler_node.body:
        if (
            isinstance(s, ast.Return)
            and isinstance(s.value, ast.Name)
            and s.value.id == _ACCUMULATOR
        ):
            return s
    return None


def _accumulator_init(
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.Assign | None:
    """The top-level ``sends = []`` init of an accumulator handler, or None."""
    for s in handler_node.body:
        if _is_collector_init(s, {_ACCUMULATOR}):
            assert isinstance(s, ast.Assign)  # narrowed by _is_collector_init
            return s
    return None


def _is_send_return(s: ast.Return) -> bool:
    """Whether ``s`` is a send-row return the fan-out can convert up: ``return Send(...)``,
    ``return [Send, ...]``, or the ``return []`` / ``return ()`` filter.

    Excludes ``return sends`` (a bare name), ``return None``, and ``return <other>`` — none of which is a
    send construct, so a handler carrying one is refused rather than mis-extended into a fan-out."""
    v = s.value
    if v is None:
        return False
    if isinstance(v, ast.List | ast.Tuple) and not v.elts:
        return True  # `return []` / `return ()` — the filter, converts to an accumulator with just the new send
    if isinstance(v, ast.Tuple):
        # A NON-empty tuple return DELIVERS at runtime (``_partition`` accepts any non-``str`` iterable,
        # BACKLOG #341), so converting it to a list-building accumulator would now be delivery-neutral
        # rather than a silent 0→N flip. It is refused anyway, on CONSERVATIVE SCOPE: the palette never
        # authors this form, and enabling the rewrite carries its own byte-stability obligations
        # (ADR 0108 §6/§7) that belong to a Steps-view item, not here. Leave it a code row / edit-as-text.
        return False
    return _send_outbounds(v) is not None


def _render_append_line(indent: str, dest: str, term: str) -> str:
    """A ``sends.append(Send("dest", msg))`` physical line, refused over the ruff column limit."""
    physical = f"{indent}{_ACCUMULATOR}.append(Send({_str_lit(dest)}, msg))"
    if len(physical) > _MAX_LINE_LENGTH:
        raise LensRewriteError(
            f"the appended send would be {len(physical)} columns — over the {_MAX_LINE_LENGTH}-column "
            "limit (ruff would wrap it); add it as text"
        )
    return physical + term


def _maybe_inject_send(lines: list[str], module_tree: ast.Module, term: str) -> None:
    """Inject ``from messagefoundry import Send`` after the LEADING import block iff ``Send`` is not in
    scope.

    Uses :func:`_leading_import_end` (the end of the leading contiguous import block, above every handler
    body) — NOT ``_last_import_line`` (the last import ANYWHERE): a stray top-level import BELOW the edited
    handler would make ``_last_import_line`` point below the body splices, and injecting there (after the
    splices grew ``lines``) would land the import mid-file (E402 / not ruff-clean). The leading-block index
    is unaffected by the body splices, so injecting LAST still lands correctly (ADR 0106 §6 H — the same
    index-stable anchor the code-set capture injection uses)."""
    if not _name_in_scope(module_tree, "Send"):
        lines.insert(_leading_import_end(module_tree), f"from messagefoundry import Send{term}")


def _apply_add_send(
    src: str,
    module_tree: ast.Module,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    edit: dict[str, Any],
    line_start: int,
    line_end: int,
) -> str:
    """Add a ``sends.append(Send(dest, msg))`` accumulator send (ADR 0104 fan-out) — ``insert_send`` and
    ``add_destination`` both route here.

    Four handler states, dispatched (never authoring a ``Send`` inside a ``return``):
    - **accumulator** (a ``sends = []`` init + ``return sends`` footer present) → insert one append at the
      anchor position, clamped to sit after the init and before the footer (never dead-code / pre-init);
    - **one returned send** (``return Send(...)`` / ``return [Send, ...]``) → convert it UP to the
      accumulator idiom in place, preserving each existing Send verbatim, then add the new destination;
    - **>1 returned send** (a Send from more than one branch) → refuse (converting would change control
      flow); edit as text;
    - **fresh** (no send construct) → lay down ``sends = []`` (body top), one append (at the anchor), and
      ``return sends`` (body end); refuse if ``sends`` is already an unrelated local.

    Every untouched line is byte-preserved (gate 2); the caller's ``_assert_reparses`` + the per-line
    ≤``_MAX_LINE_LENGTH`` guards keep the result valid and ``ruff format``-clean (gate 3)."""
    dest = edit.get("destination")
    if not isinstance(dest, str) or not dest:
        raise LensRewriteError("insert_send / add_destination requires a non-empty 'destination'")
    position = edit.get("position", "after")
    if position not in ("before", "after"):
        raise LensRewriteError(
            "insert_send / add_destination 'position' must be 'before' or 'after'"
        )

    # Take the accumulator path ONLY when ``sends`` is a clean, DELIVERING accumulator (single ``[]``
    # init, returned, bound nowhere else) — so an append is never spliced into a rebound/aliased ``sends``
    # that is not a list at runtime (an AttributeError the Steps view would never surface).
    footer = _accumulator_footer(handler_node)
    init = _accumulator_init(handler_node)
    if (
        footer is not None
        and init is not None
        and _ACCUMULATOR in _delivering_accumulators(handler_node)
    ):
        return _add_to_accumulator(
            src, module_tree, handler_node, dest, init, footer, line_start, line_end, position
        )

    # A non-accumulator handler: convert its single send/filter return up to the accumulator idiom. This
    # is the ONLY safe way to add a footer without stranding an existing terminal ``return`` (a fresh
    # ``return sends`` appended AFTER an existing ``return []`` would be unreachable — and the appends
    # would never deliver). Require exactly ONE return in the handler's own scope, that it is a send/filter
    # return, AND that it is a TOP-LEVEL terminal statement — converting a NESTED guard/early-exit return
    # (e.g. ``if bad: return []``) in place would move the fan-out into that branch and leave the main path
    # returnless. Anything else (``return None`` / ``return msg`` / a nested or multi-branch return) is
    # refused rather than mis-extended.
    all_returns = [n for n in _own_scope_nodes(handler_node) if isinstance(n, ast.Return)]
    send_returns = [s for s in all_returns if _is_send_return(s)]
    if (
        len(all_returns) == 1
        and len(send_returns) == 1
        and send_returns[0]
        in handler_node.body  # a top-level terminal statement, not a nested guard
    ):
        return _convert_return_to_accumulator(src, module_tree, dest, send_returns[0])
    if all_returns:
        raise LensRewriteError(
            "the handler's return can't be extended into a fan-out — it needs a single top-level "
            "`return Send(...)`, `return [...]`, or `return []` (or no return at all); edit it as text"
        )
    # No return at all: lay a fresh accumulator with its own footer (nothing to strand).
    if _function_binds(handler_node, _ACCUMULATOR):
        raise LensRewriteError(
            f"the handler already binds a local {_ACCUMULATOR!r} that is not a fan-out accumulator — "
            "rename it or edit as text"
        )
    return _lay_fresh_accumulator(
        src, module_tree, handler_node, dest, line_start, line_end, position
    )


def _add_to_accumulator(
    src: str,
    module_tree: ast.Module,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    dest: str,
    init: ast.Assign,
    footer: ast.Return,
    line_start: int,
    line_end: int,
    position: str,
) -> str:
    """Insert one ``sends.append(Send(dest, msg))`` into an existing accumulator, before the footer.

    The append lands at the accumulator's OWN (top-level) suite indent — never the anchor's. The anchor
    position is honored only for a TOP-LEVEL anchor (a direct body statement); a nested anchor (inside an
    if/for) would otherwise put the append at the wrong indent or inside a block (per-iteration/conditional
    delivery), so it lands just before the footer instead. The index is always clamped after the init line
    and before the footer (never dead code / pre-init)."""
    lines = _physical_lines_keepends(src)
    term = _dominant_terminator(src)
    indent = _leading_ws(lines[init.lineno - 1])  # the accumulator's own (top-level) suite indent
    append_line = _render_append_line(indent, dest, term)
    top_level = any(
        s.lineno == line_start and (s.end_lineno or s.lineno) == line_end for s in handler_node.body
    )
    idx = (line_end if position == "after" else line_start - 1) if top_level else footer.lineno - 1
    idx = max(init.lineno, min(idx, footer.lineno - 1))
    lines.insert(idx, append_line)
    _maybe_inject_send(lines, module_tree, term)
    return "".join(lines)


def _convert_return_to_accumulator(
    src: str,
    module_tree: ast.Module,
    dest: str,
    ret: ast.Return,
) -> str:
    """Convert a ``return Send(...)`` / ``return [Send, ...]`` up to the accumulator idiom, add ``dest``.

    Each existing Send's verbatim source is preserved (destination string, ``occurrence=`` kwarg, the
    ``msg`` arg byte-exact). Refuses a list carrying a non-Send element (e.g. ``SetState`` — not a pure
    fan-out) or a multi-line Send (its append can't stay a single clean line); edit those as text."""
    value = ret.value
    if isinstance(value, ast.Call):
        sends = [value]
    elif isinstance(value, ast.List | ast.Tuple):
        sends = []
        for elt in value.elts:
            if not (isinstance(elt, ast.Call) and _callee_name(elt.func) == "Send"):
                raise LensRewriteError(
                    "the returned list has a non-Send element (e.g. SetState) — converting to an "
                    "accumulator fan-out would drop it; edit it as text"
                )
            sends.append(elt)
    else:  # pragma: no cover — caller only reaches here for a recognized send return
        raise LensRewriteError("internal: return is not a Send construct")
    for s in sends:
        if (s.end_lineno or s.lineno) != s.lineno:
            raise LensRewriteError(
                "a Send in the return spans multiple physical lines — converting it to an append is out "
                "of scope; edit it as text"
            )

    lines = _physical_lines_keepends(src)
    term = _dominant_terminator(src)
    ret_ls = ret.lineno
    ret_le = ret.end_lineno or ret.lineno
    indent = _leading_ws(lines[ret_ls - 1])
    block: list[str] = [f"{indent}{_ACCUMULATOR} = []{term}"]
    for s in sends:
        physical = f"{indent}{_ACCUMULATOR}.append({_src(s, src)})"
        if len(physical) > _MAX_LINE_LENGTH:
            raise LensRewriteError(
                f"a converted append would be {len(physical)} columns — over the {_MAX_LINE_LENGTH}-"
                "column limit (ruff would wrap it); edit it as text"
            )
        block.append(physical + term)
    block.append(_render_append_line(indent, dest, term))
    block.append(f"{indent}return {_ACCUMULATOR}{term}")
    lines[ret_ls - 1 : ret_le] = block
    _maybe_inject_send(lines, module_tree, term)
    return "".join(lines)


def _lay_fresh_accumulator(
    src: str,
    module_tree: ast.Module,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    dest: str,
    line_start: int,
    line_end: int,
    position: str,
) -> str:
    """Lay down a fresh accumulator: ``sends = []`` at body top, one append at the anchor, ``return sends``
    at body end. The three inserts apply in DESCENDING index so earlier indices stay valid."""
    lines = _physical_lines_keepends(src)
    term = _dominant_terminator(src)
    body_indent = _leading_ws(lines[handler_node.body[0].lineno - 1])
    # The append lands at the handler's top-level body indent (like the init/footer). The anchor position
    # is honored only for a TOP-LEVEL anchor; a nested anchor (inside an if/for) would put a top-level-
    # indented line inside a block (invalid) or make the send per-iteration, so the append lands at the
    # body end (just before the footer) instead — one delivery per message.
    append_line = _render_append_line(body_indent, dest, term)
    init_line = f"{body_indent}{_ACCUMULATOR} = []{term}"
    footer_line = f"{body_indent}return {_ACCUMULATOR}{term}"

    first_body = handler_node.body[0].lineno
    last = handler_node.body[-1]
    body_end = last.end_lineno or last.lineno
    top_level = any(
        s.lineno == line_start and (s.end_lineno or s.lineno) == line_end for s in handler_node.body
    )
    idx_init = first_body - 1
    idx_append = (line_end if position == "after" else line_start - 1) if top_level else body_end
    idx_footer = body_end
    # Descending index (footer, then append, then init) — a stable sort keeps footer before append when
    # both land on the last-statement index, so the final order is …last-stmt, append, return sends.
    inserts = sorted(
        [(idx_footer, footer_line), (idx_append, append_line), (idx_init, init_line)],
        key=lambda t: t[0],
        reverse=True,
    )
    for idx, line in inserts:
        if idx >= len(lines):
            if lines and _line_terminator(lines[-1]) == "":
                lines[-1] = lines[-1] + term  # terminate a no-trailing-newline last line first
            lines.append(line)
        else:
            lines.insert(idx, line)
    _maybe_inject_send(lines, module_tree, term)
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
        except (SyntaxError, *_PARSER_REFUSALS):
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


def _str_lit(value: object) -> str:
    """A Python string literal in ruff's preferred quote style — double quotes, but SINGLE quotes when the
    value contains a ``"`` and no ``'`` (ruff drops to single quotes to avoid escaping the double quote).

    Matching ruff's escape-avoidance keeps a rendered literal ``ruff format --check``-clean (gate 3): a
    naive ``"a\\"b"`` would be reflowed by ruff to ``'a"b'``. (A value with both quote kinds stays double-
    quoted-with-escape, which IS ruff-canonical.)"""
    s = str(value)
    if '"' in s and "'" not in s:
        return "'" + s.replace("\\", "\\\\") + "'"
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _validated_raw_test(test: str, *, is_async: bool = False) -> str:
    """Validate the raw ``test`` escape hatch of an ``if``/``elif`` insert: ONE condition on ONE line.

    Theia review finding R1, the part ADR 0106 already implies. The escape hatch is specified as an
    expression (``test:{expr}``), but it was spliced unchecked into ``if <test>:``, so a value carrying
    line breaks could close the header and add statements of its own -- for ``elif``, a whole new
    clause body. The re-parse gate cannot see that, because the result is valid Python. So the value
    must be one line, and ``if <test>:`` must parse as exactly one ``if`` header -- the same position it
    is spliced into, so an unparenthesized walrus (``x := f()``) is accepted as it is in Python.

    A ``yield`` turns the whole handler into a generator, and an ``await`` outside an ``async def``
    handler fails at import; both change the function rather than the condition. A ``yield`` inside a
    ``lambda`` belongs to the lambda and is left alone.

    This does NOT bound what the expression does: the escape hatch still takes any expression, which
    is what ADR 0106 licenses it for (a regex condition). The ``typed_only`` mode of
    :func:`rewrite_source` refuses it outright."""
    if "\n" in test or "\r" in test:
        raise LensRewriteError(
            "the raw 'test' must be a single line - a line break would add statements to the handler"
        )
    stripped = test.strip()
    try:
        tree = ast.parse(f"if {stripped}:\n    pass\n")
    except SyntaxError as exc:
        raise LensRewriteError(f"the raw 'test' is not a single condition ({exc.msg})") from exc
    except _PARSER_REFUSALS as exc:
        raise LensRewriteError(
            f"the raw 'test' is not a single condition ({_refusal_reason(exc)})"
        ) from exc
    header = tree.body[0] if len(tree.body) == 1 else None
    if not (
        isinstance(header, ast.If)
        and len(header.body) == 1
        and isinstance(header.body[0], ast.Pass)
        and not header.orelse
    ):
        raise LensRewriteError("the raw 'test' is not a single condition")
    pending: list[ast.AST] = [header.test]
    while pending:
        node = pending.pop()
        if isinstance(node, ast.Lambda):
            # The body belongs to the lambda; its defaults run in the handler (`x=(yield)`).
            pending.extend(node.args.defaults)
            pending.extend(d for d in node.args.kw_defaults if d is not None)
            continue
        if isinstance(node, ast.Yield | ast.YieldFrom) or (
            isinstance(node, ast.Await) and not is_async
        ):
            raise LensRewriteError(
                "the raw 'test' cannot yield, or await outside an async handler - that would change "
                "the whole handler, not the condition"
            )
        pending.extend(ast.iter_child_nodes(node))
    return stripped


def _render_if_test(edit: dict[str, Any], *, is_async: bool = False) -> str:
    """The bounded test for an ``if`` template — a structured field/operator/value, or a raw ``test`` escape.

    Operators are the closed set {exists, equals, not_equals, contains}; a regex condition belongs in the
    raw ``test`` escape hatch (reads back ``recognized:false``), never a first-class GUI operator — the
    same no-mini-language line ``replace_literal`` holds (ADR 0106 §7)."""
    test = edit.get("test")
    if isinstance(test, str) and test:
        return _validated_raw_test(test, is_async=is_async)
    field = edit.get("field")
    if not isinstance(field, str) or not field:
        raise LensRewriteError("template 'if' requires a 'field' or a raw 'test'")
    read = f"msg.field({_str_lit(field)})"
    op = edit.get("operator", "exists")
    if op == "exists":
        return read
    value = _str_lit(edit.get("value", ""))
    if op == "equals":
        return f"{read} == {value}"
    if op == "not_equals":
        return f"{read} != {value}"
    if op == "contains":
        return f"{value} in ({read} or {_str_lit('')})"
    raise LensRewriteError(
        f"template 'if' operator {op!r} must be exists / equals / not_equals / contains"
    )


def _render_template(edit: dict[str, Any], *, is_async: bool = False) -> str:
    """Render an ADR 0106 structure/flow template to native Python source (LF-joined) for the paste path.

    Control templates seed a ``pass`` body (an empty suite is invalid Python); on readback the recognizer
    splits the header into a control row + a ``pass`` code row, and further steps drop into that body."""
    # Rendered at a 4-space "capture indent" (control bodies at 8): the paste path wraps the block in
    # ``def _f():`` and needs an indented body, then re-indents from this base to the anchor's suite.
    template = edit.get("template")
    if template == "filter":
        return "    return []"
    if template == "send":
        dest = edit.get("destination")
        if not isinstance(dest, str) or not dest:
            raise LensRewriteError("template 'send' requires a 'destination'")
        return f"    return Send({_str_lit(dest)}, msg)"
    if template == "raise":
        exc = edit.get("exc_type", "ValueError")
        if exc not in ("ValueError", "RuntimeError"):
            raise LensRewriteError(
                "template 'raise' exc_type must be 'ValueError' or 'RuntimeError'"
            )
        return f"    raise {exc}({_str_lit(edit.get('message', ''))})"
    if template == "for_each":
        seg = edit.get("segment_id")
        if not isinstance(seg, str) or not seg:
            raise LensRewriteError("template 'for_each' requires a 'segment_id'")
        return f"    for i in range(1, msg.count_segments({_str_lit(seg)}) + 1):\n        pass"
    if template == "if":
        return f"    if {_render_if_test(edit, is_async=is_async)}:\n        pass"
    if template == "route":
        # ADR 0076 Amendment D — the router palette's "Route to handler(s)". An empty list is a
        # deliberate ``return []``: routed nowhere, the store disposition UNROUTED (logged, never dropped).
        handlers = edit.get("handlers")
        if not isinstance(handlers, list) or not all(isinstance(h, str) and h for h in handlers):
            raise LensRewriteError(
                "template 'route' requires 'handlers': a list of non-empty handler-name strings"
            )
        return f"    return [{', '.join(_str_lit(h) for h in handlers)}]"
    raise LensRewriteError(
        f"unknown template {template!r} (expected if / for_each / filter / raise / send / route)"
    )


def _apply_insert_template(
    src: str,
    module_tree: ast.Module,
    line_start: int,
    line_end: int,
    edit: dict[str, Any],
    *,
    is_async: bool = False,
) -> str:
    """Insert an ADR 0106 structure/flow template (If / For Each / Filter / Raise / Send) at the anchor.

    Renders native Python (§5 A) and routes it through the AUDITED paste path
    (:func:`_apply_paste_block` → :func:`_parse_pasted_block` + reindent + splice), so the same
    byte-stability + validity guarantees apply. ``send`` is the one template that references a
    vocabulary name (``Send``); if the module does not already have it in scope its import is injected
    (idempotent), the same §6 H exception the wrapper insert uses. (Else If / Else are a clause-append —
    a separate ADR 0106 insert path.)"""
    block = _render_template(edit, is_async=is_async)
    result = _apply_paste_block(
        src, line_start, line_end, {"block": block, "position": edit.get("position", "after")}
    )
    # The paste path does not inject imports; ``Send`` is the only template symbol that needs one. The
    # imports are unchanged by the body splice, so the original module's last-import line still points
    # at the right insertion point in ``result``.
    if edit.get("template") == "send" and not _name_in_scope(module_tree, "Send"):
        lines = _physical_lines_keepends(result)
        # _leading_import_end (not _last_import_line): a stray top-level import BELOW the edited handler
        # would otherwise place the injected import mid-file after the body splice (E402 / not ruff-clean).
        lines.insert(
            _leading_import_end(module_tree),
            f"from messagefoundry import Send{_dominant_terminator(src)}",
        )
        result = "".join(lines)
    return result


def _clause_chain_headers(top: ast.If) -> list[int]:
    """Header linenos of an ``if`` chain — the ``if`` plus each same-column ``elif`` (excludes ``else``).

    Python models ``if / elif / else`` as nested :class:`ast.If` (each ``elif`` is a single same-column
    ``ast.If`` in the parent's ``orelse``); this walks that chain and returns the header line of every
    ``if``/``elif`` clause, so an Else-If/Else insert anchored on *any* clause resolves to the whole chain."""
    headers = [top.lineno]
    node = top
    while (
        len(node.orelse) == 1
        and isinstance(node.orelse[0], ast.If)
        and node.orelse[0].col_offset == top.col_offset
    ):
        node = node.orelse[0]
        headers.append(node.lineno)
    return headers


def _find_if_chain(root: ast.AST, line_start: int) -> ast.If | None:
    """The TOP-of-chain :class:`ast.If` whose ``if``/``elif`` header is on ``line_start`` (or ``None``).

    Anchoring on a nested ``elif`` returns the outermost ``if`` (so the new clause appends to the same
    chain, not the elif's own). Elif nodes — a parent's single same-column ``orelse`` child — are skipped as
    chain heads, leaving exactly the outermost ``if`` of each chain as a candidate."""
    ifs = [n for n in ast.walk(root) if isinstance(n, ast.If)]
    elifs = {
        id(p.orelse[0])
        for p in ifs
        if len(p.orelse) == 1
        and isinstance(p.orelse[0], ast.If)
        and p.orelse[0].col_offset == p.col_offset
    }
    for node in ifs:
        if id(node) not in elifs and line_start in _clause_chain_headers(node):
            return node
    return None


def _apply_insert_clause(
    src: str,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    line_start: int,
    edit: dict[str, Any],
) -> str:
    """Append an ADR 0106 ``elif``/``else`` clause to the ``if`` chain anchored at ``line_start``.

    A **pure line-insert**: the new clause (header + a seeded ``pass`` body, at the ``if``'s own indent)
    is spliced in — an ``elif`` before an existing ``else:`` (or at the chain's end when there is none),
    an ``else`` only at the end. No existing byte is touched, so every other row round-trips unchanged;
    the caller's re-parse gate (:func:`_assert_reparses`) is the validity backstop. Refuses (zero change)
    when there is no ``if`` at the anchor, or an ``else`` is requested but the chain already has one."""
    clause = edit.get("clause")
    if clause not in ("elif", "else"):
        raise LensRewriteError("insert_clause: 'clause' must be 'elif' or 'else'")
    top = _find_if_chain(handler_node, line_start)
    if top is None:
        raise LensRewriteError(
            f"insert_clause: no `if` clause anchored at line {line_start} "
            "(anchor an else or elif clause on the if or an elif row)"
        )
    # Walk to the deepest clause; a non-``If`` ``orelse`` there is the existing ``else`` block.
    deep = top
    while (
        len(deep.orelse) == 1
        and isinstance(deep.orelse[0], ast.If)
        and deep.orelse[0].col_offset == top.col_offset
    ):
        deep = deep.orelse[0]
    has_else = bool(deep.orelse)
    if clause == "else" and has_else:
        raise LensRewriteError(
            "insert_clause: this `if` already has an `else` clause (refused, no change)"
        )

    lines = _physical_lines_keepends(src)
    term = _dominant_terminator(src)
    indent = " " * top.col_offset
    if clause == "elif":
        header = f"{indent}elif {_render_if_test(edit, is_async=isinstance(handler_node, ast.AsyncFunctionDef))}:{term}"
    else:
        header = f"{indent}else:{term}"
    new_lines = [header, f"{indent}    pass{term}"]

    if has_else:
        # An ``elif`` slots in BEFORE the ``else:`` header (elif cannot follow else).
        deep_body_end = deep.body[-1].end_lineno or deep.lineno
        else_body_first = deep.orelse[0].lineno
        else_header = _find_keyword(lines, deep_body_end + 1, else_body_first - 1, "else")
        if else_header is None:  # inline ``else: y`` — no header line to insert before
            raise LensRewriteError("insert_clause: could not locate the `else:` header (refused)")
        insert_idx = else_header - 1
    else:
        # No ``else`` — append after the chain's last body line (0-based index == the 1-based end line).
        insert_idx = top.end_lineno or deep.end_lineno or deep.lineno
    # If we append right after a final line that lacks an EOL (no trailing newline), terminate it first so
    # the new clause starts on its own line.
    if 0 < insert_idx == len(lines) and not lines[insert_idx - 1].endswith(("\n", "\r")):
        lines[insert_idx - 1] += term
    lines[insert_idx:insert_idx] = new_lines
    return "".join(lines)


def _apply_insert_comment(src: str, line_start: int, line_end: int, edit: dict[str, Any]) -> str:
    """Insert a ``# <text>`` comment line before/after the target row, at the target's indentation.

    ADR 0106 Comment (§5 L). A comment is NOT an ``ast`` statement, so it cannot ride the wrapper
    (:func:`_render_insert_call`) or paste (:func:`_parse_pasted_block`) paths — this is a raw-line
    insert, the same keepends splice as :func:`_apply_insert_row`'s tail. Read-back: a standalone
    comment tiles into a read-only ``code`` row via :func:`_partition_suite` gap-tiling (no recognizer
    change needed). The target is a POSITION only, so it may be any row kind. Refuses a non-string
    ``text``, a text with an embedded newline/CR (it would add lines or inject code), or a rendered
    line over the column limit — so the output stays ``ruff format --check``-clean and re-parses."""
    position = edit.get("position", "after")
    if position not in ("before", "after"):
        raise LensRewriteError("insert_comment 'position' must be 'before' or 'after'")
    text = edit.get("text")
    if not isinstance(text, str):
        raise LensRewriteError("insert_comment requires a string 'text' (the comment body)")
    if "\n" in text or "\r" in text:
        raise LensRewriteError(
            "insert_comment 'text' must be a single line (a newline would add lines / could inject code)"
        )
    # Normalize to a single ``# body`` (strip a caller-supplied leading ``#`` and surrounding space) — the
    # canonical form ``ruff format`` produces; an empty body renders as a bare ``#``.
    body = text.strip().lstrip("#").strip()
    rendered = f"# {body}" if body else "#"

    lines = _physical_lines_keepends(src)
    indent = _paste_anchor_indent(lines, line_start, line_end, position)
    term = _dominant_terminator(src)
    physical = indent + rendered
    if len(physical) > _MAX_LINE_LENGTH:
        raise LensRewriteError(
            f"the inserted comment would be {len(physical)} columns — over the {_MAX_LINE_LENGTH}-column "
            "limit (ruff would wrap it); shorten it"
        )
    new_line = physical + term
    insert_idx = (line_start - 1) if position == "before" else line_end
    if insert_idx >= len(lines):
        if lines and _line_terminator(lines[-1]) == "":
            lines[-1] = lines[-1] + term
        lines.append(new_line)
    else:
        lines.insert(insert_idx, new_line)
    return "".join(lines)


def _codeset_var(name: str) -> str:
    """Derive a module-binding variable for a code-set name (``"epic_diets"`` → ``EPIC_DIETS``)."""
    var = "".join(c if (c.isalnum() or c == "_") else "_" for c in name).upper()
    if not var or var[0].isdigit():
        var = "_" + var
    return var


def _codeset_binding(tree: ast.Module, var: str) -> str | None:
    """The code-set name if a module-level ``<var> = code_set("<name>")`` capture exists, else ``None``.

    Matches both a plain ``VAR = code_set(...)`` and an annotated ``VAR: CodeSet = code_set(...)`` so an
    annotated existing binding is reused, not mistaken for a non-code-set collision."""
    for node in tree.body:
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == var for t in node.targets
        ):
            value = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == var
        ):
            value = (
                node.value
            )  # may be None (``VAR: T`` with no assignment) — the guard below rejects it
        if (
            isinstance(value, ast.Call)
            and _callee_name(value.func) == "code_set"
            and value.args
            and isinstance(value.args[0], ast.Constant)
            and isinstance(value.args[0].value, str)
        ):
            return value.args[0].value
    return None


def _apply_insert_code_lookup(
    src: str,
    tree: ast.Module,
    handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
    line_start: int,
    line_end: int,
    edit: dict[str, Any],
) -> str:
    """Insert a ``code_lookup`` step bound to a managed code set (ADR 0106 §5 I; ADR 0033 tables).

    The "full" Code-Lookup insert: renders ``code_lookup(msg, <path>, <VAR>)`` at the anchor AND, when
    ``<VAR>`` is not already captured, injects a module-level ``<VAR> = code_set("<name>")`` binding among
    the imports (plus the ``code_set`` / ``code_lookup`` imports as needed). That module-level binding is
    the THIRD sanctioned out-of-row injection (ADR 0106 §6, alongside import injection and the Else-If/Else
    clause-append): it sits outside the anchor row's byte range, and the caller's re-parse + ruff gates
    still bracket the whole result. On readback the binding is invisible module setup (never a step row)
    and the inserted call is a ``lookup`` row. Refuses a missing ``code_set``/``path``, a non-identifier
    ``var``, or a ``<VAR>`` already bound to a DIFFERENT code set (or a non-code-set value) — a collision
    the analyst resolves by naming a different variable."""
    position = edit.get("position", "after")
    if position not in ("before", "after"):
        raise LensRewriteError("insert_code_lookup 'position' must be 'before' or 'after'")
    setname = edit.get("code_set")
    if not isinstance(setname, str) or not setname:
        raise LensRewriteError("insert_code_lookup requires a non-empty 'code_set' name")
    path = edit.get("path")
    if not isinstance(path, str) or not path:
        raise LensRewriteError("insert_code_lookup requires a 'path' (the field to translate)")
    var = edit.get("var")
    if var is None:
        var = _codeset_var(setname)
    if not (isinstance(var, str) and var.isidentifier()):
        raise LensRewriteError("insert_code_lookup 'var' must be a valid Python identifier")
    if _is_reserved_binding(var):
        raise LensRewriteError(
            f"insert_code_lookup: the variable {var!r} for code set {setname!r} is a reserved name - "
            "pass a different 'var'"
        )

    # A handler-LOCAL of the same name (a param or an assignment target anywhere in this handler) makes
    # ``var`` local for the whole body, so a module-level ``var = code_set(...)`` would be SHADOWED and the
    # inserted ``code_lookup(msg, path, var)`` would reference the local instead — refuse (module-scope
    # collisions are caught below).
    if var in _bound_names(handler_node):
        raise LensRewriteError(
            f"insert_code_lookup: {var!r} is a local variable of this handler — a module-level "
            "code_set(...) binding would be shadowed; choose a different variable name"
        )

    # Decide whether to inject the module-level binding — idempotent (reuse a same-set capture) and
    # collision-guarded (refuse a var already meaning something else, which a blind inject would shadow).
    existing = _codeset_binding(tree, var)
    if existing is not None:
        if existing != setname:
            raise LensRewriteError(
                f"insert_code_lookup: {var!r} is already bound to code_set({existing!r}) — "
                "choose a different variable name"
            )
        need_binding = False  # same code set already captured — reuse it
    elif _name_in_scope(tree, var):
        raise LensRewriteError(
            f"insert_code_lookup: {var!r} is already defined in this module (not as a code set) — "
            "choose a different variable name"
        )
    else:
        need_binding = True

    row_params: dict[str, Any] = {"path": path, "table": {"expr": var}}
    default = edit.get("default")
    if default is not None:
        row_params["default"] = default
    rendered = _render_insert_call(
        "code_lookup", row_params, None, scope=_message_scope(handler_node, tree, extra_inert=var)
    )

    lines = _physical_lines_keepends(src)
    indent = _paste_anchor_indent(lines, line_start, line_end, position)
    term = _dominant_terminator(src)
    physical = indent + rendered
    if len(physical) > _MAX_LINE_LENGTH:
        raise LensRewriteError(
            f"the inserted code_lookup would be {len(physical)} columns — over the {_MAX_LINE_LENGTH}-"
            "column limit (ruff would wrap it); shorten the path or variable"
        )
    # Splice the row FIRST (deepest index), then the prelude at the LEADING import block: that block is
    # always above every handler body, so the row's index is below the prelude's — inserting the prelude
    # simply shifts the already-placed row down, preserving its position relative to its anchor. (Using
    # the leading block, not the last import anywhere, keeps this invariant even when a stray top-level
    # import trails the handlers, and lands the binding canonically at the top.)
    new_line = physical + term
    insert_idx = (line_start - 1) if position == "before" else line_end
    if insert_idx >= len(lines):
        if lines and _line_terminator(lines[-1]) == "":
            lines[-1] = lines[-1] + term
        lines.append(new_line)
    else:
        lines.insert(insert_idx, new_line)

    prelude: list[str] = []
    if not _name_in_scope(tree, "code_lookup"):
        prelude.append(f"from messagefoundry import code_lookup{term}")
    if need_binding and not _name_in_scope(tree, "code_set"):
        prelude.append(f"from messagefoundry import code_set{term}")
    if need_binding:
        # A module-level statement must be blank-line-separated from the import block (ruff format);
        # the ``code_set`` capture sits just below the imports, mirroring the canonical config layout.
        prelude.append(term)
        prelude.append(f"{var} = code_set({_str_lit(setname)}){term}")
    import_idx = _leading_import_end(tree)
    lines[import_idx:import_idx] = prelude
    return "".join(lines)


# The three ADR 0076 actions the ADR 0089 Phase A recognizer reads back from their NATIVE Message-API
# idiom. An insert of one of these emits that native form (no vocabulary import needed) so a new step
# matches an estate authored in the native API and round-trips through :func:`_recognize_native_method`.
_NATIVE_INSERT_ACTIONS = frozenset(
    {"set_field", "copy_field", "delete_segment", "add_segment", "add_repetition"}
)


# A literal HL7 path to a component or subcomponent, the grammar of ``parsing.peek.parse_path``
# restated because the lens stays stdlib-only. A malformed path simply does not match.
_LEAF_PATH_RE = re.compile(r"^[A-Z][A-Z0-9]{2}-\d+\.\d+(?:\.\d+)?$")


def _is_leaf_literal(value: Any) -> bool:
    """Whether an insert parameter is a literal HL7 path to a component or subcomponent."""
    return isinstance(value, str) and _LEAF_PATH_RE.match(value) is not None


def _copy_write_method(src: Any) -> str:
    """The ``Message`` write a native Copy Field from ``src`` uses (ADR 0206 rule 1): ``set_data`` for
    a literal component or subcomponent path, whose read is decoded, as ``actions.copy_field`` does;
    ``set`` otherwise. A ``src`` given as an expression cannot be classified and keeps ``set``; the
    handler-security lint cannot see that one either."""
    return "set_data" if _is_leaf_literal(src) else "set"


#: The characters that template text carries as structure the author meant: the HL7 component,
#: repetition, subcomponent and escape characters ``^ ~ & \``. Text holding one keeps ``set``.
#:
#: The lens is static. It cannot tell an HL7 handler from an X12 one, and it cannot read a
#: message's own separators. So it protects HL7, the default format, and adds no X12-only
#: separator (vault #2861, ADR 0206 amendment 2026-10-04). ``^`` and ``~`` are also common X12
#: separators, for a repetition and a segment end, and both X12 writes refuse those. Each
#: character here costs HL7 something: a template that keeps ``set`` lets a decoded leaf's
#: separators become structure. ``MRN: `` around a leaf decoding to ``12^34`` wrote a second
#: component while ``:`` was here.
#:
#: X12 pays for this instead. An X12 leaf read cannot hold the component separator, so on X12 one
#: in a template is always text the author typed. ``set_data`` refuses it in a whole element, so
#: the line raises, whether the author meant a composite such as ``11:B:1`` or data such as
#: ``12:30``. ``set`` would write the first and split the second without a word. An X12 author who
#: means a composite writes ``set`` by hand or writes each component.
#:
#: The HL7 field separator is not here either: a whole-field ``set`` refuses one anyway, so text
#: holding it can only mean data.
_AUTHORED_STRUCTURE = frozenset("^~&" + chr(92))


def _template_write_method(value: ast.expr, dst: ast.expr) -> str:
    """The ``Message`` write a native Set Field writing ``value`` to ``dst`` uses (ADR 0206 rule 1).

    ``set_data`` for a template whose every read is a literal component or subcomponent path, whose
    read is decoded, and whose own text holds no character in :data:`_AUTHORED_STRUCTURE`; ``set``
    for anything else. A whole-field read is raw text with its structure, which ``set_data`` would
    escape into one component, and text holding one of those characters is structure the author
    wrote, so either keeps ``set``, and the handler-security lint still flags a leaf such a template
    copies. At a literal leaf destination the two writes are the same, so ``set`` is kept there
    too."""
    if _is_leaf_literal(getattr(dst, "value", None)) or not _template_is_data(value):
        return "set"
    return "set_data"


def _template_is_data(value: ast.expr) -> bool:
    """Whether ``value`` is a template whose every read is a literal component or subcomponent path
    and whose own text holds no character in :data:`_AUTHORED_STRUCTURE`: the template
    :func:`_template_write_method` writes with ``set_data`` at a whole-field destination. A
    hand-written f-string may have no read at all, which is not one."""
    parts = _template_parts(value)
    if parts is None:
        return False
    paths = [part[PART_PATH] for part in parts if PART_PATH in part]
    text = "".join(part.get(PART_TEXT, "") for part in parts)
    return (
        bool(paths)
        and not any(char in _AUTHORED_STRUCTURE for char in text)
        and all(_is_leaf_literal(path) for path in paths)
    )


def _native_write_method(value: ast.expr, dst: ast.expr) -> str:
    """The ``Message`` write a native ``set_field`` or ``copy_field`` writing ``value`` to ``dst``
    uses: a copy's by its source (:func:`_copy_write_method`), anything else by
    :func:`_template_write_method`."""
    field_call = _msg_field_source(value)
    if field_call is not None:
        return _copy_write_method(getattr(field_call.args[0], "value", None))
    return _template_write_method(value, dst)


def _refuse_non_text_value(rendered: str, scope: _Scope, pname: str = "value") -> None:
    """Refuse a Set Field or Add Repetition value, or a Code Lookup default, that may not be text.

    ``Message.set`` and ``add_repetition`` take a ``str`` and raise TypeError on a number or
    ``None``. A tuple is worse: ``add_repetition`` writes ``str(("a", "b"))`` into a populated
    field and the message is delivered with ``('a', 'b')`` in it, and ``code_lookup`` does the same
    with ``str(default)`` (Lander review of PR 2154). So, in every mode, admitted: a string
    literal, an f-string, a message read, or a name :func:`_message_scope` lists as ``text``. A
    read that finds no field returns None, which is the pre-existing behaviour of a bare read and
    is not narrowed here."""
    node = ast.parse(rendered, mode="eval").body
    text = (
        (isinstance(node, ast.Constant) and isinstance(node.value, str))
        or isinstance(node, ast.JoinedStr)
        or (isinstance(node, ast.Name) and node.id in scope.text)
        or _is_field_read(node, scope=scope)
    )
    if not text:
        raise LensRewriteError(
            f"parameter {pname!r}: {rendered} is not text, and a field value must be text - "
            "write it as a string"
        )


#: The ``(call, parameter)`` pairs whose value ends up as a field's text.
_TEXT_VALUE_PARAMS = frozenset(
    {("set_field", "value"), ("add_repetition", "value"), ("code_lookup", "default")}
)


def _refuse_non_text_set_params(row: dict[str, Any], params: dict[str, Any]) -> None:
    """``set_params`` on a Set Field or Add Repetition value, or a Code Lookup default, may not write
    a number, ``None`` or a boolean, as a JSON scalar or as an ``{"expr": ...}`` literal (Lander
    review of PR 2154). Every mode refuses them. Every other shape is left to the moded splice,
    which takes only a literal and refuses the rest with its own message (ADR 0076 Amendment E)."""
    call = row.get("action") or row.get("call")
    for pname, value in params.items():
        if (call, pname) not in _TEXT_VALUE_PARAMS:
            continue
        literal: object = value
        if isinstance(value, dict):
            expr = value.get("expr") if set(value) == {"expr"} else None
            if not isinstance(expr, str):
                continue
            try:
                node = ast.parse(expr.strip(), mode="eval").body
            except (SyntaxError, *_PARSER_REFUSALS):
                continue  # the splice refuses it with its own message
            if not isinstance(node, ast.Constant):
                continue
            literal = node.value
        if not (literal is None or isinstance(literal, bool | int | float)):
            continue
        raise LensRewriteError(
            f"parameter {pname!r}: {value!r} is not text, and a field value must be text - "
            "write it as a string"
        )


def _render_native_insert_call(
    name: str,
    params: dict[str, Any],
    assign_to: Any,
    *,
    scope: _Scope,
) -> str:
    """Render the NATIVE Message-API form of an inserted ``set_field``/``copy_field``/``delete_segment``.

    The single source of truth for the inserted native text — chosen so that re-parsing the line
    recognizes the SAME editable action row (:func:`_recognize_native_method`):

    * ``set_field {path, value}`` renders ``msg.set(<path>, <value>)``, or ``msg.set_data`` when the
      value copies a decoded leaf (:func:`_native_write_method`, ADR 0206)
    * ``copy_field {src, dst}`` renders ``msg.set(<dst>, msg.field(<src>) or "")``, or ``msg.set_data``
      in place of ``msg.set`` when ``src`` is a literal component or subcomponent path (ADR 0206)
    * ``delete_segment {segment_id}`` renders ``msg.delete_segments(<segment_id>)``
    * ``add_segment {line}`` renders ``msg.add_segment(<line>)`` (ADR 0106 section 3, Group 1)
    * ``add_repetition {path, value}`` renders ``msg.add_repetition(<path>, <value>)`` (ADR 0106 section 3, Group 1)

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
        # every native form mutates the message in place and returns ``None``; assigning that both binds
        # ``None`` and reclassifies the row as ``code`` (only a bare call is recognized).
        raise LensRewriteError(
            f"insert_row: {name!r} returns no value, so it cannot be assigned "
            "(only db_lookup/fhir_lookup return a value to assign)"
        )
    # ADR 0106 §5 C — an ``occurrence=``/``repetition=`` passthrough makes a For-Each loop var inhabitable
    # (``occurrence={"expr":"i"}``). Computed once here so an unsupported kwarg is refused for EVERY name
    # (add_segment/delete_segment take neither), never silently dropped.
    suffix = _native_occurrence_suffix(name, params, scope)
    if name == "set_field":
        path = _render_insert_value(params.get("path", ""), "path", scope=scope)
        value = _render_insert_value(
            params.get("value", ""),
            "value",
            policy=_insert_value_policy(name, "value"),
            scope=scope,
        )
        _refuse_non_text_value(value, scope)
        write = _native_write_method(
            ast.parse(value, mode="eval").body, ast.parse(path, mode="eval").body
        )
        return f"msg.{write}({path}, {value}{suffix})"
    if name == "copy_field":
        src = _render_insert_value(params.get("src", ""), "src", scope=scope)
        dst = _render_insert_value(params.get("dst", ""), "dst", scope=scope)
        # The occurrence applies to BOTH the inner read and the outer write, so the copy operates on the
        # loop's occurrence (not occurrence 1); the recognizer surfaces only the outer set's occurrence.
        write = _copy_write_method(params.get("src"))
        return f'msg.{write}({dst}, msg.field({src}{suffix}) or ""{suffix})'
    if name == "add_segment":
        line = _render_insert_value(params.get("line", ""), "line", scope=scope)
        return f"msg.add_segment({line})"
    if name == "add_repetition":
        path = _render_insert_value(params.get("path", ""), "path", scope=scope)
        value = _render_insert_value(
            params.get("value", ""),
            "value",
            policy=_insert_value_policy(name, "value"),
            scope=scope,
        )
        _refuse_non_text_value(value, scope)
        return f"msg.add_repetition({path}, {value}{suffix})"
    # delete_segment — the recognizer reads back both ``delete_segments`` and ``delete_segment``.
    segment_id = _render_insert_value(params.get("segment_id", ""), "segment_id", scope=scope)
    return f"msg.delete_segments({segment_id})"


# The occurrence/repetition kwargs each native insert accepts (mirrors the Message API signatures:
# set/field take occurrence+repetition; add_repetition takes occurrence only; add_segment/delete_segment
# take neither). An inserted call may carry these so a For-Each loop index is usable (ADR 0106 §5 C).
_NATIVE_OCCURRENCE_KW: dict[str, tuple[str, ...]] = {
    "set_field": ("occurrence", "repetition"),
    "copy_field": ("occurrence", "repetition"),
    "add_repetition": ("occurrence",),
    "add_segment": (),
    "delete_segment": (),
}


def _native_occurrence_suffix(name: str, params: dict[str, Any], scope: _Scope) -> str:
    """Render the ``, occurrence=<v>[, repetition=<v>]`` kwarg suffix for a native insert (ADR 0106 §5 C).

    Only the kwargs the underlying Message method accepts are allowed; an unsupported one (e.g. a
    ``repetition`` on ``add_repetition``, or any on ``add_segment``/``delete_segment``) is REFUSED rather
    than silently dropped. Values render via :func:`_render_insert_value`, so a loop index passes as
    ``occurrence={"expr":"i"}`` → ``occurrence=i`` and a literal as ``occurrence=2``."""
    allowed = _NATIVE_OCCURRENCE_KW.get(name, ())
    parts: list[str] = []
    for kw in ("occurrence", "repetition"):
        if kw not in params:
            continue
        if kw not in allowed:
            raise LensRewriteError(f"insert_row: {name!r} does not accept a {kw!r} argument")
        rendered = _render_insert_value(params[kw], kw, scope=scope)
        node = ast.parse(rendered, mode="eval").body
        none_ok = kw == "repetition" and isinstance(node, ast.Constant) and node.value is None
        if not none_ok and not _is_index_value(node, scope):
            # ``occurrence="x"`` or ``occurrence=0`` raises on every message (review of head
            # c172beda9c, finding 2).
            raise LensRewriteError(
                f"parameter {kw!r}: {rendered} is not a whole number of 1 or more, a loop index, "
                "or simple arithmetic on those - edit it as text"
            )
        parts.append(f", {kw}={rendered}")
    return "".join(parts)


def _is_index_value(node: ast.expr, scope: _Scope) -> bool:
    """Whether ``node`` is an ``occurrence``/``repetition`` value that is 1 or more on every message
    (``Message.set`` raises on anything less): int-literal arithmetic over ``+``, ``-`` and ``*`` that
    comes to 1 or more, a For-Each loop index (``range(1, ...)`` starts it at 1), or a loop index plus
    such arithmetic that comes to 0 or more. No division, which yields a float, and no other name,
    whose value the lens cannot bound (review of head 6259fb97a2, finding 2)."""

    def value(n: ast.expr) -> int | None:
        if isinstance(n, ast.Constant) and type(n.value) is int:
            return n.value
        if isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.USub | ast.UAdd):
            inner = value(n.operand)
            return None if inner is None else (-inner if isinstance(n.op, ast.USub) else inner)
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add | ast.Sub | ast.Mult):
            left, right = value(n.left), value(n.right)
            if left is None or right is None or max(abs(left), abs(right)) > 10**6:
                return None
            if isinstance(n.op, ast.Add):
                return left + right
            return left - right if isinstance(n.op, ast.Sub) else left * right
        return None

    if isinstance(node, ast.Name):
        return node.id in scope.loop_indexes
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        for index, offset in ((node.left, node.right), (node.right, node.left)):
            if isinstance(index, ast.Name) and index.id in scope.loop_indexes:
                bump = value(offset)
                return bump is not None and bump >= 0
    total = value(node)
    return total is not None and total >= 1


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


def _render_insert_call(
    name: str,
    params: dict[str, Any],
    assign_to: Any,
    *,
    scope: _Scope,
) -> str:
    """Render a NEW vocabulary action/lookup call ``name(...)`` (optionally ``target = name(...)``).

    Positional arguments are emitted in the helper's signature order (the leading ``msg`` verbatim where
    the helper takes one); a parameter not in the positional signature is emitted as a keyword argument
    (e.g. a keyword-only ``default=`` / ``in_fmt=``). A scalar value renders as a Python literal, an
    ``{"expr": <source>}`` object verbatim when it runs no code. Refuses an unknown vocabulary name, a missing required
    positional parameter, a ``msg`` parameter (it is supplied automatically — passing it would emit a
    duplicate ``msg=`` kwarg), ``assign_to`` on a mutating action/lookup (only db_lookup/fhir_lookup
    return a value — assigning an action's ``None`` reclassifies the row as ``code``), or a non-identifier
    ``assign_to`` / keyword name. Also renders the ``diagnostics`` helpers (``log_note`` / ``checkpoint``,
    ADR 0106 §5) so they are insertable — they round-trip to ``diagnostic`` rows and return ``None``."""
    param_names = (
        _ACTION_PARAMS.get(name) or _LOOKUP_PARAMS.get(name) or _DIAGNOSTIC_PARAMS.get(name)
    )
    if param_names is None:
        raise LensRewriteError(
            f"insert_row: {name!r} is not a recognized vocabulary action/lookup "
            f"(known: {sorted(_ACTIONS | _LOOKUPS | _DIAGNOSTICS)})"
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
        args.append(
            _render_insert_value(
                params[pn],
                pn,
                policy=_insert_value_policy(name, pn),
                scope=_param_scope(name, pn, scope),
            )
        )
        used.add(pn)
    for pn, val in params.items():
        if pn in used:
            continue
        if not (isinstance(pn, str) and pn.isidentifier()):
            raise LensRewriteError(f"insert_row: {pn!r} is not a valid keyword parameter name")
        rendered_kw = _render_insert_value(
            val, pn, policy=_insert_value_policy(name, pn), scope=_param_scope(name, pn, scope)
        )
        if (name, pn) in _TEXT_VALUE_PARAMS:
            _refuse_non_text_value(rendered_kw, scope, pn)
        args.append(f"{pn}={rendered_kw}")
    call = f"{name}({', '.join(args)})"
    if assign_to is not None:
        if name not in _ASSIGNABLE_LOOKUPS:
            # copy_field/set_field/code_lookup/log_note/… mutate (or log) and return ``None``; ``x = set_field(…)``
            # both binds ``None`` (nonsensical) and RE-CLASSIFIES the row as ``code`` (only a bare-call
            # action is recognized, not an assignment) — an uneditable row the analyst can't recover.
            raise LensRewriteError(
                f"insert_row: {name!r} returns no value, so it cannot be assigned "
                "(only db_lookup/fhir_lookup return a value to assign)"
            )
        if not (isinstance(assign_to, str) and assign_to.isidentifier()):
            raise LensRewriteError("insert_row 'assign_to' must be a simple identifier")
        if _is_reserved_binding(assign_to):
            # Rebinding ``msg`` would turn every later message read in the handler into a read of the
            # lookup's result (Theia review finding R1); a keyword or dunder name is never a result name.
            raise LensRewriteError(
                f"insert_row 'assign_to' cannot be {assign_to!r} - choose a new variable name"
            )
        call = f"{assign_to} = {call}"
    return call


def _render_insert_value(
    value: Any,
    pname: str,
    *,
    policy: str = _POLICY_LITERAL,
    scope: _Scope,
) -> str:
    """Render a NEW call argument value: a scalar as a Python literal, an ``{"expr": …}`` verbatim.

    Unlike :func:`_render_new_value` (which guards an existing literal-vs-expression slot), an inserted
    call has no existing argument, so a scalar always renders as a literal and an object must be
    ``{"expr": <source>}`` (validated to parse as one expression, and refused unless it runs no code,
    :func:`_is_inert_value`). The rendered value must stay on a single physical line (a newline would
    change the file's line count)."""
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
    if isinstance(value, dict):
        _refuse_active_expr(rendered, pname, policy=policy, scope=scope)
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
