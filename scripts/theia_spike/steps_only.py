# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SPIKE S-4 (ADR 0208, spec section 17): a prototype of the FR-40 Steps-only classifier.

This is a spike, not product code. It answers one question: can FR-40 be implemented as a pure
function over a module's base and head sources, built on ``messagefoundry.lens.parse_source``? It
never imports or runs either source. It reads the lens's row partition read-only, and reuses a few
of the lens's private tables and predicates so it cannot drift from the grammar it checks. A product
version would need those exposed as a public surface.

The entry points are :func:`classify_file` (one path, base and head text) and
:func:`classify_change` (every changed path of a change). Each returns a :class:`Verdict`. The rules
follow FR-40 items 1 to 6. Where this code departs from the text of FR-40, a comment names the item
and says why; the spike report lists each one.
"""

from __future__ import annotations

import ast
import builtins
import difflib
import keyword
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from messagefoundry import lens
from messagefoundry.lens import CONTRACT_V2, LensParseError, parse_source

# Read-only reuse of the lens grammar. Each is private in lens.py today.
_ACTION_PARAMS: dict[str, list[str]] = lens._ACTION_PARAMS
_LOOKUP_PARAMS: dict[str, list[str]] = lens._LOOKUP_PARAMS
_DIAGNOSTIC_PARAMS: dict[str, list[str]] = lens._DIAGNOSTIC_PARAMS
_TEMPLATE_PARAMS: frozenset[tuple[str, str]] = lens._TEMPLATE_PARAMS
_ASSIGNABLE_LOOKUPS: frozenset[str] = lens._ASSIGNABLE_LOOKUPS

#: The names the lens may inject with ``from messagefoundry import <name>`` (ADR 0106 section 6 H/I).
_INJECTABLE = frozenset(
    {*_ACTION_PARAMS, *_LOOKUP_PARAMS, *_DIAGNOSTIC_PARAMS, "Send", "code_set", "code_lookup"}
)
#: Native ``msg.<method>`` writes the lens recognizes, by method, with their positional slot names.
_NATIVE_SLOTS: dict[str, tuple[str, ...]] = {
    "set": ("path", "value"),
    "set_data": ("path", "value"),
    "add_repetition": ("path", "value"),
    "add_segment": ("line",),
    "delete_segments": ("segment_id",),
    "delete_segment": ("segment_id",),
}
#: The verb each native method reads back as, for the E.11 rule 4 template list.
_NATIVE_VERB = {
    "set": "set_field",
    "set_data": "set_field",
    "add_repetition": "add_repetition",
    "add_segment": "add_segment",
    "delete_segments": "delete_segment",
    "delete_segment": "delete_segment",
}
_OCCURRENCE_KW = frozenset({"occurrence", "repetition"})
_ACCUMULATOR = "sends"
_TYPED_KINDS = frozenset({"action", "lookup", "diagnostic"})
_LINE_RE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+$")


@dataclass(frozen=True)
class Verdict:
    """Whether a change is Steps-only, and every reason it is not (empty when it is)."""

    steps_only: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Mark:
    """One entry of an element's fixed skeleton: a code-row line or a control header, with its path."""

    path: tuple[Any, ...]
    tag: str  # "code" or "header"
    content: Any
    generator_shaped: bool = False


@dataclass
class _Element:
    role: str
    name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    marks: list[_Mark] = field(default_factory=list)
    typed: list[ast.stmt] = field(default_factory=list)
    sends: list[ast.stmt] = field(default_factory=list)
    routes: list[ast.Return] = field(default_factory=list)
    for_targets: dict[int, set[str]] = field(default_factory=dict)


@dataclass
class _Module:
    source: str
    lines: list[str]
    tree: ast.Module
    elements: list[_Element]
    body_spans: list[tuple[int, int, str]]


# --- entry points ------------------------------------------------------------------------------


def classify_change(changes: Mapping[str, tuple[str | None, str | None]]) -> Verdict:
    """Classify a whole change: ``{path: (base text or None, head text or None)}``.

    Steps-only only when every changed path is (FR-40). An unchanged path is skipped."""
    reasons: list[str] = []
    for path, (base, head) in sorted(changes.items()):
        if base == head:
            continue
        verdict = classify_file(path, base, head)
        reasons.extend(f"{path}: {r}" for r in verdict.reasons)
    return Verdict(not reasons, tuple(reasons))


def classify_file(path: str, base: str | None, head: str | None) -> Verdict:
    """Classify one changed path. ``None`` means the file is absent on that side."""
    reasons: list[str] = []
    name = PurePosixPath(path.replace("\\", "/")).name
    # FR-40 item 1: an existing Router or Handler module, never a new, deleted, helper or data file.
    if base is None:
        return Verdict(False, ("path: a new file is not Steps-only",))
    if head is None:
        return Verdict(False, ("path: a deleted file is not Steps-only",))
    if not name.endswith(".py"):
        return Verdict(False, ("path: not a Python module (data, code set or environment file)",))
    if name.startswith("_"):
        return Verdict(False, ("path: a _-prefixed helper module is not Steps-only",))
    try:
        base_mod = _load(base)
    except (LensParseError, SyntaxError, ValueError) as exc:
        return Verdict(False, (f"parse: the base does not parse ({exc})",))
    if not base_mod.elements:
        return Verdict(False, ("path: the base has no @handler or @router; not a Steps module",))
    try:
        head_mod = _load(head)
    except (LensParseError, SyntaxError, ValueError) as exc:
        return Verdict(False, (f"parse: the head does not parse ({exc})",))
    if [(e.role, e.name) for e in base_mod.elements] != [
        (e.role, e.name) for e in head_mod.elements
    ]:
        return Verdict(False, ("elements: an @handler or @router was added, removed or renamed",))
    reasons.extend(_check_outside(base_mod, head_mod))
    for b_el, h_el in zip(base_mod.elements, head_mod.elements, strict=True):
        reasons.extend(_check_element(base_mod, head_mod, b_el, h_el))
    return Verdict(not reasons, tuple(reasons))


# --- loading ---------------------------------------------------------------------------------


def _split_lines(source: str) -> list[str]:
    """Physical lines with their terminators, split on CRLF, CR and LF only, as the tokenizer does."""
    return _LINE_RE.findall(source)


def _load(source: str) -> _Module:
    contracts = parse_source(source, contract=CONTRACT_V2)
    tree = ast.parse(source.removeprefix("﻿"))
    lines = _split_lines(source)
    defs = {n.lineno: n for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)}
    elements: list[_Element] = []
    spans: list[tuple[int, int, str]] = []
    for entry in contracts:
        node = defs[entry["def_line"]]
        el = _Element(role=entry["role"], name=entry["handler"], node=node)
        rows: list[dict[str, Any]] = entry["rows"]
        _index_rows(el, rows, lines)
        lo = min(r["line_start"] for r in rows)
        hi = max(r["line_end"] for r in rows)
        # Lines between the signature and the first statement that are blank or comment-only are
        # outside the lens partition, but carry no code. Treat them as body so a comment inserted
        # before the first row is not read as a module-scope byte change (spike departure, item 2).
        while lo - 1 > node.lineno and _is_blank_or_comment(lines[lo - 2]):
            lo -= 1
        spans.append((lo, hi, f"{el.role}:{el.name}"))
        elements.append(el)
    return _Module(source, lines, tree, elements, spans)


def _is_blank_or_comment(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _own_stmts(node: ast.AST) -> dict[tuple[int, int], ast.stmt]:
    """Statements under ``node`` by span, outermost first (the lens never projects nested defs)."""
    found: dict[tuple[int, int], ast.stmt] = {}
    for sub in ast.walk(node):
        if isinstance(sub, ast.stmt) and sub is not node:
            found.setdefault((sub.lineno, sub.end_lineno or sub.lineno), sub)
    return found


def _index_rows(el: _Element, rows: list[dict[str, Any]], lines: list[str]) -> None:
    """Walk the lens rows once, recording code lines, headers and typed statements with suite paths.

    A suite path is the chain of enclosing control frames, each compared by content (FR-40 item 3).
    An ``if`` frame is its test; an ``elif`` frame is the chain's ``if`` plus its own test; an
    ``else`` frame is the chain's ``if`` (spike reading of an ambiguity, see the report)."""
    by_span = _own_stmts(el.node)
    by_line: dict[int, ast.stmt] = {}
    for (start, _end), stmt in by_span.items():
        by_line.setdefault(start, stmt)
    stack: list[tuple[Any, ...]] = []
    chain_head: dict[int, tuple[Any, ...]] = {}
    for row in rows:
        nesting: int = row["nesting"]
        del stack[nesting:]
        path = tuple(stack)
        kind = row["kind"]
        ls, le = row["line_start"], row["line_end"]
        if kind == "control":
            control = row["control"]
            frame: tuple[Any, ...] | None
            if control in ("if", "elif"):
                stmt = by_line[ls]
                assert isinstance(stmt, ast.If)
                content = ("test", ast.dump(stmt.test))
                if control == "if":
                    chain_head[nesting] = content
                    frame = ("if", content)
                else:
                    frame = ("elif", chain_head.get(nesting), content)
                el.marks.append(_Mark(path, "header", frame, _if_test_generated(stmt.test)))
            elif control == "else":
                frame = ("else", chain_head.get(nesting))
                el.marks.append(_Mark(path, "header", frame, True))
            elif control == "for":
                stmt = by_line[ls]
                assert isinstance(stmt, ast.For | ast.AsyncFor)
                frame = ("for", ast.dump(stmt.target), ast.dump(stmt.iter))
                el.marks.append(_Mark(path, "header", frame, _for_generated(stmt)))
                if isinstance(stmt.target, ast.Name):
                    el.for_targets[stmt.lineno] = {stmt.target.id}
            else:  # raise: a header with no body (FR-40 item 4)
                stmt = by_span[(ls, le)]
                el.marks.append(
                    _Mark(path, "header", ("raise", ast.dump(stmt)), _raise_generated(stmt))
                )
                frame = None
            if frame is not None:
                stack.append(frame)
            continue
        if kind == "code":
            if row.get("scaffold") and _is_scaffold_stmt(by_span.get((ls, le))):
                continue  # ADR 0108 accumulator scaffold, sanctioned by FR-40 item 3
            pass_lines = {
                s.lineno
                for s in by_span.values()
                if isinstance(s, ast.Pass) and ls <= s.lineno <= le and s.end_lineno == s.lineno
            }
            for lineno in range(ls, le + 1):
                text = lines[lineno - 1].rstrip("\r\n") if lineno - 1 < len(lines) else ""
                if not text.strip():
                    continue
                if lineno in pass_lines and text.strip() == "pass":
                    continue  # a pass seed is inert, in either direction (spike departure, item 3)
                el.marks.append(_Mark(path, "code", text))
            continue
        if kind == "note":
            continue  # a comment run: no code, and the lens edits it freely
        stmt = by_span[(ls, le)]
        if kind in _TYPED_KINDS:
            el.typed.append(stmt)
        elif kind == "send":
            el.sends.append(stmt)
        elif kind == "route":
            assert isinstance(stmt, ast.Return)
            el.routes.append(stmt)


def _is_scaffold_stmt(stmt: ast.stmt | None) -> bool:
    if stmt is None:
        return False
    if isinstance(stmt, ast.Assign):
        return ast.dump(stmt) == ast.dump(ast.parse(f"{_ACCUMULATOR} = []").body[0])
    if isinstance(stmt, ast.Return):
        return ast.dump(stmt) == ast.dump(_parse_in_def(f"return {_ACCUMULATOR}"))
    return False


def _parse_in_def(text: str) -> ast.stmt:
    func = ast.parse(f"def _f():\n    {text}\n").body[0]
    assert isinstance(func, ast.FunctionDef)
    return func.body[0]


# --- FR-40 item 2: outside the def bodies ---------------------------------------------------


def _top_key(stmt: ast.stmt, spans: Iterable[tuple[int, int, str]]) -> str:
    for lo, _hi, label in spans:
        if stmt.lineno <= lo <= (stmt.end_lineno or stmt.lineno):
            return f"element {label}"
    return ast.dump(stmt)


def _masked(mod: _Module, drop: set[int]) -> list[str]:
    """The module's lines with each def body replaced by a marker and ``drop`` lines removed."""
    out: list[str] = []
    starts = {lo: label for lo, _hi, label in mod.body_spans}
    inside: set[int] = set()
    for lo, hi, _label in mod.body_spans:
        inside.update(range(lo, hi + 1))
    for lineno, text in enumerate(mod.lines, start=1):
        if lineno in starts:
            out.append(f"\x00body {starts[lineno]}\n")
        if lineno in inside or lineno in drop:
            continue
        out.append(text)
    return out


def _check_outside(base: _Module, head: _Module) -> list[str]:
    b_keys = [_top_key(s, base.body_spans) for s in base.tree.body]
    h_keys = [_top_key(s, head.body_spans) for s in head.tree.body]
    base_names = _module_names(base.tree)
    drop: set[int] = set()
    reasons: list[str] = []
    new_bindings: set[str] = set()
    matcher = difflib.SequenceMatcher(a=b_keys, b=h_keys, autojunk=False)
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag != "insert":
            reasons.append("outside: a module-scope statement was changed or removed")
            continue
        for stmt in head.tree.body[j1:j2]:
            why = _sanctioned_module_stmt(stmt, head, base.tree, base_names, new_bindings)
            if why is not None:
                reasons.append(f"outside: {why}")
                continue
            drop.update(range(stmt.lineno, (stmt.end_lineno or stmt.lineno) + 1))
            if (
                isinstance(stmt, ast.Assign)
                and stmt.lineno >= 2
                and not head.lines[stmt.lineno - 2].strip()
            ):
                drop.add(stmt.lineno - 1)  # the blank line insert_code_lookup puts before it
    if reasons:
        return reasons
    if _masked(base, set()) != _masked(head, drop):
        return ["outside: bytes outside the def bodies changed beyond the sanctioned shapes"]
    return []


def _sanctioned_module_stmt(
    stmt: ast.stmt,
    head: _Module,
    base_tree: ast.Module,
    base_names: set[str],
    new_bindings: set[str],
) -> str | None:
    """None when ``stmt`` is a sanctioned generated module-scope shape, else why it is not."""
    text = "".join(head.lines[stmt.lineno - 1 : stmt.end_lineno or stmt.lineno]).rstrip("\r\n")
    if isinstance(stmt, ast.ImportFrom):
        names = [a.name for a in stmt.names]
        if (
            stmt.module == "messagefoundry"
            and stmt.level == 0
            and len(stmt.names) == 1
            and stmt.names[0].asname is None
            and names[0] in _INJECTABLE
            # Bound, not read: the lens injects exactly when the bare name is not in scope, and a
            # module may already read the name it is about to import (lens._name_in_scope).
            and not lens._name_in_scope(base_tree, names[0])
            and text == f"from messagefoundry import {names[0]}"
        ):
            return None
        return f"an added import that is not a generated vocabulary import: {text!r}"
    if (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Name)
        and stmt.value.func.id == "code_set"
        and len(stmt.value.args) == 1
        and not stmt.value.keywords
        and isinstance(stmt.value.args[0], ast.Constant)
        and isinstance(stmt.value.args[0].value, str)
    ):
        var = stmt.targets[0].id
        expected = f"{var} = code_set({lens._str_lit(stmt.value.args[0].value)})"
        if text != expected:
            return f"a code_set binding not in the generated form: {text!r}"
        if not _assignable_name(var) or var in base_names or var in new_bindings:
            return f"a code_set binding to a name that is reserved or already used: {var!r}"
        new_bindings.add(var)
        return None
    return f"an added module-scope statement: {text!r}"


def _module_names(tree: ast.Module) -> set[str]:
    """Every name the module binds or reads anywhere, plus its imports."""
    names: set[str] = set()
    for sub in ast.walk(tree):
        if isinstance(sub, ast.Name):
            names.add(sub.id)
        elif isinstance(sub, ast.alias):
            names.add(sub.asname or sub.name.split(".")[0])
        elif isinstance(sub, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(sub.name)
        elif isinstance(sub, ast.arg):
            names.add(sub.arg)
    return names


def _assignable_name(name: str) -> bool:
    """G.7's floor for a new binding: not msg, a builtin, a keyword or a dunder name."""
    return (
        name.isidentifier()
        and name != "msg"
        and not keyword.iskeyword(name)
        and not keyword.issoftkeyword(name)
        and not hasattr(builtins, name)
        and not (name.startswith("__") and name.endswith("__"))
    )


# --- FR-40 items 3 to 6: inside each def body ------------------------------------------------


def _check_element(base: _Module, head: _Module, b: _Element, h: _Element) -> list[str]:
    label = f"{h.role} {h.name!r}"
    reasons: list[str] = []
    # Items 3 and 4 together. A generator-shaped header may be added, removed or moved freely; every
    # code-row line and every other header must keep its content, its suite path and its order
    # relative to the others. Order is checked across the two kinds as well as within each, because
    # a hand-written block moved past a code row reorders code exactly as moving the code row would.
    codes_b = [m for m in b.marks if m.tag == "code"]
    codes_h = [m for m in h.marks if m.tag == "code"]
    if codes_b != codes_h:
        reasons.append(f"code-row: {label}: a code row was changed, added, removed or moved")
    reasons.extend(f"header: {label}: {r}" for r in _check_headers(b.marks, h.marks))
    fixed_b = [m for m in b.marks if not m.generator_shaped]
    fixed_h = [m for m in h.marks if not m.generator_shaped]
    if not reasons and fixed_b != fixed_h:
        reasons.append(
            f"header: {label}: a hand-written header and a code row moved relative to each other"
        )
    # Items 5 and 6.
    reasons.extend(f"param: {label}: {r}" for r in _check_typed(base, head, b, h))
    reasons.extend(f"send: {label}: {r}" for r in _check_sends(b, h))
    reasons.extend(f"route: {label}: {r}" for r in _check_routes(b, h))
    return reasons


def _check_headers(base: list[_Mark], head: list[_Mark]) -> list[str]:
    """FR-40 item 4: headers matched by (suite path, content) in order; the rest must be generated."""
    b_hdr = [m for m in base if m.tag == "header"]
    h_hdr = [m for m in head if m.tag == "header"]
    matcher = difflib.SequenceMatcher(
        a=[(m.path, m.content) for m in b_hdr],
        b=[(m.path, m.content) for m in h_hdr],
        autojunk=False,
    )
    out: list[str] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        out.extend(
            f"a removed or moved header that is not generator-shaped: {m.content[0]}"
            for m in b_hdr[i1:i2]
            if not m.generator_shaped
        )
        out.extend(
            f"an added or changed header that is not generator-shaped: {m.content[0]}"
            for m in h_hdr[j1:j2]
            if not m.generator_shaped
        )
    return out


def _str_const(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_msg_field_lit(node: ast.expr) -> bool:
    """``msg.field("<literal>")`` exactly: what ``_render_if_test`` writes as its read."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "field"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "msg"
        and len(node.args) == 1
        and _str_const(node.args[0])
        and not node.keywords
    )


def _if_test_generated(test: ast.expr) -> bool:
    """The four tests ``_render_if_test`` writes from literal inputs: exists, ==, != and contains."""
    if _is_msg_field_lit(test):
        return True
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1):
        return False
    op, right = test.ops[0], test.comparators[0]
    if isinstance(op, ast.Eq | ast.NotEq):
        return _is_msg_field_lit(test.left) and _str_const(right)
    if isinstance(op, ast.In):
        return (
            _str_const(test.left)
            and isinstance(right, ast.BoolOp)
            and isinstance(right.op, ast.Or)
            and len(right.values) == 2
            and _is_msg_field_lit(right.values[0])
            and isinstance(right.values[1], ast.Constant)
            and right.values[1].value == ""
        )
    return False


def _for_generated(stmt: ast.For | ast.AsyncFor) -> bool:
    """``for i in range(1, msg.count_segments("<literal>") + 1):``, the For Each template."""
    if isinstance(stmt, ast.AsyncFor) or stmt.orelse:
        return False
    return (
        isinstance(stmt.target, ast.Name)
        and stmt.target.id == "i"
        and lens._range_count_segment(stmt.iter) is not None
        and not isinstance(stmt.iter, ast.Starred)
    )


def _raise_generated(stmt: ast.stmt) -> bool:
    """``raise ValueError("<literal>")`` or ``RuntimeError``, the Raise template."""
    if not isinstance(stmt, ast.Raise) or stmt.cause is not None:
        return False
    exc = stmt.exc
    return (
        isinstance(exc, ast.Call)
        and isinstance(exc.func, ast.Name)
        and exc.func.id in ("ValueError", "RuntimeError")
        and len(exc.args) == 1
        and _str_const(exc.args[0])
        and not exc.keywords
    )


# --- item 5: typed parameters ---------------------------------------------------------------


@dataclass
class _Decomposed:
    skeleton: tuple[Any, ...]
    verb: str
    kind: str
    params: dict[str, ast.expr]
    assign_to: str | None


def _decompose(stmt: ast.stmt) -> _Decomposed | None:
    """Split a typed statement into a fixed skeleton and EVERY argument node, or None.

    None means a shape the lens generator never writes (an attribute callee, a splat, an annotated
    or non-name target, an unknown keyword), which is not Steps-only when new or changed. Every
    sub-expression outside the skeleton lands in ``params``, including a native copy's inner read
    keywords and extra positionals past a signature, because the lens's own ``param_modes`` does not
    cover the former."""
    target: str | None = None
    value: ast.expr
    if isinstance(stmt, ast.Expr):
        value = stmt.value
    elif (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
    ):
        value = stmt.value
        target = stmt.targets[0].id
    else:
        return None
    if not isinstance(value, ast.Call) or any(isinstance(a, ast.Starred) for a in value.args):
        return None
    if any(kw.arg is None for kw in value.keywords):
        return None
    func = value.func
    if isinstance(func, ast.Name):
        name = func.id
        signature = _ACTION_PARAMS.get(name) or _LOOKUP_PARAMS.get(name)
        kind = "action" if name in _ACTION_PARAMS else "lookup"
        if signature is None:
            signature = _DIAGNOSTIC_PARAMS.get(name)
            kind = "diagnostic"
        if signature is None:
            return None
        if target is not None and name not in _ASSIGNABLE_LOOKUPS:
            return None
        params: dict[str, ast.expr] = {}
        for i, arg in enumerate(value.args):
            pname = signature[i] if i < len(signature) else f"arg{i}"
            if pname == "msg":
                if not (isinstance(arg, ast.Name) and arg.id == "msg"):
                    return None
                continue
            params[pname] = arg
        for kw in value.keywords:
            assert kw.arg is not None
            if kw.arg in params:
                return None
            params[kw.arg] = kw.value
        return _Decomposed(("call", name, target is not None), name, kind, params, target)
    if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
        return None
    if func.value.id != "msg":
        return None
    method = func.attr
    if method == "field" and target is not None:
        if len(value.args) != 1 or target == "msg":
            return None
        params = {"path": value.args[0]}
        for kw in value.keywords:
            if kw.arg not in _OCCURRENCE_KW:
                return None
            params[str(kw.arg)] = kw.value
        return _Decomposed(("native", "field"), "read_field", "action", params, target)
    slots = _NATIVE_SLOTS.get(method)
    if slots is None or target is not None or len(value.args) != len(slots):
        return None
    params = dict(zip(slots, value.args, strict=True))
    for kw in value.keywords:
        if kw.arg not in _OCCURRENCE_KW:
            return None
        params[str(kw.arg)] = kw.value
    shape = "plain"
    if method in ("set", "set_data"):
        inner = lens._msg_field_source(value.args[1])
        if inner is not None:
            # A copy: msg.set(dst, msg.field(src[, occurrence=...]) or ""). Spread the inner read.
            if len(inner.args) != 1 or any(kw.arg not in _OCCURRENCE_KW for kw in inner.keywords):
                return None
            shape = "copy-or" if inner is not value.args[1] else "copy"
            del params["value"]
            params["src"] = inner.args[0]
            for kw in inner.keywords:
                params[f"src.{kw.arg}"] = kw.value
    # set and set_data read back as one Set Field; the lens picks the write itself (ADR 0206).
    skeleton_method = "set" if method == "set_data" else method
    return _Decomposed(
        ("native", skeleton_method, shape), _NATIVE_VERB[method], "action", params, None
    )


def _check_typed(base: _Module, head: _Module, b: _Element, h: _Element) -> list[str]:
    """FR-40 item 5. A head row equal by content to a base row is unchanged or moved, and passes.

    Every other head row is new or changed. It pairs with the first leftover base row of the same
    skeleton, in order, so only the parameters that differ from that row are checked; with no pair,
    every parameter is new."""
    out: list[str] = []
    pool = Counter(ast.dump(s) for s in b.typed)
    changed: list[ast.stmt] = []
    for stmt in h.typed:
        key = ast.dump(stmt)
        if pool[key] > 0:
            pool[key] -= 1
        else:
            changed.append(stmt)
    leftovers: list[_Decomposed] = []
    for stmt in b.typed:
        key = ast.dump(stmt)
        if pool[key] > 0:
            pool[key] -= 1
            d = _decompose(stmt)
            if d is not None:
                leftovers.append(d)
    names = _element_names(base.tree, b.node)
    for stmt in changed:
        new = _decompose(stmt)
        if new is None:
            out.append(f"a typed row in a shape the lens never writes at line {stmt.lineno}")
            continue
        old = next(
            (
                d
                for d in leftovers
                if d.skeleton == new.skeleton and d.params.keys() == new.params.keys()
            ),
            None,
        )
        if old is not None:
            leftovers.remove(old)
        out.extend(_check_new_params(new, old, h, stmt, head))
        renamed = new.assign_to is not None and (old is None or old.assign_to != new.assign_to)
        if renamed and new.assign_to is not None and not _assignable_name(new.assign_to):
            out.append(f"assign_to {new.assign_to!r} fails G.7: msg, a builtin or a reserved name")
        elif renamed and new.assign_to in names:
            out.append(f"assign_to {new.assign_to!r} fails G.7: already bound or read")
    return out


def _element_names(tree: ast.Module, node: ast.AST) -> set[str]:
    names = set(lens._module_bound_names(tree)[0])
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.add(sub.id)
        elif isinstance(sub, ast.arg):
            names.add(sub.arg)
    return names


def _check_new_params(
    new: _Decomposed, old: _Decomposed | None, el: _Element, stmt: ast.stmt, head: _Module
) -> list[str]:
    out: list[str] = []
    for pname, node in new.params.items():
        if old is not None and ast.dump(old.params[pname]) == ast.dump(node):
            continue  # a parameter the change left alone, dynamic or not (FR-40 item 5)
        if _value_ok(new, pname, node, el, stmt, head):
            continue
        out.append(f"{new.verb}.{pname} at line {stmt.lineno} is new or changed and not a literal")
    return out


def _is_literal(node: ast.expr) -> bool:
    try:
        ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False
    return True


def _value_ok(
    new: _Decomposed, pname: str, node: ast.expr, el: _Element, stmt: ast.stmt, head: _Module
) -> bool:
    """FR-40 item 5 for one new or changed value."""
    if _is_literal(node):
        return True
    if (
        (new.verb, pname) in _TEMPLATE_PARAMS
        and new.kind == "action"
        and lens._param_mode(node) == lens.MODE_TEMPLATED
    ):
        return True
    if pname == "params" and new.verb in ("db_lookup", "fhir_lookup"):
        return _lookup_params_ok(node, fhir=new.verb == "fhir_lookup")
    if new.verb == "code_lookup" and pname == "table":
        return isinstance(node, ast.Name) and _is_code_set_binding(head.tree, node.id)
    if pname.rsplit(".", 1)[-1] in _OCCURRENCE_KW and isinstance(node, ast.Name):
        # G.7 inert: a For Each range loop index of an enclosing generated loop.
        return any(
            node.id in names and _encloses(loop_line, stmt, el)
            for loop_line, names in el.for_targets.items()
        )
    return False


def _encloses(loop_line: int, stmt: ast.stmt, el: _Element) -> bool:
    for sub in ast.walk(el.node):
        if isinstance(sub, ast.For) and sub.lineno == loop_line:
            end = sub.end_lineno or sub.lineno
            return _for_generated(sub) and sub.lineno < stmt.lineno <= end
    return False


def _is_read(node: ast.expr) -> bool:
    """G.7's read: a bounded field read, ``msg.field`` taking only occurrence and repetition."""
    if lens._is_bounded_message_read(node) or lens._is_empty_fallback_read(node):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "field"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "msg"
        and len(node.args) == 1
        and _str_const(node.args[0])
        and all(kw.arg in _OCCURRENCE_KW and _is_literal(kw.value) for kw in node.keywords)
    )


def _lookup_params_ok(node: ast.expr, *, fhir: bool) -> bool:
    """G.7's lookup-params rule: a dict with literal keys and literal or read values."""
    if not isinstance(node, ast.Dict):
        return False
    for key, value in zip(node.keys, node.values, strict=True):
        if key is None or not _is_literal(key):
            return False
        if _is_literal(value) or _is_read(value):
            continue
        if (
            fhir
            and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "FhirToken"
            and len(value.args) == 2
            and not value.keywords
            and _is_literal(value.args[0])
            and _is_read(value.args[1])
        ):
            continue
        return False
    return True


def _is_code_set_binding(tree: ast.Module, name: str) -> bool:
    """A module-level ``NAME = code_set("<literal>")`` that nothing else in the module rebinds."""
    if lens._codeset_binding(tree, name) is None:
        return False
    stores = sum(
        1
        for sub in ast.walk(tree)
        if (isinstance(sub, ast.Name) and sub.id == name and isinstance(sub.ctx, ast.Store))
        or (isinstance(sub, ast.Global | ast.Nonlocal) and name in sub.names)
    )
    return stores == 1


# --- item 6: send and route rows -------------------------------------------------------------


def _send_calls(stmt: ast.stmt) -> list[ast.expr] | None:
    """Every element a send row delivers (Send and SetState calls), or None for a malformed one."""
    if isinstance(stmt, ast.Return):
        value = stmt.value
        if isinstance(value, ast.List | ast.Tuple):
            return list(value.elts)
        if value is not None:
            return [value]
        return None
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        call = stmt.value
        if isinstance(call.func, ast.Attribute) and call.args:
            return [call.args[0]]
    return None


def _literal_send(node: ast.expr) -> bool:
    """One literal destination, the message a plain name, no keywords: ``Send("OB", msg)``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Send"
        and len(node.args) == 2
        and _str_const(node.args[0])
        and isinstance(node.args[1], ast.Name)
        and not node.keywords
    )


def _send_wrapper_key(stmt: ast.stmt) -> str:
    """The statement around a send row's calls, with the calls blanked out."""
    if isinstance(stmt, ast.Return):
        if isinstance(stmt.value, ast.List | ast.Tuple):
            return f"return-{type(stmt.value).__name__}"
        return "return"
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        call = stmt.value
        func = call.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "append"
            and isinstance(func.value, ast.Name)
            and len(call.args) == 1
            and not call.keywords
        ):
            return f"append:{func.value.id}"
    return "other"


def _check_sends(b: _Element, h: _Element) -> list[str]:
    """FR-40 item 6 at the granularity of one ``Send``: matched at base by content, or fully literal.

    A ``Send`` call, not a row, is the unit because the fan-out conversion (ADR 0108) moves an
    existing ``Send`` verbatim from a ``return`` into a ``sends.append(...)``."""
    out: list[str] = []
    pool: Counter[str] = Counter()
    dynamic_at_base: Counter[str] = Counter()
    base_wrappers: Counter[str] = Counter(_send_wrapper_key(s) for s in b.sends)
    for stmt in b.sends:
        for call in _send_calls(stmt) or []:
            key = ast.dump(call)
            pool[key] += 1
            if not _literal_send(call):
                dynamic_at_base[key] += 1
    new_literal = False
    for stmt in h.sends:
        wrapper = _send_wrapper_key(stmt)
        if base_wrappers[wrapper] > 0:
            base_wrappers[wrapper] -= 1
        elif wrapper not in ("return", "return-List", f"append:{_ACCUMULATOR}"):
            out.append(f"a send row in a shape the lens never writes at line {stmt.lineno}")
        calls = _send_calls(stmt)
        if calls is None:
            out.append(f"a malformed send row at line {stmt.lineno}")
            continue
        for call in calls:
            key = ast.dump(call)
            if pool[key] > 0:
                pool[key] -= 1
                if key in dynamic_at_base:
                    dynamic_at_base[key] -= 1
                continue
            if _literal_send(call):
                new_literal = True
                continue
            out.append(f"a new or changed send that is not fully literal at line {stmt.lineno}")
    if new_literal and +dynamic_at_base:
        out.append("a send that was dynamic at base is gone and a literal one appeared")
    return out


def _literal_route(stmt: ast.Return) -> bool:
    value = stmt.value
    if value is None or (isinstance(value, ast.Constant) and value.value is None):
        return True  # unrouted
    if _str_const(value):
        return True
    if isinstance(value, ast.List | ast.Tuple):
        return all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in value.elts)
    return False


def _check_routes(b: _Element, h: _Element) -> list[str]:
    out: list[str] = []
    pool = Counter(ast.dump(s) for s in b.routes)
    dynamic_left = Counter(ast.dump(s) for s in b.routes if not _literal_route(s))
    new_literal = False
    for stmt in h.routes:
        key = ast.dump(stmt)
        if pool[key] > 0:
            pool[key] -= 1
            if key in dynamic_left:
                dynamic_left[key] -= 1
            continue
        if _literal_route(stmt):
            new_literal = True
            continue
        out.append(f"a new or changed route that is not literal at line {stmt.lineno}")
    if new_literal and +dynamic_left:
        out.append("a route that was dynamic at base is gone and a literal one appeared")
    return out
