# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Structural gate for BACKLOG #1560 — the erased-body predicate reaches all SIX replay sites.

**Deliberately NOT env-gated, and that is the whole point of the file.** The behavioural parity tests
in ``tests/test_replay_purged_body.py`` need a live Postgres and a live SQL Server. On a developer
laptop they skip, and a fully skipped suite reports green — so two of the three backends would ship
this fix unverified by anything a builder can run. This file parses source, so it runs on every leg.

**Six sites, not two** (``replay`` and ``replay_dead`` on each of ``MessageStore``, ``PostgresStore``
and ``SqlServerStore``), and inside them more than six statements:

- ``replay``'s ``UPDATE queue SET status`` — the re-pend itself;
- ``replay``'s ``DELETE FROM delivered_keys`` — the re-send branch drops the idempotency-ledger entries
  of the rows it re-pends, so its scope must match the UPDATE's or it disarms the duplicate guard for a
  row that is not being re-delivered;
- ``replay_dead``'s ``SELECT DISTINCT message_id`` **and** its ``UPDATE``. All three backends compute
  the affected message set separately from the write. Guarding only the UPDATE flips the message from
  ``ERROR`` to ``ROUTED`` with nothing re-queued — a NEW false disposition, worse than the original
  defect, and one that ``rowcount`` alone will not reveal.

**Why this keys on the EMITTED SQL rather than on a name reference**, following the lesson recorded in
``tests/test_adr0157_fence_scope.py``: asking "does this method mention the constant?" stays green when
someone deletes the interpolation but leaves the assignment behind. The predicate is therefore looked
for in the reconstructed statement text, in the same SQL expression as the write it guards.

**Why AST and not a regex over raw source:** these statements are built from implicitly concatenated
string literals, f-strings splicing a ``{clause}``, and (on SQLite and SQL Server) a ``clause`` that
``replay_dead`` shares between its SELECT and its UPDATE. CPython folds implicit concatenation at parse
time, so reconstructing from the AST is what makes the whole statement visible at once.

The gate was made to fail on purpose before it was trusted: deleting the predicate from any one of the
guarded statements reds this file.
"""

from __future__ import annotations

import ast
import functools
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "store"

#: How the predicate reads once spliced into a statement. Each backend keeps it in a module constant
#: whose VALUE is this text, so the reconstruction below sees the literal wherever it is interpolated.
_PREDICATE = "payload <> '' OR body_ref IS NOT NULL"

#: ``(module, class, method)`` -> the SQL fragments that must each carry the predicate. A fragment is a
#: substring that identifies one statement inside the method.
_GUARDED: dict[tuple[str, str, str], tuple[str, ...]] = {
    ("store.py", "MessageStore", "replay"): (
        "UPDATE queue SET status",
        "DELETE FROM delivered_keys",
    ),
    ("store.py", "MessageStore", "replay_dead"): (
        "SELECT DISTINCT message_id",
        "UPDATE queue SET status",
    ),
    ("postgres.py", "PostgresStore", "replay"): (
        "UPDATE queue SET status",
        "DELETE FROM delivered_keys",
    ),
    ("postgres.py", "PostgresStore", "replay_dead"): (
        "SELECT DISTINCT message_id",
        "UPDATE queue SET status",
    ),
    ("sqlserver.py", "SqlServerStore", "replay"): (
        "UPDATE queue SET status",
        "DELETE FROM delivered_keys",
    ),
    ("sqlserver.py", "SqlServerStore", "replay_dead"): (
        "SELECT DISTINCT message_id",
        "UPDATE queue SET status",
    ),
}


def _sql_text(node: ast.AST) -> str | None:
    """Reconstruct a string-valued expression, resolving a spliced ``{name}`` to its module constant.

    Returns ``None`` for anything that is not a string expression, so the caller can pick *maximal*
    string expressions and skip their descendants — one statement is then counted once.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        out: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                out.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                out.append("{" + ast.unparse(value.value) + "}")
            else:  # pragma: no cover - defensive
                return None
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _sql_text(node.left)
        right = _sql_text(node.right)
        if left is None or right is None:
            return None
        return left + right
    return None


def _string_exprs(node: ast.AST, *, skip: frozenset[int] = frozenset()) -> list[str]:
    """Every MAXIMAL string expression under ``node`` (descendants of a match are not re-walked).

    ``skip`` holds ``id()`` values to ignore — the docstring, which quotes SQL fragments in prose and
    would otherwise register as an unguarded statement purely for describing one.
    """
    found: list[str] = []
    stack: list[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if id(current) in skip:
            continue
        text = _sql_text(current)
        if text is not None:
            found.append(text)
            continue  # maximal: its parts are already inside `text`
        stack.extend(ast.iter_child_nodes(current))
    return found


def _docstring_ids(fn: ast.AST) -> frozenset[int]:
    """The ``id()`` of the method's docstring expression, if it has one."""
    body = getattr(fn, "body", None)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return frozenset({id(body[0]), id(body[0].value)})
    return frozenset()


def _resolve(text: str, names: dict[str, str]) -> str:
    """Substitute each spliced ``{name}`` with its known text. Called once with the module constants
    and once with the method's locals. Anything unresolved is LEFT as ``{expr}``, so it reads as
    visibly not-the-predicate rather than quietly vanishing."""
    for name, value in names.items():
        text = text.replace("{" + name + "}", value)
    return text


def _module_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = "..."`` string assignments, so a spliced constant resolves."""
    out: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out[target.id] = node.value.value
    return out


def _local_strings(fn: ast.AST, constants: dict[str, str]) -> dict[str, str]:
    """Locals a spliced ``{name}`` can resolve to, in three shapes the backends actually use.

    ``clause = " AND ".join(where)`` (SQLite and SQL Server) is the one that matters: the predicate
    sits in the ``where`` LIST literal and reaches both of ``replay_dead``'s statements through that
    join, so a gate that cannot follow it reports a false miss on two of the six sites.
    """
    lists: dict[str, str] = {}
    out: dict[str, str] = {}
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not names:
            continue
        text = _sql_text(node.value)
        if text is not None:  # name = "..." / f"..." / "..." + "..."
            for name in names:
                out[name] = _resolve(text, constants)
        elif isinstance(node.value, ast.List):  # where = ["stage=?", ..., f"({CONST})"]
            parts = [_sql_text(e) or "" for e in node.value.elts]
            for name in names:
                lists[name] = _resolve(" AND ".join(parts), constants)
        elif (  # clause = " AND ".join(where)
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "join"
            and node.value.args
            and isinstance(node.value.args[0], ast.Name)
            and node.value.args[0].id in lists
        ):
            for name in names:
                out[name] = lists[node.value.args[0].id]
    return {**lists, **out}


def _method(tree: ast.Module, cls_name: str, method: str) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == cls_name:
            for item in node.body:
                if isinstance(item, ast.AsyncFunctionDef | ast.FunctionDef) and item.name == method:
                    return item
    raise AssertionError(f"{cls_name}.{method} not found")


@functools.cache
def _parsed(module: str) -> ast.Module:
    """One parse per backend module per run; each is thousands of lines and many cases read it."""
    return ast.parse((_ROOT / module).read_text(encoding="utf-8"))


def _statements(module: str, cls_name: str, method: str) -> tuple[dict[str, str], list[str]]:
    """The module's string constants and the method's reconstructed statements, splices resolved.

    A local string (e.g. ``clause``) may itself carry a predicate and then be spliced in, so locals are
    resolved after module constants."""
    tree = _parsed(module)
    constants = _module_constants(tree)
    fn = _method(tree, cls_name, method)
    locals_ = _local_strings(fn, constants)
    return constants, [
        _resolve(_resolve(s, constants), locals_)
        for s in _string_exprs(fn, skip=_docstring_ids(fn))
    ]


@pytest.mark.parametrize(("site", "fragments"), sorted(_GUARDED.items()))
def test_every_replay_statement_carries_the_erased_body_predicate(
    site: tuple[str, str, str], fragments: tuple[str, ...]
) -> None:
    """Each guarded statement's reconstructed SQL must contain the predicate text itself."""
    module, cls_name, method = site
    constants, statements = _statements(module, cls_name, method)
    assert any(_PREDICATE in v for v in constants.values()), (
        f"{module} defines no module constant carrying {_PREDICATE!r}; the backends must share one so"
        " this gate can resolve the splice"
    )

    for fragment in fragments:
        matching = [s for s in statements if fragment in s]
        assert matching, f"{cls_name}.{method}: no statement containing {fragment!r} was found"
        unguarded = [s for s in matching if _PREDICATE not in s]
        assert not unguarded, (
            f"{cls_name}.{method}: a {fragment!r} statement does not carry the erased-body predicate"
            f" ({_PREDICATE!r}) -- BACKLOG #1560. Offending SQL: {unguarded[0]!r}"
        )


def test_the_gate_can_see_an_unguarded_statement() -> None:
    """The positive control (SDS-3.8). A checker that finds nothing anywhere is indistinguishable from
    a clean tree, so prove the machinery reports a MISSING predicate before trusting its silence."""
    source = """
BODY_GUARD = "payload <> '' OR body_ref IS NOT NULL"

class Fake:
    async def replay(self):
        await x("UPDATE queue SET status=? WHERE message_id=?")
"""
    tree = ast.parse(source)
    constants = _module_constants(tree)
    fn = _method(tree, "Fake", "replay")
    statements = [_resolve(s, constants) for s in _string_exprs(fn)]
    matching = [s for s in statements if "UPDATE queue SET status" in s]
    assert matching, "the control's own statement must be discoverable"
    assert all(_PREDICATE not in s for s in matching), "the control must read as UNGUARDED"


def test_the_gate_resolves_a_spliced_constant() -> None:
    """The mirror control: a statement that DOES splice the constant must read as guarded, or the gate
    would red on correct code (a checker that falsely accuses is as useless as one that never sees)."""
    source = """
BODY_GUARD = "payload <> '' OR body_ref IS NOT NULL"

class Fake:
    async def replay(self):
        await x(f"UPDATE queue SET status=? WHERE message_id=? AND ({BODY_GUARD})")
"""
    tree = ast.parse(source)
    constants = _module_constants(tree)
    fn = _method(tree, "Fake", "replay")
    statements = [_resolve(s, constants) for s in _string_exprs(fn)]
    matching = [s for s in statements if "UPDATE queue SET status" in s]
    assert matching and all(_PREDICATE in s for s in matching)


# --- BACKLOG #1580: the pass-through completion-marker exclusion, same sites plus resend_to -------
#
# A pass-through completion marker is an already-terminal outbound row on an INBOUND-only lane. No
# delivery worker drains it, so every statement that turns an existing row back into outbound work
# must leave it alone: the same six replay statements as above, plus ``resend_to``'s source read on
# each backend, because a marker has no body and must never be chosen as a resend source. Same
# machinery, and the same reasons for reading emitted SQL rather than a name reference.

#: How the marker exclusion reads once spliced. Each backend keeps it in a plain module constant.
_MARKER_PREDICATE = (
    "NOT (stage = 'outbound' AND COALESCE(handler_name, '') = '@passthrough-marker')"
)

_MARKER_GUARDED: dict[tuple[str, str, str], tuple[str, ...]] = {
    **_GUARDED,
    ("store.py", "MessageStore", "resend_to"): ("LEFT JOIN shared_body",),
    ("postgres.py", "PostgresStore", "resend_to"): ("LEFT JOIN shared_body",),
    ("sqlserver.py", "SqlServerStore", "resend_to"): ("LEFT JOIN shared_body",),
}


@pytest.mark.parametrize(("site", "fragments"), sorted(_MARKER_GUARDED.items()))
def test_every_requeue_statement_excludes_passthrough_markers(
    site: tuple[str, str, str], fragments: tuple[str, ...]
) -> None:
    """Each statement that re-creates outbound work must carry the marker exclusion itself."""
    module, cls_name, method = site
    constants, statements = _statements(module, cls_name, method)
    assert any(_MARKER_PREDICATE in v for v in constants.values()), (
        f"{module} defines no module constant carrying {_MARKER_PREDICATE!r} (BACKLOG #1580)"
    )
    for fragment in fragments:
        matching = [s for s in statements if fragment in s]
        assert matching, f"{cls_name}.{method}: no statement containing {fragment!r} was found"
        unguarded = [s for s in matching if _MARKER_PREDICATE not in s]
        assert not unguarded, (
            f"{cls_name}.{method}: a {fragment!r} statement does not exclude pass-through completion"
            f" markers ({_MARKER_PREDICATE!r}) -- BACKLOG #1580. Offending SQL: {unguarded[0]!r}"
        )


@pytest.mark.parametrize(
    ("module", "cls_name"),
    [
        ("store.py", "MessageStore"),
        ("postgres.py", "PostgresStore"),
        ("sqlserver.py", "SqlServerStore"),
    ],
)
def test_the_stuck_count_does_not_exclude_markers(module: str, cls_name: str) -> None:
    """The deliberate exception, pinned so nobody "completes" the pattern. A depth-capped DEAD marker
    is a real failure: counting it keeps a parent in RECOVER mode, so replay never falls through to
    re-sending its DELIVERED siblings (the reasoning ``MessageStore.replay`` gives for #1560)."""
    _, statements = _statements(module, cls_name, "replay")
    counts = [s for s in statements if "COUNT(*)" in s]
    assert counts, f"{cls_name}.replay: the stuck count was not found"
    assert all(_MARKER_PREDICATE not in s for s in counts)


def test_the_marker_gate_can_see_an_unguarded_resend_source() -> None:
    """Positive control for the resend_to arm, which is new here: a source read with no exclusion
    must read as unguarded, or the arm's silence would prove nothing (SDS-3.8)."""
    source = """
class Fake:
    async def resend_to(self):
        src_where = "message_id=? AND stage=?"
        await x(
            "SELECT q.id FROM queue q LEFT JOIN shared_body sb ON sb.hash = q.body_ref"
            f" WHERE {src_where}"
        )
"""
    tree = ast.parse(source)
    fn = _method(tree, "Fake", "resend_to")
    statements = [_resolve(s, _local_strings(fn, {})) for s in _string_exprs(fn)]
    matching = [s for s in statements if "LEFT JOIN shared_body" in s]
    assert matching, "the control's own statement must be discoverable"
    assert all(_MARKER_PREDICATE not in s for s in matching), "the control must read as UNGUARDED"
