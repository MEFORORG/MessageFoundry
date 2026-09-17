# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`_writer_txn` is the ONLY place the SQLite store opens a writer transaction.

Seventeen writers used to hand-roll `async with self._lock: try: BEGIN ... except Exception:
rollback; raise`. That handler never fired on `asyncio.CancelledError`, which derives from
`BaseException`, so a cancelled writer left its transaction open for the next writer to inherit
(ADR 0159). They were all routed through `_writer_txn`, which unwinds on `BaseException`.

Nothing stops the eighteenth from hand-rolling it again. The commit message, the ADR and the
cancellation suite would all stay green, because a NEW writer with the old shape breaks no existing
test -- it just quietly reopens the hole. This is that guard, modelled on
`tests/test_fixture_outbox_reset.py`: a forbidden construct, a carve-out list pinned by count, and a
liveness receipt, so the test cannot pass by finding nothing.

`BEGIN` is not the only verb that matters. `SAVEPOINT` opens a NESTED transaction and `ROLLBACK TO`
unwinds one, and both carry the ADR 0159 shape exactly: a cancellation between the open and the
unwind leaves state the next writer inherits, and nested state is worse than an open BEGIN, because
the savepoint stack is depth-sensitive and nothing in SQLite names a savepoint's owner.

`RELEASE` is scanned for the OPPOSITE hazard, and the difference matters to anyone reasoning about
whether a site is safe. It is neither an open nor an unwind: it COMMITS a savepoint, together with
every savepoint opened after it, and at depth zero with no enclosing `BEGIN` it commits the whole
transaction. So a stray or mispaired `RELEASE` does not leak an open transaction -- it makes durable
what the caller still expected to be able to roll back. Both halves of the savepoint pairing are
live hazards, in opposite directions, so all three verbs are scanned on the same count pin.

`COMMIT` and bare `ROLLBACK` are deliberately NOT scanned. `MessageStore._read` ends its snapshot
with one of each (store.py:2650 and :2652), the ordinary whole-transaction close, which is the
behaviour this guard wants rather than the behaviour it bans. Matching either would red a clean tree
on the statements that keep it clean.

WHAT THIS GUARD IS AGAINST is an honest eighteenth writer reaching for the old shape, not an
attacker hiding a statement from a scanner. It reads SQL that is present in the source as text, so
a verb assembled out of pieces (`"SAVE" + "POINT x"`, `"%s x" % verb`, a name looked up at runtime)
is outside what it can see. `_txn_sites` pins the count of arguments it could not read, so a new
one of those arrives as a red rather than as silence.

Scope is `store/store.py` only, and deliberately. Postgres wraps writes in `async with
conn.transaction()` (asyncpg rolls back on any `BaseException`) and SQL Server has the
quarantine-and-reopen remedy ADR 0159 is actually about. Neither shares this shape, so sweeping them
would return a vacuous zero. Re-measured 2026-09-16 for the nested verbs specifically: `sqlserver.py`
and `postgres.py` hold zero SAVEPOINT / ROLLBACK TO / RELEASE, and no `SAVE TRANSACTION` either, so
widening the scope would still return one.
"""

from __future__ import annotations

import ast
import pathlib
from typing import NamedTuple

STORE = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "store" / "store.py"

#: The ONLY functions allowed to open a transaction, and how many `BEGIN` statements each may carry.
#: A flat ban is unsatisfiable -- something has to issue the BEGIN -- but "one or two are fine" is
#: how a third hides forever, so the COUNT is pinned: a new BEGIN inside these two moves the number
#: and reds, even though the function is exempt from the ban itself.
_ALLOWED: dict[str, tuple[int, str]] = {
    "_writer_txn": (
        1,
        "the writer-transaction helper itself -- unwinds on BaseException, under the lock, bounded",
    ),
    "MessageStore._read": (
        1,
        "the pooled READ snapshot on a borrowed connection, not self._db; it already unwinds on"
        " BaseException in its own `except BaseException: ROLLBACK` arm",
    ),
}

#: The same pin for the NESTED-transaction verbs, keyed `(qualified function name, verb)`.
#:
#: EMPTY IS THE MEASUREMENT, not an unfinished table. Scanned 2026-09-16 against `store.py` at
#: `ec32c96a8`: two BEGIN sites, and zero SAVEPOINT / ROLLBACK TO / RELEASE sites anywhere. So
#: unlike BEGIN -- where a flat ban is unsatisfiable because something has to issue it -- a flat ban
#: on these three IS satisfiable today, and an empty carve-out is the honest expression of it.
#:
#: It is a table rather than a bare ban so that the FIRST legitimate savepoint registers itself here
#: with a count and a reason, the way the BEGIN sites did, instead of arriving as a reason to delete
#: the check. A pending example: PR 1233 (BACKLOG #1632) contains a failing group-commit member in
#: its own savepoint and would add four entries -- `_GroupCommitter._run_member` SAVEPOINT 1 and
#: RELEASE 1, `_GroupCommitter._unwind_member` ROLLBACK TO 1 and RELEASE 1. Those four were measured
#: against `pull/1233/head` and confirmed independently by that PR's own session; the PR's prose
#: says `_flush`, which drives the members but holds none of the statements. Whichever of the two
#: lands second writes them; that is this guard working, not this guard being wrong.
_ALLOWED_NESTED: dict[tuple[str, str], tuple[int, str]] = {}

#: Order is not significant: `_verb_of` returns the LONGEST match, so a verb added here cannot be
#: shadowed by one that happens to be its prefix. A set rather than a tuple to say that outright,
#: because the alternative is an ordering invariant held by nothing but a comment. Why `COMMIT` and
#: bare `ROLLBACK` are absent is in the module docstring, once.
_VERBS: frozenset[str] = frozenset({"BEGIN", "SAVEPOINT", "ROLLBACK TO", "RELEASE"})

#: The aiosqlite calls that carry SQL. `executescript` is here because it is the ONE call that takes
#: several statements in a single argument, which makes it the easiest place to put a transaction
#: verb where a prefix check would never look. `executemany` is excluded: sqlite3 rejects a
#: transaction verb there, so scanning it would add a parameter with no reachable failure.
_CARRIERS: frozenset[str] = frozenset({"execute", "executescript"})


class _Site(NamedTuple):
    """One transaction-control statement, named so a fifth field cannot be added positionally."""

    verb: str
    owner: str
    line: int
    target: str


class _Scan(NamedTuple):
    """`_txn_sites`'s result: the sites, plus four receipts saying the walker really read."""

    sites: list[_Site]
    calls: int
    fstrings: int
    statements: int
    unreadable: int


class _Miscount(NamedTuple):
    """A carve-out whose statement count moved, reported structurally so controls need no parsing."""

    key: tuple[str, str]
    got: int
    expected: int
    reason: str


def _module_strings(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = "..."`` string constants.

    Exists for one call: `store.py:2542` runs `executescript(_SCHEMA)`, passing the 36 KB schema by
    NAME. Without resolving it, the single multi-statement call in the file is unreadable and the
    scan reports the easiest hiding place in the module as clean.
    """
    found: dict[str, str] = {}
    for stmt in tree.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            target, value = stmt.target, stmt.value
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            found[target.id] = value.value
    return found


def _sql_text(node: ast.expr | None, names: dict[str, str] | None = None) -> str | None:
    """Reconstruct a string-valued expression, marking interpolated parts as ``{expr}``.

    Lifted in shape from `tests/test_adr0157_fence_scope.py::_sql_text`, which is the established
    form in this directory for reading SQL out of an AST (a near-twin lives in
    `tests/test_replay_erased_body_scope.py`, and `tests/test_security_static.py::_static_str` adds
    the name resolution). Deliberately a third copy rather than an import of a sibling guard's
    private helper: `tests/_ast_sites.py` is where these belong, and consolidating the three is
    worth doing on its own rather than inside a change that has to stay narrow for a concurrent
    edit (see `_expectations`).

    Reading `ast.Constant` alone is not a small gap here. A savepoint name has to be interpolated,
    so real savepoint code is f-string or concatenation code: all four sites in PR 1233 are
    f-strings, and `execute("SAVEPOINT " + name)` is the obvious way to write it without one. A
    verb list widened without this would scan straight past every such statement and report a clean
    file. The bare-`ROLLBACK` exclusion is only safe because this reads whole expressions.

    Returns None when no text is recoverable, which is what `_txn_sites` counts as `unreadable`.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name) and names is not None:
        return names.get(node.id)
    if isinstance(node, ast.JoinedStr):
        out: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                out.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                out.append("{" + ast.unparse(value.value) + "}")
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _sql_text(node.left, names), _sql_text(node.right, names)
        if left is None and right is None:
            return None
        return (left if left is not None else "{" + ast.unparse(node.left) + "}") + (
            right if right is not None else "{" + ast.unparse(node.right) + "}"
        )
    return None


def _verb_of(text: str | None) -> str | None:
    """The transaction-control verb `text` opens with, or None.

    Whitespace is collapsed before matching so `ROLLBACK  TO` and a statement wrapped across lines
    both still read as `ROLLBACK TO`; the alternative is a guard evaded by pressing the space bar.
    The longest match wins, so `ROLLBACK TO` is never reported as some shorter verb.
    """
    if text is None:
        return None
    normalized = " ".join(text.split()).upper()
    matches = [verb for verb in _VERBS if normalized.startswith(verb)]
    return max(matches, key=len) if matches else None


def _statements(text: str, *, multi: bool) -> list[str]:
    """`text` as the statements it contains.

    `multi` is True only for `executescript`. A single-statement `execute` is NOT split: sqlite3
    rejects multiple statements there, so splitting would buy no coverage while inviting a false
    positive from a semicolon inside a quoted VALUE -- and a gate that falsely accuses costs more
    than one that misses, because the accusation lands on somebody who did nothing wrong.
    """
    if not multi:
        return [text]
    return [chunk for chunk in text.split(";") if chunk.strip()]


def _txn_sites(src: str) -> _Scan:
    """Every transaction-control statement in `src`, with four liveness receipts.

    The receipts are what separate "this file is clean" from "this walker read nothing": the number
    of SQL-carrying calls seen, how many were passed an f-string, how many statements were examined
    (the schema script alone is over a hundred), and how many arguments could not be read at all.
    The last is pinned rather than floored by the caller, because an unreadable argument is the
    exact shape an evasion takes.

    AST rather than grep on purpose: a docstring or comment saying the word BEGIN is prose, and this
    must not red on prose.
    """
    tree = ast.parse(src)
    names = _module_strings(tree)
    scopes: list[tuple[str, int, int]] = []

    class Scopes(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: list[str] = []

        def generic_visit(self, node: ast.AST) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.stack.append(node.name)
                if not isinstance(node, ast.ClassDef):
                    scopes.append(
                        (".".join(self.stack), node.lineno, node.end_lineno or node.lineno)
                    )
                super().generic_visit(node)
                self.stack.pop()
            else:
                super().generic_visit(node)

    Scopes().visit(tree)

    def owner(lineno: int) -> str:
        best: tuple[str, int, int] | None = None
        for name, start, end in scopes:
            if start <= lineno <= end and (best is None or start > best[1]):
                best = (name, start, end)
        return best[0] if best else "<module>"

    sites: list[_Site] = []
    calls = fstrings = statements = unreadable = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _CARRIERS:
            continue
        calls += 1
        first = node.args[0] if node.args else None
        if isinstance(first, ast.JoinedStr):
            fstrings += 1
        text = _sql_text(first, names)
        if text is None:
            unreadable += 1
            continue
        for chunk in _statements(text, multi=node.func.attr == "executescript"):
            statements += 1
            verb = _verb_of(chunk)
            if verb is not None:
                sites.append(
                    _Site(verb, owner(node.lineno), node.lineno, ast.unparse(node.func.value))
                )
    return _Scan(sites, calls, fstrings, statements, unreadable)


def _expectations() -> dict[tuple[str, str], tuple[int, str]]:
    """The two carve-out tables as one `(function, verb) -> (count, reason)` view.

    THE SPLIT IS TEMPORARY AND HAS AN EXPIRY. One table keyed `(function, verb)` is the simpler end
    state; `_ALLOWED` is left alone only because PR 1227 has live edits on its `MessageStore._read`
    entry, and re-keying the table would collide with them. **Merge the two tables and delete this
    helper once 1227 has landed** -- without that instruction the split looks like leftover shape
    and outlives its reason.

    One constraint while it stands, raised by 1227's own session: do not change the SHAPE of
    `_ALLOWED`'s values. If they stopped being `tuple[int, str]` here, git would still merge 1227's
    string-literal edit cleanly and the merged file would carry one entry in the old shape and the
    rest in the new one -- clean merge, runtime break, and neither branch's CI ever saw the
    combination.
    """
    expected = {(name, "BEGIN"): pin for name, pin in _ALLOWED.items()}
    expected.update(_ALLOWED_NESTED)
    return expected


def _audit(
    sites: list[_Site],
    expected: dict[tuple[str, str], tuple[int, str]],
) -> tuple[list[_Site], list[_Miscount]]:
    """Split `sites` against `expected` into (unlisted sites, carve-outs whose count moved).

    Returns structure, not prose, so the controls below assert on `.verb` and `.got` rather than
    reverse-engineering a message; rewording a failure string then cannot red a control.

    `expected` is a parameter rather than a read of `_expectations()` so the controls can drive this
    with synthetic tables. `_ALLOWED_NESTED` is empty today, so a module-global read would leave the
    counting arm exercised by exactly one data case, the two BEGIN carve-outs.
    """
    stray = [site for site in sites if (site.owner, site.verb) not in expected]
    miscounted = [
        _Miscount(key, got, count, reason)
        for key, (count, reason) in sorted(expected.items())
        if (got := sum(1 for s in sites if (s.owner, s.verb) == key)) != count
    ]
    return stray, miscounted


def test_only_writer_txn_and_the_read_snapshot_open_a_transaction() -> None:
    """Mutation: add `await self._db.execute("BEGIN")` to any method in store.py -- reds naming the
    method and line. Add a second one inside `_writer_txn` -- still reds, on the pinned count, which
    is the case a plain function-exemption list would have missed. Add
    `await self._db.execute(f"SAVEPOINT {name}")` anywhere -- reds on the nested verbs, which is the
    arm a BEGIN-only scan let through."""
    scan = _txn_sites(STORE.read_text(encoding="utf-8"))

    # Receipts: report what was EXAMINED. A walker that matched nothing would pass vacuously.
    # Measured at ec32c96a8: 356 carrying calls, 51 f-strings, 463 statements, 3 unreadable.
    assert scan.calls > 200, (
        f"liveness: only {scan.calls} SQL-carrying calls -- the walker is broken"
    )
    # Every savepoint statement interpolates its name, so the nested arm lives or dies on reading
    # f-strings, and a zero it reports is only evidence if this number is non-trivial.
    assert scan.fstrings > 30, (
        f'liveness: only {scan.fstrings} .execute(f"...") calls seen -- the f-string arm is not '
        f"reading this file, so any SAVEPOINT it fails to find proves nothing"
    )
    # The schema script is one call carrying 111 statements. If `_SCHEMA` ever stops resolving, this
    # collapses toward the call count and the multi-statement arm has gone blind without saying so.
    assert scan.statements > 400, (
        f"liveness: only {scan.statements} statements examined across {scan.calls} calls -- the "
        f"executescript arm is not resolving `_SCHEMA`, so the one multi-statement call is unread"
    )
    # PINNED, not floored: an unreadable argument is the exact shape an evasion takes, so a NEW one
    # has to be looked at. The three today are `cancel_queued`, `revoke_user_sessions` and
    # `delivery_latency_histogram`, each building a SELECT in a local variable. If you added a
    # fourth, confirm it carries no transaction verb and then move this number.
    assert scan.unreadable == 3, (
        f"{scan.unreadable} SQL arguments could not be read as text, expected 3. A new one is a new "
        f"blind spot in this guard: check it carries no transaction verb before moving the number."
    )

    stray, miscounted = _audit(scan.sites, _expectations())
    assert not stray, (
        f"scanned {scan.statements} statements across {scan.calls} SQL-carrying calls; these open "
        f"or manipulate a transaction outside `_writer_txn`, so a cancellation there would leave it "
        f"open for the next writer to inherit (ADR 0159):\n"
        + "\n".join(f"  {s.verb} in {s.owner} at store.py:{s.line} ({s.target})" for s in stray)
        + "\n\nIf the statement is deliberate, add it to `_ALLOWED` (BEGIN) or `_ALLOWED_NESTED` "
        "(SAVEPOINT / ROLLBACK TO / RELEASE) with its count and the reason it is safe."
    )
    assert not miscounted, (
        "a carve-out's statement count moved:\n"
        + "\n".join(
            f"  {m.key[0]} issues {m.got} {m.key[1]} statements, expected {m.expected}: {m.reason}"
            for m in miscounted
        )
        + "\n\nMore means a second transaction crept into a function exempt from the ban; fewer "
        "means the one that unwinds on BaseException was removed, and every writer behind it is "
        "back to leaking an open transaction on cancellation."
    )


def test_the_scanner_finds_a_hand_rolled_begin_and_ignores_prose() -> None:
    """Paired controls on the instrument, because a scanner that finds nothing anywhere would make
    the guard above pass forever. The POSITIVE arms plant the exact shapes this bans and require
    them to be found; the NEGATIVE arm plants the words in a docstring, a comment and statements
    that only look like them, and requires them NOT to be found."""
    scan = _txn_sites(
        "class S:\n"
        "    async def sneaky(self):\n"
        '        await self._db.execute("BEGIN")\n'
        '        await self._db.execute("INSERT INTO t VALUES (1)")\n'
    )
    assert [(s.verb, s.owner, s.target) for s in scan.sites] == [("BEGIN", "S.sneaky", "self._db")]
    assert (scan.calls, scan.fstrings, scan.unreadable) == (2, 0, 0)

    # The nested verbs, in the two shapes real savepoint code takes: the name is interpolated, by
    # f-string or by concatenation. A scan reading only `ast.Constant` reports this block clean.
    scan = _txn_sites(
        "class S:\n"
        "    async def nested(self):\n"
        '        await self._db.execute(f"SAVEPOINT {name}")\n'
        '        await self._db.execute("INSERT INTO t VALUES (1)")\n'
        '        await self._db.execute("ROLLBACK" + " TO " + name)\n'
        '        await self._db.execute(f"RELEASE {name}")\n'
    )
    assert [(s.verb, s.owner) for s in scan.sites] == [
        ("SAVEPOINT", "S.nested"),
        ("ROLLBACK TO", "S.nested"),
        ("RELEASE", "S.nested"),
    ]
    assert (scan.calls, scan.fstrings) == (4, 2)

    # A verb buried mid-script, reached through a module constant -- the `executescript(_SCHEMA)`
    # shape. Both halves have to work: resolving the name, and looking past the first statement.
    scan = _txn_sites(
        '_SCHEMA = "CREATE TABLE t (a);\\nSAVEPOINT sp1;\\nCREATE INDEX i ON t (a);"\n'
        "class S:\n"
        "    async def migrate(self):\n"
        "        await self._db.executescript(_SCHEMA)\n"
    )
    assert [(s.verb, s.owner) for s in scan.sites] == [("SAVEPOINT", "S.migrate")]
    assert (scan.calls, scan.statements, scan.unreadable) == (1, 3, 0)

    # ... and the same script passed to `execute`, which is NOT split, so only its first statement
    # is read. That asymmetry is deliberate (see `_statements`) and pinned so it stays deliberate.
    scan = _txn_sites(
        '_SCHEMA = "CREATE TABLE t (a);\\nSAVEPOINT sp1;"\n'
        "class S:\n"
        "    async def migrate(self):\n"
        "        await self._db.execute(_SCHEMA)\n"
    )
    assert scan.sites == []
    assert (scan.calls, scan.statements) == (1, 1)

    # An unreadable argument is counted, not silently dropped -- that count is pinned above.
    scan = _txn_sites(
        "class S:\n"
        "    async def dynamic(self):\n"
        '        sql = "SAVEPOINT sp1"\n'
        "        await self._db.execute(sql)\n"
    )
    assert scan.sites == []
    assert (scan.calls, scan.unreadable) == (1, 1)

    # The counting arm, on a populated table -- `_ALLOWED_NESTED` is empty today, so this is the
    # only place `_audit` sees a nested key at all.
    exact: dict[tuple[str, str], tuple[int, str]] = {
        ("S.nested", "SAVEPOINT"): (1, "control"),
        ("S.nested", "ROLLBACK TO"): (1, "control"),
        ("S.nested", "RELEASE"): (1, "control"),
    }
    nested = _txn_sites(
        "class S:\n"
        "    async def nested(self):\n"
        '        await self._db.execute(f"SAVEPOINT {name}")\n'
        '        await self._db.execute("ROLLBACK TO " + name)\n'
        '        await self._db.execute(f"RELEASE {name}")\n'
    ).sites
    assert _audit(nested, exact) == ([], [])
    stray, miscounted = _audit(nested, {("S.nested", "SAVEPOINT"): (1, "control")})
    assert [s.verb for s in stray] == ["ROLLBACK TO", "RELEASE"]
    assert miscounted == []
    _, miscounted = _audit(nested, {**exact, ("S.nested", "SAVEPOINT"): (2, "control")})
    assert [(m.key, m.got, m.expected) for m in miscounted] == [(("S.nested", "SAVEPOINT"), 1, 2)]

    # The join itself, which nothing else covers: `_ALLOWED_NESTED` is empty, so a typo in the
    # implied "BEGIN" key would turn both live carve-outs stray and only the main test would notice.
    assert _expectations() == {
        ("_writer_txn", "BEGIN"): _ALLOWED["_writer_txn"],
        ("MessageStore._read", "BEGIN"): _ALLOWED["MessageStore._read"],
    }

    scan = _txn_sites(
        "class S:\n"
        "    async def innocent(self):\n"
        '        """Runs inside a BEGIN opened by the caller, under its SAVEPOINT."""\n'
        "        # BEGIN is issued by _writer_txn, not here, and it does the ROLLBACK TO too\n"
        '        await self._db.execute("INSERT INTO begin_log VALUES (1)")\n'
        '        await self._db.execute("SELECT savepoint FROM release_log")\n'
        '        await self._db.execute("ROLLBACK")\n'
        '        await self._db.execute("COMMIT")\n'
        '        await self._db.executemany("SAVEPOINT sp1", [])\n'
    )
    assert scan.sites == []
    assert (scan.calls, scan.fstrings, scan.unreadable) == (4, 0, 0)
