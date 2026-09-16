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

Scope is `store/store.py` only, and deliberately. Postgres wraps writes in `async with
conn.transaction()` (asyncpg rolls back on any `BaseException`) and SQL Server has the
quarantine-and-reopen remedy ADR 0159 is actually about. Neither shares this shape, so sweeping them
would return a vacuous zero.
"""

from __future__ import annotations

import ast
import pathlib

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
        "the pooled READ snapshot on a borrowed connection, not self._db; the BEGIN's own await is"
        " inside the guarded region and the unwind goes through the shared `_unwind_txn`, shielded"
        " and bounded (BACKLOG #1635 -- the earlier `except BaseException: ROLLBACK` arm started"
        " AFTER the BEGIN and was itself cancellable, so it covered neither case)",
    ),
}


def _begin_sites(src: str) -> tuple[list[tuple[str, int, str]], int]:
    """Every `<x>.execute("BEGIN...")` call in ``src``, as (enclosing qualified name, line, target).

    AST rather than grep on purpose: a docstring or comment saying the word BEGIN is prose, and this
    must not red on prose. Returns the sites plus the total number of `.execute(...)` calls seen,
    which is the liveness receipt -- a walker that finds no calls at all would report a clean file.
    """
    tree = ast.parse(src)
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

    sites: list[tuple[str, int, str]] = []
    executes = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "execute":
            continue
        executes += 1
        first = node.args[0] if node.args else None
        if (
            isinstance(first, ast.Constant)
            and isinstance(first.value, str)
            and first.value.lstrip().upper().startswith("BEGIN")
        ):
            sites.append((owner(node.lineno), node.lineno, ast.unparse(node.func.value)))
    return sites, executes


def test_only_writer_txn_and_the_read_snapshot_open_a_transaction() -> None:
    """Mutation: add `await self._db.execute("BEGIN")` to any method in store.py -- reds naming the
    method and line. Add a second one inside `_writer_txn` -- still reds, on the pinned count, which
    is the case a plain function-exemption list would have missed."""
    src = STORE.read_text(encoding="utf-8")
    sites, executes = _begin_sites(src)

    # Liveness receipt: report what was EXAMINED. A walker that matched nothing would pass vacuously.
    assert executes > 200, (
        f"liveness: only {executes} .execute(...) calls seen -- the walker is broken"
    )

    stray = [
        f"  {name} at store.py:{line} ({target})"
        for name, line, target in sites
        if name not in _ALLOWED
    ]
    assert not stray, (
        f"scanned {executes} .execute(...) calls; these open a writer transaction outside "
        f"`_writer_txn`, so a cancellation there would leave it open for the next writer "
        f"(ADR 0159):\n" + "\n".join(stray)
    )
    for name, (expected, reason) in _ALLOWED.items():
        got = sum(1 for owner_, _, _ in sites if owner_ == name)
        assert got == expected, (
            f"{name} issues {got} BEGIN statements, expected {expected} ({reason}). More means a "
            f"second transaction crept into a function exempt from the ban; fewer means the one "
            f"that unwinds on BaseException was removed, and every writer behind it is back to "
            f"leaking an open transaction on cancellation."
        )


def test_the_scanner_finds_a_hand_rolled_begin_and_ignores_prose() -> None:
    """Paired controls on the instrument, because a scanner that finds nothing anywhere would make
    the guard above pass forever. The POSITIVE arm plants the exact shape this bans and requires it
    to be found; the NEGATIVE arm plants the word in a docstring, a comment and a non-BEGIN
    statement, and requires it NOT to be found."""
    positive = (
        "class S:\n"
        "    async def sneaky(self):\n"
        '        await self._db.execute("BEGIN")\n'
        '        await self._db.execute("INSERT INTO t VALUES (1)")\n'
    )
    sites, executes = _begin_sites(positive)
    assert [(n, t) for n, _, t in sites] == [("S.sneaky", "self._db")], sites
    assert executes == 2

    negative = (
        "class S:\n"
        "    async def innocent(self):\n"
        '        """Runs inside a BEGIN opened by the caller."""\n'
        "        # BEGIN is issued by _writer_txn, not here\n"
        '        await self._db.execute("INSERT INTO begin_log VALUES (1)")\n'
    )
    sites, executes = _begin_sites(negative)
    assert sites == [], sites
    assert executes == 1
