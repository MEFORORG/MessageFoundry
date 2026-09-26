# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every SQLite writer holds the writer lock through `_writer_guard` or `_writer_txn`, never bare.

Taken bare, the lock unwinds nothing, so a failure after a short writer's first DML leaves the
implicit transaction open for the next writer (BACKLOG #1803; the mechanism is in
`messagefoundry.store.store._writer_guard`'s docstring). Every writer was routed through the guard.

Nothing stops the next writer from taking the lock bare again, and no existing test would notice: a
new bare writer breaks nothing until something raises inside it. This pins the PROPERTY, not a
count. It reds on any `async with <x>._lock` in `store.py` outside a short allowlist of blocks that
issue no DML, and it checks that claim for each of them rather than taking the reason on trust.
Sibling of `tests/test_writer_txn_is_the_only_begin.py`, which pins the other half: that `BEGIN`
appears only inside `_writer_txn`.

WHAT THIS CANNOT SEE: a lock reached under another name (`lock = self._lock; async with lock:`), or
DML an allowlisted block reaches through a `self.` helper. It guards against an honest new writer
reaching for the old shape, not against evasion.
"""

from __future__ import annotations

import ast
import pathlib
import re
from typing import NamedTuple

from _ast_sites import callee_name

from tests.test_writer_txn_is_the_only_begin import _module_strings, _sql_text

STORE = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "store" / "store.py"

#: The ONLY blocks allowed to take the writer lock bare, keyed by qualified function name, with how
#: many bare blocks each holds and why it needs no guard. Each is checked below to issue no DML and
#: no commit: a bare COMMIT makes durable whatever another block abandoned, which is the same torn
#: write a bare DML block causes. Pinned by count so a second bare block in an exempt method reds.
_BARE_LOCK_ALLOWED: dict[str, tuple[int, str]] = {
    "MessageStore._read": (
        1,
        "the :memory: read fallback; yields the writer connection to reads, which never auto-begin",
    ),
    "MessageStore.list_fifo_lanes": (1, "lane discovery: SELECTs only, no commit needed"),
}

#: The context managers that make a lock block safe. A block under either is not a bare lock.
_SAFE_HELPERS: frozenset[str] = frozenset({"_writer_guard", "_writer_txn"})

#: DML that auto-begins a transaction under `isolation_level=''`. `REPLACE` covers the bare
#: `REPLACE INTO` spelling; `WITH` covers a CTE-led write.
_DML = re.compile(r"^\s*(INSERT|UPDATE|DELETE|REPLACE|WITH)\b", re.IGNORECASE)


class _Block(NamedTuple):
    """One `async with` over a writer lock, named so a field cannot be added positionally."""

    owner: str
    line: int
    kind: str  # "bare", or the safe helper's name
    guard_args: str  # the helper's arguments as source text; "" for a bare block
    dml: tuple[str, ...]  # DML statement heads found directly inside the block
    commits: bool  # the block calls `commit()` or `_commit()` itself


def _owners(tree: ast.Module) -> dict[int, str]:
    """Map each `async with` node's id to its innermost enclosing qualified function name."""
    found: dict[int, str] = {}

    def walk(node: ast.AST, stack: list[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                walk(child, [*stack, child.name])
            else:
                if isinstance(child, ast.AsyncWith):
                    found[id(child)] = ".".join(stack) or "<module>"
                walk(child, stack)

    walk(tree, [])
    return found


def _dml_in(node: ast.AST, names: dict[str, str]) -> tuple[str, ...]:
    """The first word of every DML statement a call inside `node` passes as readable SQL text.

    Reads the text with the sibling guard's `_sql_text`, so f-strings, `+` concatenation and
    module-level constants passed by name (`names`) are all seen."""
    heads: list[str] = []
    for call in ast.walk(node):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            continue
        if call.func.attr not in ("execute", "executemany", "executescript") or not call.args:
            continue
        text = _sql_text(call.args[0], names)
        if text is None:
            continue
        match = _DML.match(text)
        if match:
            heads.append(match.group(1).upper())
    return tuple(heads)


def _commits_in(node: ast.AST) -> bool:
    """Does a call inside `node` commit: `<x>.commit()` or `<x>._commit()`?"""
    return any(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in ("commit", "_commit")
        for call in ast.walk(node)
    )


def _lock_blocks(src: str) -> list[_Block]:
    """Every `async with` over a writer lock in `src`: bare `<x>._lock`, or a safe helper call."""
    tree = ast.parse(src)
    owners = _owners(tree)
    names = _module_strings(tree)
    blocks: list[_Block] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncWith):
            continue
        for item in node.items:
            expr = item.context_expr
            if isinstance(expr, ast.Attribute) and expr.attr == "_lock":
                kind, args = "bare", ""
            elif isinstance(expr, ast.Call) and callee_name(expr, bare_only=True) in _SAFE_HELPERS:
                kind, args = ast.unparse(expr.func), ", ".join(ast.unparse(a) for a in expr.args)
            else:
                continue
            blocks.append(
                _Block(
                    owner=owners[id(node)],
                    line=node.lineno,
                    kind=kind,
                    guard_args=args,
                    dml=_dml_in(node, names),
                    commits=_commits_in(node),
                )
            )
    return blocks


def _audit(
    blocks: list[_Block], allowed: dict[str, tuple[int, str]]
) -> tuple[list[_Block], list[tuple[str, int, int]], list[_Block]]:
    """Split the bare blocks into (not allowlisted, allowlist counts that moved, allowed-but-writing)."""
    bare = [b for b in blocks if b.kind == "bare"]
    stray = [b for b in bare if b.owner not in allowed]
    moved = [
        (owner, got, count)
        for owner, (count, _reason) in sorted(allowed.items())
        if (got := sum(1 for b in bare if b.owner == owner)) != count
    ]
    # A commit counts as writing: it turns another block's abandoned transaction into durable work.
    writing = [b for b in bare if b.owner in allowed and (b.dml or b.commits)]
    return stray, moved, writing


def test_every_writer_lock_block_is_guarded() -> None:
    """Mutation: turn any `async with _writer_guard(self._db, self._lock):` in store.py back into
    `async with self._lock:` -- reds naming that method. Add a second bare block to an allowlisted
    method -- reds on its count. Add an INSERT to an allowlisted block -- reds as a writer."""
    blocks = _lock_blocks(STORE.read_text(encoding="utf-8"))

    # Receipts: a walker that found nothing would pass vacuously. Measured 2026-09-26 on engine main
    # plus #1803: 79 guard blocks (70 with DML this reader can see), 26 _writer_txn blocks, 2 bare.
    guards = [b for b in blocks if b.kind == "_writer_guard"]
    txns = [b for b in blocks if b.kind == "_writer_txn"]
    assert len(guards) > 60, f"liveness: only {len(guards)} _writer_guard blocks seen"
    assert len(txns) > 15, f"liveness: only {len(txns)} _writer_txn blocks seen"
    assert sum(1 for b in guards if b.dml) > 50, "liveness: the DML reader sees no guarded writes"

    stray, moved, writing = _audit(blocks, _BARE_LOCK_ALLOWED)
    assert not stray, (
        "these take the SQLite writer lock bare, so a failure after their first DML would leave "
        "the implicit transaction open for the next writer to fail on or commit (BACKLOG #1803):\n"
        + "\n".join(f"  {b.owner} at store.py:{b.line}" for b in stray)
        + "\n\nUse `async with _writer_guard(self._db, self._lock):`. If the block truly issues no "
        "DML, add it to `_BARE_LOCK_ALLOWED` with its count and the reason."
    )
    assert not moved, (
        "an allowlisted method's bare-lock count moved:\n"
        + "\n".join(f"  {o} holds {g} bare blocks, expected {c}" for o, g, c in moved)
        + "\n\nMore means a new bare block hid inside an exempt method; zero means the entry is "
        "stale and should be deleted."
    )
    assert not writing, (
        "an allowlisted bare block issues DML or commits, so its reason no longer holds:\n"
        + "\n".join(
            f"  {b.owner} at store.py:{b.line}: {', '.join(b.dml) or 'commit'}" for b in writing
        )
    )
    wrong_args = [b for b in guards if b.guard_args != "self._db, self._lock"]
    assert not wrong_args, (
        "a guard over some other connection or lock protects nothing here:\n"
        + "\n".join(f"  {b.owner} at store.py:{b.line}: ({b.guard_args})" for b in wrong_args)
    )


def test_the_scanner_finds_a_bare_writer_and_passes_a_guarded_one() -> None:
    """Paired controls on the instrument: a scanner that finds nothing would pass forever."""
    blocks = _lock_blocks(
        "class MessageStore:\n"
        "    async def bare_writer(self):\n"
        "        async with self._lock:\n"
        '            await self._db.execute("UPDATE users SET x=1")\n'
        "            await self._commit()\n"
        "    async def guarded(self):\n"
        "        async with _writer_guard(self._db, self._lock):\n"
        '            await self._db.execute(f"DELETE FROM t WHERE id IN ({marks})")\n'
        "    async def reader(self):\n"
        "        async with self._lock:\n"
        '            await self._db.execute("SELECT 1")\n'
        "    async def txn(self):\n"
        "        async with _writer_txn(self._db, self._lock):\n"
        "            pass\n"
        "    async def unrelated(self):\n"
        "        async with self._other:\n"
        "            pass\n"
    )
    assert [(b.owner, b.kind, b.dml) for b in blocks] == [
        ("MessageStore.bare_writer", "bare", ("UPDATE",)),
        ("MessageStore.guarded", "_writer_guard", ("DELETE",)),
        ("MessageStore.reader", "bare", ()),
        ("MessageStore.txn", "_writer_txn", ()),
    ]
    allowed = {"MessageStore.reader": (1, "control")}
    stray, moved, writing = _audit(blocks, allowed)
    assert [b.owner for b in stray] == ["MessageStore.bare_writer"]
    assert moved == [] and writing == []

    # The count arm, and the stale-entry arm (an allowlisted method holding no bare block).
    _, moved, _ = _audit(blocks, {**allowed, "MessageStore.gone": (1, "control")})
    assert moved == [("MessageStore.gone", 0, 1)]
    # The "reason no longer holds" arm: an allowlisted block that writes.
    _, _, writing = _audit(blocks, {"MessageStore.bare_writer": (1, "control")})
    assert [b.owner for b in writing] == ["MessageStore.bare_writer"]

    # The commit arm: a bare block with no DML that still commits is writing too.
    committer = _lock_blocks(
        "class MessageStore:\n"
        "    async def checkpoint(self):\n"
        "        async with self._lock:\n"
        "            await self._commit()\n"
        '            await self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")\n'
    )
    assert [(b.dml, b.commits) for b in committer] == [((), True)]
    _, _, writing = _audit(committer, {"MessageStore.checkpoint": (1, "control")})
    assert [b.owner for b in writing] == ["MessageStore.checkpoint"]
