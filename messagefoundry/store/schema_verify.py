# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Verify a live SQLite store's schema against the shape this code builds (BACKLOG #1720).

Every statement in the SQLite schema script is ``CREATE ... IF NOT EXISTS`` and every migration is an
additive ``ALTER ... ADD COLUMN`` behind an existence guard. Both SKIP an object that already exists
under the expected name, whatever its shape, so a table or index left by an incompatible version
survives ``open()`` untouched and the first statement that needs the missing column fails much later.
The measured case is the v0.3.2 ``search_presets`` table, whose ``owner`` column the current code knows
as ``owner_user_id``.

This module is the check that runs after the schema script and the migrations. It derives the EXPECTED
shape by running the same script and migrations on a scratch ``:memory:`` database and reading it back
through the same pragmas as the live one, so a new table, column or index is covered the moment it is
added. It never parses DDL text.

The rule is deliberately one-sided. A missing column, a missing index, or an index whose name matches
but whose columns, uniqueness or partial-ness differ refuses the open. An EXTRA column or index is
tolerated: a newer build or an operator's own index does not make the store unusable. There is no
rename and no in-place repair (engine ``CLAUDE.md`` section 0: there is nothing deployed to migrate),
so the remedy the refusal names is to recreate the store.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import aiosqlite

__all__ = [
    "IndexShape",
    "SchemaMismatchError",
    "SchemaShape",
    "read_schema_shape",
    "schema_differences",
    "verify_live_schema",
]

Migrate = Callable[[aiosqlite.Connection], Awaitable[None]]

_REMEDY = (
    "This store was created by an incompatible version and cannot be upgraded in place. Recreate it:"
    " stop the engine, move the database file and its -wal and -shm files aside, then start the"
    " engine to create a fresh store."
)

# Each pragma is read through its table-valued form, so one statement reads every table and the table
# names travel as a bound parameter rather than being spliced into SQL. Only tables the EXPECTED shape
# names are read: a virtual table whose module is not loaded here would make pragma_table_info raise.
_COLUMNS_SQL = (
    "SELECT m.name AS tbl, c.name AS col"
    " FROM sqlite_master AS m, pragma_table_info(m.name) AS c"
    " WHERE m.type = 'table' AND m.name IN (SELECT value FROM json_each(?))"
)
# Indexes are read from EVERY table, not just the expected ones, so an index whose expected name was
# taken on some other table is reported as living there instead of as merely missing.
_INDEXES_SQL = (
    "SELECT i.tbl_name AS tbl, i.name AS idx, il.[unique] AS uniq, il.origin AS origin,"
    " il.partial AS partial, ii.seqno AS seqno, ii.name AS col"
    " FROM sqlite_master AS i"
    " JOIN pragma_index_list(i.tbl_name) AS il ON il.name = i.name"
    " JOIN pragma_index_info(i.name) AS ii"
    " WHERE i.type = 'index'"
)
_TABLES_SQL = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"


class SchemaMismatchError(RuntimeError):
    """The live store's schema lacks something this code needs, so ``open()`` refuses it."""


@dataclass(frozen=True)
class IndexShape:
    """What an index covers and enforces: its table, its key columns in order, and two flags."""

    table: str
    columns: tuple[str | None, ...]  # None marks an expression column
    unique: bool
    partial: bool

    def describe(self) -> str:
        cols = ", ".join(c if c is not None else "<expr>" for c in self.columns)
        flags = [f for f, on in (("unique", self.unique), ("partial", self.partial)) if on]
        return f"on {self.table}({cols})" + (f" [{', '.join(flags)}]" if flags else "")


@dataclass(frozen=True)
class SchemaShape:
    """The comparable shape of a store: columns per table, named indexes, constraint indexes.

    Names are lower-cased because SQLite resolves table, column and index names case-insensitively.
    ``named_indexes`` holds the indexes a ``CREATE INDEX`` made, keyed by name. ``constraint_indexes``
    holds the automatic ones a ``UNIQUE`` or ``PRIMARY KEY`` constraint made. Their names are
    positional (``sqlite_autoindex_<table>_<n>``), so they are compared by shape, never by name.
    """

    columns: dict[str, frozenset[str]]
    named_indexes: dict[str, IndexShape]
    constraint_indexes: frozenset[IndexShape]


async def read_schema_shape(
    db: aiosqlite.Connection, tables: list[str] | None = None
) -> SchemaShape:
    """Read ``db``'s shape. ``tables`` limits the column read; ``None`` reads every ordinary table."""
    if tables is None:
        async with db.execute(_TABLES_SQL) as cur:
            tables = [str(r[0]) for r in await cur.fetchall()]
    columns: dict[str, set[str]] = {t.lower(): set() for t in tables}
    async with db.execute(_COLUMNS_SQL, (json.dumps(tables),)) as cur:
        for tbl, col in await cur.fetchall():
            columns[str(tbl).lower()].add(str(col).lower())
    # seqno orders the key columns; the join does not promise to return them in that order.
    raw: dict[str, tuple[str, bool, str, bool, dict[int, str | None]]] = {}
    async with db.execute(_INDEXES_SQL) as cur:
        for tbl, idx, uniq, origin, partial, seqno, col in await cur.fetchall():
            entry = raw.setdefault(
                str(idx).lower(), (str(tbl).lower(), bool(uniq), str(origin), bool(partial), {})
            )
            entry[4][int(seqno)] = None if col is None else str(col).lower()
    named: dict[str, IndexShape] = {}
    constraint: set[IndexShape] = set()
    for name, (tbl, uniq, origin, partial, cols) in raw.items():
        shape = IndexShape(tbl, tuple(cols[k] for k in sorted(cols)), uniq, partial)
        if origin == "c":
            named[name] = shape
        else:
            constraint.add(shape)
    return SchemaShape({t: frozenset(c) for t, c in columns.items()}, named, frozenset(constraint))


_expected_cache: dict[tuple[str, Migrate], SchemaShape] = {}


async def _expected_shape(schema: str, migrate: Migrate) -> SchemaShape:
    """Build ``schema`` plus ``migrate`` on a scratch in-memory database and read its shape.

    Once per process: the inputs are module constants, so every later open reuses the first answer.
    """
    key = (schema, migrate)
    cached = _expected_cache.get(key)
    if cached is not None:
        return cached
    async with aiosqlite.connect(":memory:") as scratch:
        scratch.row_factory = aiosqlite.Row  # the migrations read pragma rows by column name
        await scratch.executescript(schema)
        await migrate(scratch)
        await scratch.commit()
        shape = await read_schema_shape(scratch)
    _expected_cache[key] = shape
    return shape


def schema_differences(expected: SchemaShape, live: SchemaShape) -> list[str]:
    """Every way ``live`` falls short of ``expected``, one clause each. Extras are not listed."""
    problems: list[str] = []
    for table in sorted(expected.columns):
        have = live.columns.get(table, frozenset())
        if not have:
            problems.append(f"table {table!r} is missing")
            continue
        problems.extend(
            f"table {table!r} is missing column {col!r}"
            for col in sorted(expected.columns[table] - have)
        )
    for name in sorted(expected.named_indexes):
        want = expected.named_indexes[name]
        got = live.named_indexes.get(name)
        if got is None:
            problems.append(f"index {name!r} is missing (expected {want.describe()})")
        elif got != want:
            problems.append(f"index {name!r} is {got.describe()}, expected {want.describe()}")
    live_any = set(live.named_indexes.values()) | live.constraint_indexes
    problems.extend(
        f"table {want.table!r} is missing the constraint index {want.describe()}"
        for want in sorted(expected.constraint_indexes, key=lambda s: (s.table, repr(s.columns)))
        if want not in live_any
    )
    return problems


async def verify_live_schema(
    db: aiosqlite.Connection, *, schema: str, migrate: Migrate, path: object
) -> None:
    """Refuse a live store whose schema lacks anything ``schema`` plus ``migrate`` would build.

    Raises :class:`SchemaMismatchError` naming every table, column and index that differs, and the
    remedy. It runs after the migrations commit, so a refusal leaves their additive columns in place.
    That is harmless on a store the remedy recreates anyway.
    """
    expected = await _expected_shape(schema, migrate)
    live = await read_schema_shape(db, sorted(expected.columns))
    problems = schema_differences(expected, live)
    if problems:
        raise SchemaMismatchError(
            f"store {path} does not match the schema this version needs: "
            + "; ".join(problems)
            + ". "
            + _REMEDY
        )
