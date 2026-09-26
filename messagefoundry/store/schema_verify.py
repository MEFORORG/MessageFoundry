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
added. It never parses DDL text, so a partial index's WHERE predicate is compared only as the flag
``pragma_index_list`` reports, not as the predicate itself.

The rule is deliberately one-sided. The open refuses a missing table or column, an ``INTEGER PRIMARY
KEY`` that is no longer the table's row id, a missing index, or an index whose name matches but whose
table, key columns (with their order, collation and direction), uniqueness or partial flag differ. An
EXTRA column or index is tolerated: a newer build or an operator's own index does not make the store
unusable. There is no rename and no in-place repair (engine ``CLAUDE.md`` section 0: there is nothing
deployed to migrate), so the remedy the refusal names is to recreate the store.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

import aiosqlite

__all__ = [
    "IndexShape",
    "SchemaMismatchError",
    "SchemaShape",
    "read_schema_shape",
    "schema_differences",
    "verify_live_schema",
]

log = logging.getLogger(__name__)

Migrate = Callable[[aiosqlite.Connection], Awaitable[None]]

# Short and first in the message: the paths that print an uncaught error cut it at about 200
# characters, and the differences that follow it are the part an operator can afford to lose.
_REMEDY = (
    "is from an incompatible version; recreate it: move the file and its -wal and -shm files aside,"
    " then restart."
)

# Each pragma is read through its table-valued form, so one statement reads every table, and the
# table names travel as bound parameters rather than being spliced into SQL. Only tables the EXPECTED
# shape names are read for columns. The placeholder list is built from a count, never from a name.
_COLUMNS_SQL = (
    "SELECT m.name AS tbl, c.name AS col, c.type AS type, c.pk AS pk"
    " FROM sqlite_master AS m, pragma_table_info(m.name) AS c"
    " WHERE m.type = 'table' AND lower(m.name) IN ({marks})"
)
# Indexes are read from EVERY ordinary table, not just the expected ones, so an index whose expected
# name was taken on some other table is reported as living there instead of as merely missing. Driven
# from pragma_index_list rather than from sqlite_master's index rows, because a WITHOUT ROWID table's
# key index has no sqlite_master row. Virtual tables are skipped: a module not loaded here would make
# the pragma raise. index_xinfo rather than index_info: it carries each key column's collation and
# direction; key = 0 rows are the row id or auxiliary columns, not part of what the index enforces.
_INDEXES_SQL = (
    "SELECT m.name AS tbl, il.name AS idx, il.[unique] AS uniq, il.origin AS origin,"
    " il.partial AS partial, ix.seqno AS seqno, ix.name AS col, ix.[desc] AS dsc, ix.coll AS coll"
    " FROM sqlite_master AS m, pragma_index_list(m.name) AS il, pragma_index_xinfo(il.name) AS ix"
    " WHERE m.type = 'table' AND m.sql NOT LIKE 'CREATE VIRTUAL TABLE%' AND ix.key = 1"
)
_TABLES_SQL = (
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
)


class SchemaMismatchError(sqlite3.DatabaseError):
    """The live store's schema lacks something this code needs, so ``open()`` refuses it.

    A ``sqlite3.DatabaseError`` so the CLI's store-open handler reports it as "could not open" and
    exits 2, the code it keeps apart from a negative finding (BACKLOG #1670).
    """


@dataclass(frozen=True)
class IndexShape:
    """What an index covers and enforces: its table, its key columns in order, and two flags.

    A key column reads as its name, then ``COLLATE <name>`` when not BINARY, then ``DESC`` when
    descending; ``<expr>`` stands for an expression column.
    """

    table: str
    columns: tuple[str, ...]
    unique: bool
    partial: bool

    def describe(self) -> str:
        flags = [f for f, on in (("unique", self.unique), ("partial", self.partial)) if on]
        return f"on {self.table}({', '.join(self.columns)})" + (
            f" [{', '.join(flags)}]" if flags else ""
        )


@dataclass(frozen=True)
class SchemaShape:
    """The comparable shape of a store: columns per table, row ids, named and constraint indexes.

    Names are lower-cased because SQLite resolves table, column and index names case-insensitively.
    ``rowid_columns`` maps a table to its ``INTEGER PRIMARY KEY`` column, the one that gives new rows
    their id. ``named_indexes`` holds the indexes a ``CREATE INDEX`` made, keyed by name.
    ``constraint_indexes`` holds the automatic ones a ``UNIQUE`` or ``PRIMARY KEY`` constraint made.
    Their names are positional (``sqlite_autoindex_<table>_<n>``), so they are compared by shape,
    never by name. The mappings are read-only because one expected shape is shared by every open.
    """

    columns: Mapping[str, frozenset[str]]
    rowid_columns: Mapping[str, str]
    named_indexes: Mapping[str, IndexShape]
    constraint_indexes: frozenset[IndexShape]


def _key_column(col: object, desc: object, coll: object) -> str:
    text = "<expr>" if col is None else str(col).lower()
    if coll is not None and str(coll).upper() != "BINARY":
        text += f" COLLATE {str(coll).upper()}"
    return text + (" DESC" if desc else "")


async def read_schema_shape(
    db: aiosqlite.Connection, tables: list[str] | None = None
) -> SchemaShape:
    """Read ``db``'s shape. ``tables`` limits the column read; ``None`` reads every ordinary table."""
    if tables is None:
        async with db.execute(_TABLES_SQL) as cur:
            tables = [str(r[0]) for r in await cur.fetchall()]
    columns: dict[str, set[str]] = {t.lower(): set() for t in tables}
    pk_columns: dict[str, list[tuple[str, str]]] = {}
    marks = ", ".join("?" * len(tables)) or "NULL"  # `IN ()` is a syntax error
    async with db.execute(_COLUMNS_SQL.format(marks=marks), [t.lower() for t in tables]) as cur:
        for tbl, col, decl, pk in await cur.fetchall():
            table, name = str(tbl).lower(), str(col).lower()
            columns[table].add(name)
            if pk:
                pk_columns.setdefault(table, []).append((name, str(decl).upper()))
    # seqno orders the key columns; the join does not promise to return them in that order.
    raw: dict[str, tuple[str, bool, str, bool, dict[int, str]]] = {}
    async with db.execute(_INDEXES_SQL) as cur:
        for tbl, idx, uniq, origin, partial, seqno, col, dsc, coll in await cur.fetchall():
            entry = raw.setdefault(
                str(idx).lower(), (str(tbl).lower(), bool(uniq), str(origin), bool(partial), {})
            )
            entry[4][int(seqno)] = _key_column(col, dsc, coll)
    named: dict[str, IndexShape] = {}
    constraint: set[IndexShape] = set()
    key_indexed = {tbl for tbl, _u, origin, _p, _c in raw.values() if origin == "pk"}
    # A column is the row id only when it is the table's whole key, declared exactly INTEGER, and the
    # key has no index of its own. `INTEGER PRIMARY KEY DESC`, a WITHOUT ROWID table, "INT" and a
    # composite key all get an ordinary column plus an origin 'pk' index instead.
    rowid = {
        t: cols[0][0]
        for t, cols in pk_columns.items()
        if len(cols) == 1 and cols[0][1] == "INTEGER" and t not in key_indexed
    }
    for name, (tbl, uniq, origin, partial, cols) in raw.items():
        shape = IndexShape(tbl, tuple(cols[k] for k in sorted(cols)), uniq, partial)
        if origin == "c":
            named[name] = shape
        else:
            constraint.add(shape)
    return SchemaShape(
        MappingProxyType({t: frozenset(c) for t, c in columns.items()}),
        MappingProxyType(rowid),
        MappingProxyType(named),
        frozenset(constraint),
    )


_expected_cache: dict[tuple[str, Migrate], SchemaShape] = {}


async def _expected_shape(schema: str, migrate: Migrate) -> SchemaShape:
    """Build ``schema`` plus ``migrate`` on a scratch in-memory database and read its shape.

    Once per process, keyed on the two inputs. ``migrate`` also reads module constants such as the
    message-column migration table, which the key does not see; nothing changes those at run time.
    """
    key = (schema, migrate)
    cached = _expected_cache.get(key)
    if cached is not None:
        return cached
    # Imported here: store.py imports this module, and the helper is the #1670 rule that a closed
    # connection's non-daemon worker thread has actually gone before the caller moves on.
    from messagefoundry.store.store import _await_connection_worker_exit

    scratch = await aiosqlite.connect(":memory:")
    try:
        scratch.row_factory = aiosqlite.Row  # the migrations read pragma rows by column name
        await scratch.executescript(schema)
        await migrate(scratch)
        await scratch.commit()
        shape = await read_schema_shape(scratch)
    finally:
        try:
            await scratch.close()
            await _await_connection_worker_exit(scratch)
        except Exception:  # noqa: BLE001 -- cleanup must never mask the real failure
            log.warning("error closing the scratch schema database", exc_info=True)
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
        want_rowid = expected.rowid_columns.get(table)
        if want_rowid in have and live.rowid_columns.get(table) != want_rowid:
            problems.append(
                f"table {table!r} column {want_rowid!r} is not its INTEGER PRIMARY KEY,"
                " so new rows get no id"
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
        for want in sorted(expected.constraint_indexes, key=lambda s: (s.table, s.columns))
        if want not in live_any
    )
    return problems


async def verify_live_schema(
    db: aiosqlite.Connection, *, schema: str, migrate: Migrate, path: object
) -> None:
    """Refuse a live store whose schema lacks anything ``schema`` plus ``migrate`` would build.

    Raises :class:`SchemaMismatchError` with the remedy first, then every table, column and index
    that differs. The caller runs this inside the migration transaction, so a refusal rolls the
    migrations back and leaves the file as the old version wrote it, apart from the objects the
    schema script created, which are all new tables and indexes.
    """
    expected = await _expected_shape(schema, migrate)
    live = await read_schema_shape(db, sorted(expected.columns))
    problems = schema_differences(expected, live)
    if problems:
        raise SchemaMismatchError(
            f"store {path} {_REMEDY} Differences: " + "; ".join(problems) + "."
        )
