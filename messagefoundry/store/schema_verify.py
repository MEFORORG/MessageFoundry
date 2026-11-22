# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Verify a live SQLite store's schema against the shape this code builds (BACKLOG #1720).

Every statement in the SQLite schema script is ``CREATE ... IF NOT EXISTS`` and every migration is an
additive ``ALTER ... ADD COLUMN`` behind an existence guard. Both SKIP an object that already exists
under the expected name, whatever its shape, so a table or index left by an incompatible version
survives ``open()`` untouched and the first statement that needs the missing column fails much later.
The measured case was the v0.3.2 ``search_presets`` table, whose ``owner`` column the current code knows
as ``owner_user_id``; ``_migrate`` now moves that one table in place (BACKLOG #1909).

This module is the check that runs after the schema script and the migrations. It derives the EXPECTED
shape by running the same script and migrations on a scratch ``:memory:`` database and reading it back
through the same pragmas as the live one, so a new table, column or index is covered the moment it is
added. It never parses DDL text, so a partial index's WHERE predicate is compared only as the flag
``pragma_index_list`` reports, not as the predicate itself.

The rule is deliberately one-sided. The open refuses a missing table or column, an ``INTEGER PRIMARY
KEY`` that is no longer the table's row id, a missing index, or an index whose name matches but whose
table, key columns (with their order, collation and direction), uniqueness or partial flag differ. An
EXTRA column or index is tolerated: a newer build or an operator's own index does not make the store
unusable. This check renames and repairs nothing, so the remedy the refusal names is to recreate the
store. Any in-place move, such as the v0.3.2 preset table (BACKLOG #1909), is a ``_migrate`` step
that runs before this check.
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
    "is_schema_step_error",
    "live_schema_differences",
    "read_schema_shape",
    "run_schema_step",
    "schema_differences",
    "verify_live_schema",
]

log = logging.getLogger(__name__)

Migrate = Callable[[aiosqlite.Connection], Awaitable[None]]

# Short and first in the message: the paths that print an uncaught error cut it at 200 characters
# (redaction.safe_exc), and the differences that follow it are the part an operator can afford to lose.
_REMEDY = (
    "is from an incompatible version; recreate it: move the file and its -wal and -shm files aside,"
    " then restart."
)
# A store that seals under the DEK ITSELF must not be recreated under the key it already uses. Since
# ADR 0196 that is only the frozen v1 writer ([store].aad_bind = false). The cell-bound writer seals
# under a data sub-key derived from a salt the store mints when it is created, so a recreated store is
# a new key by construction and gets the plain remedy: keeping the key is then safe, and is what the
# moved file, uploads and backups need. For the v1 writer the per-key AES-GCM invocation count
# (cipher_meta, ASVS 11.3.4) is keyed on the DEK and lives in the store file, so a fresh file under the
# same key starts the count at zero: the reset gcm_bound.py refuses to offer. A new key has no count by
# construction. The DEK's key-age stamp (secret_rotation_meta) also lives in the file and restarts on
# EITHER writer; ADR 0196 accepts that as a floor, and docs/PHI.md records its cost. The new-key
# instruction leads, so a long store path cannot push it past the 200-character cut. The commands come next,
# ahead of the differences: on a cut path the differences are the part to lose. `gen-key` and
# `protect-key --generate` are the commands the serve no-key refusal names; `rotate-key` is not one,
# because it re-encrypts an existing store and a fresh store has nothing to re-encrypt.
_REMEDY_KEYED = (
    "is from an incompatible version: set a NEW store key, then move it and its -wal/-shm aside and"
    " restart."
)
_KEYED_DETAIL = (
    " Make the key with `messagefoundry gen-key`, `messagefoundry protect-key --generate`, or your"
    " key provider. Keep the old key in MEFOR_STORE_ENCRYPTION_KEYS_RETIRED: the moved file, uploads"
    " and backups still need it. With [store].aad_bind = false the store seals under the key itself,"
    " so restarting under the old key would zero its AES-GCM use count, which lives in the store. If"
    " you set [secret_rotation].store_key_last_rotated, update it."
)
# The ALTER re-check names an object other than the altered table that fails to parse as
# "error in <kind> <name>", then ": " or a suffix, at least " after rename" and " after drop column"
# (measured on SQLite 3.50.4). Both start " after ", and _foreign_objects' ranks assume every
# suffix does. Only views and triggers get the drop remedy (see _ORDINARY_TABLE for why they are
# another tool's); SQLite uses the same form for a table or an index, which may be this build's own.
# Dropping a view or a trigger removes no row, so that remedy keeps the store and its key.
_FOREIGN_OBJECTS_SQL = "SELECT type, name FROM sqlite_master WHERE type IN ('view', 'trigger')"

# The reads below skip a table whose stored SQL is LIKE 'CREATE VIRTUAL TABLE%', because a pragma
# on a virtual table whose module is not loaded here can raise "no such module" (BACKLOG #6719).
# The store builds none, and a test pins that, so an expected name held by a virtual table reads
# as a missing table and is refused rather than skipped.
# THIS BUILD CREATES NO VIRTUAL TABLE, NO VIEW AND NO TRIGGER, which
# tests/test_schema_verify_6719_6720.py pins; the other notes in this module rely on that and point
# here.
_ORDINARY_TABLE = "m.type = 'table' AND m.sql NOT LIKE 'CREATE VIRTUAL TABLE%'"
# Each pragma is read through its table-valued form, so one statement reads every table, and the
# table names travel as bound parameters rather than being spliced into SQL. Only tables the EXPECTED
# shape names are read for columns. The placeholder list is built from a count, never from a name.
_COLUMNS_SQL = (
    "SELECT m.name AS tbl, c.name AS col, c.type AS type, c.pk AS pk"
    " FROM sqlite_master AS m, pragma_table_info(m.name) AS c"
    " WHERE " + _ORDINARY_TABLE + " AND lower(m.name) IN ({marks})"
)
# Indexes are read from EVERY ordinary table, not just the expected ones, so an index whose expected
# name was taken on some other table is reported as living there instead of as merely missing. Driven
# from pragma_index_list rather than from sqlite_master's index rows, because a WITHOUT ROWID table's
# key index has no sqlite_master row. index_xinfo rather than index_info: it carries each key column's
# collation and direction; key = 0 rows are the row id or auxiliary columns, not part of what the index
# enforces.
_INDEXES_SQL = (
    "SELECT m.name AS tbl, il.name AS idx, il.[unique] AS uniq, il.origin AS origin,"
    " il.partial AS partial, ix.seqno AS seqno, ix.name AS col, ix.[desc] AS dsc, ix.coll AS coll"
    " FROM sqlite_master AS m, pragma_index_list(m.name) AS il, pragma_index_xinfo(il.name) AS ix"
    f" WHERE {_ORDINARY_TABLE} AND ix.key = 1"
)
_SALT_TABLE_SQL = (
    "SELECT EXISTS (SELECT 1 FROM sqlite_master AS m"
    " WHERE " + _ORDINARY_TABLE + " AND lower(m.name) = 'store_salt')"
)
_TABLES_SQL = (
    "SELECT m.name FROM sqlite_master AS m"
    f" WHERE {_ORDINARY_TABLE} AND m.name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
)


class SchemaMismatchError(sqlite3.DatabaseError):
    """The live store's schema lacks something this code needs, so ``open()`` refuses it.

    A ``sqlite3.DatabaseError`` so the CLI's store-open handler reports it as "could not open" and
    exits 2, the code it keeps apart from a negative finding (BACKLOG #1670).

    ``differences`` lists what the check found missing, one clause each. It is empty when the schema
    script, a migration or this check's own read failed (BACKLOG #2101, #6720), and then ``cause``
    holds that failure's text.
    Both are kept apart from the message so a caller whose remedy differs, such as a restore-verify
    of an old backup, can word its own refusal without parsing this one.
    """

    def __init__(
        self, message: str, *, differences: tuple[str, ...] = (), cause: str | None = None
    ) -> None:
        super().__init__(message)
        self.differences = differences
        self.cause = cause


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


async def live_schema_differences(
    db: aiosqlite.Connection, *, schema: str, migrate: Migrate
) -> list[str]:
    """Every way ``db`` falls short of what ``schema`` plus ``migrate`` would build. Reads only.

    The read-only open (BACKLOG #1780) runs this without running the schema script or the
    migrations first, so an older store that only needs migrating is reported short here too."""
    expected = await _expected_shape(schema, migrate)
    live = await read_schema_shape(db, sorted(expected.columns))
    return schema_differences(expected, live)


def _remedy(counts_under_dek: bool) -> str:
    return _REMEDY_KEYED + _KEYED_DETAIL if counts_under_dek else _REMEDY


async def verify_live_schema(
    db: aiosqlite.Connection,
    *,
    schema: str,
    migrate: Migrate,
    path: object,
    counts_under_dek: bool | None,
) -> None:
    """Refuse a live store whose schema lacks anything ``schema`` plus ``migrate`` would build.

    Raises :class:`SchemaMismatchError` with the remedy first, then every table, column and index
    that differs. The caller runs this inside the migration transaction, so a refusal rolls the
    migrations back and leaves the file as the old version wrote it, apart from the objects the
    schema script created, which are all new tables and indexes.

    ``counts_under_dek`` picks the remedy: true when this process runs a local AES-GCM key and seals
    under the DEK itself (the frozen v1 writer), the one case where recreating the store under the
    same key resets its count (ADR 0196); false when it runs a local key that seals under a store
    sub-key. ``None`` means this process has no local key, and only then is the file asked: one that
    holds a count but no store salt was last written under the DEK, so an operator shell without the
    service's key still gets the new-key remedy. A process that HAS a key is never overruled by the
    file, because a restored cell-bound store also has counts and no salt row until its first open.

    A read of the live store that fails on its shape is refused the same way, through
    :func:`run_schema_step` (BACKLOG #6720): a virtual table whose stored SQL the
    ``_ORDINARY_TABLE`` predicate does not recognise, held under an expected name, raises "no such
    module" from the column read rather than reading as a difference. The expected shape is built
    outside that, so a failure of this build's own script or migrations keeps its own error.
    """
    expected = await _expected_shape(schema, migrate)
    live = await run_schema_step(
        db,
        read_schema_shape(db, sorted(expected.columns)),
        path=path,
        counts_under_dek=counts_under_dek,
    )
    problems = schema_differences(expected, live)
    if problems:
        if counts_under_dek is None:
            counts_under_dek = await _counts_under_a_dek(db)
        raise SchemaMismatchError(
            f"store {path} {_remedy(counts_under_dek)} Differences: " + "; ".join(problems) + ".",
            differences=tuple(problems),
        )


#: The SQLite messages that name an existing object's shape. A syntax error in this build's own
#: DDL, or a statement the local SQLite is too old for, is also SQLITE_ERROR, and it is not fixed
#: by recreating the store, so the code alone is not enough. An expected name held by an object of
#: another kind is not "already exists": SQLite names the kind, or refuses the index or ALTER the
#: script or a migration then runs on it (BACKLOG #6720; the texts are measured in
#: tests/test_schema_verify_6719_6720.py). "no such module" names a virtual table in the file,
#: which is never this build's own (see _ORDINARY_TABLE).
_SHAPE_MESSAGES = (
    "no such column",
    "no such table",
    "has no column named",
    "duplicate column name",
    "already exists",
    "there is already an index named",
    "there is already a table named",
    "views may not be indexed",
    "virtual tables may not be indexed",
    "Cannot add a column to a view",
    "virtual tables may not be altered",
    "because it is a view",
    "use DROP VIEW to delete view",
    "no such module",
)


def is_schema_step_error(exc: BaseException) -> bool:
    """Whether ``exc``, raised by the schema script, a migration or the verify's read of the live
    store, says the store's shape is wrong.

    Two tests, both needed. The code must be SQLite's generic ``SQLITE_ERROR``: a busy or locked
    file, a read-only file, an I/O error, a full disk and a corrupt file each carry their own primary
    code. And the message must name a missing or clashing table, column or index, or a virtual
    table's module, because a syntax error is ``SQLITE_ERROR`` too. A missing module is always an
    object some other tool left in the file (see ``_ORDINARY_TABLE``, BACKLOG #6719). None of the
    others is fixed by recreating the store, so each keeps its own error rather than getting this
    remedy (BACKLOG #2101)."""
    code = getattr(exc, "sqlite_errorcode", None)
    return (
        isinstance(exc, sqlite3.OperationalError)
        and isinstance(code, int)
        and code & 0xFF == sqlite3.SQLITE_ERROR
        and any(m in str(exc) for m in _SHAPE_MESSAGES)
    )


async def run_schema_step[T](
    db: aiosqlite.Connection,
    step: Awaitable[T],
    *,
    path: object,
    counts_under_dek: bool | None,
) -> T:
    """Await the schema script, the migrations or the verify's read of the live store, turning a
    shape failure into a refusal, and return what the step returned.

    A failure :func:`is_schema_step_error` accepts is raised as :class:`SchemaMismatchError`, from
    the original so the driver's text stays in the chain (BACKLOG #2101). It carries the remedy a
    verify refusal carries, chosen the same way: a statement that fails on an existing object's
    shape is the same incompatible version the verify reports, found one step earlier. Any other
    failure propagates unchanged.

    One shape failure gets another remedy: SQLite's re-check of the schema after an ``ALTER``
    names the view or trigger it could not parse, as in "error in view V: no such module". That
    object is another tool's (see ``_ORDINARY_TABLE``), and dropping it lets the migration run past
    it (BACKLOG #6719). Where the text fits more than one such object, the remedy names each one
    (see :func:`_foreign_objects`). A view under a name this build creates is not such an object:
    it holds the place of a table or index, which is the incompatible store the plain remedy names."""
    try:
        return await step
    except Exception as exc:
        if not is_schema_step_error(exc):
            raise
        cause = str(exc)
        foreign = await _foreign_objects(db, cause)
        if len(foreign) == 1:
            ((kind, name),) = foreign
            # The instruction leads and the name follows it, so the 200-character cut keeps it.
            raise SchemaMismatchError(
                f"store {path}: drop the {kind} {name!r}, which this build did not create and which"
                f" stops its upgrade, then restart. The schema step failed: {cause}.",
                cause=cause,
            ) from exc
        if foreign:
            # The text cannot tell these apart, so the remedy names them all rather than tell the
            # operator to drop one that may be healthy. The instruction leads and the names follow
            # it, so the 200-character cut keeps the instruction however long the names are.
            listed = [f"the {kind} {name!r}" for kind, name in foreign]
            names = f"{', '.join(listed[:-1])} and {listed[-1]}"
            raise SchemaMismatchError(
                f"store {path}: drop whichever of these stops its upgrade, then restart: {names}."
                f" The error fits each name, and this build created none of them. The schema step"
                f" failed: {cause}.",
                cause=cause,
            ) from exc
        if counts_under_dek is None:
            counts_under_dek = await _counts_under_a_dek(db)
        raise SchemaMismatchError(
            f"store {path} {_remedy(counts_under_dek)} The schema step failed: {cause}.",
            cause=cause,
        ) from exc


async def _foreign_objects(db: aiosqlite.Connection, cause: str) -> tuple[tuple[str, str], ...]:
    """The kind and name of each of another tool's views and triggers that ``cause`` may name,
    sorted, else empty.

    The name is matched against the live file's views and triggers, never cut out of the text: the
    text may add a suffix after the name, and a quoted name may hold a colon. A SQLite error while
    telling falls back to empty, the plain remedy.

    Several names can fit one text (the forms are in the note above ``_FOREIGN_OBJECTS_SQL``):
    ``vv`` and ``vv after`` both fit "error in view vv after rename: ...". A name whose remainder
    starts with ": " or with " after " ranks first, and any other name last. Every name of the first
    rank is returned, since no rule over the text can pick among them: SQLite writes "error in view
    vv after drop column: ..." when ``vv`` breaks under the change, and the same text when a view
    named ``vv after drop column`` was broken already. With ``vv`` and ``vv: no such column``,
    ``vv``'s own "error in view vv: no such column: c" fits both too. So where names collide like
    this the ambiguity remains, and the remedy names each candidate, a healthy one among them. With
    no first-rank name, the longest last-rank name is the one returned.

    The colon and " after " share a rank because a quoted name may hold either: with ``vv`` and
    ``vv: x``, "error in view vv: x after rename: ..." must not name ``vv`` alone. Where any name
    returned is a view under a name this build creates, the result is empty: that view holds the
    place of a table or index, so the store is the incompatible one the plain remedy names, whichever
    candidate stopped the change (see :func:`run_schema_step`).

    Preparing each candidate against the live file is not used to settle a tie. A view that only
    the change broke prepares as cleanly as a healthy one, since the failed ``ALTER`` is rolled
    back. A failed prepare could rule out only the other reading, an object broken already, and
    that rests on SQLite writing no suffix for an object it found broken before the change, which
    this module has not measured for every ``ALTER``; a wrong ruling-out would name a healthy object
    alone. A trigger also has no read that runs its body without a write."""
    try:
        async with db.execute(_FOREIGN_OBJECTS_SQL) as cur:
            objects = [(str(kind), str(name)) for kind, name in await cur.fetchall()]
        first: list[tuple[str, str]] = []
        last: list[tuple[str, str]] = []
        for kind, name in objects:
            rest = cause.removeprefix(f"error in {kind} {name}")
            if rest != cause and rest[:1] in (":", " "):
                exact = rest.startswith((": ", " after "))
                (first if exact else last).append((kind, name))
        named = first or ([max(last, key=lambda o: len(o[1]))] if last else [])
        if not named:
            return ()
        views = [name.lower() for kind, name in named if kind == "view"]
        # Only a view can hold an expected name's place, so a trigger needs no scratch build.
        if views and not (await _names_this_build_creates()).isdisjoint(views):
            return ()
    except sqlite3.Error as exc:
        log.warning("could not read the views and triggers to pick the schema remedy: %s", exc)
        return ()
    return tuple(sorted(named))


async def _names_this_build_creates() -> frozenset[str]:
    """Every table and named index this build's SQLite schema and migrations create."""
    # Imported here, as _expected_shape imports from store.py: store.py imports this module.
    from messagefoundry.store.store import _SCHEMA, MessageStore

    shape = await _expected_shape(_SCHEMA, MessageStore._migrate)
    return frozenset(shape.columns) | frozenset(shape.named_indexes)


async def _counts_under_a_dek(db: aiosqlite.Connection) -> bool:
    """Whether the live file records AES-GCM use but has no store salt: it was opened keyed, and
    only by a writer that seals under the DEK itself (ADR 0196). A cell-bound writer mints the salt
    row on its first keyed open, so a counted file without one never had its data key derived.

    The two tables are read separately. When the schema script itself failed (BACKLOG #2101), an
    older file may have no ``store_salt`` table at all, and that too means no salt was ever minted.
    So does a view under its name, or a virtual table ``_ORDINARY_TABLE`` skips (BACKLOG #6719):
    only an ordinary table can hold a salt this build minted. ``cipher_meta`` is read whatever object
    holds the name, so a readable count leans toward the new-key remedy rather than a reset."""
    try:
        async with db.execute("SELECT EXISTS (SELECT 1 FROM cipher_meta)") as cur:
            row = await cur.fetchone()
    except sqlite3.OperationalError:  # no count table, or an incompatible one: no count to reset
        return False
    if not (row and row[0]):
        return False
    try:
        async with db.execute(_SALT_TABLE_SQL) as cur:
            ordinary = await cur.fetchone()
        if not (ordinary and ordinary[0]):
            return True  # no ordinary salt table: this file never had a salt minted
        async with db.execute("SELECT EXISTS (SELECT 1 FROM store_salt)") as cur:
            salted = await cur.fetchone()
    except sqlite3.OperationalError as exc:
        # A busy or unreadable file answers nothing about the salt: say so, and fall back to the
        # plain remedy, as an unreadable count does above.
        log.warning("could not read store_salt to pick the schema remedy: %s", exc)
        return False
    return not (salted and salted[0])
