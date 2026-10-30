# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Verify a server-DB store's live schema before its marker is written (BACKLOG #1720).

The PostgreSQL and SQL Server DDL batches are additive and guarded, as SQLite's is: ``CREATE TABLE IF
NOT EXISTS``, ``CREATE INDEX IF NOT EXISTS``, ``IF OBJECT_ID(...) IS NULL CREATE``, ``IF
INDEXPROPERTY(...) IS NULL CREATE``, and ``ADD COLUMN`` behind an existence test. Each one SKIPS an
object that already exists under the expected name, whatever its shape. On PostgreSQL a relation of
any kind named ``ix_queue_fifo_in_seq`` makes the index build a no-op; a table left by an incompatible
version keeps its old columns. The batch then wrote the ``schema_meta`` marker, and every later open
took the ADR 0064 fast path past a schema that was never built.

This module is the check each backend runs after its batch and migrations and BEFORE its marker
write, inside the same transaction, so a refusal rolls the batch back and leaves no marker. It is the
server twin of :mod:`messagefoundry.store.schema_verify`, and reuses its shape types and its compare.

The EXPECTED shape is read from the DDL text itself, because no scratch database is available to build
it on as the SQLite check does: the columns of every ``CREATE TABLE``, every ``ADD COLUMN`` (less any
``DROP COLUMN`` after it), and every named ``CREATE INDEX`` with its table, key columns, uniqueness and
whether it has a ``WHERE``. Statements are read in order, so a later ``DROP TABLE`` or ``DROP INDEX``
removes what an earlier one created. A key column that is an expression reads as ``<expr>``, on both
sides. DDL the reader cannot place raises ``ValueError`` rather than being skipped or misread, at least:
a ``CREATE ... INDEX`` or ``CREATE TABLE`` its patterns do not match, a ``USING`` access method, and a
key column carrying a collation, an operator class or a ``NULLS`` order. A unit test reads each shipped
batch, so a new form fails there before it can reach an open.

What is NOT compared includes at least: column types, constraint indexes (a ``PRIMARY KEY`` or
``UNIQUE`` declared on the table), an index's ``INCLUDE`` list and storage options, and a partial
index's predicate, of which only its presence is compared. An index that exists but cannot serve, such
as an invalid or non-btree one on PostgreSQL or a disabled one on SQL Server, is reported by the
backend that reads it.

The rule is one-sided, as on SQLite: a missing table, column or index refuses, and so does an index
whose name matches but whose table, key columns, direction, uniqueness or partial flag differ, and a
name the batch needed that another kind of object holds. An EXTRA column or index is tolerated.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping
from functools import cache
from types import MappingProxyType

from messagefoundry.store.schema_verify import IndexShape, SchemaShape, schema_differences

__all__ = [
    "ServerSchemaMismatchError",
    "declared_schema",
    "key_column",
    "live_shape",
    "refuse_short_schema",
    "server_schema_differences",
]

log = logging.getLogger(__name__)

#: An identifier in the DDL: a plain word, optionally schema-qualified, optionally bracketed or
#: double-quoted. Only the last part is kept.
_NAME = r"(?:[\[\"]?\w+[\]\"]?\.)?[\[\"]?\w+[\]\"]?"
_CREATE_TABLE = re.compile(
    rf"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>{_NAME})\s*\(", re.I
)
_CREATE_INDEX = re.compile(
    rf"\bCREATE\s+(?P<unique>UNIQUE\s+)?(?:(?:NON)?CLUSTERED\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    rf"(?P<name>{_NAME})\s+ON\s+(?:ONLY\s+)?(?P<table>{_NAME})\s*(?P<using>USING\s+\w+\s*)?\(",
    re.I,
)
#: Every place a table or an index is created, read loosely, so a form the patterns above miss is
#: counted and refused rather than silently left unchecked. A ``#`` temporary table is not the store's.
_ANY_CREATE_TABLE = re.compile(r"\bCREATE\s+TABLE\s+(?!#)", re.I)
_ANY_CREATE_INDEX = re.compile(r"\bCREATE\s+(?:UNIQUE\s+)?(?:(?:NON)?CLUSTERED\s+)?INDEX\b", re.I)
#: The clauses PostgreSQL and SQL Server allow between an index's key list and its WHERE.
_INDEX_TAIL = re.compile(
    r"\s*(?:INCLUDE\s*\(|WITH\s*\(|NULLS\s+(?:NOT\s+)?DISTINCT\b|TABLESPACE\s+\S+)", re.I
)
_ADD_COLUMN = re.compile(
    rf"\bALTER\s+TABLE\s+(?P<table>{_NAME})\s+ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
    rf"(?P<col>{_NAME})",
    re.I,
)
_DROP_COLUMN = re.compile(
    rf"\bALTER\s+TABLE\s+(?P<table>{_NAME})\s+DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?(?P<col>{_NAME})",
    re.I,
)
_DROP_TABLE = re.compile(rf"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?P<name>{_NAME})", re.I)
_DROP_INDEX = re.compile(
    rf"\bDROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?(?P<name>{_NAME})(?:\s+ON\s+(?P<table>{_NAME}))?", re.I
)
#: The words that open a table-level constraint rather than a column definition, and the words that
#: follow ``ADD`` when what is added is not a column.
_NOT_A_COLUMN = frozenset(
    {"constraint", "primary", "unique", "check", "foreign", "exclude", "default", "period", "index"}
)
_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
_PLAIN_KEY = re.compile(r'^(\[?[A-Za-z_][\w$]*\]?|"[^"]+")(?:\s+(ASC|DESC))?$', re.I)
#: A key that is an expression: a call such as ``left(actor, 200)``, or a parenthesised expression.
_EXPR_KEY = re.compile(r'^(?:"?\w+"?\s*)?\(')


def _ident(name: str) -> str:
    """One identifier as the server stores it: a double-quoted one exactly, any other lower-cased.
    PostgreSQL folds an unquoted name to lower case and keeps a quoted one; SQL Server's brackets and
    names compare case-insensitively under its default collations, so lower case serves both."""
    if len(name) > 1 and name.startswith('"') and name.endswith('"'):
        return name[1:-1]
    return name.strip("[]").lower()


def _bare(name: str) -> str:
    return _ident(name.rsplit(".", 1)[-1])


def _balanced(text: str, start: int) -> tuple[str, int]:
    """The text inside the parenthesis opened at ``text[start - 1]``, and the index after its close.
    Quoted text is skipped, so a parenthesis inside a string literal does not count."""
    depth, i, quote = 1, start, ""
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1
        i += 1
    raise ValueError(f"unbalanced parenthesis in DDL near {text[start - 20 : start + 40]!r}")


def _top_level_items(body: str) -> list[str]:
    """``body`` split on its top-level commas, so a ``DECIMAL(10, 2)`` stays one item."""
    items: list[str] = []
    current: list[str] = []
    depth, quote = 0, ""
    for ch in body:
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            items.append("".join(current))
            current = []
            continue
        current.append(ch)
    items.append("".join(current))
    return [item.strip() for item in items if item.strip()]


def key_column(text: str) -> str:
    """One index key column as both sides of the compare spell it: a name as :func:`_ident` reads
    it, with `` DESC`` when descending, and ``<expr>`` for anything else."""
    match = _PLAIN_KEY.match(text.strip())
    if match is None:
        desc = text.strip().upper().endswith(" DESC")
        return "<expr>" + (" DESC" if desc else "")
    name, direction = match.groups()
    return _ident(name) + (" DESC" if direction and direction.upper() == "DESC" else "")


def _declared_key(text: str) -> str:
    """:func:`key_column` for a key in the DDL, refusing one whose live spelling would differ: a
    column with a collation, an operator class or a ``NULLS`` order prints as its bare name in the
    PostgreSQL catalog read, so it could never compare equal."""
    if _PLAIN_KEY.match(text.strip()) is None and _EXPR_KEY.match(text.strip()) is None:
        raise ValueError(f"index key {text!r} carries options the live-schema check cannot compare")
    return key_column(text)


@cache
def declared_schema(statements: tuple[str, ...]) -> SchemaShape:
    """The tables, columns and named indexes ``statements`` build, read in order.

    Cached per tuple of statements: each backend passes the same module-level batch on every open.
    ``rowid_columns`` and ``constraint_indexes`` are always empty, because neither is compared here.
    Raises ``ValueError`` on DDL it cannot read, which a unit test runs against each shipped batch."""
    columns: dict[str, set[str]] = {}
    indexes: dict[str, IndexShape] = {}
    for raw in statements:
        text = _COMMENT.sub(" ", raw)
        for loose, strict in (
            (_ANY_CREATE_TABLE, _CREATE_TABLE),
            (_ANY_CREATE_INDEX, _CREATE_INDEX),
        ):
            if len(loose.findall(text)) != len(strict.findall(text)):
                raise ValueError(f"DDL the live-schema check cannot read: {text.strip()[:120]!r}")
        events: list[tuple[int, str, re.Match[str]]] = []
        for kind, pattern in (
            ("table", _CREATE_TABLE),
            ("index", _CREATE_INDEX),
            ("add", _ADD_COLUMN),
            ("dropcol", _DROP_COLUMN),
            ("droptable", _DROP_TABLE),
            ("dropindex", _DROP_INDEX),
        ):
            events.extend((m.start(), kind, m) for m in pattern.finditer(text))
        for _pos, kind, m in sorted(events, key=lambda e: e[0]):
            if kind == "table":
                body, _end = _balanced(text, m.end())
                cols = columns.setdefault(_bare(m["name"]), set())
                for item in _top_level_items(body):
                    first = item.split()[0]
                    if first.lower() not in _NOT_A_COLUMN:
                        cols.add(_bare(first))
            elif kind == "index":
                if m["using"]:
                    raise ValueError(f"index access method not compared: {m.group(0)!r}")
                body, end = _balanced(text, m.end())
                while clause := _INDEX_TAIL.match(text, end):
                    end = clause.end()
                    if text[end - 1] == "(":
                        end = _balanced(text, end)[1]
                indexes[_bare(m["name"])] = IndexShape(
                    _bare(m["table"]),
                    tuple(_declared_key(item) for item in _top_level_items(body)),
                    bool(m["unique"]),
                    text[end:].lstrip().upper().startswith("WHERE"),
                )
            elif kind == "add":
                if _bare(m["col"]) not in _NOT_A_COLUMN:
                    columns.setdefault(_bare(m["table"]), set()).add(_bare(m["col"]))
            elif kind == "dropcol":
                columns.get(_bare(m["table"]), set()).discard(_bare(m["col"]))
            elif kind == "droptable":
                table = _bare(m["name"])
                columns.pop(table, None)
                for name in [n for n, shape in indexes.items() if shape.table == table]:
                    del indexes[name]
            else:
                indexes.pop(_bare(m["name"]), None)
    return SchemaShape(
        MappingProxyType({t: frozenset(c) for t, c in columns.items()}),
        MappingProxyType({}),
        MappingProxyType(indexes),
        frozenset(),
    )


def _a(noun: str) -> str:
    return ("an " if noun[:1].lower() in "aeiou" else "a ") + noun


def server_schema_differences(
    expected: SchemaShape,
    live: SchemaShape,
    taken: Mapping[str, str],
    unusable: Mapping[str, str] | None = None,
) -> list[str]:
    """Every way ``live`` falls short of ``expected``, one clause each. Extras are not listed.

    ``taken`` maps an expected table or index name to the kind of object that holds it instead (a
    table holding an index's name, a view holding a table's). Such a name gets its own clause, which
    says why the guarded ``CREATE`` skipped it, in place of a bare "is missing". ``unusable`` maps an
    expected index that exists under its name to why it cannot serve, such as ``disabled``."""
    unusable = unusable or {}
    problems: list[str] = []
    for name in sorted(taken):
        if name in expected.columns:
            problems.append(
                f"table {name!r} was never created: the name is taken by {_a(taken[name])}"
            )
        elif name in expected.named_indexes:
            problems.append(
                f"index {name!r} was never built: the name is taken by {_a(taken[name])}"
                f" (expected {expected.named_indexes[name].describe()})"
            )
    for name in sorted(unusable):
        if name in expected.named_indexes and name not in taken:
            problems.append(
                f"index {name!r} exists but is {unusable[name]}"
                f" (expected {expected.named_indexes[name].describe()})"
            )
    skip = set(taken) | set(unusable)
    rest = SchemaShape(
        MappingProxyType({t: c for t, c in expected.columns.items() if t not in skip}),
        expected.rowid_columns,
        MappingProxyType({n: s for n, s in expected.named_indexes.items() if n not in skip}),
        expected.constraint_indexes,
    )
    problems.extend(schema_differences(rest, live))
    return problems


def live_shape(
    columns: Mapping[str, Iterable[str]], indexes: Mapping[str, IndexShape]
) -> SchemaShape:
    """A :class:`SchemaShape` from what a backend read: columns per table and indexes by name.

    Names are taken as given. The backend spells them as :func:`_ident` does: PostgreSQL's catalog
    already holds an unquoted name in lower case and a quoted ``"ID"`` as ``ID``, which must not
    pass for ``id``; SQL Server lower-cases its own, as its default collations compare."""
    return SchemaShape(
        MappingProxyType({t: frozenset(cols) for t, cols in columns.items()}),
        MappingProxyType({}),
        MappingProxyType(dict(indexes)),
        frozenset(),
    )


class ServerSchemaMismatchError(RuntimeError):
    """A server-DB store's schema lacks something this build's DDL batch creates, so the open refuses
    before writing the ``schema_meta`` marker (BACKLOG #1720).

    A ``RuntimeError`` the engine defines, so the CLI prints it whole as an engine refusal. Not the
    SQLite :class:`~messagefoundry.store.schema_verify.SchemaMismatchError`: that is a
    ``sqlite3.DatabaseError``, which the CLI reports against the SQLite store path, and its remedy
    moves a file aside. ``differences`` lists what was found, one clause each."""

    def __init__(self, backend: str, database: str | None, differences: Iterable[str]) -> None:
        self.backend = backend
        self.database = database
        self.differences = tuple(differences)
        # The remedy leads, ahead of the differences, as the SQLite refusal's does: a path that cuts
        # an uncaught error's text keeps the part an operator acts on.
        super().__init__(
            f"the {backend} store schema in database {database!r} is not what this build creates, so"
            " the open refused and marked nothing current. Rename or drop each object named below,"
            " or build the store in an empty database or schema, then restart: the next open runs"
            " the batch again. Differences: " + "; ".join(self.differences) + "."
        )

    def __reduce__(self) -> tuple[type[ServerSchemaMismatchError], tuple[object, ...]]:
        # args holds only the message, so the default would call __init__ with it alone.
        return (type(self), (self.backend, self.database, self.differences))


def refuse_short_schema(
    backend: str,
    database: str | None,
    expected: SchemaShape,
    column_rows: Iterable[tuple[str, str | None, str | None]],
    indexes: Mapping[str, IndexShape],
    taken: Mapping[str, str],
    unusable: Mapping[str, str] | None = None,
) -> None:
    """Raise :class:`ServerSchemaMismatchError`, logged at ERROR first, when the live schema falls
    short of ``expected``. The one place both backends turn what they read into a refusal.

    ``column_rows`` is ``(table, kind, column)`` per live column: ``kind`` is ``None`` for a name
    nothing holds, ``"table"`` for a table, and otherwise the kind of object that holds the name.
    ``taken`` names the indexes another kind of object holds; the tables are added to it here.
    ``unusable`` is :func:`server_schema_differences`'."""
    taken = dict(taken)
    columns: dict[str, set[str]] = {}
    for table, kind, column in column_rows:
        if kind is None:
            continue  # nothing holds the name: the compare reports the table missing
        if kind != "table":
            taken[table] = kind
        elif column is not None:
            columns.setdefault(table, set()).add(column)
    problems = server_schema_differences(expected, live_shape(columns, indexes), taken, unusable)
    if problems:
        exc = ServerSchemaMismatchError(backend, database, problems)
        log.error("%s: %s", backend, exc)
        raise exc
