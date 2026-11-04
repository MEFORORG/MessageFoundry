# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Verify a server-DB store's live schema before its marker is written (BACKLOG #1720).

The PostgreSQL and SQL Server DDL batches are additive and guarded, as SQLite's is, and each guard
skips a CREATE on a name already held, whatever the shape of what holds it. What counts as held
differs by backend:

* PostgreSQL's ``CREATE TABLE IF NOT EXISTS`` and ``CREATE INDEX IF NOT EXISTS`` skip a name any
  relation holds in the creation schema: a table, an index, a view, a sequence or another kind. So a
  relation of any kind named ``ix_queue_fifo_in_seq`` makes the index build a no-op.
* SQL Server's ``IF OBJECT_ID('<name>', 'U') IS NULL CREATE TABLE`` skips only a user table of that
  name. Another kind of object holding it lets the ``CREATE TABLE`` run, and the batch then fails on
  that statement's own error. ``IF INDEXPROPERTY(OBJECT_ID('<table>'), '<name>', 'IndexID') IS NULL``
  skips an index of that name on that table, or a statistics object of it there.
* On both, ``ADD COLUMN`` runs behind a test that the column is absent.

On either backend a table left by an incompatible version keeps its old columns. The batch then wrote
the ``schema_meta`` marker, and every later open took the ADR 0064 fast path past a schema that was
never built.

This module is the check each backend runs after its batch and migrations and BEFORE its marker
write, inside the same transaction, so a refusal rolls the batch back and leaves no marker. It is the
server twin of :mod:`messagefoundry.store.schema_verify`, and reuses its shape types and its compare.

The EXPECTED shape is read from the DDL text itself, because no scratch database is available to build
it on as the SQLite check does: the columns of every ``CREATE TABLE`` and every ``ALTER TABLE``, and
every named ``CREATE INDEX`` with its table, key columns, uniqueness and whether it has a ``WHERE``.
Statements are read in order, so a later ``DROP`` or rename changes what an earlier one created. A key
column that is an expression reads as ``<expr>``, on both sides, followed by any operator class the
live read prints after it; an expression's collation is not compared, and a key that names one
raises. ``(col)`` reads as ``col``.

Given a backend, each column is also read for its type, its nullability, whether the server numbers it
(``SERIAL``, ``IDENTITY``, a PostgreSQL ``DEFAULT nextval(...)``) and, on SQL Server, a ``COLLATE``
it declares (BACKLOG #5085). A guarded ``ADD`` builds a column only on a store that lacks it, so a
column whose ``CREATE TABLE`` and ``ADD`` disagree, with no later ``ALTER COLUMN`` to bring both
together, is built two ways and raises.

DDL the reader cannot place raises ``ValueError`` rather than being skipped or misread, at least: a
``CREATE ... INDEX``, ``CREATE TABLE``, ``DROP TABLE``, ``DROP INDEX`` or ``sp_rename`` its patterns do
not match, an ``ALTER TABLE`` with more than one clause or an action it does not know, a table rename,
a ``USING`` access method, a key column or expression carrying a collation, an operator class or a
``NULLS`` order, a column type or clause it does not know, a SQL Server column that leaves its
nullability to the session, and a ``--`` or ``/*`` inside a quoted string, which may be dynamic SQL's
comment or a literal's text. A unit test reads each shipped batch, so a new form fails there before
it reaches an open.

What is NOT compared includes at least: a column's default, other than whether PostgreSQL's is a
``nextval()`` call, which reads as numbering; a PostgreSQL column's collation; constraint indexes (a
``PRIMARY KEY`` or ``UNIQUE`` declared on the table); ``CHECK`` and foreign keys; an index's
``INCLUDE`` list and storage options; and a partial index's predicate, of which only its presence is
compared. A default is not compared because each catalog prints it in its own rewritten form
(PostgreSQL ``''::text``, SQL Server ``((0))``), and a missing one fails the first insert that relies
on it rather than passing silently. An index that exists but cannot serve, such as
an invalid or non-btree one on PostgreSQL or a disabled one on SQL Server, is reported by the backend
that reads it. A store whose marker already matches is not re-read at open: the ADR 0064 fast path
skips the batch and this check together, so a change made by hand after the marker was written is not
seen until the batch next changes.

The rule is one-sided, as on SQLite. What refuses includes at least: a missing table, column or index;
a column of another type, nullability or numbering, or on SQL Server of a collation the batch
declares; an index whose name matches but whose table, key columns, direction, key options,
uniqueness or partial flag differ, or that cannot serve; and a name the batch needed that another
kind of object holds. An EXTRA column or index is tolerated.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from functools import cache
from types import MappingProxyType
from typing import Final, Literal

from messagefoundry.store.schema_verify import IndexShape, SchemaShape, schema_differences

__all__ = [
    "SCHEMA_CHECK_REV",
    "ColumnShape",
    "Dialect",
    "ServerSchemaMismatchError",
    "ServerSchemaShape",
    "declared_column",
    "declared_schema",
    "key_column",
    "live_shape",
    "mssql_live_type",
    "refuse_short_schema",
    "server_schema_differences",
]

log = logging.getLogger(__name__)

#: The revision of this check, which both server backends add to their marker hash. The check is
#: Python, so the content hash of a DDL batch cannot see it, and a store marked before a change to
#: what it refuses would take the fast path past that change forever. Bump it when the check changes
#: what it refuses; it is defined once, here, for both backends.
#: 1 (BACKLOG #1720): the check is added.
#: 2 (BACKLOG #5085, #5062): column type, nullability, numbering and SQL Server collation are
#: compared, and a PostgreSQL index key's collation, operator class and NULLS order are read.
SCHEMA_CHECK_REV: Final = 2

Dialect = Literal["postgres", "sqlserver"]

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
_ALTER_TABLE = re.compile(
    rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?P<table>{_NAME})(?=\s)", re.I
)
#: What may follow a DROP's last name: the statement's end, or a word that starts the next one. Any
#: other text, such as ``DROP TABLE public . t``, leaves the strict pattern unmatched, so it raises.
#: ``IF`` starts a T-SQL statement, ``IF EXISTS (`` included, but never ``IF EXISTS <name>``: that is
#: the drop's own guard after a word the pattern took for a name, as in ``DROP INDEX CONCURRENTLY IF
#: EXISTS ix`` read without the ``CONCURRENTLY`` its pattern now allows.
_DROP_END = (
    r"(?=\s*(?:[;')]|$)|\s+(?:CASCADE|RESTRICT|BEGIN|END|EXEC|ELSE|DROP|CREATE|ALTER)\b"
    r"|\s+IF\b(?!\s+EXISTS\s*[\w\[\"]))"
)
_DROP_TABLE = re.compile(
    rf"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?P<names>{_NAME}(?:\s*,\s*{_NAME})*){_DROP_END}",
    re.I,
)
_ON_TABLE = rf"(?:\s+ON\s+{_NAME})?"
_DROP_INDEX = re.compile(
    rf"\bDROP\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?"
    rf"(?P<names>{_NAME}{_ON_TABLE}(?:\s*,\s*{_NAME}{_ON_TABLE})*){_DROP_END}",
    re.I,
)
#: ``sp_rename``, as SQL Server runs it directly or inside an ``EXEC`` string, where every quote is
#: doubled. Only a column rename is read; ``sp_rename`` of a table or an index raises.
_SP_RENAME = re.compile(
    r"\bsp_rename\s+N?(?P<q>'{1,2})(?P<old>[^']+)(?P=q)\s*,\s*N?(?P=q)(?P<new>[^']+)(?P=q)"
    r"\s*,\s*N?(?P=q)COLUMN(?P=q)",
    re.I,
)
#: Every place a table or an index is created, dropped or renamed, read loosely, so a form the
#: patterns above miss is counted and refused rather than silently left unchecked. A ``#`` temporary
#: table is not the store's.
_LOOSE: Final = (
    (re.compile(r"\bCREATE\s+TABLE\s+(?!#)", re.I), _CREATE_TABLE),
    (re.compile(r"\bCREATE\s+(?:UNIQUE\s+)?(?:(?:NON)?CLUSTERED\s+)?INDEX\b", re.I), _CREATE_INDEX),
    (re.compile(r"\bALTER\s+TABLE\s+(?!#)", re.I), _ALTER_TABLE),
    (re.compile(r"\bDROP\s+TABLE\s+(?!#)", re.I), _DROP_TABLE),
    (re.compile(r"\bDROP\s+INDEX\b", re.I), _DROP_INDEX),
    (re.compile(r"\bsp_rename\b", re.I), _SP_RENAME),
)
#: The clauses PostgreSQL and SQL Server allow between an index's key list and its WHERE.
_INDEX_TAIL = re.compile(
    r"\s*(?:INCLUDE\s*\(|WITH\s*\(|NULLS\s+(?:NOT\s+)?DISTINCT\b|TABLESPACE\s+\S+)", re.I
)
#: The words that open a table-level constraint rather than a column definition, and the words that
#: follow ``ADD`` when what is added is not a column.
_NOT_A_COLUMN = frozenset(
    {"constraint", "primary", "unique", "check", "foreign", "exclude", "default", "period", "index"}
)
_TABLE_PRIMARY_KEY = re.compile(r"\bPRIMARY\s+KEY\s*(?:(?:NON)?CLUSTERED\s*)?\(", re.I)
_PLAIN_KEY = re.compile(r'^(\[?[A-Za-z_][\w$]*\]?|"[^"]+")(?:\s+(ASC|DESC))?$', re.I)
_PLAIN_NAME = re.compile(r'^(?:\[?[A-Za-z_][\w$]*\]?|"[^"]+")$')
#: A key that is an expression: a call such as ``left(actor, 200)``, or a parenthesised expression.
#: The catalog qualifies a function its search path does not reach, as ``pg_catalog."left"(...)``.
_EXPR_KEY = re.compile(r'^(?:(?:"?\w+"?\s*\.\s*)?"?\w+"?\s*)?\(')
#: A key's trailing ``NULLS FIRST`` or ``NULLS LAST``, with or without a direction before it.
_NULLS_ORDER = re.compile(r"\s*\bNULLS\s+(?:FIRST|LAST)$", re.I)
_DIRECTION = re.compile(r"\s+(ASC|DESC)$", re.I)
#: The words a statement inside a block starts with, at which an ``ALTER TABLE`` clause has ended
#: when no ``;`` closes it. None can appear inside a column definition.
_STATEMENT_START = frozenset({"if", "begin", "end", "exec", "execute", "else", "declare", "go"})
_TOKEN = re.compile(r"""N?'(?:[^']|'')*'|"[^"]*"|\[[^\]]*\]|\w+|\S""")


@dataclass(frozen=True)
class ColumnShape:
    """What a column holds: its type as the backend's catalog spells it, whether it takes NULL,
    whether the server numbers it, and a collation it was declared with.

    ``collation`` is ``None`` where the column takes the database's default; an expected ``None``
    matches any live collation, because the default is the database's, not this build's."""

    type: str
    nullable: bool
    identity: bool = False
    collation: str | None = None

    def describe(self, *, collation: bool = True) -> str:
        """The shape in lower-case words. The service log's redaction filter reads a run of
        all-caps words, such as ``NOT NULL`` or ``IDENTITY NOT NULL``, as a name and rewrites it
        to ``[redacted]``, which would hide the very difference a refusal reports. A refusal
        names a collation in a clause of its own, so passes ``collation=False``."""
        return (
            self.type
            + (" identity" if self.identity else "")
            + (" null" if self.nullable else " not null")
            + (f" collate {self.collation}" if collation and self.collation else "")
        )

    def core_differs(self, live: ColumnShape) -> bool:
        """Whether ``live`` has another type, nullability or numbering."""
        return replace(self, collation=None) != replace(live, collation=None)

    def collation_differs(self, live: ColumnShape) -> bool:
        """Whether this shape declares a collation that ``live`` does not have."""
        return (
            self.collation is not None and self.collation.lower() != (live.collation or "").lower()
        )


def _no_columns() -> Mapping[str, Mapping[str, ColumnShape]]:
    return MappingProxyType({})


@dataclass(frozen=True)
class ServerSchemaShape(SchemaShape):
    """:class:`SchemaShape` plus each column's :class:`ColumnShape`, by table then column. A column
    with no entry has no shape to compare: the DDL was read without a backend, or the live read did
    not say."""

    column_shapes: Mapping[str, Mapping[str, ColumnShape]] = field(default_factory=_no_columns)


# --- reading the DDL -----------------------------------------------------------------------------


def _ident(name: str) -> str:
    """One identifier as the server stores it: a double-quoted one exactly, any other lower-cased.
    PostgreSQL folds an unquoted name to lower case and keeps a quoted one; SQL Server's brackets and
    names compare case-insensitively under its default collations, so lower case serves both."""
    if len(name) > 1 and name.startswith('"') and name.endswith('"'):
        return name[1:-1]
    return name.strip("[]").lower()


def _bare(name: str) -> str:
    return _ident(name.rsplit(".", 1)[-1])


def _strip_comments(raw: str) -> str:
    """``raw`` with its ``--`` and ``/* */`` comments blanked, read left to right so a quote inside a
    comment opens nothing and a comment marker inside a quoted name is not one. A marker inside a
    string literal raises: in an ``EXEC`` string it is dynamic SQL's comment, in any other a
    literal's text, and the reader cannot tell which."""
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if raw.startswith("--", i):
            end = raw.find("\n", i)
            i = n if end < 0 else end
            out.append(" ")
        elif raw.startswith("/*", i):
            end = raw.find("*/", i + 2)
            if end < 0:
                raise ValueError(f"unterminated comment in DDL near {raw[i : i + 40]!r}")
            i = end + 2
            out.append(" ")
        elif ch in "'\"[":
            close = "]" if ch == "[" else ch
            end = raw.find(close, i + 1)
            if end < 0:
                raise ValueError(f"unterminated quote in DDL near {raw[i : i + 40]!r}")
            quoted = raw[i : end + 1]
            if ch == "'" and ("--" in quoted or "/*" in quoted):
                raise ValueError(f"a comment marker inside a string in DDL: {quoted[:60]!r}")
            out.append(quoted)
            i = end + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _string_spans(text: str) -> list[tuple[int, int]]:
    """The ``(start, end)`` of each single-quoted string in ``text``, end exclusive. A doubled quote
    inside one is its escape, so it continues the string."""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in '"[':
            end = text.find("]" if ch == "[" else ch, i + 1)
            i = n if end < 0 else end + 1
        elif ch == "'":
            j = i + 1
            while j < n:
                if text[j] == "'":
                    if text.startswith("''", j):
                        j += 2
                        continue
                    break
                j += 1
            spans.append((i, j + 1))
            i = j + 1
        else:
            i += 1
    return spans


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


def _clause(segment: str) -> str:
    """The one clause of an ``ALTER TABLE`` that ``segment`` starts with: up to a top-level ``;``,
    an unmatched ``)``, a word that starts the next statement, or the end. A top-level comma means
    more than one clause, which raises."""
    depth, quote, i, n = 0, "", 0, len(segment)
    while i < n:
        ch = segment[i]
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and ch == ";":
            break
        elif depth == 0 and ch == ",":
            raise ValueError(f"an ALTER TABLE with more than one clause: {segment[:120].strip()!r}")
        elif (
            depth == 0 and (ch.isalpha() or ch == "_") and (i == 0 or not segment[i - 1].isalnum())
        ):
            word = re.match(r"\w+", segment[i:])
            assert word is not None
            after = segment[i + len(word.group(0)) :]
            if word.group(0).lower() in _STATEMENT_START and not (
                word.group(0).lower() == "if" and re.match(r"\s+(?:NOT\s+)?EXISTS\b", after, re.I)
            ):
                break
            i += len(word.group(0))
            continue
        i += 1
    return segment[:i].strip()


# The types each catalog spells one way, keyed by every spelling the DDL may use. The live read
# compares against these spellings: PostgreSQL's format_type() and SQL Server's sys.types names.
_PG_TYPES: Final = MappingProxyType(
    {
        "text": "text",
        "integer": "integer",
        "int": "integer",
        "int4": "integer",
        "bigint": "bigint",
        "int8": "bigint",
        "smallint": "smallint",
        "int2": "smallint",
        "double precision": "double precision",
        "float8": "double precision",
        "float": "double precision",
        "real": "real",
        "float4": "real",
        "boolean": "boolean",
        "bool": "boolean",
        "bytea": "bytea",
        "date": "date",
        "uuid": "uuid",
        "json": "json",
        "jsonb": "jsonb",
        "numeric": "numeric",
        "decimal": "numeric",
        "varchar": "character varying",
        "character varying": "character varying",
        "char": "character(1)",
        "character": "character(1)",
        "timestamptz": "timestamp with time zone",
        "timestamp with time zone": "timestamp with time zone",
        "timestamp": "timestamp without time zone",
        "timestamp without time zone": "timestamp without time zone",
    }
)
_PG_SERIAL: Final = MappingProxyType(
    {
        "serial": "integer",
        "serial4": "integer",
        "bigserial": "bigint",
        "serial8": "bigint",
        "smallserial": "smallint",
        "serial2": "smallint",
    }
)
_PG_SIZED: Final = MappingProxyType(
    {
        "varchar": "character varying",
        "character varying": "character varying",
        "char": "character",
        "character": "character",
        "numeric": "numeric",
        "decimal": "numeric",
    }
)
_MSSQL_PLAIN: Final = frozenset(
    {"int", "bigint", "smallint", "tinyint", "bit", "float", "real", "date", "uniqueidentifier"}
)
_MSSQL_SIZED: Final = frozenset({"nvarchar", "varchar", "nchar", "char", "varbinary", "binary"})
_MSSQL_SCALED: Final = frozenset({"datetime2", "datetimeoffset", "time"})


def _type_parts(text: str) -> tuple[str, list[str] | None]:
    """A declared type as its lower-cased base words and its arguments, if it has any."""
    match = re.fullmatch(r"([A-Za-z][\w ]*?)\s*(?:\((.*)\))?", " ".join(text.split()))
    if match is None:
        raise ValueError(f"a column type the live-schema check cannot read: {text!r}")
    base, args = match.groups()
    return base.lower(), None if args is None else [a.strip().lower() for a in args.split(",")]


def _canonical_type(dialect: Dialect, text: str) -> tuple[str, bool]:
    """A declared type as ``dialect``'s catalog spells it, and whether the type numbers the column
    (PostgreSQL's ``SERIAL`` family). Raises ``ValueError`` on a type it does not know, so a new one
    fails the unit test that reads each shipped batch rather than refusing a correct store."""
    base, args = _type_parts(text)
    if dialect == "postgres":
        if args is None and base in _PG_SERIAL:
            return _PG_SERIAL[base], True
        if base in ("float", "double precision") and args is not None and len(args) == 1:
            return ("real" if int(args[0]) <= 24 else "double precision"), False
        if args is not None and base in _PG_SIZED and all(a.isdigit() for a in args):
            if _PG_SIZED[base] == "numeric" and len(args) == 1:
                args = [args[0], "0"]
            return f"{_PG_SIZED[base]}({','.join(args)})", False
        if args is None and base in _PG_TYPES:
            return _PG_TYPES[base], False
    else:
        if base == "integer":
            base = "int"
        if args is None and base in _MSSQL_PLAIN:
            return base, False
        if base == "float" and args is not None and len(args) == 1 and args[0].isdigit():
            return ("real" if int(args[0]) <= 24 else "float"), False
        if base in _MSSQL_SIZED and (args is None or len(args) == 1):
            size = "1" if args is None else args[0]
            if size.isdigit() or (size == "max" and base.startswith(("nvar", "var"))):
                return f"{base}({size})", False
        if base in ("decimal", "numeric") and (args is None or 1 <= len(args) <= 2):
            precision, scale = (args or ["18"]) + ["0"] * (2 - len(args or ["18"]))
            return f"{base}({precision},{scale})", False
        if base in _MSSQL_SCALED and (args is None or len(args) == 1):
            return f"{base}({'7' if args is None else args[0]})", False
    raise ValueError(f"a {dialect} column type the live-schema check does not compare: {text!r}")


def mssql_live_type(name: str, max_length: int, precision: int, scale: int) -> str:
    """A SQL Server column's type from ``sys.columns``, spelled as :func:`_canonical_type` spells a
    declared one. ``max_length`` is in bytes, two per character for an ``n`` type, and -1 for MAX."""
    base = name.lower()
    if base in _MSSQL_SIZED:
        size = "max" if max_length == -1 else str(max_length // 2 if base[0] == "n" else max_length)
        return f"{base}({size})"
    if base in ("decimal", "numeric"):
        return f"{base}({precision},{scale})"
    if base in _MSSQL_SCALED:
        return f"{base}({scale})"
    return base


@dataclass
class _Column:
    """One column as a definition declares it, before the table-level ``PRIMARY KEY`` is known."""

    type: str
    nullable: bool | None
    identity: bool
    collation: str | None
    primary_key: bool
    #: A PostgreSQL ``DEFAULT nextval(...)``: the server numbers the column, as the live read says,
    #: but unlike ``SERIAL`` or an identity it does not make the column NOT NULL.
    numbered_default: bool = False


def _skip_group(tokens: list[str], i: int) -> int:
    """The index after the parenthesised group that opens at ``tokens[i]``."""
    depth = 0
    for j in range(i, len(tokens)):
        if tokens[j] == "(":
            depth += 1
        elif tokens[j] == ")":
            depth -= 1
            if depth == 0:
                return j + 1
    raise ValueError(f"unbalanced parenthesis in a column definition: {' '.join(tokens)!r}")


_COLUMN_CLAUSES = frozenset(
    {
        "not",
        "null",
        "primary",
        "unique",
        "check",
        "references",
        "default",
        "constraint",
        "collate",
        "identity",
        "generated",
    }
)
_FK_ACTIONS = re.compile(
    r"ON\s+(?:DELETE|UPDATE)\s+(?:CASCADE|RESTRICT|NO\s+ACTION|SET\s+NULL|SET\s+DEFAULT)\b", re.I
)


def _read_column(dialect: Dialect, text: str) -> tuple[str, _Column]:
    """A column definition's name and what it declares. Raises on a clause it does not know."""
    tokens = _TOKEN.findall(_FK_ACTIONS.sub(" ", text))
    if not tokens:
        raise ValueError("an empty column definition")
    name, i, words = _bare(tokens[0]), 1, []
    while i < len(tokens) and tokens[i].lower() not in _COLUMN_CLAUSES:
        if tokens[i] == "(":
            end = _skip_group(tokens, i)
            words.append("(" + " ".join(tokens[i + 1 : end - 1]) + ")")
            i = end
        else:
            words.append(tokens[i])
            i += 1
    if not words:
        raise ValueError(f"a column definition with no type: {text!r}")
    col_type, identity = _canonical_type(dialect, " ".join(words).replace(" (", "("))
    nullable: bool | None = None
    collation: str | None = None
    primary_key = numbered_default = False

    def word(k: int) -> str:
        return tokens[k].lower() if k < len(tokens) else ""

    while i < len(tokens):
        w = word(i)
        if w == "not" and word(i + 1) == "null":
            if nullable is True:
                raise ValueError(f"a column declared both NULL and NOT NULL: {text!r}")
            nullable, i = False, i + 2
        elif w == "null":
            if nullable is False:
                raise ValueError(f"a column declared both NULL and NOT NULL: {text!r}")
            nullable, i = True, i + 1
        elif w == "primary" and word(i + 1) == "key":
            primary_key, i = True, i + 2
            if word(i) in ("clustered", "nonclustered"):
                i += 1
        elif w == "unique":
            i += 1
            if word(i) in ("clustered", "nonclustered"):
                i += 1
        elif w == "check" and word(i + 1) == "(":
            i = _skip_group(tokens, i + 1)
        elif w == "references" and i + 1 < len(tokens):
            i += 2
            if word(i) == "(":
                i = _skip_group(tokens, i)
        elif w == "default" and i + 1 < len(tokens):
            numbered_default = dialect == "postgres" and _numbers(" ".join(tokens[i + 1 :]))
            i += 2 if tokens[i + 1] not in "+-" else 3
            if tokens[i - 1] == "(":
                i = _skip_group(tokens, i - 1)
            elif word(i) == "(":
                i = _skip_group(tokens, i)
        elif w == "constraint" and i + 1 < len(tokens):
            i += 2
        elif w == "collate" and i + 1 < len(tokens):
            if dialect == "postgres":
                raise ValueError(f"a PostgreSQL column collation is not compared: {text!r}")
            collation, i = _ident(tokens[i + 1]), i + 2
        elif w == "identity" and dialect == "sqlserver":
            identity, i = True, i + 1
            if word(i) == "(":
                i = _skip_group(tokens, i)
        elif (
            w == "generated"
            and dialect == "postgres"
            and re.match(
                r"GENERATED\s+(?:ALWAYS|BY\s+DEFAULT)\s+AS\s+IDENTITY\b",
                " ".join(tokens[i : i + 5]),
                re.I,
            )
        ):
            identity = True
            i += 4 if word(i + 1) == "always" else 5
            if word(i) == "(":
                i = _skip_group(tokens, i)
        else:
            raise ValueError(f"a column clause the live-schema check cannot read: {text!r}")
    return name, _Column(col_type, nullable, identity, collation, primary_key, numbered_default)


def _numbers(default: str) -> bool:
    """Whether a PostgreSQL default, the text after ``DEFAULT``, is a ``nextval()`` call, which the
    live read counts as numbering. Outer parentheses are skipped: the catalog prints the call bare."""
    return re.match(r"[\s(]*nextval\s*\(", default, re.I) is not None


def _finish(dialect: Dialect, col: _Column, text: str) -> ColumnShape:
    """The column's :class:`ColumnShape`, its nullability settled: a key or a numbered column takes
    no NULL; otherwise PostgreSQL defaults to NULL, and SQL Server's default is the session's, so a
    SQL Server column that leaves it unsaid raises."""
    nullable = col.nullable
    if col.primary_key or col.identity:
        if nullable is True:
            raise ValueError(f"a key or numbered column declared NULL: {text!r}")
        nullable = False
    elif nullable is None:
        if dialect == "sqlserver":
            raise ValueError(f"a SQL Server column that leaves NULL to the session: {text!r}")
        nullable = True
    return ColumnShape(col.type, nullable, col.identity or col.numbered_default, col.collation)


def declared_column(dialect: Dialect, text: str) -> ColumnShape:
    """One column definition, such as ``seal TEXT NOT NULL DEFAULT ''``, as its shape. For a test
    that holds a migration's own ``ADD COLUMN`` to the batch's ``CREATE TABLE``."""
    _name, col = _read_column(dialect, text)
    return _finish(dialect, col, text)


def _declared_key(text: str) -> str:
    """:func:`key_column` for a key in the DDL, refusing one whose live spelling would differ: a
    column with a collation, an operator class or a ``NULLS`` order is read with them on PostgreSQL
    and could never compare equal to the bare name. An expression key with a ``NULLS`` order, an
    operator class or a collation is refused too. A plain name in parentheses, ``(col)``, is the
    column itself, as the catalog reads it. No shipped index uses any of these; refusing here makes
    a future one fail the unit test that reads each shipped batch, not every open."""
    key, direction = text.strip(), ""
    if match := _DIRECTION.search(key):
        key, direction = key[: match.start()], match.group(0)
    inner = key
    while inner.startswith("(") and inner.endswith(")") and _balanced(inner, 1)[1] == len(inner):
        inner = inner[1:-1].strip()
    if _PLAIN_NAME.match(inner):
        key = inner
    elif inner != key and re.search(r"\bCOLLATE\b", inner, re.I):
        # PostgreSQL stores ((col COLLATE x)) as the column with an index collation.
        raise ValueError(f"index key {text!r} carries options the live-schema check cannot compare")
    elif (end := _expression_end(key)) is not None and (
        key[end:].strip() or re.search(r"\bCOLLATE\b", key, re.I)
    ):
        # An expression with an operator class after it, such as lower(a) text_pattern_ops,
        # which the live read prints only where it is not the type's default, or with a
        # collation anywhere in it, which the live read does not compare for an expression.
        raise ValueError(f"index key {text!r} carries options the live-schema check cannot compare")
    key += direction
    if _NULLS_ORDER.search(key) or (_PLAIN_KEY.match(key) is None and _EXPR_KEY.match(key) is None):
        raise ValueError(f"index key {text!r} carries options the live-schema check cannot compare")
    return key_column(key)


def _expression_end(key: str) -> int | None:
    """Where the expression that opens ``key`` ends, or ``None`` when ``key`` does not open with
    one or its parentheses do not balance."""
    if (match := _EXPR_KEY.match(key)) is None:
        return None
    try:
        return _balanced(key, match.end())[1]
    except ValueError:
        return None


def key_column(text: str) -> str:
    """One index key column as both sides of the compare spell it: a name as :func:`_ident` reads
    it, ``<expr>`` for an expression, then what the live read printed after it (a collation or an
    operator class), then `` DESC`` when descending and a ``nulls`` order when one was printed. The
    order is lower-cased: the service log's redaction filter rewrites a run of all-caps words such
    as ``DESC NULLS FIRST`` to ``[redacted]``."""
    key = " ".join(text.split())
    nulls = ""
    if match := _NULLS_ORDER.search(key):
        nulls, key = " " + " ".join(match.group(0).lower().split()), key[: match.start()]
    desc = ""
    if match := _DIRECTION.search(key):
        desc, key = (" DESC" if match.group(1).upper() == "DESC" else ""), key[: match.start()]
    if _PLAIN_NAME.match(key):
        base = _ident(key)
    elif (end := _expression_end(key)) is not None:
        # What follows the expression, an operator class or a collation, is kept, so an
        # expression index built with one does not pass as the bare expression.
        rest = key[end:].strip()
        base = "<expr>" + (f" {rest}" if rest else "")
    else:
        head, _, rest = key.partition(" ")
        base = (_ident(head) if _PLAIN_NAME.match(head) else head) + (f" {rest}" if rest else "")
    return base + desc + nulls


@dataclass
class _Built:
    """Every shape a store may hold one column in. ``create`` is what ``CREATE TABLE`` builds on a
    new store. ``later`` is what a guarded ``ADD`` builds on an older store that lacked the column,
    and what an ``ALTER COLUMN`` leaves on an older store. Every guard in a shipped batch tests for
    the old state, so an ``ALTER COLUMN`` is not taken to reach a new store: its result must equal
    ``create``, or the column is built two ways."""

    create: ColumnShape | None = None
    later: set[ColumnShape] = field(default_factory=set)

    def ways(self) -> set[ColumnShape]:
        return self.later | ({self.create} if self.create else set())

    def altered(self, change: Callable[[ColumnShape], ColumnShape]) -> None:
        self.later = {change(s) for s in (self.later or self.ways())}


def _pk_columns(text: str) -> set[str]:
    """The columns of a ``PRIMARY KEY (...)`` in ``text``, a table item or an ``ADD CONSTRAINT``."""
    if (pk := _TABLE_PRIMARY_KEY.search(text)) is None:
        return set()
    inner, _ = _balanced(text, pk.end())
    return {_bare(k.split()[0]) for k in _top_level_items(inner)}


class _Reader:
    """The state :func:`declared_schema` builds, statement by statement: each table's columns, as
    :class:`_Built`, and the named indexes. No shapes are kept when the DDL is read without a
    backend."""

    def __init__(self, dialect: Dialect | None) -> None:
        self.dialect = dialect
        self.columns: dict[str, dict[str, _Built]] = {}
        self.indexes: dict[str, IndexShape] = {}

    def table(self, text: str, m: re.Match[str]) -> None:
        body, _end = _balanced(text, m.end())
        cols = self.columns.setdefault(_bare(m["name"]), {})
        keys: set[str] = set()
        pending: list[tuple[str, _Column, str]] = []
        for item in _top_level_items(body):
            first = item.split()[0]
            if first.lower() in _NOT_A_COLUMN:
                keys |= _pk_columns(item)
            elif self.dialect is None:
                cols.setdefault(_bare(first), _Built())
            else:
                name, col = _read_column(self.dialect, item)
                pending.append((name, col, item))
        for name, col, item in pending:
            assert self.dialect is not None
            col.primary_key = col.primary_key or name in keys
            built = cols.setdefault(name, _Built())
            shape = _finish(self.dialect, col, item)
            if built.create is None:
                built.create = shape
            else:
                built.later.add(shape)

    def index(self, text: str, m: re.Match[str]) -> None:
        if m["using"]:
            raise ValueError(f"index access method not compared: {m.group(0)!r}")
        body, end = _balanced(text, m.end())
        while clause := _INDEX_TAIL.match(text, end):
            end = clause.end()
            if text[end - 1] == "(":
                end = _balanced(text, end)[1]
        self.indexes[_bare(m["name"])] = IndexShape(
            _bare(m["table"]),
            tuple(_declared_key(item) for item in _top_level_items(body)),
            bool(m["unique"]),
            text[end:].lstrip().upper().startswith("WHERE"),
        )

    def _built(self, table: str, name: str, action: str) -> _Built:
        cols = self.columns.get(table)
        if cols is None or name not in cols:
            raise ValueError(f"{action} names a column the DDL never declares: {table}.{name}")
        return cols[name]

    def alter(self, text: str, m: re.Match[str], spans: list[tuple[int, int]]) -> None:
        table = _bare(m["table"])
        segment = text[m.end() :]
        for start, end in spans:
            if start < m.start() < end:  # inside an EXEC string: its own text, quotes undoubled
                segment = text[m.end() : end - 1].replace("''", "'")
                break
        # SQL Server's WITH [NO]CHECK says whether an added constraint checks the existing rows.
        clause = re.sub(r"^WITH\s+(?:NO)?CHECK\s+(?=ADD\b)", "", _clause(segment), flags=re.I)
        words = clause.split()
        verb = [w.lower() for w in words[:2]]
        if verb[:1] == ["add"]:
            rest = re.sub(r"^ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?", "", clause, flags=re.I)
            first = rest.split()[0].lower() if rest.split() else ""
            if first in _NOT_A_COLUMN:
                for key in _pk_columns(rest):
                    self._not_null(table, key)
                return
            if self.dialect is None:
                self.columns.setdefault(table, {}).setdefault(_bare(rest.split()[0]), _Built())
                return
            name, col = _read_column(self.dialect, rest)
            built = self.columns.setdefault(table, {}).setdefault(name, _Built())
            built.later.add(_finish(self.dialect, col, rest))
        elif verb == ["drop", "column"]:
            name = re.sub(r"^DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?", "", clause, flags=re.I)
            column = _bare(name.split()[0])
            self.columns.get(table, {}).pop(column, None)
            # PostgreSQL drops an index on a dropped column; SQL Server refuses the drop.
            self._rewrite_keys(table, column, None)
        elif verb in (["drop", "constraint"], ["check", "constraint"], ["nocheck", "constraint"]):
            return  # a key's columns keep their NOT NULL when the key is dropped, on both
        elif verb[:1] == ["set"] and clause[3:].lstrip().startswith("("):
            return  # a table's storage options, such as LOCK_ESCALATION: not compared
        elif verb == ["alter", "column"]:
            self._alter_column(table, clause, words)
        elif verb[:1] == ["rename"] and len(words) == 5 and words[1].lower() == "column":
            self._rename(table, _bare(words[2]), _bare(words[4]))
        else:
            raise ValueError(f"an ALTER TABLE the live-schema check cannot read: {clause[:120]!r}")

    def _not_null(self, table: str, name: str) -> None:
        built = self._built(table, name, "a PRIMARY KEY")
        built.create = built.create and replace(built.create, nullable=False)
        built.later = {replace(s, nullable=False) for s in built.later}

    def _alter_column(self, table: str, clause: str, words: list[str]) -> None:
        if len(words) < 3:
            raise ValueError(f"an ALTER COLUMN with no column: {clause!r}")
        if self.dialect is None:
            return
        built = self._built(table, _bare(words[2]), "ALTER COLUMN")
        rest = " ".join(words[3:])
        if self.dialect == "sqlserver":
            # The whole definition is restated; one without COLLATE takes the database default.
            _name, col = _read_column(self.dialect, f"{words[2]} {rest}")
            if col.identity or col.primary_key:
                raise ValueError(f"an ALTER COLUMN the live-schema check cannot read: {clause!r}")
            col.identity = {s.identity for s in built.ways()} == {True}
            new = _finish(self.dialect, col, clause)
            built.altered(lambda _s: new)
            return
        upper = rest.upper()
        if upper in ("SET NOT NULL", "DROP NOT NULL"):
            nullable = upper.startswith("DROP")
            built.altered(lambda s: replace(s, nullable=nullable))
        elif upper == "DROP DEFAULT" or upper.startswith("SET DEFAULT "):
            # A nextval() default numbers the column as the live read sees it, and any other
            # default, or none, does not. PostgreSQL refuses either on an identity column.
            numbered = _numbers(rest[len("SET DEFAULT ") :])  # empty after DROP DEFAULT
            built.altered(lambda s: replace(s, identity=numbered))
        elif match := re.match(
            r"(?:SET\s+DATA\s+)?TYPE\s+(.+?)(?:\s+USING\s+.*)?$", rest, re.I | re.S
        ):
            if re.search(r"\bCOLLATE\b", match.group(1), re.I):
                raise ValueError(f"a PostgreSQL column collation is not compared: {clause!r}")
            new_type, _numbered = _canonical_type(self.dialect, match.group(1))
            built.altered(lambda s: replace(s, type=new_type))
        else:
            raise ValueError(f"an ALTER COLUMN the live-schema check cannot read: {clause!r}")

    def _rewrite_keys(self, table: str, old: str, new: str | None) -> None:
        """Rename ``old`` in the keys of ``table``'s indexes, or with ``new`` ``None`` drop the
        indexes that name it, as the server does."""
        for name, shape in list(self.indexes.items()):
            if shape.table != table:
                continue
            keys = [k.split(" ", 1) for k in shape.columns]
            if not any(k[0] == old for k in keys):
                continue
            if new is None:
                del self.indexes[name]
            else:
                columns = tuple(
                    " ".join([new, *k[1:]]) if k[0] == old else " ".join(k) for k in keys
                )
                self.indexes[name] = replace(shape, columns=columns)

    def _rename(self, table: str, old: str, new: str) -> None:
        """A store that still has ``old`` gets it as ``new``; one that already has ``new`` keeps it.
        A rename of a table or column the DDL never declares raises, rather than invent one."""
        cols = self.columns.get(table)
        if cols is None or (old not in cols and new not in cols):
            raise ValueError(f"a rename of a column the DDL never declares: {table}.{old}")
        moved = cols.pop(old, None)
        built = cols.setdefault(new, _Built())
        if moved is not None:
            built.later |= moved.ways()
        self._rewrite_keys(table, old, new)

    def rename(self, m: re.Match[str]) -> None:
        if m["old"].count(".") != 1:
            raise ValueError(f"an sp_rename the live-schema check cannot read: {m.group(0)!r}")
        table, old = m["old"].split(".")
        self._rename(_bare(table), _bare(old), _bare(m["new"]))

    def drop_tables(self, m: re.Match[str]) -> None:
        for name in _top_level_items(m["names"]):
            table = _bare(name)
            self.columns.pop(table, None)
            for index in [n for n, shape in self.indexes.items() if shape.table == table]:
                del self.indexes[index]

    def drop_indexes(self, m: re.Match[str]) -> None:
        """Each index named, but on SQL Server only on the table its ``ON`` names: a name is unique
        only within its table there."""
        for item in _top_level_items(m["names"]):
            parts = item.split()
            name = _bare(parts[0])
            on = _bare(parts[-1]) if len(parts) == 3 else None
            shape = self.indexes.get(name)
            if shape is not None and (on is None or shape.table == on):
                del self.indexes[name]

    def shape(self) -> ServerSchemaShape:
        shapes: dict[str, Mapping[str, ColumnShape]] = {}
        for table, cols in self.columns.items():
            one: dict[str, ColumnShape] = {}
            for name, built in cols.items():
                ways = built.ways()
                if len(ways) > 1:
                    listed = " and ".join(sorted(s.describe() for s in ways))
                    raise ValueError(
                        f"column {table}.{name} is built two ways, as {listed}: a guarded ADD,"
                        " an ALTER COLUMN or a second CREATE TABLE disagrees with the first"
                    )
                if ways:
                    one[name] = next(iter(ways))
            shapes[table] = MappingProxyType(one)
        return ServerSchemaShape(
            MappingProxyType({t: frozenset(c) for t, c in self.columns.items()}),
            MappingProxyType({}),
            MappingProxyType(dict(self.indexes)),
            frozenset(),
            MappingProxyType(shapes) if self.dialect else _no_columns(),
        )


@cache
def declared_schema(
    statements: tuple[str, ...], dialect: Dialect | None = None
) -> ServerSchemaShape:
    """The tables, columns and named indexes ``statements`` build, read in order. Given a
    ``dialect``, each column's :class:`ColumnShape` too.

    Cached per tuple of statements: each backend passes the same module-level batch on every open.
    ``rowid_columns`` and ``constraint_indexes`` are always empty, because neither is compared here.
    Raises ``ValueError`` on DDL it cannot read, which a unit test runs against each shipped batch."""
    reader = _Reader(dialect)
    for raw in statements:
        text = _strip_comments(raw)
        for loose, strict in _LOOSE:
            if len(loose.findall(text)) != len(strict.findall(text)):
                raise ValueError(f"DDL the live-schema check cannot read: {text.strip()[:120]!r}")
        if re.search(r"\bRENAME\s+TO\b|\bALTER\s+INDEX\b", text, re.I):
            raise ValueError(f"a rename the live-schema check cannot read: {text.strip()[:120]!r}")
        spans = _string_spans(text)
        events: list[tuple[int, str, re.Match[str]]] = []
        for kind, pattern in (
            ("table", _CREATE_TABLE),
            ("index", _CREATE_INDEX),
            ("alter", _ALTER_TABLE),
            ("rename", _SP_RENAME),
            ("droptable", _DROP_TABLE),
            ("dropindex", _DROP_INDEX),
        ):
            events.extend((m.start(), kind, m) for m in pattern.finditer(text))
        for _pos, kind, m in sorted(events, key=lambda e: e[0]):
            if kind == "table":
                reader.table(text, m)
            elif kind == "index":
                reader.index(text, m)
            elif kind == "alter":
                reader.alter(text, m, spans)
            elif kind == "rename":
                reader.rename(m)
            elif kind == "droptable":
                reader.drop_tables(m)
            else:
                reader.drop_indexes(m)
    return reader.shape()


# --- the compare ---------------------------------------------------------------------------------


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
    expected index that exists under its name to why it cannot serve, such as ``disabled``. A column
    both shapes describe is compared by :meth:`ColumnShape.core_differs` and
    :meth:`ColumnShape.collation_differs`, one clause for each that differs."""
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
    # Kept apart: on SQL Server an index name is unique only within its table, so an index named
    # like a table must not hide that table's columns.
    skip_tables = {n for n in taken if n in expected.columns}
    skip_indexes = {n for n in (set(taken) | set(unusable)) if n in expected.named_indexes}
    # A table that exists with no columns is not missing; the shared compare cannot tell the two
    # apart, because SQLite's read lists every table it asked for.
    empty = {
        t for t in expected.columns if t not in skip_tables and live.columns.get(t) == frozenset()
    }
    for table in sorted(empty):
        problems.extend(
            f"table {table!r} is missing column {col!r}" for col in sorted(expected.columns[table])
        )
    unread = skip_tables | empty
    rest = SchemaShape(
        MappingProxyType({t: c for t, c in expected.columns.items() if t not in unread}),
        expected.rowid_columns,
        MappingProxyType(
            {n: s for n, s in expected.named_indexes.items() if n not in skip_indexes}
        ),
        expected.constraint_indexes,
    )
    problems.extend(schema_differences(rest, live))
    if isinstance(expected, ServerSchemaShape) and isinstance(live, ServerSchemaShape):
        for table in sorted(set(expected.column_shapes) - skip_tables):
            got_table = live.column_shapes.get(table, {})
            for col, want in sorted(expected.column_shapes[table].items()):
                got = got_table.get(col)
                if got is None:
                    continue
                # Two clauses, so a long collation name never pushes the type and nullability past
                # the 200-character cut safe_exc makes. A live collation is named only where the
                # batch declares one to compare.
                if want.core_differs(got):
                    problems.append(
                        f"table {table!r} column {col!r} is {got.describe(collation=False)},"
                        f" expected {want.describe(collation=False)}"
                    )
                if want.collation_differs(got):
                    problems.append(
                        f"table {table!r} column {col!r} has collation {got.collation!r},"
                        f" expected {want.collation!r}"
                    )
    return problems


def live_shape(
    columns: Mapping[str, Iterable[str]],
    indexes: Mapping[str, IndexShape],
    column_shapes: Mapping[str, Mapping[str, ColumnShape]] | None = None,
) -> ServerSchemaShape:
    """A :class:`ServerSchemaShape` from what a backend read: columns per table, indexes by name,
    and each column's shape where the read gave one.

    Names are taken as given. The backend spells them as :func:`_ident` does: PostgreSQL's catalog
    already holds an unquoted name in lower case and a quoted ``"ID"`` as ``ID``, which must not
    pass for ``id``; SQL Server lower-cases its own, as its default collations compare."""
    return ServerSchemaShape(
        MappingProxyType({t: frozenset(cols) for t, cols in columns.items()}),
        MappingProxyType({}),
        MappingProxyType(dict(indexes)),
        frozenset(),
        MappingProxyType({t: MappingProxyType(dict(c)) for t, c in (column_shapes or {}).items()}),
    )


class ServerSchemaMismatchError(RuntimeError):
    """A server-DB store's schema lacks something this build's DDL batch creates, so the open refuses
    before writing the ``schema_meta`` marker (BACKLOG #1720).

    A ``RuntimeError`` the engine defines, so the CLI prints it whole as an engine refusal. Not the
    SQLite :class:`~messagefoundry.store.schema_verify.SchemaMismatchError`: that is a
    ``sqlite3.DatabaseError``, which the CLI reports against the SQLite store path, and its remedy
    moves a file aside. ``differences`` lists what was found, one clause each. ``database`` is the
    configured database, ``None`` when the setting is unset; ``schema`` is the schema the store's
    tables resolve into, which PostgreSQL names and SQL Server leaves ``None``."""

    def __init__(
        self,
        backend: str,
        database: str | None,
        differences: Iterable[str],
        schema: str | None = None,
    ) -> None:
        self.backend = backend
        self.database = database
        self.schema = schema
        self.differences = tuple(differences)
        where = (
            f"database {database!r}"
            if database is not None
            else "the connection's default database"
        )
        if schema is not None:
            where = f"schema {schema!r} of {where}"
        # A column numbered where this build does not number it, or the reverse.
        numbering = (
            "for a column whose identity differs, rebuild its table as this build declares it and"
            " copy the rows across, because SQL Server cannot add or remove an identity in place"
            if backend == "sqlserver"
            else "for a column whose numbering differs, add or drop its identity, or its nextval()"
            " default"
        )
        # The differences lead and the remedy follows. At least two paths that print this cut it
        # short, provision-schema at 500 characters and safe_exc at 200, while others, the CLI and
        # log.error among them, print it whole. The remedy is the same every time, so it is what a
        # cut may lose. It is split by kind of difference, so a table that only lacks a column, or
        # holds one of another type, is not told to give up its rows.
        super().__init__(
            f"{backend} schema differs: " + "; ".join(self.differences) + f". In {where}; the"
            " open refused and marked nothing current. Rename or drop an object that takes a name,"
            " or an index of another shape or that cannot serve; add a missing column, or alter a"
            " column of another type, nullability or collation, as this build declares it;"
            f" {numbering}; or use an empty database or schema. Then restart."
        )

    def __reduce__(self) -> tuple[type[ServerSchemaMismatchError], tuple[object, ...]]:
        # args holds only the message, so the default would call __init__ with it alone.
        return (type(self), (self.backend, self.database, self.differences, self.schema))


def refuse_short_schema(
    backend: str,
    database: str | None,
    expected: SchemaShape,
    column_rows: Iterable[tuple[str, str | None, str | None, ColumnShape | None]],
    indexes: Mapping[str, IndexShape],
    taken: Mapping[str, str],
    unusable: Mapping[str, str] | None = None,
    schema: str | None = None,
) -> None:
    """Raise :class:`ServerSchemaMismatchError`, logged at ERROR first, when the live schema falls
    short of ``expected``. The one place both backends turn what they read into a refusal.

    ``column_rows`` is ``(table, kind, column, shape)`` per live column: ``kind`` is ``None`` for a
    name nothing holds, ``"table"`` for a table, and otherwise the kind of object that holds the
    name; ``column`` is ``None`` for a table with no columns; ``shape`` is the column's
    :class:`ColumnShape`, or ``None`` where the read gave none. ``taken`` names the indexes another
    kind of object holds; the tables are added to it here. ``unusable`` is
    :func:`server_schema_differences`'. ``schema`` is :class:`ServerSchemaMismatchError`'s."""
    taken = dict(taken)
    columns: dict[str, set[str]] = {}
    shapes: dict[str, dict[str, ColumnShape]] = {}
    for table, kind, column, shape in column_rows:
        if kind is None:
            continue  # nothing holds the name: the compare reports the table missing
        if kind != "table":
            taken[table] = kind
            continue
        names = columns.setdefault(table, set())
        if column is not None:
            names.add(column)
            if shape is not None:
                shapes.setdefault(table, {})[column] = shape
    problems = server_schema_differences(
        expected, live_shape(columns, indexes, shapes), taken, unusable
    )
    if problems:
        exc = ServerSchemaMismatchError(backend, database, problems, schema)
        log.error("%s", exc)  # the message already leads with the backend
        raise exc
