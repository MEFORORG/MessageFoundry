# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1720: a server-DB open reads the live schema before it writes the ``schema_meta`` marker.

The PostgreSQL and SQL Server DDL batches are additive and guarded, so each guarded CREATE skips a
name that is already taken, whatever holds it. The filing's case: on PostgreSQL a relation named
``ix_queue_fifo_in_seq`` makes ``CREATE INDEX IF NOT EXISTS`` a no-op, the open succeeds, and the
marker records a schema whose index was never built, so every later open takes the ADR 0064 fast path
past it. Each backend now compares the live catalog with what its batch declares, after the batch and
before the marker, and refuses the open naming the table, column or index.

The offline tests drive ``_ensure_schema`` through fake connections and need no server. The live legs
are gated PER TEST on ``MEFOR_TEST_POSTGRES`` / ``MEFOR_TEST_SQLSERVER``, each in a scratch schema or
database of its own that it drops afterwards. The ``postgres-store`` and ``sqlserver-store`` jobs in
``.github/workflows/ci.yml`` run this file.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import inspect
import logging
import os
import pathlib
import pickle
import re
import subprocess
import textwrap
import types
from collections.abc import AsyncIterator, Mapping
from typing import Any

import pytest

from messagefoundry.config.settings import SchemaManagement, StoreSettings
from messagefoundry.logging_setup import RedactionFilter
from messagefoundry.redaction import safe_exc
from messagefoundry.store.pool_metrics import AcquireWaitHistogram
from messagefoundry.store.schema_verify import IndexShape, SchemaShape
from messagefoundry.store.server_schema_verify import (
    ColumnShape,
    ServerSchemaMismatchError,
    ServerSchemaShape,
    declared_column,
    declared_schema,
    key_column,
    live_shape,
    mssql_live_type,
    refuse_short_schema,
    server_schema_differences,
)
from tests._server_schema_rows import mssql_declared, mssql_live_rows, pg_declared, pg_live_rows

_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))
_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))

_FIFO = "ix_queue_fifo_in_seq"
_FIFO_SHAPE = IndexShape("queue", ("stage", "channel_id", "status", "seq"), False, False)


def _shapes(shape: SchemaShape) -> Mapping[str, Mapping[str, ColumnShape]]:
    return shape.column_shapes if isinstance(shape, ServerSchemaShape) else {}


def _without_column(shape: SchemaShape, table: str, column: str) -> SchemaShape:
    cols = dict(shape.columns)
    cols[table] = cols[table] - {column}
    return live_shape(cols, shape.named_indexes, _shapes(shape))


def _with_index(shape: SchemaShape, name: str, index: IndexShape | None) -> SchemaShape:
    indexes = dict(shape.named_indexes)
    if index is None:
        del indexes[name]
    else:
        indexes[name] = index
    return live_shape(shape.columns, indexes, _shapes(shape))


def _with_column(shape: SchemaShape, table: str, column: str, col: ColumnShape) -> SchemaShape:
    shapes = {t: dict(c) for t, c in _shapes(shape).items()}
    shapes[table][column] = col
    return live_shape(shape.columns, shape.named_indexes, shapes)


# --- what each batch declares --------------------------------------------------------------------


def test_postgres_declares_the_indexes_its_migration_builds() -> None:
    """The filing's index is built in ``_migrate_lease_columns``, outside ``_SCHEMA``, so the check
    must read the migration's DDL too. Literal expectations, not read back from the parser."""
    declared = pg_declared()
    assert declared.named_indexes[_FIFO] == _FIFO_SHAPE
    assert declared.named_indexes["ix_queue_fifo_out_seq"] == IndexShape(
        "queue", ("stage", "destination_name", "status", "seq"), False, False
    )
    assert declared.named_indexes["ix_queue_lease"] == IndexShape(
        "queue", ("lease_expires_at",), False, True
    )
    assert declared.named_indexes["ix_messages_received"].columns == ("received_at", "id")
    assert declared.named_indexes["ix_queue_body_ref"].columns == ("body_ref",)
    # An expression key reads as <expr>, which is what the live read turns it into as well.
    assert declared.named_indexes["ix_audit_actor"].columns == ("<expr>", "action", "id")
    assert declared.named_indexes["ux_users_federated_subject"].partial
    # A table the batch drops, and the indexes the migration drops, are not expected.
    assert "upload_quota" not in declared.columns
    assert "ix_queue_fifo_in" not in declared.named_indexes


def test_sqlserver_declares_what_its_guarded_batch_builds() -> None:
    declared = mssql_declared()
    assert declared.named_indexes[_FIFO] == _FIFO_SHAPE
    assert declared.named_indexes["ux_alert_instance_open"] == IndexShape(
        "alert_instance", ("event_type", "connection"), True, True
    )
    # Columns an `IF COL_LENGTH(...) IS NULL ALTER TABLE ... ADD` adds, and one added with a
    # named default constraint.
    assert {"origin", "origin_actor", "documents_pruned"} <= declared.columns["messages"]
    assert "kind" in declared.columns["response"]
    assert "constraint" not in declared.columns["response"]
    # Dropped by the batch: the retired tables and the pre-ADR-0060 index names.
    assert "outbox" not in declared.columns
    assert "upload_quota" not in declared.columns
    assert "ix_queue_fifo_in" not in declared.named_indexes


def _migration_added_columns() -> set[tuple[str, str]]:
    """Every ``(table, column)`` ``_migrate_lease_columns`` adds, read from its source."""
    from messagefoundry.store import postgres

    source = inspect.getsource(postgres.PostgresStore._migrate_lease_columns)
    added = set(re.findall(r"ALTER TABLE (\w+) ADD COLUMN (\w+)", source))
    added |= {("users", col) for col in re.findall(r'^\s+\("(\w+)", "', source, re.M)}
    assert len(added) >= 20  # positive control: the reads above found the migration's columns
    return added


def test_every_column_the_postgres_migration_adds_is_in_the_batch() -> None:
    """The check reads columns from the batch alone, which holds because every column
    ``_migrate_lease_columns`` adds to an older table is also in that table's CREATE TABLE. A new
    migration column that is not would go unchecked, so this pins the premise."""
    added = _migration_added_columns()
    assert len(added) >= 20  # positive control: the walk below checks the migration's columns
    declared = pg_declared()
    missing = sorted(f"{t}.{c}" for t, c in added if c not in declared.columns.get(t, ()))
    assert not missing, missing


def test_every_index_the_postgres_migration_builds_is_one_the_check_reads() -> None:
    """The check reads ``_MIGRATION_INDEX_DDL``, a list kept beside the migration rather than run
    by it, so an index the migration builds from a literal would go unchecked. Pin both halves."""
    from messagefoundry.store import postgres

    source = inspect.getsource(postgres.PostgresStore._migrate_lease_columns)
    tree = ast.parse(textwrap.dedent(source))
    func = tree.body[0]
    assert isinstance(func, ast.AsyncFunctionDef)
    docstring = func.body[0]
    # Every string in the body but the docstring, whatever its quoting, and every f-string part.
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        if not (isinstance(docstring, ast.Expr) and node is docstring.value)
    ]
    assert literals  # positive control: the walk sees the migration's ALTER literals
    assert not [s for s in literals if re.search(r"CREATE\s+(UNIQUE\s+)?INDEX", s, re.I)]
    # BACKLOG #5062: an index the migration drops is read too, so it is not expected.
    assert not [s for s in literals if re.search(r"DROP\s+INDEX", s, re.I)]
    built = set(re.findall(r"execute\(\s*(_[A-Z_]+_DDL)\b", source))
    declared = {
        name
        for name, value in vars(postgres).items()
        if name.endswith("_DDL") and value in postgres._MIGRATION_INDEX_DDL
    }
    assert built == declared and len(built) == len(postgres._MIGRATION_INDEX_DDL)


_NAME_PART = r'(?:"?\w+"?\s*\.\s*)?"?(\w+)"?'
_INDEX_ON = re.compile(
    rf"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b.*?\bON\s+(?:ONLY\s+)?{_NAME_PART}\s*(?:USING\s+\w+\s*)?\((.*)",
    re.I | re.S,
)
#: What gives an older table a column: an ADD, or a column rename, anywhere in a statement.
_SUPPLIES_COLUMN = (
    re.compile(
        rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{_NAME_PART}\s+ADD\s+(?:COLUMN\s+)?"
        r'(?:IF\s+NOT\s+EXISTS\s+)?"?(\w+)"?',
        re.I,
    ),
    re.compile(
        rf'\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?{_NAME_PART}\s+RENAME\s+COLUMN\s+"?\w+"?'
        r'\s+TO\s+"?(\w+)"?',
        re.I,
    ),
)


def _indexes_before_their_columns(statements: list[str] | tuple[str, ...]) -> list[str]:
    """``table.column`` for each index in ``statements`` that keys or filters on a column an older
    table gets only later: from an ADD or a rename further on in ``statements``, or from
    ``_migrate_lease_columns``, which runs after them. Only index builds are read."""
    pending = set(_migration_added_columns())
    hits: list[str] = []
    for statement in reversed(statements):
        m = _INDEX_ON.search(statement)
        if m is not None:
            table, rest = m.group(1).lower(), m.group(2).lower()
            hits += [f"{t}.{c}" for t, c in pending if t == table and re.search(rf"\b{c}\b", rest)]
        for pattern in _SUPPLIES_COLUMN:
            pending |= {(t.lower(), c.lower()) for t, c in pattern.findall(statement)}
    return sorted(hits)


def test_no_postgres_batch_index_needs_a_column_its_table_gets_later() -> None:
    """BACKLOG #1720: on an older table, a column the batch's own guarded ADD or the migration
    supplies exists only once that has run, so an index built before it fails with the driver's
    undefined-column error, before the live-schema check can name the store's differences. That is
    how ``ux_users_federated_subject`` stopped a v0.3.2 store; it is built in the migration now."""
    from messagefoundry.store import postgres

    # Positive controls: the index this was found in, as it read in _SCHEMA, and a batch ADD
    # after an index on its column, with a qualified, quoted, upper-case spelling. Then the order
    # that is safe.
    assert _indexes_before_their_columns([postgres._FEDERATED_SUBJECT_INDEX_DDL]) == [
        "users.oidc_issuer",
        "users.oidc_subject",
    ]
    late = [
        'CREATE INDEX IF NOT EXISTS ix_s ON public."sessions"(USER_EPOCH)',
        "DO $$ BEGIN ALTER TABLE sessions ADD COLUMN user_epoch INTEGER; END $$",
    ]
    assert _indexes_before_their_columns(late) == ["sessions.user_epoch"]
    assert _indexes_before_their_columns(late[::-1]) == []
    assert _indexes_before_their_columns(postgres._SCHEMA) == []


def test_the_parser_reads_ddl_in_order() -> None:
    statements = (
        "-- a comment naming CREATE TABLE ghost (x INT)\n"
        'CREATE TABLE IF NOT EXISTS "t" (id INTEGER PRIMARY KEY, amount DECIMAL(10, 2),'
        " CONSTRAINT ck CHECK (amount > 0), PRIMARY KEY (id), UNIQUE (amount))",
        "CREATE UNIQUE NONCLUSTERED INDEX ix_t ON dbo.t(amount DESC, id) INCLUDE (x) WHERE id > 0",
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1) THEN ALTER TABLE t ADD COLUMN extra TEXT; END IF;"
        " END $$",
        "IF COL_LENGTH('t','more') IS NULL ALTER TABLE [t] ADD [more] INT",
        "ALTER TABLE t ADD CONSTRAINT pk PRIMARY KEY (id)",
        "ALTER TABLE t DROP COLUMN more",
        "CREATE TABLE gone (a INT)",
        "CREATE INDEX ix_gone ON gone(a)",
        "DROP TABLE IF EXISTS gone",
        "CREATE INDEX ix_old ON t(id)",
        "DROP INDEX ix_old ON t",
    )
    shape = declared_schema(statements)
    assert dict(shape.columns) == {"t": frozenset({"id", "amount", "extra"})}
    assert dict(shape.named_indexes) == {"ix_t": IndexShape("t", ("amount DESC", "id"), True, True)}


def test_the_parser_reads_clauses_between_the_keys_and_the_where() -> None:
    for tail in (
        "WITH (fillfactor = 70)",
        "TABLESPACE fast",
        "NULLS NOT DISTINCT",
        "INCLUDE (b) NULLS DISTINCT WITH (deduplicate_items = off) TABLESPACE fast",
    ):
        shape = declared_schema((f"CREATE INDEX ix_w ON t (a) {tail} WHERE a > 0",))
        assert shape.named_indexes["ix_w"].partial, tail
    assert (
        not declared_schema(("CREATE INDEX ix_w ON t (a) WITH (fillfactor = 70)",))
        .named_indexes["ix_w"]
        .partial
    )


@pytest.mark.parametrize(
    ("statement", "match"),
    [
        ("CREATE TABLE broken (id INT", "unbalanced"),
        ("CREATE INDEX ix_g ON t USING gin (a)", "access method"),
        ('CREATE INDEX ix_c ON t (name COLLATE "C")', "options"),
        ("CREATE INDEX ix_n ON t (seq DESC NULLS LAST)", "options"),
        # An expression key read as "<expr>" without its DESC would refuse a correct index.
        ("CREATE INDEX ix_e ON t (lower(name) DESC NULLS LAST)", "options"),
        ("CREATE INDEX ix_f ON t ((a + b) NULLS FIRST)", "options"),
        ("CREATE INDEX ix_o ON t (body text_pattern_ops)", "options"),
        ("CREATE INDEX CONCURRENTLY ix_k ON t (a)", "cannot read"),
        ("CREATE TABLE IF NOT EXISTS public . odd (a INT)", "cannot read"),
    ],
)
def test_the_parser_refuses_ddl_it_would_misread(statement: str, match: str) -> None:
    """Each of these would otherwise be skipped or read wrong, and so go unchecked or refuse a
    correct schema on every open."""
    with pytest.raises(ValueError, match=match):
        declared_schema((statement,))


def test_an_expression_key_keeps_its_direction_without_a_nulls_order() -> None:
    """The control for the NULLS refusals above: the same expression keys read, with their DESC."""
    shape = declared_schema(("CREATE INDEX ix_e ON t (lower(name) DESC, (a + b))",))
    assert shape.named_indexes["ix_e"].columns == ("<expr> DESC", "<expr>")


def test_a_quoted_name_keeps_its_case_and_an_unquoted_one_folds() -> None:
    """PostgreSQL folds an unquoted name and keeps a quoted one, so a live ``"ID"`` is not ``id``."""
    shape = declared_schema(('CREATE TABLE T ("Mixed" INT, Plain INT)',))
    assert dict(shape.columns) == {"t": frozenset({"Mixed", "plain"})}
    assert key_column('"ID"') == "ID"
    live = live_shape({"t": {"ID"}}, {})
    expected = live_shape({"t": {"id"}}, {})
    assert server_schema_differences(expected, live, {}) == ["table 't' is missing column 'id'"]


def test_key_columns_normalise_the_same_way_on_both_sides() -> None:
    assert key_column("Seq") == "seq"
    assert key_column('"key" DESC') == "key DESC"
    assert key_column("[status] ASC") == "status"
    assert key_column('"left"(actor, 200)') == "<expr>"
    assert key_column("lower(name) DESC") == "<expr> DESC"
    assert key_column("<expr>") == "<expr>"


# --- the compare ---------------------------------------------------------------------------------


def test_the_compare_names_each_shortfall_and_tolerates_extras() -> None:
    expected = live_shape({"queue": {"stage", "seq"}, "messages": {"id"}}, {_FIFO: _FIFO_SHAPE})
    assert server_schema_differences(expected, expected, {}) == []
    extra = live_shape(
        {"queue": {"stage", "seq", "extra"}, "messages": {"id"}, "other": {"x"}},
        {_FIFO: _FIFO_SHAPE, "ix_mine": IndexShape("queue", ("extra",), False, False)},
    )
    assert server_schema_differences(expected, extra, {}) == []
    short = live_shape({"queue": {"stage"}}, {_FIFO: IndexShape("queue", ("stage",), False, False)})
    assert server_schema_differences(expected, short, {}) == [
        "table 'messages' is missing",
        "table 'queue' is missing column 'seq'",
        f"index {_FIFO!r} is on queue(stage), expected on queue(stage, channel_id, status, seq)",
    ]


def test_a_name_held_by_another_kind_of_object_says_so() -> None:
    expected = live_shape({"queue": {"seq"}, "messages": {"id"}}, {_FIFO: _FIFO_SHAPE})
    live = live_shape({"queue": {"seq"}}, {})
    assert server_schema_differences(expected, live, {_FIFO: "table", "messages": "index"}) == [
        f"index {_FIFO!r} was never built: the name is taken by a table"
        " (expected on queue(stage, channel_id, status, seq))",
        "table 'messages' was never created: the name is taken by an index",
    ]


def test_an_index_that_exists_but_cannot_serve_says_why() -> None:
    expected = live_shape({"queue": {"seq"}}, {_FIFO: _FIFO_SHAPE})
    live = live_shape({"queue": {"seq"}}, {_FIFO: _FIFO_SHAPE})
    assert server_schema_differences(expected, live, {}, {_FIFO: "disabled"}) == [
        f"index {_FIFO!r} exists but is disabled"
        " (expected on queue(stage, channel_id, status, seq))"
    ]


def test_the_refusal_leads_with_the_differences_and_is_an_engine_refusal() -> None:
    exc = ServerSchemaMismatchError("postgres", "mf", ["table 'queue' is missing column 'seq'"])
    assert isinstance(exc, RuntimeError)
    assert type(exc).__module__.startswith("messagefoundry.")  # printed whole by the CLI
    text = str(exc)
    assert text.startswith("postgres schema differs: table 'queue' is missing column 'seq'. In ")
    assert text.index("missing column 'seq'") < text.index("Rename or drop")
    assert exc.differences == ("table 'queue' is missing column 'seq'",)
    copied = pickle.loads(pickle.dumps(exc))
    assert (str(copied), copied.differences, copied.database) == (text, exc.differences, "mf")


def test_the_refusal_names_where_it_looked_and_scopes_its_remedy() -> None:
    """The Postgres schema is named, an unset database setting never prints as ``None``, and a table
    that only lacks a column is told to gain it, never to be renamed or dropped."""
    exc = ServerSchemaMismatchError("postgres", "mf", ["x"], "tenant_b")
    assert ". In schema 'tenant_b' of database 'mf'; the open refused" in str(exc)
    copied = pickle.loads(pickle.dumps(exc))
    assert (str(copied), copied.schema) == (str(exc), "tenant_b")
    unset = ServerSchemaMismatchError("sqlserver", None, ["x"])
    assert "None" not in str(unset)
    assert ". In the connection's default database; the open refused" in str(unset)
    text = str(ServerSchemaMismatchError("postgres", "mf", ["x"]))
    assert ". In database 'mf'; the open refused" in text
    remedy = text[text.index("Rename or drop") :]
    # BACKLOG #5085: a column of another type or nullability is told to be altered, not dropped.
    assert (
        "add a missing column, or alter a column of another type, nullability or collation, as"
        " this build declares it" in remedy
    )
    # A numbering difference gets its own step on each backend.
    assert "add or drop its identity, or its nextval() default" in remedy
    sqlserver = str(ServerSchemaMismatchError("sqlserver", "mf", ["x"]))
    assert "SQL Server cannot add or remove an identity in place" in sqlserver
    # The rename-or-drop remedy is scoped to a taken name or an index, never to a whole table.
    rename = remedy[: remedy.index(";")]
    assert rename == (
        "Rename or drop an object that takes a name, or an index of another shape or that cannot"
        " serve"
    )


#: A schema-qualified ``unnest`` call with two or more arguments. PostgreSQL rewrites a multi-argument
#: ``unnest`` in FROM into ROWS FROM only when the name is unqualified, so the qualified form raises
#: UndefinedFunction. The fakes match the SQL as a string and cannot see that.
_QUALIFIED_MULTI_UNNEST = re.compile(r"pg_catalog\.unnest\s*\([^()]*,", re.IGNORECASE)


def test_no_live_schema_read_calls_a_qualified_multi_argument_unnest() -> None:
    """Only the live ``postgres-store`` leg proves the query runs; this pins the one shape known to
    fail, in every SQL constant the Postgres store and the shared check define."""
    from messagefoundry.store import postgres, server_schema_verify

    assert _QUALIFIED_MULTI_UNNEST.search("FROM pg_catalog.unnest($1::text[], $2::text[]) AS q")
    assert not _QUALIFIED_MULTI_UNNEST.search("FROM pg_catalog.unnest($1::text[]) AS t(name)")
    # server_schema_verify defines no SQL today, so it has no floor; it stays in the walk so a
    # constant added there is scanned too.
    modules = (postgres, server_schema_verify)
    texts = [
        (module.__name__, value)
        for module in modules
        for key, value in vars(module).items()
        if isinstance(value, str) and not (key.startswith("__") and key.endswith("__"))
    ]
    # Positive control: the walk reads the Postgres store's SQL. A module's dunder strings are not
    # SQL and are left out, because counting them made the control hold on a module with no SQL
    # constant at all, and the count then moved with the interpreter (3.15 stopped setting
    # __cached__).
    select = re.compile(r"\bSELECT\b", re.IGNORECASE)
    queries = [t for name, t in texts if name == postgres.__name__ and select.search(t)]
    assert len(queries) > 5, f"{postgres.__name__}: no SQL constants read"
    assert postgres._LIVE_COLUMNS_SQL in queries and postgres._LIVE_INDEXES_SQL in queries
    assert len(texts) > 10  # the walk read 66 non-dunder constants on 3.14 and 3.15
    offenders = [f"{name}: {text}" for name, text in texts if _QUALIFIED_MULTI_UNNEST.search(text)]
    assert offenders == [], offenders
    assert "ROWS FROM (pg_catalog.unnest($1::text[]), pg_catalog.unnest($2::text[]))" in (
        postgres._LIVE_INDEXES_SQL
    )


# --- PostgreSQL _ensure_schema, through a fake connection ------------------------------------------


class _PgConn:
    """The schema transaction's connection. The marker reads stale, every statement is recorded, and
    the two live-schema reads answer from ``shape`` and ``kinds``."""

    def __init__(
        self,
        shape: SchemaShape | None = None,
        kinds: Mapping[str, str] | None = None,
        overrides: Mapping[str, Mapping[str, Any]] | None = None,
    ):
        self.shape, self.kinds, self.overrides = shape, kinds, overrides
        self.executed: list[str] = []

    async def fetch(self, sql: str, *args: Any) -> list[Any]:
        return pg_live_rows(sql, args, self.shape, self.kinds, self.overrides)

    async def execute(self, sql: str, *args: Any, timeout: object = None) -> str:
        self.executed.append(sql)
        return ""

    @contextlib.asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        self.executed.append("BEGIN")
        try:
            yield
        except BaseException:
            self.executed.append("ROLLBACK")
            raise
        self.executed.append("COMMIT")

    def marker_written(self) -> bool:
        return any(sql.startswith("INSERT INTO schema_meta") for sql in self.executed)


def _pg_store(conn: _PgConn) -> Any:
    from messagefoundry.store import postgres

    store = postgres.PostgresStore.__new__(postgres.PostgresStore)
    store._settings = types.SimpleNamespace(  # type: ignore[assignment]
        db_schema=None,
        database="mf_test",
        resolved_schema_management=lambda: SchemaManagement.AUTO,
        schema_lock_timeout=StoreSettings().schema_lock_timeout,
    )

    @contextlib.asynccontextmanager
    async def _acquire(*, record: bool = True) -> AsyncIterator[Any]:
        yield conn

    async def _stale(_conn: Any, _expected: str) -> bool:
        return False

    store._timed_acquire = _acquire  # type: ignore[method-assign]
    store._schema_marker_current = _stale  # type: ignore[method-assign,assignment]
    return store


async def test_postgres_writes_the_marker_after_a_clean_check() -> None:
    """The control arm: a database holding what the batch declares opens and is marked."""
    conn = _PgConn()
    assert await _pg_store(conn)._ensure_schema() is True
    assert conn.marker_written()
    assert conn.executed[-1] == "COMMIT"


async def test_postgres_refuses_a_relation_holding_the_fifo_index_name() -> None:
    """The filing's case: a table named ``ix_queue_fifo_in_seq`` made the build a no-op."""
    conn = _PgConn(kinds={_FIFO: "r"})
    with pytest.raises(ServerSchemaMismatchError) as caught:
        await _pg_store(conn)._ensure_schema()
    assert f"index {_FIFO!r} was never built: the name is taken by a table" in str(caught.value)
    assert not conn.marker_written()
    assert conn.executed[-1] == "ROLLBACK"


async def test_postgres_refuses_a_same_named_index_of_another_shape() -> None:
    wrong = IndexShape("queue", ("stage", "channel_id", "status", "created_at"), False, False)
    conn = _PgConn(_with_index(pg_declared(), _FIFO, wrong))
    with pytest.raises(ServerSchemaMismatchError, match=r"is on queue\(stage, channel_id, status"):
        await _pg_store(conn)._ensure_schema()
    assert not conn.marker_written()


async def test_postgres_refuses_a_table_missing_a_column() -> None:
    conn = _PgConn(_without_column(pg_declared(), "transit_bound_attestation", "audit_hash"))
    with pytest.raises(ServerSchemaMismatchError) as caught:
        await _pg_store(conn)._ensure_schema()
    assert caught.value.differences == (
        "table 'transit_bound_attestation' is missing column 'audit_hash'",
    )
    assert "schema 'public' of database 'mf_test'" in str(caught.value)
    assert not conn.marker_written()


@pytest.mark.parametrize(
    ("override", "why"),
    [
        ({"usable": False}, "invalid: a build that never finished"),
        ({"method": "brin"}, "a brin index, not btree"),
    ],
)
async def test_postgres_refuses_a_right_shaped_index_that_cannot_serve(
    override: dict[str, Any], why: str
) -> None:
    """A failed CREATE INDEX CONCURRENTLY, or an index of another method, with the declared name,
    table and keys: the guarded CREATE skips it and the shape compare alone would pass it."""
    conn = _PgConn(overrides={_FIFO: override})
    with pytest.raises(ServerSchemaMismatchError) as caught:
        await _pg_store(conn)._ensure_schema()
    assert caught.value.differences == (
        f"index {_FIFO!r} exists but is {why} (expected on queue(stage, channel_id, status, seq))",
    )
    assert not conn.marker_written()


class _TwoSchemaPgConn(_PgConn):
    """Two stores in one PostgreSQL database, in different schemas. The other schema holds every
    table with every column. This one holds the same tables less each column the migration adds,
    until the migration's ``ADD`` runs here. A catalog read scoped to ``current_schema()`` sees this
    schema alone; an unscoped one sees the other schema's columns too, as ``information_schema``
    does for a role that can read both."""

    def __init__(self) -> None:
        super().__init__()
        self.other = pg_declared()
        self.missing = _migration_added_columns()
        self.unscoped: list[str] = []

    def here(self) -> SchemaShape:
        return live_shape(
            {
                table: cols - {c for t, c in self.missing if t == table}
                for table, cols in self.other.columns.items()
            },
            self.other.named_indexes,
            _shapes(self.other),
        )

    async def fetch(self, sql: str, *args: Any) -> list[Any]:
        if "information_schema.columns" not in sql:
            return pg_live_rows(sql, args, self.here())
        table = re.search(r"table_name\s*=\s*'(\w+)'", sql)
        assert table is not None, sql
        scoped = "table_schema = current_schema()" in sql
        if not scoped:
            self.unscoped.append(sql)
        holders = [self.here()] if scoped else [self.here(), self.other]
        present = {c for shape in holders for c in shape.columns.get(table[1], ())}
        named = re.search(r"column_name\s*=\s*'(\w+)'", sql)
        wanted = set(args[0]) if args else ({named[1]} if named else present)
        return [{"column_name": c} for c in sorted(present & wanted)]

    async def execute(self, sql: str, *args: Any, timeout: object = None) -> str:
        if added := re.match(r"ALTER TABLE (\w+) ADD COLUMN (\w+)", sql):
            self.missing.discard((added[1], added[2]))
        return await super().execute(sql, *args, timeout=timeout)


async def test_postgres_migration_reads_only_its_own_schema() -> None:
    """A second store in another schema of the same database must not answer for this one. With the
    migration's catalog reads unscoped, the other schema's columns made every guarded ``ADD`` skip,
    and the live-schema check then refused the open for the columns the migration never added."""
    conn = _TwoSchemaPgConn()
    assert conn.missing  # positive control: this schema starts short of the migration's columns
    assert await _pg_store(conn)._ensure_schema() is True
    assert conn.unscoped == []
    assert conn.missing == set()
    assert conn.marker_written()


# --- SQL Server _ensure_schema, through a fake cursor ----------------------------------------------


class _MsCursor:
    def __init__(self, conn: _MsConn) -> None:
        self._conn = conn
        self.description = None

    async def execute(self, sql: str, params: object = None) -> None:
        self._conn.executed.append((sql, params, self._conn._conn.timeout))

    async def fetchone(self) -> object:
        sql = self._conn.executed[-1][0]
        if "OBJECT_ID('schema_meta'" in sql or "schema_hash" in sql:
            return (None,)  # no marker: the open runs the batch
        return (0,)  # sp_getapplock granted

    async def fetchall(self) -> list[object]:
        sql, params, _timeout = self._conn.executed[-1]
        rows = mssql_live_rows(sql, params, self._conn.shape, flags=self._conn.flags)  # type: ignore[arg-type]
        return list(rows)

    async def close(self) -> None:
        pass


class _MsConn:
    def __init__(
        self,
        shape: SchemaShape | None = None,
        flags: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self.shape, self.flags = shape, flags
        self.executed: list[tuple[str, object, object]] = []
        self._conn = types.SimpleNamespace(timeout=None)
        self.committed = 0
        self.rolledback = 0

    async def cursor(self) -> _MsCursor:
        return _MsCursor(self)

    async def commit(self) -> None:
        self.committed += 1

    async def rollback(self) -> None:
        self.rolledback += 1

    def marker_written(self) -> bool:
        return any("schema_meta" in sql and "INSERT" in sql for sql, _p, _t in self.executed)


class _MsPool:
    def __init__(self, conn: _MsConn) -> None:
        self._conn = conn

    async def acquire(self) -> object:
        return self._conn

    async def release(self, conn: object) -> None:
        return None


def _ms_store(conn: _MsConn) -> Any:
    from messagefoundry.store.sqlserver import SqlServerStore

    store = SqlServerStore.__new__(SqlServerStore)
    store._pool = _MsPool(conn)
    store._settings = types.SimpleNamespace(  # type: ignore[assignment]
        command_timeout=30,
        schema_lock_timeout=StoreSettings().schema_lock_timeout,
        acquire_timeout=30.0,
        database="mf_test",
        resolved_schema_management=lambda: SchemaManagement.AUTO,
    )
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0
    store.body_copies = 0
    return store


async def test_sqlserver_writes_the_marker_after_a_clean_check_under_the_batch_timeout() -> None:
    """The control arm, and where the reads run: after the last batch statement, before the marker,
    on the batch's cursor with its lifted query timeout (0), not a timeout of their own."""
    from messagefoundry.store.sqlserver import _SCHEMA

    conn = _MsConn()
    assert await _ms_store(conn)._ensure_schema() is True
    sqls = [sql for sql, _p, _t in conn.executed]
    reads = [i for i, sql in enumerate(sqls) if sql.startswith("SELECT v.")]
    assert len(reads) == 2
    last_ddl = max(i for i, sql in enumerate(sqls) if sql == _SCHEMA[-1])
    delete = sqls.index("DELETE FROM schema_meta WHERE id=1")
    assert last_ddl < reads[0] < reads[1] < delete
    assert all(conn.executed[i][2] == 0 for i in reads)
    assert conn.marker_written()
    assert conn.committed >= 1


async def test_sqlserver_refuses_a_same_named_index_of_another_shape() -> None:
    """SQL Server's guard is ``IF INDEXPROPERTY(OBJECT_ID('queue'), name, 'IndexID') IS NULL``, so
    an index of that name on ``queue`` with another key skips the build."""
    wrong = IndexShape("queue", ("created_at",), False, False)
    conn = _MsConn(_with_index(mssql_declared(), _FIFO, wrong))
    with pytest.raises(ServerSchemaMismatchError) as caught:
        await _ms_store(conn)._ensure_schema()
    assert caught.value.differences == (
        f"index {_FIFO!r} is on queue(created_at), expected on queue(stage, channel_id, status, seq)",
    )
    assert not conn.marker_written()
    assert conn.rolledback >= 1


async def test_sqlserver_refuses_a_missing_index_and_a_missing_column() -> None:
    shape = _without_column(mssql_declared(), "messages", "origin")
    conn = _MsConn(_with_index(shape, "ix_queue_body_ref", None))
    with pytest.raises(ServerSchemaMismatchError) as caught:
        await _ms_store(conn)._ensure_schema()
    assert caught.value.differences == (
        "table 'messages' is missing column 'origin'",
        "index 'ix_queue_body_ref' is missing (expected on queue(body_ref))",
    )
    assert not conn.marker_written()


@pytest.mark.parametrize(
    ("flag", "clause"),
    [
        ({"disabled": True}, "exists but is disabled"),
        ({"hypothetical": True}, "exists but is hypothetical"),
        ({"stats_only": True}, "was never built: the name is taken by a statistics object"),
    ],
)
async def test_sqlserver_refuses_a_name_its_guard_skips_for_an_index_that_does_not_serve(
    flag: dict[str, Any], clause: str
) -> None:
    """``INDEXPROPERTY(..., 'IndexID')`` is non-NULL for each, so the guarded CREATE skips it. A
    disabled unique index enforces nothing, so its keys alone must not pass the check."""
    conn = _MsConn(flags={"ux_users_federated_subject": flag})
    with pytest.raises(ServerSchemaMismatchError) as caught:
        await _ms_store(conn)._ensure_schema()
    [difference] = caught.value.differences
    assert difference.startswith(f"index 'ux_users_federated_subject' {clause}")
    assert not conn.marker_written()


# --- the live legs ---------------------------------------------------------------------------------


@pytest.mark.skipif(not _POSTGRES_ON, reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env)")
@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        (
            "CREATE TABLE {schema}.ix_queue_fifo_in_seq (x INTEGER)",
            "index 'ix_queue_fifo_in_seq' was never built: the name is taken by a table",
        ),
        (
            "CREATE TABLE {schema}.transit_bound_attestation (id INTEGER PRIMARY KEY)",
            "table 'transit_bound_attestation' is missing column 'audit_hash'",
        ),
    ],
    ids=["colliding-relation", "missing-column"],
)
async def test_live_postgres_open_refuses_and_marks_nothing(setup: str, expected: str) -> None:
    """In a scratch schema of its own: the open refuses, rolls the whole batch back so no marker
    exists, and opens once the object it named is dropped."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore
    from tests._live_scratch import postgres_teardown, scratch_name

    base = load_settings(environ=os.environ).store
    schema = scratch_name("mefor_b1720")
    scratch = base.model_copy(update={"db_schema": schema})
    admin = await PostgresStore.open(base)
    try:
        await admin._execute(f"CREATE SCHEMA {schema}")
        await admin._execute(setup.format(schema=schema))
        with pytest.raises(ServerSchemaMismatchError) as caught:
            # Closed if it opens after all, so the pool does not outlive its schema's teardown.
            await (await PostgresStore.open(scratch)).close()
        assert expected in str(caught.value)
        row = await admin._fetchone(
            "SELECT pg_catalog.to_regclass($1) IS NULL AS absent", f"{schema}.schema_meta"
        )
        assert row is not None and row["absent"]  # rolled back with the batch: nothing marked
        dropped = setup.split(" (")[0].replace("CREATE TABLE", "DROP TABLE")
        await admin._execute(dropped.format(schema=schema))
        store = await PostgresStore.open(scratch)
        await store.close()
    finally:
        await postgres_teardown(admin, database=None, schemas=[schema])
        await admin.close()


@pytest.mark.skipif(not _POSTGRES_ON, reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env)")
async def test_live_postgres_migration_adds_a_column_another_schema_holds() -> None:
    """Two stores in one database: schema A's ``queue`` keeps ``owner``, schema B's has lost it and
    its marker. Reopening B must ADD the column in B and open, not read A's column as B's and
    refuse."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore
    from tests._live_scratch import postgres_teardown, scratch_name

    base = load_settings(environ=os.environ).store
    schemas = [scratch_name("mefor_b1720a"), scratch_name("mefor_b1720b")]
    mine = schemas[1]
    admin = await PostgresStore.open(base)
    try:
        for schema in schemas:
            await admin._execute(f"CREATE SCHEMA {schema}")
            await (await PostgresStore.open(base.model_copy(update={"db_schema": schema}))).close()
        await admin._execute(f"ALTER TABLE {mine}.queue DROP COLUMN owner")
        await admin._execute(f"DELETE FROM {mine}.schema_meta")
        store = await PostgresStore.open(base.model_copy(update={"db_schema": mine}))
        await store.close()
        rows = await admin._fetchall(
            "SELECT table_schema FROM information_schema.columns"
            " WHERE table_name = 'queue' AND column_name = 'owner'"
            " AND table_schema = ANY($1::text[])",
            schemas,
        )
        assert sorted(str(r["table_schema"]) for r in rows) == sorted(schemas)
    finally:
        await postgres_teardown(admin, database=None, schemas=schemas)
        await admin.close()


@pytest.fixture
async def sqlserver_scratch() -> AsyncIterator[tuple[Any, StoreSettings]]:
    """An empty scratch database, dropped afterwards, and auto-mode settings that point at it."""
    import pyodbc

    from messagefoundry.config.settings import load_settings
    from tests._live_scratch import bounded, scratch_name, sqlserver_admin

    base = load_settings(environ=os.environ).store
    db = scratch_name("mefor_b1720")
    async with sqlserver_admin(base) as admin:
        try:
            try:
                await bounded(
                    base, "create the scratch database", admin.run(f"CREATE DATABASE [{db}]")
                )
            except pyodbc.ProgrammingError as exc:
                # Only the principal's refusal is a fixture limit: error 262, "CREATE DATABASE
                # permission denied". A stall, a lost link or any other error is a finding.
                if "(262)" not in str(exc):
                    raise
                pytest.skip(f"cannot create a scratch database with this principal: {exc}")
            yield (
                admin,
                base.model_copy(
                    update={"database": db, "schema_management": SchemaManagement.AUTO}
                ),
            )
        finally:
            await admin.teardown(databases=[db])


async def _sqlserver_marker_rows(admin: Any, db: str) -> int:
    if await admin.scalar(f"SELECT OBJECT_ID(N'[{db}].dbo.schema_meta', N'U')") is None:
        return 0
    return int(await admin.scalar(f"SELECT COUNT(*) FROM [{db}].dbo.schema_meta"))


@pytest.mark.skipif(not _SQLSERVER_ON, reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env)")
async def test_live_sqlserver_open_refuses_a_same_named_index_and_marks_nothing(
    sqlserver_scratch: tuple[Any, StoreSettings],
) -> None:
    from messagefoundry.store.sqlserver import SqlServerStore
    from tests._live_scratch import bounded

    admin, scratch = sqlserver_scratch
    db = scratch.database
    assert db is not None
    sa = admin.settings
    store = await bounded(sa, "first open builds the store", SqlServerStore.open(scratch))
    await store.close()
    await admin.run_in(db, f"DROP INDEX {_FIFO} ON queue")
    await admin.run_in(db, f"CREATE INDEX {_FIFO} ON queue(created_at)")
    await admin.run_in(db, "DELETE FROM schema_meta")
    with pytest.raises(ServerSchemaMismatchError) as caught:
        # Closed if it opens after all, so no session holds the database at its teardown.
        await (
            await bounded(sa, "reopen over the wrong index", SqlServerStore.open(scratch))
        ).close()
    assert f"index {_FIFO!r} is on queue(created_at)" in str(caught.value)
    assert await _sqlserver_marker_rows(admin, db) == 0
    await admin.run_in(db, f"DROP INDEX {_FIFO} ON queue")
    store = await bounded(sa, "reopen once the index is dropped", SqlServerStore.open(scratch))
    await store.close()
    assert await _sqlserver_marker_rows(admin, db) == 1


@pytest.mark.skipif(not _SQLSERVER_ON, reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env)")
async def test_live_sqlserver_open_refuses_a_table_missing_a_column(
    sqlserver_scratch: tuple[Any, StoreSettings],
) -> None:
    from messagefoundry.store.sqlserver import SqlServerStore
    from tests._live_scratch import bounded

    admin, scratch = sqlserver_scratch
    db = scratch.database
    assert db is not None
    await admin.run_in(db, "CREATE TABLE transit_bound_attestation (id INT PRIMARY KEY)")
    with pytest.raises(ServerSchemaMismatchError) as caught:
        opened = SqlServerStore.open(scratch)
        await (await bounded(admin.settings, "open over the short table", opened)).close()
    assert "table 'transit_bound_attestation' is missing column 'audit_hash'" in str(caught.value)
    assert await _sqlserver_marker_rows(admin, db) == 0


# --- BACKLOG #1720 step 3: the store v0.3.2 built, opened by this build ---------------------------
#
# A v0.3.2 store does not migrate on any backend: its audit_log has no `seq`, which no migration adds
# because the column is inside every row's MAC (BACKLOG #1198, vault BACKLOG #2594; store.py's
# _migrate says so). So the open must refuse it naming
# that column, roll back, and leave the v0.3.2 marker in place. tests/test_store_schema.py holds the
# SQLite twin. While the federated-subject index sat in _SCHEMA, the PostgreSQL batch would have
# stopped before the check, on the driver's undefined-column error for users.oidc_issuer: read from
# the DDL order, and not run against a server before the move.

_V032_SEQ = "table 'audit_log' is missing column 'seq'"


def test_the_v032_server_fixture_holds_the_old_shape() -> None:
    """The embedded batches build the shape the open tests below are about, and hash to the marker
    the fixture records under v0.3.2's ``_schema_hash`` formula. That marker is the fixture's own
    value; the tag test below reads the batches and the formula's revision from v0.3.2 itself."""
    from tests import _store_v032_shape as v032

    pg = "\n".join(v032.POSTGRES_BATCH) + "\nmigration_rev=1"  # v0.3.2's _MIGRATION_REV
    assert hashlib.sha256(pg.encode()).hexdigest() == v032.POSTGRES_MARKER
    ms = "\n".join(v032.SQLSERVER_BATCH)
    assert hashlib.sha256(ms.encode()).hexdigest() == v032.SQLSERVER_MARKER
    for shape in (
        declared_schema((*v032.POSTGRES_BATCH, *v032.POSTGRES_MIGRATION), "postgres"),
        declared_schema(v032.SQLSERVER_BATCH, "sqlserver"),
    ):
        assert "seq" not in shape.columns["audit_log"]
        assert "oidc_issuer" not in shape.columns["users"]
        presets = shape.columns["search_presets"]
        assert "owner" in presets and "owner_user_id" not in presets


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    root = pathlib.Path(__file__).resolve().parents[1]
    return subprocess.run(["git", *args], cwd=root, capture_output=True, timeout=60)


def _tag_module(module: str) -> ast.Module:
    """The v0.3.2 tag's ``messagefoundry/store/<module>``, parsed. Skips only where the clone holds
    no such tag, as a shallow CI clone does; any other git failure fails the test."""
    try:
        present = _git("rev-parse", "--verify", "--quiet", "v0.3.2^{commit}").returncode == 0
    except OSError:
        present = False
    if not present:
        pytest.skip("this clone has no v0.3.2 tag")
    shown = _git("show", f"v0.3.2:messagefoundry/store/{module}")
    assert shown.returncode == 0, shown.stderr.decode("utf-8", "replace")
    return ast.parse(shown.stdout.decode("utf-8"))


def _assigned(tree: ast.Module, name: str) -> ast.expr:
    for node in tree.body:
        targets: list[ast.expr]
        if isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        elif isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        else:
            continue
        if value is not None and any(isinstance(t, ast.Name) and t.id == name for t in targets):
            return value
    raise AssertionError(f"the v0.3.2 module assigns no {name}")


def _strings(tree: ast.Module) -> list[str]:
    return [
        n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def test_the_v032_server_batches_are_the_tags_in_order() -> None:
    """Each server batch is v0.3.2's ``_SCHEMA`` list, element for element, in order. The two SQL
    Server claim procedures are calls there, so only their place is checked. PostgreSQL's marker
    formula took ``_MIGRATION_REV``, which v0.3.2 set to 1."""
    from tests import _store_v032_shape as v032

    pg = _tag_module("postgres.py")
    assert ast.literal_eval(_assigned(pg, "_SCHEMA")) == list(v032.POSTGRES_BATCH)
    assert ast.literal_eval(_assigned(pg, "_MIGRATION_REV")) == 1
    pg_strings = _strings(pg)
    assert [s for s in v032.POSTGRES_MIGRATION if s not in pg_strings] == []
    ms = _assigned(_tag_module("sqlserver.py"), "_SCHEMA")
    assert isinstance(ms, ast.List) and len(ms.elts) == len(v032.SQLSERVER_BATCH)
    for element, statement in zip(ms.elts, v032.SQLSERVER_BATCH, strict=True):
        if isinstance(element, ast.Call):
            assert "CREATE OR ALTER PROCEDURE" in statement
        else:
            assert ast.literal_eval(element) == statement


def test_the_v032_sqlite_objects_are_the_tags_in_order() -> None:
    """Every object v0.3.2's ``_SCHEMA`` creates is in the fixture, in the script's order, and every
    fixture statement is that release's text. SQLite stores a CREATE without its ``IF NOT
    EXISTS``, so that is put back before the match. The objects the script does not create are
    the ones its ``_migrate`` built, which the match finds among the module's other strings."""
    from tests import _store_v032_shape as v032

    tree = _tag_module("store.py")
    script = ast.literal_eval(_assigned(tree, "_SCHEMA"))
    created = re.compile(r"^\s*CREATE (?:UNIQUE )?(?:TABLE|INDEX) (?:IF NOT EXISTS )?(\w+)", re.M)
    names = [m.group(1) for m in map(created.match, v032.SQLITE_DDL) if m is not None]
    assert len(names) == len(v032.SQLITE_DDL)
    in_script = created.findall(script)
    assert len(set(in_script)) == len(in_script)
    assert [n for n in names if n in in_script] == in_script
    strings = _strings(tree)
    restored = [
        re.sub(r"^CREATE (UNIQUE )?(TABLE|INDEX) ", r"\g<0>IF NOT EXISTS ", s)
        for s in v032.SQLITE_DDL
    ]
    assert [s[:80] for s in restored if not any(s in c for c in strings)] == []


@pytest.mark.skipif(not _POSTGRES_ON, reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env)")
async def test_live_postgres_refuses_the_store_v032_built_and_keeps_its_marker() -> None:
    """In a scratch schema of its own: the v0.3.2 DDL, its marker and two synthetic rows, then an
    open by this build. It refuses naming the column, and the whole batch rolls back with it: the
    marker still records v0.3.2, and the preset keeps its username owner in ``owner``."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore
    from tests import _store_v032_shape as v032
    from tests._live_scratch import postgres_teardown, scratch_name

    base = load_settings(environ=os.environ).store
    schema = scratch_name("mefor_b1720v")
    admin = await PostgresStore.open(base)
    try:
        await admin._execute(f"CREATE SCHEMA {schema}")
        async with admin._timed_acquire(record=False) as conn, conn.transaction():
            await conn.execute(f"SET LOCAL search_path TO {schema}")
            for statement in (*v032.POSTGRES_BATCH, *v032.POSTGRES_MIGRATION, *v032.SEED_ROWS):
                await conn.execute(statement)
            await conn.execute(
                "INSERT INTO schema_meta (id, schema_hash, applied_at) VALUES (1, $1, 2.0)",
                v032.POSTGRES_MARKER,
            )
        with pytest.raises(ServerSchemaMismatchError) as caught:
            # Closed if it opens after all, so the pool does not outlive its schema's teardown.
            await (await PostgresStore.open(base.model_copy(update={"db_schema": schema}))).close()
        assert _V032_SEQ in str(caught.value)
        marker = await admin._fetchone(f"SELECT schema_hash FROM {schema}.schema_meta")
        assert marker is not None and marker["schema_hash"] == v032.POSTGRES_MARKER
        columns = await admin._fetchall(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_schema = $1 AND table_name = 'search_presets'",
            schema,
        )
        names = {str(r["column_name"]) for r in columns}
        assert "owner" in names and "owner_user_id" not in names
        owners = await admin._fetchall(f"SELECT owner FROM {schema}.search_presets")
        assert [r["owner"] for r in owners] == ["alice"]
    finally:
        await postgres_teardown(admin, database=None, schemas=[schema])
        await admin.close()


@pytest.mark.skipif(not _SQLSERVER_ON, reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env)")
async def test_live_sqlserver_refuses_the_store_v032_built_and_keeps_its_marker(
    sqlserver_scratch: tuple[Any, StoreSettings],
) -> None:
    """The SQL Server twin, in an empty scratch database: the open refuses naming the column, and
    the batch rolls back, so the v0.3.2 marker and the preset's ``owner`` column survive."""
    from messagefoundry.store.sqlserver import SqlServerStore
    from tests import _store_v032_shape as v032
    from tests._live_scratch import bounded

    admin, scratch = sqlserver_scratch
    db = scratch.database
    assert db is not None
    marker_row = (
        "INSERT INTO schema_meta (id, schema_hash, applied_at)"
        f" VALUES (1, '{v032.SQLSERVER_MARKER}', 2.0)"
    )

    async def seed() -> None:
        for statement in (*v032.SQLSERVER_BATCH, *v032.SEED_ROWS, marker_row):
            await admin.run_in(db, statement)

    await bounded(admin.settings, "build the store v0.3.2 built", seed())
    with pytest.raises(ServerSchemaMismatchError) as caught:
        opened = SqlServerStore.open(scratch)
        await (await bounded(admin.settings, "open the store v0.3.2 built", opened)).close()
    assert _V032_SEQ in str(caught.value)
    assert (
        await admin.scalar(f"SELECT schema_hash FROM [{db}].dbo.schema_meta")
        == v032.SQLSERVER_MARKER
    )
    listed = await admin.scalar(
        f"SELECT STRING_AGG(COLUMN_NAME, N',') FROM [{db}].INFORMATION_SCHEMA.COLUMNS"
        " WHERE TABLE_NAME = N'search_presets'"
    )
    names = set(str(listed).split(","))
    assert "owner" in names and "owner_user_id" not in names
    assert await admin.scalar(f"SELECT owner FROM [{db}].dbo.search_presets") == "alice"


# --- BACKLOG #5085: column type, nullability and numbering ------------------------------------------


def test_each_backend_declares_column_types_as_its_catalog_spells_them() -> None:
    """Literal expectations, not read back from the parser: one column of each kind per backend."""
    pg = pg_declared().column_shapes
    assert pg["queue"]["seq"] == ColumnShape("bigint", False, True)  # BIGSERIAL
    assert pg["queue"]["owner"] == ColumnShape("text", True)
    assert pg["queue"]["lease_expires_at"] == ColumnShape("double precision", True)
    assert pg["webauthn_credentials"]["credential_id_hash"] == ColumnShape(
        "character varying(128)", False
    )
    assert pg["sessions"]["seal"] == ColumnShape("text", False)
    # Renamed in place by the batch on an older store; built under the new name on a new one.
    assert "owner" not in pg["search_presets"] and "owner_user_id" in pg["search_presets"]
    ms = mssql_declared().column_shapes
    assert ms["webauthn_credentials"]["credential_id_hash"] == ColumnShape("nvarchar(128)", False)
    assert ms["secret_rotation_meta"]["fingerprint"] == ColumnShape("nvarchar(max)", False)
    assert ms["users"]["oidc_issuer"] == ColumnShape("nvarchar(256)", True)
    assert ms["users"]["totp_enabled"] == ColumnShape("bit", False)
    assert any(c.identity for t in ms.values() for c in t.values())
    assert any(c.collation == "latin1_general_100_bin2" for t in ms.values() for c in t.values())


def test_every_column_the_postgres_migration_adds_matches_the_batch() -> None:
    """The check takes each column's shape from the batch's CREATE TABLE, so a column
    ``_migrate_lease_columns`` adds to an older table with another type or nullability would be
    refused on every upgraded store. Pin that each ADD builds the same column."""
    from messagefoundry.store import postgres

    source = inspect.getsource(postgres.PostgresStore._migrate_lease_columns)
    adds = re.findall(r'ALTER TABLE (\w+) ADD COLUMN (\w+ [^"]+)"', source)
    adds += [
        ("users", f"{c} {t}") for c, t in re.findall(r'^\s+\("(\w+)", "([^"]+)"', source, re.M)
    ]
    assert len(adds) >= 20  # positive control: the reads found the migration's ADDs
    declared = pg_declared().column_shapes
    wrong = [
        f"{table}: {text}"
        for table, text in adds
        if declared_column("postgres", text) != declared[table][text.split()[0]]
    ]
    assert not wrong, wrong


@pytest.mark.parametrize(
    ("dialect", "text", "expected"),
    [
        ("postgres", "a INT PRIMARY KEY", ColumnShape("integer", False)),
        ("postgres", "a BIGSERIAL", ColumnShape("bigint", False, True)),
        ("postgres", "a INTEGER GENERATED ALWAYS AS IDENTITY", ColumnShape("integer", False, True)),
        ("postgres", "a VARCHAR(64)", ColumnShape("character varying(64)", True)),
        ("postgres", "a NUMERIC(10, 2) NOT NULL", ColumnShape("numeric(10,2)", False)),
        ("postgres", "a TIMESTAMPTZ", ColumnShape("timestamp with time zone", True)),
        (
            "postgres",
            "a TEXT NOT NULL REFERENCES users(id) ON DELETE SET NULL DEFAULT ''",
            ColumnShape("text", False),
        ),
        ("sqlserver", "a INT IDENTITY(1,1) PRIMARY KEY", ColumnShape("int", False, True)),
        ("sqlserver", "a NVARCHAR(MAX) NULL", ColumnShape("nvarchar(max)", True)),
        ("sqlserver", "a FLOAT NOT NULL DEFAULT 0", ColumnShape("float", False)),
        (
            "sqlserver",
            "a NVARCHAR(64) COLLATE Latin1_General_100_BIN2 NOT NULL",
            ColumnShape("nvarchar(64)", False, False, "latin1_general_100_bin2"),
        ),
        (
            "sqlserver",
            "a NVARCHAR(32) NOT NULL CONSTRAINT df_a DEFAULT N'x'",
            ColumnShape("nvarchar(32)", False),
        ),
    ],
)
def test_a_column_definition_reads_as_its_shape(
    dialect: Any, text: str, expected: ColumnShape
) -> None:
    assert declared_column(dialect, text) == expected


@pytest.mark.parametrize(
    ("dialect", "text", "match"),
    [
        ("postgres", "a GEOMETRY", "does not compare"),
        ("postgres", 'a TEXT COLLATE "C"', "collation is not compared"),
        ("postgres", "a TEXT NOT NULL NULL", "both null and not null"),
        ("postgres", "a TEXT GENERATED ALWAYS AS (b) STORED", "cannot read"),
        ("sqlserver", "a INT", "leaves NULL to the session"),
        ("sqlserver", "a AS (b + 1)", "does not compare"),
        ("sqlserver", "a NVARCHAR(10) SPARSE NULL", "cannot read"),
    ],
)
def test_a_column_definition_the_check_cannot_compare_raises(
    dialect: Any, text: str, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        declared_column(dialect, text)


def test_live_sqlserver_types_spell_as_declared_ones() -> None:
    for declared, live in (
        ("NVARCHAR(256)", ("nvarchar", 512, 0, 0)),
        ("NVARCHAR(MAX)", ("nvarchar", -1, 0, 0)),
        ("VARCHAR(64)", ("varchar", 64, 0, 0)),
        ("FLOAT", ("float", 8, 53, 0)),
        ("INT", ("int", 4, 10, 0)),
        ("DECIMAL(10, 2)", ("decimal", 9, 10, 2)),
        ("DATETIME2", ("datetime2", 8, 27, 7)),
    ):
        assert declared_column("sqlserver", f"a {declared} NULL").type == mssql_live_type(*live)
    # A type widening is a different spelling, so it compares unequal.
    assert (
        mssql_live_type("nvarchar", 1024, 0, 0)
        != declared_column("sqlserver", "a NVARCHAR(256) NULL").type
    )


def test_a_guarded_add_that_builds_a_column_another_way_raises_until_altered() -> None:
    """A guarded ADD runs only on a store that lacks the column, so it and the CREATE TABLE each
    build it on some store. Disagreeing, the store's shape depends on its history."""
    create = "CREATE TABLE t (id INT NOT NULL, a NVARCHAR(64) NOT NULL)"
    add = "IF COL_LENGTH('t','a') IS NULL ALTER TABLE t ADD a NVARCHAR(32) NULL"
    with pytest.raises(ValueError, match="built two ways"):
        declared_schema((create, add), "sqlserver")
    alter = "IF COL_LENGTH('t','a') <> 128 ALTER TABLE t ALTER COLUMN a NVARCHAR(64) NOT NULL"
    shape = declared_schema((create, add, alter), "sqlserver")
    assert shape.column_shapes["t"]["a"] == ColumnShape("nvarchar(64)", False)
    pg = declared_schema(
        (
            "CREATE TABLE t (a VARCHAR(128) NOT NULL)",
            "ALTER TABLE t ALTER COLUMN a TYPE VARCHAR(128)",
            "ALTER TABLE t ALTER COLUMN a SET NOT NULL",
            "ALTER TABLE t ADD PRIMARY KEY (a)",
        ),
        "postgres",
    )
    assert pg.column_shapes["t"]["a"] == ColumnShape("character varying(128)", False)


def test_a_table_level_primary_key_makes_its_columns_not_null() -> None:
    shape = declared_schema(
        ("CREATE TABLE t (a NVARCHAR(64), b INT NOT NULL, PRIMARY KEY (a, b))",), "sqlserver"
    )
    assert shape.column_shapes["t"]["a"] == ColumnShape("nvarchar(64)", False)


@pytest.mark.parametrize(
    ("live", "clause"),
    [
        (ColumnShape("bigint", True), "is bigint null, expected integer not null"),
        (ColumnShape("integer", True), "is integer null, expected integer not null"),
        (
            ColumnShape("integer", False, True),
            "is integer identity not null, expected integer not null",
        ),
    ],
)
def test_a_column_of_another_type_nullability_or_numbering_refuses(
    live: ColumnShape, clause: str
) -> None:
    expected = live_shape({"t": {"a"}}, {}, {"t": {"a": ColumnShape("integer", False)}})
    got = live_shape({"t": {"a"}}, {}, {"t": {"a": live}})
    assert server_schema_differences(expected, got, {}) == [f"table 't' column 'a' {clause}"]
    assert server_schema_differences(expected, expected, {}) == []


def test_a_collation_is_compared_only_where_the_batch_declares_one() -> None:
    bin2 = ColumnShape("nvarchar(64)", False, False, "latin1_general_100_bin2")
    expected = live_shape({"t": {"a", "b"}}, {}, {"t": {"a": bin2, "b": ColumnShape("int", True)}})
    ci = ColumnShape("nvarchar(64)", False, False, "SQL_Latin1_General_CP1_CI_AS")
    live = live_shape(
        {"t": {"a", "b"}}, {}, {"t": {"a": ci, "b": ColumnShape("int", True, False, "any")}}
    )
    assert server_schema_differences(expected, live, {}) == [
        "table 't' column 'a' has collation 'SQL_Latin1_General_CP1_CI_AS',"
        " expected 'latin1_general_100_bin2'"
    ]
    upper = ColumnShape("nvarchar(64)", False, False, "Latin1_General_100_BIN2")
    same = live_shape({"t": {"a", "b"}}, {}, {"t": {"a": upper}})
    assert server_schema_differences(expected, same, {}) == []


def test_refuse_short_schema_reads_each_columns_shape_and_an_empty_table() -> None:
    """A table with no columns is not missing: each column it lacks is named (BACKLOG #5062)."""
    expected = live_shape(
        {"t": {"a"}, "u": {"x", "y"}}, {}, {"t": {"a": ColumnShape("integer", False)}}
    )
    rows = [
        ("t", "table", "a", ColumnShape("bigint", False)),
        ("u", "table", None, None),
    ]
    with pytest.raises(ServerSchemaMismatchError) as caught:
        refuse_short_schema("postgres", "mf", expected, rows, {}, {})
    assert caught.value.differences == (
        "table 'u' is missing column 'x'",
        "table 'u' is missing column 'y'",
        "table 't' column 'a' is bigint not null, expected integer not null",
    )


def test_the_refusal_is_logged_once_without_a_doubled_prefix(
    caplog: pytest.LogCaptureFixture,
) -> None:
    expected = live_shape({"t": {"a"}}, {})
    with caplog.at_level("ERROR"), pytest.raises(ServerSchemaMismatchError):
        refuse_short_schema("postgres", "mf", expected, [("t", None, None, None)], {}, {})
    [record] = [r for r in caplog.records if r.name.endswith("server_schema_verify")]
    assert record.getMessage().startswith("postgres schema differs: table 't' is missing")


async def test_postgres_refuses_a_column_of_another_type() -> None:
    """The row's case: a type widening on an existing table, which the guarded CREATE skips."""
    wider = ColumnShape("text", True)
    conn = _PgConn(_with_column(pg_declared(), "webauthn_credentials", "credential_id_hash", wider))
    with pytest.raises(ServerSchemaMismatchError) as caught:
        await _pg_store(conn)._ensure_schema()
    assert caught.value.differences == (
        "table 'webauthn_credentials' column 'credential_id_hash' is text null,"
        " expected character varying(128) not null",
    )
    assert not conn.marker_written()


async def test_sqlserver_refuses_a_not_null_change() -> None:
    nullable = ColumnShape("nvarchar(max)", True)
    conn = _MsConn(_with_column(mssql_declared(), "secret_rotation_meta", "fingerprint", nullable))
    with pytest.raises(ServerSchemaMismatchError) as caught:
        await _ms_store(conn)._ensure_schema()
    assert caught.value.differences == (
        "table 'secret_rotation_meta' column 'fingerprint' is nvarchar(max) null,"
        " expected nvarchar(max) not null",
    )
    assert not conn.marker_written()


async def test_sqlserver_reads_nothing_for_a_batch_that_declares_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``VALUES ()`` is a syntax error, so neither read runs for zero names (BACKLOG #5062)."""
    from messagefoundry.store import sqlserver

    monkeypatch.setattr(sqlserver, "_declared_schema", lambda: live_shape({}, {}))
    conn = _MsConn()
    await _ms_store(conn)._verify_live_schema(await conn.cursor())
    assert conn.executed == []


def test_both_backends_hash_the_one_check_revision(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.store import postgres, server_schema_verify, sqlserver

    before = (postgres._schema_hash(), sqlserver._schema_hash())
    monkeypatch.setattr(server_schema_verify, "SCHEMA_CHECK_REV", 99)
    after = (postgres._schema_hash(), sqlserver._schema_hash())
    assert before[0] != after[0] and before[1] != after[1]
    assert not hasattr(sqlserver, "_SCHEMA_CHECK_REV")


# --- BACKLOG #5062: DDL the reader used to misread -------------------------------------------------


def test_a_multi_target_drop_drops_each_name() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE a (x INT)",
            "CREATE TABLE b (x INT)",
            "CREATE TABLE c (x INT)",
            "CREATE INDEX ix_1 ON c(x)",
            "CREATE INDEX ix_2 ON c(x)",
            "DROP TABLE IF EXISTS a, b",
            "DROP INDEX ix_1 ON c, ix_2 ON c",
        )
    )
    assert set(shape.columns) == {"c"} and not shape.named_indexes


@pytest.mark.parametrize(
    ("statement", "match"),
    [
        ("ALTER TABLE t ADD COLUMN a INT, ADD COLUMN b INT", "more than one clause"),
        ("ALTER TABLE t ADD a INT NULL, b INT NULL", "more than one clause"),
        ("ALTER TABLE t RENAME TO u", "rename"),
        ("ALTER INDEX ix_t RENAME TO ix_u", "rename"),
        ("EXEC sp_rename 't', 'u'", "cannot read"),
        ("ALTER TABLE t ENABLE ROW LEVEL SECURITY", "cannot read"),
        ("ALTER TABLE t OWNER TO someone", "cannot read"),
        ("ALTER TABLE ONLY t* ADD COLUMN a INT", "cannot read"),
        ("CREATE TABLE t (a TEXT DEFAULT '-- not a comment')", "comment marker inside a string"),
        ("DROP TABLE public . t", "cannot read"),
        ("DROP INDEX ix_t ON t WITH (ONLINE = ON)", "cannot read"),
        # The drop's name list is read as one run and each item checked whole afterwards.
        ("DROP TABLE t,, u", "cannot read"),
        ("DROP TABLE t u", "cannot read"),
        ('DROP TABLE "t,u"', "cannot read"),
        ("DROP TABLE a.b.t", "cannot read"),
        ("DROP INDEX ix_t ON t ON u", "cannot read"),
        ("DROP INDEX ix_t ON", "cannot read"),
    ],
)
def test_the_parser_refuses_alter_and_drop_forms_it_would_misread(
    statement: str, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        declared_schema(("CREATE TABLE t (a INT)", statement))


def test_a_column_rename_moves_the_column() -> None:
    shape = declared_schema(
        (
            "CREATE TABLE t (old TEXT)",
            "ALTER TABLE t RENAME COLUMN old TO new",
            "CREATE TABLE u (a INT NULL)",
            "EXEC(N'EXEC sp_rename ''u.a'', ''b'', ''COLUMN'';')",
        )
    )
    assert dict(shape.columns) == {"t": frozenset({"new"}), "u": frozenset({"b"})}


def test_a_parenthesised_column_key_is_the_column() -> None:
    shape = declared_schema(("CREATE INDEX ix_p ON t ((a), ((b)) DESC, (a + b))",))
    assert shape.named_indexes["ix_p"].columns == ("a", "b DESC", "<expr>")


def test_a_comment_with_a_quote_in_it_hides_nothing() -> None:
    shape = declared_schema(
        ("CREATE TABLE t (\n  a INT, -- this file's note\n  b INT /* it's */\n)",)
    )
    assert dict(shape.columns) == {"t": frozenset({"a", "b"})}


def test_a_live_key_keeps_the_options_the_ddl_reader_refuses() -> None:
    """The PostgreSQL index read now prints a key's collation, operator class and NULLS order, so a
    live index built with one compares unequal to the declared bare key."""
    assert key_column('name COLLATE "C"') == 'name COLLATE "C"'
    assert (
        key_column("body text_pattern_ops DESC NULLS LAST")
        == "body text_pattern_ops DESC nulls last"
    )
    assert key_column("seq NULLS FIRST") == "seq nulls first"
    assert key_column("lower(name) DESC NULLS LAST") == "<expr> DESC nulls last"
    # An expression keeps what the read printed after it, so it is not the bare expression.
    assert key_column("lower(name) text_pattern_ops DESC") == "<expr> text_pattern_ops DESC"
    assert key_column('(a || b) COLLATE "C"') == '<expr> COLLATE "C"'
    assert (
        key_column("seq NULLS FIRST")
        != declared_schema(("CREATE INDEX ix ON t (seq)",)).named_indexes["ix"].columns[0]
    )
    from messagefoundry.store import postgres

    for fragment in ("indcollation[k - 1]", "indclass[k - 1]", "NULLS FIRST", "NULLS LAST"):
        assert fragment in postgres._LIVE_INDEXES_SQL, fragment


# --- review round 1: guarded ALTER, per-table index drop, key rewrites -----------------------------


def test_a_guarded_alter_column_that_a_new_store_never_runs_must_match_the_create() -> None:
    """Every guard in a shipped batch tests for the old state, so a new store keeps what CREATE
    TABLE built. An ALTER COLUMN to anything else builds the column two ways."""
    create = "IF OBJECT_ID('t','U') IS NULL CREATE TABLE t (a NVARCHAR(64) NOT NULL)"
    widen = "IF COL_LENGTH('t','a') = 64 ALTER TABLE t ALTER COLUMN a NVARCHAR(128) NOT NULL"
    with pytest.raises(ValueError, match="built two ways"):
        declared_schema((create, widen), "sqlserver")
    # SQL Server resets an altered column's collation unless the ALTER restates it.
    bin2 = "CREATE TABLE t (a NVARCHAR(64) COLLATE Latin1_General_100_BIN2 NOT NULL)"
    plain = "ALTER TABLE t ALTER COLUMN a NVARCHAR(64) NOT NULL"
    with pytest.raises(ValueError, match="built two ways"):
        declared_schema((bin2, plain), "sqlserver")
    restated = "ALTER TABLE t ALTER COLUMN a NVARCHAR(64) COLLATE Latin1_General_100_BIN2 NOT NULL"
    assert declared_schema((bin2, restated), "sqlserver").column_shapes["t"]["a"].collation
    with pytest.raises(ValueError, match="built two ways"):
        declared_schema(
            ("CREATE TABLE t (a VARCHAR(64))", "ALTER TABLE t ALTER COLUMN a TYPE TEXT"),
            "postgres",
        )


def test_a_drop_index_on_another_table_keeps_the_declared_one() -> None:
    shape = declared_schema(("CREATE INDEX ix ON a(x)", "DROP INDEX ix ON b"))
    assert shape.named_indexes["ix"] == IndexShape("a", ("x",), False, False)
    assert not declared_schema(("CREATE INDEX ix ON a(x)", "DROP INDEX ix ON a")).named_indexes


def test_a_primary_key_with_no_space_before_its_list_is_read() -> None:
    shape = declared_schema(("CREATE TABLE t (a TEXT, b INT, PRIMARY KEY(a))",), "postgres")
    assert shape.column_shapes["t"]["a"] == ColumnShape("text", False)


def test_a_rename_or_drop_of_a_column_follows_into_its_indexes() -> None:
    renamed = declared_schema(
        (
            "CREATE TABLE t (old TEXT, b TEXT)",
            "CREATE INDEX ix ON t(old DESC, b)",
            "ALTER TABLE t RENAME COLUMN old TO new",
        )
    )
    assert renamed.named_indexes["ix"].columns == ("new DESC", "b")
    dropped = declared_schema(
        (
            "CREATE TABLE t (a TEXT, b TEXT)",
            "CREATE INDEX ix ON t(a)",
            "ALTER TABLE t DROP COLUMN a",
        )
    )
    assert not dropped.named_indexes


@pytest.mark.parametrize(
    ("statements", "match"),
    [
        (('CREATE INDEX ix ON t ((a COLLATE "C"))',), "options"),
        (("EXEC sp_rename 'zz.a', 'b', 'COLUMN'",), "never declares"),
        (("CREATE TABLE t (a INT)", "ALTER TABLE t RENAME COLUMN x TO y"), "never declares"),
    ],
)
def test_review_round_one_forms_raise(statements: tuple[str, ...], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        declared_schema(statements)


def test_an_index_named_like_a_table_does_not_hide_the_table() -> None:
    expected = live_shape(
        {"roles": {"id", "name"}},
        {"roles": IndexShape("other", ("x",), False, False)},
        {"roles": {"id": ColumnShape("int", False)}},
    )
    live = live_shape(
        {"roles": {"id"}},
        {"roles": IndexShape("other", ("x",), False, False)},
        {"roles": {"id": ColumnShape("bigint", False)}},
    )
    assert server_schema_differences(expected, live, {}, {"roles": "disabled"}) == [
        "index 'roles' exists but is disabled (expected on other(x))",
        "table 'roles' is missing column 'name'",
        "table 'roles' column 'id' is bigint not null, expected int not null",
    ]


# --- batch 606 repair: refusal text, pre-read, nextval, DROP INDEX, expression keys -----------------


def _redacted(text: str) -> str:
    """``text`` as the service log's redaction filter leaves it."""
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "%s", (text,), None)
    assert RedactionFilter().filter(record)
    return record.getMessage()


def test_the_refusal_survives_the_log_redaction_and_the_safe_exc_cut() -> None:
    """The service log rewrites a run of all-caps words such as ``NOT NULL`` to ``[redacted]``, which
    hid the very difference #5085 reports. The shape is written in lower case, and a long collation
    gets a clause of its own, so it cannot push the nullability past safe_exc's 200-character cut."""
    assert "[redacted]" in _redacted("is bigint NULL, expected bigint IDENTITY NOT NULL")  # control
    declared = ColumnShape("nvarchar(256)", False, True, "latin1_general_100_ci_as_sc_utf8")
    expected = live_shape(
        {"connection_state": {"connection"}}, {}, {"connection_state": {"connection": declared}}
    )
    live_col = ColumnShape("nvarchar(256)", True, False, "SQL_Latin1_General_CP1_CI_AS_KS_WS")
    got = live_shape(
        {"connection_state": {"connection"}}, {}, {"connection_state": {"connection": live_col}}
    )
    exc = ServerSchemaMismatchError("sqlserver", None, server_schema_differences(expected, got, {}))
    core = (
        "table 'connection_state' column 'connection' is nvarchar(256) null,"
        " expected nvarchar(256) identity not null"
    )
    assert exc.differences == (
        core,
        "table 'connection_state' column 'connection' has collation"
        " 'SQL_Latin1_General_CP1_CI_AS_KS_WS', expected 'latin1_general_100_ci_as_sc_utf8'",
    )
    logged = _redacted(str(exc))
    assert core in logged and "[redacted]" not in logged
    assert core in safe_exc(exc)
    assert "[redacted]" not in _redacted(key_column("seq DESC NULLS FIRST"))


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_ddl_the_check_cannot_read_fails_before_the_lock_and_the_batch(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The batch is read before the schema lock on both backends, so a form the reader refuses
    fails with no lock taken and no DDL run (BACKLOG #5062)."""
    from messagefoundry.store import postgres, sqlserver

    def unreadable() -> ServerSchemaShape:
        raise ValueError("DDL the live-schema check cannot read")

    monkeypatch.setattr(
        postgres if backend == "postgres" else sqlserver, "_declared_schema", unreadable
    )
    if backend == "postgres":
        pg = _PgConn()
        with pytest.raises(ValueError, match="cannot read"):
            await _pg_store(pg)._ensure_schema()
        assert not any("advisory" in sql for sql in pg.executed)
        assert not set(postgres._SCHEMA) & set(pg.executed)
        assert pg.executed[-1] == "ROLLBACK"
    else:
        ms = _MsConn()
        with pytest.raises(ValueError, match="cannot read"):
            await _ms_store(ms)._ensure_schema()
        sqls = [sql for sql, _p, _t in ms.executed]
        assert not any("sp_getapplock" in sql for sql in sqls)
        assert not set(sqlserver._SCHEMA) & set(sqls)
        assert ms.rolledback >= 1


def test_a_nextval_default_reads_as_numbered_without_not_null() -> None:
    """The live read counts a ``nextval()`` default as numbering, so the declared side must too, or a
    correct column refuses. Unlike ``SERIAL`` it adds no NOT NULL."""
    assert declared_column("postgres", "a BIGINT DEFAULT nextval('s'::regclass)") == ColumnShape(
        "bigint", True, True
    )
    assert declared_column("postgres", "a BIGINT NOT NULL DEFAULT nextval('s')") == ColumnShape(
        "bigint", False, True
    )
    assert declared_column("postgres", "a BIGINT DEFAULT (nextval('s'))") == ColumnShape(
        "bigint", True, True
    )
    assert declared_column("postgres", "a BIGINT DEFAULT 0") == ColumnShape("bigint", True)
    created = declared_schema(("CREATE TABLE t (a BIGINT DEFAULT nextval('s'))",), "postgres")
    assert created.column_shapes["t"]["a"] == ColumnShape("bigint", True, True)
    # An ALTER COLUMN reaches only an older store, so its result must match the CREATE: a nextval()
    # default it sets or drops changes the numbering, and any other default does not.
    same = declared_schema(
        (
            "CREATE TABLE t (a BIGINT DEFAULT nextval('s'), b INT)",
            "ALTER TABLE t ALTER COLUMN a SET DEFAULT nextval('s')",
            "ALTER TABLE t ALTER COLUMN b SET DEFAULT 0",
        ),
        "postgres",
    )
    assert same.column_shapes["t"]["a"] == ColumnShape("bigint", True, True)
    with pytest.raises(ValueError, match="built two ways"):
        declared_schema(
            (
                "CREATE TABLE t (a BIGINT DEFAULT nextval('s'))",
                "ALTER TABLE t ALTER COLUMN a DROP DEFAULT",
            ),
            "postgres",
        )
    with pytest.raises(ValueError, match="built two ways"):
        declared_schema(
            ("CREATE TABLE t (a BIGINT)", "ALTER TABLE t ALTER COLUMN a SET DEFAULT nextval('s')"),
            "postgres",
        )


def test_drop_index_concurrently_if_exists_drops_the_index() -> None:
    """``DROP INDEX CONCURRENTLY IF EXISTS ix`` once read ``CONCURRENTLY`` as the name, ended at the
    ``IF``, and left ``ix`` expected. A T-SQL ``IF EXISTS (`` after a drop still ends it."""
    base = ("CREATE TABLE t (a INT)", "CREATE INDEX ix ON t (a)")
    assert not declared_schema((*base, "DROP INDEX CONCURRENTLY IF EXISTS ix")).named_indexes
    assert not declared_schema((*base, "DROP INDEX CONCURRENTLY ix")).named_indexes
    assert not declared_schema(
        (*base, "DROP INDEX ix ON t IF EXISTS (SELECT 1 FROM sys.objects) SELECT 1")
    ).named_indexes
    with pytest.raises(ValueError, match="cannot read"):
        declared_schema((*base, "DROP INDEX bogus IF EXISTS ix"))


@pytest.mark.parametrize(
    "key",
    [
        "lower(a) text_pattern_ops",
        '(a || b) COLLATE "C"',
        "lower(a) text_pattern_ops DESC",
        'lower(a COLLATE "C")',
    ],
)
def test_an_expression_key_with_an_operator_class_or_collation_raises(key: str) -> None:
    """The live read prints an expression's operator class, so the declared side cannot read one as
    the bare ``<expr>``; an expression's collation is not compared, so a key naming one raises."""
    with pytest.raises(ValueError, match="options"):
        declared_schema((f"CREATE INDEX ix ON t ({key})",))


def test_the_live_read_adds_a_collation_after_a_column_key_only() -> None:
    """An expression's natural collation lives in indexprs, which the read cannot see, so printing
    every non-default one would refuse a correct expression index."""
    from messagefoundry.store import postgres

    assert "AND i.indkey[k - 1] <> 0" in postgres._LIVE_INDEXES_SQL
    # ruleutils prints a collation that is not the column's, the database default included.
    assert "<> 100" not in postgres._LIVE_INDEXES_SQL


def test_a_schema_qualified_function_key_reads_as_an_expression() -> None:
    """The catalog qualifies a function the search path does not reach, so the live key must still
    read as ``<expr>``, as the declared one does."""
    assert key_column('pg_catalog."left"(actor, 200)') == "<expr>"
    assert key_column("ext.f(col) DESC") == "<expr> DESC"
    shape = declared_schema(("CREATE INDEX ix ON t (pg_catalog.lower(a))",))
    assert shape.named_indexes["ix"].columns == ("<expr>",)
