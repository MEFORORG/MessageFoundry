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
import inspect
import os
import pickle
import re
import textwrap
import types
from collections.abc import AsyncIterator, Mapping
from typing import Any

import pytest

from messagefoundry.config.settings import SchemaManagement, StoreSettings
from messagefoundry.store.pool_metrics import AcquireWaitHistogram
from messagefoundry.store.schema_verify import IndexShape, SchemaShape
from messagefoundry.store.server_schema_verify import (
    ServerSchemaMismatchError,
    declared_schema,
    key_column,
    live_shape,
    server_schema_differences,
)
from tests._server_schema_rows import mssql_declared, mssql_live_rows, pg_declared, pg_live_rows

_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))
_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))

_FIFO = "ix_queue_fifo_in_seq"
_FIFO_SHAPE = IndexShape("queue", ("stage", "channel_id", "status", "seq"), False, False)


def _without_column(shape: SchemaShape, table: str, column: str) -> SchemaShape:
    cols = dict(shape.columns)
    cols[table] = cols[table] - {column}
    return live_shape(cols, shape.named_indexes)


def _with_index(shape: SchemaShape, name: str, index: IndexShape | None) -> SchemaShape:
    indexes = dict(shape.named_indexes)
    if index is None:
        del indexes[name]
    else:
        indexes[name] = index
    return live_shape(shape.columns, indexes)


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


def test_every_column_the_postgres_migration_adds_is_in_the_batch() -> None:
    """The check reads columns from the batch alone, which holds because every column
    ``_migrate_lease_columns`` adds to an older table is also in that table's CREATE TABLE. A new
    migration column that is not would go unchecked, so this pins the premise."""
    from messagefoundry.store import postgres

    source = inspect.getsource(postgres.PostgresStore._migrate_lease_columns)
    added = set(re.findall(r"ALTER TABLE (\w+) ADD COLUMN (\w+)", source))
    added |= {("users", col) for col in re.findall(r'^\s+\("(\w+)", "', source, re.M)}
    assert len(added) >= 20  # positive control: the reads above found the migration's columns
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
    built = set(re.findall(r"execute\(\s*(_[A-Z_]+_DDL)\b", source))
    declared = {
        name
        for name, value in vars(postgres).items()
        if name.endswith("_DDL") and value in postgres._MIGRATION_INDEX_DDL
    }
    assert built == declared and len(built) == len(postgres._MIGRATION_INDEX_DDL)


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


def test_the_refusal_leads_with_the_remedy_and_is_an_engine_refusal() -> None:
    exc = ServerSchemaMismatchError("postgres", "mf", ["table 'queue' is missing column 'seq'"])
    assert isinstance(exc, RuntimeError)
    assert type(exc).__module__.startswith("messagefoundry.")  # printed whole by the CLI
    text = str(exc)
    assert text.index("Rename or drop") < text.index("Differences:")
    assert text.endswith("table 'queue' is missing column 'seq'.")
    assert exc.differences == ("table 'queue' is missing column 'seq'",)
    copied = pickle.loads(pickle.dumps(exc))
    assert (str(copied), copied.differences, copied.database) == (text, exc.differences, "mf")


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
    assert "'mf_test'" in str(caught.value)
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


@pytest.fixture
async def sqlserver_scratch() -> AsyncIterator[tuple[Any, StoreSettings]]:
    """An empty scratch database, dropped afterwards, and auto-mode settings that point at it."""
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
            except TimeoutError:
                raise
            except Exception as exc:  # noqa: BLE001 - a fixture limit, not a finding
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
