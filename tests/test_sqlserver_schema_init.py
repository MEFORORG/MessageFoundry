# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Finding A: SQL Server schema-init takes the cross-node schema applock BEFORE any CREATE, so two
nodes doing an HA cold start against a virgin DB serialize the DDL instead of both running the
check-then-create `IF OBJECT_ID(...) IS NULL CREATE` guards and racing the loser into a 2714 ("There
is already an object named ..."). The real race needs a real SQL Server + two concurrent opens (the
gated service-container suite / the dogfood box), but the *contract* — applock first, then DDL, under
one transaction — is verifiable here with a fake aioodbc conn/cursor and NO ODBC driver.

ADR 0064 adds the schema_meta fast-path in front: a read-only marker probe may now precede the
applock (it takes no lock and runs no DDL), and a marker-current database skips the batch AND the
applock entirely. The contract becomes: nothing but the probe precedes the applock, and every DDL
statement still runs after it.
"""

from __future__ import annotations

import types

import pytest

from messagefoundry.config.settings import SchemaManagement
from messagefoundry.store.base import PROVISION_SCHEMA_COMMAND, SchemaNotProvisionedError
from messagefoundry.store.pool_metrics import AcquireWaitHistogram
from messagefoundry.store.sqlserver import _SCHEMA_LOCK, SqlServerStore, _schema_hash


class _FakeCursor:
    """Fakes a virgin DB by default: the ADR 0064 marker probe (`OBJECT_ID('schema_meta','U')`) sees
    NULL, so _ensure_schema falls through to the full locked batch. With ``marker_current=True`` it
    fakes an already-initialized DB: the probe sees the table and the CURRENT content hash."""

    def __init__(self, executed: list[tuple[str, object]], *, marker_current: bool = False):
        self._executed = executed
        self._marker_current = marker_current
        self._last_sql = ""
        self.description = None

    async def execute(self, sql: str, params: object = None) -> None:
        self._executed.append((sql, params))
        self._last_sql = sql

    #: What the #305 external-mode read returns: RCSI on, snapshot isolation on, default schema dbo,
    #: and SELECT on the database held.
    options_row: tuple[object, ...] = (1, 1, "dbo", 1)

    async def fetchone(self) -> object:
        if "OBJECT_ID('schema_meta'" in self._last_sql:
            return (1,) if self._marker_current else (None,)
        if "schema_hash" in self._last_sql:
            return (_schema_hash(),) if self._marker_current else (None,)
        if "sys.databases" in self._last_sql:
            return self.options_row
        return (0,)  # sp_getapplock return code >= 0 (lock granted)

    async def fetchall(self) -> list[object]:
        return []

    async def close(self) -> None:
        pass


class _FakeConn:
    def __init__(self, executed: list[tuple[str, object]], *, marker_current: bool = False):
        self.cursor_obj = _FakeCursor(executed, marker_current=marker_current)
        self.committed = 0
        self.rolledback = 0
        # The underlying pyodbc connection aioodbc exposes as `_conn`; _acquire sets its statement
        # timeout, and _ensure_schema (B10) overrides it to 0 for the schema-DDL batch.
        self._conn = types.SimpleNamespace(timeout=None)

    async def cursor(self) -> _FakeCursor:
        return self.cursor_obj

    async def commit(self) -> None:
        self.committed += 1

    async def rollback(self) -> None:
        self.rolledback += 1


class _FakePool:
    """aioodbc's ``acquire``/``release`` pair — the shape ``_acquire`` calls directly so the
    BACKLOG #1052 bound can sit between the two."""

    def __init__(self, conn: _FakeConn):
        self._conn = conn

    async def acquire(self) -> object:
        return self._conn

    async def release(self, conn: object) -> None:
        return None


def _settings(
    *, command_timeout: int, mode: SchemaManagement = SchemaManagement.AUTO
) -> types.SimpleNamespace:
    """The settings slice _ensure_schema reads. AUTO by default: these contracts are the engine
    running its OWN DDL; the #305 external-mode cases pass ``mode`` explicitly."""
    return types.SimpleNamespace(
        command_timeout=command_timeout,
        acquire_timeout=30.0,
        database="MessageFoundry",
        resolved_schema_management=lambda: mode,
    )


def _make_store(conn: _FakeConn) -> SqlServerStore:
    store = SqlServerStore.__new__(SqlServerStore)
    store._pool = _FakePool(conn)  # type: ignore[assignment]
    store._settings = _settings(command_timeout=0)  # type: ignore[assignment]
    store._acquire_wait = AcquireWaitHistogram()  # B11: _acquire records acquire-wait into this
    # A1 live cost counters — normally set by __init__ (bypassed here); _commit bumps committed_txns.
    store.committed_txns = 0
    store.body_copies = 0
    return store


def _applock_index(executed: list[tuple[str, object]]) -> int:
    """The applock's position — asserting that ONLY the read-only ADR 0064 marker probe precedes it
    (the probe takes no lock and runs no DDL, so it cannot race a peer into a 2714)."""
    lock_i = next(i for i, (sql, _) in enumerate(executed) if "sp_getapplock" in sql)
    for sql, _ in executed[:lock_i]:
        stripped = sql.lstrip().upper()
        assert stripped.startswith("SELECT") and "schema_meta" in sql, (
            f"non-probe statement before the schema applock: {sql!r}"
        )
    return lock_i


async def test_ensure_schema_takes_applock_before_any_create() -> None:
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed)
    store = _make_store(conn)

    ran = await store._ensure_schema()

    assert ran is True  # virgin DB: the full batch ran
    # The applock names the cross-node resource, and nothing but the read-only probe precedes it...
    lock_i = _applock_index(executed)
    params_lock = executed[lock_i][1]
    assert params_lock is not None and _SCHEMA_LOCK in params_lock
    # ...and it precedes every CREATE TABLE (so two virgin-DB nodes serialize rather than race to 2714).
    first_create = next(i for i, (sql, _) in enumerate(executed) if "CREATE TABLE" in sql)
    assert first_create > lock_i
    # Single committed DDL batch; the txn-scoped applock auto-releases on that commit.
    assert conn.committed == 1
    assert conn.rolledback == 0


async def test_schema_lock_resource_matches_postgres_name() -> None:
    # Both backends must take the SAME logical schema lock name family ("mefor...schema_init") so the
    # intent is obvious; the SQL Server resource is colon-namespaced like its sibling applocks.
    assert _SCHEMA_LOCK == "mefor:schema_init"


async def test_applock_precedes_the_b10_fifo_index_migration() -> None:
    """ADR 0060 adds guarded DROP-old + CREATE-new-named FIFO index statements to the _SCHEMA batch. They
    must run AFTER the schema applock (like every other DDL) so two HA nodes serialize the index rebuild
    instead of racing it, and the seq-trailing new names + old-name drops must both be present."""
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed)
    store = _make_store(conn)

    await store._ensure_schema()

    sqls = [sql for sql, _ in executed]
    joined = "\n".join(sqls)
    # The seq-trailing indexes are created and the old created_at-trailing ones dropped.
    assert "ix_queue_fifo_in_seq" in joined and "ix_queue_fifo_out_seq" in joined
    assert "DROP INDEX ix_queue_fifo_in " in joined and "DROP INDEX ix_queue_fifo_out " in joined
    # The applock precedes EVERY FIFO index statement (not just the first CREATE TABLE).
    lock_i = _applock_index(executed)
    fifo_stmt_indexes = [i for i, s in enumerate(sqls) if "ix_queue_fifo" in s]
    assert fifo_stmt_indexes and min(fifo_stmt_indexes) > lock_i
    assert conn.committed == 1 and conn.rolledback == 0  # still one committed batch


async def test_ensure_schema_exempts_statement_timeout_for_the_ddl_batch() -> None:
    """ADR 0060: a large first-upgrade FIFO index rebuild can exceed command_timeout; being killed would
    roll back the schema batch and re-fail on every restart (a crash-loop). _ensure_schema sets the
    pyodbc connection timeout to 0 (no limit) for the batch. With a non-zero command_timeout configured,
    _acquire applies it on borrow and _ensure_schema then overrides it to 0."""
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed)
    store = _make_store(conn)
    # A non-zero command_timeout, so the DDL override is visible.
    store._settings = _settings(command_timeout=30)  # type: ignore[assignment]

    await store._ensure_schema()

    assert conn._conn.timeout == 0  # the DDL-batch statement-timeout exemption was applied


async def test_marker_current_skips_batch_applock_and_timeout_exemption() -> None:
    """ADR 0064: a marker-current DB skips the whole batch — no applock, no DDL, no statement-timeout
    override (the co-start convoy path never engages) — with the probe's read txn still committed."""
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed, marker_current=True)
    store = _make_store(conn)
    store._settings = _settings(command_timeout=30)  # type: ignore[assignment]

    ran = await store._ensure_schema()

    assert ran is False
    sqls = [sql for sql, _ in executed]
    assert all("schema_meta" in s and s.lstrip().upper().startswith("SELECT") for s in sqls), sqls
    assert not any("sp_getapplock" in s for s in sqls)
    # The probe runs under the NORMAL borrow-time command timeout — the B10 raw.timeout=0 DDL
    # exemption never engages (a fast-path probe must never hang unbounded).
    assert conn._conn.timeout == 30
    assert conn.committed == 1 and conn.rolledback == 0


# --- BACKLOG #305: [store].schema_management = external -----------------------------------------


def _is_read(sql: str) -> bool:
    """External mode issues SELECTs only: the marker probe and the database-options read."""
    return sql.lstrip().upper().startswith("SELECT")


class _StaleCursor(_FakeCursor):
    """``schema_meta`` exists but records a different DDL batch: the first start of an upgrade."""

    async def fetchone(self) -> object:
        if "OBJECT_ID('schema_meta'" in self._last_sql:
            return (1,)
        if "schema_hash" in self._last_sql:
            return ("an-older-build",)
        return await super().fetchone()


async def test_external_mode_refuses_a_virgin_database_and_runs_no_ddl() -> None:
    """The whole point of external mode: open READS the marker and nothing else. No applock, no
    CREATE, no statement-timeout exemption, and the refusal names the command that clears it."""
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed)
    store = _make_store(conn)
    store._settings = _settings(  # type: ignore[assignment]
        command_timeout=30, mode=SchemaManagement.EXTERNAL
    )

    with pytest.raises(SchemaNotProvisionedError) as info:
        await store._ensure_schema()

    assert PROVISION_SCHEMA_COMMAND in str(info.value)
    # The refusal names where THIS login looked, so a provisioning run into another default schema
    # cannot send the operator round a loop of "already current".
    assert info.value.schema == "dbo"
    assert "(this login's default schema is 'dbo')" in str(info.value)
    assert "default schema and then in dbo" in str(info.value)
    assert any("schema_meta" in sql for sql, _ in executed), "the marker must actually be read"
    assert all(_is_read(sql) for sql, _ in executed), [sql for sql, _ in executed]
    assert conn._conn.timeout == 30  # the B10 DDL exemption never engaged
    assert conn.committed == 1 and conn.rolledback == 0  # the probe's read txn is closed


async def test_external_mode_refuses_a_stale_marker_without_ddl() -> None:
    """A schema-moving upgrade: the marker is there but records an older batch. Auto mode would run
    the batch here; external mode must refuse instead."""
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed)
    conn.cursor_obj = _StaleCursor(executed)
    store = _make_store(conn)
    store._settings = _settings(  # type: ignore[assignment]
        command_timeout=30, mode=SchemaManagement.EXTERNAL
    )

    with pytest.raises(SchemaNotProvisionedError):
        await store._ensure_schema()

    assert all(_is_read(sql) for sql, _ in executed)


async def test_external_mode_opens_a_provisioned_database() -> None:
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed, marker_current=True)
    store = _make_store(conn)
    store._settings = _settings(  # type: ignore[assignment]
        command_timeout=30, mode=SchemaManagement.EXTERNAL
    )

    assert await store._ensure_schema() is False
    assert all(_is_read(sql) for sql, _ in executed)


async def test_the_same_stale_marker_runs_the_batch_under_auto() -> None:
    """The control for the stale-marker refusal above: the SAME database state under auto applies the
    batch, so the refusal is the mode's doing and not the fake's."""
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed)
    conn.cursor_obj = _StaleCursor(executed)
    store = _make_store(conn)

    assert await store._ensure_schema() is True
    assert any("CREATE TABLE" in sql for sql, _ in executed)


async def test_provisioning_applies_the_batch_whatever_the_mode_says() -> None:
    """``provision-schema`` is the caller external mode routes the DDL to, so it must not refuse."""
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed)
    store = _make_store(conn)
    store._settings = _settings(  # type: ignore[assignment]
        command_timeout=0, mode=SchemaManagement.EXTERNAL
    )

    assert await store._ensure_schema(provisioning=True) is True
    lock_i = _applock_index(executed)
    first_create = next(i for i, (sql, _) in enumerate(executed) if "CREATE TABLE" in sql)
    assert first_create > lock_i


async def test_external_mode_warns_with_the_statement_for_the_option_that_is_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Only ALLOW_SNAPSHOT_ISOLATION is off: the warning must give THAT statement, not RCSI's
    disruptive WITH ROLLBACK IMMEDIATE one, and the open must still issue no ALTER."""
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed, marker_current=True)
    conn.cursor_obj.options_row = (1, 0, "dbo")
    store = _make_store(conn)
    store._settings = _settings(  # type: ignore[assignment]
        command_timeout=30, mode=SchemaManagement.EXTERNAL
    )

    with caplog.at_level("WARNING"):
        assert await store._ensure_schema() is False

    text = caplog.text
    assert "ALLOW_SNAPSHOT_ISOLATION is OFF" in text
    assert "SET ALLOW_SNAPSHOT_ISOLATION ON" in text
    assert "READ_COMMITTED_SNAPSHOT ON" not in text
    assert all(_is_read(sql) for sql, _ in executed)


async def test_external_refusal_names_missing_read_access() -> None:
    """SQL Server hides an object from a caller that cannot read it, so a login outside db_datareader
    sees no marker at all. The refusal must name the grant: provision-schema would report "already
    current" and the operator would loop."""
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed)
    conn.cursor_obj.options_row = (1, 1, "dbo", 0)
    store = _make_store(conn)
    store._settings = _settings(  # type: ignore[assignment]
        command_timeout=30, mode=SchemaManagement.EXTERNAL
    )

    with pytest.raises(SchemaNotProvisionedError) as info:
        await store._ensure_schema()

    assert "no SELECT on the database" in str(info.value)
    assert "db_datareader" in str(info.value)


async def test_the_external_read_is_not_counted_as_a_write_transaction() -> None:
    """The A1 committed_txns counter is the write currency; a read snapshot release is not one."""
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed, marker_current=True)
    store = _make_store(conn)
    store._settings = _settings(  # type: ignore[assignment]
        command_timeout=30, mode=SchemaManagement.EXTERNAL
    )

    await store._ensure_schema()

    assert conn.committed == 1  # the snapshot WAS released
    assert store.committed_txns == 0  # and was not counted as a write
