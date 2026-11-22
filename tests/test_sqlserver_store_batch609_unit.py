# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SQL Server store fixes that need no live server: BACKLOG #5663, #5666, #5672, #5675, #5692.

* #5663: ``_SyncHandoffPool.acquire`` keeps its slot when the lazy reconnect of a placeholder
  raises, and discards a connection a BaseException left mid-transaction.
* #5666: ``_ensure_database_options`` bounds its one-shot connections by
  ``[store].command_timeout`` and keeps raw driver text out of its errors and logs.
* #5672, #5675, #5692: three writes read their match from ``OUTPUT`` rather than
  ``cursor.rowcount``, which a session-wide ``SET NOCOUNT ON`` reports as ``-1``. The fake cursor
  below always reports ``-1``, the NOCOUNT reading. The live counterparts are in
  ``tests/test_sqlserver_store.py`` and run only on the gated SQL Server legs.
"""

from __future__ import annotations

import logging
import sys
import types
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

import messagefoundry.store.sqlserver as sqlserver_module
from messagefoundry.config.settings import SchemaManagement, StoreBackend, StoreSettings
from messagefoundry.store.crypto import make_cipher
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore, _SyncHandoffPool

# --- #5663: the sync handoff pool -------------------------------------------------------------


class _Conn:
    def __init__(self, n: int) -> None:
        self.n = n
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_a_failed_lazy_reconnect_keeps_the_slot() -> None:
    """Red before #5663: the factory ran before the guarded block, so its raise dropped the slot
    and the pool shrank by one on every acquire that met the fault."""
    made = [0]
    fail = [False]

    def factory() -> _Conn:
        if fail[0]:
            raise OSError("server down")
        made[0] += 1
        return _Conn(made[0])

    pool = _SyncHandoffPool(factory, 1, conn_timeout=5)
    fail[0] = True
    with pytest.raises(RuntimeError), pool.acquire():
        raise RuntimeError("handoff failed")  # discards the slot; the refill fails: a placeholder
    with pytest.raises(OSError), pool.acquire(timeout=0.1):
        pass  # the placeholder's lazy reconnect fails too
    fail[0] = False
    with pool.acquire(timeout=0.1) as conn:  # the slot is still there, and now reconnects
        assert isinstance(conn, _Conn)
    assert pool._free.qsize() == 1


def test_a_base_exception_discards_the_connection() -> None:
    """Red before #5663: only ``Exception`` marked the connection broken, so a cancellation or an
    interrupt mid-handoff put a connection with an open transaction back on the free list."""
    made: list[_Conn] = []

    def factory() -> _Conn:
        made.append(_Conn(len(made) + 1))
        return made[-1]

    pool = _SyncHandoffPool(factory, 1, conn_timeout=5)
    with pytest.raises(KeyboardInterrupt), pool.acquire() as conn:
        first = conn
        raise KeyboardInterrupt
    assert first.closed
    with pool.acquire(timeout=0.1) as conn:
        assert conn is not first
    assert pool._free.qsize() == 1


def test_a_base_exception_from_the_refill_keeps_the_slot() -> None:
    """The refill after a discard puts a placeholder back whatever the factory raises."""
    calls = [0]

    def factory() -> _Conn:
        calls[0] += 1
        if calls[0] > 1:
            raise KeyboardInterrupt
        return _Conn(1)

    pool = _SyncHandoffPool(factory, 1, conn_timeout=5)
    with pytest.raises(KeyboardInterrupt), pool.acquire():
        raise RuntimeError("handoff failed")
    assert pool._free.qsize() == 1
    assert pool._free.get_nowait() is None


def test_a_base_exception_from_the_discard_close_keeps_the_slot() -> None:
    """A close of the discarded connection that raises a BaseException still leaves the slot."""

    class _Stubborn(_Conn):
        def close(self) -> None:
            raise KeyboardInterrupt

    pool = _SyncHandoffPool(lambda: _Stubborn(1), 1, conn_timeout=5)
    with pytest.raises(KeyboardInterrupt), pool.acquire():
        raise RuntimeError("handoff failed")
    assert pool._free.qsize() == 1
    assert pool._free.get_nowait() is None


# --- #5666: the database-options check ---------------------------------------------------------

_ALTER_RCSI = "ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"
_ALTER_SNAPSHOT = "ALTER DATABASE CURRENT SET ALLOW_SNAPSHOT_ISOLATION ON"
_SECRET = "Hunter2xyz"
_DRIVER_TEXT = f"[42000] permission denied; SERVER=db;UID=sa;PWD={_SECRET}; (5011)"


def _settings() -> StoreSettings:
    return StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="localhost",
        database="mefor_test",
        username="sa",
        schema_management=SchemaManagement.AUTO,
        command_timeout=17,
    )


class _Raw:
    """The raw pyodbc surface: ``timeout`` is the per-statement limit."""

    def __init__(self) -> None:
        self.timeout = 0
        self.autocommit = False


class _OptionsCursor:
    """Its limit is the connection's ``timeout`` when it was created, as pyodbc's ``Cursor_New``
    reads it; a later change to the connection does not reach it."""

    def __init__(
        self, raw: _Raw, row: tuple[int, int], timeouts: dict[str, int], alters_fail: bool
    ) -> None:
        self._limit = raw.timeout
        self._row = row
        self._timeouts = timeouts
        self._alters_fail = alters_fail

    async def execute(self, sql: str, *params: Any) -> None:
        self._timeouts[sql] = self._limit
        if self._alters_fail and sql.startswith("ALTER DATABASE"):
            raise RuntimeError(_DRIVER_TEXT)

    async def fetchone(self) -> tuple[int, int]:
        return self._row

    async def close(self) -> None:
        pass


class _OptionsConn:
    def __init__(
        self,
        row: tuple[int, int],
        timeouts: dict[str, int],
        alters_fail: bool,
        second_cursor_fails: bool = False,
    ) -> None:
        self._conn = _Raw()
        self._args = (row, timeouts, alters_fail)
        self._second_cursor_fails = second_cursor_fails
        self._cursors = 0

    async def cursor(self) -> _OptionsCursor:
        self._cursors += 1
        if self._second_cursor_fails and self._cursors > 1:
            raise RuntimeError(_DRIVER_TEXT)  # the session died after the state read
        return _OptionsCursor(self._conn, *self._args)

    async def close(self) -> None:
        pass


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    connect_fails: bool = False,
    reread_fails: bool = False,
    alters_fail: bool = True,
    alter_cursor_fails: bool = False,
    later_row: tuple[int, int] = (0, 0),
) -> dict[str, int]:
    """``alter_cursor_fails`` makes the first connection's second cursor open raise: the cursor
    the ALTERs get. ``later_row`` is what every connection after the first reads."""
    timeouts: dict[str, int] = {}
    connects = 0

    async def _connect(**kwargs: Any) -> _OptionsConn:
        nonlocal connects
        connects += 1
        if connect_fails or (reread_fails and connects > 1):
            raise RuntimeError(_DRIVER_TEXT)
        if connects > 1:
            return _OptionsConn(later_row, timeouts, alters_fail)
        return _OptionsConn((0, 0), timeouts, alters_fail, alter_cursor_fails)

    module = types.ModuleType("aioodbc")
    module.connect = _connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    monkeypatch.setattr(sqlserver_module, "_RCSI_REREAD_DELAY_S", 0.0)
    return timeouts


_STATE_READ = (
    "SELECT is_read_committed_snapshot_on, snapshot_isolation_state "
    "FROM sys.databases WHERE name = DB_NAME()"
)
_REREAD = "SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name = DB_NAME()"


async def test_the_open_bounds_its_reads_and_not_its_alters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red before #5666: the open's state read and re-read probes kept pyodbc's default of no
    statement limit. They now run under ``[store].command_timeout``. The ALTERs keep no limit: a
    cancel landing after ROLLBACK IMMEDIATE rolled back the peers would leave RCSI off, and the
    retry at every restart would roll them back again."""
    timeouts = _install(monkeypatch, alters_fail=False)
    await SqlServerStore._ensure_database_options(_settings())
    assert timeouts == {_STATE_READ: 17, _ALTER_RCSI: 0, _ALTER_SNAPSHOT: 0}, timeouts
    reread = _install(monkeypatch)  # the ALTER fails, so the re-read probes run
    with pytest.raises(RuntimeError, match="READ_COMMITTED_SNAPSHOT is OFF"):
        await SqlServerStore._ensure_database_options(_settings())
    assert reread == {_STATE_READ: 17, _ALTER_RCSI: 0, _REREAD: 17}, reread


async def test_provision_schema_options_alters_keep_no_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """provision-schema (``fail_closed=False``) runs every statement with no limit, as on main."""
    timeouts = _install(monkeypatch, alters_fail=False)
    await SqlServerStore._ensure_database_options(_settings(), fail_closed=False)
    assert timeouts[_ALTER_RCSI] == 0
    assert timeouts[_ALTER_SNAPSHOT] == 0


async def test_the_options_refusal_redacts_the_driver_text(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Red before #5666: the refusal and the warnings interpolated the raw exception, and ODBC text
    can echo connection parameters."""
    _install(monkeypatch)
    caplog.set_level(logging.DEBUG, logger=sqlserver_module.log.name)
    with pytest.raises(RuntimeError, match="READ_COMMITTED_SNAPSHOT is OFF") as info:
        await SqlServerStore._ensure_database_options(_settings())
    assert _SECRET not in str(info.value)
    assert "permission denied" in str(info.value)  # the diagnosis itself survives redaction
    await SqlServerStore._ensure_database_options(_settings(), fail_closed=False)
    messages = [record.getMessage() for record in caplog.records]
    assert any("ALLOW_SNAPSHOT_ISOLATION" in m for m in messages), "the control: it warned"
    assert not any(_SECRET in m for m in messages), messages


async def test_the_options_connect_failure_redacts_the_driver_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, connect_fails=True)
    with pytest.raises(RuntimeError, match="could not connect to verify") as info:
        await SqlServerStore._ensure_database_options(_settings())
    assert _SECRET not in str(info.value)
    assert "permission denied" in str(info.value)  # the diagnosis itself survives redaction


# --- #5672, #5675, #5692: writes that read OUTPUT, not rowcount ---------------------------------


class _NocountCursor:
    """Reports ``rowcount == -1`` always, as a session-wide ``SET NOCOUNT ON`` does. Each executed
    statement's rowset comes from ``rowsets`` in order; a statement past the end returns none."""

    rowcount = -1
    description = [("id",)]  # _execute_output names the OUTPUT columns from it

    def __init__(self, rowsets: list[list[tuple[Any, ...]]]) -> None:
        self._rowsets = list(rowsets)
        self._current: list[tuple[Any, ...]] = []
        self.executed: list[str] = []

    async def execute(self, sql: str, params: Any = None) -> None:
        self.executed.append(sql)
        self._current = self._rowsets.pop(0) if self._rowsets else []

    async def fetchall(self) -> list[tuple[Any, ...]]:
        rows, self._current = self._current, []
        return rows

    async def fetchone(self) -> tuple[Any, ...] | None:
        return self._current.pop(0) if self._current else None


class _FakeConn:
    def __init__(self) -> None:
        self.rolled_back = 0
        self.committed = 0  # every physical commit; the counted ones go through `_commit`

    async def rollback(self) -> None:
        self.rolled_back += 1

    async def commit(self) -> None:
        self.committed += 1


def _store(cur: _NocountCursor) -> tuple[SqlServerStore, list[int]]:
    store = SqlServerStore.__new__(SqlServerStore)
    commits: list[int] = []
    conn = _FakeConn()

    @asynccontextmanager
    async def _acquire(*args: Any, **kwargs: Any) -> AsyncIterator[_FakeConn]:
        yield conn

    @asynccontextmanager
    async def _cursor(conn: Any) -> AsyncIterator[_NocountCursor]:
        yield cur

    async def _commit(conn: Any) -> None:
        commits.append(1)

    store._acquire = _acquire  # type: ignore[method-assign]
    store._cursor = _cursor  # type: ignore[method-assign]
    store._commit = _commit  # type: ignore[method-assign]
    store._settings = _settings()  # _applock reads command_timeout
    return store, commits


async def test_delete_search_preset_reads_output() -> None:
    """Red before #5672: ``rowcount`` of -1 read as nothing deleted."""
    cur = _NocountCursor([[("p1",)]])
    store, commits = _store(cur)
    assert await store.delete_search_preset(preset_id="p1", owner_user_id="u") is True
    assert "OUTPUT deleted.id" in cur.executed[0]
    assert commits == [1]
    miss = _NocountCursor([[]])
    store, _ = _store(miss)
    assert await store.delete_search_preset(preset_id="p2", owner_user_id="u") is False


async def test_attachment_incref_of_a_missing_ref_raises_under_nocount() -> None:
    """Red before #5675: ``rowcount`` of -1 is truthy, so a missing ref returned as if counted.
    The zero-match UPDATE commits as a read, so ``committed_txns`` does not count it, as on main."""
    cur = _NocountCursor([[]])
    store, commits = _store(cur)
    with pytest.raises(KeyError):
        await store.attachment_incref("f" * 64)
    assert commits == [], "a missing ref is not a counted write"
    hit = _NocountCursor([[("a" * 64,)]])
    store, commits = _store(hit)
    await store.attachment_incref("a" * 64)
    assert commits == [1]
    assert "OUTPUT inserted.id" in hit.executed[0]


async def test_upsert_alert_instance_inserts_a_first_fire_under_nocount() -> None:
    """Red before #5692: the INSERT was gated on ``rowcount == 0``, which -1 never equals, so a
    first fire was dropped. A per-key applock, taken before the UPDATE and held to the commit, makes
    two concurrent first fires queue rather than collide on ``ux_alert_instance_open``."""
    # Rowsets: the transaction-opening SELECT, the applock's return code, then the UPDATE's OUTPUT.
    cur = _NocountCursor([[], [(0,)], []])
    store, commits = _store(cur)
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="warning", now=1.0
    )
    assert len(cur.executed) == 4, cur.executed
    assert cur.executed[0].startswith("SELECT TOP (1) id FROM alert_instance")
    assert cur.executed[1] == sqlserver_module._SQL_APPLOCK
    update = cur.executed[2]
    assert update.startswith("UPDATE alert_instance SET") and "OUTPUT inserted.id" in update
    assert cur.executed[3].startswith("INSERT INTO alert_instance")
    assert commits == [1]
    repeat = _NocountCursor([[], [(0,)], [(7,)]])
    store, _ = _store(repeat)
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="warning", now=2.0
    )
    assert len(repeat.executed) == 3, "a matched UPDATE inserts nothing"


async def test_a_failed_alert_upsert_rolls_back_through_rollback_or_discard() -> None:
    """A failed upsert holds this key's applock in its open transaction, so its rollback goes
    through ``_rollback_or_discard``, which discards a connection whose rollback fails rather than
    recycle the lock to the next borrower (BACKLOG #1940)."""

    class _FailingInsert(_NocountCursor):
        async def execute(self, sql: str, params: Any = None) -> None:
            await super().execute(sql, params)
            if sql.startswith("INSERT INTO alert_instance"):
                raise RuntimeError("deadlock victim")

    cur = _FailingInsert([[], [(0,)], []])
    store, commits = _store(cur)
    discards: list[Any] = []

    async def _rollback_or_discard(conn: Any, *, within: float | None = None) -> None:
        discards.append(conn)

    store._rollback_or_discard = _rollback_or_discard  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="deadlock victim"):
        await store.upsert_alert_instance(
            event_type="connection_error", connection="OB_X", severity="warning", now=1.0
        )
    assert len(discards) == 1 and commits == []


async def test_the_options_reread_failure_logs_no_driver_text(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The re-read after a failed ALTER logged its traceback, whose text is the driver's own."""
    _install(monkeypatch, reread_fails=True)
    caplog.set_level(logging.DEBUG, logger=sqlserver_module.log.name)
    with pytest.raises(RuntimeError, match="READ_COMMITTED_SNAPSHOT is OFF"):
        await SqlServerStore._ensure_database_options(_settings())
    rereads = [r for r in caplog.records if "RCSI re-read" in r.getMessage()]
    assert rereads, "the control: the re-read failed and logged"
    assert all(r.exc_info is None and _SECRET not in r.getMessage() for r in rereads)


# --- #5667: the ingress incref reads OUTPUT -----------------------------------------------------


class _IncrefCursor(_NocountCursor):
    """Answers the incref from ``known``, and every other statement with an empty rowset."""

    def __init__(self, known: set[str]) -> None:
        super().__init__([])
        self._known = known
        self.params: list[Any] = []

    async def execute(self, sql: str, params: Any = None) -> None:
        self.executed.append(sql)
        self.params.append(params)
        self._current = []
        if sql == sqlserver_module._SQL_INCREF_ATTACHMENT and params[1] in self._known:
            self._current = [(params[1],)]


def _ingress_store(cur: _IncrefCursor) -> tuple[SqlServerStore, list[int]]:
    store, commits = _store(cur)
    store._cipher = make_cipher(None)
    store._message_events = "all"
    store.body_copies = 0
    return store, commits


async def test_ingress_of_a_missing_attachment_raises_under_nocount() -> None:
    """Red before #5667: ``rowcount`` of -1 is truthy, so the link to a missing row committed."""
    cur = _IncrefCursor(known=set())
    store, commits = _ingress_store(cur)
    with pytest.raises(KeyError):
        await store.enqueue_ingress(channel_id="c", raw="MSH|", attachment_refs=["f" * 64])
    assert commits == [], "a message linked to a missing attachment must not commit"
    assert not any("message_attachment" in sql for sql in cur.executed)


async def test_ingress_increfs_inside_its_own_transaction() -> None:
    """The incref runs on the ingress cursor, so one commit carries the row, incref and link."""
    ref = "a" * 64
    cur = _IncrefCursor(known={ref})
    store, commits = _ingress_store(cur)
    await store.enqueue_ingress(channel_id="c", raw="MSH|", attachment_refs=[ref])
    assert commits == [1]
    at = cur.executed.index(sqlserver_module._SQL_INCREF_ATTACHMENT)
    assert cur.params[at] == (1, ref)
    assert "INSERT INTO message_attachment" in cur.executed[at + 1]


# --- #5728: the Postgres read checks the byte total ------------------------------------------


class _PgReadConn:
    def __init__(self, total: int, rows: list[dict[str, Any]]) -> None:
        self._total = total
        self._rows = rows

    async def fetchval(self, sql: str, *args: Any) -> int:
        return self._total

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        return self._rows


def _pg_reader(total: int, rows: list[dict[str, Any]]) -> Any:
    store: Any = PostgresStore.__new__(PostgresStore)
    store._cipher = make_cipher(None)

    @asynccontextmanager
    async def _timed_acquire() -> AsyncIterator[_PgReadConn]:
        yield _PgReadConn(total, rows)

    store._timed_acquire = _timed_acquire
    return store


@pytest.mark.parametrize(
    "rows",
    [[], [{"seq": 0, "ciphertext": "abc"}]],
    ids=["emptied", "truncated"],
)
async def test_postgres_read_raises_on_a_short_document(rows: list[dict[str, Any]]) -> None:
    """Red before #5728: GC between the two reads returned a short document and no error."""
    with pytest.raises(KeyError, match="incomplete"):
        _ = [c async for c in _pg_reader(5, rows).read_attachment("a" * 64)]


@pytest.mark.parametrize(
    "chunks",
    [["abc", "de"], ["café-", "文書"]],
    ids=["whole", "non-ascii"],
)
async def test_postgres_read_returns_a_whole_document(chunks: list[str]) -> None:
    """The control: ``total_bytes`` is UTF-8 bytes, so a whole document must not read as short."""
    rows = [{"seq": seq, "ciphertext": chunk} for seq, chunk in enumerate(chunks)]
    total = len("".join(chunks).encode("utf-8"))
    assert [c async for c in _pg_reader(total, rows).read_attachment("a" * 64)] == chunks


async def test_a_failed_alter_cursor_open_reaches_the_alters_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ALTERs' cursor opens after the state read. A failure there, such as a session a peer's
    ROLLBACK IMMEDIATE killed, gets main's outcome for a failed ALTER: the peer re-read, then the
    refusal with its remedy and the driver text redacted. Red before the open moved into the
    ALTER's try: the raw driver error escaped the open."""
    _install(monkeypatch, alters_fail=False, alter_cursor_fails=True)
    with pytest.raises(RuntimeError, match="READ_COMMITTED_SNAPSHOT is OFF") as info:
        await SqlServerStore._ensure_database_options(_settings())
    assert "a DBA must run once" in str(info.value)
    assert _SECRET not in str(info.value)
    # The control: a peer that turned RCSI on lets the open go on, as on main.
    _install(monkeypatch, alters_fail=False, alter_cursor_fails=True, later_row=(1, 1))
    await SqlServerStore._ensure_database_options(_settings())
