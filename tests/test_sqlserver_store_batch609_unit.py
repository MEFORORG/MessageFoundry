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
    def __init__(self, raw: _Raw, row: tuple[int, int], timeouts: dict[str, int]) -> None:
        self._raw = raw
        self._row = row
        self._timeouts = timeouts

    async def execute(self, sql: str, *params: Any) -> None:
        self._timeouts[sql] = self._raw.timeout
        if sql.startswith("ALTER DATABASE"):
            raise RuntimeError(_DRIVER_TEXT)

    async def fetchone(self) -> tuple[int, int]:
        return self._row

    async def close(self) -> None:
        pass


class _OptionsConn:
    def __init__(self, row: tuple[int, int], timeouts: dict[str, int]) -> None:
        self._conn = _Raw()
        self._cursor = _OptionsCursor(self._conn, row, timeouts)

    async def cursor(self) -> _OptionsCursor:
        return self._cursor

    async def close(self) -> None:
        pass


def _install(monkeypatch: pytest.MonkeyPatch, *, connect_fails: bool = False) -> dict[str, int]:
    timeouts: dict[str, int] = {}

    async def _connect(**kwargs: Any) -> _OptionsConn:
        if connect_fails:
            raise RuntimeError(_DRIVER_TEXT)
        return _OptionsConn((0, 0), timeouts)

    module = types.ModuleType("aioodbc")
    module.connect = _connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    monkeypatch.setattr(sqlserver_module, "_RCSI_REREAD_DELAY_S", 0.0)
    # The stand-in carries no call gate; the gate itself is pinned by the #2394 tests.
    monkeypatch.setattr(sqlserver_module, "_require_call_gate", lambda conn: None)
    return timeouts


async def test_the_options_alters_run_under_the_command_timeout(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Red before #5666: the one-shot connection kept pyodbc's default of no statement limit, so an
    ALTER DATABASE waiting on a long transaction could stall the open without end. The re-read
    connections are bounded too."""
    timeouts = _install(monkeypatch)
    caplog.set_level(logging.DEBUG, logger=sqlserver_module.log.name)
    await SqlServerStore._ensure_database_options(_settings(), fail_closed=False)
    assert timeouts[_ALTER_RCSI] == 17
    assert timeouts[_ALTER_SNAPSHOT] == 17
    assert all(seconds == 17 for seconds in timeouts.values()), timeouts


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
    assert "RuntimeError: " in str(info.value)  # the type still names the fault
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


# --- #5672, #5675, #5692: writes that read OUTPUT, not rowcount ---------------------------------


class _NocountCursor:
    """Reports ``rowcount == -1`` always, as a session-wide ``SET NOCOUNT ON`` does. Each executed
    statement's rowset comes from ``rowsets`` in order; a statement past the end returns none."""

    rowcount = -1

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

    async def rollback(self) -> None:
        self.rolled_back += 1


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
    """Red before #5675: ``rowcount`` of -1 is truthy, so a missing ref committed silently."""
    cur = _NocountCursor([[]])
    store, commits = _store(cur)
    with pytest.raises(KeyError):
        await store.attachment_incref("f" * 64)
    assert commits == []
    hit = _NocountCursor([[("a" * 64,)]])
    store, commits = _store(hit)
    await store.attachment_incref("a" * 64)
    assert commits == [1]
    assert "OUTPUT inserted.id" in hit.executed[0]


async def test_upsert_alert_instance_inserts_a_first_fire_under_nocount() -> None:
    """Red before #5692: the INSERT was gated on ``rowcount == 0``, which -1 never equals, so a
    first fire was dropped. The UPDATE holds its key range to the commit, so two concurrent first
    fires queue rather than collide on ``ux_alert_instance_open``."""
    cur = _NocountCursor([[]])
    store, commits = _store(cur)
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="warning", now=1.0
    )
    assert len(cur.executed) == 2 and cur.executed[1].startswith("INSERT INTO alert_instance")
    update = cur.executed[0]
    assert "WITH (UPDLOCK, HOLDLOCK)" in update and "OUTPUT inserted.id" in update
    assert commits == [1]
    repeat = _NocountCursor([[(7,)]])
    store, _ = _store(repeat)
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="warning", now=2.0
    )
    assert len(repeat.executed) == 1, "a matched UPDATE inserts nothing"
