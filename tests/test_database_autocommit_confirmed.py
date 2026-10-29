# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every connection an autocommit DATABASE pool hands out is put in autocommit mode first (BACKLOG
#2148).

The DATABASE poll source's mark pool, the ``db_lookup`` pool and the ``DatabaseRef`` reference-sync
pool all ask aioodbc for ``autocommit=True``. pyodbc sends ``SQL_ATTR_AUTOCOMMIT`` only to turn
autocommit OFF and otherwise trusts the ODBC default, so a physical connection that arrives in
manual-commit mode keeps it. A source's mark would then run inside an open transaction and roll back
when the connection closes, and the marked rows would re-ingest.

Each test drives the real ``_make_pool`` against a faked ``aioodbc`` whose connections start with
``autocommit`` False, and records the mode each statement ran under. Synthetic data only; no driver,
no database.
"""

from __future__ import annotations

import asyncio
import sys
import threading
import time
import types
from collections.abc import Iterator
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.transports import database
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.database import (
    AutocommitNotConfirmed,
    DatabaseLookupExecutor,
    DatabaseSource,
    _acquire,
    _close_and_release,
    _make_pool,
)

_SQLSERVER: dict[str, Any] = {"server": "db.example", "database": "d"}


class _RawConnection:
    """The pyodbc connection under an aioodbc one. ``autocommit`` starts False, the state the row
    says a pooled physical connection could arrive in. ``sticky=False`` models a driver that accepts
    the set and does not keep it."""

    def __init__(self, *, sticky: bool = True) -> None:
        self._autocommit = False
        self._sticky = sticky
        self.sets: list[bool] = []

    @property
    def autocommit(self) -> bool:
        return self._autocommit

    @autocommit.setter
    def autocommit(self, value: bool) -> None:
        self.sets.append(value)
        if self._sticky:
            self._autocommit = value


class _Cursor:
    def __init__(self, conn: _Connection) -> None:
        self._conn = conn
        self.description = [("code",), ("value",)]

    async def execute(self, sql: str, params: Any = None) -> None:
        # What a statement would run under: the driver's mode at the moment it executes.
        self._conn.executed_under.append(self._conn._conn.autocommit)

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return [("A", "1")]

    async def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        rows, self._conn.rows_left = self._conn.rows_left[:size], self._conn.rows_left[size:]
        return rows

    async def close(self) -> None:
        return None


class _Connection:
    """An aioodbc connection: the driver connection sits on ``_conn``, as in aioodbc 0.5.0."""

    def __init__(self, raw: _RawConnection) -> None:
        self._conn = raw
        self.closed = False
        self.executed_under: list[bool] = []
        self.rows_left: list[tuple[Any, ...]] = [("A", "1")]

    async def cursor(self) -> _Cursor:
        return _Cursor(self)

    async def close(self) -> None:
        self.closed = True


class _Pool:
    def __init__(self, conn: _Connection) -> None:
        self.conn = conn
        self.released: list[_Connection] = []
        self.closed = False

    async def acquire(self) -> _Connection:
        return self.conn

    async def release(self, conn: _Connection) -> None:
        self.released.append(conn)

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class _Driver:
    """What the faked ``aioodbc.create_pool`` handed out, and with which ``autocommit``."""

    def __init__(self) -> None:
        self.pools: list[_Pool] = []
        self.autocommit: list[bool] = []
        self.sticky = True


@pytest.fixture
def driver(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Driver]:
    seen = _Driver()
    module = types.ModuleType("aioodbc")

    async def create_pool(**kwargs: Any) -> _Pool:
        seen.autocommit.append(kwargs["autocommit"])
        pool = _Pool(_Connection(_RawConnection(sticky=seen.sticky)))
        seen.pools.append(pool)
        return pool

    module.create_pool = create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    monkeypatch.setitem(sys.modules, "pyodbc", None)  # the #2049 guard becomes a no-op
    yield seen


async def test_an_autocommit_pool_sets_autocommit_on_every_connection_it_hands_out(
    driver: _Driver,
) -> None:
    """Red before the fix: the connection reached the caller with autocommit still False."""
    pool = await _make_pool("DSN=x", 2, autocommit=True, login_timeout=5)
    conn = await _acquire(pool, 5.0)
    assert conn._conn.autocommit is True
    assert conn._conn.sets == [True]
    await pool.release(conn)
    # Once per physical connection: a later borrow of the same one skips the driver call.
    conn = await _acquire(pool, 5.0)
    assert conn._conn.sets == [True]
    await pool.release(conn)
    assert driver.pools[0].released == [conn, conn]
    # A new physical connection is confirmed in its turn.
    driver.pools[0].conn = _Connection(_RawConnection())
    fresh = await _acquire(pool, 5.0)
    assert fresh._conn.sets == [True] and fresh._conn.autocommit is True


async def test_the_context_manager_form_is_confirmed_too(driver: _Driver) -> None:
    """``async with pool.acquire()`` is how the live SQL Server tests borrow from these pools."""
    pool = await _make_pool("DSN=x", 2, autocommit=True, login_timeout=5)
    async with pool.acquire() as conn:
        assert conn._conn.autocommit is True
    assert driver.pools[0].released == [conn]


async def test_a_connection_that_does_not_keep_autocommit_is_refused_and_set_again(
    driver: _Driver,
) -> None:
    """The read-back: a set that does not take refuses the borrow. The connection goes back to the
    pool unconfirmed, so its next borrow sets the mode again before any statement runs on it."""
    driver.sticky = False
    pool = await _make_pool("DSN=x", 2, autocommit=True, login_timeout=5)
    with pytest.raises(AutocommitNotConfirmed) as info:
        await _acquire(pool, 5.0)
    inner = driver.pools[0]
    assert inner.released == [inner.conn]
    assert inner.conn.closed is False
    assert "DSN" not in str(info.value)  # names no connection detail
    with pytest.raises(AutocommitNotConfirmed):
        await _acquire(pool, 5.0)
    assert inner.conn._conn.sets == [True, True]  # never trusted on the strength of the first try
    assert inner.conn.executed_under == []


class _RaisingRaw(_RawConnection):
    """A driver whose autocommit setter raises, as a dead link does (SQLSTATE 08S01)."""

    @property
    def autocommit(self) -> bool:
        return self._autocommit

    @autocommit.setter
    def autocommit(self, value: bool) -> None:
        raise ConnectionError("08S01")


async def test_a_setter_that_raises_discards_the_connection(driver: _Driver) -> None:
    """A dead connection returned open would be handed out, and fail, on every later borrow
    (PR 2593 covering review). The setter's thread has ended, so closing it here is safe."""
    pool = await _make_pool("DSN=x", 2, autocommit=True, login_timeout=5)
    inner = driver.pools[0]
    inner.conn = _Connection(_RaisingRaw())
    with pytest.raises(ConnectionError):
        await _acquire(pool, 5.0)
    assert inner.conn.closed is True
    assert inner.released == [inner.conn]


async def test_a_connection_with_no_driver_handle_is_refused(driver: _Driver) -> None:
    """Fail closed: a connection whose mode cannot be set is not handed out as autocommit."""
    pool = await _make_pool("DSN=x", 2, autocommit=True, login_timeout=5)
    driver.pools[0].conn._conn = None  # type: ignore[assignment]
    with pytest.raises(AutocommitNotConfirmed):
        await _acquire(pool, 5.0)
    assert driver.pools[0].released == [driver.pools[0].conn]


class _BlockingRaw(_RawConnection):
    """A driver whose autocommit set hangs until released, as a stalled server would make it.
    ``closed_during_set`` records a close that ran while the set was still inside the driver."""

    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.proceed = threading.Event()
        self.in_set = False
        self.closed_during_set = False

    @property
    def autocommit(self) -> bool:
        return self._autocommit

    @autocommit.setter
    def autocommit(self, value: bool) -> None:
        self.in_set = True
        self.entered.set()
        self.proceed.wait(10)
        self._autocommit = value
        self.in_set = False


async def test_a_borrow_abandoned_mid_set_keeps_its_bound_and_never_closes_under_the_call(
    driver: _Driver,
) -> None:
    """The set runs on a worker thread. When ``acquire_timeout`` expires during it, the borrower
    leaves at once (the bound holds), and the connection is neither closed nor reused until the
    driver call has returned. Closing it under the call would free handles the call is using."""
    pool = await _make_pool("DSN=x", 2, autocommit=True, login_timeout=5)
    inner = driver.pools[0]
    raw = _BlockingRaw()
    inner.conn = _Connection(raw)

    async def close_spy() -> None:
        raw.closed_during_set = raw.closed_during_set or raw.in_set
        inner.conn.closed = True

    inner.conn.close = close_spy  # type: ignore[method-assign]

    started = time.monotonic()
    with pytest.raises(DeliveryError, match="acquire timed out"):
        await _acquire(pool, 0.2)
    assert time.monotonic() - started < 5  # the bound held while the driver call hung
    assert inner.released == []  # not handed back while the call is running
    raw.proceed.set()
    for _ in range(200):
        if inner.released:
            break
        await asyncio.sleep(0.01)
    assert inner.released == [inner.conn]  # settled once the call returned
    assert raw.closed_during_set is False
    assert raw.autocommit is True and inner.conn.closed is False  # the set passed: returned, kept


class _RawCursor:
    """A pyodbc cursor whose close hangs on its thread until released."""

    def __init__(self, owner: _ThreadCloseCursor) -> None:
        self._owner = owner

    def close(self) -> None:
        self._owner.blocking_close()


class _ThreadCloseCursor(_Cursor):
    """A cursor whose close runs on a worker thread and hangs there until released. With
    ``raw=True`` it carries a pyodbc cursor on ``_impl``, as aioodbc 0.5.0's does; without it, only
    its own async ``close()``. ``running`` is True while the thread is inside the close."""

    def __init__(self, conn: _Connection, *, raw: bool) -> None:
        super().__init__(conn)
        self.entered = threading.Event()
        self.proceed = threading.Event()
        self.running = False
        if raw:
            self._impl = _RawCursor(self)

    def blocking_close(self) -> None:
        self.running = True
        self.entered.set()
        self.proceed.wait(10)
        self.running = False

    async def close(self) -> None:
        await asyncio.to_thread(self.blocking_close)


def _recording_pool(conn: _Connection, cur: _ThreadCloseCursor) -> tuple[_Pool, list[bool]]:
    """A pool that records, for each release, whether the close thread was still running."""
    pool = _Pool(conn)
    while_running: list[bool] = []
    release = pool.release

    async def _release(c: _Connection) -> None:
        while_running.append(cur.running)
        await release(c)

    pool.release = _release  # type: ignore[method-assign,assignment]
    return pool, while_running


async def _until(predicate: Any, seconds: float = 5.0) -> None:
    for _ in range(int(seconds / 0.01)):
        if predicate():
            return
        await asyncio.sleep(0.01)


def _cancel_tasks_since(before: set[asyncio.Task[Any]]) -> None:
    """Cancel every task this test created, as loop teardown would, and none it did not: the test
    loop is shared across the session, so another test's tasks are left alone."""
    me = asyncio.current_task()
    for other in asyncio.all_tasks() - before:
        if other is not me:
            other.cancel()


@pytest.mark.parametrize("raw", [True, False], ids=["raw-cursor", "fallback"])
async def test_a_cancelled_cursor_close_returns_the_connection_only_after_the_close_ends(
    raw: bool,
) -> None:
    """The Lander hold on PR 2593: a cancellation during the cursor close released the connection
    at once, while the worker thread was still closing the cursor on it, so the next borrower could
    reach a handle another thread was using. Now the slot goes back only once the close has ended,
    and it still goes back, so ``wait_closed`` does not wait forever."""
    conn = _Connection(_RawConnection())
    cur = _ThreadCloseCursor(conn, raw=raw)
    pool, while_running = _recording_pool(conn, cur)
    task = asyncio.ensure_future(_close_and_release(pool, conn, cur))
    await asyncio.to_thread(cur.entered.wait, 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.05)
    assert pool.released == []  # red at eb180654f: released while the thread was still closing
    cur.proceed.set()
    await _until(lambda: pool.released)
    assert pool.released == [conn]
    assert while_running == [False]


async def test_a_raw_cursor_close_cancelled_at_teardown_still_returns_the_connection() -> None:
    """Loop teardown cancels every task. The raw close's future is resolved by its thread, which no
    task cancel reaches, so the connection still goes back, after the thread, and a
    ``wait_closed`` on the pool waits for the close and no longer (PR 2593 covering review)."""
    conn = _Connection(_RawConnection())
    cur = _ThreadCloseCursor(conn, raw=True)
    pool, while_running = _recording_pool(conn, cur)
    before = asyncio.all_tasks()
    task = asyncio.ensure_future(_close_and_release(pool, conn, cur))
    await asyncio.to_thread(cur.entered.wait, 5)
    _cancel_tasks_since(before)
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.05)
    assert pool.released == []  # still closing
    cur.proceed.set()
    await _until(lambda: pool.released)
    assert pool.released == [conn]
    assert while_running == [False]


async def test_a_fallback_close_cancelled_at_teardown_keeps_the_connection_out_of_the_pool(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A cursor with no raw pyodbc cursor is closed as a task, and a teardown cancel of that task
    says nothing about its thread. That connection is never handed back, and the log says so."""
    conn = _Connection(_RawConnection())
    cur = _ThreadCloseCursor(conn, raw=False)
    pool, while_running = _recording_pool(conn, cur)
    before = asyncio.all_tasks()
    task = asyncio.ensure_future(_close_and_release(pool, conn, cur))
    await asyncio.to_thread(cur.entered.wait, 5)
    _cancel_tasks_since(before)
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.05)
    cur.proceed.set()
    await _until(lambda: not cur.running)
    await asyncio.sleep(0.05)
    assert pool.released == [] and while_running == []
    assert "kept out of the pool" in caplog.text


async def test_a_confirm_cancelled_at_teardown_never_returns_the_connection_under_the_setter(
    driver: _Driver,
) -> None:
    """Merge review of PR 2593: when the confirm itself was cancelled, as loop teardown cancels
    every task, its callback returned the connection while the worker thread could still be inside
    the pyodbc autocommit setter (the BACKLOG #2049 crash shape). Now nothing a task cancel reaches
    decides that: the connection goes back only once the setter has returned."""
    pool = await _make_pool("DSN=x", 2, autocommit=True, login_timeout=5)
    inner = driver.pools[0]
    raw = _BlockingRaw()
    inner.conn = _Connection(raw)
    while_in_set: list[bool] = []
    release = inner.release

    async def _release(c: _Connection) -> None:
        while_in_set.append(raw.in_set)
        await release(c)

    inner.release = _release  # type: ignore[method-assign,assignment]
    before = asyncio.all_tasks()
    borrow = asyncio.ensure_future(_acquire(pool, 30.0))
    await asyncio.to_thread(raw.entered.wait, 5)
    _cancel_tasks_since(before)
    with pytest.raises(asyncio.CancelledError):
        await borrow
    await asyncio.sleep(0.05)
    assert inner.released == []  # red at eb180654f: returned while the setter was running
    raw.proceed.set()
    await _until(lambda: inner.released)
    assert inner.released == [inner.conn]
    assert while_in_set == [False]


async def test_a_manual_commit_pool_is_left_alone(driver: _Driver) -> None:
    """The DATABASE destination commits itself on an ``autocommit=False`` pool, which pyodbc does
    set explicitly. That pool is not wrapped, and its connections are not touched."""
    pool = await _make_pool("DSN=x", 2, autocommit=False, login_timeout=5)
    assert pool is driver.pools[0]
    conn = await _acquire(pool, 5.0)
    assert conn._conn.sets == []


async def test_the_poll_source_marks_in_autocommit(driver: _Driver) -> None:
    source = DatabaseSource(
        Source(
            name="IB_DB",
            type=ConnectorType.DATABASE,
            settings={
                **_SQLSERVER,
                "poll_statement": "SELECT code, value FROM q",
                "mark_statement": "UPDATE q SET done = 1 WHERE code = :code",
            },
        )
    )
    batch = await source._select()
    await source._mark(batch.rows[0][0])
    assert driver.autocommit == [True]
    assert driver.pools[0].conn.executed_under == [True, True]  # the poll, then the mark
    await source.aclose()


async def test_a_db_lookup_runs_in_autocommit(driver: _Driver) -> None:
    executor = DatabaseLookupExecutor(
        {"clarity": dict(_SQLSERVER)}, egress=EgressSettings(deny_by_default=False)
    )
    rows = await executor.query("clarity", "SELECT code, value FROM t", None)
    assert rows == [{"code": "A", "value": "1"}]
    assert driver.autocommit == [True]
    assert driver.pools[0].conn.executed_under == [True]
    await executor.aclose()


async def test_a_reference_sync_runs_in_autocommit(driver: _Driver) -> None:
    from messagefoundry.pipeline.reference_sync import _load_database_source

    settings = {**_SQLSERVER, "statement": "SELECT code, value FROM t", "key_column": "code"}
    rows = await _load_database_source(settings, EgressSettings(deny_by_default=False))
    assert rows == {"A": {"value": "1"}}
    assert driver.autocommit == [True]
    assert driver.pools[0].conn.executed_under == [True]
    assert driver.pools[0].closed is True


def test_the_refusal_type_is_exported() -> None:
    assert database.AutocommitNotConfirmed is AutocommitNotConfirmed
