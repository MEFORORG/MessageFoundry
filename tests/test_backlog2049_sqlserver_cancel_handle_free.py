# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2049 - a cancelled SQL Server store call must not free an ODBC handle while its
statement is still running.

aioodbc runs every pyodbc call on an executor thread. Cancelling the awaiting task does not stop
that thread: the statement keeps running. Before the fix, the cancellation path then closed the
cursor and the connection on OTHER threads, so the running statement came back to freed handles.
pyodbc describes a result's columns on the statement handle as ``execute`` returns, and on a live
SQL Server that read of freed memory could kill the process natively (``SQLDescribeColW``,
``SQLColAttributeW``). The source measured it on hosted CI; nobody here re-ran it.

These arms run everywhere, with no server. The fakes below mirror aioodbc 0.5.0 on the one point
that matters: every call goes through ``Connection._execute``, which hands it to
``loop.run_in_executor``. A REAL thread pool runs the calls, so a close really can run while the
statement runs. The raw stand-ins record a use of a freed handle instead of crashing on it.

The live twin, which cancels a statement blocked on a real SQL Server and asserts the process
survives its return, is ``test_cancelled_statement_returning_later_does_not_crash_the_process`` in
``tests/test_sqlserver_store.py``.
"""

from __future__ import annotations

import asyncio
import threading
import types
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from typing import Any

import pytest

from messagefoundry.store.pool_metrics import AcquireWaitHistogram
from messagefoundry.store.sqlserver import SqlServerStore

# Bound on every wait for a worker thread. Generous, since these steps take milliseconds, but finite
# so a wedged case fails as a timeout instead of hanging the suite.
WAIT = 5.0
USE_AFTER_FREE = "USE-AFTER-FREE"


class _RawCursor:
    """A ``pyodbc.Cursor`` stand-in. ``execute`` blocks until the test releases the statement."""

    def __init__(self, log: list[str], release: threading.Event, started: threading.Event) -> None:
        self._log = log
        self._release = release
        self._started = started
        self.freed = False
        self.description = [("r", int, None, 10, 10, 0, False)]

    def execute(self, sql: str, *params: object) -> _RawCursor:
        self._log.append("execute:start")
        self._started.set()
        self._release.wait(WAIT)
        # pyodbc reads the result's column metadata off this handle as execute returns. That is
        # the read that crashed natively when the handle had already been freed.
        if self.freed:
            self._log.append(USE_AFTER_FREE)
        self._log.append("execute:end")
        return self

    def fetchall(self) -> list[tuple[int]]:
        if self.freed:
            self._log.append(USE_AFTER_FREE)
        return []

    def close(self) -> None:
        self.freed = True
        self._log.append("cursor.close")


class _RawConn:
    """A ``pyodbc.Connection`` stand-in. Closing it frees every statement it owns, as
    ``SQLDisconnect`` does."""

    def __init__(self, log: list[str], release: threading.Event, started: threading.Event) -> None:
        self._log = log
        self._release = release
        self._started = started
        self.cursors: list[_RawCursor] = []
        self.timeout = 0

    def cursor(self) -> _RawCursor:
        cur = _RawCursor(self._log, self._release, self._started)
        self.cursors.append(cur)
        return cur

    def commit(self) -> None:
        self._log.append("commit")

    def rollback(self) -> None:
        self._log.append("rollback")

    def close(self) -> None:
        for cur in self.cursors:
            cur.freed = True
        self._log.append("conn.close")


class _AioCursor:
    """aioodbc 0.5.0 ``Cursor``: every operation is ``await self._conn._execute(...)``."""

    def __init__(self, impl: _RawCursor, conn: _AioConn) -> None:
        self._impl = impl
        self._conn: _AioConn | None = conn

    async def _run_operation(self, func: Callable[..., Any], *args: Any) -> Any:
        if self._conn is None:
            raise RuntimeError("Cursor is closed.")
        return await self._conn._execute(func, *args)

    @property
    def description(self) -> Any:
        return self._impl.description

    async def execute(self, sql: str, *params: object) -> _AioCursor:
        await self._run_operation(self._impl.execute, sql, *params)
        return self

    async def fetchall(self) -> Any:
        return await self._run_operation(self._impl.fetchall)

    async def close(self) -> None:
        if self._conn is None:
            return
        await self._run_operation(self._impl.close)
        self._conn = None


class _AioConn:
    """aioodbc 0.5.0 ``Connection``: ``_execute`` is ``run_in_executor(self._executor, partial)``,
    and ``closed`` is derived from ``_conn``."""

    def __init__(self, raw: _RawConn, executor: ThreadPoolExecutor) -> None:
        self._conn: _RawConn | None = raw
        self._executor = executor
        self._loop = asyncio.get_running_loop()

    def _execute(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return self._loop.run_in_executor(self._executor, partial(func, *args, **kwargs))

    @property
    def closed(self) -> bool:
        return self._conn is None

    async def cursor(self) -> _AioCursor:
        assert self._conn is not None
        return _AioCursor(await self._execute(self._conn.cursor), self)

    async def commit(self) -> None:
        assert self._conn is not None
        await self._execute(self._conn.commit)

    async def rollback(self) -> None:
        assert self._conn is not None
        await self._execute(self._conn.rollback)


class _Pool:
    """aioodbc's release rule: a released connection rejoins the free list only if not closed."""

    def __init__(self, conn: _AioConn) -> None:
        self._conn = conn
        self.free: list[_AioConn] = []
        # When set, release() suspends on it: a place for a SECOND cancellation to land in cleanup.
        self.hold: asyncio.Event | None = None
        self.in_release = asyncio.Event()

    async def acquire(self) -> _AioConn:
        return self._conn

    async def release(self, conn: _AioConn) -> None:
        self.in_release.set()
        if self.hold is not None:
            await self.hold.wait()
        if not conn.closed:
            self.free.append(conn)


@dataclass
class _Rig:
    store: SqlServerStore
    pool: _Pool
    log: list[str]
    release: threading.Event
    started: threading.Event


@pytest.fixture
async def rig() -> Any:
    # More than one worker, so a close submitted during the statement CAN run beside it. With one
    # worker the pool itself would serialize them and the arms below would pass vacuously.
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-2049")
    log: list[str] = []
    release = threading.Event()
    started = threading.Event()
    raw = _RawConn(log, release, started)
    pool = _Pool(_AioConn(raw, executor))
    store = SqlServerStore.__new__(SqlServerStore)
    store._pool = pool
    store._settings = types.SimpleNamespace(  # type: ignore[assignment]
        command_timeout=0, acquire_timeout=30.0
    )
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0
    store.body_copies = 0
    try:
        yield _Rig(store, pool, log, release, started)
    finally:
        release.set()  # never leave a worker parked if an arm failed early
        executor.shutdown(wait=True)


async def _cancel_mid_statement(r: _Rig) -> asyncio.Task[Any]:
    """Start a store read, wait until its statement is running on a worker thread, cancel it."""
    task = asyncio.create_task(r.store._fetchall("SELECT 1 AS r"))
    assert await asyncio.to_thread(r.started.wait, WAIT), "the statement never started"
    task.cancel()
    return task


async def _wait_for(r: _Rig, entry: str) -> None:
    for _ in range(int(WAIT / 0.01)):
        if entry in r.log:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"{entry!r} never happened (log={r.log})")


async def test_a_cancelled_call_frees_no_handle_until_its_statement_returns(rig: _Rig) -> None:
    """THE regression gate. Before the fix the cursor and connection closed on other worker
    threads while the statement was still running, so it returned to freed handles."""
    task = await _cancel_mid_statement(rig)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, WAIT)

    # The cancellation has propagated and the statement is STILL running. Nothing may be freed yet.
    assert "execute:end" not in rig.log, rig.log
    assert "cursor.close" not in rig.log and "conn.close" not in rig.log, (
        f"a handle was freed while its statement was still running (log={rig.log})"
    )

    rig.release.set()
    await _wait_for(rig, "conn.close")

    assert USE_AFTER_FREE not in rig.log, f"the statement returned to a freed handle ({rig.log})"
    end = rig.log.index("execute:end")
    assert end < rig.log.index("cursor.close") < rig.log.index("conn.close"), rig.log
    assert rig.pool.free == [], "the quarantine regressed: the connection went back to the pool"


async def test_the_cancellation_does_not_wait_for_the_statement(rig: _Rig) -> None:
    """Keep the cancel responsive. Waiting for the statement inside the cancellation would stall a
    shutdown or a demotion for as long as the statement runs, which ADR 0159 rejected."""
    task = await _cancel_mid_statement(rig)
    with pytest.raises(asyncio.CancelledError):
        # Well under the store's own 5s close bound, so a wait on it would fail this arm.
        await asyncio.wait_for(task, 1.0)
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"


async def test_a_second_cancellation_still_frees_nothing_early(rig: _Rig) -> None:
    """Shutdown cancels, then the gather cancels again. The second one must not free anything
    early either, so the handle free cannot depend on any await in the cleanup finishing."""
    rig.pool.hold = asyncio.Event()
    task = await _cancel_mid_statement(rig)
    await asyncio.wait_for(rig.pool.in_release.wait(), WAIT)  # the cleanup is suspended
    assert task.cancel(), "the arm is vacuous: the task had finished before the second cancel"
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, WAIT)
    assert "cursor.close" not in rig.log and "conn.close" not in rig.log, rig.log

    rig.release.set()
    await _wait_for(rig, "conn.close")
    assert USE_AFTER_FREE not in rig.log, rig.log
    assert rig.pool.free == []


async def test_a_cancel_between_calls_closes_the_cursor_then_the_connection(rig: _Rig) -> None:
    """The other quarantine path: the cancellation lands while NO call is running, so the close
    starts at once instead of being handed to a call. It must still close the abandoned cursor
    first, and hold the connection out of the pool."""
    rig.release.set()
    parked = asyncio.Event()

    async def _park(conn: object) -> None:
        parked.set()
        await asyncio.Event().wait()  # suspended on the loop, with no pyodbc call in flight

    rig.store._commit_read = _park  # type: ignore[method-assign]
    task = asyncio.create_task(rig.store._fetchall("SELECT 1 AS r"))
    await asyncio.wait_for(parked.wait(), WAIT)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, WAIT)

    await _wait_for(rig, "conn.close")
    assert USE_AFTER_FREE not in rig.log, rig.log
    end = rig.log.index("execute:end")
    assert end < rig.log.index("cursor.close") < rig.log.index("conn.close"), rig.log
    assert rig.pool.free == []


async def test_an_ordinary_read_still_closes_its_cursor_and_recycles(rig: _Rig) -> None:
    """The control. With no cancellation the cursor still closes before release (EF-6) and the
    connection goes back to the pool, so the arms above cannot pass by discarding everything."""
    rig.release.set()
    assert await rig.store._fetchall("SELECT 1 AS r") == []
    assert rig.log.index("execute:end") < rig.log.index("cursor.close"), rig.log
    assert "conn.close" not in rig.log
    assert rig.pool.free == [rig.pool._conn]
