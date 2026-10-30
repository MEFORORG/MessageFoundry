# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fakes for the ODBC cancel arms (BACKLOG #2049, #2394): aioodbc over stand-in pyodbc handles that
record a use of a freed handle instead of crashing on it.

They mirror aioodbc 0.5.0 on the one point that matters: every call goes through
``Connection._execute``, which hands it to ``loop.run_in_executor``. A REAL thread pool runs the
calls, so a close really can run while a statement runs. Give the executor more than one worker, or
the pool itself serializes the calls and an arm passes vacuously.

The raw stand-ins share one ``log``. ``RawConn(name=...)`` prefixes its entries, so arms with more
than one connection can tell them apart; with no name the entries are bare, as the #2049 arms read
them.
"""

from __future__ import annotations

import asyncio
import threading
import types
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from messagefoundry.store.sqlserver import SqlServerStore


# Bound on every wait for a worker thread. Generous, since these steps take milliseconds, but finite
# so a wedged case fails as a timeout instead of hanging the suite.
WAIT = 5.0
USE_AFTER_FREE = "USE-AFTER-FREE"
# Logged when AioConn.__del__ closes a raw handle the connection still held.
DEL_CLOSE = "del:raw-close"


def always(sql: str) -> bool:
    """A ``blocks`` predicate: every statement waits for ``release``."""
    return True


def never(sql: str) -> bool:
    """A ``blocks`` predicate: no statement waits."""
    return False


class RawCursor:
    """A ``pyodbc.Cursor`` stand-in. ``execute`` blocks until the test releases the statement when
    its connection's ``blocks`` says so."""

    def __init__(self, conn: RawConn) -> None:
        self._conn = conn
        self.freed = False
        self.description = [("r", int, None, 10, 10, 0, False)]
        self._row: tuple[Any, ...] | None = None

    def execute(self, sql: str, *params: object) -> RawCursor:
        c = self._conn
        c.note("execute:start")
        if c.blocks(sql):
            c.started.set()
            c.release.wait(WAIT)
        # pyodbc reads the result's column metadata off this handle as execute returns. That is
        # the read that crashed natively when the handle had already been freed.
        if self.freed:
            c.note(USE_AFTER_FREE)
        c.note("execute:end")
        if sql in c.fails:
            raise RuntimeError("refused by the stand-in server")
        self._row = c.rows.get(sql)
        return self

    def fetchall(self) -> list[tuple[Any, ...]]:
        if self.freed:
            self._conn.note(USE_AFTER_FREE)
        return []

    def fetchone(self) -> tuple[Any, ...] | None:
        if self.freed:
            self._conn.note(USE_AFTER_FREE)
        return self._row

    def close(self) -> None:
        c = self._conn
        if c.block_cursor_close:
            c.block_cursor_close = False  # the first close only
            c.note("cursor.close:start")
            c.started.set()
            c.release.wait(WAIT)
        if c.closed:
            c.note(USE_AFTER_FREE)
        self.freed = True
        c.note("cursor.close")


class RawConn:
    """A ``pyodbc.Connection`` stand-in. Closing it frees every statement it owns, as
    ``SQLDisconnect`` does.

    ``rows`` maps a statement to the row ``fetchone`` returns after it, ``fails`` names statements
    that raise once they return, and ``blocks`` picks the statements that wait for ``release``.
    ``block_autocommit`` makes the ``autocommit`` setter wait the same way: it goes through the
    driver, so a close beside it frees the handle under it. ``block_cursor_close`` makes the first
    cursor close wait too, a place for a cancellation to land during cleanup."""

    def __init__(
        self,
        log: list[str],
        release: threading.Event,
        started: threading.Event,
        *,
        name: str = "",
        blocks: Callable[[str], bool] = always,
        rows: Mapping[str, tuple[Any, ...]] | None = None,
        fails: frozenset[str] = frozenset(),
        block_autocommit: bool = False,
        block_cursor_close: bool = False,
    ) -> None:
        self.log = log
        self.release = release
        self.started = started
        self.blocks = blocks
        self.rows = dict(rows or {})
        self.fails = fails
        self.block_autocommit = block_autocommit
        self.block_cursor_close = block_cursor_close
        self._prefix = f"{name}:" if name else ""
        self.cursors: list[RawCursor] = []
        self.closed = False
        self.timeout = 0
        self._autocommit = False

    def note(self, entry: str) -> None:
        self.log.append(self._prefix + entry)

    def cursor(self) -> RawCursor:
        cur = RawCursor(self)
        self.cursors.append(cur)
        return cur

    def commit(self) -> None:
        self.note("commit")

    def rollback(self) -> None:
        self.note("rollback")

    @property
    def autocommit(self) -> bool:
        return self._autocommit

    @autocommit.setter
    def autocommit(self, value: bool) -> None:
        self.note("autocommit:start")
        if self.block_autocommit:
            self.started.set()
            self.release.wait(WAIT)
        if self.closed:
            self.note(USE_AFTER_FREE)
        self._autocommit = value
        self.note("autocommit:end")

    def close(self) -> None:
        for cur in self.cursors:
            cur.freed = True
        self.closed = True
        self.note("conn.close")


class AioCursor:
    """aioodbc 0.5.0 ``Cursor``: every operation is ``await self._conn._execute(...)``."""

    def __init__(self, impl: RawCursor, conn: AioConn) -> None:
        self._impl = impl
        self._conn: AioConn | None = conn

    async def _run_operation(self, func: Callable[..., Any], *args: Any) -> Any:
        if self._conn is None:
            raise RuntimeError("Cursor is closed.")
        return await self._conn._execute(func, *args)

    @property
    def description(self) -> Any:
        return self._impl.description

    async def execute(self, sql: str, *params: object) -> AioCursor:
        await self._run_operation(self._impl.execute, sql, *params)
        return self

    async def fetchall(self) -> Any:
        return await self._run_operation(self._impl.fetchall)

    async def fetchone(self) -> Any:
        return await self._run_operation(self._impl.fetchone)

    async def close(self) -> None:
        if self._conn is None:
            return
        await self._run_operation(self._impl.close)
        self._conn = None


class AioConn:
    """aioodbc 0.5.0 ``Connection``: ``_execute`` is ``run_in_executor(self._executor, partial)``,
    ``closed`` is derived from ``_conn``, and ``close`` runs the raw close through ``_execute``."""

    def __init__(self, raw: RawConn, executor: ThreadPoolExecutor) -> None:
        self._conn: RawConn | None = raw
        self._executor = executor
        self._loop = asyncio.get_running_loop()

    def _execute(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return self._loop.run_in_executor(self._executor, partial(func, *args, **kwargs))

    @property
    def closed(self) -> bool:
        return self._conn is None

    async def cursor(self) -> AioCursor:
        assert self._conn is not None
        return AioCursor(await self._execute(self._conn.cursor), self)

    async def commit(self) -> None:
        assert self._conn is not None
        await self._execute(self._conn.commit)

    async def rollback(self) -> None:
        assert self._conn is not None
        await self._execute(self._conn.rollback)

    async def close(self) -> None:
        if self._conn is None:
            return
        await self._execute(self._conn.close)
        self._conn = None

    def __del__(self) -> None:
        # aioodbc 0.5.0's shape: a connection collected while it still holds its handle closes it
        # synchronously, on whatever thread runs the collector, outside any gate.
        raw = getattr(self, "_conn", None)
        if raw is not None:
            raw.note(DEL_CLOSE)
            raw.close()
            self._conn = None


class Pool:
    """aioodbc's release rule: a released connection rejoins the free list only if not closed."""

    def __init__(self, conn: AioConn) -> None:
        self._conn = conn
        self.free: list[AioConn] = []
        # When set, release() suspends on it: a place for a SECOND cancellation to land in cleanup.
        self.hold: asyncio.Event | None = None
        self.in_release = asyncio.Event()

    async def acquire(self) -> AioConn:
        return self._conn

    async def release(self, conn: AioConn) -> None:
        self.in_release.set()
        if self.hold is not None:
            await self.hold.wait()
        if not conn.closed:
            self.free.append(conn)


def bare_store(pool: Pool) -> SqlServerStore:
    """A ``SqlServerStore`` with only what ``_acquire`` and ``_cursor`` read, over ``pool``.

    The store is imported here, not at the top, so a driver-level arm that never builds one does
    not load the SQL Server store with these fakes."""
    from messagefoundry.store.pool_metrics import AcquireWaitHistogram
    from messagefoundry.store.sqlserver import SqlServerStore

    store = SqlServerStore.__new__(SqlServerStore)
    store._pool = pool
    store._settings = types.SimpleNamespace(  # type: ignore[assignment]
        command_timeout=0, acquire_timeout=30.0
    )
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0
    store.body_copies = 0
    return store


async def cancel_once_started(started: threading.Event, coro: Any) -> asyncio.Task[Any]:
    """Run ``coro`` as a task, wait until its blocking call is running on a worker, cancel it."""
    task = asyncio.create_task(coro)
    assert await asyncio.to_thread(started.wait, WAIT), "the blocking call never started"
    task.cancel()
    return task


async def wait_for_entry(log: list[str], entry: str) -> None:
    """Wait, up to :data:`WAIT`, until ``entry`` is in ``log``."""
    for _ in range(int(WAIT / 0.01)):
        if entry in log:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"{entry!r} never happened (log={log})")
