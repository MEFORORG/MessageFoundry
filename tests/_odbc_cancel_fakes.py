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
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any

# Bound on every wait for a worker thread. Generous, since these steps take milliseconds, but finite
# so a wedged case fails as a timeout instead of hanging the suite.
WAIT = 5.0
USE_AFTER_FREE = "USE-AFTER-FREE"


def _always(sql: str) -> bool:
    return True


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
        self.freed = True
        self._conn.note("cursor.close")


class RawConn:
    """A ``pyodbc.Connection`` stand-in. Closing it frees every statement it owns, as
    ``SQLDisconnect`` does.

    ``rows`` maps a statement to the row ``fetchone`` returns after it, ``fails`` names statements
    that raise once they return, and ``blocks`` picks the statements that wait for ``release``.
    ``block_autocommit`` makes the ``autocommit`` setter wait the same way: it goes through the
    driver, so a close beside it frees the handle under it."""

    def __init__(
        self,
        log: list[str],
        release: threading.Event,
        started: threading.Event,
        *,
        name: str = "",
        blocks: Callable[[str], bool] = _always,
        rows: Mapping[str, tuple[Any, ...]] | None = None,
        fails: frozenset[str] = frozenset(),
        block_autocommit: bool = False,
    ) -> None:
        self.log = log
        self.release = release
        self.started = started
        self.blocks = blocks
        self.rows = dict(rows or {})
        self.fails = fails
        self.block_autocommit = block_autocommit
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


async def wait_for_entry(log: list[str], entry: str) -> None:
    """Wait, up to :data:`WAIT`, until ``entry`` is in ``log``."""
    for _ in range(int(WAIT / 0.01)):
        if entry in log:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"{entry!r} never happened (log={log})")


async def assert_never_within(log: list[str], entry: str, within: float) -> None:
    """``entry`` stays out of ``log`` for ``within`` seconds. Without the gate the close it watches
    for lands in milliseconds, so a fraction of a second discriminates."""
    for _ in range(int(within / 0.01)):
        assert entry not in log, f"{entry!r} happened early (log={log})"
        await asyncio.sleep(0.01)
    assert entry not in log, f"{entry!r} happened early (log={log})"
