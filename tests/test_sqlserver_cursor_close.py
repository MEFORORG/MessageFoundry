# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""EF-6 invariant: every pooled SQL Server cursor is closed (its statement handle freed) BEFORE its
connection returns to the aioodbc pool.

Without MARS a SQL Server connection allows one active statement; an ``UPDATE...OUTPUT`` claim leaves
the statement active even after ``fetchall`` drains its rows, so releasing the connection with the
cursor still open hands the next borrower a "connection is busy" (HY000). The real bug needs a no-MARS
SQL Server (covered by the gated service-container suite), but the *contract* — close-before-release on
BOTH the success and exception paths — is verifiable here with a fake aioodbc connection and NO ODBC
driver. v0.2.3 shipped the ``fetchone -> fetchall`` row-drain that did NOT close the cursor; a test
like this would have caught that it was insufficient.
"""

from __future__ import annotations

import types
from contextlib import asynccontextmanager

import pytest

from messagefoundry.store.sqlserver import SqlServerStore


class _FakeCursor:
    """Records close() calls (and order) and can be told to fail on execute or close."""

    def __init__(self, events: list[str], *, fail_execute: bool = False, fail_close: bool = False):
        self._events = events
        self._fail_execute = fail_execute
        self._fail_close = fail_close
        self.closed = 0
        self.description = None

    async def execute(self, sql: str, params: object = None) -> None:
        self._events.append("execute")
        if self._fail_execute:
            raise RuntimeError("execute boom")

    async def fetchall(self) -> list[object]:
        return []

    async def fetchone(self) -> object | None:
        return None

    async def close(self) -> None:
        self.closed += 1
        self._events.append("cursor.close")
        if self._fail_close:
            raise RuntimeError("close boom")


class _FakeConn:
    def __init__(self, events: list[str], **cursor_kwargs: bool):
        self._events = events
        self.cursor_obj = _FakeCursor(events, **cursor_kwargs)

    async def cursor(self) -> _FakeCursor:
        return self.cursor_obj

    async def commit(self) -> None:
        self._events.append("commit")

    async def rollback(self) -> None:
        self._events.append("rollback")


class _FakePool:
    """Mimics aioodbc's pool: ``acquire()`` is an async context manager that, on exit, appends a
    ``release`` marker so a test can assert the cursor was closed BEFORE the connection was released."""

    def __init__(self, conn: _FakeConn, events: list[str]):
        self._conn = conn
        self._events = events

    def acquire(self) -> object:
        conn = self._conn
        events = self._events

        @asynccontextmanager
        async def _cm():  # type: ignore[no-untyped-def]
            try:
                yield conn
            finally:
                events.append("release")

        return _cm()


def _make_store(conn: _FakeConn, events: list[str]) -> SqlServerStore:
    # Bypass __init__ (no real connect): _acquire/_cursor/_execute only touch _pool and _settings.
    store = SqlServerStore.__new__(SqlServerStore)
    store._pool = _FakePool(conn, events)  # type: ignore[assignment]
    store._settings = types.SimpleNamespace(command_timeout=0)  # type: ignore[assignment]
    return store


async def test_execute_closes_cursor_before_release_on_success() -> None:
    events: list[str] = []
    conn = _FakeConn(events)
    store = _make_store(conn, events)

    await store._execute("UPDATE t SET x=1")

    assert conn.cursor_obj.closed == 1
    # The cursor MUST be closed before the pooled connection is released (the EF-6 invariant).
    assert events == ["execute", "commit", "cursor.close", "release"]


async def test_execute_closes_cursor_before_release_on_error() -> None:
    events: list[str] = []
    conn = _FakeConn(events, fail_execute=True)
    store = _make_store(conn, events)

    with pytest.raises(RuntimeError, match="execute boom"):
        await store._execute("UPDATE t SET x=1")

    assert conn.cursor_obj.closed == 1
    # Even on the rollback path the cursor is closed before release.
    assert events == ["execute", "rollback", "cursor.close", "release"]


async def test_cursor_helper_closes_when_body_raises() -> None:
    events: list[str] = []
    conn = _FakeConn(events)
    store = _make_store(conn, events)

    with pytest.raises(ValueError, match="body boom"):
        async with store._cursor(conn) as cur:
            await cur.execute("noop")
            raise ValueError("body boom")

    assert conn.cursor_obj.closed == 1


async def test_cursor_helper_close_failure_does_not_mask_body_error() -> None:
    events: list[str] = []
    conn = _FakeConn(events, fail_close=True)
    store = _make_store(conn, events)

    # close() raises, but the helper swallows it so the real in-flight error still propagates.
    with pytest.raises(ValueError, match="real error"):
        async with store._cursor(conn):
            raise ValueError("real error")

    assert conn.cursor_obj.closed == 1  # close was still attempted


async def test_cursor_helper_close_failure_swallowed_on_success() -> None:
    events: list[str] = []
    conn = _FakeConn(events, fail_close=True)
    store = _make_store(conn, events)

    # A failing close() on the success path is best-effort: swallowed, no exception surfaces.
    async with store._cursor(conn) as cur:
        await cur.execute("noop")

    assert conn.cursor_obj.closed == 1
