# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline checks of the SQL Server lock-hold helpers in ``tests/_claim_lock_helpers.py`` (BACKLOG #4915).

The helpers run only on the hosted SQL Server legs, where a failure in their cleanup shows up as a
hang in the NEXT test rather than in the one that failed. These stand-ins drive the failure paths a
live server never offers on demand: a ROLLBACK that raises, and a cancellation while the lock is
being taken. Each must still hand the connection back to the pool, and close the cursor before its
connection. The stand-in raises before any gated pyodbc call is running, so the gate's deferred close
behind a running statement is not driven here; ``tests/test_backlog2049_sqlserver_cancel_handle_free.py``
drives that path."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from messagefoundry.odbc_call_gate import call_gate
from tests._claim_lock_helpers import ss_hold_row_lock, ss_release_row_lock


class _RawCursor:
    def __init__(self, closed: list[str]) -> None:
        self._closed = closed

    def close(self) -> None:
        self._closed.append("cursor")


class _RawConn:
    def __init__(self, closed: list[str]) -> None:
        self._closed = closed

    def close(self) -> None:
        self._closed.append("conn")


class _Cursor:
    """An aioodbc-shaped cursor: ``_impl`` is the raw handle; ``fail_on`` raises on that statement."""

    def __init__(self, closed: list[str], fail_on: str | None, exc: BaseException) -> None:
        self._impl = _RawCursor(closed)
        self._fail_on = fail_on
        self._exc = exc
        self.statements: list[str] = []
        self._rows: list[tuple[Any, ...]] = []

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.statements.append(sql)
        if self._fail_on is not None and sql.startswith(self._fail_on):
            raise self._exc
        self._rows = [("IB_X", "pending", 1)] if sql.startswith("SELECT") else []

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows

    async def close(self) -> None:
        self._impl.close()


class _Conn:
    """An aioodbc-shaped connection with a bound ``_execute``, so the call gate installs on it."""

    _executor = None

    def __init__(self, closed: list[str], cur: _Cursor) -> None:
        self._conn: Any = _RawConn(closed)
        self._cur = cur

    def _execute(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    async def cursor(self) -> _Cursor:
        return self._cur


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn
        self.released: list[_Conn] = []

    async def acquire(self) -> _Conn:
        return self._conn

    async def release(self, conn: _Conn) -> None:
        self.released.append(conn)


class _Store:
    def __init__(self, pool: _Pool) -> None:
        self._pool = pool


def _rig(fail_on: str | None, exc: BaseException) -> tuple[_Store, _Conn, _Cursor, list[str]]:
    closed: list[str] = []
    cur = _Cursor(closed, fail_on, exc)
    conn = _Conn(closed, cur)
    return _Store(_Pool(conn)), conn, cur, closed


async def _settled(closed: list[str], want: int) -> list[str]:
    """The discard's close runs on an executor thread; wait for it, bounded."""
    for _ in range(200):
        if len(closed) >= want:
            break
        await asyncio.sleep(0.005)
    return closed


async def test_a_clean_release_rolls_back_and_recycles_the_connection() -> None:
    """THE CONTROL: with nothing failing, the connection goes back to the pool still open."""
    store, conn, cur, closed = _rig(None, RuntimeError())
    held_conn, held_cur = await ss_hold_row_lock(store, "m1", "ingress")
    await ss_release_row_lock(store, held_conn, held_cur)
    assert cur.statements[-1] == "ROLLBACK TRAN"
    assert call_gate(conn) is not None, "the hold must gate the connection it may have to discard"
    assert store._pool.released == [conn]
    assert conn._conn is not None, "a clean release must not discard the connection"
    assert closed == ["cursor"]


async def test_a_rollback_that_raises_still_releases_and_discards() -> None:
    """Before BACKLOG #4915 the callers' ``finally`` skipped the close and the release when the
    ROLLBACK raised, leaving the lock held against the next test's cleanup DELETE."""
    store, conn, _, closed = _rig("ROLLBACK", RuntimeError("connection broken"))
    held_conn, held_cur = await ss_hold_row_lock(store, "m1", "ingress")
    with pytest.raises(RuntimeError, match="connection broken"):
        await ss_release_row_lock(store, held_conn, held_cur)
    assert store._pool.released == [conn]
    assert conn._conn is None, "the connection must leave the pool's reach, not be recycled"
    assert await _settled(closed, 2) == ["cursor", "conn"], (
        "the cursor closes before its connection"
    )


async def test_a_cancellation_while_taking_the_lock_still_releases() -> None:
    """``except Exception`` never saw a cancellation, so the old setup cleanup leaked the connection."""
    store, conn, _, closed = _rig("BEGIN TRAN", asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await ss_hold_row_lock(store, "m1", "ingress")
    assert store._pool.released == [conn]
    assert conn._conn is None
    assert await _settled(closed, 2) == ["cursor", "conn"]
