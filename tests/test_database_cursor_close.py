# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1104: a pooled connection must never go back to the pool with an open cursor.

aioodbc/pyodbc keep the ODBC statement handle open until the cursor is closed. A connection released
with an open handle is handed to the NEXT caller still busy, and that caller's first command fails
with ``HY000 Connection is busy with results for another command`` -- attributed to whatever statement
happens to land on the recycled connection, not to the one that left it dirty.

**Why this is delivery semantics, not tidiness.** An ``UPDATE`` leaves a row count pending, so the
DATABASE source's ``mark`` is the usual victim, and ``_poll_once`` treats a failed mark as
at-least-once: the row is left unmarked and **re-emitted as a duplicate** on the next poll. Observed
on a real SQL Server 2022 container against ``main``:

    DATABASE source mark failed (row will re-emit, a duplicate):
      ('HY000', '[Microsoft][ODBC Driver 18 for SQL Server]Connection is busy with results
       for another command')
    assert [(1, 1)] == [(0, 2)]        # one row unmarked -> it will re-emit

**These tests are deterministic ON PURPOSE.** The integration test that first exposed this is racy --
it depends on pool reuse order, and measured 1 failure in 10 runs on the unfixed tree. A guard with a
~10% detection rate is not a guard, and "0 failures in 10 runs after the fix" is not evidence either:
at that base rate the difference is well inside chance. So the invariant is asserted directly, by
recording the ORDER of operations against a fake pool, where it holds or fails every time.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.transports import database as db


class _FakeCursor:
    def __init__(self, log: list[str], tag: str) -> None:
        self._log, self._tag = log, tag
        self.description: list[tuple[str, Any]] = [("id", None)]

    async def execute(self, *_a: Any, **_k: Any) -> None:
        self._log.append(f"execute:{self._tag}")

    async def fetchall(self) -> list[Any]:
        return []

    async def close(self) -> None:
        self._log.append(f"close:{self._tag}")


class _FakeConn:
    def __init__(self, log: list[str], tag: str) -> None:
        self._log, self._tag = log, tag

    async def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._log, self._tag)

    async def commit(self) -> None:
        self._log.append("commit")

    async def rollback(self) -> None:  # pragma: no cover - not exercised here
        self._log.append("rollback")


class _FakePool:
    """Records acquire/release so the ORDER of close vs release is checkable."""

    def __init__(self, log: list[str], tag: str) -> None:
        self._log, self._tag = log, tag

    async def acquire(self) -> _FakeConn:
        self._log.append("acquire")
        return _FakeConn(self._log, self._tag)

    async def release(self, _conn: Any) -> None:
        self._log.append("release")


def _assert_closed_before_released(log: list[str]) -> None:
    """Every release must be immediately preceded by a close of that connection's cursor."""
    assert "release" in log, f"the connection was never released; log={log}"
    for i, op in enumerate(log):
        if op == "release":
            assert i > 0 and log[i - 1].startswith("close:"), (
                "a pooled connection was released WITHOUT closing its cursor -- the next caller "
                f"receives it busy and fails with HY000. log={log}"
            )


@pytest.mark.asyncio
async def test_source_select_closes_its_cursor_before_release() -> None:
    src = object.__new__(db.DatabaseSource)
    log: list[str] = []
    pool = _FakePool(log, "select")
    src._get_pool = lambda: _pool_coro(pool)  # type: ignore[method-assign,assignment]
    src._acquire_timeout = 5.0  # type: ignore[attr-defined]
    src._poll_sql = "SELECT 1"  # type: ignore[attr-defined]

    await src._select()
    assert "close:select" in log, f"the poll cursor was never closed; log={log}"
    _assert_closed_before_released(log)


@pytest.mark.asyncio
async def test_source_mark_closes_its_cursor_before_release() -> None:
    """The mark is the site that actually bites: an UPDATE leaves a row count pending."""
    src = object.__new__(db.DatabaseSource)
    log: list[str] = []
    pool = _FakePool(log, "mark")
    src._get_pool = lambda: _pool_coro(pool)  # type: ignore[method-assign,assignment]
    src._acquire_timeout = 5.0  # type: ignore[attr-defined]
    src._mark_sql = "UPDATE t SET done=1 WHERE id=?"  # type: ignore[attr-defined]
    src._mark_names = ("id",)  # type: ignore[attr-defined]

    await src._mark({"id": 1})
    assert "close:mark" in log, f"the mark cursor was never closed; log={log}"
    _assert_closed_before_released(log)


@pytest.mark.asyncio
async def test_close_cursor_never_raises_and_never_skips_the_release() -> None:
    """A close failure must not mask the caller's error, nor strand the connection.

    Leaking a pooled connection to save a cursor would be the worse trade, so ``_close_cursor``
    swallows. This pins that it swallows -- if it ever propagates, the ``finally`` above it stops
    releasing and the pool drains to nothing under a flapping driver.
    """

    class _Boom:
        async def close(self) -> None:
            raise RuntimeError("driver went away mid-close")

    await db._close_cursor(_Boom())  # must not raise
    await db._close_cursor(None)  # the never-opened case


def _pool_coro(pool: _FakePool) -> Any:
    async def _c() -> _FakePool:
        return pool

    return _c()
