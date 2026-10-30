# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3740 items 10 and 12: the statements the upload-quota reserve and release send.

These tests pin the statement shape and run everywhere: SQLite through its trace callback, and the
two server backends against recording fakes, offline. What the statements DO on a live server is
pinned by `tests/test_uploads_shard_quota_interleave.py`, whose PostgreSQL and SQL Server legs
run only where `MEFOR_TEST_POSTGRES` / `MEFOR_TEST_SQLSERVER` are set.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore, _upload_quota_lock
from messagefoundry.store.store import MessageStore


def _insert(statements: list[str]) -> str:
    (insert,) = [s for s in statements if s.lstrip().upper().startswith("INSERT INTO UPLOAD_RES")]
    return insert


def _pg_log(log: list[tuple[str, tuple[Any, ...]]], sql: str, params: tuple[Any, ...]) -> None:
    # asyncpg binds $1..$N; the highest index must be the number of values passed.
    assert max(map(int, re.findall(r"\$(\d+)", sql)), default=0) == len(params), (sql, params)
    log.append((sql, params))


def _reads_of_the_ledger(sql: str) -> int:
    return sql.upper().count("FROM UPLOAD_RESERVATION")


# --- SQLite, through the live connection's trace callback ------------------------------------------


async def test_the_sqlite_reserve_reads_its_budget_in_one_aggregate(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "engine.db")
    try:
        traced: list[str] = []
        await store._db.set_trace_callback(traced.append)
        assert await store.reserve_upload_quota(
            "u-a", "r-1", size_bytes=10, max_files=2, max_total_bytes=30
        )
        off: Any = None  # sqlite3 clears the trace on None; aiosqlite's stub types only a callable
        await store._db.set_trace_callback(off)
        insert = _insert(traced)
        # The insert itself, plus ONE aggregate over the uploader's rows. Two subqueries read it
        # twice before item 12.
        assert _reads_of_the_ledger(insert) == 1, insert
        assert "COUNT(*)" in insert.upper() and "SUM(SIZE_BYTES)" in insert.upper(), insert
    finally:
        await store.close()


# --- SQL Server, against a recording cursor -------------------------------------------------------


class _MssqlCursor:
    def __init__(self, log: list[tuple[str, Any]]) -> None:
        self.log = log

    async def execute(self, sql: str, params: Any = ()) -> None:
        # One bound value per placeholder, so a dropped or extra parameter fails offline too.
        assert sql.count("?") == len(params), (sql, params)
        self.log.append(("sql", (sql, tuple(params))))

    async def fetchall(self) -> list[Any]:
        return []

    async def fetchone(self) -> Any:
        return ("r-1",)  # the reserve's OUTPUT row, the only fetchone either method makes


def _mssql(log: list[tuple[str, Any]]) -> SqlServerStore:
    store = object.__new__(SqlServerStore)
    cur = _MssqlCursor(log)

    @asynccontextmanager
    async def _acquire() -> AsyncIterator[Any]:
        yield object()

    @asynccontextmanager
    async def _cursor(conn: Any) -> AsyncIterator[Any]:
        yield cur

    async def _applock(cursor: Any, resource: str) -> None:
        log.append(("applock", resource))

    async def _commit(conn: Any) -> None:
        log.append(("commit", None))

    async def _rollback_or_discard(conn: Any) -> None:
        log.append(("rollback", None))

    vars(store).update(
        _acquire=_acquire,
        _cursor=_cursor,
        _applock=_applock,
        _commit=_commit,
        _rollback_or_discard=_rollback_or_discard,
    )
    return store


async def test_the_sqlserver_release_takes_the_named_uploaders_lock_without_reading_it() -> None:
    log: list[tuple[str, Any]] = []
    await _mssql(log).release_upload_quota(uploader_id="u-a", reservation_id="r-1")
    statements = [entry for kind, entry in log if kind == "sql"]
    # No read of the row by its reservation id, under any hint: the caller named the uploader.
    assert not any("READCOMMITTEDLOCK" in sql.upper() for sql, _ in statements), statements
    assert not any(
        sql.lstrip().upper().startswith("SELECT") and "r-1" in params for sql, params in statements
    ), statements
    kinds = [kind for kind, _ in log]
    assert kinds == ["sql", "applock", "sql", "commit"], log
    assert log[1] == ("applock", _upload_quota_lock("u-a"))
    delete_sql, delete_params = log[2][1]
    assert delete_sql.lstrip().upper().startswith("DELETE FROM UPLOAD_RESERVATION"), delete_sql
    assert "UPLOADER_ID" in delete_sql.upper() and delete_params == ("r-1", "u-a"), log[2]


async def test_the_sqlserver_reserve_reads_its_budget_in_one_aggregate() -> None:
    log: list[tuple[str, Any]] = []
    assert await _mssql(log).reserve_upload_quota(
        "u-a", "r-1", size_bytes=10, max_files=2, max_total_bytes=30
    )
    insert = _insert([entry[0] for kind, entry in log if kind == "sql"])
    assert _reads_of_the_ledger(insert) == 1, insert
    # The applock is still taken before the stale delete and the insert.
    kinds = [kind for kind, _ in log]
    assert kinds[:2] == ["sql", "applock"] and kinds[-1] == "commit", log


# --- PostgreSQL, against a recording connection ----------------------------------------------------


class _PgConn:
    def __init__(self, log: list[tuple[str, tuple[Any, ...]]]) -> None:
        self.log = log

    @asynccontextmanager
    async def transaction(self, **_kwargs: Any) -> AsyncIterator[None]:
        yield None

    async def execute(self, sql: str, *params: Any) -> str:
        _pg_log(self.log, sql, params)
        return "DELETE 0"

    async def fetchval(self, sql: str, *params: Any) -> Any:
        _pg_log(self.log, sql, params)
        return 1


def _pg(log: list[tuple[str, tuple[Any, ...]]]) -> PostgresStore:
    store = object.__new__(PostgresStore)
    conn = _PgConn(log)

    @asynccontextmanager
    async def _timed_acquire(*, record: bool = True) -> AsyncIterator[Any]:
        yield conn

    async def _advisory_lock(c: Any, classid: int, key: str) -> None:
        return None

    async def _execute(sql: str, *params: Any) -> int:
        _pg_log(log, sql, params)
        return 0

    vars(store).update(
        _timed_acquire=_timed_acquire, _advisory_lock=_advisory_lock, _execute=_execute
    )
    return store


async def test_the_postgres_reserve_reads_its_budget_in_one_aggregate() -> None:
    log: list[tuple[str, tuple[Any, ...]]] = []
    assert await _pg(log).reserve_upload_quota(
        "u-a", "r-1", size_bytes=10, max_files=2, max_total_bytes=30
    )
    insert = _insert([sql for sql, _ in log])
    assert _reads_of_the_ledger(insert) == 1, insert


async def test_the_postgres_release_matches_the_uploader() -> None:
    log: list[tuple[str, tuple[Any, ...]]] = []
    await _pg(log).release_upload_quota(uploader_id="u-a", reservation_id="r-1")
    ((sql, params),) = log
    assert sql.upper().startswith("DELETE FROM UPLOAD_RESERVATION") and "UPLOADER_ID" in sql.upper()
    assert params == ("r-1", "u-a")
