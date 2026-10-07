# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every session statement binds exactly as many parameters as it has placeholders (BACKLOG #2283).

The session cap, the inventory and the purge build their SQL from shared clauses, and the cap
repeats a group's parameters once per group. A miscount there fails only when the statement runs.
SQLite runs it in every local suite, so a SQLite miscount is caught there. The SQL Server and
Postgres statements run only on the hosted legs, which a local run skips. A miscount on those two
would surface only in CI, after the Builder that wrote it has gone.

**These tests need no database.** Each store is built with ``__new__``, as
``test_store_pool_acquire_timeout.py`` builds it, and its borrow is replaced by a connection that
records each statement and its parameters instead of running them. Then the count is checked:
``?`` against the parameter tuple on SQL Server, and on Postgres the set of ``$n`` against
``1..len(args)``, so a skipped or an extra number fails too.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.pool_metrics import AcquireWaitHistogram

_HASH = "a" * 64
_OTHER = "b" * 64
_NOW = 1_000_000.0

# One call per session statement shape, with every branch that changes the SQL. Each takes the
# store and awaits one method.
_CALLS: dict[str, Callable[[Any], Awaitable[Any]]] = {
    "create_session": lambda s: s.create_session(
        token_hash=_HASH, user_id="u", expires_at=_NOW + 60, now=_NOW, auth_mechanism="password"
    ),
    "create_session_oidc": lambda s: s.create_session(
        token_hash=_HASH,
        user_id="u",
        expires_at=_NOW + 60,
        now=_NOW,
        auth_mechanism="oidc",
        idp_auth_time=_NOW - 5,
    ),
    "get_session": lambda s: s.get_session(_HASH),
    "list_sessions": lambda s: s.list_sessions("u", now=_NOW),
    "list_sessions_idle": lambda s: s.list_sessions("u", now=_NOW, idle_seconds=1800),
    "touch_session": lambda s: s.touch_session(_HASH, now=_NOW),
    "mark_session_reauthed": lambda s: s.mark_session_reauthed(_HASH, now=_NOW, client="c"),
    "mark_session_reauthed_idp": lambda s: s.mark_session_reauthed(
        _HASH, now=_NOW, client="c", idp_auth_time=_NOW - 5
    ),
    "mark_session_mfa_verified": lambda s: s.mark_session_mfa_verified(_HASH, now=_NOW),
    "rotate_session": lambda s: s.rotate_session(_HASH, new_token_hash=_OTHER),
    "revoke_session": lambda s: s.revoke_session(_HASH, now=_NOW),
    "supersede_session": lambda s: s.supersede_session(_HASH, now=_NOW),
    "revoke_user_sessions": lambda s: s.revoke_user_sessions("u", now=_NOW),
    "revoke_user_sessions_except": lambda s: s.revoke_user_sessions(
        "u", except_token_hash=_HASH, now=_NOW
    ),
    "enforce_session_cap": lambda s: s.enforce_session_cap(
        "u", keep=2, idle_seconds=1800, split_mfa_pending=False, now=_NOW
    ),
    "enforce_session_cap_split": lambda s: s.enforce_session_cap(
        "u", keep=2, idle_seconds=1800, split_mfa_pending=True, now=_NOW
    ),
    "purge_expired_sessions": lambda s: s.purge_expired_sessions(now=_NOW),
    "purge_expired_sessions_idle": lambda s: s.purge_expired_sessions(now=_NOW, idle_seconds=1800),
}


# --- SQL Server --------------------------------------------------------------


class _MssqlCursor:
    """Records each statement. Reports one affected row and no result rows, which every session
    method accepts."""

    def __init__(self, seen: list[tuple[str, tuple[Any, ...]]]) -> None:
        self._seen = seen
        self.rowcount = 1
        self.description: list[tuple[str]] = [("token_hash",)]

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self._seen.append((sql, tuple(params)))

    async def fetchall(self) -> list[Any]:
        return []

    async def close(self) -> None:
        return None


class _MssqlConn:
    def __init__(self, seen: list[tuple[str, tuple[Any, ...]]]) -> None:
        self._seen = seen

    async def cursor(self) -> _MssqlCursor:
        return _MssqlCursor(self._seen)

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


def _mssql_store(seen: list[tuple[str, tuple[Any, ...]]]) -> Any:
    from messagefoundry.store.sqlserver import SqlServerStore

    store: Any = SqlServerStore.__new__(SqlServerStore)
    store._settings = StoreSettings(command_timeout=0)
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0

    @asynccontextmanager
    async def _acquire() -> AsyncIterator[_MssqlConn]:
        yield _MssqlConn(seen)

    store._acquire = _acquire
    return store


@pytest.mark.parametrize("name", sorted(_CALLS))
async def test_sqlserver_session_statements_bind_every_placeholder(name: str) -> None:
    seen: list[tuple[str, tuple[Any, ...]]] = []
    await _CALLS[name](_mssql_store(seen))
    assert seen, f"{name} ran no statement -- the recorder is not wired, not the SQL"
    for sql, params in seen:
        assert sql.count("?") == len(params), (
            f"{name}: {sql.count('?')} placeholders but {len(params)} parameters in:\n{sql}"
        )


def _nocount_store(seen: list[tuple[str, tuple[Any, ...]]], output_rows: list[Any]) -> Any:
    """A SQL Server store whose driver reports ``-1`` for every row count, as a session-wide
    ``SET NOCOUNT ON`` can, and whose ``OUTPUT`` rowset is ``output_rows``."""
    store = _mssql_store(seen)

    class _NoCountCursor(_MssqlCursor):
        async def fetchall(self) -> list[Any]:
            return output_rows

    class _NoCountConn(_MssqlConn):
        async def cursor(self) -> _MssqlCursor:
            cur = _NoCountCursor(self._seen)
            cur.rowcount = -1
            return cur

    @asynccontextmanager
    async def _acquire() -> AsyncIterator[_MssqlConn]:
        yield _NoCountConn(seen)

    store._acquire = _acquire
    return store


@pytest.mark.parametrize("output_rows", [[], [(_OTHER,)]])
async def test_sqlserver_rotate_reads_its_output_rowset_not_the_row_count(
    output_rows: list[Any],
) -> None:
    """BACKLOG #2283: a session-wide ``SET NOCOUNT ON`` can report ``-1`` for a zero-match UPDATE,
    and ``bool(-1)`` is True. Read from the count, a rotation of a revoked session would report
    success and hand the caller a token for nothing. The rowset decides instead, whatever the
    count says."""
    seen: list[tuple[str, tuple[Any, ...]]] = []
    store = _nocount_store(seen, output_rows)
    assert await store.rotate_session(_HASH, new_token_hash=_OTHER) is bool(output_rows)
    assert "OUTPUT inserted.token_hash" in seen[0][0]


@pytest.mark.parametrize("revoked", [0, 3])
async def test_sqlserver_revoke_user_sessions_counts_its_output_rowset(revoked: int) -> None:
    """The same hazard, on a count that is audited and returned to the API caller: read from the
    driver it would be ``-1`` whether three sessions were revoked or none."""
    seen: list[tuple[str, tuple[Any, ...]]] = []
    store = _nocount_store(seen, [(f"{n:064x}",) for n in range(revoked)])
    assert await store.revoke_user_sessions("u", except_token_hash=_HASH, now=_NOW) == revoked
    assert "OUTPUT inserted.token_hash" in seen[0][0]


async def test_sqlserver_supersede_returns_the_output_row_by_column_name() -> None:
    """``supersede_session`` reads its ``OUTPUT inserted.*`` row through ``_execute_output``
    (BACKLOG #2283), which pairs each value with its column name. Read by position instead, a
    reordered column list would fill the record from the wrong columns."""
    columns = ("user_id", "token_hash", "revoked_at", "expires_at", "created_at", "last_used_at")
    row = ("u", _HASH, _NOW, _NOW + 60, _NOW - 60, _NOW - 30)
    seen: list[tuple[str, tuple[Any, ...]]] = []
    store = _mssql_store(seen)

    class _ColumnsCursor(_MssqlCursor):
        def __init__(self, seen: list[tuple[str, tuple[Any, ...]]]) -> None:
            super().__init__(seen)
            self.description = [(c,) for c in (*columns, "client")]

        async def fetchall(self) -> list[Any]:
            return [(*row, None)]

    class _ColumnsConn(_MssqlConn):
        async def cursor(self) -> _MssqlCursor:
            return _ColumnsCursor(self._seen)

    @asynccontextmanager
    async def _acquire() -> AsyncIterator[_MssqlConn]:
        yield _ColumnsConn(seen)

    store._acquire = _acquire
    ended = await store.supersede_session(_HASH, now=_NOW)
    assert ended is not None
    assert (ended.user_id, ended.token_hash, ended.revoked_at) == ("u", _HASH, _NOW)
    assert (ended.created_at, ended.last_used_at, ended.expires_at) == (
        _NOW - 60,
        _NOW - 30,
        _NOW + 60,
    )
    assert "OUTPUT inserted.*" in seen[0][0]

    empty = _nocount_store([], [])
    assert await empty.supersede_session(_HASH, now=_NOW) is None


@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize("revoked", [0, 2])
async def test_sqlserver_session_cap_counts_its_output_rowset(revoked: int, split: bool) -> None:
    """The cap's count is audited too (BACKLOG #2283, row item 9), so it is read the same way."""
    seen: list[tuple[str, tuple[Any, ...]]] = []
    store = _nocount_store(seen, [(f"{n:064x}",) for n in range(revoked)])
    assert (
        await store.enforce_session_cap(
            "u", keep=2, idle_seconds=1800, split_mfa_pending=split, now=_NOW
        )
        == revoked
    )
    assert "OUTPUT inserted.token_hash" in seen[0][0]


# --- Postgres ----------------------------------------------------------------


class _PgConn:
    """Records each statement and returns what asyncpg would for a one-row change."""

    def __init__(self, seen: list[tuple[str, tuple[Any, ...]]]) -> None:
        self._seen = seen

    async def execute(self, sql: str, *args: Any) -> str:
        self._seen.append((sql, args))
        return "UPDATE 1"

    async def fetch(self, sql: str, *args: Any) -> list[Any]:
        self._seen.append((sql, args))
        return []

    async def fetchrow(self, sql: str, *args: Any) -> Any:
        self._seen.append((sql, args))
        return None

    def transaction(self) -> Any:
        @asynccontextmanager
        async def _txn() -> AsyncIterator[None]:
            yield

        return _txn()


class _NoPool:
    """Stands in for the asyncpg pool. A session method that reaches it borrowed outside
    ``_timed_acquire``, so with no acquire timeout (BACKLOG #1052)."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(
            f"a session method used self._pool.{name}, a borrow outside the bounded helper"
        )


def _pg_store(seen: list[tuple[str, tuple[Any, ...]]]) -> Any:
    from messagefoundry.store.postgres import PostgresStore

    store: Any = PostgresStore.__new__(PostgresStore)
    store._settings = StoreSettings()
    store._acquire_wait = AcquireWaitHistogram()

    @asynccontextmanager
    async def _timed_acquire(*, record: bool = True) -> AsyncIterator[_PgConn]:
        yield _PgConn(seen)

    store._timed_acquire = _timed_acquire

    async def _execute_after_commit(sql: str, *args: Any) -> int:
        # The one sanctioned unbounded borrow, for the two writes that follow a committed one
        # (BACKLOG #2283). Recorded like every other statement, and counted from the status tag
        # the way the real helper counts it.
        from messagefoundry.store.postgres import _rowcount

        return _rowcount(await _PgConn(seen).execute(sql, *args))

    store._execute_after_commit = _execute_after_commit
    # Any other borrow that bypasses the bounded helper reaches this and fails with a message naming
    # the bypass, rather than with a bare AttributeError.
    store._pool = _NoPool()
    return store


_PG_PLACEHOLDER = re.compile(r"\$(\d+)")


@pytest.mark.parametrize("name", sorted(_CALLS))
async def test_postgres_session_statements_bind_every_placeholder(name: str) -> None:
    seen: list[tuple[str, tuple[Any, ...]]] = []
    await _CALLS[name](_pg_store(seen))
    assert seen, f"{name} ran no statement -- the recorder is not wired, not the SQL"
    for sql, args in seen:
        used = {int(n) for n in _PG_PLACEHOLDER.findall(sql)}
        assert used == set(range(1, len(args) + 1)), (
            f"{name}: placeholders {sorted(used)} but {len(args)} parameters in:\n{sql}"
        )


async def test_the_checks_catch_a_miscount(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control: both checks above must be able to fail. A stray placeholder is planted in each
    backend's session-cap clause, the shared piece a miscount would most likely come from, and the
    recorded statement must then fail the same comparison the tests make."""
    from messagefoundry.store import postgres, sqlserver
    from messagefoundry.store.store import _SESSION_LIVE_SQL

    monkeypatch.setattr(sqlserver, "_SESSION_LIVE_SQL", _SESSION_LIVE_SQL + " AND 1=?")
    seen: list[tuple[str, tuple[Any, ...]]] = []
    await _CALLS["enforce_session_cap"](_mssql_store(seen))
    assert any(sql.count("?") != len(params) for sql, params in seen)

    monkeypatch.setattr(postgres, "_pg_session_cap_keep_sql", lambda split: " AND 1=$5")
    seen = []
    await _CALLS["enforce_session_cap"](_pg_store(seen))
    assert any(
        {int(n) for n in _PG_PLACEHOLDER.findall(sql)} != set(range(1, len(args) + 1))
        for sql, args in seen
    )
