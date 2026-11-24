# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The PostgreSQL and SQL Server at-open seal opens many cells per Transit request (vault BACKLOG
#6706).

The SQLite seal already sends each page through ``encrypt_many`` (``test_transit_batch.py``). The two
server ``_seal_surface`` sweeps sealed each cell with its own ``cipher.encrypt``, so under
``vault_transit`` a surface of N legacy values cost N Transit requests. These tests drive the real
``_seal_surface`` of each server store against an in-memory stand-in for its connection, so no
server is needed, and count requests against the batch-answering fake Transit. Synthetic data only.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

pytest.importorskip("requests", reason="Transit batch tests need the [vault] extra")
pytest.importorskip("hvac", reason="Transit batch tests need the [vault] extra")

from messagefoundry.store.crypto import cell_aad
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from tests.test_transit_batch import _BatchTransit, _cipher

_ROWS = 200
_LIKE = "mfenc:%"


def _legacy_rows() -> list[dict[str, Any]]:
    """``state`` rows holding legacy plaintext, keyed by (namespace, key)."""
    return [
        {"namespace": "ns", "key": f"k{i}", "value": f"synthetic value {i}"} for i in range(_ROWS)
    ]


def _pending(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return [
        {"namespace": r["namespace"], "key": r["key"], "v": r["value"]}
        for r in rows
        if r["value"] and not r["value"].startswith("mfenc:")
    ][:limit]


def _limit(sql: str, word: str) -> int:
    """The row limit a page SELECT names after ``word`` (``LIMIT 500`` or ``TOP (500)``)."""
    tail = sql.split(word, 1)[1].strip().lstrip("(")
    return int(tail.split(")")[0].split()[0])


def _assert_sealed(rows: list[dict[str, Any]], transit: _BatchTransit) -> None:
    opener = _cipher(transit)
    for i, r in enumerate(rows):
        assert r["value"].startswith("mfenc:")
        aad = cell_aad("state", "value", r["namespace"], r["key"])
        assert opener.decrypt(r["value"], aad=aad) == f"synthetic value {i}"


class _PgConn:
    """The asyncpg connection calls the PostgreSQL seal makes, over a list of rows."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        yield

    async def fetchval(self, sql: str, *params: Any) -> Any:
        assert "keyed_surface" in sql
        return 1  # this open wrote the marker

    async def fetch(self, sql: str, *params: Any) -> list[dict[str, Any]]:
        return _pending(self.rows, _limit(sql, "LIMIT"))

    async def execute(self, sql: str, value: str, namespace: str, key: str) -> None:
        assert sql.startswith("UPDATE state SET value=$1")
        for r in self.rows:
            if (r["namespace"], r["key"]) == (namespace, key):
                r["value"] = value


def _pg_store(conn: _PgConn, transit: _BatchTransit) -> PostgresStore:
    store = object.__new__(PostgresStore)
    store._cipher = _cipher(transit)

    async def surface_keyed(table: str, column: str) -> bool:
        return False

    async def fetchval(sql: str, *params: Any) -> int:
        return len(_pending(conn.rows, _ROWS))

    async def holds_ciphertext(table: str, column: str, like: str) -> bool:
        return False

    async def noop(*args: Any, **kwargs: Any) -> None:
        return None

    @asynccontextmanager
    async def timed_acquire(*, record: bool = True) -> AsyncIterator[_PgConn]:
        yield conn

    store._surface_keyed = surface_keyed  # type: ignore[method-assign]
    store._fetchval = fetchval  # type: ignore[method-assign]
    store._surface_holds_ciphertext = holds_ciphertext  # type: ignore[method-assign]
    store._charge_bound_batch = noop  # type: ignore[method-assign]
    store._timed_acquire = timed_acquire  # type: ignore[method-assign]
    return store


async def test_the_postgres_seal_seals_many_cells_per_transit_request() -> None:
    transit = _BatchTransit()
    conn = _PgConn(_legacy_rows())
    store = _pg_store(conn, transit)
    sealed = await store._seal_surface("state", "value", _LIKE, aad_cols=("namespace", "key"))
    assert sealed == _ROWS
    # One request per cell before the batch path: 200. One page of 200 is two batches of 128.
    assert transit.encrypt_requests == 2
    _assert_sealed(conn.rows, transit)


class _MssqlCursor:
    """The aioodbc cursor calls the SQL Server seal makes, over a list of rows."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.description: list[tuple[str]] = []
        self._result: list[tuple[Any, ...]] = []

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        if sql.startswith("SELECT TOP"):
            self.description = [("namespace",), ("key",), ("v",)]
            self._result = [
                (r["namespace"], r["key"], r["v"]) for r in _pending(self.rows, _limit(sql, "TOP"))
            ]
            return
        assert sql.startswith("UPDATE state SET [value]=?")
        value, namespace, key = params
        for r in self.rows:
            if (r["namespace"], r["key"]) == (namespace, key):
                r["value"] = value

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return self._result


class _MssqlConn:
    async def rollback(self) -> None:
        raise AssertionError("the seal rolled back")


def _mssql_store(cur: _MssqlCursor, transit: _BatchTransit) -> SqlServerStore:
    store = object.__new__(SqlServerStore)
    store._cipher = _cipher(transit)
    conn = _MssqlConn()

    async def surface_keyed(table: str, column: str) -> bool:
        return False

    async def count_unmarked(count_sql: str, *params: str) -> int:
        return len(_pending(cur.rows, _ROWS))

    async def holds_ciphertext(table: str, column: str, like: str) -> bool:
        return False

    async def claim(conn: Any, cur: Any, table: str, column: str) -> bool:
        return True

    async def noop(*args: Any, **kwargs: Any) -> None:
        return None

    @asynccontextmanager
    async def acquire() -> AsyncIterator[_MssqlConn]:
        yield conn

    @asynccontextmanager
    async def cursor(conn: Any) -> AsyncIterator[_MssqlCursor]:
        yield cur

    store._surface_keyed = surface_keyed  # type: ignore[method-assign]
    store._count_unmarked = count_unmarked  # type: ignore[method-assign]
    store._surface_holds_ciphertext = holds_ciphertext  # type: ignore[method-assign]
    store._claim_keyed_surface = claim  # type: ignore[method-assign]
    store._commit = noop  # type: ignore[method-assign]
    store._charge_bound_batch = noop  # type: ignore[method-assign]
    store._acquire = acquire  # type: ignore[method-assign]
    store._cursor = cursor  # type: ignore[method-assign]
    return store


async def test_the_sqlserver_seal_seals_many_cells_per_transit_request() -> None:
    transit = _BatchTransit()
    cur = _MssqlCursor(_legacy_rows())
    store = _mssql_store(cur, transit)
    sealed = await store._seal_surface("state", "value", _LIKE, aad_cols=("namespace", "key"))
    assert sealed == _ROWS
    # One request per cell before the batch path: 200. One page of 200 is two batches of 128.
    assert transit.encrypt_requests == 2
    _assert_sealed(cur.rows, transit)
