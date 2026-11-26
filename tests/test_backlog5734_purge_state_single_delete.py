# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5734: ``purge_state`` on SQL Server and Postgres evicts only the keys it deleted.

Checked WITHOUT a database, so it runs everywhere. Each fake models a ``state`` table and a
concurrent ``state_set`` that refreshes one expired key just before the next statement runs. A
SELECT-then-DELETE purge lists that key, deletes nothing for it, and evicts it from the cache while
its row survives. A single ``DELETE ... OUTPUT`` / ``RETURNING`` reports only what it removed.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.crypto import IdentityCipher
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore
from tests.test_sqlserver_sync_handoff_offline import _acm
from tests.test_transform_state import _route_one_handler

_CUTOFF = 1_000.0


class _Table:
    """The ``state`` table: ``(namespace, key) -> set_at``. The concurrent writer refreshes the
    ``live`` key just before the DELETE runs, so a separate SELECT ahead of it still saw it expired."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], float] = {("ns", "stale"): 10.0, ("ns", "live"): 20.0}

    def before_delete(self) -> None:
        self.rows[("ns", "live")] = 5_000.0

    def select_expired(self) -> list[tuple[str, str]]:
        return [k for k, t in self.rows.items() if t < _CUTOFF]

    def delete_expired(self) -> list[tuple[str, str]]:
        gone = self.select_expired()
        for k in gone:
            del self.rows[k]
        return gone


class _SsCursor:
    #: The OUTPUT rowset's columns, as ``_execute_output`` reads them.
    description = (("namespace",), ("state_key",))

    def __init__(self, table: _Table) -> None:
        self._t = table
        self._result: list[tuple[str, str]] = []

    async def execute(self, sql: str, params: Any = ()) -> None:
        # The SELECT branch, and the non-RETURNING DELETEs below, serve only the pre-fix code, so
        # the test fails against it.
        if sql.startswith("SELECT"):
            self._result = self._t.select_expired()
        elif sql.startswith("DELETE"):
            self._t.before_delete()
            gone = self._t.delete_expired()
            self._result = gone if "OUTPUT" in sql else []
        else:
            raise AssertionError(sql)

    async def fetchall(self) -> list[tuple[str, str]]:
        return self._result


class _SsConn:
    async def commit(self) -> None:
        pass

    async def rollback(self) -> None:
        pass


class _PgConn:
    def __init__(self, table: _Table) -> None:
        self._t = table

    @asynccontextmanager
    async def transaction(self) -> Any:
        yield

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, str]]:
        if sql.startswith("SELECT"):
            keys = self._t.select_expired()
        elif sql.startswith("DELETE") and "RETURNING" in sql:
            self._t.before_delete()
            keys = self._t.delete_expired()
        else:
            raise AssertionError(sql)
        return [{"namespace": n, "key": k} for n, k in keys]

    async def execute(self, sql: str, *args: Any) -> str:
        assert sql.startswith("DELETE"), sql
        self._t.before_delete()
        self._t.delete_expired()
        return "DELETE"


def _cache() -> dict[tuple[str, str], Any]:
    return {("ns", "stale"): {"v": 1}, ("ns", "live"): {"v": 2}}


async def test_sqlserver_purge_state_keeps_a_key_refreshed_mid_purge() -> None:
    table = _Table()
    store = object.__new__(SqlServerStore)
    store._settings = StoreSettings()
    store._cipher = IdentityCipher()
    store.committed_txns = 0
    store._state_cache = _cache()
    store._acquire = _acm(_SsConn())  # type: ignore[method-assign]
    store._cursor = _acm(_SsCursor(table))  # type: ignore[method-assign]

    purged = await store.purge_state(older_than=_CUTOFF)

    assert ("ns", "live") in table.rows  # the refreshed row survives in the table ...
    assert ("ns", "live") in store._state_cache  # ... so the cache must keep it too
    assert ("ns", "stale") not in store._state_cache and ("ns", "stale") not in table.rows
    assert purged == 1


async def test_postgres_purge_state_keeps_a_key_refreshed_mid_purge() -> None:
    table = _Table()
    store = object.__new__(PostgresStore)
    store._cluster_state_convergence = False
    store._state_versions = {}
    store._state_cache = _cache()
    store._timed_acquire = _acm(_PgConn(table))  # type: ignore[method-assign]

    purged = await store.purge_state(older_than=_CUTOFF, now=2_000.0)

    assert ("ns", "live") in table.rows
    assert ("ns", "live") in store._state_cache
    assert ("ns", "stale") not in store._state_cache and ("ns", "stale") not in table.rows
    assert purged == 1


async def test_sqlite_purge_state_reads_and_deletes_in_one_immediate_transaction(
    tmp_path: Path,
) -> None:
    """SQLite: the SELECT that names the evicted keys and the DELETE share one ``BEGIN IMMEDIATE``
    transaction, so another process cannot refresh a listed key between them. An idle pass takes
    no write lock at all (the control)."""
    store = await MessageStore.open(tmp_path / "state.db")
    try:
        mid, routed = await _route_one_handler(store)
        await store.transform_handoff(
            routed_id=routed,
            message_id=mid,
            channel_id="IB",
            deliveries=[],
            state_ops=[("ns", "old", "x")],
            now=1_000.0,
        )
        traced: list[str] = []
        await store._db.set_trace_callback(traced.append)
        assert await store.purge_state(older_than=500.0) == 0  # control: nothing expired
        assert not any(s.startswith("BEGIN") for s in traced)
        assert await store.purge_state(older_than=1_500.0) == 1
        off: Any = None  # sqlite3 clears the trace on None; aiosqlite's stub types only a callable
        await store._db.set_trace_callback(off)
        begin = traced.index("BEGIN IMMEDIATE")
        select = next(i for i, s in enumerate(traced) if s.startswith("SELECT namespace, key"))
        delete = next(i for i, s in enumerate(traced) if s.startswith("DELETE FROM state"))
        assert begin < select < delete
        assert ("ns", "old") not in store.state_view()
    finally:
        await store.close()


def _acm_then(value: Any, on_release: Any) -> Any:
    """An acquire whose release runs ``on_release``: the await between the commit and the eviction,
    in which another coroutine on the loop can commit and publish a write."""

    @asynccontextmanager
    async def cm(*_args: Any, **_kwargs: Any) -> Any:
        yield value
        on_release()

    return cm


async def test_sqlserver_purge_state_keeps_a_key_rewritten_before_its_eviction() -> None:
    """Engine PR 2989 open finding 3: a same-key write that commits and publishes while the purge
    releases its connection must survive the purge's eviction, because its row survives."""
    table = _Table()
    store = object.__new__(SqlServerStore)
    store._settings = StoreSettings()
    store._cipher = IdentityCipher()
    store.committed_txns = 0
    store._state_cache = _cache()

    def rewrite_stale() -> None:
        table.rows[("ns", "stale")] = 5_000.0
        store.publish_state_cache([(("ns", "stale"), {"v": 3})])

    store._acquire = _acm_then(_SsConn(), rewrite_stale)  # type: ignore[method-assign]
    store._cursor = _acm(_SsCursor(table))  # type: ignore[method-assign]

    assert await store.purge_state(older_than=_CUTOFF) == 1
    assert ("ns", "stale") in table.rows
    assert store._state_cache[("ns", "stale")] == {"v": 3}
    assert store._state_purge_watches == ()


async def test_postgres_purge_state_keeps_a_key_rewritten_before_its_eviction() -> None:
    table = _Table()
    store = object.__new__(PostgresStore)
    store._cluster_state_convergence = False
    store._state_versions = {}
    store._state_cache = _cache()

    def rewrite_stale() -> None:
        table.rows[("ns", "stale")] = 5_000.0
        store._publish_state_cache([(("ns", "stale"), {"v": 3})])

    store._timed_acquire = _acm_then(_PgConn(table), rewrite_stale)  # type: ignore[method-assign]

    assert await store.purge_state(older_than=_CUTOFF, now=2_000.0) == 1
    assert ("ns", "stale") in table.rows
    assert store._state_cache[("ns", "stale")] == {"v": 3}
    assert store._state_purge_watches == ()


async def test_a_write_outside_a_purge_pass_is_not_watched() -> None:
    """Control: with no purge in flight a publish records nothing, so an untouched expired key is
    still evicted by the next pass."""
    table = _Table()
    store = object.__new__(PostgresStore)
    store._cluster_state_convergence = False
    store._state_versions = {}
    store._state_cache = _cache()
    store._publish_state_cache([(("ns", "stale"), {"v": 1})])
    store._timed_acquire = _acm(_PgConn(table))  # type: ignore[method-assign]

    assert await store.purge_state(older_than=_CUTOFF, now=2_000.0) == 1
    assert ("ns", "stale") not in store._state_cache
