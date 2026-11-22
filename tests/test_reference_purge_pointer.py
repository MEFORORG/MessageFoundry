# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5733: the purge's pointer update carries the age predicate, runs on a zero-row delete,
and evicts only what it marked.

The server-backend cases run the real ``purge_reference_snapshots`` against a small in-memory model
of the two tables, with no database. The model applies the predicates the SQL text states. It does
NOT model locking or isolation. Only a real server can prove at least: that read committed
re-evaluates the age predicate after a concurrent writer commits, that the version match keeps a
re-sync's rows out of the DELETE under RCSI, that the statements parse, and that ``OUTPUT
inserted.version`` returns the new value. **No hosted test calls this purge today, so none of those
is proved by CI.** The hosted Postgres and SQL Server legs would need a test added to prove them.
"""

from __future__ import annotations

import types
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.base import StoreAcquireTimeout
from messagefoundry.store.pool_metrics import AcquireWaitHistogram
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore
from tests.test_reference_sets import _seed

CUTOFF = 1000.0
AGED = 10.0
FRESH = 5000.0


class _Model:
    """The ``reference`` and ``reference_version`` rows for one set."""

    def __init__(self, *, version: str = "v1", synced_at: float = AGED, rows: int = 1) -> None:
        self.version = version
        self.synced_at = synced_at
        self.rows = rows
        self.commits = 0
        self.before_update: Callable[[], None] | None = None
        self.after_update: Callable[[], None] | None = None
        self.isolation: str | None = None
        self.in_txn = False
        self.txn_statements: list[str] = []
        self.resync_during_delete = False

    def select(self) -> list[str]:
        return ["orphan"] if self.synced_at < CUTOFF else []

    def delete(self) -> int:
        if self.in_txn:
            self.txn_statements.append("DELETE")
        if not self.synced_at < CUTOFF:
            return 0
        count, self.rows = self.rows, 0
        return count

    def update(self, sql: str, params: Sequence[Any]) -> str | None:
        """Apply the pointer UPDATE. An age predicate counts only if the statement states one, and
        it compares against the cutoff the statement actually bound."""
        if self.before_update is not None:
            self.before_update()
        if self.in_txn:
            self.txn_statements.append("UPDATE")
        new: str | None = None
        aged = "synced_at <" not in sql or self.synced_at < params[1]
        if aged and not self.version.startswith("purged:"):
            self.version = new = f"purged:{self.version}"
        if self.after_update is not None:
            self.after_update()
        return new


class _PgTxn:
    def __init__(self, model: _Model, isolation: str | None) -> None:
        self._model = model
        self._isolation = isolation

    async def __aenter__(self) -> None:
        self._model.isolation = self._isolation
        self._model.in_txn = True

    async def __aexit__(self, *exc: object) -> None:
        self._model.in_txn = False
        self._model.commits += 1


class _PgConn:
    def __init__(self, model: _Model) -> None:
        self._model = model

    def transaction(self, *, isolation: str | None = None) -> _PgTxn:
        return _PgTxn(self._model, isolation)

    async def execute(self, sql: str, *_args: Any) -> str:
        assert sql.startswith("DELETE"), "the pointer UPDATE must read back through fetchval"
        return f"DELETE {self._model.delete()}"

    async def fetchval(self, sql: str, *args: Any) -> str | None:
        return self._model.update(sql, args)


class _PgPool:
    """Serves only the candidate read and the borrow, so a statement run on the pool fails."""

    def __init__(self, model: _Model) -> None:
        self._model = model

    async def fetch(self, _sql: str, *_args: Any) -> list[dict[str, str]]:
        return [{"name": n} for n in self._model.select()]

    async def acquire(self) -> _PgConn:
        return _PgConn(self._model)

    async def release(self, _conn: object) -> None:
        return None


class _MsCursor:
    def __init__(self, model: _Model) -> None:
        self._model = model
        self.rowcount = 0
        self._rows: list[tuple[str]] = []

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        if sql.startswith("SELECT"):
            self._rows = [(n,) for n in self._model.select()]
        elif sql.startswith("DELETE"):
            if self._model.resync_during_delete:
                # RCSI: the EXISTS saw the aged pointer at statement start, and the target scan
                # blocked on the writer, then read its committed v2 rows.
                self._model.version, self._model.synced_at = "v2", FRESH
                self.rowcount = 0 if "v.version = reference.version" in sql else 1
                self._model.rows -= self.rowcount
            else:
                self.rowcount = self._model.delete()
            self._rows = []
        else:
            new = self._model.update(sql, params)
            self.rowcount = 1 if new else 0
            self._rows = [(new,)] if new and "OUTPUT" in sql else []

    async def fetchall(self) -> list[tuple[str]]:
        return self._rows

    async def close(self) -> None:
        return None


class _MsConn:
    def __init__(self, model: _Model) -> None:
        self._model = model

    async def cursor(self) -> _MsCursor:
        return _MsCursor(self._model)

    async def commit(self) -> None:
        self._model.commits += 1

    async def rollback(self) -> None:
        raise AssertionError("the purge must not roll back here")


class _MsPool:
    def __init__(self, model: _Model) -> None:
        self._model = model

    async def acquire(self) -> _MsConn:
        return _MsConn(self._model)

    async def release(self, _conn: object) -> None:
        return None


def _server_store(backend: str, model: _Model, *, cached: str | None = "v1") -> Any:
    store: Any
    if backend == "postgres":
        store = object.__new__(PostgresStore)
        store._pool = _PgPool(model)
    else:
        store = object.__new__(SqlServerStore)
        store._pool = _MsPool(model)
    store._settings = types.SimpleNamespace(command_timeout=0, acquire_timeout=30.0)
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0
    store._reference_cache = {}
    store._reference_versions = {}
    if cached is not None:
        store._reference_cache["orphan"] = {"K": "synthetic"}
        store._reference_versions["orphan"] = cached
    return store


async def _purge(store: Any) -> int:
    deleted: int = await store.purge_reference_snapshots(older_than=CUTOFF, declared={"keep"})
    return deleted


BACKENDS = ["postgres", "sqlserver"]


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_a_set_resynced_after_the_cutoff_is_neither_marked_nor_evicted(
    backend: str,
) -> None:
    """Mutation: drop ``synced_at < ?`` from the UPDATE and the fresh pointer is marked purged."""
    model = _Model()
    store = _server_store(backend, model)

    def resync() -> None:
        model.version, model.synced_at, model.rows = "v2", FRESH, 1
        store._reference_cache["orphan"] = {"K": "fresh"}
        store._reference_versions["orphan"] = "v2"

    model.before_update = resync
    await _purge(store)
    assert model.version == "v2"
    assert store._reference_cache["orphan"] == {"K": "fresh"}
    assert store._reference_versions["orphan"] == "v2"


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_an_aged_zero_row_set_is_marked_and_evicted(backend: str) -> None:
    """An abandoned empty snapshot, or one interrupted between its DELETE and UPDATE."""
    model = _Model(rows=0)
    store = _server_store(backend, model)
    assert await _purge(store) == 0
    assert model.version == "purged:v1"
    assert "orphan" not in store._reference_cache
    assert "orphan" not in store._reference_versions


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_a_second_purge_is_a_no_op(backend: str) -> None:
    model = _Model()
    store = _server_store(backend, model)
    assert await _purge(store) == 1
    # A later converge installs the empty purged snapshot; the second pass must not evict it.
    store._reference_cache["orphan"] = {}
    store._reference_versions["orphan"] = "purged:v1"
    assert await _purge(store) == 0
    assert model.version == "purged:v1"
    assert store._reference_versions["orphan"] == "purged:v1"


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_a_cache_that_moved_to_a_newer_version_is_not_evicted(backend: str) -> None:
    """A write that commits after the purge's UPDATE installs a version the purge never saw."""
    model = _Model()
    store = _server_store(backend, model)

    def newer() -> None:
        store._reference_cache["orphan"] = {"K": "newer"}
        store._reference_versions["orphan"] = "v2"

    model.after_update = newer
    await _purge(store)
    assert store._reference_cache["orphan"] == {"K": "newer"}
    assert store._reference_versions["orphan"] == "v2"


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_a_cache_already_on_the_purged_pointer_is_evicted(backend: str) -> None:
    """``converge_reference_cache`` may install the purged pointer before the check runs."""
    model = _Model()
    store = _server_store(backend, model)

    def converged() -> None:
        store._reference_versions["orphan"] = "purged:v1"

    model.after_update = converged
    await _purge(store)
    assert "orphan" not in store._reference_cache
    assert "orphan" not in store._reference_versions


@pytest.mark.parametrize("backend", BACKENDS)
async def test_server_a_cache_behind_the_pointer_is_still_evicted(backend: str) -> None:
    """A handle that never converged holds an OLDER version than the one purged. Its rows are the
    purged set's, so keeping them would leave the orphan's values in RAM, which origin/main did not."""
    model = _Model(version="v2")
    store = _server_store(backend, model, cached="v1")
    await _purge(store)
    assert model.version == "purged:v2"
    assert "orphan" not in store._reference_cache
    assert "orphan" not in store._reference_versions


async def test_postgres_delete_and_update_share_one_read_committed_transaction() -> None:
    model = _Model()
    store = _server_store("postgres", model)
    await _purge(store)
    assert model.isolation == "read_committed"
    assert model.txn_statements == ["DELETE", "UPDATE"]
    assert model.commits == 1


async def _sqlite_version(store: MessageStore) -> str:
    cur = await store._db.execute("SELECT version FROM reference_version WHERE name = 'orphan'")
    row = await cur.fetchone()
    assert row is not None
    return str(row["version"])


async def test_sqlite_an_aged_zero_row_set_is_marked_and_evicted(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        await _seed(store, "orphan", synced_at=AGED, rows={})
        assert await _purge(store) == 0
        assert await _sqlite_version(store) == "purged:v1"
        assert "orphan" not in store.reference_view()
        assert await _purge(store) == 0
        assert await _sqlite_version(store) == "purged:v1"
    finally:
        await store.close()


async def test_sqlite_the_pointer_update_carries_the_age_predicate(tmp_path: Path) -> None:
    """A predicate test, not a race: SQLite's writer lock keeps a real re-sync out of this window.
    The fresh ``synced_at`` is injected just before the UPDATE so only that statement's own
    predicate can leave the pointer unmarked and the cache in place."""
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        await _seed(store, "orphan", synced_at=AGED, rows={"K": "1"})
        real_execute = store._db.execute
        fired = False

        async def injecting_execute(sql: str, *args: Any) -> Any:
            nonlocal fired
            if not fired and sql.lstrip().startswith("UPDATE reference_version SET row_count"):
                fired = True
                await real_execute(
                    "UPDATE reference_version SET synced_at = ? WHERE name = 'orphan'", (FRESH,)
                )
            return await real_execute(sql, *args)

        store._db.execute = injecting_execute  # type: ignore[method-assign, assignment]
        try:
            await _purge(store)
        finally:
            store._db.execute = real_execute  # type: ignore[method-assign]
        assert fired, "the injection never fired"
        assert await _sqlite_version(store) == "v1"
        assert store.reference_view()["orphan"] == {"K": "1"}
    finally:
        await store.close()


async def test_sqlserver_delete_keeps_a_resync_committed_during_its_scan() -> None:
    """Mutation: drop the version match from the DELETE and the re-sync's rows are destroyed. This
    pins the statement's shape against a modelled interleaving; it does not run RCSI."""
    model = _Model()
    model.resync_during_delete = True
    store = _server_store("sqlserver", model)
    assert await _purge(store) == 0
    assert model.rows == 1
    assert model.version == "v2"


async def test_postgres_a_busy_pool_stops_the_purge_without_raising() -> None:
    """The borrow is bounded, so a timeout must not abort the retention pass and lose its audit."""
    model = _Model()
    store = _server_store("postgres", model)

    async def busy() -> None:
        raise StoreAcquireTimeout("synthetic busy pool")

    store._pool.acquire = busy
    assert await _purge(store) == 0
    assert model.version == "v1"
    assert store._reference_versions["orphan"] == "v1"
