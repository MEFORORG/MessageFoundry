# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5720: a cancel landing in a store close's AES-GCM settle skipped every close step after
it, on all three backends, so the pool (PostgreSQL), the pool and its executor (SQL Server) or the
connections' non-daemon worker threads (SQLite) were left open.

The settle is a database write on a keyed store, so a cancel can land there; each test stands a
settle that blocks in for it. No real PostgreSQL or SQL Server is involved. Synthetic data only.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore


async def _cancel_close_in_its_settle(store: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run ``store.close()`` with a settle that blocks, cancel it there, and expect the cancel."""
    settling = asyncio.Event()

    async def blocked_settle(**_kwargs: object) -> int | None:
        settling.set()
        await asyncio.sleep(30)
        return None

    monkeypatch.setattr(store, "checkpoint_cipher_invocations", blocked_settle)
    task = asyncio.create_task(store.close())
    await asyncio.wait_for(settling.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


class _PgPool:
    def __init__(self) -> None:
        self.terminated = 0

    async def close(self) -> None:
        raise AssertionError("the pool's graceful close is not reached after the cancel")

    def terminate(self) -> None:
        self.terminated += 1


async def test_postgres_close_cancelled_in_its_settle_terminates_the_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red before the fix: the pool is never terminated."""
    pool = _PgPool()
    settings = StoreSettings(
        backend=StoreBackend.POSTGRES, server="localhost", database="mefor_test", username="mefor"
    )
    store = PostgresStore(pool, settings)
    await _cancel_close_in_its_settle(store, monkeypatch)
    assert pool.terminated == 1


class _OdbcPool:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1

    async def wait_closed(self) -> None:
        raise AssertionError("the pool's wait is not reached after the cancel")


class _Executor:
    def __init__(self) -> None:
        self.shutdown_calls: list[bool] = []

    def shutdown(self, wait: bool = True) -> None:
        self.shutdown_calls.append(wait)


async def test_sqlserver_close_cancelled_in_its_settle_releases_pool_and_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red before the fix: neither the pool nor the executor is released."""
    pool = _OdbcPool()
    executor = _Executor()
    settings = StoreSettings(
        backend=StoreBackend.SQLSERVER, server="localhost", database="mefor_test", username="sa"
    )
    store = SqlServerStore(pool, settings)
    store._pool_executor = executor  # type: ignore[assignment]
    await _cancel_close_in_its_settle(store, monkeypatch)
    assert pool.closed == 1
    assert executor.shutdown_calls == [False]
    assert store._pool_executor is None


async def test_sqlite_close_cancelled_in_its_settle_stops_the_writer_thread(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Red before the fix: the writer's non-daemon worker thread is still running."""
    store = await MessageStore.open(tmp_path / "store.db")
    thread = getattr(store._db, "_thread", None)
    assert isinstance(thread, threading.Thread)
    try:
        await _cancel_close_in_its_settle(store, monkeypatch)
        for _ in range(200):
            if not thread.is_alive():
                break
            await asyncio.sleep(0.01)
        assert not thread.is_alive()
    finally:
        if thread.is_alive():
            store._db.stop()
