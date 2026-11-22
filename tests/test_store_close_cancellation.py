# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A cancelled store close still closes everything, then re-raises (BACKLOG #5668).

The SQLite cases run a real store, because the defect is a real one there: aiosqlite's worker
threads are non-daemon, so a connection the close skipped would hang interpreter exit. The script
at the bottom of this file is the subprocess half of that check. SQL Server and Postgres use fakes:
only the hosted legs can prove the behaviour of a real pool.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore

_POINTS = ("settle", "group_commit", "read_pool")

#: Past this the child is hung. Well above a clean exit, which takes about a second.
_EXIT_BOUND_SECONDS = 25.0


def _inject(store: MessageStore, point: str) -> asyncio.Event:
    """Park the close at ``point`` until cancelled, and return the event set on arrival there."""
    entered = asyncio.Event()

    async def park() -> None:
        entered.set()
        await asyncio.Event().wait()

    if point == "settle":

        async def settle(*_: object, **__: object) -> None:
            await park()

        store.checkpoint_cipher_invocations = settle  # type: ignore[method-assign]
    elif point == "group_commit":
        committer: Any = store._group_commit
        real_aclose = committer.aclose

        async def aclose() -> None:
            try:
                await park()
            finally:
                await real_aclose()

        committer.aclose = aclose
    else:
        conn: Any = store._read_conns[0]
        real_close = conn.close

        async def close() -> None:
            try:
                await park()
            finally:
                await real_close()

        conn.close = close
    return entered


def _workers(store: MessageStore) -> list[Any]:
    return [conn._thread for conn in (*store._read_conns, store._db)]


async def _cancel_close(store: MessageStore, point: str) -> None:
    entered = _inject(store, point)
    task = asyncio.ensure_future(store.close())
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.parametrize("point", _POINTS)
async def test_a_cancelled_close_stops_every_worker_and_re_raises(
    tmp_path: Path, point: str
) -> None:
    """Red without the fix: the workers of every connection after the injection point stay alive."""
    store = await MessageStore.open(tmp_path / "close.db", group_commit_window_ms=1.0)
    workers = _workers(store)
    assert len(workers) > 1
    await _cancel_close(store, point)
    assert [w.name for w in workers if w.is_alive()] == []


@pytest.mark.parametrize("point", _POINTS)
def test_the_interpreter_exits_after_a_cancelled_close(tmp_path: Path, point: str) -> None:
    """Red without the fix: the child hangs on the non-daemon workers and hits the bound."""
    done = subprocess.run(
        [sys.executable, __file__, point, str(tmp_path / "exit.db")],
        capture_output=True,
        text=True,
        timeout=_EXIT_BOUND_SECONDS,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.strip() == "cancelled"


async def test_a_second_cancellation_does_not_strand_a_connection(tmp_path: Path) -> None:
    """A cancel that lands on the recovery itself still leaves no worker behind."""
    store = await MessageStore.open(tmp_path / "twice.db")
    workers = _workers(store)
    entered = _inject(store, "settle")
    task = asyncio.ensure_future(store.close())
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert [w.name for w in workers if w.is_alive()] == []


async def test_a_step_wedged_after_the_cancel_is_cut_at_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cancelled close must still return, and still stop the workers after the wedged step."""
    monkeypatch.setattr("messagefoundry.store.close_steps.CANCELLED_CLOSE_GRACE_SECONDS", 0.2)
    store = await MessageStore.open(tmp_path / "wedged.db", group_commit_window_ms=1.0)
    workers = _workers(store)
    entered = _inject(store, "settle")
    committer: Any = store._group_commit
    real_aclose = committer.aclose

    async def wedged() -> None:
        try:
            await asyncio.Event().wait()
        finally:
            await real_aclose()

    committer.aclose = wedged
    task = asyncio.ensure_future(store.close())
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(asyncio.shield(task), 5)
    assert task.cancelled()
    assert [w.name for w in workers if w.is_alive()] == []


async def test_a_step_failure_after_a_cancel_is_logged_and_the_cancel_wins(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store: Any = object.__new__(PostgresStore)

    class _FailingPool:
        async def close(self) -> None:
            raise OSError("synthetic detail")

    store._read_only = False
    store._pool = _FailingPool()
    with caplog.at_level("WARNING", logger="messagefoundry.store.close_steps"):
        await _cancel_at(store._close_handles, _parking_settle(store))
    assert "failed after a cancellation (OSError)" in caplog.text
    assert "synthetic detail" not in caplog.text


async def test_a_clean_close_does_not_raise(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "clean.db", group_commit_window_ms=1.0)
    workers = _workers(store)
    await store.close()
    assert [w.name for w in workers if w.is_alive()] == []


# --- fakes: SQL Server and Postgres ---------------------------------------------------------------


class _FakePool:
    def __init__(self, park_on_wait: bool = False) -> None:
        self.closed = 0
        self.waited = 0
        self._park = park_on_wait
        self.entered = asyncio.Event()

    def close(self) -> None:
        self.closed += 1

    async def wait_closed(self) -> None:
        self.waited += 1
        if self._park:
            self.entered.set()
            await asyncio.Event().wait()


class _FakeAsyncPool:
    def __init__(self) -> None:
        self.closed = 0

    async def close(self) -> None:
        self.closed += 1


class _FakeExecutor:
    def __init__(self) -> None:
        self.shutdowns = 0

    def shutdown(self, wait: bool = True) -> None:
        self.shutdowns += 1


def _parking_settle(store: Any) -> asyncio.Event:
    entered = asyncio.Event()

    async def settle(*_: object, **__: object) -> None:
        entered.set()
        await asyncio.Event().wait()

    store.checkpoint_cipher_invocations = settle
    return entered


def _sqlserver(pool: _FakePool, executor: _FakeExecutor) -> tuple[Any, list[str]]:
    store: Any = object.__new__(SqlServerStore)
    calls: list[str] = []

    async def holders() -> None:
        calls.append("holders")

    store._read_only = False
    store._pool = pool
    store._pool_executor = executor
    store.close_sync_handoff_pool = lambda: calls.append("sync")
    store._close_claim_holders = holders
    return store, calls


async def _cancel_at(close: Callable[[], Awaitable[None]], entered: asyncio.Event) -> None:
    task = asyncio.ensure_future(close())
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_sqlserver_cancelled_settlement_still_closes_everything() -> None:
    pool, executor = _FakePool(), _FakeExecutor()
    store, calls = _sqlserver(pool, executor)
    await _cancel_at(store._close_handles, _parking_settle(store))
    assert calls == ["sync", "holders"]
    assert (pool.closed, pool.waited, executor.shutdowns) == (1, 1, 1)
    assert store._pool_executor is None


async def test_sqlserver_cancelled_claim_holder_close_still_closes_the_pool() -> None:
    pool, executor = _FakePool(), _FakeExecutor()
    store, calls = _sqlserver(pool, executor)
    entered = asyncio.Event()

    async def holders() -> None:
        calls.append("holders")
        entered.set()
        await asyncio.Event().wait()

    async def settle(*_: object, **__: object) -> None:
        return None

    store._close_claim_holders = holders
    store.checkpoint_cipher_invocations = settle
    await _cancel_at(store._close_handles, entered)
    assert (pool.closed, pool.waited, executor.shutdowns) == (1, 1, 1)


async def test_sqlserver_cancelled_pool_wait_still_releases_the_executor() -> None:
    pool, executor = _FakePool(park_on_wait=True), _FakeExecutor()
    store, _calls = _sqlserver(pool, executor)

    async def settle(*_: object, **__: object) -> None:
        return None

    store.checkpoint_cipher_invocations = settle
    await _cancel_at(store._close_handles, pool.entered)
    assert executor.shutdowns == 1


async def test_sqlserver_sync_pool_failure_leaves_before_the_unbounded_pool_wait() -> None:
    """As before this change: _one_connection_store's fallback bounds the wait on this path."""
    pool, executor = _FakePool(), _FakeExecutor()
    store, calls = _sqlserver(pool, executor)

    async def settle(*_: object, **__: object) -> None:
        return None

    def broken() -> None:
        raise OSError("synthetic")

    store.checkpoint_cipher_invocations = settle
    store.close_sync_handoff_pool = broken
    with pytest.raises(OSError, match="synthetic"):
        await store._close_handles()
    assert calls == []
    assert (pool.closed, pool.waited, executor.shutdowns) == (0, 0, 0)


async def test_postgres_cancelled_settlement_still_closes_the_pool() -> None:
    store: Any = object.__new__(PostgresStore)
    pool = _FakeAsyncPool()
    store._read_only = False
    store._pool = pool
    await _cancel_at(store._close_handles, _parking_settle(store))
    assert pool.closed == 1


async def _script(point: str, path: str) -> None:
    store = await MessageStore.open(path, group_commit_window_ms=1.0)
    entered = _inject(store, point)
    task = asyncio.ensure_future(store.close())
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        print("cancelled")


if __name__ == "__main__":
    asyncio.run(_script(sys.argv[1], sys.argv[2]))
