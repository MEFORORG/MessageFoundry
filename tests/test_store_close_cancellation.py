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
import shutil
import sqlite3
import subprocess
import sys
import threading
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from messagefoundry.store.close_steps import CloseSteps
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


async def test_a_statement_running_on_a_reader_does_not_outlive_a_cancelled_close(
    tmp_path: Path,
) -> None:
    """The held-cancel path interrupts it. Without that the stop queues behind the statement."""
    store = await MessageStore.open(tmp_path / "busy.db")
    workers = _workers(store)
    entered = _inject(store, "settle")
    reader: Any = store._read_conns[0]
    endless = asyncio.ensure_future(
        reader.execute(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT MAX(x) FROM c"
        )
    )
    await asyncio.sleep(0.05)
    task = asyncio.ensure_future(store.close())
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.gather(endless, return_exceptions=True)
    assert [w.name for w in workers if w.is_alive()] == []


async def test_a_closed_coroutine_does_not_await_while_unwinding(tmp_path: Path) -> None:
    """GeneratorExit leaves ``_close_connection`` cleanly when the suspended close does not await
    while unwinding, as this fake does not. A real aiosqlite close does await in its ``finally``,
    which raises RuntimeError; ``_close_connection``'s docstring covers that case."""
    store = await MessageStore.open(tmp_path / "gen.db")
    conn: Any = store._read_conns[0]
    real_close = conn.close
    parked = asyncio.Event()

    async def close() -> None:
        parked.set()
        await asyncio.Event().wait()

    conn.close = close
    steps = CloseSteps()
    coro = MessageStore._close_connection(conn, steps)
    runner = asyncio.ensure_future(_drive_until_parked(coro, parked))
    await runner
    coro.close()  # must not raise
    conn.close = real_close
    await store.close()


async def _drive_until_parked(coro: Any, parked: asyncio.Event) -> None:
    future = coro.send(None)
    assert parked.is_set()
    assert future is not None
    future.cancel = lambda *_: False  # the coroutine stays suspended; nothing resumes it


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


# --- a repeat close after a forced stop -----------------------------------------------------------

#: Far above a repeat close that does nothing, and far below the 5 second worker wait, so a repeat
#: that waits on the wedged worker again fails here instead of passing slowly.
_REPEAT_CLOSE_BOUND_SECONDS = 1.0


def _wedge(conn: Any) -> threading.Event:
    """Hold ``conn``'s worker in a call ``interrupt()`` cannot abort, until the event is set."""
    release = threading.Event()
    conn._tx.put_nowait((None, release.wait))
    return release


async def _unwedge(release: threading.Event, worker: Any) -> None:
    release.set()
    await asyncio.to_thread(worker.join, 5)
    assert not worker.is_alive()


async def test_a_repeat_close_after_a_forced_stop_hit_its_bound_returns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red without the fix: the repeat parks in aiosqlite's close on the wedged worker."""
    monkeypatch.setattr("messagefoundry.store.close_steps.CANCELLED_CLOSE_GRACE_SECONDS", 0.1)
    store = await MessageStore.open(tmp_path / "repeat.db")
    worker: Any = store._db._thread
    release = _wedge(store._db)
    try:
        await _cancel_close(store, "settle")
        assert worker.is_alive()  # the forced stop did hit its bound
        store.checkpoint_cipher_invocations = settle = AsyncMock()  # type: ignore[method-assign]
        store._db.stop = stop = Mock(wraps=store._db.stop)  # type: ignore[method-assign]
        await asyncio.wait_for(store.close(), _REPEAT_CLOSE_BOUND_SECONDS)
        settle.assert_not_awaited()  # no second teardown
        stop.assert_not_called()
    finally:
        await _unwedge(release, worker)


async def test_a_repeat_close_after_a_cancel_inside_the_writer_close_returns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stop here is aiosqlite's own, so the bound being hit is what marks the connection."""
    monkeypatch.setattr("messagefoundry.store.close_steps.CANCELLED_CLOSE_GRACE_SECONDS", 0.1)
    store = await MessageStore.open(tmp_path / "inside.db")
    writer: Any = store._db
    worker = writer._thread
    release = _wedge(writer)
    try:
        task = asyncio.ensure_future(store.close())
        await asyncio.sleep(0.1)  # past the read pool, onto the writer's queued close
        task.cancel()  # aiosqlite then parks on its own stop
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(task), 5)
        assert worker.is_alive()
        await asyncio.wait_for(store.close(), _REPEAT_CLOSE_BOUND_SECONDS)
    finally:
        await _unwedge(release, worker)


async def test_a_failed_open_cleanup_does_not_park_on_a_force_stopped_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red without the fix: past the open's bound the abandoned cleanup reaches _close_writer on
    the stopped writer and parks, so a loop shutdown cancelling every task would hang on it."""
    monkeypatch.setattr("messagefoundry.store.store.FAILED_OPEN_CANCEL_BOUND_S", 0.1)
    monkeypatch.setattr("messagefoundry.store.close_steps.CANCELLED_CLOSE_GRACE_SECONDS", 0.1)
    entered = asyncio.Event()
    wedged: list[tuple[threading.Event, Any]] = []

    async def parking(_self: Any, *_: object, settle: bool = False, **__: object) -> None:
        if settle:
            entered.set()
            await asyncio.Event().wait()

    async def fail(self: Any) -> None:
        wedged.append((_wedge(self._db), self._db._thread))
        raise RuntimeError("synthetic open failure")

    monkeypatch.setattr(MessageStore, "checkpoint_cipher_invocations", parking)
    monkeypatch.setattr(MessageStore, "_load_state_cache", fail)
    before = asyncio.all_tasks()
    opening = asyncio.ensure_future(MessageStore.open(tmp_path / "failed.db"))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        opening.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(opening), 5)
        left = asyncio.all_tasks() - before - {asyncio.current_task()}
        assert left  # the cleanup the open stopped waiting for
        for task in left:  # as a loop shutdown does
            task.cancel()
        _, pending = await asyncio.wait(left, timeout=_REPEAT_CLOSE_BOUND_SECONDS * 3)
        assert not pending
    finally:
        for release, worker in wedged:
            await _unwedge(release, worker)


async def test_a_plain_double_close_still_runs_the_close_twice(tmp_path: Path) -> None:
    """The control: with no forced stop the repeat is not short-circuited."""
    store = await MessageStore.open(tmp_path / "double.db")
    workers = _workers(store)
    store.checkpoint_cipher_invocations = settle = AsyncMock()  # type: ignore[method-assign]
    await store.close()
    await asyncio.wait_for(store.close(), _REPEAT_CLOSE_BOUND_SECONDS)
    assert settle.await_count == 2
    assert [w.name for w in workers if w.is_alive()] == []


# --- a cancel must not cost the last-close checkpoint ---------------------------------------------


_SYNTH_ROWS = 2000


async def _committed_rows(store: MessageStore) -> None:
    await store._db.execute("CREATE TABLE synth_close (v TEXT)")
    await store._db.executemany(
        "INSERT INTO synth_close VALUES (?)", [("synthetic" * 10,) for _ in range(_SYNTH_ROWS)]
    )
    await store._db.commit()


def _rows_in_a_copy_of_only_the_db(db: Path, into: Path) -> int:
    into.mkdir()
    copy = into / db.name
    shutil.copy2(db, copy)
    conn = sqlite3.connect(copy)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM synth_close").fetchone()[0])
    finally:
        conn.close()


async def test_a_cancelled_close_of_an_idle_writer_still_checkpoints(tmp_path: Path) -> None:
    """Red when the idle writer is interrupted: its last-close checkpoint aborts, leaving a -wal."""
    db = tmp_path / "idle.db"
    store = await MessageStore.open(db)
    await _committed_rows(store)
    assert Path(f"{db}-wal").stat().st_size > 0  # the control: the rows are in the WAL
    await _cancel_close(store, "settle")
    assert not Path(f"{db}-wal").exists()
    assert _rows_in_a_copy_of_only_the_db(db, tmp_path / "copy") == _SYNTH_ROWS


async def test_a_statement_running_on_the_writer_does_not_outlive_a_cancelled_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The writer is interrupted only once its stop has had the bound, and then it still is. The
    interrupt's flag must not carry into the close, or the last-close checkpoint aborts."""
    monkeypatch.setattr("messagefoundry.store.close_steps.CANCELLED_CLOSE_GRACE_SECONDS", 0.1)
    db = tmp_path / "busywriter.db"
    store = await MessageStore.open(db)
    await _committed_rows(store)
    workers = _workers(store)
    raw = store._db._connection
    assert raw is not None
    entered = _inject(store, "settle")
    endless = asyncio.ensure_future(
        store._db.execute(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT MAX(x) FROM c"
        )
    )
    await asyncio.sleep(0.05)
    task = asyncio.ensure_future(store.close())
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    try:
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(task), 10)
        await asyncio.gather(endless, return_exceptions=True)
        assert [w.name for w in workers if w.is_alive()] == []
    finally:
        if workers[-1].is_alive():  # a failure above must not leave the statement running
            raw.interrupt()
    assert not Path(f"{db}-wal").exists()
    assert _rows_in_a_copy_of_only_the_db(db, tmp_path / "copy") == _SYNTH_ROWS


# --- a cancel of the close, told from a cancelled future ------------------------------------------


def _settle_on_a_future_someone_else_cancels(store: MessageStore) -> None:
    async def settle(*_: object, **__: object) -> None:
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        asyncio.get_running_loop().call_soon(future.cancel)
        await future

    store.checkpoint_cipher_invocations = settle  # type: ignore[method-assign]


async def test_a_close_nobody_cancelled_does_not_raise_a_foreign_cancel(tmp_path: Path) -> None:
    """Red when any CancelledError counts as a cancel of the close."""
    store = await MessageStore.open(tmp_path / "foreign.db")
    workers = _workers(store)
    _settle_on_a_future_someone_else_cancels(store)
    await store.close()
    assert [w.name for w in workers if w.is_alive()] == []


async def test_a_foreign_cancel_inside_a_connection_close_does_not_raise(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "foreignconn.db")
    workers = _workers(store)
    conn: Any = store._read_conns[0]
    real_close = conn.close

    async def close() -> None:
        await real_close()
        raise asyncio.CancelledError

    conn.close = close
    await store.close()
    assert [w.name for w in workers if w.is_alive()] == []


async def _close_inside_a_swallowed_cancel(store: MessageStore) -> asyncio.Future[None]:
    async def closer() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await store.close()

    task = asyncio.ensure_future(closer())
    await asyncio.sleep(0)
    task.cancel()
    return task


async def test_a_foreign_cancel_after_a_swallowed_cancel_does_not_raise(tmp_path: Path) -> None:
    """The baseline: a cancel this task caught before the close is not a cancel of the close."""
    store = await MessageStore.open(tmp_path / "baseline.db")
    _settle_on_a_future_someone_else_cancels(store)
    await asyncio.wait_for(await _close_inside_a_swallowed_cancel(store), 5)


async def test_a_real_cancel_after_a_swallowed_cancel_still_raises(tmp_path: Path) -> None:
    """The control for the baseline: a NEW cancel of the same task still reaches the caller."""
    store = await MessageStore.open(tmp_path / "second.db")
    workers = _workers(store)
    entered = _inject(store, "settle")
    task = await _close_inside_a_swallowed_cancel(store)
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert [w.name for w in workers if w.is_alive()] == []


async def test_a_cancel_the_task_requested_of_itself_before_the_close_still_raises(
    tmp_path: Path,
) -> None:
    """Counted before the close starts but delivered inside it, so a bare baseline would lose it."""
    store = await MessageStore.open(tmp_path / "selfcancel.db")
    workers = _workers(store)

    async def closer() -> None:
        current = asyncio.current_task()
        assert current is not None
        current.cancel()
        await store.close()

    task = asyncio.ensure_future(closer())
    with pytest.raises(asyncio.CancelledError):
        await task
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


async def test_sqlserver_repeat_close_does_not_wait_again_on_a_pool_wait_the_bound_cut() -> None:
    """Red without the guard: the repeat awaits ``wait_closed()`` with nothing bounding it."""
    pool, executor = _FakePool(park_on_wait=True), _FakeExecutor()
    store, calls = _sqlserver(pool, executor)
    store.checkpoint_cipher_invocations = AsyncMock()
    await _cancel_at(store._close_handles, pool.entered)
    assert pool.waited == 1
    await asyncio.wait_for(store._close_handles(), _REPEAT_CLOSE_BOUND_SECONDS)
    assert pool.waited == 1
    assert calls == ["sync", "holders"]  # no second teardown


async def test_sqlserver_plain_double_close_still_waits_twice() -> None:
    """The control: a pool wait that completed is not short-circuited."""
    pool, executor = _FakePool(), _FakeExecutor()
    store, _calls = _sqlserver(pool, executor)
    store.checkpoint_cipher_invocations = AsyncMock()
    await store._close_handles()
    await store._close_handles()
    assert pool.waited == 2


async def test_sqlserver_sync_pool_failure_leaves_before_the_unbounded_pool_wait() -> None:
    """As before this change, the failure leaves before the pool step and nothing here bounds a
    later wait. On an ``open()``-built store no fallback closes the pool after it."""
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


async def test_sqlserver_blocking_sync_pool_close_does_not_stall_a_cancelled_close() -> None:
    """A pyodbc close on a dead server blocks; on the loop it would stop the bound from firing."""
    pool, executor = _FakePool(), _FakeExecutor()
    store, _calls = _sqlserver(pool, executor)
    ticks = 0
    during: list[int] = []
    closed_on: list[threading.Thread] = []

    async def heartbeat() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.005)

    def blocking_close() -> None:
        closed_on.append(threading.current_thread())
        before = ticks
        threading.Event().wait(0.3)
        during.append(ticks - before)

    store.close_sync_handoff_pool = blocking_close
    beat = asyncio.ensure_future(heartbeat())
    try:
        await _cancel_at(store._close_handles, _parking_settle(store))
    finally:
        beat.cancel()
    assert closed_on and closed_on[0] is not threading.current_thread()
    assert during and during[0] > 0
    assert (pool.closed, pool.waited, executor.shutdowns) == (1, 1, 1)


async def test_sqlserver_sync_pool_close_wedged_past_the_bound_does_not_hold_the_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("messagefoundry.store.close_steps.CANCELLED_CLOSE_GRACE_SECONDS", 0.05)
    pool, executor = _FakePool(), _FakeExecutor()
    store, _calls = _sqlserver(pool, executor)
    release = threading.Event()
    store.close_sync_handoff_pool = lambda: release.wait(5)
    loop = asyncio.get_running_loop()
    started = loop.time()
    try:
        await _cancel_at(store._close_handles, _parking_settle(store))
        elapsed = loop.time() - started
    finally:
        release.set()
    # On the loop the close would run the fake's whole 5 s, because the bound could not fire.
    assert elapsed < 3
    assert (pool.closed, pool.waited, executor.shutdowns) == (1, 1, 1)


async def test_sqlserver_uncancelled_close_keeps_the_sync_pool_close_on_the_loop() -> None:
    pool, executor = _FakePool(), _FakeExecutor()
    store, _calls = _sqlserver(pool, executor)
    closed_on: list[threading.Thread] = []

    async def settle(*_: object, **__: object) -> None:
        return None

    store.checkpoint_cipher_invocations = settle
    store.close_sync_handoff_pool = lambda: closed_on.append(threading.current_thread())
    await store._close_handles()
    assert closed_on == [threading.current_thread()]


async def test_a_cancelled_close_names_itself_in_its_forced_release_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    future: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    class _Raw:
        def interrupt(self) -> None:
            raise OSError("synthetic at C:/secret/path")

    class _Conn:
        _connection = _Raw()
        _thread = None

        def stop(self) -> asyncio.Future[None]:
            return future

    steps = CloseSteps()
    steps.hold(asyncio.CancelledError())
    await MessageStore._close_connection(_Conn(), steps)  # type: ignore[arg-type]
    future.set_exception(OSError("worker gone at C:/secret/path"))
    await asyncio.sleep(0)
    assert "forcing the release after a cancelled store close also failed (OSError)" in caplog.text
    assert "stopping a connection after a cancelled store close failed (OSError)" in caplog.text
    assert "failed store open" not in caplog.text
    assert "secret" not in caplog.text


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
