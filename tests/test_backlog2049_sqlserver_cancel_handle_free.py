# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2049 - a cancelled SQL Server store call must not free an ODBC handle while its
statement is still running.

aioodbc runs every pyodbc call on an executor thread. Cancelling the awaiting task does not stop
that thread: the statement keeps running. Before the fix, the cancellation path then closed the
cursor and the connection on OTHER threads, so the running statement came back to freed handles.
pyodbc describes a result's columns on the statement handle as ``execute`` returns, and on a live
SQL Server that read of freed memory could kill the process natively (``SQLDescribeColW``,
``SQLColAttributeW``). The source measured it on hosted CI; nobody here re-ran it.

These arms run everywhere, with no server. The fakes, shared in ``tests/_odbc_cancel_fakes.py``,
mirror aioodbc 0.5.0 on the one point that matters: every call goes through
``Connection._execute``, which hands it to ``loop.run_in_executor``. A REAL thread pool runs the
calls, so a close really can run while the statement runs. The raw stand-ins record a use of a
freed handle instead of crashing on it.

The live twin, which cancels a statement blocked on a real SQL Server and asserts the process
survives its return, is ``test_cancelled_statement_returning_later_does_not_crash_the_process`` in
``tests/test_sqlserver_store.py``.
"""

from __future__ import annotations

import asyncio
import threading
import types
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import pytest

from messagefoundry.store.pool_metrics import AcquireWaitHistogram
from messagefoundry.store.sqlserver import SqlServerStore
from tests._odbc_cancel_fakes import (
    USE_AFTER_FREE,
    WAIT,
    AioConn,
    Pool,
    RawConn,
    wait_for_entry,
)


@dataclass
class _Rig:
    store: SqlServerStore
    pool: Pool
    log: list[str]
    release: threading.Event
    started: threading.Event


@pytest.fixture
async def rig() -> Any:
    # More than one worker, so a close submitted during the statement CAN run beside it. With one
    # worker the pool itself would serialize them and the arms below would pass vacuously.
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-2049")
    log: list[str] = []
    release = threading.Event()
    started = threading.Event()
    raw = RawConn(log, release, started)
    pool = Pool(AioConn(raw, executor))
    store = SqlServerStore.__new__(SqlServerStore)
    store._pool = pool
    store._settings = types.SimpleNamespace(  # type: ignore[assignment]
        command_timeout=0, acquire_timeout=30.0
    )
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0
    store.body_copies = 0
    try:
        yield _Rig(store, pool, log, release, started)
    finally:
        release.set()  # never leave a worker parked if an arm failed early
        executor.shutdown(wait=True)


async def _cancel_mid_statement(r: _Rig) -> asyncio.Task[Any]:
    """Start a store read, wait until its statement is running on a worker thread, cancel it."""
    task = asyncio.create_task(r.store._fetchall("SELECT 1 AS r"))
    assert await asyncio.to_thread(r.started.wait, WAIT), "the statement never started"
    task.cancel()
    return task


async def _wait_for(r: _Rig, entry: str) -> None:
    await wait_for_entry(r.log, entry)


async def test_a_cancelled_call_frees_no_handle_until_its_statement_returns(rig: _Rig) -> None:
    """THE regression gate. Before the fix the cursor and connection closed on other worker
    threads while the statement was still running, so it returned to freed handles."""
    task = await _cancel_mid_statement(rig)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, WAIT)

    # The cancellation has propagated and the statement is STILL running. Nothing may be freed yet.
    assert "execute:end" not in rig.log, rig.log
    assert "cursor.close" not in rig.log and "conn.close" not in rig.log, (
        f"a handle was freed while its statement was still running (log={rig.log})"
    )

    rig.release.set()
    await _wait_for(rig, "conn.close")

    assert USE_AFTER_FREE not in rig.log, f"the statement returned to a freed handle ({rig.log})"
    end = rig.log.index("execute:end")
    assert end < rig.log.index("cursor.close") < rig.log.index("conn.close"), rig.log
    assert rig.pool.free == [], "the quarantine regressed: the connection went back to the pool"


async def test_the_cancellation_does_not_wait_for_the_statement(rig: _Rig) -> None:
    """Keep the cancel responsive. Waiting for the statement inside the cancellation would stall a
    shutdown or a demotion for as long as the statement runs, which ADR 0159 rejected."""
    task = await _cancel_mid_statement(rig)
    with pytest.raises(asyncio.CancelledError):
        # Well under the store's own 5s close bound, so a wait on it would fail this arm.
        await asyncio.wait_for(task, 1.0)
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"


async def test_a_second_cancellation_still_frees_nothing_early(rig: _Rig) -> None:
    """Shutdown cancels, then the gather cancels again. The second one must not free anything
    early either, so the handle free cannot depend on any await in the cleanup finishing."""
    rig.pool.hold = asyncio.Event()
    task = await _cancel_mid_statement(rig)
    await asyncio.wait_for(rig.pool.in_release.wait(), WAIT)  # the cleanup is suspended
    assert task.cancel(), "the arm is vacuous: the task had finished before the second cancel"
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, WAIT)
    assert "cursor.close" not in rig.log and "conn.close" not in rig.log, rig.log

    rig.release.set()
    await _wait_for(rig, "conn.close")
    assert USE_AFTER_FREE not in rig.log, rig.log
    assert rig.pool.free == []


async def test_a_cancel_between_calls_closes_the_cursor_then_the_connection(rig: _Rig) -> None:
    """The other quarantine path: the cancellation lands while NO call is running, so the close
    starts at once instead of being handed to a call. It must still close the abandoned cursor
    first, and hold the connection out of the pool."""
    rig.release.set()
    parked = asyncio.Event()

    async def _park(conn: object) -> None:
        parked.set()
        await asyncio.Event().wait()  # suspended on the loop, with no pyodbc call in flight

    rig.store._commit_read = _park  # type: ignore[method-assign]
    task = asyncio.create_task(rig.store._fetchall("SELECT 1 AS r"))
    await asyncio.wait_for(parked.wait(), WAIT)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, WAIT)

    await _wait_for(rig, "conn.close")
    assert USE_AFTER_FREE not in rig.log, rig.log
    end = rig.log.index("execute:end")
    assert end < rig.log.index("cursor.close") < rig.log.index("conn.close"), rig.log
    assert rig.pool.free == []


async def test_an_ordinary_read_still_closes_its_cursor_and_recycles(rig: _Rig) -> None:
    """The control. With no cancellation the cursor still closes before release (EF-6) and the
    connection goes back to the pool, so the arms above cannot pass by discarding everything."""
    rig.release.set()
    assert await rig.store._fetchall("SELECT 1 AS r") == []
    assert rig.log.index("execute:end") < rig.log.index("cursor.close"), rig.log
    assert "conn.close" not in rig.log
    assert rig.pool.free == [rig.pool._conn]
