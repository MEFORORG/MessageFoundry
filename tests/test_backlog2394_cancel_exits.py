# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2394, the last slice: the cancel exits engine PR 2692 left open.

* **A cancelled call that has not entered the gate never runs.** A cancellation that landed after
  aioodbc handed a call to its executor, but before that call took the gate's lock, left a call
  the gate did not know about. A cleanup's close then raced it for the lock, and the call could
  run after the close, or on a connection already lent again.
* **A cancel during cursor creation.** The cursor a cancelled ``cursor()`` call made reached
  nobody and was left for the collector, possibly after its connection closed. The DATABASE twin,
  whose borrow also went back to its pool while that call ran, is in
  ``tests/test_backlog2394_database_gate.py``.
* **The SQL Server store's claim-holder exits.** A cancelled open awaited ``conn.close()``, which
  waits for the ``cursor()`` call it cancelled, and the cursor that call made was never closed.
  A cancelled claim's discard closed the holder through a shielded close it waited on, so the
  cancellation waited for the claim statement, and a second cancellation still awaited the close
  it had cut short (BACKLOG #2395 step 3).

Each arm drives a real call site against the shared fakes (``tests/_odbc_cancel_fakes.py``): a
real thread pool, and raw stand-ins that record a use of a freed handle instead of crashing on it.
Synthetic data only; no driver, no database.
"""

from __future__ import annotations

import asyncio
import gc
import threading
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import pytest

from messagefoundry.odbc_call_gate import install_call_gate
from messagefoundry.store.sqlserver import SqlServerStore
from tests._odbc_cancel_fakes import (
    DEL_CLOSE,
    USE_AFTER_FREE,
    WAIT,
    AioConn,
    Pool,
    RawConn,
    always,
    bare_store,
    cancel_once_started,
    cancelled_at_once,
    never,
    wait_for_entry,
    wait_until,
)

_CLAIM = "SELECT 1 AS claim"


@dataclass
class _Rig:
    executor: ThreadPoolExecutor
    log: list[str] = field(default_factory=list)
    release: threading.Event = field(default_factory=threading.Event)
    started: threading.Event = field(default_factory=threading.Event)

    def conn(self, **kw: Any) -> AioConn:
        return AioConn(RawConn(self.log, self.release, self.started, **kw), self.executor)


@pytest.fixture
async def rig() -> AsyncIterator[_Rig]:
    # More than one worker, so a close submitted during a call CAN run beside it.
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-2394c")
    r = _Rig(executor)
    try:
        yield r
    finally:
        r.release.set()  # never leave a worker parked if an arm failed early
        executor.shutdown(wait=True)


# --- the gate ------------------------------------------------------------------------------------


async def _waiting_on_the_gate(rig: _Rig) -> None:
    """Wait until a worker has taken the call just submitted, so it waits on the gate's lock behind
    the running statement. While it is still queued, the executor skips it on a cancel by itself,
    and an arm built on that window would pass without the gate."""
    assert await wait_until(rig.executor._work_queue.empty), "no worker took the call"
    await asyncio.sleep(0.05)  # the worker's few bytecodes between the queue and the lock


async def test_a_call_cancelled_before_it_entered_the_gate_never_runs(rig: _Rig) -> None:
    """A commit whose task was cancelled while it waited for the gate, behind a running
    statement. Red before this slice: the commit ran once the statement returned, on a connection
    its cancelled owner had already given up."""
    conn = rig.conn(blocks=always)
    install_call_gate(conn)
    cur = await conn.cursor()
    statement = asyncio.ensure_future(cur.execute(_CLAIM))
    assert await asyncio.to_thread(rig.started.wait, WAIT), "the statement never started"

    commit = asyncio.ensure_future(conn.commit())
    await _waiting_on_the_gate(rig)
    commit.cancel()
    await cancelled_at_once(commit)

    rig.release.set()
    await asyncio.wait_for(statement, WAIT)
    await asyncio.wait_for(cur.close(), WAIT)  # a later call: the gate is free again
    assert "cursor.close" in rig.log
    assert "commit" not in rig.log, rig.log
    assert USE_AFTER_FREE not in rig.log, rig.log


async def test_a_close_cancelled_before_it_entered_the_gate_still_runs_inside_it(rig: _Rig) -> None:
    """The one call the skip leaves alone. Skipped, a cancelled close would leave its handle for
    aioodbc's ``__del__`` or the collector, outside the gate; it runs once the statement returns."""
    conn = rig.conn(blocks=always)
    install_call_gate(conn)
    cur = await conn.cursor()
    statement = asyncio.ensure_future(cur.execute(_CLAIM))
    assert await asyncio.to_thread(rig.started.wait, WAIT), "the statement never started"

    closing = asyncio.ensure_future(conn.close())
    await _waiting_on_the_gate(rig)
    closing.cancel()
    await cancelled_at_once(closing)
    assert "conn.close" not in rig.log, "the arm is vacuous: the close ran beside the statement"

    rig.release.set()
    await asyncio.wait_for(statement, WAIT)
    await wait_for_entry(rig.log, "conn.close")
    assert rig.log.index("execute:end") < rig.log.index("conn.close"), rig.log
    assert USE_AFTER_FREE not in rig.log, rig.log


async def test_an_uncancelled_call_waiting_on_the_gate_still_runs(rig: _Rig) -> None:
    """The control: a call that waits behind a running one, and is not cancelled, runs after it."""
    conn = rig.conn(blocks=always)
    install_call_gate(conn)
    cur = await conn.cursor()
    statement = asyncio.ensure_future(cur.execute(_CLAIM))
    assert await asyncio.to_thread(rig.started.wait, WAIT), "the statement never started"
    commit = asyncio.ensure_future(conn.commit())
    await _waiting_on_the_gate(rig)

    rig.release.set()
    await asyncio.wait_for(asyncio.gather(statement, commit), WAIT)
    assert rig.log.index("execute:end") < rig.log.index("commit"), rig.log


# --- the SQL Server store's claim holder ---------------------------------------------------------


def _holder_store(rig: _Rig, conns: list[AioConn], **raw_kw: Any) -> SqlServerStore:
    """A store with only what the claim holder reads, whose dedicated connections are ``rig``'s."""
    store = bare_store(Pool(rig.conn()))
    store._claim_holders = {}
    store._claim_holders_closed = False
    store._claim_holders_open = 0
    store._claim_holders_opened_total = 0
    store._claim_holders_discarded_total = 0

    async def connect() -> AioConn:
        conn = rig.conn(**raw_kw)
        conns.append(conn)
        return conn

    store._connect_claim_conn = connect  # type: ignore[method-assign]
    return store


async def _closes_cursor_then_connection_once(rig: _Rig, conns: list[AioConn]) -> None:
    """Let the driver call return, then require the cursor and then the connection to close, each
    once, through the gate, with nothing left for aioodbc's ``__del__`` to close."""
    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")
    conns.clear()
    gc.collect()
    log = rig.log
    assert USE_AFTER_FREE not in log and DEL_CLOSE not in log, log
    assert log.count("cursor.close") == 1 and log.count("conn.close") == 1, log
    assert log.index("cursor.close") < log.index("conn.close"), log


async def test_a_claim_holder_open_cancelled_in_cursor_creation_does_not_wait(rig: _Rig) -> None:
    """Red before this slice: the open's except arm awaited ``conn.close()``, which the gate holds
    behind the ``cursor()`` call the cancellation cut short, so the cancellation waited for it; and
    the cursor that call made was never closed. Now the cancellation propagates at once, and the
    cursor, then the connection, close through the gate as that call returns."""
    conns: list[AioConn] = []
    store = _holder_store(rig, conns, blocks=never, block_cursor=True)
    task = await cancel_once_started(rig.started, store._open_claim_holder("ingress"))
    await cancelled_at_once(task)
    assert not {"cursor:end", "cursor.close", "conn.close"} & set(rig.log), rig.log

    del task
    await _closes_cursor_then_connection_once(rig, conns)
    assert rig.log.index("cursor:end") < rig.log.index("cursor.close"), rig.log
    assert store._claim_holders_open == 0 and store._claim_holders_opened_total == 0


async def test_a_claim_cancelled_mid_statement_discards_its_holder_without_waiting(
    rig: _Rig,
) -> None:
    """Red before this slice: the discard awaited a shielded close of the cursor, which the gate
    holds behind the claim statement, so the cancellation waited for that statement. Now the
    holder goes to the gate with no await, and closes once the statement has returned."""
    conns: list[AioConn] = []
    store = _holder_store(rig, conns, blocks=lambda sql: sql == _CLAIM)

    async def claim() -> None:
        async with store._claim_holder_ctx("ingress") as holder:
            await holder.cur.execute(_CLAIM)

    task = await cancel_once_started(rig.started, claim())
    await cancelled_at_once(task)
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"
    assert not {"cursor.close", "conn.close"} & set(rig.log), rig.log
    assert store._claim_holders.get("ingress", []) == []
    assert store._claim_holders_discarded_total == 1 and store._claim_holders_open == 0

    del task
    await _closes_cursor_then_connection_once(rig, conns)
    assert rig.log.index("execute:end") < rig.log.index("cursor.close"), rig.log


async def test_a_second_cancel_during_a_holder_discard_does_not_wait_for_the_close(
    rig: _Rig,
) -> None:
    """BACKLOG #2395 step 3. A claim failed with an ordinary error, so its discard closes the
    holder and waits for that close; the close is slow. Red before this slice: a cancellation
    landing there still awaited the close it had cut short. Now it propagates at once, and the
    close goes on: the cursor, then the connection, each once."""
    conns: list[AioConn] = []
    store = _holder_store(rig, conns, blocks=never, block_cursor_close=True)

    async def claim() -> None:
        async with store._claim_holder_ctx("ingress"):
            raise RuntimeError("claim refused by the stand-in server")

    task = await cancel_once_started(rig.started, claim())
    await cancelled_at_once(task)
    assert "cursor.close:start" in rig.log, "the arm is vacuous: the cancel missed the close"
    assert not {"cursor.close", "conn.close"} & set(rig.log), rig.log

    del task
    await _closes_cursor_then_connection_once(rig, conns)
    assert store._claim_holders_discarded_total == 1 and store._claim_holders_open == 0


async def test_an_ordinary_holder_open_and_claim_close_nothing(rig: _Rig) -> None:
    """The control: with no failure the holder is gated, kept for the next claim, and nothing on
    it is closed."""
    rig.release.set()
    conns: list[AioConn] = []
    store = _holder_store(rig, conns, blocks=never)
    async with store._claim_holder_ctx("ingress") as holder:
        await holder.cur.execute(_CLAIM)
    assert store._claim_holders["ingress"] == [holder]
    assert store._claim_holders_open == 1
    assert not {"cursor.close", "conn.close"} & set(rig.log), rig.log
