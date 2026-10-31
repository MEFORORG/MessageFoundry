# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2394 part b - the DATABASE connector's pooled borrows go through the ODBC call gate.

The connector borrowed aioodbc connections with no gate. A cancellation during ``execute`` reached
``_close_and_release`` while the statement still ran on its worker thread, and the cursor close
ran on another thread beside it. On a real driver that frees the statement handle the running call
returns to, the native crash BACKLOG #2049 recorded for the SQL Server store.

Each arm drives a real call site against a faked ``aioodbc`` built from the shared fakes
(``tests/_odbc_cancel_fakes.py``): a real thread pool, and raw stand-ins that record a use of a
freed handle instead of crashing on it. The three borrow shapes are a manual-commit destination
send and an autocommit source mark, both through ``_acquire``, and a ``DatabaseRef`` sync, which
borrows through ``acquire_pooled``. Synthetic data only; no driver, no database.
"""

from __future__ import annotations

import asyncio
import sys
import threading
import types
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.odbc_call_gate import call_gate
from messagefoundry.pipeline.reference_sync import _load_database_source
from messagefoundry.transports import database
from messagefoundry.transports.database import DatabaseDestination, DatabaseSource
from tests._odbc_cancel_fakes import (
    USE_AFTER_FREE,
    WAIT,
    AioConn,
    Pool,
    RawConn,
    cancel_once_started,
    never,
    wait_for_entry,
    wait_until,
)

_SQLSERVER: dict[str, Any] = {"server": "db.example", "database": "d"}
_INSERT = "INSERT INTO t (a) VALUES (?)"
_MARK = "UPDATE q SET done = 1 WHERE code = ?"
_REF = "SELECT code, value FROM ref"


class _ClosingPool(Pool):
    """The shared fake pool, plus aioodbc's ``close`` and ``wait_closed``. Like aioodbc's,
    ``wait_closed`` waits for the connection in use to come back."""

    def __init__(self, conn: AioConn) -> None:
        super().__init__(conn)
        self.closed = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        assert await wait_until(lambda: bool(self.free)), "the borrowed connection never came back"


@dataclass
class _Rig:
    executor: ThreadPoolExecutor
    log: list[str] = field(default_factory=list)
    release: threading.Event = field(default_factory=threading.Event)
    started: threading.Event = field(default_factory=threading.Event)
    pools: list[_ClosingPool] = field(default_factory=list)

    def raw(self, **kw: Any) -> RawConn:
        return RawConn(self.log, self.release, self.started, **kw)

    @property
    def conn(self) -> AioConn:
        return self.pools[0]._conn


@pytest.fixture
async def rig() -> AsyncIterator[_Rig]:
    # More than one worker, so a close submitted during a call CAN run beside it.
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-2394b")
    r = _Rig(executor)
    try:
        yield r
    finally:
        r.release.set()  # never leave a worker parked if an arm failed early
        executor.shutdown(wait=True)


def _aioodbc_serving(monkeypatch: pytest.MonkeyPatch, rig: _Rig, **raw_kw: Any) -> None:
    """Stand ``aioodbc`` in: each ``create_pool`` hands out a pool over one aioodbc-shaped
    connection on ``rig``'s executor, recorded in ``rig.pools``."""

    async def create_pool(**kwargs: Any) -> _ClosingPool:
        pool = _ClosingPool(AioConn(rig.raw(**raw_kw), rig.executor))
        rig.pools.append(pool)
        return pool

    module = types.ModuleType("aioodbc")
    module.create_pool = create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    monkeypatch.setitem(sys.modules, "pyodbc", None)  # the #2049 pooling guard becomes a no-op


def _destination() -> DatabaseDestination:
    return DatabaseDestination(
        Destination(
            name="OB_DB",
            type=ConnectorType.DATABASE,
            settings={**_SQLSERVER, "statement": "INSERT INTO t (a) VALUES (:a)"},
        )
    )


def _source() -> DatabaseSource:
    return DatabaseSource(
        Source(
            name="IB_DB",
            type=ConnectorType.DATABASE,
            settings={
                **_SQLSERVER,
                "poll_statement": "SELECT code, value FROM q",
                "mark_statement": "UPDATE q SET done = 1 WHERE code = :code",
            },
        )
    )


def _assert_closed_after_the_statement(rig: _Rig) -> None:
    assert USE_AFTER_FREE not in rig.log, rig.log
    assert rig.log.index("execute:end") < rig.log.index("cursor.close"), rig.log
    assert "conn.close" not in rig.log, rig.log


async def _cancel_mid_statement(monkeypatch: pytest.MonkeyPatch, rig: _Rig, coro: Any) -> None:
    """Cancel ``coro`` once its statement is running, then let the statement return, and pin the
    exit: the cancellation propagates long before the statement returns, since this connector sets
    no statement timeout and a task that waited for it could wait without bound; nothing is
    closed or returned while the statement runs; and the cursor close then runs on the
    statement's own thread, so no second thread was parked waiting for it."""
    close_threads: list[str] = []
    closer = database._close_raw_cursor

    def _recording_close(raw_cur: Any) -> None:
        close_threads.append(threading.current_thread().name)
        closer(raw_cur)

    monkeypatch.setattr(database, "_close_raw_cursor", _recording_close)
    task = await cancel_once_started(rig.started, coro)
    done, _pending = await asyncio.wait({task}, timeout=1.0)
    assert done, "the cancellation waited for the running statement"
    assert task.cancelled(), task
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"
    assert "cursor.close" not in rig.log, rig.log
    assert rig.pools[0].free == [], "the connection went back while its statement ran"

    rig.release.set()
    await wait_for_entry(rig.log, "cursor.close")
    assert await wait_until(lambda: rig.pools[0].free == [rig.conn]), "it never went back"

    _assert_closed_after_the_statement(rig)
    assert call_gate(rig.conn) is not None
    assert len(close_threads) == 1 and close_threads[0].startswith("test-2394b"), close_threads


async def test_a_cancelled_destination_send_frees_nothing_until_its_statement_returns(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The manual-commit pool, borrowed through ``_acquire``. Red before #2394 part b: the cursor
    closed on another thread while the INSERT still ran, and the connection went back at once."""
    _aioodbc_serving(monkeypatch, rig, blocks=lambda sql: sql == _INSERT)
    await _cancel_mid_statement(monkeypatch, rig, _destination().send('{"a": 1}'))


async def test_a_cancelled_source_mark_frees_nothing_until_its_statement_returns(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The autocommit pool, borrowed through ``_acquire``. The connection is put in autocommit
    first, through the gate, and goes back to the pool only once the mark has returned."""
    _aioodbc_serving(monkeypatch, rig, blocks=lambda sql: sql == _MARK)
    await _cancel_mid_statement(monkeypatch, rig, _source()._mark({"code": "A", "value": "1"}))
    assert rig.log.index("autocommit:end") < rig.log.index("execute:start"), rig.log


async def test_a_cancelled_reference_sync_frees_nothing_until_its_statement_returns(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """A ``DatabaseRef`` sync borrows through ``acquire_pooled``, not ``_acquire``, so this pins
    the gate the autocommit pool installs itself. The sync then closes its throwaway pool, and
    that close waits for the borrowed connection, so the cancelled sync ends only once the
    statement has returned: the wait ``_AutocommitPool`` already documents."""
    _aioodbc_serving(monkeypatch, rig, blocks=lambda sql: sql == _REF)
    settings = {**_SQLSERVER, "statement": _REF, "key_column": "code", "value_column": "value"}
    task = await cancel_once_started(
        rig.started, _load_database_source(settings, EgressSettings(deny_by_default=False))
    )
    await asyncio.sleep(0.1)  # time for a close beside the statement to run, were it ungated
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"
    assert "cursor.close" not in rig.log, rig.log

    rig.release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, WAIT)

    _assert_closed_after_the_statement(rig)
    assert rig.pools[0].free == [rig.conn] and rig.pools[0].closed
    assert call_gate(rig.conn) is not None


async def test_the_autocommit_set_runs_inside_the_call_gate(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """``_set_and_read_autocommit`` sets the mode on the raw handle, a driver call that aioodbc's
    ``_execute`` never sees. Gating the connection is not enough: the set must run through the
    gate too, or a gated call on the same connection, such as a close, runs beside it."""
    _aioodbc_serving(monkeypatch, rig, blocks=never, block_autocommit=True)
    pool = await _source()._get_pool()
    acquiring = asyncio.ensure_future(pool.acquire())
    assert await asyncio.to_thread(rig.started.wait, WAIT), "the set never started"
    closing = asyncio.create_task(rig.conn.close())  # a gated call, through aioodbc's _execute
    await asyncio.sleep(0.1)  # time for the close to run beside the set, were the set ungated
    assert "conn.close" not in rig.log, "the close ran beside the autocommit set"

    rig.release.set()
    await asyncio.wait_for(closing, WAIT)
    await asyncio.wait_for(acquiring, WAIT)

    assert USE_AFTER_FREE not in rig.log, rig.log
    assert rig.log.index("autocommit:end") < rig.log.index("conn.close"), rig.log


async def test_an_ordinary_send_gates_its_connection_and_returns_it_before_send_returns(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The control. With no cancellation the connection is gated, the INSERT commits, the
    cursor closes, and the connection is back in the pool by the time ``send`` returns: the
    hand-off a cancellation takes is not taken on the ordinary path."""
    rig.release.set()
    _aioodbc_serving(monkeypatch, rig, blocks=never)

    assert await _destination().send('{"a": 1}') is None

    assert call_gate(rig.conn) is not None
    assert rig.pools[0].free == [rig.conn]
    assert rig.log.index("execute:end") < rig.log.index("commit") < rig.log.index("cursor.close")
    assert USE_AFTER_FREE not in rig.log, rig.log
