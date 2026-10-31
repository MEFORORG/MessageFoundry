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
from messagefoundry.transports.database import (
    DatabaseDestination,
    DatabaseLookupExecutor,
    DatabaseSource,
)
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
    """The shared fake pool, plus aioodbc's ``close`` and ``wait_closed``. Like aioodbc's, a
    connection released into a closing pool is closed rather than kept, and ``wait_closed`` waits
    for the connection in use to come back."""

    def __init__(self, conn: AioConn) -> None:
        super().__init__(conn)
        self.closed = False
        self.returned = False
        self.waits = 0  # wait_closed calls: aioodbc wakes one waiter per return

    def close(self) -> None:
        self.closed = True

    async def release(self, conn: AioConn) -> None:
        self.returned = True
        if self.closed and not conn.closed:
            await conn.close()  # a gated call, through aioodbc's _execute
            return
        await super().release(conn)

    async def wait_closed(self) -> None:
        self.waits += 1
        assert await wait_until(lambda: self.returned), "the borrowed connection never came back"


class _RollbackRefused(RawConn):
    """A connection whose rollback the stand-in server refuses."""

    def rollback(self) -> None:
        self.note("rollback:refused")
        raise RuntimeError("refused by the stand-in server")


@dataclass
class _Rig:
    executor: ThreadPoolExecutor
    log: list[str] = field(default_factory=list)
    release: threading.Event = field(default_factory=threading.Event)
    started: threading.Event = field(default_factory=threading.Event)
    pools: list[_ClosingPool] = field(default_factory=list)

    def raw(self, raw_type: type[RawConn] = RawConn, **kw: Any) -> RawConn:
        return raw_type(self.log, self.release, self.started, **kw)

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


def _aioodbc_serving(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, *, gateable: bool = True, **raw_kw: Any
) -> None:
    """Stand ``aioodbc`` in: each ``create_pool`` hands out a pool over one aioodbc-shaped
    connection on ``rig``'s executor, recorded in ``rig.pools``."""

    async def create_pool(**kwargs: Any) -> _ClosingPool:
        pool = _ClosingPool(AioConn(rig.raw(**raw_kw), rig.executor, gateable=gateable))
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


def _assert_closed_and_rolled_back_after_the_statement(rig: _Rig) -> None:
    """The cursor closes once the statement has returned, then the cancelled statement's
    transaction is rolled back in the same gated job, and no handle was used after it was freed."""
    assert USE_AFTER_FREE not in rig.log, rig.log
    end = rig.log.index("execute:end")
    assert end < rig.log.index("cursor.close") < rig.log.index("rollback"), rig.log


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

    _assert_closed_and_rolled_back_after_the_statement(rig)
    assert "conn.close" not in rig.log, rig.log
    assert call_gate(rig.conn) is not None
    assert len(close_threads) == 1 and close_threads[0].startswith("test-2394b"), close_threads


async def test_a_cancelled_destination_send_frees_nothing_until_its_statement_returns(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The manual-commit pool, borrowed through ``_acquire``. Red before #2394 part b: the cursor
    closed on another thread while the INSERT still ran, and the connection went back at once,
    with the INSERT's transaction still open for the next send to commit."""
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


async def test_a_cancelled_send_whose_rollback_fails_still_returns_its_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """A refused rollback is logged, and the connection still goes back open: dropping its handle
    would leave a waiting borrower or pool close unwoken, since aioodbc wakes neither for a
    closed connection."""
    _aioodbc_serving(monkeypatch, rig, raw_type=_RollbackRefused, blocks=lambda s: s == _INSERT)
    task = await cancel_once_started(rig.started, _destination().send('{"a": 1}'))
    done, _pending = await asyncio.wait({task}, timeout=1.0)
    assert done, "the cancellation waited for the running statement"

    with caplog.at_level("WARNING", logger="messagefoundry.transports.database"):
        rig.release.set()
        assert await wait_until(lambda: rig.pools[0].free == [rig.conn]), "it never went back"

    assert USE_AFTER_FREE not in rig.log, rig.log
    end = rig.log.index("execute:end")
    assert end < rig.log.index("cursor.close") < rig.log.index("rollback:refused"), rig.log
    assert not rig.conn.closed and "conn.close" not in rig.log, rig.log
    assert "rollback after a cancelled statement failed" in caplog.text


async def test_an_ungated_connection_gets_no_rollback_beside_its_statement(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """A connection the gate could not wrap. Its cursor close still runs beside the statement,
    the hazard an ungated connection keeps, but no rollback is added to it."""
    _aioodbc_serving(monkeypatch, rig, gateable=False, blocks=lambda sql: sql == _INSERT)
    task = await cancel_once_started(rig.started, _destination().send('{"a": 1}'))
    done, _pending = await asyncio.wait({task}, timeout=1.0)
    assert done, "the cancellation waited for the running statement"
    assert call_gate(rig.conn) is None, "the arm is vacuous: the connection was gated"

    rig.release.set()
    assert await wait_until(lambda: rig.pools[0].free == [rig.conn]), "it never went back"
    assert "rollback" not in rig.log, rig.log


async def test_a_cancelled_reference_sync_frees_nothing_until_its_statement_returns(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """A ``DatabaseRef`` sync borrows through ``acquire_pooled``, not ``_acquire``, so this pins
    the gate the autocommit pool installs itself. The sync then closes its throwaway pool, which
    closes the connection once it comes back, after its statement and cursor."""
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

    _assert_closed_and_rolled_back_after_the_statement(rig)
    assert rig.log.index("rollback") < rig.log.index("conn.close"), rig.log
    assert rig.pools[0].closed and rig.pools[0].returned
    assert call_gate(rig.conn) is not None


async def test_a_destination_close_does_not_wait_out_a_cancelled_statement(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """A stop cancels the delivery worker, then closes the connector. The cancelled send's
    statement still holds its connection, with no time limit, so an unbounded ``wait_closed`` would
    hold the stop for as long as it runs. The close is bounded, and the connection is still
    released, and closed, only once its statement has returned."""
    monkeypatch.setattr(database, "_POOL_CLOSE_TIMEOUT_S", 0.2)
    _aioodbc_serving(monkeypatch, rig, blocks=lambda sql: sql == _INSERT)
    destination = _destination()
    task = await cancel_once_started(rig.started, destination.send('{"a": 1}'))
    done, _pending = await asyncio.wait({task}, timeout=1.0)
    assert done, "the cancellation waited for the running statement"

    await asyncio.wait_for(destination.aclose(), 1.0)
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"
    assert "conn.close" not in rig.log, rig.log

    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")
    _assert_closed_and_rolled_back_after_the_statement(rig)
    assert rig.log.index("rollback") < rig.log.index("conn.close"), rig.log


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
    await pool.release(await asyncio.wait_for(acquiring, WAIT))

    assert USE_AFTER_FREE not in rig.log, rig.log
    assert rig.log.index("autocommit:end") < rig.log.index("conn.close"), rig.log


async def test_an_ordinary_send_gates_its_connection_and_returns_it_before_send_returns(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The control. With no cancellation the connection is gated, the INSERT commits, the
    cursor closes, and the connection is back in the pool by the time ``send`` returns: the
    hand-off and the rollback a cancellation takes are not taken on the ordinary path."""
    rig.release.set()
    _aioodbc_serving(monkeypatch, rig, blocks=never)

    assert await _destination().send('{"a": 1}') is None

    assert call_gate(rig.conn) is not None
    assert rig.pools[0].free == [rig.conn]
    assert rig.log.index("execute:end") < rig.log.index("commit") < rig.log.index("cursor.close")
    assert "rollback" not in rig.log, rig.log
    assert USE_AFTER_FREE not in rig.log, rig.log


def _block_first(statement: str) -> Any:
    """A ``blocks`` predicate: only the first run of ``statement`` waits, on whichever connection
    runs it, so a second pool's call returns at once."""
    first = [True]

    def blocks(sql: str) -> bool:
        if sql == statement and first:
            first.pop()
            return True
        return False

    return blocks


async def test_a_source_probe_cancelled_in_a_hung_select_does_not_hold_its_stop(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The API's connection test cuts ``test_connection`` at its timeout, then stops the source in
    a ``finally``. The cancelled ``SELECT 1`` still holds its connection, so an unbounded pool close
    hung the request. The connection is held back behind a cancelled borrow, so the stop stops
    waiting at the bound, and the connection is still not returned, or closed, while its statement
    runs. Red with the count condition reverted: stop() never returns while the statement runs."""
    monkeypatch.setattr(database, "_POOL_CLOSE_TIMEOUT_S", 0.2)
    _aioodbc_serving(monkeypatch, rig, blocks=lambda sql: sql == "SELECT 1")
    source = _source()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(source.test_connection(), 0.5)  # the route's wait_for, shortened
    pool = rig.pools[0]
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"
    assert database._holds_back(pool) == 1

    await asyncio.wait_for(source.stop(), 1.0)
    assert pool.closed and source._pool is None
    assert not pool.returned and pool.free == [] and not rig.conn.closed, rig.log
    assert "cursor.close" not in rig.log, rig.log

    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")  # released into the closing pool, so closed
    _assert_closed_and_rolled_back_after_the_statement(rig)
    assert pool.returned and database._holds_back(pool) == 0


async def test_a_borrow_cancelled_in_its_autocommit_set_does_not_hold_the_stop(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The other connection a cancelled borrow holds back: the autocommit set an abandoned borrow
    leaves running on its thread. It counts too, so the source's stop stops waiting at the bound,
    and the connection goes back, off the count, once the set returns. Red with that count
    dropped: stop() waits for the set."""
    monkeypatch.setattr(database, "_POOL_CLOSE_TIMEOUT_S", 0.2)
    _aioodbc_serving(monkeypatch, rig, blocks=never, block_autocommit=True)
    source = _source()
    task = await cancel_once_started(rig.started, source._mark({"code": "A", "value": "1"}))
    done, _pending = await asyncio.wait({task}, timeout=1.0)
    assert done and task.cancelled(), task
    pool = rig.pools[0]
    assert database._holds_back(pool) == 1

    await asyncio.wait_for(source.stop(), 1.0)
    assert "autocommit:end" not in rig.log, "the arm is vacuous: the set had already returned"
    assert not pool.returned and not rig.conn.closed, rig.log

    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")
    assert pool.returned and database._holds_back(pool) == 0
    assert USE_AFTER_FREE not in rig.log, rig.log
    assert rig.log.index("autocommit:end") < rig.log.index("conn.close"), rig.log


async def _close_beside_an_ordinary_call(make: Any, start: Any, close: Any, rig: _Rig) -> None:
    """Start a borrow whose statement blocks, close the connector beside it with no cancellation,
    and pin that the close waits for the statement past several ticks of the bound."""
    connector = make()
    borrowing = asyncio.create_task(start(connector))
    assert await asyncio.to_thread(rig.started.wait, WAIT), "the statement never started"
    closing = asyncio.create_task(close(connector))
    done, _pending = await asyncio.wait({closing}, timeout=0.5)  # five ticks of the 0.1 s bound
    assert not done, "the close stopped waiting for an ordinary in-flight call"
    assert database._holds_back(rig.pools[0]) == 0

    rig.release.set()
    assert await asyncio.wait_for(borrowing, WAIT) is None
    await asyncio.wait_for(closing, WAIT)
    assert connector._pool is None
    assert rig.log.index("execute:end") < rig.log.index("conn.close"), rig.log
    assert "rollback" not in rig.log and USE_AFTER_FREE not in rig.log, rig.log


@pytest.mark.parametrize("side", ["destination", "source"])
async def test_an_ordinary_close_still_waits_for_an_in_flight_call(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, side: str
) -> None:
    """With no cancelled borrow, an in-flight call is an ordinary one, and the pool close waits
    for it however long it takes, as before BACKLOG #2394: the destination's ``aclose`` and the
    source's ordinary ``stop``. Red with the close bounded whatever the count: the close returns
    at the first tick, with the statement still running."""
    monkeypatch.setattr(database, "_POOL_CLOSE_TIMEOUT_S", 0.1)
    if side == "destination":
        _aioodbc_serving(monkeypatch, rig, blocks=lambda sql: sql == _INSERT)
        await _close_beside_an_ordinary_call(
            _destination, lambda d: d.send('{"a": 1}'), lambda d: d.aclose(), rig
        )
        assert rig.log.index("commit") < rig.log.index("conn.close"), rig.log
    else:
        _aioodbc_serving(monkeypatch, rig, blocks=lambda sql: sql == _MARK)
        await _close_beside_an_ordinary_call(
            _source, lambda s: s._mark({"code": "A", "value": "1"}), lambda s: s.stop(), rig
        )


async def test_a_close_already_waiting_stops_once_a_borrow_is_cancelled(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The count is read again while the close waits: a send cancelled after the close began holds
    its connection back from then on, and the close stops waiting within a tick. Red with the count
    read only once, before the wait: the close waits for the statement."""
    monkeypatch.setattr(database, "_POOL_CLOSE_TIMEOUT_S", 0.2)
    _aioodbc_serving(monkeypatch, rig, blocks=lambda sql: sql == _INSERT)
    destination = _destination()
    sending = asyncio.create_task(destination.send('{"a": 1}'))
    assert await asyncio.to_thread(rig.started.wait, WAIT), "the statement never started"
    closing = asyncio.create_task(destination.aclose())
    done, _pending = await asyncio.wait({closing}, timeout=0.5)
    assert not done, "the arm is vacuous: the close did not wait for the ordinary send"

    sending.cancel()
    done, _pending = await asyncio.wait({closing}, timeout=1.0)
    assert done, "the close kept waiting after the send was cancelled"
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"
    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")
    _assert_closed_and_rolled_back_after_the_statement(rig)


async def test_a_retried_close_waits_on_the_close_already_in_flight(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """A close cancelled while it waits leaves its ``wait_closed`` running, and the pool still
    referenced. A retried close waits on that same one, never a second waiter: aioodbc wakes one
    waiter per returned connection, so a second could wait forever. Red with a fresh
    ``wait_closed`` per close: the pool sees two."""
    monkeypatch.setattr(database, "_POOL_CLOSE_TIMEOUT_S", 0.1)
    _aioodbc_serving(monkeypatch, rig, blocks=lambda sql: sql == _INSERT)
    destination = _destination()
    sending = asyncio.create_task(destination.send('{"a": 1}'))
    assert await asyncio.to_thread(rig.started.wait, WAIT), "the statement never started"
    closing = asyncio.create_task(destination.aclose())
    await asyncio.sleep(0.05)
    closing.cancel()
    with pytest.raises(asyncio.CancelledError):
        await closing
    assert destination._pool is not None, "a cancelled close dropped a pool it had not closed"

    retry = asyncio.create_task(destination.aclose())
    done, _pending = await asyncio.wait({retry}, timeout=0.3)
    assert not done, "the retried close stopped waiting for an ordinary in-flight send"
    rig.release.set()
    assert await asyncio.wait_for(sending, WAIT) is None
    await asyncio.wait_for(retry, WAIT)
    assert destination._pool is None and rig.pools[0].waits == 1


class _FailingClose:
    """A lookup pool whose close fails, or, given ``then``, runs it before succeeding."""

    def __init__(self, error: str | None, then: Any = None) -> None:
        self._error = error
        self._then = then

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        if self._then is not None:
            self._then()
        if self._error is not None:
            raise RuntimeError(self._error)


async def test_a_lookup_close_reports_every_failure_and_keeps_a_pool_opened_meanwhile(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The lookup executor closes its pools together. Every failure is reported, the first
    raised and the rest logged, rather than the rest consumed unseen; a pool that failed to close
    stays, as before, for a later close; and a pool a lookup opened under a name after the
    snapshot is not dropped with the closed one. Red with the plain ``gather``: nothing logs the
    second failure. Red with the pop by name: the new pool is dropped unclosed."""
    executor = DatabaseLookupExecutor.__new__(DatabaseLookupExecutor)
    reopened = _FailingClose(None)

    def _reopen() -> None:
        executor._pools["c"] = reopened  # a lookup on "c" opened a new pool during the close

    first, second = _FailingClose("refused one"), _FailingClose("refused two")
    executor._pools = {"a": first, "b": second, "c": _FailingClose(None, then=_reopen)}
    with (
        caplog.at_level("WARNING", logger="messagefoundry.transports.database"),
        pytest.raises(RuntimeError, match="refused one"),
    ):
        await executor.aclose()
    assert "DatabaseLookup pool close failed" in caplog.text
    assert executor._pools == {"a": first, "b": second, "c": reopened}


async def test_after_a_cancelled_send_a_new_pool_opens_beside_the_closing_one(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The trade the bound makes. After a cancelled send, the destination's close stops waiting
    and drops its pool, so the next send opens a second pool while the first is still closing
    around the held connection. The first close then finishes once the cancelled statement
    returns: its connection goes back, is closed, and is off the count, so a later close of that
    pool would wait as before. Red with the decrement dropped: the count stays at one."""
    monkeypatch.setattr(database, "_POOL_CLOSE_TIMEOUT_S", 0.2)
    _aioodbc_serving(monkeypatch, rig, blocks=_block_first(_INSERT))
    destination = _destination()
    task = await cancel_once_started(rig.started, destination.send('{"a": 1}'))
    done, _pending = await asyncio.wait({task}, timeout=1.0)
    assert done and task.cancelled(), task
    old = rig.pools[0]
    assert database._holds_back(old) == 1

    await asyncio.wait_for(destination.aclose(), 1.0)
    assert destination._pool is None and old.closed

    assert await asyncio.wait_for(destination.send('{"a": 2}'), WAIT) is None
    assert len(rig.pools) == 2, "the second send did not open a new pool"
    new = rig.pools[1]
    assert new.free == [new._conn] and not new._conn.closed
    assert not old.returned and not old._conn.closed, "the old pool's connection went back early"

    rig.release.set()
    assert await wait_until(lambda: old._conn.closed), "the old close never finished"
    assert old.returned and database._holds_back(old) == 0
    assert USE_AFTER_FREE not in rig.log, rig.log
