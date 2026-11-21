# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Batch 611 wave 2, the DATABASE connector remainder: BACKLOG #5749, #5748 and #5756.

* #5749: a ``cursor()`` the driver refuses is classified and its connection discarded at the
  poll, the mark, the lookup query and the ``DatabaseRef`` sync, as ``send()`` already does.
* #5748: an autocommit set that fails with a connection failure (class 08) discards the
  connection rather than returning it open.
* #5756: the ``statement_timeout`` write, the autocommit set and the cursor close run on the
  pool's own executor, never on the event loop or its default executor.

Driven against the faked ``aioodbc`` of ``tests/test_backlog2394_database_gate.py``. Synthetic
data only; no driver, no database.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from messagefoundry.config.db_lookup import DbLookupError
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline.reference_sync import _load_database_source
from messagefoundry.transports import database
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from tests._odbc_cancel_fakes import WAIT, RawConn, cancel_once_started, never, wait_until
from tests.test_b611_database_connector import _BusyCursorRefused, _DriverError
from tests.test_backlog2394_database_gate import (
    _SQLSERVER,
    _aioodbc_serving,
    _destination,
    _no_probe,
    _Rig,
    _source,
)
from tests.test_backlog5010_database_gate_discard import _WakingPool


@pytest.fixture
async def rig() -> AsyncIterator[_Rig]:
    # ``release`` starts unset, so the cancel arms really do land while a call is held.
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-w2-611")
    r = _Rig(executor)
    try:
        yield r
    finally:
        r.release.set()  # never leave a worker parked if an arm failed early
        executor.shutdown(wait=True)
        for pool in r.pools:  # each connector's pool executor, which few arms close themselves
            pool_executor = database._tracked(database._POOL_EXECUTORS, pool)
            if pool_executor is not None:
                pool_executor.shutdown(wait=True)


_RECORD = {"code": 1, "value": "x"}


def _discarded(rig: _Rig) -> bool:
    """The connection was closed and given back closed, waking the pool, not kept free."""
    pool = rig.pools[0]
    return pool.free == [] and rig.conn.closed and isinstance(pool, _WakingPool) and pool.wakes == 1


# --- BACKLOG #5749 -------------------------------------------------------------------------------


async def test_a_poll_whose_cursor_is_refused_is_classified_and_discards(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """Red before: the driver's HY000 escaped ``_select`` unclassified, and the connection, which
    could make no cursor, went back to the free list to be lent again."""
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_BusyCursorRefused, blocks=never
    )
    with pytest.raises(DeliveryError) as caught:
        await _source()._select()
    assert not isinstance(caught.value, NegativeAckError), caught.value
    assert _discarded(rig), rig.log


async def test_a_mark_whose_cursor_is_refused_is_classified_and_discards(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_BusyCursorRefused, blocks=never
    )
    with pytest.raises(DeliveryError) as caught:
        await _source()._mark(dict(_RECORD))
    assert not isinstance(caught.value, NegativeAckError), caught.value
    assert "execute:start" not in rig.log
    assert _discarded(rig), rig.log


async def test_a_lookup_whose_cursor_is_refused_discards_its_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The lookup still fails as a ``DbLookupError``, now naming the classified connect failure."""
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_BusyCursorRefused, blocks=never
    )
    monkeypatch.setattr(database, "probe_login_roles", _probe_returns_nothing)
    executor = database.DatabaseLookupExecutor(
        {"clarity": dict(_SQLSERVER)}, egress=EgressSettings(deny_by_default=False)
    )
    try:
        with pytest.raises(DbLookupError) as caught:
            await executor.query("clarity", "SELECT a FROM t WHERE b = :b", {"b": 1})
        assert "connect failed" in str(caught.value) and "[HY000]" in str(caught.value)
        assert _discarded(rig), rig.log
    finally:
        await executor.aclose()


async def _probe_returns_nothing(pool: Any, *, label: str, acquire_timeout: float) -> Any:
    return database.LoginRoleReading(database.LoginRoleVerdict.NOT_RUN, cause="stood down")


async def test_a_reference_sync_whose_cursor_is_refused_is_classified_and_discards(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_BusyCursorRefused, blocks=never
    )
    monkeypatch.setattr(database, "probe_login_roles", _no_probe)
    settings = {
        **_SQLSERVER,
        "statement": "SELECT code, value FROM ref",
        "key_column": "code",
        "value_column": "value",
    }
    with pytest.raises(DeliveryError) as caught:
        await _load_database_source(settings, EgressSettings(deny_by_default=False))
    assert not isinstance(caught.value, NegativeAckError), caught.value
    assert _discarded(rig), rig.log


async def test_the_login_role_probe_discards_a_connection_that_cannot_make_a_cursor(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """Red before: an HY000 there is no class 08 failure, so the handle went back to the pool, for
    the first lookup to fail on."""
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_BusyCursorRefused, blocks=never
    )
    pool = await database._make_pool("DSN=x", 1, autocommit=False, login_timeout=5)
    reading = await database.probe_login_roles(pool, label="db_lookup:x", acquire_timeout=5.0)
    assert reading.verdict is database.LoginRoleVerdict.NOT_RUN
    assert _discarded(rig), rig.log


class _NoQueryTimeout(_BusyCursorRefused):
    state = "HYC00"


async def test_a_static_cursor_refusal_keeps_its_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The control: a driver refusing the query timeout refuses every cursor on every connection,
    so a discard would only add a login per poll. It is still the named configuration fault."""
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_NoQueryTimeout, blocks=never
    )
    with pytest.raises(NegativeAckError) as caught:
        await _source()._select()
    assert caught.value.config_fault and "statement_timeout" in str(caught.value)
    assert rig.pools[0].free == [rig.conn] and not rig.conn.closed


# --- BACKLOG #5748 -------------------------------------------------------------------------------


class _AutocommitLinkLost(RawConn):
    """A connection whose autocommit set fails with ``state``, after waiting for ``release`` when
    ``block_autocommit`` is set."""

    state = "08S01"

    @property
    def autocommit(self) -> bool:
        return False

    @autocommit.setter
    def autocommit(self, value: bool) -> None:
        self.note("autocommit:start")
        if self.block_autocommit:
            self.hold()
        raise _DriverError(self.state, f"[{self.state}] the stand-in driver failed")


class _AutocommitRefused(_AutocommitLinkLost):
    state = "HY000"


async def test_an_autocommit_set_that_loses_its_link_discards_the_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """Red before: the dead handle went back open, for the next borrow to fail on the same way."""
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_AutocommitLinkLost, blocks=never
    )
    with pytest.raises(_DriverError):
        await _source()._mark(dict(_RECORD))
    assert _discarded(rig), rig.log


async def test_an_autocommit_set_refused_otherwise_keeps_the_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The control: a set refused with no connection failure goes back open, as before, and is
    set again on its next borrow."""
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_AutocommitRefused, blocks=never
    )
    with pytest.raises(_DriverError):
        await _source()._mark(dict(_RECORD))
    assert rig.pools[0].free == [rig.conn] and not rig.conn.closed


async def test_an_abandoned_autocommit_set_that_loses_its_link_discards_the_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The borrower is cancelled while the set runs; the set then fails with 08S01. Red before:
    the settle returned the dead handle open."""
    _aioodbc_serving(
        monkeypatch,
        rig,
        pool_type=_WakingPool,
        raw_type=_AutocommitLinkLost,
        blocks=never,
        block_autocommit=True,
    )
    task = await cancel_once_started(rig.started, _source()._mark(dict(_RECORD)))
    done, _pending = await asyncio.wait({task}, timeout=WAIT)
    assert done and task.cancelled(), task
    assert not rig.conn.closed and rig.pools[0].free == []
    rig.release.set()
    assert await wait_until(lambda: _discarded(rig)), rig.log
    assert await wait_until(lambda: database._holds_back(rig.pools[0]) == 0)


# --- BACKLOG #5756 -------------------------------------------------------------------------------


class _RecordsTimeoutThread(RawConn):
    """Records the thread each non-zero ``timeout`` write runs on."""

    writes: list[str]

    @property
    def timeout(self) -> int:
        return getattr(self, "_timeout", 0)

    @timeout.setter
    def timeout(self, value: int) -> None:
        if value:  # the fake's own __init__ writes 0
            type(self).writes.append(threading.current_thread().name)
            self.note("timeout:start")
            if self.block_autocommit:  # reused as "block the setter", for the cancel arm
                self.hold()
        self._timeout = value


async def test_the_statement_timeout_write_runs_on_the_pools_executor(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """Red before: pyodbc's setter, a driver call, ran on the event loop thread."""
    monkeypatch.setattr(_RecordsTimeoutThread, "writes", [], raising=False)
    _aioodbc_serving(monkeypatch, rig, raw_type=_RecordsTimeoutThread, blocks=never)
    await _destination().send('{"a": 1}')
    assert _RecordsTimeoutThread.writes, rig.log
    assert all(name.startswith("mefor-database") for name in _RecordsTimeoutThread.writes), (
        _RecordsTimeoutThread.writes
    )
    assert rig.conn._conn is not None and rig.conn._conn.timeout == 30


async def test_a_borrower_cancelled_during_the_timeout_write_returns_it_only_once_it_ends(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    monkeypatch.setattr(_RecordsTimeoutThread, "writes", [], raising=False)
    _aioodbc_serving(
        monkeypatch, rig, raw_type=_RecordsTimeoutThread, blocks=never, block_autocommit=True
    )
    task = await cancel_once_started(rig.started, _destination().send('{"a": 1}'))
    done, _pending = await asyncio.wait({task}, timeout=WAIT)
    assert done and task.cancelled(), task
    assert rig.pools[0].free == [], "the connection went back while its setter ran"
    rig.release.set()
    assert await wait_until(lambda: rig.pools[0].free == [rig.conn]), rig.log
    assert "execute:start" not in rig.log


class _TimeoutWriteLosesLink(_RecordsTimeoutThread):
    """The held write then fails with a communication-link failure."""

    @property
    def timeout(self) -> int:
        return 0

    @timeout.setter
    def timeout(self, value: int) -> None:
        if value:
            self.note("timeout:start")
            self.hold()
            raise _DriverError("08S01", "[08S01] communication link failure")


async def test_a_timeout_write_that_fails_after_its_borrower_left_discards_the_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The borrower is cancelled during the write, which then loses its link: the dead handle is
    discarded once the write ends, not returned open."""
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_TimeoutWriteLosesLink, blocks=never
    )
    task = await cancel_once_started(rig.started, _destination().send('{"a": 1}'))
    done, _pending = await asyncio.wait({task}, timeout=WAIT)
    assert done and task.cancelled(), task
    assert rig.pools[0].free == [] and not rig.conn.closed
    rig.release.set()
    assert await wait_until(lambda: _discarded(rig)), rig.log
    assert await wait_until(lambda: database._holds_back(rig.pools[0]) == 0)


async def test_acquire_timeout_bounds_a_hung_timeout_write(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The write sits inside the borrow, so the borrow's bound covers it: a hung write fails the
    borrow transiently, and the connection goes back once the write returns."""
    monkeypatch.setattr(_RecordsTimeoutThread, "writes", [], raising=False)
    _aioodbc_serving(
        monkeypatch, rig, raw_type=_RecordsTimeoutThread, blocks=never, block_autocommit=True
    )
    dest = _destination()
    dest._acquire_timeout = 2.0  # above _TIMEOUT_WRITE_FLOOR_S, so the write is bounded
    with pytest.raises(DeliveryError) as caught:
        await asyncio.wait_for(dest.send('{"a": 1}'), WAIT)
    assert not isinstance(caught.value, NegativeAckError)
    assert "statement_timeout write did not finish" in str(caught.value)
    assert rig.pools[0].free == []
    rig.release.set()
    assert await wait_until(lambda: rig.pools[0].free == [rig.conn]), rig.log


async def test_the_cursor_close_and_autocommit_set_run_on_the_pools_executor(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """Red before: both went to the event loop's default executor, shared with every other
    connector and ``to_thread`` hop."""
    threads: list[str] = []
    closer = database._close_raw_cursor
    setter = database._set_and_read_autocommit

    def _recording_close(raw_cur: Any) -> None:
        threads.append(threading.current_thread().name)
        closer(raw_cur)

    def _recording_set(raw: Any) -> bool:
        threads.append(threading.current_thread().name)
        return setter(raw)

    monkeypatch.setattr(database, "_close_raw_cursor", _recording_close)
    monkeypatch.setattr(database, "_set_and_read_autocommit", _recording_set)
    _aioodbc_serving(monkeypatch, rig, blocks=never)
    await _source()._mark(dict(_RECORD))
    assert len(threads) == 2, (threads, rig.log)
    assert all(name.startswith("mefor-database") for name in threads), threads


# --- the coordinator's repair of 976dca70 --------------------------------------------------------


class _LoginRefusedCursor(_BusyCursorRefused):
    state = "28000"


async def test_a_send_discards_on_every_cursor_refusal_a_login_refusal_included(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """send() discards on every cursor refusal, as origin/main does; only the sites this branch
    newly classifies keep a connection on a static refusal. Red at 976dca70, which kept it."""
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_LoginRefusedCursor, blocks=never
    )
    with pytest.raises(NegativeAckError) as caught:
        await _destination().send('{"a": 1}')
    assert caught.value.credential_fault, caught.value
    assert _discarded(rig), rig.log


class _AcquireSpendsBudget(_WakingPool):
    """A pool whose acquire returns once the borrow's whole acquire_timeout has passed, read by
    the loop's clock, which ``bump`` moves forward."""

    bump: Any = None

    async def acquire(self) -> Any:
        conn = await super().acquire()
        type(self).bump()
        return conn


class _SlowTimeoutWrite(RawConn):
    """A ``timeout`` write that takes a short real time on its worker thread."""

    @property
    def timeout(self) -> int:
        return getattr(self, "_timeout", 0)

    @timeout.setter
    def timeout(self, value: int) -> None:
        if value:
            threading.Event().wait(0.05)
            self.note("timeout:set")
        self._timeout = value


@pytest.mark.parametrize("left", [0.0, 0.01])
async def test_a_borrow_whose_acquire_spent_the_budget_still_waits_for_the_write(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, left: float
) -> None:
    """Red at 976dca70: the write got a zero budget and the borrow failed, where origin/main,
    whose write had no bound, succeeded."""
    loop = asyncio.get_running_loop()
    real_time = loop.time
    offset = [0.0]
    monkeypatch.setattr(loop, "time", lambda: real_time() + offset[0])
    dest = _destination()
    dest._acquire_timeout = 1.0  # well inside WAIT, which the moved clock also reads

    def _spend() -> None:
        offset[0] += dest._acquire_timeout - left  # a sliver left is spent too

    monkeypatch.setattr(_AcquireSpendsBudget, "bump", staticmethod(_spend))
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_AcquireSpendsBudget, raw_type=_SlowTimeoutWrite, blocks=never
    )
    await asyncio.wait_for(dest.send('{"a": 1}'), WAIT)
    assert "timeout:set" in rig.log and "execute:start" in rig.log, rig.log
    assert rig.pools[0].free == [rig.conn]
