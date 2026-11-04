# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5010, #5004 and #5005 - the DATABASE connector's call-gate exits after PR 2692.

* #5010: a rollback that fails, after a cancelled statement or after a failed send, discards the
  connection. Before, it went back to the pool open, and on a live session the next send's commit
  would have committed the abandoned INSERT with its own.
* #5004: whether a borrow is unwinding a cancellation is read from the exception in flight, not
  from ``Task.cancelling()`` with no baseline. A task that once absorbed a cancel took the cancel
  path on every later borrow, and an ``uncancel()`` before the ``finally`` made the close wait on
  a statement with no time limit.
* #5005: the call gate reads a cursor's ``_impl`` in one place, logs what it cannot gate once per
  process for each type rather than on every borrow, and ``pyproject.toml`` pins aioodbc.

Each arm drives a real call site against the faked ``aioodbc`` of
``tests/test_backlog2394_database_gate.py``. Synthetic data only; no driver, no database.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import tomllib
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import odbc_call_gate
from messagefoundry.odbc_call_gate import call_gate, install_call_gate, raw_cursor
from messagefoundry.transports import database
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from tests._odbc_cancel_fakes import (
    USE_AFTER_FREE,
    AioConn,
    RawConn,
    RawCursor,
    cancel_once_started,
    never,
    wait_until,
)
from tests.test_backlog2394_database_gate import (
    _INSERT,
    _aioodbc_serving,
    _ClosingPool,
    _destination,
    _Rig,
)

_ROOT = Path(__file__).resolve().parents[1]
_DB_LOG = "messagefoundry.transports.database"


class _RollbackRefused(RawConn):
    """A connection whose rollback the stand-in server refuses."""

    def rollback(self) -> None:
        self.note("rollback:refused")
        raise RuntimeError("refused by the stand-in server")


class _WakingPool(_ClosingPool):
    """The fake pool, plus aioodbc 0.5.0's ``Pool._wakeup``, counted."""

    def __init__(self, conn: AioConn) -> None:
        super().__init__(conn)
        self.wakes = 0

    async def _wakeup(self) -> None:
        self.wakes += 1


@pytest.fixture
async def rig() -> AsyncIterator[_Rig]:
    # More than one worker, so a close submitted during a call CAN run beside it.
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-5010")
    r = _Rig(executor)
    try:
        yield r
    finally:
        r.release.set()  # never leave a worker parked if an arm failed early
        executor.shutdown(wait=True)


# --- BACKLOG #5010 -------------------------------------------------------------------------------


async def test_a_cancelled_send_whose_rollback_fails_discards_its_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """The cancelled INSERT's rollback is refused while the session lives. The connection is
    closed in the same gated job, after the cursor, and the pool gets it back closed, never on its
    free list, and is woken for it. Red before #5010: it went back open, on the free list."""
    _aioodbc_serving(
        monkeypatch,
        rig,
        pool_type=_WakingPool,
        raw_type=_RollbackRefused,
        blocks=lambda s: s == _INSERT,
    )
    task = await cancel_once_started(rig.started, _destination().send('{"a": 1}'))
    done, _pending = await asyncio.wait({task}, timeout=1.0)
    assert done and task.cancelled(), "the cancellation waited for the running statement"
    pool = rig.pools[0]

    with caplog.at_level("WARNING", logger=_DB_LOG):
        rig.release.set()
        assert await wait_until(lambda: pool.returned), "the connection never came back"
        assert await wait_until(lambda: database._holds_back(pool) == 0), "still held back"

    assert pool.free == [], "a connection whose rollback failed went back to the free list"
    assert rig.conn.closed and isinstance(pool, _WakingPool) and pool.wakes == 1
    assert USE_AFTER_FREE not in rig.log, rig.log
    order = [rig.log.index(e) for e in ("execute:end", "cursor.close", "rollback:refused")]
    assert order == sorted(order) and order[-1] < rig.log.index("conn.close"), rig.log
    assert "the connection is discarded rather than returned" in caplog.text


async def test_a_send_whose_rollback_fails_discards_its_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """No cancellation: the INSERT fails, and so does the send's own rollback. The rollback's
    error still propagates, as before, but the connection is closed after its cursor and goes
    back closed. Red before #5010: it went back open, for the next send to commit on."""
    rig.release.set()
    _aioodbc_serving(
        monkeypatch,
        rig,
        pool_type=_WakingPool,
        raw_type=_RollbackRefused,
        blocks=never,
        fails=frozenset({_INSERT}),
    )
    with (
        caplog.at_level("WARNING", logger=_DB_LOG),
        pytest.raises(RuntimeError, match="refused by the stand-in server"),
    ):
        await _destination().send('{"a": 1}')
    pool = rig.pools[0]

    assert pool.returned and pool.free == [] and rig.conn.closed
    assert isinstance(pool, _WakingPool) and pool.wakes == 1
    assert database._holds_back(pool) == 0
    order = [rig.log.index(e) for e in ("rollback:refused", "cursor.close", "conn.close")]
    assert order == sorted(order), rig.log
    assert "commit" not in rig.log and USE_AFTER_FREE not in rig.log, rig.log
    assert "rollback after a failed send failed" in caplog.text


class _LinkLostCursor(RawCursor):
    """A cursor whose failing statement raises as a pyodbc driver error, SQLSTATE first."""

    def execute(self, sql: str, *params: object) -> RawCursor:
        try:
            return super().execute(sql, *params)
        except RuntimeError as exc:
            raise RuntimeError("08S01", "[08S01] communication link failure") from exc


class _LinkLostRollbackRefused(_RollbackRefused):
    """The statement fails with a driver error, and its rollback is refused too."""

    def cursor(self) -> RawCursor:
        cur = _LinkLostCursor(self)
        self.cursors.append(cur)
        return cur


async def test_a_driver_error_whose_rollback_fails_is_classified_and_discarded(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The INSERT fails with a driver error and the rollback fails after it. The send's failure is
    classified as it would be had the rollback passed (a dropped link, so a transient retry), with
    the rollback's error as its cause, and the connection is discarded, so the retry cannot meet
    the open INSERT. Red before this round: the raw rollback error reached the runner's
    internal-error arm, which dead-letters by default."""
    rig.release.set()
    _aioodbc_serving(
        monkeypatch,
        rig,
        pool_type=_WakingPool,
        raw_type=_LinkLostRollbackRefused,
        blocks=never,
        fails=frozenset({_INSERT}),
    )
    with pytest.raises(DeliveryError, match="transient") as caught:
        await _destination().send('{"a": 1}')
    assert not isinstance(caught.value, NegativeAckError)
    assert str(caught.value.__cause__) == "refused by the stand-in server"
    pool = rig.pools[0]
    assert pool.free == [] and rig.conn.closed and "commit" not in rig.log, rig.log


async def test_a_failed_wake_is_logged_and_only_a_closed_connection_wakes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``_release`` runs in callers' ``finally`` blocks, so a wake that fails is logged rather than
    raised over the caller's outcome. A ``closed`` that is not literally ``True`` is not read as a
    discard, so it wakes nothing."""

    class _Pool:
        def __init__(self) -> None:
            self.released: list[object] = []
            self.wakes = 0

        async def release(self, conn: object) -> None:
            self.released.append(conn)

        async def _wakeup(self) -> None:
            self.wakes += 1
            raise RuntimeError("wake refused by the stand-in pool")

    class _Closed:
        closed = True

    class _Odd:
        def closed(self) -> bool:  # a method, truthy as an attribute
            return True

    pool = _Pool()
    closed, odd = _Closed(), _Odd()
    with caplog.at_level("WARNING", logger=_DB_LOG):
        await database._release(pool, closed)
        await database._release(pool, odd)
    assert pool.released == [closed, odd] and pool.wakes == 1
    assert "waking the pool for a closed connection failed" in caplog.text


async def test_a_failed_send_whose_rollback_succeeds_keeps_its_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The control for the arm above: the rollback succeeds, so the connection goes back open,
    with no wake beyond aioodbc's own, and nothing is closed."""
    rig.release.set()
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, blocks=never, fails=frozenset({_INSERT})
    )
    with pytest.raises(RuntimeError, match="refused by the stand-in server"):
        await _destination().send('{"a": 1}')
    pool = rig.pools[0]
    assert pool.free == [rig.conn] and not rig.conn.closed
    assert isinstance(pool, _WakingPool) and pool.wakes == 0
    assert "conn.close" not in rig.log, rig.log


async def test_a_discard_into_a_pool_with_no_wakeup_holds_it_back_and_says_so_once(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """A pool with no ``_wakeup`` cannot be woken for a discarded connection, so a close of it
    would wait for a wake that never comes. The discard counts as held back for good, so that
    close stops at its bound, and ERROR is logged once, not once per discard."""
    monkeypatch.setattr(odbc_call_gate, "_REPORTED", set())
    rig.release.set()
    _aioodbc_serving(
        monkeypatch, rig, raw_type=_RollbackRefused, blocks=never, fails=frozenset({_INSERT})
    )
    destination = _destination()
    with caplog.at_level("ERROR", logger=odbc_call_gate.log.name):
        with pytest.raises(RuntimeError):
            await destination.send('{"a": 1}')
        pool = rig.pools[0]
        assert rig.conn.closed and pool.free == []
        assert database._holds_back(pool) == 1
        await database._wake(pool)  # a second discard into the same pool
    assert database._holds_back(pool) == 2
    assert caplog.text.count("has no _wakeup") == 1, caplog.text


async def test_a_cancelled_discard_into_a_pool_with_no_wakeup_nets_one_hold(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """The cancel path's accounting: the detached return holds one, the unwakeable discard holds
    one for good, and the return settling drops the first. One stays, and ERROR is logged once."""
    monkeypatch.setattr(odbc_call_gate, "_REPORTED", set())
    _aioodbc_serving(monkeypatch, rig, raw_type=_RollbackRefused, blocks=lambda s: s == _INSERT)
    task = await cancel_once_started(rig.started, _destination().send('{"a": 1}'))
    done, _pending = await asyncio.wait({task}, timeout=1.0)
    assert done and task.cancelled()
    pool = rig.pools[0]
    assert database._holds_back(pool) == 1, "the detached return was not counted"
    with caplog.at_level("ERROR", logger=odbc_call_gate.log.name):
        rig.release.set()
        assert await wait_until(lambda: pool.returned), "the connection never came back"
        await asyncio.sleep(0.05)  # time for the return's settle to land after the wake
    assert rig.conn.closed and pool.free == []
    assert database._holds_back(pool) == 1
    assert caplog.text.count("has no _wakeup") == 1, caplog.text


# --- BACKLOG #5004 -------------------------------------------------------------------------------


async def _absorb_a_cancel() -> None:
    """Take a cancel and swallow it without ``uncancel()``, leaving ``cancelling()`` at one."""
    task = asyncio.current_task()
    assert task is not None
    asyncio.get_running_loop().call_soon(task.cancel)
    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.sleep(1.0)
    assert task.cancelling() == 1, "the arm is vacuous: no cancel was absorbed"


async def test_a_send_after_an_absorbed_cancel_takes_the_ordinary_path(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The task absorbed a cancel long before this send. Nothing is being cancelled now, so the
    send closes its cursor, adds no rollback, and has its connection back in the pool by the time
    it returns, with nothing held back. Red before #5004: ``cancelling()`` still read one, so the
    send rolled back after its commit and returned the connection detached, counted as held."""
    rig.release.set()
    _aioodbc_serving(monkeypatch, rig, blocks=never)
    destination = _destination()
    seen: list[object] = []

    async def body() -> None:
        await _absorb_a_cancel()
        assert await destination.send('{"a": 1}') is None
        pool = rig.pools[0]
        seen.extend([list(pool.free), database._holds_back(pool)])

    await asyncio.wait_for(asyncio.create_task(body()), 5.0)
    await asyncio.sleep(0.1)  # time for a detached return or an added rollback to land
    assert seen == [[rig.conn], 0], seen
    assert "rollback" not in rig.log, rig.log
    assert rig.log.index("commit") < rig.log.index("cursor.close"), rig.log


async def test_an_uncancel_before_the_finally_does_not_make_the_close_wait(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The cancel lands during the INSERT, and ``uncancel()`` runs before the send's ``finally``
    reaches the close, so ``cancelling()`` reads zero there. The cancellation is still the one
    unwinding, so the task ends at once, and the connection goes back, rolled back, only once the
    statement returns. Red before #5004: the close waited, through ``shield``, on the statement."""
    _aioodbc_serving(monkeypatch, rig, blocks=lambda s: s == _INSERT)
    close_and_release = database._close_and_release

    async def _uncancel_first(pool: Any, conn: Any, cur: Any, **kw: Any) -> None:
        task = asyncio.current_task()
        assert task is not None
        while task.cancelling():
            task.uncancel()
        await close_and_release(pool, conn, cur, **kw)

    monkeypatch.setattr(database, "_close_and_release", _uncancel_first)
    task = await cancel_once_started(rig.started, _destination().send('{"a": 1}'))
    done, _pending = await asyncio.wait({task}, timeout=1.0)
    assert done, "the close waited for the running statement"
    assert task.cancelled(), task
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"
    assert rig.pools[0].free == [], "the connection went back while its statement ran"

    rig.release.set()
    assert await wait_until(lambda: rig.pools[0].free == [rig.conn]), "it never went back"
    assert rig.log.index("execute:end") < rig.log.index("cursor.close") < rig.log.index("rollback")
    assert USE_AFTER_FREE not in rig.log, rig.log


# --- BACKLOG #5005 -------------------------------------------------------------------------------


def _aioodbc_shaped(name: str, **attrs: Any) -> Any:
    """An instance of a class whose module reads as aioodbc's, carrying only ``attrs``."""
    cls = type(name, (), {"__module__": "aioodbc.fake", **attrs})
    return cls()


def test_an_ungateable_aioodbc_connection_is_reported_once_not_per_borrow(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A pool borrows on every send, and each borrow installs the gate. An aioodbc connection with
    no bound ``_execute`` is still left ungated, and the ERROR is logged once for its type. Red
    before #5005: one ERROR per borrow."""
    monkeypatch.setattr(odbc_call_gate, "_REPORTED", set())
    with caplog.at_level("ERROR", logger=odbc_call_gate.log.name):
        for _ in range(3):
            conn = _aioodbc_shaped("Connection")
            install_call_gate(conn)
            assert call_gate(conn) is None
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1, caplog.text
    assert "no bound _execute" in errors[0].getMessage()


def test_a_raw_cursor_is_read_from_impl_and_a_missing_one_is_reported_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """``raw_cursor`` is the one reading of ``_impl``. A test double without it is silent; an
    aioodbc cursor without it is reported once for its type."""
    monkeypatch.setattr(odbc_call_gate, "_REPORTED", set())
    impl = object()
    with caplog.at_level("ERROR", logger=odbc_call_gate.log.name):
        assert raw_cursor(_aioodbc_shaped("Cursor", _impl=impl)) is impl
        assert raw_cursor(object()) is None
        assert raw_cursor(None) is None
        assert raw_cursor(_aioodbc_shaped("Cursor")) is None
        assert raw_cursor(_aioodbc_shaped("Cursor")) is None
    assert caplog.text.count("has no _impl") == 1, caplog.text


async def test_the_connector_close_reads_impl_through_the_gate_module(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """``_close_and_release`` reads the raw cursor through ``raw_cursor``, so an aioodbc cursor
    with no ``_impl`` is reported rather than closed through the fallback in silence. Red before
    #5005: the connector read ``cur._impl`` itself and logged nothing."""
    monkeypatch.setattr(odbc_call_gate, "_REPORTED", set())
    released: list[object] = []

    class _Pool:
        async def release(self, conn: object) -> None:
            released.append(conn)

    async def _close(self: object) -> None:
        return None

    conn = object()
    cur = _aioodbc_shaped("Cursor", close=_close)
    with caplog.at_level("ERROR", logger=odbc_call_gate.log.name):
        await database._close_and_release(_Pool(), conn, cur)
    assert released == [conn]
    assert "has no _impl" in caplog.text


async def test_the_store_pooled_cursor_reports_a_missing_impl_on_a_cancel(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The SQL Server store's pooled ``_cursor`` hands a cancelled cursor to the gate through the
    same ``raw_cursor``. An aioodbc cursor with no ``_impl`` falls back to its own close, and that
    is now reported, once. Red before #5005: it fell back in silence."""
    from messagefoundry.store.sqlserver import SqlServerStore

    monkeypatch.setattr(odbc_call_gate, "_REPORTED", set())
    closed: list[bool] = []

    async def _close(self: object) -> None:
        closed.append(True)

    cur = _aioodbc_shaped("Cursor", close=_close)

    class _Conn:
        async def cursor(self) -> Any:
            return cur

    store = SqlServerStore.__new__(SqlServerStore)
    with (
        caplog.at_level("ERROR", logger=odbc_call_gate.log.name),
        pytest.raises(asyncio.CancelledError),
    ):
        async with store._cursor(_Conn()):
            raise asyncio.CancelledError
    assert closed == [True]
    assert caplog.text.count("has no _impl") == 1, caplog.text


def test_aioodbc_is_pinned_to_the_release_the_gate_reads() -> None:
    """The gate and the connector read aioodbc 0.5.0's private names, so the extra pins that
    release exactly, and both locks resolve it. Moving the pin means re-reading those names."""
    with (_ROOT / "pyproject.toml").open("rb") as fh:
        extras = tomllib.load(fh)["project"]["optional-dependencies"]
    assert extras["sqlserver"] == ["aioodbc==0.5.0"]
    for lock in ("requirements.lock", "constraints.lock"):
        lines = (_ROOT / lock).read_text(encoding="utf-8").splitlines()
        assert [ln.split()[0] for ln in lines if ln.startswith("aioodbc==")] == ["aioodbc==0.5.0"]
