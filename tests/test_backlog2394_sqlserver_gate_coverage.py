# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2394 - the SQL Server call gate reaches the connections and cursor #2049 left ungated.

``tests/test_backlog2049_sqlserver_cancel_handle_free.py`` pins the gate on pooled connections. These
arms pin the paths that gate did not reach, with the same shared fakes
(``tests/_odbc_cancel_fakes.py``): a real thread pool, and raw stand-ins that record a use of a
freed handle instead of crashing on it.

* ``SqlServerStore._ensure_database_options`` opens its own autocommit connection before the pool
  exists, and fresh probe connections when its ALTER fails. A cancellation while a statement ran
  there reached ``conn.close()`` in a ``finally``, which freed the handles under the statement on
  another thread. It now exits like the pooled quarantine: the cursor goes to the gate, the
  connection is detached, and the cancellation does not wait for the statement.
* ``_assert_autocommit`` sets ``autocommit`` on the raw handle, a driver call, off the loop. A
  close beside it frees the handle under the set.
* ``SqlServerCoordinator._ensure_tables`` held a bare cursor on a gated connection. On a cancel it
  was never handed to the gate, and on the ordinary path it was never closed.

The live twin of the crash itself is the #2049 one in ``tests/test_sqlserver_store.py``; nothing
here needs a server.
"""

from __future__ import annotations

import asyncio
import gc
import sys
import threading
import types
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import pytest

import messagefoundry.store.sqlserver as sqlserver
from messagefoundry.config.settings import SchemaManagement, StoreBackend, StoreSettings
from messagefoundry.odbc_call_gate import call_gate, close_one_shot, install_call_gate
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator
from messagefoundry.store.sqlserver import SqlServerStore
from tests._odbc_cancel_fakes import (
    DEL_CLOSE,
    USE_AFTER_FREE,
    WAIT,
    AioConn,
    Pool,
    RawConn,
    bare_store,
    cancel_once_started,
    never,
    wait_for_entry,
    wait_until,
)

_STATE_READ = (
    "SELECT is_read_committed_snapshot_on, snapshot_isolation_state "
    "FROM sys.databases WHERE name = DB_NAME()"
)
_PROBE_READ = "SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name = DB_NAME()"
_ALTER_RCSI = "ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"


def _selects(sql: str) -> bool:
    return sql.startswith("SELECT")


def _settings() -> StoreSettings:
    # AUTO: the open-time probe runs only there (#305).
    return StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="localhost",
        database="mefor_test",
        username="sa",
        schema_management=SchemaManagement.AUTO,
    )


@dataclass
class _Rig:
    executor: ThreadPoolExecutor
    log: list[str] = field(default_factory=list)
    release: threading.Event = field(default_factory=threading.Event)
    started: threading.Event = field(default_factory=threading.Event)

    def raw(self, name: str = "", **kw: Any) -> RawConn:
        return RawConn(self.log, self.release, self.started, name=name, **kw)


@pytest.fixture
async def rig() -> AsyncIterator[_Rig]:
    # More than one worker, so a close submitted during a call CAN run beside it.
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-2394")
    r = _Rig(executor)
    try:
        yield r
    finally:
        r.release.set()  # never leave a worker parked if an arm failed early
        executor.shutdown(wait=True)


def _aioodbc_serving(
    monkeypatch: pytest.MonkeyPatch,
    rig: _Rig,
    raws: list[RawConn],
    *,
    keep: bool = False,
    gateable: bool = True,
) -> list[AioConn]:
    """Stand ``aioodbc`` in: each ``connect`` hands out the next of ``raws``, wrapped as aioodbc
    wraps it. With ``keep`` it returns the connections made. Without, it holds no reference, so the
    collector can reach them and run their aioodbc-shaped ``__del__``, as it could in a real open.
    ``gateable=False`` makes connections the gate cannot wrap."""
    made: list[AioConn] = []
    count = 0

    async def _connect(**kwargs: Any) -> AioConn:
        nonlocal count
        conn = AioConn(raws[count], rig.executor, gateable=gateable)
        count += 1
        if keep:
            made.append(conn)
        return conn

    module = types.ModuleType("aioodbc")
    module.connect = _connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    return made


async def _cancel_open_mid_call(rig: _Rig) -> None:
    """Cancel an open while its blocking driver call runs, and require the cancellation to
    propagate long before that call returns: a cancelled open must not wait on a statement that
    may be an ``ALTER DATABASE`` with no command timeout. Then run the collector, which may reach
    the abandoned connection while its statement still runs."""
    task = await cancel_once_started(
        rig.started, SqlServerStore._ensure_database_options(_settings())
    )
    done, _pending = await asyncio.wait({task}, timeout=1.0)
    assert done, "the cancellation waited for the running driver call"
    assert task.cancelled(), task
    # Drop the task, and with it the frames its cancellation keeps, so the abandoned connection is
    # garbage. A ``pytest.raises`` here would hold the traceback, and the collector would reach
    # nothing.
    del task, done
    gc.collect()


# --- the store's open-time connections -----------------------------------------------------------


async def test_a_cancelled_state_read_frees_nothing_until_it_returns(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The RCSI connection. Red before #2394: its close ran on another thread at once."""
    _aioodbc_serving(monkeypatch, rig, [rig.raw(blocks=_selects, rows={_STATE_READ: (1, 1)})])
    await _cancel_open_mid_call(rig)
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"
    assert not {"cursor.close", "conn.close", DEL_CLOSE} & set(rig.log), rig.log

    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")

    assert USE_AFTER_FREE not in rig.log, rig.log
    end = rig.log.index("execute:end")
    assert end < rig.log.index("cursor.close") < rig.log.index("conn.close"), rig.log


async def test_a_cancelled_autocommit_set_frees_nothing_until_it_returns(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """``_assert_autocommit``. Gating the connection is not enough here: the set must run through
    the gate too, or the detached close does not wait for it."""
    _aioodbc_serving(
        monkeypatch,
        rig,
        [rig.raw(blocks=never, rows={_STATE_READ: (1, 1)}, block_autocommit=True)],
    )
    await _cancel_open_mid_call(rig)
    assert "autocommit:end" not in rig.log, "the arm is vacuous: the set had already returned"
    assert not {"conn.close", DEL_CLOSE} & set(rig.log), rig.log

    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")

    assert USE_AFTER_FREE not in rig.log, rig.log
    assert rig.log.index("autocommit:end") < rig.log.index("conn.close"), rig.log
    assert "execute:start" not in rig.log, "the cancel landed after the set, so the arm is vacuous"


async def test_a_cancelled_reread_on_a_probe_frees_nothing_until_it_returns(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """``_rcsi_on_after_a_peer``'s fresh probe connection, reached when our ALTER fails."""
    main = rig.raw("main", blocks=never, rows={_STATE_READ: (0, 1)}, fails=frozenset({_ALTER_RCSI}))
    probe = rig.raw("probe", blocks=_selects, rows={_PROBE_READ: (1,)})
    _aioodbc_serving(monkeypatch, rig, [main, probe])
    await _cancel_open_mid_call(rig)
    assert "probe:execute:start" in rig.log, "the arm is vacuous: the cancel missed the probe"
    assert "probe:execute:end" not in rig.log, "the arm is vacuous: the read had already returned"
    early = {"probe:cursor.close", "probe:conn.close", f"probe:{DEL_CLOSE}"}
    assert not early & set(rig.log), rig.log

    rig.release.set()
    await wait_for_entry(rig.log, "probe:conn.close")
    await wait_for_entry(rig.log, "main:conn.close")

    assert USE_AFTER_FREE not in rig.log, rig.log
    end = rig.log.index("probe:execute:end")
    assert end < rig.log.index("probe:cursor.close") < rig.log.index("probe:conn.close"), rig.log


async def test_a_cancel_during_the_cursor_close_still_leaves_through_the_gate(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The cleanup itself can be cancelled: shutdown cancels the open once its check is done and
    its cursor close is running. The connection must still go to the gate, not to the collector."""
    _aioodbc_serving(
        monkeypatch,
        rig,
        [rig.raw(blocks=never, rows={_STATE_READ: (1, 1)}, block_cursor_close=True)],
    )
    await _cancel_open_mid_call(rig)
    assert "cursor.close:start" in rig.log, "the arm is vacuous: the cancel missed the close"
    assert not {"cursor.close", "conn.close", DEL_CLOSE} & set(rig.log), rig.log

    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")

    assert USE_AFTER_FREE not in rig.log, rig.log
    assert rig.log.index("cursor.close") < rig.log.index("conn.close"), rig.log
    # The defect this pins: the cancel handed the cursor whose close was running to the
    # gate as well, so the gate closed it a second time.
    assert rig.log.count("cursor.close") == 1, rig.log


async def test_a_cancel_during_the_connection_close_closes_it_once(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """A cancel while the connection's close runs. The close goes on, and nothing closes the
    handle a second time, through the gate or through aioodbc's ``__del__``."""
    _aioodbc_serving(
        monkeypatch,
        rig,
        [rig.raw(blocks=never, rows={_STATE_READ: (1, 1)}, block_conn_close=True)],
    )
    await _cancel_open_mid_call(rig)
    assert "conn.close:start" in rig.log, "the arm is vacuous: the cancel missed the close"
    assert not {"conn.close", DEL_CLOSE} & set(rig.log), rig.log

    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")
    gc.collect()

    assert USE_AFTER_FREE not in rig.log, rig.log
    assert DEL_CLOSE not in rig.log, rig.log
    assert rig.log.count("conn.close") == 1, rig.log
    assert rig.log.index("cursor.close") < rig.log.index("conn.close:start"), rig.log


class _CountingExecutor(ThreadPoolExecutor):
    """Counts submissions, so an arm can cancel once a close is queued behind a busy worker."""

    def __init__(self) -> None:
        super().__init__(max_workers=1, thread_name_prefix="test-2394-one")
        self.submits = 0

    def submit(self, fn: Any, /, *args: Any, **kwargs: Any) -> Any:
        future = super().submit(fn, *args, **kwargs)
        self.submits += 1  # run_in_executor submits from the loop's thread, so no race
        return future


async def test_a_cancel_while_the_connection_close_waits_for_a_worker_still_closes_it() -> None:
    """A cancel while the close is queued and not yet running. The defect this pins: the
    cancel also cancelled the queued close, so it never ran, and the handle the exit dropped was
    left to pyodbc's collector, outside the gate."""
    executor = _CountingExecutor()
    busy = threading.Event()
    log: list[str] = []
    try:
        executor.submit(busy.wait, WAIT)  # the one worker is taken, so the close queues
        conn = AioConn(RawConn(log, threading.Event(), threading.Event()), executor)
        install_call_gate(conn)
        task = asyncio.create_task(close_one_shot(conn, None))
        assert await wait_until(lambda: executor.submits >= 2), "the close was never submitted"
        task.cancel()
        done, _pending = await asyncio.wait({task}, timeout=1.0)
        assert done, "the cancellation waited for the queued close"
        assert task.cancelled(), task
        assert "conn.close" not in log, "the arm is vacuous: the close had already run"

        busy.set()
        await wait_for_entry(log, "conn.close")
        del task, done, conn
        gc.collect()

        assert log == ["conn.close"], log
    finally:
        busy.set()
        executor.shutdown(wait=True)


async def test_a_cancel_during_an_ungated_cursor_close_closes_the_connection_after_it(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """A connection the gate could not wrap. The defect this pins: the cancel left the
    connection to aioodbc's ``__del__``, which closed it on the collector's thread while the
    cursor's close still ran."""
    _aioodbc_serving(
        monkeypatch,
        rig,
        [rig.raw(blocks=never, rows={_STATE_READ: (1, 1)}, block_cursor_close=True)],
        gateable=False,
    )
    await _cancel_open_mid_call(rig)
    assert "cursor.close:start" in rig.log, "the arm is vacuous: the cancel missed the close"
    assert not {"cursor.close", "conn.close", DEL_CLOSE} & set(rig.log), rig.log

    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")

    assert USE_AFTER_FREE not in rig.log, rig.log
    assert rig.log.index("cursor.close") < rig.log.index("conn.close"), rig.log
    assert rig.log.count("conn.close") == 1, rig.log


async def test_an_ordinary_open_gates_every_connection_it_makes(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The control. With no cancellation both connections are gated, put into autocommit, read,
    and closed cursor first, so the arms above cannot pass on a path that never ran."""
    rig.release.set()
    main = rig.raw("main", blocks=never, rows={_STATE_READ: (0, 1)}, fails=frozenset({_ALTER_RCSI}))
    probe = rig.raw("probe", blocks=never, rows={_PROBE_READ: (1,)})
    made = _aioodbc_serving(monkeypatch, rig, [main, probe], keep=True)

    await SqlServerStore._ensure_database_options(_settings())

    assert len(made) == 2
    assert all(call_gate(conn) is not None for conn in made)
    assert main.closed and probe.closed and main.autocommit
    for name in ("main", "probe"):
        assert rig.log.index(f"{name}:cursor.close") < rig.log.index(f"{name}:conn.close"), rig.log
    assert USE_AFTER_FREE not in rig.log, rig.log


# --- the cluster coordinator's table setup -------------------------------------------------------


def _cluster_store(rig: _Rig, raw: RawConn) -> tuple[SqlServerStore, Pool]:
    pool = Pool(AioConn(raw, rig.executor))
    return bare_store(pool), pool


def _first_select(sql: str) -> bool:
    return sql == "SELECT 1"


async def test_a_cancelled_cluster_table_setup_hands_its_cursor_to_the_gate(rig: _Rig) -> None:
    """Red before #2394: the bare cursor was never abandoned to the gate, so the quarantine closed
    the connection with no explicit close of the cursor ahead of it."""
    store, pool = _cluster_store(rig, rig.raw(blocks=_first_select))
    coordinator = SqlServerCoordinator(store, "N")
    task = await cancel_once_started(rig.started, coordinator._ensure_tables())
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, WAIT)  # the cancel does not wait for the statement
    assert "execute:end" not in rig.log, "the arm is vacuous: the statement had already returned"
    assert "cursor.close" not in rig.log and "conn.close" not in rig.log, rig.log

    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")

    assert USE_AFTER_FREE not in rig.log, rig.log
    assert "cursor.close" in rig.log, f"the cursor was not handed to the gate ({rig.log})"
    end = rig.log.index("execute:end")
    assert end < rig.log.index("cursor.close") < rig.log.index("conn.close"), rig.log
    assert pool.free == [], "the quarantine regressed: the connection went back to the pool"


async def test_an_ordinary_cluster_table_setup_closes_its_cursor_before_release(
    rig: _Rig,
) -> None:
    """The control, and the EF-6 half: the cursor closes after the commit and before the
    connection goes back to the pool, which the bare cursor never did."""
    rig.release.set()
    store, pool = _cluster_store(rig, rig.raw(blocks=never, rows={sqlserver._SQL_APPLOCK: (0,)}))

    await SqlServerCoordinator(store, "N")._ensure_tables()

    assert rig.log.index("commit") < rig.log.index("cursor.close"), rig.log
    assert "conn.close" not in rig.log
    assert pool.free == [pool._conn]
