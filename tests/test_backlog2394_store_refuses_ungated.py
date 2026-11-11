# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2394 step 2 - the SQL Server store refuses a real aioodbc connection the call gate
cannot wrap, before any pyodbc call runs on it.

An ungated connection has no safe cancellation exit. With no gate, nothing can wait for the running
call, so closing its handles frees them under that call (the #2049 native-crash class), and leaving
them unclosed frees them wherever the last reference drops. Before this step the store's pooled
quarantine, its ``_cursor`` helper, its open-time connections and its claim connections all took
the first of those on such a connection. Now each place that opens or borrows one runs
``require_call_gate`` before its first call, and on a refusal discards the connection while nothing
runs on it, so every later exit may take a real connection as gated.

Each path gets a refusal arm and a cancel arm, with the shared fakes of
``tests/_odbc_cancel_fakes.py``. Under the ``aioodbc==0.5.0`` pin (BACKLOG #5005) no real connection
is ungated, so the fakes stand in for one by naming an ``aioodbc`` module. A stand-in the gate cannot
wrap is still not refused; ``tests/test_backlog2394_sqlserver_gate_coverage.py`` pins its exits.
Nothing here needs a server or aioodbc.
"""

from __future__ import annotations

import ast
import asyncio
import gc
import sys
import threading
import types
from collections.abc import AsyncIterator, Callable, Coroutine
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.store.sqlserver as sqlserver
from messagefoundry import odbc_call_gate
from messagefoundry.config.settings import SchemaManagement, StoreBackend, StoreSettings
from messagefoundry.odbc_call_gate import UngatedConnectionError, call_gate, require_call_gate
from messagefoundry.store.sqlserver import SqlServerStore
from tests._odbc_cancel_fakes import (
    DEL_CLOSE,
    USE_AFTER_FREE,
    AioConn,
    Pool,
    RawConn,
    bare_store,
    cancel_once_started,
    cancelled_at_once,
    never,
    wait_for_entry,
)

_STATE_READ = (
    "SELECT is_read_committed_snapshot_on, snapshot_isolation_state "
    "FROM sys.databases WHERE name = DB_NAME()"
)
_ALTER_RCSI = "ALTER DATABASE CURRENT SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"


class _RealAioConn(AioConn):
    """An ``AioConn`` that reads as a real aioodbc connection, as the gate tells one apart."""

    __module__ = "aioodbc.connection"


@dataclass
class _Rig:
    executor: ThreadPoolExecutor
    log: list[str] = field(default_factory=list)
    release: threading.Event = field(default_factory=threading.Event)
    started: threading.Event = field(default_factory=threading.Event)
    refused: list[RawConn] = field(default_factory=list)

    def raw(self, name: str = "", **kw: Any) -> RawConn:
        return RawConn(self.log, self.release, self.started, name=name, blocks=never, **kw)

    def ungated(self, name: str = "", **kw: Any) -> AioConn:
        """A real aioodbc connection the gate cannot wrap."""
        raw = self.raw(name, **kw)
        self.refused.append(raw)
        return _RealAioConn(raw, self.executor, gateable=False)


@pytest.fixture
async def rig(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[_Rig]:
    # Logged once per process for each type (BACKLOG #5005): start each arm with nothing reported.
    monkeypatch.setattr(odbc_call_gate, "_REPORTED", set())
    # More than one worker, so a close submitted during a call CAN run beside it.
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-2394r")
    r = _Rig(executor)
    try:
        yield r
    finally:
        r.release.set()  # never leave a worker parked if an arm failed early
        executor.shutdown(wait=True)


async def _closed_once_and_never_used(rig: _Rig, entry: str = "conn.close") -> None:
    """Let any held close return, then require the refused connection to have closed once, with
    no driver call run on it first and nothing left for aioodbc's ``__del__``."""
    rig.release.set()
    await wait_for_entry(rig.log, entry)
    gc.collect()
    assert rig.log.count(entry) == 1, rig.log
    assert USE_AFTER_FREE not in rig.log, rig.log
    assert not any(e.endswith(DEL_CLOSE) for e in rig.log), rig.log
    for raw in rig.refused:  # no cursor, no statement and no autocommit set ever reached one
        assert not raw.cursors and not raw.autocommit, rig.log


async def _cancel_mid_close(
    rig: _Rig, coro: Any, entry: str = "conn.close", forget: Callable[[], None] = lambda: None
) -> None:
    """Cancel ``coro`` once the refused connection's held close has started. The cancellation
    must propagate at once, and the close must still finish, once. ``forget`` drops the test's
    own references, so the collector can reach the connection."""
    task = await cancel_once_started(rig.started, coro)
    await cancelled_at_once(task)
    assert f"{entry}:start" in rig.log, "the arm is vacuous: the cancel missed the close"
    assert entry not in rig.log, rig.log
    del task
    forget()
    await _closed_once_and_never_used(rig, entry)


# --- the helper ----------------------------------------------------------------------------------


async def test_require_call_gate_refuses_only_a_real_connection_it_cannot_wrap(rig: _Rig) -> None:
    """The control for every arm below: a real connection the gate can wrap is gated, a stand-in
    it cannot wrap is left alone, and only a real one it cannot wrap is refused."""
    gateable = _RealAioConn(rig.raw(), rig.executor)
    require_call_gate(gateable)
    assert call_gate(gateable) is not None

    stand_in = AioConn(rig.raw(), rig.executor, gateable=False)
    require_call_gate(stand_in)
    assert call_gate(stand_in) is None

    with pytest.raises(UngatedConnectionError, match="_RealAioConn cannot be wrapped"):
        require_call_gate(rig.ungated())


# --- the pooled borrow ---------------------------------------------------------------------------


async def test_a_pooled_borrow_refuses_an_ungated_connection_and_drops_it(
    rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """``_borrow``. Red before step 2: the borrow lent the ungated connection, so a cancelled call
    on it reached ``_release_dirty``, whose detach closed it beside the running statement."""
    conn = rig.ungated()
    pool = Pool(conn)
    store = bare_store(pool)
    entered = False
    with (
        caplog.at_level("ERROR", logger="messagefoundry.odbc_call_gate"),
        pytest.raises(UngatedConnectionError),
    ):
        async with store._acquire():
            entered = True
    assert not entered, "the body ran on an ungated connection"
    assert conn.closed and pool.free == [], "the refused connection is lendable again"
    assert "has no bound _execute" in caplog.text
    await _closed_once_and_never_used(rig)


async def test_a_cancel_during_a_refused_borrows_release_still_never_lends_it(
    rig: _Rig,
) -> None:
    """A cancellation that lands in the release after the refusal, as a shutdown's second one
    can. The connection is already detached, so the pool still never gets it back, and its close
    still runs once."""
    conn = rig.ungated()
    pool = Pool(conn)
    pool.hold = asyncio.Event()
    store = bare_store(pool)

    async def borrow() -> None:
        async with store._acquire():
            raise AssertionError("the body ran on an ungated connection")

    task = asyncio.create_task(borrow())
    await asyncio.wait_for(pool.in_release.wait(), 1.0)
    task.cancel()
    await cancelled_at_once(task)
    # The cancel landed before the fake release read `closed`, so `free` alone proves nothing
    # here; `closed` is what that read, aioodbc's own rule, would have found.
    assert conn.closed, "the refused connection was not detached before its release"
    await _closed_once_and_never_used(rig)


class _RenamedHandleConn(_RealAioConn):
    """A real connection from an aioodbc that renamed ``_conn`` as well as ``_execute``."""

    __module__ = "aioodbc.connection"  # a class's own: a subclass never inherits it

    def __init__(self, raw: RawConn, executor: ThreadPoolExecutor) -> None:
        super().__init__(raw, executor, gateable=False)
        self._handle: RawConn | None = self._conn
        self._conn = None

    @property
    def closed(self) -> bool:
        return self._handle is None

    async def close(self) -> None:
        raw, self._handle = self._handle, None
        if raw is not None:
            await self._loop.run_in_executor(self._executor, raw.close)


async def test_a_refused_borrow_with_a_renamed_handle_is_closed_through_its_own_close(
    rig: _Rig,
) -> None:
    """Round 1 of this step's review: the detach reads ``_conn``, so a connection without one was
    put back on the free list open, refused again on every borrow."""
    raw = rig.raw()
    conn = _RenamedHandleConn(raw, rig.executor)
    pool = Pool(conn)
    with pytest.raises(UngatedConnectionError):
        async with bare_store(pool)._acquire():
            raise AssertionError("the body ran on an ungated connection")
    assert conn.closed and pool.free == [], "the refused connection is lendable again"
    assert raw.closed and not raw.cursors, rig.log


# --- the claim connection ------------------------------------------------------------------------


def _claim_store(rig: _Rig, conns: list[AioConn], **raw_kw: Any) -> SqlServerStore:
    """A store with only what the claim holder reads, whose dedicated connections are ungated."""
    store = bare_store(Pool(rig.ungated("pool")))
    store._claim_holders = {}
    store._claim_holders_closed = False
    store._claim_holders_open = 0
    store._claim_holders_opened_total = 0
    store._claim_holders_discarded_total = 0

    async def connect() -> AioConn:
        conn = rig.ungated(**raw_kw)
        conns.append(conn)
        return conn

    store._connect_claim_conn = connect  # type: ignore[method-assign]
    return store


async def test_a_claim_holder_open_refuses_an_ungated_connection_and_closes_it(
    rig: _Rig,
) -> None:
    """``_open_claim_holder``. Red before step 2: the holder kept the ungated connection, and the
    discard after a cancelled claim closed it beside the running claim statement."""
    conns: list[AioConn] = []
    store = _claim_store(rig, conns)
    with pytest.raises(UngatedConnectionError):
        await store._open_claim_holder("ingress")
    assert conns and conns[0].closed
    assert store._claim_holders_open == 0 and store._claim_holders_opened_total == 0
    conns.clear()
    await _closed_once_and_never_used(rig)


async def test_a_cancel_during_a_refused_claim_connections_close_does_not_wait(
    rig: _Rig,
) -> None:
    """A cancellation while the refused claim connection's close runs propagates at once, and the
    close goes on: once, and never through aioodbc's ``__del__``."""
    conns: list[AioConn] = []
    store = _claim_store(rig, conns, block_conn_close=True)
    await _cancel_mid_close(rig, store._open_claim_holder("ingress"), forget=conns.clear)


# --- the open-time connections -------------------------------------------------------------------


def _settings() -> StoreSettings:
    # AUTO: the open-time probe runs only there (#305).
    return StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="localhost",
        database="mefor_test",
        username="sa",
        schema_management=SchemaManagement.AUTO,
    )


def _aioodbc_serving(monkeypatch: pytest.MonkeyPatch, conns: list[AioConn]) -> None:
    """Stand ``aioodbc`` in: each ``connect`` hands out the next of ``conns``."""
    queue = list(conns)

    async def _connect(**kwargs: Any) -> AioConn:
        return queue.pop(0)

    module = types.ModuleType("aioodbc")
    module.connect = _connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)


def _open() -> Coroutine[Any, Any, None]:
    return SqlServerStore._ensure_database_options(_settings())


async def test_the_rcsi_connection_refuses_an_ungated_connection_and_closes_it(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """``_ensure_database_options``' own connection. Red before step 2: a cancelled state read
    or ``ALTER`` on it closed the connection beside the running statement. The open now fails
    with the refusal itself, not a message about RCSI."""
    _aioodbc_serving(monkeypatch, [rig.ungated(rows={_STATE_READ: (1, 1)})])
    with pytest.raises(UngatedConnectionError):
        await _open()
    await _closed_once_and_never_used(rig)


async def test_a_cancel_during_the_refused_rcsi_connections_close_does_not_wait(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    _aioodbc_serving(monkeypatch, [rig.ungated(block_conn_close=True)])
    await _cancel_mid_close(rig, _open())


def _gated_main(rig: _Rig, **kw: Any) -> AioConn:
    """The open's own connection, gated, with RCSI off and an ``ALTER`` that fails, so the open
    reaches the re-read on a fresh probe connection."""
    raw = rig.raw("main", rows={_STATE_READ: (0, 1)}, fails=frozenset({_ALTER_RCSI}), **kw)
    return _RealAioConn(raw, rig.executor)


async def test_the_rcsi_reread_refuses_an_ungated_probe_and_the_open_says_so(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """``_rcsi_on_after_a_peer``'s probe. Red before step 2: a cancelled re-read closed the probe
    beside its running statement. The refusal is not read as an unreadable state, which would
    report RCSI off and hide the cause."""
    _aioodbc_serving(monkeypatch, [_gated_main(rig), rig.ungated("probe")])
    with pytest.raises(UngatedConnectionError):
        await _open()
    await _closed_once_and_never_used(rig, "probe:conn.close")
    await wait_for_entry(rig.log, "main:conn.close")


async def test_a_cancel_during_the_refused_probes_close_does_not_wait(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    _aioodbc_serving(monkeypatch, [_gated_main(rig), rig.ungated("probe", block_conn_close=True)])
    await _cancel_mid_close(rig, _open(), "probe:conn.close")
    await wait_for_entry(rig.log, "main:conn.close")


# --- the source pin ------------------------------------------------------------------------------


def _direct_calls(func: ast.AST) -> list[str]:
    """The dotted names ``func`` calls in its own body, not in a function nested inside it."""
    names: list[str] = []
    pending = list(ast.iter_child_nodes(func))
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Attribute):
                names.append(target.attr)  # `self._connect_claim_conn()` reads as its method
                if isinstance(target.value, ast.Name):
                    names.append(f"{target.value.id}.{target.attr}")
            elif isinstance(target, ast.Name):
                names.append(target.id)
        pending.extend(ast.iter_child_nodes(node))
    return names


def test_every_store_connect_requires_the_gate() -> None:
    """The refusal holds only while every way a real connection enters the store requires the
    gate. A new ``aioodbc.connect`` in a function that does not, or a second pooled borrow beside
    ``_borrow``, fails here rather than run ungated."""
    tree = ast.parse(Path(sqlserver.__file__).read_text(encoding="utf-8"))
    funcs = {
        node.name: _direct_calls(node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    connects = sorted(name for name, calls in funcs.items() if "aioodbc.connect" in calls)
    # The control: the pin sees the three connect sites this step gated, so it is not vacuous.
    assert connects == ["_connect_claim_conn", "_ensure_database_options", "_rcsi_on_after_a_peer"]
    for name in connects:
        if name == "_connect_claim_conn":  # a seam the tests replace; its one caller gates
            continue
        assert "_require_call_gate" in funcs[name], name
    claim_openers = [n for n, calls in funcs.items() if "_connect_claim_conn" in calls]
    assert claim_openers == ["_open_claim_holder"]
    assert "_require_call_gate" in funcs["_open_claim_holder"]
    assert [n for n, calls in funcs.items() if "acquire_pooled" in calls] == ["_borrow"]
    assert "_gate_or_discard" in funcs["_borrow"]
