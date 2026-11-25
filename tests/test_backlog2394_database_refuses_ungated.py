# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2394 step 1 - the DATABASE connector refuses a real aioodbc connection the call gate
cannot wrap, before any pyodbc call runs on it.

Before, the connector borrowed such a connection ungated. On a cancellation its exits then dropped
the handles unclosed (``_close_and_release``), so pyodbc freed them, with a rollback and a
disconnect, wherever the last reference dropped, which could be the event loop thread. Both borrow
sites, ``_acquire`` and the autocommit pool's ``_acquire_confirmed``, now run
``require_call_gate`` first and discard a refused connection while nothing runs on it, as the SQL
Server store does (``tests/test_backlog2394_store_refuses_ungated.py``).

Under the ``aioodbc==0.5.0`` pin (BACKLOG #5005) no real connection is ungated, so the fakes stand
in for one by naming an ``aioodbc`` module. A stand-in the gate cannot wrap is still not refused;
``tests/test_backlog2394_database_gate.py`` pins its cancel exit. Synthetic data only; no driver,
no database.
"""

from __future__ import annotations

import ast
import asyncio
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.odbc_call_gate import UngatedConnectionError, call_gate
from messagefoundry.transports import database
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.database import DatabaseDestination
from tests import test_backlog2394_store_refuses_ungated as _store_arms
from tests._odbc_cancel_fakes import (
    AioConn,
    cancel_once_started,
    cancelled_at_once,
    wait_for_entry,
    wait_until,
)
from tests.test_backlog2394_store_refuses_ungated import (
    _closed_once_and_never_used,
    _direct_calls,
    _RealAioConn,
    _RenamedHandleConn,
    _Rig,
)
from tests.test_backlog5010_database_gate_discard import _WakingPool

rig = _store_arms.rig  # the store arms' fixture: a fresh executor, and the ERROR log reset


async def test_only_a_real_connection_the_gate_cannot_wrap_is_refused(rig: _Rig) -> None:
    """The control for every arm below: ``_acquire`` lends a real connection the gate can wrap,
    gated, and a stand-in it cannot wrap, ungated; neither is closed."""
    gateable = _RealAioConn(rig.raw(), rig.executor)
    assert await database._acquire(_WakingPool(gateable), 1.0) is gateable
    assert call_gate(gateable) is not None

    stand_in = AioConn(rig.raw(), rig.executor, gateable=False)
    assert await database._acquire(_WakingPool(stand_in), 1.0) is stand_in
    assert call_gate(stand_in) is None
    assert not gateable.closed and not stand_in.closed and "conn.close" not in rig.log


async def test_a_borrow_refuses_an_ungated_connection_and_closes_it(
    rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """``_acquire``, the destination's, the source's, the lookup's and the login role probe's
    borrow. Red before step 1: it lent the ungated connection."""
    conn = rig.ungated()
    pool = _WakingPool(conn)
    with (
        caplog.at_level("ERROR", logger="messagefoundry.odbc_call_gate"),
        pytest.raises(UngatedConnectionError),
    ):
        await database._acquire(pool, 1.0)
    assert conn.closed and pool.free == [], "the refused connection is lendable again"
    assert pool.wakes == 1, "the pool was not woken for the freed slot"
    assert "has no bound _execute" in caplog.text
    await _closed_once_and_never_used(rig)


async def test_an_autocommit_borrow_refuses_before_its_autocommit_set(rig: _Rig) -> None:
    """``_AutocommitPool._acquire_confirmed``, which a ``DatabaseRef`` sync borrows through. Red
    before step 1: the autocommit set, a driver call, ran on the ungated connection."""
    conn = rig.ungated()
    inner = _WakingPool(conn)
    pool = database._AutocommitPool(inner)
    with pytest.raises(UngatedConnectionError):
        await pool.acquire()
    assert conn.closed and inner.free == [], "the refused connection is lendable again"
    await _closed_once_and_never_used(rig)


async def test_a_send_on_a_refused_connection_fails_as_a_permanent_config_fault(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """End to end through a destination send: the refusal surfaces as a permanent
    ``config_fault``, which stops the lane rather than retrying a login every borrow refuses
    (BACKLOG #2394 added item 2), and no statement ran. Red before: a transient
    ``DeliveryError``."""
    conn = rig.ungated()

    async def create_pool(**kwargs: Any) -> _WakingPool:
        return _WakingPool(conn)

    module = types.ModuleType("aioodbc")
    module.create_pool = create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    monkeypatch.setitem(sys.modules, "pyodbc", None)  # the #2049 pooling guard becomes a no-op
    destination = DatabaseDestination(
        Destination(
            name="OB_DB",
            type=ConnectorType.DATABASE,
            settings={
                "server": "db.example",
                "database": "d",
                "statement": "INSERT INTO t (a) VALUES (:a)",
            },
        )
    )
    with pytest.raises(NegativeAckError) as raised:
        await destination.send('{"a": 1}')
    assert raised.value.permanent and raised.value.config_fault, raised.value
    assert isinstance(raised.value.__cause__, UngatedConnectionError)
    assert "db.example" not in str(raised.value)
    await _closed_once_and_never_used(rig)


async def test_a_refusal_does_not_wait_for_the_close_it_starts(rig: _Rig) -> None:
    """The refused connection's handle is dropped at once and closed on a worker thread, and the
    borrow fails without waiting for that close, so a slow disconnect or a busy executor does not
    hold it past its ``acquire_timeout``. The close still runs, once."""
    conn = rig.ungated(block_conn_close=True)
    pool = _WakingPool(conn)
    with pytest.raises(UngatedConnectionError):
        await asyncio.wait_for(database._acquire(pool, 1.0), 1.0)
    assert await asyncio.to_thread(rig.started.wait, 1.0), "the arm is vacuous: no close started"
    assert "conn.close" not in rig.log, "the arm is vacuous: the close was not held"
    assert conn.closed and pool.free == [], "the refused connection is lendable again"
    await _closed_once_and_never_used(rig)


async def test_a_refused_renamed_handle_is_closed_through_its_own_close(rig: _Rig) -> None:
    raw = rig.raw()
    conn = _RenamedHandleConn(raw, rig.executor)
    pool = _WakingPool(conn)
    with pytest.raises(UngatedConnectionError):
        await database._acquire(pool, 1.0)
    assert conn.closed and pool.free == [], "the refused connection is lendable again"
    assert raw.closed and not raw.cursors, rig.log


async def test_a_cancelled_renamed_handle_close_keeps_it_out_of_the_pool_until_it_returns(
    rig: _Rig,
) -> None:
    """A cancellation during that close propagates at once, and the connection, which still reads
    open, goes back only once its close has returned, so neither a later borrow nor the pool's
    own close can close it a second time beside the first."""
    raw = rig.raw(block_conn_close=True)
    conn = _RenamedHandleConn(raw, rig.executor)
    pool = _WakingPool(conn)
    task = await cancel_once_started(rig.started, database._acquire(pool, 1.0))
    await cancelled_at_once(task)
    assert "conn.close:start" in rig.log, "the arm is vacuous: the cancel missed the close"
    assert not conn.closed and not pool.returned, "it went back while its close ran"
    rig.release.set()
    await wait_for_entry(rig.log, "conn.close")
    assert await wait_until(lambda: pool.returned), "it never went back"
    assert conn.closed and pool.free == [], rig.log
    assert rig.log.count("conn.close:start") == 1 and rig.log.count("conn.close") == 1, rig.log
    # Held back while its close ran, so a pool close stopped at its bound; no longer once back.
    assert await wait_until(lambda: not database._holds_back(pool)), "still counted held back"


def test_every_database_borrow_requires_the_gate() -> None:
    """The refusal holds only while every way a pooled connection enters the connector requires
    the gate. At least a new ``.acquire()`` call outside the two borrow sites, a borrow site that
    does not refuse, a bare ``install_call_gate`` call and a pool made outside ``_make_pool`` fail
    here rather than run ungated. It does not check that the gate comes before the first call, nor
    that a caller hands ``acquire_pooled`` an autocommit pool, as ``reference_sync`` does."""
    source = Path(database.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert "from aioodbc import" not in source  # every pool reads as `aioodbc.create_pool`
    defs = [
        (node.name, _direct_calls(node))
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    names = [name for name, _ in defs]
    funcs = dict(defs)
    borrows = sorted(name for name, calls in defs if "acquire" in calls)
    # The control: the pin sees the two borrow sites, so it is not vacuous.
    assert borrows == ["_acquire", "_acquire_confirmed"]
    for name in [*borrows, "_make_pool", "_require_gate_or_discard"]:
        assert names.count(name) == 1, f"{name} is defined twice, so the pin reads only one"
    for name in borrows:
        assert "_require_gate_or_discard" in funcs[name], name
    assert "require_call_gate" in funcs["_require_gate_or_discard"]
    assert not [n for n, calls in defs if "install_call_gate" in calls]
    assert sorted(n for n, calls in defs if "aioodbc.create_pool" in calls) == ["_make_pool"]
    assert not [n for n, calls in defs if "aioodbc.connect" in calls]
    assert not [n for n, calls in defs if "acquire_pooled" in calls]
