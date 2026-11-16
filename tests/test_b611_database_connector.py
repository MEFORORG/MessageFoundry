# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Batch 611, the DATABASE connector: BACKLOG #5749, #5748 and #5756.

* #5749: a ``cursor()`` the driver refuses on a borrowed connection is the connection's failure,
  before any statement ran. It is classified as a connect failure, so a transient outage retries
  instead of escaping unclassified.
* #5748: a connection-class failure (SQLSTATE class 08) discards the connection rather than
  returning it to its pool, so a dead handle is not lent again.
* #5756: every borrow applies a statement timeout, and each pool runs its driver calls on its own
  executor rather than the event loop's default one.

Each arm drives a real call site against the faked ``aioodbc`` of
``tests/test_backlog2394_database_gate.py``. Synthetic data only; no driver, no database.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor

import pytest

from messagefoundry.transports import database
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from tests._odbc_cancel_fakes import RawConn, RawCursor, never
from tests.test_backlog2394_database_gate import (
    _aioodbc_serving,
    _destination,
    _Rig,
    _source,
)
from tests.test_backlog5010_database_gate_discard import _WakingPool


class _DriverError(Exception):
    """A pyodbc-shaped driver error: the SQLSTATE in ``args[0]``."""


class _CursorRefused(RawConn):
    """A connection whose driver cannot allocate a statement handle."""

    state = "08S01"

    def cursor(self) -> RawCursor:
        self.note("cursor:refused")
        raise _DriverError(self.state, f"[{self.state}] the stand-in server refused a cursor")


class _BusyCursorRefused(_CursorRefused):
    state = "HY000"


class _LinkLostCursor(RawCursor):
    """A cursor whose statement fails with a communication-link failure (class 08)."""

    def execute(self, sql: str, *params: object) -> RawCursor:
        super().execute(sql, *params)
        raise _DriverError("08S01", "[08S01] communication link failure")


class _LinkLost(RawConn):
    """A connection whose statements fail with the link gone; its rollback still succeeds."""

    def cursor(self) -> RawCursor:
        cur = _LinkLostCursor(self)
        self.cursors.append(cur)
        return cur


class _Rejected(RawCursor):
    """A cursor whose statement the server rejects: a constraint violation, class 23."""

    def execute(self, sql: str, *params: object) -> RawCursor:
        super().execute(sql, *params)
        raise _DriverError("23000", "[23000] constraint violation")


class _RejectsStatement(RawConn):
    def cursor(self) -> RawCursor:
        cur = _Rejected(self)
        self.cursors.append(cur)
        return cur


@pytest.fixture
async def rig() -> AsyncIterator[_Rig]:
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="test-b611")
    r = _Rig(executor)
    r.release.set()  # nothing here blocks
    try:
        yield r
    finally:
        executor.shutdown(wait=True)


# --- BACKLOG #5749 -------------------------------------------------------------------------------


@pytest.mark.parametrize("raw_type", [_CursorRefused, _BusyCursorRefused])
async def test_a_refused_cursor_is_a_transient_connect_failure(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, raw_type: type[RawConn]
) -> None:
    """Red before #5749: the driver's own exception escaped send() unclassified, so the delivery
    worker read it as an internal error. A permanent state there (HY000) is retried too, since no
    statement ran, so no message can be at fault."""
    _aioodbc_serving(monkeypatch, rig, raw_type=raw_type, blocks=never)
    dest = _destination()
    with pytest.raises(DeliveryError) as caught:
        await dest.send('{"a": 1}')
    assert not isinstance(caught.value, NegativeAckError), caught.value
    assert "connect failed" in str(caught.value) or "transient" in str(caught.value)
    assert "execute:start" not in rig.log


async def test_a_cursor_failure_that_is_no_driver_error_still_propagates(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """A bug is not misread as a transport failure: with no SQLSTATE the exception is unchanged."""

    class _Bug(RawConn):
        def cursor(self) -> RawCursor:
            raise ZeroDivisionError("a bug")

    _aioodbc_serving(monkeypatch, rig, raw_type=_Bug, blocks=never)
    with pytest.raises(ZeroDivisionError):
        await _destination().send('{"a": 1}')


# --- BACKLOG #5748 -------------------------------------------------------------------------------


async def test_a_send_that_loses_its_link_discards_the_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The INSERT fails with 08S01 and the rollback passes. Red before #5748: the dead handle went
    back to the free list, for the next send to fail on the same way."""
    _aioodbc_serving(monkeypatch, rig, pool_type=_WakingPool, raw_type=_LinkLost, blocks=never)
    with pytest.raises(DeliveryError) as caught:
        await _destination().send('{"a": 1}')
    assert not isinstance(caught.value, NegativeAckError)
    pool = rig.pools[0]
    assert pool.returned and pool.free == [], "a connection whose link failed went back"
    assert rig.conn.closed and isinstance(pool, _WakingPool) and pool.wakes == 1


async def test_a_refused_cursor_of_class_08_discards_the_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    _aioodbc_serving(monkeypatch, rig, pool_type=_WakingPool, raw_type=_CursorRefused, blocks=never)
    with pytest.raises(DeliveryError):
        await _destination().send('{"a": 1}')
    assert rig.pools[0].free == [] and rig.conn.closed


async def test_a_statement_the_server_rejects_keeps_its_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The control: a class 23 rejection is the message's fault, and the connection is healthy."""
    _aioodbc_serving(monkeypatch, rig, raw_type=_RejectsStatement, blocks=never)
    with pytest.raises(NegativeAckError):
        await _destination().send('{"a": 1}')
    assert rig.pools[0].free == [rig.conn] and not rig.conn.closed


async def test_a_poll_that_loses_its_link_discards_the_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The source's borrow sites share the release, so a poll gets the same discard."""
    _aioodbc_serving(monkeypatch, rig, pool_type=_WakingPool, raw_type=_LinkLost, blocks=never)
    with pytest.raises(_DriverError):
        await _source()._select()
    assert rig.pools[0].free == [] and rig.conn.closed


async def test_the_login_role_probe_discards_a_connection_whose_link_failed(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The probe handles its failure before the release, so it passes the discard itself."""
    _aioodbc_serving(monkeypatch, rig, pool_type=_WakingPool, raw_type=_LinkLost, blocks=never)
    pool = await database._make_pool("DSN=x", 1, autocommit=False, login_timeout=5)
    reading = await database.probe_login_roles(pool, label="db_lookup:x", acquire_timeout=5.0)
    assert reading.verdict is database.LoginRoleVerdict.NOT_RUN
    assert rig.pools[0].free == [] and rig.conn.closed


def test_connection_lost_reads_the_chain_a_traceback_prints() -> None:
    link = _DriverError("08S01", "link")
    wrapped = DeliveryError("wrapped")
    wrapped.__cause__ = link
    assert database._connection_lost(wrapped)
    suppressed = DeliveryError("unrelated")
    suppressed.__context__ = link
    suppressed.__suppress_context__ = True
    assert not database._connection_lost(suppressed)
    assert not database._connection_lost(_DriverError("23000", "dup"))
    assert not database._connection_lost(None)
