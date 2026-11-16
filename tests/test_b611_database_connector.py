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

from messagefoundry.transports.base import DeliveryError, NegativeAckError
from tests._odbc_cancel_fakes import RawConn, RawCursor, never
from tests.test_backlog2394_database_gate import (
    _aioodbc_serving,
    _destination,
    _Rig,
)


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
