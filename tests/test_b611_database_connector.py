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

import sys
import types
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from messagefoundry.config.models import DEFAULT_DB_STATEMENT_TIMEOUT, ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.transports import database
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.database import DatabaseDestination
from tests._fake_dbapi_driver import DriverError
from tests._odbc_cancel_fakes import RawConn, RawCursor, never
from tests.test_backlog2394_database_gate import (
    _SQLSERVER,
    _aioodbc_serving,
    _destination,
    _Rig,
    _source,
)
from tests.test_backlog5010_database_gate_discard import _WakingPool


class _DriverError(DriverError):
    """A pyodbc-shaped driver error: the SQLSTATE in ``args[0]``, from a driver's module."""


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


@pytest.mark.parametrize("raw_type", [_CursorRefused, _BusyCursorRefused])
async def test_a_refused_cursor_discards_the_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, raw_type: type[RawConn]
) -> None:
    """A handle that cannot make a cursor is not lent again, whatever its SQLSTATE class."""
    _aioodbc_serving(monkeypatch, rig, pool_type=_WakingPool, raw_type=raw_type, blocks=never)
    with pytest.raises(DeliveryError):
        await _destination().send('{"a": 1}')
    assert rig.pools[0].free == [] and rig.conn.closed


class _NoQueryTimeout(_CursorRefused):
    state = "HYC00"


async def test_a_driver_refusing_the_query_timeout_stops_the_lane(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """A static driver-capability fault is a config_fault naming the setting, not a retry."""
    _aioodbc_serving(monkeypatch, rig, raw_type=_NoQueryTimeout, blocks=never)
    with pytest.raises(NegativeAckError) as caught:
        await _destination().send('{"a": 1}')
    assert caught.value.config_fault and "statement_timeout" in str(caught.value)


async def test_the_connection_test_classifies_a_refused_cursor_as_send_does(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_BusyCursorRefused, blocks=never
    )
    with pytest.raises(DeliveryError) as caught:
        await _destination().test_connection()
    assert not isinstance(caught.value, NegativeAckError)
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


# --- BACKLOG #5756 -------------------------------------------------------------------------------


def _recording_kwargs(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Wrap the faked ``aioodbc.create_pool`` so each call's arguments are recorded."""
    module = sys.modules["aioodbc"]
    inner = module.create_pool
    calls: list[dict[str, Any]] = []

    async def create_pool(**kwargs: Any) -> Any:
        calls.append(kwargs)
        return await inner(**kwargs)

    monkeypatch.setattr(module, "create_pool", create_pool)
    return calls


def _with(settings: dict[str, Any]) -> DatabaseDestination:
    return DatabaseDestination(
        Destination(
            name="OB_DB",
            type=ConnectorType.DATABASE,
            settings={**_SQLSERVER, "statement": "INSERT INTO t (a) VALUES (:a)", **settings},
        )
    )


@pytest.mark.parametrize(("settings", "expected"), [({}, 30), ({"statement_timeout": 7}, 7)])
async def test_a_send_borrows_with_the_statement_timeout(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, settings: dict[str, Any], expected: int
) -> None:
    """Red before #5756: the pyodbc connection's timeout stayed 0, so a hung statement held its
    connection, its lane and any stop without bound."""
    _aioodbc_serving(monkeypatch, rig, blocks=never)
    await _with(settings).send('{"a": 1}')
    raw = rig.pools[0]._conn._conn
    assert raw is not None and raw.timeout == expected


async def test_a_statement_timeout_of_zero_sets_no_limit(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    _aioodbc_serving(monkeypatch, rig, blocks=never)
    await _with({"statement_timeout": 0}).send('{"a": 1}')
    assert rig.pools[0]._conn._conn is not None and rig.pools[0]._conn._conn.timeout == 0


async def test_a_source_borrows_with_the_statement_timeout(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    _aioodbc_serving(monkeypatch, rig, blocks=never)
    await _source()._mark({"code": 1, "value": "x"})
    raw = rig.pools[0]._conn._conn
    assert raw is not None and raw.timeout == DEFAULT_DB_STATEMENT_TIMEOUT


@pytest.mark.parametrize("bad", [True, 2.5, -1, "soon", 2**31])
def test_a_bad_statement_timeout_is_refused_at_build(bad: object) -> None:
    with pytest.raises(ValueError, match="statement_timeout") as caught:
        _with({"statement_timeout": bad})
    assert str(bad) not in str(caught.value).replace(str(2**31 - 1), "")


async def test_each_pool_runs_on_its_own_executor_until_it_closes(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """Red before #5756: aioodbc was given no executor, so every DATABASE pool shared the event
    loop's default one. The executor is sized to the pool and shut down once its close ends."""
    _aioodbc_serving(monkeypatch, rig, blocks=never)
    calls = _recording_kwargs(monkeypatch)
    dest = _with({"pool_max": 3})
    await dest.send('{"a": 1}')
    executor = calls[0].get("executor")
    assert isinstance(executor, ThreadPoolExecutor)
    assert executor._max_workers == 3 + 4
    assert not executor._shutdown
    await dest.aclose()
    assert executor._shutdown


async def test_a_pool_that_never_opens_shuts_its_executor_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[ThreadPoolExecutor] = []

    async def create_pool(**kwargs: Any) -> Any:
        seen.append(kwargs["executor"])
        raise _DriverError("28000", "login refused")

    module = types.ModuleType("aioodbc")
    module.create_pool = create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    monkeypatch.setitem(sys.modules, "pyodbc", None)
    with pytest.raises(_DriverError):
        await database._make_pool("DSN=x", 1, autocommit=False, login_timeout=5)
    assert seen and seen[0]._shutdown


async def test_a_lookup_pool_borrows_with_its_statement_timeout(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """The lookup pool's first borrow, the login role probe, already carries the timeout."""
    _aioodbc_serving(monkeypatch, rig, blocks=never)
    executor = database.DatabaseLookupExecutor(
        {"clarity": {**_SQLSERVER, "statement_timeout": 9}},
        egress=EgressSettings(deny_by_default=False),
    )
    pool = await executor._get_pool("clarity")
    assert database._tracked(database._STATEMENT_TIMEOUTS, pool) == 9
    raw = rig.pools[0]._conn._conn
    assert raw is not None and raw.timeout == 9
    pool_executor = database._tracked(database._POOL_EXECUTORS, pool)
    assert pool_executor is not None and not pool_executor._shutdown
    await executor.aclose()
    assert pool_executor._shutdown


async def test_a_driver_refusing_the_timeout_attribute_stops_the_lane(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """pyodbc's setter hands the value to the driver, which may refuse it. The borrow fails closed
    as a config_fault naming the setting, and the connection, which ran nothing, goes back."""

    class _RefusesTimeout(RawConn):
        @property
        def timeout(self) -> int:
            return 0

        @timeout.setter
        def timeout(self, value: int) -> None:
            if value:  # the fake's own __init__ writes 0
                raise _DriverError("HYC00", "[HYC00] optional feature not implemented")

    _aioodbc_serving(monkeypatch, rig, raw_type=_RefusesTimeout, blocks=never)
    with pytest.raises(NegativeAckError) as caught:
        await _destination().send('{"a": 1}')
    assert caught.value.config_fault and "statement_timeout" in str(caught.value)
    assert rig.pools[0].free == [rig.conn] and "execute:start" not in rig.log


async def test_a_cursor_refusal_with_no_timeout_set_is_not_blamed_on_it(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    _aioodbc_serving(monkeypatch, rig, raw_type=_NoQueryTimeout, blocks=never)
    with pytest.raises(DeliveryError) as caught:
        await _with({"statement_timeout": 0}).send('{"a": 1}')
    assert not isinstance(caught.value, NegativeAckError)


def test_the_factories_declare_the_statement_timeout() -> None:
    from messagefoundry.config.wiring import Database, DatabasePoll

    spec = Database(server="db.example", database="d", statement="SELECT 1", statement_timeout=5)
    assert spec.settings["statement_timeout"] == 5
    poll = DatabasePoll(server="db.example", database="d", poll_statement="SELECT a FROM q")
    assert poll.settings["statement_timeout"] is None  # the connector picks the dialect's default


# --- the Manager's repair of 2026-11-16: findings A, B and H -------------------------------------


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        ({}, DEFAULT_DB_STATEMENT_TIMEOUT),
        ({"statement_timeout": None}, DEFAULT_DB_STATEMENT_TIMEOUT),
        ({"dialect": "sqlserver", "odbc_driver": "PostgreSQL Unicode"}, 30),
        ({"dialect": "generic", "odbc_driver": "ODBC Driver 18 for SQL Server"}, 30),
        ({"dialect": "Generic", "odbc_driver": " odbc driver 17 for sql server "}, 30),
        ({"dialect": "generic", "odbc_driver": "PostgreSQL Unicode"}, 0),
        (
            {
                "dialect": "generic",
                "odbc_driver": "PostgreSQL ANSI(x64)",
                "statement_timeout": None,
            },
            0,
        ),
        ({"dialect": "generic", "odbc_driver": "MySQL ODBC 8.0 Unicode Driver"}, 0),
        ({"dialect": "generic", "odbc_driver": "Some Other Driver"}, 0),
        ({"dialect": "generic"}, 0),
        ({"dialect": "generic", "odbc_driver": "PostgreSQL Unicode", "statement_timeout": 5}, 5),
        (
            {
                "dialect": "generic",
                "odbc_driver": "ODBC Driver 18 for SQL Server",
                "statement_timeout": 0,
            },
            0,
        ),
        ({"dialect": "sqlserver", "statement_timeout": 0}, 0),
    ],
)
def test_an_unset_statement_timeout_takes_the_driver_familys_default(
    settings: dict[str, Any], expected: int
) -> None:
    """Finding A, keyed by driver family on the Manager's answer: psqlODBC is reported to refuse
    the attribute pyodbc's setter writes, so a default of 30 there would stop every default
    generic lane on it. Only Microsoft's driver, on either dialect, defaults to 30; any family not
    known to take the setter defaults to 0. A value the operator sets is applied whatever the
    driver."""
    assert database._statement_timeout(settings, "t") == expected


class _TimeoutSetterFails(RawConn):
    """A connection whose driver fails the ``timeout`` write with ``state``."""

    state = "08S01"

    @property
    def timeout(self) -> int:
        return 0

    @timeout.setter
    def timeout(self, value: int) -> None:
        if value:  # the fake's own __init__ writes 0
            raise _DriverError(self.state, f"[{self.state}] the stand-in driver failed")


class _TimeoutSetterTimesOut(_TimeoutSetterFails):
    state = "HYT00"


@pytest.mark.parametrize("raw_type", [_TimeoutSetterFails, _TimeoutSetterTimesOut])
async def test_a_transient_setter_failure_retries_and_discards_the_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, raw_type: type[RawConn]
) -> None:
    """Finding B: a class 08 or HYT failure of the write is the connection's, not a refusal of
    the setting. Before the repair it stopped the lane as a config_fault and lent the handle
    again."""
    _aioodbc_serving(monkeypatch, rig, pool_type=_WakingPool, raw_type=raw_type, blocks=never)
    with pytest.raises(DeliveryError) as caught:
        await _destination().send('{"a": 1}')
    assert not isinstance(caught.value, NegativeAckError), caught.value
    pool = rig.pools[0]
    assert pool.returned and pool.free == [] and rig.conn.closed
    assert "execute:start" not in rig.log


#: A stand-in driver module: :func:`database._raised_by_a_driver` counts an exception class from a
#: module that declares the DB-API ``apilevel``.
_FAKE_DRIVER = types.ModuleType("b611_fake_driver")
_FAKE_DRIVER.apilevel = "2.0"  # type: ignore[attr-defined]


class _ClosedHandle(Exception):
    """pyodbc's shape for a closed connection: a message, no SQLSTATE, a driver's class."""


_ClosedHandle.__module__ = _FAKE_DRIVER.__name__


@pytest.fixture
def fake_driver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, _FAKE_DRIVER.__name__, _FAKE_DRIVER)


class _TimeoutReadFails(RawConn):
    @property
    def timeout(self) -> int:
        raise _ClosedHandle("Attempt to use a closed connection.")

    @timeout.setter
    def timeout(self, value: int) -> None:
        pass


@pytest.mark.usefixtures("fake_driver")
async def test_a_timeout_read_that_raises_discards_the_connection(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """Finding H: the read sat outside the try, so a closed handle raised out of the borrow and
    the connection never went back, a leaked pool slot."""
    _aioodbc_serving(
        monkeypatch, rig, pool_type=_WakingPool, raw_type=_TimeoutReadFails, blocks=never
    )
    with pytest.raises(DeliveryError) as caught:
        await _destination().send('{"a": 1}')
    assert not isinstance(caught.value, NegativeAckError)
    pool = rig.pools[0]
    assert pool.returned and pool.free == [] and rig.conn.closed


class _NoDriverTimeout(RawConn):
    @property
    def timeout(self) -> int:
        raise AttributeError("timeout")

    @timeout.setter
    def timeout(self, value: int) -> None:
        pass


async def test_a_driver_with_no_timeout_warns_once_per_pool(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """Finding H: the warning was logged on every borrow."""
    _aioodbc_serving(monkeypatch, rig, raw_type=_NoDriverTimeout, blocks=never)
    dest = _destination()
    with caplog.at_level("WARNING", logger=database.logger.name):
        for _ in range(3):
            await dest.send('{"a": 1}')
    warned = [r for r in caplog.records if "no driver timeout" in r.getMessage()]
    assert len(warned) == 1


class _TimeoutReadBug(RawConn):
    @property
    def timeout(self) -> int:
        raise RuntimeError("a bug in the binding")

    @timeout.setter
    def timeout(self, value: int) -> None:
        pass


async def test_a_timeout_read_that_is_no_driver_error_propagates_unchanged(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig
) -> None:
    """Finding 4: the borrow re-raises a non-driver error unchanged and returns the connection,
    which ran nothing, open. Before the repair it raised its own transient DeliveryError and
    discarded a healthy connection each time.

    ``_connect`` still reads any connect-time failure with no SQLSTATE as a transient connect
    failure (BACKLOG #5713), so a send sees that, with the bug unchanged as its cause."""
    _aioodbc_serving(monkeypatch, rig, raw_type=_TimeoutReadBug, blocks=never)
    with pytest.raises(DeliveryError) as caught:
        await _destination().send('{"a": 1}')
    cause = caught.value.__cause__
    assert isinstance(cause, RuntimeError) and str(cause) == "a bug in the binding"
    assert rig.pools[0].free == [rig.conn] and not rig.conn.closed


async def test_a_driver_with_no_timeout_does_not_warn_when_no_limit_was_asked(
    monkeypatch: pytest.MonkeyPatch, rig: _Rig, caplog: pytest.LogCaptureFixture
) -> None:
    """Finding 6: a pool whose statement_timeout is 0 loses nothing to a driver with no
    ``timeout``, so the warning that a bound was dropped is not logged."""
    _aioodbc_serving(monkeypatch, rig, raw_type=_NoDriverTimeout, blocks=never)
    with caplog.at_level("WARNING", logger=database.logger.name):
        await _with({"statement_timeout": 0}).send('{"a": 1}')
    assert not [r for r in caplog.records if "no driver timeout" in r.getMessage()]
