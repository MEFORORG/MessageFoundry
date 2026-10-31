# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0157 Inc 0 on SQL Server: the lease claim/renew runs under ``[cluster].lease_renew_timeout_seconds``.

Until BACKLOG #1497 the clamp bound only the Postgres coordinator. The SQL Server claim inherited
``[store].command_timeout`` (30 s by default) from the ODBC connection while it held the leadership
lock, so a hung claim could hold a stepdown past that lock's fence-length wait.

Most of this file needs no database. The store is built with ``__new__`` over a fake pool, the
driverless idiom of ``tests/test_store_pool_acquire_timeout.py``. Its fake raw connection behaves as
pyodbc does in the one way the clamp depends on: a cursor copies ``Connection.timeout`` when it is
created, so the timeout a statement runs under is the one in force at that moment.

The last test is gated on ``MEFOR_TEST_SQLSERVER`` and runs on the hosted ``sql server (store +
connector)`` legs, whose catch-all step in ``.github/workflows/ci.yml`` names this file. It proves
the driver really ends a statement at the clamp, which no fake can.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    ClusterSettings,
    StoreSettings,
    _detection_margin_seconds,
    load_settings,
)
from messagefoundry.pipeline.cluster import build_coordinator
from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator
from messagefoundry.store.pool_metrics import AcquireWaitHistogram
from messagefoundry.store.sqlserver import _clamped_statement_timeout

# --- the whole-second conversion ---------------------------------------------


@pytest.mark.parametrize(
    ("clamp", "command_timeout", "expected"),
    [
        (4.5, 30, 4),  # the stock derived clamp rounds DOWN, never past the checked value
        (1.0, 30, 1),
        (8.9, 30, 8),
        (0.5, 30, 1),  # never 0, which would mean no limit (the settings refuse this on SQL Server)
        (4.5, 3, 3),  # a shorter command_timeout still wins
        (4.5, 4, 4),
        (4.5, 0, 4),  # command_timeout 0 is no limit, so the clamp is the only bound
    ],
)
def test_the_clamp_becomes_whole_seconds_rounded_down(
    clamp: float, command_timeout: int, expected: int
) -> None:
    assert _clamped_statement_timeout(clamp, command_timeout) == expected


# --- the store seam, over a fake pyodbc connection ---------------------------


class _Raw:
    """The pyodbc ``Connection``: records every ``timeout`` assignment."""

    def __init__(self) -> None:
        self._timeout = 0
        self.assigned: list[int] = []

    @property
    def timeout(self) -> int:
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        assert isinstance(value, int), "pyodbc's Connection.timeout takes an int"
        self._timeout = value
        self.assigned.append(value)

    def close(self) -> None:
        pass


class _Cursor:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn
        self.timeout = conn._conn.timeout if conn._conn is not None else None  # copied at creation
        self.description = [("owner",), ("leader_epoch",)]

    async def execute(self, sql: str, params: Any = None) -> None:
        self._conn.statement_timeouts.append(self.timeout)
        if self._conn.fail is not None:
            raise self._conn.fail
        if self._conn.hang is not None:
            await self._conn.hang.wait()

    async def fetchall(self) -> list[tuple[object, ...]]:
        return [("A", 7)]

    async def close(self) -> None:
        pass


class _Conn:
    def __init__(self) -> None:
        self._conn: _Raw | None = _Raw()
        self.raw = self._conn
        self.statement_timeouts: list[int | None] = []
        self.fail: Exception | None = None
        self.hang: asyncio.Event | None = None
        self.rolled_back = 0

    @property
    def closed(self) -> bool:
        return self._conn is None

    async def cursor(self) -> _Cursor:
        return _Cursor(self)

    async def commit(self) -> None:
        pass

    async def rollback(self) -> None:
        self.rolled_back += 1


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self.conn = conn
        self.released: list[_Conn] = []

    async def acquire(self) -> _Conn:
        return self.conn

    async def release(self, conn: _Conn) -> None:
        self.released.append(conn)


class _HangingPool:
    """A pool whose acquire never returns: every connection is out, or the server is unreachable."""

    async def acquire(self) -> _Conn:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def release(self, conn: _Conn) -> None:
        pass


def _store(conn: _Conn, command_timeout: int = 30, acquire_timeout: float = 30.0) -> Any:
    from messagefoundry.store.sqlserver import SqlServerStore

    store = SqlServerStore.__new__(SqlServerStore)
    store._pool = _Pool(conn)
    store._settings = StoreSettings(
        command_timeout=command_timeout, acquire_timeout=acquire_timeout
    )
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0
    store.body_copies = 0
    return store


async def test_the_clamped_read_runs_under_the_clamp_and_restores_command_timeout() -> None:
    conn = _Conn()
    store = _store(conn)
    row = await store._fetchone_clamped("MERGE leader_lease ...", ("k",), timeout_clamp=4.5)
    assert row == {"owner": "A", "leader_epoch": 7}
    assert conn.statement_timeouts == [4]
    # _borrow applies command_timeout, the clamp replaces it for the statement, and it is put back.
    assert conn.raw.assigned == [30, 4, 30]
    assert conn.raw.timeout == 30


async def test_a_shorter_command_timeout_still_ends_the_claim_first() -> None:
    conn = _Conn()
    store = _store(conn, command_timeout=2)
    await store._fetchone_clamped("MERGE leader_lease ...", ("k",), timeout_clamp=4.5)
    assert conn.statement_timeouts == [2]
    assert conn.raw.timeout == 2


async def test_the_timeout_is_restored_when_the_statement_raises() -> None:
    """The driver's own timeout arrives as an ordinary exception, after the statement returned, so
    the connection goes back to the pool and must carry command_timeout again."""
    conn = _Conn()
    conn.fail = RuntimeError("HYT00 query timeout expired")
    store = _store(conn)
    with pytest.raises(RuntimeError, match="HYT00"):
        await store._fetchone_clamped("MERGE leader_lease ...", ("k",), timeout_clamp=4.5)
    assert conn.statement_timeouts == [4]
    assert conn.rolled_back == 1
    assert conn.raw.assigned == [30, 4, 30]
    assert conn.raw.timeout == 30
    assert conn.closed is False  # an ordinary error recycles the connection, as before


async def test_a_cancelled_claim_quarantines_and_does_not_touch_the_timeout() -> None:
    """A cancellation may leave the statement running on an executor thread, so setting the timeout
    then would be an ODBC call beside it. The connection is quarantined instead and never lent."""
    conn = _Conn()
    raw = conn.raw
    conn.hang = asyncio.Event()
    store = _store(conn)
    task = asyncio.create_task(
        store._fetchone_clamped("MERGE leader_lease ...", ("k",), timeout_clamp=4.5)
    )
    while not conn.statement_timeouts and not task.done():
        await asyncio.sleep(0)
    assert not task.done(), "the claim ended before its statement started"
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert raw.assigned == [30, 4], "no restore may run beside a cancelled statement"
    assert conn.closed is True  # _borrow quarantined it


async def test_the_claim_waits_for_a_pooled_connection_at_most_the_clamp() -> None:
    """A renew that waited out a saturated pool past the fence would still extend the lease after
    this node self-fenced, so the borrow is bounded by the clamp too. Control: an ordinary read on
    the same wedged pool waits the full acquire_timeout."""
    from messagefoundry.store.base import StoreAcquireTimeout

    store = _store(_Conn(), acquire_timeout=3.0)
    store._pool = _HangingPool()
    started = time.monotonic()
    with pytest.raises(StoreAcquireTimeout):
        await store._fetchone_clamped("MERGE leader_lease ...", ("k",), timeout_clamp=1.0)
    clamped = time.monotonic() - started
    started = time.monotonic()
    with pytest.raises(StoreAcquireTimeout):
        await store._fetchone("SELECT 1", ())
    unclamped = time.monotonic() - started
    assert clamped < 2.0 <= unclamped, (clamped, unclamped)


async def test_a_failed_restore_does_not_fail_a_claim_that_returned() -> None:
    """The restore is best-effort: the statement has returned, so a renew that committed is not
    reported as failed because putting command_timeout back raised."""

    class _RefusingRaw(_Raw):
        @property
        def timeout(self) -> int:
            return self._timeout

        @timeout.setter
        def timeout(self, value: int) -> None:
            if self.assigned[-2:] == [30, 4]:
                raise RuntimeError("SQLSetConnectAttr failed")
            self._timeout = value
            self.assigned.append(value)

    conn = _Conn()
    conn._conn = conn.raw = _RefusingRaw()
    row = await _store(conn)._fetchone_clamped("MERGE leader_lease ...", ("k",), timeout_clamp=4.5)
    assert row == {"owner": "A", "leader_epoch": 7}
    assert conn.raw.assigned == [30, 4]


async def test_the_unclamped_read_is_unchanged() -> None:
    """Control: every other store read keeps command_timeout and assigns nothing more."""
    conn = _Conn()
    store = _store(conn)
    await store._fetchone("SELECT owner, leader_epoch FROM leader_lease", ("k",))
    assert conn.statement_timeouts == [30]
    assert conn.raw.assigned == [30]


# --- the coordinator ---------------------------------------------------------


async def test_the_coordinator_claim_runs_under_its_renew_clamp_end_to_end() -> None:
    """The coordinator over the real store seam: the MERGE runs at the clamp, rounded down."""
    conn = _Conn()
    coord = SqlServerCoordinator(_store(conn), "A", lease_renew_timeout_seconds=3.25)
    await coord._maintain_leadership()
    assert coord.is_leader() is True
    assert coord.current_epoch() == 7
    assert conn.statement_timeouts == [3]
    assert conn.raw.timeout == 30


async def test_the_paused_owner_read_is_not_clamped() -> None:
    """Only the claim is in scope: the paused tick's owner read keeps its own BACKLOG #2540 bound."""
    calls: list[str] = []

    class _Store:
        async def _fetchone(self, sql: str, params: tuple[object, ...]) -> dict[str, object]:
            calls.append("plain")
            return {"owner": "A"}

        async def _fetchone_clamped(
            self, sql: str, params: tuple[object, ...], *, timeout_clamp: float
        ) -> dict[str, object]:
            raise AssertionError("a paused node must not send the claim")

    coord = SqlServerCoordinator(_Store(), "A", monotonic=lambda: 0.0)
    coord._no_claim_until = 10.0
    assert await coord._claim_or_renew_lease() is False
    assert calls == ["plain"]


class _SqlServerSettings:
    backend = "sqlserver"
    db_schema = None


class _StubStore:
    _pool = object()
    _owner = "host:1:abcd"
    _settings = _SqlServerSettings()


def test_build_coordinator_threads_the_clamp_to_the_sqlserver_coordinator() -> None:
    coord = build_coordinator(
        _StubStore(), ClusterSettings(enabled=True, lease_renew_timeout_seconds=3.25)
    )
    assert isinstance(coord, SqlServerCoordinator)
    assert coord._renew_timeout == 3.25


def test_build_coordinator_threads_the_derived_clamp_to_the_sqlserver_coordinator() -> None:
    coord = build_coordinator(_StubStore(), ClusterSettings(enabled=True))
    assert isinstance(coord, SqlServerCoordinator)
    assert coord._renew_timeout == 4.5


# --- the config refusal --------------------------------------------------------

_SQLSERVER = (
    '[store]\nbackend = "sqlserver"\nserver = "s"\ndatabase = "d"\nauth = "integrated"\n'
    "[cluster]\nenabled = true\n"
)
_POSTGRES = (
    '[store]\nbackend = "postgres"\nserver = "pg"\ndatabase = "d"\nusername = "u"\n'
    "[cluster]\nenabled = true\n"
)


def _load(tmp_path: Path, text: str) -> Any:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(text, encoding="utf-8")
    return load_settings(config_path=cfg, environ={})


def test_a_sub_second_clamp_is_refused_on_sqlserver(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="whole seconds"):
        _load(tmp_path, _SQLSERVER + "lease_renew_timeout_seconds = 0.5\n")


def test_a_one_second_clamp_and_the_derived_clamp_load_on_sqlserver(tmp_path: Path) -> None:
    assert _load(tmp_path, _SQLSERVER + "lease_renew_timeout_seconds = 1.0\n").cluster.enabled
    assert _load(tmp_path, _SQLSERVER).cluster.lease_renew_timeout_seconds == 4.5


def test_a_sub_second_clamp_still_loads_on_postgres(tmp_path: Path) -> None:
    """Control: asyncpg takes a fractional timeout, so the refusal is SQL Server's alone."""
    s = _load(tmp_path, _POSTGRES + "lease_renew_timeout_seconds = 0.5\n")
    assert s.cluster.lease_renew_timeout_seconds == 0.5


# --- the start-up warning on the SQL Server bound --------------------------------

_TWICE_THE_CLAMP = "twice lease_renew_timeout_seconds"


def test_sqlserver_warns_when_twice_the_clamp_reaches_the_margin(tmp_path: Path) -> None:
    """Margin 9.0 at 10/20/30; a 4.6 clamp passes the margin check (4.6 < 9.0) but 9.2 >= 9.0."""
    s = _load(tmp_path, _SQLSERVER + "lease_renew_timeout_seconds = 4.6\n")
    assert s.cluster.lease_renew_timeout_seconds == 4.6
    note = s.sqlserver_renew_bound_warning()
    assert note is not None
    assert _TWICE_THE_CLAMP in note
    assert "(2 x 4.6 = 9.2 s)" in note
    assert "margin (9 s)" in note
    # The operator set this value, so the note may tell them to lower it.
    assert "Lower lease_renew_timeout_seconds below 4.5 s" in note
    assert "is not set" not in note


def test_sqlserver_warns_at_the_shipped_timings(tmp_path: Path) -> None:
    """The derived 4.5 at 10/20/30 is exactly half the 9.0 margin, so twice it reaches the margin.
    Pinned because the changelog and CONFIGURATION.md say a stock SQL Server cluster warns."""
    s = _load(tmp_path, _SQLSERVER)
    assert s.cluster.lease_renew_timeout_seconds == 4.5
    note = s.sqlserver_renew_bound_warning()
    assert note is not None
    # Derived, so the note names the fence/TTL pair and never a value the operator did not set.
    assert "lease_renew_timeout_seconds is not set" in note
    assert "leaves the renew little or no headroom on SQL Server" in note
    assert "(2 x 4.5 = 9 s)" in note
    assert "set lease_renew_timeout_seconds explicitly, below 4.5 s" in note
    assert "Lower lease_renew_timeout_seconds" not in note
    assert _TWICE_THE_CLAMP not in note


def test_the_same_value_set_explicitly_is_named_as_set(tmp_path: Path) -> None:
    """Control for the derived wording: 4.5 written by hand is the operator's, so lowering it is
    the remedy, and the derived text does not appear."""
    note = _load(
        tmp_path, _SQLSERVER + "lease_renew_timeout_seconds = 4.5\n"
    ).sqlserver_renew_bound_warning()
    assert note is not None
    assert _TWICE_THE_CLAMP in note
    assert "Lower lease_renew_timeout_seconds below 4.5 s" in note
    assert "is not set" not in note


def test_a_floored_derived_clamp_names_widening_alone(tmp_path: Path) -> None:
    """Fence 4.0 / TTL 6.0 leaves a 1.2 s margin; the derived clamp is floored at 1.0, and no clamp
    at or above the 1 s SQL Server floor is below 0.6 s, so setting one is not offered."""
    s = _load(
        tmp_path,
        _SQLSERVER
        + "heartbeat_seconds = 1.0\nleader_fence_timeout_seconds = 4.0\n"
        + "leader_lease_ttl_seconds = 6.0\n",
    )
    assert s.cluster.lease_renew_timeout_seconds == 1.0
    note = s.sqlserver_renew_bound_warning()
    assert note is not None
    assert "lease_renew_timeout_seconds is not set" in note
    assert "Widen the gap between leader_fence_timeout_seconds" in note
    assert "explicitly" not in note
    assert "Lower lease_renew_timeout_seconds" not in note


def test_the_warning_prints_a_float_margin_short(tmp_path: Path) -> None:
    """At fence 2.0 / TTL 4.7 the margin is 2.3000000000000003 as a float; the note says 2.3."""
    s = _load(
        tmp_path,
        _SQLSERVER
        + "heartbeat_seconds = 1.0\nleader_fence_timeout_seconds = 2.0\n"
        + "leader_lease_ttl_seconds = 4.7\n",
    )
    assert repr(_detection_margin_seconds(2.0, 4.7)) == "2.3000000000000003"
    note = s.sqlserver_renew_bound_warning()
    assert note is not None
    assert "margin (2.3 s)" in note
    assert "0000" not in note


def test_postgres_does_not_warn_with_the_same_numbers(tmp_path: Path) -> None:
    """Control: on Postgres the borrow and statement share one deadline, so the clamp is the bound."""
    assert (
        _load(
            tmp_path, _POSTGRES + "lease_renew_timeout_seconds = 4.6\n"
        ).sqlserver_renew_bound_warning()
        is None
    )
    assert _load(tmp_path, _POSTGRES).sqlserver_renew_bound_warning() is None


def test_sqlserver_with_ample_margin_does_not_warn(tmp_path: Path) -> None:
    """Control: 2 x 4.4 = 8.8 < 9.0, just inside; and 2 x 2.0 well inside."""
    for clamp in ("4.4", "2.0"):
        s = _load(tmp_path, _SQLSERVER + f"lease_renew_timeout_seconds = {clamp}\n")
        assert s.sqlserver_renew_bound_warning() is None


def test_loading_settings_logs_no_renew_bound_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The load itself stays quiet even on a config that warns, so ``serve`` logs it exactly once."""
    caplog.set_level(logging.WARNING)
    s = _load(tmp_path, _SQLSERVER)
    assert s.sqlserver_renew_bound_warning() is not None
    assert not [r for r in caplog.records if _TWICE_THE_CLAMP in r.getMessage()]


def test_serve_logs_the_renew_bound_warning_once_logging_is_configured() -> None:
    """``serve`` loads its settings before ``configure_logging``, so the warning is logged after it,
    or it would reach the filtered lastResort only. Read from the source, as the breaker-budget seam
    test in tests/test_ad_user_account_control.py does, because running ``serve`` that far starts an
    engine."""
    import inspect

    from messagefoundry import __main__ as cli

    source = inspect.getsource(cli._serve)
    checked = source.index("if _logging_refused is not None:")
    warned = source.index("settings.sqlserver_renew_bound_warning()")
    assert source.index("_load_service_settings(") < checked < warned
    assert source.count("sqlserver_renew_bound_warning") == 1
    assert "sqlserver_renew_bound_warning" not in inspect.getsource(load_settings)


# --- against a real server -----------------------------------------------------


@pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)
async def test_the_driver_ends_a_slow_claim_at_the_clamp() -> None:
    """A statement slower than the clamp ends at the clamp, not at command_timeout, and the store
    still works afterwards. That the clamp is put back is pinned offline above: here every borrow
    re-applies command_timeout, so a live read of it could not tell."""
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    store = await SqlServerStore.open(settings)
    try:
        if 0 < settings.command_timeout <= 4:
            pytest.skip("command_timeout would end the 4 s statement before the clamp could")
        started = time.monotonic()
        # HYT00 alone: the ODBC query timeout. A bare "timeout" would also match the
        # StoreAcquireTimeout a clamped borrow raises, which is not the bound under test.
        with pytest.raises(Exception, match="HYT00"):
            await store._fetchone_clamped(
                "WAITFOR DELAY '00:00:04'; SELECT 1 AS x", (), timeout_clamp=1.5
            )
        assert time.monotonic() - started < 3.5, "the clamp did not end the statement"
        assert await store._fetchone("SELECT 1 AS x") == {"x": 1}
    finally:
        await store.close()
