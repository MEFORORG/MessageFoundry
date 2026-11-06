# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The login role probe for the SQL Server logins ``db_lookup`` and ``DatabaseRef`` dial (BACKLOG
#2617, slice 2).

When a lookup connection's pool first opens, and when a reference set's pool first opens for its
DSN, the engine reads the login's fixed-role membership with ``IS_SRVROLEMEMBER`` and
``IS_ROLEMEMBER``, by the same closed role sets the store's own preflight reads. "Clean" means no
database-wide write role. An over-grant warns and nothing is refused; a NULL read is "cannot judge",
never clean; a probe that cannot run warns and the hop goes ahead.

Before this change no probe existed: a lookup on a ``db_owner`` login ran with no warning, which
``test_an_over_granted_lookup_login_warns_and_the_lookup_still_runs`` shows (it fails on the
unfixed code, which logs nothing and has no ``role_readings``).

Synthetic data only; no driver, no database. The live twin is
``tests/test_sqlserver_lookup_login_role_probe.py``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.wiring import DatabaseRef, ReferenceSpec
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner, _load_database_source
from messagefoundry.sqlserver_roles import (
    SQLSERVER_FIXED_DATABASE_ROLES,
    SQLSERVER_FIXED_SERVER_ROLES,
)
from messagefoundry.store import privilege
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import database
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.database import (
    DatabaseLookupExecutor,
    LoginRoleReading,
    LoginRoleVerdict,
    classify_login_roles,
    probe_login_roles,
)

_EGRESS = EgressSettings(deny_by_default=False)
_LOOKUP = {"clarity": {"server": "db.example", "database": "Clarity"}}
_ROLES = SQLSERVER_FIXED_SERVER_ROLES + SQLSERVER_FIXED_DATABASE_ROLES
_LOGGER = "messagefoundry.transports.database"


def _row(held: tuple[str, ...] = (), null: tuple[str, ...] = ()) -> tuple[Any, ...]:
    """A probe row: 1 for each role in ``held``, NULL for each in ``null``, 0 for the rest."""
    for name in held + null:
        assert name in _ROLES, name
    return tuple(1 if r in held else None if r in null else 0 for r in _ROLES)


# --- the pure classification -------------------------------------------------------------------


def test_the_store_and_the_probe_read_one_role_list() -> None:
    """The leaf is the one spelling: store/privilege.py re-exports it rather than keeping a copy."""
    assert privilege.SQLSERVER_FIXED_SERVER_ROLES is SQLSERVER_FIXED_SERVER_ROLES
    assert privilege.SQLSERVER_FIXED_DATABASE_ROLES is SQLSERVER_FIXED_DATABASE_ROLES


@pytest.mark.parametrize(
    "held",
    [(), ("db_datareader",), ("db_datareader", "db_denydatawriter"), ("db_denydatareader",)],
)
def test_a_reader_login_is_clean(held: tuple[str, ...]) -> None:
    assert classify_login_roles(_row(held)) == LoginRoleReading(LoginRoleVerdict.CLEAN)


@pytest.mark.parametrize(
    ("held", "finding"),
    [
        (("db_datareader", "db_datawriter"), "database role db_datawriter"),
        (("db_owner",), "database role db_owner"),
        (("db_ddladmin",), "database role db_ddladmin"),
        (("db_securityadmin",), "database role db_securityadmin"),
        (("sysadmin",), "server role sysadmin"),
        (("bulkadmin",), "server role bulkadmin"),
    ],
)
def test_a_database_wide_write_or_admin_role_is_over_granted(
    held: tuple[str, ...], finding: str
) -> None:
    reading = classify_login_roles(_row(held))
    assert reading.verdict is LoginRoleVerdict.OVER_GRANTED
    assert reading.held == (finding,)


def test_a_denied_writer_is_not_a_finding() -> None:
    """``db_denydatawriter`` takes back the table writes ``db_datawriter`` grants."""
    reading = classify_login_roles(_row(("db_datawriter", "db_denydatawriter")))
    assert reading.verdict is LoginRoleVerdict.CLEAN


def test_a_null_read_cannot_judge_and_is_never_clean() -> None:
    """A NULL is a name that did not resolve for this login, not "not a member"."""
    reading = classify_login_roles(_row(("db_datareader",), null=("sysadmin", "db_owner")))
    assert reading.verdict is LoginRoleVerdict.CANNOT_JUDGE
    assert reading.unread == ("server role sysadmin", "database role db_owner")
    assert reading.held == ()


def test_a_held_write_role_beside_a_null_is_still_over_granted() -> None:
    """A partial read can only understate an over-grant, so what was read as held is reported."""
    reading = classify_login_roles(_row(("db_datawriter",), null=("sysadmin",)))
    assert reading.verdict is LoginRoleVerdict.OVER_GRANTED
    assert reading.held == ("database role db_datawriter",)
    assert reading.unread == ("server role sysadmin",)


def test_a_driver_that_answers_booleans_reads_the_same() -> None:
    row = tuple(r == "db_owner" for r in _ROLES)
    assert classify_login_roles(row).held == ("database role db_owner",)


def test_a_row_of_the_wrong_width_did_not_run() -> None:
    reading = classify_login_roles((0, 0))
    assert reading.verdict is LoginRoleVerdict.NOT_RUN
    assert reading.cause is not None and "columns" in reading.cause


# --- the probe against a faked pool --------------------------------------------------------------


class _Cursor:
    """Answers the role probe with ``role_row`` and any other statement with ``rows``."""

    def __init__(self, pool: _Pool) -> None:
        self._pool = pool
        self.description: list[tuple[str]] = []
        self._pending: list[tuple[Any, ...]] = []
        self._probe = False

    async def execute(self, sql: str, params: Any = None) -> None:
        self._pool.executed.append((sql, params))
        self._probe = "IS_SRVROLEMEMBER" in sql
        if self._probe and self._pool.probe_error is not None:
            raise self._pool.probe_error
        self.description = [("code",), ("value",)]
        self._pending = list(self._pool.rows)

    async def fetchone(self) -> tuple[Any, ...] | None:
        assert self._probe, "only the role probe reads one row"
        return self._pool.role_row

    async def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        rows, self._pending = self._pending[:size], self._pending[size:]
        return rows

    async def fetchall(self) -> list[tuple[Any, ...]]:
        rows, self._pending = self._pending, []
        return rows

    async def close(self) -> None:
        return None


class _Conn:
    def __init__(self, pool: _Pool) -> None:
        self._pool = pool

    async def cursor(self) -> _Cursor:
        return _Cursor(self._pool)


class _Pool:
    def __init__(self, role_row: tuple[Any, ...] | None) -> None:
        self.role_row = role_row
        self.rows: list[tuple[Any, ...]] = [("A", "1")]
        self.executed: list[tuple[str, Any]] = []
        self.probe_error: Exception | None = None
        self.acquire_error: Exception | None = None
        self.acquired = 0
        self.released = 0
        self.closed = False

    async def acquire(self) -> _Conn:
        if self.acquire_error is not None:
            raise self.acquire_error
        self.acquired += 1
        return _Conn(self)

    async def release(self, conn: _Conn) -> None:
        self.released += 1

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    @property
    def probes(self) -> int:
        return sum("IS_SRVROLEMEMBER" in sql for sql, _ in self.executed)


def _serve(monkeypatch: pytest.MonkeyPatch, pool: _Pool) -> list[str]:
    """Hand ``pool`` to every ``_make_pool`` call, and record each DSN asked for."""
    dsns: list[str] = []

    async def fake_make_pool(
        dsn: str, pool_max: int, *, autocommit: bool, login_timeout: int | None
    ) -> _Pool:
        dsns.append(dsn)
        return pool

    monkeypatch.setattr(database, "_make_pool", fake_make_pool)
    return dsns


async def test_the_probe_reads_every_role_by_name_with_bound_parameters() -> None:
    pool = _Pool(_row())
    await probe_login_roles(pool, label="db_lookup:clarity", acquire_timeout=5.0)
    [(sql, params)] = pool.executed
    assert sql.count("IS_SRVROLEMEMBER(?)") == len(SQLSERVER_FIXED_SERVER_ROLES)
    assert sql.count("IS_ROLEMEMBER(?)") == len(SQLSERVER_FIXED_DATABASE_ROLES)
    assert params == _ROLES  # names bound, never spliced into the text
    assert pool.released == 1


async def test_a_clean_login_logs_info(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        reading = await probe_login_roles(
            _Pool(_row(("db_datareader",))), label="db_lookup:clarity", acquire_timeout=5.0
        )
    assert reading.verdict is LoginRoleVerdict.CLEAN
    [record] = caplog.records
    assert record.levelno == logging.INFO
    assert "no database-wide write role" in record.getMessage()
    assert "object-level grants are not read" in record.getMessage()


async def test_a_null_read_warns_that_it_cannot_judge(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        reading = await probe_login_roles(
            _Pool(_row(null=("db_owner",))), label="db_lookup:clarity", acquire_timeout=5.0
        )
    assert reading.verdict is LoginRoleVerdict.CANNOT_JUDGE
    [record] = caplog.records
    assert record.levelno == logging.WARNING
    assert "cannot judge" in record.getMessage() and "database role db_owner" in record.getMessage()


async def test_an_unreachable_partner_warns_and_never_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The borrow fails after the pool opened: NOT_RUN, a warning, no exception."""
    pool = _Pool(_row())
    pool.acquire_error = ConnectionError("08S01 secret-host;PWD=hunter2")
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        reading = await probe_login_roles(pool, label="db_lookup:clarity", acquire_timeout=5.0)
    assert reading.verdict is LoginRoleVerdict.NOT_RUN
    assert reading.cause == "ConnectionError"  # the type alone: a driver message can carry the DSN
    [record] = caplog.records
    assert record.levelno == logging.WARNING and "did not run" in record.getMessage()
    assert "hunter2" not in caplog.text and "secret-host" not in caplog.text


async def test_a_borrow_timeout_is_named_and_does_not_raise() -> None:
    pool = _Pool(_row())
    pool.acquire_error = DeliveryError("DATABASE pool acquire timed out after 5s")
    reading = await probe_login_roles(pool, label="db_lookup:clarity", acquire_timeout=5.0)
    assert reading.verdict is LoginRoleVerdict.NOT_RUN
    assert reading.cause == "DATABASE pool acquire timed out after 5s"


async def test_a_failed_probe_statement_names_its_sqlstate_not_its_text() -> None:
    pool = _Pool(_row())
    pool.probe_error = Exception("42000", "[Microsoft] secret-host denied PWD=hunter2")
    reading = await probe_login_roles(pool, label="db_lookup:clarity", acquire_timeout=5.0)
    assert reading.verdict is LoginRoleVerdict.NOT_RUN
    assert reading.cause is not None and "42000" in reading.cause
    assert "hunter2" not in reading.cause and "secret-host" not in reading.cause
    assert pool.released == 1  # the connection still goes back


async def test_no_row_did_not_run() -> None:
    reading = await probe_login_roles(_Pool(None), label="db_lookup:clarity", acquire_timeout=5.0)
    assert reading == LoginRoleReading(LoginRoleVerdict.NOT_RUN, cause="the probe returned no row")


# --- the db_lookup executor ------------------------------------------------------------------------


async def test_an_over_granted_lookup_login_warns_and_the_lookup_still_runs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Red before the fix: no probe ran, nothing was logged, and ``role_readings`` did not exist."""
    pool = _Pool(_row(("db_datareader", "db_owner")))
    _serve(monkeypatch, pool)
    executor = DatabaseLookupExecutor(_LOOKUP, egress=_EGRESS)
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        rows = await executor.query("clarity", "SELECT code, value FROM t", None)
    assert rows == [{"code": "A", "value": "1"}]  # warn, never refuse
    assert executor.role_readings["clarity"].verdict is LoginRoleVerdict.OVER_GRANTED
    assert "'db_lookup:clarity'" in caplog.text and "database role db_owner" in caplog.text
    assert "Warning only: nothing is refused" in caplog.text
    await executor.aclose()


async def test_the_lookup_probe_runs_once_when_the_pool_first_opens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _Pool(_row(("db_datareader",)))
    _serve(monkeypatch, pool)
    executor = DatabaseLookupExecutor(_LOOKUP, egress=_EGRESS)
    assert executor.role_readings == {}  # start dials nothing, so nothing is probed yet
    for _ in range(3):
        await executor.query("clarity", "SELECT code, value FROM t", None)
    assert pool.probes == 1
    assert pool.executed[0][0].startswith("SELECT IS_SRVROLEMEMBER")  # before the first lookup
    assert executor.role_readings["clarity"].verdict is LoginRoleVerdict.CLEAN
    await executor.aclose()


async def test_a_probe_that_cannot_run_does_not_block_the_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _Pool(_row())
    pool.probe_error = Exception("08S01", "link reset")
    _serve(monkeypatch, pool)
    executor = DatabaseLookupExecutor(_LOOKUP, egress=_EGRESS)
    rows = await executor.query("clarity", "SELECT code, value FROM t", None)
    assert rows == [{"code": "A", "value": "1"}]
    assert executor.role_readings["clarity"].verdict is LoginRoleVerdict.NOT_RUN
    await executor.aclose()


# --- the DatabaseRef sync --------------------------------------------------------------------------

_REF = {
    "server": "db.example",
    "database": "d",
    "statement": "SELECT code, value FROM t",
    "key_column": "code",
    "value_column": "value",
}


async def test_an_over_granted_reference_login_warns_and_the_set_still_loads(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    pool = _Pool(_row(("db_datareader", "db_datawriter")))
    _serve(monkeypatch, pool)
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        loaded = await _load_database_source(dict(_REF), _EGRESS, name="codes")
    assert loaded == {"A": "1"}
    assert "'reference:codes'" in caplog.text and "database role db_datawriter" in caplog.text
    assert pool.executed[0][0].startswith("SELECT IS_SRVROLEMEMBER")  # before the statement


async def test_a_reference_probe_is_remembered_per_set_and_dsn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _Pool(_row(("db_datareader",)))
    _serve(monkeypatch, pool)
    probed: set[tuple[str, ...]] = set()
    for _ in range(2):
        await _load_database_source(dict(_REF), _EGRESS, name="codes", probed=probed)
    assert pool.probes == 1
    # Another login on the same set is probed again.
    await _load_database_source(
        {**_REF, "username": "other", "password": "synthetic-pw"},
        _EGRESS,
        name="codes",
        probed=probed,
    )
    assert pool.probes == 2
    assert len(probed) == 2
    assert all("synthetic-pw" not in part for key in probed for part in key)  # no credential kept
    # A changed password alone is the same login, so it is not probed again.
    await _load_database_source(
        {**_REF, "username": "other", "password": "rotated-pw"},
        _EGRESS,
        name="codes",
        probed=probed,
    )
    assert pool.probes == 2
    # With no memory, every call probes.
    await _load_database_source(dict(_REF), _EGRESS, name="codes")
    assert pool.probes == 3


async def test_a_reference_pool_that_fails_to_open_is_probed_on_the_next_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probed: set[tuple[str, ...]] = set()

    async def unreachable(*_a: object, **_k: object) -> object:
        raise ConnectionError("08001")

    monkeypatch.setattr(database, "_make_pool", unreachable)
    with pytest.raises(ConnectionError):
        await _load_database_source(dict(_REF), _EGRESS, name="codes", probed=probed)
    assert probed == set()
    pool = _Pool(_row())
    _serve(monkeypatch, pool)
    await _load_database_source(dict(_REF), _EGRESS, name="codes", probed=probed)
    assert pool.probes == 1


async def test_the_runner_probes_each_set_once_across_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = ReferenceSpec(
        name="codes",
        source=DatabaseRef(
            server="db.example",
            database="d",
            statement="SELECT code, value FROM t",
            key_column="code",
            value_column="value",
        ),
    )
    pool = _Pool(_row(("db_owner",)))
    _serve(monkeypatch, pool)
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        runner = ReferenceSyncRunner(store, lambda: [spec], ReferenceSettings(), egress=_EGRESS)
        for _ in range(3):
            assert (await runner.sync_all()).synced == 1  # an over-grant never fails the sync
        assert pool.probes == 1
    finally:
        await store.close()
