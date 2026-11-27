# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``DatabaseRef`` sync bounds its statement and refuses a result that does not fit its columns.

Before this, ``_load_database_source`` set no statement timeout on its throwaway pool, so an
uncancelled statement held the sync pass without bound. It also built the set from any result:
a ``value_column`` the result lacked gave every key a ``None`` value, a NULL key became the
literal key ``"None"``, and of two rows with one key the last silently won, each replacing the
last-good snapshot. Synthetic data only; no driver, no database (``_make_pool`` is faked).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import DEFAULT_DB_STATEMENT_TIMEOUT
from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.wiring import DatabaseRef, ReferenceSpec, Registry, WiringError, env
from messagefoundry.pipeline.reference_sync import (
    ReferenceColumnMismatch,
    ReferenceKeyRefused,
    ReferenceStatementTimedOut,
    ReferenceStatementTimeoutRefused,
    ReferenceSyncRunner,
    _load_database_source,
    reference_statement_timeout,
)
from messagefoundry.pipeline.wiring_runner import build_check_registry
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import database
from tests._fake_dbapi_driver import DriverError

_EGRESS = EgressSettings(deny_by_default=False)
_BASE: dict[str, Any] = {
    "server": "db.example",
    "database": "d",
    "key_column": "code",
    "statement": "SELECT code, value FROM codes",
}


class _Raw:
    """Stands in for the pyodbc connection under an aioodbc one: holds ``timeout``."""

    def __init__(self) -> None:
        self.timeout = 0
        self.at_cursor: int | None = None  # pyodbc applies the timeout when a cursor is made


class _RefusingRaw(_Raw):
    """A driver connection whose ``timeout`` setter fails as a refusal (no transient SQLSTATE)."""

    def __setattr__(self, attr: str, value: Any) -> None:
        if attr == "timeout" and value:
            raise DriverError("HYC00", "[HYC00] optional feature not implemented")
        object.__setattr__(self, attr, value)


class _Cursor:
    def __init__(self, rows: list[tuple[Any, ...]], columns: tuple[str, ...]) -> None:
        self.description = [(c,) for c in columns]
        self.rows = rows
        self.execute_error: BaseException | None = None
        self._pending: list[tuple[Any, ...]] = []

    async def execute(self, sql: str, params: Any = None) -> None:
        if self.execute_error is not None:
            raise self.execute_error
        self._pending = list(self.rows)

    async def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        rows, self._pending = self._pending[:size], self._pending[size:]
        return rows

    async def fetchall(self) -> list[tuple[Any, ...]]:
        rows, self._pending = self._pending, []
        return rows

    async def close(self) -> None:
        return None


class _Conn:
    def __init__(self, cur: _Cursor, raw: _Raw) -> None:
        self._conn = raw
        self.cur = cur

    async def cursor(self) -> _Cursor:
        self._conn.at_cursor = self._conn.timeout
        return self.cur


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self.conn = conn

    async def acquire(self) -> _Conn:
        return self.conn

    async def release(self, conn: _Conn) -> None:
        return None

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


def _patch_pool(
    monkeypatch: pytest.MonkeyPatch,
    rows: list[tuple[Any, ...]],
    *,
    columns: tuple[str, ...] = ("code", "value"),
    raw: _Raw | None = None,
) -> _Pool:
    pool = _Pool(_Conn(_Cursor(rows, columns), raw or _Raw()))

    async def fake_make_pool(dsn: str, pool_max: int, **_k: object) -> _Pool:
        return pool

    async def no_probe(*_a: object, **_k: object) -> database.LoginRoleReading:
        return database.LoginRoleReading(database.LoginRoleVerdict.CLEAN)

    monkeypatch.setattr(database, "_make_pool", fake_make_pool)
    monkeypatch.setattr(database, "probe_login_roles", no_probe)
    return pool


# --- the statement timeout --------------------------------------------------------------------------


async def test_the_sync_cursor_carries_the_default_statement_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red before the fix: the cursor was made with the driver's timeout untouched, 0, no limit."""
    pool = _patch_pool(monkeypatch, [("A", "1")])
    await _load_database_source(dict(_BASE), _EGRESS, name="codes")
    assert pool.conn._conn.at_cursor == DEFAULT_DB_STATEMENT_TIMEOUT


async def test_a_declared_statement_timeout_reaches_the_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _patch_pool(monkeypatch, [("A", "1")])
    await _load_database_source({**_BASE, "statement_timeout": 7}, _EGRESS, name="codes")
    assert pool.conn._conn.at_cursor == 7


async def test_a_timed_out_statement_fails_as_its_own_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _patch_pool(monkeypatch, [("A", "1")])
    pool.conn.cur.execute_error = DriverError("HYT00", "[HYT00] Query timeout expired SYN-DETAIL")
    with pytest.raises(ReferenceStatementTimedOut, match="statement_timeout=30s") as info:
        await _load_database_source(dict(_BASE), _EGRESS, name="codes")
    assert "SYN-DETAIL" not in str(info.value)
    assert info.value.__context__ is None


async def test_another_driver_error_is_not_read_as_a_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _patch_pool(monkeypatch, [("A", "1")])
    pool.conn.cur.execute_error = DriverError("42S02", "[42S02] Invalid object name")
    with pytest.raises(DriverError, match="42S02"):
        await _load_database_source(dict(_BASE), _EGRESS, name="codes")


async def test_a_driver_that_refuses_the_timeout_fails_as_its_own_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_pool(monkeypatch, [("A", "1")], raw=_RefusingRaw())
    with pytest.raises(ReferenceStatementTimeoutRefused, match="statement_timeout = 0") as info:
        await _load_database_source(dict(_BASE), _EGRESS, name="codes")
    assert info.value.__context__ is None


async def test_a_cursor_refusing_the_timeout_fails_as_the_refusal_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _patch_pool(monkeypatch, [("A", "1")])

    async def refuse_cursor() -> _Cursor:
        raise DriverError("HY092", "[HY092] invalid attribute")

    monkeypatch.setattr(pool.conn, "cursor", refuse_cursor)
    with pytest.raises(ReferenceStatementTimeoutRefused) as info:
        await _load_database_source(dict(_BASE), _EGRESS, name="codes")
    assert info.value.__context__ is None


async def test_a_hyt00_with_no_timeout_set_is_not_read_as_this_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _patch_pool(monkeypatch, [("A", "1")])
    pool.conn.cur.execute_error = DriverError("HYT00", "[HYT00] timeout")
    with pytest.raises(DriverError, match="HYT00"):
        await _load_database_source({**_BASE, "statement_timeout": 0}, _EGRESS, name="codes")


def test_databaseref_carries_and_checks_statement_timeout() -> None:
    spec = DatabaseRef(server="s", database="d", statement="SELECT 1 AS k", key_column="k")
    assert reference_statement_timeout(spec.settings) == DEFAULT_DB_STATEMENT_TIMEOUT
    spec = DatabaseRef(
        server="s", database="d", statement="SELECT 1 AS k", key_column="k", statement_timeout=0
    )
    assert reference_statement_timeout(spec.settings) == 0
    for bad in (-1, 1.5, True):
        with pytest.raises(WiringError, match="DATABASE reference source statement_timeout"):
            DatabaseRef(
                server="s",
                database="d",
                statement="SELECT 1 AS k",
                key_column="k",
                statement_timeout=bad,  # type: ignore[arg-type]
            )


def test_the_build_check_refuses_an_env_statement_timeout_the_sync_would_refuse() -> None:
    registry = Registry()
    registry.references["codes"] = ReferenceSpec(
        name="codes",
        source=DatabaseRef(
            server="db.example.org",
            database="d",
            statement="SELECT code, value FROM codes",
            key_column="code",
            statement_timeout=env("MEFOR_TEST_5891_TIMEOUT"),
        ),
    )

    def check(value: str) -> None:
        build_check_registry(
            registry,
            inbound_bind_host="127.0.0.1",
            env_values={"mefor_test_5891_timeout": value},
            egress=_EGRESS,
        )

    with pytest.raises(WiringError, match="DATABASE reference source statement_timeout"):
        check("1.5")
    check("45")  # the control


# --- rows that do not fit the declared columns -------------------------------------------------------


async def test_a_value_column_the_result_lacks_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Red before the fix: every key got the value ``None``."""
    _patch_pool(monkeypatch, [("A", "1"), ("B", "2")])
    with pytest.raises(ReferenceColumnMismatch, match="value_column is not among") as info:
        await _load_database_source({**_BASE, "value_column": "syn_col"}, _EGRESS, name="codes")
    assert "syn_col" not in str(info.value)  # a setting's value is never logged


async def test_a_key_column_the_result_holds_twice_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red before the fix: a join's second ``code`` column silently became the key."""
    _patch_pool(monkeypatch, [("A", "X", "1")], columns=("code", "code", "value"))
    with pytest.raises(ReferenceColumnMismatch, match="key_column names more than one"):
        await _load_database_source(dict(_BASE), _EGRESS, name="codes")


async def test_a_doubled_column_in_the_dict_shape_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red before the fix: of two ``name`` columns the dict kept only the last."""
    _patch_pool(monkeypatch, [("A", "x", "y")], columns=("code", "name", "name"))
    with pytest.raises(ReferenceColumnMismatch, match="holds a column name twice"):
        await _load_database_source(dict(_BASE), _EGRESS, name="codes")


async def test_a_doubled_other_column_is_fine_with_a_value_column(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_pool(monkeypatch, [("A", "x", "y", "1")], columns=("code", "name", "name", "value"))
    rows = await _load_database_source({**_BASE, "value_column": "value"}, _EGRESS, name="codes")
    assert rows == {"A": "1"}


async def test_a_null_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Red before the fix: the row was stored under the literal key ``"None"``."""
    _patch_pool(monkeypatch, [("A", "1"), (None, "2")])
    with pytest.raises(ReferenceKeyRefused, match=r"row #1 has a NULL key_column"):
        await _load_database_source(dict(_BASE), _EGRESS, name="codes")


async def test_a_duplicate_key_is_refused_without_naming_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red before the fix: the later row silently overwrote the earlier one."""
    _patch_pool(monkeypatch, [("SYN-KEY", "1"), ("B", "2"), ("SYN-KEY", "3")])
    with pytest.raises(ReferenceKeyRefused, match=r"rows #0 and #2") as info:
        await _load_database_source({**_BASE, "value_column": "value"}, _EGRESS, name="codes")
    assert "SYN-KEY" not in str(info.value)


async def test_a_fitting_result_still_builds_the_set(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_pool(monkeypatch, [("A", "1"), ("B", None)], columns=("code", "value"))
    assert await _load_database_source(dict(_BASE), _EGRESS, name="codes") == {
        "A": {"value": "1"},
        "B": {"value": None},
    }


async def test_a_refused_result_keeps_the_last_good_snapshot_and_logs_why(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    pool = _patch_pool(monkeypatch, [("A", "1"), ("B", "2")])
    spec = ReferenceSpec(
        name="codes",
        source=DatabaseRef(
            server="db.example",
            database="d",
            statement="SELECT code, value FROM codes",
            key_column="code",
            value_column="value",
        ),
    )
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        runner = ReferenceSyncRunner(store, lambda: [spec], ReferenceSettings(), egress=_EGRESS)
        assert (await runner.sync_all()).synced == 1
        good = dict(store.reference_view()["codes"])
        pool.conn.cur.rows = [("A", "9"), ("A", "8")]
        with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.reference_sync"):
            result = await runner.sync_all()
        assert result.failed == 1 and result.synced == 0
        assert dict(store.reference_view()["codes"]) == good
        assert "rows #0 and #1" in caplog.text
    finally:
        await store.close()
