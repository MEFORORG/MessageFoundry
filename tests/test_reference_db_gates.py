# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``DatabaseRef`` statement passes ``db_lookup``'s read-only statement test and a row ceiling
(BACKLOG #2617, slice 1).

Before this, ``_load_database_source`` ran the operator's statement on an autocommit pool with no
statement test and no read intent, and read the whole result with ``fetchall()``. Three things are
pinned here: the statement test at ``messagefoundry check`` and at every sync, the
``ApplicationIntent=ReadOnly`` DSN, and the ``max_rows`` ceiling, which refuses the sync rather than
truncating the set. Synthetic data only; no driver, no database (``_make_pool`` is faked).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.wiring import (
    DEFAULT_REFERENCE_MAX_ROWS,
    DatabaseRef,
    ReferenceSourceSpec,
    ReferenceSpec,
    Registry,
    WiringError,
    env,
)
from messagefoundry.pipeline.reference_sync import (
    ReferenceRowCeilingExceeded,
    ReferenceStatementRefused,
    ReferenceSyncError,
    ReferenceSyncRunner,
    _load_database_source,
    database_source_dsn,
    reference_max_rows,
    reference_statement,
)
from messagefoundry.pipeline.wiring_runner import build_check_registry
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import database

_EGRESS = EgressSettings(deny_by_default=False)
_BASE: dict[str, Any] = {"server": "db.example", "database": "d", "key_column": "code"}

# Each is refused by the db_lookup gate; the first is the stored-procedure shape the old DatabaseRef
# docstring invited.
_REFUSED = (
    "EXEC dbo.provider_codes",
    "UPDATE codes SET v = 1",
    "SELECT code INTO copy FROM codes",
    "SELECT code FROM codes; DELETE FROM codes",
    "WITH c AS (SELECT 1 AS code) DELETE FROM codes",
)


class _Cursor:
    """Counts every row it hands out, so a test sees how much left the driver."""

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.description = [("code",), ("value",)]
        self._all = rows
        self._pending: list[tuple[Any, ...]] = []
        self.handed_out = 0
        self.fetchall_calls = 0
        self.closed = False

    async def execute(self, sql: str, params: Any = None) -> None:
        self._pending = list(self._all)

    async def fetchall(self) -> list[tuple[Any, ...]]:
        self.fetchall_calls += 1
        rows, self._pending = self._pending, []
        self.handed_out += len(rows)
        return rows

    async def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        rows, self._pending = self._pending[:size], self._pending[size:]
        self.handed_out += len(rows)
        return rows

    async def close(self) -> None:
        self.closed = True


class _Conn:
    def __init__(self, cur: _Cursor) -> None:
        self.cur = cur

    async def cursor(self) -> _Cursor:
        return self.cur


class _Pool:
    def __init__(self, cur: _Cursor) -> None:
        self.conn = _Conn(cur)
        self.closed = False

    async def acquire(self) -> _Conn:
        return self.conn

    async def release(self, conn: _Conn) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _rows(n: int) -> list[tuple[Any, ...]]:
    return [(f"C{i}", f"V{i}") for i in range(n)]


def _patch_pool(monkeypatch: pytest.MonkeyPatch, rows: list[tuple[Any, ...]]) -> _Pool:
    pool = _Pool(_Cursor(rows))

    async def fake_make_pool(
        dsn: str, pool_max: int, *, autocommit: bool, login_timeout: int | None
    ) -> _Pool:
        return pool

    monkeypatch.setattr(database, "_make_pool", fake_make_pool)
    return pool


def _no_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse(*_a: object, **_k: object) -> object:
        raise AssertionError("the statement should have been refused before a pool was made")

    monkeypatch.setattr(database, "_make_pool", refuse)


# --- the statement test ----------------------------------------------------------------------------


@pytest.mark.parametrize("statement", _REFUSED)
async def test_the_sync_refuses_a_statement_the_lookup_gate_refuses(
    monkeypatch: pytest.MonkeyPatch, statement: str
) -> None:
    """Red before the fix: the sync dialled and ran the statement. Now nothing is dialled."""
    _no_pool(monkeypatch)
    with pytest.raises(ReferenceStatementRefused, match="DatabaseRef statement must be") as info:
        await _load_database_source({**_BASE, "statement": statement}, _EGRESS, name="codes")
    assert "reference set 'codes'" in str(info.value)
    assert statement not in str(info.value)  # the refusal never echoes the statement
    assert info.value.__cause__ is None and info.value.__context__ is None


async def test_the_sync_log_names_the_gate_and_not_the_lookup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The sync logs the error CLASS only. That class has to say which control refused the set,
    and must not read as a ``db_lookup`` failure."""
    _no_pool(monkeypatch)
    # Built without DatabaseRef, which would refuse the statement when declared: this is the
    # sync's backstop for a spec that reached the runner some other way.
    spec = ReferenceSpec(name="codes", source=_raw_source(statement="EXEC dbo.p"))
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        runner = ReferenceSyncRunner(store, lambda: [spec], ReferenceSettings(), egress=_EGRESS)
        with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.reference_sync"):
            result = await runner.sync_all()
        assert result.failed == 1 and result.synced == 0
        assert "codes" not in store.reference_view()
        text = caplog.text
        assert "ReferenceStatementRefused" in text
        assert "DbLookupError" not in text
    finally:
        await store.close()


def _check(registry: Registry, env_values: dict[str, Any] | None = None) -> None:
    build_check_registry(
        registry, inbound_bind_host="127.0.0.1", env_values=env_values or {}, egress=_EGRESS
    )


_REF_SETTINGS: dict[str, Any] = {
    "server": "db.example.org",
    "database": "d",
    "statement": "SELECT code, value FROM codes",
    "key_column": "code",
}


def _registry(**over: Any) -> Registry:
    registry = Registry()
    source = DatabaseRef(**{**_REF_SETTINGS, **over})
    registry.references["codes"] = ReferenceSpec(name="codes", source=source)
    return registry


def _raw_source(**over: Any) -> ReferenceSourceSpec:
    """A database reference source built without ``DatabaseRef``, so no declaration check runs."""
    return ReferenceSourceSpec("database", {**_REF_SETTINGS, **over})


def _raw_registry(**over: Any) -> Registry:
    registry = Registry()
    registry.references["codes"] = ReferenceSpec(name="codes", source=_raw_source(**over))
    return registry


@pytest.mark.parametrize("statement", _REFUSED)
def test_database_ref_refuses_the_statement_when_declared(statement: str) -> None:
    """Every path that loads the config refuses it, not only the build check, which
    ``messagefoundry check`` runs only with a ``messagefoundry.toml``."""
    with pytest.raises(WiringError, match="DatabaseRef statement must be") as info:
        DatabaseRef(**{**_REF_SETTINGS, "statement": statement})
    assert statement not in str(info.value)
    assert info.value.__cause__ is None and info.value.__context__ is None


@pytest.mark.parametrize("statement", _REFUSED)
def test_the_build_check_refuses_the_statement(statement: str) -> None:
    """Red before the fix: ``messagefoundry check`` passed a statement every sync would run."""
    with pytest.raises(WiringError, match="reference set 'codes': DatabaseRef statement must be"):
        _check(_raw_registry(statement=statement))


def test_the_build_check_labels_a_refused_statement_as_what_it_is() -> None:
    """A statement refusal is not a connector that failed to build. Red at eb180654f, where it read
    ``connector build failed: ...``."""
    with pytest.raises(WiringError) as info:
        _check(_raw_registry(statement="EXEC dbo.p"))
    text = str(info.value)
    assert text.startswith("reference statement refused (read-only statement test): ")
    assert "connector build failed" not in text


def test_the_build_check_refuses_the_statement_of_an_unprovisioned_set() -> None:
    """The statement is a literal, so it is tested even where an ``env()`` server does not resolve
    and the rest of the set is left to its sync."""
    registry = _raw_registry(server=env("MEFOR_TEST_2617_SERVER"), statement="EXEC dbo.p")
    with pytest.raises(WiringError, match="DatabaseRef statement must be"):
        _check(registry)
    _check(_registry(server=env("MEFOR_TEST_2617_SERVER")))  # the control: a SELECT passes


def test_an_env_statement_is_tested_once_resolved() -> None:
    """``DatabaseRef`` cannot read an ``env()`` statement, so it leaves it to the build check and the
    sync rather than failing the load on the ref object itself."""
    registry = _registry(statement=env("MEFOR_TEST_2617_SQL"))
    with pytest.raises(WiringError, match="DatabaseRef statement must be"):
        _check(registry, {"mefor_test_2617_sql": "EXEC dbo.p"})
    _check(registry, {"mefor_test_2617_sql": "SELECT code, value FROM codes"})  # the control


def test_the_build_check_passes_a_read_only_statement() -> None:
    for statement in (
        "SELECT code, value FROM codes",
        "WITH c AS (SELECT code, value FROM codes) SELECT code, value FROM c;",
        "SELECT code, 'EXEC' AS value FROM codes -- a keyword in a literal or a comment is data",
    ):
        _check(_registry(statement=statement))


def test_reference_statement_returns_a_passing_statement() -> None:
    assert reference_statement({"statement": "SELECT a FROM t"}) == "SELECT a FROM t"
    # An absent statement is a missing setting, not a statement the gate refused.
    with pytest.raises(ReferenceSyncError, match="requires a 'statement'") as info:
        reference_statement({}, name="codes")
    assert not isinstance(info.value, ReferenceStatementRefused)
    assert issubclass(ReferenceStatementRefused, ReferenceSyncError)


# --- the read intent ---------------------------------------------------------------------------------


def test_the_reference_dsn_advertises_read_only_intent() -> None:
    """Red before the fix: the sync's DSN carried no ApplicationIntent."""
    dsn = database_source_dsn(dict(_BASE))
    assert "ApplicationIntent=ReadOnly" in dsn
    # A head part, as odbc_connection_string requires of every keyword but the TLS ones. The
    # position is not the TLS guard; messagefoundry.odbc_dsn says what is.
    assert dsn.index("ApplicationIntent") < dsn.index("Encrypt=")


# --- the row ceiling --------------------------------------------------------------------------------


async def test_the_sync_refuses_more_rows_than_max_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Red before the fix: the whole result was read with fetchall() and materialized."""
    pool = _patch_pool(monkeypatch, _rows(50))
    settings = {**_BASE, "statement": "SELECT code, value FROM t", "max_rows": 10}
    with pytest.raises(ReferenceRowCeilingExceeded, match="max_rows=10") as info:
        await _load_database_source(settings, _EGRESS, name="codes")
    cur = pool.conn.cur
    assert cur.fetchall_calls == 0
    assert cur.handed_out == 11  # one past the ceiling, never the whole result
    assert cur.closed is True and pool.closed is True
    assert "C0" not in str(info.value) and "V0" not in str(info.value)  # no row in the text


async def test_exactly_max_rows_rows_load(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_pool(monkeypatch, _rows(10))
    settings = {**_BASE, "statement": "SELECT code, value FROM t", "max_rows": 10}
    loaded = await _load_database_source(settings, _EGRESS)
    assert len(loaded) == 10 and loaded["C9"] == {"value": "V9"}


async def test_max_rows_zero_turns_the_ceiling_off(monkeypatch: pytest.MonkeyPatch) -> None:
    for off in (0, "0"):
        pool = _patch_pool(monkeypatch, _rows(30))
        settings = {**_BASE, "statement": "SELECT code, value FROM t", "max_rows": off}
        loaded = await _load_database_source(settings, _EGRESS)
        assert len(loaded) == 30
        assert pool.conn.cur.fetchall_calls == 1


async def test_the_default_ceiling_applies_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    assert reference_max_rows({}) == DEFAULT_REFERENCE_MAX_ROWS == 100_000
    pool = _patch_pool(monkeypatch, _rows(3))
    loaded = await _load_database_source(
        {**_BASE, "statement": "SELECT code, value FROM t"}, _EGRESS
    )
    assert len(loaded) == 3 and pool.conn.cur.fetchall_calls == 0


async def test_a_sync_over_the_ceiling_keeps_the_last_good_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    spec = ReferenceSpec(
        name="codes",
        source=DatabaseRef(
            server="db.example",
            database="d",
            statement="SELECT code, value FROM t",
            key_column="code",
            value_column="value",
            max_rows=5,
        ),
    )
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        runner = ReferenceSyncRunner(store, lambda: [spec], ReferenceSettings(), egress=_EGRESS)
        _patch_pool(monkeypatch, _rows(5))
        assert (await runner.sync_all()).synced == 1
        good = dict(store.reference_view()["codes"])
        assert len(good) == 5
        _patch_pool(monkeypatch, _rows(6))
        with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.reference_sync"):
            result = await runner.sync_all()
        assert result.failed == 1 and result.synced == 0
        assert dict(store.reference_view()["codes"]) == good  # last-good kept, not truncated
        assert "ReferenceRowCeilingExceeded" in caplog.text
    finally:
        await store.close()


# --- max_rows is read by one rule at declaration, at check and at sync ------------------------------


@pytest.mark.parametrize("bad", [-1, True, 2.5, "abc", "-3"])
def test_database_ref_refuses_a_bad_max_rows_when_declared(bad: object) -> None:
    over: dict[str, Any] = {"max_rows": bad}
    with pytest.raises(WiringError, match="DATABASE reference source max_rows") as info:
        DatabaseRef(server="s", database="d", statement="SELECT a", key_column="a", **over)
    assert "value withheld" in str(info.value)


def test_database_ref_accepts_a_count_zero_or_an_env_ref() -> None:
    for good in (1, 250_000, 0, "0", " 7 ", env("MEFOR_TEST_2617_ROWS")):
        over: dict[str, Any] = {"max_rows": good}
        spec = DatabaseRef(server="s", database="d", statement="SELECT a", key_column="a", **over)
        assert spec.settings["max_rows"] is good
    default = DatabaseRef(server="s", database="d", statement="SELECT a", key_column="a")
    assert default.settings["max_rows"] == DEFAULT_REFERENCE_MAX_ROWS


def test_the_build_check_refuses_an_env_max_rows_the_sync_would_refuse() -> None:
    registry = _registry(max_rows=env("MEFOR_TEST_2617_ROWS"))
    with pytest.raises(WiringError, match="DATABASE reference source max_rows"):
        _check(registry, {"mefor_test_2617_rows": "-5"})
    _check(registry, {"mefor_test_2617_rows": "500"})  # the control


async def test_the_sync_refuses_a_bad_max_rows_before_a_pool_is_made(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_pool(monkeypatch)
    with pytest.raises(ValueError, match="DATABASE reference source max_rows"):
        await _load_database_source(
            {**_BASE, "statement": "SELECT a FROM t", "max_rows": "-1"}, _EGRESS
        )
