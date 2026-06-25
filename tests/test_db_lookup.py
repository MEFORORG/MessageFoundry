# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for handler-callable live db_lookup (ADR 0010).

Covers the accessor + active-runner indirection (config/db_lookup.py), the pooled executor against a
FAKED aioodbc pool (transports/database.py), the DatabaseLookup factory + Registry table (config/
wiring.py), the fail-closed egress gate, and the end-to-end dry-run-raises behavior. Synthetic data only.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry import db_lookup
from messagefoundry.config.db_lookup import DbLookupError, activated
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    MLLP,
    DatabaseLookup,
    Registry,
    WiringError,
    build_inbound_connection,
)
from messagefoundry.pipeline import dryrun
from messagefoundry.pipeline.wiring_runner import check_lookup_allowed
from messagefoundry.store import MessageStatus
from messagefoundry.transports import database
from messagefoundry.transports.database import DatabaseLookupExecutor

# --- a faked aioodbc pool/conn/cursor (no driver, no DB) ----------------------


class _FakeCursor:
    def __init__(self, rows: list[tuple[Any, ...]], columns: list[str], error: Exception | None):
        self._rows = rows
        self._columns = columns
        self._error = error
        self.description = [(c,) for c in columns] if columns else None
        self.executed: tuple[str, tuple[Any, ...]] | None = None

    async def execute(self, sql: str, params: tuple[Any, ...]) -> None:
        self.executed = (sql, params)
        if self._error is not None:
            raise self._error

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)


class _FakeConn:
    def __init__(self, cursor: _FakeCursor):
        self._cursor = cursor

    async def cursor(self) -> _FakeCursor:
        return self._cursor


class _FakePool:
    def __init__(self, cursor: _FakeCursor):
        self.cursor_obj = cursor
        self.acquired = 0
        self.released = 0
        self.closed = False

    async def acquire(self) -> _FakeConn:
        self.acquired += 1
        return _FakeConn(self.cursor_obj)

    async def release(self, conn: _FakeConn) -> None:
        self.released += 1

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _patch_pool(
    monkeypatch: pytest.MonkeyPatch,
    *,
    rows: list[tuple[Any, ...]] | None = None,
    columns: list[str] | None = None,
    error: Exception | None = None,
) -> _FakePool:
    """Replace the module-level _make_pool so the executor gets a fake pool (no aioodbc, no DB)."""
    pool = _FakePool(_FakeCursor(rows or [], columns or [], error))

    async def fake_make_pool(dsn: str, pool_max: int, *, autocommit: bool) -> _FakePool:
        return pool

    monkeypatch.setattr(database, "_make_pool", fake_make_pool)
    return pool


_CONN = {"clarity": {"server": "db.local", "database": "Clarity"}}


# --- accessor + active-runner indirection ------------------------------------


def test_db_lookup_raises_with_no_active_runner() -> None:
    # Outside a live Handler (Router / dry-run / no lookups) there is no runner → fail loud.
    with pytest.raises(DbLookupError, match="unavailable here"):
        db_lookup("clarity", "SELECT 1", {})


def test_db_lookup_delegates_to_active_runner() -> None:
    calls: list[tuple[str, str, Any]] = []

    def runner(connection: str, statement: str, params: Any) -> list[dict[str, Any]]:
        calls.append((connection, statement, params))
        return [{"npi": "123"}]

    with activated(runner):
        rows = db_lookup("clarity", "SELECT npi FROM p WHERE mrn = :mrn", {"mrn": "M1"})
    assert rows == [{"npi": "123"}]
    assert calls == [("clarity", "SELECT npi FROM p WHERE mrn = :mrn", {"mrn": "M1"})]
    # The runner is reset on exit — calling again raises.
    with pytest.raises(DbLookupError):
        db_lookup("clarity", "SELECT 1", {})


# --- the pooled executor (faked driver) --------------------------------------


async def test_executor_query_returns_rows_as_dicts(monkeypatch: pytest.MonkeyPatch) -> None:
    pool = _patch_pool(
        monkeypatch, rows=[("123", "Smith"), ("456", "Jones")], columns=["npi", "name"]
    )
    ex = DatabaseLookupExecutor(_CONN)
    rows = await ex.query("clarity", "SELECT npi, name FROM p WHERE mrn = :mrn", {"mrn": "M1"})
    assert rows == [{"npi": "123", "name": "Smith"}, {"npi": "456", "name": "Jones"}]
    # :name placeholders are translated to positional and bound in order.
    assert pool.cursor_obj.executed is not None
    sql, params = pool.cursor_obj.executed
    assert ":mrn" not in sql and "?" in sql
    assert params == ("M1",)
    assert pool.acquired == 1 and pool.released == 1  # connection always released


async def test_executor_empty_result(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_pool(monkeypatch, rows=[], columns=["npi"])
    ex = DatabaseLookupExecutor(_CONN)
    assert await ex.query("clarity", "SELECT npi FROM p WHERE mrn = :mrn", {"mrn": "X"}) == []


async def test_executor_unknown_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_pool(monkeypatch)
    ex = DatabaseLookupExecutor(_CONN)
    with pytest.raises(DbLookupError, match="no DatabaseLookup connection named 'nope'"):
        await ex.query("nope", "SELECT 1", {})


async def test_executor_missing_param(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_pool(monkeypatch, columns=["npi"])
    ex = DatabaseLookupExecutor(_CONN)
    with pytest.raises(DbLookupError, match="missing parameter"):
        await ex.query("clarity", "SELECT npi FROM p WHERE mrn = :mrn", {})  # no 'mrn'


async def test_executor_db_error_is_phi_free(monkeypatch: pytest.MonkeyPatch) -> None:
    # A driver error carrying a SQLSTATE (args[0]) is wrapped as DbLookupError naming the connection +
    # state only — never the statement, params, or data.
    pool = _patch_pool(monkeypatch, columns=["npi"], error=Exception("08S01", "connection reset"))
    ex = DatabaseLookupExecutor(_CONN)
    secret_sql = "SELECT npi FROM patient WHERE ssn = :ssn"
    with pytest.raises(DbLookupError) as ei:
        await ex.query("clarity", secret_sql, {"ssn": "000-00-0000"})
    msg = str(ei.value)
    assert "clarity" in msg and "08S01" in msg
    assert "ssn" not in msg and "000-00-0000" not in msg and "patient" not in msg
    assert pool.released == 1  # released even on error


async def test_executor_aclose_closes_pools(monkeypatch: pytest.MonkeyPatch) -> None:
    pool = _patch_pool(monkeypatch, columns=["x"])
    ex = DatabaseLookupExecutor(_CONN)
    await ex.query("clarity", "SELECT x", {})  # opens the pool lazily
    await ex.aclose()
    assert pool.closed is True


def test_executor_requires_server_and_database() -> None:
    with pytest.raises(ValueError, match="requires a 'database'"):
        DatabaseLookupExecutor({"bad": {"server": "db.local"}})


# --- DatabaseLookup factory + Registry table ---------------------------------


def test_database_lookup_factory_registers(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.config import wiring

    reg = Registry()
    monkeypatch.setattr(wiring, "_active", reg)
    DatabaseLookup("clarity", server="db.local", database="Clarity")
    assert "clarity" in reg.lookups
    assert reg.lookups["clarity"].settings["server"] == "db.local"


def test_database_lookup_duplicate_name(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.config import wiring

    reg = Registry()
    monkeypatch.setattr(wiring, "_active", reg)
    DatabaseLookup("clarity", server="a", database="A")
    with pytest.raises(WiringError, match="duplicate database lookup"):
        DatabaseLookup("clarity", server="b", database="B")


# --- fail-closed egress gate -------------------------------------------------


def test_check_lookup_allowed_permits_allowlisted_host() -> None:
    egress = EgressSettings(allowed_db=["db.local:1433"])
    check_lookup_allowed("clarity", {"server": "db.local", "port": 1433}, egress)  # no raise


def test_check_lookup_allowed_denies_unlisted_host() -> None:
    egress = EgressSettings(allowed_db=["db.local:1433"])
    with pytest.raises(WiringError, match="not in the \\[egress\\].allowed_db"):
        check_lookup_allowed("clarity", {"server": "evil.example", "port": 1433}, egress)


def test_check_lookup_allowed_unrestricted_when_empty() -> None:
    check_lookup_allowed(
        "clarity", {"server": "anything", "port": 1433}, EgressSettings()
    )  # no raise


# --- end-to-end: dry-run raises (db_lookup is the live-lookup exception) ------


def test_dry_run_raises_when_handler_calls_db_lookup() -> None:
    reg = Registry()
    reg.add_router("r", lambda msg: ["h"])  # type: ignore[no-untyped-def, arg-type]

    def handler(msg: Any) -> None:
        db_lookup("clarity", "SELECT npi FROM p WHERE mrn = :mrn", {"mrn": msg["PID-3.1"]})
        return None

    reg.add_handler("h", handler)  # type: ignore[arg-type]
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=2575), router="r"))
    raw = "MSH|^~\\&|S|F|R|F|20260614||ADT^A01|1|P|2.5\rPID|1||M1^^^MR\r"
    result = dryrun.dry_run(reg, raw, inbound="IB")
    assert result.disposition is MessageStatus.ERROR
    assert "db_lookup" in (result.error or "")


# --- S12 audit anchors (ADDED-4): HL7-as-untrusted-input at db_lookup ----------
# The S12 audit verdict for the db_lookup boundary is CONFORMING (PHI-2/REL-2/NET-2/PROC-1). These pin
# the load-bearing invariants. NOTE — write/read-only is enforced by *parameterization* (a value can
# never inject a write) + the documented read-only contract + the autocommit pool; there is no
# statement-keyword write-blocker. So a Handler AUTHOR could still pass a literal write statement: that
# is the author's contract, not an attacker-influenceable path. See the audit memo + backlog note S12-1.


async def test_audit_attacker_value_cannot_inject_a_write(monkeypatch: pytest.MonkeyPatch) -> None:
    # The threat is untrusted HL7 reaching the DB. A hostile field value is bound as a PARAMETER, never
    # interpolated into SQL — so it can never become a `; DROP TABLE` / write. Pin: the value lands in
    # the positional params tuple and the SQL keeps its single placeholder, byte-for-byte.
    pool = _patch_pool(monkeypatch, rows=[], columns=["npi"])
    ex = DatabaseLookupExecutor(_CONN)
    hostile = "1; DROP TABLE patient; --"  # an attacker-influenced HL7 field value
    await ex.query("clarity", "SELECT npi FROM p WHERE mrn = :mrn", {"mrn": hostile})
    assert pool.cursor_obj.executed is not None
    sql, params = pool.cursor_obj.executed
    assert params == (hostile,)  # carried as data, not SQL
    assert sql.count("?") == 1 and "DROP" not in sql  # the hostile text never reached the statement


async def test_audit_query_runs_via_autocommit_readonly_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Read-only posture: the lookup pool is opened with autocommit=True (each query is its own implicit,
    # uncommitted-state-free transaction — nothing here issues a write/commit path). Pin the pool flag so
    # a refactor can't silently open a writable transactional pool for live lookups.
    seen: dict[str, bool] = {}
    real_pool = _patch_pool(monkeypatch, rows=[], columns=["npi"])

    async def spy_make_pool(dsn: str, pool_max: int, *, autocommit: bool):  # type: ignore[no-untyped-def]
        seen["autocommit"] = autocommit
        return real_pool

    monkeypatch.setattr(database, "_make_pool", spy_make_pool)
    ex = DatabaseLookupExecutor(_CONN)
    await ex.query("clarity", "SELECT npi FROM p WHERE mrn = :mrn", {"mrn": "M1"})
    assert seen["autocommit"] is True


def test_audit_db_lookup_egress_gate_is_allowed_db(monkeypatch: pytest.MonkeyPatch) -> None:
    # NET-2: a DatabaseLookup dials out, so it is gated by [egress].allowed_db SPECIFICALLY (not a
    # different transport's list). An unlisted server is refused fail-closed at load/reload/start.
    egress = EgressSettings(allowed_db=["db.local:1433"])
    with pytest.raises(WiringError, match="\\[egress\\].allowed_db"):
        check_lookup_allowed("clarity", {"server": "exfil.evil", "port": 1433}, egress)
