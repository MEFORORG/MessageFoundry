"""DATABASE destination connector (ADR 0003): param binding, error classification, DSN/TLS, egress.

The aioodbc/pyodbc driver is never imported — the pool is faked, and error classification is duck-typed
on the SQLSTATE, so the full logic is unit-tested without a real SQL Server (the live round-trip is
CI-service-container-gated, like the SQL Server store backend).
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Database, WiringError
from messagefoundry.pipeline.wiring_runner import check_egress_allowed
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.database import (
    DatabaseDestination,
    _bind_params,
    _build_dsn,
    _classify_db_error,
    _is_transient,
    _parse_named_params,
    _sqlstate,
)

INSERT = "INSERT INTO obs (mrn, val) VALUES (:mrn, :val)"


def _dest(**over: Any) -> DatabaseDestination:
    base: dict[str, Any] = dict(server="sql.example.com", database="MFDB", statement=INSERT)
    base.update(over)
    d = build_destination(
        Destination(name="OB_DB", type=ConnectorType.DATABASE, settings=Database(**base).settings)
    )
    assert isinstance(d, DatabaseDestination)
    return d


# --- pure helpers ------------------------------------------------------------


def test_parse_named_params_translates_to_positional() -> None:
    sql, names = _parse_named_params(INSERT)
    assert sql == "INSERT INTO obs (mrn, val) VALUES (?, ?)"
    assert names == ["mrn", "val"]


def test_parse_named_params_skips_literals_and_casts() -> None:
    # A time literal '12:30' and a ::cast must NOT be mistaken for parameters.
    sql, names = _parse_named_params("SELECT x::int WHERE t = '12:30' AND id = :id")
    assert sql == "SELECT x::int WHERE t = '12:30' AND id = ?"
    assert names == ["id"]


def test_bind_params_orders_values() -> None:
    assert _bind_params('{"mrn": "1", "val": "x"}', ["mrn", "val"]) == ("1", "x")


@pytest.mark.parametrize("payload", ["not json", "[1, 2]", '{"mrn": "1"}'])
def test_bind_params_bad_payload_is_permanent(payload: str) -> None:
    with pytest.raises(NegativeAckError) as ei:
        _bind_params(payload, ["mrn", "val"])
    assert ei.value.permanent is True


def test_is_transient_by_sqlstate() -> None:
    assert _is_transient("08S01") and _is_transient("40001") and _is_transient("HYT00")
    assert not _is_transient("23000") and not _is_transient("42000")


def test_classify_db_error() -> None:
    assert type(_classify_db_error("08S01", "x")) is DeliveryError  # transient → retry
    permanent = _classify_db_error("23000", "constraint")
    assert isinstance(permanent, NegativeAckError) and permanent.permanent is True


def test_sqlstate_extraction() -> None:
    assert _sqlstate(Exception("08S01", "msg")) == "08S01"
    assert (
        _sqlstate(ValueError("some bug")) is None
    )  # not SQLSTATE-shaped → propagates as a code bug
    assert _sqlstate(Exception("123", "x")) is None  # wrong length


def test_build_dsn_secure_defaults() -> None:
    dsn = _build_dsn(
        {"server": "sql.example.com", "database": "MFDB", "username": "u", "password": "p"}
    )
    assert "SERVER={sql.example.com},1433" in dsn
    assert "DATABASE={MFDB}" in dsn
    assert "UID={u}" in dsn and "PWD={p}" in dsn
    assert dsn.rstrip(";").endswith("Encrypt=yes;TrustServerCertificate=no")  # security flags last


def test_build_dsn_braces_neutralize_injection() -> None:
    dsn = _build_dsn({"server": "s", "database": "MFDB", "password": "p};DROP", "username": "u"})
    assert "PWD={p}};DROP}" in dsn  # the inner } is doubled, so it can't close the brace early


def test_build_dsn_weak_tls_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError):
        _build_dsn({"server": "s", "database": "d", "encrypt": False})


def test_build_dsn_weak_tls_allowed_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    assert "Encrypt=no" in _build_dsn({"server": "s", "database": "d", "encrypt": False})


def test_build_dsn_bad_auth() -> None:
    with pytest.raises(ValueError):
        _build_dsn({"server": "s", "database": "d", "auth": "kerberos"})


@pytest.mark.parametrize("missing", ["server", "database", "statement"])
def test_requires_core_settings(missing: str) -> None:
    base: dict[str, Any] = dict(server="s", database="d", statement=INSERT)
    base[missing] = ""
    with pytest.raises(ValueError):
        build_destination(
            Destination(name="OB", type=ConnectorType.DATABASE, settings=Database(**base).settings)
        )


# --- send() with a faked pool (no driver) ------------------------------------


class _FakeCursor:
    def __init__(self, exc: Exception | None = None) -> None:
        self.executed: list[tuple[str, tuple[Any, ...]]] = []
        self._exc = exc

    async def execute(self, sql: str, params: tuple[Any, ...]) -> None:
        self.executed.append((sql, params))
        if self._exc is not None:
            raise self._exc


class _FakeConn:
    def __init__(self, cur: _FakeCursor) -> None:
        self._cur = cur
        self.committed = False
        self.rolledback = False

    async def cursor(self) -> _FakeCursor:
        return self._cur

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolledback = True


class _FakePool:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn
        self.released: list[_FakeConn] = []

    async def acquire(self) -> _FakeConn:
        return self._conn

    async def release(self, conn: _FakeConn) -> None:
        self.released.append(conn)


async def test_send_executes_and_commits() -> None:
    cur = _FakeCursor()
    conn = _FakeConn(cur)
    dest = _dest()
    dest._pool = _FakePool(conn)
    await dest.send('{"mrn": "1", "val": "x"}')
    assert cur.executed == [("INSERT INTO obs (mrn, val) VALUES (?, ?)", ("1", "x"))]
    assert conn.committed and not conn.rolledback


async def test_send_permanent_db_error_dead_letters() -> None:
    conn = _FakeConn(_FakeCursor(Exception("23000", "constraint violation")))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(NegativeAckError) as ei:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert ei.value.permanent is True
    assert conn.rolledback


async def test_send_transient_db_error_retries() -> None:
    conn = _FakeConn(_FakeCursor(Exception("08S01", "connection lost")))
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(DeliveryError) as ei:
        await dest.send('{"mrn": "1", "val": "x"}')
    assert not isinstance(ei.value, NegativeAckError)  # transient → retry, not dead-letter
    assert conn.rolledback


async def test_send_non_db_error_propagates() -> None:
    conn = _FakeConn(_FakeCursor(ValueError("a real bug")))  # args[0] not SQLSTATE-shaped
    dest = _dest()
    dest._pool = _FakePool(conn)
    with pytest.raises(ValueError):
        await dest.send('{"mrn": "1", "val": "x"}')
    assert conn.rolledback


async def test_send_bad_payload_is_permanent_before_any_connection() -> None:
    dest = _dest()  # no pool injected — a bad payload fails before _get_pool is reached
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("not json")
    assert ei.value.permanent is True


# --- egress allowlist --------------------------------------------------------


def _db_dest(server: str, port: int = 1433) -> Destination:
    return Destination(
        name="OB",
        type=ConnectorType.DATABASE,
        settings=Database(server=server, database="d", statement=INSERT, port=port).settings,
    )


def test_egress_blocks_unlisted_server() -> None:
    with pytest.raises(WiringError):
        check_egress_allowed(
            _db_dest("other.example.com"), EgressSettings(allowed_db=["sql.example.com"])
        )


def test_egress_permits_listed_server() -> None:
    check_egress_allowed(
        _db_dest("sql.example.com"), EgressSettings(allowed_db=["sql.example.com"])
    )


def test_egress_host_port_match() -> None:
    egress = EgressSettings(allowed_db=["sql.example.com:1433"])
    check_egress_allowed(_db_dest("sql.example.com", 1433), egress)  # ok
    with pytest.raises(WiringError):
        check_egress_allowed(_db_dest("sql.example.com", 1434), egress)  # wrong port


def test_egress_unrestricted_when_empty() -> None:
    check_egress_allowed(_db_dest("anywhere.example"), EgressSettings())  # empty = unrestricted
