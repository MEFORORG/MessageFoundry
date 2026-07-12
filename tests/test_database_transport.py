# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DATABASE destination connector (ADR 0003): param binding, error classification, DSN/TLS, egress.

The aioodbc/pyodbc driver is never imported — the pool is faked, and error classification is duck-typed
on the SQLSTATE, so the full logic is unit-tested without a real SQL Server. The live aioodbc round-trip
is exercised separately by the gated integration suite (test_database_connector_integration.py).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from datetime import datetime
from decimal import Decimal
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Database, DatabasePoll, WiringError
from messagefoundry.pipeline.wiring_runner import check_egress_allowed, check_source_allowed
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.database import (
    DatabaseDestination,
    DatabaseSource,
    _bind_params,
    _build_connection,
    _build_dsn,
    _build_odbc_dsn,
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
    # SERVER is emitted UNBRACED (validated, not brace-quoted) so the driver parses the ",port" suffix
    # and the TLS handshake resolves the host — a brace-quoted "SERVER={host},port" is malformed ODBC
    # and breaks certificate handling against a real SQL Server (mirrors the store's connection_string).
    assert "SERVER=sql.example.com,1433" in dsn
    assert "SERVER={" not in dsn  # never brace the host
    assert "DATABASE={MFDB}" in dsn
    assert "UID={u}" in dsn and "PWD={p}" in dsn
    assert dsn.rstrip(";").endswith("Encrypt=yes;TrustServerCertificate=no")  # security flags last


def test_build_dsn_braces_neutralize_injection() -> None:
    dsn = _build_dsn({"server": "s", "database": "MFDB", "password": "p};DROP", "username": "u"})
    assert "PWD={p}};DROP}" in dsn  # the inner } is doubled, so it can't close the brace early


@pytest.mark.parametrize("bad", ["host;DROP", "host}xx", "host{xx", "a=b", "host\nx"])
def test_build_dsn_rejects_server_injection(bad: str) -> None:
    # The SERVER value is unbraced, so it is *validated* (not brace-quoted) to carry no ODBC
    # connection-string metacharacters — an attacker-influenced host can't inject extra keywords.
    with pytest.raises(ValueError, match="server must not contain"):
        _build_dsn({"server": bad, "database": "d", "username": "u", "password": "p"})


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


# --- generic ODBC dialect (#66) ---------------------------------------------


def test_build_connection_sqlserver_is_byte_identical() -> None:
    # The default dialect must be byte-identical to the SQL Server preset (_build_dsn) + report weakened.
    s = {"server": "sql.example.com", "database": "MFDB", "username": "u", "password": "p"}
    dsn, weakened = _build_connection(dict(s))
    assert dsn == _build_dsn(dict(s))
    assert weakened is False


def test_build_connection_dispatches_generic() -> None:
    s = {"dialect": "generic", "odbc_driver": "PostgreSQL Unicode", "server": "db.example"}
    dsn, weakened = _build_connection(dict(s))
    assert dsn == _build_odbc_dsn(dict(s))
    # Generic path never reports weakened — TLS is the operator's responsibility on this path.
    assert weakened is False


def test_build_connection_rejects_unknown_dialect() -> None:
    with pytest.raises(ValueError, match="dialect must be"):
        _build_connection({"dialect": "mongo", "server": "s"})


def test_build_odbc_dsn_postgres_shape() -> None:
    dsn = _build_odbc_dsn(
        {
            "odbc_driver": "PostgreSQL Unicode",
            "server": "db.example",
            "database": "mefor",
            "username": "svc",
            "password": "pw",
            "odbc_params": {"PORT": 5432, "SSLmode": "verify-full"},
        }
    )
    assert "DRIVER={PostgreSQL Unicode}" in dsn
    assert "SERVER=db.example" in dsn and "SERVER={" not in dsn  # host unbraced, like the SS preset
    assert "DATABASE={mefor}" in dsn
    assert "UID={svc}" in dsn and "PWD={pw}" in dsn  # default credential keywords
    assert "PORT={5432}" in dsn and "SSLmode={verify-full}" in dsn
    # No SQL-Server TLS keywords are forced onto the generic path.
    assert "Encrypt=" not in dsn and "TrustServerCertificate=" not in dsn


def test_build_odbc_dsn_no_weak_tls_refusal() -> None:
    # A generic DSN with no TLS keyword is NOT refused (unlike the SQL Server preset with encrypt=false)
    # — MessageFoundry cannot introspect an arbitrary driver's TLS posture; the operator owns it.
    dsn = _build_odbc_dsn({"odbc_driver": "MySQL ODBC 8.0 Unicode Driver", "server": "db.example"})
    assert dsn.startswith("DRIVER={MySQL ODBC 8.0 Unicode Driver};SERVER=db.example")


def test_generic_dsn_warns_when_no_tls_keyword(caplog: pytest.LogCaptureFixture) -> None:
    # Fail-safe visibility (#66 review): the generic path can't enforce/introspect TLS, so with no
    # ssl/tls/encrypt keyword in odbc_params it must WARN loudly rather than silently cross in plaintext.
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.database"):
        _build_odbc_dsn({"odbc_driver": "PostgreSQL Unicode", "server": "db.example"})
    assert any("TLS verification is NOT enforced" in r.getMessage() for r in caplog.records)


def test_generic_dsn_no_warn_when_tls_keyword_present(caplog: pytest.LogCaptureFixture) -> None:
    # An operator who set a TLS keyword (SSLmode) has taken ownership → no WARNING (DEBUG only).
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.database"):
        _build_odbc_dsn(
            {
                "odbc_driver": "PostgreSQL Unicode",
                "server": "db.example",
                "odbc_params": {"SSLmode": "verify-full"},
            }
        )
    assert not any("TLS verification is NOT enforced" in r.getMessage() for r in caplog.records)


def test_build_odbc_dsn_custom_credential_keywords() -> None:
    dsn = _build_odbc_dsn(
        {
            "odbc_driver": "MySQL ODBC 8.0 Unicode Driver",
            "server": "db.example",
            "username": "svc",
            "password": "pw",
            "odbc_user_key": "USER",
            "odbc_password_key": "PASSWORD",
        }
    )
    assert "USER={svc}" in dsn and "PASSWORD={pw}" in dsn


def test_build_odbc_dsn_requires_driver() -> None:
    with pytest.raises(ValueError, match="requires an 'odbc_driver'"):
        _build_odbc_dsn({"server": "db.example"})


def test_build_odbc_dsn_brace_quotes_values() -> None:
    # An injection attempt in a param value can't close the brace early (the inner } is doubled).
    dsn = _build_odbc_dsn(
        {"odbc_driver": "PostgreSQL Unicode", "server": "db.example", "password": "p};DROP"}
    )
    assert "PWD={p}};DROP}" in dsn


@pytest.mark.parametrize("bad", ["host;x", "host{x", "host=x", "host\nx"])
def test_build_odbc_dsn_rejects_server_injection(bad: str) -> None:
    with pytest.raises(ValueError, match="server must not contain"):
        _build_odbc_dsn({"odbc_driver": "PostgreSQL Unicode", "server": bad})


@pytest.mark.parametrize("bad_key", ["a;b", "a=b", "a{b", "1abc", "a\nb"])
def test_build_odbc_dsn_rejects_bad_param_key(bad_key: str) -> None:
    with pytest.raises(ValueError, match="not a valid ODBC keyword"):
        _build_odbc_dsn(
            {"odbc_driver": "PostgreSQL Unicode", "server": "s", "odbc_params": {bad_key: "v"}}
        )


@pytest.mark.parametrize("reserved", ["DRIVER", "server", "Database"])
def test_build_odbc_dsn_rejects_reserved_param_key(reserved: str) -> None:
    with pytest.raises(ValueError, match="must not set"):
        _build_odbc_dsn(
            {"odbc_driver": "PostgreSQL Unicode", "server": "s", "odbc_params": {reserved: "v"}}
        )


def test_generic_destination_builds_without_database() -> None:
    # The generic dialect may omit `database` (e.g. Oracle service name) — the destination still builds.
    d = build_destination(
        Destination(
            name="OB_DB_GEN",
            type=ConnectorType.DATABASE,
            settings=Database(
                server="db.example",
                dialect="generic",
                odbc_driver="PostgreSQL Unicode",
                statement=INSERT,
                odbc_params={"PORT": "5432"},
            ).settings,
        )
    )
    assert isinstance(d, DatabaseDestination)
    assert d._dialect == "generic"
    assert d._weakened_tls is False  # generic never crosses the weakened-TLS machinery


def test_sqlserver_destination_still_requires_database() -> None:
    with pytest.raises(ValueError, match="requires a 'database'"):
        build_destination(
            Destination(
                name="OB_DB_SS",
                type=ConnectorType.DATABASE,
                settings=Database(server="db.example", statement=INSERT).settings,
            )
        )


def test_generic_destination_dsn_has_no_sqlserver_tls() -> None:
    d = _dest(dialect="generic", odbc_driver="PostgreSQL Unicode", database="mefor")
    assert "Encrypt=" not in d._dsn and "DRIVER={PostgreSQL Unicode}" in d._dsn


def test_database_odbc_params_reject_envref() -> None:
    from messagefoundry.config.wiring import env

    with pytest.raises(WiringError, match="may not use env"):
        Database(
            server="db.example",
            dialect="generic",
            odbc_driver="PostgreSQL Unicode",
            statement=INSERT,
            odbc_params={"SSLmode": env("pg_sslmode")},
        )


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

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
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


class _HangingPool:
    """A pool whose acquire never returns — stands in for an exhausted pool / unresponsive DB."""

    async def acquire(self) -> object:
        await asyncio.Event().wait()


async def test_send_pool_acquire_timeout_is_transient() -> None:
    # WP-L3-07 (ASVS 13.1.2/13.2.6): a borrow that can't be satisfied within acquire_timeout fails as a
    # transient DeliveryError (retry) instead of blocking the delivery worker forever.
    dest = _dest(acquire_timeout=0.05)
    dest._pool = _HangingPool()
    with pytest.raises(DeliveryError, match="pool acquire timed out"):
        await dest.send('{"mrn": "1", "val": "x"}')


async def test_lookup_pool_acquire_timeout_is_db_lookup_error() -> None:
    # The handler-callable lookup maps the same timeout onto its PHI-free DbLookupError type.
    from messagefoundry.transports.database import DatabaseLookupExecutor, DbLookupError

    ex = DatabaseLookupExecutor(
        {"clarity": {"server": "s", "database": "d", "acquire_timeout": 0.05}}
    )
    ex._pools["clarity"] = _HangingPool()
    with pytest.raises(DbLookupError, match="pool acquire timed out"):
        await ex.query("clarity", "SELECT 1", None)


# --- test_connection() reachability probe (SELECT 1) -------------------------


async def test_probe_runs_select_1() -> None:
    cur = _FakeCursor()
    pool = _FakePool(_FakeConn(cur))
    dest = _dest()
    dest._pool = pool
    await dest.test_connection()  # no raise = reachable
    assert ("SELECT 1", ()) in cur.executed  # a no-param read, never a write
    assert pool.released  # the connection was returned to the pool


async def test_probe_transient_error_is_delivery_error() -> None:
    dest = _dest()
    dest._pool = _FakePool(_FakeConn(_FakeCursor(Exception("08S01", "connection lost"))))
    with pytest.raises(DeliveryError) as ei:
        await dest.test_connection()
    assert not isinstance(ei.value, NegativeAckError)  # transient → reachability fail


async def test_probe_auth_error_is_permanent() -> None:
    dest = _dest()
    dest._pool = _FakePool(_FakeConn(_FakeCursor(Exception("28000", "login failed"))))
    with pytest.raises(NegativeAckError):  # bad credentials → permanent (still a test failure)
        await dest.test_connection()


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


# === DATABASE source (poll) ==================================================
# Like the destination tests, the driver is never imported — a fake pool/cursor stands in, so the
# poll/mark/body logic is unit-tested without a real SQL Server.

POLL = "SELECT id, payload FROM mf_inbox WHERE status='NEW' ORDER BY id"
MARK = "UPDATE mf_inbox SET status='DONE' WHERE id=:id"


def _src(**over: Any) -> DatabaseSource:
    base: dict[str, Any] = dict(
        server="sql.example.com", database="MFDB", poll_statement=POLL, mark_statement=MARK
    )
    base.update(over)
    s = build_source(Source(type=ConnectorType.DATABASE, settings=DatabasePoll(**base).settings))
    assert isinstance(s, DatabaseSource)
    return s


class _RecordingHandler:
    def __init__(self, exc: Exception | None = None) -> None:
        self.bodies: list[bytes] = []
        self._exc = exc

    async def __call__(self, raw: bytes) -> str | None:
        self.bodies.append(raw)
        if self._exc is not None:
            raise self._exc
        return None


class _SrcCursor:
    def __init__(
        self,
        columns: list[str],
        rows: list[tuple[Any, ...]],
        *,
        poll_exc: Exception | None = None,
        mark_exc: Exception | None = None,
    ) -> None:
        self.description = [(c,) for c in columns]
        self._rows = rows
        self._poll_exc = poll_exc
        self._mark_exc = mark_exc
        self.marks: list[tuple[str, tuple[Any, ...]]] = []

    async def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> None:
        if params is None:  # the poll SELECT
            if self._poll_exc is not None:
                raise self._poll_exc
        else:  # a per-row mark
            self.marks.append((sql, params))
            if self._mark_exc is not None:
                raise self._mark_exc

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self._rows)


class _SrcConn:
    def __init__(self, cur: _SrcCursor) -> None:
        self._cur = cur

    async def cursor(self) -> _SrcCursor:
        return self._cur


class _SrcPool:
    def __init__(self, conn: _SrcConn) -> None:
        self._conn = conn
        self.closed = False

    async def acquire(self) -> _SrcConn:
        return self._conn

    async def release(self, conn: _SrcConn) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


async def _run_poll(
    src: DatabaseSource,
    columns: list[str],
    rows: list[tuple[Any, ...]],
    handler: _RecordingHandler,
    **cur_kw: Any,
) -> _SrcCursor:
    cur = _SrcCursor(columns, rows, **cur_kw)
    src._pool = _SrcPool(_SrcConn(cur))
    src._handler = handler
    await src._poll_once()
    return cur


async def test_source_polls_each_row_and_marks_processed() -> None:
    src = _src(body_column="payload")
    h = _RecordingHandler()
    cur = await _run_poll(src, ["id", "payload"], [(1, "AAA"), (2, "BBB")], h)
    assert h.bodies == [b"AAA", b"BBB"]  # one body per row, verbatim (body_column)
    assert (
        cur.marks
        == [  # :id translated to ?, bound from each row — only AFTER the handler returned
            ("UPDATE mf_inbox SET status='DONE' WHERE id=?", (1,)),
            ("UPDATE mf_inbox SET status='DONE' WHERE id=?", (2,)),
        ]
    )


async def test_source_json_body_is_whole_row() -> None:
    src = _src(body_column=None, mark_statement=None)
    h = _RecordingHandler()
    await _run_poll(src, ["id", "val"], [(1, "x")], h)
    assert json.loads(h.bodies[0]) == {"id": 1, "val": "x"}


async def test_source_json_serializes_dates_decimal_bytes() -> None:
    src = _src(body_column=None, mark_statement=None)
    h = _RecordingHandler()
    await _run_poll(
        src, ["t", "amt", "blob"], [(datetime(2026, 6, 12, 8, 30), Decimal("1.50"), b"\x00\x01")], h
    )
    obj = json.loads(h.bodies[0])
    assert obj["t"] == "2026-06-12T08:30:00"
    assert obj["amt"] == "1.50"  # Decimal → str (no float rounding)
    assert obj["blob"] == base64.b64encode(b"\x00\x01").decode("ascii")


async def test_source_body_column_decodes_bytes_verbatim() -> None:
    src = _src(body_column="payload", mark_statement=None)
    h = _RecordingHandler()
    hl7 = "MSH|^~\\&|A|B".encode()
    await _run_poll(src, ["id", "payload"], [(1, hl7)], h)
    assert h.bodies[0] == hl7  # a column holding an HL7 message round-trips byte-for-byte


async def test_source_handler_failure_leaves_row_unmarked() -> None:
    src = _src(body_column="payload")
    h = _RecordingHandler(exc=RuntimeError("store write failed"))
    cur = await _run_poll(src, ["id", "payload"], [(1, "AAA")], h)
    assert h.bodies == [b"AAA"]  # handler was attempted
    assert cur.marks == []  # but the row is NOT marked → it re-emits next poll (at-least-once)


async def test_source_mark_failure_does_not_abort_batch_tail() -> None:
    src = _src(body_column="payload")
    h = _RecordingHandler()
    cur = await _run_poll(
        src, ["id", "payload"], [(1, "A"), (2, "B")], h, mark_exc=Exception("08S01", "deadlock")
    )
    assert h.bodies == [b"A", b"B"]  # both rows handled despite the first mark erroring
    assert len(cur.marks) == 2  # both marks attempted (the error is logged, not fatal)


async def test_source_without_mark_statement_does_not_mark() -> None:
    src = _src(body_column="payload", mark_statement=None)
    h = _RecordingHandler()
    cur = await _run_poll(src, ["id", "payload"], [(1, "A")], h)
    assert h.bodies == [b"A"]
    assert cur.marks == []


async def test_source_missing_body_column_skips_row() -> None:
    src = _src(body_column="nope")
    h = _RecordingHandler()
    cur = await _run_poll(src, ["id", "payload"], [(1, "A")], h)
    assert h.bodies == []  # no body could be built → row skipped, not delivered
    assert cur.marks == []


async def test_source_run_loop_survives_a_poll_error() -> None:
    src = _src(body_column="payload")
    calls: list[int] = []

    async def boom() -> None:
        calls.append(1)
        src._stop.set()  # exit the loop after this one iteration
        raise RuntimeError("poll blew up")

    src._poll_once = boom  # type: ignore[method-assign]
    src._poll_seconds = 0.0
    await src._run()  # must NOT propagate — a bad poll never kills the poller
    assert calls == [1]


# --- source: leader-gating (Track B Step 4b) --------------------------------


def test_source_declares_polls_shared_resource() -> None:
    # A polled DB table is a shared external resource — the runner reads this flag to leader-gate it.
    assert DatabaseSource.polls_shared_resource is True


async def test_source_run_loop_skips_poll_when_gate_false() -> None:
    # A follower (leader_gate() -> False) must NOT execute poll_statement nor mark any rows: the loop
    # ticks but _poll_once is never reached, so the shared table is untouched (no duplicate intake).
    src = _src(body_column="payload")
    src._leader_gate = lambda: False
    src._poll_seconds = 0.0
    polled = {"n": 0}

    async def spy() -> None:  # would run poll_statement + marks if reached
        polled["n"] += 1
        src._stop.set()
        raise AssertionError("a follower must not poll")

    src._poll_once = spy  # type: ignore[method-assign]
    # Let the loop spin a few ticks, then stop it (a follower never sets _stop itself via the spy).
    runner = asyncio.create_task(src._run())
    await asyncio.sleep(0.02)
    src._stop.set()
    await runner
    assert polled["n"] == 0  # poll_once was gated out every tick


async def test_source_follower_real_poll_issues_no_sql() -> None:
    # Higher-fidelity follower test (matches the FILE source's end-to-end check): let the REAL
    # _poll_once run under a False gate against a pool that raises if touched. The gate must short-
    # circuit before any acquire/SELECT/mark — so a regression where _may_poll returns True but
    # _poll_once is reached would surface as the pool being acquired (not just a spy never called).
    class _PoisonPool:
        async def acquire(self) -> object:
            raise AssertionError("a follower must not acquire a connection / issue any SQL")

    src = _src(body_column="payload")
    src._pool = _PoisonPool()  # already-built pool → _get_pool returns it without reconnecting
    src._handler = _RecordingHandler()
    src._leader_gate = lambda: False
    src._poll_seconds = 0.0
    runner = asyncio.create_task(src._run())
    await asyncio.sleep(0.02)  # several ticks — each must skip the poison pool
    src._stop.set()
    await runner  # must not raise: the gate kept the real _poll_once away from the pool


async def test_source_run_loop_polls_when_gate_true() -> None:
    # A leader (leader_gate() -> True) polls exactly as the un-gated default does.
    src = _src(body_column="payload")
    src._leader_gate = lambda: True
    src._poll_seconds = 0.0
    calls: list[int] = []

    async def spy() -> None:
        calls.append(1)
        src._stop.set()  # one iteration then exit

    src._poll_once = spy  # type: ignore[method-assign]
    await src._run()
    assert calls == [1]  # the gate was True → poll_once ran


async def test_source_may_poll_logs_transition_once_then_resumes() -> None:
    # _may_poll is the gate check: False while a follower, True once leader, and it flips its
    # transition flag so it logs once per transition rather than every skipped tick.
    src = _src(body_column="payload")
    leader = {"on": False}
    src._leader_gate = lambda: leader["on"]
    assert src._may_poll() is False and src._skipping is True
    assert src._may_poll() is False and src._skipping is True  # still a follower (no re-flip)
    leader["on"] = True
    assert src._may_poll() is True and src._skipping is False  # became leader → resume


async def test_source_stop_closes_the_pool() -> None:
    src = _src(body_column="payload")
    pool = _SrcPool(_SrcConn(_SrcCursor(["id", "payload"], [])))
    src._pool = pool

    async def handler(raw: bytes) -> str | None:
        return None

    await src.start(handler)
    await src.stop()
    assert src._task is None
    assert pool.closed  # aclose drained the pool


@pytest.mark.parametrize("missing", ["server", "database", "poll_statement"])
def test_source_requires_core_settings(missing: str) -> None:
    base: dict[str, Any] = dict(server="s", database="d", poll_statement=POLL)
    base[missing] = ""
    with pytest.raises(ValueError):
        build_source(Source(type=ConnectorType.DATABASE, settings=DatabasePoll(**base).settings))


# --- source connect-allowlist ([egress].allowed_db) --------------------------


def _src_cfg(server: str, port: int = 1433) -> Source:
    return Source(
        type=ConnectorType.DATABASE,
        settings=DatabasePoll(server=server, database="d", poll_statement=POLL, port=port).settings,
    )


def test_source_connect_blocks_unlisted_server() -> None:
    with pytest.raises(WiringError):
        check_source_allowed(
            _src_cfg("other.example.com"), "IB_DB", EgressSettings(allowed_db=["sql.example.com"])
        )


def test_source_connect_permits_listed_server() -> None:
    check_source_allowed(
        _src_cfg("sql.example.com"), "IB_DB", EgressSettings(allowed_db=["sql.example.com"])
    )


def test_source_connect_unrestricted_when_empty() -> None:
    check_source_allowed(_src_cfg("anywhere.example"), "IB_DB", EgressSettings())


def test_source_connect_ignores_non_database_source() -> None:
    mllp = Source(type=ConnectorType.MLLP, settings={"port": 2575})
    check_source_allowed(mllp, "IB_MLLP", EgressSettings(allowed_db=["sql.example.com"]))
