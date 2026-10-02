# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness DATABASE family (vault BACKLOG #2676): a DatabasePoll inbound and a Database outbound.

MEASURED, not assumed: the engine's DATABASE connector is ODBC-only (``dialect='sqlserver'`` over the
Microsoft ODBC Driver 18, or ``dialect='generic'`` over an operator-named ODBC driver), reached through
``aioodbc``/``pyodbc`` from the ``[sqlserver]`` extra, which the CI install line does not carry. There
is no SQLite path. So almost everything below runs WITHOUT a database -- the graph loads and serves,
the harness SQL is parameterized and agrees with the graph's, credentials never sit in source, and the
scenarios report SKIPPED (never a pass) without their preconditions and can still say no -- and the one
end-to-end test is gated on ``MEFOR_TEST_SQLSERVER`` and skips with its reason everywhere else.

Nothing here mocks the engine's transport. The fakes stand in for ``pyodbc`` under the HARNESS's own
driver and sink, to check the SQL they send; no fake ever produces a scenario pass against the engine.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from harness import drivers, sinks
from harness.__main__ import main
from harness.drivers import Driver, Injection, _database
from harness.drivers.database import DatabaseDriver
from harness.endpoints import Endpoints
from harness.scenarios import SCENARIOS, run_scenario
from harness.scenarios.database import DatabaseScenario
from harness.sinks import Record, Sink
from harness.sinks.database import DatabaseSink
from messagefoundry.apiclient import EngineClient
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import DatabasePoll, EnvRef, env, load_config
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from tests._harness_engine import HARNESS_CONFIG, ephemeral_overrides, serve_harness_config

DB_CONFIG = HARNESS_CONFIG / "database"

_CREDENTIALS = {
    _database.ENV_NAME: "harness_test",
    _database.ENV_USERNAME: "harness_user",
    _database.ENV_PASSWORD: "not-a-real-secret",
}


def _as_client(fake: object) -> EngineClient:
    """Hand a scenario a fake client that answers only the calls its test makes."""
    return fake  # type: ignore[return-value]


# --- the graph --------------------------------------------------------------------------------------


def test_the_graph_loads_and_wires_a_poll_inbound_and_a_write_outbound() -> None:
    registry = load_config(str(DB_CONFIG))
    assert set(registry.inbound) == {_database.INBOUND_NAME}
    assert set(registry.outbound) == {_database.OUTBOUND_NAME}
    inbound = registry.inbound[_database.INBOUND_NAME]
    assert inbound.spec.type is ConnectorType.DATABASE
    assert inbound.router == "harness_db_router"
    assert inbound.spec.settings["body_column"] == "payload"
    assert inbound.spec.settings["dialect"] == "sqlserver"
    # TLS is never weakened by the harness graph.
    for spec in (inbound.spec, registry.outbound[_database.OUTBOUND_NAME].spec):
        assert spec.settings["encrypt"] is True
        assert spec.settings["trust_server_certificate"] is False


def test_the_graph_runs_the_sql_the_harness_creates_its_tables_for() -> None:
    """The graph cannot import the harness, so it carries its SQL as literals; this holds the two
    copies equal, so the tables the driver and sink create are the ones the engine reads and writes."""
    registry = load_config(str(DB_CONFIG))
    poll = registry.inbound[_database.INBOUND_NAME].spec.settings
    write = registry.outbound[_database.OUTBOUND_NAME].spec.settings
    assert poll["poll_statement"] == _database.POLL_STATEMENT
    assert poll["mark_statement"] == _database.MARK_STATEMENT
    assert write["statement"] == _database.WRITE_STATEMENT


def test_the_tables_the_harness_creates_carry_every_column_the_graph_uses() -> None:
    """The DDL and the graph's SQL are written separately; a column renamed in one and not the other
    passes every offline check and fails only on a real server, so the columns are pinned here."""
    inbox, _, outbox = _database.CREATE_TABLES.partition(f"CREATE TABLE {_database.OUTBOX} (")
    assert f"CREATE TABLE {_database.INBOX} (" in inbox
    for column in ("id INT", "payload NVARCHAR", "status NVARCHAR(16) NOT NULL DEFAULT 'NEW'"):
        assert column in inbox, column
    for column in ("id INT", "control_id NVARCHAR", "message_type NVARCHAR", "payload NVARCHAR"):
        assert column in outbox, column
    assert "status" not in outbox  # control: the split above really separated the two tables


def _credentials_in_source(settings: dict[str, Any]) -> list[str]:
    """The connection settings that would carry a credential from source: a literal, or an ``env()``
    with a default. Only an ``env()`` with NO default keeps it to the environment."""
    no_default = env("x").default
    return sorted(
        key
        for key in ("database", "username", "password")
        if not (isinstance(settings.get(key), EnvRef) and settings[key].default is no_default)
    )


def test_no_credential_is_in_the_graph_source() -> None:
    registry = load_config(str(DB_CONFIG))
    specs = {name: c.spec for name, c in registry.inbound.items()}
    specs |= {name: c.spec for name, c in registry.outbound.items()}
    assert set(specs) == {_database.INBOUND_NAME, _database.OUTBOUND_NAME}
    for name, spec in specs.items():
        assert _credentials_in_source(spec.settings) == [], name


def test_the_credential_check_flags_a_literal_and_a_defaulted_secret() -> None:
    """Negative control for the test above: the check can say no."""
    literal = DatabasePoll(
        server="h", database="d", username="u", password="pw", poll_statement="SELECT 1"
    ).settings
    defaulted = DatabasePoll(
        server="h",
        database=env("harness_database_name"),
        username=env("harness_database_username"),
        password=env("harness_database_password", default="pw"),
        poll_statement="SELECT 1",
    ).settings
    assert _credentials_in_source(literal) == ["database", "password", "username"]
    assert _credentials_in_source(defaulted) == ["password"]


def test_the_shared_graph_checks_walk_the_database_graph_too() -> None:
    """The endpoint-default and no-harness-import checks in test_harness_scenarios.py walk
    ``_graph_dirs()``; this graph is outside ``harness/config``'s top level, so pin that they reach it."""
    from tests.test_harness_scenarios import _graph_dirs, _graph_env_refs

    assert DB_CONFIG in _graph_dirs()
    refs = {(r.key.removeprefix("harness_"), r.default) for r in _graph_env_refs()}
    assert ("database_port", 1433) in refs
    assert ("database_password", env("x").default) in refs


# --- the harness SQL and connection, against a fake pyodbc ------------------------------------------


class _FakeError(Exception):
    pass


class _FakeCursor:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    def execute(self, sql: str, *params: object) -> _FakeCursor:
        self._conn.executed.append((sql, params))
        if self._conn.refuse_at is not None and len(self._conn.executed) == self._conn.refuse_at:
            raise _FakeError(f"refused, quoting the value back: {params!r}")
        return self

    def fetchone(self) -> tuple[int]:
        return (self._conn.high_water,)

    def fetchall(self) -> list[tuple[object, ...]]:
        rows, self._conn.rows = self._conn.rows, []
        return rows


class _FakeConn:
    def __init__(self, *, refuse_at: int | None = None, high_water: int = 0) -> None:
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.refuse_at = refuse_at
        self.high_water = high_water
        self.rows: list[tuple[object, ...]] = []
        self.closed = False

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)

    def close(self) -> None:
        self.closed = True


def _fake_pyodbc(
    monkeypatch: pytest.MonkeyPatch,
    *,
    drivers_listed: Sequence[str] = (_database.ODBC_DRIVER,),
    conn: _FakeConn | None = None,
    connect_error: str | None = None,
) -> list[tuple[str, dict[str, object]]]:
    calls: list[tuple[str, dict[str, object]]] = []

    def connect(dsn: str, **kwargs: object) -> _FakeConn:
        calls.append((dsn, kwargs))
        if connect_error is not None:
            raise _FakeError(connect_error)
        assert conn is not None
        return conn

    fake = SimpleNamespace(Error=_FakeError, drivers=lambda: list(drivers_listed), connect=connect)
    monkeypatch.setitem(sys.modules, "pyodbc", fake)
    return calls


@pytest.fixture
def credentials(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name, value in _CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    yield


def test_the_environment_names_are_the_ones_the_graph_reads() -> None:
    assert set(_database.REQUIRED_ENV) == {
        _database.ENV_NAME,
        _database.ENV_USERNAME,
        _database.ENV_PASSWORD,
    }
    assert _database.ENV_PASSWORD == "MEFOR_VALUE_HARNESS_DATABASE_PASSWORD"  # noqa: S105


def test_the_dsn_quotes_every_value_and_never_weakens_tls() -> None:
    t = _database.Target("db.example", 1433, "harness", "u}x", "p;w}d=1")
    dsn = _database.build_dsn(t)
    assert "SERVER=db.example,1433;" in dsn
    assert "UID={u}}x};" in dsn and "PWD={p;w}}d=1};" in dsn  # no keyword can be smuggled in
    assert dsn.endswith("Encrypt=yes;TrustServerCertificate=no;")
    assert "p;w}d=1" not in repr(t)  # the password stays out of a repr
    with pytest.raises(ValueError, match="must not contain"):
        _database.build_dsn(_database.Target("db;Encrypt=no", 1433, "d", "u", "p"))


def test_the_harness_sql_is_parameterized_and_names_only_its_own_tables() -> None:
    assert _database.INSERT_INBOX.count("?") == 1
    assert _database.SELECT_OUTBOX_AFTER.count("?") == 1
    for sql in (_database.POLL_STATEMENT, _database.MARK_STATEMENT, _database.WRITE_STATEMENT):
        assert "?" not in sql and "%" not in sql
    assert _database.MARK_STATEMENT.endswith("WHERE id = :id")
    assert all(f":{name}" in _database.WRITE_STATEMENT for name in ("control_id", "payload"))


def test_unavailable_names_each_missing_precondition(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    eps = Endpoints(environ={})
    monkeypatch.setitem(sys.modules, "pyodbc", None)  # the [sqlserver] extra is absent
    assert "pyodbc is not installed" in _database.unavailable(eps)
    _fake_pyodbc(monkeypatch, drivers_listed=["SQLite3"])
    assert "ODBC driver is not installed" in _database.unavailable(eps)
    _fake_pyodbc(monkeypatch)
    assert _database.unavailable(eps) == ""
    monkeypatch.delenv(_database.ENV_PASSWORD)
    assert _database.unavailable(eps).startswith(f"{_database.ENV_PASSWORD} is not set")


def test_connect_reports_every_unusable_database_as_a_connection_error(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    bad = Endpoints({"database_server": "db;Encrypt=no"}, environ={})
    monkeypatch.setitem(sys.modules, "pyodbc", None)
    with pytest.raises(ConnectionError, match="pyodbc is not installed"):
        _database.connect(bad)
    _fake_pyodbc(monkeypatch, conn=_FakeConn())
    with pytest.raises(ConnectionError, match="must not contain"):
        _database.connect(bad)
    monkeypatch.delenv(_database.ENV_NAME)
    with pytest.raises(ConnectionError, match=f"{_database.ENV_NAME} is not set"):
        _database.connect(Endpoints(environ={}))


def test_connect_creates_the_tables_and_reports_a_refusal_without_the_dsn(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    eps = Endpoints({"database_server": "127.0.0.1", "database_port": "14330"}, environ={})
    conn = _FakeConn()
    calls = _fake_pyodbc(monkeypatch, conn=conn)
    assert _database.connect(eps) is conn
    (dsn, kwargs) = calls[0]
    assert "SERVER=127.0.0.1,14330;" in dsn
    assert kwargs == {"autocommit": True, "timeout": _database.LOGIN_TIMEOUT}
    assert getattr(conn, "timeout", None) == _database.QUERY_TIMEOUT  # no statement blocks forever
    assert conn.executed == [(_database.CREATE_TABLES, ())]
    _fake_pyodbc(monkeypatch, connect_error="Login failed for user 'harness_user'")
    with pytest.raises(ConnectionError, match="Login failed") as raised:
        _database.connect(eps)
    assert _CREDENTIALS[_database.ENV_PASSWORD] not in str(raised.value)


def test_the_driver_binds_each_payload_as_a_parameter(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    hostile = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|X'); DROP TABLE dbo.mf_harness_inbox;--|P|2.5.1"
    conn = _FakeConn(refuse_at=2)  # the second insert is refused
    _fake_pyodbc(monkeypatch)
    monkeypatch.setattr(_database, "connect", lambda eps: conn)
    out = DatabaseDriver(Endpoints(environ={})).inject([hostile.encode(), b"second", b"third"])
    assert [o.error for o in out] == ["", "insert refused: _FakeError", ""]
    assert [sql for sql, _ in conn.executed] == [_database.INSERT_INBOX] * 3
    assert conn.executed[0][1] == (hostile,)  # the payload is a bound value, never SQL text
    assert "second" not in out[1].error  # the refusal text quoted the value; the report does not
    assert conn.closed


def test_the_driver_reports_an_unreachable_server_per_payload(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    _fake_pyodbc(monkeypatch, connect_error="TCP Provider: connection refused")
    out = DatabaseDriver(Endpoints(environ={})).inject([b"a", b"b"])
    assert len(out) == 2 and all("connection refused" in o.error for o in out)
    monkeypatch.setitem(sys.modules, "pyodbc", None)  # and without the extra: reported, not raised
    out = DatabaseDriver(Endpoints(environ={})).inject([b"a"])
    assert out == [Injection(error="pyodbc is not installed")]


def test_the_sink_reads_only_rows_written_after_it_started(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    conn = _FakeConn(high_water=41)
    _fake_pyodbc(monkeypatch)
    monkeypatch.setattr(_database, "connect", lambda eps: conn)
    with DatabaseSink(Endpoints(environ={})) as sink:
        conn.rows = [(42, "C42", "ADT^A05", "MSH|a", 5), (43, "C43", "ADT^A05", "MSH|b", 5)]
        first = sink.records()
        conn.rows = [(44, "C44", "ADT^A05", "MSH|c", 5)]
        second = sink.records()
    assert [r.meta["control_id"] for r in first] == ["C42", "C43"]
    assert [r.meta["id"] for r in second] == ["42", "43", "44"]
    queried = [params for sql, params in conn.executed if sql == _database.SELECT_OUTBOX_AFTER]
    assert queried == [(41,), (43,)]  # the high-water mark moves; old rows are never re-read
    assert conn.closed


def test_the_sink_reads_no_payload_over_the_cap_and_records_the_refusal(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    """ASVS 5.1.1: the read withholds an over-cap payload server-side, and the sink records the row
    as refused, never as a delivery and never silently dropped. The fetched-side check bites too."""
    sql = _database.SELECT_OUTBOX_AFTER
    cap = _database.MAX_OUTBOX_PAYLOAD_CHARS
    assert cap == DEFAULT_MAX_MESSAGE_BYTES
    assert f"CASE WHEN DATALENGTH(payload) <= {2 * cap} THEN payload END" in sql
    assert "DATALENGTH(payload) / 2" in sql
    conn = _FakeConn()
    _fake_pyodbc(monkeypatch)
    monkeypatch.setattr(_database, "connect", lambda eps: conn)
    with DatabaseSink(Endpoints(environ={})) as sink:
        sink.max_payload_chars = 5
        conn.rows = [
            (1, "C1", "ADT^A05", None, cap + 1),  # withheld by the server
            (2, "C2", "ADT^A05", "MSH|ab", 6),  # fetched, but over the sink's own cap
            (3, "C3", "ADT^A05", "MSH|a", 5),  # at the cap: kept
        ]
        records = sink.records()
    assert [r.meta["control_id"] for r in records] == ["C1", "C2", "C3"]
    assert [r.payload for r in records] == [b"", b"", b"MSH|a"]
    # A withheld payload names the server-side cap, which the attribute cannot raise or hide.
    assert records[0].meta["refused"].startswith(f"{cap + 1} characters, over the {cap}-character")
    assert records[1].meta["refused"].startswith("6 characters, over the 5-character cap")
    assert "refused" not in records[2].meta
    assert "MSH" not in records[1].meta["refused"]  # the refusal never quotes the payload


def test_the_sink_survives_a_dropped_session_and_closes_on_a_failed_start(
    monkeypatch: pytest.MonkeyPatch, credentials: None
) -> None:
    _fake_pyodbc(monkeypatch)
    dropping = _FakeConn(refuse_at=2)  # the high-water read succeeds, the first poll is refused
    dials: list[_FakeConn] = []

    def dial(eps: Endpoints) -> _FakeConn:
        dials.append(dropping)
        return dropping

    monkeypatch.setattr(_database, "connect", dial)
    with DatabaseSink(Endpoints(environ={})) as sink:
        assert sink.records() == []
        assert sink.last_error == "_FakeError"
        assert dropping.closed  # the dead session is dropped, not reused
        dropping.rows = [(1, "C1", "ADT^A05", "MSH|a", 5)]
        assert [r.meta["control_id"] for r in sink.records()] == ["C1"]  # the next poll redials
    assert len(dials) == 2
    refusing = _FakeConn(refuse_at=1)  # the high-water read itself is refused
    monkeypatch.setattr(_database, "connect", lambda eps: refusing)
    with pytest.raises(ConnectionError, match="cannot read the harness outbox"):
        DatabaseSink(Endpoints(environ={})).start()
    assert refusing.closed


def test_the_driver_and_sink_dial_only_the_database_server_endpoint() -> None:
    eps = Endpoints(environ={})
    assert isinstance(drivers.build("database", eps, "database_server"), DatabaseDriver)
    assert isinstance(sinks.build("database", eps, "database_server"), DatabaseSink)
    with pytest.raises(KeyError, match="dials database_server"):
        drivers.build("database", eps, "mllp_in")
    with pytest.raises(KeyError, match="dials database_server"):
        sinks.build("database", eps, "mllp_echo")


# --- the scenarios: SKIPPED without their preconditions, and able to say no -------------------------


class _Client:
    def __init__(
        self, served: Sequence[str], status: str = "processed", *, running: bool = True
    ) -> None:
        self._served = served
        self._status = status
        self._running = running

    def list_channels(self) -> list[SimpleNamespace]:
        return [SimpleNamespace(id=name, running=self._running) for name in self._served]

    def list_messages(self, *, control_id: str, **kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(messages=[SimpleNamespace(status=self._status)])


def test_the_scenarios_claim_database_in_and_out_and_nothing_else() -> None:
    family = {n: s for n, s in SCENARIOS.items() if isinstance(s, DatabaseScenario)}
    assert set(family) == {"database_roundtrip", "database_unrouted"}
    claimed = set().union(*(s.covers for s in family.values()))
    assert claimed == {("database", "inbound"), ("database", "outbound")}


@pytest.mark.parametrize("name", ["database_roundtrip", "database_unrouted"])
def test_a_scenario_without_its_preconditions_is_skipped_not_passed(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setattr(_database, "unavailable", lambda eps: "pyodbc is not installed (test)")
    result = run_scenario(SCENARIOS[name], _as_client(_Client([])), timeout=0.1)
    assert result.skipped and not result.ok
    assert result.detail == "pyodbc is not installed (test)"


def test_a_scenario_against_an_engine_not_serving_the_graph_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_database, "unavailable", lambda eps: "")
    client = _as_client(_Client(["IB_Coverage_MLLP"]))
    result = run_scenario(SCENARIOS["database_roundtrip"], client, timeout=0.1)
    assert result.skipped and not result.ok
    assert f"does not serve {_database.INBOUND_NAME}" in result.detail


def test_a_served_but_stopped_inbound_is_a_failure_not_a_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The engine serving the graph with its database inbound down (no credentials on the engine
    side, an unlisted [egress].allowed_db) is a broken setup to report, not a precondition to skip."""
    monkeypatch.setattr(_database, "unavailable", lambda eps: "")
    client = _as_client(_Client([_database.INBOUND_NAME], running=False))
    result = run_scenario(SCENARIOS["database_roundtrip"], client, timeout=0.1)
    assert not result.ok and not result.skipped
    assert "is not running" in result.detail


def test_an_unusable_database_fails_both_scenarios_alike(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unreachable server is a FAIL for the roundtrip (the sink cannot start) exactly as for the
    unrouted scenario (the driver cannot insert): never a skip, never a setup exit."""
    monkeypatch.setattr(_database, "unavailable", lambda eps: "")

    def refuse(eps: Endpoints) -> object:
        raise ConnectionError("cannot connect to the harness database: login failed")

    monkeypatch.setattr(_database, "connect", refuse)
    client = _as_client(_Client([_database.INBOUND_NAME]))
    for name in ("database_roundtrip", "database_unrouted"):
        result = run_scenario(SCENARIOS[name], client, timeout=0.1)
        assert not result.ok and not result.skipped, name
        assert "login failed" in result.detail, name


def test_a_skipped_result_can_never_be_ok() -> None:
    from harness.scenarios import ScenarioResult

    with pytest.raises(ValueError, match="cannot also be ok"):
        ScenarioResult(SCENARIOS["database_unrouted"], True, "", skipped=True)


def test_the_roundtrip_scenario_fails_when_nothing_reaches_the_outbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative control, runnable without a database: every disposition reads PROCESSED, yet a sink
    that sees no outbox row must fail the scenario; the same run with the rows present passes. The
    fakes replace the harness driver and sink only, to exercise the scenario's own verdict."""
    injected: list[bytes] = []

    class Recorder(Driver):
        kind = "database"

        def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
            injected.extend(payloads)
            return [Injection() for _ in payloads]

    class Outbox(Sink):
        kind = "database"

        def __init__(self, echo: bool) -> None:
            super().__init__()
            self._echo = echo

        def records(self) -> list[Record]:
            if self._echo and not super().records():
                for payload in injected:
                    message = Message.parse(payload.decode())
                    message["MSH-6"] = "HARNESS_DB"
                    self._add(Record(str(message).encode()))
            return super().records()

    monkeypatch.setattr(_database, "unavailable", lambda eps: "")
    monkeypatch.setattr(drivers, "build", lambda kind, eps, key: Recorder())
    client = _as_client(_Client([_database.INBOUND_NAME]))

    monkeypatch.setattr(sinks, "build", lambda kind, eps, key: Outbox(echo=False))
    empty = run_scenario(SCENARIOS["database_roundtrip"], client, timeout=0.5)
    assert not empty.ok and not empty.skipped
    assert empty.detail.endswith("0/3 delivered to the database sink")

    injected.clear()
    monkeypatch.setattr(sinks, "build", lambda kind, eps, key: Outbox(echo=True))
    full = run_scenario(SCENARIOS["database_roundtrip"], client, timeout=0.5)
    assert full.ok, full.detail


def test_the_unrouted_scenario_fails_on_the_wrong_disposition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Accept(Driver):
        kind = "database"

        def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
            return [Injection() for _ in payloads]

    monkeypatch.setattr(_database, "unavailable", lambda eps: "")
    monkeypatch.setattr(drivers, "build", lambda kind, eps, key: Accept())
    wrong = _as_client(_Client([_database.INBOUND_NAME], status="processed"))
    result = run_scenario(SCENARIOS["database_unrouted"], wrong, timeout=0.5)
    assert not result.ok and "statuses seen: ['processed']" in result.detail
    right = _as_client(_Client([_database.INBOUND_NAME], status="unrouted"))
    assert run_scenario(SCENARIOS["database_unrouted"], right, timeout=0.5).ok


def test_the_cli_prints_skip_and_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(_database, "unavailable", lambda eps: "pyodbc is not installed (test)")
    assert main(["--scenario", "database_unrouted", "--engine", "http://127.0.0.1:9"]) == 2
    out = capsys.readouterr().out
    assert out.startswith("SKIP  database_unrouted: pyodbc is not installed (test)")
    assert "PASS" not in out


# --- the graph SERVED, without a database ------------------------------------------------------------


@contextmanager
def _served(
    tmp_path: Path, overrides: dict[str, str] | None = None
) -> Iterator[tuple[EngineClient, Endpoints]]:
    """Serve ``harness/config/database`` and yield a client for it, plus the endpoints it uses."""
    values = ephemeral_overrides(tmp_path) if overrides is None else overrides
    with (
        serve_harness_config(tmp_path, values, config_dir=DB_CONFIG) as (api_url, eps),
        EngineClient(api_url) as client,
    ):
        yield client, eps


def test_the_graph_serves_and_builds_both_connectors_without_a_database(
    tmp_path: Path, credentials: None
) -> None:
    """With credentials in the environment the engine constructs both connectors (the DSN, the TLS
    gate) and starts them; with no server the poll only logs and retries. What it cannot do here is
    reach a database, which is what the gated test below is for."""
    with _served(tmp_path) as (client, _eps):
        channels = {c.id: c for c in client.list_channels()}
        rows = {(r.role, r.channel_name): r.status for r in client.connections()}
    assert channels[_database.INBOUND_NAME].running
    assert channels[_database.INBOUND_NAME].source_type == "database"
    assert rows[("source", _database.INBOUND_NAME)] == "running"
    assert rows[("destination", _database.OUTBOUND_NAME)] == "running"


def test_without_credentials_in_the_environment_both_connectors_fail_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control for the test above, and the measurement behind the subdirectory: the graph
    holds no credential, so without the environment's both connections fail to start -- isolated, the
    engine still running -- rather than dialling with a blank."""
    for name in _database.REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)
    with _served(tmp_path) as (client, _eps):
        assert client.health() is not None
        channels = {c.id: c for c in client.list_channels()}
        rows = {(r.role, r.channel_name): r.status for r in client.connections()}
    assert not channels[_database.INBOUND_NAME].running
    assert rows[("source", _database.INBOUND_NAME)] == "failed"
    assert rows[("destination", _database.OUTBOUND_NAME)] == "failed"


class _MislabelledAlert(AssertionError):
    """The one failure the xfail below is about; any other failure reports as a real failure."""


@pytest.mark.xfail(
    strict=True,
    raises=_MislabelledAlert,
    reason=(
        "engine defect: LoggingAlertSink.connection_stopped (messagefoundry/pipeline/alerts.py) "
        "words every alert 'outbound %r halted', and RegistryRunner._record_failed calls it for an "
        "INBOUND that failed to start too, whose detail ('failed to start: ...') names no direction "
        "-- so an inbound startup failure would be alerted to an operator as an outbound"
    ),
)
def test_an_inbound_that_fails_to_start_is_not_alerted_as_an_outbound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    for name in _database.REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alerts"),
        _served(tmp_path),
    ):
        pass
    alerts = [
        r.getMessage()
        for r in caplog.records
        if "connection_stopped" in r.getMessage() and repr(_database.INBOUND_NAME) in r.getMessage()
    ]
    assert alerts, "control: the inbound's failed start raised no connection_stopped alert"
    if any(f"outbound {_database.INBOUND_NAME!r}" in line for line in alerts):
        raise _MislabelledAlert(alerts[0])


# --- live: a real SQL Server, gated -------------------------------------------------------------------


def _live_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Ephemeral endpoints for everything else; the database endpoints and credentials from the
    ``MEFOR_VALUE_HARNESS_DATABASE_*`` variables, else from the CI store job's ``MEFOR_STORE_*``."""
    overrides = ephemeral_overrides(tmp_path)
    overrides["database_server"] = os.environ.get(
        "MEFOR_VALUE_HARNESS_DATABASE_SERVER", os.environ.get("MEFOR_STORE_SERVER", "localhost")
    )
    overrides["database_port"] = os.environ.get(
        "MEFOR_VALUE_HARNESS_DATABASE_PORT", os.environ.get("MEFOR_STORE_PORT", "1433")
    )
    for harness_var, store_var in (
        (_database.ENV_NAME, "MEFOR_STORE_DATABASE"),
        (_database.ENV_USERNAME, "MEFOR_STORE_USERNAME"),
        (_database.ENV_PASSWORD, "MEFOR_STORE_PASSWORD"),
    ):
        if not os.environ.get(harness_var) and os.environ.get(store_var):
            monkeypatch.setenv(harness_var, os.environ[store_var])
    return overrides


def test_live_database_family_against_sql_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not os.getenv("MEFOR_TEST_SQLSERVER"):
        pytest.skip(
            "set MEFOR_TEST_SQLSERVER=1 (+ a SQL Server and its credentials) to run the DATABASE "
            "family end to end; without one this family is unverified"
        )
    if os.environ.get("MEFOR_STORE_TRUST_SERVER_CERTIFICATE", "").lower() in ("1", "true", "yes"):
        pytest.skip(
            "the SQL Server's certificate is not trusted here (MEFOR_STORE_TRUST_SERVER_CERTIFICATE), "
            "and the harness database graph never weakens TLS"
        )
    overrides = _live_overrides(tmp_path, monkeypatch)
    reason = _database.unavailable(Endpoints(overrides))
    if reason:
        pytest.skip(reason)
    with _served(tmp_path, overrides) as (client, eps):
        for name in ("database_roundtrip", "database_unrouted"):
            result = run_scenario(SCENARIOS[name], client, timeout=60.0, endpoints=eps)
            assert not result.skipped, result.detail
            assert result.ok, f"{name}: {result.detail}"
