# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for handler-callable live db_lookup (ADR 0010).

Covers the accessor + active-runner indirection (config/db_lookup.py), the pooled executor against a
FAKED aioodbc pool (transports/database.py), the DatabaseLookup factory + Registry table (config/
wiring.py), the fail-closed egress gate, and the end-to-end dry-run-raises behavior. Synthetic data only.
"""

from __future__ import annotations

from decimal import Decimal
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
    """A cursor over ``rows`` that counts every row it hands out, so a test can see how much of a
    result left the driver, not only what the executor returned. ``max_batch`` makes ``fetchmany``
    return fewer rows than asked, as a real driver may while more remain."""

    def __init__(
        self,
        rows: list[tuple[Any, ...]],
        columns: list[str],
        error: Exception | None,
        max_batch: int | None = None,
    ):
        self._rows = rows
        self._columns = columns
        self._error = error
        self._max_batch = max_batch
        self._pos = 0
        self.description = [(c,) for c in columns] if columns else None
        self.executed: tuple[str, tuple[Any, ...]] | None = None
        self.fetched = 0
        self.fetchall_calls = 0

    async def execute(self, sql: str, params: tuple[Any, ...]) -> None:
        self.executed = (sql, params)
        if self._error is not None:
            raise self._error

    def _take(self, n: int) -> list[tuple[Any, ...]]:
        out = self._rows[self._pos : self._pos + n]
        self._pos += len(out)
        self.fetched += len(out)
        return out

    async def fetchall(self) -> list[tuple[Any, ...]]:
        self.fetchall_calls += 1
        return self._take(len(self._rows))

    async def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        return self._take(min(size, self._max_batch) if self._max_batch else size)


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
    max_batch: int | None = None,
) -> _FakePool:
    """Replace the module-level _make_pool so the executor gets a fake pool (no aioodbc, no DB)."""
    pool = _FakePool(_FakeCursor(rows or [], columns or [], error, max_batch))

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


# --- the row ceiling, charged at the fetch (BACKLOG #1730) --------------------


def _capped(max_rows: Any) -> dict[str, dict[str, Any]]:
    return {"clarity": {"server": "db.local", "database": "Clarity", "max_rows": max_rows}}


async def test_executor_refuses_a_result_over_max_rows_at_the_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 10,000 matching rows against a ceiling of 3: the lookup is refused, and the driver handed out
    # max_rows + 1 rows, not the whole result. Before #1730 the executor ran fetchall and returned
    # all 10,000.
    rows = [(f"NPI{i}", f"SSN-{i}") for i in range(10_000)]
    pool = _patch_pool(monkeypatch, rows=rows, columns=["npi", "ssn"])
    ex = DatabaseLookupExecutor(_capped(3))
    with pytest.raises(DbLookupError) as ei:
        await ex.query("clarity", "SELECT npi, ssn FROM patient WHERE mrn = :mrn", {"mrn": "M1"})
    msg = str(ei.value)
    assert "clarity" in msg and "max_rows=3" in msg
    # PHI-free: no row value, no statement text, no parameter.
    assert "NPI0" not in msg and "SSN-" not in msg and "patient" not in msg and "M1" not in msg
    assert pool.cursor_obj.fetched == 4
    assert pool.cursor_obj.fetchall_calls == 0
    assert pool.released == 1  # the connection goes back even on a refusal


async def test_executor_returns_a_result_of_exactly_max_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The boundary: max_rows rows is a full answer, not an overflow.
    pool = _patch_pool(monkeypatch, rows=[("1",), ("2",), ("3",)], columns=["npi"])
    ex = DatabaseLookupExecutor(_capped(3))
    rows = await ex.query("clarity", "SELECT npi FROM p", {})
    assert rows == [{"npi": "1"}, {"npi": "2"}, {"npi": "3"}]
    assert pool.cursor_obj.fetched == 3


async def test_executor_ceiling_holds_when_the_driver_returns_short_batches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A driver may return fewer rows than asked while more remain. The executor keeps asking, so a
    # short batch neither hides an overflow nor cuts a legal result short.
    under = _patch_pool(monkeypatch, rows=[(i,) for i in range(5)], columns=["n"], max_batch=2)
    assert (
        len(await DatabaseLookupExecutor(_capped(5)).query("clarity", "SELECT n FROM t", {})) == 5
    )
    assert under.cursor_obj.fetched == 5

    over = _patch_pool(monkeypatch, rows=[(i,) for i in range(50)], columns=["n"], max_batch=2)
    with pytest.raises(DbLookupError, match="max_rows=5"):
        await DatabaseLookupExecutor(_capped(5)).query("clarity", "SELECT n FROM t", {})
    assert over.cursor_obj.fetched == 6


async def test_executor_default_ceiling_is_500(monkeypatch: pytest.MonkeyPatch) -> None:
    # A lookup that sets no max_rows gets DEFAULT_DB_LOOKUP_MAX_ROWS: 500 rows pass, 501 refuse.
    assert database.DEFAULT_DB_LOOKUP_MAX_ROWS == 500
    _patch_pool(monkeypatch, rows=[(i,) for i in range(500)], columns=["n"])
    assert len(await DatabaseLookupExecutor(_CONN).query("clarity", "SELECT n FROM t", {})) == 500

    pool = _patch_pool(monkeypatch, rows=[(i,) for i in range(5_000)], columns=["n"])
    with pytest.raises(DbLookupError, match="max_rows=500"):
        await DatabaseLookupExecutor(_CONN).query("clarity", "SELECT n FROM t", {})
    assert pool.cursor_obj.fetched == 501


async def test_executor_max_rows_zero_removes_the_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    # The documented opt-out, same convention as poll_max_rows: 0 means no ceiling, read by fetchall.
    pool = _patch_pool(monkeypatch, rows=[(i,) for i in range(2_000)], columns=["n"])
    rows = await DatabaseLookupExecutor(_capped(0)).query("clarity", "SELECT n FROM t", {})
    assert len(rows) == 2_000
    assert pool.cursor_obj.fetchall_calls == 1


@pytest.mark.parametrize(
    "bad", [-1, -1234, True, "many-9876", 2.5, float("inf"), float("nan"), Decimal("2.5")]
)
def test_executor_refuses_a_bad_max_rows_at_construction(bad: Any) -> None:
    # Refused where serve and messagefoundry check build the executor, not at the first message. A
    # bool is an int to Python, so True would otherwise mean a ceiling of one row, and int(2.5) is 2.
    with pytest.raises(ValueError, match="DatabaseLookup 'clarity' max_rows") as ei:
        DatabaseLookupExecutor(_capped(bad))
    # The value arrives env()-resolved, so the refusal withholds it, chain included (BACKLOG #1183).
    assert str(bad) not in str(ei.value)
    assert ei.value.__cause__ is None


@pytest.mark.parametrize(("given", "rows_allowed"), [("7", 7), (7.0, 7), ("0", None)])
def test_executor_reads_an_env_resolved_max_rows(given: Any, rows_allowed: int | None) -> None:
    # env() values arrive as strings; a whole float is a whole number.
    assert DatabaseLookupExecutor(_capped(given))._max_rows["clarity"] == rows_allowed


# --- read-only statement gate, defence in depth (SEC-009 / ADR 0010) ---------


async def test_insert_lookup_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    # A write statement is rejected BEFORE it reaches the autocommit pool — the fake cursor never runs.
    pool = _patch_pool(monkeypatch, columns=["x"])
    ex = DatabaseLookupExecutor(_CONN)
    with pytest.raises(DbLookupError, match="read-only SELECT/WITH"):
        await ex.query("clarity", "INSERT INTO t VALUES (1)", None)
    assert pool.cursor_obj.executed is None  # the write never reached/committed


@pytest.mark.parametrize(
    "stmt",
    [
        "UPDATE t SET x=1",
        "DELETE FROM t",
        "MERGE t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET x=1",
        "EXEC sp_foo",
        "EXECUTE dbo.bar",
        "  exec sp_lower ",
    ],
)
async def test_update_and_exec_rejected(monkeypatch: pytest.MonkeyPatch, stmt: str) -> None:
    pool = _patch_pool(monkeypatch, columns=["x"])
    ex = DatabaseLookupExecutor(_CONN)
    with pytest.raises(DbLookupError, match="read-only SELECT/WITH"):
        await ex.query("clarity", stmt, None)
    assert pool.cursor_obj.executed is None


async def test_multi_statement_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    pool = _patch_pool(monkeypatch, columns=["x"])
    ex = DatabaseLookupExecutor(_CONN)
    with pytest.raises(DbLookupError, match="read-only SELECT/WITH"):
        await ex.query("clarity", "SELECT 1; DROP TABLE t", None)
    assert pool.cursor_obj.executed is None


async def test_select_with_leading_comment_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A leading comment preamble and a CTE both pass the gate and execute on the fake.
    pool = _patch_pool(monkeypatch, rows=[("123",)], columns=["npi"])
    ex = DatabaseLookupExecutor(_CONN)
    rows = await ex.query(
        "clarity", "-- comment\nSELECT npi FROM provider WHERE mrn = :mrn", {"mrn": "M1"}
    )
    assert rows == [{"npi": "123"}]
    assert pool.cursor_obj.executed is not None

    pool2 = _patch_pool(monkeypatch, rows=[("1",)], columns=["c"])
    ex2 = DatabaseLookupExecutor(_CONN)
    assert await ex2.query("clarity", "WITH cte AS (SELECT 1 AS c) SELECT * FROM cte", None) == [
        {"c": "1"}
    ]
    assert pool2.cursor_obj.executed is not None


async def test_trailing_semicolon_select_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A single trailing ';' (with only whitespace/comments after) is NOT a second statement.
    pool = _patch_pool(monkeypatch, rows=[("1",)], columns=["c"])
    ex = DatabaseLookupExecutor(_CONN)
    assert await ex.query("clarity", "SELECT 1 AS c ;  ", None) == [{"c": "1"}]
    assert pool.cursor_obj.executed is not None


# --- write-shaped statements that still OPEN with SELECT/WITH (BACKLOG #1574, #1658) ---------
#
# Each of these passed the former leading-token gate: it read the first six characters and then only
# looked for a ';'. Opening with SELECT or WITH never meant the rest was a read, and T-SQL needs no
# ';' between statements, so the chain shapes below are two statements the ';' rule cannot see.


@pytest.mark.parametrize(
    "stmt",
    [
        # #1574: SELECT ... INTO writes a table while opening with SELECT.
        "SELECT * INTO staging_copy FROM patients",
        "select mrn, name into #tmp from patients",
        # #1574: a CTE preamble followed by a terminal write.
        "WITH doomed AS (SELECT id FROM patients) "
        "DELETE FROM patients WHERE id IN (SELECT id FROM doomed)",
        "WITH c AS (SELECT 1 AS x) UPDATE patients SET mrn='X' FROM c",
        "WITH c AS (SELECT 1 AS x) INSERT INTO audit SELECT x FROM c",
        # #1658: a chained write with NO semicolon between the statements.
        "SELECT 1 UPDATE patients SET mrn='X'",
        "SELECT mrn FROM p WHERE id=1 DELETE FROM p",
        "SELECT 1 MERGE t USING s ON t.id=s.id WHEN MATCHED THEN DELETE",
        "SELECT 1 EXEC sp_who",
        "SELECT 1 DROP TABLE patients",
        # EXEC of dynamic SQL is a statement, not the scalar-function form the gate tolerates.
        "SELECT 1 EXEC('DELETE FROM patients')",
        # A comment preamble cannot mask any of it.
        "-- harmless preamble\nSELECT * INTO copy FROM patients",
        "/* harmless preamble */ SELECT * INTO copy FROM patients",
    ],
)
async def test_write_shaped_select_and_cte_rejected(
    monkeypatch: pytest.MonkeyPatch, stmt: str
) -> None:
    pool = _patch_pool(monkeypatch, columns=["x"])
    ex = DatabaseLookupExecutor(_CONN)
    with pytest.raises(DbLookupError, match="read-only SELECT/WITH"):
        await ex.query("clarity", stmt, None)
    assert pool.cursor_obj.executed is None  # the write never reached/committed


@pytest.mark.parametrize(
    "stmt",
    [
        # An unreadable remainder is refused rather than guessed at.
        "SELECT 1 /* never closed",
        "SELECT 'never closed",
        "SELECT [never closed",
        # The first token must be the whole word, not a prefix of a longer one.
        "SELECTX 1",
        "WITHOUT ROWID",
    ],
)
def test_unreadable_or_non_select_head_rejected(stmt: str) -> None:
    with pytest.raises(DbLookupError, match="read-only SELECT/WITH"):
        database._require_read_only(stmt)


@pytest.mark.parametrize(
    "stmt",
    [
        # The benign CTE contract (shipped, pinned above) restated against the predicate directly.
        "WITH cte AS (SELECT 1 AS c) SELECT * FROM cte",
        "WITH c AS (SELECT 1 AS x) SELECT * FROM c;",
        # A write keyword INSIDE a literal or a quoted identifier is data, not a statement.
        "SELECT npi FROM provider WHERE note = 'DELETE FROM patients'",
        "SELECT note FROM t WHERE note = 'a;b'",
        "SELECT [delete] FROM t",
        'SELECT "update" FROM t',
        # A write keyword is only a keyword as a whole word.
        "SELECT update_ts, deleted_flag, into_bin FROM t",
        # MySQL's scalar INSERT()/TRUNCATE() share a keyword's name but are calls, not statements.
        "SELECT INSERT('abc', 1, 1, 'z') AS s",
        "SELECT TRUNCATE(1.234, 2) AS s",
        # Comments are skipped wherever they sit, and T-SQL block comments nest.
        "SELECT 1; -- trailing note",
        "SELECT /* nested /* deep */ still */ 1",
    ],
)
def test_read_only_statements_still_admitted(stmt: str) -> None:
    assert database._require_read_only(stmt) is None


def test_lookup_dsn_is_read_only() -> None:
    # The db_lookup pool advertises ApplicationIntent=ReadOnly; the destination default does NOT (so the
    # DATABASE destination/source DSN stays byte-identical).
    settings = {"server": "db.local", "database": "Clarity", "username": "u", "password": "p"}
    assert "ApplicationIntent=ReadOnly" in database._build_dsn(settings, read_only=True)
    assert "ApplicationIntent=ReadOnly" not in database._build_dsn(settings)


# --- DatabaseLookup factory + Registry table ---------------------------------


def test_database_lookup_factory_registers(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.config import wiring

    reg = Registry()
    monkeypatch.setattr(wiring, "_active", reg)
    DatabaseLookup("clarity", server="db.local", database="Clarity")
    assert "clarity" in reg.lookups
    assert reg.lookups["clarity"].settings["server"] == "db.local"
    # The factory writes the shipped ceiling explicitly (BACKLOG #1730), and it matches the executor's.
    assert reg.lookups["clarity"].settings["max_rows"] == database.DEFAULT_DB_LOOKUP_MAX_ROWS
    DatabaseLookup("epic", server="db.local", database="Epic", max_rows=25)
    assert reg.lookups["epic"].settings["max_rows"] == 25


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
# the load-bearing invariants. NOTE — *parameterization* keeps a hostile VALUE from injecting a write.
# Read-only for the STATEMENT itself rests on the privilege of the account the lookup dials. The
# `_require_read_only` statement gate and ApplicationIntent=ReadOnly are defence in depth only. The
# autocommit pool adds no read-only property (BACKLOG #1574, #1791; docs/CONNECTIONS.md). A Handler
# AUTHOR's literal statement is the author's contract, not an attacker-influenceable path. See the
# audit memo + backlog note S12-1.


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
    # Pins autocommit=True, the pool mode ADR 0010 chose: each lookup is one self-contained read. The
    # flag gives NO read-only property. A write the statement gate admitted would commit at once, so
    # read-only rests on the lookup account's privilege (BACKLOG #1791; docs/CONNECTIONS.md). The test
    # name predates that correction and is kept.
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
