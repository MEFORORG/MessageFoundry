# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DATABASE stored-proc OUT-param / scalar-return capture (BACKLOG #67, ADR 0013 amendment).

The aioodbc/pyodbc driver is never imported — a fake cursor/conn/pool stands in (mirroring
test_database_transport.py), so the merge-all-result-sets capture logic and the wiring-time opt-in gate
are unit-tested without a real SQL Server.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Database, WiringError, build_outbound_connection
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.database import DatabaseDestination

# `{ ? = CALL proc }` ODBC escape with a :name bind (translated to positional ? by the connector).
PROC = "{ ? = CALL dbo.ingest(:mrn) }"


def _dest(**over: Any) -> DatabaseDestination:
    base: dict[str, Any] = dict(  # noqa: C408
        server="s", database="d", statement=PROC, capture_out_params=True
    )
    base.update(over)
    d = build_destination(
        Destination(name="OB_DB", type=ConnectorType.DATABASE, settings=Database(**base).settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, DatabaseDestination)
    return d


class _MergeCursor:
    """A fake cursor exposing multiple result sets via nextset() — a proc that emits data rows AND a
    trailing OUT/return SELECT."""

    def __init__(
        self, sets: list[tuple[list[tuple[Any, ...]] | None, list[tuple[Any, ...]] | None]]
    ):
        # sets: list of (rows, description); rows=None models "not a query" (fetchall raises).
        self._sets = sets
        self._i = 0

    @property
    def description(self) -> list[tuple[Any, ...]] | None:
        return self._sets[self._i][1]

    async def fetchall(self) -> list[tuple[Any, ...]]:
        rows = self._sets[self._i][0]
        if rows is None:
            raise RuntimeError("No results.  Previous SQL was not a query.")
        return rows

    async def nextset(self) -> bool:
        if self._i + 1 < len(self._sets):
            self._i += 1
            return True
        return False


# --- __init__ / setting plumbing --------------------------------------------


def test_out_params_implies_capture_response() -> None:
    d = _dest()
    assert d.capture_out_params is True
    assert d.capture_response is True  # implied even though capture_response was not set


def test_capture_response_default_off_is_byte_identical() -> None:
    d = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.DATABASE,
            settings=Database(
                server="s", database="d", statement="INSERT INTO t VALUES (1)"
            ).settings,
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, DatabaseDestination)
    assert d.capture_out_params is False and d.capture_response is False


# --- _capture_merged: walk + merge every result set -------------------------


async def test_merges_data_rows_and_out_return_select() -> None:
    d = _dest()
    cur = _MergeCursor(
        [
            ([(1, "a"), (2, "b")], [("id",), ("name",)]),  # a data result-set
            ([(0, 4242)], [("return_value",), ("new_id",)]),  # the trailing OUT/return SELECT
        ]
    )
    r = await d._capture(cur)
    assert r.outcome == "accepted"
    # Every set is merged into one JSON array — the OUT/return row is NOT dropped.
    assert '"return_value": 0' in r.body and '"new_id": 4242' in r.body
    assert '"id": 1' in r.body and '"name": "b"' in r.body
    assert r.detail == "3 row(s)"


async def test_skips_non_query_sets_and_captures_the_out_select() -> None:
    # A proc whose first "set" is a non-query (an internal INSERT) → fetchall raises; it must be skipped,
    # not fail the capture, and the trailing OUT/return SELECT is still captured.
    d = _dest()
    cur = _MergeCursor([(None, None), ([(7,)], [("status",)])])
    r = await d._capture(cur)
    assert r.outcome == "accepted" and '"status": 7' in r.body


async def test_no_out_values_is_no_reply() -> None:
    d = _dest()
    cur = _MergeCursor([(None, None)])  # nothing to fetch anywhere
    r = await d._capture(cur)
    assert r.outcome == "no_reply" and r.body == ""


async def test_over_row_cap_is_unparseable_empty_body() -> None:
    d = _dest(capture_max_rows=2)
    cur = _MergeCursor([([(1,), (2,)], [("x",)]), ([(3,)], [("x",)])])  # 3 merged > cap 2
    r = await d._capture(cur)
    assert r.outcome == "unparseable" and r.body == ""


async def test_unserializable_column_does_not_raise() -> None:
    # A column value json can't encode must NOT propagate (that would roll back the successful write).
    d = _dest()

    class _Weird:
        pass

    cur = _MergeCursor([([(_Weird(),)], [("col",)])])
    r = await d._capture(cur)
    assert r.outcome == "unparseable" and r.body == ""


async def test_single_set_without_nextset_capability() -> None:
    # A cursor with no nextset() (some drivers) still captures its single set under capture_out_params.
    d = _dest()

    class _NoNext:
        description = [("status",)]

        async def fetchall(self) -> list[tuple[Any, ...]]:
            return [(9,)]

    r = await d._capture(_NoNext())
    assert r.outcome == "accepted" and '"status": 9' in r.body


# --- send() end-to-end with a faked pool ------------------------------------


class _SendCursor(_MergeCursor):
    def __init__(self, sets: list[Any]) -> None:
        super().__init__(sets)
        self.executed: list[tuple[str, tuple[Any, ...]]] = []

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.executed.append((sql, params))


class _Conn:
    def __init__(self, cur: _SendCursor) -> None:
        self._cur = cur
        self.committed = False
        self.rolledback = False

    async def cursor(self) -> _SendCursor:
        return self._cur

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolledback = True


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn

    async def acquire(self) -> _Conn:
        return self._conn

    async def release(self, conn: _Conn) -> None:
        pass


async def test_send_captures_out_params_pre_commit() -> None:
    cur = _SendCursor([([(0, 555)], [("return_value",), ("new_id",)])])
    d, conn = _send_dest(cur)
    resp = await d.send('{"mrn": "42"}')
    assert conn.committed and not conn.rolledback
    assert resp is not None and resp.outcome == "accepted"
    assert '"return_value": 0' in resp.body and '"new_id": 555' in resp.body
    # The proc was executed with the :mrn bind translated to positional ?.
    assert cur.executed == [("{ ? = CALL dbo.ingest(?) }", ("42",))]


# --- BACKLOG #5714: a driver error reading the result is the write's failure -------------

# pyodbc's shape: ``args == (sqlstate, message)``. 40001 is SQL Server's deadlock victim, 42000 a
# RAISERROR from a later statement in the proc's batch.
_DEADLOCK = Exception("40001", "[40001] deadlock victim (1205) (SQLFetch)")
_PROC_ERROR = Exception("42000", "[42000] proc failed (50000) (SQLMoreResults)")


class _FaultCursor(_SendCursor):
    """A ``_SendCursor`` whose fetch or ``nextset()`` raises a driver error on a chosen set."""

    def __init__(
        self,
        sets: list[Any],
        *,
        fetch_raises_on: int | None = None,
        nextset_raises_on: int | None = None,
    ) -> None:
        super().__init__(sets)
        self._fetch_raises_on = fetch_raises_on
        self._nextset_raises_on = nextset_raises_on

    async def fetchall(self) -> list[tuple[Any, ...]]:
        if self._i == self._fetch_raises_on:
            raise _DEADLOCK
        return await super().fetchall()

    async def nextset(self) -> bool:
        if self._i == self._nextset_raises_on:
            raise _PROC_ERROR
        return await super().nextset()


def _send_dest(cur: _SendCursor, **over: Any) -> tuple[DatabaseDestination, _Conn]:
    conn = _Conn(cur)
    d = _dest(**over)
    d._pool = _Pool(conn)
    return d, conn


async def test_send_rolls_back_when_a_result_set_fetch_fails() -> None:
    """Red on the old code: the blanket ``except`` around ``fetchall`` read the deadlock as "not a
    query", so the write committed and the row would have been recorded as delivered."""
    cur = _FaultCursor([([(1,)], [("id",)]), ([(0,)], [("status",)])], fetch_raises_on=1)
    d, conn = _send_dest(cur)
    with pytest.raises(DeliveryError) as ei:
        await d.send('{"mrn": "42"}')
    assert not isinstance(ei.value, NegativeAckError)  # 40001 is transient: the row retries
    assert conn.rolledback and not conn.committed


async def test_send_rolls_back_when_nextset_raises_a_later_statement_error() -> None:
    """Red on the old code: an error ``nextset()`` raised stopped the walk and the write committed."""
    cur = _FaultCursor([([(1,)], [("id",)]), ([(0,)], [("status",)])], nextset_raises_on=0)
    d, conn = _send_dest(cur)
    with pytest.raises(NegativeAckError) as ei:
        await d.send('{"mrn": "42"}')
    assert ei.value.permanent is True and ei.value.code == "42000"
    assert conn.rolledback and not conn.committed


async def test_an_error_past_the_row_cap_still_reaches_send() -> None:
    """Over ``capture_max_rows`` the walk goes on to the last set, so a later statement's error is
    not left unread under the commit. Red on the old code, which returned at the cap."""
    cur = _FaultCursor(
        [([(1,), (2,)], [("x",)]), ([(3,)], [("x",)]), ([(4,)], [("x",)])],
        nextset_raises_on=1,
    )
    d, conn = _send_dest(cur, capture_max_rows=2)
    with pytest.raises(NegativeAckError):
        await d.send('{"mrn": "42"}')
    assert conn.rolledback and not conn.committed


async def test_over_cap_walks_every_set_before_reporting_unparseable() -> None:
    cur = _FaultCursor([([(1,), (2,)], [("x",)]), ([(3,)], [("x",)]), (None, None)])
    d, conn = _send_dest(cur, capture_max_rows=2)
    resp = await d.send('{"mrn": "42"}')
    assert resp is not None and resp.outcome == "unparseable" and resp.body == ""
    assert cur._i == 2  # the walk reached the last set
    assert conn.committed


async def test_a_set_with_no_description_is_not_fetched() -> None:
    """A genuine "not a query" set is read from ``description``, never from a failed fetch, so the
    write still commits. pyodbc raises "No results" from a fetch in exactly that state."""

    class _NoFetch(_SendCursor):
        async def fetchall(self) -> list[tuple[Any, ...]]:
            if self.description is None:
                raise AssertionError("fetched a set with no description")
            return await super().fetchall()

    cur = _NoFetch([(None, None), ([(7,)], [("status",)])])
    d, conn = _send_dest(cur)
    resp = await d.send('{"mrn": "42"}')
    assert resp is not None and resp.outcome == "accepted" and '"status": 7' in resp.body
    assert conn.committed and not conn.rolledback


# --- wiring-time opt-in gate -------------------------------------------------


def test_wiring_accepts_out_params_on_proc_call() -> None:
    # An ODBC {CALL} escape and a leading EXEC both qualify — and the flag has NO RETURNING/OUTPUT token.
    build_outbound_connection(
        "OB_CALL", Database(server="s", database="d", statement=PROC, capture_out_params=True)
    )
    build_outbound_connection(
        "OB_EXEC",
        Database(
            server="s",
            database="d",
            statement="DECLARE @rv INT; EXEC @rv = dbo.proc :mrn; SELECT @rv AS status;",
            capture_out_params=True,
        ),
    )


def test_wiring_out_params_implies_capture_response() -> None:
    conn = build_outbound_connection(
        "OB_CALL2", Database(server="s", database="d", statement=PROC, capture_out_params=True)
    )
    assert conn.spec.settings.get("capture_response") is True


def test_wiring_rejects_out_params_on_plain_write() -> None:
    with pytest.raises(WiringError, match="stored-procedure call"):
        build_outbound_connection(
            "OB_BAD",
            Database(
                server="s",
                database="d",
                statement="INSERT INTO t (mrn) VALUES (:mrn)",
                capture_out_params=True,
            ),
        )
