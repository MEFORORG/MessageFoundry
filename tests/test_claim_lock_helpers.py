# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Offline checks of the SQL Server lock-hold helpers in ``tests/_claim_lock_helpers.py`` (BACKLOG #4915).

The helpers run only on the hosted SQL Server legs, where a failure in their cleanup shows up as a
hang in the NEXT test rather than in the one that failed. These stand-ins drive the failure paths a
live server never offers on demand: a ROLLBACK that raises, a cancellation while the lock is being
taken, and a release on a connection nobody gated. Each must still hand the connection back to the
pool, and close the cursor before its connection. The stand-in raises before any gated pyodbc call is
running, so the gate's deferred close behind a running statement is not driven here;
``tests/test_backlog2049_sqlserver_cancel_handle_free.py`` drives that path.

``assert_skip_named`` is checked here too, with constructed claim results: a live server cannot be
made to produce the wrong answer it must refuse."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

import tests._claim_lock_helpers as helpers
from messagefoundry.odbc_call_gate import call_gate
from messagefoundry.store import ClaimAbortPhase, ClaimedHeads, ClaimLockTimeout, Stage
from tests._claim_lock_helpers import assert_skip_named, ss_hold_row_lock, ss_release_row_lock


class _RawCursor:
    def __init__(self, closed: list[str]) -> None:
        self._closed = closed

    def close(self) -> None:
        self._closed.append("cursor")


class _RawConn:
    def __init__(self, closed: list[str]) -> None:
        self._closed = closed

    def close(self) -> None:
        self._closed.append("conn")


class _Cursor:
    """An aioodbc-shaped cursor: ``_impl`` is the raw handle; ``fail_on`` raises on that statement."""

    def __init__(self, closed: list[str], fail_on: str | None, exc: BaseException) -> None:
        self._impl = _RawCursor(closed)
        self._fail_on = fail_on
        self._exc = exc
        self.statements: list[str] = []
        self._rows: list[tuple[Any, ...]] = []

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.statements.append(sql)
        if self._fail_on is not None and sql.startswith(self._fail_on):
            raise self._exc
        self._rows = [("IB_X", "pending", 1)] if sql.startswith("SELECT") else []

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows

    async def close(self) -> None:
        self._impl.close()


class _Conn:
    """An aioodbc-shaped connection with a bound ``_execute``, so the call gate installs on it."""

    _executor = None

    def __init__(self, closed: list[str], cur: _Cursor) -> None:
        self._conn: Any = _RawConn(closed)
        self._cur = cur

    def _execute(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    async def cursor(self) -> _Cursor:
        return self._cur


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn
        self.released: list[_Conn] = []

    async def acquire(self) -> _Conn:
        return self._conn

    async def release(self, conn: _Conn) -> None:
        self.released.append(conn)


class _Store:
    def __init__(self, pool: _Pool) -> None:
        self._pool = pool


def _rig(fail_on: str | None, exc: BaseException) -> tuple[_Store, _Conn, _Cursor, list[str]]:
    closed: list[str] = []
    cur = _Cursor(closed, fail_on, exc)
    conn = _Conn(closed, cur)
    return _Store(_Pool(conn)), conn, cur, closed


async def _settled(closed: list[str], want: int) -> list[str]:
    """The discard's close runs on an executor thread; wait for it, bounded at about 10 s so a late
    worker thread on a loaded runner does not read as a close out of order."""
    for _ in range(2000):
        if len(closed) >= want:
            break
        await asyncio.sleep(0.005)
    return closed


async def test_a_clean_release_rolls_back_and_recycles_the_connection() -> None:
    """THE CONTROL: with nothing failing, the connection goes back to the pool still open."""
    store, conn, cur, closed = _rig(None, RuntimeError())
    held_conn, held_cur = await ss_hold_row_lock(store, "m1", "ingress")
    await ss_release_row_lock(store, held_conn, held_cur)
    assert cur.statements[-1] == "ROLLBACK TRAN"
    assert call_gate(conn) is not None, "the hold must gate the connection it may have to discard"
    assert store._pool.released == [conn]
    assert conn._conn is not None, "a clean release must not discard the connection"
    assert closed == ["cursor"]


async def test_a_rollback_that_raises_still_releases_and_discards() -> None:
    """Before BACKLOG #4915 the callers' ``finally`` skipped the close and the release when the
    ROLLBACK raised, leaving the lock held against the next test's cleanup DELETE."""
    store, conn, _, closed = _rig("ROLLBACK", RuntimeError("connection broken"))
    held_conn, held_cur = await ss_hold_row_lock(store, "m1", "ingress")
    with pytest.raises(RuntimeError, match="connection broken"):
        await ss_release_row_lock(store, held_conn, held_cur)
    assert store._pool.released == [conn]
    assert conn._conn is None, "the connection must leave the pool's reach, not be recycled"
    assert await _settled(closed, 2) == ["cursor", "conn"], (
        "the cursor closes before its connection"
    )


async def test_a_cancellation_while_taking_the_lock_still_releases() -> None:
    """``except Exception`` never saw a cancellation, so the old setup cleanup leaked the connection."""
    store, conn, _, closed = _rig("BEGIN TRAN", asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await ss_hold_row_lock(store, "m1", "ingress")
    assert store._pool.released == [conn]
    assert conn._conn is None
    assert await _settled(closed, 2) == ["cursor", "conn"]


async def test_a_release_on_a_connection_nobody_gated_still_discards_through_the_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T6 takes its connection straight from the pool, not through ``ss_hold_row_lock``. A release
    that found it ungated used to discard through ``close_one_shot``, which closes the handles beside
    a statement a cancellation may have left running: the BACKLOG #2049 native-crash shape. The
    release now gates the connection first, so the discard goes to the gate (BACKLOG #4915)."""
    store, conn, cur, closed = _rig("ROLLBACK", RuntimeError("connection broken"))
    assert call_gate(conn) is None, "the rig must start ungated, or this proves nothing"

    async def _refuse(*_: Any) -> None:
        raise AssertionError("the discard took close_one_shot, so it ran outside the call gate")

    monkeypatch.setattr(helpers, "close_one_shot", _refuse)
    with pytest.raises(RuntimeError, match="connection broken"):
        await ss_release_row_lock(store, conn, cur)
    assert call_gate(conn) is not None
    assert store._pool.released == [conn]
    assert conn._conn is None
    assert await _settled(closed, 2) == ["cursor", "conn"]


async def test_a_release_with_no_cursor_discards_without_raising() -> None:
    """A caller whose cursor was never made ran no statement, so it holds no transaction: the release
    discards the connection, says nothing, and still hands it back to the pool."""
    store, conn, _, closed = _rig(None, RuntimeError())
    await ss_release_row_lock(store, conn, None)
    assert store._pool.released == [conn]
    assert conn._conn is None
    assert await _settled(closed, 1) == ["conn"]


async def test_a_release_before_the_lock_was_taken_discards_without_a_rollback() -> None:
    """``held=False``, for T6's setup failing before its lock is proven taken: no ROLLBACK, which on
    no open transaction would raise 3903 and replace the setup's own failure. The cursor still goes
    to the gate before its connection."""
    store, conn, cur, closed = _rig("ROLLBACK", RuntimeError("3903: no BEGIN TRANSACTION"))
    await ss_release_row_lock(store, conn, cur, held=False)
    assert cur.statements == []
    assert store._pool.released == [conn]
    assert conn._conn is None
    assert await _settled(closed, 2) == ["cursor", "conn"]


def _aborted(phase: ClaimAbortPhase, named: frozenset[str]) -> ClaimedHeads:
    return ClaimedHeads(
        by_lane={},
        rearm=frozenset(),
        lock_timeout=ClaimLockTimeout(phase=phase, lanes_in_claim=1),
        head_skipped=named,
    )


_LANE = "IB_SKIP"


@pytest.mark.parametrize("stage", [Stage.INGRESS.value, Stage.ROUTED.value])
def test_a_head_abort_before_the_fetch_may_not_echo_the_lane(stage: str) -> None:
    """BACKLOG #4915. At INGRESS and ROUTED a HEAD-phase 1222 comes before the fetch and read no
    row, so a ``{lane}`` there is the request list echoed back, the first-fix defect of BACKLOG
    #1270. The first #4915 fix admitted it for every caller."""
    assert_skip_named(
        _aborted(ClaimAbortPhase.HEAD, frozenset()), _LANE, abort_ok=True, stage=stage
    )
    with pytest.raises(AssertionError, match="HEAD-phase 1222"):
        assert_skip_named(
            _aborted(ClaimAbortPhase.HEAD, frozenset({_LANE})), _LANE, abort_ok=True, stage=stage
        )


def test_an_outbound_head_abort_may_carry_the_skip_its_fetch_read() -> None:
    """THE CONTROL for the test above: only an OUTBOUND claim stays in the HEAD phase past its fetch,
    through the ``delivered_keys`` probe, so the lane it read may ride out. Nothing else may."""
    outbound = Stage.OUTBOUND.value
    for named in (frozenset(), frozenset({_LANE})):
        assert_skip_named(
            _aborted(ClaimAbortPhase.HEAD, named), _LANE, abort_ok=True, stage=outbound
        )
    with pytest.raises(AssertionError, match="HEAD-phase 1222"):
        assert_skip_named(
            _aborted(ClaimAbortPhase.HEAD, frozenset({_LANE, "IB_OTHER"})),
            _LANE,
            abort_ok=True,
            stage=outbound,
        )


@pytest.mark.parametrize("stage", [Stage.INGRESS.value, Stage.OUTBOUND.value])
def test_an_abort_is_admitted_only_when_asked_and_only_in_the_head_phase(stage: str) -> None:
    """``abort_ok=False`` admits no abort, and a FINALIZE-phase abort came after the fetch, so in
    both the lane must still be named."""
    for phase, abort_ok in ((ClaimAbortPhase.HEAD, False), (ClaimAbortPhase.FINALIZE, True)):
        with pytest.raises(AssertionError, match="without being named"):
            assert_skip_named(_aborted(phase, frozenset()), _LANE, abort_ok=abort_ok, stage=stage)
        assert_skip_named(
            _aborted(phase, frozenset({_LANE})), _LANE, abort_ok=abort_ok, stage=stage
        )
