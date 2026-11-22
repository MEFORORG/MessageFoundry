# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A parent metadata cell that opens but cannot be read as correlation lineage dead-letters its
routed row, so the FIFO lane moves on (BACKLOG #5758). A key outage still holds the lane. Postgres
applies state writes in one (namespace, key) order, as SQL Server does.

SQLite runs for real. Postgres and SQL Server run against offline fakes, which prove the control
flow of each handoff and nothing about a live server's locking."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store import MessageStatus, OutboxStatus, Stage
from messagefoundry.store import postgres as pg
from messagefoundry.store import sqlserver as ss
from messagefoundry.store import store as sqlite_module
from messagefoundry.store.cell_tag import CellTagError
from messagefoundry.store.crypto import CipherUnavailableError, IdentityCipher
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore
from tests.test_metadata_bag import _to_routed

# A marker no refusal may echo: the log and the error name the row, never the cell's content.
_SENTINEL = "SYNTHSENTINEL"

BAD_CELLS = {
    "malformed-json": '{"correlation_depth": "' + _SENTINEL,
    "non-dict": f'["{_SENTINEL}"]',
    "json-null": "null",
    "non-numeric-depth": f'{{"correlation_depth": "{_SENTINEL}"}}',
    "list-depth": '{"correlation_depth": [1]}',
    "infinity-depth": '{"correlation_depth": Infinity}',
    "nan-depth": '{"correlation_depth": NaN}',
    "deep-nesting": "[" * 200_000,
    # Decodes, but the child's json.dumps of the root would overflow the encoder.
    "deep-root": '{"correlation_root_id": ' + "[" * 15_600 + "]" * 15_600 + "}",
    "non-string-root": '{"correlation_root_id": {"k": 1}}',
}
_BAD = pytest.mark.parametrize("cell", list(BAD_CELLS.values()), ids=list(BAD_CELLS))
_GOOD_CELL = '{"correlation_depth": 3, "correlation_id": "root"}'


def _assert_clean_refusal(err: BaseException) -> None:
    """Nothing the refusal carries reaches the cell: json's error holds the whole document."""
    assert isinstance(err, CellTagError)
    assert _SENTINEL not in str(err)
    assert err.__cause__ is None and err.__context__ is None


# --- SQLite, for real ---------------------------------------------------------------------------


@pytest.fixture
async def sqlite_store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    store = await MessageStore.open(tmp_path / "t5758.db")
    try:
        yield store
    finally:
        await store.close()


async def _set_cell(store: MessageStore, mid: str, cell: str) -> None:
    await store._db.execute("UPDATE messages SET metadata=? WHERE id=?", (cell, mid))
    await store._db.commit()


async def _queue_rows(store: MessageStore, mid: str) -> list[tuple[str, str]]:
    cur = await store._db.execute("SELECT stage, status FROM queue WHERE message_id=?", (mid,))
    return [(str(r[0]), str(r[1])) for r in await cur.fetchall()]


async def _handoff(store: MessageStore, mid: str, rid: str) -> bool:
    return await store.transform_handoff(
        routed_id=rid,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        pt_deliveries=[("PT_5758", "MSH|^~\\&|CHILD")],
    )


@_BAD
async def test_sqlite_dead_letters_once_and_frees_the_lane(
    sqlite_store: MessageStore, cell: str, caplog: pytest.LogCaptureFixture
) -> None:
    mid, rtd = await _to_routed(sqlite_store)
    await _set_cell(sqlite_store, mid, cell)
    with caplog.at_level(logging.WARNING):
        assert await _handoff(sqlite_store, mid, rtd.id) is False

    assert await _queue_rows(sqlite_store, mid) == [(Stage.ROUTED.value, OutboxStatus.DEAD.value)]
    message = await sqlite_store.get_message(mid)
    assert message is not None and message["status"] == MessageStatus.ERROR.value
    assert any("correlation metadata" in r.getMessage() for r in caplog.records)
    assert _SENTINEL not in caplog.text
    # No child was produced from the refused cell.
    cur = await sqlite_store._db.execute("SELECT id FROM messages")
    assert len(list(await cur.fetchall())) == 1

    # A re-run is a no-op, so the row is dead-lettered exactly once.
    assert await _handoff(sqlite_store, mid, rtd.id) is False
    assert await _queue_rows(sqlite_store, mid) == [(Stage.ROUTED.value, OutboxStatus.DEAD.value)]

    # The next message on the lane is claimable.
    next_mid, next_rtd = await _to_routed(sqlite_store)
    assert next_rtd.message_id == next_mid


async def test_sqlite_valid_parent_still_produces_its_child(sqlite_store: MessageStore) -> None:
    mid, rtd = await _to_routed(sqlite_store)
    await _set_cell(sqlite_store, mid, _GOOD_CELL)
    assert await _handoff(sqlite_store, mid, rtd.id) is True
    cur = await sqlite_store._db.execute("SELECT metadata FROM messages WHERE id<>?", (mid,))
    rows = list(await cur.fetchall())
    assert len(rows) == 1 and '"correlation_depth": 4' in str(rows[0][0])


async def test_sqlite_key_outage_still_holds_the_lane(
    sqlite_store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    mid, rtd = await _to_routed(sqlite_store)

    def outage(*_a: Any, **_k: Any) -> str:
        raise CipherUnavailableError("synthetic key outage")

    monkeypatch.setattr(sqlite_module, "open_message_cell", outage)
    with pytest.raises(CipherUnavailableError):
        await _handoff(sqlite_store, mid, rtd.id)
    # Rolled back and not dead: the row is still in flight, to re-run once the key is back.
    assert await _queue_rows(sqlite_store, mid) == [
        (Stage.ROUTED.value, OutboxStatus.INFLIGHT.value)
    ]


# --- Postgres, offline ---------------------------------------------------------------------------


class _Tx:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *_exc: object) -> bool:
        return False


class _PgConn:
    def __init__(self, cell: str | None) -> None:
        self.cell = cell

    def transaction(self, **_kw: Any) -> _Tx:
        return _Tx()

    async def fetchval(self, _sql: str, *_args: Any) -> str:
        return "rtd"

    async def fetchrow(self, _sql: str, *_args: Any) -> dict[str, Any]:
        return {"channel_id": "IB", "metadata": self.cell}


def _pg_store(cell: str | None) -> tuple[Any, dict[str, list[Any]]]:
    store: Any = object.__new__(PostgresStore)
    seen: dict[str, list[Any]] = {"dead": [], "children": [], "state": []}
    store._cipher = IdentityCipher()
    store._state_cache = {}
    store._cluster_state_convergence = False
    conn = _PgConn(cell)

    @asynccontextmanager
    async def acquire(**_kw: Any) -> AsyncIterator[_PgConn]:
        yield conn

    async def noop(*_a: Any, **_k: Any) -> None:
        return None

    async def child(
        _conn: Any, _rid: str, _mid: str, _pt: str, _body: str, meta: Any, *_a: Any
    ) -> bool:
        seen["children"].append(meta)
        return True

    async def state(_conn: Any, namespace: str, key: str, *_a: Any) -> None:
        seen["state"].append((namespace, key))

    async def dead(outbox_id: str, error: str, now: float | None = None) -> None:
        seen["dead"].append((outbox_id, error))

    store._timed_acquire = acquire
    store._lock_outbound_lanes = noop
    store._insert_passthrough_child_pg = child
    store._insert_passthrough_marker_pg = noop
    store._inherit_attachments = noop
    store._apply_state_op = state
    store._event = noop
    store._maybe_finalize_message = noop
    store._record_own_state_bumps = lambda _bumped: None
    store.dead_letter_now = dead
    return store, seen


_PG_KWARGS: dict[str, Any] = {
    "routed_id": "rtd",
    "message_id": "m-5758",
    "channel_id": "IB",
    "deliveries": [],
    "pt_deliveries": [("PT", "MSH|child")],
}


@_BAD
async def test_postgres_dead_letters_once(cell: str, caplog: pytest.LogCaptureFixture) -> None:
    store, seen = _pg_store(cell)
    with caplog.at_level(logging.WARNING):
        assert await store.transform_handoff(**_PG_KWARGS) is False
    assert [row for row, _ in seen["dead"]] == ["rtd"]
    assert seen["children"] == []
    assert _SENTINEL not in caplog.text and _SENTINEL not in seen["dead"][0][1]


async def test_postgres_valid_parent_reaches_its_child() -> None:
    store, seen = _pg_store(_GOOD_CELL)
    assert await store.transform_handoff(**_PG_KWARGS) is True
    assert seen["dead"] == []
    assert seen["children"][0]["correlation_depth"] == 3


async def test_postgres_key_outage_does_not_dead_letter(monkeypatch: pytest.MonkeyPatch) -> None:
    store, seen = _pg_store(_GOOD_CELL)

    def outage(*_a: Any, **_k: Any) -> str:
        raise CipherUnavailableError("synthetic key outage")

    monkeypatch.setattr(pg, "open_message_cell", outage)
    with pytest.raises(CipherUnavailableError):
        await store.transform_handoff(**_PG_KWARGS)
    assert seen["dead"] == []


async def test_postgres_state_writes_are_sorted_and_keep_last_writer() -> None:
    store, seen = _pg_store(None)
    # Values that do not order: a plain sorted(state_ops) would raise TypeError on the tie.
    ops = [("zeta", "k", {"v": 1}), ("alpha", "b", {"v": 2}), ("alpha", "a", {"v": 3})]
    ties = [("alpha", "a", {"v": 4})]
    kwargs = {**_PG_KWARGS, "pt_deliveries": [], "state_ops": ops + ties}
    assert await store.transform_handoff(**kwargs) is True
    assert seen["state"] == [("alpha", "a"), ("alpha", "a"), ("alpha", "b"), ("zeta", "k")]
    assert store._state_cache[("alpha", "a")] == {"v": 4}


# --- SQL Server, offline: the async handoff and its fused sync twin ------------------------------


class _SsAsyncCursor:
    def __init__(self, cell: str | None) -> None:
        self.cell, self._last = cell, ""

    async def execute(self, sql: str, _params: Any = ()) -> None:
        self._last = sql

    async def fetchone(self) -> Any:
        return _ss_row(self._last, self.cell)

    async def fetchall(self) -> Any:
        return []

    async def close(self) -> None:
        return None


class _SsSyncCursor:
    def __init__(self, cell: str | None) -> None:
        self.cell, self._last = cell, ""

    def execute(self, sql: str, _params: Any = ()) -> None:
        self._last = sql

    def fetchone(self) -> Any:
        return _ss_row(self._last, self.cell)

    def fetchall(self) -> Any:
        return []

    def close(self) -> None:
        return None


class _SsSyncConn:
    def __init__(self, cur: _SsSyncCursor) -> None:
        self._cur, self.rollbacks, self.commits = cur, 0, 0

    def cursor(self) -> _SsSyncCursor:
        return self._cur

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


class _SsAsyncConn:
    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


def _ss_row(sql: str, cell: str | None) -> Any:
    if sql == ss._SQL_DELETE_GUARD:
        return ("rtd",)
    if sql == ss._SQL_SELECT_METADATA:
        return ("IB", cell)
    if "sp_getapplock" in sql:
        return (0,)
    return None


def _ss_store(cell: str | None) -> tuple[Any, list[str]]:
    store: Any = object.__new__(SqlServerStore)
    dead: list[str] = []
    store._cipher = IdentityCipher()
    store._state_cache = {}
    store._message_events = "all"
    store._audit_mac_key = None
    store._audit_chain_keyed = False
    store.committed_txns = 0
    store.body_copies = 0

    @asynccontextmanager
    async def acquire(*_a: Any, **_k: Any) -> AsyncIterator[_SsAsyncConn]:
        yield _SsAsyncConn()

    @asynccontextmanager
    async def cursor(*_a: Any, **_k: Any) -> AsyncIterator[_SsAsyncCursor]:
        yield _SsAsyncCursor(cell)

    async def dead_letter(outbox_id: str, _error: str, now: float | None = None) -> None:
        dead.append(outbox_id)

    store._acquire = acquire
    store._cursor = cursor
    store.dead_letter_now = dead_letter
    return store, dead


@_BAD
async def test_sqlserver_async_dead_letters_once(cell: str) -> None:
    store, dead = _ss_store(cell)
    assert await store.transform_handoff(**_PG_KWARGS) is False
    assert dead == ["rtd"]


@_BAD
def test_sqlserver_sync_raises_the_contained_family_and_rolls_back(cell: str) -> None:
    """The fused path dead-letters on ``CellTagError`` in ``_process_routed_item``."""
    store, _dead = _ss_store(cell)
    conn = _SsSyncConn(_SsSyncCursor(cell))
    with pytest.raises(CellTagError) as info:
        store.transform_handoff_sync(conn, **_PG_KWARGS)
    _assert_clean_refusal(info.value)
    assert conn.rollbacks == 1 and conn.commits == 0


def test_sqlserver_valid_parent_decodes_unchanged() -> None:
    assert ss._parent_meta_from_row(_GOOD_CELL, message_id="m", channel_id="IB") == {
        "correlation_depth": 3,
        "correlation_id": "root",
    }
    assert ss._parent_meta_from_row(None, message_id="m", channel_id="IB") == {}
    assert ss._parent_meta_from_row("", message_id="m", channel_id="IB") == {}


def test_sqlserver_sync_key_outage_is_not_the_contained_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _dead = _ss_store(_GOOD_CELL)

    def outage(*_a: Any, **_k: Any) -> str:
        raise CipherUnavailableError("synthetic key outage")

    monkeypatch.setattr(ss, "open_message_cell", outage)
    with pytest.raises(CipherUnavailableError) as info:
        store.transform_handoff_sync(_SsSyncConn(_SsSyncCursor(_GOOD_CELL)), **_PG_KWARGS)
    assert not isinstance(info.value, CellTagError)
