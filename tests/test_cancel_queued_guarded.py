# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``cancel_queued`` writes CANCELLED only over a row that is still PENDING (BACKLOG #5732).

SQLite runs for real. Postgres and SQL Server run against recording fakes, so these tests pin the
statement each one sends and how it counts. Nothing here, and no hosted test, drives a concurrent
claim against a real Postgres or SQL Server, so the race on those two is argued, not measured.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock

import pytest

from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from tests._store_audit import no_purge_audit


@pytest.fixture
async def store(tmp_path: Any) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "cancel.db")
    yield s
    await s.close()


async def _status(store: MessageStore, message_id: str) -> str:
    return str((await store.outbox_for(message_id))[0]["status"])


def _intercept_lane_select(store: MessageStore, after_select: Any) -> None:
    """Run ``after_select`` once, after the lane SELECT was fetched and just before the UPDATE."""
    real = store._db.execute
    fired = False

    async def execute(sql: str, *args: Any) -> Any:
        nonlocal fired
        if not fired and sql.startswith("UPDATE queue SET status=?, updated_at=?"):
            fired = True
            await after_select(real)
        return await real(sql, *args)

    store._db.execute = execute  # type: ignore[method-assign,assignment]


async def test_sqlite_row_claimed_after_the_select_stays_claimed_and_is_not_counted(
    store: MessageStore,
) -> None:
    first = await store.enqueue_message(channel_id="c", raw="a", deliveries=[("d", "p")], now=1.0)
    second = await store.enqueue_message(channel_id="c", raw="b", deliveries=[("d", "q")], now=2.0)
    claimed_id = (await store.outbox_for(first))[0]["id"]

    async def claim(execute: Any) -> None:
        await execute(
            "UPDATE queue SET status=? WHERE id=?", (OutboxStatus.INFLIGHT.value, claimed_id)
        )

    _intercept_lane_select(store, claim)
    assert await store.cancel_queued(None, "d", now=3.0, audit=no_purge_audit) == 1
    assert await _status(store, first) == OutboxStatus.INFLIGHT.value
    assert await _status(store, second) == OutboxStatus.CANCELLED.value


async def test_sqlite_another_process_cannot_claim_between_select_and_update(
    store: MessageStore, tmp_path: Any
) -> None:
    mid = await store.enqueue_message(channel_id="c", raw="a", deliveries=[("d", "p")], now=1.0)
    row_id = (await store.outbox_for(mid))[0]["id"]
    refused: list[bool] = []

    async def rival_claim(_execute: Any) -> None:
        rival = sqlite3.connect(tmp_path / "cancel.db", timeout=0)
        try:
            with rival:
                rival.execute(
                    "UPDATE queue SET status=? WHERE id=?", (OutboxStatus.INFLIGHT.value, row_id)
                )
            refused.append(False)
        except sqlite3.OperationalError:
            refused.append(True)
        finally:
            rival.close()

    _intercept_lane_select(store, rival_claim)
    assert await store.cancel_queued(None, "d", now=2.0, audit=no_purge_audit) == 1
    assert refused == [True]
    assert await _status(store, mid) == OutboxStatus.CANCELLED.value


async def test_sqlite_queue_deeper_than_the_bound_variable_limit_cancels(
    store: MessageStore,
) -> None:
    for n in range(60):
        await store.enqueue_message(
            channel_id="c", raw=f"m{n}", deliveries=[("d", f"p{n}")], now=float(n)
        )
    # Lowered rather than enqueuing past the default limit; setlimit must run on aiosqlite's thread.
    await store._db._execute(store._db._conn.setlimit, sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 50)
    assert await store.cancel_queued(None, "d", now=100.0, audit=no_purge_audit) == 60


async def test_sqlite_top_only_cancels_the_oldest_pending_row(store: MessageStore) -> None:
    older = await store.enqueue_message(channel_id="c", raw="a", deliveries=[("d", "p")], now=1.0)
    newer = await store.enqueue_message(channel_id="c", raw="b", deliveries=[("d", "q")], now=2.0)
    assert await store.cancel_queued(None, "d", top_only=True, now=3.0, audit=no_purge_audit) == 1
    assert await _status(store, older) == OutboxStatus.CANCELLED.value
    assert await _status(store, newer) == OutboxStatus.PENDING.value


async def test_sqlite_empty_cancel_with_no_audit_row_commits_nothing(store: MessageStore) -> None:
    before = store.committed_txns
    assert await store.cancel_queued(None, "d", now=1.0, audit=no_purge_audit) == 0
    assert store.committed_txns == before
    assert not store._db.in_transaction


def _postgres_fake(returned: list[tuple[str, str, int]]) -> tuple[PostgresStore, Any]:
    conn = AsyncMock()
    conn.fetch.return_value = [
        {"id": row_id, "message_id": message_id, "seq": seq} for row_id, message_id, seq in returned
    ]

    @asynccontextmanager
    async def transaction(**_kwargs: Any) -> AsyncIterator[None]:
        yield

    conn.transaction = transaction

    @asynccontextmanager
    async def acquire() -> AsyncIterator[Any]:
        yield conn

    pg = PostgresStore.__new__(PostgresStore)
    pg._timed_acquire = acquire  # type: ignore[method-assign,assignment]
    pg._event = AsyncMock()  # type: ignore[method-assign]
    pg._lock_finalize_batch = AsyncMock()  # type: ignore[method-assign]
    pg._maybe_finalize_message = AsyncMock()  # type: ignore[method-assign]
    pg._append_operator_audit = AsyncMock()  # type: ignore[method-assign]
    return pg, conn


@pytest.mark.parametrize("top_only", [False, True])
async def test_postgres_one_guarded_update_and_counts_only_returned_rows(top_only: bool) -> None:
    pg, conn = _postgres_fake([("q2", "m2", 2), ("q1", "m1", 1)])
    n = await pg.cancel_queued(None, "d", top_only=top_only, now=5.0, audit=no_purge_audit)
    assert n == 2
    conn.fetch.assert_awaited_once()
    conn.execute.assert_not_awaited()
    sql = conn.fetch.await_args.args[0]
    assert sql.startswith("UPDATE queue SET status=$5, updated_at=$6 WHERE ")
    assert "RETURNING id, message_id, seq" in sql
    assert "FOR UPDATE" not in sql and "SKIP LOCKED" not in sql
    if top_only:
        assert ") AND status=$2 RETURNING" in sql and "ORDER BY seq LIMIT 1" in sql
    else:
        assert "status=$2" in sql and "LIMIT" not in sql
    assert conn.fetch.await_args.args[2] == OutboxStatus.PENDING.value
    assert conn.fetch.await_args.args[5] == OutboxStatus.CANCELLED.value
    # Events keep the queue's order, which RETURNING does not promise.
    assert [c.args[1] for c in pg._event.await_args_list] == ["m1", "m2"]  # type: ignore[attr-defined]
    pg._lock_finalize_batch.assert_awaited_once()  # type: ignore[attr-defined]


async def test_postgres_lost_race_audits_zero() -> None:
    pg, _conn = _postgres_fake([])
    assert await pg.cancel_queued(None, "d", top_only=True, now=5.0, audit=no_purge_audit) == 0
    pg._event.assert_not_awaited()  # type: ignore[attr-defined]
    assert pg._append_operator_audit.await_args.args[3] == 0  # type: ignore[attr-defined]


def _sqlserver_fake(returned: list[tuple[str, str, int]]) -> tuple[SqlServerStore, Any]:
    cur = AsyncMock()
    cur.fetchall.return_value = returned
    conn = object()

    @asynccontextmanager
    async def acquire() -> AsyncIterator[Any]:
        yield conn

    @asynccontextmanager
    async def cursor(_conn: Any) -> AsyncIterator[Any]:
        yield cur

    ms = SqlServerStore.__new__(SqlServerStore)
    ms._acquire = acquire  # type: ignore[method-assign]
    ms._cursor = cursor  # type: ignore[method-assign,assignment]
    ms._commit = AsyncMock()  # type: ignore[method-assign]
    ms._event = AsyncMock()  # type: ignore[method-assign]
    ms._lock_finalize_batch = AsyncMock()  # type: ignore[method-assign]
    ms._maybe_finalize = AsyncMock()  # type: ignore[method-assign]
    ms._append_operator_audit = AsyncMock()  # type: ignore[method-assign]
    return ms, cur


@pytest.mark.parametrize("channel_id", [None, "c"])
@pytest.mark.parametrize("top_only", [False, True])
async def test_sqlserver_one_guarded_update_and_counts_only_output_rows(
    top_only: bool, channel_id: str | None
) -> None:
    output = [("q2", "m2", 2), ("q1", "m1", 1)]
    ms, cur = _sqlserver_fake(output)
    if top_only:
        cur.fetchall.side_effect = [[("q1",)], output]
    n = await ms.cancel_queued(channel_id, "d", top_only=top_only, now=5.0, audit=no_purge_audit)
    assert n == 2
    assert cur.execute.await_count == (2 if top_only else 1)
    sql, params = cur.execute.await_args.args
    assert sql.startswith("UPDATE queue SET status=?, updated_at=? OUTPUT inserted.id")
    assert "TOP" not in sql and "UPDLOCK" not in sql and "READPAST" not in sql
    assert params[:2] == (OutboxStatus.CANCELLED.value, 5.0)
    if top_only:
        # The head's id is fixed first, so a claimed head cannot slide to the next row.
        head_sql = cur.execute.await_args_list[0].args[0]
        assert head_sql.startswith("SELECT TOP (1) id FROM queue") and "ORDER BY seq" in head_sql
        assert sql.endswith(" WHERE id=? AND status=?")
        assert params[2:] == ("q1", OutboxStatus.PENDING.value)
    else:
        assert "status=?" in sql.split(" WHERE ", 1)[1]
        assert params[-1] == OutboxStatus.PENDING.value
        assert (channel_id in params) is (channel_id is not None)
    assert [c.args[1] for c in ms._event.await_args_list] == ["m1", "m2"]  # type: ignore[attr-defined]
    ms._lock_finalize_batch.assert_awaited_once()  # type: ignore[attr-defined]


async def test_sqlserver_claimed_head_returns_zero_and_does_not_slide() -> None:
    ms, cur = _sqlserver_fake([])
    cur.fetchall.side_effect = [[("q1",)], []]
    assert await ms.cancel_queued(None, "d", top_only=True, now=5.0, audit=no_purge_audit) == 0
    assert cur.execute.await_count == 2
    assert cur.execute.await_args.args[1][2] == "q1"
    ms._event.assert_not_awaited()  # type: ignore[attr-defined]
    assert ms._append_operator_audit.await_args.args[3] == 0  # type: ignore[attr-defined]
    ms._commit.assert_awaited_once()  # type: ignore[attr-defined]


async def test_sqlserver_empty_lane_top_only_sends_no_update() -> None:
    ms, cur = _sqlserver_fake([])
    assert await ms.cancel_queued(None, "d", top_only=True, now=5.0, audit=no_purge_audit) == 0
    cur.execute.assert_awaited_once()
    assert ms._append_operator_audit.await_args.args[3] == 0  # type: ignore[attr-defined]
