# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``cancel_queued`` writes CANCELLED only over a row that is still PENDING (BACKLOG #5732).

SQLite runs for real. Postgres and SQL Server run against recording fakes, so these tests pin the
statement each one sends and how it counts. Nothing here, and no hosted test, drives a concurrent
claim against a real Postgres or SQL Server, so the race on those two is argued, not measured.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock

import pytest

from messagefoundry.store import MessageStore, OutboxStatus
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import AuditAppend
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
        except sqlite3.OperationalError as exc:
            # Only a lock refusal counts: any other failure would prove nothing about the lock.
            assert exc.sqlite_errorcode == sqlite3.SQLITE_BUSY
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


async def _seed_lane(store: MessageStore, rows: int) -> list[str]:
    return [
        await store.enqueue_message(
            channel_id="c", raw=f"m{n}", deliveries=[("d", f"p{n}")], now=float(n)
        )
        for n in range(rows)
    ]


def _counting_audit(seen: list[int], *, fail_on_call: int | None = None) -> Any:
    def build(cancelled: int) -> AuditAppend:
        seen.append(cancelled)
        if len(seen) == fail_on_call:
            raise RuntimeError("audit refused")
        return AuditAppend("test.cancel_chunk", actor="test", detail=str(cancelled))

    return build


async def _audited_counts(store: MessageStore) -> list[int]:
    cur = await store._db.execute(
        "SELECT detail FROM audit_log WHERE action='test.cancel_chunk' ORDER BY seq"
    )
    return [int(r["detail"]) for r in await cur.fetchall()]


async def test_sqlite_deep_cancel_runs_in_bounded_transactions(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MessageStore, "_CANCEL_CHUNK_ROWS", 5, raising=False)
    mids = await _seed_lane(store, 12)
    before = store.committed_txns
    seen: list[int] = []
    assert await store.cancel_queued(None, "d", now=50.0, audit=_counting_audit(seen)) == 12
    assert store.committed_txns - before == 3
    assert await _audited_counts(store) == [5, 5, 2]
    assert {await _status(store, m) for m in mids} == {OutboxStatus.CANCELLED.value}
    assert not store._db.in_transaction


async def test_sqlite_failure_in_a_later_chunk_keeps_earlier_chunks_cancelled_and_audited(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MessageStore, "_CANCEL_CHUNK_ROWS", 5, raising=False)
    mids = await _seed_lane(store, 12)
    seen: list[int] = []
    with pytest.raises(RuntimeError, match="audit refused"):
        await store.cancel_queued(None, "d", now=50.0, audit=_counting_audit(seen, fail_on_call=2))
    statuses = [await _status(store, m) for m in mids]
    # Oldest first: the first chunk stands, and the failed chunk rolled back whole.
    assert statuses == [OutboxStatus.CANCELLED.value] * 5 + [OutboxStatus.PENDING.value] * 7
    assert await _audited_counts(store) == [5]
    assert not store._db.in_transaction


async def test_sqlite_row_claimed_in_a_later_chunk_stays_claimed(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MessageStore, "_CANCEL_CHUNK_ROWS", 2, raising=False)
    mids = await _seed_lane(store, 4)
    claimed_id = (await store.outbox_for(mids[2]))[0]["id"]
    real = store._db.execute
    updates = 0

    async def execute(sql: str, *args: Any) -> Any:
        nonlocal updates
        if sql.startswith("UPDATE queue SET status=?, updated_at=?"):
            updates += 1
            if updates == 2:
                await real(
                    "UPDATE queue SET status=? WHERE id=?",
                    (OutboxStatus.INFLIGHT.value, claimed_id),
                )
        return await real(sql, *args)

    store._db.execute = execute  # type: ignore[method-assign,assignment]
    assert await store.cancel_queued(None, "d", now=50.0, audit=no_purge_audit) == 3
    assert await _status(store, mids[2]) == OutboxStatus.INFLIGHT.value
    assert await _status(store, mids[3]) == OutboxStatus.CANCELLED.value


async def test_sqlite_row_enqueued_during_a_deep_cancel_is_not_cancelled(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(MessageStore, "_CANCEL_CHUNK_ROWS", 2, raising=False)
    await _seed_lane(store, 4)
    arrivals: list[asyncio.Task[str]] = []

    def audit(cancelled: int) -> AuditAppend:
        if not arrivals:
            # Queues on the writer lock now, so it runs between the first and second chunk.
            arrivals.append(
                asyncio.create_task(
                    store.enqueue_message(
                        channel_id="c", raw="late", deliveries=[("d", "late")], now=60.0
                    )
                )
            )
        return AuditAppend("test.cancel_chunk", actor="test", detail=str(cancelled))

    assert await store.cancel_queued(None, "d", now=50.0, audit=audit) == 4
    assert await _status(store, await arrivals[0]) == OutboxStatus.PENDING.value


def _postgres_fake(returned: list[tuple[str, str, int]]) -> tuple[PostgresStore, Any]:
    conn = AsyncMock()
    # The second chunk matches nothing, which ends the walk.
    conn.fetch.side_effect = [
        [
            {"id": row_id, "message_id": message_id, "seq": seq}
            for row_id, message_id, seq in returned
        ],
        [],
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
    pg._fetchone = AsyncMock(return_value={"high_water": 9})  # type: ignore[method-assign]
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
    assert conn.fetch.await_count == (1 if top_only else 2)
    conn.execute.assert_not_awaited()
    call = conn.fetch.await_args_list[0]
    sql = call.args[0]
    assert sql.startswith("UPDATE queue SET status=$5, updated_at=$6 WHERE ")
    assert "RETURNING id, message_id, seq" in sql
    assert "FOR UPDATE" not in sql and "SKIP LOCKED" not in sql
    assert ") AND status=$2 RETURNING" in sql
    if top_only:
        assert "ORDER BY seq LIMIT 1)" in sql and len(call.args) == 7
    else:
        # An array subquery runs once, so a chunk cannot grow past its LIMIT on a re-check.
        assert "id = ANY(ARRAY(SELECT id FROM queue" in sql
        assert f"seq<=$7 ORDER BY seq LIMIT {PostgresStore._CANCEL_CHUNK_ROWS}" in sql
        assert call.args[7] == 9
    assert call.args[2] == OutboxStatus.PENDING.value
    assert call.args[5] == OutboxStatus.CANCELLED.value
    # Events keep the queue's order, which RETURNING does not promise.
    assert [c.args[1] for c in pg._event.await_args_list] == ["m1", "m2"]  # type: ignore[attr-defined]
    pg._lock_finalize_batch.assert_awaited_once()  # type: ignore[attr-defined]


async def test_postgres_lost_race_audits_zero() -> None:
    pg, _conn = _postgres_fake([])
    assert await pg.cancel_queued(None, "d", top_only=True, now=5.0, audit=no_purge_audit) == 0
    pg._event.assert_not_awaited()  # type: ignore[attr-defined]
    assert pg._append_operator_audit.await_args.args[3] == 0  # type: ignore[attr-defined]


async def test_postgres_final_empty_chunk_writes_no_second_audit_row() -> None:
    pg, _conn = _postgres_fake([("q1", "m1", 1)])
    assert await pg.cancel_queued(None, "d", now=5.0, audit=no_purge_audit) == 1
    pg._append_operator_audit.assert_awaited_once()  # type: ignore[attr-defined]
    assert pg._append_operator_audit.await_args.args[3] == 1  # type: ignore[attr-defined]


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
    ms._fetchone = AsyncMock(return_value={"high_water": 9})  # type: ignore[method-assign]
    ms._commit = AsyncMock()  # type: ignore[method-assign]
    ms._commit_read = AsyncMock()  # type: ignore[method-assign]
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
    cur.fetchall.side_effect = [[("q1",)], output] if top_only else [output, []]
    n = await ms.cancel_queued(channel_id, "d", top_only=top_only, now=5.0, audit=no_purge_audit)
    assert n == 2
    assert cur.execute.await_count == 2
    sql, params = cur.execute.await_args_list[1 if top_only else 0].args
    assert sql.startswith("UPDATE queue SET status=?, updated_at=? OUTPUT inserted.id")
    assert "UPDLOCK" not in sql and "READPAST" not in sql
    assert params[:2] == (OutboxStatus.CANCELLED.value, 5.0)
    if top_only:
        # The head's id is fixed first, so a claimed head cannot slide to the next row.
        head_sql = cur.execute.await_args_list[0].args[0]
        assert head_sql.startswith("SELECT TOP (1) id FROM queue") and "ORDER BY seq" in head_sql
        assert "TOP" not in sql and sql.endswith(" WHERE id=? AND status=?")
        assert params[2:] == ("q1", OutboxStatus.PENDING.value)
    else:
        assert f"id IN (SELECT TOP ({SqlServerStore._CANCEL_CHUNK_ROWS}) id FROM queue" in sql
        assert sql.endswith(" AND seq<=? ORDER BY seq) AND status=?")
        assert params[-2:] == (9, OutboxStatus.PENDING.value)
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


async def test_sqlserver_final_empty_chunk_writes_no_audit_and_counts_no_commit() -> None:
    output = [("q1", "m1", 1)]
    ms, cur = _sqlserver_fake(output)
    cur.fetchall.side_effect = [output, []]
    assert await ms.cancel_queued(None, "d", now=5.0, audit=no_purge_audit) == 1
    ms._append_operator_audit.assert_awaited_once()  # type: ignore[attr-defined]
    assert ms._append_operator_audit.await_args.args[3] == 1  # type: ignore[attr-defined]
    ms._commit.assert_awaited_once()  # type: ignore[attr-defined]
    ms._commit_read.assert_awaited_once()  # type: ignore[attr-defined]


async def test_sqlserver_empty_lane_sends_no_update_and_audits_zero() -> None:
    ms, cur = _sqlserver_fake([])
    ms._fetchone.return_value = {"high_water": None}  # type: ignore[attr-defined]
    assert await ms.cancel_queued(None, "d", now=5.0, audit=no_purge_audit) == 0
    cur.execute.assert_not_awaited()
    assert ms._append_operator_audit.await_args.args[3] == 0  # type: ignore[attr-defined]


async def test_sqlserver_empty_lane_top_only_sends_no_update() -> None:
    ms, cur = _sqlserver_fake([])
    assert await ms.cancel_queued(None, "d", top_only=True, now=5.0, audit=no_purge_audit) == 0
    cur.execute.assert_awaited_once()
    assert ms._append_operator_audit.await_args.args[3] == 0  # type: ignore[attr-defined]
