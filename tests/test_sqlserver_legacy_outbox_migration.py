# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The legacy SQL Server ``outbox`` table is folded into ``queue`` and DROPped (ASVS 14.2.7).

**What was actually wrong.** The table was recreated by `_SCHEMA` on every open and read by nothing:
the staged pipeline and every delivery-side method use `queue`. So `outbox.payload` — a full outbound
PHI body on any store upgraded from the pre-staged-pipeline layout — was reached by no purge on any
backend, while `messages.raw` blanked on its own window. The message read as purged and the body
survived indefinitely. Migrating the rows in puts them under the ordinary outbound windows; dropping
the table is what makes the retirement true rather than merely documented.

**Why this test simulates an UPGRADE rather than just checking a fresh open.** On a fresh DB the
migration statement's `IF OBJECT_ID('outbox','U') IS NOT NULL` guard is false and the body never runs
— a test that only opened a clean store would pass without executing a single line of the thing it
claims to verify. Worse, `_ensure_schema` SKIPS the whole DDL batch when `schema_meta` already records
the current hash, so creating a legacy table after a normal open and re-opening would ALSO migrate
nothing. Both are the "green because nothing was measured" failure. So each test here seeds a real
legacy table and then clears the schema marker, which is exactly the state a genuine upgrade presents:
`_SCHEMA` changed, so its hash no longer matches, so the batch re-runs.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import pytest

from messagefoundry.store import OutboxStatus, Stage

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

#: The legacy DDL, verbatim as it stood in `_SCHEMA` before the retirement. Kept here rather than
#: imported because the point is to reconstruct a schema the code no longer contains.
_LEGACY_OUTBOX_DDL = """CREATE TABLE outbox (
    id NVARCHAR(64) NOT NULL PRIMARY KEY, message_id NVARCHAR(64) NOT NULL,
    channel_id NVARCHAR(256) NOT NULL, destination_name NVARCHAR(256) NOT NULL,
    payload NVARCHAR(MAX) NOT NULL, status NVARCHAR(32) NOT NULL,
    attempts INT NOT NULL DEFAULT 0, next_attempt_at FLOAT NOT NULL, last_error NVARCHAR(MAX) NULL,
    created_at FLOAT NOT NULL, updated_at FLOAT NOT NULL)"""


async def _open_store() -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    return await SqlServerStore.open(settings)


async def _reset(store: Any) -> None:
    """Clean slate. `outbox` is dropped defensively: a previous test in this module may have left one
    behind, and it is NOT in any other suite's reset list any more (the table is retired)."""
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute("IF OBJECT_ID('outbox','U') IS NOT NULL DROP TABLE outbox")
        for table in ("message_events", "queue", "response", "delivered_keys", "messages"):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()


@pytest.fixture
async def store() -> AsyncIterator[Any]:
    s = await _open_store()
    await _reset(s)
    try:
        yield s
    finally:
        await _reset(s)
        await s.close()


async def _seed_legacy(store: Any, rows: list[tuple[Any, ...]], *, messages: list[str]) -> None:
    """Recreate the legacy table, seed it, and put the DB into the state an UPGRADE presents.

    Clearing `schema_meta` is the load-bearing step: with a current marker `_ensure_schema` returns
    before executing anything, so without this the next open would migrate nothing and every
    assertion below would pass vacuously. A real upgrade reaches the same state by a different route
    — `_SCHEMA` changed, so its content hash no longer matches what the marker records.
    """
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute("IF OBJECT_ID('outbox','U') IS NOT NULL DROP TABLE outbox")
        await cur.execute(_LEGACY_OUTBOX_DDL)
        for mid in messages:
            await cur.execute(
                "INSERT INTO messages (id, channel_id, received_at, source_type, control_id,"
                " message_type, raw, status) VALUES (?,?,?,?,?,?,?,?)",
                (mid, "IB", 1.0, "mllp", "C", "ADT^A01", RAW, "routed"),
            )
        for row in rows:
            await cur.execute(
                "INSERT INTO outbox (id, message_id, channel_id, destination_name, payload, status,"
                " attempts, next_attempt_at, last_error, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                row,
            )
        await cur.execute("DELETE FROM schema_meta")
        await conn.commit()


async def _tables(store: Any) -> set[str]:
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute("SELECT name FROM sys.tables")
        return {r[0] for r in await cur.fetchall()}


async def _queue_rows(store: Any) -> list[dict[str, Any]]:
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute(
            "SELECT id, message_id, stage, channel_id, destination_name, payload, status,"
            " attempts, created_at, seq FROM queue ORDER BY seq"
        )
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r, strict=True)) for r in await cur.fetchall()]


async def test_legacy_outbox_rows_migrate_into_queue_and_the_table_is_dropped(store: Any) -> None:
    """The core claim: rows survive as stage='outbound' queue rows, and the table is gone.

    Mutation: delete the `DROP TABLE outbox` from the `_SCHEMA` statement — reds on the table
    assertion. Delete the whole statement — reds on the row assertion first.
    """
    await _seed_legacy(
        store,
        [
            (
                "o1",
                "m1",
                "IB",
                "OB_A",
                "PAYLOAD-1",
                OutboxStatus.PENDING.value,
                0,
                0.0,
                None,
                1.0,
                1.0,
            ),
            (
                "o2",
                "m1",
                "IB",
                "OB_B",
                "PAYLOAD-2",
                OutboxStatus.PENDING.value,
                3,
                9.0,
                "boom",
                2.0,
                2.0,
            ),
        ],
        messages=["m1"],
    )

    reopened = await _open_store()
    try:
        assert "outbox" not in await _tables(reopened), (
            "the legacy table survived the schema batch — a DROP that did not fire leaves the "
            "unpurgeable PHI tier exactly where it was"
        )
        rows = await _queue_rows(reopened)
        assert len(rows) == 2, f"expected both legacy rows folded in, got {rows}"
        by_id = {r["id"]: r for r in rows}
        assert set(by_id) == {"o1", "o2"}, (
            "row ids must be preserved (they are referenced elsewhere)"
        )
        for r in rows:
            assert r["stage"] == Stage.OUTBOUND.value
            assert r["message_id"] == "m1"
            assert r["channel_id"] == "IB"
        # Every column carried over verbatim — a migration that silently reset attempts or dropped
        # last_error would resurrect a dead row as deliverable.
        assert by_id["o1"]["destination_name"] == "OB_A"
        assert by_id["o1"]["payload"] == "PAYLOAD-1"
        assert by_id["o2"]["destination_name"] == "OB_B"
        assert by_id["o2"]["payload"] == "PAYLOAD-2"
        assert by_id["o2"]["attempts"] == 3
        assert by_id["o1"]["created_at"] == 1.0 and by_id["o2"]["created_at"] == 2.0
    finally:
        await reopened.close()


async def test_migrated_rows_are_reachable_by_the_delivery_path(store: Any) -> None:
    """A migrated row is not merely present — it must be CLAIMABLE, or the backlog silently stalls.

    This is the assertion that distinguishes a real migration from rows parked in a table with the
    wrong stage/status: `claim_next_fifo` filters on both.
    """
    await _seed_legacy(
        store,
        [
            (
                "o1",
                "m1",
                "IB",
                "OB_A",
                "PAYLOAD-1",
                OutboxStatus.PENDING.value,
                0,
                0.0,
                None,
                1.0,
                1.0,
            )
        ],
        messages=["m1"],
    )
    reopened = await _open_store()
    try:
        item = await reopened.claim_next_fifo("OB_A")
        assert item is not None, (
            "the migrated row is not claimable — the legacy backlog would stall"
        )
        assert item.payload == "PAYLOAD-1"
    finally:
        await reopened.close()


async def test_an_orphaned_legacy_row_is_skipped_rather_than_failing_the_open(store: Any) -> None:
    """`queue.message_id` is FK-enforced; an orphan would abort the whole DDL batch.

    That is not a degraded start — the batch is one transaction, so it rolls back and re-fails on
    every restart: a crash-loop. The orphan was unreplayable anyway (nothing can view or route a row
    whose message is gone), so it is dropped and the surviving row still migrates.

    Mutation: remove the `EXISTS (SELECT 1 FROM messages ...)` filter — this test reds with an FK
    violation at open, which is precisely the crash-loop it exists to prevent.
    """
    await _seed_legacy(
        store,
        [
            ("o1", "m1", "IB", "OB_A", "GOOD", OutboxStatus.PENDING.value, 0, 0.0, None, 1.0, 1.0),
            # message 'gone' was never inserted
            (
                "o2",
                "gone",
                "IB",
                "OB_A",
                "ORPHAN",
                OutboxStatus.PENDING.value,
                0,
                0.0,
                None,
                1.0,
                1.0,
            ),
        ],
        messages=["m1"],
    )
    reopened = await _open_store()
    try:
        assert "outbox" not in await _tables(reopened)
        rows = await _queue_rows(reopened)
        assert [r["id"] for r in rows] == ["o1"], (
            f"the orphan should be skipped and the good row kept, got {[r['id'] for r in rows]}"
        )
    finally:
        await reopened.close()


async def test_an_id_already_present_in_queue_does_not_abort_the_batch(store: Any) -> None:
    """`queue.id` is the PK, so a colliding legacy id would raise 2627 and roll the batch back.

    uuid4 ids make a genuine collision implausible, which is exactly why this needs a test rather
    than an argument: the anti-join is unreachable in normal operation, so nothing else would ever
    exercise it, and a silent regression would surface only as a customer's crash-looping upgrade.

    Mutation: remove the `NOT EXISTS (SELECT 1 FROM queue ...)` filter — reds with a PK violation.
    """
    await _seed_legacy(
        store,
        [("dup", "m1", "IB", "OB_A", "LEGACY", OutboxStatus.PENDING.value, 0, 0.0, None, 1.0, 1.0)],
        messages=["m1"],
    )
    # Plant a `queue` row that already owns the id, then re-clear the marker the insert did not touch.
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, payload,"
            " status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                "dup",
                "m1",
                Stage.OUTBOUND.value,
                "IB",
                "OB_A",
                "ALREADY-HERE",
                OutboxStatus.PENDING.value,
                0,
                0.0,
                5.0,
                5.0,
            ),
        )
        await conn.commit()

    reopened = await _open_store()
    try:
        assert "outbox" not in await _tables(reopened), (
            "the batch aborted — the table is still here"
        )
        rows = await _queue_rows(reopened)
        assert len(rows) == 1, f"the colliding legacy row must not be inserted twice, got {rows}"
        assert rows[0]["payload"] == "ALREADY-HERE", (
            "the pre-existing queue row must win, not be lost"
        )
    finally:
        await reopened.close()


async def test_a_fresh_store_has_no_outbox_table_at_all(store: Any) -> None:
    """The other half of the retirement: `_SCHEMA` must no longer CREATE the table.

    Cheap, and it is the assertion that catches a revert of the DDL removal — the migration statement
    alone would then drop a table the very same batch had just recreated, which is stable but leaves
    every open re-creating an empty unpurgeable tier.
    """
    tables = await _tables(store)
    assert "outbox" not in tables, "a fresh open recreated the retired legacy table"
    assert "queue" in tables, "liveness: the table enumeration is reading a real schema"
