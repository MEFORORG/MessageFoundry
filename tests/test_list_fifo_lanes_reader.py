# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SQLite lane discovery reads off the writer, in one statement (BACKLOG #5673, the SQLite item).

The row's SQL Server claim is not built or pinned here.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from messagefoundry.store.store import MessageStore, OutboxStatus, Stage

_RAW = "MSH|^~\\&|A|B|C|D|20260101000000||ADT^A01|SYNTH1|P|2.5\r"


async def test_discovery_does_not_wait_on_the_write_lock(tmp_path: Path) -> None:
    """Red before the fix: the read parks behind the held writer lock and hits the bound."""
    store = await MessageStore.open(tmp_path / "lanes.db")
    try:
        await store.enqueue_ingress(channel_id="IB_A", raw=_RAW, now=1.0)
        async with store._lock:
            lanes = await asyncio.wait_for(store.list_fifo_lanes(Stage.INGRESS.value), 5)
        assert [lane for lane, _due in lanes] == ["IB_A"]
    finally:
        await store.close()


async def test_discovery_is_one_statement_however_many_lanes(tmp_path: Path) -> None:
    """Red before the fix: 1 + one SELECT per lane."""
    store = await MessageStore.open(tmp_path / "count.db")
    try:
        for i in range(5):
            await store.enqueue_ingress(channel_id=f"IB_{i}", raw=_RAW, now=1.0)
        seen: list[str] = []
        for conn in store._read_conns:
            await conn.set_trace_callback(seen.append)
        await store.list_fifo_lanes(Stage.INGRESS.value)
        assert len([s for s in seen if s.lstrip().upper().startswith("SELECT")]) == 1
    finally:
        await store.close()


async def _set_due(store: MessageStore, mid: str, due: float) -> None:
    await store._db.execute("UPDATE queue SET next_attempt_at=? WHERE message_id=?", (due, mid))
    await store._db.commit()


async def test_the_due_time_is_the_rowid_heads_not_the_earliest(tmp_path: Path) -> None:
    """The head is the lowest-rowid pending row, even with a tail row due sooner."""
    store = await MessageStore.open(tmp_path / "head.db")
    try:
        head = await store.enqueue_ingress(channel_id="IB_A", raw=_RAW, now=1.0)
        tail = await store.enqueue_ingress(channel_id="IB_A", raw=_RAW, now=2.0)
        await _set_due(store, head, 500.0)
        await _set_due(store, tail, 10.0)
        assert await store.list_fifo_lanes(Stage.INGRESS.value) == [("IB_A", 500.0)]
    finally:
        await store.close()


async def test_a_non_pending_head_is_skipped(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "skip.db")
    try:
        first = await store.enqueue_ingress(channel_id="IB_A", raw=_RAW, now=1.0)
        second = await store.enqueue_ingress(channel_id="IB_A", raw=_RAW, now=2.0)
        await _set_due(store, second, 77.0)
        await store._db.execute(
            "UPDATE queue SET status=? WHERE message_id=?", (OutboxStatus.INFLIGHT.value, first)
        )
        await store._db.commit()
        assert await store.list_fifo_lanes(Stage.INGRESS.value) == [("IB_A", 77.0)]
    finally:
        await store.close()


async def test_order_limit_and_cursor_are_kept(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "page.db")
    try:
        for name in ("IB_C", "IB_A", "IB_B", "ib_a"):
            await store.enqueue_ingress(channel_id=name, raw=_RAW, now=1.0)
        stage = Stage.INGRESS.value
        names = [lane for lane, _due in await store.list_fifo_lanes(stage)]
        assert names == ["IB_A", "IB_B", "IB_C", "ib_a"]  # BINARY order
        assert [n for n, _ in await store.list_fifo_lanes(stage, limit=2)] == ["IB_A", "IB_B"]
        assert [n for n, _ in await store.list_fifo_lanes(stage, after="IB_B", limit=1)] == ["IB_C"]
    finally:
        await store.close()


async def test_a_null_lane_takes_a_limit_slot_and_is_dropped(tmp_path: Path) -> None:
    """The per-lane lookup this replaced behaved this way: ``= NULL`` matched no head."""
    store = await MessageStore.open(tmp_path / "null.db")
    try:
        mid = await store.enqueue_ingress(channel_id="IB_A", raw=_RAW, now=1.0)
        await store._db.execute(
            "UPDATE queue SET stage=?, destination_name=NULL WHERE message_id=?",
            (Stage.OUTBOUND.value, mid),
        )
        await store._db.commit()
        assert await store.list_fifo_lanes(Stage.OUTBOUND.value, limit=1) == []
    finally:
        await store.close()


async def test_memory_store_still_discovers(tmp_path: Path) -> None:
    store = await MessageStore.open(":memory:")
    try:
        await store.enqueue_ingress(channel_id="IB_A", raw=_RAW, now=1.0)
        assert [n for n, _ in await store.list_fifo_lanes(Stage.INGRESS.value)] == ["IB_A"]
    finally:
        await store.close()
