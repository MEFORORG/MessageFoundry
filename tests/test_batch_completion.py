# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Batch outbound completion primitives — BACKLOG #134 / ADR 0082 (store layer).

``mark_batch_done`` / ``mark_batch_failed`` / ``dead_letter_batch`` complete N outbound rows (framed
into one BHS…BTS envelope by the delivery worker) in a **single transaction**, preserving the
count-and-log + at-least-once + strict-FIFO invariants: all N flip together, the finalizer runs once
per distinct message, and a batch failure is atomic (all re-pend to the same deadline, or all
dead-letter). Verified on **both** SQLite and (gated) SQL Server.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, AsyncIterator

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStatus, MessageStore


async def _open_sqlserver() -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    store = await SqlServerStore.open(load_settings(environ=os.environ).store)
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in ("message_events", "state", "queue", "response", "outbox", "messages"):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    return store


@pytest.fixture(params=["sqlite", "sqlserver"])
async def store(request: Any, tmp_path: Path) -> AsyncIterator[Any]:
    if request.param == "sqlserver":
        if not os.getenv("MEFOR_TEST_SQLSERVER"):
            pytest.skip("set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) for the SQL Server leg")
        s = await _open_sqlserver()
    else:
        s = await MessageStore.open(tmp_path / "batch.db")
    yield s
    await s.close()


async def _n_outbound(store: Any, n: int, dest: str = "OB1") -> tuple[list[str], list[str]]:
    """Enqueue N single-delivery messages to one outbound lane; claim all N in FIFO order.
    Returns (message_ids, outbox_ids) — outbox_ids in claimed seq order."""
    mids = []
    for i in range(n):
        mids.append(
            await store.enqueue_message(
                channel_id="c1", raw=f"MSH|m{i}", deliveries=[(dest, f"p{i}")], now=100.0 + i
            )
        )
    ids = []
    while True:
        item = await store.claim_next_fifo(dest, now=200.0)
        if item is None:
            break
        ids.append(item.id)
    return mids, ids


# --- mark_batch_done: N rows delivered together, each message finalizes PROCESSED ----------------


async def test_mark_batch_done_finalizes_every_message(store: Any) -> None:
    mids, ids = await _n_outbound(store, 3)
    assert len(ids) == 3
    await store.mark_batch_done(ids, now=300.0)
    for mid in mids:
        assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    assert await store.count_dead() == 0
    # No pending rows remain on the lane.
    depth, _ = await store.pending_depth("OB1")
    assert depth == 0


async def test_mark_batch_done_skips_a_vanished_member(store: Any) -> None:
    mids, ids = await _n_outbound(store, 2)
    # A bogus id (a member cancelled/purged mid-flight) must be skipped, not fail the batch.
    await store.mark_batch_done([ids[0], "nonexistent-id", ids[1]], now=300.0)
    for mid in mids:
        assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


# --- mark_batch_failed: atomic all-N disposition ------------------------------------------------


async def test_mark_batch_failed_transient_repends_all_to_one_deadline(store: Any) -> None:
    _mids, ids = await _n_outbound(store, 3)
    next_at = await store.mark_batch_failed(ids, "transient boom", RetryPolicy(), now=300.0)
    assert next_at is not None and next_at > 300.0  # rescheduled, not dead-lettered
    # All 3 are PENDING again on the lane, re-claimable as the same prefix (strict FIFO).
    depth, _ = await store.pending_depth("OB1")
    assert depth == 3
    assert await store.count_dead() == 0


async def test_mark_batch_failed_exhausted_deadletters_all(store: Any) -> None:
    # max_attempts=1 and the claim already bumped attempts to 1 → the whole batch dead-letters.
    _mids, ids = await _n_outbound(store, 3)
    result = await store.mark_batch_failed(
        ids, "permanent-ish", RetryPolicy(max_attempts=1), now=300.0
    )
    assert result is None  # dead-lettered → no reschedule float
    assert await store.count_dead() == 3
    depth, _ = await store.pending_depth("OB1")
    assert depth == 0


# --- dead_letter_batch: permanent envelope reject → all N DEAD (ADR 0082 decision #1) -----------


async def test_dead_letter_batch_deadletters_all_atomically(store: Any) -> None:
    mids, ids = await _n_outbound(store, 3)
    await store.dead_letter_batch(ids, "AR: partner rejected the batch", now=300.0)
    assert await store.count_dead() == 3
    # Each message finalizes to a terminal ERROR disposition (not PROCESSED).
    for mid in mids:
        assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


async def test_dead_letter_batch_skips_vanished(store: Any) -> None:
    _mids, ids = await _n_outbound(store, 2)
    await store.dead_letter_batch([ids[0], "gone", ids[1]], "AR", now=300.0)
    assert await store.count_dead() == 2


# --- H-8 lock ordering: every multi-message finalizer takes its per-message locks in SORTED order --
#
# The ADR 0082 batch primitives each finalize N distinct message_ids in ONE transaction, and the
# finalizer takes a per-message lock (a SQL Server applock / a Postgres advisory lock). They built
# their finalize set as a dict keyed in *caller* (outbox_ids) order and then iterated it, so two
# concurrent batches holding overlapping id sets could take the same two locks in OPPOSITE orders and
# deadlock (SQL Server 1205). A fan-out message has one outbound row per destination and each
# destination lane batches independently, so overlapping sets are reachable in normal operation.
#
# The store's documented H-8 rule is that a finalizer spanning more than one message acquires in
# CANONICAL (sorted) id order — see _lock_finalize_batch. These pin that the batch primitives obey it.
# They fail on the pre-fix code (which yielded caller order) for any batch whose ids arrive unsorted.


def _descending(mids: list[str], ids: list[str]) -> list[str]:
    """Outbox ids ordered so their message_ids DESCEND — the worst case for the pre-fix code, and
    deterministic: for n>=2 distinct ids, descending can never coincide with ascending."""
    return [i for _m, i in sorted(zip(mids, ids), reverse=True)]


async def _finalize_order(store: Any, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Spy the per-message finalizer, returning the message_ids in the order it was called."""
    seen: list[str] = []
    name = "_maybe_finalize" if hasattr(store, "_maybe_finalize") else "_maybe_finalize_message"
    original = getattr(store, name)

    async def spy(*args: Any, **kwargs: Any) -> Any:
        # message_id is the first str positional (SQL Server passes a cursor/conn ahead of it).
        seen.append(next(a for a in args if isinstance(a, str)))
        return await original(*args, **kwargs)

    monkeypatch.setattr(store, name, spy)
    return seen


async def test_mark_batch_done_finalizes_in_sorted_id_order(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    mids, ids = await _n_outbound(store, 4)
    seen = await _finalize_order(store, monkeypatch)
    await store.mark_batch_done(_descending(mids, ids), now=300.0)
    assert seen == sorted(mids), "H-8: multi-message finalize must acquire in canonical id order"


async def test_mark_batch_failed_finalizes_in_sorted_id_order(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    mids, ids = await _n_outbound(store, 4)
    seen = await _finalize_order(store, monkeypatch)
    # max_attempts=0 => the batch dead-letters, which is the path that finalizes every member.
    await store.mark_batch_failed(
        _descending(mids, ids), "boom", RetryPolicy(max_attempts=0), now=300.0
    )
    assert seen == sorted(mids), "H-8: multi-message finalize must acquire in canonical id order"


async def test_dead_letter_batch_finalizes_in_sorted_id_order(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    mids, ids = await _n_outbound(store, 4)
    seen = await _finalize_order(store, monkeypatch)
    await store.dead_letter_batch(_descending(mids, ids), "boom", now=300.0)
    assert seen == sorted(mids), "H-8: multi-message finalize must acquire in canonical id order"
