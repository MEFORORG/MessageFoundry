# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0058 — batch-claim the contiguous DUE head-prefix on the INGRESS/ROUTED FIFO claim path.

The invariant matrix T1–T10. ``claim_next_fifo_batch`` is **store-level reliability-core** (per-lane
FIFO is a HARD conformance gate, #285), so the store-level cases below are **backend-parametrized**: the
SQLite case runs everywhere; the **SQL Server** and **Postgres** cases run only when their respective
``MEFOR_TEST_*`` env (+ connection env) is set — the CI service-container legs set them. The
worker-level cases (N=1 byte-identity, in-batch head-of-line) drive the RegistryRunner over SQLite.

SQL Server gets a **real** batch claim (the cutoff-CTE), not a delegation — it runs the full
ingress→routed→outbound pipeline (``supports_ingest_stage = True``), so T1–T8 run there too. T6
(locked-head BLOCKS not skips) is the PR-blocking #285 gate on the ``sql-server`` leg.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, AsyncIterator

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStore, OutboxStatus, Stage
from messagefoundry.store.store import MessageStatus

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

# --- backend parametrization -------------------------------------------------
# Each backend is a (id, factory) where factory() -> async store handle (truncated). The SQLite factory
# always runs; the server-DB factories skip (pytest.skip) unless their MEFOR_TEST_* env is set.

_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))


async def _open_sqlite(tmp_path: Path) -> MessageStore:
    return await MessageStore.open(tmp_path / "batch.db")


async def _open_sqlserver(tmp_path: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    async with s._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in (
            "message_events",
            "queue",
            "response",
            "delivered_keys",
            "outbox",
            "messages",
        ):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    return s


async def _open_postgres(tmp_path: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    async with s._pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE message_events, queue, response, delivered_keys, messages"
            " RESTART IDENTITY CASCADE"
        )
    await s._load_state_cache()
    await s._load_reference_cache()
    return s


@pytest.fixture(params=["sqlite", "sqlserver", "postgres"])
async def store(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[Any]:
    backend = request.param
    if backend == "sqlserver" and not _SQLSERVER_ON:
        pytest.skip("set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the SQL Server case")
    if backend == "postgres" and not _POSTGRES_ON:
        pytest.skip("set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres case")
    opener = {"sqlite": _open_sqlite, "sqlserver": _open_sqlserver, "postgres": _open_postgres}[
        backend
    ]
    s = await opener(tmp_path)
    s._test_backend = backend  # tag so a test can branch on backend-specific locking
    try:
        yield s
    finally:
        await s.close()


# --- helpers ----------------------------------------------------------------


async def _seed_ingress(store: Any, channel: str, times: list[float]) -> list[str]:
    """Enqueue one ingress message per timestamp; return message ids in order."""
    ids = []
    for t in times:
        mid = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=t)
        ids.append(mid)
    return ids


async def _seed_routed(store: Any, channel: str, times: list[float]) -> list[str]:
    """Land one INFLIGHT-then-PENDING routed row per timestamp (drive ingress→routed), in order. Returns
    the message ids. Each routed row carries handler 'H' and is PENDING at its created_at."""
    mids = []
    for t in times:
        mid = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=t)
        ing = await store.claim_next_fifo(channel, now=t + 0.001, stage=Stage.INGRESS.value)
        assert ing is not None
        await store.route_handoff(
            ingress_id=ing.id,
            message_id=mid,
            channel_id=channel,
            handlers=[("H", RAW)],
            disposition=MessageStatus.ROUTED,
            now=t + 0.002,
        )
        mids.append(mid)
    return mids


async def _make_not_due(
    store: Any, channel: str, stage: str, message_id: str, until: float
) -> None:
    """Push one lane row's next_attempt_at into the future (simulate a backing-off head) WITHOUT
    consuming an attempt — done directly so the test controls the not-due boundary precisely."""
    backend = store._test_backend
    if backend == "sqlite":
        await store._db.execute(
            "UPDATE queue SET next_attempt_at=? WHERE message_id=? AND stage=?",
            (until, message_id, stage),
        )
        await store._db.commit()
    elif backend == "postgres":
        async with store._pool.acquire() as conn:
            await conn.execute(
                "UPDATE queue SET next_attempt_at=$1 WHERE message_id=$2 AND stage=$3",
                until,
                message_id,
                stage,
            )
    else:  # sqlserver
        async with store._pool.acquire() as conn:
            cur = await conn.cursor()
            await cur.execute(
                "UPDATE queue SET next_attempt_at=? WHERE message_id=? AND stage=?",
                (until, message_id, stage),
            )
            await conn.commit()


# --- T1: FIFO contiguous-due, not-due INTERIOR head BLOCKS -------------------


@pytest.mark.parametrize("stage", [Stage.INGRESS.value, Stage.ROUTED.value])
async def test_t1_contiguous_due_interior_not_due_truncates(store: Any, stage: str) -> None:
    """[due, not-due, due] → the batch claims exactly the FIRST due row (the prefix), never {row1,row3}:
    a not-due INTERIOR head truncates the prefix there (strict per-lane FIFO, #285)."""
    channel = "IB_T1"
    seed = _seed_ingress if stage == Stage.INGRESS.value else _seed_routed
    mids = await seed(store, channel, [100.0, 101.0, 102.0])
    # Make the MIDDLE row not due (a backing-off interior head).
    await _make_not_due(store, channel, stage, mids[1], until=10_000.0)
    items = await store.claim_next_fifo_batch(channel, now=200.0, stage=stage, limit=8)
    # Only the head (row1) is claimed: the not-due row2 truncates the prefix; row3 is NOT reached.
    assert [it.message_id for it in items] == [mids[0]]


# --- T2: ingress backing-off head → empty batch ------------------------------


async def test_t2_backing_off_head_yields_empty_batch(store: Any) -> None:
    """An ingress head re-pended +5s by mark_failed(RetryPolicy()) → a subsequent batch returns []
    (lane blocks), never the newer due tail."""
    channel = "IB_T2"
    mids = await _seed_ingress(store, channel, [100.0, 101.0])
    # Claim the head, then mark_failed with the default RetryPolicy (re-pends +5s).
    head = await store.claim_next_fifo(channel, now=110.0, stage=Stage.INGRESS.value)
    assert head is not None and head.message_id == mids[0]
    await store.mark_failed(head.id, "inbound not in registry", RetryPolicy(), now=110.0)
    # At now=112 the head (next_attempt_at≈115) is NOT due → the whole batch blocks (empty).
    assert (
        await store.claim_next_fifo_batch(channel, now=112.0, stage=Stage.INGRESS.value, limit=8)
        == []
    )
    # Once the head is due again it leads the batch (still ahead of the tail).
    items = await store.claim_next_fifo_batch(
        channel, now=120.0, stage=Stage.INGRESS.value, limit=8
    )
    assert items and items[0].message_id == mids[0]


# --- T3: crash-mid-batch K of N ----------------------------------------------


async def test_t3_crash_mid_batch_recovers_tail_in_order(store: Any) -> None:
    """Claim N=8 INFLIGHT, hand off the first 3, then simulate a crash (no handoff for 4..8). Run
    reset_stale_inflight; assert rows 1..3 are gone (consumed), 4..8 re-pended in order, and a pure
    re-run hands off each exactly once (no loss, no dup)."""
    channel = "IB_T3"
    times = [100.0 + i for i in range(8)]
    mids = await _seed_ingress(store, channel, times)
    items = await store.claim_next_fifo_batch(
        channel, now=200.0, stage=Stage.INGRESS.value, limit=8
    )
    assert [it.message_id for it in items] == mids  # all 8, in order
    # Hand off the first 3 (committed); 4..8 "crash" before their handoff (stay INFLIGHT).
    for it in items[:3]:
        await store.route_handoff(
            ingress_id=it.id,
            message_id=it.message_id,
            channel_id=channel,
            handlers=[("H", RAW)],
            disposition=MessageStatus.ROUTED,
            now=201.0,
        )
    recovered = await store.reset_stale_inflight(now=300.0, stage=Stage.INGRESS.value)
    assert recovered == 5  # rows 4..8 re-pended; 1..3 were DELETEd by their handoffs
    # Re-claim: the recovered tail comes back in order, and a pure re-run hands each off exactly once.
    again = await store.claim_next_fifo_batch(
        channel, now=310.0, stage=Stage.INGRESS.value, limit=8
    )
    assert [it.message_id for it in again] == mids[3:]
    for it in again:
        ok = await store.route_handoff(
            ingress_id=it.id,
            message_id=it.message_id,
            channel_id=channel,
            handlers=[("H", RAW)],
            disposition=MessageStatus.ROUTED,
            now=311.0,
        )
        assert ok is True  # exactly-once: each recovered row hands off once
    # Every message routed exactly once: 8 distinct ROUTED messages, each with one routed row.
    for mid in mids:
        assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value


# --- T4: poison-bound at position K>1 ----------------------------------------


async def test_t4_attempts_bumped_in_claim_commit_for_all(store: Any) -> None:
    """attempts+1 is bumped on EVERY claimed row inside the one claim commit (durable-before-work, ADR
    0055 AC-2) — so the G6 ingress-attempts ceiling sees the bump even for a row at batch index >= 2. A
    re-claim of the same rows shows attempts strictly increasing (no infinite re-claim without a bump)."""
    channel = "IB_T4"
    mids = await _seed_ingress(store, channel, [100.0, 101.0, 102.0])
    first = await store.claim_next_fifo_batch(
        channel, now=200.0, stage=Stage.INGRESS.value, limit=8
    )
    assert [it.attempts for it in first] == [1, 1, 1]  # post-increment, all three
    # Re-pend them (simulate a crash before any handoff) and re-claim: attempts bumps again, per row.
    await store.reset_stale_inflight(now=210.0, stage=Stage.INGRESS.value)
    second = await store.claim_next_fifo_batch(
        channel, now=220.0, stage=Stage.INGRESS.value, limit=8
    )
    assert [it.message_id for it in second] == mids  # same order
    assert [it.attempts for it in second] == [
        2,
        2,
        2,
    ]  # bumped again, durably (poison ceiling can fire)


# --- T7: head-of-line within a batch (monotonic order, no re-sort) ------------


async def test_t7_batch_is_monotonic_lane_order(store: Any) -> None:
    """The returned list is strictly oldest-first in seq order (rowid on SQLite) — seq-only per-lane
    FIFO (ADR 0059). The worker iterates it in that order and never re-sorts (e.g. by id). With many rows
    the order must not be the random uuid id order."""
    channel = "IB_T7"
    times = [100.0 + i for i in range(16)]
    mids = await _seed_ingress(store, channel, times)
    items = await store.claim_next_fifo_batch(
        channel, now=200.0, stage=Stage.INGRESS.value, limit=16
    )
    assert [it.message_id for it in items] == mids  # exact enqueue order
    # The ids are random uuids — assert the lane order is NOT merely sorted-by-id (a real ordering test).
    assert [it.message_id for it in items] != sorted(it.message_id for it in items)


# --- T8: undecryptable interior row dead-lettered standalone + dropped --------


async def test_t8_undecryptable_interior_dead_lettered_tail_survives(
    store: Any, tmp_path: Path
) -> None:
    """An undecryptable interior row is dead-lettered standalone and DROPPED from the batch; the later
    rows still process (a DEAD head doesn't block), and the surviving tail keeps its order."""
    if store._test_backend != "sqlite":
        pytest.skip(
            "undecryptable-payload injection is exercised on SQLite (cipher seam is the same)"
        )
    import base64

    from messagefoundry.store.crypto import make_cipher

    # Re-open with a cipher so payloads are encrypted; then corrupt the MIDDLE row's payload at rest.
    await store.close()
    key = base64.b64encode(b"\x11" * 32).decode("ascii")  # a valid 32-byte base64 key
    enc = await MessageStore.open(tmp_path / "batch.db", cipher=make_cipher(key, []))
    channel = "IB_T8"
    mids = await _seed_ingress(enc, channel, [100.0, 101.0, 102.0])
    # Corrupt row2's payload to an undecryptable blob (keep the marker so it routes through decrypt).
    await enc._db.execute(
        "UPDATE queue SET payload=? WHERE message_id=? AND stage=?",
        ("mfenc:v1:not-base64-$$$", mids[1], Stage.INGRESS.value),
    )
    await enc._db.commit()
    items = await enc.claim_next_fifo_batch(channel, now=200.0, stage=Stage.INGRESS.value, limit=8)
    # row2 is dropped (dead-lettered); row1 + row3 survive, in order.
    assert [it.message_id for it in items] == [mids[0], mids[2]]
    # The dropped row is DEAD (terminal), not stuck INFLIGHT.
    cur = await enc._db.execute(
        "SELECT status FROM queue WHERE message_id=? AND stage=?", (mids[1], Stage.INGRESS.value)
    )
    row = await cur.fetchone()
    assert row is not None and row["status"] == OutboxStatus.DEAD.value
    await enc.close()


# --- T10: throughput sanity (N=8 fewer claim commits, output identical) -------


async def test_t10_batch_claims_all_due_in_one_call(store: Any) -> None:
    """fifo_claim_batch=8 drains a fixed backlog in ONE claim call (vs 8 single claims), and the claimed
    set + order are identical to draining one-at-a-time. (The commit-count win is structural — one
    claim_next_fifo_batch == one claim commit for the whole prefix.)"""
    channel = "IB_T10"
    times = [100.0 + i for i in range(8)]
    mids = await _seed_ingress(store, channel, times)
    batch = await store.claim_next_fifo_batch(
        channel, now=200.0, stage=Stage.INGRESS.value, limit=8
    )
    assert [it.message_id for it in batch] == mids  # the whole backlog, in one call, in order
    # The lane is now empty (all 8 INFLIGHT) — a second batch returns nothing.
    assert (
        await store.claim_next_fifo_batch(channel, now=200.0, stage=Stage.INGRESS.value, limit=8)
        == []
    )


# --- limit clamps the prefix -------------------------------------------------


async def test_limit_claims_at_most_n(store: Any) -> None:
    """limit=3 over a 5-deep all-due lane claims exactly the 3 oldest, in order; the rest stay PENDING."""
    channel = "IB_LIMIT"
    mids = await _seed_ingress(store, channel, [100.0 + i for i in range(5)])
    items = await store.claim_next_fifo_batch(
        channel, now=200.0, stage=Stage.INGRESS.value, limit=3
    )
    assert [it.message_id for it in items] == mids[:3]
    # The next batch picks up the remaining two, in order.
    rest = await store.claim_next_fifo_batch(channel, now=200.0, stage=Stage.INGRESS.value, limit=3)
    assert [it.message_id for it in rest] == mids[3:]


async def test_empty_lane_returns_empty(store: Any) -> None:
    assert (
        await store.claim_next_fifo_batch("NOPE", now=200.0, stage=Stage.INGRESS.value, limit=8)
        == []
    )
