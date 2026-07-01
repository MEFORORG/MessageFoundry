# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0059 — seq-only per-lane FIFO (dropping the ``_fifo_created_at`` write-time clamp).

Per-lane FIFO now orders by ``seq`` alone (SQLite ``rowid``, SQL Server ``BIGINT IDENTITY``, Postgres
``BIGSERIAL``) — the monotonic insert counter — instead of ``(created_at, seq)``. ``created_at`` stays a
real ingest-time/metrics timestamp but is no longer an ordering key and no longer per-lane-clamped. Per-
lane FIFO is a HARD conformance gate (#285), so these are **backend-parametrized** exactly like
``test_batch_claim_fifo``: the SQLite case runs everywhere; the **SQL Server** and **Postgres** cases run
only when their ``MEFOR_TEST_*`` env is set (the CI service-container legs set them).

Coverage:
- single-lane seq order == enqueue order (all 3 backends)
- the clock-skew anti-regression guard (a backward wall-clock step must NOT reorder; all 3)
- the outbound destination-lane fan-in: concurrent transform_handoffs → delivery order == seq order
  (SQL Server + Postgres — the real multi-writer lane; SQLite serializes a fortiori)
- the RESPONSE-stage loopback re-ingress fan-in twin (SQL Server + Postgres)
- the SQLite rowid-reuse churn guard (DELETE recycles rowids — ``rowid = max(live)+1`` holds)
- blocks-on-backing-off-head under seq ordering (no skip; #285) (all 3)
- the contiguous-due batch cutoff under seq ordering (all 3)
- replay / reset_stale_inflight preserve seq position (all 3)
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, AsyncIterator

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStore, Stage
from messagefoundry.store.store import MessageStatus

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

# --- backend parametrization (mirrors test_batch_claim_fifo) ------------------

_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))


async def _open_sqlite(tmp_path: Path) -> MessageStore:
    return await MessageStore.open(tmp_path / "seq_fifo.db")


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
    s._test_backend = backend  # tag so a test can branch on backend-specific behavior
    try:
        yield s
    finally:
        await s.close()


# --- helpers -----------------------------------------------------------------


async def _seed_ingress(store: Any, channel: str, times: list[float]) -> list[str]:
    """Enqueue one ingress message per timestamp; return message ids in enqueue order."""
    ids = []
    for t in times:
        mid = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=t)
        ids.append(mid)
    return ids


async def _land_routed(store: Any, channel: str, mid: str, now: float) -> str:
    """Drive one message's ingress row to a PENDING routed row (handler 'H'); return its routed_id."""
    ing = await store.claim_next_fifo(channel, now=now, stage=Stage.INGRESS.value)
    assert ing is not None and ing.message_id == mid
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id=channel,
        handlers=[("H", RAW)],
        disposition=MessageStatus.ROUTED,
        now=now,
    )
    routed = await store.claim_next_fifo(channel, now=now, stage=Stage.ROUTED.value)
    assert routed is not None and routed.message_id == mid
    return routed.id


async def _make_not_due(
    store: Any, channel: str, stage: str, message_id: str, until: float
) -> None:
    """Push one lane row's next_attempt_at into the future (a backing-off head) without consuming an
    attempt — done directly so the test controls the not-due boundary precisely."""
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


# --- single-lane seq order == enqueue order ----------------------------------


async def test_seq_only_fifo_single_lane(store: Any) -> None:
    """Enqueue m1..mN into one channel lane, drain via the single FIFO claim, and assert the claim order
    is exactly the enqueue order — which is the seq order. Monotonically increasing now= values keep this
    indistinguishable from the legacy ordering; the backward-clock test proves the seq-only behavior."""
    channel = "IB_SEQ1"
    times = [100.0 + i for i in range(8)]
    mids = await _seed_ingress(store, channel, times)
    claimed: list[str] = []
    for _ in range(len(mids)):
        item = await store.claim_next_fifo(channel, now=500.0, stage=Stage.INGRESS.value)
        assert item is not None
        claimed.append(item.message_id)
        await store.mark_done(item.id, now=500.0)
    assert claimed == mids  # claim order == enqueue order == seq order
    assert await store.claim_next_fifo(channel, now=500.0, stage=Stage.INGRESS.value) is None


async def test_fifo_holds_under_backward_clock(store: Any) -> None:
    """ANTI-REGRESSION (must-fix #6): a BACKWARD wall-clock step must not reorder the lane. Enqueue m1
    @now=100 then m2 @now=50: created_at goes BACKWARD while seq goes FORWARD. With the old
    ``created_at, seq`` ordering m2 (smaller created_at) would sort ahead of m1 — the clamp existed only
    to paper over that. Seq-only orders by the insert counter, so the claim order is the arrival order
    (m1, m2) regardless of the clock. This FAILS if ordering ever reverts to a clock-sensitive basis."""
    channel = "IB_BACK"
    m1 = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=100.0)
    m2 = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=50.0)  # clock stepped BACK
    first = await store.claim_next_fifo(channel, now=500.0, stage=Stage.INGRESS.value)
    assert first is not None and first.message_id == m1  # arrival/seq order, not clock order
    await store.mark_done(first.id, now=500.0)
    second = await store.claim_next_fifo(channel, now=500.0, stage=Stage.INGRESS.value)
    assert second is not None and second.message_id == m2


# --- outbound destination-lane fan-in (the real multi-writer lane) -----------


async def test_outbound_fanin_fifo_is_commit_order(store: Any) -> None:
    """Two inbounds (IB_A, IB_B) both target ONE destination (OB_FAN). Interleave their transform
    handoffs CONCURRENTLY; assert the destination lane drains in seq (= insert-commit) order. The
    fan-in lane has no cross-inbound "receive order" to honor — its FIFO guarantee is insert-commit
    order, and seq is DB-assigned at INSERT, so claim-by-seq IS commit order. On SQL Server / Postgres
    the handoffs genuinely race; on SQLite the process-wide lock serializes them a fortiori."""
    dest = "OB_FAN"
    # Land a routed row per (inbound, message) so each transform_handoff has a claimed routed row.
    routed: list[tuple[str, str]] = []  # (routed_id, message_id)
    for i in range(8):
        ch = "IB_A" if i % 2 == 0 else "IB_B"
        mid = await store.enqueue_ingress(channel_id=ch, raw=RAW, now=100.0 + i)
        rid = await _land_routed(store, ch, mid, now=100.0 + i)
        routed.append((rid, mid))

    # Concurrently hand each routed row off to the SAME destination. The order in which these commit is
    # the order seq is assigned; the lane must then drain in that exact order.
    async def _handoff(rid: str, mid: str) -> None:
        ch = "IB_A"  # channel_id on the outbound row is informational; the lane key is dest
        await store.transform_handoff(
            routed_id=rid,
            message_id=mid,
            channel_id=ch,
            deliveries=[(dest, f"body-{mid}")],
            now=200.0,
        )

    await asyncio.gather(*(_handoff(rid, mid) for rid, mid in routed))

    # Drain the destination lane and capture the bodies in claim order.
    drained: list[str] = []
    while True:
        item = await store.claim_next_fifo(dest, now=300.0, stage=Stage.OUTBOUND.value)
        if item is None:
            break
        drained.append(item.payload)
        await store.mark_done(item.id, now=300.0)
    assert len(drained) == len(routed)
    # Whatever the commit order, the drain order must equal the seq order of the outbound rows. Read the
    # committed seq order straight from the table and assert the lane drained in exactly that order.
    seq_order = await _bodies_in_seq_order(store, dest)
    assert drained == seq_order


async def _bodies_in_seq_order(store: Any, dest: str) -> list[str]:
    """Decrypt the OUTBOUND-lane bodies for ``dest`` in ascending seq (rowid on SQLite) order — the
    authoritative committed FIFO order, read independently of the claim path."""
    backend = store._test_backend
    rows: list[Any]
    if backend == "sqlite":
        cur = await store._db.execute(
            "SELECT payload FROM queue WHERE stage=? AND destination_name=? ORDER BY rowid",
            (Stage.OUTBOUND.value, dest),
        )
        rows = await cur.fetchall()
        return [store._cipher.decrypt(r["payload"]) for r in rows]
    if backend == "postgres":
        async with store._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT payload FROM queue WHERE stage=$1 AND destination_name=$2 ORDER BY seq",
                Stage.OUTBOUND.value,
                dest,
            )
        return [store._cipher.decrypt(r["payload"]) for r in rows]
    # sqlserver
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute(
            "SELECT payload FROM queue WHERE stage=? AND destination_name=? ORDER BY seq",
            (Stage.OUTBOUND.value, dest),
        )
        fetched = await cur.fetchall()
        await cur.close()
    return [store._cipher.decrypt(r[0]) for r in fetched]


# --- RESPONSE-stage loopback re-ingress fan-in twin (must-fix #5) -------------


async def test_response_lane_fanin_fifo_is_commit_order(store: Any) -> None:
    """The SECOND real multi-writer lane on the server backends: concurrent ``complete_with_response``
    re-ingressing replies into ONE loopback lane (``reingress_to``). Each call produces a Stage.RESPONSE
    work-row keyed by the loopback channel; the lane must drain in seq (= insert-commit) order. Set up N
    messages each with one delivered-able outbound row, then complete them CONCURRENTLY with a reply that
    re-ingresses to the same loopback. Assert the RESPONSE lane claims in seq order."""
    loopback = "IB_LOOP"
    dest = "OB_RESP"
    # Each message gets one pending outbound row (the FK target a response work-row references).
    outbox_ids: list[str] = []
    for i in range(8):
        mid = await store.enqueue_message(
            channel_id="IB_REAL", raw=RAW, deliveries=[(dest, f"req-{i}")], now=100.0 + i
        )
        item = await store.claim_next_fifo(dest, now=150.0, stage=Stage.OUTBOUND.value)
        assert item is not None and item.message_id == mid
        outbox_ids.append(item.id)

    async def _complete(oid: str, i: int) -> None:
        await store.complete_with_response(
            oid,
            body=f"reply-{i}",
            outcome="accepted",
            reingress_to=loopback,
            now=200.0,
        )

    await asyncio.gather(*(_complete(oid, i) for i, oid in enumerate(outbox_ids)))

    # Drain the loopback RESPONSE lane; the claim order must equal the committed seq order of the rows.
    claimed_ids: list[str] = []
    while True:
        item = await store.claim_next_fifo(loopback, now=300.0, stage=Stage.RESPONSE.value)
        if item is None:
            break
        claimed_ids.append(item.id)
        await store.mark_done(item.id, now=300.0)
    assert len(claimed_ids) == len(outbox_ids)
    seq_ids = await _response_ids_in_seq_order(store, loopback)
    assert claimed_ids == seq_ids


async def _response_ids_in_seq_order(store: Any, loopback: str) -> list[str]:
    """The RESPONSE-lane row ids for ``loopback`` in ascending seq (rowid) order — the committed FIFO
    order, read independently of the claim path."""
    backend = store._test_backend
    if backend == "sqlite":
        cur = await store._db.execute(
            "SELECT id FROM queue WHERE stage=? AND channel_id=? ORDER BY rowid",
            (Stage.RESPONSE.value, loopback),
        )
        rows = await cur.fetchall()
        return [r["id"] for r in rows]
    if backend == "postgres":
        async with store._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id FROM queue WHERE stage=$1 AND channel_id=$2 ORDER BY seq",
                Stage.RESPONSE.value,
                loopback,
            )
        return [r["id"] for r in rows]
    # sqlserver
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute(
            "SELECT id FROM queue WHERE stage=? AND channel_id=? ORDER BY seq",
            (Stage.RESPONSE.value, loopback),
        )
        fetched = await cur.fetchall()
        await cur.close()
    return [r[0] for r in fetched]


# --- SQLite rowid-reuse churn guard (pins rowid = max(live)+1) ----------------


async def test_seq_fifo_survives_rowid_reuse(store: Any) -> None:
    """SQLite recycles a rowid only after the row holding it is DELETEd (without AUTOINCREMENT, ``rowid =
    max(live rowid) + 1``). Many handoff cycles (each consumes/DELETEs the ingress + routed rows) churn
    rowids; among the LIVE pending rows of a lane, ``ORDER BY rowid`` must still be receive order. This
    pins the load-bearing rowid allocation the seq-only ordering depends on (ADR 0059)."""
    if store._test_backend != "sqlite":
        pytest.skip("rowid-reuse is a SQLite-specific allocation property")
    channel = "IB_CHURN"
    # Churn: enqueue + fully drain ingress→routed→outbound a number of times so many rowids are deleted.
    for i in range(20):
        mid = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=100.0 + i)
        rid = await _land_routed(store, channel, mid, now=100.0 + i)
        await store.transform_handoff(
            routed_id=rid,
            message_id=mid,
            channel_id=channel,
            deliveries=[("OB_CHURN", f"b-{i}")],
            now=100.0 + i,
        )
        out = await store.claim_next_fifo("OB_CHURN", now=100.0 + i, stage=Stage.OUTBOUND.value)
        assert out is not None
        await store.mark_done(out.id, now=100.0 + i)
    # Now enqueue a fresh batch into the churned lane; their rowids are freshly allocated above the
    # surviving max. Among these LIVE pending ingress rows, rowid order must be receive order.
    fresh = await _seed_ingress(store, channel, [500.0 + i for i in range(5)])
    drained: list[str] = []
    for _ in range(len(fresh)):
        item = await store.claim_next_fifo(channel, now=600.0, stage=Stage.INGRESS.value)
        assert item is not None
        drained.append(item.message_id)
        await store.mark_done(item.id, now=600.0)
    assert drained == fresh


# --- blocks-on-backing-off-head under seq ordering (#285 no-skip) ------------


async def test_seq_fifo_blocks_on_backing_off_head(store: Any) -> None:
    """seq 1,2,3 in one lane; mark the head (seq=1) not-due (future next_attempt_at). The single claim
    must return None and the batch claim []: the lane BLOCKS on the backing-off head, never skipping to
    the due tail (#285). Advancing the clock past the head re-offers 1, then 2, 3 in order."""
    channel = "IB_BLOCK"
    mids = await _seed_ingress(store, channel, [100.0, 101.0, 102.0])
    await _make_not_due(store, channel, Stage.INGRESS.value, mids[0], until=10_000.0)
    # Single claim blocks on the not-due head.
    assert await store.claim_next_fifo(channel, now=200.0, stage=Stage.INGRESS.value) is None
    # Batch claim returns [] (the head is the first row and it is not due).
    assert (
        await store.claim_next_fifo_batch(channel, now=200.0, stage=Stage.INGRESS.value, limit=8)
        == []
    )
    # Clock advances past the head → 1, 2, 3 drain in seq order.
    drained: list[str] = []
    for _ in range(3):
        item = await store.claim_next_fifo(channel, now=20_000.0, stage=Stage.INGRESS.value)
        assert item is not None
        drained.append(item.message_id)
        await store.mark_done(item.id, now=20_000.0)
    assert drained == mids


# --- contiguous-due batch cutoff under seq ordering --------------------------


async def test_seq_fifo_contiguous_due_cutoff(store: Any) -> None:
    """seq 1,2,3,4 in one lane; make seq=2 not-due. A batch(limit=10) must return EXACTLY [seq 1]: the
    not-due interior head (seq=2) truncates the contiguous-due prefix there in seq order, never reaching
    seq 3/4 (strict per-lane FIFO; the cutoff keys on next_attempt_at and breaks at the first not-due in
    seq order)."""
    channel = "IB_CUT"
    mids = await _seed_ingress(store, channel, [100.0, 101.0, 102.0, 103.0])
    await _make_not_due(store, channel, Stage.INGRESS.value, mids[1], until=10_000.0)
    items = await store.claim_next_fifo_batch(
        channel, now=200.0, stage=Stage.INGRESS.value, limit=10
    )
    assert [it.message_id for it in items] == [mids[0]]


# --- replay / reset preserve seq position ------------------------------------


async def test_replay_and_reset_preserve_seq_position(store: Any) -> None:
    """replay / reset_stale_inflight are in-place UPDATEs that never re-stamp seq, so a recovered/replayed
    row re-enters at its ORIGINAL FIFO position. Lane: m1,m2,m3. Claim m1 (head) and mark_failed so it
    re-pends in place; replay m1; it must STILL be the head ahead of m2,m3 (seq unchanged). Then a
    reset_stale_inflight on an inflight head likewise keeps its position."""
    channel = "IB_REPLAY"
    mids = await _seed_ingress(store, channel, [100.0, 101.0, 102.0])
    head = await store.claim_next_fifo(channel, now=110.0, stage=Stage.INGRESS.value)
    assert head is not None and head.message_id == mids[0]
    # Fail the head with a real backoff, then replay it — replay recovers the dead/pending head in place.
    await store.mark_failed(
        head.id, "boom", RetryPolicy(max_attempts=9, backoff_seconds=5), now=110.0
    )
    await store.replay(mids[0], now=120.0)
    # After replay the head is due again and STILL leads the lane (seq unchanged), ahead of m2/m3.
    again = await store.claim_next_fifo(channel, now=130.0, stage=Stage.INGRESS.value)
    assert again is not None and again.message_id == mids[0]  # original position preserved
    # Now simulate a crash: leave it inflight and recover via reset_stale_inflight; it re-enters at head.
    recovered = await store.reset_stale_inflight(now=140.0, stage=Stage.INGRESS.value)
    assert recovered >= 1
    head2 = await store.claim_next_fifo(channel, now=150.0, stage=Stage.INGRESS.value)
    assert head2 is not None and head2.message_id == mids[0]  # still the head after recovery
    await store.mark_done(head2.id, now=150.0)
    # The tail then drains in seq order.
    nxt = await store.claim_next_fifo(channel, now=160.0, stage=Stage.INGRESS.value)
    assert nxt is not None and nxt.message_id == mids[1]
