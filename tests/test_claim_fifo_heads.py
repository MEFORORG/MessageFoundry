# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0066 — the pooled-claimer store primitives: ``claim_fifo_heads`` / ``list_fifo_lanes`` /
``release_claimed`` (the §8 store-level matrix, minus the external-lock schedules).

Backend-parametrized like ``test_batch_claim_fifo.py``: the SQLite case runs everywhere; the SQL
Server / Postgres cases run when their ``MEFOR_TEST_*`` env (+ connection env) is set — the CI
service-container legs set them. The **true-T6 external-lock schedules** (rows 1a/1b/1c/1e/1f held
via a second connection) live in ``test_batch_claim_locking.py`` (they are only observable on the
server backends — on SQLite the process-wide lock totally orders producers and claimers, so the
locked-head state is unobservable; the serialized behavior is asserted here instead). The pooled H1
epoch-fencing rows live beside the existing fence tests in ``test_sqlserver_store.py`` /
``test_postgres_store.py``.

NOTHING in the engine calls these yet (ADR 0066 PR 2) — this is the store contract only.
"""

from __future__ import annotations

import asyncio
import importlib
import os
from pathlib import Path
from typing import Any, AsyncIterator

import pytest

from messagefoundry.store import ClaimedHeads, MessageStore, OutboxStatus, Stage
from messagefoundry.store.store import MessageStatus

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))

# The backend module owning each store implementation (its _FIFO_HEADS_LANE_CHUNK clamp).
_BACKEND_MODULE = {
    "sqlite": "messagefoundry.store.store",
    "postgres": "messagefoundry.store.postgres",
    "sqlserver": "messagefoundry.store.sqlserver",
}


async def _open_sqlite(tmp_path: Path) -> MessageStore:
    return await MessageStore.open(tmp_path / "heads.db")


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
    s._test_backend = backend  # tag so a test can branch on backend-specific access
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


def _pg_sql(sql: str) -> str:
    """Rewrite qmark placeholders to asyncpg's $1..$n (test helper; SQL is test-owned constants)."""
    out: list[str] = []
    n = 0
    for ch in sql:
        if ch == "?":
            n += 1
            out.append(f"${n}")
        else:
            out.append(ch)
    return "".join(out)


async def _exec(store: Any, sql: str, params: tuple[Any, ...]) -> None:
    """Run one write statement against whichever backend the fixture opened (qmark placeholders)."""
    backend = store._test_backend
    if backend == "sqlite":
        await store._db.execute(sql, params)
        await store._db.commit()
    elif backend == "postgres":
        async with store._pool.acquire() as conn:
            await conn.execute(_pg_sql(sql), *params)
    else:  # sqlserver
        async with store._pool.acquire() as conn:
            cur = await conn.cursor()
            await cur.execute(sql, params)
            await conn.commit()


async def _query(store: Any, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    """Run one read against whichever backend the fixture opened; rows as dicts."""
    backend = store._test_backend
    if backend == "sqlite":
        cur = await store._db.execute(sql, params)
        return [dict(r) for r in await cur.fetchall()]
    if backend == "postgres":
        async with store._pool.acquire() as conn:
            return [dict(r) for r in await conn.fetch(_pg_sql(sql), *params)]
    return list(await store._fetchall(sql, params))  # sqlserver


async def _lane_rows(store: Any, lane_col: str, lane: str, stage: str) -> list[dict[str, Any]]:
    """All queue rows for one lane at ``stage``, in lane FIFO order (rowid on SQLite, seq elsewhere)."""
    order = "rowid" if store._test_backend == "sqlite" else "seq"
    return await _query(
        store,
        f"SELECT id, message_id, status, attempts, next_attempt_at FROM queue"
        f" WHERE stage=? AND {lane_col}=? ORDER BY {order}",
        (stage, lane),
    )


async def _make_not_due(store: Any, stage: str, message_id: str, until: float) -> None:
    """Push one lane row's next_attempt_at into the future (a backing-off head) WITHOUT consuming an
    attempt — done directly so the test controls the not-due boundary precisely."""
    await _exec(
        store,
        "UPDATE queue SET next_attempt_at=? WHERE message_id=? AND stage=?",
        (until, message_id, stage),
    )


# --- basic multi-lane contract ------------------------------------------------


async def test_multi_lane_contiguous_due_prefix_one_call(store: Any) -> None:
    """One call over two free lanes claims each lane's whole due prefix, oldest-first per lane, with
    POST-increment attempts (G6); the claimed rows are INFLIGHT so a second call claims nothing."""
    a = await _seed_ingress(store, "IB_HA", [100.0, 101.0, 102.0])
    b = await _seed_ingress(store, "IB_HB", [100.5, 101.5])
    res = await store.claim_fifo_heads(
        Stage.INGRESS.value, ["IB_HA", "IB_HB"], now=200.0, per_lane_limit=8
    )
    assert isinstance(res, ClaimedHeads)
    assert set(res.by_lane) == {"IB_HA", "IB_HB"}
    assert [it.message_id for it in res.by_lane["IB_HA"]] == a
    assert [it.message_id for it in res.by_lane["IB_HB"]] == b
    assert all(it.attempts == 1 for items in res.by_lane.values() for it in items)
    assert res.rearm == frozenset()
    again = await store.claim_fifo_heads(
        Stage.INGRESS.value, ["IB_HA", "IB_HB"], now=200.0, per_lane_limit=8
    )
    assert again.by_lane == {} and again.rearm == frozenset()


async def test_empty_and_unknown_lanes(store: Any) -> None:
    res = await store.claim_fifo_heads(Stage.INGRESS.value, [], now=200.0)
    assert res.by_lane == {} and res.rearm == frozenset()
    res2 = await store.claim_fifo_heads(Stage.INGRESS.value, ["NOPE"], now=200.0)
    assert res2.by_lane == {} and res2.rearm == frozenset()
    assert await store.list_fifo_lanes(Stage.INGRESS.value) == []


async def test_duplicate_lanes_deduped(store: Any) -> None:
    """A duplicated lane name claims its prefix once (the request set is de-duplicated — on SQL
    Server a duplicate would otherwise violate the @heads PRIMARY KEY)."""
    mids = await _seed_ingress(store, "IB_HDUP", [100.0])
    res = await store.claim_fifo_heads(
        Stage.INGRESS.value, ["IB_HDUP", "IB_HDUP"], now=200.0, per_lane_limit=8
    )
    assert [it.message_id for it in res.by_lane["IB_HDUP"]] == mids


# --- 1d: not-due head blocks the lane; list_fifo_lanes reports the HEAD's due time


async def test_not_due_head_blocks_lane_and_discovery_reports_head_due(store: Any) -> None:
    """[not-due head, due tail] → the lane yields NOTHING (head-of-line preserved; the due tail is
    never reached past) and NO row is UPDATEd (attempts untouched — probe-then-claim). And
    list_fifo_lanes reports the HEAD's next_attempt_at, never the due tail row's (§3.6: the sweep
    must not ready a head-blocked lane)."""
    mids = await _seed_ingress(store, "IB_HD", [100.0, 101.0])
    await _make_not_due(store, Stage.INGRESS.value, mids[0], until=10_000.0)
    res = await store.claim_fifo_heads(Stage.INGRESS.value, ["IB_HD"], now=200.0, per_lane_limit=8)
    assert res.by_lane == {} and res.rearm == frozenset()
    rows = await _lane_rows(store, "channel_id", "IB_HD", Stage.INGRESS.value)
    assert [(r["status"], r["attempts"]) for r in rows] == [
        (OutboxStatus.PENDING.value, 0),
        (OutboxStatus.PENDING.value, 0),
    ]
    lanes = await store.list_fifo_lanes(Stage.INGRESS.value)
    assert lanes == [("IB_HD", 10_000.0)]  # the HEAD's due time — not the due tail's 101.0


async def test_multi_lane_isolation_not_due_head(store: Any) -> None:
    """Lane A head-blocked (backing off), lane B free → ONE call returns B only; A untouched."""
    a = await _seed_ingress(store, "IB_HIA", [100.0, 101.0])
    b = await _seed_ingress(store, "IB_HIB", [100.0])
    await _make_not_due(store, Stage.INGRESS.value, a[0], until=10_000.0)
    res = await store.claim_fifo_heads(
        Stage.INGRESS.value, ["IB_HIA", "IB_HIB"], now=200.0, per_lane_limit=8
    )
    assert set(res.by_lane) == {"IB_HIB"}
    assert [it.message_id for it in res.by_lane["IB_HIB"]] == b
    rows = await _lane_rows(store, "channel_id", "IB_HIA", Stage.INGRESS.value)
    assert all(r["status"] == OutboxStatus.PENDING.value and r["attempts"] == 0 for r in rows)


async def test_interior_not_due_truncates_prefix_tail_untouched(store: Any) -> None:
    """[due, not-due, due] → exactly the head is claimed (never {row1,row3}); the rows past the
    cutoff are never UPDATEd (status pending, attempts 0)."""
    mids = await _seed_ingress(store, "IB_HT", [100.0, 101.0, 102.0])
    await _make_not_due(store, Stage.INGRESS.value, mids[1], until=10_000.0)
    res = await store.claim_fifo_heads(Stage.INGRESS.value, ["IB_HT"], now=200.0, per_lane_limit=8)
    assert [it.message_id for it in res.by_lane["IB_HT"]] == [mids[0]]
    for mid in mids[1:]:
        row = (
            await _query(
                store,
                "SELECT status, attempts FROM queue WHERE message_id=? AND stage=?",
                (mid, Stage.INGRESS.value),
            )
        )[0]
        assert row["status"] == OutboxStatus.PENDING.value and row["attempts"] == 0


# --- per_lane_limit -----------------------------------------------------------


async def test_per_lane_limit_gt1_claims_prefix_then_rest(store: Any) -> None:
    mids = await _seed_ingress(store, "IB_HK", [100.0 + i for i in range(5)])
    first = await store.claim_fifo_heads(
        Stage.INGRESS.value, ["IB_HK"], now=200.0, per_lane_limit=3
    )
    assert [it.message_id for it in first.by_lane["IB_HK"]] == mids[:3]
    rest = await store.claim_fifo_heads(Stage.INGRESS.value, ["IB_HK"], now=200.0, per_lane_limit=3)
    assert [it.message_id for it in rest.by_lane["IB_HK"]] == mids[3:]


async def test_outbound_per_lane_limit_clamped_to_one(store: Any) -> None:
    """per_lane_limit is HARD-1 for OUTBOUND (H2 atomicity + single-outstanding-head retry
    semantics): even per_lane_limit=8 claims exactly the head; the next row is untouched."""
    m1 = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB_H1", "p1")], now=100.0
    )
    m2 = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB_H1", "p2")], now=101.0
    )
    res = await store.claim_fifo_heads(Stage.OUTBOUND.value, ["OB_H1"], now=200.0, per_lane_limit=8)
    assert [it.message_id for it in res.by_lane["OB_H1"]] == [m1]
    row = (
        await _query(
            store,
            "SELECT status, attempts FROM queue WHERE message_id=? AND stage=?",
            (m2, Stage.OUTBOUND.value),
        )
    )[0]
    assert row["status"] == OutboxStatus.PENDING.value and row["attempts"] == 0


# --- H2: delivered-then-re-pended outbound head --------------------------------


async def test_h2_delivered_then_repended_completed_in_txn_and_rearmed(store: Any) -> None:
    """A delivered-then-re-pended outbound head (reset_stale_inflight after mark_done committed / a
    failover re-claim) is completed DONE inside the claim txn, NEVER returned (no re-send), and its
    lane is reported in ``rearm`` — the follow-up claim advances to the next head with no reorder."""
    m1 = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB_H2", "p1")], now=100.0
    )
    m2 = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB_H2", "p2")], now=101.0
    )
    first = await store.claim_fifo_heads(Stage.OUTBOUND.value, ["OB_H2"], now=200.0)
    item = first.by_lane["OB_H2"][0]
    assert item.message_id == m1
    await store.mark_done(item.id, now=300.0)  # commits the H2 ledger row
    await _exec(
        store,
        "UPDATE queue SET status=?, next_attempt_at=?, updated_at=? WHERE id=?",
        (OutboxStatus.PENDING.value, 300.0, 300.0, item.id),
    )
    res = await store.claim_fifo_heads(Stage.OUTBOUND.value, ["OB_H2"], now=400.0)
    assert res.by_lane == {}  # consumed in-store, never handed to a worker
    assert res.rearm == frozenset({"OB_H2"})
    row = (await _query(store, "SELECT status FROM queue WHERE id=?", (item.id,)))[0]
    assert row["status"] == OutboxStatus.DONE.value
    assert (await store.get_message(m1))["status"] == MessageStatus.PROCESSED.value
    nxt = await store.claim_fifo_heads(Stage.OUTBOUND.value, ["OB_H2"], now=401.0)
    assert [it.message_id for it in nxt.by_lane["OB_H2"]] == [m2]  # the lane advanced, in order


# --- release_claimed ------------------------------------------------------------


async def test_release_claimed_restores_attempts_keeps_schedule(store: Any) -> None:
    """release_claimed undoes exactly the claim's attempts increment, leaves next_attempt_at
    UNCHANGED (a release is not a failure), and is FIFO-neutral (the re-claim returns the same rows
    in the same order)."""
    mids = await _seed_ingress(store, "IB_HR", [100.0, 101.0])
    before = await _lane_rows(store, "channel_id", "IB_HR", Stage.INGRESS.value)
    schedule = {r["id"]: r["next_attempt_at"] for r in before}
    res = await store.claim_fifo_heads(Stage.INGRESS.value, ["IB_HR"], now=200.0, per_lane_limit=8)
    items = res.by_lane["IB_HR"]
    assert [it.attempts for it in items] == [1, 1]
    await store.release_claimed([it.id for it in items], now=210.0)
    after = await _lane_rows(store, "channel_id", "IB_HR", Stage.INGRESS.value)
    for r in after:
        assert r["status"] == OutboxStatus.PENDING.value
        assert r["attempts"] == 0  # the increment undone exactly (attempts-neutral)
        assert r["next_attempt_at"] == schedule[r["id"]]  # UNCHANGED — no backoff consumed
    again = await store.claim_fifo_heads(
        Stage.INGRESS.value, ["IB_HR"], now=220.0, per_lane_limit=8
    )
    assert [it.message_id for it in again.by_lane["IB_HR"]] == mids
    assert [it.attempts for it in again.by_lane["IB_HR"]] == [1, 1]


async def test_release_claimed_noops_on_non_inflight_and_unknown(store: Any) -> None:
    """Unknown ids and rows not currently INFLIGHT are left untouched (idempotent; the floor-0 can
    never underflow a pending row's attempts)."""
    mids = await _seed_ingress(store, "IB_HRN", [100.0])
    await store.release_claimed([], now=200.0)
    await store.release_claimed(["no-such-id"], now=200.0)
    row = (
        await _query(
            store,
            "SELECT id, status, attempts FROM queue WHERE message_id=? AND stage=?",
            (mids[0], Stage.INGRESS.value),
        )
    )[0]
    await store.release_claimed([row["id"]], now=200.0)  # pending, not inflight → untouched
    row2 = (
        await _query(
            store,
            "SELECT status, attempts FROM queue WHERE message_id=? AND stage=?",
            (mids[0], Stage.INGRESS.value),
        )
    )[0]
    assert row2["status"] == OutboxStatus.PENDING.value and row2["attempts"] == 0


# --- lane-chunk clamp -----------------------------------------------------------


async def test_lane_chunk_clamped_second_call_covers_rest(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """More lanes than the chunk clamp in one call → only the FIRST chunk lanes (request order) are
    claimed; a second call with the remainder covers the rest."""
    mod = importlib.import_module(_BACKEND_MODULE[store._test_backend])
    monkeypatch.setattr(mod, "_FIFO_HEADS_LANE_CHUNK", 3)
    lanes = [f"IB_HC{i}" for i in range(5)]
    for lane in lanes:
        await _seed_ingress(store, lane, [100.0])
    res = await store.claim_fifo_heads(Stage.INGRESS.value, lanes, now=200.0)
    assert set(res.by_lane) == set(lanes[:3])
    rest = await store.claim_fifo_heads(Stage.INGRESS.value, lanes[3:], now=200.0)
    assert set(rest.by_lane) == set(lanes[3:])


def test_chunk_clamp_constants_pinned() -> None:
    """Pin the documented clamp boundaries (SQLite 200 — the write-lock hold bound; server backends
    500 — the VALUES-list / lane-array bound), so a drive-by edit trips a test (mutation-test the
    boundaries, per the harness-gate lesson)."""
    from messagefoundry.store import postgres as pg_mod
    from messagefoundry.store import sqlserver as ss_mod
    from messagefoundry.store import store as sqlite_mod

    assert sqlite_mod._FIFO_HEADS_LANE_CHUNK == 200
    assert pg_mod._FIFO_HEADS_LANE_CHUNK == 500
    assert ss_mod._FIFO_HEADS_LANE_CHUNK == 500
    assert sqlite_mod._RELEASE_CHUNK == pg_mod._RELEASE_CHUNK == ss_mod._RELEASE_CHUNK == 500


# --- list_fifo_lanes -------------------------------------------------------------


async def test_list_fifo_lanes_pagination_and_stage_scoping(store: Any) -> None:
    for lane, t in (("IB_L1", 100.0), ("IB_L2", 101.0), ("IB_L3", 102.0)):
        await _seed_ingress(store, lane, [t])
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB_L1", "p")], now=100.0)
    all_lanes = await store.list_fifo_lanes(Stage.INGRESS.value)
    assert all_lanes == [("IB_L1", 100.0), ("IB_L2", 101.0), ("IB_L3", 102.0)]
    # limit + after cursor walks the same set in ascending lane order.
    walked: list[tuple[str, float]] = []
    after: str | None = None
    while True:
        page = await store.list_fifo_lanes(Stage.INGRESS.value, limit=1, after=after)
        if not page:
            break
        walked.extend(page)
        after = page[-1][0]
    assert walked == all_lanes
    # Another stage's lanes are invisible to this stage's discovery (and vice versa).
    out_lanes = await store.list_fifo_lanes(Stage.OUTBOUND.value)
    assert [lane for lane, _ in out_lanes] == ["OB_L1"]


async def test_list_fifo_lanes_excludes_fully_claimed_lane(store: Any) -> None:
    """A lane with no PENDING rows left (all inflight) disappears from discovery."""
    await _seed_ingress(store, "IB_LC", [100.0])
    res = await store.claim_fifo_heads(Stage.INGRESS.value, ["IB_LC"], now=200.0)
    assert set(res.by_lane) == {"IB_LC"}
    assert await store.list_fifo_lanes(Stage.INGRESS.value) == []


# --- SQLite: the vacuous/serialized locked-head case -----------------------------


async def test_sqlite_claim_serializes_behind_global_lock_no_skip(store: Any) -> None:
    """On SQLite the true-T6 locked-head schedule is UNOBSERVABLE: the process-wide lock totally
    orders producers and claimers, so a claim issued while the lock is held simply WAITS and then
    claims the TRUE head — the lock is the no-skip guarantee (ADR 0066 §3.5). The server-backend
    external-lock schedules live in test_batch_claim_locking.py."""
    if store._test_backend != "sqlite":
        pytest.skip("the SQLite global-lock serialization case")
    mids = await _seed_ingress(store, "IB_HS", [100.0, 101.0])
    async with store._lock:
        task = asyncio.ensure_future(
            store.claim_fifo_heads(Stage.INGRESS.value, ["IB_HS"], now=200.0, per_lane_limit=8)
        )
        await asyncio.sleep(0.05)
        assert not task.done()  # serialized behind the lock — never a lock-skip, never an error
    res = await asyncio.wait_for(task, timeout=5.0)
    assert [it.message_id for it in res.by_lane["IB_HS"]] == mids  # the TRUE head leads


# --- poison containment (SQLite; the cipher seam is the same on all backends) ----


async def test_poison_rows_dead_lettered_dropped_and_lane_rearmed(
    store: Any, tmp_path: Path
) -> None:
    """An undecryptable HEAD is dead-lettered standalone, dropped, and its lane joins ``rearm``
    (whole prefix consumed); an undecryptable INTERIOR row is dropped while the surviving tail keeps
    its order and the lane does NOT re-arm (it got items)."""
    if store._test_backend != "sqlite":
        pytest.skip(
            "undecryptable-payload injection is exercised on SQLite (cipher seam is the same)"
        )
    import base64

    from messagefoundry.store.crypto import make_cipher

    await store.close()
    key = base64.b64encode(b"\x11" * 32).decode("ascii")
    enc = await MessageStore.open(tmp_path / "heads.db", cipher=make_cipher(key, []))
    try:
        # Lane 1: a single poison HEAD → dropped + DEAD + the lane re-arms.
        a = await _seed_ingress(enc, "IB_HP1", [100.0])
        await enc._db.execute(
            "UPDATE queue SET payload=? WHERE message_id=? AND stage=?",
            ("mfenc:v1:not-base64-$$$", a[0], Stage.INGRESS.value),
        )
        await enc._db.commit()
        res = await enc.claim_fifo_heads(Stage.INGRESS.value, ["IB_HP1"], now=200.0)
        assert res.by_lane == {} and res.rearm == frozenset({"IB_HP1"})
        cur = await enc._db.execute(
            "SELECT status FROM queue WHERE message_id=? AND stage=?",
            (a[0], Stage.INGRESS.value),
        )
        row = await cur.fetchone()
        assert row is not None and row["status"] == OutboxStatus.DEAD.value
        # Lane 2: a poison INTERIOR row → dropped; the surviving tail keeps order; NOT re-armed.
        b = await _seed_ingress(enc, "IB_HP2", [100.0, 101.0, 102.0])
        await enc._db.execute(
            "UPDATE queue SET payload=? WHERE message_id=? AND stage=?",
            ("mfenc:v1:not-base64-$$$", b[1], Stage.INGRESS.value),
        )
        await enc._db.commit()
        res2 = await enc.claim_fifo_heads(
            Stage.INGRESS.value, ["IB_HP2"], now=200.0, per_lane_limit=8
        )
        assert [it.message_id for it in res2.by_lane["IB_HP2"]] == [b[0], b[2]]
        assert "IB_HP2" not in res2.rearm
    finally:
        await enc.close()
