# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0060 — rename-based FIFO covering-index migration (land ADR 0059's re-key on UPGRADED DBs).

ADR 0059 re-keyed the per-lane FIFO indexes to trail in ``seq`` but KEPT the names
``ix_queue_fifo_in/out`` under name-existence guards (``CREATE INDEX IF NOT EXISTS`` / ``IF
INDEXPROPERTY(...) IS NULL CREATE``). A fresh DB got the seq-trailing index; an UPGRADED DB silently kept
its old ``created_at``-trailing index and never adopted the seq-only claim's index. ADR 0060 renames the
seq-trailing index to ``ix_queue_fifo_*_seq`` and runs an idempotent on-open migration that DROPs the
old-named index and CREATEs the new one, so upgraded DBs adopt it. B3 shipped these indexes with ZERO
test coverage (a grep of ``tests/`` for ``ix_queue_fifo`` found nothing) — this suite closes that gap so
the stale-index class cannot recur silently.

Backend-parametrized exactly like ``test_seq_only_fifo`` / ``test_batch_claim_fifo``: the SQLite case
runs everywhere; the SQL Server and Postgres cases run only when their ``MEFOR_TEST_*`` env is set (the CI
service-container legs set them). A few migration-mechanics tests (crash atomicity, index-independence,
the mixed-version hazard) are SQLite-only + driver-free — they need no server DB and probe the
``executescript``/``_migrate`` commit boundary the design reasoned about.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, AsyncIterator

import pytest

from messagefoundry.store import MessageStore, Stage

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))

_OLD_NAMES = {"ix_queue_fifo_in", "ix_queue_fifo_out"}
_NEW_NAMES = {"ix_queue_fifo_in_seq", "ix_queue_fifo_out_seq"}


# --- backend openers (mirror test_seq_only_fifo) ------------------------------


async def _open_sqlite(path: Path) -> MessageStore:
    return await MessageStore.open(path)


async def _open_sqlserver(_: Path) -> Any:
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


async def _open_postgres(_: Path) -> Any:
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


_OPENERS = {"sqlite": _open_sqlite, "sqlserver": _open_sqlserver, "postgres": _open_postgres}


@pytest.fixture(params=["sqlite", "sqlserver", "postgres"])
async def store(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[Any]:
    backend = request.param
    if backend == "sqlserver" and not _SQLSERVER_ON:
        pytest.skip("set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the SQL Server case")
    if backend == "postgres" and not _POSTGRES_ON:
        pytest.skip("set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres case")
    s = await _OPENERS[backend](tmp_path / "fifo_idx.db")
    s._test_backend = backend
    s._test_path = tmp_path / "fifo_idx.db"  # for reopen (SQLite); server reopens via settings
    try:
        yield s
    finally:
        await s.close()


# --- backend-specific index introspection + downgrade + reopen ----------------


async def _fifo_index_names(store: Any) -> set[str]:
    """The names of every ``ix_queue_fifo*`` index on the ``queue`` table — the DDL contract probe."""
    backend = store._test_backend
    if backend == "sqlite":
        cur = await store._db.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='queue'"
            " AND name LIKE 'ix_queue_fifo%'"
        )
        return {r["name"] for r in await cur.fetchall()}
    if backend == "postgres":
        async with store._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT indexname FROM pg_indexes WHERE tablename='queue'"
                " AND indexname LIKE 'ix_queue_fifo%'"
            )
        return {r["indexname"] for r in rows}
    async with store._pool.acquire() as conn:  # sqlserver
        cur = await conn.cursor()
        await cur.execute(
            "SELECT name FROM sys.indexes WHERE object_id=OBJECT_ID('queue')"
            " AND name LIKE 'ix_queue_fifo%'"
        )
        rows = await cur.fetchall()
        await cur.close()
    return {r[0] for r in rows}


async def _any_fifo_index_carries_created_at(store: Any) -> bool:
    """True if ANY ``ix_queue_fifo*`` index still keys on ``created_at`` (the stale definition). The
    negative assertion that the migration actually shed the old column, not just renamed a name."""
    backend = store._test_backend
    if backend == "sqlite":
        for name in await _fifo_index_names(store):
            cur = await store._db.execute(f"PRAGMA index_info({name})")
            # PRAGMA index_info doesn't cover expression/rowid; the columns are the indexed key columns.
            cols = {r["name"] for r in await cur.fetchall()}
            if "created_at" in cols:
                return True
        return False
    if backend == "postgres":
        async with store._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT indexdef FROM pg_indexes WHERE tablename='queue'"
                " AND indexname LIKE 'ix_queue_fifo%'"
            )
        return any("created_at" in r["indexdef"] for r in rows)
    async with store._pool.acquire() as conn:  # sqlserver
        cur = await conn.cursor()
        await cur.execute(
            "SELECT c.name FROM sys.indexes i"
            " JOIN sys.index_columns ic ON ic.object_id=i.object_id AND ic.index_id=i.index_id"
            " JOIN sys.columns c ON c.object_id=i.object_id AND c.column_id=ic.column_id"
            " WHERE i.object_id=OBJECT_ID('queue') AND i.name LIKE 'ix_queue_fifo%'"
        )
        rows = await cur.fetchall()
        await cur.close()
    return any(r[0] == "created_at" for r in rows)


async def _downgrade_to_old_indexes(store: Any) -> None:
    """Make an open store LOOK like a pre-B10 (upgraded-but-not-yet-migrated) DB: drop the seq-trailing
    ix_queue_fifo_*_seq and re-create the OLD created_at-trailing ix_queue_fifo_in/out. A reopen then
    exercises the real migration path."""
    backend = store._test_backend
    stmts = [
        "DROP INDEX IF EXISTS ix_queue_fifo_in_seq",
        "DROP INDEX IF EXISTS ix_queue_fifo_out_seq",
        "CREATE INDEX ix_queue_fifo_in ON queue(stage, channel_id, status, created_at)",
        "CREATE INDEX ix_queue_fifo_out ON queue(stage, destination_name, status, created_at)",
    ]
    if backend == "sqlite":
        # SQLite CREATE INDEX can't include rowid, so the old index legitimately trailed in created_at.
        for s in stmts:
            await store._db.execute(s)
        await store._db.commit()
    elif backend == "postgres":
        async with store._pool.acquire() as conn:
            for s in stmts:
                await conn.execute(s)
    else:  # sqlserver — DROP INDEX needs the ON queue form; IF EXISTS is supported (2016+)
        ss = [
            "DROP INDEX IF EXISTS ix_queue_fifo_in_seq ON queue",
            "DROP INDEX IF EXISTS ix_queue_fifo_out_seq ON queue",
            "CREATE INDEX ix_queue_fifo_in ON queue(stage, channel_id, status, created_at)",
            "CREATE INDEX ix_queue_fifo_out ON queue(stage, destination_name, status, created_at)",
        ]
        async with store._pool.acquire() as conn:
            cur = await conn.cursor()
            for s in ss:
                await cur.execute(s)
            await conn.commit()
            await cur.close()


async def _reopen(store: Any) -> Any:
    """Re-open the SAME underlying DB (triggering _migrate / _ensure_schema again) and return the new
    handle, tagged for the helpers. The caller owns closing it."""
    backend = store._test_backend
    fresh = await _OPENERS_NO_CLEAN[backend](store._test_path)
    fresh._test_backend = backend
    fresh._test_path = store._test_path
    return fresh


async def _open_sqlserver_noclean(_: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    return await SqlServerStore.open(load_settings(environ=os.environ).store)


async def _open_postgres_noclean(_: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    s = await PostgresStore.open(load_settings(environ=os.environ).store)
    await s._load_state_cache()
    await s._load_reference_cache()
    return s


# Reopen must NOT truncate (that would erase the seeded rows the migration is meant to preserve).
_OPENERS_NO_CLEAN = {
    "sqlite": _open_sqlite,
    "sqlserver": _open_sqlserver_noclean,
    "postgres": _open_postgres_noclean,
}


async def _drain_lane(store: Any, channel: str) -> list[str]:
    out: list[str] = []
    while True:
        item = await store.claim_next_fifo(channel, now=10_000.0, stage=Stage.INGRESS.value)
        if item is None:
            break
        out.append(item.message_id)
        await store.mark_done(item.id, now=10_000.0)
    return out


# --- fresh-DB index contract (all 3 backends) --------------------------------


async def test_fresh_db_has_seq_index_not_old(store: Any) -> None:
    """A brand-new store carries ONLY the seq-trailing ix_queue_fifo_*_seq; the old created_at-trailing
    ix_queue_fifo_in/out are never created, and no FIFO index keys on created_at."""
    names = await _fifo_index_names(store)
    assert _NEW_NAMES <= names, names
    assert not (_OLD_NAMES & names), f"stale old-named FIFO index on a fresh DB: {names}"
    assert not await _any_fifo_index_carries_created_at(store)


# --- upgraded DB migrates + preserves FIFO (all 3 backends) -------------------


async def test_upgraded_db_migrates_and_preserves_fifo(store: Any) -> None:
    """Seed pending rows across two lanes whose seq order DISAGREES with created_at order (a backward
    clock step), then DOWNGRADE the indexes to the old created_at-trailing names (simulating a pre-B10
    upgraded DB) and REOPEN to run the real migration. Assert: (a) old-named indexes gone, new present,
    no FIFO index trails created_at; (b) every seeded row still claims in strict seq order (the rebuild
    preserved rows AND ordering follows seq, not the dropped created_at); (c) the queue row set is
    unchanged (no rows touched)."""
    ch1, ch2 = "IB_UP1", "IB_UP2"
    # Backward clock within each lane: seq increases while created_at decreases → the two keys disagree,
    # so a mistaken created_at-ordered claim would return a DIFFERENT order than seq.
    m1a = await store.enqueue_ingress(channel_id=ch1, raw=RAW, now=100.0)
    m1b = await store.enqueue_ingress(channel_id=ch1, raw=RAW, now=50.0)
    m2a = await store.enqueue_ingress(channel_id=ch2, raw=RAW, now=100.0)
    m2b = await store.enqueue_ingress(channel_id=ch2, raw=RAW, now=50.0)
    before = await _queue_fingerprint(store)

    await _downgrade_to_old_indexes(store)
    assert _OLD_NAMES <= await _fifo_index_names(store)  # precondition: looks pre-B10

    reopened = await _reopen(store)
    try:
        names = await _fifo_index_names(reopened)
        assert _NEW_NAMES <= names, names
        assert not (_OLD_NAMES & names), f"old-named index survived the migration: {names}"
        assert not await _any_fifo_index_carries_created_at(reopened)
        # The row set is byte-identical — the migration touched only indexes, never rows.
        assert await _queue_fingerprint(reopened) == before
        # FIFO order follows seq (arrival), NOT the dropped created_at: m*a before m*b in each lane.
        assert await _drain_lane(reopened, ch1) == [m1a, m1b]
        assert await _drain_lane(reopened, ch2) == [m2a, m2b]
    finally:
        await reopened.close()


async def _queue_fingerprint(store: Any) -> list[tuple[Any, ...]]:
    """A stable, order-independent fingerprint of the queue rows (id, message_id, stage, status, seq) to
    prove the migration didn't add/drop/mutate rows. Ordered by seq for a deterministic compare."""
    backend = store._test_backend
    if backend == "sqlite":
        # SQLite has no `seq` column — the intrinsic rowid IS the seq (ADR 0059).
        cur = await store._db.execute(
            "SELECT id, message_id, stage, status, rowid AS seq FROM queue ORDER BY rowid"
        )
        return [tuple(r) for r in await cur.fetchall()]
    if backend == "postgres":
        async with store._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, message_id, stage, status, seq FROM queue ORDER BY seq"
            )
        return [tuple(r) for r in rows]
    async with store._pool.acquire() as conn:  # sqlserver
        cur = await conn.cursor()
        await cur.execute("SELECT id, message_id, stage, status, seq FROM queue ORDER BY seq")
        rows = await cur.fetchall()
        await cur.close()
    return [tuple(r) for r in rows]


# --- idempotent re-open (all 3 backends) -------------------------------------


async def test_idempotent_reopen_is_stable(store: Any) -> None:
    """Re-opening an already-migrated DB is a no-op: the FIFO index set stays exactly the seq-trailing
    pair, no old-named index reappears, and nothing errors (guards the DDL against re-firing/regressing)."""
    reopened = await _reopen(store)
    try:
        assert await _fifo_index_names(reopened) >= _NEW_NAMES
        assert not (_OLD_NAMES & await _fifo_index_names(reopened))
    finally:
        await reopened.close()


# --- SQLite-only, driver-free: migration mechanics ---------------------------


async def test_partial_migration_converges_and_stays_correct(tmp_path: Path) -> None:
    """SQLite auto-commits DDL (legacy isolation), so a crash mid-migration can leave a PARTIAL index
    state (some old dropped, some new created). B10 does NOT rely on atomicity here — the FIFO index is
    correctness-neutral and the migration is idempotent — so ANY partial state (a) still claims in strict
    seq order and (b) converges to the seq-trailing pair on the next open. Construct a representative
    mid-crash partial state (old-in dropped + new-in created, but old-out still present + new-out missing)
    and verify both properties. This is the honest replacement for a transactional-rollback assertion:
    the safety guarantee is convergence + correctness-neutrality, not atomicity."""
    path = tmp_path / "partial.db"
    s = await MessageStore.open(path)
    s._test_backend = "sqlite"
    s._test_path = path
    ch = "IB_PART"
    mids = [await s.enqueue_ingress(channel_id=ch, raw=RAW, now=t) for t in (100.0, 50.0, 75.0)]
    # Force a representative "crashed between the swap statements" partial index state.
    await s._db.execute("DROP INDEX IF EXISTS ix_queue_fifo_in_seq")
    await s._db.execute("DROP INDEX IF EXISTS ix_queue_fifo_out_seq")
    await s._db.execute(
        "CREATE INDEX ix_queue_fifo_out ON queue(stage, destination_name, status, created_at)"
    )
    await s._db.execute("CREATE INDEX ix_queue_fifo_in_seq ON queue(stage, channel_id, status)")
    await s._db.commit()
    # (a) claims are correct in this mixed/partial index state (correctness-neutral).
    assert await _drain_lane(s, ch) == mids  # strict seq order despite the odd index set
    await s.close()

    # (b) a clean reopen's idempotent _migrate converges to the seq-trailing pair, old gone.
    s2 = await MessageStore.open(path)
    s2._test_backend = "sqlite"
    try:
        assert await _fifo_index_names(s2) == _NEW_NAMES
        assert not await _any_fifo_index_carries_created_at(s2)
    finally:
        await s2.close()


async def test_claim_is_index_independent(tmp_path: Path) -> None:
    """The load-bearing invariant B10 rests on: the per-lane claim orders by rowid and NAMES no index, so
    the OLD created_at index, the NEW seq index, and NO FIFO index at all return the IDENTICAL claimed
    order. Seed identical backward-clock rows into three fresh DBs, put each in a different index state,
    and assert the drained order matches."""

    async def _seed_and_drain(index_state: str) -> list[str]:
        path = tmp_path / f"indep_{index_state}.db"
        s = await MessageStore.open(path)
        s._test_backend = "sqlite"
        ch = "IB_IND"
        mids = [
            await s.enqueue_ingress(channel_id=ch, raw=RAW, now=t)
            for t in (100.0, 50.0, 75.0, 25.0)
        ]
        if index_state == "old":
            await _downgrade_to_old_indexes(s)
        elif index_state == "none":
            await s._db.execute("DROP INDEX IF EXISTS ix_queue_fifo_in_seq")
            await s._db.execute("DROP INDEX IF EXISTS ix_queue_fifo_out_seq")
            await s._db.commit()
        # "new" leaves the seq-trailing index in place (as opened).
        drained = await _drain_lane(s, ch)
        await s.close()
        return [mids.index(x) for x in drained]  # positions, comparable across DBs

    new = await _seed_and_drain("new")
    old = await _seed_and_drain("old")
    none = await _seed_and_drain("none")
    assert new == old == none == [0, 1, 2, 3], (new, old, none)  # strict seq order in every state


async def test_mixed_version_stale_index_reappears(tmp_path: Path) -> None:
    """Documents the mixed-version fleet hazard (ADR 0060): a pre-B10 binary opening a B10-migrated DB
    re-creates the stale created_at-trailing index next to the new one, because its schema-init still runs
    the old-named CREATE IF NOT EXISTS. This pins WHY shared-DB upgrades must be stop-the-world; it is a
    regression that motivates the runbook note, not behaviour we support."""
    path = tmp_path / "mixed.db"
    s = await MessageStore.open(path)  # B10 migrates → new-only
    s._test_backend = "sqlite"
    assert await _fifo_index_names(s) == _NEW_NAMES
    # Simulate an OLD (pre-B10) binary's schema-init: it would run the old-named CREATE IF NOT EXISTS.
    await s._db.execute(
        "CREATE INDEX IF NOT EXISTS ix_queue_fifo_in ON queue(stage, channel_id, status)"
    )
    await s._db.execute(
        "CREATE INDEX IF NOT EXISTS ix_queue_fifo_out ON queue(stage, destination_name, status)"
    )
    await s._db.commit()
    both = await _fifo_index_names(s)
    await s.close()
    assert _OLD_NAMES <= both and _NEW_NAMES <= both, (
        "the mixed-version hazard must reproduce (stale index reappears next to the new one): "
        f"{both}"
    )
