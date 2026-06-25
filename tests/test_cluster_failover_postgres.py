# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Active-passive leadership failover against a REAL Postgres (Workstream A2/A6).

**Gated**: skipped unless ``MEFOR_TEST_POSTGRES`` is set (plus ``MEFOR_STORE_*`` connection env), like
:mod:`tests.test_postgres_store`. A CI Postgres service-container job (push to ``main``) sets the env
and runs it for real; it is a no-op locally and on PRs. Requires the ``postgres`` extra (``asyncpg``).

What this validates that the always-run fake-pool unit tests (``tests/test_cluster_lease.py``) cannot:
the actual ``leader_lease`` SQL against a real database clock — the atomic acquire/renew
``INSERT ... ON CONFLICT DO UPDATE ... WHERE owner OR clock_timestamp()-expired`` and the
``leadership_lease`` read — plus genuine two-node contention, takeover after a real TTL elapses, clean
release, and the full ``start()``/``stop()`` lifecycle electing exactly one leader. (Row/lane-lease
reclaim — how a promoted leader recovers a crashed node's in-flight rows — is covered against Postgres
in ``tests/test_postgres_store.py``; the full load-driven kill-the-primary-mid-load benchmark is
Workstream D.)
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable

import pytest

from messagefoundry.pipeline.cluster import DbCoordinator
from messagefoundry.store import OutboxStatus

_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres failover tests",
)

# Short, test-only lease timings (the validator's heartbeat < fence < ttl ordering still holds): a real
# TTL elapses in ~1s so the takeover test doesn't sleep long, while staying well above scheduling jitter.
_TTL = 1.0
_FENCE = 0.6
_HEARTBEAT = 0.3


@pytest.fixture
async def coords() -> AsyncIterator[tuple[Callable[..., DbCoordinator], object]]:
    """Open a real Postgres store, ensure + truncate the cluster tables, and yield a factory that builds
    DbCoordinators sharing its pool (so they contend on the same ``leader_lease`` row, as real nodes
    would). Each built coordinator is tracked and stopped on teardown."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    store = await PostgresStore.open(settings)
    built: list[DbCoordinator] = []
    # The cluster tables (nodes + leader_lease) are created lazily by a coordinator's start(); seed them
    # via one coordinator's _ensure_nodes_table so the TRUNCATE below has something to clear.
    seed = DbCoordinator(store._pool, "seed", db_schema=settings.db_schema)
    await seed._ensure_nodes_table()
    async with store._pool.acquire() as conn:
        await conn.execute("TRUNCATE nodes, leader_lease RESTART IDENTITY CASCADE")

    def make(node_id: str, **kw: object) -> DbCoordinator:
        c = DbCoordinator(
            store._pool,
            node_id,
            db_schema=settings.db_schema,
            heartbeat_seconds=kw.pop("heartbeat_seconds", _HEARTBEAT),  # type: ignore[arg-type]
            node_timeout_seconds=kw.pop("node_timeout_seconds", 5.0),  # type: ignore[arg-type]
            leader_lease_ttl_seconds=kw.pop("leader_lease_ttl_seconds", _TTL),  # type: ignore[arg-type]
            leader_fence_timeout_seconds=kw.pop("leader_fence_timeout_seconds", _FENCE),  # type: ignore[arg-type]
        )
        built.append(c)
        return c

    try:
        yield make, store
    finally:
        for c in built:
            await c.stop()
        await store.close()


# --- the leadership-lease SQL under genuine two-node contention -------------


async def test_exactly_one_acquires_under_contention(coords) -> None:
    # Two coordinators race the SAME leader_lease row: the atomic INSERT ... ON CONFLICT ... WHERE row
    # lock must let exactly ONE acquire. Drive the maintenance tick directly (no loops) for determinism.
    make, _ = coords
    a, b = make("A"), make("B")
    await a._ensure_nodes_table()  # idempotent; the seed already created it
    await a._maintain_leadership()
    await b._maintain_leadership()
    assert a.is_leader() is True
    assert b.is_leader() is False  # the live lease blocks B
    owner, expires = await a.leadership_lease()
    assert owner == "A"
    assert expires is not None and expires > 0


async def test_standby_cannot_acquire_while_lease_live(coords) -> None:
    # B repeatedly tries to acquire while A's lease is live (real clock_timestamp comparison) — never wins.
    make, _ = coords
    a, b = make("A"), make("B")
    await a._maintain_leadership()
    for _ in range(3):
        await b._maintain_leadership()
        assert b.is_leader() is False
    assert a.is_leader() is True


async def test_clean_release_lets_standby_take_over_immediately(coords) -> None:
    # A clean release expires A's lease row, so B acquires on its very next tick — no wait for the TTL.
    make, _ = coords
    a, b = make("A"), make("B")
    await a._maintain_leadership()
    assert a.is_leader() is True
    await a._release_leadership()
    assert a.is_leader() is False
    await b._maintain_leadership()
    assert b.is_leader() is True
    owner, _expires = await b.leadership_lease()
    assert owner == "B"


async def test_standby_takes_over_after_lease_expires(coords) -> None:
    # A "crashes" (stops renewing) — its lease ages out against the DB clock; after the TTL elapses B
    # acquires, and A, if it ever ran maintenance again, would find B owns a live lease and demote.
    make, _ = coords
    a, b = make("A"), make("B")
    await a._maintain_leadership()
    assert a.is_leader() is True
    await asyncio.sleep(_TTL + 0.4)  # let A's lease expire (A is no longer renewing)
    await b._maintain_leadership()
    assert b.is_leader() is True  # took over the expired lease
    await a._maintain_leadership()  # A runs again much later
    assert a.is_leader() is False  # B owns a live lease now → A demotes


async def test_leadership_lease_reports_none_before_any_lease(coords) -> None:
    # Before anyone acquires, the lease row is absent → leadership_lease() reports (None, None).
    make, _ = coords
    a = make("A")
    owner, expires = await a.leadership_lease()
    assert owner is None and expires is None


# --- full start()/stop() lifecycle electing exactly one leader --------------


async def _await_until(predicate: Callable[[], bool], timeout: float) -> bool:
    """Poll ``predicate`` until True or ``timeout`` (real time); returns whether it became True."""
    deadline = timeout
    step = 0.05
    waited = 0.0
    while waited < deadline:
        if predicate():
            return True
        await asyncio.sleep(step)
        waited += step
    return predicate()


async def test_lifecycle_elects_one_then_fails_over_on_clean_stop(coords) -> None:
    # The real loops: start two coordinators; exactly one becomes leader within a bounded wait. Stop the
    # leader cleanly (expires its lease) → the survivor acquires. Proves start()/stop() + the heartbeat
    # loop's acquire/renew path against a real database, end to end.
    make, _ = coords
    a, b = make("A"), make("B")
    await a.start()
    await b.start()
    # One of them acquires within a few heartbeats.
    assert await _await_until(lambda: a.is_leader() or b.is_leader(), timeout=3.0)
    leader, follower = (a, b) if a.is_leader() else (b, a)
    assert not (a.is_leader() and b.is_leader())  # never both
    # Clean-stop the leader → it expires its lease → the follower acquires on its next tick.
    await leader.stop()
    assert await _await_until(follower.is_leader, timeout=3.0)
    assert follower.is_leader() is True


# --- H6: end-to-end stale-epoch fence after a real two-node handover ---------


async def _clear_data(store: object) -> None:
    """Empty the message/queue data tables so the FIFO claim below starts from a known single head."""
    async with store._pool.acquire() as conn:  # type: ignore[attr-defined]
        rows = await conn.fetch(
            "SELECT tablename FROM pg_tables WHERE schemaname = ANY (current_schemas(false))"
        )
        existing = {r["tablename"] for r in rows}
        targets = [t for t in ("messages", "queue", "outbox", "response") if t in existing]
        if targets:
            await conn.execute(f"TRUNCATE {', '.join(targets)} RESTART IDENTITY CASCADE")


async def test_resumed_ex_leader_is_fenced_after_real_handover(coords) -> None:
    # H6 stale-epoch failover assertion (the half UNBLOCKED by S2/H1), end-to-end against a real DB.
    #
    # The store-level fence tests (tests/test_postgres_store.py) seed the lease epoch BY HAND. This proves
    # the *real coordinator handover* produces the fence: A acquires (epoch 1), A "crashes" (stops
    # renewing), B takes over once the lease expires and the fresh-acquire BUMPS the epoch (→ 2). A then
    # "resumes" past its temporal self-fence — but it still holds its now-stale epoch 1. We push A's held
    # epoch + lease key into the store (exactly as the engine does on promotion) and assert A's FIFO claim
    # is REJECTED (0 rows) — A delivers NOTHING, so no duplicate/out-of-order egress. B (current epoch)
    # then claims the SAME head, proving the lane is intact and only the live leader drains it.
    make, store = coords
    await _clear_data(store)
    a, b = make("A"), make("B")

    # A acquires; capture its held epoch + the lease key it validated against (what the engine pushes down).
    await a._maintain_leadership()
    assert a.is_leader() is True
    a_epoch = a.current_epoch()
    lease_key = a.lease_key()
    assert a_epoch is not None and lease_key is not None

    # A "crashes": let its lease age out against the DB clock, then B takes over and BUMPS the epoch.
    await asyncio.sleep(_TTL + 0.4)
    await b._maintain_leadership()
    assert b.is_leader() is True
    b_epoch = b.current_epoch()
    assert b_epoch is not None and b_epoch > a_epoch  # fresh acquire advanced the fencing token

    # One queued head on a single FIFO lane.
    mid = await store.enqueue_message(  # type: ignore[attr-defined]
        channel_id="IB", raw=_RAW, deliveries=[("OB1", "p")], now=100.0
    )

    # A resumes past its temporal self-fence holding the STALE epoch — the durable fence must reject it.
    store.set_leader_epoch(a_epoch, lease_key=lease_key)  # type: ignore[attr-defined]
    assert await store.claim_next_fifo("OB1", now=200.0) is None  # type: ignore[attr-defined]
    outbox = await store.outbox_for(mid)  # type: ignore[attr-defined]
    assert outbox[0]["status"] == OutboxStatus.PENDING.value  # head untouched — A delivered nothing
    assert outbox[0]["attempts"] == 0  # the rejected claim didn't even bump attempts

    # The current leader (B's epoch) claims the same head: the lane is intact, only the live leader drains.
    store.set_leader_epoch(b_epoch, lease_key=lease_key)  # type: ignore[attr-defined]
    claimed = await store.claim_next_fifo("OB1", now=201.0)  # type: ignore[attr-defined]
    assert claimed is not None and claimed.message_id == mid
    await store.mark_done(claimed.id, now=202.0)  # type: ignore[attr-defined]
