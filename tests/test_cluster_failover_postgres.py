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
