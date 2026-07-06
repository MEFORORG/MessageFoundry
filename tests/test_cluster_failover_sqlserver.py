# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Active-passive leadership failover against a REAL SQL Server (Phase 4, SQL Server parity).

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env), like
:mod:`tests.test_sqlserver_store`. The CI mssql service-container job runs it for real; it is a no-op
locally and on PRs without the env. Requires the ``sqlserver`` extra (``aioodbc`` + ODBC Driver 18).

The SQL Server sibling of :mod:`tests.test_cluster_failover_postgres`: it validates the real
``leader_lease`` T-SQL against a real database clock that the always-run unit tests cannot — the atomic
``MERGE leader_lease WITH (HOLDLOCK) ... WHEN MATCHED AND (owner = me OR expired)`` acquire/renew and the
``leadership_lease`` read — plus genuine two-node contention, **takeover after a real TTL elapses against
the DB clock**, clean release, and the full ``start()``/``stop()`` lifecycle electing exactly one leader
and failing over on a clean stop. (Failover in-flight *row* recovery — the on-promotion
``reset_stale_inflight`` — is covered as an engine unit test in ``tests/test_cluster_graph_gating.py``.)
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable

import pytest

from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator
from messagefoundry.store import OutboxStatus

_RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server failover tests",
)

# Short, test-only lease timings (heartbeat < fence < ttl still holds): a real TTL elapses in ~1s so the
# takeover test doesn't sleep long, while staying well above scheduling jitter.
_TTL = 1.0
_FENCE = 0.6
_HEARTBEAT = 0.3

_CLUSTER_TABLES = ("leader_lease", "nodes", "cluster_config")


@pytest.fixture
async def coords() -> AsyncIterator[tuple[Callable[..., SqlServerCoordinator], object]]:
    """Open a real SQL Server store, (re)create the cluster tables empty, and yield a factory building
    SqlServerCoordinators that SHARE that store (so they contend on the same ``leader_lease`` row, as
    real nodes would). Each built coordinator is stopped on teardown."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    store = await SqlServerStore.open(settings)
    # Start each test from empty cluster tables: drop, then let a seed coordinator recreate them (the
    # direct-tick tests call _maintain_leadership, which assumes the tables already exist).
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in _CLUSTER_TABLES:
            await cur.execute(f"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DROP TABLE {table}")
        await conn.commit()
    await SqlServerCoordinator(store, "seed")._ensure_tables()

    built: list[SqlServerCoordinator] = []

    def make(node_id: str, **kw: object) -> SqlServerCoordinator:
        c = SqlServerCoordinator(
            store,
            node_id,
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


# --- the leadership-lease T-SQL under genuine two-node contention -----------


async def test_exactly_one_acquires_under_contention(coords) -> None:
    # Two coordinators race the SAME leader_lease row: MERGE WITH(HOLDLOCK) must let exactly ONE acquire.
    make, _ = coords
    a, b = make("A"), make("B")
    await a._maintain_leadership()
    await b._maintain_leadership()
    assert a.is_leader() is True
    assert b.is_leader() is False  # the live lease blocks B
    owner, expires = await a.leadership_lease()
    assert owner == "A"
    assert expires is not None and expires > 0


async def test_standby_cannot_acquire_while_lease_live(coords) -> None:
    # B repeatedly tries while A's lease is live (real DB-clock comparison) — never wins.
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
    # acquires, and A, if it runs maintenance again, finds B owns a live lease and demotes.
    make, _ = coords
    a, b = make("A"), make("B")
    await a._maintain_leadership()
    assert a.is_leader() is True
    await asyncio.sleep(
        _TTL + 0.4
    )  # let A's lease expire against SYSUTCDATETIME() (A no longer renews)
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
    step = 0.05
    waited = 0.0
    while waited < timeout:
        if predicate():
            return True
        await asyncio.sleep(step)
        waited += step
    return predicate()


async def test_lifecycle_elects_one_then_fails_over_on_clean_stop(coords) -> None:
    # The real loops (the "2-node failover" capstone): start two coordinators; exactly one becomes leader
    # within a bounded wait. Clean-stop the leader (expires its lease) → the survivor acquires. Proves
    # start()/stop() + the heartbeat loop's acquire/renew path against a real SQL Server, end to end.
    make, _ = coords
    a, b = make("A"), make("B")
    await a.start()
    await b.start()
    assert await _await_until(lambda: a.is_leader() or b.is_leader(), timeout=3.0)
    leader, follower = (a, b) if a.is_leader() else (b, a)
    assert not (a.is_leader() and b.is_leader())  # never both
    await leader.stop()  # clean stop expires the lease → the follower acquires on its next tick
    assert await _await_until(follower.is_leader, timeout=3.0)
    assert follower.is_leader() is True


# --- H6: end-to-end stale-epoch fence after a real two-node handover ---------


async def _clear_data(store: object) -> None:
    """Empty the message/queue data tables (FK order) so the FIFO claim starts from a known single head."""
    async with store._pool.acquire() as conn:  # type: ignore[attr-defined]
        cur = await conn.cursor()
        for table in ("queue", "response", "outbox", "messages"):
            await cur.execute(f"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DELETE FROM {table}")
        await conn.commit()


async def test_resumed_ex_leader_is_fenced_after_real_handover(coords) -> None:
    # H6 stale-epoch failover assertion (the half UNBLOCKED by S2/H1), end-to-end against a real SQL Server.
    #
    # The store-level fence tests (tests/test_sqlserver_store.py) seed the lease epoch BY HAND. This proves
    # the *real coordinator handover* produces the fence: A acquires (epoch 1), A "crashes" (stops
    # renewing), B takes over once the lease expires and the fresh acquire BUMPS the epoch (→ 2). A then
    # "resumes" past its temporal self-fence still holding its now-stale epoch 1. We push A's held epoch +
    # lease key into the store (exactly as the engine does on promotion) and assert A's FIFO claim is
    # REJECTED (0 rows) — A delivers NOTHING, so no duplicate/out-of-order egress. B (current epoch) then
    # claims the SAME head, proving the lane is intact and only the live leader drains it.
    make, store = coords
    await _clear_data(store)
    a, b = make("A"), make("B")

    await a._maintain_leadership()
    assert a.is_leader() is True
    a_epoch = a.current_epoch()
    lease_key = a.lease_key()
    assert a_epoch is not None and lease_key is not None

    await asyncio.sleep(_TTL + 0.4)  # A "crashes": its lease ages out against SYSUTCDATETIME()
    await b._maintain_leadership()
    assert b.is_leader() is True
    b_epoch = b.current_epoch()
    assert b_epoch is not None and b_epoch > a_epoch  # fresh acquire advanced the fencing token

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
