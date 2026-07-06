# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SQL Server active-passive coordinator behaviour — against a real SQL Server.

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` (+ ``MEFOR_STORE_*`` connection env) is set, exactly
like ``tests/test_sqlserver_store.py``. The CI mssql service-container job runs it for real. Covers
leader election (acquire / renew / take-over / no-take-over-while-live = the split-brain guard), the
self-fence watchdog, clean-stop release, membership-derived leadership, the config-version token, and the
``leadership_lease`` observability read.
"""

from __future__ import annotations

import asyncio
import os
from typing import AsyncIterator

import pytest

from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)

_CLUSTER_TABLES = ("leader_lease", "nodes", "cluster_config")


@pytest.fixture
async def store() -> AsyncIterator[object]:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    # Each test starts from no cluster tables (the coordinator's _ensure_tables recreates them).
    async with s._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in _CLUSTER_TABLES:
            await cur.execute(f"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DROP TABLE {table}")
        await conn.commit()
    yield s
    await s.close()


def _coord(store: object, node: str, **kw: object) -> SqlServerCoordinator:
    return SqlServerCoordinator(store, node, **kw)  # type: ignore[arg-type]


async def test_acquire_then_renew_keeps_leadership(store) -> None:
    c = _coord(store, "nodeA:1:aaaa")
    await c._ensure_tables()
    await c._register()
    assert await c._claim_or_renew_lease() is True  # fresh acquire
    await c._maintain_leadership()
    assert c.is_leader() is True
    assert await c._claim_or_renew_lease() is True  # renew (we already own it)
    assert c.is_leader() is True
    owner, expires = await c.leadership_lease()
    assert owner == "nodeA:1:aaaa" and expires is not None


async def test_second_node_cannot_take_a_live_lease(store) -> None:
    # The split-brain guard: while A's lease is live, B must NOT be able to acquire.
    a = _coord(store, "nodeA:1:aaaa")
    await a._ensure_tables()
    await a._register()
    await a._maintain_leadership()
    assert a.is_leader() is True

    b = _coord(store, "nodeB:2:bbbb")
    await b._register()
    assert await b._claim_or_renew_lease() is False
    await b._maintain_leadership()
    assert b.is_leader() is False
    owner, _ = await b.leadership_lease()
    assert owner == "nodeA:1:aaaa"  # A still holds it


async def test_standby_takes_over_an_expired_lease(store) -> None:
    a = _coord(store, "nodeA:1:aaaa")
    await a._ensure_tables()
    await a._register()
    await a._maintain_leadership()
    assert a.is_leader() is True

    # Simulate A going dark: force its lease expired (epoch 0 < DB now) without waiting out a TTL.
    await store._execute(  # type: ignore[attr-defined]
        "UPDATE leader_lease SET lease_expires_at = 0 WHERE lease_key = ?", (a._lease_key,)
    )
    b = _coord(store, "nodeB:2:bbbb")
    await b._register()
    assert await b._claim_or_renew_lease() is True  # expired → B takes over
    await b._maintain_leadership()
    assert b.is_leader() is True
    owner, _ = await b.leadership_lease()
    assert owner == "nodeB:2:bbbb"


async def test_clean_stop_releases_lease_for_immediate_takeover(store) -> None:
    a = _coord(store, "nodeA:1:aaaa")
    await a._ensure_tables()
    await a._register()
    await a._maintain_leadership()
    assert a.is_leader() is True
    await a.stop()  # expires the lease row
    assert a.is_leader() is False

    b = _coord(store, "nodeB:2:bbbb")
    await b._register()
    assert await b._claim_or_renew_lease() is True  # no TTL wait — A released
    assert (await b.leadership_lease())[0] == "nodeB:2:bbbb"


async def test_self_fence_demotes_on_stalled_renew(store) -> None:
    # A leader whose renew stalls past the fence timeout (its OWN monotonic clock) demotes itself before
    # the lease can expire — no DB I/O. Drive a controllable monotonic clock.
    clock = {"t": 1000.0}
    c = _coord(
        store,
        "nodeA:1:aaaa",
        leader_fence_timeout_seconds=5.0,
        monotonic=lambda: clock["t"],
    )
    await c._ensure_tables()
    await c._register()
    await c._maintain_leadership()
    assert c.is_leader() is True  # _last_renew_ok stamped at t=1000

    clock["t"] = 1004.0  # within the fence window
    c._check_fence()
    assert c.is_leader() is True
    clock["t"] = 1006.0  # past the 5s fence timeout
    c._check_fence()
    assert c.is_leader() is False


async def test_cluster_members_reports_single_live_leader(store) -> None:
    a = _coord(store, "nodeA:1:aaaa")
    await a._ensure_tables()
    await a._register()
    await a._maintain_leadership()
    await a.heartbeat_once()  # fold the is_leader flag into the nodes row

    b = _coord(store, "nodeB:2:bbbb")
    await b._register()
    await b.heartbeat_once()

    members = await a.cluster_members()
    by_id = {m.node_id: m for m in members}
    assert set(by_id) == {"nodeA:1:aaaa", "nodeB:2:bbbb"}
    assert by_id["nodeA:1:aaaa"].is_leader is True
    assert by_id["nodeB:2:bbbb"].is_leader is False


async def test_concurrent_acquire_exactly_one_wins(store) -> None:
    # True contention on a FRESH lease: distinct nodes race _claim_or_renew_lease at once. MERGE
    # WITH(HOLDLOCK) must serialize the key range so exactly one acquires and the rest see a live
    # lease owned by another (no PK violation / 1205 deadlock escapes). The sequential
    # no-take-over test covers the ordered case; this is the concurrent split-brain guard.
    coords = [_coord(store, f"node{i}:{i}:{i:04x}") for i in range(4)]
    await coords[0]._ensure_tables()
    for c in coords:
        await c._register()
    results = await asyncio.gather(*[c._claim_or_renew_lease() for c in coords])
    assert sum(1 for r in results if r) == 1


async def test_config_version_seed_and_bump(store) -> None:
    c = _coord(store, "nodeA:1:aaaa")
    await c._ensure_tables()
    assert await c.config_version() == 0
    assert c.config_version_cached() == 0
    assert await c.bump_config_version() == 1
    assert c.config_version_cached() == 1
    assert await c.bump_config_version() == 2
    # A fresh reader sees the bumped value.
    other = _coord(store, "nodeB:2:bbbb")
    assert await other.config_version() == 2
