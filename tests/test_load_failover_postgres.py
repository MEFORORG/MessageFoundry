# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Failover UNDER LOAD against a REAL Postgres (Workstream D / Gate #3) — the live kill-the-primary run.

**Gated**: skipped unless ``MEFOR_TEST_POSTGRES`` is set (plus ``MEFOR_STORE_*`` connection env), like
:mod:`tests.test_postgres_store` / :mod:`tests.test_cluster_failover_postgres`. The Postgres
service-container CI job (push to ``main`` / ``workflow_dispatch``) runs it for real; it is a no-op
locally and on PRs without the env. Requires the ``postgres`` extra (``asyncpg``).

What this proves that the lease-only failover unit/integration tests cannot: that under sustained MLLP
load, SIGKILLing the leader leads to the standby promoting, recovering the dead leader's in-flight rows
(the leader lease-reclaim sweep, run once on promotion), and delivering everything the engine had
acknowledged — with bounded duplicates and preserved per-lane FIFO order. See
:mod:`harness.load.failover` and ``docs/CLUSTERING.md``.
"""

from __future__ import annotations

import os

import pytest

from _failover_load_support import assert_failover_ok, failover_test_profile, reserve_failover_ports

from harness.load.failover import run_failover_load

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run the Postgres failover-load test",
)

# The data + cluster tables to clear before the run so a clean pipeline / clean election is guaranteed
# (TRUNCATE ... CASCADE from `messages` clears its `queue` children too).
_RESET_TABLES = (
    "messages",
    "queue",
    "outbox",
    "response",
    "leader_lease",
    "nodes",
    "lane_leases",
    "cluster_config",
)


async def _reset_store() -> None:
    """Truncate the data + cluster tables that exist, so the failover run starts from an empty pipeline."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    store = await PostgresStore.open(settings)
    try:
        async with store._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT tablename FROM pg_tables WHERE schemaname = ANY (current_schemas(false))"
            )
            existing = {r["tablename"] for r in rows}
            targets = [t for t in _RESET_TABLES if t in existing]
            if targets:
                await conn.execute(f"TRUNCATE {', '.join(targets)} RESTART IDENTITY CASCADE")
    finally:
        await store.close()


async def test_failover_load_postgres() -> None:
    await _reset_store()
    report = await run_failover_load(
        failover_test_profile(),
        ports=reserve_failover_ports(),
        db_backend="postgres",
    )
    print("\n" + report.render_console())  # surface the full failover report in the CI log
    assert_failover_ok(report)
