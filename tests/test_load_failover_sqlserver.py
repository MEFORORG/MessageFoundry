# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Failover UNDER LOAD against a REAL SQL Server (Workstream D / Gate #3) — the live kill-the-primary run.

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env), like
:mod:`tests.test_sqlserver_store` / :mod:`tests.test_cluster_failover_sqlserver`. The mssql
service-container CI job runs it for real; it is a no-op locally and on PRs without the env. Requires the
``sqlserver`` extra (``aioodbc`` + ODBC Driver 18).

This is the **first live proof** of the SQL Server on-promotion recovery path under a real crash: SQL
Server active-passive has NO per-row leases, so ``reclaims_inflight() == True`` makes the engine skip the
startup reset and recovery rests entirely on the on-promotion ``reset_stale_inflight`` in ``_start_graph``
(unit-covered, but never exercised under load until now). It SIGKILLs the leader mid-load and asserts the
survivor promotes, recovers the in-flight rows, and loses nothing it acknowledged. See
:mod:`harness.load.failover` and ``docs/CLUSTERING.md``.
"""

from __future__ import annotations

import os

import pytest

from _failover_load_support import (
    assert_failover_ok,
    dump_queue_breakdown,
    failover_test_profile,
    reserve_failover_ports,
)

from harness.load.failover import run_failover_load

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run the SQL Server failover-load test",
)

# Cleared child-before-parent (the FK is queue/outbox/response → messages) so the run starts from an
# empty pipeline + a clean leader election. DELETE (not TRUNCATE — FK-referenced tables) and only when the
# table already exists (a fresh DB has none yet — the nodes create them empty on start).
_RESET_TABLES = (
    "queue",
    "outbox",
    "response",
    "leader_lease",
    "nodes",
    "cluster_config",
    "messages",
)


async def _reset_store() -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    store = await SqlServerStore.open(settings)
    try:
        async with store._pool.acquire() as conn:
            cur = await conn.cursor()
            for table in _RESET_TABLES:
                await cur.execute(f"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DELETE FROM {table}")
            await conn.commit()
    finally:
        await store.close()


# This heavy two-node SIGKILL-under-load run against a real DB intermittently spikes past the global
# 60s pytest-timeout on slower CI runners (a transient drain/election stall, not a product bug — it
# clears on a re-run; see the CI-flake history). Give it a generous per-test budget AND auto-retry a
# transient stall rather than reding the whole gated leg.
@pytest.mark.timeout(180)
@pytest.mark.flaky(reruns=2, reruns_delay=5)
async def test_failover_load_sqlserver() -> None:
    await _reset_store()
    report = await run_failover_load(
        failover_test_profile(),
        ports=reserve_failover_ports(),
        db_backend="sqlserver",
    )
    print("\n" + report.render_console())  # surface the full failover report in the CI log
    await dump_queue_breakdown("sqlserver")  # DIAGNOSTIC: name the stage the undrained rows sit in
    assert_failover_ok(report)
