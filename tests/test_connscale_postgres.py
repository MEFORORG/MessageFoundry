# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale smoke against a REAL Postgres store with a small pool (B11 wall #2 coverage).

The SQLite CI smoke (test_connscale_smoke.py) cannot cover wall #2 — the pool-wait wall is a no-op on
SQLite (no pool). This leg forces ``MEFOR_STORE_POOL_SIZE`` BELOW the default (≤4) so the
``perf_counter``-measured acquire-WAIT histogram (the PRIMARY pool-wait signal) is NON-TRIVIAL even at
small N: with ~3N inbound workers contending for a handful of pooled connections, acquires actually
queue, so the acquire-wait percentiles are populated and the pool-wait instrumentation gets real
regression coverage. Gated on ``MEFOR_TEST_POSTGRES`` like the other server-DB suites; the CI
``postgres-store`` leg sets the connection env (and forces the small pool).

NOTE on the pool size: an *extremely* tiny pool (1-2) is too aggressive here. ``GET /status`` runs
``db_status()`` (four sequential ``COUNT(*)``/``pg_database_size`` queries) on every harness poll, and
under the ~3N-worker empty-claim herd those acquires can starve past the poller's per-request HTTP
timeout on a slow/contended CI runner — every poll then fails and the drain/reconcile loops burn the
whole test budget (the original PR #675 hang). A pool of 4 keeps the wall non-trivial (4 ≪ 3N) while
leaving ``/status`` enough acquire slack to answer within the poll timeout.
"""

from __future__ import annotations

import os
import socket

import pytest

from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.runner import run_connscale

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("MEFOR_TEST_POSTGRES") != "1",
        reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_*) to run the Postgres connscale leg",
    ),
    pytest.mark.timeout(300),
]


def _free_port() -> int:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    try:
        return int(s.getsockname()[1])
    finally:
        s.close()


@pytest.mark.flaky(reruns=2, reruns_delay=5)
async def test_connscale_postgres_pool_wait_is_measured() -> None:
    # The CI step forces MEFOR_STORE_POOL_SIZE=4 in base_env; assert a below-default pool is actually
    # in effect so the wall under test is non-trivial (the default pool of 40 would mask the
    # acquire-wait curve). 4 is small enough that ~3N workers still queue on it, but not so small that
    # /status's db_status() COUNT queries starve past the poll timeout (the PR #675 hang — see module
    # docstring).
    pool_size = int(os.environ.get("MEFOR_STORE_POOL_SIZE", "0"))
    assert 1 <= pool_size <= 4, (
        "this leg must force a below-default pool (MEFOR_STORE_POOL_SIZE 1-4) so the acquire-wait "
        f"wall is non-trivial; got {pool_size}"
    )

    profile = load_connscale_profile_text("""
[connscale]
name = "pg-pool-it"
counts = [16, 32]
sweep_mode = "fixed_per_conn"
per_conn_rate = 2.0
aggregate_rate = 64.0
hold_seconds = 2.0
connect_batch = 8
connect_batch_pause_s = 0.0
poll_interval_s = 0.25
drain_timeout_s = 60.0
base_port = 41200
transform = "cheap"
reload_probe = false
store_backend = "postgres"
corpus_count_per_trigger = 5

[connscale.slo]
zero_loss = true
""")

    # Draw the sink port FIRST, then the API base — same safe order as the SQLite smoke. The runner
    # uses ``engine_api_port_base + step`` per sweep step, and back-to-back ephemeral allocations are
    # adjacent (X, X+1); drawing the sink first keeps it BELOW the whole API block, so step 1's API
    # port (api_base+1) can never land on the sink port (the deterministic-on-Windows 10048 collision).
    sink_port = _free_port()
    api_port = _free_port()
    report = await run_connscale(
        profile,  # type: ignore[arg-type]
        engine_api_port_base=api_port,
        sink_host="127.0.0.1",
        sink_port=sink_port,
        sink_ports=1,
        install_executor_shim=True,
    )

    assert len(report.records) == 2
    for r in report.records:
        assert r.no_loss.ok, (r.count, r.no_loss.detail)
        # Wall #2 PRIMARY signal: on a SERVER store the pool snapshot is present (not None as on
        # SQLite), and with a small (≤4) pool under ~3N workers the acquire-wait percentiles +
        # occupancy are populated — the regression coverage SQLite cannot give.
        assert r.pool_wait_p99_ms is not None, r
        assert r.pool_size_max is not None and r.pool_size_max <= 4, r
        assert r.pool_idle_min is not None, r

    assert report.result_ok, [c for c in report.slos if not c.ok]
