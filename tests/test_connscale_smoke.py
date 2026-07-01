# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale CI smoke (B11) — a fast, hermetic end-to-end run on SQLite.

The harness OWNS a fresh engine subprocess per sweep step (EngineNode), serving ``harness/config/
connscale`` with ``MEFOR_CONNSCALE_COUNT`` env-set, and drives a tiny connection-count sweep. It
proves the harness SPINS N connections, NO-LOSS reconcile holds, the FD + empty-claim counters move
MONOTONICALLY with N (the wall exists and scales), the additive engine fields are present (back-compat
shim works), and the executor boot-shim populates wall #1 / the reload probe returns a finite number.

It does NOT regression-cover wall #1 (executor) or wall #2 (pool) as REAL curves: at small N on
SQLite the pool wall is a documented no-op and the executor is under-threshold — stated honestly here.
The Postgres CI leg (pool_size forced to 1-2) gives the acquire-wait wall real small-N coverage.

A small N (12 → 24) keeps it inside the pytest-timeout budget; the shipped ``connscale-smoke`` profile
(N=50/100), run via the ``--connscale`` CLI in CI, is the larger-N variant.
"""

from __future__ import annotations

import socket
import sys

import pytest

from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.runner import run_connscale

pytestmark = pytest.mark.timeout(120)  # the per-test 60s default is too tight for two engine spawns


def _free_port() -> int:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    try:
        return int(s.getsockname()[1])
    finally:
        s.close()


def _smoke_profile(base_port: int) -> object:
    # Small N (12 → 24) + short holds so the smoke fits the pytest budget; both sweep modes by default.
    return load_connscale_profile_text(f"""
[connscale]
name = "smoke-it"
counts = [12, 24]
sweep_mode = "both"
aggregate_rate = 24.0
per_conn_rate = 1.0
hold_seconds = 1.5
connect_batch = 8
connect_batch_pause_s = 0.0
poll_interval_s = 0.25
drain_timeout_s = 30.0
base_port = {base_port}
transform = "cheap"
reload_probe = true
store_backend = "sqlite"
corpus_count_per_trigger = 5

[connscale.slo]
zero_loss = true
fd_monotonic = true
empty_claims_monotonic = true
""")


@pytest.mark.flaky(
    reruns=2, reruns_delay=3
)  # CI runners are noisy (mf-ci-test-flakes): re-run clears
async def test_connscale_smoke_end_to_end() -> None:
    # Reserve a base inbound-port block that won't collide with the sink/API ports. The 24-conn max
    # sweep needs 24 contiguous inbound ports; pick a high base well clear of the ephemeral churn.
    base_port = 41000
    sink_port = _free_port()
    api_port = _free_port()
    profile = _smoke_profile(base_port)

    report = await run_connscale(
        profile,  # type: ignore[arg-type]
        engine_api_port_base=api_port,
        sink_host="127.0.0.1",
        sink_port=sink_port,
        sink_ports=1,
        install_executor_shim=True,
    )

    # (1) A record per (sweep_mode, N): both modes × {12, 24} = 4 rows.
    assert len(report.records) == 4
    modes = {(r.sweep_mode, r.count) for r in report.records}
    assert modes == {
        ("fixed_aggregate", 12),
        ("fixed_aggregate", 24),
        ("fixed_per_conn", 12),
        ("fixed_per_conn", 24),
    }

    # (2) No-loss at each N (sent == engine_read, engine_written == sink_received, backlog drained).
    for r in report.records:
        assert r.sent > 0, r
        assert r.no_loss.ok, (r.sweep_mode, r.count, r.no_loss.detail)

    # (3) Curve monotonicity smoke (a LOOSE >= per mode; CI runners are noisy): FD count + empty-claims
    # at N=24 >= N=12. Asserted via the report's monotonicity SLOs.
    slo_by_name = {c.name: c for c in report.slos}
    assert slo_by_name["fd_count_monotonic"].ok, slo_by_name["fd_count_monotonic"].observed
    assert slo_by_name["empty_claims_monotonic"].ok, slo_by_name["empty_claims_monotonic"].observed

    # (4) The additive engine fields are present + non-None where the shim/probe ran (back-compat
    # works): the executor boot-shim populates wall #1, and the FD probe reads the engine PID.
    assert report.shim_installed
    for r in report.records:
        assert r.executor_queue_depth_peak is not None, r  # the shim installed the default executor
        assert r.executor_busy_peak is not None, r
        assert r.fd_count_peak is not None and r.fd_count_peak > 0, r
        # Wall #3 is separated, never summed into one number; both halves are non-negative.
        assert r.idle_poll_per_s >= 0.0 and r.wake_fanout_per_s >= 0.0

    # (5) The reload-latency probe returns a finite number at each step (wall #5).
    for r in report.records:
        assert r.reload_seconds is not None and r.reload_seconds >= 0.0, r

    # (6) Wall #2 (pool) is a documented no-op on SQLite — recorded as absent (None), not a fake 0.
    for r in report.records:
        assert r.pool_wait_p99_ms is None, r
        assert r.pool_idle_min is None, r

    assert report.result_ok and report.exit_code == 0


@pytest.mark.skipif(sys.platform != "win32" and sys.platform != "linux", reason="OS FD probe path")
def test_fd_sampler_reads_self() -> None:
    # The FD sampler reads a live PID (this test process) — a positive handle/fd count — and returns
    # None for a definitely-dead PID, never raising.
    import os

    from harness.load.connscale.probe import FdSampler

    live = FdSampler(os.getpid()).sample()
    assert live is None or live > 0  # None only if the OS tool is unavailable on this runner
    dead = FdSampler(2**31 - 1).sample()  # an implausible PID
    assert dead is None
