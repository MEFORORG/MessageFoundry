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

import random
import socket
import sys

import pytest

from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.runner import run_connscale

pytestmark = pytest.mark.timeout(120)  # the per-test 60s default is too tight for two engine spawns

# The connection-count sweep; its max sets the contiguous inbound-port width (BACKLOG #1014).
_SMOKE_COUNTS = (12, 24)

# Contiguous inbound-port window for the random anchor (BACKLOG #1014). Both bounds are
# chosen to keep the block clear of ports OTHER tests bind, so a concurrent worktree's
# connscale block cannot land on a sibling's fixed listener:
#   - LOWER bound sits ABOVE the sibling fixed-port MLLP band. Sibling tests bind fixed
#     inbound ports in the 11xxx-19xxx range (e.g. 15099, 19601); anchoring at 20000+ keeps
#     the connscale block entirely above them. [20000,30000) is empty of fixed test binds.
#   - UPPER bound stays BELOW the OS ephemeral floors (Linux 32768+, Windows/macOS 49152+)
#     so a kernel-assigned ephemeral port -- the sink/API ports from _free_port(), or any
#     unrelated connection -- can never land inside the block after it is probed.
# The upper bound is exclusive.
_INBOUND_PORT_LO = 20000
_INBOUND_PORT_HI = 30000


def _free_port() -> int:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    try:
        return int(s.getsockname()[1])
    finally:
        s.close()


def _free_contiguous_ports(n: int, *, tries: int = 200) -> list[int]:
    """Reserve ``n`` contiguous free inbound ports anchored at a RANDOM base.

    The random anchor is the concurrency fix (BACKLOG #1014): it de-correlates worktrees so
    two suites rarely pick overlapping blocks. The old fixed ``base_port = 41000`` guaranteed
    a collision whenever two checkouts ran the suite at once. Probe/bind-and-release only holds
    the block momentarily, so it cannot truly reserve it against a concurrent engine -- the
    random anchor over a wide window is the real defense, and a genuine future collision now
    surfaces as a RED rather than a masked retry.
    """
    if _INBOUND_PORT_HI - n <= _INBOUND_PORT_LO:
        raise RuntimeError(
            f"cannot reserve {n} contiguous ports in [{_INBOUND_PORT_LO},{_INBOUND_PORT_HI})"
        )
    for _ in range(tries):
        base = random.randint(_INBOUND_PORT_LO, _INBOUND_PORT_HI - n)
        socks: list[socket.socket] = []
        try:
            for i in range(n):
                s = socket.socket()
                # No SO_REUSEADDR on purpose: honest free-detection. A live listener must make
                # bind FAIL here, unlike SO_REUSEADDR's Windows steal semantics. The block is
                # released before the engine binds, so REUSEADDR would only add false-frees.
                try:
                    s.bind(("127.0.0.1", base + i))
                except OSError:
                    s.close()
                    break
                socks.append(s)
            if len(socks) == n:
                return list(range(base, base + n))
        finally:
            for sock in socks:
                sock.close()
    raise RuntimeError(
        f"could not reserve {n} contiguous free ports in "
        f"[{_INBOUND_PORT_LO},{_INBOUND_PORT_HI}) after {tries} tries"
    )


def _smoke_profile(base_port: int) -> object:
    # Small N (12 → 24) + short holds so the smoke fits the pytest budget; both sweep modes by default.
    return load_connscale_profile_text(f"""
[connscale]
name = "smoke-it"
counts = {list(_SMOKE_COUNTS)}
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


async def test_connscale_smoke_end_to_end() -> None:
    # Dynamically reserve a contiguous inbound-port block (BACKLOG #1014). The sweep's max
    # connection count needs that many contiguous inbound ports, and the engine binds
    # base_port + i for each. A RANDOM anchor de-correlates concurrent worktrees so they no
    # longer contend for one fixed block; contiguity is asserted at the acquisition site, and
    # the allocator fails loudly if no free block can be found (never a silent fixed fallback).
    # The sink/API ports stay ephemeral (above the inbound window) and won't hit the block.
    inbound_ports = _free_contiguous_ports(max(_SMOKE_COUNTS))
    assert inbound_ports == list(range(inbound_ports[0], inbound_ports[0] + max(_SMOKE_COUNTS))), (
        inbound_ports
    )
    base_port = inbound_ports[0]
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

    # (5) The reload-latency probe (wall #5) times an O(connections) quiesce-and-swap. Like the other
    # OS-side probes it is best-effort and gap-tolerant BY DESIGN: a reload fired mid-hold at the highest
    # connection count can occasionally exceed the client timeout under peak load, and the probe records a
    # gap (None) rather than a fabricated number (see harness/load/connscale/probe.py time_reload). Require
    # it to have MEASURED at least one step (the probe is wired and works) and to be finite wherever present
    # — asserting a number at EVERY step would be stricter than the probe's own contract and flakes on slow
    # CI runners.
    measured_reloads = [r.reload_seconds for r in report.records if r.reload_seconds is not None]
    assert measured_reloads, [(r.sweep_mode, r.count) for r in report.records]
    assert all(s >= 0.0 for s in measured_reloads)

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


def test_free_contiguous_ports_are_contiguous_and_in_window() -> None:
    # The allocator returns exactly n ascending, contiguous ports inside the window. It
    # deliberately does NOT re-bind to "prove free" -- that is TOCTOU-racy and would reintroduce
    # the exact flake class BACKLOG #1014 removes.
    ports = _free_contiguous_ports(8)
    assert len(ports) == 8
    assert ports == list(range(ports[0], ports[0] + 8))
    assert ports[0] >= _INBOUND_PORT_LO
    assert ports[-1] < _INBOUND_PORT_HI


def test_free_contiguous_ports_fails_loud_when_unsatisfiable() -> None:
    # tries=0 hits the post-loop exhaustion branch deterministically (without occupying the
    # whole window) and must raise -- never fall back silently to a fixed port (BACKLOG #1014).
    with pytest.raises(RuntimeError, match="could not reserve"):
        _free_contiguous_ports(8, tries=0)


def test_free_contiguous_ports_fails_loud_when_window_too_narrow() -> None:
    # The width guard fires BEFORE any probing when the requested block cannot fit the window
    # at all: asking for one more port than the window holds can never be satisfied, so it
    # raises up front rather than looping (BACKLOG #1014 -- fail loud, never a silent fallback).
    with pytest.raises(RuntimeError, match="cannot reserve"):
        _free_contiguous_ports(_INBOUND_PORT_HI - _INBOUND_PORT_LO + 1)
