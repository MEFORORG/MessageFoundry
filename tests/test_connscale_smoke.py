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

import sys
from collections.abc import Sequence

import pytest

from harness.load.connscale.probe import ProbeDegraded
from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.report import ConnScaleRecord
from harness.load.connscale.runner import run_connscale
from tests._connscale_ports import (
    INBOUND_PORT_HI,
    INBOUND_PORT_LO,
    require_contiguous,
    reserve_api_and_sink_bases,
    reserve_contiguous_ports,
)

pytestmark = pytest.mark.timeout(120)  # the per-test 60s default is too tight for two engine spawns

# The connection-count sweep; its max sets the contiguous inbound-port width (BACKLOG #1014).
_SMOKE_COUNTS = (12, 24)

# The three port families this run consumes -- inbound, API and sink -- are all reserved as whole
# contiguous ranges by tests/_connscale_ports.py, which is where the windows and the rationale for
# them live (BACKLOG #1014 for the inbound family, #1103 for the other two).


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


def _is_budget_exhausted(cause: str) -> bool:
    """Is this recorded cause one where the probe SPENT its whole timeout budget?

    Delegates to the probe's own :class:`ProbeDegraded` rather than listing members here, so the
    tolerable set cannot drift member-by-member away from the definition. An UNRECOGNISED cause is
    treated as not-tolerable: a new degrade path must be classified deliberately, and defaulting the
    unknown to "tolerate" is how a fresh probe defect would arrive already excused."""
    try:
        return ProbeDegraded(cause).is_budget_exhausted
    except ValueError:
        return False


def _assert_fd_probe(records: Sequence[ConnScaleRecord]) -> None:
    """Assert wall #4 to the strength the OS probe's contract actually supports — no more, no less.

    This used to be a bare ``assert r.fd_count_peak is not None and r.fd_count_peak > 0, r`` inside the
    loop above, with no tolerance for a probe that honestly could not measure. ``fd_count_peak`` is
    ``None`` on every one of the probe's degrade paths, and only some of them implicate anything under
    test — so a starved runner whose process-table walk timed out reddened a REQUIRED context as though
    the ENGINE were at fault, and did it with a message that named no mechanism. The record now carries
    the cause, so this can state a verdict instead of a value check.

    The tolerable/not line is the probe's own (``ProbeDegraded.is_budget_exhausted``), NOT a second
    vocabulary invented here. It is the same line ``tests/test_connscale_cpu_probe.py`` draws from the
    seconds a failed walk actually spent: budget exhausted is COULD NOT MEASURE, anything faster is
    MEASURED AND BROKEN.

    Four properties, and none is weaker than the old assertion wherever the probe worked:

    1. Where the probe READ, the count must be positive — the wall exists. Unchanged.
    2. Where it did not, the record must NAME a cause. An unattributable gap FAILS. A tolerance that
       swallowed it would buy a green by destroying the only evidence of what went wrong, which is the
       failure mode this whole change exists to remove.
    3. A cause that is not budget-exhausted FAILS — a walk that returned zero rows, a failed
       enumeration, a snapshot with no root row, a per-PID read that ran and parsed nothing. A broken
       probe must not hide behind the tolerance written for a slow one.
    4. A budget-exhausted cause is tolerated PER RECORD but not for the run: at least one step must have
       measured, so a probe that never works anywhere still cannot pass. That is the same bound
       assertion (5) below already places on the reload probe."""
    for r in records:
        if r.fd_count_peak is not None:
            assert r.fd_count_peak > 0, r
            continue
        causes = tuple(r.fd_probe_degraded)
        scope = f"{r.fd_probe_degraded_ticks} of {r.fd_probe_ticks} probe tick(s) degraded"
        assert causes, (
            f"UNATTRIBUTED GAP -- wall #4 read nothing at {r.sweep_mode}@N={r.count} and the record "
            f"names no cause ({scope}). A gap that cannot say which probe path produced it is not "
            f"evidence about the engine in either direction, and is deliberately NOT tolerated: "
            f"tolerating it is what made one starved runner and one broken enumerator the same "
            f"artifact. Record: {r}"
        )
        broken = tuple(c for c in causes if not _is_budget_exhausted(c))
        assert not broken, (
            f"PROBE DEFECT -- wall #4 read nothing at {r.sweep_mode}@N={r.count} because {broken} "
            f"({scope}; all causes {causes}). None of those is an exhausted timeout budget: the probe "
            f"RAN and produced nothing usable, which is a defect in the probe itself and is reported "
            f"as a failure rather than downgraded to a tolerated gap. Record: {r}"
        )
    # Every step degraded, and (given the loop above) every cause was an exhausted budget. Each such
    # step alone measures the RUNNER rather than this tree, but a run in which the FD probe never once
    # read is not evidence that wall #4 exists -- so the tolerance stops here instead of buying a green
    # over zero measurements.
    detail = "; ".join(
        f"{r.sweep_mode}@N={r.count} {r.fd_probe_degraded_ticks}/{r.fd_probe_ticks} "
        f"{tuple(r.fd_probe_degraded)}"
        for r in records
    )
    assert any(r.fd_count_peak is not None for r in records), (
        f"WALL #4 UNMEASURED -- all {len(records)} step(s) degraded on an exhausted probe budget "
        f"[{detail}]. Any single step timing out is tolerated; a whole run measuring wall #4 zero "
        f"times is not, because nothing here then covers it."
    )


async def test_connscale_smoke_end_to_end() -> None:
    # Reserve a contiguous inbound-port block (BACKLOG #1014). The sweep's max connection count
    # needs that many contiguous inbound ports, and the engine binds base_port + i for each. A
    # RANDOM anchor de-correlates concurrent worktrees so they no longer contend for one fixed
    # block; contiguity is asserted at the acquisition site, and the allocator fails loudly if no
    # free block can be found (never a silent fixed fallback).
    inbound_ports = reserve_contiguous_ports(
        max(_SMOKE_COUNTS), lo=INBOUND_PORT_LO, hi=INBOUND_PORT_HI
    )
    base_port = require_contiguous(inbound_ports, max(_SMOKE_COUNTS), "inbound")
    profile = _smoke_profile(base_port)

    # ... and reserve the API and sink RANGES the same way (BACKLOG #1103). Both are derived by
    # increment from their base -- the runner binds api_port + step for EVERY sweep step, the sink
    # binds sink_port + i for every sink port -- so reserving only the base, as this test used to,
    # left every port after the first merely assumed free. Two CI reds came of that assumption, on
    # PRs that could not reach this code at all. All three families now come from disjoint windows
    # below the OS ephemeral floors, so the kernel cannot hand one out after it is probed.
    api_port, sink_port = reserve_api_and_sink_bases(profile, sink_ports=1)  # type: ignore[arg-type]

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
        # Wall #3 is separated, never summed into one number; both halves are non-negative.
        assert r.idle_poll_per_s >= 0.0 and r.wake_fanout_per_s >= 0.0

    # (4b) Wall #4 (FD), asserted only as far as this test is ENTITLED to. See _assert_fd_probe.
    _assert_fd_probe(report.records)

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


# The port-allocator's own guards (contiguity, fail-loud exhaustion, the too-narrow window, and
# #1103's "every port the sweep will use was reserved") live in tests/test_connscale_ports.py,
# beside the allocator they cover.
