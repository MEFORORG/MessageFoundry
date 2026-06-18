# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shared helpers for the container-gated failover-load tests (Postgres + SQL Server).

NOT a test module (the leading underscore keeps pytest from collecting it): it holds the small,
backend-agnostic pieces the two gated tests share — a short synthetic failover profile, free-port
reservation, and the common pass assertions. Each backend test supplies its own pre-run store reset.
"""

from __future__ import annotations

import socket

from harness.load.failover import FailoverPorts, FailoverReport
from harness.load.profile import LoadProfile, load_profile_text

# A SHORT failover profile sized for CI: tuned-short leases (heartbeat < fence < ttl), a modest rate at
# pool_size = 1 (sound per-lane ordering), and a generous drain for a server-DB round-trip per handoff.
# recovery_ttl_multiple is roomy (3×) so ordinary CI scheduling jitter doesn't flake the time bound.
_PROFILE = """
[load]
name = "failover-it"
pool_size = 1
corpus_count_per_trigger = 10
poll_interval_s = 0.3
drain_timeout_s = 60.0
[[load.target]]
name = "adt"
host = "127.0.0.1"
port = 2600
types = ["ADT"]
[load.mix]
"ADT^A01" = 1.0
[load.failover]
kill_at_fraction = 0.4
heartbeat_seconds = 1.5
leader_fence_timeout_seconds = 3.0
leader_lease_ttl_seconds = 5.0
recovery_ttl_multiple = 3.0
max_dup_rate = 0.30
[[load.phase]]
name = "warmup"
kind = "warmup"
loop = "open"
rate_start = 20.0
duration_s = 3.0
[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 40.0
duration_s = 10.0
"""


def failover_test_profile() -> LoadProfile:
    return load_profile_text(_PROFILE, where="<failover-it>")


def reserve_failover_ports() -> FailoverPorts:
    """Reserve 6 free loopback ports (3 inbound hubs + sink + 2 API). Reserve then close, accepting the
    small close→bind window (the engine subprocess binds them moments later) — the same pattern the
    in-process load integration test uses."""
    socks = []
    try:
        for _ in range(6):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        nums = [int(s.getsockname()[1]) for s in socks]
    finally:
        for s in socks:
            s.close()
    adt, results, other, sink, api_a, api_b = nums
    return FailoverPorts(
        inbound_adt=adt,
        inbound_results=results,
        inbound_other=other,
        sink=sink,
        sink_count=1,
        api_a=api_a,
        api_b=api_b,
    )


# The CONFORMANCE-tier SLOs the gated test hard-asserts (host-INDEPENDENT, per the v0.1 two-tier gate,
# Q3): a kill must lose nothing acknowledged, preserve per-lane FIFO, never split-brain, keep duplicates
# bounded, and promote. Per-lane FIFO is a hard gate on BOTH backends: the harness's live ordering check
# found a real SQL Server reorder (READPAST in claim_next_fifo skipping a producer-locked head, #285),
# which is FIXED — so a nonzero inversion is now a genuine regression, not a known backend gap.
#
# NOT gated here (REPORTED only): the functional-recovery *time* depends on the runner's OS/network (a
# killed process's port rebind is near-instant on Linux but can lag tens of seconds on Windows), so the
# gated test asserts only that recovery *occurred*; the published reference-config baseline gates the time.
_CONFORMANCE_SLOS = frozenset(
    {
        "promotion_observed",
        "no_acknowledged_loss",
        "per_lane_ordering",
        "single_leader",
        "max_dup_rate",
    }
)


def assert_failover_ok(report: FailoverReport) -> None:
    """The shared pass bar: a primary was killed, the survivor promoted, recovery occurred, and every
    host-independent CONFORMANCE invariant held (no acknowledged loss, drained pipeline, per-lane FIFO, no
    split-brain, bounded duplicates). Recovery *time* is reported but not gated here (host-dependent)."""
    detail = "\n\n" + report.render_console()
    assert report.killed_node is not None and report.promoted_node is not None, detail
    assert report.promotion_seconds is not None, "no promotion observed" + detail
    assert report.recovery_seconds is not None, "no functional recovery observed" + detail
    assert report.acked_not_delivered == 0, "acknowledged-message loss" + detail
    assert report.in_pipeline_final == 0, "pipeline did not drain" + detail
    assert report.dead_final == 0, "messages were dead-lettered" + detail
    assert report.lane_inversions == 0, "per-lane FIFO violation" + detail
    # The ordering check must be NON-VACUOUS: the failover run fans out to >= 2 destinations, so real
    # per-destination lane keying yields >= 2 lanes. A single lane means MSH-6 collapsed and the FIFO
    # check would certify nothing (the major review finding) — fail loudly rather than pass degenerate.
    assert report.lanes_observed >= 2, "per-lane ordering measurement is vacuous (1 lane)" + detail
    assert report.max_concurrent_leaders == 1, "split-brain (two leaders)" + detail
    assert report.acked > 0, "no load was accepted" + detail
    failed = [s.name for s in report.slos if s.name in _CONFORMANCE_SLOS and not s.ok]
    assert not failed, f"conformance SLOs failed: {failed}" + detail
