# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Always-run unit tests for the failover-load harness — the PURE pieces, no live engines.

The full two-node SIGKILL run is container-gated (``tests/test_load_failover_{postgres,sqlserver}.py``);
these cover the parts that don't need a server DB: ``[load.failover]`` parsing, the
:class:`~harness.load.failover_track.FailoverTracker` reconciliation/ordering, phase splitting, the
per-node env, and the report builder's SLO verdicts under synthetic inputs.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from harness.load.failover import (
    FailoverError,
    FailoverPorts,
    NodeStats,
    _build_report,
    _KillOutcome,
    _node_env,
    _split_phases,
)
from harness.load.failover_track import FailoverTracker
from harness.load.metrics import Counters
from harness.load.profile import LoadProfileError, load_profile_text

# --- a minimal failover profile for the parsing/report tests -----------------

_PROFILE_TMPL = """
[load]
name = "fo-unit"
pool_size = 1
[[load.target]]
name = "adt"
port = 2600
types = ["ADT"]
[load.mix]
"ADT^A01" = 1.0
{failover}
[[load.phase]]
name = "warmup"
kind = "warmup"
loop = "open"
rate_start = 10.0
duration_s = 1.0
[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 20.0
duration_s = 2.0
"""

_FAILOVER_OK = """
[load.failover]
kill_at_fraction = 0.5
heartbeat_seconds = 2.0
leader_fence_timeout_seconds = 4.0
leader_lease_ttl_seconds = 6.0
recovery_ttl_multiple = 2.0
max_dup_rate = 0.1
"""


def _profile(failover: str = _FAILOVER_OK):
    return load_profile_text(_PROFILE_TMPL.format(failover=failover), where="<test>")


# --- profile parsing ---------------------------------------------------------


def test_failover_table_parses() -> None:
    fo = _profile().failover
    assert fo is not None
    assert fo.kill_at_fraction == 0.5
    assert fo.leader_lease_ttl_seconds == 6.0
    assert fo.max_dup_rate == 0.1


def test_failover_defaults_when_table_minimal() -> None:
    fo = _profile("[load.failover]\nkill_at_fraction = 0.3\n").failover
    assert fo is not None
    assert fo.kill_at_fraction == 0.3
    assert fo.heartbeat_seconds == 2.0  # default
    assert fo.leader_lease_ttl_seconds == 6.0  # default
    assert fo.recovery_ttl_multiple == 2.0  # default
    assert fo.max_promotion_seconds is None


def test_absent_failover_table_is_none() -> None:
    # A profile with NO [load.failover] parses byte-identically (the field defaults to None).
    assert _profile(failover="").failover is None


def test_failover_rejects_bad_lease_ordering() -> None:
    bad = "[load.failover]\nheartbeat_seconds = 5.0\nleader_fence_timeout_seconds = 4.0\n"
    with pytest.raises(LoadProfileError, match="heartbeat_seconds < leader_fence"):
        _profile(bad)


def test_failover_rejects_kill_fraction_at_bounds() -> None:
    with pytest.raises(LoadProfileError, match="kill_at_fraction"):
        _profile("[load.failover]\nkill_at_fraction = 0.0\n")
    with pytest.raises(LoadProfileError, match="kill_at_fraction"):
        _profile("[load.failover]\nkill_at_fraction = 1.0\n")


def test_failover_rejects_unknown_key() -> None:
    with pytest.raises(LoadProfileError, match="unknown key"):
        _profile("[load.failover]\nbogus = 1\n")


# --- FailoverTracker ---------------------------------------------------------


def test_tracker_acked_subset_delivered_is_no_loss() -> None:
    t = FailoverTracker()
    for seq in range(5):
        t.on_ack(seq)
    for seq in range(5):
        t.on_delivery("d0", seq)
    assert t.acked_count == 5
    assert t.delivered_count == 5
    assert t.acked_not_delivered() == 0
    assert t.acked_all_delivered is True


def test_tracker_detects_acknowledged_loss() -> None:
    t = FailoverTracker()
    for seq in range(5):
        t.on_ack(seq)
    for seq in (0, 1, 2, 4):  # 3 acked but never delivered
        t.on_delivery("d0", seq)
    assert t.acked_not_delivered() == 1
    assert t.acked_all_delivered is False


def test_tracker_intake_gap_is_not_loss() -> None:
    # A sent-but-un-ACKed message (the kill window) is never recorded as acked, so it can't count as
    # acknowledged loss even though it never arrives.
    t = FailoverTracker()
    t.on_ack(0)
    t.on_ack(1)
    t.on_delivery("d0", 0)
    t.on_delivery("d0", 1)
    # seq 2 was sent but never acked (and never delivered) — not loss.
    assert t.acked_not_delivered() == 0


def test_tracker_ordering_monotonic_ok() -> None:
    t = FailoverTracker()
    for seq in (0, 3, 5, 9):  # a monotonic subsequence on one lane (destination)
        t.on_delivery("d0", seq)
    assert t.lane_inversions == 0


def test_tracker_ordering_inversion_detected() -> None:
    t = FailoverTracker()
    for seq in (0, 5, 3):  # 3 is a NEW seq arriving below the lane's high-water (5) → a FIFO break
        t.on_delivery("d0", seq)
    assert t.lane_inversions == 1


def test_tracker_redelivery_is_repeat_not_inversion() -> None:
    # An at-least-once re-delivery is an ALREADY-SEEN seq arriving again on the lane — a duplicate,
    # never an ordering violation (the crash-recovery path re-delivers in-flight rows).
    t = FailoverTracker()
    t.on_delivery("d0", 3)
    t.on_delivery("d0", 5)
    t.on_delivery("d0", 3)  # re-delivery of an already-seen seq → a repeat, not an inversion
    assert t.lane_repeats == 1
    assert t.lane_inversions == 0


def test_tracker_per_lane_independence() -> None:
    # Two destinations are independent lanes: a low seq on one is not "out of order" vs a high seq on
    # the other (fan-out delivers every seq to every destination).
    t = FailoverTracker()
    t.on_delivery("d0", 5)
    t.on_delivery("d1", 3)
    assert t.lane_inversions == 0


# --- phase splitting ---------------------------------------------------------


def test_split_phases_warmup_then_measured() -> None:
    prefix, measured = _split_phases(_profile())
    assert [p.name for p in prefix] == ["warmup"]
    assert measured.name == "sustained"


def test_split_phases_rejects_two_measured() -> None:
    two = (
        _PROFILE_TMPL.format(failover=_FAILOVER_OK)
        + """
[[load.phase]]
name = "soak"
kind = "soak"
loop = "open"
rate_start = 20.0
duration_s = 2.0
"""
    )
    with pytest.raises(FailoverError, match="exactly one measured"):
        _split_phases(load_profile_text(two, where="<t>"))


def test_split_phases_rejects_measured_not_last() -> None:
    text = """
[load]
name = "x"
[[load.target]]
name = "a"
port = 2600
types = ["ADT"]
[load.mix]
"ADT^A01" = 1.0
[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 20.0
duration_s = 2.0
[[load.phase]]
name = "cooldown"
kind = "ramp"
loop = "open"
rate_start = 5.0
duration_s = 1.0
"""
    with pytest.raises(FailoverError, match="must be the LAST phase"):
        _split_phases(load_profile_text(text, where="<t>"))


# --- per-node env ------------------------------------------------------------


def test_node_env_configures_cluster_and_forces_pool() -> None:
    fo = _profile().failover
    assert fo is not None
    ports = FailoverPorts(2600, 2601, 2602, 2700, 1, 8801, 8802)
    env = _node_env(
        {"MEFOR_STORE_POOL_SIZE": "1", "PATH": "/x"},
        node_id="fo-a",
        ports=ports,
        fo=fo,
        sink_host="127.0.0.1",
    )
    assert env["MEFOR_CLUSTER_ENABLED"] == "true"
    assert env["MEFOR_CLUSTER_NODE_ID"] == "fo-a"
    assert env["MEFOR_AUTH_ENABLED"] == "false"
    assert int(env["MEFOR_STORE_POOL_SIZE"]) >= 5  # forced up from the inherited 1
    assert env["MEFOR_LOAD_ADT_PORT"] == "2600"
    assert env["MEFOR_LOAD_SINK_PORT"] == "2700"
    assert env["PATH"] == "/x"  # inherited env is preserved
    # The lease timings are passed through so both nodes agree on the (short) timing.
    assert float(env["MEFOR_CLUSTER_LEADER_LEASE_TTL_SECONDS"]) == 6.0


# --- report builder ----------------------------------------------------------


def _outcome(promotion: float | None = 2.0, recovery: float | None = 7.0, leaders: int = 1):
    return _KillOutcome(
        killed=SimpleNamespace(node_id="fo-a"),  # type: ignore[arg-type]
        survivor=SimpleNamespace(node_id="fo-b"),  # type: ignore[arg-type]
        promotion_seconds=promotion,
        recovery_seconds=recovery,
        max_concurrent_leaders=leaders,
    )


def _counters(*, sent=100, acked=98, sink_received=300) -> Counters:
    return Counters(sent=sent, acked=acked, sink_received=sink_received, timeouts=sent - acked)


def _report(*, tracker: FailoverTracker, outcome=None, final=None, counters=None):
    fo = _profile().failover
    assert fo is not None
    return _build_report(
        _profile(),
        "postgres",
        counters or _counters(),
        tracker,
        outcome or _outcome(),
        final or NodeStats(done=294, dead=0, pending=0, inflight=0, in_pipeline=0),
        done_at_start=0,
        fo=fo,
        notes=[],
    )


def _full_tracker(n: int = 98) -> FailoverTracker:
    t = FailoverTracker()
    for seq in range(n):
        t.on_ack(seq)
        t.on_delivery("d0", seq)  # in-order on one lane → no inversions
    return t


def test_build_report_pass() -> None:
    rep = _report(tracker=_full_tracker())
    assert rep.result_ok is True
    assert rep.exit_code == 0
    assert rep.acked_not_delivered == 0
    assert rep.recovery_seconds == 7.0
    assert rep.intake_gap == 2  # sent 100 − acked 98
    assert all(s.ok for s in rep.slos)


def test_build_report_fails_on_acknowledged_loss() -> None:
    t = FailoverTracker()
    for seq in range(98):
        t.on_ack(seq)
    for seq in range(90):  # 8 acked never delivered
        t.on_delivery("d0", seq)
    rep = _report(tracker=t)
    assert rep.acked_not_delivered == 8
    assert rep.result_ok is False
    assert any(s.name == "no_acknowledged_loss" and not s.ok for s in rep.slos)


def test_build_report_fails_when_pipeline_not_drained() -> None:
    rep = _report(
        tracker=_full_tracker(),
        final=NodeStats(done=294, dead=0, pending=3, inflight=1, in_pipeline=4),
    )
    assert rep.result_ok is False
    assert any(s.name == "no_acknowledged_loss" and not s.ok for s in rep.slos)


def test_build_report_fails_on_recovery_timeout() -> None:
    rep = _report(tracker=_full_tracker(), outcome=_outcome(promotion=None, recovery=None))
    assert rep.result_ok is False
    assert any(s.name == "functional_recovery_seconds" and not s.ok for s in rep.slos)
    assert any(s.name == "promotion_observed" and not s.ok for s in rep.slos)


def test_build_report_fails_on_slow_recovery() -> None:
    # TTL 6 × multiple 2 = 12s bound; 15s recovery must fail.
    rep = _report(tracker=_full_tracker(), outcome=_outcome(recovery=15.0))
    assert rep.result_ok is False
    assert any(s.name == "functional_recovery_seconds" and not s.ok for s in rep.slos)


def test_build_report_fails_on_excess_duplicates() -> None:
    # engine_delivered = done 294; sink_received 600 → 306 dups → rate ~1.04 >> 0.1 cap.
    rep = _report(tracker=_full_tracker(), counters=_counters(sink_received=600))
    assert rep.duplicates == 306
    assert rep.result_ok is False
    assert any(s.name == "max_dup_rate" and not s.ok for s in rep.slos)


def test_build_report_fails_on_ordering_inversion() -> None:
    # Everything acked is delivered (no loss), but one NEW seq arrives below the lane's high-water →
    # a genuine per-lane FIFO break that must fail the conformance SLO.
    t = FailoverTracker()
    for seq in range(98):
        t.on_ack(seq)
    for seq in [
        *range(96),
        97,
        96,
    ]:  # 96 arrives AFTER 97 on lane d0 → inversion; all 0..97 delivered
        t.on_delivery("d0", seq)
    assert t.acked_not_delivered() == 0
    rep = _report(tracker=t)
    assert rep.lane_inversions == 1
    assert rep.result_ok is False
    assert any(s.name == "per_lane_ordering" and not s.ok for s in rep.slos)


def test_build_report_flags_split_brain() -> None:
    rep = _report(tracker=_full_tracker(), outcome=_outcome(leaders=2))
    assert rep.result_ok is False
    assert any(s.name == "single_leader" and not s.ok for s in rep.slos)


def test_report_json_and_console_smoke() -> None:
    rep = _report(tracker=_full_tracker())
    js = rep.to_json_dict()
    assert js["kind"] == "failover"
    assert js["result"] == "PASS"
    assert js["failover"]["recovery_seconds"] == 7.0
    text = rep.render_console()
    assert "Failover-load report" in text
    assert "RESULT: PASS" in text
