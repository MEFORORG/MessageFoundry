# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Claim-mode A/B comparison (ADR 0066) — the per_lane-vs-pooled verdict logic, pure + hermetic."""

from __future__ import annotations

import json

from harness.load.connscale.compare import (
    COLLAPSE_FAIL,
    COLLAPSE_INCONCLUSIVE,
    COLLAPSE_PASS,
    build_comparison,
)
from harness.load.connscale.report import ConnScaleRecord, NoLoss


def _record(
    *,
    claim_mode: str,
    count: int,
    achieved_read: float,
    idle_poll: float,
    sweep_mode: str = "fixed_aggregate",
    no_loss_ok: bool = True,
) -> ConnScaleRecord:
    # A breached arm reconciles fewer at the sink than were sent — the authoritative loss signal,
    # independent of ``achieved_read`` (which the /stats poller zeroes under overload).
    sink = 1000 if no_loss_ok else 900
    detail = "ok" if no_loss_ok else "lost 100 (sink_received 900 < sent 1000)"
    return ConnScaleRecord(
        sweep_mode=sweep_mode,
        count=count,
        offered_aggregate_rate=400.0,
        sent=1000,
        acked=1000,
        nak=0,
        deferred=0,
        no_loss=NoLoss(no_loss_ok, 1000, 1000, sink, sink, 0, detail),
        in_pipeline_peak=3,
        drain_seconds=1.0,
        executor_queue_depth_peak=None,
        executor_busy_peak=None,
        pool_wait_p50_ms=None,
        pool_wait_p95_ms=None,
        pool_wait_p99_ms=None,
        pool_wait_max_ms=None,
        pool_idle_min=None,
        pool_size_max=None,
        empty_claims_per_s=idle_poll,
        idle_poll_per_s=idle_poll,
        wake_fanout_per_s=0.0,
        fd_count_peak=100,
        reload_seconds=None,
        ack_p50_ms=1.0,
        ack_p95_ms=2.0,
        ack_p99_ms=3.0,
        claim_mode=claim_mode,
        achieved_read_per_s=achieved_read,
        achieved_written_per_s=achieved_read,
        cpu_seconds_total=5.0,
        cpu_util_cores_mean=0.5,
    )


def test_single_arm_has_no_comparison() -> None:
    recs = [_record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0)]
    assert build_comparison(recs, ("per_lane",)) is None


def test_collapse_pass_and_throughput_ok() -> None:
    # pooled idle-poll materially lower (0 vs 100) + throughput within tolerance ⇒ overall PASS.
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=399.0, idle_poll=0.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert cmp.ok
    row = cmp.rows[0]
    assert row.collapse_verdict == COLLAPSE_PASS
    assert row.throughput_ok
    assert row.collapse_ratio == 0.0


def test_throughput_regression_fails() -> None:
    # pooled achieved 25% below per_lane (past the 10% tolerance) ⇒ throughput FAIL ⇒ overall FAIL.
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=300.0, idle_poll=0.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert not cmp.ok
    assert not cmp.rows[0].throughput_ok


def test_no_collapse_fails_when_above_floor() -> None:
    # per_lane idle-poll clears the floor but pooled did NOT drop (equal) ⇒ collapse FAIL ⇒ overall FAIL.
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=400.0, idle_poll=100.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert cmp.rows[0].collapse_verdict == COLLAPSE_FAIL
    assert not cmp.ok


def test_collapse_inconclusive_below_floor_does_not_fail() -> None:
    # Both idle-poll rates below the noise floor ⇒ INCONCLUSIVE, and (throughput ok) ⇒ overall PASS.
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=1.0),
        _record(claim_mode="pooled", count=500, achieved_read=400.0, idle_poll=1.5),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert cmp.rows[0].collapse_verdict == COLLAPSE_INCONCLUSIVE
    assert cmp.ok  # an inconclusive collapse never fails the run


def test_missing_pooled_arm_is_reported_loudly() -> None:
    # per_lane ran at N=500 and N=1000; the pooled arm at N=1000 failed to start (RCSI-off gate) and
    # is absent from records. The comparison must detect it structurally and FAIL loudly.
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=399.0, idle_poll=0.0),
        _record(claim_mode="per_lane", count=1000, achieved_read=400.0, idle_poll=200.0),
        # no pooled @ 1000
    ]
    cmp = build_comparison(
        recs,
        ("per_lane", "pooled"),
        missing_detail={("fixed_aggregate", 1000): "RCSI OFF fail-closed gate"},
    )
    assert cmp is not None
    assert cmp.missing_arms == 1
    assert not cmp.ok
    missing_row = next(r for r in cmp.rows if r.count == 1000)
    assert missing_row.pooled_missing
    assert "RCSI OFF" in missing_row.missing_detail
    # It surfaces in both the JSON and the human table.
    body = json.loads(json.dumps(cmp.to_json_dict()))
    assert body["summary"]["missing_arms"] == 1
    assert "POOLED ARM MISSING" in cmp.render_table()


def test_json_and_table_render() -> None:
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=399.0, idle_poll=0.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    body = cmp.to_json_dict()
    assert body["kind"] == "claim_mode_ab"
    assert body["baseline"] == "per_lane" and body["candidate"] == "pooled"
    assert body["overall_ok"] is True
    table = cmp.render_table()
    assert "Claim-mode A/B" in table
    assert "collapse: PASS" in table
    assert "throughput: OK" in table


def _summary(cmp_obj: object) -> dict[str, object]:
    body = cmp_obj.to_json_dict()  # type: ignore[attr-defined]
    return body["summary"]  # type: ignore[index,no-any-return]


def test_candidate_loss_is_a_hard_fail() -> None:
    # The pooled arm looks great on throughput + collapse, but it BREACHED zero-loss (dropped
    # messages). That is a hard fail regardless — pooled must never drop. The old compare (loss-blind)
    # would PASS this; the loss-aware guard fails it.
    recs = [
        _record(claim_mode="per_lane", count=1500, achieved_read=400.0, idle_poll=200.0),
        _record(
            claim_mode="pooled", count=1500, achieved_read=410.0, idle_poll=0.0, no_loss_ok=False
        ),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert not cmp.ok
    row = cmp.rows[0]
    assert row.candidate_lost
    assert not row.ok
    assert cmp.candidate_zero_loss_ok is False
    assert _summary(cmp)["candidate_zero_loss_ok"] is False
    assert "CANDIDATE LOST" in cmp.render_table()


def test_breached_baseline_is_resilience_not_vacuous_throughput_pass() -> None:
    # THE poller-zero artifact: at scale per_lane drowns (breaches zero-loss) and its achieved rate
    # reads a phantom 0.0. pooled holds zero-loss with real throughput. The old compare read
    # throughput_non_regression=True vacuously (pooled 410 >= zeroed 0). The loss-aware compare marks
    # the throughput comparison UNSOUND, reports it as a resilience win, and does NOT claim a pass.
    recs = [
        _record(
            claim_mode="per_lane", count=1500, achieved_read=0.0, idle_poll=0.0, no_loss_ok=False
        ),
        _record(claim_mode="pooled", count=1500, achieved_read=410.0, idle_poll=0.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    row = cmp.rows[0]
    assert not row.throughput_comparable  # the drowning baseline makes the delta unsound
    assert row.resilience_win
    assert row.ok  # pooled held zero-loss ⇒ the row passes on resilience, not on a phantom delta
    assert cmp.ok
    # The verdict is inconclusive (null), NEVER a vacuous True, and the resilience win is surfaced.
    assert cmp.throughput_non_regression is None
    summary = _summary(cmp)
    assert summary["throughput_non_regression"] is None
    assert summary["resilience_wins"] == 1
    assert summary["baseline_zero_loss_breaches"] == 1
    assert summary["candidate_zero_loss_ok"] is True
    assert "RESILIENCE" in cmp.render_table()


def test_all_baselines_breached_yields_null_not_phantom_true() -> None:
    # Every count's per_lane baseline drowned (the Run-1 shape). There is NO sound baseline anywhere,
    # so the aggregate throughput verdict must be null (inconclusive) — the exact phantom-True the
    # follow-up removes — while pooled holding zero-loss keeps the run PASS on resilience.
    recs = [
        _record(
            claim_mode="per_lane", count=1000, achieved_read=0.0, idle_poll=0.0, no_loss_ok=False
        ),
        _record(claim_mode="pooled", count=1000, achieved_read=400.0, idle_poll=0.0),
        _record(
            claim_mode="per_lane", count=1500, achieved_read=0.0, idle_poll=0.0, no_loss_ok=False
        ),
        _record(claim_mode="pooled", count=1500, achieved_read=400.0, idle_poll=0.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert cmp.throughput_non_regression is None
    assert _summary(cmp)["throughput_non_regression"] is None
    assert cmp.resilience_wins == 2
    assert cmp.ok  # pooled held zero-loss at both counts
