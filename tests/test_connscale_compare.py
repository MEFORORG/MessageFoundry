# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Claim-mode A/B comparison (ADR 0066) — the per_lane-vs-pooled verdict logic, pure + hermetic."""

from __future__ import annotations

import dataclasses
import json

from harness.load.connscale.compare import (
    COLLAPSE_FAIL,
    COLLAPSE_INCONCLUSIVE,
    COLLAPSE_PASS,
    build_comparison,
)
from harness.load.connscale.report import ConnScaleRecord, NoLoss, SandboxReading


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
        empty_claims_per_msg=None,
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
    return body["summary"]


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


def _timed_out(rec: ConnScaleRecord) -> ConnScaleRecord:
    return dataclasses.replace(rec, drain_seconds=None)


def test_a_lossy_earlier_trial_fails_the_cell_bug_5429() -> None:
    # Two trials per arm; the pooled arm's FIRST trial lost messages and the last held. Keeping only the
    # last trial per cell used to pass this A/B.
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(
            claim_mode="pooled", count=500, achieved_read=399.0, idle_poll=0.0, no_loss_ok=False
        ),
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=399.0, idle_poll=0.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert not cmp.ok
    (row,) = cmp.rows
    assert row.candidate_lost
    assert row.candidate is not None
    assert row.candidate.trials == 2
    assert "trial 0: lost 100" in row.candidate.no_loss_detail


def test_a_timed_out_candidate_trial_fails_the_cell_bug_5429() -> None:
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _timed_out(_record(claim_mode="pooled", count=500, achieved_read=399.0, idle_poll=0.0)),
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=399.0, idle_poll=0.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert not cmp.ok
    (row,) = cmp.rows
    assert row.candidate is not None
    assert not row.candidate.drain_completed
    # A timed-out drain is not reported as a lost message: the reconcile held.
    assert row.candidate.no_loss_ok
    assert not row.candidate_lost
    assert "CANDIDATE UNDRAINED" in cmp.render_table()
    rows = cmp.to_json_dict()["rows"]
    assert isinstance(rows, list)
    assert rows[0]["drain_completed"] == {"per_lane": True, "pooled": False}
    assert rows[0]["trials"] == {"per_lane": 2, "pooled": 2}


def test_a_timed_out_baseline_drain_keeps_the_throughput_guard_bug_5429() -> None:
    # per_lane's drain timed out but its reconcile held; pooled regressed to a quarter of the rate. The
    # throughput comparison must stay sound and fail the row, not pass as a resilience win.
    recs = [
        _timed_out(_record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0)),
        _record(claim_mode="pooled", count=500, achieved_read=100.0, idle_poll=0.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert not cmp.ok
    assert cmp.rows[0].throughput_comparable
    assert not cmp.rows[0].throughput_ok
    assert cmp.resilience_wins == 0


def test_an_orphan_candidate_cell_fails_the_ab_bug_5429() -> None:
    # A pooled cell at N=1000 with no per_lane baseline has no row, so it used to be skipped silently.
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=399.0, idle_poll=0.0),
        _record(
            claim_mode="pooled", count=1000, achieved_read=10.0, idle_poll=0.0, no_loss_ok=False
        ),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert not cmp.ok
    assert cmp.orphan_candidate_cells == [("fixed_aggregate", 1000)]
    summary = cmp.to_json_dict()["summary"]
    assert isinstance(summary, dict)
    assert summary["orphan_candidate_cells"] == [{"sweep_mode": "fixed_aggregate", "count": 1000}]
    assert any("NO per_lane baseline" in n for n in cmp.notes)
    assert "NO per_lane BASELINE (the A/B fails): [fixed_aggregate] N=1000" in cmp.render_table()


def test_one_lossy_baseline_trial_keeps_the_throughput_guard_bug_5429() -> None:
    # per_lane drowned in trial 0 only; pooled held zero-loss at a quarter of the rate on every trial.
    # The regression must still fail against the clean per_lane trials, not pass as a resilience win.
    recs = [
        _record(
            claim_mode="per_lane", count=500, achieved_read=0.0, idle_poll=100.0, no_loss_ok=False
        ),
        _record(claim_mode="pooled", count=500, achieved_read=100.0, idle_poll=0.0),
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=100.0, idle_poll=0.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    (row,) = cmp.rows
    assert row.baseline.clean_read_per_s == 400.0
    assert row.throughput_comparable
    assert not row.throughput_ok
    assert not cmp.ok


def test_an_undrained_pooled_arm_is_not_a_resilience_win_bug_5429() -> None:
    recs = [
        _record(
            claim_mode="per_lane", count=500, achieved_read=0.0, idle_poll=100.0, no_loss_ok=False
        ),
        _timed_out(_record(claim_mode="pooled", count=500, achieved_read=399.0, idle_poll=0.0)),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert not cmp.ok
    assert cmp.resilience_wins == 0


def test_trials_aggregate_to_the_mean_rate_bug_5429() -> None:
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=390.0, idle_poll=0.0),
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=410.0, idle_poll=0.0),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert cmp.ok
    assert cmp.rows[0].candidate is not None
    assert cmp.rows[0].candidate.achieved_read_per_s == 400.0
    assert cmp.rows[0].candidate.sent == 2000


def test_an_inconclusive_baseline_is_no_resilience_win_and_fails_the_row() -> None:
    # BACKLOG #5574: a per_lane arm that cleared nothing is neither a breach nor a measurement, so
    # it cannot make the row pass on the resilience basis, which skips the throughput guard. The
    # control is the same baseline as a proven breach, which still reads as a resilience win.
    from dataclasses import replace as _replace

    breached = _record(
        claim_mode="per_lane", count=10, achieved_read=0.0, idle_poll=1.0, no_loss_ok=False
    )
    pooled = _record(claim_mode="pooled", count=10, achieved_read=100.0, idle_poll=0.0)
    cmp = build_comparison([breached, pooled], ("per_lane", "pooled"))
    assert cmp is not None and len(cmp.rows) == 1
    assert cmp.rows[0].resilience_win and cmp.rows[0].ok
    unsure = _replace(breached, no_loss=_replace(breached.no_loss, inconclusive=True))
    cmp = build_comparison([unsure, pooled], ("per_lane", "pooled"))
    assert cmp is not None and len(cmp.rows) == 1
    assert not cmp.rows[0].resilience_win
    assert not cmp.rows[0].ok
    loss = cmp.to_json_dict()["rows"][0]["loss"]  # type: ignore[index]
    assert loss["per_lane_zero_loss_inconclusive"] is True
    assert loss["pooled_zero_loss_inconclusive"] is False
    # The summary counts the row it fails, beside the breaches it does not count.
    summary = cmp.to_json_dict()["summary"]
    assert isinstance(summary, dict)
    assert summary["baseline_inconclusive"] == 1
    assert summary["baseline_zero_loss_breaches"] == 0
    assert "baseline_inconclusive=1" in cmp.render_table()


def test_a_baseline_inconclusive_trial_fails_the_row_whatever_the_other_trials_proved() -> None:
    # BACKLOG #5574: the fold must be monotone. A baseline of [LOSS, INCONCLUSIVE] used to pass as
    # a resilience win while [OK, INCONCLUSIVE] failed, so a proven breach in one trial lifted the
    # INCONCLUSIVE trial's fail. Both fail now. The control is [LOSS, LOSS], the "per_lane drowns"
    # case, which stays a resilience win.
    from dataclasses import replace as _replace

    from harness.load.connscale.compare import _loss_label

    breached = _record(
        claim_mode="per_lane", count=10, achieved_read=0.0, idle_poll=1.0, no_loss_ok=False
    )
    clean = _record(claim_mode="per_lane", count=10, achieved_read=100.0, idle_poll=1.0)
    unsure = _replace(breached, no_loss=_replace(breached.no_loss, inconclusive=True), trial=1)
    pooled = [
        _replace(
            _record(claim_mode="pooled", count=10, achieved_read=100.0, idle_poll=0.0), trial=t
        )
        for t in (0, 1)
    ]
    for first in (breached, clean):
        cmp = build_comparison([first, unsure, *pooled], ("per_lane", "pooled"))
        assert cmp is not None and len(cmp.rows) == 1
        (row,) = cmp.rows
        assert row.baseline.trials == 2 and row.baseline.inconclusive_trials == 1
        # No throughput comparison rests on it either, so the summary does not fold it in.
        assert not row.throughput_comparable and cmp.throughput_non_regression is None
        assert not row.resilience_win and not row.ok and not cmp.ok, first.no_loss.detail
        assert _loss_label(row).startswith("BASELINE INCONCLUSIVE -- 1 of 2 per_lane trial(s)")
        assert cmp.baseline_inconclusive == 1
        loss = cmp.to_json_dict()["rows"][0]["loss"]  # type: ignore[index]
        assert loss["per_lane_inconclusive_trials"] == 1
    # A proven breach still counts as one beside the INCONCLUSIVE trial, and the label names it so
    # it does not read as if per_lane lost nothing; it just cannot pass the row.
    cmp = build_comparison([breached, unsure, *pooled], ("per_lane", "pooled"))
    assert cmp is not None and cmp.baseline_zero_loss_breaches == 1
    assert "another per_lane trial proved a breach" in _loss_label(cmp.rows[0])
    cmp = build_comparison([clean, unsure, *pooled], ("per_lane", "pooled"))
    assert cmp is not None and "another per_lane trial" not in _loss_label(cmp.rows[0])
    drowned = _replace(breached, trial=1)
    cmp = build_comparison([breached, drowned, *pooled], ("per_lane", "pooled"))
    assert cmp is not None and len(cmp.rows) == 1
    assert cmp.rows[0].resilience_win and cmp.rows[0].ok and cmp.ok


def test_an_inconclusive_arm_is_labelled_inconclusive_not_a_breach() -> None:
    from dataclasses import replace as _replace

    from harness.load.connscale.compare import _loss_label

    base = _record(claim_mode="per_lane", count=10, achieved_read=100.0, idle_poll=1.0)
    pooled = _record(claim_mode="pooled", count=10, achieved_read=100.0, idle_poll=0.0)
    unsure_base = _replace(base, no_loss=_replace(base.no_loss, ok=False, inconclusive=True))
    cmp = build_comparison([unsure_base, pooled], ("per_lane", "pooled"))
    assert cmp is not None and len(cmp.rows) == 1
    assert _loss_label(cmp.rows[0]).startswith("BASELINE INCONCLUSIVE")
    assert cmp.baseline_zero_loss_breaches == 0
    unsure_pooled = _replace(pooled, no_loss=_replace(pooled.no_loss, ok=False, inconclusive=True))
    cmp = build_comparison([base, unsure_pooled], ("per_lane", "pooled"))
    assert cmp is not None and len(cmp.rows) == 1
    assert not cmp.rows[0].ok
    assert _loss_label(cmp.rows[0]).startswith("CANDIDATE INCONCLUSIVE")


_SUBPROCESS = SandboxReading(requested="subprocess", effective="subprocess", startup_seconds=1.0)


def test_the_ab_table_names_its_sandbox_arm_bug_5090() -> None:
    # `--report-compare` writes this table; it named no sandbox arm, so a subprocess-arm A/B read
    # the same as an in-process one.
    recs = [
        dataclasses.replace(
            _record(claim_mode=mode, count=500, achieved_read=400.0, idle_poll=idle),
            sandbox=_SUBPROCESS,
        )
        for mode, idle in (("per_lane", 100.0), ("pooled", 0.0))
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert cmp.ok
    assert cmp.sandbox_arms == ("subprocess",)
    assert "\nsandbox: subprocess\n" in cmp.render_table()
    assert cmp.to_json_dict()["sandbox_arms"] == ["subprocess"]


def test_records_from_two_sandbox_arms_fail_the_ab_rather_than_pool_bug_5090() -> None:
    # No cell is keyed on the sandbox arm, so two arms' records would pool into one cell. A profile
    # cannot produce this (a sandbox A/B composes with no other), so the comparison refuses it.
    recs = [
        _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
        _record(claim_mode="pooled", count=500, achieved_read=400.0, idle_poll=0.0),
        dataclasses.replace(
            _record(claim_mode="per_lane", count=500, achieved_read=400.0, idle_poll=100.0),
            sandbox=_SUBPROCESS,
        ),
    ]
    cmp = build_comparison(recs, ("per_lane", "pooled"))
    assert cmp is not None
    assert all(row.ok for row in cmp.rows)  # the control: only the mixture fails it
    assert not cmp.ok
    assert cmp.sandbox_arms == ("off", "subprocess")
    assert "SANDBOX ARMS MIXED (off, subprocess) -> the A/B FAILS" in cmp.render_table()
    assert any("[sandbox] arms" in n for n in cmp.notes)
