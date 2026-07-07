# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Replay of the COMMITTED 2026-07-06 ADR 0071 B5 `fuse_ab` SQL-Server bench artifact through the
fusion A/B comparator — the regression guard for the ``in_pipeline`` verdict fix (ADR 0071 §10 item 8).

The bench's raw per-trial ``records`` are reconstructed from the committed JSON and re-run through the
(now fixed) :func:`build_fuse_comparison`. This proves the fix against REAL data, from the fields
already in the artifact (drain time + the reconcile's residual backlog), with NO new recorded metric —
so the historical artifact replays unchanged.

The defect it locks down: the old guard gated on ``in_pipeline_peak``, the /stats-POLLER-sampled gauge,
which under-samples under overload. At N=1024 the poller read a spuriously low B0 peak (max 9316 across
trials — one trial as low as 1369) against a steady B1 ~21k and fired a FALSE "in_pipeline grew" NO-GO
*reason*, even though B1 actually DRAINED FASTER (~143 s vs ~158 s). The corrected guard reads the
authoritative sink/drain signal and passes N=1024's in_pipeline clause. The run's OVERALL verdict stays
NO-GO (N=256 +6.45 % and N=512 +9.27 % still fail the >=10 % lift bar) and the zero-loss reconcile is
untouched.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harness.load.connscale.compare import FUSE_GO, FUSE_NO_GO, build_fuse_comparison
from harness.load.connscale.report import ConnScaleRecord, NoLoss

_FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "benchmarks"
    / "results"
    / "2026-07-06-adr0071-b5-throughput"
    / "fuse_ab.json"
)


def _record_from_json(d: dict[str, Any]) -> ConnScaleRecord:
    """Faithfully reconstruct a :class:`ConnScaleRecord` from one committed ``records[*]`` dict (the
    inverse of :meth:`ConnScaleRecord.to_json_dict`), so the replay feeds the comparator the SAME
    per-trial inputs the live bench did."""
    achieved = d["achieved"]
    cpu = d["cpu"]
    traffic = d["traffic"]
    nl = d["no_loss"]
    w1 = d["wall1_executor"]
    w2 = d["wall2_pool_wait"]
    w3 = d["wall3_empty_claims"]
    w6 = d["wall6_ack_ms"]
    return ConnScaleRecord(
        sweep_mode=d["sweep_mode"],
        count=d["count"],
        offered_aggregate_rate=d["offered_aggregate_rate"],
        sent=traffic["sent"],
        acked=traffic["acked"],
        nak=traffic["nak"],
        deferred=traffic["deferred"],
        timeouts=traffic["timeouts"],
        no_loss=NoLoss(
            nl["ok"],
            nl["sent"],
            nl["engine_read"],
            nl["engine_written"],
            nl["sink_received"],
            nl["backlog"],
            nl["detail"],
        ),
        in_pipeline_peak=traffic["in_pipeline_peak"],
        drain_seconds=traffic["drain_seconds"],
        executor_queue_depth_peak=w1["queue_depth_peak"],
        executor_busy_peak=w1["busy_peak"],
        pool_wait_p50_ms=w2["p50_ms"],
        pool_wait_p95_ms=w2["p95_ms"],
        pool_wait_p99_ms=w2["p99_ms"],
        pool_wait_max_ms=w2["max_ms"],
        pool_idle_min=w2["idle_min"],
        pool_size_max=w2["size_max"],
        empty_claims_per_s=w3["total_per_s"],
        idle_poll_per_s=w3["idle_poll_per_s"],
        wake_fanout_per_s=w3["wake_fanout_per_s"],
        fd_count_peak=d["wall4_fd"]["count_peak"],
        reload_seconds=d["wall5_reload"]["seconds"],
        ack_p50_ms=w6["p50"],
        ack_p95_ms=w6["p95"],
        ack_p99_ms=w6["p99"],
        claim_mode=d["claim_mode"],
        achieved_read_per_s=achieved["read_per_s"],
        achieved_written_per_s=achieved["written_per_s"],
        cpu_seconds_total=cpu["seconds_total"],
        cpu_util_cores_peak=cpu["util_cores_peak"],
        cpu_util_cores_mean=cpu["util_cores_mean"],
        working_set_peak_bytes=d["working_set"]["peak_bytes"],
        fuse_thread_hops=d["fuse_thread_hops"],
    )


def _load() -> tuple[dict[str, Any], list[ConnScaleRecord]]:
    body = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    records = [_record_from_json(r) for r in body["records"]]
    return body, records


def test_fixture_is_the_expected_shape() -> None:
    # Guard the replay's premise: the committed artifact is the 3-trial B0/B1 pooled SQL-Server sweep
    # over N in {256, 512, 1024} it claims to be. If this drifts, the assertions below are meaningless.
    body, records = _load()
    assert body["profile"] == "fuse_ab"
    assert body["db_backend"] == "sqlserver"
    assert len(records) == 18  # 2 arms x 3 counts x 3 trials
    counts = {(r.fuse_thread_hops, r.count) for r in records}
    assert counts == {(f, n) for f in (False, True) for n in (256, 512, 1024)}


def _rows_by_count(records: list[ConnScaleRecord]) -> dict[int, Any]:
    cmp = build_fuse_comparison(records, (False, True))
    assert cmp is not None
    return {row.count: row for row in cmp.rows}


def test_n1024_old_poller_clause_would_misfire_but_new_drain_guard_passes() -> None:
    # (a) + (b): the exact §10-item-8 defect + fix, against the real N=1024 cell.
    _body, records = _load()
    rows = _rows_by_count(records)
    row = rows[1024]
    assert row.candidate is not None

    # (a) The OLD clause gated on the poller in_pipeline peak; recomputing it here it MIS-FIRES: B1's
    # sampled peak (21969) dwarfs B0's spuriously-low sampled peak (9316), so it reads "grew".
    old_clause = row.candidate.in_pipeline_peak <= (row.baseline.in_pipeline_peak * 1.05 + 1.0)
    assert row.baseline.in_pipeline_peak == 9316
    assert row.candidate.in_pipeline_peak == 21969
    assert not old_clause

    # (b) The NEW guard reads the authoritative whole-pipeline drain signal: both arms' drains COMPLETED
    # (await_drain saw in_pipeline reach 0) and B1 drained FASTER (lower worst drain time) — so its
    # in_pipeline clause PASSES.
    assert row.baseline.drain_completed and row.candidate.drain_completed
    assert (
        row.candidate.drain_seconds_worst is not None
        and row.baseline.drain_seconds_worst is not None
    )
    assert row.candidate.drain_seconds_worst < row.baseline.drain_seconds_worst
    assert row.in_pipeline_ok


def test_overall_stays_no_go_but_reasons_are_corrected() -> None:
    # (c): the verdict is unchanged (NO-GO) but the misleading in_pipeline reasons are gone. N=1024 is
    # now a marginal artifact-corrected GO (+10.0 %); the conjunctive gate can't be rescued by it because
    # N=256 (+6.45 %) and N=512 (+9.27 %) still fail the >=10 % lift bar.
    _body, records = _load()
    cmp = build_fuse_comparison(records, (False, True))
    assert cmp is not None
    rows = {row.count: row for row in cmp.rows}

    # N=256: no longer a false "in_pipeline grew"; NO-GO on the lift clause.
    assert rows[256].in_pipeline_ok
    assert rows[256].verdict == FUSE_NO_GO
    assert rows[256].lift_pct is not None and 6.0 < rows[256].lift_pct < 7.0
    assert "lift" in rows[256].reason and "< 10%" in rows[256].reason
    assert "in_pipeline" not in rows[256].reason

    # N=512: NO-GO on the lift clause (was already so — reason unchanged).
    assert rows[512].in_pipeline_ok
    assert rows[512].verdict == FUSE_NO_GO
    assert rows[512].lift_pct is not None and 9.0 < rows[512].lift_pct < 10.0

    # N=1024: the artifact-corrected marginal GO (>=10 %, significant, drains flat-or-faster).
    assert rows[1024].in_pipeline_ok
    assert rows[1024].verdict == FUSE_GO
    assert rows[1024].lift_pct is not None and rows[1024].lift_pct >= 10.0
    assert rows[1024].significant

    # ...yet the conjunctive overall gate stays NO-GO (any NO-GO cell forces it).
    assert cmp.overall_verdict == FUSE_NO_GO
    assert cmp.no_go_cells == 2 and cmp.go_cells == 1

    # The committed artifact (produced by the OLD comparator) recorded the misleading N=1024 reason and
    # in_pipeline_ok=false — this is exactly what the fix corrects.
    stored = {r["count"]: r for r in _body_rows()}
    assert stored[1024]["guards"]["in_pipeline_ok"] is False
    assert "in_pipeline grew" in stored[1024]["reason"]


def _body_rows() -> list[dict[str, Any]]:
    body, _ = _load()
    rows: list[dict[str, Any]] = body["fuse_comparison"]["rows"]
    return rows


def test_zero_loss_reconcile_output_is_unchanged() -> None:
    # (d): the fix touches ONLY the in_pipeline guard — the at-least-once reconcile is byte-identical in
    # behavior. Anchor on the reconcile identity (sink_received == sent) + drain for every B1 arm, and on
    # the run staying green (candidate held zero-loss; the correctness fold passes).
    _body, records = _load()
    cmp = build_fuse_comparison(records, (False, True))
    assert cmp is not None

    for r in records:
        if r.fuse_thread_hops:  # every B1 (candidate) trial reconciled cleanly and drained
            assert r.no_loss.ok
            assert r.no_loss.backlog == 0
            assert r.no_loss.sink_received == r.no_loss.sent  # the reconcile identity holds exactly

    for row in cmp.rows:
        assert row.candidate is not None
        assert row.candidate.zero_loss_ok
        assert not row.candidate_lost
        assert row.candidate.drain_completed  # every B1 arm's whole-pipeline drain completed
        assert row.delivered_offered_ok  # B1 delivered/offered == 1.0 >= 0.98 (kept up end-to-end)

    assert cmp.candidate_zero_loss_ok  # the hard guard held
    assert cmp.ok  # correctness fold green: a NO-GO throughput verdict is not a red build
