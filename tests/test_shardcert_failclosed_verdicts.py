# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shard-certification verdicts that read PASS on a run they exist to refuse (BACKLOG #5440, #5441).

Unit tests over synthetic counters: no load run, no database, no fleet.
"""

from __future__ import annotations

import pytest

from harness.load.shardcert import ShardCertLadderReport, ShardCertReport, ShardCertStepRecord


def _report(**over: object) -> ShardCertReport:
    """A healthy co-located broadcast report: 1000 ACKed messages, D = 2, every copy arrived."""
    base: dict[str, object] = {
        "shards": ("s1", "s2"),
        "owned": {"s1": ["OB_1"], "s2": ["OB_2"]},
        "killed_shard": None,
        "sent": 1000,
        "acked": 1000,
        "delivered_distinct": 1000,
        "sink_received": 2000,
        "acked_not_delivered": 0,
        "lane_inversions": 0,
        "lanes_observed": 4,
        "lane_repeats": 0,
        "engine_done": 3000,
        "engine_dead": 0,
        "in_pipeline_final": 0,
        "drained": True,
        "drain_seconds": 2.0,
        "stranded_nonterminal": 0,
        "queue_breakdown": "",
        "offered": 1000,
        "achieved_intake": 1000,
        "dests": 2,
        "handlers": 3,
        "delivering": 2,
        "acked_copies_missing": 0,
        "dead_total": 0,
    }
    base.update(over)
    return ShardCertReport(**base)  # type: ignore[arg-type]


# --- BACKLOG #5440: the single-box report gates the all-stage dead total ---------------------------------


def test_healthy_report_passes() -> None:
    assert _report().ok is True


def test_routed_stage_dead_letters_fail_the_single_box_report() -> None:
    """H = 3, D = 2: the third handler delivers nothing, so its transform dead-lettering at the routed stage
    loses no sink copy and leaves the outbound-scoped ``engine_dead`` at 0. Only the store's all-stage dead
    total sees it, and the verdict must read it."""
    rep = _report(dead_total=1000)
    assert rep.engine_dead == 0
    assert rep.lossless is True
    assert rep.ok is False
    assert "verdict=FAIL" in rep.render()
    js = rep.to_json_dict()
    assert js["verdict"] == "FAIL"
    assert js["correctness"]["dead_total"] == 1000  # type: ignore[index]
    assert js["schema_version"] == 6


def test_unmeasured_dead_total_fails_closed() -> None:
    """A producer that never supplies the all-stage dead total gets a FAIL, never a silent PASS."""
    fields = {k: v for k, v in _report().__dict__.items() if k != "dead_total"}
    rep = ShardCertReport(**fields)
    assert rep.dead_total == -1
    assert rep.ok is False


# --- BACKLOG #5441: the ladder verdict holds every rung to the single-run pass bar -----------------------


def _ladder(*reports: ShardCertReport) -> ShardCertLadderReport:
    """A ladder whose rungs come from measured reports, through the same ``from_report`` the climb uses."""
    return ShardCertLadderReport(
        records=[
            ShardCertStepRecord.from_report(10.0 * (i + 1), rep, hold_seconds=60.0)
            for i, rep in enumerate(reports)
        ]
    )


def test_healthy_ladder_passes() -> None:
    lad = _ladder(_report(), _report())
    assert lad.ok is True
    assert lad.exit_code == 0
    assert lad.result_label == "PASS"


@pytest.mark.parametrize(
    "over",
    [
        pytest.param({"lane_repeats": 3}, id="duplicate-deliveries"),
        pytest.param({"lanes_observed": 1}, id="single-lane"),
        pytest.param({"engine_dead": 2}, id="outbound-dead-letters"),
        pytest.param({"dead_total": 2}, id="routed-dead-letters"),
        pytest.param(
            {"acked": 0, "achieved_intake": 0, "delivered_distinct": 0, "sink_received": 0},
            id="nothing-acked",
        ),
    ],
)
def test_ladder_fails_a_rung_the_single_run_bar_refuses(over: dict[str, int]) -> None:
    bad = _report(**over)
    assert bad.ok is False  # the single-run bar already refuses it
    lad = _ladder(_report(), bad)
    assert lad.ok is False
    assert lad.exit_code == 1
    assert lad.result_label == "FAIL"


def test_step_record_carries_the_pass_bar_fields() -> None:
    rec = ShardCertStepRecord.from_report(
        10.0, _report(lanes_observed=5, engine_dead=1, dead_total=3)
    )
    assert (rec.lanes_observed, rec.engine_dead, rec.dead_total) == (5, 1, 3)
    js = rec.to_json_dict()
    assert (js["lanes_observed"], js["engine_dead"], js["dead_total"]) == (5, 1, 3)
    assert js["correctness_ok"] is False


def test_step_record_without_the_pass_bar_fields_fails_closed() -> None:
    """A synthetic record that never carried the lane count or the dead totals must not pass the ladder."""
    rec = ShardCertStepRecord(
        aggregate_rate=10.0,
        offered=600,
        achieved_intake=600,
        delivered=600,
        in_pipeline_peak=0,
        ack_p50_ms=1.0,
        ack_p99_ms=2.0,
        drain_seconds=1.0,
        no_loss=True,
        lane_inversions=0,
        lane_repeats=0,
        stranded_nonterminal=0,
    )
    assert rec.correctness_ok is False
    assert ShardCertLadderReport(records=[rec]).ok is False
