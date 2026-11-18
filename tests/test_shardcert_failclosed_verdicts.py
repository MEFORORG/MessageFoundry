# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shard-certification verdicts that read PASS on a run they exist to refuse (BACKLOG #5440, #5441,
#5442).

Unit tests over synthetic counters: no load run, no database, no fleet.
"""

from __future__ import annotations

import pytest

from harness.load.enginepoll import PoolStats
from harness.load.shardcert import (
    ShardCertDriveReport,
    ShardCertLadderReport,
    ShardCertReport,
    ShardCertStepRecord,
)
from harness.load.shardcert_ladder import (
    ConsolidatedLadderReport,
    LadderRung,
    RungOutcome,
    RungVerdict,
    build_consolidated_report,
    build_rung_outcome,
)


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


# --- BACKLOG #5442: the two-box ladder reads the abort marker and the gate's pool -------------------------

_DESTS = 4


def _drive(rate: float, *, sink_short: int = 0, drained: bool = True) -> ShardCertDriveReport:
    """A two-box drive report for one rung: ``rate`` msg/s for 60 s, every message acked and fanned out to
    all ``_DESTS`` sinks less ``sink_short`` copies."""
    acked = int(rate * 60)
    sink = acked * _DESTS - sink_short
    return ShardCertDriveReport(
        shards=("a", "b"),
        dests=_DESTS,
        handlers=_DESTS,
        delivering=_DESTS,
        driver_count=2,
        sink_count=_DESTS,
        aggregate_rate=rate,
        hold_seconds=60.0,
        offered=acked,
        sent=acked,
        acked=acked,
        sink_received=sink,
        lane_inversions=0,
        lane_repeats=0,
        lanes_observed=_DESTS,
        ack_p50_ms=1.0,
        ack_p99_ms=2.0,
        engine_done=sink,
        engine_dead=0,
        in_pipeline_final=0,
        drained=drained,
        drain_seconds=0.0,
        tallied_behind_gate=True,
    )


def _clean_gate(pool: PoolStats | None = None) -> dict[str, object]:
    """The ENGINE_DRAINED payload of a clean rung, with the pool block the engine posts on it."""
    payload: dict[str, object] = {
        "engine_ok": True,
        "drained": True,
        "stranded": 0,
        "dead_total": 0,
        "in_pipeline_final": 0,
        "drain_seconds": 1.0,
    }
    if pool is not None:
        payload["store_pool"] = pool.to_json_dict()
    return payload


#: The ENGINE_DRAINED payload run_shardcert_engine posts on a rung the drive aborted mid-delivery.
_ABORTED_GATE: dict[str, object] = {
    "valid": False,
    "aborted": True,
    "engine_ok": False,
    "drained": False,
    "note": "drive aborted mid-delivery; sinks torn down; store-truth INVALID, not a collapse",
}

_HEALTHY_POOL = PoolStats(
    requested=40,
    max_size=40,
    size=40,
    idle_min=10,
    shards_reporting=2,
    acquire_wait_count=10_000,
    acquire_wait_mean_ms=0.01,
    acquire_wait_p95_ms=0.05,
    acquire_wait_p99_ms=0.1,
)
_TRIPPED_POOL = PoolStats(
    requested=40,
    max_size=40,
    size=40,
    idle_min=0,
    shards_reporting=2,
    acquire_wait_count=10_000,
    acquire_wait_mean_ms=3.0,
    acquire_wait_p95_ms=25.0,
    acquire_wait_p99_ms=60.0,
)


def _rung(index: int, rate: float) -> LadderRung:
    return LadderRung(index=index, ingress_rate=rate, hold_seconds=60.0, drain_timeout=150.0)


def _sustained(index: int, rate: float, pool: PoolStats = _HEALTHY_POOL) -> RungOutcome:
    """A clean rung whose ENGINE_RUNG_REPORT never arrived: store-truth and pool come from the gate."""
    out = build_rung_outcome(_rung(index, rate), _drive(rate), _clean_gate(pool), None)
    assert out.verdict is RungVerdict.SUSTAINED
    return out


def _consolidated(climb: list[RungOutcome]) -> ConsolidatedLadderReport:
    return build_consolidated_report(
        shards=("a", "b"),
        dests=_DESTS,
        handlers=_DESTS,
        delivering=_DESTS,
        routing="broadcast",
        lanes_per_shard=1,
        driver_count=2,
        sink_count=_DESTS,
        climb=climb,
        soak=None,
        climb_aborted=False,
        soak_aborted=False,
    )


@pytest.mark.parametrize("where", ["gate", "report"])
def test_aborted_store_truth_is_inconclusive_not_collapsed(where: str) -> None:
    drive = _drive(24.0, sink_short=500, drained=False)
    gate = _ABORTED_GATE if where == "gate" else None
    report = {**_ABORTED_GATE, "stranded": -1, "dead_total": -1} if where == "report" else None
    out = build_rung_outcome(_rung(1, 24.0), drive, gate, report)
    assert out.verdict is RungVerdict.INCONCLUSIVE
    assert out.engine_reported is False
    assert any("INVALID" in n for n in out.notes)


def test_aborted_rung_does_not_bracket_a_ceiling() -> None:
    """A sustained rung, then a rung the engine marked aborted. Scored COLLAPSED, the aborted rung
    bracketed a ceiling at exit 0; it proves nothing, so the run is SETUP_DEGRADED."""
    aborted = build_rung_outcome(
        _rung(1, 24.0), _drive(24.0, sink_short=500, drained=False), _ABORTED_GATE, None
    )
    rep = _consolidated([_sustained(0, 20.0), aborted])
    assert rep.first_collapse_ingress_rate is None
    assert rep.ceiling_bracketed is False
    assert rep.exit_code == 2
    assert rep.result_label == "SETUP_DEGRADED"


def test_gate_only_rung_reads_its_pool_from_the_gate() -> None:
    out = _sustained(0, 20.0, pool=_TRIPPED_POOL)
    assert out.pool.measured is True
    assert out.pool.tripped is True
    assert not any("NOT MEASURED" in n for n in out.notes)


def test_pool_bound_gate_only_ladder_does_not_exit_zero() -> None:
    """Every rung's ENGINE_RUNG_REPORT was lost; the drain gates carried a tripped pool. The ladder must
    name the pool as the wall, not publish the ceiling as a PASS."""
    rep = _consolidated([_sustained(0, 20.0), _sustained(1, 24.0, pool=_TRIPPED_POOL)])
    assert rep.ceiling_pool_bound is True
    assert rep.exit_code == 2
    assert rep.result_label == "POOL_BOUND"


def test_report_pool_still_wins_over_the_gate() -> None:
    """The report's pool block is read first; the gate's is the fallback only."""
    report = {**_clean_gate(), "store_pool": _TRIPPED_POOL.to_json_dict()}
    out = build_rung_outcome(_rung(0, 20.0), _drive(20.0), _clean_gate(_HEALTHY_POOL), report)
    assert out.pool.tripped is True
