# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Offline unit tests for the turnkey two-box SIZING ceiling ladder (PR-C2).

The live drive/engine halves need a real 4-shard SQL-Server fleet + two boxes, so these exercise the
PURE, testable core WITHOUT a live engine: the rung plan, the drain-window collapse-vs-tail CLASSIFIER
(the trust-critical piece — a false "pinned ceiling" is the failure mode), the phase-timing aggregation
from synthetic node logs, the soak-rate pick + slope, and the consolidated report's ceiling / target /
verdict math + render/JSON.

Store-truth for the classifier comes from the RELIABLE ENGINE_DRAINED drain gate (``gate``); the later,
more fragile ENGINE_RUNG_REPORT (``report``) only ADDS phase timing + the soak slope — so a late/lost
report can never fabricate a collapse. When neither arrives the rung is INCONCLUSIVE (a coord glitch),
never a proven collapse.
"""

from __future__ import annotations

import math

import pytest

from harness.load import coord
from harness.load import shardcert as _shardcert
from harness.load.shardcert import ShardCertDriveReport
from harness.load.shardcert_ladder import (
    TARGET_INGRESS_PER_S,
    ClaimTiming,
    ConsolidatedLadderReport,
    LadderRung,
    PhaseTiming,
    RungVerdict,
    _CLAIM_RE,
    _PHASE_RE,
    _claim_lines,
    _phase_lines,
    aggregate_claim_timing,
    aggregate_phase_timing,
    build_consolidated_report,
    build_rung_outcome,
    classify_rung,
    in_pipeline_slope,
    pick_soak_rate,
    plan_climb_rungs,
    slope_is_draining,
    stops_climb,
)

# --- helpers -----------------------------------------------------------------


def _drive(
    *,
    ingress: float,
    dests: int = 8,
    acked: int,
    sink_received: int | None = None,
    lane_inversions: int = 0,
    lane_repeats: int = 0,
    lanes_observed: int = 4,
    hold_seconds: float = 60.0,
    drained: bool = True,
) -> ShardCertDriveReport:
    """A synthetic multi-process drive report. Defaults are a clean, lossless rung (S == A*dests)."""
    s = acked * dests if sink_received is None else sink_received
    return ShardCertDriveReport(
        shards=("a", "b", "c", "d"),
        dests=dests,
        driver_count=4,
        sink_count=dests,
        aggregate_rate=ingress,
        hold_seconds=hold_seconds,
        offered=round(ingress * hold_seconds),
        sent=acked,
        acked=acked,
        sink_received=s,
        lane_inversions=lane_inversions,
        lane_repeats=lane_repeats,
        lanes_observed=lanes_observed,
        ack_p50_ms=1.0,
        ack_p99_ms=2.0,
        engine_done=s,
        engine_dead=0,
        in_pipeline_final=0,
        drained=drained,
        drain_seconds=1.0,
    )


def _gate(
    *,
    engine_ok: bool = True,
    drained: bool = True,
    stranded: int = 0,
    dead_total: int = 0,
    in_pipeline_final: int = 0,
) -> dict[str, object]:
    """The ENGINE_DRAINED drain-gate payload (reliable store-truth the classifier keys off)."""
    return {
        "engine_ok": engine_ok,
        "drained": drained,
        "stranded": stranded,
        "dead_total": dead_total,
        "in_pipeline_final": in_pipeline_final,
    }


def _report(
    *,
    slope: float | None = None,
    phase: dict[str, object] | None = None,
    notes: list[str] | None = None,
) -> dict[str, object]:
    """The ENGINE_RUNG_REPORT payload (supplementary: phase timing + soak slope). Also carries a redundant
    store-truth cross-check in production, but the classifier prefers the gate."""
    return {
        "engine_ok": True,
        "drained": True,
        "stranded": 0,
        "dead_total": 0,
        "in_pipeline_final": 0,
        "in_pipeline_slope": slope,
        "phase_timing": phase or PhaseTiming(2, 100, 0.6, 1.2, 8.0, 20.0).to_json_dict(),
        "notes": notes or [],
    }


def _phase_line(san: int, sam: float, samx: float, mdn: int, mdm: float, mdmx: float) -> str:
    return (
        "2026-07-09T00:38:11Z INFO     messagefoundry.pipeline.wiring_runner: "
        f"delivery phase timing (stage=outbound): send_ack n={san} mean={sam:.2f}ms max={samx:.2f}ms "
        f"| mark_done n={mdn} mean={mdm:.2f}ms max={mdmx:.2f}ms"
    )


# --- new coord constants -----------------------------------------------------


def test_new_ladder_coord_constants_are_distinct() -> None:
    names = [
        coord.ENGINE_DRAINED,
        coord.ENGINE_RUNG_REPORT,
        coord.LADDER_STOP,
        coord.LADDER_SOAK,
        coord.SHARDS_READY,
        coord.DRIVE_START,
    ]
    assert all(isinstance(n, str) and n for n in names)
    assert len(set(names)) == len(names)  # no accidental dup with an existing message name


# --- rung plan ---------------------------------------------------------------


def test_plan_climb_rungs_ascending_dedup_indexed() -> None:
    rungs = plan_climb_rungs([64, 20, 24, 20], hold_seconds=60.0, drain_timeout=150.0)
    assert [r.ingress_rate for r in rungs] == [20.0, 24.0, 64.0]  # ascending, de-duplicated
    assert [r.index for r in rungs] == [0, 1, 2]
    assert [r.run_suffix for r in rungs] == ["r0", "r1", "r2"]
    assert rungs[0].outbound_rate(8) == 160.0
    assert all(not r.is_soak for r in rungs)


def test_plan_climb_rungs_empty_rejected() -> None:
    with pytest.raises(ValueError):
        plan_climb_rungs([], hold_seconds=60.0, drain_timeout=150.0)


def test_soak_rung_suffix() -> None:
    soak = LadderRung(
        index=-1, ingress_rate=64.0, hold_seconds=300.0, drain_timeout=300.0, is_soak=True
    )
    assert soak.run_suffix == "soak"


# --- the classifier truth-table (the trust-critical piece) -------------------


def test_classify_sustained() -> None:
    assert (
        classify_rung(
            engine_reported=True, engine_ok=True, no_loss=True, lane_inversions=0, lane_repeats=0
        )
        is RungVerdict.SUSTAINED
    )


def test_classify_collapsed_when_engine_confirmed_not_drained() -> None:
    # Engine store-truth CONFIRMED (reported) and failed (stranded/dead/not-drained) — a TRUE collapse.
    assert (
        classify_rung(
            engine_reported=True, engine_ok=False, no_loss=True, lane_inversions=0, lane_repeats=0
        )
        is RungVerdict.COLLAPSED
    )


def test_classify_inconclusive_when_store_truth_unconfirmed() -> None:
    # Neither the drain gate nor the report arrived — a coord glitch, NOT a proven collapse. Must be
    # INCONCLUSIVE so it cannot fabricate a bracketed ceiling.
    assert (
        classify_rung(
            engine_reported=False, engine_ok=False, no_loss=True, lane_inversions=0, lane_repeats=0
        )
        is RungVerdict.INCONCLUSIVE
    )


def test_classify_frozen_tail_engine_clean_but_sink_short() -> None:
    # Engine drained clean (nothing stranded/lost) but the sink came up short with NO ordering/dup break —
    # a teardown/latency tail, NOT collapse. This is the exact false-ceiling the drain window prevents.
    assert (
        classify_rung(
            engine_reported=True, engine_ok=True, no_loss=False, lane_inversions=0, lane_repeats=0
        )
        is RungVerdict.FROZEN_TAIL
    )


def test_classify_correctness_fail_outranks_everything() -> None:
    # An inversion / duplicate (from the always-present sink-truth) is a hard correctness break regardless
    # of the engine/throughput signals — even when store-truth is unconfirmed.
    assert (
        classify_rung(
            engine_reported=True, engine_ok=True, no_loss=True, lane_inversions=1, lane_repeats=0
        )
        is RungVerdict.CORRECTNESS_FAIL
    )
    assert (
        classify_rung(
            engine_reported=False, engine_ok=False, no_loss=False, lane_inversions=0, lane_repeats=2
        )
        is RungVerdict.CORRECTNESS_FAIL
    )


def test_stops_climb_on_collapse_correctness_and_inconclusive() -> None:
    assert stops_climb(RungVerdict.COLLAPSED) is True
    assert stops_climb(RungVerdict.CORRECTNESS_FAIL) is True
    assert (
        stops_climb(RungVerdict.INCONCLUSIVE) is True
    )  # can't certify further without store-truth
    assert stops_climb(RungVerdict.SUSTAINED) is False
    # A frozen tail does NOT stop the climb — the engine sustained it; keep probing for the real collapse.
    assert stops_climb(RungVerdict.FROZEN_TAIL) is False


# --- phase-timing aggregation ------------------------------------------------


def test_aggregate_phase_timing_n_weighted_and_drops_first_window(tmp_path) -> None:
    # Each shard log's FIRST phase window is a ramp window that must be DROPPED. Put an absurd ramp value
    # first so a failure to drop it would blow up the mean unmistakably.
    (tmp_path / "shard-a.log").write_text(
        "\n".join(
            [
                "some startup line without timing",
                _phase_line(10, 99.0, 999.0, 10, 99.0, 999.0),  # ramp — DROPPED
                _phase_line(100, 0.60, 1.20, 100, 8.0, 20.0),
                _phase_line(200, 0.50, 1.00, 200, 6.0, 30.0),
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "shard-b.log").write_text(
        "\n".join(
            [
                _phase_line(5, 99.0, 999.0, 5, 99.0, 999.0),  # ramp — DROPPED
                _phase_line(50, 0.80, 1.50, 50, 10.0, 40.0),
            ]
        ),
        encoding="utf-8",
    )
    pt = aggregate_phase_timing([tmp_path / "shard-a.log", tmp_path / "shard-b.log"])
    assert pt.windows == 3
    assert pt.deliveries == 350  # 100 + 200 + 50
    # send_ack n-weighted mean = (0.6*100 + 0.5*200 + 0.8*50) / 350 = 200/350
    assert math.isclose(pt.send_ack_mean_ms, 200.0 / 350.0, rel_tol=1e-9)
    # mark_done n-weighted mean = (8*100 + 6*200 + 10*50) / 350 = 2500/350
    assert math.isclose(pt.mark_done_mean_ms, 2500.0 / 350.0, rel_tol=1e-9)
    assert pt.send_ack_max_ms == 1.50
    assert pt.mark_done_max_ms == 40.0
    assert not pt.empty


def test_aggregate_phase_timing_missing_and_empty_logs(tmp_path) -> None:
    (tmp_path / "shard-a.log").write_text("no timing lines here at all\n", encoding="utf-8")
    pt = aggregate_phase_timing(
        [tmp_path / "shard-a.log", tmp_path / "does-not-exist.log"]  # missing file tolerated
    )
    assert pt.empty
    assert pt.windows == 0
    assert pt.deliveries == 0
    assert pt.send_ack_mean_ms == 0.0


def test_aggregate_phase_timing_keep_first_window(tmp_path) -> None:
    # With drop_first_window=False the single (only) window is KEPT — otherwise a 1-window log aggregates
    # to empty (its sole window is the dropped ramp), which would understate a short smoke rung.
    (tmp_path / "shard-a.log").write_text(
        _phase_line(100, 0.60, 1.20, 100, 8.0, 20.0), encoding="utf-8"
    )
    dropped = aggregate_phase_timing([tmp_path / "shard-a.log"])
    assert dropped.empty  # the lone window was the ramp window → dropped → nothing left
    kept = aggregate_phase_timing([tmp_path / "shard-a.log"], drop_first_window=False)
    assert kept.windows == 1
    assert kept.deliveries == 100
    assert math.isclose(kept.mark_done_mean_ms, 8.0)


def test_phase_timing_json_roundtrip() -> None:
    pt = PhaseTiming(3, 350, 0.5714, 1.5, 7.1428, 40.0)
    d = pt.to_json_dict()
    back = PhaseTiming.from_json_dict(d)
    assert back.windows == 3
    assert back.deliveries == 350
    assert math.isclose(back.mark_done_max_ms, 40.0)
    assert "phase timing" in pt.render()
    assert "none captured" in PhaseTiming(0, 0, 0.0, 0.0, 0.0, 0.0).render()


# --- in_pipeline slope -------------------------------------------------------


def test_in_pipeline_slope_growing_flat_draining() -> None:
    growing = in_pipeline_slope([[0.0, 0.0], [10.0, 100.0], [20.0, 200.0]])
    assert growing is not None and math.isclose(growing, 10.0, rel_tol=1e-6)
    flat = in_pipeline_slope([[0.0, 50.0], [10.0, 50.0], [20.0, 50.0]])
    assert flat is not None and math.isclose(flat, 0.0, abs_tol=1e-9)
    draining = in_pipeline_slope([[0.0, 200.0], [10.0, 100.0], [20.0, 0.0]])
    assert draining is not None and draining < 0


def test_in_pipeline_slope_too_few_points() -> None:
    assert in_pipeline_slope([]) is None
    assert in_pipeline_slope([[1.0, 5.0]]) is None
    # all samples at the same instant → slope undefined, not a divide-by-zero
    assert in_pipeline_slope([[3.0, 1.0], [3.0, 9.0]]) is None


def test_slope_is_draining_bar() -> None:
    # _SLOPE_FLAT_TOL dropped 1.0 -> 0.25 in LOCKSTEP with D4's slope de-inflation (shardcert.py divides the
    # N×-summed unified-store in_pipeline, hence the slope, by the shard count). The pair is gate-invariant
    # on any physical run; the threshold is now the TRUE, N-independent backlog-growth rate.
    assert slope_is_draining(0.0) is True
    assert slope_is_draining(-5.0) is True
    assert slope_is_draining(0.25) is True  # exactly at the flat tolerance (the new bar)
    assert slope_is_draining(0.5) is False  # growing
    assert (
        slope_is_draining(1.0) is False
    )  # the OLD bar now reads GROWING — the de-inflation coupling
    assert slope_is_draining(None) is False  # no trace ⇒ cannot certify the plateau


# --- build_rung_outcome ------------------------------------------------------


def _rung(idx: int = 0, rate: float = 20.0) -> LadderRung:
    return LadderRung(index=idx, ingress_rate=rate, hold_seconds=60.0, drain_timeout=150.0)


def test_build_rung_outcome_sustained_from_gate() -> None:
    out = build_rung_outcome(_rung(), _drive(ingress=20.0, acked=1200), _gate(), _report())
    assert out.verdict is RungVerdict.SUSTAINED
    assert out.engine_reported is True
    assert out.outbound_rate() == 160.0
    assert out.outbound_delivered_expected() == 1200 * 8
    # phase timing came from the report
    assert out.phase.deliveries == 100


def test_build_rung_outcome_late_report_still_classified_by_gate() -> None:
    # THE FIX: a lossless drive whose ENGINE_RUNG_REPORT is late/lost (report=None) but whose reliable
    # drain gate arrived is classified SUSTAINED (store-truth from the gate) — NOT a fabricated collapse.
    out = build_rung_outcome(_rung(), _drive(ingress=20.0, acked=1200), _gate(engine_ok=True), None)
    assert out.engine_reported is True
    assert out.verdict is RungVerdict.SUSTAINED
    assert out.phase.empty  # only the phase timing is missing
    assert any("phase timing" in n and "absent" in n for n in out.notes)


def test_build_rung_outcome_both_absent_is_inconclusive() -> None:
    # Neither gate nor report ⇒ store-truth unconfirmed ⇒ INCONCLUSIVE (a coord glitch, not a collapse).
    out = build_rung_outcome(_rung(), _drive(ingress=20.0, acked=1200), None, None)
    assert out.engine_reported is False
    assert out.verdict is RungVerdict.INCONCLUSIVE
    assert any("UNCONFIRMED" in n for n in out.notes)


def test_build_rung_outcome_collapsed_from_gate() -> None:
    drive = _drive(ingress=28.0, acked=1680, sink_received=1680 * 8 - 400, drained=False)
    out = build_rung_outcome(
        _rung(idx=2, rate=28.0), drive, _gate(engine_ok=False, drained=False, stranded=400), None
    )
    assert out.verdict is RungVerdict.COLLAPSED
    assert out.engine_stranded == 400


def test_build_rung_outcome_frozen_tail() -> None:
    drive = _drive(ingress=24.0, acked=1440, sink_received=1440 * 8 - 5)
    out = build_rung_outcome(_rung(idx=1, rate=24.0), drive, _gate(engine_ok=True), _report())
    assert out.no_loss is False
    assert out.verdict is RungVerdict.FROZEN_TAIL


# --- soak-rate pick ----------------------------------------------------------


def _outcome(rate: float, verdict: RungVerdict, *, is_soak: bool = False, lanes_observed: int = 4):
    rung = LadderRung(
        index=0, ingress_rate=rate, hold_seconds=60.0, drain_timeout=150.0, is_soak=is_soak
    )
    drive = _drive(ingress=rate, acked=int(rate * 60), lanes_observed=lanes_observed)
    out = build_rung_outcome(rung, drive, _gate(), _report())
    # force the verdict/shape for report-shape tests independent of the drive's actual numbers. Kept-up
    # rungs (drive_drain_seconds=0.0 ⇒ honest sustainable rate == offered) so these SELECTION/shape tests
    # read in offered terms; the D1 drain-discount is exercised by the dedicated tests below.
    return type(out)(
        **{**out.__dict__, "verdict": verdict, "is_soak": is_soak, "drive_drain_seconds": 0.0}
    )


def test_pick_soak_rate_highest_sustained() -> None:
    records = [
        _outcome(20.0, RungVerdict.SUSTAINED),
        _outcome(24.0, RungVerdict.SUSTAINED),
        _outcome(28.0, RungVerdict.FROZEN_TAIL),  # NOT sustained ⇒ not eligible
        _outcome(32.0, RungVerdict.COLLAPSED),
    ]
    assert pick_soak_rate(records) == 24.0


def test_pick_soak_rate_override_wins() -> None:
    records = [_outcome(20.0, RungVerdict.SUSTAINED)]
    assert pick_soak_rate(records, override=99.0) == 99.0


def test_pick_soak_rate_none_when_nothing_sustained() -> None:
    records = [_outcome(20.0, RungVerdict.COLLAPSED), _outcome(24.0, RungVerdict.FROZEN_TAIL)]
    assert pick_soak_rate(records) is None


# --- consolidated report -----------------------------------------------------


def _rep(climb, soak=None, climb_aborted: bool = False) -> ConsolidatedLadderReport:
    return build_consolidated_report(
        shards=("a", "b", "c", "d"),
        dests=8,
        driver_count=4,
        sink_count=8,
        climb=climb,
        soak=soak,
        climb_aborted=climb_aborted,
    )


def test_report_pins_ceiling_and_brackets_collapse() -> None:
    climb = [
        _outcome(20.0, RungVerdict.SUSTAINED),
        _outcome(24.0, RungVerdict.SUSTAINED),
        _outcome(28.0, RungVerdict.COLLAPSED),
    ]
    rep = _rep(climb)
    assert rep.pinned_ingress_rate == 24.0
    assert rep.pinned_outbound_rate == 24.0 * 8
    assert rep.first_collapse_ingress_rate == 28.0
    assert rep.ceiling_bracketed is True
    assert rep.ok is True  # a ceiling is a MEASUREMENT, not a verdict failure
    assert rep.exit_code == 0


def test_report_inconclusive_does_not_fabricate_a_bracket() -> None:
    # An INCONCLUSIVE rung (unconfirmed store-truth) must NOT be scored as a collapse: it does not populate
    # first_collapse and leaves the pinned rate an honest FLOOR — the trust-critical fix.
    climb = [
        _outcome(20.0, RungVerdict.SUSTAINED),
        _outcome(24.0, RungVerdict.INCONCLUSIVE),  # a coord glitch, not a collapse
    ]
    rep = _rep(climb)
    assert rep.pinned_ingress_rate == 20.0
    assert rep.first_collapse_ingress_rate is None  # NOT bracketed by the inconclusive rung
    assert rep.ceiling_bracketed is False
    assert "FLOOR" in rep.render()


def test_report_floor_when_never_collapsed() -> None:
    climb = [_outcome(20.0, RungVerdict.SUSTAINED), _outcome(24.0, RungVerdict.SUSTAINED)]
    rep = _rep(climb)
    assert rep.pinned_ingress_rate == 24.0
    assert rep.first_collapse_ingress_rate is None
    assert rep.ceiling_bracketed is False  # a FLOOR — the true ceiling is above the top rung
    assert "FLOOR" in rep.render()


def test_report_target_clearing_ingress() -> None:
    # 521/s is an INGRESS target (45M/day). A pinned 64/s ingress does NOT clear it; a pinned 600/s does.
    below = _rep([_outcome(64.0, RungVerdict.SUSTAINED), _outcome(80.0, RungVerdict.COLLAPSED)])
    assert below.clears_target_ingress is False
    above = _rep([_outcome(600.0, RungVerdict.SUSTAINED), _outcome(640.0, RungVerdict.COLLAPSED)])
    assert above.clears_target_ingress is True
    assert math.isclose(TARGET_INGRESS_PER_S, 45_000_000 / 86_400)


def test_report_correctness_break_fails_verdict() -> None:
    climb = [_outcome(20.0, RungVerdict.SUSTAINED), _outcome(24.0, RungVerdict.CORRECTNESS_FAIL)]
    rep = _rep(climb)
    assert rep.correctness_ok is False
    assert rep.ok is False
    assert rep.exit_code == 1


def test_report_vacuous_fifo_gate_scoped_to_sustained() -> None:
    # lanes_observed < 2 on a SUSTAINED rung ⇒ vacuous FIFO evidence ⇒ correctness NOT ok.
    sustained_vacuous = _outcome(20.0, RungVerdict.SUSTAINED, lanes_observed=1)
    assert _rep([sustained_vacuous]).correctness_ok is False
    # But lanes_observed < 2 on a COLLAPSED rung is a THROUGHPUT measurement, not a correctness failure —
    # a near-zero-delivery collapse legitimately sees <2 lanes; the ladder must still exit 0.
    climb = [
        _outcome(20.0, RungVerdict.SUSTAINED, lanes_observed=4),
        _outcome(24.0, RungVerdict.COLLAPSED, lanes_observed=1),
    ]
    rep = _rep(climb)
    assert rep.correctness_ok is True
    assert rep.exit_code == 0


def test_report_climb_aborted_exits_setup_code_2() -> None:
    # A two-box rendezvous/timeout abort mid-run must surface exit 2 (setup), never a false PASS — even
    # when the rungs that DID run were clean.
    climb = [_outcome(20.0, RungVerdict.SUSTAINED)]
    rep = _rep(climb, climb_aborted=True)
    assert rep.exit_code == 2
    assert rep.setup_degraded is True
    assert rep.to_json_dict()["result"] == "SETUP_DEGRADED"
    assert "SETUP-DEGRADED" in rep.render()
    # an EMPTY aborted climb (rung-0 rendezvous failure) is also exit 2, not the empty-climb exit 1
    assert _rep([], climb_aborted=True).exit_code == 2


def test_report_inconclusive_climb_is_setup_degraded_not_pass() -> None:
    # An unconfirmed ENGINE store-truth (INCONCLUSIVE) is a coord/infra degradation, NOT a clean result —
    # it must surface exit 2 (never a nothing-certified PASS), consistent with the rendezvous-abort rule.
    only_inconclusive = _rep([_outcome(20.0, RungVerdict.INCONCLUSIVE)])
    assert only_inconclusive.pinned_ingress_rate is None
    assert only_inconclusive.store_truth_unconfirmed is True
    assert only_inconclusive.exit_code == 2
    assert only_inconclusive.to_json_dict()["result"] == "SETUP_DEGRADED"
    # a trailing INCONCLUSIVE after real sustained rungs is still a degradation (re-run for a clean bracket)
    partial = _rep(
        [_outcome(20.0, RungVerdict.SUSTAINED), _outcome(24.0, RungVerdict.INCONCLUSIVE)]
    )
    assert partial.pinned_ingress_rate == 20.0  # the floor is still reported
    assert partial.exit_code == 2
    # a soak-only INCONCLUSIVE does NOT degrade the climb's exit code (soak is supplementary)
    soak_inconc = _outcome(20.0, RungVerdict.INCONCLUSIVE, is_soak=True)
    clean = _rep([_outcome(20.0, RungVerdict.SUSTAINED)], soak=soak_inconc)
    assert clean.store_truth_unconfirmed is False
    assert clean.exit_code == 0


def test_report_soak_ok_requires_sustained_and_draining_slope() -> None:
    climb = [_outcome(24.0, RungVerdict.SUSTAINED)]
    soak_ok = _outcome(24.0, RungVerdict.SUSTAINED, is_soak=True)
    soak_ok = type(soak_ok)(**{**soak_ok.__dict__, "in_pipeline_slope": 0.2})
    rep = _rep(climb, soak=soak_ok)
    assert rep.soak_ok is True
    # soak sustained but GROWING slope ⇒ NOT ok (slow saturation)
    soak_grow = type(soak_ok)(**{**soak_ok.__dict__, "in_pipeline_slope": 12.0})
    assert _rep(climb, soak=soak_grow).soak_ok is False
    # no soak ⇒ soak_ok False
    assert _rep(climb).soak_ok is False


def test_report_renders_and_serializes() -> None:
    climb = [
        _outcome(20.0, RungVerdict.SUSTAINED),
        _outcome(24.0, RungVerdict.SUSTAINED),
        _outcome(28.0, RungVerdict.COLLAPSED),
    ]
    soak = _outcome(24.0, RungVerdict.SUSTAINED, is_soak=True)
    soak = type(soak)(**{**soak.__dict__, "in_pipeline_slope": 0.1})
    rep = _rep(climb, soak=soak)

    text = rep.render()
    assert "SIZING ladder" in text
    assert "pinned sustainable ceiling: 24 ingress/s = 192 outbound/s" in text
    assert "521/s INGRESS target" in text
    assert "soak" in text.lower()

    js = rep.to_json_dict()
    assert js["kind"] == "shardcert_ladder_two_box"
    assert js["result"] == "PASS"
    assert js["climb_aborted"] is False
    assert js["ceiling"]["pinned_ingress_rate"] == 24.0
    assert js["ceiling"]["pinned_outbound_rate"] == 192.0
    assert js["ceiling"]["first_collapse_ingress_rate"] == 28.0
    assert js["ceiling"]["clears_target_ingress"] is False
    assert isinstance(js["climb"], list) and len(js["climb"]) == 3
    assert js["soak"] is not None


def test_report_empty_climb_is_not_ok() -> None:
    rep = _rep([])
    assert rep.correctness_ok is False  # nothing driven ⇒ cannot certify
    assert rep.pinned_ingress_rate is None
    assert rep.exit_code == 1  # empty (non-aborted) climb ⇒ correctness fail, not setup abort


# --- D1: honest sustainable-ingress rate (offered spread over hold + MEASURED drain) ------------------


def _honest_rung(
    rate: float,
    verdict: RungVerdict = RungVerdict.SUSTAINED,
    *,
    drain_seconds: float | None,
    hold: float = 60.0,
    sink_received: int | None = None,
    phase_windows: int = 0,
):
    """A RungOutcome with an EXPLICIT measured drain + phase windows / sink count for the honest-rate +
    delivered-rate tests — unlike ``_outcome`` (kept-up, drain 0). Phase is ALWAYS set (windows=0 ⇒ no
    delivered rate)."""
    base = _outcome(rate, verdict)
    overrides: dict[str, object] = {
        "drive_drain_seconds": drain_seconds,
        "hold_seconds": hold,
        "phase": PhaseTiming(phase_windows, phase_windows, 1.0, 2.0, 1.0, 2.0),
    }
    if sink_received is not None:
        overrides["sink_received"] = sink_received
    return type(base)(**{**base.__dict__, **overrides})


def test_sustainable_ingress_rate_penalizes_post_hold_drain() -> None:
    # A rung offered 521/s over a 60s hold that the engine could only clear by draining 150s more (span =
    # 3.5×hold) proves a TRUE sustainable ingress of 521 × 60/210 ≈ 148.86/s — the (hold+drain)/hold = 3.5×
    # overstatement is removed.
    r = _honest_rung(521.0, drain_seconds=150.0, hold=60.0)
    assert r.sustainable_ingress_rate == pytest.approx(521.0 * 60.0 / 210.0)
    assert r.sustainable_ingress_rate == pytest.approx(148.857, abs=1e-2)
    # a rung that KEPT UP in real time (drain ≈ 0) is not penalized — honest == offered
    assert _honest_rung(521.0, drain_seconds=0.0).sustainable_ingress_rate == pytest.approx(521.0)


def test_sustainable_ingress_rate_none_when_drain_unmeasured_and_excluded_from_pinned() -> None:
    # No measured drain ⇒ no honest rate ⇒ the rung is EXCLUDED from the pinned ceiling (never silently
    # reported at the inflated offered rate).
    r = _honest_rung(521.0, drain_seconds=None)
    assert r.sustainable_ingress_rate is None
    assert _rep([r]).pinned_ingress_rate is None


def test_pinned_ingress_rate_is_honest_not_offered() -> None:
    # The pinned ceiling + the §8 gate key off the HONEST rate, not max(offered).
    rep = _rep([_honest_rung(521.0, drain_seconds=150.0, hold=60.0)])
    assert rep.pinned_ingress_rate == pytest.approx(148.857, abs=1e-2)
    assert rep.pinned_outbound_rate == pytest.approx(148.857 * 8, abs=1e-1)


def test_clears_target_ingress_no_longer_fires_at_true_149() -> None:
    # The literal §8-gate correction: a rung offered 521 that only cleared via a long drain sustains ~149/s
    # and must NOT clear the 521/s ingress target.
    assert (
        _rep([_honest_rung(521.0, drain_seconds=150.0, hold=60.0)]).clears_target_ingress is False
    )


def test_clears_target_ingress_fires_only_when_honest_ge_target() -> None:
    # Kept-up (drain ≈ 0) at >= 520.833/s clears; the SAME offered rate with a large measured drain (honest
    # below target) does not.
    assert _rep([_honest_rung(521.0, drain_seconds=0.0)]).clears_target_ingress is True
    assert _rep([_honest_rung(521.0, drain_seconds=60.0, hold=60.0)]).clears_target_ingress is False


def test_pinned_picks_max_honest_not_max_offered() -> None:
    # r_hi offers MORE (200) but only cleared via a long drain (honest = 200×60/300 = 40); r_lo offers less
    # (100) but kept up (honest = 100). The honest ceiling is r_lo — a higher-offered rung that only drained
    # must not out-rank the lower-offered rung that kept up.
    r_lo = _honest_rung(100.0, drain_seconds=0.0, hold=60.0)
    r_hi = _honest_rung(200.0, drain_seconds=240.0, hold=60.0)
    rep = _rep([r_lo, r_hi])
    assert rep.pinned_ingress_rate == pytest.approx(100.0)
    assert rep.pinned_rung is r_lo


# --- D3: span-correct MEASURED delivered rate (phase-window denominator, not sink/hold) ---------------


def test_delivered_rate_per_s_span_correct_not_hold() -> None:
    from harness.load.shardcert_ladder import _PHASE_WINDOW_SECONDS

    n = 4
    windows = 168  # Σ across n shards ⇒ span = (168/4)×5 = 210s (== hold+drain of a 3.5× rung)
    r = _honest_rung(
        521.0, drain_seconds=150.0, hold=60.0, sink_received=42000, phase_windows=windows
    )
    span = (windows / n) * _PHASE_WINDOW_SECONDS
    assert r.delivered_rate_per_s(n) == pytest.approx(42000 / span)
    # deliveries span hold+drain, so the span-correct rate is far below the naive sink/hold
    assert r.delivered_rate_per_s(n) < (42000 / 60.0) / 3.0
    # no phase windows / non-positive shard count ⇒ None (no spurious rate when phase timing is off)
    assert (
        _honest_rung(
            521.0, drain_seconds=1.0, sink_received=42000, phase_windows=0
        ).delivered_rate_per_s(n)
        is None
    )
    assert r.delivered_rate_per_s(0) is None


# --- verdict invariance: the rate fixes touch reported numbers only, never classification ------------


def test_classify_and_verdicts_unchanged_by_rate_fix() -> None:
    # classify_rung is a pure function of the reliable authorities; the D1/D3/D4/D6 work never feeds it.
    cases = [
        (True, True, 0, True, RungVerdict.SUSTAINED),
        (False, True, 0, True, RungVerdict.COLLAPSED),
        (True, False, 0, True, RungVerdict.FROZEN_TAIL),
        (True, True, 1, True, RungVerdict.CORRECTNESS_FAIL),
        (True, True, 0, False, RungVerdict.INCONCLUSIVE),
    ]
    for eng_ok, no_loss, inv, reported, expect in cases:
        assert (
            classify_rung(
                engine_reported=reported,
                engine_ok=eng_ok,
                no_loss=no_loss,
                lane_inversions=inv,
                lane_repeats=0,
            )
            is expect
        )


# --- D6: the store-claim round-trip #842 could not see (aggregated, disjoint from the delivery line) --


def _claim_line(
    n: int, mean: float, mx: float, lpc: float, rpc: float, rearm: int, empty: int
) -> str:
    return (
        "2026-07-09T00:38:11Z INFO     messagefoundry.pipeline.phase_timing: "
        f"claim phase timing (stage=outbound): claim n={n} mean={mean:.2f}ms max={mx:.2f}ms | "
        f"lanes/claim={lpc:.2f} rows/claim={rpc:.2f} rearm={rearm} empty={empty} claimers=1"
    )


def test_claim_line_not_false_matched() -> None:
    delivery = _phase_line(100, 1.5, 9.0, 100, 12.0, 40.0)
    claim = _claim_line(50, 53.0, 90.0, 8.0, 6.0, 2, 1)
    both = delivery + "\n" + claim
    # the delivery aggregator sees ONLY the delivery line; the claim aggregator ONLY the claim line
    assert len(_phase_lines(both)) == 1
    assert len(_claim_lines(both)) == 1
    # neither regex can cross-match the other's line
    assert _PHASE_RE.search(claim) is None
    assert _CLAIM_RE.search(delivery) is None


def test_aggregate_claim_timing_nweighted_drops_first_window(tmp_path) -> None:
    log_a = tmp_path / "shard-a.log"
    log_b = tmp_path / "shard-b.log"
    # first line per log is the ramp window and is DROPPED
    log_a.write_text(
        "\n".join(
            [
                _claim_line(1, 999.0, 999.0, 0.0, 0.0, 0, 0),  # ramp — dropped
                _claim_line(10, 50.0, 80.0, 8.0, 6.0, 1, 0),
                _claim_line(30, 60.0, 90.0, 8.0, 5.0, 0, 2),
            ]
        ),
        encoding="utf-8",
    )
    log_b.write_text(
        "\n".join(
            [
                _claim_line(1, 999.0, 999.0, 0.0, 0.0, 0, 0),  # ramp — dropped
                _claim_line(20, 55.0, 70.0, 8.0, 4.0, 3, 1),
            ]
        ),
        encoding="utf-8",
    )
    agg = aggregate_claim_timing(
        [log_a, log_b, tmp_path / "missing.log"]
    )  # missing contributes nothing
    assert agg.windows == 3
    assert agg.claims == 60  # 10 + 30 + 20
    assert agg.claim_mean_ms == pytest.approx((10 * 50 + 30 * 60 + 20 * 55) / 60)  # n-weighted
    assert agg.claim_max_ms == 90.0
    assert agg.lanes_per_claim == pytest.approx(8.0)
    assert agg.rows_per_claim == pytest.approx((10 * 6 + 30 * 5 + 20 * 4) / 60)
    assert agg.rearm == 4  # 1 + 0 + 3
    assert agg.empty == 3  # 0 + 2 + 1


def test_claim_timing_flows_to_rung_json() -> None:
    rung = LadderRung(index=0, ingress_rate=24.0, hold_seconds=60.0, drain_timeout=150.0)
    drive = _drive(ingress=24.0, acked=1440)
    claim = ClaimTiming(
        windows=5,
        claims=250,
        claim_mean_ms=53.0,
        claim_max_ms=90.0,
        lanes_per_claim=8.0,
        rows_per_claim=6.0,
        rearm=2,
        empty=1,
    )
    report = {**_report(), "claim_timing": claim.to_json_dict()}
    out = build_rung_outcome(rung, drive, _gate(), report)
    assert out.claim == claim
    assert out.to_json_dict()["claim_timing"]["claim_mean_ms"] == 53.0
    # report=None ⇒ empty ClaimTiming (no crash), mirroring the empty-PhaseTiming fallback
    out2 = build_rung_outcome(rung, drive, _gate(), None)
    assert out2.claim.is_empty
    assert out2.to_json_dict()["claim_timing"]["claims"] == 0


# --- D4: the unified-store in_pipeline is de-duped (single store view) so its slope is not N× ----------


def test_in_pipeline_trace_dedups_unified_store_sum(monkeypatch) -> None:
    import asyncio
    from types import SimpleNamespace

    n = 4
    urls = [f"http://h{i}" for i in range(n)]
    stop = asyncio.Event()
    seq = [
        n * 100,
        n * 200,
        n * 300,
        n * 400,
    ]  # each shard reports the SAME whole-store depth; poller SUMS

    class _FakePoller:
        def __init__(self, urls, *a, **k):
            self._i = 0

        async def open(self) -> None:
            pass

        async def close(self) -> None:
            pass

        async def sample_once(self):
            v = seq[self._i] if self._i < len(seq) else seq[-1]
            self._i += 1
            if self._i >= len(seq):
                stop.set()  # deterministic stop after the fixed sequence (no timing race)
            return SimpleNamespace(in_pipeline=v)

    monkeypatch.setattr(_shardcert, "EnginePoller", _FakePoller)
    out: list[list[float]] = []
    asyncio.run(_shardcert._sample_in_pipeline_trace(urls, stop, out, interval=0.001))
    vals = [v for _, v in out]
    # every recorded point is the SINGLE-store view (summed N× ÷ N), never the N× aggregate
    assert vals == [100.0, 200.0, 300.0, 400.0]  # NOT the raw summed [400, 800, 1200, 1600]
    assert float(n * 400) not in vals  # 1600 (the raw summed high point) never appears
    # de-inflating every point divides the least-squares slope by N — the coupling with _SLOPE_FLAT_TOL=0.25
    slope = in_pipeline_slope(out)
    assert slope is not None and slope > 0


def test_peak_sampler_dedups(monkeypatch) -> None:
    import asyncio
    from types import SimpleNamespace

    n = 4
    urls = [f"http://h{i}" for i in range(n)]
    stop = asyncio.Event()

    class _FakePoller:
        def __init__(self, urls, *a, **k):
            self._i = 0

        async def open(self) -> None:
            pass

        async def close(self) -> None:
            pass

        async def sample_once(self):
            self._i += 1
            if self._i >= 3:
                stop.set()
            return SimpleNamespace(in_pipeline=n * 250)  # summed high-water

    monkeypatch.setattr(_shardcert, "EnginePoller", _FakePoller)
    out = [0]
    asyncio.run(_shardcert._sample_in_pipeline_peak(urls, stop, out, interval=0.001))
    assert out[0] == 250  # the SINGLE-store high-water, not n×250


# --- D1 (finding-2 fix): the honest rate uses the RELIABLE engine drain, not the advisory drive drain -


def test_honest_rate_prefers_reliable_engine_drain_over_drive_miss() -> None:
    # The drive's remote await_drain MISSED (None) under load, but the engine store-truth drain IS present (a
    # SUSTAINED rung always has one). The honest rate must use the RELIABLE engine drain, NOT drop the rung
    # from the ceiling — else clears_target_ingress reads False for a fleet that provably cleared the target.
    base = _outcome(600.0, RungVerdict.SUSTAINED)
    rung = type(base)(
        **{
            **base.__dict__,
            "drive_drain_seconds": None,  # remote poll missed under load
            "engine_drain_seconds": 5.0,  # reliable engine store-truth drain
            "hold_seconds": 60.0,
        }
    )
    assert (
        rung.rate_drain_seconds == 5.0
    )  # prefers the reliable engine drain over the missing drive drain
    assert rung.sustainable_ingress_rate == pytest.approx(600.0 * 60.0 / 65.0)  # computed, NOT None
    rep = _rep([rung])
    assert rep.pinned_ingress_rate == pytest.approx(
        600.0 * 60.0 / 65.0
    )  # sustained rung NOT excluded
    assert (
        rep.clears_target_ingress is True
    )  # 553.8 >= 520.833 — the fleet's clear is not mis-reported


def test_build_rung_outcome_reads_engine_drain_and_prefers_it() -> None:
    # The ENGINE_DRAINED gate carries the reliable engine drain; build_rung_outcome folds it into RungOutcome
    # and the honest rate prefers it over the drive report's own (advisory) drain.
    rung = LadderRung(index=0, ingress_rate=600.0, hold_seconds=60.0, drain_timeout=150.0)
    drive = _drive(ingress=600.0, acked=36000)  # drive.drain_seconds == 1.0
    out = build_rung_outcome(rung, drive, {**_gate(), "drain_seconds": 5.0}, None)
    assert out.engine_drain_seconds == 5.0
    assert out.rate_drain_seconds == 5.0  # engine (5.0) preferred over drive (1.0)
    assert out.sustainable_ingress_rate == pytest.approx(600.0 * 60.0 / 65.0)
    assert out.to_json_dict()["engine_drain_seconds"] == 5.0
    # a gate WITHOUT drain_seconds (older engine) falls back to the drive drain
    out2 = build_rung_outcome(rung, drive, _gate(), None)
    assert out2.engine_drain_seconds is None
    assert out2.rate_drain_seconds == 1.0  # drive fallback


# --- D6 (finding-1 fix): the ENGINE_RUNG_REPORT producer attaches BOTH phase AND claim timing -----------


def test_attach_rung_timings_carries_nonempty_claim_timing(tmp_path) -> None:
    # The bug was: run_engine_ladder attached only payload["phase_timing"], so claim_timing was ALWAYS empty
    # in a real run despite the node logs carrying claim lines. _attach_rung_timings must attach BOTH.
    from harness.load.shardcert_ladder import _attach_rung_timings

    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join(
            [
                _phase_line(1, 1.0, 1.0, 1, 1.0, 1.0),  # delivery ramp window (dropped)
                _phase_line(100, 1.5, 9.0, 100, 12.0, 40.0),  # delivery steady window
                _claim_line(1, 999.0, 999.0, 0.0, 0.0, 0, 0),  # claim ramp window (dropped)
                _claim_line(50, 53.0, 90.0, 8.0, 6.0, 2, 1),  # claim steady window
            ]
        ),
        encoding="utf-8",
    )
    payload: dict[str, object] = {}
    _attach_rung_timings(payload, [log])
    assert payload["phase_timing"]["deliveries"] == 100  # type: ignore[index]
    assert payload["claim_timing"]["claims"] == 50  # type: ignore[index]  # NON-empty — the producer fix
    assert payload["claim_timing"]["windows"] == 1  # type: ignore[index]
    # and it flows to the consumer end-to-end
    out = build_rung_outcome(
        LadderRung(index=0, ingress_rate=24.0, hold_seconds=60.0, drain_timeout=150.0),
        _drive(ingress=24.0, acked=1440),
        _gate(),
        payload,
    )
    assert out.claim.claims == 50
