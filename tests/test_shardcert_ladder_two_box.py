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
from harness.load.shardcert import ShardCertDriveReport
from harness.load.shardcert_ladder import (
    TARGET_INGRESS_PER_S,
    ConsolidatedLadderReport,
    LadderRung,
    PhaseTiming,
    RungVerdict,
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
    assert slope_is_draining(0.0) is True
    assert slope_is_draining(-5.0) is True
    assert slope_is_draining(1.0) is True  # exactly at the flat tolerance
    assert slope_is_draining(5.0) is False  # growing
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
    # force the verdict/shape for report-shape tests independent of the drive's actual numbers
    return type(out)(**{**out.__dict__, "verdict": verdict, "is_soak": is_soak})


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
