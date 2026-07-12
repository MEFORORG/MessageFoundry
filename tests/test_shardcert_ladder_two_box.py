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
from harness.load.shardcert import (
    ShardCertDriveReport,
    ShardCertEngineReport,
    _derive_drive_complete_timeout,
    _derive_driver_done_timeout,
    _derive_engine_drained_timeout,
)
from harness.load.shardcert_ladder import (
    TARGET_EVENTS_PER_S,
    ClaimTiming,
    ConsolidatedLadderReport,
    LadderRung,
    PhaseTiming,
    RungVerdict,
    _CLAIM_RE,
    _PHASE_RE,
    _claim_lines,
    _engine_rung_payload,
    _phase_lines,
    _OBSERVER_DISAGREE_TOL,
    aggregate_claim_timing,
    aggregate_phase_timing,
    build_consolidated_report,
    build_rung_outcome,
    classify_rung,
    in_pipeline_slope,
    observers_inconclusive,
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
    handlers: int | None = None,
    delivering: int | None = None,
    acked: int,
    sink_received: int | None = None,
    lane_inversions: int = 0,
    lane_repeats: int = 0,
    lanes_observed: int = 4,
    hold_seconds: float = 60.0,
    drained: bool = True,
) -> ShardCertDriveReport:
    """A synthetic multi-process drive report. Defaults are a clean, lossless rung (S == A*delivering).

    BACKLOG #209: ``handlers`` (H) and ``delivering`` (D) both default to ``dests``, so every test written
    before the split is byte-identical (the pre-#209 graph WAS H = D = dests). The FAN-OUT is D — the
    lossless default and every delivery assertion below key off it, never off ``dests``."""
    h = dests if handlers is None else handlers
    d = dests if delivering is None else delivering
    s = acked * d if sink_received is None else sink_received
    return ShardCertDriveReport(
        shards=("a", "b", "c", "d"),
        dests=dests,
        handlers=h,
        delivering=d,
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


def free_budget_at_hub(acked: int, handlers: int, delivering: int) -> int:
    """The A4b non-delivering-handler strand budget the guard credits at H > D: ``A × max(0, H − D)``.

    At the ADT-hub shape the router selects H handlers but only D DELIVER; the other H − D per message
    self-filter, so up to ``A × (H − D)`` stranded/dead ROUTED rows block ZERO deliveries. The A4b permit
    (:func:`observers_inconclusive`) subtracts from a DELIVERY count (``A × D``), so only strands BEYOND this
    budget can have blocked a real delivery. Mirrors the ``free`` expression in the guard exactly."""
    return acked * max(0, handlers - delivering)


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


def _outcome(
    rate: float,
    verdict: RungVerdict,
    *,
    is_soak: bool = False,
    lanes_observed: int = 4,
    dests: int = 8,
    handlers: int | None = None,
    delivering: int | None = None,
):
    rung = LadderRung(
        index=0, ingress_rate=rate, hold_seconds=60.0, drain_timeout=150.0, is_soak=is_soak
    )
    drive = _drive(
        ingress=rate,
        acked=int(rate * 60),
        lanes_observed=lanes_observed,
        dests=dests,
        handlers=handlers,
        delivering=delivering,
    )
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


def _rep(
    climb,
    soak=None,
    climb_aborted: bool = False,
    soak_aborted: bool = False,
    *,
    dests: int = 8,
    handlers: int | None = None,
    delivering: int | None = None,
) -> ConsolidatedLadderReport:
    # H and D default to dests ⇒ the pre-#209 H = D = dests report, so every existing test is unchanged.
    return build_consolidated_report(
        shards=("a", "b", "c", "d"),
        dests=dests,
        handlers=dests if handlers is None else handlers,
        delivering=dests if delivering is None else delivering,
        driver_count=4,
        sink_count=8,
        climb=climb,
        soak=soak,
        climb_aborted=climb_aborted,
        soak_aborted=soak_aborted,
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


def test_report_target_clearing_events() -> None:
    # B10: 520.83/s is a TOTAL-EVENTS target (45M/day, in + out), NOT an ingress target. At dests=8 each
    # ingress message yields 9 events, so the boundary ingress is 520.833/9 = 57.87/s.
    below = _rep([_outcome(50.0, RungVerdict.SUSTAINED), _outcome(56.0, RungVerdict.COLLAPSED)])
    assert below.sustained_events_per_s == pytest.approx(450.0)  # 50 x 9
    assert below.clears_target_events is False
    above = _rep([_outcome(64.0, RungVerdict.SUSTAINED), _outcome(80.0, RungVerdict.COLLAPSED)])
    assert above.sustained_events_per_s == pytest.approx(576.0)  # 64 x 9
    assert above.clears_target_events is True  # under the OLD ingress gate this read False
    assert math.isclose(TARGET_EVENTS_PER_S, 45_000_000 / 86_400)


@pytest.mark.parametrize(
    ("dests", "handlers", "delivering"),
    [
        # H = D = dests — the pre-#209 shapes. The gate arithmetic is unchanged for every one of them.
        (1, 1, 1),
        (2, 2, 2),
        (4, 4, 4),
        (8, 8, 8),
        (16, 16, 16),
        # BACKLOG #209: the fan-out is now INDEPENDENT of the topology and of the selection width. The
        # boundary must key on D alone — a D=2 graph is a D=2 graph whether it declares 2 connections or 16,
        # and whether the router selects 2 handlers or 20.
        (16, 16, 2),
        (4, 20, 4),  # the reference ADT hub
        (8, 20, 1),
    ],
)
def test_target_gate_fires_exactly_at_total_events_boundary(
    dests: int, handlers: int, delivering: int
) -> None:
    # The A0 falsifier, re-keyed on DELIVERING. The gate must fire exactly at
    # ingress = 520.8333 / (1 + delivering), for every fan-out — and must NOT move when `dests` or
    # `handlers` move at a fixed D. A drain of 0 makes pinned_ingress_rate == the offered rate exactly,
    # isolating the gate arithmetic.
    boundary = TARGET_EVENTS_PER_S / (1 + delivering)

    def rep_at(ingress: float) -> ConsolidatedLadderReport:
        return build_consolidated_report(
            shards=("a", "b", "c", "d"),
            dests=dests,
            handlers=handlers,
            delivering=delivering,
            driver_count=4,
            sink_count=8,
            climb=[_honest_rung(ingress, drain_seconds=0.0)],
            soak=None,
            climb_aborted=False,
            soak_aborted=False,
        )

    assert rep_at(boundary).clears_target_events is True  # >= fires AT the boundary
    assert rep_at(boundary * 1.001).clears_target_events is True
    assert rep_at(boundary * 0.999).clears_target_events is False
    assert rep_at(boundary).sustained_events_per_s == pytest.approx(TARGET_EVENTS_PER_S)


def test_sustained_events_per_s_keys_on_delivering_not_dests_or_handlers() -> None:
    """THE B10 SITE, guarded at the reference hub (BACKLOG #209).

    `sustained_events_per_s` is the number the SYSTEM-REQUIREMENTS §8 decision keys off. One ingress
    message yields itself plus one event per DELIVERED copy — `1 + D`. The two plausible-but-wrong
    multipliers both OVERSTATE it, in the permissive direction:

    * `1 + dests` — the pre-#209 formula. Model the hub by raising `dests` to 20 and it reports `p*21`
      against a truth of `p*5`: a **4.2x** overstatement.
    * `1 + handlers` — reading the router's selection width as the fan-out: `p*21` again.

    The hub here declares 4 destination CONNECTIONS, the router SELECTS 20 handlers, and 4 deliver.
    """
    p = 10.0
    shape: dict[str, int] = {"dests": 4, "handlers": 20, "delivering": 4}
    hub = _rep([_honest_rung(p, drain_seconds=0.0, **shape)], **shape)

    assert hub.pinned_ingress_rate == pytest.approx(p)
    assert hub.sustained_events_per_s == pytest.approx(p * 5)  # 1 + D
    assert hub.sustained_events_per_s != pytest.approx(p * 21)  # NOT 1 + handlers
    assert hub.pinned_outbound_rate == pytest.approx(p * 4)  # deliveries/s = ingress * D
    # The rung agrees with the report — and its txn/msg is the ADR 0051 hub cost, 3 + 2(20) + 2(4).
    assert hub.climb[0].outbound_rate() == pytest.approx(p * 4)
    assert hub.climb[0].txn_per_message == 51

    # And the same D with a 20-connection topology reports the SAME events — dests is not in the math.
    wide_shape: dict[str, int] = {"dests": 20, "handlers": 20, "delivering": 4}
    wide = _rep([_honest_rung(p, drain_seconds=0.0, **wide_shape)], **wide_shape)
    assert wide.sustained_events_per_s == pytest.approx(p * 5)
    assert wide.sustained_events_per_s != pytest.approx(p * 21)


def test_target_gate_is_not_the_old_ingress_gate() -> None:
    # Regression guard on B10 itself: at dests=8 the OLD gate demanded 520.83 ingress/s where the correct
    # demand is 57.87 ingress/s — a 9x phantom. Pin a rate between the two and assert it now clears.
    rep = _rep([_honest_rung(100.0, drain_seconds=0.0)])
    assert 57.87 < 100.0 < TARGET_EVENTS_PER_S  # between the true and the phantom threshold
    assert rep.clears_target_events is True


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


# --- B9: a run whose SOAK collapsed must not report PASS --------------------------------------------


def test_collapsed_soak_reports_soak_not_sustained_not_pass() -> None:
    """B9 (found on redo-pooled-soak12-01, 2026-07-10). `ok` tracks CORRECTNESS only — a throughput ceiling
    is a measurement, not a pass/fail — so a 900s soak that collapsed still exits 0. That is deliberate, but
    it used to serialize as `result: "PASS"` alongside a `pinned_ingress_rate` taken from the 60s climb that
    the soak had just disproved. The exit code keeps its meaning; the LABEL stops lying."""
    climb = [_outcome(10.0, RungVerdict.SUSTAINED)]
    soak = _outcome(12.0, RungVerdict.COLLAPSED, is_soak=True)
    rep = _rep(climb, soak=soak)

    assert rep.correctness_ok is True  # no FIFO inversion / dup
    assert rep.exit_code == 0  # unchanged: throughput is a measurement
    assert rep.soak_ok is False
    assert rep.soak_not_sustained is True
    assert rep.result_label == "SOAK_NOT_SUSTAINED"

    js = rep.to_json_dict()
    assert js["result"] == "SOAK_NOT_SUSTAINED"  # was "PASS" before B9
    assert js["soak_not_sustained"] is True
    assert js["exit_code"] == 0
    assert js["schema_version"] == 4  # v4 (#209): `dests` stopped meaning the fan-out
    assert "SOAK NOT SUSTAINED" in rep.render()


def test_frozen_tail_soak_also_reads_not_sustained() -> None:
    # A FROZEN_TAIL soak (the B7 degraded-drain-gate false negative) did not hold either — soak_ok is
    # verdict==SUSTAINED alone, so it must not read PASS.
    rep = _rep(
        [_outcome(10.0, RungVerdict.SUSTAINED)],
        soak=_outcome(10.0, RungVerdict.FROZEN_TAIL, is_soak=True),
    )
    assert rep.result_label == "SOAK_NOT_SUSTAINED"
    assert rep.exit_code == 0


def test_sustained_and_skipped_soaks_still_pass() -> None:
    sustained = _rep(
        [_outcome(10.0, RungVerdict.SUSTAINED)],
        soak=_outcome(10.0, RungVerdict.SUSTAINED, is_soak=True),
    )
    assert sustained.result_label == "PASS" and sustained.soak_not_sustained is False
    # A legitimately SKIPPED soak (nothing sustained to soak) is benign — not a product signal.
    skipped = _rep([_outcome(10.0, RungVerdict.SUSTAINED)], soak=None)
    assert skipped.result_label == "PASS" and skipped.soak_not_sustained is False
    # The warning lines must NOT appear on a clean run — otherwise a too-broad guard goes unnoticed.
    for text in (sustained.render(), skipped.render()):
        assert "SOAK NOT SUSTAINED" not in text
        assert "SOAK UNCONFIRMED" not in text


def test_inconclusive_soak_is_unconfirmed_not_a_proven_saturation() -> None:
    """B9 / adversarial review. An INCONCLUSIVE soak means the engine store-truth NEVER ARRIVED — a coord
    glitch. It is UNKNOWN, not proven-failed. Labelling it SOAK_NOT_SUSTAINED ("the offered operating point
    did NOT hold") would fabricate a negative the verdict explicitly disclaims — the same fabrication class
    as B6/B7, and one the codebase refuses everywhere else (`classify_rung` will not score an unconfirmed
    rung COLLAPSED; `first_collapse_ingress_rate` requires `engine_reported`).

    It must NOT become SETUP_DEGRADED either: `store_truth_unconfirmed` deliberately inspects only the CLIMB,
    ruling that "a soak-only inconclusive is supplementary — the climb still pinned the ceiling". So it keeps
    exit 0 and gets its own honest label."""
    rep = _rep(
        [_outcome(10.0, RungVerdict.SUSTAINED)],
        soak=_outcome(12.0, RungVerdict.INCONCLUSIVE, is_soak=True),
    )
    assert rep.soak_ok is False  # it did not sustain ...
    assert rep.soak_not_sustained is False  # ... but nothing was PROVEN about it
    assert rep.soak_store_truth_unconfirmed is True
    assert rep.setup_degraded is False  # a soak-only inconclusive is supplementary
    assert rep.exit_code == 0
    assert rep.result_label == "SOAK_UNCONFIRMED"

    text = rep.render()
    assert "SOAK UNCONFIRMED" in text
    assert "SOAK NOT SUSTAINED" not in text  # never assert a negative we cannot substantiate
    js = rep.to_json_dict()
    assert js["result"] == "SOAK_UNCONFIRMED"
    assert js["soak_store_truth_unconfirmed"] is True and js["soak_not_sustained"] is False


def test_soak_not_sustained_never_masks_a_degradation_or_a_correctness_break() -> None:
    # Precedence: an ABORTED soak is a setup degradation (exit 2, no measurement), NOT a product signal —
    # it must not be relabelled SOAK_NOT_SUSTAINED, which would read as a real saturation result.
    aborted = _rep([_outcome(10.0, RungVerdict.SUSTAINED)], soak=None, soak_aborted=True)
    assert aborted.soak_not_sustained is False
    assert aborted.result_label == "SETUP_DEGRADED" and aborted.exit_code == 2
    # A correctness break outranks everything, even with a collapsed soak.
    broke = _rep(
        [_outcome(10.0, RungVerdict.CORRECTNESS_FAIL)],
        soak=_outcome(12.0, RungVerdict.COLLAPSED, is_soak=True),
    )
    assert broke.result_label == "FAIL" and broke.exit_code == 1


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


def test_report_soak_ok_gates_on_verdict_only_not_slope() -> None:
    # B5: soak_ok gates on verdict==SUSTAINED ONLY (the two reliable authorities). The D4-de-inflated
    # in_pipeline slope proved SIGN-UNSTABLE across rates, so a SUSTAINED soak is ok regardless of it.
    climb = [_outcome(24.0, RungVerdict.SUSTAINED)]
    soak = _outcome(24.0, RungVerdict.SUSTAINED, is_soak=True)
    for slope in (-3.5, 0.1, 3.94, 10.98):  # the exact rig slopes, incl. the sign flip
        s = type(soak)(**{**soak.__dict__, "in_pipeline_slope": slope})
        assert _rep(climb, soak=s).soak_ok is True
    # a flat slope cannot rescue a NON-SUSTAINED soak — the verdict is the gate
    not_sustained = type(soak)(
        **{**soak.__dict__, "verdict": RungVerdict.FROZEN_TAIL, "in_pipeline_slope": 0.0}
    )
    assert _rep(climb, soak=not_sustained).soak_ok is False
    # no soak ⇒ soak_ok False
    assert _rep(climb).soak_ok is False


def test_report_soak_slope_still_rendered_as_advisory() -> None:
    # B5: the honest slope is still REPORTED (render's flat/GROWING label) even though it no longer gates.
    soak = _outcome(24.0, RungVerdict.SUSTAINED, is_soak=True)
    soak = type(soak)(**{**soak.__dict__, "in_pipeline_slope": 10.98})
    rep = _rep([_outcome(24.0, RungVerdict.SUSTAINED)], soak=soak)
    text = rep.render()
    assert rep.soak_ok is True  # the gate ignores the slope
    assert "GROWING (slow saturation)" in text  # but it is still shown as advisory context
    assert "+10.98 rows/s" in text


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
    assert "TOTAL-EVENTS target" in text
    # B10: the render must show the total-events arithmetic, not compare ingress against the budget.
    # #209: the multiplier is DELIVERING (here == dests == 8, the default shape ⇒ 216 is unchanged).
    assert "24 ingress/s x (1 + 8 delivering) = 216 events/s" in text
    assert "soak" in text.lower()

    js = rep.to_json_dict()
    assert js["kind"] == "shardcert_ladder_two_box"
    assert js["result"] == "PASS"
    assert js["climb_aborted"] is False
    assert js["ceiling"]["pinned_ingress_rate"] == 24.0
    assert js["ceiling"]["pinned_outbound_rate"] == 192.0
    assert js["ceiling"]["first_collapse_ingress_rate"] == 28.0
    assert js["ceiling"]["sustained_events_per_s"] == 216.0  # 24 ingress x (1 + 8 delivering)
    assert js["ceiling"]["clears_target_events"] is False  # 216 < 520.83
    # B10 (v3): the old ingress-denominated keys are REMOVED, not redefined — a stale consumer must
    # KeyError rather than branch on a boolean whose meaning silently flipped.
    assert "clears_target_ingress" not in js["ceiling"]
    assert "target_ingress_per_s" not in js
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
    dests: int = 8,
    handlers: int | None = None,
    delivering: int | None = None,
):
    """A RungOutcome with an EXPLICIT measured drain + phase windows / sink count for the honest-rate +
    delivered-rate tests — unlike ``_outcome`` (kept-up, drain 0). Phase is ALWAYS set (windows=0 ⇒ no
    delivered rate). The #209 shape passes through (H/D default to ``dests``)."""
    base = _outcome(rate, verdict, dests=dests, handlers=handlers, delivering=delivering)
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


# --- B8: the SOAK rate is the honest sustainable rate, never the raw offered rate --------------------
#
# The real pooled ceiling re-run (2026-07-10), per-rung engine drains from the report JSON. The offered rate
# CLIMBS 16→36 while the honest rate DECLINES 13.05→10.93: the fleet is not gaining headroom, it is absorbing
# a bigger burst and draining it afterwards. r6=40 never drained at all (COLLAPSED, no honest rate).
_POOLED_CLIMB = (
    (16.0, 13.5),
    (20.0, 32.5),
    (24.0, 56.8),
    (28.0, 81.4),
    (32.0, 109.6),
    (36.0, 137.5),
)


def test_pick_soak_rate_uses_honest_rate_not_offered() -> None:
    """B8. A climb rung is a VOLUME test: SUSTAINED proves the fleet DELIVERED offered×dests within
    hold+drain, never that it KEPT UP at the offered rate. Picking the raw offered rate hands the soak a rate
    the fleet was never shown to sustain — and because max() over OFFERED selects the highest sustained rung,
    which is the rung with the LONGEST drain, it selects the MOST overstated estimator on the ladder. On this
    real data the old code picked 36/s against a true ~13/s, so the 900s soak collapsed by construction."""
    climb = [_honest_rung(rate, drain_seconds=d) for rate, d in _POOLED_CLIMB]
    picked = pick_soak_rate(climb)
    assert picked is not None
    assert picked == pytest.approx(13.053, abs=1e-2)  # r0: the MAX of a DECLINING series
    assert picked < 36.0  # never the top sustained rung's offered rate (what the old code returned)

    # The honest series declines monotonically as the offer rises — that is the burst-absorption signature.
    honest = [r.sustainable_ingress_rate for r in climb]
    assert all(a is not None and b is not None and a > b for a, b in zip(honest, honest[1:]))
    # ... so the pin is the max of a decline, NOT a flat series: the top rung is the WORST estimator.
    assert honest[0] == pytest.approx(13.053, abs=1e-2)
    assert honest[-1] == pytest.approx(10.934, abs=1e-2)


def test_pick_soak_rate_equals_the_pinned_ceiling_the_report_publishes() -> None:
    """The contradiction B8 closes. `pinned_ingress_rate` already computed the HONEST rate and published it
    as the ladder's ceiling, while `pick_soak_rate` — forty lines away — fed the soak the OFFERED rate. The
    ladder must not soak at a rate above the ceiling it publishes."""
    climb = [_honest_rung(rate, drain_seconds=d) for rate, d in _POOLED_CLIMB]
    assert pick_soak_rate(climb) == _rep(climb).pinned_ingress_rate


def test_pick_soak_rate_skips_rungs_with_no_measured_drain() -> None:
    """An unmeasured span cannot denominate a rate — mirrors `pinned_ingress_rate`'s own exclusion. A rung
    that never drained has no honest rate precisely BECAUSE it collapsed; it must not poison the pick."""
    climb = [
        _honest_rung(16.0, drain_seconds=13.5),
        _honest_rung(40.0, RungVerdict.COLLAPSED, drain_seconds=None),
    ]
    assert pick_soak_rate(climb) == pytest.approx(13.053, abs=1e-2)
    # An override still wins outright, even with nothing sustained (the deliberate bracket-testing path).
    assert pick_soak_rate(climb, override=12.0) == 12.0


def test_honest_rate_discounts_a_rung_that_only_cleared_via_a_long_drain() -> None:
    # B8: a rung offered 521 that only cleared via a 150 s drain over a 60 s hold sustains 521*60/210 = 149/s.
    # The honest-rate discount is what this asserts; it is INDEPENDENT of the B10 target-units question.
    rep = _rep([_honest_rung(521.0, drain_seconds=150.0, hold=60.0)])
    assert rep.pinned_ingress_rate == pytest.approx(521.0 * 60.0 / 210.0)  # ~148.9, not 521

    # B10: that honest 148.9 ingress/s IS 1340 total events/s at dests=8, so it clears the 45M/day budget.
    # The old gate compared 148.9 against 520.83 and reported NO — the 9x phantom. This is the correction.
    assert rep.sustained_events_per_s == pytest.approx(521.0 * 60.0 / 210.0 * 9.0)
    assert rep.clears_target_events is True


def test_target_gate_keys_off_the_honest_rate_not_the_offered_rate() -> None:
    # The honest-rate discount still governs the gate: two rungs at the SAME offered 60/s ingress differ only
    # in measured drain, and only the kept-up one clears. (60 x 9 = 540 >= 520.83; 30 x 9 = 270 < 520.83.)
    kept_up = _rep([_honest_rung(60.0, drain_seconds=0.0)])
    long_drain = _rep([_honest_rung(60.0, drain_seconds=60.0, hold=60.0)])
    assert kept_up.pinned_ingress_rate == pytest.approx(60.0)
    assert long_drain.pinned_ingress_rate == pytest.approx(30.0)  # 60 * 60/120
    assert kept_up.clears_target_events is True
    assert long_drain.clears_target_events is False


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
    # from the ceiling — else clears_target_events reads False for a fleet that provably cleared the target.
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
        rep.clears_target_events is True
    )  # 553.8 ingress x 9 = 4984 events/s — the fleet's clear is not mis-reported


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


# --- B1: the DRIVER_DONE await timeout is derived from the hold (long soaks are runnable) --------------


def test_derive_driver_done_timeout() -> None:
    # A long soak (hold 700s) derives a timeout well above the old fixed 600s, so it no longer aborts
    # mid-send (which reaped the sinks and manufactured a fake collapse, B3). An explicit override wins.
    assert _derive_driver_done_timeout(700.0, 300.0, None) == 700.0 + 300.0 + 60.0
    assert _derive_driver_done_timeout(60.0, 90.0, None) == 210.0
    assert _derive_driver_done_timeout(60.0, 90.0, 25.0) == 25.0  # explicit override wins


# --- B6: the SINK's DRIVE_COMPLETE bound must dominate every coordinator step, not just the hold --------


def _soak_sink_wait(
    *,
    await_engine_drained: bool = True,
    driver_done_timeout: float | None = None,
    override: float | None = None,
) -> float:
    """The 900s soak's sink bound, at the ladder's own child_ready/engine_drained defaults."""
    return _derive_drive_complete_timeout(
        900.0,
        150.0,
        child_ready_timeout=120.0,
        engine_drained_timeout=300.0,
        await_engine_drained=await_engine_drained,
        driver_done_timeout=driver_done_timeout,
        override=override,
    )


def test_derive_drive_complete_timeout_covers_a_900s_soak() -> None:
    # B6 is B1's sibling and nastier. The sink's await opens at SINK_BOUND — before the other sinks bind,
    # before the senders arm, before DRIVE_GO — and closes only after DRIVER_DONE + the /stats drain + the
    # ENGINE_DRAINED gate. The old FIXED 600.0 therefore fired ~300s into a 900s hold: every sink recorded a
    # partial tally and dropped its socket while the engine was still delivering. And because a sink
    # self-timeout is not a drive CoordTimeout, no RUNG_ABORTED marker is posted, so B3's abort-invalidation
    # never fires: the engine reads a REAL stranded>0 from store-truth and the soak renders a fabricated
    # COLLAPSED, indistinguishable from a genuine product collapse. So the bound must DOMINATE the sum of
    # the coordinator's own step timeouts across that window.
    soak = _soak_sink_wait()
    # 2*120 (sinks bind, senders arm) + (900+150+60 DRIVER_DONE) + 150 (drain) + 300 (engine gate) + 60
    assert soak == 1860.0
    assert soak > 600.0  # the bug: the old fixed default, blown by any hold >~540s
    assert soak > 900.0 + 150.0  # clears the hold + drain outright
    # The sink's window strictly CONTAINS the coordinator's DRIVER_DONE wait, so it must outlast it.
    assert soak > _derive_driver_done_timeout(900.0, 150.0, None)


def test_derive_drive_complete_timeout_climb_rung_and_toggles() -> None:
    # A climb rung (hold 60, drain 150) also clears comfortably — closing the handback's secondary worry
    # that a SLOW-DRAIN rung's SINK_BOUND->DRIVE_COMPLETE wall-time could itself approach the old 600s.
    climb = _derive_drive_complete_timeout(
        60.0,
        150.0,
        child_ready_timeout=120.0,
        engine_drained_timeout=300.0,
        await_engine_drained=True,
    )
    assert climb == 240.0 + 270.0 + 150.0 + 300.0 + 60.0 == 1020.0
    assert climb > 600.0

    # Without the PR-C2 store-truth drain gate the engine_drained term drops out entirely.
    assert _soak_sink_wait(await_engine_drained=False) == 1860.0 - 300.0
    # A driver_done override propagates into the sink's bound (the sink still contains that window).
    assert _soak_sink_wait(driver_done_timeout=25.0) == 240.0 + 25.0 + 150.0 + 300.0 + 60.0
    # An explicit sink override wins outright — the escape hatch, as with driver_done.
    assert _soak_sink_wait(override=42.0) == 42.0


# --- B7: the ENGINE_DRAINED gate wait scales with the drain window it is waiting on ------------------


def test_derive_engine_drained_timeout_scales_with_the_drain_window() -> None:
    # The gate wait must cover the ENGINE's own drain (bounded by the same drain_timeout) + its store read.
    # At the ladder's shipped drain of 150s this reproduces the old fixed 300.0 exactly — no behaviour change
    # for the default run — but a raised drain window now raises the gate with it, instead of outgrowing it.
    assert _derive_engine_drained_timeout(150.0, None) == 300.0  # byte-identical to the old default
    assert (
        _derive_engine_drained_timeout(600.0, None) == 750.0
    )  # the old 300.0 silently under-shot here
    assert _derive_engine_drained_timeout(30.0, None) == 180.0
    assert _derive_engine_drained_timeout(600.0, 42.0) == 42.0  # explicit override wins


def test_a_lost_drain_gate_can_never_produce_a_collapsed_verdict() -> None:
    """GUARD (B7 severity). The obvious reading — "a lost gate makes the drive tally on the advisory /stats
    poller, which zeroes under load, so a frozen tail reads as a collapse" — is WRONG, and B7's fix must NOT
    'correct' it by re-classifying the rung INVALID. `classify_rung` never consumes the poller (its own
    docstring: "The remote poller is NEVER an input"), and COLLAPSED requires the ENGINE's own store-truth to
    say it did not drain. A lost gate cannot touch `engine_ok`; it only removes the barrier, so the sinks may
    tally early — which lands on FROZEN_TAIL: benign, excluded from the ceiling, non-climb-stopping. The real
    cost is a false NEGATIVE (a healthy soak reads soak_ok=False). Hence: derive the wait, don't re-classify.

    The per-cell truth table is covered above; this pins the INVARIANT across the gate-loss scenario."""
    for no_loss in (True, False):  # the sink tally may or may not be short when the barrier is lost
        verdict = classify_rung(
            engine_reported=True,  # store-truth still arrives, via ENGINE_RUNG_REPORT
            engine_ok=True,  # ... and the engine really did drain clean
            no_loss=no_loss,
            lane_inversions=0,
            lane_repeats=0,
        )
        assert verdict is not RungVerdict.COLLAPSED  # never fabricated
        assert not stops_climb(verdict)  # and never halts the climb


# --- B2: an ABORTED soak reads as setup-degraded (exit 2), never a clean PASS with soak=null -----------


def test_report_soak_aborted_exits_setup_code_2() -> None:
    rep = _rep([_outcome(20.0, RungVerdict.SUSTAINED)], soak=None, soak_aborted=True)
    assert rep.soak is None
    assert rep.soak_ok is False
    assert rep.climb_aborted is False
    assert rep.setup_degraded is True
    assert rep.exit_code == 2
    assert rep.to_json_dict()["result"] == "SETUP_DEGRADED"
    assert rep.to_json_dict()["soak_aborted"] is True
    text = rep.render()
    assert "ABORTED" in text
    assert "skipped" not in text
    assert "SETUP-DEGRADED" in text
    assert "during the soak" in text


def test_report_skipped_soak_is_not_degraded() -> None:
    # Guard: a legitimately-skipped soak (no sustained rung to soak) stays a benign exit 0 — distinct from an
    # abort, which the rig bug conflated.
    rep = _rep([_outcome(20.0, RungVerdict.SUSTAINED)], soak=None, soak_aborted=False)
    assert rep.setup_degraded is False
    assert rep.exit_code == 0
    assert "skipped" in rep.render()
    assert "ABORTED" not in rep.render()
    assert rep.to_json_dict()["soak_aborted"] is False


# --- B3: an aborted rung's ENGINE store-truth reads INVALID(abort), never a fabricated collapse --------


def _engine_report(
    *, aborted: bool, drained: bool = False, stranded: int = -1
) -> ShardCertEngineReport:
    return ShardCertEngineReport(
        shards=("a",),
        owned={"a": ["a"]},
        killed_shard=None,
        stranded_nonterminal=stranded,
        queue_breakdown="(rung aborted — store-truth not read)" if aborted else "(clean)",
        drained=drained,
        aborted=aborted,
    )


def test_engine_report_aborted_renders_invalid_not_fail() -> None:
    rep = _engine_report(aborted=True)
    assert rep.ok is False  # not a PASS
    text = rep.render()
    assert "verdict=INVALID(abort)" in text
    assert "verdict=FAIL" not in text  # an abort must NEVER read as a fabricated collapse
    assert "NOT a product collapse" in text


def test_engine_rung_payload_marks_aborted_invalid() -> None:
    p = _engine_rung_payload(_engine_report(aborted=True))
    assert p["aborted"] is True and p["valid"] is False and p["engine_ok"] is False
    p2 = _engine_rung_payload(_engine_report(aborted=False, drained=True, stranded=0))
    assert p2["aborted"] is False and p2["valid"] is True and p2["engine_ok"] is True


# --- A4b: the cross-observer INCONCLUSIVE guard (BACKLOG #219) -----------------------------------------
#
# The ladder has TWO independent observers of a rung's outcome — the ENGINE store-truth tally (drained /
# stranded / dead) and the DRIVE sink socket count (S vs A*dests). When they DISAGREE, or a required
# collector reads zero on a non-zero-volume run, the outcome must downgrade to INCONCLUSIVE rather than be
# silently resolved by trusting one observer (the B-class fabrication). These tests force the disagreement
# in BOTH directions and assert INCONCLUSIVE, and assert that genuine AGREEMENT still yields a real
# SUSTAINED / COLLAPSED — the semantics change must be surgical, not a blanket downgrade.


def test_observers_inconclusive_inert_without_counts() -> None:
    # The boolean truth-table callers pass no counts (sentinel <0) ⇒ the guard is INERT, so the historical
    # classify_rung verdicts are preserved. This is what keeps every pre-A4b test above green.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=-1,
            sink_received=-1,
            delivering=1,
            engine_stranded=0,
            engine_dead_total=0,
        )
        is False
    )
    assert (
        observers_inconclusive(
            engine_ok=True,
            acked=1000,
            sink_received=-1,  # one side missing ⇒ still inert
            delivering=8,
            engine_stranded=0,
            engine_dead_total=0,
        )
        is False
    )


def test_observers_inconclusive_trigger_a_sink_overcounts_engine_permit() -> None:
    # (a) The engine says it could NOT clear the load (stranded=400 ⇒ at most A*dests-400 deliveries can have
    # happened) but the sink observed MORE than that permit beyond slack — a hard inter-observer contradiction.
    # expected = 1000*8 = 8000; permit = 7600; slack = 0.01*8000 = 80; threshold = 7680.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=1000,
            sink_received=8000,  # fully lossless sink while the store says it stranded 400 rows
            delivering=8,
            engine_stranded=400,
            engine_dead_total=0,
        )
        is True
    )


def test_observers_inconclusive_trigger_a_tolerance_boundary() -> None:
    # A benign teardown tail within slack is NOT a contradiction (trust the engine ⇒ COLLAPSED); one delivery
    # beyond the slack IS. permit=7600, slack=80 ⇒ threshold 7680.
    def at(sink_received: int) -> bool:
        return observers_inconclusive(
            engine_ok=False,
            acked=1000,
            sink_received=sink_received,
            delivering=8,
            engine_stranded=400,
            engine_dead_total=0,
        )

    assert at(7680) is False  # exactly at the slack edge
    assert at(7681) is True  # one past ⇒ inconsistent
    assert at(7000) is False  # sink UNDER-counts (a genuine collapse) ⇒ never trips (a)


def test_observers_inconclusive_trigger_a_needs_known_strand_tally() -> None:
    # A collapse whose strand/dead tally is UNKNOWN (sentinel -1) can't compute the permit, so (a) can't
    # detect an over-count — the rung is left to the COLLAPSED branch rather than guessed INCONCLUSIVE.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=1000,
            sink_received=8000,
            delivering=8,
            engine_stranded=-1,  # unknown
            engine_dead_total=-1,
        )
        is False
    )


def test_observers_inconclusive_trigger_b_blind_collector() -> None:
    # (b) The engine store-truth says it delivered a non-zero intake CLEAN, yet the sink — the drive's only
    # reliable delivery observer — counted ZERO. That is a blind/absent collector, not a measured zero.
    assert (
        observers_inconclusive(
            engine_ok=True,
            acked=1000,
            sink_received=0,
            delivering=8,
            engine_stranded=0,
            engine_dead_total=0,
        )
        is True
    )
    # But a genuine TOTAL collapse also reads S==0 — there the engine CONFIRMS it (engine_ok False, everything
    # stranded), so it is honestly COLLAPSED, NOT flagged by the blind-collector rule.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=1000,
            sink_received=0,
            delivering=8,
            engine_stranded=1000,  # permit = 8000-8000 = 0; S==0 is consistent
            engine_dead_total=0,
        )
        is False
    )


def test_observers_inconclusive_zero_volume_is_inert() -> None:
    # No non-zero volume to reconcile (acked==0) ⇒ inert (a vacuous run is caught elsewhere, not here).
    assert (
        observers_inconclusive(
            engine_ok=True,
            acked=0,
            sink_received=0,
            delivering=8,
            engine_stranded=0,
            engine_dead_total=0,
        )
        is False
    )


def test_classify_rung_cross_observer_disagreement_is_inconclusive_not_collapsed() -> None:
    # THE semantic change: engine store-truth says COLLAPSED (engine_ok False, stranded>0) but the sink
    # counted every expected delivery (no_loss True / S==A*dests). Pre-A4b this was silently stamped
    # COLLAPSED (trusting the engine, fabricating a bracket); now it is INCONCLUSIVE.
    assert (
        classify_rung(
            engine_reported=True,
            engine_ok=False,
            no_loss=True,
            lane_inversions=0,
            lane_repeats=0,
            acked=1000,
            sink_received=8000,
            delivering=8,
            engine_stranded=400,
            engine_dead_total=0,
        )
        is RungVerdict.INCONCLUSIVE
    )


def test_classify_rung_agreeing_collapse_still_collapsed() -> None:
    # Agreement in the collapse direction: the engine stranded 400 rows AND the sink is short by 400 (both
    # observers see the loss). No contradiction ⇒ a REAL COLLAPSED, not a downgrade.
    assert (
        classify_rung(
            engine_reported=True,
            engine_ok=False,
            no_loss=False,
            lane_inversions=0,
            lane_repeats=0,
            acked=1000,
            sink_received=8000 - 400,
            delivering=8,
            engine_stranded=400,
            engine_dead_total=0,
        )
        is RungVerdict.COLLAPSED
    )


def test_classify_rung_agreeing_sustained_still_sustained() -> None:
    # Agreement in the sustain direction: engine drained clean AND the sink is fully lossless ⇒ SUSTAINED,
    # untouched by the guard.
    assert (
        classify_rung(
            engine_reported=True,
            engine_ok=True,
            no_loss=True,
            lane_inversions=0,
            lane_repeats=0,
            acked=1000,
            sink_received=8000,
            delivering=8,
            engine_stranded=0,
            engine_dead_total=0,
        )
        is RungVerdict.SUSTAINED
    )


def test_classify_rung_blind_collector_is_inconclusive_not_frozen_tail() -> None:
    # A "frozen tail" with ZERO deliveries on a non-zero, engine-confirmed-clean run is not a latency tail —
    # it is a blind sink collector ⇒ INCONCLUSIVE, never a benign FROZEN_TAIL (which would let the climb read
    # it as sustained-adjacent).
    assert (
        classify_rung(
            engine_reported=True,
            engine_ok=True,
            no_loss=False,
            lane_inversions=0,
            lane_repeats=0,
            acked=1000,
            sink_received=0,
            delivering=8,
            engine_stranded=0,
            engine_dead_total=0,
        )
        is RungVerdict.INCONCLUSIVE
    )


def test_classify_rung_correctness_still_outranks_cross_observer() -> None:
    # A FIFO inversion / dup outranks everything, even a cross-observer contradiction — the ordering is
    # correctness first, then the store-truth/observer guards.
    assert (
        classify_rung(
            engine_reported=True,
            engine_ok=False,
            no_loss=True,
            lane_inversions=1,  # correctness break present
            lane_repeats=0,
            acked=1000,
            sink_received=8000,
            delivering=8,
            engine_stranded=400,
            engine_dead_total=0,
        )
        is RungVerdict.CORRECTNESS_FAIL
    )


def test_build_rung_outcome_cross_observer_disagreement_inconclusive_with_note() -> None:
    # Integration: a lossless drive (S==A*dests) whose ENGINE store-truth reports a collapse (stranded>0) is
    # a contradiction the classifier must not resolve by trusting one side — build_rung_outcome yields
    # INCONCLUSIVE and records WHY, distinct from the store-truth-unconfirmed INCONCLUSIVE.
    drive = _drive(ingress=28.0, acked=1680)  # sink_received defaults to A*dests = fully lossless
    out = build_rung_outcome(
        _rung(idx=2, rate=28.0),
        drive,
        _gate(engine_ok=False, drained=False, stranded=400),
        None,
    )
    assert out.engine_reported is True  # store-truth DID arrive — this is not the unconfirmed cause
    assert out.verdict is RungVerdict.INCONCLUSIVE
    assert any("cross-observer INCONCLUSIVE" in n for n in out.notes)


def test_build_rung_outcome_agreeing_collapse_still_collapsed() -> None:
    # The engine stranded 400 AND the sink is short by 400 — the observers AGREE, so it stays a real COLLAPSED
    # (regression guard: the guard must not over-fire on a genuine collapse).
    drive = _drive(ingress=28.0, acked=1680, sink_received=1680 * 8 - 400)
    out = build_rung_outcome(
        _rung(idx=2, rate=28.0),
        drive,
        _gate(engine_ok=False, drained=False, stranded=400),
        None,
    )
    assert out.verdict is RungVerdict.COLLAPSED
    assert not any("cross-observer" in n for n in out.notes)


def test_cross_observer_inconclusive_propagates_to_ladder_result_and_json() -> None:
    # A cross-observer INCONCLUSIVE climb rung must propagate exactly like the store-truth-unconfirmed one:
    # store_truth_unconfirmed ⇒ SETUP_DEGRADED / exit 2 (nothing certified), and it EXCLUDES itself from the
    # collapse bracket so it can never fabricate a false ceiling.
    sustained = build_rung_outcome(
        _rung(idx=0, rate=20.0), _drive(ingress=20.0, acked=1200), _gate(), _report()
    )
    disagreeing = build_rung_outcome(
        _rung(idx=1, rate=24.0),
        _drive(ingress=24.0, acked=1440),  # fully lossless sink ...
        _gate(engine_ok=False, drained=False, stranded=400),  # ... but the store says it collapsed
        None,
    )
    assert disagreeing.verdict is RungVerdict.INCONCLUSIVE
    rep = _rep([sustained, disagreeing])
    assert rep.store_truth_unconfirmed is True
    assert (
        rep.first_collapse_ingress_rate is None
    )  # the inconsistent rung never brackets the ceiling
    # the floor is still the honest sustained rung (its drain-discounted rate), never the inconsistent one
    assert rep.pinned_ingress_rate == pytest.approx(sustained.sustainable_ingress_rate)
    assert rep.pinned_rung is sustained
    assert rep.setup_degraded is True
    assert rep.exit_code == 2
    js = rep.to_json_dict()
    assert js["result"] == "SETUP_DEGRADED"
    assert js["store_truth_unconfirmed"] is True
    assert js["schema_version"] == 4  # v4 (#209) — the A4b keys themselves are unchanged/additive
    assert js["climb"][1]["verdict"] == "inconclusive"  # the enum value carries into the JSON


def test_default_observer_tolerance_is_a_small_fraction() -> None:
    # The tolerance is a small fraction of expected deliveries — big enough to absorb a few-delivery tail,
    # small enough that a material contradiction always trips. Pin it so a careless widening turns red.
    assert 0.0 < _OBSERVER_DISAGREE_TOL <= 0.05


# --- BACKLOG #209: routed_fanout != delivered (H != D) ------------------------------------------------
#
# The ladder's delivery arithmetic used to key on `dests`, which was only ever correct because the graph
# hardwired H = N = dests. Now `dests` is TOPOLOGY (outbound CONNECTIONS / sink port-band width) and the
# FAN-OUT is `delivering` (D). Every site that multiplies an intake by a fan-out must use D. These pin the
# ones that can silently fabricate a result: the no-loss identity and the A4b cross-observer guard (the
# 45M/day headline is guarded above by test_sustained_events_per_s_keys_on_delivering_not_dests_or_handlers).


def test_no_loss_expects_A_times_delivering_not_dests() -> None:
    """The no-loss identity is ``S == A * delivering``, NOT ``S == A * dests``.

    The hub shape: 8 destination CONNECTIONS declared, the router selects 20 handlers, only 4 deliver. A
    perfectly healthy rung therefore lands ``A * 4`` copies at the sinks. Keyed on ``dests`` the drive would
    expect ``A * 8``, read a 50% shortfall as LOSS, and NOTHING would ever sustain — the ladder would report
    a collapse at every rate and pin a ceiling of NONE.
    """
    a = 1000
    healthy = _drive(ingress=20.0, acked=a, dests=8, handlers=20, delivering=4, sink_received=a * 4)
    assert healthy.no_loss is True
    assert healthy.ok is True

    # The wrong expectation, made explicit: A*dests is 2x the truth here.
    assert a * healthy.dests == 2 * (a * healthy.delivering)

    # A genuinely short sink (one delivery lost) still FAILS — the re-keying is not a blanket relaxation.
    lossy = _drive(
        ingress=20.0, acked=a, dests=8, handlers=20, delivering=4, sink_received=a * 4 - 1
    )
    assert lossy.no_loss is False

    # And a sink that somehow saw A*dests copies is NOT lossless either — it is over-counted, not healthy.
    over = _drive(ingress=20.0, acked=a, dests=8, handlers=20, delivering=4, sink_received=a * 8)
    assert over.no_loss is False

    # The default shape (H = D = dests) is unchanged: A*dests and A*delivering coincide.
    default = _drive(ingress=20.0, acked=a)
    assert default.no_loss is True and default.sink_received == a * 8


def test_a4b_guard_still_fires_at_H_ne_N() -> None:
    """*** THE SINGLE TEST THAT CATCHES THE SILENT REGRESSION. ***

    A4b (BACKLOG #219): when the ENGINE store-truth says it STRANDED rows but the DRIVE sink counted a
    fully lossless delivery, the two independent observers CONTRADICT each other and the rung must be
    INCONCLUSIVE — never a COLLAPSED bracket fabricated by silently trusting the engine.

    Leave ``observers_inconclusive`` keyed on ``dests`` and, at D < dests, BOTH ``expected`` and ``permit``
    inflate::

        expected = A*dests  = 8000   (truth: A*delivering = 4000)
        permit   = 8000-400 = 7600   (truth: 4000-400     = 3600)
        S        = 4000              (a FULLY lossless run at D=4)
        trigger (a): S > permit + slack  =>  4000 > 7680  =>  FALSE

    ...so trigger (a) CAN NEVER FIRE. The guard is DISARMED — no error, no note, no existing test failure
    (every pre-#209 test runs D == dests, where the two coincide). The rung falls through to ``not
    engine_ok`` and is stamped COLLAPSED: a bracketed ceiling fabricated out of a contradiction. Keyed on D
    it fires::

        expected = 4000, permit = 3600, slack = 40  =>  4000 > 3640  =>  TRUE

    UPDATED (BACKLOG #209, non-delivering-handler strand budget): the UNIT assertions below pin the D-vs-dests
    key and do NOT pass ``handlers`` (so ``free == 0`` and they are byte-identical to before). The END-TO-END
    assertion, however, now flows ``drive.handlers`` (H=20) into the permit, which credits the non-delivering
    budget ``free = A×(H−D) = 16000``. The old end-to-end scenario stranded only 400 rows — WITHIN that budget,
    so it is NOT a contradiction but an honest COLLAPSED (the previously-asserted INCONCLUSIVE there was itself
    the fabricated verdict the fix removes; see
    ``test_a4b_does_not_fabricate_inconclusive_on_a_genuine_H_gt_D_collapse``). To keep this a GENUINE
    contradiction the end-to-end block strands MORE than ``free`` (delivery-bearing excess), so the guard still
    honestly fires INCONCLUSIVE.
    """
    a = 1000
    dests, handlers, delivering = 8, 20, 4
    lossless_at_D = a * delivering  # the sink saw EVERY expected copy

    # The unit: the guard sees the contradiction.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=lossless_at_D,
            delivering=delivering,
            engine_stranded=400,
            engine_dead_total=0,
        )
        is True
    )
    # ...and it is exactly the D-vs-dests substitution that would have disarmed it.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=lossless_at_D,
            delivering=dests,  # the BUG: the topology count standing in for the fan-out
            engine_stranded=400,
            engine_dead_total=0,
        )
        is False
    ), "keyed on dests the A4b guard is silently disarmed at D < dests"

    # The classifier: INCONCLUSIVE, not a fabricated COLLAPSED.
    assert (
        classify_rung(
            engine_reported=True,
            engine_ok=False,
            no_loss=True,
            lane_inversions=0,
            lane_repeats=0,
            acked=a,
            sink_received=lossless_at_D,
            delivering=delivering,
            engine_stranded=400,
            engine_dead_total=0,
        )
        is RungVerdict.INCONCLUSIVE
    )

    # And end-to-end through the integration path, which is where the wiring actually has to be right:
    # build_rung_outcome must hand the guard `drive.delivering`, not `drive.dests`.
    #
    # BACKLOG #209 update: the integration path also passes `drive.handlers` (H=20) into the permit, which
    # credits the non-delivering-handler strand budget `free = A×(H−D) = 1000×16 = 16000`. To be a GENUINE
    # cross-observer contradiction here (fully-lossless sink at D, yet the store stranded DELIVERY-bearing
    # rows) the strand tally must EXCEED that budget — otherwise the strands are all attributable to the 16
    # self-filtering handlers per message and there is no contradiction (that case is an honest COLLAPSED,
    # exercised by `test_a4b_does_not_fabricate_inconclusive_on_a_genuine_H_gt_D_collapse`). Pre-fix the guard
    # subtracted every stranded row from a DELIVERY permit, so any stranded count (400, or 20000) tripped it;
    # the earlier version of this test used stranded=400 and asserted INCONCLUSIVE — that was the fabricated
    # verdict the #209 fix removes. We now strand MORE than the free budget so the contradiction is real.
    stranded_excess = (
        free_budget_at_hub(a, handlers, delivering) + 500
    )  # 16000 + 500, beyond `free`
    drive = _drive(
        ingress=24.0,
        acked=a,
        dests=dests,
        handlers=handlers,
        delivering=delivering,
        sink_received=lossless_at_D,
    )
    assert drive.no_loss is True  # the sink is fully lossless at the TRUE fan-out
    out = build_rung_outcome(
        _rung(idx=1, rate=24.0),
        drive,
        _gate(engine_ok=False, drained=False, stranded=stranded_excess),
        None,
    )
    assert out.verdict is RungVerdict.INCONCLUSIVE, (
        "the A4b cross-observer guard did not fire at H != D — either it is keyed on dests (permit "
        "inflated) or it failed to charge the DELIVERY-bearing strand excess beyond the non-delivering "
        "budget against the permit: the rung was stamped COLLAPSED, a fabricated ceiling bracket"
    )
    assert any("cross-observer INCONCLUSIVE" in n for n in out.notes)

    # The climb must not bracket a ceiling from it (the whole point of INCONCLUSIVE).
    rep = _rep([out], dests=dests, handlers=handlers, delivering=delivering)
    assert rep.first_collapse_ingress_rate is None
    assert rep.store_truth_unconfirmed is True and rep.exit_code == 2


def test_a4b_guard_still_finds_a_genuine_collapse_at_H_ne_N() -> None:
    # The complement: at H != D a REAL collapse (both observers see the loss) must still read COLLAPSED —
    # the D-keying must not turn the guard into a blanket downgrade.
    a = 1000
    drive = _drive(
        ingress=24.0,
        acked=a,
        dests=8,
        handlers=20,
        delivering=4,
        sink_received=a * 4 - 400,  # short by exactly what the engine says it stranded
    )
    out = build_rung_outcome(
        _rung(idx=1, rate=24.0), drive, _gate(engine_ok=False, drained=False, stranded=400), None
    )
    assert out.verdict is RungVerdict.COLLAPSED
    assert not any("cross-observer" in n for n in out.notes)


# --- BACKLOG #209: A4b permit UNIT bug — `expected` is a DELIVERY count (A×D) but stranded/dead are ROW
# counts across ALL stages. At H==D they coincide (every pre-#209 test passed); at H>D routed strands scale
# with H while deliveries scale with D, so subtracting every strand from a DELIVERY permit drives it strongly
# negative and fabricates INCONCLUSIVE on a GENUINE collapse. The fix credits the non-delivering-handler
# strand budget `free = A×(H−D)` (rows whose transform returns None ⇒ block ZERO deliveries) before any strand
# counts against the delivery permit. These four pin: the H==D byte-identity, that a genuine H>D collapse is
# NOT fabricated, that a REAL over-count still fires, and (above) the #209 D-keying regression guard.


def _old_a4b_permit(*, acked: int, delivering: int, stranded: int, dead: int) -> int:
    """The PRE-#209 permit expression the fix must be byte-identical to at H==D: it subtracts EVERY strand and
    dead row from the DELIVERY count, with no non-delivering-handler credit. Used to (a) pin the H==D identity
    and (b) demonstrate the OLD formula's fabricated verdict at H>D."""
    return acked * delivering - max(0, stranded) - max(0, dead)


def test_a4b_permit_is_byte_identical_at_H_equals_D() -> None:
    """At H==D the fixed permit MUST equal the pre-#209 `A*D - stranded - dead` exactly — this PINS that no
    published run (all pre-#209 runs had H==D) can regress. `free = A*max(0,H-D) = 0` at H==D, so the
    non-delivering budget is empty and `blocked == stranded + dead`, folding to the old expression."""
    a, d = 1000, 8
    # A spread of (stranded, dead, sink) tuples at H==D. For each: assert the guard's verdict matches what the
    # OLD `S > (A*D - stranded - dead) + slack` yields, for both engine_ok states the guard reaches.
    slack = int(_OBSERVER_DISAGREE_TOL * a * d)  # 0.01*8000 = 80
    cases = [
        (0, 0, a * d),  # lossless, nothing stranded
        (400, 0, a * d),  # fully lossless sink while store stranded 400 ⇒ contradiction
        (400, 100, a * d - 500),  # sink short by exactly the loss ⇒ honest collapse, agrees
        (400, 0, a * d - 400 + slack),  # exactly at the slack edge
        (400, 0, a * d - 400 + slack + 1),  # one past the edge ⇒ contradiction
        (2000, 0, a * d),  # heavy strand, lossless sink
    ]
    for stranded, dead, sink in cases:
        old_permit = _old_a4b_permit(acked=a, delivering=d, stranded=stranded, dead=dead)
        old_verdict = sink > old_permit + _OBSERVER_DISAGREE_TOL * (a * d)
        # (1) handlers explicitly == delivering (H==D)
        new_h_eq_d = observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=sink,
            delivering=d,
            handlers=d,  # H == D ⇒ free == 0
            engine_stranded=stranded,
            engine_dead_total=dead,
        )
        # (2) handlers UNSET (default 0) — a caller that never passed handlers must also be byte-identical
        new_h_unset = observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=sink,
            delivering=d,
            engine_stranded=stranded,
            engine_dead_total=dead,
        )
        assert new_h_eq_d is old_verdict, (stranded, dead, sink, old_permit)
        assert new_h_unset is old_verdict, (stranded, dead, sink, old_permit)


def test_a4b_does_not_fabricate_inconclusive_on_a_genuine_H_gt_D_collapse() -> None:
    """*** THE HEADLINE. *** A GENUINE H>D collapse where the two observers AGREE must be honestly COLLAPSED,
    NOT fabricated INCONCLUSIVE. The bug: `expected = A*D` (a DELIVERY count) but the engine strands ROUTED
    rows that scale with H. At H=20, D=4 the router selects 20 handlers per message and 16 self-filter, so a
    real collapse strands a large number of NON-delivering routed rows. The OLD permit subtracts every one
    from a delivery count ⇒ permit goes strongly negative ⇒ `S > permit + slack` fires on any nonzero sink ⇒
    the collapse is mislabeled INCONCLUSIVE — a fabricated verdict in the honesty guard itself."""
    a, dests, handlers, delivering = 1000, 8, 20, 4
    # A genuine collapse: the engine stranded a large number of routed rows that are WITHIN the non-delivering
    # budget (they are the self-filtering handlers' rows — they block zero deliveries), and the sink honestly
    # UNDER-counts (S well below A*D). The observers AGREE: loss happened, both saw it.
    free = free_budget_at_hub(a, handlers, delivering)  # 1000*(20-4) = 16000
    stranded = (
        free - 4000
    )  # 12000: large, but WITHIN the non-delivering budget ⇒ blocks 0 deliveries
    sink = (
        a * delivering - 3000
    )  # 4000 - 3000 = 1000: sink honestly under-counts (a real shortfall)
    assert sink > 0 and stranded > 0 and stranded < free  # a real, in-budget collapse

    # The FIX: NOT inconclusive — so classify_rung can honestly stamp it COLLAPSED.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=sink,
            delivering=delivering,
            handlers=handlers,
            engine_stranded=stranded,
            engine_dead_total=0,
        )
        is False
    )
    # The OLD formula (no free budget) WOULD have fabricated INCONCLUSIVE here — proving the bug was real and
    # the fix closes it. old_permit = 4000 - 12000 = -8000; slack = 40; S=1000 > -7960 ⇒ True (fabricated).
    old_permit = _old_a4b_permit(acked=a, delivering=delivering, stranded=stranded, dead=0)
    assert old_permit < 0  # the delivery permit went negative — the tell-tale of the unit bug
    assert sink > old_permit + _OBSERVER_DISAGREE_TOL * (
        a * delivering
    )  # OLD ⇒ True ⇒ INCONCLUSIVE

    # End-to-end: the classifier stamps the honest COLLAPSED, not the fabricated INCONCLUSIVE.
    assert (
        classify_rung(
            engine_reported=True,
            engine_ok=False,
            no_loss=False,
            lane_inversions=0,
            lane_repeats=0,
            acked=a,
            sink_received=sink,
            delivering=delivering,
            handlers=handlers,
            engine_stranded=stranded,
            engine_dead_total=0,
        )
        is RungVerdict.COLLAPSED
    )
    drive = _drive(
        ingress=24.0,
        acked=a,
        dests=dests,
        handlers=handlers,
        delivering=delivering,
        sink_received=sink,
    )
    out = build_rung_outcome(
        _rung(idx=1, rate=24.0),
        drive,
        _gate(engine_ok=False, drained=False, stranded=stranded),
        None,
    )
    assert out.verdict is RungVerdict.COLLAPSED, (
        "a GENUINE H>D collapse was fabricated INCONCLUSIVE — the A4b permit subtracted non-delivering "
        "routed strands from a DELIVERY count and went negative (BACKLOG #209 unit bug)"
    )
    assert not any("cross-observer" in n for n in out.notes)


def test_a4b_still_fires_on_a_real_overcount_at_H_gt_D() -> None:
    """The guard must NOT be neutered by the fix — it must still fire on a genuine over-count at H>D. Three
    proofs it narrowed the guard rather than disabling it:

    (i)  a sink that counts MORE than the store could possibly have delivered (S > A*D + slack) — an impossible
         over-count regardless of strands;
    (ii) a lossless sink (S == A*D) while the engine stranded a count EXCEEDING the free budget; and
    (iii) a lossless sink (S == A*D) while the engine stranded a count WITHIN the free budget — STILL a hard
         contradiction. A fully-lossless sink means every accepted message delivered all D copies, which leaves
         ZERO non-terminal rows; a self-filtering handler's routed row is finalized TERMINAL and never enters
         the ``stranded`` tally, so the ``free`` budget has no in-tally population to absorb. Crediting an
         in-budget strand to ``free`` here would forgive a genuinely-stuck ingress/delivering row as if it
         blocked nothing — the stage-blind over-forgiveness that let a lossless sink coincident with strands
         fabricate a bracketed COLLAPSED. So the lossless-sink clause fires BEFORE ``free`` is consulted."""
    a, handlers, delivering = 1000, 20, 4
    expected = a * delivering  # 4000
    slack = _OBSERVER_DISAGREE_TOL * expected  # 40
    free = free_budget_at_hub(a, handlers, delivering)  # 16000

    # (i) The sink observed MORE than the engine could ever have delivered — over-count, strands irrelevant.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=expected + int(slack) + 1,  # 4041 > A*D + slack
            delivering=delivering,
            handlers=handlers,
            engine_stranded=0,
            engine_dead_total=0,
        )
        is True
    )

    # (ii) A FULLY lossless sink at D, while the engine stranded MORE than the free budget.
    stranded_excess = (
        free + 500
    )  # 16500: 500 beyond what the non-delivering handlers can account for
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=expected,  # fully lossless at the true fan-out
            delivering=delivering,
            handlers=handlers,
            engine_stranded=stranded_excess,
            engine_dead_total=0,
        )
        is True
    )
    # (iii) The SAME lossless sink with strands INSIDE the free budget is STILL a contradiction — a lossless
    # sink cannot coexist with ANY stuck row, and self-filtering handler rows (which `free` models) are
    # terminal, so they never appear in the strand tally to be absorbed. The lossless clause fires regardless.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=expected,
            delivering=delivering,
            handlers=handlers,
            engine_stranded=free - 1,  # 15999: in-budget, but a lossless sink still contradicts it
            engine_dead_total=0,
        )
        is True
    )


def test_a4b_lossless_sink_with_ingress_strand_is_not_forgiven_by_free() -> None:
    """*** THE FINDING. *** A stage-blind ``free`` budget must NOT forgive a delivery-blocking strand that
    coincides with a fully-lossless sink. Scenario: A=1000, H=20, D=4, engine STRANDS 500 rows at INGRESS
    (those 500 messages never routed ⇒ delivered 0 of their 4 copies ⇒ at most (1000-500)*4 = 2000 deliveries
    were physically possible), yet the DRIVE sink reports the FULL A*D = 4000 (lossless). That is a hard
    cross-observer contradiction: a lossless sink is impossible if 500 messages never left ingress.

    The pre-finding formula credited the 500 strands to ``free = A*(H-D) = 16000`` (blocked=0, permit=4000),
    so ``4000 > 4040`` was False, the guard stayed silent, and ``classify_rung`` stamped a FABRICATED
    COLLAPSED — a bracketed ceiling built from a genuine contradiction, the exact B-class defect the guard
    exists to prevent. ``free`` is stage-blind and models a NON-EXISTENT population (self-filtering handler
    rows are terminal, never stranded), so a lossless sink coincident with ANY strand must fire BEFORE ``free``
    is consulted."""
    a, dests, handlers, delivering = 1000, 20, 20, 4
    lossless = (
        a * delivering
    )  # 4000: the sink saw EVERY copy — impossible if 500 msgs stranded at ingress
    ingress_strand = 500
    # Sanity: 500 ingress strands cap physically-possible deliveries at 2000, far below the lossless 4000.
    assert (a - ingress_strand) * delivering < lossless

    # The unit: the guard MUST fire — a lossless sink cannot coexist with a stranded row.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=lossless,
            delivering=delivering,
            handlers=handlers,
            engine_stranded=ingress_strand,  # well within free=16000, but delivery-blocking
            engine_dead_total=0,
        )
        is True
    ), "stage-blind free forgave an ingress strand coincident with a lossless sink"

    # The classifier: INCONCLUSIVE, not the fabricated COLLAPSED.
    assert (
        classify_rung(
            engine_reported=True,
            engine_ok=False,
            no_loss=True,
            lane_inversions=0,
            lane_repeats=0,
            acked=a,
            sink_received=lossless,
            delivering=delivering,
            handlers=handlers,
            engine_stranded=ingress_strand,
            engine_dead_total=0,
        )
        is RungVerdict.INCONCLUSIVE
    )

    # End-to-end: no bracketed ceiling is pinned from the contradiction.
    drive = _drive(
        ingress=24.0,
        acked=a,
        dests=dests,
        handlers=handlers,
        delivering=delivering,
        sink_received=lossless,
    )
    assert drive.no_loss is True
    out = build_rung_outcome(
        _rung(idx=1, rate=24.0),
        drive,
        _gate(engine_ok=False, drained=False, stranded=ingress_strand),
        None,
    )
    assert out.verdict is RungVerdict.INCONCLUSIVE
    assert any("cross-observer INCONCLUSIVE" in n for n in out.notes)
    rep = _rep([out], dests=dests, handlers=handlers, delivering=delivering)
    assert rep.first_collapse_ingress_rate is None  # no fabricated bracket


def test_rung_json_carries_the_shape_and_schema_v4() -> None:
    # The report has to SAY which shape it served, or a reader cannot tell a 4.2x-overstated headline from a
    # correct one. schema_version 4 is the signal that `dests` stopped meaning the fan-out.
    shape: dict[str, int] = {"dests": 4, "handlers": 20, "delivering": 4}
    out = _outcome(20.0, RungVerdict.SUSTAINED, **shape)
    rep = _rep([out], **shape)

    js = rep.to_json_dict()
    rung_js = js["climb"][0]
    assert rung_js["dests"] == 4
    assert rung_js["handlers"] == 20
    assert rung_js["delivering"] == 4
    assert rung_js["txn_per_message"] == 51  # 3 + 2(20) + 2(4) — the ADR 0051 hub cost
    assert rung_js["outbound_expected"] == out.acked * 4  # A * D, never A * dests

    assert js["schema_version"] == 4
    topo = js["topology"]
    assert topo["dests"] == 4 and topo["handlers"] == 20 and topo["delivering"] == 4
    assert topo["txn_per_message"] == 51
    assert topo["events_per_message"] == 5  # 1 + D, NOT 1 + handlers (21)


def test_drive_report_json_carries_the_shape_and_schema_v2() -> None:
    js = _drive(ingress=20.0, acked=1000, dests=8, handlers=20, delivering=4).to_json_dict()
    assert (
        js["schema_version"] == 2
    )  # `dests` stopped meaning the fan-out ⇒ a stale reader must notice
    topo = js["topology"]
    assert (topo["dests"], topo["handlers"], topo["delivering"]) == (8, 20, 4)
    assert topo["txn_per_message"] == 51 and topo["events_per_message"] == 5


def test_render_states_the_right_model() -> None:
    # The topology line used to STATE the wrong model in prose ("delivered = ingress x dests"). An operator
    # reading a hub run would have been told the wrong arithmetic in the same breath as the wrong number.
    rep = _rep(
        [_honest_rung(10.0, drain_seconds=0.0, dests=4, handlers=20, delivering=4)],
        dests=4,
        handlers=20,
        delivering=4,
    )
    text = rep.render()
    assert "delivered = ingress x D" in text
    assert "total events = ingress x (1 + D)" in text
    assert "delivered = ingress x dests" not in text  # the old, wrong prose is gone
    assert "H=20 selected, D=4 delivering" in text
    assert "txn/msg = 3 + 2H + 2D = 51" in text
