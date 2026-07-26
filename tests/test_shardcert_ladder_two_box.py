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
import types

import pytest

from harness.load import coord
from harness.load import shardcert as _shardcert
from harness.load.enginepoll import PoolStats
from harness.load.shardcert import (
    PRODUCT_STORE_POOL_SIZE,
    InboundBandTooNarrow,
    RungFidelity,
    ShardCertDriveReport,
    ShardCertEngineReport,
    _derive_drive_complete_timeout,
    _derive_driver_done_timeout,
    _derive_engine_drained_timeout,
    check_inbound_bands,
    inbound_band_count,
    inbound_band_warning,
    resolve_store_pool_size,
)
from harness.load.shardcert_ladder import (
    _CLAIM_RE,
    _OBSERVER_DISAGREE_TOL,
    _PHASE_RE,
    TARGET_EVENTS_PER_S,
    ClaimTiming,
    ConsolidatedLadderReport,
    LadderRung,
    PhaseTiming,
    RungOutcome,
    RungVerdict,
    _claim_lines,
    _engine_rung_payload,
    _phase_lines,
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
    sent: int | None = None,
    sink_received: int | None = None,
    lane_inversions: int = 0,
    lane_repeats: int = 0,
    lanes_observed: int = 4,
    hold_seconds: float = 60.0,
    drained: bool = True,
    routing: str = "broadcast",
    lanes: int = 1,
    deferred_backpressure: int = -1,
    deferred_schedule: int = -1,
) -> ShardCertDriveReport:
    """A synthetic multi-process drive report. Defaults are a clean, lossless rung (S == A*delivering).

    BACKLOG #209: ``handlers`` (H) and ``delivering`` (D) both default to ``dests``, so every test written
    before the split is byte-identical (the pre-#209 graph WAS H = D = dests). The FAN-OUT is D — the
    lossless default and every delivery assertion below key off it, never off ``dests``.

    ARTIFACT 4 (2026-07-14): ``sent`` defaults to ``acked`` (an engine that accepted everything the drive
    pushed), which is what every pre-existing test meant. Set it EXPLICITLY to model a fidelity failure.

    ⭐ GATE v2: a ``sent`` shortfall NAMES NO CULPRIT BY ITSELF — ``sent`` is ENGINE-PACED (a full send buffer
    means the ENGINE stopped reading its socket), so the ``deferred_*`` split is what arbitrates. The
    defaults are the ``-1`` NOT-RECORDED sentinels, which is the honest default for a synthetic report: a
    shortfall then scores OFFER_SHORTFALL (cause UNATTRIBUTED, fail-closed) and blames NOBODY. To model a
    real RIG shortfall pass ``deferred_schedule=`` dominant; to model the ENGINE refusing to read its socket
    pass ``deferred_backpressure=`` dominant. THE DEFAULTS DELIBERATELY DO NOT BLAME THE RIG — v1 did, and
    that is the defect this gate exists to remove."""
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
        sent=acked if sent is None else sent,
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
        routing=routing,
        lanes=lanes,
        deferred_backpressure=deferred_backpressure,
        deferred_schedule=deferred_schedule,
    )


def _gate(
    *,
    engine_ok: bool = True,
    drained: bool = True,
    stranded: int = 0,
    dead_total: int = 0,
    in_pipeline_final: int = 0,
    ingress_stranded: int | None = None,
    routed_stranded: int | None = None,
    outbound_stranded: int | None = None,
) -> dict[str, object]:
    """The ENGINE_DRAINED drain-gate payload (reliable store-truth the classifier keys off).

    BACKLOG #229: the per-stage strand keys are added ONLY when explicitly supplied, so a gate built without
    them is byte-identical to an older engine payload (the guard then falls back to the stage-blind total)."""
    payload: dict[str, object] = {
        "engine_ok": engine_ok,
        "drained": drained,
        "stranded": stranded,
        "dead_total": dead_total,
        "in_pipeline_final": in_pipeline_final,
    }
    if ingress_stranded is not None:
        payload["ingress_stranded"] = ingress_stranded
    if routed_stranded is not None:
        payload["routed_stranded"] = routed_stranded
    if outbound_stranded is not None:
        payload["outbound_stranded"] = outbound_stranded
    return payload


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
    routing: str = "broadcast",
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
        routing=routing,
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
    routing: str = "broadcast",
    lanes_per_shard: int = 1,
) -> ConsolidatedLadderReport:
    # H and D default to dests ⇒ the pre-#209 H = D = dests report, so every existing test is unchanged.
    return build_consolidated_report(
        shards=("a", "b", "c", "d"),
        dests=dests,
        handlers=dests if handlers is None else handlers,
        delivering=dests if delivering is None else delivering,
        routing=routing,
        lanes_per_shard=lanes_per_shard,
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
            routing="broadcast",
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
    assert (
        js["schema_version"] == 8
    )  # v8 (#229): +the per-stage strand split for the sound H>D A4b permit
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
    assert all(a is not None and b is not None and a > b for a, b in zip(honest, honest[1:]))  # noqa: B905
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
    assert (
        js["schema_version"] == 8
    )  # v8 (#229): +per-stage strand split for the sound H>D A4b permit
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


# --- BACKLOG #229: the SOUND per-stage `blocked` on the under-counting branch -------------------------
#
# #209 credited the non-delivering-handler `free` budget STAGE-BLIND to the opaque `stranded + dead` total,
# so on the UNDER-counting branch (S < A*D) an INGRESS strand (which blocks ALL D copies — the message never
# routed) or an OUTBOUND strand (blocks 1) inside the `free` window was credited as blocking ZERO. That
# MISSED a partial over-count (the sink counts MORE than the store's REAL capacity, yet less than A*D) at
# H>D, returning a definite verdict where it must downgrade to INCONCLUSIVE. The fix threads the per-stage
# split and charges each strand its true weight; the `free` budget is credited against ROUTED strands ONLY,
# so a genuine H>D collapse (routed strands ~A*H) still reads as the honest COLLAPSED the observers agree on.


def test_a4b_ingress_strand_in_free_window_now_downgrades_to_inconclusive_at_H_gt_D() -> None:
    """*** THE #229 HEADLINE. *** An H>D rung: the engine strands rows at INGRESS that fall INSIDE the old
    stage-blind `free` window, and the sink UNDER-counts (S < A*D, so the lossless clause a' does NOT fire)
    but reports MORE than the store's real capacity. The pre-#229 permit credited those ingress strands to
    `free` (blocked 0, permit = A*D) and read the rung as COLLAPSED — a definite verdict fabricated from a
    genuine cross-observer contradiction. The sound per-stage permit charges each ingress strand D copies, so
    the permit is the real capacity and the rung correctly downgrades to INCONCLUSIVE."""
    a, dests, handlers, delivering = 1000, 20, 20, 4
    expected = a * delivering  # 4000
    free = free_budget_at_hub(a, handlers, delivering)  # 1000*(20-4) = 16000
    ingress_strand = 500  # WELL within `free`, so the stage-blind formula forgives it entirely
    # 500 ingress strands ⇒ those 500 messages never routed ⇒ real capacity = (1000-500)*4 = 2000 deliveries.
    real_capacity = (a - ingress_strand) * delivering
    assert real_capacity == 2000
    # The sink reports 3000: BELOW A*D=4000 (a' does not fire) but ABOVE the store's real capacity of 2000 —
    # a hard cross-observer contradiction the stage-blind formula misses.
    sink = 3000
    assert real_capacity < sink < expected
    assert ingress_strand < free  # the tell-tale: the strand sits inside the forgiven `free` window

    # OLD (stage-blind) permit: blocked = max(0, unclear - free) = max(0, 500 - 16000) = 0 ⇒ permit = 4000.
    old_blocked = max(0, ingress_strand - free)
    old_permit = expected - old_blocked
    slack = _OBSERVER_DISAGREE_TOL * expected  # 40
    assert old_blocked == 0 and old_permit == expected
    assert not (
        sink > old_permit + slack
    )  # OLD ⇒ guard SILENT ⇒ falls through to COLLAPSED (fabricated)

    # NEW (sound per-stage) permit: ingress strand blocks D each ⇒ blocked = 500*4 = 2000 ⇒ permit = 2000.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=sink,
            delivering=delivering,
            handlers=handlers,
            engine_stranded=ingress_strand,
            engine_dead_total=0,
            ingress_stranded=ingress_strand,
            routed_stranded=0,
            outbound_stranded=0,
        )
        is True
    )
    # ...and WITHOUT the per-stage split (older payload / sentinel) it stays byte-identical to OLD ⇒ False.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=sink,
            delivering=delivering,
            handlers=handlers,
            engine_stranded=ingress_strand,
            engine_dead_total=0,
        )
        is False
    )

    # End-to-end through the integration path: the gate now carries the per-stage split ⇒ INCONCLUSIVE.
    drive = _drive(
        ingress=24.0,
        acked=a,
        dests=dests,
        handlers=handlers,
        delivering=delivering,
        sink_received=sink,
    )
    assert drive.no_loss is False  # the sink honestly under-counts (S=3000 < A*D=4000)
    out = build_rung_outcome(
        _rung(idx=1, rate=24.0),
        drive,
        _gate(
            engine_ok=False,
            drained=False,
            stranded=ingress_strand,
            ingress_stranded=ingress_strand,
            routed_stranded=0,
            outbound_stranded=0,
        ),
        None,
    )
    assert out.verdict is RungVerdict.INCONCLUSIVE, (
        "the sound per-stage A4b permit did not fire: an ingress strand blocking D copies was credited to "
        "the stage-blind `free` window and a partial over-count was mislabeled COLLAPSED (BACKLOG #229)"
    )
    assert any("cross-observer INCONCLUSIVE" in n for n in out.notes)
    # The rung must be EXCLUDED from the collapse bracket — the whole point of INCONCLUSIVE.
    rep = _rep([out], dests=dests, handlers=handlers, delivering=delivering)
    assert rep.first_collapse_ingress_rate is None
    # The per-stage split is carried onto the record + JSON so the verdict is auditable.
    assert out.engine_ingress_stranded == ingress_strand
    eng_js = out.to_json_dict()["engine"]
    assert isinstance(eng_js, dict)
    assert eng_js["ingress_stranded"] == ingress_strand
    assert eng_js["routed_stranded"] == 0 and eng_js["outbound_stranded"] == 0


def test_a4b_genuine_H_gt_D_routed_collapse_still_reads_collapsed_with_per_stage_split() -> None:
    """The soundness tension: a GENUINE H>D collapse strands ROUTED rows that scale ~A*H (the router selected
    H handlers per stuck message and none ran transform yet). With the per-stage split present the routed
    strands must be credited against `free` so the collapse reads as the honest COLLAPSED both observers
    agree on — NOT re-fabricated INCONCLUSIVE. This is the exact failure the [0,1] routed bound must avoid."""
    a, dests, handlers, delivering = 1000, 8, 20, 4
    free = free_budget_at_hub(a, handlers, delivering)  # 16000
    # A real collapse: 3000 messages got through completely, 700 stuck with ALL 20 routed rows stranded.
    # (1000 accepted here for the ladder; model the strand counts directly.) Routed strands scale with H:
    routed_strand = (
        free - 4000
    )  # 12000: large, WITHIN the non-delivering budget ⇒ blocks 0 net deliveries
    sink = (
        a * delivering - 3000
    )  # 1000: the sink honestly under-counts — observers AGREE loss happened
    assert 0 < routed_strand < free and 0 < sink < a * delivering

    # NEW per-stage permit: routed blocked = max(0, routed_strand - free) = max(0, 12000-16000) = 0 ⇒
    # permit = A*D = 4000; sink=1000 is NOT > 4040 ⇒ guard silent ⇒ honest COLLAPSED (NOT fabricated).
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=sink,
            delivering=delivering,
            handlers=handlers,
            engine_stranded=routed_strand,
            engine_dead_total=0,
            ingress_stranded=0,
            routed_stranded=routed_strand,
            outbound_stranded=0,
        )
        is False
    )
    # End-to-end: COLLAPSED, no cross-observer note.
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
        _gate(
            engine_ok=False,
            drained=False,
            stranded=routed_strand,
            ingress_stranded=0,
            routed_stranded=routed_strand,
            outbound_stranded=0,
        ),
        None,
    )
    assert out.verdict is RungVerdict.COLLAPSED, (
        "a genuine H>D routed-strand collapse was re-fabricated INCONCLUSIVE — the [0,1] routed bound failed "
        "to credit the non-delivering `free` budget against the routed strands (BACKLOG #229 soundness tension)"
    )
    assert not any("cross-observer" in n for n in out.notes)


def test_a4b_outbound_strand_blocks_one_each_at_H_gt_D() -> None:
    """An OUTBOUND strand blocks exactly ONE delivery (a single message→destination row), NOT the stage-blind
    zero the `free` window would forgive. With enough outbound strands the sink's report exceeds real capacity
    ⇒ INCONCLUSIVE; the stage-blind formula (no per-stage split) misses it."""
    a, handlers, delivering = 1000, 20, 4
    expected = a * delivering  # 4000
    slack = _OBSERVER_DISAGREE_TOL * expected  # 40
    outbound_strand = 1500  # each blocks 1 delivery ⇒ real capacity = 4000 - 1500 = 2500
    sink = 3000  # below A*D (a' silent) but above real capacity 2500 ⇒ contradiction
    assert expected - outbound_strand < sink < expected
    # SOUND: blocked = outbound_strand = 1500 ⇒ permit = 2500 ⇒ sink=3000 > 2540 ⇒ fires.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=sink,
            delivering=delivering,
            handlers=handlers,
            engine_stranded=outbound_strand,
            engine_dead_total=0,
            ingress_stranded=0,
            routed_stranded=0,
            outbound_stranded=outbound_strand,
        )
        is True
    )
    # STAGE-BLIND fallback (no per-stage split): free=16000 forgives all 1500 ⇒ permit=4000 ⇒ silent.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=sink,
            delivering=delivering,
            handlers=handlers,
            engine_stranded=outbound_strand,
            engine_dead_total=0,
        )
        is False
    )
    # (the `slack` above is the same 1% band the sound branch clears; kept explicit for the arithmetic.)
    assert slack == 40


def test_a4b_per_stage_permit_is_byte_identical_at_H_equals_D_even_with_split_present() -> None:
    """At H==D the gate MUST take the stage-blind branch even when the per-stage split IS supplied — the sound
    per-stage weights (ingress*D) would otherwise diverge from the pre-#229 `A*D - stranded - dead` and
    regress a published run. `free == 0` at H==D, so the sound branch is deliberately GATED to H>D."""
    a, d = 1000, 8
    slack = _OBSERVER_DISAGREE_TOL * a * d
    # A spread at H==D; for each, the verdict must match the OLD `S > (A*D - stranded - dead) + slack`, and
    # must be IDENTICAL whether or not the per-stage split is supplied (the gate ignores it at H==D).
    cases = [
        (0, 0, 0, 0, a * d - 500),  # honest collapse, agrees
        (300, 0, 0, 300, a * d - 300 + int(slack) + 1),  # one past the edge ⇒ contradiction
        (200, 100, 300, 0, a * d - 700),  # split across ingress+routed, sink short by the loss
    ]
    for ingress_s, routed_s, outbound_s, dead, sink in cases:
        stranded = ingress_s + routed_s + outbound_s
        old_permit = a * d - max(0, stranded) - max(0, dead)
        old_verdict = sink > old_permit + slack
        with_split = observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=sink,
            delivering=d,
            handlers=d,  # H == D ⇒ free == 0 ⇒ stage-blind branch, split IGNORED
            engine_stranded=stranded,
            engine_dead_total=dead,
            ingress_stranded=ingress_s,
            routed_stranded=routed_s,
            outbound_stranded=outbound_s,
        )
        without_split = observers_inconclusive(
            engine_ok=False,
            acked=a,
            sink_received=sink,
            delivering=d,
            handlers=d,
            engine_stranded=stranded,
            engine_dead_total=dead,
        )
        assert with_split is old_verdict, (ingress_s, routed_s, outbound_s, dead, sink)
        assert without_split is old_verdict, (ingress_s, routed_s, outbound_s, dead, sink)


def test_rung_json_carries_the_shape_and_schema_v5() -> None:
    # The report has to SAY which shape it served, or a reader cannot tell a 4.2x-overstated headline from a
    # correct one. schema_version 4 was the signal that `dests` stopped meaning the fan-out; v5 adds
    # `routing`, without which the DERIVED (1, 1) pair a partitioned run reports is indistinguishable from a
    # legal broadcast --handlers 1 --delivering 1 run (a ~50x slower graph).
    shape: dict[str, int] = {"dests": 4, "handlers": 20, "delivering": 4}
    out = _outcome(20.0, RungVerdict.SUSTAINED, **shape)
    rep = _rep([out], **shape)

    js = rep.to_json_dict()
    rung_js = js["climb"][0]
    assert rung_js["dests"] == 4
    assert rung_js["handlers"] == 20
    assert rung_js["delivering"] == 4
    assert rung_js["routing"] == "broadcast"
    assert rung_js["txn_per_message"] == 51  # 3 + 2(20) + 2(4) — the ADR 0051 hub cost
    assert rung_js["outbound_expected"] == out.acked * 4  # A * D, never A * dests

    assert (
        js["schema_version"] == 8
    )  # v8 (#229): +per-stage strand split for the sound H>D A4b permit
    topo = js["topology"]
    assert isinstance(topo, dict)
    assert topo["dests"] == 4 and topo["handlers"] == 20 and topo["delivering"] == 4
    assert topo["routing"] == "broadcast"
    assert topo["txn_per_message"] == 51
    assert topo["events_per_message"] == 5  # 1 + D, NOT 1 + handlers (21)


def test_partitioned_ladder_report_names_its_shape() -> None:
    # ⭐ THE PROVENANCE PIN. A partitioned dests=64 run reports the DERIVED accounting pair (1, 1) — which is
    # EXACTLY what a legal BROADCAST `--dests 64 --handlers 1 --delivering 1` run reports, from a graph that
    # funnels every message onto ONE strict-FIFO lane (~16 msg/s) instead of round-robining 64 (~800+). The
    # topology blocks are otherwise byte-identical; `routing` is the ONLY key that separates them.
    part = _rep(
        [
            _outcome(
                400.0,
                RungVerdict.SUSTAINED,
                dests=64,
                handlers=1,
                delivering=1,
                routing="partitioned",
            )
        ],
        dests=64,
        handlers=1,
        delivering=1,
        routing="partitioned",
    )
    bcast = _rep(
        [_outcome(400.0, RungVerdict.SUSTAINED, dests=64, handlers=1, delivering=1)],
        dests=64,
        handlers=1,
        delivering=1,
    )
    p_topo = part.to_json_dict()["topology"]
    b_topo = bcast.to_json_dict()["topology"]
    assert isinstance(p_topo, dict) and isinstance(b_topo, dict)

    # Everything a pre-v5 reader could see is identical...
    assert {k: v for k, v in p_topo.items() if k != "routing"} == {
        k: v for k, v in b_topo.items() if k != "routing"
    }
    # ...and ONLY `routing` tells them apart.
    assert p_topo["routing"] == "partitioned" and b_topo["routing"] == "broadcast"
    assert "routing=partitioned" in part.render()
    climb = part.to_json_dict()["climb"]
    assert isinstance(climb, list)
    assert climb[0]["routing"] == "partitioned"


def test_drive_report_json_carries_the_shape_and_schema_v3() -> None:
    drive = _drive(
        ingress=20.0,
        acked=1000,
        dests=8,
        handlers=20,
        delivering=4,
        deferred_backpressure=7,
        deferred_schedule=3,
    )
    js = drive.to_json_dict()
    # v2: `dests` != fan-out; v3: +routing; v4: +fidelity gate + G (inbound bands); v5: +store_pool and the
    # DEFERRAL CAUSE SPLIT + sent_ratio ⇒ a stale reader notices rather than silently mis-reading.
    assert js["schema_version"] == 5
    topo = js["topology"]
    assert isinstance(topo, dict)
    assert (topo["dests"], topo["handlers"], topo["delivering"]) == (8, 20, 4)
    assert topo["routing"] == "broadcast"
    assert topo["txn_per_message"] == 51 and topo["events_per_message"] == 5

    # ⭐ v5: every number the gate scores on is RECOVERABLE FROM THE ARTIFACT. An unauditable run is
    # worthless — and the cause split is the ONLY thing that separates an engine bind from a rig shortfall.
    traffic = js["traffic"]
    assert isinstance(traffic, dict)
    assert traffic["deferred_backpressure"] == 7 and traffic["deferred_schedule"] == 3
    # offered = 20/s x 60s = 1,200; sent defaulted to acked = 1,000 ⇒ an 83% sent ratio. The bar the 0.98
    # sent floor is meant to be RE-DERIVED against is now in the artifact instead of being unrecoverable.
    assert traffic["sent_ratio"] == 0.8333
    assert traffic["fidelity_gate_version"] == 2  # a v1 verdict is NOT comparable to a v2 one
    # ⭐ ...and because the deferrals are BACKPRESSURE-dominant (7 > 3), that shortfall is an ENGINE finding,
    # NOT a rig failure: the rung stays DRIVEN and keeps its rate. v1 would have called this exact row a
    # DRIVE_SHORTFALL and voided it.
    assert traffic["fidelity"] == "backpressure_bind"
    assert traffic["fidelity_driven"] is True
    assert traffic["fidelity_admissible"] is False  # driven, but it may not PIN a ceiling
    # ARTIFACT 2: the pool size the run actually used must be reconstructible from the JSON alone.
    pool_js = js["store_pool"]
    assert isinstance(pool_js, dict)
    assert pool_js["product_default"] == PRODUCT_STORE_POOL_SIZE


def test_publishable_gate_applies_the_d4_half_derate() -> None:
    # The RAW gate trips at HALF the ingress a 45M/day CLAIM needs (the Phase-5 D4 derate). Under broadcast
    # this never mattered — the shape capped ingress at ~16 msg/s so the raw gate could never trip at all.
    # Under PARTITIONED (fan-out 1, events = ingress x 2) it trips at 260 ingress/s, and a reader who quoted
    # it would be publishing a 45M/day claim on HALF the required ceiling.
    raw_boundary = TARGET_EVENTS_PER_S / 2  # fan-out 1 ⇒ events = ingress x 2
    just_raw = _rep(
        [_honest_rung(raw_boundary, drain_seconds=0.0, dests=64, handlers=1, delivering=1)],
        dests=64,
        handlers=1,
        delivering=1,
        routing="partitioned",
    )
    assert just_raw.clears_target_events is True  # the RAW measurement clears...
    assert just_raw.clears_target_events_publishable is False  # ...but it is NOT publishable.

    publishable = _rep(
        [_honest_rung(raw_boundary * 2, drain_seconds=0.0, dests=64, handlers=1, delivering=1)],
        dests=64,
        handlers=1,
        delivering=1,
        routing="partitioned",
    )
    assert publishable.clears_target_events is True
    assert publishable.clears_target_events_publishable is True

    js = publishable.to_json_dict()
    assert js["publishable_derate"] == 0.5
    assert js["raw_events_per_s_needed_to_publish"] == round(TARGET_EVENTS_PER_S / 0.5, 3)
    ceiling = js["ceiling"]
    assert isinstance(ceiling, dict)
    assert ceiling["publishable_events_per_s"] == round(ceiling["sustained_events_per_s"] * 0.5, 3)
    assert ceiling["clears_target_events_publishable"] is True


def test_accepted_ingress_rate_is_the_honest_floor_under_the_offered_rate() -> None:
    # `sustainable_ingress_rate` is OFFERED-derived and never looks at `acked`; SUSTAINED only bounds the
    # intake shortfall by _INTAKE_TOL (5%). So AT the ceiling — exactly where offered and accepted diverge —
    # the pinned figure can overstate what was truly accepted. Both must be emitted.
    rung = LadderRung(index=0, ingress_rate=100.0, hold_seconds=60.0, drain_timeout=150.0)
    drive = _drive(ingress=100.0, acked=5_700, hold_seconds=60.0)  # 5% under the 6,000 offered
    out = build_rung_outcome(rung, drive, _gate(), _report())

    assert out.sustainable_ingress_rate is not None and out.accepted_ingress_rate is not None
    # offered-derived == 100 x 60/61; accepted-derived == 5700/61 — the accepted one is the honest FLOOR.
    assert out.accepted_ingress_rate < out.sustainable_ingress_rate
    assert out.accepted_ingress_rate == pytest.approx(5_700 / 61.0)
    assert out.to_json_dict()["accepted_ingress_rate"] == round(5_700 / 61.0, 3)


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


# =====================================================================================================
# THE FOUR BENCH ARTIFACTS (2026-07-14). Ten pre-registered falsifiers hunted the ENGINE for a
# throughput wall. Then five separate HARNESS artifacts turned up, each able to MANUFACTURE a fake
# ceiling. #1 (the shardcert router broadcasting to every destination) is fixed in #1042. These pin the
# other four. Each one, left in, would have commissioned an engine build against a bench bug.
# =====================================================================================================


# --- ARTIFACT 2: the store pool was pinned at 1/5 of the product default, and recorded nowhere --------


def test_store_pool_defaults_to_the_product_default_not_the_hardcoded_eight() -> None:
    """⭐ THE DEFAULT MOVED, DELIBERATELY. The bench pinned ``MEFOR_STORE_POOL_SIZE=8`` with a bare
    ``setdefault`` at two sites. The pool is per shard PROCESS, so a 4-shard fleet ran on 32 concurrent
    store connections against a product posture of 4 x 40 = 160. At a ~12 ms round-trip and 7 txn/message
    that caps ingress around 380 msg/s — AND THE CAP IS FLAT IN L, which is exactly what a pooled-claim
    wall looks like in every column we have ever plotted."""
    assert (
        PRODUCT_STORE_POOL_SIZE == 40
    )  # StoreSettings.pool_size — read from the model, not copied
    assert resolve_store_pool_size({}, None) == PRODUCT_STORE_POOL_SIZE
    assert resolve_store_pool_size({}, None) != 8  # the value that would have faked the wall


def test_store_pool_explicit_override_wins_and_is_sweepable() -> None:
    # The fix is NOT a silent bump to 40 — it is that the pool became an EXPLICIT, SWEEPABLE variable.
    assert (
        resolve_store_pool_size({}, 8) == 8
    )  # reproduce the old posture ON PURPOSE, on the record
    assert resolve_store_pool_size({}, 160) == 160
    assert resolve_store_pool_size({"MEFOR_STORE_POOL_SIZE": "12"}, 96) == 96  # flag beats ambient
    with pytest.raises(ValueError):
        resolve_store_pool_size({}, 0)


def test_store_pool_ambient_env_is_still_honoured_exactly_as_setdefault_did() -> None:
    # `setdefault` let an operator pin the pool out-of-band. That MUST keep working — only the DEFAULT
    # moved. Precedence: explicit flag > ambient env > product default.
    assert resolve_store_pool_size({"MEFOR_STORE_POOL_SIZE": "64"}, None) == 64
    assert resolve_store_pool_size({}, None, environ={"MEFOR_STORE_POOL_SIZE": "24"}) == 24
    # A garbage ambient value is LOUD, never silently the default (a bad pin must not read as a good one).
    with pytest.raises(ValueError):
        resolve_store_pool_size({"MEFOR_STORE_POOL_SIZE": "lots"}, None)
    with pytest.raises(ValueError):
        resolve_store_pool_size({"MEFOR_STORE_POOL_SIZE": "0"}, None)


def _pool_sample(**over: object) -> object:
    """A synthetic drain-time EngineSample carrying a pool snapshot (what the poller hands PoolStats)."""
    base: dict[str, object] = {
        "pool_max_size": 40,
        "pool_size": 40,
        "pool_idle_min": 12,
        "pool_shards_reporting": 4,
        "pool_acquire_wait_count": 100_000,
        "pool_acquire_wait_mean_ms": 0.0135,  # the STEP-2 measured baseline: no queueing
        "pool_wait_p95_max_ms": 0.02,
        "pool_wait_p99_max_ms": 0.05,
        "pool_wait_max_ms": 1.2,
    }
    return types.SimpleNamespace(**{**base, **over})


def _engine_report_with_pool(pool: PoolStats) -> ShardCertEngineReport:
    return ShardCertEngineReport(
        shards=("a", "b", "c", "d"),
        owned={s: [] for s in "abcd"},
        killed_shard=None,
        stranded_nonterminal=0,
        queue_breakdown="QUEUE",
        drained=True,
        dead_total=0,
        drain_seconds=1.0,
        pool=pool,
    )


def test_pool_tripwire_is_silent_at_the_measured_baseline() -> None:
    # The 0.0135 ms baseline is the run where the pool provably was NOT the constraint (560 txn/s against
    # 32 connections = ~21% utilisation). A tripwire that fires there is a fake instrument.
    pool = PoolStats.from_sample(_pool_sample(), requested=40)
    assert pool.measured is True
    assert pool.tripped is False
    assert pool.trip_reason is None
    assert pool.requested_matches_engine is True


def test_pool_tripwire_fires_on_p95_the_primary_bar() -> None:
    """The PRIMARY bar is p95, NOT the mean. ``AcquireWaitHistogram.record()`` fires on EVERY acquire, not
    only ones that WAITED — so ``count`` is really a store-round-trip counter and ``mean_ms`` is DILUTED by
    the flood of zero-wait acquires. A pool that is dry 5% of the time, blocking hard when it is, still
    shows a small mean. Gating on the mean alone would be a fake instrument; p95 catches it."""
    bound = PoolStats.from_sample(_pool_sample(pool_wait_p95_max_ms=7.5), requested=8)
    assert bound.tripped is True
    assert bound.trip_reason is not None
    assert "p95" in bound.trip_reason and "THE POOL IS THE CONSTRAINT" in bound.trip_reason
    # ...and the mean stays a SECONDARY bar that can still fire on its own.
    mean_bound = PoolStats.from_sample(_pool_sample(pool_acquire_wait_mean_ms=2.0), requested=8)
    assert mean_bound.tripped is True
    assert mean_bound.trip_reason is not None and "mean" in mean_bound.trip_reason


def test_pool_tripwire_abstains_when_the_pool_was_never_measured() -> None:
    # An unmeasured pool is UNKNOWN, never INNOCENT. `tripped` False here means "no evidence", and the rung
    # note says so — the gate must not read absent data as "no queueing" (the dead-gate failure mode).
    unmeasured = PoolStats(requested=40)
    assert unmeasured.measured is False
    assert unmeasured.tripped is False and unmeasured.trip_reason is None
    assert "not measured" in unmeasured.render()


def test_pool_size_mismatch_between_harness_and_engine_is_a_finding() -> None:
    # Recording what we ASKED for is not the same as knowing what we GOT. /status reports the engine's own
    # configured maximum; a divergence means MEFOR_STORE_POOL_SIZE never reached the shard processes.
    mismatch = PoolStats.from_sample(_pool_sample(pool_max_size=8), requested=40)
    assert mismatch.requested_matches_engine is False
    assert "REQUESTED != ENGINE" in mismatch.render()


def test_effective_pool_size_is_recoverable_from_the_report_json() -> None:
    """⭐ A run whose pool size is not recoverable from its own artifact is UNAUDITABLE. This walks the REAL
    wire: the engine report -> the ENGINE_RUNG_REPORT payload -> build_rung_outcome -> the JSON."""
    payload = _engine_rung_payload(
        _engine_report_with_pool(PoolStats.from_sample(_pool_sample(), requested=40))
    )
    pool_payload = payload["store_pool"]
    assert isinstance(pool_payload, dict)
    assert pool_payload["requested_pool_size"] == 40  # it crosses the coord wire...

    out = build_rung_outcome(_rung(), _drive(ingress=20.0, acked=1200), _gate(), payload)
    pool_js = out.to_json_dict()["store_pool"]
    assert isinstance(pool_js, dict)
    assert pool_js["requested_pool_size"] == 40  # ...and lands in the rung's own JSON
    assert pool_js["engine_max_size"] == 40  # MEASURED from /status, not asserted from our own env
    assert pool_js["tripwire"]["tripped"] is False

    rep = _rep([out])
    store_pool = rep.to_json_dict()["store_pool"]
    assert isinstance(store_pool, dict)
    assert store_pool["requested_pool_size"] == 40
    assert store_pool["product_default"] == PRODUCT_STORE_POOL_SIZE
    assert store_pool["tripped_at_rates"] == []
    assert "store pool: requested=40" in rep.render()


def test_a_pool_bind_is_reported_as_a_pool_bind_not_left_to_look_like_a_claim_wall() -> None:
    """The whole point of ARTIFACT 2. A pool bind strands at outbound, grows claim_mean, and is immune to
    drive and to the drive box's disk — IDENTICAL to the pooled-claim wall in every column we have looked
    at. It would have commissioned the tempdb claim-query rewrite. The tripwire is the discriminator, and
    it has to reach the report an operator actually reads."""
    payload = _engine_rung_payload(
        _engine_report_with_pool(
            PoolStats.from_sample(_pool_sample(pool_wait_p95_max_ms=9.0), requested=8)
        )
    )
    out = build_rung_outcome(_rung(rate=20.0), _drive(ingress=20.0, acked=1200), _gate(), payload)
    assert out.pool.tripped is True
    assert any("THE POOL IS THE CONSTRAINT" in n for n in out.notes)

    store_pool = _rep([out]).to_json_dict()["store_pool"]
    assert isinstance(store_pool, dict)
    assert store_pool["tripwire"]["tripped"] is True
    assert store_pool["tripped_at_rates"] == [20.0]  # NAMED, so the ceiling attributes to the pool


def test_an_unmeasured_pool_says_so_in_the_rung_notes() -> None:
    # No ENGINE_RUNG_REPORT (or an older engine half) ⇒ no pool block. That must READ as "a pool bind cannot
    # be ruled out from this rung", never as silence.
    out = build_rung_outcome(_rung(), _drive(ingress=20.0, acked=1200), _gate(), None)
    assert out.pool.measured is False
    assert any("store pool NOT MEASURED" in n for n in out.notes)


# --- ARTIFACT 3: the ceiling was OFFERED-derived — it reported the PLAN, not the engine ---------------


def test_accepted_derived_ceiling_is_carried_to_the_headline_beside_the_offered_one() -> None:
    """⭐ ARTIFACT 3. ``sustainable_ingress_rate`` is ``ingress_rate x hold / (hold + drain)`` — ``acked``
    NEVER ENTERS IT. #1042 added ``accepted_ingress_rate`` per rung, but it stayed a PASSENGER: ``pinned_rung``
    still selected on the OFFERED figure and every headline (events/s, publishable, the SOAK RATE) keyed off
    it.

    Here the drive pushed the full 6,000 it offered and the engine accepted 5,760 (96% — inside the 5% intake
    tolerance, so the rung is SUSTAINED and ADMISSIBLE). The offered-derived ceiling therefore OVERSTATES the
    accepted one, and it does so precisely AT the ceiling, which is where they diverge."""
    rung = LadderRung(index=0, ingress_rate=100.0, hold_seconds=60.0, drain_timeout=150.0)
    drive = _drive(ingress=100.0, acked=5_760, sent=6_000, hold_seconds=60.0)  # offered = 6,000
    out = build_rung_outcome(rung, drive, _gate(), _report())
    assert out.fidelity_admissible is True  # the gap is INSIDE the gate — it is not voided away
    assert out.verdict is RungVerdict.SUSTAINED

    rep = _rep([out])
    span = 60.0 + 1.0  # hold + the measured drain
    assert rep.pinned_ingress_rate == pytest.approx(
        100.0 * 60.0 / span
    )  # OFFERED-derived (unchanged)
    assert rep.pinned_accepted_ingress_rate == pytest.approx(5_760 / span)  # ACCEPTED-derived

    # ⭐ THE ANTI-REGRESSION: this FAILS if anyone re-derives the new number from `offered`. `offered/span`
    # is 6000/61 — which IS the offered-derived figure. The accepted one must be the smaller, ENGINE-observed
    # quantity, 5760/61.
    assert rep.pinned_accepted_ingress_rate != pytest.approx(6_000 / span)
    assert rep.pinned_accepted_ingress_rate < rep.pinned_ingress_rate
    assert rep.accepted_vs_offered_ratio == pytest.approx(0.96, abs=1e-3)

    ceiling = rep.to_json_dict()["ceiling"]
    assert isinstance(ceiling, dict)
    # BOTH, in the same block, in every currency the offered one is quoted in.
    assert ceiling["pinned_ingress_rate"] == round(100.0 * 60.0 / span, 3)
    assert str(ceiling["pinned_ingress_rate_basis"]).startswith("offered")
    assert ceiling["pinned_accepted_ingress_rate"] == round(5_760 / span, 3)
    assert str(ceiling["pinned_accepted_ingress_rate_basis"]).startswith("accepted")
    assert ceiling["accepted_events_per_s"] == round(5_760 / span * 9, 3)  # x (1 + D), D = 8
    assert ceiling["accepted_vs_offered_ratio"] == round(0.96, 4)
    # ...and the rung still carries its own pair (the #1042 field, unchanged).
    climb_js = rep.to_json_dict()["climb"]
    assert isinstance(climb_js, list)
    assert climb_js[0]["accepted_ingress_rate"] == round(5_760 / span, 3)

    text = rep.render()
    assert "accepted-derived ceiling (from acked, NOT offered)" in text
    assert "OVERSTATES THIS RUN" in text  # 96% < 99% ⇒ the divergence is called out, not buried


def test_accepted_events_gate_can_disagree_with_the_offered_one() -> None:
    """The two ceilings are not decoration: they can return DIFFERENT ANSWERS to the 45M/day question. A run
    that clears the target on what we ASKED FOR and misses it on what the engine TOOK must report both."""
    rate = TARGET_EVENTS_PER_S / 2  # fan-out 1 ⇒ events = ingress x 2; exactly at the raw bar
    offered = round(rate * 60.0)
    rung = LadderRung(index=0, ingress_rate=rate, hold_seconds=60.0, drain_timeout=150.0)
    drive = _drive(
        ingress=rate,
        acked=int(offered * 0.96),  # the engine took 96% — admissible, but under the offer
        sent=offered,
        hold_seconds=60.0,
        dests=64,
        handlers=1,
        delivering=1,
    )
    out = build_rung_outcome(rung, drive, {**_gate(), "drain_seconds": 0.0}, _report())
    rep = _rep([out], dests=64, handlers=1, delivering=1, routing="partitioned")

    assert rep.clears_target_events is True  # on the OFFER...
    assert rep.clears_target_events_accepted is False  # ...but NOT on what the engine accepted.
    ceiling = rep.to_json_dict()["ceiling"]
    assert isinstance(ceiling, dict)
    assert ceiling["clears_target_events"] is True
    assert ceiling["clears_target_events_accepted"] is False


# --- ARTIFACT 4: classify_rung never compared `acked` to `offered` (THE LOAD-BEARING ONE) -------------


def _fidelity_rung(
    *,
    offered_rate: float,
    sent: int,
    acked: int,
    hold: float = 60.0,
    deferred_backpressure: int = -1,
    deferred_schedule: int = -1,
    pool: PoolStats | None = None,
    index: int = 1,
    drained: bool = True,
    engine_ok: bool = True,
) -> RungOutcome:
    """A rung built through the REAL two-box integration path (build_rung_outcome -> classify_rung), so the
    gate is pinned where STEP 5 actually runs — not on a hand-assembled RungOutcome. The ``filling`` gate
    shipped LIVE on the co-located path and DEAD on this one, and nobody noticed for a day.

    The ``deferred_*`` split rides through the SAME path, because that plumbing IS the v2 gate: a
    ``build_rung_outcome`` that drops it scores every shortfall as UNATTRIBUTED and silently loses the
    BACKPRESSURE_BIND finding.

    ``drained=False`` yields a TRUE COLLAPSE (engine store-truth reported and not drained) — needed because
    the realistic pool bind lands on the rung the pool BREAKS, not the one it lets through."""
    rung = LadderRung(
        index=index, ingress_rate=offered_rate, hold_seconds=hold, drain_timeout=150.0
    )
    drive = _drive(
        ingress=offered_rate,
        acked=acked,
        sent=sent,
        hold_seconds=hold,
        deferred_backpressure=deferred_backpressure,
        deferred_schedule=deferred_schedule,
        drained=drained,
    )
    report = _report() if pool is None else {**_report(), "store_pool": pool.to_json_dict()}
    gate = _gate(engine_ok=engine_ok, drained=drained)
    return build_rung_outcome(rung, drive, gate, report)


def test_fidelity_healthy_rung_is_admissible() -> None:
    out = _fidelity_rung(offered_rate=20.0, sent=1200, acked=1200)  # offered == 1200
    assert out.fidelity is RungFidelity.ADMISSIBLE
    assert out.fidelity_admissible is True
    assert out.verdict is RungVerdict.SUSTAINED
    js = out.to_json_dict()
    assert js["fidelity"] == "admissible"
    assert js["fidelity_reason"] is None
    # An admissible rung pins the ceiling exactly as before — the gate adds no drag to a healthy climb.
    assert _rep([out]).pinned_ingress_rate is not None


def test_fidelity_drive_shortfall_is_void_and_is_NOT_an_engine_result() -> None:
    """⭐ THE RIG COULD NOT PUSH IT. Partitioned needs ~520 msg/s of drive against the ~16 the rig pushes
    today, so an UNDER-DRIVEN rung is the DEFAULT EXPECTATION, not an edge case. The engine accepted
    everything that arrived (lossless, drained, S == A*D), so ``classify_rung`` says SUSTAINED — and the
    ceiling built from it is a pure function of the LADDER PLAN.

    ⭐ GATE v2: the DRIVE_SHORTFALL verdict now REQUIRES the deferrals to be dominated by the GENERATOR's own
    tick-lag (``deferred_schedule``) — the sends never reached a connection, so no engine ever saw them. The
    bare ``sent`` shortfall this test used to assert on is NOT sufficient and MUST NOT BE: ``sent`` is
    engine-paced, so v1's "any shortfall ⇒ the rig" rule would have read a REAL ENGINE BACKPRESSURE BIND as
    a rig failure and voided the finding. See the backpressure sibling below, which is the same shortfall
    with the opposite cause and the opposite verdict."""
    out = _fidelity_rung(
        offered_rate=520.0,
        sent=960,
        acked=960,  # offered 31,200; the rig pushed 3%
        deferred_schedule=30_240,  # THE GENERATOR fell behind its own tick — it never reached a socket
        deferred_backpressure=0,  # the engine's buffers were never full: it was never the constraint
    )

    # The verdict machinery is UNCHANGED and STILL says SUSTAINED — that is the defect, demonstrated:
    assert out.verdict is RungVerdict.SUSTAINED
    assert out.no_loss is True

    # ...and the fidelity gate is what catches it.
    assert out.fidelity is RungFidelity.DRIVE_SHORTFALL
    assert out.fidelity_admissible is False
    reason = out.to_json_dict()["fidelity_reason"]
    assert isinstance(reason, str)
    assert "DRIVE SHORTFALL" in reason
    assert "measures the RIG" in reason  # NOT the engine — the distinction IS the point
    assert any("DRIVE SHORTFALL" in n for n in out.notes)

    # VOID FOR THE CEILING: an under-driven climb must not pin anything.
    rep = _rep([out])
    assert rep.pinned_ingress_rate is None
    assert rep.pinned_rung is None
    assert rep.voided_climb == [out]
    fid = rep.to_json_dict()["fidelity"]
    assert isinstance(fid, dict)
    assert fid["all_admissible"] is False
    assert fid["any_drive_shortfall"] is True
    assert fid["any_engine_intake_bind"] is False  # NOT blamed on the engine
    assert fid["any_backpressure_bind"] is False  # v2: nor on engine backpressure
    assert fid["void_rungs"][0]["fidelity"] == "drive_shortfall"
    assert "FIDELITY: 1 of 1 climb rung(s) VOID" in rep.render()

    # v2: the CAUSE is in the artifact, so the verdict is auditable rather than asserted. And this rung
    # established NO RATE — it can neither pin nor bracket.
    rung_js = out.to_json_dict()
    assert rung_js["deferred_schedule"] == 30_240 and rung_js["deferred_backpressure"] == 0
    assert rung_js["fidelity_driven"] is False
    assert rep.driven_climb == []
    assert rep.first_collapse_ingress_rate is None


def test_fidelity_engine_intake_bind_is_void_and_IS_an_engine_finding() -> None:
    """⭐ THE ENGINE WOULD NOT TAKE IT. The SAME lossless/drained/SUSTAINED serialization as the drive
    shortfall above — and a COMPLETELY DIFFERENT FINDING. The drive pushed the whole plan; the engine
    accepted 80%. That is a bind at INTAKE (ingress/routed are hard-1 per-lane pools keyed on the INBOUND
    connection), and it is NOT the same thing as a lane/claim wall."""
    out = _fidelity_rung(
        offered_rate=100.0, sent=6000, acked=4800
    )  # offered 6,000; sent all; took 80%

    assert out.verdict is RungVerdict.SUSTAINED  # again: the verdict cannot see it
    assert out.fidelity is RungFidelity.ENGINE_INTAKE_BIND
    assert out.fidelity_admissible is False
    reason = out.to_json_dict()["fidelity_reason"]
    assert isinstance(reason, str)
    assert "ENGINE INTAKE BIND" in reason
    assert "REAL finding" in reason and "check G, not L" in reason

    rep = _rep([out])
    assert rep.pinned_ingress_rate is None  # VOID for the ceiling
    fid = rep.to_json_dict()["fidelity"]
    assert isinstance(fid, dict)
    assert fid["any_engine_intake_bind"] is True
    assert fid["any_drive_shortfall"] is False  # NOT blamed on the rig


def test_fidelity_distinguishes_the_two_failures_that_used_to_serialise_identically() -> None:
    """THE assertion the whole gate exists for. Same offered, same engine-side counts, same SUSTAINED
    verdict — and the operator can now tell "my load generator is too small" from "the engine bound".

    v2: the shortfall arm carries its CAUSE (``deferred_schedule`` dominant = the generator never reached a
    socket). Without it the rung is UNATTRIBUTED, not a drive shortfall — see the fail-closed test below."""
    shortfall = _fidelity_rung(
        offered_rate=100.0,
        sent=4800,
        acked=4800,
        deferred_schedule=1200,
        deferred_backpressure=0,
    )
    bind = _fidelity_rung(offered_rate=100.0, sent=6000, acked=4800)

    assert shortfall.verdict is bind.verdict is RungVerdict.SUSTAINED  # indistinguishable before...
    assert shortfall.acked == bind.acked  # ...on identical engine-side counts, even
    assert shortfall.fidelity is not bind.fidelity  # ...and distinguishable now
    assert shortfall.fidelity is RungFidelity.DRIVE_SHORTFALL
    assert bind.fidelity is RungFidelity.ENGINE_INTAKE_BIND


def test_fidelity_is_fail_closed_when_sent_was_never_recorded() -> None:
    # `sent` at the -1 sentinel (an older drive report / a synthetic record) is UNKNOWN — and UNKNOWN is
    # VOID, never a silent skip. A gate that abstains into "pass" is a dead gate that reads like a live one.
    out = _fidelity_rung(offered_rate=20.0, sent=-1, acked=1200)
    assert out.fidelity is RungFidelity.UNKNOWN
    assert out.fidelity_admissible is False
    assert _rep([out]).pinned_ingress_rate is None
    reason = out.to_json_dict()["fidelity_reason"]
    assert isinstance(reason, str) and "never a pass" in reason


def test_an_under_driven_climb_no_longer_pins_a_ceiling_from_the_plan() -> None:
    """⭐ THE MONEY TEST. Four climb rungs, every one lossless and drained and SUSTAINED, every one driven at
    ~3% of its offered rate. Before the gate this climb pinned a ceiling at the TOP rung's offered rate — a
    number the rig never once pushed — and then SOAKED at it. Now it pins NOTHING, and says why."""
    climb = [
        _fidelity_rung(offered_rate=rate, sent=960, acked=960)
        for rate in (100.0, 200.0, 400.0, 520.0)
    ]
    assert all(r.verdict is RungVerdict.SUSTAINED for r in climb)  # every rung "sustained"
    rep = _rep(climb)
    assert rep.pinned_ingress_rate is None
    assert rep.sustained_events_per_s is None
    assert rep.clears_target_events is False
    assert rep.publishable_events_per_s is None
    assert len(rep.voided_climb) == 4
    # ...and the SOAK is not armed at a fictional rate either (it used to soak the offered figure).
    assert pick_soak_rate(climb) is None


def test_fidelity_gate_fires_on_the_two_box_path_specifically() -> None:
    """⭐ THE `filling` REPEAT-FAILURE GUARD. ``ShardCertStepRecord.filling`` is LIVE on the co-located ladder
    and explicitly DEAD on the two-box one (``ShardCertDriveReport.ceiling`` passes ``filling=False #
    ABSTAIN``) — and the two-box path is the ONLY path STEP 5 runs. This pins the fidelity gate to the
    two-box record type END TO END: the drive report computes it, ``build_rung_outcome`` carries it onto the
    RungOutcome, and the consolidated report ACTS on it."""
    drive = _drive(
        ingress=520.0,
        acked=960,
        sent=960,
        hold_seconds=60.0,
        deferred_schedule=30_240,
        deferred_backpressure=0,
    )
    assert drive.fidelity is RungFidelity.DRIVE_SHORTFALL  # (1) the DRIVE report itself
    traffic = drive.to_json_dict()["traffic"]
    assert isinstance(traffic, dict)
    assert traffic["fidelity_admissible"] is False
    # v2: the CAUSE SPLIT is in the drive report's own traffic block, or nothing downstream can attribute.
    assert traffic["deferred_schedule"] == 30_240 and traffic["deferred_backpressure"] == 0

    out = build_rung_outcome(_rung(rate=520.0), drive, _gate(), _report())
    assert out.sent == 960  # (2) `sent` actually CROSSED into the two-box rung record
    # ⭐ ...AND SO DID THE CAUSE SPLIT. This is the exact plumbing the v2 gate rests on: a build_rung_outcome
    # that drops these scores EVERY shortfall as UNATTRIBUTED and silently loses the BACKPRESSURE_BIND
    # finding — a dead gate that reads exactly like a live one, which is this file's signature defect.
    assert out.deferred_schedule == 30_240 and out.deferred_backpressure == 0
    assert out.fidelity is RungFidelity.DRIVE_SHORTFALL

    rep = _rep([out])  # (3) ...and the CEILING acts on it
    assert rep.pinned_ingress_rate is None
    fid = rep.to_json_dict()["fidelity"]
    assert isinstance(fid, dict)
    assert fid["all_admissible"] is False


# --- ARTIFACT 5: the INBOUND pool (G) is narrower than the outbound one (L), and was never recorded ---


def test_inbound_band_warning_fires_exactly_when_G_is_below_L() -> None:
    """``G = shards x lanes_per_shard`` is the width of the INGRESS and ROUTED hard-1 per-lane pools;
    ``L = dests`` is the OUTBOUND one. The lane-scaling law applies to ALL THREE. At the SHIPPED DEFAULTS
    (4 shards, 1 lane, 8 dests) G = 4 < L = 8 — so a destination sweep ALREADY plateaus on the inbound pool
    and manufactures what reads, column for column, as an outbound/pooled-claim wall."""
    assert inbound_band_count(4, 1) == 4
    assert inbound_band_count(4, 4) == 16

    warn = inbound_band_warning(4, 1, 8)  # ⭐ the shipped default IS the narrow case
    assert warn is not None
    assert "INBOUND BAND NARROWER" in warn
    assert "G = shards(4) x lanes_per_shard(1) = 4" in warn and "L = dests(8)" in warn
    assert "--lanes-per-shard (>= 2)" in warn  # ceil(8/4) — the fix, stated in the message

    assert inbound_band_warning(4, 2, 8) is None  # G == L ⇒ inbound is no longer the narrow pool
    assert inbound_band_warning(4, 8, 8) is None  # wider still


def test_inbound_band_check_warns_by_default_and_refuses_only_under_strict() -> None:
    """It CANNOT be a hard refusal by default: G < L is TRUE at the documented command line, so a refusal
    would red every existing invocation and every existing test. Warn + record by default; refuse only for a
    deliberate lane sweep, which is where silently measuring the ingress pool wastes the whole experiment."""
    assert check_inbound_bands(4, 1, 8) is not None  # warns (to stderr) and RETURNS the note
    assert check_inbound_bands(4, 2, 8) is None  # nothing to say
    with pytest.raises(InboundBandTooNarrow):
        check_inbound_bands(4, 1, 8, strict=True)
    assert check_inbound_bands(4, 2, 8, strict=True) is None  # strict does NOT fire when G >= L


def test_G_and_L_are_both_recorded_in_the_report_json() -> None:
    """G was computed on BOTH boxes and recorded on NEITHER: the engine derived ``lanes`` from the built
    graph and posted it in SHARDS_READY; the drive read it, sliced sender bands with it, and dropped it. So a
    plateau could not be attributed to the right pool from the artifact alone."""
    drive = _drive(ingress=20.0, acked=1200, dests=8, lanes=1)
    assert drive.inbound_bands == 4 and drive.inbound_band_narrower is True
    d_topo = drive.to_json_dict()["topology"]
    assert isinstance(d_topo, dict)
    assert d_topo["lanes_per_shard"] == 1
    assert d_topo["inbound_bands"] == 4  # G
    assert d_topo["dests"] == 8  # L
    assert d_topo["inbound_bands_narrower_than_dests"] is True

    out = build_rung_outcome(_rung(), drive, _gate(), _report())
    assert out.lanes_per_shard == 1
    assert out.to_json_dict()["lanes_per_shard"] == 1
    assert any("inbound bands G=4 < outbound lanes L=8" in n for n in out.notes)

    rep = _rep([out], lanes_per_shard=1)
    topo = rep.to_json_dict()["topology"]
    assert isinstance(topo, dict)
    assert topo["inbound_bands"] == 4 and topo["dests"] == 8
    assert topo["inbound_bands_narrower_than_dests"] is True
    assert "INBOUND IS THE NARROW POOL" in rep.render()


def test_a_wide_enough_inbound_band_is_reported_as_such() -> None:
    # The complement: at --lanes-per-shard 2 the inbound side matches the outbound one, the warning is
    # silent, and the report says so — so an operator can PROVE the sweep measured the pool it meant to.
    drive = _drive(ingress=20.0, acked=1200, dests=8, lanes=2)
    assert drive.inbound_bands == 8  # G == L
    assert drive.inbound_band_narrower is False

    out = build_rung_outcome(_rung(), drive, _gate(), _report())
    assert not any("inbound bands" in n for n in out.notes)
    rep = _rep([out], lanes_per_shard=2)
    topo = rep.to_json_dict()["topology"]
    assert isinstance(topo, dict)
    assert topo["inbound_bands"] == 8
    assert topo["inbound_bands_narrower_than_dests"] is False
    assert "INBOUND IS THE NARROW POOL" not in rep.render()


# ======================================================================================================
# ⭐ FIDELITY GATE v2 — THE `sent`-SHORTFALL ARM IS CAUSE-SPLIT
# ======================================================================================================
# v1's rule was `sent < 0.98 x offered => DRIVE_SHORTFALL => VOID the rung`, printing "this rung says
# NOTHING about the engine; it measures the RIG. Add sender workers / drive boxes and re-run."
#
# THAT IS BACKWARDS, AND WRONG IN THE MOST DANGEROUS DIRECTION. `sent` is ENGINE-PACED: it is incremented
# only after a job is popped from a BOUNDED asyncio.Queue, and the write loop `await writer.drain()`s
# before popping the next. When the engine stops reading its socket the TCP window fills, drain() blocks,
# the queue fills, `submit_nowait()` refuses, and the offer lands in `deferred` WITHOUT advancing `sent`.
# The governor's own docstring says so ("if the pool can't accept a send (ENGINE LAGGING) it's counted as
# *deferred*"). So `sent < offered` IS THE SIGNATURE OF ENGINE BACKPRESSURE — and v1 read the single most
# important engine signal, called it a rig failure, VOIDED the rung, and sent the operator out to buy
# hardware. It would have discarded the one real finding the ladder exists to produce.
#
# v2 ATTRIBUTES the shortfall from the `deferred_*` counters instead of ASSUMING it.


def test_backpressure_bind_is_an_ENGINE_finding_and_is_NOT_voided_as_a_rig_failure() -> None:
    """⭐⭐ THE CRUX. The SAME `sent` shortfall v1 blamed on the rig — but the deferrals are dominated by FULL
    SEND BUFFERS, i.e. the ENGINE stopped reading its socket. This is an ENGINE BIND. It may BE the ceiling,
    and it must NOT be voided away as "your load generator is too small"."""
    out = _fidelity_rung(
        offered_rate=100.0,
        sent=4_800,  # offered 6,000 — an 80% sent ratio, IDENTICAL to a drive shortfall's numbers
        acked=4_800,
        deferred_backpressure=1_200,  # ...but the buffers were FULL: THE ENGINE would not take the bytes
        deferred_schedule=0,  # the generator kept up with its own tick perfectly
    )
    assert out.fidelity is RungFidelity.BACKPRESSURE_BIND

    # (1) IT IS NOT THE RIG. This is the assertion v1 would have failed.
    assert out.fidelity is not RungFidelity.DRIVE_SHORTFALL
    reason = out.fidelity_reason
    assert isinstance(reason, str)
    assert "REAL engine finding, NOT a rig failure" in reason
    assert "drive boxes" not in reason  # v1 sent the operator shopping on exactly this signature

    # (2) IT KEEPS ITS RATE LABEL and may BRACKET the ceiling — an engine bind is a FINDING, not a void.
    assert out.fidelity_driven is True
    # (3) ...but it may NOT PIN one: the engine did not HOLD this rate, it REFUSED it.
    assert out.fidelity_admissible is False

    rep = _rep([out])
    assert rep.driven_climb == [out]  # in the BRACKET's candidate set...
    assert rep.admissible_climb == []  # ...and out of the PIN's
    assert rep.pinned_ingress_rate is None

    fid = rep.to_json_dict()["fidelity"]
    assert isinstance(fid, dict)
    assert fid["any_backpressure_bind"] is True
    assert fid["any_drive_shortfall"] is False  # ⭐ THE ENGINE IS NOT BLAMED ON THE RIG
    assert fid["climb_driven_rungs"] == 1 and fid["climb_not_driven_rungs"] == 0


def test_the_same_sent_shortfall_splits_on_CAUSE_alone() -> None:
    """The two rungs are byte-identical in `offered`, `sent` and `acked` — every number v1 looked at. ONLY
    the deferral cause differs, and it flips the verdict from a RIG failure to an ENGINE finding. v1 could
    not express this distinction at all, so it guessed — and it guessed the dangerous way every time."""
    rig = _fidelity_rung(
        offered_rate=100.0,
        sent=4_800,
        acked=4_800,
        deferred_schedule=1_200,
        deferred_backpressure=0,
    )
    engine = _fidelity_rung(
        offered_rate=100.0,
        sent=4_800,
        acked=4_800,
        deferred_backpressure=1_200,
        deferred_schedule=0,
    )

    assert (rig.offered, rig.sent, rig.acked) == (engine.offered, engine.sent, engine.acked)
    assert rig.fidelity is RungFidelity.DRIVE_SHORTFALL
    assert engine.fidelity is RungFidelity.BACKPRESSURE_BIND
    # And the consequence differs where it matters: only the RIG one is void for the BRACKET too.
    assert rig.fidelity_driven is False
    assert engine.fidelity_driven is True


def test_an_unattributed_sent_shortfall_is_FAIL_CLOSED_and_blames_NOBODY() -> None:
    """⭐ FAIL-CLOSED. An older drive half records no `deferred_*` split, so the shortfall's CAUSE IS UNKNOWN.
    "The rig ran out" and "the engine applied backpressure" are OPPOSITE findings, and this rung
    distinguishes NEITHER. The gate must say exactly that — not guess, and above all NOT default to
    DRIVE_SHORTFALL (a silent default to "the rig" is the v1 defect wearing a fresh coat)."""
    out = _fidelity_rung(offered_rate=100.0, sent=4_800, acked=4_800)  # no split recorded

    assert out.fidelity is RungFidelity.OFFER_SHORTFALL
    assert out.fidelity is not RungFidelity.DRIVE_SHORTFALL  # ⭐ NOT a guess against the rig
    assert out.fidelity is not RungFidelity.BACKPRESSURE_BIND  # ⭐ nor a guess against the engine

    reason = out.fidelity_reason
    assert isinstance(reason, str)
    assert "CAUSE NOT ATTRIBUTED" in reason
    assert "we CANNOT say" in reason

    # It VOIDS — for BOTH the pin and the bracket, because no rate was ever established on the wire.
    assert out.fidelity_admissible is False
    assert out.fidelity_driven is False
    rep = _rep([out])
    assert rep.pinned_ingress_rate is None
    assert rep.first_collapse_ingress_rate is None

    fid = rep.to_json_dict()["fidelity"]
    assert isinstance(fid, dict)
    assert fid["any_offer_shortfall"] is True
    assert (
        fid["any_drive_shortfall"] is False
    )  # a silent skip that waves it through would be a BLOCKER
    assert fid["any_backpressure_bind"] is False


def test_a_dead_heat_between_the_two_causes_names_no_culprit() -> None:
    """Equal counters (including 0 == 0: the offers vanished with neither cause recorded) attribute to
    NEITHER side. Naming a culprit on a tie would be a coin-flip dressed up as a measurement."""
    tie = _fidelity_rung(
        offered_rate=100.0,
        sent=4_800,
        acked=4_800,
        deferred_backpressure=600,
        deferred_schedule=600,
    )
    assert tie.fidelity is RungFidelity.OFFER_SHORTFALL
    assert tie.fidelity_driven is False


# ======================================================================================================
# ⭐ BLOCKER 1 — A REAL ENGINE COLLAPSE MUST STILL BRACKET THE CEILING
# ======================================================================================================


def _collapsed_engine_bound_rung(rate: float) -> RungOutcome:
    """The top rung of a GENUINE saturation climb: the drive pushed the whole plan, the engine accepted only
    70% of it (an INTAKE BIND) and the pipeline did not drain (a store-truth COLLAPSE). This is what an
    engine actually saturating LOOKS LIKE — `_is_ceiling` fires on exactly this `acked < offered` shortfall."""
    rung = LadderRung(index=2, ingress_rate=rate, hold_seconds=60.0, drain_timeout=150.0)
    offered = round(rate * 60.0)
    drive = _drive(
        ingress=rate,
        acked=int(offered * 0.70),  # the ENGINE would not take it ⇒ ENGINE_INTAKE_BIND
        sent=offered,  # the drive pushed the WHOLE plan — the rig is NOT the problem
        hold_seconds=60.0,
        drained=False,  # ...and the pipeline did not drain ⇒ a store-truth COLLAPSE
    )
    # engine_ok False + not drained ⇒ classify_rung returns COLLAPSED (store-truth CONFIRMED).
    return build_rung_outcome(
        rung, drive, _gate(engine_ok=False, drained=False, in_pipeline_final=500), _report()
    )


def test_a_real_engine_collapse_still_brackets_the_ceiling() -> None:
    """⭐⭐ BLOCKER 1. An ENGINE SATURATING AT RATE R IS EXACTLY `acked < 0.95 x offered` — that IS this
    project's own model of a ceiling (`_is_ceiling` fires on the same shortfall). So the top rung of a REAL
    saturation climb is normally BOTH `COLLAPSED` and fidelity-ENGINE_BOUND.

    Drawing the bracket from `admissible_climb` threw that rung out and made the report announce "no ceiling
    reached (raise the ladder)" on a run that had MEASURED A GENUINE COLLAPSE — discarding the one result a
    saturation climb exists to produce. AN ENGINE BIND IS A FINDING, NOT A VOID."""
    held = _fidelity_rung(offered_rate=20.0, sent=1_200, acked=1_200)  # SUSTAINED + admissible
    collapsed = _collapsed_engine_bound_rung(40.0)  # the engine saturated here

    assert held.fidelity is RungFidelity.ADMISSIBLE
    assert collapsed.verdict is RungVerdict.COLLAPSED  # a REAL, store-truth-confirmed collapse
    assert collapsed.fidelity is RungFidelity.ENGINE_INTAKE_BIND
    assert collapsed.engine_reported is True

    rep = _rep([held, collapsed])

    # ⭐ THE BRACKET IS SET BY THE COLLAPSE — the engine-bound rung is DRIVEN, so its RATE is real.
    assert collapsed.fidelity_driven is True
    assert rep.first_collapse_ingress_rate == 40.0
    assert rep.ceiling_bracketed is True  # NOT "raise the ladder" — we MEASURED the wall
    assert rep.pinned_ingress_rate is not None  # ...and the FLOOR still comes from the held rung

    # The PIN stays stricter than the BRACKET: an engine-bound rung may not pin a rate it REFUSED.
    assert rep.admissible_climb == [held]
    assert rep.driven_climb == [held, collapsed]
    assert rep.pinned_rung is held

    # It is NOT a "void collapse" — the rate label is real, so nothing is thrown away.
    assert rep.has_void_collapse is False
    assert rep.void_collapsed_climb == []

    ceiling = rep.to_json_dict()["ceiling"]
    assert isinstance(ceiling, dict)
    assert ceiling["first_collapse_ingress_rate"] == 40.0
    assert ceiling["bracketed"] is True
    assert "ENGINE_INTAKE_BIND" in str(ceiling["bracket_basis"]).upper()
    text = rep.render()
    assert "first collapse at: 40 ingress/s" in text
    assert "raise the ladder" not in text  # the pre-fix report said exactly this, on THIS run


def test_a_collapse_at_a_rate_NOBODY_DROVE_still_does_not_bracket() -> None:
    """The other direction, and the reason the bracket is `driven` rather than "any collapse". A rung the RIG
    never pushed collapsed at an OFFERED rate that was never established on the wire. The collapse is real;
    the RATE LABEL is fiction, and only a RATE can bracket a ceiling."""
    held = _fidelity_rung(offered_rate=20.0, sent=1_200, acked=1_200)
    rung = LadderRung(index=2, ingress_rate=520.0, hold_seconds=60.0, drain_timeout=150.0)
    drive = _drive(
        ingress=520.0,
        acked=960,
        sent=960,  # offered 31,200 — the rig pushed 3%
        hold_seconds=60.0,
        drained=False,
        deferred_schedule=30_240,  # ...and THE GENERATOR is why (a genuine rig shortfall)
        deferred_backpressure=0,
    )
    never_driven = build_rung_outcome(
        rung, drive, _gate(engine_ok=False, drained=False, in_pipeline_final=500), _report()
    )

    assert never_driven.verdict is RungVerdict.COLLAPSED  # the collapse IS real
    assert never_driven.fidelity is RungFidelity.DRIVE_SHORTFALL
    assert never_driven.fidelity_driven is False  # ...but no RATE was established

    rep = _rep([held, never_driven])
    assert rep.first_collapse_ingress_rate is None  # so it cannot bracket
    assert rep.ceiling_bracketed is False
    assert rep.has_void_collapse is True  # ...and it is NOT hidden: it is NAMED
    assert rep.void_collapsed_climb == [never_driven]
    assert any("THE COLLAPSE IS REAL" in n for n in rep.void_collapse_notes)


def test_the_two_ladder_callers_agree_that_an_engine_bind_keeps_its_rate() -> None:
    """⭐ THE `filling` REPEAT-FAILURE GUARD, APPLIED TO THE BRACKET. The `filling` gate shipped LIVE on the
    co-located ladder and DEAD on the two-box one, and nobody noticed for a day. The two ladder callers must
    AGREE on the engine-bind case: an ENGINE bind KEEPS its rate (it is a finding); only a NOT-DRIVEN rung
    (drive shortfall / unattributed / unknown) voids it. Reviewers found the two DISAGREED on exactly this."""
    # The predicate BOTH callers split on. The co-located ladder publishes a ceiling_rate for a DRIVEN rung
    # and voids a NOT-DRIVEN one; the two-box bracket admits exactly the same set.
    assert RungFidelity.ADMISSIBLE.driven is True
    assert RungFidelity.ENGINE_INTAKE_BIND.driven is True
    assert RungFidelity.BACKPRESSURE_BIND.driven is True
    assert RungFidelity.DRIVE_SHORTFALL.driven is False
    assert RungFidelity.OFFER_SHORTFALL.driven is False
    assert RungFidelity.UNKNOWN.driven is False
    # `not_driven` is the exact complement — no verdict may fall through BOTH gates, or be counted twice.
    for fid in RungFidelity:
        assert fid.driven is not fid.not_driven

    # ...and the two-box BRACKET uses that predicate — the same split, not a parallel re-implementation.
    collapsed = _collapsed_engine_bound_rung(40.0)
    held = _fidelity_rung(offered_rate=20.0, sent=1_200, acked=1_200)
    rep = _rep([held, collapsed])
    assert [r.fidelity.driven for r in rep.driven_climb] == [True, True]
    assert rep.first_collapse_ingress_rate == 40.0


# ======================================================================================================
# ⭐ BLOCKER 2 — THE STORE-POOL TRIPWIRE MUST TAINT THE VERDICT, NOT MERELY ANNOTATE IT
# ======================================================================================================


def test_a_pool_bound_ceiling_cannot_ship_as_a_confident_bracketed_PASS() -> None:
    """⭐⭐ BLOCKER 2. The tripwire used to be ADVISORY ONLY: `pool.tripped` appended a note and built
    `pool_tripped_rungs`, which was emitted to JSON and READ BY NOTHING. It entered no verdict, no bracket,
    no result token and no exit code — so a POOL-BOUND ceiling still shipped as a confident `result: PASS`,
    exit 0. That is VERBATIM the artifact the tripwire exists to prevent: a pool bind is column-for-column
    identical to the pooled-claim wall it would otherwise be blamed on, and it would have commissioned an
    engine rewrite against a BENCH ARTIFACT.

    The rate is REAL, so it is not voided — but it must be ATTRIBUTED TO THE RESOURCE, and it must never be
    quotable as the ENGINE's ceiling."""
    pool_bound = PoolStats.from_sample(_pool_sample(pool_wait_p95_max_ms=9.0), requested=8)
    assert pool_bound.tripped is True  # the pre-registered tripwire fired

    # A rung that is otherwise PERFECT: fully driven, fully accepted, lossless, drained, SUSTAINED.
    out = _fidelity_rung(offered_rate=20.0, sent=1_200, acked=1_200, pool=pool_bound)
    assert out.fidelity is RungFidelity.ADMISSIBLE
    assert out.verdict is RungVerdict.SUSTAINED
    assert out.pool.tripped is True

    rep = _rep([out])
    # The NUMBER survives — it is a real measurement, and suppressing it would lose information...
    assert rep.pinned_ingress_rate is not None
    # ...but the VERDICT is TAINTED: this is the POOL's wall, not the engine's.
    assert rep.ceiling_pool_bound is True
    assert rep.ceiling_admissible is False
    assert rep.result_label == "POOL_BOUND"  # ⭐ NOT "PASS"
    assert rep.exit_code == 2  # ⭐ NOT 0 — an exit-code-gated harness cannot read this as a pass

    js = rep.to_json_dict()
    assert js["result"] == "POOL_BOUND"
    assert js["exit_code"] == 2
    ceiling = js["ceiling"]
    assert isinstance(ceiling, dict)
    assert ceiling["pool_bound"] is True
    assert ceiling["admissible"] is False
    assert ceiling["pinned_ingress_rate"] is not None  # the number is still THERE, still auditable
    store_pool = js["store_pool"]
    assert isinstance(store_pool, dict)
    assert store_pool["tripped_at_rates"] == [20.0]

    # ...and an operator reading the TEXT cannot mistake it for an engine ceiling.
    text = rep.render()
    assert "POOL-BOUND CEILING — NOT AN ENGINE CEILING" in text
    assert "RESULT: POOL-BOUND CEILING" in text


def test_the_pool_trips_on_the_rung_it_BREAKS_not_the_one_it_lets_through() -> None:
    """⭐⭐ THE CASE THE FIRST FIX MISSED — and it is the ONLY case that occurs in practice.

    A pool bind does not announce itself on the rung it lets through. It announces itself on the rung it
    BREAKS. So the realistic ladder is: a LOW rung sustains on a healthy pool, and the NEXT rung collapses
    *because* the store pool saturated. The trip lands on the COLLAPSING rung — which is the one that
    brackets the ceiling.

    v1 of the taint keyed on the PINNED rung (falling back to the bracketing rung only when NOTHING pinned).
    A pin always exists here, so the collapsing rung's trip was NEVER CONSULTED, and an executed reproduction
    gave: tripped on rung=[40.0], first_collapse=40.0, bracketed=True, ceiling_pool_bound=FALSE,
    result=PASS, exit 0 — the POOL's own wall, published as the ENGINE's ceiling, with a clean exit code.

    That is verbatim the artifact the tripwire exists to prevent. The predicate is now FAIL-SAFE: any driven
    rung that tripped taints the ceiling. A false taint costs one cheap re-run at a larger --store-pool-size;
    a missed one costs an engine rewrite against a bench artifact."""
    clean = PoolStats.from_sample(_pool_sample(), requested=40)
    pool_bound = PoolStats.from_sample(_pool_sample(pool_wait_p95_max_ms=9.0), requested=8)
    assert clean.tripped is False and pool_bound.tripped is True

    # 20/s SUSTAINS on a healthy pool -> it PINS.  40/s COLLAPSES because the pool saturated -> it BRACKETS.
    sustained = _fidelity_rung(index=0, offered_rate=20.0, sent=1_200, acked=1_200, pool=clean)
    collapsed = _fidelity_rung(
        index=1,
        offered_rate=40.0,
        sent=2_400,
        acked=2_400,
        pool=pool_bound,
        drained=False,
        engine_ok=False,
    )
    assert sustained.verdict is RungVerdict.SUSTAINED
    assert collapsed.verdict is not RungVerdict.SUSTAINED

    rep = _rep([sustained, collapsed])
    assert (
        rep.pinned_rung is sustained
    )  # a pin EXISTS — which is exactly what silenced the v1 predicate
    assert rep.pinned_rung.pool.tripped is False  # ...and the PINNED rung's pool is CLEAN
    assert rep.first_collapse_ingress_rate == 40.0  # the bracket comes from the rung the POOL broke
    assert rep.ceiling_bracketed is True

    # ⭐ The taint must fire anyway. The ceiling is the pool's, not the engine's.
    assert rep.ceiling_pool_bound is True
    assert rep.ceiling_admissible is False
    assert rep.result_label == "POOL_BOUND"  # NOT "PASS"
    assert rep.exit_code == 2  # NOT 0
    assert "POOL-BOUND CEILING — NOT AN ENGINE CEILING" in rep.render()
    assert rep.to_json_dict()["store_pool"]["tripped_at_rates"] == [40.0]


def test_a_clean_pool_leaves_the_verdict_untouched() -> None:
    """The taint must be a real discriminator, not a blanket pessimism: a run whose pool WAS measured and did
    NOT trip still PASSes at exit 0 with an admissible ceiling. A gate that always fires is not a gate."""
    clean = PoolStats.from_sample(_pool_sample(), requested=40)
    assert clean.tripped is False

    out = _fidelity_rung(offered_rate=20.0, sent=1_200, acked=1_200, pool=clean)
    rep = _rep([out])
    assert rep.ceiling_pool_bound is False
    assert rep.ceiling_admissible is True
    assert rep.result_label == "PASS"
    assert rep.exit_code == 0
    assert "POOL-BOUND CEILING" not in rep.render()


def test_a_pool_bound_ceiling_does_not_mask_a_run_where_nothing_was_measured() -> None:
    """POOL_BOUND says "we measured a ceiling and the POOL owns it". A rendezvous abort says "we measured
    NOTHING". The second dominates — attributing a ceiling to the pool on a run that never produced one
    would be a fabrication of exactly the kind this gate exists to stop."""
    pool_bound = PoolStats.from_sample(_pool_sample(pool_wait_p95_max_ms=9.0), requested=8)
    out = _fidelity_rung(offered_rate=20.0, sent=1_200, acked=1_200, pool=pool_bound)
    rep = _rep([out], climb_aborted=True)

    assert rep.ceiling_pool_bound is True  # the pool DID trip...
    assert (
        rep.result_label == "SETUP_DEGRADED"
    )  # ...but nothing was certified, and THAT is the headline
    assert rep.exit_code == 2
