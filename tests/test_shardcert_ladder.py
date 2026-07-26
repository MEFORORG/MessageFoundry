# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The shardcert ascending rate-ladder ceiling hunt — climb/stop logic + the rate-spec parser.

Non-gated: the actual drive (a fresh 4-shard fleet per rate step) needs a real SQL Server, so these
substitute a synthetic ``_run_ladder_step`` and exercise the ladder's ordering, one-record-per-step,
stop-at-ceiling (the throughput-SUSTAIN signal — non-drain/loss or an intake shortfall beyond
``_INTAKE_TOL``, deliberately NOT ``delivered < offered``), and correctness-verdict logic in-process.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from harness.load import shardcert
from harness.load.shardcert import (
    RungFidelity,
    ShardCertReport,
    ShardCertStepRecord,
    parse_rate_ladder,
    run_shardcert_ladder,
)
from harness.load.shardcert_ladder import ClaimTiming, aggregate_claim_timing


def _step(
    rate: float,
    *,
    offered: int,
    achieved_intake: int | None = None,
    delivered: int | None = None,
    no_loss: bool = True,
    inversions: int = 0,
    stranded: int = 0,
    in_pipeline_peak: int = 0,
    # Filling-detector inputs. The defaults are the "not measured" SENTINELS, so every pre-existing
    # test keeps its exact meaning (fill_ratio None ⇒ the filling criterion abstains).
    e2e_first_p50: float = 0.0,
    e2e_first_n: int = 0,
    e2e_second_p50: float = 0.0,
    e2e_second_n: int = 0,
    # ARTIFACT 4 (2026-07-14): the FIDELITY gate's drive-side input. A healthy step by definition SENT what
    # it offered, so that is the default — a synthetic step that left `sent` at the -1 sentinel would be
    # UNKNOWN-fidelity (VOID) on every rung, which is not the "healthy step" these tests mean to describe.
    # Pass it explicitly to model a shortfall.
    sent: int | None = None,
    # ⭐ GATE v2: a `sent` shortfall NAMES NO CULPRIT BY ITSELF (`sent` is ENGINE-PACED — a full send buffer
    # means the ENGINE stopped reading). These two arbitrate. The `-1` defaults are the honest NOT-RECORDED
    # sentinels: a shortfall then scores OFFER_SHORTFALL (cause unattributed) and blames NOBODY. Pass
    # `deferred_schedule=` dominant for a real RIG shortfall, `deferred_backpressure=` for an ENGINE one.
    deferred_backpressure: int = -1,
    deferred_schedule: int = -1,
) -> ShardCertStepRecord:
    # A healthy step defaults to a full intake (achieved_intake == offered) and delivered == intake.
    # ``achieved_intake`` and ``delivered`` are set INDEPENDENTLY on purpose: the ceiling now keys off
    # the MEASURED intake vs offered (with a tolerance) and no_loss — never a raw ``delivered < offered``.
    intake = offered if achieved_intake is None else achieved_intake
    return ShardCertStepRecord(
        aggregate_rate=rate,
        offered=offered,
        achieved_intake=intake,
        delivered=intake if delivered is None else delivered,
        in_pipeline_peak=in_pipeline_peak,
        ack_p50_ms=1.0,
        ack_p99_ms=2.0,
        drain_seconds=1.0,
        no_loss=no_loss,
        lane_inversions=inversions,
        lane_repeats=0,
        stranded_nonterminal=stranded,
        e2e_first_half_p50_ms=e2e_first_p50,
        e2e_first_half_count=e2e_first_n,
        e2e_second_half_p50_ms=e2e_second_p50,
        e2e_second_half_count=e2e_second_n,
        sent=offered if sent is None else sent,
        deferred_backpressure=deferred_backpressure,
        deferred_schedule=deferred_schedule,
    )


def _plenty() -> int:
    """A per-half sample count comfortably above the abstain floor — so a test that means to exercise the
    RATIO is never silently abstaining on thin data instead."""
    return shardcert._FILLING_MIN_SAMPLES * 2


def _fill_step(
    rate: float,
    *,
    first_p50: float,
    second_p50: float,
    n: int | None = None,
    first_n: int | None = None,
    second_n: int | None = None,
) -> ShardCertStepRecord:
    """A rung that PASSES both pre-existing bars — lossless (``no_loss``, i.e. drained with nothing
    acked-not-delivered) and a full intake — so the ONLY thing that can make it a ceiling is
    ``filling``."""
    samples = _plenty() if n is None else n
    return _step(
        rate,
        offered=1000,
        achieved_intake=1000,  # full intake: the intake bar cannot fire
        no_loss=True,  # lossless AND drained: the no_loss bar cannot fire
        e2e_first_p50=first_p50,
        e2e_first_n=samples if first_n is None else first_n,
        e2e_second_p50=second_p50,
        e2e_second_n=samples if second_n is None else second_n,
    )


# --- rate-spec parsing -------------------------------------------------------


def test_parse_rate_ladder_comma_list() -> None:
    assert parse_rate_ladder("40,80,120") == [40.0, 80.0, 120.0]


def test_parse_rate_ladder_range() -> None:
    assert parse_rate_ladder("40:200:40") == [40.0, 80.0, 120.0, 160.0, 200.0]


@pytest.mark.parametrize("bad", ["40:80", "40:80:0", "40:80:-5", "", "  "])
def test_parse_rate_ladder_rejects_bad(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_rate_ladder(bad)


# --- ladder climb/stop -------------------------------------------------------


def test_ladder_one_record_per_step_and_stops_at_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # (a)+(d): 40/s is a clean full-intake step; 80/s is HEALTHY but its intake is ~1.25% short of the
    # theoretical offered (token-bucket boundary-drop, WITHIN _INTAKE_TOL) and must NOT trip; 120/s
    # falls materially short of offered (~17%, beyond TOL) ⇒ ceiling; 160/s must NEVER run.
    plan = {
        40.0: _step(40.0, offered=400),  # full intake, healthy
        80.0: _step(80.0, offered=800, achieved_intake=790),  # within-TOL shortfall, still healthy
        120.0: _step(
            120.0, offered=1200, achieved_intake=1000
        ),  # intake shortfall beyond TOL ⇒ ceiling
        160.0: _step(160.0, offered=1600, achieved_intake=900),
    }
    seen: list[float] = []

    async def fake_step(*, rate: float, **_kw: object) -> ShardCertStepRecord:
        seen.append(rate)
        return plan[rate]

    monkeypatch.setattr(shardcert, "_run_ladder_step", fake_step)
    report = asyncio.run(run_shardcert_ladder(rates=[40, 80, 120, 160]))

    assert seen == [40.0, 80.0, 120.0]  # stopped climbing after the ceiling; 160/s never driven
    assert len(report.records) == 3  # exactly one record per driven step
    assert report.ceiling_rate == 120.0
    assert report.records[-1].ceiling is True
    assert report.records[0].ceiling is False  # clean full-intake step
    assert report.records[1].ceiling is False  # within-TOL shortfall did NOT false-trip the ceiling
    # The notes list is no longer ceiling-only: a rung that fails the ARTIFACT-4 fidelity gate also notes
    # itself (here the 120/s ceiling rung, whose intake fell 17% short of a fully-sent offer, is an ENGINE
    # INTAKE BIND). Assert the ceiling note is PRESENT, not that it is first.
    assert any("ceiling at 120" in n for n in report.notes)


def test_ladder_sorts_ascending_and_dedups(monkeypatch: pytest.MonkeyPatch) -> None:
    plan = {r: _step(float(r), offered=r * 10, delivered=r * 10) for r in (40, 80, 120)}

    async def fake_step(*, rate: float, **_kw: object) -> ShardCertStepRecord:
        return plan[int(rate)]

    monkeypatch.setattr(shardcert, "_run_ladder_step", fake_step)
    report = asyncio.run(run_shardcert_ladder(rates=[120, 40, 80, 40]))  # unsorted + duplicate

    assert [r.aggregate_rate for r in report.records] == [40.0, 80.0, 120.0]
    assert report.ceiling_rate is None  # nothing hit the ceiling → whole ladder ran
    assert report.ok is True
    assert report.exit_code == 0


def test_ladder_verdict_fails_on_correctness_break(monkeypatch: pytest.MonkeyPatch) -> None:
    # A per-lane FIFO break at a step ⇒ the ladder verdict is FAIL even though no ceiling was hit.
    plan = {
        40.0: _step(40.0, offered=400, delivered=400),
        80.0: _step(80.0, offered=800, delivered=800, inversions=3),
    }

    async def fake_step(*, rate: float, **_kw: object) -> ShardCertStepRecord:
        return plan[rate]

    monkeypatch.setattr(shardcert, "_run_ladder_step", fake_step)
    report = asyncio.run(run_shardcert_ladder(rates=[40, 80]))

    assert report.ok is False
    assert report.exit_code == 1


def test_ladder_verdict_fails_on_real_loss(monkeypatch: pytest.MonkeyPatch) -> None:
    # (c) real acknowledged loss (acked_not_delivered>0 ⇒ no_loss=False) FAILs the verdict; it also
    # reads as a throughput ceiling (the fleet did not sustain the rate losslessly) and stops the climb.
    plan = {
        40.0: _step(40.0, offered=400),  # clean
        80.0: _step(
            80.0, offered=800, achieved_intake=800, no_loss=False
        ),  # ingested all, lost some
        120.0: _step(120.0, offered=1200),  # must NEVER run — the climb stopped at the lossy step
    }
    seen: list[float] = []

    async def fake_step(*, rate: float, **_kw: object) -> ShardCertStepRecord:
        seen.append(rate)
        return plan[rate]

    monkeypatch.setattr(shardcert, "_run_ladder_step", fake_step)
    report = asyncio.run(run_shardcert_ladder(rates=[40, 80, 120]))

    assert seen == [40.0, 80.0]  # stopped at the lossy step; 120/s never driven
    assert report.ceiling_rate == 80.0
    assert report.ok is False  # a correctness break (loss) ⇒ verdict FAIL
    assert report.exit_code == 1


def test_ceiling_property_signals() -> None:
    # The ceiling keys off MEASURED intake vs offered (+ tolerance) and no_loss — never delivered<offered.
    # (a) a HEALTHY step whose intake is a hair under offered (within _INTAKE_TOL) is NOT a ceiling — the
    # token-bucket boundary-drop the old `delivered < offered` test false-tripped on.
    assert _step(250.0, offered=5000, achieved_intake=4900).ceiling is False  # 2% short
    # exactly at the tolerance edge is still not a ceiling (the shortfall is not yet BELOW the bar).
    assert _step(200.0, offered=1000, achieved_intake=950).ceiling is False  # 5% short == the bar
    # (d) intake materially short of offered (beyond _INTAKE_TOL) ⇒ ceiling.
    assert _step(300.0, offered=6000, achieved_intake=5000).ceiling is True  # ~17% short
    # (b) a full-intake step whose pipeline never drained (no_loss=False, backlog remained) ⇒ ceiling.
    backed_up = _step(
        300.0, offered=6000, achieved_intake=6000, no_loss=False, in_pipeline_peak=1500
    )
    assert backed_up.ceiling is True
    # (e) the `filling` term is the THIRD way to fail sustain — covered in depth below. A record with no
    # e2e halves (every pre-existing synthetic step) ABSTAINS, so none of the above changed meaning.
    assert _step(250.0, offered=5000).fill_ratio is None
    assert _step(250.0, offered=5000).filling is False


# --- `fill_ratio`: the "still filling" detector (2026-07-13) -----------------
#
# The gap it closes: a rung can pass BOTH pre-existing bars — lossless-and-drained (`no_loss`) and a full
# intake — while its in-flight backlog is still GROWING under the offered load. The generous post-hold
# drain window then clears a backlog that was still climbing, and the rung is scored SUSTAINED. It was
# not: it only drained because the offer STOPPED. `fill_ratio` catches that by splitting the HOLD's E2E
# stream into two equal-length STEADY cohorts (the warm-up ramp and the post-hold drain are excluded) and
# comparing the second half's median to the first (ratio >> 1 ⇒ latency was still climbing at hold end).
#
# *** SCOPE — this gate is CO-LOCATED-LADDER ONLY. *** It is NOT the STEP-4 §7 "M2" validity check (different
# source, split key, bar and purpose — see the `_FILLING_RATIO` block in shardcert.py), and it CANNOT fire
# on the TWO-BOX rig path that STEP 4 actually runs: there is no cross-process E2E stream to split there.
# Every two-box ceiling — including the ~16 msg/s STEP-4 plateau — is measured WITHOUT this term, and
# `test_two_box_drive_ceiling_abstains_from_the_filling_term` pins that so the abstain stays DELIBERATE.


def test_filling_rung_is_a_ceiling_even_when_lossless_and_drained() -> None:
    """(a) THE POINT: a rung that passes no_loss AND full-intake is STILL not sustained when M2 >> 1."""
    # E2E median tripled across the hold (10ms -> 30ms) — the s4-climbA signature (M2 1.37-3.06 observed
    # on rungs that nonetheless passed no_loss+drained and were wrongly scored as sustainable).
    rung = _fill_step(16.0, first_p50=10.0, second_p50=30.0)
    assert rung.no_loss is True  # the two pre-existing bars BOTH pass ...
    assert rung.achieved_intake == rung.offered  # ... so neither of them can be what fails it
    assert rung.fill_ratio == pytest.approx(3.0)
    assert rung.filling is True
    assert rung.ceiling is True  # ⇒ NOT sustained, purely on the M2 term


def test_steady_rung_still_passes() -> None:
    """(b) A steady plateau — the two halves' medians are ~equal — is NOT a ceiling."""
    flat = _fill_step(12.0, first_p50=10.0, second_p50=10.0)
    assert flat.fill_ratio == pytest.approx(1.0)
    assert flat.filling is False
    assert flat.ceiling is False

    # Ordinary run-to-run jitter (a 20% wobble) must not false-fail: the bar sits well above ~1.0.
    jittery = _fill_step(12.0, first_p50=10.0, second_p50=12.0)
    assert jittery.fill_ratio == pytest.approx(1.2)
    assert jittery.filling is False
    assert jittery.ceiling is False

    # A rung can be SLOW yet perfectly steady — M2 is a RATIO, so absolute latency is irrelevant. A
    # half-second-latency rung that is not GROWING is a legitimate operating point, not a ceiling.
    slow_but_steady = _fill_step(12.0, first_p50=500.0, second_p50=505.0)
    assert slow_but_steady.filling is False
    assert slow_but_steady.ceiling is False

    # A rung that got FASTER across the hold (backlog relaxing) is obviously not filling.
    draining = _fill_step(12.0, first_p50=30.0, second_p50=10.0)
    assert draining.fill_ratio == pytest.approx(1.0 / 3.0)
    assert draining.filling is False


def test_filling_abstains_on_thin_data() -> None:
    """(c) Too few samples in EITHER half ⇒ ABSTAIN (fall back to the pre-existing bars), never fail."""
    floor = shardcert._FILLING_MIN_SAMPLES
    # A ratio that would SCREAM filling (5x) is ignored when the evidence is thin — the gate only ever
    # ADDS a ceiling on clear evidence.
    thin_first = _fill_step(
        16.0, first_p50=10.0, second_p50=50.0, first_n=floor - 1, second_n=_plenty()
    )
    assert thin_first.fill_ratio is None  # abstained ...
    assert thin_first.filling is False
    assert (
        thin_first.ceiling is False
    )  # ... so the rung is judged on no_loss + intake alone: it PASSES

    thin_second = _fill_step(
        16.0, first_p50=10.0, second_p50=50.0, first_n=_plenty(), second_n=floor - 1
    )
    assert thin_second.fill_ratio is None
    assert thin_second.ceiling is False

    # Exactly AT the floor is enough (the guard is `< _FILLING_MIN_SAMPLES`), so the bar is inclusive.
    at_floor = _fill_step(16.0, first_p50=10.0, second_p50=50.0, n=floor)
    assert at_floor.fill_ratio == pytest.approx(5.0)
    assert at_floor.filling is True

    # NOT MEASURED at all (the default sentinels — a correctness-path or synthetic record): abstain, so
    # the correctness/kill path and every pre-M2 caller keep their exact prior verdict.
    unmeasured = _step(16.0, offered=1000)
    assert unmeasured.fill_ratio is None
    assert unmeasured.filling is False
    assert unmeasured.ceiling is False

    # A zero first-half median (division guard) abstains rather than raising ZeroDivisionError.
    zero_base = _fill_step(16.0, first_p50=0.0, second_p50=50.0)
    assert zero_base.fill_ratio is None
    assert zero_base.filling is False


def test_filling_boundary_is_strictly_above_the_bar() -> None:
    """(d) The bar is STRICT (`> _FILLING_RATIO`) — exactly at it is not yet filling."""
    bar = shardcert._FILLING_RATIO
    at_bar = _fill_step(16.0, first_p50=10.0, second_p50=10.0 * bar)
    assert at_bar.fill_ratio == pytest.approx(bar)
    assert at_bar.filling is False  # exactly AT the bar is not OVER it
    assert at_bar.ceiling is False

    just_over = _fill_step(16.0, first_p50=10.0, second_p50=10.0 * bar + 0.1)
    assert just_over.fill_ratio > bar
    assert just_over.filling is True
    assert just_over.ceiling is True

    just_under = _fill_step(16.0, first_p50=10.0, second_p50=10.0 * bar - 0.1)
    assert just_under.fill_ratio < bar
    assert just_under.filling is False
    assert just_under.ceiling is False


def _report(**over: object) -> ShardCertReport:
    """A minimal healthy :class:`ShardCertReport` — the sizing path's output, which is the ONLY producer
    of the M2 halves."""
    base: dict[str, object] = {
        "shards": ("s1",),
        "owned": {"s1": ["OB_1"]},
        "killed_shard": None,
        "sent": 1000,
        "acked": 1000,
        "delivered_distinct": 1000,
        "sink_received": 1000,
        "acked_not_delivered": 0,
        "lane_inversions": 0,
        "lanes_observed": 8,
        "lane_repeats": 0,
        "engine_done": 1000,
        "engine_dead": 0,
        "in_pipeline_final": 0,
        "drained": True,
        "drain_seconds": 2.0,
        "stranded_nonterminal": 0,
        "queue_breakdown": "",
        "offered": 1000,
        "achieved_intake": 1000,
    }
    base.update(over)
    return ShardCertReport(**base)  # type: ignore[arg-type]


def test_from_report_carries_the_e2e_halves() -> None:
    """REGRESSION (the M2 detector shipped DEAD): ``from_report`` is the ONLY path from the measured
    report into the gated record. It declared the four half fields but never copied them, so every real
    rung carried the 0 sentinel ⇒ ``fill_ratio is None`` ⇒ ``filling`` was False on EVERY rung and the
    detector was unreachable code that read as "steady". Pin the plumbing, not just the arithmetic."""
    report = _report(
        e2e_first_half_p50_ms=10.0,
        e2e_first_half_count=_plenty(),
        e2e_second_half_p50_ms=30.0,
        e2e_second_half_count=_plenty(),
    )
    rec = ShardCertStepRecord.from_report(16.0, report)

    assert rec.e2e_first_half_p50_ms == 10.0
    assert rec.e2e_first_half_count == _plenty()
    assert rec.e2e_second_half_p50_ms == 30.0
    assert rec.e2e_second_half_count == _plenty()
    assert rec.no_loss is True  # the report is lossless-and-drained ...
    assert rec.fill_ratio == pytest.approx(3.0)
    assert rec.filling is True
    assert rec.ceiling is True  # ... yet it IS the ceiling, and that verdict survives the plumbing

    # An UNSPLIT report (correctness/kill path — capture_peak=False ⇒ no midpoint swap) still abstains.
    assert ShardCertStepRecord.from_report(16.0, _report()).fill_ratio is None
    assert ShardCertStepRecord.from_report(16.0, _report()).ceiling is False


def test_ladder_stops_climbing_at_a_filling_rung(monkeypatch: pytest.MonkeyPatch) -> None:
    """M2 must feed the SUSTAIN decision, not merely be computed: a filling rung STOPS the climb, and the
    rung above it is never driven (that is what makes the reported ceiling honest)."""
    plan = {
        8.0: _fill_step(8.0, first_p50=10.0, second_p50=10.0),  # steady ⇒ sustained
        16.0: _fill_step(16.0, first_p50=10.0, second_p50=30.0),  # FILLING ⇒ the ceiling
        32.0: _fill_step(32.0, first_p50=10.0, second_p50=10.0),  # must NEVER be driven
    }
    seen: list[float] = []

    async def fake_step(*, rate: float, **_kw: object) -> ShardCertStepRecord:
        seen.append(rate)
        return plan[rate]

    monkeypatch.setattr(shardcert, "_run_ladder_step", fake_step)
    report = asyncio.run(run_shardcert_ladder(rates=[8, 16, 32]))

    assert seen == [8.0, 16.0]  # the climb stopped AT the filling rung; 32/s never driven
    assert report.ceiling_rate == 16.0
    assert report.records[0].filling is False
    assert report.records[-1].filling is True
    # A filling rung is a THROUGHPUT measurement, not a correctness break — the verdict still PASSES
    # (nothing was lost or reordered; the fleet simply cannot sustain that rate).
    assert report.ok is True
    assert report.exit_code == 0


def test_filling_verdict_is_visible_in_render_and_json() -> None:
    """A filling ceiling reads as ``no_loss=OK`` on every pre-existing bar, so the term MUST be surfaced —
    otherwise an operator sees an unexplained CEILING and cannot tell it from real loss. The JSON also
    stamps the GATE VERSION, so a v2 (filling-gated) ceiling can never be silently compared to a v1 one."""
    filling = _fill_step(16.0, first_p50=10.0, second_p50=30.0)
    text = filling.render()
    assert "fill=3.00" in text  # NOT "M2=" — that name belongs to the STEP-4 §7 validity check
    assert "M2" not in text
    assert "FILLING" in text
    assert "CEILING" in text

    js = filling.to_json_dict()
    assert js["e2e_fill_ratio"] == pytest.approx(3.0)
    assert js["filling"] is True
    assert js["ceiling"] is True
    assert js["ceiling_gate_version"] == shardcert.CEILING_GATE_VERSION

    # ABSTAINED renders as n/a and serializes as null — never as a spurious "steady" 1.0.
    abstained = _step(16.0, offered=1000)
    assert "fill=n/a" in abstained.render()
    assert "FILLING" not in abstained.render()
    assert abstained.to_json_dict()["e2e_fill_ratio"] is None
    assert abstained.to_json_dict()["filling"] is False


def test_ladder_empty_rates_rejected() -> None:
    with pytest.raises(ValueError):
        asyncio.run(run_shardcert_ladder(rates=[]))


def test_ladder_report_renders_and_serializes(monkeypatch: pytest.MonkeyPatch) -> None:
    plan = {
        40.0: _step(40.0, offered=400, achieved_intake=350)
    }  # intake short beyond TOL ⇒ ceiling

    async def fake_step(*, rate: float, **_kw: object) -> ShardCertStepRecord:
        return plan[rate]

    monkeypatch.setattr(shardcert, "_run_ladder_step", fake_step)
    report = asyncio.run(run_shardcert_ladder(rates=[40]))

    text = report.render()
    assert "rate-ladder" in text
    assert "CEILING" in text
    js = report.to_json_dict()
    assert js["kind"] == "shardcert_ladder"
    assert js["ceiling_rate"] == 40.0
    assert isinstance(js["records"], list) and len(js["records"]) == 1


# --- claim timing is PER STAGE, not a four-stage blend (2026-07-13) --------------------------------
#
# The engine emits one `claim phase timing (stage=%s)` line PER STAGE per window. The ladder's regex did
# not capture `stage=`, so aggregate_claim_timing n-weighted INGRESS + ROUTED + OUTBOUND + RESPONSE into a
# single `claim_mean_ms`. Every claim_mean this programme has quoted is therefore a BLEND, not the outbound
# claim — and the outbound claim is the one the throughput analysis reasons about. These pin the split.


def _claim_line(stage: str, n: int, mean: float) -> str:
    return (
        f"2026-07-13 00:00:00 INFO claim phase timing (stage={stage}): "
        f"claim n={n} mean={mean:.2f}ms max={mean * 2:.2f}ms | "
        f"lanes/claim=1.00 rows/claim=1.00 rearm=0 empty=0 claimers=1"
    )


def test_claim_timing_splits_by_stage_and_blend_is_unchanged(tmp_path: Path) -> None:
    log = tmp_path / "shard-a.log"
    # EACH STAGE's ramp window is dropped (2026-07-13) — not just the file's first line. Both stages
    # therefore carry their own ramp window here; before the fix the outbound ramp survived and skewed
    # the outbound mean (13.37-era logs: invisible under n-weighting, but not on a short rung).
    log.write_text(
        "\n".join(
            [
                _claim_line("ingress", 1, 99.0),  # ingress ramp window — dropped
                _claim_line("outbound", 1, 99.0),  # outbound ramp window — dropped
                _claim_line("ingress", 100, 2.0),
                _claim_line("outbound", 100, 20.0),
            ]
        ),
        encoding="utf-8",
    )
    ct = aggregate_claim_timing([log])

    # The BLEND is retained byte-identically (existing reports quote it): n-weighted over both stages.
    assert ct.claims == 200
    assert ct.claim_mean_ms == pytest.approx(11.0)  # (100*2 + 100*20) / 200

    # ...but it is NOT the outbound claim, and the split now says so.
    assert set(ct.by_stage) == {"ingress", "outbound"}
    assert ct.by_stage["ingress"].claim_mean_ms == pytest.approx(2.0)
    assert ct.by_stage["outbound"].claim_mean_ms == pytest.approx(20.0)
    assert ct.by_stage["outbound"].claims == 100
    # The blend understates the outbound claim by ~2x here — the whole point of the fix.
    assert ct.claim_mean_ms < ct.by_stage["outbound"].claim_mean_ms


def test_claim_timing_by_stage_round_trips_through_json(tmp_path: Path) -> None:
    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join([_claim_line("outbound", 1, 9.0), _claim_line("outbound", 10, 5.0)]),
        encoding="utf-8",
    )
    ct = aggregate_claim_timing([log])
    back = ClaimTiming.from_json_dict(ct.to_json_dict())
    assert back.by_stage["outbound"].claim_mean_ms == pytest.approx(5.0)
    assert back.claim_mean_ms == pytest.approx(ct.claim_mean_ms)


def test_claim_timing_parses_a_legacy_pre_stage_log(tmp_path: Path) -> None:
    """A log from before the engine emitted `stage=` must still parse — blend only, no split."""
    log = tmp_path / "shard-a.log"
    log.write_text(
        "INFO claim phase timing: claim n=1 mean=1.00ms max=1.00ms | "
        "lanes/claim=1.00 rows/claim=1.00 rearm=0 empty=0 claimers=1\n"
        "INFO claim phase timing: claim n=10 mean=4.00ms max=8.00ms | "
        "lanes/claim=1.00 rows/claim=1.00 rearm=0 empty=0 claimers=1",
        encoding="utf-8",
    )
    ct = aggregate_claim_timing([log])
    assert ct.claims == 10
    assert ct.claim_mean_ms == pytest.approx(4.0)
    assert ct.by_stage == {}  # no stage in the log => no split, and never a fabricated one


# --- the RAMP-WINDOW drop is PER STAGE, not PER FILE (2026-07-13) ----------------------------------
#
# The engine emits one timing line PER STAGE per window, so a node log is four INTERLEAVED window
# streams. The aggregators did `matches[1:]` — one line off the WHOLE FILE — so only whichever stage
# logged first lost its ramp window and every other stage KEPT one. These pin the per-stage drop.
#
# NO PUBLISHED NUMBER MOVES: recomputed over the banked raw rig lines (714 outbound windows, n=63,484
# claims), STEP 2's published outbound claim reads 13.368 ms either way — a 0.003% change, because the
# ramp windows carry n~1 under an n-weighted mean. The MECHANISM was wrong; the numbers were not. It
# matters on SHORT rungs (a 120 s hold is ~24 windows/stage, not ~180) — the next rig run's shape.


def test_ramp_window_is_dropped_per_stage_not_per_file(tmp_path: Path) -> None:
    """(a) The FIRST line in the file is ``stage=ingress``. Before the fix that one line was the whole
    drop, so OUTBOUND's ramp window survived into the outbound mean — the stage every published claim
    number is about. Ingress must also not be over-dropped: it loses its ramp window and nothing more."""
    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join(
            [
                _claim_line(
                    "ingress", 1, 500.0
                ),  # ramp; FIRST in the file (the old drop's only victim)
                _claim_line("outbound", 1, 900.0),  # ramp; SURVIVED the per-file drop = the defect
                _claim_line("ingress", 50, 2.0),  # real
                _claim_line("outbound", 50, 20.0),  # real
            ]
        ),
        encoding="utf-8",
    )
    ct = aggregate_claim_timing([log])

    # OUTBOUND's ramp window is gone. Pre-fix this read (900x1 + 20x50) / 51 = 37.25 ms — an 86% skew.
    out = ct.by_stage["outbound"]
    assert out.windows == 1
    assert out.claims == 50
    assert out.claim_mean_ms == pytest.approx(20.0)

    # ...and INGRESS did NOT lose a SECOND (real) window to pay for it.
    ing = ct.by_stage["ingress"]
    assert ing.windows == 1
    assert ing.claims == 50
    assert ing.claim_mean_ms == pytest.approx(2.0)

    # The blend is the n-weighted mean of exactly the surviving windows: (2x50 + 20x50) / 100.
    assert ct.windows == 2
    assert ct.claims == 100
    assert ct.claim_mean_ms == pytest.approx(11.0)


def test_ramp_window_dropped_for_a_stage_that_is_not_first_in_the_file(tmp_path: Path) -> None:
    """(b) A stage whose first line appears LATE in the log still loses its OWN first window. Pinned on
    the EPISODE aggregator so the fix is shown to land in all three, not just the claim one."""
    from harness.load.shardcert_ladder import aggregate_episode_timing

    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join(
            [
                _episode_line("outbound", 1, 999.0),  # outbound ramp
                _episode_line("outbound", 10, 62.5),  # outbound real
                _episode_line("response", 1, 999.0),  # response ramp — THIRD stage, appears LAST
                _episode_line("response", 10, 30.0),  # response real
            ]
        ),
        encoding="utf-8",
    )
    et = aggregate_episode_timing([log])

    # Pre-fix: (999x1 + 30x10) / 11 = 118.09 ms. The stage's own ramp window is its own to drop.
    resp = et.by_stage["response"]
    assert resp.windows == 1
    assert resp.episodes == 10
    assert resp.episode_mean_ms == pytest.approx(30.0)
    assert et.by_stage["outbound"].episode_mean_ms == pytest.approx(62.5)


def test_ramp_window_is_dropped_per_file_and_stage_not_per_stage_across_shards(
    tmp_path: Path,
) -> None:
    """(b2) MULTI-SHARD. The drop key is ``(FILE, STAGE)`` — every shard is its OWN process with its OWN
    ramp window, so shard-b's outbound ramp must be dropped even though shard-a already showed an outbound
    window. Guards the ONE plausible regression the single-log tests cannot see: hoisting ``seen`` out of
    the ``for path in log_paths`` loop. That "optimization" keeps every shard's ramp window but the first
    shard's, and every other test in this file still passes."""
    log_a = tmp_path / "shard-a.log"
    log_b = tmp_path / "shard-b.log"
    for log in (log_a, log_b):
        log.write_text(
            "\n".join(
                [
                    _claim_line("ingress", 1, 500.0),  # ingress ramp — dropped in BOTH shards
                    _claim_line("outbound", 1, 900.0),  # outbound ramp — dropped in BOTH shards
                    _claim_line("ingress", 50, 2.0),  # real
                    _claim_line("outbound", 50, 20.0),  # real
                ]
            ),
            encoding="utf-8",
        )
    ct = aggregate_claim_timing([log_a, log_b])

    out = ct.by_stage["outbound"]
    assert out.windows == 2  # one real window PER SHARD — not 3 (shard-b's ramp kept)
    assert out.claims == 100
    # BOTH shards' 900ms ramp windows are excluded. A per-stage-across-files drop would keep shard-b's,
    # reading (900x1 + 20x100) / 101 = 28.71 ms.
    assert out.claim_mean_ms == pytest.approx(20.0)

    ing = ct.by_stage["ingress"]
    assert ing.windows == 2
    assert ing.claim_mean_ms == pytest.approx(2.0)


def _legacy_claim_line(n: int, mean: float) -> str:
    """A pre-stage (legacy) claim line — no ``(stage=...)``. ``_CLAIM_RE`` parses it with stage=None."""
    return (
        f"INFO claim phase timing: claim n={n} mean={mean:.2f}ms max={mean * 2:.2f}ms | "
        f"lanes/claim=1.00 rows/claim=1.00 rearm=0 empty=0 claimers=1"
    )


def test_legacy_no_stage_log_still_drops_exactly_one_window(tmp_path: Path) -> None:
    """(c) REGRESSION PIN. A log with no ``stage=`` has one implicit stage, so the per-stage drop must
    collapse to the old per-file drop EXACTLY: one window off the front, never two, never zero."""
    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join(
            [
                _legacy_claim_line(1, 1.0),  # the ramp window — dropped, exactly as before
                _legacy_claim_line(10, 4.0),
                _legacy_claim_line(10, 6.0),
            ]
        ),
        encoding="utf-8",
    )
    ct = aggregate_claim_timing([log])

    assert ct.windows == 2  # 3 lines - 1 ramp. NOT 1 (over-drop), NOT 3 (no drop).
    assert ct.claims == 20
    assert ct.claim_mean_ms == pytest.approx(5.0)  # (4x10 + 6x10) / 20
    assert ct.by_stage == {}  # no stage in the log => no split, and never a fabricated one


def test_legacy_no_stage_blend_is_byte_identical(tmp_path: Path) -> None:
    """(d) n-weighting is UNCHANGED. The blend of a no-stage log is Σ(mean×n)/Σn over the surviving
    windows — an UNEQUAL-n case, so a mean-of-means regression would show — and its JSON dict still
    carries NO ``by_stage`` key, so an existing consumer reads a byte-identical object."""
    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join(
            [_legacy_claim_line(1, 50.0), _legacy_claim_line(90, 1.0), _legacy_claim_line(10, 10.0)]
        ),
        encoding="utf-8",
    )
    ct = aggregate_claim_timing([log])

    # n-WEIGHTED (90x1 + 10x10) / 100 = 1.9 ms — NOT the unweighted mean-of-means (5.5 ms).
    assert ct.claim_mean_ms == pytest.approx(1.9)
    assert ct.claims == 100
    assert ct.to_json_dict() == {
        "windows": 2,
        "claims": 100,
        "claim_mean_ms": 1.9,
        "claim_max_ms": 20.0,
        "lanes_per_claim": 1.0,
        "rows_per_claim": 1.0,
        "rearm": 0,
        "empty": 0,
    }

    # And the drop is still opt-out-able: nothing is dropped when the caller says so.
    assert aggregate_claim_timing([log], drop_first_window=False).windows == 3


def _phase_line(san: int, sam: float, mdn: int, mdm: float) -> str:
    return (
        f"INFO delivery phase timing (stage=outbound): "
        f"send_ack n={san} mean={sam:.2f}ms max={sam * 2:.2f}ms | "
        f"mark_done n={mdn} mean={mdm:.2f}ms max={mdm * 2:.2f}ms"
    )


def test_phase_timing_drop_is_unchanged_because_the_delivery_line_is_single_stage(
    tmp_path: Path,
) -> None:
    """The delivery (send_ack/mark_done) line is deliberately LEFT ALONE: ``_PHASE_RE`` captures no
    ``stage`` group, so :func:`_drop_ramp_window` sees one implicit group and the per-file drop it always
    did is still correct. Pinned so a future reader does not "fix" a non-bug.

    This asserts the AGGREGATOR's behaviour on a single-stage log, and that is ALL it asserts. It is **not**
    a tripwire for a second emitter — a second stage would still produce ``windows == 1`` here. The
    single-stage property is an INVARIANT OF THE EMITTER, and the test that actually guards it is
    :func:`test_delivery_phase_line_has_exactly_one_emitter_and_it_is_outbound` below."""
    from harness.load.shardcert_ladder import aggregate_phase_timing

    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join([_phase_line(1, 99.0, 1, 99.0), _phase_line(10, 0.5, 10, 10.0)]),
        encoding="utf-8",
    )
    pt = aggregate_phase_timing([log])

    assert pt.windows == 1  # exactly one window dropped, as before
    assert pt.deliveries == 10
    assert pt.send_ack_mean_ms == pytest.approx(0.5)
    assert pt.mark_done_mean_ms == pytest.approx(10.0)


def test_delivery_phase_line_has_exactly_one_emitter_and_it_is_outbound() -> None:
    """THE REAL TRIPWIRE for the test above. ``aggregate_phase_timing`` blends every delivery window into
    ONE mean and drops ONE ramp window per file — correct only while the line is single-stage. But
    ``DeliveryPhaseTiming.maybe_emit(*, stage: str = "outbound")`` takes ``stage`` as a DEFAULTED parameter,
    not a constant, so nothing in the type system stops a second stage from emitting it.

    Pin it at the source: exactly one call site, and it passes ``stage="outbound"``. If someone wires up a
    second stage, THIS fails — with the full list of what else must change (see ``_drop_ramp_window``:
    ``_PHASE_RE`` needs a ``stage`` group, ``aggregate_phase_timing`` must move to NAMED groups because a
    leading group shifts ``m.group(1)..m.group(6)``, and ``PhaseTiming`` needs a ``by_stage`` split — or it
    silently repeats the four-stage ``claim_mean`` blend bug)."""
    import messagefoundry.pipeline as pipeline_pkg

    pkg_dir = Path(pipeline_pkg.__file__).parent
    call_sites = [
        (path.name, line.strip())
        for path in sorted(pkg_dir.glob("*.py"))
        for line in path.read_text(encoding="utf-8").splitlines()
        if "_delivery_phase_stats.maybe_emit(" in line
    ]

    assert len(call_sites) == 1, f"a SECOND delivery-phase emitter appeared: {call_sites}"
    name, line = call_sites[0]
    assert name == "wiring_runner.py"
    assert 'stage="outbound"' in line, f"the delivery phase line is no longer outbound-only: {line}"


# =====================================================================================================
# SCOPE PINS: the filling gate is CO-LOCATED-LADDER ONLY.
#
# The gate lives on `ShardCertStepRecord`, whose only producer is `from_report(ShardCertReport)` — i.e.
# `run_shardcert` (single process: it both sends and sinks, so a Correlator can join the timestamps).
# STEP 4 runs the TWO-BOX ladder, where senders and sinks are separate processes behind a metadata-only
# coord: there is NO E2E stream to split, and the per-rung verdict is `classify_rung`, which has no
# filling term. These tests PIN that, so the abstain is a DELIBERATE, documented limitation rather than
# a silently-dead gate that reads like a live one.
# =====================================================================================================


def _drive_report(**over: object) -> shardcert.ShardCertDriveReport:
    base: dict[str, object] = {
        "shards": ("s1", "s2"),
        "dests": 8,
        "handlers": 8,
        "delivering": 8,
        "driver_count": 4,
        "sink_count": 8,
        "aggregate_rate": 16.0,
        "hold_seconds": 60.0,
        "offered": 960,
        "sent": 960,
        "acked": 960,
        "sink_received": 960 * 8,
        "lane_inversions": 0,
        "lane_repeats": 0,
        "lanes_observed": 8,
        "ack_p50_ms": 1.0,
        "ack_p99_ms": 2.0,
        "engine_done": 960 * 8,
        "engine_dead": 0,
        "in_pipeline_final": 0,
        "drained": True,
        "drain_seconds": 5.0,
    }
    base.update(over)
    return shardcert.ShardCertDriveReport(**base)  # type: ignore[arg-type]


def test_two_box_drive_report_carries_no_e2e_at_all() -> None:
    """The STRUCTURAL reason the gate cannot fire on the rig path: the two-box drive report has no E2E
    field to split. A sink process's ``Correlator`` never sees ``on_send`` (the senders are OTHER
    processes), so ``metrics.e2e`` is empty by construction. If someone later plumbs a cross-process
    correlation in, this test fails and forces them to ALSO wire the term into ``classify_rung`` — which
    is the half that actually decides a two-box rung. Changing only one half changes nothing."""
    from dataclasses import fields

    assert [f.name for f in fields(shardcert.ShardCertDriveReport) if "e2e" in f.name] == []


def test_two_box_drive_ceiling_abstains_from_the_filling_term() -> None:
    """A two-box rung that is lossless + full-intake is NOT a ceiling — and cannot be made one by the
    filling term, because that term abstains here BY CONSTRUCTION. The abstain must be EXPLICIT (the
    report says so in its JSON), never a silent 0-sentinel default that reads as "steady"."""
    healthy = _drive_report()
    assert healthy.no_loss is True
    assert healthy.ceiling is False

    js = healthy.to_json_dict()
    tp = js["throughput"]
    assert isinstance(tp, dict)
    assert tp["ceiling"] is False
    assert tp["filling_evaluated"] is False  # the gate ABSTAINED — stated, not implied
    assert tp["ceiling_gate_version"] == shardcert.CEILING_GATE_VERSION
    assert "no cross-process E2E" in str(tp["filling_abstain_reason"])

    # The OTHER two terms still work on this path (the abstain is scoped to `filling` alone).
    assert _drive_report(acked=100).ceiling is True  # intake shortfall
    assert _drive_report(sink_received=0).ceiling is True  # no_loss=False (vacuous sink)


def test_classify_rung_has_no_filling_term_so_a_filling_two_box_rung_still_sustains() -> None:
    """THE KNOWN GAP, pinned. ``classify_rung`` is the two-box per-rung verdict, and it consults only the
    engine store-truth + the sink socket-truth. A rung that drained clean and lost nothing is SUSTAINED —
    even if it was still FILLING — because no filling signal exists on this path to consult. This test
    exists so that fact is deliberate and visible, and so anyone adding the term has to change it."""
    from harness.load.shardcert_ladder import RungVerdict, classify_rung, stops_climb

    verdict = classify_rung(
        engine_reported=True,
        engine_ok=True,  # the engine drained clean — post-hold, after the offer stopped
        no_loss=True,  # the sink saw every copy
        lane_inversions=0,
        lane_repeats=0,
        acked=960,
        sink_received=960 * 8,
        delivering=8,
        handlers=8,
    )
    assert verdict is RungVerdict.SUSTAINED
    assert (
        stops_climb(verdict) is False
    )  # the climb continues — a filling rung is NOT scored a ceiling


# =====================================================================================================
# S_lane (STEP 4 ARM 1): the LANE EPISODE aggregator.
#
# Without this the ARM 1 deliverable — one number, S_lane_mean for stage=outbound — would exist only as
# an INFO line buried in per-shard node logs, to be hand-grepped per rung, per shard, with no n-weighting
# and no ramp-window drop. That is precisely how the four-stage `claim_mean` blend went unnoticed.
# =====================================================================================================


def _episode_line(
    stage: str,
    n: int,
    mean: float,
    *,
    rows: float = 1.0,
    dropped: int = 0,
    dropped_ms: float = 0.0,
    lanes: int = 8,
    slots: int = 256,
    window: float = 5.0,
    util: float = 0.5,
) -> str:
    lam = (rows * 1000.0) / mean if mean > 0 else 0.0
    return (
        f"INFO lane episode timing (stage={stage}): "
        f"episode n={n} mean={mean:.2f}ms max={mean * 3:.2f}ms | "
        f"rows/episode={rows:.2f} lambda_max_per_lane={lam:.2f}/s | "
        f"dropped n={dropped} sum={dropped_ms:.2f}ms | "
        f"lanes={lanes} slots={slots} window={window:.2f}s utilization={util:.3f}"
    )


def test_episode_timing_splits_by_stage_and_drops_the_ramp_window(tmp_path: Path) -> None:
    """The load-bearing property: the OUTBOUND number must never be blended with the prefix stages (the
    already-committed ``claim_mean`` error), and each shard's FIRST window is the ramp — dropped, exactly
    as the claim/phase aggregators do."""
    from harness.load.shardcert_ladder import aggregate_episode_timing

    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join(
            [
                _episode_line("outbound", 1, 999.0),  # outbound RAMP window — must be DROPPED
                _episode_line(
                    "ingress", 1, 999.0, rows=1.0
                ),  # ingress RAMP window — must be DROPPED
                _episode_line("outbound", 10, 62.5),
                _episode_line("outbound", 10, 62.5),
                _episode_line("ingress", 10, 8.0, rows=64.0),  # a BATCHING prefix stage
            ]
        ),
        encoding="utf-8",
    )
    et = aggregate_episode_timing([log])

    out = et.by_stage["outbound"]
    assert out.episodes == 20
    assert out.episode_mean_ms == pytest.approx(62.5)  # the 999 ms ramp window did NOT poison it
    assert out.rows_per_episode == pytest.approx(1.0)  # SELF-CHECK: hard-1 holds on outbound
    assert out.lambda_max_per_lane == pytest.approx(16.0, rel=1e-3)  # 1000/62.5
    # min(lanes, slots) / S_lane = min(8, 256) x 16/s = 128 deliveries/s — the rig's measured ceiling.
    assert out.aggregate_ceiling_per_s == pytest.approx(128.0, rel=1e-3)

    # The INGRESS stage is kept SEPARATE, and its lambda is ROWS-based: 64 rows per 8 ms episode = 8000/s,
    # not the 125/s a naive 1/mean reciprocal would report.
    ing = et.by_stage["ingress"]
    assert ing.rows_per_episode == pytest.approx(64.0)
    assert ing.lambda_max_per_lane == pytest.approx(8000.0, rel=1e-3)
    assert set(et.by_stage) == {"outbound", "ingress"}


def test_episode_timing_slot_cap_bounds_the_aggregate_ceiling() -> None:
    """``min(lanes, slots)``, NOT ``lanes``. At the programme's 1,500-connection target against the
    default 256-slot pool, a reader applying ``lanes / S_lane`` over-states the ceiling ~5.9x."""
    from harness.load.shardcert_ladder import EpisodeTiming

    et = EpisodeTiming(
        windows=1,
        episodes=100,
        episode_mean_ms=62.5,
        episode_max_ms=190.0,
        rows_per_episode=1.0,
        lambda_max_per_lane=16.0,
        dropped=0,
        dropped_ms=0.0,
        lanes=1500.0,  # the fleet target ...
        slots=256.0,  # ... but only 256 lanes can be in-flight at once
        utilization=0.9,
    )
    assert et.aggregate_ceiling_per_s == pytest.approx(256 * 16.0, rel=1e-3)  # 4096/s, NOT 24000/s


def test_episode_timing_carries_occupancy_so_the_negative_branch_is_falsifiable(
    tmp_path: Path,
) -> None:
    """S_lane alone cannot distinguish "the lanes are idle" from "the lanes are busy on EMPTY claims". A
    booked mean of 25 ms reads as "the lanes do not bind" — but if utilization is ~1.0 they bind anyway,
    and ARM 1 would be sent down exactly the blind alley it exists to prevent."""
    from harness.load.shardcert_ladder import aggregate_episode_timing

    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join(
            [
                _episode_line("outbound", 1, 25.0),  # ramp (dropped)
                _episode_line("outbound", 40, 25.0, dropped=120, dropped_ms=4680.0, util=0.98),
            ]
        ),
        encoding="utf-8",
    )
    out = aggregate_episode_timing([log]).by_stage["outbound"]
    assert out.episode_mean_ms == pytest.approx(25.0)  # the benign "lanes do not bind" number ...
    assert out.utilization == pytest.approx(0.98)  # ... but the lanes were busy 98% of the window
    assert out.dropped == 120
    assert out.dropped_ms == pytest.approx(4680.0)


def test_episode_timing_round_trips_and_survives_a_log_with_no_episode_lines(
    tmp_path: Path,
) -> None:
    from harness.load.shardcert_ladder import EpisodeTiming, aggregate_episode_timing

    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join([_episode_line("outbound", 1, 9.0), _episode_line("outbound", 10, 62.5)]),
        encoding="utf-8",
    )
    et = aggregate_episode_timing([log])
    back = EpisodeTiming.from_json_dict(et.to_json_dict())
    assert back.by_stage["outbound"].episode_mean_ms == pytest.approx(62.5)
    assert back.episode_mean_ms == pytest.approx(et.episode_mean_ms)

    # A missing / episode-free log contributes nothing and NEVER raises (a bench report must not crash on
    # a truncated log), and renders an explicit "none captured" rather than a fabricated zero.
    empty = aggregate_episode_timing([tmp_path / "nope.log"])
    assert empty.is_empty
    assert empty.aggregate_ceiling_per_s == 0.0
    assert "none captured" in empty.render()


def test_engine_rung_report_carries_the_episode_aggregate(tmp_path: Path) -> None:
    """END-TO-END for the plumbing: the engine half must ATTACH ``episode_timing`` to ENGINE_RUNG_REPORT
    and ``build_rung_outcome`` must read it back onto the rung — otherwise S_lane never reaches the rig's
    report and ARM 1's headline number has to be hand-grepped out of per-shard node logs."""
    from harness.load.shardcert_ladder import _attach_rung_timings

    log = tmp_path / "shard-a.log"
    log.write_text(
        "\n".join([_episode_line("outbound", 1, 9.0), _episode_line("outbound", 10, 62.5)]),
        encoding="utf-8",
    )
    payload: dict[str, object] = {}
    _attach_rung_timings(payload, [log])

    assert "episode_timing" in payload  # alongside phase_timing + claim_timing
    et = payload["episode_timing"]
    assert isinstance(et, dict)
    by_stage = et["by_stage"]
    assert isinstance(by_stage, dict)
    assert by_stage["outbound"]["episode_mean_ms"] == pytest.approx(62.5)


# =====================================================================================================
# ARTIFACT 4 (2026-07-14) — THE FIDELITY GATE, ON THE CO-LOCATED PATH TOO.
#
# The repo has ALREADY SHIPPED a gate that is live on one rung record type and dead on the other: the
# `filling` term is computed by `ShardCertStepRecord` (here) and explicitly ABSTAINED by
# `ShardCertDriveReport.ceiling` (two-box), and the two-box path is the only path STEP 5 runs. The
# fidelity predicate therefore lives in ONE pure function (`shardcert.rung_fidelity`, beside
# `_is_ceiling`) and is called from BOTH record types. These pin the co-located caller; the two-box
# caller is pinned in tests/test_shardcert_ladder_two_box.py. Landing it in only one is the repeat.
# =====================================================================================================


def test_step_record_fidelity_admissible_on_a_driven_step() -> None:
    rec = _step(40.0, offered=400, sent=400, achieved_intake=400)
    assert rec.fidelity is RungFidelity.ADMISSIBLE
    js = rec.to_json_dict()
    assert js["sent"] == 400
    assert js["fidelity"] == "admissible"
    assert js["fidelity_admissible"] is True
    assert js["fidelity_reason"] is None


def test_step_record_fidelity_drive_shortfall_is_the_rig_not_the_engine() -> None:
    # The generator offered 400 and pushed 300. The engine took everything that arrived — so `no_loss` is
    # True and `ceiling` is False: a clean, healthy-looking rung that says NOTHING about the engine.
    #
    # ⭐ GATE v2: the DRIVE_SHORTFALL verdict REQUIRES the deferrals to be dominated by the GENERATOR's own
    # tick-lag. The bare `sent` shortfall this test used to assert on is NOT sufficient and must not be:
    # `sent` is engine-paced, so "any shortfall ⇒ the rig" would read a REAL engine backpressure bind as a
    # rig failure. The RIG cause is stated explicitly here; the ENGINE cause is the sibling test below.
    rec = _step(
        40.0,
        offered=400,
        sent=300,
        achieved_intake=300,
        deferred_schedule=100,  # the generator never reached a socket
        deferred_backpressure=0,  # the engine's buffers were never full
    )
    assert rec.no_loss is True
    assert rec.fidelity is RungFidelity.DRIVE_SHORTFALL
    assert rec.fidelity.driven is False  # no rate was established: it can neither pin nor bracket
    reason = rec.to_json_dict()["fidelity_reason"]
    assert isinstance(reason, str) and "measures the RIG" in reason
    assert "FIDELITY VOID (DRIVE_SHORTFALL)" in rec.render()


def test_step_record_fidelity_engine_intake_bind_is_a_real_engine_finding() -> None:
    # The generator pushed the whole 400; the engine accepted 300. Same counts as above on the ENGINE side,
    # opposite finding. This one IS an engine result — and a different one from a lane/claim wall.
    rec = _step(40.0, offered=400, sent=400, achieved_intake=300)
    assert rec.fidelity is RungFidelity.ENGINE_INTAKE_BIND
    reason = rec.to_json_dict()["fidelity_reason"]
    assert isinstance(reason, str) and "ENGINE INTAKE BIND" in reason


def test_step_record_fidelity_is_fail_closed_when_sent_is_unrecorded() -> None:
    # The -1 sentinel is UNKNOWN, and UNKNOWN is VOID. An unmeasured gate is never a pass — which is
    # precisely how `fill_ratio` died (four unset half-fields silently took the 0 sentinel and abstained).
    rec = ShardCertStepRecord(
        aggregate_rate=40.0,
        offered=400,
        achieved_intake=400,
        delivered=400,
        in_pipeline_peak=0,
        ack_p50_ms=1.0,
        ack_p99_ms=2.0,
        drain_seconds=1.0,
        no_loss=True,
        lane_inversions=0,
        lane_repeats=0,
        stranded_nonterminal=0,
    )
    assert rec.sent == -1
    assert rec.fidelity is RungFidelity.UNKNOWN


def test_step_record_carries_sent_across_from_the_report() -> None:
    """⭐ THE `fill_ratio` REPEAT-FAILURE GUARD, exactly. `from_report` is where the filling terms had to be
    carried across, and omitting them would have pinned every rung at the "not measured" sentinel — a
    detector that is structurally incapable of firing and reads as "steady". `sent` lives on ShardCertReport
    and must make the same crossing, or the co-located fidelity gate is dead code."""
    report = _report(sent=1234, acked=1200, offered=1250, achieved_intake=1200)
    rec = ShardCertStepRecord.from_report(40.0, report)
    assert rec.sent == 1234  # NOT the -1 sentinel
    assert rec.fidelity is RungFidelity.ADMISSIBLE  # 1234/1250 = 98.7%; 1200/1250 = 96%


def test_colocated_ladder_report_rolls_up_the_void_rates(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator reading ``ceiling_rate`` must be able to see, FROM THE SAME ARTIFACT, whether the climb it
    came from was actually DRIVEN at the rates it names — and, where it fell short, WHOSE fault that was.

    The 80/s rung is the band the pre-existing sustain bar WAVES THROUGH: its intake is 97% of offered, so
    ``achieved_intake >= offered * (1 - _INTAKE_TOL)`` holds and ``ceiling`` is False — a healthy-looking
    rung. But the DRIVE only pushed 97% of the plan, so it is not an engine measurement at all. Only the
    fidelity gate can see that, because it is the only thing that looks at ``sent``.

    The 120/s rung is the opposite: the drive pushed the WHOLE plan and the engine took 83%. That trips the
    intake bar (so it is the ceiling, as it always was) — and it is now NAMED as an ENGINE INTAKE BIND rather
    than left as an anonymous "intake shortfall" an operator could read either way."""
    plan = {
        40.0: _step(40.0, offered=400),  # driven + healthy: sent == offered == intake
        # The RIG came up 3% short — and v2 requires that to be SAID (deferred_schedule dominant), not
        # inferred from the shortfall alone, which would equally fit an ENGINE backpressure bind.
        80.0: _step(
            80.0,
            offered=800,
            sent=776,
            achieved_intake=776,
            deferred_schedule=24,
            deferred_backpressure=0,
        ),
        120.0: _step(120.0, offered=1200, sent=1200, achieved_intake=1000),  # the ENGINE took 83%
    }

    async def fake_step(*, rate: float, **_kw: object) -> ShardCertStepRecord:
        return plan[rate]

    monkeypatch.setattr(shardcert, "_run_ladder_step", fake_step)
    report = asyncio.run(run_shardcert_ladder(rates=[40, 80, 120]))

    # The 80/s drive shortfall did NOT trip the old sustain bar — the climb rolled straight past it.
    assert plan[80.0].ceiling is False
    assert plan[80.0].fidelity is RungFidelity.DRIVE_SHORTFALL
    assert (
        report.ceiling_rate == 120.0
    )  # the ceiling is unchanged: this is ADDITIVE, not a redefinition
    assert plan[120.0].fidelity is RungFidelity.ENGINE_INTAKE_BIND

    assert report.fidelity_void_rates == [80.0, 120.0]  # the shortfall AND the intake bind
    js = report.to_json_dict()
    assert js["schema_version"] == 2  # v2: +sent +fidelity per record, +the roll-up
    fid = js["fidelity"]
    assert isinstance(fid, dict)
    assert fid["all_admissible"] is False
    assert fid["void_rates"] == [80.0, 120.0]
    assert any("DRIVE SHORTFALL" in n for n in report.notes)
    assert any("ENGINE INTAKE BIND" in n for n in report.notes)


def test_colocated_report_records_the_pool_and_the_inbound_bands() -> None:
    """ARTIFACTS 2 + 5 on the single-box report. The pool size a run used and the inbound band count G must
    be recoverable from the artifact — on BOTH paths, not just the two-box one."""
    from harness.load.enginepoll import PoolStats

    rep = _report(
        shards=("a", "b", "c", "d"),
        owned={s: [] for s in "abcd"},
        dests=8,
        lanes_per_shard=1,
        pool=PoolStats(requested=40, max_size=40, size=40, idle_min=10, shards_reporting=4),
    )
    assert rep.inbound_bands == 4  # G = 4 shards x 1 lane
    js = rep.to_json_dict()
    assert js["schema_version"] == 4  # v4: +store_pool, +topology G

    topo = js["topology"]
    assert isinstance(topo, dict)
    assert topo["lanes_per_shard"] == 1
    assert topo["inbound_bands"] == 4  # G
    assert topo["dests"] == 8  # L
    assert (
        topo["inbound_bands_narrower_than_dests"] is True
    )  # the shipped default IS the narrow case

    pool = js["store_pool"]
    assert isinstance(pool, dict)
    assert pool["requested_pool_size"] == 40  # NOT the old hardcoded 8, and NOT unrecorded
    assert pool["requested_matches_engine"] is True
    assert pool["tripwire"]["tripped"] is False
