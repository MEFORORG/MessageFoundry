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
from harness.load.shardcert_ladder import ClaimTiming, aggregate_claim_timing
from harness.load.shardcert import (
    ShardCertStepRecord,
    parse_rate_ladder,
    run_shardcert_ladder,
)


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
    assert report.notes and "ceiling at 120" in report.notes[0]


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
    # A ramp window (dropped), then two stages with very different claim costs.
    log.write_text(
        "\n".join(
            [
                _claim_line("ingress", 1, 99.0),  # first window per log = the dropped ramp window
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
