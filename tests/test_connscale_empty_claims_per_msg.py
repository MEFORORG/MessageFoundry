# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1101: the empty-claims monotonicity SLO must measure the engine, not the runner.

The SLO used to read ``empty_claims_per_s``, which carries wall clock in its denominator. Anything
that slowed the run -- CPU contention on a shared CI runner, or the O(N) reload probe firing mid-hold
and stalling commits -- collapsed the numerator while the denominator kept ticking, so the metric
fell and the gate went red with **no engine change**. Measured on one commit, one box: four contended
replicates spread **0.451 to 2.49** against a 0.75 floor. That is a coin flip, not a detector.

The fix reads ``empty_claims_per_msg`` instead. Both inputs are deltas over the SAME window --
``samples[0]`` to ``samples[-1]`` -- so the span cancels and the quantity is exactly
``Δempty_claims / Δread``. That window is the hold PLUS the step's post-drain tail, NOT the hold
alone; it is defined once, in ``harness.load.connscale.runner._empty_claim_rates``, and this
paragraph used to call it "in-hold", which the final sample is not (BACKLOG #1420).

**These tests exist to stop the fix from being the WRONG kind of fix.** A metric that never fails is
not an improvement on one that fails at random, and a correction is the easiest place to skip
measuring because it feels like it has already paid its dues. So the invariance property and the
still-detects-a-real-regression property are pinned TOGETHER: neither alone is evidence.

BACKLOG #1211 limb two then changed WHAT IS GRADED, and several tests below were retargeted with it.
``empty_claims_per_msg`` is still the metric and is still recorded on every run; what went away is
the vs-N slope gate over it, replaced by ``_empty_claims_base_reading_slo`` -- a sign test on each
``per_lane`` lane's reading at the BASE connection count -- plus a predicted herd floor that is
recorded and not enforced. Every retarget kept the property and changed the subject; each one says
which, at the test.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import pathlib
import re
import warnings

import pytest

from harness.load.connscale.profile import ConnScaleProfile, load_connscale_profile_text
from harness.load.connscale.report import (
    CONNSCALE_WORKERS_PER_CONNECTION,
    DIAGNOSTIC_FIELDS,
    ENGINE_IDLE_POLL_INTERVAL_S,
    ConnScaleRecord,
    ConnScaleReport,
    NoLoss,
    herd_floor_readings,
    lane_label,
    monotonic_pairs,
    predict_herd_levels,
)
from harness.load.connscale.runner import (
    _MONOTONIC_TOLERANCE,
    _empty_claims_base_reading_slo,
    _empty_claims_per_msg,
    _monotonic_slo,
)
from tests import test_connscale_smoke as _smoke_module
from tests.test_connscale_smoke import (
    _DEFAULT_READINGS_PATH,
    _LOCAL_READINGS_ENV,
    _READINGS_JSON_ENV,
    _append_step_summary,
    _record_ratio_readings,
    _write_readings_json,
)


def _rec(
    mode: str,
    count: int,
    *,
    per_msg: float | None,
    claim_mode: str = "per_lane",
    rate: float = 24.0,
    fd_peak: int | None = 100,
) -> ConnScaleRecord:
    """A record carrying only the fields these SLOs read; the rest are inert placeholders.

    ``rate`` DEFAULTS TO THE RATE THAT PRODUCED THE HARVESTED READINGS, not to a round number. The
    herd-floor model divides by the offered aggregate rate, so a wrong default makes every predicted
    level wrong while every test still passes. The sweep these records model is the in-suite profile
    in ``tests/test_connscale_smoke.py``, whose ``aggregate_rate`` is 24.0 -- that profile is the one
    CI actually runs and the one every reading harvested for BACKLOG #1211 came from. (The shipped
    ``harness/load/profiles/connscale-smoke.toml`` reads 35.0, but no workflow invokes it; PERF-36.)

    A ``fixed_per_conn`` STEP DOES NOT OFFER ``aggregate_rate``. ``ConnScaleProfile.aggregate_rate_for``
    returns ``per_conn_rate * count`` for that mode, so a herd-floor assertion on a ``fixed_per_conn``
    record must pass ``rate=`` explicitly -- at N=12 with the smoke's ``per_conn_rate = 1.0`` the real
    offered rate is 12.0, which predicts a different floor (23.24, not 15.30).
    """
    return ConnScaleRecord(
        sweep_mode=mode,
        count=count,
        offered_aggregate_rate=rate,
        sent=1000,
        acked=1000,
        nak=0,
        deferred=0,
        timeouts=0,
        no_loss=NoLoss(True, 1000, 1000, 1000, 1000, 0, "ok"),
        in_pipeline_peak=3,
        drain_seconds=1.2,
        executor_queue_depth_peak=2,
        executor_busy_peak=1,
        pool_wait_p50_ms=None,
        pool_wait_p95_ms=None,
        pool_wait_p99_ms=None,
        pool_wait_max_ms=None,
        pool_idle_min=None,
        pool_size_max=None,
        empty_claims_per_s=10.0,
        idle_poll_per_s=4.0,
        wake_fanout_per_s=6.0,
        empty_claims_per_msg=per_msg,
        fd_count_peak=fd_peak,
        reload_seconds=None,
        ack_p50_ms=None,
        ack_p95_ms=None,
        ack_p99_ms=None,
        claim_mode=claim_mode,
    )


_METRIC = "empty_claims_per_msg"
_KEY = lambda r: r.empty_claims_per_msg  # noqa: E731


def _profile(*counts: int) -> ConnScaleProfile:
    """A real profile whose only load-bearing field here is ``counts``.

    ``_empty_claims_base_reading_slo`` reads the profile for exactly one thing -- ``min(counts)``, the
    base connection count it grades at. It is parsed through the shipped loader rather than built by
    hand so that a required field added to :class:`ConnScaleProfile` fails here, where a hand-rolled
    stub would silently supply its own default and the tests would keep passing against a profile
    shape the runner no longer accepts.
    """
    return load_connscale_profile_text(
        f"""
[connscale]
name = "unit"
counts = {list(counts)}
sweep_mode = "both"
aggregate_rate = 24.0
per_conn_rate = 1.0
hold_seconds = 1.5
connect_batch = 8
connect_batch_pause_s = 0.0
poll_interval_s = 0.25
drain_timeout_s = 30.0
base_port = 20000
transform = "cheap"
reload_probe = false
store_backend = "sqlite"
corpus_count_per_trigger = 5

[connscale.slo]
zero_loss = true
empty_claims_base_reading = true
""",
        where="<unit-test profile>",
    )


# --------------------------------------------------------------------------------------------------
# The property the fix exists for.
# --------------------------------------------------------------------------------------------------


def test_per_msg_is_invariant_when_the_whole_run_is_slowed() -> None:
    """Contention scales numerator and denominator identically, so the ratio does not move.

    This is the defect reproduced arithmetically. A run that is slowed by 3x reports a third of the
    empty claims per SECOND and a third of the messages per second -- the engine behaved identically,
    only the clock changed.
    """
    fast = _empty_claims_per_msg(total_per_s=450.0, achieved_read_per_s=9.0)
    slowed = _empty_claims_per_msg(total_per_s=150.0, achieved_read_per_s=3.0)

    assert fast == pytest.approx(50.0)
    assert slowed == pytest.approx(50.0), (
        "per-message must not move when the run is uniformly slowed; if it does, the fix has "
        "reproduced the very wall-clock dependence #1101 records"
    )


def test_per_second_would_have_moved_on_the_same_data() -> None:
    """The negative half of the pair: show the OLD metric fails on data the new one survives.

    Without this, 'the new metric is stable' is unfalsifiable -- a constant would also pass.
    """
    fast_per_s, slowed_per_s = 450.0, 150.0
    floor = 0.75
    assert slowed_per_s < fast_per_s * floor, (
        "the old per-second metric must visibly collapse here, otherwise this fixture does not "
        "exercise the defect at all"
    )
    # ...while per-message, on the identical run, is unchanged.
    assert _empty_claims_per_msg(fast_per_s, 9.0) == _empty_claims_per_msg(slowed_per_s, 3.0)


def test_per_msg_is_none_when_no_messages_were_absorbed() -> None:
    """Undefined must stay undefined. Returning 0.0 would chain through the comparison as a reading."""
    assert _empty_claims_per_msg(total_per_s=12.0, achieved_read_per_s=0.0) is None
    assert _empty_claims_per_msg(total_per_s=0.0, achieved_read_per_s=0.0) is None


# --------------------------------------------------------------------------------------------------
# The property that stops this being a gate that never fires.
#
# RETARGETED BY BACKLOG #1211 LIMB TWO, WHICH REPLACED THE GATE THESE WERE WRITTEN AGAINST. They drove
# `_monotonic_slo` over `empty_claims_per_msg` -- a vs-N slope. That gate was measurably broken in five
# ways at once: it fired on the environment in 15 of 153 harvested CI runs, including two pushes to
# `main`, while PASSING a curve flattened to half its healthy value in 143 of 144 transitions. Its
# replacement, `_empty_claims_base_reading_slo`, grades one thing: every `per_lane` lane produced a
# STRICTLY POSITIVE reading at the BASE connection count.
#
# THE vs-N SLOPE IS NOW ASSERTED NOWHERE, deliberately -- BACKLOG #1211 records that as a real loss --
# so nothing below may be rewritten as a slope test. `_monotonic_slo` appears once more in this
# section, labelled as the RETIRED comparator, because "the new check catches this" is worth little
# without "and the old one did not".
# --------------------------------------------------------------------------------------------------


def test_slo_still_fails_when_the_base_reading_is_dead() -> None:
    """A REAL regression -- the empty-claim counter not moving at all -- must go red.

    THIS IS DEFECT 3 OF THE FIVE BACKLOG #1211 MEASURED, PINNED AS A REGRESSION TEST. The retired vs-N
    gate PASSED a TOTAL collapse whenever it hit both counts, because ``not (0.0 < 0.0)`` is True: it
    reported ``observed = 'monotonic'`` over an engine whose herd had stopped entirely. The second arm
    drives that retired form on the identical records, so the claim above is executed rather than
    asserted in prose -- if it ever goes red, this test has stopped being about what it says.
    """
    records = [
        _rec("fixed_aggregate", 12, per_msg=0.0),
        _rec("fixed_aggregate", 24, per_msg=0.0),
    ]
    check = _empty_claims_base_reading_slo(_profile(12, 24), records)
    assert not check.ok, "a dead empty-claim counter at the base count must fail the SLO"
    assert "fixed_aggregate@N=12" in str(check.observed), check.observed

    assert _monotonic_slo("the-retired-vs-n-form", records, _KEY).ok, (
        "the retired vs-N gate is supposed to PASS this total collapse -- that is defect 3, and it "
        "is the reason the replacement above exists"
    )


def test_slo_passes_on_the_healthy_shape_and_says_how_many_lanes_it_graded() -> None:
    """The measured healthy base reading: 39.1 at N=12, against 39.0 predicted from the sweep itself.

    ``ok`` ALONE WOULD BE A GATE THAT CANNOT FAIL. The SLO reports ok=True over a run that graded
    NOTHING -- deliberately, following the ``intake_audit`` shape -- so a green here is evidence only
    when the observed string also says a lane was actually graded. Both are asserted, and the lane
    count is asserted exactly, so a lane silently dropping out of grading fails here.
    """
    records = [
        _rec("fixed_aggregate", 12, per_msg=39.1),
        _rec("fixed_aggregate", 24, per_msg=77.8),
    ]
    check = _empty_claims_base_reading_slo(_profile(12, 24), records)
    assert check.ok, check.observed
    assert str(check.observed) == "present (1 of 1 lane(s) graded)", check.observed


def test_a_missing_base_reading_is_ungraded_rather_than_passed_or_failed() -> None:
    """``None`` is "no reading" -- not "a reading of zero", and not "use the next N up" either.

    THE UNDEFINED READING SITS AT THE BASE COUNT, WHICH IS THE ONLY PLACE IT TESTS ANYTHING.
    ``herd_floor_readings`` matches the base count EXACTLY and never promotes a larger-N reading, so a
    fixture that put the ``None`` at N=24 would leave a healthy base reading to grade and would assert
    nothing at all.

    Three things must hold together, because each alone is satisfied by a different bug: the run is
    not red (a ``None`` coerced to 0.0 would read as a dead counter), it is not silently green either
    (the observed string has to say NOT GRADED), and the N=24 reading must not have been promoted into
    the base slot.
    """
    records = [
        _rec("fixed_aggregate", 12, per_msg=None),
        _rec("fixed_aggregate", 24, per_msg=40.0),
    ]
    check = _empty_claims_base_reading_slo(_profile(12, 24), records)
    observed = str(check.observed)
    assert check.ok, observed
    assert "NOT GRADED" in observed, observed
    assert "no reading" in observed, observed
    assert "40" not in observed, f"the N=24 reading must not fill N=12's slot: {observed}"


# --------------------------------------------------------------------------------------------------
# The latent grouping defect, fixed in the same pass.
# --------------------------------------------------------------------------------------------------


def test_a_pooled_lane_is_ungraded_rather_than_measured_against_a_per_lane_model() -> None:
    """The herd prediction assumes one worker set per lane per stage. A pooled dispatcher is not that.

    THE POOLED FIXTURE READS 0.0 SO THAT GRADING IT WOULD GO RED, which is what makes ``check.ok`` a
    real assertion here rather than a formality: the only way this run stays green is if the pooled
    lane was excluded in words instead of compared against a model that does not describe it. And 0.0
    is the realistic pooled value, not a contrived one -- ``compare.py`` states pooled's empty-claim
    rate SHOULD be materially lower, which is the whole reason the exclusion exists.

    AT LEAST ONE SHIPPED PROFILE ALREADY SETS ``claim_modes = ["per_lane", "pooled"]`` --
    ``harness/load/profiles/pooled_ab.toml`` -- so a pooled lane beside a per_lane one is not
    hypothetical, and an earlier version of this docstring asserted the opposite. What has actually
    kept a wrongly-graded pooled lane from manufacturing a red is narrower: pooled_ab's
    ``[connscale.slo]`` arms ``zero_loss`` and not ``empty_claims_base_reading``, so nothing shipped
    today pairs this check with a pooled arm.

    THAT IS A COINCIDENCE OF CONFIGURATION, NOT A GUARANTEE. ``profile.py``'s ``_validate`` would
    ACCEPT the pairing: it rejects the check only when ``per_lane`` is ABSENT from ``claim_modes``,
    and pooled_ab lists both. So the exclusion below is the only thing standing between a pooled lane
    and a verdict from a model that does not describe it, and it is required regardless.
    """
    records = [
        _rec("fixed_aggregate", 12, per_msg=40.0, claim_mode="per_lane"),
        _rec("fixed_aggregate", 24, per_msg=80.0, claim_mode="per_lane"),
        _rec("fixed_aggregate", 12, per_msg=0.0, claim_mode="pooled"),
        _rec("fixed_aggregate", 24, per_msg=0.0, claim_mode="pooled"),
    ]
    check = _empty_claims_base_reading_slo(_profile(12, 24), records)
    assert check.ok, check.observed
    assert str(check.observed) == "present (1 of 2 lane(s) graded)", check.observed

    by_label = {r.label: r for r in herd_floor_readings(records, _KEY, base_count=12)}
    pooled = by_label["fixed_aggregate/pooled"]
    assert pooled.ok is None, "a pooled lane must be ungraded -- not passed, and not failed"
    assert "claim_mode=pooled" in str(pooled.not_graded), pooled.not_graded
    assert by_label["fixed_aggregate"].ok is True


def test_a_dead_lane_is_still_caught_beside_a_healthy_one() -> None:
    """The grouping must not become a way to hide a real defect behind a second lane.

    Both lanes here are ``per_lane`` and both are graded, so this is the masking case the exclusion
    above cannot cover. The SLO names every dead lane rather than reporting a verdict over the run.
    """
    records = [
        _rec("fixed_aggregate", 12, per_msg=0.0),  # dead
        _rec("fixed_aggregate", 24, per_msg=0.0),
        _rec("fixed_per_conn", 12, per_msg=45.0, rate=12.0),  # healthy, and graded
        _rec("fixed_per_conn", 24, per_msg=90.0, rate=24.0),
    ]
    check = _empty_claims_base_reading_slo(_profile(12, 24), records)
    observed = str(check.observed)
    assert not check.ok, observed
    assert "fixed_aggregate@N=12" in observed, observed
    assert "fixed_per_conn" not in observed, f"only the dead lane is named: {observed}"


# --------------------------------------------------------------------------------------------------
# BACKLOG #1211: the readings must survive a PASSING run.
#
# The SLO writes a number into `observed` only once a reading has already left its band -- a passing
# run records the literal string "monotonic" and discards every value. So the only samples that ever
# survived were the excursions, and a sample selected on having excursioned cannot measure the
# distribution it excursioned from. #1211 requires that variance before anyone may touch the band, so
# these pin that every run records every reading.
#
# NOTHING HERE WIDENS THE BAND, AND LIMB TWO DID NOT WIDEN IT EITHER. The hold this block used to
# carry -- "that is limb two, and it stays blocked until the samples exist" -- is DISCHARGED: the
# samples exist (894 lane transitions from 153 CI runs) and limb two shipped. It did not touch the
# rendered band's width, deliberately, so these rows stay directly comparable with the 454 payloads
# already harvested. What it did was RETIRE the band as a verdict: the emitter still prints OUTSIDE
# BAND and nothing fails on it. The tests in this section cover the RECORDING, which is unchanged.
# --------------------------------------------------------------------------------------------------


def _rows(text: str) -> list[str]:
    """The rendered table's DATA rows, with the preamble prose and the header lines excluded.

    THE PREAMBLE NOW CONTAINS THE LITERAL WORDS "OUTSIDE BAND", on every run, breach or none: limb two
    added a sentence saying an OUTSIDE BAND row fails nothing. So ``"OUTSIDE BAND" in text`` over the
    whole document matches the EXPLANATION instead of a verdict. That one string broke two negative
    controls in this file and silently defanged two positive ones, which then passed on a report whose
    rendered rows carried no verdict at all -- the failure with no signal is the worse half.

    This file already records the general shape at ``test_the_table_carries_NO_band_and_says_so``: a
    substring occurring twice cannot witness the presence of either occurrence. Scope to the row.
    """
    return [line for line in text.splitlines() if line.startswith("| ") and "| lane |" not in line]


def _report(*records: ConnScaleRecord) -> ConnScaleReport:
    return ConnScaleReport(
        profile="smoke",
        engine_url="http://127.0.0.1:0",
        db_backend=None,
        shim_installed=True,
        records=list(records),
        slos=[],
        result_ok=True,
        exit_code=0,
    )


def _render(report: ConnScaleReport, **kw: object) -> str:
    return report.render_readings_markdown(_METRIC, _KEY, tolerance=_MONOTONIC_TOLERANCE, **kw)


def test_a_passing_run_records_every_reading_not_only_the_excursions() -> None:
    """The property #1211 exists for, asserted against a run whose SLO is GREEN.

    The healthy shape is asserted first, so this cannot pass by accidentally rendering a failure.
    """
    recs = [_rec("fixed_per_conn", 12, per_msg=48.4), _rec("fixed_per_conn", 24, per_msg=60.0)]
    premise = _empty_claims_base_reading_slo(_profile(12, 24), recs)
    assert premise.ok and "NOT GRADED" not in str(premise.observed), (
        f"the test lost its own premise: this run must be green AND graded, not green because "
        f"nothing was graded. observed={premise.observed}"
    )

    text = _render(_report(*recs))
    assert "48.4" in text and "60" in text, text
    assert not [row for row in _rows(text) if "OUTSIDE BAND" in row], text


def test_the_slo_alone_would_have_recorded_neither_of_those_numbers() -> None:
    """The other half of the pair: without this change a green run keeps no number at all.

    Stated as a test rather than as a claim in the item, because it is the entire justification for
    emitting anything -- and it is the sort of premise that quietly stops being true.

    RETARGETED ONTO THE LIVE GATE (BACKLOG #1211 limb two). The retired vs-N form recorded the literal
    string "monotonic" on a green run; its replacement records a LANE COUNT. Neither carries a
    reading, which is the property -- but pinned to the retired form this would have asserted a dead
    string, going red only when some unrelated FD change touched it.
    """
    recs = [_rec("fixed_per_conn", 12, per_msg=48.4), _rec("fixed_per_conn", 24, per_msg=60.0)]
    check = _empty_claims_base_reading_slo(_profile(12, 24), recs)
    observed = str(check.observed)
    assert check.ok, observed
    assert "lane(s) graded" in observed, observed
    assert "48.4" not in observed and "60" not in observed, observed


def test_the_replayed_pr343_excursion_reproduces_the_items_own_arithmetic() -> None:
    """BACKLOG #1211 records: ``fixed_per_conn@N=24: 36 < prior 48.4 * 0.75 (= 36.30) short by 0.30``.

    The floor and the margin are produced by the emitter here, not restated by hand, so a change to
    either the tolerance or the arithmetic has to come back through this test.
    """
    text = _render(
        _report(_rec("fixed_per_conn", 12, per_msg=48.4), _rec("fixed_per_conn", 24, per_msg=36.0))
    )
    row = next(line for line in text.splitlines() if "| 24 |" in line)
    assert "36.3" in row, row  # the band floor, 48.4 * 0.75
    assert "-0.3" in row, row  # short by 0.30
    assert "OUTSIDE BAND" in row, row


def test_the_emitted_band_tracks_the_slo_tolerance_rather_than_a_second_copy() -> None:
    """A hard-coded 0.75 in the emitter would drift from the tolerance its caller passes.

    Rendering the SAME records at two tolerances must move the floor, which is only true if the
    emitter reads its tolerance rather than carrying its own.

    THE WIDTH ITSELF IS DELIBERATELY UNCHANGED BY BACKLOG #1211 limb two, which retired this band as a
    verdict without touching it as a number -- so these rows stay directly comparable with the 454
    readings already harvested, and that corpus is what a later item reads to decide whether any floor
    can become a gate. Do not widen it here to make a test pass.
    """
    report = _report(
        _rec("fixed_per_conn", 12, per_msg=100.0), _rec("fixed_per_conn", 24, per_msg=90.0)
    )
    loose = report.render_readings_markdown(_METRIC, _KEY, tolerance=0.25)
    tight = report.render_readings_markdown(_METRIC, _KEY, tolerance=0.05)
    assert "| 75 |" in loose, loose  # 100 * 0.75
    assert "| 95 |" in tight, tight  # 100 * 0.95
    assert any("within band" in row for row in _rows(loose)), loose
    assert any("OUTSIDE BAND" in row for row in _rows(tight)), tight


def test_the_emitted_lane_label_matches_the_graded_lane_label() -> None:
    """A reading filed under ``fixed_per_conn`` that a verdict reports as ``fixed_per_conn/pooled``
    is two distributions, not one. Both sides read ``lane_label``; this asserts they agree.

    The verdict side used to be ``_monotonic_slo``'s detail string. After BACKLOG #1211 limb two the
    empty-claims verdict comes from ``herd_floor_readings`` instead, so that is what is compared. The
    property did not change -- only which function has to agree with the emitter.
    """
    recs = [
        _rec("fixed_per_conn", 12, per_msg=40.0, claim_mode="pooled"),
        _rec("fixed_per_conn", 24, per_msg=10.0, claim_mode="pooled"),
    ]
    assert [r.label for r in herd_floor_readings(recs, _KEY, base_count=12)] == [
        "fixed_per_conn/pooled"
    ]
    assert "| fixed_per_conn/pooled |" in _render(_report(*recs))
    assert lane_label("fixed_per_conn", "pooled") == "fixed_per_conn/pooled"
    assert lane_label("fixed_per_conn", "per_lane") == "fixed_per_conn"


def test_undefined_readings_are_absent_rather_than_rendered_as_zero() -> None:
    """``None`` means no messages were absorbed. A zero row would be a fabricated sample, and it
    would drag any distribution built from these tables toward a value never measured."""
    text = _render(
        _report(
            _rec("fixed_per_conn", 12, per_msg=None),
            _rec("fixed_per_conn", 24, per_msg=42.0),
        )
    )
    assert "| 12 |" not in text, text
    assert "| 24 |" in text
    # The surviving reading is a lane HEAD: the skipped one never became its prior.
    assert "first in lane" in text


def test_a_run_that_produced_no_reading_says_so_rather_than_rendering_an_empty_table() -> None:
    text = _render(_report(_rec("fixed_per_conn", 12, per_msg=None)))
    assert "No empty_claims_per_msg reading was produced" in text
    assert "| lane |" not in text


def test_a_capped_table_states_what_it_dropped() -> None:
    """An oversized step-summary write is dropped ENTIRELY, so a big profile must lose rows. It may
    not lose them silently -- a truncated table that looks complete is worse than a short one."""
    recs = [_rec("fixed_per_conn", n, per_msg=float(n)) for n in range(12, 40)]
    text = _render(_report(*recs), max_rows=5)
    assert "capped at 5" in text
    assert "23 further row(s) not shown" in text
    assert len([line for line in text.splitlines() if line.startswith("| fixed_per_conn |")]) == 5


# --------------------------------------------------------------------------------------------------
# Writing it out. The renderer above is pure; these cover the one place that touches a file.
# --------------------------------------------------------------------------------------------------


def test_the_step_summary_is_appended_never_truncated(tmp_path, monkeypatch) -> None:
    """``$GITHUB_STEP_SUMMARY`` accumulates across every step of the job; overwriting it would eat
    another step's output."""
    summary = tmp_path / "summary.md"
    summary.write_text("## someone else's step\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    _append_step_summary("## mine\n")
    _append_step_summary("## mine again\n")

    body = summary.read_text(encoding="utf-8")
    assert body.startswith("## someone else's step")
    assert body.count("## mine") == 2


def test_the_recorder_writes_the_readings_through_to_the_summary(tmp_path, monkeypatch) -> None:
    """End to end: a report in, the rows in the job summary, on a run whose SLO passes."""
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("RUNNER_OS", "Windows")
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")

    _record_ratio_readings(
        _report(_rec("fixed_per_conn", 12, per_msg=48.4), _rec("fixed_per_conn", 24, per_msg=60.0))
    )

    body = summary.read_text(encoding="utf-8")
    assert "48.4" in body and "60" in body
    assert "runner_os: Windows" in body and "run_id: 12345" in body
    assert not [row for row in _rows(body) if "OUTSIDE BAND" in row], body


def test_a_local_run_writes_a_FILE_because_stderr_does_not_survive_a_pass(
    tmp_path, monkeypatch
) -> None:
    """REPLACES a test that asserted the opposite, and the old one PASSED while the behaviour was broken.

    It read ``assert "readings go here" in capsys.readouterr().err`` and its docstring said the
    emitter "must not invent a file". **capsys reads pytest's CAPTURE**, so the assertion saw a write
    that a real passing run never surfaces: pytest captures at the FILE DESCRIPTOR and DISCARDS the
    capture when the test passes. The test's own instrument was the thing hiding the defect -- it
    asserted a property that was true and useless, on exactly the runs this emitter exists for.

    Measured both ways before the change: a passing test's stderr marker appears 0 times under
    default capture and 1 time under ``-s``.
    """
    target = tmp_path / "readings.md"
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setenv(_LOCAL_READINGS_ENV, str(target))

    _append_step_summary("first\n")
    _append_step_summary("second\n")

    assert target.read_text(encoding="utf-8") == "first\nsecond\n", "append, never truncate"


def test_the_job_summary_outranks_the_local_override(tmp_path, monkeypatch) -> None:
    """CI behaviour is untouched by the local escape hatch, which is the point of the precedence."""
    summary = tmp_path / "summary.md"
    local = tmp_path / "local.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv(_LOCAL_READINGS_ENV, str(local))

    _append_step_summary("ci\n")

    assert summary.read_text(encoding="utf-8") == "ci\n"
    assert not local.exists(), "a stray local variable must not divert CI's readings"


def test_with_no_variable_set_it_lands_somewhere_and_names_where(monkeypatch) -> None:
    """A reading nobody can find is not a reading, so the path is announced.

    The announcement is a WARNING and not a print, because warnings survive the same capture that
    swallows stdout and stderr on a passing test. A print here would reproduce the defect inside the
    fix.
    """
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv(_LOCAL_READINGS_ENV, raising=False)

    marker = "readings-probe-" + str(id(monkeypatch))
    with pytest.warns(UserWarning, match="connscale readings appended to") as caught:
        _append_step_summary(marker + "\n")

    named = pathlib.Path(str(caught[0].message).split("appended to ", 1)[1].strip())
    assert named.is_file(), f"the warning named {named} but nothing is there"
    assert marker in named.read_text(encoding="utf-8")


def test_the_default_landing_place_actually_receives_the_write(monkeypatch) -> None:
    """Asserts the WRITE, deliberately WITHOUT asserting the warning.

    Its sibling above checks the path is announced. Keeping them separate is what lets the suite tell
    two different regressions apart: reverting to the old stderr fallback writes NO file, while
    swapping the warning for a print still writes one. Scored together they produced IDENTICAL red
    sets -- a suite that catches both defects without distinguishing them.
    """
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv(_LOCAL_READINGS_ENV, raising=False)

    marker = "landing-probe-" + str(id(monkeypatch))
    before = _DEFAULT_READINGS_PATH.stat().st_size if _DEFAULT_READINGS_PATH.is_file() else 0
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        _append_step_summary(marker + "\n")

    assert _DEFAULT_READINGS_PATH.is_file(), "nothing reached the default landing place"
    assert marker in _DEFAULT_READINGS_PATH.read_text(encoding="utf-8")
    assert _DEFAULT_READINGS_PATH.stat().st_size > before, "append, so a shared file grows"


def test_an_unwritable_summary_warns_rather_than_failing_the_run(tmp_path, monkeypatch) -> None:
    """Turning a diagnostics failure into a red leg on an unrelated pull request is the disease
    #1211 is treating. It must not be silent either: a dead emitter and a live one would render
    identically, and the dead one would look like a clean run forever."""
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "no-such-dir" / "summary.md"))
    with pytest.warns(UserWarning, match="could not record connscale readings"):
        _append_step_summary("x\n")


def test_the_pairing_is_shared_rather_than_reimplemented() -> None:
    """``monotonic_pairs`` is ONE definition of the pairing, read by two consumers. Both are driven.

    THE TWO CONSUMERS NO LONGER READ THE SAME METRIC, which is why this test names two. The emitter
    still pairs on ``empty_claims_per_msg`` -- that is the recorded ratio, unchanged by BACKLOG #1211
    limb two -- while the only SLO still built on ``_monotonic_slo`` is ``fd_count_monotonic``.
    Driving the SLO on the retired empty-claims metric would assert agreement about a metric no gate
    reads: vacuously true, and unable to regress. So the pairing arithmetic is asserted on the
    emitter's metric and the SLO's agreement with it is asserted on the FD counter.
    """
    recs = [_rec("fixed_per_conn", 12, per_msg=48.4), _rec("fixed_per_conn", 24, per_msg=36.0)]
    pairs = monotonic_pairs(recs, _KEY, tolerance=_MONOTONIC_TOLERANCE)
    assert len(pairs) == 1
    pair = pairs[0]
    assert not pair.ok and pair.count == 24 and pair.prior == 48.4
    assert pair.threshold == pytest.approx(36.3)

    fd_key = lambda r: r.fd_count_peak  # noqa: E731
    fd_recs = [
        _rec("fixed_per_conn", 12, per_msg=48.4, fd_peak=200),
        _rec("fixed_per_conn", 24, per_msg=36.0, fd_peak=100),
    ]
    fd_pairs = monotonic_pairs(fd_recs, fd_key, tolerance=_MONOTONIC_TOLERANCE)
    assert len(fd_pairs) == 1 and not fd_pairs[0].ok, (
        "the FD fixture must actually breach, or the agreement asserted below holds trivially"
    )
    fd_pair = fd_pairs[0]
    detail = str(_monotonic_slo("fd_count_monotonic", fd_recs, fd_key).observed)
    assert detail == (
        f"{fd_pair.label}@N={fd_pair.count}: {fd_pair.value:.3g} < prior {fd_pair.prior:.3g} "
        f"* {fd_pair.tolerance_floor:.2f}"
    )


# --- the machine-readable copy (BACKLOG #1211) ---------------------------------------------------


def test_the_json_copy_carries_the_same_pairs_as_the_markdown(monkeypatch) -> None:
    """THE ANTI-DRIFT CONTROL, and it is the reason this copy is safe to add at all.

    Two renderings of one measurement is exactly how a second definition of the band gets born. Both
    go through ``monotonic_pairs``, so this asserts they AGREE on every lane, value and verdict --
    if either grew its own pairing, this diverges instead of both quietly being plausible.
    """
    recs = [
        _rec("fixed_per_conn", 12, per_msg=48.0),
        _rec("fixed_per_conn", 24, per_msg=30.0),
    ]
    report = _report(*recs)
    payload = report.readings_payload(
        "empty_claims_per_msg", lambda r: r.empty_claims_per_msg, tolerance=0.25
    )
    table = report.render_readings_markdown(
        "empty_claims_per_msg", lambda r: r.empty_claims_per_msg, tolerance=0.25
    )

    judged = [r for r in payload["readings"] if not r["first_in_lane"]]
    assert len(judged) == 1
    row = judged[0]
    assert row["ok"] is False, "30.0 is below 48.0 * 0.75 and both must say so"
    # The markdown states the same verdict for the same reading. Scoped to the ROW: the preamble
    # carries the words "OUTSIDE BAND" too, so a whole-document test here passes on a table whose
    # rows are all within band -- a positive control that cannot fail, and it would say nothing.
    assert any("OUTSIDE BAND" in r for r in _rows(table)), table
    assert f"{row['value']:.4g}" in table
    assert f"{row['prior']:.4g}" in table
    assert row["ratio"] == pytest.approx(30.0 / 48.0)


def test_the_json_copy_is_not_capped_where_the_markdown_is(monkeypatch) -> None:
    """The markdown caps rows because an oversized step summary write is dropped IN FULL. An
    artifact has no such cliff, so silently dropping rows from the machine-readable copy would be
    the worse trade -- it is the copy a later reader actually computes from."""
    recs = []
    for n in range(2, 60, 2):
        recs.append(_rec("fixed_per_conn", n, per_msg=float(n)))
    payload = _report(*recs).readings_payload(
        "empty_claims_per_msg", lambda r: r.empty_claims_per_msg, tolerance=0.25
    )
    assert len(payload["readings"]) == len(recs), "every reading must survive into the JSON"


def test_the_json_is_written_to_the_named_path(tmp_path, monkeypatch) -> None:
    target = tmp_path / "nested" / "readings.json"
    monkeypatch.setenv(_READINGS_JSON_ENV, str(target))

    _write_readings_json({"schema_version": 1, "readings": []})

    assert target.is_file(), "the parent directory must be created"
    assert json.loads(target.read_text(encoding="utf-8"))["schema_version"] == 1


def test_a_failed_json_write_warns_rather_than_failing_the_run(tmp_path, monkeypatch) -> None:
    """Same discipline as the markdown: a diagnostics failure must never redden an unrelated PR."""
    monkeypatch.setenv(_READINGS_JSON_ENV, str(tmp_path))  # a directory cannot be written as a file

    with pytest.warns(UserWarning, match="could not write connscale readings JSON"):
        _write_readings_json({"schema_version": 1})


# --------------------------------------------------------------------------------------------------
# The predicted herd floor (BACKLOG #1211 limb two): RECORDED, NOT ENFORCED.
#
# THE MODEL HAD NO TEST AT ALL BEFORE THIS SECTION, and it is the piece the whole limb rests on: the
# floor that an owner ruling declined to gate on, and the number a later item will read a distribution
# of. `report.py`'s own comment on `ENGINE_IDLE_POLL_INTERVAL_S` once cited a test in this file as
# what caught drift between that mirror and the engine's default. No such test existed, and that
# comment has since retracted the citation itself -- it now says the mirror
# "IS ENFORCED BY NOTHING AT RUNTIME" and must be moved by hand. These tests are the coverage that
# vanished citation promised.
#
# THEY DO NOT RESTORE THE CITATION, deliberately. report.py names no test now, so nothing here has to
# stay in step with a sentence over there -- which is how the falsified quotation happened: a sibling
# change deleted the sentence this comment was quoting, inside the same branch that added the quote.
# The one fragment quoted above is kept SHORT ENOUGH TO GREP: report.py wraps its comment prose, so a
# quotation spanning a line break is unfindable by the obvious check and rots the same silent way.
#
# The arithmetic is pinned against LITERALS worked out from the derivation, never against a second
# call to the function under test. A prediction re-derived from the code it is testing would agree
# with any change to that code, which is how a model becomes unfalsifiable while looking covered.
# --------------------------------------------------------------------------------------------------


def _render_with_floor(report: ConnScaleReport, base_count: int) -> str:
    """Render WITH the herd-floor section. Kept separate from ``_render`` on purpose.

    The floor table emits rows shaped like the ratio table's, so folding ``base_count`` into
    ``_render`` would silently inflate the row counts the capping tests assert on -- and those tests
    would keep passing while measuring a different table.
    """
    return report.render_readings_markdown(
        _METRIC, _KEY, tolerance=_MONOTONIC_TOLERANCE, base_count=base_count
    )


_FLOOR_HEADING = "### predicted herd floor at N="


def _floor_rows(text: str) -> list[str]:
    """The FLOOR table's rows only, taken from after its heading.

    BOTH TABLES EMIT ROWS OF THE SAME SHAPE -- ``| lane | N | ... |`` -- so ``_rows`` over the whole
    document returns the ratio table's rows first, and a ``next(...)`` for a lane at the base count
    finds the wrong table's row and reads a blank band column as a missing floor. Split on the
    heading; the two tables answer different questions about the same lane.
    """
    return _rows(text[text.index(_FLOOR_HEADING) :])


def test_the_predicted_levels_reproduce_the_four_harvested_cells() -> None:
    """The model derived for BACKLOG #1211, pinned at the four cells the smoke sweep actually runs.

    DERIVED, NOT FITTED, and this test is where that stays true. ``wake = W*(N-1)`` empty claims from
    the engine-wide singleton wake, ``idle = W*N/(interval*rate)`` from the clock-driven re-SELECT,
    and the floor is their geometric mean. Against the harvested ubuntu medians -- 39.89, 79.29,
    47.41, 79.17 -- these predictions land within 5.1 percent, having been chosen against none of
    them.

    THE fixed_per_conn CELLS OFFER A DIFFERENT RATE, which is exactly the trap the ``rate`` parameter
    on ``_rec`` exists for: at N=12 with per-connection rate 1.0 the offered aggregate is 12.0, not
    24.0, and the predicted floor is 23.24 rather than 15.30.
    """
    agg_12 = predict_herd_levels(12, 24.0)
    agg_24 = predict_herd_levels(24, 24.0)
    per_conn_12 = predict_herd_levels(12, 12.0)
    per_conn_24 = predict_herd_levels(24, 24.0)
    assert agg_12 is not None and agg_24 is not None
    assert per_conn_12 is not None and per_conn_24 is not None

    assert (agg_12.wake, agg_12.idle, agg_12.total) == (33.0, 6.0, 39.0)
    assert agg_12.floor == pytest.approx(15.297, abs=0.001)  # sqrt(39 * 6)
    assert agg_24.total == 81.0 and agg_24.floor == pytest.approx(31.177, abs=0.001)
    assert per_conn_12.total == 45.0 and per_conn_12.floor == pytest.approx(23.238, abs=0.001)
    assert per_conn_24.total == 81.0

    # 15.30 is the number the owner's record-do-not-gate ruling was made against: a push to `main`
    # whose windows-2022 job PASSED read 13.12 here. Gating would have reddened a green leg.
    assert agg_12.floor < 15.30 < agg_12.total


def test_no_prediction_is_made_where_the_model_has_no_premise() -> None:
    """``None`` is RECORDED BUT NOT GRADED, and it must never be softened into a default.

    A single connection has no siblings, so there is no herd to predict; a non-positive offered rate
    is a folded batch-box record or a step that offered nothing, and dividing by it would either
    raise or manufacture a floor from a rate that means something else.
    """
    assert predict_herd_levels(1, 24.0) is None
    assert predict_herd_levels(0, 24.0) is None
    assert predict_herd_levels(12, 0.0) is None
    assert predict_herd_levels(12, -1.0) is None
    assert predict_herd_levels(2, 24.0) is not None, "N=2 is the first count with a sibling"


def test_the_mirrored_engine_poll_interval_has_not_drifted() -> None:
    """``ENGINE_IDLE_POLL_INTERVAL_S`` is a COPY of an engine value the harness does not import.

    It is the denominator of the ``idle`` term, so a drift between the engine's backstop and this
    mirror moves every predicted floor with no connscale change and nothing at runtime to notice.
    ``report.py`` states plainly that nothing catches it -- the mirror
    "IS ENFORCED BY NOTHING AT RUNTIME" -- and it names no test. An earlier version of that comment
    did claim one, before BACKLOG #1211 limb two, which made it a compensating control resting on a
    false premise. This test is the coverage; report.py no longer cites it, so neither side has to
    track the other's prose.

    BOTH ENGINE VALUES ARE PINNED, because which one is operative depends on the claim mode. The
    connscale sweep runs ``per_lane`` (the runner sets ``MEFOR_PIPELINE_CLAIM_MODE`` there), where the
    backstop is ``RegistryRunner``'s ``poll_interval``. ``pooled_sweep_interval`` is the pooled-mode
    sibling, and report.py's comment explicitly does NOT cite it. It says
    "It is NOT ``pooled_sweep_interval``," and records that an earlier version of itself did. They are
    both 0.25 today, which is why citing the wrong one read as correct for as long as it did. Pinning
    both means either drifting fails here.

    EVERY QUOTATION IN THIS DOCSTRING IS TRIMMED TO ONE SOURCE LINE ON BOTH SIDES. report.py wraps its
    comment prose and so does this file, so a quote spanning a line break cannot be checked by the
    obvious grep -- which is exactly how the falsified quotation these paragraphs replace survived.
    """
    from messagefoundry.config.settings import PipelineSettings
    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    mirror = ENGINE_IDLE_POLL_INTERVAL_S
    per_lane_backstop = inspect.signature(RegistryRunner.__init__).parameters["poll_interval"]
    pooled_backstop = PipelineSettings.model_fields["pooled_sweep_interval"].default

    assert mirror == per_lane_backstop.default, (
        "the harness mirror has drifted from RegistryRunner's per_lane backstop, which is the one "
        "the connscale sweep actually runs under -- every recorded herd floor is now a number about "
        "a different engine"
    )
    assert mirror == pooled_backstop, (
        "the harness mirror has drifted from PipelineSettings.pooled_sweep_interval, the pooled-mode "
        "backstop. The connscale sweep runs per_lane, so this is not the value it reads -- it is "
        "pinned so that a drift in EITHER engine default fails here, not because report.py cites it "
        "(its comment says the opposite: 'It is NOT pooled_sweep_interval')"
    )
    assert CONNSCALE_WORKERS_PER_CONNECTION == 3, (
        "router + transform + delivery worker per connection. Changing this changes every predicted "
        "level, so change it deliberately and update the pinned cells above in the same commit."
    )


def test_the_floor_table_grades_the_base_count_and_says_why_when_it_cannot() -> None:
    """The three-state verdict, rendered. ``ok`` is ``bool | None`` and the third state is not a pass.

    A pooled lane and a per_lane lane are rendered together so the two shapes appear side by side:
    one carries a verdict, the other carries the reason it has none. A two-way truthiness test in the
    renderer would print the ungraded lane as BELOW FLOOR, and nothing type-checks this package.
    """
    text = _render_with_floor(
        _report(
            _rec("fixed_aggregate", 12, per_msg=39.1),
            _rec("fixed_aggregate", 24, per_msg=77.8),
            _rec("fixed_aggregate", 12, per_msg=0.5, claim_mode="pooled"),
        ),
        base_count=12,
    )
    assert "predicted herd floor at N=12" in text, text
    assert "recorded, not enforced" in text, text

    graded = next(r for r in _floor_rows(text) if r.startswith("| fixed_aggregate | 12 |"))
    assert "39.1" in graded and "15.3" in graded and "above floor" in graded, graded

    ungraded = next(r for r in _floor_rows(text) if r.startswith("| fixed_aggregate/pooled |"))
    assert "claim_mode=pooled" in ungraded, ungraded
    assert "BELOW FLOOR" not in ungraded, f"an ungraded lane is not a breach: {ungraded}"


def test_a_reading_UNDER_its_predicted_floor_is_graded_below_floor() -> None:
    """THE OTHER DIRECTION OF THE FLOOR COMPARISON. Without this the true branch never runs.

    Every other fixture in this suite reads ABOVE its predicted floor, so ``ok = value >=
    prediction.floor`` was only ever exercised on one side. A comparison pinned in one direction
    cannot be told apart from a constant: three separate mutations of it -- ``ok = True``, the
    renderer's verdict column hard-coded to "above floor", and ``ok = value >= 0.0`` -- all left the
    suite green. The recorded floor column is what BACKLOG #1415 will read to decide whether to gate,
    so a column that cannot register a breach is a measurement nobody can act on.

    9.0 IS CHOSEN TO SEPARATE THE FLOOR FROM THE SIGN TEST, which is the mutation that would otherwise
    hide. At N=12 offering 24.0/s the predicted floor is 15.297, so 9.0 is a breach -- and it is
    strictly positive, so ``_empty_claims_base_reading_slo`` PASSES the same records. The two checks
    answer different questions about one reading, and swapping the floor for the sign test reddens
    here rather than agreeing with itself.
    """
    records = [
        _rec("fixed_aggregate", 12, per_msg=9.0),
        _rec("fixed_aggregate", 24, per_msg=60.0),
    ]

    reading = next(r for r in herd_floor_readings(records, _KEY, base_count=12) if r.count == 12)
    assert reading.not_graded is None, "this lane is per_lane and has a prediction -- it is graded"
    assert reading.prediction is not None
    assert reading.value == 9.0 < reading.prediction.floor, reading
    assert reading.ok is False, (
        f"a reading of 9.0 under a predicted floor of {reading.prediction.floor:.3f} must grade "
        f"False, not None and not True; got ok={reading.ok!r}"
    )

    # The sign test is UNAFFECTED, which is what makes the floor a second, independent question.
    assert _empty_claims_base_reading_slo(_profile(12, 24), records).ok, (
        "9.0 is a positive base reading -- the sign test must still pass, or this fixture is not "
        "separating the floor from it"
    )

    row = next(
        r
        for r in _floor_rows(_render_with_floor(_report(*records), base_count=12))
        if r.startswith("| fixed_aggregate | 12 |")
    )
    assert "BELOW FLOOR" in row, f"the rendered verdict must name the breach: {row}"
    assert "above floor" not in row, row
    assert "-6.3" in row, f"the margin must render NEGATIVE, signed, not as a distance: {row}"

    payload = _report(*records).readings_payload(_METRIC, _KEY, tolerance=0.25, base_count=12)
    block = payload["herd_floor"]
    assert isinstance(block, dict)
    json_row = next(r for r in block["readings"] if r["count"] == 12)
    assert json_row["ok"] is False, (
        f"the machine-readable copy must agree with the table: {json_row}"
    )
    assert json_row["margin"] == pytest.approx(9.0 - 15.297, abs=0.001), json_row


def test_the_floor_block_is_absent_unless_a_base_count_is_given() -> None:
    """``base_count`` is optional on both emitters, so a consumer must read the block with ``.get``.

    Asserted on both renderings together: a block that appeared in one and not the other would be two
    answers to one question, and the JSON is the copy a later harvest computes from.
    """
    report = _report(_rec("fixed_aggregate", 12, per_msg=39.1))
    assert "predicted herd floor" not in _render(report)
    assert "herd_floor" not in report.readings_payload(_METRIC, _KEY, tolerance=0.25)

    assert "predicted herd floor" in _render_with_floor(report, base_count=12)
    assert "herd_floor" in report.readings_payload(_METRIC, _KEY, tolerance=0.25, base_count=12)


def test_the_floor_block_says_the_same_thing_in_both_renderings() -> None:
    """The anti-drift control, one metric family over from the ratio's.

    Two renderings of one measurement is how a second definition gets born, and the JSON is the copy
    a later harvest will actually read -- so the markdown agreeing with it is what makes the harvest
    auditable against what CI printed at the time.
    """
    recs = [_rec("fixed_aggregate", 12, per_msg=39.1), _rec("fixed_aggregate", 24, per_msg=77.8)]
    report = _report(*recs)
    block = report.readings_payload(_METRIC, _KEY, tolerance=0.25, base_count=12)["herd_floor"]
    assert isinstance(block, dict)

    assert block["base_count"] == 12
    assert block["enforced"] is False, "the floor is recorded, not gated -- an owner ruling"
    assert block["workers_per_connection"] == CONNSCALE_WORKERS_PER_CONNECTION
    assert block["idle_poll_interval_s"] == ENGINE_IDLE_POLL_INTERVAL_S

    rows = block["readings"]
    assert isinstance(rows, list) and len(rows) == 1
    row = rows[0]
    assert row["lane"] == "fixed_aggregate" and row["count"] == 12
    assert row["value"] == 39.1 and row["ok"] is True and row["not_graded"] is None
    assert row["predicted_total"] == 39.0
    assert row["floor"] == pytest.approx(15.297, abs=0.001)
    assert row["margin"] == pytest.approx(39.1 - 15.297, abs=0.001)

    graded = next(
        r for r in _floor_rows(_render_with_floor(report, base_count=12)) if "| 12 |" in r
    )
    assert f"{row['floor']:.3g}" in graded, graded
    assert f"{row['predicted_total']:.3g}" in graded, graded


def test_the_payload_version_moved_and_the_harvested_ratio_ROWS_did_not() -> None:
    """The version bump is pinned HERE because nothing else pins it, in either direction.

    ``readings_payload``'s ``schema_version`` went 1 -> 2 for the ``herd_floor`` block. It is a plain
    literal in a dict, and the only other schema assertion in this suite reads ``to_json()`` and the
    module-level ``SCHEMA_VERSION`` -- a DIFFERENT artifact, deliberately left at 1. Without this a
    reverted bump, or a bump applied to the wrong one of the two, changes nothing anybody would see.

    THE RATIO ROW SHAPE IS PINNED BESIDE IT, and that is the load-bearing half: 454 version-1 payloads
    were harvested for BACKLOG #1211, and a later item reads them together with everything written
    after this. A key added to, renamed in or dropped from a ratio row splits that corpus in two.
    """
    report = _report(
        _rec("fixed_aggregate", 12, per_msg=48.0), _rec("fixed_aggregate", 24, per_msg=30.0)
    )
    payload = report.readings_payload(_METRIC, _KEY, tolerance=0.25, base_count=12)
    assert payload["schema_version"] == 2

    rows = payload["readings"]
    assert isinstance(rows, list) and len(rows) == 2
    head, judged = rows
    assert head["first_in_lane"] is True and judged["first_in_lane"] is False

    # TWO SHAPES, PINNED SEPARATELY. A lane's first reading has no prior, so it carries no band and no
    # verdict -- writing one would be a threshold computed from nothing. Pinning only the judged row
    # would leave the head row free to grow a fabricated `ok`, which is the exact error the ratio
    # table's own "first in lane" rendering exists to avoid.
    assert set(head) == {"lane", "count", "value", "first_in_lane"}, sorted(head)
    assert set(judged) == {
        "lane",
        "count",
        "value",
        "prior",
        "threshold",
        "margin",
        "ratio",
        "ok",
        "first_in_lane",
    }, (
        f"a ratio row's shape changed: {sorted(judged)}. The 454 payloads already harvested carry "
        f"the version-1 keys, so this is a corpus split, not a refactor -- say why in the same commit."
    )


# --------------------------------------------------------------------------------------------------
# BACKLOG #1366: the BAND-LESS diagnostic fields.
#
# The ratio says THAT something moved; these say WHICH. Drain-tail and reload-probe separate ONLY on
# drain_seconds against reload_seconds; contention separates from probe-cost ONLY on the FD probe's
# tick counts. Every one of these readings already existed on the record and never left the `test`
# job, which uploads no artifacts -- so a connscale failure was undiagnosable from CI alone.
#
# NONE OF THEM HAS AN SLO BAND, and that is the design constraint the whole shape follows from. Since
# BACKLOG #1211 limb two retired the empty-claims band as a verdict, `fd_count_monotonic` is the ONLY
# SLO left that has one -- this comment said "two" and named `empty_claims_monotonic` beside it, which
# stopped being true in the same commit that deleted that name. Rendering `prior` / `band floor` /
# `margin` for a band-less field would print a threshold computed from whichever reading happened to
# precede it -- false precision manufactured by the renderer. Hence a SECOND table rather than a reuse
# of the banded one.
# --------------------------------------------------------------------------------------------------


def _diag(mode: str, count: int, **over: object) -> ConnScaleRecord:
    """A record with the diagnostic fields set. Reuses `_rec` so the inert placeholders stay in one
    place; `dataclasses.replace` works because ConnScaleRecord is frozen."""
    base = _rec(mode, count, per_msg=10.0)
    return dataclasses.replace(base, **over)  # type: ignore[arg-type]


def _diag_report(*records: ConnScaleRecord) -> ConnScaleReport:
    return ConnScaleReport(
        profile="smoke",
        engine_url="http://127.0.0.1:0",
        db_backend=None,
        shim_installed=True,
        records=list(records),
        slos=[],
        result_ok=True,
        exit_code=0,
    )


#: The fields this item ships, written out INDEPENDENTLY of the constant under test.
#:
#: THE FIRST VERSION OF THE TEST BELOW ITERATED `DIAGNOSTIC_FIELDS` AND CHECKED EACH LABEL AGAINST THE
#: RENDERED TEXT. That is self-referential: rename a field in the set and the test looks for the NEW
#: name, finds it, and passes. A mutation run proved it -- renaming `cpu_util_cores_mean` out of the
#: shipped set SURVIVED. A test that reads the same constant it is testing measures nothing.
_EXPECTED_DIAGNOSTIC_LABELS = frozenset(
    {
        "drain_seconds",
        "reload_seconds",
        "fd_probe_ticks",
        "fd_probe_degraded_ticks",
        "cpu_util_cores_mean",
    }
)


def test_the_shipped_field_set_is_exactly_what_this_item_promises() -> None:
    """Pinned against a LITERAL, not against the constant itself, so an add, a removal or a rename all
    fail here and have to be made deliberately."""
    shipped = {f.label for f in DIAGNOSTIC_FIELDS}
    assert shipped == _EXPECTED_DIAGNOSTIC_LABELS, (
        f"the shipped diagnostic set changed. Added: {sorted(shipped - _EXPECTED_DIAGNOSTIC_LABELS)}; "
        f"removed: {sorted(_EXPECTED_DIAGNOSTIC_LABELS - shipped)}. That is a scope change to BACKLOG "
        f"#1366, not a refactor -- update this literal in the same commit and say why."
    )


def test_every_shipped_diagnostic_field_reaches_the_table() -> None:
    """...and each one actually renders. Checked against the LITERAL for the same reason."""
    text = _diag_report(_diag("fixed_per_conn", 12)).render_diagnostics_markdown()
    for label in sorted(_EXPECTED_DIAGNOSTIC_LABELS):
        assert label in text, f"{label} never reached the table: {text}"


def test_each_field_says_what_it_DISCRIMINATES_not_just_what_it_is() -> None:
    """A reader meeting these in a job summary needs to know which explanation each one separates.
    A bare column header is a number with no question attached to it."""
    text = _diag_report(_diag("fixed_per_conn", 12)).render_diagnostics_markdown()
    for field in DIAGNOSTIC_FIELDS:
        assert field.discriminates in text, f"{field.label} emitted without its rationale"


def test_THE_DISTINCTION_THAT_MATTERS_none_renders_as_a_dash_never_as_zero() -> None:
    """ "the probe did not measure" and "the probe measured zero" are DIFFERENT VERDICTS, and telling
    them apart is the entire point of fd_probe_degraded_ticks. A None coerced to 0 would assert a
    clean measurement that never happened."""
    text = _diag_report(
        _diag("fixed_per_conn", 12, reload_seconds=None, fd_probe_degraded_ticks=0)
    ).render_diagnostics_markdown()
    row = next(line for line in text.splitlines() if line.startswith("| fixed_per_conn |"))
    assert "| - |" in row, f"an unmeasured field must render as a dash: {row}"
    assert "| 0 |" in row, f"a measured zero must still render as 0: {row}"


def test_the_table_carries_NO_band_and_says_so() -> None:
    """The constraint that produced a second renderer. A threshold column here would be manufactured."""
    text = _diag_report(_diag("fixed_per_conn", 12)).render_diagnostics_markdown()
    header = next(line for line in text.splitlines() if line.startswith("| lane | N |"))
    for forbidden in ("prior", "band floor", "margin", "verdict"):
        assert forbidden not in header, f"a band-less table must not carry a {forbidden!r} column"
    # PINNED TO THE SENTENCE, NOT THE PHRASE. The first version asserted "no band" over the whole
    # text, which the HEADING also satisfies -- so deleting the explanatory sentence SURVIVED a
    # mutation. A substring occurring twice cannot witness the presence of either occurrence.
    assert "None of these has an SLO band" in text, (
        "the preamble must state IN PROSE that these fields carry no band. The heading alone is not "
        "enough -- a reader skimming to the table needs it beside the numbers."
    )


def test_it_emits_on_a_PASSING_report():  # noqa: ANN201
    """The selection-bias property, one metric family over from #1211. A field recorded only on
    failure cannot establish its own normal range."""
    report = _diag_report(_diag("fixed_per_conn", 12), _diag("fixed_per_conn", 24))
    assert report.result_ok, "the test lost its own premise"
    text = report.render_diagnostics_markdown()
    assert text.count("| fixed_per_conn |") == 2, text


def test_the_lane_label_is_the_SAME_definition_the_banded_table_uses() -> None:
    """Two tables from one run must name a lane identically, or a reader diffing them chases a
    difference in the labelling rather than in the data."""
    recs = [_diag("fixed_per_conn", 12, claim_mode="pooled")]
    text = _diag_report(*recs).render_diagnostics_markdown()
    assert f"| {lane_label('fixed_per_conn', 'pooled')} |" in text
    assert "| fixed_per_conn/pooled |" in text


def test_a_run_with_no_records_says_so_rather_than_rendering_an_empty_table() -> None:
    text = _diag_report().render_diagnostics_markdown()
    assert "No record was produced" in text
    assert "| lane | N |" not in text


def test_a_capped_DIAGNOSTICS_table_states_what_it_dropped() -> None:
    """Same reason as the banded table: an oversized step-summary write is dropped ENTIRELY, so a big
    profile must lose rows -- and may not lose them silently.

    NAMED DISTINCTLY FROM THE BANDED TABLE'S CAP TEST ON PURPOSE. This function first shared that
    name, and Python silently REPLACED the earlier definition -- pytest collected one, #236's cap test
    stopped running, and nothing reported it. The guard below now fails the file rather than the run
    going quietly one test lighter."""
    recs = [_diag("fixed_per_conn", n) for n in range(12, 30)]
    text = _diag_report(*recs).render_diagnostics_markdown(max_rows=4)
    assert "capped at 4" in text
    assert "14 further row(s) not shown" in text
    assert len([x for x in text.splitlines() if x.startswith("| fixed_per_conn |")]) == 4


def test_the_fixture_emits_diagnostics_UNCONDITIONALLY_not_only_on_failure() -> None:
    """The renderer emitting on a passing report is only half the property. The FIXTURE must call it
    without a condition -- gating it on `result_ok` would restore exactly the selection bias #1211
    exists to remove, and the renderer's own tests could not see that.

    Scanned rather than driven: the fixture spawns engine subprocesses, so running it here would cost
    the whole sweep to assert one call site.
    """
    source = pathlib.Path(_smoke_module.__file__).read_text(encoding="utf-8")
    body = source[source.index("async def smoke_report") :]
    call = re.search(r"^\s*_record_diagnostics\(report\)\s*$", body, re.M)
    assert call, f"the fixture must call _record_diagnostics; body was {body[:400]!r}"
    line = body[: call.start()].count(chr(10))
    preceding = body.splitlines()[max(0, line - 3) : line]
    assert not any(re.match(r"\s*(if|elif|else|try|except)\b", p) for p in preceding), (
        f"the call must be unconditional; the three lines before it were {preceding}"
    )


def test_no_two_tests_in_this_file_share_a_name() -> None:
    """A duplicate `def test_...` is SILENT: the later definition replaces the earlier, pytest collects
    one, and the lost test leaves no error, no warning and no failing assertion. The only visible trace
    is a collected count one lower than the number of definitions -- which nobody reads.

    Caught here for real: a new cap test was given the name of an existing one, and #236's cap coverage
    vanished. The file counted 29 definitions and ran 28.
    """
    source = pathlib.Path(__file__).read_text(encoding="utf-8")
    names = re.findall(r"^def (test_[A-Za-z0-9_]+)", source, re.M)
    duplicates = sorted({n for n in names if names.count(n) > 1})
    assert not duplicates, (
        f"these test names are defined more than once, so the earlier definition is silently "
        f"discarded: {duplicates}. Rename one; do not delete either."
    )
    # Positive control: the scan must actually be finding tests, or the assertion above is vacuous.
    assert len(names) > 20, (
        f"the name scan found only {len(names)} tests; it is not reading the file"
    )
