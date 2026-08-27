# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1101: the empty-claims monotonicity SLO must measure the engine, not the runner.

The SLO used to read ``empty_claims_per_s``, which carries wall clock in its denominator. Anything
that slowed the run -- CPU contention on a shared CI runner, or the O(N) reload probe firing mid-hold
and stalling commits -- collapsed the numerator while the denominator kept ticking, so the metric
fell and the gate went red with **no engine change**. Measured on one commit, one box: four contended
replicates spread **0.451 to 2.49** against a 0.75 floor. That is a coin flip, not a detector.

The fix reads ``empty_claims_per_msg`` instead. Both inputs are deltas over the SAME first-to-last
in-hold samples, so the span cancels and the quantity is exactly ``Δempty_claims / Δread``.

**These tests exist to stop the fix from being the WRONG kind of fix.** A metric that never fails is
not an improvement on one that fails at random, and a correction is the easiest place to skip
measuring because it feels like it has already paid its dues. So the invariance property and the
still-detects-a-real-regression property are pinned TOGETHER: neither alone is evidence.
"""

from __future__ import annotations

import json
import pathlib
import warnings

import pytest

from harness.load.connscale.report import (
    ConnScaleRecord,
    ConnScaleReport,
    NoLoss,
    lane_label,
    monotonic_pairs,
)
from harness.load.connscale.runner import (
    _MONOTONIC_TOLERANCE,
    _empty_claims_per_msg,
    _monotonic_slo,
)
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
) -> ConnScaleRecord:
    """A record carrying only the fields these SLOs read; the rest are inert placeholders."""
    return ConnScaleRecord(
        sweep_mode=mode,
        count=count,
        offered_aggregate_rate=35.0,
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
        fd_count_peak=100,
        reload_seconds=None,
        ack_p50_ms=None,
        ack_p95_ms=None,
        ack_p99_ms=None,
        claim_mode=claim_mode,
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
# --------------------------------------------------------------------------------------------------


def test_slo_still_fails_on_a_genuine_herd_collapse() -> None:
    """A REAL regression -- per-message herd size dropping with N -- must still go red.

    The engine claim wall #3 makes is that the per-commit herd GROWS with connection count. A drop
    means the instrumentation or the fanout changed. The fix must not buy stability by becoming blind.
    """
    records = [
        _rec("fixed_aggregate", 12, per_msg=40.0),
        _rec("fixed_aggregate", 24, per_msg=10.0),  # collapsed, far under the 0.75 floor
    ]
    check = _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_msg)
    assert not check.ok, "a genuine per-message collapse must fail the SLO"
    assert "fixed_aggregate@N=24" in str(check.observed)


def test_slo_passes_on_the_healthy_shape() -> None:
    """The measured healthy readings: 39.1 at N=12 rising to 77.8 at N=24, a clean 2.0x."""
    records = [
        _rec("fixed_aggregate", 12, per_msg=39.1),
        _rec("fixed_aggregate", 24, per_msg=77.8),
    ]
    assert _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_msg).ok


def test_slo_skips_undefined_readings_without_failing() -> None:
    """None is 'no reading', not 'a reading of zero'."""
    records = [
        _rec("fixed_aggregate", 12, per_msg=40.0),
        _rec("fixed_aggregate", 24, per_msg=None),
    ]
    assert _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_msg).ok


# --------------------------------------------------------------------------------------------------
# The latent grouping defect, fixed in the same pass.
# --------------------------------------------------------------------------------------------------


def test_monotonicity_does_not_chain_across_claim_modes() -> None:
    """Grouping by sweep_mode ALONE compares per_lane against pooled.

    ``compare.py`` states pooled's empty-claim rate SHOULD be materially lower, so a CORRECT engine
    would fail this the moment a profile set ``claim_modes = ["per_lane", "pooled"]``. No shipped
    profile does, which is the only reason it has never fired -- the grouping is wrong regardless.
    Ordered so that a sweep_mode-only grouping sorts pooled's low N=12 after per_lane's high N=24.
    """
    records = [
        _rec("fixed_aggregate", 12, per_msg=40.0, claim_mode="per_lane"),
        _rec("fixed_aggregate", 24, per_msg=80.0, claim_mode="per_lane"),
        _rec("fixed_aggregate", 12, per_msg=4.0, claim_mode="pooled"),
        _rec("fixed_aggregate", 24, per_msg=8.0, claim_mode="pooled"),
    ]
    check = _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_msg)
    assert check.ok, (
        "each claim mode rises monotonically on its own; failing here means prev_val is being "
        f"chained across claim modes, which is the #1101 latent defect. observed={check.observed}"
    )


def test_a_regression_inside_one_claim_mode_is_still_caught() -> None:
    """The grouping fix must not become a way to hide a real drop behind a second claim mode."""
    records = [
        _rec("fixed_aggregate", 12, per_msg=40.0, claim_mode="per_lane"),
        _rec("fixed_aggregate", 24, per_msg=5.0, claim_mode="per_lane"),  # real collapse
        _rec("fixed_aggregate", 12, per_msg=4.0, claim_mode="pooled"),
        _rec("fixed_aggregate", 24, per_msg=8.0, claim_mode="pooled"),
    ]
    check = _monotonic_slo("empty_claims_monotonic", records, lambda r: r.empty_claims_per_msg)
    assert not check.ok
    assert "N=24" in str(check.observed)


# --------------------------------------------------------------------------------------------------
# BACKLOG #1211: the readings must survive a PASSING run.
#
# The SLO writes a number into `observed` only once a reading has already left its band -- a passing
# run records the literal string "monotonic" and discards every value. So the only samples that ever
# survived were the excursions, and a sample selected on having excursioned cannot measure the
# distribution it excursioned from. #1211 requires that variance before anyone may touch the band, so
# these pin that every run records every reading.
#
# NOTHING HERE WIDENS THE BAND. That is limb two, and it stays blocked until the samples exist.
# --------------------------------------------------------------------------------------------------

_METRIC = "empty_claims_per_msg"
_KEY = lambda r: r.empty_claims_per_msg  # noqa: E731


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
    assert _monotonic_slo("empty_claims_monotonic", recs, _KEY).ok, "the test lost its own premise"

    text = _render(_report(*recs))
    assert "48.4" in text and "60" in text, text
    assert "OUTSIDE BAND" not in text


def test_the_slo_alone_would_have_recorded_neither_of_those_numbers() -> None:
    """The other half of the pair: without this change a green run keeps no number at all.

    Stated as a test rather than as a claim in the item, because it is the entire justification for
    emitting anything -- and it is the sort of premise that quietly stops being true.
    """
    recs = [_rec("fixed_per_conn", 12, per_msg=48.4), _rec("fixed_per_conn", 24, per_msg=60.0)]
    check = _monotonic_slo("empty_claims_monotonic", recs, _KEY)
    assert check.observed == "monotonic"
    assert "48.4" not in str(check.observed) and "60" not in str(check.observed)


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
    """A hard-coded 0.75 in the emitter would drift from the band the SLO actually enforces.

    Rendering the SAME records at two tolerances must move the floor, which is only true if the
    emitter reads its tolerance rather than carrying its own.
    """
    report = _report(
        _rec("fixed_per_conn", 12, per_msg=100.0), _rec("fixed_per_conn", 24, per_msg=90.0)
    )
    loose = report.render_readings_markdown(_METRIC, _KEY, tolerance=0.25)
    tight = report.render_readings_markdown(_METRIC, _KEY, tolerance=0.05)
    assert "| 75 |" in loose, loose  # 100 * 0.75
    assert "| 95 |" in tight, tight  # 100 * 0.95
    assert "within band" in loose and "OUTSIDE BAND" in tight


def test_the_emitted_lane_label_matches_the_slo_detail_string() -> None:
    """A reading filed under ``fixed_per_conn`` that a failure reports as ``fixed_per_conn/pooled``
    is two distributions, not one. Both sides read ``lane_label``; this asserts they agree."""
    recs = [
        _rec("fixed_per_conn", 12, per_msg=40.0, claim_mode="pooled"),
        _rec("fixed_per_conn", 24, per_msg=10.0, claim_mode="pooled"),
    ]
    detail = str(_monotonic_slo("empty_claims_monotonic", recs, _KEY).observed)
    assert detail.startswith("fixed_per_conn/pooled@N=24"), detail
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
    assert "OUTSIDE BAND" not in body


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
    """The SLO and the emitter must read ONE definition of the pairing.

    Asserted by driving `monotonic_pairs` directly and checking the SLO's detail string agrees with
    the pair it reports -- if the SLO grew its own copy, this would diverge silently.
    """
    recs = [_rec("fixed_per_conn", 12, per_msg=48.4), _rec("fixed_per_conn", 24, per_msg=36.0)]
    pairs = monotonic_pairs(recs, _KEY, tolerance=_MONOTONIC_TOLERANCE)
    assert len(pairs) == 1
    pair = pairs[0]
    assert not pair.ok and pair.count == 24 and pair.prior == 48.4
    assert pair.threshold == pytest.approx(36.3)

    detail = str(_monotonic_slo("empty_claims_monotonic", recs, _KEY).observed)
    assert detail == (
        f"{pair.label}@N={pair.count}: {pair.value:.3g} < prior {pair.prior:.3g} "
        f"* {pair.tolerance_floor:.2f}"
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
    # The markdown states the same verdict for the same reading.
    assert "OUTSIDE BAND" in table
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
