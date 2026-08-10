# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The CI step-margin gate, and the wiring that makes it real (BACKLOG #344).

Two halves, and both are needed. The arithmetic half is easy to get right and easy to test. The
WIRING half is where this class of guard actually dies: a margin check that is present in the tree and
absent from the workflow, or keyed on the JOB's conclusion instead of the STEP's, passes every unit
test while measuring nothing. So the workflow assertions below read `ci.yml` and say what they
scanned.

Every check here was made to go RED on purpose before it was trusted green -- see each docstring's
falsification note. That is not ceremony: the whole finding behind #344 is that re-reading confirms
what you meant and only a check can test what you wrote, and across the CI-triage cluster it came
from, re-reading was 0-for-7 at catching a wrong number.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from scripts.ci.step_margin import (
    DEFAULT_MIN_MARGIN,
    Baseline,
    MarginError,
    clock_dir,
    decide,
    find_baseline,
    format_clock,
    load_baselines,
    main,
    parse_clock,
    read_mark,
    self_check,
    summary_block,
    write_mark,
)

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_BASELINE_FILE = _ROOT / "scripts" / "ci" / "step_margin_baseline.toml"

#: The steps in `test` that carry their own `timeout-minutes` and are therefore in scope. Named here
#: rather than discovered, so a step that LOSES its cap is a failure rather than a silently smaller
#: scan -- an empty scan and a clean scan must not look alike.
_GATED_STEPS = ("Tests (pytest)", "Web console tests (pytest)")


def _uncensored(seconds: int = 600) -> Baseline:
    return Baseline(
        step="Tests (pytest)",
        leg="ubuntu-latest",
        max_passing_seconds=seconds,
        censored=False,
        censored_by="",
        source="a fixture; measured 2026-01-01 over a pool of nothing.",
    )


# --- the arithmetic --------------------------------------------------------------------------------


def test_clock_round_trips_and_refuses_a_non_duration() -> None:
    """A silently-zero duration computes as an infinite margin, which is the one wrong answer a
    watchdog may never give -- so the parser refuses rather than defaulting."""
    assert parse_clock("25:51") == 1551
    assert parse_clock("1:05:00") == 3900
    assert format_clock(1551) == "25:51"
    for bad in ("", "25", "25:xx", "-1:00", "25:51:00:00"):
        with pytest.raises(MarginError):
            parse_clock(bad)


def test_a_margin_at_the_floor_passes_and_a_hair_under_it_fails() -> None:
    """The gate, at its own boundary. At the floor exactly it is OK -- an inclusive floor, so the
    published threshold is the one that fires rather than one tick off it.

    Falsified by changing the comparison to `<=`: the first assertion goes RED. Restored.
    """
    at_floor = decide(
        elapsed_seconds=600 / DEFAULT_MIN_MARGIN,
        cap_seconds=600,
        outcome="success",
        baseline=_uncensored(),
    )
    assert (at_floor.code, at_floor.exit_code) == ("OK", 0)
    under = decide(
        elapsed_seconds=600 / DEFAULT_MIN_MARGIN + 1,
        cap_seconds=600,
        outcome="success",
        baseline=_uncensored(),
    )
    assert (under.code, under.exit_code) == ("LOW", 1)


def test_the_run_this_item_was_filed_for_would_have_been_flagged() -> None:
    """windows-2025's 25:51 against the 26:00 cap that then killed a green suite at 26:07.

    The leg sat at 1.006x and nothing said a word, while the comment beside the cap asserted "~2x
    headroom". This is the check saying the word.
    """
    verdict = decide(
        elapsed_seconds=parse_clock("25:51"),
        cap_seconds=parse_clock("26:00"),
        outcome="success",
        baseline=_uncensored(parse_clock("25:51")),
    )
    assert verdict.code == "LOW"
    assert verdict.exit_code == 1
    assert "1.006x" in verdict.headline
    assert any("Raising the cap is NOT the fix" in n for n in verdict.notes)


def test_a_skipped_step_reports_NO_OBSERVATION_and_never_a_ratio() -> None:
    """THE NEGATIVE CONTROL. A docs-only PR skips the gated steps, and a check that then printed a
    healthy margin would be reporting on a step that did not run -- the exact "green signal that means
    nothing" shape. It must say so in words.

    Falsified by deleting the `outcome == "skipped"` branch: the run then raises on a missing elapsed
    (exit 2) rather than reporting NO OBSERVATION, and this goes RED on the code assertion. Restored.
    """
    verdict = decide(
        elapsed_seconds=None, cap_seconds=600, outcome="skipped", baseline=_uncensored()
    )
    assert (verdict.code, verdict.exit_code) == ("NO OBSERVATION", 0)
    assert "x" not in verdict.headline.replace("margin observation", "")  # no ratio anywhere
    assert any("not a healthy margin" in n for n in verdict.notes)


@pytest.mark.parametrize("outcome", ["failure", "cancelled"])
def test_a_step_that_did_not_conclude_success_is_CENSORED_not_scored(outcome: str) -> None:
    """A killed step's duration is a LOWER BOUND: it is the cap, not the work. Scoring it would
    publish a margin of exactly 1.000x for every kill, which is arithmetic about the cap rather than a
    measurement of the suite.

    Keying on the STEP's own conclusion is what makes this reachable at all -- the job conclusion
    cannot distinguish a step killed at its cap from a step that passed inside a job that was
    cancelled later.
    """
    verdict = decide(
        elapsed_seconds=3300, cap_seconds=3300, outcome=outcome, baseline=_uncensored()
    )
    assert (verdict.code, verdict.exit_code) == ("CENSORED", 0)
    assert "LOWER BOUND" in verdict.headline
    assert "1.000x" not in verdict.headline
    assert any("false premise" in n for n in verdict.notes)


def test_a_zero_duration_refuses_rather_than_reporting_an_infinite_margin() -> None:
    with pytest.raises(MarginError) as exc:
        decide(elapsed_seconds=0, cap_seconds=600, outcome="success", baseline=_uncensored())
    assert "infinite margin" in str(exc.value)


def test_an_unknown_outcome_refuses_rather_than_guessing() -> None:
    with pytest.raises(MarginError):
        decide(elapsed_seconds=10, cap_seconds=600, outcome="green", baseline=_uncensored())


# --- the recorded maximum, and its censoring ------------------------------------------------------


def test_a_censored_baseline_carries_its_caveat_into_every_report() -> None:
    """A recorded maximum collected under a cap is a LOWER bound: the runs that wanted longer were
    killed at the cap and dropped for not concluding success, so they are missing from exactly the
    tail being measured. Dividing by it quietly is how 1.006x read as survivable.

    Falsified by dropping the `if baseline.censored` branch: RED. Restored.
    """
    censored = Baseline(
        step="Tests (pytest)",
        leg="windows-2025",
        max_passing_seconds=2147,
        censored=True,
        censored_by="the 36:00 cap in force when the pool was collected",
        source="a fixture; measured 2026-01-01.",
    )
    verdict = decide(elapsed_seconds=1000, cap_seconds=3300, outcome="success", baseline=censored)
    assert any("RIGHT-CENSORED" in n and "flatters itself" in n for n in verdict.notes)
    assert any("36:00 cap in force" in n for n in verdict.notes)


def test_exceeding_the_recorded_maximum_says_RE_DERIVE_and_names_the_pool() -> None:
    """The record rots silently otherwise: the same table was published wrong twice, and neither
    error was found by re-reading it. Nothing read it, so this run reads it."""
    verdict = decide(
        elapsed_seconds=700, cap_seconds=3300, outcome="success", baseline=_uncensored(600)
    )
    note = next(n for n in verdict.notes if n.startswith("RE-DERIVE"))
    assert "11:40" in note and "10:00" in note
    assert "measured 2026-01-01" in note  # the pool travels with the number


def test_a_gated_step_with_no_recorded_maximum_FAILS_CLOSED() -> None:
    """A capped step nobody has sized is precisely the state this item is about. Defaulting to
    "no baseline, carry on" would let one appear silently, so the lookup refuses and names what it
    does know."""
    rows = load_baselines(_BASELINE_FILE)
    with pytest.raises(MarginError) as exc:
        find_baseline(rows, "Some future step", "ubuntu-latest")
    assert "nobody has sized" in str(exc.value)
    assert "Tests (pytest) @ ubuntu-latest" in str(exc.value)  # prints what it scanned


def test_a_baseline_row_recording_a_zero_maximum_is_refused(tmp_path: Path) -> None:
    """A 0:00 maximum divides by zero in the percent-of-record line, and a row asserting the suite has
    never run is not an observation. Refuse at load, where the row is still nameable."""
    bad = tmp_path / "b.toml"
    bad.write_text(
        '[[baseline]]\nstep = "S"\nleg = "L"\nmax_passing = "0:00"\ncensored = false\n'
        'source = "measured 2026-01-01 over nothing at all, which is the point of this fixture."\n',
        encoding="utf-8",
    )
    with pytest.raises(MarginError) as exc:
        load_baselines(bad)
    assert "has no row, not a zero one" in str(exc.value)


def test_every_baseline_row_states_its_pool_and_its_date() -> None:
    """A ratio whose pool is not stated cannot be rechecked, and that is this item's own finding about
    its own measurements. Enforced rather than requested."""
    rows = load_baselines(_BASELINE_FILE)
    print(f"[step-margin] baseline rows: {[(r.step, r.leg) for r in rows]}")
    assert rows, "the baseline records nothing -- a check against nothing is not a check"
    for row in rows:
        assert re.search(r"\d{4}-\d{2}-\d{2}", row.source), (
            f"{row.step} @ {row.leg} states no measurement date: {row.source!r}"
        )
        assert len(row.source) > 60, f"{row.step} @ {row.leg} states no pool: {row.source!r}"
        if row.censored:
            assert row.censored_by, f"{row.step} @ {row.leg} is censored by nothing in particular"


# --- the check's own control ----------------------------------------------------------------------


def test_the_live_control_returns_both_answers() -> None:
    """A gate that has never been red is a claim, not a control -- and this gate's red condition has
    never occurred in this repo, so nothing else would ever demonstrate it can fire."""
    lines = self_check()
    assert any("LOW, exit 1" in line for line in lines)
    assert any("OK, exit 0" in line for line in lines)


def test_the_control_refuses_when_the_gate_cannot_go_red(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control is only worth running if IT can fail. Neutered gate, live refusal.

    A floor of 0.0 makes every margin acceptable, which is what a gate silently disabled looks like:
    the check then exits 2 (could not measure) rather than 0 (clean).
    """
    with pytest.raises(MarginError) as exc:
        self_check(min_margin=0.0)
    assert "NEGATIVE control did not fire" in str(exc.value)
    assert "green means nothing" in str(exc.value)


# --- end to end through main ----------------------------------------------------------------------


def test_main_reds_on_a_low_margin_and_writes_the_summary(tmp_path: Path) -> None:
    """Exit 1 is the gate. The summary carries the elapsed, the percent-of-cap and the controls, so a
    reader can see what was measured rather than being told a verdict."""
    summary = tmp_path / "summary.md"
    rc = main(
        [
            "--step",
            "Tests (pytest)",
            "--leg",
            "windows-2025",
            "--cap-minutes",
            "55",
            "--outcome",
            "success",
            "--elapsed-seconds",
            "2580",
            "--summary-file",
            str(summary),
        ]
    )
    assert rc == 1
    text = summary.read_text(encoding="utf-8")
    assert "**LOW**" in text
    assert "43:00 of a 55:00 cap" in text
    assert "78.2% of the cap" in text
    assert "1.279x" in text
    assert "control (negative)" in text and "control (positive)" in text


def test_main_is_green_on_a_healthy_margin_and_still_shows_the_controls(tmp_path: Path) -> None:
    """Also the end-to-end mark path: two marks, an elapsed derived from them, one verdict."""
    write_mark("t0", tmp_path, at=1000.0)
    write_mark("t1", tmp_path, at=1968.0)  # 16:08, this leg's recorded maximum
    summary = tmp_path / "summary.md"
    rc = main(
        [
            "--step",
            "Tests (pytest)",
            "--leg",
            "ubuntu-latest",
            "--cap-minutes",
            "25",
            "--outcome",
            "success",
            "--since",
            "t0",
            "--until",
            "t1",
            "--clock-dir",
            str(tmp_path),
            "--summary-file",
            str(summary),
        ]
    )
    assert rc == 0
    text = summary.read_text(encoding="utf-8")
    assert "**OK**" in text
    assert "16:08 of a 25:00 cap" in text
    assert "control (negative)" in text  # the refusal is shown even on a green run


# --- the clock ------------------------------------------------------------------------------------


def test_a_mark_round_trips_through_a_file_and_now_is_live(tmp_path: Path) -> None:
    """The clock lives in Python rather than in `echo ... >> "$GITHUB_ENV"`, because that spelling
    routes a Windows path through a bash redirection on two of the three legs and no local run can
    exercise it."""
    stamp = write_mark("t0", tmp_path, at=1234.5)
    assert stamp == 1234.5
    assert read_mark("t0", tmp_path) == 1234.5
    assert read_mark("now", tmp_path) > 1_700_000_000  # the live clock, not a recorded mark


def test_a_missing_mark_REFUSES_rather_than_reading_as_zero(tmp_path: Path) -> None:
    """A missing mark substituted with 0 makes elapsed an epoch-sized number, and the ratio that
    follows looks exactly like an answer. This is the shape that turns a check into a decoration."""
    with pytest.raises(MarginError) as exc:
        read_mark("never-written", tmp_path)
    assert "did not run" in str(exc.value)
    assert "Refusing to guess" in str(exc.value)


def test_main_in_mark_mode_writes_the_mark_and_does_nothing_else(tmp_path: Path) -> None:
    summary = tmp_path / "summary.md"
    rc = main(
        ["--mark", "before-tests", "--clock-dir", str(tmp_path), "--summary-file", str(summary)]
    )
    assert rc == 0
    assert read_mark("before-tests", tmp_path) > 0
    assert not summary.exists(), "mark mode must not emit a verdict -- it has measured nothing yet"


def test_main_refuses_a_check_with_a_missing_mark(tmp_path: Path) -> None:
    """Exit 2 -- could not measure. NOT 0, which would read as a healthy leg."""
    rc = main(
        [
            "--step",
            "Tests (pytest)",
            "--leg",
            "ubuntu-latest",
            "--cap-minutes",
            "25",
            "--outcome",
            "success",
            "--since",
            "absent",
            "--until",
            "now",
            "--clock-dir",
            str(tmp_path),
        ]
    )
    assert rc == 2


def test_the_clock_dir_prefers_RUNNER_TEMP(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """On a runner the marks must land in the job's own temp, which is wiped with the job -- never in
    a shared system temp where a stale mark from another run could be read as this one's."""
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    assert clock_dir() == tmp_path
    assert clock_dir(str(tmp_path / "explicit")) == tmp_path / "explicit"
    monkeypatch.delenv("RUNNER_TEMP")
    assert clock_dir() != tmp_path  # falls back rather than raising


def test_main_exits_2_when_it_cannot_measure_and_never_0(tmp_path: Path) -> None:
    """Could-not-measure must not be confused with clean, and must not be confused with LOW either --
    three outcomes, three exit codes."""
    rc = main(
        [
            "--step",
            "Tests (pytest)",
            "--leg",
            "some-runner-that-does-not-exist",
            "--cap-minutes",
            "25",
            "--outcome",
            "success",
            "--elapsed-seconds",
            "100",
            "--summary-file",
            str(tmp_path / "s.md"),
        ]
    )
    assert rc == 2


def test_the_summary_for_a_skipped_step_says_so_instead_of_looking_clean(tmp_path: Path) -> None:
    """The negative control, end to end and in the artefact a human reads."""
    summary = tmp_path / "summary.md"
    rc = main(
        [
            "--step",
            "Web console tests (pytest)",
            "--leg",
            "ubuntu-latest",
            "--cap-minutes",
            "5",
            "--outcome",
            "skipped",
            "--summary-file",
            str(summary),
        ]
    )
    assert rc == 0
    text = summary.read_text(encoding="utf-8")
    assert "**NO OBSERVATION**" in text
    assert "did not run" in text
    assert "%" not in text.split("<details>")[0]  # no percent-of-cap is claimed for a step that ran


def test_the_summary_block_prints_what_it_scanned() -> None:
    """A summary that says only "OK" is indistinguishable from a summary that scanned nothing."""
    verdict = decide(
        elapsed_seconds=600, cap_seconds=1500, outcome="success", baseline=_uncensored(600)
    )
    block = summary_block(
        step="Tests (pytest)",
        leg="ubuntu-latest",
        verdict=verdict,
        controls=self_check(),
        min_margin=DEFAULT_MIN_MARGIN,
    )
    for expected in ("Tests (pytest)", "ubuntu-latest", "10:00", "25:00", "40.0%", "1.30x"):
        assert expected in block, f"{expected!r} missing from the job summary"


# --- the wiring, which is where this class of guard actually dies -----------------------------------


def _test_job() -> dict:
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    return doc["jobs"]["test"]  # type: ignore[no-any-return]


def _matrix_legs() -> list[dict]:
    """The per-leg matrix entries, parsed out of the shell that BUILDS the matrix in `changes`.

    The matrix is assembled at runtime (per-repo), so it is not readable as YAML data -- it is three
    single-quoted JSON literals in a `run:` body. Reading them here is deliberate: the alternative is
    a second copy of the leg list in this file, and two copies of a rule drift.
    """
    text = _CI.read_text(encoding="utf-8")
    legs = [json.loads(m) for m in re.findall(r"^\s*\w+='(\{\"os\".*?\})'$", text, re.MULTILINE)]
    assert legs, "no matrix legs found in ci.yml -- the extraction has rotted, not the workflow"
    return legs


def test_the_margin_check_is_wired_into_the_test_job_after_both_gated_steps() -> None:
    """A margin script in the tree and absent from the workflow measures nothing.

    Placement is load-bearing and not cosmetic: a step `if:` carrying no status function has an
    implicit `success()`, so a failing check placed BETWEEN the two gated steps would silently skip
    the second suite. It runs last.

    Falsified by moving the check above `Web console tests (pytest)`: the ordering assertion goes RED.
    Restored.
    """
    steps = _test_job()["steps"]
    names = [str(s.get("name", "")) for s in steps]
    print(f"[step-margin] test-job steps scanned: {len(names)}")
    check = [i for i, n in enumerate(names) if n.startswith("Step margin -- both gated steps")]
    assert len(check) == 1, f"expected exactly one margin check step, found {check} in {names}"
    for gated in _GATED_STEPS:
        assert gated in names, f"{gated!r} is gone from ci.yml -- re-scope this guard deliberately"
        assert names.index(gated) < check[0], f"the margin check must run after {gated!r}"
    assert steps[check[0]].get("if") == "always()", (
        "the margin check must run even when a gated step failed -- otherwise the one case it exists "
        "for (a step killed at its cap) is the one case it never reports"
    )
    assert "scripts/ci/step_margin.py" in str(steps[check[0]].get("run", ""))


def test_every_mark_the_check_reads_is_written_by_a_step_that_runs_first() -> None:
    """The clock, wired. A `--since`/`--until` label with no `--mark` step ahead of it is a check that
    exits 2 on every run -- loud, but only after it reaches CI.

    Falsified by renaming either `--mark` label without renaming its reader: RED, naming the label.
    Restored.
    """
    steps = _test_job()["steps"]
    written: dict[str, int] = {}
    for i, step in enumerate(steps):
        for label in re.findall(r"--mark\s+(\S+)", str(step.get("run", ""))):
            written[label] = i
    check_index = next(
        i for i, s in enumerate(steps) if str(s.get("name", "")).startswith("Step margin -- both")
    )
    read = set(re.findall(r"--(?:since|until)\s+(\S+)", str(steps[check_index].get("run", ""))))
    read.discard("now")  # the live clock, written by nobody
    print(f"[step-margin] marks written: {sorted(written)}; marks read: {sorted(read)}")
    assert read, "the check reads no marks at all -- it is no longer timing anything"
    for label in sorted(read):
        assert label in written, f"the check reads mark {label!r} that no step writes"
        assert written[label] < check_index, f"mark {label!r} is written after it is read"
    unread = sorted(set(written) - read)
    assert not unread, f"marks written and never read: {unread}"


def test_the_margin_check_keys_on_the_STEPS_OWN_CONCLUSION_never_the_jobs() -> None:
    """The single substitution that reproduced a published maximum of 24:35 where the truth was 25:51.

    A step that nearly exhausts its cap is the most likely to push its job into `job_timeout`, so
    filtering on the JOB deletes the tightest rows by construction. Every gated step therefore carries
    an `id:` and the check reads `steps.<id>.outcome`.

    Falsified by substituting `job.status` for either outcome expression: RED. Restored.
    """
    steps = _test_job()["steps"]
    ids = {str(s.get("name", "")): s.get("id") for s in steps}
    for gated in _GATED_STEPS:
        assert ids.get(gated), (
            f"{gated!r} carries no `id:`, so its own outcome cannot be referenced"
        )
    check = next(s for s in steps if str(s.get("name", "")).startswith("Step margin -- both"))
    env = check.get("env") or {}
    referenced = {str(v) for v in env.values()}
    for gated in _GATED_STEPS:
        expected = "${{ steps." + str(ids[gated]) + ".outcome }}"
        assert expected in referenced, f"the check does not read {expected}; env is {referenced}"
    joined = " ".join(referenced) + str(check.get("run", ""))
    assert "job.status" not in joined and "job.conclusion" not in joined


def test_the_web_console_step_no_longer_shares_the_engine_suites_budget() -> None:
    """BACKLOG #344 proposal 5. Two steps on one `timeout-minutes` is why the nesting invariant could
    not hold for the second one on any leg: reaching it has already spent setup plus `Tests`, so its
    cap could never fire first.

    Falsified by restoring `timeout-minutes: matrix.step_timeout` on that step: RED. Restored.
    """
    steps = _test_job()["steps"]
    console = next(s for s in steps if s.get("name") == "Web console tests (pytest)")
    engine = next(s for s in steps if s.get("name") == "Tests (pytest)")
    assert console["timeout-minutes"] == "${{ matrix.webconsole_step_timeout }}"
    assert engine["timeout-minutes"] == "${{ matrix.step_timeout }}"
    assert console["timeout-minutes"] != engine["timeout-minutes"]


def test_every_leg_sizes_both_gated_steps_and_the_pair_fits_inside_the_job_cap() -> None:
    """The machine-checkable half of the nesting invariant, per leg.

    WHAT THIS DOES NOT CHECK, said so it is not read as more: the real invariant is
    setup(max) + step_timeout + webconsole_step_timeout < job_timeout, and setup(max) is a measured
    quantity that lives in a comment -- unreadable from here. So this checks the two caps against the
    job cap and nothing else; the setup term is arithmetic in the note above the web console step. The
    weaker check still catches the edit that matters, which is a cap raised without re-summing.
    """
    legs = _matrix_legs()
    print(f"[step-margin] matrix legs scanned: {[leg['os'] for leg in legs]}")
    assert len(legs) == 3, f"expected three legs, found {[leg['os'] for leg in legs]}"
    for leg in legs:
        assert "webconsole_step_timeout" in leg, f"{leg['os']} does not size the web console step"
        both = leg["step_timeout"] + leg["webconsole_step_timeout"]
        assert both < leg["job_timeout"], (
            f"{leg['os']}: step_timeout {leg['step_timeout']} + webconsole_step_timeout "
            f"{leg['webconsole_step_timeout']} = {both} does not fit under job_timeout "
            f"{leg['job_timeout']}, before setup is even counted"
        )


def test_the_baseline_covers_every_gated_step_on_every_leg() -> None:
    """A leg with no recorded maximum fails the run closed at CI time; catching it here is cheaper."""
    rows = load_baselines(_BASELINE_FILE)
    legs = [leg["os"] for leg in _matrix_legs()]
    missing = [
        f"{step} @ {leg}"
        for step in _GATED_STEPS
        for leg in legs
        if not any(r.step == step and r.leg == leg for r in rows)
    ]
    print(
        f"[step-margin] checked {len(_GATED_STEPS)} step(s) x {len(legs)} leg(s) against {len(rows)} row(s)"
    )
    assert not missing, f"no recorded maximum for: {missing}"
