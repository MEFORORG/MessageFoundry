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

#: The gated steps, each with the JOB that owns it and the matrix knobs that cap it. Named here rather
#: than discovered, so a step that LOSES its cap is a failure rather than a silently smaller scan -- an
#: empty scan and a clean scan must not look alike.
#:
#: ONE ENTRY PER (JOB, STEP), because the web console suite moved out of `test` into its own
#: `webconsole` job. Every invariant below used to be written against `test` alone and is now applied
#: per job; none of them was relaxed to accommodate the move. The pair that must fit under a job cap is
#: now a single step per job rather than two sharing one, which is the easier obligation -- see the
#: `webconsole` job header in ci.yml for why that completes BACKLOG #344 proposal 5 instead of undoing
#: it.
_GATED: dict[str, tuple[str, str, str]] = {
    # job name: (gated step name, its step-cap matrix key, that job's job-cap matrix key)
    "test": ("Tests (pytest)", "step_timeout", "job_timeout"),
    "webconsole": (
        "Web console tests (pytest)",
        "webconsole_step_timeout",
        "webconsole_job_timeout",
    ),
}

#: Flat view, for the assertions that only care about which steps are gated at all.
_GATED_STEPS = tuple(step for step, _, _ in _GATED.values())


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


def test_a_LOW_verdict_leads_with_the_STEPS_SUCCESS_and_names_a_TIMING_gate() -> None:
    """BACKLOG #1254. The required contexts render as `test (<os>, py3.14)` -- named for WHERE they
    ran, never for WHAT they assert -- so a LOW margin reds a check whose label reads *the tests
    failed on Windows*. Measured 2026-08-13: a seat read that label, formed the wrong hypothesis, and
    corrected itself only by opening the log. A vague label invites a look at the log; a confident
    wrong one closes the question.

    Renaming the job is the dangerous lever -- those three strings are required contexts, and a
    required-but-absent context blocks every PR -- so the fix is the one that cannot wedge anything:
    this gate's own first line states what did NOT fail before it states what did.

    THE CLAIM IS ONE THE INSTRUMENT HOLDS, not one it infers. `LOW` is reachable only from
    `outcome == "success"` (anything else is CENSORED), and that outcome is the measured step's own
    conclusion -- so "the step concluded success" is read, not assumed.

    Falsified by restoring the old `MARGIN LOW: {shape}` headline: the success claim is absent from
    the string entirely, so the membership assertions AND the ordering assertion go RED. Restored.
    """
    verdict = decide(
        elapsed_seconds=parse_clock("25:51"),
        cap_seconds=parse_clock("26:00"),
        outcome="success",
        baseline=_uncensored(parse_clock("25:51")),
    )
    head = verdict.headline
    assert (verdict.code, verdict.exit_code) == ("LOW", 1)
    assert "Tests (pytest)" in head  # the step whose outcome it actually read, named
    assert "CONCLUDED SUCCESS" in head
    assert "TIMING" in head
    assert "1.006x" in head  # the measurement survives the rewording rather than being replaced
    # The claim LEADS. A sentence saying so after the ratio is the same information in the position
    # where the misreading has already happened.
    assert head.index("CONCLUDED SUCCESS") < head.index("1.006x")


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

    ALSO THE NEGATIVE CONTROL for the LOW headline above (BACKLOG #1254), and this is the arm where
    the `test (<os>, py3.14)` label is RIGHT. A step that was killed or cancelled did not conclude
    success, so carrying the success clause here would be that defect inverted -- a gate telling a
    reader nothing failed while the thing it measured is exactly what failed.
    """
    verdict = decide(
        elapsed_seconds=3300, cap_seconds=3300, outcome=outcome, baseline=_uncensored()
    )
    assert (verdict.code, verdict.exit_code) == ("CENSORED", 0)
    assert "LOWER BOUND" in verdict.headline
    assert "1.000x" not in verdict.headline
    assert any("false premise" in n for n in verdict.notes)
    assert "CONCLUDED SUCCESS" not in verdict.headline


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


def _job(name: str) -> dict:
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    jobs = doc["jobs"]
    assert name in jobs, f"ci.yml has no {name!r} job -- jobs are {sorted(jobs)}"
    return jobs[name]  # type: ignore[no-any-return]


def _matrix_legs() -> list[dict]:
    """The `test` job's per-leg matrix entries, parsed out of the shell that BUILDS them in `changes`.

    The matrix is assembled at runtime (per-repo), so it is not readable as YAML data -- it is
    single-quoted JSON literals in a `run:` body. Reading them here is deliberate: the alternative is
    a second copy of the leg list in this file, and two copies of a rule drift.

    THE NAMES COME FROM THE `test` JOB'S OWN EMISSION, not from a pattern over the whole step, and
    that is the fix for a real miss. This used to match any shell variable holding a JSON object with
    an `os` key. That was an accurate description of the file on the day it was written and not a
    description of the QUESTION -- which is "what legs does the `test` job run". Measured 2026-08-30,
    when `changes` gained a `tooling_matrix` for a DIFFERENT job: this helper returned six legs for a
    three-leg job, and the two callers reported a leg-count break and six missing baseline rows for
    legs that do not exist. Resolving the interpolated names first cannot pick up another job's
    matrix, because another job's matrix is not in this job's include list.
    """
    text = _CI.read_text(encoding="utf-8")
    include = re.search(r'echo "matrix=\{\\"include\\":\[([^]]*)\]\}"', text)
    assert include, (
        'the `test` job\'s `matrix={"include":[...]}` emission is gone from ci.yml -- this '
        "extraction has rotted, not the workflow"
    )
    names = [n.strip().lstrip("$") for n in include.group(1).split(",") if n.strip()]
    assert names, "the test matrix include list is empty"
    legs = []
    for name in names:
        found = re.search(rf"^\s*{re.escape(name)}='(\{{\"os\".*?\}})'$", text, re.MULTILINE)
        assert found, (
            f"the include list names ${name}, but no such leg literal is assigned in ci.yml"
        )
        legs.append(json.loads(found.group(1)))
    return legs


def test_the_margin_check_is_wired_into_every_gated_job_after_its_gated_step() -> None:
    """A margin script in the tree and absent from the workflow measures nothing.

    Placement is load-bearing and not cosmetic: a step `if:` carrying no status function has an
    implicit `success()`, so a failing check placed AHEAD of its gated step would silently skip that
    suite. It runs last in each job that owns one.

    Falsified by moving either check above its gated step: the ordering assertion goes RED. Restored.
    """
    for job_name, (gated, _, _) in _GATED.items():
        steps = _job(job_name)["steps"]
        names = [str(s.get("name", "")) for s in steps]
        # The CHECK is the step that READS a mark (`--since`); the mark-writers use `--mark`. Matching
        # on the flag rather than the name is deliberate -- "Step margin -- start the clock" also
        # starts with "Step margin", so a name prefix would match a writer and pass for the wrong step.
        check = [i for i, s in enumerate(steps) if "--since" in str(s.get("run", ""))]
        print(f"[step-margin] {job_name}-job steps scanned: {len(names)}; check at {check}")
        assert len(check) == 1, f"expected exactly one margin check in {job_name}, found {check}"
        assert gated in names, (
            f"{gated!r} is gone from {job_name} -- re-scope this guard deliberately"
        )
        assert names.index(gated) < check[0], f"the margin check must run after {gated!r}"
        assert steps[check[0]].get("if") == "always()", (
            "the margin check must run even when a gated step failed -- otherwise the one case it "
            "exists for (a step killed at its cap) is the one case it never reports"
        )
        assert "scripts/ci/step_margin.py" in str(steps[check[0]].get("run", ""))


def test_every_mark_the_check_reads_is_written_by_a_step_that_runs_first() -> None:
    """The clock, wired. A `--since`/`--until` label with no `--mark` step ahead of it is a check that
    exits 2 on every run -- loud, but only after it reaches CI.

    Falsified by renaming either `--mark` label without renaming its reader: RED, naming the label.
    Restored.
    """
    for job_name in _GATED:
        steps = _job(job_name)["steps"]
        written: dict[str, int] = {}
        for i, step in enumerate(steps):
            for label in re.findall(r"--mark\s+(\S+)", str(step.get("run", ""))):
                written[label] = i
        check_index = next(i for i, s in enumerate(steps) if "--since" in str(s.get("run", "")))
        read = set(re.findall(r"--(?:since|until)\s+(\S+)", str(steps[check_index].get("run", ""))))
        read.discard("now")  # the live clock, written by nobody
        print(f"[step-margin] {job_name}: marks written {sorted(written)}; read {sorted(read)}")
        assert read, f"{job_name}'s check reads no marks at all -- it is no longer timing anything"
        for label in sorted(read):
            assert label in written, f"{job_name}'s check reads mark {label!r} that no step writes"
            assert written[label] < check_index, f"mark {label!r} is written after it is read"
        # Marks are per-JOB now (each job writes and reads its own), so an unread mark means a
        # half-finished move rather than a harmless leftover: the two jobs cannot see each other's.
        unread = sorted(set(written) - read)
        assert not unread, f"{job_name}: marks written and never read: {unread}"


def test_the_margin_check_keys_on_the_STEPS_OWN_CONCLUSION_never_the_jobs() -> None:
    """The single substitution that reproduced a published maximum of 24:35 where the truth was 25:51.

    A step that nearly exhausts its cap is the most likely to push its job into `job_timeout`, so
    filtering on the JOB deletes the tightest rows by construction. Every gated step therefore carries
    an `id:` and the check reads `steps.<id>.outcome`.

    Falsified by substituting `job.status` for either outcome expression: RED. Restored.
    """
    for job_name, (gated, _, _) in _GATED.items():
        steps = _job(job_name)["steps"]
        ids = {str(s.get("name", "")): s.get("id") for s in steps}
        assert ids.get(gated), (
            f"{gated!r} in {job_name} carries no `id:`, so its own outcome cannot be referenced"
        )
        check = next(s for s in steps if "--since" in str(s.get("run", "")))
        env = check.get("env") or {}
        referenced = {str(v) for v in env.values()}
        expected = "${{ steps." + str(ids[gated]) + ".outcome }}"
        assert expected in referenced, (
            f"{job_name}'s check does not read {expected}; env is {referenced}"
        )
        joined = " ".join(referenced) + str(check.get("run", ""))
        assert "job.status" not in joined and "job.conclusion" not in joined


def test_the_web_console_suite_shares_neither_budget_nor_job_with_the_engine_suite() -> None:
    """BACKLOG #344 proposal 5. Two steps on one `timeout-minutes` is why the nesting invariant could
    not hold for the second one on any leg: reaching it has already spent setup plus `Tests`, so its
    cap could never fire first.

    Falsified by restoring `timeout-minutes: matrix.step_timeout` on that step: RED. Restored.
    """
    caps: dict[str, str] = {}
    for job_name, (gated, step_key, _) in _GATED.items():
        steps = _job(job_name)["steps"]
        step = next(s for s in steps if s.get("name") == gated)
        expected = "${{ matrix." + step_key + " }}"
        assert step["timeout-minutes"] == expected, (
            f"{gated!r} in {job_name} must be capped by {expected}, found "
            f"{step.get('timeout-minutes')!r}"
        )
        caps[gated] = str(step["timeout-minutes"])

    # STRONGER THAN BEFORE, not weaker. The two suites no longer merely carry DIFFERENT caps inside one
    # job -- they are in DIFFERENT JOBS, so neither can spend the other's wall-clock at all. Assert the
    # separation structurally as well as by cap name, since the cap names alone would still pass if the
    # console step were moved back beside the engine one with its own knob.
    assert len(set(caps.values())) == len(caps), f"gated steps share a cap expression: {caps}"
    owners = {gated: job for job, (gated, _, _) in _GATED.items()}
    assert len(set(owners.values())) == len(owners), (
        f"two gated steps share a job, so one is again queued behind the other: {owners}"
    )


def test_every_leg_sizes_each_gated_step_inside_its_own_job_cap() -> None:
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
        # ONE gated step per job now, so the obligation is per (job, leg) rather than a SUM of two step
        # budgets under a single job cap. Each job's own step cap must fit under its own job cap. This
        # is the same invariant, applied where the steps actually live -- and it stays deliberately
        # weaker than the real rule, which adds a measured setup term that lives in a comment and is
        # unreadable from here.
        for job_name, (_, step_key, job_key) in _GATED.items():
            assert step_key in leg, (
                f"{leg['os']} does not size {job_name}'s gated step ({step_key})"
            )
            assert job_key in leg, f"{leg['os']} does not cap the {job_name} job ({job_key})"
            assert leg[step_key] < leg[job_key], (
                f"{leg['os']}: {step_key} {leg[step_key]} does not fit under {job_key} "
                f"{leg[job_key]}, before setup is even counted"
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
