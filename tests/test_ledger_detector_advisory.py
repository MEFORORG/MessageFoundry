# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pin that the three wired ledger detectors REPORT and cannot GATE (BACKLOG #1525).

``tests/test_dangling_citation_advisory.py`` opens by recording that its detector *"was a working
detector that ran nowhere"*. Three more shipped into that state and stayed there: measured at
``817db9651``, ``citation_line_check.py``, ``banner_sha_check.py`` and ``subject_exists_screen.py``
were each named in exactly three places -- ``docs/BACKLOG.md``, their own test, and
``tests/tooling_manifest.txt`` -- and invoked by no workflow, hook or script.

ONE FILE FOR THREE JOBS, WHICH DEPARTS FROM THE ONE-FILE-PER-TOOL SHAPE OF THE TWO EXISTING ADVISORY
SUITES, deliberately. The properties being pinned are identical per job and the only thing that
varies is a job key and a script path, so three copies would be three places for the same assertion
to rot independently. What the parameters must NOT hide is a per-job difference, and there is one --
the subject-exists screen takes no ``--advisory`` -- so that job carries its own arm below rather
than a parameter that quietly excuses it.

WHAT KEEPS THEM ADVISORY. Four things, and three are assertable from inside the repository:

1. the workflow holds no required status-check context;
2. a FINDING cannot exit non-zero -- ``--advisory`` where the tool has finding-shaped failure, and
   for the subject-exists screen the stronger fact that it has none;
3. ``continue-on-error: true``, so even a tool's empty-population REFUSAL cannot fail the job;
4. each job is absent from the ``liveness`` job's ``needs``, so none can redden the one job in that
   file built to go red.

Branch protection lives on the SERVER, so (1) is only assertable against the checked-in claim in
``.github/required-contexts.txt`` -- the same honest limit the two sibling suites state for
themselves. This proves the repository does not CLAIM these contexts are required, never that the
server agrees.

THE ABSENCE ASSERTIONS CARRY POSITIVE CONTROLS. "This string is not in that list" and "that list is
empty because the parser broke" produce the identical green, so each absence check first proves its
instrument finds something it should.

THE DEPTH ARM IS NOT HOUSEKEEPING. ``banner_sha_check.py`` resolves each cited sha with ``git log``
and ``subject_exists_screen.py`` probes ``origin/main``; on the default shallow checkout the first
reports everything unresolvable and prints a clean summary, and the second cannot resolve the ref at
all. That is the same dead-gate shape the ``liveness`` job's comment records three times in this very
workflow, so the ``fetch-depth: 0`` on those two jobs is pinned here as a property, not left to a
reviewer noticing its deletion.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from tests._workflow_contexts import context_of, jobs_of, required_contexts

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW_NAME = "quality-advisory.yml"
_WORKFLOWS = _ROOT / ".github" / "workflows"
_PRE_COMMIT = _ROOT / ".pre-commit-config.yaml"

#: job key -> the checker it runs, spelled as the workflow spells it.
_DETECTORS: dict[str, str] = {
    "citation-line-drift": "scripts/docs/citation_line_check.py",
    "banner-sha-agreement": "scripts/docs/banner_sha_check.py",
    "subject-exists": "scripts/docs/subject_exists_screen.py",
}

#: The jobs whose tool asks git a question, and so cannot work on a shallow checkout.
_NEEDS_FULL_HISTORY = ("banner-sha-agreement", "subject-exists")

#: The four measurement jobs the liveness meta-gate rules on. None of these three may join them.
_LIVENESS_MEASUREMENT_JOBS = {"complexity", "clone", "coverage", "mutation"}

#: Parsed ONCE. `jobs_of` re-parses an 83 KB workflow on every call and this module asks five
#: questions of it, several under a parametrize; nothing here mutates the result.
_JOBS = jobs_of(_WORKFLOW_NAME)


def _analysis_step(job_key: str) -> dict:
    """The one step in ``job_key`` that invokes its checker."""
    script = _DETECTORS[job_key]
    jobs = _JOBS
    assert job_key in jobs, (
        f"{_WORKFLOW_NAME} has no {job_key!r} job -- re-point this guard rather than letting it pass"
    )
    steps = [step for step in jobs[job_key]["steps"] if script in (step.get("run") or "")]
    assert len(steps) == 1, (
        f"expected exactly 1 step in {job_key!r} invoking {script}, found {len(steps)}"
    )
    return steps[0]


def _invocation(job_key: str) -> str:
    """The single command line that runs the checker, never the whole step body.

    ASSERTED ON THE LINE, NOT THE BODY, and that distinction is measured rather than theoretical:
    test_dangling_citation_advisory.py records a first version of this assertion that searched the
    whole step, matched the step's own warning message, and stayed green after the flag was deleted
    from the command.
    """
    body = _analysis_step(job_key)["run"]
    script = _DETECTORS[job_key]
    lines = [line for line in body.splitlines() if script in line]
    assert len(lines) == 1, (
        f"expected one line invoking {script} in {job_key}, found {len(lines)}: {lines}"
    )
    return lines[0]


# --------------------------------------------------------------------------------------------
# The checks actually run.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("job_key", sorted(_DETECTORS))
def test_the_checker_exists_at_the_path_the_workflow_names(job_key: str) -> None:
    """A workflow naming a missing script fails at run time, not at review time."""
    script = _DETECTORS[job_key]
    assert (_ROOT / script).is_file(), f"{_WORKFLOW_NAME} references a missing script: {script}"


@pytest.mark.parametrize("job_key", sorted(_DETECTORS))
def test_exactly_one_workflow_invokes_the_checker_and_it_is_the_advisory_one(job_key: str) -> None:
    """The whole defect was a script nothing ran. Pin WHERE it runs, not merely THAT it runs.

    A second invocation elsewhere is the thing to catch: added to a workflow holding a required
    context, these checks would begin gating merges without anyone deciding that they should.
    """
    script = _DETECTORS[job_key]
    invoking = sorted(
        path.name for path in _WORKFLOWS.glob("*.yml") if script in path.read_text(encoding="utf-8")
    )
    assert invoking == [_WORKFLOW_NAME], (
        f"{script} must be invoked by {_WORKFLOW_NAME} alone (it holds no required context); "
        f"found it in {invoking}. Wiring it into another workflow is an owner decision."
    )


@pytest.mark.parametrize("job_key", sorted(_DETECTORS))
def test_the_checker_is_not_in_a_commit_refusing_hook(job_key: str) -> None:
    """A pre-commit hook REFUSES the commit, which is blocking by another name.

    The positive control matters: this file legitimately contains other script paths, so a passing
    assertion must be shown to be reading a populated file rather than an empty or renamed one.
    """
    text = _PRE_COMMIT.read_text(encoding="utf-8")
    assert "scripts/hooks/ledger_check.py" in text, (
        "positive control failed: .pre-commit-config.yaml no longer names the ledger gate, so this "
        "file is not the hook config this test believes it is reading"
    )
    assert _DETECTORS[job_key] not in text, (
        f"{_DETECTORS[job_key]} is wired into .pre-commit-config.yaml, which refuses a commit. "
        f"Promoting one of these checks to blocking is an owner decision (BACKLOG #1525)."
    )


# --------------------------------------------------------------------------------------------
# They cannot gate.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("job_key", sorted(_DETECTORS))
def test_the_analysis_step_cannot_fail_its_job(job_key: str) -> None:
    """Without this, a checker's empty-population refusal -- what running from the wrong directory
    looks like -- would fail the job, and the job would be a gate nobody approved."""
    step = _analysis_step(job_key)
    assert step.get("continue-on-error") is True, (
        f"{job_key}/{step.get('name')!r} runs the checker without continue-on-error: true"
    )


@pytest.mark.parametrize("job_key", ["citation-line-drift", "banner-sha-agreement"])
def test_the_checker_is_invoked_in_advisory_mode(job_key: str) -> None:
    """Both tools FAIL CLOSED by default: a finding exits 1. `--advisory` is the opt-out."""
    invocation = _invocation(job_key)
    assert "--advisory" in invocation, (
        f"{job_key} invokes its checker without --advisory on the command itself, so a finding "
        f"would exit 1: {invocation.strip()!r}"
    )


def test_the_subject_exists_screen_is_not_given_an_advisory_flag() -> None:
    """THE ONE JOB THAT MUST NOT CARRY THE FLAG, and its absence is the stronger guarantee.

    That screen's findings already exit 0 -- candidates are a report, not a failure. Every non-zero
    exit it can produce is the screen MALFUNCTIONING: a broken extractor or probe control (2), an
    unresolvable ref (2), an unreadable ledger (2), or a known-true ledger control that did not fire
    (1). #1426 was exactly that malfunction shipping green for weeks, so a flag able to downgrade
    those would reinstate the defect under the word "advisory".

    Its absence also fails LOUDLY rather than silently: argparse rejects an unknown option with exit
    2, so adding the flag reddens the step instead of quietly gating nothing.
    """
    assert "--advisory" not in _invocation("subject-exists"), (
        "subject_exists_screen.py has no --advisory and must not be given one: its only non-zero "
        "exits are malfunctions, so the flag could only ever hide a broken screen (BACKLOG #1525)."
    )


def test_no_detector_job_can_redden_the_liveness_meta_gate() -> None:
    """`liveness` is the one job in this workflow built to go red. Adding one of these to its
    `needs` would route a ledger finding into the only failing surface the file has.

    NOT PARAMETRIZED: the assertion is over the whole `needs` list, so per-job arms would re-run one
    identical check three times and read as three guarantees where there is one."""
    needs = set(_JOBS["liveness"]["needs"])
    assert needs == _LIVENESS_MEASUREMENT_JOBS, (
        f"liveness needs {sorted(needs)}; expected {sorted(_LIVENESS_MEASUREMENT_JOBS)}"
    )
    assert needs.isdisjoint(_DETECTORS)


def test_no_job_in_this_workflow_is_a_claimed_required_context() -> None:
    """The repository's checked-in claim about what gates a merge must not name this workflow.

    HONEST LIMIT: branch protection lives on the server and this asserts the CLAIM, not the server.
    The positive control makes the absence meaningful -- an empty or unparsed list would otherwise
    satisfy the assertion for the wrong reason.
    """
    required = required_contexts()
    assert "cla" in required and len(required) >= 10, (
        f"positive control failed: required_contexts() returned {len(required)} entries and did not "
        "include the known-required 'cla', so its absence findings prove nothing"
    )
    assert set(_DETECTORS) <= _JOBS.keys(), (
        f"{_WORKFLOW_NAME} no longer declares {sorted(set(_DETECTORS) - _JOBS.keys())}"
    )
    declared = {context_of(key, job) for key, job in _JOBS.items()}
    assert not (declared & set(required)), (
        f"{_WORKFLOW_NAME} is advisory by design and must never be promoted, but "
        f"{sorted(declared & set(required))} appears in .github/required-contexts.txt"
    )


# --------------------------------------------------------------------------------------------
# They can see a real hit.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("job_key", _NEEDS_FULL_HISTORY)
def test_the_git_reading_jobs_check_out_full_history(job_key: str) -> None:
    """A shallow checkout makes both of these report nothing and print a reassuring summary.

    This is the workflow's own recorded failure class -- the `liveness` job exists because a shallow
    fetch destroyed diff-cover's merge base and the empty report read as clean. The positive control
    is the third job: citation-line-drift asks git nothing and legitimately runs shallow, so a
    blanket "every checkout is deep" rule would be satisfied by a file where depth means nothing.
    """
    steps = _JOBS[job_key]["steps"]
    checkout = next(step for step in steps if "checkout" in (step.get("uses") or ""))
    assert checkout.get("with", {}).get("fetch-depth") == 0, (
        f"{job_key} reads git history and must check out with fetch-depth: 0; on a shallow clone it "
        "measures nothing and says so in a line that reads clean"
    )


def test_the_file_reading_job_is_not_forced_deep_by_a_blanket_rule() -> None:
    """The control for the arm above. `citation_line_check.py` reads files and asks git nothing, so
    its job is the one place a depth assertion must NOT hold -- which is what proves the assertion
    above is about the tools' needs rather than about every checkout in the file."""
    steps = _JOBS["citation-line-drift"]["steps"]
    checkout = next(step for step in steps if "checkout" in (step.get("uses") or ""))
    assert checkout.get("with", {}).get("fetch-depth") is None


def test_the_citation_baseline_the_workflow_relies_on_is_in_the_tree() -> None:
    """`--baseline` with no argument resolves to a shipped file. If that file is gone the tool exits
    2 -- a malfunction, correctly -- but the leg then reports nothing for a reason nobody wrote.

    Read from the TOOL's own constant rather than re-spelling the path here: two spellings of one
    path is the drift this repository keeps paying for.
    """
    spec = importlib.util.spec_from_file_location(
        "_citation_line_check", _ROOT / _DETECTORS["citation-line-drift"]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.DEFAULT_BASELINE.is_file(), (
        f"{module.DEFAULT_BASELINE} is missing; the citation-line job invokes --baseline bare"
    )


# --------------------------------------------------------------------------------------------
# The two dead-gate warnings are coupled to prose the TOOLS own, and nothing pinned that.
# --------------------------------------------------------------------------------------------

#: job key -> (the needle its step greps for, the tool source that must still produce it).
#: Both needles are ENGLISH SUMMARY PROSE. Reword either line in its tool and the warning stops
#: firing while the job stays green -- a silent loss of exactly the dead-gate control these two
#: jobs were given. The two are pinned DIFFERENTLY because only one is a literal in its source; see
#: the arms below, and do not merge them back into one parametrized check.
_CONTROL_NEEDLES = {
    "banner-sha-agreement": ("examined 0 closing-claim sha", "scripts/docs/banner_sha_check.py"),
    "subject-exists": ("FIRED as expected", "scripts/docs/subject_exists_screen.py"),
}


@pytest.mark.parametrize("job_key", sorted(_CONTROL_NEEDLES))
def test_the_dead_gate_warning_still_greps_for_the_needle_this_suite_tracks(job_key: str) -> None:
    """Reads the needle out of the WORKFLOW, so the arms below cannot pass by agreeing with a copy."""
    needle = _CONTROL_NEEDLES[job_key][0]
    body = _analysis_step(job_key)["run"]
    assert f'grep -q "{needle}"' in body, (
        f"{job_key} no longer greps for {needle!r}. Update _CONTROL_NEEDLES and this suite together, "
        "or the dead-gate warning is guarding a string nobody emits."
    )


def test_the_subject_exists_dead_gate_needle_is_a_literal_its_tool_still_holds() -> None:
    """A SOURCE-SUBSTRING CHECK, AND ONLY BECAUSE THIS NEEDLE IS A LITERAL (SDS-3.8).

    `FIRED as expected` is written verbatim in the screen, so its presence there answers the question
    being asked. Its sibling needle is NOT, and applying the same check to it would be an instrument
    answering an adjacent question: `examined 0 closing-claim sha` is assembled by an f-string and
    appears nowhere in that file, which is exactly how this arm first failed. That one is pinned by
    driving real stdout instead, below.

    Only the ledger-control path can produce this line, and BOTH of its controls have retired today
    (BACKLOG #1525), so a real run cannot currently print it -- which is why this is the literal
    check and not a stdout one.
    """
    needle, source = _CONTROL_NEEDLES["subject-exists"]
    assert needle in (_ROOT / source).read_text(encoding="utf-8"), (
        f"{source} no longer contains the literal {needle!r}, so the subject-exists dead-gate "
        "warning can never fire and a screen with no live control would render as a clean run."
    )


def test_the_banner_sha_dead_gate_needle_matches_REAL_STDOUT(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """THE STRONGER HALF, because a needle present in the SOURCE can still never reach STDOUT.

    Drives the tool's `main` over a ledger whose only cited sha is unresolvable -- which is what a
    shallow checkout produces for EVERY sha -- and greps the captured output the way the workflow
    greps the file it redirected. Nothing here restates the tool's format string: a test that
    rebuilt the summary line itself would agree with a copy rather than with the tool.
    """
    spec = importlib.util.spec_from_file_location(
        "_banner_sha_for_needle", _ROOT / _DETECTORS["banner-sha-agreement"]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    ledger = tmp_path / "LEDGER.md"
    ledger.write_text(
        # The closed-status banner glyph, quoted as a token per CLAUDE.md section 11.
        "## 1. a row\n\n> \u2705 **SHIPPED in `deadbeef1234`.**\n\nprose\n",
        encoding="utf-8",
    )
    rc = module.main([str(ledger), "--repo", str(tmp_path)])
    out = capsys.readouterr().out

    assert rc == 0, "an unresolvable sha is not a finding; only the coverage line reports it"
    needle = _CONTROL_NEEDLES["banner-sha-agreement"][0]
    assert needle in out, (
        f"the shallow-checkout case no longer prints {needle!r}, so the workflow's grep is dead and "
        f"a run that examined nothing would render as a clean one. Got: {out!r}"
    )
