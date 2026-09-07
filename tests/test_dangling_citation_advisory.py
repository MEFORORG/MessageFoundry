# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pin that the dangling-citation scan REPORTS and cannot GATE (BACKLOG #1431).

``scripts/docs/dangling_citation_check.py`` was a working detector that ran nowhere: measured at
``46ea10a78`` its path occurred zero times across ``.github/`` plus ``.pre-commit-config.yaml``,
while a positive control (``backlog_citation_check.py``, a real ``run:``) occurred once and an
invented path occurred zero times. Only its TEST was wired, through ci.yml's ``DOC_GUARDS``.

WIRING IT UP IS HALF A DECISION, AND THIS FILE HOLDS THE OTHER HALF. Making a check run is a
Builder's call; making one BLOCK A MERGE is the owner's, and BACKLOG #353 sits unbuilt on exactly
that reasoning. So the job added to ``quality-advisory.yml`` is advisory by construction, and the
properties that make it so are strings in a YAML file -- one edit drops ``--advisory`` or
``continue-on-error`` and the check silently becomes something nobody approved.

WHAT KEEPS IT ADVISORY, and which half a test can see. Four things do:

1. the workflow holds no required status-check context;
2. ``--advisory`` makes a live-shape finding exit 0 rather than 1 (the tool's default is to fail);
3. ``continue-on-error: true`` means even the checker's empty-population REFUSAL cannot fail the job;
4. the job is absent from the ``liveness`` job's ``needs``, so it cannot redden the one job in that
   file built to go red.

Branch protection lives on the SERVER, so (1) is only assertable against the checked-in claim in
``.github/required-contexts.txt`` -- the same limit ``test_quality_advisory_invariants.py`` states
for itself. That is a real limit and it is named rather than papered over: this suite can prove the
repository does not CLAIM the context is required, not that the server agrees.

THE ABSENCE ASSERTIONS CARRY POSITIVE CONTROLS, deliberately. "This string is not in that list" and
"that list is empty because the parser broke" produce the identical green, and a test whose only
reachable outcome is success is not a test. Each absence check below first proves the instrument
finds something it should.
"""

from __future__ import annotations

from pathlib import Path

from tests._workflow_contexts import context_of, jobs_of, required_contexts

_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW_NAME = "quality-advisory.yml"
_WORKFLOWS = _ROOT / ".github" / "workflows"
_PRE_COMMIT = _ROOT / ".pre-commit-config.yaml"

#: The job key added by BACKLOG #1431.
_JOB = "dangling-citations"

#: The checker, spelled as the workflow spells it.
_SCRIPT = "scripts/docs/dangling_citation_check.py"

#: The four measurement jobs the liveness meta-gate rules on. The advisory citation job is
#: deliberately NOT among them -- see the module docstring, point 4.
_LIVENESS_MEASUREMENT_JOBS = {"complexity", "clone", "coverage", "mutation"}


def _analysis_step() -> dict:
    """The one step in the citation job that invokes the checker."""
    jobs = jobs_of(_WORKFLOW_NAME)
    assert _JOB in jobs, (
        f"{_WORKFLOW_NAME} has no {_JOB!r} job -- re-point this guard rather than letting it pass"
    )
    steps = [step for step in jobs[_JOB]["steps"] if _SCRIPT in (step.get("run") or "")]
    assert len(steps) == 1, (
        f"expected exactly 1 step in {_JOB!r} invoking {_SCRIPT}, found {len(steps)}"
    )
    return steps[0]


# --------------------------------------------------------------------------------------------
# The check actually runs.
# --------------------------------------------------------------------------------------------


def test_the_checker_exists_at_the_path_the_workflow_names() -> None:
    """A workflow naming a script that is not in the repo fails at run time, not at review time."""
    assert (_ROOT / _SCRIPT).is_file(), f"{_WORKFLOW_NAME} references a missing script: {_SCRIPT}"


def test_exactly_one_workflow_invokes_the_checker_and_it_is_the_advisory_one() -> None:
    """The whole defect was a script nothing ran. Pin WHERE it runs, not merely THAT it runs.

    A second invocation somewhere else is the thing to catch: added to a workflow holding a required
    context, this check would begin gating merges without anyone deciding that it should.
    """
    invoking = sorted(
        path.name
        for path in _WORKFLOWS.glob("*.yml")
        if _SCRIPT in path.read_text(encoding="utf-8")
    )
    print(f"[dangling-citations] workflows invoking {_SCRIPT}: {invoking}")
    assert invoking == [_WORKFLOW_NAME], (
        f"{_SCRIPT} must be invoked by {_WORKFLOW_NAME} alone (it holds no required context); "
        f"found it in {invoking}. Wiring it into another workflow is an owner decision."
    )


def test_the_checker_is_not_in_a_commit_refusing_hook() -> None:
    """A pre-commit hook REFUSES the commit, which is blocking by another name.

    The positive control matters: this file legitimately contains other script paths, so a passing
    assertion must be shown to be reading a populated file rather than an empty or renamed one.
    """
    text = _PRE_COMMIT.read_text(encoding="utf-8")
    assert "scripts/hooks/ledger_check.py" in text, (
        "positive control failed: .pre-commit-config.yaml no longer names the ledger gate, so this "
        "file is not the hook config this test believes it is reading"
    )
    assert _SCRIPT not in text, (
        f"{_SCRIPT} is wired into .pre-commit-config.yaml, which refuses a commit. Promoting this "
        f"check to blocking is an owner decision (BACKLOG #1431)."
    )


# --------------------------------------------------------------------------------------------
# It cannot gate.
# --------------------------------------------------------------------------------------------


def test_the_analysis_step_cannot_fail_its_job() -> None:
    """Without this, the checker's empty-population refusal -- what running from the wrong directory
    looks like -- would fail the job, and the job would be a gate nobody approved."""
    step = _analysis_step()
    assert step.get("continue-on-error") is True, (
        f"{_JOB}/{step.get('name')!r} runs the checker without continue-on-error: true"
    )


def test_the_checker_is_invoked_in_advisory_mode() -> None:
    """The tool FAILS CLOSED by default: a live-shape citation exits 1. `--advisory` is the opt-out,
    and it is what makes a finding reportable without being blocking.

    ASSERTED ON THE INVOCATION LINE, NOT ANYWHERE IN THE BODY, and that distinction is not
    hypothetical -- it is why this docstring exists. The first version of this test asked whether
    the string ``--advisory`` appeared in the step at all. It DID, in the step's own warning message,
    so deleting the flag from the command left the test green. Caught by mutating the workflow and
    watching the guard stay silent, which is the only way that class of defect shows itself.
    """
    body = _analysis_step()["run"]
    invocations = [line for line in body.splitlines() if _SCRIPT in line]
    assert len(invocations) == 1, (
        f"expected one line invoking {_SCRIPT} in {_JOB}, found {len(invocations)}: {invocations}"
    )
    assert "--advisory" in invocations[0], (
        f"{_JOB} invokes {_SCRIPT} without --advisory on the command itself, so a live-shape "
        f"finding would exit 1: {invocations[0].strip()!r}"
    )


def test_the_job_cannot_redden_the_liveness_meta_gate() -> None:
    """`liveness` is the one job in this workflow built to go red. Adding the citation job to its
    `needs` would route a citation finding into the only failing surface the file has."""
    liveness = jobs_of(_WORKFLOW_NAME)["liveness"]
    needs = set(liveness["needs"])
    assert needs == _LIVENESS_MEASUREMENT_JOBS, (
        f"liveness needs {sorted(needs)}; expected {sorted(_LIVENESS_MEASUREMENT_JOBS)}"
    )
    assert _JOB not in needs


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
    jobs = jobs_of(_WORKFLOW_NAME)
    assert _JOB in jobs, f"{_WORKFLOW_NAME} no longer declares {_JOB!r}"
    declared = {context_of(key, job) for key, job in jobs.items()}
    overlap = declared & set(required)
    print(
        f"[dangling-citations] {len(declared)} contexts in {_WORKFLOW_NAME}, {len(required)} required"
    )
    assert not overlap, (
        f"{_WORKFLOW_NAME} is advisory by design and must never be promoted, but "
        f"{sorted(overlap)} appears in .github/required-contexts.txt"
    )
