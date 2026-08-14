# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The free-threaded canary must be capable of reporting a problem.

`freethread-smoke.yml` was structurally incapable of it: every step was `continue-on-error`, every
step after setup was gated on `steps.setup.outcome == 'success'`, AND the job itself was
`continue-on-error`. So a runner that could not provision 3.14t skipped everything and went green,
and a failing smoke test was swallowed and went green. Five runs, five successes, and nothing in that
record could distinguish a canary that flew from one that never left the ground.

(For the record: it WAS genuinely flying — run 30256316219 shows `sys._is_gil_enabled() = False` on a
free-threading build with 73 tests passing. The defect was latent, not active. That is precisely why
it needed a test: nothing would have told us when it stopped.)

These tests pin the two properties that make the signal real — the verdict step exists and is allowed
to fail — and the property that makes failing safe: this workflow never runs on a pull request.
"""

import re
from pathlib import Path

import pytest
import yaml

_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "freethread-smoke.yml"

# Steps whose outcome the verdict must consider. Each is continue-on-error by design, so each is a
# way for the canary to fail quietly if nothing rules on it afterwards.
_DIAGNOSTIC_STEPS = ("setup", "install", "gil", "smoke")


@pytest.fixture(scope="module")
def workflow() -> dict:
    assert _WORKFLOW.is_file(), f"workflow not found at {_WORKFLOW}"
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def job(workflow: dict) -> dict:
    return workflow["jobs"]["freethread"]


def _verdict_step(job: dict) -> dict:
    steps = [s for s in job["steps"] if "Verdict" in (s.get("name") or "")]
    assert len(steps) == 1, "expected exactly one verdict step"
    return steps[0]


# --------------------------------------------------------------------------------------------
# The signal must be able to exist.
# --------------------------------------------------------------------------------------------


def test_the_job_is_not_continue_on_error(job: dict) -> None:
    """Job-level continue-on-error made every path green. It bought nothing — the triggers already
    guarantee nothing is gated — and cost the entire signal."""
    assert job.get("continue-on-error") is not True, (
        "a job that cannot fail cannot report a dead canary"
    )


def test_the_verdict_step_can_fail(job: dict) -> None:
    step = _verdict_step(job)
    assert step.get("continue-on-error") is not True, (
        "the verdict step is the only thing that turns collected outcomes into a signal; "
        "continue-on-error here silently restores the original defect"
    )
    assert step.get("if") == "always()", "the verdict must run even when an earlier step failed"


def test_the_verdict_considers_every_diagnostic_step(job: dict) -> None:
    """A step whose outcome nothing reads is a step that can fail in silence."""
    step = _verdict_step(job)
    env = step.get("env") or {}
    referenced = " ".join(str(v) for v in env.values())
    for name in _DIAGNOSTIC_STEPS:
        assert f"steps.{name}.outcome" in referenced, (
            f"the verdict never reads steps.{name}.outcome, so that step can fail quietly"
        )


def test_every_diagnostic_step_has_an_id(job: dict) -> None:
    """Outcomes are only readable via a step id."""
    ids = {s.get("id") for s in job["steps"] if s.get("id")}
    assert set(_DIAGNOSTIC_STEPS) <= ids, f"missing ids: {set(_DIAGNOSTIC_STEPS) - ids}"


# --------------------------------------------------------------------------------------------
# ...and failing must stay safe.
# --------------------------------------------------------------------------------------------


def test_the_workflow_never_runs_on_a_pull_request(workflow: dict) -> None:
    """This is what makes a red canary harmless, and it is structural rather than a convention.
    `on:` parses to the key True under YAML 1.1, hence the lookup."""
    triggers = workflow.get("on") or workflow.get(True)
    assert set(triggers) == {"schedule", "workflow_dispatch"}, (
        f"unexpected triggers {sorted(triggers)} -- a PR trigger would make this job block a merge"
    )


def test_the_smoke_step_does_not_hide_pytest_behind_a_pipe(job: dict) -> None:
    """`pytest | tee` yields tee's exit status, not pytest's -- the pipe trap this repo keeps hitting."""
    smoke = next(s for s in job["steps"] if s.get("id") == "smoke")
    body = smoke["run"]
    assert not re.search(r"pytest[^\n|]*\|\s*tee", body), (
        "pytest's exit code would be masked by tee"
    )
    assert "STATUS=$?" in body and "exit $STATUS" in body


def test_a_vacuous_pass_is_treated_as_a_failure(job: dict) -> None:
    """pytest exiting 0 having collected nothing is the same shape as the gates fixed in #25:
    success that measured nothing."""
    verdict = _verdict_step(job)["run"]
    assert "PASSED" in verdict
    assert "measured nothing" in verdict, "a zero-test pass must be called out, not accepted"
