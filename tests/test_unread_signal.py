# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The properties `.github/zizmor.yml` suppresses a `dangerous-triggers` finding ON, held as tests.

A SUPPRESSION IS A CLAIM, AND A CLAIM NOBODY CAN WATCH FAIL IS AN ASSUMPTION WEARING A GREEN TICK.
`unread-signal.yml` runs on `workflow_run`, which zizmor flags for the "pwn request" class: the job
runs from the DEFAULT BRANCH with a privileged token, so a workflow that checks out and EXECUTES the
triggering pull request's code would hand any fork pull request a write token.

THIS WORKFLOW IS THE WEAKEST OF THE THREE `workflow_run` SUPPRESSIONS IN THIS REPOSITORY, and that is
why it needs its own file. `nightly-notice.yml` and `failure-signal.yml` both claim NO CHECKOUT and no
`uses:` at all, and their tests assert exactly that. This one checks out and runs two actions, so it
cannot borrow their argument. What makes it safe is a DIFFERENT property -- on a `workflow_run`,
`github.sha` is the default branch's last commit, so a checkout that names no `ref:` takes TRUSTED
code and never the pull request's head. That single word `ref:` is the whole difference between this
workflow and the escalation zizmor is warning about, and adding it would redden nothing else.

Each test below corresponds to one bullet of the justification in `.github/zizmor.yml`. If one fails,
fix the workflow or re-justify the suppression -- do not weaken the test.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = _ROOT / ".github" / "workflows"
FILE = WORKFLOWS / "unread-signal.yml"

_SHA_PINNED = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _doc() -> dict:
    return yaml.safe_load(FILE.read_text(encoding="utf-8"))


def _on(doc: dict) -> dict:
    # PyYAML parses a bare `on:` key as the BOOLEAN True, not the string "on". Reading doc["on"]
    # returns None and every assertion built on it would pass vacuously.
    return doc[True]


def _steps() -> list[dict]:
    steps = _doc()["jobs"]["announce"]["steps"]
    # Positive control for every assertion built on this list. A renamed job would otherwise make
    # "no offenders were found" and "nothing was looked at" render identically.
    assert steps, "the announce job has no steps to inspect"
    return steps


def _run_blocks() -> list[str]:
    blocks = [str(s["run"]) for s in _steps() if "run" in s]
    assert blocks, "the announce job has no `run:` step to inspect"
    return blocks


def _step(step_id: str) -> dict:
    matches = [s for s in _steps() if s.get("id") == step_id]
    assert len(matches) == 1, f"expected exactly one step with id {step_id!r}, found {len(matches)}"
    return matches[0]


# --- the load-bearing one -----------------------------------------------------------------------


def test_the_checkout_never_names_a_ref() -> None:
    """THE pwn-request precondition, and the only thing standing between this and an escalation.

    On a `workflow_run` GitHub sets `github.sha` to the DEFAULT BRANCH's last commit. A checkout with
    no `ref:` therefore takes trusted code. `ref: ${{ github.event.workflow_run.head_sha }}` would
    fetch the triggering pull request's head instead and execute it under a token that can write to
    this repository -- a one-line change that reddens nothing else in CI.
    """
    checkouts = [s for s in _steps() if str(s.get("uses", "")).startswith("actions/checkout")]
    assert checkouts, "no checkout step found; this test is watching the wrong workflow"
    for step in checkouts:
        with_ = step.get("with") or {}
        assert "ref" not in with_, (
            "the checkout names a `ref:`. On a workflow_run that is how the TRIGGERING pull "
            "request's head gets fetched and run under a privileged token. The zizmor "
            "dangerous-triggers suppression for this file rests on its absence."
        )
        assert with_.get("persist-credentials") is False, (
            "the checkout must set persist-credentials: false so no git credential survives it."
        )


def test_it_runs_only_first_party_sha_pinned_actions() -> None:
    """Weaker than the sibling workflows' "no `uses:` at all", so it is stated and held explicitly."""
    uses = [str(s["uses"]) for s in _steps() if "uses" in s]
    assert uses, (
        "no actions at all; either the workflow changed or this test is watching the wrong one"
    )
    for ref in uses:
        assert ref.startswith("actions/"), (
            f"{ref!r} is not a first-party GitHub action. This workflow holds a write token on a "
            "workflow_run trigger; adding third-party code to it needs its own justification in "
            ".github/zizmor.yml."
        )
        assert _SHA_PINNED.match(ref), f"{ref!r} is not pinned to a 40-character commit SHA."


def test_it_is_least_privilege_and_cannot_modify_code() -> None:
    """The token adds or removes one label and posts one comment. It cannot push, tag, or write code."""
    doc = _doc()
    assert doc["permissions"] == {"contents": "read"}, (
        f"top-level permissions are {doc.get('permissions')!r}. Keep the file default read-only so a "
        "job added here cannot inherit write scope by accident."
    )
    job_perms = doc["jobs"]["announce"].get("permissions")
    assert job_perms == {"contents": "read", "pull-requests": "write"}, (
        f"the announce job's permissions are {job_perms!r}. Anything that can modify code -- "
        "`contents: write`, `packages: write`, `id-token: write` -- turns the open fork path into "
        "the escalation the zizmor suppression says is closed."
    )


def test_every_event_value_reaches_a_script_through_env() -> None:
    """A branch name is chosen by whoever opened the branch.

    Interpolating `${{ github.event.* }}` into a `run:` body splices attacker-controlled text into a
    shell script.
    """
    offenders = [b for b in _run_blocks() if "${{" in b]
    assert offenders == [], (
        "A run block interpolates a GitHub expression directly. Hoist it to the step's `env:` and "
        "reference it as a shell variable."
    )
    # The positive half. Absence of `${{` also holds for a workflow that reads no event value at
    # all, so on its own it cannot tell "hoisted to env" from "gone".
    hoisted = [v for v in _step("resolve").get("env", {}).values() if "github.event" in str(v)]
    assert hoisted, (
        "the resolve step declares no `github.event` value in its `env:`. Either the values moved "
        "into the script body -- which the check above would then catch -- or this test is now "
        "watching the wrong step."
    )


def test_the_merge_queue_parse_is_gated_on_an_event_a_fork_cannot_produce() -> None:
    """`head_branch` is the one attacker-influenceable field this workflow parses.

    It is read only to recover a pull-request number from a `gh-readonly-queue/<base>/pr-<N>-<sha>`
    ref, and only when the triggering run's event was `merge_group`, which a fork cannot produce.
    """
    block = str(_step("resolve")["run"])
    assert "HEAD_BRANCH" in block, "the merge-queue parse is gone; re-read this test"
    gate = 'RUN_EVENT:-}" = "merge_group"'
    assert gate in block, (
        "the HEAD_BRANCH parse is no longer gated on the triggering run's event being merge_group. "
        "Ungated, an attacker-chosen branch name reaches the parse on any run."
    )


# --- the design rules the item settles, which no lint would ever catch --------------------------


def test_it_never_writes_the_reviewed_label() -> None:
    """THE ONE THING THIS MUST NEVER DO.

    A workflow that applies `reviewed` is the fail-open design review-gate.yml's author already
    rejected: a gate whose safe state depends on another workflow having succeeded is not a gate.
    The reasoning is in that file's header and this test is what keeps it true here.
    """
    for block in _run_blocks():
        assert "-label reviewed" not in block, (
            "unread-signal.yml writes the `reviewed` label. Nothing automated may ever add or "
            "remove it -- see the FAIL-CLOSED paragraph in .github/workflows/review-gate.yml."
        )


def test_it_is_not_and_must_not_become_a_required_context() -> None:
    """It reports a fact about a pull request from OUTSIDE that pull request's own event.

    Requiring it would let one pull request's state block another's, which is stalled-prs.yml's
    recorded reasoning for itself -- and a `workflow_run` reports no status context to the head at
    all, so requiring it would wedge every pull request forever (the required-but-absent trap).
    """
    from tests._workflow_contexts import required_contexts

    job_name = str(_doc()["jobs"]["announce"]["name"])
    assert job_name not in required_contexts(), (
        f"{job_name!r} appears in .github/required-contexts.txt. This job must stay advisory."
    )


def test_the_job_name_carries_no_expression() -> None:
    """tests/_workflow_contexts.py expands `${{ }}` in a job name to a `.+` WILDCARD when resolving a
    required context to its job. A templated name here could silently match an existing required
    context and re-point every check built on that mapping at this job instead.
    """
    assert "${{" not in str(_doc()["jobs"]["announce"]["name"])


def test_every_watched_workflow_exists_by_name() -> None:
    """A typo in `workflows:` fires nothing, silently, forever.

    `workflow_run` matches on a workflow's `name:`, not its filename, and GitHub reports no error for
    a name that matches nothing -- the signal would simply never arrive, which is the exact silence
    this workflow exists to end.
    """
    watched = _on(_doc())["workflow_run"]["workflows"]
    assert watched, "the watched-workflow list is empty"
    names = set()
    for path in WORKFLOWS.glob("*.yml"):
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(parsed, dict) and "name" in parsed:
            names.add(str(parsed["name"]))
    # Positive control: the resolver must find a name we know is there, or an empty `names` would
    # make every membership check below fail for the wrong reason.
    assert "CI" in names, "the workflow-name index did not resolve; this test proves nothing"
    missing = [w for w in watched if w not in names]
    assert missing == [], f"unread-signal.yml watches {missing}, which no workflow is named."


def test_the_lost_self_clearing_chain_is_recorded_where_it_was_lost() -> None:
    """RETIRED 2026-09-04, and this test now guards the RECORD instead of the behaviour.

    IT USED TO ASSERT `review gate` was in the watched list, because that is what made the `unread`
    label self-withdrawing rather than sticky: labelling a pull request `reviewed` re-ran
    review-gate.yml, whose completion re-triggered this workflow, which removed the label. The
    docstring ended "drop `review gate` from the watched list and the flag survives being read, with
    nothing reporting it". That prediction was correct and it is now the shipped behaviour.

    The owner retired the reviewer requirement and review-gate.yml was deleted, so the entry named a
    workflow that no longer exists and `test_every_watched_workflow_exists_by_name` failed on it.
    The two tests were in direct contradiction: one required the name present, the other required it
    resolvable. Nobody could satisfy both.

    SO THE REGRESSION IS REAL AND ACCEPTED, NOT FIXED. `review gate` was the only watched workflow
    firing on a `labeled` event, so `unread` now clears on the next push rather than when somebody
    reads the pull request. This test exists so that fact cannot quietly disappear: it fails if the
    entry is re-added without restoring the mechanism, and it fails if the explanation is deleted.
    """
    watched = _on(_doc())["workflow_run"]["workflows"]
    assert "review gate" not in watched, (
        "`review gate` is back in the watched list. review-gate.yml was deleted on 2026-09-04, so "
        "this entry resolves to nothing and fires never. If the workflow has been restored, restore "
        "the original test with it rather than leaving this one passing by accident."
    )
    assert "KNOWN REGRESSION" in FILE.read_text(encoding="utf-8"), (
        "the recorded reason `review gate` left the watched list is gone from unread-signal.yml. "
        "The regression it names -- `unread` no longer withdrawing when a pull request is read -- is "
        "still shipped, so deleting the explanation leaves the behaviour with nothing describing it."
    )


def test_the_comment_is_written_only_on_the_flag_transition() -> None:
    """The label doubles as the idempotency token, so a pull request is announced once per unread
    episode rather than once per completed workflow. Without the guard, every green check on a
    waiting pull request would post another comment.
    """
    commenting = [s for s in _steps() if "gh pr comment" in str(s.get("run", ""))]
    assert len(commenting) == 1, "expected exactly one commenting step"
    assert commenting[0].get("if") == "steps.decide.outputs.action == 'flag'"


def test_the_label_removal_is_guarded_so_it_need_not_swallow_its_exit_code() -> None:
    """`clear` means the label IS present, so the removal cannot fail for the ordinary reason.

    That guard is what lets the step keep its exit code instead of hiding a token failure behind a
    `|| true`, which is the shape tests/test_security_posture.py refuses on a required job.
    """
    removals = [s for s in _steps() if "--remove-label" in str(s.get("run", ""))]
    assert len(removals) == 1, "expected exactly one label-removal step"
    assert removals[0].get("if") == "steps.decide.outputs.action == 'clear'"
    assert "|| true" not in str(removals[0]["run"])
