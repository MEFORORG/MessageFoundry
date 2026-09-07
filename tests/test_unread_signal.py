# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The properties `.github/zizmor.yml` suppresses a `dangerous-triggers` finding ON, held as tests.

A SUPPRESSION IS A CLAIM, AND A CLAIM NOBODY CAN WATCH FAIL IS AN ASSUMPTION WEARING A GREEN TICK.
`unread-signal.yml` runs on `workflow_run`, which zizmor flags for the "pwn request" class: the job
runs from the DEFAULT BRANCH with a privileged token, so a workflow that checks out and EXECUTES the
triggering pull request's code would hand any fork pull request a write token.

THIS WORKFLOW IS THE WEAKEST OF THE `workflow_run` SUPPRESSIONS IN THIS REPOSITORY, and that is why
it needs its own file. `nightly-notice.yml` and `failure-signal.yml` both claim NO CHECKOUT and no
`uses:` at all, and their tests assert exactly that. This one checks out and runs two actions, so it
cannot borrow their argument. What makes it safe is a DIFFERENT property -- `github.sha` is the
default branch's last commit on a `workflow_run` and the base branch's last commit on a
`pull_request_target`, so a checkout that names no `ref:` takes TRUSTED code on either arm and never
the pull request's head. That single word `ref:` is the whole difference between this workflow and
the escalation zizmor is warning about, and adding it would redden nothing else.

IT ALSO RUNS ON `pull_request_target`, which zizmor flags under the same rule, and the argument is
the one above rather than a second one: the ref-less checkout. Which of the two label-bearing events
carries that arm is itself load-bearing -- under `pull_request` the ref-less default is the MERGE
commit, so the same file with one word changed would execute head code -- and no assertion about the
checkout can see it, so it has a test of its own.

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

    ONE ASSERTION, TWO ARMS, and the same missing word carries both. On a `workflow_run` GitHub sets
    `github.sha` to the DEFAULT BRANCH's last commit; on a `pull_request_target` it sets it to the
    BASE branch's last commit. Either way a checkout with no `ref:` takes trusted code.
    `ref: ${{ github.event.workflow_run.head_sha }}` -- or its `pull_request.head.sha` twin -- would
    fetch the triggering pull request's head instead and execute it under a token that can write to
    this repository. A one-line change that reddens nothing else in CI.

    WHAT THIS TEST CANNOT SEE is the other half of that argument: WHICH EVENT the label arm runs on.
    Switching `pull_request_target` to `pull_request` leaves this checkout `ref:`-less and still
    opens the hole, because under `pull_request` the ref-less default is the MERGE commit. That
    mutation is named by
    `test_the_label_arm_runs_on_the_event_whose_default_checkout_is_the_base` below, so the two
    breaks stay one red each.
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


def test_review_gate_stays_out_of_the_watched_list() -> None:
    """review-gate.yml was DELETED on 2026-09-04; a watched name resolving to nothing fires never.

    `test_every_watched_workflow_exists_by_name` already refuses an unresolvable name generically.
    This one names the specific entry, because `review gate` is what a reader restoring the
    self-clearing chain would reach for first -- and re-adding it would restore nothing.
    """
    watched = _on(_doc())["workflow_run"]["workflows"]
    assert "review gate" not in watched, (
        "`review gate` is back in the watched list. review-gate.yml was deleted on 2026-09-04, so "
        "this entry resolves to nothing and fires never. The self-clearing chain is carried by the "
        "`pull_request_target` label arm now; see the tests below."
    )


# --- the trigger list, which is load-bearing and can go quiet without reddening anything ---------
#
# WHY THIS SECTION EXISTS, and the lesson is not this workflow's alone.
# `.github/required-contexts.txt` records it as a general finding: A CONTROL BUILT ON ONE TRIGGER CAN
# BE BLIND TO ITS OWN REMOVAL. Measured 2026-08-31 on the retired review gate -- dropping `labeled`
# from its `types:` list made that gate unclearable and reddened NOTHING, with 65 tests passing.
#
# THIS WORKFLOW THEN SHIPPED THE SAME FAILURE, which is why the finding gets a test here rather than
# a citation. `review gate` was the only watched workflow firing on a label event. It was deleted
# with the reviewer requirement on 2026-09-04, the entry naming it went because it resolved to
# nothing, and the label arm went with it -- silently, because no test asked whether one existed.
# MEASURED on PR 897, 2026-09-05: `reviewed` was added at 20:39:02Z and `unread` was not withdrawn
# until 20:42:38Z, by run 33990769043 reacting to a `workflow_run` COMPLETION. The read did not clear
# the flag; an unrelated workflow finishing did.
#
# THE DETECTOR IS FED LITERALS, NEVER VALUES TAKEN FROM THE SHIPPED FILE. A control derived from the
# artifact it judges moves with that artifact, so a real mutation reddens the control as well as the
# test that should be naming the mutation -- two reds, one of them bookkeeping. The rule and the
# measurement behind it are recorded in tests/test_merge_gate_controls.py's retirement note.


def _signal_gaps(triggers: dict) -> list[str]:
    """Ways a trigger set leaves the `unread` flag unable to be raised, or unable to be withdrawn.

    Pure, and it takes a plain mapping so the controls below can plant one.
    """
    gaps: list[str] = []

    run = triggers.get("workflow_run")
    if not isinstance(run, dict) or not run.get("workflows"):
        gaps.append(
            "no `workflow_run` arm watching any workflow: nothing observes the last required check "
            "settling, which is the only moment a pull request BECOMES green and unread, so the "
            "flag is never raised"
        )
    elif "completed" not in (run.get("types") or []):
        gaps.append(
            "the `workflow_run` arm does not take `completed`: a run that has merely STARTED says "
            "nothing about whether the pull request is green"
        )

    # A label event exists on these two events and nowhere else. An arm declaring no `types:` takes
    # GitHub's default of [opened, synchronize, reopened], which carries neither label event -- so
    # presence of the ARM is not presence of the TRIGGER, and both are checked.
    arms = {
        k: (triggers.get(k) or {}) for k in ("pull_request", "pull_request_target") if k in triggers
    }
    for event, why in (
        (
            "labeled",
            "so `unread` is not withdrawn when somebody reads the pull request and labels it. It "
            "waits for the next watched-workflow completion, and a pull request that is finished "
            "and green -- the only kind this signal is about -- has none coming",
        ),
        (
            "unlabeled",
            "so removing `reviewed` cannot put the flag back. The pull request then stops being "
            "reported as unread while being exactly that",
        ),
    ):
        if not any(event in ((block or {}).get("types") or []) for block in arms.values()):
            gaps.append(f"no arm fires on an `{event}` event, {why}")

    return gaps


def test_the_signal_gap_detector_fires_on_a_trigger_set_that_can_go_quiet() -> None:
    """NEGATIVE CONTROL OF THE DETECTOR.

    "The shipped triggers are whole" and "the detector matches nothing" are the same green, and
    separating them is the whole point of this pair. Every planted set below is a LITERAL; the first
    is the state this repository actually shipped between 2026-09-04 and the arm that fixed it.
    """
    watching = {"workflows": ["CI"], "types": ["completed"]}

    shipped_regression = {"workflow_run": watching, "workflow_dispatch": None}
    assert any("`labeled`" in g for g in _signal_gaps(shipped_regression)), (
        "the detector cannot see a missing label arm, which is the exact shape that shipped"
    )
    assert any("`unlabeled`" in g for g in _signal_gaps(shipped_regression))

    assert any(
        "workflow_run" in g for g in _signal_gaps({"pull_request_target": {"types": ["labeled"]}})
    ), (
        "the detector cannot see a missing workflow_run arm, which is how the flag stops being RAISED"
    )

    assert any(
        "completed" in g
        for g in _signal_gaps({"workflow_run": {"workflows": ["CI"], "types": ["requested"]}})
    ), "the detector cannot see a workflow_run arm reacting to the wrong phase"

    # PRESENCE OF THE ARM IS NOT PRESENCE OF THE TRIGGER. A bare `pull_request_target:` takes
    # GitHub's default types, which carry no label event at all -- the shape most likely to be read
    # as a fix while changing nothing.
    bare = _signal_gaps({"workflow_run": watching, "pull_request_target": None})
    assert any("`labeled`" in g for g in bare) and any("`unlabeled`" in g for g in bare), (
        "the detector accepted a bare `pull_request_target:` as carrying a label trigger"
    )

    # Exactly one edge missing must report exactly one gap, or the detector cannot tell a half-fix
    # from a whole one.
    half = _signal_gaps({"workflow_run": watching, "pull_request_target": {"types": ["labeled"]}})
    assert len(half) == 1 and "`unlabeled`" in half[0], half


def test_the_signal_gap_detector_stays_quiet_on_a_trigger_set_that_only_widens() -> None:
    """THE OTHER MUTATION, and a must-trip suite is blind to over-correction without it.

    A detector broad enough to flag legitimate widening gets "fixed" by deleting the event somebody
    added on purpose. Adding a cron, a push arm, or further pull-request types is not the hazard, so
    each must stay clean here -- and this test must not go red for any mutation the one above
    catches, or the two stop naming different breaks.
    """
    widened = {
        "workflow_run": {"workflows": ["CI", "Security"], "types": ["completed"]},
        "pull_request_target": {"types": ["labeled", "unlabeled", "reopened", "ready_for_review"]},
        "workflow_dispatch": {"inputs": {"pr": {"required": True}}},
        "schedule": [{"cron": "0 7 * * 1"}],
        "push": {"branches": ["main"]},
    }
    assert _signal_gaps(widened) == [], (
        "the detector flagged a trigger set that only ADDS events and types. Widening when this "
        "workflow evaluates is legitimate, and a detector that refuses it will be silenced."
    )


def test_the_shipped_trigger_list_can_both_raise_and_withdraw_the_flag() -> None:
    """THE DETECTOR AGAINST THE SHIPPED FILE, which is the half that can actually go wrong.

    The controls above prove it can fire and that it does not fire at everything. This is what it
    fires at.
    """
    gaps = _signal_gaps(_on(_doc()))
    assert gaps == [], (
        "unread-signal.yml's trigger list has a gap that reddens nothing else in CI:\n  "
        + "\n  ".join(gaps)
    )


def test_the_label_arm_runs_on_the_event_whose_default_checkout_is_the_base() -> None:
    """THE HALF `test_the_checkout_never_names_a_ref` CANNOT SEE, and the swap is one word.

    A label event exists on `pull_request` and `pull_request_target` only, so restoring the
    self-clearing chain had to take one of them. They are not interchangeable here:

    * under `pull_request_target` a `ref:`-less checkout takes the BASE branch, and the workflow
      FILE is read from the base too. Both trusted.
    * under `pull_request` a `ref:`-less checkout takes the MERGE commit -- the pull request's own
      code, fetched and executed under this job's `pull-requests: write` token -- and the workflow
      file is read from the head as well.

    So switching this one word opens the pwn-request hole the zizmor `dangerous-triggers`
    suppression for this file says is closed, while leaving every other test in this module green.
    scripts/quality/workflow_local_action_check.py records the same rule at its own source.
    """
    triggers = _on(_doc())
    assert "pull_request_target" in triggers, (
        "the label arm is gone or was renamed. If it moved to `pull_request`, read this docstring "
        "before changing this assertion: that event's ref-less checkout takes the merge commit."
    )
    assert "pull_request" not in triggers, (
        "a `pull_request` arm was added. Under it a `ref:`-less checkout takes the MERGE commit, so "
        "this workflow would fetch and run the triggering pull request's code while holding "
        "`pull-requests: write`. Use `pull_request_target`, whose ref-less default is the base."
    )


def test_the_label_arm_reaches_the_resolver_through_env() -> None:
    """The `pull_request_target` arm carries its own number, and it must arrive the way the others
    do -- through `env:`, never spliced into the shell body.

    `test_every_event_value_reaches_a_script_through_env` refuses the splice generically. This names
    the specific value, so deleting the arm's plumbing while leaving its trigger in place -- which
    would resolve every label event to no pull request and do nothing, quietly -- is one named red.
    """
    env = _step("resolve").get("env", {})
    hoisted = [k for k, v in env.items() if "github.event.pull_request.number" in str(v)]
    assert hoisted, (
        "no `env:` entry on the resolve step carries `github.event.pull_request.number`. The "
        "`pull_request_target` arm then resolves to no pull request, and every label event is a "
        "no-op run that reports success."
    )
    block = str(_step("resolve")["run"])
    for name in hoisted:
        assert name in block, f"{name!r} is declared in `env:` but the script never reads it"


def test_both_arms_share_one_concurrency_key() -> None:
    """Two runs asking "is this pull request unread" are the SAME fact.

    The group must resolve to the same string for a label event and for a workflow completion on one
    pull request, or the two arms serialise against nothing and the comment can post twice. Both
    `workflow_run.head_branch` and `pull_request.head.ref` are the head's unqualified branch name,
    which is why the key is a branch rather than a number.
    """
    concurrency = _doc()["concurrency"]
    group = str(concurrency["group"])
    assert "github.event.workflow_run.head_branch" in group
    assert "github.event.pull_request.head.ref" in group, (
        f"the concurrency group is {group!r}. A `pull_request_target` run falls through to an empty "
        "key, so every pull request's label events share one group and a run for one blocks another."
    )
    assert concurrency["cancel-in-progress"] is False


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
