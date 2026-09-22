# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`ci.yml`'s `changes` step on a MERGE QUEUE event, driven directly.

The queue commit is the one that reaches `main`, so whatever this step decides there is the last
gating decision anybody makes about the change. Until the `merge_group` arm was added, nothing
decided it on purpose: the event fell through to the `pull_request` arm, where `BASE_SHA` comes from
``github.event.pull_request.base.sha`` and a merge_group payload carries no pull_request at all.

**An empty `BASE_SHA` does not fail, it succeeds emptily.** ``git diff --name-only "...HEAD"`` with an
empty left operand is ``HEAD...HEAD``: exit 0, no output, nothing on stderr. Every path grep in the
step then missed, and the queue's gating fell to the ``[ -z "$changed" ]`` fail-safe near the bottom.

That fail-safe reads "no files changed, so run everything". It is correct for an empty PR diff and was
correct here only by accident -- and the accident is one edit deep. Read in isolation it invites the
opposite reading, "nothing changed, so there is nothing to test". Flip it and every queue run skips
install, lint, type-check and the whole of pytest, then reports GREEN, because a skipped required leg
reports success. That is the silent-control shape ADR 0158 names, on the merge path.

So this module pins two different things, and BOTH are needed:

1. the arm's emitted values, through real bash -- what the queue actually gates on; and
2. that the arm is reached BEFORE the step's ``git diff``, which is the only property that
   distinguishes a deliberate decision from the fall-through that happened to agree with it.

Point 2 is why a value-only test would prove nothing here. The arm was written to PRESERVE the
behaviour that was already running, so its outputs are identical to the fall-through's. Delete the arm
and every value assertion below still passes. The stderr discriminator is what notices.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _bash_resolver import explain_returncode, probe_env, require_bash  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_SOURCE_REPO = "MEFORORG/MessageFoundry"

#: What the queue gates on. Read as a pair with the job `if:` conditions asserted at the bottom of
#: this file, because these rows DO NOT all mean the same thing:
#:
#: * `serverdb` decides nothing. sqlserver-store and postgres-store name merge_group in their own
#:   job `if:`, so a queue entry runs them whatever this emits.
#: * `code` is belt-and-braces. `test` and `webconsole` name merge_group in their own STEP `if:`.
#: * `docker`, `ide`, `tooling` and `packaging` DO decide their jobs -- docker-smoke, ide, tooling
#:   and packaging-build are each gated on an output of this step AND name merge_group nowhere, so
#:   false here is that job OFF in the queue. `_DECIDED_BY_THE_ARM_ALONE` below pins that set.
#:
#: Asserting the outputs without that context would teach a reader the opposite of what the workflow
#: does. The same partition is stated at the arm in ci.yml; the two move together.
_EXPECTED = {
    "serverdb": "false",
    "docker": "false",
    "code": "true",
    "ide": "false",
    "tooling": "false",
    # Pinned when the arm gained this output. It is what the residual arm already computed off the
    # empty diff, so emitting it changed no behaviour -- pinning it puts the arm's newest output
    # under the same guard as the rest, where a later edit to it cannot go unread.
    "packaging": "false",
}

#: Jobs whose own `if:` names merge_group, so they run on a queue entry whatever `changes` emits.
#: Pinned because the comment in the arm points at them, and a comment that names a list nothing
#: checks goes stale silently.
_SELF_GATED_ON_QUEUE = {
    "test",
    "webconsole",
    "sqlserver-store",
    "postgres-store",
    "load-test",
    "load-test-sqlserver",
    "windows-service-smoke",
}

#: The mirror image, and the one the arm's comment in ci.yml enumerates: jobs GATED ON AN OUTPUT of
#: the `changes` step that name merge_group nowhere, so the arm alone settles whether they run in the
#: queue. Pinned because an unchecked enumeration is exactly what went wrong here once -- an earlier
#: draft of that comment named these four under the predicate "the jobs that name merge_group
#: nowhere", which is a WIDER set.
_DECIDED_BY_THE_ARM_ALONE = {
    "docker-smoke",
    "ide",
    "tooling",
    "packaging-build",
}

#: The two jobs that satisfy the SECOND half of that predicate and not the first, which is the whole
#: of why the wider set is wider: `changes`, which has no `if:` at all, and `ci-gate`, which is
#: `always()` and reads no output of this step. The arm's comment in ci.yml names both.
_NOWHERE_AND_DECIDED_HERE_BY_NOTHING = {"changes", "ci-gate"}

#: The control for the pin above: every job that satisfies only that second half.
#:
#: SPELLED OUT, NOT DERIVED, and that is the point of it. Writing this as
#: ``_DECIDED_BY_THE_ARM_ALONE | _NOWHERE_AND_DECIDED_HERE_BY_NOTHING`` reads the same and controls
#: nothing, because a control derived from the pin it controls FOLLOWS that pin. Measured on this
#: file 2026-09-22: give `tooling` a merge_group mention and drop it from the pin above -- which is
#: what that pin's own failure message asks for -- and a derived wider set shrinks in step, stays
#: green, and reports nothing, while the population the ci.yml comment cites has gone from six to
#: five. The count this replaced went red there, so a derived set would have been WEAKER than the
#: count it was meant to improve on.
#:
#: This was a COUNT of six until 2026-09-22, and a count holds while membership moves. Renaming the
#: `ci-gate` job key left six at six in this module while a set names it. (It is caught outside this
#: module, by tests/test_required_contexts.py -- "silent" here means silent HERE.) The `changes`
#: rename is NOT an example of the same thing and must not be cited as one: it raises KeyError in
#: `_changes_step_script` below and in tests/test_ci_tooling_gate.py, and trips an assert in
#: tests/test_ci_odbc_installer_pipefail.py. Measured 2026-09-22 by renaming the job key: 17 tests
#: failed across those three modules. It was never a silent mutation.
_NAMES_MERGE_GROUP_NOWHERE = {
    "changes",
    "ci-gate",
    "docker-smoke",
    "ide",
    "tooling",
    "packaging-build",
}

# THE RELATION BETWEEN THE TWO PINS, CHECKED AT IMPORT RATHER THAN CLAIMED IN PROSE.
#
# The prose above says the wider pin is the narrower one plus exactly two named jobs. Until
# 2026-09-22 that was a claim and nothing more: the wider constant was spelled as a union, and a
# comment said the union "means the two pins cannot be edited into equality". A union gives a
# superset, not a STRICT one -- add both names to `_DECIDED_BY_THE_ARM_ALONE` and the two sets are
# equal, which was measured true. That is the compensating-control-on-a-false-premise defect
# (Secure_Development_Standards SDS-3.6/SDS-3.7) sitting in a module whose whole job is catching it.
#
# The second assertion is where disjointness lives: the difference of the two pins is disjoint from
# the narrower one by construction, so requiring that difference to EQUAL the two-name literal
# requires those two names to be out of the narrower pin.
assert _DECIDED_BY_THE_ARM_ALONE < _NAMES_MERGE_GROUP_NOWHERE, (
    "the two pins in this module are no longer a strict narrowing: the wider one does not properly "
    f"contain the narrower one.\n  narrower: {sorted(_DECIDED_BY_THE_ARM_ALONE)}\n"
    f"  wider:    {sorted(_NAMES_MERGE_GROUP_NOWHERE)}\n"
    "If they came out EQUAL, the gated-on-an-output half of the arm's predicate in ci.yml has "
    "stopped discriminating and that arm's comment is now false. Read it before moving either pin."
)
_EXTRAS_IN_THE_WIDER_PIN = _NAMES_MERGE_GROUP_NOWHERE - _DECIDED_BY_THE_ARM_ALONE
assert _EXTRAS_IN_THE_WIDER_PIN == _NOWHERE_AND_DECIDED_HERE_BY_NOTHING, (
    "the wider pin is no longer the narrower one plus exactly the two jobs the arm's comment in "
    "ci.yml names.\n"
    f"  unexpected extras: {sorted(_EXTRAS_IN_THE_WIDER_PIN - _NOWHERE_AND_DECIDED_HERE_BY_NOTHING)}\n"
    f"  missing extras:    {sorted(_NOWHERE_AND_DECIDED_HERE_BY_NOTHING - _EXTRAS_IN_THE_WIDER_PIN)}\n"
    "A name in the first list is gated on an output of the `changes` step in a spelling the "
    "detector below does not read, or is a genuinely new kind of job the arm's comment does not "
    "cover. A name in the second means one of those two jobs moved. Either way the ci.yml comment "
    "is the thing to re-read, not this literal."
)


def _changes_step_script() -> str:
    """The real `run:` body of the `changes` step, read out of the workflow."""
    data = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    for step in data["jobs"]["changes"]["steps"]:
        if step.get("id") == "f":
            return str(step["run"])
    raise AssertionError("the `changes` step lost its `id: f`; this gate was restructured")


def _strip_merge_group_arm(script: str) -> str:
    """The pre-fix script: the same body with the merge_group arm removed.

    This is the negative control. Mirroring what the fall-through USED to do in Python would prove
    nothing about the shell -- the point is that the real step, minus this arm, reaches `git diff`.
    """
    lines = script.split("\n")
    start = next(
        (
            i
            for i, ln in enumerate(lines)
            if ln.strip() == 'if [ "$EVENT_NAME" = "merge_group" ]; then'
        ),
        None,
    )
    assert start is not None, "the merge_group arm is gone from ci.yml; that is the regression"
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i] == " " * indent + "fi"),
        None,
    )
    assert end is not None, "the merge_group arm has no closing `fi` at its own indent"
    return "\n".join(lines[:start] + lines[end + 1 :])


def _run(bash: str, cwd: Path, script_text: str, event: str) -> tuple[dict[str, str], str]:
    """Execute a detector body in `cwd` and return (parsed outputs, stderr).

    `cwd` is deliberately NOT a git repository in this module: that is what makes the step's own
    `git diff` audible on stderr when it runs, and silent when the arm exits before it.
    """
    script = cwd / "detector.sh"
    script.write_text(script_text, encoding="utf-8", newline="\n")
    out_file = cwd / "gh_output"
    out_file.write_text("", encoding="utf-8")
    # The child needs real utilities, not just the interpreter -- `probe_env` appends the
    # interpreter's own directory, where git and grep ship. Same call, same reason, as
    # tests/test_ci_tooling_gate.py, whose comment carries the measurement (BACKLOG #1373).
    env = probe_env(Path(bash), dict(os.environ))
    env.update(
        {
            "EVENT_NAME": event,
            # EMPTY, which is the whole point: this is what a merge_group payload supplies.
            "BASE_SHA": "",
            "GITHUB_REPOSITORY": _SOURCE_REPO,
            "GITHUB_OUTPUT": str(out_file),
        }
    )
    proc = subprocess.run(  # noqa: S603  # nosec B603 - resolved interpreter, fixed argv, tmp paths
        [bash, str(script)],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        timeout=180,
        check=False,
    )
    stderr = proc.stderr.decode("utf-8", "replace")
    assert proc.returncode == 0, (
        explain_returncode(proc.returncode, "the `changes` detector step") + "\n" + stderr
    )
    parsed: dict[str, str] = {}
    for line in out_file.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            parsed[key] = value
    return parsed, stderr


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    d = tmp_path / "not_a_repo"
    d.mkdir()
    return d


# --- what the queue gates on ----------------------------------------------------------------------


@pytest.mark.parametrize(("key", "expected"), sorted(_EXPECTED.items()))
def test_the_merge_group_arm_emits_the_pinned_value(
    workdir: Path, tmp_path: Path, key: str, expected: str
) -> None:
    """Each output the queue arm decides, one row per output so a failure names the one that moved."""
    bash = require_bash(tmp_path)
    outputs, _ = _run(bash, workdir, _changes_step_script(), "merge_group")
    assert outputs.get(key) == expected, (
        f"the merge_group arm emits {key}={outputs.get(key)!r}, pinned at {expected!r}. If this is a "
        "deliberate coverage change, move the pin and say so -- do not let the queue's gating drift "
        "without a reader noticing"
    )


def test_the_merge_group_arm_emits_a_usable_tooling_matrix(workdir: Path, tmp_path: Path) -> None:
    """An arm that exits without emitting KILLS the job on fromJSON. It does not skip it.

    test_ci_tooling_gate.py asserts this across every non-PR arm including this one. It is repeated
    here because the failure is fatal and the two files can be edited apart.
    """
    bash = require_bash(tmp_path)
    outputs, _ = _run(bash, workdir, _changes_step_script(), "merge_group")
    assert "tooling_matrix" in outputs, (
        "the merge_group arm exits without writing tooling_matrix. fromJSON on an unset output FAILS "
        "the job -- it does not fall back to a full matrix"
    )
    assert json.loads(outputs["tooling_matrix"])["os"], (
        "the merge_group arm emitted an empty os list"
    )


# --- the discriminator, which is the part a value test cannot do ----------------------------------


def test_the_arm_decides_before_the_step_ever_runs_git(workdir: Path, tmp_path: Path) -> None:
    """THE REGRESSION, asserted in both directions in one test.

    The arm preserves the values the fall-through already produced, so asserting the values cannot
    tell a deliberate arm from a deleted one. What CAN tell them apart is whether the step reaches its
    `git diff`. With the arm, it exits first and git never runs. Without it, git runs against a
    directory that is not a repository and says so on stderr.

    Both halves are asserted so that gutting the control is also a failure: if the second assertion
    stops firing, this test has lost its grip on the pre-fix behaviour and proves nothing about the
    arm.
    """
    bash = require_bash(tmp_path)
    not_a_repo = re.compile(r"not a git repository", re.I)

    _, with_arm = _run(bash, workdir, _changes_step_script(), "merge_group")
    assert not not_a_repo.search(with_arm), (
        "the merge_group arm let the step reach `git diff`. The arm must exit before it -- that is "
        f"the whole of what it changes. stderr was:\n{with_arm}"
    )

    control = tmp_path / "control"
    control.mkdir()
    _, without_arm = _run(
        bash, control, _strip_merge_group_arm(_changes_step_script()), "merge_group"
    )
    assert not_a_repo.search(without_arm), (
        "the CONTROL did not reach `git diff` either, so the assertion above proves nothing. Either "
        "the step stopped calling git, or the arm-stripping helper is cutting the wrong block"
    )


# --- the context the emitted values are read in ---------------------------------------------------


def test_the_jobs_that_run_on_a_queue_entry_regardless_are_pinned(workdir: Path) -> None:
    """`serverdb=false` above does NOT mean the heavy legs are off in the queue.

    Seven jobs name merge_group in their own `if:` and so ignore what `changes` emits. The arm's
    comment says this; without a check, that comment is free to go stale while reading as current --
    and a reader who believes it would size the queue's cost at a fraction of the truth.
    """
    data = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    found = set()
    for name, job in data["jobs"].items():
        # `if:` EXPRESSIONS ONLY, at job level and step level. Searching the whole job -- which the
        # first draft of this test did -- matches comments and `run:` bodies too, so it reported the
        # `changes` job itself the moment that job gained an arm NAMING the event it gates. A gate
        # that cannot tell "decides on this event" from "mentions this event" is not measuring the
        # thing its failure message claims.
        conditions = [job.get("if", "")]
        conditions += [step.get("if", "") for step in job.get("steps", []) or []]
        if any("merge_group" in str(c) for c in conditions):
            found.add(name)
    assert found == _SELF_GATED_ON_QUEUE, (
        "the set of jobs that run on a merge_group entry regardless of the path filters has moved.\n"
        f"  added:   {sorted(found - _SELF_GATED_ON_QUEUE)}\n"
        f"  removed: {sorted(_SELF_GATED_ON_QUEUE - found)}\n"
        "That is a coverage AND cost change on the merge path. If it is deliberate, move this pin "
        "and the arm's comment together."
    )


def _partition_jobs(data: dict[str, Any]) -> tuple[set[str], set[str]]:
    """(jobs the merge_group arm alone decides, jobs that name merge_group nowhere).

    A function rather than a loop inside the test, so the predicate can be EXERCISED on a constructed
    workflow and not only pinned against the one real one. A detector that is only ever pinned is a
    detector whose own behaviour nobody has measured.
    """
    decided: set[str] = set()
    names_it_nowhere: set[str] = set()
    for name, job in data["jobs"].items():
        conditions = [str(job.get("if", ""))]
        conditions += [str(step.get("if", "")) for step in job.get("steps", []) or []]
        # BOTH SPELLINGS OF THE SAME REFERENCE. An Actions expression indexes a context with a dot
        # or with brackets, and `needs.changes.outputs['code']` is the same read as
        # `needs.changes.outputs.code`. ci.yml uses the dot form throughout (measured 2026-09-22:
        # zero bracket occurrences), so this clause changes no verdict on today's file. It is here
        # because a bracket-spelled gate is what a job DECIDED by the arm looks like while falling
        # outside this set, which would make the wider pin below report that the job reads no output
        # of this step. That is backwards, and backwards in the direction a reader would act on.
        # test_the_detector_reads_a_bracket_spelled_output_gate is the constructed row for it.
        gated_on_an_output = any(
            "needs.changes.outputs." in c or "needs.changes.outputs[" in c for c in conditions
        )
        # A substring test, so it is blind to an `if:` that is TRUE on merge_group without naming
        # it, such as webconsole's job-level `github.event_name != 'push'`. webconsole is caught
        # today only because its step `if:` lines name the event outright. Known limit, not widened.
        self_gated = any("merge_group" in c for c in conditions)
        if not self_gated:
            names_it_nowhere.add(name)
        if gated_on_an_output and not self_gated:
            decided.add(name)
    return decided, names_it_nowhere


def test_the_detector_reads_a_bracket_spelled_output_gate() -> None:
    """A constructed row, because ci.yml cannot exercise this case: it has no bracket spellings.

    Without it the bracket clause in `_partition_jobs` is a line nothing measures, and a later edit
    could drop it with every pin below still green. `unrelated` is the control: a bracket spelling of
    some OTHER job's outputs must not count as gated on this step, or the widening would be matching
    the bracket rather than the reference.
    """
    data: dict[str, Any] = {
        "jobs": {
            "dotted": {"if": "needs.changes.outputs.code == 'true'"},
            "bracketed": {"if": "needs.changes.outputs['code'] == 'true'"},
            "unrelated": {"if": "needs.other.outputs['code'] == 'true'"},
        }
    }
    decided, names_it_nowhere = _partition_jobs(data)
    assert decided == {"dotted", "bracketed"}, (
        f"the detector read {sorted(decided)} as gated on an output of the `changes` step. Both "
        "spellings of that reference must count, and nothing else may"
    )
    assert names_it_nowhere == {"dotted", "bracketed", "unrelated"}, (
        f"the wider half of the predicate read {sorted(names_it_nowhere)}; none of these three names "
        "merge_group, so all three belong to it"
    )


def test_the_jobs_the_arm_alone_decides_are_pinned_and_so_is_the_wider_set() -> None:
    """The four jobs whose queue fate `changes` settles by itself -- with the control for that four.

    The arm's comment in ci.yml enumerates these. An earlier draft enumerated the SAME four under a
    wider predicate, "the jobs that name merge_group nowhere", which also takes in `changes` itself
    and `ci-gate`. Neither is decided by anything this step emits, so the enumeration read as checked
    while being wrong about what it had checked.

    Both sets are pinned by membership, and each is its own literal. The wider pin is what makes the
    narrowing legible: it is the decided set plus exactly the two jobs the comment names, so a job
    that crosses between the two predicates is reported by name in whichever pin it left.

    THE STRICTNESS CHECK COMES FIRST, and where it sits is the whole of what it is worth. The same
    assertion, ``decided < names_it_nowhere``, once sat BEHIND the two pins, where it could not fire:
    the pins had already fixed both sets at their pinned membership, and the module-level assert
    above makes that membership a strict narrowing, so equality was excluded before a reader reached
    it. It was then deleted as an assertion that could not fail -- which is true of where it sat and
    false of the property it asserts. The state that separates the two, measured 2026-09-22: give a
    step in `changes` an `if:` naming merge_group and a step in `ci-gate` an `if:` reading
    ``needs.changes.outputs.code``, then follow every failure message that produces. Every pin goes
    green with the two predicates selecting IDENTICAL jobs, the gated-on-an-output half doing no
    work, and ci.yml's "BOTH HALVES OF THAT PREDICATE ARE LOAD-BEARING" false. Ahead of the pins,
    the same assertion fires on exactly that state, and the module-level assert above catches the
    constants an editor would have edited to reach it.
    """
    data = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    decided, names_it_nowhere = _partition_jobs(data)

    assert decided != names_it_nowhere, (
        "the two predicates now select the SAME jobs, so the gated-on-an-output half of the arm's "
        "predicate in ci.yml is doing no work and that arm's comment, which says BOTH HALVES ARE "
        "LOAD-BEARING, is false.\n"
        f"  both sets: {sorted(decided)}\n"
        "This fires AHEAD of the two pins below on purpose. Their messages invite you to move a "
        "pin, and moving both to match this state is green and wrong. Re-read the arm's comment in "
        "ci.yml and rewrite it, or restore whatever made the two halves differ, before you touch "
        "either pin."
    )
    assert decided == _DECIDED_BY_THE_ARM_ALONE, (
        "the set of jobs the merge_group arm alone decides has moved.\n"
        f"  added:   {sorted(decided - _DECIDED_BY_THE_ARM_ALONE)}\n"
        f"  removed: {sorted(_DECIDED_BY_THE_ARM_ALONE - decided)}\n"
        "A job entering this set gains the queue as a place it can be switched off by a path filter "
        "alone. If that is deliberate, move this pin and the arm's comment in ci.yml together."
    )
    assert names_it_nowhere == _NAMES_MERGE_GROUP_NOWHERE, (
        "the CONTROL moved: the set of jobs that name merge_group nowhere is not the pinned one.\n"
        f"  added:   {sorted(names_it_nowhere - _NAMES_MERGE_GROUP_NOWHERE)}\n"
        f"  removed: {sorted(_NAMES_MERGE_GROUP_NOWHERE - names_it_nowhere)}\n"
        "The assertion above passed, so the jobs the arm alone decides are where they were; what "
        "moved reads no output of this step -- a job renamed, added, deleted, or given or stripped "
        "of a merge_group mention. This set is what the arm's comment cites as the reason the "
        "predicate carries a gated-on-an-output half at all, so move this pin and that comment "
        "together."
    )
