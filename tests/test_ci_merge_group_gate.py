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
correct here only by accident: nothing about a queue entry means "run everything", it just happened to
produce an empty diff. Read in isolation the fail-safe invites the opposite reading, "nothing changed,
so there is nothing to test". Flip it and, ON A PULL REQUEST whose diff comes back empty, ``test``
skips install, lint, format check, both type-checks and the whole of pytest, ``webconsole`` skips
install and the console suite, and the run reports GREEN, because a skipped required leg reports
success. That is the silent-control shape ADR 0158 names.

**THAT HAZARD IS NOT ON THE MERGE PATH, AND AN EARLIER VERSION OF THIS DOCSTRING SAID IT WAS.** Measured
2026-09-21, at the tree this module ships in and at ``origin/main`` alike: 12 steps are gated on
``code == 'true'`` -- 8 in ``test``, 4 in ``webconsole`` -- and all twelve also carry
``|| github.event_name == 'merge_group'``, so in the queue not one of them can skip on account of
``code``, however it is set. What the arm fixes is that the queue's gating was an accident of an empty
base rather than a decision, and that the queue sat inside the fail-safe's blast radius at all. That is
worth fixing; it is not a silent green merge, and saying so was a false premise (SDS-3.7).

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

#: The control for the pin above: WHICH jobs satisfy only the second half of that predicate. The wider
#: set adds `changes` (no `if:` at all) and `ci-gate` (`always()`). Neither is DECIDED by anything this
#: step emits. `ci-gate` does READ all of it -- both its failing steps pass `toJSON(needs)` into the
#: log -- and reading an output is not being gated on one; only the second settles whether a job runs.
#:
#: A SET, NOT A COUNT, AND THE DIFFERENCE WAS MEASURED (2026-09-21). A bare `== 6` stayed green under
#: three edits a reader of the arm's comment in ci.yml would want to hear about: renaming the job key
#: `ci-gate`, deleting `ci-gate` and adding an always-on job in its place, and renaming `changes`
#: itself, which is the job every `needs: changes` here points at. This set fires on all three. What
#: ELSE sees a key rename is incidental rather than pinned: the required branch-protection context is
#: a job's `name:` ("CI gate"), so tests/test_required_contexts.py resolves the renamed job to the same
#: context and trips only through a literal `["ci-gate"]` lookup, and a `changes` rename reaches this
#: module's other tests only as a KeyError in `_changes_step_script`. Pinning the set costs two string
#: literals beyond the count and names nothing the arm's comment does not already assert out loud.
_NAMES_MERGE_GROUP_NOWHERE = {
    "changes",
    "ci-gate",
    "docker-smoke",
    "ide",
    "packaging-build",
    "tooling",
}


def _if_conditions(job: dict[str, object]) -> list[str]:
    """Every `if:` expression a job carries -- its own, then each step's -- as strings.

    `if:` EXPRESSIONS ONLY, at job level and step level. Searching the whole job -- which the first
    draft of the gating tests did -- matches comments and `run:` bodies too, so it reported the
    `changes` job itself the moment that job gained an arm NAMING the event it gates. A gate that
    cannot tell "decides on this event" from "mentions this event" is not measuring the thing its
    failure message claims.
    """
    steps = job.get("steps") or []
    assert isinstance(steps, list)
    return [str(job.get("if", ""))] + [str(step.get("if", "")) for step in steps]


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
        if any("merge_group" in c for c in _if_conditions(job)):
            found.add(name)
    assert found == _SELF_GATED_ON_QUEUE, (
        "the set of jobs that run on a merge_group entry regardless of the path filters has moved.\n"
        f"  added:   {sorted(found - _SELF_GATED_ON_QUEUE)}\n"
        f"  removed: {sorted(_SELF_GATED_ON_QUEUE - found)}\n"
        "That is a coverage AND cost change on the merge path. If it is deliberate, move this pin "
        "and the arm's comment together."
    )


def test_the_jobs_the_arm_alone_decides_are_pinned_and_so_is_the_wider_set() -> None:
    """The four jobs whose queue fate `changes` settles by itself -- with the control for that four.

    The arm's comment in ci.yml enumerates these. An earlier draft enumerated the SAME four under a
    wider predicate, "the jobs that name merge_group nowhere", which also takes in `changes` itself
    and `ci-gate`. Neither is decided by anything this step emits, so the enumeration read as checked
    while being wrong about what it had checked.

    BOTH SETS ARE PINNED BY NAME, and the wider one is what makes the narrowing legible: a reader can
    see the difference is exactly `changes` and `ci-gate`.

    A THIRD ASSERTION USED TO SIT BELOW THESE TWO AND HAS BEEN REMOVED: ``decided < names_it_nowhere``,
    docstring'd as catching the two sets coming out the same. It could not fire. `decided` is built as
    ``gated_on_an_output and not self_gated`` and `names_it_nowhere` as ``not self_gated``, so the
    first is a subset of the second BY CONSTRUCTION, and the strict form can only break on equality --
    which the two pins above forbid (a four-name set never equals a six-name one) and reach first.
    Measured 2026-09-21 over ten mutations of ci.yml chosen to red each pin alone and both together,
    in both directions (a job leaving a set, a job entering one): the first pin fired on five, the
    second on eight, the subset guard on NONE. A guard that cannot fail is worse than none, because it
    licenses the behaviour it appears to check.

    That guard was also the premise of an argument for dropping the wider pin altogether: "a strict
    subset test already guarantees the two sets differ". Both readings hold at once -- the subset test
    is redundant in logic AND inert at runtime -- so it guaranteed nothing. What forbids the two sets
    coinciding is the pair of by-name pins, which is why the wider one stays and the guard goes. The
    count it replaced went for its own measured reason, recorded at `_NAMES_MERGE_GROUP_NOWHERE`. Do
    not restore either one.
    """
    data = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    decided: set[str] = set()
    names_it_nowhere: set[str] = set()
    for name, job in data["jobs"].items():
        conditions = _if_conditions(job)
        gated_on_an_output = any("needs.changes.outputs." in c for c in conditions)
        # KNOWN LIMIT, recorded because a green run cannot show it: this is a SUBSTRING test, so it
        # sees only conditions that NAME the event. A negation-shaped condition that is true on a
        # queue entry without naming it -- `webconsole`'s job `if:` is `github.event_name != 'push'`
        # -- reads here as not-self-gated; webconsole lands in `_SELF_GATED_ON_QUEUE` only because
        # its STEP `if:`s do name merge_group. Widen by hand, not by regex, if a job ever gains a
        # negation as its only queue arm.
        self_gated = any("merge_group" in c for c in conditions)
        if not self_gated:
            names_it_nowhere.add(name)
        if gated_on_an_output and not self_gated:
            decided.add(name)

    assert decided == _DECIDED_BY_THE_ARM_ALONE, (
        "the set of jobs the merge_group arm alone decides has moved.\n"
        f"  added:   {sorted(decided - _DECIDED_BY_THE_ARM_ALONE)}\n"
        f"  removed: {sorted(_DECIDED_BY_THE_ARM_ALONE - decided)}\n"
        "A job entering this set gains the queue as a place it can be switched off by a path filter "
        "alone. If that is deliberate, move this pin and the arm's comment in ci.yml together."
    )
    assert names_it_nowhere == _NAMES_MERGE_GROUP_NOWHERE, (
        "the CONTROL moved: the jobs naming merge_group nowhere are no longer the pinned set.\n"
        f"  added:   {sorted(names_it_nowhere - _NAMES_MERGE_GROUP_NOWHERE)}\n"
        f"  removed: {sorted(_NAMES_MERGE_GROUP_NOWHERE - names_it_nowhere)}\n"
        f"  now:     {sorted(names_it_nowhere)}\n"
        "The assertion above only means something while this set is the strictly LARGER one -- it is "
        "what the arm's comment cites as the reason the predicate carries a gated-on-an-output half "
        "at all. A job renamed rather than re-gated lands here, and nothing else in this suite sees "
        "a renamed job key: the required branch-protection context is a job's `name:`, not its key."
    )
