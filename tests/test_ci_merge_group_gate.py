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
from typing import Any, NamedTuple

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
#: of why the wider set is wider. The arm's comment in ci.yml names both.
#:
#: What is CHECKED about them is that they are gated on no output of the `changes` step: that is the
#: two pins below, read together. Why each is not -- `changes` has no `if:` at all today and
#: `ci-gate` is `always()` -- is colour, and nothing verifies it. Do not promote it to a reason in
#: prose somewhere else.
_NOWHERE_AND_DECIDED_HERE_BY_NOTHING = {"changes", "ci-gate"}

#: The control for `_DECIDED_BY_THE_ARM_ALONE`: every job that satisfies only that second half.
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

#: The other side of the arm's predicate, and the one nothing pinned until 2026-09-22: jobs gated on
#: an output of the `changes` step that ALSO name merge_group, so the `NOT self_gated` half is what
#: takes them out of `_DECIDED_BY_THE_ARM_ALONE`. An empty set means that half removes nothing and
#: ci.yml's "BOTH HALVES ARE LOAD-BEARING" has gone false; a SMALLER set means the same claim has
#: gone false for the named job. Both are checked, because non-emptiness alone is a weaker pin than
#: the count this module already threw out for holding while membership moved.
#:
#: sqlserver-store and postgres-store carry `serverdb` in their job `if:`; `test` and `webconsole`
#: carry `code` in their STEP `if:` lines, which ci.yml's `code` row calls belt-and-braces -- so the
#: tidy-up that empties this set is an invited edit, not a contrived one.
_SELF_GATED_AND_GATED = {
    "test",
    "webconsole",
    "sqlserver-store",
    "postgres-store",
}

# The relation BETWEEN the three pins above is checked, not claimed in prose, by
# `test_the_two_pins_are_a_strict_narrowing` further down. Read that test before editing any of
# them: it reads only these constants and never the workflow, so it still says what is wrong with
# the literals when ci.yml is missing or unparseable.

#: One quoted bracket index, normalised back to a dot, so `needs['changes'].outputs.code`,
#: `needs.changes.outputs['code']` and `needs['changes']['outputs']['code']` all collapse to the one
#: substring test in `_partition_jobs`. An Actions expression may bracket-index ANY segment of a
#: context, so a list of the spellings to look for is a completeness claim over an open set -- what
#: SDS-3.6 says not to maintain. Normalising asks the question once instead.
#:
#: KNOWN LIMIT, STATED RATHER THAN IMPLIED, because the first draft of this line bounded the index to
#: `[A-Za-z_][\w-]*` and so read `needs.changes.outputs['3rd']` and `['a.b']` as NOT gated -- moving
#: the boundary while the comment above claimed there was none. The quote is captured and
#: back-referenced so the two must match, and anything but a quote is accepted between them. What is
#: still not read is an index that is itself an EXPRESSION, `needs[matrix.dep].outputs.code`, which
#: no amount of string work resolves. A job spelled that way lands outside `decided`.
_BRACKET_INDEX = re.compile(r"\[\s*(['\"])([^'\"]+)\1\s*\]")


class _Partition(NamedTuple):
    """How each of this file's 13 jobs falls under the two halves of the arm's predicate."""

    #: Gated on an output of the `changes` step AND naming merge_group nowhere -- the arm alone
    #: settles whether these run in the queue.
    decided: set[str]
    #: Naming merge_group nowhere, whatever they are gated on.
    names_it_nowhere: set[str]
    #: Naming merge_group in their own job-level or step-level `if:`.
    self_gated: set[str]
    #: Self-gated AND gated on an output. This one exists to be NON-EMPTY: it is the whole of what
    #: the `NOT self_gated` half of the arm's predicate removes, so an empty set means that half has
    #: stopped doing any work. `decided` versus `names_it_nowhere` measures the other half; without
    #: this, "BOTH HALVES ARE LOAD-BEARING" was checked in one direction only.
    self_gated_and_gated: set[str]


def _partition_jobs(jobs: dict[str, Any]) -> _Partition:
    """Sort a workflow's jobs under both halves of the arm's predicate, in one scan.

    ONE scan, four measurements, because every pin in this module reads the same two facts about a
    job. The pins stay separate literals -- what is shared is the detector, not a pin.

    It takes the JOBS mapping rather than the parsed document so a constructed case needs no
    workflow-shaped wrapper: a detector that is only ever pinned against the one real file is a
    detector whose own behaviour nobody has measured.
    `test_the_detector_reads_an_output_gate_however_it_is_spelled` is those constructed rows.

    `if:` EXPRESSIONS ONLY, at job level and step level. Searching the whole job -- which an early
    draft of the self-gated pin did -- matches comments and `run:` bodies too, so it reported the
    `changes` job itself the moment that job gained an arm NAMING the event it gates. A gate that
    cannot tell "decides on this event" from "mentions this event" is not measuring the thing its
    failure message claims.
    """
    decided: set[str] = set()
    names_it_nowhere: set[str] = set()
    self_gated: set[str] = set()
    self_gated_and_gated: set[str] = set()
    for name, job in jobs.items():
        # `str()` and `or []` are both load-bearing on legal YAML this file does not happen to
        # contain: a bare `if: true` parses to a bool, and `steps:` with nothing under it parses to
        # None. Each raises TypeError without one of these -- one guard each, measured, not both --
        # and takes out the three tests that call this, which is every pin in the module. The value
        # pins and the bash discriminator would still run.
        conditions = [str(job.get("if", ""))]
        conditions += [str(step.get("if", "")) for step in job.get("steps", []) or []]
        # Normalised first, so one substring test reads the reference however it is spelled. ci.yml
        # uses the dot form throughout (measured 2026-09-22: zero bracket occurrences, and no job's
        # verdict moves under the normalisation), so this changes nothing on today's file. It is
        # here because a bracket-spelled gate is what a job the arm DECIDES looks like while falling
        # outside `decided`, which makes the wider pin report that the job reads no output of this
        # step -- backwards, and backwards in the direction a reader acts on.
        gated_on_an_output = any(
            "needs.changes.outputs." in _BRACKET_INDEX.sub(r".\2", c) for c in conditions
        )
        # A substring test, so it is blind to an `if:` that is TRUE on merge_group without naming
        # it, such as webconsole's job-level `github.event_name != 'push'`. webconsole is caught
        # today only because its step `if:` lines name the event outright. Known limit, not widened.
        if any("merge_group" in c for c in conditions):
            self_gated.add(name)
            if gated_on_an_output:
                self_gated_and_gated.add(name)
        else:
            names_it_nowhere.add(name)
            if gated_on_an_output:
                decided.add(name)
    return _Partition(decided, names_it_nowhere, self_gated, self_gated_and_gated)


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


def test_the_jobs_that_run_on_a_queue_entry_regardless_are_pinned() -> None:
    """`serverdb=false` above does NOT mean the heavy legs are off in the queue.

    Seven jobs name merge_group in their own `if:` and so ignore what `changes` emits. The arm's
    comment says this; without a check, that comment is free to go stale while reading as current --
    and a reader who believes it would size the queue's cost at a fraction of the truth.

    This reads `_partition_jobs` rather than scanning the jobs itself. It had its own copy of that
    scan until 2026-09-22, which made the same predicate two edits wide: widen one copy and this pin
    and `_NAMES_MERGE_GROUP_NOWHERE` stop describing one partition of the same 13 jobs, with the
    failure landing in the OTHER test and pointing at ci.yml rather than at the detector somebody
    edited.
    """
    found = _partition_jobs(yaml.safe_load(_CI.read_text(encoding="utf-8"))["jobs"]).self_gated
    assert found == _SELF_GATED_ON_QUEUE, (
        "the set of jobs that run on a merge_group entry regardless of the path filters has moved.\n"
        f"  added:   {sorted(found - _SELF_GATED_ON_QUEUE)}\n"
        f"  removed: {sorted(_SELF_GATED_ON_QUEUE - found)}\n"
        "That is a coverage AND cost change on the merge path. If it is deliberate, move this pin "
        "and the arm's comment together."
    )


def test_the_detector_reads_an_output_gate_however_it_is_spelled() -> None:
    """Constructed rows, because ci.yml cannot exercise these: it has no bracket spellings at all.

    Without them the normalisation in `_partition_jobs` is a line nothing measures, and a later edit
    could drop it with every pin below still green. Every row here is a control for something, and a
    row that only agrees with its neighbours is not worth its lines:

    * `unrelated` brackets some OTHER job's outputs, so a detector matching the BRACKET rather than
      the reference fails on it.
    * `expression-index` is a real gate spelled the one way the normalisation cannot read, because
      `matrix.dep` resolves at run time. It is pinned as NOT decided, so a widening that appears to
      cover it -- treating any `needs[...]` as `needs.changes`, say -- goes red here rather than
      quietly reading some other job's outputs as this step's.
    * `on-the-queue` is gated on an output AND names the event, so it is the only row in BOTH
      `self_gated` and `self_gated_and_gated`, and is in neither `decided` nor `names_it_nowhere`.
    * `queue-only` names the event in a STEP `if:` and is gated on nothing. It is the control for
      `self_gated_and_gated`: without it that field's guard can be deleted with every assertion here
      still green, because every other self-gated row is also gated. It also catches a merge_group
      scan narrowed to the job-level `if:`.
    * `step-gated` puts the reference in a STEP `if:`, which is where `test` and `webconsole` -- the
      only two of ci.yml's jobs gated at step level and not job level -- carry theirs.
    * `null-steps` has `steps:` with nothing under it and `bool-if` is `if: true`. Both are legal
      YAML, and each raises TypeError in the scan without one of its `or []` / `str()` guards.
      Measured 2026-09-22, one guard each and not both. `ungated`, a job with no `if:` key at all,
      raises under NEITHER -- it is here because `changes` itself is that shape, not as a guard
      control.
    """
    jobs: dict[str, Any] = {
        "dotted": {"if": "needs.changes.outputs.code == 'true'"},
        "leaf-bracketed": {"if": "needs.changes.outputs['code'] == 'true'"},
        "root-bracketed": {"if": "needs['changes'].outputs.code == 'true'"},
        "fully-bracketed": {"if": "needs['changes']['outputs']['code'] == 'true'"},
        "odd-key-bracketed": {"if": "needs.changes.outputs['3rd'] == 'true'"},
        "step-gated": {"steps": [{"if": "needs.changes.outputs.code == 'true'"}]},
        "unrelated": {"if": "needs.other.outputs['code'] == 'true'"},
        "expression-index": {"if": "needs[matrix.dep].outputs.code == 'true'"},
        "ungated": {},
        "null-steps": {"steps": None},
        "bool-if": {"if": True},
        "on-the-queue": {
            "if": "needs.changes.outputs.code == 'true' || github.event_name == 'merge_group'"
        },
        "queue-only": {"steps": [{"if": "github.event_name == 'merge_group'"}]},
    }
    decided_rows = {
        "dotted",
        "leaf-bracketed",
        "root-bracketed",
        "fully-bracketed",
        "odd-key-bracketed",
        "step-gated",
    }
    read_as_ungated = {"unrelated", "expression-index", "ungated", "null-steps", "bool-if"}
    found = _partition_jobs(jobs)
    assert found.decided == decided_rows, (
        f"the detector read {sorted(found.decided)} as decided by the arm alone. Every spelling of "
        "the same reference must count wherever the `if:` sits, a bracket around anything else must "
        "not, and a job that names the event is decided by its own `if:` rather than by this step"
    )
    assert found.names_it_nowhere == decided_rows | read_as_ungated, (
        f"the wider half of the predicate read {sorted(found.names_it_nowhere)}. It is every job "
        "that does NOT name merge_group, whatever it is gated on, so all five ungated rows belong "
        "to it and neither queue row does"
    )
    assert found.self_gated == {"on-the-queue", "queue-only"}, (
        f"the self-gated half read {sorted(found.self_gated)}; the two queue rows name the event, "
        "one in a job `if:` and one in a step `if:`, and nothing else does"
    )
    assert found.self_gated_and_gated == {"on-the-queue"}, (
        f"the intersection read {sorted(found.self_gated_and_gated)}. `on-the-queue` is the only "
        "row that is both; `queue-only` is self-gated and gated on nothing, so a field that just "
        "copies `self_gated` fails here. This intersection is what the `NOT self_gated` half of the "
        "arm's predicate removes"
    )


def test_the_two_pins_are_a_strict_narrowing() -> None:
    """The relation the pins' own comments claim, checked instead of claimed.

    READS THE THREE LITERALS AND NOTHING ELSE. No workflow is parsed here on purpose: the property is
    about the constants, so it still answers when ci.yml is missing or unparseable.

    Until 2026-09-22 this relation was prose. The wider constant was spelled
    ``_DECIDED_BY_THE_ARM_ALONE | {"changes", "ci-gate"}`` under a comment saying the union "means
    the two pins cannot be edited into equality". A union gives a superset, not a STRICT one: add
    both names to `_DECIDED_BY_THE_ARM_ALONE` and the two come out equal, which was measured true.
    A compensating control resting on a false premise, in a module whose whole job is catching that
    (Secure_Development_Standards SDS-3.6/SDS-3.7).

    Neither assertion implies the other. The first is the containment half, which the second does not
    give: ``wider - narrower`` can equal the two names while `narrower` holds a name `wider` never
    had. The second is where disjointness lives, which the first does not give: the difference of the
    two pins is disjoint from the narrower one by construction, so requiring that difference to EQUAL
    the two-name literal requires those two names to be out of the narrower pin.
    """
    assert _DECIDED_BY_THE_ARM_ALONE < _NAMES_MERGE_GROUP_NOWHERE, (
        "the two PINNED LITERALS in this module are no longer a strict narrowing: the wider one "
        f"does not properly contain the narrower one.\n"
        f"  narrower: {sorted(_DECIDED_BY_THE_ARM_ALONE)}\n"
        f"  wider:    {sorted(_NAMES_MERGE_GROUP_NOWHERE)}\n"
        "Nothing here read ci.yml, so this says the constants are wrong and says nothing about the "
        "workflow. If they came out EQUAL you were most likely editing both pins to follow a "
        "failure below, which is the one move that gets there; go back and read what that failure "
        "actually asked for, and the arm's comment in ci.yml, before editing a literal again."
    )
    extras = _NAMES_MERGE_GROUP_NOWHERE - _DECIDED_BY_THE_ARM_ALONE
    assert extras == _NOWHERE_AND_DECIDED_HERE_BY_NOTHING, (
        "the wider pin is no longer the narrower one plus exactly the two jobs the arm's comment in "
        "ci.yml names.\n"
        f"  unexpected extras: {sorted(extras - _NOWHERE_AND_DECIDED_HERE_BY_NOTHING)}\n"
        f"  missing extras:    {sorted(_NOWHERE_AND_DECIDED_HERE_BY_NOTHING - extras)}\n"
        "A name in the first list is a job the arm decides that the detector did not read as gated, "
        "or a genuinely new kind of job the arm's comment does not cover. A name in the second means "
        "one of those two jobs moved. Either way the ci.yml comment is the thing to re-read, not "
        "this literal."
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

    BOTH HALVES OF THE ARM'S PREDICATE ARE CHECKED HERE, and each needs its own assertion because
    each goes vacuous in its own way. ``decided != names_it_nowhere`` says the GATED-ON-AN-OUTPUT
    half still removes something. ``self_gated_and_gated`` non-empty says the NOT-SELF-GATED half
    does, and it is the only thing that does: measured 2026-09-22, re-spell the output gates of the
    four jobs that also name merge_group so that intersection is empty, and every other check in this
    module stays green while ci.yml's claim that both halves are load-bearing has gone false.

    THE VACUITY CHECKS COME FIRST, and where they sit is the whole of what they are worth. The
    equality one, spelled ``decided < names_it_nowhere``, once sat BEHIND the two pins, where it
    could not fire: the pins had already fixed both sets at their pinned membership, and
    `test_the_two_pins_are_a_strict_narrowing` makes that membership a strict narrowing, so equality
    was excluded before a reader reached it. It was then deleted as an assertion that could not fail
    -- which is true of where it sat and false of the property it asserts. It is back here as ``!=``
    rather than ``<``, because containment is `_partition_jobs`'s to guarantee and inequality is the
    only part that can go wrong. The state that separates sitting here from sitting there, measured
    2026-09-22: give a step in `changes` an `if:` naming merge_group and a step in `ci-gate` an `if:`
    reading ``needs.changes.outputs.code``, then follow every failure message that produces. Every
    pin goes green with the two predicates selecting IDENTICAL jobs. Ahead of the pins, this fires on
    exactly that state, and the strict-narrowing test catches the literals an editor would have
    edited to reach it.
    """
    found = _partition_jobs(yaml.safe_load(_CI.read_text(encoding="utf-8"))["jobs"])
    decided = found.decided
    names_it_nowhere = found.names_it_nowhere

    assert found.self_gated_and_gated, (
        "no job is BOTH gated on an output of the `changes` step and self-gated on merge_group, so "
        "the `NOT self_gated` half of the arm's predicate now removes nothing and ci.yml's claim "
        "that BOTH HALVES ARE LOAD-BEARING is false in that direction.\n"
        f"  gated on an output, and nothing else is: {sorted(decided)}\n"
        "At least these reach it: a self-gated job stopped reading an output of this step; the last "
        "such job was deleted or renamed; every such job stopped naming the event, in which case "
        "they are in the line above; or the detector stopped reading the spelling they use. Re-read "
        "the arm's comment in ci.yml before moving a pin."
    )
    assert found.self_gated_and_gated == _SELF_GATED_AND_GATED, (
        "the set of jobs that are BOTH self-gated and gated on an output has moved.\n"
        f"  added:   {sorted(found.self_gated_and_gated - _SELF_GATED_AND_GATED)}\n"
        f"  removed: {sorted(_SELF_GATED_AND_GATED - found.self_gated_and_gated)}\n"
        "The assertion above passed, so the `NOT self_gated` half still removes SOMETHING -- this "
        "one says it removes the same jobs. A name leaving is a job whose belt-and-braces output "
        "gate was tidied away, which is the edit ci.yml's `code` row calls belt-and-braces and so "
        "invites. Move this pin and that row together."
    )
    assert decided != names_it_nowhere, (
        "the two predicates now select the SAME jobs, so the gated-on-an-output half of the arm's "
        "predicate in ci.yml is doing no work and that arm's comment, which says BOTH HALVES ARE "
        "LOAD-BEARING, is false.\n"
        f"  both sets: {sorted(decided)}\n"
        "This fires AHEAD of the two pins below on purpose. Their messages invite you to move a "
        "pin, and at least two ways of following them reach a state that is green and wrong -- "
        "moving both pins, or dropping the two extra names from the wider one alone. Re-read the "
        "arm's comment in ci.yml and rewrite it, or restore whatever made the two halves differ, "
        "before you touch either pin."
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
