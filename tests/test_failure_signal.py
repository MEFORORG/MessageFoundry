# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin the premises that make `failure-signal.yml`'s `workflow_run` trigger safe.

`.github/zizmor.yml` suppresses `dangerous-triggers` for this file. That suppression is only honest
while the properties it rests on hold, and a comment cannot enforce them. These tests are what make
the suppression a claim rather than a hope, in the same shape as `test_nightly_notice.py`.

WHAT ZIZMOR IS OBJECTING TO, stated so a future reader does not have to guess. `workflow_run` runs
from the DEFAULT BRANCH with a privileged token. The attack it names -- the "pwn request" class -- is
a workflow that then checks out and EXECUTES the triggering pull request's code, which escalates any
fork pull request into a write token. Every precondition for that is absent here, and each one below
is asserted rather than described.

ONE DIFFERENCE FROM nightly-notice.yml, AND IT IS DELIBERATE. That workflow reacts only to
`schedule`, so no pull request can reach it at all. This one MUST react to pull-request runs, because
labelling the pull request is the entire point. So the fork path is open, and the tests below cover
what that costs instead of pretending it is closed: no code from the head is fetched or run, the
token cannot modify code, and the one attacker-influenceable field is gated on an event a fork cannot
produce.

THE FILE ALSO CARRIES A COVERAGE CLAIM NOW, AND THAT IS THE SECOND HALF OF THIS SUITE (BACKLOG
#1402). `workflow_run` watches a list of workflow NAMES. Nothing in GitHub compares that list against
the set of workflows that gate a merge, so a newly required workflow is unwatched from the moment it
arrives and nothing anywhere goes red. The tests below close the loop in the other direction: every
required context must resolve to a workflow that is either watched or named as an exclusion IN THE
WORKFLOW'S OWN HEADER, with a reason.

WHAT "REQUIRED" MEANS HERE IS THE CHECKED-IN CLAIM, NOT THE SERVER, and the difference decides what a
green run is worth. These tests read `.github/required-contexts.txt`. Branch protection lives on the
server, so a context armed there is invisible to this file until somebody transcribes it -- and the
instrument that reconciles the two is `scripts/ci/check_required_contexts_drift.py`, which is
scheduled and needs `gh` auth. **This suite catches an unwatched workflow at the moment the file is
updated; the drift checker is what makes the file trustworthy in the first place.** Neither covers
the other, and reading this one as a server-side guard is the exact misreading that checker's own
header was written to prevent.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterable, Mapping
from pathlib import Path

import pytest

from tests._workflow_contexts import load_workflow, required_contexts, resolve

yaml = pytest.importorskip("yaml")

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
FILE = WORKFLOWS / "failure-signal.yml"

#: One recorded exclusion, as written in `failure-signal.yml`'s header: `# not-watched: <file> -- why`.
#:
#: The header's own FORMAT line spells the placeholder `<workflow file>`, which cannot match this
#: pattern, so documenting the format does not accidentally declare an exclusion.
#:
#: A BROKEN PARSER FAILS IN THE SAFE DIRECTION. If this stops matching, the exclusion set comes back
#: empty and the coverage test below goes RED over a workflow that really is excluded. It cannot go
#: quietly green, which is the failure mode a record-parsing test has to rule out.
_NOT_WATCHED = re.compile(
    r"^#\s*not-watched:\s*(?P<file>[A-Za-z0-9_.-]+\.yml)\s+--\s+(?P<reason>\S.*?)\s*$", re.M
)


def _doc() -> dict:
    return yaml.safe_load(FILE.read_text(encoding="utf-8"))


def _on(doc: dict) -> dict:
    # PyYAML parses a bare `on:` key as the BOOLEAN True, not the string "on". Reading doc["on"]
    # returns None and every assertion below would pass vacuously.
    return doc[True]


def _steps() -> list[dict]:
    steps = _doc()["jobs"]["signal"]["steps"]
    # Positive control for every assertion built on this list. An empty or renamed job would make
    # "no offenders were found" and "nothing was looked at" render identically.
    assert steps, "the signal job has no steps to inspect"
    return steps


def _run_blocks() -> list[str]:
    blocks = [s["run"] for s in _steps() if "run" in s]
    assert blocks, "the signal job has no `run:` step to inspect"
    return blocks


def _step(step_id: str) -> dict:
    """One named step, looked up by `id:` rather than by position.

    Positional indexing would still fail if the steps were reordered, but it would fail somewhere
    unrelated to the reorder. Naming the step makes the message say what actually moved.
    """
    matches = [s for s in _steps() if s.get("id") == step_id]
    assert len(matches) == 1, f"expected exactly one step with id {step_id!r}, found {len(matches)}"
    return matches[0]


def _run_block(step_id: str) -> str:
    step = _step(step_id)
    assert "run" in step, f"step {step_id!r} has no `run:` body to inspect"
    return str(step["run"])


# The four readers below are memoised. Each re-reads files that do not change during a run, and the
# coverage tests call them repeatedly; uncached, this module cost 10.5s instead of 0.4s. Treat every
# return as READ-ONLY -- the one test that varies them copies first.
@functools.cache
def _watched_names() -> frozenset[str]:
    """The workflow NAMES this file's `workflow_run` trigger observes."""
    watched = frozenset(_on(_doc())["workflow_run"]["workflows"])
    assert watched, "the watch list is empty, so every assertion built on it would pass vacuously"
    return watched


@functools.cache
def _workflow_names() -> dict[str, str]:
    """Every workflow file here -> the `name:` it reports under. Unnamed files are omitted.

    Parsed through the shared `load_workflow`, which ASSERTS the file parses to a mapping and names
    it if not. A local `yaml.safe_load(...) or {}` would instead drop an unparseable workflow out of
    this map silently -- and this map is the input every coverage assertion below rests on.
    """
    names: dict[str, str] = {}
    for path in WORKFLOWS.glob("*.yml"):
        name = load_workflow(path.name).get("name")
        if isinstance(name, str):
            names[path.name] = name
    return names


def _watched_files(names: Mapping[str, str], watched: Iterable[str]) -> set[str]:
    """Workflow FILES whose `name:` is in `watched`.

    `workflow_run` matches on the name, so every question here has to cross that indirection. Spelling
    it out at each site is how three slightly different spellings of one rule appear.
    """
    watched_set = set(watched)
    return {file for file, name in names.items() if name in watched_set}


@functools.cache
def _declared_exclusions() -> dict[str, str]:
    """Workflow files this file says it deliberately does not watch -> the recorded reason.

    Read from the workflow's OWN header rather than restated here. Two copies of one list are free to
    drift, and a test that carries the second copy passes while the record it is meant to enforce is
    wrong -- which is the defect BACKLOG #1335 was.
    """
    text = FILE.read_text(encoding="utf-8")
    return {m.group("file"): m.group("reason") for m in _NOT_WATCHED.finditer(text)}


@functools.cache
def _required_context_workflows() -> dict[str, str]:
    """Every required status-check context -> the workflow FILE that can report it."""
    mapping: dict[str, str] = {}
    for context in required_contexts():
        where = resolve(context)
        # The required-but-absent trap (docs/CI.md): a required context nothing can report blocks
        # every pull request forever. Never skip it -- an unresolvable context is also a context this
        # coverage check would otherwise pass over in silence.
        assert where is not None, (
            f"required context {context!r} resolves to no workflow in .github/workflows. Either the "
            "job was renamed or .github/required-contexts.txt is stale; both wedge every pull request."
        )
        mapping[context] = where[0]
    assert mapping, ".github/required-contexts.txt yielded no contexts, so nothing below is checked"
    return mapping


def _unwatched(
    context_workflow: Mapping[str, str],
    workflow_name: Mapping[str, str],
    watched: Iterable[str],
    excluded: Iterable[str],
) -> dict[str, str]:
    """Required contexts whose workflow is neither watched nor excluded on the record.

    PURE OVER ITS ARGUMENTS ON PURPOSE. The anti-vacuity arm below drives it with mutated copies of
    the real inputs, so the guard can be shown to produce a DIFFERENT answer without any test editing
    `failure-signal.yml` or `required-contexts.txt` on disk.
    """
    watched_set = set(watched)
    excluded_set = set(excluded)
    return {
        context: workflow
        for context, workflow in context_workflow.items()
        if workflow not in excluded_set and workflow_name.get(workflow) not in watched_set
    }


def test_it_pulls_in_no_third_party_actions() -> None:
    """Nothing from the triggering ref is fetched, let alone executed.

    This is the strongest of the properties: with no `uses:` at all there is no checkout, no
    third-party bundle, and therefore no path from a fork's branch to code running under the
    default branch's token.
    """
    assert [s for s in _steps() if "uses" in s] == [], (
        "failure-signal.yml gained a `uses:`. The zizmor suppression for dangerous-triggers "
        "rests on this workflow running no third-party code and checking nothing out. Either "
        "remove it, or re-justify the suppression in .github/zizmor.yml."
    )


def test_it_is_least_privilege_and_cannot_modify_code() -> None:
    """The token can label a pull request or comment on an issue. It cannot push, tag or write code."""
    doc = _doc()
    assert doc["permissions"] == {"contents": "read"}, (
        f"top-level permissions are {doc.get('permissions')!r}. Keep the file default read-only so a "
        "job added here cannot inherit write scope by accident."
    )
    job_perms = doc["jobs"]["signal"].get("permissions")
    assert job_perms == {"pull-requests": "write", "issues": "write"}, (
        f"the signal job's permissions are {job_perms!r}. It needs exactly these two writes. Anything "
        "that can modify code -- `contents: write`, `packages: write`, `id-token: write` -- turns the "
        "open fork path into the escalation the zizmor suppression says is closed."
    )


def test_every_event_value_reaches_a_script_through_env() -> None:
    """A branch name is chosen by whoever opened the branch.

    Interpolating `${{ github.event.* }}` into a `run:` body would splice attacker-controlled text
    into a shell script. Every such value must arrive as an environment variable instead.
    """
    offenders = [b for b in _run_blocks() if "${{" in b]
    assert offenders == [], (
        "A run block interpolates a GitHub expression directly. Hoist it to the step's `env:` "
        "and reference it as a shell variable."
    )
    # The positive half of the same claim. Absence of `${{` also holds for a workflow that reads no
    # event value at all, so on its own it cannot tell "hoisted to env" from "gone". Assert the
    # hoist itself: the resolve step is where the attacker-influenceable fields arrive.
    hoisted = [v for v in _step("resolve").get("env", {}).values() if "github.event" in str(v)]
    assert hoisted, (
        "the resolve step declares no `github.event` value in its `env:`. Either the values moved "
        "into the script body -- which the check above would then have to catch -- or this test is "
        "now watching the wrong step."
    )


def test_the_merge_queue_parse_is_gated_on_an_event_a_fork_cannot_produce() -> None:
    """`head_branch` is the one attacker-influenceable field this workflow reads.

    It is parsed only to recover the pull-request number from a merge-queue ref, and only when the
    triggering run was a `merge_group`. A fork pull request cannot produce that event, so a branch
    named to look like a queue ref never reaches the parse.
    """
    resolve = _run_block("resolve")
    assert "HEAD_BRANCH" in resolve, (
        "the resolve step no longer reads HEAD_BRANCH. If the merge-queue parse moved, move this "
        "assertion with it; the suppression in .github/zizmor.yml names this test by name."
    )
    guard = re.search(r'if \[ -z "\$pr" \] && \[ "\$RUN_EVENT" = "merge_group" \]', resolve)
    assert guard is not None, (
        "The merge-queue branch parse is no longer gated on RUN_EVENT = merge_group. Ungated, a "
        "crafted branch name could steer the label onto an unrelated pull request."
    )


def test_every_watched_workflow_exists() -> None:
    """A watched name that no workflow answers to is dead config that reads as coverage.

    `workflow_run` matches on a workflow's `name:`, not its filename, so renaming one silently
    retires the watch -- no error, no run, permanent silence. That is the failure this signal exists
    to end, one level up.

    It asserts EXISTENCE only. An earlier name for this test also claimed each watched workflow
    produces a required context, and that is false: `.github/required-contexts.txt` lists CodeQL
    under "DELIBERATELY NOT REQUIRED", because its SARIF upload needs a scope fork-PR tokens lack.
    Watching a non-required workflow is intentional -- a red CodeQL run is still worth attributing.
    """
    watched = _watched_names()
    present = set(_workflow_names().values())
    # Positive control: the scan must actually be reading workflows, or `missing` below is just the
    # watch list back again and the failure message would blame the wrong file.
    assert len(present) > 5, f"the workflow scan found only {len(present)} named files"
    missing = watched - present
    assert missing == set(), (
        f"failure-signal.yml watches names no workflow answers to: {missing}. "
        f"Names present: {sorted(present)}"
    )


def test_it_only_acts_on_a_real_failure() -> None:
    """A cancelled run is not a red.

    Branch protection gates on the latest head, so a cancelled predecessor says nothing about the
    current one. Labelling on `cancelled` would train readers to ignore the label.
    """
    condition = _doc()["jobs"]["signal"]["if"]
    assert "conclusion == 'failure'" in condition
    assert "cancelled" not in condition


# ---------------------------------------------------------------------------------------------------
# COVERAGE IN THE OTHER DIRECTION (BACKLOG #1402). `test_every_watched_workflow_exists` asks whether
# each watched name is real. These ask the reverse -- whether each workflow that GATES A MERGE is
# watched -- which is the direction nothing checked, and the direction a newly armed context breaks.
# ---------------------------------------------------------------------------------------------------


def test_every_required_workflow_is_watched_or_excluded_on_the_record() -> None:
    """A required workflow nobody watches goes red and signals nobody, which is the whole defect.

    Silence is not self-describing: a required workflow missing from the watch list looks exactly like
    one somebody decided not to watch. So the only difference this test can read is whether a reason
    was written down, and it requires one.
    """
    uncovered = _unwatched(
        _required_context_workflows(), _workflow_names(), _watched_names(), _declared_exclusions()
    )
    assert uncovered == {}, (
        f"these required contexts report from workflows failure-signal.yml neither watches nor "
        f"excludes: {uncovered}. Add the workflow's `name:` to the `workflows:` list, or add a "
        f"`# not-watched: <file> -- <reason>` line to that file's header saying why a red there needs "
        f"no attribution. If you believe a reason IS written, check that the line matches the format; "
        f"an unparsed exclusion is not an exclusion (BACKLOG #1402)."
    )


def test_a_recorded_exclusion_names_a_real_workflow_that_really_is_required() -> None:
    """An exclusion outlives what it excused, and then it reads as considered rather than stale."""
    exclusions = _declared_exclusions()
    known = set(_workflow_names())
    required_workflows = set(_required_context_workflows().values())
    for workflow, reason in exclusions.items():
        assert workflow in known, (
            f"failure-signal.yml excludes {workflow!r}, which is not a named workflow file here. "
            "Either it was renamed or deleted; drop the exclusion with it."
        )
        assert workflow in required_workflows, (
            f"failure-signal.yml excludes {workflow!r}, but no required context reports from it any "
            "more, so the exclusion excuses nothing. Delete it rather than leaving a stale record."
        )
        assert len(reason) > 20, (
            f"the exclusion for {workflow!r} gives the reason {reason!r}. A reason short enough to be "
            "a label is not a reason; say what a reader should do with a red there instead."
        )


def test_nothing_is_both_watched_and_excluded() -> None:
    """The two records must not contradict each other. One of them would then be wrong and unread."""
    both = set(_declared_exclusions()) & _watched_files(_workflow_names(), _watched_names())
    assert both == set(), (
        f"{sorted(both)} are watched AND recorded as deliberately not watched. Whichever is stale, a "
        "reader meeting one of them draws the wrong conclusion."
    )


def test_the_coverage_guard_can_produce_a_different_answer() -> None:
    """THE ANTI-VACUITY ARM, and the load-bearing half of this pair.

    The hole this item was scored on closed by accident: the one unwatched required workflow -- the
    review gate -- was RETIRED on 2026-09-04, so the guard above passes for a reason that has nothing
    to do with the guard. A check whose only evidence is a green run over healthy inputs cannot tell
    "nothing is wrong" from "this asks nothing". So drive it with MUTATED COPIES of the real inputs
    and show it says something different. Copies, never the files: a test that edits a workflow in
    place breaks every sibling test running beside it.
    """
    contexts = _required_context_workflows()
    names = _workflow_names()
    watched = _watched_names()
    excluded = _declared_exclusions()

    # The untouched baseline. Without it the arms below prove only that the function returns
    # something non-empty for some input, which any constant would satisfy.
    assert _unwatched(contexts, names, watched, excluded) == {}

    # 1. REMOVE A WATCHED NAME. Derived from the data rather than spelled out, so this arm keeps
    #    testing the mechanism after the watch list changes.
    covering = sorted(_watched_files(names, watched) & set(contexts.values()))
    assert covering, "no required workflow is watched at all -- removing a watch cannot change this"
    dropped = names[covering[0]]
    assert _unwatched(contexts, names, watched - {dropped}, excluded) != {}, (
        f"dropping {dropped!r} from the watch list left every required context still covered, so the "
        "guard is not reading the watch list it claims to read"
    )

    # 2. ARM A NEW REQUIRED CONTEXT NOBODY WATCHES. This is the live case: the next context added to
    #    branch protection arrives unwatched, and this is what must go red for it.
    invented = dict(contexts) | {"a context armed after this test was written": "invented.yml"}
    assert _unwatched(invented, names, watched, excluded) != {}, (
        "a required context on a workflow nobody watches read as covered"
    )

    # 3. AN EXCLUSION THAT IS NOT WRITTEN DOWN IS NOT AN EXCLUSION -- and one that is, is honoured.
    #    Both directions, or the exclusion set could be ignored entirely and arm 2 would not notice.
    lone = {"a context on an unwatched workflow": "invented.yml"}
    assert _unwatched(lone, names, watched, ()) != {}
    assert _unwatched(lone, names, watched, {"invented.yml"}) == {}


# ---------------------------------------------------------------------------------------------------
# ATTRIBUTING A MERGE-QUEUE EJECTION (BACKLOG #1403).
# ---------------------------------------------------------------------------------------------------


def test_an_ejection_says_which_run_caused_it() -> None:
    """A bare `ci-red` label on an ejected pull request points at nothing.

    The pull request's own head is green, and the queue revalidates against a different job set, so
    the ejecting job may be one the pull request never ran. The run name and URL are the only way in.
    """
    body = _run_block("attribute-ejection")
    assert "gh pr comment" in body, (
        "the attribution step no longer comments on the pull request, so an ejection is again a bare "
        "label with nothing behind it"
    )
    assert "$RUN_NAME" in body and "$RUN_URL" in body, (
        "the attribution comment names neither the run nor its URL, which is the only content that "
        "makes it worth posting"
    )


def test_the_ejection_comment_is_scoped_to_the_merge_queue() -> None:
    """A comment on every red pull request is noise a reader learns to skip.

    Scoping it to `merge_group` is what keeps the comment worth reading: on an ordinary red the author
    can find the run from the checks tab, so only the ejection case has nothing else to go on.
    """
    condition = str(_step("attribute-ejection")["if"])
    assert "merge_group" in condition, (
        "the attribution step is no longer gated on the merge-queue event. Ungated it comments on "
        "every red pull request, which trains readers to ignore the comment."
    )
    assert "steps.resolve.outputs.pr" in condition, (
        "the attribution step no longer requires a resolved pull request, so it would try to comment "
        "on nothing when a queue run has no number to recover"
    )


def test_the_ejection_step_reads_its_run_values_from_the_environment() -> None:
    """Same rule as the resolve step, asserted separately because it is a separate step.

    The blanket scan above catches `${{` anywhere in a `run:` body. This adds the positive half for
    THIS step: the values must actually arrive through `env:`, or the step could satisfy the blanket
    scan by reading nothing at all.
    """
    env = _step("attribute-ejection").get("env", {})
    from_event = {k for k, v in env.items() if "github.event" in str(v)}
    assert from_event >= {"RUN_NAME", "RUN_URL"}, (
        f"the attribution step's env carries {sorted(from_event)}. The run name and URL must reach "
        "the script through the environment, never spliced into the body."
    )
