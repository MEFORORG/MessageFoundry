# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A concurrency group must not put two different pull requests in one group (BACKLOG #1533).

THE DEFECT THIS HOLDS. `cla.yml` keyed its group on ``github.ref`` under ``pull_request_target``.
For ``pull_request`` that context is ``refs/pull/<n>/merge`` and so is per-pull-request; for
``pull_request_target`` it is ``refs/heads/<DEFAULT branch>``. Every open pull request therefore
resolved to one group, ``cla-refs/heads/main``, and with that arm cancellable each new run cancelled
the in-flight ``cla`` run of an unrelated one.

DEFAULT BRANCH, NOT BASE BRANCH. GitHub's own pages disagree -- the variables page says the ref comes
from the base branch, the events page says the default branch -- and on a main-based pull request the
two readings are the same string, so main-based measurements cannot tell them apart. A STACKED pull
request can: measured 2026-09-11, a pull request based on a feature branch had its ``cla`` run
cancelled one second after a ``main``-based pull request's run was created, which is impossible if
the keys were per-base. It does not change the fix -- a pull request number separates them either
way -- but it is why ``github.base_ref`` is in ``_SHARED_CONTEXTS`` below: a per-BASE key looks
per-pull-request and is not. ``cla`` is a REQUIRED context, and a cancelled run
carries no steps and no logs -- it renders in the fail column with nothing to read, which is why it
went unattributed.

WHY A TEST RATHER THAN A CAREFUL COMMENT. The two spellings differ by one word, the wrong one looks
like the five sibling workflows that are correct, and the failure is INVISIBLE in the file: a group
key that silently collapses produces no error, no warning and no log line. It is only observable in
the cancellation record of runs on OTHER branches, which nobody reads while reviewing this file.

THE INVARIANT. On an event that fires once per pull request but whose ``github.ref`` is not
per-pull-request, the concurrency group must not key on any context that is SHARED across pull
requests. The key must carry something that separates them (the payload number) or something unique
per run (``github.run_id``).

``push``, ``schedule`` and ``workflow_dispatch`` are deliberately outside ``COLLAPSING_EVENTS``, and
that exclusion is the reason this test does not flag ``ci.yml``: they do not fire per pull request,
so a ``github.ref`` key there groups a branch or a scheduled line with itself, which is intended.
``merge_group`` is outside it because its ref is
``refs/heads/gh-readonly-queue/<base>/pr-<n>-<sha>``, already unique per queue entry.

``workflow_run`` IS INSIDE IT, and an earlier draft of this file had that wrong. The draft said
workflow_run "does not fire per pull request", which ``failure-signal.yml`` refutes in this very
repository: it runs ``on: workflow_run`` over CI, Security, CodeQL and backlog-hygiene, each of which
runs on ``pull_request``, so it fires once per pull request run -- and a workflow_run event's
``github.ref`` is the default branch, shared by every pull request exactly as
``pull_request_target``'s is. ``check_suite`` is included for the same reason. Neither is a current
offender (``failure-signal.yml`` keys on ``github.event.workflow_run.id`` and ``unread-signal.yml``
on the head ref), so including them costs nothing today and covers the next file.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from tests._workflow_contexts import WORKFLOWS, load_workflow

# PyYAML resolves YAML 1.1 booleans, so a workflow's bare `on:` key parses as the BOOLEAN True and
# `doc["on"]` raises KeyError. Measured against cla.yml: the top-level keys come back as
# `['name', True, 'concurrency', 'permissions', 'jobs']`. Naming it once beats a bare `True`
# subscript that reads like a typo at every call site.
_ON = True

# Events that fire once per pull request AND whose github.ref does not distinguish one pull request
# from another. See the module docstring for why each is in or out; workflow_run and check_suite are
# in because a workflow_run event's ref is the DEFAULT BRANCH while it fires per pull request run.
COLLAPSING_EVENTS = ("pull_request_target", "issue_comment", "workflow_run", "check_suite")

# Contexts that hold the SAME value for every open pull request, so keying a group on one of them on
# a collapsing event puts every pull request in one group.
#
# `github.ref` ALONE IS NOT ENOUGH, and an earlier draft of this file checked only that. Under
# `pull_request_target` github.ref IS the base ref, so `github.ref_name` is its short form and
# `github.base_ref` and `github.event.pull_request.base.ref` are the same branch by another spelling
# -- every one of them expands to "main" for every pull request opened against main. That draft
# shipped a parametrized row asserting `github.ref_name` was SAFE on pull_request_target, which
# affirmatively blessed the substitution that reinstates the defect. `github.workflow` and
# `github.repository` are constants, which is the same failure with no branch in it at all.
#
# `github.event.pull_request.head.ref` is deliberately NOT here: a head ref is per-pull-request, and
# it is what unread-signal.yml keys on. The `.base.ref` pattern must not match it, which is why that
# entry is anchored on `base` rather than matching any trailing `.ref`.
_SHARED_CONTEXTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github.ref", re.compile(r"(?<![.\w])github\.ref(?![_\w])")),
    ("github.ref_name", re.compile(r"(?<![.\w])github\.ref_name(?![\w])")),
    ("github.base_ref", re.compile(r"(?<![.\w])github\.base_ref(?![\w])")),
    ("github.event.pull_request.base.ref", re.compile(r"pull_request\.base\.ref(?![\w])")),
    ("github.workflow", re.compile(r"(?<![.\w])github\.workflow(?![_\w])")),
    ("github.repository", re.compile(r"(?<![.\w])github\.repository(?![_\w])")),
)

# `github.event_name == 'X' && <then> || <otherwise>` -- the shape every conditional key here uses.
_ARMED = re.compile(
    r"github\.event_name\s*==\s*'(?P<event>[a-z_]+)'\s*&&\s*(?P<then>.+?)\s*\|\|\s*(?P<otherwise>.+)$",
    re.DOTALL,
)

_EXPR = re.compile(r"\$\{\{(?P<body>.*?)\}\}", re.DOTALL)

# A body this module does not model. `_ARMED`'s `then` is lazy and stops at the FIRST `||`, so a
# parenthesised inner conditional splits in the wrong place and both arm checks clear -- a silent
# WRONG match rather than a non-match, which the fail-closed branch below never sees. Rejecting these
# shapes outright is what makes "fails closed" true for a mis-parse and not only for a non-parse.
_UNMODELLED = re.compile(r"[()]|!=")


def _shared_contexts_in(text: str) -> list[str]:
    return [name for name, pat in _SHARED_CONTEXTS if pat.search(text)]


def _on_events(doc: Mapping[Any, Any]) -> list[str]:
    """The event names a workflow declares. Handles `on: pull_request` (flow) and the block form.

    dependabot-auto-merge.yml uses the flow spelling, so a mapping-only reader silently reports that
    file as declaring NO events -- which would make every assertion about it vacuously true.
    """
    on = doc.get(_ON, doc.get("on"))
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(e) for e in on]
    if isinstance(on, dict):
        return [str(k) for k in on]
    return []


def shared_context_reaches(expression: str, event: str) -> str | None:
    """The shared context that can be ``expression``'s value on ``event``, or None if none can.

    Conservative in three separate ways, because each corresponds to a way a guard goes quiet:
    an unconditional key reaches every event; a body naming a shared context in a shape this module
    does not model is reported rather than waved through; and an unrecognised conditional counts as
    reaching every event.
    """
    for match in _EXPR.finditer(expression):
        body = match.group("body")
        found = _shared_contexts_in(body)
        if not found:
            continue
        if _UNMODELLED.search(body):
            return found[0]  # a shape we cannot split correctly, and it names a shared context
        armed = _ARMED.search(body.strip())
        if not armed:
            return found[0]  # unconditional, or a conditional shape we do not model
        then, otherwise = armed.group("then"), armed.group("otherwise")
        gated = armed.group("event")
        if event == gated and (hit := _shared_contexts_in(then)):
            return hit[0]
        if event != gated and (hit := _shared_contexts_in(otherwise)):
            return hit[0]
    return None


def collapses_across_pull_requests(group: str, event: str) -> bool:
    """Does ``group`` put two DIFFERENT pull requests in one concurrency group on ``event``?

    THE PREDICATE, and deliberately the only one. Reaching a shared context is not by itself the
    defect: ``github.ref`` is reached on ``pull_request`` in five workflows here and that is CORRECT,
    because there it expands to ``refs/pull/<n>/merge``. The defect needs both halves -- a shared-
    context key AND an event on which that context does not separate pull requests. Writing it once
    means the invariant below and the paired-arms rows cannot drift into two definitions of the bug.
    """
    return event in COLLAPSING_EVENTS and shared_context_reaches(group, event) is not None


def _concurrency_groups(doc: Mapping[Any, Any]) -> list[tuple[str, str]]:
    """Every concurrency group in a workflow as (where, group) -- workflow level AND job level.

    JOB LEVEL IS NOT OPTIONAL. ``jobs.<id>.concurrency`` has the same grouping and cancellation
    semantics, and cla.yml has exactly one job -- so the identical defect written one indentation
    level down cancels the identical required check while a workflow-level-only reader returns None
    and passes. No workflow here declares one today, which is exactly when to cover it.
    """
    out: list[tuple[str, str]] = []
    block = doc.get("concurrency")
    if isinstance(block, str):
        out.append(("workflow", block))
    elif isinstance(block, dict) and block.get("group") is not None:
        out.append(("workflow", str(block["group"])))
    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            jb = job.get("concurrency")
            if isinstance(jb, str):
                out.append((f"job {job_id}", jb))
            elif isinstance(jb, dict) and jb.get("group") is not None:
                out.append((f"job {job_id}", str(jb["group"])))
    return out


def _workflow_files() -> list[Path]:
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def test_no_workflow_groups_two_pull_requests_under_one_concurrency_key() -> None:
    """The invariant, over every workflow file rather than the one that taught it."""
    offenders: list[str] = []
    for path in _workflow_files():
        doc = load_workflow(path.name)
        events = _on_events(doc)
        for where, group in _concurrency_groups(doc):
            for event in events:
                if not collapses_across_pull_requests(group, event):
                    continue
                shared = shared_context_reaches(group, event)
                offenders.append(
                    f"{path.name} ({where}): group {group!r} can key on {shared} for the "
                    f"{event!r} event, where that context does not separate pull requests -- every "
                    f"open pull request lands in one group. Key on "
                    f"github.event.pull_request.number or github.run_id."
                )
    assert not offenders, "concurrency keys that collapse across pull requests:\n  " + "\n  ".join(
        offenders
    )


def test_the_scan_is_aimed_at_a_population_that_contains_the_shape_it_checks() -> None:
    """NOT VACUOUS: the files exist, parse, and at least one declares a collapsing event.

    A pass above means nothing if the glob found no workflows, if none declared
    ``pull_request_target``, or if no workflow carries a concurrency block at all. Each of those
    would make the loop body unreachable and the assertion trivially true.
    """
    files = _workflow_files()
    assert len(files) >= 20, f"only {len(files)} workflow files found; the glob is not aimed"

    with_concurrency = [p.name for p in files if _concurrency_groups(load_workflow(p.name))]
    declaring = [
        p.name
        for p in files
        if any(e in COLLAPSING_EVENTS for e in _on_events(load_workflow(p.name)))
    ]
    assert len(with_concurrency) >= 15, with_concurrency
    assert "cla.yml" in declaring, declaring
    assert len(declaring) >= 2, f"expected more than one file on a collapsing event: {declaring}"

    # The flow-style `on:` spelling parses. dependabot-auto-merge.yml writes `on: pull_request`, and a
    # reader that only understood the block form would report it as declaring no events.
    assert _on_events(load_workflow("dependabot-auto-merge.yml")) == ["pull_request"]


def test_the_cla_group_puts_the_number_on_the_pull_request_arm_and_run_id_on_the_others() -> None:
    """cla.yml specifically, asserted ON THE ARMS rather than on substring presence.

    AN EARLIER DRAFT OF THIS TEST CHECKED ONLY THAT BOTH TOKENS APPEARED SOMEWHERE IN THE STRING,
    which cannot see WHICH arm either sits in. Two mutations passed it green, and both are worse than
    the defect this file exists to stop:

      * arms swapped -- `... && github.run_id || github.event.pull_request.number`. The re-push
        saving is gone, and on issue_comment and merge_group the fallback names a number neither
        payload carries, so both collapse onto the single key `cla-`.
      * a third arm added for the signing path -- `... || github.event_name == 'issue_comment' &&
        github.event.issue.number || github.run_id`. run_id is still in the string, so a substring
        check passes, while issue_comment moves onto a shared per-pull-request group where the
        documented pending-cancel discards a run recording someone's signature.

    So the fallback arm is asserted to be EXACTLY `github.run_id`, which is the only spelling that
    keeps issue_comment and merge_group each in a group of one.
    """
    block = load_workflow("cla.yml")["concurrency"]
    group = str(block["group"])

    bodies = [m.group("body") for m in _EXPR.finditer(group)]
    assert len(bodies) == 1, f"expected one expression in the cla group, got {bodies}"
    armed = _ARMED.search(bodies[0].strip())
    assert armed is not None, (
        f"the cla group is no longer the modelled conditional shape: {group!r}"
    )

    assert armed.group("event") == "pull_request_target", armed.group("event")
    assert "github.event.pull_request.number" in armed.group("then"), armed.group("then")
    # EXACTLY run_id, not merely containing it: a third arm hides inside a containment check.
    assert armed.group("otherwise").strip() == "github.run_id", armed.group("otherwise")
    assert not _shared_contexts_in(group), _shared_contexts_in(group)

    # Still cancellable on the pull-request arm, so a rapid re-push supersedes its own earlier run.
    assert block["cancel-in-progress"] == "${{ github.event_name == 'pull_request_target' }}"


@pytest.mark.parametrize(
    ("group", "event", "expected"),
    [
        # PLANTED: the exact defect, as cla.yml carried it. Must be seen.
        (
            "cla-${{ github.event_name == 'pull_request_target' && github.ref || github.run_id }}",
            "pull_request_target",
            True,
        ),
        # The shipped fix. Must NOT be seen.
        (
            "cla-${{ github.event_name == 'pull_request_target' && "
            "github.event.pull_request.number || github.run_id }}",
            "pull_request_target",
            False,
        ),
        # ASYMMETRY, and the reason this checker is event-aware rather than a grep. The identical
        # expression keyed on `pull_request` is CORRECT -- that is security.yml, codeql.yml,
        # net-helper.yml, zizmor.yml and quality-advisory.yml -- so a checker that reddened on it
        # would condemn five working workflows and teach nothing about the sixth. github.ref IS
        # reached here; what makes it safe is the EVENT, which is the whole point.
        (
            "security-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}",
            "pull_request",
            False,
        ),
        # The same five-sibling expression on a collapsing event: still safe, because the condition
        # gates github.ref to `pull_request` and this is not it. This row and the one above are the
        # pair that separates "reads the trigger" from "greps for a string".
        (
            "security-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}",
            "pull_request_target",
            False,
        ),
        # The FALLBACK arm reaching a shared context is the same defect wearing the other sleeve.
        (
            "x-${{ github.event_name == 'pull_request' && github.run_id || github.ref }}",
            "pull_request_target",
            True,
        ),
        (
            "x-${{ github.event_name == 'pull_request' && github.run_id || github.ref }}",
            "pull_request",
            False,
        ),
        # Unconditional: a defect on a collapsing event, fine on the two backlog-hygiene declares.
        ("backlog-hygiene-${{ github.ref }}", "pull_request_target", True),
        ("backlog-hygiene-${{ github.ref }}", "pull_request", False),
        ("backlog-hygiene-${{ github.ref }}", "merge_group", False),
        # EVERY OTHER SPELLING OF THE BASE BRANCH. Under pull_request_target github.ref IS the base
        # ref, so each of these is "main" for every pull request opened against main -- the measured
        # defect, reached by a substitution a reader might think this test had cleared.
        ("x-${{ github.ref_name }}", "pull_request_target", True),
        ("x-${{ github.ref_name }}", "pull_request", False),
        (
            "cla-${{ github.event_name == 'pull_request_target' && github.base_ref "
            "|| github.run_id }}",
            "pull_request_target",
            True,
        ),
        (
            "cla-${{ github.event_name == 'pull_request_target' && "
            "github.event.pull_request.base.ref || github.run_id }}",
            "pull_request_target",
            True,
        ),
        # Constants: the same failure with no branch in it at all.
        ("x-${{ github.workflow }}", "issue_comment", True),
        ("x-${{ github.repository }}", "pull_request_target", True),
        # workflow_run is a collapsing event: its ref is the default branch and failure-signal.yml
        # fires it once per pull request run. The real failure-signal key is not this.
        ("failure-signal-${{ github.ref }}", "workflow_run", True),
        # Near-misses that must NOT match. A head ref IS per-pull-request and is unread-signal.yml's
        # real key; a naive `.ref` or `base` pattern hits it.
        ("unread-signal-${{ github.event.pull_request.head.ref }}", "pull_request_target", False),
        ("ingress-rate-probe", "pull_request_target", False),
    ],
)
def test_the_checker_separates_the_defect_from_the_five_correct_siblings(
    group: str, event: str, expected: bool
) -> None:
    """PAIRED ARMS. Mutating toward the defect must redden; mutating toward a correct sibling must not.

    Disjoint verdicts on the same expression under two different events is the discriminating case:
    it shows the checker reads the TRIGGER, which is the whole content of the bug. A checker that
    only matched the string ``github.ref`` would return True for both rows of that pair.
    """
    assert collapses_across_pull_requests(group, event) is expected


def test_an_unmodelled_expression_naming_a_shared_context_fails_closed() -> None:
    """A shape the parser cannot SPLIT CORRECTLY must be reported, not waved through.

    "Fails closed" has to cover a WRONG match, not only a non-match, and an earlier draft only tested
    the non-match. `_ARMED`'s `then` is lazy and stops at the first `||`, so a parenthesised inner
    conditional splits in the wrong place, both arm checks clear, and the verdict comes back False on
    an expression that is the defect. The example below is the live one: on a FORK pull request the
    inner comparison is false and the key becomes github.ref, which is the measured defect narrowed
    to exactly the population a CLA gate exists to police.
    """
    forky = (
        "cla-${{ github.event_name == 'pull_request_target' && "
        "(github.event.pull_request.head.repo.full_name == github.repository && github.run_id "
        "|| github.ref) || github.run_id }}"
    )
    assert collapses_across_pull_requests(forky, "pull_request_target") is True

    # A non-match must also fail closed, which is the case the earlier draft did cover.
    exotic = "x-${{ fromJSON(github.event_name == 'a' && '1' || '2') && github.ref }}"
    assert collapses_across_pull_requests(exotic, "pull_request_target") is True

    # ... and it stays silent when no shared context is named, so "fails closed" is not "always red",
    # which would be a guard that cannot pass and so cannot discriminate.
    assert collapses_across_pull_requests(
        "x-${{ fromJSON(something) }}", "pull_request_target"
    ) is (False)
    # unread-signal.yml's real key is an unmodelled `||` chain naming no shared context. It must pass,
    # or the fail-closed rule would redden a correct workflow and be deleted.
    real = "unread-signal-${{ github.event.workflow_run.head_branch || github.event.pull_request.head.ref || inputs.pr }}"
    assert collapses_across_pull_requests(real, "pull_request_target") is False
    assert collapses_across_pull_requests(real, "workflow_run") is False


def test_a_job_level_concurrency_block_is_scanned_too() -> None:
    """The defect written one indentation level down must still be seen.

    No workflow here declares a job-level block today, so this is the only thing standing between
    that and a silent pass. `_concurrency_groups` is exercised on a synthetic document rather than a
    real file for exactly that reason.
    """
    doc = {
        "jobs": {
            "cla": {"concurrency": {"group": "cla-${{ github.ref }}", "cancel-in-progress": True}}
        }
    }
    found = _concurrency_groups(doc)
    assert found == [("job cla", "cla-${{ github.ref }}")], found
    assert collapses_across_pull_requests(found[0][1], "pull_request_target") is True

    # Both levels at once, and the workflow-level one keeps its label.
    both = {"concurrency": {"group": "a-${{ github.run_id }}"}, "jobs": {"j": {"concurrency": "b"}}}
    assert _concurrency_groups(both) == [("workflow", "a-${{ github.run_id }}"), ("job j", "b")]

    # A real file still resolves through the same helper, so the two paths cannot drift.
    assert (
        "workflow",
        str(load_workflow("cla.yml")["concurrency"]["group"]),
    ) in _concurrency_groups(load_workflow("cla.yml"))
