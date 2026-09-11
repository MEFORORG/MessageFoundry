# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A concurrency group must not put two different pull requests in one group (BACKLOG #1533).

THE DEFECT THIS HOLDS. `cla.yml` keyed its group on ``github.ref`` under ``pull_request_target``.
For ``pull_request`` that context is ``refs/pull/<n>/merge`` and so is per-pull-request; for
``pull_request_target`` it is the BASE ref, ``refs/heads/main``. Every open pull request therefore
resolved to one group, ``cla-refs/heads/main``, and with that arm cancellable each new push to any
pull request cancelled the in-flight ``cla`` run of an unrelated one. ``cla`` is a REQUIRED context,
so the victim could not merge, and a cancelled run carries no steps and no logs -- it renders in the
fail column with nothing to read, which is why it went unattributed.

WHY A TEST RATHER THAN A CAREFUL COMMENT. The two spellings differ by one word, the wrong one looks
like the five sibling workflows that are correct, and the failure is INVISIBLE in the file: a group
key that silently collapses produces no error, no warning and no log line. It is only observable in
the cancellation record of runs on OTHER branches, which nobody reads while reviewing this file.

THE INVARIANT. For an event that fires once per pull request but whose ``github.ref`` is not
per-pull-request -- ``pull_request_target`` and ``issue_comment`` -- the concurrency group must not
key on ``github.ref``. It must key on something that separates pull requests (the payload number) or
something unique per run (``github.run_id``).

``push``, ``schedule``, ``workflow_dispatch`` and ``workflow_run`` are deliberately NOT in that set,
and the exclusion is the reason this test does not flag ``ci.yml``. They do not fire per pull
request, so a ``github.ref`` key there groups a branch or a scheduled line with itself, which is the
intended behaviour rather than the defect. ``merge_group`` is excluded for the opposite reason: its
ref is ``refs/heads/gh-readonly-queue/<base>/pr-<n>-<sha>``, already unique per queue entry.
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
# from another. These are the only events where a github.ref key collapses across pull requests.
COLLAPSING_EVENTS = ("pull_request_target", "issue_comment")

# `github.ref` as a whole context, not the `.ref` tail of `github.event.pull_request.head.ref` and
# not the different context `github.ref_name`. unread-signal.yml keys on the former and would be a
# false positive under a looser pattern.
_GITHUB_REF = re.compile(r"(?<![.\w])github\.ref(?![_\w])")

# `github.event_name == 'X' && <a> || <b>` -- the shape every conditional key in this repo uses.
_ARMED = re.compile(
    r"github\.event_name\s*==\s*'(?P<event>[a-z_]+)'\s*&&\s*(?P<then>.+?)\s*\|\|\s*(?P<otherwise>.+)$",
    re.DOTALL,
)

_EXPR = re.compile(r"\$\{\{(?P<body>.*?)\}\}", re.DOTALL)


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


def github_ref_reaches(expression: str, event: str) -> bool:
    """Can the ``github.ref`` token be the value of ``expression`` on ``event``?

    Conservative: an expression shape this does not recognise, but which mentions github.ref, counts
    as reaching every event. A checker that answered "unknown -> fine" would pass the very defect it
    exists to catch.
    """
    for match in _EXPR.finditer(expression):
        body = match.group("body")
        if not _GITHUB_REF.search(body):
            continue
        armed = _ARMED.search(body.strip())
        if not armed:
            return True  # an unconditional github.ref key: reachable on every event
        then, otherwise = armed.group("then"), armed.group("otherwise")
        gated_event = armed.group("event")
        if _GITHUB_REF.search(then) and event == gated_event:
            return True
        if _GITHUB_REF.search(otherwise) and event != gated_event:
            return True
    return False


def collapses_across_pull_requests(group: str, event: str) -> bool:
    """Does ``group`` put two DIFFERENT pull requests in one concurrency group on ``event``?

    THE PREDICATE, and deliberately the only one. Reachability alone is not the defect:
    ``github.ref`` is reached on ``pull_request`` in five workflows here and that is CORRECT, because
    there it expands to ``refs/pull/<n>/merge``. The defect needs both halves -- a github.ref key AND
    an event whose github.ref is shared between pull requests. Writing it once means the invariant
    below and the paired-arms rows cannot drift into two different definitions of the bug.
    """
    return event in COLLAPSING_EVENTS and github_ref_reaches(group, event)


def _concurrency_group(doc: dict[str, Any]) -> str | None:
    block = doc.get("concurrency")
    if isinstance(block, str):
        return block
    if isinstance(block, dict):
        return None if block.get("group") is None else str(block["group"])
    return None


def _workflow_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml"))


def test_no_workflow_groups_two_pull_requests_under_one_concurrency_key() -> None:
    """The invariant, over every workflow file rather than the one that taught it."""
    offenders: list[str] = []
    for path in _workflow_files():
        doc = load_workflow(path.name)
        group = _concurrency_group(doc)
        if group is None:
            continue
        for event in _on_events(doc):
            if collapses_across_pull_requests(group, event):
                offenders.append(
                    f"{path.name}: group {group!r} keys on github.ref for the {event!r} event, "
                    f"where github.ref is not per-pull-request -- every open pull request lands in "
                    f"one group. Key on github.event.pull_request.number or github.run_id."
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

    with_concurrency = [p.name for p in files if _concurrency_group(load_workflow(p.name))]
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


def test_the_cla_group_is_keyed_per_pull_request_and_keeps_its_re_push_saving() -> None:
    """cla.yml specifically: per-pull-request key, and the supersede-on-re-push behaviour intact.

    The second half matters because the safest possible key -- ``github.run_id`` on every arm --
    would satisfy the invariant above while silently discarding what the block is for.
    """
    block = load_workflow("cla.yml")["concurrency"]
    assert "github.event.pull_request.number" in block["group"], block["group"]
    assert not _GITHUB_REF.search(block["group"]), block["group"]
    # Still cancellable on the pull-request arm, so a rapid re-push supersedes its own earlier run.
    assert block["cancel-in-progress"] == "${{ github.event_name == 'pull_request_target' }}"
    # And the other two events keep a unique-per-run group: never cancelled, never queued behind a
    # sibling. `issue_comment` is the signing path, so a discarded run loses a recorded signature.
    assert "github.run_id" in block["group"], block["group"]


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
            "cla-${{ github.event_name == 'pull_request_target' && github.event.pull_request.number "
            "|| github.run_id }}",
            "pull_request_target",
            False,
        ),
        # ASYMMETRY, and the reason this checker is event-aware rather than a grep for `github.ref`.
        # The identical expression keyed on `pull_request` is CORRECT -- that is security.yml,
        # codeql.yml, net-helper.yml, zizmor.yml and quality-advisory.yml -- so a checker that
        # reddened on it would condemn five working workflows and teach nothing about the sixth.
        # github.ref IS reached here; what makes it safe is the EVENT, which is the whole point.
        (
            "security-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}",
            "pull_request",
            False,
        ),
        # The same five-sibling expression evaluated on a collapsing event: still safe, because the
        # condition gates github.ref to `pull_request` and this is not it. This row and the one above
        # are the pair that separates "reads the trigger" from "greps for a string".
        (
            "security-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}",
            "pull_request_target",
            False,
        ),
        # The FALLBACK arm reaching github.ref is the same defect wearing the other sleeve: here
        # github.ref is what every event EXCEPT pull_request gets.
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
        # Unconditional github.ref is reachable on whatever the file declares -- so it is a defect on
        # a collapsing event and fine on the two events backlog-hygiene.yml actually declares.
        ("backlog-hygiene-${{ github.ref }}", "pull_request_target", True),
        ("backlog-hygiene-${{ github.ref }}", "pull_request", False),
        ("backlog-hygiene-${{ github.ref }}", "merge_group", False),
        # Near-miss contexts that must NOT match. `head.ref` is unread-signal.yml's real key, and
        # `github.ref_name` is a different context; a naive `github.ref` substring hits both.
        ("unread-signal-${{ github.event.pull_request.head.ref }}", "pull_request_target", False),
        ("x-${{ github.ref_name }}", "pull_request_target", False),
        # No expression at all.
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


def test_an_unrecognised_expression_mentioning_github_ref_fails_closed() -> None:
    """A shape the parser does not model must be reported, not waved through.

    The opposite default is how a guard rots: someone writes a group key in a form this regex does
    not cover, the checker answers "not recognised, therefore fine", and the gate goes quiet without
    going red. See docs/Secure_Development_Standards.md on a control whose false negative is silent.
    """
    exotic = "x-${{ fromJSON(github.event_name == 'a' && '1' || '2') && github.ref }}"
    assert github_ref_reaches(exotic, "pull_request_target") is True
    # ... and it stays silent when github.ref is genuinely absent, so "fails closed" is not "always
    # red", which would be a guard that cannot pass and so cannot discriminate.
    assert github_ref_reaches("x-${{ fromJSON(something) }}", "pull_request_target") is False
