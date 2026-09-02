# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
FILE = WORKFLOWS / "failure-signal.yml"


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
    watched = set(_on(_doc())["workflow_run"]["workflows"])
    assert watched, "the watch list is empty, so every assertion below would pass against nothing"
    present = set()
    for path in WORKFLOWS.glob("*.yml"):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        name = doc.get("name")
        if isinstance(name, str):
            present.add(name)
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
