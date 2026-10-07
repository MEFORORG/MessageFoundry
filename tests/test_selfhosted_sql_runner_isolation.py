# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The in-repository half of what keeps fork code off the self-hosted SQL runner (vault BACKLOG #2765).

The real controls are server-side and are named, once, in the header of
``.github/workflows/selfhosted-win2025-sql.yml``; read the reasoning there. The first of them, an
organization runner group restricted to that one file at ``refs/heads/main``, admits ANY run of that
file at ``main``, so it holds only while facts about this repository stay true that nothing on the
server can check. This module pins them:

* that file's only trigger is ``workflow_dispatch``, with no dispatch inputs;
* its checkout takes neither ``ref:`` nor ``repository:``, so a main run cannot be pointed at fork code;
* no other workflow's ``runs-on`` asks for a self-hosted runner, that label, or a runner group.

A fork pull request can still add or edit a workflow in its own head; that path is what the
server-side settings exist for, and this module does not claim to cover it. The ``runs-on`` sweep
reads literal labels only: a label built by an expression at run time, or read from a variable, is
not resolvable here and is not caught.
"""

from __future__ import annotations

from typing import Any

from tests._workflow_contexts import WORKFLOWS, jobs_of, load_workflow, triggers_of

_FILE = "selfhosted-win2025-sql.yml"
_LABEL = "mefor-win2025-sql"
_FORBIDDEN_LABELS = {"self-hosted", _LABEL}


def _labels(runs_on: Any) -> list[str]:
    """A job's ``runs-on`` as a flat list of labels: a string, a list, or ``{labels: ...}``."""
    if isinstance(runs_on, str):
        return [runs_on]
    if isinstance(runs_on, list):
        return [str(label) for label in runs_on]
    if isinstance(runs_on, dict):
        return _labels(runs_on.get("labels"))
    return []


def _workflow_names() -> list[str]:
    names = sorted(p.name for p in [*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    assert _FILE in names and len(names) > 10, f"workflow discovery looks broken: {names}"
    return names


def test_the_selfhosted_sql_workflow_is_triggered_by_workflow_dispatch_alone() -> None:
    triggers = triggers_of(_FILE)
    assert set(triggers) == {"workflow_dispatch"}
    config = triggers["workflow_dispatch"]
    assert not (isinstance(config, dict) and config.get("inputs")), (
        f"{_FILE} declares workflow_dispatch inputs; see its header before adding any"
    )


def test_the_selfhosted_sql_workflow_checks_out_only_the_commit_it_was_started_at() -> None:
    checkouts = [
        step
        for job in jobs_of(_FILE).values()
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    # POSITIVE CONTROL: an empty list would make the assertion below vacuous.
    assert checkouts, f"{_FILE} has no actions/checkout step; re-read this module before editing it"
    for step in checkouts:
        with_ = step.get("with") or {}
        assert "ref" not in with_ and "repository" not in with_, f"{_FILE} checkout: {with_}"


def test_no_other_workflow_asks_for_a_self_hosted_runner() -> None:
    # POSITIVE CONTROL: the sweep's reader finds the labels where they are meant to be, so an empty
    # result below is not an instrument that cannot see them.
    own = {
        label.lower() for job in jobs_of(_FILE).values() for label in _labels(job.get("runs-on"))
    }
    assert own >= _FORBIDDEN_LABELS, f"{_FILE} no longer targets {sorted(_FORBIDDEN_LABELS)}"

    offenders: list[str] = []
    for name in _workflow_names():
        if name == _FILE:
            continue
        # Raw text, case-insensitive, for the custom label: it catches a literal sitting in a matrix
        # or a comment. Comments count: none names it today.
        if _LABEL in (WORKFLOWS / name).read_text(encoding="utf-8").lower():
            offenders.append(f"{name}: names {_LABEL}")
        jobs = load_workflow(name).get("jobs") or {}
        for key, job in jobs.items():
            runs_on = job.get("runs-on") if isinstance(job, dict) else None
            if isinstance(runs_on, dict) and "group" in runs_on:
                offenders.append(f"{name}:{key}: runs-on names a runner group")
            hit = {label.lower() for label in _labels(runs_on)} & _FORBIDDEN_LABELS
            if hit:
                offenders.append(f"{name}:{key}: runs-on asks for {sorted(hit)}")
    assert offenders == [], offenders
