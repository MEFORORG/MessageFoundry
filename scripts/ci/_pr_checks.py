#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One reading of a pull request's ``statusCheckRollup``, shared by the checks that need it.

WHY THIS IS ITS OWN MODULE. It was split out when two scripts read the rollup:
``check_stalled_prs.py`` asked "is this green and unable to merge", ``check_unread_prs.py`` asked "is
this green and unread". The second was deleted on 2026-09-13 (BACKLOG #1490). Today the callers are
``check_stalled_prs.py`` and ``scripts/coord/pr_state.py``. What the module owns
is GitHub's rollup vocabulary, which is GitHub's to change and not ours, and the next reader that
needs it would otherwise start a second copy free to drift -- silently, in the one direction that
matters, since a conclusion string nobody classified reads as green. ``tests/_workflow_contexts.py``
carries the same single-source note for the context-to-job mapping, for the same reason.

TWO NODE SHAPES, and mixing them up is the easy mistake. GitHub returns a CheckRun (``status`` plus
``conclusion``, named by ``name``) and a StatusContext (``state``, named by ``context``) through the
same array. A node whose shape is unrecognised is counted as UNSETTLED rather than ignored: "I could
not classify this" must never read as "this is green".
"""

from __future__ import annotations

#: Conclusions that count as a failure. ``ERROR`` is a StatusContext ``state``; before it was listed a
#: commit status in ERROR had a verdict nobody classified, and so read as green.
FAILING = frozenset(
    {"FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED", "STARTUP_FAILURE", "ERROR"}
)

#: The only verdicts that count as passed. Anything else is FAILING, STALE or unsettled.
PASSING = frozenset({"SUCCESS", "NEUTRAL", "SKIPPED"})

#: A CheckRun conclusion GitHub gives a run it abandoned after 14 days. counts() reads it as neither
#: failing nor unsettled, as it always has, so an optional stale run never hides a stalled PR from
#: check_stalled_prs. pr_state reads a STALE REQUIRED run as failing, since GitHub never re-runs it,
#: and ranks it as failing when it breaks a tie between same-named runs.
STALE = "STALE"

#: StatusContext ``state`` values that mean it has not reported. ``EXPECTED`` is a status that has
#: been asked for. CheckRuns need no list: in_progress() reads any status but COMPLETED as running.
UNSETTLED = frozenset({"PENDING", "EXPECTED"})


def name_of(node: object) -> str:
    """The context string a rollup node reports under, or ``""`` if it does not name itself.

    A CheckRun's context string is its job ``name``; a StatusContext's is ``context``. Callers match
    this against branch-protection context strings, so both spellings have to resolve.
    """
    if not isinstance(node, dict):
        return ""
    return str(node.get("name") or node.get("context") or "")


def in_progress(node: object) -> bool:
    """True while a node may still be running.

    A CheckRun (it carries ``status``) runs until its status is COMPLETED: an allowlist, so a status
    nobody listed (QUEUED, IN_PROGRESS, WAITING, REQUESTED, PENDING, a new one) reads as running, as
    clear_stale_ci_red.newest_by_name reads it. A StatusContext runs while its ``state`` is in
    UNSETTLED.
    """
    if not isinstance(node, dict):
        return False
    if node.get("status"):
        return str(node["status"]).upper() != "COMPLETED"
    return str(node.get("state") or "").upper() in UNSETTLED


def verdict_of(node: object) -> str:
    """A node's verdict, upper-cased: a CheckRun's ``conclusion``, else a StatusContext's ``state``."""
    if not isinstance(node, dict):
        return ""
    return str(node.get("conclusion") or node.get("state") or "").upper()


def counts(rollup: object) -> tuple[int, int]:
    """``(failing, unsettled)`` over a ``statusCheckRollup`` payload.

    Pure. A node whose shape is unrecognised is counted as UNSETTLED -- see the module docstring for
    why that direction is the safe one.
    """
    if not isinstance(rollup, list):
        return (0, 0)
    failing = unsettled = 0
    for node in rollup:
        if not isinstance(node, dict):
            unsettled += 1
            continue
        verdict = verdict_of(node)
        if in_progress(node):
            unsettled += 1
        elif verdict in FAILING:
            failing += 1
        elif verdict not in PASSING and verdict != STALE:
            # An allowlist, not a denylist: a verdict nobody listed is unsettled, never green.
            unsettled += 1
    return (failing, unsettled)
