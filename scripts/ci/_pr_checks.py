#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""One reading of a pull request's ``statusCheckRollup``, shared by the checks that need it.

WHY THIS IS ONE MODULE AND NOT TWO COPIES. ``check_stalled_prs.py`` asks "is this green and unable to
merge". ``check_unread_prs.py`` asks "is this green and unread". Different questions, but both turn on
the same underlying fact: GitHub's rollup vocabulary, which is GitHub's to change and not ours. Two
copies of that vocabulary would be free to drift, and the drift would be silent in the one direction
that matters -- a conclusion string nobody classified reads as green -- which is the defect both
checks exist to prevent. ``tests/_workflow_contexts.py`` carries the same single-source note for the
context-to-job mapping, for the same reason.

TWO NODE SHAPES, and mixing them up is the easy mistake. GitHub returns a CheckRun (``status`` plus
``conclusion``, named by ``name``) and a StatusContext (``state``, named by ``context``) through the
same array. A node whose shape is unrecognised is counted as UNSETTLED rather than ignored: "I could
not classify this" must never read as "this is green".
"""

from __future__ import annotations

#: Conclusions that count as a failure.
FAILING = frozenset({"FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED", "STARTUP_FAILURE"})

#: Statuses that mean a check has not settled yet.
UNSETTLED = frozenset({"QUEUED", "IN_PROGRESS", "WAITING", "PENDING", "REQUESTED"})


def name_of(node: object) -> str:
    """The context string a rollup node reports under, or ``""`` if it does not name itself.

    A CheckRun's context string is its job ``name``; a StatusContext's is ``context``. Callers match
    this against branch-protection context strings, so both spellings have to resolve.
    """
    if not isinstance(node, dict):
        return ""
    return str(node.get("name") or node.get("context") or "")


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
        status = str(node.get("status") or "").upper()
        conclusion = str(node.get("conclusion") or "").upper()
        state = str(node.get("state") or "").upper()
        verdict = conclusion or state
        if status in UNSETTLED or state in UNSETTLED:
            unsettled += 1
        elif verdict in FAILING:
            failing += 1
        elif not verdict and not status:
            unsettled += 1
    return (failing, unsettled)
