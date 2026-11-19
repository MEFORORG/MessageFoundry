# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read the required status-check contexts: from the checked-in file and from the server.

ONE READER, stdlib only. At least four callers need it and two of them run where PyYAML and pytest
are not installed: ``scripts/release/tag_provenance.py`` on the release runner, and
``scripts/ci/check_required_contexts_drift.py`` on the scanner-lock job.
``scripts/coord/pr_state.py`` loads it by path and passes ``allow_empty=True`` (see
``branch_protection_contexts``), and ``tests/_workflow_contexts.py`` uses the same file parser. Before vault BACKLOG #2631 each had its
own copy, and two of them disagreed on what an absent server list means. Here an absent list
RAISES: a changed API shape is not an empty required set. By default an empty list, an unprotected
branch and an unenforced one raise too; ``branch_protection_contexts`` names the one opt-out.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CANONICAL = ROOT / ".github" / "required-contexts.txt"


def parse_contexts_file(text: str) -> list[str]:
    """The contexts a ``required-contexts.txt`` records: comments and blank lines stripped."""
    return [s for line in text.splitlines() if (s := line.strip()) and not s.startswith("#")]


def file_contexts(path: Path = CANONICAL) -> list[str]:
    return parse_contexts_file(path.read_text(encoding="utf-8"))


def gh_api(args: Sequence[str]) -> Any:
    """``gh api <args>`` parsed as JSON. Raises naming the exit code; never prints a URL."""
    # B603 asks whether untrusted input reaches a subprocess. Here argv is a list, there is no
    # shell, and the variable parts are the repository, branch and commit a caller passes in.
    out = subprocess.run(  # noqa: S603  # nosec B603 B607 - list argv, no shell
        ["gh", "api", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    if out.returncode != 0:
        raise RuntimeError(f"gh api exited {out.returncode}: {out.stderr.strip()[:400]}")
    if not out.stdout.strip():
        raise RuntimeError("gh api returned no output")
    return json.loads(out.stdout)


def branch_protection_contexts(payload: Any, *, allow_empty: bool = False) -> list[str]:
    """The contexts classic branch protection requires, from a ``branches/{branch}`` payload.

    That endpoint answers an anonymous reader, so no admin scope is needed. GitHub carries the
    required set twice, as ``contexts`` and as ``checks[].context``; the answer is the union, so a
    context recorded under only one of them is still read.

    An empty answer RAISES by default: an unprotected branch, an ``enforcement_level`` of ``off`` and
    an empty list all mean classic protection requires nothing, and a caller comparing against this
    set or gating a release on it must refuse rather than read "nothing is required" (BACKLOG
    #5465). ``allow_empty=True`` is for a caller that unions this with the ruleset contexts and
    refuses an empty COMBINED set itself; it gets ``[]`` for those three cases instead. A payload
    with neither list raises either way, because the API shape changed and nothing was read, unless
    it also says ``protected: false``, which GitHub may send with no status-check block at all.
    """
    if not isinstance(payload, dict):
        raise RuntimeError(f"the branch payload is a {type(payload).__name__}, not an object")
    unprotected = payload.get("protected") is False
    protection = payload.get("protection") or {}
    checks = (
        protection.get("required_status_checks") or {} if isinstance(protection, dict) else None
    )
    if not isinstance(checks, dict):
        raise RuntimeError(
            "the branch payload's protection.required_status_checks is not an object"
        )
    contexts = checks.get("contexts")
    check_list = checks.get("checks")
    if contexts is None and check_list is None and not unprotected:
        raise RuntimeError(
            "the branch payload carried no required_status_checks.contexts or .checks -- the API "
            "shape changed, or this branch is unprotected. Either way it is not an empty required set."
        )
    if not isinstance(contexts, list | None) or not isinstance(check_list, list | None):
        raise RuntimeError("required_status_checks.contexts or .checks is not a list")
    unique = list(
        dict.fromkeys(
            _named(
                [
                    *(contexts or []),
                    *(c.get("context") if isinstance(c, dict) else None for c in check_list or []),
                ],
                "required_status_checks",
            )
        )
    )
    if unprotected:
        why_empty = "the branch is not protected"
    elif checks.get("enforcement_level") == "off":
        why_empty = "required_status_checks.enforcement_level is off"
    elif not unique:
        why_empty = "required_status_checks lists no context"
    else:
        return unique
    if allow_empty:
        return []
    raise RuntimeError(
        f"{why_empty}, so classic branch protection requires nothing. That is refused, not read as "
        "an empty required set."
    )


def _named(entries: list[Any], where: str) -> list[str]:
    """``entries`` unchanged when every one is a non-blank string; otherwise a refusal.

    A null, empty or whitespace-only entry would become a required context nothing can report, or
    the string ``'None'``, so it is refused as a shape the reader does not understand.
    """
    if not all(isinstance(c, str) and c.strip() for c in entries):
        raise RuntimeError(f"a {where} entry names no context: {entries!r}")
    return entries


def ruleset_contexts(rules: Any) -> list[str]:
    """The contexts every ruleset on a branch requires, from a ``rules/branches/{branch}`` payload.

    An empty list is a real answer here: a branch with no ruleset requires nothing through one.
    """
    if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
        raise RuntimeError("the branch rules payload is not a list of rule objects")
    return _named(
        [
            check.get("context") if isinstance(check, dict) else None
            for rule in rules
            if rule.get("type") == "required_status_checks"
            for check in (rule.get("parameters") or {}).get("required_status_checks") or []
        ],
        "ruleset required_status_checks",
    )
