# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read the required status-check contexts: from the checked-in file and from the server.

ONE READER, stdlib only. Three callers need it and two of them run where PyYAML and pytest are not
installed: ``scripts/release/tag_provenance.py`` on the release runner, and
``scripts/ci/check_required_contexts_drift.py`` on the scanner-lock job.
``tests/_workflow_contexts.py`` uses the same file parser. Before vault BACKLOG #2631 each had its
own copy, and two of them disagreed on what an absent server list means. Here an absent list
RAISES: an unprotected branch, or a changed API shape, is not an empty required set.
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
    return json.loads(out.stdout or "null")


def branch_protection_contexts(payload: dict[str, Any]) -> list[str]:
    """The contexts classic branch protection requires, from a ``branches/{branch}`` payload.

    That endpoint answers an anonymous reader, so no admin scope is needed.
    """
    protection = payload.get("protection") or {}
    checks = protection.get("required_status_checks") or {}
    contexts = checks.get("contexts")
    if contexts is None:
        raise RuntimeError(
            "the branch payload carried no required_status_checks.contexts -- the API shape changed, "
            "or this branch is unprotected. Either way it is not an empty required set."
        )
    return [str(c) for c in contexts]


def ruleset_contexts(rules: list[dict[str, Any]]) -> list[str]:
    """The contexts every ruleset on a branch requires, from a ``rules/branches/{branch}`` payload.

    An empty list is a real answer here: a branch with no ruleset requires nothing through one.
    """
    return [
        str(check["context"])
        for rule in rules
        if rule.get("type") == "required_status_checks"
        for check in (rule.get("parameters") or {}).get("required_status_checks") or []
    ]
