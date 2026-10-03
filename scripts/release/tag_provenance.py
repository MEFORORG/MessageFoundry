# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refuse a release tag whose commit is not on ``main`` or did not pass main's required checks.

vault BACKLOG #2631, limb 2. A tag push runs the release, and the release builds whatever commit the
tag names. Nothing before this asked where that commit came from. So a tag on a branch nobody
merged, or on a merge whose checks went red, would build, sign and publish exactly like a tag on a
reviewed commit. This script asks two questions before anything is built:

1. **Is the commit on ``main``?** The compare API answers it: ``main...<sha>`` reports ``behind``
   when the commit is an ancestor of ``main`` and ``identical`` when it is ``main``'s tip. Any other
   answer refuses.
2. **Did its required checks pass?** The required set is the union of two readings: the contexts
   branch protection requires on the server now, and the contexts ``.github/required-contexts.txt``
   records at the tagged commit. The union is deliberate. The file can lag the server, and the
   server was once cut to a single context for an afternoon, so either alone can be short. An empty
   union refuses, because a set with nothing in it proves nothing.

   Each context passes on its LATEST report for the commit, a check run or a commit status. A check
   run passes on the conclusions branch protection accepts: ``success``, ``neutral`` or ``skipped``.
   A commit status passes on ``success``. A context with no report at all refuses.

**Where its promise ends.** It binds only a ref that carries this copy of ``release.yml``, as the
workflow's header says of every guard in it. It is a gate inside the release; it is not a ruleset,
so it cannot stop a tag being pushed, only that tag being released. And it reads the server through
the job's own token, so an API failure refuses rather than passes.

Usage: ``python scripts/release/tag_provenance.py --repo OWNER/NAME --sha <commit>``. The ``gh`` CLI
must be authenticated, which ``GH_TOKEN`` does on a runner.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_CONTEXTS_FILE = _ROOT / ".github" / "required-contexts.txt"

#: Compare statuses that put the commit on ``main``: an ancestor of its tip, or the tip itself.
ON_MAIN = frozenset({"behind", "identical"})

#: Check-run conclusions branch protection treats as passing.
PASSING_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})


@dataclass(frozen=True)
class Report:
    """One report for a context: a check run or a commit status, as the API returned it."""

    #: The API id. Ids grow over time, so the largest id is the latest report.
    id: int
    context: str
    #: ``check`` for a check run, ``status`` for a commit status.
    kind: str
    #: A check run's ``status`` (``completed``, ``in_progress``...) or a commit status's ``state``.
    state: str
    #: A check run's ``conclusion``; empty for a commit status or an unfinished run.
    conclusion: str = ""

    def passed(self) -> bool:
        if self.kind == "check":
            return self.state == "completed" and self.conclusion in PASSING_CONCLUSIONS
        return self.state == "success"

    def describe(self) -> str:
        if self.kind == "check":
            return f"check run {self.state}/{self.conclusion or 'none'}"
        return f"commit status {self.state}"


def contexts_in_file(text: str) -> list[str]:
    """The contexts ``.github/required-contexts.txt`` records: comments and blank lines stripped.

    The same rule as ``tests/_workflow_contexts.required_contexts``, which imports PyYAML and so is
    not importable on the release runner. tests/test_release_tag_provenance.py holds the two equal.
    """
    return [s for line in text.splitlines() if (s := line.strip()) and not s.startswith("#")]


def verdict(compare_status: str, required: Iterable[str], reports: Iterable[Report]) -> list[str]:
    """Every reason to refuse the release. An empty list is a pass."""
    problems: list[str] = []
    if compare_status not in ON_MAIN:
        problems.append(
            f"the tagged commit is not on main: comparing main with it reports {compare_status!r}, "
            f"not one of {sorted(ON_MAIN)}"
        )
    wanted = sorted(set(required))
    if not wanted:
        problems.append(
            "no required context was found, on the server or in .github/required-contexts.txt, so "
            "there is nothing to prove the commit passed"
        )
    latest: dict[str, Report] = {}
    for report in reports:
        held = latest.get(report.context)
        if held is None or report.id > held.id:
            latest[report.context] = report
    for context in wanted:
        last = latest.get(context)
        if last is None:
            problems.append(f"required context {context!r} never reported on the tagged commit")
        elif not last.passed():
            problems.append(
                f"required context {context!r} did not pass on the tagged commit: its latest "
                f"report is a {last.describe()}"
            )
    return problems


def _gh(args: Sequence[str]) -> str:
    """Run ``gh`` and return its output, or raise naming what failed. Never prints a URL."""
    # B603 asks whether untrusted input reaches a subprocess. Here argv is a list, there is no
    # shell, and the variable parts are the repository and commit the workflow passes in.
    out = subprocess.run(  # noqa: S603  # nosec B603 B607 - list argv, no shell
        ["gh", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    if out.returncode != 0:
        raise RuntimeError(f"gh api exited {out.returncode}: {out.stderr.strip()[:400]}")
    return out.stdout


def _lines_of_json(text: str) -> list[list[object]]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def read_server(repo: str, sha: str, branch: str) -> tuple[str, list[str], list[Report]]:
    """(compare status, contexts the server requires, every report on ``sha``) read through gh."""
    compare = _gh(["api", f"repos/{repo}/compare/{branch}...{sha}", "--jq", ".status"]).strip()
    server = json.loads(
        _gh(
            [
                "api",
                f"repos/{repo}/branches/{branch}",
                "--jq",
                ".protection.required_status_checks.contexts // []",
            ]
        )
        or "[]"
    )
    # One JSON array per line, so paginated pages concatenate without a parse across them.
    runs = _lines_of_json(
        _gh(
            [
                "api",
                "--paginate",
                f"repos/{repo}/commits/{sha}/check-runs?per_page=100",
                "--jq",
                '.check_runs[] | [.id, .name, .status, (.conclusion // "")] | @json',
            ]
        )
    )
    statuses = _lines_of_json(
        _gh(
            [
                "api",
                "--paginate",
                f"repos/{repo}/commits/{sha}/statuses?per_page=100",
                "--jq",
                ".[] | [.id, .context, .state] | @json",
            ]
        )
    )
    reports = [
        Report(id=int(str(i)), context=str(n), kind="check", state=str(s), conclusion=str(c))
        for i, n, s, c in runs
    ] + [
        Report(id=int(str(i)), context=str(n), kind="status", state=str(s)) for i, n, s in statuses
    ]
    return compare, [str(c) for c in server], reports


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--repo", required=True, help="OWNER/NAME")
    parser.add_argument("--sha", required=True, help="the commit the tag names")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--contexts-file", type=Path, default=_CONTEXTS_FILE)
    args = parser.parse_args(argv)

    try:
        compare, server, reports = read_server(args.repo, args.sha, args.branch)
    except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as exc:
        print(f"::error::could not read the tagged commit's provenance, so it is refused: {exc}")
        return 1
    in_file = contexts_in_file(args.contexts_file.read_text(encoding="utf-8"))
    required = sorted(set(server) | set(in_file))
    print(
        f"commit {args.sha}: compare with {args.branch} reports {compare!r}; "
        f"{len(required)} required context(s) ({len(server)} on the server, {len(in_file)} in "
        f"the file); {len(reports)} report(s) on the commit"
    )
    problems = verdict(compare, required, reports)
    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        print(
            "::error::the release is refused (vault BACKLOG #2631). Tag a commit that is on "
            f"{args.branch} and passed every required check, or re-run the checks that failed."
        )
        return 1
    print(f"the tagged commit is on {args.branch} and passed all {len(required)} required contexts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
