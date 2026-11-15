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
2. **Did its required checks pass?** The required set is the union of three readings: the contexts
   classic branch protection requires, the contexts any ruleset on the branch requires, and the
   contexts ``.github/required-contexts.txt`` records at the tagged commit. The union is
   deliberate. The file can lag the server, and the server was once cut to a single context for an
   afternoon, so any one reading alone can be short. An empty union refuses, because a set with
   nothing in it proves nothing.

   A context passes only when EVERY latest report of it passes; which reports are latest is a
   question of what supersedes what (BACKLOG #5591):

   * A commit status is superseded by a later status of the same context, since GitHub itself
     judges a context on its newest status.
   * A check run is superseded by a later run of the same name in the SAME check suite. That is
     what re-running a GitHub Actions job makes: new runs, with higher ids, in the workflow run's
     own suite (measured 2026-11-14 on run 43659597734, attempt 2: suite 118209571176 held the
     failed and the passing ``CI gate`` runs). Runs of one name in DIFFERENT suites are independent
     reports, for example main's push run and a dispatched run of one workflow, or two apps posting
     one name, and GitHub orders nothing between them. So each suite's latest run must pass, and a
     green in one suite never hides a red or a still-running run in another.
   * The exception is a suite whose workflow ran on an event in :data:`POOLED_EVENTS`. Those
     events, such as a comment on a pull request, run against the default branch's tip on behalf of
     something else, so each one adds a suite to main's tip without testing it: every
     ``issue_comment`` run of the CLA workflow adds a ``cla`` suite there (measured 2026-11-14). Held
     one suite apiece, a single red comment run could never be superseded, and anyone who can
     comment could block releasing main's tip for good. Those suites are pooled into one lineage
     per context, judged on its latest run as every suite was before #5591, so the pooling never
     passes a commit the earlier rule refused.
   * A run whose suite the API did not name is its own lineage, so nothing supersedes it; the
     refusal names it, and an unknown event is held per suite, never pooled.

   Every run is read (``filter=all``), because the endpoint's default ``latest`` filter returns only
   the newest runs, which hides an earlier attempt from the rule that has to judge it. Ids are
   compared only within a kind, since the two kinds number their ids separately. A check run
   passes on the conclusions branch protection accepts: ``success``, ``neutral`` or ``skipped``. A
   commit status passes on ``success``. A context with no report at all refuses.

   **A red latest run blocks the tag** even when the merge-queue run passed. That covers main's own
   push run, the nightly run and a dispatched run on the same commit. A release gate fails closed.
   The remedy is to re-run the failed jobs of THAT workflow run ("Re-run failed jobs"), then re-run
   the release; a fresh dispatch starts a new suite and leaves the red one standing. GitHub re-runs
   a workflow run only within 30 days of it, so past that the remedy is to tag a newer commit.
   (Manager ruling under the owner's driver rule, 2026-10-03; the owner may overturn it.) A required
   check still RUNNING is waited for, up to ``--wait-seconds``, so a tag pushed right after a merge
   is judged on the finished run, but a red that waiting cannot fix refuses at once.

   A context the server requires now that never reported on the commit also refuses, even when it
   was added after the commit merged. Nothing tells "added later" apart from "skipped by a bypass",
   so the gate does not guess. The remedy is to tag a newer commit that ran the new check.

**Where its promise ends.** It binds only a ref that carries this copy of ``release.yml``, as the
workflow's header says of every guard in it. It is a gate inside the release; it is not a ruleset,
so it cannot stop a tag being pushed, only that tag being released. And it reads the server through
the job's own token, so an API failure refuses rather than passes.

Usage: ``python scripts/release/tag_provenance.py --repo OWNER/NAME --sha <commit>``. The ``gh`` CLI
must be authenticated, which ``GH_TOKEN`` does on a runner.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
from scripts.ci.required_contexts import (  # noqa: E402
    CANONICAL,
    branch_protection_contexts,
    file_contexts,
    gh_api,
    ruleset_contexts,
)

#: Compare statuses that put the commit on ``main``: an ancestor of its tip, or the tip itself.
ON_MAIN = frozenset({"behind", "identical"})

#: Check-run conclusions branch protection treats as passing.
PASSING_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})

#: Workflow events that run against the default branch's tip on behalf of a comment, a pull
#: request or another run, so their suites land on main's tip without testing it. This repository's
#: required contexts come from workflows triggered on at least these. A suite on any other event, or
#: on none, is judged on its own.
POOLED_EVENTS = frozenset({"issue_comment", "pull_request_target", "workflow_run"})


@dataclass(frozen=True)
class Report:
    """One report for a context: a check run or a commit status, as the API returned it."""

    #: The API id. Within one kind, ids grow over time, so the largest is the latest report.
    id: int
    context: str
    #: ``check`` for a check run, ``status`` for a commit status.
    kind: str
    #: A check run's ``status`` (``completed``, ``in_progress``...) or a commit status's ``state``.
    state: str
    #: A check run's ``conclusion``; empty for a commit status or an unfinished run.
    conclusion: str = ""
    #: A check run's check-suite id; ``None`` for a commit status, or a run the API gave none for.
    suite: int | None = None
    #: The event of the workflow run that owns the suite; empty for a status or a non-Actions suite.
    event: str = ""

    def lineage(self) -> tuple[str, str, str]:
        """What a later report must share to supersede this one.

        A status is superseded by a later status of its context. A check run is superseded only by a
        later run in its own check suite, or, for a suite on a :data:`POOLED_EVENTS` event, by a
        later run in any such suite. A run with no suite id is superseded by nothing, because its
        lineage names the run itself.
        """
        if self.kind == "status":
            return (self.context, self.kind, "")
        if self.event in POOLED_EVENTS:
            return (self.context, self.kind, "pooled")
        if self.suite is None:
            return (self.context, self.kind, f"run:{self.id}")
        return (self.context, self.kind, f"suite:{self.suite}")

    def is_unfinished(self) -> bool:
        return self.state == "pending" if self.kind == "status" else self.state != "completed"

    def passed(self) -> bool:
        if self.kind == "check":
            return self.state == "completed" and self.conclusion in PASSING_CONCLUSIONS
        return self.state == "success"

    def describe(self) -> str:
        if self.kind == "check":
            suite = self.suite if self.suite is not None else "unnamed"
            return (
                f"check run {self.state}/{self.conclusion or 'none'} (run {self.id}, suite "
                f"{suite}, event {self.event or 'unknown'})"
            )
        return f"commit status {self.state}"


def latest_reports(reports: Iterable[Report]) -> list[Report]:
    """The reports nothing later supersedes: the highest id in each :meth:`Report.lineage`."""
    latest: dict[tuple[str, str, str], Report] = {}
    for report in reports:
        key = report.lineage()
        held = latest.get(key)
        if held is None or report.id > held.id:
            latest[key] = report
    return list(latest.values())


def verdict(
    compare_status: str,
    required: Iterable[str],
    reports: Iterable[Report],
    still_running: Iterable[str] = (),
) -> list[str]:
    """Every reason to refuse the release. An empty list is a pass.

    ``still_running`` names contexts whose unfinished reports are not judged yet, so a caller that
    is waiting can ask whether anything ELSE already refuses. A finished red report of such a
    context still refuses: waiting on another suite cannot supersede it.
    """
    skip = set(still_running)
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
    latest = latest_reports(reports)
    for context in wanted:
        lasts = [r for r in latest if r.context == context]
        if not lasts and context not in skip:
            problems.append(f"required context {context!r} never reported on the tagged commit")
        for last in lasts:
            if context in skip and last.is_unfinished():
                continue
            if not last.passed():
                problems.append(
                    f"required context {context!r} did not pass on the tagged commit: a latest "
                    f"report of it is a {last.describe()}"
                )
    return problems


def reports_from(
    check_pages: list[dict[str, Any]],
    status_pages: list[list[Any]],
    run_pages: Iterable[dict[str, Any]] = (),
) -> list[Report]:
    """Reports out of the slurped ``check-runs``, ``statuses`` and ``actions/runs`` pages.

    The workflow runs give each Actions suite its event; a suite no run names gets none.
    """
    events = {
        int(run["check_suite_id"]): str(run.get("event") or "")
        for page in run_pages
        for run in page.get("workflow_runs") or []
        if run.get("check_suite_id") is not None
    }
    return [
        Report(
            id=int(run["id"]),
            context=str(run["name"]),
            kind="check",
            state=str(run["status"]),
            conclusion=str(run.get("conclusion") or ""),
            suite=(suite := _suite_id(run)),
            event=events.get(suite, "") if suite is not None else "",
        )
        for page in check_pages
        for run in page.get("check_runs") or []
    ] + [
        Report(id=int(s["id"]), context=str(s["context"]), kind="status", state=str(s["state"]))
        for page in status_pages
        for s in page
    ]


def _suite_id(run: dict[str, Any]) -> int | None:
    suite = run.get("check_suite")
    if isinstance(suite, dict) and suite.get("id") is not None:
        return int(suite["id"])
    return None


def read_server(repo: str, sha: str, branch: str) -> tuple[str, list[str], list[Report]]:
    """(compare status, contexts the server requires, every report on ``sha``) read through gh."""
    # per_page=1: only `status` is wanted, and the endpoint otherwise pages in commits and patches.
    compare = gh_api([f"repos/{repo}/compare/{branch}...{sha}?per_page=1", "--jq", "{status}"])
    server = branch_protection_contexts(gh_api([f"repos/{repo}/branches/{branch}"]))
    rule_pages = gh_api(["--paginate", "--slurp", f"repos/{repo}/rules/branches/{branch}"])
    server += ruleset_contexts([rule for page in rule_pages for rule in page])
    checks = gh_api(
        ["--paginate", "--slurp", f"repos/{repo}/commits/{sha}/check-runs?filter=all&per_page=100"]
    )
    statuses = gh_api(
        ["--paginate", "--slurp", f"repos/{repo}/commits/{sha}/statuses?per_page=100"]
    )
    runs = gh_api(
        ["--paginate", "--slurp", f"repos/{repo}/actions/runs?head_sha={sha}&per_page=100"]
    )
    return str(compare["status"]), server, reports_from(checks, statuses, runs)


def unfinished(required: Iterable[str], reports: Iterable[Report]) -> list[str]:
    """Required contexts with a latest report still queued, running or pending."""
    wanted = set(required)
    return sorted(
        {r.context for r in latest_reports(reports) if r.context in wanted and r.is_unfinished()}
    )


def _at_least(minimum: int) -> Callable[[str], int]:
    def parse(text: str) -> int:
        value = int(text)
        if value < minimum:
            raise argparse.ArgumentTypeError(f"must be at least {minimum}, got {value}")
        return value

    return parse


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--repo", required=True, help="OWNER/NAME")
    parser.add_argument("--sha", required=True, help="the commit the tag names")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--contexts-file", type=Path, default=CANONICAL)
    parser.add_argument(
        "--wait-seconds",
        type=_at_least(0),
        default=1800,
        help="how long to wait for a required check that is still running (default 1800)",
    )
    parser.add_argument("--poll-seconds", type=_at_least(1), default=60)
    args = parser.parse_args(argv)
    in_file = file_contexts(args.contexts_file)

    deadline = time.monotonic() + args.wait_seconds
    while True:
        try:
            compare, server, reports = read_server(args.repo, args.sha, args.branch)
        except (
            RuntimeError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            subprocess.SubprocessError,
            OSError,
        ) as exc:
            print(
                f"::error::could not read the tagged commit's provenance, so it is refused: {exc}"
            )
            return 1
        required = set(server) | set(in_file)
        running = unfinished(required, reports)
        # A tag pushed minutes after a merge meets main's own push run still going. Wait for it
        # rather than refuse: the rule judges a finished run. But stop at once when something
        # waiting cannot fix has already failed, such as a commit that is not on main.
        settled = verdict(compare, required, reports, still_running=running)
        left = deadline - time.monotonic()
        if not running or settled or left <= 0:
            break
        print(f"waiting for {len(running)} required check(s) still running: {running}")
        time.sleep(min(args.poll_seconds, left))

    print(
        f"commit {args.sha}: compare with {args.branch} reports {compare!r}; "
        f"{len(required)} required context(s) ({len(set(server))} on the server, {len(in_file)} "
        f"in the file); {len(reports)} report(s) on the commit"
    )
    problems = verdict(compare, required, reports)
    for problem in problems:
        print(f"::error::{problem}")
    if running and not settled:
        print(
            f"::error::gave up after {args.wait_seconds}s waiting for {running}, still running. "
            "Re-run the release once they finish."
        )
    if problems:
        print(
            "::error::the release is refused (vault BACKLOG #2631). Tag a commit that is on "
            f"{args.branch} and passed every required check. A failed check run counts against "
            "the commit until the workflow run that holds it re-runs its failed jobs and they "
            "pass; a fresh dispatch does not clear it, and past 30 days tag a newer commit. A "
            "check still running counts until it ends. Then re-run the release."
        )
        return 1
    print(f"the tagged commit is on {args.branch} and passed all {len(required)} required contexts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
