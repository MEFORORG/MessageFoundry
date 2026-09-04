#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Read the ``ci-red`` label back, and say WHICH run reddened each pull request (BACKLOG #1385).

``failure-signal.yml`` writes the label. Until this script, **nothing read it** -- a grep for
``ci-red`` returned the writing workflow plus prose in ``CLAUDE.md`` and ``docs/METHOD.md`` saying so.
A signal nobody reads is not a signal, and this is the other half.

THE DEFECT IT EXISTS FOR, measured on PR 669. That pull request entered the merge queue and was
ejected, twice, while **its own required contexts were green on the PR page**. The failures were in
``merge_group`` runs -- the branch merged with ``main``, a different set of runs the PR page does not
surface at all. Three full CI cycles were spent discovering that by hand. The attribution was
recoverable from the API the whole time; nothing asked.

WHAT THIS PRINTS that ``gh pr view`` structurally cannot: for each labelled pull request, the newest
FAILING run attributed to it, marked ``[merge_group]`` when the run is one the PR page cannot show.
That mark is the finding, not decoration -- it is the difference between "your change is broken" and
"your change conflicts with what landed since", and the PR page renders the second as green.

TWO RULES ARE COPIED FROM THE WRITER ON PURPOSE, because a reader that classifies differently from
the writer reports causes the label was never applied for:

  * **The watched workflows** (``_WATCHED``) match ``failure-signal.yml``'s ``workflows:`` list. CLA
    Assistant is excluded there, deliberately, and so is excluded here.
  * **Only ``failure`` counts** (``_RED``). A CANCELLED run is not a red -- branch protection gates on
    the latest head, so a cancelled predecessor says nothing about the current one. Counting it would
    misattribute every merge-queue ejection, which cancels its siblings on the way out.

AND THE ATTRIBUTION RULE IS THE WRITER'S, IN THE WRITER'S ORDER. ``pull_requests[0]`` where GitHub
supplies it; otherwise the ``pr-<N>-`` parse off the ref, **gated on ``event == "merge_group"``**.
That gate is a security control, not a tidiness one: a branch name is chosen by whoever opened the
branch, and a fork cannot produce a ``merge_group`` event. A ref named ``pr-999-whatever`` on any
other event resolves to nothing here, exactly as it does in the workflow.

A LABELLED PULL REQUEST WITH NO FAILING RUN IS REPORTED, NOT DROPPED. It reads ``UNATTRIBUTED``. The
common cause is benign -- the run aged out of the API window, or the label outlived the run it was
applied for -- but "I could not attribute this" must never render as "this is fine", which is the
defect class this whole signal chain exists to close.

USAGE
    python scripts/ci/report_ci_red.py                       # uses gh's auth
    python scripts/ci/report_ci_red.py --repo owner/name
    python scripts/ci/report_ci_red.py --warn-only           # report, always exit 0
    python scripts/ci/report_ci_red.py \\
        --prs-json prs.json --runs-json runs.json            # offline/testing

EXIT
    0  nothing carries the label (or --warn-only)
    1  at least one pull request carries it -- there is a red to attribute
    2  the query itself failed; fail closed rather than report a clean repo
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

#: The label ``failure-signal.yml`` applies. One string, so the reader and any future writer edit
#: cannot silently disagree about which label is being talked about.
CI_RED_LABEL = "ci-red"

#: Workflows whose failure earns the label. Mirrors ``failure-signal.yml``'s ``workflows:`` list --
#: see the module docstring for why CLA Assistant is not in it.
_WATCHED = frozenset({"CI", "Security", "CodeQL", "backlog-hygiene"})

#: The only conclusion that is a red. Mirrors the writer's ``conclusion == 'failure'`` gate.
_RED = "failure"

#: ``gh-readonly-queue/<base>/pr-<N>-<sha>``. Anchored on a path segment so a branch merely CONTAINING
#: the text (``feature/pr-12-notes``) cannot match -- and read only for a ``merge_group`` run anyway.
_MERGE_QUEUE_REF = re.compile(r"(?:\A|/)pr-(\d+)-[0-9a-f]+\Z")

#: The pull-request fields this reader needs. Beside the parser so the two cannot drift.
PR_FIELDS = "number,title,state,headRefName"


@dataclass(frozen=True)
class Red:
    """One pull request carrying the label, and the run it was earned by (if that is recoverable)."""

    number: int
    title: str
    run_name: str | None = None
    run_event: str | None = None
    run_url: str | None = None
    created_at: str | None = None

    @property
    def attributed(self) -> bool:
        return self.run_name is not None

    @property
    def hidden_from_the_pr_page(self) -> bool:
        """True when the run is one the pull request's own checks list does not show.

        This is the whole point of the report. A ``merge_group`` run tests the branch MERGED WITH the
        base, which is not the head the PR page reports on, so the page can read fully green while
        this is the thing blocking the merge.
        """
        return self.run_event == "merge_group"

    def line(self) -> str:
        # ASCII only: this lands in operator consoles whose code page is cp1252, where a non-ASCII
        # dash renders as a replacement character.
        if not self.attributed:
            return (
                f"#{self.number} {self.title[:60]} -- UNATTRIBUTED: no failing run for this pull "
                f"request in the window queried (aged out, or the label outlived its run)"
            )
        where = (
            " [merge_group -- NOT VISIBLE ON THE PR PAGE]" if self.hidden_from_the_pr_page else ""
        )
        return f"#{self.number} {self.title[:60]} -- {self.run_name} failed{where} {self.run_url}"


def _pr_for_run(run: dict[str, object]) -> int | None:
    """The pull request a run belongs to, by the writer's rule in the writer's order.

    Returns ``None`` rather than guessing. In particular a ``pr-<N>-`` ref on any event other than
    ``merge_group`` resolves to ``None``: that ref is only trustworthy because a fork cannot raise a
    ``merge_group`` event, and dropping the gate would let a branch name anybody can choose steer the
    attribution.
    """
    supplied = run.get("pull_requests")
    if isinstance(supplied, list) and supplied:
        first = supplied[0]
        if isinstance(first, dict) and isinstance(first.get("number"), int):
            return int(first["number"])
    if str(run.get("event") or "") != "merge_group":
        return None
    found = _MERGE_QUEUE_REF.search(str(run.get("head_branch") or ""))
    return int(found.group(1)) if found else None


def attribute(prs: list[dict[str, object]], runs: list[dict[str, object]]) -> list[Red]:
    """Join labelled pull requests to the newest failing run of a watched workflow.

    Pure: no network, no git. The CLI supplies both payloads so tests drive THIS function rather than
    a re-implementation of the rule -- a test asserting a copy of the rule proves nothing about the
    rule. Ordering is newest-run-first by ``created_at``; a run with no timestamp sorts last rather
    than being dropped.
    """
    newest: dict[int, dict[str, object]] = {}
    for run in runs:
        if not isinstance(run, dict):
            continue
        if str(run.get("name") or "") not in _WATCHED:
            continue
        if str(run.get("conclusion") or "").lower() != _RED:
            continue
        number = _pr_for_run(run)
        if number is None:
            continue
        stamp = str(run.get("created_at") or "")
        held = newest.get(number)
        if held is None or stamp > str(held.get("created_at") or ""):
            newest[number] = run

    found: list[Red] = []
    for pr in prs:
        if not isinstance(pr, dict):
            continue
        raw = pr.get("number")
        # Narrow rather than coerce: a surprising payload must become a finding, never a crash.
        number = raw if isinstance(raw, int) else 0
        run = newest.get(number)
        found.append(
            Red(
                number=number,
                title=str(pr.get("title") or ""),
                run_name=str(run.get("name") or "") if run else None,
                run_event=str(run.get("event") or "") if run else None,
                run_url=str(run.get("html_url") or "") if run else None,
                created_at=str(run.get("created_at") or "") if run else None,
            )
        )
    return sorted(found, key=lambda r: r.number, reverse=True)


def _gh(cmd: list[str]) -> object:
    # B603: fixed argv, no shell. The only variable element is --repo, an operator-typed CLI argument.
    # Same posture as check_stalled_prs.py; see the note there.
    out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, operator-supplied repo
        cmd, capture_output=True, text=True, timeout=180
    )
    if out.returncode != 0:
        raise RuntimeError(
            f"{cmd[0]} {cmd[1]} failed ({out.returncode}): {out.stderr.strip()[:400]}"
        )
    return json.loads(out.stdout)


def _fetch_prs(repo: str | None) -> list[dict[str, object]]:
    cmd = ["gh", "pr", "list", "--label", CI_RED_LABEL, "--state", "open"]
    cmd += ["--limit", "100", "--json", PR_FIELDS]
    if repo:
        cmd += ["--repo", repo]
    payload = _gh(cmd)
    return [p for p in payload if isinstance(p, dict)] if isinstance(payload, list) else []


def _fetch_runs(repo: str | None) -> list[dict[str, object]]:
    slug = repo or ":owner/:repo"
    # per_page=100 deliberately: any gh api list route DEFAULTS TO 30, and a reader that silently
    # cannot see two thirds of its own corpus reports a clean repo. (BACKLOG #1385's own notes record
    # a session that concluded a label had never been re-applied off exactly that truncation.)
    cmd = ["gh", "api", f"repos/{slug}/actions/runs?status=failure&per_page=100"]
    payload = _gh(cmd)
    if not isinstance(payload, dict):
        return []
    runs = payload.get("workflow_runs")
    return [r for r in runs if isinstance(r, dict)] if isinstance(runs, list) else []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo", default=None, help="owner/name; defaults to gh's current repo")
    parser.add_argument("--prs-json", type=Path, default=None, help="a saved payload (testing)")
    parser.add_argument("--runs-json", type=Path, default=None, help="a saved payload (testing)")
    parser.add_argument(
        "--warn-only", action="store_true", help="report and exit 0 rather than 1 on a finding"
    )
    args = parser.parse_args(argv)

    try:
        if args.prs_json is not None:
            loaded = json.loads(args.prs_json.read_text(encoding="utf-8"))
            prs = [p for p in loaded if isinstance(p, dict)] if isinstance(loaded, list) else []
        else:
            prs = _fetch_prs(args.repo)
        if args.runs_json is not None:
            loaded = json.loads(args.runs_json.read_text(encoding="utf-8"))
            runs = [r for r in loaded if isinstance(r, dict)] if isinstance(loaded, list) else []
        else:
            runs = _fetch_runs(args.repo) if prs else []
    except (RuntimeError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
        # FAIL CLOSED. "I could not ask" must never render as "nothing is red" -- that is this
        # script's own defect class, one level up.
        print(f"::error::could not read the {CI_RED_LABEL} state ({exc!r}). Treating as a FAILURE.")
        return 2

    # Liveness receipt: say what was EXAMINED. "nothing is red" and "the query returned nothing"
    # are otherwise indistinguishable from the exit code alone.
    # "run(s)", not "failing run(s)": the live fetch asks for status=failure, but --runs-json takes
    # whatever the caller supplies, and a receipt must not assert a property of its input it did not
    # check. `attribute` applies the conclusion filter itself.
    print(
        f"ci-red: {len(prs)} open pull request(s) carry {CI_RED_LABEL}; "
        f"scanned {len(runs)} run(s) for attribution"
    )
    if not prs:
        print("ci-red: no pull request is carrying a red.")
        return 0

    reds = attribute(prs, runs)
    for red in reds:
        print(f"::warning::{red.line()}")

    hidden = [r for r in reds if r.hidden_from_the_pr_page]
    if hidden:
        print(
            f"::error::{len(hidden)} pull request(s) were reddened by a merge_group run. Their own "
            "checks can read GREEN on the PR page: a merge-queue run tests the branch MERGED WITH the "
            "base, which is not the head the page reports on. Read the run linked above, not the PR's "
            "check list -- re-queueing without reading it spends a full CI cycle to learn nothing."
        )
    return 0 if args.warn_only else 1


if __name__ == "__main__":
    raise SystemExit(main())
