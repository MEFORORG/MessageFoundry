#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A pull request can be finished, green and unread, and nothing anywhere says so.

THE DEFECT THIS EXISTS FOR (BACKLOG #1413). ``a reviewer has read this`` became a required context on
2026-08-31. It is fail-closed and correct: a brand-new pull request starts blocked, and the only way
past it is ``gh pr edit <N> --add-label reviewed``. Nothing automated ever adds that label, which is
the design. The missing half is the OTHER side -- nothing tells anyone the pull request is waiting.
BACKLOG #1413 carries the census that establishes it, with its positive control; it is not restated
here, because a count of workflow files goes stale the moment one is added.

WHY THE OBVIOUS SIGNALS DO NOT COVER IT.

* ``.github/CODEOWNERS`` routes every path to one account, and GitHub does not request review from a
  pull request's own AUTHOR. Nearly every pull request here is self-authored by that same account, so
  the routing that works on a dependabot pull request is inert on ours.
* ``check_stalled_prs.py`` keys its daily report on ``mergeStateStatus == BEHIND``. An unread pull
  request reads ``BLOCKED``, so it falls outside that report entirely.
* An approval gate cannot substitute. Every session on this machine pushes as one GitHub identity, and
  GitHub will not let an author approve their own pull request, so
  ``required_approving_review_count: 1`` would wedge every pull request permanently.

THE SIGNATURE, and every field in it was chosen to dodge a specific trap::

    state OPEN  AND  not draft  AND  mergeable != CONFLICTING
      AND  the `reviewed` label is ABSENT  (read LIVE, from the pull request)
      AND  the rollup MINUS the review gate's own context is non-empty, all settled, all green

TRAP 1 -- ``mergeStateStatus`` IS NEVER READ, AND THAT IS THE POINT. GitHub returns ONE value with
precedence, so ``BEHIND``, ``DIRTY`` and ``UNSTABLE`` each mask a missing required check. A seat
triaging on that field sees ``BEHIND``, runs ``gh pr update-branch``, fires ``synchronize`` -- which
STRIPS the label -- and only then does the pull request flip to ``BLOCKED``. The requirement is
invisible until you act on something else. So the field is not merely ignored here: it is absent from
:data:`PR_FIELDS`, so this check cannot read it even by accident, and
``tests/test_unread_prs.py`` pins that absence.

TRAP 2 -- THE REVIEW GATE'S OWN CONCLUSION IS NOT EVIDENCE EITHER, IN EITHER DIRECTION. It is excluded
from the rollup and the label is read directly instead.

* RED gate, label present: a reviewer labelled the pull request and the job has not re-run yet.
  Reading the gate would report a read pull request as unread.
* GREEN gate, label ABSENT: review-gate.yml line 105 evaluates
  ``github.event.pull_request.labels`` -- the EVENT PAYLOAD, captured when the run was queued, not the
  live pull request. A ``labeled`` run that queues behind a ``synchronize`` run therefore starts stale
  and can pass on state that no longer holds, and the removal that invalidated it was made with
  ``GITHUB_TOKEN``, which by GitHub's own rule triggers no further workflow run to correct it.
  BACKLOG #1423 and PR 783 fix that inside the gate. This check does not wait for that fix and is not
  affected by it: the LIVE label is the only reliable read of whether a pull request was marked read,
  so that is what this reads.

WHAT THIS DELIBERATELY DOES NOT CHECK. Whether the required SET is complete. That is branch
protection's server-side answer and ``.github/required-contexts.txt`` is only the checked-in claim
about it; conflating the two would import a drift defect that has its own item. What is asserted here
is narrower and true: everything that reported is green, and something did report.

WHAT IT DOES NOT DO. Apply the ``reviewed`` label. That is the fail-open design the gate's author
already rejected -- a gate whose safe state depends on another workflow having succeeded is not a
gate -- and the reasoning is in ``.github/workflows/review-gate.yml``'s own header.

USAGE
    python scripts/ci/check_unread_prs.py --pr 731 --repo owner/name
    python scripts/ci/check_unread_prs.py --pr-json pr.json --body-out c.md   # offline/testing
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
from scripts.ci._pr_checks import counts, name_of  # noqa: E402

#: The label a reviewer adds. Set by hand, never by a workflow. Removed on `synchronize`.
REVIEWED_LABEL = "reviewed"

#: The label this check adds. It carries the same fact the comment carries, in the form a SEAT can
#: consume: `gh pr list --label unread` finds every pull request in this state in ONE call. Named for
#: the STATE and not for a person, because the `reviewed` label is a PROCESS gate -- it records that a
#: step happened, and neither label may be described as establishing that an independent party looked.
#:
#: WHAT WITHDRAWS IT, because the comment body promises this to a reader and a promise that stops
#: being true is worse than none. `.github/workflows/unread-signal.yml` evaluates on two edges: a
#: watched workflow COMPLETING, and a pull request being LABELLED or UNLABELLED. Between
#: 2026-09-04 and this line the second edge did not exist -- `review gate` was the only watched
#: workflow firing on a label event and it was deleted with the reviewer requirement -- and the
#: comment claimed automatic withdrawal anyway. The measurement that caught it is recorded on the
#: trigger list in that workflow, at the arm that fixed it, rather than restated here.
UNREAD_LABEL = "unread"

#: The review gate's own status-check context. Excluded from the rollup -- see TRAP 2 above. This is
#: the job `name:` in .github/workflows/review-gate.yml, which is what branch protection matches.
REVIEW_GATE_CONTEXT = "a reviewer has read this"

#: The fields fetched. `mergeStateStatus` IS DELIBERATELY ABSENT (TRAP 1) and a test holds it out.
#: `mergeable` is the orthogonal read -- MERGEABLE / CONFLICTING / UNKNOWN, independent of check state.
PR_FIELDS = "number,title,url,state,isDraft,mergeable,labels,statusCheckRollup,headRefName"

#: What the caller should do. The workflow branches on these and performs the writes itself, so every
#: mutation is visible in the workflow file rather than buried in a script.
FLAG = "flag"  # matches the signature and is not flagged yet -> label it and say so
KEEP = "keep"  # matches, already flagged -> nothing (this is what makes the comment fire ONCE)
CLEAR = "clear"  # no longer matches but is still flagged -> withdraw the label
NONE = "none"  # does not match, not flagged -> nothing


def labels_of(pr: dict[str, object]) -> set[str]:
    """The label names on a pull request payload, read LIVE rather than from an event payload."""
    raw = pr.get("labels")
    if not isinstance(raw, list):
        return set()
    return {str(n.get("name") or "") for n in raw if isinstance(n, dict)}


def is_unread(pr: dict[str, object]) -> bool:
    """Does this pull request match the green-mergeable-unread signature?

    Pure: no network, no git. The CLI supplies the payload so tests drive THIS function rather than a
    re-statement of the rule -- a test asserting a copy of the rule proves nothing about the rule.
    """
    if str(pr.get("state") or "").upper() != "OPEN":
        return False
    if pr.get("isDraft") is True:
        return False
    # Only CONFLICTING suppresses. UNKNOWN means GitHub has not computed it yet, and this check errs
    # toward REPORTING: failing to report returns the silence this whole script exists to end, while a
    # spurious report costs one reader one glance.
    if str(pr.get("mergeable") or "").upper() == "CONFLICTING":
        return False
    if REVIEWED_LABEL in labels_of(pr):
        return False

    rollup = pr.get("statusCheckRollup")
    others = (
        [n for n in rollup if name_of(n) != REVIEW_GATE_CONTEXT] if isinstance(rollup, list) else []
    )
    # A rollup that is empty once the gate is removed means nothing has REPORTED yet -- a pull request
    # opened seconds ago, not a green one. Silence is not success, which is the same rule
    # check_stalled_prs.py applies to a zero-length pull request list.
    if not others:
        return False
    failing, unsettled = counts(others)
    return failing == 0 and unsettled == 0


def decide(pr: dict[str, object]) -> str:
    """One of :data:`FLAG`, :data:`KEEP`, :data:`CLEAR`, :data:`NONE`.

    The flag label doubles as the idempotency token: the comment is written only on the FLAG
    transition, so a pull request is announced once per unread episode rather than once per run.
    """
    flagged = UNREAD_LABEL in labels_of(pr)
    if is_unread(pr):
        return KEEP if flagged else FLAG
    return CLEAR if flagged else NONE


def root_owners(codeowners: str) -> list[str]:
    """The handles on the catch-all ``*`` rule of a CODEOWNERS file, de-duplicated, in file order.

    DERIVED RATHER THAN HARDCODED, because that is the behaviour the repository already wants. Add a
    second maintainer to CODEOWNERS -- which GOVERNANCE.md and MAINTAINERS.md both anticipate -- and
    the mention widens with no edit here and nothing to go stale. CODEOWNERS is LAST-match-wins, so
    the last catch-all rule is the one that governs.
    """
    winner: list[str] = []
    for line in codeowners.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        parts = stripped.split()
        if parts[0] != "*":
            continue
        winner = [p for p in parts[1:] if p.startswith("@")]
    return list(dict.fromkeys(winner))


def comment_body(pr: dict[str, object], repo: str, owners: list[str]) -> str:
    """The notification. ASCII only, no glyphs -- CLAUDE.md section 11.

    THIS HALF IS THE PUSH AND THE LABEL IS NOT, and the two must not be described as one thing.
    ``failure-signal.yml`` states the same distinction for ``ci-red``: a label collapses "fetch a
    rollup per pull request" into "list pull requests carrying one label", which makes a poll
    affordable, but GitHub still cannot reach into a session. A COMMENT does reach a person -- it
    notifies everyone subscribed to the pull request, and the mention additionally raises it to
    GitHub's `mention` reason, which survives a participating-only notification filter.
    """
    number = pr.get("number")
    mention = f"{' '.join(owners)}\n\n" if owners else ""
    return f"""{mention}This pull request is green and nobody has marked it read.

Every check that has reported is passing and the `{REVIEWED_LABEL}` label is absent, so
`{REVIEW_GATE_CONTEXT}` is the only thing between it and a merge. Nothing else reports that, which is
why this comment exists (BACKLOG #1413).

To clear it, IN THIS ORDER:

1. If the branch is behind `main`, update it FIRST: `gh pr update-branch --repo {repo} {number}`.
   That push fires `synchronize`, and `synchronize` REMOVES the `{REVIEWED_LABEL}` label. Labelling
   before updating throws the label away and costs a round trip.
2. Read the diff.
3. `gh pr edit {number} --repo {repo} --add-label {REVIEWED_LABEL}`

DO NOT TRIAGE THIS FROM `mergeStateStatus`. It returns one value with precedence, so `BEHIND`,
`DIRTY` and `UNSTABLE` each mask the missing check -- the requirement is invisible until you act on
something else. This check never reads that field; see `scripts/ci/check_unread_prs.py`.

A seat can find every pull request in this state in one call: `gh pr list --label {UNREAD_LABEL}`.

Adding `{REVIEWED_LABEL}` withdraws `{UNREAD_LABEL}`: the label event re-evaluates this pull request,
and so does the next completion of a watched workflow. Those are the two edges that clear it, so a
change neither of them reports -- converting to a draft, say -- can leave the label standing until one
of them next happens.

The `{REVIEWED_LABEL}` label is a PROCESS gate. It records that a step happened. It does not
establish that an independent party looked, and nothing here should be read as saying it does.
"""


def _fetch(
    repo: str | None, pr: str | None, pr_json: Path | None, attempts: int, delay: float
) -> dict[str, object]:
    """The pull request payload, re-read until its rollup settles or the budget runs out.

    WHY THE RETRY. This runs from a `workflow_run` completion, and the rollup can still report the
    run that JUST finished as in progress for a few seconds. Without a wait, the LAST workflow to
    finish -- the one whose completion makes the pull request green -- is exactly the evaluation most
    likely to lose the race, and then nobody signals. Every watched workflow triggers an evaluation,
    so an earlier miss is usually covered; the last one has nothing behind it.

    A still-unsettled rollup after the budget is NOT an error. It means the suite is genuinely mid-
    flight, which is the normal path to green, and the next completion evaluates again.
    """
    if pr_json is not None:
        payload = json.loads(pr_json.read_text(encoding="utf-8"))
        return dict(payload) if isinstance(payload, dict) else {}

    cmd = ["gh", "pr", "view", str(pr), "--json", PR_FIELDS]
    if repo:
        cmd += ["--repo", repo]
    last: dict[str, object] = {}
    for attempt in range(max(1, attempts)):
        if attempt:
            time.sleep(delay)
        # B603: fixed argv, no shell. The variable elements are CLI arguments supplied on a CI runner
        # -- not message, config, or network data. Same posture as check_stalled_prs.py.
        out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, operator-supplied
            cmd, capture_output=True, text=True, timeout=180
        )
        if out.returncode != 0:
            raise RuntimeError(f"gh pr view failed ({out.returncode}): {out.stderr.strip()[:400]}")
        payload = json.loads(out.stdout)
        last = dict(payload) if isinstance(payload, dict) else {}
        rollup = last.get("statusCheckRollup")
        others = (
            [n for n in rollup if name_of(n) != REVIEW_GATE_CONTEXT]
            if isinstance(rollup, list)
            else []
        )
        if others and counts(others)[1] == 0:
            return last
        print(f"rollup not settled yet (attempt {attempt + 1} of {max(1, attempts)})")
    return last


def _emit(**outputs: str) -> None:
    """Write step outputs for the workflow, and always print them so a log reader sees the same."""
    for key, value in outputs.items():
        print(f"{key}={value}")
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            handle.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--pr", default=None, help="pull request number")
    parser.add_argument("--repo", default=None, help="owner/name; defaults to gh's current repo")
    parser.add_argument("--pr-json", type=Path, default=None, help="a saved payload (testing)")
    parser.add_argument("--codeowners", type=Path, default=_ROOT / ".github" / "CODEOWNERS")
    parser.add_argument("--body-out", type=Path, default=None, help="where to write the comment")
    parser.add_argument("--settle-attempts", type=int, default=4)
    parser.add_argument("--settle-seconds", type=float, default=20.0)
    args = parser.parse_args(argv)

    if args.pr is None and args.pr_json is None:
        parser.error("one of --pr or --pr-json is required")

    try:
        pr = _fetch(args.repo, args.pr, args.pr_json, args.settle_attempts, args.settle_seconds)
    except (RuntimeError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
        # LOUD, not silent. "I could not read the pull request" must never render as "it is fine" --
        # this script's whole subject is a state that is already invisible.
        print(f"::error::could not read the pull request ({exc!r}).", file=sys.stderr)
        return 2

    if not pr:
        print("::error::empty pull request payload. Refusing to report a verdict.", file=sys.stderr)
        return 2

    action = decide(pr)
    number = pr.get("number")
    print(f"unread-signal: pull request {number} -> {action}")

    if action == FLAG and args.body_out is not None:
        owners: list[str] = []
        try:
            owners = root_owners(args.codeowners.read_text(encoding="utf-8"))
        except OSError as exc:
            # Degrade, do not fail: a comment with no mention still notifies the pull request's
            # subscribers. Say so, so a missing mention is never mistaken for nobody being assigned.
            print(f"::warning::could not read {args.codeowners} ({exc!r}); commenting unmentioned.")
        args.body_out.write_text(
            comment_body(pr, str(args.repo or ""), owners), encoding="utf-8", newline="\n"
        )

    _emit(action=action, number=str(number if isinstance(number, int) else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
