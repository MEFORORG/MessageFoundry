#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Remove ``ci-red`` where the pull request's OWN head now says it is earned by nothing.

``failure-signal.yml`` writes the label. ``scripts/ci/report_ci_red.py`` reads it back. NOTHING has
ever removed it -- measured 2026-09-17, a repo-wide grep for ``remove-label``/``removeLabel``/
``remove_label`` over ``.github`` and ``scripts`` returns one hit, the vendored CLA Octokit route
table, which is not a caller. That is the defect this closes, and it closes it by READING STATE
rather than by reacting to a success.

WHY NOT A SUCCESS ARM ON failure-signal.yml, WHICH IS THE OBVIOUS FIX. A ``workflow_run`` event
carries ONE workflow. Three are watched and FIFTEEN contexts are required, nine of them from
``security.yml`` alone, so a Security success is not evidence about CI -- measured over
2026-09-10..16, 190 of 921 distinct ``(event, head_sha)`` groups had one watched workflow succeed
while another failed on the same head. Completions are not ordered. The event's ``head_sha`` is often
not the pull request's head: 29 percent of successful ``pull_request`` runs attributable to a
still-open pull request sat on a sha that pull request had already left. And a merge-queue ejection
reds a pull request whose OWN HEAD IS GREEN, so no success on that head can ever refute it. A success
arm has to answer all four from a payload that knows none of them. This asks the head instead, in one
snapshot, where the answer is settled.

WHY IT IS RUN BY HAND AND NOT ON A CRON. Proportion, measured. 2026-09-17 against the live
repository: 20 of 40 open pull requests carry the label, 17 have a required context FAILING on their
current head right now, one is a live merge-queue ejection, and THREE are clearable. The label is not
noisy -- it is UNCLEARABLE, over a standing population of three. A scheduled writer would be the only
``pull-requests: write`` job in this repository running on a timer, and it would carry a checkout, a
Python install and a circuit breaker to clear three labels that gate nothing. Arm one when the
measured clearable population justifies it; this is sized to today's.

WHAT IT CLEARS -- all of these together, and every one fails CLOSED:

  1. The pull request is OPEN and carries the label.
  2. Every context in ``.github/required-contexts.txt`` is present on the pull request's CURRENT head
     as a check run that is ``completed`` AND concluded ``success``. Not "no failures": absent,
     queued, in_progress, cancelled, neutral, skipped and stale all keep the label.
     ``.github/required-contexts.txt`` and ``failure-signal.yml`` both record that a cancelled run is
     not a green one. This is deliberately STRICTER than branch protection, which counts ``neutral``
     and ``skipped`` as passing: a check that did not run is not evidence that anything passed, and
     this script removes a red signal on the strength of the answer.
  3. No merge-queue ejection stands against the current head -- no ``removed_from_merge_queue`` event
     and no ``failure-signal.yml`` ejection comment dated after the head was first seen.

WHY THE EJECTION LATCH READS THE TIMELINE AND NOT ``?status=failure``. Both timeline records are
DURABLE. A run's ``conclusion`` is MUTABLE: re-running a failed run overwrites it, so the run drops
out of ``actions/runs?status=failure`` entirely -- measured on run 35141892251, absent from that
filter today while ``attempts/1`` still reads ``conclusion=failure``. An ejection latch built on that
filter releases the moment somebody re-runs the ejecting job, which destroys exactly the signal
BACKLOG #1403 built. A timeline event and a bot comment survive a re-run.

AND THE RELEASE CONDITION IS "THE HEAD MOVED PAST IT", WHICH IS A HEURISTIC AND IS NAMED AS ONE. The
queue tests the branch MERGED WITH the base, which is not the head the pull request page reports on,
so no run on the head can retire an ejection. What retires it is the head no longer being the head
that was ejected -- evidence the ejection's subject is gone, NOT proof the author fixed it. The queue
re-tests on re-queue either way. The queue's merge commit is squashed (measured: 6fb06529 has one
parent), so the ejected head is not recoverable from it and no exact linkage exists.

WHAT IT DELIBERATELY DOES NOT DO:

  * It does not touch ``failure-signal.yml``. No new job, trigger, token, ``uses:`` or ``${{ }}``
    site, so the four claims ``.github/zizmor.yml`` makes about that file -- every one of them
    evidenced by a test scoped to ``jobs.signal`` -- stay exactly as true as they are today.
  * It does not attribute the red to a RUN, so it does not inherit ``report_ci_red.py``'s single
    unpaginated ``?status=failure`` window. That window is why PR 1212 reads ``UNATTRIBUTED`` there
    for a label that is real and precisely explicable; this clears 1212 without naming the run.
  * It does not compare-and-swap on the label's timestamp. Measured 2026-09-17: PR 1151 took THREE
    attributed watched failures and carries exactly ONE ``labeled ci-red`` timeline event, because
    ``gh pr edit --add-label`` on a label already present emits no event. A guard comparing
    ``max(labeled)`` before and after cannot fire for the only thing the writer ever does to an
    already-labelled pull request, and would read as protection while protecting nothing. The guard
    below re-derives the EVIDENCE instead.
  * It removes no label but the one string ``report_ci_red.CI_RED_LABEL``, and never touches a closed
    or merged pull request.
  * It does not use the search API. Measured 2026-09-16: a comment search for the ejection phrase
    returned ``total_count: 0`` while a direct read of PR 1229's comments returned the comment. The
    index lags, and a lagging index fails in the clearing direction.

USAGE
    python scripts/ci/clear_stale_ci_red.py --repo MEFORORG/MessageFoundry            # DRY RUN
    python scripts/ci/clear_stale_ci_red.py --repo MEFORORG/MessageFoundry --apply
    python scripts/ci/clear_stale_ci_red.py --repo MEFORORG/MessageFoundry --apply --only 1173

EXIT
    0  the dry run completed, or every clearable label was removed
    1  more labels were clearable than ``--max-removals``; NOTHING was removed
    2  a read failed. Fail closed: never report "nothing was stale" for a query that did not run.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_CONTEXTS_FILE = ROOT / ".github" / "required-contexts.txt"


def _load_reader() -> Any:
    """``scripts/`` is not a package, so the sibling is imported by path."""
    target = Path(__file__).resolve().parent / "report_ci_red.py"
    spec = importlib.util.spec_from_file_location("report_ci_red", target)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("report_ci_red", module)
    spec.loader.exec_module(module)
    return module


#: The ONE label string, taken from the reader, which takes it from the writer. Never a literal here.
CI_RED_LABEL: str = _load_reader().CI_RED_LABEL

#: The stable clause of ``failure-signal.yml``'s ejection comment. The run NAME leads the real body
#: and varies, so the match is anchored on the part that does not.
EJECTION_PHRASE = "so the queue ejected it"

#: Timeline events that mean the merge queue touched this pull request.
_QUEUE_EVENTS = frozenset({"added_to_merge_queue", "removed_from_merge_queue"})

#: Items asked for in ONE page. The default is 30 and the heads here carry 41 to 85 check runs, so an
#: unpaginated read silently drops a third to two thirds of its own corpus.
PAGE: int = 100

#: A sha long enough to address a commit. ``?head_sha=<12 chars>`` returns ``total_count: 0`` rather
#: than an error, so a short sha anywhere in this chain reads as "no check runs on this head".
_FULL_SHA = re.compile(r"\A[0-9a-f]{40}\Z")

#: More than this in one pass is a classification bug, not a clean-up. Raise it deliberately.
MAX_REMOVALS: int = 10


class ReadFailed(RuntimeError):
    """A query did not run. Distinct from a query that ran and found nothing."""


def required_contexts(path: Path | None = None) -> list[str]:
    """The contexts recorded in ``.github/required-contexts.txt`` (comments and blanks stripped).

    Parsed here rather than imported from ``tests._workflow_contexts``, which owns the identical
    two-line parse: that module imports PyYAML at module scope and falls back to importing pytest,
    and this script has to run from a checkout with neither. The copy is PINNED instead --
    ``test_the_required_set_this_script_reads_is_the_checked_in_one`` compares the two readers, so a
    drift reds rather than passing quietly.
    """
    lines = (path or REQUIRED_CONTEXTS_FILE).read_text(encoding="utf-8").splitlines()
    return [s for line in lines if (s := line.strip()) and not s.startswith("#")]


def _gh(cmd: list[str]) -> object:
    # B603: fixed argv, no shell. The only variable element is --repo, an operator-typed argument.
    out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, operator-supplied repo
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300
    )
    if out.returncode != 0:
        raise ReadFailed(
            f"{' '.join(cmd[:3])} failed ({out.returncode}): {out.stderr.strip()[:300]}"
        )
    return json.loads(out.stdout or "null")


def _pages(repo: str | None, route: str, key: str | None = None) -> list[dict[str, object]]:
    """Every item of one FULLY PAGINATED list route.

    ``--slurp`` makes ``--paginate`` emit an ARRAY OF PAGES, which is the only form that parses.
    Note that gh REFUSES ``--slurp`` together with ``--jq`` (measured on gh 2.93.0), so the filtering
    happens here rather than in the query.

    TWO PAGE SHAPES come back through the same paginator and both must be handled: an OBJECT wrapping
    a named array (``check-runs`` -> ``check_runs``) and a BARE ARRAY (``issues/<n>/timeline``). A
    helper that handles only the first returns NOTHING for the timeline, which reads as "this pull
    request was never ejected" -- the clearing direction.

    A route that yields no pages RAISES. An empty answer from a list endpoint is a failed read here,
    never a fact about the repository.
    """
    slug = repo or ":owner/:repo"
    payload = _gh(["gh", "api", "--paginate", "--slurp", f"repos/{slug}/{route}"])
    if not isinstance(payload, list) or not payload:
        raise ReadFailed(f"{route} returned no pages; an unread route is a failure, not an absence")
    found: list[dict[str, object]] = []
    for page in payload:
        block = page if isinstance(page, list) else ((page.get(key) or []) if key else [])
        found.extend(item for item in block if isinstance(item, dict))
    return found


def newest_by_name(check_runs: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    """The check run that SPEAKS FOR each context name on a head.

    TWO RULES, AND THE FIRST IS THE ONE THAT MATTERS. An UNSETTLED run of a name beats a settled one
    outright, whatever the timestamps say. A head can carry two concurrent, non-cancelled runs of the
    same watched workflow -- measured 2026-09-17 on the head shared by PRs 1226 and 1241, which
    carried two CI runs created 35 seconds apart whose durations differed by 67, so the
    EARLIER-created one finished LAST. Picking "the newest" there can read a still-running leg as
    green. Second, among runs in the same settled state, the greatest ``started_at`` wins; a run with
    no timestamp loses to one that has a timestamp rather than winning by arriving last.

    LIST ORDER IS NEVER USED. The GraphQL ``statusCheckRollup`` sibling is measurably not ordered by
    ``startedAt`` -- on this repository's own PR 1226, a later entry carried an OLDER settled success
    while an earlier entry carried the newer in-flight re-run -- and this endpoint promises no order
    either.
    """
    speaks: dict[str, dict[str, object]] = {}
    for run in check_runs:
        name = str(run.get("name") or "")
        if not name:
            continue
        held = speaks.get(name)
        if held is None:
            speaks[name] = run
            continue
        run_unsettled = run.get("status") != "completed"
        held_unsettled = held.get("status") != "completed"
        started_later = str(run.get("started_at") or "") > str(held.get("started_at") or "")
        unsettled_wins = run_unsettled and not held_unsettled
        if unsettled_wins or (run_unsettled == held_unsettled and started_later):
            speaks[name] = run
    return speaks


def unmet_contexts(speaks: dict[str, dict[str, object]], required: list[str]) -> list[str]:
    """Every required context that is NOT a settled success, as ``name=state`` strings."""
    unmet: list[str] = []
    for context in required:
        run = speaks.get(context)
        if run is None:
            unmet.append(f"{context}=ABSENT")
        elif run.get("status") != "completed":
            unmet.append(f"{context}={run.get('status')}")
        elif run.get("conclusion") != "success":
            unmet.append(f"{context}={run.get('conclusion')}")
    return unmet


def head_seen_at(check_runs: list[dict[str, object]], git_date: str) -> str:
    """The EARLIEST moment this head is known to have existed.

    The MINIMUM of the git committer date and the earliest check-run start, and both directions
    matter. The git date is written by whoever made the commit, so a forward-dated commit alone would
    make a stale head look newer than the ejection holding its label. A "re-run all jobs" pushes every
    check-run start forward, so that alone would make an old head look new. Taking the minimum means
    BOTH would have to move, and either one alone holds the latch.
    """
    starts = [str(c.get("started_at") or "") for c in check_runs if c.get("started_at")]
    stamps = [s for s in (git_date, min(starts) if starts else "") if s]
    return min(stamps) if stamps else ""


def queue_evidence(events: list[dict[str, object]], since: str) -> list[str]:
    """Every sign the merge queue reddened this head, at or after ``since``. Empty means none.

    A MISSING timestamp counts as evidence rather than as absence: an event this script cannot place
    in time is one it cannot rule out.
    """
    found: list[str] = []
    for event in events:
        kind = str(event.get("event") or "")
        stamp = str(event.get("created_at") or "")
        placed = (not stamp) or stamp >= since
        if not placed:
            continue
        if kind in _QUEUE_EVENTS:
            found.append(f"{kind} at {stamp or 'an unreadable time'}")
        elif kind == "commented" and EJECTION_PHRASE in str(event.get("body") or ""):
            found.append(f"ejection comment at {stamp or 'an unreadable time'}")
    return found


def assess(repo: str | None, number: int, required: list[str]) -> tuple[bool, str, str]:
    """``(clearable, reason, fingerprint)`` for one labelled pull request. Every read happens here.

    The FINGERPRINT is the whole basis of the decision reduced to a comparable string: the head, the
    check run that speaks for each required context and what it concluded, when the head was first
    seen, and the standing queue evidence. It is what the pre-write pass re-derives -- see
    :func:`_remove`.
    """
    view = _gh(
        ["gh", "pr", "view", str(number), "--json", "number,state,labels,headRefOid"]
        + (["--repo", repo] if repo else [])
    )
    if not isinstance(view, dict):
        raise ReadFailed(f"pr view {number} did not return an object")
    if view.get("state") != "OPEN":
        return False, f"the pull request is {view.get('state')}, not OPEN", ""
    if CI_RED_LABEL not in {str(lab.get("name")) for lab in view.get("labels") or []}:
        return False, f"it does not carry {CI_RED_LABEL}", ""

    head = str(view.get("headRefOid") or "")
    if not _FULL_SHA.match(head):
        raise ReadFailed(f"#{number} returned a head that is not a full sha: {head!r}")

    checks = _pages(repo, f"commits/{head}/check-runs?per_page={PAGE}", "check_runs")
    speaks = newest_by_name(checks)
    unmet = unmet_contexts(speaks, required)
    basis: dict[str, object] = {
        "head": head,
        "contexts": {
            c: [speaks[c].get("id"), speaks[c].get("status"), speaks[c].get("conclusion")]
            for c in required
            if c in speaks
        },
    }
    if unmet:
        shown = ", ".join(unmet[:3])
        more = f" (+{len(unmet) - 3} more)" if len(unmet) > 3 else ""
        return (
            False,
            f"{len(unmet)} of {len(required)} required context(s) are not a settled success on head "
            f"{head[:8]}: {shown}{more}",
            json.dumps(basis, sort_keys=True),
        )

    commit = _gh(["gh", "api", f"repos/{repo or ':owner/:repo'}/git/commits/{head}"])
    git_date = ""
    if isinstance(commit, dict) and isinstance(commit.get("committer"), dict):
        git_date = str(commit["committer"].get("date") or "")
    seen = head_seen_at(checks, git_date)
    if not seen:
        raise ReadFailed(f"#{number}: head {head[:8]} has no readable first-seen time")

    events = _pages(repo, f"issues/{number}/timeline?per_page={PAGE}")
    if not events:
        # Positive control. This pull request carries the label, so its timeline MUST hold the event
        # that applied it. An empty read is the paginator failing, not a history-less pull request.
        raise ReadFailed(f"issues/{number}/timeline returned no events for a labelled pull request")
    standing = queue_evidence(events, seen)
    basis["seen"] = seen
    basis["queue"] = standing
    fingerprint = json.dumps(basis, sort_keys=True)
    if standing:
        return (
            False,
            f"the merge queue reddened it and the head has NOT moved past that -- {standing[0]}, "
            f"head {head[:8]} first seen {seen}. Its own head being green is the DEFECT this label "
            "reports, not evidence against it (BACKLOG #1403): the queue tests the branch merged "
            "with the base, which is not the head the pull request page reports on",
            fingerprint,
        )

    return (
        True,
        f"all {len(required)} required context(s) are a settled success on head {head[:8]}, and no "
        f"merge-queue ejection stands against a head first seen {seen}",
        fingerprint,
    )


def _remove(repo: str | None, number: int, required: list[str], fingerprint: str) -> bool:
    """Re-derive the whole basis, then remove the label only if nothing moved.

    THE RACE THIS CLOSES AND THE ONE IT DOES NOT. GitHub's label API has no compare-and-swap, so a
    removal can land on a label re-applied after this pass decided. Comparing the label's own
    timestamp CANNOT detect that -- ``--add-label`` on a label already present emits no timeline
    event (measured: PR 1151, three attributed watched failures, one ``labeled`` event). So the guard
    re-reads the EVIDENCE instead: a new red on this head changes the check run that speaks for a
    required context, and a new ejection changes the queue list. The window shrinks from the whole
    pass to one round trip. It is not zero, and that residual is recorded rather than glossed.
    """
    clearable, reason, fresh = assess(repo, number, required)
    if not clearable or fresh != fingerprint:
        print(
            f"  REFUSE #{number}  the evidence moved between the decision and the write: {reason}"
        )
        return False
    out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
        ["gh", "pr", "edit", str(number), "--remove-label", CI_RED_LABEL]
        + (["--repo", repo] if repo else []),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    if out.returncode != 0:
        raise ReadFailed(
            f"gh pr edit {number} failed ({out.returncode}): {out.stderr.strip()[:300]}"
        )
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo", default=None, help="owner/name; defaults to gh's current repo")
    parser.add_argument("--apply", action="store_true", help="remove; without it this is a dry run")
    parser.add_argument(
        "--only", type=int, action="append", default=None, help="these numbers only"
    )
    parser.add_argument("--max-removals", type=int, default=MAX_REMOVALS)
    args = parser.parse_args(argv)

    try:
        required = required_contexts()
        if not required:
            raise ReadFailed(f"{REQUIRED_CONTEXTS_FILE.name} yielded no contexts")
        listed = _gh(
            ["gh", "pr", "list", "--state", "open", "--limit", "100", "--label", CI_RED_LABEL]
            + ["--json", "number"]
            + (["--repo", args.repo] if args.repo else [])
        )
        if not isinstance(listed, list):
            raise ReadFailed("gh pr list did not return an array")
        numbers = sorted((int(p["number"]) for p in listed if isinstance(p, dict)), reverse=True)
        if args.only:
            numbers = [n for n in numbers if n in set(args.only)]
        verdicts: list[tuple[int, bool, str, str]] = []
        for number in numbers:
            clearable, reason, fingerprint = assess(args.repo, number, required)
            verdicts.append((number, clearable, reason, fingerprint))
    except (ReadFailed, ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        # FAIL CLOSED, and note which direction that is HERE: a script that cannot read must remove
        # nothing. "I could not ask" renders as "I changed nothing", never as "nothing was stale".
        print(f"could not read the {CI_RED_LABEL} state ({exc!r}). Removed NOTHING.")
        return 2

    # Liveness receipt: say what was EXAMINED, so "nothing to clear" and "nothing was looked at"
    # cannot read the same.
    print(
        f"{CI_RED_LABEL}: examined {len(verdicts)} labelled pull request(s) against "
        f"{len(required)} required context(s)"
    )
    for number, clearable, reason, _ in verdicts:
        print(f"  {'CLEAR' if clearable else 'KEEP '} #{number}  {reason}")

    clears = [v for v in verdicts if v[1]]
    if not clears:
        print(f"{CI_RED_LABEL}: nothing to clear; every label is still earned.")
        return 0
    if len(clears) > args.max_removals:
        print(
            f"{len(clears)} labels are clearable, over the --max-removals ceiling of "
            f"{args.max_removals}. REMOVED NOTHING. A pass that wants to clear most of the "
            f"population is a classification bug, not a clean-up: {sorted(v[0] for v in clears)}. "
            "Re-read the KEEP reasons above before raising the ceiling."
        )
        return 1
    if not args.apply:
        print(
            f"{CI_RED_LABEL}: DRY RUN -- would remove {len(clears)} label(s): "
            f"{sorted(v[0] for v in clears)}. Re-run with --apply."
        )
        return 0

    removed = 0
    try:
        for number, _, _, fingerprint in clears:
            if _remove(args.repo, number, required, fingerprint):
                removed += 1
                print(f"  CLEARED #{number}")
    except (ReadFailed, ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        print(f"removed {removed} label(s), then a write or re-read failed ({exc!r}). Stopping.")
        return 2
    print(f"{CI_RED_LABEL}: removed {removed} of {len(clears)} label(s) judged clear.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
