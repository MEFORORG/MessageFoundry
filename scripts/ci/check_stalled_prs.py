#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A pull request can be finished, green, armed to merge — and unable to merge, forever, silently.

THE DEFECT THIS EXISTS FOR — measured on this repo, 2026-08-01. Nine open pull requests had zero
failing checks and zero pending checks. Not one of them could merge. Six had auto-merge ARMED, which
will never fire. PR #74 had been sitting in that state since 2026-07-30 and was found only because
somebody went looking for "stuck CI" by hand.

THE MECHANISM. Branch protection sets ``required_status_checks.strict = true`` (a PR must be up to
date with ``main`` to merge) and there is no merge queue. The suite takes ~20 minutes. So a PR that
goes green has to win a race: it must finish while ``main`` holds still. When it loses — when anything
else lands first — it flips to ``BEHIND`` and stops. Armed auto-merge does NOT update a ``BEHIND``
branch; it only waits on checks, which are already green. Nothing re-syncs it. Nothing reports it.

WHY NOTHING ELSE CATCHES IT. Every existing signal is a check outcome, and no check has failed — that
is the whole problem. ``statusCheckRollup`` is all green, ``nightly-notice.yml`` watches CI runs (there
is no failing run), and the author has no reason to look because their last signal was a full pass.
The state is indistinguishable from "merging shortly" except by asking a question nobody asks:
*is this PR still able to merge at all?* A green dashboard and a wedged repository look identical.

THE SIGNATURE is exact and decidable from one API call::

    state = OPEN  AND  mergeStateStatus = BEHIND  AND  failing = 0  AND  pending = 0

An ARMED PR matching it is worse than an unarmed one: the arming is a promise to the author that it
will land by itself, and that promise is false. Unarmed matches are merely waiting on a human.

WHAT THIS DOES NOT FIX. The race itself. Only a merge queue removes it — this converts a SILENT
failure into a LOUD one, which is the part that let #74 sit for days. If a merge queue is enabled,
this check costs nothing and goes quiet on its own.

WHY SCHEDULED AND NOT PER-PR. The stall arrives when a DIFFERENT pull request merges, so the affected
PR has no run in flight and nothing to hang a per-PR check on. It becomes true while the repository is
idle, which is exactly when nobody is looking.

AND WHO WATCHES THIS. A scheduled check whose own failure reports nowhere is a gate that cannot fire:
a report that stopped arriving looks exactly like a day with nothing to report. This ran red three
mornings running before anyone noticed, so ``.github/workflows/nightly-notice.yml`` now watches
``Stalled PRs`` and opens one deduplicated issue when a scheduled run of it fails. See
:data:`ROLLUP_FIELDS` for what those three reds actually were.

USAGE
    python scripts/ci/check_stalled_prs.py                     # uses gh's auth
    python scripts/ci/check_stalled_prs.py --repo owner/name
    python scripts/ci/check_stalled_prs.py --prs-json prs.json # offline/testing
    python scripts/ci/check_stalled_prs.py --warn-only         # report, always exit 0
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
# The rollup vocabulary is GitHub's, not ours, so one module owns it rather than each reader keeping a
# copy — a conclusion string an unclassified copy let through would read as GREEN, which is the exact
# defect this script exists to catch. check_unread_prs.py was the second reader until it was deleted on
# 2026-09-05; _pr_checks.py records why the split outlived it.
from scripts.ci._pr_checks import counts as _counts  # noqa: E402

#: The merge state that means "head is behind base". GitHub computes this server-side; it is not
#: derivable from the check rollup, which is why the rollup alone cannot see this defect.
_BEHIND = "BEHIND"

#: Asked for across EVERY open pull request in one query. Cheap: no per-PR check runs.
LIST_FIELDS = "number,title,state,mergeStateStatus,autoMergeRequest,headRefName"

#: Fetched ONE PULL REQUEST AT A TIME, and only for the ones that could still be a stall.
#:
#: WHY THE QUERY IS SPLIT, MEASURED 2026-09-05. Asking for `statusCheckRollup` alongside the fields
#: above, across every open pull request, is what GitHub's GraphQL API refused to answer: the daily
#: cron failed three times running (runs 33753049186, 33870995359, 33962763074), each with
#: ``gh pr list failed (1): unexpected end of JSON input`` -- an empty body, which is what `gh` prints
#: when it cannot parse the response. Reproduced locally against this repository at 67 open pull
#: requests: the combined query returns ``HTTP 502/504`` in about 11 seconds, while the same query
#: WITHOUT the rollup returns all 67 in about 3. The rollup is the cost -- it pulls every check run of
#: every pull request, and this repository reports about 29 per pull request, so the node count grows
#: with the open set and crossed the timeout somewhere between 2026-09-02 (green) and 2026-09-03 (red).
#:
#: Splitting it fixes the defect by construction: NO SINGLE QUERY now carries more than one pull
#: request's rollup, so the node count that crossed the timeout cannot reassemble however far the
#: repository grows. One `gh pr view` per candidate, each well under a second.
#:
#: WHAT IT DOES NOT DO IS MAKE THE WORK SMALL, and the first draft of this comment claimed it did.
#: The candidate set is every OPEN and BEHIND pull request, and that is VOLATILE: measured twice
#: within the hour on 2026-09-05 against 67 open pull requests, it was 16 and then 38, because a pull
#: request flips to BEHIND the moment anything else merges -- the very race this check exists to
#: catch. So the cost is one sub-second call per BEHIND pull request, measured at 30s wall clock for
#: 38 of them, and it scales with a set that can approach the whole open list. That is fine for a
#: daily cron and would not be for anything interactive.
ROLLUP_FIELDS = "statusCheckRollup"

#: The ceiling handed to `gh pr list`. A returned count EQUAL to this is a TRUNCATION SIGNAL, not a
#: population -- `_fetch` refuses to report on a capped list rather than under-reporting silently.
#: Set well above the current open count (67 on 2026-09-05) so the guard has headroom before it bites.
LIST_LIMIT = 300


@dataclass(frozen=True)
class Stall:
    """One pull request that is green and cannot merge."""

    number: int
    title: str
    branch: str
    armed: bool

    def line(self) -> str:
        # ASCII only: this string lands in GitHub Actions annotations and in operator consoles whose
        # code page is cp1252, where a non-ASCII dash renders as a replacement char.
        flag = "ARMED -- auto-merge will never fire" if self.armed else "not armed"
        return f"#{self.number} [{self.branch}] {self.title[:60]} ({flag})"


def could_be_stalled(pr: dict[str, object]) -> bool:
    """Whether this pull request's check rollup is worth fetching at all.

    The half of the stall signature that is decidable WITHOUT the rollup, and therefore the pre-filter
    that lets :func:`_fetch` skip the expensive per-PR query for most pull requests.

    ONE definition, used by both :func:`_fetch` and :func:`scan`, deliberately. If the fetcher's
    pre-filter and the scanner's rule were written out twice, a pull request the fetcher skipped could
    still reach the scanner, which would then read a rollup that was never fetched as an EMPTY one --
    and an empty rollup counts as zero failing and zero pending, i.e. GREEN. That is a false stall
    report manufactured by the optimisation, so the two share this predicate instead.
    """
    return (
        str(pr.get("state") or "").upper() == "OPEN"
        and str(pr.get("mergeStateStatus") or "").upper() == _BEHIND
    )


def scan(prs: list[dict[str, object]]) -> list[Stall]:
    """Every open PR matching the stall signature, most recently opened first.

    Pure: no network, no git. The CLI supplies the payload so tests drive THIS function rather than a
    re-implementation of the rule — a test asserting a copy of the rule proves nothing about the rule.
    """
    found: list[Stall] = []
    for pr in prs:
        if not could_be_stalled(pr):
            continue
        failing, unsettled = _counts(pr.get("statusCheckRollup"))
        if failing or unsettled:
            continue
        # Narrow rather than coerce: int(<some dict>) would raise, turning a surprising payload into a
        # crash instead of a finding. A PR whose number is unreadable still gets reported, as #0.
        raw_number = pr.get("number")
        found.append(
            Stall(
                number=raw_number if isinstance(raw_number, int) else 0,
                title=str(pr.get("title") or ""),
                branch=str(pr.get("headRefName") or ""),
                armed=pr.get("autoMergeRequest") is not None,
            )
        )
    return sorted(found, key=lambda s: s.number, reverse=True)


#: Per-call subprocess ceilings. Before the split, ONE call at 180s bounded the whole job at about
#: three minutes; that property is gone, so the ceilings are sized per command and the workflow job
#: carries its own `timeout-minutes`. A `gh pr view` measured well under a second has no business
#: waiting three minutes before it reports a hang.
LIST_TIMEOUT = 180
VIEW_TIMEOUT = 60

#: Attempts per `gh` call. The split multiplied the transient-failure surface: one query became one
#: plus one per BEHIND pull request, so a single flaky 502 that used to be a one-in-one chance is now
#: one-in-N -- and this check now opens an issue when it fails (see the module docstring), which would
#: turn ordinary API flake into recurring noise. Retried serially, never in parallel: GitHub's own
#: guidance for a single token is to make requests serially to stay clear of secondary rate limits,
#: and a secondary-limit 403 inside a fail-closed check is just this outage again, arriving slower.
_ATTEMPTS = 3
_BACKOFF_SECONDS = 2.0


def _gh(repo: str | None, *args: str) -> list[str]:
    """One `gh` argv, with `--repo` appended when the operator named one.

    Both queries build their argv here so the ``--repo`` rule exists once. A ``--repo`` that reached
    the listing but not the per-PR fetch would read two different repositories in one sweep, with
    nothing reporting a problem.
    """
    return ["gh", *args, *(["--repo", repo] if repo else [])]


def _rows(payload: object) -> list[dict[str, object]]:
    """Every dict in a JSON array payload; anything else is an empty population.

    Non-dict rows are dropped rather than passed on: `scan` calls ``pr.get(...)`` on each one.
    """
    if not isinstance(payload, list):
        return []
    return [row for row in payload if isinstance(row, dict)]


def _run_gh(cmd: list[str], timeout: float = LIST_TIMEOUT) -> str:
    """Run one `gh` command and return its stdout, raising when every attempt fails."""
    last = ""
    for attempt in range(_ATTEMPTS):
        # B603: fixed argv, no shell. The only variable elements are --repo and a PR number, both
        # derived from an operator-typed CLI argument or from GitHub's own response on a CI runner --
        # not message, config, or network data. Same posture as check_required_workflow_state.py.
        #
        # encoding, not bare text=True: a PR title can carry bytes that are not cp1252, and text=True
        # decodes with the locale codec, which on a stock Windows box raises instead of returning the
        # title. scripts/security/vuln_metrics.py carries the same fix for the same reason.
        out = subprocess.run(  # noqa: S603  # nosec B603 — fixed argv, no shell, operator-supplied
            cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout
        )
        if out.returncode == 0:
            return out.stdout
        last = f"{' '.join(cmd[:4])} failed ({out.returncode}): {out.stderr.strip()[:400]}"
        if attempt + 1 < _ATTEMPTS:
            time.sleep(_BACKOFF_SECONDS * (attempt + 1))
    raise RuntimeError(f"{last} (after {_ATTEMPTS} attempts)")


def _fetch(
    repo: str | None,
    prs_json: Path | None,
    runner: Callable[[list[str], float], str] | None = None,
) -> list[dict[str, object]]:
    """The open pull requests, with a check rollup on the ones that could be a stall.

    ``runner`` is injected so a test can drive the SPLIT — which commands are issued, and for which
    pull requests — without a network. See :data:`ROLLUP_FIELDS` for why the query is split at all.

    Resolved in the BODY rather than bound as a default argument, deliberately: a default would
    capture :func:`_run_gh` at import time, so ``monkeypatch.setattr(module, "_run_gh", stub)`` would
    be silently ineffective and the test would reach the real network while appearing to stub it.
    """
    run = runner if runner is not None else _run_gh
    if prs_json is not None:
        return _rows(json.loads(prs_json.read_text(encoding="utf-8")))

    listing = _gh(
        repo, "pr", "list", "--state", "open", "--limit", str(LIST_LIMIT), "--json", LIST_FIELDS
    )
    prs = _rows(json.loads(run(listing, LIST_TIMEOUT)))

    # A RESULT SET EQUAL TO THE CAP HAS TOLD YOU NOTHING. `gh pr list` truncates at --limit silently,
    # so a capped list would under-report stalls with no sign that anything was missed. Fail closed --
    # this script's whole posture is that "I could not see everything" must never render as "nothing
    # is wrong".
    if len(prs) >= LIST_LIMIT:
        raise RuntimeError(
            f"gh pr list returned {len(prs)}, which EQUALS the --limit of {LIST_LIMIT}. That is a "
            "truncation signal, not a population: some open pull requests were not examined. Raise "
            "LIST_LIMIT."
        )

    for pr in prs:
        if not could_be_stalled(pr):
            continue
        number = pr.get("number")
        if not isinstance(number, int):
            # FAIL CLOSED, and the tempting alternative is a false report. Leaving the key absent
            # does NOT make `scan` drop this pull request: `_counts(None)` returns (0, 0) -- zero
            # failing, zero unsettled -- which is indistinguishable from a fully GREEN rollup, so the
            # PR would be announced as a stall on evidence that was never fetched. Verified against
            # scripts/ci/_pr_checks.py rather than assumed.
            raise RuntimeError(
                f"an open pull request came back with an unusable number ({number!r}), so its check "
                "rollup cannot be fetched. Refusing to report on a payload this check cannot verify."
            )
        view = _gh(repo, "pr", "view", str(number), "--json", ROLLUP_FIELDS)
        one = json.loads(run(view, VIEW_TIMEOUT))
        if not isinstance(one, dict):
            # FAIL CLOSED, for the same reason as the branch above and it is easy to get backwards.
            # Storing None here would NOT drop the pull request: `_counts(None)` is (0, 0), which is
            # indistinguishable from a fully green rollup, so an unreadable response would be
            # announced as a stall. An earlier draft of this line did exactly that.
            raise RuntimeError(
                f"the check rollup for #{number} came back unreadable ({one!r}). Refusing to report "
                "on a payload this check cannot verify."
            )
        pr["statusCheckRollup"] = one.get("statusCheckRollup")

    return prs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo", default=None, help="owner/name; defaults to gh's current repo")
    parser.add_argument("--prs-json", type=Path, default=None, help="a saved payload (testing)")
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="report and exit 0 — for adoption, before the backlog of existing stalls is cleared",
    )
    args = parser.parse_args(argv)

    try:
        prs = _fetch(args.repo, args.prs_json)
    except (RuntimeError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
        # FAIL CLOSED. "I could not list the PRs" must never render as "nothing is stalled" — that is
        # this script's own defect class, one level up.
        print(
            f"::error::could not list pull requests ({exc!r}). Treating as a FAILURE.",
            file=sys.stderr,
        )
        return 2

    stalls = scan(prs)
    armed = [s for s in stalls if s.armed]

    # Liveness receipt: say what was EXAMINED. "no stalls" and "nothing was scanned" are otherwise
    # indistinguishable from the exit code, and an empty sweep reporting success is the exact shape
    # this check is meant to make impossible.
    print(f"stalled-prs: scanned {len(prs)} open pull request(s); {len(stalls)} stalled")
    if not prs:
        print(
            "::error::ZERO open pull requests came back. That is a broken query, not a clean repo — "
            "refusing to report success.",
            file=sys.stderr,
        )
        return 2

    if not stalls:
        print("stalled-prs: every open PR can still reach a merge.")
        return 0

    for stall in stalls:
        print(f"::warning::green but cannot merge: {stall.line()}")

    if armed:
        print(
            f"::error::{len(armed)} pull request(s) are green, ARMED for auto-merge, and BEHIND. Armed "
            "auto-merge does not update a BEHIND branch -- it waits on checks that already passed, so "
            "these will never merge and nothing else will say so. Re-sync each from the base branch "
            "(merge or rebase, then push) and it will land. The durable fix is a merge queue, which "
            "removes the race these are losing.",
            file=sys.stderr,
        )

    return 0 if args.warn_only else (1 if armed else 0)


if __name__ == "__main__":
    raise SystemExit(main())
