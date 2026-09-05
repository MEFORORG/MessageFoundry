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
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
# The rollup vocabulary is GitHub's, not ours. One module owns it so no second copy can drift — a
# conclusion string nobody classified would read as GREEN, which is the exact defect this exists to
# catch. check_unread_prs.py was the other reader until it was deleted on 2026-09-05.
from scripts.ci._pr_checks import counts as _counts  # noqa: E402

#: The merge state that means "head is behind base". GitHub computes this server-side; it is not
#: derivable from the check rollup, which is why the rollup alone cannot see this defect.
_BEHIND = "BEHIND"

#: The fields this check needs. Kept beside the parser so the two cannot drift.
PR_FIELDS = "number,title,state,mergeStateStatus,autoMergeRequest,statusCheckRollup,headRefName"


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


def scan(prs: list[dict[str, object]]) -> list[Stall]:
    """Every open PR matching the stall signature, most recently opened first.

    Pure: no network, no git. The CLI supplies the payload so tests drive THIS function rather than a
    re-implementation of the rule — a test asserting a copy of the rule proves nothing about the rule.
    """
    found: list[Stall] = []
    for pr in prs:
        if str(pr.get("state") or "").upper() != "OPEN":
            continue
        if str(pr.get("mergeStateStatus") or "").upper() != _BEHIND:
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


def _fetch(repo: str | None, prs_json: Path | None) -> list[dict[str, object]]:
    if prs_json is not None:
        payload = json.loads(prs_json.read_text(encoding="utf-8"))
        return list(payload) if isinstance(payload, list) else []
    cmd = ["gh", "pr", "list", "--state", "open", "--limit", "100", "--json", PR_FIELDS]
    if repo:
        cmd += ["--repo", repo]
    # B603: fixed argv, no shell. The only variable element is --repo, an operator-typed CLI argument
    # on a CI runner — not message, config, or network data. Same posture as
    # check_required_workflow_state.py; see the note there.
    out = subprocess.run(  # noqa: S603  # nosec B603 — fixed argv, no shell, operator-supplied repo
        cmd, capture_output=True, text=True, timeout=180
    )
    if out.returncode != 0:
        raise RuntimeError(f"gh pr list failed ({out.returncode}): {out.stderr.strip()[:400]}")
    payload = json.loads(out.stdout)
    return list(payload) if isinstance(payload, list) else []


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
