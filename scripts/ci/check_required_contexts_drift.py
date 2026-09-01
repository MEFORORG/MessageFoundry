# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization
"""Reconcile ``.github/required-contexts.txt`` against the LIVE required set on the server.

THE DEFECT THIS EXISTS FOR -- measured on ``MEFORORG/MessageFoundry`` 2026-08-30: branch protection
required **15** contexts while the checked-in file named **13**. The two absent from the file were
``CodeQL (python)`` and ``CodeQL (javascript-typescript)``, which the file's own header listed under
"DELIBERATELY NOT REQUIRED". So the file did not merely omit them -- it asserted the opposite of the
server, on a question whose whole point is to be answerable from a clone.

WHY NOTHING CAUGHT IT. ``tests/test_required_contexts.py`` compares in-repo text to in-repo text: the
file against ``docs/CI.md``, against workflow job names, against a pinned count. Every one of those
still agreed with every other while the SERVER moved underneath them, and the count pin
(``assert len(contexts) == 13``) is a literal written once by hand, not a measurement. A suite that
only ever asks "do our documents agree" cannot see a document that agrees with itself and not reality.

WHY THIS IS A SEPARATE SCRIPT, not a branch inside ``check_required_workflow_state.py``. That sibling
asks REACHABILITY -- *can this context ever report?* This one asks ACCURACY -- *does our checked-in claim
match the server?* A context can be perfectly reachable and still be missing from the file, and a
context in the file can be reachable while nothing requires it. Folding both into one instrument would
give a single exit code two meanings, which is the confusion this repo's own CI notes keep naming.

*** WHAT IT DOES NOT CHECK, STATED SO NOBODY READS MORE INTO A GREEN RUN THAN IT CARRIES. ***
Only the CONTEXT SET. It says nothing about ``strict``, ``enforce_admins``, or
``required_approving_review_count``, and those move independently -- ``strict`` was ALSO drifted on
2026-08-30, and this script would not have caught it. Measured that day, and it is the reason for the
split: the context list is on ``GET /repos/{owner}/{repo}/branches/{branch}``, which answers
**unauthenticated**; ``strict`` lives only on ``.../branches/{branch}/protection``, which returns 401
without admin scope. So the reconciliation below costs no permission at all, and covering ``strict``
would need a token this workflow deliberately does not hold. Widening it is a real follow-up with a
real cost, not an oversight.

Usage::

    python scripts/ci/check_required_contexts_drift.py --repo owner/name
    python scripts/ci/check_required_contexts_drift.py --branch-json saved.json   # testing
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))
from tests._workflow_contexts import required_contexts  # noqa: E402

_CANONICAL = ".github/required-contexts.txt"


def _server_contexts(repo: str | None, branch: str, branch_json: Path | None) -> list[str]:
    """The contexts branch protection currently requires, from the PUBLIC branch endpoint.

    Deliberately NOT ``.../protection``: that endpoint carries ``strict`` but needs admin scope and
    401s without it. This one exposes ``protection.required_status_checks.contexts`` to an anonymous
    reader, so the check runs under the workflow's existing read-only token -- and would still run on a
    fork PR, where no elevated token exists.
    """
    if branch_json is not None:
        payload = json.loads(branch_json.read_text(encoding="utf-8"))
    else:
        endpoint = (
            f"repos/{repo}/branches/{branch}"
            if repo
            else f"repos/{{owner}}/{{repo}}/branches/{branch}"
        )
        # B603 asks whether untrusted input reaches a subprocess. It cannot here: argv is a fixed
        # literal list, there is no shell, and the only variable elements are `--repo`/`--branch`,
        # operator-typed CLI arguments on a CI runner -- not message, config, or network data.
        out = subprocess.run(  # noqa: S603  # nosec B603 B607 - fixed argv, no shell, operator repo
            ["gh", "api", endpoint], capture_output=True, text=True, timeout=120
        )
        if out.returncode != 0:
            raise RuntimeError(f"gh api failed ({out.returncode}): {out.stderr.strip()[:400]}")
        payload = json.loads(out.stdout)

    protection = payload.get("protection") or {}
    checks = protection.get("required_status_checks") or {}
    contexts = checks.get("contexts")
    if contexts is None:
        raise RuntimeError(
            "the branch payload carried no required_status_checks.contexts -- the API shape changed, "
            "or this branch is unprotected. Either way it is not an empty required set."
        )
    return [str(c) for c in contexts]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo", default=None, help="owner/name; defaults to gh's current repo")
    parser.add_argument("--branch", default="main", help="the protected branch (default: main)")
    parser.add_argument(
        "--branch-json", type=Path, default=None, help="a saved branch payload (testing)"
    )
    args = parser.parse_args(argv)

    declared = required_contexts()
    if not declared:
        print(
            f"::error::{_CANONICAL} parsed to ZERO contexts -- the format changed under the parser. "
            "That is a broken check, not a clean sweep.",
            file=sys.stderr,
        )
        return 2

    try:
        live = _server_contexts(args.repo, args.branch, args.branch_json)
    except (RuntimeError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
        # FAIL CLOSED. "We could not read branch protection" must never render as "the file is
        # accurate" -- that is the same blindness this script exists to catch, one level up.
        print(
            f"::error::could not read branch protection ({exc!r}). Treating as a FAILURE.",
            file=sys.stderr,
        )
        return 2

    server_only = sorted(set(live) - set(declared))
    file_only = sorted(set(declared) - set(live))

    # Liveness receipt: report what was COMPARED. "no drift" and "nothing was checked" must not render
    # identically -- a silent zero is the failure mode every gate in this repo is written against.
    print(
        f"required-contexts-drift: compared {len(declared)} declared in {_CANONICAL} "
        f"against {len(live)} required on {args.repo or 'this repo'}@{args.branch}"
    )

    if not server_only and not file_only:
        print(
            f"required-contexts-drift: the file matches the server exactly ({len(live)} contexts)."
        )
        return 0

    if server_only:
        print(
            "::error::REQUIRED ON THE SERVER, ABSENT FROM THE FILE -- these BLOCK a merge while the "
            "checked-in answer says they do not:\n  " + "\n  ".join(server_only),
            file=sys.stderr,
        )
    if file_only:
        print(
            "::error::NAMED IN THE FILE, NOT REQUIRED ON THE SERVER -- the file claims these gate a "
            "merge and nothing does:\n  " + "\n  ".join(file_only),
            file=sys.stderr,
        )
    print(
        f"::error::Reconcile them in ONE change. If the SERVER is right, edit {_CANONICAL} (and the "
        "count pinned in tests/test_required_contexts.py, and a negative control per new context -- "
        "tests/_negative_controls.py requires one, and reads the list from this same file). If the "
        "FILE is right, the fix is on the server and adding to protection is all-or-nothing: the REST "
        "endpoint 422s with `already_exists` if any context in the request is already required, and "
        "then adds NONE of them, so send only the missing ones.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
