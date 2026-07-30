#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every REQUIRED status check must belong to a workflow GitHub will actually run.

THE DEFECT THIS EXISTS FOR — measured, on a sibling repo, 2026-07-30. The private vault repo
(``wshallwshall/MessageFoundry``) had 10 required contexts whose workflows were all
``disabled_manually``. A disabled workflow never dispatches, so those contexts never reported: NO pull
request could ever merge, and every merge there had silently been riding admin bypass. It sat like
that long enough for nobody to notice, because the symptom presents to a human as *"CI is stuck"* —
not as *"branch protection is misconfigured"*.

WHY THE EXISTING GUARD CANNOT SEE IT. ``tests/test_required_contexts.py`` resolves each required
context against the job names in ``.github/workflows/``. A ``disabled_manually`` workflow keeps its
file and its job name on disk, so that check passes cheerfully while the context can never report. The
property it measures — "a job with this name exists in YAML" — is true in both the healthy case and the
broken one. That is the same defect shape as a CI monitor polling for "nothing pending": sound about
the thing it looks at, blind to the thing that can fail. Workflow ``state`` is server-side and
invisible to any file-based test, which is why this lives in a scheduled job rather than in pytest.

WHY SCHEDULED AND NOT PER-PR. A workflow disabled *after* the last pull request is invisible to any
per-PR check — there is no PR to run it on. The failure arrives while the repository is idle, which is
exactly when nobody is looking. A daily sweep is the only shape that catches it.

SCOPE. This checks REACHABILITY (can the context ever report?), not outcome. Whether a check passes is
CI's job; whether it is capable of running at all is this one's.

USAGE
    python scripts/ci/check_required_workflow_state.py                  # uses gh's auth
    python scripts/ci/check_required_workflow_state.py --repo owner/name
    python scripts/ci/check_required_workflow_state.py --states-json states.json   # offline/testing
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

# Reuse the SAME resolver the doc-drift tests use, rather than re-deriving context -> workflow here.
# A second implementation of that mapping is exactly the drift this repo keeps writing parity tests to
# catch (ruff/bandit scan scope, the required-set prose). One resolver, two callers.
sys.path.insert(0, str(_ROOT))
from tests._workflow_contexts import required_contexts, resolve  # noqa: E402

#: GitHub reports a runnable workflow as ``active``. Everything else -- ``disabled_manually``,
#: ``disabled_inactivity`` (60 days idle on a fork/scheduled-only repo), ``disabled_fork`` -- means it
#: will not dispatch, so a required context it owns can never report.
_RUNNABLE = "active"


def _workflow_states(repo: str | None, states_json: Path | None) -> dict[str, str]:
    """``{workflow filename: state}`` for every workflow in the repo.

    Keyed on the FILENAME rather than the display name: the display name is what ``workflow_run``
    matches on, but a required context resolves to a FILE, and two workflows may legitimately share a
    display name (this repo has two called "CodeQL").
    """
    if states_json is not None:
        payload = json.loads(states_json.read_text(encoding="utf-8"))
    else:
        cmd = ["gh", "api", "--paginate"]
        cmd.append(
            f"repos/{repo}/actions/workflows" if repo else "repos/{owner}/{repo}/actions/workflows"
        )
        # B603 asks whether untrusted input reaches a subprocess. It cannot here: argv is a fixed
        # literal list, there is no shell, and the only variable element is `--repo`, an operator-typed
        # CLI argument on a CI runner — not message, config, or network data. Annotated per-line with a
        # reason, the posture security.yml's bandit notes require.
        out = subprocess.run(  # noqa: S603  # nosec B603 — fixed argv, no shell, operator-supplied repo
            cmd, capture_output=True, text=True, timeout=120
        )
        if out.returncode != 0:
            raise RuntimeError(f"gh api failed ({out.returncode}): {out.stderr.strip()[:400]}")
        payload = json.loads(out.stdout)
    workflows = payload.get("workflows", payload if isinstance(payload, list) else [])
    return {Path(str(w.get("path", ""))).name: str(w.get("state", "")) for w in workflows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo", default=None, help="owner/name; defaults to gh's current repo")
    parser.add_argument(
        "--states-json", type=Path, default=None, help="a saved API payload (testing)"
    )
    args = parser.parse_args(argv)

    contexts = required_contexts()
    if not contexts:
        print(
            "::error::.github/required-contexts.txt parsed to ZERO contexts — the format changed under "
            "the parser. That is a broken check, not a clean sweep.",
            file=sys.stderr,
        )
        return 2

    try:
        states = _workflow_states(args.repo, args.states_json)
    except (RuntimeError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
        # FAIL CLOSED. "We could not read workflow state" must never read as "every workflow is fine" —
        # that is the same blindness this script exists to catch, one level up.
        print(
            f"::error::could not read workflow state ({exc!r}). Treating as a FAILURE.",
            file=sys.stderr,
        )
        return 2
    if not states:
        print(
            "::error::the API returned ZERO workflows — refusing to report success.",
            file=sys.stderr,
        )
        return 2

    unreachable: list[str] = []
    unresolved: list[str] = []
    checked = 0
    for ctx in contexts:
        where = resolve(ctx)
        if where is None:
            unresolved.append(ctx)
            continue
        workflow = where[0]
        state = states.get(workflow)
        if state is None:
            unresolved.append(f"{ctx} (workflow {workflow} not present on the server)")
            continue
        checked += 1
        if state != _RUNNABLE:
            unreachable.append(f"{ctx}  ->  {workflow}  [state={state}]")

    # Liveness receipt: report what was EXAMINED. "no unreachable contexts" and "nothing was checked"
    # are otherwise indistinguishable from the exit code.
    print(f"required-workflow-state: checked {checked} of {len(contexts)} required contexts")

    if unresolved:
        for item in unresolved:
            print(
                f"::error::required context resolves to no runnable workflow: {item}",
                file=sys.stderr,
            )
        return 1

    if unreachable:
        # THE VAULT SHAPE, called out by name. When EVERY required context is unreachable, no pull
        # request can merge at all, and the only visible symptom is that PRs hang — which reads as
        # flakiness, not misconfiguration. Say the diagnosis out loud so nobody spends a day on it.
        if len(unreachable) == checked:
            print(
                "::error::EVERY required context belongs to a non-active workflow. NO pull request can "
                "merge — each required check will hang as 'Expected — waiting for status to be "
                "reported' forever. This presents as 'CI is stuck'; it is branch protection pointing at "
                "workflows GitHub will not run. Measured in this exact state on the vault repo "
                "(2026-07-30), where every merge had silently been riding admin bypass.",
                file=sys.stderr,
            )
        for item in unreachable:
            print(f"::error::{item}", file=sys.stderr)
        print(
            "\nRe-enable the workflow (`gh workflow enable <file>`), or remove the context from branch "
            "protection AND .github/required-contexts.txt — deliberately, in a reviewed diff.",
            file=sys.stderr,
        )
        return 1

    print(f"required-workflow-state: all {checked} required contexts belong to active workflows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
