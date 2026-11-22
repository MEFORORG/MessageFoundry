#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every REQUIRED status check must belong to a workflow GitHub will actually run.

THE DEFECT THIS EXISTS FOR — measured, on a sibling repo, 2026-07-30. The private vault repo
(``MEFORORG/MessageFoundry-vault``) had 10 required contexts whose workflows were all
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
import re
import subprocess
import sys
from collections.abc import Collection
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

# Reuse the SAME resolver the doc-drift tests use, rather than re-deriving context -> workflow here.
# A second implementation of that mapping is exactly the drift this repo keeps writing parity tests to
# catch (ruff/bandit scan scope, the required-set prose). One resolver, two callers.
sys.path.insert(0, str(_ROOT))

# Run as a script, an import failure would exit 1, the findings code, so it exits 2 here. The script
# imports yaml first: without it the resolver falls back to pytest's importorskip, whose Skipped is a
# BaseException. Imported by a test module, the failure propagates, so that skip still works there.
try:
    if __name__ == "__main__":
        import yaml as _yaml_before_resolver  # noqa: F401

    from scripts.ci.required_contexts import gh_api
    from tests._workflow_contexts import (
        reportable_contexts,
        required_contexts,
        resolve,
    )
except ImportError as exc:
    if __name__ != "__main__":
        raise
    print(
        f"::error::could not import a dependency ({exc!r}). Treating as a FAILURE.",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc

# isort: split
# After the resolver, which owns the handling of an absent PyYAML.
import yaml  # noqa: E402

#: GitHub reports a runnable workflow as ``active``. Everything else -- ``disabled_manually``,
#: ``disabled_inactivity`` (60 days idle on a fork/scheduled-only repo), ``disabled_fork`` -- means it
#: will not dispatch, so a required context it owns can never report.
_RUNNABLE = "active"

#: One path segment, ASCII only. The literal ``.github`` below is the only leading dot allowed.
_SEGMENT = r"[A-Za-z0-9_][A-Za-z0-9._-]*"

#: Every path this script accepts. Group 1 is set only for a file directly in ``.github/workflows``.
_WORKFLOW_PATH = re.compile(
    rf"\.github/workflows/(?:({_SEGMENT})|{_SEGMENT}(?:/{_SEGMENT})+)"
    rf"|dynamic/{_SEGMENT}(?:/{_SEGMENT})+"
)

#: What reading the local contexts file and workflow YAML can raise. The resolver asserts a mapping
#: and then indexes into the parse, so a wrongly shaped file surfaces as an assertion, attribute or
#: type error. RuntimeError covers RecursionError from deeply nested YAML.
_LOCAL_READ_ERRORS = (
    OSError,
    ValueError,
    RuntimeError,
    yaml.YAMLError,
    AssertionError,
    AttributeError,
    TypeError,
)


def _workflow_entries(payload: object) -> list[object]:
    """The workflow entries in any payload shape this script accepts, or ``RuntimeError``.

    THREE SHAPES: one API page (``{"workflows": [...]}``), the LIST OF PAGES that ``--slurp`` emits, and
    a saved bare list of workflows. A list is told apart by whether its entries carry ``workflows``, and
    a list mixing the two is refused rather than guessed at. An error object on any page lands here too,
    so one bad page cannot pass as a short list.
    """
    if isinstance(payload, dict):
        pages: list[object] = [payload]
    elif not isinstance(payload, list):
        raise RuntimeError(f"workflow payload is a {type(payload).__name__}, not an object or list")
    elif not any(isinstance(entry, dict) and "workflows" in entry for entry in payload):
        return payload  # bare workflows; _workflow_state refuses a bad one
    else:
        pages = payload

    entries: list[object] = []
    for page in pages:
        block = page.get("workflows") if isinstance(page, dict) else None
        if not isinstance(block, list):
            raise RuntimeError("a workflow page has no `workflows` array")
        entries.extend(block)
    return entries


def _workflow_state(entry: object) -> tuple[str, str]:
    """``(path, state)`` of one entry, or ``RuntimeError``.

    A missing field must not default to ``""``, and a padded one must not pass through: either would
    report a malformed payload as a disabled or absent workflow, exit 1, which is the findings code.
    """
    if not isinstance(entry, dict):
        raise RuntimeError("a workflow entry is not an object")
    path, state = entry.get("path"), entry.get("state")
    # Two isinstance checks rather than one all(): mypy narrows these and not a generator.
    if not (isinstance(path, str) and isinstance(state, str)) or not all(
        value and value == value.strip() for value in (path, state)
    ):
        raise RuntimeError("a workflow entry lacks a usable `path` or `state`")
    return path, state


def _direct_workflow_file(path: str) -> str | None:
    """The filename of an allowlisted direct path, ``None`` for a well-formed other, else raises.

    An ALLOWLIST on the raw path, because a list of bad spellings cannot be complete: a backslash, a
    case change, ``%2e``, or a trailing NUL or zero-width space each once passed as an ignorable
    entry, which would hide a disabled workflow. The well-formed others are a file nested under
    ``.github/workflows`` and a ``dynamic/`` entry, each at least two segments deep. Anything else
    raises ``RuntimeError``.
    """
    match = _WORKFLOW_PATH.fullmatch(path)
    if match is None:
        raise RuntimeError(f"workflow path {path!r} is not canonical")
    return match[1]


def _workflow_states(
    repo: str | None, states_json: Path | None, required: Collection[str]
) -> dict[str, str]:
    """``{filename: state}`` of the direct workflow files.

    Raises ``RuntimeError`` at least on a path that ``_direct_workflow_file`` refuses, even one
    directly in ``.github/workflows``.

    Keyed on the FILENAME rather than the display name: the display name is what ``workflow_run``
    matches on, but a required context resolves to a FILE, and two workflows may legitimately share a
    display name (this repo has two called "CodeQL"). ``required`` names the files a required context
    resolves to, the only ones whose conflicting repeat is refused.
    """
    if states_json is not None:
        payload = json.loads(states_json.read_text(encoding="utf-8"))
    else:
        # --slurp because --paginate alone concatenates one JSON document per page, which does not
        # parse. gh requests 100 per page here, so that would start at more than 100 workflows.
        route = f"repos/{repo or '{owner}/{repo}'}/actions/workflows"
        payload = gh_api(["--paginate", "--slurp", route])
    # A repeat that disagrees on a required file is refused; for any other file, setdefault keeps the first state listed.
    states: dict[str, str] = {}
    for path, state in map(_workflow_state, _workflow_entries(payload)):
        name = _direct_workflow_file(path)
        if name is not None and states.setdefault(name, state) != state and name in required:
            raise RuntimeError(f"workflow {name} is listed with conflicting states")
    return states


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo", default=None, help="owner/name; defaults to gh's current repo")
    parser.add_argument(
        "--states-json", type=Path, default=None, help="a saved API payload (testing)"
    )
    args = parser.parse_args(argv)

    try:
        contexts = required_contexts()
        resolved = {ctx: resolve(ctx) for ctx in contexts}
        # A missing or empty directory globs to nothing and raises nothing.
        if not reportable_contexts():
            raise RuntimeError("no workflow jobs found in the local .github/workflows")
    except _LOCAL_READ_ERRORS as exc:
        # Exit 1 is the findings code, and an uncaught exception would exit 1 too.
        print(
            f"::error::could not read the required contexts or workflow files ({exc!r}). Treating "
            "as a FAILURE.",
            file=sys.stderr,
        )
        return 2
    if not contexts:
        print(
            "::error::.github/required-contexts.txt parsed to ZERO contexts — the format changed under "
            "the parser. That is a broken check, not a clean sweep.",
            file=sys.stderr,
        )
        return 2

    try:
        required = {where[0] for where in resolved.values() if where is not None}
        states = _workflow_states(args.repo, args.states_json, required)
    except (RuntimeError, ValueError, subprocess.SubprocessError, OSError) as exc:
        # FAIL CLOSED. "We could not read workflow state" must never read as "every workflow is fine" —
        # that is the same blindness this script exists to catch, one level up. ValueError covers both
        # JSONDecodeError and UnicodeDecodeError; RuntimeError covers RecursionError from deep JSON.
        print(
            f"::error::could not read workflow state ({exc!r}). Treating as a FAILURE.",
            file=sys.stderr,
        )
        return 2
    if not states:
        print(
            "::error::the API returned ZERO workflows in .github/workflows — refusing to report "
            "success.",
            file=sys.stderr,
        )
        return 2

    unreachable: list[str] = []
    unresolved: list[str] = []
    checked = 0
    for ctx in contexts:
        where = resolved[ctx]
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
            # !r because the value is server data, and a raw newline would start a new `::` command.
            unreachable.append(f"{ctx}  ->  {workflow}  [state={state!r}]")

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
