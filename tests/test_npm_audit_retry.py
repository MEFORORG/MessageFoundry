# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``npm audit`` must retry a transport failure, and must never pass without a verdict.

THE DEFECT THIS EXISTS FOR. ``npm audit`` exits non-zero BOTH when the advisory database reports a
vulnerability AND when it cannot be reached, so the bare ``npm audit --package-lock-only`` this
replaced made an unreachable registry indistinguishable from a finding. A red therefore said nothing
about the dependencies, which is a compensating control resting on a false premise. Measured
2026-09-04: of 34 failures of the required ``npm-audit (ide dependency vulnerabilities)`` context in
one night, 32 were ``503 Service Unavailable`` or ``network timeout at .../advisories/bulk`` and 2
were real findings. Each one blocked a merge or evicted a merge-queue entry.

WHAT IS PINNED, AND WHY IT IS THIS AND NOT A SIGNATURE. The retry is the convenience; the property
that must not regress is that the step stays **fail-closed**. So the load-bearing assertion is not
"the word retry appears" but that **every** path reaching ``exit 0`` is inside the branch where
``npm audit`` itself succeeded. A future edit that adds a friendly "registry unreachable, carrying
on" fall-through would keep every other marker in place and silently turn a required security gate
into one that passes when it learned nothing. That edit is what this module is here to catch.

WHAT CANNOT BE TESTED HERE, stated rather than papered over. Whether ``npm audit --json`` really
emits ``.metadata.vulnerabilities`` on a verdict, and really omits it on a transport error, is a
property of npm and is not exercised by this module -- it needs a runner with a network. That
assumption is deliberately arranged so being WRONG about it is safe: if the discriminator never
matches, a real finding is treated as "no verdict", the retries are exhausted, and the job FAILS.
The assumption can cost a false red. It cannot produce a false green, which is what the
``exit 0`` assertion below pins.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

_REPO = Path(__file__).resolve().parents[1]
_SECURITY = _REPO / ".github" / "workflows" / "security.yml"

_STEP_NAME = "Audit the locked npm dependencies (install-free)"


def _audit_step() -> dict[str, object]:
    """The npm-audit step, located by name rather than by index."""
    doc = yaml.safe_load(_SECURITY.read_text(encoding="utf-8"))
    steps = [
        step
        for job in doc["jobs"].values()
        for step in (job.get("steps") or [])
        if isinstance(step, dict) and step.get("name") == _STEP_NAME
    ]
    assert len(steps) == 1, f"expected exactly one {_STEP_NAME!r} step, found {len(steps)}"
    return steps[0]


def _run_lines() -> list[str]:
    run = _audit_step().get("run")
    assert isinstance(run, str), "the npm-audit step must carry a multi-line run block"
    return run.strip().splitlines()


def test_the_audit_step_retries_rather_than_reporting_a_transport_error_as_a_finding() -> None:
    lines = _run_lines()
    body = "\n".join(lines)
    assert "for attempt in" in body, (
        "the npm-audit step no longer loops. A single invocation cannot tell an unreachable "
        "registry from a vulnerability, which is the defect this step was changed to fix."
    )
    assert "sleep" in body, (
        "a retry loop with no backoff hammers a registry that is already failing"
    )


def test_the_step_discriminates_a_verdict_from_a_transport_failure() -> None:
    body = "\n".join(_run_lines())
    assert ".metadata.vulnerabilities" in body, (
        "the step must decide 'verdict or transport failure' on the CONTENT of the audit output. "
        "Exit status alone cannot separate them -- that is the whole defect."
    )


def test_the_only_way_to_pass_is_npm_audit_itself_succeeding() -> None:
    """The fail-closed property. This is the assertion that matters.

    Every ``exit 0`` must sit inside the ``if npm audit ...; then`` branch. Anything else is a path
    that reports success without an audit verdict.
    """
    lines = _run_lines()
    exits = [i for i, line in enumerate(lines) if re.match(r"\s*exit\s+0\b", line)]
    assert exits, "the step can never succeed; it has no `exit 0` at all"
    assert len(exits) == 1, (
        f"expected exactly one `exit 0`, found {len(exits)} at lines "
        f"{[i + 1 for i in exits]}. Every additional success path is a way to pass without a "
        "verdict, so they are counted rather than assumed benign."
    )

    # Walk backwards to the ENCLOSING `if`, tracking `fi` so a block that has already closed cannot
    # lend its condition to a later line. An earlier version of this test searched the whole preface
    # for `if npm audit`, which every later line trivially satisfies -- it passed a deliberate
    # fail-open mutation and so proved nothing.
    idx = exits[0]
    depth = 0
    opener = None
    for line in reversed(lines[:idx]):
        stripped = line.strip()
        if stripped == "fi":
            depth += 1
        elif re.match(r"if\s+.*;\s*then$", stripped):
            if depth == 0:
                opener = stripped
                break
            depth -= 1
    assert opener is not None, (
        f"the `exit 0` on line {idx + 1} sits in no `if` block at all, so it is reached "
        "unconditionally once control arrives there."
    )
    assert re.match(r"if\s+npm audit\b", opener), (
        f"the `exit 0` on line {idx + 1} is guarded by {opener!r}, not by `npm audit` succeeding. "
        "A required security gate must not report success when it obtained no verdict -- see this "
        "module's docstring."
    )


def test_exhausting_the_retries_fails_rather_than_passing() -> None:
    lines = _run_lines()
    tail = "\n".join(lines[-6:])
    assert re.search(r"^\s*exit\s+1\b", tail, re.M), (
        "after the retry loop the step must exit non-zero. Falling out of the loop into a success "
        "is exactly the fail-open this step exists to avoid."
    )


def test_the_step_pins_bash_so_the_loop_semantics_are_not_the_runner_default() -> None:
    assert _audit_step().get("shell") == "bash", (
        "the run block relies on bash loop and test semantics; leaving the shell implicit lets a "
        "runner default change them underneath it"
    )
