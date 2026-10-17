# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The hosted-Windows Postgres store leg in ci.yml: what it runs, and that it gates nothing.

`postgres-store-windows` exists because Windows is the only supported v1 deployment platform (owner
ruling 2026-10-16) and `postgres-store` runs on ubuntu only. It is a COPY of that job's test steps,
and a copy drifts: the ubuntu job's steps say to APPEND each new lever's test file, and an append
that lands on one job only would leave the other silently narrower. So this module pins the copy to
its source rather than to a list of its own.

It also pins that the leg is advisory. Why it is, and what a red there means, is stated once in
docs/CI.md under "The `CI gate` roll-up"; making it blocking is a decision that moves this test.
"""

from __future__ import annotations

import functools
import re
from typing import Any

from tests._workflow_contexts import jobs_of, needs_of, required_contexts

_LINUX = "postgres-store"
_WINDOWS = "postgres-store-windows"
_REPO_GUARD = "github.repository == 'MEFORORG/MessageFoundry'"
_TEST_FILE = re.compile(r"tests/test_[A-Za-z0-9_]+\.py")
_EXPR = re.compile(r"\$\{\{\s*matrix\.os\s*\}\}")


@functools.cache
def _ci_jobs() -> dict[str, dict[str, Any]]:
    """Parsed once per process. Read-only: nothing here mutates what it returns."""
    return jobs_of("ci.yml")


#: The one pytest flag the Windows leg may add: the `test` matrix's Windows per-test watchdog.
_WINDOWS_ONLY_FLAG = "--timeout=120"


def _runs_by_test_file(job: dict[str, Any]) -> dict[str, list[tuple[str, str]]]:
    """Each test file a job's steps run, mapped to every (env, flags) it is run under.

    Job env and step env merged as GitHub merges them; flags are the run's other tokens, so a
    narrowing (`-m`, `--ignore`, `-x`, a swallowed exit code, ...) shows up as a difference. A LIST
    per file, so a file run twice is not collapsed into one run. `#` lines inside a `run:` are
    skipped, so a file a comment names is not counted as run.
    """
    out: dict[str, list[tuple[str, str]]] = {}
    for step in job.get("steps") or []:
        run = "\n".join(
            line
            for line in str(step.get("run", "")).splitlines()
            if not line.lstrip().startswith("#")
        )
        files = _TEST_FILE.findall(run)
        env = repr(sorted({**(job.get("env") or {}), **(step.get("env") or {})}.items()))
        flags = " ".join(t for t in run.split() if t not in files and t != _WINDOWS_ONLY_FLAG)
        for name in files:
            out.setdefault(name, []).append((env, flags))
    return {name: sorted(runs) for name, runs in out.items()}


def test_the_windows_leg_runs_the_ubuntu_legs_files_the_same_way() -> None:
    """Same files, each under the same MEFOR_* env and pytest flags, as often as on ubuntu."""
    linux = _runs_by_test_file(_ci_jobs()[_LINUX])
    windows = _runs_by_test_file(_ci_jobs()[_WINDOWS])
    assert linux and all(
        "('MEFOR_TEST_POSTGRES', '1')" in env for runs in linux.values() for env, _ in runs
    ), "control: the ubuntu postgres-store job parsed to no gated test files; the parsing drifted"
    assert windows == linux, (
        "postgres-store-windows has drifted from postgres-store. Append a file, or change a step's "
        "env or flags, in BOTH jobs.\n"
        f"  only ubuntu:  {sorted(set(linux) - set(windows))}\n"
        f"  only windows: {sorted(set(windows) - set(linux))}\n"
        f"  run differs:  {sorted(k for k in set(linux) & set(windows) if linux[k] != windows[k])}"
    )


def test_the_windows_leg_runs_on_the_ubuntu_legs_triggers_minus_the_queue() -> None:
    """The PR path gate, schedule and dispatch, on this repository only; NOT merge_group.

    docs/CI.md says why. Note what this does NOT prove: the `if:` does not name merge_group, so the
    leg stays out of the queue only because `changes` emits `serverdb=false` there, which
    tests/test_ci_merge_group_gate.py pins.
    """
    linux_if = str(_ci_jobs()[_LINUX]["if"]).strip()
    queue_arm = " || github.event_name == 'merge_group'"
    assert queue_arm in linux_if, "control: the ubuntu leg's queue arm moved; re-derive this test"
    expected = f"({linux_if.replace(queue_arm, '')}) && {_REPO_GUARD}"
    assert str(_ci_jobs()[_WINDOWS]["if"]).strip() == expected


def test_the_windows_leg_runs_on_hosted_windows_with_a_job_timeout() -> None:
    job = _ci_jobs()[_WINDOWS]
    assert job["runs-on"] == "${{ matrix.os }}"
    assert job["strategy"]["matrix"]["os"] == ["windows-2022", "windows-2025"]
    # GitHub's default is six hours, on 2x-billed runners.
    timeout = job.get("timeout-minutes")
    assert type(timeout) is int and 0 < timeout < 360, f"not a real job cap: {timeout!r}"


def test_the_windows_leg_runs_every_step_and_can_go_red() -> None:
    """Ways to skip a step, or never go red, that the per-file comparison cannot see."""
    job = _ci_jobs()[_WINDOWS]
    assert "continue-on-error" not in job
    for step in job["steps"]:
        assert "continue-on-error" not in step, step.get("name")
        run = str(step.get("run", ""))
        if "pytest" not in run:
            continue
        assert "if" not in step, f"a pytest step is conditional: {step.get('name')}"
        # Narrowing flags are caught by the per-file comparison; this flag is Windows-only.
        assert _WINDOWS_ONLY_FLAG in run.split(), f"{step.get('name')} lacks the flag"


def test_the_windows_leg_uses_the_ubuntu_legs_action_pins() -> None:
    """Same action at the same SHA, so an action bump cannot be the difference between the legs."""

    def pins(job: dict[str, Any]) -> dict[str, str]:
        return {str(s["uses"]).split("@")[0]: str(s["uses"]) for s in job["steps"] if "uses" in s}

    linux, windows = pins(_ci_jobs()[_LINUX]), pins(_ci_jobs()[_WINDOWS])
    assert linux, "control: the ubuntu job parsed to no `uses:` steps"
    assert windows == linux


def test_the_windows_leg_is_not_rolled_up_by_ci_gate() -> None:
    needs = needs_of(_ci_jobs()["ci-gate"])
    assert _LINUX in needs, "control: the ubuntu leg IS rolled up, so the needs parsing works"
    assert _WINDOWS not in needs, (
        "postgres-store-windows is in ci-gate's needs, which makes it merge-blocking through the "
        "required `CI gate` context. If that is now intended, it is a decision: move this test."
    )


def test_the_windows_leg_reports_no_required_context() -> None:
    required = set(required_contexts())
    assert "CI gate" in required, "control: the required-contexts parsing has drifted"
    job = _ci_jobs()[_WINDOWS]
    contexts = {_EXPR.sub(os, str(job["name"])) for os in job["strategy"]["matrix"]["os"]}
    assert all("${{" not in c for c in contexts), f"name template not expanded: {contexts}"
    assert not contexts & required
