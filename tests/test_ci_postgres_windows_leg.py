# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The hosted-Windows Postgres store leg in ci.yml: what it runs, and that it gates nothing.

`postgres-store-windows` exists because Windows is the only supported v1 deployment platform (owner
ruling 2026-10-16) and `postgres-store` runs on ubuntu only. It is a COPY of that job's test steps,
and a copy drifts: the ubuntu job's steps say to APPEND each new lever's test file, and an append
that lands on one job only would leave the other silently narrower. So this module pins the copy to
its source rather than to a list of its own.

It also pins that the leg is advisory. `CI gate` is a required context, so a job in its `needs` is a
merge blocker in all but name; the leg is new and unmeasured, and making it blocking is a separate
decision that should move this test on purpose.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_REQUIRED = _ROOT / ".github" / "required-contexts.txt"

_LINUX = "postgres-store"
_WINDOWS = "postgres-store-windows"
_REPO_GUARD = "github.repository == 'MEFORORG/MessageFoundry'"


def _jobs() -> dict[str, Any]:
    jobs: dict[str, Any] = yaml.safe_load(_CI.read_text(encoding="utf-8"))["jobs"]
    return jobs


def _test_files(job: dict[str, Any]) -> list[str]:
    """Every tests/test_*.py a job's steps name in a `run:`, in order, duplicates kept."""
    found: list[str] = []
    for step in job["steps"]:
        found += re.findall(r"tests/test_[A-Za-z0-9_]+\.py", str(step.get("run", "")))
    return found


def _pytest_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in job["steps"] if "pytest" in str(s.get("run", ""))]


def test_the_windows_leg_runs_exactly_the_ubuntu_legs_test_files() -> None:
    jobs = _jobs()
    linux, windows = _test_files(jobs[_LINUX]), _test_files(jobs[_WINDOWS])
    assert linux, "found no test files in the ubuntu postgres-store job; the parsing has drifted"
    assert sorted(windows) == sorted(linux), (
        "postgres-store-windows no longer runs the same test files as postgres-store. Append the "
        "file to BOTH jobs.\n"
        f"  only ubuntu:  {sorted(set(linux) - set(windows))}\n"
        f"  only windows: {sorted(set(windows) - set(linux))}"
    )


def test_the_windows_leg_connects_with_the_ubuntu_legs_store_env() -> None:
    """Same MEFOR_STORE_* and gate env, so the two legs differ only in the server under them."""
    jobs = _jobs()
    linux_envs = [dict(s.get("env") or {}) for s in _pytest_steps(jobs[_LINUX])]
    assert linux_envs, "found no pytest steps in the ubuntu postgres-store job"
    common = {k: v for k, v in linux_envs[0].items() if all(e.get(k) == v for e in linux_envs)}
    assert common.get("MEFOR_TEST_POSTGRES") == "1", "the parsing has drifted: no shared gate env"
    assert dict(jobs[_WINDOWS]["env"]) == common

    # Per-step extras (the connscale step's pool size) must match by step too.
    def extras(job: dict[str, Any], base: dict[str, Any]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for step in _pytest_steps(job):
            extra = {k: v for k, v in (step.get("env") or {}).items() if base.get(k) != v}
            for name in re.findall(r"tests/test_[A-Za-z0-9_]+\.py", str(step["run"])):
                out[name] = extra
        return out

    assert extras(jobs[_WINDOWS], common) == extras(jobs[_LINUX], common)


def test_the_windows_leg_runs_when_the_ubuntu_leg_runs_and_only_here() -> None:
    jobs = _jobs()
    linux_if = str(jobs[_LINUX]["if"]).strip()
    assert str(jobs[_WINDOWS]["if"]).strip() == f"({linux_if}) && {_REPO_GUARD}"


def test_the_windows_leg_runs_on_hosted_windows_only() -> None:
    job = _jobs()[_WINDOWS]
    assert job["runs-on"] == "${{ matrix.os }}"
    assert job["strategy"]["matrix"]["os"] == ["windows-2022", "windows-2025"]


def test_the_windows_leg_has_a_job_timeout() -> None:
    """GitHub's default is six hours, and this leg runs on 2x-billed runners."""
    timeout = _jobs()[_WINDOWS].get("timeout-minutes")
    assert isinstance(timeout, int) and 0 < timeout < 360


def test_the_windows_leg_is_not_rolled_up_by_ci_gate() -> None:
    needs = _jobs()["ci-gate"]["needs"]
    assert _LINUX in needs, "control: the ubuntu leg IS rolled up, so the needs parsing works"
    assert _WINDOWS not in needs, (
        "postgres-store-windows is in ci-gate's needs, which makes it merge-blocking through the "
        "required `CI gate` context. If that is now intended, it is a decision: move this test."
    )


def test_the_windows_leg_reports_no_required_context() -> None:
    required = {
        line.strip()
        for line in _REQUIRED.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert "CI gate" in required, "control: the required-contexts parsing has drifted"
    job = _jobs()[_WINDOWS]
    contexts = {
        str(job["name"]).replace("${{ matrix.os }}", os) for os in job["strategy"]["matrix"]["os"]
    }
    assert contexts == {"postgres store (windows-2022)", "postgres store (windows-2025)"}
    assert not contexts & required
