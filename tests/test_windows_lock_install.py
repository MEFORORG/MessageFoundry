# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""security.yml's ``windows-lock-install`` job installs every hashed runtime lock on win32 (BACKLOG #5594).

Windows is the only supported v1 platform, and before this job nothing that runs on a pull request
installed a hashed lock there. These assertions pin the properties that make the job answer that
question: it runs on a Windows runner (so ``sys_platform == 'win32'`` markers evaluate as a deploying
site's do, which ``pip --platform`` on Linux does not), it installs each runtime lock with
``--require-hashes --only-binary :all:``, and it is not skipped on a pull request.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[1]
_SECURITY = _REPO / ".github" / "workflows" / "security.yml"
_JOB = "windows-lock-install"

#: The runtime locks a deploying Windows site would install from. A lock exported in the DEP-1 step
#: and installable on Windows that is missing here is the gap this job exists to close.
_RUNTIME_LOCKS = (
    "requirements.lock",
    "docker/locks/requirements-core.lock",
    "docker/locks/requirements-sqlserver.lock",
    "security/locks/requirements-harness.lock",
)


def _job() -> dict:
    doc = yaml.safe_load(_SECURITY.read_text(encoding="utf-8"))
    job = doc["jobs"].get(_JOB)
    assert job is not None, f"security.yml has no {_JOB!r} job (BACKLOG #5594)"
    return job


def _install_lines() -> list[str]:
    lines: list[str] = []
    for step in _job()["steps"]:
        for raw in str(step.get("run", "")).splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and re.search(r"\bpip\b.*\binstall\b", line):
                lines.append(line)
    return lines


def test_job_runs_on_a_windows_runner() -> None:
    runs_on = str(_job()["runs-on"])
    assert runs_on.startswith("windows-"), (
        f"{_JOB} runs on {runs_on!r}. Only a win32 interpreter evaluates the lock's "
        "`sys_platform == 'win32'` markers; `--platform win_amd64` on Linux still skips those pins."
    )


def test_job_reports_on_every_pull_request() -> None:
    job = _job()
    assert job.get("if") is None, f"{_JOB} carries a job-level if: and can skip a pull request"
    assert job.get("continue-on-error") in (None, False), f"{_JOB} discards its own failure"


def test_every_runtime_lock_is_installed_hashed_and_wheel_only() -> None:
    lines = _install_lines()
    for lock in _RUNTIME_LOCKS:
        hits = [ln for ln in lines if ln.endswith(f"-r {lock}")]
        assert len(hits) == 1, f"{_JOB} installs {lock} at {len(hits)} site(s), expected 1: {lines}"
        line = hits[0]
        assert "--require-hashes" in line, f"{lock} is installed without --require-hashes: {line}"
        assert "--only-binary :all:" in line, f"{lock} may build an sdist: {line}"
        assert "--dry-run" not in line, f"{lock} is only dry-run, so an uninstallable wheel passes"
        assert "--platform" not in line, (
            f"{lock} is installed with --platform, which changes tags but not marker evaluation"
        )


def test_each_lock_gets_a_freshly_cleared_venv() -> None:
    """One lock must not satisfy another's pin: every install follows its own ``venv --clear``."""
    body = "\n".join(str(s.get("run", "")) for s in _job()["steps"])
    code = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    installs = [i for i, ln in enumerate(code) if re.search(r"\bpip\b.*\binstall\b", ln)]
    assert installs, f"{_JOB} installs nothing"
    for i in installs:
        assert i > 0 and "-m venv --clear" in code[i - 1], (
            f"{_JOB}'s install {code[i]!r} does not follow a `python -m venv --clear`"
        )


def test_every_runtime_lock_exists() -> None:
    """Non-vacuity: a renamed lock would leave the job installing a path that is not there."""
    missing = [lock for lock in _RUNTIME_LOCKS if not (_REPO / lock).is_file()]
    assert not missing, f"runtime lock(s) named by {_JOB} are missing: {missing}"
