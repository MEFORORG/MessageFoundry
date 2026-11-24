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

from tests._workflow_contexts import WORKFLOWS, jobs_of

_REPO = Path(__file__).resolve().parents[1]
_JOB = "windows-lock-install"

#: The runtime locks a deploying Windows site would install from. A lock exported in the DEP-1 step
#: and installable on Windows that is missing here is the gap this job exists to close.
_RUNTIME_LOCKS = (
    "requirements.lock",
    "docker/locks/requirements-core.lock",
    "docker/locks/requirements-sqlserver.lock",
    "docker/locks/requirements-postgres.lock",
    "security/locks/requirements-harness.lock",
    # Not a runtime lock, but release.yml's `sbom-windows` job installs it on Windows.
    "ci/locks/release-tools.lock",
)

#: DEP-1 exports no Windows job installs: the Linux-run scanner and quality toolchains, and the
#: hashless constraints file.
_NOT_ON_WINDOWS = frozenset(
    {"ci/locks/ci-scanners.lock", "ci/locks/ci-quality.lock", "constraints.lock"}
)


def _job() -> dict:
    job = jobs_of("security.yml").get(_JOB)
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
        # ...and installs INTO the venv just cleared, not some other interpreter.
        venv = code[i - 1].rsplit(" ", 1)[-1].strip('"')
        assert f'--python "{venv}/Scripts/python.exe"' in code[i], (
            f"{_JOB}'s install {code[i]!r} does not target the venv {venv!r} cleared before it"
        )


def test_the_lock_list_matches_the_dep1_runtime_exports() -> None:
    """The list above is a copy, so pin it to its source: every lock the DEP-1 step exports, less
    the ones named in ``_NOT_ON_WINDOWS``. A lock added there without being added here, and to the
    job, reds this; so does a Windows-installed lock filed as not-on-Windows."""
    text = (WORKFLOWS / "security.yml").read_text(encoding="utf-8")
    exported = set(re.findall(r"^[ \t]*uv export .*-o (\S+)[ \t]*$", text, flags=re.MULTILINE))
    assert exported, "found no `uv export ... -o` line in security.yml; this check sees nothing"
    assert exported >= _NOT_ON_WINDOWS, sorted(_NOT_ON_WINDOWS - exported)
    runtime = exported - _NOT_ON_WINDOWS
    assert runtime == set(_RUNTIME_LOCKS), (
        f"DEP-1 runtime exports {sorted(runtime)} differ from {_JOB}'s list {sorted(_RUNTIME_LOCKS)}"
    )


def test_every_runtime_lock_exists() -> None:
    """Non-vacuity: a renamed lock would leave the job installing a path that is not there."""
    assert _RUNTIME_LOCKS, "_RUNTIME_LOCKS in this test file is empty; this check walks nothing"
    missing = [lock for lock in _RUNTIME_LOCKS if not (_REPO / lock).is_file()]
    assert not missing, f"runtime lock(s) named by {_JOB} are missing: {missing}"
