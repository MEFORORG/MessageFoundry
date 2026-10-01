# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The semgrep install in ``security.yml`` retries, and must never let the scan run without it.

WHY THE RETRY EXISTS. semgrep is pinned, but its transitive set resolves live from PyPI. Merge-group
run 36832387843 (2026-10-01) failed the blocking semgrep gate at install time: pip reported
ResolutionImpossible with "no matching distributions" for pydantic-core at every version. Six minutes
later the same pin resolved pydantic-core 2.46.5 on the same runner image. One empty index read had
reded the merge queue.

WHAT IS PINNED. The retry is the convenience. The property that must not regress is that the step
stays FAIL-CLOSED: after the last failed attempt the step exits non-zero, and nothing after the loop
runs. This module runs the loop as committed, under ``bash -e`` like the runner's default shell, with
``python`` and ``sleep`` stubbed. A future edit that falls through to the scan after exhausting the
retries keeps every textual marker and fails here.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from _bash_resolver import probe_env, require_bash

yaml = pytest.importorskip("yaml")

_ROOT = Path(__file__).resolve().parents[1]
_SECURITY = _ROOT / ".github" / "workflows" / "security.yml"
_STEP_NAME = "Run the MessageFoundry rules"
_INSTALL = 'until python -m pip install --upgrade pip "semgrep==1.172.0"'
_ATTEMPTS = 3

#: Stubs for the two commands the loop calls. ``python`` fails until call number $SUCCEED_ON.
_STUBS = 'n=0\npython() { n=$((n + 1)); [ "$n" -ge "$SUCCEED_ON" ]; }\nsleep() { :; }\n'
#: Printed only if control reaches the code after the loop, where the scan runs.
_AFTER = 'echo "calls=${n}"\necho SCAN-REACHED\n'


def _retry_loops() -> list[str]:
    """The retry loop from every semgrep step, from ``attempt=1`` through its ``done``."""
    doc = yaml.safe_load(_SECURITY.read_text(encoding="utf-8"))
    loops: list[str] = []
    for job in doc["jobs"].values():
        for step in job.get("steps") or []:
            if not isinstance(step, dict) or step.get("name") != _STEP_NAME:
                continue
            lines = str(step.get("run")).splitlines()
            start = lines.index("attempt=1")
            end = lines.index("done", start)
            loops.append("\n".join(lines[start : end + 1]) + "\n")
    return loops


def test_every_semgrep_install_is_the_same_retry_loop() -> None:
    loops = _retry_loops()
    # Two today: the standalone semgrep job and the repo-scan composite. Fewer than two means a copy
    # lost its retry; the parity test owns the exact count of copies.
    assert len(loops) >= 2, f"expected the retry loop in both semgrep steps, found {len(loops)}"
    assert len(set(loops)) == 1, "the semgrep retry loops have drifted apart between copies"
    assert _INSTALL in loops[0], f"the loop no longer installs through {_INSTALL!r}"


@pytest.fixture(scope="module")
def bash(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return Path(require_bash(tmp_path_factory.mktemp("resolve-bash")))


def _drive(bash: Path, succeed_on: int) -> subprocess.CompletedProcess[str]:
    script = _STUBS + _retry_loops()[0] + _AFTER
    env = probe_env(bash, dict(os.environ, SUCCEED_ON=str(succeed_on)))
    return subprocess.run(
        [str(bash), "-e", "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )


@pytest.mark.parametrize("succeed_on", [1, 2, _ATTEMPTS])
def test_a_recovered_install_reaches_the_scan(bash: Path, succeed_on: int) -> None:
    result = _drive(bash, succeed_on)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"calls={succeed_on}" in result.stdout
    assert "SCAN-REACHED" in result.stdout


def test_an_install_that_never_succeeds_fails_closed(bash: Path) -> None:
    result = _drive(bash, _ATTEMPTS + 1)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "SCAN-REACHED" not in result.stdout, "the scan ran after every install attempt failed"
    assert "::error::" in result.stdout
    assert result.stdout.count("::warning::") == _ATTEMPTS - 1
