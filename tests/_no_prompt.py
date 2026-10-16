# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Launch a script the way the caller that hung did: stdin held OPEN, and no ``-NonInteractive``.

A Mandatory parameter that a partial call binds without supplying makes PowerShell PROMPT on stdin.
A caller whose stdin stays open and silent (the Bash tool) then waits forever. ``mail.ps1 -Send`` did
this until PR 2332, and vault BACKLOG #3627 found the same shape in more coordination scripts.

Neither condition may be dropped. ``-NonInteractive`` turns the prompt into an instant error, and
``subprocess.run`` closes stdin so the prompt reads EOF; either one hides the hang and lets a test
pass against the broken script.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from tests._spawn_lock import single_spawn

# Below pyproject.toml's --timeout=60 so a hang usually fails the calling test by name rather than the
# leg. Not always: a wait inside single_spawn() for a racer storm counts against the same per-test
# clock, so a launch that waits out a storm and then hangs can still hit pytest-timeout first.
PROMPT_TIMEOUT = 45


def run_holding_stdin_open(argv: Sequence[str], *, cwd: Path) -> tuple[int, str]:
    """Run ``argv`` with stdin open and silent; return ``(exit code, stderr)``, or fail on a hang."""
    # The context manager closes both pipes and reaps the process on every path, including the fail.
    with single_spawn(), subprocess.Popen(
        list(argv), cwd=str(cwd), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, text=True,
    ) as proc:  # fmt: skip
        try:
            # A refusal is one short error, far under a pipe buffer, so wait() cannot deadlock on it.
            # communicate() is not usable here: it closes stdin, which is the condition under test.
            rc = proc.wait(timeout=PROMPT_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            # Either cause is possible here, so name both: a slow pwsh start under load looks the same.
            pytest.fail(
                f"{' '.join(argv)} did not exit in {PROMPT_TIMEOUT}s: it is waiting on a stdin "
                "prompt, or pwsh started very slowly"
            )
        assert proc.stderr is not None
        return rc, proc.stderr.read()
