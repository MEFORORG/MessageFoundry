# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Launch a script the way the caller that hung did: stdin held OPEN, and no ``-NonInteractive``.

A Mandatory parameter that a partial call binds without supplying makes PowerShell PROMPT on stdin.
A caller whose stdin stays open and silent (the Bash tool) then waits forever. ``mail.ps1 -Send`` did
this until PR 2332, and vault BACKLOG #3627 found the same shape in more coordination scripts.

Neither condition may be dropped. ``-NonInteractive`` turns the prompt into an instant error. A
launch without ``stdin=PIPE`` inherits the test process's stdin, which pytest's default capture
points at a null device, so the prompt reads EOF. Either one hides the hang and lets a test pass
against the broken script.
"""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from tests._spawn_lock import single_spawn

# Below pyproject.toml's --timeout=60 so a hang usually fails the calling test by name rather than the
# leg. Not always: a wait inside single_spawn() for a racer storm counts against the same per-test
# clock, so a launch that waits out a storm and then hangs can still hit pytest-timeout first.
PROMPT_TIMEOUT = 45


def run_holding_stdin_open(
    argv: Sequence[str], *, cwd: Path, env: Mapping[str, str] | None = None
) -> tuple[int, str]:
    """Run ``argv`` with stdin open and silent; return ``(exit code, stderr)``, or fail on a hang."""
    err: list[str] = []
    # The context manager closes both pipes and reaps the process on every path, including the fail.
    with single_spawn(), subprocess.Popen(
        list(argv), cwd=str(cwd), env=env, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, text=True,
    ) as proc:  # fmt: skip
        stream = proc.stderr
        assert stream is not None
        # Drained on a thread so a script that fails OPEN and writes past the pipe buffer is not
        # misreported as a prompt hang. communicate() is not usable: it closes stdin, the condition
        # under test.
        reader = threading.Thread(target=lambda: err.append(stream.read()), daemon=True)
        reader.start()
        try:
            rc = proc.wait(timeout=PROMPT_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            reader.join(timeout=5)
            # Either cause is possible here, so name both: a slow pwsh start under load looks the same.
            pytest.fail(
                f"{' '.join(argv)} did not exit in {PROMPT_TIMEOUT}s: it is waiting on a stdin "
                f"prompt, or pwsh started very slowly. stderr so far: {''.join(err)[-2000:]!r}"
            )
        reader.join()
    return rc, "".join(err)
