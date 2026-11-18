# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Polling shapes the API-burn guard used to let through (BACKLOG #5449).

scripts/hooks/block-api-burn.ps1 anchored `gh` only at a shell separator or a loop keyword, so a gh
whose output is ASSIGNED (`$r = gh ...`, `` s=`gh ...` ``) was never in command position; it
required `gh` and whitespace, so `gh.exe` was never gh; it ended `--watch` only at whitespace or the
end, so `--watch;` was no flag; and its forever-loop list held `while true`, `while :`,
`while ($true)` and `until`, so `while (1)` and `for (;;)` were no loop.

The allow arm pins the ordinary work the widened anchors must still pass. The guard is driven as a
subprocess with a real PreToolUse payload, through the helpers of tests/test_api_burn_guard.py.
"""

from __future__ import annotations

import shutil

import pytest

from tests.test_api_burn_guard import run_guard
from tests.test_blanket_stage_guard import assert_allowed, bash
from tests.test_worktree_gate import assert_denied

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)

MUST_DENY = [
    pytest.param(
        "while ($true) { $r = gh pr view 1 --json state; Start-Sleep 30 }",
        id="powershell-assignment-in-loop",
    ),
    pytest.param(
        "while true; do s=`gh run view 9 --json status`; sleep 30; done",
        id="bash-backtick-assignment-in-loop",
    ),
    pytest.param("gh.exe run watch 5", id="gh-exe-run-watch"),
    pytest.param("gh.exe pr checks 5 --watch", id="gh-exe-watch-flag"),
    pytest.param("while true; do gh.exe pr view 1; sleep 5; done", id="gh-exe-in-sleep-loop"),
    pytest.param("gh pr checks 5 --watch; echo done", id="watch-before-semicolon"),
    pytest.param("gh pr checks 5 --watch&& echo done", id="watch-before-and"),
    pytest.param("gh pr checks 5 --watch=true", id="watch-with-value"),
    pytest.param("while (1) { gh pr view 1 --json state }", id="powershell-while-1"),
    pytest.param("while(1){gh pr view 1}", id="powershell-while-1-unspaced"),
    pytest.param("for (;;) { gh pr view 1 --json state }", id="powershell-for-ever"),
    pytest.param("for ((;;)); do gh pr view 1; done", id="bash-for-ever"),
    pytest.param("while ((1)); do gh pr view 1; done", id="bash-while-arith-1"),
]

MUST_ALLOW = [
    pytest.param("$n = gh pr view 1 --json number", id="one-assignment-no-loop"),
    pytest.param("s=`gh pr view 1 --json state`; echo $s", id="one-backtick-read"),
    pytest.param("gh.exe pr view 1", id="gh-exe-single-read"),
    pytest.param('gh pr comment 5 --body "never --watch"', id="quoted-watch-mention"),
    pytest.param("gh pr checks 5; echo --watch-later", id="other-flag-prefix"),
    pytest.param("for (;;) { echo tick }", id="forever-without-gh"),
    pytest.param("for ($i = 0; $i -lt 3; $i++) { gh pr view $i }", id="bounded-powershell-for"),
]


@pytest.mark.parametrize("command", MUST_DENY)
def test_polling_shape_is_denied(command: str) -> None:
    assert "BLOCKED" in assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize("command", MUST_ALLOW)
def test_ordinary_gh_work_is_still_allowed(command: str) -> None:
    assert_allowed(run_guard(bash(command)))
