# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Polling shapes the API-burn guard used to let through (BACKLOG #5449).

scripts/hooks/block-api-burn.ps1 anchored `gh` only at a shell separator or a loop keyword, so a gh
whose output is ASSIGNED (`$r = gh ...`, `` s=`gh ...` ``) was never in command position; it
required `gh` and whitespace, so `gh.exe` was never gh; it ended `--watch` only at whitespace or the
end, so `--watch;` was no flag; and its forever-loop list held `while true`, `while :`,
`while ($true)` and `until`, so `while (1)` and `for (;;)` were no loop.

The deny arm pins at least those shapes; it does not claim every way to run gh or to loop, and the
open bypasses are listed beside $ASSIGN in the guard. The allow arm pins the ordinary work the
widened anchors must still pass, including the commands origin/main allowed that the first cuts of
this change denied. The guard is driven as a subprocess with a real PreToolUse payload, through the
helpers of tests/test_api_burn_guard.py.
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
    pytest.param("s=`gh pr checks 5 --watch`", id="watch-closed-by-a-backtick"),
    pytest.param("gh pr checks 5 --watch>out.txt", id="watch-before-a-redirect"),
    pytest.param("while (1) { gh pr view 1 --json state }", id="powershell-while-1"),
    pytest.param("while(1){gh pr view 1}", id="powershell-while-1-unspaced"),
    pytest.param("for (;;) { gh pr view 1 --json state }", id="powershell-for-ever"),
    pytest.param("for ((;;)); do gh pr view 1; done", id="bash-for-ever"),
    pytest.param("while ((1)); do gh pr view 1; done", id="bash-while-arith-1"),
    pytest.param("do { gh pr view 1 --json state } while (1)", id="powershell-do-while-1"),
    pytest.param(
        "do { $r = gh pr view 1 --json state; Start-Sleep 30 } while ($true)",
        id="powershell-do-while-assignment",
    ),
    pytest.param("gh pr checks 5 -R 'o/r' --watch; echo done", id="watch-after-a-quoted-argument"),
    pytest.param('gh pr checks 5 --repo "o/r" --watch&& echo done', id="watch-after-quoted-repo"),
]

MUST_ALLOW = [
    pytest.param("$n = gh pr view 1 --json number", id="one-assignment-no-loop"),
    pytest.param("s=`gh pr view 1 --json state`; echo $s", id="one-backtick-read"),
    pytest.param("gh.exe pr view 1", id="gh-exe-single-read"),
    pytest.param('gh pr comment 5 --body "never --watch"', id="quoted-watch-mention"),
    pytest.param("gh pr checks 5; echo --watch-later", id="other-flag-prefix"),
    pytest.param("for (;;) { echo tick }", id="forever-without-gh"),
    # Each reaches the widened patterns and must not be denied by them.
    pytest.param(
        "gh pr view 1; for ($i = 0; $i -lt 3; $i++) { echo x }", id="bounded-for-is-not-forever"
    ),
    pytest.param("git commit -m 'Replace `gh run watch` with one read'", id="backticked-mention"),
    pytest.param("git log --grep=gh run watch", id="option-value-is-not-an-assignment"),
    pytest.param(
        'gh pr comment 5 --body "do not use --watch; read once"', id="watch-in-quoted-prose"
    ),
    pytest.param(
        'gh pr comment 5 --body "polling (gh pr checks --watch) burns budget"',
        id="watch-in-parenthesised-prose",
    ),
    pytest.param("gh pr checks 5 --watch=false", id="watch-explicitly-off"),
    pytest.param("for ($i = 0; $i -lt 3; $i++) { gh pr view $i }", id="bounded-powershell-for"),
    # Allowed on origin/main and newly denied by the first two cuts of this change (review round
    # 2c1df56a). None of them watches with gh or runs gh in a loop.
    pytest.param("gh pr checkout 5 && npx jest --watch;", id="watch-belongs-to-a-later-command"),
    pytest.param(
        "gh pr view 5 --json number\nnpx jest --watch;", id="watch-on-a-later-line-of-a-script"
    ),
    pytest.param('echo "never write $x = gh run watch"', id="powershell-assignment-in-prose"),
    pytest.param(
        "while true; do if [ $x = gh ]; then break; fi; done", id="test-bracket-compares-to-gh"
    ),
    pytest.param("s=gh run watch", id="gh-as-an-assigned-string-value"),
    pytest.param("gh pr view 5; while (1) { echo tick }", id="while-1-body-without-gh"),
    pytest.param("gh pr view 5 && for ((;;)); do date; done", id="for-ever-body-without-gh"),
    pytest.param("gh pr checks 5 --watch=0", id="watch-explicitly-zero"),
    pytest.param("if (gh pr view 1) { echo --watch; }", id="watch-belongs-to-a-braced-body"),
    pytest.param("gh pr checks 5 --watch=f", id="watch-explicitly-f"),
    # Review round de5b1e8b: each calls gh once, origin/main allowed it, and the widened anchor
    # alone handed it to the old whole-line rules.
    pytest.param(
        "$prs = gh pr list --json number; foreach ($p in $prs) { Start-Sleep 1 }",
        id="assigned-gh-then-a-sleeping-loop",
    ),
    pytest.param("$n = gh pr view 1; npx jest --watch", id="assigned-gh-then-another-watch"),
    pytest.param("gh.exe pr view 1; npx jest --watch", id="gh-exe-then-another-watch"),
    pytest.param(
        "$x = gh pr view 1 --json title; Write-Host 'gh run watch is banned'",
        id="assigned-gh-then-run-watch-prose",
    ),
    pytest.param(
        "$o = gh pr view 1 --json state; until ((Test-Path flag)) { Start-Sleep 1 }",
        id="assigned-gh-then-an-until-loop",
    ),
    pytest.param(
        'gh pr comment 5 --body "Replaced the poll (gh pr checks --watch; 1200/hr) with one read"',
        id="watch-in-bracketed-quoted-prose",
    ),
    pytest.param(
        'git commit -m "Drop the poll; gh pr checks 5 --watch; is banned"',
        id="watch-after-a-separator-in-quoted-prose",
    ),
    pytest.param("gh pr view 5 # never use --watch; read once", id="watch-in-a-comment"),
    pytest.param(
        'echo "never do this; $y = gh run watch 5"', id="assignment-after-quoted-separator"
    ),
    # STILL DENIED, AND PINNED SO A FIX SHOWS. The guard cannot find where a loop body ends, so a
    # gh after a while (1) or for (;;) loop reads as inside it. That gh runs once at most, so each
    # is a false deny; a body-end rule would lose the deny on a nested body such as
    # `for (;;) { if (x) { y }; gh ... }`.
    pytest.param(
        "while (1) { echo tick }; gh pr view 5",
        id="gh-after-a-forever-loop",
        marks=pytest.mark.xfail(strict=True, reason="loop body end is not parsed"),
    ),
    pytest.param(
        "while (1) { if (Test-Path x) { break } }; gh pr view 5",
        id="gh-after-a-loop-that-breaks",
        marks=pytest.mark.xfail(strict=True, reason="loop body end is not parsed"),
    ),
]


@pytest.mark.parametrize("command", MUST_DENY)
def test_polling_shape_is_denied(command: str) -> None:
    assert "BLOCKED" in assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize("command", MUST_ALLOW)
def test_ordinary_gh_work_is_still_allowed(command: str) -> None:
    assert_allowed(run_guard(bash(command)))
