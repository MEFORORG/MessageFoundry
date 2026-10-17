# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the GitHub-API-polling PreToolUse guard.

The guard (``scripts/hooks/block-api-burn.ps1``) denies `gh run watch`, a `--watch` flag on any gh
command, and a hand-rolled poll loop around gh, because every session on a machine spends one
shared GitHub budget. Why it is still needed, with the 2026-10-17 measurement, is in its header.

THE TWO ARMS ARE DISJOINT AND BOTH ARE REQUIRED. The deny arm alone passes for a guard that denies
everything, and the allow arm alone passes for a guard that denies nothing. The allow arm carries
the false denies measured in real transcripts, because a guard that blocks ordinary work gets
switched off.

Each test drives the real hook as a subprocess with a real PreToolUse payload on stdin.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.test_blanket_stage_guard import assert_allowed, bash
from tests.test_worktree_gate import assert_denied

GUARD = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "block-api-burn.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def run_guard(payload: dict[str, Any] | str) -> dict[str, Any] | None:
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(GUARD)],
        input=raw,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, f"guard exited {proc.returncode}: {proc.stderr}"
    if not proc.stdout.strip():
        return None
    decision: dict[str, Any] = json.loads(proc.stdout)
    return decision


MUST_DENY = [
    pytest.param("gh run watch", id="run-watch"),
    pytest.param("gh run watch 12345 --exit-status", id="run-watch-with-id"),
    pytest.param("gh pr checks 5 --watch", id="checks-watch"),
    pytest.param("cd /tmp && gh run watch", id="after-separator"),
    pytest.param('bash -c "gh run watch"', id="behind-bash-c"),
    pytest.param("pwsh -Command 'gh pr checks 5 --watch'", id="behind-pwsh-command"),
    pytest.param("while true; do gh pr view 1; sleep 3; done", id="while-loop"),
    pytest.param(
        'until s=$(gh pr view 9 --json state --jq .state) && [ "$s" = MERGED ]; do sleep 300; done',
        id="until-loop-gh-in-condition",
    ),
    pytest.param(
        "for i in $(seq 100); do gh run view 9 --json status; sleep 30; done", id="for-loop"
    ),
    pytest.param(
        "while ($true) { gh pr view 1 --json state; Start-Sleep -Seconds 30 }",
        id="powershell-while",
    ),
    pytest.param(
        "do { gh pr view 1 --json state; Start-Sleep 30 } while ($true)", id="powershell-do-while"
    ),
    pytest.param("bash -lc 'gh run watch 5'", id="behind-bash-lc"),
    pytest.param('cmd /c "gh run watch 5"', id="behind-cmd-c"),
    # The measured nested shape: a forever loop reading several PRs, sleeping between rounds.
    pytest.param(
        "while :; do open=''; for p in 1 2 3; do s=$(gh pr view $p --json state --jq .state); "
        'open="$open $s"; done; sleep 600; done',
        id="measured-while-colon-nested-for",
    ),
    pytest.param(
        "1..100 | ForEach-Object { gh pr view 1 --json state; Start-Sleep 30 }",
        id="powershell-foreach-object",
    ),
    # No sleep at all is the worst rate, not a safe one.
    pytest.param("while true; do gh pr view 1 --json state; done", id="tight-while-true"),
    pytest.param("until gh pr merge 5 --squash; do :; done", id="tight-until"),
    pytest.param("sleep 5; while true; do gh pr view 1; done", id="sleep-before-forever-loop"),
    pytest.param("while ($true) { gh pr view 1 --json state }", id="tight-powershell-while"),
]

MUST_ALLOW = [
    pytest.param('echo "gh run watch is banned"', id="quoted-mention"),
    pytest.param('echo "do not use gh pr checks --watch"', id="quoted-flag-mention"),
    pytest.param("gh run view 12345", id="single-shot-view"),
    pytest.param("gh pr checks 5", id="checks-without-watch"),
    pytest.param("gh pr view 48 --json statusCheckRollup", id="rollup-read"),
    pytest.param("sleep 3", id="bare-sleep"),
    pytest.param("while true; do echo tick; sleep 1; done", id="loop-without-gh"),
    # The measured false deny: one sleep, then one read of each PR.
    pytest.param(
        "gh api -X PUT repos/o/r/pulls/1/update-branch; sleep 5; "
        "for n in 1 2 3; do gh pr view $n --json mergeable; done",
        id="sleep-once-then-read-each",
    ),
    pytest.param(
        "for n in 1 2 3; do gh pr view $n --json state; done", id="loop-of-reads-no-sleep"
    ),
    pytest.param(
        'gh pr comment 5 --body "we do this later"; sleep 2; gh pr view 5',
        id="prose-do-before-sleep",
    ),
    pytest.param(
        'gh pr comment 5 --body "fix for the flake, while waiting"; sleep 2; gh pr view 5',
        id="prose-for-and-while-before-sleep",
    ),
    pytest.param('gh pr comment 5 --body "never use --watch"', id="quoted-watch-at-body-end"),
    pytest.param("for f in *.log; do grep -c gh $f; sleep 1; done", id="grep-c-gh-is-not-gh"),
    pytest.param(
        "gh pr list --json number --jq '.[].number' | while read n; do gh pr view $n; done",
        id="while-read-iterates-and-ends",
    ),
]


@pytest.mark.parametrize("command", MUST_DENY)
def test_polling_is_denied(command: str) -> None:
    assert "BLOCKED" in assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize("command", MUST_ALLOW)
def test_ordinary_gh_work_is_allowed(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


def test_the_loop_deny_names_the_cache_escape() -> None:
    reason = assert_denied(run_guard(bash("while true; do gh pr view 1; sleep 3; done")))
    assert "--cache 60s" in reason


@pytest.mark.parametrize("raw", ["", "not json", "{}", '{"tool_input": {}}'])
def test_unreadable_input_fails_open(raw: str) -> None:
    assert_allowed(run_guard(raw))
