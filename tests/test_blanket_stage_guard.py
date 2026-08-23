# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
r"""Tests for the blanket-git-stage PreToolUse guard (scripts/hooks/block-blanket-git-stage.ps1).

The guard stops one session sweeping another session's files into its commit: it denies
`git add -A/--all/-u/.` and `git commit -a/-am/--all`, and passes everything else silently.

THE CASE THESE TESTS EXIST FOR. The guard used to match the program name with `-cnotmatch`, so it
compared a SPELLING while Windows resolves an EXECUTABLE. `git`, `Git` and `GIT` all run the same
git.exe -- measured, all three print the same `git --version` under PowerShell and under Git Bash
-- so `Git add -A` staged the whole tree while `git add -A` was denied, and the only difference was
the capital letter. The program name is now matched case-insensitively.

ONLY THE PROGRAM NAME. The subcommand and flag tests stay case-SENSITIVE, and the allow-side cases
below pin that. Measured against real git: `git ADD .` returns "git: 'ADD' is not a git command",
`git add -a` returns "error: unknown switch `a'", and `git commit --ALL` returns "error: unknown
option `ALL'". Folding case there would deny commands git itself refuses to run.

KNOWN OVER-DENY, AND THE CASE FIX WIDENED IT. The guard splits on `(\|\||&&|[;|&\n])`, which
carries no quote or line state, so quoted text after a newline, `;`, `|` or `&` lands at the front
of a segment and is read there as a program name. Prose that quotes a blanket-stage command is
denied on that path: a heredoc writing a doc, a commit message body, a `gh pr create --body`, even
a single-line markdown table cell. Two non-prose commands go the same way -- `git log --all --grep
commit` and `git grep -n add -- .` are read-only and both deny -- because the subcommand and flag
tokens are matched ANYWHERE in the segment rather than at argv position.

THE CLASS IS PRE-EXISTING, WHICH IS WHY THE CASE FIX STILL LANDED. Every case below was driven
against the committed guard in its lowercase spelling first, and every one already denied. The fix
widens the class from one spelling to all of them; it creates no new class, and across roughly 800
driven payloads nothing flipped from DENY to ALLOW. The real repair is a program-position test over
a quote-aware splitter -- `Test-GitProgramPosition` exists at `c0d6cef8^` and was removed by the
revert at `c0d6cef8` -- which belongs to the shared segment-scanner work and has no allocated
number here. The cases are pinned below so that work flips them deliberately.

A MEASUREMENT THAT DID NOT ANSWER THIS QUESTION, recorded so it is not repeated. A scan of every
tracked file found 1 segment that already trips the guard and 0 that the case fix newly trips. The
arithmetic replicates and the population is wrong: the guard screens `tool_input.command`, while
every false deny above lives in text composed at call time -- a commit body, a heredoc, a PR body
-- which a scan of tracked file CONTENT cannot contain by construction. Only ten tracked segments
lead with a non-lowercase "Git" at all, so zero out of ten could never have separated "safe" from
"this corpus has almost none of the shape".

Each test drives the real hook as a subprocess with a real PreToolUse payload on stdin, so the
contract under test is the one Claude Code actually invokes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

# The deny ENVELOPE is one contract shared by every PreToolUse hook here, so its assertion has one
# home; tests/test_worktree_gate_git.py imports it from the same place.
from tests.test_worktree_gate import assert_denied

GUARD = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "block-blanket-git-stage.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def run_guard(payload: dict[str, Any] | str) -> dict[str, Any] | None:
    """Invoke the hook exactly as Claude Code does. Returns the deny object, or None for 'allow'."""
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(GUARD)],
        input=raw,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # The guard is fail-OPEN: a non-zero exit would be a guardrail wedging git work, and an exit
    # code the harness ignores would leave the guard off with nobody the wiser.
    assert proc.returncode == 0, f"guard exited {proc.returncode}: {proc.stderr}"
    if not proc.stdout.strip():
        return None
    decision: dict[str, Any] = json.loads(proc.stdout)
    return decision


def bash(command: str, tool: str = "Bash") -> dict[str, Any]:
    # No cwd is threaded through: unlike the worktree gate, this guard never reads $j.cwd.
    return {
        "session_id": "s-1",
        "cwd": "C:/repo",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    }


def assert_allowed(result: dict[str, Any] | None) -> None:
    assert result is None, f"expected ALLOW, got deny: {result}"


# ------------------------------------------------------------------ the case bypass, now closed

# Every spelling here RUNS on Windows and used to pass the guard untouched. The list is a FAMILY on
# purpose -- title case, all caps and mixed -- because a test pinning one spelling cannot see a fix
# that handles two.
CAPITALISED_DENY = [
    "Git add -A",
    "GIT add -A",
    "gIt add -A",
    "giT add .",
    "Git add --all",
    "GIT add -u",
    "Git commit -a",
    "GIT commit -am wip",
    "Git commit --all",
    "Git\tadd\t-A",
]


@pytest.mark.parametrize("command", CAPITALISED_DENY)
def test_a_capitalised_git_is_still_the_git_program(command: str) -> None:
    assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize("command", ["git add -A", "git commit -am wip"])
def test_the_lowercase_spelling_still_denies(command: str) -> None:
    """The floor. Widening the program match must not cost the coverage that already worked."""
    assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize(
    "command",
    [
        "cd sub && Git add -A",
        "cd sub; GIT commit -am wip",
        "ls | Git add -A",
        "false || Git add --all",
    ],
)
def test_a_capitalised_git_after_a_shell_separator_denies(command: str) -> None:
    """Each shell-separated simple command is judged on its own, in every spelling."""
    assert_denied(run_guard(bash(command)))


def test_the_powershell_tool_is_guarded_too() -> None:
    assert_denied(run_guard(bash("Git add -A", tool="PowerShell")))


# ------------------------------------------------- the subcommand and the flags stay case-bound

CASE_BOUND_ALLOW = [
    "git ADD -A",
    "GIT ADD -A",
    "git COMMIT -am wip",
    "Git commit -AM wip",
    "git add --ALL",
    "git commit --ALL",
]


@pytest.mark.parametrize("command", CASE_BOUND_ALLOW)
def test_a_miscased_subcommand_or_flag_is_not_a_blanket_stage(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


# --------------------------------------------------------------------------- the rest still runs

ORDINARY_ALLOW = [
    "git add README.md",
    "Git add README.md docs/X.md",
    "git commit -m 'a message'",
    "Git commit -m 'a message'",
    "git commit --amend",
    "Git commit --amend --no-edit",
    "git status",
    "gitk --all",
    "git-add -A",
    'echo "see Git add -A"',
]


@pytest.mark.parametrize("command", ORDINARY_ALLOW)
def test_ordinary_work_is_not_denied(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


def test_the_anchor_holds_so_a_word_ending_in_git_is_not_the_program() -> None:
    """`^` pins the match to the front of a split segment. Widening the CASE must not widen that."""
    assert_allowed(run_guard(bash("legit add -A")))
    assert_allowed(run_guard(bash("/usr/bin/legit add -A")))


# ------------------------------------------------------------------------------ the deny message


def test_the_add_deny_names_the_flag_and_the_way_forward() -> None:
    reason = assert_denied(run_guard(bash("GIT add -A")))
    assert "-A/--all/-u/." in reason
    assert "git add <path>" in reason  # a deny must say how to proceed, not just say no


def test_the_commit_deny_names_its_own_rule() -> None:
    reason = assert_denied(run_guard(bash("Git commit -am wip")))
    assert "-a/-am/--all" in reason


# -------------------------------------------------------------- the known over-deny, pinned

# These are WRONG, and they are pinned so a future program-position fix flips them on purpose
# rather than finding them. Each pair asserts the capitalised form the case fix newly denies AND
# the lowercase form that already denied before it -- the pair is the evidence that this widens an
# existing class rather than creating one. See the module docstring.
OVER_DENY_PAIRS = [
    pytest.param(
        'git commit -m "fix\nGit add -A is blocked"',
        'git commit -m "fix\ngit add -A is blocked"',
        id="commit-message-body",
    ),
    pytest.param(
        "cat >> docs/X.md <<'EOF'\nGit add -A stages everything.\nEOF",
        "cat >> docs/X.md <<'EOF'\ngit add -A stages everything.\nEOF",
        id="heredoc-writing-a-doc",
    ),
    pytest.param(
        'echo "| Git add -A | denied |" >> docs/X.md',
        'echo "| git add -A | denied |" >> docs/X.md',
        id="single-line-split-on-pipe-inside-quotes",
    ),
    pytest.param(
        'git commit -m "wip; Git add -A was the trap"',
        'git commit -m "wip; git add -A was the trap"',
        id="single-line-split-on-semicolon-inside-quotes",
    ),
    pytest.param(
        "Git log --all --grep commit",
        "git log --all --grep commit",
        id="read-only-log-search",
    ),
    pytest.param(
        "Git grep -n add -- .",
        "git grep -n add -- .",
        id="read-only-content-search",
    ),
]


@pytest.mark.parametrize(("capitalised", "lowercase"), OVER_DENY_PAIRS)
def test_prose_and_read_only_commands_are_over_denied(capitalised: str, lowercase: str) -> None:
    assert_denied(run_guard(bash(capitalised)))
    assert_denied(run_guard(bash(lowercase)))


# --------------------------------------------------------------------------------- still fail-open


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "not json at all", "{}", '{"tool_input": {}}', '{"tool_input": {"command": ""}}'],
)
def test_a_payload_the_guard_cannot_read_allows(raw: str) -> None:
    """A guardrail must never wedge all git work. Anything unreadable passes silently."""
    assert_allowed(run_guard(raw))
