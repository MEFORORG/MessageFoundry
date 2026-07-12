"""Tests for rule 3 of the worktree gate: git commands that swap the SHARED PRIMARY's working tree.

This rule exists because it actually happened. A sibling session ran `git checkout <its-branch>` inside
the shared primary checkout and then left HEAD detached — and every other session standing in that
directory silently found itself reading a different commit's files. Rules 1 and 2 cannot see it: a git
command is a SHELL call, not an Edit, so no amount of tool-argument inspection catches it.

The rule is narrow on purpose. Only verbs that change WHICH COMMIT the primary's tree reflects, or that
discard work, are denied — and only for the primary. A worktree may switch its own branch freely.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the harness

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def shell(command: str, cwd: Path | str, tool: str = "Bash") -> dict[str, Any]:
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    }


@pytest.fixture
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


# --------------------------------------------------------------------- the verb that caused the damage


@pytest.mark.parametrize(
    "command",
    [
        "git checkout claude/some-branch",
        "git switch other-branch",
        "git reset --hard origin/main",
        "git stash push -u",
        "git clean -fd",
        "git restore .",
        "git rebase origin/main",
        "git merge origin/main",
        "git cherry-pick abc123",
        "git revert abc123",
    ],
)
def test_tree_swapping_verbs_are_denied_in_the_primary(
    primary: Path, repos_file: Path, command: str
) -> None:
    reason = assert_denied(run_gate(shell(command, cwd=primary), repos_file))
    assert "SHARED PRIMARY" in reason
    assert "restore-primary.ps1" in reason  # the repair path must be offered, not just a refusal


def test_reaching_into_the_primary_with_dash_C_is_denied(tmp_path: Path, repos_file: Path) -> None:
    """A session sitting in a worktree can still hijack the primary — a cwd-only check misses this."""
    worktree = tmp_path / "Repo-alerts"
    primary = tmp_path / "Repo"
    assert_denied(run_gate(shell(f'git -C "{primary}" checkout main', cwd=worktree), repos_file))


def test_cd_into_the_primary_then_checkout_is_denied(tmp_path: Path, repos_file: Path) -> None:
    """`cd <primary>; git checkout x` defeats both cwd and -C parsing, so the path is matched in-text."""
    worktree = tmp_path / "Repo-alerts"
    primary = tmp_path / "Repo"
    assert_denied(run_gate(shell(f"cd {primary} && git checkout main", cwd=worktree), repos_file))


def test_git_exe_spelling_is_denied(primary: Path, repos_file: Path) -> None:
    assert_denied(run_gate(shell("git.exe checkout main", cwd=primary), repos_file))


# --------------------------------------------------------------------- what must keep working


@pytest.mark.parametrize(
    "command",
    [
        "git status",
        "git log --oneline -5",
        "git diff origin/main",
        "git show HEAD:docs/adr/README.md",
        "git fetch origin",
        "git branch --list",
        "git worktree list",
        "git rev-parse HEAD",
        "git ls-tree --name-only origin/main docs/",
        "git commit -m 'x'",
        "git push -u origin branch",
        "git pull --ff-only",
        "git merge-base HEAD origin/main",
        "git merge-tree --write-tree a b",
    ],
)
def test_reads_and_safe_verbs_are_allowed_in_the_primary(
    primary: Path, repos_file: Path, command: str
) -> None:
    assert run_gate(shell(command, cwd=primary), repos_file) is None


def test_a_worktree_may_switch_its_own_branch(tmp_path: Path, repos_file: Path) -> None:
    """Only the SHARED primary is protected — a worktree's own tree is its own business."""
    worktree = tmp_path / "Repo-alerts"
    assert run_gate(shell("git checkout -b feature/x", cwd=worktree), repos_file) is None
    assert run_gate(shell("git reset --hard HEAD~1", cwd=worktree), repos_file) is None


def test_a_different_repo_is_untouched(tmp_path: Path, repos_file: Path) -> None:
    other = tmp_path / "SomethingElse"
    assert run_gate(shell("git checkout main", cwd=other), repos_file) is None


def test_the_repair_script_itself_is_allowed(primary: Path, repos_file: Path) -> None:
    """The escape hatch must pass the guard, or the gate becomes a trap: an agent may REPAIR the primary,
    it just may not hijack it."""
    cmd = rf"pwsh -NoProfile -File {primary}\scripts\worktree\restore-primary.ps1"
    assert run_gate(shell(cmd, cwd=primary), repos_file) is None


def test_a_non_git_command_is_ignored(primary: Path, repos_file: Path) -> None:
    assert run_gate(shell("pytest -q", cwd=primary), repos_file) is None
    assert run_gate(shell("ruff check .", cwd=primary), repos_file) is None


def test_a_word_containing_a_denied_verb_is_not_a_false_positive(
    primary: Path, repos_file: Path
) -> None:
    """`git log --grep=checkout` must not be mistaken for `git checkout`."""
    assert run_gate(shell("git log --oneline | grep resetting", cwd=primary), repos_file) is None
