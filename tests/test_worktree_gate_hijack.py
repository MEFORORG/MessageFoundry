"""Tests for rule 3b of the worktree gate: hijacking a LINKED WORKTREE onto an existing branch.

Rule 3 protects only the shared PRIMARY. Rule 3b protects every OTHER governed worktree from the one
move that actually happened here: a session with no worktree of its own ran `git checkout <a-branch>`
inside somebody else's worktree, yanking that session's files onto a different branch mid-task. git
permits it because its native guard only blocks a branch that is ALREADY checked out somewhere -- a
"free" branch can be grabbed by any worktree.

The rule is narrow: only a switch onto an EXISTING LOCAL BRANCH is denied. Creating a new branch
(-b/-c), restoring files (`--`/pathspec), and reset/rebase/merge of the worktree's OWN branch stay
allowed. Unlike rules 1-3 (which string-match paths and need no real repo), rule 3b asks git itself
whether the target is a governed linked worktree and whether the destination names a real branch, so
these tests build REAL repos + worktrees.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the subprocess harness

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="needs pwsh (PowerShell 7) and git on PATH",
)


def git(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
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
def repo(tmp_path: Path) -> SimpleNamespace:
    """A real GOVERNED primary + a linked worktree (on `wt-branch`) + a second branch to hijack onto.

    Layout:
        <tmp>/Primary            main worktree, branch `main`   (listed in repos.txt -> governed)
        <tmp>/Primary-wt         linked worktree, branch `wt-branch`
        branch `claude/other-branch` exists but is checked out NOWHERE -- the grabbable "free" branch.
    """
    primary = tmp_path / "Primary"
    git("init", "-b", "main", str(primary))
    git("config", "user.email", "t@example.com", cwd=primary)
    git("config", "user.name", "t", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "-A", cwd=primary)
    git("commit", "-m", "seed", cwd=primary)
    # A branch that exists but is checked out nowhere -- the exact shape of claude/asvs-handoff.
    git("branch", "claude/other-branch", cwd=primary)
    wt = tmp_path / "Primary-wt"
    git("worktree", "add", "-b", "wt-branch", str(wt), cwd=primary)

    repos = tmp_path / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    return SimpleNamespace(primary=primary, wt=wt, repos=repos, other="claude/other-branch")


# ------------------------------------------------------------------ the hijack, in every spelling


def test_checkout_onto_existing_branch_in_a_linked_worktree_is_denied(
    repo: SimpleNamespace,
) -> None:
    reason = assert_denied(run_gate(shell(f"git checkout {repo.other}", cwd=repo.wt), repo.repos))
    assert "LINKED WORKTREE" in reason
    assert repo.other in reason
    assert "new.ps1" in reason  # must tell the model how to proceed, not just refuse


def test_switch_onto_existing_branch_in_a_linked_worktree_is_denied(repo: SimpleNamespace) -> None:
    assert_denied(run_gate(shell(f"git switch {repo.other}", cwd=repo.wt), repo.repos))


def test_dash_C_into_a_linked_worktree_is_denied(repo: SimpleNamespace) -> None:
    """A session sitting elsewhere reaches into the worktree with -C -- a cwd-only check misses this."""
    assert_denied(
        run_gate(shell(f'git -C "{repo.wt}" checkout {repo.other}', cwd=repo.primary), repo.repos)
    )


def test_cd_into_a_linked_worktree_then_checkout_is_denied(repo: SimpleNamespace) -> None:
    assert_denied(
        run_gate(
            shell(f'cd "{repo.wt}" && git checkout {repo.other}', cwd=repo.primary), repo.repos
        )
    )


def test_git_exe_spelling_is_denied(repo: SimpleNamespace) -> None:
    assert_denied(run_gate(shell(f"git.exe checkout {repo.other}", cwd=repo.wt), repo.repos))


# ------------------------------------------------------------------ what MUST keep working


def test_creating_a_new_branch_in_place_is_allowed(repo: SimpleNamespace) -> None:
    """-b/-c create a brand-new branch nobody holds -- not a hijack of an in-flight one."""
    assert run_gate(shell("git checkout -b brand-new", cwd=repo.wt), repo.repos) is None
    assert run_gate(shell("git switch -c brand-new2", cwd=repo.wt), repo.repos) is None


def test_restoring_a_file_is_allowed(repo: SimpleNamespace) -> None:
    """`git checkout -- <path>` (and `checkout <ref> -- <path>`) is a file restore, not a branch move."""
    assert run_gate(shell("git checkout -- seed.txt", cwd=repo.wt), repo.repos) is None
    assert (
        run_gate(shell(f"git checkout {repo.other} -- seed.txt", cwd=repo.wt), repo.repos) is None
    )


def test_reset_and_rebase_of_the_worktrees_own_branch_are_allowed(repo: SimpleNamespace) -> None:
    """A worktree owns its own history -- it just may not be pulled onto another in-flight branch."""
    assert run_gate(shell("git reset --hard HEAD", cwd=repo.wt), repo.repos) is None
    assert run_gate(shell("git rebase main", cwd=repo.wt), repo.repos) is None
    assert run_gate(shell("git merge main", cwd=repo.wt), repo.repos) is None


def test_checking_out_the_branch_already_on_is_allowed(repo: SimpleNamespace) -> None:
    """A no-op checkout of the branch you are already on must not be flagged."""
    assert run_gate(shell("git checkout wt-branch", cwd=repo.wt), repo.repos) is None


def test_checkout_of_a_nonexistent_branch_is_allowed(repo: SimpleNamespace) -> None:
    """Only an EXISTING local branch is a hijack target; a typo/new name is not (and git errors anyway)."""
    assert run_gate(shell("git checkout does-not-exist", cwd=repo.wt), repo.repos) is None


def test_reads_are_allowed_in_a_linked_worktree(repo: SimpleNamespace) -> None:
    assert run_gate(shell(f"git show {repo.other}:seed.txt", cwd=repo.wt), repo.repos) is None
    assert run_gate(shell(f"git diff HEAD..{repo.other}", cwd=repo.wt), repo.repos) is None


# ------------------------------------------------------------------ scope: primary vs linked vs alien


def test_the_same_move_in_the_primary_uses_rule_3_not_3b(repo: SimpleNamespace) -> None:
    """In the primary the message is the SHARED PRIMARY one (rule 3 owns it), never rule 3b's."""
    reason = assert_denied(
        run_gate(shell(f"git checkout {repo.other}", cwd=repo.primary), repo.repos)
    )
    assert "SHARED PRIMARY" in reason
    assert "LINKED WORKTREE" not in reason


def test_a_worktree_of_an_UNGOVERNED_repo_is_untouched(tmp_path: Path) -> None:
    """Rule 3b acts only when the worktree's MAIN tree is a governed primary -- an alien repo is free."""
    other = tmp_path / "Alien"
    git("init", "-b", "main", str(other))
    git("config", "user.email", "t@example.com", cwd=other)
    git("config", "user.name", "t", cwd=other)
    (other / "f.txt").write_text("x\n", encoding="utf-8")
    git("add", "-A", cwd=other)
    git("commit", "-m", "seed", cwd=other)
    git("branch", "some-branch", cwd=other)
    wt = tmp_path / "Alien-wt"
    git("worktree", "add", "-b", "wt", str(wt), cwd=other)
    repos = tmp_path / "repos.txt"
    repos.write_text(f"{tmp_path / 'SomethingGoverned'}\n", encoding="utf-8")  # NOT the alien repo
    assert run_gate(shell("git checkout some-branch", cwd=wt), repos) is None
