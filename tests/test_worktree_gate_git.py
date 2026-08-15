# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for rule 3 of the worktree gate: git commands that swap the SHARED PRIMARY's working tree.

This rule exists because it actually happened. A sibling session ran `git checkout <its-branch>` inside
the shared primary checkout and then left HEAD detached — and every other session standing in that
directory silently found itself reading a different commit's files. Rules 1 and 2 cannot see it: a git
command is a SHELL call, not an Edit, so no amount of tool-argument inspection catches it.

The rule is narrow on purpose. Only verbs that change WHICH COMMIT the primary's tree reflects, or that
discard work, are denied — and only for the primary. A linked worktree switching onto an EXISTING branch
(the hijack that this whole guard grew out of) is the separate, narrower rule 3b — see
tests/test_worktree_gate_hijack.py; everything else a worktree does to its own branch stays free.
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


def test_non_hijacking_git_verbs_in_a_worktree_are_allowed(
    tmp_path: Path, repos_file: Path
) -> None:
    """A worktree owns its own history: creating a new branch (-b) and resetting its own branch stay
    free. Only switching onto an EXISTING branch is denied, and that is rule 3b -- it needs a real
    worktree git can classify, so it lives in tests/test_worktree_gate_hijack.py."""
    worktree = tmp_path / "Repo-alerts"
    assert run_gate(shell("git checkout -b feature/x", cwd=worktree), repos_file) is None
    assert run_gate(shell("git reset --hard HEAD~1", cwd=worktree), repos_file) is None


def test_a_nested_worktree_naming_its_own_path_is_allowed(tmp_path: Path, repos_file: Path) -> None:
    """BACKLOG #308. `Test-Governed` EXEMPTS ``<primary>/.claude/worktrees/<name>`` -- a linked worktree
    living under the primary is not the primary, and a git verb there swaps only its own tree. Rule 3's
    in-text fallback must honour the SAME exemption.

    It did not: a path separator clears both boundary lookaheads, so any command whose TEXT contained the
    nested worktree's own path matched the primary and was denied. That is where ``new.ps1`` puts every
    worktree, so `cd <own worktree> && git rebase ...` -- the most ordinary thing a session does -- was
    refused as if it were swapping the shared tree, while the identical command with the path omitted was
    allowed. The block therefore depended on how the command was SPELLED, not on what it touched."""
    nested = tmp_path / "Repo" / ".claude" / "worktrees" / "alerts"
    assert (
        run_gate(shell(f"cd {nested} && git switch -c feature/x", cwd=nested), repos_file) is None
    )
    assert run_gate(shell(f"git -C {nested} rebase origin/main", cwd=nested), repos_file) is None


def test_naming_the_primary_in_an_unrelated_argument_is_allowed(
    tmp_path: Path, repos_file: Path
) -> None:
    """The in-text fallback must match a DIRECTORY-CHANGE argument, not the path appearing anywhere.

    Measured 2026-08-04, three times in one session: a safe `git restore <files>` in a worktree was
    denied as *"would change the working tree of the SHARED PRIMARY"* because a later `cat` in the same
    compound command happened to name ``<primary>/.git/mefor-coord/...``. Isolating the identical git
    call was allowed instantly, so the verdict depended on what else the command said.

    Worse than the noise: the refusal TEXT asserted the primary was at risk when it never was, and a gate
    that misdescribes what it blocked teaches people to route around it. Same defect #308 fixed for the
    nested-worktree subpath, arriving through a different spelling."""
    primary = tmp_path / "Repo"
    nested = primary / ".claude" / "worktrees" / "alerts"
    # the exact shape that fired: a worktree-local git verb + an unrelated read under the primary
    assert (
        run_gate(
            shell(
                f'git restore a.py b.py && cat "{primary}/.git/mefor-coord/alloc/backlog/.mark"',
                cwd=nested,
            ),
            repos_file,
        )
        is None
    )
    # a read of the primary's tree alongside a worktree verb is still not a write to it
    assert (
        run_gate(shell(f"git switch -c wip && ls {primary}/docs", cwd=nested), repos_file) is None
    )


def test_a_git_verb_inside_the_coordination_dir_still_swaps_the_primary(
    tmp_path: Path, repos_file: Path
) -> None:
    """Why rule 1's coordination exemption lives in rule 1 and NOT in ``Test-Governed``.

    ``<primary>/.git/mefor-coord/`` is exempt from rule 1, because a write there lands in the shared
    git dir and not in the primary's working tree. The obvious refactor is to put that exemption in
    ``Test-Governed`` beside the ``.claude/worktrees/`` one, whose shape is identical. That would open a
    real bypass: rule 3 feeds the SESSION'S cwd through the same helper, and a git verb run from inside
    the coordination directory resolves GIT_DIR to the primary and swaps the tree every other session is
    standing in. Rule 1 judges a write TARGET; only rule 1 may exempt this path.

    The ``-C`` spelling is the one that proves the deny is STRUCTURAL rather than a lucky hit from the
    in-text fallback: an explicit ``-C`` is authoritative about which repository git acts on, so it sets
    ``$anyInferredTarget`` false and disables that fallback entirely."""
    primary = tmp_path / "Repo"
    coord = f"{primary}/.git/mefor-coord"
    nested = primary / ".claude" / "worktrees" / "alerts"

    # resolved from a `cd` in the prefix ...
    assert_denied(run_gate(shell(f"cd {coord} && git reset --hard", cwd=nested), repos_file))
    # ... from the session's cwd ...
    assert_denied(run_gate(shell("git reset --hard", cwd=coord), repos_file))
    # ... and with the fallback switched off, which is the load-bearing case
    assert_denied(run_gate(shell(f'git -C "{coord}" reset --hard', cwd=nested), repos_file))
    # a read from there is still fine, as everywhere else
    assert run_gate(shell("git status", cwd=coord), repos_file) is None


def test_stepping_into_the_primary_still_denies_however_it_is_spelled(
    tmp_path: Path, repos_file: Path
) -> None:
    """The narrowing must not cost the true positive the fallback exists for. Every directory-change
    spelling that lands in the primary still denies, including the PowerShell aliases and `cd /d`."""
    primary = tmp_path / "Repo"
    for step in (
        f"cd {primary} && git checkout main",
        f"cd '{primary}' ; git reset --hard",
        f'pushd "{primary}"; git checkout main',
        f"Set-Location {primary}; git checkout main",
        f"Set-Location -LiteralPath {primary}; git switch main",
        f"sl {primary}; git checkout main",
        f"chdir {primary} && git checkout main",
        f"cd /d {primary} && git checkout main",
        # already inside the primary, then wandering: still denied, deliberately conservative
        f"cd {primary} && cd {tmp_path / 'Elsewhere'} && git checkout main",
    ):
        assert_denied(run_gate(shell(step, cwd=tmp_path), repos_file)), step


def test_reaching_into_the_primary_is_still_denied_around_the_nested_exemption(
    tmp_path: Path, repos_file: Path
) -> None:
    """The #308 exemption must not open a hole: only ``/.claude/worktrees/`` is exempt, so the primary
    itself -- and any OTHER path inside it, including its own ``.claude/hooks`` -- still deny."""
    primary = tmp_path / "Repo"
    assert_denied(run_gate(shell(f"cd {primary} && git checkout main", cwd=primary), repos_file))
    hooks = primary / ".claude" / "hooks"
    assert_denied(run_gate(shell(f"cd {hooks} && git checkout main", cwd=hooks), repos_file))


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
