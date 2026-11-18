# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Codex session in a linked worktree resolves repo skills from the primary checkout.

.gitignore keeps .claude/skills out of git, so a linked worktree carries none of its own.
Disposable repositories only; plumbing commands, so no hook in any git config runs.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def bridge():
    spec = importlib.util.spec_from_file_location("codex_bridge", ROOT / "scripts/codex/bridge.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", "-c", f"core.hooksPath={cwd / 'no-hooks'}", *args],
        cwd=cwd,
        input="",
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()


def _skill(directory: Path, name: str, description: str) -> Path:
    path = directory / name / "SKILL.md"
    path.parent.mkdir(parents=True)
    path.write_text(f"---\nname: {name}\ndescription: {description}\n---\nProcedure\n")
    return path


@pytest.fixture
def linked(tmp_path):
    primary = tmp_path / "primary"
    primary.mkdir()
    _git("init", "-q", cwd=primary)
    empty_tree = _git("hash-object", "-t", "tree", "--stdin", cwd=primary)
    commit = _git(
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit-tree",
        "-m",
        "x",
        empty_tree,
        cwd=primary,
    )
    worktree = tmp_path / "linked"
    _git("worktree", "add", "-q", "--detach", str(worktree), commit, cwd=primary)
    return primary, worktree


def test_a_linked_worktree_resolves_a_primary_checkout_skill(bridge, linked, tmp_path):
    primary, worktree = linked
    source = _skill(primary / ".claude/skills", "batch", "Primary batch")
    found = bridge.source_skill(worktree, "batch", user_skills=tmp_path / "no-user-skills")
    assert found.resolve() == source.resolve()


def test_precedence_is_worktree_then_primary_then_user(bridge, linked, tmp_path):
    primary, worktree = linked
    user = tmp_path / "user-skills"
    _skill(user, "shared", "User shared")
    _skill(user, "useronly", "User only")
    _skill(primary / ".claude/skills", "shared", "Primary shared")
    _skill(primary / ".claude/skills", "both", "Primary both")
    local = _skill(worktree / ".claude/skills", "both", "Worktree both")
    assert bridge.source_skill(worktree, "both", user_skills=user).resolve() == local.resolve()
    assert "Primary shared" in bridge.source_skill(worktree, "shared", user_skills=user).read_text()
    assert bridge.source_skill(worktree, "useronly", user_skills=user) == user / "useronly/SKILL.md"


def test_sync_in_a_linked_worktree_writes_pointers_for_primary_skills(bridge, linked, tmp_path):
    primary, worktree = linked
    _skill(primary / ".claude/skills", "batch", "Primary batch")
    _skill(worktree / ".claude/skills", "local", "Worktree local")
    messages = bridge.sync_skills(worktree, user_skills=tmp_path / "no-user-skills")
    assert not [m for m in messages if m.startswith("MISSING SOURCE")]
    assert "Primary batch" in (worktree / ".agents/skills/batch/SKILL.md").read_text()
    assert "Worktree local" in (worktree / ".agents/skills/local/SKILL.md").read_text()


def test_the_primary_checkout_reads_only_its_own_skills(bridge, linked):
    primary, _ = linked
    assert bridge.repo_skill_directories(primary) == [primary / ".claude/skills"]


def test_a_directory_nested_in_a_repository_is_not_given_its_skills(bridge, linked):
    primary, _ = linked
    nested = primary / "sub"
    nested.mkdir()
    assert bridge.repo_skill_directories(nested) == [nested / ".claude/skills"]


def test_outside_any_repository_only_the_root_is_searched(bridge, tmp_path):
    assert bridge.repo_skill_directories(tmp_path) == [tmp_path / ".claude/skills"]
