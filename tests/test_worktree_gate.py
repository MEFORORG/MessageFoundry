"""Tests for the worktree gate PreToolUse hook (scripts/hooks/worktree_gate.ps1).

The gate keeps concurrent Claude Code sessions from BUILDING in the shared primary checkout. It is keyed
on the write's TARGET PATH, never on the session's cwd -- the distinction these tests exist to pin down,
because ~29% of this repo's real Edit/Write calls come from a session sitting in the primary but write
into a sibling worktree by absolute path, and those are already correct. A cwd-keyed gate would deny them
all.

Each test drives the real hook script as a subprocess with a real PreToolUse payload on stdin and asserts
on the deny/allow decision, so the contract under test is the one Claude Code actually invokes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

GATE = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "worktree_gate.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def run_gate(payload: dict[str, Any] | str, repos_file: Path) -> dict[str, Any] | None:
    """Invoke the hook exactly as Claude Code does. Returns the deny object, or None for 'allow'."""
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(GATE),
            "-ReposFile",
            str(repos_file),
        ],
        input=raw,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # A hook must never crash the tool call: a non-zero exit that is not 2 is silently ignored by the
    # harness, which would leave the gate off with nobody the wiser.
    assert proc.returncode == 0, f"gate exited {proc.returncode}: {proc.stderr}"
    if not proc.stdout.strip():
        return None
    decision: dict[str, Any] = json.loads(proc.stdout)
    return decision


def assert_denied(result: dict[str, Any] | None) -> str:
    assert result is not None, "expected a DENY, got allow"
    out = result["hookSpecificOutput"]
    # The wrapper is mandatory: a bare {"permissionDecision": "deny"} is silently ignored upstream and the
    # write lands anyway. Pin the exact shape.
    assert out["hookEventName"] == "PreToolUse"
    assert out["permissionDecision"] == "deny"
    reason = out["permissionDecisionReason"]
    assert isinstance(reason, str) and reason
    return reason


@pytest.fixture
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text(f"# governed\n{primary}\n", encoding="utf-8")
    return f


def edit(target: Path | str, cwd: Path | str, tool: str = "Edit") -> dict[str, Any]:
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"file_path": str(target)},
    }


# --------------------------------------------------------------------------- rule 1: writes


def test_write_into_primary_is_denied(primary: Path, repos_file: Path) -> None:
    reason = assert_denied(run_gate(edit(primary / "src" / "app.py", primary), repos_file))
    assert "SHARED PRIMARY" in reason
    assert "new.ps1" in reason  # the deny must tell the model how to proceed, not just say no
    assert "rescue.ps1" in reason


def test_write_into_sibling_worktree_from_a_primary_cwd_is_allowed(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    """The 29% case. The session sits in the primary and writes into a worktree by absolute path -- correct."""
    worktree = tmp_path / "Repo-alerts" / "src" / "app.py"
    assert run_gate(edit(worktree, cwd=primary), repos_file) is None


def test_traversal_out_of_a_sibling_and_back_into_the_primary_is_denied(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    """Without canonicalization this string does not match the primary's prefix and walks through."""
    sneaky = tmp_path / "Repo-alerts" / ".." / "Repo" / "src" / "app.py"
    assert_denied(run_gate(edit(sneaky, cwd=primary), repos_file))


def test_nested_first_party_worktree_is_allowed(primary: Path, repos_file: Path) -> None:
    """git nests `claude --worktree` worktrees INSIDE the primary's path; they are worktrees, not the primary."""
    worktree = primary / ".claude" / "worktrees" / "wt-1" / "src" / "app.py"
    assert run_gate(edit(worktree, cwd=primary), repos_file) is None


def test_relative_path_is_resolved_against_cwd_then_denied(primary: Path, repos_file: Path) -> None:
    assert_denied(run_gate(edit("src/app.py", cwd=primary), repos_file))


def test_unrelated_repo_is_allowed(tmp_path: Path, primary: Path, repos_file: Path) -> None:
    other = tmp_path / "SomethingElse" / "x.py"
    assert run_gate(edit(other, cwd=other.parent), repos_file) is None


@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
def test_every_write_tool_is_gated(primary: Path, repos_file: Path, tool: str) -> None:
    assert_denied(run_gate(edit(primary / "x.py", primary, tool=tool), repos_file))


def test_notebook_edit_uses_notebook_path(primary: Path, repos_file: Path) -> None:
    payload = {
        "session_id": "s-1",
        "cwd": str(primary),
        "tool_name": "NotebookEdit",
        "tool_input": {"notebook_path": str(primary / "nb.ipynb")},
    }
    assert_denied(run_gate(payload, repos_file))


def test_read_is_never_gated(primary: Path, repos_file: Path) -> None:
    """Reading and planning in the primary stays frictionless -- only building is blocked."""
    payload = {
        "session_id": "s-1",
        "cwd": str(primary),
        "tool_name": "Read",
        "tool_input": {"file_path": str(primary / "src" / "app.py")},
    }
    assert run_gate(payload, repos_file) is None


# --------------------------------------------------------------------------- rule 2: dispatch


@pytest.mark.parametrize("tool", ["Task", "Agent", "Workflow"])
def test_dispatch_from_the_primary_is_denied(primary: Path, repos_file: Path, tool: str) -> None:
    """A subagent inherits this cwd, cannot make itself a worktree, and its denied edits do not reliably
    surface to the parent -- so the fan-out is stopped at the cheapest possible point."""
    payload = {
        "session_id": "s-1",
        "cwd": str(primary),
        "tool_name": tool,
        "tool_input": {"prompt": "go"},
    }
    reason = assert_denied(run_gate(payload, repos_file))
    assert "subagent" in reason.lower()


def test_dispatch_from_a_worktree_is_allowed(tmp_path: Path, repos_file: Path) -> None:
    worktree = tmp_path / "Repo-alerts"
    payload = {
        "session_id": "s-1",
        "cwd": str(worktree),
        "tool_name": "Task",
        "tool_input": {"prompt": "go"},
    }
    assert run_gate(payload, repos_file) is None


# --------------------------------------------------------------------------- rule 4: EnterWorktree


def enter_worktree(cwd: Path | str, name: str = "wt-1") -> dict[str, Any]:
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "EnterWorktree",
        "tool_input": {"name": name},
    }


def test_enter_worktree_is_denied(primary: Path, repos_file: Path) -> None:
    """Relocating a live session re-files its transcript and drops the chat from its window's list."""
    reason = assert_denied(run_gate(enter_worktree(cwd=primary), repos_file))
    assert "EnterWorktree" in reason
    assert "sessions.ps1" in reason  # the deny must point at the recovery path, not just say no


def test_enter_worktree_denied_even_from_a_worktree_cwd(tmp_path: Path, repos_file: Path) -> None:
    """Rule 4 keys on the TOOL, not cwd -- relocation loses the chat wherever you start it."""
    assert_denied(run_gate(enter_worktree(cwd=tmp_path / "Repo-alerts"), repos_file))


def test_exit_worktree_is_allowed(primary: Path, repos_file: Path) -> None:
    """ExitWorktree is a safe keep; only EnterWorktree is denied."""
    payload = {
        "session_id": "s-1",
        "cwd": str(primary),
        "tool_name": "ExitWorktree",
        "tool_input": {},
    }
    assert run_gate(payload, repos_file) is None


def test_enter_worktree_allowed_when_gate_is_off(primary: Path, empty_repos: Path) -> None:
    """Kill switch wins: no allowlist -> even EnterWorktree passes."""
    assert run_gate(enter_worktree(cwd=primary), empty_repos) is None


def test_normal_edit_still_allowed_alongside_rule_4(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    """Adding rule 4 must not disturb the 29% case: a write into a sibling worktree stays allowed."""
    worktree = tmp_path / "Repo-alerts" / "src" / "app.py"
    assert run_gate(edit(worktree, cwd=primary), repos_file) is None


# --------------------------------------------------------------------------- rule 3: git tree-swaps


def bash(cmd: str, cwd: Path | str, tool: str = "Bash") -> dict[str, Any]:
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": cmd},
    }


def test_git_checkout_in_the_primary_is_denied(primary: Path, repos_file: Path) -> None:
    """The core rule-3 case: `cd <primary> && git checkout` swaps the shared tree out from under siblings."""
    reason = assert_denied(
        run_gate(bash(f'cd "{primary}" && git checkout somebranch', primary), repos_file)
    )
    assert "SHARED PRIMARY" in reason


def test_git_dash_c_reset_into_the_primary_is_denied(primary: Path, repos_file: Path) -> None:
    """An explicit -C into the primary from a worktree cwd must still block (the -C handler catches it)."""
    worktree = primary.parent / "Repo-alerts"
    assert_denied(run_gate(bash(f'git -C "{primary}" reset --hard', worktree), repos_file))


def test_git_dash_c_into_a_primary_subdir_is_denied(primary: Path, repos_file: Path) -> None:
    """A path INTO the primary (a subdirectory) is still the primary's tree."""
    worktree = primary.parent / "Repo-alerts"
    assert_denied(run_gate(bash(f'git -C "{primary}/sub" checkout x', worktree), repos_file))


def test_git_merge_into_sibling_worktree_whose_name_extends_the_primary_is_allowed(
    primary: Path, repos_file: Path
) -> None:
    """The false positive this fix removes: a sibling worktree path CONTAINS the primary's as a prefix
    substring ('Repo-ss-capture' starts with 'Repo'). Its -C already resolved to a non-governed target,
    so the raw-substring fallback must NOT re-flag it. `git merge` into that sibling is ordinary work."""
    sibling = primary.parent / "Repo-ss-capture"
    assert run_gate(bash(f'git -C "{sibling}" merge origin/main', primary), repos_file) is None


def test_git_rebase_into_sibling_worktree_extending_the_primary_is_allowed(
    primary: Path, repos_file: Path
) -> None:
    sibling = primary.parent / "Repo2"
    assert run_gate(bash(f'git -C "{sibling}" rebase main', primary), repos_file) is None


def test_git_checkout_naming_primary_with_trailing_separator_is_denied(
    primary: Path, repos_file: Path
) -> None:
    """A trailing path separator IS a real boundary and must still match (no false negative)."""
    worktree = primary.parent / "Repo-alerts"
    assert_denied(run_gate(bash(f'cd "{primary}/" ; git checkout x', worktree), repos_file))


def test_git_checkout_naming_primary_with_trailing_dot_is_denied(
    primary: Path, repos_file: Path
) -> None:
    """Windows STRIPS a trailing dot from a path component, so `cd <primary>.` resolves to the primary and
    a checkout there swaps the shared tree. This is the regression guard for the trailing-dot false
    negative that the first boundary fix introduced (a bare `(?![a-z0-9._-])` with `.` in the reject class
    ALLOWED it); the second lookahead must block it again."""
    worktree = primary.parent / "Repo-alerts"
    assert_denied(
        run_gate(bash(f'cd "{primary}." && git checkout somebranch', worktree), repos_file)
    )


def test_git_merge_into_sibling_worktree_named_with_dot_suffix_is_allowed(
    primary: Path, repos_file: Path
) -> None:
    """A genuinely different directory whose name extends the primary with a dotted suffix ('Repo.old') is
    NOT the primary -- the second lookahead must not re-flag it (the false positive that put `.` in the
    reject class in the first place). Its -C already resolved to a non-governed target."""
    sibling = primary.parent / "Repo.old"
    assert run_gate(bash(f'git -C "{sibling}" merge origin/main', primary), repos_file) is None


def test_git_read_verb_in_the_primary_is_allowed(primary: Path, repos_file: Path) -> None:
    """merge-base/merge-tree are read-only plumbing -- the verb match must not fire on them."""
    assert run_gate(bash("git merge-base HEAD origin/main", primary), repos_file) is None


# --------------------------------------------------------------------------- fail-open contract


@pytest.fixture
def empty_repos(tmp_path: Path) -> Iterator[Path]:
    f = tmp_path / "empty.txt"
    f.write_text("# nothing governed\n", encoding="utf-8")
    yield f


def test_no_allowlist_means_the_gate_is_off(primary: Path, empty_repos: Path) -> None:
    """The allowlist is also the kill switch: remove it and every session is ungated, immediately."""
    assert run_gate(edit(primary / "x.py", primary), empty_repos) is None


def test_missing_allowlist_file_is_off(tmp_path: Path, primary: Path) -> None:
    assert run_gate(edit(primary / "x.py", primary), tmp_path / "nope.txt") is None


@pytest.mark.parametrize("junk", ["", "not json", "[]", '{"tool_name": "Edit"}'])
def test_malformed_input_fails_open(repos_file: Path, junk: str) -> None:
    """A guardrail that wedges every tool call on a bad payload gets uninstalled, and then it guards
    nothing. Every error path must allow."""
    assert run_gate(junk, repos_file) is None
