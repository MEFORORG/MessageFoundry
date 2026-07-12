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
