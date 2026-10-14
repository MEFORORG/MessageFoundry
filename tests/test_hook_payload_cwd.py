# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Hooks answer for the worktree their input names, not the one they run in.

Measured 2026-10-12: the desktop app starts a worktree session's CLI with ``--project-config-root
<primary checkout>``. A hook then runs with its working directory, ``CLAUDE_PROJECT_DIR`` and ``git
rev-parse --show-toplevel`` all naming the PRIMARY. Only the ``cwd`` field of the JSON on stdin names
the worktree. ``scripts/hooks/_hookinput.ps1`` reads that field, as UTF-8.

This file holds the helper's own tests and the one changed hook no other test file drives,
``lane-level.ps1``. The hooks that have a test file carry their case there.

Every hook here runs IN the primary, as the app runs it. Each arm that names the worktree has a
control that does not, and the control is what shows the fixture reproduces the fault.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "scripts" / "hooks"
HELPER = HOOKS / "_hookinput.ps1"
LANE = HOOKS / "lane-level.ps1"
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the hooks are PowerShell run under pwsh on Windows",
)

# Not ASCII on purpose. The console decoder [Console]::In uses turns this into two box-drawing
# characters, which is the half of the defect a plain ASCII path cannot show.
ACCENTED = "caf\u00e9-linked"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _same_dir(a: str, b: Path) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def _primary_with(tmp_path: Path, worktree_leaf: str) -> tuple[Path, Path]:
    """A primary checkout and one linked worktree. realpath, so 8.3 and long names cannot differ."""
    base = Path(os.path.realpath(tmp_path))
    repo = base / "primary"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    wt = base / worktree_leaf
    _git(repo, "worktree", "add", "-q", "-b", "linked", str(wt))
    return repo, wt


def _run(script: Path, cwd: Path, stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return proc


def _raw(payload: dict[str, Any], *, ascii_escaped: bool = False) -> bytes:
    """The input as the harness writes it: raw UTF-8, never escaped to ASCII."""
    return json.dumps(payload, ensure_ascii=ascii_escaped).encode("utf-8")


# --------------------------------------------------------------------------------------------------
# The helper.
# --------------------------------------------------------------------------------------------------


def _helper(tmp_path: Path, call: str, stdin: bytes) -> dict[str, Any]:
    probe = tmp_path / "probe.ps1"
    probe.write_text(
        # UTF-8 out as well as in, or the probe's own console encoder mangles what the helper read.
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        f". '{HELPER}'\n$t = Read-CcxHookInput\n{call} | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    proc = _run(probe, tmp_path, stdin)
    return dict(json.loads(proc.stdout.decode("utf-8")))


def test_the_helper_reads_a_cwd_that_is_not_ascii(tmp_path: Path) -> None:
    _, wt = _primary_with(tmp_path, ACCENTED)
    got = _helper(tmp_path, "Get-CcxHookPayloadCwd -Text $t", _raw({"cwd": str(wt)}))
    assert got["Named"] is True and got["Reason"] == "", got
    assert _same_dir(got["Cwd"], wt), got


def test_the_helper_walks_up_to_the_worktree_root(tmp_path: Path) -> None:
    _, wt = _primary_with(tmp_path, "linked")
    sub = wt / "deep" / "er"
    sub.mkdir(parents=True)
    got = _helper(tmp_path, "@{ Root = Get-CcxWorktreeRoot '" + str(sub) + "' }", _raw({}))
    assert _same_dir(got["Root"], wt), got


def test_the_helper_says_no_cwd_is_not_a_fault(tmp_path: Path) -> None:
    got = _helper(
        tmp_path,
        "Resolve-CcxHookSession -Text $t | Select-Object Named, Dir, Reason",
        _raw({"session_id": "s1"}),
    )
    assert got == {"Named": False, "Dir": None, "Reason": ""}, got


# --------------------------------------------------------------------------------------------------
# Resolve-CcxHookSession: the two checks on the `cwd`, and the pin. The Lander's verdict on korus#223
# measured a `cwd` that followed a `cd` into a sibling worktree or another repository, and the hooks
# answered for wherever it pointed. Every probe here runs IN the primary, as the desktop app runs a
# hook, and each case that falls back has a control that does not.
# --------------------------------------------------------------------------------------------------


def _resolve(repo: Path, tmp_path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    probe = tmp_path / "resolve.ps1"
    probe.write_text(
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        f". '{HELPER}'\n$t = Read-CcxHookInput\n"
        "$r = Resolve-CcxHookSession -Text $t\n"
        "[pscustomobject]@{ Dir = $r.Dir; Reason = $r.Reason; Note = $r.Note } | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    proc = _run(probe, repo, _raw(payload))
    return dict(json.loads(proc.stdout.decode("utf-8")))


def _other_repo(tmp_path: Path) -> Path:
    other = Path(os.path.realpath(tmp_path)) / "other-repo"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    return other


def test_a_cwd_in_the_sessions_own_worktree_is_used(tmp_path: Path) -> None:
    repo, wt = _primary_with(tmp_path, "linked")
    got = _resolve(repo, tmp_path, {"cwd": str(wt), "session_id": "s1", "hook_event_name": "Stop"})
    assert got["Dir"] and _same_dir(got["Dir"], wt), got
    assert got["Reason"] == "" and got["Note"] == "", got


def test_a_cwd_in_another_repository_is_a_fault_without_a_pin(tmp_path: Path) -> None:
    repo, _ = _primary_with(tmp_path, "linked")
    other = _other_repo(tmp_path)
    got = _resolve(repo, tmp_path, {"cwd": str(other), "session_id": "s1"})
    assert got["Dir"] is None, got
    assert "which is in another repository" in got["Reason"], got


def test_a_cwd_under_an_empty_git_file_is_a_fault(tmp_path: Path) -> None:
    """A `.git` that names no git directory is not a checkout. Walking up to it alone accepted it."""
    repo, _ = _primary_with(tmp_path, "linked")
    fake = Path(os.path.realpath(tmp_path)) / "fake"
    fake.mkdir()
    (fake / ".git").write_text("", encoding="utf-8")
    got = _resolve(repo, tmp_path, {"cwd": str(fake), "session_id": "s1"})
    assert got["Dir"] is None and "names no git directory" in got["Reason"], got


def test_after_a_cd_to_a_sibling_the_hook_answers_for_the_pinned_worktree(tmp_path: Path) -> None:
    repo, wt = _primary_with(tmp_path, "linked")
    sibling = Path(os.path.realpath(tmp_path)) / "sibling"
    _git(repo, "worktree", "add", "-q", "-b", "sibling", str(sibling))
    start = _resolve(
        repo, tmp_path, {"cwd": str(wt), "session_id": "s1", "hook_event_name": "SessionStart"}
    )
    assert start["Dir"] and _same_dir(start["Dir"], wt), start
    got = _resolve(
        repo, tmp_path, {"cwd": str(sibling), "session_id": "s1", "hook_event_name": "Stop"}
    )
    assert got["Dir"] and _same_dir(got["Dir"], wt), "the session showed as its sibling after a cd"
    assert "outside the worktree the session started in" in got["Note"], got
    # The control: another session that STARTED in the sibling is answered for there.
    other = _resolve(
        repo, tmp_path, {"cwd": str(sibling), "session_id": "s2", "hook_event_name": "SessionStart"}
    )
    assert other["Dir"] and _same_dir(other["Dir"], sibling), other


def test_after_a_cd_to_another_repository_the_hook_answers_for_the_pinned_worktree(
    tmp_path: Path,
) -> None:
    repo, wt = _primary_with(tmp_path, "linked")
    other = _other_repo(tmp_path)
    _resolve(
        repo, tmp_path, {"cwd": str(wt), "session_id": "s1", "hook_event_name": "SessionStart"}
    )
    got = _resolve(
        repo, tmp_path, {"cwd": str(other), "session_id": "s1", "hook_event_name": "Stop"}
    )
    assert got["Dir"] and _same_dir(got["Dir"], wt), got
    assert "which is in another repository" in got["Note"], got
    assert not (other / ".git" / "mefor-coord").exists(), (
        "nothing may be written into that repository"
    )


def test_a_pin_naming_a_removed_worktree_is_ignored(tmp_path: Path) -> None:
    repo, wt = _primary_with(tmp_path, "linked")
    _resolve(
        repo, tmp_path, {"cwd": str(wt), "session_id": "s1", "hook_event_name": "SessionStart"}
    )
    _git(repo, "worktree", "remove", "--force", str(wt))
    got = _resolve(
        repo, tmp_path, {"cwd": str(repo), "session_id": "s1", "hook_event_name": "Stop"}
    )
    assert got["Dir"] and _same_dir(got["Dir"], repo), got


# --------------------------------------------------------------------------------------------------
# lane-level.ps1. It tells a builder lane by its worktree's name, so from the primary it answered for
# neither lane nor dispatcher and said nothing.
# --------------------------------------------------------------------------------------------------


def _lane(repo: Path, payload: dict[str, Any]) -> str:
    out = _run(LANE, repo, _raw(payload)).stdout.decode("utf-8").strip()
    return str(json.loads(out)["hookSpecificOutput"]["additionalContext"]) if out else ""


@pytest.fixture
def builder_lane(tmp_path: Path) -> tuple[Path, Path]:
    repo, wt = _primary_with(tmp_path, "builder-lane")
    (repo / ".git" / "mefor-coord").mkdir()
    return repo, wt


def test_lane_level_nags_the_builder_worktree_the_input_names(
    builder_lane: tuple[Path, Path],
) -> None:
    repo, wt = builder_lane
    text = _lane(repo, {"hook_event_name": "Stop", "cwd": str(wt)})
    assert "[lane] Your lane level is unstated or stale" in text, text


def test_lane_level_without_a_cwd_reads_where_it_runs(builder_lane: tuple[Path, Path]) -> None:
    """The control. The primary is no builder lane, so the same call says nothing at all."""
    repo, _ = builder_lane
    assert _lane(repo, {"hook_event_name": "Stop"}) == ""


def test_lane_level_says_aloud_when_the_cwd_does_not_exist(
    builder_lane: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, _ = builder_lane
    gone = str(Path(os.path.realpath(tmp_path)) / "deleted-worktree")
    text = _lane(repo, {"hook_event_name": "Stop", "cwd": gone})
    assert "[lane] COULD NOT READ THIS SESSION'S WORKTREE" in text, text
    assert "deleted-worktree, which does not exist" in text, text
