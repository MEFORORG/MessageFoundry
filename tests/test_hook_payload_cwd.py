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
    got = _helper(tmp_path, "Get-CcxHookWorktree -Text $t", _raw({"cwd": str(sub)}))
    assert _same_dir(got["Root"], wt), got


def test_the_helper_says_no_cwd_is_not_a_fault(tmp_path: Path) -> None:
    got = _helper(tmp_path, "Get-CcxHookWorktree -Text $t", _raw({"session_id": "s1"}))
    assert got == {"Named": False, "Root": None, "Reason": ""}, got


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
