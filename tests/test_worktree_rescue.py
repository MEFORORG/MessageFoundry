# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/worktree/rescue.ps1`` refuses a call without ``-Name`` instead of prompting for it.

Vault BACKLOG #3627. With ``-Name`` Mandatory, a call that left it out made PowerShell prompt on
stdin, and a caller with stdin open and silent hung; ``tests/_no_prompt.py`` says why the launch
must keep both of those conditions.

The script anchors on ``$PSScriptRoot``, so it runs from a copy inside a throwaway repository. The
real checkout is never in reach: a guard that failed open here would stash the repository it names.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._no_prompt import run_holding_stdin_open

_RESCUE = Path(__file__).resolve().parents[1] / "scripts" / "worktree" / "rescue.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="rescue.ps1 is a PowerShell script driven through pwsh on Windows",
)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def test_a_call_without_name_refuses_instead_of_prompting(tmp_path: Path) -> None:
    """``-NoInstall`` alone leaves ``-Name`` unbound. Verified red (a 45s hang) pre-fix."""
    repo = tmp_path / "repo"
    (repo / "scripts" / "worktree").mkdir(parents=True)
    shutil.copy2(_RESCUE, repo / "scripts" / "worktree" / "rescue.ps1")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "seed", "--no-verify")
    # Dirty, so a guard that failed open would reach the stash rather than the nothing-to-do exit.
    (repo / "work.txt").write_text("uncommitted\n", encoding="utf-8")

    rc, err = run_holding_stdin_open(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            str(repo / "scripts" / "worktree" / "rescue.ps1"),
            "-NoInstall",
        ],
        cwd=repo,
    )
    assert rc != 0, "a rescue naming no worktree must be refused"
    assert "-Name" in err, err
    # Refused means NOTHING moved: the work is still here and nothing was stashed.
    assert (repo / "work.txt").is_file()
    assert _git(repo, "stash", "list") == ""
