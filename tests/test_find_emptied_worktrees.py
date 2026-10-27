# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An emptied-in-place worktree folder is reported, with the Desktop log line that emptied it.

BACKLOG #2525. A Desktop GC's ``git worktree remove --force`` on a folder a session holds open fails on
Windows after it has deleted the files, the ``.git`` link and the registration. The folder left behind
has no ``.git`` and is absent from ``git worktree list``. ``find-emptied-worktrees.ps1`` and
``hygiene-report.ps1`` section f name each one, beside the log lines that name it.

The positive control is a planted empty, unregistered folder: it must be reported. Beside it, a live
registered worktree and a folder that still carries a ``.git`` must not be, and a log line about a
folder whose name merely starts the same way must not be attached to it.

Everything is a throwaway repository and a planted log directory; no real worktree or Desktop log is
read.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.test_worktree_hygiene_report import _violations

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "worktree" / "find-emptied-worktrees.ps1"
TIMEOUT = 120

pytestmark = [
    pytest.mark.skipif(
        shutil.which("pwsh") is None or os.name != "nt", reason="needs pwsh on Windows"
    ),
    pytest.mark.timeout(300),
]


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def layout(tmp_path: Path) -> dict[str, Path]:
    primary = tmp_path / "repo"
    primary.mkdir()
    git(primary, "init", "-q", "-b", "main")
    git(primary, "config", "user.email", "t@example.invalid")
    git(primary, "config", "user.name", "t")
    (primary / "f.txt").write_text("x", encoding="utf-8")
    git(primary, "add", "f.txt")
    git(primary, "commit", "-qm", "base")
    trees = primary / ".claude" / "worktrees"
    trees.mkdir(parents=True)
    live = trees / "seat-live"
    git(primary, "worktree", "add", "-q", "-b", "live", str(live))
    emptied = trees / "seat-a"
    emptied.mkdir()
    # Not registered, but it still carries a .git: not what the GC leaves.
    kept = trees / "seat-kept"
    kept.mkdir()
    (kept / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")

    logs = tmp_path / "desktop-1" / "logs"
    logs.mkdir(parents=True)
    fwd = emptied.as_posix()
    back = str(emptied)
    lines = [
        # Both failure shapes, one with each slash spelling: each must be attached.
        f"2026-09-23 16:46:28 [error] [WorktreePool] [reapUntrackedWorktreeDir] git worktree remove "
        f"refused: error: failed to delete '{fwd}': Permission denied",
        f"2026-09-23 17:15:42 [warn] Git worktree remove failed, will try manual cleanup: error: "
        f"failed to delete '{back}': Permission denied",
        # The marker without its second substring: not a failure line.
        f"2026-09-23 17:20:00 [warn] Git worktree remove failed, will try manual cleanup: fatal: "
        f"'{back}' is not a working tree",
        # A sibling whose name starts the same way: must not be attached to seat-a.
        f"2026-09-23 17:30:00 [error] [reapUntrackedWorktreeDir] git worktree remove refused: "
        f"error: failed to delete '{fwd}b': Permission denied",
        f"2026-09-23 17:40:00 [info] [reapUntrackedWorktreeDir] Removed untracked worktree dir {fwd}",
    ]
    (logs / "main1.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"primary": primary, "emptied": emptied, "live": live, "kept": kept, "logs": logs}


def run(layout: dict[str, Path], *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-RepoRoot",
            str(layout["primary"]),
            "-LogRoot",
            str(layout["logs"]),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


def test_a_planted_emptied_folder_is_reported_with_its_log_lines(layout: dict[str, Path]) -> None:
    proc = run(layout, "-Json")
    assert proc.returncode == 0, proc.stderr
    out: dict[str, Any] = json.loads(proc.stdout)
    found = {Path(e["Path"]).name: e for e in out["emptied"]}
    assert set(found) == {"seat-a"}, found
    texts = [ln["Text"] for ln in found["seat-a"]["LogLines"]]
    assert len(texts) == 2, texts
    assert any("reapUntrackedWorktreeDir] git worktree remove refused" in t for t in texts)
    assert any("will try manual cleanup" in t and "Permission denied" in t for t in texts)
    assert not any("is not a working tree" in t for t in texts)
    assert not any("seat-ab" in t for t in texts)
    assert found["seat-a"]["Entries"] == 0


def test_the_text_form_names_the_folder_and_the_line(layout: dict[str, Path]) -> None:
    proc = run(layout)
    assert proc.returncode == 0, proc.stderr
    assert "1 emptied worktree folder(s)" in proc.stdout
    assert str(layout["emptied"]) in proc.stdout
    assert "main1.log:1:" in proc.stdout


def test_nothing_is_reported_once_the_folder_is_recovered(layout: dict[str, Path]) -> None:
    """The negative control on the same layout: re-adding the worktree clears the finding."""
    layout["emptied"].rmdir()
    git(layout["primary"], "worktree", "add", "-q", "-b", "recovered", str(layout["emptied"]))
    proc = run(layout)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("No emptied worktree folder"), proc.stdout


def test_it_runs_no_destructive_git_verb_and_no_delete_cmdlet() -> None:
    assert _violations(SCRIPT) == []
