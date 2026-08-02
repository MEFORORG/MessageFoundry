# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the two signals ``scripts/coord/overlap.ps1`` reports per file.

``Files`` is the UNION of what a branch committed-and-has-not-landed with what is dirty in its tree.
That union is right for the human report and wrong for a gate, which needs to know whether someone is
editing the file *now*. ``Dirty`` and the per-query ``MatchedDirty`` carry that distinction.

**The case these exist for is the one that fails SILENT.** A live session whose file is dirty *and*
committed at once -- uncommitted edits in one region, landed work in another -- is a genuine collision.
If ``MatchedDirty`` were computed from the committed diff rather than the working tree it would read
false there, the gate would allow the edit, and two sessions would write the same file with nothing
reported. An over-block is loud and annoying; this would be quiet and cost someone their work.

Driven against a REAL git fixture, because the question is entirely about what git reports: a test
using stub rows would only assert that the plumbing carries a value someone else computed.
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
OVERLAP = ROOT / "scripts" / "coord" / "overlap.ps1"
TIMEOUT = 45

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="overlap.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def peer_worktree(tmp_path: Path) -> tuple[Path, Path]:
    """A primary tracking origin/main, plus a linked worktree acting as another session's checkout."""
    origin = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True, capture_output=True
    )
    primary = tmp_path / "primary"
    primary.mkdir()
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(primary)], check=True, capture_output=True
    )
    git(primary, "config", "user.email", "t@example.invalid")
    git(primary, "config", "user.name", "t")
    for name in ("alpha.txt", "beta.txt"):
        (primary / name).write_text("base\n", encoding="utf-8")
    git(primary, "add", "-A")
    git(primary, "commit", "-qm", "base")
    git(primary, "remote", "add", "origin", str(origin))
    git(primary, "push", "-q", "origin", "main")

    peer = tmp_path / "peer-wt"
    git(primary, "worktree", "add", "-q", "-b", "peer-branch", str(peer))
    return primary, peer


def query(primary: Path, tmp_path: Path, path: str) -> list[dict[str, Any]]:
    """Ask overlap.ps1 about ONE file, from the primary's perspective, bypassing the cache."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(OVERLAP),
            "-Repo",
            str(primary),
            "-File",
            path,
            "-Json",
            "-Refresh",
            "-ConfigRoot",
            str(tmp_path / "no-such-config"),
            "-TasksDir",
            str(tmp_path / "no-such-tasks"),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"overlap exited {proc.returncode}: {proc.stderr}"
    out = proc.stdout.strip()
    parsed: list[dict[str, Any]] = json.loads(out) if out else []
    return parsed


def test_a_file_dirty_and_committed_at_once_reports_matcheddirty(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    """THE SILENT-FAILURE CASE. Raised by a session that spent an evening in exactly this state.

    The peer has COMMITTED a change to alpha.txt and then made a further UNCOMMITTED edit to it. It is
    simultaneously in the committed-and-unlanded set and in the working tree. If MatchedDirty were
    derived from the committed diff it would read false, the gate would allow, and two sessions would
    edit one file with nothing reported -- a quiet loss rather than a loud refusal.
    """
    primary, peer = peer_worktree
    (peer / "alpha.txt").write_text("base\ncommitted change\n", encoding="utf-8")
    git(peer, "add", "alpha.txt")
    git(peer, "commit", "-qm", "committed work on alpha")
    (peer / "alpha.txt").write_text("base\ncommitted change\nUNSAVED EDIT\n", encoding="utf-8")

    rows = query(primary, tmp_path, "alpha.txt")
    assert rows, "overlap reported nothing for a file the peer is changing"
    row = rows[0]
    assert "alpha.txt" in row["Dirty"], f"Dirty must carry the working-tree edit: {row['Dirty']}"
    assert row["MatchedDirty"] is True, (
        "dirty-AND-committed must report MatchedDirty, or the gate allows a real collision"
    )


def test_a_committed_and_clean_file_does_not_report_matcheddirty(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    """The over-block that was actually reported: committed, tree clean, session done with the file."""
    primary, peer = peer_worktree
    (peer / "beta.txt").write_text("base\ncommitted change\n", encoding="utf-8")
    git(peer, "add", "beta.txt")
    git(peer, "commit", "-qm", "committed work on beta")

    rows = query(primary, tmp_path, "beta.txt")
    assert rows, "a committed file should still be REPORTED, just not as an active edit"
    row = rows[0]
    assert row["MatchedDirty"] is False
    assert "beta.txt" not in (row["Dirty"] or [])
    assert "beta.txt" in row["Files"], "it must remain in Files -- the peer did author it"


def test_an_uncommitted_only_file_reports_matcheddirty(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    primary, peer = peer_worktree
    (peer / "alpha.txt").write_text("base\nunsaved only\n", encoding="utf-8")

    rows = query(primary, tmp_path, "alpha.txt")
    assert rows
    assert rows[0]["MatchedDirty"] is True


def test_an_untouched_file_is_not_reported(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    primary, peer = peer_worktree
    (peer / "alpha.txt").write_text("base\nunsaved only\n", encoding="utf-8")
    assert query(primary, tmp_path, "beta.txt") == []


def test_overlap_does_not_rewrite_a_peers_git_index(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    """An observer must not perturb what it observes.

    A plain ``git status`` REWRITES the index of the repo it inspects, and overlap walks every peer
    worktree on a PreToolUse hook -- so merely asking "what is in flight" was mutating other sessions'
    checkouts. Fixed with --no-optional-locks; pinned here so it cannot silently regress.
    """
    primary, peer = peer_worktree
    (peer / "alpha.txt").write_text("base\nunsaved\n", encoding="utf-8")
    index = Path(git(peer, "rev-parse", "--path-format=absolute", "--git-dir").strip()) / "index"
    query(primary, tmp_path, "alpha.txt")  # warm any lazy refresh, then measure
    before = index.stat().st_mtime_ns
    query(primary, tmp_path, "alpha.txt")
    assert index.stat().st_mtime_ns == before, "overlap rewrote a peer worktree's git index"
