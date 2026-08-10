# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The SessionStart banner (``scripts/worktree/session-context.ps1``) must degrade, never throw.

Whatever this hook prints to stdout IS the chat's starting context. If it raises, the session opens
with a stack trace instead of its coordination rules -- and the failure is silent, because nobody
reads a hook's exit code. These tests pin the fail-safe contract around the presence roster it now
calls into: a missing, broken, or slow ``presence.ps1`` must cost you the live-session list and
nothing else.

The scripts are copied into a throwaway tree rather than edited in place, so a test run never mutates
the repo -- these same scripts are live in every sibling session while the suite runs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "scripts" / "worktree" / "session-context.ps1"
PRESENCE = ROOT / "scripts" / "coord" / "presence.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="session-context.ps1 needs pwsh on Windows",
)

# Printed unconditionally, before any worktree or presence logic runs. Its presence in stdout is the
# signal that the hook produced real context rather than dying early.
ALWAYS_PRINTED = "[MessageFoundry] This project prefers Ultracode"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def staged(tmp_path: Path) -> Path:
    """A git repo with 2+ worktrees (so the parallel-session block runs) holding script copies."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "f.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-qm", "init")
    _git(repo, "worktree", "add", "-q", "-b", "second", str(tmp_path / "wt2"))

    (repo / "scripts" / "worktree").mkdir(parents=True)
    (repo / "scripts" / "coord").mkdir(parents=True)
    shutil.copy(CONTEXT, repo / "scripts" / "worktree" / "session-context.ps1")
    return repo


def run_context(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "worktree" / "session-context.ps1"),
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,  # the whole point is that it exits 0 even when presence.ps1 fails
    )


def fake_presence(repo: Path, rows: list[dict[str, object]]) -> None:
    """Stand in for presence.ps1 -Json, emitting exactly the shape the real script emits."""
    payload = json.dumps(rows).replace("'", "''")  # '' escapes a quote in a PS single-quoted string
    (repo / "scripts" / "coord" / "presence.ps1").write_text(
        f"Write-Output '{payload}'\n", encoding="utf-8"
    )


def test_banner_survives_a_missing_presence_script(staged: Path) -> None:
    """presence.ps1 absent (an older checkout, a partial clone) must not cost the banner."""
    assert not (staged / "scripts" / "coord" / "presence.ps1").exists()
    proc = run_context(staged)
    assert proc.returncode == 0
    assert ALWAYS_PRINTED in proc.stdout
    assert "PARALLEL SESSION" in proc.stdout
    assert "LIVE sessions" not in proc.stdout  # degraded, not crashed


def test_banner_survives_a_presence_script_that_throws(staged: Path) -> None:
    (staged / "scripts" / "coord" / "presence.ps1").write_text(
        "throw 'presence exploded'\n", encoding="utf-8"
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert ALWAYS_PRINTED in proc.stdout
    assert "PARALLEL SESSION" in proc.stdout
    assert "LIVE sessions" not in proc.stdout


def test_banner_survives_presence_emitting_junk(staged: Path) -> None:
    """Malformed JSON on stdout must not take the hook down in ConvertFrom-Json."""
    (staged / "scripts" / "coord" / "presence.ps1").write_text(
        "Write-Output 'not json at all'\n", encoding="utf-8"
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert ALWAYS_PRINTED in proc.stdout


def test_live_peers_are_rendered_when_presence_reports_them(staged: Path) -> None:
    """The positive arm: a peer in the shared primary on another surface must be called out.

    Without this the suite would pass with the presence block silently emitting nothing at all --
    every other test here asserts an ABSENCE, which a no-op integration also satisfies.
    """
    # One foreign vscode session sitting in the shared primary -- the worst case the banner exists for.
    fake_presence(
        staged,
        [
            {
                "Short": "deadbeef",
                "Surface": "vscode",
                "Worktree": "primary",
                "Branch": "main",
                "IsSelf": False,
                "IsPrimary": True,
                "State": "LIVE",
            }
        ],
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert "LIVE sessions in this repo right now (1 besides you)" in proc.stdout
    assert "deadbeef" in proc.stdout
    assert "vscode" in proc.stdout
    assert "SHARED PRIMARY" in proc.stdout
    assert "cannot be reached by" in proc.stdout  # the non-desktop coordination note


def test_the_session_id_is_labelled_because_the_same_banner_prints_real_shas(
    staged: Path,
) -> None:
    """BACKLOG #1098: an 8-hex session id printed bare reads as an abbreviated commit SHA.

    It reads that way for a measured reason rather than a vague one, and this test measures it: the
    ``git worktree list`` block a few lines up prints ``<path> <abbreviated sha> [branch]``, so the same
    banner already teaches "8 hex before a bracketed branch = commit SHA". The roster then reused the
    shape for a registry session id, which resolves to no git object at all. A session comparing "is that
    worktree ahead of mine" against it gets an error at best, and the wrong tree if the prefix resolves.

    The POSITIVE CONTROL is the first half: assert the real SHA is genuinely in this output, keyed to
    ``rev-parse HEAD`` so it is an object and not a shape. Without it the second assertion would be a
    claim about an ambiguity nobody had shown to exist.
    """
    head = subprocess.run(
        ["git", "-C", str(staged), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    fake_presence(
        staged,
        [
            {
                "Short": "deadbeef",
                "Surface": "desktop",
                "Worktree": "sibling",
                "Branch": "second",
                "IsSelf": False,
                "IsPrimary": False,
                "State": "LIVE",
            }
        ],
    )
    proc = run_context(staged)
    assert proc.returncode == 0

    sha_rows = [ln for ln in proc.stdout.splitlines() if head[:7] in ln]
    assert sha_rows, (
        f"no row carries HEAD ({head[:7]}), so this banner does not in fact print commit SHAs and the "
        f"ambiguity below is unproven -- fix this control before trusting the assertion after it"
    )
    print(f"real SHA rows in the same banner: {sha_rows}")

    row = next(ln for ln in proc.stdout.splitlines() if "deadbeef" in ln)
    print(f"roster row: {row!r}")
    assert row.strip().startswith("session deadbeef"), (
        f"the registry session id is printed bare, in the same shape the worktree rows use for a real "
        f"abbreviated SHA: {row!r}"
    )


def test_self_is_excluded_from_the_peer_count(staged: Path) -> None:
    fake_presence(
        staged,
        [
            {
                "Short": "aaaaaaaa",
                "Surface": "desktop",
                "Worktree": "w",
                "Branch": "b",
                "IsSelf": True,
                "IsPrimary": False,
                "State": "LIVE",
            }
        ],
    )
    proc = run_context(staged)
    assert proc.returncode == 0
    assert "LIVE sessions" not in proc.stdout  # you alone is not a coordination problem
