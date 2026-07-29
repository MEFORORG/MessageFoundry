# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the cross-surface session roster (``scripts/coord/presence.ps1``).

Every test drives the REAL script as a subprocess against a throwaway git repo and a fixture config
root, so what is under test is the logic the SessionStart hook actually runs -- not a Python
re-implementation of its rules that could drift from it silently.

Two properties carry the weight:

* **VS Code sessions are included.** That is the entire reason this exists. The Desktop app's own
  ``list_sessions`` never registers a session it did not spawn, so a VS Code session is invisible to
  it; ``<config-root>/sessions/<pid>.json`` is the only registry that has every surface.
* **Liveness is fenced, not a bare pid check.** A pid alone is not identity: pids get reused and these
  records outlive their process. ``test_pid_reuse_is_not_reported_live`` is the one that matters --
  it uses a REAL running pid whose process started long after the recorded session, which is exactly
  the shape of a recycled pid, and asserts the roster refuses to call it LIVE.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

PRESENCE = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "presence.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="presence.ps1 needs pwsh on Windows (Get-CimInstance / Process.StartTime)",
)

NOW_MS = int(time.time() * 1000)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A real git repo -- the script scopes presence to worktrees sharing one .git."""
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    (r / "f.txt").write_text("x", encoding="utf-8")
    _git(r, "add", "f.txt")
    _git(r, "commit", "-qm", "init")
    return r


@pytest.fixture
def config_root(tmp_path: Path) -> Path:
    root = tmp_path / ".claude"
    (root / "sessions").mkdir(parents=True)
    return root


def write_session(
    config_root: Path,
    *,
    pid: int,
    cwd: Path | str,
    session_id: str,
    entrypoint: str = "claude-desktop",
    started_at: int | None = None,
) -> None:
    rec = {
        "pid": pid,
        "sessionId": session_id,
        "cwd": str(cwd),
        "startedAt": NOW_MS if started_at is None else started_at,
        "version": "2.1.219",
        "peerProtocol": 1,
        "kind": "interactive",
        "entrypoint": entrypoint,
        "name": session_id[:8],
        "nameSource": "derived",
    }
    (config_root / "sessions" / f"{pid}.json").write_text(json.dumps(rec), encoding="utf-8")


def run_presence(repo: Path, config_root: Path, *extra: str) -> list[dict[str, Any]]:
    """Invoke the real script and return its JSON rows."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(PRESENCE),
            "-Repo",
            str(repo),
            "-ConfigRoot",
            str(config_root),
            "-Json",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,  # asserted below with the stderr attached, which check=True would hide
    )
    assert proc.returncode == 0, f"presence.ps1 failed: {proc.stderr}"
    out = proc.stdout.strip()
    return json.loads(out) if out else []


def test_live_session_in_repo_is_listed(repo: Path, config_root: Path) -> None:
    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="aaaaaaaa-1111")
    rows = run_presence(repo, config_root)
    assert [r["Short"] for r in rows] == ["aaaaaaaa"]
    assert rows[0]["State"] == "LIVE"


def test_vscode_session_is_included_and_labelled(repo: Path, config_root: Path) -> None:
    """The reason this script exists: the Desktop app's session tooling cannot see these."""
    write_session(
        config_root,
        pid=os.getpid(),
        cwd=repo,
        session_id="bbbbbbbb-2222",
        entrypoint="claude-vscode",
    )
    rows = run_presence(repo, config_root)
    assert len(rows) == 1
    assert rows[0]["Surface"] == "vscode"
    assert rows[0]["State"] == "LIVE"


def test_pid_reuse_is_not_reported_live(repo: Path, config_root: Path) -> None:
    """A real, running pid recorded against a much older session start = a recycled pid.

    This is the failure a bare `is the pid alive` check waves through, and the one Claude Code's own
    registry cannot catch on this host (its `procStart` field serialises as absent, so its guard
    passes unconditionally). The roster computes process start time itself and must reject this.
    """
    two_days_ago = NOW_MS - (48 * 60 * 60 * 1000)
    write_session(
        config_root,
        pid=os.getpid(),
        cwd=repo,
        session_id="cccccccc-3333",
        started_at=two_days_ago,
    )
    assert run_presence(repo, config_root) == []  # not live, so absent by default

    rows = run_presence(repo, config_root, "-All")
    assert [r["State"] for r in rows] == ["STALE"]
    assert "reused" in rows[0]["Detail"]


def test_dead_pid_is_excluded_by_default_and_shown_with_all(repo: Path, config_root: Path) -> None:
    dead = _find_free_pid()
    write_session(config_root, pid=dead, cwd=repo, session_id="dddddddd-4444")
    assert run_presence(repo, config_root) == []

    rows = run_presence(repo, config_root, "-All")
    assert [r["State"] for r in rows] == ["DEAD"]


def test_session_outside_the_repo_is_ignored(repo: Path, config_root: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "not-the-repo"
    elsewhere.mkdir()
    write_session(config_root, pid=os.getpid(), cwd=elsewhere, session_id="eeeeeeee-5555")
    assert run_presence(repo, config_root) == []


def test_sibling_prefix_directory_is_not_treated_as_inside_the_repo(
    repo: Path, config_root: Path
) -> None:
    """`<repo>-sweep` shares a string prefix with `<repo>` but is a different tree.

    A naive StartsWith would fold every `MessageFoundry-*` sibling worktree into the primary and
    report sessions as colliding in a checkout they are nowhere near.
    """
    sibling = repo.parent / f"{repo.name}-sweep"
    sibling.mkdir()
    write_session(config_root, pid=os.getpid(), cwd=sibling, session_id="ffffffff-6666")
    assert run_presence(repo, config_root) == []


def test_subdirectory_cwd_still_maps_to_its_worktree(repo: Path, config_root: Path) -> None:
    sub = repo / "messagefoundry" / "config"
    sub.mkdir(parents=True)
    write_session(config_root, pid=os.getpid(), cwd=sub, session_id="99999999-7777")
    rows = run_presence(repo, config_root)
    assert len(rows) == 1
    assert rows[0]["IsPrimary"] is True


def test_linked_worktree_session_is_scoped_to_its_own_branch(
    repo: Path, config_root: Path, tmp_path: Path
) -> None:
    """A sibling worktree's session must report ITS branch, not the primary's."""
    wt = tmp_path / "wt-feature"
    _git(repo, "worktree", "add", "-b", "feature-x", str(wt))
    write_session(config_root, pid=os.getpid(), cwd=wt, session_id="77777777-8888")
    rows = run_presence(repo, config_root)
    assert len(rows) == 1
    assert rows[0]["Branch"] == "feature-x"
    assert rows[0]["IsPrimary"] is False
    assert rows[0]["Worktree"] == "wt-feature"


def test_malformed_record_does_not_break_the_roster(repo: Path, config_root: Path) -> None:
    """A hook that throws on one bad file would take the whole SessionStart banner down."""
    (config_root / "sessions" / "99999.json").write_text("{not json", encoding="utf-8")
    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="12121212-9999")
    rows = run_presence(repo, config_root)
    assert [r["Short"] for r in rows] == ["12121212"]


def _find_free_pid() -> int:
    """A pid that is not currently running -- start a process, note its pid, wait for it to exit."""
    proc = subprocess.Popen(
        ["cmd", "/c", "exit"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    proc.wait(timeout=30)
    time.sleep(0.3)  # let the OS reap it before we claim the pid is gone
    return proc.pid
