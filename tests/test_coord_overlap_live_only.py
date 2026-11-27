# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``overlap.ps1 -LiveOnly`` walks only the worktrees a live session owns.

The collision gate and session-context.ps1 read only Live rows. Walking every dormant worktree as
well outran both hooks' harness timeouts once worktrees accumulated (1481 measured 2026-11-27), and
a killed hook checks nothing. So the mode must:

* still return the live peer's row, dirty file and all, so the gate can still deny on it;
* drop the dormant peer's row, which neither caller reads;
* neither read nor write the whole-map cache, because a live-only map read back by a bare run would
  under-report every dormant worktree.

Driven against real throwaway repos, because the question is what the script walks and writes.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
OVERLAP = ROOT / "scripts" / "coord" / "overlap.ps1"
TIMEOUT = 60

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="overlap.ps1 needs pwsh on Windows",
)


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


def _cache_path(repo: Path) -> Path:
    """The whole-map cache file for this querying root, named as overlap.ps1 names it."""
    common = _git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    top = _git(repo, "rev-parse", "--path-format=absolute", "--show-toplevel").strip()
    norm = top.replace("\\", "/").rstrip("/").lower()
    key = hashlib.sha256(norm.encode("utf-8")).hexdigest()[:8]
    return Path(common) / "mefor-coord" / "overlap-cache" / f"{key}.json"


@pytest.fixture
def fleet(tmp_path: Path) -> Iterator[dict[str, Any]]:
    """A primary, a LIVE peer and a DORMANT peer, both peers editing ``alpha.txt``.

    The session record names a freshly spawned child rather than this pytest process, for the
    reason tests/test_coord_overlap_work_signal.py's fixture gives: liveness rejects a record whose
    process started long before it registered, and an xdist worker can be old.
    """
    origin = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True, capture_output=True
    )
    primary = tmp_path / "primary"
    primary.mkdir()
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(primary)], check=True, capture_output=True
    )
    _git(primary, "config", "user.email", "t@example.invalid")
    _git(primary, "config", "user.name", "t")
    (primary / "alpha.txt").write_text("base\n", encoding="utf-8")
    _git(primary, "add", "-A")
    _git(primary, "commit", "-qm", "base")
    _git(primary, "remote", "add", "origin", str(origin))
    _git(primary, "push", "-q", "origin", "main")

    live = tmp_path / "live-wt"
    dormant = tmp_path / "dormant-wt"
    _git(primary, "worktree", "add", "-q", "-b", "live-branch", str(live))
    _git(primary, "worktree", "add", "-q", "-b", "dormant-branch", str(dormant))
    (live / "alpha.txt").write_text("base\nlive edit\n", encoding="utf-8")
    (dormant / "alpha.txt").write_text("base\ndormant edit\n", encoding="utf-8")

    config_root = tmp_path / ".claude-account-9"
    (config_root / "sessions").mkdir(parents=True)
    stand_in = subprocess.Popen(  # noqa: S603  # nosec B603 - fixed argv, no shell, our interpreter
        [sys.executable, "-I", "-c", "import time; time.sleep(600)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    (config_root / "sessions" / "1.json").write_text(
        json.dumps(
            {
                "pid": stand_in.pid,
                "sessionId": str(uuid.uuid4()),
                "cwd": str(live),
                "startedAt": int(time.time() * 1000),
                "entrypoint": "claude-code",
            }
        ),
        encoding="utf-8",
    )
    yield {"primary": primary, "config_root": config_root, "tmp": tmp_path}

    stand_in.terminate()
    try:
        stand_in.wait(timeout=10)
    except subprocess.TimeoutExpired:
        stand_in.kill()
        stand_in.wait(timeout=10)


def _overlap(fleet: dict[str, Any], *args: str) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(OVERLAP),
            "-Repo",
            str(fleet["primary"]),
            "-ConfigRoot",
            str(fleet["config_root"]),
            "-TasksDir",
            str(fleet["tmp"] / "no-such-tasks"),
            "-Json",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"overlap exited {proc.returncode}: {proc.stderr}\n{proc.stdout}"
    return proc


def _rows(proc: subprocess.CompletedProcess[str]) -> list[dict[str, Any]]:
    got = json.loads(proc.stdout)
    return got if isinstance(got, list) else [got]


def test_live_only_keeps_the_live_peer_and_drops_the_dormant_one(fleet: dict[str, Any]) -> None:
    # POSITIVE CONTROL: the full walk sees both peers, so the fixture can tell a dropped row from a
    # row that was never there.
    full = {r["Branch"]: r for r in _rows(_overlap(fleet, "-Refresh"))}
    assert set(full) == {"live-branch", "dormant-branch"}, full
    assert full["live-branch"]["Live"] is True
    assert full["dormant-branch"]["Live"] is False

    live_only = _rows(_overlap(fleet, "-LiveOnly"))
    assert [r["Branch"] for r in live_only] == ["live-branch"], live_only
    assert "alpha.txt" in live_only[0]["Dirty"], live_only[0]


def test_live_only_answers_the_single_file_query_the_gate_denies_on(fleet: dict[str, Any]) -> None:
    rows = _rows(_overlap(fleet, "-LiveOnly", "-File", "alpha.txt"))
    assert [r["Branch"] for r in rows] == ["live-branch"], rows
    assert rows[0]["MatchedDirty"] is True, rows[0]


def test_live_only_neither_writes_nor_reads_the_whole_map_cache(fleet: dict[str, Any]) -> None:
    cache = _cache_path(fleet["primary"])
    assert not cache.exists()
    _overlap(fleet, "-LiveOnly")
    assert not cache.exists(), "a live-only map was cached, so a bare run would under-report"

    # A planted cache holding only a fabricated row: a run that read it would return that row.
    _overlap(fleet)
    assert cache.exists(), "the control: a full walk does write the cache"
    planted = json.loads(cache.read_text(encoding="utf-8-sig"))
    planted["rows"] = [
        {"Worktree": "ghost", "Branch": "ghost-branch", "Live": True, "Files": ["alpha.txt"]}
    ]
    cache.write_text(json.dumps(planted), encoding="utf-8")
    assert [r["Branch"] for r in _rows(_overlap(fleet))] == ["ghost-branch"], (
        "the control: a full run within the window does read the planted cache"
    )
    assert [r["Branch"] for r in _rows(_overlap(fleet, "-LiveOnly"))] == ["live-branch"]
