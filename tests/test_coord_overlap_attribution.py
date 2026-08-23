# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Which worktree does ``scripts/coord/overlap.ps1`` say a session is sitting in?

A session is attributed to a worktree by its cwd. The rule has to survive the layout this project
actually uses: linked worktrees live **inside** the primary checkout, at
``<primary>/.claude/worktrees/<name>``. So every linked worktree's path is *also* a prefix match for
the primary's own row, and "the worktree containing this cwd" has two correct-looking answers.

The old rule walked the session table and took the first prefix hit, which handed the primary row
whichever linked-worktree session the hashtable happened to enumerate first. The primary checkout was
then reported LIVE, on a branch nobody was on, "building" a peer's task list -- and because hashtable
order is not stable, it was a *different* wrong answer run to run, which is why it read as noise
rather than as a bug.

Driven against a REAL nested worktree, because nesting is the entire mechanism. A fixture with two
sibling directories would pass under both the old rule and the new one and prove nothing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
OVERLAP = ROOT / "scripts" / "coord" / "overlap.ps1"
TIMEOUT = 60
NOW_MS = int(time.time() * 1000)

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
def nested_layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    """The real shape: a primary, a linked worktree NESTED under it, and an outside vantage point.

    ``.claude/`` is gitignored and the ignore is pushed, so the primary sits exactly on origin/main
    with a clean tree -- otherwise the nested worktree's own files would show up as the primary's
    untracked changes and give it a row on their own merits, masking the attribution question.
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
    git(primary, "config", "user.email", "t@example.invalid")
    git(primary, "config", "user.name", "t")
    (primary / ".gitignore").write_text(".claude/\n", encoding="utf-8")
    (primary / "alpha.txt").write_text("base\n", encoding="utf-8")
    git(primary, "add", "-A")
    git(primary, "commit", "-qm", "base")
    git(primary, "remote", "add", "origin", str(origin))
    git(primary, "push", "-q", "origin", "main")

    nested = primary / ".claude" / "worktrees" / "peer"
    git(primary, "worktree", "add", "-q", "-b", "peer-branch", str(nested))
    vantage = tmp_path / "vantage"
    git(primary, "worktree", "add", "-q", "-b", "vantage-branch", str(vantage))
    return primary, nested, vantage


@pytest.fixture
def config_root(tmp_path: Path) -> Path:
    root = tmp_path / ".claude-config"
    (root / "sessions").mkdir(parents=True)
    return root


def write_session(
    config_root: Path, *, pid: int, cwd: Path, session_id: str, started_at: int = NOW_MS
) -> None:
    """A live session record. A record stamped alongside its process's start fences as LIVE.

    ``started_at`` defaults to import time, which is the right stamp for *this* process; a spawned
    child needs its own, because the fence rejects a record that precedes its process by too much.
    """
    (config_root / "sessions" / f"{pid}.json").write_text(
        json.dumps(
            {
                "pid": pid,
                "sessionId": session_id,
                "cwd": str(cwd),
                "startedAt": started_at,
                "version": "2.1.219",
                "peerProtocol": 1,
                "kind": "interactive",
                "entrypoint": "claude-vscode",
                "name": session_id[:8],
                "nameSource": "derived",
            }
        ),
        encoding="utf-8",
    )


def survey(vantage: Path, config_root: Path, tmp_path: Path) -> list[dict[str, Any]]:
    """The whole map, from a worktree that is neither the primary nor the one under test."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(OVERLAP),
            "-Repo",
            str(vantage),
            "-Json",
            "-Refresh",
            "-ConfigRoot",
            str(config_root),
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


def row_for(rows: list[dict[str, Any]], path: Path) -> dict[str, Any] | None:
    want = str(path).replace("\\", "/").rstrip("/").lower()
    for r in rows:
        if str(r.get("Path", "")).replace("\\", "/").rstrip("/").lower() == want:
            return r
    return None


def test_a_nested_worktrees_session_is_attributed_to_it_not_the_primary(
    nested_layout: tuple[Path, Path, Path], config_root: Path, tmp_path: Path
) -> None:
    """THE BUG. One session, sitting in a worktree nested under the primary checkout.

    Its cwd is a prefix match for both. Before the fix the primary could win that race and be reported
    as a live session on ``main`` -- a collision signal naming the wrong worktree, wrong branch and
    wrong work.
    """
    primary, nested, vantage = nested_layout
    (nested / "alpha.txt").write_text("base\npeer edit\n", encoding="utf-8")
    write_session(config_root, pid=os.getpid(), cwd=nested, session_id="aaaaaaaa-1111")

    rows = survey(vantage, config_root, tmp_path)

    peer = row_for(rows, nested)
    assert peer is not None, "the nested worktree must be reported"
    assert peer["Live"] is True, "the session is sitting in it"
    assert peer["Short"] == "aaaaaaaa"
    assert peer["Branch"] == "peer-branch"

    got = row_for(rows, primary)
    # The primary is clean and holds no session, so the correct answer is no row at all. Before the
    # fix it appeared, Live, wearing this session's id.
    assert got is None or got["Live"] is False, f"the primary is not where that session is: {got}"


def test_the_primary_still_owns_a_session_whose_cwd_is_actually_in_it(
    nested_layout: tuple[Path, Path, Path], config_root: Path, tmp_path: Path
) -> None:
    """Longest-prefix must not become never-the-primary.

    A session genuinely sitting in the primary checkout -- including one in a subdirectory of it that
    is not a worktree -- still belongs to the primary. This is the over-correction that would swap one
    silent mis-attribution for another.
    """
    primary, _nested, vantage = nested_layout
    subdir = primary / "messagefoundry"
    subdir.mkdir()
    (primary / "alpha.txt").write_text("base\nprimary edit\n", encoding="utf-8")
    write_session(config_root, pid=os.getpid(), cwd=subdir, session_id="bbbbbbbb-2222")

    rows = survey(vantage, config_root, tmp_path)

    got = row_for(rows, primary)
    assert got is not None, "a session in the primary's own subdirectory must attribute to it"
    assert got["Live"] is True
    assert got["Short"] == "bbbbbbbb"


def test_two_nested_sessions_each_land_in_their_own_worktree(
    nested_layout: tuple[Path, Path, Path], config_root: Path, tmp_path: Path
) -> None:
    """The ordering hazard, with enough sessions present for order to matter.

    First-hit-wins is only *visibly* arbitrary once more than one session is a candidate. Two sessions
    in two nested worktrees: each must land in its own, the primary must claim neither, and the answer
    must be the same every run -- the old rule's depended on hashtable enumeration order, so an
    unstable wrong answer read as noise and nobody filed it.
    """
    primary, nested, vantage = nested_layout
    other = primary / ".claude" / "worktrees" / "peer2"
    git(primary, "worktree", "add", "-q", "-b", "peer2-branch", str(other))
    (nested / "alpha.txt").write_text("base\npeer edit\n", encoding="utf-8")
    (other / "alpha.txt").write_text("base\npeer2 edit\n", encoding="utf-8")

    write_session(config_root, pid=os.getpid(), cwd=nested, session_id="cccccccc-3333")
    child = subprocess.Popen(  # a second REAL live pid; the fence needs a process, not a number
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        write_session(
            config_root,
            pid=child.pid,
            cwd=other,
            session_id="dddddddd-4444",
            started_at=int(time.time() * 1000),
        )
        answers = [
            json.dumps(
                sorted((str(r["Path"]).lower(), bool(r["Live"]), str(r["Short"])) for r in rows)
            )
            for rows in (survey(vantage, config_root, tmp_path) for _ in range(3))
        ]
    finally:
        child.kill()
        child.wait(timeout=10)

    assert len(set(answers)) == 1, f"overlap gave more than one answer for one state: {answers}"

    rows = json.loads(answers[0])
    by_path = {p: (live, short) for p, live, short in rows}
    assert by_path.get(str(nested).replace("\\", "/").lower()) == (True, "cccccccc")
    assert by_path.get(str(other).replace("\\", "/").lower()) == (True, "dddddddd")
    got = by_path.get(str(primary).replace("\\", "/").lower())
    assert got is None or got[0] is False, f"the primary owns neither session: {got}"


# ------------------------------------------------------- the human table names what its id IS
#
# Measured 2026-08-22 (BACKLOG #1310): this value is ``Substring(0, 8)`` of a registry session UUID,
# so it is hex by construction and indistinguishable by inspection from an abbreviated commit hash --
# and this repo prints REAL abbreviated hashes elsewhere in the same shape. A reader took one for a
# revision, searched three object stores for it, found nothing, and concluded the warning was invented.
#
# The scan is on the SHAPE OF THE LINE rather than on the value, because the value itself carries no
# evidence of which kind it is. The only thing that separates them is the word in front.


def human_table(vantage: Path, config_root: Path, tmp_path: Path) -> str:
    """The non-JSON report, which is what a person reads and what nothing else in this file covers."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(OVERLAP),
            "-Repo",
            str(vantage),
            "-Refresh",
            "-ConfigRoot",
            str(config_root),
            "-TasksDir",
            str(tmp_path / "no-such-tasks"),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"overlap exited {proc.returncode}: {proc.stderr}"
    return proc.stdout


def test_the_human_table_labels_the_session_id(
    nested_layout: tuple[Path, Path, Path], config_root: Path, tmp_path: Path
) -> None:
    """The id is SHOWN and it is NAMED. Suppressing it would satisfy half of this and hide the peer."""
    _primary, nested, vantage = nested_layout
    (nested / "alpha.txt").write_text("base\npeer edit\n", encoding="utf-8")
    write_session(config_root, pid=os.getpid(), cwd=nested, session_id="aaaaaaaa-1111")

    out = human_table(vantage, config_root, tmp_path)
    rows = [ln for ln in out.splitlines() if "aaaaaaaa" in ln]
    assert rows, f"the peer's identity was suppressed entirely:\n{out}"
    for ln in rows:
        before = ln[: ln.index("aaaaaaaa")]
        assert before.rstrip().lower().endswith("session"), (
            "this line ends in an 8-hex token beside a branch name with no noun in front of it, which "
            f"is the shape of an abbreviated commit hash:\n{ln}"
        )


def test_the_changed_file_count_says_what_it_counts(
    nested_layout: tuple[Path, Path, Path], config_root: Path, tmp_path: Path
) -> None:
    """``Files``' committed half is narrowed against the HEAD of whoever asked.

    So the number on this line is "beyond what you already have", not "what this peer changed", and the
    same peer yields a different one for a different caller. A bare "changed file(s)" overstates it.
    """
    _primary, nested, vantage = nested_layout
    (nested / "alpha.txt").write_text("base\npeer edit\n", encoding="utf-8")
    write_session(config_root, pid=os.getpid(), cwd=nested, session_id="aaaaaaaa-1111")

    out = human_table(vantage, config_root, tmp_path)
    counts = [ln.strip() for ln in out.splitlines() if "file(s)" in ln]
    assert counts, f"no file count in the table at all:\n{out}"
    for ln in counts:
        assert "beyond yours" in ln, (
            f"the count reads as absolute when it is caller-relative:\n{ln}"
        )
