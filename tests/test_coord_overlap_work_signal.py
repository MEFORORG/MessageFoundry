# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The WORK signal in ``scripts/coord/overlap.ps1``: where it reads, and what it says when it reads
nothing.

**These are positive controls, and that is the point.** The defect they pin cost nothing at all until
someone measured it, because a work signal that reads an empty store renders exactly like a fleet with
nothing to say. Measured 2026-08-30: a live run over 136 rows returned a work signal on ZERO of them
and had been doing so for over a week. Three faults were stacked, each on its own enough to produce
that zero:

1. The reader looked only in ``~/.claude/tasks``. A box runs several config roots and a session's task
   list lives under the root it BOOTED from; both live sessions were on ``.claude-account-2``.
2. Task directories are now named ``session-<first 8 of the id>``. The old ``<SessionId>*`` glob cannot
   match that shape at any root.
3. Nothing writes task files any more. 209 exist across six roots, newest 2026-08-22; all 21
   directories created since hold none.

So each test below plants work somewhere the OLD reader could not have found it and asserts the signal
comes back. A test that only asserted "no crash" would have passed throughout the outage.

The last two tests are about the census, which is the actual remedy for fault 3: the reader cannot be
fixed into finding work that nobody writes, so the requirement is that an empty store SAYS SO instead
of reporting zero work.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
OVERLAP = ROOT / "scripts" / "coord" / "overlap.ps1"
TIMEOUT = 90

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
def fleet(tmp_path: Path) -> dict[str, Any]:
    """A primary, a peer worktree, and a LIVE session registered against the peer.

    The registry record names this pytest process, whose pid is by definition alive and whose start
    time precedes ``startedAt`` -- the two things ``Test-RecordLiveness`` checks. Without a live
    session the row carries no session id and the work signal is never consulted at all, so the
    liveness is load-bearing rather than scene-setting.
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
    (primary / "alpha.txt").write_text("base\n", encoding="utf-8")
    git(primary, "add", "-A")
    git(primary, "commit", "-qm", "base")
    git(primary, "remote", "add", "origin", str(origin))
    git(primary, "push", "-q", "origin", "main")

    peer = tmp_path / "peer-wt"
    git(primary, "worktree", "add", "-q", "-b", "peer-branch", str(peer))

    # NOT NAMED ".claude". The whole first fault was a reader that only ever looked at the default
    # root, so a fixture root spelled that way could pass while the bug was fully present.
    config_root = tmp_path / ".claude-account-9"
    (config_root / "sessions").mkdir(parents=True)
    session_id = str(uuid.uuid4())
    (config_root / "sessions" / "1.json").write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "sessionId": session_id,
                "cwd": str(peer),
                "startedAt": int(time.time() * 1000),
                "entrypoint": "claude-code",
            }
        ),
        encoding="utf-8",
    )
    return {
        "primary": primary,
        "peer": peer,
        "config_root": config_root,
        "session_id": session_id,
        "seats": Path(
            git(primary, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
        )
        / "mefor-coord"
        / "seats",
    }


def survey(fleet: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    """The whole-map query. No ``-TasksDir``: the task stores must be DERIVED from the config root,
    which is the repair under test."""
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(OVERLAP),
            "-Repo",
            str(fleet["primary"]),
            "-Json",
            "-Refresh",
            "-ConfigRoot",
            str(fleet["config_root"]),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


def live_row(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert proc.returncode == 0, f"overlap exited {proc.returncode}: {proc.stderr}"
    rows = json.loads(proc.stdout.strip() or "[]")
    live: list[dict[str, Any]] = [r for r in rows if r["Live"]]
    assert len(live) == 1, f"expected exactly one live row, got {[r['Worktree'] for r in rows]}"
    return live[0]


def plant_task(store: Path, dir_name: str, subject: str) -> None:
    d = store / dir_name
    d.mkdir(parents=True)
    (d / "1.json").write_text(
        json.dumps({"subject": subject, "status": "in_progress"}), encoding="utf-8"
    )


def plant_seat(seats: Path, session_id: str, goal: str) -> None:
    d = seats / "box-key"
    d.mkdir(parents=True, exist_ok=True)
    (d / "rec.json").write_text(
        json.dumps({"sessionId": session_id, "seat": "builder", "goal": goal}), encoding="utf-8"
    )


def test_a_task_list_outside_the_default_config_root_is_found(fleet: dict[str, Any]) -> None:
    """FAULT 1. The task list lives under an account root, which is where every real one lives.

    The old reader's store was the single literal ``~/.claude/tasks``, so this file was unreachable no
    matter what it contained.
    """
    plant_task(fleet["config_root"] / "tasks", fleet["session_id"], "porting the ORU feed")
    row = live_row(survey(fleet))
    assert row["Work"] == ["porting the ORU feed"], row["Work"]
    assert row["WorkSource"] == ["task"], row["WorkSource"]


def test_the_new_session_prefixed_directory_shape_is_found(fleet: dict[str, Any]) -> None:
    """FAULT 2. Directories are now ``session-<first 8>``, which no ``<full uuid>*`` glob can match."""
    plant_task(
        fleet["config_root"] / "tasks",
        f"session-{fleet['session_id'][:8]}",
        "draining the outbox retry queue",
    )
    row = live_row(survey(fleet))
    assert row["Work"] == ["draining the outbox retry queue"], row["Work"]
    assert row["WorkSource"] == ["task"], row["WorkSource"]


def test_a_declared_seat_goal_answers_when_no_task_list_exists(fleet: dict[str, Any]) -> None:
    """FAULT 3, and the reason a reader repair alone would still report nothing.

    Nothing writes task files any more, so the signal needs a source that is still being written. The
    seat record is, by a Stop hook, on every session.
    """
    plant_seat(fleet["seats"], fleet["session_id"], "rebuilding the DICOM SR mapper")
    row = live_row(survey(fleet))
    assert row["Work"] == ["rebuilding the DICOM SR mapper"], row["Work"]
    assert row["WorkSource"] == ["seat"], row["WorkSource"]


def test_a_task_list_outranks_the_seat_goal(fleet: dict[str, Any]) -> None:
    """A live task list is a finer-grained answer than a goal declared once at session start, so it
    wins. Both planted, so this fails if the fallback ever became an unconditional append."""
    plant_task(fleet["config_root"] / "tasks", fleet["session_id"], "the current step")
    plant_seat(fleet["seats"], fleet["session_id"], "the whole session goal")
    row = live_row(survey(fleet))
    assert row["Work"] == ["the current step"], row["Work"]


def test_an_empty_task_store_says_so_rather_than_reporting_no_work(fleet: dict[str, Any]) -> None:
    """THE DEFECT ITSELF. An empty store and a quiet fleet rendered identically for over a week.

    The store exists and holds nothing, which is precisely the live condition measured 2026-08-30 for
    every directory created since 2026-08-22. The census must name that, not print a zero.
    """
    (fleet["config_root"] / "tasks").mkdir()
    proc = survey(fleet)
    assert proc.returncode == 0, proc.stderr
    assert "THE TASK STORE IS EMPTY" in proc.stderr, proc.stderr
    # The counted half of the same claim, so a future edit cannot keep the sentence and lose the
    # measurement behind it.
    assert "read 0 task(s) across 1 of 1 task store(s)" in proc.stderr, proc.stderr


def test_the_census_counts_what_it_actually_read(fleet: dict[str, Any]) -> None:
    """THE POSITIVE CONTROL FOR THE CENSUS ITSELF. Without it, a census hard-coded to zero would
    satisfy the test above, and a reader that had gone blind again would still print a reassuring
    'empty store' line while work sat unread beside it."""
    plant_task(fleet["config_root"] / "tasks", fleet["session_id"], "one")
    plant_seat(fleet["seats"], fleet["session_id"], "two")
    proc = survey(fleet)
    assert proc.returncode == 0, proc.stderr
    assert "read 1 task(s) across 1 of 1 task store(s) and 1 seat record(s)" in proc.stderr, (
        proc.stderr
    )
    assert "asked 1 live session(s): 1 answered from a task list" in proc.stderr, proc.stderr
    assert "THE TASK STORE IS EMPTY" not in proc.stderr, proc.stderr
