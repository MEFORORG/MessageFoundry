# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/hooks/seat-record.ps1`` records the session's OWN worktree, and says when it cannot.

BACKLOG #5954: the Stop hook forwarded the raw payload to ``seat.ps1 -Record``, which took the
payload's ``cwd`` as its worktree. That ``cwd`` is where the session is NOW, so after a ``cd`` into a
sibling worktree the record landed there. It also discarded the recorder's output and exit code, so
a recorder that never ran read the same as a healthy one. The hook now resolves the worktree with the
shared session-pin rules in ``scripts/hooks/_hookinput.ps1`` and reports a recorder that did not exit 0.

Each test runs the hook IN the primary, as the desktop app does, from a throwaway clone that carries
its own copies of the scripts under test.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._session_pin import seed_pin

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


def _init(r: Path) -> None:
    r.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = Path(os.path.realpath(tmp_path)) / "repo"
    _init(r)
    for rel in (
        "scripts/hooks/seat-record.ps1",
        "scripts/hooks/_hookinput.ps1",
        "scripts/coord/seat.ps1",
        "scripts/coord/mail-key.ps1",
        "scripts/coord/coord-root.ps1",
    ):
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, r / rel)
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def _linked(repo: Path, name: str) -> Path:
    wt = repo.parent / name
    git(repo, "worktree", "add", "-q", "-b", name, str(wt))
    return wt


def _hook(repo: Path, payload: dict[str, str] | None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "hooks" / "seat-record.ps1"),
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        input="" if payload is None else json.dumps(payload),
    )
    assert proc.returncode == 0, proc.stderr
    return proc


def _records(repo: Path) -> list[dict]:
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    seats = Path(common) / "mefor-coord" / "seats"
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(seats.rglob("*.json"))]


def _same_dir(a: str, b: Path) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


class TestTheRecordLandsOnTheSessionsWorktree:
    def test_a_cd_into_a_sibling_still_records_the_pinned_worktree(self, repo: Path) -> None:
        """Mutation: forward the raw payload with no -Worktree. Red: the record names ``sib``."""
        own = _linked(repo, "own")
        sib = _linked(repo, "sib")
        seed_pin(repo, own, "s1")
        _hook(repo, {"session_id": "s1", "hook_event_name": "Stop", "cwd": str(sib)})
        recs = _records(repo)
        assert recs, "no episode record was written"
        assert all(_same_dir(r["worktree"], own) for r in recs), [r["worktree"] for r in recs]

    def test_an_unpinned_worktree_cwd_of_this_repository_is_still_recorded_there(
        self, repo: Path
    ) -> None:
        """A desktop-app session after /clear has no pin (rule 5). Its record still lands at its
        cwd's worktree, as before this hook used the pin rules, and the turn end stays silent."""
        own = _linked(repo, "own")
        proc = _hook(repo, {"session_id": "s1", "hook_event_name": "Stop", "cwd": str(own)})
        recs = _records(repo)
        assert recs, proc.stdout + proc.stderr
        assert all(_same_dir(r["worktree"], own) for r in recs), [r["worktree"] for r in recs]
        assert "[seat]" not in proc.stdout, proc.stdout

    def test_a_cwd_that_does_not_exist_records_nothing_and_says_so(
        self, repo: Path, tmp_path: Path
    ) -> None:
        gone = str(Path(os.path.realpath(tmp_path)) / "deleted-worktree")
        proc = _hook(repo, {"session_id": "s1", "hook_event_name": "Stop", "cwd": gone})
        assert "could not read this session's worktree" in proc.stdout, proc.stdout
        assert "Nothing was recorded" in proc.stdout, proc.stdout
        assert _records(repo) == []

    def test_a_cwd_in_another_repository_records_nothing_there(
        self, repo: Path, tmp_path: Path
    ) -> None:
        other = Path(os.path.realpath(tmp_path)) / "other"
        _init(other)
        (other / "g.txt").write_text("y", encoding="utf-8")
        git(other, "add", "-A")
        git(other, "commit", "-qm", "base")
        proc = _hook(repo, {"session_id": "s1", "hook_event_name": "Stop", "cwd": str(other)})
        assert "another repository" in proc.stdout, proc.stdout
        assert _records(other) == []
        assert _records(repo) == []

    def test_without_a_cwd_the_record_names_where_the_hook_runs(self, repo: Path) -> None:
        """The control: the same hook does record, so the arms above can fail."""
        proc = _hook(repo, {"session_id": "s1", "hook_event_name": "Stop"})
        recs = _records(repo)
        assert recs, proc.stdout + proc.stderr
        assert all(_same_dir(r["worktree"], repo) for r in recs)
        assert "[seat]" not in proc.stdout, "the success path prints nothing"


class TestARecorderThatDidNotRunIsReported:
    def test_a_non_zero_exit_is_said_aloud(self, repo: Path) -> None:
        """Mutation: discard the recorder's output and exit code again. Red: silence."""
        (repo / "scripts" / "coord" / "seat.ps1").write_text(
            "[Console]::Error.WriteLine('recorder broke'); exit 3\n", encoding="utf-8"
        )
        proc = _hook(repo, {"session_id": "s1", "hook_event_name": "Stop"})
        assert "the seat recorder exited 3" in proc.stdout, proc.stdout
        assert "recorder broke" in proc.stdout, proc.stdout

    def test_a_missing_input_reader_is_said_aloud(self, repo: Path) -> None:
        (repo / "scripts" / "hooks" / "_hookinput.ps1").unlink()
        proc = _hook(repo, {"session_id": "s1", "hook_event_name": "Stop"})
        assert "_hookinput.ps1 is missing" in proc.stdout, proc.stdout
        assert _records(repo) == []
