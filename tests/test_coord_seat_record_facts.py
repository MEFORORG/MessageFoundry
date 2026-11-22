# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a `seat.ps1` record says about its tree, its episode and its roster verdict.

Three defects, one per group below, each of which left a valid-looking record that was wrong:

- BACKLOG #5874: the first dirty path lost a character when its status line began with a space.
- BACKLOG #5875: a claim or allocation was attributed to the wrong episode, or to none.
- BACKLOG #5876: a plain record pass erased the roster verdict a declaration had written.

Every run uses a throwaway repository, and `MEFOR_COORD_ROOT` is removed from the child's
environment, so nothing here can touch a live coordination root.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
SEATS = ROOT / "docs" / "roles" / "seats.json"
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    (r / "docs" / "roles").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    for name in ("seat.ps1", "mail-key.ps1", "coord-root.ps1"):
        shutil.copy2(COORD / name, r / "scripts" / "coord" / name)
    shutil.copy2(SEATS, r / "docs" / "roles" / "seats.json")
    # Ignored so the copied tooling never shows up in the dirty-path assertions below.
    (r / ".gitignore").write_text("scripts/\ndocs/\n", encoding="utf-8")
    for name in ("alpha.txt", "beta.txt", "gamma.txt"):
        (r / name).write_text("x\n", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def seat(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["CLAUDE_CODE_SESSION_ID"] = "record-facts-probe"
    env.pop("MEFOR_COORD_ROOT", None)
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / "seat.ps1"),
            *args,
        ],
        cwd=str(repo),
        input="",
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc


def declare(repo: Path, label: str = "builder") -> dict[str, Any]:
    seat(repo, "-Declare", "-Seat", label, "-Goal", "record facts probe")
    return read_record(repo)


def plain_record(repo: Path) -> subprocess.CompletedProcess[str]:
    return seat(repo, "-Record")


def coord_dir(repo: Path) -> Path:
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return Path(common) / "mefor-coord"


def read_record(repo: Path) -> dict[str, Any]:
    found = sorted((coord_dir(repo) / "seats").rglob("*.json"))
    assert len(found) == 1, f"expected exactly one record, got {[p.name for p in found]}"
    rec: dict[str, Any] = json.loads(found[0].read_text(encoding="utf-8"))
    return rec


def episode_start(rec: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(str(rec["lifecycleAt"]))


def put_json(path: Path, body: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body), encoding="utf-8")


# --- BACKLOG #5874 ------------------------------------------------------------------------------


def test_a_first_status_line_beginning_with_a_space_keeps_its_whole_path(repo: Path) -> None:
    (repo / "alpha.txt").write_text("changed\n", encoding="utf-8")
    assert declare(repo)["dirty"]["paths"] == ["alpha.txt"]


def test_a_rename_records_the_new_path_and_counts_once(repo: Path) -> None:
    git(repo, "mv", "beta.txt", "renamed.txt")
    dirty = declare(repo)["dirty"]
    assert dirty["paths"] == ["renamed.txt"]
    assert dirty["count"] == 1
    assert dirty["trackedCount"] == 1


def test_a_path_git_would_quote_is_recorded_as_its_real_name(repo: Path) -> None:
    """A space and a non-ASCII letter: plain porcelain quotes one and octal-escapes the other."""
    name = "café notes.txt"
    (repo / name).write_text("new\n", encoding="utf-8")
    dirty = declare(repo)["dirty"]
    assert dirty["untracked"] == [name]
    assert dirty["untrackedCount"] == 1


def test_tracked_and_untracked_stay_separated(repo: Path) -> None:
    (repo / "alpha.txt").write_text("changed\n", encoding="utf-8")
    (repo / "new.txt").write_text("new\n", encoding="utf-8")
    dirty = declare(repo)["dirty"]
    assert sorted(dirty["paths"]) == ["alpha.txt", "new.txt"]
    assert dirty["untracked"] == ["new.txt"]
    assert dirty["trackedCount"] == 1


def test_a_clean_tree_records_no_dirty_paths(repo: Path) -> None:
    dirty = declare(repo)["dirty"]
    assert dirty["count"] == 0
    assert dirty["paths"] == []


# --- BACKLOG #5875 ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("minutes", "expected"), [(20, "this-episode"), (-20, "worktree-inherited")]
)
def test_an_allocation_is_attributed_by_instant_after_a_prior_read(
    repo: Path, minutes: int, expected: str
) -> None:
    """The second pass reads the episode start back through the prior record."""
    rec = declare(repo)
    stamp = episode_start(rec) + timedelta(minutes=minutes)
    # The form alloc.ps1 writes: round-trip with a numeric offset.
    offset = stamp.astimezone(timezone(timedelta(hours=-6))).isoformat()
    put_json(
        coord_dir(repo) / "alloc" / "adr" / "9001.json",
        {"worktree": rec["worktree"], "claimed": offset},
    )
    plain_record(repo)
    allocations = read_record(repo)["allocations"]
    assert [a["attribution"] for a in allocations] == [expected]


@pytest.mark.parametrize(
    ("minutes", "expected"), [(20, "this-episode"), (-20, "worktree-inherited")]
)
def test_a_claim_reads_the_field_claim_ps1_writes(repo: Path, minutes: int, expected: str) -> None:
    rec = declare(repo)
    stamp = episode_start(rec) + timedelta(minutes=minutes)
    put_json(
        coord_dir(repo) / "claims" / "9002.json",
        {"worktree": rec["worktree"], "claimed": stamp.astimezone(UTC).isoformat()},
    )
    plain_record(repo)
    claims = read_record(repo)["claims"]
    assert [c["attribution"] for c in claims] == [expected]
    recorded = datetime.fromisoformat(str(claims[0]["claimedAt"]))
    assert recorded == stamp


def test_a_stamp_with_no_zone_is_unknown_rather_than_guessed(repo: Path) -> None:
    rec = declare(repo)
    put_json(
        coord_dir(repo) / "alloc" / "adr" / "9003.json",
        {"worktree": rec["worktree"], "claimed": "2026-11-22T10:00:00"},
    )
    plain_record(repo)
    assert [a["attribution"] for a in read_record(repo)["allocations"]] == ["unknown"]


# --- BACKLOG #5876 ------------------------------------------------------------------------------


def test_a_plain_pass_keeps_the_declared_roster_resolution(repo: Path) -> None:
    declared = declare(repo, "mgr")
    assert (declared["seatCanonical"], declared["seatRosterVerdict"]) == ("manager", "alias")
    proc = plain_record(repo)
    after = read_record(repo)
    assert (after["seatCanonical"], after["seatRosterVerdict"]) == ("manager", "alias")
    assert proc.stderr.strip() == ""


def test_a_plain_pass_does_not_reprint_a_retired_objection(repo: Path) -> None:
    """The verdict is carried, not re-resolved, so a hook path stays quiet."""
    declared = declare(repo, "console")
    assert declared["seatRosterVerdict"] == "retired"
    proc = plain_record(repo)
    assert read_record(repo)["seatRosterVerdict"] == "retired"
    assert proc.stderr.strip() == ""


def test_a_new_declaration_replaces_the_carried_verdict(repo: Path) -> None:
    declare(repo, "console")
    plain_record(repo)
    after = declare(repo, "manager")
    assert (after["seatCanonical"], after["seatRosterVerdict"]) == ("manager", "live")


def test_a_never_declared_record_still_reads_none(repo: Path) -> None:
    plain_record(repo)
    rec = read_record(repo)
    assert rec["seatCanonical"] is None
    assert rec["seatRosterVerdict"] == "none"
