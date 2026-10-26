# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The lane tooling carries no item ceiling (owner ruling 2026-10-26).

The ruling is stated once, in the header of ``scripts/coord/lane.ps1``. That script defaulted
``-Capacity`` to 4 and wrote it into every lane record, and ``scripts/hooks/lane-level.ps1`` read a
lane stating no free items as AT CAPACITY.

These tests fail if a default cap of 4 comes back in either script:

1. a statement records ``capacity`` as null, with no upper bound on its counts, and prints no
   ceiling; a 4 carried on an old record is replaced with null on the next write. The key stays,
   because an older lane.ps1 on another branch assigns it, and that throws when the key is missing;
2. ``-Capacity`` is not a parameter any more, so a caller cannot reintroduce a cap by passing one;
3. the dispatcher arm of the hook reports a lane that states 0 free and 4 in flight, on a record
   still naming capacity 4, with its counts and with no capacity verdict. Against the scripts before
   this change it printed ``AT-CAPACITY`` and ``of 4``;
4. the hook's own self-test passes;
5. a builder lane whose level is 45 minutes old is asked to restate. Its age is how a level stated
   under the old ceiling ages out, and the hook read every stamp hours in the future on a machine
   west of UTC until this change.
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

ROOT = Path(__file__).resolve().parents[1]
LANE = ROOT / "scripts" / "coord" / "lane.ps1"
HOOK = ROOT / "scripts" / "hooks" / "lane-level.ps1"
MAIL_KEY = ROOT / "scripts" / "coord" / "mail-key.ps1"
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the coordination scripts need pwsh on Windows",
)


def _env(root: Path | None = None) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("MEFOR_COORD_ROOT", "CLAUDE_CODE_SESSION_ID")
    }
    if root is not None:
        env["MEFOR_COORD_ROOT"] = str(root)
    return env


def _ps(
    script: Path, cwd: Path, *args: str, root: Path | None = None, stdin: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), *args],
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT,
        check=False,
        env=_env(root),
    )


def _git_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    for args in (
        ["init", "-q", "-b", "main"],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
        ["commit", "-q", "--allow-empty", "-m", "base"],
    ):
        subprocess.run(["git", "-C", str(path), *args], check=True, timeout=TIMEOUT)
    return path


def _lane_record(repo: Path) -> Path:
    files = sorted((repo / ".git" / "mefor-coord" / "lanes").glob("*.json"))
    assert len(files) == 1, f"expected exactly one lane record, found {[p.name for p in files]}"
    return files[0]


# ------------------------------------------------------------------------------------- lane.ps1


def test_a_statement_records_no_capacity_and_prints_no_ceiling(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path / "repo")
    # 150 is past the old ValidateRange(0, 99) on both counts: no upper bound may come back either.
    proc = _ps(LANE, repo, "-Free", "150", "-InFlight", "150", "-Note", "n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rec = json.loads(_lane_record(repo).read_text(encoding="utf-8"))
    assert "capacity" in rec and rec["capacity"] is None, rec
    # The control: the statement itself was recorded, counts and all.
    assert rec["statedFree"] == 150 and rec["statedInFlight"] == 150, rec
    assert "150 free / 150 in flight," in proc.stdout, proc.stdout
    assert " of " not in proc.stdout.split("stated")[0], proc.stdout


def test_a_negative_count_is_still_refused(tmp_path: Path) -> None:
    """The control for the unbounded range: the lower bound still holds."""
    repo = _git_repo(tmp_path / "repo")
    proc = _ps(LANE, repo, "-Free", "-1", "-InFlight", "0")
    assert proc.returncode != 0, proc.stdout
    assert not (repo / ".git" / "mefor-coord" / "lanes").exists(), "a refused call wrote a lane"


def test_a_capacity_left_on_an_old_record_is_nulled_on_the_next_write(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path / "repo")
    assert _ps(LANE, repo, "-Free", "1", "-InFlight", "1").returncode == 0
    record = _lane_record(repo)
    old: dict[str, Any] = json.loads(record.read_text(encoding="utf-8"))
    old["capacity"] = 4
    record.write_text(json.dumps(old), encoding="utf-8")
    # The control: -Show is a strict read and prints the old record as it is.
    show = _ps(LANE, repo, "-Show")
    assert show.returncode == 0, show.stderr
    assert json.loads(show.stdout)["capacity"] == 4

    for args in (("-Asked",), ("-Free", "0", "-InFlight", "5")):
        record.write_text(json.dumps(old), encoding="utf-8")
        proc = _ps(LANE, repo, *args)
        assert proc.returncode == 0, (args, proc.stdout + proc.stderr)
        new = json.loads(record.read_text(encoding="utf-8"))
        assert "capacity" in new and new["capacity"] is None, (args, new)


def test_capacity_is_no_longer_a_parameter(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path / "repo")
    proc = _ps(LANE, repo, "-Free", "0", "-InFlight", "4", "-Capacity", "4")
    assert proc.returncode != 0, proc.stdout
    assert "Capacity" in proc.stderr, proc.stderr
    assert not (repo / ".git" / "mefor-coord" / "lanes").exists(), "a refused call wrote a lane"


# --------------------------------------------------------------------------------- lane-level.ps1


def _box_key(path: Path) -> str:
    """The box key from the real mail-key.ps1, never a Python copy of it."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f". '{MAIL_KEY}'; ConvertTo-BoxKey -Path $env:BK_PATH",
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
        env=dict(os.environ, BK_PATH=str(path)),
    )
    return proc.stdout.strip()


def _plant_seat(seats: Path, box: str, worktree: Path | str, seat: str) -> None:
    d = seats / box
    d.mkdir(parents=True, exist_ok=True)
    rec = {
        "schema": 1,
        "asOf": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "lifecycle": "open",
        "boxKey": box,
        "worktree": str(worktree),
        "sessionKey": f"s-{box}",
        "seat": seat,
        "branch": "main",
        "claims": [],
        "allocations": [],
        "handoff": None,
    }
    (d / f"s-{box}.json").write_text(json.dumps(rec), encoding="utf-8")


def test_the_dispatcher_report_has_no_capacity_verdict(tmp_path: Path) -> None:
    shared = tmp_path / "shared" / "mefor-coord"
    seats = shared / "seats"
    lanes = shared / "lanes"
    lanes.mkdir(parents=True)
    dispatcher = _git_repo(tmp_path / "dispatcher-lane")
    tree = tmp_path / "builder-tree"
    tree.mkdir()

    box = _box_key(tree)
    _plant_seat(seats, box, tree, "builder")
    # The hook reads no verdict below a floor of five seat directories. These name no live tree.
    for i in range(4):
        _plant_seat(seats, f"filler-{i:04d}", "C:/no/such/tree", "manager")
    # The retired ceiling's own case, on a record written before the change: 0 free, 4 in flight,
    # capacity 4, stated just now with nothing moved since.
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lane: dict[str, Any] = {
        "v": 1,
        "capacity": 4,
        "statedFree": 0,
        "statedInFlight": 4,
        "statedUtc": now,
        "statedNote": "four in flight",
        "turnsSinceStated": 0,
        "tipAtStated": "x",
        "tipNow": "x",
        "claimHashAtStated": "a",
        "claimHashNow": "a",
    }
    (lanes / f"{box}.json").write_text(json.dumps(lane), encoding="utf-8")

    proc = _ps(HOOK, dispatcher, root=shared, stdin=json.dumps({"hook_event_name": "Stop"}))
    assert proc.returncode == 0, proc.stderr
    text = str(json.loads(proc.stdout)["hookSpecificOutput"]["additionalContext"])

    # The control: the lane was discovered and its record read, before and after this change alike.
    assert 'Note: "four in flight"' in text, text
    # The ceiling checks come first, so against the old scripts they are what fails.
    assert "capacity" not in text.lower(), text
    assert "of 4" not in text, text
    assert "4 in flight, 0 free by work" in text, text
    # A level stated just now is not in the future. West of UTC the old age read said -300m here.
    assert "stated -" not in text, text


def test_the_hook_self_test_passes(tmp_path: Path) -> None:
    proc = _ps(HOOK, tmp_path, "-SelfTest")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "none of them can read a lane as full" in proc.stdout, proc.stdout


NAG = "Your lane level is unstated or stale"


@pytest.mark.parametrize(("minutes_ago", "nags"), [(0, False), (45, True)])
def test_a_builder_lane_is_asked_again_once_its_level_ages(
    tmp_path: Path, minutes_ago: int, nags: bool
) -> None:
    """The 0-minute case is the control: the nag below is the age's, not the record's shape's."""
    shared = tmp_path / "shared" / "mefor-coord"
    (shared / "lanes").mkdir(parents=True)
    builder = _git_repo(tmp_path / "builder-lane")
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - minutes_ago * 60))
    lane = {"v": 1, "statedFree": 0, "statedInFlight": 1, "statedUtc": stamp, "turnsSinceStated": 0}
    (shared / "lanes" / f"{_box_key(builder)}.json").write_text(json.dumps(lane), encoding="utf-8")

    proc = _ps(HOOK, builder, root=shared, stdin=json.dumps({"hook_event_name": "Stop"}))
    assert proc.returncode == 0, proc.stderr
    assert (NAG in proc.stdout) is nags, proc.stdout
