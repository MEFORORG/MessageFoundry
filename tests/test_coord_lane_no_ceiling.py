# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The lane tooling carries no item ceiling (owner ruling 2026-10-26).

``scripts/coord/lane.ps1`` defaulted ``-Capacity`` to 4 and wrote it into every lane record, and
``scripts/hooks/lane-level.ps1`` read a lane stating no free items as AT CAPACITY. The owner retired
the four-item lane ceiling, the start-throttle by burn, and any WIP limit on briefing: Builders and
Managers work at full speed, and usage is governed only by the Steward's holds and the korus
Workflow gate.

These tests fail if a default cap of 4 comes back in either script:

1. a statement records no ``capacity`` and prints no ceiling, and one carried on an old record is
   dropped on the next write;
2. ``-Capacity`` is not a parameter any more, so a caller cannot reintroduce a cap by passing one;
3. the dispatcher arm of the hook reports a lane that states 0 free and 4 in flight, on a record
   still naming capacity 4, with its counts and with no capacity verdict. Against the scripts before
   this change it printed ``AT-CAPACITY`` and ``of 4``;
4. the hook's own self-test passes.
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
    proc = _ps(LANE, repo, "-Free", "0", "-InFlight", "9", "-Note", "n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rec = json.loads(_lane_record(repo).read_text(encoding="utf-8"))
    assert "capacity" not in rec, rec
    # The control: the statement itself was recorded, nine in flight and all.
    assert rec["statedFree"] == 0 and rec["statedInFlight"] == 9, rec
    assert "0 free / 9 in flight," in proc.stdout, proc.stdout
    assert " of " not in proc.stdout.split("stated")[0], proc.stdout


def test_a_capacity_left_on_an_old_record_is_dropped_on_the_next_write(tmp_path: Path) -> None:
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
        assert "capacity" not in json.loads(record.read_text(encoding="utf-8")), args


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

    # The control: the lane was discovered and its counts read.
    assert "1 LANES" in text, text
    assert "4 in flight, 0 free by work" in text, text
    assert "capacity" not in text.lower(), text
    assert "of 4" not in text, text


def test_the_hook_self_test_passes(tmp_path: Path) -> None:
    proc = _ps(HOOK, tmp_path, "-SelfTest")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "none of them can read a lane as full" in proc.stdout, proc.stdout
