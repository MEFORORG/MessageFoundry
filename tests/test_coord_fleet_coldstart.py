# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the cold-start transfer path (``scripts/coord/fleet.ps1 -ColdStart``).

This is the command a virgin session runs as its first act after the fleet moves to another Claude
account. It gets one shot, in front of an operator who by construction has no context to check it
against, so the properties worth pinning are about what it REFUSES to imply -- not about formatting.

Every test drives the real script as a subprocess against a throwaway git repo whose
``.git/mefor-coord/seats`` is populated by hand, matching the convention in
``test_coord_presence.py``: what is under test is the script the owner actually pastes, never a
Python re-implementation of its rules that could drift from it silently.

The load-bearing tests:

* ``test_empty_population_is_not_reported_as_an_all_clear`` -- an empty respawn population and an
  instrument that could not look produce THE SAME output here. If that ever renders as a clean bill
  of health, a fleet gets silently dropped at the one moment nobody can audit it.
* ``test_receipt_precedes_every_briefing`` -- the receipt is the only thing that scopes the briefing
  list. Printed after it, it is a footnote nobody reads before clicking.
* ``test_record_missing_optional_fields_does_not_crash`` -- a cold start reads records written by the
  PREVIOUS writer version, which is exactly when a field can be absent. Crashing there produces no
  output at all, at the worst possible moment.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

FLEET = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "fleet.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="fleet.ps1 needs pwsh on Windows",
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def _record(**over: Any) -> dict[str, Any]:
    """A complete episode record. Fields mirror the shape seat.ps1 writes."""
    now = datetime.now(UTC) - timedelta(minutes=5)
    rec: dict[str, Any] = {
        "schema": 1,
        "writerVersion": "seat.ps1/test",
        "asOf": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "asOfSource": "hook:Stop",
        "writes": 1,
        "lifecycle": "open",
        "lifecycleAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "boxKey": "box",
        "worktree": "C:\\nonexistent\\predecessor",
        "worktreeSource": "payload",
        # A session id the liveness fence cannot match, so the row lands on INTERRUPTED.
        "sessionId": "00000000-0000-0000-0000-000000000001",
        "sessionKey": "00000000-0000-0000-0000-000000000001",
        "sessionIdSource": "payload",
        "kind": None,
        "entrypoint": None,
        "pid": 1,
        "configRootLabel": "acct-test",
        "configRootSource": "env",
        "poolEpoch": 1,
        "seat": None,
        "seatSource": None,
        "declaredAt": None,
        "goal": None,
        "done": None,
        "outOfScope": None,
        "branch": "some-branch",
        "upstream": None,
        "tip": "0" * 40,
        "mergeBase": "0" * 40,
        "touchedPaths": [],
        "unpushed": {"count": 0, "base": "origin/main"},
        "dirty": {"count": 0, "paths": [], "untracked": []},
        "stashSha": None,
        "stashCovers": "tracked-only",
        "claims": [],
        "allocations": [],
        "handoff": None,
        "predecessor": None,
        "notes": "",
    }
    rec.update(over)
    return rec


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    _git(r, "commit", "--allow-empty", "-q", "-m", "base")
    return r


def _seat(repo: Path, box: str, rec: dict[str, Any]) -> None:
    d = repo / ".git" / "mefor-coord" / "seats" / box
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{rec['sessionKey']}.json").write_text(json.dumps(rec), encoding="utf-8")


def _coldstart(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(FLEET), "-ColdStart", "-RepoHint", str(repo)],
        capture_output=True,
        text=True,
    )


def test_emits_a_briefing_for_every_respawn_eligible_seat(repo: Path) -> None:
    """INTERRUPTED and HANDED are both respawn-eligible; both must get a full briefing."""
    _seat(repo, "box-interrupted", _record(seat="alpha"))
    _seat(
        repo,
        "box-handed",
        _record(
            lifecycle="handed",
            seat="beta",
            sessionId="00000000-0000-0000-0000-000000000002",
            sessionKey="00000000-0000-0000-0000-000000000002",
        ),
    )

    res = _coldstart(repo)

    assert "RESPAWN POPULATION: 2 seat(s)" in res.stdout
    assert "BRIEFING 1 OF 2" in res.stdout
    assert "BRIEFING 2 OF 2" in res.stdout
    assert "SEAT: alpha" in res.stdout
    assert "SEAT: beta" in res.stdout
    # Each briefing must carry the command that regenerates it alone.
    assert res.stdout.count("fleet.ps1 -Chip -BoxKey") == 2


def test_closed_seats_are_excluded(repo: Path) -> None:
    """CLOSED is finished work. Respawning it would duplicate a completed seat."""
    _seat(repo, "box-closed", _record(lifecycle="closed", seat="done-already"))

    res = _coldstart(repo)

    assert "RESPAWN POPULATION: 0 seat(s)" in res.stdout
    assert "done-already" not in res.stdout


def test_empty_population_is_not_reported_as_an_all_clear(repo: Path) -> None:
    """An empty population and a blind instrument produce the same output -- say so."""
    res = _coldstart(repo)

    assert "RESPAWN POPULATION: 0 seat(s)" in res.stdout
    assert "NO SEAT IS RESPAWN-ELIGIBLE" in res.stdout
    # The refusal to imply an all-clear is the point of the test.
    assert "SAME output" in res.stdout
    assert "RECEIPT -- what was EXAMINED" in res.stdout


def test_receipt_precedes_every_briefing(repo: Path) -> None:
    """The receipt is what scopes the list; after the briefings it is a footnote."""
    _seat(repo, "box-a", _record(seat="alpha"))

    res = _coldstart(repo)

    assert res.stdout.index("RECEIPT -- what was EXAMINED") < res.stdout.index("BRIEFING 1 OF 1")


def test_record_missing_optional_fields_does_not_crash(repo: Path) -> None:
    """A cold start reads records from the PREVIOUS writer, where a field may simply be absent."""
    rec = _record(seat="alpha")
    for gone in ("handoff", "stashSha", "touchedPaths", "claims", "allocations", "notes"):
        rec.pop(gone, None)
    _seat(repo, "box-old-writer", rec)

    res = _coldstart(repo)

    assert "BRIEFING 1 OF 1" in res.stdout, (
        f"cold start produced no briefing for a record from an older writer.\n"
        f"stderr: {res.stderr[:2000]}"
    )
    assert "SEAT: alpha" in res.stdout
