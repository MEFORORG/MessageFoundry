# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""fleet.ps1: a live session outranks a newer record, and a briefing says what it does not know.

BACKLOG #5872: an ordinary superseded record whose own session is live in that tree reads RUNNING.
A frozen legacy copy stays SUPERSEDED, or one session shows twice. BACKLOG #5875, reader side: an
`unknown` attribution is not "an earlier occupant's", and `statusKnown: false` is not a clean tree.

Every root here is a temp directory: the seats, the session registry and the profile.
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
COORD = ROOT / "scripts" / "coord"
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the coordination scripts need pwsh on Windows",
)


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout.strip()


def _sid(session: str) -> str:
    return f"{session}-0000-0000-0000-000000000000"


def _ago(seconds: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - seconds))


class Fleet:
    """A temp repo, shared root and profile, with fleet.ps1 run against them."""

    def __init__(self, base: Path, coord: Path = COORD) -> None:
        self.coord = coord
        self.repo = base / "repo"
        self.repo.mkdir()
        for args in (
            ["init", "-q", "-b", "main"],
            ["config", "user.email", "t@example.invalid"],
            ["config", "user.name", "t"],
        ):
            _git(self.repo, *args)
        (self.repo / "f.txt").write_text("x", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "base")
        self.top = _git(self.repo, "rev-parse", "--show-toplevel")
        self.shared = base / "shared" / "mefor-coord"
        self.seats = self.shared / "seats"
        self.seats.mkdir(parents=True)
        self.profile = base / "profile"
        self.registry = self.profile / ".claude" / "sessions"
        self.registry.mkdir(parents=True)
        self.new_box = self._key("ConvertTo-BoxKey")
        self.legacy_box = self._key("ConvertTo-LegacyBoxKey")

    def _key(self, fn: str, path: str | None = None) -> str:
        """A box key from the real mail-key.ps1, never a Python copy of it."""
        proc = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f". '{self.coord / 'mail-key.ps1'}'; {fn} -Path $env:BK_PATH",
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=True,
            env=dict(os.environ, BK_PATH=path or self.top),
        )
        return proc.stdout.strip()

    def seat(self, box: str, session: str, as_of: str, **extra: Any) -> None:
        rec: dict[str, Any] = {
            "schema": 1,
            "lifecycle": "open",
            "boxKey": box,
            "worktree": self.top,
            "sessionId": _sid(session),
            "sessionKey": session,
            "seat": "builder",
            "branch": "main",
            "asOf": as_of,
            "claims": [],
            "allocations": [],
            "handoff": None,
        }
        rec.update(extra)
        stem = rec.pop("file_stem", session)
        d = self.seats / box
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{stem}.json").write_text(json.dumps(rec), encoding="utf-8")

    def live(self, session: str, cwd: str | None = None, sid: str | None = None) -> None:
        """Register a session on this test's own pid, so the real fence reads it LIVE."""
        rec = {
            "pid": os.getpid(),
            "sessionId": sid or _sid(session),
            "cwd": cwd or self.top,
            "startedAt": int(time.time() * 1000),
            "kind": "interactive",
            "entrypoint": "claude-desktop",
        }
        (self.registry / f"{session}.json").write_text(json.dumps(rec), encoding="utf-8")

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.pop("CLAUDE_CODE_SESSION_ID", None)
        env.pop("CLAUDE_CONFIG_DIR", None)
        env["MEFOR_COORD_ROOT"] = str(self.shared)
        env["USERPROFILE"] = str(self.profile)
        return subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(self.coord / "fleet.ps1"),
                *args,
            ],
            cwd=str(self.repo),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
            env=env,
        )

    def states(self) -> dict[tuple[str, str], str]:
        proc = self._run("-Json")
        assert proc.returncode in (0, 2), proc.stderr
        rows = json.loads(proc.stdout)["rows"]
        if isinstance(rows, dict):
            rows = [rows]
        return {(r["Box"], r["SessionKey"]): r["State"] for r in rows}

    def chip(self, session: str = "sess-a") -> str:
        proc = self._run("-Chip", "-BoxKey", self.new_box, "-SessionKey", session)
        assert proc.returncode == 0, proc.stderr
        return proc.stdout


@pytest.fixture
def fleet(tmp_path: Path) -> Fleet:
    return Fleet(tmp_path)


# ---------------------------------------------------------------------- BACKLOG #5872


def test_a_live_session_with_a_newer_record_in_its_tree_is_running(fleet: Fleet) -> None:
    fleet.seat(fleet.new_box, "sess-old", _ago(7200))
    fleet.seat(fleet.new_box, "sess-new", _ago(10))
    fleet.live("sess-old")
    got = fleet.states()
    assert got[(fleet.new_box, "sess-old")] == "RUNNING"
    assert got[(fleet.new_box, "sess-new")] == "INTERRUPTED"


def test_the_same_shape_with_no_live_session_stays_superseded(fleet: Fleet) -> None:
    """The control: only the fence moves the row above."""
    fleet.seat(fleet.new_box, "sess-old", _ago(7200))
    fleet.seat(fleet.new_box, "sess-new", _ago(10))
    assert fleet.states()[(fleet.new_box, "sess-old")] == "SUPERSEDED"


@pytest.mark.parametrize(
    ("legacy_age", "new_age"), [(7200, 10), (10, 7200)], ids=["legacy-older", "legacy-newer"]
)
def test_a_frozen_legacy_copy_of_a_live_session_shows_once(
    fleet: Fleet, legacy_age: int, new_age: int
) -> None:
    fleet.seat(fleet.legacy_box, "sess-e", _ago(legacy_age))
    fleet.seat(fleet.new_box, "sess-e", _ago(new_age))
    fleet.live("sess-e")
    got = fleet.states()
    assert got[(fleet.legacy_box, "sess-e")] == "SUPERSEDED"
    assert got[(fleet.new_box, "sess-e")] == "RUNNING"


def test_an_older_copy_of_a_live_session_with_no_key_shows_once(fleet: Fleet) -> None:
    """With no sessionKey it is not frozen, so the session id is what keeps it from a second row."""
    fleet.seat(fleet.legacy_box, "sess-e", _ago(7200), sessionKey="", file_stem="copy")
    fleet.seat(fleet.new_box, "sess-e", _ago(10))
    fleet.live("sess-e")
    got = fleet.states()
    assert got[(fleet.legacy_box, "")] == "SUPERSEDED"
    assert got[(fleet.new_box, "sess-e")] == "RUNNING"


@pytest.mark.parametrize("lifecycle", ["closed", "handed"])
def test_a_newer_closing_copy_keeps_the_live_sessions_older_row_superseded(
    fleet: Fleet, lifecycle: str
) -> None:
    """That copy already shows the session, so a RUNNING row beside it would be a second one."""
    fleet.seat(fleet.new_box, "sess-e", _ago(7200))
    fleet.seat(fleet.legacy_box, "sess-e", _ago(10), lifecycle=lifecycle)
    fleet.live("sess-e")
    assert fleet.states()[(fleet.new_box, "sess-e")] == "SUPERSEDED"


def test_a_live_session_that_left_the_tree_stays_superseded(fleet: Fleet, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    fleet.seat(fleet.new_box, "sess-old", _ago(7200))
    fleet.seat(fleet.new_box, "sess-new", _ago(10))
    fleet.live("sess-old", cwd=str(elsewhere))
    assert fleet.states()[(fleet.new_box, "sess-old")] == "SUPERSEDED"


def test_a_session_that_moved_to_the_primary_checkout_stays_superseded(fleet: Fleet) -> None:
    """A worktree nested under the primary: the primary's cwd contains it but is not in it."""
    nested = fleet.repo / ".claude" / "worktrees" / "x"
    _git(fleet.repo, "worktree", "add", "-q", "-b", "x", str(nested))
    top = _git(nested, "rev-parse", "--show-toplevel")
    box = fleet._key("ConvertTo-BoxKey", top)
    fleet.seat(box, "sess-old", _ago(7200), worktree=top)
    fleet.seat(box, "sess-new", _ago(10), worktree=top)
    fleet.live("sess-old", cwd=fleet.top)
    assert fleet.states()[(box, "sess-old")] == "SUPERSEDED"
    # The control: the same records with the session in that worktree.
    fleet.live("sess-old", cwd=top)
    assert fleet.states()[(box, "sess-old")] == "RUNNING"


def test_a_live_session_matched_only_by_id_prefix_does_not_count(fleet: Fleet) -> None:
    """The registry lookup matches on a prefix, so LIVE can name a longer, different session id."""
    fleet.seat(fleet.new_box, "sess-old", _ago(7200), sessionId="abcd1234")
    fleet.seat(fleet.new_box, "sess-new", _ago(10))
    fleet.live("other", sid="abcd1234-0000-0000-0000-000000000000")
    assert fleet.states()[(fleet.new_box, "sess-old")] == "SUPERSEDED"


# ---------------------------------------------------------------------- BACKLOG #5875, reader


def test_an_unknown_claim_tells_the_successor_to_check(fleet: Fleet) -> None:
    claims = [
        {"key": "backlog-1", "attribution": "this-episode"},
        {"key": "backlog-2", "attribution": "worktree-inherited"},
        {"key": "backlog-3", "attribution": "unknown"},
    ]
    fleet.seat(fleet.new_box, "sess-a", _ago(60), claims=claims)
    lines = fleet.chip().splitlines()
    assert any(ln.strip() == "CLAIMS HELD BY THE PREDECESSOR EPISODE: backlog-1" for ln in lines)
    earlier = next(i for i, ln in enumerate(lines) if "FROM EARLIER OCCUPANTS" in ln)
    assert lines[earlier + 1].strip() == "backlog-2"
    unknown = next(i for i, ln in enumerate(lines) if "CLAIMS OF UNKNOWN ATTRIBUTION" in ln)
    assert "CHECK" in lines[unknown]
    assert lines[unknown + 1].strip() == "backlog-3"


def test_only_unknown_claims_do_not_read_as_none(fleet: Fleet) -> None:
    claims = [{"key": "backlog-3", "attribution": "unknown"}]
    fleet.seat(fleet.new_box, "sess-a", _ago(60), claims=claims)
    chip = fleet.chip()
    stripped = [ln.strip() for ln in chip.splitlines()]
    assert "CLAIMS HELD BY THE PREDECESSOR EPISODE: none confirmed" in stripped
    assert "CLAIMS HELD BY THE PREDECESSOR EPISODE: none" not in stripped
    assert "FROM EARLIER OCCUPANTS" not in chip


def test_an_unknown_allocation_tells_the_successor_to_check(fleet: Fleet) -> None:
    allocs = [
        {"kind": "backlog", "number": 7, "attribution": "worktree-inherited"},
        {"kind": "adr", "number": 9, "attribution": "unknown"},
    ]
    fleet.seat(fleet.new_box, "sess-a", _ago(60), allocations=allocs)
    chip = fleet.chip()
    assert "1 MORE are allocated to that worktree PATH by earlier occupants." in chip
    stripped = [ln.strip() for ln in chip.splitlines()]
    assert "LEDGER NUMBERS ALLOCATED BY THIS EPISODE: none confirmed" in stripped
    assert "LEDGER NUMBERS ALLOCATED BY THIS EPISODE: none" not in stripped
    assert "LEDGER NUMBERS OF UNKNOWN ATTRIBUTION" in chip
    assert "adr #9" in chip


def test_a_claim_with_no_attribution_keeps_its_wording(fleet: Fleet) -> None:
    fleet.seat(fleet.new_box, "sess-a", _ago(60), claims=[{"key": "backlog-4"}])
    chip = fleet.chip()
    assert "CLAIMS HELD BY THE PREDECESSOR EPISODE: none" in chip
    assert "FROM EARLIER OCCUPANTS" in chip
    assert "UNKNOWN ATTRIBUTION" not in chip


def test_a_failed_git_status_reads_as_unknown_not_clean(fleet: Fleet) -> None:
    dirty: dict[str, Any] = {
        "statusKnown": False,
        "count": None,
        "paths": [],
        "trackedCount": None,
        "untrackedCount": None,
        "untracked": [],
    }
    fleet.seat(fleet.new_box, "sess-a", _ago(60), dirty=dirty)
    assert "TREE STATE UNKNOWN" in fleet.chip()


@pytest.mark.parametrize(
    "dirty",
    [
        {"count": 0, "paths": [], "trackedCount": 0, "untrackedCount": 0, "untracked": []},
        {"statusKnown": True, "count": 0, "untracked": []},
        None,
    ],
    ids=["no-field", "known", "no-dirty-object"],
)
def test_a_record_with_a_known_or_absent_status_says_nothing(fleet: Fleet, dirty: Any) -> None:
    fleet.seat(fleet.new_box, "sess-a", _ago(60), dirty=dirty)
    assert "TREE STATE UNKNOWN" not in fleet.chip()
