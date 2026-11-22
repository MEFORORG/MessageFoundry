# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How fleet.ps1 orders two records of one tree (BACKLOG #5872).

A live session is RUNNING even when a newer record shares its tree. A crashed predecessor is
SUPERSEDED even when both records fall in one rounded age bucket, because the compare reads the
instants and not the 0.1 h ages. An exact tie supersedes neither, since picking one could hide a
crashed seat from the respawn population. The exception is one session's frozen legacy-box copy: it
stays SUPERSEDED ahead of LIVE, or that session shows twice, and it never supersedes the session's
own new-box record.

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


class Fleet:
    """A temp repo, shared root and profile, with fleet.ps1 run against them."""

    def __init__(self, base: Path) -> None:
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

    def _key(self, fn: str) -> str:
        """A box key from the real mail-key.ps1, never a Python copy of it."""
        proc = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f". '{COORD / 'mail-key.ps1'}'; {fn} -Path $env:BK_PATH",
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=True,
            env=dict(os.environ, BK_PATH=self.top),
        )
        return proc.stdout.strip()

    def seat(
        self, box: str, session: str, as_of: str | None, *, omit_key: bool = False, **extra: Any
    ) -> None:
        rec: dict[str, Any] = {
            "schema": 1,
            "lifecycle": "open",
            "boxKey": box,
            "worktree": self.top,
            "sessionId": f"{session}-0000-0000-0000-000000000000",
            "sessionKey": session,
            "seat": "builder",
            "branch": "main",
            "claims": [],
            "allocations": [],
            "handoff": None,
        }
        if as_of is not None:
            rec["asOf"] = as_of
        rec.update(extra)
        if omit_key:
            del rec["sessionKey"]
        d = self.seats / box
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{session}.json").write_text(json.dumps(rec), encoding="utf-8")

    def live(self, session: str, cwd: str | None = None) -> None:
        """Register a session on this test's own pid, so the real fence reads it LIVE."""
        rec = {
            "pid": os.getpid(),
            "sessionId": f"{session}-0000-0000-0000-000000000000",
            "cwd": cwd or self.top,
            "startedAt": int(time.time() * 1000),
            "kind": "interactive",
            "entrypoint": "claude-desktop",
        }
        (self.registry / f"{session}.json").write_text(json.dumps(rec), encoding="utf-8")

    def states(self) -> dict[tuple[str, str], str]:
        env = dict(os.environ)
        env.pop("CLAUDE_CODE_SESSION_ID", None)
        env.pop("CLAUDE_CONFIG_DIR", None)
        env["MEFOR_COORD_ROOT"] = str(self.shared)
        env["USERPROFILE"] = str(self.profile)
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(COORD / "fleet.ps1"), "-Json"],
            cwd=str(self.repo),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
            env=env,
        )
        assert proc.returncode in (0, 2), proc.stderr
        rows = json.loads(proc.stdout)["rows"]
        if isinstance(rows, dict):
            rows = [rows]
        return {(r["Box"], r["SessionKey"]): r["State"] for r in rows}


@pytest.fixture
def fleet(tmp_path: Path) -> Fleet:
    return Fleet(tmp_path)


def _ago(seconds: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - seconds))


def test_a_live_session_with_a_newer_record_in_its_tree_is_running(fleet: Fleet) -> None:
    fleet.seat(fleet.new_box, "sess-old", _ago(3600))
    fleet.seat(fleet.new_box, "sess-new", _ago(10))
    fleet.live("sess-old")
    got = fleet.states()
    assert got[(fleet.new_box, "sess-old")] == "RUNNING"
    assert got[(fleet.new_box, "sess-new")] == "INTERRUPTED"


def test_a_crashed_predecessor_in_one_age_bucket_is_superseded(fleet: Fleet) -> None:
    """Twenty seconds apart both round to the same 0.1 h age."""
    fleet.seat(fleet.new_box, "sess-old", _ago(40))
    fleet.seat(fleet.new_box, "sess-new", _ago(20))
    got = fleet.states()
    assert got[(fleet.new_box, "sess-old")] == "SUPERSEDED"
    assert got[(fleet.new_box, "sess-new")] == "INTERRUPTED"


def test_a_crashed_predecessor_in_another_age_bucket_is_superseded(fleet: Fleet) -> None:
    """The control for the case above: this one was already told apart by the rounded ages."""
    fleet.seat(fleet.new_box, "sess-old", _ago(7200))
    fleet.seat(fleet.new_box, "sess-new", _ago(20))
    got = fleet.states()
    assert got[(fleet.new_box, "sess-old")] == "SUPERSEDED"
    assert got[(fleet.new_box, "sess-new")] == "INTERRUPTED"


def test_an_exact_tie_supersedes_neither(fleet: Fleet) -> None:
    """asOf has one-second resolution. Breaking a tie could hide a crashed seat from a respawn."""
    stamp = _ago(30)
    fleet.seat(fleet.new_box, "sess-a", stamp)
    fleet.seat(fleet.new_box, "sess-b", stamp)
    got = fleet.states()
    assert got[(fleet.new_box, "sess-a")] == "INTERRUPTED"
    assert got[(fleet.new_box, "sess-b")] == "INTERRUPTED"


def test_a_record_with_no_timestamp_supersedes_nothing(fleet: Fleet) -> None:
    fleet.seat(fleet.new_box, "sess-a", None)
    fleet.seat(fleet.new_box, "sess-b", _ago(30))
    got = fleet.states()
    assert got[(fleet.new_box, "sess-a")] == "INTERRUPTED"
    assert got[(fleet.new_box, "sess-b")] == "INTERRUPTED"


@pytest.mark.parametrize(
    ("legacy_age", "new_age"),
    [(3600, 10), (10, 3600), (30, 30)],
    ids=["legacy-older", "legacy-newer", "tied"],
)
def test_a_live_session_with_a_frozen_legacy_copy_shows_once(
    fleet: Fleet, legacy_age: int, new_age: int
) -> None:
    stamps = {age: _ago(age) for age in {legacy_age, new_age}}
    fleet.seat(fleet.legacy_box, "sess-e", stamps[legacy_age])
    fleet.seat(fleet.new_box, "sess-e", stamps[new_age])
    fleet.live("sess-e")
    got = fleet.states()
    assert got[(fleet.legacy_box, "sess-e")] == "SUPERSEDED"
    assert got[(fleet.new_box, "sess-e")] == "RUNNING"


@pytest.mark.parametrize(
    ("legacy_age", "new_age"),
    [(3600, 10), (10, 3600)],
    ids=["legacy-older", "legacy-newer"],
)
def test_a_crashed_session_with_a_frozen_legacy_copy_stays_respawnable(
    fleet: Fleet, legacy_age: int, new_age: int
) -> None:
    """A frozen copy written last must not take the session's only respawnable row with it."""
    fleet.seat(fleet.legacy_box, "sess-e", _ago(legacy_age))
    fleet.seat(fleet.new_box, "sess-e", _ago(new_age))
    got = fleet.states()
    assert got[(fleet.legacy_box, "sess-e")] == "SUPERSEDED"
    assert got[(fleet.new_box, "sess-e")] == "INTERRUPTED"


def test_a_newer_frozen_copy_makes_its_session_the_last_occupant(fleet: Fleet) -> None:
    """The session wrote last, so its new-box record is the tree's one respawnable row."""
    fleet.seat(fleet.new_box, "sess-a", _ago(7200))
    fleet.seat(fleet.new_box, "sess-b", _ago(3600))
    fleet.seat(fleet.legacy_box, "sess-a", _ago(10))
    got = fleet.states()
    assert got[(fleet.new_box, "sess-a")] == "INTERRUPTED"
    assert got[(fleet.legacy_box, "sess-a")] == "SUPERSEDED"
    assert got[(fleet.new_box, "sess-b")] == "SUPERSEDED"


def test_a_session_closed_through_a_newer_legacy_copy_is_not_respawnable(fleet: Fleet) -> None:
    fleet.seat(fleet.new_box, "sess-e", _ago(7200))
    fleet.seat(fleet.legacy_box, "sess-e", _ago(60), lifecycle="closed")
    got = fleet.states()
    assert got[(fleet.new_box, "sess-e")] == "CLOSED"
    assert got[(fleet.legacy_box, "sess-e")] == "CLOSED"


def test_a_session_handed_through_a_newer_legacy_copy_shows_once(fleet: Fleet) -> None:
    fleet.seat(fleet.new_box, "sess-e", _ago(7200))
    fleet.seat(fleet.legacy_box, "sess-e", _ago(60), lifecycle="handed")
    got = fleet.states()
    assert got[(fleet.new_box, "sess-e")] == "HANDED"
    assert got[(fleet.legacy_box, "sess-e")] == "SUPERSEDED"


def test_the_shared_nosid_key_freezes_nothing(fleet: Fleet) -> None:
    """Every writer with no session id uses this key, so two such records may be two sessions."""
    fleet.seat(fleet.new_box, "nosid", _ago(7200))
    fleet.seat(fleet.new_box, "sess-c", _ago(3600))
    fleet.seat(fleet.legacy_box, "nosid", _ago(10))
    got = fleet.states()
    assert got[(fleet.new_box, "sess-c")] == "SUPERSEDED"
    assert got[(fleet.legacy_box, "nosid")] == "INTERRUPTED"


def test_a_legacy_copy_with_no_session_key_is_still_frozen(fleet: Fleet) -> None:
    fleet.seat(fleet.legacy_box, "sess-e", _ago(3600), omit_key=True)
    fleet.seat(fleet.new_box, "sess-e", _ago(10))
    fleet.live("sess-e")
    got = fleet.states()
    assert got[(fleet.legacy_box, "")] == "SUPERSEDED"
    assert got[(fleet.new_box, "sess-e")] == "RUNNING"


def test_a_live_session_that_left_the_tree_is_superseded(fleet: Fleet, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    fleet.seat(fleet.new_box, "sess-old", _ago(3600))
    fleet.seat(fleet.new_box, "sess-new", _ago(10))
    fleet.live("sess-old", cwd=str(elsewhere))
    assert fleet.states()[(fleet.new_box, "sess-old")] == "SUPERSEDED"


def test_a_stamp_with_no_offset_orders_as_utc(fleet: Fleet) -> None:
    fleet.seat(fleet.new_box, "sess-old", _ago(3600).removesuffix("Z"))
    fleet.seat(fleet.new_box, "sess-new", _ago(60))
    got = fleet.states()
    assert got[(fleet.new_box, "sess-old")] == "SUPERSEDED"
    assert got[(fleet.new_box, "sess-new")] == "INTERRUPTED"


def test_another_sessions_live_legacy_record_is_not_frozen(fleet: Fleet) -> None:
    """Only a session's own new-box record freezes its legacy copy."""
    fleet.seat(fleet.legacy_box, "sess-old", _ago(3600))
    fleet.seat(fleet.new_box, "sess-new", _ago(10))
    fleet.live("sess-old")
    got = fleet.states()
    assert got[(fleet.legacy_box, "sess-old")] == "RUNNING"
    assert got[(fleet.new_box, "sess-new")] == "INTERRUPTED"
