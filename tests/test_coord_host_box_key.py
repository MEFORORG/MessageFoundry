# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The box key hashes the host as well as the worktree path (docs/COORD-SHARED-ROOT.md, step 4).

A box key names a seat directory, a mailbox and a lane file. On a shared root two PCs can each hold
a worktree at the same path, and a path-only key gave them one of each. These tests pin:

1. two hosts at one path get two keys, while the legacy path-only key still collides (the control);
2. the exact hash input, ``<HOST>|<normalised path>``, so the sender and the drain cannot drift;
3. mail queued under the legacy key is still read, and another host's box at this path is not;
4. a seat record written under the legacy key is carried into the new key, never another host's,
   and the roster marks the legacy record superseded.
"""

from __future__ import annotations

import hashlib
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
HOOKS = ROOT / "scripts" / "hooks"
TIMEOUT = 90
OTHER = "OTHER-PC"
SESSION = "11111111-2222-3333-4444-555555555555"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the coordination scripts need pwsh on Windows",
)


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    for args in (
        ["init", "-q", "-b", "main"],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
    ):
        _git(r, *args)
    (r / "f.txt").write_text("x", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    return r


@pytest.fixture
def shared(tmp_path: Path) -> Path:
    s = tmp_path / "shared" / "mefor-coord"
    s.mkdir(parents=True)
    return s


def _env(root: Path | None, **extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("MEFOR_COORD_ROOT", None)
    env.pop("CLAUDE_CODE_SESSION_ID", None)
    if root is not None:
        env["MEFOR_COORD_ROOT"] = str(root)
    env.update(extra)
    return env


def _ps(
    script: Path, cwd: Path, *args: str, env: dict[str, str], stdin: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), *args],
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )


def _key(path: str | Path, host: str | None = None, *, legacy: bool = False) -> str:
    """A box key from the real mail-key.ps1, never a Python copy of it."""
    if legacy:
        call = "ConvertTo-LegacyBoxKey -Path $env:BK_PATH"
    elif host:
        call = "ConvertTo-BoxKey -Path $env:BK_PATH -HostName $env:BK_HOST"
    else:
        call = "ConvertTo-BoxKey -Path $env:BK_PATH"
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f". '{COORD / 'mail-key.ps1'}'; {call}",
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
        env=dict(os.environ, BK_PATH=str(path), BK_HOST=host or ""),
    )
    return proc.stdout.strip()


def _top(repo: Path) -> str:
    return _git(repo, "rev-parse", "--show-toplevel")


# ------------------------------------------------------------------------------------ the key


def test_two_hosts_at_one_path_get_two_keys() -> None:
    path = r"D:\Code\MessageFoundry\.claude\worktrees\autonomy-plan"
    mine, theirs = _key(path, "ALIENWARE"), _key(path, "MEFORDEV01")
    assert mine != theirs, "two PCs at one path must not share a seat id or a mailbox"
    # The readable half is unchanged, so a directory listing still names the tree.
    assert mine.rsplit("-", 1)[0] == theirs.rsplit("-", 1)[0] == "autonomy-plan"
    # The controls. One host twice gives one key, so the difference above is the host's. And the old
    # key, which has no host input at all, names neither box: it is a read-only name now.
    assert _key(path, "ALIENWARE") == mine
    assert _key(path, legacy=True) not in (mine, theirs)


def test_the_host_is_case_insensitive_and_defaults_to_this_machine() -> None:
    path = r"C:\x\tree"
    assert _key(path, "other-pc") == _key(path, OTHER)
    assert _key(path) == _key(path, os.environ["COMPUTERNAME"])


def test_the_hash_input_is_host_bar_normalised_path() -> None:
    path = "D:/Work/Some/Tree/"
    norm = r"d:\work\some\tree"
    digest = hashlib.sha256(f"{OTHER}|{norm}".encode()).hexdigest()[:8]
    assert _key(path, OTHER) == f"tree-{digest}"
    legacy = hashlib.sha256(norm.encode()).hexdigest()[:8]
    assert _key(path, legacy=True) == f"tree-{legacy}"


# ------------------------------------------------------------------------------------ mail


def _plant_seat(seats: Path, box: str, worktree: str, host: str | None, **extra: Any) -> Path:
    rec: dict[str, Any] = {
        "schema": 1,
        "asOf": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "lifecycle": "open",
        "boxKey": box,
        "worktree": worktree,
        "sessionId": "sess-p-0000-0000-0000-000000000000",
        "sessionKey": "sess-p",
        "seat": "builder",
        "branch": "main",
        "claims": [],
        "allocations": [],
        "handoff": None,
    }
    if host is not None:
        rec["host"] = host
    rec.update(extra)
    d = seats / box
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"{rec['sessionKey']}.json"
    f.write_text(json.dumps(rec), encoding="utf-8")
    return f


def _send(repo: Path, shared: Path, to: str, body: str) -> subprocess.CompletedProcess[str]:
    return _ps(
        COORD / "mail.ps1", repo, "-Send", "-To", to, "-Body", body, "-Json", env=_env(shared)
    )


def _drain(repo: Path, shared: Path) -> str:
    payload = {"hook_event_name": "SessionStart", "cwd": str(repo), "session_id": SESSION}
    proc = _ps(HOOKS / "mail-drain.ps1", repo, env=_env(shared), stdin=json.dumps(payload))
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_a_path_send_lands_in_this_hosts_box(repo: Path, shared: Path) -> None:
    proc = _send(repo, shared, str(repo), "for this pc")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)[0]["Key"] == _key(repo)
    assert "for this pc" in _drain(repo, shared)


def test_another_hosts_box_at_this_path_is_not_read(repo: Path, shared: Path) -> None:
    theirs = _key(repo, OTHER)
    _plant_seat(shared / "seats", theirs, str(repo), OTHER)
    assert _send(repo, shared, theirs, "for the other pc").returncode == 0
    assert "for the other pc" not in _drain(repo, shared)
    assert list((shared / "mail" / "box" / theirs / "inbox").glob("*.json")), "left for its owner"


def _queue_under_the_legacy_key(repo: Path, shared: Path, body: str) -> Path:
    """Mail as a sender older than the change queued it: in the path-only box."""
    assert _send(repo, shared, str(repo), body).returncode == 0
    box = shared / "mail" / "box"
    legacy_inbox = box / _key(repo, legacy=True) / "inbox"
    legacy_inbox.mkdir(parents=True)
    for f in (box / _key(repo) / "inbox").glob("*.json"):
        f.rename(legacy_inbox / f.name)
    assert len(list(legacy_inbox.glob("*.json"))) == 1
    return legacy_inbox


def test_mail_under_the_legacy_key_is_moved_and_read(repo: Path, shared: Path) -> None:
    legacy_inbox = _queue_under_the_legacy_key(repo, shared, "queued before the change")
    # A file this channel did not mint is not counted as waiting: the drain would never move it.
    (legacy_inbox / "note.json").write_text("{}", encoding="utf-8")

    status = _ps(COORD / "mail.ps1", repo, "-Status", "-Json", env=_env(shared))
    assert status.returncode == 0, status.stderr
    assert json.loads(status.stdout)["LegacyInbox"] == 1

    assert "queued before the change" in _drain(repo, shared)
    assert [f.name for f in legacy_inbox.glob("*.json")] == ["note.json"]
    assert list((shared / "mail" / "box" / _key(repo) / "inbox").glob("*--*.json"))


def test_the_watcher_wakes_on_mail_under_the_legacy_key(repo: Path, shared: Path) -> None:
    _queue_under_the_legacy_key(repo, shared, "wake me")
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(HOOKS / "mail-watch.ps1"),
            "-MaxWaitSeconds",
            "15",
            "-PollSeconds",
            "1",
        ],
        cwd=str(repo),
        input=json.dumps({"cwd": str(repo), "session_id": SESSION}),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        env=_env(shared),
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "wake me" in proc.stderr


def test_a_legacy_seat_id_is_sent_to_the_new_box(repo: Path, shared: Path) -> None:
    """A seat id published before the change names the old box, which every PC at the path reads."""
    legacy = _key(repo, legacy=True)
    _plant_seat(shared / "seats", legacy, str(repo), None)
    proc = _send(repo, shared, legacy, "to an old id")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)[0]["Key"] == _key(repo)
    assert not (shared / "mail" / "box" / legacy).exists()

    # When the newest record under that old id is another host's, the mail goes to THAT host's box.
    time.sleep(0.05)
    _plant_seat(shared / "seats", legacy, str(repo), OTHER, sessionKey="sess-q")
    proc = _send(repo, shared, legacy, "to the other pc")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)[0]["Key"] == _key(repo, OTHER)


# ------------------------------------------------------------------------------------ seats


def _declare(repo: Path, shared: Path, session: str) -> subprocess.CompletedProcess[str]:
    return _ps(
        COORD / "seat.ps1",
        repo,
        "-Declare",
        "-Seat",
        "builder",
        "-Done",
        "d",
        env=_env(shared, CLAUDE_CODE_SESSION_ID=session),
    )


def _hours_ago(h: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - h * 3600))


def test_a_seat_writes_only_the_new_key_and_carries_a_legacy_prior(
    repo: Path, shared: Path
) -> None:
    top = _top(repo)
    seats = shared / "seats"
    old = _plant_seat(
        seats,
        _key(top, legacy=True),
        top,
        None,
        sessionKey="sess-a",
        goal="goal from before the change",
        writes=5,
        asOf=_hours_ago(1),
    )
    before = old.read_bytes()
    proc = _declare(repo, shared, "sess-a")
    assert proc.returncode == 0, proc.stderr

    new = seats / _key(top) / "sess-a.json"
    rec = json.loads(new.read_text(encoding="utf-8"))
    assert rec["goal"] == "goal from before the change"
    assert rec["writes"] == 6
    assert rec["boxKey"] == _key(top)
    assert old.read_bytes() == before, "no writer touches the legacy key"

    fleet = _ps(COORD / "fleet.ps1", repo, "-Json", env=_env(shared))
    assert fleet.returncode in (0, 2), fleet.stderr
    rows = {r["Box"]: r for r in json.loads(fleet.stdout)["rows"]}
    assert rows[_key(top, legacy=True)]["State"] == "SUPERSEDED"
    assert rows[_key(top)]["State"] != "SUPERSEDED"


def test_a_legacy_record_from_another_host_is_not_adopted(repo: Path, shared: Path) -> None:
    top = _top(repo)
    _plant_seat(
        shared / "seats",
        _key(top, legacy=True),
        top,
        OTHER,
        sessionKey="sess-b",
        goal="the other pc's goal",
        asOf=_hours_ago(1),
    )
    assert _declare(repo, shared, "sess-b").returncode == 0
    rec = json.loads((shared / "seats" / _key(top) / "sess-b.json").read_text(encoding="utf-8"))
    assert rec.get("goal") != "the other pc's goal"


def test_a_legacy_record_stamped_with_this_host_is_still_found(repo: Path, shared: Path) -> None:
    """The migration copies records under their old path-only directories and stamps `host`, so the
    old key is read for ANY record and judged by host, not only for records with no host."""
    top = _top(repo)
    seats = shared / "seats"
    old = _plant_seat(
        seats,
        _key(top, legacy=True),
        top,
        os.environ["COMPUTERNAME"],
        sessionKey="sess-d",
        goal="stamped by the migration",
        asOf=_hours_ago(1),
    )
    assert _declare(repo, shared, "sess-d").returncode == 0
    rec = json.loads((seats / _key(top) / "sess-d.json").read_text(encoding="utf-8"))
    assert rec["goal"] == "stamped by the migration"

    fleet = _ps(COORD / "fleet.ps1", repo, "-Json", env=_env(shared))
    assert fleet.returncode in (0, 2), fleet.stderr
    rows = {r["Box"]: r for r in json.loads(fleet.stdout)["rows"]}
    assert rows[old.parent.name]["State"] == "SUPERSEDED"


def test_a_legacy_record_written_after_the_new_one_is_the_prior(repo: Path, shared: Path) -> None:
    """An older seat.ps1 on a worktree's branch may still write the old box while the hook writes the
    new one. The record written last wins, whichever box it is in."""
    top = _top(repo)
    seats = shared / "seats"
    _plant_seat(seats, _key(top), top, None, sessionKey="sess-c", goal="stale", asOf=_hours_ago(2))
    time.sleep(0.05)
    _plant_seat(
        seats, _key(top, legacy=True), top, None, sessionKey="sess-c", goal="declared later"
    )
    assert _declare(repo, shared, "sess-c").returncode == 0
    rec = json.loads((seats / _key(top) / "sess-c.json").read_text(encoding="utf-8"))
    assert rec["goal"] == "declared later"


# ------------------------------------------------------------------------------------ lanes


@pytest.fixture
def builder(tmp_path: Path) -> Path:
    """A repo whose leaf names a builder lane, so the lane hook asks it for its level."""
    r = tmp_path / "builder-lane"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    return r


def _lane_hook(cwd: Path, shared: Path) -> str:
    proc = _ps(
        HOOKS / "lane-level.ps1",
        cwd,
        env=_env(shared),
        stdin=json.dumps({"hook_event_name": "Stop"}),
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _plant_lane(shared: Path, key: str, host: str | None) -> None:
    lanes = shared / "lanes"
    lanes.mkdir(exist_ok=True)
    rec: dict[str, Any] = {
        "v": 1,
        "statedFree": 1,
        "statedInFlight": 1,
        "statedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "turnsSinceStated": 0,
    }
    if host is not None:
        rec["host"] = host
    (lanes / f"{key}.json").write_text(json.dumps(rec), encoding="utf-8")


NAG = "Your lane level is unstated or stale"


def test_the_lane_hook_reads_a_lane_file_under_the_legacy_key(builder: Path, shared: Path) -> None:
    assert NAG in _lane_hook(builder, shared), "the control: no lane file at all is stale"
    _plant_lane(shared, _key(builder, legacy=True), None)
    assert NAG not in _lane_hook(builder, shared)


def test_the_lane_hook_ignores_another_hosts_legacy_lane_file(builder: Path, shared: Path) -> None:
    _plant_lane(shared, _key(builder, legacy=True), OTHER)
    assert NAG in _lane_hook(builder, shared)
    _plant_lane(shared, _key(builder), None)
    assert NAG not in _lane_hook(builder, shared), "this host's own lane file is read first"


def test_a_fresher_level_under_the_legacy_key_beats_an_unstated_new_file(
    builder: Path, shared: Path
) -> None:
    """`lane.ps1 -Asked` on the new key writes no number; it must not hide a stated old level."""
    lanes = shared / "lanes"
    lanes.mkdir()
    (lanes / f"{_key(builder)}.json").write_text(
        json.dumps({"v": 1, "statedUtc": None, "turnsSinceStated": 0}), encoding="utf-8"
    )
    assert NAG in _lane_hook(builder, shared), "the control: an unstated new file alone nags"
    _plant_lane(shared, _key(builder, legacy=True), None)
    assert NAG not in _lane_hook(builder, shared)


def test_a_legacy_seat_id_with_an_unreadable_host_is_refused(repo: Path, shared: Path) -> None:
    legacy = _key(repo, legacy=True)
    f = _plant_seat(shared / "seats", legacy, str(repo), None)
    rec = json.loads(f.read_text(encoding="utf-8"))
    rec["host"] = 123  # present but not text: NOT CHECKABLE HERE, and it names no box
    f.write_text(json.dumps(rec), encoding="utf-8")
    proc = _send(repo, shared, legacy, "to nobody")
    assert proc.returncode != 0
    assert not (shared / "mail" / "box").exists()


def test_one_session_crossing_the_change_is_one_seat(repo: Path, shared: Path) -> None:
    """Minutes apart is inside fleet.ps1's 0.1 h age rounding; the new box still wins."""
    top = _top(repo)
    seats = shared / "seats"
    _plant_seat(seats, _key(top, legacy=True), top, None, sessionKey="sess-e")
    _plant_seat(seats, _key(top), top, None, sessionKey="sess-e")
    fleet = _ps(COORD / "fleet.ps1", repo, "-Json", env=_env(shared))
    assert fleet.returncode in (0, 2), fleet.stderr
    rows = {r["Box"]: r for r in json.loads(fleet.stdout)["rows"]}
    assert rows[_key(top, legacy=True)]["State"] == "SUPERSEDED"
    assert rows[_key(top)]["State"] != "SUPERSEDED"
