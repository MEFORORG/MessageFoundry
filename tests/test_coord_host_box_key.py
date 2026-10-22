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
    # The control: the old path-only key is the collision this change removes.
    assert _key(path, legacy=True) == _key(path.upper(), legacy=True)
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


def test_mail_under_the_legacy_key_is_moved_and_read(repo: Path, shared: Path) -> None:
    legacy = _key(repo, legacy=True)
    # A seat id published before the change IS the legacy key, and mail to it lands there.
    _plant_seat(shared / "seats", legacy, str(repo), None)
    assert _send(repo, shared, legacy, "queued before the change").returncode == 0
    legacy_inbox = shared / "mail" / "box" / legacy / "inbox"
    assert len(list(legacy_inbox.glob("*.json"))) == 1

    status = _ps(COORD / "mail.ps1", repo, "-Status", "-Json", env=_env(shared))
    assert status.returncode == 0, status.stderr
    assert json.loads(status.stdout)["LegacyInbox"] == 1

    assert "queued before the change" in _drain(repo, shared)
    assert not list(legacy_inbox.glob("*.json")), "the drain moves the legacy inbox into its box"
    assert list((shared / "mail" / "box" / _key(repo) / "inbox").glob("*.json"))


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
