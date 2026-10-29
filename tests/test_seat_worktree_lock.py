# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A declared seat's worktree carries git's ``locked`` file, and a clean exit removes only its own.

BACKLOG #2524; why a lock at all is scripts/worktree/worktree-audit.ps1's header. ``seat.ps1``
creates the lock only on ``-Prompt`` (SessionStart), hands it over on a SessionStart from /clear,
/resume or /compact, and only relabels it on ``-Declare``. ``-Record`` (every Stop) never locks. Only
the SessionEnd hook ``seat-unlock.ps1`` unlocks it.

The properties pinned here each fail silently:

* **The lock lands in the admin directory, with the reason ``<seat> <session id>``.** The GC reads the
  file, not the session record.
* **Another holder's lock survives.** Claude Code locks an ``isolation: worktree`` agent's tree while it
  is live; replacing that reason would hand the tree back to Claude's own sweep.
* **Unlock removes only this session's lock**, never a foreign one, and never another session's.
* **The primary checkout is skipped cleanly**, since git refuses to lock it.

Everything runs in a throwaway repository with its own copies of the scripts, and a temp
USERPROFILE, so no real worktree, seat record or session registry is read or written.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 120
SID = "11111111-2222-3333-4444-555555555555"
OTHER_SID = "99999999-8888-7777-6666-555555555555"
COPIED = (
    "scripts/coord/seat.ps1",
    "scripts/coord/mail-key.ps1",
    "scripts/coord/coord-root.ps1",
    "scripts/coord/session-registry.ps1",
    "scripts/coord/occupancy.ps1",
    "scripts/worktree/seat-lock.ps1",
    "scripts/worktree/worktree-audit.ps1",
    "scripts/hooks/seat-unlock.ps1",
    "scripts/hooks/_hookinput.ps1",
)

pytestmark = [
    pytest.mark.skipif(
        shutil.which("pwsh") is None or os.name != "nt", reason="seat.ps1 needs pwsh on Windows"
    ),
    pytest.mark.timeout(300),
]


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


def env_for(home: Path, **extra: str) -> dict[str, str]:
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in {
            "CLAUDE_CODE_SESSION_ID",
            "CLAUDE_CODE_REMOTE",
            "MEFOR_COORD_ROOT",
            "KORUS_AGENT",
            "CLAUDE_CONFIG_DIR",
        }
    }
    # The session registry is read under USERPROFILE; an empty home holds none.
    env["USERPROFILE"] = str(home)
    env.update(extra)
    return env


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    return h


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    for rel in COPIED:
        dest = r / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dest)
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


@pytest.fixture
def wt(repo: Path, tmp_path: Path) -> Path:
    w = tmp_path / "wt-seat"
    git(repo, "worktree", "add", "-q", "-b", "seat-branch", str(w))
    return w


def admin_dir(w: Path) -> Path:
    return Path(git(w, "rev-parse", "--path-format=absolute", "--git-dir").strip())


def lock_text(w: Path) -> str | None:
    f = admin_dir(w) / "locked"
    return f.read_text(encoding="utf-8").strip() if f.is_file() else None


def seat(cwd: Path, home: Path, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(cwd / "scripts" / "coord" / "seat.ps1"),
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env_for(home, **extra),
    )


def arrive(
    w: Path, home: Path, sid: str = SID, source: str = "startup"
) -> subprocess.CompletedProcess[str]:
    """The SessionStart path: the only one that creates a lock. Silent by contract."""
    proc = seat(w, home, "-Prompt", "-SessionId", sid, "-Source", source)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "", "-Prompt is a hook path and must stay silent"
    return proc


def declare(
    w: Path, home: Path, sid: str = SID, *, arrive_first: bool = True
) -> subprocess.CompletedProcess[str]:
    """SessionStart then -Declare, as a real session runs them."""
    if arrive_first:
        arrive(w, home, sid)
    proc = seat(w, home, "-Declare", "-Seat", "builder", "-Goal", "g", "-SessionId", sid)
    assert proc.returncode == 0, proc.stderr
    return proc


def live_record(home: Path, sid: str) -> subprocess.Popen[bytes]:
    """A registry record for sid whose pid started just now: LIVE to the fence. Kill it after."""
    sessions = home / ".claude" / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(240)"])
    record = {"pid": sleeper.pid, "sessionId": sid, "startedAt": int(time.time() * 1000)}
    (sessions / "1.json").write_text(json.dumps(record), encoding="utf-8")
    return sleeper


def unlock_hook(
    w: Path, home: Path, sid: str, reason: str = "prompt_input_exit"
) -> subprocess.CompletedProcess[str]:
    payload = json.dumps(
        {"session_id": sid, "cwd": str(w), "hook_event_name": "SessionEnd", "reason": reason}
    )
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(w / "scripts" / "hooks" / "seat-unlock.ps1"),
        ],
        cwd=str(w),
        input=payload,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env_for(home),
    )


def test_a_declared_seats_worktree_carries_the_locked_file(wt: Path, home: Path) -> None:
    assert lock_text(wt) is None, "the fixture worktree must start unlocked"
    proc = declare(wt, home)
    assert lock_text(wt) == f"builder {SID}"
    assert "worktree lock: relabelled" in proc.stdout
    # git itself reads it as locked, which is what every reclaimer asks.
    listing = git(wt, "worktree", "list", "--porcelain")
    assert f"locked builder {SID}" in listing


def test_the_sessionstart_path_locks_before_any_declaration(wt: Path, home: Path) -> None:
    arrive(wt, home)
    assert lock_text(wt) == f"undeclared {SID}"
    # The declaration then relabels the same session's lock, with no moment unlocked.
    proc = declare(wt, home, arrive_first=False)
    assert "worktree lock: relabelled" in proc.stdout
    assert lock_text(wt) == f"builder {SID}"


def test_a_declaration_never_creates_a_lock(wt: Path, home: Path) -> None:
    """SessionStart and SessionEnd come from one settings file; -Declare can run where that file
    wires no SessionEnd. So a lock exists only where SessionStart made it."""
    proc = declare(wt, home, arrive_first=False)
    assert "worktree lock: not-locked" in proc.stdout, proc.stdout
    assert lock_text(wt) is None


def placed_record(home: Path, name: str, sid: str, pid: int, cwd: Path) -> None:
    """A registry record the occupancy fence places in cwd. No startedAt, so a running pid reads
    UNVERIFIED, which is a veto state: the fence treats it as possibly live."""
    sessions = home / ".claude" / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    record = {"pid": pid, "sessionId": sid, "cwd": str(cwd)}
    (sessions / f"{name}.json").write_text(json.dumps(record), encoding="utf-8")


@pytest.mark.parametrize("source", ["clear", "resume"])
def test_a_clear_or_resume_hands_the_lock_to_the_new_id(wt: Path, home: Path, source: str) -> None:
    """The old id's lock reads LIVE (the same process carries on), so neither a takeover nor any
    exit would release it. The SessionStart that follows hands it to the new id when no other
    session is in the tree. The old id's record carries this test's pid, an ancestor of the hook,
    as a real record carries the Claude process that runs the hook."""
    declare(wt, home)
    placed_record(home, "self", SID, os.getpid(), wt)
    unlock_hook(wt, home, SID, reason=source)
    assert lock_text(wt) == f"builder {SID}", "the old id's end must not unlock"
    arrive(wt, home, OTHER_SID, source=source)
    assert lock_text(wt) == f"builder {OTHER_SID}", "the seat label is kept across the handover"
    unlock_hook(wt, home, OTHER_SID)
    assert lock_text(wt) is None, "the new id's clean exit releases it"


def test_a_clear_beside_a_live_peer_in_the_tree_keeps_its_lock(wt: Path, home: Path) -> None:
    """Two sessions in one tree: the peer holds the lock and is live. A /clear in the other must
    not take it, or the newcomer's exit would unlock the tree under the peer."""
    declare(wt, home)
    sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(240)"])
    try:
        placed_record(home, "peer", SID, sleeper.pid, wt)
        arrive(wt, home, OTHER_SID, source="clear")
        assert lock_text(wt) == f"builder {SID}"
    finally:
        sleeper.kill()
        sleeper.wait()


def test_a_clear_keeps_the_lock_when_the_fence_cannot_look(wt: Path, home: Path) -> None:
    """No session registry at all: a live peer cannot be ruled out, so nothing is handed over."""
    declare(wt, home)
    assert not (home / ".claude" / "sessions").exists()
    arrive(wt, home, OTHER_SID, source="clear")
    assert lock_text(wt) == f"builder {SID}"


def test_a_startup_beside_a_live_seat_lock_keeps_it(wt: Path, home: Path) -> None:
    """The control for the handover: only clear, resume or compact hand a lock over."""
    declare(wt, home)
    sleeper = live_record(home, SID)
    try:
        arrive(wt, home, OTHER_SID, source="startup")
        assert lock_text(wt) == f"builder {SID}"
    finally:
        sleeper.kill()
        sleeper.wait()


def test_declaring_again_is_idempotent(wt: Path, home: Path) -> None:
    declare(wt, home)
    proc = declare(wt, home)
    assert "worktree lock: kept-own" in proc.stdout
    assert lock_text(wt) == f"builder {SID}"


def test_another_holders_lock_is_kept(wt: Path, home: Path, repo: Path) -> None:
    claude = "claude agent agent-abc (pid 4242)"
    git(repo, "worktree", "lock", "--reason", claude, str(wt))
    proc = declare(wt, home)
    assert "worktree lock: kept-foreign" in proc.stdout
    assert lock_text(wt) == claude
    # And a clean exit leaves it too.
    proc = unlock_hook(wt, home, SID)
    assert proc.returncode == 0, proc.stderr
    assert lock_text(wt) == claude


def test_a_live_seats_lock_is_kept_and_a_dead_ones_is_taken_over(
    wt: Path, home: Path, repo: Path
) -> None:
    held = f"manager {OTHER_SID}"
    git(repo, "worktree", "lock", "--reason", held, str(wt))
    sleeper = live_record(home, OTHER_SID)
    try:
        arrive(wt, home)
        assert lock_text(wt) == held
    finally:
        sleeper.kill()
        sleeper.wait()
    sessions = home / ".claude" / "sessions"

    # No record, but a registry file caught mid-write might be that seat's: still not gone.
    (sessions / "1.json").write_text("{", encoding="utf-8")
    arrive(wt, home)
    assert lock_text(wt) == held

    # No registry record at all: reported elsewhere, but not taken over, because a live seat in a
    # config root this reader cannot see reads the same way.
    (sessions / "1.json").unlink()
    arrive(wt, home)
    assert lock_text(wt) == held

    # A record missing startedAt must not throw under seat.ps1's StrictMode; its pid is not
    # running, which is a positive dead signal, so the arriving seat takes the lock over.
    dead = {"pid": 999999, "sessionId": OTHER_SID}
    (sessions / "1.json").write_text(json.dumps(dead), encoding="utf-8")
    arrive(wt, home)
    assert lock_text(wt) == f"undeclared {SID}"


def test_close_keeps_the_lock_and_a_stop_never_places_one(wt: Path, home: Path) -> None:
    """A closed seat is often still open, so -Close must not unlock. -Record (every Stop) runs the
    primary's copy through the user-scope shim, so it must not lock: a tree whose own branch has no
    unlock hook would never be unlocked."""
    declare(wt, home)
    proc = seat(wt, home, "-Close", "-SessionId", SID)
    assert proc.returncode == 0, proc.stderr
    assert lock_text(wt) == f"builder {SID}"
    git(wt, "worktree", "unlock", str(wt))
    proc = seat(wt, home, "-Record", "-SessionId", SID)
    assert proc.returncode == 0, proc.stderr
    assert lock_text(wt) is None


def test_the_sessionend_hook_follows_the_cwd_when_it_starts_in_the_primary(
    wt: Path, home: Path, repo: Path
) -> None:
    """Under the desktop app the hook starts in the primary; with no pin (a session since /clear)
    it must still find the worktree from the input's cwd."""
    declare(wt, home)
    payload = json.dumps(
        {"session_id": SID, "cwd": str(wt), "hook_event_name": "SessionEnd", "reason": "other"}
    )
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "hooks" / "seat-unlock.ps1"),
        ],
        cwd=str(repo),
        input=payload,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env_for(home),
    )
    assert proc.returncode == 0, proc.stderr
    assert lock_text(wt) is None


def test_the_sessionend_hook_skips_a_clear_and_a_resume(wt: Path, home: Path) -> None:
    declare(wt, home)
    for reason in ("clear", "resume"):
        proc = unlock_hook(wt, home, SID, reason=reason)
        assert proc.returncode == 0, proc.stderr
        assert lock_text(wt) == f"builder {SID}", f"reason={reason} ended no seat"
    proc = unlock_hook(wt, home, SID, reason="prompt_input_exit")
    assert lock_text(wt) is None, "control: a real exit unlocks"


def test_a_session_with_no_session_id_places_no_lock(wt: Path, home: Path) -> None:
    """Its lock could never be matched at exit or placed by the report, so it would be permanent."""
    proc = seat(wt, home, "-Declare", "-Seat", "builder", "-Goal", "g", "-SessionId", "sess-abc")
    assert "worktree lock: skipped-no-session-id" in proc.stdout
    assert lock_text(wt) is None


def test_the_sessionend_hook_unlocks_only_its_own_session(wt: Path, home: Path) -> None:
    declare(wt, home)
    proc = unlock_hook(wt, home, OTHER_SID)
    assert proc.returncode == 0 and proc.stdout == "", (proc.stdout, proc.stderr)
    assert lock_text(wt) == f"builder {SID}", "another session's exit must not unlock it"
    proc = unlock_hook(wt, home, SID)
    assert proc.returncode == 0 and proc.stdout == "", (proc.stdout, proc.stderr)
    assert lock_text(wt) is None


def test_the_primary_checkout_is_skipped_cleanly(repo: Path, home: Path) -> None:
    proc = declare(repo, home)
    assert "worktree lock: skipped-primary" in proc.stdout
    assert not (repo / ".git" / "locked").exists()


@pytest.mark.parametrize("agent", ["", "codex"])
def test_the_unlock_key_agrees_with_seat_ps1s_session_key(agent: str) -> None:
    """seat-unlock.ps1 derives the key with ConvertTo-SeatSessionKey; seat.ps1 locked with
    Get-SessionKey. If they drift, every clean exit reads kept-foreign and leaks its lock."""
    samples = [
        SID,
        "a b/c:d",
        "x" * 120,
        "ID-with.dots_and-dashes",
    ]
    probe = (
        f"$ast = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{ROOT / 'scripts' / 'coord' / 'seat.ps1'}', [ref]$null, [ref]$null); "
        "$fn = $ast.FindAll({ param($n) $n -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$n.Name -eq 'Get-SessionKey' }, $true) | Select-Object -First 1; "
        ". ([scriptblock]::Create($fn.Extent.Text)); "
        f". '{ROOT / 'scripts' / 'worktree' / 'worktree-audit.ps1'}'; "
        f"$env:KORUS_AGENT = '{agent}'; "
        "$out = foreach ($s in $input) { [pscustomobject]@{ a = (Get-SessionKey -Payload $null "
        "-Override $s).Key; b = ConvertTo-SeatSessionKey $s } }; "
        "ConvertTo-Json -InputObject @($out) -Compress"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", probe],
        input="\n".join(samples),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    )
    rows = json.loads(proc.stdout)
    assert len(rows) == len(samples), rows
    for row in rows:
        assert row["a"] == row["b"], row


def test_a_cloud_session_does_not_lock_or_error(wt: Path, home: Path) -> None:
    # -Declare refuses in the cloud before it gets here; -Prompt is the path a cloud VM can reach.
    proc = seat(wt, home, "-Prompt", "-SessionId", SID, CLAUDE_CODE_REMOTE="true")
    assert proc.returncode == 0, proc.stderr
    assert lock_text(wt) is None
