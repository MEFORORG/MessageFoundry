# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the shared session-liveness fence (``scripts/coord/session-registry.ps1``).

This module exists so ``presence.ps1`` (a read-only roster) and ``sessions.ps1`` (which MOVES a
transcript) give the SAME answer to "is this session alive". Two copies of a safety check drift, and
the copy that drifts is the one nobody is testing.

The contract these tests pin, in order of how much damage getting it wrong causes:

1. **A live session is reported LIVE even when nothing has written its transcript for hours.**
   Transcript mtime is not liveness -- subagent and workflow output is filed under
   ``<sessionId>/subagents/`` -- and ``sessions.ps1`` used mtime alone to decide whether it was safe
   to move a transcript out from under a running writer.
2. **A recycled pid is not LIVE.** The fence compares process start time against the recorded session
   start; without it this is a bare pid check and a reused pid reads as alive.
3. **"Not registered" is UNKNOWN, never "dead".** A cleanly-exited session and a never-registered one
   are indistinguishable here, so the answer must not license a destructive action by itself.
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

from tests._dead_pid import never_live_pid

REGISTRY = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "session-registry.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="session-registry.ps1 needs pwsh on Windows (Process.StartTime)",
)

NOW_MS = int(time.time() * 1000)


@pytest.fixture
def config_root(tmp_path: Path) -> Path:
    root = tmp_path / ".claude"
    (root / "sessions").mkdir(parents=True)
    return root


def write_session(
    config_root: Path, *, pid: int, session_id: str, started_at: int | None = None, **extra: Any
) -> None:
    rec = {
        "pid": pid,
        "sessionId": session_id,
        "cwd": str(config_root),
        "startedAt": NOW_MS if started_at is None else started_at,
        "kind": "interactive",
        "entrypoint": "claude-desktop",
        **extra,
    }
    (config_root / "sessions" / f"{pid}.json").write_text(json.dumps(rec), encoding="utf-8")


def liveness(config_root: Path, session_id: str) -> dict[str, Any]:
    """Call the real Get-SessionLiveness and return its result as a dict."""
    script = (
        f". '{REGISTRY}'; "
        f"$r = Get-SessionLiveness -SessionId '{session_id}' -ConfigRoot '{config_root}'; "
        f"[pscustomobject]@{{Found=$r.Found;State=$r.State;Detail=$r.Detail}} | ConvertTo-Json -Compress"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    parsed: dict[str, Any] = json.loads(proc.stdout.strip())
    return parsed


def test_live_session_is_live_regardless_of_any_transcript_activity(config_root: Path) -> None:
    """THE case that motivated this module.

    On this host a verifiably-live session was measured 32 minutes idle by transcript mtime, because
    its workflow output went to a subagent directory. ``sessions.ps1`` would have moved its transcript
    out from under it. The registry fence must say LIVE with no reference to file activity at all.
    """
    write_session(config_root, pid=os.getpid(), session_id="aaaaaaaa-1111")
    got = liveness(config_root, "aaaaaaaa")
    assert got["Found"] is True
    assert got["State"] == "LIVE"


def test_recycled_pid_is_not_live(config_root: Path) -> None:
    """A real running pid recorded against a much older session start = a reused pid."""
    write_session(
        config_root,
        pid=os.getpid(),
        session_id="bbbbbbbb-2222",
        started_at=NOW_MS - (48 * 60 * 60 * 1000),
    )
    got = liveness(config_root, "bbbbbbbb")
    assert got["State"] == "STALE"
    assert "reused" in got["Detail"]


def test_dead_pid_is_dead(config_root: Path) -> None:
    write_session(config_root, pid=never_live_pid(), session_id="cccccccc-3333")
    assert liveness(config_root, "cccccccc")["State"] == "DEAD"


def test_unregistered_session_is_unknown_not_dead(config_root: Path) -> None:
    """A cleanly-exited session leaves no record -- and neither does one that never registered.

    Reporting that as "dead" would let a caller destroy a live session's state on an absence.
    """
    got = liveness(config_root, "dddddddd")
    assert got["Found"] is False
    assert got["State"] == "UNKNOWN"
    assert got["State"] != "DEAD"


def test_record_without_startedat_is_unverified_not_live(config_root: Path) -> None:
    """The fence cannot be evaluated, so it has not been passed. Must not upgrade to LIVE."""
    rec = {
        "pid": os.getpid(),
        "sessionId": "eeeeeeee-5555",
        "cwd": str(config_root),
        "kind": "interactive",
        "entrypoint": "claude-vscode",
    }
    (config_root / "sessions" / "99001.json").write_text(json.dumps(rec), encoding="utf-8")
    got = liveness(config_root, "eeeeeeee")
    assert got["State"] == "UNVERIFIED"


def test_vscode_sessions_are_visible_to_the_fence(config_root: Path) -> None:
    """The registry is the only source that has them; the Desktop app's tooling does not."""
    write_session(
        config_root, pid=os.getpid(), session_id="ffffffff-6666", entrypoint="claude-vscode"
    )
    assert liveness(config_root, "ffffffff")["State"] == "LIVE"


def test_malformed_record_does_not_break_the_lookup(config_root: Path) -> None:
    (config_root / "sessions" / "99002.json").write_text("{not json", encoding="utf-8")
    write_session(config_root, pid=os.getpid(), session_id="99999999-7777")
    assert liveness(config_root, "99999999")["State"] == "LIVE"


def test_prefix_match_reports_the_most_alive_candidate(config_root: Path) -> None:
    """Deciding whether it is safe to disturb something: an ambiguous prefix must not resolve to the
    dead one and green-light the move."""
    write_session(config_root, pid=never_live_pid(), session_id="7777abcd-8888")
    write_session(config_root, pid=os.getpid(), session_id="7777efgh-9999")
    assert liveness(config_root, "7777")["State"] == "LIVE"


# --------------------------------------------------------------------------------------------------
# Test-ScheduledTaskSession: the registry cannot tell a scheduled-task run from a person's session,
# so the function reads the transcript's first line instead.
# --------------------------------------------------------------------------------------------------

SCHEDULED_FIRST_LINE = {
    "type": "queue-operation",
    "operation": "enqueue",
    "content": '<scheduled-task name="board-refresh" file="x/SKILL.md">\nThis is an automated run.',
}
PERSON_FIRST_LINE = {"type": "queue-operation", "operation": "enqueue", "content": "/seat Lander"}


def write_transcript(
    config_root: Path, project: str, session_id: str, first: dict[str, Any]
) -> None:
    d = config_root / "projects" / project
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{session_id}.jsonl").write_text(json.dumps(first) + "\n{}\n", encoding="utf-8")


def scheduled(config_root: Path, session_id: str) -> bool:
    script = (
        f". '{REGISTRY}'; "
        f"if (Test-ScheduledTaskSession -Root '{config_root}' -SessionId '{session_id}') "
        "{ 'YES' } else { 'NO' }"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip() == "YES"


def test_a_scheduled_run_is_recognised_from_its_transcript(config_root: Path) -> None:
    # A project directory name that encodes no particular cwd: the lookup must not depend on one.
    write_transcript(config_root, "c--anywhere", "aaaaaaaa-1111", SCHEDULED_FIRST_LINE)
    assert scheduled(config_root, "aaaaaaaa-1111") is True


def test_a_persons_session_is_not_scheduled(config_root: Path) -> None:
    write_transcript(config_root, "D--repo", "bbbbbbbb-1111", PERSON_FIRST_LINE)
    assert scheduled(config_root, "bbbbbbbb-1111") is False


def test_a_missing_or_broken_transcript_is_not_scheduled(config_root: Path) -> None:
    """Fails toward 'a person's session', which is what every caller assumed before."""
    assert scheduled(config_root, "cccccccc-1111") is False
    d = config_root / "projects" / "D--repo"
    d.mkdir(parents=True)
    (d / "dddddddd-1111.jsonl").write_text("not json\n", encoding="utf-8")
    assert scheduled(config_root, "dddddddd-1111") is False


def test_a_hostile_session_id_is_refused(config_root: Path) -> None:
    write_transcript(config_root, "D--repo", "eeeeeeee-1111", SCHEDULED_FIRST_LINE)
    assert scheduled(config_root, r"..\D--repo\eeeeeeee-1111") is False


def test_a_scheduled_prompt_written_as_a_user_record_is_recognised(config_root: Path) -> None:
    """A runner that skips the queue entry must not silently turn the flag off."""
    first = {"type": "user", "message": {"role": "user", "content": '<scheduled-task name="t">'}}
    write_transcript(config_root, "D--repo", "ffffffff-1111", first)
    assert scheduled(config_root, "ffffffff-1111") is True


def _roots_and_records(home: str | None, cwd: Path | None = None) -> dict[str, Any]:
    """Get-ClaudeConfigRoots and Get-SessionRecords with USERPROFILE set to ``home``, or unset.

    Any error the reads write fails the call: pwsh -Command exits 0 when only its last statement
    succeeds, so a throw inside a read would otherwise go unseen."""
    env = {
        k: v for k, v in os.environ.items() if k.upper() not in {"USERPROFILE", "CLAUDE_CONFIG_DIR"}
    }
    if home is not None:
        env["USERPROFILE"] = home
    script = (
        f". '{REGISTRY}'; "
        "$roots = @(Get-ClaudeConfigRoots | ForEach-Object { Split-Path $_ -Leaf }); "
        "$recs = @(Get-SessionRecords -IncludeUnreadable | "
        "ForEach-Object { if ($_.Unreadable) { 'unreadable:' + (Split-Path $_.File -Leaf) } "
        "else { [string]$_.Record.sessionId } }); "
        "[pscustomobject]@{ Roots = $roots; Records = $recs } | ConvertTo-Json -Compress"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=env,
        cwd=cwd,
    )
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    parsed: dict[str, Any] = json.loads(proc.stdout.strip())
    return parsed


def test_every_root_and_record_under_the_profile_is_read_by_its_own_name(tmp_path: Path) -> None:
    """Vault BACKLOG #2985. The reads took paths as wildcard patterns and skipped hidden records: a
    root named .claude[1] was dropped, [1].json read as 1.json, and a hidden record was not listed.
    Every one is read now, each by its own name."""
    home = tmp_path / "home[1]"
    for leaf, sid in ((".claude", "plain"), (".claude[1]", "in-bracketed-root")):
        (home / leaf / "sessions").mkdir(parents=True)
        write_session(home / leaf, pid=1, session_id=sid)
    sessions = home / ".claude" / "sessions"
    (sessions / "[1].json").write_text(json.dumps({"sessionId": "bracketed-name"}), "utf-8")
    hidden = sessions / "2.json"
    hidden.write_text(json.dumps({"sessionId": "hidden"}), encoding="utf-8")
    subprocess.run(["attrib", "+h", "+s", str(hidden)], check=True, capture_output=True)
    # A directory named as a record, hidden or not, is listed and reads as unreadable.
    for name in ("dir.json", "hidden-dir.json"):
        (sessions / name).mkdir()
    subprocess.run(["attrib", "+h", str(sessions / "hidden-dir.json")], check=True)

    got = _roots_and_records(str(home))
    assert sorted(got["Roots"]) == [".claude", ".claude[1]"], got
    assert sorted(got["Records"]) == sorted(
        [
            "plain",
            "bracketed-name",
            "hidden",
            "in-bracketed-root",
            "unreadable:dir.json",
            "unreadable:hidden-dir.json",
        ]
    ), got


def test_an_unset_profile_names_no_config_root(tmp_path: Path) -> None:
    """With no USERPROFILE there is no root to read, and the reads return empty. A -LiteralPath read
    of a null path throws, and the -Path read before it listed the current directory, so the run
    stands in a directory holding a registry: 0a7ccdca1c read that registry as a root."""
    in_cwd = tmp_path / ".claude"
    (in_cwd / "sessions").mkdir(parents=True)
    write_session(in_cwd, pid=1, session_id="in-the-cwd")
    assert _roots_and_records(None, cwd=tmp_path) == {"Roots": [], "Records": []}


# --------------------------------------------------------------------------------------------------
# BACKLOG #5491: the fence must answer, not throw, under Set-StrictMode -Version Latest. seat.ps1 and
# fleet.ps1 both set it, and it reaches these functions through the caller's scope. A record missing a
# property is exactly what a registry file caught mid-write looks like.
# --------------------------------------------------------------------------------------------------


def _strict(script: str) -> str:
    """Run ``script`` after dot-sourcing the registry under StrictMode Latest; return its stdout."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f". '{REGISTRY}'; Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'; "
            + script,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
    return proc.stdout.strip()


def _strict_fence(record: dict[str, Any]) -> str:
    """Test-RecordLiveness's State for ``record``, parsed from JSON as a real record is."""
    payload = json.dumps(record).replace("'", "''")
    return _strict(f"(Test-RecordLiveness -Record ('{payload}' | ConvertFrom-Json)).State")


@pytest.mark.parametrize(
    "record",
    [
        {"sessionId": "s", "startedAt": NOW_MS},
        {"pid": "not-a-number", "sessionId": "s", "startedAt": NOW_MS},
        {"pid": 2**40, "sessionId": "s", "startedAt": NOW_MS},
    ],
    ids=["no-pid-key", "non-numeric-pid", "pid-past-int32"],
)
def test_a_record_whose_pid_cannot_be_read_is_unreadable_under_strict_mode(
    record: dict[str, Any],
) -> None:
    """The header's contract: no pid, or one that is not a number, is UNREADABLE -- possibly live."""
    assert _strict_fence(record) == "UNREADABLE"


@pytest.mark.parametrize(
    "extra",
    [{}, {"startedAt": "not-a-number"}, {"startedAt": 2**62}],
    ids=["no-startedat-key", "non-numeric-startedat", "startedat-out-of-range"],
)
def test_a_live_pid_whose_start_cannot_be_read_is_unverified_under_strict_mode(
    extra: dict[str, Any],
) -> None:
    """The fence could not be evaluated, so it is not passed, and it must not throw either."""
    assert _strict_fence({"pid": os.getpid(), "sessionId": "s", **extra}) == "UNVERIFIED"


def test_a_live_record_is_still_live_under_strict_mode() -> None:
    """Control: the guarded reads still pass a record that carries every field, a fractional
    startedAt included, which the cast this replaced rounded."""
    assert _strict_fence({"pid": os.getpid(), "sessionId": "s", "startedAt": NOW_MS}) == "LIVE"
    assert _strict_fence({"pid": os.getpid(), "sessionId": "s", "startedAt": NOW_MS + 0.5}) == (
        "LIVE"
    )


def test_a_hashtable_record_is_still_fenced_under_strict_mode() -> None:
    """A dictionary record's keys are read too, as a bare property read of one did."""
    got = _strict(f"(Test-RecordLiveness -Record @{{ pid = $PID; startedAt = {NOW_MS} }}).State")
    assert got in {"LIVE", "STALE"}, got


def test_a_miss_beside_a_record_naming_no_session_is_not_a_clean_miss(config_root: Path) -> None:
    """That record may be the session asked about, caught mid-write, so the miss reads UNREADABLE.
    Under seat.ps1's StrictMode it used to throw, and seat.ps1 refused the clear on the throw."""
    (config_root / "sessions" / "99004.json").write_text(
        json.dumps({"pid": os.getpid(), "startedAt": NOW_MS}), encoding="utf-8"
    )
    got = _strict(
        f"$r = Get-SessionLiveness -SessionId 'abcdabcd' -ConfigRoot '{config_root}'; "
        "'{0}|{1}' -f $r.Found, $r.State"
    )
    assert got == "False|UNREADABLE"


def test_a_record_with_no_session_id_does_not_break_a_lookup_under_strict_mode(
    config_root: Path,
) -> None:
    """One sessionId-less record in the registry must not throw every lookup, or a caller that
    catches the throw reports the session it asked about as unknown."""
    (config_root / "sessions" / "99003.json").write_text(
        json.dumps({"pid": os.getpid(), "startedAt": NOW_MS}), encoding="utf-8"
    )
    write_session(config_root, pid=os.getpid(), session_id="5491aaaa-0000")
    got = _strict(
        f"$r = Get-SessionLiveness -SessionId '5491aaaa' -ConfigRoot '{config_root}'; "
        f"$l = Get-LoginForSession -SessionId '5491aaaa-0000' -ConfigRoot '{config_root}'; "
        "'{0}|{1}' -f $r.State, $l.Matched"
    )
    assert got == "LIVE|1"
