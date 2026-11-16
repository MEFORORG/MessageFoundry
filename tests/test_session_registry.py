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
        "'{0}|{1}|{2}' -f $r.Found, $r.State, $r.Detail"
    )
    found, state, detail = got.split("|", 2)
    assert (found, state) == ("False", "UNREADABLE")
    assert "99004.json" in detail, "the refusal must name the record an operator has to find"


def _anonymous(config_root: Path, name: str, record: dict[str, Any], age_h: float = 0) -> Path:
    """A registry record that names no session, its file last written ``age_h`` hours ago."""
    path = config_root / "sessions" / name
    path.write_text(json.dumps(record), encoding="utf-8")
    if age_h:
        then = time.time() - age_h * 3600
        os.utime(path, (then, then))
    return path


def test_an_old_record_naming_no_session_is_reported_but_does_not_veto(config_root: Path) -> None:
    """The twin of the veto: one that never gains its id must not block every clear for good. Its
    startedAt and its file are two days old, and it has no pid, so its fence is UNREADABLE."""
    _anonymous(config_root, "99007.json", {"startedAt": NOW_MS - 48 * 3600 * 1000}, age_h=48)
    got = liveness(config_root, "5491eeee")
    assert got["State"] == "UNKNOWN", got
    assert "99007.json" in got["Detail"], got


def test_an_old_startedat_on_a_freshly_written_file_still_vetoes(config_root: Path) -> None:
    """Age is the newer of startedAt and the file's last write: a rewrite seconds ago is fresh."""
    _anonymous(config_root, "99011.json", {"startedAt": NOW_MS - 48 * 3600 * 1000})
    assert liveness(config_root, "5491a1a1")["State"] == "UNREADABLE"


@pytest.mark.parametrize(("age_h", "state"), [(0, "UNREADABLE"), (48, "UNKNOWN")])
def test_a_future_startedat_is_ignored_and_the_file_age_decides(
    config_root: Path, age_h: float, state: str
) -> None:
    """A negative age is not fresh, or one future-dated record would veto until that date."""
    future = NOW_MS + 10 * 365 * 24 * 3600 * 1000
    _anonymous(config_root, "99012.json", {"startedAt": future}, age_h=age_h)
    assert liveness(config_root, "5491b2b2")["State"] == state


@pytest.mark.parametrize(
    ("record", "state"),
    [
        ({"pid": os.getpid(), "startedAt": NOW_MS}, "UNREADABLE"),
        ({"startedAt": NOW_MS}, "UNKNOWN"),
    ],
    ids=["live-vetoes-whatever-its-age", "unreadable-past-the-bound-does-not"],
)
def test_a_live_record_naming_no_session_vetoes_past_the_freshness_bound(
    config_root: Path, record: dict[str, Any], state: str
) -> None:
    """A LIVE one stops vetoing when its process exits, so the bound does not apply to it. A bound of
    zero hours makes every record old; only the LIVE one still vetoes."""
    _anonymous(config_root, "99013.json", record)
    got = _strict(
        f"(Get-SessionLiveness -SessionId '5491c3c3' -ConfigRoot '{config_root}' "
        "-AnonymousFreshHours 0).State"
    )
    assert got == state


@pytest.mark.parametrize(("age_h", "state"), [(0, "UNREADABLE"), (48, "UNKNOWN")])
def test_with_no_usable_startedat_the_file_age_decides(
    config_root: Path, age_h: float, state: str
) -> None:
    _anonymous(config_root, "99008.json", {"startedAt": "not-a-number"}, age_h=age_h)
    assert liveness(config_root, "5491ffff")["State"] == state


def test_no_anonymous_veto_leaves_a_gone_match_gone(config_root: Path) -> None:
    """For a caller that reports those records once itself, as fleet.ps1 does."""
    write_session(config_root, pid=never_live_pid(), session_id="5491abab-0000")
    _anonymous(config_root, "99009.json", {"pid": os.getpid(), "startedAt": NOW_MS})
    got = _strict(
        f"(Get-SessionLiveness -SessionId '5491abab' -ConfigRoot '{config_root}' -NoAnonymousVeto).State"
    )
    assert got == "DEAD"


def _fleet(
    tmp_path: Path, anonymous: dict[str, Any] | None, coord: Path | None = None
) -> tuple[dict[str, Any], Path, Path]:
    """Run fleet.ps1 -Json over one seat whose own registry record is DEAD, beside an optional
    registry record that names no session. Returns the JSON, the repo and the anonymous file."""
    home = tmp_path / "home"
    root = home / ".claude"
    (root / "sessions").mkdir(parents=True)
    write_session(root, pid=never_live_pid(), session_id="5491dead-0000-0000-0000-000000000000")
    repo = tmp_path / "repo"
    anon = root / "sessions" / "99010.json"
    if anonymous is not None:
        anon.write_text(json.dumps({"cwd": str(repo), **anonymous}), encoding="utf-8")

    repo.mkdir()
    for args in (
        ["init", "-q", "-b", "main"],
        ["-c", "user.email=t@e.invalid", "-c", "user.name=t", "commit", "-q", "--allow-empty"]
        + ["-m", "base"],
    ):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    shared = tmp_path / "shared"
    seat_dir = shared / "seats" / "box-5491"
    seat_dir.mkdir(parents=True)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    seat = {
        "schema": 1,
        "asOf": stamp,
        "lifecycle": "open",
        "boxKey": "box-5491",
        "worktree": str(repo / "absent"),
        "sessionId": "5491dead-0000-0000-0000-000000000000",
        "sessionKey": "5491dead",
        "seat": "builder",
        "branch": "b",
        "claims": [],
        "allocations": [],
        "handoff": None,
    }
    (seat_dir / "5491dead.json").write_text(json.dumps(seat), encoding="utf-8")

    env = {
        k: v
        for k, v in os.environ.items()
        if k.upper() not in {"USERPROFILE", "MEFOR_COORD_ROOT", "CLAUDE_CODE_SESSION_ID"}
    }
    env.update(USERPROFILE=str(home), MEFOR_COORD_ROOT=str(shared))
    fleet = (coord or REGISTRY.parent) / "fleet.ps1"
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(fleet), "-Json"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env=env,
    )
    assert proc.returncode in (0, 2), proc.stderr
    j: dict[str, Any] = json.loads(proc.stdout)
    return j, repo, anon


def _anonymous_stops(j: dict[str, Any]) -> list[str]:
    return [s for s in j["receipt"]["stopConditions"] if s.startswith("anonymousLiveRecords=")]


def test_fleet_reports_an_anonymous_record_once_and_keeps_each_seats_own_verdict(
    tmp_path: Path,
) -> None:
    """A live record naming no session must not mark every gone seat POSSIBLY RUNNING. It is one
    stop condition instead, so no seat is offered for respawn while it exists, and it counts as a
    live session in the repo without reading as a seat writer that failed."""
    j, _, anon = _fleet(tmp_path, {"pid": os.getpid(), "startedAt": NOW_MS})
    rows = {r["Box"]: r for r in j["rows"]}
    assert rows["box-5491"]["Fence"] == "DEAD", rows["box-5491"]
    receipt = j["receipt"]
    assert receipt["anonymousLiveRecords"] == 1, receipt
    assert str(anon) in receipt["anonymousLiveRecordFiles"]
    stops = _anonymous_stops(j)
    assert len(stops) == 1 and str(anon) in stops[0] and "respawn" in stops[0], stops
    assert receipt["liveSessionsInRepo"] == 1, receipt
    assert receipt["liveSessionsWithoutRecord"] == 0, receipt


def test_fleet_fires_no_anonymous_stop_without_such_a_record(tmp_path: Path) -> None:
    """The twin: with only the seat's own DEAD record, no anonymous stop and a zero count."""
    j, _, _ = _fleet(tmp_path, None)
    assert j["receipt"]["anonymousLiveRecords"] == 0, j["receipt"]
    assert _anonymous_stops(j) == []


def test_fleet_names_a_failed_anonymous_scan_as_a_stop_not_a_count(tmp_path: Path) -> None:
    """An instrument that failed must not read as one stray record. The scan is made to throw in a
    copy of the scripts, so the real ones are untouched."""
    coord = tmp_path / "coord"
    coord.mkdir()
    for name in ("fleet.ps1", "mail-key.ps1", "coord-root.ps1"):
        shutil.copy2(REGISTRY.parent / name, coord / name)
    broken = REGISTRY.read_text(encoding="utf-8") + (
        "\nfunction Get-AnonymousSessionRecords { throw 'scan-broke-5491' }\n"
    )
    (coord / "session-registry.ps1").write_text(broken, encoding="utf-8")
    j, _, _ = _fleet(tmp_path, None, coord=coord)
    assert j["receipt"]["anonymousLiveRecords"] is None, j["receipt"]
    stops = _anonymous_stops(j)
    assert len(stops) == 1 and "scan-broke-5491" in stops[0], stops


@pytest.mark.parametrize(
    ("pid", "refused"), [("not-a-number", True), (None, False)], ids=["unreadable", "dead"]
)
def test_sessions_rehome_refuses_an_unreadable_fence(
    tmp_path: Path, pid: str | None, refused: bool
) -> None:
    """sessions.ps1 moves a transcript, so an UNREADABLE fence must stop it. A non-numeric pid used
    to throw in the fence, which stopped the move; reading UNREADABLE must stop it the same way. The
    twin, a DEAD record, passes the guard and finds the transcript already filed."""
    repo = tmp_path / "repo"
    (repo / "scripts" / "worktree").mkdir(parents=True)
    (repo / "scripts" / "coord").mkdir(parents=True)
    shutil.copy2(REGISTRY.parents[1] / "worktree" / "sessions.ps1", repo / "scripts" / "worktree")
    shutil.copy2(REGISTRY, repo / "scripts" / "coord")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, capture_output=True)
    primary = (
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "list", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        )
        .stdout.splitlines()[0]
        .removeprefix("worktree ")
        .replace("/", "\\")
    )
    home = tmp_path / "home"
    root = home / ".claude"
    sid = "5491eeee-1111-2222-3333-444444444444"
    slug = "".join(c if c.isalnum() else "-" for c in primary)
    transcript = root / "projects" / slug / f"{sid}.jsonl"
    transcript.parent.mkdir(parents=True)
    transcript.write_text(json.dumps({"type": "user", "cwd": primary}) + "\n", encoding="utf-8")
    old = time.time() - 3600
    os.utime(transcript, (old, old))
    (root / "sessions").mkdir()
    (root / "sessions" / "1.json").write_text(
        json.dumps(
            {"pid": pid if pid else never_live_pid(), "sessionId": sid, "startedAt": NOW_MS}
        ),
        encoding="utf-8",
    )
    env = {k: v for k, v in os.environ.items() if k.upper() not in {"USERPROFILE"}}
    env["USERPROFILE"] = str(home)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File"]
        + [str(repo / "scripts" / "worktree" / "sessions.ps1"), "-Rehome", sid[:8]],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env=env,
    )
    if refused:
        assert proc.returncode != 0 and "UNREADABLE" in proc.stderr, proc.stdout + proc.stderr
    else:
        assert proc.returncode == 0 and "already filed" in proc.stdout, proc.stdout + proc.stderr
    assert transcript.exists()


def test_a_gone_match_beside_a_live_record_naming_no_session_is_unreadable(
    config_root: Path,
) -> None:
    """The matched record reads DEAD, but the anonymous live one may be the same session, caught
    mid-write after a relaunch, so the answer must not license a clear."""
    write_session(config_root, pid=never_live_pid(), session_id="5491cccc-0000")
    (config_root / "sessions" / "99005.json").write_text(
        json.dumps({"pid": os.getpid(), "startedAt": NOW_MS}), encoding="utf-8"
    )
    assert liveness(config_root, "5491cccc")["State"] == "UNREADABLE"


def test_a_dead_record_naming_no_session_does_not_veto(config_root: Path) -> None:
    """A record whose own fence reads DEAD cannot be a live session, so it leaves a miss clean."""
    (config_root / "sessions" / "99006.json").write_text(
        json.dumps({"pid": never_live_pid(), "startedAt": NOW_MS}), encoding="utf-8"
    )
    assert liveness(config_root, "5491dddd")["State"] == "UNKNOWN"


def test_a_far_future_startedat_is_unverified_not_stale_or_a_throw_under_strict_mode() -> None:
    """No session registers in the future, so the start is unusable: UNVERIFIED, which every caller
    treats as possibly live. The cast this replaced threw, which stopped them all; STALE would not."""
    record = {"pid": os.getpid(), "sessionId": "s", "startedAt": 200_000_000_000_000}
    assert _strict_fence(record) == "UNVERIFIED"


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
