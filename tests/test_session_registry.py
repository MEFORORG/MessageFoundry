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
from collections.abc import Callable
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


@pytest.mark.parametrize(
    ("anon_cwd", "state"),
    [
        ("here", "UNREADABLE"),
        ("here-sub", "UNREADABLE"),
        ("elsewhere", "DEAD"),
        (None, "UNREADABLE"),
        ("parent", "UNREADABLE"),
        ("plain-parent", "DEAD"),
        ("long-path-prefix", "UNREADABLE"),
        ("dot-dot-out-of-tree", "UNREADABLE"),
        ("relative", "UNREADABLE"),
        ("sibling-prefix", "DEAD"),
        ("drive-root", "DEAD"),
    ],
    ids=[
        "same-worktree",
        "inside-worktree",
        "other-worktree",
        "no-cwd-fails-closed",
        "checkout-holding-the-worktree",
        "plain-parent-does-not-reach",
        "long-path-prefix",
        "dot-dot-out-of-the-tree-still-vetoes",
        "relative-cwd-fails-closed",
        "sibling-sharing-a-prefix",
        "drive-root-does-not-reach",
    ],
)
def test_the_anonymous_veto_reaches_only_the_worktree_it_names(
    config_root: Path, tmp_path: Path, anon_cwd: str | None, state: str
) -> None:
    """A record naming no session vetoes a lookup for its own tree, case, slashes and a \\\\?\\
    prefix aside, and one for a tree under a git checkout it sits in, as a primary checkout holds
    its worktrees. A cwd spelled ``<tree>\\..\\<other>`` is not collapsed, so it still vetoes
    ``<tree>`` as it did on main. A plain parent directory does not reach, nor does another tree,
    even one whose name starts with this one's. One with no readable cwd, or a relative one, cannot
    be placed, so it vetoes everywhere."""
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    here = checkout / "wt-here"
    cwds = {
        "here": str(here).upper().replace("\\", "/") + "/",
        "here-sub": str(here / "sub"),
        "elsewhere": str(tmp_path / "wt-elsewhere"),
        "parent": str(checkout),
        "plain-parent": str(tmp_path),
        "long-path-prefix": "\\\\?\\" + str(here),
        "dot-dot-out-of-tree": str(here / ".." / "wt-elsewhere"),
        "relative": "wt-elsewhere",
        "sibling-prefix": str(checkout / "wt-here-too"),
        "drive-root": tmp_path.anchor,
    }
    write_session(config_root, pid=never_live_pid(), session_id="5491abab-0000")
    record: dict[str, Any] = {"pid": os.getpid(), "startedAt": NOW_MS}
    if anon_cwd is not None:
        record["cwd"] = cwds[anon_cwd]
    _anonymous(config_root, "99009.json", record)
    got = _strict(
        f"(Get-SessionLiveness -SessionId '5491abab' -ConfigRoot '{config_root}' "
        f"-Worktree '{here}').State"
    )
    assert got == state


@pytest.mark.parametrize(
    ("hours_ahead", "state"), [(0, "UNREADABLE"), (48, "UNKNOWN"), (-1, "UNREADABLE")]
)
def test_a_callers_now_ages_the_anonymous_records(
    config_root: Path, tmp_path: Path, hours_ahead: int, state: str
) -> None:
    """box-activity.ps1 passes its own -Now. A fresh record naming no session vetoes at the real
    time and has aged out 48 hours later, by the caller's clock rather than the wall clock. A
    nullable -Now read through .Value threw here under StrictMode. A record written after a clock
    taken an hour ago is the freshest kind: it used to read as future-dated and drop out."""
    wt = tmp_path / "wt-now"
    _anonymous(config_root, "99017.json", {"startedAt": NOW_MS, "cwd": str(wt)})
    got = _strict(
        f"(Get-SessionLiveness -SessionId '5491e5e5' -ConfigRoot '{config_root}' "
        f"-Worktree '{wt}' -Now ([DateTime]::UtcNow.AddHours({hours_ahead}))).State"
    )
    assert got == state


def test_a_local_kind_now_ages_a_record_as_the_same_instant_in_utc(config_root: Path) -> None:
    """A Local-kind -Now was subtracted from UTC times as if it were UTC, so every age moved by the
    local offset, and on a box ahead of UTC a fresh record aged out. The same instant now ages a
    record alike in either kind. On 352502253e the two ages differed by the offset (on a box whose
    offset is not zero)."""
    started = NOW_MS - 20 * 3600 * 1000
    _anonymous(config_root, "99018.json", {"startedAt": started, "cwd": "C:\\x"}, age_h=20)
    got = _strict(
        f"$rows = @(Get-SessionRecords -ConfigRoot '{config_root}'); $u = [DateTime]::UtcNow; "
        "$a = @(Get-AnonymousSessionRecords -Records $rows -Now $u); "
        "$b = @(Get-AnonymousSessionRecords -Records $rows -Now $u.ToLocalTime()); "
        "'{0:F2}|{1:F2}|{2}' -f $a[0].AgeHours, $b[0].AgeHours, $b[0].Fresh"
    )
    utc_age, local_age, fresh = got.split("|")
    assert abs(float(utc_age) - 20) < 0.1, got
    assert local_age == utc_age, got
    assert fresh == "True", got


def test_a_vanished_record_file_ages_zero_whatever_its_startedat() -> None:
    """A file gone between the listing and the read is the shape of one being replaced right now,
    so it is fresh even with a two-day-old startedAt."""
    got = _strict(
        '$row = [pscustomobject]@{ Record = (\'{"startedAt": '
        f"{NOW_MS - 48 * 3600 * 1000}"
        "}' | ConvertFrom-Json); File = (Join-Path $env:TEMP 'mefor-5491-vanished-9f3a.json') }; "
        "$a = @(Get-AnonymousSessionRecords -Records @($row)); '{0}|{1}' -f $a.Count, $a[0].Fresh"
    )
    assert got == "1|True"


def _fleet(
    tmp_path: Path,
    anonymous: dict[str, Any] | None,
    coord: Path | None = None,
    anon_in_seat_worktree: bool = True,
    raw_records: dict[str, str] | None = None,
    extra_seats: dict[str, str] | None = None,
    fleet_args: list[str] | None = None,
    prepare: Callable[[Path], None] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run fleet.ps1 -Json over one seat whose own registry record is DEAD, beside an optional
    registry record that names no session. The record's cwd is the seat's worktree, or another
    directory, unless ``anonymous`` sets its own. Both sit inside the primary checkout, which is a
    worktree of this repo, so a live record in either counts in the denominator. ``raw_records`` maps more registry file names to
    their exact text, and ``extra_seats`` more seat boxes to the exact text of one seat record in
    each. ``fleet_args`` replaces ``-Json``. ``prepare`` gets the repo after its first commit.
    Returns the run and the anonymous record's path."""
    home = tmp_path / "home"
    root = home / ".claude"
    (root / "sessions").mkdir(parents=True)
    write_session(root, pid=never_live_pid(), session_id="5491dead-0000-0000-0000-000000000000")
    for name, text in (raw_records or {}).items():
        (root / "sessions" / name).write_text(text, encoding="utf-8")
    repo = tmp_path / "repo"
    seat_wt = repo / "seat-worktree"
    anon = root / "sessions" / "99010.json"
    if anonymous is not None:
        cwd = str(seat_wt) if anon_in_seat_worktree else str(repo / "other-worktree")
        anon.write_text(json.dumps({"cwd": cwd, **anonymous}), encoding="utf-8")

    repo.mkdir()
    for args in (
        ["init", "-q", "-b", "main"],
        ["-c", "user.email=t@e.invalid", "-c", "user.name=t", "commit", "-q", "--allow-empty"]
        + ["-m", "base"],
    ):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    if prepare is not None:
        prepare(repo)
    shared = tmp_path / "shared"
    seat_dir = shared / "seats" / "box-5491"
    seat_dir.mkdir(parents=True)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    seat = {
        "schema": 1,
        "asOf": stamp,
        "lifecycle": "open",
        "boxKey": "box-5491",
        "worktree": str(seat_wt),
        "sessionId": "5491dead-0000-0000-0000-000000000000",
        "sessionKey": "5491dead",
        "seat": "builder",
        "branch": "b",
        "claims": [],
        "allocations": [],
        "handoff": None,
    }
    (seat_dir / "5491dead.json").write_text(json.dumps(seat), encoding="utf-8")
    for box, text in (extra_seats or {}).items():
        (shared / "seats" / box).mkdir()
        (shared / "seats" / box / "seat.json").write_text(text, encoding="utf-8")

    env = {
        k: v
        for k, v in os.environ.items()
        if k.upper() not in {"USERPROFILE", "MEFOR_COORD_ROOT", "CLAUDE_CODE_SESSION_ID"}
    }
    env.update(USERPROFILE=str(home), MEFOR_COORD_ROOT=str(shared))
    fleet = (coord or REGISTRY.parent) / "fleet.ps1"
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(fleet), *(fleet_args or ["-Json"])],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env=env,
    )
    return proc, anon


def _fleet_json(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert proc.returncode in (0, 2), proc.stderr
    j: dict[str, Any] = json.loads(proc.stdout)
    return j


def test_fleet_reads_a_seat_with_an_anonymous_record_in_its_worktree_as_possibly_running(
    tmp_path: Path,
) -> None:
    """The record may be this seat relaunched, so the seat must not read INTERRUPTED, which -Chip and
    respawn.ps1 treat as respawnable, and the receipt names it. The seat's worktree is not a
    registered git worktree here, but it sits inside the primary checkout, so the record counts in
    the denominator too; the denominator tests below assert that count."""
    proc, anon = _fleet(tmp_path, {"pid": os.getpid(), "startedAt": NOW_MS})
    j = _fleet_json(proc)
    row = {r["Box"]: r for r in j["rows"]}["box-5491"]
    assert row["State"] == "POSSIBLY RUNNING", row
    receipt = j["receipt"]
    assert receipt["anonymousLiveRecords"] == 1, receipt
    assert str(anon) in receipt["anonymousLiveRecordFiles"]


def test_fleet_leaves_a_seat_alone_when_the_anonymous_record_is_in_another_worktree(
    tmp_path: Path,
) -> None:
    """The twin: a record in another directory is not this seat, so the seat keeps its own
    verdict. That directory is inside the primary checkout, so the record still counts in the
    denominator; that is not what this asserts."""
    proc, _ = _fleet(
        tmp_path, {"pid": os.getpid(), "startedAt": NOW_MS}, anon_in_seat_worktree=False
    )
    row = {r["Box"]: r for r in _fleet_json(proc)["rows"]}["box-5491"]
    assert row["Fence"] == "DEAD", row
    assert row["State"] in ("INTERRUPTED", "ORPHANED-STALE"), row


def test_fleet_suppresses_the_roster_for_an_anonymous_record_with_no_cwd(tmp_path: Path) -> None:
    """It cannot be placed, so no seat can be told apart from a relaunch: exit 4 and nothing on
    stdout, which respawn.ps1 reads as a fleet run with no JSON and stops on."""
    proc, anon = _fleet(tmp_path, {"pid": os.getpid(), "startedAt": NOW_MS, "cwd": None})
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert not proc.stdout.strip(), proc.stdout
    assert "ROSTER SUPPRESSED" in proc.stderr and str(anon) in proc.stderr, proc.stderr


def test_fleet_renders_with_no_anonymous_record(tmp_path: Path) -> None:
    """The twin: nothing anonymous, a normal roster and a zero count."""
    proc, _ = _fleet(tmp_path, None)
    assert _fleet_json(proc)["receipt"]["anonymousLiveRecords"] == 0


def test_fleet_suppresses_the_roster_when_the_anonymous_scan_fails(tmp_path: Path) -> None:
    """An instrument that failed must not read as no record. The scan is made to throw in a copy of
    the scripts, so the real ones are untouched."""
    coord = _broken_coord(
        tmp_path, "function Get-AnonymousSessionRecords { throw 'scan-broke-5491' }"
    )
    proc, _ = _fleet(tmp_path, None, coord=coord)
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert not proc.stdout.strip(), proc.stdout
    assert "scan-broke-5491" in proc.stderr, proc.stderr


def _broken_coord(tmp_path: Path, override: str) -> Path:
    """A copy of fleet.ps1 and the scripts it loads, with ``override`` appended to the copy of
    session-registry.ps1, so the real scripts are untouched."""
    coord = tmp_path / "coord"
    coord.mkdir()
    for name in ("fleet.ps1", "mail-key.ps1", "coord-root.ps1"):
        shutil.copy2(REGISTRY.parent / name, coord / name)
    (coord / "session-registry.ps1").write_text(
        REGISTRY.read_text(encoding="utf-8") + "\n" + override + "\n", encoding="utf-8"
    )
    return coord


def test_fleet_suppresses_the_roster_when_the_anonymous_scan_fails_with_no_message(
    tmp_path: Path,
) -> None:
    """The failure is the throw, not its message: an empty message read as a scan that passed."""
    coord = _broken_coord(
        tmp_path, "function Get-AnonymousSessionRecords { throw [System.Exception]::new('') }"
    )
    proc, _ = _fleet(tmp_path, None, coord=coord)
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert not proc.stdout.strip(), proc.stdout
    assert "with no message" in proc.stderr, proc.stderr


def test_fleet_reads_a_seat_whose_lookup_throws_as_possibly_running(tmp_path: Path) -> None:
    """An unevaluated fence is not a gone session. A throw used to read UNKNOWN, rendered
    INTERRUPTED, which -Chip and respawn.ps1 treat as respawnable."""
    coord = _broken_coord(tmp_path, "function Get-SessionLiveness { throw 'lookup-broke-5491' }")
    proc, _ = _fleet(tmp_path, None, coord=coord)
    j = _fleet_json(proc)
    row = {r["Box"]: r for r in j["rows"]}["box-5491"]
    assert row["Fence"] == "UNREADABLE", row
    assert row["State"] == "POSSIBLY RUNNING", row
    # The receipt says the instrument failed, so a broken fence cannot pass for a busy fleet.
    assert "lookup-broke-5491" in json.dumps(j), j


def test_fleet_reaches_its_refusal_on_an_empty_object_registry_file(tmp_path: Path) -> None:
    """A registry file holding ``{}`` parses to an object with no properties. Reading its cwd threw
    under StrictMode and ended fleet with exit 1. It names no session, no pid and no cwd, so it
    cannot be placed: the roster is suppressed with exit 4 and the file named."""
    proc, _ = _fleet(tmp_path, None, raw_records={"99015.json": "{}"})
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "99015.json" in proc.stderr, proc.stderr
    assert "cannot be found" not in proc.stderr, proc.stderr


def test_fleet_counts_a_live_anonymous_record_in_a_real_worktree_in_its_denominator(
    tmp_path: Path,
) -> None:
    """A LIVE record naming no session, whose cwd is one of this repo's worktrees (the primary
    checkout here), matches no seat record, so the roster is incomplete by it. It was left out of
    liveSessionsWithoutRecord with no stop. The seat's worktree sits under that checkout, so the
    seat reads POSSIBLY RUNNING too."""
    proc, _ = _fleet(
        tmp_path, {"pid": os.getpid(), "startedAt": NOW_MS, "cwd": str(tmp_path / "repo")}
    )
    j = _fleet_json(proc)
    assert j["receipt"]["liveSessionsWithoutRecord"] == 1, j["receipt"]
    row = {r["Box"]: r for r in j["rows"]}["box-5491"]
    assert row["State"] == "POSSIBLY RUNNING", row


def _live_named_record(cwd: Path) -> str:
    """A LIVE registry record naming a session no seat record holds, sitting in ``cwd``."""
    return json.dumps(
        {
            "pid": os.getpid(),
            "startedAt": NOW_MS,
            "sessionId": "5485live-0000-0000-0000-000000000000",
            "cwd": str(cwd),
        }
    )


def _linked_worktree(repo: Path) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "add", "-q", "--detach", str(repo.parent / "repo-wt")],
        check=True,
        capture_output=True,
    )


def _nested_repo(repo: Path) -> None:
    (repo / "nested" / ".git").mkdir(parents=True)


@pytest.mark.parametrize(
    ("where", "counted", "prepare"),
    [
        ("repo/sub/dir", 1, None),
        ("repo-wt/sub", 1, _linked_worktree),
        ("repo-other", 0, None),
        ("repo/nested/sub", 0, _nested_repo),
    ],
    ids=["subdirectory", "linked-worktree-subdirectory", "sibling-prefix", "nested-repository"],
)
def test_fleet_counts_a_live_session_in_a_worktree_subdirectory_in_its_denominator(
    tmp_path: Path, where: str, counted: int, prepare: Callable[[Path], None] | None
) -> None:
    """BACKLOG #5485. A live session whose cwd is a subdirectory of one of this repo's worktrees is
    a session in that worktree. Exact equality left it out of liveSessionsWithoutRecord, so the
    roster read complete without it. A sibling directory sharing the name as a prefix is not inside
    the worktree, and nor is a directory under another repository nested in it."""
    # The cwd is not created: the denominator compares paths. A nested .git is what it reads.
    proc, _ = _fleet(
        tmp_path,
        None,
        raw_records={"99485.json": _live_named_record(tmp_path / where)},
        prepare=prepare,
    )
    j = _fleet_json(proc)
    assert j["receipt"]["liveSessionsWithoutRecord"] == counted, j["receipt"]
    fired = [s for s in j["receipt"]["stopConditions"] if s.startswith("liveSessionsWithoutRecord")]
    assert len(fired) == counted, j["receipt"]["stopConditions"]


def test_fleet_raises_a_stop_when_a_seat_record_is_unreadable(tmp_path: Path) -> None:
    """BACKLOG #5485. An unreadable seat record was counted in the receipt and fired no stop, so the
    roster could read complete with a seat missing from it. The stop names that file and not the
    parseable seat record _fleet always writes beside it, which is the twin. A record is written by
    one atomic rename, so the stop says it is damaged and to move it out by hand, never to run again:
    a rerun reads the same damaged file and stops the same way."""
    proc, _ = _fleet(tmp_path, None, extra_seats={"box-5485": "{not json"})
    j = _fleet_json(proc)
    assert j["receipt"]["recordsUnreadable"] == 1, j["receipt"]
    fired = [s for s in j["receipt"]["stopConditions"] if s.startswith("recordsUnreadable")]
    assert len(fired) == 1, j["receipt"]["stopConditions"]
    assert "box-5485" in fired[0] and "box-5491" not in fired[0], fired
    assert "damaged" in fired[0] and "by hand" in fired[0], fired
    assert "run again" not in fired[0], fired


@pytest.mark.parametrize(
    ("pid", "anonymous", "refusal"),
    [
        ("not-a-number", None, "UNREADABLE"),
        (None, None, None),
        (None, "primary", "names no session"),
        (None, "elsewhere", None),
    ],
    ids=["unreadable", "dead", "anonymous-in-its-tree", "anonymous-elsewhere"],
)
def test_sessions_rehome_refuses_an_unreadable_fence(
    tmp_path: Path,
    pid: str | None,
    anonymous: str | None,
    refusal: str | None,
    home_name: str = "home",
) -> None:
    """sessions.ps1 moves a transcript, so an UNREADABLE fence must stop it. A non-numeric pid used
    to throw in the fence, which stopped the move; reading UNREADABLE must stop it the same way. A
    record naming no session in the transcript's birth tree stops it too, and the refusal names that
    record rather than calling a dead session RUNNING. The twins, a DEAD record alone or beside an
    anonymous record in another tree, pass the guard and find the transcript already filed."""
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
    home = tmp_path / home_name
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
    anon = root / "sessions" / "2.json"
    if anonymous is not None:
        cwd = primary if anonymous == "primary" else str(tmp_path / "elsewhere")
        anon.write_text(json.dumps({"startedAt": NOW_MS, "cwd": cwd}), encoding="utf-8")
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
    if refusal:
        assert proc.returncode != 0 and refusal in proc.stderr, proc.stdout + proc.stderr
        if anonymous:
            assert "2.json" in proc.stderr and "still RUNNING" not in proc.stderr, proc.stderr
    else:
        assert proc.returncode == 0 and "already filed" in proc.stdout, proc.stdout + proc.stderr
    assert transcript.exists()


_REHOME_SID = "7622eeee-1111-2222-3333-444444444444"


def _relocated_session(tmp_path: Path) -> dict[str, Path]:
    """A throwaway repo and profile holding one dead session whose transcript was born in the primary
    but is filed under a worktree slug, so ``-Rehome`` has a real move to make. Returns the paths."""
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
    slug = "".join(c if c.isalnum() else "-" for c in primary)
    source = root / "projects" / f"{slug}-wt" / f"{_REHOME_SID}.jsonl"
    source.parent.mkdir(parents=True)
    source.write_text(
        json.dumps({"type": "user", "cwd": primary, "message": {"content": "synthetic"}}) + "\n",
        encoding="utf-8",
    )
    old = time.time() - 3600
    os.utime(source, (old, old))
    (root / "sessions").mkdir()
    (root / "sessions" / "1.json").write_text(
        json.dumps({"pid": never_live_pid(), "sessionId": _REHOME_SID, "startedAt": NOW_MS}),
        encoding="utf-8",
    )
    dest = root / "projects" / slug / f"{_REHOME_SID}.jsonl"
    dest.parent.mkdir(parents=True)
    return {"repo": repo, "home": home, "root": root, "source": source, "dest": dest}


def _rehome(paths: dict[str, Path]) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k.upper() not in {"USERPROFILE"}}
    env["USERPROFILE"] = str(paths["home"])
    script = paths["repo"] / "scripts" / "worktree" / "sessions.ps1"
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script), "-Rehome", _REHOME_SID[:8]],
        cwd=str(paths["repo"]),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env=env,
    )


@pytest.mark.parametrize("age_h", [None, 0, 48], ids=["directory-only", "fresh", "old"])
def test_sessions_rehome_refuses_beside_a_fresh_unreadable_registry_file(
    tmp_path: Path, age_h: float | None
) -> None:
    """BACKLOG #7622. A registry file that does not parse may be this session's own record mid-write,
    and Get-SessionLiveness never lists it, so the move went ahead. A fresh one now refuses and moves
    nothing. The twins, no such file or one older than the 24-hour bound, still rehome a dead session."""
    paths = _relocated_session(tmp_path)
    if age_h is None:
        # A directory named *.json is not a record being written, so it does not veto.
        (paths["root"] / "sessions" / "3.json").mkdir()
    else:
        bad = paths["root"] / "sessions" / "2.json"
        bad.write_text('{"pid": 12', encoding="utf-8")
        stamp = time.time() - age_h * 3600
        os.utime(bad, (stamp, stamp))
    proc = _rehome(paths)
    if age_h == 0:
        assert proc.returncode != 0 and "cannot be read" in proc.stderr, proc.stdout + proc.stderr
        assert "2.json" in proc.stderr, proc.stderr
        assert paths["source"].exists() and not paths["dest"].exists()
    else:
        assert proc.returncode == 0 and "Rehomed session" in proc.stdout, proc.stdout + proc.stderr
        assert paths["dest"].exists() and not paths["source"].exists()


_STUB = json.dumps({"type": "custom-title", "customTitle": "synthetic", "sessionId": _REHOME_SID})
_NOT_TITLE = "holds a record that is not a title"


@pytest.mark.parametrize(
    ("existing", "backup", "refusal"),
    [
        (_STUB + "\n", None, None),
        (json.dumps({"type": "ai-title", "aiTitle": "synthetic"}) + "\n", None, None),
        (_STUB + "\n" + json.dumps({"type": "user", "cwd": "x"}) + "\n", None, _NOT_TITLE),
        ("not json\n", None, _NOT_TITLE),
        ("[" + _STUB + "]\n", None, _NOT_TITLE),
        (json.dumps({"TYPE": "custom-title"}) + "\n", None, _NOT_TITLE),
        (json.dumps({"type": "Custom-Title"}) + "\n", None, _NOT_TITLE),
        ("", None, "no title record"),
        (_STUB + "\n", "earlier stub\n", ".stub.bak already exists"),
    ],
    ids=[
        "stub",
        "ai-title-stub",
        "real-transcript",
        "unparsed",
        "array",
        "key-case",
        "value-case",
        "empty",
        "backup-exists",
    ],
)
def test_sessions_rehome_merges_only_a_title_stub_at_the_destination(
    tmp_path: Path, existing: str, backup: str | None, refusal: str | None
) -> None:
    """BACKLOG #7623. A file at the destination was taken to be a title stub whatever it held, so a
    real transcript there was overwritten and its lines appended to the moved one, and an existing
    backup was overwritten too. Now only a file of title records merges; anything else, or an
    existing backup, refuses and changes nothing on disk."""
    paths = _relocated_session(tmp_path)
    paths["dest"].write_text(existing, encoding="utf-8")
    bak = paths["dest"].with_name(paths["dest"].name + ".stub.bak")
    if backup is not None:
        bak.write_text(backup, encoding="utf-8")
    source_text = paths["source"].read_text(encoding="utf-8")
    proc = _rehome(paths)
    if refusal:
        assert proc.returncode != 0 and refusal in proc.stderr, proc.stdout + proc.stderr
        assert paths["source"].read_text(encoding="utf-8") == source_text
        assert paths["dest"].read_text(encoding="utf-8") == existing
        if backup is None:
            assert not bak.exists()
        else:
            assert bak.read_text(encoding="utf-8") == backup
    else:
        assert proc.returncode == 0 and "Rehomed session" in proc.stdout, proc.stdout + proc.stderr
        assert not paths["source"].exists()
        merged = paths["dest"].read_text(encoding="utf-8-sig")
        assert merged.startswith(source_text.strip()) and merged.rstrip().endswith(existing.strip())
        assert bak.read_text(encoding="utf-8") == existing


def test_sessions_reads_a_profile_whose_name_holds_a_bracket(tmp_path: Path) -> None:
    """Vault BACKLOG #2985, added item 2. sessions.ps1 listed USERPROFILE as a pattern, so a profile
    named home[1] matched only a folder named home1, found no config root and no transcript. Red
    before the fix: the DEAD case below did not find the transcript already filed."""
    test_sessions_rehome_refuses_an_unreadable_fence(
        tmp_path, None, None, None, home_name="home[1]"
    )


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
    """A startedAt in the future is not a registration that happened: UNVERIFIED, which at least
    seat.ps1, sessions.ps1 and the remove guards treat as possibly live. The cast this replaced
    threw on this value; STALE would read as gone. A moderate future value, inside the range the
    cast handled, reads the same under the default skew."""
    record = {"pid": os.getpid(), "sessionId": "s", "startedAt": 200_000_000_000_000}
    assert _strict_fence(record) == "UNVERIFIED"
    record["startedAt"] = int((time.time() + 1800) * 1000)
    assert _strict_fence(record) == "UNVERIFIED"


def test_a_live_anonymous_record_with_a_future_startedat_still_vetoes(
    config_root: Path, tmp_path: Path
) -> None:
    """Its fence reads UNVERIFIED, not STALE, so the scan keeps it and its fresh file vetoes."""
    wt = tmp_path / "wt-future"
    future = int((time.time() + 3600) * 1000)
    _anonymous(config_root, "99014.json", {"pid": os.getpid(), "startedAt": future, "cwd": str(wt)})
    got = _strict(
        f"(Get-SessionLiveness -SessionId '5491d4d4' -ConfigRoot '{config_root}' "
        f"-Worktree '{wt}').State"
    )
    assert got == "UNREADABLE"


def test_a_session_registered_after_its_process_started_is_live_under_a_wide_skew() -> None:
    """The twin: an hour-later registration is a real start time, and remove.ps1 widens the skew to
    read it LIVE. Rejecting every future startedAt turned this UNVERIFIED (PR 3001's red)."""
    record = {"pid": os.getpid(), "sessionId": "s", "startedAt": int((time.time() + 3600) * 1000)}
    payload = json.dumps(record).replace("'", "''")
    got = _strict(
        f"(Test-RecordLiveness -Record ('{payload}' | ConvertFrom-Json) "
        "-StartSkewMinutes ([int]::MaxValue)).State"
    )
    assert got == "LIVE"


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


AUDIT = REGISTRY.parents[1] / "worktree" / "worktree-audit.ps1"


def _stale_seat_locks(config_root: Path, locked: Path, sid: str, prelude: str = "") -> str:
    """How many seat locks Get-StaleSeatLocks lists for one lock on ``locked`` held by ``sid``."""
    return _strict(
        f". '{AUDIT}'; {prelude}"
        f"$w = [pscustomobject]@{{ Path = '{locked}'; Locked = $true; "
        f"LockReason = 'builder {sid}' }}; "
        f"@(Get-StaleSeatLocks -Worktrees @($w) -ConfigRoot '{config_root}').Count"
    )


@pytest.mark.parametrize(
    ("anon_cwd", "listed"),
    [(None, 1), ("locked", 0), ("elsewhere", 0)],
    ids=["no-anonymous-record-lists-the-lock", "anonymous-in-the-tree-vetoes", "anywhere-vetoes"],
)
def test_stale_seat_locks_keep_the_box_wide_anonymous_veto(
    config_root: Path, tmp_path: Path, anon_cwd: str | None, listed: int
) -> None:
    """A fresh record naming no session vetoes every seat lock on the box, wherever its cwd is: a
    junction, 8.3 or subst spelling of the locked tree cannot be told apart from another tree by
    its spelling, so the lookup names no worktree (fail closed). With no such record, the gone
    session's lock is listed."""
    sid = "5491a0a0-0000-4000-8000-000000000000"
    write_session(config_root, pid=never_live_pid(), session_id=sid)
    locked = tmp_path / "wt-locked"
    if anon_cwd is not None:
        cwd = str(locked) if anon_cwd == "locked" else str(tmp_path / "wt-other")
        _anonymous(config_root, "99016.json", {"pid": os.getpid(), "startedAt": NOW_MS, "cwd": cwd})
    assert _stale_seat_locks(config_root, locked, sid) == str(listed)


# A fence stub for the start-skew plumbing: LIVE only under the removal paths' unbounded skew, STALE
# (gone) under any bounded one, so the seat's reading names which skew its lookup passed.
_SKEW_STUB = (
    "function Test-RecordLiveness { param([AllowNull()][object]$Record, [int]$StartSkewMinutes = 15) "
    "if ($StartSkewMinutes -eq [int]::MaxValue) { return @{ State = 'LIVE'; Detail = '' } } "
    "return @{ State = 'STALE'; Detail = 'bounded skew' } }"
)


def test_stale_seat_locks_use_the_removal_paths_unbounded_start_skew(
    config_root: Path, tmp_path: Path
) -> None:
    """A session whose process started long before it registered reads LIVE to the removal fence,
    which passes [int]::MaxValue, and read STALE, so gone, here under the default 15 minutes. The
    stub reads LIVE only under the unbounded skew; on 3c19a009b6 the lock was listed."""
    sid = "5491a1a1-0000-4000-8000-000000000000"
    write_session(config_root, pid=never_live_pid(), session_id=sid)
    locked = tmp_path / "wt-skew"
    assert _stale_seat_locks(config_root, locked, sid, prelude=_SKEW_STUB + "; ") == "0"
    # A lookup that throws lists no lock either, so the count alone cannot tell the two apart. The
    # reading names which one it was: LIVE here, UNREADABLE for a throw.
    assert _seat_lock_state(config_root, sid, _SKEW_STUB + "; ") == "LIVE"


def _seat_lock_state(config_root: Path, sid: str, prelude: str) -> str:
    """The State Get-SeatLockReading gives a seat lock held by ``sid``, after ``prelude``."""
    return _strict(
        f". '{AUDIT}'; {prelude}"
        f"(Get-SeatLockReading -SessionKey '{sid}' -ConfigRoot '{config_root}').State"
    )


def test_a_seat_lock_lookup_that_throws_reads_unreadable_not_live(config_root: Path) -> None:
    """The negative control for the skew test above: a throwing lookup also lists no lock, and its
    reading is UNREADABLE, so the LIVE assertion there fails if the stub's lookup threw."""
    sid = "5491a2a2-0000-4000-8000-000000000000"
    write_session(config_root, pid=never_live_pid(), session_id=sid)
    throw = "function Get-SessionLiveness { throw 'lookup-broke-5491' }; "
    assert _stale_seat_locks(config_root, config_root / "wt-throw", sid, prelude=throw) == "0"
    assert _seat_lock_state(config_root, sid, throw) == "UNREADABLE"


def test_fleet_uses_the_removal_paths_unbounded_start_skew(tmp_path: Path) -> None:
    """The twin in fleet.ps1: a seat the removal fence reads LIVE read STALE under the default skew,
    rendered INTERRUPTED, which -Chip and respawn.ps1 treat as respawnable. On 3c19a009b6 it read
    INTERRUPTED."""
    proc, _ = _fleet(tmp_path, None, coord=_broken_coord(tmp_path, _SKEW_STUB))
    row = {r["Box"]: r for r in _fleet_json(proc)["rows"]}["box-5491"]
    assert row["Fence"] == "LIVE", row
    assert row["State"] == "RUNNING", row


def test_fleet_reads_an_empty_object_seat_record_under_strict_mode(tmp_path: Path) -> None:
    """A seat record holding ``{}`` has no properties, and ``.PSObject.Properties.Name`` on it threw
    under fleet.ps1's StrictMode Latest, ending the run with exit 1. On 3c19a009b6 it did."""
    proc, _ = _fleet(tmp_path, None, extra_seats={"box-empty": "{}"})
    assert "cannot be found" not in proc.stderr, proc.stderr
    j = _fleet_json(proc)
    boxes = {r["Box"] for r in j["rows"]}
    assert {"box-5491", "box-empty"} <= boxes, boxes


def test_fleet_chip_renders_a_seat_record_missing_its_fields_under_strict_mode(
    tmp_path: Path,
) -> None:
    """The -Chip briefing read its seat record's fields bare, so a record lacking asOf, claims or
    handoff threw under fleet.ps1's StrictMode Latest and wrote no briefing. A missing field now
    renders as not declared."""
    rec = {"sessionKey": "5491c0de", "sessionId": "5491c0de-0000", "worktree": str(tmp_path / "w")}
    proc, _ = _fleet(
        tmp_path,
        None,
        extra_seats={"box-chip": json.dumps(rec)},
        fleet_args=["-Chip", "-BoxKey", "box-chip", "-SessionKey", "5491c0de"],
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "You are a REPLACEMENT SEAT" in proc.stdout, proc.stdout
    assert "SEAT: NOT DECLARED" in proc.stdout, proc.stdout
    assert "CLAIMS HELD BY THE PREDECESSOR EPISODE: none" in proc.stdout, proc.stdout


# respawn.ps1 (in the vault) respawns only rows whose State is one of these.
_RESPAWNABLE = {"INTERRUPTED", "HANDED", "ORPHANED-STALE"}


@pytest.mark.parametrize(
    "text",
    [
        "{}",
        "null",
        json.dumps({"sessionKey": "5491c1de", "worktree": "C:\\nowhere"}),
        json.dumps({"sessionKey": "5491c1de", "sessionId": "5491c1de-0000"}),
        json.dumps({"sessionKey": "5491c1de", "lifecycle": "handed"}),
    ],
    ids=["empty-object", "null", "no-session-id", "no-worktree", "handed-no-fields"],
)
def test_fleet_reads_an_incomplete_seat_record_as_possibly_running(
    tmp_path: Path, text: str
) -> None:
    """A seat record that names no session or no worktree cannot be fenced. It read INTERRUPTED
    (HANDED when it said so), the population respawn.ps1 respawns and -Chip briefs with
    ``git -C ""``. It now reads POSSIBLY RUNNING and the receipt names it. On 352502253e each case
    read INTERRUPTED, or HANDED."""
    proc, _ = _fleet(tmp_path, None, extra_seats={"box-part": text})
    j = _fleet_json(proc)
    row = {r["Box"]: r for r in j["rows"]}["box-part"]
    assert row["State"] == "POSSIBLY RUNNING", row
    assert row["State"] not in _RESPAWNABLE
    assert row["Fence"] == "UNREADABLE", row
    assert j["receipt"]["seatRecordsIncomplete"] == 1, j["receipt"]
    assert "box-part" in json.dumps(j["receipt"]["stopConditions"]), j["receipt"]
    # The twin: the complete seat record beside it keeps its own verdict.
    assert {r["Box"]: r for r in j["rows"]}["box-5491"]["State"] in _RESPAWNABLE


def test_fleet_chip_writes_no_briefing_for_an_incomplete_seat_record(tmp_path: Path) -> None:
    """-Chip briefed a record with no worktree with ``git -C ""``, which runs in whatever directory
    the replacement seat starts in. It now refuses and names the record."""
    proc, _ = _fleet(
        tmp_path,
        None,
        extra_seats={"box-chip": json.dumps({"sessionKey": "5491c2de"})},
        fleet_args=["-Chip", "-BoxKey", "box-chip", "-SessionKey", "5491c2de"],
    )
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "git -C" not in proc.stdout, proc.stdout
    assert "box-chip" in proc.stderr and "names no session or no worktree" in proc.stderr
