# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the cross-surface session roster (``scripts/coord/presence.ps1``).

Every test drives the REAL script as a subprocess against a throwaway git repo and a fixture config
root, so what is under test is the logic the SessionStart hook actually runs -- not a Python
re-implementation of its rules that could drift from it silently.

Two properties carry the weight:

* **VS Code sessions are included.** That is the entire reason this exists. The Desktop app's own
  ``list_sessions`` never registers a session it did not spawn, so a VS Code session is invisible to
  it; ``<config-root>/sessions/<pid>.json`` is the only registry that has every surface.
* **Liveness is fenced, not a bare pid check.** A pid alone is not identity: pids get reused and these
  records outlive their process. ``test_pid_reuse_is_not_reported_live`` is the one that matters --
  it uses a REAL running pid whose process started long after the recorded session, which is exactly
  the shape of a recycled pid, and asserts the roster refuses to call it LIVE.
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

PRESENCE = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "presence.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="presence.ps1 needs pwsh on Windows (Get-CimInstance / Process.StartTime)",
)

NOW_MS = int(time.time() * 1000)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A real git repo -- the script scopes presence to worktrees sharing one .git."""
    return _make_repo(tmp_path / "repo")


def _make_repo(path: Path) -> Path:
    path.mkdir()
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "t@example.invalid")
    _git(path, "config", "user.name", "t")
    (path / "f.txt").write_text("x", encoding="utf-8")
    _git(path, "add", "f.txt")
    _git(path, "commit", "-qm", "init")
    return path


@pytest.fixture
def config_root(tmp_path: Path) -> Path:
    root = tmp_path / ".claude"
    (root / "sessions").mkdir(parents=True)
    return root


def write_session(
    config_root: Path,
    *,
    pid: int,
    cwd: Path | str,
    session_id: str,
    entrypoint: str = "claude-desktop",
    started_at: int | None = None,
    filename: str | None = None,
) -> None:
    rec = {
        "pid": pid,
        "sessionId": session_id,
        "cwd": str(cwd),
        "startedAt": NOW_MS if started_at is None else started_at,
        "version": "2.1.219",
        "peerProtocol": 1,
        "kind": "interactive",
        "entrypoint": entrypoint,
        "name": session_id[:8],
        "nameSource": "derived",
    }
    name = filename or f"{pid}.json"
    (config_root / "sessions" / name).write_text(json.dumps(rec), encoding="utf-8")


def run_presence(repo: Path, config_root: Path, *extra: str) -> list[dict[str, Any]]:
    """Invoke the real script and return its JSON rows."""
    out = run_raw(repo, config_root, "-Json", *extra).stdout.strip()
    return json.loads(out) if out else []


def test_live_session_in_repo_is_listed(repo: Path, config_root: Path) -> None:
    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="aaaaaaaa-1111")
    rows = run_presence(repo, config_root)
    assert [r["Short"] for r in rows] == ["aaaaaaaa"]
    assert rows[0]["State"] == "LIVE"


def test_vscode_session_is_included_and_labelled(repo: Path, config_root: Path) -> None:
    """The reason this script exists: the Desktop app's session tooling cannot see these."""
    write_session(
        config_root,
        pid=os.getpid(),
        cwd=repo,
        session_id="bbbbbbbb-2222",
        entrypoint="claude-vscode",
    )
    rows = run_presence(repo, config_root)
    assert len(rows) == 1
    assert rows[0]["Surface"] == "vscode"
    assert rows[0]["State"] == "LIVE"


def test_pid_reuse_is_not_reported_live(repo: Path, config_root: Path) -> None:
    """A real, running pid recorded against a much older session start = a recycled pid.

    This is the failure a bare `is the pid alive` check waves through, and the one Claude Code's own
    registry cannot catch on this host (its `procStart` field serialises as absent, so its guard
    passes unconditionally). The roster computes process start time itself and must reject this.
    """
    two_days_ago = NOW_MS - (48 * 60 * 60 * 1000)
    write_session(
        config_root,
        pid=os.getpid(),
        cwd=repo,
        session_id="cccccccc-3333",
        started_at=two_days_ago,
    )
    assert run_presence(repo, config_root) == []  # not live, so absent by default

    rows = run_presence(repo, config_root, "-All")
    assert [r["State"] for r in rows] == ["STALE"]
    assert "reused" in rows[0]["Detail"]


def test_dead_pid_is_excluded_by_default_and_shown_with_all(repo: Path, config_root: Path) -> None:
    dead = never_live_pid()
    write_session(config_root, pid=dead, cwd=repo, session_id="dddddddd-4444")
    assert run_presence(repo, config_root) == []

    rows = run_presence(repo, config_root, "-All")
    assert [r["State"] for r in rows] == ["DEAD"]


def test_session_outside_the_repo_is_ignored(repo: Path, config_root: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "not-the-repo"
    elsewhere.mkdir()
    write_session(config_root, pid=os.getpid(), cwd=elsewhere, session_id="eeeeeeee-5555")
    assert run_presence(repo, config_root) == []


def test_sibling_prefix_directory_is_not_treated_as_inside_the_repo(
    repo: Path, config_root: Path
) -> None:
    """`<repo>-sweep` shares a string prefix with `<repo>` but is a different tree.

    A naive StartsWith would fold every `MessageFoundry-*` sibling worktree into the primary and
    report sessions as colliding in a checkout they are nowhere near.
    """
    sibling = repo.parent / f"{repo.name}-sweep"
    sibling.mkdir()
    write_session(config_root, pid=os.getpid(), cwd=sibling, session_id="ffffffff-6666")
    assert run_presence(repo, config_root) == []


def test_subdirectory_cwd_still_maps_to_its_worktree(repo: Path, config_root: Path) -> None:
    sub = repo / "messagefoundry" / "config"
    sub.mkdir(parents=True)
    write_session(config_root, pid=os.getpid(), cwd=sub, session_id="99999999-7777")
    rows = run_presence(repo, config_root)
    assert len(rows) == 1
    assert rows[0]["IsPrimary"] is True


def test_linked_worktree_session_is_scoped_to_its_own_branch(
    repo: Path, config_root: Path, tmp_path: Path
) -> None:
    """A sibling worktree's session must report ITS branch, not the primary's."""
    wt = tmp_path / "wt-feature"
    _git(repo, "worktree", "add", "-b", "feature-x", str(wt))
    write_session(config_root, pid=os.getpid(), cwd=wt, session_id="77777777-8888")
    rows = run_presence(repo, config_root)
    assert len(rows) == 1
    assert rows[0]["Branch"] == "feature-x"
    assert rows[0]["IsPrimary"] is False
    assert rows[0]["Worktree"] == "wt-feature"


def test_malformed_record_does_not_break_the_roster(repo: Path, config_root: Path) -> None:
    """A hook that throws on one bad file would take the whole SessionStart banner down."""
    (config_root / "sessions" / "99999.json").write_text("{not json", encoding="utf-8")
    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="12121212-9999")
    rows = run_presence(repo, config_root)
    assert [r["Short"] for r in rows] == ["12121212"]


def test_the_human_table_names_its_columns_so_the_id_cannot_read_as_a_sha(
    repo: Path, config_root: Path
) -> None:
    """BACKLOG #1098. The default (non-``-Json``) output is a fixed-width table with no header, whose
    leading cell is an 8-hex REGISTRY SESSION ID -- the same shape ``git worktree list`` uses for an
    abbreviated commit SHA, in a banner (``session-context.ps1``) that points readers straight here.

    Asserts the EMITTED TEXT, which is the only place this defect can exist: every other test in this
    file reads ``-Json``, where the field is named ``Short`` and no ambiguity is possible. That is
    precisely how a reporting defect survives a green suite.
    """
    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="abcdef01-1111")
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(PRESENCE),
            "-Repo",
            str(repo),
            "-ConfigRoot",
            str(config_root),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, f"presence.ps1 failed: {proc.stderr}"
    print(proc.stdout)

    lines = proc.stdout.splitlines()
    header = next((ln for ln in lines if "sess-id" in ln), None)
    assert header is not None, (
        f"the table prints no column header, so its leading 8-hex cell has no stated meaning:\n"
        f"{proc.stdout}"
    )
    assert "surface" in header and "worktree" in header and "branch" in header, (
        f"a header naming only the ambiguous column leaves the rest unnamed: {header!r}"
    )

    # The header must sit above the row it governs, or it labels a different table.
    row = next(ln for ln in lines if "abcdef01" in ln)
    assert lines.index(header) < lines.index(row)
    # And the id must land UNDER its own column rather than merely somewhere on the line. A header
    # whose cells do not line up with the data is a label pointing at the wrong value, which is the
    # same class of defect this test exists to close.
    assert row.index("abcdef01") == header.index("sess-id"), (
        f"header and row are not aligned, so the label points at the wrong cell:\n"
        f"{header!r}\n{row!r}"
    )


def test_outside_a_repo_the_json_roster_carries_an_unavailable_receipt(tmp_path: Path) -> None:
    """ "I could not look" must not render as "nobody is live" on the machine-readable channel.

    presence.ps1 already emits an UNAVAILABLE receipt to STDERR for the RepoFound=true /
    Available=false case, precisely so an empty stdout list stops being ambiguous -- its own comment
    says so. The RepoFound=FALSE path returned the same ``[]`` with NO receipt at all, so one of the
    two ways of being unable to look stayed silent on exactly the channel a consumer parses. The fix
    had been applied to one of two paths.

    stdout is deliberately unchanged and still ``[]``: every existing consumer keeps working, and the
    receipt is what separates the cases. Asserting BOTH is the point -- a test that only checked
    stderr would pass against a version that had broken the JSON contract.
    """
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(PRESENCE), "-Json"],
        cwd=str(outside),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.stdout.strip() == "[]", f"the JSON contract changed: {proc.stdout!r}"
    assert "UNAVAILABLE" in proc.stderr, (
        "an unreadable roster emitted no receipt, so an empty list is indistinguishable from "
        f"'nobody is live': stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    assert "not inside a git repository" in proc.stderr.lower(), proc.stderr


def test_a_scheduled_run_is_flagged_and_a_persons_session_is_not(
    repo: Path, config_root: Path
) -> None:
    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="aaaaaaaa-1111")
    d = config_root / "projects" / "any"
    d.mkdir(parents=True)
    (d / "aaaaaaaa-1111.jsonl").write_text(
        json.dumps({"type": "queue-operation", "content": '<scheduled-task name="t">'}) + "\n",
        encoding="utf-8",
    )
    rows = run_presence(repo, config_root)
    assert [r["Scheduled"] for r in rows] == [True]

    (d / "aaaaaaaa-1111.jsonl").write_text(
        json.dumps({"type": "queue-operation", "content": "hello"}) + "\n", encoding="utf-8"
    )
    rows = run_presence(repo, config_root)
    assert [r["Scheduled"] for r in rows] == [False]


# --- -Fleet (vault BACKLOG #3674) ------------------------------------------------------------------
# Ported from korus efd7b428db, with the engine's stricter fence kept: the caller's own repository is
# always scanned, not only when no record names any repository.


def run_raw(repo: Path, config_root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    """Invoke the real script with no output parsing, so stdout and stderr can both be asserted."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(PRESENCE),
            "-Repo",
            str(repo),
            "-ConfigRoot",
            str(config_root),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,  # asserted below with the stderr attached, which check=True would hide
    )
    # The engine copy exits 0 on an unavailable fence; korus's `exit 2` is deliberately not ported.
    assert proc.returncode == 0, f"presence.ps1 failed: rc={proc.returncode}\n{proc.stderr}"
    return proc


@pytest.fixture
def other_repo(tmp_path: Path) -> Path:
    """A second repository whose name shares no prefix with ``repo``, so no name test can fold it."""
    return _make_repo(tmp_path / "other")


def test_fleet_lists_sessions_from_every_repository_the_records_name(
    repo: Path, other_repo: Path, config_root: Path
) -> None:
    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="a1a1a1a1-0001")
    # A second record with the same live pid is fine: each file is its own record.
    write_session(
        config_root, pid=os.getpid(), cwd=other_repo, session_id="b2b2b2b2-0002", filename="b2.json"
    )

    # Control: the default run is scoped to one repository and cannot see the other one's session.
    assert [r["Short"] for r in run_presence(repo, config_root)] == ["a1a1a1a1"]

    rows = run_presence(repo, config_root, "-Fleet")
    assert sorted(r["Short"] for r in rows) == ["a1a1a1a1", "b2b2b2b2"]

    proc = run_raw(repo, config_root, "-Fleet")
    assert "the FLEET of 2 repositories" in proc.stdout, proc.stdout


def test_the_default_run_says_it_is_scoped_and_fleet_does_not(
    repo: Path, config_root: Path
) -> None:
    """A repo-scoped count must not read as the whole fleet. Both the table and the empty roster
    carry the warning, since "nobody is here" is the reading the scope most often corrupts."""
    empty = run_raw(repo, config_root)
    assert "SCOPED TO THIS REPOSITORY" in empty.stdout, empty.stdout
    assert "presence.ps1 -Fleet" in empty.stdout

    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="c3c3c3c3-0003")
    table = run_raw(repo, config_root)
    assert "SCOPED TO THIS REPOSITORY" in table.stdout, table.stdout
    assert "Live Claude sessions in this repo (1)" in table.stdout

    fleet = run_raw(repo, config_root, "-Fleet")
    assert "SCOPED TO THIS REPOSITORY" not in fleet.stdout, fleet.stdout
    assert "Live Claude sessions in the FLEET of 1 repository (1)" in fleet.stdout
    # -Fleet is wider, not complete, and says so rather than letting its silence read as an all-clear.
    assert "NOT proven absent" in fleet.stdout, fleet.stdout


def test_an_available_empty_roster_still_states_its_scope(repo: Path, config_root: Path) -> None:
    """The branch "nobody is here" actually takes: a readable registry whose only record is dead.
    With no records at all the run takes the UNAVAILABLE branch instead, so this needs its own case."""
    write_session(config_root, pid=never_live_pid(), cwd=repo, session_id="c4c4c4c4-0004")
    default = run_raw(repo, config_root)
    assert "No live sessions found in this repo." in default.stdout, default.stdout
    assert "SCOPED TO THIS REPOSITORY" in default.stdout

    fleet = run_raw(repo, config_root, "-Fleet")
    assert "No live sessions found in the FLEET of 1 repository." in fleet.stdout, fleet.stdout
    assert "NOT proven absent" in fleet.stdout


def test_fleet_still_scans_the_callers_repo_when_its_only_record_is_gone(
    repo: Path, other_repo: Path, config_root: Path
) -> None:
    """THE THIRD SHAPE. occupancy.ps1 makes the fence unavailable for a gone checkout named as this
    repo's worktree. Under -Fleet such a record names no repository on disk, so a port that picks
    repositories only from usable cwds never scans ``repo`` -- the live record in ``other_repo``
    supplies a hint, the caller fallback never fires -- and reports the fence available on a roster
    it never read. The engine seeds the caller's repository unconditionally."""
    gone = repo.parent / f"{repo.name}-gone"
    assert not gone.exists()
    write_session(config_root, pid=never_live_pid(), cwd=gone, session_id="d4d4d4d4-0004")
    write_session(config_root, pid=os.getpid(), cwd=other_repo, session_id="e5e5e5e5-0005")

    proc = run_raw(repo, config_root, "-Fleet", "-Json")
    assert "UNAVAILABLE" in proc.stderr, (
        f"-Fleet called the fence available while a gone checkout of the caller's repo had a "
        f"record: stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    # The other repository's live session is still reported: unavailable is not empty.
    assert [r["Short"] for r in json.loads(proc.stdout)] == ["e5e5e5e5"]

    human = run_raw(repo, config_root, "-Fleet")
    assert "Roster INCOMPLETE" in human.stdout, human.stdout


def test_fleet_third_shape_control_reads_available(
    repo: Path, other_repo: Path, config_root: Path
) -> None:
    """The control for the test above: the same run without the gone record must stay available,
    or that test passes against a fence that refuses unconditionally."""
    write_session(config_root, pid=os.getpid(), cwd=other_repo, session_id="e5e5e5e5-0005")
    proc = run_raw(repo, config_root, "-Fleet", "-Json")
    assert "UNAVAILABLE" not in proc.stderr, proc.stderr
    assert [r["Short"] for r in json.loads(proc.stdout)] == ["e5e5e5e5"]


def test_fleet_scans_a_repo_named_only_by_a_deregistered_checkout(
    repo: Path, other_repo: Path, config_root: Path, tmp_path: Path
) -> None:
    """A deregistered linked worktree fails ``rev-parse``, so a hint loop that skips on that failure
    never scans the repository it belongs to. The filesystem reading of its ``.git`` file still
    names the repository, and that repository's fence then reports the checkout unplaceable."""
    wt = tmp_path / "wt-dereg"
    _git(other_repo, "worktree", "add", "-q", "-b", "dereg", str(wt))
    shutil.rmtree(other_repo / ".git" / "worktrees" / wt.name)
    probe = subprocess.run(
        ["git", "-C", str(wt), "rev-parse", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert probe.returncode != 0, "the fixture must be a checkout rev-parse can no longer place"
    write_session(config_root, pid=never_live_pid(), cwd=wt, session_id="f6f6f6f6-0006")

    proc = run_raw(repo, config_root, "-Fleet", "-Json")
    assert "UNAVAILABLE" in proc.stderr, proc.stderr
    assert "git worktree list" in proc.stderr, proc.stderr


def test_fleet_finds_a_deregistered_relative_path_checkout(
    repo: Path, other_repo: Path, config_root: Path, tmp_path: Path
) -> None:
    """``worktree add --relative-paths`` writes a relative ``.git`` pointer. Read unresolved, it named
    no real directory, so the scan was dropped and the fence read available."""
    wt = tmp_path / "wt-rel"
    added = subprocess.run(
        [
            "git",
            "-C",
            str(other_repo),
            "worktree",
            "add",
            "-q",
            "--relative-paths",
            "-b",
            "rel",
            str(wt),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if added.returncode != 0 and "relative-paths" in added.stderr:
        pytest.skip(f"this git has no --relative-paths (2.48+): {added.stderr.strip()}")
    assert added.returncode == 0, added.stderr
    assert not Path(
        (wt / ".git").read_text(encoding="utf-8").split(":", 1)[1].strip()
    ).is_absolute()
    shutil.rmtree(other_repo / ".git" / "worktrees" / wt.name)
    write_session(config_root, pid=never_live_pid(), cwd=wt, session_id="a7a7a7a7-0007")

    proc = run_raw(repo, config_root, "-Fleet", "-Json")
    assert "UNAVAILABLE" in proc.stderr, proc.stderr
    assert "git worktree list" in proc.stderr, proc.stderr


def test_a_scan_that_throws_is_an_unavailable_repository_not_a_crash(
    repo: Path, other_repo: Path, config_root: Path
) -> None:
    """A record the fence cannot convert, in another repository, used to throw out of that repo's
    scan and end the whole -Fleet run with exit 1. The default run never places that record."""
    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="b8b8b8b8-0008")
    bad = {"pid": 4242, "sessionId": "c9c9c9c9-0009", "cwd": str(other_repo), "startedAt": "abc"}
    (config_root / "sessions" / "bad.json").write_text(json.dumps(bad), encoding="utf-8")

    assert (
        run_raw(repo, config_root, "-Json").stderr.strip() == ""
    )  # control: default is unaffected

    proc = run_raw(repo, config_root, "-Fleet", "-Json")  # run_raw asserts rc 0
    assert "UNAVAILABLE" in proc.stderr, proc.stderr
    assert [r["Short"] for r in json.loads(proc.stdout)] == ["b8b8b8b8"]


def test_fleet_with_an_unresolvable_repo_says_it_was_not_scanned(
    other_repo: Path, config_root: Path, tmp_path: Path
) -> None:
    write_session(config_root, pid=os.getpid(), cwd=other_repo, session_id="d1d1d1d1-0010")
    missing = tmp_path / "no-such-repo"
    proc = run_raw(missing, config_root, "-Fleet", "-Json")
    assert "could not be resolved" in proc.stderr, proc.stderr
    assert [r["Short"] for r in json.loads(proc.stdout)] == ["d1d1d1d1"]


def test_fleet_rows_name_their_repository_and_only_ours_is_the_shared_primary(
    repo: Path, other_repo: Path, config_root: Path
) -> None:
    """Without a repository on each row, two repos' trunks both print as ``primary`` and both carry
    the SHARED PRIMARY warning, which reads as two sessions in the caller's own trunk."""
    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="e1e1e1e1-0011")
    write_session(
        config_root, pid=os.getpid(), cwd=other_repo, session_id="f1f1f1f1-0012", filename="f1.json"
    )
    # -SelfPid 1 so neither row is the caller, which would suppress the warning on both.
    proc = run_raw(repo, config_root, "-Fleet", "-SelfPid", "1")
    lines = proc.stdout.splitlines()
    ours = next(ln for ln in lines if "e1e1e1e1" in ln)
    theirs = next(ln for ln in lines if "f1f1f1f1" in ln)
    assert f"{repo.name}/primary" in ours and f"{other_repo.name}/primary" in theirs, proc.stdout
    flags = [lines[lines.index(ours) + 1], lines[lines.index(theirs) + 1]]
    assert "SHARED PRIMARY" in flags[0], proc.stdout
    assert "SHARED PRIMARY" not in flags[1], proc.stdout

    rows = {r["Short"]: r for r in run_presence(repo, config_root, "-Fleet")}
    assert Path(rows["e1e1e1e1"]["Repo"]).name == repo.name
    assert Path(rows["f1f1f1f1"]["Repo"]).name == other_repo.name
    assert rows["e1e1e1e1"]["IsOwnRepo"] is True
    assert rows["f1f1f1f1"]["IsOwnRepo"] is False


def test_fleet_survives_a_record_on_a_drive_that_no_longer_exists(
    repo: Path, config_root: Path
) -> None:
    """Walking up from such a cwd makes Join-Path throw. The default run never walks it."""
    write_session(config_root, pid=os.getpid(), cwd=repo, session_id="a2a2a2a2-0013")
    write_session(
        config_root,
        pid=never_live_pid(),
        cwd="Q:\\gone\\x",
        session_id="b3b3b3b3-0014",
        filename="q.json",
    )
    if Path("Q:\\").exists():
        pytest.skip("drive Q: exists on this machine, so the record is not on a missing drive")
    rows = run_presence(repo, config_root, "-Fleet")  # run_presence asserts rc 0
    assert [r["Short"] for r in rows] == ["a2a2a2a2"]
