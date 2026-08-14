# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the fleet-continuity writer and reader (``scripts/coord/seat.ps1``, ``fleet.ps1``).

These drive the REAL scripts as subprocesses against a throwaway git repo, for the reason
``test_coord_presence.py`` states: a Python re-implementation of the rules would drift from the
scripts silently, and the whole point of this layer is that it must not lie.

**WHAT THIS LAYER IS FOR.** When a Claude account's weekly budget is exhausted the owner opens ONE
session under a different account, with no inherited context, no inherited memory and no realtime
channel to anything that was running. It has to work out what every seat was doing from disk alone.
So the failure that matters is not "the roster is wrong" -- it is "the roster is confidently empty",
which is byte-identical to a healthy quiet fleet.

**THE TESTS THAT CARRY THE WEIGHT**, each pinning a defect measured on a live box rather than a
hypothetical:

* ``test_missing_field_is_absent_not_empty`` -- ``@($null).Count`` is 1 in PowerShell, so a field
  that was never written reads as one element. A count agreed with a plausible wrong answer until
  the shape was dumped, so the shape is what this asserts.
* ``test_untracked_files_are_named_not_just_counted`` -- ``git stash create`` has no ``-u`` and
  captures TRACKED edits only, so the one category that cannot be recovered from anywhere else is
  exactly what it silently omits.
* ``test_inherited_allocations_are_not_attributed_to_this_episode`` -- a worktree path outlives its
  occupant, and matching on path alone hands a replacement someone else's ledger numbers.
* ``test_receipt_reports_examined_not_merely_found`` -- the reader must state what it LOOKED AT, so
  that an empty roster over a dead writer is distinguishable from an empty roster over an idle one.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SEAT = ROOT / "scripts" / "coord" / "seat.ps1"
FLEET = ROOT / "scripts" / "coord" / "fleet.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 / fleet.ps1 need pwsh on Windows (Process.StartTime, config-root discovery)",
)


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return out.stdout.strip()


def _pwsh(script: Path, *args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(script), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A real git repo with a commit, so merge-base and diff have something to resolve."""
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    (r / "tracked.txt").write_text("original\n", encoding="utf-8")
    _git(r, "add", "tracked.txt")
    _git(r, "commit", "-qm", "base")
    return r


def _record_path(repo: Path, session: str) -> Path:
    seats = repo / ".git" / "mefor-coord" / "seats"
    hits = list(seats.glob(f"*/{session}.json"))
    assert hits, f"no record written for {session} under {seats}"
    return hits[0]


def _write_record(repo: Path, session: str) -> dict:
    r = _pwsh(SEAT, "-Record", "-SessionId", session, cwd=repo)
    assert r.returncode == 0, f"seat.ps1 must exit 0 even on failure; stderr={r.stderr}"
    return json.loads(_record_path(repo, session).read_text(encoding="utf-8"))


def test_writer_exits_zero_and_writes_one_record(repo: Path) -> None:
    rec = _write_record(repo, "sess-aaaa")
    assert rec["sessionKey"] == "sess-aaaa"
    assert rec["branch"] == "main"
    assert rec["worktreeSource"] == "git rev-parse --show-toplevel"


def test_no_session_id_collapses_to_one_record_not_one_per_turn(repo: Path) -> None:
    """A hook runs as a pwsh CHILD whose pid changes every turn.

    Keying an unidentified session on pid would mint roughly one record per turn -- about 60 files
    for a 30-turn session -- and a reader would see 60 seats where there is one. The key is the
    literal string ``nosid`` for exactly that reason.
    """
    for _ in range(3):
        assert _pwsh(SEAT, "-Record", cwd=repo).returncode == 0
    seats = repo / ".git" / "mefor-coord" / "seats"
    records = list(seats.glob("*/*.json"))
    assert len(records) == 1, [p.name for p in records]
    assert records[0].name == "nosid.json"


def test_missing_field_is_absent_not_empty(repo: Path) -> None:
    """Assert on SHAPE, because a count cannot tell absent from empty here.

    ``@($null).Count`` is 1 in PowerShell, so a field that was never written counts as one element.
    That is not a hypothetical: the ``commits`` field was added to the git-facts helper and never
    wired into the record, and the count agreed with a plausible wrong answer until the type was
    dumped. So every field the reader depends on is asserted PRESENT by key.
    """
    rec = _write_record(repo, "sess-shape")
    for key in (
        "commits",
        "touchedPaths",
        "mergeBase",
        "dirty",
        "stashCovers",
        "claims",
        "allocations",
        "poolEpoch",
        "configRootSource",
    ):
        assert key in rec, f"{key} missing from the record entirely -- a reader would see null"


def test_untracked_files_are_named_not_just_counted(repo: Path) -> None:
    """``git stash create`` captures TRACKED edits only -- there is no ``-u``.

    So the single highest-value thing to rescue, a file that exists nowhere but that working
    directory, is exactly what the stash does not cover. A record that stored only a stash sha and a
    dirty count would tell a replacement seat "nothing to recover" about the very work it replaces.
    """
    (repo / "brand_new.txt").write_text("only here\n", encoding="utf-8")
    rec = _write_record(repo, "sess-untracked")

    assert rec["dirty"]["untrackedCount"] == 1
    assert "brand_new.txt" in rec["dirty"]["untracked"]
    # No tracked edits, so there is nothing for the stash to hold -- and the record must SAY that
    # rather than leaving a null the reader could mistake for "clean".
    assert rec["stashSha"] is None
    assert rec["stashCovers"] == "nothing-untracked-only"


def test_tracked_edit_produces_a_recoverable_stash(repo: Path) -> None:
    """The positive control for the test above: the stash must actually work when it applies."""
    (repo / "tracked.txt").write_text("modified\n", encoding="utf-8")
    rec = _write_record(repo, "sess-tracked")

    assert rec["stashCovers"] == "tracked-only"
    assert rec["stashSha"]
    # The commit object must really contain the change, not merely exist.
    blob = _git(repo, "show", f"{rec['stashSha']}:tracked.txt")
    assert blob == "modified"


def test_commits_are_recorded_as_the_involuntary_answer(repo: Path) -> None:
    """Owner ruling 2026-08-14 demoted the voluntary declared half.

    So the record has to answer "what was this seat doing" without anyone declaring anything, and
    commit subjects are what it answers with: written as a side effect of working, dated, and
    describing what was DONE rather than intended.
    """
    _git(repo, "checkout", "-qb", "feature")
    (repo / "tracked.txt").write_text("work\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "do the thing")
    # merge-base resolves against origin/main; without a remote there is none, so pin one locally.
    _git(repo, "update-ref", "refs/remotes/origin/main", _git(repo, "rev-parse", "main"))

    rec = _write_record(repo, "sess-commits")
    assert any("do the thing" in c for c in rec["commits"])
    assert "tracked.txt" in rec["touchedPaths"]


def test_inherited_allocations_are_not_attributed_to_this_episode(repo: Path) -> None:
    """A worktree PATH outlives the session that occupied it.

    Measured on the first record this writer ever produced: 18 backlog allocations resolved to the
    writing worktree, the oldest claimed eight days earlier by a different session in the same
    directory. Handing those to a replacement as "yours" would have it rehome ledger numbers
    belonging to work that finished last week.
    """
    alloc = repo / ".git" / "mefor-coord" / "alloc" / "backlog"
    alloc.mkdir(parents=True)
    (alloc / "9001.json").write_text(
        json.dumps(
            {
                "number": "9001",
                "kind": "backlog",
                "worktree": str(repo).replace("\\", "/"),
                "claimed": "2020-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    rec = _write_record(repo, "sess-alloc")

    got = [a for a in rec["allocations"] if a["number"] == "9001"]
    assert got, "the allocation must still be REPORTED -- it does sit in this worktree"
    assert got[0]["attribution"] == "worktree-inherited", (
        "an allocation predating this episode must never be attributed to it"
    )


def test_receipt_reports_examined_not_merely_found(repo: Path) -> None:
    """An empty roster and a dead writer produce the same output unless the receipt says otherwise.

    The reader of this output is by construction the person least equipped to notice -- they are
    reading it because they lost the context that would have told them.
    """
    _write_record(repo, "sess-receipt")
    r = _pwsh(FLEET, "-Json", cwd=repo)
    payload = json.loads(r.stdout)

    for key in (
        "rootsExamined",
        "fenceAvailable",
        "recordsExamined",
        "recordsUnreadable",
        "liveSessionsWithoutRecord",
        "writerHeartbeatIn",
        "originMainAgeMinutes",
        "stopConditions",
    ):
        assert key in payload["receipt"], f"receipt must report {key}"
    assert payload["receipt"]["recordsExamined"] == 1


def test_writer_heartbeat_is_separate_from_having_something_to_say(repo: Path) -> None:
    """ "The writer ran" and "the seat had output" are different sentences.

    A reader that cannot separate them reads a silently disabled hook as an idle fleet, and hooks are
    disabled silently by ``disableAllHooks``, org policy and workspace trust alike.
    """
    _pwsh(SEAT, "-Record", cwd=repo)
    alive = repo / ".git" / "mefor-coord" / "seats" / ".writer-alive"
    assert list(alive.glob("*.txt")), "every invocation must leave a heartbeat"


def test_bad_worktree_writes_nothing_rather_than_a_junk_box(repo: Path, tmp_path: Path) -> None:
    """A git-resolution failure is a NO-WRITE path, never an empty-key path.

    ``mail.ps1`` records that the unguarded version of this "silently mints a NEW box that no reader
    will ever drain", and 11 of 29 mailboxes on one live box were that residue.
    """
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    r = _pwsh(SEAT, "-Record", cwd=outside)
    assert r.returncode == 0, "must not take the session's Stop hook down with it"
    assert not (outside / ".git").exists()
