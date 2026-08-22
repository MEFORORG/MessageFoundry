# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the two signals ``scripts/coord/overlap.ps1`` reports per file.

``Files`` is the UNION of what a branch committed-and-has-not-landed with what is dirty in its tree.
That union is right for the human report and wrong for a gate, which needs to know whether someone is
editing the file *now*. ``Dirty`` and the per-query ``MatchedDirty`` carry that distinction.

**The case these exist for is the one that fails SILENT.** A live session whose file is dirty *and*
committed at once -- uncommitted edits in one region, landed work in another -- is a genuine collision.
If ``MatchedDirty`` were computed from the committed diff rather than the working tree it would read
false there, the gate would allow the edit, and two sessions would write the same file with nothing
reported. An over-block is loud and annoying; this would be quiet and cost someone their work.

The second half of this file asks a different question about the same field: not *which* signal a file
matched, but whether the peer is the one who put it there at all. ``Files``' committed half is a set
difference against ``origin/main``, which credits a peer with every commit on its branch -- including
the ones it inherited from the worktree asking the question.

Driven against a REAL git fixture, because the question is entirely about what git reports: a test
using stub rows would only assert that the plumbing carries a value someone else computed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
OVERLAP = ROOT / "scripts" / "coord" / "overlap.ps1"
TIMEOUT = 45

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="overlap.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def peer_worktree(tmp_path: Path) -> tuple[Path, Path]:
    """A primary tracking origin/main, plus a linked worktree acting as another session's checkout."""
    origin = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True, capture_output=True
    )
    primary = tmp_path / "primary"
    primary.mkdir()
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(primary)], check=True, capture_output=True
    )
    git(primary, "config", "user.email", "t@example.invalid")
    git(primary, "config", "user.name", "t")
    for name in ("alpha.txt", "beta.txt"):
        (primary / name).write_text("base\n", encoding="utf-8")
    git(primary, "add", "-A")
    git(primary, "commit", "-qm", "base")
    git(primary, "remote", "add", "origin", str(origin))
    git(primary, "push", "-q", "origin", "main")

    peer = tmp_path / "peer-wt"
    git(primary, "worktree", "add", "-q", "-b", "peer-branch", str(peer))
    return primary, peer


def query(primary: Path, tmp_path: Path, path: str) -> list[dict[str, Any]]:
    """Ask overlap.ps1 about ONE file, from the primary's perspective, bypassing the cache."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(OVERLAP),
            "-Repo",
            str(primary),
            "-File",
            path,
            "-Json",
            "-Refresh",
            "-ConfigRoot",
            str(tmp_path / "no-such-config"),
            "-TasksDir",
            str(tmp_path / "no-such-tasks"),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"overlap exited {proc.returncode}: {proc.stderr}"
    out = proc.stdout.strip()
    parsed: list[dict[str, Any]] = json.loads(out) if out else []
    return parsed


def test_a_file_dirty_and_committed_at_once_reports_matcheddirty(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    """THE SILENT-FAILURE CASE. Raised by a session that spent an evening in exactly this state.

    The peer has COMMITTED a change to alpha.txt and then made a further UNCOMMITTED edit to it. It is
    simultaneously in the committed-and-unlanded set and in the working tree. If MatchedDirty were
    derived from the committed diff it would read false, the gate would allow, and two sessions would
    edit one file with nothing reported -- a quiet loss rather than a loud refusal.
    """
    primary, peer = peer_worktree
    (peer / "alpha.txt").write_text("base\ncommitted change\n", encoding="utf-8")
    git(peer, "add", "alpha.txt")
    git(peer, "commit", "-qm", "committed work on alpha")
    (peer / "alpha.txt").write_text("base\ncommitted change\nUNSAVED EDIT\n", encoding="utf-8")

    rows = query(primary, tmp_path, "alpha.txt")
    assert rows, "overlap reported nothing for a file the peer is changing"
    row = rows[0]
    assert "alpha.txt" in row["Dirty"], f"Dirty must carry the working-tree edit: {row['Dirty']}"
    assert row["MatchedDirty"] is True, (
        "dirty-AND-committed must report MatchedDirty, or the gate allows a real collision"
    )


def test_a_committed_and_clean_file_does_not_report_matcheddirty(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    """The over-block that was actually reported: committed, tree clean, session done with the file."""
    primary, peer = peer_worktree
    (peer / "beta.txt").write_text("base\ncommitted change\n", encoding="utf-8")
    git(peer, "add", "beta.txt")
    git(peer, "commit", "-qm", "committed work on beta")

    rows = query(primary, tmp_path, "beta.txt")
    assert rows, "a committed file should still be REPORTED, just not as an active edit"
    row = rows[0]
    assert row["MatchedDirty"] is False
    assert "beta.txt" not in (row["Dirty"] or [])
    assert "beta.txt" in row["Files"], "it must remain in Files -- the peer did author it"


def test_an_uncommitted_only_file_reports_matcheddirty(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    primary, peer = peer_worktree
    (peer / "alpha.txt").write_text("base\nunsaved only\n", encoding="utf-8")

    rows = query(primary, tmp_path, "alpha.txt")
    assert rows
    assert rows[0]["MatchedDirty"] is True


def test_an_untouched_file_is_not_reported(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    primary, peer = peer_worktree
    (peer / "alpha.txt").write_text("base\nunsaved only\n", encoding="utf-8")
    assert query(primary, tmp_path, "beta.txt") == []


# --------------------------------------------- whose commit is it? (attribution of the committed half)
#
# Measured 2026-08-22. The gate told a session that ``scripts/coord/handoff.ps1`` had been "CHANGED AND
# COMMITTED" on a peer's branch and to "check its commits before you duplicate or revert it". The peer
# had never touched the file in any commit it owned: the blob was byte-identical across the peer's whole
# branch, and the single commit that authored it was one the READER had written and the peer had merely
# inherited by being cut from the reader's own work.
#
# So the reader went looking for a peer's conflicting commit, found only their own, and had no way to
# read that except as the gate being broken. That is how a gate stops being read, and then gets
# uninstalled -- collision_gate.ps1's own docstring names that as its failure mode.
#
# The committed half is intersect(origin/main...HEAD, origin/main..HEAD), both evaluated inside the PEER
# worktree. Neither term knows anything about the querying session, so a commit the querier authored is
# indistinguishable from one the peer authored. The remedy is a THIRD intersect term anchored on the
# querying worktree's own HEAD; the two origin/main anchors must stay, because they are what makes the
# set self-clear when a branch lands by squash-merge (pinned below).


@pytest.fixture
def shared_history(tmp_path: Path) -> tuple[Path, Path]:
    """A peer cut FROM the querying worktree's HEAD, so the two share a commit that authored a file.

    Three files with three different provenances, which is what makes the fixture discriminating:
    ``shared.txt`` comes from a commit BOTH have, ``peer_only.txt`` from a commit only the peer has,
    and ``alpha.txt`` is uncommitted in the peer's tree. A fixture that branched at ``origin/main``
    (as ``peer_worktree`` above does) cannot separate them at all.
    """
    origin = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True, capture_output=True
    )
    primary = tmp_path / "primary"
    primary.mkdir()
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(primary)], check=True, capture_output=True
    )
    git(primary, "config", "user.email", "t@example.invalid")
    git(primary, "config", "user.name", "t")
    for name in ("alpha.txt", "beta.txt"):
        (primary / name).write_text("base\n", encoding="utf-8")
    git(primary, "add", "-A")
    git(primary, "commit", "-qm", "base")
    git(primary, "remote", "add", "origin", str(origin))
    git(primary, "push", "-q", "origin", "main")

    # THE SHARED COMMIT: authored here, ahead of origin/main, and inherited by the peer below.
    (primary / "shared.txt").write_text("mine\n", encoding="utf-8")
    git(primary, "add", "shared.txt")
    git(primary, "commit", "-qm", "work the querying session authored")

    peer = tmp_path / "peer-wt"
    git(primary, "worktree", "add", "-q", "-b", "peer-branch", str(peer))  # from the primary's HEAD
    (peer / "peer_only.txt").write_text("theirs\n", encoding="utf-8")
    git(peer, "add", "peer_only.txt")
    git(peer, "commit", "-qm", "work only the peer authored")
    (peer / "alpha.txt").write_text("base\nunsaved\n", encoding="utf-8")
    return primary, peer


def test_a_commit_the_querying_worktree_already_has_is_not_credited_to_the_peer(
    shared_history: tuple[Path, Path], tmp_path: Path
) -> None:
    """THE FALSE POSITIVE. Sending a reader to audit their own commit is worse than saying nothing."""
    primary, _peer = shared_history
    assert query(primary, tmp_path, "shared.txt") == [], (
        "the peer was credited with a file whose only commit is one the querying worktree already "
        "has, so 'check its commits' sends the reader to their own work"
    )


def test_a_commit_only_the_peer_has_is_still_reported(
    shared_history: tuple[Path, Path], tmp_path: Path
) -> None:
    """NEGATIVE CONTROL. Without it, "stop reporting committed files" passes the test above."""
    primary, _peer = shared_history
    rows = query(primary, tmp_path, "peer_only.txt")
    assert rows, "a file the peer committed on its OWN commit is real, actionable overlap"
    assert "peer_only.txt" in rows[0]["Files"]


def test_an_uncommitted_peer_edit_is_never_filtered(
    shared_history: tuple[Path, Path], tmp_path: Path
) -> None:
    """The dirty half must not be narrowed by ANY ancestry rule: somebody is typing in it now.

    ``alpha.txt`` is untouched by every commit in this fixture, so it survives only if the working-tree
    signal is unioned in after the committed half is filtered -- which is also why the filter has to go
    before that union and not after. Applied after, it would drop the whole ROW and take the gate's
    deny path down with it, turning a false-positive fix into a silent missed collision.
    """
    primary, _peer = shared_history
    rows = query(primary, tmp_path, "alpha.txt")
    assert rows, "an uncommitted peer edit is always a collision"
    assert rows[0]["MatchedDirty"] is True
    assert "alpha.txt" in rows[0]["Files"]


def test_a_branch_that_landed_by_squash_merge_still_self_clears(tmp_path: Path) -> None:
    """REGRESSION PIN on the property the narrowing above must not cost.

    This repo squash-merges, so a landed branch's commit never becomes an ancestor of anything: the
    merge base never advances and ``origin/main...HEAD`` keeps crediting it with its files forever,
    blocking that file set until someone prunes the worktree. Only the two-dot term clears it, and only
    because it is anchored on ``origin/main``. Re-anchoring either existing term on the querying HEAD
    would suppress the reported false positive too -- and silently restore this one. Measured
    2026-07-30 and never pinned by a test until now.
    """
    origin = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True, capture_output=True
    )
    primary = tmp_path / "primary"
    primary.mkdir()
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(primary)], check=True, capture_output=True
    )
    git(primary, "config", "user.email", "t@example.invalid")
    git(primary, "config", "user.name", "t")
    (primary / "alpha.txt").write_text("base\n", encoding="utf-8")
    git(primary, "add", "-A")
    git(primary, "commit", "-qm", "base")
    git(primary, "remote", "add", "origin", str(origin))
    git(primary, "push", "-q", "origin", "main")

    peer = tmp_path / "peer-wt"
    git(primary, "worktree", "add", "-q", "-b", "peer-branch", str(peer))
    (peer / "gamma.txt").write_text("landed work\n", encoding="utf-8")
    git(peer, "add", "gamma.txt")
    git(peer, "commit", "-qm", "work that is about to land")

    # LAND IT THE WAY THIS REPO LANDS THINGS: squashed, so the peer's commit is not an ancestor.
    git(primary, "merge", "--squash", "peer-branch")
    git(primary, "commit", "-qm", "work that is about to land (#1)")
    git(primary, "push", "-q", "origin", "main")
    assert (
        subprocess.run(
            [
                "git",
                "-C",
                str(primary),
                "merge-base",
                "--is-ancestor",
                "peer-branch",
                "origin/main",
            ],
            capture_output=True,
            timeout=TIMEOUT,
            check=False,
        ).returncode
        != 0
    ), (
        "the fixture did not actually squash -- the peer's commit IS an ancestor, so nothing is pinned"
    )

    assert query(primary, tmp_path, "gamma.txt") == [], (
        "a branch whose work has landed is still credited with its files, so its session blocks that "
        "file set indefinitely"
    )


def raw_query(primary: Path, tmp_path: Path, path: str) -> str:
    """The same query, but returning stdout VERBATIM -- ``query`` above maps '' to [] and would hide
    the very difference under test."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(OVERLAP),
            "-Repo",
            str(primary),
            "-File",
            path,
            "-Json",
            "-Refresh",
            "-ConfigRoot",
            str(tmp_path / "no-such-config"),
            "-TasksDir",
            str(tmp_path / "no-such-tasks"),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"overlap exited {proc.returncode}: {proc.stderr}"
    return proc.stdout.strip()


def raw_survey(primary: Path, tmp_path: Path) -> str:
    """The WHOLE-MAP -Json query, verbatim. A different call site from ``raw_query``, and it fails
    differently: this one is fed ``Build-Map``'s return value, which is AutomationNull when empty."""
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(OVERLAP),
            "-Repo",
            str(primary),
            "-Json",
            "-Refresh",
            "-ConfigRoot",
            str(tmp_path / "no-such-config"),
            "-TasksDir",
            str(tmp_path / "no-such-tasks"),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"overlap exited {proc.returncode}: {proc.stderr}"
    return proc.stdout.strip()


def test_the_whole_map_json_query_emits_no_phantom_row(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    """A ZERO-ROW ANSWER MUST BE ZERO ROWS, not one null one.

    ``Build-Map`` returns AutomationNull when it has no rows, and parameter binding converts that to a
    real ``$null`` at the call -- where ``@($null).Count`` is 1, not 0. So a naive "if empty print []"
    guard is dead in precisely the case it exists for, and the query emits ``[null]``: a phantom row,
    strictly worse for any consumer that counts or indexes than the nothing it replaced.
    """
    primary, _peer = (
        peer_worktree  # peer worktree exists but is clean, and no session is registered
    )
    out = raw_survey(primary, tmp_path)
    assert out == "[]", f"a no-rows map must be an empty array, not {out!r}"
    assert json.loads(out) == []


def test_a_json_query_always_emits_an_array(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    """AN ANSWER OF "NOBODY" MUST NOT LOOK LIKE NO ANSWER.

    ``@() | ConvertTo-Json -AsArray`` sends zero objects down the pipeline, so ConvertTo-Json never runs
    and the script printed NOTHING -- ``-AsArray`` only shapes output that exists. On stdout that is
    byte-for-byte what a script dying before it answers looks like, so no consumer could separate an
    all-clear from a failure. The collision gate consumes this on every Edit and Write; measured
    2026-08-02, the gate reported "could not check" on an ordinary edit to an untouched file because of
    exactly this.
    """
    primary, peer = peer_worktree
    (peer / "alpha.txt").write_text("base\nunsaved\n", encoding="utf-8")

    assert raw_query(primary, tmp_path, "beta.txt") == "[]", "a no-hit query must still answer"
    hit = raw_query(primary, tmp_path, "alpha.txt")
    assert hit.startswith("["), f"a hit must be an array too, not a bare object: {hit[:80]}"
    assert json.loads(hit), "and it must parse with at least one row"


def test_overlap_does_not_rewrite_a_peers_git_index(
    peer_worktree: tuple[Path, Path], tmp_path: Path
) -> None:
    """An observer must not perturb what it observes.

    A plain ``git status`` REWRITES the index of the repo it inspects, and overlap walks every peer
    worktree on a PreToolUse hook -- so merely asking "what is in flight" was mutating other sessions'
    checkouts. Fixed with --no-optional-locks; pinned here so it cannot silently regress.
    """
    primary, peer = peer_worktree
    (peer / "alpha.txt").write_text("base\nunsaved\n", encoding="utf-8")
    index = Path(git(peer, "rev-parse", "--path-format=absolute", "--git-dir").strip()) / "index"
    query(primary, tmp_path, "alpha.txt")  # warm any lazy refresh, then measure
    before = index.stat().st_mtime_ns
    query(primary, tmp_path, "alpha.txt")
    assert index.stat().st_mtime_ns == before, "overlap rewrote a peer worktree's git index"
