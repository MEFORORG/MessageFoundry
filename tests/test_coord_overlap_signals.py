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


# ------------------------------------------------ the walk has a budget, and blowing it is not silent
#
# THE COST IS PROCESS COUNT. This walk spawns one git per diff term per worktree, so it scales with how
# many worktrees exist rather than with how much work is in them. Measured 2026-08-22 at 73 worktrees:
# 11.4s for the two origin/main terms, 14.6s once a third term was evaluated per peer, 12.0s with that
# term gated on one up-front `for-each-ref`. collision_gate.ps1 runs this on every Edit and Write under
# a harness timeout of 20s, and when that timeout fires the HOOK is killed -- so it emits nothing, and
# empty stdout from a PreToolUse hook is byte-identical to "checked, nobody else is touching this file".
# That is the one failure the gate cannot narrate, because it is no longer running when it happens.
#
# -TimeBudgetSeconds moves the bail INSIDE the walk, where it can still be reported. The properties
# under test are not the timing. They are:
#
#   1. an overrun exits 3 and writes NO cache -- a stored under-report would answer every query for the
#      whole window as though the walk had finished;
#   2. the rows the walk DID reach are returned, every one of them stamped Partial/Walked/Total;
#   3. a walk that reached NOTHING prints nothing, never "[]", so "[]" keeps meaning exactly one thing:
#      a COMPLETE walk that found nobody.
#
# The rows used to be withheld too, on the reasoning that half a walk under-reports. It does, and the
# conclusion still did not follow: discarding them does not finish the walk, it only loses the peers
# already found. Measured 2026-08-30 at 162 worktrees, the walk took 26.1s against the gate's 16s budget
# and bailed on five runs of five, so the gate spent that period allowing edits against a map it had
# been handed and dropped. A partial map may ADD a warning and never remove one; property 3 and the
# exit code are what stop it being read as an all-clear.


def _budgeted(
    primary: Path, tmp_path: Path, budget: str, parallel: str | None = None
) -> subprocess.CompletedProcess[str]:
    """The whole-map query with a walk budget, WITHOUT asserting the exit code -- that is the subject."""
    args = [
        "pwsh",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(OVERLAP),
        "-Repo",
        str(primary),
        "-Json",
        "-Refresh",
        "-TimeBudgetSeconds",
        budget,
        "-ConfigRoot",
        str(tmp_path / "no-such-config"),
        "-TasksDir",
        str(tmp_path / "no-such-tasks"),
    ]
    if parallel is not None:
        args += ["-ParallelLimit", parallel]
    return subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT, check=False)


@pytest.fixture
def many_peers(tmp_path: Path) -> Path:
    """A dozen peers, so a budget has somewhere to stop that is neither the start nor the end.

    ``three_peers`` cannot serve here: with three worktrees a walk either bails before the first or
    finishes, and the interesting state -- some reached, some not -- has almost no window to land in.
    """
    origin = tmp_path / "origin-many.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True, capture_output=True
    )
    primary = tmp_path / "primary-many"
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
    for n in range(12):
        peer = tmp_path / f"many-{n}"
        git(primary, "worktree", "add", "-q", "-b", f"many-{n}", str(peer))
        (peer / f"file-{n}.txt").write_text("theirs\n", encoding="utf-8")
        git(peer, "add", "-A")
        git(peer, "commit", "-qm", f"peer {n} work")
    return primary


@pytest.fixture
def three_peers(tmp_path: Path) -> Path:
    """A primary with three peer worktrees, each carrying a commit -- enough git spawns to overrun."""
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
    for n in range(3):
        peer = tmp_path / f"peer-{n}"
        git(primary, "worktree", "add", "-q", "-b", f"peer-{n}", str(peer))
        (peer / f"file-{n}.txt").write_text("theirs\n", encoding="utf-8")
        git(peer, "add", "-A")
        git(peer, "commit", "-qm", f"peer {n} work")
    return primary


def test_a_generous_budget_still_returns_the_whole_map(three_peers: Path, tmp_path: Path) -> None:
    """CONTROL. Without it, a bail on every run would satisfy the test below."""
    proc = _budgeted(three_peers, tmp_path, "60")
    assert proc.returncode == 0, f"exited {proc.returncode}: {proc.stderr}"
    rows = json.loads(proc.stdout.strip())
    assert len(rows) == 3, f"expected all three peers, got {[r['Worktree'] for r in rows]}"


def _cache_path(primary: Path) -> Path:
    common = git(primary, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return Path(common) / "mefor-coord" / "overlap-cache.json"


def test_a_walk_that_reaches_nothing_prints_nothing_rather_than_an_empty_array(
    three_peers: Path, tmp_path: Path
) -> None:
    """THE INVARIANT EVERY OTHER PARTIAL-MAP RULE RESTS ON.

    ``[]`` is the literal all-clear, so a walk that checked nobody must never be able to render as one.
    A budget this small bails before the first worktree, leaving no rows to stamp -- and an unstamped
    empty array is indistinguishable from a complete walk that found nobody.
    """
    cache = _cache_path(three_peers)
    assert not cache.exists(), (
        "the fixture must start with no cache, or the assertion below is blind"
    )
    proc = _budgeted(three_peers, tmp_path, "0.01")
    assert proc.returncode == 3, f"expected the budget exit, got {proc.returncode}: {proc.stderr}"
    assert proc.stdout.strip() == "", f"an unstamped map was printed anyway:\n{proc.stdout}"
    assert not cache.exists(), (
        "an abandoned walk was cached, pinning the under-report for the window"
    )


def test_a_partial_walk_returns_what_it_reached_and_stamps_every_row(
    many_peers: Path, tmp_path: Path
) -> None:
    """THE ROWS THAT USED TO BE THROWN AWAY, and the label that stops them reading as the whole map.

    The budget is SEARCHED FOR rather than hardcoded, because it cannot be derived from the wall clock:
    the budget covers the walk only, while the measurable time also carries a pwsh start and the session
    registry, which together outweigh a twelve-peer walk. So the test steps the budget down until the
    walk lands part-way, and fails if no budget ever does -- which is the honest failure, since a script
    that could never return a partial map is exactly what this asserts against.
    """
    full = _budgeted(many_peers, tmp_path, "0")
    assert full.returncode == 0, f"the control walk failed: {full.stderr}"
    total = len(json.loads(full.stdout.strip()))
    assert total >= 8, f"the fixture must give the budget something to run out of, got {total}"

    # CONTROL: a COMPLETE walk carries no stamp at all. Without this the assertions below are satisfied
    # by a script that marks every map partial, which would be a different lie in the same field.
    for row in json.loads(full.stdout.strip()):
        assert "Partial" not in row, f"a complete walk stamped itself partial: {row}"

    # SERIAL, so the budget divides the work in a straight line. Under a parallel walk the same budget
    # can still let every worktree through, because they are not being done in sequence.
    proc = None
    for budget in ("0.40", "0.25", "0.15", "0.10", "0.06", "0.04", "0.025"):
        _cache_path(many_peers).unlink(missing_ok=True)
        candidate = _budgeted(many_peers, tmp_path, budget, parallel="1")
        if candidate.returncode == 3 and candidate.stdout.strip():
            proc = candidate
            break
    assert proc is not None, (
        "no budget produced a partial map with rows in it -- either the walk never bails part-way, "
        "or it still discards the peers it reached"
    )
    rows = json.loads(proc.stdout.strip())
    for row in rows:
        assert row.get("Partial") is True, f"a partial row was not stamped: {row}"
        assert row["Total"] > row["Walked"], (
            f"a partial walk claimed full coverage: walked {row['Walked']} of {row['Total']}"
        )
    assert not _cache_path(many_peers).exists(), (
        "an abandoned walk was cached, pinning the under-report for the window"
    )


def test_the_serial_and_parallel_walks_produce_the_same_map(
    many_peers: Path, tmp_path: Path
) -> None:
    """THE PARALLEL WALK IS AN OPTIMISATION, so it has to be invisible in the answer.

    Runspaces return in completion order, and rows that shuffle between runs read as churn to anyone
    diffing two maps -- so the comparison is on the ORDERED text, not on a set.
    """
    _cache_path(many_peers).unlink(missing_ok=True)
    one = _budgeted(many_peers, tmp_path, "0", parallel="1")
    _cache_path(many_peers).unlink(missing_ok=True)
    many = _budgeted(many_peers, tmp_path, "0", parallel="8")
    assert one.returncode == 0 and many.returncode == 0, f"{one.stderr}\n{many.stderr}"
    assert one.stdout.strip() == many.stdout.strip(), (
        "the parallel walk changed the map it was supposed to only speed up"
    )


def test_the_term_memo_does_not_change_the_answer(many_peers: Path, tmp_path: Path) -> None:
    """A COLD AND A WARM WALK MUST AGREE, or the memo is answering a question it was not asked.

    The memo skips three of the four git spawns per worktree on a hit, keyed on the commit ids those
    diffs read. A key that omitted an input would show up here as a second walk disagreeing with the
    first -- which is the only failure mode a content-addressed cache has.
    """
    common = Path(
        git(many_peers, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    )
    memo = common / "mefor-coord" / "overlap-terms.json"
    memo.unlink(missing_ok=True)
    _cache_path(many_peers).unlink(missing_ok=True)

    cold = _budgeted(many_peers, tmp_path, "0")
    assert cold.returncode == 0, f"the cold walk failed: {cold.stderr}"
    assert memo.exists(), "the walk never wrote a term memo, so the warm run below proves nothing"

    _cache_path(many_peers).unlink(missing_ok=True)
    warm = _budgeted(many_peers, tmp_path, "0")
    assert warm.returncode == 0, f"the warm walk failed: {warm.stderr}"
    assert cold.stdout.strip() == warm.stdout.strip(), "the memo changed the map it replayed"
