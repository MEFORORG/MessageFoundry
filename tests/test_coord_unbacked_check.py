# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The unbacked-work check must answer the question it is read as answering.

Every test here pins a mistake that was actually made, not one that was imagined.

**Per REF, never per HEAD.** ``git rev-list --count HEAD --not --remotes`` run per worktree returned
0 for every repository on the machine, and that was reported as "nothing single-copy anywhere". The
same machine held 802 unbacked commits across 239 branches. A branch no worktree has checked out is
invisible to a HEAD-based sweep, and that is the normal state of most branches, so the failure is
silent and total rather than partial.

**Configured is not reachable.** ``--not --remotes`` excludes everything reachable from
``refs/remotes/*``, which are LOCAL COPIES. A repository whose origin no longer answers reported
"0 unbacked commits" across 7 refs while every one of those commits existed on exactly one disk. A
check that cannot tell must not print the word that means it can, so this reports UNVERIFIABLE and
fails rather than reporting clean.

**Coverage is a first-class output.** A run that examined nothing and a run that examined everything
must not print the same reassuring line, so the coverage line is asserted even on the clean path.

The fixtures build throwaway repositories under ``tmp_path`` and never touch the real ``.git/hooks``
or the live claim registry: the engine suite runs under ``pytest-xdist`` at ``-n 4 --dist loadfile``,
so four workers would race any shared state. Nothing here asserts on elapsed time for the same
reason.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "coord" / "unbacked_check.ps1"
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="unbacked_check.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


def check(*paths: Path, extra: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [
        "pwsh",
        "-NoProfile",
        "-File",
        str(CHECK),
        "-Path",
        ",".join(str(p) for p in paths),
    ]
    if extra:
        cmd.extend(extra)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)


def _bare(path: Path, head: str = "main") -> Path:
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", head, str(path)], check=True, capture_output=True
    )
    return path


def _commit(repo: Path, name: str, text: str, msg: str) -> None:
    (repo / name).write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", msg)


def _squash_land(repo: Path, text: str) -> None:
    """Branch ``side`` gets one commit; ``main`` gets the same CONTENT as a different commit -- what
    a squash-merge produces -- and is pushed to origin. HEAD is left on main."""
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", text, "work")
    git(repo, "checkout", "-q", "main")
    _commit(repo, "g.txt", text, "squashed: work")
    git(repo, "push", "-q", "origin", "main")


@pytest.fixture
def origin(tmp_path: Path) -> Path:
    """A bare repo standing in for a reachable remote. Local, so no network in the suite."""
    return _bare(tmp_path / "origin.git")


@pytest.fixture
def repo(tmp_path: Path, origin: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    (r / "f.txt").write_text("base", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    git(r, "remote", "add", "origin", str(origin))
    git(r, "push", "-q", "origin", "main")
    git(r, "fetch", "-q", "origin")
    return r


def test_a_pushed_branch_reads_clean_and_still_states_its_coverage(repo: Path) -> None:
    """The negative control. Without it, a check that always says 'unbacked' would pass every other
    test here."""
    r = check(repo)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "0 unbacked commits" in r.stdout
    # A bare "clean" is indistinguishable from a run that scanned nothing. This is the assertion that
    # makes the clean path trustworthy.
    assert "coverage :" in r.stdout
    # Refs AND worktrees, deliberately: a single count cannot say which of the two it meant, and the
    # gap between them is where a detached HEAD hides.
    assert "1 refs and" in r.stdout
    # "incl. primary" is asserted deliberately: git worktree list registers the primary checkout, so
    # two people counting worktrees differ by one and each thinks the other found something.
    assert "worktree checkouts (incl. primary) across 1 repository" in r.stdout
    assert "1 worktree checkouts" in r.stdout


def test_a_branch_no_worktree_has_checked_out_is_still_counted(repo: Path) -> None:
    """THE REGRESSION. HEAD stays on main throughout; the unbacked work is on a branch that is never
    checked out, which is exactly what a per-HEAD sweep cannot see."""
    git(repo, "checkout", "-q", "-b", "side")
    (repo / "g.txt").write_text("side work", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "unpushed on side")
    # Leave HEAD back on main, which IS pushed. `side` now holds work no checkout points at -- the
    # ordinary state of a branch, and the one a per-HEAD sweep cannot see.
    git(repo, "checkout", "-q", "main")

    # HEAD is back on main, which IS pushed. A per-HEAD check reports clean here.
    assert git(repo, "rev-list", "--count", "HEAD", "--not", "--remotes").strip() == "0"

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "side" in r.stdout
    assert "1 commits on 1 branch exist on no remote" in r.stdout


def test_a_detached_worktree_head_is_counted(repo: Path, tmp_path: Path) -> None:
    """THE THIRD REGRESSION, and the one a per-ref fix does not cover. A worktree with a detached
    HEAD is on no branch, so scanning refs/heads cannot reach it however thorough that scan is.
    Measured 2026-08-16: 23 of 44 registered worktrees were detached and 11 carried 30 commits on no
    remote while this script reported zero."""
    git(repo, "checkout", "-q", "-b", "tmpwork")
    (repo / "d.txt").write_text("detached work", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "work that will be left detached")
    sha = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "checkout", "-q", "main")
    # Delete the branch so the commit is reachable ONLY from the worktree's detached HEAD -- the
    # exact shape that made this invisible.
    git(repo, "branch", "-qD", "tmpwork")
    wt = tmp_path / "detached-wt"
    git(repo, "worktree", "add", "--detach", str(wt), sha)

    # Every branch is pushed, so a ref-only scan sees nothing.
    for ref in git(repo, "for-each-ref", "--format=%(refname)", "refs/heads").splitlines():
        assert git(repo, "rev-list", "--count", ref.strip(), "--not", "--remotes").strip() == "0"

    res = check(repo)
    assert res.returncode == 1, res.stdout + res.stderr
    assert "detached" in res.stdout
    # Coverage must name refs AND worktrees; one number hides which of the two it meant.
    assert "worktree checkouts" in res.stdout


def test_a_repo_with_no_remote_at_all_is_reported_not_skipped(tmp_path: Path) -> None:
    r = tmp_path / "lonely"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "only copy")

    res = check(r)
    assert res.returncode == 1, res.stdout + res.stderr
    assert "NO-REMOTE" in res.stdout
    # The remedy differs from an ordinary unpushed branch, so the wording must too.
    assert "needs a remote first" in res.stdout


def test_an_unreachable_remote_is_unverifiable_not_clean(repo: Path, tmp_path: Path) -> None:
    """The false negative that shipped in the first version of this script: a repository whose remote
    no longer answers reported 0 unbacked, because refs/remotes/* still excluded everything."""
    git(repo, "remote", "set-url", "origin", str(tmp_path / "gone.git"))

    res = check(repo)
    assert res.returncode == 1, res.stdout + res.stderr
    assert "UNVERIFIABLE" in res.stdout
    assert "NONE reachable" in res.stdout
    # The distinguishing assertion: it must NOT claim cleanliness it cannot establish.
    assert "0 unbacked commits" not in res.stdout


def test_skipping_reachability_says_so_rather_than_meaning_something_else(
    repo: Path, tmp_path: Path
) -> None:
    git(repo, "remote", "set-url", "origin", str(tmp_path / "gone.git"))

    res = check(repo, extra=["-SkipReachability"])
    # Without the probe it cannot detect the dead remote, so it reports clean -- but it must say that
    # reachability was not checked, or the operator reads a weaker result as the stronger one.
    assert "reachability NOT checked" in res.stdout


def test_a_comma_list_through_dash_file_is_split(repo: Path, tmp_path: Path) -> None:
    """`pwsh -File` hands a comma list over as ONE string. The script errored with
    "Path does not exist: 'a','b'" instead of scanning either."""
    second = tmp_path / "second"
    second.mkdir()
    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(second)], check=True, capture_output=True
    )
    git(second, "config", "user.email", "t@example.invalid")
    git(second, "config", "user.name", "t")
    (second / "f.txt").write_text("x", encoding="utf-8")
    git(second, "add", "-A")
    git(second, "commit", "-qm", "base")

    res = check(repo, second)
    assert "Path does not exist" not in res.stdout + res.stderr
    assert "2 repositories" in res.stdout


# --- BACKLOG #1299: content-durability classification -------------------------------------------
#
# `--not --remotes` answers "does this COMMIT OBJECT exist on a remote". The reader asks "is any WORK
# at risk". Measured on the fleet box 2026-08-23, EVERY alarm was that divergence -- 8 of 8 -- and the
# remedy the script printed would have force-pushed rescue tags for work already on `main`.
#
# The four tests below are two PAIRS. Each must-not-trip arm has a must-trip twin that differs by the
# one property the classification turns on, because a classifier that suppressed everything would pass
# the must-not-trip arms alone.


def test_a_squash_landed_branch_is_reclassified_not_alarmed(repo: Path) -> None:
    """MUST NOT TRIP. The squash-merge case: `main` carries the CONTENT under a different sha, so the
    branch points at an object on no remote while nothing is at risk."""
    _squash_land(repo, "landed")
    git(repo, "fetch", "-q", "origin")

    r = check(repo)
    assert "0 unbacked commits" in r.stdout, r.stdout + r.stderr
    assert r.returncode == 0, r.stdout + r.stderr
    # The reclassification must be VISIBLE. A silent one is how a real alarm gets suppressed with
    # nobody aware the mechanism exists.
    assert "durable  :" in r.stdout
    assert "squash/rebase-landed" in r.stdout


def test_genuinely_unpushed_work_still_trips(repo: Path) -> None:
    """MUST TRIP -- the twin of the test above, differing only in that the content is nowhere else.
    Without this, a classifier that suppressed every finding would pass its partner."""
    git(repo, "checkout", "-q", "-b", "side")
    (repo / "g.txt").write_text("this exists on exactly one disk", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "real work")

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "exist on no remote" in r.stdout
    assert "Remedy" in r.stdout


def test_a_clean_merge_over_backed_parents_is_reclassified(repo: Path) -> None:
    """MUST NOT TRIP. A local `merge origin/main into <branch>` makes a NEW commit whose parents are
    both backed and which contributes nothing of its own -- it is re-derivable by re-running it."""
    git(repo, "checkout", "-q", "-b", "side")
    (repo / "side.txt").write_text("side", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "side work")
    git(repo, "push", "-q", "origin", "side")
    git(repo, "checkout", "-q", "main")
    (repo / "main.txt").write_text("main", encoding="utf-8")  # a DIFFERENT file: merges cleanly
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "main work")
    git(repo, "push", "-q", "origin", "main")
    git(repo, "fetch", "-q", "origin")
    git(repo, "checkout", "-q", "side")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge main into side", "main")

    r = check(repo)
    assert "0 unbacked commits" in r.stdout, r.stdout + r.stderr
    assert r.returncode == 0, r.stdout + r.stderr
    assert "tree identical to the automatic merge" in r.stdout


def test_a_merge_carrying_a_HAND_RESOLUTION_still_trips(repo: Path) -> None:
    """MUST TRIP, AND THIS IS THE ARM THAT MAKES THE CLASSIFICATION SOUND RATHER THAN USUALLY-RIGHT.

    Its twin above differs by ONE property: there the merge was automatic, here a human resolved a
    conflict. Both parents are backed in both cases, so a 'parents are backed' test alone -- the
    obvious fix -- clears BOTH. But a hand resolution exists in NEITHER parent and nowhere else on
    earth, so clearing it would lose exactly the work this script exists to protect.

    MUTATION-VERIFIED, and the first wording of this docstring had it backwards. Replacing the tree
    comparison in `Test-CommitContentDurable` with an unconditional pass was measured: THIS test FAILS
    (the script clears the merge and returns 0 where 1 is required) while its twin above still PASSES.
    That asymmetry is the proof -- the twin alone cannot detect the missing check, so a suite holding
    only must-not-trip arms would be green over a classifier that loses hand-resolved work."""
    git(repo, "checkout", "-q", "-b", "side")
    (repo / "f.txt").write_text("side version", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "side edits f")
    git(repo, "push", "-q", "origin", "side")
    git(repo, "checkout", "-q", "main")
    (repo / "f.txt").write_text("main version", encoding="utf-8")  # SAME file: conflicts
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "main edits f")
    git(repo, "push", "-q", "origin", "main")
    git(repo, "fetch", "-q", "origin")
    git(repo, "checkout", "-q", "side")
    subprocess.run(
        ["git", "-C", str(repo), "merge", "--no-ff", "-m", "merge"], capture_output=True, text=True
    )
    subprocess.run(
        ["git", "-C", str(repo), "merge", "main"], capture_output=True, text=True, timeout=TIMEOUT
    )
    # Resolve by hand to a value in NEITHER parent. This text exists on one disk.
    (repo / "f.txt").write_text("hand-resolved: neither side nor main", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "merge main into side, resolved by hand")

    r = check(repo)
    assert r.returncode == 1, "a hand-resolved merge is NOT re-derivable\n" + r.stdout + r.stderr
    assert "exist on no remote" in r.stdout


# --- BACKLOG #1349: the printed remedy must not write an unverifiable ref -----------------------


def test_the_printed_remedy_writes_a_ref_that_can_be_VERIFIED_LATER(repo: Path) -> None:
    """The tool's own advice used to produce the defect its sibling audit reports.

    The remedy block printed a bare
    ``git push --force <remote> <branch>:refs/tags/rescue/branch/<branch>``, which writes a ref
    recording nothing about what it captured. Such a ref can only be graded against a branch that
    still exists -- and a rescue ref is read once, after the branch it names is already gone.

    Measured 2026-09-03 in the live checkout: ``rescue.ps1 -Check`` examined 1671 refs and returned
    UNVERIFIABLE for all 1671, every one of them written by a push of exactly that shape. So this
    asserts BOTH halves: the bare form is gone, and ``-Anchor`` is what replaced it. Asserting only
    that ``-Anchor`` appears would pass a block that printed both and left the reader to choose.
    """
    git(repo, "checkout", "-q", "-b", "side")
    (repo / "g.txt").write_text("this exists on exactly one disk", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "real work")

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "Remedy" in r.stdout
    assert "rescue.ps1 -Anchor" in r.stdout
    assert ":refs/tags/rescue/branch/" not in r.stdout, (
        "still printing the bare push that writes an unverifiable ref"
    )
    # The reason has to travel with the command, or the extra step reads as ceremony and gets cut.
    assert "A bare push records none of that" in r.stdout


# --- BACKLOG #5493, #5502: a multi-commit branch, and a clone with one unreachable remote ---------


def test_a_landed_OLDEST_commit_does_not_clear_the_newer_unpushed_ones(repo: Path) -> None:
    """MUST TRIP. ``git cherry <upstream> <commit>`` lists EVERY commit in ``upstream..commit``,
    oldest first. Reading its first line as the verdict for ``<commit>`` read the OLDEST commit's
    mark, so once the branch's first commit had squash-landed upstream, every newer commit on top of
    it -- work that exists on one disk -- read as patch-already-upstream and the ref was cleared.

    Its twin is ``test_a_squash_landed_branch_is_reclassified_not_alarmed``: the same landed commit
    with nothing on top must still clear."""
    _squash_land(repo, "landed")
    git(repo, "fetch", "-q", "origin")
    git(repo, "checkout", "-q", "side")
    _commit(repo, "h.txt", "this exists on exactly one disk", "newer work, never pushed anywhere")
    git(repo, "checkout", "-q", "main")

    # The premise: the oldest commit's line is '-', the newest commit's line is '+'.
    marks = git(repo, "cherry", "origin/main", "side").split()
    assert marks[0] == "-" and marks[2] == "+", marks

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "side" in r.stdout
    assert "2 commits on 1 branch exist on no remote" in r.stdout


def _add_backup_remote(repo: Path, tmp_path: Path) -> None:
    """Its HEAD names ``trunk``, which nobody pushes -- what a plain ``git init --bare`` gives when
    the pushed branch differs from the default. It answers, but advertises no HEAD, so a probe that
    read ``ls-remote --exit-code HEAD``'s exit 2 as unreachable would stop trusting it."""
    git(repo, "remote", "add", "backup", str(_bare(tmp_path / "backup.git", head="trunk")))
    git(repo, "push", "-q", "backup", "main")


@pytest.fixture
def two_remotes(repo: Path, tmp_path: Path) -> Path:
    """``repo`` with a second reachable remote, ``backup``, holding a branch that origin does not."""
    _add_backup_remote(repo, tmp_path)
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "pushed to backup only", "work on backup only")
    git(repo, "push", "-q", "backup", "side")
    git(repo, "checkout", "-q", "main")
    git(repo, "fetch", "-q", "--all")
    return repo


def test_a_branch_backed_by_a_reachable_second_remote_reads_clean(two_remotes: Path) -> None:
    """MUST NOT TRIP -- the control for the test below. Both remotes answer, so a branch held by
    ``backup`` alone is backed."""
    r = check(two_remotes)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "0 unbacked commits" in r.stdout
    assert "2 of 2 configured remote(s) answered" in r.stdout


def test_a_branch_backed_ONLY_by_an_unreachable_remote_is_counted(
    two_remotes: Path, tmp_path: Path
) -> None:
    """MUST TRIP. The repository is not UNVERIFIABLE, because origin answers, but ``refs/remotes/
    backup/side`` is a local copy of a store that no longer answers. Excluding it with a bare
    ``--not --remotes`` cleared a branch whose only other copy is gone."""
    git(two_remotes, "remote", "set-url", "backup", str(tmp_path / "gone.git"))

    r = check(two_remotes)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "UNVERIFIABLE" not in r.stdout
    assert "1 of 2 configured remote(s) answered" in r.stdout
    # The remedy differs from an unpushed branch -- restore the remote -- so the remote is named.
    assert "not trusted, did not answer: backup" in r.stdout
    assert "side" in r.stdout
    assert "1 commits on 1 branch exist on no remote" in r.stdout


def test_a_tracking_ref_of_a_remote_no_longer_configured_does_not_back_a_branch(repo: Path) -> None:
    """MUST TRIP. Every configured remote answers, but ``refs/remotes/gone/side`` belongs to no
    configured remote -- a namespace a removed remote left behind. It is a local copy of a store
    nobody can reach, so it must not clear the branch it points at."""
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "held only under an orphan namespace", "work")
    git(repo, "checkout", "-q", "main")
    git(repo, "update-ref", "refs/remotes/gone/side", "side")

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "1 of 1 configured remote(s) answered" in r.stdout
    assert "1 commits on 1 branch exist on no remote" in r.stdout


def test_a_squash_landed_verdict_needs_a_REACHABLE_origin(repo: Path, tmp_path: Path) -> None:
    """MUST TRIP. The patch-id arm reads ``origin/main``. When origin no longer answers but another
    remote does, that ref is a local copy of a dead store, so a patch found there proves nothing about
    where the content now lives."""
    _add_backup_remote(repo, tmp_path)
    _squash_land(repo, "landed on origin only")
    # Local main goes back to what backup holds, so only `side` can be a finding.
    git(repo, "reset", "-q", "--hard", "HEAD~1")
    git(repo, "fetch", "-q", "--all")
    git(repo, "remote", "set-url", "origin", str(tmp_path / "gone.git"))

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "UNVERIFIABLE" not in r.stdout
    assert "squash/rebase-landed" not in r.stdout
    assert "1 commits on 1 branch exist on no remote" in r.stdout
