# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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


@pytest.fixture
def origin(tmp_path: Path) -> Path:
    """A bare repo standing in for a reachable remote. Local, so no network in the suite."""
    o = tmp_path / "origin.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(o)], check=True, capture_output=True
    )
    return o


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
    git(repo, "checkout", "-q", "-b", "side")
    (repo / "g.txt").write_text("landed", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "work")
    # main gets the same CONTENT as a different commit -- what a squash-merge produces.
    git(repo, "checkout", "-q", "main")
    (repo / "g.txt").write_text("landed", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "squashed: work")
    git(repo, "push", "-q", "origin", "main")
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
