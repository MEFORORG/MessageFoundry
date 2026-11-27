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

import json
import os
import re
import shutil
import stat
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


def test_a_repository_s_Commits_includes_its_detached_head_commits(
    repo: Path, tmp_path: Path
) -> None:
    """BACKLOG #6489 item 1. The per-repository figure summed branch findings only, so a repository whose
    only unbacked work sat on a detached HEAD reported Commits 0 while CommitsUnbacked said 1 -- and
    the NO-REMOTE and UNVERIFIABLE lines print that per-repository figure."""
    git(repo, "checkout", "-q", "--detach")
    _commit(repo, "d.txt", "detached work", "detached only")
    sha = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "checkout", "-q", "main")
    git(repo, "worktree", "add", "--detach", str(tmp_path / "detached-wt"), sha)

    r = check(repo, extra=["-Json"])
    assert r.returncode == 1, r.stdout + r.stderr
    doc = json.loads(r.stdout)
    assert doc["DetachedWorktreesUnbacked"] == 1
    assert doc["CommitsUnbacked"] == 1
    assert doc["Repositories"][0]["Commits"] == 1


def test_a_HEAD_detached_on_a_branch_s_history_is_not_counted_twice(tmp_path: Path) -> None:
    """BACKLOG #6489 item 1, its overlap case. A no-remote repository holds 3 commits on ``main``
    and its primary checkout is detached at main: 3 distinct commits, not 6."""
    r = tmp_path / "lonely"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    for i in range(3):
        _commit(r, "f.txt", str(i), f"c{i}")
    git(r, "checkout", "-q", "--detach")

    res = check(r)
    assert res.returncode == 1, res.stdout + res.stderr
    assert (
        "3 commits across 1 refs and 1 detached checkout(s) exist on this disk only" in res.stdout
    )


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
    assert "not trusted, no configured remote: 1 tracking ref(s)" in r.stdout
    assert "1 commits on 1 branch exist on no remote" in r.stdout


def test_a_nested_remote_that_did_not_answer_is_not_trusted_through_its_parent(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP. ``--remotes=origin`` globs ``refs/remotes/origin/*``, and that ``*`` crosses
    ``/``, so trusting origin also trusted the namespace of a dead remote named ``origin/dead``."""
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "held only by a nested dead remote", "work")
    git(repo, "checkout", "-q", "main")
    # `git remote add` refuses a name that is a subset of an existing remote's; a hand-edited config
    # does not, and `git remote` then lists it.
    git(repo, "config", "remote.origin/dead.url", str(tmp_path / "gone.git"))
    git(repo, "config", "remote.origin/dead.fetch", "+refs/heads/*:refs/remotes/origin/dead/*")
    assert "origin/dead" in git(repo, "remote").split()
    git(repo, "update-ref", "refs/remotes/origin/dead/side", "side")

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "not trusted, did not answer: origin/dead" in r.stdout
    assert "1 commits on 1 branch exist on no remote" in r.stdout


def test_an_EMPTY_remote_backs_nothing(repo: Path, tmp_path: Path) -> None:
    """MUST TRIP -- the twin of the HEAD-less backup in ``two_remotes``. Both answer, but this one
    holds no branch at all: a store recreated empty. Its stale tracking refs must not back anything,
    so with it the only remote the repository is UNVERIFIABLE, not clean."""
    git(repo, "remote", "set-url", "origin", str(_bare(tmp_path / "recreated.git")))

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "UNVERIFIABLE" in r.stdout
    assert "answered with no refs (an empty store): origin" in r.stdout
    assert "0 unbacked commits" not in r.stdout


def test_a_TAGS_ONLY_durability_remote_answers_and_backs_what_it_holds(
    repo: Path, tmp_path: Path
) -> None:
    """MUST NOT TRIP. A durability store may hold only rescue tags, fetched into its own tracking
    namespace. It answers, with tags and no branch, so it is trusted: a probe that asked for
    branches alone read it as dead and reported the branch it rescued as unbacked."""
    git(repo, "remote", "add", "dur", str(_bare(tmp_path / "dur.git")))
    git(repo, "config", "remote.dur.fetch", "+refs/tags/rescue/*:refs/remotes/dur/rescuetags/*")
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "rescued as a tag only", "work")
    git(repo, "checkout", "-q", "main")
    git(repo, "push", "-q", "dur", "side:refs/tags/rescue/side")
    git(repo, "fetch", "-q", "dur")
    # The premise: dur holds no branch at all.
    assert git(repo, "ls-remote", "--heads", "dur").strip() == ""

    r = check(repo)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "2 of 2 configured remote(s) answered" in r.stdout
    assert "0 unbacked commits" in r.stdout


def test_a_repo_with_no_remote_counts_commits_an_orphan_tracking_ref_points_at(
    tmp_path: Path,
) -> None:
    """MUST TRIP. With no remote configured nothing may exclude, but a bare ``--not --remotes``
    still let a namespace left behind by a removed remote hide the commits it points at."""
    r = tmp_path / "lonely"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    _commit(r, "f.txt", "x", "only copy")
    git(r, "update-ref", "refs/remotes/gone/main", "main")

    res = check(r)
    assert res.returncode == 1, res.stdout + res.stderr
    assert "NO-REMOTE" in res.stdout
    assert "1 commits across 1 refs exist on this disk only" in res.stdout


def test_a_squash_landed_verdict_needs_a_REACHABLE_origin(repo: Path, tmp_path: Path) -> None:
    """MUST TRIP. The patch-id arm reads a trusted remote's default branch, origin first. When origin
    no longer answers but another remote does, ``origin/main`` is a local copy of a dead store, so a
    patch found there proves nothing about where the content now lives; backup's main lacks it."""
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


def test_a_squash_landed_verdict_from_a_REACHABLE_second_remote_clears(
    repo: Path, tmp_path: Path
) -> None:
    """MUST NOT TRIP -- the twin of the test above, differing in one property: backup's main also
    carries the squash. Origin still does not answer, so the verdict must come from backup."""
    _add_backup_remote(repo, tmp_path)
    _squash_land(repo, "landed on both")
    git(repo, "push", "-q", "backup", "main")
    git(repo, "reset", "-q", "--hard", "HEAD~1")
    git(repo, "fetch", "-q", "--all")
    git(repo, "remote", "set-url", "origin", str(tmp_path / "gone.git"))

    r = check(repo)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "0 unbacked commits" in r.stdout
    assert "patch already on backup/main (squash/rebase-landed)" in r.stdout


@pytest.mark.parametrize("shares_history", [False, True], ids=["unrelated", "related"])
def test_a_squash_landed_verdict_needs_SHARED_history(
    repo: Path, tmp_path: Path, shares_history: bool
) -> None:
    """The ``unrelated`` case MUST TRIP; ``related`` is its must-not-trip twin. Origin does not
    answer and backup holds no main, so the patch-id arm falls back to ``other``'s main. When that
    main is another project's history that happens to hold an identical diff, ``git cherry``
    compared the whole of both and marked the unbacked commit landed."""
    git(repo, "remote", "add", "backup", str(_bare(tmp_path / "backup.git", head="trunk")))
    git(repo, "push", "-q", "backup", "main:keep")  # backs local main; offers no main candidate
    git(repo, "remote", "add", "other", str(_bare(tmp_path / "other.git")))
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "identical diff", "work")
    git(repo, "checkout", "-q", "main")
    if shares_history:
        _commit(repo, "g.txt", "identical diff", "squashed: work")
        git(repo, "push", "-q", "other", "main")
        git(repo, "reset", "-q", "--hard", "HEAD~1")
    else:
        u = tmp_path / "unrelated"
        u.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(u)], check=True, capture_output=True)
        git(u, "config", "user.email", "t@example.invalid")
        git(u, "config", "user.name", "t")
        _commit(u, "other.txt", "another project", "unrelated root")
        _commit(u, "g.txt", "identical diff", "same diff, unrelated history")
        git(u, "push", "-q", str(tmp_path / "other.git"), "main")
    git(repo, "fetch", "-q", "--all")
    git(repo, "remote", "set-url", "origin", str(tmp_path / "gone.git"))

    r = check(repo)
    if shares_history:
        assert r.returncode == 0, r.stdout + r.stderr
        assert "patch already on other/main (squash/rebase-landed)" in r.stdout
    else:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "squash/rebase-landed" not in r.stdout
        assert "1 commits on 1 branch exist on no remote" in r.stdout


@pytest.mark.parametrize("landed", [True, False], ids=["landed", "not-landed"])
def test_a_DANGLING_remote_HEAD_falls_back_to_main(repo: Path, landed: bool) -> None:
    """``landed`` MUST NOT TRIP; ``not-landed`` is its must-trip twin. ``refs/remotes/origin/HEAD``
    names a branch that was pruned -- a default branch renamed from master to main. Taking that
    target alone left origin with no candidate, so a squash on origin/main stopped clearing."""
    if landed:
        _squash_land(repo, "landed")
    else:
        git(repo, "checkout", "-q", "-b", "side")
        _commit(repo, "g.txt", "this exists on exactly one disk", "work")
        git(repo, "checkout", "-q", "main")
    git(repo, "fetch", "-q", "origin")
    git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/master")

    r = check(repo)
    if landed:
        assert r.returncode == 0, r.stdout + r.stderr
        assert "patch already on origin/main (squash/rebase-landed)" in r.stdout
    else:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "1 commits on 1 branch exist on no remote" in r.stdout


@pytest.mark.parametrize("inside", [False, True], ids=["outside", "inside"])
def test_a_remote_HEAD_target_counts_only_inside_its_own_namespace(
    repo: Path, inside: bool
) -> None:
    """``outside`` MUST TRIP; ``inside`` is its must-not-trip twin. When ``refs/remotes/origin/HEAD``
    points at a LOCAL tag holding an unpushed squash, that content is on this disk only, so it must
    not mark the branch landed. Pointed at ``refs/remotes/origin/main`` holding the same squash, it
    does."""
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "squashed somewhere", "work")
    git(repo, "checkout", "-q", "main")
    _commit(repo, "g.txt", "squashed somewhere", "squashed: work")
    if inside:
        git(repo, "push", "-q", "origin", "main")
        git(repo, "fetch", "-q", "origin")
        git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    else:
        # A tag, so no branch scan sees the unpushed squash; local main goes back to what is pushed.
        git(repo, "tag", "local-squash")
        git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/tags/local-squash")
        git(repo, "reset", "-q", "--hard", "HEAD~1")

    r = check(repo)
    if inside:
        assert r.returncode == 0, r.stdout + r.stderr
        assert "patch already on origin/main (squash/rebase-landed)" in r.stdout
    else:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "squash/rebase-landed" not in r.stdout
        assert "1 commits on 1 branch exist on no remote" in r.stdout


@pytest.mark.parametrize("on_backup", [True, False], ids=["squash-on-backup", "squash-nowhere"])
def test_a_squash_on_a_SECOND_answering_remote_clears(
    repo: Path, tmp_path: Path, on_backup: bool
) -> None:
    """``squash-on-backup`` MUST NOT TRIP; ``squash-nowhere`` is its must-trip twin. Both remotes
    answer and origin/main lacks the squash. Reading only the first candidate that shares history,
    origin, missed the squash on backup's main, where the content is just as durable."""
    _add_backup_remote(repo, tmp_path)
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "landed on backup", "work")
    git(repo, "checkout", "-q", "main")
    _commit(repo, "g.txt", "landed on backup", "squashed: work")
    if on_backup:
        git(repo, "push", "-q", "backup", "main")
    git(repo, "reset", "-q", "--hard", "HEAD~1")
    git(repo, "fetch", "-q", "--all")

    r = check(repo)
    assert "2 of 2 configured remote(s) answered" in r.stdout
    if on_backup:
        assert r.returncode == 0, r.stdout + r.stderr
        assert "patch already on backup/main (squash/rebase-landed)" in r.stdout
    else:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "1 commits on 1 branch exist on no remote" in r.stdout


@pytest.mark.parametrize("target_inside", [False, True], ids=["to-local-branch", "to-own-ref"])
def test_a_tracking_SYMREF_pointing_outside_its_remote_backs_nothing(
    repo: Path, target_inside: bool
) -> None:
    """``to-local-branch`` MUST TRIP; ``to-own-ref`` is its must-not-trip twin. ``--remotes=origin``
    follows symrefs, so ``refs/remotes/origin/HEAD -> refs/heads/side`` made the unpushed branch
    exclude itself. Pointed at origin's own ``side`` tracking ref, after a real push, it is backed."""
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "this exists on exactly one disk", "work")
    git(repo, "checkout", "-q", "main")
    if target_inside:
        git(repo, "push", "-q", "origin", "side")
        git(repo, "fetch", "-q", "origin")
        git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/side")
    else:
        git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/heads/side")

    r = check(repo)
    if target_inside:
        assert r.returncode == 0, r.stdout + r.stderr
        assert "0 unbacked commits" in r.stdout
    else:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "1 commits on 1 branch exist on no remote" in r.stdout


@pytest.mark.parametrize("corrupt", [True, False], ids=["missing-object", "intact"])
def test_a_FAILED_scan_is_unverifiable_never_zero(repo: Path, corrupt: bool) -> None:
    """``missing-object`` MUST TRIP; ``intact`` is its control. A rev-list that dies prints nothing,
    and the script read that silence as 0 unbacked commits."""
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "first", "first unpushed")
    first = git(repo, "rev-parse", "HEAD").strip()
    _commit(repo, "h.txt", "second", "second unpushed")
    git(repo, "checkout", "-q", "main")
    if corrupt:
        obj = repo / ".git" / "objects" / first[:2] / first[2:]
        os.chmod(obj, stat.S_IWRITE)
        obj.unlink()

    r = check(repo)
    assert "0 unbacked commits" not in r.stdout
    if corrupt:
        # Exit 2, "could not run": a broken measurement is not work needing a rescue push.
        assert r.returncode == 2, r.stdout + r.stderr
        assert "UNVERIFIABLE" in r.stdout
        assert "git FAILED for: side" in r.stdout
    else:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "git FAILED" not in r.stdout
        assert "2 commits on 1 branch exist on no remote" in r.stdout


@pytest.mark.parametrize("name", ["café", "cafe"], ids=["non-ascii", "ascii"])
def test_a_NON_ASCII_branch_name_does_not_break_the_scan(repo: Path, name: str) -> None:
    """``non-ascii`` MUST TRIP; ``ascii`` is its twin. PowerShell decoded git's output with the
    console code page, so a branch named ``cafe`` with an accent came back garbled, every rev-list
    fed that name failed, and the whole repository read UNVERIFIABLE instead of naming ``side``."""
    git(repo, "branch", name)
    git(repo, "push", "-q", "origin", name)
    git(repo, "fetch", "-q", "origin")
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "this exists on exactly one disk", "work")
    git(repo, "checkout", "-q", "main")

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "UNVERIFIABLE" not in r.stdout
    assert "1 commits on 1 branch exist on no remote" in r.stdout


def test_a_RELATIVE_path_after_set_location_reads_one_repository(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP. With ``-Path .`` after a ``Set-Location``, ``& git -C .`` read PowerShell's
    location while the directly started git read the process directory, which Set-Location does not
    move. The listings and scans then came from the wrong repository and ``side`` was never named."""
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(other)], check=True, capture_output=True)
    git(other, "config", "user.email", "t@example.invalid")
    git(other, "config", "user.name", "t")
    _commit(other, "x.txt", "another repository", "base")
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "this exists on exactly one disk", "work")
    git(repo, "checkout", "-q", "main")

    cmd = f"Set-Location -LiteralPath '{repo}'; & '{CHECK}' -Path ."
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", cmd],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        cwd=other,
    )
    assert "NO-REMOTE" not in r.stdout, r.stdout + r.stderr
    assert "side" in r.stdout, r.stdout + r.stderr
    assert "1 commits on 1 branch exist on no remote" in r.stdout


def test_the_git_started_is_the_one_PATH_discovery_finds_and_its_failure_exits_2(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP. The script starts the git PowerShell command discovery resolves -- here a
    ``git.cmd`` placed first on PATH -- rather than handing a bare ``git`` to the process starter,
    which searches pwsh's own folder and the current directory first and never finds a ``.cmd``.
    That shim refuses every ``rev-list --stdin``, and the refusal must read as a scan failure,
    exit 2, never as a clean run.

    It does NOT reproduce a write to a closed stdin pipe: measured with the try/catch in Invoke-Git
    removed, this test still passed, even with 4000 tracking refs in the exclusion set."""
    real_git = shutil.which("git")
    assert real_git is not None
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "git.cmd").write_text(
        f'@echo off\r\nif "%3"=="rev-list" if "%4"=="--stdin" exit /b 128\r\n"{real_git}" %*\r\n',
        encoding="ascii",
        newline="",
    )
    env = dict(os.environ, PATH=f"{shim}{os.pathsep}{os.environ['PATH']}")
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(CHECK), "-Path", str(repo)],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        env=env,
    )
    assert r.returncode == 2, r.stdout + r.stderr
    assert "UNVERIFIABLE" in r.stdout
    assert "git FAILED for:" in r.stdout


@pytest.mark.parametrize("corrupt", [True, False], ids=["bad-packed-refs", "intact"])
def test_a_FAILED_ref_listing_is_unverifiable_never_zero(repo: Path, corrupt: bool) -> None:
    """``bad-packed-refs`` MUST TRIP; ``intact`` is its control. A for-each-ref that dies lists
    nothing, and nothing read as "no tracking refs" and "no branches"."""
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "this exists on exactly one disk", "work")
    git(repo, "checkout", "-q", "main")
    git(repo, "pack-refs", "--all")
    if corrupt:
        with (repo / ".git" / "packed-refs").open("a", encoding="ascii") as f:
            f.write("this line is not a packed ref\n")

    r = check(repo)
    assert "0 unbacked commits" not in r.stdout
    if corrupt:
        assert r.returncode == 2, r.stdout + r.stderr
        assert "UNVERIFIABLE" in r.stdout
        assert "git FAILED for:" in r.stdout
    else:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "1 commits on 1 branch exist on no remote" in r.stdout


def test_a_BROKEN_tracking_ref_does_not_make_the_run_read_clean(repo: Path) -> None:
    """MUST TRIP, and still measure. A tracking ref naming a missing object made the
    ``--remotes=origin`` glob die for every ref, and the empty output read as 0 unbacked commits. It
    backs nothing, so the run must neither read clean nor give up: ``side`` is named."""
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "this exists on exactly one disk", "work")
    git(repo, "checkout", "-q", "main")
    bad = repo / ".git" / "refs" / "remotes" / "origin" / "bad"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("0123456789abcdef0123456789abcdef01234567\n", encoding="ascii")

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "0 unbacked commits" not in r.stdout
    assert "UNVERIFIABLE" not in r.stdout
    assert "1 commits on 1 branch exist on no remote" in r.stdout


@pytest.mark.parametrize(
    "real", [False, True], ids=["local-tag-named-like-it", "real-tracking-ref"]
)
def test_a_local_ref_NAMED_like_a_tracking_ref_never_stands_in(
    repo: Path, tmp_path: Path, real: bool
) -> None:
    """``local-tag-named-like-it`` MUST TRIP; ``real-tracking-ref`` is its must-not-trip twin. With
    no real ``refs/remotes/backup/main``, ``rev-parse refs/remotes/backup/main`` resolved a local tag
    of that name holding an unpushed squash, and the squash marked the branch landed."""
    git(repo, "remote", "add", "backup", str(_bare(tmp_path / "backup.git", head="trunk")))
    git(repo, "push", "-q", "backup", "main:keep")
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "squashed somewhere", "work")
    git(repo, "checkout", "-q", "main")
    _commit(repo, "g.txt", "squashed somewhere", "squashed: work")
    if real:
        git(repo, "push", "-q", "backup", "main")
    else:
        git(repo, "tag", "refs/remotes/backup/main")
    git(repo, "reset", "-q", "--hard", "HEAD~1")
    git(repo, "fetch", "-q", "--all")

    r = check(repo)
    if real:
        assert r.returncode == 0, r.stdout + r.stderr
        assert "patch already on backup/main (squash/rebase-landed)" in r.stdout
    else:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "squash/rebase-landed" not in r.stdout
        assert "1 commits on 1 branch exist on no remote" in r.stdout


@pytest.mark.parametrize("landed", [True, False], ids=["landed", "not-landed"])
def test_a_STALE_remote_HEAD_does_not_hide_main(repo: Path, landed: bool) -> None:
    """``landed`` MUST NOT TRIP; ``not-landed`` is its must-trip twin. ``refs/remotes/origin/HEAD``
    still names an unpruned ``origin/master``. Keeping only the first of HEAD target, main and
    master read master alone, so a squash on origin/main stopped clearing."""
    git(repo, "push", "-q", "origin", "main:master")
    if landed:
        _squash_land(repo, "landed")
    else:
        git(repo, "checkout", "-q", "-b", "side")
        _commit(repo, "g.txt", "this exists on exactly one disk", "work")
        git(repo, "checkout", "-q", "main")
    git(repo, "fetch", "-q", "origin")
    git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/master")

    r = check(repo)
    if landed:
        assert r.returncode == 0, r.stdout + r.stderr
        assert "patch already on origin/main (squash/rebase-landed)" in r.stdout
    else:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "1 commits on 1 branch exist on no remote" in r.stdout


def test_a_MISSING_git_exits_2_could_not_run(repo: Path, tmp_path: Path) -> None:
    """MUST TRIP. With no git on PATH the script wrote its message with Write-Error under Stop,
    which ended it with exit 1 -- "unbacked found" -- before the exit 2 that means "could not run"."""
    pwsh = shutil.which("pwsh")
    assert pwsh is not None
    empty = tmp_path / "empty-path"
    empty.mkdir()
    env = dict(os.environ, PATH=str(empty))
    r = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(CHECK), "-Path", str(repo)],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        env=env,
    )
    assert r.returncode == 2, r.stdout + r.stderr
    assert "git is not on PATH" in r.stderr


@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_a_partly_failed_scan_still_lists_what_it_measured(repo: Path, as_json: bool) -> None:
    """``text`` MUST TRIP; ``json`` pins the same items in the machine output. One branch whose
    history lost an object made the repository print only the failure, hiding the at-risk branch
    that scanned fine beside it."""
    git(repo, "checkout", "-q", "-b", "atrisk")
    _commit(repo, "g.txt", "this exists on exactly one disk", "work")
    git(repo, "checkout", "-q", "main")
    git(repo, "checkout", "-q", "-b", "broken")
    _commit(repo, "h.txt", "first", "first")
    first = git(repo, "rev-parse", "HEAD").strip()
    _commit(repo, "i.txt", "second", "second")
    git(repo, "checkout", "-q", "main")
    obj = repo / ".git" / "objects" / first[:2] / first[2:]
    os.chmod(obj, stat.S_IWRITE)
    obj.unlink()

    r = check(repo, extra=["-Json"] if as_json else None)
    assert r.returncode == 2, r.stdout + r.stderr
    if as_json:
        doc = json.loads(r.stdout)
        repo_doc = doc["Repositories"][0]
        assert "broken" in repo_doc["ScanFailed"]
        assert [(f["Ref"], f["Commits"]) for f in repo_doc["Findings"]] == [("atrisk", 1)]
    else:
        assert "git FAILED for: broken" in r.stdout
        assert re.search(r"^\s+atrisk\s+1\s*$", r.stdout, re.MULTILINE), r.stdout


def test_a_failed_EXCLUSION_set_withholds_counts_rather_than_call_backed_work_unbacked(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP. When origin's tracking refs cannot be listed, nothing is excluded, so every count
    is taken against too little. Listing them as "on no remote" would send an operator to
    rescue-push work that is on origin. A git.cmd shim fails only that listing."""
    git(repo, "checkout", "-q", "-b", "pushed")
    _commit(repo, "g.txt", "on origin", "work")
    git(repo, "push", "-q", "origin", "pushed")
    git(repo, "checkout", "-q", "main")
    git(repo, "fetch", "-q", "origin")
    real_git = shutil.which("git")
    assert real_git is not None
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "git.cmd").write_text(
        f'@echo off\r\nif "%3"=="for-each-ref" if "%5"=="refs/remotes/origin" exit /b 128\r\n'
        f'"{real_git}" %*\r\n',
        encoding="ascii",
        newline="",
    )
    env = dict(os.environ, PATH=f"{shim}{os.pathsep}{os.environ['PATH']}")
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(CHECK), "-Path", str(repo)],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        env=env,
    )
    assert r.returncode == 2, r.stdout + r.stderr
    assert "git FAILED for: (tracking refs of origin)" in r.stdout
    assert (
        "a git listing failed for (tracking refs of origin); per-branch counts are not shown"
        in (r.stdout)
    )
    assert not re.search(r"^\s+pushed\s+\d+\s*$", r.stdout, re.MULTILINE), r.stdout


@pytest.mark.parametrize("kind", ["never-landed", "squash-landed"])
def test_a_failed_listing_under_SKIP_REACHABILITY_withholds_counts(
    repo: Path, tmp_path: Path, kind: str
) -> None:
    """MUST TRIP, both cases. Under -SkipReachability a failed tracking-ref listing also empties
    the squash candidates, so a squash-landed branch would be listed as at-risk work. The rule is
    the same in every mode: when a trusted-refs listing failed, per-branch counts are not shown."""
    git(repo, "checkout", "-q", "-b", "pushed")
    _commit(repo, "p.txt", "on origin", "pushed work")
    git(repo, "push", "-q", "origin", "pushed")
    git(repo, "checkout", "-q", "main")
    if kind == "squash-landed":
        _squash_land(repo, "landed")  # branch `side`, its content squashed onto origin/main
    else:
        git(repo, "checkout", "-q", "-b", "side")
        _commit(repo, "h.txt", "this exists on exactly one disk", "work")
        git(repo, "checkout", "-q", "main")
    git(repo, "fetch", "-q", "origin")
    real_git = shutil.which("git")
    assert real_git is not None
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "git.cmd").write_text(
        f'@echo off\r\nif "%3"=="for-each-ref" if "%5"=="refs/remotes/origin" exit /b 128\r\n'
        f'"{real_git}" %*\r\n',
        encoding="ascii",
        newline="",
    )
    env = dict(os.environ, PATH=f"{shim}{os.pathsep}{os.environ['PATH']}")
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(CHECK), "-Path", str(repo), "-SkipReachability"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        env=env,
    )
    assert r.returncode == 2, r.stdout + r.stderr
    assert (
        "a git listing failed for (tracking refs of origin); per-branch counts are not shown"
        in (r.stdout)
    )
    assert not re.search(r"^\s+(side|pushed)\s+\d+\s*$", r.stdout, re.MULTILINE), r.stdout


@pytest.mark.parametrize("deleted", [True, False], ids=["deleted-on-remote", "still-there"])
def test_a_tracking_ref_whose_branch_the_remote_DELETED_backs_nothing(
    repo: Path, origin: Path, deleted: bool
) -> None:
    """``deleted-on-remote`` MUST TRIP; ``still-there`` is its must-not-trip twin. origin answers,
    but ``refs/remotes/origin/side`` is a local copy of a branch origin no longer holds. Trusting
    every tracking ref of an answering remote cleared work that exists on this disk only."""
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "pushed, then deleted on the remote", "work")
    git(repo, "push", "-q", "origin", "side")
    git(repo, "checkout", "-q", "main")
    git(repo, "fetch", "-q", "origin")
    if deleted:
        git(origin, "branch", "-qD", "side")

    r = check(repo)
    if deleted:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "no longer advertised by their remote: 1 tracking ref(s)" in r.stdout
        assert "1 commits on 1 branch exist on no remote" in r.stdout
    else:
        assert r.returncode == 0, r.stdout + r.stderr
        assert "0 unbacked commits" in r.stdout


@pytest.mark.parametrize("orphan", [True, False], ids=["orphan-branch", "branch-off-main"])
def test_a_squash_verdict_needs_history_shared_with_the_BRANCH_not_head(
    repo: Path, orphan: bool
) -> None:
    """``orphan-branch`` MUST TRIP; ``branch-off-main`` is its must-not-trip twin. Relatedness was
    judged against HEAD, so an orphan branch whose one commit happens to carry the same diff as a
    commit on origin/main was compared with it by ``git cherry`` and marked landed."""
    if orphan:
        git(repo, "checkout", "-q", "--orphan", "orph")
        git(repo, "rm", "-rqf", ".")
        _commit(repo, "g.txt", "same diff", "orphan work")
        branch = "orph"
    else:
        git(repo, "checkout", "-q", "-b", "side")
        _commit(repo, "g.txt", "same diff", "work")
        branch = "side"
    git(repo, "checkout", "-q", "main")
    _commit(repo, "g.txt", "same diff", "squashed: work")
    git(repo, "push", "-q", "origin", "main")
    git(repo, "fetch", "-q", "origin")

    r = check(repo)
    if orphan:
        assert r.returncode == 1, r.stdout + r.stderr
        assert "squash/rebase-landed" not in r.stdout
        assert re.search(rf"^\s+{branch}\s+1\s*$", r.stdout, re.MULTILINE), r.stdout
    else:
        assert r.returncode == 0, r.stdout + r.stderr
        assert "patch already on origin/main (squash/rebase-landed)" in r.stdout


def test_a_tracking_TAG_whose_target_commit_is_missing_does_not_kill_the_scan(
    repo: Path,
) -> None:
    """MUST TRIP, and still measure. Under -SkipReachability every tracking ref excludes, and one
    naming an annotated tag whose target commit is gone made every rev-list die, so the run read
    UNVERIFIABLE with nothing measured. The tag backs nothing; ``side`` is named."""
    git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "g.txt", "this exists on exactly one disk", "work")
    git(repo, "checkout", "-q", "--detach", "main")
    _commit(repo, "r.txt", "rescued", "rescued work")
    target = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "tag", "-a", "-m", "rescue", "rescue-tag", target)
    tag_oid = git(repo, "rev-parse", "rescue-tag").strip()
    git(repo, "checkout", "-q", "main")
    git(repo, "update-ref", "refs/remotes/origin/rescue-tag", tag_oid)
    git(repo, "tag", "-d", "rescue-tag")
    obj = repo / ".git" / "objects" / target[:2] / target[2:]
    os.chmod(obj, stat.S_IWRITE)
    obj.unlink()

    r = check(repo, extra=["-SkipReachability"])
    assert r.returncode == 1, r.stdout + r.stderr
    assert "git FAILED" not in r.stdout
    assert "1 commits on 1 branch exist on no remote" in r.stdout


def test_a_FAILED_remote_listing_is_unverifiable_never_no_remote(
    repo: Path, tmp_path: Path
) -> None:
    """MUST TRIP. A ``git remote`` that failed listed nothing, and the repository read NO-REMOTE
    with every commit counted against no exclusion at all."""
    real_git = shutil.which("git")
    assert real_git is not None
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "git.cmd").write_text(
        f'@echo off\r\nif "%3"=="remote" exit /b 128\r\n"{real_git}" %*\r\n',
        encoding="ascii",
        newline="",
    )
    env = dict(os.environ, PATH=f"{shim}{os.pathsep}{os.environ['PATH']}")
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(CHECK), "-Path", str(repo)],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        env=env,
    )
    assert r.returncode == 2, r.stdout + r.stderr
    assert "git FAILED for: (remote listing)" in r.stdout
    assert "NO-REMOTE" not in r.stdout
    assert "0 of 0 configured" not in r.stdout, r.stdout


@pytest.mark.parametrize("name", ["wt-é", "wt-e"], ids=["non-ascii", "ascii"])
def test_a_detached_worktree_at_a_NON_ASCII_path_is_counted(
    repo: Path, tmp_path: Path, name: str
) -> None:
    """``non-ascii`` MUST TRIP; ``ascii`` is its twin. The worktree list was decoded with the
    console code page, so a path with an accent came back garbled, failed Test-Path and was
    skipped: its unbacked detached commit was never counted."""
    git(repo, "checkout", "-q", "--detach", "main")
    _commit(repo, "d.txt", "detached work", "detached work")
    sha = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "checkout", "-q", "main")
    git(repo, "worktree", "add", "--detach", str(tmp_path / name), sha)

    r = check(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "1 commits on 1 detached worktree exist on no remote" in r.stdout
