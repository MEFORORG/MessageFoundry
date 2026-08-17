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
