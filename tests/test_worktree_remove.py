# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Execution tests for ``scripts/worktree/remove.ps1`` (BACKLOG #1037).

``remove.ps1`` is the most destructive script in ``scripts/worktree/``: it force-removes a worktree
and, under ``-DeleteBranch``, force-deletes a ref. ``git worktree remove`` destroys the per-worktree
HEAD reflog and ``git branch -D`` destroys the ref *and* its branch reflog, so a force-delete on a
branch holding unique commits leaves them reachable from **no ref and no reflog**. That logic was
covered by review only, because the script derived its repo root from ``$PSScriptRoot`` with no
override -- so the only thing a test could point it at was this checkout, which no test may touch.

The ``-RepoRoot`` parameter (the same shape ``prune-merged.ps1`` already had, and the same reason)
is what makes these tests possible. Every test here drives the REAL script as a subprocess against a
synthetic repo built under ``tmp_path``.

Two rules, inherited from ``tests/test_worktree_prune_merged.py``:

* **Assert the decision and the reason, not survival.** A branch that survives proves nothing on its
  own -- ``git branch -d`` refuses an unmerged branch by itself, so a survival-only assertion passes
  on a script that has lost the re-verification step entirely. The keep tests therefore assert the
  reported reason and the commit count as well.
* **Carry a positive control in the same invocation where one is possible.** A refusal test that only
  shows a non-zero exit cannot distinguish "the guard fired" from "the script is broken", so each
  refusal is followed by the invocation that is *supposed* to succeed.

``-DeleteBranch``'s keep path is reached through ``$LASTEXITCODE`` after ``git branch -d`` fails.
That branch is only reachable while ``$PSNativeCommandUseErrorActionPreference`` is ``$false``
(measured ``False`` on pwsh 7.6.3, which is what these tests run on). Should a future pwsh flip that
default, ``git branch -d``'s non-zero exit would become a terminating error under the script's
``$ErrorActionPreference = "Stop"`` and the keep path would stop running -- these tests would then go
red, which is the correct outcome and the reason the assertion is on the reported reason rather than
on the branch merely existing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
SCRIPT = _REPO / "scripts" / "worktree" / "remove.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="remove.ps1 is a PowerShell script driven through pwsh on Windows",
)


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return proc.stdout


def _git_ok(repo: Path, *args: str) -> bool:
    """Run a git command for its exit status only (a non-zero exit is data, not a failure)."""
    return (
        subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
        ).returncode
        == 0
    )


def _commit(repo: Path, name: str, text: str) -> str:
    (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", "--", name)
    _git(repo, "commit", "-qm", f"add {name}")
    return _git(repo, "rev-parse", "HEAD").strip()


class Fixture:
    """A synthetic repo with a primary at ``<root>/wt/repo`` and ``<root>/wt/repo-<slug>`` siblings.

    The layout is dictated by the script under test: it derives ``<parent>/<leaf>-<Name>`` from the
    repo root, so the fixture has to reproduce that shape rather than choose its own.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.primary = root / "wt" / "repo"

    def sibling(self, slug: str) -> Path:
        return self.primary.parent / f"{self.primary.name}-{slug}"

    def add(self, slug: str, branch: str | None = None) -> Path:
        path = self.sibling(slug)
        _git(self.primary, "worktree", "add", "-q", "-b", branch or slug, str(path))
        return path

    def registered(self) -> set[str]:
        out = _git(self.primary, "worktree", "list", "--porcelain")
        return {
            ln.split(" ", 1)[1].replace("\\", "/").rstrip("/")
            for ln in out.splitlines()
            if ln.startswith("worktree ")
        }

    def is_registered(self, path: Path) -> bool:
        return str(path).replace("\\", "/").rstrip("/") in self.registered()

    def branch_exists(self, name: str) -> bool:
        return _git_ok(self.primary, "rev-parse", "--verify", "--quiet", f"refs/heads/{name}")


@pytest.fixture
def fx(tmp_path: Path) -> Fixture:
    f = Fixture(tmp_path)
    f.primary.mkdir(parents=True)
    _git(f.primary, "init", "-q", "-b", "main")
    _git(f.primary, "config", "user.email", "t@example.invalid")
    _git(f.primary, "config", "user.name", "t")
    seed = _commit(f.primary, "seed.txt", "seed")
    # No network and no remote: the merge re-verification reads refs/remotes/origin/main, which
    # `update-ref` can write directly.
    _git(f.primary, "update-ref", "refs/remotes/origin/main", seed)
    return f


def run(
    fx: Fixture,
    *args: str,
    script: Path | None = None,
    repo_root: Path | str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Drive the real script. ``repo_root`` defaults to the fixture primary and is NEVER omitted
    unless a test is deliberately exercising the ``$PSScriptRoot`` default against a copied script.
    """
    argv = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script or SCRIPT)]
    root = fx.primary if repo_root is None else repo_root
    if root != "":
        argv += ["-RepoRoot", str(root)]
    return subprocess.run([*argv, *args], capture_output=True, text=True, timeout=180, check=False)


def test_removes_a_clean_worktree(fx: Fixture) -> None:
    wt = fx.add("clean")
    assert fx.is_registered(wt)

    proc = run(fx, "-Name", "clean")

    assert proc.returncode == 0, proc.stderr
    assert "Removed worktree" in proc.stdout
    assert not wt.exists()
    assert not fx.is_registered(wt)
    # No -DeleteBranch: the ref is the one thing that must survive.
    assert fx.branch_exists("clean")


def test_untracked_files_do_not_block_removal(fx: Fixture) -> None:
    """The `.venv` case the header calls expected -- and it is why `--force` is unconditional."""
    wt = fx.add("venv")
    (wt / ".venv").mkdir()
    (wt / ".venv" / "marker.txt").write_text("not tracked anywhere", encoding="utf-8")

    proc = run(fx, "-Name", "venv")

    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()


def test_uncommitted_tracked_changes_are_refused_and_force_overrides(fx: Fixture) -> None:
    wt = fx.add("dirty")
    (wt / "seed.txt").write_text("modified", encoding="utf-8")

    refused = run(fx, "-Name", "dirty")

    assert refused.returncode != 0
    assert "uncommitted tracked changes" in refused.stderr
    assert wt.exists()
    assert fx.is_registered(wt)

    # Positive control in the same fixture: the ONLY difference is -Force, so the refusal above was
    # the guard firing and not an unrelated failure.
    forced = run(fx, "-Name", "dirty", "-Force")

    assert forced.returncode == 0, forced.stderr
    assert not wt.exists()
    assert not fx.is_registered(wt)


def test_delete_branch_force_deletes_only_after_reverifying_containment(fx: Fixture) -> None:
    """The `-d` fails / re-verify / `-D` path -- the one that force-deletes a ref.

    Shape: the branch's commit IS on origin/main but the LOCAL main lags, which is the ordinary
    state of this repo and the reason `-D` exists at all. The precondition is asserted rather than
    assumed, so the test cannot silently pass through the easy `-d` path instead.
    """
    wt = fx.add("landed")
    tip = _commit(wt, "landed.txt", "work that has since landed upstream")
    _git(fx.primary, "update-ref", "refs/remotes/origin/main", tip)

    # `git branch -d` consults the CURRENT branch, which is still at the seed: so it must refuse.
    assert "landed" not in _git(fx.primary, "branch", "--merged", "main")
    assert _git(fx.primary, "rev-list", "--count", "origin/main..landed").strip() == "0"

    proc = run(fx, "-Name", "landed", "-DeleteBranch")

    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()
    assert not fx.branch_exists("landed")
    # The recovery recipe is the only undo once the ref and both reflogs are gone, so it must be
    # printed with the full tip, before the delete.
    assert tip in proc.stdout
    assert "Recover a deleted branch with" in proc.stdout


def test_delete_branch_keeps_a_branch_holding_commits_not_on_origin_main(fx: Fixture) -> None:
    """The lossless half: unique commits mean the branch is KEPT, and the reason is reported.

    Asserting only that the branch survived would pass on a script that never re-verified anything,
    because `git branch -d` refuses an unmerged branch on its own. The reported count is what
    distinguishes "the re-verification ran and said keep" from "the delete simply failed".
    """
    wt = fx.add("ahead")
    tip = _commit(wt, "ahead.txt", "unique work, never pushed")

    proc = run(fx, "-Name", "ahead", "-DeleteBranch")

    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()
    assert fx.branch_exists("ahead")
    assert _git(fx.primary, "rev-parse", "refs/heads/ahead").strip() == tip
    combined = proc.stdout + proc.stderr
    assert "1 commit(s) on 'ahead' are not on origin/main" in combined
    assert "KEPT" in combined


def test_delete_branch_reads_the_branch_from_git_not_the_directory_name(fx: Fixture) -> None:
    """`-Name` is the DIRECTORY. Deleting a branch named after it would delete the wrong ref."""
    wt = fx.add("slugged", branch="claude/other")
    # A decoy ref whose name IS the directory slug. If the script ever goes back to `branch -D
    # $Name`, this is what it destroys.
    _git(fx.primary, "branch", "slugged", "main")

    proc = run(fx, "-Name", "slugged", "-DeleteBranch")

    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()
    assert not fx.branch_exists("claude/other")
    assert fx.branch_exists("slugged")


def test_detached_head_refuses_delete_branch_without_removing_anything(fx: Fixture) -> None:
    wt = fx.sibling("detached")
    _git(fx.primary, "worktree", "add", "-q", "--detach", str(wt))

    refused = run(fx, "-Name", "detached", "-DeleteBranch")

    assert refused.returncode != 0
    assert "detached HEAD" in refused.stderr
    # The branch is read BEFORE the removal precisely so a refusal here costs nothing.
    assert wt.exists()
    assert fx.is_registered(wt)

    # Positive control: the same worktree, same script, without -DeleteBranch.
    proc = run(fx, "-Name", "detached")

    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()


def test_refuses_a_worktree_that_does_not_exist(fx: Fixture) -> None:
    proc = run(fx, "-Name", "nope")

    assert proc.returncode != 0
    assert "No such worktree" in proc.stderr
    # It names the path it looked for -- the whole failure mode of BACKLOG #1078 is a caller who
    # cannot tell WHICH root was searched.
    assert str(fx.sibling("nope")) in proc.stderr


def test_a_repo_root_that_does_not_exist_is_refused(fx: Fixture) -> None:
    proc = run(fx, "-Name", "clean", repo_root=fx.root / "no-such-repo")

    assert proc.returncode != 0
    assert "RepoRoot does not exist" in proc.stderr


def test_the_script_location_default_still_anchors_when_no_root_is_passed(fx: Fixture) -> None:
    """The override must not become the only working path.

    Invoking a COPY that lives at ``<fixture>/scripts/worktree/remove.ps1`` with no ``-RepoRoot``
    exercises the ``$PSScriptRoot`` default -- the path every real invocation takes -- without ever
    pointing the real script at this checkout.
    """
    wt = fx.add("bydefault")
    copied = fx.primary / "scripts" / "worktree" / "remove.ps1"
    copied.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SCRIPT, copied)

    proc = run(fx, "-Name", "bydefault", script=copied, repo_root="")

    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()
    assert not fx.is_registered(wt)


# --- BACKLOG #1295: claims held by a removed worktree --------------------------
#
# `claim.ps1 -Release` is WORKTREE-SCOPED, so a claim outliving its holder can never be released
# normally and reads as actively-being-built forever. Measured 2026-08-19: 19 of 28 live claims were
# already orphaned this way, and this script -- the sanctioned removal path -- had no claim handling,
# so it was a source of them.
#
# THE FALSE POSITIVE IS THE ONE TO FEAR, not the missed release. Handing a LIVE worktree's key to
# another session invites the duplicate build the registry exists to stop, which is strictly worse
# than the orphan. That is why two of the tests below assert a claim SURVIVES.


def _claims_dir(fx: Fixture) -> Path:
    common = _git(fx.primary, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    d = Path(common) / "mefor-coord" / "claims"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_claim(fx: Fixture, key: str, worktree: Path | str) -> Path:
    f = _claims_dir(fx) / f"{key}.json"
    f.write_text(
        json.dumps({"key": key, "worktree": str(worktree).replace("\\", "/"), "note": "t"}),
        encoding="utf-8",
    )
    return f


def test_a_claim_held_by_the_removed_worktree_is_released(fx: Fixture) -> None:
    wt = fx.add("alpha")
    claim = _write_claim(fx, "9001", wt)
    assert claim.exists(), (
        "POSITIVE CONTROL: the claim must exist before removal, or this proves nothing"
    )

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode == 0, proc.stderr
    assert not claim.exists(), (
        "the claim outlived its holder and can now never be released normally"
    )
    assert "9001" in proc.stdout, (
        "the release happened silently; an operator cannot audit what they cannot see"
    )


def test_a_claim_held_by_a_DIFFERENT_worktree_survives(fx: Fixture) -> None:
    """THE FALSE-POSITIVE GUARD, and it matters more than the release itself."""
    wt = fx.add("alpha")
    other = fx.add("beta")
    mine = _write_claim(fx, "9002", wt)
    theirs = _write_claim(fx, "9003", other)

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode == 0, proc.stderr
    assert not mine.exists(), "the removed worktree's own claim was not released"
    assert theirs.exists(), (
        "a claim belonging to a LIVING worktree was released. That hands its key to another session "
        "and invites the duplicate build the registry exists to stop -- worse than the orphan."
    )


def test_a_claim_whose_path_merely_PREFIXES_the_removed_one_survives(fx: Fixture) -> None:
    """`repo-alpha` is a string prefix of `repo-alpha-two`. A StartsWith match would release both.

    This is the exact shape the matching rule forbids -- full normalised path, no prefix, no leaf.
    """
    wt = fx.add("alpha")
    nested = fx.add("alpha-two")
    exact = _write_claim(fx, "9004", wt)
    victim = _write_claim(fx, "9005", nested)

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode == 0, proc.stderr
    # CONTROL: without this the test passes when the sweep does nothing at all.
    assert not exact.exists(), "the sweep did not run, so the prefix result below proves nothing"
    assert victim.exists(), "a prefix match released a different worktree's claim"


def test_an_unreadable_claim_is_left_in_place_and_reported(fx: Fixture) -> None:
    """UNREADABLE IS NOT ABSENT. A file that will not parse might name this worktree, so it is
    reported rather than deleted on a guess -- and rather than silently skipped, which would make a
    stranded claim look like a clean sweep."""
    fx.add("alpha")
    bad = _claims_dir(fx) / "9006.json"
    bad.write_text("{not json", encoding="utf-8")

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode == 0, proc.stderr
    assert bad.exists(), "an unparseable claim was deleted on a guess"
    combined = proc.stdout + proc.stderr
    assert "9006" in combined, (
        "the unreadable claim was skipped silently, which reads as a clean sweep"
    )


def test_removal_still_succeeds_with_no_claims_directory(fx: Fixture) -> None:
    """The sweep must not turn a working removal into a failure on a repo that has never claimed."""
    fx.add("alpha")
    proc = run(fx, "-Name", "alpha")
    assert proc.returncode == 0, proc.stderr
    assert not fx.is_registered(fx.sibling("alpha"))


# --- BACKLOG #1293: allocations a removed worktree owns ------------------------
#
# Ownership of a ledger number is a casefolded PATH-STRING comparison against the worktree recorded
# at allocation time, with no fallback when that directory is gone. So removal BURNS the number:
# `owns()` returns false for every session forever and any PR that must re-introduce the heading is
# unlandable by anyone. PR #397 was stranded exactly this way.
#
# IT REFUSES RATHER THAN WARNS BECAUSE THERE IS NO POST-HOC FIX. A claim can be released afterwards;
# an allocation cannot be re-keyed -- ownership is documented non-transferable -- so the removal is
# the only moment this can be stopped.


def _alloc_dir(fx: Fixture, kind: str = "backlog") -> Path:
    common = _git(fx.primary, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    d = Path(common) / "mefor-coord" / "alloc" / kind
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_alloc(fx: Fixture, number: str, worktree: Path | str, kind: str = "backlog") -> Path:
    f = _alloc_dir(fx, kind) / f"{number}.json"
    f.write_text(
        json.dumps(
            {
                "number": number,
                "kind": kind,
                "title": "t",
                "branch": "b",
                "worktree": str(worktree).replace("\\", "/"),
            }
        ),
        encoding="utf-8",
    )
    return f


def _put_on_main(fx: Fixture, body: str) -> None:
    """Put a docs/BACKLOG.md on origin/main WITHOUT touching the working tree, so the guard's
    ls-tree/show read is what is exercised rather than a file on disk."""
    (fx.primary / "docs").mkdir(exist_ok=True)
    (fx.primary / "docs" / "BACKLOG.md").write_text(body, encoding="utf-8")
    _git(fx.primary, "add", "docs/BACKLOG.md")
    _git(fx.primary, "commit", "-qm", "ledger")
    head = _git(fx.primary, "rev-parse", "HEAD").strip()
    _git(fx.primary, "update-ref", "refs/remotes/origin/main", head)


def test_removal_is_REFUSED_when_the_worktree_owns_an_unlanded_number(fx: Fixture) -> None:
    wt = fx.add("alpha")
    _write_alloc(fx, "9101", wt)

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode != 0, "the removal proceeded and burned the number"
    assert "9101" in proc.stderr, "the refusal does not name the number, so nobody can act on it"
    assert fx.is_registered(wt), "the worktree was removed despite the refusal"


def test_removal_PROCEEDS_when_the_owned_number_is_already_on_main(fx: Fixture) -> None:
    """THE CONTROL THAT MAKES THE REFUSAL ABOVE MEAN SOMETHING. Without it, a guard that refused
    unconditionally would pass every other test here and block every removal in the repo."""
    wt = fx.add("alpha")
    _write_alloc(fx, "9102", wt)
    _put_on_main(fx, "# Backlog" + chr(10) * 2 + "## 9102. already landed" + chr(10))

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode == 0, proc.stderr
    assert not fx.is_registered(wt)


def test_an_allocation_owned_by_a_DIFFERENT_worktree_does_not_block(fx: Fixture) -> None:
    wt = fx.add("alpha")
    other = fx.add("beta")
    _write_alloc(fx, "9103", other)

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode == 0, proc.stderr
    assert not fx.is_registered(wt)


def test_an_unreadable_allocation_record_refuses(fx: Fixture) -> None:
    """CANNOT-TELL COUNTS AS AT-RISK. An unparseable record might name this worktree, and proceeding
    on that ambiguity is the irreversible direction."""
    wt = fx.add("alpha")
    (_alloc_dir(fx) / "9104.json").write_text("{not json", encoding="utf-8")

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode != 0, "removal proceeded past a record it could not read"
    assert "9104" in proc.stderr
    assert fx.is_registered(wt)


def test_the_override_is_NOT_Force(fx: Fixture) -> None:
    """-Force means "I accept losing uncommitted changes". It must not also mean "I accept burning a
    ledger number" -- one consent covering two unrelated risks is how an irreversible one gets given
    away by accident."""
    wt = fx.add("alpha")
    _write_alloc(fx, "9105", wt)

    forced = run(fx, "-Name", "alpha", "-Force")
    assert forced.returncode != 0, "-Force bypassed the allocation guard"
    assert fx.is_registered(wt)

    allowed = run(fx, "-Name", "alpha", "-AllowOrphanedAllocations")
    assert allowed.returncode == 0, allowed.stderr
    assert not fx.is_registered(wt)
