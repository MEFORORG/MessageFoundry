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
