# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests._no_prompt import run_holding_stdin_open
from tests.test_worktree_remove_path import _ENV, copy_real_scripts, settle_worktrees

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
    cwd: Path | None = None,
    extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Drive the real script. ``repo_root`` defaults to the fixture primary and is NEVER omitted
    unless a test is deliberately exercising the ``$PSScriptRoot`` default against a copied script.

    The environment is the shared ``_ENV``: no inherited GIT_* variable, CLAUDE_CONFIG_DIR or
    MEFOR_COORD_ROOT, so git answers for the fixture and the claim and allocation reads resolve to
    the fixture's own coordination root, never the shared real one. ``extra`` adds to it.
    """
    # Both removal routes refuse a tree written to inside its quiet period (vault BACKLOG #2988), and
    # every fixture tree is seconds old. The quiet period itself is driven in
    # tests/test_worktree_remove_in_use.py.
    settle_worktrees(fx.primary)
    argv = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script or SCRIPT)]
    root = fx.primary if repo_root is None else repo_root
    if root != "":
        argv += ["-RepoRoot", str(root)]
    return subprocess.run(
        [*argv, *args],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        cwd=str(cwd or fx.root),
        env={**_ENV, **(extra or {})},
    )


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


def test_ignored_venv_does_not_block_removal(fx: Fixture) -> None:
    """The `.venv` case the header calls expected. It is gitignored, as it is in this repository, so
    `git status --porcelain` does not list it and -Name does not refuse it."""
    (fx.primary / ".git" / "info" / "exclude").write_text(".venv/\n", encoding="utf-8")
    wt = fx.add("venv")
    (wt / ".venv").mkdir()
    (wt / ".venv" / "marker.txt").write_text("not tracked anywhere", encoding="utf-8")

    proc = run(fx, "-Name", "venv")

    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()


@pytest.mark.parametrize("hide_untracked", [False, True], ids=["default", "showUntrackedFiles-no"])
def test_name_refuses_untracked_files_and_force_overrides(
    fx: Fixture, hide_untracked: bool
) -> None:
    """Red before the fix (BACKLOG #2554 finding 3): -Name dropped every `??` line, so an untracked
    file older than the quiet period went with `worktree remove --force` without -Force. A config
    that hides untracked files from `git status` must not hide them from the refusal."""
    if hide_untracked:
        _git(fx.primary, "config", "status.showUntrackedFiles", "no")
    wt = fx.add("untracked")
    (wt / "deep").mkdir()
    (wt / "deep" / "notes.txt").write_text("untracked work\n", encoding="utf-8")

    refused = run(fx, "-Name", "untracked")

    assert refused.returncode != 0
    assert "untracked files" in refused.stderr, refused.stdout + refused.stderr
    assert "deep/" in refused.stdout
    assert (wt / "deep" / "notes.txt").is_file()
    assert fx.is_registered(wt)

    control = run(fx, "-Name", "untracked", "-Force")
    assert control.returncode == 0, control.stdout + control.stderr
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
    copy_real_scripts(fx.primary)
    copied = fx.primary / "scripts" / "worktree" / "remove.ps1"

    proc = run(fx, "-Name", "bydefault", script=copied, repo_root="")

    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()
    assert not fx.is_registered(wt)


_LINKED_REFUSAL = "-Name from a linked worktree's copy needs -RepoRoot"


def test_a_copy_in_a_LINKED_worktree_refuses_name_without_repo_root(fx: Fixture) -> None:
    """BACKLOG #1894. Before it, the copy in linked worktree ``repo-host`` searched ``repo-host-foo``;
    anchored on the primary it would reach ``repo-foo`` instead, a different tree that may be another
    session's. A linked copy therefore refuses -Name unless -RepoRoot names the checkout meant, and
    -RepoRoot is used as given: the linked worktree reaches its own sibling, the primary reaches its."""
    host = fx.add("host")
    target = fx.add("foo")
    beside_host = host.parent / f"{host.name}-foo"
    _git(fx.primary, "worktree", "add", "-q", "-b", "host-foo", str(beside_host))
    copy_real_scripts(host)
    copied = host / "scripts" / "worktree" / "remove.ps1"

    refused = run(fx, "-Name", "foo", script=copied, repo_root="")
    assert refused.returncode != 0
    assert _LINKED_REFUSAL in refused.stderr, refused.stdout + refused.stderr
    assert "Nothing was removed" in refused.stderr, refused.stderr
    assert target.exists() and beside_host.exists()

    old_shape = run(fx, "-Name", "foo", script=copied, repo_root=host)
    assert old_shape.returncode == 0, old_shape.stdout + old_shape.stderr
    assert not beside_host.exists()
    assert not fx.is_registered(beside_host)
    assert target.exists()

    proc = run(fx, "-Name", "foo", script=copied, repo_root=fx.primary)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not target.exists()
    assert not fx.is_registered(target)
    assert host.exists() and fx.is_registered(host)

    listing = run(fx, "-List", script=copied, repo_root="")
    assert listing.returncode == 0, listing.stdout + listing.stderr
    assert f"-Name root: {fx.primary}" in listing.stdout, listing.stdout


@pytest.mark.parametrize("leftover", ["absent", "unregistered-dir"])
def test_a_linked_copy_never_reaches_the_primarys_sibling_when_its_own_is_not_registered(
    fx: Fixture, leftover: str
) -> None:
    """Red at 265e6e87 (BACKLOG #1894 review round 4, finding 1): the guard refused only while
    ``repo-host-foo`` was a REGISTERED worktree, so with it absent, or left as a plain directory,
    the linked copy removed ``repo-foo``. Before #1894 that copy threw on ``repo-host-foo``, so the
    run reached a tree it never could. It must refuse and leave both in place."""
    host = fx.add("host")
    target = fx.add("foo")
    copy_real_scripts(host)
    beside_host = host.parent / f"{host.name}-foo"
    if leftover == "unregistered-dir":
        beside_host.mkdir()
        (beside_host / "left.txt").write_text("x", encoding="utf-8")

    proc = run(
        fx, "-Name", "foo", script=host / "scripts" / "worktree" / "remove.ps1", repo_root=""
    )

    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert _LINKED_REFUSAL in proc.stderr, proc.stdout + proc.stderr
    assert target.exists() and fx.is_registered(target)
    assert (beside_host / "left.txt").is_file() == (leftover == "unregistered-dir")


def test_name_refuses_a_directory_that_is_not_a_registered_worktree(fx: Fixture) -> None:
    """A separate clone at the sibling path is not this clone's worktree, and every read -Name makes
    would be asked of the wrong repository. Refused up front; the registered control goes through."""
    stranger = fx.sibling("stranger")
    stranger.mkdir()
    _git(stranger, "init", "-q", "-b", "main")

    proc = run(fx, "-Name", "stranger", "-Force")

    assert proc.returncode != 0
    assert "not a registered linked worktree" in proc.stderr, proc.stdout + proc.stderr
    assert (stranger / ".git").is_dir()

    wt = fx.add("known")
    control = run(fx, "-Name", "known")
    assert control.returncode == 0, control.stdout + control.stderr
    assert not wt.exists()


# --- BACKLOG #1038: what the removal must not lose ------------------------------------------------
#
# A `remove.ps1 -Nested` route existed for one round and was withdrawn: its occupancy fence could not
# see an `isolation: worktree` subagent. These two guards stayed, because they hold on the one route
# this script has.


def test_a_detached_HEAD_holding_commits_no_ref_holds_is_refused_even_with_force(
    fx: Fixture,
) -> None:
    """Red before the fix: removal deletes the HEAD reflog with the worktree, so those commits would be
    reachable from nothing. -Force means "discard changes" and does not override it."""
    wt = fx.sibling("loose")
    _git(fx.primary, "worktree", "add", "-q", "--detach", str(wt))
    tip = _commit(wt, "loose.txt", "only here")

    proc = run(fx, "-Name", "loose", "-Force")

    assert proc.returncode != 0
    assert "held by no ref" in proc.stderr
    assert wt.exists() and fx.is_registered(wt)
    # Control: once a branch holds the commit, the same removal goes through.
    _git(fx.primary, "branch", "keep-loose", tip)
    again = run(fx, "-Name", "loose", "-Force")
    assert again.returncode == 0, again.stderr
    assert not wt.exists()


def test_a_git_status_that_FAILS_refuses_instead_of_reading_as_clean(fx: Fixture) -> None:
    """Red before the fix: a corrupt index makes `git status` exit 128 and print nothing, which the
    guard read as "no tracked changes", and the edit below was then force-removed without -Force."""
    wt = fx.add("broken")
    (wt / "seed.txt").write_text("an edit nobody committed\n", encoding="utf-8")
    index = Path(_git(wt, "rev-parse", "--path-format=absolute", "--git-path", "index").strip())
    index.write_bytes(b"not an index")

    proc = run(fx, "-Name", "broken")

    assert proc.returncode != 0
    assert "git status failed" in proc.stderr
    assert (wt / "seed.txt").read_text(encoding="utf-8") == "an edit nobody committed\n"


# --- BACKLOG #5648: the gates -Name used to skip ---------------------------------------------------
#
# -Path refused each of these, and a bare -Name went past them to `worktree remove --force` and a
# blanket `worktree prune`. Each refusal below is paired with the run that is supposed to succeed.


@pytest.mark.parametrize("var", ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"])
def test_name_refuses_an_inherited_git_redirect(fx: Fixture, var: str) -> None:
    """Red before the fix: -Name checked these only under -Discard. GIT_DIR pointed at another
    repository makes every read below describe that repository, not the target."""
    other = fx.root / "other"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    wt = fx.add("redirected")

    proc = run(fx, "-Name", "redirected", extra={var: str(other / ".git")})

    assert proc.returncode != 0
    assert f"{var} is set" in proc.stderr, proc.stdout + proc.stderr
    assert wt.exists() and fx.is_registered(wt)

    control = run(fx, "-Name", "redirected")
    assert control.returncode == 0, control.stdout + control.stderr
    assert not wt.exists()


def test_name_refuses_when_the_caller_stands_inside_the_target(fx: Fixture) -> None:
    """Red before the fix: git's removal from inside the tree fails part-way, after deleting what it
    could. The refusal has to come before anything is removed."""
    wt = fx.add("standing")
    (wt / "deep").mkdir()
    (wt / "deep" / "kept.txt").write_text("untracked, older than six hours\n", encoding="utf-8")

    proc = run(fx, "-Name", "standing", "-Force", cwd=wt / "deep")

    assert proc.returncode != 0
    assert "standing inside" in proc.stderr, proc.stdout + proc.stderr
    assert (wt / "deep" / "kept.txt").is_file()
    assert (wt / "seed.txt").is_file()
    assert fx.is_registered(wt)

    control = run(fx, "-Name", "standing", "-Force")
    assert control.returncode == 0, control.stdout + control.stderr
    assert not wt.exists()


def test_name_refuses_when_the_copy_being_run_lives_inside_the_target(fx: Fixture) -> None:
    """Red before the fix: the copy in the target removed its own tree from under itself."""
    wt = fx.add("selfhost")
    copy_real_scripts(wt)
    inside = wt / "scripts" / "worktree" / "remove.ps1"

    proc = run(fx, "-Name", "selfhost", "-Force", script=inside)

    assert proc.returncode != 0
    assert "lives inside" in proc.stderr, proc.stdout + proc.stderr
    assert inside.is_file() and fx.is_registered(wt)

    control = run(fx, "-Name", "selfhost", "-Force")
    assert control.returncode == 0, control.stdout + control.stderr
    assert not wt.exists()


@pytest.mark.parametrize(
    ("var", "value"),
    [
        ("GIT_CONFIG_PARAMETERS", "'core.fsmonitor=false'"),
        ("GIT_CONFIG_COUNT", "0"),
        ("GIT_CONFIG_GLOBAL", ""),
    ],
)
@pytest.mark.parametrize("route", ["-Name", "-List"])
def test_a_git_config_carrier_refuses_every_route(
    fx: Fixture, var: str, value: str, route: str
) -> None:
    """Vault BACKLOG #8225 item 2, #5648's remainder. Red before the fix: remove.ps1 refused the four
    redirects but not config carried in the environment, which steers every `git -C <path>` read, for
    example through a core.fsmonitor hook. GIT_CONFIG_GLOBAL is given an empty file of its own."""
    if var == "GIT_CONFIG_GLOBAL":
        value = str(fx.root / "empty.gitconfig")
        Path(value).write_text("", encoding="utf-8")
    wt = fx.add("carried")
    args = ("-Name", "carried") if route == "-Name" else ("-List",)

    proc = run(fx, *args, extra={var: value})

    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert f"{var} is set" in proc.stderr, proc.stdout + proc.stderr
    assert wt.exists() and fx.is_registered(wt)

    control = run(fx, *args)
    assert control.returncode == 0, control.stdout + control.stderr
    assert wt.exists() != (route == "-Name")


def _junction(link: Path, target: Path) -> None:
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True
    )


@pytest.mark.parametrize("via", ["cwd", "script"])
def test_name_refuses_a_junction_alias_of_the_target(fx: Fixture, via: str) -> None:
    """Vault BACKLOG #8225 item 8. Red before the fix: the inside-target check compared spellings
    only, so a caller standing in, or running a copy from, a junction alias of the target passed it
    and the forced removal ran from inside the tree."""
    wt = fx.add("aliased")
    (wt / "deep").mkdir()
    copy_real_scripts(wt)
    alias = fx.root / "alias"
    _junction(alias, wt)
    try:
        if via == "cwd":
            proc = run(fx, "-Name", "aliased", "-Force", cwd=alias / "deep")
            needle = "standing inside"
        else:
            proc = run(
                fx,
                "-Name",
                "aliased",
                "-Force",
                script=alias / "scripts" / "worktree" / "remove.ps1",
            )
            needle = "lives inside"
        assert proc.returncode != 0, proc.stdout + proc.stderr
        assert needle in proc.stderr, proc.stdout + proc.stderr
        assert (wt / "seed.txt").is_file() and fx.is_registered(wt)
    finally:
        os.rmdir(alias)

    control = run(fx, "-Name", "aliased", "-Force")
    assert control.returncode == 0, control.stdout + control.stderr
    assert not wt.exists()


def test_name_refuses_a_commit_only_the_head_reflog_holds_even_with_force(fx: Fixture) -> None:
    """Vault BACKLOG #8225 item 9. Red before the fix: -Path refused it and -Name did not. A commit
    made on a detached HEAD, then left by switching back, is held by the tree's HEAD reflog alone,
    which the removal deletes."""
    wt = fx.add("reflogged")
    _git(wt, "checkout", "-q", "--detach")
    loose = _commit(wt, "loose.txt", "held by the HEAD reflog alone")
    _git(wt, "checkout", "-q", "reflogged")

    proc = run(fx, "-Name", "reflogged", "-Force")

    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "no shared ref holds" in proc.stdout, proc.stdout + proc.stderr
    assert wt.exists() and fx.is_registered(wt)

    # Control: once a branch holds the commit, the same call removes the tree.
    _git(fx.primary, "branch", "keep-loose", loose)
    control = run(fx, "-Name", "reflogged", "-Force")
    assert control.returncode == 0, control.stdout + control.stderr
    assert not wt.exists()


def test_name_removes_a_tree_whose_amended_commit_only_the_kept_branch_reflog_holds(
    fx: Fixture,
) -> None:
    """The twin of the reflog refusal. Without -DeleteBranch the branch stays, and its own reflog
    with it, so an amended commit survives the removal and must not refuse it. With -DeleteBranch
    the script may delete the branch and its reflog, so the check keeps counting the commit and the
    same tree refuses."""
    wt = fx.add("amended")
    _commit(wt, "a.txt", "v1")
    _git(wt, "commit", "-q", "--amend", "-m", "v1 amended")

    refused = run(fx, "-Name", "amended", "-DeleteBranch")
    assert refused.returncode != 0, refused.stdout + refused.stderr
    assert "no shared ref holds" in refused.stdout, refused.stdout + refused.stderr
    assert wt.exists() and fx.is_registered(wt)

    proc = run(fx, "-Name", "amended")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not wt.exists()
    assert fx.branch_exists("amended")


@pytest.mark.parametrize("flag", ["--skip-worktree", "--assume-unchanged"])
def test_name_refuses_a_flagged_file_and_force_overrides_it_by_name(fx: Fixture, flag: str) -> None:
    """Red before the fix: git status does not read a flagged file, so an edit to one read as a clean
    tree and was force-removed without -Force."""
    wt = fx.add("flagged")
    _git(wt, "update-index", flag, "seed.txt")
    (wt / "seed.txt").write_text("an edit git status cannot see\n", encoding="utf-8")
    assert _git(wt, "status", "--porcelain").strip() == "", "PRECONDITION: status must read clean"

    refused = run(fx, "-Name", "flagged")

    assert refused.returncode != 0
    assert "flagged seed.txt" in refused.stdout, refused.stdout + refused.stderr
    assert "skip-worktree or assume-unchanged" in refused.stderr
    assert (wt / "seed.txt").read_text(encoding="utf-8") == "an edit git status cannot see\n"
    assert fx.is_registered(wt)

    # -Force overrides it, and the override names what it discarded.
    forced = run(fx, "-Name", "flagged", "-Force")
    assert forced.returncode == 0, forced.stdout + forced.stderr
    assert "-Force: not refusing 1 file(s) flagged" in forced.stdout, forced.stdout
    assert "flagged seed.txt" in forced.stdout
    assert not wt.exists()


def test_name_names_flagged_files_in_the_tracked_change_refusal(fx: Fixture) -> None:
    """The refusal that tells the operator to re-run with -Force must show every flagged file that
    -Force would also take, not only the tracked change."""
    wt = fx.add("both")
    (wt / "other.txt").write_text("tracked\n", encoding="utf-8")
    _git(wt, "add", "other.txt")
    _git(wt, "commit", "-qm", "other")
    _git(wt, "update-index", "--skip-worktree", "seed.txt")
    (wt / "seed.txt").write_text("hidden edit\n", encoding="utf-8")
    (wt / "other.txt").write_text("visible edit\n", encoding="utf-8")

    proc = run(fx, "-Name", "both")

    assert proc.returncode != 0
    assert "uncommitted tracked changes" in proc.stderr, proc.stdout + proc.stderr
    assert "flagged seed.txt" in proc.stdout, proc.stdout
    assert fx.is_registered(wt)


def test_name_runs_no_blanket_prune_so_another_stale_registration_survives(fx: Fixture) -> None:
    """Red before the fix (and BACKLOG #7619): -Name ran `git worktree prune` after the removal, which
    drops every registration whose directory is missing at that moment, with its HEAD reflog."""
    gone = fx.add("gone")
    shutil.rmtree(gone)
    assert fx.is_registered(gone), "PRECONDITION: the stale registration must exist"
    # The negative control: a prune in this fixture WOULD drop it, so its survival below means something.
    dry = subprocess.run(
        ["git", "-C", str(fx.primary), "worktree", "prune", "--dry-run", "--verbose"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "repo-gone" in dry.stdout + dry.stderr, dry
    wt = fx.add("mine")

    proc = run(fx, "-Name", "mine")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not wt.exists() and not fx.is_registered(wt)
    assert fx.is_registered(gone), (
        "a blanket prune dropped a registration this run was not asked about"
    )


# --- claims and the removed worktree: refused before, never released after --------------------
#
# BACKLOG #1295 made this route DELETE the claim files a removed tree held, because `claim.ps1
# -Release` is worktree-scoped and a claim outliving its holder reads as in flight forever. That
# release left no line in the claims .history file (#1068), and it fired while the work could
# still be running (vault BACKLOG #2988). So -Name now refuses a claimed tree, as -Path does, and
# the release goes through claim.ps1, which records it.
#
# THE FALSE POSITIVE IS STILL THE ONE TO FEAR. A claim held by a DIFFERENT, living worktree must
# neither block the removal nor be touched, and a claim whose path merely prefixes the target is a
# different worktree's.


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


def test_a_claims_registry_under_a_dead_link_refuses(fx: Fixture) -> None:
    """Vault BACKLOG #2985, added item 1. Red before the fix: remove.ps1 read a registry it could not
    reach as absent, so a coordination folder that is a link to a folder now gone read as "no
    claims" and the tree went. It reads registries the nightly removal's way now: absent only when
    the folder above lists without it."""
    wt = fx.add("unreached")
    common = Path(
        _git(fx.primary, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    )
    target = fx.root / "share-gone"
    target.mkdir()
    _junction(common / "mefor-coord", target)
    target.rmdir()
    try:
        proc = run(fx, "-Name", "unreached", "-Force")
        assert proc.returncode != 0, proc.stdout + proc.stderr
        assert "the claims directory" in proc.stdout + proc.stderr, proc.stdout + proc.stderr
        assert wt.exists() and fx.is_registered(wt)
    finally:
        os.rmdir(common / "mefor-coord")

    # Control: with no coordination folder at all, the same call removes the tree.
    control = run(fx, "-Name", "unreached", "-Force")
    assert control.returncode == 0, control.stdout + control.stderr
    assert not wt.exists()


def test_a_claim_held_by_the_target_refuses_and_is_not_released(fx: Fixture) -> None:
    wt = fx.add("alpha")
    claim = _write_claim(fx, "9001", wt)

    proc = run(fx, "-Name", "alpha", "-Force")

    assert proc.returncode != 0
    assert "still holds 1 work claim(s): 9001" in proc.stdout, proc.stdout + proc.stderr
    assert claim.exists(), "a claim was released with no .history line"
    assert fx.is_registered(wt)
    history = _claims_dir(fx) / ".history"
    assert not history.exists(), "this script wrote to the release ledger; only claim.ps1 may"

    # Control: released first, the same call removes the tree.
    claim.unlink()
    proc = run(fx, "-Name", "alpha", "-Force")
    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()


def test_a_claim_held_by_a_DIFFERENT_worktree_survives(fx: Fixture) -> None:
    """THE FALSE-POSITIVE GUARD: it neither blocks the removal nor is released by it."""
    wt = fx.add("alpha")
    other = fx.add("beta")
    theirs = _write_claim(fx, "9003", other)

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()
    assert theirs.exists(), (
        "a claim belonging to a LIVING worktree was released. That hands its key to another session "
        "and invites the duplicate build the registry exists to stop -- worse than the orphan."
    )


def test_a_claim_whose_path_merely_PREFIXES_the_removed_one_survives(fx: Fixture) -> None:
    """`repo-alpha` is a string prefix of `repo-alpha-two`. A StartsWith match would refuse on, or
    release, the other tree's claim. Full normalised path, no prefix, no leaf."""
    wt = fx.add("alpha")
    nested = fx.add("alpha-two")
    victim = _write_claim(fx, "9005", nested)
    # CONTROL that the match is live at all: the same spelling of THIS tree refuses.
    exact = _write_claim(fx, "9004", wt)
    assert run(fx, "-Name", "alpha").returncode != 0
    exact.unlink()

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode == 0, proc.stderr
    assert not wt.exists()
    assert victim.exists(), "a prefix match released a different worktree's claim"


def test_an_unreadable_claim_refuses_and_is_left_in_place(fx: Fixture) -> None:
    """UNREADABLE IS NOT ABSENT. A file that will not parse might name this worktree, so the removal
    refuses, and the file is not deleted on a guess."""
    wt = fx.add("alpha")
    bad = _claims_dir(fx) / "9006.json"
    bad.write_text("{not json", encoding="utf-8")

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode != 0
    assert "9006.json does not parse" in proc.stdout, proc.stdout + proc.stderr
    assert bad.exists(), "an unparseable claim was deleted on a guess"
    assert fx.is_registered(wt)


def test_removal_still_succeeds_with_no_claims_directory(fx: Fixture) -> None:
    """The check must not turn a working removal into a failure on a repo that has never claimed."""
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


def _put_adr_on_main(fx: Fixture, number: str) -> None:
    """Put an ADR on origin/main WITHOUT touching the working tree, so the guard's ls-tree read is
    what is exercised rather than a file on disk.

    THIS USED TO PLANT A docs/BACKLOG.md. The ledger left this repository (BACKLOG #1250), so
    `remove.ps1` can no longer answer "did this backlog number land" and returns its CANNOT TELL --
    which the caller treats as at-risk, by design. ADR numbers are still here, so the control moved
    to the kind that has an answer.
    """
    adr = fx.primary / "docs" / "adr"
    adr.mkdir(parents=True, exist_ok=True)
    (adr / f"{number}-already-landed.md").write_text(f"# ADR {number}\n", encoding="utf-8")
    _git(fx.primary, "add", "docs/adr")
    _git(fx.primary, "commit", "-qm", "adr")
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
    unconditionally would pass every other test here and block every removal in the repo.

    ON AN ADR NUMBER, because that is the only kind this repository can still answer for since the
    ledger moved (BACKLOG #1250). A backlog number now returns CANNOT TELL, so it can no longer
    carry the PROCEEDS arm -- see `_put_adr_on_main`.
    """
    wt = fx.add("alpha")
    _write_alloc(fx, "9102", wt, kind="adr")
    _put_adr_on_main(fx, "9102")

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


# --- BACKLOG #1829: the retired-allocator tombstone ------------------------------------------------
#
# Why remove.ps1 skips this one ownerless record is in its Read-RecordFile comment.

_TOMBSTONE_WRITER = SCRIPT.parents[1] / "coord" / "tombstone-retired-backlog-allocator.ps1"
_ABSENT = object()  # a field the record leaves out entirely


def _tombstone_record(**over: object) -> dict[str, object]:
    record: dict[str, object] = {
        "number": "1000000",
        "kind": "backlog",
        "title": "RETIRED ALLOCATOR TOMBSTONE (BACKLOG #1829).",
        "branch": "",
        "worktree": "",
        "claimed": "2026-09-26T07:40:31.8261737-05:00",
        "tombstone": True,
    }
    record.update(over)
    return {k: v for k, v in record.items() if v is not _ABSENT}


def _write_tombstone(fx: Fixture, number: str = "1000000", **over: object) -> Path:
    f = _alloc_dir(fx) / f"{number}.json"
    f.write_text(json.dumps(_tombstone_record(number=number, **over)), encoding="utf-8")
    return f


def test_the_tombstone_fixture_is_the_shape_the_writer_writes() -> None:
    """The tests below are only about the real tombstone if they write the record the writer writes."""
    src = _TOMBSTONE_WRITER.read_text(encoding="utf-8")
    # Only the record's own hashtable counts, so a comment or help line naming a field cannot pass.
    block = re.search(r"\$record = \[ordered\]@\{(.*?)^\}", src, re.DOTALL | re.MULTILINE)
    assert block, "the tombstone writer no longer builds `$record = [ordered]@{...}`"
    fields = (
        r'^\s*branch\s*=\s*""\s*$',
        r'^\s*worktree\s*=\s*""\s*$',
        r"^\s*tombstone\s*=\s*\$true\s*$",
    )
    for field in fields:
        assert re.search(field, block.group(1), re.MULTILINE), (
            f"the tombstone record no longer sets {field}; re-check remove.ps1"
        )


def test_the_tombstone_alone_does_not_refuse_a_removal(fx: Fixture) -> None:
    wt = fx.add("alpha")
    _write_tombstone(fx)

    proc = run(fx, "-Name", "alpha")
    assert proc.returncode == 0, proc.stderr
    assert not fx.is_registered(wt)


def test_the_tombstone_does_not_hide_a_real_at_risk_allocation(fx: Fixture) -> None:
    wt = fx.add("alpha")
    _write_tombstone(fx)
    _write_alloc(fx, "9106", wt)

    proc = run(fx, "-Name", "alpha", "-Force")
    assert proc.returncode != 0, "the tombstone skip let a real at-risk allocation through"
    assert "9106" in proc.stderr
    assert "1000000" not in proc.stderr, "the tombstone was still reported as unreadable"
    assert fx.is_registered(wt)


_NEAR_MISSES: dict[str, dict[str, object]] = {
    "1000001": {"tombstone": "true"},
    "1000002": {"tombstone": 1},
    "1000003": {"tombstone": False},
    "1000004": {"tombstone": _ABSENT},
    "1000005": {"worktree": _ABSENT},
    "1000006": {"worktree": None},
    "1000007": {"worktree": " "},
    "1000008": {"branch": "b"},
    "1000009": {"branch": _ABSENT},
}


def test_an_ownerless_record_that_is_not_exactly_the_tombstone_still_refuses(fx: Fixture) -> None:
    """FAIL-CLOSED IS KEPT. Only the writer's exact shape is skipped; each near miss stays a
    cannot-tell, and -Force still does not cover it. The guard lists every unreadable record in one
    refusal, so one run checks every shape, and the real tombstone beside them is the control."""
    wt = fx.add("alpha")
    _write_tombstone(fx)
    for number, over in _NEAR_MISSES.items():
        _write_tombstone(fx, number, **over)

    proc = run(fx, "-Name", "alpha", "-Force")
    assert proc.returncode != 0, "removal proceeded past every near-tombstone"
    for number, over in _NEAR_MISSES.items():
        assert f"{number}.json" in proc.stderr, f"near-tombstone {over!r} was skipped"
    assert "1000000.json" not in proc.stderr, "the real tombstone was reported as unreadable"
    assert fx.is_registered(wt)


def test_a_malformed_record_beside_the_tombstone_still_refuses(fx: Fixture) -> None:
    wt = fx.add("alpha")
    _write_tombstone(fx)
    (_alloc_dir(fx) / "9107.json").write_text("{not json", encoding="utf-8")

    proc = run(fx, "-Name", "alpha", "-Force")
    assert proc.returncode != 0, "removal proceeded past a record it could not read"
    assert "9107" in proc.stderr
    assert fx.is_registered(wt)


@pytest.mark.parametrize("args", [(), ("-Force",)], ids=["bare", "force-only"])
def test_a_call_without_a_target_refuses_instead_of_prompting(
    fx: Fixture, args: tuple[str, ...]
) -> None:
    """Vault BACKLOG #3627: the default ``ByName`` set bound without ``-Name``. Red pre-fix."""
    wt = fx.add("alpha")
    rc, err = run_holding_stdin_open(
        ["pwsh", "-NoProfile", "-File", str(SCRIPT), "-RepoRoot", str(fx.primary), *args],
        cwd=fx.primary,
    )
    assert rc != 0, "a removal naming no worktree must be refused"
    assert "-Name" in err, err
    assert fx.is_registered(wt)
    assert fx.branch_exists("alpha")


def test_name_through_a_junction_alias_of_the_primary_is_neither_ambiguous_nor_unregistered(
    fx: Fixture,
) -> None:
    """Red in review round 2 (BACKLOG #1894): reached through a junction, the primary's own copy read
    its alias spelling as a second candidate and refused as ambiguous. It must remove the one real
    tree. An alias -RepoRoot is refused since review round 3: -Name builds its target from the
    spelling given, so the spelling must be the checkout's top as git resolves it."""
    alias = fx.root / "alias"
    _junction(alias, fx.primary.parent)
    try:
        copy_real_scripts(fx.primary)
        via_alias = alias / fx.primary.name / "scripts" / "worktree" / "remove.ps1"

        first = fx.add("viaalias")
        proc = run(fx, "-Name", "viaalias", script=via_alias, repo_root="")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert not first.exists() and not fx.is_registered(first)

        second = fx.add("viaroot")
        proc = run(fx, "-Name", "viaroot", repo_root=alias / fx.primary.name)
        assert proc.returncode != 0, proc.stdout + proc.stderr
        assert "not the top of a checkout" in proc.stderr, proc.stdout + proc.stderr
        assert second.exists() and fx.is_registered(second)
    finally:
        os.rmdir(alias)


@pytest.mark.parametrize("how", ["explicit", "positional-dot"])
def test_name_refuses_a_repo_root_below_the_checkout_top(fx: Fixture, how: str) -> None:
    """Red in review round 3 (BACKLOG #1894): an explicit -RepoRoot was re-read through
    ``--show-toplevel``, so a subdirectory of the primary re-anchored on the primary and removed
    ``<primary>-<Name>``, a tree the caller never named. Before #1894 it built ``<subdir>-<Name>`` and
    threw "No such worktree". A removal script must never reach further than it did."""
    target = fx.add("foo")
    sub = fx.primary / "sub"
    sub.mkdir()

    if how == "explicit":
        proc = run(fx, "-Name", "foo", repo_root=sub)
    else:
        proc = run(fx, "-Name", "foo", ".", repo_root="", cwd=sub)

    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "Nothing was removed" in proc.stderr, proc.stdout + proc.stderr
    assert target.exists() and fx.is_registered(target)

    control = run(fx, "-Name", "foo", repo_root=fx.primary)
    assert control.returncode == 0, control.stdout + control.stderr
    assert not target.exists()


def test_a_linked_copy_run_through_a_junction_still_refuses(fx: Fixture) -> None:
    """Red in review round 3 (BACKLOG #1894): the ambiguity guard built the copy's old sibling from the
    junction spelling it was invoked through, which git's list never matches, so it removed
    ``repo-foo`` while ``repo-host-foo``, the tree the copy's older command meant, was registered.
    The linked-copy refusal reads git's own record of the copy's checkout, so no spelling skips it."""
    host = fx.add("host")
    target = fx.add("foo")
    beside_host = host.parent / f"{host.name}-foo"
    _git(fx.primary, "worktree", "add", "-q", "-b", "host-foo", str(beside_host))
    copy_real_scripts(host)
    alias = fx.root / "hostalias"
    _junction(alias, host)
    try:
        proc = run(
            fx, "-Name", "foo", script=alias / "scripts" / "worktree" / "remove.ps1", repo_root=""
        )
    finally:
        os.rmdir(alias)

    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert _LINKED_REFUSAL in proc.stderr, proc.stdout + proc.stderr
    assert target.exists() and fx.is_registered(target)
    assert beside_host.exists() and fx.is_registered(beside_host)


def test_a_linked_copy_through_a_junction_of_its_parent_refuses_with_its_sibling_absent(
    fx: Fixture,
) -> None:
    """Red at 265e6e87 (BACKLOG #1894 review round 4, finding 4, the double-alias family): with the
    copy's parent reached through a junction and its own old sibling absent, nothing matched the
    guard, so the run removed ``repo-foo``. The refusal does not depend on any spelling."""
    host = fx.add("host")
    target = fx.add("foo")
    copy_real_scripts(host)
    alias = fx.root / "parentalias"
    _junction(alias, host.parent)
    try:
        proc = run(
            fx,
            "-Name",
            "foo",
            script=alias / host.name / "scripts" / "worktree" / "remove.ps1",
            repo_root="",
        )
    finally:
        os.rmdir(alias)

    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert _LINKED_REFUSAL in proc.stderr, proc.stdout + proc.stderr
    assert target.exists() and fx.is_registered(target)


def test_a_copy_below_the_primarys_top_refuses_name(fx: Fixture) -> None:
    """A copy at ``<primary>/sub/scripts/worktree`` used to search ``<primary>/sub-<Name>`` and throw
    "No such worktree". Re-anchored on the primary it would reach ``<primary>-<Name>``, a tree it
    never could, so -Name refuses unless the copy's root is its checkout's top."""
    target = fx.add("foo")
    sub = fx.primary / "sub"
    sub.mkdir()
    copy_real_scripts(sub)

    proc = run(fx, "-Name", "foo", script=sub / "scripts" / "worktree" / "remove.ps1", repo_root="")

    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "Nothing was removed" in proc.stderr, proc.stdout + proc.stderr
    assert target.exists() and fx.is_registered(target)
