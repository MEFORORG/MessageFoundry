# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Recent uncommitted work, and clones inside a tolerated directory, refuse a removal.

Vault BACKLOG #1017, owner points (iv) and (i), and #2554 finding 3. The working-tree signal dated
the root, the entries directly under it, and two caches, so an edit two folders down moved none of
them. A subagent with no claim that has not committed leaves only that edit, and the session
registry cannot see its tree. Before this change ``-Path -Force`` removed it, and ``-Name`` removed
its new untracked files even without ``-Force``. The ignored-directory exception also tolerated
``.venv`` and ``node_modules`` at any depth, and never looked for the git clones pip and npm put
inside them.

Same rig and rules as ``tests/test_worktree_remove_in_use.py``: synthetic repositories under
``tmp_path`` only, and each refusal is paired with the run that is supposed to succeed.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from tests.test_worktree_remove_in_use import ROUTES, _sibling, _target
from tests.test_worktree_remove_path import (
    Rig,
    _commit,
    _git,
    _out,
    build_rig,
    pytestmark,  # noqa: F401  (the same Windows-and-pwsh skip)
    settle_worktrees,
)


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    return build_rig(tmp_path)


def _deep(wt: Path) -> Path:
    """A tracked file two folders below the root, committed. The caller settles the tree."""
    (wt / "pkg" / "sub").mkdir(parents=True)
    _commit(wt, "pkg/sub/x.py")
    return wt / "pkg" / "sub" / "x.py"


def _extended(path: Path) -> str:
    """The extended-length spelling, which keeps a trailing dot that Win32 would drop."""
    return "\\\\?\\" + str(path)


# --- point (iv): recent uncommitted work, whatever -Force says -----------------------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_a_recent_edit_two_folders_deep_refuses_even_with_force(rig: Rig, route: str) -> None:
    """The breaking case: an edit below the root moves no date the old signal read. Red before the
    fix on both routes: the tree went with exit 0 and took the edit with it."""
    wt = _sibling(rig, "deep")
    edited = _deep(wt)
    settle_worktrees(rig.primary)
    edited.write_text("work in progress\n", encoding="utf-8")

    proc = rig.run(*_target(route, wt), "-Force", settle=False)

    assert proc.returncode != 0, _out(proc)
    assert "Target holds recent uncommitted work" in _out(proc), _out(proc)
    assert "pkg/sub/x.py" in _out(proc), _out(proc)
    assert edited.read_text(encoding="utf-8") == "work in progress\n"
    assert rig.is_registered(wt)

    # Control: the same edit, once it is older than the quiet period, still goes with -Force, so an
    # owner can clear an abandoned tree.
    proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_a_recent_untracked_file_refuses_name_without_force(rig: Rig) -> None:
    """-Name lets untracked files go without -Force. Red before the fix: a fresh one did too."""
    wt = _sibling(rig, "fresh")
    (wt / "pkg" / "sub").mkdir(parents=True)
    settle_worktrees(rig.primary)
    new = wt / "pkg" / "sub" / "new.py"
    new.write_text("not committed yet\n", encoding="utf-8")

    proc = rig.run("-Name", "fresh", settle=False)

    assert proc.returncode != 0, _out(proc)
    assert "Target holds recent uncommitted work" in _out(proc), _out(proc)
    assert "pkg/sub/new.py" in _out(proc), _out(proc)
    assert new.is_file()

    proc = rig.run("-Name", "fresh")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_a_recent_deletion_is_dated_by_the_folder_that_held_it(rig: Rig) -> None:
    """A deleted file has no write time. Removing it rewrites its folder, which is what is dated."""
    wt = _sibling(rig, "gone")
    edited = _deep(wt)
    settle_worktrees(rig.primary)
    edited.unlink()

    proc = rig.run("-Path", str(wt), "-Force", settle=False)

    assert proc.returncode != 0, _out(proc)
    assert "Target holds recent uncommitted work" in _out(proc), _out(proc)
    assert "pkg/sub/x.py" in _out(proc), _out(proc)

    proc = rig.run("-Path", str(wt), "-Force")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_a_recent_rename_is_dated_by_its_folders(rig: Rig) -> None:
    """A renamed file keeps its own old write time. The rename rewrote the folder that holds both
    names, so the folders above each pending path are dated too."""
    wt = _sibling(rig, "moved")
    _deep(wt)
    settle_worktrees(rig.primary)
    _git(wt, "mv", "pkg/sub/x.py", "pkg/sub/y.py")

    proc = rig.run("-Path", str(wt), "-Force", settle=False)

    assert proc.returncode != 0, _out(proc)
    assert "Target holds recent uncommitted work" in _out(proc), _out(proc)
    assert "'pkg/sub' was written" in _out(proc), _out(proc)

    proc = rig.run("-Path", str(wt), "-Force")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


@pytest.mark.parametrize("route", ROUTES)
def test_a_pending_path_that_cannot_be_dated_refuses(rig: Rig, route: str) -> None:
    """A name ending in a dot: git lists it, and Windows reads the name without the dot, so no write
    time can be read for it. The file and its folder are dated two days back, so only the
    cannot-date branch can refuse. Red before the fix: nothing tried to date it."""
    wt = _sibling(rig, "undatable")
    (wt / "pkg").mkdir()
    settle_worktrees(rig.primary)
    odd = wt / "pkg" / "trail."
    with open(_extended(odd), "w", encoding="utf-8") as f:
        f.write("a name Win32 cannot spell\n")
    try:
        then = time.time() - 2 * 24 * 3600
        os.utime(_extended(odd), (then, then))
        os.utime(wt / "pkg", (then, then))
        assert "pkg/trail." in _git(wt, "status", "--porcelain", "--untracked-files=all")

        proc = rig.run(*_target(route, wt), "-Force", settle=False)

        assert proc.returncode != 0, _out(proc)
        assert "Pending work of unknown age" in _out(proc), _out(proc)
        assert "pkg/trail." in _out(proc), _out(proc)
        assert rig.is_registered(wt)
    finally:
        # pytest's own cleanup cannot spell this name either.
        if os.path.lexists(_extended(odd)):
            os.remove(_extended(odd))

    proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


# --- point (i): repositories git status does not read into, and the ignored-directory exception -------


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "clone",
    [
        ".venv/src/pkg",
        "node_modules/left-pad",
        "node_modules/@scope/dep",
        "ide/node_modules/vsce",
    ],
    ids=["venv-src", "node-modules", "scoped", "nested-node-modules"],
)
def test_a_clone_inside_an_ignored_venv_or_node_modules_refuses(
    rig: Rig, route: str, clone: str
) -> None:
    """Git lists an ignored .venv or node_modules as one line and never reads inside, so a pip
    editable clone, or a clone in node_modules, with commits no other ref has, went with the tree.
    Red before the fix on both routes. -Force overrides it, as it does other ignored content."""
    wt = _sibling(rig, "clones")
    (wt / clone / ".git").mkdir(parents=True)
    (wt / clone / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    if clone.startswith("ide/"):
        # As in this repository: ide/ is tracked, and its node_modules holds more than clones. git
        # does not list an ignored folder holding nothing but repositories; the root ones are read
        # whether git lists them or not.
        _commit(wt, "ide/package.json")
        (wt / "ide" / "node_modules" / ".package-lock.json").write_text("{}\n", encoding="utf-8")

    proc = rig.run(*_target(route, wt))

    assert proc.returncode != 0, _out(proc)
    assert "git status does not read into" in _out(proc), _out(proc)
    assert f"{clone}/  (a git clone inside" in _out(proc), _out(proc)
    assert (wt / clone).is_dir() and rig.is_registered(wt)

    proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_an_untracked_nested_repository_refuses_name_without_force(rig: Rig) -> None:
    """git status lists a nested repository as one folder and never dates or lists what is inside.
    Red before the fix: -Name removed it, commits and all, without -Force."""
    wt = _sibling(rig, "nest")
    inner = wt / "nested"
    inner.mkdir()
    _git(inner, "init", "-q", "-b", "main")
    assert "?? nested/" in _git(wt, "status", "--porcelain", "--untracked-files=all")

    proc = rig.run("-Name", "nest")

    assert proc.returncode != 0, _out(proc)
    assert "an untracked git repository inside the tree" in _out(proc), _out(proc)
    assert inner.is_dir()

    proc = rig.run("-Name", "nest", "-Force")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


@pytest.mark.parametrize("route", ROUTES)
def test_a_nested_repository_committed_in_recently_refuses_even_with_force(
    rig: Rig, route: str
) -> None:
    """A commit inside a nested repository rewrites its .git and moves no folder the outer status
    lists. Its own git state is dated, so a live one refuses whatever -Force says."""
    wt = _sibling(rig, "livenest")
    inner = wt / "pkg" / "nested"
    inner.mkdir(parents=True)
    _git(inner, "init", "-q", "-b", "main")
    _git(inner, "config", "user.email", "t@example.invalid")
    _git(inner, "config", "user.name", "t")
    _git(inner, "config", "commit.gpgsign", "false")
    _commit(inner, "a.txt")
    settle_worktrees(rig.primary)
    (inner / "a.txt").write_text("more work\n", encoding="utf-8")
    _git(inner, "commit", "-q", "-am", "unpushed work")

    proc = rig.run(*_target(route, wt), "-Force", settle=False)

    assert proc.returncode != 0, _out(proc)
    assert "nested repository that was active recently" in _out(proc), _out(proc)
    assert "pkg/nested" in _out(proc), _out(proc)
    assert (inner / "a.txt").is_file()

    proc = rig.run(*_target(route, wt), "-Force")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()


def test_more_pending_paths_than_the_cap_refuses_even_with_force(rig: Rig) -> None:
    """Past the cap nothing is sampled. The files are created before the tree is settled, so only
    the cap can refuse."""
    wt = _sibling(rig, "many")
    bulk = wt / "pkg" / "generated"
    bulk.mkdir(parents=True)
    for i in range(5001):
        (bulk / f"{i}.txt").write_bytes(b"")

    proc = rig.run("-Name", "many", "-Force")

    assert proc.returncode != 0, _out(proc)
    assert "more than 5000 pending paths" in _out(proc), _out(proc)
    assert wt.exists() and rig.is_registered(wt)


def test_a_venv_below_the_root_is_not_tolerated(rig: Rig) -> None:
    """Only the tree's own environment, at the root, goes without -Force. Red before the fix: the
    pattern matched at any depth. node_modules and the four caches stay tolerated at any depth,
    because this repository's own ide/node_modules is one. An empty .venv/src is no clone."""
    wt = _sibling(rig, "nested")
    (wt / "pkg").mkdir()
    _commit(wt, "pkg/keep.txt")

    nested = wt / "pkg" / ".venv"
    nested.mkdir()
    (nested / "artefact.bin").write_text("someone else's environment\n", encoding="utf-8")
    proc = rig.run("-Path", str(wt))
    assert proc.returncode != 0, _out(proc)
    assert "!! pkg/.venv/" in _out(proc), _out(proc)
    (nested / "artefact.bin").unlink()
    nested.rmdir()

    for name in ("node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"):
        (wt / "pkg" / name).mkdir()
        (wt / "pkg" / name / "artefact.bin").write_text("rebuildable\n", encoding="utf-8")
    (wt / ".venv" / "src").mkdir(parents=True)
    (wt / ".venv" / "artefact.bin").write_text("rebuildable\n", encoding="utf-8")

    proc = rig.run("-Path", str(wt))
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()
