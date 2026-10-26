# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``scripts/worktree/remove.ps1 -Discard``: park the uncommitted work on ``refs/attic``, then remove.

docs/AUTONOMY-PLAN.md 6.3. -Discard snapshots tracked changes and untracked files into a commit made
through a temporary index and ``commit-tree``, never the shared stash, parks it on a clone-local
``refs/attic/<date>-<name>``, and then removes the tree. It is not -Force: every refusal the script
makes without it still refuses with it, and the six-hour fence still holds.

Same rig and rules as ``tests/test_worktree_remove_in_use.py``: synthetic repositories under
``tmp_path`` only, and each refusal is paired with the run that is supposed to succeed.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.test_worktree_remove_in_use import ROUTES, _sibling, _target
from tests.test_worktree_remove_path import (
    _ENV,
    SCRIPT,
    Rig,
    _commit,
    _git,
    _out,
    build_rig,
    pytestmark,  # noqa: F401  (the same Windows-and-pwsh skip)
    settle_worktrees,
)

_REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    return build_rig(tmp_path)


def _attic(rig: Rig) -> list[str]:
    out = _git(rig.primary, "for-each-ref", "--format=%(refname)", "refs/attic/")
    return [ln for ln in out.splitlines() if ln]


def _leaf(route: str, wt: Path) -> str:
    return _target(route, wt)[1] if route == "-Name" else wt.name


def _days() -> tuple[str, str]:
    """Today in UTC and tomorrow, so a run that crosses midnight cannot flake a name check."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%d"), (now + timedelta(days=1)).strftime("%Y-%m-%d")


def _show(rig: Rig, rev: str) -> str:
    return _git(rig.primary, "show", rev)


@pytest.mark.parametrize("route", ROUTES)
def test_discard_parks_tracked_and_untracked_work_and_removes_the_tree(
    rig: Rig, route: str
) -> None:
    """The one thing it is for. Without -Discard both kinds of work refuse on -Path, and the tracked
    change refuses on -Name; with it, both land in the parked commit and the tree goes."""
    wt = _sibling(rig, "parked")
    tip = _git(wt, "rev-parse", "HEAD").strip()
    (wt / "seed.txt").write_text("tracked edit\n", encoding="utf-8")
    (wt / "pkg").mkdir()
    (wt / "pkg" / "new.txt").write_text("untracked work\n", encoding="utf-8")

    proc = rig.run(*_target(route, wt))
    assert proc.returncode != 0, _out(proc)
    assert wt.exists() and _attic(rig) == []

    proc = rig.run(*_target(route, wt), "-Discard")

    assert proc.returncode == 0, _out(proc)
    assert not wt.exists() and not rig.is_registered(wt)
    refs = _attic(rig)
    assert len(refs) == 1, refs
    assert refs[0] in {f"refs/attic/{d}-{_leaf(route, wt)}" for d in _days()}, refs
    assert refs[0] in _out(proc), _out(proc)
    assert _show(rig, f"{refs[0]}:seed.txt") == "tracked edit\n"
    assert _show(rig, f"{refs[0]}:pkg/new.txt") == "untracked work\n"
    # One parent, the HEAD it was taken on: nothing was staged apart from the files on disk.
    assert _git(rig.primary, "rev-parse", f"{refs[0]}^@").split() == [tip]
    # The tree's own branch is untouched, and so is the shared stash.
    assert _git(rig.primary, "rev-parse", wt.name).strip() == tip
    assert _git(rig.primary, "stash", "list").strip() == ""


def test_a_staged_version_that_differs_from_disk_is_parked_as_a_second_parent(rig: Rig) -> None:
    """The snapshot reads the files on disk. A version staged and then edited again lives only in
    the tree's index, which the removal deletes, so it is parked as the commit's second parent."""
    wt = _sibling(rig, "staged")
    (wt / "seed.txt").write_text("staged version\n", encoding="utf-8")
    _git(wt, "add", "seed.txt")
    (wt / "seed.txt").write_text("disk version\n", encoding="utf-8")

    proc = rig.run("-Name", "staged", "-Discard")

    assert proc.returncode == 0, _out(proc)
    (ref,) = _attic(rig)
    assert _show(rig, f"{ref}:seed.txt") == "disk version\n"
    assert _show(rig, f"{ref}^2:seed.txt") == "staged version\n"


def test_the_index_variable_is_not_left_set_and_a_callers_own_one_refuses(
    rig: Rig, tmp_path: Path
) -> None:
    """The script shares the caller's process when it is run with ``&``, so the temporary index must
    be unset afterwards, and a caller's own GIT_INDEX_FILE must not be overwritten: -Name refuses one
    under -Discard, as -Path always has. The temporary index file itself is deleted."""
    wt = _sibling(rig, "envcheck")
    (wt / "work.txt").write_text("untracked work\n", encoding="utf-8")
    settle_worktrees(rig.primary)
    temp = tmp_path / "tmpdir"
    temp.mkdir()

    def in_process(prelude: str) -> subprocess.CompletedProcess[str]:
        command = (
            f"{prelude}"
            f"try {{ & '{SCRIPT}' -RepoRoot '{rig.primary}' -Name envcheck -Discard }} "
            'catch { Write-Host "THREW: $($_.Exception.Message)" } '
            'Write-Host "INDEX=[$env:GIT_INDEX_FILE]"'
        )
        return subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=str(rig.root),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            env={**_ENV, "USERPROFILE": str(rig.home), "TMP": str(temp), "TEMP": str(temp)},
        )

    refused = in_process(f"$env:GIT_INDEX_FILE = '{temp / 'callers.index'}'; ")
    assert "GIT_INDEX_FILE is set" in _out(refused), _out(refused)
    assert f"INDEX=[{temp / 'callers.index'}]" in _out(refused), _out(refused)
    assert wt.exists() and _attic(rig) == []

    proc = in_process("")
    assert "THREW" not in _out(proc), _out(proc)
    assert "INDEX=[]" in _out(proc), _out(proc)
    assert not wt.exists()
    assert len(_attic(rig)) == 1
    assert list(temp.iterdir()) == []


def test_an_ignored_file_still_refuses_path_under_discard(rig: Rig) -> None:
    """-Discard is not -Force. An ignored file outside the tolerated caches is not parked, so -Path
    refuses it exactly as without -Discard, and parks nothing."""
    wt = rig.add(rig.scratch("ignored"))
    (wt / "run.log").write_text("ignored, and possibly the only copy\n", encoding="utf-8")
    (wt / "work.txt").write_text("untracked work\n", encoding="utf-8")

    proc = rig.run("-Path", str(wt), "-Discard")

    assert proc.returncode != 0, _out(proc)
    assert "!! run.log" in _out(proc) and "which -Discard does not park" in _out(proc), _out(proc)
    assert "?? work.txt" not in _out(proc), _out(proc)
    assert (wt / "run.log").is_file() and (wt / "work.txt").is_file()
    assert _attic(rig) == []

    (wt / "run.log").unlink()
    proc = rig.run("-Path", str(wt), "-Discard")
    assert proc.returncode == 0, _out(proc)
    assert not wt.exists()
    (ref,) = _attic(rig)
    assert _show(rig, f"{ref}:work.txt") == "untracked work\n"


def test_a_nested_repository_still_refuses_name_under_discard(rig: Rig) -> None:
    """A nested repository's content cannot be parked, so -Discard leaves its refusal alone."""
    wt = _sibling(rig, "nest")
    (wt / "nested").mkdir()
    _git(wt / "nested", "init", "-q", "-b", "main")

    proc = rig.run("-Name", "nest", "-Discard")

    assert proc.returncode != 0, _out(proc)
    assert "an untracked git repository inside the tree" in _out(proc), _out(proc)
    assert (wt / "nested" / ".git").exists() and _attic(rig) == []


@pytest.mark.parametrize("route", ROUTES)
def test_the_six_hour_fence_still_refuses_under_discard(rig: Rig, route: str) -> None:
    """A tree a session has just finished cannot be discarded: its fresh work refuses, whatever
    -Discard says, and nothing is parked. Once the work is older than the quiet period it goes."""
    wt = _sibling(rig, "fresh")
    (wt / "pkg" / "sub").mkdir(parents=True)
    _commit(wt, "pkg/sub/x.py")
    settle_worktrees(rig.primary)
    (wt / "pkg" / "sub" / "x.py").write_text("work in progress\n", encoding="utf-8")

    proc = rig.run(*_target(route, wt), "-Discard", settle=False)

    assert proc.returncode != 0, _out(proc)
    assert "Target holds recent uncommitted work" in _out(proc), _out(proc)
    assert rig.is_registered(wt) and _attic(rig) == []

    proc = rig.run(*_target(route, wt), "-Discard")
    assert proc.returncode == 0, _out(proc)
    (ref,) = _attic(rig)
    assert _show(rig, f"{ref}:pkg/sub/x.py") == "work in progress\n"


def test_a_same_day_clash_gets_a_suffix_and_never_moves_the_existing_ref(rig: Rig) -> None:
    wt = _sibling(rig, "clash")
    (wt / "work.txt").write_text("second parking\n", encoding="utf-8")
    seed = _git(rig.primary, "rev-parse", "HEAD").strip()
    taken = [f"refs/attic/{d}-clash" for d in _days()]
    for ref in taken:
        _git(rig.primary, "update-ref", ref, seed)

    proc = rig.run("-Name", "clash", "-Discard")

    assert proc.returncode == 0, _out(proc)
    new = sorted(set(_attic(rig)) - set(taken))
    assert len(new) == 1 and new[0] in {f"{ref}-2" for ref in taken}, _attic(rig)
    assert _show(rig, f"{new[0]}:work.txt") == "second parking\n"
    for ref in taken:
        assert _git(rig.primary, "rev-parse", ref).strip() == seed


@pytest.mark.parametrize("route", ROUTES)
def test_a_clean_tree_parks_nothing_and_is_removed(rig: Rig, route: str) -> None:
    wt = _sibling(rig, "clean")

    proc = rig.run(*_target(route, wt), "-Discard")

    assert proc.returncode == 0, _out(proc)
    assert "nothing to park" in _out(proc), _out(proc)
    assert not wt.exists() and _attic(rig) == []


def test_env_and_db_files_stay_out_of_the_snapshot_through_the_real_gitignore(rig: Rig) -> None:
    """The snapshot is ``git add -A``, so what keeps a local secret or the message store out of it is
    this repository's own .gitignore. That file is copied in as it stands, so dropping either pattern
    from it turns this red. -Name lets ignored files go with the tree, so both reach the snapshot
    step; -Path would refuse them first."""
    wt = _sibling(rig, "secrets")
    shutil.copyfile(_REPO / ".gitignore", wt / ".gitignore")
    _git(wt, "add", ".gitignore")
    _git(wt, "commit", "-q", "-m", "the real .gitignore")
    (wt / ".env").write_text("EXAMPLE_PLACEHOLDER=not-a-secret\n", encoding="utf-8")
    (wt / "messagefoundry.db").write_bytes(b"synthetic, not a store\n")
    # Not at the root: the real .gitignore ignores a root *.txt.
    (wt / "pkg").mkdir()
    (wt / "pkg" / "work.py").write_text("untracked work\n", encoding="utf-8")

    proc = rig.run("-Name", "secrets", "-Discard")

    assert proc.returncode == 0, _out(proc)
    (ref,) = _attic(rig)
    parked = _git(rig.primary, "ls-tree", "-r", "--name-only", ref).split()
    assert "pkg/work.py" in parked, parked
    assert ".env" not in parked and "messagefoundry.db" not in parked, parked
