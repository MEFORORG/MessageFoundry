# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2420's by-path residuals in the DR staging sweep and teardown
(`messagefoundry/pipeline/dr_backup.py`).

- The teardown's removal pass on Windows descended a subdirectory whose name Win32 rewrites, and a
  sibling junction took it outside the staging directory.
- The POSIX retry of a refused removal changed an entry's mode and removed it by its full path.
- The sweep's lock open and marker test, and the teardown's re-mark, went by path, so a staging
  directory swapped for a link had its lock opened, and its marks made, in the link's target.
- A file renamed after its screen, with a new file made under its name, was emptied as the new one
  and reported clean.

All synthetic: no file here holds PHI.
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.pipeline import dr_backup

_PLAINTEXT = b"synthetic plaintext"
_OUTSIDE = b"synthetic outside file"


def _abandoned(root: Path, prefix: str = "mefor-backup-") -> Path:
    """A staging directory whose run died: made the real way, holding plaintext, its lock handle
    closed with nothing removed, which is what a crash or SIGKILL leaves."""
    work = dr_backup._open_staging(root, prefix, secure=False)
    (work.path / "archive.tar").write_bytes(_PLAINTEXT)
    dr_backup._unlock_and_close(work._fd)
    return work.path


def _link_dir(target: Path, link: Path) -> None:
    """A directory link at ``link``: a junction on Windows, which needs no privilege, else a symlink."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def _verbatim(root: Path, *names: str) -> str:
    # Not `dr_backup._win_verbatim`, which resolves the parent and so rewrites a `sub.` above a name.
    return "\\\\?\\" + os.path.abspath(root) + "".join("\\" + name for name in names)


@pytest.fixture
def win_tmp(tmp_path: Path) -> Iterator[Path]:
    """``tmp_path``, removed through the verbatim prefix afterwards, since a plain removal cannot
    reach a name such as ``sub.``."""
    yield tmp_path
    shutil.rmtree(_verbatim(tmp_path), ignore_errors=True)


# --- the removal pass never leaves the staging directory through a rewritten name ---------------


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 path rewriting is Windows-only")
def test_the_removal_does_not_follow_a_rewritten_name_through_a_sibling_junction(
    win_tmp: Path,
) -> None:
    """`sub.` opens as `sub` by the plain path, and `sub` is a junction to a directory outside.
    Red before the fix: the plain-path `rmtree` descended `sub.` as the junction and deleted
    `victim.dat` outside the staging directory, then failed. Now the removal goes by the verbatim
    path, removes `sub.` as itself, and the outside file is whole."""
    outside = win_tmp / "outside"
    outside.mkdir()
    (outside / "victim.dat").write_bytes(_OUTSIDE)
    staging = win_tmp / "mefor-verify-planted"
    staging.mkdir()
    os.mkdir(_verbatim(staging, "sub."))
    with open(_verbatim(staging, "sub.", "inner.tar"), "wb") as handle:
        handle.write(_PLAINTEXT)
    _link_dir(outside, staging / "sub")
    assert dr_backup._remove_tree(staging) is True
    assert (outside / "victim.dat").read_bytes() == _OUTSIDE
    # The control: the staging directory itself, `sub.` and the junction included, is gone.
    assert not os.path.lexists(_verbatim(staging))


# --- a refused removal is retried by path only on Windows ---------------------------------------


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_a_refused_removal_is_retried_by_path_only_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    """Red before the fix on `linux`: the POSIX handler changed the entry's mode and unlinked it by
    its full path, which follows a directory above it swapped for a link. The control, `win32`: the
    Windows arm, which a read-only file needs, still clears the mode and retries the removal."""
    entry = tmp_path / "entry.tar"
    entry.write_bytes(_PLAINTEXT)
    chmods: list[str] = []
    real_chmod = os.chmod

    def recording_chmod(path: str, mode: int) -> None:
        chmods.append(path)
        real_chmod(path, mode)

    monkeypatch.setattr(os, "chmod", recording_chmod)
    monkeypatch.setattr(sys, "platform", platform)
    refused = PermissionError(13, "synthetic refusal")
    if platform == "win32":
        dr_backup._clear_readonly_and_retry(os.unlink, str(entry), refused)
        assert chmods == [str(entry)]
        assert not entry.exists()
    else:
        with pytest.raises(PermissionError):
            dr_backup._clear_readonly_and_retry(os.unlink, str(entry), refused)
        assert chmods == []
        assert entry.read_bytes() == _PLAINTEXT


# --- the sweep reads the owner, the lock and the marker through the directory opened as itself ---


def _swap_for_link_at_owner_read(
    monkeypatch: pytest.MonkeyPatch, candidate: Path, target: Path
) -> None:
    """Swap ``candidate`` for a link to ``target`` right after the sweep reads its owner by path,
    and answer that read with the owner the real directory had."""
    real_owner = dr_backup._owner_of
    swapped: list[bool] = []

    def owner_then_swap(path: Path) -> object | None:
        found = real_owner(path)
        if Path(path) == candidate and not swapped:
            swapped.append(True)
            candidate.rename(candidate.with_name("moved-away"))
            _link_dir(target, candidate)
        return found

    monkeypatch.setattr(dr_backup, "_owner_of", owner_then_swap)


def test_a_candidate_swapped_for_a_link_after_its_owner_read_is_not_torn_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Red before the fix: the lock was opened by path, through the link, in the target, whose own
    lock and marker then proved the candidate abandoned, and the teardown ran on the link."""
    root = tmp_path / "root"
    candidate = _abandoned(root)
    target = _abandoned(tmp_path / "elsewhere")
    owner = dr_backup._owner_of(candidate)
    assert owner is not None
    _swap_for_link_at_owner_read(monkeypatch, candidate, target)
    torn: list[Path] = []
    monkeypatch.setattr(dr_backup, "_teardown_staging", lambda path: torn.append(path))
    with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
        assert dr_backup._sweep_owned(root, owner, own=None) == 0
    assert torn == []
    assert any("as itself" in r.getMessage() for r in caplog.records)
    assert (target / "archive.tar").read_bytes() == _PLAINTEXT


def test_the_owner_that_decides_is_read_from_the_directory_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before the fix: only the by-path owner read was consulted, so a directory whose open
    handle reports another owner was swept. The control: with no stand-in it is swept."""
    root = tmp_path / "root"
    candidate = _abandoned(root)
    owner = dr_backup._owner_of(candidate)
    assert owner is not None
    real_fd_owner = dr_backup._owner_of_fd

    def fd_owner(fd: int, opened_as: Path) -> object | None:
        return "someone-else" if Path(opened_as) == candidate else real_fd_owner(fd, opened_as)

    monkeypatch.setattr(dr_backup, "_owner_of_fd", fd_owner)
    assert dr_backup._sweep_owned(root, owner, own=None) == 0
    assert (candidate / "archive.tar").read_bytes() == _PLAINTEXT
    monkeypatch.setattr(dr_backup, "_owner_of_fd", real_fd_owner)
    assert dr_backup._sweep_owned(root, owner, own=None) == 1
    assert not candidate.exists()


# --- the re-mark goes through the directory opened as itself, by an exclusive create ------------


def test_the_re_mark_makes_nothing_in_a_links_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The removal refused, and the directory was swapped for a link before the re-mark. Red before
    the fix: the re-mark created `.lock` and `.lock-held` through the link, in its target."""
    staging = tmp_path / "mefor-backup-planted"
    staging.mkdir()
    target = tmp_path / "elsewhere"
    target.mkdir()

    def refuse_then_swap(path: Path) -> str:
        staging.rename(tmp_path / "moved-away")
        _link_dir(target, staging)
        return "synthetic leftover"

    monkeypatch.setattr(dr_backup, "_discard_verify_staging", refuse_then_swap)
    with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
        assert dr_backup._teardown_staging(staging) == "synthetic leftover"
    assert sorted(p.name for p in target.iterdir()) == []
    assert any("could not be marked" in r.getMessage() for r in caplog.records)


def test_the_re_mark_puts_back_a_missing_lock_and_keeps_an_existing_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a surviving directory is marked for the next sweep, a missing name created and
    an existing plain file left as it is."""
    staging = tmp_path / "mefor-backup-kept"
    staging.mkdir()
    (staging / dr_backup._LOCK_NAME).write_bytes(b"kept")
    monkeypatch.setattr(dr_backup, "_discard_verify_staging", lambda path: "synthetic leftover")
    assert dr_backup._teardown_staging(staging) == "synthetic leftover"
    assert (staging / dr_backup._LOCK_NAME).read_bytes() == b"kept"
    marker = staging / dr_backup._HELD_MARKER_NAME
    assert stat.S_ISREG(os.lstat(marker).st_mode) and marker.read_bytes() == b""


# --- a file renamed away and replaced under its name is not emptied as the new one --------------


def test_a_file_renamed_and_replaced_after_its_screen_is_reported_not_emptied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Renamed between the screen and the open, with a new file made under its name. Red before the
    fix: the new file was emptied and the directory reported clean, while `moved.tar` kept its
    plaintext. Both platforms."""
    staging = tmp_path / "mefor-verify-planted"
    staging.mkdir()
    (staging / "a.tar").write_bytes(_PLAINTEXT)
    (staging / "own.tar").write_bytes(_PLAINTEXT)
    real_open = dr_backup._open_unfollowed

    def rename_replace_then_open(entry: Path, dir_fd: int | None, here: str | None) -> int:
        if entry.name == "a.tar":
            os.rename(staging / "a.tar", staging / "moved.tar")
            (staging / "a.tar").write_bytes(b"synthetic replacement")
        return real_open(entry, dir_fd, here)

    monkeypatch.setattr(dr_backup, "_open_unfollowed", rename_replace_then_open)
    assert dr_backup._empty_files_in_place(staging) == [
        "a.tar (changed while being emptied, not truncated)"
    ]
    assert (staging / "moved.tar").read_bytes() == _PLAINTEXT
    assert (staging / "a.tar").read_bytes() == b"synthetic replacement"
    # The control: the other file of the same directory is still emptied.
    assert (staging / "own.tar").read_bytes() == b""
