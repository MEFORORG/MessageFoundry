# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2420's by-path residuals in the DR staging sweep and teardown
(`messagefoundry/pipeline/dr_backup.py`).

- The teardown's removal pass on Windows descended a subdirectory whose name Win32 rewrites, and a
  sibling junction took it outside the staging directory.
- The POSIX retry of a refused removal changed an entry's mode and removed it by its full path.
- On POSIX the sweep's lock open and marker test, and the teardown's re-mark, went by path, so a staging
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
from typing import Any

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


# --- on POSIX the sweep reads the owner, the lock and the marker through the opened directory ---


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


@pytest.mark.skipif(sys.platform == "win32", reason="Windows goes by path here, as before")
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


@pytest.mark.skipif(sys.platform == "win32", reason="Windows goes by path here, as before")
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


# --- on POSIX the re-mark goes through the opened directory, by an exclusive create -------------


@pytest.mark.skipif(sys.platform == "win32", reason="Windows goes by path here, as before")
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


# --- the re-mark's exclusive create, when the name is taken -------------------------------------


def test_the_re_mark_refuses_an_entry_at_a_mark_name_that_is_not_a_plain_file(
    tmp_path: Path,
) -> None:
    """`.lock` is taken by a directory: the re-mark raises rather than accept it, on Windows at the
    exclusive create and on POSIX at the check after it. The control: the other name is created."""
    staging = tmp_path / "mefor-backup-kept"
    staging.mkdir()
    (staging / dr_backup._LOCK_NAME).mkdir()
    with dr_backup._HeldStagingDir(staging) as held_dir:
        with pytest.raises(OSError):  # Windows refuses the create itself, POSIX the check
            held_dir.mark(dr_backup._LOCK_NAME)
        held_dir.mark(dr_backup._HELD_MARKER_NAME)
    assert (staging / dr_backup._HELD_MARKER_NAME).is_file()


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows creates through _win_create_new, not os.open"
)
def test_the_re_mark_creates_a_name_that_went_after_its_create_was_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The entry is removed between the refused create and its check, as a concurrent teardown's
    removal can do: it is created once more rather than leave the directory unmarked."""
    staging = tmp_path / "mefor-backup-kept"
    staging.mkdir()
    lock = staging / dr_backup._LOCK_NAME
    lock.write_bytes(b"")
    real_open = os.open

    def refused_then_gone(*args: Any, **kwargs: Any) -> int:
        try:
            return real_open(*args, **kwargs)
        except FileExistsError:
            lock.unlink()
            raise

    with dr_backup._HeldStagingDir(staging) as held_dir:
        monkeypatch.setattr(os, "open", refused_then_gone)
        held_dir.mark(dr_backup._LOCK_NAME)
    assert lock.is_file()


def test_the_re_mark_makes_nothing_at_a_dangling_links_target(tmp_path: Path) -> None:
    """A dangling file link planted at `.lock-held`. Red on Windows before the round-2 fix: the
    `os.open` exclusive create followed it and made the file at the target, outside the directory.
    Now the link is a name in use and is refused as not a plain file."""
    staging = tmp_path / "mefor-backup-kept"
    staging.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside / "made", staging / dr_backup._HELD_MARKER_NAME)
    except OSError:
        pytest.skip("this account cannot create a symbolic link here")
    with dr_backup._HeldStagingDir(staging) as held_dir, pytest.raises(OSError):
        held_dir.mark(dr_backup._HELD_MARKER_NAME)
    assert sorted(p.name for p in outside.iterdir()) == []


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 path rewriting is Windows-only")
def test_a_swept_candidate_whose_name_windows_rewrites_gets_the_verbatim_refusal(
    win_tmp: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A planted `mefor-backup-x.` opens as the abandoned `mefor-backup-x` beside it. A stand-in has
    the owner read by the name `mefor-backup-x` alone answer another owner, so the sweep leaves
    that name and reaches the planted one first; one directory reporting two owners by its two
    names is the stand-in's, not a real volume's. Through the planted name the sweep proves the
    other directory abandoned, and the teardown's refusal names the planted name by its verbatim
    path and touches neither directory."""
    other = win_tmp / "mefor-backup-x"
    other.mkdir()
    (other / "archive.tar").write_bytes(_PLAINTEXT)
    for name in (dr_backup._LOCK_NAME, dr_backup._HELD_MARKER_NAME):
        (other / name).write_bytes(b"")
    os.mkdir(_verbatim(win_tmp, "mefor-backup-x."))
    owner = dr_backup._owner_of(other)
    assert owner is not None
    real_owner = dr_backup._owner_of

    def owner_of(path: Path) -> object | None:
        return "someone-else" if os.fspath(path) == os.fspath(other) else real_owner(path)

    monkeypatch.setattr(dr_backup, "_owner_of", owner_of)
    with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
        assert dr_backup._sweep_owned(win_tmp, owner, own=None) == 0
    refusals = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.ERROR and "Remove-Item -LiteralPath" in r.getMessage()
    ]
    assert refusals and all("mefor-backup-x." in m for m in refusals)
    assert not any("as itself" in r.getMessage() for r in caplog.records)
    assert (other / "archive.tar").read_bytes() == _PLAINTEXT
    assert os.path.lexists(_verbatim(win_tmp, "mefor-backup-x."))


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="POSIX permissions, as a non-root account"
)
def test_without_o_path_a_directory_it_cannot_read_is_still_swept_by_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A platform with no `O_PATH` (macOS) and a directory of this account with no read bit. Red on
    9be6759e20a: the read-only open was refused, so the sweep left a directory origin/main swept.
    It now goes by path for that directory, as origin/main did."""
    root = tmp_path / "root"
    candidate = _abandoned(root)
    owner = dr_backup._owner_of(candidate)
    assert owner is not None
    monkeypatch.delattr(os, "O_PATH", raising=False)
    candidate.chmod(0o300)
    try:
        with dr_backup._HeldStagingDir(candidate) as held_dir:
            assert held_dir.fd is None
            held_dir.mark(dr_backup._HELD_MARKER_NAME)
        assert dr_backup._proven_abandoned(candidate, owner) is True
    finally:
        candidate.chmod(0o700)


def test_the_proof_reads_the_owner_by_path_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One by-path owner read per candidate, as origin/main makes. Red at 97f8dc96943 on Windows,
    where the directory goes by path: the owner was read by path twice, a second
    security-descriptor read and a wider window for a candidate that goes between them."""
    root = tmp_path / "root"
    candidate = _abandoned(root)
    owner = dr_backup._owner_of(candidate)
    assert owner is not None
    real_owner = dr_backup._owner_of
    reads: list[Path] = []

    def counted(path: Path) -> object | None:
        reads.append(Path(path))
        return real_owner(path)

    monkeypatch.setattr(dr_backup, "_owner_of", counted)
    assert dr_backup._proven_abandoned(candidate, owner) is True
    assert reads == [candidate]
