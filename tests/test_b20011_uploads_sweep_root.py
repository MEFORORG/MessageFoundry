# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The uploads orphan sweep reads its root before it trusts an absent answer (BACKLOG #6575, from
BACKLOG #8341 items 2 and 4). Synthetic data only.

Item 4: a listing error that reads as absence, as a lost drive's does, ended the pass at 0 with no
log, so retention reported clean passes for good. Now only a root that reads as never made, under
a folder that answers, is an empty pass; anything else raises, and ``prune_expired`` logs it.

Item 2, in part: a sidecar the file system reports absent sent its body to the unlink even when the
uploads root was no longer the folder the sweep listed, as after a share remounted under it. The
root's identity is now pinned before the listing and checked before each temp or body goes, and
a listing that answers absence after that pin succeeded raises."""

from __future__ import annotations

import errno
import logging
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.uploads import _BLOB_SUFFIX, _META_SUFFIX, _ORPHAN_MIN_AGE_SECONDS, UploadStore

_TXT = b"synthetic diagnostic line\n"


def _store(root: Path) -> UploadStore:
    return UploadStore(root, make_cipher(generate_key(), write_v2=True), max_bytes=1_000_000)


def _backdate(path: Path) -> None:
    stamp = time.time() - 2 * _ORPHAN_MIN_AGE_SECONDS
    os.utime(path, (stamp, stamp))


class _NameNotFound(FileNotFoundError):
    """A missing name as both platforms report one: Windows ERROR_FILE_NOT_FOUND (2), which POSIX
    ignores, so ``is_name_absent`` answers True on either."""

    winerror = 2


# --- item 4: a lost drive is not a root that was never made --------------------------------------


def _lose_the_drive(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    """Every folder from ``root`` up to its anchor answers ``FileNotFoundError``, as a drive letter
    that is no longer mapped does (Windows ERROR_PATH_NOT_FOUND, which ``is_absent`` reads as
    absence)."""
    lost = {root.absolute(), *root.absolute().parents}
    real = Path.stat
    real_lexists = os.path.lexists

    def _stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self.absolute() in lost:
            raise FileNotFoundError(errno.ENOENT, "The system cannot find the path specified")
        return real(self, follow_symlinks=follow_symlinks)

    def _lexists(path: Any) -> bool:
        # No name is there either, so the walk runs off the anchor, as above a lost drive.
        return False if Path(path).absolute() in lost else real_lexists(path)

    monkeypatch.setattr(Path, "stat", _stat)
    monkeypatch.setattr(os.path, "lexists", _lexists)


def test_a_lost_drive_raises_rather_than_reading_as_a_clean_sweep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On origin/main the listing's FileNotFoundError returned 0 with no log.
    store = _store(tmp_path / "drive" / "uploads")
    _lose_the_drive(monkeypatch, store._root)
    with pytest.raises(FileNotFoundError):
        store._sweep_orphans_sync(now=time.time())


async def test_a_lost_drive_is_logged_by_the_retention_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = _store(tmp_path / "drive" / "uploads")
    _lose_the_drive(monkeypatch, store._root)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = await store.prune_expired()
    assert result.orphans_removed == 0
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert errors == ["uploaded-logs orphan sweep failed; will retry next pass"]


@pytest.mark.parametrize("depth", [1, 3], ids=["root-only", "folders-above-it-too"])
def test_a_root_no_save_has_made_is_still_a_quiet_empty_sweep(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, depth: int
) -> None:
    # The control: before the first save, the root, and any folder above it the save's mkdir
    # would make, is missing under a folder that answers.
    root = tmp_path.joinpath(*(["missing"] * (depth - 1)), "uploads")
    store = _store(root)
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.uploads"):
        assert store._sweep_orphans_sync(now=time.time()) == 0
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_a_root_under_a_file_is_not_a_root_never_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The nearest answering folder above must be a folder; a file there is a misconfiguration,
    # never an empty pass. The listing is made to answer absence, as Windows does here.
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x", encoding="utf-8")
    store = _store(blocker / "uploads")
    real = Path.stat

    def _stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self == store._root:
            raise FileNotFoundError(errno.ENOENT, "not found")
        return real(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", _stat)
    with pytest.raises(FileNotFoundError):
        store._sweep_orphans_sync(now=time.time())


# --- item 2, in part: the root must still be the folder the sweep pinned ------------------------


def _swap_root_after_listing(
    monkeypatch: pytest.MonkeyPatch, store: UploadStore, other: Path, *, swapped: bool = True
) -> list[int]:
    """The root's first ``stat``, the sweep's pin, is real; with ``swapped``, every later one
    answers as ``other``, as a share remounted under the root's name would. Returns a list that
    grows by one per ``stat`` of the root, so a test can tell stopping from skipping."""
    real = Path.stat
    root_stats: list[int] = []

    def _stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self == store._root:
            root_stats.append(1)
            if swapped and len(root_stats) > 1:
                return real(other, follow_symlinks=follow_symlinks)
        return real(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", _stat)
    return root_stats


async def _live_pair_whose_sidecar_reads_absent(
    store: UploadStore, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    """A real pair past the floor, whose sidecar exists but whose ``lstat`` answers a missing name,
    as a stale client cache or a POSIX missing parent can. The listing still shows the sidecar, so
    it is kept out of the listing for the sweep to reach the check at all."""
    meta = await store.save(data=_TXT, filename="live.txt", uploader="op", uploader_id="u1")
    body = store._root / f"{meta.file_id}{_BLOB_SUFFIX}"
    sidecar = store._root / f"{meta.file_id}{_META_SUFFIX}"
    _backdate(body)
    real_lstat = os.lstat
    real_iterdir = Path.iterdir

    def _lstat(path: Any, **kwargs: Any) -> os.stat_result:
        if Path(path).name == sidecar.name:
            raise _NameNotFound(errno.ENOENT, "No such file or directory")
        return real_lstat(path, **kwargs)

    def _iterdir(self: Path) -> Any:
        listed = list(real_iterdir(self))
        if self == store._root:
            return iter([p for p in listed if p.name != sidecar.name])
        return iter(listed)

    monkeypatch.setattr(os, "lstat", _lstat)
    monkeypatch.setattr(Path, "iterdir", _iterdir)
    return body, sidecar


@pytest.mark.parametrize("swapped", [False, True], ids=["control", "root-swapped"])
async def test_a_root_swapped_after_the_listing_keeps_the_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    swapped: bool,
) -> None:
    """On origin/main the body went in both cases. The control pins the residual the row keeps: with
    the root unchanged, an absent answer alone still sends the body to the unlink."""
    store = _store(tmp_path / "uploads")
    body, sidecar = await _live_pair_whose_sidecar_reads_absent(store, monkeypatch)
    other = tmp_path / "another-folder"
    other.mkdir()
    _swap_root_after_listing(monkeypatch, store, other, swapped=swapped)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        removed = store._sweep_orphans_sync(now=time.time())

    assert sidecar.exists()
    if swapped:
        assert removed == 0 and body.exists(), "a body was unlinked under a root that changed"
        errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
        assert len(errors) == 1 and "orphan sweep stopped" in errors[0]
        assert "now answers as a different folder" in errors[0]
    else:
        assert removed == 1 and not body.exists()


@pytest.mark.parametrize("swapped", [False, True], ids=["control", "root-swapped"])
async def test_a_root_swapped_stops_before_the_next_orphan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swapped: bool
) -> None:
    # Two orphans: the swap is seen at the first, and the second is never reached, so the root is
    # stated twice (the pin and one check) rather than once per orphan, as a skip would make it.
    store = _store(tmp_path / "uploads")
    store._root.mkdir(mode=0o700, parents=True)
    bodies = []
    for _ in range(2):
        body = store._root / f"{secrets.token_hex(16)}{_BLOB_SUFFIX}"
        body.write_text("SYNTHETIC", encoding="utf-8")
        _backdate(body)
        bodies.append(body)
    other = tmp_path / "another-folder"
    other.mkdir()
    root_stats = _swap_root_after_listing(monkeypatch, store, other, swapped=swapped)
    removed = store._sweep_orphans_sync(now=time.time())
    if swapped:
        assert removed == 0 and all(body.exists() for body in bodies)
        assert len(root_stats) == 2, "the sweep went on past the swap"
    else:
        assert removed == 2 and not any(body.exists() for body in bodies)
        assert len(root_stats) == 3


def test_a_linked_root_whose_target_is_lost_is_not_a_root_never_made(tmp_path: Path) -> None:
    # The root's name is there, as a link to a folder that is gone, as a junction or symlink to a
    # lost volume is. On the first fix it read as never made and the pass was a silent 0.
    target = tmp_path / "volume" / "uploads"
    target.mkdir(parents=True)
    root = tmp_path / "uploads"
    try:
        root.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create a symbolic link")
    target.rmdir()
    with pytest.raises(FileNotFoundError):
        _store(root)._sweep_orphans_sync(now=time.time())


def test_an_ancestor_that_is_a_dangling_link_is_not_a_root_never_made(tmp_path: Path) -> None:
    target = tmp_path / "volume"
    target.mkdir()
    mount = tmp_path / "mount"
    try:
        mount.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create a symbolic link")
    target.rmdir()
    with pytest.raises(FileNotFoundError):
        _store(mount / "uploads")._sweep_orphans_sync(now=time.time())


# --- the repair round: a pinned root, a raced root, and a temp under a swapped root --------------


def _listing_answers_absence(monkeypatch: pytest.MonkeyPatch, store: UploadStore) -> None:
    """The root's ``stat`` is real and succeeds, and only its listing then answers a missing path,
    as a share that drops between the two reads does. Only the sweep's own listing answers so, so
    the age pass before it in ``prune_expired`` still runs."""
    real_iterdir = Path.iterdir

    def _iterdir(self: Path) -> Any:
        if self == store._root and sys._getframe(1).f_code.co_name == "_sweep_orphans_sync":
            raise FileNotFoundError(errno.ENOENT, "The system cannot find the path specified")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", _iterdir)


def test_an_absent_listing_after_the_pin_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Before the repair the pin's success was not used: the root was still a folder, so the
    # root.is_dir() fallback read the listing's absence as an empty pass and returned a silent 0.
    store = _store(tmp_path / "uploads")
    store._root.mkdir(mode=0o700, parents=True)
    _listing_answers_absence(monkeypatch, store)
    with pytest.raises(FileNotFoundError):
        store._sweep_orphans_sync(now=time.time())


async def test_an_absent_listing_after_the_pin_is_logged_by_the_retention_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = _store(tmp_path / "uploads")
    store._root.mkdir(mode=0o700, parents=True)
    _listing_answers_absence(monkeypatch, store)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = await store.prune_expired()
    assert result.orphans_removed == 0
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert errors == ["uploaded-logs orphan sweep failed; will retry next pass"]


def test_a_root_a_save_makes_after_a_failed_pin_is_a_quiet_empty_sweep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Pins the root.is_dir() fallback: the pin answers absence because no root exists yet, and a
    # save makes it before the sweep reads it again, so _root_never_made answers False (the name is
    # there now) and only the fallback keeps this from a false ERROR. The next pass lists it.
    store = _store(tmp_path / "uploads")
    real = Path.stat
    made: list[int] = []

    def _stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self == store._root and not made:
            made.append(1)
            self.mkdir(mode=0o700)  # the racing save's mkdir lands after this stat missed
            raise FileNotFoundError(errno.ENOENT, "No such file or directory")
        return real(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", _stat)
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.uploads"):
        assert store._sweep_orphans_sync(now=time.time()) == 0
    assert made == [1] and store._root.is_dir()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize("swapped", [False, True], ids=["control", "root-swapped"])
def test_a_root_swapped_after_the_listing_keeps_a_temp_leftover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swapped: bool
) -> None:
    # Before the repair a temp went to the unlink with no root-identity check, so it went in both
    # cases; a body already had the check.
    store = _store(tmp_path / "uploads")
    store._root.mkdir(mode=0o700, parents=True)
    temp = store._root / f".{secrets.token_hex(16)}{_BLOB_SUFFIX}.{secrets.token_hex(4)}.tmp"
    temp.write_text("SYNTHETIC", encoding="utf-8")
    _backdate(temp)
    other = tmp_path / "another-folder"
    other.mkdir()
    root_stats = _swap_root_after_listing(monkeypatch, store, other, swapped=swapped)
    removed = store._sweep_orphans_sync(now=time.time())
    assert len(root_stats) == 2, "the temp's unlink was not preceded by a root-identity check"
    if swapped:
        assert removed == 0 and temp.exists(), "a temp was unlinked under a root that changed"
    else:
        assert removed == 1 and not temp.exists()


@pytest.mark.parametrize("kind", ["temp", "body"])
def test_a_root_that_stops_answering_before_an_unlink_keeps_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, kind: str
) -> None:
    # The lost branch of the check right before the unlink: no entry error is raised, only the
    # root's own stat after the pin fails, so the except-path check never runs and only the
    # pre-unlink one can keep the file.
    store = _store(tmp_path / "uploads")
    store._root.mkdir(mode=0o700, parents=True)
    fid = secrets.token_hex(16)
    if kind == "temp":
        leftover = store._root / f".{fid}{_BLOB_SUFFIX}.{secrets.token_hex(4)}.tmp"
    else:
        leftover = store._root / f"{fid}{_BLOB_SUFFIX}"
    leftover.write_text("SYNTHETIC", encoding="utf-8")
    _backdate(leftover)
    real = Path.stat
    root_stats: list[int] = []

    def _stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self == store._root:
            root_stats.append(1)
            if len(root_stats) > 1:
                raise OSError(errno.EIO, "Input/output error")
        return real(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", _stat)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        removed = store._sweep_orphans_sync(now=time.time())
    assert removed == 0 and leftover.exists()
    assert len(root_stats) == 2
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "stopped answering" in errors[0]


def test_a_root_swapped_between_the_pin_and_the_listing_logs_a_true_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The swap lands after the pin and before the listing, so the sweep lists the new folder and
    # the root still answers as it. The stop's ERROR named "the one the sweep listed", which is
    # the folder the root does answer as here; it must name the pin, the folder read before the
    # listing, which is true whichever side of the listing the swap landed on.
    store = _store(tmp_path / "uploads")
    store._root.mkdir(mode=0o700, parents=True)
    other = tmp_path / "another-folder"
    other.mkdir()
    name = f"{secrets.token_hex(16)}{_BLOB_SUFFIX}"
    for folder in (store._root, other):
        (folder / name).write_text("SYNTHETIC", encoding="utf-8")
        _backdate(folder / name)
    real_stat = Path.stat
    real_iterdir = Path.iterdir
    swapped: list[int] = []

    def _stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self == store._root and swapped:
            return real_stat(other, follow_symlinks=follow_symlinks)
        return real_stat(self, follow_symlinks=follow_symlinks)

    def _iterdir(self: Path) -> Any:
        if self == store._root:
            swapped.append(1)  # the remount lands before the listing reads the folder
            return iter([self / entry.name for entry in real_iterdir(other)])
        return real_iterdir(self)

    monkeypatch.setattr(Path, "stat", _stat)
    monkeypatch.setattr(Path, "iterdir", _iterdir)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        removed = store._sweep_orphans_sync(now=time.time())

    assert removed == 0 and (store._root / name).exists() and (other / name).exists()
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "now answers as a different folder" in errors[0]
    assert "the one the sweep listed" not in errors[0]
    assert "read before its listing" in errors[0]
