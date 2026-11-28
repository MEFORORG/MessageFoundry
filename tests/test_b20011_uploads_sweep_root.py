# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The uploads orphan sweep reads its root before it trusts an absent answer (BACKLOG #6575, from
BACKLOG #8341 items 2 and 4). Synthetic data only.

Item 4: a listing error that reads as absence, as a lost drive's does, ended the pass at 0 with no
log, so retention reported clean passes for good. Now only a root that reads as never made, under
a folder that answers, is an empty pass; anything else raises, and ``prune_expired`` logs it.

Item 2, in part: a sidecar the file system reports absent sent its body to the unlink even when the
uploads root was no longer the folder the sweep listed, as after a share remounted under it. The
root's identity is now pinned at the listing and checked before each body goes."""

from __future__ import annotations

import errno
import logging
import os
import secrets
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

    def _stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self.absolute() in lost:
            raise FileNotFoundError(errno.ENOENT, "The system cannot find the path specified")
        return real(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", _stat)


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


# --- item 2, in part: the root must still be the folder the sweep listed ------------------------


def _swap_root_after_listing(
    monkeypatch: pytest.MonkeyPatch, store: UploadStore, other: Path, *, swapped: bool = True
) -> None:
    """The root's first ``stat``, the sweep's pin, is real; with ``swapped``, every later one
    answers as ``other``, as a share remounted under the root's name would."""
    real = Path.stat
    root_stats = 0

    def _stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        nonlocal root_stats
        if self == store._root:
            root_stats += 1
            if swapped and root_stats > 1:
                return real(other, follow_symlinks=follow_symlinks)
        return real(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", _stat)


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
        assert "no longer the folder the sweep listed" in errors[0]
    else:
        assert removed == 1 and not body.exists()


async def test_a_root_swapped_stops_before_the_next_orphan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two orphans: the swap is seen at the first, and the second is never reached.
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
    _swap_root_after_listing(monkeypatch, store, other)
    assert store._sweep_orphans_sync(now=time.time()) == 0
    assert all(body.exists() for body in bodies)
