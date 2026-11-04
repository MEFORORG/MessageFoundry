# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4988 and #4989, two DR staging gaps engine PR 2675 named.

#4988: the backup's early sweep of its staging root went by the process's own owner. On a share
whose server sets the owner, a directory there carrying the process's owner may have been made by
another principal, and the sweep would have removed it, while docs/PHI.md said every sweep takes
only what a new directory of the run's account gets. The early sweep now goes by the owner a probe
in the staging root gets, read through the descriptor that created it (``fstat`` on POSIX,
``GetSecurityInfo`` on its handle on Windows). When the probe
cannot be created, as on a full volume, it goes by the process's owner only where the staging root
itself carries that owner.

#4989: an entry whose ``is_dir`` raised was listed as a file, so a directory the walk could not type
was never walked, the fail-safe's ``lstat`` found no regular file, and the teardown logged that every
file was emptied and raised no cleanup alert. Such a directory is now reported as not walked.

Every test uses synthetic bytes only. Severity is conditional (CLAUDE.md section 0)."""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.pipeline import dr_backup
from tests.test_b2420_staging_truncate import (
    _abandoned,
    _exists_at_open,
    _link_dir,
    _root_probe_answers_none,
    _share_owner_for,
    _store_and_runner,
)

# --- #4988: the early sweep goes by the owner a directory in the staging root gets ---------------


async def test_the_early_sweep_leaves_a_directory_carrying_the_process_owner_on_a_share(
    tmp_path, monkeypatch, caplog
) -> None:
    """On a share whose server sets the owner, a dead-looking directory carrying the process's own
    owner is another principal's. The early sweep, keyed on the process's owner, removed it. Keyed
    on the owner a probe there gets, it leaves it and says so, and still removes this account's
    own leftover before the run's directory is opened."""
    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    data = (tmp_path / "data").absolute()
    ours = _abandoned(data, "mefor-backup-")
    other = _abandoned(data, "mefor-backup-")
    _share_owner_for(data, monkeypatch, made_by_another=other)
    ours_at_open = _exists_at_open(monkeypatch, ours)
    try:
        with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
            result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None and result.verify is not None and result.verify.ok
    # The control: this account's leftover went in the early sweep, before the open.
    assert ours_at_open[0] is False
    # The other principal's directory is whole, and named in the log.
    assert (other / "archive.tar").read_bytes() == b"synthetic plaintext"
    assert any(
        "has another owner" in r.getMessage() and other.name in r.getMessage()
        for r in caplog.records
    )
    assert not any(p.name.startswith("mefor-owner-probe-") for p in data.iterdir())


async def test_a_failed_probe_on_a_share_does_not_fall_back_to_the_process_owner(
    tmp_path, monkeypatch
) -> None:
    """When the probe in the staging root answers None and the root itself carries the share's
    owner, as one this account made there does, the early sweep is off rather than keyed on the
    process's owner, so another principal's directory carrying that owner survives the run. This
    run's own directory's owner still sweeps this account's leftover once it is open."""
    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    data = (tmp_path / "data").absolute()
    ours = _abandoned(data, "mefor-backup-")
    other = _abandoned(data, "mefor-backup-")
    _share_owner_for(data, monkeypatch, made_by_another=other, root_too=True)
    _root_probe_answers_none(data, monkeypatch, first=None)
    ours_at_open = _exists_at_open(monkeypatch, ours)
    try:
        result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None and result.verify is not None and result.verify.ok
    assert ours_at_open[0] is True  # the early sweep was off
    assert not ours.exists()  # swept by this run's own directory's owner
    assert (other / "archive.tar").read_bytes() == b"synthetic plaintext"


def _probe_creation_fails_in(data: Path, monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Creating an owner probe in ``data`` fails with ENOSPC, as on a volume a killed run filled.
    Returns the refused attempts."""
    refused: list[Path] = []
    real_probe = dr_backup._owner_probe

    @contextlib.contextmanager
    def probe(root: Path | None) -> Iterator[tuple[int, Path]]:
        if root is not None and Path(root).absolute() == data:
            refused.append(Path(root))
            raise OSError(errno.ENOSPC, "No space left on device")
        with real_probe(root) as made:
            yield made

    monkeypatch.setattr(dr_backup, "_owner_probe", probe)
    return refused


async def test_a_full_volume_still_frees_a_killed_runs_leftover_before_space_refuses(
    tmp_path, monkeypatch, caplog
) -> None:
    """On a volume a killed run filled, no probe can be created there. The early sweep goes by the
    process's owner, which the staging root carries, as it did before the probe, so the leftover
    goes before the space check and the run proceeds instead of refusing with `space`. The failed
    probe is logged."""
    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    data = (tmp_path / "data").absolute()
    dead = _abandoned(data, "mefor-backup-")
    refused = _probe_creation_fails_in(data, monkeypatch)

    class _Usage:
        def __init__(self, free: int) -> None:
            self.free = free

    # The leftover is what fills the volume: while it exists there is no room.
    monkeypatch.setattr(shutil, "disk_usage", lambda _path: _Usage(1 if dead.exists() else 1 << 40))
    dead_at_open = _exists_at_open(monkeypatch, dead)
    try:
        with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
            result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None and result.verify is not None and result.verify.ok
    assert refused  # the control: the probe really was refused
    assert dead_at_open[0] is False  # freed before this run's directory was opened
    assert any(
        r.levelno == logging.WARNING and "could not learn the owner" in r.getMessage()
        for r in caplog.records
    )
    # The failed probe's own cause is logged, not swallowed.
    assert any(
        "owner probe in" in r.getMessage() and "No space left" in r.getMessage()
        for r in caplog.records
    )


async def test_a_short_run_whose_early_probe_answered_does_not_probe_again(
    tmp_path, monkeypatch
) -> None:
    """The second probe on a shortfall runs only when the early probe answered None, as docs/PHI.md
    says. When the early probe answered, the early sweep already went by that owner, so a short run
    refuses with `space` after one probe, writing no second probe into a nearly full root."""
    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    data = (tmp_path / "data").absolute()
    probes = _root_probe_answers_none(data, monkeypatch, first=0)  # records, never refuses

    class _Usage:
        free = 1

    monkeypatch.setattr(shutil, "disk_usage", lambda _path: _Usage())
    try:
        with pytest.raises(dr_backup.BackupError) as caught:
            await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert caught.value.kind == "space"
    assert len(probes) == 1


@pytest.mark.skipif(sys.platform == "win32", reason="the descriptor-read probe is POSIX only")
def test_the_probe_owner_comes_from_the_descriptor_not_a_later_path_read(
    tmp_path, monkeypatch
) -> None:
    """An account that can rename entries in the staging root swaps another object in at the
    probe's name right after it is created. The owner still comes from the descriptor that created
    the probe, and a path read of the name, which here would answer the swapped object's owner, is
    never made."""
    root = tmp_path / "root"
    root.mkdir()
    real_mkstemp = tempfile.mkstemp
    created: list[int] = []

    def swapping_mkstemp(*args: Any, **kwargs: Any) -> Any:
        fd, name = real_mkstemp(*args, **kwargs)
        created.append(os.fstat(fd).st_ino)
        os.rename(name, root / "moved-away")
        Path(name).write_bytes(b"")  # the swapped-in object, at the probe's name
        return fd, name

    def path_read(path: Path) -> object | None:
        return "swapped-owner"

    seen: list[int] = []
    real_fd_owner = dr_backup._owner_of_fd

    def fd_owner(fd: int, opened_as: Path) -> object | None:
        seen.append(os.fstat(fd).st_ino)
        return real_fd_owner(fd, opened_as)

    monkeypatch.setattr(tempfile, "mkstemp", swapping_mkstemp)
    monkeypatch.setattr(dr_backup, "_owner_of", path_read)
    monkeypatch.setattr(dr_backup, "_owner_of_fd", fd_owner)
    assert dr_backup._probe_owner(root) == os.geteuid()  # type: ignore[attr-defined,unused-ignore]
    # The descriptor read the object the probe created, not what the name held afterwards.
    assert seen == created
    assert (root / "moved-away").stat().st_ino == created[0]


@pytest.mark.skipif(sys.platform != "win32", reason="the handle-read probe is the Windows half")
def test_the_windows_probe_owner_comes_from_the_handle_not_a_later_path_read(
    tmp_path, monkeypatch
) -> None:
    """The Windows mirror of the descriptor test above. An account that can rename entries in the
    staging root moves the probe away right after it is created and puts its own file at the
    probe's name. The owner still comes from ``GetSecurityInfo`` on the handle that created the
    probe, a path read of the name, which here would answer the swapped object's owner, is never
    made, and closing the handle deletes the probe the engine made, not the swapped-in file."""
    root = tmp_path / "root"
    root.mkdir()
    real_probe = dr_backup._owner_probe
    real_owner = dr_backup._owner_of
    created: list[int] = []
    expected: list[object | None] = []
    swapped: list[Path] = []

    @contextlib.contextmanager
    def swapping_probe(where: Path | None) -> Iterator[tuple[int, Path]]:
        with real_probe(where) as (fd, name):
            created.append(os.fstat(fd).st_ino)
            moved = root / "moved-away"
            os.rename(name, moved)
            expected.append(real_owner(moved))
            name.write_bytes(b"")  # the swapped-in object, at the probe's name
            swapped.append(name)
            yield fd, name

    def path_read(path: Path) -> object | None:
        return "swapped-owner"

    seen: list[int] = []
    real_fd_owner = dr_backup._owner_of_fd

    def fd_owner(fd: int, opened_as: Path) -> object | None:
        seen.append(os.fstat(fd).st_ino)
        return real_fd_owner(fd, opened_as)

    monkeypatch.setattr(dr_backup, "_owner_probe", swapping_probe)
    monkeypatch.setattr(dr_backup, "_owner_of", path_read)
    monkeypatch.setattr(dr_backup, "_owner_of_fd", fd_owner)
    got = dr_backup._probe_owner(root)
    assert expected[0] is not None  # the control: the real owner could be read
    assert got == expected[0]
    assert got != "swapped-owner"
    # The handle read the object the probe created, not what the name held afterwards.
    assert seen == created
    # Closing the handle deleted the engine's own probe where the rename put it, and left the
    # swapped-in file at the probe's name alone.
    assert not (root / "moved-away").exists()
    assert swapped[0].exists()


def test_the_fallback_reads_the_staging_roots_owner_from_a_descriptor(
    tmp_path, monkeypatch
) -> None:
    """``_fallback_root_owner`` reads the root's owner from a descriptor it opened, never by path:
    a path read here answers another owner, and the gate still passes on the real one. The
    control: a root carrying another owner fails the gate."""
    root = tmp_path / "root"
    root.mkdir()
    owner = dr_backup._owner_of(root)
    assert owner is not None
    monkeypatch.setattr(dr_backup, "_owner_of", lambda path: "path-read-owner")
    assert dr_backup._fallback_root_owner(root, owner) == owner
    assert dr_backup._fallback_root_owner(root, "another-owner") is None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows opens a link root as itself")
def test_the_windows_fallback_refuses_a_junction_root(tmp_path) -> None:
    """A staging root that is a junction is opened as itself and refused, as ``_owner_of`` refuses
    one, so the fallback never reads its target's owner."""
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    _link_dir(target, link)
    owner = dr_backup._owner_of(target)
    assert owner is not None
    assert dr_backup._fallback_root_owner(target, owner) == owner  # the control
    assert dr_backup._fallback_root_owner(link, owner) is None


def test_a_leaked_probe_file_is_swept_and_a_nonempty_one_is_kept(tmp_path) -> None:
    """A probe file whose removal failed is empty and holds no lock. The sweep of its root by
    its owner removes it, and leaves a probe-named file that holds anything."""
    root = tmp_path / "root"
    root.mkdir()
    leaked = root / f"{dr_backup._OWNER_PROBE_PREFIX}leaked"
    leaked.write_bytes(b"")
    kept = root / f"{dr_backup._OWNER_PROBE_PREFIX}kept"
    kept.write_bytes(b"synthetic")
    owner = dr_backup._owner_of(leaked)
    assert owner is not None
    dr_backup._sweep_owned(root, owner, own=None)
    assert not leaked.exists()
    assert kept.read_bytes() == b"synthetic"


# --- #4989: a directory the walk took for a file is reported ------------------------------------


def _staging_with_untyped_subdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A staging directory holding ``sub/inner.tar``, behind the seam for an ``is_dir`` that
    raised: the walk lists ``sub`` among the files, and so never descends into it."""
    staging = tmp_path / "mefor-backup-own"
    (staging / "sub").mkdir(parents=True)
    (staging / "sub" / "inner.tar").write_bytes(b"synthetic plaintext")
    real_walk = dr_backup._walk

    def walk(top: Path, **kwargs: Any) -> Iterator[Any]:
        for step in real_walk(top, **kwargs):
            dirs, files = step[1], step[2]
            if "sub" in dirs:
                dirs.remove("sub")  # in place, so neither walk descends
                files.append("sub")
            yield step

    monkeypatch.setattr(dr_backup, "_walk", walk)
    return staging


def test_a_directory_the_walk_lists_as_a_file_is_reported(tmp_path, monkeypatch) -> None:
    staging = _staging_with_untyped_subdir(tmp_path, monkeypatch)
    (staging / "own.tar").write_bytes(b"synthetic plaintext")
    unproven = dr_backup._empty_files_in_place(staging)
    assert unproven == ["sub/ (not walked)"]
    # It was never walked, so its file is still full; the sibling file is emptied.
    assert (staging / "sub" / "inner.tar").read_bytes() == b"synthetic plaintext"
    assert (staging / "own.tar").read_bytes() == b""


def test_the_teardown_reports_it_and_does_not_say_every_file_was_emptied(
    tmp_path, monkeypatch, caplog
) -> None:
    """The cleanup alert hangs on the returned sentence. With the directory unreported, the
    teardown returned None and logged that every file was emptied."""
    staging = _staging_with_untyped_subdir(tmp_path, monkeypatch)
    monkeypatch.setattr(dr_backup, "_remove_tree", lambda path: False)
    monkeypatch.setattr(dr_backup, "_STAGING_REMOVE_DELAYS", ())
    with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
        leftover = dr_backup._discard_verify_staging(staging)
    assert leftover is not None and "sub/ (not walked)" in leftover
    assert not any("every file emptied" in r.getMessage() for r in caplog.records)
    assert any(
        r.levelno == logging.ERROR and "sub/ (not walked)" in r.getMessage() for r in caplog.records
    )


def test_a_directory_link_listed_as_a_file_is_still_not_reported(tmp_path) -> None:
    """The control: a junction (Windows) or a symlink (POSIX) to a directory names another path and
    is never walked, as before. Windows reports a junction as a directory, so it is checked apart."""
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    _link_dir(target, link)
    inside = str(tmp_path) if os.name == "nt" else None
    assert dr_backup._truncate_unfollowed(link, None, inside) is None
