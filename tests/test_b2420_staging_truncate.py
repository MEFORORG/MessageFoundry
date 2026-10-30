# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2420: the backup's sweep of its own staging root takes only directories with this run's
owner, and the truncate fail-safe empties the object it checked, never a name it checked earlier.

`.mefor-staging` under a server-DB store's backup destination inherits whatever the destination
grants. Before this item the backup swept it with no owner filter, so another account could plant a
`mefor-backup-*` directory holding a lock file and a marker there, and force the teardown's fail-safe
to run on it. That fail-safe `lstat`ed each file and then opened it BY NAME, so a name swapped for a
link, or a parent directory swapped for a junction, between the check and the open would have had
the engine truncate a file outside the directory.

Every test uses synthetic bytes only."""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher

_OUTSIDE = b"not the engine's to empty"


def _abandoned(root: Path, prefix: str) -> Path:
    """A staging directory whose run died: made the real way, holding plaintext, then its lock handle
    closed with nothing removed, which is what a crash or SIGKILL leaves."""
    work = dr_backup._open_staging(root, prefix, secure=False)
    (work.path / "archive.tar").write_bytes(b"synthetic plaintext")
    dr_backup._unlock_and_close(work._fd)
    return work.path


def _link_dir(target: Path, link: Path) -> None:
    """A directory link at ``link``: a junction on Windows, which needs no privilege, else a symlink."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


# --- the owner filter on the backup's own sweep -------------------------------------------------


async def _store_and_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A keyed SQLite store holding one synthetic message, and a backup runner for it. The OS temp
    dir is pointed at an empty directory of the test's own."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "ostemp"))
    (tmp_path / "ostemp").mkdir()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    key = generate_key()
    store = await MessageStore.open(data_dir / "msg.db", cipher=make_cipher(key))
    await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|synthetic-body",
        deliveries=[("d1", "OUT|synthetic-delivery")],
        control_id="CID-1",
        now=1.0,
    )
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "dest")),
        store_settings=StoreSettings(path=str(data_dir / "msg.db"), encryption_key=key),
        config_dir=None,
        instance="dev",
    )
    return store, runner


async def test_the_backups_sweep_of_its_staging_root_leaves_another_accounts_directory(
    tmp_path, monkeypatch, caplog
) -> None:
    """A server-DB store stages in `.mefor-staging` under the destination. A dead-looking directory
    there owned by another account is not swept, and the sweep says so, while this account's
    abandoned one still is."""
    import logging

    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    # Stage where a server-DB store would, while still snapshotting this SQLite store.
    real_root_for = dr_backup._staging_root_for

    def server_db_root(*, server_db: bool, store_path: str | None, destination: Path):
        return real_root_for(server_db=True, store_path=store_path, destination=destination)

    monkeypatch.setattr(dr_backup, "_staging_root_for", server_db_root)
    root = (tmp_path / "dest").absolute() / ".mefor-staging"
    ours = _abandoned(root, "mefor-backup-")
    planted = _abandoned(root, "mefor-backup-")
    real_owner = dr_backup._owner_of

    def owner(path: Path) -> object | None:
        return "someone-else" if Path(path) == planted else real_owner(path)

    monkeypatch.setattr(dr_backup, "_owner_of", owner)
    try:
        with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
            result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None and result.verify is not None and result.verify.ok
    # The control: this account's abandoned directory is gone.
    assert not ours.exists()
    # The plant is untouched, its bytes whole, and named in the log.
    assert (planted / "archive.tar").read_bytes() == b"synthetic plaintext"
    assert sorted(p.name for p in root.iterdir()) == [planted.name]
    assert any(
        "has another owner" in r.getMessage() and planted.name in r.getMessage()
        for r in caplog.records
    )


async def test_a_dead_runs_leftover_is_swept_before_the_staging_directory_is_made(
    tmp_path, monkeypatch
) -> None:
    """A killed run can leave a volume full, and then making this run's own directory fails. The
    sweep therefore runs first, keyed on the owner a new directory of this process gets."""
    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    dead = _abandoned((tmp_path / "data").absolute(), "mefor-backup-")
    real_open = dr_backup._open_staging
    dead_at_open: list[bool] = []

    def open_after_the_sweep(root: Path, prefix: str, *, secure: bool):
        dead_at_open.append(dead.exists())
        return real_open(root, prefix, secure=secure)

    monkeypatch.setattr(dr_backup, "_open_staging", open_after_the_sweep)
    try:
        result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None
    assert dead_at_open[0] is False


# --- the fail-safe truncates the object it checked ----------------------------------------------


def test_a_file_swapped_for_a_hard_link_after_its_check_is_not_truncated(
    tmp_path, monkeypatch
) -> None:
    """The name passed the check as a regular file with one link, then became a hard link to a file
    outside before the open. Opened by name, that outside file was emptied. A hard link needs no
    privilege on either platform, so this runs everywhere."""
    staging = tmp_path / "mefor-verify-planted"
    staging.mkdir()
    outside = tmp_path / "outside.dat"
    outside.write_bytes(_OUTSIDE)
    (staging / "own.tar").write_bytes(b"synthetic plaintext")
    swapped = staging / "swap.dat"
    swapped.write_bytes(b"synthetic")
    real_open = dr_backup._open_unfollowed

    def swap_then_open(entry: Path, dir_fd: int | None) -> int:
        if entry.name == "swap.dat":
            os.unlink(swapped)
            try:
                os.link(outside, swapped)
            except OSError as exc:  # pragma: no cover - a file system without hard links
                pytest.skip(f"hard links unavailable here: {exc}")
        return real_open(entry, dir_fd)

    monkeypatch.setattr(dr_backup, "_open_unfollowed", swap_then_open)
    unproven = dr_backup._empty_files_in_place(staging)
    assert outside.read_bytes() == _OUTSIDE
    assert unproven == ["swap.dat (hard-linked, not truncated)"]
    # The control: a file of its own in the same directory is still emptied.
    assert (staging / "own.tar").read_bytes() == b""


def test_a_file_swapped_for_a_symlink_after_its_check_is_not_truncated(
    tmp_path, monkeypatch
) -> None:
    staging = tmp_path / "mefor-verify-planted"
    staging.mkdir()
    outside = tmp_path / "outside.dat"
    outside.write_bytes(_OUTSIDE)
    (staging / "own.tar").write_bytes(b"synthetic plaintext")
    swapped = staging / "swap.dat"
    swapped.write_bytes(b"synthetic")
    real_open = dr_backup._open_unfollowed

    def swap_then_open(entry: Path, dir_fd: int | None) -> int:
        if entry.name == "swap.dat":
            os.unlink(swapped)
            try:
                os.symlink(outside, swapped)
            except OSError as exc:  # pragma: no cover - Windows without the symlink privilege
                pytest.skip(f"symlinks unavailable here: {exc}")
        return real_open(entry, dir_fd)

    monkeypatch.setattr(dr_backup, "_open_unfollowed", swap_then_open)
    unproven = dr_backup._empty_files_in_place(staging)
    assert outside.read_bytes() == _OUTSIDE
    # POSIX refuses the open (ELOOP); Windows opens the link as itself and refuses it on the handle.
    assert unproven in (["swap.dat"], ["swap.dat (changed while being emptied, not truncated)"])
    assert (staging / "own.tar").read_bytes() == b""


def test_a_directory_swapped_for_a_link_after_its_listing_is_not_followed(
    tmp_path, monkeypatch
) -> None:
    """The subdirectory passed the walk's link filter, then was moved away and replaced by a link
    to a directory outside before the walk entered it."""
    staging = tmp_path / "mefor-verify-planted"
    (staging / "sub").mkdir(parents=True)
    (staging / "sub" / "inner.tar").write_bytes(b"synthetic plaintext")
    (staging / "own.tar").write_bytes(b"synthetic plaintext")
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "victim.dat").write_bytes(_OUTSIDE)
    real_walk = dr_backup._walk

    def walk_then_swap(top: Path, **kwargs: Any) -> Iterator[Any]:
        listing = iter(real_walk(top, **kwargs))
        yield next(listing)  # the root, whose dirnames the caller filters before resuming
        os.rename(staging / "sub", tmp_path / "moved")
        _link_dir(outside_dir, staging / "sub")
        yield from listing

    monkeypatch.setattr(dr_backup, "_walk", walk_then_swap)
    unproven = dr_backup._empty_files_in_place(staging)
    assert (outside_dir / "victim.dat").read_bytes() == _OUTSIDE
    assert (staging / "own.tar").read_bytes() == b""
    if sys.platform == "win32":
        # Reached by path through the junction, and refused without its name, before any file in
        # it is opened or named.
        assert unproven == [dr_backup._OUTSIDE_REASON]
    else:
        # The descriptor walk refuses to enter it, and says so.
        assert unproven == ["sub/ (not listed)"]


def test_a_staging_root_that_is_a_link_is_not_walked(tmp_path) -> None:
    """The root itself replaced by a link to a directory outside: nothing there is emptied, and the
    fail-safe says it could not list the directory rather than calling it empty."""
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "victim.dat").write_bytes(_OUTSIDE)
    staging = tmp_path / "mefor-verify-planted"
    _link_dir(outside_dir, staging)
    unproven = dr_backup._empty_files_in_place(staging)
    assert (outside_dir / "victim.dat").read_bytes() == _OUTSIDE
    assert unproven == ["mefor-verify-planted/ (not listed)"]


def test_the_fail_safe_still_empties_its_own_files_in_nested_directories(tmp_path) -> None:
    """The control for every refusal above: plain files at every depth are emptied, and nothing is
    reported."""
    staging = tmp_path / "mefor-verify-own"
    (staging / "a" / "b").mkdir(parents=True)
    files = [staging / "top.tar", staging / "a" / "mid.db", staging / "a" / "b" / "deep.db"]
    for f in files:
        f.write_bytes(b"synthetic plaintext")
    assert dr_backup._empty_files_in_place(staging) == []
    assert [f.read_bytes() for f in files] == [b"", b"", b""]


def test_two_files_of_one_name_that_refuse_are_both_reported(tmp_path, monkeypatch) -> None:
    """Only the nameless reason for something outside is said once; two refusing files that share a
    name in different directories are two entries, so the report does not under-count."""
    staging = tmp_path / "mefor-verify-own"
    for sub in ("a", "b"):
        (staging / sub).mkdir(parents=True)
        (staging / sub / "extracted_store.db").write_bytes(b"synthetic plaintext")

    def refuse(entry: Path, dir_fd: int | None) -> int:
        raise PermissionError(13, "synthetic sharing violation", str(entry))

    monkeypatch.setattr(dr_backup, "_open_unfollowed", refuse)
    assert dr_backup._empty_files_in_place(staging) == ["extracted_store.db", "extracted_store.db"]
