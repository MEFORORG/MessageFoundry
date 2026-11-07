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
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

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

    def swap_then_open(entry: Path, dir_fd: int | None, inside: str | None) -> int:
        if entry.name == "swap.dat":
            os.unlink(swapped)
            try:
                os.link(outside, swapped)
            except OSError as exc:  # pragma: no cover - a file system without hard links
                pytest.skip(f"hard links unavailable here: {exc}")
        return real_open(entry, dir_fd, inside)

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

    def swap_then_open(entry: Path, dir_fd: int | None, inside: str | None) -> int:
        if entry.name == "swap.dat":
            os.unlink(swapped)
            try:
                os.symlink(outside, swapped)
            except OSError as exc:  # pragma: no cover - Windows without the symlink privilege
                pytest.skip(f"symlinks unavailable here: {exc}")
        return real_open(entry, dir_fd, inside)

    monkeypatch.setattr(dr_backup, "_open_unfollowed", swap_then_open)
    unproven = dr_backup._empty_files_in_place(staging)
    assert outside.read_bytes() == _OUTSIDE
    # POSIX refuses the open (ELOOP); Windows opens the link as itself and refuses it on the handle.
    assert unproven in (["swap.dat"], ["swap.dat (changed while being emptied, not truncated)"])
    assert (staging / "own.tar").read_bytes() == b""


def test_a_directory_swapped_for_a_link_after_its_listing_is_not_followed(
    tmp_path, monkeypatch
) -> None:
    """The subdirectory was listed in the root, then was moved away and replaced by a link to a
    directory outside while the root's own file was being emptied, before the walk entered it."""
    staging = tmp_path / "mefor-verify-planted"
    (staging / "sub").mkdir(parents=True)
    (staging / "sub" / "inner.tar").write_bytes(b"synthetic plaintext")
    (staging / "own.tar").write_bytes(b"synthetic plaintext")
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "victim.dat").write_bytes(_OUTSIDE)
    real_open = dr_backup._open_unfollowed

    def swap_then_open(entry: Path, dir_fd: int | None, inside: str | None) -> int:
        if entry.name == "own.tar":  # the root's file, emptied before the walk enters `sub`
            os.rename(staging / "sub", tmp_path / "moved")
            _link_dir(outside_dir, staging / "sub")
        return real_open(entry, dir_fd, inside)

    monkeypatch.setattr(dr_backup, "_open_unfollowed", swap_then_open)
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

    def refuse(entry: Path, dir_fd: int | None, inside: str | None) -> int:
        raise PermissionError(13, "synthetic sharing violation", str(entry))

    monkeypatch.setattr(dr_backup, "_open_unfollowed", refuse)
    assert dr_backup._empty_files_in_place(staging) == ["extracted_store.db", "extracted_store.db"]


# --- review round three -------------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
def test_a_fifo_planted_at_the_lock_does_not_hold_the_teardown(
    tmp_path, monkeypatch, caplog
) -> None:
    """A teardown whose removal is refused puts the lock file and marker back. A FIFO planted at the
    lock name held that open until a reader came, which may be never; it now fails at once and is
    logged."""
    import logging
    import threading

    staging = tmp_path / "mefor-backup-planted"
    staging.mkdir()
    fifo = staging / ".lock"
    os.mkfifo(fifo)
    # The removal refused, so the directory and its FIFO survive to the re-mark.
    monkeypatch.setattr(dr_backup, "_discard_verify_staging", lambda path: "synthetic leftover")
    done: list[str | None] = []
    with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
        worker = threading.Thread(
            target=lambda: done.append(dr_backup._teardown_staging(staging)), daemon=True
        )
        worker.start()
        worker.join(10)
        try:
            assert not worker.is_alive(), "the re-mark open blocked on a FIFO"
        finally:
            if worker.is_alive():  # free the blocked open, so the red arm does not leak a thread
                os.close(os.open(fifo, os.O_RDONLY | os.O_NONBLOCK))
                worker.join(10)
    assert done == ["synthetic leftover"]
    assert any("could not be marked" in r.getMessage() for r in caplog.records)


async def test_the_os_temp_sweep_is_keyed_on_the_process_owner(tmp_path, monkeypatch) -> None:
    """On a share whose server sets the owner, this run's staging directory reports that owner, not
    the process's. A standalone verify this account ran left its directory in the OS temp dir with
    the process's owner, and the backup's sweep of the temp dir must still take it."""
    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    dead_verify = _abandoned(tmp_path / "ostemp", "mefor-verify-")
    data = (tmp_path / "data").absolute()
    # Everything the run makes in its data dir carries the share's owner, its owner probe included.
    _share_owner_for(data, monkeypatch)
    try:
        result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None and result.verify is not None and result.verify.ok
    assert not dead_verify.exists()


async def test_a_backup_that_will_not_fit_opens_no_staging_directory(tmp_path, monkeypatch) -> None:
    """The free-space check runs after the sweeps and before this run's directory is opened, so a
    full volume fails with kind `space`, and no lock or marker is written before the refusal."""
    import shutil

    store, runner = await _store_and_runner(tmp_path, monkeypatch)

    class _Usage:
        free = 1

    monkeypatch.setattr(shutil, "disk_usage", lambda _path: _Usage())
    opened: list[Path] = []
    real_open = dr_backup._open_staging

    def recording_open(root: Path, prefix: str, *, secure: bool):
        opened.append(root)
        return real_open(root, prefix, secure=secure)

    monkeypatch.setattr(dr_backup, "_open_staging", recording_open)
    try:
        with pytest.raises(dr_backup.BackupError) as caught:
            await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert caught.value.kind == "space"
    assert opened == []


def _share_owner_for(
    data: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    made_by_another: Path | None = None,
    root_too: bool = False,
) -> None:
    """A server-owner stand-in: everything made under ``data`` reports the share's owner, not the
    process's, as on an SMB or NFS share whose server sets the owner. ``made_by_another`` is a
    directory another principal made there that carries the owner this process's own directories
    get elsewhere, as SYSTEM on the file server can. ``root_too`` has ``data`` itself report the
    share's owner, as a staging root this account made on such a share does. It drives both the
    path read and the descriptor read, which a POSIX owner probe uses."""
    real_owner = dr_backup._owner_of
    real_fd_owner = dr_backup._owner_of_fd

    def on_share(path: Path) -> bool:
        p = Path(path).absolute()
        if p == data:
            return root_too
        return p != made_by_another and p.is_relative_to(data)

    def owner(path: Path) -> object | None:
        return "share-owner" if on_share(path) else real_owner(path)

    def fd_owner(fd: int, opened_as: Path) -> object | None:
        return "share-owner" if on_share(opened_as) else real_fd_owner(fd, opened_as)

    monkeypatch.setattr(dr_backup, "_owner_of", owner)
    monkeypatch.setattr(dr_backup, "_owner_of_fd", fd_owner)


def _root_probe_answers_none(
    data: Path, monkeypatch: pytest.MonkeyPatch, *, first: int | None = 1
) -> list[Path]:
    """The probe of ``data`` answers None for its ``first`` calls (every call when ``None``), as
    when it cannot be created there. The early sweep then goes by ``_fallback_root_owner`` (BACKLOG
    #4988). Returns the calls, one per probe of ``data``."""
    real_probe = dr_backup._probe_owner
    calls: list[Path] = []

    def probe(root: Path | None) -> object | None:
        if root is not None and Path(root).absolute() == data:
            calls.append(root)
            if first is None or len(calls) <= first:
                return None
        return real_probe(root)

    monkeypatch.setattr(dr_backup, "_probe_owner", probe)
    return calls


def _exists_at_open(monkeypatch: pytest.MonkeyPatch, path: Path) -> list[bool]:
    """Whether ``path`` still exists at each staging open, in order."""
    seen: list[bool] = []
    real_open = dr_backup._open_staging

    def recording_open(root: Path, prefix: str, *, secure: bool):
        seen.append(path.exists())
        return real_open(root, prefix, secure=secure)

    monkeypatch.setattr(dr_backup, "_open_staging", recording_open)
    return seen


def _recording_open(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    opened: list[Path] = []
    real_open = dr_backup._open_staging

    def recording_open(root: Path, prefix: str, *, secure: bool):
        opened.append(root)
        return real_open(root, prefix, secure=secure)

    monkeypatch.setattr(dr_backup, "_open_staging", recording_open)
    return opened


async def test_a_killed_runs_leftover_on_a_server_owner_share_is_freed_before_space_refuses(
    tmp_path, monkeypatch
) -> None:
    """On a share whose server sets the owner, an early sweep that did not go by the owner a probe
    there gets misses a killed run's large leftover; since BACKLOG #4988 that is one whose probe
    answered None. Before this, the free-space check then refused with `space`, and every later
    backup did too until someone deleted it by hand. The check now sweeps by the owner a probe
    directory there gets, and the run proceeds."""
    import shutil

    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    data = (tmp_path / "data").absolute()
    dead = _abandoned(data, "mefor-backup-")
    _share_owner_for(data, monkeypatch)
    _root_probe_answers_none(data, monkeypatch)

    class _Usage:
        def __init__(self, free: int) -> None:
            self.free = free

    # The leftover is what fills the volume: while it exists there is no room.
    monkeypatch.setattr(shutil, "disk_usage", lambda _path: _Usage(1 if dead.exists() else 1 << 40))
    try:
        result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None and result.verify is not None and result.verify.ok
    assert not dead.exists()
    assert not any(p.name.startswith("mefor-owner-probe-") for p in data.iterdir())


async def test_a_leftover_emptied_but_not_removed_by_the_probe_sweep_still_lets_the_run_fit(
    tmp_path, monkeypatch
) -> None:
    """A probe sweep that empties a killed run's leftover but cannot remove its directory counts
    nothing, yet the space is free. The space check runs again after that sweep whatever it
    counted, so the run proceeds instead of refusing with `space`."""
    import shutil

    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    data = (tmp_path / "data").absolute()
    dead = _abandoned(data, "mefor-backup-")
    heavy = dead / "archive.tar"
    _share_owner_for(data, monkeypatch)
    _root_probe_answers_none(data, monkeypatch)
    real_teardown = dr_backup._teardown_staging

    def emptied_not_removed(path: Path) -> str | None:
        # The seam: the files go, the directory removal is refused, so the sweep counts 0.
        if Path(path).name == dead.name:
            heavy.unlink(missing_ok=True)
            return None
        return real_teardown(path)

    monkeypatch.setattr(dr_backup, "_teardown_staging", emptied_not_removed)

    class _Usage:
        def __init__(self, free: int) -> None:
            self.free = free

    # The leftover's file is what fills the volume: while it exists there is no room.
    monkeypatch.setattr(
        shutil, "disk_usage", lambda _path: _Usage(1 if heavy.exists() else 1 << 40)
    )
    try:
        result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None and result.verify is not None and result.verify.ok
    assert not heavy.exists()
    assert dead.exists()  # emptied, not removed: the sweep counted nothing


async def test_a_genuinely_short_volume_on_a_server_owner_share_still_refuses(
    tmp_path, monkeypatch
) -> None:
    """The control: with the same stand-in and the same failed first probe, a volume that is short
    even once the second probe's sweep takes the leftover still refuses with `space`, opens no run
    directory, and leaves no probe behind."""
    import shutil

    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    data = (tmp_path / "data").absolute()
    dead = _abandoned(data, "mefor-backup-")
    _share_owner_for(data, monkeypatch)
    probes = _root_probe_answers_none(data, monkeypatch)

    class _Usage:
        free = 1

    monkeypatch.setattr(shutil, "disk_usage", lambda _path: _Usage())
    opened = _recording_open(monkeypatch)
    try:
        with pytest.raises(dr_backup.BackupError) as caught:
            await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert caught.value.kind == "space"
    assert opened == []
    # Probed twice: the leftover went by the second probe's owner, the path this test controls.
    assert len(probes) == 2
    assert not dead.exists()  # swept by the probed owner before the refusal
    assert not any(
        p.name.startswith(("mefor-owner-probe-", "mefor-backup-")) for p in data.iterdir()
    )


async def test_a_leaked_owner_probe_is_swept_by_the_next_run(tmp_path, monkeypatch) -> None:
    """An empty probe-named directory with no lock, as an earlier build's directory probe whose
    removal failed left. The next sweep of its root removes it, and leaves a probe-named directory
    that holds anything."""
    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    data = (tmp_path / "data").absolute()
    leaked = Path(tempfile.mkdtemp(prefix="mefor-owner-probe-", dir=data))
    kept = Path(tempfile.mkdtemp(prefix="mefor-owner-probe-", dir=data))
    (kept / "keep.txt").write_bytes(b"synthetic")
    try:
        result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None
    assert not leaked.exists()
    assert (kept / "keep.txt").read_bytes() == b"synthetic"


@pytest.mark.skipif(sys.platform != "win32", reason="GetFinalPathNameByHandleW is Windows-only")
def test_a_volume_without_final_paths_empties_nothing_and_says_so(
    tmp_path, monkeypatch, caplog
) -> None:
    """Some redirectors cannot name a handle's final path. The fail-safe then cannot show any file
    lies inside the directory, so it empties nothing, never falling back to a path, and logs that it
    could not run there, naming no file."""
    import ctypes
    import logging

    staging = tmp_path / "mefor-verify-own"
    staging.mkdir()
    (staging / "extracted_store.db").write_bytes(b"synthetic plaintext")

    def unsupported(fd: int) -> str:
        raise ctypes.WinError(50)  # type: ignore[attr-defined]  # ERROR_NOT_SUPPORTED

    monkeypatch.setattr(dr_backup, "_win_final_path", unsupported)
    with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
        unproven = dr_backup._empty_files_in_place(staging)
    assert unproven == ["mefor-verify-own/ (not listed)"]
    assert (staging / "extracted_store.db").read_bytes() == b"synthetic plaintext"
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("fail-safe cannot run on the volume" in m for m in warnings)
    assert not any("extracted_store.db" in m for m in warnings)


def test_a_file_that_vanishes_only_after_its_open_is_still_reported(tmp_path, monkeypatch) -> None:
    """BACKLOG #4992: only the OPEN's "not found" means there was nothing to empty. The same error
    from a check on the already-open file leaves that file full, so it is reported by name, and the
    teardown does not read the directory as holding no plaintext."""
    staging = tmp_path / "mefor-verify-own"
    staging.mkdir()
    (staging / "extracted_store.db").write_bytes(b"synthetic plaintext")

    def gone(fd: int, length: int) -> None:
        raise FileNotFoundError(2, "synthetic: not found after the open")

    monkeypatch.setattr(os, "ftruncate", gone)
    assert dr_backup._empty_files_in_place(staging) == ["extracted_store.db"]
    assert (staging / "extracted_store.db").read_bytes() == b"synthetic plaintext"


# --- the name screened is the name truncated, and a listed name that is gone is reported ---------
#
# Two defects of this item's class, rolled in 2026-11-04 from engine PR 2744's open findings 1 and 2.

_PLAINTEXT = b"synthetic plaintext"
_GONE = dr_backup._GONE_REASON


def _verbatim(root: Path, *names: str) -> str:
    """``root/names...`` behind the verbatim prefix, which has Win32 open each name exactly as
    written, so a test can make and read the names an ordinary open would rewrite."""
    return "\\\\?\\" + os.path.abspath(root) + "".join("\\" + name for name in names)


def _plant(root: Path, *names: str) -> None:
    with open(_verbatim(root, *names), "wb") as handle:
        handle.write(_PLAINTEXT)


def _size(root: Path, *names: str) -> int:
    return os.stat(_verbatim(root, *names)).st_size


@pytest.fixture
def win_tmp(tmp_path: Path) -> Iterator[Path]:
    """``tmp_path``, removed through the verbatim prefix afterwards: an ordinary removal cannot reach
    a name such as ``NUL`` or ``a.tar.``."""
    yield tmp_path
    shutil.rmtree(_verbatim(tmp_path), ignore_errors=True)


_windows_only = pytest.mark.skipif(
    sys.platform != "win32", reason="Win32 path rewriting is Windows-only"
)


@_windows_only
@pytest.mark.parametrize("name", ["extracted_store.db.", "extracted_store.db ", "NUL"])
def test_a_name_windows_rewrites_is_reported_and_not_truncated_as_another_file(
    win_tmp: Path, name: str
) -> None:
    """Win32 drops a trailing dot or space, and opens a device name as the device, before it opens a
    path. Red before the fix: `extracted_store.db.` was checked and truncated as
    `extracted_store.db`, so the listed file kept its plaintext; with no such sibling the open found
    nothing and read as nothing to empty. Either way the report called the directory clean."""
    staging = win_tmp / "mefor-verify-planted"
    staging.mkdir()
    _plant(staging, name)
    sibling = name.rstrip(". ")
    if sibling != name:
        (staging / sibling).write_bytes(b"synthetic sibling")
    unproven = dr_backup._empty_files_in_place(staging)
    assert unproven == [f"{name} {dr_backup._REWRITTEN_FILE}"]
    assert _size(staging, name) == len(_PLAINTEXT)
    if sibling != name:
        # The control: the sibling is a listed file of its own, and is emptied as itself.
        assert (staging / sibling).read_bytes() == b""


@_windows_only
def test_a_directory_name_windows_rewrites_is_not_walked_as_another_directory(
    win_tmp: Path,
) -> None:
    """`sub.` opens as `sub`. Red before the fix: the walk held and listed `sub` in its place, so
    `sub.`'s file was never reached, and nothing reported it."""
    staging = win_tmp / "mefor-verify-planted"
    staging.mkdir()
    os.mkdir(_verbatim(staging, "sub."))
    _plant(staging, "sub.", "inner.tar")
    (staging / "sub").mkdir()
    (staging / "sub" / "own.tar").write_bytes(_PLAINTEXT)
    unproven = dr_backup._empty_files_in_place(staging)
    assert unproven == [f"sub./ {dr_backup._REWRITTEN_DIR}"]
    assert _size(staging, "sub.", "inner.tar") == len(_PLAINTEXT)
    assert (staging / "sub" / "own.tar").read_bytes() == b""


@_windows_only
def test_a_staging_root_whose_name_windows_rewrites_is_not_walked(win_tmp: Path) -> None:
    """A sweep can hand the fail-safe a planted `mefor-backup-x.`, which opens as `mefor-backup-x`."""
    os.mkdir(_verbatim(win_tmp, "mefor-backup-x."))
    other = win_tmp / "mefor-backup-x"
    other.mkdir()
    (other / "archive.tar").write_bytes(_PLAINTEXT)
    unproven = dr_backup._empty_files_in_place(win_tmp / "mefor-backup-x.")
    assert unproven == [f"mefor-backup-x./ {dr_backup._REWRITTEN_DIR}"]
    assert (other / "archive.tar").read_bytes() == _PLAINTEXT


@_windows_only
def test_the_teardown_touches_no_other_directory_for_a_rewritten_name(win_tmp: Path) -> None:
    """The teardown's own removal goes by path before any fail-safe runs. Red before the fix: it
    removed `mefor-backup-x` for `mefor-backup-x.`, then found the name gone and returned clean,
    while the planted directory kept its file. Now nothing is removed, emptied or re-marked."""
    planted = win_tmp / "mefor-backup-x."
    os.mkdir(_verbatim(win_tmp, "mefor-backup-x."))
    _plant(win_tmp, "mefor-backup-x.", "planted.tar")
    other = win_tmp / "mefor-backup-x"
    other.mkdir()
    (other / "archive.tar").write_bytes(_PLAINTEXT)
    leftover = dr_backup._teardown_staging(planted)
    assert leftover is not None and "since Windows opens that path as another" in leftover
    assert sorted(p.name for p in other.iterdir()) == ["archive.tar"]
    assert (other / "archive.tar").read_bytes() == _PLAINTEXT
    assert _size(win_tmp, "mefor-backup-x.", "planted.tar") == len(_PLAINTEXT)


@_windows_only
def test_the_root_final_path_compare_refuses_a_rewritten_root_the_screen_missed(
    win_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backstop for the root: with the screen told to pass every name, the directory held for
    `mefor-backup-x.` is `mefor-backup-x`, whose final path names another directory."""
    os.mkdir(_verbatim(win_tmp, "mefor-backup-x."))
    other = win_tmp / "mefor-backup-x"
    other.mkdir()
    (other / "archive.tar").write_bytes(_PLAINTEXT)
    monkeypatch.setattr(dr_backup, "_win_opens_another", lambda path: False)
    unproven = dr_backup._empty_files_in_place(win_tmp / "mefor-backup-x.")
    assert unproven == ["mefor-backup-x./ (changed while being emptied, not walked)"]
    assert (other / "archive.tar").read_bytes() == _PLAINTEXT


@_windows_only
def test_the_final_path_compare_refuses_a_rewritten_name_the_screen_missed(
    win_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backstop for the name screen: with the screen told to pass every name, the file opened
    for `a.tar.` and the directory held for `sub.` have final paths other than the names listed, so
    neither is emptied as the listed name."""
    staging = win_tmp / "mefor-verify-planted"
    staging.mkdir()
    _plant(staging, "a.tar.")
    (staging / "a.tar").write_bytes(b"synthetic sibling")
    os.mkdir(_verbatim(staging, "sub."))
    _plant(staging, "sub.", "inner.tar")
    (staging / "sub").mkdir()
    monkeypatch.setattr(dr_backup, "_win_opens_another", lambda path: False)
    unproven = dr_backup._empty_files_in_place(staging)
    assert sorted(unproven) == [
        "a.tar. (changed while being emptied, not truncated)",
        "sub./ (changed while being emptied, not walked)",
    ]
    assert _size(staging, "a.tar.") == len(_PLAINTEXT)
    assert _size(staging, "sub.", "inner.tar") == len(_PLAINTEXT)


def test_a_file_renamed_after_the_listing_is_reported_not_read_as_nothing_to_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Renamed between the listing and the screen. Red before the fix: the screen's "not found" read
    as nothing to empty, so the teardown called the directory clean while `moved.tar` still held
    its plaintext under a name the walk had not listed. Both platforms."""
    staging = tmp_path / "mefor-verify-planted"
    staging.mkdir()
    (staging / "a.tar").write_bytes(_PLAINTEXT)
    seam = "_win_held_walk" if sys.platform == "win32" else "_walk"
    real_walk = getattr(dr_backup, seam)

    def rename_after_listing(*args: Any, **kwargs: Any) -> Iterator[Any]:
        for step in real_walk(*args, **kwargs):
            if "a.tar" in step[2]:
                os.rename(staging / "a.tar", staging / "moved.tar")
            yield step

    monkeypatch.setattr(dr_backup, seam, rename_after_listing)
    assert dr_backup._empty_files_in_place(staging) == [f"a.tar {_GONE}"]
    assert (staging / "moved.tar").read_bytes() == _PLAINTEXT


def test_a_file_renamed_after_its_screen_is_reported_not_read_as_nothing_to_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Renamed between the screen and the first open: the open's "not found" is reported too."""
    staging = tmp_path / "mefor-verify-planted"
    staging.mkdir()
    (staging / "a.tar").write_bytes(_PLAINTEXT)
    (staging / "own.tar").write_bytes(_PLAINTEXT)
    real_open = dr_backup._open_unfollowed

    def rename_then_open(entry: Path, dir_fd: int | None, inside: str | None) -> int:
        if entry.name == "a.tar":
            os.rename(staging / "a.tar", staging / "moved.tar")
        return real_open(entry, dir_fd, inside)

    monkeypatch.setattr(dr_backup, "_open_unfollowed", rename_then_open)
    assert dr_backup._empty_files_in_place(staging) == [f"a.tar {_GONE}"]
    assert (staging / "moved.tar").read_bytes() == _PLAINTEXT
    # The control: the other file of the same directory is still emptied.
    assert (staging / "own.tar").read_bytes() == b""


# --- the refusal for a rewritten staging name, and the screens' never-raise guard ----------------
#
# BACKLOG #2420. Most tests here patch the screen, so they run on both platforms: the advice and the
# guards are the same code on each.


def test_the_refusal_for_a_rewritten_staging_name_advises_no_removal_by_hand(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A removal by the plain path removes the other directory (see `_rewritten_staging_refusal`).
    Red before the fix: the refusal said "delete it by hand", in the sentence returned and in the log
    line. It now names the directory by its verbatim path alone, and that path as the only removal."""
    import logging

    staging = tmp_path / "mefor-backup-x"
    staging.mkdir()
    (staging / "archive.tar").write_bytes(_PLAINTEXT)
    monkeypatch.setattr(dr_backup, "_win_rewritten", lambda path: True)
    with caplog.at_level(logging.ERROR, logger=dr_backup.__name__):
        leftover = dr_backup._teardown_staging(staging)
    logged = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert leftover is not None and len(logged) == 1
    verbatim = dr_backup._win_verbatim(staging)
    assert leftover.startswith(
        "a plaintext staging directory was not removed or emptied; never remove it by its plain path"
    )
    for text in (leftover, logged[0]):
        assert "by hand" not in text
        assert "delete it" not in text
        assert (
            "with this command: Remove-Item -LiteralPath "
            f"{dr_backup._ps_literal(verbatim)} -Recurse -Force ;" in text
        )
        assert "PowerShell, not cmd.exe" in text
        # A redacted path is not the directory's, and a command on it would find nothing.
        assert (
            "a path here that shows <redacted>, [redacted] or any other redaction marker was "
            "rewritten by redaction and is not the directory's path, so run no command here"
            in (text)
        )
        # The plain path appears only inside the verbatim one.
        assert str(staging) not in text.replace(verbatim, "")
    # Nothing was removed, emptied or re-marked.
    assert sorted(p.name for p in staging.iterdir()) == ["archive.tar"]
    assert (staging / "archive.tar").read_bytes() == _PLAINTEXT


@_windows_only
def test_the_refusals_verbatim_path_names_the_planted_directory_not_the_other(
    win_tmp: Path,
) -> None:
    """The path the refusal tells the operator to remove by reaches `mefor-backup-x.` itself."""
    os.mkdir(_verbatim(win_tmp, "mefor-backup-x."))
    _plant(win_tmp, "mefor-backup-x.", "planted.tar")
    (win_tmp / "mefor-backup-x").mkdir()
    (win_tmp / "mefor-backup-x" / "archive.tar").write_bytes(_PLAINTEXT)
    planted = win_tmp / "mefor-backup-x."
    leftover = dr_backup._teardown_staging(planted)
    verbatim = dr_backup._win_verbatim(planted)
    literal = dr_backup._ps_literal(verbatim)
    assert leftover is not None and f"; it is {literal}, whose name ends in a dot;" in leftover
    assert os.listdir(verbatim) == ["planted.tar"]


def _refusal_for(name: str, root: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """The refusal for ``root/name``, with the screen patched to flag it, on either platform."""
    monkeypatch.setattr(dr_backup, "_win_rewritten", lambda path: True)
    refusal = dr_backup._rewritten_staging_refusal(root / name)
    assert refusal is not None
    return refusal


def test_a_trailing_space_is_visible_in_the_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Printed bare, `mefor-backup-x ` read as `mefor-backup-x`, the other directory, and a copy of it
    removed that one. Red before the fix: the path ran straight into " was not removed". Now the
    closing quote follows the space, and the space is named in words."""
    refusal = _refusal_for("mefor-backup-x ", tmp_path, monkeypatch)
    verbatim = dr_backup._win_verbatim(tmp_path / "mefor-backup-x ")
    assert verbatim.endswith("mefor-backup-x ")
    assert f"it is {dr_backup._ps_literal(verbatim)}, whose name ends in a space;" in refusal
    dotted = _refusal_for("mefor-backup-x. ", tmp_path, monkeypatch)
    assert "whose name ends in a dot then a space;" in dotted


def test_a_percent_in_the_name_cannot_expand_in_the_advised_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Interactive cmd.exe expands `%PATH%` even inside double quotes. Red before the fix: the advice
    was cmd.exe's rd with the path in double quotes. Now the only command is PowerShell's, on a
    single-quoted literal, in which nothing expands, and no cmd.exe form is given."""
    name = "mefor-backup-x%PATH% "
    refusal = _refusal_for(name, tmp_path, monkeypatch)
    literal = dr_backup._ps_literal(dr_backup._win_verbatim(tmp_path / name))
    assert literal.endswith("%PATH% '")
    assert "PowerShell, not cmd.exe" in refusal
    assert f"with this command: Remove-Item -LiteralPath {literal} -Recurse -Force ;" in refusal
    assert '"' not in refusal
    assert "rd /s" not in refusal


def test_a_quote_in_the_name_is_doubled_in_the_literal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single quote, or any of the four characters PowerShell also reads as one, would end the
    literal early."""
    name = "mefor-backup-o'\u2018\u2019\u201a\u201bx."
    refusal = _refusal_for(name, tmp_path, monkeypatch)
    assert "mefor-backup-o''\u2018\u2018\u2019\u2019\u201a\u201a\u201b\u201bx.'" in refusal
    literal = dr_backup._ps_path(dr_backup._win_verbatim(tmp_path / name))
    joined = dr_backup.join_before_checks(refusal, "; ", "the run failed: synthetic")
    assert _head(joined, literal).endswith("no error; the run failed: synthetic")


def test_the_refusal_names_the_exact_path_to_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A check by the plain path goes through the same rewrite, and a check that cannot read the path
    prints False with an access-denied error. Red before the fix: "check that it is gone" named no
    path."""
    name = "mefor-backup-x%PATH% "
    refusal = _refusal_for(name, tmp_path, monkeypatch)
    literal = dr_backup._ps_literal(dr_backup._win_verbatim(tmp_path / name))
    assert refusal.endswith(
        f"must print False and no error; to check, in PowerShell: Test-Path -LiteralPath {literal}"
    )


# --- the third and fourth holds: the markers redaction writes, a two-step check, and the check
# --- last in the message, which holds no line break


def test_the_refusal_names_every_marker_redaction_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path rewritten by redaction names nothing, so a check on it reads as gone. Red before the
    fix: the text warned only about `[redacted]`, while the log's credential scrub writes
    `<redacted>`. The control: that scrub, run over a refusal whose path holds `pwd=`, does write
    `<redacted>` into the path and leaves the warning whole."""
    from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER, scrub_credentials

    refusal = _refusal_for("mefor-backup-x.", tmp_path / "pwd=nightly", monkeypatch)
    warning = (
        "a path here that shows <redacted>, [redacted] or any other redaction marker "
        "was rewritten by redaction and is not the directory's path, so run no command here"
    )
    assert warning in refusal
    # Each marker the warning names is the one its writer still writes. The support bundle's
    # marker is covered by "any other", and is not written: a line holding it takes the bundle's
    # whole-line credential pass.
    from messagefoundry import redaction
    from messagefoundry.support.redact import REDACTION_PLACEHOLDER

    assert CREDENTIAL_PLACEHOLDER == "<redacted>"
    assert redaction._REDACTED == "[redacted]"
    assert REDACTION_PLACEHOLDER not in refusal
    scrubbed = scrub_credentials(refusal)
    assert warning in scrubbed
    assert "pwd=<redacted>" in scrubbed.rpartition("Test-Path -LiteralPath ")[2]


def test_the_check_is_a_two_step_control(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A False alone is the same whether the directory is gone or the command names nothing. Red
    before the fix: the check was run only after the removal."""
    refusal = _refusal_for("mefor-backup-x%PATH% ", tmp_path, monkeypatch)
    first = refusal.index(
        "first run the Test-Path command on this same path that ends this message, and only that "
        "command; it must print True"
    )
    stop = refusal.index(
        "a False means that command does not reach this directory, whether it is gone, cannot be "
        "read or is named wrong, so run nothing more; only after a True, remove it only with this "
        "command:"
    )
    removal = refusal.index("Remove-Item -LiteralPath")
    assert first < stop < removal
    again = refusal.index(
        "then run that Test-Path command again, which must print False and no error"
    )
    assert first < removal < again


def _checks(*literals: str) -> str:
    """The checks a message ends in, one per literal, as the refusal writes them."""
    return "; to check, in PowerShell: " + " ; ".join(
        f"Test-Path -LiteralPath {literal}" for literal in literals
    )


def _head(text: str, *literals: str) -> str:
    """``text`` without the checks on ``literals``, which must end it. ``text`` must hold no line
    break, and no check anywhere else."""
    tail = _checks(*literals)
    assert text.endswith(tail), text[-300:]
    assert "\n" not in text
    head = text[: -len(tail)]
    assert "Test-Path -LiteralPath" not in head
    return head


def test_the_refusal_ends_in_its_check_and_holds_no_line_break(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before the fix: the check followed a line break, which fails `str.isprintable`, and
    `redact` skips its encoded-HL7 pass on such a text."""
    name = "mefor-backup-x%PATH% "
    refusal = _refusal_for(name, tmp_path, monkeypatch)
    literal = dr_backup._ps_literal(dr_backup._win_verbatim(tmp_path / name))
    assert refusal.isprintable()
    _head(refusal, literal)


@pytest.mark.parametrize(
    ("odd", "spelled"),
    [
        ("\u2028", "[char]0x2028"),
        ("\x85", "[char]0x0085"),
        ("\n", "[char]0x000A"),
        ("\u200b", "[char]0x200B"),
        ("\u00a0", "[char]0x00A0"),
    ],
)
def test_a_name_that_is_not_printable_is_named_exactly_and_stays_printable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, odd: str, spelled: str
) -> None:
    """A name can hold a character that fails `str.isprintable`, a line break among them, which
    would turn off `redact`'s encoded-HL7 pass for the whole message. Red before the fix: the
    refusal carried the raw character, three times. It now spells it as PowerShell evaluates it."""
    name = f"mefor-backup-x{odd}y."
    refusal = _refusal_for(name, tmp_path, monkeypatch)
    assert refusal.isprintable()
    verbatim = dr_backup._win_verbatim(tmp_path / name)
    head, _, tail = verbatim.rpartition(odd)
    path = f"('' + {dr_backup._ps_literal(head)} + {spelled} + {dr_backup._ps_literal(tail)})"
    assert dr_backup._ps_path(verbatim) == path
    _head(refusal, path)
    assert f"Remove-Item -LiteralPath {path} -Recurse -Force ;" in refusal
    assert dr_backup._split_checks(refusal)[1] == f"Test-Path -LiteralPath {path}"


def test_a_lone_surrogate_in_the_name_is_spelled_and_does_not_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Windows name can hold an unpaired UTF-16 unit, which Python keeps as a lone surrogate
    and strict UTF-16 encoding refuses. Red before the fix: `_ps_path` raised UnicodeEncodeError
    on it, out of the teardown's refusal. It now spells the unit as a .NET string holds it. That
    PowerShell's path layer reaches such a directory is unmeasured; the two-step check reads False
    if it does not, and a False means run nothing."""
    odd = "\udc80"
    name = f"mefor-backup-{odd}."
    refusal = _refusal_for(name, tmp_path, monkeypatch)
    assert refusal.isprintable()
    verbatim = dr_backup._win_verbatim(tmp_path / name)
    head, _, tail = verbatim.rpartition(odd)
    path = f"('' + {dr_backup._ps_literal(head)} + [char]0xDC80 + {dr_backup._ps_literal(tail)})"
    assert dr_backup._ps_path(verbatim) == path
    _head(refusal, path)
    assert f"Remove-Item -LiteralPath {path} -Recurse -Force ;" in refusal
    assert dr_backup._split_checks(refusal)[1] == f"Test-Path -LiteralPath {path}"


def test_a_lone_surrogate_in_the_name_does_not_raise_from_the_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback, for a path that cannot be formed, names the directory through `_ps_path` too,
    outside any guard. Red before the fix: the surrogate raised there, out of a function that must
    never raise."""
    name = "mefor-backup-\udc80."

    def _refuse(path: Path) -> str:
        raise OSError("synthetic: the verbatim path cannot be formed")

    monkeypatch.setattr(dr_backup, "_win_verbatim", _refuse)
    refusal = _refusal_for(name, tmp_path, monkeypatch)
    assert refusal.isprintable()
    assert "it is named ('' + 'mefor-backup-' + [char]0xDC80 + '.')" in refusal
    assert "Remove-Item" not in refusal


def test_a_caller_adds_its_text_before_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before the fix: the callers' text followed the command, on a line of its own, so the
    message held a line break. Any other leftover keeps its separator."""
    name = "mefor-backup-x."
    refusal = _refusal_for(name, tmp_path, monkeypatch)
    literal = dr_backup._ps_literal(dr_backup._win_verbatim(tmp_path / name))
    joined = dr_backup.join_before_checks(refusal, "; ", "the run failed: synthetic")
    assert _head(joined, literal).endswith("no error; the run failed: synthetic")
    plain = "the plaintext staging directory x could not be cleared"
    assert dr_backup.join_before_checks(plain, "; ", "more") == f"{plain}; more"


def test_two_refusals_in_one_message_both_end_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The run's error can carry the verify's refusal after the backup's own. Each check names its
    own path, and nothing but checks follows either."""
    first, second = "mefor-backup-x.", "mefor-verify-y "
    backup = _refusal_for(first, tmp_path, monkeypatch)
    verify = _refusal_for(second, tmp_path, monkeypatch)
    inner = dr_backup.join_before_checks(
        f"restore-verify FAIL: the verify failed, but {verify}", " ", "(kept for diagnosis)"
    )
    joined = dr_backup.join_before_checks(backup, "; ", f"the run failed: {inner}")
    literals = [
        dr_backup._ps_literal(dr_backup._win_verbatim(tmp_path / n)) for n in (first, second)
    ]
    assert _head(joined, *literals).endswith("(kept for diagnosis)")


def test_a_check_written_inside_a_planted_name_is_not_taken_for_the_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A planted name can hold the lead and a check of its own. Only the check that really ends the
    message moves."""
    name = "mefor-backup-x; to check, in PowerShell: Test-Path -LiteralPath 'x'."
    verbatim = "\\\\?\\C:\\root\\" + name
    monkeypatch.setattr(dr_backup, "_win_rewritten", lambda path: True)
    monkeypatch.setattr(dr_backup, "_win_verbatim", lambda path: verbatim)
    refusal = dr_backup._rewritten_staging_refusal(Path("root") / name)
    assert refusal is not None
    joined = dr_backup.join_before_checks(refusal, "; ", "the run failed: synthetic")
    expected = f"no error; the run failed: synthetic{_checks(dr_backup._ps_literal(verbatim))}"
    assert joined.endswith(expected)


async def test_the_kept_for_diagnosis_append_comes_before_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backup's own verify adds `(kept for diagnosis ...)` after the verify's reason, which ends
    in the refusal when the verify's staging survived. Red before the fix: it followed the
    command."""
    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    try:
        name = "mefor-verify-x."
        refusal = _refusal_for(name, tmp_path, monkeypatch)
        literal = dr_backup._ps_literal(dr_backup._win_verbatim(tmp_path / name))

        def failed_verify(**kwargs: Any) -> dr_backup.VerifyResult:
            return dr_backup.VerifyResult("FAIL", reason=f"the verify failed, but {refusal}")

        monkeypatch.setattr(dr_backup, "_verify_archive_blocking", failed_verify)
        monkeypatch.setattr(runner, "_keep_failed_archive", lambda *a: tmp_path / "kept.mfbak")
        with pytest.raises(dr_backup.BackupError) as raised:
            await runner._verify_and_publish(
                tmp_path / "a.mfbak.tmp",
                tmp_path / "a.mfbak",
                key=None,
                staging_root=tmp_path,
                secure=False,
            )
        assert _head(str(raised.value), literal).endswith(
            " (kept for diagnosis as kept.mfbak; it holds no retention slot, and nothing in the "
            "engine expires it)"
        )
    finally:
        await store.close()


async def _build_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raised_error: Exception
) -> tuple[str, str]:
    """The error `_build_in_staging` raises for ``raised_error`` when the release leaves a refusal,
    and the literal that refusal's check names."""
    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    try:
        name = "mefor-backup-x."
        refusal = _refusal_for(name, tmp_path, monkeypatch)
        literal = dr_backup._ps_literal(dr_backup._win_verbatim(tmp_path / name))

        class _Work:
            path = tmp_path / name
            secure = False

            def claim(self) -> bool:
                return True

            def release(self) -> str:
                return refusal

        def refused_build(**kwargs: Any) -> Any:
            raise raised_error

        monkeypatch.setattr(runner, "_build_archive_blocking", refused_build)
        with pytest.raises(dr_backup.BackupError) as raised:
            runner._build_in_staging(
                cast(Any, _Work()),
                out_path=tmp_path / "a.mfbak",
                snap_path=None,
                key=None,
                key_id=None,
                config_only=True,
                now=1.0,
                bundle=cast(Any, None),
            )
        return str(raised.value), literal
    finally:
        await store.close()


@pytest.mark.parametrize(
    ("raised_error", "expected"),
    [
        (
            dr_backup.BackupError("snapshot", "synthetic build refusal"),
            "; the build failed: synthetic build refusal",
        ),
        (OSError("synthetic disk fault"), "; the build failed: OSError: synthetic disk fault"),
    ],
)
async def test_the_build_failed_append_comes_before_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raised_error: Exception, expected: str
) -> None:
    """`_build_in_staging` leads a build's own refusal, and an OSError, with the release's
    leftover. Red before the fix: `; the build failed: ...` followed the command."""
    message, literal = await _build_error(tmp_path, monkeypatch, raised_error)
    assert _head(message, literal).endswith(expected)


async def test_encoded_hl7_a_caller_adds_to_the_refusal_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Synthetic data. A build error that names a percent-encoded field run, joined to the
    release's refusal. Red before the fix: the refusal's line break made the message fail
    `str.isprintable`, so `redact` left the run in it."""
    from messagefoundry.redaction import redact

    encoded = "PID%7C1%7C%7CSMITH%5EJOHN%7C19700101"
    # The control: without the refusal, the run is redacted.
    assert "SMITH%5EJOHN" not in redact(f"the build failed: {encoded}")
    message, _ = await _build_error(
        tmp_path, monkeypatch, dr_backup.BackupError("snapshot", f"synthetic {encoded}")
    )
    assert encoded in message
    assert "SMITH%5EJOHN" not in redact(message)


@pytest.mark.parametrize(
    ("status", "kind", "before"),
    [
        ("KEY_MISMATCH", "key", ") \u2014 env/external KeyProvider required at the DR site"),
        ("FAIL", "seed", " \u2014 refusing to activate against an unverified store"),
    ],
)
async def test_the_cold_seed_abort_adds_its_text_before_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, kind: str, before: str
) -> None:
    """`pipeline/dr.py`'s cold-seed restore-verify aborts add their text after the verify's reason,
    which ends in the refusal when the verify's staging survived. Red before the fix: it followed
    the command."""
    import messagefoundry.pipeline.dr as drmod
    from messagefoundry.config.settings import DrSettings

    name = "mefor-verify-x."
    refusal = _refusal_for(name, tmp_path, monkeypatch)
    literal = dr_backup._ps_literal(dr_backup._win_verbatim(tmp_path / name))

    async def verify(*_a: object, **_k: object) -> dr_backup.VerifyResult:
        return dr_backup.VerifyResult(status, reason=f"the verify failed, but {refusal}")

    monkeypatch.setattr(drmod, "run_restore_verify", verify)
    store = await MessageStore.open(tmp_path / "msg.db")
    try:

        async def noop() -> None:
            return None

        coord = drmod.DrCoordinator(
            store,
            DrSettings(enabled=True),
            store_settings=StoreSettings(path=str(tmp_path / "msg.db")),
            activate_profile=noop,
            deactivate_profile=noop,
        )
        with pytest.raises(drmod.DrActivationError) as raised:
            await coord._verify_seed(str(tmp_path / "seed.mfbak"), "synthetic-actor", 1.0)
        assert raised.value.kind == kind
        head = _head(str(raised.value), literal)
        assert head.index("must print False and no error") < head.index(before)
    finally:
        await store.close()


def test_the_plain_path_ban_survives_the_failure_records_cut_on_the_verify_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failure record and the alert keep the first 200 characters of the backup's verify error,
    which leads with the passing verify's reason. Red before the fix: the path came first, so a
    verbatim path over about 58 characters pushed the ban past the cut."""
    from messagefoundry.redaction import safe_exc

    deep = tmp_path / ("d" * 120)
    deep.mkdir()
    monkeypatch.setattr(dr_backup, "_verify_in_staging", _passing_verify)
    monkeypatch.setattr(dr_backup, "_win_rewritten", lambda path: True)
    result = dr_backup._verify_archive_blocking(
        archive_path=_plaintext_archive(tmp_path), keys=[], full=False, staging_root=deep
    )
    assert result.reason is not None and result.reason.startswith("the archive verified, but ")
    # The backup's own wrapping of a verify that did not pass (`_verify_and_publish`).
    error = dr_backup.BackupError(
        "verify",
        dr_backup.join_before_checks(
            f"restore-verify {result.status}: {result.reason}",
            " ",
            "(kept for diagnosis as synthetic.mfbak; it holds no retention slot, and nothing in "
            "the engine expires it)",
        ),
    )
    assert "never remove it by its plain path" in safe_exc(error)


@_windows_only
def test_the_verbatim_path_of_a_share_takes_the_unc_form() -> None:
    assert (
        dr_backup._win_verbatim(Path("\\\\server\\share\\root\\mefor-backup-x."))
        == "\\\\?\\UNC\\server\\share\\root\\mefor-backup-x."
    )
    assert (
        dr_backup._win_verbatim(Path("\\\\?\\C:\\root\\mefor-backup-x."))
        == "\\\\?\\C:\\root\\mefor-backup-x."
    )


class _ScreenFault(ValueError):
    """What the patched screen raises: no OSError, so a guard that catches only OSError lets it out."""


def _raising_screen(path: Path) -> bool:
    raise _ScreenFault("synthetic screen fault")


def _plaintext_archive(tmp_path: Path) -> str:
    archive = tmp_path / "synthetic.mfbak"
    archive.write_bytes(b"synthetic plaintext archive")
    return str(archive)


def _passing_verify(*args: Any, **kwargs: Any) -> dr_backup.VerifyResult:
    return dr_backup.VerifyResult("PASS")


def _faulting_verify(*args: Any, **kwargs: Any) -> dr_backup.VerifyResult:
    raise RuntimeError("synthetic verify fault")


def test_a_screen_that_raises_does_not_replace_the_verify_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The verify's teardown runs after its verdict, and `release` must never raise over it. Red
    before the fix: the screen at the top of `_discard_verify_staging` sat outside its guard, so
    its fault escaped the verify in place of the verdict."""
    monkeypatch.setattr(dr_backup, "_verify_in_staging", _passing_verify)
    monkeypatch.setattr(dr_backup, "_win_rewritten", _raising_screen)
    result = dr_backup._verify_archive_blocking(
        archive_path=_plaintext_archive(tmp_path), keys=[], full=False, staging_root=tmp_path
    )
    # The verdict survives. A name the screen could not check is not touched, and is named.
    assert result.status == "FAIL"
    assert result.reason is not None and result.reason.startswith("the archive verified, but ")
    (staging,) = tmp_path.glob("mefor-verify-*")
    literal = dr_backup._ps_literal(dr_backup._win_verbatim(staging))
    assert f"; it is {literal} (the engine's screen of its name failed: " in result.reason
    assert "could not be checked" in result.reason
    assert (staging / dr_backup._LOCK_NAME).exists()


def test_a_screen_that_raises_does_not_replace_the_error_in_flight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same screen, while the verify itself is raising. Red before the fix: the screen's fault
    replaced the verify's own exception."""
    monkeypatch.setattr(dr_backup, "_verify_in_staging", _faulting_verify)
    monkeypatch.setattr(dr_backup, "_win_rewritten", _raising_screen)
    with pytest.raises(RuntimeError, match="synthetic verify fault") as raised:
        dr_backup._verify_archive_blocking(
            archive_path=_plaintext_archive(tmp_path), keys=[], full=False, staging_root=tmp_path
        )
    (note,) = raised.value.__notes__
    assert "could not be checked" in note and "by hand" not in note


def test_a_name_whose_screen_raised_is_neither_removed_nor_re_marked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`release` reads a screen fault as a name not to touch: it removes nothing and re-marks
    nothing, since marks by that name may land in another directory. Red before the fix: the
    screen's fault escaped `release`."""
    work = dr_backup._open_staging(tmp_path, "mefor-verify-", secure=False)
    (work.path / "archive.tar").write_bytes(_PLAINTEXT)
    os.remove(work.path / dr_backup._HELD_MARKER_NAME)
    monkeypatch.setattr(dr_backup, "_win_rewritten", _raising_screen)
    leftover = work.release()
    assert leftover is not None and "could not be checked" in leftover
    assert sorted(p.name for p in work.path.iterdir()) == [dr_backup._LOCK_NAME, "archive.tar"]
    assert (work.path / "archive.tar").read_bytes() == _PLAINTEXT


def test_a_verbatim_path_that_cannot_be_formed_still_forbids_the_plain_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fault forming the verbatim path still leaves the refusal standing, never the discard's
    generic "delete it" line, and names no command an operator would have to assemble."""
    staging = tmp_path / "mefor-backup-x"
    staging.mkdir()
    monkeypatch.setattr(dr_backup, "_win_rewritten", lambda path: True)
    monkeypatch.setattr(dr_backup, "_win_verbatim", _raising_screen)
    leftover = dr_backup._teardown_staging(staging)
    assert leftover is not None
    assert leftover.startswith(
        "a plaintext staging directory was not removed or emptied; never remove it by its plain path"
    )
    assert (
        f"; it is named 'mefor-backup-x', in '{tmp_path}', and since its verbatim path" in leftover
    )
    assert "no removal can be named for it here; leave it in place" in leftover
    assert "Remove-Item" not in leftover
    assert "delete it" not in leftover and "by hand" not in leftover
    assert staging.is_dir()
