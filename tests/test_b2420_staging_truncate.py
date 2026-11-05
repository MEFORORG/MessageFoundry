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
_REWRITTEN = "(a name Windows opens as another object, not {})"
_GONE = "(moved or removed before it was emptied, not truncated)"


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
    assert unproven == [f"{name} {_REWRITTEN.format('truncated')}"]
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
    assert unproven == [f"sub./ {_REWRITTEN.format('walked')}"]
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
    assert unproven == [f"mefor-backup-x./ {_REWRITTEN.format('walked')}"]
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
