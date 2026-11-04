# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4988 and #4989, two DR staging gaps engine PR 2675 named.

#4988: the backup's early sweep of its staging root went by the process's own owner. On a share
whose server sets the owner, a directory there carrying the process's owner may have been made by
another principal, and the sweep would have removed it, while docs/PHI.md said every sweep takes
only what a new directory of the run's account gets. The early sweep now goes by the owner a bare
probe directory in the staging root gets.

#4989: an entry whose ``is_dir`` raised was listed as a file, so a directory the walk could not type
was never walked, the fail-safe's ``lstat`` found no regular file, and the teardown logged that every
file was emptied and raised no cleanup alert. Such a directory is now reported as not walked.

Every test uses synthetic bytes only. Severity is conditional (CLAUDE.md section 0)."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.pipeline import dr_backup
from tests.test_b2420_staging_truncate import (
    _abandoned,
    _link_dir,
    _store_and_runner,
)

# --- #4988: the early sweep goes by the owner a directory in the staging root gets ---------------


def _server_owner_share(
    data: Path, monkeypatch: pytest.MonkeyPatch, *, made_by_another: Path
) -> None:
    """A server-owner stand-in: what this process makes under ``data`` reports the share's owner.
    ``made_by_another`` is a directory another principal made there that carries the owner this
    process's own directories get elsewhere, as SYSTEM on the file server can."""
    real_owner = dr_backup._owner_of

    def owner(path: Path) -> object | None:
        p = Path(path).absolute()
        if p == made_by_another:
            return real_owner(path)
        if p != data and p.is_relative_to(data):
            return "share-owner"
        return real_owner(path)

    monkeypatch.setattr(dr_backup, "_owner_of", owner)


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
    _server_owner_share(data, monkeypatch, made_by_another=other)
    real_open = dr_backup._open_staging
    ours_at_open: list[bool] = []

    def open_after_the_sweep(root: Path, prefix: str, *, secure: bool):
        ours_at_open.append(ours.exists())
        return real_open(root, prefix, secure=secure)

    monkeypatch.setattr(dr_backup, "_open_staging", open_after_the_sweep)
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


async def test_a_failed_staging_root_probe_does_not_fall_back_to_the_process_owner(
    tmp_path, monkeypatch
) -> None:
    """When the probe in the staging root answers None, the early sweep is off rather than keyed on
    the process's owner. This run's own directory's owner still sweeps once it is open."""
    store, runner = await _store_and_runner(tmp_path, monkeypatch)
    data = (tmp_path / "data").absolute()
    dead = _abandoned(data, "mefor-backup-")
    real_probe = dr_backup._probe_owner

    def no_answer_in_data(root: Path | None) -> object | None:
        return None if root is not None and Path(root).absolute() == data else real_probe(root)

    monkeypatch.setattr(dr_backup, "_probe_owner", no_answer_in_data)
    real_open = dr_backup._open_staging
    dead_at_open: list[bool] = []

    def recording_open(root: Path, prefix: str, *, secure: bool):
        dead_at_open.append(dead.exists())
        return real_open(root, prefix, secure=secure)

    monkeypatch.setattr(dr_backup, "_open_staging", recording_open)
    try:
        result = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert result is not None
    assert dead_at_open[0] is True
    assert not dead.exists()  # swept by this run's own directory's owner


# --- #4989: a directory the walk took for a file is reported ------------------------------------


def _untyped_subdir(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """The seam for an ``is_dir`` that raised: the walk lists directory ``name`` among the files,
    and so never descends into it."""
    real_walk = dr_backup._walk

    def walk(top: Path, **kwargs: Any) -> Iterator[Any]:
        for step in real_walk(top, **kwargs):
            dirs, files = step[1], step[2]
            if name in dirs:
                dirs.remove(name)  # in place, so neither walk descends
                files.append(name)
            yield step

    monkeypatch.setattr(dr_backup, "_walk", walk)


def test_a_directory_the_walk_lists_as_a_file_is_reported(tmp_path, monkeypatch) -> None:
    staging = tmp_path / "mefor-backup-own"
    (staging / "sub").mkdir(parents=True)
    (staging / "sub" / "inner.tar").write_bytes(b"synthetic plaintext")
    (staging / "own.tar").write_bytes(b"synthetic plaintext")
    _untyped_subdir(monkeypatch, "sub")
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
    staging = tmp_path / "mefor-backup-own"
    (staging / "sub").mkdir(parents=True)
    (staging / "sub" / "inner.tar").write_bytes(b"synthetic plaintext")
    _untyped_subdir(monkeypatch, "sub")
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
