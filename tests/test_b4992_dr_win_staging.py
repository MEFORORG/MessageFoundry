# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4992: the Windows half of the DR staging truncate fail-safe (BACKLOG #2420).

Before this item it kept its own ctypes helpers beside ``transports/file.py``'s, and they had drifted:

- it opened a directory, read its final path and CLOSED it again before opening that directory's
  files by path, so a local account able to rename entries there had a window to swap the directory
  for a junction;
- it reopened a reparse point that names no path (a cloud, deduplicated or tiered file) through its
  filter, which can recall or hydrate it, before checking it was a regular file with one link;
- it read error 1, 50 or 87 from ANY call as "cannot report a file's final path", and named the
  staging root for a subdirectory that failed.

Every test here is Windows-only: the code under test runs only there. Synthetic bytes only."""

from __future__ import annotations

import ctypes
import logging
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.pipeline import dr_backup
from messagefoundry.transports import file as file_mod

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="the Windows fail-safe path")

_OUTSIDE = b"not the engine's to empty"
_PLAINTEXT = b"synthetic plaintext"
_DEDUP_TAG = 0x80000013  # IO_REPARSE_TAG_DEDUP: a reparse tag with no name-surrogate bit


def _junction(target: Path, link: Path) -> None:
    if sys.platform == "win32":  # narrows mypy; every test here is Windows-only
        import _winapi

        _winapi.CreateJunction(str(target), str(link))


@pytest.mark.parametrize("swap", ["sub", "root"])
def test_a_directory_cannot_be_swapped_while_its_files_are_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap: str
) -> None:
    """Each directory, and the staging root, stays held from its check until its files are emptied.

    Red before the fix: the check closed its handle, so the rename succeeded, a junction to an
    outside tree took the directory's place, and the file was opened through it (the final-path
    check then caught it, reported as something reached through a link)."""
    staging = tmp_path / "mefor-verify-own"
    (staging / "sub").mkdir(parents=True)
    (staging / "top.tar").write_bytes(_PLAINTEXT)
    (staging / "sub" / "inner.tar").write_bytes(_PLAINTEXT)
    # The tree a junction in place of the swapped directory would lead to.
    outside = tmp_path / "outside"
    (outside / "sub").mkdir(parents=True)
    (outside / "top.tar").write_bytes(_OUTSIDE)
    (outside / "sub" / "inner.tar").write_bytes(_OUTSIDE)
    victim = staging / "sub" if swap == "sub" else staging
    lead = outside / "sub" if swap == "sub" else outside
    # The root is swapped while its OWN file is opened, when no directory below it is held: a held
    # subdirectory alone already stops a rename of the root.
    trigger = "inner.tar" if swap == "sub" else "top.tar"
    renamed: list[bool] = []
    real_open = dr_backup._open_unfollowed

    def swap_then_open(entry: Path, dir_fd: int | None) -> int:
        if entry.name == trigger and not renamed:
            try:
                os.rename(victim, tmp_path / "moved")
            except PermissionError:
                renamed.append(False)
            else:
                _junction(lead, victim)
                renamed.append(True)
        return real_open(entry, dir_fd)

    monkeypatch.setattr(dr_backup, "_open_unfollowed", swap_then_open)
    unproven = dr_backup._empty_files_in_place(staging)
    assert renamed == [False], "the directory could be renamed while its file was being opened"
    assert (outside / "top.tar").read_bytes() == _OUTSIDE
    assert (outside / "sub" / "inner.tar").read_bytes() == _OUTSIDE
    assert (staging / "top.tar").read_bytes() == b""
    assert (staging / "sub" / "inner.tar").read_bytes() == b""
    assert unproven == []


def test_a_staged_file_is_screened_without_opening_it_through_a_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``os.lstat`` opens a cloud, deduplicated or tiered file through its filter, so the screen
    before the open uses the file connector's as-itself stat instead.

    Red before the fix: every staged file was ``os.lstat``-ed by name."""
    staging = tmp_path / "mefor-verify-own"
    (staging / "sub").mkdir(parents=True)
    names = {"top.tar", "inner.db"}
    (staging / "top.tar").write_bytes(_PLAINTEXT)
    (staging / "sub" / "inner.db").write_bytes(_PLAINTEXT)
    real_lstat = os.lstat
    screened: list[str] = []

    def recording(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if Path(path).name in names:
            screened.append(Path(path).name)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", recording)
    assert dr_backup._empty_files_in_place(staging) == []
    assert screened == []
    assert (staging / "top.tar").read_bytes() == b""
    assert (staging / "sub" / "inner.db").read_bytes() == b""


def test_a_cloud_file_is_checked_before_its_filter_is_let_serve_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reparse point that names no path is opened again so its filter serves it, which can recall
    or hydrate it. That reopen now comes only after the file opened as itself is shown to be a regular
    file with one link, so a hard link to someone else's cloud file is refused unopened.

    Every file here is made to look deduplicated. The control: the staging directory's own file is
    still reopened through its filter, and emptied. The attribute tag is read once per open."""
    staging = tmp_path / "mefor-verify-own"
    staging.mkdir()
    own = staging / "own.tar"
    own.write_bytes(_PLAINTEXT)
    swapped = staging / "swap.dat"
    swapped.write_bytes(b"synthetic")
    outside = tmp_path / "outside.dat"
    outside.write_bytes(_OUTSIDE)

    real_tag = file_mod._attribute_tag
    file_tag_reads: list[int] = []

    def deduplicated(handle: int) -> tuple[int, int]:
        attributes, tag = real_tag(handle)
        if attributes & stat.FILE_ATTRIBUTE_DIRECTORY:
            return attributes, tag
        file_tag_reads.append(handle)
        return attributes | stat.FILE_ATTRIBUTE_REPARSE_POINT, _DEDUP_TAG

    real_create = file_mod._win_create
    reopened: list[str] = []

    def recording(path: Path, access: int, share: int, flags: int) -> int:
        if flags == 0:  # the open that lets a filter act
            reopened.append(Path(path).name)
        return real_create(path, access, share, flags)

    real_open = dr_backup._open_unfollowed

    def link_then_open(entry: Path, dir_fd: int | None) -> int:
        # After the lstat that would have refused it, the name becomes a second link to a file
        # outside the directory.
        if entry.name == swapped.name:
            os.unlink(swapped)
            os.link(outside, swapped)
        return real_open(entry, dir_fd)

    monkeypatch.setattr(file_mod, "_attribute_tag", deduplicated)
    monkeypatch.setattr(file_mod, "_win_create", recording)
    monkeypatch.setattr(dr_backup, "_open_unfollowed", link_then_open)
    unproven = dr_backup._empty_files_in_place(staging)
    assert unproven == ["swap.dat (hard-linked, not truncated)"]
    assert outside.read_bytes() == _OUTSIDE
    assert reopened == ["own.tar"], "a file the check refuses was opened through its filter"
    assert own.read_bytes() == b""
    # One per open, not one per check: the as-itself screen and the open, for each of two files.
    assert len(file_tag_reads) == 4


def _refuse_open(monkeypatch: pytest.MonkeyPatch, refused: Path, code: int) -> None:
    """``CreateFileW`` on ``refused`` fails with the Win32 error ``code``; every other open is real."""
    real_create = file_mod._win_create

    def refusing(path: Path, access: int, share: int, flags: int) -> int:
        if Path(path) == refused:
            raise ctypes.WinError(code)  # type: ignore[attr-defined]
        return real_create(path, access, share, flags)

    monkeypatch.setattr(file_mod, "_win_create", refusing)


@pytest.mark.parametrize("code", [1, 50, 87])
def test_an_open_failing_with_a_volume_code_is_not_read_as_a_volume_without_final_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, code: int
) -> None:
    """Error 1, 50 or 87 from the OPEN of the staging root says nothing about final paths. It is
    logged as itself, and the volume warning stays for a failed final-path query alone.

    Red before the fix: any OSError with one of those codes logged that the volume cannot report a
    file's final path."""
    staging = tmp_path / "mefor-verify-own"
    staging.mkdir()
    (staging / "extracted_store.db").write_bytes(_PLAINTEXT)
    _refuse_open(monkeypatch, staging, code)
    with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
        unproven = dr_backup._empty_files_in_place(staging)
    assert unproven == ["mefor-verify-own/ (not listed)"]
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert not any("cannot report a file's final path" in m for m in warnings)
    assert any("could not open or list" in m and f"WinError {code}" in m for m in warnings)
    assert not any("extracted_store.db" in m for m in warnings)


def test_a_subdirectory_that_cannot_be_opened_is_named_not_the_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A subdirectory whose open fails is reported by its own name. The root's own file is still
    emptied, and the refused subdirectory's file is left as it was, never emptied by path.

    Red before the fix: the error carried no file name, so the report named the staging root."""
    staging = tmp_path / "mefor-verify-own"
    (staging / "config").mkdir(parents=True)
    (staging / "top.tar").write_bytes(_PLAINTEXT)
    (staging / "config" / "inner.toml").write_bytes(_PLAINTEXT)
    _refuse_open(monkeypatch, staging / "config", 5)  # ERROR_ACCESS_DENIED
    with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
        unproven = dr_backup._empty_files_in_place(staging)
    assert unproven == ["config/ (not listed)"]
    assert (staging / "top.tar").read_bytes() == b""
    assert (staging / "config" / "inner.toml").read_bytes() == _PLAINTEXT
    assert any("WinError 5" in r.getMessage() for r in caplog.records)


def test_a_failed_final_path_query_still_reads_as_the_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The control for the two tests above: the same code from the final-path query itself still
    means a volume that cannot report one, and nothing is emptied there."""
    staging = tmp_path / "mefor-verify-own"
    staging.mkdir()
    (staging / "extracted_store.db").write_bytes(_PLAINTEXT)

    def unsupported(handle: int) -> str:
        raise ctypes.WinError(87)  # type: ignore[attr-defined]

    monkeypatch.setattr(dr_backup, "_win_final_path", unsupported)
    with caplog.at_level(logging.WARNING, logger=dr_backup.__name__):
        unproven = dr_backup._empty_files_in_place(staging)
    assert unproven == ["mefor-verify-own/ (not listed)"]
    assert (staging / "extracted_store.db").read_bytes() == _PLAINTEXT
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("cannot report a file's final path" in m for m in warnings)


def test_a_link_already_in_the_directory_is_skipped_not_reported(tmp_path: Path) -> None:
    """A link holds no plaintext, so the fail-safe skips it without a report, as ``os.lstat`` let it.
    The screen that replaced ``os.lstat`` reads the reparse tag itself: ``os.fstat`` on a symlink
    opened as itself calls it a regular file, and the link was then reported as a swap."""
    staging = tmp_path / "mefor-verify-own"
    staging.mkdir()
    outside = tmp_path / "outside.dat"
    outside.write_bytes(_OUTSIDE)
    (staging / "own.tar").write_bytes(_PLAINTEXT)
    try:
        (staging / "link.dat").symlink_to(outside)
    except OSError as exc:  # pragma: no cover - Windows without the symlink privilege
        pytest.skip(f"symlinks unavailable here: {exc}")
    assert dr_backup._empty_files_in_place(staging) == []
    assert outside.read_bytes() == _OUTSIDE
    assert (staging / "own.tar").read_bytes() == b""
