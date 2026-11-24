# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A part swapped for a folder or a socket after its check is damage, not a 500 (BACKLOG #5388,
added item 3).

Synthetic values only. On POSIX the open of a socket answers ``ENXIO``, and ``fdopen`` of a
folder's descriptor ``EISDIR``. ``_refused_read`` answers an error whose path a fresh ``lstat``
shows is not a regular file as damage, and one that names no path by its errno alone, through
``_NOT_A_FILE``, so the by-id read raises ``UploadDamagedError`` rather than re-raising either. The
swap is forced by raising the error the open gives, since a real swap races the ``lstat``; the
socket case raises one naming no path, which the real open never does, to pin that errno verdict.
"""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

import pytest

import messagefoundry.uploads as uploads
from messagefoundry.store.crypto import make_cipher
from messagefoundry.uploads import UploadDamagedError, UploadStore


@pytest.mark.parametrize(
    "exc",
    [
        OSError(errno.ENXIO, "No such device or address"),
        IsADirectoryError(errno.EISDIR, "Is a directory"),
        OSError(errno.ELOOP, "Too many levels of symbolic links"),
    ],
    ids=["socket", "folder", "link"],
)
def test_a_folder_or_a_socket_swapped_in_is_damage(exc: OSError) -> None:
    assert uploads._refused_read(exc) == "damaged"


@pytest.mark.parametrize("code", [errno.EMFILE, errno.EIO])
def test_a_retryable_error_is_still_re_raised(code: int) -> None:
    """Control: an error a retry may clear is still the caller's to re-raise."""
    assert uploads._refused_read(OSError(code, "synthetic")) is None


@pytest.mark.parametrize("swap", ["folder", "socket"])
@pytest.mark.parametrize("part", ["sidecar", "body"])
async def test_a_swapped_part_answers_damaged_on_a_by_id_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap: str, part: str
) -> None:
    store = UploadStore(tmp_path / "uploads", make_cipher(None), max_bytes=4096)
    meta = await store.save(
        data=b"synthetic diagnostic line\n", filename="a.txt", uploader="op", uploader_id="u-op"
    )
    real = uploads._open_plain
    suffix = ".meta" if part == "sidecar" else ".blob"

    def _swapped(path: Path) -> object:
        if path.name.endswith(suffix):
            if swap == "socket":
                # A socket's ENXIO that names no path, so no fresh lstat is made and the errno
                # alone decides (``uploads._NOT_A_FILE``); the part is left as it is, since
                # nothing reads it. A real socket's open names the path, and its re-check would
                # answer damage whatever the errno, so this pins only the errno's verdict; it also
                # runs where a socket cannot be made, as on Windows.
                raise OSError(errno.ENXIO, "synthetic swap")
            # The part really is a folder now, as a fresh lstat reads it (``uploads._recheck``):
            # an error naming a part that is still a regular file is not damage.
            path.unlink()
            path.mkdir()
            raise IsADirectoryError(errno.EISDIR, "synthetic swap", str(path))
        return real(path)

    monkeypatch.setattr(uploads, "_open_plain", _swapped)
    with pytest.raises(UploadDamagedError):
        if part == "sidecar":
            await store.get_meta(meta.file_id)
        else:
            await store.read_bytes(meta.file_id)


def test_a_failed_folder_check_is_logged_not_swallowed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class _OsWithAFailingLstat:
        """The ``os`` the uploads module reads, with only its ``lstat`` failing, so no other
        module's ``os.lstat`` is patched."""

        def __getattr__(self, name: str) -> object:
            return getattr(os, name)

        @staticmethod
        def lstat(path: object) -> object:
            raise ValueError("synthetic")

    monkeypatch.setattr(uploads, "os", _OsWithAFailingLstat())
    with caplog.at_level(logging.DEBUG, logger=uploads.__name__):
        assert uploads._refused_read(PermissionError(13, "denied", "x.meta")) == "denied"
    assert any("synthetic" in r.getMessage() for r in caplog.records), caplog.records
