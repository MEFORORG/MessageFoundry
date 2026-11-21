# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A part swapped for a folder or a socket after its check is damage, not a 500 (BACKLOG #5388,
added item 3).

Synthetic values only. On POSIX the open of a socket answers ``ENXIO``, and ``fdopen`` of a
folder's descriptor ``EISDIR``. ``_refused_read`` answered both ``None``, so the by-id read
re-raised them and the route answered a server error. The swap is forced by raising the error the
open gives, since a real swap races the ``lstat``.
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


@pytest.mark.parametrize("code", [errno.ENXIO, errno.EISDIR])
@pytest.mark.parametrize("part", ["sidecar", "body"])
async def test_a_swapped_part_answers_damaged_on_a_by_id_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int, part: str
) -> None:
    store = UploadStore(tmp_path / "uploads", make_cipher(None), max_bytes=4096)
    meta = await store.save(
        data=b"synthetic diagnostic line\n", filename="a.txt", uploader="op", uploader_id="u-op"
    )
    real = uploads._open_plain
    suffix = ".meta" if part == "sidecar" else ".blob"

    def _swapped(path: Path) -> object:
        if path.name.endswith(suffix):
            raise OSError(code, "synthetic swap", str(path))
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
    def _fails(path: object) -> object:
        raise ValueError("synthetic")

    monkeypatch.setattr(os, "lstat", _fails)
    with caplog.at_level(logging.WARNING, logger=uploads.__name__):
        assert uploads._refused_read(PermissionError(13, "denied", "x.meta")) == "denied"
    assert any("ValueError" in r.getMessage() for r in caplog.records), caplog.records
    assert not any("x.meta" in r.getMessage() for r in caplog.records)
