# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A part that is not a plain file is a handled refusal on every platform (BACKLOG #5388 added
item 3).

On origin/main ``_refused_read`` knew only ``_NotPlainError``, ``ELOOP`` and ``PermissionError``.
A directory swapped in after the check made POSIX ``fdopen`` raise ``IsADirectoryError``, and a
socket made the open raise ``ENXIO``; both were re-raised, so the route answered 500. The lstat
it made on a ``PermissionError`` also swallowed its own failure silently. Synthetic data only."""

from __future__ import annotations

import errno
import logging
import os
import socket
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

import messagefoundry.uploads as uploads
from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry.uploads import UploadDamagedError
from tests._bound_proof import reproving_transport
from tests.test_b532r_uploads_sidecar_reads import _blob, _OsWith, _saved, _sidecar, _store
from tests.test_upload_api import (
    _DAMAGED_TEXT,
    ADT,
    PW,
    _add_user,
    _login,
    _make_user,
    _uploads_settings,
    engine,  # noqa: F401 - the fixture, used by name
)


def _is_a_directory(path: Any) -> OSError:
    # As an fdopen of a directory's descriptor raises it, naming the descriptor, not the path.
    return IsADirectoryError(errno.EISDIR, "Is a directory", 3)


def _no_such_device(path: Any) -> OSError:
    # As Linux answers an open of a socket.
    return OSError(errno.ENXIO, "No such device or address", str(path))


def _refusing(refused: set[Path], error: Any) -> Any:
    """An ``os.open`` that raises ``error(path)`` for a path in ``refused``."""

    def _open(path: Any, flags: int, *args: Any) -> int:
        if Path(path) in refused:
            raise error(path)
        return os.open(path, flags, *args)

    return _open


# --- the classification ---------------------------------------------------------------------------


def test_a_directory_named_by_its_descriptor_is_damage() -> None:
    assert uploads._refused_read(_is_a_directory(None)) == "damaged"


def test_a_socket_refused_at_the_open_is_damage(tmp_path: Path) -> None:
    assert uploads._refused_read(_no_such_device(tmp_path / "x.meta")) == "damaged"


def test_any_refusal_on_a_path_that_is_now_not_a_regular_file_is_damage(tmp_path: Path) -> None:
    # At least BSD answers an open of a socket with EOPNOTSUPP, so the errno alone is not enough.
    folder = tmp_path / "x.meta"
    folder.mkdir()
    exc = OSError(errno.EOPNOTSUPP, "Operation not supported", str(folder))
    assert uploads._refused_read(exc) == "damaged"


def test_a_transient_error_on_a_regular_file_is_still_re_raised(tmp_path: Path) -> None:
    # Control: an I/O error or too many open files may pass on a retry, so it is not a refusal.
    plain = tmp_path / "x.meta"
    plain.write_bytes(b"synthetic")
    assert uploads._refused_read(OSError(errno.EIO, "Input/output error", str(plain))) is None
    assert uploads._refused_read(OSError(errno.EMFILE, "Too many open files")) is None
    assert uploads._refused_read(PermissionError(13, "denied", str(plain))) == "denied"


def test_a_recheck_that_fails_is_logged_not_swallowed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=uploads._log.name)
    for name in (str(tmp_path / "gone.meta"), "bad\0name.meta"):
        caplog.clear()
        assert uploads._refused_read(PermissionError(13, "denied", name)) == "denied"
        assert any("checked again" in r.getMessage() for r in caplog.records), name
    # A descriptor or no name at all is not a path to check, so nothing fails and nothing logs.
    caplog.clear()
    assert uploads._refused_read(PermissionError(13, "denied", 3)) == "denied"
    assert uploads._refused_read(PermissionError(13, "denied")) == "denied"
    assert not caplog.records


# --- the store's by-id reads ----------------------------------------------------------------------


@pytest.mark.parametrize("error", [_is_a_directory, _no_such_device], ids=["eisdir", "enxio"])
async def test_every_by_id_read_refuses_a_part_the_open_says_is_not_plain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Any
) -> None:
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    blob = _blob(store, meta.file_id)
    refused: set[Path] = set()
    monkeypatch.setattr(uploads, "os", _OsWith(_refusing(refused, error)))
    refused.add(blob)
    with pytest.raises(UploadDamagedError):
        await store.read_bytes(meta.file_id)
    refused.add(sidecar)
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)
    with pytest.raises(UploadDamagedError):
        await store.delete(meta.file_id)
    assert sidecar.is_file() and blob.is_file()


async def test_a_directory_swapped_in_after_its_check_is_damage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A real swap. POSIX opens the directory, and on origin/main the fdopen then raised
    # IsADirectoryError; Windows refuses the open with a PermissionError.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    swap: set[Path] = set()

    def _dir_then_open(path: Any, flags: int, *args: Any) -> int:
        target = Path(path)
        if target in swap:
            swap.discard(target)
            target.unlink()
            target.mkdir()
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_dir_then_open))
    swap.add(_blob(store, meta.file_id))
    with pytest.raises(UploadDamagedError):
        await store.read_bytes(meta.file_id)
    swap.add(_sidecar(store, meta.file_id))
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)


@pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(socket, "AF_UNIX"),
    reason="a socket file needs POSIX AF_UNIX",
)
async def test_a_socket_swapped_in_after_its_check_is_damage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    held: list[socket.socket] = []

    def _socket_then_open(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == sidecar and not held:
            sidecar.unlink()
            sock = socket.socket(socket.AF_UNIX)
            held.append(sock)
            # Bound by its relative name, since an AF_UNIX path is short.
            monkeypatch.chdir(sidecar.parent)
            sock.bind(sidecar.name)
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_socket_then_open))
    try:
        with pytest.raises(UploadDamagedError):
            await store.get_meta(meta.file_id)
    finally:
        for sock in held:
            sock.close()


# --- the route ------------------------------------------------------------------------------------


@pytest.mark.parametrize("error", [_is_a_directory, _no_such_device], ids=["eisdir", "enxio"])
async def test_the_route_answers_the_damaged_423_not_a_500(
    engine: Engine,  # noqa: F811 - the imported fixture
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Any,
) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    await _add_user(service, Role.ADMINISTRATOR, name="root")
    root = tmp_path / "uploads"
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = reproving_transport(PW, app=app)
    refused: set[Path] = set()
    monkeypatch.setattr(uploads, "os", _OsWith(_refusing(refused, error)))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        ha = await _login(c, "root")
        body_fid = (
            await c.post("/uploads", files={"file": ("x.hl7", ADT, "text/plain")}, headers=h)
        ).json()["file_id"]
        meta_fid = (
            await c.post("/uploads", files={"file": ("y.hl7", ADT, "text/plain")}, headers=h)
        ).json()["file_id"]
        refused.update({root / f"{body_fid}.blob", root / f"{meta_fid}.meta"})
        # The body reaches its owner as the damaged 423.
        r = await c.get(f"/uploads/{body_fid}/messages", headers=h)
        assert r.status_code == 423, r.text
        assert r.json()["detail"] == _DAMAGED_TEXT
        # A sidecar hides its owner, so the override holder gets the 423, on browse and delete.
        for r in (
            await c.get(f"/uploads/{meta_fid}/messages", headers=ha),
            await c.delete(f"/uploads/{meta_fid}", headers=ha),
        ):
            assert r.status_code == 423, r.text
            assert r.json()["detail"] == _DAMAGED_TEXT
    assert (root / f"{meta_fid}.meta").exists() and (root / f"{meta_fid}.blob").exists()
