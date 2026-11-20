# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A part that is not a plain file is a handled refusal on every platform (BACKLOG #5388 added
item 3).

On origin/main 9421dcbf27 ``_refused_read`` knew only ``_NotPlainError``, ``ELOOP`` and
``PermissionError``. A directory swapped in after the check made POSIX ``fdopen`` raise
``IsADirectoryError``, and a socket made the open raise ``ENXIO`` (``EOPNOTSUPP`` on the BSDs);
both were re-raised, so the route answered 500. The lstat it made on a ``PermissionError`` also
swallowed its own failure silently. Synthetic data only."""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import socket
import sys
from collections.abc import Iterator
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
    # Defensive only: an fdopen of a directory's descriptor raises this, naming the descriptor,
    # and _open_plain now refuses a directory before its fdopen.
    return IsADirectoryError(errno.EISDIR, "Is a directory", 3)


def _no_such_device(path: Any) -> OSError:
    # As Linux answers an open of a socket.
    return OSError(errno.ENXIO, "No such device or address", str(path))


def _not_supported(path: Any) -> OSError:
    # As macOS and the BSDs answer an open of a socket.
    return OSError(errno.EOPNOTSUPP, "Operation not supported", str(path))


def _not_found(path: Any) -> OSError:
    # As Windows answers an open that followed a dangling link.
    return FileNotFoundError(errno.ENOENT, "No such file or directory", str(path))


_OPEN_ERRORS = pytest.mark.parametrize(
    "error", [_no_such_device, _not_supported, _not_found], ids=["enxio", "eopnotsupp", "enoent"]
)


def _swapping(refused: set[Path], error: Any) -> Any:
    """An ``os.open`` that, for a path in ``refused``, puts a directory in the file's place, as a
    swap after the check would, then raises ``error(path)``, as the platform's open would for a
    part that is not a plain file. A directory stands in for the socket or link, since every
    platform can make one."""

    def _open(path: Any, flags: int, *args: Any) -> int:
        target = Path(path)
        if target in refused:
            if target.is_file():
                target.unlink()
                target.mkdir()
            raise error(path)
        return os.open(path, flags, *args)

    return _open


# --- the classification ---------------------------------------------------------------------------


def test_a_not_a_file_errno_decides_only_when_the_path_cannot_be_checked(tmp_path: Path) -> None:
    assert uploads._refused_read(_is_a_directory(None)) == "damaged"
    assert uploads._refused_read(_no_such_device(tmp_path / "gone.meta")) == "damaged"
    # A regular file answered ENXIO for some other reason is not called damaged.
    plain = tmp_path / "x.meta"
    plain.write_bytes(b"synthetic")
    assert uploads._refused_read(_no_such_device(plain)) is None


def test_any_refusal_on_a_path_that_is_now_not_a_regular_file_is_damage(tmp_path: Path) -> None:
    folder = tmp_path / "x.meta"
    folder.mkdir()
    assert uploads._refused_read(_not_supported(folder)) == "damaged"
    assert uploads._refused_read(OSError(errno.EIO, "Input/output error", str(folder))) == "damaged"
    link = tmp_path / "y.meta"
    try:
        link.symlink_to(tmp_path / "elsewhere")
    except OSError:
        pytest.skip("this account cannot create a symbolic link")
    assert uploads._refused_read(OSError(errno.EIO, "Input/output error", str(link))) == "damaged"


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
    assert uploads._refused_read(PermissionError(13, "denied", "bad\0name.meta")) == "denied"
    assert any("checked again" in r.getMessage() for r in caplog.records)
    # A part that is gone, a descriptor, or no name at all is not a failed check, so none logs.
    caplog.clear()
    assert uploads._refused_read(PermissionError(13, "denied", str(tmp_path / "gone"))) == "denied"
    assert uploads._refused_read(PermissionError(13, "denied", 3)) == "denied"
    assert uploads._refused_read(PermissionError(13, "denied")) == "denied"
    assert not caplog.records


# --- the store's by-id reads ----------------------------------------------------------------------


@_OPEN_ERRORS
async def test_every_by_id_read_refuses_a_part_swapped_after_its_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Any
) -> None:
    store = _store(tmp_path / "uploads")
    refused: set[Path] = set()
    monkeypatch.setattr(uploads, "os", _OsWith(_swapping(refused, error)))
    # Control: under the patched open, a sound upload still reads.
    sound = await _saved(store)
    assert await store.get_meta(sound.file_id) == sound
    assert await store.read_bytes(sound.file_id)
    body = await _saved(store)
    meta = await _saved(store)
    gone = await _saved(store)
    refused.update(
        {_blob(store, body.file_id), _sidecar(store, meta.file_id), _sidecar(store, gone.file_id)}
    )
    with pytest.raises(UploadDamagedError):
        await store.read_bytes(body.file_id)
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)
    with pytest.raises(UploadDamagedError):
        await store.delete(gone.file_id)
    assert _blob(store, gone.file_id).is_file()


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


async def test_a_dangling_link_swapped_in_after_its_check_is_damage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows follows the link, so on origin/main its open answered FileNotFoundError and the
    # read said the upload was not there; POSIX refuses it with ELOOP.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    probe = tmp_path / "probe"
    try:
        probe.symlink_to(tmp_path / "nowhere")
    except OSError:
        pytest.skip("this account cannot create a symbolic link")

    def _link_then_open(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == sidecar and sidecar.is_file():
            sidecar.unlink()
            sidecar.symlink_to(tmp_path / "nowhere")
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_link_then_open))
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)


async def test_a_directory_swapped_in_for_the_body_before_the_delete_unlinks_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    blob = _blob(store, meta.file_id)
    real = uploads._pair_lock

    @contextlib.contextmanager
    def _swap_then_lock(path: Path, **kwargs: Any) -> Iterator[None]:
        blob.unlink()
        blob.mkdir()
        with real(path, **kwargs):
            yield

    monkeypatch.setattr(uploads, "_pair_lock", _swap_then_lock)
    with pytest.raises(UploadDamagedError):
        await store.delete(meta.file_id)
    assert blob.is_dir() and _sidecar(store, meta.file_id).is_file()


@pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(socket, "AF_UNIX"),
    reason="a socket file needs POSIX AF_UNIX",
)
@pytest.mark.parametrize("read", ["get_meta", "read_bytes", "delete"])
async def test_a_socket_swapped_in_after_its_check_is_damage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    part = _blob(store, meta.file_id) if read == "read_bytes" else _sidecar(store, meta.file_id)
    held: list[socket.socket] = []

    def _socket_then_open(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == part and not held:
            part.unlink()
            sock = socket.socket(socket.AF_UNIX)
            held.append(sock)
            # Bound by its relative name, since an AF_UNIX path is short.
            monkeypatch.chdir(part.parent)
            sock.bind(part.name)
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_socket_then_open))
    try:
        with pytest.raises(UploadDamagedError):
            await getattr(store, read)(meta.file_id)
    finally:
        for sock in held:
            sock.close()


# --- the route ------------------------------------------------------------------------------------


@_OPEN_ERRORS
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
    monkeypatch.setattr(uploads, "os", _OsWith(_swapping(refused, error)))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        ha = await _login(c, "root")
        body_fid = (
            await c.post("/uploads", files={"file": ("x.hl7", ADT, "text/plain")}, headers=h)
        ).json()["file_id"]
        meta_fids = [
            (await c.post("/uploads", files={"file": (n, ADT, "text/plain")}, headers=h)).json()[
                "file_id"
            ]
            for n in ("y.hl7", "z.hl7")
        ]
        refused.add(root / f"{body_fid}.blob")
        refused.update(root / f"{fid}.meta" for fid in meta_fids)
        # The body reaches its owner as the damaged 423.
        r = await c.get(f"/uploads/{body_fid}/messages", headers=h)
        assert r.status_code == 423, r.text
        assert r.json()["detail"] == _DAMAGED_TEXT
        # A sidecar hides its owner, so the override holder gets the 423, on browse and delete,
        # each meeting the swap at its own open.
        for r in (
            await c.get(f"/uploads/{meta_fids[0]}/messages", headers=ha),
            await c.delete(f"/uploads/{meta_fids[1]}", headers=ha),
        ):
            assert r.status_code == 423, r.text
            assert r.json()["detail"] == _DAMAGED_TEXT
    assert (root / f"{meta_fids[1]}.meta").exists() and (root / f"{meta_fids[1]}.blob").is_file()
