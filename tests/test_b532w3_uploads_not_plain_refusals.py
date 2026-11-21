# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A part that is not a plain file is a handled refusal, for at least the kinds these tests
plant, on every platform (BACKLOG #5388 added item 3).

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
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import messagefoundry.uploads as uploads
from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry.uploads import UploadAccessError, UploadDamagedError
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


def test_a_not_a_file_errno_decides_only_when_the_error_names_no_path(tmp_path: Path) -> None:
    assert uploads._refused_read(_is_a_directory(None)) == "damaged"
    # A part that is gone by the re-check is not called damaged: its absence is the caller's to
    # report (r3, finding 3; on 52c0fdef3ca this answered "damaged").
    assert uploads._refused_read(_no_such_device(tmp_path / "gone.meta")) is None
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


async def test_a_directory_swapped_in_for_the_sidecar_is_refused_before_the_body_goes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Before the fix the body was unlinked first, then the sidecar's unlink raised a raw OSError:
    # a 500, with the body already gone.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    real = uploads._pair_lock

    @contextlib.contextmanager
    def _swap_then_lock(path: Path, **kwargs: Any) -> Iterator[None]:
        sidecar.unlink()
        sidecar.mkdir()
        with real(path, **kwargs):
            yield

    monkeypatch.setattr(uploads, "_pair_lock", _swap_then_lock)
    with pytest.raises(UploadDamagedError):
        await store.delete(meta.file_id)
    assert sidecar.is_dir() and _blob(store, meta.file_id).is_file()


@pytest.mark.parametrize("error", ["denied", "eio"])
async def test_a_body_unlink_that_fails_on_a_file_is_not_damage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: str
) -> None:
    # Control: only a directory is answered as damage. A permission on the body is the
    # access-refused answer a read gives, and any other failure is raised as it is; neither is a
    # file an operator should delete. A Windows sharing violation is the incomplete delete instead
    # (tests/test_b532w3_uploads_delete_incomplete.py).
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    blob = _blob(store, meta.file_id)
    real_unlink = Path.unlink

    def _unlink(self: Path, missing_ok: bool = False) -> None:
        if self == blob:
            if error == "denied":
                raise PermissionError(errno.EACCES, "Permission denied", str(self))
            raise OSError(errno.EIO, "Input/output error", str(self))
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", _unlink)
    if error == "denied":
        with pytest.raises(UploadAccessError):
            await store.delete(meta.file_id)
    else:
        with pytest.raises(OSError) as raised:
            await store.delete(meta.file_id)
        assert raised.value.errno == errno.EIO
    assert blob.is_file() and _sidecar(store, meta.file_id).is_file()


async def test_a_sidecar_unlink_that_fails_after_the_body_went_is_no_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # On 433f9d36ce0 the body was gone and the sidecar's failure raised a raw OSError: a 500 with
    # no audit row. On 52c0fdef3ca the delete was returned as a success while the upload stayed
    # listed (r3, finding 9). Now the unlink is tried again, then the delete raises the
    # incomplete error carrying the metadata, so the route records the row and answers a retry.
    caplog.set_level(logging.WARNING, logger=uploads._log.name)
    from tests.test_b532w3_uploads_delete_incomplete import _failing_unlink, _sharing_violation

    monkeypatch.setattr(uploads, "_UNLINK_PAUSE", 0.0)
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    real_unlink = Path.unlink
    tries = _failing_unlink(monkeypatch, sidecar, _sharing_violation)
    with pytest.raises(uploads.UploadDeleteIncompleteError) as raised:
        await store.delete(meta.file_id)
    assert raised.value.removed == meta
    assert len(tries) == uploads._UNLINK_ATTEMPTS
    assert not _blob(store, meta.file_id).exists() and sidecar.is_file()
    assert any("delete it again" in r.getMessage() for r in caplog.records)
    # What is on disk is what the store reports: the upload is still listed, and a retry, once the
    # sidecar can go, finishes the delete.
    assert [m.file_id for m in await store.list_files()] == [meta.file_id]
    monkeypatch.setattr(Path, "unlink", real_unlink)
    await store.delete(meta.file_id)
    assert not sidecar.exists() and not await store.list_files()


@pytest.mark.parametrize("read", ["get_meta", "read_bytes"])
async def test_a_transient_open_error_on_a_regular_part_is_re_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    # Control: _open_plain converts a refused open only when the name is now not a plain file.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    part = _blob(store, meta.file_id) if read == "read_bytes" else _sidecar(store, meta.file_id)

    def _eio(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == part:
            raise OSError(errno.EIO, "Input/output error", str(path))
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_eio))
    with pytest.raises(OSError) as raised:
        await getattr(store, read)(meta.file_id)
    assert raised.value.errno == errno.EIO


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


# --- a Windows AF_UNIX socket ---------------------------------------------------------------------

# What Windows reports for an AF_UNIX socket file, as measured on Windows 11: an lstat st_mode
# of a regular file, the reparse-point attribute, and the AF_UNIX reparse tag. Its open then
# fails with EINVAL. Before the fix that read as a regular file refusing for a transient
# reason, so the route answered 500.
_WINDOWS_SOCKET_STAT = SimpleNamespace(
    st_mode=0o100666, st_file_attributes=0x420, st_reparse_tag=0x80000023
)


def test_a_windows_socket_stat_is_not_a_regular_file() -> None:
    socket_stat: Any = _WINDOWS_SOCKET_STAT
    assert not uploads._is_regular(socket_stat)
    # An app execution alias, as %LOCALAPPDATA%\Microsoft\WindowsApps holds, is refused the same
    # way, as are the device and FIFO files WSL makes.
    for tag in (0x8000001B, 0x80000024, 0x80000025, 0x80000026):
        alias: Any = SimpleNamespace(st_mode=0o100777, st_file_attributes=0x420, st_reparse_tag=tag)
        assert not uploads._is_regular(alias)
    # Controls: a plain file, and a reparse point of another kind, such as a cloud placeholder.
    plain: Any = SimpleNamespace(st_mode=0o100666, st_file_attributes=0x20, st_reparse_tag=0)
    cloud: Any = SimpleNamespace(
        st_mode=0o100666, st_file_attributes=0x420, st_reparse_tag=0x9000001A
    )
    assert uploads._is_regular(plain) and uploads._is_regular(cloud)


class _OsWithSocket(_OsWith):
    """``_OsWith``, where a path in ``sockets`` lstats as a Windows AF_UNIX socket and refuses its
    open with ``EINVAL``, as a socket swapped in after the check would on Windows. Runs on every
    platform."""

    def __init__(self, sockets: set[Path]) -> None:
        def _open(path: Any, flags: int, *args: Any) -> int:
            if Path(path) in sockets:
                raise OSError(errno.EINVAL, "Invalid argument", str(path))
            return os.open(path, flags, *args)

        super().__init__(_open)
        self._sockets = sockets

    def lstat(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(path, str | os.PathLike) and Path(path) in self._sockets:
            return _WINDOWS_SOCKET_STAT
        return os.lstat(path, *args, **kwargs)


@pytest.mark.parametrize("read", ["get_meta", "read_bytes", "delete"])
async def test_a_windows_socket_swapped_in_after_its_check_is_damage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    part = _blob(store, meta.file_id) if read == "read_bytes" else _sidecar(store, meta.file_id)
    sockets: set[Path] = set()
    monkeypatch.setattr(uploads, "os", _OsWithSocket(sockets))
    # Control: under the patched module, a sound upload still reads.
    assert await store.read_bytes(meta.file_id)
    sockets.add(part)
    with pytest.raises(UploadDamagedError):
        await getattr(store, read)(meta.file_id)


def _bind_windows_socket(path: Path) -> Any:
    """A Windows AF_UNIX socket bound at ``path``, a name relative to the working directory, since
    an AF_UNIX path is short, through Winsock, since CPython offers no ``socket.AF_UNIX`` on
    Windows. Returns its closer. Skips where Winsock refuses one, as before Windows 10 1803."""
    import ctypes
    import struct

    ws2 = ctypes.WinDLL("ws2_32")  # type: ignore[attr-defined,unused-ignore]
    if ws2.WSAStartup(0x0202, ctypes.create_string_buffer(512)) != 0:
        pytest.skip("Winsock did not start")
    ws2.socket.restype = ctypes.c_size_t
    sock = ws2.socket(1, 1, 0)  # AF_UNIX, SOCK_STREAM
    opened = sock != ctypes.c_size_t(-1).value

    def _close() -> None:
        # Every exit after the startup balances it, the skips included.
        if opened:
            ws2.closesocket(ctypes.c_size_t(sock))
        ws2.WSACleanup()

    name = os.fsencode(path)
    addr = struct.pack("H", 1) + name.ljust(108, b"\0")
    if not opened:
        reason = "Winsock offers no AF_UNIX socket here"
    elif len(name) >= 108:
        reason = "the socket path is longer than sockaddr_un holds"
    elif ws2.bind(ctypes.c_size_t(sock), addr, len(addr)) != 0:
        reason = "Winsock could not bind an AF_UNIX socket here"
    else:
        return _close
    _close()
    pytest.skip(reason)


@pytest.mark.skipif(sys.platform != "win32", reason="a Windows AF_UNIX socket needs Windows")
@pytest.mark.parametrize("swapped", [False, True], ids=["before-the-check", "after-the-check"])
@pytest.mark.parametrize("read", ["get_meta", "read_bytes", "delete"])
async def test_a_real_windows_socket_is_damage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read: str, swapped: bool
) -> None:
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    part = _blob(store, meta.file_id) if read == "read_bytes" else _sidecar(store, meta.file_id)
    closers: list[Any] = []

    monkeypatch.chdir(part.parent)

    def _plant() -> None:
        part.unlink()
        closers.append(_bind_windows_socket(Path(part.name)))

    if swapped:

        def _socket_then_open(path: Any, flags: int, *args: Any) -> int:
            if Path(path) == part and not closers:
                _plant()
            return os.open(path, flags, *args)

        monkeypatch.setattr(uploads, "os", _OsWith(_socket_then_open))
    else:
        _plant()
    try:
        with pytest.raises(UploadDamagedError):
            await getattr(store, read)(meta.file_id)
        assert closers, "the socket was never planted"
    finally:
        for close in closers:
            close()


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
        # each on its own upload. The delete meets the swap at the route's own read; the store
        # delete's in-lock refusals are covered by the store tests above.
        for r in (
            await c.get(f"/uploads/{meta_fids[0]}/messages", headers=ha),
            await c.delete(f"/uploads/{meta_fids[1]}", headers=ha),
        ):
            assert r.status_code == 423, r.text
            assert r.json()["detail"] == _DAMAGED_TEXT
    assert (root / f"{meta_fids[1]}.meta").exists() and (root / f"{meta_fids[1]}.blob").is_file()
