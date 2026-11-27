# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One unreachable translator at every ``uploads.py`` site (BACKLOG #5388, the deferred scope of
engine PR 3134).

A share that goes away under a part arrives as at least three shapes: a POSIX ``ESTALE``, a
Windows error such as ``ERROR_NETNAME_DELETED`` (64) under ``EINVAL``, and a Windows
``FileNotFoundError`` carrying ``ERROR_BAD_NETPATH`` (53). Each step of a part's read, the first
``lstat``, the Windows check after the open and the read itself, classes all three as unreachable,
so a by-id read answers ``UploadStorageUnreachableError`` rather than a server error or a missing
file. Every site that reads a ``FileNotFoundError`` as absence reads it through ``is_absent``, so
an outage is never a removal, a lost body or a pair already gone.

Synthetic values only. The faults are raised by patching the one call that meets them, since a
real outage cannot be made on a test runner.
"""

from __future__ import annotations

import errno
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

import messagefoundry.uploads as uploads
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.uploads import UploadStorageUnreachableError, UploadStore
from tests.test_b532r_uploads_sidecar_reads import _OsWith

_Fault = Callable[[Path | None], OSError]


def _os_error(
    cls: type[OSError], code: int, text: str, path: Path | None, winerror: int | None = None
) -> OSError:
    """``cls(code, text)``, naming ``path`` when one is given, as a read's error names none."""
    exc = cls(code, text) if path is None else cls(code, text, str(path))
    if winerror is not None:
        exc.winerror = winerror  # type: ignore[attr-defined,misc,unused-ignore]
    return exc


def _stale(path: Path | None) -> OSError:
    """A stale NFS handle (POSIX ESTALE)."""
    return _os_error(OSError, errno.ESTALE, "Stale file handle", path)


def _share_lost(path: Path | None) -> OSError:
    """ERROR_NETNAME_DELETED, which CPython raises under EINVAL."""
    text = "The specified network name is no longer available"
    return _os_error(OSError, errno.EINVAL, text, path, winerror=64)


def _share_down(path: Path | None) -> OSError:
    """ERROR_BAD_NETPATH, which CPython maps to ENOENT and so raises as a FileNotFoundError."""
    text = "The network path was not found"
    return _os_error(FileNotFoundError, errno.ENOENT, text, path, winerror=53)


_NOT_FNF: dict[str, _Fault] = {"estale": _stale, "share-lost": _share_lost}
_ALL: dict[str, _Fault] = {**_NOT_FNF, "share-down": _share_down}


async def _saved(tmp_path: Path, *, keyed: bool = False) -> tuple[UploadStore, str, Path, Path]:
    cipher = make_cipher(generate_key() if keyed else None)
    store = UploadStore(tmp_path / "uploads", cipher, max_bytes=4096)
    meta = await store.save(
        data=b"synthetic diagnostic line\n", filename="a.txt", uploader="op", uploader_id="u-op"
    )
    blob, sidecar = store._paths(meta.file_id)
    return store, meta.file_id, blob, sidecar


def _lstat_fails(monkeypatch: pytest.MonkeyPatch, target: Path, fault: _Fault) -> None:
    """``Path.lstat`` raises ``fault`` for ``target`` alone."""
    real = Path.lstat

    def _lstat(self: Path) -> os.stat_result:
        if self == target:
            raise fault(self)
        return real(self)

    monkeypatch.setattr(Path, "lstat", _lstat)


def _unlink_fails(monkeypatch: pytest.MonkeyPatch, target: Path, fault: _Fault) -> None:
    """``os.unlink``, which ``Path.unlink`` calls, raises ``fault`` for ``target`` alone."""
    real = os.unlink

    def _unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        if Path(path) == target:
            raise fault(target)
        real(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", _unlink)


async def _call(store: UploadStore, op: str, fid: str) -> object:
    if op == "get_meta":
        return await store.get_meta(fid)
    if op == "read_bytes":
        return await store.read_bytes(fid)
    return await store.delete(fid)


# --- the by-id reads: each step of a part's read ---------------------------------------------------


@pytest.mark.parametrize("fault", list(_NOT_FNF))
@pytest.mark.parametrize("op", ["get_meta", "read_bytes", "delete"])
async def test_an_outage_at_the_first_lstat_answers_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str, fault: str
) -> None:
    # 8401eaff finding 1: the open's own lstat classed only a FileNotFoundError, so an ESTALE or a
    # dropped Windows share there was re-raised and the route answered a server error.
    store, fid, blob, sidecar = await _saved(tmp_path)
    _lstat_fails(monkeypatch, blob if op == "read_bytes" else sidecar, _NOT_FNF[fault])
    with pytest.raises(UploadStorageUnreachableError):
        await _call(store, op, fid)
    monkeypatch.undo()
    assert blob.exists() and sidecar.exists()  # the delete removed nothing


@pytest.mark.parametrize("fault", list(_ALL))
@pytest.mark.parametrize("op", ["get_meta", "read_bytes"])
async def test_an_outage_at_the_check_after_the_open_answers_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str, fault: str
) -> None:
    # 8401eaff finding 2: Windows checks the name again once it is open, and an error there was
    # raised as it was: a server error, or for a FileNotFoundError a missing upload.
    store, fid, blob, sidecar = await _saved(tmp_path)
    target = blob if op == "read_bytes" else sidecar
    opened: list[Path] = []

    def _recording_open(path: Any, flags: int, *args: Any) -> int:
        opened.append(Path(path))
        return os.open(path, flags, *args)

    real = Path.lstat

    def _lstat(self: Path) -> os.stat_result:
        if self == target and target in opened:
            raise _ALL[fault](self)
        return real(self)

    monkeypatch.setattr(uploads, "_O_NOFOLLOW", 0)  # the Windows path, on every platform
    monkeypatch.setattr(uploads, "os", _OsWith(_recording_open))
    monkeypatch.setattr(Path, "lstat", _lstat)
    with pytest.raises(UploadStorageUnreachableError):
        await _call(store, op, fid)


class _ReadFails:
    """A part's handle whose read meets ``fault``, as a read whose share went away does."""

    def __init__(self, handle: Any, fault: OSError) -> None:
        self._handle = handle
        self._fault = fault

    def __enter__(self) -> _ReadFails:
        return self

    def __exit__(self, *exc: object) -> None:
        self._handle.close()

    def read(self, size: int = -1) -> bytes:
        raise self._fault


def _read_fails(monkeypatch: pytest.MonkeyPatch, target: Path, fault: OSError) -> None:
    real = uploads._open_plain

    def _open(path: Path) -> tuple[Any, os.stat_result]:
        handle, info = real(path)
        if path == target:
            return _ReadFails(handle, fault), info
        return handle, info

    monkeypatch.setattr(uploads, "_open_plain", _open)


@pytest.mark.parametrize("fault", list(_NOT_FNF))
@pytest.mark.parametrize("op", ["get_meta", "read_bytes"])
async def test_an_outage_during_the_read_answers_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str, fault: str
) -> None:
    # 8401eaff finding 5: a read-time outage was re-raised, a server error. A read's error names
    # no path, so it was never checked again either.
    store, fid, blob, sidecar = await _saved(tmp_path)
    _read_fails(monkeypatch, blob if op == "read_bytes" else sidecar, _NOT_FNF[fault](None))
    with pytest.raises(UploadStorageUnreachableError):
        await _call(store, op, fid)


@pytest.mark.parametrize("op", ["get_meta", "read_bytes"])
async def test_a_device_fault_during_the_read_is_still_raised_as_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str
) -> None:
    """Control: EIO is a device fault too (``path_reach``), so it is not an outage."""
    store, fid, blob, sidecar = await _saved(tmp_path)
    _read_fails(
        monkeypatch,
        blob if op == "read_bytes" else sidecar,
        OSError(errno.EIO, "Input/output error"),
    )
    with pytest.raises(OSError) as raised:
        await _call(store, op, fid)
    assert not isinstance(raised.value, uploads._UnreachableError)
    assert raised.value.errno == errno.EIO


@pytest.mark.parametrize("fault", list(_NOT_FNF))
async def test_the_deletes_recheck_of_a_refused_sidecar_answers_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    # The delete checks a refused sidecar again with an lstat; an outage there was passed to
    # _refused_read, which answered None, and was re-raised.
    store, fid, blob, sidecar = await _saved(tmp_path, keyed=True)
    _lstat_fails(monkeypatch, sidecar, _NOT_FNF[fault])
    with pytest.raises(UploadStorageUnreachableError):
        await store.delete(fid, sidecar_refused=True)
    monkeypatch.undo()
    assert blob.exists() and sidecar.exists()


# --- the sites that read a FileNotFoundError as absence --------------------------------------------


async def test_a_body_the_share_hides_is_not_a_lost_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # _lost_body_size answered 0, a lost body, for a body whose share could not be reached, so
    # the class check could call a sound upload one rotate-key can never seal.
    store, _fid, blob, _sidecar = await _saved(tmp_path)
    _lstat_fails(monkeypatch, blob, _share_down)
    assert store._lost_body_size(blob) is None
    monkeypatch.undo()
    blob.unlink()
    assert store._lost_body_size(blob) == 0  # control: an absent body is still a lost one


async def test_the_prune_does_not_age_a_pair_whose_body_the_share_hides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store, fid, blob, _sidecar = await _saved(tmp_path)
    _lstat_fails(monkeypatch, blob, _share_down)
    with caplog.at_level(logging.WARNING, logger=uploads.__name__):
        assert store._aged_on_disk_sync(fid) is None
    assert any("could not age the pair" in r.getMessage() for r in caplog.records)


async def test_the_prune_keeps_the_sidecar_when_the_share_hides_the_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The prune read a FileNotFoundError on the body's unlink as a body already removed, and
    # unlinked the sidecar, the listing key, of a pair whose body was still on the share.
    store, fid, blob, sidecar = await _saved(tmp_path)
    meta = await store.get_meta(fid)
    _unlink_fails(monkeypatch, blob, _share_down)
    assert store._prune_pair_sync(meta) is False
    monkeypatch.undo()
    assert blob.exists() and sidecar.exists()


async def test_a_discard_whose_body_the_share_hides_keeps_the_pair_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # missing_ok read the outage as a body already gone, so the discard removed the sidecar and
    # reported the pair removed while its body stayed on the share.
    store, fid, blob, sidecar = await _saved(tmp_path)
    _unlink_fails(monkeypatch, blob, _share_down)
    with caplog.at_level(logging.ERROR, logger=uploads.__name__):
        assert store._discard_cancelled_sync(fid) is False
    monkeypatch.undo()
    assert blob.exists() and sidecar.exists()
    assert any("not fully removed" in r.getMessage() for r in caplog.records)


async def test_a_discard_whose_sidecar_the_share_hides_is_logged_not_read_as_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store, fid, _blob, sidecar = await _saved(tmp_path)
    _unlink_fails(monkeypatch, sidecar, _share_down)
    with caplog.at_level(logging.ERROR, logger=uploads.__name__):
        assert store._discard_cancelled_sync(fid) is False
    monkeypatch.undo()
    assert sidecar.exists()
    assert any("not fully removed" in r.getMessage() for r in caplog.records)


async def test_rotate_key_skips_a_body_the_share_hides_rather_than_count_it_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A lost body is not a skip, so a pass that met an outage on one could read as done and the
    # operator retire the key that body may still be under.
    store, fid, blob, _sidecar = await _saved(tmp_path)
    _lstat_fails(monkeypatch, blob, _share_down)
    half = store._reseal_half(cast(Any, None), fid, blob, "body", gate=cast(Any, None))
    assert half is uploads._Half.SKIPPED


async def test_rotate_keys_replace_raises_an_outage_rather_than_call_the_file_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store, _fid, blob, _sidecar = await _saved(tmp_path)
    seen = blob.lstat()
    tmp = blob.with_name(blob.name + ".tmp")
    tmp.write_text("synthetic", encoding="utf-8")
    _lstat_fails(monkeypatch, blob, _share_down)
    with pytest.raises(FileNotFoundError) as raised:
        uploads._replace_if_unchanged(tmp, blob, seen)
    assert getattr(raised.value, "winerror", None) == 53
