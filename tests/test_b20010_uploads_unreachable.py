# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One unreachable translator at every ``uploads.py`` site (BACKLOG #5388, the deferred scope of
engine PR 3134).

A share that goes away under a part arrives as at least three shapes: a POSIX ``ESTALE``, a
Windows error such as ``ERROR_NETNAME_DELETED`` (64) under ``EINVAL``, and a Windows
``FileNotFoundError`` carrying ``ERROR_BAD_NETPATH`` (53). Each step of a part's read, the first
``lstat``, the Windows check after the open and the read itself, classes all three as unreachable,
so a by-id read answers ``UploadStorageUnreachableError`` rather than a server error or a missing
file. At least the sites tested here read a ``FileNotFoundError`` as absence only through
``is_absent``, and the ones a removal or a ``rotate-key`` lost body rests on that the last section
names only through ``is_name_absent``. Other sites still read a Windows missing folder or drive as
absence; the changelog fragment names them.

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
    _after_the_open_fails(monkeypatch, blob if op == "read_bytes" else sidecar, _ALL[fault])
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
        self.failed = True
        raise self._fault

    failed = False


def _read_fails(monkeypatch: pytest.MonkeyPatch, target: Path, fault: OSError) -> list[_ReadFails]:
    """The read of ``target`` meets ``fault``; returns the handles it made, to tell when it did."""
    real = uploads._open_plain
    made: list[_ReadFails] = []

    def _open(path: Path) -> tuple[Any, os.stat_result]:
        handle, info = real(path)
        if path == target:
            made.append(_ReadFails(handle, fault))
            return made[-1], info
        return handle, info

    monkeypatch.setattr(uploads, "_open_plain", _open)
    return made


#: A read's error as CPython raises it: it names no path, and on Windows it carries no winerror,
#: since the read's errno comes from the C runtime. A dropped Windows share is then EINVAL or,
#: for ERROR_BAD_NETPATH, a FileNotFoundError.
_READ_FAULTS: dict[str, Callable[[], OSError]] = {
    "estale": lambda: _stale(None),
    "windows-einval": lambda: OSError(errno.EINVAL, "Invalid argument"),
    "windows-enoent": lambda: FileNotFoundError(errno.ENOENT, "No such file or directory"),
}


@pytest.mark.parametrize("fault", list(_READ_FAULTS))
@pytest.mark.parametrize("op", ["get_meta", "read_bytes"])
async def test_an_outage_during_the_read_answers_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str, fault: str
) -> None:
    # 8401eaff finding 5: a read-time outage was re-raised, a server error, or for ENOENT read as
    # a missing upload. A read's error names no path, so it was never checked again either.
    store, fid, blob, sidecar = await _saved(tmp_path)
    target = blob if op == "read_bytes" else sidecar
    made = _read_fails(monkeypatch, target, _READ_FAULTS[fault]())
    if fault == "windows-einval":
        # The name's own check after the read meets the dropped share, as it would.
        real = os.lstat

        def _lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            if made and made[-1].failed and Path(path) == target:
                raise _share_down(target)
            return real(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", _lstat)
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
    monkeypatch.undo()
    blob.unlink()
    aged = store._aged_on_disk_sync(fid)  # control: an absent body still ages, at size 0
    assert aged is not None and aged.size == 0


async def test_the_prune_logs_a_sidecar_the_share_hides_after_the_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # missing_ok swallowed the outage on the sidecar's unlink, with no log.
    store, fid, blob, sidecar = await _saved(tmp_path)
    meta = await store.get_meta(fid)
    _unlink_fails(monkeypatch, sidecar, _share_down)
    with caplog.at_level(logging.WARNING, logger=uploads.__name__):
        assert store._prune_pair_sync(meta) is True
    monkeypatch.undo()
    assert not blob.exists() and sidecar.exists()
    assert any("but not its sidecar" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("op", ["get_meta", "read_bytes"])
async def test_an_open_that_says_absent_of_a_file_still_there_is_not_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str
) -> None:
    # Windows maps a dropped share to ENOENT with no winerror on an open. When the share is back
    # for the re-check, the file is there, and the open's error was re-raised: a missing upload.
    store, fid, blob, sidecar = await _saved(tmp_path)
    target = blob if op == "read_bytes" else sidecar

    def _open(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == target:
            raise FileNotFoundError(errno.ENOENT, "No such file or directory", str(path))
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_open))
    with pytest.raises(UploadStorageUnreachableError):
        await _call(store, op, fid)


@pytest.mark.parametrize("op", ["get_meta", "read_bytes"])
async def test_an_open_that_says_absent_of_a_file_that_is_gone_is_still_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str
) -> None:
    """Control: the part really went between the lstat and the open, so the answer is a missing
    upload, not a storage outage."""
    store, fid, blob, sidecar = await _saved(tmp_path)
    target = blob if op == "read_bytes" else sidecar

    def _open(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == target:
            target.unlink()
            raise FileNotFoundError(errno.ENOENT, "No such file or directory", str(path))
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_open))
    with pytest.raises(uploads.UploadNotFoundError):
        await _call(store, op, fid)


@pytest.mark.parametrize("fault", list(_NOT_FNF))
async def test_an_outage_at_the_fstat_after_the_open_answers_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    store, fid, _blob, _sidecar = await _saved(tmp_path)

    class _OsFstatFails:
        """The ``os`` the uploads module reads, with only its ``fstat`` failing."""

        def __getattr__(self, name: str) -> object:
            return getattr(os, name)

        @staticmethod
        def fstat(fd: int) -> os.stat_result:
            raise _NOT_FNF[fault](None)

    monkeypatch.setattr(uploads, "os", _OsFstatFails())
    with pytest.raises(UploadStorageUnreachableError):
        await store.get_meta(fid)


async def test_a_cancelled_saves_removal_is_not_called_done_while_the_share_is_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Path.exists answers False for any OSError, so an unreachable pair read as removed and the
    # WARNING withdrew the ERROR that it may still be stored with no audit row.
    store, fid, blob, sidecar = await _saved(tmp_path)
    _unlink_fails(monkeypatch, blob, _share_down)
    real_lstat, real_stat = os.lstat, os.stat

    def _down(real: Callable[..., os.stat_result]) -> Callable[..., os.stat_result]:
        def _call_it(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            if Path(path) in (blob, sidecar):
                raise _share_down(Path(path))
            return real(path, *args, **kwargs)

        return _call_it

    monkeypatch.setattr(os, "lstat", _down(real_lstat))
    monkeypatch.setattr(os, "stat", _down(real_stat))
    real_exists = os.path.exists

    def _exists(path: Any) -> bool:
        # What os.path.exists answers for a path whose stat fails; on Windows it does not call
        # os.stat, so the patch above would not reach it.
        return False if Path(path) in (blob, sidecar) else real_exists(path)

    monkeypatch.setattr(os.path, "exists", _exists)
    entry = uploads._PendingRemoval(file_id=fid, deadline=0.0, flagged=True)
    with caplog.at_level(logging.WARNING, logger=uploads.__name__):
        assert store._remove_and_report_sync(entry) is False
    assert not any("no longer applies" in r.getMessage() for r in caplog.records)


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
    monkeypatch.undo()
    blob.unlink()
    # Control: a body that is absent is still a lost one.
    half = store._reseal_half(cast(Any, None), fid, blob, "body", gate=cast(Any, None))
    assert half is uploads._Half.LOST


async def test_rotate_key_skips_a_body_whose_read_says_enoent_while_it_is_there(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The read's ENOENT, as Windows gives a dropped share with no winerror, was read as a body
    # that is gone, so the half was LOST while the body was on disk.
    store, fid, blob, _sidecar = await _saved(tmp_path, keyed=True)
    _read_fails(monkeypatch, blob, _READ_FAULTS["windows-enoent"]())
    cipher = cast(Any, store._cipher)
    half = store._reseal_half(cipher, fid, blob, "body", gate=cast(Any, None))
    assert half is uploads._Half.SKIPPED


async def test_rotate_keys_replace_raises_an_outage_rather_than_call_the_file_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A FileNotFoundError here was the file removed; an unreachable one reached the write's
    # handler as a FileNotFoundError, which _root_gone could log as the uploads directory gone.
    _store, _fid, blob, _sidecar = await _saved(tmp_path)
    seen = blob.lstat()
    tmp = blob.with_name(blob.name + ".tmp")
    tmp.write_text("synthetic", encoding="utf-8")
    _lstat_fails(monkeypatch, blob, _share_down)
    with pytest.raises(uploads._UnreachableError):
        uploads._replace_if_unchanged(tmp, blob, seen)


async def test_the_prune_logs_a_leftover_sidecar_it_could_not_clear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The body was already gone, and the leftover sidecar's unlink was suppressed with no log.
    store, fid, blob, sidecar = await _saved(tmp_path)
    meta = await store.get_meta(fid)
    blob.unlink()
    _unlink_fails(monkeypatch, sidecar, _share_down)
    with caplog.at_level(logging.WARNING, logger=uploads.__name__):
        assert store._prune_pair_sync(meta) is False
    monkeypatch.undo()
    assert sidecar.exists()
    assert any("leftover sidecar" in r.getMessage() for r in caplog.records)


# --- only a missing final name is gone (round-3 findings 1, 2, 3 and 6) ------------------------------


def _name_missing(path: Path | None) -> OSError:
    """ERROR_FILE_NOT_FOUND (2): the final name is not there, the one code ``is_name_absent``
    reads as gone on Windows."""
    text = "The system cannot find the file specified"
    return _os_error(FileNotFoundError, errno.ENOENT, text, path, winerror=2)


def _parent_missing(path: Path | None) -> OSError:
    """ERROR_PATH_NOT_FOUND (3), a missing folder above the name, which CPython maps to ENOENT."""
    text = "The system cannot find the path specified"
    return _os_error(FileNotFoundError, errno.ENOENT, text, path, winerror=3)


def _drive_missing(path: Path | None) -> OSError:
    """ERROR_INVALID_DRIVE (15), which CPython maps to ENOENT too. Which file calls answer it is not
    measured: on one Windows 11 box a path on an unmapped drive letter answered 3, as
    :func:`_parent_missing` does."""
    text = "The system cannot find the drive specified"
    return _os_error(FileNotFoundError, errno.ENOENT, text, path, winerror=15)


#: Errors ``is_absent`` reads as absence and ``is_name_absent`` does not: the name may be there.
_NOT_NAME: dict[str, _Fault] = {"parent-missing": _parent_missing, "drive-missing": _drive_missing}


def _every_lstat_fails(monkeypatch: pytest.MonkeyPatch, target: Path, fault: _Fault) -> None:
    """``Path.lstat`` and ``os.lstat`` both raise ``fault`` for ``target``, as a dropped drive or
    folder answers every check of a name under it."""
    _lstat_fails(monkeypatch, target, fault)
    real = os.lstat

    def _lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if isinstance(path, str | os.PathLike) and Path(path) == target:
            raise fault(target)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", _lstat)


@pytest.mark.parametrize("fault", list(_NOT_NAME))
async def test_known_absent_reads_only_a_missing_name_as_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    # A missing folder or drive read as a pair removed, so a cancelled save's ERROR was withdrawn
    # while its pair may still be stored on the drive that dropped.
    _store, _fid, blob, _sidecar = await _saved(tmp_path)
    _every_lstat_fails(monkeypatch, blob, _NOT_NAME[fault])
    assert uploads._known_absent(blob) is False
    monkeypatch.undo()
    _every_lstat_fails(monkeypatch, blob, _name_missing)
    assert uploads._known_absent(blob) is True  # control: a missing name is still gone


@pytest.mark.parametrize("fault", list(_NOT_NAME))
async def test_rotate_keys_replace_reads_a_missing_folder_as_an_outage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    # A missing folder or drive was the file removed, so a body there counted as lost.
    _store, _fid, blob, _sidecar = await _saved(tmp_path)
    seen = blob.lstat()
    tmp = blob.with_name(blob.name + ".tmp")
    tmp.write_text("synthetic", encoding="utf-8")
    _lstat_fails(monkeypatch, blob, _NOT_NAME[fault])
    with pytest.raises(uploads._UnreachableError):
        uploads._replace_if_unchanged(tmp, blob, seen)
    monkeypatch.undo()
    _lstat_fails(monkeypatch, blob, _name_missing)
    with pytest.raises(uploads._ChangedUnderReseal) as changed:  # control: a missing name
        uploads._replace_if_unchanged(tmp, blob, seen)
    assert changed.value.gone


@pytest.mark.parametrize("fault", list(_NOT_NAME))
async def test_rotate_key_skips_a_body_under_a_missing_folder_rather_than_count_it_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    # A lost body is not a skip, so a dropped drive could read as a pass that is done, and the
    # operator retire the key the body is still under.
    store, fid, blob, _sidecar = await _saved(tmp_path)
    _every_lstat_fails(monkeypatch, blob, _NOT_NAME[fault])
    half = store._reseal_half(cast(Any, None), fid, blob, "body", gate=cast(Any, None))
    assert half is uploads._Half.SKIPPED
    monkeypatch.undo()
    _every_lstat_fails(monkeypatch, blob, _name_missing)
    # Control: a body whose name is missing is still a lost one.
    half = store._reseal_half(cast(Any, None), fid, blob, "body", gate=cast(Any, None))
    assert half is uploads._Half.LOST


class _OsOpenAndLstatFail:
    """The ``os`` the uploads module reads: the open of ``target`` says it is absent, with no
    winerror as a Windows open gives, and its own ``lstat`` of ``target`` meets ``fault``."""

    def __init__(self, target: Path, fault: _Fault) -> None:
        self._target = target
        self._fault = fault

    def __getattr__(self, name: str) -> Any:
        return getattr(os, name)

    def open(self, path: Any, flags: int, *args: Any) -> int:
        if Path(path) == self._target:
            raise FileNotFoundError(errno.ENOENT, "No such file or directory", str(path))
        return os.open(path, flags, *args)

    def lstat(self, path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if Path(path) == self._target:
            raise self._fault(self._target)
        return os.lstat(path, *args, **kwargs)


@pytest.mark.parametrize("fault", list(_NOT_NAME))
async def test_rotate_key_skips_a_body_whose_failed_open_meets_a_missing_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    # The re-check after a failed open read a missing folder or drive as the body gone, and the
    # half reused that verdict, so it was LOST while the body may still be under the OLD key.
    store, fid, blob, _sidecar = await _saved(tmp_path, keyed=True)
    cipher = cast(Any, store._cipher)
    monkeypatch.setattr(uploads, "os", _OsOpenAndLstatFail(blob, _NOT_NAME[fault]))
    half = store._reseal_half(cipher, fid, blob, "body", gate=cast(Any, None))
    assert half is uploads._Half.SKIPPED
    monkeypatch.setattr(uploads, "os", _OsOpenAndLstatFail(blob, _name_missing))
    # Control: a re-check that says the name is missing is still a lost body.
    half = store._reseal_half(cipher, fid, blob, "body", gate=cast(Any, None))
    assert half is uploads._Half.LOST


def _after_the_open_fails(monkeypatch: pytest.MonkeyPatch, target: Path, fault: _Fault) -> None:
    """The Windows check of ``target`` after its open raises ``fault``, on every platform."""
    opened: list[Path] = []

    def _recording_open(path: Any, flags: int, *args: Any) -> int:
        opened.append(Path(path))
        return os.open(path, flags, *args)

    real = Path.lstat

    def _lstat(self: Path) -> os.stat_result:
        if self == target and target in opened:
            raise fault(self)
        return real(self)

    monkeypatch.setattr(uploads, "_O_NOFOLLOW", 0)
    monkeypatch.setattr(uploads, "os", _OsWith(_recording_open))
    monkeypatch.setattr(Path, "lstat", _lstat)


@pytest.mark.parametrize("fault", list(_NOT_NAME))
@pytest.mark.parametrize("op", ["get_meta", "read_bytes"])
async def test_a_missing_folder_at_the_check_after_the_open_answers_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str, fault: str
) -> None:
    # Round-3 finding 1: only winerror 53 and 67 were an outage there, so a missing folder or
    # drive under a part that was just opened answered a missing upload.
    store, fid, blob, sidecar = await _saved(tmp_path)
    _after_the_open_fails(monkeypatch, blob if op == "read_bytes" else sidecar, _NOT_NAME[fault])
    with pytest.raises(UploadStorageUnreachableError):
        await _call(store, op, fid)


@pytest.mark.parametrize("op", ["get_meta", "read_bytes"])
async def test_a_missing_name_at_the_check_after_the_open_is_still_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str
) -> None:
    """Control: the name went after the open, so the answer is a missing upload."""
    store, fid, blob, sidecar = await _saved(tmp_path)
    _after_the_open_fails(monkeypatch, blob if op == "read_bytes" else sidecar, _name_missing)
    with pytest.raises(uploads.UploadNotFoundError):
        await _call(store, op, fid)
