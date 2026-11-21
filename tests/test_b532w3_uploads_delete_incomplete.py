# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Review round 3 repairs for the uploads delete and by-id reads (BACKLOG #5388 added item 3).

Each test names the finding it pins and what 52c0fdef3ca did instead. At least: a delete that
could not finish is no success (findings 9 and 11), the in-lock sidecar check fails closed
(finding 10), a refused open is classed by what the name is now, the same on every platform
(findings 1, 3 and 14), a refused body unlink is damage only for a directory (finding 13), and a
failed re-check is logged once (finding 4). Synthetic data only."""

from __future__ import annotations

import contextlib
import copy
import errno
import json
import logging
import os
import pickle
import stat
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi import HTTPException

import messagefoundry.uploads as uploads
import messagefoundry_webconsole.routes.uploaded_logs as ul
from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry.uploads import (
    UploadAccessError,
    UploadDamagedError,
    UploadDeleteIncompleteError,
    UploadNotFoundError,
)
from tests._bound_proof import reproving_transport
from tests.test_b532r_uploads_sidecar_reads import _blob, _OsWith, _saved, _sidecar, _store
from tests.test_upload_api import (
    ADT,
    PW,
    _add_user,
    _login,
    _make_user,
    _uploads_settings,
    engine,  # noqa: F401 - the fixture, used by name
)


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uploads, "_UNLINK_PAUSE", 0.0)


def _sharing_violation(path: Path) -> PermissionError:
    """A Windows sharing violation, as an unlink of a file another handle holds open meets."""
    exc = PermissionError(errno.EACCES, "The process cannot access the file", str(path))
    exc.winerror = 32  # type: ignore[attr-defined,misc,unused-ignore]
    return exc


def _failing_unlink(
    monkeypatch: pytest.MonkeyPatch, target: Path, error: Any, times: int | None = None
) -> list[Path]:
    """Make ``Path.unlink`` of ``target`` raise ``error(target)``, ``times`` times or for good."""
    real = Path.unlink
    tries: list[Path] = []

    def _unlink(self: Path, missing_ok: bool = False) -> None:
        if self == target and (times is None or len(tries) < times):
            tries.append(self)
            raise error(self)
        real(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", _unlink)
    return tries


# --- finding 11: a body another handle holds open --------------------------------------------------


async def test_a_body_held_open_is_an_incomplete_delete_not_access_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On 52c0fdef3ca this was UploadAccessError, whose text says "do not delete it for this".
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    blob = _blob(store, meta.file_id)
    tries = _failing_unlink(monkeypatch, blob, _sharing_violation)
    with pytest.raises(UploadDeleteIncompleteError) as raised:
        await store.delete(meta.file_id)
    assert raised.value.removed is None
    assert len(tries) == uploads._UNLINK_ATTEMPTS
    assert blob.is_file() and _sidecar(store, meta.file_id).is_file()


async def test_a_body_held_open_briefly_is_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The engine's own read ends between the tries, so the delete finishes.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    blob = _blob(store, meta.file_id)
    _failing_unlink(monkeypatch, blob, _sharing_violation, times=1)
    assert (await store.delete(meta.file_id)).meta == meta
    assert not blob.exists() and not _sidecar(store, meta.file_id).exists()


# --- finding 13: a body unlink refused for a permission, whatever the body is ----------------------


class _OsLstatAs(_OsWith):
    """``os`` as ``uploads`` sees it, where an ``lstat`` of ``path`` answers ``info``."""

    def __init__(self, path: Path, info: Any) -> None:
        super().__init__(os.open)
        self._path, self._info = path, info

    def lstat(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(path, str | os.PathLike) and Path(path) == self._path:
            return self._info
        return os.lstat(path, *args, **kwargs)


async def test_a_fifo_body_whose_unlink_a_permission_refuses_is_access_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A FIFO is unlinked as a file is, so its kind is not why the unlink failed. On 52c0fdef3ca
    # the re-check saw it was not regular and answered "damaged".
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    blob = _blob(store, meta.file_id)
    fifo = SimpleNamespace(st_mode=stat.S_IFIFO | 0o644, st_file_attributes=0, st_reparse_tag=0)
    monkeypatch.setattr(uploads, "os", _OsLstatAs(blob, fifo))
    _failing_unlink(
        monkeypatch, blob, lambda p: PermissionError(errno.EPERM, "Operation not permitted", str(p))
    )
    with pytest.raises(UploadAccessError):
        await store.delete(meta.file_id)
    assert blob.is_file() and _sidecar(store, meta.file_id).is_file()


# --- finding 10: the in-lock sidecar check fails closed --------------------------------------------


@pytest.mark.parametrize("error", ["denied", "eio"])
async def test_a_sidecar_that_cannot_be_checked_keeps_the_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: str
) -> None:
    # On 52c0fdef3ca the check answered "not a directory" and the body was unlinked.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    real_lock = uploads._pair_lock
    real_lstat = Path.lstat

    def _lstat(self: Path) -> os.stat_result:
        if self == sidecar:
            if error == "denied":
                raise PermissionError(errno.EACCES, "Permission denied", str(self))
            raise OSError(errno.EIO, "Input/output error", str(self))
        return real_lstat(self)

    @contextlib.contextmanager
    def _lock_then_refuse(path: Path, **kwargs: Any) -> Iterator[None]:
        with real_lock(path, **kwargs):
            monkeypatch.setattr(Path, "lstat", _lstat)
            yield

    monkeypatch.setattr(uploads, "_pair_lock", _lock_then_refuse)
    if error == "denied":
        with pytest.raises(UploadAccessError):
            await store.delete(meta.file_id)
    else:
        with pytest.raises(OSError) as raised:
            await store.delete(meta.file_id)
        assert raised.value.errno == errno.EIO
    monkeypatch.setattr(Path, "lstat", real_lstat)
    assert _blob(store, meta.file_id).is_file() and sidecar.is_file()


# --- findings 1, 3 and 14: a refused open, classed by what the name is now -------------------------


class _OsInvalidOpen(_OsLstatAs):
    """``_OsLstatAs``, where an open of ``path`` is refused with ``EINVAL``."""

    def __init__(self, path: Path, info: Any) -> None:
        super().__init__(path, info)

        def _open(target: Any, flags: int, *args: Any) -> int:
            if Path(target) == path:
                raise OSError(errno.EINVAL, "Invalid argument", str(target))
            return os.open(target, flags, *args)

        self._open = _open


def _regular(attributes: int, tag: int) -> Any:
    return SimpleNamespace(
        st_mode=stat.S_IFREG | 0o644, st_file_attributes=attributes, st_reparse_tag=tag
    )


@pytest.mark.parametrize("read", ["get_meta", "read_bytes"])
async def test_an_invalid_open_of_an_unlisted_reparse_point_is_re_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    # Manager ruling, r4 item 5: a reparse tag _UNOPENABLE_REPARSE_TAGS does not list is re-raised
    # as an error, never "damaged" with a notice that invites a delete. On e59bc518d5a it was
    # answered damaged.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    part = _blob(store, meta.file_id) if read == "read_bytes" else _sidecar(store, meta.file_id)
    monkeypatch.setattr(uploads, "os", _OsInvalidOpen(part, _regular(0x420, 0x80000099)))
    with pytest.raises(OSError) as raised:
        await getattr(store, read)(meta.file_id)
    assert raised.value.errno == errno.EINVAL
    assert not isinstance(raised.value, UploadDamagedError)


@pytest.mark.parametrize(
    "info",
    [
        _regular(0x20, 0),
        _regular(0x420, 0x9000101A),
        _regular(0x420, 0x80000013),
        _regular(0x420, 0x8000001E),
        _regular(0x420, 0x80000021),
    ],
    ids=["plain-file", "cloud-placeholder", "dedup", "azure-file-sync", "onedrive"],
)
async def test_an_invalid_open_of_a_readable_file_is_re_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, info: Any
) -> None:
    # Control: the Windows CRT answers EINVAL for every Win32 error it does not map, as a share
    # fault or a placeholder whose filter is not running may be. That is not damage, which would
    # invite an operator to delete a sound file.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    monkeypatch.setattr(uploads, "os", _OsInvalidOpen(_blob(store, meta.file_id), info))
    with pytest.raises(OSError) as raised:
        await store.read_bytes(meta.file_id)
    assert raised.value.errno == errno.EINVAL
    assert not isinstance(raised.value, UploadDamagedError)


async def test_the_incomplete_error_copies_and_its_args_hold_no_filename(tmp_path: Path) -> None:
    meta = await _saved(_store(tmp_path / "uploads"))
    removal = uploads.UploadRemoval(meta, True, False)
    exc = UploadDeleteIncompleteError(meta.file_id, removal)
    assert copy.copy(exc).removed == removal and copy.copy(exc).args == exc.args
    assert pickle.loads(pickle.dumps(exc)).removed == removal
    # An orphaned operation logs the error's repr, so the uploader's filename must not be in it
    # (round-f03184d8 finding 4).
    assert exc.args == (meta.file_id,) and meta.filename not in repr(exc)


async def test_a_body_gone_after_its_unlink_failed_lets_the_delete_finish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Another remover took the body after its unlink was refused. On 3ac67f76c81 that answered
    # access refused, leaving the sidecar listed; on e59bc518d5a the unlink's error was dropped
    # unlogged (r4 item 6) and the body counted as this call's removal.
    caplog.set_level(logging.WARNING, logger=uploads._log.name)
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    blob = _blob(store, meta.file_id)
    real = Path.unlink

    def _unlink(self: Path, missing_ok: bool = False) -> None:
        if self == blob and blob.exists():
            real(self)
            raise PermissionError(errno.EACCES, "Access is denied", str(self))
        real(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", _unlink)
    removal = await store.delete(meta.file_id)
    assert (removal.meta, removal.body_removed, removal.sidecar_removed) == (meta, False, True)
    assert not _sidecar(store, meta.file_id).exists()
    assert any("did not remove it" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("met", [errno.ENXIO, errno.EINVAL], ids=["linux-socket", "windows-socket"])
@pytest.mark.parametrize("read", ["get_meta", "read_bytes"])
async def test_a_part_removed_before_the_recheck_reads_as_missing_on_every_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read: str, met: int
) -> None:
    # On 52c0fdef3ca the Linux race answered "damaged" (ENXIO is in _NOT_A_FILE) and the Windows
    # race re-raised EINVAL, a 500. Now both answer as an absent part does.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    part = _blob(store, meta.file_id) if read == "read_bytes" else _sidecar(store, meta.file_id)

    def _gone(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == part:
            part.unlink()
            raise OSError(met, os.strerror(met), str(path))
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_gone))
    with pytest.raises(UploadNotFoundError):
        await getattr(store, read)(meta.file_id)


class _OsRecheckFails(_OsWith):
    """``os`` as ``uploads`` sees it, where an open of ``path`` is refused and an ``lstat`` of it
    fails, as a re-check meeting a transient fault would."""

    def __init__(self, path: Path, error: OSError) -> None:
        def _open(target: Any, flags: int, *args: Any) -> int:
            if Path(target) == path:
                raise error
            return os.open(target, flags, *args)

        super().__init__(_open)
        self._path = path

    def lstat(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(path, str | os.PathLike) and Path(path) == self._path:
            raise OSError(errno.EIO, "Input/output error", str(path))
        return os.lstat(path, *args, **kwargs)


async def test_a_part_that_cannot_be_checked_again_is_not_damage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On 52c0fdef3ca an ENXIO whose re-check failed answered "damaged" by its errno (finding 3).
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    error = OSError(errno.ENXIO, "No such device or address", str(sidecar))
    monkeypatch.setattr(uploads, "os", _OsRecheckFails(sidecar, error))
    with pytest.raises(OSError) as raised:
        await store.get_meta(meta.file_id)
    assert raised.value.errno == errno.ENXIO
    assert not isinstance(raised.value, UploadDamagedError)


async def test_a_failed_recheck_is_logged_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # On 52c0fdef3ca the open's re-check and _refused_read's each logged it (finding 4).
    caplog.set_level(logging.WARNING, logger=uploads._log.name)
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    error = PermissionError(errno.EACCES, "Permission denied", str(sidecar))
    monkeypatch.setattr(uploads, "os", _OsRecheckFails(sidecar, error))
    with pytest.raises(UploadAccessError):
        await store.get_meta(meta.file_id)
    assert sum("checked again" in r.getMessage() for r in caplog.records) == 1


# --- the route and the web console -----------------------------------------------------------------


async def test_the_route_answers_an_incomplete_delete_409_and_records_the_part_done(
    engine: Engine,  # noqa: F811 - the imported fixture
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    await _add_user(service, Role.ADMINISTRATOR, name="root")
    root = tmp_path / "uploads"
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = reproving_transport(PW, app=app)
    real_unlink = Path.unlink
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        held, partial = [
            (await c.post("/uploads", files={"file": (n, ADT, "text/plain")}, headers=h)).json()[
                "file_id"
            ]
            for n in ("held.hl7", "partial.hl7")
        ]
        _failing_unlink(monkeypatch, root / f"{held}.blob", _sharing_violation)
        r = await c.delete(f"/uploads/{held}", headers=h)
        assert r.status_code == 409, r.text
        assert "nothing was deleted" in r.json()["detail"]
        monkeypatch.setattr(Path, "unlink", real_unlink)
        _failing_unlink(monkeypatch, root / f"{partial}.meta", _sharing_violation)
        # The retry while the sidecar still cannot go removes nothing, so it writes no row (r4
        # item 3; on e59bc518d5a each retry wrote one).
        for _ in range(2):
            r = await c.delete(f"/uploads/{partial}", headers=h)
            assert r.status_code == 409, r.text
            assert "not fully deleted" in r.json()["detail"]
            # It claims no listing, which is false for the never-sealable kind (r4 item 8).
            assert "listed" not in r.json()["detail"]
        listed = (await c.get("/uploads", headers=h)).json()
        assert partial in json.dumps(listed)
        monkeypatch.setattr(Path, "unlink", real_unlink)
        assert (await c.delete(f"/uploads/{partial}", headers=h)).status_code == 200
    rows = [a for a in await engine.store.list_audit() if a["action"] == "upload.delete"]
    details = [json.loads(str(a["detail"])) for a in rows]
    # No row for the held body, which lost nothing; one for the partial delete, which removed the
    # body, and one for the retry that removed only the sidecar.
    assert all(d["file_id"] != held for d in details)
    mine = sorted(
        (d.get("sidecar_kept", False), d.get("body_removed", True))
        for d in details
        if d["file_id"] == partial
    )
    assert mine == [(False, False), (True, True)]
    assert (root / f"{held}.blob").is_file() and (root / f"{held}.meta").is_file()
    assert not (root / f"{partial}.meta").exists()


def test_the_web_console_names_an_incomplete_delete_apart_from_a_refusal() -> None:
    code = ul._refusal_code(HTTPException(409, "x"), ul._DELETE_CODES)
    assert code == ul.DELETE_INCOMPLETE_CODE
    assert "did not finish" in ul._LIST_NOTICES[code]


# --- r4: a delete reports only what it removed, and a storage it cannot reach is no answer -------


def _unreachable_share(path: Path) -> FileNotFoundError:
    """What Windows raises for a path on a share it cannot reach: ERROR_BAD_NETPATH, as ENOENT."""
    exc = FileNotFoundError(errno.ENOENT, "The network path was not found", str(path))
    exc.winerror = 53  # type: ignore[attr-defined,misc,unused-ignore]
    return exc


class _OsLstatRaises(_OsWith):
    """``os`` as ``uploads`` sees it, where an ``lstat`` of ``path`` raises ``error(path)``."""

    def __init__(self, path: Path, error: Any) -> None:
        super().__init__(os.open)
        self._path, self._error = path, error

    def lstat(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(path, str | os.PathLike) and Path(path) == self._path:
            raise self._error(Path(path))
        return os.lstat(path, *args, **kwargs)


async def test_a_body_unlink_on_a_dropped_share_is_no_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # r4 item 1. On e59bc518d5a the re-lstat's ENOENT read as "gone", so the delete returned
    # success with both files still on disk.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    blob = _blob(store, meta.file_id)
    monkeypatch.setattr(uploads, "os", _OsLstatRaises(blob, _unreachable_share))
    _failing_unlink(monkeypatch, blob, lambda p: OSError(errno.EIO, "Input/output error", str(p)))
    # r5 item 2: whether the body went is not known, so the error says so and carries the
    # metadata for the route's row; on ee36e28d9d6 it was the plain unreachable refusal.
    with pytest.raises(uploads.UploadDeleteUnconfirmedError) as raised:
        await store.delete(meta.file_id)
    assert raised.value.meta == meta and meta.filename not in repr(raised.value)
    assert blob.is_file() and _sidecar(store, meta.file_id).is_file()


async def test_a_sidecar_on_a_dropped_share_in_the_lock_keeps_the_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # r4 item 2. On e59bc518d5a an ENOENT there read as absence, and the body was unlinked.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    real_lock = uploads._pair_lock
    real_lstat = Path.lstat

    def _lstat(self: Path) -> os.stat_result:
        if self == sidecar:
            raise _unreachable_share(self)
        return real_lstat(self)

    @contextlib.contextmanager
    def _lock_then_drop(path: Path, **kwargs: Any) -> Iterator[None]:
        with real_lock(path, **kwargs):
            monkeypatch.setattr(Path, "lstat", _lstat)
            yield

    monkeypatch.setattr(uploads, "_pair_lock", _lock_then_drop)
    with pytest.raises(uploads.UploadStorageUnreachableError):
        await store.delete(meta.file_id)
    monkeypatch.setattr(Path, "lstat", real_lstat)
    assert _blob(store, meta.file_id).is_file() and sidecar.is_file()


async def test_a_delete_that_removed_nothing_is_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # r4 item 2: a delete that raced another finds both parts gone in the lock. On e59bc518d5a it
    # returned the metadata, so the route wrote a second upload.delete row.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    real_lock = uploads._pair_lock

    @contextlib.contextmanager
    def _raced(path: Path, **kwargs: Any) -> Iterator[None]:
        _blob(store, meta.file_id).unlink()
        _sidecar(store, meta.file_id).unlink()
        with real_lock(path, **kwargs):
            yield

    monkeypatch.setattr(uploads, "_pair_lock", _raced)
    with pytest.raises(UploadNotFoundError):
        await store.delete(meta.file_id)


@pytest.mark.parametrize("read", ["get_meta", "read_bytes"])
async def test_an_open_on_a_dropped_share_is_unreachable_not_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, read: str
) -> None:
    # r4 item 9. On e59bc518d5a the open's ENOENT answered 404: an intact file read as gone.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    part = _blob(store, meta.file_id) if read == "read_bytes" else _sidecar(store, meta.file_id)

    def _dropped(target: Any, flags: int, *args: Any) -> int:
        if Path(target) == part:
            raise _unreachable_share(Path(target))
        return os.open(target, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_dropped))
    with pytest.raises(uploads.UploadStorageUnreachableError):
        await getattr(store, read)(meta.file_id)


async def test_the_route_answers_an_unreachable_storage_503_and_the_console_names_it(
    engine: Engine,  # noqa: F811 - the imported fixture
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    root = tmp_path / "uploads"
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = reproving_transport(PW, app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        fid = (
            await c.post("/uploads", files={"file": ("x.hl7", ADT, "text/plain")}, headers=h)
        ).json()["file_id"]
        blob = root / f"{fid}.blob"
        monkeypatch.setattr(uploads, "os", _OsLstatRaises(blob, _unreachable_share))
        _failing_unlink(
            monkeypatch, blob, lambda p: OSError(errno.EIO, "Input/output error", str(p))
        )
        r = await c.delete(f"/uploads/{fid}", headers=h)
        assert r.status_code == 503, r.text
        assert "could not be confirmed" in r.json()["detail"]
    # r5 item 2: the attempt is recorded with its outcome unknown, never as nothing removed. On
    # ee36e28d9d6 no row was written.
    rows = [a for a in await engine.store.list_audit() if a["action"] == "upload.delete"]
    assert [json.loads(str(a["detail"]))["body_removed"] for a in rows] == ["unknown"]


# --- r5: every caller gets the storage 503, a gone sidecar is not kept, and more network losses ---


def test_the_console_names_each_storage_outage() -> None:
    busy = HTTPException(503, "x", headers={"Retry-After": "5"})
    assert ul._refusal_code(busy, ul._DELETE_CODES) == ul.KEY_SERVICE_BUSY_CODE
    busy.storage_unreachable = True  # type: ignore[attr-defined]
    assert ul._refusal_code(busy, ul._DELETE_CODES) == ul.STORAGE_UNREACHABLE_CODE
    busy.outcome_unconfirmed = True  # type: ignore[attr-defined]
    code = ul._refusal_code(busy, ul._DELETE_CODES)
    assert code == ul.DELETE_UNCONFIRMED_CODE
    assert "could not be confirmed" in ul._LIST_NOTICES[code]


async def test_an_owner_meets_the_storage_503_not_a_404_when_the_share_is_down(
    engine: Engine,  # noqa: F811 - the imported fixture
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # r5 item 1. On ee36e28d9d6 _authorized_upload_meta answered 404 to every caller without
    # FILES_ACCESS_ANY, so an owner was told their file was gone.
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    root = tmp_path / "uploads"
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = reproving_transport(PW, app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        fid = (
            await c.post("/uploads", files={"file": ("x.hl7", ADT, "text/plain")}, headers=h)
        ).json()["file_id"]
        sidecar = root / f"{fid}.meta"

        def _dropped(target: Any, flags: int, *args: Any) -> int:
            if Path(target) == sidecar:
                raise _unreachable_share(Path(target))
            return os.open(target, flags, *args)

        monkeypatch.setattr(uploads, "os", _OsWith(_dropped))
        for r in (
            await c.get(f"/uploads/{fid}/messages", headers=h),
            await c.delete(f"/uploads/{fid}", headers=h),
        ):
            assert r.status_code == 503, r.text
            assert "could not be reached" in r.json()["detail"]
    assert not [a for a in await engine.store.list_audit() if a["action"] == "upload.delete"]
    assert sidecar.is_file()


async def test_a_sidecar_gone_inside_the_lock_is_not_recorded_as_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # r5 item 3. On ee36e28d9d6 the removal read sidecar_removed False, which the route wrote as
    # sidecar_kept: true for a sidecar that was not there.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    real_lock = uploads._pair_lock

    @contextlib.contextmanager
    def _sidecar_raced(path: Path, **kwargs: Any) -> Iterator[None]:
        _sidecar(store, meta.file_id).unlink()
        with real_lock(path, **kwargs):
            yield

    monkeypatch.setattr(uploads, "_pair_lock", _sidecar_raced)
    removal = await store.delete(meta.file_id)
    assert (removal.body_removed, removal.sidecar_removed) == (True, False)
    assert removal.sidecar_was_there is False


@pytest.mark.parametrize("winerror", [64, 59, 1231])
async def test_an_open_that_lost_its_share_with_einval_is_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, winerror: int
) -> None:
    # r5 item 4: a share that drops mid-session answers EINVAL with a network winerror. On
    # ee36e28d9d6 it was re-raised as EINVAL, a 500.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    part = _blob(store, meta.file_id)

    def _lost(target: Any, flags: int, *args: Any) -> int:
        if Path(target) == part:
            exc = OSError(errno.EINVAL, "The specified network name is no longer available")
            exc.winerror = winerror  # type: ignore[attr-defined,misc,unused-ignore]
            raise exc
        return os.open(target, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_lost))
    with pytest.raises(uploads.UploadStorageUnreachableError):
        await store.read_bytes(meta.file_id)


def test_path_reach_names_the_network_losses_and_not_eio() -> None:
    from messagefoundry.path_reach import is_unreachable

    for code in (53, 67, 51, 59, 64, 1222, 1231, 1232):
        exc = OSError(errno.EINVAL, "x")
        exc.winerror = code  # type: ignore[attr-defined,misc,unused-ignore]
        assert is_unreachable(exc), code
    for name in ("ESTALE", "EHOSTDOWN", "ENETDOWN", "ENETUNREACH"):
        posix = getattr(errno, name, None)
        if posix is not None:
            assert is_unreachable(OSError(posix, name)), name
    # Controls: EIO is a device fault too, and a winerror that is no int is no answer.
    assert not is_unreachable(OSError(errno.EIO, "Input/output error"))
    odd = OSError(errno.EINVAL, "x")
    odd.winerror = "64"  # type: ignore[attr-defined,misc,unused-ignore]
    assert not is_unreachable(odd)


def test_in_use_reads_only_an_int_winerror() -> None:
    # r3 item 10. On ee36e28d9d6 an unhashable winerror raised TypeError inside the delete.
    odd = PermissionError(errno.EACCES, "x")
    odd.winerror = [32]  # type: ignore[attr-defined,misc,unused-ignore]
    assert uploads._in_use(odd) is False
    text = PermissionError(errno.EACCES, "x")
    text.winerror = "32"  # type: ignore[attr-defined,misc,unused-ignore]
    assert uploads._in_use(text) is False
