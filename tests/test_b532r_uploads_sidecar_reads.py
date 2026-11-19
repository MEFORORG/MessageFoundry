# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How an upload's sidecar and body are read (BACKLOG #5387 added item 1, #5388 added item 2).

A planted small stamp is refused rather than read as decades old. A byte-order mark or whitespace
around a sidecar does not make it damaged. A sidecar is read with a size cap and without following
a file swapped in after its check. A file the engine is not permitted to read is a handled refusal,
not a server error. Synthetic data only."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.uploads as uploads
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.uploads import (
    UploadDamagedError,
    UploadedFileMeta,
    UploadFieldError,
    UploadStore,
    UploadUnreadableError,
)

_BODY = b"synthetic diagnostic line\n"
_DAY = 86_400


def _store(root: Path, key: str | None = None) -> UploadStore:
    cipher = make_cipher(key, write_v2=True) if key is not None else make_cipher(None)
    return UploadStore(root, cipher, max_bytes=4096)


async def _saved(store: UploadStore) -> UploadedFileMeta:
    return await store.save(data=_BODY, filename="a.txt", uploader="op", uploader_id="u-op")


def _sidecar(store: UploadStore, fid: str) -> Path:
    return store._root / f"{fid}.meta"  # noqa: SLF001 - the test plants a file at the seam


def _blob(store: UploadStore, fid: str) -> Path:
    return store._root / f"{fid}.blob"  # noqa: SLF001


def _age(*paths: Path, days: float) -> None:
    stamp = time.time() - days * _DAY
    for path in paths:
        os.utime(path, (stamp, stamp))


# --- a small positive planted stamp ---------------------------------------------------------------


@pytest.mark.parametrize("stamp", [1, 1.0, 1_000_000_000.0, uploads._MIN_SIDECAR_STAMP - 1])
async def test_a_small_positive_stamp_is_refused_and_not_pruned_on_the_first_pass(
    tmp_path: Path, stamp: float
) -> None:
    # On origin/main any stamp above 0 was accepted, so a planted 1 read as decades old and the
    # first prune pass deleted a pair that had just landed.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    d = json.loads(sidecar.read_text(encoding="utf-8"))
    d["uploaded_at"] = stamp
    sidecar.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)
    assert (await store.prune_expired(retention_days=30)).pruned == []
    assert sidecar.exists() and _blob(store, meta.file_id).exists()
    # Still aged by its pair on disk, as any refused sidecar is.
    _age(sidecar, _blob(store, meta.file_id), days=60)
    assert [m.file_id for m in (await store.prune_expired(retention_days=30)).pruned] == [
        meta.file_id
    ]


async def test_a_stamp_at_the_floor_is_read(tmp_path: Path) -> None:
    # Control: the floor itself is a stamp the reader takes, and the prune ages it by that stamp.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    d = json.loads(sidecar.read_text(encoding="utf-8"))
    d["uploaded_at"] = uploads._MIN_SIDECAR_STAMP
    sidecar.write_text(json.dumps(d), encoding="utf-8")
    assert (await store.get_meta(meta.file_id)).uploaded_at == uploads._MIN_SIDECAR_STAMP


# --- a byte-order mark or whitespace around a sidecar ---------------------------------------------


_PADS = {
    "bom": ("﻿", ""),
    "whitespace": ("\r\n \t", "\n\n"),
    "bom-and-whitespace": (" ﻿\n", "\r\n"),
}


@pytest.mark.parametrize("pad", list(_PADS))
async def test_a_padded_plaintext_sidecar_is_read(tmp_path: Path, pad: str) -> None:
    # On origin/main a byte-order mark failed the JSON parse, so the upload was refused as damaged,
    # left out of its owner's listing and quota, and aged on disk by the prune.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    lead, tail = _PADS[pad]
    sidecar.write_text(lead + sidecar.read_text(encoding="utf-8") + tail, encoding="utf-8")
    assert await store.get_meta(meta.file_id) == meta
    assert [m.file_id for m in await store.list_files()] == [meta.file_id]


@pytest.mark.parametrize("pad", list(_PADS))
async def test_a_padded_sealed_sidecar_on_a_keyless_store_is_never_pruned(
    tmp_path: Path, pad: str
) -> None:
    # A sidecar sealed under a key, read by a store with no key, is the cipher-declined kind: the
    # key recovers it, so the prune never removes it. On origin/main a byte-order mark or leading
    # whitespace hid the marker, so the same file read as damaged and the prune deleted the pair
    # once it was old on disk.
    root = tmp_path / "uploads"
    meta = await _saved(_store(root, generate_key()))
    keyless = _store(root)
    sidecar, body = _sidecar(keyless, meta.file_id), _blob(keyless, meta.file_id)
    lead, tail = _PADS[pad]
    sidecar.write_text(lead + sidecar.read_text(encoding="utf-8") + tail, encoding="utf-8")
    with pytest.raises(UploadUnreadableError) as refused:
        await keyless.get_meta(meta.file_id)
    assert not isinstance(refused.value, UploadDamagedError)
    _age(sidecar, body, days=60)
    assert (await keyless.prune_expired(retention_days=30)).pruned == []
    assert sidecar.exists() and body.exists()


async def test_a_padded_sealed_sidecar_reads_under_its_key(tmp_path: Path) -> None:
    key = generate_key()
    store = _store(tmp_path / "uploads", key)
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    sidecar.write_text("﻿" + sidecar.read_text(encoding="utf-8") + "\r\n", encoding="utf-8")
    assert await store.get_meta(meta.file_id) == meta


async def test_a_whitespace_only_sidecar_is_damaged(tmp_path: Path) -> None:
    # Control: padding is not a sidecar, so one that holds nothing else is refused as damaged.
    store = _store(tmp_path / "uploads", generate_key())
    meta = await _saved(store)
    _sidecar(store, meta.file_id).write_text(" \r\n﻿\t", encoding="utf-8")
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)


# --- the sidecar size cap -------------------------------------------------------------------------


async def test_a_sidecar_over_the_cap_is_damaged_and_never_read_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On origin/main every reader read a sidecar whole, the scan under _quota_lock included, so a
    # planted one of any size was read into memory there.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    sound = sidecar.read_text(encoding="utf-8")
    monkeypatch.setattr(uploads, "_SIDECAR_LIMIT", len(sound) + 64)
    sidecar.write_text(sound + " " * 65, encoding="utf-8")
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)
    with pytest.raises(UploadDamagedError):
        await store.delete(meta.file_id)
    assert await store.list_files() == []
    assert sidecar.exists()
    # Control: the same sidecar at the cap is read.
    sidecar.write_text(sound + " " * 64, encoding="utf-8")
    assert await store.get_meta(meta.file_id) == meta


async def test_save_refuses_metadata_the_reader_would_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "uploads")
    monkeypatch.setattr(uploads, "_SIDECAR_LIMIT", 32)
    with pytest.raises(UploadFieldError):
        await _saved(store)
    root = store._root  # noqa: SLF001 - nothing was left behind
    assert not root.exists() or not any(root.iterdir())


# --- a file swapped in after its check, and one the engine may not read ---------------------------


class _OsWith:
    """The ``os`` module as ``uploads`` sees it, with ``open`` replaced, so the test changes what
    the store's own open meets and nothing else in the process."""

    def __init__(self, open_: Any) -> None:
        self._open = open_

    def __getattr__(self, name: str) -> Any:
        return self._open if name == "open" else getattr(os, name)


async def test_a_sidecar_swapped_after_its_check_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On origin/main the lstat check and the read were separate opens, so a file replaced between
    # them was read. The swap here is another upload's sound sidecar under this one's name.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    other = tmp_path / "other.meta"
    other.write_text(sidecar.read_text(encoding="utf-8"), encoding="utf-8")

    def _swap_then_open(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == sidecar:
            os.replace(other, sidecar)
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_swap_then_open))
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFOs and O_NONBLOCK")
async def test_a_fifo_swapped_in_after_its_check_does_not_block_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)

    def _fifo_then_open(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == sidecar:
            sidecar.unlink()
            os.mkfifo(sidecar)
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_fifo_then_open))
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)


@pytest.mark.skipif(sys.platform == "win32", reason="O_NOFOLLOW")
async def test_a_link_swapped_in_after_its_check_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    target = tmp_path / "elsewhere.meta"
    target.write_text(sidecar.read_text(encoding="utf-8"), encoding="utf-8")

    def _link_then_open(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == sidecar:
            sidecar.unlink()
            sidecar.symlink_to(target)
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_link_then_open))
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)


@pytest.mark.parametrize("part", ["meta", "blob"])
async def test_a_part_the_engine_may_not_read_is_a_handled_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, part: str
) -> None:
    # On origin/main a PermissionError escaped get_meta, read_bytes and delete, so the routes
    # answered 500.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    denied = store._root / f"{meta.file_id}.{part}"  # noqa: SLF001

    def _deny(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == denied:
            raise PermissionError(13, "Permission denied", str(path))
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_deny))
    if part == "meta":
        with pytest.raises(UploadDamagedError):
            await store.get_meta(meta.file_id)
        with pytest.raises(UploadDamagedError):
            await store.delete(meta.file_id)
        # Nothing was removed.
        assert denied.exists() and _blob(store, meta.file_id).exists()
        # The scan skips it, and the prune does not take it, however old.
        assert await store.list_files() == []
        _age(denied, _blob(store, meta.file_id), days=60)
        assert (await store.prune_expired(retention_days=30)).pruned == []
    else:
        with pytest.raises(UploadDamagedError):
            await store.read_bytes(meta.file_id)
