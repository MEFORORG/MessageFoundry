# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How an upload's sidecar and body are read (BACKLOG #5387 added item 1, #5388 added item 2).

A planted small stamp is refused rather than read as decades old. A byte-order mark or whitespace
around a sidecar does not make it damaged. A sidecar is read with a size cap and without following
a file swapped in after its check. A file the engine is not permitted to read is a handled refusal,
not a server error. Synthetic data only."""

from __future__ import annotations

import errno
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
    UploadAccessError,
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
    "bom": ("\ufeff", ""),
    "whitespace": ("\r\n \t", "\n\n"),
    "bom-and-whitespace": (" \ufeff\n", "\r\n"),
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
    sidecar.write_text("\ufeff" + sidecar.read_text(encoding="utf-8") + "\r\n", encoding="utf-8")
    assert await store.get_meta(meta.file_id) == meta


async def test_a_whitespace_only_sidecar_is_damaged(tmp_path: Path) -> None:
    # Control: padding is not a sidecar, so one that holds nothing else is refused as damaged.
    store = _store(tmp_path / "uploads", generate_key())
    meta = await _saved(store)
    _sidecar(store, meta.file_id).write_text(" \r\n\ufeff\t", encoding="utf-8")
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


async def test_a_regular_file_replaced_after_its_check_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Control: an atomic replace by a regular file, as a rotate-key reseal does, is not a refusal.
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
    assert await store.get_meta(meta.file_id) == meta


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


async def test_a_link_swapped_in_after_its_check_is_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # On origin/main the lstat check and the read were separate opens, so a link swapped in
    # between them was followed. POSIX refuses it at the open (O_NOFOLLOW); Windows, which has no
    # such flag, by the check of the name after the open.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    target = tmp_path / "elsewhere.meta"
    target.write_text(sidecar.read_text(encoding="utf-8"), encoding="utf-8")
    probe = tmp_path / "probe"
    try:
        probe.symlink_to(target)
    except OSError:
        pytest.skip("this account cannot create a symbolic link")

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
    # Follow-up: refused as access, never as damage an operator may then delete for good.
    if part == "meta":
        with pytest.raises(UploadAccessError) as read:
            await store.get_meta(meta.file_id)
        assert not isinstance(read.value, UploadDamagedError)
        with pytest.raises(UploadAccessError):
            await store.delete(meta.file_id)
        # Nothing was removed.
        assert denied.exists() and _blob(store, meta.file_id).exists()
        # The scan skips it, and the prune does not take it, however old.
        assert await store.list_files() == []
        _age(denied, _blob(store, meta.file_id), days=60)
        assert (await store.prune_expired(retention_days=30)).pruned == []
    else:
        with pytest.raises(UploadAccessError) as read:
            await store.read_bytes(meta.file_id)
        assert not isinstance(read.value, UploadDamagedError)


# --- the padding tolerance holds in rotate-key, the startup count and the tag alert -------------


async def test_rotate_key_reseals_a_padded_sealed_sidecar_rather_than_sealing_it_twice(
    tmp_path: Path,
) -> None:
    # Review round 1: the reseal decided "plaintext" on the raw text, so a padded sealed sidecar,
    # which the reader takes, was sealed a second time and then refused on every read.
    key = generate_key()
    store = _store(tmp_path / "uploads", key)
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    sidecar.write_text("\ufeff " + sidecar.read_text(encoding="utf-8"), encoding="utf-8")
    assert await store.warn_if_unsealed() == 0
    result = await store.reseal_to_active()
    assert result.sealed_plaintext == 0
    assert await store.get_meta(meta.file_id) == meta


async def test_a_padded_moved_sidecar_still_raises_the_tag_alert(tmp_path: Path) -> None:
    # Review round 1: the alert's own checks read the raw text, so padding hid the marker from
    # them and a sidecar moved under another id with a byte-order mark in front went unreported.
    key = generate_key()
    store = UploadStore(tmp_path / "uploads", make_cipher(key, write_v2=True), max_bytes=4096)
    reports: list[tuple[str, str]] = []
    store._cipher.set_tag_failure_hook(lambda table, reason: reports.append((table, reason)))  # type: ignore[attr-defined]  # noqa: SLF001
    a = await _saved(store)
    b = await _saved(store)
    moved = "\ufeff" + _sidecar(store, a.file_id).read_text(encoding="utf-8")
    _sidecar(store, b.file_id).write_text(moved, encoding="utf-8")
    assert [m.file_id for m in await store.list_files()] == [a.file_id]
    assert len(reports) == 1 and b.file_id[:12] in reports[0][1]


async def test_a_body_stored_under_a_larger_upload_limit_is_still_served(tmp_path: Path) -> None:
    # Review round 1: no size cap on a body read, so lowering max_upload_bytes does not turn a
    # sound upload stored before it into a damaged one.
    root = tmp_path / "uploads"
    data = b"x" * 9000 + b"\n"
    meta = await UploadStore(root, make_cipher(None), max_bytes=10_000).save(
        data=data, filename="a.txt", uploader="op", uploader_id="u-op"
    )
    assert await UploadStore(root, make_cipher(None), max_bytes=10).read_bytes(meta.file_id) == data


# --- review round 2 --------------------------------------------------------------------------------


@pytest.mark.parametrize("part", ["meta", "blob"])
async def test_a_transient_os_error_is_not_answered_as_a_damaged_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, part: str
) -> None:
    # Review round 2: too many open files may pass on a retry, so it propagates rather than read
    # as damage an operator may then delete for good.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    busy = store._root / f"{meta.file_id}.{part}"  # noqa: SLF001

    def _emfile(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == busy:
            raise OSError(errno.EMFILE, "Too many open files", str(path))
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_emfile))
    if part == "meta":
        with pytest.raises(OSError) as raised:
            await store.get_meta(meta.file_id)
        assert not isinstance(raised.value, UploadDamagedError)
        with pytest.raises(OSError):
            await store.delete(meta.file_id)
        assert busy.exists() and _blob(store, meta.file_id).exists()
    else:
        with pytest.raises(OSError):
            await store.read_bytes(meta.file_id)


async def test_the_startup_count_does_not_count_an_oversized_padded_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review round 2: the count read past any amount of padding, and called a sidecar the reader
    # refuses as oversized a sealed one. It is now read as the reader reads it, or not counted.
    key = generate_key()
    store = _store(tmp_path / "uploads", key)
    meta = await _saved(store)
    sidecar = _sidecar(store, meta.file_id)
    sealed = sidecar.read_text(encoding="utf-8")
    monkeypatch.setattr(uploads, "_SIDECAR_LIMIT", len(sealed) + 64)
    sidecar.write_text(" " * 32 + sealed, encoding="utf-8")
    assert await store.warn_if_unsealed() == 0
    sidecar.write_text("x" * (len(sealed) + 128), encoding="utf-8")
    assert await store.warn_if_unsealed() == 0


async def test_rotate_key_leaves_a_sidecar_that_would_seal_past_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review round 2: sealing grows a sidecar by a third, so a plaintext one under the cap could be
    # written past it, then refused by every read and aged out by the prune. Follow-up: it was then
    # counted a skip, which failed every rotate-key run and held the rotation record open for good,
    # though nothing of it is under the prior key. It is now its own terminal count.
    root = tmp_path / "uploads"
    meta = await _saved(_store(root))
    sidecar = root / f"{meta.file_id}.meta"
    plain = sidecar.read_text(encoding="utf-8")
    monkeypatch.setattr(uploads, "_PLAIN_SIDECAR_LIMIT", len(plain.encode("utf-8")) - 1)
    result = await _store(root, generate_key()).reseal_to_active()
    assert (result.skipped, result.too_long) == (0, 1)
    assert not result.incomplete
    assert result.resealed == 1  # the body is still sealed
    assert sidecar.read_text(encoding="utf-8") == plain
