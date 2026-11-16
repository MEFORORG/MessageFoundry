# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A sidecar's JSON is checked, never trusted (BACKLOG #5387), and a damaged one is a handled
refusal on the by-id reads, never an uncaught error (BACKLOG #5388). Synthetic data only."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.uploads import (
    UploadDamagedError,
    UploadedFileMeta,
    UploadStore,
    UploadUnreadableError,
    sanitize_filename,
)

_BODY = b"synthetic diagnostic line\n"


def _keyless(tmp_path: Path) -> UploadStore:
    # The identity cipher passes unmarked sidecars, which is where a planted one is read.
    return UploadStore(tmp_path / "uploads", make_cipher(None), max_bytes=4096)


def _keyed(tmp_path: Path) -> UploadStore:
    return UploadStore(
        tmp_path / "uploads", make_cipher(generate_key(), write_v2=True), max_bytes=4096
    )


async def _saved(store: UploadStore, name: str = "a.txt") -> UploadedFileMeta:
    return await store.save(data=_BODY, filename=name, uploader="op", uploader_id="u-op")


def _sidecar(store: UploadStore, fid: str) -> Path:
    return store._root / f"{fid}.meta"  # noqa: SLF001 - the test plants a file at the seam


def _plant(store: UploadStore, fid: str, **fields: Any) -> None:
    path = _sidecar(store, fid)
    d = json.loads(path.read_text(encoding="utf-8"))
    d.update(fields)
    path.write_text(json.dumps(d), encoding="utf-8")


async def test_a_sidecar_naming_another_upload_cannot_steer_the_prune(tmp_path: Path) -> None:
    store = _keyless(tmp_path)
    victim = await _saved(store, "victim.txt")
    planted = await _saved(store, "planted.txt")
    # The planted sidecar names the victim and is aged past retention.
    _plant(store, planted.file_id, file_id=victim.file_id, uploaded_at=time.time() - 90 * 86_400)
    result = await store.prune_expired()
    assert [m.file_id for m in result.pruned] == []
    assert _sidecar(store, victim.file_id).exists()
    assert [m.file_id for m in await store.list_files()] == [victim.file_id]


@pytest.mark.parametrize(
    "fields",
    [
        {"size": -10_000_000},
        {"message_count": -1},
        {"size": True},
        {"size": "12"},
        {"uploaded_at": float("inf")},
        {"uploaded_at": -1.0},
        {"uploaded_at": 10**400},
        {"uploaded_at": time.time() + 10 * 86_400},
        {"size": 10**4000},
        {"uploaded_at": "now"},
        {"uploader_id": ["u-op"]},
        {"filename": {"x": 1}},
        {"filename": "\ud800x.txt"},
        {"filename": "a" * 300 + ".txt"},
        {"uploader": "u" * 2000},
        {"sha256": "0" * 65},
        {"content_type": "x" * 65},
    ],
    ids=lambda f: next(iter(f)),
)
async def test_a_sidecar_with_an_out_of_shape_field_is_left_out(
    tmp_path: Path, fields: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    store = _keyless(tmp_path)
    kept = await _saved(store, "kept.txt")
    bad = await _saved(store, "bad.txt")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        # Positive control: an untouched sidecar lists and logs no refusal.
        assert len(await store.list_files()) == 2
        assert not any("malformed metadata" in r.getMessage() for r in caplog.records)
        _plant(store, bad.file_id, **fields)
        assert [m.file_id for m in await store.list_files()] == [kept.file_id]
    assert any("malformed metadata" in r.getMessage() for r in caplog.records)


async def test_a_sidecar_at_the_text_bounds_still_reads(tmp_path: Path) -> None:
    # The bounds sit past anything save writes, so a field at the bound is not refused.
    store = _keyless(tmp_path)
    meta = await _saved(store)
    _plant(store, meta.file_id, uploader="u" * 1024, sha256="0" * 64, filename="a" * 255)
    assert (await store.get_meta(meta.file_id)).uploader == "u" * 1024


async def test_a_planted_filename_is_sanitized(tmp_path: Path) -> None:
    store = _keyless(tmp_path)
    meta = await _saved(store)
    _plant(store, meta.file_id, filename="..\\..\\evil\x07.txt")
    assert (await store.get_meta(meta.file_id)).filename == "evil.txt"


def test_sanitizing_a_name_cut_on_a_space_is_a_fixed_point() -> None:
    # Each sidecar read sanitizes the stored name again, so a second pass must change nothing.
    once = sanitize_filename("a" * 254 + " " + "b" * 10 + ".txt")
    assert not once.endswith(" ")
    assert sanitize_filename(once) == once


async def test_a_well_formed_sidecar_still_reads(tmp_path: Path) -> None:
    for store in (
        _keyless(tmp_path / "plain"),
        _keyed(tmp_path / "keyed"),
    ):
        meta = await _saved(store)
        assert await store.get_meta(meta.file_id) == meta
        assert await store.list_files() == [meta]


# --- BACKLOG #5388: a damaged file is a handled refusal on every by-id read ----------------------

_DAMAGED_SIDECARS = {
    "not-utf8": b"\xff\xfe\x00 not utf-8",
    "not-json": b"{not json",
    "nested": b"[" * 100_000 + b"]" * 100_000,
    "long-int": b'{"size": ' + b"9" * 5000 + b"}",
    "not-object": b"[1, 2]",
}


@pytest.mark.parametrize("raw", list(_DAMAGED_SIDECARS.values()), ids=list(_DAMAGED_SIDECARS))
async def test_a_damaged_sidecar_is_refused_on_get_meta_and_delete(
    tmp_path: Path, raw: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    store = _keyless(tmp_path)
    meta = await _saved(store)
    _sidecar(store, meta.file_id).write_bytes(raw)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        with pytest.raises(UploadDamagedError):
            await store.get_meta(meta.file_id)
        with pytest.raises(UploadDamagedError):
            await store.delete(meta.file_id)
    # Refused, so nothing was removed, and the scan leaves it out rather than failing.
    assert _sidecar(store, meta.file_id).exists()
    assert await store.list_files() == []
    assert any("damaged, refused" in r.getMessage() for r in caplog.records)


async def test_a_damaged_sidecar_on_a_keyed_store_is_refused_on_delete(tmp_path: Path) -> None:
    store = _keyed(tmp_path)
    meta = await _saved(store)
    _sidecar(store, meta.file_id).write_bytes(b"\xff\xfe\x00 not utf-8")
    with pytest.raises(UploadUnreadableError):
        await store.get_meta(meta.file_id)
    with pytest.raises(UploadUnreadableError):
        await store.delete(meta.file_id)
    assert _sidecar(store, meta.file_id).exists()


async def test_a_never_sealable_sidecar_with_a_bad_tail_is_deleted(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Plaintext, not UTF-8 only past the part the class check reads, over a missing body: the kind
    # the scan classes, so delete removes it, and logs no refusal for it.
    store = _keyed(tmp_path)
    meta = await _saved(store)
    (store._root / f"{meta.file_id}.blob").unlink()  # noqa: SLF001
    _sidecar(store, meta.file_id).write_bytes(b" " * (4 * 64 * 1024) + b"\xff")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        # Positive control: the read refuses it and that refusal is captured.
        with pytest.raises(UploadDamagedError):
            await store.get_meta(meta.file_id)
        assert any("damaged, refused" in r.getMessage() for r in caplog.records)
        caplog.clear()
        removed = await store.delete(meta.file_id)
    assert removed.file_id == meta.file_id
    assert not _sidecar(store, meta.file_id).exists()
    assert not any("damaged, refused" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    "raw",
    [b"\xff\xfe not utf-8", b"not base64!", b"%%%%", b"abcd!", b"QUJ", "QUJDé".encode()],
    ids=["not-utf8", "odd-alphabet", "no-alphabet", "stray-char", "bad-padding", "non-ascii"],
)
async def test_a_damaged_body_is_refused_on_read_bytes(tmp_path: Path, raw: bytes) -> None:
    store = _keyless(tmp_path)
    meta = await _saved(store)
    (store._root / f"{meta.file_id}.blob").write_bytes(raw)  # noqa: SLF001
    with pytest.raises(UploadDamagedError):
        await store.read_bytes(meta.file_id)


def _blob(store: UploadStore, fid: str) -> Path:
    return store._root / f"{fid}.blob"  # noqa: SLF001 - the test plants a file at the seam


@pytest.mark.parametrize("part", ["meta", "blob"])
async def test_a_directory_in_place_of_a_file_is_refused_on_every_by_id_read(
    tmp_path: Path, part: str
) -> None:
    # It answered a server error: the read met IsADirectoryError, or PermissionError on Windows.
    store = _keyless(tmp_path)
    meta = await _saved(store)
    path = _sidecar(store, meta.file_id) if part == "meta" else _blob(store, meta.file_id)
    path.unlink()
    path.mkdir()
    reads = [store.delete, store.get_meta if part == "meta" else store.read_bytes]
    for read in reads:
        with pytest.raises(UploadDamagedError):
            await read(meta.file_id)
    assert path.is_dir()
    # Positive control: the same read of a sound upload succeeds.
    sound = await _saved(store, "sound.txt")
    assert await store.read_bytes(sound.file_id) == _BODY
    assert await store.get_meta(sound.file_id) == sound


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
@pytest.mark.parametrize("part", ["meta", "blob"])
async def test_a_fifo_in_place_of_a_file_is_refused_without_blocking(
    tmp_path: Path, part: str
) -> None:
    store = _keyless(tmp_path)
    meta = await _saved(store)
    path = _sidecar(store, meta.file_id) if part == "meta" else _blob(store, meta.file_id)
    path.unlink()
    os.mkfifo(path)
    read = store.get_meta if part == "meta" else store.read_bytes
    # A FIFO sidecar is refused by delete too, since delete opens the sidecar; a FIFO body is only
    # unlinked, so delete removes the pair.
    calls = (read, store.delete) if part == "meta" else (read,)
    for call in calls:
        with pytest.raises(UploadDamagedError):
            # An open of the FIFO would block the worker thread for good.
            await asyncio.wait_for(call(meta.file_id), timeout=10)
    if part == "blob":
        await asyncio.wait_for(store.delete(meta.file_id), timeout=10)
        assert not path.exists() and not _sidecar(store, meta.file_id).exists()


async def test_a_genuine_upload_dated_ahead_of_a_stepped_back_clock_is_not_pruned(
    tmp_path: Path,
) -> None:
    # Its uploaded_at is more than a day ahead of the prune's clock, so it is refused, but it is
    # not damaged: it must wait for wall time, not be pruned by its mtime, which is ahead too.
    store = _keyed(tmp_path)
    meta = await _saved(store)
    result = await store.prune_expired(now=time.time() - 3 * 86_400, retention_days=30)
    assert result.pruned == []
    assert await store.get_meta(meta.file_id) == meta


_DAY = 86_400


def _age(*paths: Path, days: float) -> None:
    stamp = time.time() - days * _DAY
    for path in paths:
        os.utime(path, (stamp, stamp))


_REFUSED_PLANTS = {
    # A sidecar dated far ahead, which the shape check refuses, on a cipher that passes plaintext.
    "far-future": (_keyless, b"plant"),
    # One that is not JSON, on the same cipher.
    "passthrough-not-json": (_keyless, b"{not json"),
    # One that is not UTF-8, on a keyed store, over a text body: not the never-sealable kind.
    "keyed-not-utf8": (_keyed, b"\xff\xfe not utf-8"),
}


@pytest.mark.parametrize("case", list(_REFUSED_PLANTS), ids=list(_REFUSED_PLANTS))
async def test_a_refused_sidecar_is_pruned_once_old_on_disk_and_not_before(
    tmp_path: Path, case: str, caplog: pytest.LogCaptureFixture
) -> None:
    factory, raw = _REFUSED_PLANTS[case]
    store = factory(tmp_path)
    meta = await _saved(store)
    if case == "far-future":
        _plant(store, meta.file_id, uploaded_at=time.time() + 400 * _DAY)
    else:
        _sidecar(store, meta.file_id).write_bytes(raw)
    sidecar, body = _sidecar(store, meta.file_id), _blob(store, meta.file_id)
    assert await store.list_files() == []  # refused, so not trusted for the listing
    rows: list[UploadedFileMeta] = []

    async def _audit(row: UploadedFileMeta) -> None:
        rows.append(row)

    # Fresh on disk: not due.
    assert (await store.prune_expired(retention_days=30, audit=_audit)).pruned == []
    # Only the sidecar old: the body's mtime still holds it (the later of the two).
    _age(sidecar, days=60)
    assert (await store.prune_expired(retention_days=30, audit=_audit)).pruned == []
    assert sidecar.exists() and body.exists()
    _age(sidecar, body, days=60)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = await store.prune_expired(retention_days=30, audit=_audit)
    assert [m.file_id for m in result.pruned] == [meta.file_id]
    assert not sidecar.exists() and not body.exists()
    # Nothing the sidecar claims reaches the permanent audit row.
    assert [(r.file_id, r.uploader, r.uploader_id, r.filename) for r in rows] == [
        (meta.file_id, "", "", "")
    ]
    assert any("whose sidecar was refused" in r.getMessage() for r in caplog.records)


async def test_a_sidecar_the_cipher_declines_is_still_not_pruned(tmp_path: Path) -> None:
    # Control for the test above: a key rotated away must not destroy data, so a sidecar the cipher
    # declines (a plaintext one over a text body, on a keyed store) is not aged on disk.
    store = _keyed(tmp_path)
    meta = await _saved(store)
    _sidecar(store, meta.file_id).write_text(json.dumps(asdict(meta)), encoding="utf-8")
    _age(_sidecar(store, meta.file_id), _blob(store, meta.file_id), days=60)
    assert (await store.prune_expired(retention_days=30)).pruned == []
    assert _sidecar(store, meta.file_id).exists()


def _chain(exc: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    cur: BaseException | None = exc
    while cur is not None and cur not in seen:
        seen.append(cur)
        cur = cur.__cause__ or cur.__context__
    return seen


async def test_a_refusal_carries_no_file_content_on_its_chain(tmp_path: Path) -> None:
    # The decode error holds the whole file (.doc, .object); it must not ride the refusal's chain.
    store = _keyless(tmp_path)
    meta = await _saved(store)
    _sidecar(store, meta.file_id).write_bytes(b'{"filename": "SYNTH-SECRET", oops')
    (store._root / f"{meta.file_id}.blob").write_bytes(b"SYNTH-BODY \xff")  # noqa: SLF001
    for read in (store.get_meta, store.read_bytes, store.delete):
        with pytest.raises(UploadUnreadableError) as info:
            await read(meta.file_id)
        assert [type(e) for e in _chain(info.value)] == [UploadDamagedError]
