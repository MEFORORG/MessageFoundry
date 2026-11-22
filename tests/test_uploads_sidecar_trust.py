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
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.uploads import (
    UploadDamagedError,
    UploadedFileMeta,
    UploadFieldError,
    UploadQuotaError,
    UploadStore,
    UploadUnreadableError,
    sanitize_filename,
)

_BODY = b"synthetic diagnostic line\n"


def _keyless(tmp_path: Path) -> UploadStore:
    # The identity cipher passes unmarked sidecars, which is where a planted one is read.
    return UploadStore(tmp_path / "uploads", make_cipher(None), max_bytes=4096)


def _keyed(tmp_path: Path, *, max_files_per_user: int = 100) -> UploadStore:
    return UploadStore(
        tmp_path / "uploads",
        make_cipher(generate_key(), write_v2=True),
        max_bytes=4096,
        max_files_per_user=max_files_per_user,
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
        {"uploaded_at": 2**53 + 1},
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
        removed = (await store.delete(meta.file_id)).meta
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
    # Its uploaded_at is more than a day ahead of the prune's clock, but it is not damaged: it must
    # wait for wall time, not be pruned by its mtime, which is ahead too.
    store = _keyed(tmp_path)
    meta = await _saved(store)
    result = await store.prune_expired(now=time.time() - 3 * 86_400, retention_days=30)
    assert result.pruned == []
    assert await store.get_meta(meta.file_id) == meta


async def test_a_genuine_upload_under_a_stepped_back_clock_is_listed_billed_and_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Written while the clock read 400 days ahead, then the clock was stepped back to now. The
    # shape check reads no clock (BACKLOG #5387), so the upload is not hidden or unbilled.
    store = _keyed(tmp_path, max_files_per_user=1)
    ahead = time.time() + 400 * _DAY
    with monkeypatch.context() as m:
        m.setattr(time, "time", lambda: ahead)
        meta = await _saved(store)
    assert meta.uploaded_at == ahead
    assert [m.file_id for m in await store.list_files()] == [meta.file_id]
    assert await store.get_meta(meta.file_id) == meta
    assert await store.read_bytes(meta.file_id) == _BODY
    # Counted by the quota: a second upload by the same owner is over the one-file cap.
    with pytest.raises(UploadQuotaError):
        await _saved(store, "second.txt")


async def test_a_malformed_stamp_is_still_refused(tmp_path: Path) -> None:
    # Control for the test above: the shape check still refuses a stamp out of shape.
    store = _keyless(tmp_path)
    meta = await _saved(store)
    _plant(store, meta.file_id, uploaded_at=-1.0)
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)
    assert await store.list_files() == []


_DAY = 86_400


def _age(*paths: Path, days: float) -> None:
    stamp = time.time() - days * _DAY
    for path in paths:
        os.utime(path, (stamp, stamp))


def _overwrite(raw: bytes) -> Callable[[UploadStore, str], None]:
    def damage(store: UploadStore, fid: str) -> None:
        _sidecar(store, fid).write_bytes(raw)

    return damage


def _restamp(stamp: float | None) -> Callable[[UploadStore, str], None]:
    # BACKLOG #5387: a missing or non-positive stamp, read as the epoch, was past every window,
    # so the first prune deleted the body with no retention window.
    def damage(store: UploadStore, fid: str) -> None:
        path = _sidecar(store, fid)
        d = json.loads(path.read_text(encoding="utf-8"))
        d.pop("uploaded_at")
        if stamp is not None:
            d["uploaded_at"] = stamp
        path.write_text(json.dumps(d), encoding="utf-8")

    return damage


_REFUSED_PLANTS = {
    # A sidecar that is not JSON, on a cipher that passes plaintext.
    "passthrough-not-json": (_keyless, _overwrite(b"{not json")),
    # One that is not UTF-8, on a keyed store, over a text body: not the never-sealable kind.
    "keyed-not-utf8": (_keyed, _overwrite(b"\xff\xfe not utf-8")),
    # A stamp that is missing, 0 or negative, kept while fresh on disk however old it reads.
    "stamp-missing": (_keyless, _restamp(None)),
    "stamp-zero": (_keyless, _restamp(0)),
    "stamp-negative": (_keyless, _restamp(-1)),
}


@pytest.mark.parametrize("case", list(_REFUSED_PLANTS))
async def test_a_refused_sidecar_is_pruned_once_old_on_disk_and_not_before(
    tmp_path: Path, case: str, caplog: pytest.LogCaptureFixture
) -> None:
    factory, damage = _REFUSED_PLANTS[case]
    store = factory(tmp_path)
    meta = await _saved(store)
    damage(store, meta.file_id)
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


async def test_a_genuine_upload_is_pruned_at_its_real_age(tmp_path: Path) -> None:
    # Control for the test above: a sound stamp still ages by the stamp, whatever the mtimes say.
    store = _keyless(tmp_path)
    young = await _saved(store, "young.txt")
    old = await _saved(store, "old.txt")
    _plant(store, old.file_id, uploaded_at=time.time() - 31 * _DAY)
    _plant(store, young.file_id, uploaded_at=time.time() - 29 * _DAY)
    result = await store.prune_expired(retention_days=30)
    assert [m.file_id for m in result.pruned] == [old.file_id]
    assert [m.file_id for m in await store.list_files()] == [young.file_id]


@pytest.mark.parametrize("clock", [0.0, -86_400.0])
async def test_save_refuses_a_clock_the_reader_would_refuse(
    tmp_path: Path, clock: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    # BACKLOG #5387: a clock before 1970 would write a stamp the reader refuses, so save refuses
    # it up front rather than clamping it to a stamp the prune would delete at once.
    store = _keyless(tmp_path)
    monkeypatch.setattr(time, "time", lambda: clock)
    with pytest.raises(UploadFieldError):
        await _saved(store)
    monkeypatch.undo()
    assert await store.list_files() == []
    root = store._root  # noqa: SLF001 - nothing was written
    assert not root.exists() or not any(root.iterdir())


async def test_a_sound_sidecar_dated_far_ahead_is_aged_by_its_pair_on_disk(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Its stamp alone would never age out, so the prune reads the pair's mtimes instead, and never
    # an mtime ahead of the clock. Its own metadata is trusted for the listing and the audit row.
    store = _keyless(tmp_path)
    meta = await _saved(store)
    _plant(store, meta.file_id, uploaded_at=time.time() + 400 * _DAY)
    sidecar, body = _sidecar(store, meta.file_id), _blob(store, meta.file_id)
    assert [m.file_id for m in await store.list_files()] == [meta.file_id]
    rows: list[UploadedFileMeta] = []

    async def _audit(row: UploadedFileMeta) -> None:
        rows.append(row)

    assert (await store.prune_expired(retention_days=30, audit=_audit)).pruned == []
    _age(sidecar, days=60)
    assert (await store.prune_expired(retention_days=30, audit=_audit)).pruned == []
    _age(sidecar, body, days=-400)  # ahead of the clock on disk too: never pruned
    assert (await store.prune_expired(retention_days=30, audit=_audit)).pruned == []
    _age(sidecar, body, days=60)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = await store.prune_expired(retention_days=30, audit=_audit)
    assert [m.file_id for m in result.pruned] == [meta.file_id]
    assert not sidecar.exists() and not body.exists()
    assert [(r.file_id, r.uploader_id) for r in rows] == [(meta.file_id, "u-op")]
    assert any("uploaded_at is ahead of the clock" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("key", ["uploader", "uploader_id"])
async def test_save_refuses_an_account_field_the_reader_would_refuse(
    tmp_path: Path, key: str
) -> None:
    # BACKLOG #5387: save and the reader share one bound, so no write is one the reader refuses.
    store = _keyless(tmp_path)
    at_bound = {"uploader": "op", "uploader_id": "u-op", key: "u" * 1024}
    meta = await store.save(data=_BODY, filename="a.txt", **at_bound)
    assert await store.get_meta(meta.file_id) == meta
    assert [m.file_id for m in await store.list_files()] == [meta.file_id]
    for bad in ("u" * 1025, "op\ud800"):
        with pytest.raises(UploadFieldError) as info:
            await store.save(data=_BODY, filename="b.txt", **{**at_bound, key: bad})
        assert bad not in str(info.value)
    # Nothing was written by the refused saves.
    assert [m.file_id for m in await store.list_files()] == [meta.file_id]


async def test_a_lone_damaged_sidecar_is_pruned_with_a_log_line(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # No body, so no audit row is written; the log line is the removal's only record.
    store = _keyless(tmp_path)
    meta = await _saved(store)
    _blob(store, meta.file_id).unlink()
    _sidecar(store, meta.file_id).write_bytes(b"{not json")
    _age(_sidecar(store, meta.file_id), days=60)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        await store.prune_expired(retention_days=30)
    assert not _sidecar(store, meta.file_id).exists()
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


async def test_a_pair_sealed_under_a_key_is_not_damaged_on_a_keyless_store(tmp_path: Path) -> None:
    # The keyless cipher hands a sealed value back as it is. That file is not damaged, since its
    # key recovers it, so it must be cipher-declined: refused, never aged on disk and pruned.
    keyed = _keyed(tmp_path)
    meta = await _saved(keyed)
    sidecar, body = _sidecar(keyed, meta.file_id), _blob(keyed, meta.file_id)
    _age(sidecar, body, days=60)
    keyless = _keyless(tmp_path)
    assert await keyless.list_files() == []
    for read in (keyless.get_meta, keyless.read_bytes):
        with pytest.raises(UploadUnreadableError) as info:
            await read(meta.file_id)
        assert not isinstance(info.value, UploadDamagedError)
    assert (await keyless.prune_expired(retention_days=30)).pruned == []
    assert sidecar.exists() and body.exists()
