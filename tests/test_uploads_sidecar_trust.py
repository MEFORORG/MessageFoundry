# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A sidecar's JSON is checked, never trusted (BACKLOG #5387), and a damaged one is a handled
refusal on the by-id reads, never an uncaught error (BACKLOG #5388). Synthetic data only."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.uploads import (
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
    ],
    ids=lambda f: next(iter(f)),
)
async def test_a_sidecar_with_an_out_of_shape_field_is_left_out(
    tmp_path: Path, fields: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    store = _keyless(tmp_path)
    kept = await _saved(store, "kept.txt")
    bad = await _saved(store, "bad.txt")
    _plant(store, bad.file_id, **fields)
    assert [m.file_id for m in await store.list_files()] == [kept.file_id]
    assert any("malformed metadata" in r.getMessage() for r in caplog.records)


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
    with pytest.raises(UploadUnreadableError):
        await store.get_meta(meta.file_id)
    with pytest.raises(UploadUnreadableError):
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


@pytest.mark.parametrize(
    "raw",
    [b"\xff\xfe not utf-8", b"not base64!", b"%%%%", b"abcd!"],
    ids=["not-utf8", "bad-padding", "no-alphabet", "stray-char"],
)
async def test_a_damaged_body_is_refused_on_read_bytes(tmp_path: Path, raw: bytes) -> None:
    store = _keyless(tmp_path)
    meta = await _saved(store)
    (store._root / f"{meta.file_id}.blob").write_bytes(raw)  # noqa: SLF001
    with pytest.raises(UploadUnreadableError):
        await store.read_bytes(meta.file_id)


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
        assert [type(e) for e in _chain(info.value)] == [UploadUnreadableError]
