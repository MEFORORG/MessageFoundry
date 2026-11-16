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
from messagefoundry.uploads import UploadedFileMeta, UploadStore

_BODY = b"synthetic diagnostic line\n"


def _keyless(tmp_path: Path, *, retention_days: int = 30) -> UploadStore:
    # The identity cipher passes unmarked sidecars, which is where a planted one is read.
    return UploadStore(
        tmp_path / "uploads", make_cipher(None), max_bytes=4096, retention_days=retention_days
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


async def test_a_well_formed_sidecar_still_reads(tmp_path: Path) -> None:
    for store in (
        _keyless(tmp_path / "plain"),
        UploadStore(
            tmp_path / "keyed" / "uploads",
            make_cipher(generate_key(), write_v2=True),
            max_bytes=4096,
        ),
    ):
        meta = await _saved(store)
        assert await store.get_meta(meta.file_id) == meta
        assert await store.list_files() == [meta]
