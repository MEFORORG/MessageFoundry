# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5552, the items PR 2962's review added. Synthetic data only.

Item 3: a FIFO in place of a sidecar or a body is refused without blocking by every reader that
opens one; the by-id reads and the delete are pinned in ``tests/test_uploads_sidecar_trust.py``,
and the startup count and the listing scan here. Item 8: the link predicate is one function shared
with ``config/atomic_edit.py``, and the control-byte set the text check counts is built once."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from messagefoundry import uploads
from messagefoundry.config import atomic_edit
from messagefoundry.parsing import sniff
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.uploads import UploadStore

_BODY = b"synthetic diagnostic line\n"


def _keyed(tmp_path: Path) -> UploadStore:
    return UploadStore(
        tmp_path / "uploads", make_cipher(generate_key(), write_v2=True), max_bytes=4096
    )


# --- item 3: a FIFO blocks no reader -------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
@pytest.mark.timeout(60)
@pytest.mark.parametrize("part", ["meta", "blob"])
async def test_a_fifo_blocks_neither_the_startup_count_nor_the_listing_scan(
    tmp_path: Path, part: str
) -> None:
    store = _keyed(tmp_path)
    fifo = await store.save(data=_BODY, filename="a.txt", uploader="op", uploader_id="u1")
    sound = await store.save(data=_BODY, filename="b.txt", uploader="op", uploader_id="u1")
    path = store._root / f"{fifo.file_id}.{part}"
    path.unlink()
    os.mkfifo(path)
    # An open of the FIFO would block the worker thread for good, and serve's startup with it.
    assert await asyncio.wait_for(store.warn_if_unsealed(), timeout=10) == 0
    listed = await asyncio.wait_for(store.list_files(), timeout=10)
    # A FIFO body is not read by the scan, which opens only sidecars, so that upload still lists.
    expected = {sound.file_id} if part == "meta" else {sound.file_id, fifo.file_id}
    assert {m.file_id for m in listed} == expected
    pruned = await asyncio.wait_for(store.prune_expired(), timeout=10)
    assert pruned.pruned == []
    assert path.exists()


# --- item 8: duplicated code -------------------------------------------------------------------


def test_the_link_predicate_is_the_one_atomic_edit_uses() -> None:
    # On origin/main uploads.py and config/atomic_edit.py each carried their own test and their
    # own copy of the name-surrogate bit.
    assert getattr(uploads, "_names_a_link") is atomic_edit._names_a_link  # noqa: B009
    assert not hasattr(uploads, "_NAME_SURROGATE_TAG")


def test_the_counted_control_bytes_are_built_once() -> None:
    # On origin/main nontext_upload_reason rebuilt this set from range(256) on every call.
    expected = bytes(
        b for b in range(256) if (b < 0x20 or b == 0x7F) and b not in sniff._TEXT_ALLOWED_CONTROLS
    )
    assert expected == sniff._DENSITY_CONTROLS
    assert b"\t" not in sniff._DENSITY_CONTROLS and b"\x01" in sniff._DENSITY_CONTROLS


def test_the_text_check_counts_through_the_built_set(monkeypatch: pytest.MonkeyPatch) -> None:
    # The check reads the module's set, so emptied it counts nothing: a control-dense body passes.
    dense = b"MSH|" + b"\x01" * 9000
    assert sniff.nontext_upload_reason(dense) is not None
    monkeypatch.setattr(sniff, "_DENSITY_CONTROLS", b"")
    assert sniff.nontext_upload_reason(dense) is None
