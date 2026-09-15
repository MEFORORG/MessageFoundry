# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A failed upload write must leave nothing behind, and the sweep must not eat a live one (#1678).

Two leftovers used to survive a failed ``UploadStore.save`` for the life of the uploads directory: the
``.<id>.<suffix>.<tag>.tmp`` an interrupted atomic write left, and the ``<id>.blob`` whose sidecar
never landed. Neither is reachable through ``_iter_sidecars``, which yields ``.meta`` names only, so
``list_files``, ``prune_expired`` and ``reseal_to_active`` all walked past them — a partial PHI body
outside the retention window the module promises.

**The sweep that collects them UNLINKS, which is why half this file is about what it must NOT do.** An
operator's own file, a sidecar that will not decrypt, a leftover too young to be certain about, and —
the one that matters — a write that is happening right now all have to survive it."""

from __future__ import annotations

import asyncio
import os
import secrets
import threading
import time
from pathlib import Path

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.uploads import (
    _BLOB_SUFFIX,
    _META_SUFFIX,
    _ORPHAN_MIN_AGE_SECONDS,
    _ORPHAN_TMP_RE,
    PruneResult,
    UploadStore,
    _atomic_write_text,
)

_TXT = b"diagnostic log line\n"


def _store(tmp_path: Path, *, key: bool = True) -> UploadStore:
    cipher = make_cipher(generate_key() if key else None, write_v2=True)
    return UploadStore(tmp_path / "uploads", cipher, max_bytes=1_000_000)


def _names(root: Path) -> list[str]:
    return sorted(p.name for p in root.iterdir())


def _backdate(path: Path, *, seconds: float) -> None:
    """Age ``path`` by ``seconds`` so the sweep's floor is satisfied."""
    stamp = time.time() - seconds
    os.utime(path, (stamp, stamp))


# --- the write paths clean up after themselves -------------------------------------------------


async def test_a_half_written_body_is_not_left_in_the_uploads_root(tmp_path: Path) -> None:
    """Disk-full is the realistic trigger and the blob is the large write. Measured before the fix at
    engine 7cb9969cb: ``save`` raised and left ``.<id>.blob.<tag>.tmp`` holding half the ciphertext,
    with ``list_files`` 0, ``prune_expired`` ten years on 0, and ``reseal_to_active`` all zeros."""
    store = _store(tmp_path)
    root = tmp_path / "uploads"
    real = Path.write_text

    def _half_then_fail(self: Path, data: str, *a: object, **kw: object) -> int:
        if _BLOB_SUFFIX in self.name:
            real(self, data[: len(data) // 2], *a, **kw)  # type: ignore[arg-type]
            raise OSError(28, "No space left on device")
        return real(self, data, *a, **kw)  # type: ignore[arg-type,no-any-return]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Path, "write_text", _half_then_fail)
        with pytest.raises(OSError, match="No space left"):
            await store.save(data=_TXT, filename="a.txt", uploader="op", uploader_id="u1")

    assert _names(root) == []
    assert await store.list_files() == []


async def test_a_failed_sidecar_write_takes_the_body_it_orphaned_with_it(tmp_path: Path) -> None:
    """The body is written first because the sidecar is the listing key. A failure in that window used
    to leave a sidecar-less ``<id>.blob`` that no sweep could see. Both halves must go."""
    store = _store(tmp_path)
    root = tmp_path / "uploads"
    real = os.replace

    def _fail_the_sidecar(src: object, dst: object, **kw: object) -> None:
        if str(dst).endswith(_META_SUFFIX):
            raise OSError(5, "I/O error")
        real(src, dst, **kw)  # type: ignore[arg-type]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(os, "replace", _fail_the_sidecar)
        with pytest.raises(OSError, match="I/O error"):
            await store.save(data=_TXT, filename="a.txt", uploader="op", uploader_id="u1")

    assert _names(root) == []
    assert await store.list_files() == []


async def test_a_cancelled_write_cleans_up_too(tmp_path: Path) -> None:
    """The cleanup catches ``BaseException``, not ``Exception``: a cancelled upload must not be the one
    shape that still leaks. ``asyncio.CancelledError`` derives from ``BaseException``."""
    store = _store(tmp_path)
    root = tmp_path / "uploads"
    real = Path.write_text

    def _cancel_mid_write(self: Path, data: str, *a: object, **kw: object) -> int:
        if _BLOB_SUFFIX in self.name:
            real(self, data, *a, **kw)  # type: ignore[arg-type]
            raise asyncio.CancelledError
        return real(self, data, *a, **kw)  # type: ignore[arg-type,no-any-return]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Path, "write_text", _cancel_mid_write)
        with pytest.raises(asyncio.CancelledError):
            await store.save(data=_TXT, filename="a.txt", uploader="op", uploader_id="u1")

    assert _names(root) == []


# --- the sweep collects what a DEAD process left ------------------------------------------------


async def test_the_sweep_removes_both_leftover_shapes_and_counts_them(tmp_path: Path) -> None:
    """A process killed mid-write leaves what no ``finally`` could clean. Plant both shapes as a dead
    process would, age them past the floor, and the prune pass collects them."""
    store = _store(tmp_path)
    root = tmp_path / "uploads"
    root.mkdir(mode=0o700, parents=True)
    live = await store.save(data=_TXT, filename="keep.txt", uploader="op", uploader_id="u1")

    stale_tmp = root / f".{secrets.token_hex(16)}{_BLOB_SUFFIX}.{secrets.token_hex(4)}.tmp"
    stale_tmp.write_text("half a ciphertext", encoding="utf-8")
    stale_blob = root / f"{secrets.token_hex(16)}{_BLOB_SUFFIX}"
    stale_blob.write_text("a body whose sidecar never landed", encoding="utf-8")
    for leftover in (stale_tmp, stale_blob):
        _backdate(leftover, seconds=2 * _ORPHAN_MIN_AGE_SECONDS)

    result = await store.prune_expired()
    assert result.orphans_removed == 2
    assert result.pruned == []  # the live file is nowhere near its retention window
    assert not stale_tmp.exists()
    assert not stale_blob.exists()
    # The live pair is untouched and still readable.
    assert [m.file_id for m in await store.list_files()] == [live.file_id]
    assert await store.read_bytes(live.file_id) == _TXT
    # Idempotent: a second pass has nothing left to do.
    assert await store.prune_expired() == PruneResult()


async def test_a_leftover_younger_than_the_floor_is_left_alone(tmp_path: Path) -> None:
    """The floor is what stands in for a liveness check across processes, so it has to actually hold."""
    store = _store(tmp_path)
    root = tmp_path / "uploads"
    root.mkdir(mode=0o700, parents=True)
    fresh = root / f".{secrets.token_hex(16)}{_BLOB_SUFFIX}.{secrets.token_hex(4)}.tmp"
    fresh.write_text("mid-write right now", encoding="utf-8")
    _backdate(fresh, seconds=_ORPHAN_MIN_AGE_SECONDS / 2)

    assert (await store.prune_expired()).orphans_removed == 0
    assert fresh.exists()


# --- the sweep refuses everything it cannot positively identify ---------------------------------


# Every value below must stay a LITERAL. A parametrize list is evaluated at COLLECTION time and each
# pytest-xdist worker collects independently, so a generated id differs per worker and aborts the
# whole run with "Different tests were collected between gw0 and gwN". The file_id below only has to
# be 32 hex characters to stand for a real one; nothing here depends on it being fresh.
@pytest.mark.parametrize(
    "name",
    [
        "operator-notes.txt",  # an operator's own file in the uploads dir
        "scratch.tmp",  # a temp, but not one of ours
        ".nope.blob.zz.tmp",  # our shape, wrong id and wrong tag alphabet
        "not-a-file-id.blob",  # a .blob whose stem is not a 32-hex file_id
        "0f1e2d3c4b5a69788796a5b4c3d2e1f0.blob.bak",  # an operator's copy of a body
    ],
)
async def test_the_sweep_never_unlinks_a_file_that_is_not_ours(tmp_path: Path, name: str) -> None:
    """The pass DELETES, so an unrecognised name is left alone — the same refusal ``_iter_sidecars``
    makes. A pattern that drifted wider than the writer's own spelling would start eating these."""
    store = _store(tmp_path)
    root = tmp_path / "uploads"
    root.mkdir(mode=0o700, parents=True)
    stray = root / name
    stray.write_text("not the engine's", encoding="utf-8")
    _backdate(stray, seconds=10 * _ORPHAN_MIN_AGE_SECONDS)

    assert (await store.prune_expired()).orphans_removed == 0
    assert stray.exists()


async def test_a_body_whose_sidecar_will_not_decrypt_is_kept(tmp_path: Path) -> None:
    """A rotated-away key must not let this pass destroy a live pair. ``_iter_sidecars`` yields a
    sidecar WITHOUT opening it, so an undecryptable one still makes its body reachable."""
    store = _store(tmp_path)
    root = tmp_path / "uploads"
    meta = await store.save(data=_TXT, filename="a.txt", uploader="op", uploader_id="u1")
    blob = root / f"{meta.file_id}{_BLOB_SUFFIX}"
    # Re-seal the sidecar under a key this store does not hold — the shape a rotation leaves behind.
    other = make_cipher(generate_key(), write_v2=True)
    (root / f"{meta.file_id}{_META_SUFFIX}").write_text(
        other.encrypt("{}", aad=b"unrelated"), encoding="utf-8"
    )
    _backdate(blob, seconds=10 * _ORPHAN_MIN_AGE_SECONDS)

    assert await store.list_files() == []  # it cannot be listed ...
    assert (await store.prune_expired()).orphans_removed == 0  # ... and it is still not swept
    assert blob.exists()


# --- a LIVE write is safe by identity, not by age -----------------------------------------------


async def _sweep_while_blocked_on(
    store: UploadStore, *, blocks: str
) -> tuple[PruneResult, list[Path]]:
    """Start a ``save``, park it inside the write of the ``blocks`` temp with that file already aged
    past the sweep's floor, run one prune pass against it, then let the save finish.

    The backdating is the point of the fixture: it removes the age floor from the argument entirely,
    so anything that survives survives because ``_inflight_names`` held it, not because it looked
    young. Both halves really do run concurrently — ``save`` and ``prune_expired`` each dispatch
    through ``asyncio.to_thread``, so they are on different worker threads."""
    started = threading.Event()
    release = threading.Event()
    parked: list[Path] = []
    real = Path.write_text

    def _park(self: Path, data: str, *a: object, **kw: object) -> int:
        written: int = real(self, data, *a, **kw)  # type: ignore[arg-type]
        if blocks in self.name and self.name.endswith(".tmp"):
            parked.append(self)
            _backdate(self, seconds=10 * _ORPHAN_MIN_AGE_SECONDS)
            started.set()
            assert release.wait(timeout=30), "the test never released the parked write"
        return written

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Path, "write_text", _park)
        task = asyncio.create_task(
            store.save(data=_TXT, filename="live.txt", uploader="op", uploader_id="u1")
        )
        try:
            assert await asyncio.to_thread(started.wait, 30), "the write never reached the park"
            result = await store.prune_expired()
        finally:
            release.set()
        await task
    return result, parked


async def test_the_sweep_does_not_remove_a_temp_a_live_write_is_holding(tmp_path: Path) -> None:
    """The in-flight registry, not the age floor, is what makes this safe — the parked temp is aged ten
    hours past the floor before the sweep runs, so a threshold-only design removes it here."""
    store = _store(tmp_path)
    result, parked = await _sweep_while_blocked_on(store, blocks=_BLOB_SUFFIX)

    assert parked, "the blob temp was never created"
    assert result.orphans_removed == 0
    listed = await store.list_files()
    assert len(listed) == 1  # the upload the sweep ran through completed normally
    assert await store.read_bytes(listed[0].file_id) == _TXT
    assert not parked[0].exists()  # ... and its temp was consumed by the replace, not by the sweep


async def test_the_sweep_does_not_remove_a_body_still_waiting_for_its_sidecar(
    tmp_path: Path,
) -> None:
    """The other in-flight window: between the body's write and its sidecar's, the body is a
    sidecar-less ``.blob`` and looks exactly like the leftover this pass exists to collect."""
    store = _store(tmp_path)
    root = tmp_path / "uploads"
    result, parked = await _sweep_while_blocked_on(store, blocks=_META_SUFFIX)

    assert parked, "the meta temp was never created"
    assert result.orphans_removed == 0
    listed = await store.list_files()
    assert len(listed) == 1
    assert (root / f"{listed[0].file_id}{_BLOB_SUFFIX}").exists()
    assert await store.read_bytes(listed[0].file_id) == _TXT


# --- drift guard --------------------------------------------------------------------------------


def test_the_orphan_pattern_matches_the_name_the_writer_actually_mints(tmp_path: Path) -> None:
    """The sweep UNLINKS what ``_ORPHAN_TMP_RE`` matches, so the pattern and ``_atomic_write_text``'s
    name minting must not drift apart. Assert against the real minted name rather than a literal."""
    root = tmp_path / "uploads"
    root.mkdir(mode=0o700, parents=True)
    fid = secrets.token_hex(16)
    seen: list[str] = []
    real = os.replace

    def _spy(src: object, dst: object, **kw: object) -> None:
        seen.append(Path(str(src)).name)
        real(src, dst, **kw)  # type: ignore[arg-type]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(os, "replace", _spy)
        for suffix in (_BLOB_SUFFIX, _META_SUFFIX):
            _atomic_write_text(root, root / f"{fid}{suffix}", "ciphertext")

    assert len(seen) == 2
    for name in seen:
        assert _ORPHAN_TMP_RE.match(name), f"the sweep would walk past its own temp: {name}"
