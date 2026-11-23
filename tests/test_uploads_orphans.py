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
import errno
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry import path_reach
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
        return real(self, data, *a, **kw)  # type: ignore[arg-type]

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
        return real(self, data, *a, **kw)  # type: ignore[arg-type]

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


def test_an_aborted_sweep_stops_before_its_next_entry(tmp_path: Path) -> None:
    """BACKLOG #2264, code review. A pass writes its audit rows only once the orphan sweep returns,
    so a slow sweep over a large dir must stop on the pass's abort rather than hold those rows past
    a stop. With the abort already set, an aged leftover is left for the next pass."""
    store = _store(tmp_path)
    root = tmp_path / "uploads"
    root.mkdir(mode=0o700, parents=True)
    stale_blob = root / f"{secrets.token_hex(16)}{_BLOB_SUFFIX}"
    stale_blob.write_text("a body whose sidecar never landed", encoding="utf-8")
    _backdate(stale_blob, seconds=2 * _ORPHAN_MIN_AGE_SECONDS)
    aborted = threading.Event()
    aborted.set()

    assert store._sweep_orphans_sync(now=time.time(), abort=aborted) == 0
    assert stale_blob.exists()
    assert store._sweep_orphans_sync(now=time.time(), abort=threading.Event()) == 1


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
    """A rotated-away key must not let this pass destroy a live pair. The sweep checks a sidecar's
    NAME without opening it, so an undecryptable one still makes its body reachable."""
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


# --- a read fault that raises is not read as an absence (BACKLOG #6575) --------------------------


_ORPHAN_TEXT = "SYNTHETIC-ORPHAN-BODY-TEXT"


def _aged_orphan(store: UploadStore) -> Path:
    """A ``.blob`` with no sidecar, past the floor: exactly what the sweep exists to remove."""
    store._root.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = store._root / f"{secrets.token_hex(16)}{_BLOB_SUFFIX}"
    body.write_text(_ORPHAN_TEXT, encoding="utf-8")
    _backdate(body, seconds=2 * _ORPHAN_MIN_AGE_SECONDS)
    return body


async def _aged_live_body(store: UploadStore) -> Path:
    """The body of a real pair, past the floor, so only its sidecar keeps the sweep off it."""
    meta = await store.save(data=_TXT, filename="live.txt", uploader="op", uploader_id="u1")
    body = store._root / f"{meta.file_id}{_BLOB_SUFFIX}"
    _backdate(body, seconds=2 * _ORPHAN_MIN_AGE_SECONDS)
    return body


def _on_root_listing(
    monkeypatch: pytest.MonkeyPatch,
    store: UploadStore,
    hook: Callable[[int], object] = lambda _: None,
) -> list[int]:
    """Call ``hook`` with the listing's number after each real read of the store's root, and
    return the numbers seen, so a test can fail or race one particular listing."""
    real = Path.iterdir
    seen: list[int] = []

    def _listed(self: Path) -> Iterator[Path]:
        listed = real(self)
        if self == store._root:
            seen.append(len(seen) + 1)
            hook(seen[-1])
        return listed

    monkeypatch.setattr(Path, "iterdir", _listed)
    return seen


def _win_not_found(code: int) -> FileNotFoundError:
    """A ``FileNotFoundError`` carrying a Windows error code, on any platform. Windows maps at
    least a missing parent (3) and an unreachable share (53) to this class, so the class alone
    does not say the file is absent."""

    class _WinNotFound(FileNotFoundError):
        winerror = code

    return _WinNotFound(2, "not found")


@pytest.mark.parametrize("flaky", [False, True], ids=["control", "transient-stat-failure"])
async def test_a_transient_stat_failure_does_not_read_as_no_sidecars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flaky: bool
) -> None:
    """``Path.is_dir`` returns False on a swallowed ``OSError``. The sweep's known-sidecar set used
    to come from a reader gated on it, while its delete loop listed the root again, so one failed
    stat would have read as no sidecars and removed every body past the floor. The control is the
    same directory with no fault: the real orphan goes and the live body stays either way."""
    store = _store(tmp_path)
    live = await _aged_live_body(store)
    orphan = _aged_orphan(store)
    if flaky:
        real = Path.is_dir
        checks = 0

        def _second_check_fails(self: Path, *, follow_symlinks: bool = True) -> bool:
            nonlocal checks
            if self == store._root:
                checks += 1
                if checks > 1:
                    return False
            return real(self, follow_symlinks=follow_symlinks)

        monkeypatch.setattr(Path, "is_dir", _second_check_fails)

    assert store._sweep_orphans_sync(now=time.time()) == 1
    assert live.exists(), "a body with a sidecar was removed"
    assert not orphan.exists(), "the real orphan was not removed"
    if flaky:
        assert checks == 0, "the sweep asked a check that swallows a read fault"


@pytest.mark.parametrize("partway", [False, True], ids=["at-the-call", "partway-through"])
async def test_a_listing_that_fails_aborts_the_sweep_and_deletes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, partway: bool
) -> None:
    """``Path.iterdir`` reads the whole directory inside the call on 3.14, and the partway case
    holds the sweep to reading it whole first whichever way a later version does it."""
    store = _store(tmp_path)
    live = await _aged_live_body(store)
    orphan = _aged_orphan(store)
    real = Path.iterdir

    def _fails(self: Path) -> Iterator[Path]:
        if self != store._root:
            return real(self)
        if not partway:
            raise OSError(5, "Input/output error")

        def _entries() -> Iterator[Path]:
            yield orphan
            raise OSError(5, "Input/output error")

        return _entries()

    monkeypatch.setattr(Path, "iterdir", _fails)
    with pytest.raises(OSError, match="Input/output error"):
        store._sweep_orphans_sync(now=time.time())
    assert orphan.exists() and live.exists()


async def test_a_root_not_created_yet_is_an_empty_sweep(tmp_path: Path) -> None:
    store = _store(tmp_path)
    assert not store._root.exists()
    assert store._sweep_orphans_sync(now=time.time()) == 0


async def test_an_unreachable_root_is_not_read_as_a_missing_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The class is ``FileNotFoundError`` either way, and only a root that is really not there may
    end the pass quietly. An unreachable one raises, so ``prune_expired`` logs it."""
    store = _store(tmp_path)
    orphan = _aged_orphan(store)

    def _unreachable(_listing: int) -> None:
        raise _win_not_found(53)

    _on_root_listing(monkeypatch, store, _unreachable)
    with pytest.raises(FileNotFoundError):
        store._sweep_orphans_sync(now=time.time())
    assert orphan.exists()


async def test_an_aborted_sweep_keeps_the_passes_result_and_logs_no_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """What ``prune_expired`` does with the abort: the pairs it already removed stay reported, the
    orphan count is zero because nothing was swept, and the failure is an ERROR with no body in it."""
    store = _store(tmp_path)
    expired = await _aged_live_body(store)
    orphan = _aged_orphan(store)

    def _sweeps_listing_fails(listing: int) -> None:
        if listing > 1:  # the first is the pass's own sidecar scan
            raise OSError(5, "Input/output error")

    _on_root_listing(monkeypatch, store, _sweeps_listing_fails)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        result = await store.prune_expired(now=time.time() + 31 * 86_400)

    assert [f"{m.file_id}{_BLOB_SUFFIX}" for m in result.pruned] == [expired.name]
    assert result.orphans_removed == 0
    assert orphan.exists()
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert [r.getMessage() for r in errors] == [
        "uploaded-logs orphan sweep failed; will retry next pass"
    ]
    assert _ORPHAN_TEXT not in caplog.text


async def test_the_sweep_lists_the_root_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    orphan = _aged_orphan(store)
    listings = _on_root_listing(monkeypatch, store)
    assert store._sweep_orphans_sync(now=time.time()) == 1
    assert len(listings) == 1
    assert not orphan.exists()


async def test_a_sidecar_the_listing_did_not_show_keeps_its_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The listing is a snapshot. A sidecar can land after it, or a share can return a short
    listing with no error, so the listing alone never authorises the unlink."""
    store = _store(tmp_path)
    body = _aged_orphan(store)
    sidecar = body.with_suffix(_META_SUFFIX)
    _on_root_listing(monkeypatch, store, lambda _: sidecar.write_text("landed", encoding="utf-8"))
    assert store._sweep_orphans_sync(now=time.time()) == 0
    assert body.exists()


async def test_a_sidecar_landing_during_the_age_check_keeps_its_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sidecar check is the last read before the unlink, so the age check is not a gap."""
    store = _store(tmp_path)
    body = _aged_orphan(store)
    sidecar = body.with_suffix(_META_SUFFIX)
    real = Path.stat

    def _lands_during_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        result = real(self, follow_symlinks=follow_symlinks)
        if self == body:
            sidecar.write_text("landed", encoding="utf-8")
        return result

    monkeypatch.setattr(Path, "stat", _lands_during_stat)
    assert store._sweep_orphans_sync(now=time.time()) == 0
    assert body.exists()


_ONE_ENTRY_FAULTS: list[Callable[[], OSError]] = [
    lambda: PermissionError(13, "Permission denied"),
    lambda: OSError(errno.ESTALE, "Stale file handle"),
    lambda: _win_not_found(53),
    lambda: _win_not_found(3),
]
_ONE_ENTRY_FAULT_IDS = ["denied", "stale-handle", "unreachable-share", "missing-parent"]


@pytest.mark.parametrize("fault", _ONE_ENTRY_FAULTS, ids=_ONE_ENTRY_FAULT_IDS)
async def test_a_body_stat_fault_leaves_only_that_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: Callable[[], OSError]
) -> None:
    """A dangling link named like a body can raise the codes a lost share does, from its target. With
    the root still answering, that entry is skipped and the orphans listed after it still go."""
    store = _store(tmp_path)
    bodies = [_aged_orphan(store) for _ in range(3)]
    real = Path.stat

    def _one_body_faults(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self == bodies[0]:
            raise fault()
        return real(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", _one_body_faults)
    assert store._sweep_orphans_sync(now=time.time()) == 2
    assert [body.exists() for body in bodies] == [True, False, False]


@pytest.mark.parametrize("fault", _ONE_ENTRY_FAULTS, ids=_ONE_ENTRY_FAULT_IDS)
async def test_a_fault_on_one_sidecar_leaves_only_that_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fault: Callable[[], OSError],
) -> None:
    """A lasting fault on one name must not stop the sweep at that name on every pass, or nothing
    listed after it would ever be reclaimed. Its body stays, and it is named once an interval."""
    store = _store(tmp_path)
    bodies = [_aged_orphan(store) for _ in range(3)]
    denied = bodies[0].with_suffix(_META_SUFFIX).name
    real = os.lstat

    def _one_sidecar_denied(path: Any, **kwargs: Any) -> os.stat_result:
        if Path(path).name == denied:
            raise fault()
        return real(path, **kwargs)

    monkeypatch.setattr(os, "lstat", _one_sidecar_denied)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert store._sweep_orphans_sync(now=time.time()) == 2
        assert store._sweep_orphans_sync(now=time.time()) == 0

    assert [body.exists() for body in bodies] == [True, False, False]
    assert not [r for r in caplog.records if r.levelno == logging.ERROR]
    named = [r for r in caplog.records if "left" in r.getMessage()]
    assert len(named) == 1 and bodies[0].name in named[0].getMessage()
    assert _ORPHAN_TEXT not in caplog.text


async def test_a_young_body_with_a_faulting_sidecar_costs_the_pass_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A body under the floor is not a removal candidate, so its sidecar is never asked about."""
    store = _store(tmp_path)
    aged = _aged_orphan(store)
    young = _aged_orphan(store)
    _backdate(young, seconds=_ORPHAN_MIN_AGE_SECONDS / 2)
    young_sidecar = young.with_suffix(_META_SUFFIX).name
    real = os.lstat

    def _young_sidecar_faults(path: Any, **kwargs: Any) -> os.stat_result:
        if Path(path).name == young_sidecar:
            raise OSError(errno.ESTALE, "Stale file handle")
        return real(path, **kwargs)

    monkeypatch.setattr(os, "lstat", _young_sidecar_faults)
    assert store._sweep_orphans_sync(now=time.time()) == 1
    assert young.exists() and not aged.exists()


@pytest.mark.parametrize("fault", _ONE_ENTRY_FAULTS, ids=_ONE_ENTRY_FAULT_IDS)
async def test_a_root_that_stops_answering_stops_the_sweep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    fault: Callable[[], OSError],
) -> None:
    """A sidecar check that raises never lets a body go. The fault lands on the second orphan's
    sidecar and the root then fails its own ``stat``: the first orphan was already confirmed and
    removed and stays counted, and the third is never reached, which tells stopping from skipping.
    The ERROR names the root's own fault, not the entry's."""
    store = _store(tmp_path)
    bodies = [_aged_orphan(store) for _ in range(3)]
    real = os.lstat
    real_stat = Path.stat
    sidecars = 0

    def _second_sidecar_faults(path: Any, **kwargs: Any) -> os.stat_result:
        nonlocal sidecars
        if str(path).endswith(_META_SUFFIX):
            sidecars += 1
            if sidecars == 2:
                raise fault()
        return real(path, **kwargs)

    def _root_lost_after_it(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if sidecars >= 2 and self == store._root:
            raise OSError(errno.EIO, "Input/output error")
        return real_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "lstat", _second_sidecar_faults)
    monkeypatch.setattr(Path, "stat", _root_lost_after_it)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert store._sweep_orphans_sync(now=time.time()) == 1

    assert sum(body.exists() for body in bodies) == 2
    assert sidecars == 2
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1, [r.getMessage() for r in errors]
    message = errors[0].getMessage()
    assert "orphan sweep stopped" in message
    assert "Input/output error" in message, "the ERROR must name the root's own fault"
    assert str(fault().strerror) not in message, "the ERROR named the entry's fault"
    assert _ORPHAN_TEXT not in caplog.text


@pytest.mark.parametrize(("platform", "absent"), [("win32", False), ("linux", True)])
def test_a_not_found_error_with_no_windows_code(
    monkeypatch: pytest.MonkeyPatch, platform: str, absent: bool
) -> None:
    """A Windows lookup failure carries a code, so one with none proves nothing and must not
    authorise an unlink. POSIX has no such code, so there the class is the whole answer."""
    monkeypatch.setattr(path_reach, "sys", SimpleNamespace(platform=platform))
    assert path_reach.is_name_absent(FileNotFoundError(errno.ENOENT, "not found")) is absent


def test_a_not_found_error_with_a_network_loss_code_is_not_a_missing_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``is_name_absent`` narrows ``is_absent``, so what that calls unreachable is never absence."""
    monkeypatch.setattr(path_reach, "sys", SimpleNamespace(platform="linux"))
    exc = FileNotFoundError(errno.ESTALE, "Stale file handle")
    assert not path_reach.is_absent(exc)
    assert not path_reach.is_name_absent(exc)


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
