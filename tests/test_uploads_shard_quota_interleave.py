# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1941: two engine shards must not double-book the per-uploader upload quota through a
stale pre-reserve scan.

``UploadStore._reserve_across_shards`` handed the ledger ``cap - observed`` as headroom, with
``observed`` taken from a sidecar scan BEFORE the reserve. The ledger counts only uploads in
flight, and the second scan inside ``_build_and_write`` counted the disk and never read the ledger.
So a shard whose scan went stale could reserve on headroom that no longer existed, and both shards
then passed the disk scan before either write landed. The worked case from vault PR 1765 is the
one driven here: cap 3, one file on disk, two shards, four files land.

**The interleave is forced, not raced.** Shard B's pre-reserve scan is parked right after it
reads the disk (one file), while shard A lands a second file and then starts a third, parked just
after its own disk scan with its reservation held. Then B resumes on its stale reading. On the old
code B reserved against headroom 2, scanned two files, passed, and wrote, and A wrote too: four
files. Now B reads the ledger back after reserving, sees A's reservation, and is refused.

Two ``UploadStore`` objects, each with its own ``asyncio.Lock`` and its own store connection over
one database and one uploads directory. That is the shard shape for this property: the in-process
lock gives zero protection between them. Both run on one event loop so the ordering is exact.

The SQLite case runs everywhere. The Postgres and SQL Server cases are the backends a real sharded
deployment runs (``require_unified_store`` refuses SQLite past one shard) and are gated like the
rest of the server-backend suite: ``MEFOR_TEST_POSTGRES`` / ``MEFOR_TEST_SQLSERVER`` plus the
``MEFOR_STORE_*`` connection env. Each uses a fresh uploader id, so no table cleanup is needed.
"""

from __future__ import annotations

import asyncio
import os
import threading
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.uploads import (
    UploadedFileMeta,
    UploadQuotaError,
    UploadQuotaLedger,
    UploadStore,
)

_CAP = 3
_WAIT = 10.0


async def _race_stale_scan(
    tmp_path: Path, ledger_a: UploadQuotaLedger, ledger_b: UploadQuotaLedger, uploader_id: str
) -> tuple[object, object, list[Path]]:
    """Drive the worked interleave. Returns (shard B's outcome, shard A's third save, sidecars)."""
    uploads_dir = tmp_path / "uploads"
    cipher = make_cipher(generate_key())  # one DEK across the fleet, as in a real shard set

    def _shard(ledger: UploadQuotaLedger) -> UploadStore:
        return UploadStore(
            uploads_dir, cipher, max_bytes=4096, max_files_per_user=_CAP, store=ledger
        )

    a, b = _shard(ledger_a), _shard(ledger_b)

    async def _save(store: UploadStore, name: str) -> UploadedFileMeta:
        return await store.save(
            data=f"{name}\n".encode(),
            filename=f"{name}.txt",
            uploader="alice",
            uploader_id=uploader_id,
        )

    await _save(a, "on_disk_0")  # the one file already on disk

    # Park B's pre-reserve scan right after it has read the disk.
    b_scanned, b_go = threading.Event(), threading.Event()
    real_b_observed = b._observed_sync

    def _b_observed(uploader_id: str) -> tuple[int, int]:
        out = real_b_observed(uploader_id)
        b_scanned.set()
        b_go.wait(_WAIT)
        return out

    b._observed_sync = _b_observed  # type: ignore[method-assign]

    # Park A's third save just after its under-lock disk scan, with its reservation held.
    a_paused, a_go = threading.Event(), threading.Event()
    real_a_scan = a._scan_metas_sync
    armed = False
    scans = 0

    def _a_scan() -> list[UploadedFileMeta]:
        nonlocal scans
        out = real_a_scan()
        if armed:
            scans += 1
            if scans == 2:  # 1 = the pre-reserve scan, 2 = the scan inside _build_and_write
                a_paused.set()
                a_go.wait(_WAIT)
        return out

    a._scan_metas_sync = _a_scan  # type: ignore[method-assign]

    b_task = asyncio.create_task(_save(b, "shard_b"))
    a_task: asyncio.Task[UploadedFileMeta] | None = None
    try:
        assert await asyncio.to_thread(b_scanned.wait, _WAIT), "shard B never scanned"
        await _save(a, "on_disk_1")  # lands while B's reading still says one file
        armed = True
        a_task = asyncio.create_task(_save(a, "shard_a"))
        assert await asyncio.to_thread(a_paused.wait, _WAIT), "shard A never reached its scan"
        b_go.set()
        # B must finish while A is still parked; that is the interleave under test.
        (b_outcome,) = await asyncio.gather(b_task, return_exceptions=True)
    finally:
        b_go.set()
        a_go.set()
        # Settle both even when an assertion above failed, so a shard's real outcome is not lost
        # to a pending task destroyed at loop close.
        await asyncio.gather(
            *(t for t in (b_task, a_task) if t is not None), return_exceptions=True
        )
    assert a_task is not None
    (a_outcome,) = await asyncio.gather(a_task, return_exceptions=True)
    return b_outcome, a_outcome, sorted(uploads_dir.glob("*.meta"))


def _assert_one_budget(b_outcome: object, a_outcome: object, sidecars: list[Path]) -> None:
    assert len(sidecars) <= _CAP, (
        f"overshoot: {len(sidecars)} files landed for a cap of {_CAP} -> "
        f"{[p.name for p in sidecars]}; B={b_outcome!r} A={a_outcome!r}"
    )
    # Which shard loses matters: A reserved first and read the ledger before B existed in it, so A
    # is entitled to the last slot. B must be refused, and by the shard limb, not the disk limb.
    assert isinstance(a_outcome, UploadedFileMeta), f"shard A should have landed: {a_outcome!r}"
    assert isinstance(b_outcome, UploadQuotaError), f"shard B should be refused: {b_outcome!r}"
    assert "another engine shard is mid-upload" in str(b_outcome), str(b_outcome)
    assert len(sidecars) == _CAP


async def _assert_in_flight_contract(store: Any, uploader_id: str) -> None:
    """The read the fix depends on: raw in-flight totals, (0, 0) for an unknown uploader."""
    assert await store.upload_quota_in_flight(uploader_id) == (0, 0)
    assert await store.reserve_upload_quota(
        uploader_id, files=1, size_bytes=10, max_files=5, max_total_bytes=100
    )
    assert await store.reserve_upload_quota(
        uploader_id, files=1, size_bytes=20, max_files=5, max_total_bytes=100
    )
    assert await store.upload_quota_in_flight(uploader_id) == (2, 30)
    await store.reserve_upload_quota(uploader_id, files=-1, size_bytes=-10)
    assert await store.upload_quota_in_flight(uploader_id) == (1, 20)
    await store.reserve_upload_quota(uploader_id, files=-1, size_bytes=-20)
    assert await store.upload_quota_in_flight(uploader_id) == (0, 0)


# --- one pair of store connections per backend -------------------------------------------------

_Pair = Callable[[Path], AbstractAsyncContextManager[tuple[Any, Any]]]


@asynccontextmanager
async def _sqlite_pair(tmp_path: Path) -> AsyncIterator[tuple[Any, Any]]:
    from messagefoundry.store.store import MessageStore

    db = tmp_path / "engine.db"
    async with _opened(MessageStore.open, db) as a, _opened(MessageStore.open, db) as b:
        yield a, b


def _server_pair(module: str, cls: str) -> _Pair:
    """Two connections to the server store named by the ``MEFOR_STORE_*`` env. Each test uses a
    fresh uploader id, so no table cleanup is needed."""

    @asynccontextmanager
    async def _pair(_tmp_path: Path) -> AsyncIterator[tuple[Any, Any]]:
        import importlib

        from messagefoundry.config.settings import load_settings

        store_cls = getattr(importlib.import_module(module), cls)
        settings = load_settings(environ=os.environ).store
        async with _opened(store_cls.open, settings) as a, _opened(store_cls.open, settings) as b:
            yield a, b

    return _pair


@asynccontextmanager
async def _opened(opener: Callable[[Any], Any], arg: Any) -> AsyncIterator[Any]:
    store = await opener(arg)
    try:
        yield store
    finally:
        await store.close()


_BACKENDS = [
    pytest.param(_sqlite_pair, id="sqlite"),
    pytest.param(
        _server_pair("messagefoundry.store.postgres", "PostgresStore"),
        id="postgres",
        marks=pytest.mark.skipif(
            not os.getenv("MEFOR_TEST_POSTGRES"),
            reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres tests",
        ),
    ),
    pytest.param(
        _server_pair("messagefoundry.store.sqlserver", "SqlServerStore"),
        id="sqlserver",
        marks=pytest.mark.skipif(
            not os.getenv("MEFOR_TEST_SQLSERVER"),
            reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
        ),
    ),
]


@pytest.mark.parametrize("pair", _BACKENDS)
async def test_a_stale_pre_reserve_scan_cannot_double_book(tmp_path: Path, pair: _Pair) -> None:
    async with pair(tmp_path) as (ledger_a, ledger_b):
        outcome = await _race_stale_scan(tmp_path, ledger_a, ledger_b, f"u-1941-{uuid.uuid4().hex}")
    _assert_one_budget(*outcome)


@pytest.mark.parametrize("pair", _BACKENDS)
async def test_upload_quota_in_flight_reads_what_reserve_and_release_left(
    tmp_path: Path, pair: _Pair
) -> None:
    async with pair(tmp_path) as (store, _):
        await _assert_in_flight_contract(store, f"u-1941-{uuid.uuid4().hex}")


@pytest.mark.parametrize("pair", _BACKENDS)
async def test_a_live_reserve_joining_an_old_row_is_not_reclaimed_with_it(
    tmp_path: Path, pair: _Pair
) -> None:
    """BACKLOG #2648. Shard A's slot leaked, then shard B reserved and is mid-write. Shard C's
    reserve arrives once A's slot is past the window but B's is not, and must still count B. The
    reserve used to keep the row's old clock when it joined a non-zero row, so the reset dropped
    B's live slot along with A's leaked one, and C counted neither B's file nor B's slot."""
    uploader_id = f"u-2648-{uuid.uuid4().hex}"
    async with pair(tmp_path) as (shard_ab, shard_c):

        async def _reserve(store: Any, stale_after: float = 300.0) -> bool:
            return bool(
                await store.reserve_upload_quota(
                    uploader_id,
                    files=1,
                    size_bytes=10,
                    max_files=10,
                    max_total_bytes=1000,
                    stale_after=stale_after,
                )
            )

        assert await _reserve(shard_ab)  # shard A, never released
        await asyncio.sleep(2.0)
        assert await _reserve(shard_ab)  # shard B, mid-write
        # Shard C: A's slot is twice the window old, B's is well inside it.
        assert await _reserve(shard_c, stale_after=1.0)
        # B's reserve moved the clock, so nothing was reclaimed: A's leaked slot stays while the
        # row is active (it clears once the uploader is idle), and B's live slot is counted.
        assert await shard_c.upload_quota_in_flight(uploader_id) == (3, 30)
        # Drain the row, so a server-backend run leaves nothing in flight behind it.
        await shard_c.reserve_upload_quota(uploader_id, files=-3, size_bytes=-30)
        assert await shard_c.upload_quota_in_flight(uploader_id) == (0, 0)
