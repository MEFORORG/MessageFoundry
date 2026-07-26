# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DR-1 sub-test A — the DR snapshot under a CONCURRENT WRITER (contention path, SQLite-local, no rig).

The existing consistency test (``tests/test_backup_runner.py::test_snapshot_is_consistent_and_nonmutating``)
runs both snapshot mechanisms against a QUIESCENT store. This adds the missing coverage: a concurrent
asyncio task hammering the store WRITE path (``enqueue_message``, under ``Store._lock``) WHILE a snapshot
runs — the busy-store case an operator actually faces.

**What the live code actually does** (``messagefoundry/store/store.py::MessageStore.snapshot_to``): BOTH
``vacuum_into`` AND ``online_backup`` wrap their whole body in ``async with self._lock``. So a same-store
asyncio writer is **blocked for the snapshot's full duration in BOTH methods** — the online-backup API
yields the *SQLite* write lock to *other connections* between page batches, but not this store's single
asyncio write lock, and the store funnels every write through that one lock + writer connection. We assert
that TRUE behavior (serialization for both) rather than a differential — see the return notes for why the
"online_backup lets the store's own writer advance" framing does not hold against this code.

The block is proven from the lock structure (deterministic), not a wall-clock threshold, so it does not
flake on a jittery Windows CI runner (cf. the "MF CI Test Flakes" memory)."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from pathlib import Path

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import make_cipher

# --- helpers -----------------------------------------------------------------


async def _store_with_rows_n(path: Path, key_b64: str, n: int) -> MessageStore:
    """A SQLite store pre-loaded with ``n`` routed messages (each 1 outbound delivery) — a large-ish body
    so the snapshot copy is non-trivial, and a real backlog for the snapshot to capture whole."""
    store = await MessageStore.open(path, cipher=make_cipher(key_b64))
    for i in range(n):
        await store.enqueue_message(
            channel_id="seed",
            raw="MSH|^~\\&|seed-body",
            deliveries=[("d1", f"OUT|seed-{i}")],
            control_id=f"SEED-{i}",
            message_type="ADT^A01",
            summary="MRN000 DOE^JANE",
            now=1.0 + i,
        )
    return store


class _ConcurrentWriter:
    """A background task looping ``enqueue_message`` on a store, counting committed rows — the concurrent
    write load for the snapshot-contention test. Cooperatively stoppable; captures the first exception."""

    def __init__(self, store: MessageStore) -> None:
        self._store = store
        self._stop = False
        self.count = 0
        self.error: BaseException | None = None

    async def run(self) -> None:
        i = 0
        try:
            while not self._stop:
                await self._store.enqueue_message(
                    channel_id="writer",
                    raw="MSH|^~\\&|writer-body",
                    deliveries=[("d1", f"OUT|w-{i}")],
                    control_id=f"CW-{i}",
                    now=100000.0 + i,
                )
                self.count += 1
                i += 1
                await asyncio.sleep(0)  # yield so the snapshot task can run (and contend the lock)
        except Exception as exc:  # captured; the test asserts it stayed None
            self.error = exc

    async def reached(self, target: int, *, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while self.count < target:
            if self.error is not None:
                raise self.error
            if time.monotonic() > deadline:
                raise AssertionError(f"writer did not reach {target} (stuck at {self.count})")
            await asyncio.sleep(0.002)

    def stop(self) -> None:
        self._stop = True


def _sqlite_integrity_ok(db_path: Path) -> bool:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = [str(r[0]) for r in conn.execute("PRAGMA integrity_check")]
    finally:
        conn.close()
    return rows == ["ok"]


def _sqlite_count(db_path: Path, table: str) -> int:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        (n,) = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # table is a constant
    finally:
        conn.close()
    return int(n)


# --- the test ----------------------------------------------------------------


@pytest.mark.parametrize("snapshot_method", ["vacuum_into", "online_backup"])
async def test_snapshot_serializes_concurrent_writer_and_stays_consistent(
    tmp_path: Path, snapshot_method: str
) -> None:
    from messagefoundry.store.crypto import generate_key

    key_b64 = generate_key()
    n = 1000
    store = await _store_with_rows_n(tmp_path / "msg.db", key_b64, n)
    # A quiescent baseline: the writer must actually add rows (so the "under load" claim is real).
    quiescent_stats = await store.stats()

    writer = _ConcurrentWriter(store)
    task = asyncio.create_task(writer.run())
    c0 = 0
    try:
        await writer.reached(25)  # the writer is actively committing rows before we snapshot

        # (1) SERIALIZATION: the store write lock is held for the whole snapshot, so the concurrent
        # writer makes essentially NO forward progress DURING the snapshot — at most the single write
        # already in flight when the snapshot grabbed the lock can finish. TRUE for BOTH methods
        # (deterministic from the `async with self._lock` that wraps both branches; not a timing bound).
        c0 = writer.count
        dest = tmp_path / "snap.db"
        await store.snapshot_to(dest, method=snapshot_method)
        advanced = writer.count - c0
        assert advanced <= 1, (
            f"{snapshot_method}: the writer advanced {advanced} rows DURING the snapshot; the store "
            f"write lock should have blocked it for the snapshot's full duration"
        )

        # (2) NO DEADLOCK: once the snapshot releases the lock the writer resumes and makes progress.
        await writer.reached(writer.count + 25)
    finally:
        writer.stop()
        await task
    assert writer.error is None, f"the concurrent writer failed: {writer.error!r}"
    assert writer.count > c0  # overall forward progress across the snapshot

    # (3) CONSISTENT COPY: the snapshot is a non-torn, point-in-time copy that captured the committed
    # backlog whole (the seeded rows are all present; integrity_check passes on the raw copy).
    assert _sqlite_integrity_ok(dest)
    assert _sqlite_count(dest, "messages") >= n

    # (4) NON-MUTATING (AC-2) under a store that has taken concurrent writes: a second snapshot leaves
    # the live queue byte-identical — no claim/mutate/reset/complete of a staged-queue row. Mirrors the
    # existing consistency test, but after the store is no longer pristine.
    stats_before = await store.stats()
    depth_before = await store.in_pipeline_depth()
    assert stats_before != quiescent_stats  # the concurrent writer really did add outbound rows
    dest2 = tmp_path / "snap2.db"
    await store.snapshot_to(dest2, method=snapshot_method)
    assert await store.stats() == stats_before
    assert await store.in_pipeline_depth() == depth_before
    await store.close()
