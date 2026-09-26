# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DR-1 sub-test A — the DR snapshot under a CONCURRENT WRITER (contention path, SQLite-local, no rig).

The existing consistency test (``tests/test_backup_runner.py::test_snapshot_is_consistent_and_nonmutating``)
runs both snapshot mechanisms against a QUIESCENT store. This adds the missing coverage: a concurrent
asyncio task hammering the store WRITE path (``enqueue_message``, under ``Store._lock``) WHILE a snapshot
runs — the busy-store case an operator actually faces.

**BACKLOG #1937 reversed what this file used to assert.** Before it, BOTH methods ran the copy on the
writer connection inside ``async with self._lock``, and this test pinned that: the writer advanced at most
one row during a snapshot. On a deploying site that would have stalled every store write, logins included,
for the whole copy. Now only the WAL checkpoint holds the lock; the copy runs on a dedicated ``mode=ro``
connection in one read transaction. So a store write completes WHILE the copy is still running, and the
copy stays point-in-time and intact.

The overlap is proven with a gate, not a wall-clock threshold, so it does not flake on a jittery Windows
CI runner: the copy's own connection worker thread is held at the start of the copy until the test has
seen a write complete. On the pre-#1937 code that held thread is the writer's, under the store lock, so
the write cannot complete and the test fails on its bound."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import aiosqlite
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


#: How long the gated copy waits for the test before proceeding anyway, so a failure never hangs the
#: suite. Far above the bound a write gets, so the write's own bound is what fails first.
_GATE_SECONDS = 30.0
#: How long a store write issued during the gated copy may take. A write off the lock takes
#: milliseconds; under the pre-#1937 lock it can never finish while the copy is held.
_WRITE_BOUND_SECONDS = 5.0


def _gate_the_copy(
    monkeypatch: pytest.MonkeyPatch, gate: threading.Event, entered: threading.Event
) -> None:
    """Hold the snapshot COPY at its start, on the worker thread of whichever connection runs it.

    Wraps ``VACUUM INTO`` and ``Connection.backup`` so that, before the real copy, the connection's own
    aiosqlite worker thread blocks on ``gate``. That occupies exactly the thread and the lock position
    a long copy would, so a store write issued meanwhile completes only if the copy runs off both the
    store lock and the writer connection. Reads aiosqlite's private ``_execute``, the one way to run a
    callable on that connection's thread; a rename errors here rather than passing silently.
    """

    def _hold(conn: aiosqlite.Connection) -> Any:
        def _wait() -> None:
            entered.set()
            gate.wait(_GATE_SECONDS)

        return conn._execute(_wait)

    real_execute = aiosqlite.Connection.execute
    real_backup = aiosqlite.Connection.backup

    def gated_execute(self: aiosqlite.Connection, sql: str, parameters: Any = None) -> Any:
        # Pass every other statement through untouched, keeping aiosqlite's await-or-`async with`
        # return object; only the copy statement becomes a coroutine.
        if not sql.lstrip().upper().startswith("VACUUM INTO"):
            return real_execute(self, sql, parameters)

        async def _run() -> Any:
            await _hold(self)
            return await real_execute(self, sql, parameters)

        return _run()

    async def gated_backup(self: aiosqlite.Connection, target: Any, **kwargs: Any) -> None:
        await _hold(self)
        await real_backup(self, target, **kwargs)

    monkeypatch.setattr(aiosqlite.Connection, "execute", gated_execute)
    monkeypatch.setattr(aiosqlite.Connection, "backup", gated_backup)


async def _until(predicate: Callable[[], bool], *, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.005)


@pytest.mark.parametrize("snapshot_method", ["vacuum_into", "online_backup"])
async def test_a_store_write_completes_while_the_snapshot_copy_runs(
    tmp_path: Path, snapshot_method: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1937: the copy must not hold the store write lock (or the writer connection).

    Fails on the pre-#1937 code: there the gated thread is the writer's, inside ``self._lock``, so the
    write below times out on ``_WRITE_BOUND_SECONDS``."""
    from messagefoundry.store.crypto import generate_key

    n = 20
    store = await _store_with_rows_n(tmp_path / "msg.db", generate_key(), n)
    gate, entered = threading.Event(), threading.Event()
    dest = tmp_path / "snap.db"
    try:
        _gate_the_copy(monkeypatch, gate, entered)
        snap = asyncio.create_task(store.snapshot_to(dest, method=snapshot_method))
        try:
            await _until(
                lambda: entered.is_set() or snap.done(),
                timeout=_GATE_SECONDS,
                what="the snapshot copy to start",
            )
            if snap.done():
                await snap  # it failed before reaching the copy: surface that error, not a timeout
                pytest.fail("the snapshot finished without ever starting a gated copy")
            try:
                await asyncio.wait_for(
                    store.enqueue_message(
                        channel_id="during",
                        raw="MSH|^~\\&|during-body",
                        deliveries=[("d1", "OUT|during")],
                        control_id="DURING-1",
                        now=50000.0,
                    ),
                    timeout=_WRITE_BOUND_SECONDS,
                )
            except TimeoutError:
                pytest.fail(
                    f"{snapshot_method}: a store write waited more than {_WRITE_BOUND_SECONDS}s "
                    f"on a running snapshot copy; the copy holds the store write lock"
                )
            assert not snap.done(), "the snapshot finished before the write; nothing overlapped"
        finally:
            gate.set()
            await snap
    finally:
        monkeypatch.undo()
        await store.close()
    assert _sqlite_integrity_ok(dest)
    assert _sqlite_count(dest, "messages") >= n


@pytest.mark.parametrize("snapshot_method", ["vacuum_into", "online_backup"])
async def test_snapshot_under_a_concurrent_writer_stays_consistent(
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

        # (1) The snapshot runs under a live writer. Whether any given write lands inside the copy is
        # timing, so it is not asserted here; the gated test above proves the overlap deterministically.
        c0 = writer.count
        dest = tmp_path / "snap.db"
        await store.snapshot_to(dest, method=snapshot_method)

        # (2) NO DEADLOCK: the writer keeps making progress after the snapshot.
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
