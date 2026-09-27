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

The overlap is proven with a gate, so it does not rest on a timing threshold that could flake on a
jittery Windows CI runner. The copy's own connection worker thread is held until the test has seen a
write complete. For ``vacuum_into`` the hold sits INSIDE the ``VACUUM INTO``, after its read transaction
has opened, so the write lands mid-copy and the test can assert the copy excludes it. SQLite cannot pause
a backup step, so for ``online_backup`` the hold sits just before the step. The deciding assertions are
structural: while the copy is held, the store lock is free and the held thread is not the writer's. On
the pre-#1937 code both fail at once. A 5 s bound on the write is only a hang guard."""

from __future__ import annotations

import asyncio
import sqlite3
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import aiosqlite
import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import make_cipher
from messagefoundry.store.store import _sqlite_readonly_uri

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
    conn = sqlite3.connect(_sqlite_readonly_uri(str(db_path.absolute())), uri=True)
    try:
        rows = [str(r[0]) for r in conn.execute("PRAGMA integrity_check")]
    finally:
        conn.close()
    return rows == ["ok"]


def _sqlite_count(db_path: Path, table: str) -> int:
    conn = sqlite3.connect(_sqlite_readonly_uri(str(db_path.absolute())), uri=True)
    try:
        (n,) = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # table is a constant
    finally:
        conn.close()
    return int(n)


def _sqlite_orphans(db_path: Path) -> tuple[int, int]:
    """(messages with no queue row, queue rows with no message). A copy torn between the two tables of
    one ``enqueue_message`` transaction shows here, where ``integrity_check`` sees nothing."""
    conn = sqlite3.connect(_sqlite_readonly_uri(str(db_path.absolute())), uri=True)
    try:
        (bare,) = conn.execute(
            "SELECT COUNT(*) FROM messages m WHERE NOT EXISTS "
            "(SELECT 1 FROM queue q WHERE q.message_id = m.id)"
        ).fetchone()
        (orphan,) = conn.execute(
            "SELECT COUNT(*) FROM queue q WHERE NOT EXISTS "
            "(SELECT 1 FROM messages m WHERE m.id = q.message_id)"
        ).fetchone()
    finally:
        conn.close()
    return int(bare), int(orphan)


# --- the test ----------------------------------------------------------------


#: How long the gated copy waits for the test before proceeding anyway, so a failure never hangs the
#: suite. Far above the bound a write gets, so the write's own bound is what fails first.
_GATE_SECONDS = 30.0
#: A hang guard on the store write issued during the held copy, not the deciding check. A write off
#: the lock takes milliseconds; under the pre-#1937 lock it could never finish while the copy is held.
_WRITE_BOUND_SECONDS = 5.0
#: Progress callbacks to let pass once ``VACUUM INTO`` is inside its transaction before holding it.
#: SQLite opens the copy's read transaction right after the nested ``BEGIN`` that flips autocommit, so
#: a few callbacks later the read snapshot is certainly open. If the hold ever landed before that, the
#: mid-copy write would appear in the copy and the exact-count assertion would fail, not pass.
_INSIDE_AFTER_CALLBACKS = 50


class _CopyGate:
    """Hold the snapshot COPY on the worker thread of whichever connection runs it.

    ``VACUUM INTO`` is held from a SQLite progress handler, INSIDE the statement once its read
    transaction is open. ``Connection.backup`` is held just before its single step, because SQLite
    runs no progress handler during a backup step. Either way the hold occupies exactly the thread,
    and the lock position, a long copy would. Reads aiosqlite's private ``_execute`` and ``_conn``,
    the only ways to reach that connection's thread and its sqlite3 object; a rename errors here
    rather than passing silently.
    """

    def __init__(self) -> None:
        self.release = threading.Event()
        self.entered = threading.Event()
        self.held_on: threading.Thread | None = None

    def _wait(self) -> None:
        self.held_on = threading.current_thread()
        self.entered.set()
        self.release.wait(_GATE_SECONDS)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_execute = aiosqlite.Connection.execute
        real_backup = aiosqlite.Connection.backup
        gate = self

        def gated_execute(self: aiosqlite.Connection, sql: str, parameters: Any = None) -> Any:
            # Pass every other statement through untouched, keeping aiosqlite's await-or-`async with`
            # return object; only the copy statement becomes a coroutine.
            if not sql.lstrip().upper().startswith("VACUUM INTO"):
                return real_execute(self, sql, parameters)
            raw = self._conn
            seen = 0

            def _inside() -> int:
                nonlocal seen
                if raw.in_transaction and not gate.entered.is_set():
                    seen += 1
                    if seen >= _INSIDE_AFTER_CALLBACKS:
                        gate._wait()
                return 0  # never abort the statement

            async def _run() -> Any:
                await self.set_progress_handler(_inside, 1)
                result = await real_execute(self, sql, parameters)
                # Cleared on success only. On a cancellation the thread may still be held, so a
                # queued clear would wait on the gate and stall the very unwind under test; the
                # handler is inert once the gate has fired anyway.
                # sqlite3 clears the handler on None; aiosqlite's stub omits that form.
                await self.set_progress_handler(None, 1)  # type: ignore[arg-type]
                return result

            return _run()

        async def gated_backup(self: aiosqlite.Connection, target: Any, **kwargs: Any) -> None:
            await self._execute(gate._wait)
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

    Fails on the pre-#1937 code at the first two assertions: there the held thread is the writer's,
    inside ``self._lock``."""
    from messagefoundry.store.crypto import generate_key

    n = 20
    store = await _store_with_rows_n(tmp_path / "msg.db", generate_key(), n)
    gate = _CopyGate()
    dest = tmp_path / "snap.db"
    try:
        gate.install(monkeypatch)
        snap = asyncio.create_task(store.snapshot_to(dest, method=snapshot_method))
        try:
            await _until(
                lambda: gate.entered.is_set() or snap.done(),
                timeout=_GATE_SECONDS,
                what="the snapshot copy to start",
            )
            if snap.done():
                await snap  # it failed before reaching the copy: surface that error, not a timeout
                pytest.fail("the snapshot finished without ever starting a gated copy")
            # The deciding checks, with no timing in them: the copy is held, and neither the store
            # lock nor the writer connection's thread is what holds it.
            assert not store._lock.locked(), (
                f"{snapshot_method}: the store write lock is held while the copy runs"
            )
            assert gate.held_on is not store._db._thread, (
                f"{snapshot_method}: the copy runs on the store's writer connection"
            )
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
            gate.release.set()
            await snap
    finally:
        monkeypatch.undo()
        await store.close()
    assert _sqlite_integrity_ok(dest)
    assert _sqlite_orphans(dest) == (0, 0)
    # Point-in-time, exactly. VACUUM INTO was held inside its read transaction, so the write landed
    # mid-copy and must be absent. The backup was held before its step, so the write precedes the
    # copy's snapshot and must be present.
    expected = n if snapshot_method == "vacuum_into" else n + 1
    assert _sqlite_count(dest, "messages") == expected


async def test_a_wal_checkpoint_during_the_copy_runs_passive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1937: a retention checkpoint that lands mid-copy must not TRUNCATE.

    The copy's read transaction pins the WAL, so a TRUNCATE there waits out the writer's 5 s busy
    timeout under the store lock and then fails anyway. The statement chosen is asserted, not how long
    the call took, so the check carries no timing."""
    from messagefoundry.store.crypto import generate_key

    store = await _store_with_rows_n(tmp_path / "msg.db", generate_key(), 5)
    gate = _CopyGate()
    seen: list[str] = []
    try:
        gate.install(monkeypatch)
        real = store._db.execute

        def spy(sql: str, parameters: Any = None) -> Any:
            if "wal_checkpoint" in sql:
                seen.append(sql)
            return real(sql, parameters)

        monkeypatch.setattr(store._db, "execute", spy)
        snap = asyncio.create_task(store.snapshot_to(tmp_path / "snap.db"))
        try:
            await _until(
                lambda: gate.entered.is_set() or snap.done(),
                timeout=_GATE_SECONDS,
                what="the snapshot copy to start",
            )
            if snap.done():
                await snap
                pytest.fail("the snapshot finished without ever starting a gated copy")
            # The snapshot's own opening checkpoint ran before any copy, so it truncates.
            assert seen == ["PRAGMA wal_checkpoint(TRUNCATE)"]
            assert store._snapshot_copies == 1
            seen.clear()
            await store.wal_checkpoint()
            assert seen == ["PRAGMA wal_checkpoint(PASSIVE)"]
        finally:
            gate.release.set()
            await snap
        seen.clear()
        assert store._snapshot_copies == 0
        await store.wal_checkpoint()  # no copy running now, so the ordinary TRUNCATE is back
        assert seen == ["PRAGMA wal_checkpoint(TRUNCATE)"]
    finally:
        monkeypatch.undo()
        await store.close()


async def test_a_cancelled_copy_is_interrupted_and_uncounted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #1937: cancelling a snapshot mid-copy interrupts the ``VACUUM INTO``, so the close does
    not queue behind the rest of it, and the running-copy count returns to zero."""
    from messagefoundry.store.crypto import generate_key

    store = await _store_with_rows_n(tmp_path / "msg.db", generate_key(), 5)
    gate = _CopyGate()
    interrupted: list[aiosqlite.Connection] = []
    real_interrupt = aiosqlite.Connection.interrupt

    async def spy_interrupt(self: aiosqlite.Connection) -> None:
        interrupted.append(self)
        await real_interrupt(self)

    try:
        gate.install(monkeypatch)
        monkeypatch.setattr(aiosqlite.Connection, "interrupt", spy_interrupt)
        snap = asyncio.create_task(store.snapshot_to(tmp_path / "snap.db"))
        await _until(
            lambda: gate.entered.is_set() or snap.done(),
            timeout=_GATE_SECONDS,
            what="the snapshot copy to start",
        )
        assert not snap.done(), "the snapshot finished without ever starting a gated copy"
        snap.cancel()
        await _until(lambda: bool(interrupted), timeout=_GATE_SECONDS, what="the interrupt")
        gate.release.set()  # the held statement resumes, sees the interrupt, and aborts
        with pytest.raises(asyncio.CancelledError):
            await snap
        assert len(interrupted) == 1 and interrupted[0] is not store._db
        assert store._snapshot_copies == 0
        # The store is unharmed: an ordinary snapshot still works after the cancelled one.
        await store.snapshot_to(tmp_path / "snap2.db")
    finally:
        gate.release.set()
        monkeypatch.undo()
        await store.close()
    assert _sqlite_integrity_ok(tmp_path / "snap2.db")


def test_the_snapshot_source_uri_survives_awkward_paths(tmp_path: Path) -> None:
    """The ``mode=ro`` URI opens a path holding a space, ``#`` and ``%`` (BACKLOG #1937)."""

    odd = tmp_path / "a b#c%25d"
    odd.mkdir()
    db = odd / "msg.db"
    sqlite3.connect(db).execute("CREATE TABLE t (x)").connection.close()
    conn = sqlite3.connect(_sqlite_readonly_uri(str(db.absolute())), uri=True)
    try:
        assert conn.execute("SELECT name FROM sqlite_master").fetchall() == [("t",)]
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("CREATE TABLE u (x)")  # read-only, so the store can never be written
    finally:
        conn.close()


@pytest.mark.skipif(sys.platform != "win32", reason="UNC paths are a Windows form")
def test_the_snapshot_source_uri_opens_a_unc_path(tmp_path: Path) -> None:
    """``as_uri()`` puts a UNC server in the URI authority, which SQLite refuses; the helper does not."""

    db = tmp_path / "msg.db"
    sqlite3.connect(db).execute("CREATE TABLE t (x)").connection.close()
    drive, rest = str(db.absolute()).split(":", 1)
    unc = f"\\\\localhost\\{drive}${rest}"
    if not Path(unc).exists():
        pytest.skip("the administrative share is not reachable on this host")
    uri = _sqlite_readonly_uri(unc)
    assert uri.startswith("file:////localhost/"), uri
    conn = sqlite3.connect(uri, uri=True)
    try:
        assert conn.execute("SELECT name FROM sqlite_master").fetchall() == [("t",)]
    finally:
        conn.close()


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
    assert _sqlite_orphans(dest) == (0, 0)
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
