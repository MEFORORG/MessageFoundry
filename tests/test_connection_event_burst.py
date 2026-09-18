# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1731 — the connection-event drainer writes one transaction per BURST, not per event.

Before this, ``_connection_event_drainer`` awaited one ``record_connection_event`` per queued event,
and each cost one INSERT plus one commit, so a connect-per-message sender paid extra commits for
every connection it opened. The drainer now takes whatever is already queued after its blocking get
and writes it with ``record_connection_events`` in one transaction.

SQLite counts every physical commit in ``MessageStore.committed_txns``, which is what these tests
read. The Postgres and SQL Server twins of the store-level test live in their own gated suites.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.store.store import ConnectionEventWrite


def _event(i: int, **over: object) -> ConnectionEventWrite:
    ev = ConnectionEventWrite(
        connection=f"IB_T{i % 2}",
        transport="mllp",
        direction="inbound",
        kind="established" if i % 2 == 0 else "closed",
        peer_host=f"10.0.0.{i}",
        message_id=None,
        reason=None if i % 2 == 0 else f"clean eof {i}",
    )
    ev.update(over)  # type: ignore[typeddict-item]
    return ev


def _enqueue(runner: RegistryRunner, ev: ConnectionEventWrite) -> None:
    """Through the real emit helper, never ``q.put_nowait``, so the queue item shape is the runner's."""
    runner._enqueue_connection_event(
        connection=ev["connection"],
        transport=ev["transport"],
        direction=ev["direction"],
        kind=ev["kind"],
        peer_host=ev["peer_host"],
        message_id=ev["message_id"],
        reason=ev["reason"],
    )


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "burst.db")
    try:
        yield s
    finally:
        await s.close()


@pytest.fixture
async def runner(store: MessageStore) -> AsyncIterator[RegistryRunner]:
    r = RegistryRunner(Registry(), store)
    r._conn_event_q = asyncio.Queue(maxsize=1000)  # normally created in start()
    yield r
    if r._conn_event_drainer is not None:
        r._conn_event_drainer.cancel()
        await asyncio.gather(r._conn_event_drainer, return_exceptions=True)


def _start_drainer(runner: RegistryRunner) -> asyncio.Task[None]:
    task = asyncio.create_task(runner._connection_event_drainer())
    runner._conn_event_drainer = task
    return task


async def _join(runner: RegistryRunner) -> None:
    q = runner._conn_event_q
    assert q is not None
    # The teardown flush contract: join() resolves only once every event was written or dropped.
    await asyncio.wait_for(q.join(), 2.0)


async def test_a_queued_burst_costs_one_commit_and_lands_every_row(
    store: MessageStore, runner: RegistryRunner
) -> None:
    k = 20
    for i in range(k):
        _enqueue(runner, _event(i))
    before = store.committed_txns
    _start_drainer(runner)
    await _join(runner)

    assert store.committed_txns - before == 1, "a burst must cost ONE commit, not one per event"
    events = await store.list_connection_events(limit=100)
    assert len(events) == k
    by_peer = {e.peer_host: e for e in events}
    for i in range(k):
        e = by_peer[f"10.0.0.{i}"]
        assert e.connection == f"IB_T{i % 2}" and e.transport == "mllp"
        assert e.direction == "inbound" and e.message_id is None
        assert e.kind == ("established" if i % 2 == 0 else "closed")
        assert e.reason == (None if i % 2 == 0 else f"clean eof {i}")


async def test_a_backlog_is_written_in_bounded_slices(
    store: MessageStore, runner: RegistryRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(wiring_runner, "_CONN_EVENT_BURST_MAX", 4)
    for i in range(10):
        _enqueue(runner, _event(i))
    before = store.committed_txns
    _start_drainer(runner)
    await _join(runner)
    assert store.committed_txns - before == 3  # 4 + 4 + 2
    assert len(await store.list_connection_events(limit=100)) == 10


async def test_a_single_event_is_written_without_lingering(
    store: MessageStore, runner: RegistryRunner
) -> None:
    _start_drainer(runner)
    await asyncio.sleep(0)  # the drainer is now parked on the blocking get
    before = store.committed_txns
    _enqueue(runner, _event(1))
    # No linger window: the lone event is written as soon as the drainer wakes, well inside this bound.
    await asyncio.wait_for(runner._conn_event_q.join(), 0.5)  # type: ignore[union-attr]
    assert store.committed_txns - before == 1
    [e] = await store.list_connection_events()
    assert e.kind == "closed" and e.reason == "clean eof 1"


async def test_a_failed_burst_is_dropped_once_and_the_drainer_keeps_going(
    store: MessageStore, runner: RegistryRunner, caplog: pytest.LogCaptureFixture
) -> None:
    # A value SQLite cannot bind fails the SECOND row of the INSERT, after the first has executed,
    # so this is a real mid-burst failure inside the store's transaction, not a stub raising early.
    _enqueue(runner, _event(0))
    _enqueue(runner, _event(1, peer_host=object()))
    _enqueue(runner, _event(2))
    task = _start_drainer(runner)
    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await _join(runner)

    drops = [r for r in caplog.records if "connection-event write failed" in r.getMessage()]
    assert [r.getMessage() for r in drops] == ["connection-event write failed; dropping 3 event(s)"]
    assert await store.list_connection_events() == []  # all-or-nothing: row 0 did not survive
    assert not store._db.in_transaction  # the failed burst left no open transaction behind
    assert not task.done()

    _enqueue(runner, _event(4))
    await _join(runner)
    [e] = await store.list_connection_events()
    assert e.peer_host == "10.0.0.4"


async def test_stop_flushes_a_queued_burst(store: MessageStore) -> None:
    runner = RegistryRunner(Registry(), store)
    await runner.start()
    try:
        assert runner._conn_event_q is not None and runner._conn_event_drainer is not None
        for i in range(5):
            _enqueue(runner, _event(i))
    finally:
        await asyncio.wait_for(runner.stop(), timeout=5.0)
    assert runner._conn_event_q is None
    assert len(await store.list_connection_events(limit=100)) == 5


async def test_the_store_writes_a_burst_in_one_transaction(store: MessageStore) -> None:
    before = store.committed_txns
    await store.record_connection_events([_event(i, now=100.0 + i) for i in range(3)])
    assert store.committed_txns - before == 1
    events = await store.list_connection_events()
    assert [e.ts for e in events] == [102.0, 101.0, 100.0]
    assert [e.reason for e in events] == [None, "clean eof 1", None]

    before = store.committed_txns
    await store.record_connection_events([])
    assert store.committed_txns == before  # an empty burst opens no transaction
