# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1731 — the connection-event drainer writes one transaction per BURST, not per event.

Before this, ``_connection_event_drainer`` awaited one ``record_connection_event`` per queued event,
and each cost one INSERT plus one commit, so a connect-per-message sender paid extra commits for
every connection it opened. The drainer now takes whatever is already queued after its blocking get
and writes it with ``record_connection_events`` in one transaction.

SQLite counts every physical commit in ``MessageStore.committed_txns``, which is what these tests
read. The Postgres and SQL Server twins of the store-level test live in their own gated suites.

Two layers, and they are deliberately not the same rule. The STORE's burst is all-or-nothing, so a
failure leaves the table exactly as it was. The DRAINER then re-writes the refused burst one row at
a time, so the cost of one unwritable row is one observation rather than a whole burst of them.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
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


async def test_a_failed_burst_costs_only_its_bad_row_and_the_drainer_keeps_going(
    store: MessageStore, runner: RegistryRunner, caplog: pytest.LogCaptureFixture
) -> None:
    """One unwritable row must not take its neighbours down with it.

    The store's write stays all-or-nothing -- that is the transaction's job, and
    ``test_the_store_refuses_a_burst_all_or_nothing`` below pins it. The DRAINER's job is the other
    one: re-write the refused burst a row at a time, so a burst of 256 costs one observation rather
    than 256. The events either side of the bad row are the ones a reader most wants, because they
    are what happened around whatever went wrong.

    The bad row is rejected by SQLITE (a NULL into ``connection``, which is ``NOT NULL``) rather
    than by the driver's parameter binding, so the first row has really been stepped when the burst
    fails and the rollback has something to undo.
    """
    _enqueue(runner, _event(0))
    _enqueue(runner, _event(1, connection=None))
    _enqueue(runner, _event(2))
    task = _start_drainer(runner)
    before = store.committed_txns
    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await _join(runner)

    warnings = [
        r for r in caplog.records if "connection-event burst write failed" in r.getMessage()
    ]
    assert [r.getMessage() for r in warnings] == [
        # Two facts an operator acts on. The exception CLASS: one malformed row and a store that is
        # gone want opposite responses, and "the write failed" cannot tell them which they have.
        # And SALVAGED, not attempted -- this read "rewrote 3 ... dropped 1" for a burst of which
        # two landed, which is arithmetic that does not add up.
        "connection-event burst write failed (IntegrityError);"
        " salvaged 2 of 3 event(s) singly, dropped 1"
    ]
    kept = await store.list_connection_events()
    assert sorted(e.peer_host for e in kept) == ["10.0.0.0", "10.0.0.2"]
    # Two salvaged rows commit; the third rolls back and commits nothing.
    assert store.committed_txns - before == 2
    assert not store._db.in_transaction  # neither the failed burst nor the failed retry left one
    assert not task.done()

    _enqueue(runner, _event(4))
    await _join(runner)
    assert sorted(e.peer_host for e in await store.list_connection_events()) == [
        "10.0.0.0",
        "10.0.0.2",
        "10.0.0.4",
    ]


async def test_a_salvage_gives_up_once_the_store_itself_is_refusing(
    store: MessageStore, runner: RegistryRunner, caplog: pytest.LogCaptureFixture
) -> None:
    """The salvage must not pay a full retry for every row when nothing is writable.

    Each single-row retry costs a connection-acquire wait -- 30 seconds by default on the server
    backends -- so an unbounded salvage of a 256-row burst stalls the drainer for hours to rescue
    nothing. The cutoff is on CONSECUTIVE failures, so the one-bad-row case above is untouched.

    The store is made to refuse EVERY write, which is what a store that is gone looks like from
    here. The count in the message is the honest one: it names how many were salvaged and how many
    were dropped, not how many were attempted.
    """
    monkeypatch = pytest.MonkeyPatch()
    for i in range(10):
        _enqueue(runner, _event(i))

    attempts = 0

    async def always_refuses(events: object) -> None:
        nonlocal attempts
        attempts += 1
        raise sqlite3.OperationalError("injected: the store is gone")

    monkeypatch.setattr(store, "record_connection_events", always_refuses)
    task = _start_drainer(runner)
    try:
        with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
            await _join(runner)
    finally:
        monkeypatch.undo()

    # One burst write plus at most the cutoff's worth of single-row retries -- NOT one per row.
    assert attempts == 1 + wiring_runner._CONN_EVENT_SALVAGE_GIVE_UP
    [warning] = [r for r in caplog.records if "connection-event" in r.getMessage()]
    assert warning.getMessage() == (
        "connection-event burst write failed (OperationalError); salvaged 0 of 10 event(s), then"
        " gave up after 3 single-row failures in a row and dropped 10"
    )
    assert not task.done()  # the drainer survives a store that is refusing everything

    # And it recovers: the next burst is written normally once the store is back.
    _enqueue(runner, _event(4))
    await _join(runner)
    assert [e.peer_host for e in await store.list_connection_events()] == ["10.0.0.4"]


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


async def test_the_store_refuses_a_burst_all_or_nothing(store: MessageStore) -> None:
    """The store's own contract, separate from the drainer's salvage above.

    The bad row is rejected by SQLITE, not by the driver: ``connection`` is ``NOT NULL``, and NULL
    binds without complaint, so row 1 has been stepped when row 2 fails. That is what makes this a
    test of the ROLLBACK -- a row the driver refused before sending would leave the table unchanged
    whether or not a transaction was there, so the assertion would hold for the wrong reason.
    """
    await store.record_connection_events([_event(0, now=100.0)])
    before = store.committed_txns
    with pytest.raises(sqlite3.IntegrityError):
        await store.record_connection_events(
            [_event(1, now=200.0), _event(2, now=201.0, connection=None)]
        )
    # On the CONTENT: a missing rollback leaves the ts=200.0 row, and naming it is what separates
    # "rolled back" from "never reached the table".
    assert [e.ts for e in await store.list_connection_events()] == [100.0]
    assert store.committed_txns == before  # a refused burst commits nothing
    assert not store._db.in_transaction  # and leaves no transaction open for the next writer
