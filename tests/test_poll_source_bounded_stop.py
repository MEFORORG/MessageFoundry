# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An ordinary stop() of the Database and RemoteFile sources is bounded (BACKLOG #4685).

Both used to join their poll task with no bound of their own, so a poll blocked on a hung database
or an unreachable share held a shutdown or a reload until the call returned. Each now waits
``POLL_STOP_GRACE_S``, then cancels the task and logs, as ``FileSource.stop()`` does (BACKLOG
#1620); a store call is never cut. The Timer source keeps its unbounded join: its only awaits are
the stop signal and the hand-off, so a bound could only ever cut a store call.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any

import pytest

from messagefoundry.transports import database as database_module
from messagefoundry.transports import remotefile as remotefile_module
from messagefoundry.transports.base import PollStopGuard
from tests.test_database_transport import _MARKED_1, _noop, _started, _StepCursor
from tests.test_remotefile_transport import _FakeClient, _FakeLedger, _settle, _src

_DB_LOGGER = "messagefoundry.transports.database"
_REMOTE_LOGGER = "messagefoundry.transports.remotefile"


# --- the guard ---------------------------------------------------------------


async def test_the_guard_gives_a_full_grace_after_a_store_call() -> None:
    """The store call lasts 1.5 graces and the task ends 0.75 grace after it. The guard must wait
    for that, because the task always gets a full grace after a store call to reach its next stop
    check. Mutation: drop the ``max(deadline, ended + grace)`` restart. Red: the guard gives up at
    2 graces, before the task ends."""
    grace = 0.5
    guard = PollStopGuard()
    entered = asyncio.Event()

    async def poll() -> None:
        with guard.store_call():
            entered.set()
            await asyncio.sleep(1.5 * grace)
        await asyncio.sleep(0.75 * grace)  # the next step, which the stop check follows

    task = asyncio.create_task(poll())
    await entered.wait()
    assert await asyncio.wait_for(guard.join(task, grace), 10) is True
    assert not guard.inside(task)


async def test_the_guard_gives_up_outside_a_store_call() -> None:
    """Control: a task blocked outside any store call is given up on after one grace."""
    guard = PollStopGuard()
    task = asyncio.create_task(asyncio.Event().wait())
    try:
        started = time.monotonic()
        assert await asyncio.wait_for(guard.join(task, 0.1), 5) is False
        assert time.monotonic() - started < 2
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


# --- Database ----------------------------------------------------------------


async def test_database_stop_gives_up_on_a_blocked_select(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The select hangs, as one against an unresponsive server does. Mutation: join the poll task
    with no bound again. Red: stop() does not return within 3 s."""
    monkeypatch.setattr(database_module, "POLL_STOP_GRACE_S", 0.2)
    cur = _StepCursor(["id", "payload"], [], hang_from=1)
    src, poll = await _started(cur, _noop)
    pool = src._pool
    await asyncio.wait_for(cur.in_select.wait(), 5)
    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger=_DB_LOGGER):
        await asyncio.wait_for(src.stop(), 3)
    elapsed = time.monotonic() - started

    assert elapsed < 2, f"stop() took {elapsed:.2f}s against a 0.2s grace"
    assert poll.cancelled()
    assert src._task is None and pool.closed
    assert any("did not stop within" in r.getMessage() for r in caplog.records)


async def test_database_stop_never_cuts_a_hand_off_in_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hand-off is the durable store commit. A stop that arrives mid-hand-off waits it out, past
    the grace, and the row is then marked. Mutation: give up regardless of the store call. Red: the
    hand-off is cut, nothing commits and the row is never marked."""
    monkeypatch.setattr(database_module, "POLL_STOP_GRACE_S", 0.2)
    entered = asyncio.Event()
    committed: list[bytes] = []

    async def slow_commit(raw: bytes) -> str | None:
        entered.set()
        await asyncio.sleep(0.5)  # 2.5 graces long
        committed.append(raw)
        return None

    cur = _StepCursor(["id", "payload"], [(1, "AAA"), (2, "BBB")])
    src, poll = await _started(cur, slow_commit)
    await asyncio.wait_for(entered.wait(), 5)
    await asyncio.wait_for(src.stop(), 10)

    assert committed == [b"AAA"], "the hand-off was cut short"
    assert cur.marks == _MARKED_1  # marked, and the stop check kept the second row back
    assert not poll.cancelled()


async def test_database_stop_is_bounded_behind_a_call_that_ignores_the_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mark that does not yield to the cut keeps the poll task alive past it, as a driver call
    held on a thread can. stop() still returns, with the pool closed under the task, and the next
    stop() joins it. The committed row is left unmarked, the duplicate a failed mark makes.
    Mutation: close the pool without a bound after an ordinary cut. Red: stop() hangs on the
    connection the mark still holds."""
    monkeypatch.setattr(database_module, "POLL_STOP_GRACE_S", 0.1)
    monkeypatch.setattr(database_module, "_CUT_JOIN_TIMEOUT_S", 0.05)
    monkeypatch.setattr(database_module, "_POOL_CLOSE_TIMEOUT_S", 0.05)
    cur = _StepCursor(
        ["id", "payload"],
        [(1, "AAA")],
        mark_gate=asyncio.Event(),
        hold_through_cancel=asyncio.Event(),
    )
    assert cur.hold_through_cancel is not None
    src, poll = await _started(cur, _noop)
    pool = src._pool
    await asyncio.wait_for(cur.in_mark.wait(), 5)
    stop = asyncio.create_task(src.stop())
    try:
        # wait, not wait_for: on a head without the bound, wait_for's cancel of the hung stop would
        # take the cancelled path instead of failing the test.
        done, _ = await asyncio.wait({stop}, timeout=5)
        assert done, "an ordinary stop() did not return behind a held driver call"
        stop.result()
        assert src._task is poll and not poll.done() and pool.closed
    finally:
        cur.hold_through_cancel.set()
        await asyncio.wait_for(asyncio.gather(poll, stop, return_exceptions=True), 5)
    await asyncio.wait_for(src.stop(), 5)
    assert poll.cancelled() and src._task is None
    assert cur.marks == []


# --- RemoteFile --------------------------------------------------------------


def _blocked_listing(
    monkeypatch: pytest.MonkeyPatch,
    client: _FakeClient,
    entered: threading.Event,
    release: threading.Event,
) -> None:
    """Make the client's listing block on its thread, as one against an unreachable server does."""

    def blocked(_remote_dir: str) -> list[Any]:
        entered.set()
        release.wait(10)
        return []

    monkeypatch.setattr(client, "list_entries", blocked)


async def test_remotefile_stop_gives_up_on_a_blocked_listing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Mutation: restore the unbounded ``gather`` in ``stop()``. Red: stop() does not return within
    3 s (it waits for the blocked call)."""
    monkeypatch.setattr(remotefile_module, "POLL_STOP_GRACE_S", 0.2)
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A"})
    src = _src(monkeypatch, client)
    entered, release = threading.Event(), threading.Event()
    _blocked_listing(monkeypatch, client, entered, release)
    await src.start(_noop)
    poll = src._task
    assert poll is not None
    try:
        assert await asyncio.to_thread(entered.wait, 5), "the poll never reached the listing"
        started = time.monotonic()
        with caplog.at_level(logging.WARNING, logger=_REMOTE_LOGGER):
            await asyncio.wait_for(src.stop(), 3)
        elapsed = time.monotonic() - started
    finally:
        release.set()

    assert elapsed < 2, f"stop() took {elapsed:.2f}s against a 0.2s grace"
    assert poll.cancelled() and src._task is None
    assert "/in/a.hl7" in client.files  # nothing was read or moved
    assert any("did not stop within" in r.getMessage() for r in caplog.records)


async def test_remotefile_stop_never_cuts_a_hand_off_in_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hand-off and the leave-mode ledger write after it are store calls. A stop that arrives
    mid-hand-off waits them out, past the grace, and the file is recorded as ingested. Leave mode
    keeps every step after the hand-off on the loop, so no thread hop can outlast the grace.
    Mutation: give up regardless of the store call. Red: the hand-off is cut and nothing is
    recorded."""
    monkeypatch.setattr(remotefile_module, "POLL_STOP_GRACE_S", 0.2)
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A"})
    src = _src(monkeypatch, client, after_read="leave")
    ledger = _FakeLedger()
    src.processed_ledger = ledger
    entered = asyncio.Event()
    committed: list[bytes] = []

    async def slow_commit(raw: bytes) -> str | None:
        entered.set()
        await asyncio.sleep(0.5)  # 2.5 graces long
        committed.append(raw)
        return None

    src._handler = slow_commit
    await _settle(src)  # the settle poll (BACKLOG #2071): records the size, reads nothing
    src._poll_seconds = 0.0
    await src.start(slow_commit)
    poll = src._task
    assert poll is not None
    await asyncio.wait_for(entered.wait(), 5)
    await asyncio.wait_for(src.stop(), 10)

    assert committed == [b"MSH|^~\\&|A"], "the hand-off was cut short"
    assert len(ledger.keys) == 1, "the file was not recorded as ingested"
    assert not poll.cancelled()


class _SlowLedger(_FakeLedger):
    """A leave-mode ledger whose read or write, once armed, outlasts the stop grace."""

    def __init__(self, slow: str) -> None:
        super().__init__()
        self.slow = slow
        self.armed = False
        self.entered = asyncio.Event()

    async def _maybe_wait(self, method: str) -> None:
        if self.armed and method == self.slow:
            self.entered.set()
            await asyncio.sleep(0.5)  # 2.5 graces long

    async def is_processed(self, file_key: str) -> bool:
        await self._maybe_wait("is_processed")
        return await super().is_processed(file_key)

    async def mark_processed(self, file_key: str) -> None:
        await self._maybe_wait("mark_processed")
        await super().mark_processed(file_key)


@pytest.mark.parametrize("slow", ["is_processed", "mark_processed"])
async def test_remotefile_stop_never_cuts_a_ledger_call(
    monkeypatch: pytest.MonkeyPatch, slow: str
) -> None:
    """The leave-mode ledger read and write are store calls too. A stop that arrives inside one
    waits it out, past the grace. Mutation: drop the ``store_call()`` around that ledger call. Red:
    the poll task is cancelled inside it."""
    monkeypatch.setattr(remotefile_module, "POLL_STOP_GRACE_S", 0.2)
    client = _FakeClient(files={"/in/a.hl7": b"MSH|^~\\&|A"})
    src = _src(monkeypatch, client, after_read="leave")
    ledger = _SlowLedger(slow)
    src.processed_ledger = ledger
    src._handler = _noop
    await _settle(src)
    ledger.armed = True
    src._poll_seconds = 0.0
    await src.start(_noop)
    poll = src._task
    assert poll is not None
    await asyncio.wait_for(ledger.entered.wait(), 5)
    await asyncio.wait_for(src.stop(), 10)

    assert not poll.cancelled(), f"stop() cut the poll task inside the ledger's {slow}"
    if slow == "mark_processed":
        assert len(ledger.keys) == 1, "the file was not recorded as ingested"


async def test_a_cancelled_remotefile_stop_still_cuts_the_poll_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancel of stop() itself, as the runner's outer cancel sends, cuts the poll task at once,
    as the ``gather`` join before the bound did (ADR 0157 Amendment B). Mutation: drop the
    ``task.cancel()`` in stop()'s cancel arm. Red: the task is left blocked in the listing."""
    monkeypatch.setattr(remotefile_module, "POLL_STOP_GRACE_S", 60.0)
    client = _FakeClient()
    src = _src(monkeypatch, client)
    entered, release = threading.Event(), threading.Event()
    _blocked_listing(monkeypatch, client, entered, release)
    await src.start(_noop)
    poll = src._task
    assert poll is not None
    try:
        assert await asyncio.to_thread(entered.wait, 5), "the poll never reached the listing"
        stop = asyncio.create_task(src.stop())
        await asyncio.sleep(0)  # stop() is now waiting on the poll task
        stop.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(stop, 5)
        done, _ = await asyncio.wait({poll}, timeout=5)
        assert done and poll.cancelled(), "a cancelled stop() left the poll task running"
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(poll, return_exceptions=True), 15)
