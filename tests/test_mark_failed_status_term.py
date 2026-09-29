# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0157 Amendment A (BACKLOG #2078, #2348): ``mark_failed``'s retry branch re-pends only an
INFLIGHT row, on SQLite.

The race: a worker claims a row, and while its send is failing something else resolves the row. An
operator dead-letters it, a successor delivers it, a recovery re-pends it. The late worker then calls
``mark_failed``. Before the amendment its retry UPDATE matched on ``id`` alone, so it put a DONE or DEAD
row back in the queue (a second send) and wrote a ``failed`` event on a finished message.

Each race test here has its positive control beside it: an INFLIGHT row still re-pends, with its event.
The Postgres and SQL Server twins run on the hosted legs in ``tests/test_adr0157_postgres_fence.py`` and
``tests/test_adr0157_sqlserver_fence.py``; the SQL Server offline twin is in
``tests/test_adr0157_sqlserver_fence_offline.py``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus

_RETRY = RetryPolicy(max_attempts=None, backoff_seconds=5, backoff_multiplier=1)


@pytest.fixture(params=[0.0, 2.0], ids=["inline", "group-commit"])
async def store(tmp_path: Path, request: pytest.FixtureRequest) -> AsyncIterator[MessageStore]:
    """Both write paths: the inline transaction, and a member of the group-commit batch."""
    s = await MessageStore.open(tmp_path / "t.db", group_commit_window_ms=request.param)
    try:
        yield s
    finally:
        await s.close()


async def _failed_events(store: MessageStore, message_id: str) -> int:
    return sum(1 for e in await store.events_for(message_id) if e["event"] == "failed")


async def _message_status(store: MessageStore, message_id: str) -> str:
    msg = await store.get_message(message_id)
    assert msg is not None
    return str(msg["status"])


async def _claimed(store: MessageStore, *dests: str) -> tuple[str, list[str]]:
    mid = await store.enqueue_message(
        channel_id="IB", raw="MSH|x", deliveries=[(d, "p") for d in dests], now=100.0
    )
    items = await store.claim_ready(now=100.0)
    return mid, [i.id for i in sorted(items, key=lambda i: i.destination_name or "")]


async def test_an_inflight_row_still_re_pends_with_its_event(store: MessageStore) -> None:
    """The positive control for every test below: the status term must not stop a genuine retry."""
    mid, (oid,) = await _claimed(store, "OB1")

    next_at = await store.mark_failed(oid, "boom", _RETRY, now=100.0)

    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value
    assert next_at == row["next_attempt_at"] == 105.0
    assert await _failed_events(store, mid) == 1


async def test_a_late_worker_cannot_re_pend_a_done_row(store: MessageStore) -> None:
    mid, (oid,) = await _claimed(store, "OB1")
    await store.mark_done(oid, now=101.0)  # the row finished while the late send was failing

    next_at = await store.mark_failed(oid, "late failure", _RETRY, now=102.0)

    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.DONE.value
    assert await _message_status(store, mid) == MessageStatus.PROCESSED.value
    assert await _failed_events(store, mid) == 0  # no 'failed' event on a PROCESSED message
    assert await store.claim_ready(now=10_000.0) == []  # nothing to send twice
    # Ruling item 3: the retry time still comes back, so the caller's wake is armed as before.
    assert next_at == 107.0


async def test_a_late_worker_cannot_re_pend_a_dead_row(store: MessageStore) -> None:
    mid, (oid,) = await _claimed(store, "OB1")
    await store.dead_letter_now(oid, "operator dead-letter", now=101.0)

    await store.mark_failed(oid, "late failure", _RETRY, now=102.0)

    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.DEAD.value
    assert await _message_status(store, mid) == MessageStatus.ERROR.value
    assert await _failed_events(store, mid) == 0
    assert await store.claim_ready(now=10_000.0) == []


async def test_a_late_worker_cannot_re_pend_a_cancelled_row(store: MessageStore) -> None:
    """CANCELLED is terminal too. ``cancel_queued`` binds PENDING rows only, so the row is flipped
    directly here to stand for any writer that resolved it mid-send."""
    mid, (oid,) = await _claimed(store, "OB1")
    await store._db.execute(
        "UPDATE queue SET status=? WHERE id=?", (OutboxStatus.CANCELLED.value, oid)
    )
    await store._db.commit()

    await store.mark_failed(oid, "late failure", _RETRY, now=102.0)

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.CANCELLED.value
    assert await _failed_events(store, mid) == 0


async def test_a_row_something_else_re_pended_keeps_its_own_schedule(store: MessageStore) -> None:
    """A recovery (here ``release_claimed``) already put the row back. The late retry changes nothing
    on it, not even its deadline, and the row is still claimable: declining it strands nothing."""
    mid, (oid,) = await _claimed(store, "OB1")
    await store.release_claimed([oid], now=101.0)
    before = (await store.outbox_for(mid))[0]

    next_at = await store.mark_failed(oid, "late failure", _RETRY, now=102.0)

    after = (await store.outbox_for(mid))[0]
    assert after["status"] == OutboxStatus.PENDING.value
    assert after["next_attempt_at"] == before["next_attempt_at"]
    assert after["last_error"] == before["last_error"]
    assert await _failed_events(store, mid) == 0
    assert isinstance(next_at, float)
    assert [i.id for i in await store.claim_ready(now=before["next_attempt_at"])] == [oid]


async def test_the_dead_branch_is_unchanged(store: MessageStore) -> None:
    """C2 keeps a status term off terminal resolves, so the amendment does not touch the DEAD branch.
    Pinned so a later edit that spreads the term to both branches has to change this test on purpose."""
    mid, (oid,) = await _claimed(store, "OB1")
    await store.mark_failed(oid, "boom", _RETRY, now=100.0)  # PENDING, not INFLIGHT, attempts 1

    assert await store.mark_failed(oid, "boom", RetryPolicy(max_attempts=1), now=102.0) is None

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DEAD.value


async def test_a_batch_retry_re_pends_only_the_members_still_inflight(store: MessageStore) -> None:
    """Partial match, stated as a choice: a member no longer INFLIGHT is skipped, event and all, and
    the members still INFLIGHT re-pend together to the one shared deadline."""
    mid, (a, b) = await _claimed(store, "OB1", "OB2")
    await store.mark_done(a, now=101.0)

    next_at = await store.mark_batch_failed([a, b], "envelope failed", _RETRY, now=102.0)

    rows = {r["destination_name"]: r for r in await store.outbox_for(mid)}
    assert rows["OB1"]["status"] == OutboxStatus.DONE.value
    assert rows["OB2"]["status"] == OutboxStatus.PENDING.value
    assert next_at == rows["OB2"]["next_attempt_at"] == 107.0
    assert await _failed_events(store, mid) == 1


async def test_a_batch_retry_with_no_member_inflight_writes_nothing(store: MessageStore) -> None:
    mid, (a, b) = await _claimed(store, "OB1", "OB2")
    await store.mark_done(a, now=101.0)
    await store.mark_done(b, now=101.0)

    next_at = await store.mark_batch_failed([a, b], "envelope failed", _RETRY, now=102.0)

    assert {r["status"] for r in await store.outbox_for(mid)} == {OutboxStatus.DONE.value}
    assert await _failed_events(store, mid) == 0
    assert next_at == 107.0
