# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0157 Amendment A (BACKLOG #2078, #2348): ``mark_failed``'s retry branch re-pends only an
INFLIGHT or PENDING row, on SQLite. The PENDING half is the owner's widening of 2026-09-29.

The race: a worker claims a row, and while its send is failing something else resolves the row. An
operator dead-letters it, a successor delivers it, a recovery re-pends it. The late worker then calls
``mark_failed``. Before the amendment its retry UPDATE matched on ``id`` alone, so it put a DONE or DEAD
row back in the queue (a second send) and wrote a ``failed`` event on a finished message.

The first cut of the amendment matched INFLIGHT only. On clustered Postgres a send that outlasts
``lease_ttl_seconds`` is re-pended by ``reclaim_expired_leases`` with ``next_attempt_at=now``, so that
cut dropped the attempt's backoff, its ``failed`` event and its ``last_error``, on every such attempt.
The widened term keeps all three for a PENDING row. Terminal rows are still no-ops, as the controls.

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


async def _sweep(store: MessageStore, oid: str, now: float) -> None:
    """Stand in for Postgres's ``reclaim_expired_leases``, which SQLite does not have: INFLIGHT to
    PENDING, due at once, the claim's ``attempts`` increment kept."""
    await store._db.execute(
        "UPDATE queue SET status=?, next_attempt_at=?, updated_at=? WHERE id=? AND status=?",
        (OutboxStatus.PENDING.value, now, now, oid, OutboxStatus.INFLIGHT.value),
    )
    await store._db.commit()


async def test_a_swept_pending_row_takes_the_backoff_the_event_and_the_error(
    store: MessageStore,
) -> None:
    """The owner's widening (2026-09-29). A lease sweep re-pended the row, due at once, while its
    send was still failing. The late retry must still apply its backoff, write its ``failed`` event
    and record its ``last_error``. Before the widening all three were lost on every such attempt, so
    the row kept no durable backoff and no record. Mutation: narrow the term back to INFLIGHT only."""
    mid, (oid,) = await _claimed(store, "OB1")
    await _sweep(store, oid, now=101.0)

    next_at = await store.mark_failed(oid, "late failure", _RETRY, now=102.0)

    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value
    assert next_at == row["next_attempt_at"] == 107.0  # the backoff, not the sweep's "now"
    assert row["last_error"] == "late failure"
    assert row["attempts"] == 1  # mark_failed never touches the count; the next claim bumps it
    assert await _failed_events(store, mid) == 1
    assert await store.claim_ready(now=106.0) == []  # not due inside the backoff
    assert [i.id for i in await store.claim_ready(now=107.0)] == [oid]  # still claimable: no strand


async def test_a_swept_row_a_successor_already_re_claimed_is_re_pended_and_nothing_strands(
    store: MessageStore,
) -> None:
    """The owner-accepted residual, unchanged by the widening. The sweep re-pended the row and a
    successor claimed it again, so it is INFLIGHT under the successor when the late retry lands. The
    term is true, so the row goes back to PENDING while the successor is still sending: one more send
    later, which at-least-once allows. What this pins is that nothing is lost or stranded. The
    successor's own resolve still lands, because the terminal resolves carry no status term (C2)."""
    mid, (oid,) = await _claimed(store, "OB1")
    await _sweep(store, oid, now=101.0)
    assert [i.id for i in await store.claim_ready(now=101.0)] == [oid]  # the successor, attempts 2

    await store.mark_failed(oid, "late failure", _RETRY, now=102.0)
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.PENDING.value

    await store.mark_done(oid, now=103.0)  # the successor's send succeeded

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DONE.value
    assert await _message_status(store, mid) == MessageStatus.PROCESSED.value
    assert await store.claim_ready(now=10_000.0) == []


async def test_a_successor_failure_after_the_late_re_pend_keeps_its_own_record(
    store: MessageStore,
) -> None:
    """The same interleaving, with the successor's send failing too. The late retry left the row
    PENDING, so under the INFLIGHT-only term the successor's own ``mark_failed`` would have missed and
    lost its record. The widened term lands it: both failures are recorded, the row is PENDING and
    claimable, and the deadline is the later of the two writes."""
    mid, (oid,) = await _claimed(store, "OB1")
    await _sweep(store, oid, now=101.0)
    await store.claim_ready(now=101.0)  # the successor, attempts 2
    await store.mark_failed(oid, "late failure", _RETRY, now=102.0)

    next_at = await store.mark_failed(oid, "successor failure", _RETRY, now=103.0)

    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value
    assert next_at == row["next_attempt_at"] == 108.0
    assert row["last_error"] == "successor failure"
    assert await _failed_events(store, mid) == 2
    assert [i.id for i in await store.claim_ready(now=108.0)] == [oid]


async def test_a_second_retry_on_a_pending_row_moves_its_deadline_by_the_gap_only(
    store: MessageStore,
) -> None:
    """Re-pending an already-PENDING row rewrites ``next_attempt_at``. Both writers compute the backoff
    from the same stored ``attempts``, so the later write moves the deadline later by the gap between
    the two calls, never earlier. A wake armed for the earlier deadline fires early, claims nothing,
    and the dispatcher's sweep backstop picks the row up at the new one: latency, not loss."""
    mid, (oid,) = await _claimed(store, "OB1")
    first = await store.mark_failed(oid, "first", _RETRY, now=102.0)

    second = await store.mark_failed(oid, "second", _RETRY, now=104.0)

    assert first == 107.0 and second == 109.0
    assert (await store.outbox_for(mid))[0]["next_attempt_at"] == 109.0
    assert await store.claim_ready(now=107.0) == []
    assert [i.id for i in await store.claim_ready(now=109.0)] == [oid]


async def test_a_late_retry_lands_on_a_row_the_operator_replayed(store: MessageStore) -> None:
    """A cost of the widening, pinned so it is a choice and not a surprise. An operator dead-letters
    the row mid-send and then replays it, so it is PENDING again with ``attempts=0`` and no error.
    The late retry now lands on it: it takes one base backoff, the late send's ``last_error`` and a
    ``failed`` event labelled ``attempt 0``. Nothing is lost and the row is still claimable.

    The multiplier is 2 on purpose. The exponent is ``attempts - 1``, floored at 0, so ``attempts=0``
    takes ``backoff_seconds`` exactly: 102 + 5. Without the floor it would be 102 + 2.5."""
    mid, (oid,) = await _claimed(store, "OB1")
    await store.dead_letter_now(oid, "operator dead-letter", now=101.0)
    assert await store.replay_dead(now=101.5) == 1
    policy = RetryPolicy(max_attempts=None, backoff_seconds=5, backoff_multiplier=2)

    next_at = await store.mark_failed(oid, "late failure", policy, now=102.0)

    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value
    assert next_at == row["next_attempt_at"] == 107.0
    assert row["last_error"] == "late failure"
    assert [e["detail"] for e in await store.events_for(mid) if e["event"] == "failed"] == [
        "attempt 0: late failure"
    ]
    assert [i.id for i in await store.claim_ready(now=107.0)] == [oid]


async def test_a_zero_multiplier_on_a_reset_row_does_not_raise(store: MessageStore) -> None:
    """``backoff_multiplier`` is not validated, so 0 is accepted. On a row a replay reset to
    ``attempts=0``, an unfloored exponent evaluates ``0.0 ** -1`` and raises ZeroDivisionError from
    inside the store call. The floor makes it the base backoff instead."""
    mid, (oid,) = await _claimed(store, "OB1")
    await store.dead_letter_now(oid, "operator dead-letter", now=101.0)
    await store.replay_dead(now=101.5)
    policy = RetryPolicy(max_attempts=None, backoff_seconds=5, backoff_multiplier=0)

    assert await store.mark_failed(oid, "late failure", policy, now=102.0) == 107.0
    assert await store.mark_batch_failed([oid], "late failure", policy, now=103.0) == 108.0


async def test_the_dead_branch_is_unchanged(store: MessageStore) -> None:
    """C2 keeps a status term off terminal resolves, so the amendment does not touch the DEAD branch.
    Pinned so a later edit that spreads the term to both branches has to change this test on purpose."""
    mid, (oid,) = await _claimed(store, "OB1")
    await store.mark_failed(oid, "boom", _RETRY, now=100.0)  # PENDING, not INFLIGHT, attempts 1

    assert await store.mark_failed(oid, "boom", RetryPolicy(max_attempts=1), now=102.0) is None

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DEAD.value


async def test_a_batch_retry_skips_only_a_terminal_member(store: MessageStore) -> None:
    """Partial match, stated as a choice: a terminal member is skipped, event and all, and the
    members still INFLIGHT re-pend together to the one shared deadline."""
    mid, (a, b) = await _claimed(store, "OB1", "OB2")
    await store.mark_done(a, now=101.0)

    next_at = await store.mark_batch_failed([a, b], "envelope failed", _RETRY, now=102.0)

    rows = {r["destination_name"]: r for r in await store.outbox_for(mid)}
    assert rows["OB1"]["status"] == OutboxStatus.DONE.value
    assert rows["OB2"]["status"] == OutboxStatus.PENDING.value
    assert next_at == rows["OB2"]["next_attempt_at"] == 107.0
    assert await _failed_events(store, mid) == 1


async def test_a_batch_retry_re_pends_a_swept_member_with_the_rest(store: MessageStore) -> None:
    """The widening's batch twin. A member the lease sweep re-pended is PENDING, not terminal, so it
    re-pends to the one shared deadline with the INFLIGHT member and gets its own event, instead of
    keeping the sweep's "now". The two members sit on different destinations here, so this pins the
    shared deadline and not an ADR 0082 envelope's lane position."""
    mid, (a, b) = await _claimed(store, "OB1", "OB2")
    await _sweep(store, a, now=101.0)

    next_at = await store.mark_batch_failed([a, b], "envelope failed", _RETRY, now=102.0)

    rows = await store.outbox_for(mid)
    assert {r["status"] for r in rows} == {OutboxStatus.PENDING.value}
    assert {r["next_attempt_at"] for r in rows} == {next_at} == {107.0}
    assert {r["last_error"] for r in rows} == {"envelope failed"}
    assert await _failed_events(store, mid) == 2


async def test_a_batch_retry_with_every_member_terminal_writes_nothing(store: MessageStore) -> None:
    mid, (a, b) = await _claimed(store, "OB1", "OB2")
    await store.mark_done(a, now=101.0)
    await store.mark_done(b, now=101.0)

    next_at = await store.mark_batch_failed([a, b], "envelope failed", _RETRY, now=102.0)

    assert {r["status"] for r in await store.outbox_for(mid)} == {OutboxStatus.DONE.value}
    assert await _failed_events(store, mid) == 0
    assert next_at == 107.0
