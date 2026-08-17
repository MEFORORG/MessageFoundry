# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0157 — the H1 leader-epoch fence on TERMINAL resolves (C1/C3/D1) and on ``claim_ready`` (C5).

**Gated** on ``MEFOR_TEST_POSTGRES`` like the rest of the Postgres suite, so a laptop run skips this
file entirely. The *structural* half of ADR 0157 — which writes carry which guard — is pinned by
``tests/test_adr0157_fence_scope.py``, which is deliberately NOT gated and runs on every leg.

Every test drives the same interleaving: claim a row while holding epoch N, bump the authoritative
``leader_lease`` to N+1 behind this handle's back (exactly what a standby's fresh acquire does), then
attempt the terminal write. The fence must reject it, roll the WHOLE disposition back, and RE-PEND the
row (D1) so the fence's own residue is a bounded duplicate rather than a strand.

The invariant that decides every assertion here: at-least-once **permits duplication and forbids
stranding or loss**. A change turning a possible strand into a possible duplicate is an improvement;
the reverse is unacceptable however elegant.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStatus, OutboxStatus, Stage

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

_LEASE_KEY = "public:mefor_cluster_leader"

#: Cleared between tests, children before parents. ``leader_lease`` is included here **on purpose**:
#: the main Postgres suite's ``_TABLES`` omits it, so a row seeded by one test survives into the next
#: and any test whose premise is "no lease row" silently stops testing that. Owning the cleanup here
#: makes each test's precondition explicit instead of inherited from file order.
_TABLES = ("message_events", "delivered_keys", "response", "queue", "messages", "leader_lease")


@pytest.fixture
async def store() -> AsyncIterator[object]:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    await _reset(s)
    yield s
    await s.close()


async def _reset(store) -> None:
    async with store._pool.acquire() as conn:
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS leader_lease ("
            " lease_key TEXT PRIMARY KEY, owner TEXT, lease_expires_at DOUBLE PRECISION NOT NULL,"
            " leader_epoch BIGINT NOT NULL DEFAULT 0)"
        )
        for table in _TABLES:
            await conn.execute(f"DELETE FROM {table}")
    store.set_leader_epoch(None)
    store.fenced_writes = 0


async def _seed_epoch(store, epoch: int) -> None:
    """Set the authoritative ``leader_lease.leader_epoch`` — in production the coordinator owns it."""
    async with store._pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO leader_lease (lease_key, owner, lease_expires_at, leader_epoch)"
            " VALUES ($1, 'live', 9e18, $2)"
            " ON CONFLICT (lease_key) DO UPDATE SET leader_epoch = EXCLUDED.leader_epoch",
            _LEASE_KEY,
            epoch,
        )


async def _drop_lease_row(store) -> None:
    async with store._pool.acquire() as conn:
        await conn.execute("DELETE FROM leader_lease WHERE lease_key = $1", _LEASE_KEY)


async def _ledger_count(store, outbox_id: str) -> int:
    async with store._pool.acquire() as conn:
        return int(
            await conn.fetchval("SELECT COUNT(*) FROM delivered_keys WHERE outbox_id=$1", outbox_id)
        )


async def _events(store, message_id: str) -> list[str]:
    async with store._pool.acquire() as conn:
        rows = await conn.fetch("SELECT event FROM message_events WHERE message_id=$1", message_id)
    return [r["event"] for r in rows]


async def _claim_one(store, dest: str = "OB1", *, epoch: int = 5):
    """Claim a row as the CURRENT leader holding ``epoch``."""
    await _seed_epoch(store, epoch)
    store.set_leader_epoch(epoch, lease_key=_LEASE_KEY)
    claimed = await store.claim_next_fifo(dest, now=200.0)
    assert claimed is not None
    return claimed


async def _superseded(store, epoch: int = 6) -> None:
    """A standby took over and bumped the epoch — this handle's held token is now stale."""
    await _seed_epoch(store, epoch)


# --- the fence fires: terminal resolves roll back WHOLE and re-pend --------------


async def test_fenced_mark_done_rolls_back_and_repends(store) -> None:
    """The whole disposition goes together, and the row comes back PENDING (C3 + D1).

    Mutation that must break it: drop ``+ guard`` from mark_done's UPDATE — the row flips DONE and the
    H2 ledger row appears, i.e. the superseded node records a delivery the successor will make again.
    """
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    claimed = await _claim_one(store)
    await _superseded(store)

    await store.mark_done(claimed.id)  # returns normally — a fenced write is NOT an exception

    outbox = (await store.outbox_for(mid))[0]
    assert outbox["status"] == OutboxStatus.PENDING.value  # D1: re-pended, NOT left INFLIGHT
    assert outbox["attempts"] == 0  # release_claimed undoes the claim's increment
    assert await _ledger_count(store, claimed.id) == 0
    assert "delivered" not in await _events(store, mid)
    msg = await store.get_message(mid)
    assert msg is not None and msg["status"] != MessageStatus.PROCESSED.value
    assert store.fenced_writes == 1


async def test_fenced_writes_land_when_the_epoch_is_current(store) -> None:
    """The negative twin — the point of a fence is that it does NOT fire on the true leader.

    Mutation: flip ``<=`` to ``<`` in the resolve guard. Equality IS the true-leader case, so every
    assertion here fails while the fenced tests still pass. That asymmetry is why these two exist as a
    pair: either one alone can be satisfied by a guard that is simply always-on or always-off.
    """
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    claimed = await _claim_one(store)
    # NO _superseded() — this node is still the current leader.

    await store.mark_done(claimed.id)

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DONE.value
    assert await _ledger_count(store, claimed.id) == 1
    assert "delivered" in await _events(store, mid)
    assert store.fenced_writes == 0


async def test_resolve_guard_is_fail_open_on_a_missing_lease_row(store) -> None:
    """The most important test in this file: the resolve guard's polarity is INVERTED vs the claim's.

    A missing ``leader_lease`` row must let a terminal resolve LAND. Reusing the claim's fail-closed
    idiom here would mass-strand every in-flight row the instant that row went missing. Mutation: paste
    ``_EPOCH_GUARD_CLAIM`` at the resolve site — ``NULL <= 5`` is false and this fails.
    """
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    claimed = await _claim_one(store)
    await _drop_lease_row(store)  # the row vanishes while we still hold epoch 5

    await store.mark_done(claimed.id)

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DONE.value
    assert await _ledger_count(store, claimed.id) == 1
    assert store.fenced_writes == 0


async def test_lease_key_none_with_an_armed_epoch_disagrees_by_design(store) -> None:
    """``set_leader_epoch(5, lease_key=None)`` is representable, and the two guards must disagree.

    ``COALESCE(NULL, 5) <= 5`` → the resolve lands; ``NULL <= 5`` → the claim declines. Pins the
    asymmetry against a future tidy-up that unifies the two templates into one.
    """
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    store.set_leader_epoch(None)
    claimed = await store.claim_next_fifo("OB1", now=200.0)
    assert claimed is not None

    store.set_leader_epoch(5, lease_key=None)  # armed epoch, nothing to validate it against
    await store.mark_done(claimed.id)
    assert store.fenced_writes == 0  # the resolve LANDED

    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB2", "p")], now=100.0)
    assert await store.claim_next_fifo("OB2", now=200.0) is None  # the claim DECLINED


async def test_fenced_dead_letter_now_writes_no_false_terminal(store) -> None:
    """The sharpest write of the set: a DEAD row is never re-claimed, so H2 cannot heal a false one.

    A superseded node dead-lettering a row the live leader is about to deliver loses it permanently —
    strand-direction, which the at-least-once invariant forbids outright.
    """
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    claimed = await _claim_one(store)
    await _superseded(store)

    await store.dead_letter_now(claimed.id, "boom")

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.PENDING.value
    assert "dead" not in await _events(store, mid)
    msg = await store.get_message(mid)
    assert msg is not None and msg["status"] != MessageStatus.ERROR.value
    assert store.fenced_writes == 1


async def test_fenced_complete_with_response_persists_no_artifact(store) -> None:
    """The guard rides the FIRST statement, so the reply artifact never outlives its queue row.

    Mutation: move ``_exec_terminal`` after the response INSERT — the artifact then persists with no
    resolved queue row, precisely the half-applied state C3 rejects.
    """
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    claimed = await _claim_one(store)
    await _superseded(store)

    await store.complete_with_response(claimed.id, body="ACK", outcome="ok", reingress_to="IB_LOOP")

    async with store._pool.acquire() as conn:
        responses = int(
            await conn.fetchval("SELECT COUNT(*) FROM response WHERE message_id=$1", mid)
        )
        work_rows = int(
            await conn.fetchval("SELECT COUNT(*) FROM queue WHERE stage=$1", Stage.RESPONSE.value)
        )
    assert responses == 0  # no artifact
    assert work_rows == 0  # no re-ingress work-row
    assert await _ledger_count(store, claimed.id) == 0
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.PENDING.value
    assert store.fenced_writes == 1


async def test_mark_failed_dead_branch_fenced_retry_branch_lands(store) -> None:
    """Both branches in ONE test, because the split between them IS the design (C1).

    The DEAD branch is terminal and fenced. The retry branch RE-PENDS, and fencing that would leave the
    row INFLIGHT — converting a permitted duplicate into a forbidden strand. Mutation: make the guard
    unconditional and the retry half fails.
    """
    mid_a = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    claimed_a = await _claim_one(store)
    await _superseded(store)

    # Row A: retries exhausted → the DEAD branch → fenced.
    assert await store.mark_failed(claimed_a.id, "boom", RetryPolicy(max_attempts=1)) is None
    assert (await store.outbox_for(mid_a))[0]["status"] == OutboxStatus.PENDING.value
    assert store.fenced_writes == 1

    # Row B: retry-forever → the PENDING branch. Claim it as the CURRENT leader (epoch 6), then leave
    # the epoch stale-free: the retry branch must land regardless, and must not be counted.
    mid_b = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB2", "p")], now=100.0
    )
    store.set_leader_epoch(6, lease_key=_LEASE_KEY)
    claimed_b = await store.claim_next_fifo("OB2", now=200.0)
    assert claimed_b is not None
    await _superseded(store, 7)  # superseded again, mid-flight

    next_at = await store.mark_failed(claimed_b.id, "transient", RetryPolicy(max_attempts=None))
    assert isinstance(next_at, float)  # rescheduled, not dead-lettered
    assert (await store.outbox_for(mid_b))[0]["status"] == OutboxStatus.PENDING.value
    assert store.fenced_writes == 1  # UNCHANGED — the retry branch is never inspected


async def test_repend_writes_land_under_a_bumped_epoch(store) -> None:
    """C1's other direction, as a test, so nobody "completes" the fence by guarding these.

    ``release_claimed`` / ``reschedule_claimed`` return a row to PENDING. Fencing them would leave
    INFLIGHT the one path that today hands over instantly — and would break D1's own recovery, which
    is itself a ``release_claimed``.
    """
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    claimed = await _claim_one(store)
    await _superseded(store)

    await store.release_claimed([claimed.id])
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.PENDING.value

    store.set_leader_epoch(6, lease_key=_LEASE_KEY)
    claimed2 = await store.claim_next_fifo("OB1", now=200.0)
    assert claimed2 is not None
    await _superseded(store, 7)
    await store.reschedule_claimed([claimed2.id], 999.0)
    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value
    assert row["next_attempt_at"] == 999.0
    assert store.fenced_writes == 0  # neither is a terminal resolve


async def test_fenced_batch_is_all_or_nothing_and_repends_every_member(store) -> None:
    """A fence on ANY member rolls back ALL N, and D1 re-pends ALL N — including those never walked.

    Members past the raise were never touched by the UPDATE, but they ARE still INFLIGHT from the
    claim, so a sentinel carrying only the walked prefix would strand the tail. Mutation: carry the
    walked prefix instead of ``tuple(outbox_ids)`` and members 2..N stay INFLIGHT.
    """
    mid = await store.enqueue_message(
        channel_id="IB",
        raw=RAW,
        deliveries=[("OB1", "p1"), ("OB1", "p2"), ("OB1", "p3")],
        now=100.0,
    )
    await _seed_epoch(store, 5)
    store.set_leader_epoch(5, lease_key=_LEASE_KEY)
    batch = await store.claim_next_fifo_batch("OB1", now=200.0, stage=Stage.OUTBOUND.value, limit=3)
    assert len(batch) == 3
    await _superseded(store)

    await store.mark_batch_done([b.id for b in batch])

    outbox = await store.outbox_for(mid)
    assert {o["status"] for o in outbox} == {OutboxStatus.PENDING.value}
    for member in batch:
        assert await _ledger_count(store, member.id) == 0
    assert store.fenced_writes == 1  # once per CALL, not once per member


# --- C5: the UNORDERED claim path -----------------------------------------------


async def test_claim_ready_is_fenced(store) -> None:
    """C5. Fails before ADR 0157 — ``claim_ready`` carried no epoch guard at all."""
    await _seed_epoch(store, 5)
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )

    store.set_leader_epoch(3, lease_key=_LEASE_KEY)  # superseded ex-leader
    assert await store.claim_ready(now=200.0) == []
    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value
    assert row["attempts"] == 0  # a declined claim consumes no retry
    assert row["owner"] is None

    store.set_leader_epoch(5, lease_key=_LEASE_KEY)  # the current leader
    assert len(await store.claim_ready(now=200.0)) == 1


async def test_claim_ready_unfenced_with_no_lease_row_at_all(store) -> None:
    """The single-node arm: epoch None means NO fence, so claim_ready behaves exactly as pre-0157.

    Its precondition is set explicitly rather than inherited from an earlier test's leftover row.
    """
    await _drop_lease_row(store)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    store.set_leader_epoch(None)
    assert len(await store.claim_ready(now=200.0)) == 1


# --- parity + recovery ----------------------------------------------------------


async def test_unfenced_terminal_sql_is_character_identical(store) -> None:
    """The parity anchor: with no epoch armed, the emitted SQL and arg list are exactly pre-0157.

    This is what lets ADR 0157 claim single-node and SQLite behaviour is untouched — otherwise pure
    assertion. Captures the real statement rather than reasoning about the code.
    """
    captured: list[tuple[str, tuple[object, ...]]] = []
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    store.set_leader_epoch(None)
    claimed = await store.claim_next_fifo("OB1", now=200.0)
    assert claimed is not None

    real_acquire = store._timed_acquire

    class _Spy:
        def __init__(self, conn) -> None:
            self._conn = conn

        def __getattr__(self, name):
            return getattr(self._conn, name)

        async def execute(self, sql, *args):
            captured.append((sql, args))
            return await self._conn.execute(sql, *args)

    class _Ctx:
        def __init__(self, inner) -> None:
            self._inner = inner

        async def __aenter__(self):
            return _Spy(await self._inner.__aenter__())

        async def __aexit__(self, *exc):
            return await self._inner.__aexit__(*exc)

    store._timed_acquire = lambda *a, **k: _Ctx(real_acquire(*a, **k))
    try:
        await store.mark_done(claimed.id)
    finally:
        store._timed_acquire = real_acquire

    updates = [(sql, args) for sql, args in captured if sql.startswith("UPDATE queue SET status")]
    assert updates, "mark_done issued no queue status UPDATE"
    sql, args = updates[0]
    assert sql == (
        "UPDATE queue SET status=$1, last_error=NULL, updated_at=$2,"
        " owner=NULL, lease_expires_at=NULL WHERE id=$3"
    )
    assert len(args) == 3  # no guard args appended
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DONE.value


async def test_fenced_write_is_recovered_without_a_sweep(store) -> None:
    """D1's payoff, and the reason the fence's own residue is not a SQL Server strand.

    A second handle claims the fenced row IMMEDIATELY — no ``reclaim_expired_leases``, no
    ``recover_inflight_on_promotion``, no waiting out a 60s row lease. Mutation: replace
    ``_after_fenced_write``'s ``release_claimed`` with ``pass`` and the row stays INFLIGHT, so the
    successor's claim returns None and this fails.
    """
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    claimed = await _claim_one(store)
    await _superseded(store)
    await store.mark_done(claimed.id)
    assert store.fenced_writes == 1

    successor = await PostgresStore.open(load_settings(environ=os.environ).store)
    try:
        successor.set_leader_epoch(6, lease_key=_LEASE_KEY)  # the new current epoch
        taken = await successor.claim_next_fifo("OB1", now=300.0)
        assert taken is not None, "the fenced row was not immediately re-claimable"
        await successor.mark_done(taken.id)
        assert await _ledger_count(store, taken.id) == 1  # delivered EXACTLY once, by the successor
        msg = await successor.get_message(mid)
        assert msg is not None and msg["status"] == MessageStatus.PROCESSED.value
    finally:
        await successor.close()
