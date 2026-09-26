# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0157 Inc 3 — the H1 leader-epoch fence on SQL Server's TERMINAL resolves (C1/C3/D1) and on
``claim_ready`` (C5), against a real server.

**Gated** on ``MEFOR_TEST_SQLSERVER``, so it runs only on the hosted ``sqlserver-store`` legs (the
catch-all step in ``.github/workflows/ci.yml`` names it). Which writes carry which guard is pinned
without a database by ``tests/test_adr0157_sqlserver_fence_offline.py``, which runs on every leg.

This is the twin of ``tests/test_adr0157_postgres_fence.py``, and every test drives the same
interleaving: claim a row while holding epoch N, bump ``leader_lease`` to N+1 behind this handle's
back (what a standby's fresh acquire does), then attempt the terminal write. The fence must reject it,
roll the WHOLE disposition back, and RE-PEND the row (D1).

The two recovery-closure tests at the end are GAP 1's last criterion: after a fenced write the row is
resolved within bounded time. On SQL Server that needs no periodic sweep and no Inc 2 machinery. D1
re-pends at once; if D1 itself fails, the promotion ``reset_stale_inflight`` the successor already
runs collects the row.

No test here cancels a statement mid-flight: on SQL Server that path can natively crash pyodbc, and it
is a separate ledger item.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Any

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStatus, OutboxStatus, Stage
from tests.test_sqlserver_store import _seed_lease_epoch

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

# SqlServerCoordinator's lease key: constant, because this store ignores [store].db_schema.
_LEASE_KEY = "mefor_cluster_leader"

#: Cleared between tests, children before parents. ``leader_lease`` is cleared on purpose, so a test
#: whose premise is "no lease row" is not quietly testing a row an earlier file left behind.
_TABLES = ("message_events", "delivered_keys", "response", "queue", "messages", "leader_lease")


async def _open() -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    return await SqlServerStore.open(load_settings(environ=os.environ).store)


@pytest.fixture
async def store() -> AsyncIterator[Any]:
    s = await _open()
    try:
        await _seed_epoch(s, 0)  # creates leader_lease if absent; the row is cleared just below
        for table in _TABLES:
            await s._execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
        s.set_leader_epoch(None)
        s.fenced_writes = 0
        yield s
    finally:
        await s.close()


async def _seed_epoch(store: Any, epoch: int) -> None:
    """Set the authoritative ``leader_lease.leader_epoch``; in production the coordinator owns it."""
    await _seed_lease_epoch(store, _LEASE_KEY, epoch)


async def _drop_lease_row(store: Any) -> None:
    await store._execute("DELETE FROM leader_lease WHERE lease_key = ?", (_LEASE_KEY,))


async def _ledger_count(store: Any, outbox_id: str) -> int:
    rows = await store._fetchall(
        "SELECT COUNT(*) AS c FROM delivered_keys WHERE outbox_id=?", (outbox_id,)
    )
    return int(rows[0]["c"])


async def _events(store: Any, message_id: str) -> list[str]:
    rows = await store._fetchall(
        "SELECT event FROM message_events WHERE message_id=?", (message_id,)
    )
    return [r["event"] for r in rows]


async def _claim_one(store: Any, dest: str = "OB1", *, epoch: int = 5) -> Any:
    """Claim a row as the CURRENT leader holding ``epoch``."""
    await _seed_epoch(store, epoch)
    store.set_leader_epoch(epoch, lease_key=_LEASE_KEY)
    claimed = await store.claim_next_fifo(dest, now=200.0)
    assert claimed is not None
    return claimed


async def _superseded(store: Any, epoch: int = 6) -> None:
    """A standby took over and bumped the epoch; this handle's held token is now stale."""
    await _seed_epoch(store, epoch)


async def _enqueue(store: Any, *deliveries: tuple[str, str]) -> str:
    mid: str = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=list(deliveries or [("OB1", "p")]), now=100.0
    )
    return mid


# --- the fence fires: terminal resolves roll back WHOLE and re-pend --------------------------


async def test_fenced_mark_done_rolls_back_and_repends(store: Any) -> None:
    """C3 + D1. Mutation that must break it: drop ``+ guard`` from mark_done's UPDATE, and the row
    flips DONE with an H2 ledger row, recording a delivery the successor will make again."""
    mid = await _enqueue(store)
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


async def test_fenced_writes_land_when_the_epoch_is_current(store: Any) -> None:
    """The negative twin. Mutation: flip ``<=`` to ``<`` in the resolve guard; equality IS the true
    leader, so this fails while the fenced tests still pass."""
    mid = await _enqueue(store)
    claimed = await _claim_one(store)

    await store.mark_done(claimed.id)

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DONE.value
    assert await _ledger_count(store, claimed.id) == 1
    assert "delivered" in await _events(store, mid)
    assert store.fenced_writes == 0


async def test_resolve_guard_is_fail_open_on_a_missing_lease_row(store: Any) -> None:
    """The resolve polarity is INVERTED against the claim's. A missing ``leader_lease`` row must let a
    terminal resolve LAND. Mutation: splice the claim guard at a resolve site, and ``NULL <= 5`` is
    UNKNOWN, so this fails."""
    mid = await _enqueue(store)
    claimed = await _claim_one(store)
    await _drop_lease_row(store)  # the row vanishes while we still hold epoch 5

    await store.mark_done(claimed.id)

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DONE.value
    assert await _ledger_count(store, claimed.id) == 1
    assert store.fenced_writes == 0


async def test_lease_key_none_with_an_armed_epoch_disagrees_by_design(store: Any) -> None:
    """``ISNULL(NULL, 5) <= 5`` lets the resolve land; ``NULL <= 5`` declines the claim.

    A lease row at epoch 6 is present on purpose. With the real key the resolve would be FENCED
    (6 > 5), so a landing write proves the None key was bound as None and matched no row, rather
    than proving only that the table was empty."""
    await _enqueue(store)
    claimed = await store.claim_next_fifo("OB1", now=200.0)
    assert claimed is not None
    await _seed_epoch(store, 6)

    store.set_leader_epoch(5, lease_key=None)
    await store.mark_done(claimed.id)
    assert store.fenced_writes == 0  # the resolve LANDED

    await _enqueue(store, ("OB2", "p"))
    assert await store.claim_next_fifo("OB2", now=200.0) is None  # the claim DECLINED


async def test_fenced_dead_letter_now_writes_no_false_terminal(store: Any) -> None:
    """A DEAD row is never re-claimed, so H2 cannot heal a false one: strand-direction."""
    mid = await _enqueue(store)
    claimed = await _claim_one(store)
    await _superseded(store)

    await store.dead_letter_now(claimed.id, "boom")

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.PENDING.value
    assert "dead" not in await _events(store, mid)
    msg = await store.get_message(mid)
    assert msg is not None and msg["status"] != MessageStatus.ERROR.value
    assert store.fenced_writes == 1


async def test_fenced_complete_with_response_persists_no_artifact(store: Any) -> None:
    """The guard rides the FIRST write, so the reply artifact never outlives its queue row."""
    mid = await _enqueue(store)
    claimed = await _claim_one(store)
    await _superseded(store)

    await store.complete_with_response(claimed.id, body="ACK", outcome="ok", reingress_to="LOOP")

    responses = await store._fetchall(
        "SELECT COUNT(*) AS c FROM response WHERE message_id=?", (mid,)
    )
    work_rows = await store._fetchall(
        "SELECT COUNT(*) AS c FROM queue WHERE stage=?", (Stage.RESPONSE.value,)
    )
    assert int(responses[0]["c"]) == 0  # no artifact
    assert int(work_rows[0]["c"]) == 0  # no re-ingress work-row
    assert await _ledger_count(store, claimed.id) == 0
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.PENDING.value
    assert store.fenced_writes == 1


async def test_fenced_ingress_handoff_dead_branch_repends_the_work_row(store: Any) -> None:
    """The depth-cap DEAD branch is terminal on a claimed RESPONSE work-row, so it is fenced; a
    rejection returns False and re-pends the token instead of consuming it."""
    mid = await _enqueue(store)
    claimed = await _claim_one(store)
    # now= is explicit: the work row is due at the write's `now`, and the claim below runs on the
    # same fixed test clock. Left to default, `now` is wall-clock time and the row is never due.
    await store.complete_with_response(
        claimed.id, body="ACK", outcome="ok", reingress_to="LOOP", now=205.0
    )
    token = await store.claim_next_fifo("LOOP", now=210.0, stage=Stage.RESPONSE.value)
    assert token is not None
    await _superseded(store)

    consumed = await store.ingress_handoff(
        response_row_id=token.id,
        loopback_channel_id="LOOP",
        correlation_depth_cap=0,  # child depth 1 > 0: the DEAD branch
        control_id=None,
        message_type=None,
        summary=None,
    )

    assert consumed is False
    rows = await store._fetchall("SELECT status FROM queue WHERE id=?", (token.id,))
    assert rows[0]["status"] == OutboxStatus.PENDING.value
    assert "dead" not in await _events(store, mid)
    assert store.fenced_writes == 1


async def test_mark_failed_dead_branch_fenced_retry_branch_lands(store: Any) -> None:
    """Both branches in one test, because the split between them IS the design (C1)."""
    mid_a = await _enqueue(store)
    claimed_a = await _claim_one(store)
    await _superseded(store)

    assert await store.mark_failed(claimed_a.id, "boom", RetryPolicy(max_attempts=1)) is None
    assert (await store.outbox_for(mid_a))[0]["status"] == OutboxStatus.PENDING.value
    assert store.fenced_writes == 1

    mid_b = await _enqueue(store, ("OB2", "p"))
    store.set_leader_epoch(6, lease_key=_LEASE_KEY)
    claimed_b = await store.claim_next_fifo("OB2", now=200.0)
    assert claimed_b is not None
    await _superseded(store, 7)

    next_at = await store.mark_failed(claimed_b.id, "transient", RetryPolicy(max_attempts=None))
    assert isinstance(next_at, float)  # rescheduled, not dead-lettered
    assert (await store.outbox_for(mid_b))[0]["status"] == OutboxStatus.PENDING.value
    assert store.fenced_writes == 1  # UNCHANGED — the retry branch is never inspected


async def test_repend_writes_land_under_a_bumped_epoch(store: Any) -> None:
    """C1's other direction, so nobody "completes" the fence by guarding these."""
    mid = await _enqueue(store)
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
    assert store.fenced_writes == 0


async def test_fenced_batch_is_all_or_nothing_and_repends_every_member(store: Any) -> None:
    """A fence on ANY member rolls back ALL N, and D1 re-pends ALL N."""
    mid = await _enqueue(store, ("OB1", "p1"), ("OB1", "p2"), ("OB1", "p3"))
    await _seed_epoch(store, 5)
    store.set_leader_epoch(5, lease_key=_LEASE_KEY)
    batch = await store.claim_ready(limit=3, now=200.0)
    assert len(batch) == 3
    await _superseded(store)

    await store.mark_batch_done([b.id for b in batch])

    assert {o["status"] for o in await store.outbox_for(mid)} == {OutboxStatus.PENDING.value}
    for member in batch:
        assert await _ledger_count(store, member.id) == 0
    assert store.fenced_writes == 1  # once per CALL, not once per member


def _force_nocount(store: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run ``SET NOCOUNT ON`` on every cursor this store opens.

    A STRESS state, not the production one: production sets NOCOUNT only inside parameterized
    calls, which SQL Server restores on return. Under a session-wide NOCOUNT ``cursor.rowcount`` did
    not report 0 for a zero-match UPDATE, so these tests pin that the fence does not depend on it."""
    real_cursor = store._cursor

    @asynccontextmanager
    async def nocount_cursor(conn: Any) -> AsyncIterator[Any]:
        async with real_cursor(conn) as cur:
            await cur.execute("SET NOCOUNT ON;")
            try:
                yield cur
            finally:
                # Put the session back. Without this, NOCOUNT outlived this store: a LATER test's
                # freshly opened store read reset_stale_inflight() as -4 (-1 per stage) on both
                # SQL Server legs, consistent with the ODBC driver manager handing the same
                # physical connection, session options intact, to the next pool.
                with suppress(Exception):
                    await cur.execute("SET NOCOUNT OFF;")

    monkeypatch.setattr(store, "_cursor", nocount_cursor)


async def test_the_fence_fires_under_nocount_on(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The production-shaped fence test. Mutation: read ``cur.rowcount == 0`` in ``_exec_terminal``
    instead of the OUTPUT rowset, and the fenced half fails (the write lands DONE)."""
    _force_nocount(store, monkeypatch)
    mid = await _enqueue(store)
    claimed = await _claim_one(store)
    await _superseded(store)

    await store.mark_done(claimed.id)

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.PENDING.value
    assert await _ledger_count(store, claimed.id) == 0
    assert store.fenced_writes == 1


async def test_a_current_leaders_write_lands_under_nocount_on(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The negative twin under NOCOUNT: the OUTPUT rowset must report the matched row, or the true
    leader's every write would be re-pended."""
    _force_nocount(store, monkeypatch)
    mid = await _enqueue(store)
    claimed = await _claim_one(store)

    await store.mark_done(claimed.id)

    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DONE.value
    assert await _ledger_count(store, claimed.id) == 1
    assert store.fenced_writes == 0


# --- C5: the UNORDERED claim path ------------------------------------------------------------


async def test_claim_ready_is_fenced(store: Any) -> None:
    """C5. Fails before Inc 3: ``claim_ready`` carried no epoch guard on SQL Server at all."""
    await _seed_epoch(store, 5)
    mid = await _enqueue(store)

    store.set_leader_epoch(3, lease_key=_LEASE_KEY)  # superseded ex-leader
    assert await store.claim_ready(now=200.0) == []
    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value
    assert row["attempts"] == 0  # a declined claim consumes no retry

    store.set_leader_epoch(5, lease_key=_LEASE_KEY)  # the current leader
    assert len(await store.claim_ready(now=200.0)) == 1


async def test_claim_ready_unfenced_with_no_lease_row_at_all(store: Any) -> None:
    """The single-node arm: epoch None means NO fence, so claim_ready behaves as before Inc 3."""
    await _drop_lease_row(store)
    await _enqueue(store)
    store.set_leader_epoch(None)
    assert len(await store.claim_ready(now=200.0)) == 1


# --- GAP 1: recovery closure -----------------------------------------------------------------


async def test_fenced_write_is_recovered_without_a_sweep(store: Any) -> None:
    """D1's payoff. A second handle claims the fenced row AT ONCE: no periodic sweep (SQL Server has
    none), no promotion, no Inc 2 reload backstop. Mutation: replace ``_after_fenced_write``'s
    ``release_claimed`` with ``pass`` and the row stays INFLIGHT, so this fails."""
    mid = await _enqueue(store)
    claimed = await _claim_one(store)
    await _superseded(store)
    await store.mark_done(claimed.id)
    assert store.fenced_writes == 1

    successor = await _open()
    try:
        successor.set_leader_epoch(6, lease_key=_LEASE_KEY)
        taken = await successor.claim_next_fifo("OB1", now=300.0)
        assert taken is not None, "the fenced row was not immediately re-claimable"
        await successor.mark_done(taken.id)
        assert await _ledger_count(store, taken.id) == 1  # delivered EXACTLY once, by the successor
        msg = await successor.get_message(mid)
        assert msg is not None and msg["status"] == MessageStatus.PROCESSED.value
    finally:
        await successor.close()


async def test_a_failed_repend_is_collected_by_the_successors_promotion_reset(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backstop when D1 itself fails. The fence fires only after some node's fresh acquire bumped
    the epoch, and every claim path is now fenced, so a row this node still holds was claimed BEFORE
    that bump. The successor's promotion runs ``reset_stale_inflight()`` (engine ``_start_graph``,
    clustered SQL Server branch), which re-pends it.

    Honest scope: this drives the reset directly rather than a real promotion. It shows the reset
    collects the fence's residue. ``tests/test_cluster_graph_gating.py`` pins that a clustered SQL
    Server promotion runs the reset."""
    mid = await _enqueue(store)
    claimed = await _claim_one(store)
    await _superseded(store)

    async def refuse(ids: Any, now: float | None = None) -> None:
        raise RuntimeError("re-pend refused")

    monkeypatch.setattr(store, "release_claimed", refuse)
    await store.mark_done(claimed.id)
    assert store.fenced_writes == 1
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.INFLIGHT.value

    successor = await _open()
    try:
        successor.set_leader_epoch(6, lease_key=_LEASE_KEY)
        # What promotion runs on SQL Server. now= is explicit because the reset stamps
        # next_attempt_at=now, and the claim below runs on the fixed test clock. The proof is the
        # ROW STATE, not the returned count: that count is built from cursor.rowcount, which reads
        # -1 per stage whenever the session has NOCOUNT on (see the report on PR 1576).
        await successor.reset_stale_inflight(now=250.0)
        assert (await successor.outbox_for(mid))[0]["status"] == OutboxStatus.PENDING.value
        taken = await successor.claim_next_fifo("OB1", now=300.0)
        assert taken is not None and taken.id == claimed.id
        await successor.mark_done(taken.id)
        assert await _ledger_count(store, taken.id) == 1
    finally:
        await successor.close()
