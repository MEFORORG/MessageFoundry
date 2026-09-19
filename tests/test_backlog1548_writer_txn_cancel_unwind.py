# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SQLite writer transaction unwinds on CANCELLATION, not just on ordinary exceptions.

``asyncio.CancelledError`` derives from ``BaseException``, so the store's ``except Exception``
rollbacks never fired on a cancellation: the writer left its transaction open, and because SQLite has
exactly ONE write connection behind one ``asyncio.Lock``, the next writer to take that lock would
inherit it. The next writer that issues no ``BEGIN`` of its own -- most of the store's short writers
-- would then have its ``COMMIT`` make the abandoned statements durable too. On a stage handoff that
is how a cancelled route would lose work on first deployment: the ingress row's guarded ``DELETE``
becomes durable while the routed rows it should have produced never existed.

These drive :func:`messagefoundry.store.store._writer_txn` through the store's public API at three
distinct cancel points, on both of the store's stage handoffs -- ``route_handoff`` (ingress ->
routed) and ``ingress_handoff`` (the re-ingress edge, ADR 0013 Increment 2). Each arm proves the
same things:

1. the failure propagates;
2. NO transaction is left open;
3. an UNRELATED writer can still use the connection afterwards -- that writer deliberately issues no
   ``BEGIN``, so it is the probe that would carry the abandoned work if one were still open;
4. it did NOT carry that work: the ingress row is still there, still ``inflight``, and nothing the
   failed handoff would have produced leaked;
5. the handoff RE-RUNS to success, which is the at-least-once contract the unwind exists to keep.

The ordinary-exception CONTROL arm is not padding. A cancel test alone cannot tell "cancellation now
unwinds correctly" from "cancellation is now silently swallowed" -- both leave a clean database. The
control arm injects a plain exception at the SAME await and runs the SAME assertions, so the two
paths are shown to behave identically. The GROUPED cases run again with GROUP COMMIT enabled, where
the writer transaction lives in the committer task and the cancellation must additionally resolve
every enrolled member's future or its caller parks on it forever. ``ingress_handoff`` has no such
arm: it takes ``_writer_txn`` directly rather than going through ``_run_grouped``, so there is no
committer to cancel.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store.store import (
    MessageStatus,
    MessageStore,
    OutboxStatus,
    Stage,
)

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"
CH = "IB_TEST_ADT"
# The re-ingress lanes: an outbound that captures a reply, and the loopback inbound it re-enters on.
DEST = "OB_TEST_REPLY"
LOOPBACK = "IB_TEST_LOOP"
REPLY = "MSH|^~\\&|F|RF|S|F|20260101||RSP^K11|RSP1|P|2.5.1\rMSA|AA|MSG1\r"
# A non-zero window is what flips the store from inline-commit to the committer coroutine.
GC_WINDOW_MS = 5.0
# Bound on every handshake with the trapped writer. Generous (these are sub-millisecond in practice)
# but finite, so a wedged case fails as a timeout instead of hanging the suite.
WAIT = 5.0

# The three cancel points, named by the await the failure lands on.
BEGIN, BODY, COMMIT = "begin", "body", "commit"
CANCEL_POINTS = [BEGIN, BODY, COMMIT]
ARMS = ["cancel", "control"]


class _Boom(Exception):
    """The control arm's ordinary exception. Deliberately NOT a RuntimeError, so it can never be
    confused with the coordinated-rollback error the group committer rejects members with."""


class _Trap:
    """Stall (or fail) the store's single writer at ONE chosen await inside its transaction.

    ``arm(point)`` selects the await:

    * ``begin``  -- just after ``BEGIN`` landed: the transaction is open, nothing written;
    * ``body``   -- just after the handoff's guarded ``DELETE``: one uncommitted mutation open;
    * ``commit`` -- just before ``COMMIT``: the whole handoff written and not yet durable.

    In the CANCEL arm the writer parks there until the test cancels its task. In the CONTROL arm it
    raises :class:`_Boom` at that same await instead. Nothing else differs between the arms.

    ``stall_rollback`` additionally holds the unwind's ``ROLLBACK`` open for a beat, which is the
    window the cancel-twice cases need to land a SECOND cancellation inside the shielded rollback."""

    def __init__(self, db: Any) -> None:
        self._real_execute = db.execute
        self._real_commit = db.commit
        self._real_rollback = db.rollback
        self.point: str | None = None
        self.raise_instead = False
        self.stall_rollback = 0.0
        self.reached = asyncio.Event()
        self.release = asyncio.Event()
        self.rollback_started = asyncio.Event()
        self.rollback_finished = asyncio.Event()
        db.execute = self._execute
        db.commit = self._commit
        db.rollback = self._rollback

    def arm(self, point: str, *, raise_instead: bool = False) -> None:
        self.point = point
        self.raise_instead = raise_instead
        self.reached.clear()

    async def _execute(self, sql: Any, *args: Any, **kwargs: Any) -> Any:
        cur = await self._real_execute(sql, *args, **kwargs)
        # Trip AFTER the statement really ran: a cancellation delivered at this await leaves the
        # worker thread's work applied, which is the state the unwind has to clean up.
        text = str(sql)
        if (self.point == BEGIN and text.startswith("BEGIN")) or (
            self.point == BODY and text.startswith("DELETE FROM queue")
        ):
            await self._trip()
        return cur

    async def _commit(self) -> Any:
        if self.point == COMMIT:
            await self._trip()  # before the real COMMIT: everything written, nothing durable
        return await self._real_commit()

    async def _rollback(self) -> Any:
        self.rollback_started.set()
        if self.stall_rollback:
            await asyncio.sleep(self.stall_rollback)
        try:
            return await self._real_rollback()
        finally:
            self.rollback_finished.set()

    async def _trip(self) -> None:
        self.point = None  # one shot: the recovery re-run must not trip it again
        self.reached.set()
        if self.raise_instead:
            raise _Boom("injected at the cancel point")
        await self.release.wait()


async def _prepare(store: MessageStore) -> tuple[str, str]:
    """One received message, claimed at the ingress stage and ready to hand off."""
    mid = await store.enqueue_ingress(channel_id=CH, raw=RAW)
    item = await store.claim_next_fifo(CH, stage=Stage.INGRESS.value)
    assert item is not None
    return mid, item.id


async def _route(store: MessageStore, mid: str, ingress_id: str) -> bool:
    return bool(
        await store.route_handoff(
            ingress_id=ingress_id,
            message_id=mid,
            channel_id=CH,
            handlers=[("h", RAW)],
            disposition=MessageStatus.ROUTED,
        )
    )


async def _assert_connection_clean(store: MessageStore, *, probe: str) -> None:
    """The invariant itself, and the probe that detects its absence. Shared by every assert helper
    here -- it is the one mechanism the whole file exists to exercise, so it gets ONE definition.

    Order matters. `in_transaction` is asserted FIRST because the probe below closes whatever is
    open, which would mask the failure at the `begin` cancel point.

    The probe is load-bearing for a specific reason: `record_connection_event` takes the write lock
    and issues its INSERT with NO `BEGIN` of its own. If the failed writer's transaction were still
    open, this INSERT would join it and its commit would make the abandoned work durable -- which is
    exactly the inheritance this unwind exists to prevent. Should that method ever grow a
    transaction of its own, this stops proving anything and needs replacing with another short
    writer."""
    assert not store._db.in_transaction, "the failed writer left its transaction open"
    await store.record_connection_event(
        connection=probe, transport="mllp", direction="inbound", kind="probe"
    )
    assert len(await store.list_connection_events(connection=probe)) == 1


async def _assert_unwound_and_recovered(
    store: MessageStore, mid: str, ingress_id: str, *, probe: str
) -> None:
    """The post-conditions EVERY failing writer must meet -- cancel arm and control arm alike.

    Shared verbatim by both arms on purpose: a cancellation that was swallowed rather than unwound
    would still satisfy a cancel-only test, and only a side-by-side comparison against the ordinary
    failure shows the two paths now agree."""
    # 1-2. No transaction left open, and the next writer can use the connection.
    await _assert_connection_clean(store, probe=probe)

    # 3. ...and it did NOT carry the abandoned work with it.
    cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (ingress_id,))
    row = await cur.fetchone()
    assert row is not None, "the failed handoff's guarded DELETE became durable -- work lost"
    assert row["status"] == OutboxStatus.INFLIGHT.value

    # 4. Nothing the failed handoff would have produced leaked.
    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM queue WHERE stage=? AND message_id=?",
        (Stage.ROUTED.value, mid),
    )
    assert (await cur.fetchone())["n"] == 0
    assert (await store.get_message(mid))["status"] == MessageStatus.RECEIVED.value

    # 5. Recovery: the in-flight row re-pends and the SAME handoff re-runs to success. This is the
    #    at-least-once contract -- a rolled-back handoff must be re-runnable, not merely harmless.
    assert await store.reset_stale_inflight(stage=Stage.INGRESS.value) >= 1
    item = await store.claim_next_fifo(CH, stage=Stage.INGRESS.value)
    assert item is not None and item.message_id == mid
    assert await _route(store, mid, item.id)
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value


# --- inline writer transaction (group-commit DISABLED, the default) -----------------------------


@pytest.mark.parametrize("arm", ARMS)
@pytest.mark.parametrize("point", CANCEL_POINTS)
async def test_inline_writer_unwinds(tmp_path: Path, point: str, arm: str) -> None:
    """A cancellation at any of the three cancel points unwinds the inline writer transaction, and an
    ordinary exception at the same await does exactly the same thing."""
    store = await MessageStore.open(tmp_path / f"inline-{point}-{arm}.db")
    try:
        trap = _Trap(store._db)
        mid, ingress_id = await _prepare(store)
        trap.arm(point, raise_instead=arm == "control")

        if arm == "cancel":
            task = asyncio.create_task(_route(store, mid, ingress_id))
            await asyncio.wait_for(trap.reached.wait(), WAIT)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(_Boom):
                await _route(store, mid, ingress_id)

        await _assert_unwound_and_recovered(store, mid, ingress_id, probe=f"{point}-{arm}")
    finally:
        await store.close()


@pytest.mark.parametrize("point", CANCEL_POINTS)
async def test_inline_writer_survives_a_second_cancellation(tmp_path: Path, point: str) -> None:
    """A SECOND cancellation landing inside the shielded rollback corrupts nothing: the rollback still
    runs to completion, the original cancellation still propagates, and the connection is clean.

    Without the shield the second cancel would kill the rollback and leave the very half-open
    transaction the first cancel's unwind was closing."""
    store = await MessageStore.open(tmp_path / f"twice-{point}.db")
    try:
        trap = _Trap(store._db)
        trap.stall_rollback = 0.05  # hold the ROLLBACK open long enough to cancel into it
        mid, ingress_id = await _prepare(store)
        trap.arm(point)

        task = asyncio.create_task(_route(store, mid, ingress_id))
        await asyncio.wait_for(trap.reached.wait(), WAIT)
        task.cancel()
        await asyncio.wait_for(trap.rollback_started.wait(), WAIT)
        task.cancel()  # lands while the unwind is parked on the shielded rollback
        with pytest.raises(asyncio.CancelledError):
            await task

        assert trap.rollback_finished.is_set(), "the second cancellation killed the rollback"
        await _assert_unwound_and_recovered(store, mid, ingress_id, probe=f"twice-{point}")
    finally:
        await store.close()


@pytest.mark.parametrize("arm", ARMS)
async def test_standalone_dead_letter_writer_unwinds(tmp_path: Path, arm: str) -> None:
    """``dead_letter_now(_standalone=True)`` is the ONE grouped writer that also owns a second, inline
    transaction -- the undecryptable-payload path a standalone claim takes, which must never join a
    batch. It is covered here because routing only ``_run_grouped`` would have left it behind with the
    ``except Exception`` shape it was copied from."""
    store = await MessageStore.open(
        tmp_path / f"standalone-{arm}.db", group_commit_window_ms=GC_WINDOW_MS
    )
    try:
        mid = await store.enqueue_ingress(channel_id=CH, raw=RAW)
        item = await store.claim_next_fifo(CH, stage=Stage.INGRESS.value)
        assert item is not None
        trap = _Trap(store._db)
        trap.arm(COMMIT, raise_instead=arm == "control")

        async def _dead() -> None:
            await store.dead_letter_now(item.id, "undecryptable payload: test", _standalone=True)

        if arm == "cancel":
            task = asyncio.create_task(_dead())
            await asyncio.wait_for(trap.reached.wait(), WAIT)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(_Boom):
                await _dead()

        await _assert_connection_clean(store, probe=f"standalone-{arm}")
        cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (item.id,))
        row = await cur.fetchone()
        assert row is not None and row["status"] == OutboxStatus.INFLIGHT.value
        assert (await store.get_message(mid))["status"] == MessageStatus.RECEIVED.value

        # And it re-runs: the row really does go DEAD on the second attempt.
        await _dead()
        cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (item.id,))
        assert (await cur.fetchone())["status"] == OutboxStatus.DEAD.value
    finally:
        await store.close()


# --- the re-ingress stage handoff (ADR 0013 Increment 2) ----------------------------------------


async def _prepare_reingress(store: MessageStore) -> tuple[str, str]:
    """One delivered message whose captured reply produced a claimed ``Stage.RESPONSE`` work-row.

    Built through the real path rather than by inserting the row, so the state under test is the
    state the re-ingress worker actually hands to :meth:`MessageStore.ingress_handoff`."""
    origin = await store.enqueue_message(
        channel_id=CH, raw=RAW, deliveries=[(DEST, RAW)], now=100.0
    )
    item = (await store.claim_ready(destination_name=DEST, now=100.0))[0]
    await store.complete_with_response(
        item.id, body=REPLY, outcome="accepted", reingress_to=LOOPBACK, now=101.0
    )
    work = await store.claim_next_fifo(LOOPBACK, now=102.0, stage=Stage.RESPONSE.value)
    assert work is not None  # now INFLIGHT -- the token this handoff consumes
    return origin, work.id


async def _reingress(store: MessageStore, work_id: str, *, now: float = 110.0) -> bool:
    return bool(
        await store.ingress_handoff(
            response_row_id=work_id,
            loopback_channel_id=LOOPBACK,
            correlation_depth_cap=8,
            control_id="RSP1",
            message_type="RSP^K11",
            summary="reply",
            now=now,
        )
    )


async def _message_count(store: MessageStore) -> int:
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
    return int((await cur.fetchone())["n"])


async def _assert_reingress_unwound_and_recovered(
    store: MessageStore, origin: str, work_id: str, *, probe: str
) -> None:
    """The post-conditions a failed ``ingress_handoff`` must meet -- cancel arm and control arm alike.

    The work-row's existence IS the exactly-once token, so the load-bearing assertion is that the
    guarded ``DELETE`` did not become durable. Had it, the reply would be consumed with no child
    produced: the re-ingress is gone, and nothing re-derives it."""
    # 1-2. No transaction left open, and the next writer can use the connection.
    await _assert_connection_clean(store, probe=probe)

    # 3. ...and it did NOT carry the abandoned work with it: the token survived.
    cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (work_id,))
    row = await cur.fetchone()
    assert row is not None, "the failed handoff consumed the work-row -- the reply is lost"
    assert row["status"] == OutboxStatus.INFLIGHT.value

    # 4. Nothing the failed handoff would have produced leaked: no child message, no ingress row for
    #    it, and the origin did not finalize on the strength of a handoff that never committed.
    assert await _message_count(store) == 1
    assert (await store.pending_depth(LOOPBACK, stage=Stage.INGRESS.value))[0] == 0
    assert (await store.get_message(origin))["status"] != MessageStatus.PROCESSED.value

    # 5. Recovery: the in-flight token re-pends and the SAME handoff re-runs to success. This is the
    #    at-least-once contract -- a rolled-back handoff must be re-runnable, not merely harmless.
    assert await store.reset_stale_inflight(stage=Stage.RESPONSE.value, now=120.0) >= 1
    again = await store.claim_next_fifo(LOOPBACK, now=121.0, stage=Stage.RESPONSE.value)
    assert again is not None and again.id == work_id
    assert await _reingress(store, work_id, now=122.0)
    assert await _message_count(store) == 2
    assert (await store.get_message(origin))["status"] == MessageStatus.PROCESSED.value
    assert (await store.pending_depth(LOOPBACK, stage=Stage.INGRESS.value))[0] == 1


@pytest.mark.parametrize("arm", ARMS)
@pytest.mark.parametrize("point", CANCEL_POINTS)
async def test_ingress_handoff_writer_unwinds(tmp_path: Path, point: str, arm: str) -> None:
    """``ingress_handoff`` is the second stage handoff, and its own docstring calls it a clone of
    ``route_handoff`` -- but it was left on the ``except Exception`` shape when the unwind first
    landed. A cancellation at any of the three cancel points now unwinds it, and an ordinary
    exception at the same await does exactly the same thing.

    The ``body`` point lands on the guarded ``DELETE``, which is where this handoff would do its
    damage: the child message and its ingress row are written and uncommitted at that moment, so a
    transaction left open would let the next writer's COMMIT make the token's consumption durable
    while the child it should have produced was never there."""
    store = await MessageStore.open(tmp_path / f"reingress-{point}-{arm}.db")
    try:
        origin, work_id = await _prepare_reingress(store)
        trap = _Trap(store._db)
        trap.arm(point, raise_instead=arm == "control")

        if arm == "cancel":
            task = asyncio.create_task(_reingress(store, work_id))
            await asyncio.wait_for(trap.reached.wait(), WAIT)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(_Boom):
                await _reingress(store, work_id)

        await _assert_reingress_unwound_and_recovered(
            store, origin, work_id, probe=f"reingress-{point}-{arm}"
        )
    finally:
        await store.close()


@pytest.mark.parametrize("point", CANCEL_POINTS)
async def test_ingress_handoff_survives_a_second_cancellation(tmp_path: Path, point: str) -> None:
    """A SECOND cancellation landing inside the shielded rollback leaves the re-ingress token intact,
    exactly as it does for ``route_handoff``. Without the shield the second cancel would kill the
    rollback and leave the half-open transaction the first cancel's unwind was closing."""
    store = await MessageStore.open(tmp_path / f"reingress-twice-{point}.db")
    try:
        origin, work_id = await _prepare_reingress(store)
        trap = _Trap(store._db)
        trap.stall_rollback = 0.05  # hold the ROLLBACK open long enough to cancel into it
        trap.arm(point)

        task = asyncio.create_task(_reingress(store, work_id))
        await asyncio.wait_for(trap.reached.wait(), WAIT)
        task.cancel()
        await asyncio.wait_for(trap.rollback_started.wait(), WAIT)
        task.cancel()  # lands while the unwind is parked on the shielded rollback
        with pytest.raises(asyncio.CancelledError):
            await task

        assert trap.rollback_finished.is_set(), "the second cancellation killed the rollback"
        await _assert_reingress_unwound_and_recovered(
            store, origin, work_id, probe=f"reingress-twice-{point}"
        )
    finally:
        await store.close()


# --- group-commit writer transaction (ADR 0055, the committer's shared BEGIN ... COMMIT) ---------


@pytest.mark.parametrize("arm", ARMS)
@pytest.mark.parametrize("point", CANCEL_POINTS)
async def test_group_commit_writer_unwinds(tmp_path: Path, point: str, arm: str) -> None:
    """Same three cancel points with group commit ON, where the writer transaction lives in the
    COMMITTER task. Cancelling it must roll the batch back AND reject every enrolled member's future:
    a member's caller parks on that future (the inbound ACK gate among them), so a batch abandoned
    without rejection would park it forever."""
    store = await MessageStore.open(
        tmp_path / f"gc-{point}-{arm}.db", group_commit_window_ms=GC_WINDOW_MS
    )
    try:
        gc = store._group_commit
        assert gc is not None
        trap = _Trap(store._db)
        mid, ingress_id = await _prepare(store)
        trap.arm(point, raise_instead=arm == "control")

        member = asyncio.create_task(_route(store, mid, ingress_id))
        await asyncio.wait_for(trap.reached.wait(), WAIT)

        if arm == "cancel":
            committer = gc._task
            assert committer is not None
            committer.cancel()
            with pytest.raises(asyncio.CancelledError):
                await committer
            # The member was rejected before the committer died -- not stranded on its future.
            with pytest.raises(RuntimeError, match="committer cancelled"):
                await member
            # Revive the committer for the recovery re-run below. What is under test is the state of
            # the CONNECTION after the unwind, not the committer's own lifecycle.
            gc._task = None
            gc.start()
        else:
            with pytest.raises(_Boom):
                await member

        await _assert_unwound_and_recovered(store, mid, ingress_id, probe=f"gc-{point}-{arm}")
    finally:
        await store.close()


@pytest.mark.parametrize("point", CANCEL_POINTS)
async def test_group_commit_survives_a_second_cancellation(tmp_path: Path, point: str) -> None:
    """The cancel-twice case with group commit ON: a second cancellation of the committer, landing
    inside the shielded rollback, still leaves the batch rolled back and the connection clean."""
    store = await MessageStore.open(
        tmp_path / f"gc-twice-{point}.db", group_commit_window_ms=GC_WINDOW_MS
    )
    try:
        gc = store._group_commit
        assert gc is not None
        trap = _Trap(store._db)
        trap.stall_rollback = 0.05
        mid, ingress_id = await _prepare(store)
        trap.arm(point)

        member = asyncio.create_task(_route(store, mid, ingress_id))
        await asyncio.wait_for(trap.reached.wait(), WAIT)
        committer = gc._task
        assert committer is not None
        committer.cancel()
        await asyncio.wait_for(trap.rollback_started.wait(), WAIT)
        committer.cancel()
        with pytest.raises(asyncio.CancelledError):
            await committer

        assert trap.rollback_finished.is_set(), "the second cancellation killed the rollback"
        with pytest.raises(RuntimeError, match="committer cancelled"):
            await member

        gc._task = None
        gc.start()
        await _assert_unwound_and_recovered(store, mid, ingress_id, probe=f"gc-twice-{point}")
    finally:
        await store.close()
