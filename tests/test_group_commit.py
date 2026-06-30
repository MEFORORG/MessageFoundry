# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Group-commit (ADR 0055) — the app-side committer coroutine for the SQLite write connection.

Exercises the acceptance criteria with group-commit ENABLED (``group_commit_window_ms > 0``):

* **AC-1** — a group rollback re-runs EVERY member (a failure mid-batch rejects every member's future;
  no member is silently dropped or partially applied).
* **AC-2** — ``claim_next_fifo`` never groups: the ``attempts+1`` poison-guard commits standalone,
  *before* the post-claim work, and never shares the post-claim batch's rollback fate (so a poisoned
  message increments ``attempts`` durably even when later work rolls back — no infinite loop / FIFO
  head-of-line block).
* **AC-3** — the inbound ACK (modeled by ``enqueue_ingress`` returning) is released only AFTER the
  ingress member's group commit is durable.
* **AC-4** — a member publishes its ``_state_cache`` delta ONLY on commit success; a rolled-back
  member publishes nothing.
* **AC-5** — the per-channel-FIFO / at-least-once / single-finalizer behaviour is unchanged with the
  flag ON (covered by re-running the staged-pipeline suite under group-commit; this module adds a
  direct FIFO + single-finalizer assertion under the flag for good measure).

These drive the store-level semantics directly (the committer is a store-internal coroutine); the full
listener→worker path is unaffected because the API is byte-identical with the flag on or off.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from messagefoundry.store.store import (
    MessageStatus,
    MessageStore,
    OutboxStatus,
    Stage,
    _GroupCommitter,
)

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"

# A non-zero window is what flips the store from inline-commit to the committer coroutine. Keep it
# tiny so the coalescing window doesn't slow the suite, but non-zero so the committer path is live.
GC_WINDOW_MS = 5.0


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(
        tmp_path / "gc.db", group_commit_window_ms=GC_WINDOW_MS, group_commit_max_batch=64
    )
    assert s._group_commit is not None  # the committer coroutine is actually live for these tests
    yield s
    await s.close()


async def _claim_ingress(store: MessageStore, channel: str):
    return await store.claim_next_fifo(channel, stage=Stage.INGRESS.value)


# --- AC-1: a group rollback re-runs EVERY member (no member dropped, no partial apply) ----------


async def test_group_rollback_reruns_all(tmp_path: Path) -> None:
    """A failure in ONE member of a batch rolls the WHOLE batch back: every member's future is
    rejected (so each caller re-runs — nothing is silently dropped), and NO member's write is left
    partially applied. Driven directly against the committer so the batch membership is deterministic:
    three members enrolled together, the middle one raises mid-batch."""
    s = await MessageStore.open(tmp_path / "ac1.db", group_commit_window_ms=GC_WINDOW_MS)
    try:
        gc = s._group_commit
        assert gc is not None

        # Three members share one open transaction. Each writes a distinct marker row into a scratch
        # table; the middle one raises AFTER writing, so the whole batch must roll back and leave the
        # table empty — proving member 1's already-issued write is NOT partially applied.
        await s._db.execute("CREATE TABLE gc_marker (n INTEGER)")
        await s._db.commit()

        async def write(n: int, *, boom: bool) -> int:
            await s._db.execute("INSERT INTO gc_marker (n) VALUES (?)", (n,))
            if boom:
                raise RuntimeError(f"member {n} failed mid-batch")
            return n

        # Enrol all three into the SAME batch (gather → they queue before the committer drains).
        results = await asyncio.gather(
            gc.submit(lambda: write(1, boom=False)),
            gc.submit(lambda: write(2, boom=True)),
            gc.submit(lambda: write(3, boom=False)),
            return_exceptions=True,
        )

        # EVERY member's future was rejected — none silently succeeded/dropped.
        assert all(isinstance(r, Exception) for r in results), results
        # The failing member sees its OWN cause; the innocent siblings see a coordinated rollback.
        assert isinstance(results[1], RuntimeError) and "member 2 failed" in str(results[1])
        assert isinstance(results[0], RuntimeError) and isinstance(results[2], RuntimeError)
        assert "rolled back" in str(results[0]) and "rolled back" in str(results[2])

        # NO partial apply: member 1's INSERT was rolled back with the rest — the table is empty.
        cur = await s._db.execute("SELECT COUNT(*) AS n FROM gc_marker")
        assert (await cur.fetchone())["n"] == 0

        # And each rejected caller can RE-RUN to success (the re-run the rejection licenses). Re-submit
        # the two innocent members (and a fixed member 2) — this clean batch commits.
        again = await asyncio.gather(
            gc.submit(lambda: write(1, boom=False)),
            gc.submit(lambda: write(2, boom=False)),
            gc.submit(lambda: write(3, boom=False)),
        )
        assert sorted(again) == [1, 2, 3]
        cur = await s._db.execute("SELECT n FROM gc_marker ORDER BY n")
        assert [r["n"] for r in await cur.fetchall()] == [1, 2, 3]
    finally:
        await s.close()


async def test_group_rollback_reruns_all_via_store_api(store: MessageStore) -> None:
    """The same property through the public store API: a real grouped handoff that raises mid-batch
    rejects its co-batched siblings too, none of their writes land, and a clean re-run then succeeds —
    so no received message is silently dropped by a sibling's failure."""
    # Three ingress messages, each claimed, ready to route_handoff.
    mids = [await store.enqueue_ingress(channel_id="IB", raw=RAW) for _ in range(3)]
    items = [await _claim_ingress(store, "IB") for _ in mids]
    assert all(it is not None for it in items)

    # Make ONE handoff's event-insert blow up so its member fails inside the shared batch.
    real_event = store._event
    armed = {"boom": True}

    async def maybe_boom(message_id: str, *a: object, **k: object) -> None:
        if armed["boom"] and message_id == mids[1]:
            raise RuntimeError("event insert failed for the middle message")
        await real_event(message_id, *a, **k)  # type: ignore[arg-type]

    store._event = maybe_boom  # type: ignore[method-assign]

    async def do_handoff(mid: str, item) -> bool:
        return await store.route_handoff(
            ingress_id=item.id,
            message_id=mid,
            channel_id="IB",
            handlers=[("h", RAW)],
            disposition=MessageStatus.ROUTED,
        )

    results = await asyncio.gather(
        *(do_handoff(m, it) for m, it in zip(mids, items)), return_exceptions=True
    )
    # Every co-batched caller was rejected (rolled back together) — not just the failing one.
    assert all(isinstance(r, Exception) for r in results), results

    # NO partial apply: zero routed rows leaked for ANY of the three, and every ingress row is still
    # inflight (recoverable), so nothing was silently dropped.
    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM queue WHERE stage=?", (Stage.ROUTED.value,)
    )
    assert (await cur.fetchone())["n"] == 0
    for mid in mids:
        assert (await store.get_message(mid))["status"] == MessageStatus.RECEIVED.value

    # Recover the inflight ingress rows and re-run cleanly — all three now route (re-run re-derives).
    armed["boom"] = False
    store._event = real_event  # type: ignore[method-assign]
    assert await store.reset_stale_inflight(stage=Stage.INGRESS.value) == 3
    for mid in mids:
        item = await _claim_ingress(store, "IB")
        assert item is not None
        assert await store.route_handoff(
            ingress_id=item.id,
            message_id=item.message_id,
            channel_id="IB",
            handlers=[("h", RAW)],
            disposition=MessageStatus.ROUTED,
        )
    for mid in mids:
        assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value


# --- AC-2: claim_next_fifo poison-guard commits standalone, never shares the batch's rollback ----


async def test_claim_poisonguard_standalone(store: MessageStore) -> None:
    """``claim_next_fifo`` is STANDALONE: the ``attempts+1`` poison-guard commits inline at claim time,
    BEFORE any post-claim grouped work and independent of its rollback fate. So a message whose
    post-claim processing keeps failing still has a DURABLY incremented ``attempts`` — it can dead-
    letter on a finite cap instead of head-of-line-blocking the lane forever."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)

    # 1st claim: attempts goes 0 → 1, committed standalone before we do anything else.
    item = await _claim_ingress(store, "IB")
    assert item is not None
    cur = await store._db.execute("SELECT attempts, status FROM queue WHERE id=?", (item.id,))
    row = await cur.fetchone()
    assert row["attempts"] == 1 and row["status"] == OutboxStatus.INFLIGHT.value

    # Now a post-claim grouped handoff for THIS row fails and rolls back. The standalone claim commit
    # already happened, so attempts MUST stay at 1 (the increment is durable, not rolled back with it).
    async def boom(*a: object, **k: object) -> None:
        raise RuntimeError("transform failed after claim")

    store._event = boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await store.route_handoff(
            ingress_id=item.id,
            message_id=mid,
            channel_id="IB",
            handlers=[("h", RAW)],
            disposition=MessageStatus.ROUTED,
        )
    cur = await store._db.execute("SELECT attempts FROM queue WHERE id=?", (item.id,))
    assert (await cur.fetchone())[
        "attempts"
    ] == 1  # durable: the poison-guard did NOT roll back with the failed batch

    # Recover + re-claim: attempts advances to 2 (durably again). A finite cap would now make progress
    # toward dead-lettering rather than re-claiming the same head forever.
    assert await store.reset_stale_inflight(stage=Stage.INGRESS.value) == 1
    again = await _claim_ingress(store, "IB")
    assert again is not None and again.id == item.id
    cur = await store._db.execute("SELECT attempts FROM queue WHERE id=?", (item.id,))
    assert (await cur.fetchone())["attempts"] == 2  # advanced — no infinite loop at attempts=1


async def test_claim_never_enrolls_in_committer(store: MessageStore) -> None:
    """A claim must NEVER enrol in the committer batch (it commits inline under the writer lock). Spy
    on the committer's ``submit`` and assert a ``claim_next_fifo`` invokes it ZERO times, while a
    grouped op (``mark_done``) invokes it — proving the claim path is structurally standalone, so it
    can neither be blocked by a slow batch nor share its rollback fate (no FIFO head-of-line block)."""
    gc = store._group_commit
    assert gc is not None
    calls = {"n": 0}
    real_submit = gc.submit

    async def counting_submit(run, **kwargs):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        return await real_submit(run, **kwargs)

    gc.submit = counting_submit  # type: ignore[method-assign]
    try:
        await store.enqueue_ingress(channel_id="IB", raw=RAW)
        before = calls["n"]
        item = await _claim_ingress(store, "IB")  # MUST NOT call submit
        assert item is not None
        assert calls["n"] == before, "claim enrolled in the committer batch (must be standalone)"
        # A grouped op DOES enrol — confirms the spy actually observes committer traffic.
        await store.mark_done(item.id if item.destination_name else "no-row")
        assert calls["n"] == before + 1
    finally:
        gc.submit = real_submit  # type: ignore[method-assign]


# --- AC-3: ACK released only after the ingress member's group commit is durable -----------------


async def test_ack_waits_for_durable_ingress(store: MessageStore) -> None:
    """``enqueue_ingress`` (the ACK-on-receipt boundary) must not RETURN until its ingress member's
    group commit is durable — the inbound ACK is built only after it returns, so returning early would
    ACK data a crash could still lose. Assert that once it returns, the row is committed and visible on
    an INDEPENDENT read connection (i.e. it really hit the durable WAL, not just the writer's view)."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)

    # The return value (the ACK gate) is the message id, and the message + ingress row are durable NOW.
    assert isinstance(mid, str)
    assert (await store.get_message(mid))["status"] == MessageStatus.RECEIVED.value

    # Read through the dedicated read-only WAL pool (a SEPARATE connection from the writer): it can only
    # see the row if the committer's COMMIT already landed in the WAL before enqueue_ingress returned.
    seen = await store.get_message(mid)  # read path uses the read pool
    assert seen is not None and seen["raw"] == RAW
    item = await _claim_ingress(store, "IB")
    assert item is not None and item.message_id == mid  # the ingress row is durably claimable


async def test_ack_gate_rejected_on_group_rollback(store: MessageStore) -> None:
    """The flip side of AC-3: if the ingress member's batch rolls back, the ACK gate (the
    ``enqueue_ingress`` await) RAISES rather than returning a fake ack — the sender is never told AA
    for data that didn't persist."""

    async def boom(*a: object, **k: object) -> None:
        raise RuntimeError("ingress insert failed mid-batch")

    # enqueue_ingress's grouped body calls _insert_message first; fail it so the ingress member rolls
    # back inside the committer batch and the awaiting ACK gate raises instead of returning a fake mid.
    store._insert_message = boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await store.enqueue_ingress(channel_id="IB", raw=RAW)
    # Nothing persisted — no message row, no ingress queue row (the rollback took it all).
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM messages")
    assert (await cur.fetchone())["n"] == 0
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM queue")
    assert (await cur.fetchone())["n"] == 0


# --- AC-4: cache delta published ONLY on commit success -----------------------------------------


async def test_cache_publish_only_on_success(store: MessageStore) -> None:
    """A grouped member publishes its ``_state_cache`` delta only on its own commit success. A
    committing transform_handoff with a state op makes the value visible via ``state_view``; a
    rolled-back one publishes nothing (the cache stays untouched), so a synchronous ``state_get`` never
    sees uncommitted state."""
    # Success path: route → transform with a state op; after commit the cache carries the value.
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    assert item is not None
    await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
    assert routed is not None
    ok = await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "p")],
        state_ops=[("ns", "k_ok", "committed-value")],
    )
    assert ok is True
    assert store.state_view()[("ns", "k_ok")] == "committed-value"  # published after commit

    # Rollback path: a second message whose transform_handoff fails AFTER applying its state op (the
    # event insert raises) must leave the cache untouched — the rolled-back op publishes nothing.
    mid2 = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item2 = await _claim_ingress(store, "IB")
    assert item2 is not None
    await store.route_handoff(
        ingress_id=item2.id,
        message_id=mid2,
        channel_id="IB",
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed2 = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
    assert routed2 is not None

    async def boom(*a: object, **k: object) -> None:
        raise RuntimeError("transform event insert failed")

    store._event = boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await store.transform_handoff(
            routed_id=routed2.id,
            message_id=mid2,
            channel_id="IB",
            deliveries=[("OB_B", "p")],
            state_ops=[("ns", "k_rolledback", "should-not-appear")],
        )
    # The rolled-back op published NOTHING: the key is absent from the read-through cache...
    assert ("ns", "k_rolledback") not in store.state_view()
    # ...and absent from the durable state table (the whole member rolled back).
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM state WHERE key=?", ("k_rolledback",))
    assert (await cur.fetchone())["n"] == 0
    # The earlier committed value is unaffected.
    assert store.state_view()[("ns", "k_ok")] == "committed-value"


# --- AC-5: per-channel FIFO / at-least-once / single-finalizer unchanged with the flag ON --------


async def test_per_channel_fifo_preserved_under_group_commit(store: MessageStore) -> None:
    """Per-channel FIFO into routing is unchanged with group-commit ON: two messages arriving in order
    on the same inbound are claimed at the ingress stage in strict arrival order."""
    m1 = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    m2 = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=2.0)
    first = await _claim_ingress(store, "IB")
    second = await _claim_ingress(store, "IB")
    assert first is not None and second is not None
    assert (first.message_id, second.message_id) == (m1, m2)  # arrival order preserved


async def test_single_finalizer_unchanged_under_group_commit(store: MessageStore) -> None:
    """The single-finalizer disposition flow is unchanged with the flag ON: a two-handler message does
    not finalize PROCESSED while a sibling routed row is still pending, then finalizes once both
    handlers' deliveries are done — proving the finalizer (the sole authority) behaves identically."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    assert item is not None
    await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("h1", RAW), ("h2", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    # h1 transforms + its outbound delivers — but h2's routed row is still pending → NOT processed yet.
    r1 = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
    assert r1 is not None
    await store.transform_handoff(
        routed_id=r1.id, message_id=mid, channel_id="IB", deliveries=[("OB_A", "p")]
    )
    out_a = await store.claim_next_fifo("OB_A")
    assert out_a is not None
    await store.mark_done(out_a.id)
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value  # premature guard

    # h2 transforms + delivers → now every handler is resolved → PROCESSED (single finalizer).
    r2 = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
    assert r2 is not None
    await store.transform_handoff(
        routed_id=r2.id, message_id=mid, channel_id="IB", deliveries=[("OB_B", "p")]
    )
    out_b = await store.claim_next_fifo("OB_B")
    assert out_b is not None
    await store.mark_done(out_b.id)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_at_least_once_idempotent_handoff_under_group_commit(store: MessageStore) -> None:
    """At-least-once's idempotent re-run is intact with the flag ON: a committed route_handoff is a
    no-op on re-invocation (the consumed ingress row is gone), so a crash-re-run never double-produces.
    This is the property group-commit's rollback-reject-rerun relies on."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    assert item is not None
    assert await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    # Re-invoke with the SAME ingress id: the row is already consumed → idempotent no-op, no dup row.
    again = await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("h", "dup")],
        disposition=MessageStatus.ROUTED,
    )
    assert again is False
    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM queue WHERE message_id=? AND stage=?",
        (mid, Stage.ROUTED.value),
    )
    assert (await cur.fetchone())["n"] == 1  # exactly one routed row — no double-produce


# --- committer unit behaviours backing the ACs (deterministic batch membership) -----------------


async def test_committer_resolves_each_member_with_its_own_result(tmp_path: Path) -> None:
    """On a clean batch the committer resolves EACH member's future with that member's own return
    value (not a shared/last value) — the property AC-1's per-member rejection mirrors on success."""
    s = await MessageStore.open(tmp_path / "unit.db", group_commit_window_ms=GC_WINDOW_MS)
    try:
        gc = s._group_commit
        assert gc is not None
        out = await asyncio.gather(*(gc.submit((lambda n=n: _ret(n))) for n in range(5)))
        assert out == [0, 1, 2, 3, 4]
    finally:
        await s.close()


async def _ret(n: int) -> int:
    return n


async def test_committer_submit_after_close_raises(tmp_path: Path) -> None:
    """Once closed the committer refuses new members (so a post-close store op can't silently strand a
    future no committer will ever resolve)."""
    s = await MessageStore.open(tmp_path / "closed.db", group_commit_window_ms=GC_WINDOW_MS)
    gc = s._group_commit
    assert isinstance(gc, _GroupCommitter)
    await s.close()
    with pytest.raises(RuntimeError, match="closed"):
        await gc.submit(lambda: _ret(1))


# --- regression: no member is stranded beyond one max_batch chunk (adversarial finding #1/#3) ----


async def test_burst_larger_than_max_batch_drains_fully(tmp_path: Path) -> None:
    """A burst that enrols MORE than max_batch members within one wake cycle must ALL resolve — the
    committer caps a single _flush at max_batch but MUST re-arm itself to drain the remainder, never
    strand the tail until the next unrelated submit(). Regression for the drain-loop stranding bug:
    100 concurrent ingress with max_batch=4 previously left 96 hung forever."""
    s = await MessageStore.open(
        tmp_path / "burst.db", group_commit_window_ms=GC_WINDOW_MS, group_commit_max_batch=4
    )
    try:
        # gather() queues all 100 before the committer drains its first batch → a single burst whose
        # remainder (96) can only resolve if _run re-arms _wake after each capped flush.
        mids = await asyncio.wait_for(
            asyncio.gather(*(s.enqueue_ingress(channel_id="IB", raw=RAW) for _ in range(100))),
            timeout=10.0,  # the bug hung forever; a generous bound still fails fast if it regresses
        )
        assert len(mids) == 100 and len(set(mids)) == 100  # every ingress resolved, none stranded
        cur = await s._db.execute(
            "SELECT COUNT(*) AS n FROM queue WHERE stage=?", (Stage.INGRESS.value,)
        )
        assert (await cur.fetchone())["n"] == 100  # all durable
    finally:
        await s.close()


async def test_close_drains_remainder_no_deadlock(tmp_path: Path) -> None:
    """close()/aclose() must FLUSH every enrolled member, not deadlock when the backlog exceeds one
    flush (the docstring's 'nothing is stranded'). Regression for the Hazard-B shutdown deadlock: with
    a backlog > 2x max_batch the committer used to block on _wake.wait() forever and close() hung."""
    s = await MessageStore.open(
        tmp_path / "closedrain.db", group_commit_window_ms=GC_WINDOW_MS, group_commit_max_batch=2
    )
    # Enrol a backlog larger than 2x max_batch, then close while members are still pending. Every one
    # must commit and close() must return promptly (the deadlock made it hang indefinitely).
    enqueues = [asyncio.create_task(s.enqueue_ingress(channel_id="IB", raw=RAW)) for _ in range(11)]
    mids = await asyncio.wait_for(asyncio.gather(*enqueues), timeout=10.0)
    assert len(mids) == 11
    await asyncio.wait_for(s.close(), timeout=10.0)  # must not deadlock
    # Independently confirm all 11 are durable in the closed DB.
    s2 = await MessageStore.open(tmp_path / "closedrain.db", group_commit_window_ms=GC_WINDOW_MS)
    try:
        cur = await s2._db.execute(
            "SELECT COUNT(*) AS n FROM queue WHERE stage=?", (Stage.INGRESS.value,)
        )
        assert (await cur.fetchone())["n"] == 11
    finally:
        await s2.close()


# --- regression: a cancelled caller never skips a committed member's cache publish (finding #2) ---


async def test_cancelled_transform_still_publishes_committed_state(tmp_path: Path) -> None:
    """If a transform worker is CANCELLED while parked on the committer future, the enrolled member
    still commits — and its committed state op MUST still reach _state_cache (the publish is a
    committer-frame post-commit hook, not the cancelled caller's post-await frame). Regression for the
    'committed state missing from cache until restart' divergence."""
    # A large window so the caller is reliably parked inside the committer when we cancel it.
    s = await MessageStore.open(
        tmp_path / "cancel.db", group_commit_window_ms=300.0, group_commit_max_batch=64
    )
    try:
        mid = await store_route_to_routed(s)
        routed = await s.claim_next_fifo("IB", stage=Stage.ROUTED.value)
        assert routed is not None

        async def do() -> bool:
            return await s.transform_handoff(
                routed_id=routed.id,
                message_id=mid,
                channel_id="IB",
                deliveries=[("OB_A", "p")],
                state_ops=[("ns", "k_cancel", "committed-value")],
            )

        t = asyncio.create_task(do())
        await asyncio.sleep(0.03)  # let it enrol + park on the committer future
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t  # the cancel still propagates to the worker (cancellability preserved)

        # Give the committer its window to commit the (now detached) member, then assert BOTH the
        # durable write AND the cache carry the value — no divergence.
        await asyncio.sleep(0.6)
        cur = await s._db.execute("SELECT COUNT(*) AS n FROM state WHERE key=?", ("k_cancel",))
        assert (await cur.fetchone())["n"] == 1  # committed durably
        assert s.state_view()[("ns", "k_cancel")] == "committed-value"  # AND visible in the cache
    finally:
        await s.close()


async def store_route_to_routed(s: MessageStore) -> str:
    """Enqueue one ingress and route it so a single routed row awaits transform; returns its mid."""
    mid = await s.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(s, "IB")
    assert item is not None
    await s.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    return mid


# --- regression: disabled-by-default path constructs NO committer and still publishes state -------


async def test_disabled_path_has_no_committer_and_publishes_state(tmp_path: Path) -> None:
    """With group_commit_window_ms=0 (the default) the store builds NO committer (inline-commit path)
    yet a transform_handoff still publishes its committed state op to the cache — pinning that the
    disabled path's on_commit publish (post-commit, in-frame) is byte-equivalent in effect to the old
    post-_run_grouped publish. Guards against a future _run_grouped refactor silently dropping it."""
    s = await MessageStore.open(tmp_path / "disabled.db")  # window defaults to 0 → disabled
    try:
        assert s._group_commit is None  # no committer constructed on the default path
        mid = await store_route_to_routed(s)
        routed = await s.claim_next_fifo("IB", stage=Stage.ROUTED.value)
        assert routed is not None
        ok = await s.transform_handoff(
            routed_id=routed.id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB_A", "p")],
            state_ops=[("ns", "k_disabled", "v")],
        )
        assert ok is True
        assert s.state_view()[("ns", "k_disabled")] == "v"  # published inline after commit
        # And a rolled-back op on the disabled path publishes nothing (mirror of AC-4, flag OFF).
        mid2 = await store_route_to_routed(s)
        routed2 = await s.claim_next_fifo("IB", stage=Stage.ROUTED.value)
        assert routed2 is not None

        async def boom(*a: object, **k: object) -> None:
            raise RuntimeError("event insert failed")

        s._event = boom  # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            await s.transform_handoff(
                routed_id=routed2.id,
                message_id=mid2,
                channel_id="IB",
                deliveries=[("OB_B", "p")],
                state_ops=[("ns", "k_rb_disabled", "nope")],
            )
        assert ("ns", "k_rb_disabled") not in s.state_view()  # rolled back → never published
    finally:
        await s.close()
