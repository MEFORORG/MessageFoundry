"""Durable store/queue behaviour: enqueue, claim, retry/backoff, dead-letter,
crash recovery, replay, and message finalization. Time is injected for determinism."""

from __future__ import annotations

import os
import stat

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus


@pytest.fixture
async def store(tmp_path):
    s = await MessageStore.open(tmp_path / "test.db")
    yield s
    await s.close()


async def test_open_uses_wal_and_normal_synchronous(store: MessageStore) -> None:
    cur = await store._db.execute("PRAGMA journal_mode")
    assert str((await cur.fetchone())[0]).lower() == "wal"
    cur = await store._db.execute("PRAGMA synchronous")
    assert (await cur.fetchone())[0] == 1  # NORMAL — crash-safe under WAL, faster than FULL


async def test_open_honors_full_synchronous(tmp_path) -> None:
    s = await MessageStore.open(tmp_path / "full.db", synchronous="FULL")
    try:
        cur = await s._db.execute("PRAGMA synchronous")
        assert (await cur.fetchone())[0] == 2  # FULL
    finally:
        await s.close()


async def test_open_rejects_unknown_synchronous(tmp_path) -> None:
    with pytest.raises(ValueError):
        await MessageStore.open(tmp_path / "bad.db", synchronous="sometimes")


async def test_open_restricts_db_file_to_owner(tmp_path) -> None:
    # The store file holds PHI at rest; opening it must not leave it world-readable.
    db = tmp_path / "perms.db"
    s = await MessageStore.open(db)
    try:
        assert db.exists()
        # POSIX: owner-only 0600. Windows uses an icacls DACL we don't introspect here.
        if os.name != "nt":
            assert stat.S_IMODE(db.stat().st_mode) == 0o600
    finally:
        await s.close()


async def test_enqueue_creates_message_and_outbox_rows(store: MessageStore) -> None:
    mid = await store.enqueue_message(
        channel_id="c1",
        raw="MSH|...",
        deliveries=[("archive", "MSH|...")],
        control_id="MSG001",
        message_type="ADT^A01",
        now=100.0,
    )
    msg = await store.get_message(mid)
    # enqueue_message (the direct/legacy write) routes straight to outbound rows → ROUTED. The staged
    # live path uses enqueue_ingress (RECEIVED) then handoff (ROUTED) — see test_staged_pipeline.
    assert msg["status"] == MessageStatus.ROUTED.value
    assert msg["control_id"] == "MSG001"
    outbox = await store.outbox_for(mid)
    assert len(outbox) == 1
    assert outbox[0]["status"] == OutboxStatus.PENDING.value
    events = await store.events_for(mid)
    assert events[0]["event"] == "received"


async def test_enqueue_with_no_delivery_is_unrouted(store: MessageStore) -> None:
    # Accepted but matched no destination: logged (UNROUTED), preserved, but no outbox rows.
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[], now=100.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.UNROUTED.value
    assert len(await store.outbox_for(mid)) == 0


async def test_record_received_logs_filtered_and_error(store: MessageStore) -> None:
    fid = await store.record_received(
        channel_id="c1", raw="x", status=MessageStatus.FILTERED, control_id="F1", now=100.0
    )
    assert (await store.get_message(fid))["status"] == MessageStatus.FILTERED.value
    assert len(await store.outbox_for(fid)) == 0

    eid = await store.record_received(
        channel_id="c1", raw="bad", status=MessageStatus.ERROR, error="parse error: boom", now=100.0
    )
    emsg = await store.get_message(eid)
    assert emsg["status"] == MessageStatus.ERROR.value
    assert emsg["error"] == "parse error: boom"


async def test_claim_marks_inflight_and_increments_attempts(store: MessageStore) -> None:
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=100.0
    )
    claimed = await store.claim_ready(now=100.0)
    assert len(claimed) == 1
    assert claimed[0].attempts == 1
    assert claimed[0].payload == "p1"
    # Re-claiming finds nothing (already inflight).
    assert await store.claim_ready(now=100.0) == []
    rows = await store.outbox_for(mid)
    assert rows[0]["status"] == OutboxStatus.INFLIGHT.value


async def test_mark_done_finalizes_message(store: MessageStore) -> None:
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=100.0
    )
    item = (await store.claim_ready(now=100.0))[0]
    await store.mark_done(item.id, now=101.0)
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DONE.value
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_failure_reschedules_with_backoff(store: MessageStore) -> None:
    retry = RetryPolicy(max_attempts=3, backoff_seconds=5, backoff_multiplier=2)
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=100.0
    )
    item = (await store.claim_ready(now=100.0))[0]  # attempt 1
    await store.mark_failed(item.id, "boom", retry, now=100.0)

    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value
    # attempts=1 -> backoff = 5 * 2**0 = 5s
    assert row["next_attempt_at"] == 105.0
    # Not due yet at t=104, due at t=105.
    assert await store.claim_ready(now=104.0) == []
    assert len(await store.claim_ready(now=105.0)) == 1


async def test_exhausting_retries_dead_letters_and_errors_message(store: MessageStore) -> None:
    retry = RetryPolicy(max_attempts=2, backoff_seconds=1, backoff_multiplier=1)
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=0.0)
    t = 0.0
    # Drive attempts until dead.
    for _ in range(5):
        claimed = await store.claim_ready(now=t)
        if not claimed:
            t += 10  # advance past backoff
            continue
        await store.mark_failed(claimed[0].id, "boom", retry, now=t)
        t += 10
    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.DEAD.value
    assert row["attempts"] == retry.max_attempts
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


async def test_default_retry_policy_retries_forever(store: MessageStore) -> None:
    # The built-in default (max_attempts=None) never dead-letters via mark_failed — it reschedules
    # with backoff indefinitely, so a transient failure is never silently lost (the conservative
    # posture). Only a finite max_attempts opts back into dead-lettering.
    assert RetryPolicy().max_attempts is None
    retry = RetryPolicy(backoff_seconds=1, backoff_multiplier=1)  # default (None) max_attempts
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=0.0)
    t = 0.0
    for _ in range(20):  # far past the old default of 5
        claimed = await store.claim_ready(now=t)
        if claimed:
            await store.mark_failed(claimed[0].id, "boom", retry, now=t)
        t += 10
    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value  # still retrying, never dead
    assert row["attempts"] > 5


async def test_dead_letter_now_fails_fast_without_consuming_a_retry(store: MessageStore) -> None:
    # Fail-fast path (permanent reject / internal error): force DEAD immediately, no backoff and no
    # extra attempt consumed, and the message finalizes to ERROR + shows in the dead-letter list.
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=0.0)
    item = (await store.claim_ready(now=0.0))[0]  # attempt 1
    await store.dead_letter_now(item.id, "negative ACK (MSA-1=AR)", now=1.0)
    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.DEAD.value
    assert row["attempts"] == 1  # claim incremented it; dead_letter_now must not bump it again
    assert row["last_error"] == "negative ACK (MSA-1=AR)"
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value
    assert len(await store.list_dead(channel_id="c1")) == 1


async def test_dead_letter_now_on_missing_row_is_a_noop(store: MessageStore) -> None:
    await store.dead_letter_now("does-not-exist", "boom")  # must not raise


async def test_pending_depth_counts_and_reports_oldest(store: MessageStore) -> None:
    # pending_depth scopes to one destination, counts only PENDING rows, and reports the oldest
    # enqueue time — what the queue_buildup detector keys off.
    assert await store.pending_depth("d1") == (0, None)  # empty lane
    await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=10.0)
    await store.enqueue_message(channel_id="c1", raw="y", deliveries=[("d1", "p2")], now=20.0)
    await store.enqueue_message(channel_id="c1", raw="z", deliveries=[("d2", "p3")], now=30.0)
    assert await store.pending_depth("d1") == (2, 10.0)  # d2's row isn't counted
    # Claiming the head makes it INFLIGHT, so it drops out of the pending depth.
    await store.claim_next_fifo("d1", now=10.0)
    assert await store.pending_depth("d1") == (1, 20.0)


async def test_claim_next_fifo_ignores_owner_single_node(store: MessageStore) -> None:
    # Track B Step 5: SQLite is single-node (no lane leases), so claim_next_fifo accepts an `owner`
    # kwarg for protocol uniformity but IGNORES it — passing a node id behaves identically to the
    # no-owner claim (claims the same head, same FIFO order). The runner only passes a non-None owner
    # on a clustered Postgres store, never here.
    await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=10.0)
    await store.enqueue_message(channel_id="c1", raw="y", deliveries=[("d1", "p2")], now=20.0)
    first = await store.claim_next_fifo("d1", now=30.0, owner="node-A")
    assert first is not None and first.payload == "p1"  # oldest head, owner ignored
    await store.mark_done(first.id, now=31.0)
    second = await store.claim_next_fifo("d1", now=32.0, owner="node-B")
    assert second is not None and second.payload == "p2"  # next head, different owner — still FIFO


async def test_reset_stale_inflight_recovers_after_crash(store: MessageStore) -> None:
    await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=100.0)
    await store.claim_ready(now=100.0)  # now inflight; simulate crash before delivery
    recovered = await store.reset_stale_inflight(now=200.0)
    assert recovered == 1
    # Recovered row is claimable again.
    assert len(await store.claim_ready(now=200.0)) == 1


async def test_dead_letter_missing_destinations(store: MessageStore) -> None:
    # A message queued to two outbounds; the registry no longer has OB_GONE -> its row dead-letters
    # at startup, the surviving outbound's row is untouched, and the message isn't stranded (H-5).
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("OB_KEEP", "p1"), ("OB_GONE", "p2")], now=0.0
    )
    killed = await store.dead_letter_missing_destinations({"OB_KEEP"}, now=5.0)
    assert killed == 1
    rows = {r["destination_name"]: r for r in await store.outbox_for(mid)}
    assert rows["OB_GONE"]["status"] == OutboxStatus.DEAD.value
    assert "destination removed" in rows["OB_GONE"]["last_error"]
    assert rows["OB_KEEP"]["status"] == OutboxStatus.PENDING.value  # untouched
    assert (await store.get_message(mid))[
        "status"
    ] == MessageStatus.ROUTED.value  # KEEP still live (routed, awaiting delivery)


async def test_dead_letter_missing_destinations_finalizes_when_all_gone(
    store: MessageStore,
) -> None:
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("OB_GONE", "p")], now=0.0
    )
    assert await store.dead_letter_missing_destinations(set(), now=5.0) == 1
    # the sole delivery is dead -> the message finalizes to ERROR, not stranded at RECEIVED
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


async def test_dead_letter_missing_destinations_noop_when_present(store: MessageStore) -> None:
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("OB_A", "p")], now=0.0)
    assert await store.dead_letter_missing_destinations({"OB_A", "OB_B"}, now=5.0) == 0
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.PENDING.value


async def test_replay_requeues_dead_not_done(store: MessageStore) -> None:
    # Per-message replay recovers STUCK deliveries (dead/pending) but must NOT re-pend an already
    # DONE one — re-queuing a delivered row would re-deliver it and un-finalize the message (M-2,
    # load-bearing once a Step-B message can hold rows at two stages at once).
    retry = RetryPolicy(max_attempts=1, backoff_seconds=1)
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1"), ("d2", "p2")], now=0.0
    )
    items = await store.claim_ready(limit=10, now=0.0)
    done_item, dead_item = items[0], items[1]
    await store.mark_done(done_item.id, now=1.0)
    await store.mark_failed(dead_item.id, "boom", retry, now=1.0)  # exhausts -> dead
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value

    requeued = await store.replay(mid, now=2.0)
    assert requeued == 1  # only the DEAD row — the DONE row is left alone (not re-delivered)
    by_id = {r["id"]: r for r in await store.outbox_for(mid)}
    assert by_id[done_item.id]["status"] == OutboxStatus.DONE.value
    assert by_id[dead_item.id]["status"] == OutboxStatus.PENDING.value
    assert by_id[dead_item.id]["attempts"] == 0
    # The re-queued OUTBOUND row → the message is routed-again, awaiting delivery (ROUTED).
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value


async def test_replay_resends_fully_delivered_message(store: MessageStore) -> None:
    # Nothing stuck (all delivered) → replay re-sends: the DONE row is re-queued for re-transmission
    # (the deliberate operator re-send; outbounds are idempotent).
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=0.0)
    item = (await store.claim_ready(now=0.0))[0]
    await store.mark_done(item.id, now=1.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    requeued = await store.replay(mid, now=2.0)
    assert requeued == 1
    row = (await store.outbox_for(mid))[0]
    assert row["status"] == OutboxStatus.PENDING.value and row["attempts"] == 0
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value


async def _dead_delivery(
    store: MessageStore, channel_id: str, dest: str, *, payload: str = "p", now: float = 0.0
) -> str:
    """Enqueue one delivery and drive it straight to DEAD (max_attempts=1). Returns message id."""
    mid = await store.enqueue_message(
        channel_id=channel_id, raw="x", deliveries=[(dest, payload)], now=now
    )
    item = (await store.claim_ready(now=now, destination_name=dest))[0]
    await store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1), now=now)
    return mid


async def test_list_and_count_dead_with_filters(store: MessageStore) -> None:
    await _dead_delivery(store, "c1", "d1", now=10.0)
    await _dead_delivery(store, "c2", "d2", now=20.0)
    assert await store.count_dead() == 2
    rows = await store.list_dead()
    assert [r["destination_name"] for r in rows] == ["d2", "d1"]  # newest-failed first
    assert rows[0]["channel_id"] == "c2"
    assert rows[0]["attempts"] == 1 and rows[0]["last_error"] == "boom"
    # scoping filters
    assert await store.count_dead(destination_name="d1") == 1
    assert await store.count_dead(channel_id="c2") == 1
    assert len(await store.list_dead(channel_id="c2")) == 1


async def test_list_dead_excludes_done_and_pending(store: MessageStore) -> None:
    mid = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p")], now=0.0)
    await store.mark_done((await store.claim_ready(now=0.0))[0].id, now=1.0)
    await store.enqueue_message(channel_id="c1", raw="y", deliveries=[("d1", "p2")], now=0.0)
    assert await store.count_dead() == 0
    assert list(await store.list_dead()) == []
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_replay_dead_requeues_only_dead_rows(store: MessageStore) -> None:
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1"), ("d2", "p2")], now=0.0
    )
    done_item = (await store.claim_ready(now=0.0, destination_name="d1"))[0]
    dead_item = (await store.claim_ready(now=0.0, destination_name="d2"))[0]
    await store.mark_done(done_item.id, now=1.0)
    await store.mark_failed(dead_item.id, "boom", RetryPolicy(max_attempts=1), now=1.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value

    requeued = await store.replay_dead(now=2.0)
    assert requeued == 1  # only the dead delivery, not the delivered one
    rows = {r["destination_name"]: r for r in await store.outbox_for(mid)}
    assert rows["d1"]["status"] == OutboxStatus.DONE.value  # untouched
    assert rows["d2"]["status"] == OutboxStatus.PENDING.value and rows["d2"]["attempts"] == 0
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    assert await store.count_dead() == 0
    assert any(e["event"] == "replayed" for e in await store.events_for(mid))


async def test_replay_dead_scoped_by_destination(store: MessageStore) -> None:
    await _dead_delivery(store, "c1", "d1", now=0.0)
    await _dead_delivery(store, "c1", "d2", now=0.0)
    requeued = await store.replay_dead(destination_name="d1", now=5.0)
    assert requeued == 1
    assert await store.count_dead() == 1  # d2 left dead
    assert (await store.list_dead())[0]["destination_name"] == "d2"


async def test_replay_dead_none_returns_zero(store: MessageStore) -> None:
    assert await store.replay_dead(now=0.0) == 0


async def test_replay_dead_rolls_back_on_partial_failure(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _dead_delivery(store, "c1", "d1", now=0.0)

    async def boom(*a: object, **k: object) -> None:
        raise RuntimeError("event insert failed")

    monkeypatch.setattr(store, "_event", boom)
    with pytest.raises(RuntimeError):
        await store.replay_dead(now=5.0)

    # The batch rolled back: the row is still DEAD (not half-flipped to PENDING)...
    assert await store.count_dead() == 1
    # ...and the shared connection is left usable (no dangling open transaction).
    mid = await store.enqueue_message(channel_id="c2", raw="x", deliveries=[("d2", "p")], now=6.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value


async def test_multiple_destinations_finalize_independently(store: MessageStore) -> None:
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1"), ("d2", "p2")], now=0.0
    )
    items = await store.claim_ready(limit=10, now=0.0)
    await store.mark_done(items[0].id, now=1.0)
    # One done, one still pending -> message not finalized yet (stays ROUTED).
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    await store.mark_done(items[1].id, now=2.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_stats_reports_queue_depth(store: MessageStore) -> None:
    await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=0.0)
    await store.enqueue_message(channel_id="c1", raw="y", deliveries=[("d1", "p2")], now=0.0)
    assert (await store.stats()).get(OutboxStatus.PENDING.value) == 2


# --- purge (soft-cancel) -----------------------------------------------------


async def test_cancel_queued_all_soft_cancels_and_finalizes(store: MessageStore) -> None:
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=100.0
    )
    n = await store.cancel_queued("c1", "d1", now=101.0)
    assert n == 1
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.CANCELLED.value
    # All deliveries terminal and none dead -> message finalizes as processed (not error).
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    assert any(e["event"] == "cancelled" for e in await store.events_for(mid))


async def test_cancel_queued_top_only_cancels_the_head(store: MessageStore) -> None:
    m1 = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=100.0)
    m2 = await store.enqueue_message(channel_id="c1", raw="y", deliveries=[("d1", "p2")], now=101.0)
    n = await store.cancel_queued("c1", "d1", top_only=True, now=102.0)
    assert n == 1
    # The head (earliest next_attempt_at) is cancelled; the other stays queued.
    assert (await store.outbox_for(m1))[0]["status"] == OutboxStatus.CANCELLED.value
    assert (await store.outbox_for(m2))[0]["status"] == OutboxStatus.PENDING.value


async def test_cancel_queued_leaves_inflight_untouched(store: MessageStore) -> None:
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=100.0
    )
    await store.claim_ready(now=100.0)  # -> inflight
    assert await store.cancel_queued("c1", "d1", now=101.0) == 0
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.INFLIGHT.value


# --- connection metrics ------------------------------------------------------


async def test_connection_metrics_inbound_and_destination(store: MessageStore) -> None:
    m1 = await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=10.0)
    item = (await store.claim_ready(now=10.0))[0]
    await store.mark_done(item.id, now=12.0)
    await store.enqueue_message(channel_id="c1", raw="y", deliveries=[("d1", "p2")], now=20.0)

    m = await store.connection_metrics(since=0.0, now=100.0, rate_window=1000.0)
    inbound = m.inbound["c1"]
    assert inbound.read == 2 and inbound.errored == 0 and inbound.last_at == 20.0
    dest = m.destinations[("c1", "d1")]
    assert dest.queue_depth == 1  # m2 still pending
    assert dest.written == 1  # m1 delivered
    assert dest.recent_done == 1  # within the rate window
    assert dest.oldest_pending_at == 20.0  # m2's created_at
    assert m1  # (silence unused warning; m1 id retained for clarity)


async def test_enqueue_stores_summary_and_metadata(store: MessageStore) -> None:
    await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1")], summary="MRN 1 · DOE", now=100.0
    )
    rows = await store.list_messages()
    assert rows[0]["summary"] == "MRN 1 · DOE"
    assert rows[0]["metadata"] is None
    assert rows[0]["last_event"] == "received"  # only event so far


async def test_list_messages_last_event_reflects_latest(store: MessageStore) -> None:
    mid = await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=100.0
    )
    item = (await store.claim_ready(now=100.0))[0]
    await store.mark_done(item.id, now=101.0)
    rows = await store.list_messages()
    assert rows[0]["last_event"] == "delivered"
    assert mid


async def test_db_status_reports_counts_journal_size(store: MessageStore) -> None:
    await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=100.0)
    st = await store.db_status()
    assert st.messages == 1
    assert st.events >= 1  # the 'received' event
    assert st.journal_mode.lower() == "wal"
    assert st.size_bytes > 0
    assert st.path == store.path


async def test_integrity_check_ok(store: MessageStore) -> None:
    ok, detail = await store.integrity_check()
    assert ok is True
    assert detail == "ok"


async def test_record_audit_writes_audit_log(store: MessageStore) -> None:
    await store.record_audit(
        "summary_search_display", channel_id="c1", detail='{"count": 2}', now=100.0
    )
    entries = await store.list_audit()
    assert len(entries) == 1
    assert entries[0]["action"] == "summary_search_display"
    assert entries[0]["channel_id"] == "c1"


async def test_connection_metrics_respects_since_window(store: MessageStore) -> None:
    await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=10.0)
    item = (await store.claim_ready(now=10.0))[0]
    await store.mark_done(item.id, now=12.0)  # delivered at t=12
    await store.enqueue_message(channel_id="c1", raw="y", deliveries=[("d1", "p2")], now=20.0)

    m = await store.connection_metrics(since=15.0, now=100.0, rate_window=1000.0)
    assert m.inbound["c1"].read == 1  # only the t=20 message counts since t=15
    dest = m.destinations[("c1", "d1")]
    assert dest.written == 0  # the t=12 delivery predates the window
    assert dest.queue_depth == 1  # current state is unaffected by the window
