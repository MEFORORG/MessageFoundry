# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Durable store/queue behaviour: enqueue, claim, retry/backoff, dead-letter,
crash recovery, replay, and message finalization. Time is injected for determinism."""

from __future__ import annotations

import os
import stat
import sys

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


# The icacls DACL is Windows-only (POSIX uses chmod). Run these where os.name == "nt" is REAL —
# forcing it via monkeypatch would make pathlib instantiate WindowsPath and crash pytest on Linux.
_windows_only = pytest.mark.skipif(sys.platform != "win32", reason="icacls DACL is Windows-only")


def _capture_icacls(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Capture the icacls argv _secure_file would run (no real icacls), as the user 'minter'."""
    import messagefoundry.store.store as store_mod

    captured: list[list[str]] = []

    class _R:
        returncode = 0
        stderr = ""
        stdout = ""

    monkeypatch.setenv("USERNAME", "minter")
    monkeypatch.setattr(
        store_mod.subprocess, "run", lambda argv, **kw: (captured.append(argv), _R())[1]
    )
    return captured


@_windows_only
def test_secure_file_grants_extra_read_principals(monkeypatch: pytest.MonkeyPatch) -> None:
    # The DPAPI key file must stay readable by the engine's service principal (SYSTEM + any
    # --grant-account), not just the minting admin (BACKLOG #44). The icacls grant must carry them.
    from pathlib import Path

    import messagefoundry.store.store as store_mod

    captured = _capture_icacls(monkeypatch)
    store_mod._secure_file(
        Path("key.dpapi"), extra_read_grants=["*S-1-5-18", "NT SERVICE\\MessageFoundry"]
    )
    argv = captured[0]
    assert argv[0] == "icacls" and "/inheritance:r" in argv and "/grant:r" in argv
    assert "minter:F" in argv  # owner keeps full control
    assert "*S-1-5-18:R" in argv  # SYSTEM read
    assert "NT SERVICE\\MessageFoundry:R" in argv  # service account read


@_windows_only
def test_secure_file_default_is_owner_only(monkeypatch: pytest.MonkeyPatch) -> None:
    # The generic store DB/WAL path passes no extra grants -> owner-only DACL, unchanged.
    from pathlib import Path

    import messagefoundry.store.store as store_mod

    captured = _capture_icacls(monkeypatch)
    store_mod._secure_file(Path("store.db"))
    assert captured[0] == ["icacls", "store.db", "/inheritance:r", "/grant:r", "minter:F"]


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


async def test_disposition_text_is_phi_scrubbed_at_the_store_layer(store: MessageStore) -> None:
    # #120: error / last_error / detail go through the safe_text PHI chokepoint at write, so an HL7
    # fragment that a handler/connector put into an exception can't land in those columns — the last
    # line of defense even if a caller forgot to scrub (and the only one on SQL Server, which stores
    # these plaintext). Covers mark_failed (last_error) + record_received (messages.error + event detail).
    phi = "PID|1||100^^^H^MR||DOE^JANE"
    retry = RetryPolicy(max_attempts=1, backoff_seconds=1, backoff_multiplier=1)
    mid = await store.enqueue_message(
        channel_id="c1", raw="MSH|x", deliveries=[("d1", "p1")], now=0.0
    )
    item = (await store.claim_ready(now=0.0))[0]
    await store.mark_failed(
        item.id, f"delivery rejected: {phi}", retry, now=0.0
    )  # max=1 → dead-letter
    last_error = (await store.outbox_for(mid))[0]["last_error"] or ""
    assert (
        "DOE^JANE" not in last_error
        and "100^^^H^MR" not in last_error
        and "[redacted]" in last_error
    )

    eid = await store.record_received(
        channel_id="c1", raw="MSH|x", status=MessageStatus.ERROR, error=f"bad value {phi}", now=0.0
    )
    assert "DOE^JANE" not in ((await store.get_message(eid))["error"] or "")
    # record_received also mirrors the error into a message_events.detail row — scrubbed there too.
    assert all("DOE^JANE" not in (e["detail"] or "") for e in await store.events_for(eid))


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


async def test_in_pipeline_depth_spans_stages_and_excludes_done(store: MessageStore) -> None:
    # Two outbound rows (pending) are counted.
    await store.enqueue_message(
        channel_id="c1", raw="x", deliveries=[("d1", "p1"), ("d2", "p2")], now=0.0
    )
    assert await store.in_pipeline_depth() == 2
    # An ingress-stage row in a DIFFERENT stage is counted too — stats() (outbound-only) can't see it.
    await store.enqueue_ingress(channel_id="c2", raw="y", now=0.0)
    assert (await store.stats()).get(OutboxStatus.PENDING.value) == 2  # outbound-only: unchanged
    assert await store.in_pipeline_depth() == 3  # 1 ingress + 2 outbound, all pending
    # Claiming flips the outbound rows to inflight (still in-pipeline); marking one done drops it out.
    items = await store.claim_ready(limit=10, now=1.0)
    assert await store.in_pipeline_depth() == 3  # inflight still counts as not-done
    await store.mark_done(items[0].id, now=2.0)
    assert await store.in_pipeline_depth() == 2  # one outbound delivered → excluded


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


async def test_list_messages_received_at_range(store: MessageStore) -> None:
    """The message-log date filter (#4b): received_from/received_to bound received_at to [from, to)."""
    for ts in (1000.0, 2000.0, 3000.0):
        await store.enqueue_message(channel_id="c1", raw="x", deliveries=[("d1", "p1")], now=ts)
    got = sorted(
        r["received_at"] for r in await store.list_messages(received_from=1500, received_to=2500)
    )
    assert got == [2000.0]  # lower inclusive, upper exclusive
    assert await store.count_messages(received_from=1500, received_to=2500) == 1
    open_ended = sorted(r["received_at"] for r in await store.list_messages(received_from=2000.0))
    assert open_ended == [2000.0, 3000.0]  # open upper bound
    assert await store.count_messages() == 3  # no filter = all (regression guard)


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


# --- H2: outbound idempotency ledger (delivered_keys) ------------------------------------------
#
# A delivered_keys row is written in the SAME txn as mark_done / complete_with_response (hash + ids
# only, no body/PHI); the FIFO claim skip-and-completes a re-claimed already-delivered head without
# re-sending; an operator replay re-send is NOT deduped.


async def _ledger_rows(store: MessageStore) -> list[dict]:
    cur = await store._db.execute("SELECT * FROM delivered_keys ORDER BY delivery_seq")
    return [dict(r) for r in await cur.fetchall()]


async def test_mark_done_writes_one_ledger_row(store: MessageStore) -> None:
    mid = await store.enqueue_message(
        channel_id="c1", raw="MSH|x", deliveries=[("d1", "p1")], control_id="CTRL1", now=100.0
    )
    item = await store.claim_next_fifo("d1", now=100.0)
    assert item is not None
    await store.mark_done(item.id, now=101.0)
    rows = await _ledger_rows(store)
    assert len(rows) == 1
    assert rows[0]["outbox_id"] == item.id
    assert rows[0]["message_id"] == mid
    assert rows[0]["destination_name"] == "d1"
    assert rows[0]["delivery_seq"] == 1
    # Ledger carries hashes + ids only — never the payload/body or any PHI field.
    assert "p1" not in str(rows[0].values())
    assert "MSH" not in str(rows[0].values())
    assert len(rows[0]["delivery_key"]) == 64  # sha256 hex


async def test_ledger_at_rest_carries_no_phi(tmp_path) -> None:
    # At-rest no-PHI assertion: read the delivered_keys table's RAW on-disk bytes (not the live row
    # mapping) and confirm neither the body NOR the control_id appears in the clear — the control_id is
    # only HASHED into delivery_key, never stored.
    import sqlite3

    db = tmp_path / "ledger.db"
    s = await MessageStore.open(db)
    try:
        await s.enqueue_message(
            channel_id="c1",
            raw="MSH|secretbody",
            deliveries=[("d1", "secretbody")],
            control_id="MRN-998877",
            now=100.0,
        )
        item = await s.claim_next_fifo("d1", now=100.0)
        assert item is not None
        await s.mark_done(item.id, now=101.0)
    finally:
        await s.close()
    raw = sqlite3.connect(db).execute("SELECT * FROM delivered_keys").fetchall()
    blob = repr(raw)
    assert raw and "secretbody" not in blob  # no body at rest
    assert (
        "MRN-998877" not in blob
    )  # control_id is hashed into delivery_key, never stored cleartext


async def test_complete_with_response_writes_one_ledger_row(store: MessageStore) -> None:
    mid = await store.enqueue_message(
        channel_id="c1", raw="MSH|x", deliveries=[("d1", "p1")], now=100.0
    )
    item = await store.claim_next_fifo("d1", now=100.0)
    assert item is not None
    await store.complete_with_response(
        item.id, body="MSA|AA", outcome="accepted", detail="ok", now=101.0
    )
    rows = await _ledger_rows(store)
    assert len(rows) == 1 and rows[0]["outbox_id"] == item.id
    assert "MSA" not in str(rows[0].values())  # the reply body never lands in the ledger
    assert mid  # message persisted


async def test_ingress_routed_completion_writes_no_ledger_row(store: MessageStore) -> None:
    # Only outbound deliveries own an external send; an ingress/routed completion writes no ledger row.
    await store.enqueue_ingress(channel_id="c1", raw="MSH|x", now=100.0)
    item = await store.claim_next_fifo("c1", now=100.0, stage="ingress")
    assert item is not None and item.destination_name is None
    # route_handoff consumes the ingress row; either way no ledger row exists for a non-outbound row.
    assert await _ledger_rows(store) == []


async def test_claim_skips_and_completes_already_delivered_head_no_resend(
    store: MessageStore,
) -> None:
    # Deliver row → ledger written + DONE. Then simulate a post-commit re-claim (failover / a stale
    # reset_stale_inflight after mark_done committed): force the DONE row back to PENDING. The next
    # FIFO claim must skip-and-complete it (return None, DONE again) WITHOUT handing it to a worker.
    mid = await store.enqueue_message(
        channel_id="c1", raw="MSH|x", deliveries=[("d1", "p1")], now=100.0
    )
    item = await store.claim_next_fifo("d1", now=100.0)
    assert item is not None
    await store.mark_done(item.id, now=101.0)
    assert len(await _ledger_rows(store)) == 1
    # Re-pend the already-delivered row WITHOUT clearing its ledger entry (the crash-re-run shape).
    await store._db.execute(
        "UPDATE queue SET status=? WHERE id=?", (OutboxStatus.PENDING.value, item.id)
    )
    await store._db.commit()
    # The claim consumes the dup head in place and returns None — the worker never re-sends it.
    assert await store.claim_next_fifo("d1", now=200.0) is None
    rows = await store.outbox_for(mid)
    assert rows[0]["status"] == OutboxStatus.DONE.value  # completed in place, not re-delivered
    # Exactly one ledger row still (the skip-and-complete does NOT add a second).
    assert len(await _ledger_rows(store)) == 1
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_crash_re_run_before_commit_is_a_noop_replay(store: MessageStore) -> None:
    # A crash BEFORE mark_done committed leaves no ledger row, so the recovered row re-delivers (the
    # inherent at-least-once window) — but re-running mark_done writes exactly ONE ledger row total
    # (idempotent on the content hash), never two for the same logical delivery.
    await store.enqueue_message(channel_id="c1", raw="MSH|x", deliveries=[("d1", "p1")], now=100.0)
    item = await store.claim_next_fifo("d1", now=100.0)
    assert item is not None
    await store.mark_done(item.id, now=101.0)
    # Idempotent: a second mark_done of the same row does not add a duplicate ledger row.
    await store.mark_done(item.id, now=102.0)
    assert len(await _ledger_rows(store)) == 1


async def test_replay_resend_is_not_deduped(store: MessageStore) -> None:
    # An operator replay of a fully-delivered message must actually RE-SEND (not be skip-and-completed
    # as a duplicate): replay DELETEs the ledger entry, so the re-claimed row is claimed normally.
    mid = await store.enqueue_message(
        channel_id="c1", raw="MSH|x", deliveries=[("d1", "p1")], now=100.0
    )
    item = await store.claim_next_fifo("d1", now=100.0)
    assert item is not None
    await store.mark_done(item.id, now=101.0)
    assert len(await _ledger_rows(store)) == 1
    # Re-send: nothing stuck, so replay re-pends the DONE row AND drops its ledger entry.
    requeued = await store.replay(mid, now=200.0)
    assert requeued == 1
    assert await _ledger_rows(store) == []  # ledger cleared for the re-sent row
    # The replayed row is claimed normally (NOT deduped) and re-delivers.
    again = await store.claim_next_fifo("d1", now=200.0)
    assert again is not None and again.id == item.id and again.payload == "p1"
    await store.mark_done(again.id, now=201.0)
    # A fresh ledger row is written for the re-delivery (seq recomputes to 1 after the delete).
    assert len(await _ledger_rows(store)) == 1
