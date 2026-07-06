# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""PostgreSQL store behaviour — mirrors the SQLite/SQL Server suites, against a real Postgres.

**Gated**: skipped unless ``MEFOR_TEST_POSTGRES`` is set (plus ``MEFOR_STORE_*`` connection env),
so it's a no-op locally and in normal CI. A CI Postgres service-container job sets the env and runs it
for real. Requires the ``postgres`` extra (``asyncpg``). For the loopback dev Postgres
(``encrypt=false``) also set ``MEFOR_ALLOW_INSECURE_TLS=1`` (``scripts/dev/postgres.ps1`` exports it),
or the fixture errors on the bind-guard rather than skipping.

Beyond the SQL Server parity tests, this also exercises the **staged pipeline** Postgres supports
(ingress → routed → outbound, finalize PROCESSED; the ROUTED→FILTERED collapse), reference snapshots,
transform-state writes, and cross-stage stale-inflight recovery.
"""

from __future__ import annotations

import os
from typing import AsyncIterator

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStatus, OutboxStatus, Stage
from messagefoundry.store.content_search import make_spec

# A synthetic ADT carrying a (fake) MRN + name in PID — never real PHI.
_ADT_SEARCH = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN9001^^^H^MR||DOE^JANE\r"

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

# Tables cleaned between tests (FK order: children before parents).
_TABLES = (
    "message_events",
    "audit_log",
    "cluster_config",
    "queue",
    "response",
    "delivered_keys",
    "messages",
    "state",
    "state_version",
    "reference",
    "reference_version",
    "sessions",
    "webauthn_credentials",  # ADR 0068: FK to users(id) — must clear before users
    "user_roles",
    "ad_group_role_map",
    "ad_group_scope_map",
    "users",
    "roles",
)


@pytest.fixture
async def store() -> AsyncIterator[object]:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    # Clean slate (the container DB persists across tests in a run).
    async with s._pool.acquire() as conn:
        await conn.execute("TRUNCATE " + ", ".join(_TABLES) + " RESTART IDENTITY CASCADE")
    # open() seeded the read-through caches from the DB BEFORE this truncate, so re-load them from the
    # now-empty tables — otherwise a prior test's state/reference rows linger in this handle's in-memory
    # caches (e.g. _state_versions) and leak across tests (Track B Step 6b).
    await s._load_state_cache()
    await s._load_reference_cache()
    yield s
    await s.close()


# --- parity tests (mirror tests/test_sqlserver_store.py) -----------------------


async def test_enqueue_creates_message_and_outbox(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p1"), ("OB2", "p2")], control_id="MSG1"
    )
    msg = await store.get_message(mid)
    assert msg is not None and msg["status"] == MessageStatus.ROUTED.value
    assert msg["control_id"] == "MSG1"
    outbox = await store.outbox_for(mid)
    assert {o["destination_name"] for o in outbox} == {"OB1", "OB2"}
    assert all(o["status"] == OutboxStatus.PENDING.value for o in outbox)


async def test_enqueue_with_no_delivery_is_unrouted(store) -> None:
    mid = await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[])
    msg = await store.get_message(mid)
    assert msg is not None and msg["status"] == MessageStatus.UNROUTED.value
    assert await store.outbox_for(mid) == []


async def test_binary_carriage_round_trips_nul_bearing(store) -> None:
    # ADR 0028: base64 carriage carries NUL-bearing bytes through the TEXT body column, where the
    # latin-1 round-trip it supersedes would be REJECTED at psycopg bind ("cannot contain NUL").
    from messagefoundry.parsing import RawMessage

    data = bytes(range(256)) * 4
    carried = RawMessage.from_bytes(data, "binary").raw
    mid = await store.enqueue_ingress(channel_id="IB", raw=carried, message_type="binary")
    msg = await store.get_message(mid)
    assert msg is not None and "\x00" not in msg["raw"]
    assert RawMessage(msg["raw"], "binary").raw_bytes == data


async def test_record_received_filtered_and_error(store) -> None:
    f = await store.record_received(channel_id="IB", raw=RAW, status=MessageStatus.FILTERED)
    e = await store.record_received(
        channel_id="IB", raw=RAW, status=MessageStatus.ERROR, error="bad parse"
    )
    assert (await store.get_message(f))["status"] == MessageStatus.FILTERED.value
    erow = await store.get_message(e)
    assert erow["status"] == MessageStatus.ERROR.value and erow["error"] == "bad parse"


async def test_claim_marks_inflight_and_increments_attempts(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    items = await store.claim_ready(limit=10, now=200.0)
    assert len(items) == 1 and items[0].attempts == 1 and items[0].destination_name == "OB1"
    outbox = await store.outbox_for(mid)
    assert outbox[0]["status"] == OutboxStatus.INFLIGHT.value


async def test_mark_done_finalizes_message(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    item = (await store.claim_ready(now=200.0))[0]
    await store.mark_done(item.id, now=300.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_complete_with_response_parity(store) -> None:
    # ADR 0013 backend parity: Postgres complete_with_response must produce an identical `response` row
    # + PROCESSED finalization to SQLite, with the same single-transaction atomicity, and response_seq
    # must be replay-stable (replay resets attempts=0, so an attempts-keyed row would collide).
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    item = (await store.claim_ready(now=200.0))[0]
    await store.complete_with_response(
        item.id, body="MSA|AA", outcome="accepted", detail="MSA-1=AA", now=300.0
    )
    outbox = await store.outbox_for(mid)
    assert outbox[0]["status"] == OutboxStatus.DONE.value
    # The `response` table is invisible to the finalizer (it scans `queue` only) → PROCESSED.
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    caps = await store.correlate_response(mid)
    assert len(caps) == 1
    assert (caps[0].destination_name, caps[0].response_seq, caps[0].outcome, caps[0].body) == (
        "OB1",
        1,
        "accepted",
        "MSA|AA",
    )
    # Re-send (replay → attempts reset to 0) → seq=2, no PK collision.
    assert await store.replay(mid, now=400.0) == 1
    item2 = (await store.claim_ready(now=500.0))[0]
    await store.complete_with_response(item2.id, body="MSA|AA|2", outcome="accepted", now=600.0)
    caps2 = await store.correlate_response(mid)
    assert [(c.response_seq, c.body) for c in caps2] == [(1, "MSA|AA"), (2, "MSA|AA|2")]


async def test_ingress_handoff_parity(store) -> None:
    # ADR 0013 Increment 2 backend parity: Postgres ingress_handoff must consume the Stage.RESPONSE
    # work-row + produce the re-ingressed message+ingress row atomically, exactly-once, like SQLite.
    from messagefoundry.store.store import MessageStore, Stage

    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    item = (await store.claim_ready(now=200.0))[0]
    reply = "MSH|^~\\&|P|F|R|RF|20260101||RSP^K11|R1|P|2.5.1\r"
    await store.complete_with_response(
        item.id, body=reply, outcome="accepted", reingress_to="IB_LOOP", now=300.0
    )
    work = await store.claim_next_fifo("IB_LOOP", now=400.0, stage=Stage.RESPONSE.value)
    assert work is not None and work.channel_id == "IB_LOOP" and work.message_id == mid
    ok = await store.ingress_handoff(
        response_row_id=work.id,
        loopback_channel_id="IB_LOOP",
        correlation_depth_cap=8,
        control_id="R1",
        message_type="RSP^K11",
        summary=None,
        now=500.0,
    )
    assert ok is True
    # token consumed; origin PROCESSED; a re-ingressed child + ingress row on the loopback lane
    assert await store.claim_next_fifo("IB_LOOP", now=501.0, stage=Stage.RESPONSE.value) is None
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    child_mid = MessageStore._reingress_message_id(mid, "OB1", 1, reply)
    child = await store.get_message(child_mid)
    assert child is not None and child["status"] == MessageStatus.RECEIVED.value
    # idempotent: a second handoff on the same (now-gone) token is a no-op
    assert (
        await store.ingress_handoff(
            response_row_id=work.id,
            loopback_channel_id="IB_LOOP",
            correlation_depth_cap=8,
            control_id="R1",
            message_type="RSP^K11",
            summary=None,
            now=502.0,
        )
        is False
    )


async def test_failure_reschedules_with_backoff(store) -> None:
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    item = (await store.claim_ready(now=200.0))[0]
    await store.mark_failed(
        item.id, "boom", RetryPolicy(max_attempts=3, backoff_seconds=5.0), now=200.0
    )
    outbox = await store.outbox_for(item.message_id)
    assert outbox[0]["status"] == OutboxStatus.PENDING.value
    assert outbox[0]["next_attempt_at"] > 200.0
    assert outbox[0]["last_error"] == "boom"


async def test_exhausting_retries_dead_letters(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    retry = RetryPolicy(max_attempts=1)
    item = (await store.claim_ready(now=200.0))[0]  # attempts -> 1
    await store.mark_failed(item.id, "boom", retry, now=200.0)  # attempts(1) >= max(1) -> dead
    outbox = await store.outbox_for(mid)
    assert outbox[0]["status"] == OutboxStatus.DEAD.value
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


async def test_reset_stale_inflight_recovers(store) -> None:
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    item = (await store.claim_ready(now=200.0))[0]
    recovered = await store.reset_stale_inflight(now=300.0)
    assert recovered == 1
    assert (await store.outbox_for(item.message_id))[0]["status"] == OutboxStatus.PENDING.value


# --- H1: store-checked leader epoch (fencing token) ---------------------------


async def _seed_lease_epoch(store, lease_key: str, epoch: int) -> None:
    """Upsert the single ``leader_lease`` row to ``epoch`` (the authoritative current leader epoch). In
    production the cluster coordinator owns this row; here we set it directly to simulate the DB state a
    standby's fresh-acquire bump left behind, so the store's claim guard has something to validate."""
    async with store._pool.acquire() as conn:
        await conn.execute(
            "CREATE TABLE IF NOT EXISTS leader_lease ("
            " lease_key TEXT PRIMARY KEY, owner TEXT, lease_expires_at DOUBLE PRECISION NOT NULL,"
            " leader_epoch BIGINT NOT NULL DEFAULT 0)"
        )
        await conn.execute(
            "INSERT INTO leader_lease (lease_key, owner, lease_expires_at, leader_epoch)"
            " VALUES ($1, 'live', 9e18, $2)"
            " ON CONFLICT (lease_key) DO UPDATE SET leader_epoch = EXCLUDED.leader_epoch",
            lease_key,
            epoch,
        )


async def test_stale_epoch_claim_is_rejected_zero_rows(store) -> None:
    # The fence. The authoritative leader_lease.leader_epoch is 5 (a standby took over and bumped it). A
    # superseded ex-leader still believes it holds epoch 3 (held < current) — its FIFO claim must affect
    # 0 rows (return None) and leave the head PENDING, untouched.
    lease_key = "public:mefor_cluster_leader"
    await _seed_lease_epoch(store, lease_key, 5)
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    store.set_leader_epoch(3, lease_key=lease_key)  # ex-leader holds a STALE (older) epoch
    claimed = await store.claim_next_fifo("OB1", now=200.0)
    assert claimed is None  # rejected by the fence
    outbox = await store.outbox_for(mid)
    assert outbox[0]["status"] == OutboxStatus.PENDING.value  # head untouched, lane intact
    assert outbox[0]["attempts"] == 0  # claim did not even increment attempts


async def test_current_epoch_claim_succeeds(store) -> None:
    # The live leader holds the SAME epoch as the lease row (held == current): its claim passes. Equal is
    # the boundary — held >= current must include equality, else the true leader could never claim.
    lease_key = "public:mefor_cluster_leader"
    await _seed_lease_epoch(store, lease_key, 5)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    store.set_leader_epoch(5, lease_key=lease_key)
    claimed = await store.claim_next_fifo("OB1", now=200.0)
    assert claimed is not None
    assert claimed.destination_name == "OB1"


async def test_epoch_guard_disabled_when_none_is_byte_identical(store) -> None:
    # set_leader_epoch(None) (single-node / not-yet-leader) leaves the claim unfenced — byte-identical to
    # pre-H1: it claims even with no leader_lease row at all.
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    store.set_leader_epoch(None)
    claimed = await store.claim_next_fifo("OB1", now=200.0)
    assert claimed is not None


async def test_stale_then_promoted_claim_preserves_fifo_head(store) -> None:
    # FIFO survives the fence: two messages on one lane (N then N+1). A stale ex-leader is rejected (0
    # rows) so it delivers NEITHER; once this node is the current leader (held == lease epoch) it claims
    # the OLDEST first (N), preserving per-lane order across the would-be split-brain.
    lease_key = "public:mefor_cluster_leader"
    await _seed_lease_epoch(store, lease_key, 5)
    m1 = await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "n")], now=100.0)
    m2 = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "n1")], now=101.0
    )
    store.set_leader_epoch(3, lease_key=lease_key)  # stale ex-leader
    assert await store.claim_next_fifo("OB1", now=200.0) is None  # rejected, delivers nothing
    store.set_leader_epoch(5, lease_key=lease_key)  # now the current leader
    first = await store.claim_next_fifo("OB1", now=201.0)
    assert first is not None and first.message_id == m1  # OLDEST first — FIFO intact
    await store.mark_done(first.id, now=202.0)
    second = await store.claim_next_fifo("OB1", now=203.0)
    assert second is not None and second.message_id == m2


async def test_pooled_claim_fenced_ex_leader_claims_zero_across_all_lanes(store) -> None:
    # ADR 0066 §8 row 7 (H1 pooled): the epoch guard rides the pooled claim's UPDATE, so a
    # superseded ex-leader's claim_fifo_heads matches 0 rows across ALL requested lanes in one shot —
    # and leaves every head PENDING with attempts untouched (non-kept/unclaimed rows are never
    # UPDATEd; the probe's locks release at commit).
    lease_key = "public:mefor_cluster_leader"
    await _seed_lease_epoch(store, lease_key, 5)
    m1 = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB_PF1", "p")], now=100.0
    )
    m2 = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB_PF2", "p")], now=100.0
    )
    store.set_leader_epoch(3, lease_key=lease_key)  # ex-leader holds a STALE (older) epoch
    res = await store.claim_fifo_heads(Stage.OUTBOUND.value, ["OB_PF1", "OB_PF2"], now=200.0)
    assert res.by_lane == {} and res.rearm == frozenset()  # fenced: 0 rows, EMPTY-all
    for mid in (m1, m2):
        outbox = await store.outbox_for(mid)
        assert outbox[0]["status"] == OutboxStatus.PENDING.value
        assert outbox[0]["attempts"] == 0  # untouched — no claim, no increment
    store.set_leader_epoch(5, lease_key=lease_key)  # the current leader claims normally
    res2 = await store.claim_fifo_heads(Stage.OUTBOUND.value, ["OB_PF1", "OB_PF2"], now=201.0)
    assert set(res2.by_lane) == {"OB_PF1", "OB_PF2"}


async def test_replay_requeues(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    item = (await store.claim_ready(now=200.0))[0]
    await store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1), now=200.0)  # -> dead
    requeued = await store.replay(mid, now=300.0)
    assert requeued == 1
    outbox = await store.outbox_for(mid)
    assert outbox[0]["status"] == OutboxStatus.PENDING.value and outbox[0]["attempts"] == 0
    # Outbound-only requeue → the message is routed again, awaiting delivery (ROUTED).
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value


async def _dead(store, channel_id: str, dest: str, *, now: float = 100.0) -> str:
    mid = await store.enqueue_message(
        channel_id=channel_id, raw=RAW, deliveries=[(dest, "p")], now=now
    )
    item = (await store.claim_ready(now=now, destination_name=dest))[0]
    await store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1), now=now)
    return mid


async def test_list_count_and_replay_dead(store) -> None:
    await _dead(store, "IB", "OB1", now=100.0)
    await _dead(store, "IB2", "OB2", now=200.0)
    assert await store.count_dead() == 2
    rows = await store.list_dead()
    assert [r["destination_name"] for r in rows] == ["OB2", "OB1"]  # newest-failed first
    assert rows[0]["attempts"] == 1 and rows[0]["last_error"] == "boom"
    assert await store.count_dead(destination_name="OB1") == 1

    assert await store.replay_dead(destination_name="OB1", now=300.0) == 1
    assert await store.count_dead() == 1
    assert (await store.list_dead())[0]["destination_name"] == "OB2"


async def test_content_search_scan_decrypt(store) -> None:
    """ADR 0046 #51 backend parity: scan-and-decrypt content search behaves identically to SQLite —
    metadata pre-filter bounds the scan, the decrypted body matches the needle, field-path resolves,
    and the scan/result caps truncate. (Runs against a real Postgres in the gated CI leg.)"""
    await store.enqueue_message(
        channel_id="IB_A", raw=_ADT_SEARCH, deliveries=[], control_id="MSG1", message_type="ADT^A01"
    )
    await store.enqueue_message(
        channel_id="IB_B", raw=RAW, deliveries=[], control_id="MSG2", message_type="ADT^A01"
    )
    # Substring on decrypted raw (a SQL LIKE could never match the at-rest ciphertext).
    res = await store.search_messages(make_spec(content="JANE", field_path=None, field_value=None))
    assert res.matched == 1 and res.rows[0]["control_id"] == "MSG1"
    assert "raw" not in res.rows[0]  # metadata-only result
    # Field-path resolver against the decrypted body.
    res2 = await store.search_messages(
        make_spec(content=None, field_path="PID-5.1", field_value="DOE")
    )
    assert res2.matched == 1 and res2.rows[0]["control_id"] == "MSG1"
    # Metadata pre-filter narrows the candidate set before any decrypt.
    res3 = await store.search_messages(
        make_spec(content="ADT", field_path=None, field_value=None), channel_id="IB_A"
    )
    assert res3.scanned == 1 and res3.matched == 1
    # Scan cap truncates.
    res4 = await store.search_messages(
        make_spec(content="zzz-no-match", field_path=None, field_value=None, scan_limit=1)
    )
    assert res4.scanned == 1 and res4.truncated is True


async def test_replay_dead_only_dead_rows(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p1"), ("OB2", "p2")], now=100.0
    )
    done = (await store.claim_ready(now=100.0, destination_name="OB1"))[0]
    dead = (await store.claim_ready(now=100.0, destination_name="OB2"))[0]
    await store.mark_done(done.id, now=110.0)
    await store.mark_failed(dead.id, "boom", RetryPolicy(max_attempts=1), now=110.0)

    assert await store.replay_dead(now=200.0) == 1  # only the dead row
    rows = {r["destination_name"]: r for r in await store.outbox_for(mid)}
    assert rows["OB1"]["status"] == OutboxStatus.DONE.value
    assert rows["OB2"]["status"] == OutboxStatus.PENDING.value and rows["OB2"]["attempts"] == 0
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value


async def test_stats_and_metrics(store) -> None:
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    stats = await store.stats()
    assert stats.get(OutboxStatus.PENDING.value) == 1
    assert await store.in_pipeline_depth() == 1  # whole-pipeline gauge (one outbound row, pending)
    metrics = await store.connection_metrics(since=0.0, now=200.0, rate_window=60.0)
    assert metrics.inbound["IB"].read == 1
    assert metrics.destinations[("IB", "OB1")].queue_depth == 1
    db = await store.db_status()
    assert db.messages == 1 and db.journal_mode == "postgres"
    ok, _ = await store.integrity_check()
    assert ok is True


async def test_cancel_queued(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    cancelled = await store.cancel_queued("IB", "OB1", now=200.0)
    assert cancelled == 1
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.CANCELLED.value
    # All deliveries terminal (cancelled) → PROCESSED.
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_dead_letter_missing_destinations(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("GONE", "p")], now=100.0
    )
    killed = await store.dead_letter_missing_destinations({"OB1"}, now=200.0)
    assert killed == 1
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.DEAD.value
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


async def test_audit_chain_verifies(store) -> None:
    await store.record_audit("message_view", actor="alice", detail="view 1")
    await store.record_audit("export", actor="bob", detail="export 1")
    ok, msg = await store.verify_audit_chain()
    assert ok is True and "verified 2" in (msg or "")
    anchor = await store.audit_anchor()
    assert anchor[0] == 2
    ok2, _ = await store.verify_audit_chain(expected_anchor=anchor)
    assert ok2 is True
    rows = await store.list_audit()
    assert [r["action"] for r in rows] == ["export", "message_view"]  # newest first


async def test_record_audit_tees_off_box_redacted(store) -> None:
    # The off-box audit tee must fire on the real backend too (sec-offbox-log), via the same shared
    # emit_audit_tee path as SQLite — metadata only, with any HL7 in `detail` redacted.
    import json as _json
    import logging as _logging

    captured: list[str] = []

    class _Handler(_logging.Handler):
        def emit(self, record: _logging.LogRecord) -> None:
            captured.append(record.getMessage())

    handler = _Handler()
    logger = _logging.getLogger("messagefoundry.audit")
    logger.addHandler(handler)
    try:
        await store.record_audit("message.error", actor="svc", detail="PID|1||DOE^JANE^Q", now=1.0)
    finally:
        logger.removeHandler(handler)
    assert len(captured) == 1
    line = captured[0]
    assert "DOE" not in line and "JANE" not in line  # PHI scrubbed before it leaves the process
    rec = _json.loads(line)
    assert rec["event"] == "audit" and rec["action"] == "message.error" and rec["actor"] == "svc"


async def test_security_events_for_user_scopes_to_actor(store) -> None:
    # The /me/security-events source on the real backend: only the target actor's auth.* rows,
    # newest-first, honoring limit; other actors' rows and non-auth.* rows excluded.
    await store.record_audit("auth.login_success", actor="alice", detail="1")
    await store.record_audit("auth.login_failed", actor="bob", detail="b")  # other actor
    await store.record_audit("message_view", actor="alice", detail="x")  # not auth.*
    await store.record_audit("auth.password_changed", actor="alice", detail="2")
    rows = await store.security_events_for_user("alice")
    assert [r["action"] for r in rows] == ["auth.password_changed", "auth.login_success"]
    assert len(await store.security_events_for_user("alice", limit=1)) == 1
    assert len(await store.security_events_for_user("carol")) == 0


async def test_auth_users_roles_sessions(store) -> None:
    await store.upsert_role(role_id="operator", display_name="Operator", description=None)
    await store.create_user(
        user_id="u1",
        username="alice",
        auth_provider="local",
        display_name="Alice",
        email="a@example.org",
        password_hash="hash",
        now=1000.0,
    )
    assert await store.count_users() == 1
    user = await store.get_user_by_username("alice")
    assert user is not None and user.id == "u1" and user.password_hash == "hash"

    await store.set_user_roles("u1", ["operator"], assigned_by="t", now=2.0)
    assert await store.get_user_role_ids("u1") == ["operator"]

    await store.set_ad_group_role_map([("CN=Ops,DC=x", "operator")])
    assert await store.roles_for_ad_groups(["cn=ops,dc=x"]) == {"operator"}

    await store.set_ad_group_scope_map([("CN=Ops,DC=x", "IB")])
    assert await store.channels_for_ad_groups(["cn=ops,dc=x"]) == {"IB"}

    await store.record_login_failure("u1", failed_attempts=2, locked_until=500.0, now=10.0)
    assert (await store.get_user("u1")).locked_until == 500.0
    await store.record_login_success("u1", now=20.0)
    refreshed = await store.get_user("u1")
    assert refreshed.failed_attempts == 0 and refreshed.last_login_at == 20.0

    await store.create_session(token_hash="tok", user_id="u1", expires_at=9_999.0, now=10.0)
    assert (await store.get_session("tok")).user_id == "u1"
    await store.revoke_session("tok", now=30.0)
    assert (await store.get_session("tok")).revoked_at == 30.0
    await store.create_session(token_hash="old", user_id="u1", expires_at=5.0, now=1.0)
    assert await store.purge_expired_sessions(now=100.0) >= 1

    await store.delete_user("u1")
    assert await store.get_user("u1") is None
    assert await store.get_user_role_ids("u1") == []


async def test_roles_permissions_contract(store) -> None:
    """ADR 0045 custom-roles store contract on the real Postgres backend (parity with SQLite):
    the additive ``roles.permissions`` column round-trips a custom role's JSON, ``get_role`` exposes
    NULL permissions for a built-in, and ``delete_custom_role`` refuses a built-in / is idempotent.
    Reuses the single source-of-truth assertion from the SQLite suite so the live-server CI leg
    actually catches a Postgres regression in the new column/methods."""
    from tests.test_custom_roles import _assert_roles_contract

    await _assert_roles_contract(store)


async def test_webauthn_store_contract(store) -> None:
    """ADR 0068 §4 webauthn_credentials contract on the real Postgres backend: multi-row CRUD,
    the 1023-byte credential-id round-trip, duplicate-label integrity violation, and the strict
    sign-count compare-and-set under this backend's row-lock idiom. Extra-free import (the shared
    module never touches the [webauthn] extra, so this leg — which installs .[dev,postgres] —
    actually runs it instead of importorskip-skipping)."""
    from tests._webauthn_store_contract import _assert_webauthn_store_contract

    await _assert_webauthn_store_contract(store)


async def test_totp_store_contract(store) -> None:
    """WP-14 TOTP store contract on the real Postgres backend — the backfill that finally executes
    the FOR UPDATE row-lock paths (consume_totp_step / consume_recovery_code_hash) under test."""
    from tests._webauthn_store_contract import _assert_totp_contract

    await _assert_totp_contract(store)


async def test_mark_session_reauthed_reanchors_client(store) -> None:
    """WP-L3-13: mark_session_reauthed(client=) re-anchors the session's client address via COALESCE;
    a None client leaves it unchanged while still refreshing reauth_at. Exercises the new COALESCE
    write (incl. the None-bind / asyncpg $2 type inference) on the real Postgres backend."""
    await store.create_user(
        user_id="u2",
        username="bob",
        auth_provider="local",
        display_name=None,
        email=None,
        password_hash="h",
        now=1.0,
    )
    await store.create_session(
        token_hash="s1", user_id="u2", expires_at=9_999.0, client="10.1.1.1", now=1.0
    )
    await store.mark_session_reauthed("s1", now=50.0, client="10.2.2.2")
    s = await store.get_session("s1")
    assert s is not None and s.client == "10.2.2.2" and s.reauth_at == 50.0
    # client=None keeps the stored address (COALESCE) while still refreshing reauth_at.
    await store.mark_session_reauthed("s1", now=60.0)
    s = await store.get_session("s1")
    assert s is not None and s.client == "10.2.2.2" and s.reauth_at == 60.0
    await store.delete_user("u2")


# --- staged-pipeline tests (Postgres-only; the full ingress→routed→outbound flow) ---


async def test_staged_pipeline_processes_to_delivered(store) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW, control_id="MSG1", now=100.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.RECEIVED.value

    ingress = await store.claim_next_fifo("IB", now=110.0, stage=Stage.INGRESS.value)
    assert ingress is not None and ingress.stage == Stage.INGRESS.value
    routed = await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=120.0,
    )
    assert routed is True
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value

    routed_item = await store.claim_next_fifo("IB", now=130.0, stage=Stage.ROUTED.value)
    assert routed_item is not None and routed_item.handler_name == "H1"
    transformed = await store.transform_handoff(
        routed_id=routed_item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB1", "transformed")],
        now=140.0,
    )
    assert transformed is True

    out = await store.claim_next_fifo("OB1", now=150.0)
    assert out is not None and out.payload == "transformed"
    await store.mark_done(out.id, now=160.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_routed_to_filtered_collapse(store) -> None:
    """A routed message whose only handler transforms to ZERO deliveries collapses to FILTERED."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    ingress = await store.claim_next_fifo("IB", now=110.0, stage=Stage.INGRESS.value)
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=120.0,
    )
    routed_item = await store.claim_next_fifo("IB", now=130.0, stage=Stage.ROUTED.value)
    # Transform produced nothing → the finalizer collapses ROUTED → FILTERED.
    await store.transform_handoff(
        routed_id=routed_item.id, message_id=mid, channel_id="IB", deliveries=[], now=140.0
    )
    assert (await store.get_message(mid))["status"] == MessageStatus.FILTERED.value


async def test_unrouted_when_no_handler(store) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    ingress = await store.claim_next_fifo("IB", now=110.0, stage=Stage.INGRESS.value)
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[],
        disposition=MessageStatus.UNROUTED,
        now=120.0,
    )
    assert (await store.get_message(mid))["status"] == MessageStatus.UNROUTED.value


async def test_handoff_is_idempotent(store) -> None:
    """A committed route_handoff has consumed the ingress row, so a re-invocation is a no-op."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    ingress = await store.claim_next_fifo("IB", now=110.0, stage=Stage.INGRESS.value)
    first = await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=120.0,
    )
    second = await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=130.0,
    )
    assert first is True and second is False


async def test_transform_state_write_and_view(store) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    ingress = await store.claim_next_fifo("IB", now=110.0, stage=Stage.INGRESS.value)
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=120.0,
    )
    routed_item = await store.claim_next_fifo("IB", now=130.0, stage=Stage.ROUTED.value)
    await store.transform_handoff(
        routed_id=routed_item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB1", "x")],
        state_ops=[("ns", "mrn", {"anon": "A1"})],
        now=140.0,
    )
    # The committed state write is visible via the read-through cache...
    assert store.state_view()[("ns", "mrn")] == {"anon": "A1"}
    # ...and survives a reopen (loaded from the table).
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    reopened = await PostgresStore.open(load_settings(environ=os.environ).store)
    try:
        assert reopened.state_view()[("ns", "mrn")] == {"anon": "A1"}
    finally:
        await reopened.close()


async def test_reference_snapshot_write_and_read(store) -> None:
    await store.write_reference_snapshot(
        name="providers", version="v1", rows={"P1": {"name": "Dr A"}, "P2": {"name": "Dr B"}}
    )
    view = store.reference_view()
    assert view["providers"]["P1"] == {"name": "Dr A"}
    # A new version flips atomically and replaces the prior snapshot.
    await store.write_reference_snapshot(
        name="providers", version="v2", rows={"P1": {"name": "Dr A2"}}
    )
    view = store.reference_view()
    assert view["providers"] == {"P1": {"name": "Dr A2"}}
    # Reopen reloads the active snapshot from reference_version.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    reopened = await PostgresStore.open(load_settings(environ=os.environ).store)
    try:
        assert reopened.reference_view()["providers"] == {"P1": {"name": "Dr A2"}}
    finally:
        await reopened.close()


async def test_converge_reference_cache_follower_read_through(store) -> None:
    """Track B Step 6: a FOLLOWER handle converges its read cache from a snapshot another handle (the
    leader) wrote into the shared DB — without re-reading the external source. Idempotent + the
    empty-snapshot case both covered."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    # A second store handle on the SAME DB simulating a follower node. It opened before any snapshot, so
    # its cache starts empty.
    follower = await PostgresStore.open(load_settings(environ=os.environ).store)
    try:
        assert "providers" not in follower.reference_view()

        # The "leader" (the fixture handle) materializes a snapshot → reference_version + rows advance.
        await store.write_reference_snapshot(
            name="providers", version="v1", rows={"P1": {"npi": "111"}}
        )
        # The follower read-through pulls it into its own cache and reports the refreshed name.
        refreshed = await follower.converge_reference_cache()
        assert refreshed == ["providers"]
        assert follower.reference_view()["providers"] == {"P1": {"npi": "111"}}
        # Idempotent: a second converge with no change refreshes nothing.
        assert await follower.converge_reference_cache() == []

        # A newer snapshot the leader writes is picked up on the next converge (version advanced).
        await store.write_reference_snapshot(
            name="providers", version="v2", rows={"P1": {"npi": "222"}}
        )
        assert await follower.converge_reference_cache() == ["providers"]
        assert follower.reference_view()["providers"] == {"P1": {"npi": "222"}}

        # The empty-snapshot case: a set synced to zero rows still converges as a present empty {}.
        await store.write_reference_snapshot(name="empty", version="v1", rows={})
        assert await follower.converge_reference_cache() == ["empty"]
        assert follower.reference_view()["empty"] == {}
    finally:
        await follower.close()


async def _route_and_claim_routed(store, channel_id: str, now: float):
    """Drive a message through ingress→routed and return its (message_id, routed_item) so a test can call
    transform_handoff with state_ops. Mirrors the ingress→routed steps in test_transform_state_write_and_view."""
    mid = await store.enqueue_ingress(channel_id=channel_id, raw=RAW, now=now)
    ingress = await store.claim_next_fifo(channel_id, now=now + 1, stage=Stage.INGRESS.value)
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id=channel_id,
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=now + 2,
    )
    routed_item = await store.claim_next_fifo(channel_id, now=now + 3, stage=Stage.ROUTED.value)
    return mid, routed_item


async def test_converge_state_cache_follower_read_through(store) -> None:
    """Track B Step 6b: a FOLLOWER handle converges its transform-state cache from a write another handle
    (the writer) committed to the shared DB. Both enable convergence (the engine gate in a cluster). The
    follower sees the value, a second converge is idempotent, and the WRITER's own version advanced (so it
    would skip re-reading its own namespace)."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    store.enable_state_convergence()  # the "writer" node
    follower = await PostgresStore.open(load_settings(environ=os.environ).store)
    follower.enable_state_convergence()
    try:
        assert ("ns", "mrn") not in follower.state_view()

        # The writer commits a state write (bumping ns's version in the same txn).
        mid, routed = await _route_and_claim_routed(store, "IB", now=100.0)
        await store.transform_handoff(
            routed_id=routed.id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB1", "x")],
            state_ops=[("ns", "mrn", {"anon": "A1"})],
            now=110.0,
        )
        # The writer recorded its own new version, so its own converge would skip this namespace.
        assert store._state_versions["ns"] == 1

        # The follower read-through pulls A's committed write into its own cache and reports the namespace.
        refreshed = await follower.converge_state_cache()
        assert refreshed == ["ns"]
        assert follower.state_view()[("ns", "mrn")] == {"anon": "A1"}
        # Idempotent: a second converge with no new write refreshes nothing.
        assert await follower.converge_state_cache() == []
    finally:
        await follower.close()


async def test_transform_handoff_without_convergence_writes_no_state_version(store) -> None:
    """Track B Step 6b byte-identical: a handle that did NOT call enable_state_convergence() must write
    ZERO state_version rows on a transform_handoff with state_ops (single-node stays unchanged)."""
    mid, routed = await _route_and_claim_routed(store, "IB", now=100.0)
    await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB1", "x")],
        state_ops=[("ns", "mrn", {"anon": "A1"})],
        now=110.0,
    )
    row = await store._fetchone("SELECT COUNT(*) AS n FROM state_version")
    assert int(row["n"]) == 0  # no version bump → byte-identical single-node behaviour
    assert store._state_versions == {}


async def test_purge_state_bumps_version_for_follower_drop(store) -> None:
    """Track B Step 6b: a clustered purge bumps the purged namespace's version, so a follower's converge
    re-reads it and drops the purged key."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    store.enable_state_convergence()
    follower = await PostgresStore.open(load_settings(environ=os.environ).store)
    follower.enable_state_convergence()
    try:
        # The writer commits a state entry (set_at=110), then the follower converges to see it.
        mid, routed = await _route_and_claim_routed(store, "IB", now=100.0)
        await store.transform_handoff(
            routed_id=routed.id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB1", "x")],
            state_ops=[("ns", "mrn", {"anon": "A1"})],
            now=110.0,
        )
        assert await follower.converge_state_cache() == ["ns"]
        assert ("ns", "mrn") in follower.state_view()

        # The writer (a leader-gated singleton) purges everything older than 200 → the row goes, version bumps.
        purged = await store.purge_state(older_than=200.0, now=200.0)
        assert purged == 1
        # The follower converges again and drops the purged key (the namespace re-read finds zero rows).
        assert await follower.converge_state_cache() == ["ns"]
        assert ("ns", "mrn") not in follower.state_view()
    finally:
        await follower.close()


async def test_reset_stale_inflight_across_stages(store) -> None:
    """reset_stale_inflight (stage=None) recovers an in-flight row at every stage in one pass."""
    # An in-flight ingress row.
    mid_i = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    await store.claim_next_fifo("IB", now=110.0, stage=Stage.INGRESS.value)
    # An in-flight routed row (route a second message, then claim its routed row).
    mid_r = await store.enqueue_ingress(channel_id="IB2", raw=RAW, now=120.0)
    ing_r = await store.claim_next_fifo("IB2", now=121.0, stage=Stage.INGRESS.value)
    await store.route_handoff(
        ingress_id=ing_r.id,
        message_id=mid_r,
        channel_id="IB2",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=122.0,
    )
    await store.claim_next_fifo("IB2", now=123.0, stage=Stage.ROUTED.value)
    # An in-flight outbound row.
    await store.enqueue_message(channel_id="IB3", raw=RAW, deliveries=[("OB1", "p")], now=130.0)
    await store.claim_ready(now=131.0, destination_name="OB1")

    recovered = await store.reset_stale_inflight(now=200.0)
    assert recovered == 3
    # Each lane's head is pending again.
    assert (await store.claim_next_fifo("IB", now=210.0, stage=Stage.INGRESS.value)) is not None
    assert (await store.claim_next_fifo("IB2", now=210.0, stage=Stage.ROUTED.value)) is not None
    assert (await store.claim_next_fifo("OB1", now=210.0)) is not None
    assert mid_i and mid_r  # referenced


# --- multi-node row leases (Track B Step 2; Postgres-only, additive) -----------
#
# Isolation note: some lease assertions below use the UNSCOPED global sweep with exact-count equality
# (e.g. reclaim_expired_leases(now=...) == 1). These are hermetic only because the `store` fixture
# TRUNCATEs all tables at the START of each test and pytest runs serially against the DB — a serial
# run sees only the current test's rows. Run this module serially against an isolated DB; do not run
# overlapping/parallel sessions against the same shared Postgres or the global counts become flaky.


async def _queue_row(store, queue_id: str):
    """Read a queue row's lease columns directly (lease state is not on OutboxItem)."""
    async with store._pool.acquire() as conn:
        return await conn.fetchrow(
            "SELECT owner, lease_expires_at, status FROM queue WHERE id=$1", queue_id
        )


def _ttl(store) -> float:
    return store._settings.lease_ttl_seconds


async def test_claim_ready_stamps_owner_and_lease(store) -> None:
    """claim_ready marks the row this owner's and stamps lease_expires_at = now + ttl."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    item = (await store.claim_ready(now=200.0))[0]
    row = await _queue_row(store, item.id)
    assert row["owner"] == store._owner
    assert row["lease_expires_at"] == pytest.approx(200.0 + _ttl(store))
    assert row["status"] == OutboxStatus.INFLIGHT.value


async def test_claim_next_fifo_stamps_owner_and_lease(store) -> None:
    """claim_next_fifo stamps owner + lease the same way as claim_ready."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    item = await store.claim_next_fifo("OB1", now=200.0)
    assert item is not None
    row = await _queue_row(store, item.id)
    assert row["owner"] == store._owner
    assert row["lease_expires_at"] == pytest.approx(200.0 + _ttl(store))


async def test_reclaim_expired_leases_only_reclaims_expired(store) -> None:
    """reclaim_expired_leases reclaims only rows whose lease is in the past; a fresh lease is left in
    flight; it sets the row pending with owner/lease cleared and next_attempt_at=now."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    expired = (await store.claim_ready(now=200.0, destination_name="OB1"))[0]
    # A second row claimed LATER, so its lease expires later than `expired`'s.
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB2", "p")], now=100.0)
    fresh = (await store.claim_ready(now=250.0, destination_name="OB2"))[0]

    sweep_at = 200.0 + _ttl(store) + 1.0  # past expired's lease, before fresh's (claimed at 250)
    assert sweep_at < 250.0 + _ttl(store)

    reclaimed = await store.reclaim_expired_leases(now=sweep_at)
    assert reclaimed == 1
    ex_row = await _queue_row(store, expired.id)
    assert ex_row["status"] == OutboxStatus.PENDING.value
    assert ex_row["owner"] is None and ex_row["lease_expires_at"] is None
    fr_row = await _queue_row(store, fresh.id)
    assert fr_row["status"] == OutboxStatus.INFLIGHT.value  # not reclaimed
    # The reclaimed row is due now (next_attempt_at == sweep time) — claimable again.
    again = await store.claim_next_fifo("OB1", now=sweep_at)
    assert again is not None and again.id == expired.id


async def test_recover_inflight_on_promotion_owner_scoped(store) -> None:
    # #293: on promotion the new leader recovers the PRIOR leader's stranded inflight rows (owner-scoped,
    # lease-BLIND) WITHOUT waiting out the ~ttl per-row lease, and WITHOUT touching its own freshly-
    # claimed rows (no self-theft).
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    # The PRIOR leader = a distinct store instance (→ inflight under a FUTURE row lease, owned by its
    # distinct store-instance id).
    other = await PostgresStore.open(load_settings(environ=os.environ).store)
    try:
        assert other._owner != store._owner
        await store.enqueue_message(
            channel_id="IB", raw=RAW, deliveries=[("OB_OLD", "p")], now=100.0
        )
        old = await other.claim_next_fifo("OB_OLD", now=200.0)
        assert old is not None
        # The SURVIVOR claims its OWN row (queue owner=store._owner). A future lease, so nothing can
        # recover it on lease-expiry grounds.
        await store.enqueue_message(
            channel_id="IB", raw=RAW, deliveries=[("OB_NEW", "p")], now=100.0
        )
        mine = await store.claim_next_fifo("OB_NEW", now=200.0)
        assert mine is not None
        # Recover at t=210, while BOTH leases (claimed at 200, ttl=60 → expire at 260) are still in the
        # FUTURE — so the recovery is provably lease-BLIND, not merely an early expired-lease sweep.
        recover_at = 210.0
        assert (await _queue_row(store, old.id))["lease_expires_at"] > recover_at  # not yet expired

        recovered = await store.recover_inflight_on_promotion(now=recover_at)
        assert recovered == 1  # ONLY the prior leader's row (owner-scoped)

        old_row = await _queue_row(store, old.id)
        assert old_row["status"] == OutboxStatus.PENDING.value  # re-pended despite a future lease
        assert old_row["owner"] is None and old_row["lease_expires_at"] is None
        mine_row = await _queue_row(store, mine.id)
        assert (
            mine_row["status"] == OutboxStatus.INFLIGHT.value
        )  # OUR row untouched (no self-theft)
        assert mine_row["owner"] == store._owner

        # End-to-end: the re-pended head is claimable again at once.
        again = await store.claim_next_fifo("OB_OLD", now=211.0)
        assert again is not None and again.id == old.id
    finally:
        await other.close()


async def test_reclaim_expired_leases_is_stage_scoped(store) -> None:
    """A stage filter restricts the reclaim to that stage's expired rows."""
    # Expired ingress row.
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    await store.claim_next_fifo("IB", now=200.0, stage=Stage.INGRESS.value)
    # Expired outbound row.
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    await store.claim_ready(now=200.0, destination_name="OB1")

    sweep_at = 200.0 + _ttl(store) + 1.0
    # Scope to outbound: only the outbound row is reclaimed.
    assert await store.reclaim_expired_leases(now=sweep_at, stage=Stage.OUTBOUND.value) == 1
    # The ingress row is still inflight; an unscoped sweep then reclaims it.
    assert await store.reclaim_expired_leases(now=sweep_at) == 1


async def test_two_owner_no_theft(store) -> None:
    """A second store instance (distinct owner) must not reclaim owner A's row while its lease is
    still in the future, but reclaims it once expired — no theft of a live sibling's in-flight row."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    owner_b = await PostgresStore.open(load_settings(environ=os.environ).store)
    try:
        assert owner_b._owner != store._owner
        await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
        claimed = (await store.claim_ready(now=200.0, destination_name="OB1"))[0]
        ttl = _ttl(store)

        # Before the lease expires: B reclaims nothing (no theft).
        assert await owner_b.reclaim_expired_leases(now=200.0 + ttl - 1.0) == 0
        # The protection is purely time-based (reclaim is owner-agnostic) — even A's OWN sweep
        # reclaims nothing before expiry; it's the lease_expires_at < now gate, not the owner.
        assert await store.reclaim_expired_leases(now=200.0 + ttl - 1.0) == 0
        assert (await _queue_row(store, claimed.id))["status"] == OutboxStatus.INFLIGHT.value
        assert (await _queue_row(store, claimed.id))["owner"] == store._owner

        # After the lease expires: B reclaims it (A is presumed dead).
        assert await owner_b.reclaim_expired_leases(now=200.0 + ttl + 1.0) == 1
        reclaimed = await _queue_row(store, claimed.id)
        assert reclaimed["status"] == OutboxStatus.PENDING.value and reclaimed["owner"] is None
    finally:
        await owner_b.close()


# --- failover FIFO safety: stranded-head reclaim folded into the no-owner claim ----


async def test_fifo_claim_recovers_stranded_head_after_failover(store) -> None:
    """Active-passive failover FIFO safety: a crashed/fenced prior leader leaves the lane HEAD N inflight
    under an EXPIRED row lease. The next leader claims this lane via the ordinary (no-owner) FIFO claim,
    which reclaims this lane's expired-lease inflight rows in the SAME txn BEFORE the head SELECT — so it
    gets the RECOVERED head N, never N+1 ahead of it. Without that fold the PENDING-only head SELECT
    would skip the still-inflight N and deliver N+1 first (a per-lane FIFO break across failover)."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "N")], now=100.0)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "Np1")], now=101.0)

    # The prior leader claims the head N and then "crashes": N stays inflight (no mark_done/mark_failed)
    # and its row lease is left to age out. (A single store instance models the prior leader here; the
    # graph runs on the leader only, so the new leader is the same store reopened / a promoted standby.)
    head = await store.claim_next_fifo("OB1", now=200.0)
    assert head is not None and head.payload == "N"  # N is now inflight under an expiring lease

    # Past the TTL: N's row lease has expired. The new leader claims the lane via the ordinary FIFO path.
    expired_at = 200.0 + _ttl(store) + 1.0
    recovered = await store.claim_next_fifo("OB1", now=expired_at)
    # It must get the RECOVERED head N, never N+1 ahead of it — strict order survives the failover.
    assert recovered is not None and recovered.payload == "N"
    assert recovered.id == head.id


async def test_fifo_claim_leaves_live_head_untouched(store) -> None:
    """The stranded-head reclaim is scoped to EXPIRED leases, so a live head (lease still in the future)
    is NOT re-pended/re-claimed by a second poll — head-of-line blocking holds on the active node."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "N")], now=100.0)
    head = await store.claim_next_fifo("OB1", now=200.0)
    assert head is not None and head.payload == "N"
    # A second poll well before the lease expires: nothing reclaimed, nothing re-claimed (the inflight
    # head still holds its future lease, so the expired-lease reclaim matches nothing).
    again = await store.claim_next_fifo("OB1", now=200.0 + _ttl(store) - 1.0)
    assert again is None
    row = await _queue_row(store, head.id)
    assert row["status"] == OutboxStatus.INFLIGHT.value  # still held by the live node
    assert row["owner"] == store._owner


async def _queue_columns(store) -> set[str]:
    async with store._pool.acquire() as conn:
        return {
            r["column_name"]
            for r in await conn.fetch(
                "SELECT column_name FROM information_schema.columns WHERE table_name='queue'"
            )
        }


async def test_schema_migration_adds_lease_columns(store) -> None:
    """The guarded migration (_migrate_lease_columns) adds the lease columns to a pre-existing Step-1
    `queue` table that lacks them.

    This genuinely drives the ADD COLUMN branch: we drop the columns to recreate the pre-Step-1 shape,
    re-run the migration, then assert the columns reappear and a claim can stamp them. (The fixture DB
    already has the columns from CREATE TABLE, so without first dropping them the ALTER path would be
    unexercised — deleting the migration would still pass.)"""
    # Drop the lease columns to simulate a Step-1 table that predates them. A real Step-1 database
    # also predates the ADR 0064 schema_meta marker, so the simulation must delete it too — with a
    # current marker _ensure_schema would (correctly) fast-path and never reach the migration.
    async with store._pool.acquire() as conn:
        await conn.execute("ALTER TABLE queue DROP COLUMN owner, DROP COLUMN lease_expires_at")
        await conn.execute("DELETE FROM schema_meta")
    assert {"owner", "lease_expires_at"}.isdisjoint(await _queue_columns(store))

    # Re-run the schema migration (runs the guarded ADD COLUMN under the schema advisory lock).
    assert await store._ensure_schema() is True  # pre-marker DB: the full batch really ran

    # The columns are restored...
    assert {"owner", "lease_expires_at"} <= await _queue_columns(store)
    # ...and a claim successfully writes them.
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    item = (await store.claim_ready(now=200.0))[0]
    row = await _queue_row(store, item.id)
    assert row["owner"] == store._owner and row["lease_expires_at"] is not None


async def test_schema_migration_is_idempotent_when_columns_present(store) -> None:
    """Re-running the migration against an already-migrated table is a no-op that leaves the columns in
    place (the information_schema guard means no ALTER fires). The marker is deleted first so the run
    actually reaches _migrate_lease_columns — with it current, the ADR 0064 fast-path would skip the
    batch and this test would stop exercising the guard its docstring pins."""
    assert {"owner", "lease_expires_at"} <= await _queue_columns(store)
    async with store._pool.acquire() as conn:
        await conn.execute("DELETE FROM schema_meta")
    assert await store._ensure_schema() is True  # full run: guarded ADD COLUMN must not fire/error
    assert {"owner", "lease_expires_at"} <= await _queue_columns(store)


async def test_reset_stale_inflight_still_unconditional(store) -> None:
    """reset_stale_inflight stays unconditional: it recovers ALL inflight rows regardless of lease,
    including one whose lease is still in the future (single-node startup recovery is unchanged).
    The recovered (now-pending) row also has its lease metadata cleared."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    claimed = (await store.claim_ready(now=200.0))[0]
    # Lease is well in the future; an expiry-gated reclaim would skip it...
    assert await store.reclaim_expired_leases(now=200.0) == 0
    # ...but the unconditional startup reset recovers it anyway.
    recovered = await store.reset_stale_inflight(now=200.0)
    assert recovered == 1
    row = await _queue_row(store, claimed.id)
    assert row["status"] == OutboxStatus.PENDING.value
    # The recovery transition clears the stale owner/lease (parity with reclaim_expired_leases).
    assert row["owner"] is None and row["lease_expires_at"] is None


async def test_reclaim_expired_leases_no_expired_returns_zero(store) -> None:
    """The zero-row command-tag path: a sweep before any lease has expired reclaims nothing."""
    # Nothing inflight at all.
    assert await store.reclaim_expired_leases(now=100.0) == 0
    # An inflight row whose lease is still in the future — not yet reclaimable.
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    await store.claim_ready(now=200.0)
    assert await store.reclaim_expired_leases(now=201.0) == 0


async def test_inflight_exit_clears_lease_metadata(store) -> None:
    """A row leaving inflight clears owner/lease_expires_at so the documented 'NULL while
    pending/terminal' invariant holds: mark_done (→done), dead_letter_now (→dead), and
    mark_failed (→pending) all leave a clean row."""
    # mark_done → done
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    done = (await store.claim_ready(now=200.0, destination_name="OB1"))[0]
    await store.mark_done(done.id, now=210.0)
    r = await _queue_row(store, done.id)
    assert r["status"] == OutboxStatus.DONE.value
    assert r["owner"] is None and r["lease_expires_at"] is None

    # dead_letter_now → dead
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB2", "p")], now=100.0)
    dead = (await store.claim_ready(now=200.0, destination_name="OB2"))[0]
    await store.dead_letter_now(dead.id, "boom", now=210.0)
    r = await _queue_row(store, dead.id)
    assert r["status"] == OutboxStatus.DEAD.value
    assert r["owner"] is None and r["lease_expires_at"] is None

    # mark_failed → pending (retry not exhausted)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB3", "p")], now=100.0)
    failed = (await store.claim_ready(now=200.0, destination_name="OB3"))[0]
    await store.mark_failed(failed.id, "transient", RetryPolicy(max_attempts=3), now=210.0)
    r = await _queue_row(store, failed.id)
    assert r["status"] == OutboxStatus.PENDING.value
    assert r["owner"] is None and r["lease_expires_at"] is None


# --- cluster coordinator (Track B Step 3; Postgres-only DbCoordinator) ---------
#
# These run against the same gated Postgres container as the lease tests. The `store` fixture already
# TRUNCATEs the queue/messages tables, but NOT a `nodes` table (it didn't exist in Step 2), so each
# test cleans `nodes` itself for hermeticity in the shared DB.


async def _nodes_table_exists(store) -> bool:
    async with store._pool.acquire() as conn:
        return bool(
            await conn.fetchval(
                "SELECT to_regclass('nodes') IS NOT NULL"  # NULL when the table doesn't exist
            )
        )


async def _node_row(store, node_id: str):
    async with store._pool.acquire() as conn:
        return await conn.fetchrow(
            "SELECT host, pid, started_at, last_seen, status FROM nodes WHERE node_id=$1", node_id
        )


async def _drop_nodes(store) -> None:
    # Clear BOTH lazily-created coordinator tables for a clean slate. `leader_lease` is NOT in the
    # per-test TRUNCATE (_TABLES) — it is created on demand by a coordinator's start() — so without
    # dropping it here a prior test's lease row (default TTL 30s, >> the 2s election window) survives
    # into the next leader-election test and blocks acquisition, surfacing as "neither node is leader".
    # The next start() recreates both via _ensure_nodes_table.
    async with store._pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS nodes")
        await conn.execute("DROP TABLE IF EXISTS leader_lease")


async def _wait_leader(coord, *, want: bool, timeout: float = 2.0) -> None:
    """Poll the cheap cached is_leader() gate until it reaches ``want`` (election is acquired on the
    coordinator's maintenance tick, so it is eventually-consistent, not instant after start())."""
    import asyncio

    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if coord.is_leader() is want:
            return
        await asyncio.sleep(0.02)
    assert coord.is_leader() is want, f"is_leader did not become {want} within {timeout}s"


async def test_db_coordinator_registers_heartbeats_and_deregisters(store) -> None:
    """start() creates the nodes table + inserts this node's row; the heartbeat advances last_seen;
    stop() marks the node left; re-start() is idempotent (no duplicate row, no DDL error)."""
    from messagefoundry.pipeline.cluster import DbCoordinator

    await _drop_nodes(store)
    coord = DbCoordinator(store._pool, "node-X", heartbeat_seconds=0.05)
    try:
        await coord.start()
        assert await _nodes_table_exists(store)
        row = await _node_row(store, "node-X")
        assert row is not None and row["status"] == "active"
        first_seen = row["last_seen"]

        # Advance the heartbeat deterministically (the discrete coroutine, no sleep race).
        await coord.heartbeat_once()
        bumped = (await _node_row(store, "node-X"))["last_seen"]
        assert bumped >= first_seen

        # Leader election (Step 4): the sole node acquires leadership on its maintenance tick.
        await _wait_leader(coord, want=True)
    finally:
        await coord.stop()
        # After stop() the node has released the leader lock and dropped its dedicated connection.
        assert coord.is_leader() is False

    # stop() marked the node left, not deleted (a clean-shutdown tombstone).
    left = await _node_row(store, "node-X")
    assert left is not None and left["status"] == "left"

    # Re-running start() is idempotent: re-activates the same single row, no DDL error.
    coord2 = DbCoordinator(store._pool, "node-X", heartbeat_seconds=0.05)
    try:
        await coord2.start()
        async with store._pool.acquire() as conn:
            count = await conn.fetchval("SELECT COUNT(*) FROM nodes WHERE node_id=$1", "node-X")
        assert count == 1
        assert (await _node_row(store, "node-X"))["status"] == "active"
    finally:
        await coord2.stop()
        await _drop_nodes(store)


async def test_db_coordinator_stop_safe_before_start(store) -> None:
    """stop() is safe even if start() never ran (nothing to cancel; the mark-left UPDATE is a no-op
    against a missing/absent table guarded by its own try/except)."""
    from messagefoundry.pipeline.cluster import DbCoordinator

    await _drop_nodes(store)
    coord = DbCoordinator(store._pool, "node-Y", heartbeat_seconds=0.05)
    await coord.stop()  # must not raise


async def test_build_coordinator_postgres_enabled_returns_db_coordinator(store) -> None:
    """On an enabled [cluster] Postgres store, the factory returns a DbCoordinator whose node-id
    defaults to the store's lease owner-id (node-id == owner-id invariant for Steps 4/5)."""
    from messagefoundry.config.settings import ClusterSettings
    from messagefoundry.pipeline.cluster import DbCoordinator, build_coordinator

    coord = build_coordinator(store, ClusterSettings(enabled=True))
    assert isinstance(coord, DbCoordinator)
    assert coord.node_id == store._owner  # reuses _owner when [cluster].node_id is unset

    # An explicit node_id override wins over the store owner.
    pinned = build_coordinator(store, ClusterSettings(enabled=True, node_id="pinned-node"))
    assert isinstance(pinned, DbCoordinator) and pinned.node_id == "pinned-node"


# --- leader election (Track B Step 4; real session-level advisory lock) --------


async def test_db_coordinator_single_leader_and_failover(store) -> None:
    """Two coordinators on the same DB (distinct node-ids): exactly ONE becomes leader. When the
    leader stops (releasing its session-level advisory lock), the surviving follower acquires
    leadership on its next maintenance tick."""
    from messagefoundry.pipeline.cluster import DbCoordinator

    await _drop_nodes(store)
    a = DbCoordinator(store._pool, "node-A", heartbeat_seconds=0.05)
    b = DbCoordinator(store._pool, "node-B", heartbeat_seconds=0.05)
    try:
        await a.start()
        await b.start()
        # Give both a few ticks to contend; exactly one holds the lock (the winner is non-deterministic).
        import asyncio

        deadline = asyncio.get_event_loop().time() + 2.0
        while asyncio.get_event_loop().time() < deadline:
            if a.is_leader() ^ b.is_leader():  # exactly one leader
                break
            await asyncio.sleep(0.02)
        assert a.is_leader() ^ b.is_leader(), "exactly one of the two nodes must be leader"

        leader, follower = (a, b) if a.is_leader() else (b, a)
        assert follower.is_leader() is False

        # Stop the leader → it releases the advisory lock; the follower takes over on its next tick.
        await leader.stop()
        await _wait_leader(follower, want=True)
        assert follower.is_leader() is True
        # The stopped leader left a clean-shutdown tombstone (status='left'), and a clean stop also
        # demotes its cached gate — it must not still report itself leader after handover.
        assert leader.is_leader() is False
        stopped_row = await _node_row(store, leader.node_id)
        assert stopped_row is not None and stopped_row["status"] == "left"
    finally:
        await a.stop()
        await b.stop()
        await _drop_nodes(store)


async def test_db_coordinator_cluster_members_lists_both_and_derives_leader(store) -> None:
    """Track B Step 7: two coordinators on one DB → cluster_members() lists BOTH nodes, exactly one has
    is_leader=true (the advisory-lock holder, whose leadership the heartbeat folds into nodes.is_leader),
    and the derived leader matches. Mirrors the Step-4 two-node election harness + nodes-table cleanup."""
    import asyncio

    from messagefoundry.pipeline.cluster import DbCoordinator

    await _drop_nodes(store)
    a = DbCoordinator(store._pool, "node-A", heartbeat_seconds=0.05)
    b = DbCoordinator(store._pool, "node-B", heartbeat_seconds=0.05)
    try:
        await a.start()
        await b.start()
        # Give both a few ticks to contend AND to fold their leadership into the heartbeat flag (the
        # heartbeat runs before the election tick, so the flag lands the beat AFTER leadership is won).
        deadline = asyncio.get_event_loop().time() + 2.0
        while asyncio.get_event_loop().time() < deadline:
            members = await a.cluster_members()
            if len(members) == 2 and sum(1 for m in members if m.is_leader) == 1:
                break
            await asyncio.sleep(0.05)

        members = await a.cluster_members()
        # BOTH nodes are listed (stable order by node_id), and the derived leader is the lock holder.
        assert [m.node_id for m in members] == ["node-A", "node-B"]
        leaders = [m.node_id for m in members if m.is_leader]
        assert len(leaders) == 1, "exactly one node must derive as leader"
        expected = a.node_id if a.is_leader() else b.node_id
        assert leaders[0] == expected
        # Liveness is populated for real nodes (unlike the single-node synthetic entry).
        for m in members:
            assert m.status == "active"
            assert m.last_seen is not None and m.started_at is not None
            assert m.host is not None and m.pid is not None
    finally:
        await a.stop()
        await b.stop()
        await _drop_nodes(store)


async def test_db_coordinator_cluster_members_freshness_filters_stale_leader(store) -> None:
    """Track B Step 7: a crashed ex-leader leaves is_leader=true in its row (a hard crash skips the
    clean-shutdown clear). cluster_members() must NOT report it as the live leader — the freshness filter
    (last_seen within node_timeout_seconds) discards the stale flag. Simulate the crash residue directly
    in the table (an old last_seen + is_leader=true) so no live node currently leads."""
    from messagefoundry.pipeline.cluster import DbCoordinator

    await _drop_nodes(store)
    # A short node_timeout so an old last_seen is unambiguously stale.
    coord = DbCoordinator(
        store._pool, "node-fresh", heartbeat_seconds=0.05, node_timeout_seconds=1.0
    )
    try:
        await coord.start()
        # Ensure the table exists, then inject a stale ex-leader row: is_leader=true but last_seen long ago.
        async with store._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO nodes (node_id, host, pid, started_at, last_seen, status, is_leader) "
                "VALUES ($1,$2,$3,$4,$5,$6,TRUE)",
                "node-crashed",
                "h",
                999,
                1.0,
                1.0,  # epoch ~1970 → far outside node_timeout_seconds
                "active",
            )
        members = {m.node_id: m for m in await coord.cluster_members()}
        assert set(members) == {"node-fresh", "node-crashed"}
        # The stale ex-leader's is_leader flag is filtered out (not fresh) → it is NOT a reported leader.
        assert members["node-crashed"].is_leader is False
    finally:
        await coord.stop()
        await _drop_nodes(store)


async def test_db_coordinator_cluster_members_failover_overlap_single_live_leader(store) -> None:
    """Track B Step 7: the failover window. A just-crashed ex-leader's row is STILL fresh (recent but
    frozen last_seen) and still carries is_leader=true, while a newly-promoted node has already folded
    is_leader=true into its own (advancing) heartbeat. Both rows are fresh-and-flagged, so a
    freshness-filter-only derivation would report TWO leaders — and could name the dead node if it sorts
    first. cluster_members() must instead report EXACTLY ONE leader, the live (freshest) one."""
    import asyncio
    import time as _time

    from messagefoundry.pipeline.cluster import DbCoordinator

    await _drop_nodes(store)
    # Generous node_timeout so the injected ex-leader's slightly-old last_seen still counts as fresh
    # (this is the overlap window, not the stale-discard case the previous test covers).
    coord = DbCoordinator(
        store._pool, "node-new", heartbeat_seconds=0.05, node_timeout_seconds=30.0
    )
    try:
        await coord.start()
        await _wait_leader(coord, want=True)  # the live node wins the lock and folds the flag in
        # Inject a crashed ex-leader whose flag is still set and whose last_seen is recent enough to be
        # "fresh" but a little BEHIND the live node's still-advancing heartbeat. 'node-crashed' sorts
        # before 'node-new', so a naive ORDER BY pick would wrongly name the dead node.
        async with store._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO nodes (node_id, host, pid, started_at, last_seen, status, is_leader) "
                "VALUES ($1,$2,$3,$4,$5,$6,TRUE)",
                "node-crashed",
                "h",
                999,
                _time.time(),
                _time.time() - 5.0,  # recent → still within the 30s freshness window
                "active",
            )
        # Give the live node a couple of beats so its last_seen is unambiguously newer than the frozen
        # ex-leader's, then derive membership.
        await asyncio.sleep(0.2)
        members = {m.node_id: m for m in await coord.cluster_members()}
        assert set(members) == {"node-new", "node-crashed"}
        leaders = [n for n, m in members.items() if m.is_leader]
        assert leaders == ["node-new"], (
            "exactly one derived leader, the live (freshest) node — not the still-fresh crashed ex-leader"
        )
    finally:
        await coord.stop()
        await _drop_nodes(store)


async def test_leader_maintenance_sweep_reclaims_expired_lease(store) -> None:
    """The engine's leader sweep path end-to-end against the real store: an inflight row with an
    EXPIRED lease is returned to 'pending' by LeaderMaintenanceRunner.sweep_once() when the
    coordinator is the leader (reusing reclaim_expired_leases semantics)."""
    from messagefoundry.pipeline.cluster import DbCoordinator
    from messagefoundry.pipeline.leader_tasks import LeaderMaintenanceRunner

    await _drop_nodes(store)
    # Seed an inflight row: claim at now=100 stamps lease_expires_at = 100 + lease_ttl (default 60).
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    item = (await store.claim_ready(now=100.0))[0]
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.INFLIGHT.value

    coord = DbCoordinator(store._pool, "node-sweep", heartbeat_seconds=0.05)
    try:
        await coord.start()
        await _wait_leader(coord, want=True)
        runner = LeaderMaintenanceRunner(store, coord, interval_seconds=10.0)
        # now well past the lease expiry (160) → the expired-lease row is reclaimed to pending.
        reclaimed = await runner.sweep_once(now=10_000.0)
        assert reclaimed == 1
        row = (await store.outbox_for(item.message_id))[0]
        assert row["status"] == OutboxStatus.PENDING.value
        assert row["owner"] is None and row["lease_expires_at"] is None
    finally:
        await coord.stop()
        await _drop_nodes(store)


# --- config-reload version token (Track B Step 6; cluster_config single-row table) -----


async def test_db_coordinator_config_version_bump_and_round_trip(store) -> None:
    """bump_config_version increments and persists the single cluster_config row (id=1); a second
    coordinator/handle on the same DB reads the bumped value. is_clustered()/config_version round-trip."""
    from messagefoundry.pipeline.cluster import DbCoordinator

    a = DbCoordinator(store._pool, "node-A")
    b = DbCoordinator(store._pool, "node-B")
    # A fresh DB initializes to version 0 (the INSERT ... ON CONFLICT bootstraps the row).
    assert a.is_clustered() is True
    assert await a.config_version() == 0
    # Bumping increments and persists; the new value is cached for the cheap sync read.
    assert await a.bump_config_version() == 1
    assert a.config_version_cached() == 1
    assert await a.bump_config_version() == 2

    # A SECOND coordinator handle reads the persisted, bumped value (shared via the single row).
    assert await b.config_version() == 2
    assert b.config_version_cached() == 2

    # The single row is exactly id=1 (single-row invariant).
    async with store._pool.acquire() as conn:
        rows = await conn.fetch("SELECT id, config_version FROM cluster_config")
    assert len(rows) == 1 and rows[0]["id"] == 1 and rows[0]["config_version"] == 2


# --- EF-3: summary + metadata (MRN + patient name) encrypted at rest ---------


async def test_summary_metadata_encrypted_at_rest_and_decrypt(store) -> None:
    """EF-3: summary/metadata (direct MRN + patient name) are ciphered at rest on Postgres and
    decrypt on the detail + tracking-list read paths — parity with the SQLite suite."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import PREFIX, AesGcmCipher
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    summary, metadata = "MRN=999001 NAME=DOE^JANE", '{"site": "WESTWING"}'
    s = await PostgresStore.open(settings, cipher=AesGcmCipher(b"k" * 32))
    try:
        mid = await s.enqueue_message(
            channel_id="IB", raw=RAW, deliveries=[("OB", "p")], summary=summary, metadata=metadata
        )
        # at rest: ciphertext, with no MRN/name/site visible in the blob.
        row = await s._fetchone("SELECT summary, metadata FROM messages WHERE id=$1", mid)
        assert row["summary"].startswith(PREFIX) and "999001" not in row["summary"]
        assert row["metadata"].startswith(PREFIX) and "WESTWING" not in row["metadata"]
        # decrypt on the read paths.
        rec = await s.get_message(mid)
        assert rec["summary"] == summary and rec["metadata"] == metadata
        assert any(
            m["summary"] == summary and m["metadata"] == metadata for m in await s.list_messages()
        )
    finally:
        await s.close()


# --- H2: outbound idempotency ledger parity (gated) --------------------------------------------


async def _pg_ledger(store) -> list[dict]:
    rows = await store._fetchall("SELECT * FROM delivered_keys ORDER BY delivery_seq")
    return [dict(r) for r in rows]


async def test_mark_done_writes_one_ledger_row_pg(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], control_id="MSG1", now=100.0
    )
    item = await store.claim_next_fifo("OB1", now=200.0)
    assert item is not None
    await store.mark_done(item.id, now=300.0)
    rows = await _pg_ledger(store)
    assert len(rows) == 1
    assert rows[0]["outbox_id"] == item.id and rows[0]["delivery_seq"] == 1
    assert "p1" not in str(rows[0].values()) and "MSH" not in str(rows[0].values())
    assert len(rows[0]["delivery_key"]) == 64
    assert mid


async def test_claim_skips_already_delivered_head_no_resend_pg(store) -> None:
    # Deliver → ledger + DONE; re-pend the DONE row (failover / post-commit reset) WITHOUT clearing the
    # ledger; the next claim skip-and-completes it in place (None) — no re-send, still exactly one row.
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], now=100.0
    )
    item = await store.claim_next_fifo("OB1", now=200.0)
    assert item is not None
    await store.mark_done(item.id, now=300.0)
    assert len(await _pg_ledger(store)) == 1
    async with store._pool.acquire() as conn:
        await conn.execute(
            "UPDATE queue SET status=$1 WHERE id=$2", OutboxStatus.PENDING.value, item.id
        )
    assert await store.claim_next_fifo("OB1", now=400.0) is None  # dup head completed in place
    outbox = await store.outbox_for(mid)
    assert outbox[0]["status"] == OutboxStatus.DONE.value
    assert len(await _pg_ledger(store)) == 1
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_crash_re_run_mark_done_is_idempotent_pg(store) -> None:
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], now=100.0)
    item = await store.claim_next_fifo("OB1", now=200.0)
    assert item is not None
    await store.mark_done(item.id, now=300.0)
    await store.mark_done(item.id, now=301.0)  # re-run after crash → no duplicate ledger row
    assert len(await _pg_ledger(store)) == 1


async def test_replay_resend_not_deduped_pg(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], now=100.0
    )
    item = await store.claim_next_fifo("OB1", now=200.0)
    assert item is not None
    await store.mark_done(item.id, now=300.0)
    assert len(await _pg_ledger(store)) == 1
    assert await store.replay(mid, now=400.0) == 1  # re-send drops the ledger entry
    assert await _pg_ledger(store) == []
    again = await store.claim_next_fifo("OB1", now=500.0)
    assert again is not None and again.id == item.id  # claimed normally, NOT deduped
    await store.mark_done(again.id, now=600.0)
    assert len(await _pg_ledger(store)) == 1


# --- pass-through (PT) re-ingress parity (mirrors tests/test_passthrough.py, ADR 0013) ---
#
# The atomic PT branch inside transform_handoff (a Send into an internal PT inbound re-ingresses the
# body as a new INGRESS child + stamps the parent's terminal marker) is implemented at full SQLite
# parity here (supports_pt_reingress=True). These drive the real staged flow (enqueue_ingress →
# route_handoff → transform_handoff) to land an INFLIGHT routed row, then exercise the PT branch.


async def _pg_seed_routed(
    store,
    *,
    channel_id: str = "IB_REAL",
    raw: str = "MSH|payload",
    metadata: str | None = None,
    now: float = 100.0,
):
    """A message at the ROUTED stage with a single INFLIGHT routed row (as the transform worker would
    have claimed it), ready for a transform_handoff. Returns (message_id, routed_id)."""
    mid = await store.enqueue_ingress(channel_id=channel_id, raw=raw, metadata=metadata, now=now)
    ingress = await store.claim_next_fifo(channel_id, now=now + 1, stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id=channel_id,
        handlers=[("h1", raw)],
        disposition=MessageStatus.ROUTED,
        now=now + 2,
    )
    routed_item = await store.claim_next_fifo(channel_id, now=now + 3, stage=Stage.ROUTED.value)
    assert routed_item is not None
    return mid, routed_item.id


async def test_pt_handoff_produces_child_and_parent_processed_pg(store) -> None:
    import json

    parent, routed = await _pg_seed_routed(store, now=100.0)
    ok = await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        now=110.0,
    )
    assert ok is True
    # Parent: PROCESSED (a done PT marker row, no in-flight rows) — NOT FILTERED.
    pmsg = await store.get_message(parent)
    assert pmsg is not None and pmsg["status"] == MessageStatus.PROCESSED.value
    # Child: a distinct message on the PT channel, RECEIVED, correlated, with a pending INGRESS row.
    msgs = await store.list_messages(channel_id="PT_NEXT")
    assert len(msgs) == 1
    child = msgs[0]
    assert child["id"] != parent
    assert child["status"] == MessageStatus.RECEIVED.value
    assert child["source_type"] == "passthrough"
    full = await store.get_message(child["id"])
    assert full is not None and full["raw"] == "MSH|child"
    meta = json.loads(full["metadata"])
    assert meta["correlation_id"] == parent
    assert meta["correlation_root_id"] == parent
    assert meta["correlation_depth"] == 1
    assert meta["passthrough_from"] == parent
    depth, _ = await store.pending_depth("PT_NEXT", stage=Stage.INGRESS.value)
    assert depth == 1


async def test_pt_child_id_is_content_addressed_pg(store) -> None:
    parent, routed = await _pg_seed_routed(store, now=100.0)
    await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        now=110.0,
    )
    from messagefoundry.store.store import MessageStore

    expected = MessageStore._passthrough_message_id(routed, "PT_NEXT", "MSH|child")
    assert (await store.list_messages(channel_id="PT_NEXT"))[0]["id"] == expected


async def test_pt_plus_outbound_in_one_handler_pg(store) -> None:
    parent, routed = await _pg_seed_routed(store, now=100.0)
    ok = await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[("OB_REAL", "MSH|out")],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        now=110.0,
    )
    assert ok is True
    # The real outbound row is pending → parent not yet finalized (stays ROUTED until delivery).
    depth_out, _ = await store.pending_depth("OB_REAL", stage=Stage.OUTBOUND.value)
    assert depth_out == 1
    assert (await store.get_message(parent))["status"] == MessageStatus.ROUTED.value
    # The PT child exists independently.
    assert len(await store.list_messages(channel_id="PT_NEXT")) == 1


async def test_pt_handoff_idempotent_rerun_pg(store) -> None:
    parent, routed = await _pg_seed_routed(store, now=100.0)
    assert await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        now=110.0,
    )
    # Routed row is gone → second call is a no-op (False), writes nothing.
    assert (
        await store.transform_handoff(
            routed_id=routed,
            message_id=parent,
            channel_id="IB_REAL",
            deliveries=[],
            pt_deliveries=[("PT_NEXT", "MSH|child")],
            now=120.0,
        )
        is False
    )
    assert len(await store.list_messages(channel_id="PT_NEXT")) == 1


async def test_pt_depth_cap_drops_child_and_errors_parent_pg(store) -> None:
    import json

    cap = 3
    parent, routed = await _pg_seed_routed(
        store,
        metadata=json.dumps({"correlation_depth": cap, "correlation_root_id": "root-1"}),
        now=100.0,
    )
    ok = await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        correlation_depth_cap=cap,
        now=110.0,
    )
    assert ok is True
    # No child produced; parent finalizes ERROR (the dead PT marker row).
    assert await store.list_messages(channel_id="PT_NEXT") == []
    pmsg = await store.get_message(parent)
    assert pmsg is not None and pmsg["status"] == MessageStatus.ERROR.value


async def test_pt_correlation_root_propagates_pg(store) -> None:
    import json

    parent, routed = await _pg_seed_routed(
        store,
        metadata=json.dumps(
            {"correlation_depth": 2, "correlation_root_id": "ROOT", "correlation_id": "mid-prev"}
        ),
        now=100.0,
    )
    await store.transform_handoff(
        routed_id=routed,
        message_id=parent,
        channel_id="IB_REAL",
        deliveries=[],
        pt_deliveries=[("PT_NEXT", "MSH|child")],
        now=110.0,
    )
    child_id = (await store.list_messages(channel_id="PT_NEXT"))[0]["id"]
    full = await store.get_message(child_id)
    assert full is not None
    meta = json.loads(full["metadata"])
    assert meta["correlation_root_id"] == "ROOT"
    assert meta["correlation_depth"] == 3
    assert meta["correlation_id"] == parent


async def test_pt_no_pt_is_byte_identical_pg(store) -> None:
    # Regression: empty pt_deliveries leaves the pre-feature path unchanged (normal FILTERED collapse).
    parent, routed = await _pg_seed_routed(store, now=100.0)
    assert await store.transform_handoff(
        routed_id=routed, message_id=parent, channel_id="IB_REAL", deliveries=[], now=110.0
    )
    pmsg = await store.get_message(parent)
    assert pmsg is not None and pmsg["status"] == MessageStatus.FILTERED.value


async def test_supports_pt_reingress_true_pg(store) -> None:
    assert store.supports_pt_reingress is True


# --- ADR 0064: schema-init fast-path -------------------------------------------


async def test_schema_fastpath_skips_and_reruns(store) -> None:
    """The ``schema_meta`` marker skips the DDL batch on a current DB; a missing marker (a pre-marker
    upgrade) or a stale hash (a future DDL edit) forces one full idempotent run that restores it."""
    assert await store._ensure_schema() is False  # marker current after open → skipped
    async with store._pool.acquire() as conn:
        await conn.execute("DELETE FROM schema_meta")
    assert await store._ensure_schema() is True  # pre-marker DB → full run, marker rewritten
    assert await store._ensure_schema() is False
    async with store._pool.acquire() as conn:
        await conn.execute("UPDATE schema_meta SET schema_hash='stale' WHERE id=1")
    assert await store._ensure_schema() is True  # hash mismatch (a DDL edit) → full run


async def test_mark_failed_returns_reschedule_time(store) -> None:
    """WS-C: the runner arms the per-lane retry wake on mark_failed's returned next_attempt_at —
    rescheduled → the epoch time; dead-lettered/missing → None (parity with the SQLite backend)."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    item = (await store.claim_ready(now=200.0))[0]
    next_at = await store.mark_failed(item.id, "transient", RetryPolicy(), now=1000.0)
    assert next_at == 1005.0  # attempts=1 → backoff 5.0 * 2**0
    assert await store.mark_failed("no-such-row", "x", RetryPolicy(), now=1000.0) is None
