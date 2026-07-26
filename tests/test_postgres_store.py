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

import asyncio
import base64
import json
import os
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest

from messagefoundry.config.models import ContentType, RetryPolicy, Validation
from messagefoundry.config.wiring import ConnectionSpec, ConnectorType, InboundConnection, Registry
from messagefoundry.parsing.binary import chunk_b64, is_doc_ref, parse_doc_ref
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import Peek
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.store import MessageStatus, OutboxStatus, Stage
from messagefoundry.store.content_search import make_spec
from messagefoundry.store.crypto import MARKER_PREFIX, cell_aad, generate_key, make_cipher

# A synthetic ADT carrying a (fake) MRN + name in PID — never real PHI.
_ADT_SEARCH = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN9001^^^H^MR||DOE^JANE\r"

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

# The AA acknowledgement MessageFoundry returns to RAW's inbound sender (ADR 0021 "Response Sent") — a
# synthetic ACK frame, never real PHI. Used to exercise record_ack_sent's at-rest PHI fail-safe.
_ACK_AA = "MSH|^~\\&|C|D|A|B|20260101||ACK^A01|MSG1|P|2.5.1\rMSA|AA|MSG1\r"

# Tables cleaned between tests (FK order: children before parents).
_TABLES = (
    "message_events",
    "audit_log",
    "audit_chain_meta",  # #190 audit-chain keying watermark — a keying test (CLI-23) sets it; leaving it
    #                      would fail-close a later keyless record_audit (poison across tests)
    "cipher_meta",  # ASVS 11.3.4 per-key GCM invocation counters (no FK)
    "connection_event",  # #46 lifecycle log (no FK) — ciphered `reason` rows else leak across runs
    #                      and break the key-rotation reencrypt scan (persistent contamination)
    "cluster_config",
    "message_attachment",  # #149 attachment linkage (no FK)
    "attachment_chunk",  # #149 attachment chunks (no FK)
    "attachment",  # #149 attachment headers (no FK)
    "queue",
    "response",
    "delivered_keys",
    "resend_log",  # ADR 0090 idempotency ledger (no FK) — STOREF-8/9 reuse keys across tests
    "alert_instance",  # #56 operator alert-state (no FK) — ALERT-19 lists ALL active rows
    "search_presets",  # ADR 0136 saved searches (no FK, so CASCADE never reaches it) — the ciphered
    #                    `criteria` is in the key-rotation reencrypt scan, and this suite asserts EXACT
    #                    rotate counts, so a preset left by one test miscounts an unrelated one
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
    # audit_chain_meta was truncated above; sync the in-memory keying watermark so this keyless fixture
    # handle never carries a stale watermark that would fail-close a later keyless record_audit (#190).
    s._audit_keyed_from = None
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


# Synthetic HL7 only — never real PHI. \xff makes the first body invalid UTF-8 (decode-error path); the
# second is valid UTF-8 with a NUL in a PID field (the post-decode guard / happy path).
_INGEST4_DECODE_ERR_NUL = b"MSH|^~\\&|S|F|R|F|20260101||ADT^A01|MSG1|P|2.5\rPID|1||X\x00Y\xff\r"
_INGEST4_HAPPY_NUL = b"MSH|^~\\&|S|F|R|F|20260101||ADT^A01|MSG1|P|2.5\rPID|1||X\x00Y\r"


def _ingest4_registry() -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name="IB_HL7",
            spec=ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


async def test_ingest4_nul_ingress_persists_error_row(store) -> None:
    # INGEST-4 (load-bearing): only PostgreSQL reproduces the accept-and-drop — a stored NUL is REJECTED
    # at asyncpg bind (DataError / SQLSTATE 22021), which pre-fix unwound out of _handle_inbound into the
    # transport's `except` and dropped the whole TCP connection with NO ERROR row (count-and-log violation,
    # CLAUDE.md §2). The fix dead-letters a NUL-bearing body BEFORE the store write, carrying the exact
    # bytes as ADR 0028 base64. Prove: the handler RETURNS NORMALLY (an AR NAK), the ERROR row PERSISTS,
    # raw is NUL-free mfb64, raw_bytes round-trips, and no asyncpg exception escapes — on every body.
    import asyncpg  # extra-gated; imported inside the (skip-guarded) test, never at module import

    from messagefoundry.parsing import RawMessage

    runner = RegistryRunner(_ingest4_registry(), store)
    ic = runner.registry.inbound["IB_HL7"]

    # Non-vacuity: on an UNENCRYPTED store (the default; mfenc base64 would otherwise be NUL-free) an
    # un-guarded NUL bind raises DataError/22021 — the exact failure the guard now prevents.
    if not store._cipher.encrypts:
        with pytest.raises(asyncpg.exceptions.DataError) as probe:
            await store.enqueue_ingress(channel_id="IB_PROBE", raw="a\x00b", message_type="hl7v2")
        assert getattr(probe.value, "sqlstate", None) == "22021"

    for body in (_INGEST4_DECODE_ERR_NUL, _INGEST4_HAPPY_NUL):
        before = {m["id"] for m in await store.list_messages(channel_id="IB_HL7")}
        ack = await runner._handle_inbound(ic, body)  # must NOT raise / drop the connection
        assert ack is not None and "MSA|AR" in ack  # AR NAK, not a dropped connection
        after = await store.list_messages(channel_id="IB_HL7")
        new = [m for m in after if m["id"] not in before]
        assert len(new) == 1  # exactly one ERROR row persisted for this body
        erow = new[0]
        assert erow["status"] == MessageStatus.ERROR.value
        raw = (await store.get_message(erow["id"]))["raw"]
        assert "\x00" not in raw and RawMessage(raw, "hl7v2").is_binary  # NUL-free mfb64 carriage
        assert RawMessage(raw, "hl7v2").raw_bytes == body  # exact bytes recoverable


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


# --- ADR 0021 "Response Sent" inbound ACK capture parity (MLLP-20) -----------------------------
# record_ack_sent's PHI fail-safe on the SERVER store — mirrors tests/test_ack_sent_store.py (SQLite):
# an AA body is stored ONLY when the store is encrypted and is ciphertext at rest; a NAK never stores a
# body; the ack_sent row surfaces under a sentinel destination without disturbing outbound reply order.


async def test_record_ack_sent_aa_body_encrypted_at_rest_pg(store) -> None:
    # (1) An AA ack_body is persisted only on an ENCRYPTED store, and on disk it is ciphertext: it
    # carries the v1 marker, is not the plaintext AA frame, and decrypts back to exactly it. A second,
    # ciphered handle is needed because the fixture store is the identity cipher (unencrypted) — mirrors
    # the existing at-rest encryption tests in this file.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import PREFIX
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    cipher = make_cipher(generate_key())  # held so we can assert the decrypt round-trip below
    s = await PostgresStore.open(settings, cipher=cipher)
    try:
        mid = await s.enqueue_message(channel_id="IB_X", raw=RAW, deliveries=[("d", "p")])
        await s.record_ack_sent(
            message_id=mid,
            inbound_name="IB_X",
            ack_body=_ACK_AA,
            ack_code="AA",
            ack_phase="ingest",
            outcome="accepted",
        )
        # correlate_response surfaces the ack_sent row and decrypts its body at the read boundary.
        ack = next(r for r in await s.correlate_response(mid) if r.kind == "ack_sent")
        assert ack.ack_code == "AA" and ack.ack_phase == "ingest"
        assert ack.body == _ACK_AA  # decrypted round-trip
        # Raw column read (the ciphered handle's _fetchone does NOT decrypt) → ciphertext on disk. Assert
        # the deterministic decrypt round-trip, NOT `"MSA" not in <b64>` (base64 can contain that run).
        disk = (
            await s._fetchone(
                "SELECT body FROM response WHERE message_id=$1 AND kind='ack_sent'", mid
            )
        )["body"]
        assert disk.startswith(PREFIX)  # stored under the encrypted marker, not in the clear
        assert disk != _ACK_AA
        assert cipher.decrypt(disk) == _ACK_AA  # and it genuinely encrypts the AA frame
    finally:
        await s.close()


async def test_record_ack_sent_nak_stores_no_body_pg(store) -> None:
    # (2) PHI fail-safe: a NAK passes ack_body=None → body is always NULL on disk (even on an ENCRYPTED
    # store), and the offending field value lives only in the safe_text-scrubbed detail. The ciphered
    # handle proves the NULL is the fail-safe itself, not merely the unencrypted-store behaviour.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings, cipher=make_cipher(generate_key()))
    try:
        mid = await s.enqueue_message(channel_id="IB_X", raw=RAW, deliveries=[("d", "p")])
        await s.record_ack_sent(
            message_id=mid,
            inbound_name="IB_X",
            ack_body=None,
            ack_code="AR",
            ack_phase="parse",
            outcome="rejected",
            detail=f"bad PID: {_ADT_SEARCH}",
        )
        ack = next(r for r in await s.correlate_response(mid) if r.kind == "ack_sent")
        assert ack.ack_code == "AR" and ack.body is None  # metadata captured, body never stored
        assert ack.detail is not None and "DOE" not in ack.detail  # safe_text-scrubbed (#120)
        # NULL at rest even though the store is encrypted (the encrypt-only-AA gate is body-specific).
        disk = (
            await s._fetchone(
                "SELECT body FROM response WHERE message_id=$1 AND kind='ack_sent'", mid
            )
        )["body"]
        assert disk is None
    finally:
        await s.close()


async def test_record_ack_sent_sentinel_disjoint_from_outbound_pg(store) -> None:
    # (3) The ack_sent row sorts under a sentinel destination (\x1fack:<inbound>) disjoint from every
    # real destination, so an outbound reply's per-destination ordering is untouched and the seqs are
    # kind-scoped. Runs on the default (unencrypted) fixture handle, which ALSO exercises the fail-safe
    # that an AA body is not stored in the clear on an unencrypted store.
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    item = (await store.claim_ready(now=200.0))[0]
    await store.complete_with_response(item.id, body="PARTNER-REPLY", outcome="accepted", now=300.0)
    await store.record_ack_sent(
        message_id=mid,
        inbound_name="IB",
        ack_body=_ACK_AA,
        ack_code="AA",
        ack_phase="ingest",
        outcome="accepted",
    )
    by_kind = {r.kind: r for r in await store.correlate_response(mid)}
    assert by_kind["response"].destination_name == "OB1"
    assert by_kind["response"].response_seq == 1  # outbound reply unaffected by the ack row
    assert by_kind["ack_sent"].destination_name.startswith("\x1fack:")
    assert by_kind["ack_sent"].response_seq == 1  # its own kind-scoped sequence
    assert by_kind["ack_sent"].body is None  # unencrypted store → AA body not stored in the clear
    # A second ack for the same message increments only the ack lane.
    await store.record_ack_sent(
        message_id=mid,
        inbound_name="IB",
        ack_body=None,
        ack_code="AA",
        ack_phase="ingest",
        outcome="accepted",
    )
    acks = [r for r in await store.correlate_response(mid) if r.kind == "ack_sent"]
    assert sorted(r.response_seq for r in acks) == [1, 2]


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


async def test_startup_attestation_tamper_evidence_chains_and_tees(
    store, tmp_path, monkeypatch
) -> None:
    # RBAC-16: engine tampering must fail-close AND land a hash-chained, off-box-teed startup_integrity
    # row (actor=None) on the REAL Postgres backend — proving the NULL-actor tamper row persists +
    # chain-verifies + tees here, not just on SQLite. Reuses the single-source contract from the D3 suite.
    from tests.test_startup_attestation import _assert_startup_attestation_tamper_evidence

    await _assert_startup_attestation_tamper_evidence(store, tmp_path, monkeypatch)


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


async def test_http_grant_deny_audit_precision(store) -> None:
    """RBAC-4 (ASVS 16.3.2) on the real Postgres backend: the HTTP ``require()`` grant/deny audit set is
    EXACT and the ``method != "GET"`` guard REFUSES to audit a sensitive-permission READ. Reuses the
    single source-of-truth helper from the SQLite suite so this live-server leg proves the deny/grant
    row is actually written by ``record_audit`` / read by ``list_audit`` on Postgres — not just SQLite."""
    from tests.test_auth_hardening import _assert_http_grant_deny_precision

    await _assert_http_grant_deny_precision(store)


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


async def test_all_declined_finalizes_not_deployed(store) -> None:
    """#233 (ADR 0111) parity: a routed message whose only handler declined every Send (each to a
    present-but-not-deployed target) finalizes NOT_DEPLOYED — not FILTERED — carries a ``not_deployed``
    event naming the connection, and queues ZERO outbound rows. The decline is persisted in the SAME
    handoff txn, so the finalizer distinguishes it from an intentional filter (spec §3.3)."""
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
        deliveries=[],
        declined=["OB_OFF"],
        now=140.0,
    )
    assert (await store.get_message(mid))["status"] == MessageStatus.NOT_DEPLOYED.value
    nd = [e["destination"] for e in await store.events_for(mid) if e["event"] == "not_deployed"]
    assert nd == ["OB_OFF"]
    assert await store.outbox_for(mid) == []  # AC-2: not one row in the outbound stage


async def test_declined_sibling_still_processed_event_retained(store) -> None:
    """#233 mixed parity: one deployed delivery + one declined leg → the message finalizes PROCESSED
    once the deployed leg delivers (it DID deliver somewhere — not NOT_DEPLOYED), and the
    ``not_deployed`` event for the skipped leg is still recorded."""
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
        deliveries=[("OB1", "body")],
        declined=["OB_OFF"],
        now=140.0,
    )
    out = await store.claim_next_fifo("OB1", now=150.0)
    await store.mark_done(out.id, now=160.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    nd = [e["destination"] for e in await store.events_for(mid) if e["event"] == "not_deployed"]
    assert nd == ["OB_OFF"]


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


async def test_reference_rows_rotate_on_reencrypt_to_active(store) -> None:
    """Key rotation (reencrypt_to_active) must rotate reference.value too (BACKLOG #235) — without
    the reference pass, a later retired-key drop silently loses every synced snapshot. Self-contained:
    the fixture's clean slate + only-reference writes make the rotation count exactly this snapshot's
    2 rows."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    k1, k2 = generate_key(), generate_key()
    # Entry cleanliness: the exact == 2 below assumes the fixture's clean slate held.
    assert await store._fetchall("SELECT name FROM reference") == []
    try:
        s1 = await PostgresStore.open(settings, cipher=make_cipher(k1))
        try:
            await s1.write_reference_snapshot(
                name="codes", version="v1", rows={"P1": {"mrn": "M-SECRET-1"}, "P2": "plain"}
            )
        finally:
            await s1.close()

        c2 = make_cipher(k2, [k1])
        assert isinstance(c2, AesGcmCipher)
        s2 = await PostgresStore.open(settings, cipher=c2)
        try:
            assert await s2.reencrypt_to_active() == 2  # exactly the two reference rows
            rows = await s2._fetchall("SELECT value FROM reference")
            assert len(rows) == 2
            for r in rows:
                # under the ACTIVE key now (mfenc:v1:<k2-fingerprint>:...), no plaintext PHI visible
                assert r["value"].startswith(c2.active_marker_prefix)
                assert "M-SECRET-1" not in r["value"]
            assert s2.reference_view()["codes"]["P1"] == {"mrn": "M-SECRET-1"}  # still decrypts
            assert await s2.reencrypt_to_active() == 0  # idempotent
        finally:
            await s2.close()

        # Proof the rows were actually rewritten: a handle with ONLY k2 (retired dropped) reads them.
        s3 = await PostgresStore.open(settings, cipher=make_cipher(k2))
        try:
            assert s3.reference_view()["codes"] == {"P1": {"mrn": "M-SECRET-1"}, "P2": "plain"}
        finally:
            await s3.close()
    finally:
        # Shared-DB hygiene (even on assertion failure): the CI suites share ONE database, and the
        # `store` fixture OPENS the store BEFORE its clean-slate TRUNCATE — reference rows left
        # encrypted under this test's own keys would crash the next (keyless) fixture open inside
        # _load_reference_cache (IdentityCipher passthrough -> json.loads of an mfenc blob),
        # cascading setup ERRORs across the rest of the run. Purge with a handle carrying BOTH keys
        # (rows sit under k1 or k2 depending on where a failure struck), raw DELETEs like the
        # fixture's TRUNCATE idiom.
        cleanup = await PostgresStore.open(settings, cipher=make_cipher(k2, [k1]))
        try:
            async with cleanup._pool.acquire() as conn:
                await conn.execute("DELETE FROM reference")
                await conn.execute("DELETE FROM reference_version")
        finally:
            await cleanup.close()


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


async def test_keyless_open_of_encrypted_reference_fails_closed(store) -> None:
    """#241 F2: a keyless open of a store carrying key-encrypted ``reference`` rows must fail closed
    with the operator-facing StoreKeylessError (naming the table + remedy), not a raw JSONDecodeError
    from an ``mfenc:`` blob reaching ``json.loads`` in ``_read_active_reference_snapshots``. The CI
    Postgres-store leg is the authoritative proof of this read seam."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import StoreKeylessError
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    k = generate_key()
    try:
        keyed = await PostgresStore.open(settings, cipher=make_cipher(k))
        try:
            await keyed.write_reference_snapshot(
                name="providers", version="v1", rows={"P1": {"mrn": "M-SECRET-REF"}}
            )
        finally:
            await keyed.close()

        with pytest.raises(StoreKeylessError) as ei:
            await PostgresStore.open(settings)  # keyless open of an encrypted store — fail closed
        assert "reference" in str(ei.value) and "MEFOR_STORE_ENCRYPTION_KEY" in str(ei.value)
    finally:
        # Shared-DB hygiene (even on assertion failure): purge the encrypted reference rows so the next
        # keyless fixture open does not itself fail-close inside _read_active_reference_snapshots.
        cleanup = await PostgresStore.open(settings, cipher=make_cipher(k))
        try:
            async with cleanup._pool.acquire() as conn:
                await conn.execute("DELETE FROM reference")
                await conn.execute("DELETE FROM reference_version")
        finally:
            await cleanup.close()


async def test_keyless_open_of_encrypted_state_fails_closed(store) -> None:
    """#241 F2: a keyless open of a store carrying key-encrypted ``state`` rows must fail closed with
    StoreKeylessError, not a raw JSONDecodeError nor a silent skip — a PHI hard rule. The CI
    Postgres-store leg is the authoritative proof of this read seam."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import StoreKeylessError
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    k = generate_key()
    try:
        keyed = await PostgresStore.open(settings, cipher=make_cipher(k))
        try:
            mid, routed = await _route_and_claim_routed(keyed, "IB", now=100.0)
            await keyed.transform_handoff(
                routed_id=routed.id,
                message_id=mid,
                channel_id="IB",
                deliveries=[("OB1", "x")],
                state_ops=[("ns", "k", {"mrn": "M-SECRET-STATE"})],
                now=110.0,
            )
            sealed = await keyed._fetchall("SELECT value FROM state")
            assert sealed and sealed[0]["value"].startswith(MARKER_PREFIX)  # ciphertext at rest
        finally:
            await keyed.close()

        with pytest.raises(StoreKeylessError) as ei:
            await PostgresStore.open(settings)  # keyless open — fail closed, not a silent skip
        assert "state" in str(ei.value) and "MEFOR_STORE_ENCRYPTION_KEY" in str(ei.value)
    finally:
        # Purge the encrypted state (+ the ingress message/queue rows) with a keyed handle so the next
        # keyless fixture open does not fail-close inside _load_state_cache.
        cleanup = await PostgresStore.open(settings, cipher=make_cipher(k))
        try:
            async with cleanup._pool.acquire() as conn:
                # NB: Postgres has no physical `outbox` table (the outbound stage lives in `queue`,
                # unlike SQL Server which does carry a real `outbox` table) — do not DELETE FROM outbox here.
                for table in ("message_events", "state", "response", "queue", "messages"):
                    await conn.execute(f"DELETE FROM {table}")
        finally:
            await cleanup.close()


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


async def test_reset_stale_inflight_owned_scopes_lanes_and_preserves_sibling_lease(store) -> None:
    """ADR 0073 ownership-scoped recovery: ``owned=OwnedLanes(...)`` re-pends ONLY the caller
    shard's lanes — its channels (ingress/routed/response lanes) + its rendezvous-owned outbound
    destinations — clearing owner/lease on exactly the rows it re-pends. A live sibling shard's
    inflight rows are untouched: still INFLIGHT **with their claim-stamped owner + lease intact**
    (Postgres stamps owner on claim; a sibling's scoped restart must never owner/lease-strip them
    the way the unconditional reset above deliberately does)."""
    from messagefoundry.store.store import OwnedLanes

    # Shard A's crash residue: an inflight ingress row on its channel IB_A + an inflight outbound
    # row on its owned lane OB_A.
    await store.enqueue_ingress(channel_id="IB_A", raw=RAW, now=100.0)
    ing_a = await store.claim_next_fifo("IB_A", now=110.0, stage=Stage.INGRESS.value)
    await store.enqueue_message(channel_id="IB_A", raw=RAW, deliveries=[("OB_A", "p")], now=100.0)
    out_a = await store.claim_next_fifo("OB_A", now=110.0)
    # Live sibling shard B, mid-flight on ITS lanes (same store handle → same owner id; the scoped
    # reset must discriminate by LANE, not by the claim-owner column).
    await store.enqueue_ingress(channel_id="IB_B", raw=RAW, now=100.0)
    ing_b = await store.claim_next_fifo("IB_B", now=115.0, stage=Stage.INGRESS.value)
    await store.enqueue_message(channel_id="IB_B", raw=RAW, deliveries=[("OB_B", "p")], now=100.0)
    out_b = await store.claim_next_fifo("OB_B", now=115.0)
    assert None not in (ing_a, out_a, ing_b, out_b)

    # Reset + re-claim run INSIDE the sibling's lease window (claimed at 115, ttl 60 → expires
    # 175): past it, the FIFO claim's own expired-lease stranded-head reclaim would legitimately
    # take B's head and muddy the "sibling untouched" assertion.
    owned_a = OwnedLanes(channels=frozenset({"IB_A"}), destinations=frozenset({"OB_A"}))
    recovered = await store.reset_stale_inflight(now=120.0, owned=owned_a)
    assert recovered == 2  # exactly shard A's ingress + outbound rows, despite 4 inflight total
    for row_id in (ing_a.id, out_a.id):
        row = await _queue_row(store, row_id)
        assert row["status"] == OutboxStatus.PENDING.value
        assert row["owner"] is None and row["lease_expires_at"] is None  # cleared on re-pend
    for row_id in (ing_b.id, out_b.id):
        row = await _queue_row(store, row_id)
        assert row["status"] == OutboxStatus.INFLIGHT.value  # sibling untouched...
        assert row["owner"] == store._owner  # ...owner survives the sibling's scoped reset
        assert row["lease_expires_at"] == pytest.approx(115.0 + _ttl(store))  # lease intact
    # The recovered lanes are claimable again at once; the sibling's heads are still held.
    again = await store.claim_next_fifo("IB_A", now=130.0, stage=Stage.INGRESS.value)
    assert again is not None and again.id == ing_a.id
    assert await store.claim_next_fifo("IB_B", now=130.0, stage=Stage.INGRESS.value) is None


async def test_reset_stale_inflight_owned_empty_sets_match_nothing(store) -> None:
    """An EMPTY owned set matches NOTHING for the stages it scopes (no statement, never ``IN ()``):
    recovering 'no lanes' must never widen into recovering 'all lanes'. Both inflight rows keep
    status AND owner/lease."""
    from messagefoundry.store.store import OwnedLanes

    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    ing = await store.claim_next_fifo("IB", now=110.0, stage=Stage.INGRESS.value)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    out = await store.claim_next_fifo("OB1", now=110.0)
    assert ing is not None and out is not None

    empty = OwnedLanes(channels=frozenset(), destinations=frozenset())
    assert await store.reset_stale_inflight(now=200.0, owned=empty) == 0
    for row_id in (ing.id, out.id):
        row = await _queue_row(store, row_id)
        assert row["status"] == OutboxStatus.INFLIGHT.value
        assert row["owner"] == store._owner
        assert row["lease_expires_at"] == pytest.approx(110.0 + _ttl(store))


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


async def test_config_convergence_runner_reloads_from_real_db(store) -> None:
    """HA-16 clause 2 (sibling reload propagation) over a REAL coordinator: a ConfigConvergenceRunner
    on node B converges when a SECOND coordinator A bumps the shared ``cluster_config`` token in the DB
    and B's cache is refreshed by an actual DB round-trip (the maintenance-tick path, cluster.py:786).

    The unit test in tests/test_cluster.py scripts ``config_version_cached`` on a fake coordinator; this
    exercises the full live chain the fake can't — A bumps the DB row → B refreshes its cache from the
    real DB → B's convergence runner reloads once and advances its applied version."""
    from messagefoundry.pipeline.cluster import DbCoordinator
    from messagefoundry.pipeline.config_convergence import ConfigConvergenceRunner

    a = DbCoordinator(store._pool, "node-A")
    b = DbCoordinator(store._pool, "node-B")
    # Seed both from the real DB: a fresh cluster_config initializes to 0, so neither node is behind.
    assert await a.config_version() == 0
    assert await b.config_version() == 0

    applied = {"v": 0}
    reloads: list[int] = []

    async def reload() -> None:
        # Convergence re-reads THIS node's own config dir; here we record the version B converged to.
        reloads.append(b.config_version_cached())

    runner = ConfigConvergenceRunner(
        b,
        applied_version=lambda: applied["v"],
        set_applied_version=lambda v: applied.__setitem__("v", v),
        reload=reload,
        interval_seconds=10.0,
    )
    # Caught up (0 == 0): no reload.
    assert await runner.converge_once() is False
    assert reloads == []

    # A real operator reload on node A bumps the shared token in the DB.
    assert await a.bump_config_version() == 1
    # B has NOT yet refreshed its cache from the DB, so its convergence poll still reads 0 → no reload.
    # (The cached poll is what gates convergence, so the DB bump alone does nothing until B's tick.)
    assert b.config_version_cached() == 0
    assert await runner.converge_once() is False
    assert reloads == []

    # B's maintenance tick refreshes the cached version from the REAL DB (the config_version() step).
    assert await b.config_version() == 1
    assert b.config_version_cached() == 1
    # Now B is behind → it reloads ONCE and advances applied to 1.
    assert await runner.converge_once() is True
    assert reloads == [1] and applied["v"] == 1
    # Caught up again → no second reload (idempotent, no feedback loop).
    assert await runner.converge_once() is False
    assert reloads == [1]


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


# --- #149 Phase 4: streaming attachment substrate parity (ADR 0105) ------------------------------
# Mirrors tests/test_attachment_substrate.py (the SQLite reference) against a real Postgres — same
# assertions as the SQL Server parity block: verbatim chunked round-trip, per-chunk seal at rest,
# content-address dedup, refcount incref/decref + GC, two-object ingress commit + rollback on a missing
# ref, retention decref + join-DELETE (idempotent, no shared-attachment underflow), the dead-row
# keeps/releases split (either purge order), fan-out single decref, below-threshold byte-identical, and
# the key-rotation re-seal.

import hashlib as _hashlib  # noqa: E402 - local to the attachment block, mirrors the SQLite suite

_A_CHUNKS = ["QUJDRA==part0::", "RUZHSA==part1::", "SUpLTA==part2::"]
_A_DOC = "".join(_A_CHUNKS)
_A_REF = _hashlib.sha256(_A_DOC.encode("utf-8")).hexdigest()
DAY = 86_400.0


async def _a_read(s, ref: str) -> list[str]:
    return [c async for c in s.read_attachment(ref)]


async def _a_refcount(s, ref: str) -> int | None:
    row = await s._fetchone("SELECT refcount FROM attachment WHERE id=$1", ref)
    return None if row is None else int(row["refcount"])


async def _a_chunks(s, ref: str) -> int:
    row = await s._fetchone(
        "SELECT COUNT(*) AS n FROM attachment_chunk WHERE attachment_id=$1", ref
    )
    return int(row["n"])


async def _a_joins(s, mid: str) -> int:
    row = await s._fetchone("SELECT COUNT(*) AS n FROM message_attachment WHERE message_id=$1", mid)
    return int(row["n"])


async def _a_row_payload(s, oid: str) -> str:
    row = await s._fetchone("SELECT payload FROM queue WHERE id=$1", oid)
    return str(row["payload"])


async def _a_detach_and_settle(s, *, now: float, ref: str) -> str:
    mid = await s.enqueue_ingress(channel_id="IB", raw="MSH|skel", attachment_refs=[ref], now=now)
    item = await s.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    await s.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        disposition=MessageStatus.FILTERED,
        now=now,
    )
    return mid


async def _a_dead_deliver(s, *, now: float, ref: str, dest: str = "OB_D") -> tuple[str, str]:
    mid = await s.enqueue_ingress(channel_id="IB", raw="MSH|skel", attachment_refs=[ref], now=now)
    item = await s.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    await s.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[(dest, "MSH|dead|mfdoc:v1:ref:doc")],
        disposition=MessageStatus.ROUTED,
        now=now,
    )
    [row] = await s.outbox_for(mid)
    await s.claim_ready(now=now)
    await s.dead_letter_now(row["id"], "permanent reject (AR)", now=now)
    return mid, row["id"]


async def test_attachment_put_read_roundtrip_verbatim(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    assert ref == _A_REF
    assert await _a_chunks(store, ref) == len(_A_CHUNKS)
    assert await _a_read(store, ref) == _A_CHUNKS
    assert "".join(await _a_read(store, ref)) == _A_DOC
    assert await _a_refcount(store, ref) == 0


async def test_attachment_read_missing_raises(store) -> None:
    with pytest.raises(KeyError):
        await _a_read(store, _A_REF)


async def test_attachment_dedups_identical_content(store) -> None:
    r1 = await store.put_attachment(_A_CHUNKS, "application/pdf")
    r2 = await store.put_attachment(_A_CHUNKS, "application/pdf")
    assert r1 == r2 == _A_REF
    assert await _a_chunks(store, r1) == len(_A_CHUNKS)
    row = await store._fetchone("SELECT COUNT(*) AS n FROM attachment WHERE id=$1", r1)
    assert int(row["n"]) == 1
    other = await store.put_attachment(["totally different"], "text/plain")
    assert other != r1


async def test_attachment_incref_decref_gc_at_zero(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    await store.attachment_incref(ref)
    await store.attachment_incref(ref)
    assert await _a_refcount(store, ref) == 2
    await store.attachment_decref(ref)
    assert await _a_refcount(store, ref) == 1
    assert await _a_read(store, ref) == _A_CHUNKS
    await store.attachment_decref(ref)
    assert await _a_refcount(store, ref) is None
    assert await _a_chunks(store, ref) == 0
    with pytest.raises(KeyError):
        await _a_read(store, ref)
    await store.attachment_decref(ref)  # tolerant no-op past zero


async def test_attachment_incref_missing_raises(store) -> None:
    with pytest.raises(KeyError):
        await store.attachment_incref("f" * 64)


async def test_attachment_startup_sweep_reclaims_orphans_and_incomplete(store) -> None:
    zero_ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    orphan_id = "a" * 64
    async with store._pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO attachment_chunk (attachment_id, seq, ciphertext) VALUES ($1,$2,$3)",
            orphan_id,
            0,
            store._cipher.encrypt("orphaned pdf bytes"),
        )
    live_ref = await store.put_attachment(["a live document"], "text/plain")
    await store.attachment_incref(live_ref)

    assert await store.sweep_orphan_attachments() == 2
    assert await _a_refcount(store, zero_ref) is None
    assert await _a_chunks(store, zero_ref) == 0
    assert await _a_chunks(store, orphan_id) == 0
    assert await _a_refcount(store, live_ref) == 1
    assert "".join(await _a_read(store, live_ref)) == "a live document"
    assert await store.sweep_orphan_attachments() == 0


async def test_attachment_ingress_two_object_commit(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    assert await _a_refcount(store, ref) == 0
    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|skel", attachment_refs=[ref])
    assert await _a_refcount(store, ref) == 1
    assert await _a_joins(store, mid) == 1
    row = await store._fetchone(
        "SELECT attachment_id FROM message_attachment WHERE message_id=$1", mid
    )
    assert row["attachment_id"] == ref


async def test_attachment_ingress_dedups_duplicate_refs(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    await store.enqueue_ingress(channel_id="IB", raw="skel", attachment_refs=[ref, ref])
    assert await _a_refcount(store, ref) == 1


async def test_attachments_for_returns_linked_metadata(store) -> None:
    # #149 Phase 3b operator read surface: attachments_for JOINs the linkage → header (metadata only).
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|skel", attachment_refs=[ref])
    rows = await store.attachments_for(mid)
    assert len(rows) == 1
    row = dict(rows[0])
    assert row["attachment_id"] == ref
    assert row["content_type"] == "application/pdf"
    assert row["total_bytes"] == len(_A_DOC.encode("utf-8"))
    # A message with no detached document → empty.
    plain = await store.enqueue_ingress(channel_id="IB", raw="MSH|plain")
    assert await store.attachments_for(plain) == []


async def test_attachment_ingress_missing_ref_rolls_back(store) -> None:
    with pytest.raises(KeyError):
        await store.enqueue_ingress(channel_id="IB", raw="skel", attachment_refs=["0" * 64])
    row = await store._fetchone("SELECT COUNT(*) AS n FROM messages")
    assert int(row["n"]) == 0


async def test_attachment_purge_decrefs_and_deletes_linkage(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid = await _a_detach_and_settle(store, now=0.0, ref=ref)
    assert await _a_refcount(store, ref) == 1

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (await store.get_message(mid))["raw"] == ""
    assert await _a_refcount(store, ref) is None
    assert await _a_chunks(store, ref) == 0
    assert await _a_joins(store, mid) == 0


async def test_attachment_shared_refcount_two_purge_each(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    m1 = await _a_detach_and_settle(store, now=0.0, ref=ref)
    m2 = await _a_detach_and_settle(store, now=20 * DAY, ref=ref)
    assert await _a_refcount(store, ref) == 2

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await _a_refcount(store, ref) == 1
    assert await _a_chunks(store, ref) == len(_A_CHUNKS)
    assert "".join(await _a_read(store, ref)) == _A_DOC
    assert await _a_joins(store, m1) == 0 and await _a_joins(store, m2) == 1

    assert await store.purge_message_bodies(older_than=30 * DAY) == 1
    assert await _a_refcount(store, ref) is None
    assert await _a_chunks(store, ref) == 0


async def test_attachment_double_purge_idempotent_no_underflow(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    m1 = await _a_detach_and_settle(store, now=0.0, ref=ref)
    m2 = await _a_detach_and_settle(store, now=20 * DAY, ref=ref)
    assert await _a_refcount(store, ref) == 2

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await store.purge_message_bodies(older_than=10 * DAY) == 0

    assert await _a_refcount(store, ref) == 1
    assert await _a_chunks(store, ref) == len(_A_CHUNKS)
    assert "".join(await _a_read(store, ref)) == _A_DOC
    assert await _a_joins(store, m1) == 0 and await _a_joins(store, m2) == 1


async def test_attachment_fanout_single_decref_at_purge(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid = await store.enqueue_ingress(
        channel_id="IB", raw="MSH|skel", attachment_refs=[ref], now=0.0
    )
    item = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "pa"), ("OB_B", "pb")],
        disposition=MessageStatus.ROUTED,
        now=0.0,
    )
    assert await _a_refcount(store, ref) == 1
    rows = await store.outbox_for(mid)
    assert len(rows) == 2
    await store.claim_ready(now=0.0)
    for r in rows:
        await store.mark_done(r["id"], now=0.0)
    assert await _a_refcount(store, ref) == 1

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await _a_refcount(store, ref) is None
    assert await _a_joins(store, mid) == 0


async def test_attachment_no_attachment_retention_byte_identical(store) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|plain", now=0.0)
    item = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        disposition=MessageStatus.FILTERED,
        now=0.0,
    )
    assert await _a_joins(store, mid) == 0
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (await store.get_message(mid))["raw"] == ""
    row = await store._fetchone("SELECT COUNT(*) AS n FROM message_attachment")
    assert int(row["n"]) == 0


async def test_attachment_release_standalone_and_idempotent(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|skel", attachment_refs=[ref])
    assert await _a_refcount(store, ref) == 1
    await store.release_message_attachments(mid)
    assert await _a_refcount(store, ref) is None
    assert await _a_joins(store, mid) == 0
    await store.release_message_attachments(mid)
    assert await _a_refcount(store, ref) is None


async def test_attachment_dead_row_keeps_through_body_purge(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid, oid = await _a_dead_deliver(store, now=0.0, ref=ref)
    assert await _a_refcount(store, ref) == 1

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (await store.get_message(mid))["raw"] == ""
    assert await _a_row_payload(store, oid) == "MSH|dead|mfdoc:v1:ref:doc"
    assert await _a_refcount(store, ref) == 1
    assert "".join(await _a_read(store, ref)) == _A_DOC


async def test_attachment_dead_purge_releases_after_body_purge(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid, oid = await _a_dead_deliver(store, now=0.0, ref=ref)
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await _a_refcount(store, ref) == 1

    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await _a_row_payload(store, oid) == ""
    assert await _a_refcount(store, ref) is None
    assert await _a_joins(store, mid) == 0


async def test_attachment_dead_purge_releases_when_run_first(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid, oid = await _a_dead_deliver(store, now=0.0, ref=ref)

    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await _a_row_payload(store, oid) == ""
    assert await _a_refcount(store, ref) is None
    assert await _a_joins(store, mid) == 0

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (await store.get_message(mid))["raw"] == ""
    assert await _a_refcount(store, ref) is None


async def test_attachment_dead_purge_idempotent_no_underflow(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    m1, _ = await _a_dead_deliver(store, now=0.0, ref=ref, dest="OB_1")
    m2, _ = await _a_dead_deliver(store, now=20 * DAY, ref=ref, dest="OB_2")
    assert await _a_refcount(store, ref) == 2

    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await store.purge_dead_letters(older_than=10 * DAY) == 0

    assert await _a_refcount(store, ref) == 1
    assert await _a_chunks(store, ref) == len(_A_CHUNKS)
    assert await _a_joins(store, m1) == 0 and await _a_joins(store, m2) == 1


async def test_attachment_chunks_sealed_at_rest_and_reseal_on_rotation(store) -> None:
    # The `store` fixture truncated the attachment tables → clean slate. Use dedicated keyed handles for
    # the seal/rotation round-trip (mirrors the SQLite reseal test on a persistent server DB).
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    k1, k2 = generate_key(), generate_key()

    s1 = await PostgresStore.open(settings, cipher=make_cipher(k1))
    try:
        ref = await s1.put_attachment(_A_CHUNKS, "application/pdf")
        rows = await s1._fetchall(
            "SELECT ciphertext FROM attachment_chunk WHERE attachment_id=$1 ORDER BY seq", ref
        )
        assert len(rows) == len(_A_CHUNKS)
        for r in rows:
            assert r["ciphertext"].startswith(MARKER_PREFIX)
        assert await _a_read(s1, ref) == _A_CHUNKS
    finally:
        await s1.close()

    s2 = await PostgresStore.open(settings, cipher=make_cipher(k2, [k1]))
    try:
        rotated = await s2.reencrypt_to_active()
        assert rotated >= len(_A_CHUNKS)
        assert await _a_read(s2, ref) == _A_CHUNKS
    finally:
        await s2.close()

    s3 = await PostgresStore.open(settings, cipher=make_cipher(k2))
    try:
        assert await _a_read(s3, ref) == _A_CHUNKS
        assert ref == _A_REF
    finally:
        await s3.close()


# --- STORE-4: runner-level ACK-on-receipt + post-ingress no-NAK on the real backend ----------
# Drives the runner's real AA-emitting path (_handle_inbound) + _process_ingress_item against THIS
# file's real backend `store` fixture — no `.start()`, no socket (port=0 never binds). The SQLite
# suites cover the AA-after-commit tie and the FILE-source post-ingress path; these pin them on the
# reply-capable (MLLP) path against PG. Gated like every test here; a green leg confirms the design.


def _mllp_inbound_registry(name: str, route) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name,
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
        )
    )
    reg.add_router("r", route)
    return reg


async def test_mllp_inbound_commits_ingress_before_aa(store) -> None:
    # ACK-on-receipt tie: _handle_inbound builds the AA only AFTER enqueue_ingress durably commits the
    # raw to the ingress stage. Assert the AA reply AND that the committed ingress row is visible +
    # claimable — the AA was not returned ahead of a durable commit (count-and-log intact).
    reg = _mllp_inbound_registry("IB_MLLP", lambda m: [])
    runner = RegistryRunner(reg, store)
    ack = await runner._handle_inbound(reg.inbound["IB_MLLP"], RAW.encode("utf-8"))
    assert ack is not None and Peek.parse(ack).field("MSA-1") == "AA"  # positive ACK to the sender
    ing = await store.claim_next_fifo("IB_MLLP", stage=Stage.INGRESS.value)
    assert ing is not None and ing.stage == Stage.INGRESS.value
    msg = await store.get_message(ing.message_id)
    assert msg is not None and msg["status"] == MessageStatus.RECEIVED.value
    assert msg["raw"] == RAW and msg["control_id"] == "MSG1"  # raw preserved, durably persisted


async def test_mllp_post_ingress_failure_errors_without_nak(store) -> None:
    # Reply-capable post-ingress no-NAK path: AA'd on receipt, then a router-phase failure (an unknown
    # handler name — fail-closed in route_only) dead-letters the message to ERROR AFTER the ACK. No
    # second reply/NAK: _handle_inbound wrote the one AA; _process_ingress_item holds no sender socket
    # and returns a control-flow outcome, never an ACK string.
    reg = _mllp_inbound_registry("IB_MLLP", lambda m: ["ghost"])  # names an unregistered handler
    runner = RegistryRunner(reg, store)
    ack = await runner._handle_inbound(reg.inbound["IB_MLLP"], RAW.encode("utf-8"))
    assert (
        ack is not None and Peek.parse(ack).field("MSA-1") == "AA"
    )  # the sole sender-facing reply
    item = await store.claim_next_fifo("IB_MLLP", stage=Stage.INGRESS.value)
    assert item is not None
    outcome = await runner._process_ingress_item("IB_MLLP", item)
    assert (await store.get_message(item.message_id))["status"] == MessageStatus.ERROR.value
    assert outcome[0] is _ItemOutcome.PROCESSED  # lane advanced; no NAK back to the sender


# =====================================================================================================
# P1 batch 2 — cross-backend store-method parity (mirrors tests/test_sqlserver_store.py twins).
# STOREF-8 (resend_to), STOREF-9 (reingress + edit-and-resend), RBAC-8 (summary_access census),
# ALERT-19 (alert_instance CRUD). Synthetic HL7 only; every assertion is deterministic (no sleeps).
# =====================================================================================================

# Synthetic ADT + a distinct transformed/edited body — never real PHI (ADR 0090 resend/edit matrix).
_RS_ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
_RS_TRANSFORMED = "MSH|^~\\&|MEFOR|RF|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rZXF|sent\r"
_RS_EDITED = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||200^^^H^MR||DOE^JOHN\r"


async def _rs_seed(
    store, *, channel: str = "in1", deliveries: list[tuple[str, str]] | None = None
) -> str:
    """Shared STOREF-8/9 seed: a logged message with retained transformed outbound bodies."""
    return await store.enqueue_message(
        channel_id=channel,
        raw=_RS_ADT,
        deliveries=deliveries if deliveries is not None else [("OB1", _RS_TRANSFORMED)],
        control_id="MSG1",
        source_type="file",
    )


async def _pg_force_error(store, mid: str, error: str) -> None:
    """Force a seeded origin to a terminal ERROR (ciphered at rest) — proves the direct edit-resend
    never reopens/overwrites it (mirrors test_edit_resend.py::_seed_error)."""
    async with store._pool.acquire() as conn:
        await conn.execute(
            "UPDATE messages SET status=$1, error=$2 WHERE id=$3",
            MessageStatus.ERROR.value,
            store._enc(error, aad=cell_aad("messages", "error", mid)),
            mid,
        )


# --- ASVS 14.2.7: messages.metadata rides the body window (parity with SQLite + SQL Server) ---------


async def _pg_set_meta(store, message_id: str, bag: dict) -> None:
    """Attach a metadata bag the way transform_handoff does (encrypted, cell-AAD bound)."""
    async with store._pool.acquire() as conn:
        await conn.execute(
            "UPDATE messages SET metadata=$1 WHERE id=$2",
            store._enc(json.dumps(bag), aad=cell_aad("messages", "metadata", message_id)),
            message_id,
        )


async def _pg_terminal(store) -> str:
    """A message whose every queue row is DONE — i.e. body-purge eligible."""
    mid = await _rs_seed(store)
    for r in await store.outbox_for(mid):
        await store.mark_done(str(r["id"]))
    return mid


async def test_purge_nulls_metadata_with_the_body_pg(store) -> None:
    """ASVS 14.2.7 parity on Postgres — metadata is NULLed by the same widened statement."""
    mid = await _pg_terminal(store)
    await _pg_set_meta(store, mid, {"user": {"mrn": "MRN001"}})
    assert await store.message_metadata_json(mid) is not None

    assert await store.purge_message_bodies(older_than=9_999_999_999.0) == 1

    assert await store.message_metadata_json(mid) is None


async def test_purge_sweeps_pre_upgrade_metadata_pg(store) -> None:
    """The upgrade case — and the real check on asyncpg placeholder ORDER.

    The widened statement keeps the `*lead` binds (cutoff params, then the inflight array) leading the
    eligible-set subquery. A mis-numbered `$n` passes on SQLite (which uses positional `?`) and fails
    ONLY here, so this test is the one that actually verifies the Postgres bind order.
    """
    mid = await _pg_terminal(store)
    assert await store.purge_message_bodies(older_than=9_999_999_999.0) == 1  # pre-upgrade purge
    await _pg_set_meta(store, mid, {"user": {"mrn": "MRN001"}})
    assert (await store.get_message(mid))["raw"] == ""

    assert await store.purge_message_bodies(older_than=9_999_999_999.0) == 1  # counted → audited

    assert await store.message_metadata_json(mid) is None
    assert await store.purge_message_bodies(older_than=9_999_999_999.0) == 0  # idempotent


async def test_purge_metadata_respects_the_inflight_guard_pg(store) -> None:
    """The `metadata IS NOT NULL` disjunct is OR-ed INSIDE the eligible set, never around it —
    verified through Postgres's `= ANY($n::text[])` inflight bind, which has no SQLite analogue."""
    mid = await _rs_seed(store)  # left PENDING — never claimed, never done
    await _pg_set_meta(store, mid, {"user": {"mrn": "MRN001"}})

    assert await store.purge_message_bodies(older_than=9_999_999_999.0) == 0

    assert await store.message_metadata_json(mid) is not None


async def test_purge_search_presets_pg(store) -> None:
    """ASVS 14.2.7 Tier 2 parity on Postgres: old presets purged, new kept, second pass a no-op.

    Cleans up after itself even on failure — `search_presets` rides the key-rotation reencrypt scan and
    this suite asserts EXACT rotate counts, so a leaked row would red an unrelated test.
    """
    try:
        await store.upsert_search_preset(
            preset_id="pg-stale", owner="alice", name="stale", criteria="{}", now=0.0
        )
        await store.upsert_search_preset(
            preset_id="pg-fresh", owner="alice", name="fresh", criteria="{}", now=40 * DAY
        )

        assert await store.purge_search_presets(older_than=30 * DAY) == 1

        assert {r["name"] for r in await store.list_search_presets("alice")} == {"fresh"}
        assert await store.purge_search_presets(older_than=30 * DAY) == 0  # idempotent
    finally:
        async with store._pool.acquire() as conn:
            await conn.execute("DELETE FROM search_presets")


async def test_search_preset_retention_keys_on_last_used_pg(store) -> None:
    """#306 parity on Postgres: a RECALLED-but-unedited preset survives; a NULL `last_used_at` still ages.

    Pins the `GREATEST(updated_at, COALESCE(last_used_at, updated_at))` idiom end-to-end — including
    the migration case, where a row written before the column existed carries NULL and must fall back
    to `updated_at` alone. Cleans up after itself (the exact-rotate-count reason above).
    """
    try:
        for pid, name in (("pg-used", "used"), ("pg-idle", "idle"), ("pg-legacy", "legacy")):
            await store.upsert_search_preset(
                preset_id=pid, owner="alice", name=name, criteria="{}", now=0.0
            )
        # The recall stamps last_used_at past the cutoff...
        got = await store.get_search_preset(preset_id="pg-used", owner="alice", now=40 * DAY)
        assert got is not None and got["last_used_at"] is None  # PRE-stamp snapshot
        async with store._pool.acquire() as conn:
            stamped = await conn.fetchval(
                "SELECT last_used_at FROM search_presets WHERE id='pg-used'"
            )
            assert stamped == 40 * DAY
            # ...while the migration row is explicitly NULL (the post-ALTER state).
            await conn.execute("UPDATE search_presets SET last_used_at=NULL WHERE id='pg-legacy'")

        assert await store.purge_search_presets(older_than=30 * DAY) == 2  # idle + legacy

        assert {r["name"] for r in await store.list_search_presets("alice")} == {"used"}
    finally:
        async with store._pool.acquire() as conn:
            await conn.execute("DELETE FROM search_presets")


# --- STOREF-8: resend_to plain-parity matrix (mirrors tests/test_resend.py, on real Postgres) --------


async def test_resend_plain_parity_pg(store) -> None:
    from messagefoundry.store.base import (
        ResendKeyConflict,
        ResendSourceAmbiguous,
        ResendSourceEmpty,
        ResendSourceNotFound,
    )

    # at-least-once: a genuine NEW pending tail row shipping the retained TRANSFORMED body.
    mid = await _rs_seed(store)
    before = {r["id"] for r in await store.outbox_for(mid)}
    out = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    assert out.status == "resent" and out.to_destination == "OB2" and out.from_destination == "OB1"
    ob2 = [r for r in await store.outbox_for(mid) if r["destination_name"] == "OB2"]
    assert len(ob2) == 1 and ob2[0]["id"] not in before and ob2[0]["id"] == out.outbox_id
    assert ob2[0]["status"] == OutboxStatus.PENDING.value
    payloads = {p["destination_name"]: p["payload"] for p in await store.outbox_payloads_for(mid)}
    assert payloads["OB2"] == _RS_TRANSFORMED  # ships the TRANSFORMED body, decrypted at rest
    # TAIL: the resend row has the greatest seq (BIGSERIAL) of the lane, so FIFO orders it last.
    async with store._pool.acquire() as conn:
        seqs = {
            r["id"]: r["seq"]
            for r in await conn.fetch("SELECT id, seq FROM queue WHERE message_id=$1", mid)
        }
    assert seqs[ob2[0]["id"]] == max(seqs.values())

    # same-key duplicate -> exactly one row, reports the prior outcome.
    dup = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    assert dup.status == "duplicate" and dup.outbox_id == out.outbox_id
    assert len([r for r in await store.outbox_for(mid) if r["destination_name"] == "OB2"]) == 1
    # new key -> a genuine second resend (source pinned; OB2 is now ambiguous).
    out2 = await store.resend_to(message_id=mid, to="OB2", idempotency_key="k2", from_="OB1")
    assert out2.status == "resent"
    assert len([r for r in await store.outbox_for(mid) if r["destination_name"] == "OB2"]) == 2

    # key reused across a DIFFERENT message -> conflict (409), never a silent drop.
    m2 = await _rs_seed(store)
    with pytest.raises(ResendKeyConflict):
        await store.resend_to(message_id=m2, to="OB2", idempotency_key="k1")
    assert [r for r in await store.outbox_for(m2) if r["destination_name"] == "OB2"] == []
    # key reused for a DIFFERENT target -> conflict.
    with pytest.raises(ResendKeyConflict):
        await store.resend_to(message_id=mid, to="OB3", idempotency_key="k1")

    # retention-nulled source -> ResendSourceEmpty (never a zero-length PROCESSED body).
    m3 = await _rs_seed(store)
    for r in await store.outbox_for(m3):
        await store.mark_done(str(r["id"]))
    assert await store.purge_message_bodies(older_than=9_999_999_999.0) >= 1
    with pytest.raises(ResendSourceEmpty):
        await store.resend_to(message_id=m3, to="OB2", idempotency_key="k3")

    # no delivered body (ERROR-only) -> ResendSourceNotFound.
    eid = await store.record_received(
        channel_id="in1", raw=_RS_ADT, status=MessageStatus.ERROR, error="parse boom"
    )
    with pytest.raises(ResendSourceNotFound):
        await store.resend_to(message_id=eid, to="OB2", idempotency_key="k4")

    # a dead-lettered source is an eligible source (divert-to-standby, ADR 0090 §1).
    m4 = await _rs_seed(store)
    src = [r for r in await store.outbox_for(m4) if r["destination_name"] == "OB1"][0]
    await store.mark_failed(str(src["id"]), "permanent AR", RetryPolicy(max_attempts=0))
    out4 = await store.resend_to(message_id=m4, to="OB2", idempotency_key="k5")
    assert out4.status == "resent" and out4.from_destination == "OB1"

    # ambiguous multi-destination source requires from_; naming it ships THAT source's body.
    m5 = await _rs_seed(
        store, deliveries=[("OB1", _RS_TRANSFORMED), ("OB3", _RS_TRANSFORMED + "X")]
    )
    with pytest.raises(ResendSourceAmbiguous):
        await store.resend_to(message_id=m5, to="OB2", idempotency_key="k6")
    out5 = await store.resend_to(message_id=m5, to="OB2", idempotency_key="k7", from_="OB3")
    assert out5.status == "resent" and out5.from_destination == "OB3"
    p5 = {p["destination_name"]: p["payload"] for p in await store.outbox_payloads_for(m5)}
    assert p5["OB2"] == _RS_TRANSFORMED + "X"

    # the resend event records the lane hop but never the PHI body.
    details = [str(e["detail"] or "") for e in await store.events_for(mid)]
    assert any("OB1->OB2" in d for d in details)
    assert all("ZXF|" not in d and "PID|" not in d for d in details)


async def test_resend_reopens_processed_to_routed_pg(store) -> None:
    # The ROUTED write is the replay re-queue exception; the finalizer stays terminal-authority.
    mid = await _rs_seed(store)
    for r in await store.outbox_for(mid):
        await store.mark_done(str(r["id"]))
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    await store.resend_to(message_id=mid, to="OB2", idempotency_key="k1")
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    ob2 = [r for r in await store.outbox_for(mid) if r["destination_name"] == "OB2"][0]
    await store.mark_done(str(ob2["id"]))
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_resend_funnels_behind_uncommitted_producer_pg(store) -> None:
    # ADR 0090 §3 PG divergence (contrast to SQL Server): resend_to takes the per-lane advisory
    # write-funnel (_lock_outbound_lanes), so it BLOCKS behind a producer holding the same OB2 lane
    # lock and can't commit ahead of it — commit-order == seq-order, closing the SKIP-LOCKED/MVCC
    # inversion a second writer would open. DETERMINISTIC: the block is a genuine lock wait (a false
    # pass would require the advisory lock NOT to block, which is impossible while the producer txn
    # is held) — observed via wait_for(shield(task)) raising TimeoutError, never a sleep-race.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    mid = await store.enqueue_message(
        channel_id="IB", raw=_RS_ADT, deliveries=[("OB1", "SRC")], now=100.0
    )
    pmid = await store.enqueue_message(
        channel_id="IB", raw=_RS_ADT, deliveries=[], now=100.0
    )  # FK parent for the manual OB2 producer row
    other = await PostgresStore.open(load_settings(environ=os.environ).store)
    conn = await store._pool.acquire()
    try:
        tx = conn.transaction()
        await tx.start()
        # Hold the OB2 lane lock + an uncommitted producer row (seq N) open across the probe.
        await store._lock_outbound_lanes(conn, ("OB2",))
        await store._insert_outbound_row(conn, pmid, "IB", "OB2", "PRODUCER", 101.0)
        task = asyncio.create_task(
            other.resend_to(message_id=mid, to="OB2", idempotency_key="k1", from_="OB1", now=102.0)
        )
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                asyncio.shield(task), timeout=2.0
            )  # funnels behind the held lock
        await (
            tx.commit()
        )  # producer commits at seq N; the resend can now take the lane lock (seq N+1)
        out = await asyncio.wait_for(task, timeout=10.0)
        assert out.status == "resent"
        # ORDER: the resend lands at the lane TAIL, never ahead of the older producer.
        async with store._pool.acquire() as c2:
            lane = await c2.fetch(
                "SELECT id, payload FROM queue WHERE stage=$1 AND destination_name=$2 ORDER BY seq",
                Stage.OUTBOUND.value,
                "OB2",
            )
        assert [
            store._dec(r["payload"], aad=cell_aad("queue", "payload", r["id"])) for r in lane
        ] == ["PRODUCER", "SRC"]
    finally:
        await store._pool.release(conn)
        await other.close()


# --- STOREF-9: reingress (RE-ROUTE) + resend_to(body_override=) (DIRECT edit), on real Postgres ------


async def test_reingress_parity_pg(store) -> None:
    from messagefoundry.store.base import ReingressOriginMissing, ResendKeyConflict
    from messagefoundry.store.store import REINGRESS_TARGET_PREFIX

    origin = await _rs_seed(store)
    before = await store.get_message(origin)
    out = await store.reingress(origin_message_id=origin, raw=_RS_EDITED, idempotency_key="k1")
    assert out.status == "resubmitted" and out.message_id == origin and out.new_message_id != origin
    assert out.channel_id == "in1"

    child = await store.get_message(out.new_message_id)
    assert child is not None and child["raw"] == _RS_EDITED  # the EDITED body, decrypted at rest
    assert child["status"] == MessageStatus.RECEIVED.value and child["channel_id"] == "in1"
    meta = json.loads(child["metadata"])
    assert meta["correlation_id"] == origin and meta["correlation_root_id"] == origin
    assert meta["edited_from"] == origin
    # the child carries exactly one pending INGRESS row; the origin owns none of its own.
    async with store._pool.acquire() as conn:
        crows = await conn.fetch(
            "SELECT status FROM queue WHERE message_id=$1 AND stage=$2",
            out.new_message_id,
            Stage.INGRESS.value,
        )
        orows = await conn.fetch(
            "SELECT status FROM queue WHERE message_id=$1 AND stage=$2", origin, Stage.INGRESS.value
        )
    assert len(crows) == 1 and crows[0]["status"] == OutboxStatus.PENDING.value
    assert list(orows) == []

    # origin byte-identical (never opened for write).
    after = await store.get_message(origin)
    assert after["raw"] == before["raw"] == _RS_ADT
    assert after["status"] == before["status"] and after["metadata"] == before["metadata"]

    # same key -> duplicate, same child, still exactly one child + one ingress row (no double-inject).
    dup = await store.reingress(origin_message_id=origin, raw=_RS_EDITED, idempotency_key="k1")
    assert dup.status == "duplicate" and dup.new_message_id == out.new_message_id
    async with store._pool.acquire() as conn:
        n = await conn.fetchval("SELECT COUNT(*) FROM messages WHERE id=$1", out.new_message_id)
        ing = await conn.fetch(
            "SELECT status FROM queue WHERE message_id=$1 AND stage=$2",
            out.new_message_id,
            Stage.INGRESS.value,
        )
    assert n == 1 and len(ing) == 1
    # new key -> a distinct second child.
    out2 = await store.reingress(origin_message_id=origin, raw=_RS_EDITED, idempotency_key="k2")
    assert out2.status == "resubmitted" and out2.new_message_id != out.new_message_id
    # key reused across a DIFFERENT message -> conflict.
    other = await _rs_seed(store)
    with pytest.raises(ResendKeyConflict):
        await store.reingress(origin_message_id=other, raw=_RS_EDITED, idempotency_key="k1")
    # missing origin -> ReingressOriginMissing.
    with pytest.raises(ReingressOriginMissing):
        await store.reingress(origin_message_id="nope", raw=_RS_EDITED, idempotency_key="k9")
    # the re-ingress records its DISJOINT target key (@reingress:<channel>).
    async with store._pool.acquire() as conn:
        td = await conn.fetchval("SELECT to_destination FROM resend_log WHERE resend_key=$1", "k1")
    assert td == f"{REINGRESS_TARGET_PREFIX}in1"


async def test_direct_edit_parity_pg(store) -> None:
    from messagefoundry.store.base import ResendSourceEmpty

    origin = await _rs_seed(store)
    await _pg_force_error(store, origin, "connection refused: partner down")
    before = await store.get_message(origin)
    assert before["status"] == MessageStatus.ERROR.value

    out = await store.resend_to(
        message_id=origin, to="OB2", idempotency_key="k1", body_override=_RS_EDITED
    )
    assert out.status == "resent" and out.to_destination == "OB2" and out.message_id == origin

    # ORIGIN byte-identical — raw + status + ERROR text + metadata all preserved (read, never written).
    after = await store.get_message(origin)
    assert after["raw"] == before["raw"] == _RS_ADT
    assert after["status"] == before["status"] == MessageStatus.ERROR.value
    assert after["error"] == before["error"] == "connection refused: partner down"
    assert after["metadata"] == before["metadata"]
    origin_payloads = {
        p["destination_name"]: p["payload"] for p in await store.outbox_payloads_for(origin)
    }
    assert origin_payloads == {"OB1": _RS_TRANSFORMED}  # origin outbox untouched

    # the edited OB2 delivery hangs off a NEW correlated child, never the origin.
    async with store._pool.acquire() as conn:
        crows = await conn.fetch(
            "SELECT id, message_id FROM queue WHERE stage=$1 AND destination_name=$2",
            Stage.OUTBOUND.value,
            "OB2",
        )
    assert len(crows) == 1 and crows[0]["id"] == out.outbox_id
    child_id = crows[0]["message_id"]
    assert child_id != origin
    child = await store.get_message(child_id)
    assert child["raw"] == _RS_EDITED and child["status"] == MessageStatus.ROUTED.value
    cmeta = json.loads(child["metadata"])
    assert cmeta["correlation_id"] == origin and cmeta["edited_from"] == origin
    child_payloads = {
        p["destination_name"]: p["payload"] for p in await store.outbox_payloads_for(child_id)
    }
    assert child_payloads == {"OB2": _RS_EDITED}

    # empty edited body -> ResendSourceEmpty, with NO partial mutation (no OB2E row, no child).
    m2 = await _rs_seed(store)
    with pytest.raises(ResendSourceEmpty):
        await store.resend_to(message_id=m2, to="OB2E", idempotency_key="k2", body_override="")
    async with store._pool.acquire() as conn:
        ne = await conn.fetch(
            "SELECT id FROM queue WHERE stage=$1 AND destination_name=$2",
            Stage.OUTBOUND.value,
            "OB2E",
        )
    assert list(ne) == []

    # idempotent: same key/body -> duplicate, exactly one OB3 delivery on one child.
    first = await store.resend_to(
        message_id=m2, to="OB3", idempotency_key="k3", body_override=_RS_EDITED
    )
    second = await store.resend_to(
        message_id=m2, to="OB3", idempotency_key="k3", body_override=_RS_EDITED
    )
    assert first.status == "resent" and second.status == "duplicate"
    async with store._pool.acquire() as conn:
        ob3 = await conn.fetch(
            "SELECT id FROM queue WHERE stage=$1 AND destination_name=$2",
            Stage.OUTBOUND.value,
            "OB3",
        )
    assert len(ob3) == 1 and ob3[0]["id"] == first.outbox_id


# --- RBAC-8: server-side summary_access census (record_audit + list_audit), on real Postgres --------


async def test_summary_access_census_survives_and_coalesces_pg(store) -> None:
    # Drive the REAL backend-agnostic coalescer end-to-end so the census JSON detail + NULL/scope
    # keying persist through record_audit and read back via list_audit on the real backend (the piece
    # that today rides SQLite only). Fixed `now` values make the hour bucketing deterministic.
    from messagefoundry.api.app import _SummaryAuditCoalescer

    c = _SummaryAuditCoalescer()
    await c.note(store, "alice", "ch1", 3, 0.0)  # hour 0
    await c.note(store, "alice", "ch1", 2, 60.0)  # same hour -> accumulate, no emit
    assert [r for r in await store.list_audit() if r["action"] == "summary_access"] == []
    await c.note(store, "alice", "ch1", 1, 3600.0)  # hour 1 -> flush hour-0 window (count 5)
    rows = [r for r in await store.list_audit() if r["action"] == "summary_access"]
    assert len(rows) == 1
    assert json.loads(rows[0]["detail"]) == {"count": 5, "window_start": 0}
    assert rows[0]["actor"] == "alice" and rows[0]["channel_id"] == "ch1"

    await c.note(store, "bob", "", 4, 3600.0)  # hour 1, scope "" -> channel_id NULL
    await c.flush(store)  # emit alice hour-1 (count 1) + bob (count 4)
    rows = [r for r in await store.list_audit() if r["action"] == "summary_access"]
    assert len(rows) == 3
    got = sorted((r["actor"], r["channel_id"], json.loads(r["detail"])["count"]) for r in rows)
    assert got == [("alice", "ch1", 1), ("alice", "ch1", 5), ("bob", None, 4)]
    assert any(
        r["actor"] == "bob" and r["channel_id"] is None for r in rows
    )  # scope "" -> SQL NULL
    # the #170 list_audit filters resolve summary_access rows on the real backend.
    af = await store.list_audit(action="summary_access", actor="alice")
    assert len(af) == 2 and all(
        r["action"] == "summary_access" and r["actor"] == "alice" for r in af
    )
    ok, _ = await store.verify_audit_chain()
    assert ok is True  # the census rows didn't fork the audit chain


# --- ALERT-19: alert_instance CRUD lifecycle + reason cipher-at-rest, on real Postgres --------------


async def test_alert_instance_lifecycle_pg(store) -> None:
    # first fire opens one `open` instance (count 1, first_seen==last_seen).
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="critical", now=100.0
    )
    (a,) = await store.list_active_alert_instances()
    assert a.status == "open" and a.count == 1 and a.first_seen == 100.0 and a.last_seen == 100.0
    assert a.severity == "critical"

    # re-fire folds into the live instance (PG's native ON CONFLICT path): same id, count++, last wins.
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="warning", now=150.0
    )
    (a2,) = await store.list_active_alert_instances()
    assert a2.id == a.id and a2.count == 2 and a2.last_seen == 150.0 and a2.severity == "warning"
    # a DIFFERENT key opens a distinct instance.
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_Y", severity="critical", now=160.0
    )
    assert len(await store.list_active_alert_instances()) == 2

    # ack -> acknowledged + acked_by/at, excluded from the open count; unknown id -> False.
    assert await store.ack_alert_instance(a.id, actor="scott", now=200.0) is True
    got = await store.get_alert_instance(a.id)
    assert got is not None and got.status == "acknowledged"
    assert got.acked_by == "scott" and got.acked_at == 200.0
    assert await store.ack_alert_instance(999999, actor="scott") is False
    assert await store.count_open_alerts_by_connection() == {"OB_Y": 1}
    # an acknowledged re-fire folds in (count++) but does NOT pop back to open.
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="critical", now=210.0
    )
    got = await store.get_alert_instance(a.id)
    assert got.status == "acknowledged" and got.count == 3
    assert await store.count_open_alerts_by_connection() == {"OB_Y": 1}

    # resolve closes it; the same key re-opens a FRESH distinct instance (partial index frees it).
    assert await store.resolve_alert_instance(a.id, now=300.0) is True
    assert {r.connection for r in await store.list_active_alert_instances()} == {"OB_Y"}
    assert await store.resolve_alert_instance(a.id) is False
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="warning", now=310.0
    )
    (reopened,) = [r for r in await store.list_active_alert_instances() if r.connection == "OB_X"]
    assert reopened.id != a.id and reopened.status == "open" and reopened.count == 1

    # inverse-signal resolver closes only the matching key; a no-match is a no-op (0).
    assert (
        await store.resolve_alert_instances_for(
            event_type="connection_error", connection="OB_X", now=320.0
        )
        == 1
    )
    assert {r.connection for r in await store.list_active_alert_instances()} == {"OB_Y"}
    assert (
        await store.resolve_alert_instances_for(event_type="connection_error", connection="NOPE")
        == 0
    )

    # purge: only RESOLVED rows older than the cutoff are pruned (open/ack survive).
    (y,) = [r for r in await store.list_active_alert_instances() if r.connection == "OB_Y"]
    await store.resolve_alert_instance(y.id, now=100.0)  # resolved at 100.0 -> purgeable
    assert await store.purge_alert_instances(older_than=200.0) == 1
    await store.upsert_alert_instance(
        event_type="queue_buildup", connection="OB_R", severity="warning", now=500.0
    )
    (rr,) = [r for r in await store.list_active_alert_instances() if r.connection == "OB_R"]
    await store.resolve_alert_instance(rr.id, now=500.0)  # too recent for older_than=200.0
    assert await store.purge_alert_instances(older_than=200.0) == 0

    # side-observer: an alert write creates NO message/queue row (invisible to the finalizer).
    before = await store.stats()
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_Z", severity="critical", now=600.0
    )
    assert await store.stats() == before


async def test_alert_reason_encrypted_at_rest_pg(store) -> None:
    # Metadata-only + the scrubbed reason is encrypted at rest through a keyed handle (PG TEXT cipher
    # pass) — decrypted at the read boundary, ciphertext on disk.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s2 = await PostgresStore.open(settings, cipher=make_cipher(generate_key()))
    try:
        await s2.upsert_alert_instance(
            event_type="connection_error",
            connection="OB_ENC",
            severity="critical",
            reason="connect refused to 10.0.0.9",
            now=100.0,
        )
        (a,) = [r for r in await s2.list_active_alert_instances() if r.connection == "OB_ENC"]
        assert a.reason == "connect refused to 10.0.0.9"  # decrypted at the boundary
    finally:
        await s2.close()
    async with store._pool.acquire() as conn:  # read the RAW column (fixture handle: no cipher)
        raw = await conn.fetchval("SELECT reason FROM alert_instance WHERE connection=$1", "OB_ENC")
    assert isinstance(raw, str) and raw.startswith(MARKER_PREFIX)  # ciphertext on disk
    assert "refused" not in raw


# --- BATCH-3 cross-backend guards: store-once-inert + rotate/audit CLI on a live Postgres ------


async def test_store_once_deliver_many_body_ref_inert(store) -> None:
    """STOREF-17 (Postgres mirror): store-once-deliver-many dedup is SQLite-only this increment
    (ADR 0099); on Postgres it is INERT — the schema carries ``shared_body`` + ``queue.body_ref``
    (parity comments postgres.py:229-234/677-678/873-874), but ``transform_handoff`` writes each fan-out
    delivery inline (``_insert_outbound_row`` omits ``body_ref`` → NULL), never a shared copy. The SAME
    input that dedups on SQLite (test_store_once_deliver_many.py:88) must here create ZERO ``shared_body``
    rows and leave every outbound ``body_ref`` NULL — and delivery parity must still hold: each
    independent inline ciphertext decrypts to the identical plaintext (the LEFT-JOIN read falls through
    to the inline payload when ``body_ref`` IS NULL, byte-identical to the pre-dedup path)."""
    # A transformed body fanned out to ≥2 destinations — the exact shape that triggers the SQLite dedup;
    # kept distinct from RAW (the routed handler body) as the SQLite reference test does.
    body = "MSH|^~\\&|XFORM|||||20260101||ADT^A01|OUT1|P|2.5.1\r"
    dests = ["OB_A", "OB_B", "OB_C"]
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    ing = await store.claim_next_fifo("IB", now=100.0, stage=Stage.INGRESS.value)
    assert ing is not None
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    rtd = await store.claim_next_fifo("IB", now=100.0, stage=Stage.ROUTED.value)
    assert rtd is not None
    await store.transform_handoff(
        routed_id=rtd.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[(d, body) for d in dests],
        now=100.0,
    )
    # (1) No shared copy was ever created — dedup is inert on this backend.
    n = await store._fetchone("SELECT COUNT(*) AS n FROM shared_body")
    assert n is not None and int(n["n"]) == 0
    # (2) Every fan-out outbound row stores the body inline (body_ref NULL) — N independent copies.
    rows = await store._fetchall(
        "SELECT body_ref FROM queue WHERE message_id=$1 AND stage=$2", mid, Stage.OUTBOUND.value
    )
    assert len(rows) == len(dests) and all(r["body_ref"] is None for r in rows)
    # (3) Delivery parity: each destination's inline ciphertext decrypts to the identical plaintext.
    for d in dests:
        item = await store.claim_next_fifo(d, now=100.0, stage=Stage.OUTBOUND.value)
        assert item is not None and item.payload == body


async def test_audit_verify_cli_server(store, capsys) -> None:
    """CLI-22 (Postgres mirror): the ``audit-verify`` CLI wrapper reaches the live Postgres store via
    ``MEFOR_STORE_*`` env (no ``--db``; the M-31 missing-DB guard is SQLite-only, so it's inert and the
    CLI goes straight to ``open_store`` on the env-configured backend). Seed a keyless audit chain
    through the fixture handle (``record_audit`` commits per row, so the CLI's separate connection sees
    it), then run the CLI OFF the event loop — ``_audit_verify`` calls ``asyncio.run`` internally, which
    raises inside a running loop, so ``asyncio.to_thread`` gives it a fresh loop + its own pool."""
    from messagefoundry.__main__ import main

    await store.record_audit("message_view", actor="alice", detail="v1")
    await store.record_audit("export", actor="bob", detail="e1")
    rc = await asyncio.to_thread(main, ["audit-verify"])  # backend from env; NO --db
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK:" in out and "verified 2" in out


async def test_rekey_audit_cli_server(store, capsys, monkeypatch) -> None:
    """CLI-23 (Postgres mirror): the ``rekey-audit`` CLI wrapper enables HMAC keying of an existing
    keyless chain (#190-D). It reaches the live Postgres store purely via ``MEFOR_STORE_*`` env (no
    ``--db``), needs a DEK to key, and writes ``audit_chain_meta.keyed_from_id = MAX(audit_log.id)+1`` via
    PG's ``INSERT ... ON CONFLICT`` upsert under the advisory lock. Seed keyless (the fixture handle
    opened without a DEK), compute the watermark at RUNTIME (the fixture TRUNCATE ... RESTART IDENTITY
    reseeds the serial, but computing MAX(id)+1 is correct on either reseed behaviour), then drive the
    CLI off the event loop (its internal ``asyncio.run`` would raise in a running loop)."""
    from messagefoundry.__main__ import main

    await store.record_audit("legacy1", actor="x")
    await store.record_audit("legacy2", actor="x")
    row = await store._fetchone("SELECT MAX(id) + 1 AS wm FROM audit_log")
    assert row is not None
    wm = int(row["wm"])
    # Give the CLI a DEK (set AFTER the keyless fixture opened, so the seeded chain stays keyless).
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    rc = await asyncio.to_thread(main, ["rekey-audit"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK:" in out and f"keyed from id={wm}" in out
    # Idempotent: the watermark is set → a second run is a no-op, never a second move.
    rc2 = await asyncio.to_thread(main, ["rekey-audit"])
    assert rc2 == 0
    assert "already keyed" in capsys.readouterr().out


async def test_rotate_key_cli_reencrypts_server_store(store, capsys, monkeypatch, tmp_path) -> None:
    """CLI-24 (Postgres mirror): the ``rotate-key`` CLI wrapper (resolve_active_key + keyring from env +
    open_store dispatch + reencrypt_to_active) has only ever run against SQLite ``--db``; the underlying
    method is covered on PG for attachment chunks only, and the CLI wiring not at all. Drive
    ``main(["rotate-key"])`` against the live Postgres store: the backend + retired/active keyring come
    purely from ``MEFOR_STORE_*`` env (no ``--db``). The ``store`` fixture truncated every table, so
    rotation sees ONLY this test's key_a rows (no foreign-key leftover → no CipherError). After rotation
    every ciphertext carries the new active key's fingerprint and the message decrypts under key_b ALONE
    (retired key dropped) — end-to-end proof."""
    from messagefoundry.__main__ import main
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    monkeypatch.chdir(
        tmp_path
    )  # isolate from any stray ./messagefoundry.toml (env wins, but be safe)
    settings = load_settings(environ=os.environ).store
    key_a, key_b = generate_key(), generate_key()
    active_id_b = make_cipher(key_b).active_key_id

    seed = await PostgresStore.open(settings, cipher=make_cipher(key_a))
    try:
        mid = await seed.enqueue_message(channel_id="ch", raw=RAW, deliveries=[("d", RAW)])
    finally:
        await seed.close()

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key_b)  # new active
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED", key_a)  # old, decrypt-only bridge
    rc = await asyncio.to_thread(main, ["rotate-key"])  # asyncio.run inside → off the loop
    assert rc == 0
    assert "re-encrypted" in capsys.readouterr().out

    verify = await PostgresStore.open(
        settings, cipher=make_cipher(key_b)
    )  # key_b alone, no retired
    try:
        assert len(await verify.list_messages()) == 1
        assert (await verify.get_message(mid))["raw"] == RAW  # decrypts under the new key alone
        blobs = await verify._fetchall(
            "SELECT raw AS v FROM messages UNION ALL SELECT payload AS v FROM queue WHERE payload <> ''"
        )
        assert blobs  # at least messages.raw + the one outbound payload
        for r in blobs:
            assert r["v"].startswith(MARKER_PREFIX)
            assert r["v"].split(":", 3)[2] == active_id_b  # mfenc:v1:<active_id>:<blob>
    finally:
        await verify.close()


# =====================================================================================================
# P1 batch 4 — STOREF-11: the ingress document-detach PIPELINE on real PostgreSQL (#149, ADR 0105
# Phase 1a). Postgres advertises supports_streaming_attachments=True and implements put_attachment /
# read_attachment / sweep_orphan_attachments + enqueue_ingress(attachment_refs=) (the two-object commit),
# so the SAME over-threshold OBX-5 ED detach that tests/test_ingress_document_detach.py exercises on
# SQLite runs identically here. Those SQLite tests, plus the store-level two-object-commit tests already
# in this file, cover the pieces separately; this block drives the runner end-to-end
# (RegistryRunner._handle_inbound / _detach_documents) against the LIVE server store — the piece the
# server legs were missing. Every assertion is deterministic (no sleeps, no kills); synthetic HL7 only.
# =====================================================================================================


def _big_b64(nbytes: int) -> str:
    """A big UNBROKEN base64 string standing in for a base64 PDF sitting in OBX-5.5 (synthetic)."""
    return base64.b64encode(b"P" * nbytes).decode("ascii")


def _hl7_with_doc(b64: str) -> str:
    """A minimal MDM^T02 carrying one OBX-5 ED Base64 document (``^Application^PDF^Base64^<b64>``)."""
    return (
        "MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||MDM^T02|MSGID001|P|2.5\r"
        "EVN|T02|20260101120000\r"
        "PID|1||MRN123^^^FAC||DOE^JOHN\r"
        f"OBX|1|ED|PDF^Report||^Application^PDF^Base64^{b64}||||||F\r"
    )


def _stream_ack_code(ack: str | None) -> str | None:
    """The MSA-1 acknowledgement code (AA/AE/AR) from a framed HL7 ACK string, or None."""
    if ack is None:
        return None
    for seg in ack.replace("\n", "\r").split("\r"):
        if seg.startswith("MSA|"):
            return seg.split("|")[1]
    return None


def _streaming_ic(
    *, threshold: int | None = 500, max_message_bytes: int | None = None, strict: bool = False
) -> InboundConnection:
    return InboundConnection(
        name="IB_STREAM",
        spec=ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
        router="r",
        content_type=ContentType.HL7V2,
        validation=Validation(strict=strict),
        stream_threshold_bytes=threshold,
        max_message_bytes=max_message_bytes,
    )


def _streaming_registry(ic: InboundConnection) -> Registry:
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_router("r", lambda m: [])  # no-op router; ingress never routes in these tests
    return reg


async def _only_message(store) -> dict:
    """The single ``messages`` row (the fixture truncates, and each test drives one inbound)."""
    rows = await store._fetchall("SELECT status, raw, error FROM messages")
    assert len(rows) == 1
    return dict(rows[0])


async def _attachment_count(store) -> int:
    row = await store._fetchone("SELECT COUNT(*) AS n FROM attachment")
    return int(row["n"])


async def test_over_threshold_detaches_verbatim_pg(store) -> None:
    b64 = _big_b64(2000)  # ~2668 base64 chars, well over the 500-byte message threshold
    raw = _hl7_with_doc(b64)
    ic = _streaming_ic(threshold=500)
    runner = RegistryRunner(_streaming_registry(ic), store)

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _stream_ack_code(ack) == "AA"
    row = await _only_message(store)
    assert row["status"] == MessageStatus.RECEIVED.value
    skeleton = row["raw"]
    # The skeleton is SMALL (the bulky base64 is gone) and the other segments are intact.
    assert len(skeleton) < len(raw)
    assert "DOE^JOHN" in skeleton and "EVN|T02" in skeleton
    assert b64 not in skeleton  # the document was lifted out
    # OBX-5.5 now holds a live ref handle whose content address is the sha256 of the verbatim base64.
    obx5_5 = Message.parse(skeleton).field("OBX-5.5")
    assert obx5_5 is not None and is_doc_ref(obx5_5)
    ref, content_type = parse_doc_ref(obx5_5)
    assert ref == _hashlib.sha256(b64.encode("utf-8")).hexdigest()
    assert content_type == "Application"
    # The attachment holds the EXACT base64 bytes on the server store, increffed once by the ingress commit.
    assert await _a_refcount(store, ref) == 1
    assert "".join(await _a_read(store, ref)) == b64
    assert await _a_chunks(store, ref) == len(list(chunk_b64(b64)))


async def test_below_threshold_byte_identical_pg(store) -> None:
    b64 = _big_b64(50)  # small; the whole message stays under the 5000-byte threshold
    raw = _hl7_with_doc(b64)
    assert len(raw) < 5000
    ic = _streaming_ic(threshold=5000)
    runner = RegistryRunner(_streaming_registry(ic), store)

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _stream_ack_code(ack) == "AA"
    row = await _only_message(store)
    assert row["status"] == MessageStatus.RECEIVED.value
    assert row["raw"] == raw  # BYTE-IDENTICAL: no detach, no re-encode
    assert await _attachment_count(store) == 0  # no attachment row


async def test_over_max_message_bytes_naks_ar_pg(store) -> None:
    b64 = _big_b64(4000)
    raw = _hl7_with_doc(b64)
    # Cap below the body but at/above the threshold: admitted past the threshold gate, then rejected by the
    # total cap (Peek.parse) → NAK AR + ERROR, before any detach.
    ic = _streaming_ic(threshold=500, max_message_bytes=1000)
    assert len(raw) > 1000
    runner = RegistryRunner(_streaming_registry(ic), store)

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _stream_ack_code(ack) == "AR"
    row = await _only_message(store)
    assert row["status"] == MessageStatus.ERROR.value
    assert "exceeds max size" in row["error"]
    assert await _attachment_count(store) == 0


async def test_stream_inflight_budget_naks_ae_pg(store) -> None:
    b64 = _big_b64(2000)
    raw = _hl7_with_doc(b64)
    ic = _streaming_ic(threshold=500)
    runner = RegistryRunner(_streaming_registry(ic), store, stream_inflight_budget_bytes=10)

    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))

    assert _stream_ack_code(ack) == "AE"  # detach refused (backpressure) → NAK AE
    row = await _only_message(store)
    assert row["status"] == MessageStatus.ERROR.value
    assert "streaming detach failed" in row["error"]
    assert (
        await _attachment_count(store) == 0
    )  # nothing written (budget checked before put_attachment)
    assert runner._stream_inflight_bytes == 0  # counter released in the finally


async def test_ack_fires_after_skeleton_and_incref_commit_pg(store) -> None:
    # When _handle_inbound returns AA, the RECEIVED skeleton row AND the attachment incref are already
    # durable (the two-object commit) — count-and-log holds on the server store.
    b64 = _big_b64(1500)
    ic = _streaming_ic(threshold=500)
    runner = RegistryRunner(_streaming_registry(ic), store)

    ack = await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))
    assert _stream_ack_code(ack) == "AA"

    row = await _only_message(store)
    assert row["status"] == MessageStatus.RECEIVED.value
    ref, _ = parse_doc_ref(Message.parse(row["raw"]).field("OBX-5.5"))
    assert await _a_refcount(store, ref) == 1  # incref durable at the moment AA is available


async def test_crash_orphan_sweep_and_rerun_dedups_pg(store) -> None:
    # Simulate a crash AFTER put_attachment (refcount 0) but BEFORE the skeleton commit: _detach_documents
    # stores the attachment, then the process dies before enqueue_ingress. No ACK was sent.
    b64 = _big_b64(1500)
    raw = _hl7_with_doc(b64)
    ic = _streaming_ic(threshold=500)
    runner = RegistryRunner(_streaming_registry(ic), store)

    skeleton, refs = await runner._detach_documents(ic, raw)
    assert len(refs) == 1
    ref = refs[0]
    assert await _a_refcount(store, ref) == 0  # orphan: stored, never increffed (no commit, no ACK)

    # The Phase-0 startup sweep reclaims the refcount-0 orphan so no PHI chunk is left at rest.
    assert await store.sweep_orphan_attachments() == 1
    assert await _a_refcount(store, ref) is None

    # The sender resends (no ACK) → a full re-run re-derives identically: same ref (dedup on sha256), one
    # attachment at refcount 1, verbatim bytes recovered, RECEIVED.
    ack = await runner._handle_inbound(ic, raw.encode("utf-8"))
    assert _stream_ack_code(ack) == "AA"
    assert await _a_refcount(store, ref) == 1
    assert "".join(await _a_read(store, ref)) == b64


async def test_strict_downgraded_to_header_only_over_threshold_pg(store, monkeypatch) -> None:
    # Over the streaming threshold, whole-body hl7apy validation is NOT invoked (header-only downgrade) —
    # the detached document is opaque, so the header parse Peek already did is the validation seam.
    def _boom(text, *, expected_version=None):  # type: ignore[no-untyped-def]
        raise AssertionError("whole-body validate must not run over the streaming threshold")

    monkeypatch.setattr(wiring_runner, "validate", _boom)
    b64 = _big_b64(2000)
    ic = _streaming_ic(threshold=500, strict=True)
    runner = RegistryRunner(_streaming_registry(ic), store)

    ack = await runner._handle_inbound(ic, _hl7_with_doc(b64).encode("utf-8"))
    assert _stream_ack_code(ack) == "AA"  # RECEIVED, not blocked by (skipped) strict validation
    assert (await _only_message(store))["status"] == MessageStatus.RECEIVED.value


# --- ADR 0150: the client address column + its migration, on real Postgres --------------------------


async def test_audit_client_recorded_and_chained(store) -> None:
    """The address round-trips through record_audit/list_audit on the real backend, a `system` write
    stays NULL rather than inheriting it, and the chain verifies across both row shapes."""
    await store.record_audit("messages.export", actor="alice", client="10.4.2.9")
    await store.record_audit("retention.purge", actor="system")  # engine-internal: no client
    rows = [dict(r) for r in await store.list_audit(limit=2)]
    assert rows[0]["action"] == "retention.purge" and rows[0]["client"] is None
    assert rows[1]["client"] == "10.4.2.9"
    ok, message = await store.verify_audit_chain()
    assert ok, message


async def test_audit_client_migration_on_a_preexisting_table(store) -> None:
    """The real upgrade path on Postgres: a DB whose ``audit_log`` predates ``client`` gets the column
    ALTERed in, its legacy rows keep their ORIGINAL hashes, and the chain still verifies — then a new
    address-bearing row chains cleanly onto them.

    The DDL batch is skipped when the ADR 0064 ``schema_meta`` marker matches, so this clears the marker
    to reproduce what a genuine upgrade does: adding statements to ``_SCHEMA`` changes ``_schema_hash()``,
    which forces exactly this one full (idempotent) re-run."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.store import audit_row_hash

    async with store._pool.acquire() as conn:
        await conn.execute("ALTER TABLE audit_log DROP COLUMN IF EXISTS client")
        await conn.execute("DELETE FROM schema_meta")
        prev = ""
        for i in range(3):
            prev = audit_row_hash(
                prev, ts=float(i), actor="u", action="legacy", channel_id=None, detail=None
            )
            await conn.execute(
                "INSERT INTO audit_log (ts, actor, action, channel_id, detail, row_hash)"
                " VALUES ($1,$2,$3,$4,$5,$6)",
                float(i),
                "u",
                "legacy",
                None,
                None,
                prev,
            )
    legacy_head = prev

    upgraded = await PostgresStore.open(load_settings(environ=os.environ).store)
    try:
        rows = await upgraded._fetchall("SELECT client, row_hash FROM audit_log ORDER BY id")
        assert [r["client"] for r in rows] == [None, None, None]
        assert rows[-1]["row_hash"] == legacy_head  # legacy hashes NOT rewritten
        ok, message = await upgraded.verify_audit_chain()
        assert ok, message
        await upgraded.record_audit("messages.export", actor="alice", client="10.4.2.9")
        ok, message = await upgraded.verify_audit_chain()
        assert ok, message  # one chain over old-format + new-format rows
        assert "4" in (message or "")
    finally:
        await upgraded.close()


# --- ASVS 11.3.4: the persisted per-key AES-GCM invocation bound -------------
# These exercise the BACKEND-SPECIFIC upsert SQL (the only place it runs at all). The offline unit
# suite in tests/test_asvs_gcm_invocation_bound.py covers the arithmetic on SQLite; nothing but this
# gated leg proves the Postgres statement is even syntactically valid, so a skip here is a real
# coverage hole, not a formality.


async def test_cipher_invocations_upsert_is_atomic_and_additive(store) -> None:
    key_id = f"testkey-{uuid4().hex[:12]}"
    assert await store.cipher_invocations(key_id) == 0  # an unknown key reads as zero, never raises

    assert await store.add_cipher_invocations(key_id, 100) == 100  # INSERT arm
    assert await store.add_cipher_invocations(key_id, 50) == 150  # UPDATE arm accumulates
    assert await store.cipher_invocations(key_id) == 150

    # Concurrent adds against one row: the whole point of the atomic upsert is that N processes on the
    # one unified store aggregate rather than clobber. A last-write-wins upsert would land on 151.
    await asyncio.gather(*(store.add_cipher_invocations(key_id, 1) for _ in range(20)))
    assert await store.cipher_invocations(key_id) == 170


async def test_cipher_invocations_are_keyed_per_key_id(store) -> None:
    a = f"testkey-{uuid4().hex[:12]}"
    b = f"testkey-{uuid4().hex[:12]}"
    await store.add_cipher_invocations(a, 7)
    await store.add_cipher_invocations(b, 3)
    # Rotation semantics: a new key_id is an independent row, and the old one is untouched.
    assert await store.cipher_invocations(a) == 7
    assert await store.cipher_invocations(b) == 3


async def test_checkpoint_is_a_noop_without_a_bounded_cipher(store) -> None:
    # The gated fixtures open with the default (identity) cipher, so there is no birthday budget to
    # bound and the checkpoint must return None rather than writing a row.
    assert await store.checkpoint_cipher_invocations() is None


async def test_the_BOUNDED_path_survives_a_keyed_reopen(store) -> None:
    """The bound END TO END on this backend, not just the upsert primitive.

    The fixture above opens with the IDENTITY cipher, so it exercises none of the enable-and-reserve
    inside ``PostgresStore.open``, the close-time settlement, or the persistence across a reopen. A
    keyed handle is the only way those run here at all."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.gcm_bound import GCM_RESERVE_BLOCK
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    k = generate_key()
    cipher = make_cipher(k)
    key_id = cipher.active_key_id
    try:
        keyed = await PostgresStore.open(settings, cipher=cipher)
        try:
            assert cipher.invocation_bound_enabled, (
                "open() must enable + reserve BEFORE the first write"
            )
            assert await keyed.cipher_invocations(key_id) >= GCM_RESERVE_BLOCK
            for _ in range(5):
                await keyed.enqueue_ingress(channel_id="IB", raw=RAW)
            spent = cipher.cumulative_invocations()
            assert 0 < spent < GCM_RESERVE_BLOCK
        finally:
            await keyed.close()  # settles to the exact spend

        reopened_cipher = make_cipher(k)
        reopened = await PostgresStore.open(settings, cipher=reopened_cipher)
        try:
            # The requirement: the KEY's lifetime figure survives the process, on this backend.
            assert reopened_cipher.cumulative_invocations() == spent
            await reopened.enqueue_ingress(channel_id="IB", raw=RAW)
            assert reopened_cipher.cumulative_invocations() > spent
        finally:
            await reopened.close()
    finally:
        # Shared-DB hygiene: drop this test's encrypted rows + counter row (the fixture truncates on
        # entry, but a later keyless open must never meet ciphertext it cannot read).
        cleanup = await PostgresStore.open(settings, cipher=make_cipher(k))
        try:
            async with cleanup._pool.acquire() as conn:
                for table in ("message_events", "queue", "response", "messages"):
                    await conn.execute(f"DELETE FROM {table}")  # FK order: children first
                await conn.execute("DELETE FROM cipher_meta WHERE key_id = $1", key_id)
        finally:
            await cleanup.close()


async def test_session_rotation_contract(store) -> None:
    """ASVS 7.2.4: rotate_session is a pure re-key — old hash dead, every other column carried
    forward, replay and revoked rows refused. Extra-free shared contract, so this leg actually runs
    it rather than importorskip-skipping."""
    from tests._session_rotation_contract import assert_session_rotation_contract

    await assert_session_rotation_contract(store)
