# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SQL Server store behaviour — mirrors the SQLite suite, against a real SQL Server.

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env),
so it's a no-op locally and in normal CI. The CI mssql service-container job sets the env and runs
it for real. Requires the ``sqlserver`` extra (``aioodbc`` + ODBC Driver 18).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from collections.abc import AsyncIterator
from typing import Any
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
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

# The AA acknowledgement MessageFoundry returns to RAW's inbound sender (ADR 0021 "Response Sent") — a
# synthetic ACK frame, never real PHI. Used to exercise record_ack_sent's at-rest PHI fail-safe.
_ACK_AA = "MSH|^~\\&|C|D|A|B|20260101||ACK^A01|MSG1|P|2.5.1\rMSA|AA|MSG1\r"


# claim_fifo_heads' SQL Server path opens with SET LOCK_TIMEOUT 0 (ADR 0066 §9 never-block), so a
# transient lock can fail-close the whole batch to EMPTY-all — by_lane AND rearm both empty, rolled
# back, nothing consumed. That yield is contract-legal but flakes a single-shot assertion. _claim_until
# re-issues past a transient EMPTY-all for the sites that assert a NON-empty outcome; a successful claim
# never retries, and a genuinely-unclaimable head stays EMPTY-all every pass and still fails after the
# cap (masks nothing). Sites that assert EMPTY-all itself (a fenced ex-leader) call claim_fifo_heads
# directly. Mirrors _claim_heads in test_claim_fifo_heads.py (the fix for this same never-block class).
async def _claim_until(store: Any, *args: Any, **kwargs: Any) -> Any:
    res = await store.claim_fifo_heads(*args, **kwargs)
    for _ in range(16):
        if res.by_lane or res.rearm:
            break
        await asyncio.sleep(0.01)
        res = await store.claim_fifo_heads(*args, **kwargs)
    return res


@pytest.fixture
async def store() -> AsyncIterator[object]:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    # Clean slate (the container DB persists across tests in a run).
    async with s._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in (
            "message_events",
            "audit_log",
            "audit_chain_meta",  # #190 audit-chain keying watermark — a keying test (CLI-23) sets it;
            #                      leaving it would fail-close a later keyless record_audit (poison)
            "cipher_meta",  # ASVS 11.3.4 per-key GCM invocation counters (no FK)
            "connection_event",  # #46 lifecycle log (no FK) — ciphered `reason` rows else leak across
            #                      runs and break the key-rotation reencrypt scan (persistent contamination)
            "state",
            "reference",  # ADR 0006 snapshot rows (no FK) — leaked ciphered/plaintext rows break the
            #               exact reencrypt counts (the == 6 in
            #               test_reencrypt_to_active_rotates_all_columns_including_state)
            "reference_version",  # ADR 0006 active-version pointers (no FK)
            "message_attachment",  # #149 attachment linkage (no FK; cleared for a clean slate)
            "attachment_chunk",  # #149 attachment chunks (no FK)
            "attachment",  # #149 attachment headers (no FK)
            "queue",  # FK to messages(id) — must be cleared before messages
            "response",  # FK to messages(id) — must be cleared before messages
            "delivered_keys",  # H2 idempotency ledger (no FK, but ids reference messages)
            "resend_log",  # ADR 0090 idempotency ledger (no FK) — STOREF-8/9 reuse keys across tests
            "alert_instance",  # #56 operator alert-state (no FK) — ALERT-19 lists ALL active rows
            "search_presets",  # ADR 0136 saved searches (no FK) — the ciphered `criteria` rides the
            #                    key-rotation reencrypt scan, and this suite asserts EXACT rotate
            #                    counts (the == 6 / == 2 above), so a preset left behind by one test
            #                    silently miscounts an unrelated one
            "messages",
            "sessions",
            "webauthn_credentials",  # ADR 0068: FK to users(id) — must clear before users
            "user_roles",
            "ad_group_role_map",
            "users",
            "roles",
        ):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    # audit_chain_meta was cleared above; sync the in-memory keying watermark so this keyless fixture
    # handle never carries a stale watermark that would fail-close a later keyless record_audit (#190).
    s._audit_keyed_from = None
    # open() seeded the reference read-through cache BEFORE the clean-slate DELETE above, so re-load it
    # from the now-empty tables — otherwise a prior test's reference rows linger in this handle's
    # in-memory cache/versions and leak across tests (mirrors the Postgres fixture; Track B Step 6).
    await s._load_reference_cache()
    yield s
    await s.close()


async def test_enqueue_creates_message_and_outbox(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p1"), ("OB2", "p2")], control_id="MSG1"
    )
    msg = await store.get_message(mid)
    assert msg is not None and msg["status"] == MessageStatus.RECEIVED.value
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
    # ADR 0028: base64 carriage carries NUL-bearing bytes through the NVARCHAR(MAX) body column, where
    # the latin-1 round-trip it supersedes would be SILENTLY TRUNCATED at the first NUL.
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
    # INGEST-4 twin of the Postgres test (mirrored-pair convention: same name/body, backend-specific
    # comment). SQL Server never RAISED on a NUL — it SILENTLY TRUNCATES the NVARCHAR(MAX) at the first
    # NUL, so pre-fix the ERROR row persisted but the stored raw was cut mid-body (a fidelity defect, not
    # a dropped connection). The fix makes that moot: a NUL-bearing body is carried as ADR 0028 base64, so
    # the ERROR row persists with the EXACT bytes recoverable via raw_bytes — no truncation.
    from messagefoundry.parsing import RawMessage

    runner = RegistryRunner(_ingest4_registry(), store)
    ic = runner.registry.inbound["IB_HL7"]

    for body in (_INGEST4_DECODE_ERR_NUL, _INGEST4_HAPPY_NUL):
        before = {m["id"] for m in await store.list_messages(channel_id="IB_HL7")}
        ack = await runner._handle_inbound(ic, body)  # must NOT raise
        assert ack is not None and "MSA|AR" in ack  # AR NAK
        after = await store.list_messages(channel_id="IB_HL7")
        new = [m for m in after if m["id"] not in before]
        assert len(new) == 1
        erow = new[0]
        assert erow["status"] == MessageStatus.ERROR.value
        raw = (await store.get_message(erow["id"]))["raw"]
        assert "\x00" not in raw and RawMessage(raw, "hl7v2").is_binary
        assert RawMessage(raw, "hl7v2").raw_bytes == body  # full bytes, no NVARCHAR truncation


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


async def test_failure_reschedules_with_backoff(store) -> None:
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    item = (await store.claim_ready(now=200.0))[0]
    await store.mark_failed(
        item.id, "boom", RetryPolicy(max_attempts=3, backoff_seconds=5.0), now=200.0
    )
    outbox = await store.outbox_for(item.message_id)
    assert outbox[0]["status"] == OutboxStatus.PENDING.value
    assert outbox[0]["next_attempt_at"] > 200.0  # rescheduled into the future
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
    # Outbound-only replay -> ROUTED (no pending ingress/routed row); staged parity with SQLite/PG.
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

    # scoped replay leaves the other dead
    assert await store.replay_dead(destination_name="OB1", now=300.0) == 1
    assert await store.count_dead() == 1
    assert (await store.list_dead())[0]["destination_name"] == "OB2"


async def test_content_search_scan_decrypt(store) -> None:
    """ADR 0046 #51 backend parity: scan-and-decrypt content search behaves identically to SQLite —
    metadata pre-filter bounds the scan, the decrypted body matches the needle, field-path resolves,
    and the scan/result caps truncate. (Runs against a real SQL Server in the gated CI leg.)"""
    await store.enqueue_message(
        channel_id="IB_A", raw=_ADT_SEARCH, deliveries=[], control_id="MSG1", message_type="ADT^A01"
    )
    await store.enqueue_message(
        channel_id="IB_B", raw=RAW, deliveries=[], control_id="MSG2", message_type="ADT^A01"
    )
    res = await store.search_messages(make_spec(content="JANE", field_path=None, field_value=None))
    assert res.matched == 1 and res.rows[0]["control_id"] == "MSG1"
    assert "raw" not in res.rows[0]  # metadata-only result
    res2 = await store.search_messages(
        make_spec(content=None, field_path="PID-5.1", field_value="DOE")
    )
    assert res2.matched == 1 and res2.rows[0]["control_id"] == "MSG1"
    res3 = await store.search_messages(
        make_spec(content="ADT", field_path=None, field_value=None), channel_id="IB_A"
    )
    assert res3.scanned == 1 and res3.matched == 1
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
    # Dead-letter (outbound) replay reverts the message ERROR -> ROUTED; staged parity with SQLite/PG.
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
    assert db.messages == 1
    ok, _ = await store.integrity_check()
    assert ok is True


async def test_security_events_for_user_scopes_to_actor(store) -> None:
    # The /me/security-events source on the real backend: only the target actor's auth.* rows,
    # newest-first, honoring limit (TOP); other actors' rows and non-auth.* rows excluded.
    await store.record_audit("auth.login_success", actor="alice", detail="1")
    await store.record_audit("auth.login_failed", actor="bob", detail="b")  # other actor
    await store.record_audit("message_view", actor="alice", detail="x")  # not auth.*
    await store.record_audit("auth.password_changed", actor="alice", detail="2")
    rows = await store.security_events_for_user("alice")
    assert [r["action"] for r in rows] == ["auth.password_changed", "auth.login_success"]
    assert len(await store.security_events_for_user("alice", limit=1)) == 1
    assert len(await store.security_events_for_user("carol")) == 0


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
    # row (actor=None) on the REAL SQL Server backend — proving the NULL-actor tamper row persists +
    # chain-verifies + tees here, not just on SQLite. Reuses the single-source contract from the D3 suite.
    from tests.test_startup_attestation import _assert_startup_attestation_tamper_evidence

    await _assert_startup_attestation_tamper_evidence(store, tmp_path, monkeypatch)


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
    """ADR 0045 custom-roles store contract on the real SQL Server backend (parity with SQLite):
    the additive ``roles.permissions`` column round-trips a custom role's JSON, ``get_role`` exposes
    NULL permissions for a built-in, and ``delete_custom_role`` refuses a built-in / is idempotent.
    Reuses the single source-of-truth assertion from the SQLite suite so the live-server CI leg
    actually catches a SQL Server regression in the new column/methods."""
    from tests.test_custom_roles import _assert_roles_contract

    await _assert_roles_contract(store)


async def test_webauthn_store_contract(store) -> None:
    """ADR 0068 §4 webauthn_credentials contract on the real SQL Server backend: multi-row CRUD,
    the 1023-byte credential-id round-trip (NVARCHAR(MAX) body vs the NVARCHAR(64) digest PK),
    duplicate-label integrity violation, and the strict sign-count compare-and-set under the
    UPDLOCK/ROWLOCK idiom. Extra-free import (the shared module never touches the [webauthn]
    extra, so this leg — which installs .[dev,sqlserver] — actually runs it)."""
    from tests._webauthn_store_contract import _assert_webauthn_store_contract

    await _assert_webauthn_store_contract(store)


async def test_totp_store_contract(store) -> None:
    """WP-14 TOTP store contract on the real SQL Server backend — the backfill that finally
    executes the UPDLOCK row-lock paths (consume_totp_step / consume_recovery_code_hash)."""
    from tests._webauthn_store_contract import _assert_totp_contract

    await _assert_totp_contract(store)


async def test_mark_session_reauthed_reanchors_client(store) -> None:
    """WP-L3-13: mark_session_reauthed(client=) re-anchors the session's client address via COALESCE;
    a None client leaves it unchanged while still refreshing reauth_at. Exercises the new COALESCE
    write (incl. the None-bind) on the real backend — the PR-blocking sql-server leg's coverage of it."""
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


# --- staged pipeline (ADR 0001) — ingress -> routed -> outbound on real SQL Server -------------
# These exercise the concurrency-correct paths the faked-driver tests can't (DELETE...OUTPUT claim
# idempotency, the sp_getapplock finalize serialization, RCSI) against the live container.


async def _ingress_and_claim(store, channel: str, raw: str, now: float = 100.0):
    """enqueue_ingress + claim the ingress row to inflight; returns (message_id, ingress_item)."""
    mid = await store.enqueue_ingress(channel_id=channel, raw=raw, now=now)
    ing = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value, now=now)
    assert ing is not None and ing.stage == Stage.INGRESS.value
    return mid, ing


async def test_staged_flow_end_to_end_processed(store) -> None:
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    assert (await store.get_message(mid))["status"] == MessageStatus.RECEIVED.value
    assert await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    assert rtd is not None and rtd.stage == Stage.ROUTED.value
    assert await store.transform_handoff(
        routed_id=rtd.id, message_id=mid, channel_id="IB", deliveries=[("OB1", "body")], now=100.0
    )
    ob = await store.claim_next_fifo("OB1", stage=Stage.OUTBOUND.value, now=100.0)
    assert ob is not None and ob.payload == "body" and ob.stage == Stage.OUTBOUND.value
    await store.mark_done(ob.id, now=110.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    assert [e["event"] for e in await store.events_for(mid)] == [
        "received",
        "routed",
        "transformed",
        "delivered",
    ]


async def test_all_declined_finalizes_not_deployed(store) -> None:
    """#233 (ADR 0111) parity: a routed message whose only handler declined every Send (each to a
    present-but-not-deployed target) finalizes NOT_DEPLOYED — not FILTERED — carries a ``not_deployed``
    event naming the connection, and queues ZERO outbound rows. The decline is persisted in the SAME
    handoff txn (both SS finalize twins share ``_finalize_from_message_status``), so the finalizer
    distinguishes it from an intentional filter."""
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    await store.transform_handoff(
        routed_id=rtd.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        declined=["OB_OFF"],
        now=100.0,
    )
    assert (await store.get_message(mid))["status"] == MessageStatus.NOT_DEPLOYED.value
    nd = [e["destination"] for e in await store.events_for(mid) if e["event"] == "not_deployed"]
    assert nd == ["OB_OFF"]
    assert await store.outbox_for(mid) == []  # AC-2: not one row in the outbound stage


async def test_declined_sibling_still_processed_event_retained(store) -> None:
    """#233 mixed parity: one deployed delivery + one declined leg → the message finalizes PROCESSED
    once the deployed leg delivers (it DID deliver somewhere — not NOT_DEPLOYED), and the
    ``not_deployed`` event for the skipped leg is still recorded."""
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    await store.transform_handoff(
        routed_id=rtd.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB1", "body")],
        declined=["OB_OFF"],
        now=100.0,
    )
    ob = await store.claim_next_fifo("OB1", stage=Stage.OUTBOUND.value, now=110.0)
    await store.mark_done(ob.id, now=120.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    nd = [e["destination"] for e in await store.events_for(mid) if e["event"] == "not_deployed"]
    assert nd == ["OB_OFF"]


async def test_claim_routed_carries_handler_name(store) -> None:
    # REGRESSION: the routed-stage claim MUST surface handler_name so the transform worker knows which
    # handler to run. A claim whose OUTPUT/SELECT drops the column returns handler_name=None, so the
    # runner dead-letters every routed row ("handler None ... missing"). The store-flow tests never
    # read it (transform_handoff keys off routed_id, not the name), so only the load smoke caught it.
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H_alpha", RAW), ("H_beta", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    # FIFO claim (the transform worker's path) preserves handler-list order and carries the name.
    first = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    assert first is not None and first.handler_name == "H_alpha"
    second = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    assert second is not None and second.handler_name == "H_beta"
    # Deliver one; outbound rows carry no handler_name, and claim_ready must round-trip that NULL too.
    await store.transform_handoff(
        routed_id=first.id, message_id=mid, channel_id="IB", deliveries=[("OB1", "b")], now=100.0
    )
    ob = await store.claim_ready(now=100.0)
    assert len(ob) == 1 and ob[0].destination_name == "OB1" and ob[0].handler_name is None


async def test_handoff_idempotent_second_call_returns_false(store) -> None:
    # The DELETE...OUTPUT claim-readback no-op guard (the @table-var bug would ship green on a fake).
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    kw = dict(ingress_id=ing.id, message_id=mid, channel_id="IB", disposition=MessageStatus.ROUTED)  # noqa: C408
    assert await store.route_handoff(handlers=[("H1", RAW)], now=100.0, **kw)
    assert await store.route_handoff(handlers=[("H1", RAW)], now=100.0, **kw) is False
    rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    tkw = dict(routed_id=rtd.id, message_id=mid, channel_id="IB", deliveries=[("OB1", "b")])  # noqa: C408
    assert await store.transform_handoff(now=100.0, **tkw)
    assert await store.transform_handoff(now=100.0, **tkw) is False


async def test_route_unrouted_no_handlers(store) -> None:
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    assert await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[],
        disposition=MessageStatus.UNROUTED,
        now=100.0,
    )
    assert (await store.get_message(mid))["status"] == MessageStatus.UNROUTED.value
    assert await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0) is None


async def test_transform_filtered_when_no_deliveries(store) -> None:
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    assert await store.transform_handoff(
        routed_id=rtd.id, message_id=mid, channel_id="IB", deliveries=[], now=100.0
    )
    # every handler ran and delivered nothing -> FILTERED
    assert (await store.get_message(mid))["status"] == MessageStatus.FILTERED.value


async def test_finalizer_not_premature_across_sibling_handlers(store) -> None:
    # GATING: a delivered handler must not finalize while a sibling's routed row is still in flight.
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW), ("H2", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    r1 = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    await store.transform_handoff(
        routed_id=r1.id, message_id=mid, channel_id="IB", deliveries=[("OB1", "b1")], now=100.0
    )
    o1 = await store.claim_next_fifo("OB1", stage=Stage.OUTBOUND.value, now=100.0)
    await store.mark_done(o1.id, now=101.0)
    # H2's routed row is still pending -> NOT processed yet
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    r2 = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    await store.transform_handoff(
        routed_id=r2.id, message_id=mid, channel_id="IB", deliveries=[("OB2", "b2")], now=100.0
    )
    o2 = await store.claim_next_fifo("OB2", stage=Stage.OUTBOUND.value, now=100.0)
    await store.mark_done(o2.id, now=102.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_reset_stale_inflight_recovers_all_stages(store) -> None:
    # An inflight ingress/routed row (not just outbound) MUST be re-pended or the message hangs.
    _m1, _i1 = await _ingress_and_claim(store, "IB", RAW)  # ingress inflight
    m2, i2 = await _ingress_and_claim(store, "IB2", RAW)
    await store.route_handoff(
        ingress_id=i2.id,
        message_id=m2,
        channel_id="IB2",
        handlers=[("H", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    await store.claim_next_fifo("IB2", stage=Stage.ROUTED.value, now=100.0)  # routed inflight
    m3, i3 = await _ingress_and_claim(store, "IB3", RAW)
    await store.handoff(
        ingress_id=i3.id,
        message_id=m3,
        channel_id="IB3",
        deliveries=[("OB", "b")],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    await store.claim_next_fifo("OB", stage=Stage.OUTBOUND.value, now=100.0)  # outbound inflight
    assert await store.reset_stale_inflight(now=200.0) == 3


async def test_dead_letter_missing_handlers_errors_the_message(store) -> None:
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("GoneHandler", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    assert await store.dead_letter_missing_handlers({"OtherHandler"}, now=200.0) == 1
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


async def test_transform_state_persists_and_reloads_on_reopen(store) -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    await store.transform_handoff(
        routed_id=rtd.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB", "b")],
        state_ops=[("ns", "k", {"v": 1})],
        now=100.0,
    )
    assert dict(store.state_view())[("ns", "k")] == {"v": 1}
    s2 = await SqlServerStore.open(load_settings(environ=os.environ).store)
    try:
        assert dict(s2.state_view())[("ns", "k")] == {"v": 1}  # _load_state_cache repopulated it
    finally:
        await s2.close()


async def test_concurrent_route_handoff_exactly_one_wins(store) -> None:
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    results = await asyncio.gather(
        *[
            store.route_handoff(
                ingress_id=ing.id,
                message_id=mid,
                channel_id="IB",
                handlers=[("H", RAW)],
                disposition=MessageStatus.ROUTED,
                now=100.0,
            )
            for _ in range(4)
        ]
    )
    assert sum(1 for r in results if r) == 1  # exactly one True; no PK/1205 deadlock escaped


async def test_audit_chain_no_fork_under_concurrent_record_audit(store) -> None:
    await asyncio.gather(
        *[store.record_audit("act", actor="u", detail=f"d{i}", now=100.0 + i) for i in range(25)]
    )
    ok, detail = await store.verify_audit_chain()
    assert ok is True, detail
    count, _head = await store.audit_anchor()
    assert count == 25


async def test_rcsi_enabled_after_open(store) -> None:
    row = await store._fetchone(
        "SELECT is_read_committed_snapshot_on AS r FROM sys.databases WHERE name = DB_NAME()"
    )
    assert row is not None and row["r"] == 1


async def test_purge_message_bodies_blanks_delivered(store) -> None:
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB", "secret-body")],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    ob = await store.claim_next_fifo("OB", stage=Stage.OUTBOUND.value, now=100.0)
    await store.mark_done(ob.id, now=110.0)  # -> PROCESSED, all terminal
    assert await store.purge_message_bodies(older_than=200.0) == 1
    assert (await store.get_message(mid))["raw"] == ""  # blanked, not deleted


async def _set_meta_ss(store, message_id: str, bag: dict) -> None:
    """Attach a metadata bag the way transform_handoff does (encrypted, cell-AAD bound)."""
    async with store._acquire() as conn, store._cursor(conn) as cur:
        await cur.execute(
            "UPDATE messages SET metadata=? WHERE id=?",
            (
                store._enc(json.dumps(bag), aad=cell_aad("messages", "metadata", message_id)),
                message_id,
            ),
        )
        await store._commit(conn)


async def _terminal_message(store, *, control: str = "CID-M", now: float = 100.0) -> str:
    """Drive one message all the way to terminal (every queue row DONE) and return its id."""
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB", "secret-body")],
        disposition=MessageStatus.ROUTED,
        now=now,
    )
    ob = await store.claim_next_fifo("OB", stage=Stage.OUTBOUND.value, now=now)
    await store.mark_done(ob.id, now=now + 10.0)
    return mid


async def test_purge_nulls_metadata_with_the_body(store) -> None:
    """ASVS 14.2.7 parity on SQL Server — metadata is NULLed by the same widened statement."""
    mid = await _terminal_message(store)
    await _set_meta_ss(store, mid, {"user": {"mrn": "MRN001"}})
    assert await store.message_metadata_json(mid) is not None

    assert await store.purge_message_bodies(older_than=200.0) == 1

    assert await store.message_metadata_json(mid) is None


async def test_purge_search_presets_ss(store) -> None:
    """ASVS 14.2.7 Tier 2 parity on SQL Server: old presets purged, new kept, second pass a no-op.

    Cleans up after itself even on failure — `search_presets` rides the key-rotation reencrypt scan and
    this suite asserts EXACT rotate counts, so a leaked row would red an unrelated test. That matters
    more here than on Postgres: a pyodbc native crash re-runs this WHOLE file (retry-native-crash.sh)
    against a DB that would still hold the leftovers.
    """
    try:
        await store.upsert_search_preset(
            preset_id="ss-stale", owner="alice", name="stale", criteria="{}", now=0.0
        )
        await store.upsert_search_preset(
            preset_id="ss-fresh", owner="alice", name="fresh", criteria="{}", now=40 * DAY
        )

        assert await store.purge_search_presets(older_than=30 * DAY) == 1

        assert {r["name"] for r in await store.list_search_presets("alice")} == {"fresh"}
        assert await store.purge_search_presets(older_than=30 * DAY) == 0  # idempotent
    finally:
        async with store._acquire() as conn, store._cursor(conn) as cur:
            await cur.execute("DELETE FROM search_presets")
            await store._commit(conn)


async def test_search_preset_retention_keys_on_last_used_ss(store) -> None:
    """#306 parity on SQL Server: a RECALLED-but-unedited preset survives; NULL `last_used_at` still ages.

    T-SQL has no portable GREATEST (2022+ only, floor is 2016 SP1), so the greatest-of-two is spelled
    as `updated_at < cutoff AND (last_used_at IS NULL OR last_used_at < cutoff)`. This pins BOTH arms:
    the recall arm and the NULL (pre-column migration) arm. Cleans up after itself (see above).
    """
    try:
        for pid, name in (("ss-used", "used"), ("ss-idle", "idle"), ("ss-legacy", "legacy")):
            await store.upsert_search_preset(
                preset_id=pid, owner="alice", name=name, criteria="{}", now=0.0
            )
        # The recall stamps last_used_at past the cutoff...
        got = await store.get_search_preset(preset_id="ss-used", owner="alice", now=40 * DAY)
        assert got is not None and got["last_used_at"] is None  # PRE-stamp snapshot
        row = await store._fetchone("SELECT last_used_at FROM search_presets WHERE id='ss-used'")
        assert row is not None and row["last_used_at"] == 40 * DAY
        # ...while the migration row is explicitly NULL (the post-ALTER state).
        await store._execute("UPDATE search_presets SET last_used_at=NULL WHERE id='ss-legacy'")

        assert await store.purge_search_presets(older_than=30 * DAY) == 2  # idle + legacy

        assert {r["name"] for r in await store.list_search_presets("alice")} == {"used"}
    finally:
        async with store._acquire() as conn, store._cursor(conn) as cur:
            await cur.execute("DELETE FROM search_presets")
            await store._commit(conn)


async def test_purge_sweeps_pre_upgrade_metadata_via_the_temp_eligible_table(store) -> None:
    """The upgrade case, and the proof the widened statement still reads connection-scoped #eligible.

    A row purged by a pre-upgrade engine has a blank `raw` but live `metadata`; the
    `raw <> '' OR metadata IS NOT NULL` guard must still find it THROUGH `#eligible`, which is created
    without params so it lives at connection scope rather than being scoped to an sp_executesql call.
    """
    mid = await _terminal_message(store)
    assert await store.purge_message_bodies(older_than=200.0) == 1  # the pre-upgrade purge
    await _set_meta_ss(store, mid, {"user": {"mrn": "MRN001"}})
    assert (await store.get_message(mid))["raw"] == ""

    assert await store.purge_message_bodies(older_than=200.0) == 1  # counted → audited

    assert await store.message_metadata_json(mid) is None
    assert await store.purge_message_bodies(older_than=200.0) == 0  # idempotent once both blank


async def test_transform_handoff_crash_between_statements_rolls_back(store, monkeypatch) -> None:
    # The at-least-once invariant: a handoff is ONE txn. Abort after produce, before finalize/commit,
    # and assert nothing leaked (routed row recovered, no orphan outbound/state, no cache leak).
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)

    async def boom(*a, **k):
        raise RuntimeError("simulated crash before commit")

    monkeypatch.setattr(store, "_maybe_finalize", boom)
    with pytest.raises(RuntimeError):
        await store.transform_handoff(
            routed_id=rtd.id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB", "b")],
            state_ops=[("ns", "k", 1)],
            now=100.0,
        )
    monkeypatch.undo()
    assert ("ns", "k") not in dict(store.state_view())  # post-commit-only cache; no leak
    rows = await store._fetchall("SELECT stage, status FROM queue WHERE message_id=?", (mid,))
    pairs = {(r["stage"], r["status"]) for r in rows}
    assert (Stage.OUTBOUND.value, OutboxStatus.PENDING.value) not in pairs  # no orphan outbound
    assert (Stage.ROUTED.value, OutboxStatus.INFLIGHT.value) in pairs  # consumed row rolled back
    # recover + a clean re-run delivers exactly once
    assert await store.reset_stale_inflight(now=200.0) >= 1
    rtd2 = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=200.0)
    assert await store.transform_handoff(
        routed_id=rtd2.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB", "b")],
        state_ops=[("ns", "k", 1)],
        now=200.0,
    )
    ob = await store.claim_next_fifo("OB", stage=Stage.OUTBOUND.value, now=200.0)
    await store.mark_done(ob.id, now=210.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_reencrypt_to_active_rotates_all_columns_including_state(store) -> None:
    # GATING: key rotation must rotate messages.raw + queue.payload + state.value, or transform state
    # is silently lost after the retired key is dropped.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    k1, k2 = b"k" * 32, b"K" * 32
    old = await SqlServerStore.open(settings, cipher=AesGcmCipher(k1))
    try:
        mid, ing = await _ingress_and_claim(old, "IB", RAW)
        await old.route_handoff(
            ingress_id=ing.id,
            message_id=mid,
            channel_id="IB",
            handlers=[("H", RAW)],
            disposition=MessageStatus.ROUTED,
            now=100.0,
        )
        rtd = await old.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
        await old.transform_handoff(
            routed_id=rtd.id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB", "body")],
            state_ops=[("ns", "k", {"v": 1})],
            now=100.0,
        )
    finally:
        await old.close()

    # Assert against the very cipher that does the rewriting, via the marker prefix IT writes — so the
    # check pins marker + version + key id together (and the alg too, on v2) and stays right whatever
    # at-rest format is active. The `== 6` below is the independent proof that rotation really ran.
    active_cipher = AesGcmCipher(k2, retired_keys=[k1])
    rotated = await SqlServerStore.open(settings, cipher=active_cipher)
    try:
        # messages.raw + the outbound queue.payload + state.value (3 core) + the 3 lifecycle-event
        # message_events.detail rows this flow writes — all now ciphered under H4 — = 6 under the
        # retired key (H4 added error/last_error/detail to the rotation; here only the event details
        # are populated). The dedicated H4 columns get their own check in
        # test_reencrypt_rotates_error_lasterror_detail.
        assert await rotated.reencrypt_to_active() == 6
        blobs = await rotated._fetchall(
            "SELECT value AS v FROM state"
            " UNION ALL SELECT raw FROM messages"
            " UNION ALL SELECT payload FROM queue WHERE payload <> ''"
        )
        for r in blobs:
            assert r["v"].startswith(active_cipher.active_marker_prefix), r["v"]
        assert dict(rotated.state_view())[("ns", "k")] == {"v": 1}  # still decrypts
        assert await rotated.reencrypt_to_active() == 0  # idempotent
    finally:
        # #241 F2: this test leaves state.value ciphered under k2 (+ the message/queue rows). Purge them
        # with this still-open keyed handle BEFORE closing, so the next KEYLESS `store` fixture open does
        # not fail-close inside _load_state_cache — SqlServerStore.open eagerly warms the state cache
        # during open(), before the fixture's clean-slate DELETE can run. (Postgres has no analogue of
        # this state-rotating test, so its suite never hit this cascade.)
        try:
            async with rotated._pool.acquire() as conn:
                cur = await conn.cursor()
                for table in ("message_events", "state", "response", "queue", "messages"):
                    await cur.execute(f"DELETE FROM {table}")
                await conn.commit()
        finally:
            await rotated.close()


async def test_replay_two_mode_recover_then_resend(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p1"), ("OB2", "p2")], now=100.0
    )
    d1 = (await store.claim_ready(now=100.0, destination_name="OB1"))[0]
    d2 = (await store.claim_ready(now=100.0, destination_name="OB2"))[0]
    await store.mark_done(d1.id, now=110.0)
    await store.mark_failed(d2.id, "boom", RetryPolicy(max_attempts=1), now=110.0)  # -> dead
    # recover mode: a dead row exists -> re-pend ONLY it; the DONE sibling is NOT re-fired (M-2)
    assert await store.replay(mid, now=200.0) == 1
    by = {r["destination_name"]: r for r in await store.outbox_for(mid)}
    assert by["OB1"]["status"] == OutboxStatus.DONE.value
    assert by["OB2"]["status"] == OutboxStatus.PENDING.value
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    # finish OB2 -> fully delivered -> resend mode re-pends BOTH done rows
    o2 = await store.claim_next_fifo("OB2", stage=Stage.OUTBOUND.value, now=200.0)
    await store.mark_done(o2.id, now=210.0)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    assert await store.replay(mid, now=300.0) == 2


async def test_dead_letter_missing_destinations_errors_the_message(store) -> None:
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("GoneDest", "b")],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    assert await store.dead_letter_missing_destinations({"OtherDest"}, now=200.0) == 1
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


async def test_cancel_queued_finalizes_via_batch_lock(store) -> None:
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB", "b")],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    assert await store.cancel_queued(None, "OB", now=200.0) == 1
    assert (await store.outbox_for(mid))[0]["status"] == OutboxStatus.CANCELLED.value
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


# --- query/response (ADR 0013) — capture, correlate, re-ingress on real SQL Server ------------


async def _delivered_outbound(store, channel: str = "IB", dest: str = "OB", now: float = 100.0):
    """A message with one claimed outbound delivery (ready for complete_with_response)."""
    mid = await store.enqueue_message(
        channel_id=channel, raw=RAW, deliveries=[(dest, "req")], now=now
    )
    item = await store.claim_next_fifo(dest, stage=Stage.OUTBOUND.value, now=now)
    assert item is not None
    return mid, item


async def test_complete_with_response_captures_and_finalizes(store) -> None:
    mid, item = await _delivered_outbound(store)
    await store.complete_with_response(
        item.id, body="ACK^AA", outcome="ok", detail="all good", now=110.0
    )
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    resps = await store.correlate_response(mid)
    assert len(resps) == 1
    r = resps[0]
    assert r.destination_name == "OB" and r.response_seq == 1 and r.outcome == "ok"
    assert r.body == "ACK^AA" and r.detail == "all good"  # both decrypted (both ciphertext at rest)


async def test_correlate_orders_by_seq_and_decrypts(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB", "a"), ("OB", "b")], now=100.0
    )
    i1 = await store.claim_next_fifo("OB", stage=Stage.OUTBOUND.value, now=100.0)
    i2 = await store.claim_next_fifo("OB", stage=Stage.OUTBOUND.value, now=100.0)
    await store.complete_with_response(i1.id, body="first", outcome="ok", now=110.0)
    await store.complete_with_response(i2.id, body="second", outcome="ok", now=120.0)
    resps = await store.correlate_response(mid)
    assert [r.response_seq for r in resps] == [1, 2]  # 1+MAX per (message,dest), latest last
    assert [r.body for r in resps] == ["first", "second"]


# --- ADR 0021 "Response Sent" inbound ACK capture parity (MLLP-20) -----------------------------
# record_ack_sent's PHI fail-safe on the SERVER store — mirrors tests/test_ack_sent_store.py (SQLite):
# an AA body is stored ONLY when the store is encrypted and is ciphertext at rest; a NAK never stores a
# body; the ack_sent row surfaces under a sentinel destination without disturbing outbound reply order.


async def test_record_ack_sent_aa_body_encrypted_at_rest_ss(store) -> None:
    # (1) An AA ack_body is persisted only on an ENCRYPTED store, and on disk it is ciphertext: it
    # carries the mfenc: marker, is not the plaintext AA frame, and decrypts back to exactly it. A
    # second, ciphered handle is needed because the fixture store is the identity cipher (unencrypted)
    # — mirrors the existing at-rest encryption tests in this file.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    cipher = make_cipher(generate_key())  # held so we can assert the decrypt round-trip below
    s = await SqlServerStore.open(settings, cipher=cipher)
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
        # destination_name + response_seq come back alongside the body: they are the row half of the
        # cell AAD the store binds it under (sqlserver.py record_ack_sent), and destination_name is a
        # SENTINEL ("\x1fack:" + inbound_name), so read it rather than reconstructing it here.
        row = await s._fetchone(
            "SELECT body, destination_name, response_seq FROM response"
            " WHERE message_id=? AND kind=?",
            (mid, "ack_sent"),
        )
        disk = row["body"]
        assert disk.startswith(MARKER_PREFIX)  # stored under the encrypted marker, not in the clear
        assert disk != _ACK_AA
        # Decrypt under the SAME cell AAD the store wrote with (ASVS 11.3.3 / ADR 0019): a v2 value is
        # bound to its (table, column, row) cell, so a bare decrypt fails closed on one. Harmless on a
        # v1 value — that reader ignores the caller's aad by design (dual-read).
        aad = cell_aad("response", "body", mid, row["destination_name"], row["response_seq"])
        assert cipher.decrypt(disk, aad=aad) == _ACK_AA  # and it genuinely encrypts the AA frame
    finally:
        await s.close()


async def test_record_ack_sent_nak_stores_no_body_ss(store) -> None:
    # (2) PHI fail-safe: a NAK passes ack_body=None → body is always NULL on disk (even on an ENCRYPTED
    # store), and the offending field value lives only in the safe_text-scrubbed detail. The ciphered
    # handle proves the NULL is the fail-safe itself, not merely the unencrypted-store behaviour.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings, cipher=make_cipher(generate_key()))
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
                "SELECT body FROM response WHERE message_id=? AND kind=?", (mid, "ack_sent")
            )
        )["body"]
        assert disk is None
    finally:
        await s.close()


async def test_record_ack_sent_sentinel_disjoint_from_outbound_ss(store) -> None:
    # (3) The ack_sent row sorts under a sentinel destination (\x1fack:<inbound>) disjoint from every
    # real destination, so an outbound reply's per-destination ordering is untouched and the seqs are
    # kind-scoped. Runs on the default (unencrypted) fixture handle, which ALSO exercises the fail-safe
    # that an AA body is not stored in the clear on an unencrypted store.
    mid, item = await _delivered_outbound(store)
    await store.complete_with_response(item.id, body="PARTNER-REPLY", outcome="ok", now=110.0)
    await store.record_ack_sent(
        message_id=mid,
        inbound_name="IB",
        ack_body=_ACK_AA,
        ack_code="AA",
        ack_phase="ingest",
        outcome="accepted",
    )
    by_kind = {r.kind: r for r in await store.correlate_response(mid)}
    assert by_kind["response"].destination_name == "OB"
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


async def test_reingress_happy_path(store) -> None:
    from messagefoundry.store.store import MessageStore

    mid, item = await _delivered_outbound(store)
    await store.complete_with_response(
        item.id, body="MSH|reply", outcome="ok", reingress_to="LOOP", now=110.0
    )
    # the pending RESPONSE token holds the origin non-terminal
    assert (await store.get_message(mid))["status"] != MessageStatus.PROCESSED.value
    token = await store.claim_next_fifo("LOOP", stage=Stage.RESPONSE.value, now=110.0)
    assert token is not None and token.stage == Stage.RESPONSE.value
    assert await store.response_body_for_work_row(token.id) == "MSH|reply"
    assert await store.ingress_handoff(
        response_row_id=token.id,
        loopback_channel_id="LOOP",
        correlation_depth_cap=10,
        control_id=None,
        message_type=None,
        summary=None,
        now=110.0,
    )
    # the re-ingress child exists under the canonical content-addressed id, RECEIVED, with lineage
    child_id = MessageStore._reingress_message_id(mid, "OB", 1, "MSH|reply")
    child = await store.get_message(child_id)
    assert child is not None and child["status"] == MessageStatus.RECEIVED.value
    assert child["raw"] == "MSH|reply"
    ing = await store.claim_next_fifo("LOOP", stage=Stage.INGRESS.value, now=110.0)
    assert ing is not None and ing.message_id == child_id  # child queued on the loopback lane
    # token consumed -> origin finalizes PROCESSED
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_reingress_idempotent_rerun(store) -> None:
    mid, item = await _delivered_outbound(store)
    await store.complete_with_response(
        item.id, body="reply", outcome="ok", reingress_to="LOOP", now=110.0
    )
    token = await store.claim_next_fifo("LOOP", stage=Stage.RESPONSE.value, now=110.0)
    kw = dict(  # noqa: C408
        response_row_id=token.id,
        loopback_channel_id="LOOP",
        correlation_depth_cap=10,
        control_id=None,
        message_type=None,
        summary=None,
        now=110.0,
    )
    assert await store.ingress_handoff(**kw) is True
    assert await store.ingress_handoff(**kw) is False  # token consumed -> guarded no-op


async def test_reingress_corrupt_ref_dead_letters(store) -> None:
    mid, item = await _delivered_outbound(store)
    await store.complete_with_response(
        item.id, body="reply", outcome="ok", reingress_to="LOOP", now=110.0
    )
    token = await store.claim_next_fifo("LOOP", stage=Stage.RESPONSE.value, now=110.0)
    # tamper the token ref to something unparseable (no US separator)
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute("UPDATE queue SET payload=? WHERE id=?", ("garbage-no-sep", token.id))
        await conn.commit()
    assert (
        await store.ingress_handoff(
            response_row_id=token.id,
            loopback_channel_id="LOOP",
            correlation_depth_cap=10,
            control_id=None,
            message_type=None,
            summary=None,
            now=110.0,
        )
        is True
    )  # consumed (dead-lettered), never re-looped
    assert (await store.get_message(mid))[
        "status"
    ] == MessageStatus.ERROR.value  # a DEAD row -> ERROR


async def test_reingress_depth_cap_dead_letters(store) -> None:
    mid, item = await _delivered_outbound(store)
    await store.complete_with_response(
        item.id, body="reply", outcome="ok", reingress_to="LOOP", now=110.0
    )
    token = await store.claim_next_fifo("LOOP", stage=Stage.RESPONSE.value, now=110.0)
    # cap=0 -> child_depth (0+1) > 0 -> depth-cap dead-letter
    assert (
        await store.ingress_handoff(
            response_row_id=token.id,
            loopback_channel_id="LOOP",
            correlation_depth_cap=0,
            control_id=None,
            message_type=None,
            summary=None,
            now=110.0,
        )
        is True
    )
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


async def test_response_rotation_and_purge(store) -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher, _fingerprint
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    k1, k2 = b"r" * 32, b"R" * 32
    old = await SqlServerStore.open(settings, cipher=AesGcmCipher(k1))
    try:
        mid, item = await _delivered_outbound(old)
        await old.complete_with_response(
            item.id, body="secret-reply", outcome="ok", detail="secret-detail", now=110.0
        )
    finally:
        await old.close()

    # Assert through the rotating cipher's own marker prefix, not a hand-rolled split of one field —
    # the shipped accessor tracks whatever at-rest format the writer emits (v1 pins marker+version+key
    # id; v2 pins the alg too). Paired with the retired fingerprint's ABSENCE, which is derived from a
    # DIFFERENT property (_fingerprint, not active_marker_prefix) so the two still cross-check: were
    # the prefix ever to go over-broad, rotation would silently no-op and startswith pass vacuously.
    retired_id = _fingerprint(k1)
    active_cipher = AesGcmCipher(k2, retired_keys=[k1])
    rotated = await SqlServerStore.open(settings, cipher=active_cipher)
    try:
        await rotated.reencrypt_to_active()  # rotates response.body + detail (among others)
        blobs = await rotated._fetchall("SELECT body, detail FROM response")
        assert blobs, "expected a rotated response row"
        for b in blobs:
            for v in (b["body"], b["detail"]):
                assert v.startswith(active_cipher.active_marker_prefix), v
                assert retired_id not in v
        r = (await rotated.correlate_response(mid))[0]
        assert (
            r.body == "secret-reply" and r.detail == "secret-detail"
        )  # still decrypts post-rotation
    finally:
        await rotated.close()

    purged = await SqlServerStore.open(settings, cipher=AesGcmCipher(k2, retired_keys=[k1]))
    try:
        await purged.purge_message_bodies(older_than=10_000.0)
        r = (await purged.correlate_response(mid))[0]
        assert (
            r.body is None and r.detail is None
        )  # purged to NULL -> None on read (PG/SQLite parity)
    finally:
        await purged.close()


async def test_reingress_peek_failed_errors_child_and_skips_ingress(store) -> None:
    from messagefoundry.store.store import MessageStore

    mid, item = await _delivered_outbound(store)
    await store.complete_with_response(
        item.id, body="bad-body", outcome="ok", reingress_to="LOOP", now=110.0
    )
    token = await store.claim_next_fifo("LOOP", stage=Stage.RESPONSE.value, now=110.0)
    assert (
        await store.ingress_handoff(
            response_row_id=token.id,
            loopback_channel_id="LOOP",
            correlation_depth_cap=10,
            control_id=None,
            message_type=None,
            summary=None,
            peek_failed=True,
            now=110.0,
        )
        is True
    )
    child_id = MessageStore._reingress_message_id(mid, "OB", 1, "bad-body")
    child = await store.get_message(child_id)
    # child is persisted (counted) but ERROR, and NO ingress row is queued (no downstream work)
    assert child is not None and child["status"] == MessageStatus.ERROR.value
    assert child["error"] == "re-ingress body failed HL7 peek"
    assert await store.claim_next_fifo("LOOP", stage=Stage.INGRESS.value, now=110.0) is None
    # token still consumed -> origin finalizes
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_reencrypt_skips_null_response_detail(store) -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher, _fingerprint
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    k1, k2 = b"n" * 32, b"N" * 32
    old = await SqlServerStore.open(settings, cipher=AesGcmCipher(k1))
    try:
        mid, item = await _delivered_outbound(old)
        # detail=None (the common case) -> response.detail stored NULL
        await old.complete_with_response(item.id, body="reply-body", outcome="ok", now=110.0)
    finally:
        await old.close()

    retired_id = _fingerprint(k1)
    active_cipher = AesGcmCipher(k2, retired_keys=[k1])
    rotated = await SqlServerStore.open(settings, cipher=active_cipher)
    try:
        await rotated.reencrypt_to_active()  # must not crash on / mis-handle the NULL detail
        row = (await rotated._fetchall("SELECT body, detail FROM response"))[0]
        assert row["detail"] is None  # NULL skipped (IS NOT NULL guard), not crashed
        # The row itself was NOT skipped: body carries the rotating cipher's active marker prefix,
        # and no longer the retired fingerprint (checked off _fingerprint, so it cross-checks the
        # prefix rather than restating it — an over-broad prefix would make startswith vacuous).
        assert row["body"].startswith(active_cipher.active_marker_prefix)
        assert retired_id not in row["body"]
        r = (await rotated.correlate_response(mid))[0]
        assert r.body == "reply-body" and r.detail is None
    finally:
        await rotated.close()


# --- EF-3: summary + metadata (MRN + patient name) encrypted at rest ---------


async def test_summary_metadata_encrypted_at_rest_and_decrypt(store) -> None:
    """EF-3: summary/metadata (direct MRN + patient name) ciphered at rest on SQL Server and
    decrypt on the detail + tracking-list read paths — parity with the SQLite/PG suites."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    summary, metadata = "MRN=999001 NAME=DOE^JANE", '{"site": "WESTWING"}'
    s = await SqlServerStore.open(settings, cipher=AesGcmCipher(b"k" * 32))
    try:
        mid = await s.enqueue_message(
            channel_id="IB", raw=RAW, deliveries=[("OB", "p")], summary=summary, metadata=metadata
        )
        # at rest: ciphertext, with no MRN/name/site visible in the blob.
        row = (await s._fetchall("SELECT summary, metadata FROM messages WHERE id=?", (mid,)))[0]
        assert row["summary"].startswith(MARKER_PREFIX) and "999001" not in row["summary"]
        assert row["metadata"].startswith(MARKER_PREFIX) and "WESTWING" not in row["metadata"]
        # decrypt on the read paths.
        rec = await s.get_message(mid)
        assert rec["summary"] == summary and rec["metadata"] == metadata
        assert any(
            m["summary"] == summary and m["metadata"] == metadata for m in await s.list_messages()
        )
    finally:
        await s.close()


async def test_reencrypt_rotates_summary_and_metadata(store) -> None:
    """EF-3: summary/metadata are rotated under the active key like the body — not stranded under a
    retired key (which a later retired-key drop would make undecryptable)."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher, _fingerprint
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    k1, k2 = b"k" * 32, b"K" * 32
    summary, metadata = "MRN=42 NAME=ROE^RICH", '{"site": "EAST"}'
    old = await SqlServerStore.open(settings, cipher=AesGcmCipher(k1))
    try:
        await old.enqueue_message(
            channel_id="IB", raw=RAW, deliveries=[], summary=summary, metadata=metadata
        )
    finally:
        await old.close()

    retired_id = _fingerprint(k1)
    active_cipher = AesGcmCipher(k2, retired_keys=[k1])
    rotated = await SqlServerStore.open(settings, cipher=active_cipher)
    try:
        await rotated.reencrypt_to_active()
        row = (await rotated._fetchall("SELECT summary, metadata FROM messages"))[0]
        # Under the ACTIVE key in the ACTIVE marker format — the prefix the rotating cipher writes —
        # and no longer under the retired one. The second check comes off _fingerprint, not
        # active_marker_prefix, so it independently proves rotation ran rather than restating it.
        for v in (row["summary"], row["metadata"]):
            assert v.startswith(active_cipher.active_marker_prefix), v
            assert retired_id not in v
        [m] = await rotated.list_messages()
        assert (
            m["summary"] == summary and m["metadata"] == metadata
        )  # still decrypts under the new key
    finally:
        await rotated.close()


# --- H4: error / last_error / message_events.detail encrypted at rest ----------
# SQL Server parity with SQLite/Postgres: the three nullable disposition-text columns route through the
# SAME store cipher — at-rest ciphertext in whichever mfenc format that cipher writes, decrypt-on-read,
# rotated on rekey, and legacy plaintext migrated on open. (Naming a version here would be wrong: these
# tests hand the store a make_cipher() handle, whose writer default is still the frozen v1; the SHIPPED
# store builds its cipher via build_cipher with write_v2=[store].aad_bind, now on. The claim is which
# columns are enciphered, which holds either way.) The prior "SQL Server keeps these plaintext"
# residual is retired.


async def test_error_lasterror_detail_encrypted_at_rest_and_decrypt(store) -> None:
    """H4: messages.error / queue.last_error / message_events.detail are ciphertext at rest on SQL
    Server and decrypt on every read path — parity with the SQLite/PG suites. Error strings are plain
    (no HL7 delimiters) so safe_text leaves them intact and the round-trip is exact."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings, cipher=AesGcmCipher(b"k" * 32))
    try:
        # messages.error (record_received) + message_events.detail (the "error" event row).
        err = "bad parse error from upstream"
        eid = await s.record_received(
            channel_id="IB", raw=RAW, status=MessageStatus.ERROR, error=err
        )
        # queue.last_error (mark_failed -> dead) + a "dead" message_events.detail.
        mid = await s.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=100.0)
        item = (await s.claim_ready(now=100.0))[0]
        fail = "delivery refused by partner endpoint"
        await s.mark_failed(item.id, fail, RetryPolicy(max_attempts=1), now=110.0)  # -> DEAD

        # AT REST: every value is mfenc:... ciphertext — the cleartext phrase never appears in the col.
        # (Version-agnostic per the section header: the marker version belongs to the cipher, not to
        # this claim — v1 here, v2 via build_cipher/[store].aad_bind or MEFOR_TEST_FORCE_AAD_BIND.)
        erow = (await s._fetchall("SELECT error FROM messages WHERE id=?", (eid,)))[0]
        assert erow["error"].startswith(MARKER_PREFIX) and "bad parse" not in erow["error"]
        qrow = (await s._fetchall("SELECT last_error FROM queue WHERE message_id=?", (mid,)))[0]
        assert qrow["last_error"].startswith(MARKER_PREFIX) and "refused" not in qrow["last_error"]
        drows = await s._fetchall(
            "SELECT detail FROM message_events WHERE detail IS NOT NULL ORDER BY id"
        )
        assert drows, "expected at least one event with a detail"
        for d in drows:
            assert d["detail"].startswith(MARKER_PREFIX)  # no plaintext detail at rest
            assert "bad parse" not in d["detail"] and "refused" not in d["detail"]

        # DECRYPT ON READ: every read path returns the cleartext.
        assert (await s.get_message(eid))["error"] == err
        assert any(m["error"] == err for m in await s.list_messages())
        [dead] = await s.list_dead()
        assert dead["last_error"] == fail
        assert all(o["last_error"] == fail for o in await s.outbox_for(mid))
        events = await s.events_for(eid)
        assert any(e["detail"] == err for e in events)  # the "error" event detail decrypts
    finally:
        await s.close()


async def test_reencrypt_rotates_error_lasterror_detail(store) -> None:
    """H4: the three disposition-text columns are rotated to the active key on rekey like the body —
    not stranded under a retired key (which a later retired-key drop would make undecryptable)."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher, _fingerprint
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    k1, k2 = b"k" * 32, b"K" * 32
    err, fail = "bad parse rotated", "delivery rotated failure"
    old = await SqlServerStore.open(settings, cipher=AesGcmCipher(k1))
    try:
        await old.record_received(channel_id="IB", raw=RAW, status=MessageStatus.ERROR, error=err)
        await old.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=100.0)
        item = (await old.claim_ready(now=100.0))[0]
        await old.mark_failed(item.id, fail, RetryPolicy(max_attempts=1), now=110.0)  # -> DEAD
    finally:
        await old.close()

    retired_id = _fingerprint(k1)
    active_cipher = AesGcmCipher(k2, retired_keys=[k1])
    rotated = await SqlServerStore.open(settings, cipher=active_cipher)
    try:
        await rotated.reencrypt_to_active()
        # every non-null disposition-text value now carries the ACTIVE key id, in whichever marker
        # format the rotating cipher writes (active_marker_prefix spans marker + version + fingerprint,
        # plus the alg on v2) — and none still carries the RETIRED fingerprint. That second check is
        # derived from _fingerprint rather than the prefix, so it cross-checks rotation actually ran.
        blobs = await rotated._fetchall(
            "SELECT error AS v FROM messages WHERE error IS NOT NULL"
            " UNION ALL SELECT last_error FROM queue WHERE last_error IS NOT NULL"
            " UNION ALL SELECT detail FROM message_events WHERE detail IS NOT NULL"
        )
        assert blobs, "expected rotated disposition-text values"
        for r in blobs:
            assert r["v"].startswith(active_cipher.active_marker_prefix), r["v"]
            assert retired_id not in r["v"], r["v"]
        # still decrypts under the new key on the read paths.
        assert any(m["error"] == err for m in await rotated.list_messages())
        assert (await rotated.list_dead())[0]["last_error"] == fail
        assert await rotated.reencrypt_to_active() == 0  # idempotent
    finally:
        await rotated.close()


async def test_legacy_plaintext_error_detail_migrated_on_open(store) -> None:
    """H4: a no-key -> key restart encrypts legacy plaintext error/last_error/detail in place via
    _encrypt_existing_rows (the message_events.detail pass is keyed on the INT IDENTITY id). After the
    keyed open, the at-rest columns are ciphertext and reads still return the original cleartext."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    err, fail = "legacy bad parse", "legacy delivery failure"
    # (1) Keyless (identity cipher): values land as PLAINTEXT at rest.
    plain = await SqlServerStore.open(settings)
    try:
        eid = await plain.record_received(
            channel_id="IB", raw=RAW, status=MessageStatus.ERROR, error=err
        )
        mid = await plain.enqueue_message(
            channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=100.0
        )
        item = (await plain.claim_ready(now=100.0))[0]
        await plain.mark_failed(item.id, fail, RetryPolicy(max_attempts=1), now=110.0)
        # sanity: stored plaintext (no cipher prefix) before the migration runs. A NEGATIVE assert, so
        # it must exclude EVERY marker version — a v1-only spelling would pass on an encrypted v2 value.
        erow = (await plain._fetchall("SELECT error FROM messages WHERE id=?", (eid,)))[0]
        assert erow["error"] == err and not erow["error"].startswith(MARKER_PREFIX)
    finally:
        await plain.close()

    # (2) Re-open WITH a key: open() runs _encrypt_existing_rows and migrates the legacy plaintext.
    keyed = await SqlServerStore.open(settings, cipher=AesGcmCipher(b"k" * 32))
    try:
        erow = (await keyed._fetchall("SELECT error FROM messages WHERE id=?", (eid,)))[0]
        assert erow["error"].startswith(MARKER_PREFIX) and "bad parse" not in erow["error"]
        qrow = (await keyed._fetchall("SELECT last_error FROM queue WHERE message_id=?", (mid,)))[0]
        assert qrow["last_error"].startswith(MARKER_PREFIX)
        drows = await keyed._fetchall("SELECT detail FROM message_events WHERE detail IS NOT NULL")
        assert drows and all(d["detail"].startswith(MARKER_PREFIX) for d in drows)
        # reads still return the original cleartext after the in-place migration.
        assert (await keyed.get_message(eid))["error"] == err
        assert (await keyed.list_dead())[0]["last_error"] == fail
    finally:
        await keyed.close()


# --- ADR 0006 reference snapshots (BACKLOG #235) — the T-SQL port proof --------------------------
# Mirrors the Postgres suite (test_postgres_store.py) + the SQLite donor (test_reference_sets.py),
# plus the T-SQL-only seams: the UTF-16 NVARCHAR(450) width guard, the BIN2 collation, and the
# no-key -> key `_encrypt_existing_rows` reference pass. Runs only on the CI sqlserver-store legs.
# HYGIENE RULE: a test that writes reference rows under a TEST-LOCAL key must purge them on exit
# via _purge_reference_rows in a finally (even on assertion failure) — see its docstring for why.


async def _purge_reference_rows(*keys: bytes) -> None:
    """Shared-DB hygiene for tests that write reference rows under a TEST-LOCAL key — run it in a
    ``finally`` so it happens even on assertion failure. The CI suites share ONE database per run,
    and the ``store`` fixture OPENS the store BEFORE its clean-slate DELETE: reference rows left
    encrypted under a key the next (keyless) fixture open doesn't carry crash that open inside
    _load_reference_cache — IdentityCipher passes the mfenc blob through and json.loads raises —
    cascading setup ERRORs across every later test in the run. Opens with the test's own key(s)
    (first = active, rest = retired) so the cleanup open itself can decrypt whatever state the
    failure left behind, then raw-DELETEs the reference tables (the fixture's clean-slate idiom)."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
    from messagefoundry.store.sqlserver import SqlServerStore

    cipher = AesGcmCipher(keys[0], retired_keys=list(keys[1:]))
    cleanup = await SqlServerStore.open(load_settings(environ=os.environ).store, cipher=cipher)
    try:
        async with cleanup._pool.acquire() as conn:
            cur = await conn.cursor()
            await cur.execute("DELETE FROM reference")
            await cur.execute("DELETE FROM reference_version")
            await conn.commit()
    finally:
        await cleanup.close()


async def test_reference_snapshot_write_and_read(store) -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

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
    # Only the active version's rows remain in the table (DELETE + INSERT in ONE transaction).
    rows = await store._fetchall("SELECT DISTINCT version FROM reference")
    assert [r["version"] for r in rows] == ["v2"]
    # Reopen reloads the active snapshot from reference_version.
    reopened = await SqlServerStore.open(load_settings(environ=os.environ).store)
    try:
        assert reopened.reference_view()["providers"] == {"P1": {"name": "Dr A2"}}
    finally:
        await reopened.close()


async def test_keyless_open_of_encrypted_reference_fails_closed(store) -> None:
    """#241 F2: a keyless open of a store carrying key-encrypted ``reference`` rows must fail closed
    with the operator-facing StoreKeylessError (naming the table + remedy), not a raw JSONDecodeError
    from feeding an ``mfenc:`` blob straight into ``json.loads`` in ``_read_active_reference_snapshots``.
    The CI sqlserver-store leg is the authoritative proof of this T-SQL read seam."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import StoreKeylessError
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    k = generate_key()
    try:
        keyed = await SqlServerStore.open(settings, cipher=make_cipher(k))
        try:
            await keyed.write_reference_snapshot(
                name="providers", version="v1", rows={"P1": {"mrn": "M-SECRET-REF"}}
            )
        finally:
            await keyed.close()

        with pytest.raises(StoreKeylessError) as ei:
            await SqlServerStore.open(settings)  # keyless open of an encrypted store — fail closed
        assert "reference" in str(ei.value) and "MEFOR_STORE_ENCRYPTION_KEY" in str(ei.value)
    finally:
        # Shared-DB hygiene (even on assertion failure): purge the encrypted reference rows with the
        # SAME key that wrote them — make_cipher(k), a base64-str key — so the next keyless fixture open
        # does not itself fail-close inside _read_active_reference_snapshots. NB: not the raw-bytes
        # _purge_reference_rows helper: it takes bytes keys (AesGcmCipher(keys[0])) and a base64 str `k`
        # both TypeErrors and would open under the wrong key (the write used make_cipher(k)).
        cleanup = await SqlServerStore.open(settings, cipher=make_cipher(k))
        try:
            async with cleanup._pool.acquire() as conn:
                cur = await conn.cursor()
                await cur.execute("DELETE FROM reference")
                await cur.execute("DELETE FROM reference_version")
                await conn.commit()
        finally:
            await cleanup.close()


async def test_keyless_open_of_encrypted_state_fails_closed(store) -> None:
    """#241 F2 (the un-mask): a keyless open of a store carrying key-encrypted ``state`` rows must fail
    closed with StoreKeylessError, NOT silently skip the rows (``_load_state_cache`` previously caught
    ``(CipherError, ValueError)`` and dropped them — quietly losing PHI-bearing transform state). The
    CI sqlserver-store leg is the authoritative proof of this T-SQL read seam."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import StoreKeylessError
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    k = generate_key()
    try:
        keyed = await SqlServerStore.open(settings, cipher=make_cipher(k))
        try:
            mid, ing = await _ingress_and_claim(keyed, "IB", RAW)
            await keyed.route_handoff(
                ingress_id=ing.id,
                message_id=mid,
                channel_id="IB",
                handlers=[("H", RAW)],
                disposition=MessageStatus.ROUTED,
                now=100.0,
            )
            rtd = await keyed.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
            await keyed.transform_handoff(
                routed_id=rtd.id,
                message_id=mid,
                channel_id="IB",
                deliveries=[("OB", "b")],
                state_ops=[("ns", "k", {"mrn": "M-SECRET-STATE"})],
                now=100.0,
            )
            sealed = await keyed._fetchall("SELECT value FROM state")
            assert sealed and sealed[0]["value"].startswith(MARKER_PREFIX)  # ciphertext at rest
        finally:
            await keyed.close()

        with pytest.raises(StoreKeylessError) as ei:
            await SqlServerStore.open(settings)  # keyless open — fail closed, not a silent skip
        assert "state" in str(ei.value) and "MEFOR_STORE_ENCRYPTION_KEY" in str(ei.value)
    finally:
        # Purge the encrypted state (+ the ingress message/queue rows) with a keyed handle so the next
        # keyless fixture open does not fail-close inside _load_state_cache.
        cleanup = await SqlServerStore.open(settings, cipher=make_cipher(k))
        try:
            async with cleanup._pool.acquire() as conn:
                cur = await conn.cursor()
                for table in ("message_events", "state", "response", "queue", "messages"):
                    await cur.execute(f"DELETE FROM {table}")
                await conn.commit()
        finally:
            await cleanup.close()


async def test_reference_empty_snapshot_present_after_reopen(store) -> None:
    # A source that syncs to ZERO rows is a valid (empty) set — present as {} both before and after
    # a reopen (the cache load drives from reference_version LEFT JOIN reference, so it isn't lost).
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    await store.write_reference_snapshot(name="codes", version="v1", rows={})
    assert store.reference_view()["codes"] == {}
    reopened = await SqlServerStore.open(load_settings(environ=os.environ).store)
    try:
        assert reopened.reference_view()["codes"] == {}  # still present, not absent
    finally:
        await reopened.close()


async def test_converge_reference_cache_follower_read_through(store) -> None:
    """Track B Step 6: a FOLLOWER handle converges its read cache from a snapshot another handle (the
    leader) wrote into the shared DB — without re-reading the external source. Idempotent + the
    empty-snapshot case both covered, plus the pin that the LEADER's own write leaves nothing for its
    own converge (write_reference_snapshot's post-commit bookkeeping set both cache and versions)."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    # A second store handle on the SAME DB simulating a follower node. It opened before any snapshot,
    # so its cache starts empty.
    follower = await SqlServerStore.open(load_settings(environ=os.environ).store)
    try:
        assert "providers" not in follower.reference_view()

        # The "leader" (the fixture handle) materializes a snapshot → reference_version + rows advance.
        await store.write_reference_snapshot(
            name="providers", version="v1", rows={"P1": {"npi": "111"}}
        )
        # The leader's own converge refreshes NOTHING: its post-commit bookkeeping already recorded
        # the version it just wrote, so it never re-reads its own snapshot.
        assert await store.converge_reference_cache() == []
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


async def test_reference_snapshot_encrypted_at_rest(store) -> None:
    """Reference values (may carry PHI for patient-keyed sets) are mfenc ciphertext at rest while
    reference_view() serves plaintext — SQLite/PG parity (test_reference_sets.py analog)."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    try:
        s = await SqlServerStore.open(settings, cipher=AesGcmCipher(b"k" * 32))
        try:
            await s.write_reference_snapshot(name="codes", version="v1", rows={"MRN": "SECRET999"})
            assert s.reference_view()["codes"]["MRN"] == "SECRET999"  # cache is plaintext
            # The value column at rest is ciphertext (no PHI visible in the blob).
            row = (await s._fetchall("SELECT value FROM reference"))[0]
            assert row["value"].startswith(MARKER_PREFIX) and "SECRET999" not in row["value"]
        finally:
            await s.close()
        # Reopening with the same cipher decrypts back into the cache.
        reopened = await SqlServerStore.open(settings, cipher=AesGcmCipher(b"k" * 32))
        try:
            assert reopened.reference_view()["codes"]["MRN"] == "SECRET999"
        finally:
            await reopened.close()
    finally:
        # Rows here are encrypted under this test's own key — never leave them for the next
        # (keyless) fixture open to trip over.
        await _purge_reference_rows(b"k" * 32)


async def test_reference_non_ascii_value_round_trips(store) -> None:
    # pyodbc/aioodbc NVARCHAR unicode binding: a non-ASCII JSON value (through NVARCHAR(MAX)) and a
    # non-ASCII key (through NVARCHAR(450)) round-trip exactly on the KEYLESS path — the one where
    # the column carries raw JSON rather than ASCII base64 ciphertext, so the N-column encoding is
    # actually exercised.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    rows = {"clinic-Ærø": {"name": "Sørensen 診療所", "note": "café"}}
    await store.write_reference_snapshot(name="clinics", version="v1", rows=rows)
    assert store.reference_view()["clinics"] == rows
    reopened = await SqlServerStore.open(load_settings(environ=os.environ).store)
    try:
        assert reopened.reference_view()["clinics"] == rows  # read back from the DB, not the cache
    finally:
        await reopened.close()


async def test_reference_key_at_450_code_units_passes(store) -> None:
    # Exactly the NVARCHAR(450) bound, in UTF-16 code units — accepted by the guard AND by the DB.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    key = "k" * 450
    await store.write_reference_snapshot(name="wide", version="v1", rows={key: "v"})
    assert store.reference_view()["wide"][key] == "v"
    reopened = await SqlServerStore.open(load_settings(environ=os.environ).store)
    try:
        assert reopened.reference_view()["wide"][key] == "v"  # the DB round-trips the full key
    finally:
        await reopened.close()


async def test_reference_key_over_450_code_units_fails_guard_keeps_last_good(store) -> None:
    """The fail-closed width guard: a 451-code-unit key is refused BEFORE the snapshot transaction —
    named error carrying set name + ordinal + code-unit length + truncated hash, NEVER the raw key
    (reference keys may be PHI) — and the prior snapshot stays live."""
    await store.write_reference_snapshot(name="wide", version="v1", rows={"ok": "1"})
    bad_key = "x" * 451
    with pytest.raises(ValueError, match=r"NVARCHAR\(450\)") as exc:
        await store.write_reference_snapshot(name="wide", version="v2", rows={bad_key: "2"})
    msg = str(exc.value)
    assert "reference set 'wide'" in msg  # names the set...
    assert "key #0" in msg and "451 UTF-16 code units" in msg and "sha256:" in msg  # ...and the how
    assert bad_key not in msg and "xxxx" not in msg  # the raw key never leaks into the error (PHI)
    # The prior snapshot stays live — in the read cache AND as the DB's active version.
    assert store.reference_view()["wide"] == {"ok": "1"}
    vrow = (await store._fetchall("SELECT version FROM reference_version WHERE name=?", ("wide",)))[
        0
    ]
    assert vrow["version"] == "v1"


async def test_reference_astral_key_fails_guard_not_insert(store) -> None:
    # 300 code POINTS (< 450, so a naive len() passes it) but 600 UTF-16 code units (> 450, so the
    # NVARCHAR(450) bind would truncate mid-transaction): the guard measures code units and refuses
    # up front — a ValueError with the guard's named text, not a driver truncation error.
    key = "\U0001d11e" * 300  # U+1D11E MUSICAL SYMBOL G CLEF — 2 UTF-16 code units per code point
    assert len(key) == 300 and len(key.encode("utf-16-le")) // 2 == 600
    with pytest.raises(ValueError, match="UTF-16 code units") as exc:
        await store.write_reference_snapshot(name="astral", version="v1", rows={key: "v"})
    assert "refusing the snapshot" in str(exc.value)  # the GUARD's error, not pyodbc's
    assert key not in str(exc.value)  # raw key withheld (PHI)
    # Nothing landed: the guard fired BEFORE the transaction opened.
    rows = await store._fetchall("SELECT name FROM reference_version WHERE name=?", ("astral",))
    assert rows == []


async def test_reference_case_differing_keys_stay_distinct(store) -> None:
    # Binary collation (Latin1_General_100_BIN2) on [key]: under a case-insensitive database default
    # these two externally-sourced keys would raise a PK duplicate MID-transaction — a perpetual
    # per-interval sync failure. With BIN2 they load and read back as two distinct rows.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    rows = {"mrn-abc": "lower", "MRN-ABC": "upper"}
    await store.write_reference_snapshot(name="cased", version="v1", rows=rows)
    assert store.reference_view()["cased"] == rows
    table = await store._fetchall("SELECT [key] FROM reference WHERE name=?", ("cased",))
    assert {r["key"] for r in table} == {"mrn-abc", "MRN-ABC"}  # two distinct rows landed
    reopened = await SqlServerStore.open(load_settings(environ=os.environ).store)
    try:
        assert reopened.reference_view()["cased"] == rows  # distinct through the JOIN read too
    finally:
        await reopened.close()


async def test_reference_plaintext_migrated_on_keyed_reopen(store) -> None:
    """STORE-1 x ADR 0006: reference rows are NOT "born encrypted" — under a no-key deployment
    IdentityCipher writes plaintext JSON, and the first keyed open's _encrypt_existing_rows reference
    pass encrypts them in place (the no-key -> key transition)."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
    from messagefoundry.store.sqlserver import SqlServerStore

    try:
        # (1) The keyless fixture handle writes plaintext JSON at rest. A NEGATIVE assert, so it must
        # exclude EVERY marker version — a v1-only spelling would pass on an encrypted v2 value.
        await store.write_reference_snapshot(name="codes", version="v1", rows={"MRN": "SECRET999"})
        row = (await store._fetchall("SELECT value FROM reference"))[0]
        assert row["value"] == '"SECRET999"' and not row["value"].startswith(MARKER_PREFIX)

        # (2) Re-open WITH a key: open() runs the _encrypt_existing_rows reference pass and
        # migrates it.
        keyed = await SqlServerStore.open(
            load_settings(environ=os.environ).store, cipher=AesGcmCipher(b"k" * 32)
        )
        try:
            row = (await keyed._fetchall("SELECT value FROM reference"))[0]
            assert row["value"].startswith(MARKER_PREFIX) and "SECRET999" not in row["value"]
            assert keyed.reference_view()["codes"]["MRN"] == "SECRET999"  # decrypts on cache load
        finally:
            await keyed.close()
    finally:
        # Stage (2) leaves rows encrypted under this test's own key — purge them, or the next
        # (keyless) fixture open crashes. (A stage-(1) failure leaves decodable plaintext, and the
        # keyed cleanup open handles that state too — decrypt is a passthrough on plaintext.)
        await _purge_reference_rows(b"k" * 32)


async def test_reference_rows_rotate_on_reencrypt_to_active(store) -> None:
    """Key rotation must rotate reference.value too, or a later retired-key drop silently loses every
    synced snapshot. Self-contained: the fixture's clean slate + only-reference writes make the
    rotation count exactly this snapshot's 2 rows (the == 6 in
    test_reencrypt_to_active_rotates_all_columns_including_state is untouched — that test writes no
    reference rows, and the fixture clears `reference` between tests)."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    k1, k2 = b"k" * 32, b"K" * 32
    # Entry cleanliness: the exact == 2 below assumes the fixture's clean slate held.
    assert await store._fetchall("SELECT name FROM reference") == []
    try:
        old = await SqlServerStore.open(settings, cipher=AesGcmCipher(k1))
        try:
            await old.write_reference_snapshot(
                name="codes", version="v1", rows={"P1": {"mrn": "M-SECRET-1"}, "P2": "plain"}
            )
        finally:
            await old.close()

        active_cipher = AesGcmCipher(k2, retired_keys=[k1])
        rotated = await SqlServerStore.open(settings, cipher=active_cipher)
        try:
            assert await rotated.reencrypt_to_active() == 2  # exactly the two reference rows
            rows = await rotated._fetchall("SELECT value FROM reference")
            assert len(rows) == 2
            for r in rows:
                # under the ACTIVE key, in the ACTIVE marker format; no plaintext PHI visible
                assert r["value"].startswith(active_cipher.active_marker_prefix)
                assert "M-SECRET-1" not in r["value"]
            assert rotated.reference_view()["codes"]["P1"] == {"mrn": "M-SECRET-1"}  # decrypts
            assert await rotated.reencrypt_to_active() == 0  # idempotent
        finally:
            await rotated.close()

        # Proof the rows were actually rewritten: a handle with ONLY k2 (retired dropped) reads them.
        solo = await SqlServerStore.open(settings, cipher=AesGcmCipher(k2))
        try:
            assert solo.reference_view()["codes"] == {"P1": {"mrn": "M-SECRET-1"}, "P2": "plain"}
        finally:
            await solo.close()
    finally:
        # Rows here sit under k1 or k2 depending on where a failure struck — the cleanup handle
        # carries both, so the purge works from any exit path.
        await _purge_reference_rows(k2, k1)


# --- H1: store-checked leader epoch (fencing token) ---------------------------


async def _seed_lease_epoch(store, lease_key: str, epoch: int) -> None:
    """Upsert the single ``leader_lease`` row to ``epoch`` (the authoritative current leader epoch). The
    cluster coordinator owns this row in production; the test sets it directly to simulate the DB state a
    standby's fresh-acquire bump left behind, so the store's claim guard has something to validate."""
    await store._execute(
        "IF OBJECT_ID(N'leader_lease', N'U') IS NULL"
        " CREATE TABLE leader_lease ("
        " lease_key NVARCHAR(256) NOT NULL PRIMARY KEY, owner NVARCHAR(256) NULL,"
        " lease_expires_at FLOAT NOT NULL,"
        " leader_epoch BIGINT NOT NULL CONSTRAINT DF_leader_lease_epoch DEFAULT 0);"
    )
    await store._execute(
        "MERGE leader_lease WITH (HOLDLOCK) AS t USING (SELECT ? AS lease_key) AS s"
        " ON t.lease_key = s.lease_key"
        " WHEN MATCHED THEN UPDATE SET leader_epoch = ?"
        " WHEN NOT MATCHED THEN INSERT (lease_key, owner, lease_expires_at, leader_epoch)"
        " VALUES (?, 'live', 9e18, ?);",
        (lease_key, epoch, lease_key, epoch),
    )


async def test_stale_epoch_claim_is_rejected_zero_rows(store) -> None:
    # The fence. leader_lease.leader_epoch is 5 (a standby took over + bumped). A superseded ex-leader
    # still believes it holds epoch 3 (held < current) — its FIFO claim must affect 0 rows (None) and
    # leave the head PENDING, untouched.
    lease_key = "dbo:mefor_cluster_leader"
    await _seed_lease_epoch(store, lease_key, 5)
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0
    )
    store.set_leader_epoch(3, lease_key=lease_key)  # ex-leader holds a STALE (older) epoch
    assert await store.claim_next_fifo("OB1", now=200.0) is None  # rejected by the fence
    outbox = await store.outbox_for(mid)
    assert outbox[0]["status"] == OutboxStatus.PENDING.value  # head untouched, lane intact
    assert outbox[0]["attempts"] == 0


async def test_current_epoch_claim_succeeds(store) -> None:
    # The live leader holds the SAME epoch as the lease row (held == current): its claim passes. Equality
    # is the boundary — held >= current must include equality, else the true leader could never claim.
    lease_key = "dbo:mefor_cluster_leader"
    await _seed_lease_epoch(store, lease_key, 5)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    store.set_leader_epoch(5, lease_key=lease_key)
    claimed = await store.claim_next_fifo("OB1", now=200.0)
    assert claimed is not None and claimed.destination_name == "OB1"


async def test_epoch_guard_disabled_when_none_is_byte_identical(store) -> None:
    # set_leader_epoch(None) leaves the claim unfenced — byte-identical to pre-H1 (claims with no lease).
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    store.set_leader_epoch(None)
    assert await store.claim_next_fifo("OB1", now=200.0) is not None


async def test_stale_then_promoted_claim_preserves_fifo_head(store) -> None:
    # FIFO survives the fence: two messages on one lane (N, N+1). A stale ex-leader is rejected (delivers
    # neither); once this node is the current leader it claims the OLDEST first (N), preserving per-lane
    # order across the would-be split-brain.
    lease_key = "dbo:mefor_cluster_leader"
    await _seed_lease_epoch(store, lease_key, 5)
    m1 = await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "n")], now=100.0)
    m2 = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "n1")], now=101.0
    )
    store.set_leader_epoch(3, lease_key=lease_key)  # stale ex-leader
    assert await store.claim_next_fifo("OB1", now=200.0) is None
    store.set_leader_epoch(5, lease_key=lease_key)  # current leader
    first = await store.claim_next_fifo("OB1", now=201.0)
    assert first is not None and first.message_id == m1  # OLDEST first — FIFO intact
    await store.mark_done(first.id, now=202.0)
    second = await store.claim_next_fifo("OB1", now=203.0)
    assert second is not None and second.message_id == m2


async def test_pooled_claim_fenced_ex_leader_claims_zero_across_all_lanes(store) -> None:
    # ADR 0066 §8 row 7 (H1 pooled): the epoch guard rides the pooled claim's probe AND UPDATE, so a
    # superseded ex-leader's claim_fifo_heads matches 0 rows across ALL requested lanes in one shot —
    # and leaves every head PENDING with attempts untouched (the probe locked nothing).
    lease_key = "dbo:mefor_cluster_leader"
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
    res2 = await _claim_until(store, Stage.OUTBOUND.value, ["OB_PF1", "OB_PF2"], now=201.0)
    assert set(res2.by_lane) == {"OB_PF1", "OB_PF2"}


async def test_require_rcsi_for_pooled_passes_on_healthy_db(store) -> None:
    # _ensure_database_options force-enabled RCSI at open (the CI container permits the ALTER), so
    # the pooled hard-verify passes; on a locked-down DB it raises with the DBA remediation text.
    await store.require_rcsi_for_pooled()


# --- H2: outbound idempotency ledger parity (gated) --------------------------------------------


async def _ss_ledger(store) -> list[dict]:
    return await store._fetchall("SELECT * FROM delivered_keys ORDER BY delivery_seq")


async def test_mark_done_writes_one_ledger_row_ss(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], control_id="MSG1", now=100.0
    )
    item = await store.claim_next_fifo("OB1", now=200.0)
    assert item is not None
    await store.mark_done(item.id, now=300.0)
    rows = await _ss_ledger(store)
    assert len(rows) == 1
    assert rows[0]["outbox_id"] == item.id and rows[0]["delivery_seq"] == 1
    assert "p1" not in str(rows[0].values()) and "MSH" not in str(rows[0].values())
    assert len(rows[0]["delivery_key"]) == 64
    assert mid


async def test_claim_skips_already_delivered_head_no_resend_ss(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], now=100.0
    )
    item = await store.claim_next_fifo("OB1", now=200.0)
    assert item is not None
    await store.mark_done(item.id, now=300.0)
    assert len(await _ss_ledger(store)) == 1
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute(
            "UPDATE queue SET status=? WHERE id=?", (OutboxStatus.PENDING.value, item.id)
        )
        await conn.commit()
    assert await store.claim_next_fifo("OB1", now=400.0) is None  # dup head completed in place
    outbox = await store.outbox_for(mid)
    assert outbox[0]["status"] == OutboxStatus.DONE.value
    assert len(await _ss_ledger(store)) == 1
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_crash_re_run_mark_done_is_idempotent_ss(store) -> None:
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], now=100.0)
    item = await store.claim_next_fifo("OB1", now=200.0)
    assert item is not None
    await store.mark_done(item.id, now=300.0)
    await store.mark_done(item.id, now=301.0)  # re-run after crash → no duplicate ledger row
    assert len(await _ss_ledger(store)) == 1


async def test_replay_resend_not_deduped_ss(store) -> None:
    mid = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], now=100.0
    )
    item = await store.claim_next_fifo("OB1", now=200.0)
    assert item is not None
    await store.mark_done(item.id, now=300.0)
    assert len(await _ss_ledger(store)) == 1
    assert await store.replay(mid, now=400.0) == 1  # re-send drops the ledger entry
    assert await _ss_ledger(store) == []
    again = await store.claim_next_fifo("OB1", now=500.0)
    assert again is not None and again.id == item.id  # claimed normally, NOT deduped
    await store.mark_done(again.id, now=600.0)
    assert len(await _ss_ledger(store)) == 1


# --- pass-through (PT) re-ingress parity (mirrors tests/test_passthrough.py, ADR 0013) ---
#
# The atomic PT branch inside transform_handoff (a Send into an internal PT inbound re-ingresses the
# body as a new INGRESS child + stamps the parent's terminal marker) is implemented at full SQLite
# parity here (supports_pt_reingress=True). These drive the real staged flow (enqueue_ingress →
# route_handoff → transform_handoff) to land an INFLIGHT routed row, then exercise the PT branch.


async def _ss_seed_routed(
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
    ing = await store.claim_next_fifo(channel_id, stage=Stage.INGRESS.value, now=now)
    assert ing is not None
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id=channel_id,
        handlers=[("h1", raw)],
        disposition=MessageStatus.ROUTED,
        now=now,
    )
    rtd = await store.claim_next_fifo(channel_id, stage=Stage.ROUTED.value, now=now)
    assert rtd is not None
    return mid, rtd.id


async def test_pt_handoff_produces_child_and_parent_processed_ss(store) -> None:
    import json

    parent, routed = await _ss_seed_routed(store, now=100.0)
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


async def test_pt_child_id_is_content_addressed_ss(store) -> None:
    parent, routed = await _ss_seed_routed(store, now=100.0)
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


async def test_pt_plus_outbound_in_one_handler_ss(store) -> None:
    parent, routed = await _ss_seed_routed(store, now=100.0)
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


async def test_pt_handoff_idempotent_rerun_ss(store) -> None:
    parent, routed = await _ss_seed_routed(store, now=100.0)
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


async def test_pt_depth_cap_drops_child_and_errors_parent_ss(store) -> None:
    import json

    cap = 3
    parent, routed = await _ss_seed_routed(
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


async def test_pt_correlation_root_propagates_ss(store) -> None:
    import json

    parent, routed = await _ss_seed_routed(
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


async def test_pt_no_pt_is_byte_identical_ss(store) -> None:
    # Regression: empty pt_deliveries leaves the pre-feature path unchanged (normal FILTERED collapse).
    parent, routed = await _ss_seed_routed(store, now=100.0)
    assert await store.transform_handoff(
        routed_id=routed, message_id=parent, channel_id="IB_REAL", deliveries=[], now=110.0
    )
    pmsg = await store.get_message(parent)
    assert pmsg is not None and pmsg["status"] == MessageStatus.FILTERED.value


async def test_supports_pt_reingress_true_ss(store) -> None:
    assert store.supports_pt_reingress is True


# --- ADR 0064: schema-init fast-path -------------------------------------------


async def test_schema_fastpath_skips_and_reruns(store) -> None:
    """The ``schema_meta`` marker skips the DDL batch on a current DB; a missing marker (a pre-marker
    upgrade) or a stale hash (a future DDL edit) forces one full idempotent run that restores it."""
    assert await store._ensure_schema() is False  # marker current after open → skipped
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute("DELETE FROM schema_meta")
        await conn.commit()
        await cur.close()
    assert await store._ensure_schema() is True  # pre-marker DB → full run, marker rewritten
    assert await store._ensure_schema() is False
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute("UPDATE schema_meta SET schema_hash='stale' WHERE id=1")
        await conn.commit()
        await cur.close()
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
# Mirrors tests/test_attachment_substrate.py (the SQLite reference) against a real SQL Server: the
# verbatim chunked round-trip, per-chunk seal at rest, content-address dedup, refcount incref/decref +
# GC, the two-object ingress commit + rollback on a missing ref, the retention decref + join-DELETE
# (idempotent, no shared-attachment underflow), the dead-row keeps/releases split (either purge order),
# fan-out single decref, the below-threshold byte-identical path, and the key-rotation re-seal.

import hashlib as _hashlib  # noqa: E402 - local to the attachment block, mirrors the SQLite suite

_A_CHUNKS = ["QUJDRA==part0::", "RUZHSA==part1::", "SUpLTA==part2::"]
_A_DOC = "".join(_A_CHUNKS)
_A_REF = _hashlib.sha256(_A_DOC.encode("utf-8")).hexdigest()
DAY = 86_400.0


async def _a_read(s, ref: str) -> list[str]:
    return [c async for c in s.read_attachment(ref)]


async def _a_refcount(s, ref: str) -> int | None:
    row = await s._fetchone("SELECT refcount FROM attachment WHERE id=?", (ref,))
    return None if row is None else int(row["refcount"])


async def _a_chunks(s, ref: str) -> int:
    row = await s._fetchone(
        "SELECT COUNT(*) AS n FROM attachment_chunk WHERE attachment_id=?", (ref,)
    )
    return int(row["n"])


async def _a_joins(s, mid: str) -> int:
    row = await s._fetchone(
        "SELECT COUNT(*) AS n FROM message_attachment WHERE message_id=?", (mid,)
    )
    return int(row["n"])


async def _a_row_payload(s, oid: str) -> str:
    row = await s._fetchone("SELECT payload FROM queue WHERE id=?", (oid,))
    return str(row["payload"])


async def _a_detach_and_settle(s, *, now: float, ref: str) -> str:
    """Ingest a detached-attachment message and consume its ingress row (handoff, no deliveries) so it
    has no pending/inflight row and is retention-eligible when now < the purge cutoff."""
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
    """Ingest a detached message, route it to ONE outbound, then dead-letter that row — leaving a single
    DEAD, still-replayable outbound row that HOLDS the attachment (its payload is kept)."""
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
    assert ref == _A_REF  # content-addressed by the sha256 of the verbatim concatenated plaintext
    assert await _a_chunks(store, ref) == len(_A_CHUNKS)
    assert await _a_read(store, ref) == _A_CHUNKS  # exact slices back — reconstructs byte-for-byte
    assert "".join(await _a_read(store, ref)) == _A_DOC
    assert await _a_refcount(store, ref) == 0  # fresh: refcount 0 until increffed


async def test_attachment_read_missing_raises(store) -> None:
    with pytest.raises(KeyError):
        await _a_read(store, _A_REF)


async def test_attachment_dedups_identical_content(store) -> None:
    r1 = await store.put_attachment(_A_CHUNKS, "application/pdf")
    r2 = await store.put_attachment(_A_CHUNKS, "application/pdf")
    assert r1 == r2 == _A_REF
    assert await _a_chunks(store, r1) == len(_A_CHUNKS)  # one physical copy, not two
    row = await store._fetchone("SELECT COUNT(*) AS n FROM attachment WHERE id=?", (r1,))
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
    await store.attachment_decref(ref)  # last decref GCs header + chunks
    assert await _a_refcount(store, ref) is None
    assert await _a_chunks(store, ref) == 0
    with pytest.raises(KeyError):
        await _a_read(store, ref)
    await store.attachment_decref(ref)  # double-decref past zero is a tolerant no-op


async def test_attachment_incref_missing_raises(store) -> None:
    with pytest.raises(KeyError):
        await store.attachment_incref("f" * 64)


async def test_attachment_startup_sweep_reclaims_orphans_and_incomplete(store) -> None:
    zero_ref = await store.put_attachment(_A_CHUNKS, "application/pdf")  # refcount-0
    orphan_id = "a" * 64  # header-less chunk (incomplete write)
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute(
            "INSERT INTO attachment_chunk (attachment_id, seq, ciphertext) VALUES (?,?,?)",
            (orphan_id, 0, store._cipher.encrypt("orphaned pdf bytes")),
        )
        await conn.commit()
        await cur.close()
    live_ref = await store.put_attachment(["a live document"], "text/plain")
    await store.attachment_incref(live_ref)

    assert await store.sweep_orphan_attachments() == 2  # refcount-0 header + header-less group
    assert await _a_refcount(store, zero_ref) is None
    assert await _a_chunks(store, zero_ref) == 0
    assert await _a_chunks(store, orphan_id) == 0
    assert await _a_refcount(store, live_ref) == 1  # live attachment survives
    assert "".join(await _a_read(store, live_ref)) == "a live document"
    assert await store.sweep_orphan_attachments() == 0  # idempotent


async def test_attachment_ingress_two_object_commit(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    assert await _a_refcount(store, ref) == 0
    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|skel", attachment_refs=[ref])
    assert await _a_refcount(store, ref) == 1  # increffed by the ingress commit
    assert await _a_joins(store, mid) == 1  # one linkage row
    row = await store._fetchone(
        "SELECT attachment_id FROM message_attachment WHERE message_id=?", (mid,)
    )
    assert row["attachment_id"] == ref


async def test_attachment_ingress_dedups_duplicate_refs(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    await store.enqueue_ingress(channel_id="IB", raw="skel", attachment_refs=[ref, ref])
    assert await _a_refcount(store, ref) == 1  # distinct refs → increffed once


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
    assert int(row["n"]) == 0  # rolled back — no skeleton row, no ACK


async def test_attachment_purge_decrefs_and_deletes_linkage(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid = await _a_detach_and_settle(store, now=0.0, ref=ref)
    assert await _a_refcount(store, ref) == 1

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (await store.get_message(mid))["raw"] == ""
    assert await _a_refcount(store, ref) is None  # decref'd → GC
    assert await _a_chunks(store, ref) == 0
    assert await _a_joins(store, mid) == 0


async def test_attachment_shared_refcount_two_purge_each(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    m1 = await _a_detach_and_settle(store, now=0.0, ref=ref)
    m2 = await _a_detach_and_settle(store, now=20 * DAY, ref=ref)
    assert await _a_refcount(store, ref) == 2

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1  # only m1 eligible
    assert await _a_refcount(store, ref) == 1  # sibling m2 keeps the document
    assert await _a_chunks(store, ref) == len(_A_CHUNKS)
    assert "".join(await _a_read(store, ref)) == _A_DOC
    assert await _a_joins(store, m1) == 0 and await _a_joins(store, m2) == 1

    assert await store.purge_message_bodies(older_than=30 * DAY) == 1  # now m2
    assert await _a_refcount(store, ref) is None
    assert await _a_chunks(store, ref) == 0


async def test_attachment_double_purge_idempotent_no_underflow(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    m1 = await _a_detach_and_settle(store, now=0.0, ref=ref)
    m2 = await _a_detach_and_settle(store, now=20 * DAY, ref=ref)  # sibling, not yet eligible
    assert await _a_refcount(store, ref) == 2

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await store.purge_message_bodies(older_than=10 * DAY) == 0  # re-run: nothing to null

    assert await _a_refcount(store, ref) == 1  # NO double-decref → sibling survives
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
    assert await _a_refcount(store, ref) == 1  # handoff did not incref
    rows = await store.outbox_for(mid)
    assert len(rows) == 2
    await store.claim_ready(now=0.0)
    for r in rows:
        await store.mark_done(r["id"], now=0.0)
    assert await _a_refcount(store, ref) == 1  # delivery never touches the refcount

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await _a_refcount(store, ref) is None  # exactly one decref at purge
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
    assert int(row["n"]) == 0  # linkage table untouched


async def test_attachment_release_standalone_and_idempotent(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|skel", attachment_refs=[ref])
    assert await _a_refcount(store, ref) == 1
    await store.release_message_attachments(mid)
    assert await _a_refcount(store, ref) is None
    assert await _a_joins(store, mid) == 0
    await store.release_message_attachments(mid)  # idempotent no-op
    assert await _a_refcount(store, ref) is None


async def test_attachment_dead_row_keeps_through_body_purge(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid, oid = await _a_dead_deliver(store, now=0.0, ref=ref)
    assert await _a_refcount(store, ref) == 1

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (await store.get_message(mid))["raw"] == ""
    assert await _a_row_payload(store, oid) == "MSH|dead|mfdoc:v1:ref:doc"  # still replayable
    assert await _a_refcount(store, ref) == 1  # attachment SURVIVES for the replay
    assert "".join(await _a_read(store, ref)) == _A_DOC


async def test_attachment_dead_purge_releases_after_body_purge(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid, oid = await _a_dead_deliver(store, now=0.0, ref=ref)
    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert await _a_refcount(store, ref) == 1  # kept: dead row still replayable

    assert await store.purge_dead_letters(older_than=10 * DAY) == 1
    assert await _a_row_payload(store, oid) == ""
    assert await _a_refcount(store, ref) is None  # last replayable holder gone → GC
    assert await _a_joins(store, mid) == 0


async def test_attachment_dead_purge_releases_when_run_first(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    mid, oid = await _a_dead_deliver(store, now=0.0, ref=ref)

    assert await store.purge_dead_letters(older_than=10 * DAY) == 1  # dead purge BEFORE body purge
    assert await _a_row_payload(store, oid) == ""
    assert await _a_refcount(store, ref) is None  # released here — dead row was the last holder
    assert await _a_joins(store, mid) == 0

    assert await store.purge_message_bodies(older_than=10 * DAY) == 1
    assert (await store.get_message(mid))["raw"] == ""
    assert await _a_refcount(store, ref) is None  # no double-decref / underflow


async def test_attachment_dead_purge_idempotent_no_underflow(store) -> None:
    ref = await store.put_attachment(_A_CHUNKS, "application/pdf")
    m1, _ = await _a_dead_deliver(store, now=0.0, ref=ref, dest="OB_1")
    m2, _ = await _a_dead_deliver(store, now=20 * DAY, ref=ref, dest="OB_2")
    assert await _a_refcount(store, ref) == 2

    assert await store.purge_dead_letters(older_than=10 * DAY) == 1  # only m1 past cutoff
    assert await store.purge_dead_letters(older_than=10 * DAY) == 0  # re-run: nothing to blank

    assert await _a_refcount(store, ref) == 1  # m1 released once; m2 survives
    assert await _a_chunks(store, ref) == len(_A_CHUNKS)
    assert await _a_joins(store, m1) == 0 and await _a_joins(store, m2) == 1


async def test_attachment_chunks_sealed_at_rest_and_reseal_on_rotation(store) -> None:
    # The `store` fixture truncated the attachment tables → clean slate. Use dedicated keyed handles for
    # the seal/rotation round-trip (mirrors the SQLite reseal test on a persistent server DB).
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    k1, k2 = generate_key(), generate_key()

    s1 = await SqlServerStore.open(settings, cipher=make_cipher(k1))
    try:
        ref = await s1.put_attachment(_A_CHUNKS, "application/pdf")
        rows = await s1._fetchall(
            "SELECT ciphertext FROM attachment_chunk WHERE attachment_id=? ORDER BY seq", (ref,)
        )
        assert len(rows) == len(_A_CHUNKS)
        for r in rows:  # each chunk independently mfenc-sealed at rest, not plaintext
            assert r["ciphertext"].startswith(MARKER_PREFIX)
        assert await _a_read(s1, ref) == _A_CHUNKS
    finally:
        await s1.close()

    # Rotate: active = k2, k1 kept decrypt-only for the re-encrypt pass.
    s2 = await SqlServerStore.open(settings, cipher=make_cipher(k2, [k1]))
    try:
        rotated = await s2.reencrypt_to_active()
        assert rotated >= len(_A_CHUNKS)  # every chunk re-sealed under the active key
        assert await _a_read(s2, ref) == _A_CHUNKS
    finally:
        await s2.close()

    # Reopen with ONLY k2 (no retired key): reading proves the chunks are now sealed under k2.
    s3 = await SqlServerStore.open(settings, cipher=make_cipher(k2))
    try:
        assert await _a_read(s3, ref) == _A_CHUNKS
        assert ref == _A_REF  # the content address is over plaintext — rotation-stable
    finally:
        await s3.close()


# --- STORE-4: runner-level ACK-on-receipt + post-ingress no-NAK on the real backend ----------
# Drives the runner's real AA-emitting path (_handle_inbound) + _process_ingress_item against THIS
# file's real backend `store` fixture — no `.start()`, no socket (port=0 never binds). The SQLite
# suites cover the AA-after-commit tie and the FILE-source post-ingress path; these pin them on the
# reply-capable (MLLP) path against SS. Gated like every test here; a green leg confirms the design.


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
# P1 batch 2 — cross-backend store-method parity (mirrors tests/test_postgres_store.py twins).
# STOREF-8 (resend_to), STOREF-9 (reingress + edit-and-resend), RBAC-8 (summary_access census),
# ALERT-19 (alert_instance CRUD). Synthetic HL7 only; every assertion is deterministic (no sleeps).
# =====================================================================================================

# Synthetic ADT + a distinct transformed/edited body — never real PHI (ADR 0090 resend/edit matrix).
_RS_ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
_RS_TRANSFORMED = "MSH|^~\\&|MEFOR|RF|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rZXF|sent\r"
_RS_EDITED = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||200^^^H^MR||DOE^JOHN\r"

# A PENDING outbound queue row insert (seq is IDENTITY/auto). Used to plant an uncommitted producer
# row for the SS concurrency divergence tests — the fixture handle opens with no cipher so payload
# is plaintext.
_INSERT_PENDING_OUTBOUND = (
    "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, payload,"
    " status, attempts, next_attempt_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
)


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


async def _ss_force_error(store, mid: str, error: str) -> None:
    """Force a seeded origin to a terminal ERROR (ciphered at rest) — proves the direct edit-resend
    never reopens/overwrites it (mirrors test_edit_resend.py::_seed_error)."""
    async with store._acquire() as conn, store._cursor(conn) as cur:
        try:
            await cur.execute(
                "UPDATE messages SET status=?, error=? WHERE id=?",
                (
                    MessageStatus.ERROR.value,
                    store._enc(error, aad=cell_aad("messages", "error", mid)),
                    mid,
                ),
            )
            await store._commit(conn)
        except Exception:
            await conn.rollback()
            raise


# --- STOREF-8: resend_to plain-parity matrix (mirrors tests/test_resend.py, on real SQL Server) ------


async def test_resend_plain_parity_ss(store) -> None:
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
    # TAIL: the resend row has the greatest seq (BIGINT IDENTITY) of the lane, so FIFO orders it last.
    seqs = {
        r["id"]: r["seq"]
        for r in await store._fetchall("SELECT id, seq FROM queue WHERE message_id=?", (mid,))
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


async def test_resend_reopens_processed_to_routed_ss(store) -> None:
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


async def test_resend_does_not_funnel_ss(store) -> None:
    # ADR 0090 §3 SS divergence (deliberate contrast to PG's funnel): SS resend_to takes NO per-lane
    # write-funnel — only the per-key applock (sqlserver.py:5620, declined-funnel note :5607) — so it
    # COMPLETES while a producer holds an uncommitted OB2 row, never blocking on the lane. DETERMINISTIC:
    # genuinely non-blocking (were it to funnel, the wait_for timeout would fail the test).
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    mid = await store.enqueue_message(
        channel_id="in1", raw=_RS_ADT, deliveries=[("OB1", "SRC")], now=100.0
    )
    pmid = await store.enqueue_message(channel_id="IB", raw=_RS_ADT, deliveries=[], now=100.0)
    other = await SqlServerStore.open(load_settings(environ=os.environ).store)
    async with store._acquire() as conn, store._cursor(conn) as cur:
        try:
            await cur.execute(
                _INSERT_PENDING_OUTBOUND,
                (
                    uuid4().hex,
                    pmid,
                    Stage.OUTBOUND.value,
                    "IB",
                    "OB2",
                    "PRODUCER",
                    OutboxStatus.PENDING.value,
                    0,
                    101.0,
                    101.0,
                    101.0,
                ),
            )  # producer held uncommitted (seq N)
            out = await asyncio.wait_for(
                other.resend_to(
                    message_id=mid, to="OB2", idempotency_key="k1", from_="OB1", now=102.0
                ),
                timeout=10.0,
            )
            assert out.status == "resent"  # no funnel: completes despite the held producer
        finally:
            await conn.rollback()  # discard the producer
            await other.close()


async def test_serial_claim_blocks_on_uncommitted_producer_ss(store) -> None:
    # ADR 0090 §3 (SS serial strong FIFO, sqlserver.py:4187): claim_next_fifo reads the head WITH
    # (UPDLOCK, ROWLOCK) and deliberately NO READPAST, so it head-of-line-BLOCKS on a lower-seq
    # uncommitted producer — strict per-lane FIFO. DETERMINISTIC: a genuine lock wait (observed via
    # wait_for(shield) TimeoutError); once the producer commits, it is delivered FIRST (seq N before N+1).
    pmid = await store.enqueue_message(channel_id="IB", raw=_RS_ADT, deliveries=[], now=100.0)
    task: asyncio.Task | None = None
    async with store._acquire() as conn, store._cursor(conn) as cur:
        try:
            await cur.execute(
                _INSERT_PENDING_OUTBOUND,
                (
                    uuid4().hex,
                    pmid,
                    Stage.OUTBOUND.value,
                    "IB",
                    "OB2",
                    "PRODUCER",
                    OutboxStatus.PENDING.value,
                    0,
                    101.0,
                    101.0,
                    101.0,
                ),
            )  # producer seq N, held uncommitted
            # a serial claim on a spare pooled connection blocks on the uncommitted head N.
            task = asyncio.create_task(store.claim_next_fifo("OB2", now=300.0))
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
            await store._commit(conn)  # commit producer -> the blocked claim gets the head N
        except BaseException:
            await conn.rollback()  # unblock the claim on the failure path
            raise
    head = await asyncio.wait_for(task, timeout=10.0)
    assert (
        head is not None and head.payload == "PRODUCER"
    )  # seq N first — strong FIFO across the block


async def test_pooled_claim_skips_uncommitted_producer_ss(store) -> None:
    # ADR 0066/0090 §3 (SS pooled weak fan-in, sqlserver.py claim_fifo_heads): the pooled claim probes
    # with an RCSI snapshot, so an uncommitted lower-seq producer is INVISIBLE and the committed resend
    # is claimed ahead of it — the deliberately-accepted weak cross-source fan-in (per-source FIFO still
    # holds). The contrast to the serial claim's head-of-line block above. DETERMINISTIC: the snapshot
    # visibility is fixed by insert-commit state, not timing (wait_for only bounds a would-be hang).
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    mid = await store.enqueue_message(
        channel_id="in1", raw=_RS_ADT, deliveries=[("OB1", "SRCB")], now=100.0
    )
    pmid = await store.enqueue_message(channel_id="IB", raw=_RS_ADT, deliveries=[], now=100.0)
    other = await SqlServerStore.open(load_settings(environ=os.environ).store)
    async with store._acquire() as conn, store._cursor(conn) as cur:
        try:
            await cur.execute(
                _INSERT_PENDING_OUTBOUND,
                (
                    uuid4().hex,
                    pmid,
                    Stage.OUTBOUND.value,
                    "IB",
                    "OB2B",
                    "PRODUCER",
                    OutboxStatus.PENDING.value,
                    0,
                    101.0,
                    101.0,
                    101.0,
                ),
            )  # producer seq M, held uncommitted
            # the resend commits at seq M+1 on OB2B (no funnel) while the producer stays uncommitted.
            out = await asyncio.wait_for(
                other.resend_to(
                    message_id=mid, to="OB2B", idempotency_key="k1", from_="OB1", now=102.0
                ),
                timeout=10.0,
            )
            assert out.status == "resent"
            # pooled claim: the invisible uncommitted producer is skipped -> the resend IS claimed.
            res = await asyncio.wait_for(
                _claim_until(store, Stage.OUTBOUND.value, ["OB2B"], now=300.0), timeout=10.0
            )
            claimed = res.by_lane.get("OB2B", [])
            assert len(claimed) == 1 and claimed[0].payload == "SRCB"
        finally:
            await conn.rollback()  # discard the producer
            await other.close()


# --- STOREF-9: reingress (RE-ROUTE) + resend_to(body_override=) (DIRECT edit), on real SQL Server ----


async def test_reingress_parity_ss(store) -> None:
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
    crows = await store._fetchall(
        "SELECT status FROM queue WHERE message_id=? AND stage=?",
        (out.new_message_id, Stage.INGRESS.value),
    )
    orows = await store._fetchall(
        "SELECT status FROM queue WHERE message_id=? AND stage=?", (origin, Stage.INGRESS.value)
    )
    assert len(crows) == 1 and crows[0]["status"] == OutboxStatus.PENDING.value
    assert orows == []

    # origin byte-identical (never opened for write).
    after = await store.get_message(origin)
    assert after["raw"] == before["raw"] == _RS_ADT
    assert after["status"] == before["status"] and after["metadata"] == before["metadata"]

    # same key -> duplicate, same child, still exactly one child + one ingress row (no double-inject).
    dup = await store.reingress(origin_message_id=origin, raw=_RS_EDITED, idempotency_key="k1")
    assert dup.status == "duplicate" and dup.new_message_id == out.new_message_id
    n = (
        await store._fetchone(
            "SELECT COUNT(*) AS n FROM messages WHERE id=?", (out.new_message_id,)
        )
    )["n"]
    ing = await store._fetchall(
        "SELECT status FROM queue WHERE message_id=? AND stage=?",
        (out.new_message_id, Stage.INGRESS.value),
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
    td = (
        await store._fetchone("SELECT to_destination FROM resend_log WHERE resend_key=?", ("k1",))
    )["to_destination"]
    assert td == f"{REINGRESS_TARGET_PREFIX}in1"


async def test_direct_edit_parity_ss(store) -> None:
    from messagefoundry.store.base import ResendSourceEmpty

    origin = await _rs_seed(store)
    await _ss_force_error(store, origin, "connection refused: partner down")
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
    crows = await store._fetchall(
        "SELECT id, message_id FROM queue WHERE stage=? AND destination_name=?",
        (Stage.OUTBOUND.value, "OB2"),
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
    ne = await store._fetchall(
        "SELECT id FROM queue WHERE stage=? AND destination_name=?", (Stage.OUTBOUND.value, "OB2E")
    )
    assert ne == []

    # idempotent: same key/body -> duplicate, exactly one OB3 delivery on one child.
    first = await store.resend_to(
        message_id=m2, to="OB3", idempotency_key="k3", body_override=_RS_EDITED
    )
    second = await store.resend_to(
        message_id=m2, to="OB3", idempotency_key="k3", body_override=_RS_EDITED
    )
    assert first.status == "resent" and second.status == "duplicate"
    ob3 = await store._fetchall(
        "SELECT id FROM queue WHERE stage=? AND destination_name=?", (Stage.OUTBOUND.value, "OB3")
    )
    assert len(ob3) == 1 and ob3[0]["id"] == first.outbox_id


# --- RBAC-8: server-side summary_access census (record_audit + list_audit), on real SQL Server ------


async def test_summary_access_census_survives_and_coalesces_ss(store) -> None:
    # Drive the REAL backend-agnostic coalescer end-to-end so the census JSON detail (NVARCHAR(MAX)) +
    # NULL/scope keying persist through record_audit and read back via list_audit on the real backend
    # (the piece that today rides SQLite only). Fixed `now` makes the hour bucketing deterministic.
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

    await c.note(store, "bob", "", 4, 3600.0)  # hour 1, scope "" -> channel_id NULL (NVARCHAR NULL)
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


# --- ALERT-19: alert_instance CRUD lifecycle + reason cipher-at-rest, on real SQL Server ------------


async def test_alert_instance_lifecycle_ss(store) -> None:
    # first fire opens one `open` instance (count 1, first_seen==last_seen).
    await store.upsert_alert_instance(
        event_type="connection_error", connection="OB_X", severity="critical", now=100.0
    )
    (a,) = await store.list_active_alert_instances()
    assert a.status == "open" and a.count == 1 and a.first_seen == 100.0 and a.last_seen == 100.0
    assert a.severity == "critical"
    # pyodbc returns Decimal for BIGINT/FLOAT; _alert_instance_row coerces id/count to int (sqlserver.py:3241).
    assert isinstance(a.id, int) and isinstance(a.count, int)

    # re-fire folds into the live instance (SS UPDATE-then-conditional-INSERT path): same id, count++.
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


async def test_alert_reason_encrypted_at_rest_ss(store) -> None:
    # Metadata-only + the scrubbed reason is encrypted at rest through a keyed handle (SS NVARCHAR(MAX)
    # cipher pass — closes the ALERT-18 "SS separate cipher pass not exercised" note) — decrypted at the
    # read boundary, ciphertext on disk.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s2 = await SqlServerStore.open(settings, cipher=make_cipher(generate_key()))
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
    raw = (
        await store._fetchone("SELECT reason FROM alert_instance WHERE connection=?", ("OB_ENC",))
    )["reason"]
    assert isinstance(raw, str) and raw.startswith(MARKER_PREFIX)  # ciphertext on disk
    assert "refused" not in raw


# --- BATCH-3 cross-backend guards: store-once-inert + rotate/audit CLI on a live SQL Server ----


async def test_store_once_deliver_many_body_ref_inert(store) -> None:
    """STOREF-17: store-once-deliver-many dedup is SQLite-only this increment (ADR 0099); on SQL Server
    it is INERT — the schema carries ``shared_body`` + ``queue.body_ref`` (parity comments
    sqlserver.py:661-664/715-717), but ``transform_handoff`` writes each fan-out delivery inline
    (``_insert_outbound`` omits ``body_ref`` → NULL), never a shared copy. The SAME input that dedups on
    SQLite (test_store_once_deliver_many.py:88) must here create ZERO ``shared_body`` rows and leave
    every outbound ``body_ref`` NULL — and delivery parity must still hold: each independent inline
    ciphertext decrypts to the identical plaintext (the LEFT-JOIN read falls through to the inline
    payload when ``body_ref`` IS NULL, byte-identical to the pre-dedup path)."""
    # A transformed body fanned out to ≥2 destinations — the exact shape that triggers the SQLite dedup;
    # kept distinct from RAW (the routed handler body) as the SQLite reference test does.
    body = "MSH|^~\\&|XFORM|||||20260101||ADT^A01|OUT1|P|2.5.1\r"
    dests = ["OB_A", "OB_B", "OB_C"]
    mid, ing = await _ingress_and_claim(store, "IB", RAW)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
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
        "SELECT body_ref AS v FROM queue WHERE message_id=? AND stage=?",
        (mid, Stage.OUTBOUND.value),
    )
    assert len(rows) == len(dests) and all(r["v"] is None for r in rows)
    # (3) Delivery parity: each destination's inline ciphertext decrypts to the identical plaintext.
    for d in dests:
        item = await store.claim_next_fifo(d, stage=Stage.OUTBOUND.value, now=100.0)
        assert item is not None and item.payload == body


async def test_audit_verify_cli_server(store, capsys) -> None:
    """CLI-22: the ``audit-verify`` CLI wrapper (load_settings + open_store + printed OK/FAIL + exit
    code) has only ever run against SQLite; here it reaches the live SQL Server store via ``MEFOR_STORE_*``
    env (no ``--db`` — that only rewrites the unused SQLite ``[store].path``; the M-31 missing-DB guard is
    SQLite-only, so it's inert and the CLI goes straight to ``open_store`` on the env-configured backend).
    Seed a keyless audit chain through the fixture handle (``record_audit`` commits per row, so the CLI's
    separate connection sees it), then run the CLI OFF the event loop — ``_audit_verify`` calls
    ``asyncio.run`` internally, which raises inside a running loop, so ``asyncio.to_thread`` gives it a
    fresh loop + its own pool against the same server DB."""
    from messagefoundry.__main__ import main

    await store.record_audit("message_view", actor="alice", detail="v1")
    await store.record_audit("export", actor="bob", detail="e1")
    rc = await asyncio.to_thread(main, ["audit-verify"])  # backend from env; NO --db
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK:" in out and "verified 2" in out


async def test_rekey_audit_cli_server(store, capsys, monkeypatch) -> None:
    """CLI-23: the ``rekey-audit`` CLI wrapper enables HMAC keying of an existing keyless chain
    (#190-D). It reaches the live SQL Server store purely via ``MEFOR_STORE_*`` env (no ``--db``; the
    SQLite missing-file guard is inert for server backends), needs a DEK to key, and writes
    ``audit_chain_meta.keyed_from_id = MAX(audit_log.id)+1`` via the SS UPDATE-then-INSERT upsert. Seed
    keyless (the fixture handle opened without a DEK), compute the watermark at RUNTIME (DELETE does not
    reseed SS IDENTITY, so the SQLite test's literal ``id=3`` is invalid here), then drive the CLI off
    the event loop (its internal ``asyncio.run`` would raise in a running loop)."""
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
    """CLI-24: the ``rotate-key`` CLI wrapper (resolve_active_key + keyring from env + open_store dispatch
    + reencrypt_to_active) has only ever run against SQLite ``--db``; the underlying store method is
    covered on SS, but not the CLI wiring. Drive ``main(["rotate-key"])`` against the live SQL Server
    store: the backend + retired/active keyring come purely from ``MEFOR_STORE_*`` env (no ``--db``). The
    ``store`` fixture truncated every table, so rotation sees ONLY this test's key_a rows (no foreign-key
    leftover → no CipherError). After rotation every ciphertext carries the new active key's fingerprint
    and the message decrypts under key_b ALONE (retired key dropped) — end-to-end proof."""
    from messagefoundry.__main__ import main
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
    from messagefoundry.store.sqlserver import SqlServerStore

    monkeypatch.chdir(
        tmp_path
    )  # isolate from any stray ./messagefoundry.toml (env wins, but be safe)
    settings = load_settings(environ=os.environ).store
    key_a, key_b = generate_key(), generate_key()
    # The rotation writer is NOT an object this test holds: main(["rotate-key"]) -> open_store ->
    # build_store_cipher(settings), i.e. write_v2=[store].aad_bind. Mirror that posture so the marker
    # this test expects is the one the CLI actually wrote, whichever way the aad_bind default sits.
    cipher_b = make_cipher(key_b, write_v2=settings.aad_bind)
    assert isinstance(cipher_b, AesGcmCipher)

    seed = await SqlServerStore.open(settings, cipher=make_cipher(key_a))
    try:
        mid = await seed.enqueue_message(channel_id="ch", raw=RAW, deliveries=[("d", RAW)])
    finally:
        await seed.close()

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key_b)  # new active
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED", key_a)  # old, decrypt-only bridge
    rc = await asyncio.to_thread(main, ["rotate-key"])  # asyncio.run inside → off the loop
    assert rc == 0
    assert "re-encrypted" in capsys.readouterr().out

    verify = await SqlServerStore.open(settings, cipher=cipher_b)  # key_b alone, no retired
    try:
        assert len(await verify.list_messages()) == 1
        assert (await verify.get_message(mid))["raw"] == RAW  # decrypts under the new key alone
        blobs = await verify._fetchall(
            "SELECT raw AS v FROM messages UNION ALL SELECT payload FROM queue WHERE payload <> ''"
        )
        assert blobs  # at least messages.raw + the one outbound payload
        for r in blobs:
            assert r["v"].startswith(MARKER_PREFIX)
            assert r["v"].startswith(cipher_b.active_marker_prefix)  # active key, active format
    finally:
        await verify.close()


# =====================================================================================================
# P1 batch 4 — STOREF-11: the ingress document-detach PIPELINE on real SQL Server (#149, ADR 0105
# Phase 1a). SS advertises supports_streaming_attachments=True and implements put_attachment /
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


async def test_over_threshold_detaches_verbatim_ss(store) -> None:
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


async def test_below_threshold_byte_identical_ss(store) -> None:
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


async def test_over_max_message_bytes_naks_ar_ss(store) -> None:
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


async def test_stream_inflight_budget_naks_ae_ss(store) -> None:
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


async def test_ack_fires_after_skeleton_and_incref_commit_ss(store) -> None:
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


async def test_crash_orphan_sweep_and_rerun_dedups_ss(store) -> None:
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


async def test_strict_downgraded_to_header_only_over_threshold_ss(store, monkeypatch) -> None:
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


async def test_http_grant_deny_audit_precision(store) -> None:
    """RBAC-4 (ASVS 16.3.2) on the real SQL Server backend: the HTTP ``require()`` grant/deny audit set
    is EXACT and the ``method != "GET"`` guard REFUSES to audit a sensitive-permission READ. Reuses the
    single source-of-truth helper from the SQLite suite so this live-server leg proves the deny/grant
    row is actually written by ``record_audit`` / read by ``list_audit`` on SQL Server — not just SQLite."""
    from tests.test_auth_hardening import _assert_http_grant_deny_precision

    await _assert_http_grant_deny_precision(store)


# --- ADR 0150: the client address column + its migration, on real SQL Server ------------------------


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
    """The real upgrade path on SQL Server: a DB whose ``audit_log`` predates ``client`` gets the column
    ALTERed in, its legacy rows keep their ORIGINAL hashes, and the chain still verifies — then a new
    address-bearing row chains cleanly onto them.

    The DDL batch is skipped when the ADR 0064 ``schema_meta`` marker matches, so this clears the marker
    to reproduce what a genuine upgrade does: adding statements to ``_SCHEMA`` changes ``_schema_hash()``,
    which forces exactly this one full (idempotent) re-run."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore
    from messagefoundry.store.store import audit_row_hash

    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute(
            "IF COL_LENGTH('audit_log','client') IS NOT NULL "
            "ALTER TABLE audit_log DROP COLUMN client"
        )
        await cur.execute("DELETE FROM schema_meta")
        prev = ""
        for i in range(3):
            prev = audit_row_hash(
                prev, ts=float(i), actor="u", action="legacy", channel_id=None, detail=None
            )
            await cur.execute(
                "INSERT INTO audit_log (ts, actor, action, channel_id, detail, row_hash)"
                " VALUES (?,?,?,?,?,?)",
                (float(i), "u", "legacy", None, None, prev),
            )
        await conn.commit()
    legacy_head = prev

    upgraded = await SqlServerStore.open(load_settings(environ=os.environ).store)
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
# gated leg proves the SQL Server statement is even syntactically valid, so a skip here is a real
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
    """The bound END TO END on the SQL Server store of record, not just the upsert primitive.

    The fixture above opens with the IDENTITY cipher, so it exercises none of the enable-and-reserve
    inside ``SqlServerStore.open``, the close-time settlement, or the persistence across a reopen. A
    keyed handle is the only way those run here at all."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.gcm_bound import GCM_RESERVE_BLOCK
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    k = generate_key()
    cipher = make_cipher(k)
    key_id = cipher.active_key_id
    try:
        keyed = await SqlServerStore.open(settings, cipher=cipher)
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
        reopened = await SqlServerStore.open(settings, cipher=reopened_cipher)
        try:
            # The requirement: the KEY's lifetime figure survives the process, on this backend.
            assert reopened_cipher.cumulative_invocations() == spent
            await reopened.enqueue_ingress(channel_id="IB", raw=RAW)
            assert reopened_cipher.cumulative_invocations() > spent
        finally:
            await reopened.close()
    finally:
        # Shared-DB hygiene: drop this test's encrypted rows + counter row (the fixture clears on entry,
        # but a later keyless open must never meet ciphertext it cannot read).
        cleanup = await SqlServerStore.open(settings, cipher=make_cipher(k))
        try:
            async with cleanup._pool.acquire() as conn:
                cur = await conn.cursor()
                for table in ("message_events", "queue", "response", "messages"):
                    await cur.execute(f"DELETE FROM {table}")  # FK order: children first
                await cur.execute("DELETE FROM cipher_meta WHERE key_id = ?", (key_id,))
                await conn.commit()
        finally:
            await cleanup.close()


async def test_session_rotation_contract(store) -> None:
    """ASVS 7.2.4: rotate_session is a pure re-key — old hash dead, every other column carried
    forward, replay and revoked rows refused. Extra-free shared contract, so this leg actually runs
    it rather than importorskip-skipping."""
    from tests._session_rotation_contract import assert_session_rotation_contract

    await assert_session_rotation_contract(store)
