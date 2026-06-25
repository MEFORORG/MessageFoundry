# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SQL Server store behaviour — mirrors the SQLite suite, against a real SQL Server.

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env),
so it's a no-op locally and in normal CI. The CI mssql service-container job sets the env and runs
it for real. Requires the ``sqlserver`` extra (``aioodbc`` + ODBC Driver 18).
"""

from __future__ import annotations

import asyncio
import os
from typing import AsyncIterator

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.store import MessageStatus, OutboxStatus, Stage

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


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
            "state",
            "queue",  # FK to messages(id) — must be cleared before messages
            "response",  # FK to messages(id) — must be cleared before messages
            "delivered_keys",  # H2 idempotency ledger (no FK, but ids reference messages)
            "outbox",
            "messages",
            "sessions",
            "user_roles",
            "ad_group_role_map",
            "users",
            "roles",
        ):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
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
    kw = dict(ingress_id=ing.id, message_id=mid, channel_id="IB", disposition=MessageStatus.ROUTED)
    assert await store.route_handoff(handlers=[("H1", RAW)], now=100.0, **kw)
    assert await store.route_handoff(handlers=[("H1", RAW)], now=100.0, **kw) is False
    rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    tkw = dict(routed_id=rtd.id, message_id=mid, channel_id="IB", deliveries=[("OB1", "b")])
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

    active_id = AesGcmCipher(k2).active_key_id
    rotated = await SqlServerStore.open(settings, cipher=AesGcmCipher(k2, retired_keys=[k1]))
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
            assert r["v"].split(":", 3)[2] == active_id, r["v"]  # mfenc:v1:<active_id>:<blob>
        assert dict(rotated.state_view())[("ns", "k")] == {"v": 1}  # still decrypts
        assert await rotated.reencrypt_to_active() == 0  # idempotent
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
    kw = dict(
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
    from messagefoundry.store.crypto import AesGcmCipher
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

    active_id = AesGcmCipher(k2).active_key_id
    rotated = await SqlServerStore.open(settings, cipher=AesGcmCipher(k2, retired_keys=[k1]))
    try:
        await rotated.reencrypt_to_active()  # rotates response.body + detail (among others)
        blobs = await rotated._fetchall("SELECT body, detail FROM response")
        for b in blobs:
            assert b["body"].split(":", 3)[2] == active_id  # mfenc:v1:<active_id>:...
            assert b["detail"].split(":", 3)[2] == active_id
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
    from messagefoundry.store.crypto import AesGcmCipher
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

    active_id = AesGcmCipher(k2).active_key_id
    rotated = await SqlServerStore.open(settings, cipher=AesGcmCipher(k2, retired_keys=[k1]))
    try:
        await rotated.reencrypt_to_active()  # must not crash on / mis-handle the NULL detail
        row = (await rotated._fetchall("SELECT body, detail FROM response"))[0]
        assert row["detail"] is None  # NULL skipped (IS NOT NULL guard), not crashed
        assert row["body"].split(":", 3)[2] == active_id  # body rotated to the active key
        r = (await rotated.correlate_response(mid))[0]
        assert r.body == "reply-body" and r.detail is None
    finally:
        await rotated.close()


# --- EF-3: summary + metadata (MRN + patient name) encrypted at rest ---------


async def test_summary_metadata_encrypted_at_rest_and_decrypt(store) -> None:
    """EF-3: summary/metadata (direct MRN + patient name) ciphered at rest on SQL Server and
    decrypt on the detail + tracking-list read paths — parity with the SQLite/PG suites."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import PREFIX, AesGcmCipher
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


async def test_reencrypt_rotates_summary_and_metadata(store) -> None:
    """EF-3: summary/metadata are rotated under the active key like the body — not stranded under a
    retired key (which a later retired-key drop would make undecryptable)."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import AesGcmCipher
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

    active_id = AesGcmCipher(k2).active_key_id
    rotated = await SqlServerStore.open(settings, cipher=AesGcmCipher(k2, retired_keys=[k1]))
    try:
        await rotated.reencrypt_to_active()
        row = (await rotated._fetchall("SELECT summary, metadata FROM messages"))[0]
        assert row["summary"].split(":", 3)[2] == active_id  # mfenc:v1:<active_id>:<blob>
        assert row["metadata"].split(":", 3)[2] == active_id
        [m] = await rotated.list_messages()
        assert (
            m["summary"] == summary and m["metadata"] == metadata
        )  # still decrypts under the new key
    finally:
        await rotated.close()


# --- H4: error / last_error / message_events.detail encrypted at rest ----------
# SQL Server parity with SQLite/Postgres: the three nullable disposition-text columns route through the
# SAME store cipher (mfenc:v1) — at-rest ciphertext, decrypt-on-read, rotated on rekey, and legacy
# plaintext migrated on open. The prior "SQL Server keeps these plaintext" residual is retired.


async def test_error_lasterror_detail_encrypted_at_rest_and_decrypt(store) -> None:
    """H4: messages.error / queue.last_error / message_events.detail are ciphertext at rest on SQL
    Server and decrypt on every read path — parity with the SQLite/PG suites. Error strings are plain
    (no HL7 delimiters) so safe_text leaves them intact and the round-trip is exact."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.crypto import PREFIX, AesGcmCipher
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

        # AT REST: every value is mfenc:v1:... ciphertext — the cleartext phrase never appears in the col.
        erow = (await s._fetchall("SELECT error FROM messages WHERE id=?", (eid,)))[0]
        assert erow["error"].startswith(PREFIX) and "bad parse" not in erow["error"]
        qrow = (await s._fetchall("SELECT last_error FROM queue WHERE message_id=?", (mid,)))[0]
        assert qrow["last_error"].startswith(PREFIX) and "refused" not in qrow["last_error"]
        drows = await s._fetchall(
            "SELECT detail FROM message_events WHERE detail IS NOT NULL ORDER BY id"
        )
        assert drows, "expected at least one event with a detail"
        for d in drows:
            assert d["detail"].startswith(PREFIX)  # no plaintext detail at rest
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
    from messagefoundry.store.crypto import AesGcmCipher
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

    active_id = AesGcmCipher(k2).active_key_id
    rotated = await SqlServerStore.open(settings, cipher=AesGcmCipher(k2, retired_keys=[k1]))
    try:
        await rotated.reencrypt_to_active()
        # every non-null disposition-text value now carries the ACTIVE key id (mfenc:v1:<active>:...).
        blobs = await rotated._fetchall(
            "SELECT error AS v FROM messages WHERE error IS NOT NULL"
            " UNION ALL SELECT last_error FROM queue WHERE last_error IS NOT NULL"
            " UNION ALL SELECT detail FROM message_events WHERE detail IS NOT NULL"
        )
        assert blobs, "expected rotated disposition-text values"
        for r in blobs:
            assert r["v"].split(":", 3)[2] == active_id, r["v"]
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
    from messagefoundry.store.crypto import PREFIX, AesGcmCipher
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
        # sanity: stored plaintext (no cipher prefix) before the migration runs.
        erow = (await plain._fetchall("SELECT error FROM messages WHERE id=?", (eid,)))[0]
        assert erow["error"] == err and not erow["error"].startswith(PREFIX)
    finally:
        await plain.close()

    # (2) Re-open WITH a key: open() runs _encrypt_existing_rows and migrates the legacy plaintext.
    keyed = await SqlServerStore.open(settings, cipher=AesGcmCipher(b"k" * 32))
    try:
        erow = (await keyed._fetchall("SELECT error FROM messages WHERE id=?", (eid,)))[0]
        assert erow["error"].startswith(PREFIX) and "bad parse" not in erow["error"]
        qrow = (await keyed._fetchall("SELECT last_error FROM queue WHERE message_id=?", (mid,)))[0]
        assert qrow["last_error"].startswith(PREFIX)
        drows = await keyed._fetchall("SELECT detail FROM message_events WHERE detail IS NOT NULL")
        assert drows and all(d["detail"].startswith(PREFIX) for d in drows)
        # reads still return the original cleartext after the in-place migration.
        assert (await keyed.get_message(eid))["error"] == err
        assert (await keyed.list_dead())[0]["last_error"] == fail
    finally:
        await keyed.close()


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
