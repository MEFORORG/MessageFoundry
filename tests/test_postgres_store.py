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

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

# Tables cleaned between tests (FK order: children before parents).
_TABLES = (
    "message_events",
    "audit_log",
    "lane_leases",
    "cluster_config",
    "queue",
    "messages",
    "state",
    "state_version",
    "reference",
    "reference_version",
    "sessions",
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


async def test_renew_leases_extends_own_inflight_rows(store) -> None:
    """renew_leases extends lease_expires_at for this owner's inflight rows, returns the count, and
    leaves a non-inflight row and a different owner's row untouched."""
    # This owner's inflight row.
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    mine = (await store.claim_ready(now=200.0, destination_name="OB1"))[0]
    # A done (non-inflight) row owned by this store.
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB2", "p")], now=100.0)
    done = (await store.claim_ready(now=200.0, destination_name="OB2"))[0]
    await store.mark_done(done.id, now=205.0)

    # A second store instance (distinct owner) claims its own inflight row.
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    other = await PostgresStore.open(load_settings(environ=os.environ).store)
    try:
        assert other._owner != store._owner
        await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB3", "p")], now=100.0)
        theirs = (await other.claim_ready(now=200.0, destination_name="OB3"))[0]
        theirs_before = (await _queue_row(store, theirs.id))["lease_expires_at"]

        renewed = await store.renew_leases([mine.id, done.id, theirs.id], now=300.0)
        assert renewed == 1  # only this owner's still-inflight row
        assert (await _queue_row(store, mine.id))["lease_expires_at"] == pytest.approx(
            300.0 + _ttl(store)
        )
        # The done row (terminal) and the other owner's row are unchanged.
        assert (await _queue_row(store, done.id))["status"] == OutboxStatus.DONE.value
        assert (await _queue_row(store, theirs.id))["lease_expires_at"] == theirs_before
    finally:
        await other.close()


async def test_reclaim_expired_leases_only_reclaims_expired(store) -> None:
    """reclaim_expired_leases reclaims only rows whose lease is in the past; a fresh/renewed lease is
    left in flight; it sets the row pending with owner/lease cleared and next_attempt_at=now."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    expired = (await store.claim_ready(now=200.0, destination_name="OB1"))[0]
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB2", "p")], now=100.0)
    fresh = (await store.claim_ready(now=200.0, destination_name="OB2"))[0]

    # Sweep at a time after `expired`'s lease but before `fresh`'s would be only fair if equal — both
    # were claimed at 200 with the same ttl, so renew `fresh` to push its lease out.
    await store.renew_leases([fresh.id], now=250.0)
    sweep_at = 200.0 + _ttl(store) + 1.0  # past expired's lease, before fresh's renewed lease
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


# --- Track B Step 5: per-lane FIFO ownership (atomic lane leases) ----------------


async def _lane_lease(store, lane: str):
    """Read a lane_leases row directly (owner + expiry)."""
    async with store._pool.acquire() as conn:
        return await conn.fetchrow(
            "SELECT owner, lease_expires_at FROM lane_leases WHERE lane=$1", lane
        )


async def test_fifo_lane_mutual_exclusion(store) -> None:
    """With an owner set, claiming a FIFO lane leases it to that node; a concurrent claim by a
    DIFFERENT owner returns None (it does not own the lane) even though rows remain."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], now=100.0)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p2")], now=101.0)

    a = await store.claim_next_fifo("OB1", now=200.0, owner="A")
    assert a is not None and a.payload == "p1"  # A claims the head and now holds the lane
    # B does not own the lane → no claim, even though p2 is still pending.
    assert await store.claim_next_fifo("OB1", now=200.0, owner="B") is None

    lease = await _lane_lease(store, "outbound:OB1")
    assert lease is not None and lease["owner"] == "A"
    assert lease["lease_expires_at"] == pytest.approx(200.0 + _ttl(store))  # unexpired


async def test_fifo_strict_order_under_contention(store) -> None:
    """Two owners A/B alternately poll one lane with rows R1,R2,R3; only the lane owner ever claims, so
    the rows come out in strict order R1,R2,R3 and never two at once."""
    for i, t in enumerate((100.0, 101.0, 102.0)):
        await store.enqueue_message(
            channel_id="IB", raw=RAW, deliveries=[("OB1", f"R{i + 1}")], now=t
        )
    claimed: list[str] = []
    now = 200.0
    for _ in range(3):
        # Both nodes poll; the non-owner gets None (lane is owned), the owner claims the single head.
        a = await store.claim_next_fifo("OB1", now=now, owner="A")
        b = await store.claim_next_fifo("OB1", now=now, owner="B")
        got = [x for x in (a, b) if x is not None]
        assert len(got) == 1  # exactly one node claims — never two at once
        item = got[0]
        claimed.append(item.payload)
        await store.mark_done(item.id, now=now + 0.5)  # advance the head for the next round
        now += 1.0
    assert claimed == ["R1", "R2", "R3"]  # strict FIFO across the contending nodes


async def test_fifo_lane_handoff_on_expiry(store) -> None:
    """A lane held by owner A whose lease has expired can be taken over by owner B atomically — a freed
    lane moves to another node, still one owner at a time."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], now=100.0)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p2")], now=101.0)

    a = await store.claim_next_fifo("OB1", now=200.0, owner="A")
    assert a is not None and a.payload == "p1"
    await store.mark_done(a.id, now=201.0)
    # Before A's lane lease expires, B cannot claim.
    assert await store.claim_next_fifo("OB1", now=200.0, owner="B") is None

    # Age the lane lease out (now past 200 + ttl): B can now take over the freed lane and claim p2.
    expired_at = 200.0 + _ttl(store) + 1.0
    b = await store.claim_next_fifo("OB1", now=expired_at, owner="B")
    assert b is not None and b.payload == "p2"
    lease = await _lane_lease(store, "outbound:OB1")
    assert lease is not None and lease["owner"] == "B"  # ownership transferred atomically


async def test_fifo_crash_mid_delivery_preserves_order(store) -> None:
    """A node that crashes holding the lane head leaves N inflight under an expired ROW lease. When the
    next node takes over the (expired) lane lease, it must NOT skip past the stranded N and deliver N+1
    first — the owned claim reclaims this lane's expired-lease inflight rows in the SAME txn before the
    head SELECT, so the recovered head N blocks the lane and is the one delivered. This is the strict
    cross-node FIFO invariant under crash (the row-lease reclaim must not be decoupled from the lane
    handoff)."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "N")], now=100.0)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "Np1")], now=101.0)

    # A claims the head N and then "crashes": N stays inflight (no mark_done/mark_failed), and A stops
    # renewing both its lane lease and N's row lease.
    a = await store.claim_next_fifo("OB1", now=200.0, owner="A")
    assert a is not None and a.payload == "N"  # N is now inflight under A

    # Past the TTL: A's lane lease AND N's row lease have both expired. B takes over the lane.
    expired_at = 200.0 + _ttl(store) + 1.0
    b = await store.claim_next_fifo("OB1", now=expired_at, owner="B")
    # B must get the RECOVERED head N, never N+1 ahead of it — strict order survives the crash.
    assert b is not None and b.payload == "N"


async def test_fifo_strict_order_under_contention_either_owner_wins(store) -> None:
    """Symmetric to the A-first contention test: when B polls the empty-lane FIRST it becomes the single
    owner and A is the one blocked, proving the winner is whoever acquires first regardless of identity
    (not a hard-coded A-always-wins)."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], now=100.0)
    # B polls first this round → B wins the lane; A then gets None.
    b = await store.claim_next_fifo("OB1", now=200.0, owner="B")
    assert b is not None and b.payload == "p1"
    assert await store.claim_next_fifo("OB1", now=200.0, owner="A") is None
    lease = await _lane_lease(store, "outbound:OB1")
    assert lease is not None and lease["owner"] == "B"


async def test_fifo_owner_none_parity_no_lane_lease(store) -> None:
    """Without an owner, claim_next_fifo behaves exactly as the existing single-node FIFO claim and
    creates NO lane_leases row (the byte-identical path)."""
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p1")], now=100.0)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p2")], now=101.0)

    first = await store.claim_next_fifo("OB1", now=200.0)
    assert first is not None and first.payload == "p1"
    await store.mark_done(first.id, now=201.0)
    second = await store.claim_next_fifo("OB1", now=202.0)
    assert second is not None and second.payload == "p2"
    # No lane lease was ever taken on the no-owner path.
    assert await _lane_lease(store, "outbound:OB1") is None


async def test_fifo_ingress_lane_owned_by_channel(store) -> None:
    """Ingress lanes are keyed by channel_id, so the lane key is ``ingress:<channel>`` — proving the
    lane key is stage-aware for the routing/transform stages too."""
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    item = await store.claim_next_fifo("IB", now=200.0, stage=Stage.INGRESS.value, owner="A")
    assert item is not None
    lease = await _lane_lease(store, "ingress:IB")
    assert lease is not None and lease["owner"] == "A"
    # A different node cannot claim the same ingress lane while A holds it.
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=101.0)
    assert (
        await store.claim_next_fifo("IB", now=200.0, stage=Stage.INGRESS.value, owner="B")
    ) is None


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
    # Drop the lease columns to simulate a Step-1 table that predates them.
    async with store._pool.acquire() as conn:
        await conn.execute("ALTER TABLE queue DROP COLUMN owner, DROP COLUMN lease_expires_at")
    assert {"owner", "lease_expires_at"}.isdisjoint(await _queue_columns(store))

    # Re-run the schema migration (runs the guarded ADD COLUMN under the schema advisory lock).
    await store._ensure_schema()

    # The columns are restored...
    assert {"owner", "lease_expires_at"} <= await _queue_columns(store)
    # ...and a claim successfully writes them.
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    item = (await store.claim_ready(now=200.0))[0]
    row = await _queue_row(store, item.id)
    assert row["owner"] == store._owner and row["lease_expires_at"] is not None


async def test_schema_migration_is_idempotent_when_columns_present(store) -> None:
    """Re-running the migration against an already-migrated table is a no-op that leaves the columns in
    place (the information_schema guard means no ALTER fires)."""
    assert {"owner", "lease_expires_at"} <= await _queue_columns(store)
    await store._ensure_schema()  # already-migrated DB: guarded ADD COLUMN must not fire/error
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


async def test_renew_leases_empty_and_no_match_return_zero(store) -> None:
    """The zero-row command-tag path: renew_leases([]) and a renew that matches no owned inflight row
    both return 0 (a worker timer will hit the empty case routinely)."""
    assert await store.renew_leases([], now=300.0) == 0
    # A row owned by THIS store but already done — no inflight match, so 0.
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB1", "p")], now=100.0)
    done = (await store.claim_ready(now=200.0))[0]
    await store.mark_done(done.id, now=205.0)
    assert await store.renew_leases([done.id], now=300.0) == 0


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
    async with store._pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS nodes")


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
        # owns_lane() is real in Step 5: this node has claimed no lane, so it owns none (the cached
        # set is empty). A lane only becomes owned after claim_next_fifo(owner=...) acquires its lease.
        assert coord.owns_lane("any-lane") is False
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
