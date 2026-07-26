# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0073 — ownership-scoped crash recovery on a live PostgreSQL (engine shards, ONE unified store).

The Postgres twin of ``test_shard_recovery_sqlserver.py`` — same target invariant, same in-process
(no real processes) simulation, closing the SS/PG parity gap the plan calls out (the SS end-to-end
2-shard crash+recover+drain test exists; the PG one did not — PG had only the unit-level scoped-reset
primitive coverage in ``test_postgres_store.py``).

**Gated**: skipped unless ``MEFOR_TEST_POSTGRES`` is set (plus ``MEFOR_STORE_*`` connection env), so
it's a no-op locally and in normal CI; a CI Postgres service-container job runs it for real. Requires
the ``postgres`` extra (``asyncpg``); for a loopback dev Postgres (``encrypt=false``) also set
``MEFOR_ALLOW_INSECURE_TLS=1``.

THE TARGET INVARIANT, simulated in-process: two engine shards share ONE store; shard A "crashes"
mid-flight at EVERY stage while shard B is live mid-flight. Shard A's restart runs
``reset_stale_inflight(owned=A_lanes)`` and must re-pend EXACTLY A's rows — its inbound channel's
ingress/routed residue plus its rendezvous-owned outbound lane — never touching B's in-flight rows.

**The Postgres-specific subtlety** (already proven at unit level in
``test_reset_stale_inflight_owned_scopes_lanes_and_preserves_sibling_lease``): Postgres **stamps the
owner + lease on claim**, so a sibling shard's in-flight rows carry a non-null owner/lease. A scoped
restart must discriminate by **lane**, never by the claim-owner column — the live sibling's rows must
survive with owner AND lease intact. So the scoped resets run INSIDE the sibling's lease window (claim
at 110, ttl 60 → expires 170; reset at 120/121), before the FIFO claim's own expired-lease
stranded-head reclaim could legitimately take the sibling's head and muddy the "untouched" assertion.

After both shards recover, a full drain proves zero loss (every seeded message reaches PROCESSED, no
stranded pending/inflight rows) and no duplicate outbound completion (exactly one outbound row per
message-destination; the fanned-out message completes once per lane).

Each shard's :class:`OwnedLanes` is derived exactly as ``Engine._owned_lanes`` does: channels = the
shard-filtered registry's inbound map, destinations = ``owned_destination_set`` under the pinned
``all_shard_ids`` universe that ``filter_registry_for_shard`` attaches."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import pytest

from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    OutboundConnection,
    Registry,
)
from messagefoundry.pipeline.sharding import (
    filter_registry_for_shard,
    owned_destination_set,
    owner_shard_of_destination,
)
from messagefoundry.store import MessageStatus, OutboxStatus, Stage
from messagefoundry.store.store import OwnedLanes

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_POSTGRES"),
    reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* connection env) to run Postgres tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

# The pinned shard universe: two engine shards, one unified store.
SHARD_IDS = ("a", "b")

# Lease-window discipline (see module docstring): seed at ENQ_NOW, claim at CLAIM_NOW so every
# in-flight row's lease expires at CLAIM_NOW + ttl(60) = 170; run the scoped resets BEFORE then so a
# live sibling's held head can't be swept by the FIFO expired-lease stranded-head reclaim. The drain
# happens well past the window (DRAIN_NOW) — by then nothing is in-flight, so no reclaim can fire.
ENQ_NOW = 100.0
CLAIM_NOW = 110.0
RESET_NOW_A = 120.0
RESET_NOW_B = 121.0
DRAIN_NOW = 10_000.0


def _find_dest(shard: str) -> str:
    """Search destination names until rendezvous hashing assigns one to ``shard`` — the same
    deterministic owner every process derives (restart-stable, no runtime coordination)."""
    for i in range(1000):
        name = f"OB_T{i}"
        if owner_shard_of_destination(name, SHARD_IDS) == shard:
            return name
    raise AssertionError(f"no destination found for shard {shard!r} in 1000 candidates")


DEST_A = _find_dest("a")  # the outbound lane shard a owns (claims/delivers/recovers)
DEST_B = _find_dest("b")  # the outbound lane shard b owns


# Tables cleaned between tests (subset of test_postgres_store.py's fixture — this file touches only the
# queue/messages/response family, but TRUNCATE ... CASCADE keeps the FK order safe).
_TABLES = (
    "message_events",
    "queue",
    "response",
    "delivered_keys",
    "messages",
    "state",
)


@pytest.fixture
async def store() -> AsyncIterator[Any]:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    # Clean slate (the container DB persists across tests in a run).
    async with s._pool.acquire() as conn:
        await conn.execute("TRUNCATE " + ", ".join(_TABLES) + " RESTART IDENTITY CASCADE")
    # open() seeded read-through caches BEFORE this truncate; re-load them from the now-empty tables so
    # a prior test's state rows don't linger in this handle's in-memory caches (Track B Step 6b idiom).
    await s._load_state_cache()
    yield s
    await s.close()


# --- topology: a 2-shard config graph on one store -----------------------------------------------


def _reg_two_shards() -> Registry:
    """IB_A (shard a) + IB_B (shard b) → r → h; both shards share BOTH outbound destinations."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_A",
            ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-in", "pattern": "*.hl7"}),
            router="r",
            shard="a",
        )
    )
    reg.add_inbound(
        InboundConnection(
            "IB_B",
            ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-in", "pattern": "*.hl7"}),
            router="r",
            shard="b",
        )
    )
    for dest in (DEST_A, DEST_B):
        reg.add_outbound(
            OutboundConnection(dest, ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/o"}))
        )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: None)
    return reg


def _lanes(shard: str) -> OwnedLanes:
    """Derive one shard's OwnedLanes EXACTLY as ``Engine._owned_lanes`` does: filter the config
    graph for the shard, then channels = the filtered inbound map, destinations = the rendezvous-
    owned subset under the pinned universe the filter attached."""
    filtered = filter_registry_for_shard(_reg_two_shards(), shard)
    assert filtered.shard_id == shard  # >1-shard config → identity attached
    assert filtered.all_shard_ids == SHARD_IDS
    return OwnedLanes(
        channels=frozenset(filtered.inbound),
        destinations=owned_destination_set(filtered, filtered.shard_id, filtered.all_shard_ids),
    )


def test_topology_partitions_lanes_pg() -> None:
    # Pin the constructed split: each shard owns its inbound channel + exactly one outbound lane.
    a, b = _lanes("a"), _lanes("b")
    assert a.channels == frozenset({"IB_A"}) and a.destinations == frozenset({DEST_A})
    assert b.channels == frozenset({"IB_B"}) and b.destinations == frozenset({DEST_B})


# --- store drivers (explicit clock: pass now for lease-window control) -----------------------------


async def _seed_shard_midflight(store: Any, channel: str) -> tuple[list[str], list[str]]:
    """Seed one shard 'crashed mid-flight at every pipeline stage' on the shared store.

    Three messages on ``channel``: msg1 claimed at INGRESS (left INFLIGHT), msg2 claimed at ROUTED
    (left INFLIGHT), msg3 transformed to outbound rows on BOTH destinations (the shard's own lane is
    claimed INFLIGHT by the caller). Returns ``(message_ids, inflight_row_ids_before_outbound)`` —
    the outbound claim is the caller's (lane ownership, not message origin, decides who claims it)."""
    mids: list[str] = []
    inflight: list[str] = []
    # msg1: crashed after the ingress claim, before routing.
    mid1 = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=ENQ_NOW)
    ing1 = await store.claim_next_fifo(channel, CLAIM_NOW, stage=Stage.INGRESS.value)
    assert ing1 is not None
    mids.append(mid1)
    inflight.append(ing1.id)
    # msg2: routed, crashed after the routed claim, before transform.
    mid2 = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=ENQ_NOW)
    ing2 = await store.claim_next_fifo(channel, CLAIM_NOW, stage=Stage.INGRESS.value)
    assert ing2 is not None
    await store.route_handoff(
        ingress_id=ing2.id,
        message_id=mid2,
        channel_id=channel,
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
        now=ENQ_NOW,
    )
    rtd2 = await store.claim_next_fifo(channel, CLAIM_NOW, stage=Stage.ROUTED.value)
    assert rtd2 is not None
    mids.append(mid2)
    inflight.append(rtd2.id)
    # msg3: transformed with fan-out to BOTH destinations (rows land PENDING on both lanes).
    mid3 = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=ENQ_NOW)
    ing3 = await store.claim_next_fifo(channel, CLAIM_NOW, stage=Stage.INGRESS.value)
    assert ing3 is not None
    await store.route_handoff(
        ingress_id=ing3.id,
        message_id=mid3,
        channel_id=channel,
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
        now=ENQ_NOW,
    )
    rtd3 = await store.claim_next_fifo(channel, CLAIM_NOW, stage=Stage.ROUTED.value)
    assert rtd3 is not None
    await store.transform_handoff(
        routed_id=rtd3.id,
        message_id=mid3,
        channel_id=channel,
        deliveries=[(DEST_A, "pa"), (DEST_B, "pb")],
        now=ENQ_NOW,
    )
    mids.append(mid3)
    return mids, inflight


async def _claim_owned_outbound(store: Any, dest: str) -> str:
    """The shard's delivery worker claims its OWNED lane's head (left INFLIGHT = crashed
    mid-delivery). Which message produced the row is irrelevant — lane ownership decides."""
    item = await store.claim_next_fifo(dest, CLAIM_NOW, stage=Stage.OUTBOUND.value)
    assert item is not None and item.destination_name == dest
    return str(item.id)


async def _queue_row(store: Any, row_id: str) -> Any:
    row = await store._fetchone(
        "SELECT owner, lease_expires_at, status FROM queue WHERE id=$1", row_id
    )
    assert row is not None, f"queue row {row_id} vanished"
    return row


async def _row_status(store: Any, row_id: str) -> str:
    return str((await _queue_row(store, row_id))["status"])


async def _live_rows(store: Any) -> list[dict[str, Any]]:
    return await store._fetchall(
        "SELECT id, message_id, stage, status FROM queue WHERE status IN ($1,$2)",
        OutboxStatus.PENDING.value,
        OutboxStatus.INFLIGHT.value,
    )


async def _status(store: Any, mid: str) -> str:
    msg = await store.get_message(mid)
    assert msg is not None
    return str(msg["status"])


# ============================ the target invariant ============================


async def test_scoped_reset_recovers_exactly_own_lanes_then_drains_zero_loss_pg(store: Any) -> None:
    """Shard A crashed mid-flight at every stage while shard B is live mid-flight, one shared store:
    A's scoped reset re-pends EXACTLY A's rows (count + per-row status), B's stay INFLIGHT **with
    their claim-stamped owner + lease intact** (the PG subtlety); after B's scoped reset too, a full
    drain loses nothing and completes each outbound exactly once."""
    lanes_a, lanes_b = _lanes("a"), _lanes("b")
    ttl = store._settings.lease_ttl_seconds

    # --- seed BOTH shards' mid-flight work on the ONE store ---
    mids_a, rows_a = await _seed_shard_midflight(store, "IB_A")
    mids_b, rows_b = await _seed_shard_midflight(store, "IB_B")
    rows_a.append(await _claim_owned_outbound(store, DEST_A))
    rows_b.append(await _claim_owned_outbound(store, DEST_B))
    for row_id in (*rows_a, *rows_b):
        row = await _queue_row(store, row_id)
        assert row["status"] == OutboxStatus.INFLIGHT.value
        # Postgres stamps owner + lease on claim — every in-flight row carries this handle's owner.
        assert row["owner"] == store._owner
        assert row["lease_expires_at"] == pytest.approx(CLAIM_NOW + ttl)

    # --- shard A restarts: ownership-scoped recovery, INSIDE shard B's lease window ---
    recovered_a = await store.reset_stale_inflight(now=RESET_NOW_A, owned=lanes_a)
    assert recovered_a == len(rows_a) == 3  # ingress + routed + owned-outbound, nothing else
    for row_id in rows_a:
        row = await _queue_row(store, row_id)
        assert row["status"] == OutboxStatus.PENDING.value
        assert row["owner"] is None and row["lease_expires_at"] is None  # cleared on re-pend
    # Every one of live shard B's in-flight rows is untouched — still INFLIGHT AND (the PG guarantee)
    # still owner/lease-stamped: A's scoped restart discriminated by LANE, not the claim-owner column.
    for row_id in rows_b:
        row = await _queue_row(store, row_id)
        assert row["status"] == OutboxStatus.INFLIGHT.value
        assert row["owner"] == store._owner
        assert row["lease_expires_at"] == pytest.approx(CLAIM_NOW + ttl)

    # --- shard B restarts too (still inside its own lease window) ---
    recovered_b = await store.reset_stale_inflight(now=RESET_NOW_B, owned=lanes_b)
    assert recovered_b == len(rows_b) == 3
    for row_id in rows_b:
        row = await _queue_row(store, row_id)
        assert row["status"] == OutboxStatus.PENDING.value
        assert row["owner"] is None and row["lease_expires_at"] is None

    # --- drain-and-verify: re-claim + complete EVERYTHING; zero loss, no duplicate completion.
    # Drain well past the lease window (DRAIN_NOW) — nothing is in-flight now, so no expired-lease
    # reclaim can fire; every claimed row is a cleanly re-pended one. ---
    for channel, dest in (("IB_A", DEST_A), ("IB_B", DEST_B)):
        for _ in range(10):  # bounded: at most 1 recovered ingress row per channel
            ing = await store.claim_next_fifo(channel, DRAIN_NOW, stage=Stage.INGRESS.value)
            if ing is None:
                break
            await store.route_handoff(
                ingress_id=ing.id,
                message_id=ing.message_id,
                channel_id=channel,
                handlers=[("h", ing.payload)],
                disposition=MessageStatus.ROUTED,
                now=DRAIN_NOW,
            )
        for _ in range(10):  # recovered msg2 routed row + msg1's fresh one
            rtd = await store.claim_next_fifo(channel, DRAIN_NOW, stage=Stage.ROUTED.value)
            if rtd is None:
                break
            await store.transform_handoff(
                routed_id=rtd.id,
                message_id=rtd.message_id,
                channel_id=channel,
                deliveries=[(dest, rtd.payload)],
                now=DRAIN_NOW,
            )
    for dest in (DEST_A, DEST_B):
        for _ in range(20):
            item = await store.claim_next_fifo(dest, DRAIN_NOW, stage=Stage.OUTBOUND.value)
            if item is None:
                break
            await store.mark_done(item.id, now=DRAIN_NOW)

    # Zero rows lost: every seeded message reached the terminal PROCESSED disposition...
    for mid in (*mids_a, *mids_b):
        assert await _status(store, mid) == MessageStatus.PROCESSED.value
    # ...and no stranded pending/inflight rows remain at ANY stage.
    assert await _live_rows(store) == []
    # No duplicate outbound completion: exactly one DONE row per (message, destination) —
    # msg1/msg2 of each shard delivered once, msg3 fanned out to both lanes exactly once each.
    ob_rows = await store._fetchall(
        "SELECT message_id, destination_name, status FROM queue WHERE stage=$1",
        Stage.OUTBOUND.value,
    )
    assert all(r["status"] == OutboxStatus.DONE.value for r in ob_rows)
    pairs = [(r["message_id"], r["destination_name"]) for r in ob_rows]
    assert len(pairs) == len(set(pairs))  # never two rows for one message-destination
    per_mid = {mid: sum(1 for m, _d in pairs if m == mid) for mid in (*mids_a, *mids_b)}
    assert per_mid == {
        mids_a[0]: 1,
        mids_a[1]: 1,
        mids_a[2]: 2,  # fan-out: one per destination, no dup
        mids_b[0]: 1,
        mids_b[1]: 1,
        mids_b[2]: 2,
    }


# ============================ stage composition + global fallback ============================


async def _seed_all_four_stages(store: Any, channel: str, dest: str) -> list[str]:
    """One INFLIGHT row at each of the four stages for one shard: ingress, routed, outbound, and a
    RESPONSE work-row (captured-reply re-ingress token, keyed on the shard's inbound channel)."""
    rows: list[str] = []
    # ingress
    await store.enqueue_ingress(channel_id=channel, raw=RAW, now=ENQ_NOW)
    ing = await store.claim_next_fifo(channel, CLAIM_NOW, stage=Stage.INGRESS.value)
    assert ing is not None
    rows.append(ing.id)
    # routed
    mid = await store.enqueue_ingress(channel_id=channel, raw=RAW, now=ENQ_NOW)
    ing2 = await store.claim_next_fifo(channel, CLAIM_NOW, stage=Stage.INGRESS.value)
    assert ing2 is not None
    await store.route_handoff(
        ingress_id=ing2.id,
        message_id=mid,
        channel_id=channel,
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
        now=ENQ_NOW,
    )
    rtd = await store.claim_next_fifo(channel, CLAIM_NOW, stage=Stage.ROUTED.value)
    assert rtd is not None
    rows.append(rtd.id)
    # outbound (the Step-A primitive is the shortest path to a claimable outbound row)
    await store.enqueue_message(channel_id=channel, raw=RAW, deliveries=[(dest, "p")], now=ENQ_NOW)
    out = await store.claim_next_fifo(dest, CLAIM_NOW, stage=Stage.OUTBOUND.value)
    assert out is not None
    rows.append(out.id)
    # response: deliver a second outbound WITH a captured reply owing a re-ingress on this channel
    await store.enqueue_message(channel_id=channel, raw=RAW, deliveries=[(dest, "p2")], now=ENQ_NOW)
    out2 = await store.claim_next_fifo(dest, CLAIM_NOW, stage=Stage.OUTBOUND.value)
    assert out2 is not None
    await store.complete_with_response(
        out2.id, body="ACK", outcome="AA", reingress_to=channel, now=ENQ_NOW
    )
    resp = await store.claim_next_fifo(channel, CLAIM_NOW, stage=Stage.RESPONSE.value)
    assert resp is not None and resp.stage == Stage.RESPONSE.value
    rows.append(resp.id)
    return rows


async def test_scoped_reset_stage_composition_empty_sets_and_global_pg(store: Any) -> None:
    """The smaller invariants: (1) an EMPTY owned set matches NOTHING (recovering 'no lanes' never
    widens into 'all lanes') — rows keep status AND owner/lease; (2) per-``stage=`` scoped resets
    compose across all four stages to the same rows the all-stage scoped pass owns; (3) ``owned=None``
    stays the unconditional global reset (byte-identical single-node recovery)."""
    lanes_a = _lanes("a")
    ttl = store._settings.lease_ttl_seconds
    rows_a = await _seed_all_four_stages(store, "IB_A", DEST_A)
    rows_b = await _seed_all_four_stages(store, "IB_B", DEST_B)

    # (1) empty sets: statement skipped per stage — 0 recovered, all 8 rows still INFLIGHT AND still
    # owner/lease-stamped (never widened into a global owner/lease strip).
    empty = OwnedLanes(channels=frozenset(), destinations=frozenset())
    assert await store.reset_stale_inflight(now=RESET_NOW_A, owned=empty) == 0
    for row_id in (*rows_a, *rows_b):
        row = await _queue_row(store, row_id)
        assert row["status"] == OutboxStatus.INFLIGHT.value
        assert row["owner"] == store._owner
        assert row["lease_expires_at"] == pytest.approx(CLAIM_NOW + ttl)

    # (2) stage-by-stage composition for shard A: each stage recovers exactly its one row.
    per_stage = {
        st.value: await store.reset_stale_inflight(now=RESET_NOW_A, stage=st.value, owned=lanes_a)
        for st in Stage
    }
    assert per_stage == {
        Stage.INGRESS.value: 1,
        Stage.ROUTED.value: 1,
        Stage.OUTBOUND.value: 1,
        Stage.RESPONSE.value: 1,
    }
    for row_id in rows_a:
        assert await _row_status(store, row_id) == OutboxStatus.PENDING.value
    for row_id in rows_b:
        assert await _row_status(store, row_id) == OutboxStatus.INFLIGHT.value  # B untouched

    # (3) owned=None: the unconditional global path recovers B's residue across all stages.
    assert await store.reset_stale_inflight(now=RESET_NOW_B) == len(rows_b) == 4
    for row_id in rows_b:
        assert await _row_status(store, row_id) == OutboxStatus.PENDING.value


async def test_scoped_reset_chunks_wide_lane_sets_pg(store: Any) -> None:
    """An owned destination set wider than ``_RESET_LANE_CHUNK`` (500) splits into multiple chunked
    ``IN`` statements inside the one transaction — the real lane in the overflow set is still
    recovered exactly once."""
    await store.enqueue_message(channel_id="IB_A", raw=RAW, deliveries=[(DEST_A, "p")], now=ENQ_NOW)
    out = await store.claim_next_fifo(DEST_A, CLAIM_NOW, stage=Stage.OUTBOUND.value)
    assert out is not None
    wide = OwnedLanes(
        channels=frozenset(),
        destinations=frozenset({DEST_A, *(f"OB_PAD_{i}" for i in range(600))}),  # 601 → 2 chunks
    )
    assert await store.reset_stale_inflight(now=RESET_NOW_A, owned=wide) == 1
    assert await _row_status(store, out.id) == OutboxStatus.PENDING.value
