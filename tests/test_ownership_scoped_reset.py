# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Ownership-scoped crash recovery (ADR 0073), SQLite store level.

``reset_stale_inflight(owned=OwnedLanes(...))`` must recover exactly the caller's config-graph
lanes — ``channels`` scoping the ``channel_id``-keyed stages (ingress/routed/response),
``destinations`` scoping outbound — and never re-pend a live sibling shard's in-flight rows.
``owned=None`` stays the byte-identical global recovery; an EMPTY owned set matches NOTHING.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.store.store import (
    MessageStore,
    OutboxStatus,
    OwnedLanes,
    Stage,
    owned_lane_scope,
)

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "scoped.db")
    yield s
    await s.close()


async def _row_status(store: MessageStore, row_id: str) -> str:
    cur = await store._db.execute("SELECT status FROM queue WHERE id=?", (row_id,))
    row = await cur.fetchone()
    assert row is not None, f"queue row {row_id!r} vanished"
    return str(row["status"])


async def _seed_inflight_ingress(store: MessageStore, channel: str) -> str:
    """One INFLIGHT ingress row on ``channel``; returns the queue-row id."""
    await store.enqueue_ingress(channel_id=channel, raw=RAW)
    item = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value)
    assert item is not None
    return item.id


async def _seed_inflight_routed(store: MessageStore, channel: str, handler: str) -> str:
    """One INFLIGHT routed-stage row on ``channel`` (row inserted directly, then claimed via the
    real claim path — same idiom as test_staged_pipeline's _insert_routed_row)."""
    mid = await store.enqueue_ingress(channel_id=channel, raw=RAW)
    rid = f"routed-{handler}-{channel}"
    await store._db.execute(
        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
        " payload, status, attempts, next_attempt_at, created_at, updated_at)"
        " VALUES (?,?,?,?,NULL,?,?,?,0,?,?,?)",
        (
            rid,
            mid,
            Stage.ROUTED.value,
            channel,
            handler,
            store._cipher.encrypt(RAW),
            OutboxStatus.PENDING.value,
            0.0,
            0.0,
            0.0,
        ),
    )
    await store._db.commit()
    item = await store.claim_next_fifo(channel, stage=Stage.ROUTED.value)
    assert item is not None and item.id == rid
    return rid


async def _seed_inflight_outbound(store: MessageStore, channel: str, dest: str) -> str:
    """One INFLIGHT outbound row on destination lane ``dest``."""
    await store.enqueue_message(channel_id=channel, raw=RAW, deliveries=[(dest, RAW)])
    item = await store.claim_next_fifo(dest)
    assert item is not None
    return item.id


async def _seed_inflight_response(store: MessageStore, loopback: str) -> str:
    """One INFLIGHT Stage.RESPONSE work-row keyed by the loopback ``channel_id`` (seeded the way
    tests/test_reingress.py does — direct insert of the artifact-reference row, then a real claim)."""
    # NB: a distinct destination (OB_RESP) so this seed's pending outbound row never interleaves
    # with the outbound-lane seeds' FIFO claims on OB_X/OB_Y.
    mid = await store.enqueue_message(channel_id="IB_REAL", raw=RAW, deliveries=[("OB_RESP", RAW)])
    rid = f"resp-{loopback}"
    ref = store._enc(f"{mid}\x1fOB_RESP\x1f1")
    await store._db.execute(
        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
        " payload, status, attempts, next_attempt_at, created_at, updated_at)"
        " VALUES (?,?,?,?,NULL,NULL,?,?,0,?,?,?)",
        (rid, mid, Stage.RESPONSE.value, loopback, ref, OutboxStatus.PENDING.value, 0.0, 0.0, 0.0),
    )
    await store._db.commit()
    item = await store.claim_next_fifo(loopback, stage=Stage.RESPONSE.value)
    assert item is not None and item.id == rid
    return rid


async def _seed_all_lanes(store: MessageStore) -> dict[str, str]:
    """INFLIGHT rows across every stage on two channels (A/B), two response loopbacks, and two
    destinations (X/Y). Returns lane-label -> queue-row id."""
    return {
        "ingress_A": await _seed_inflight_ingress(store, "IB_A"),
        "ingress_B": await _seed_inflight_ingress(store, "IB_B"),
        "routed_A": await _seed_inflight_routed(store, "IB_A", "h1"),
        "routed_B": await _seed_inflight_routed(store, "IB_B", "h2"),
        "response_A": await _seed_inflight_response(store, "IB_LOOP_A"),
        "response_B": await _seed_inflight_response(store, "IB_LOOP_B"),
        "outbound_X": await _seed_inflight_outbound(store, "IB_A", "OB_X"),
        "outbound_Y": await _seed_inflight_outbound(store, "IB_B", "OB_Y"),
    }


OWNED_A_X = frozenset({"ingress_A", "routed_A", "response_A", "outbound_X"})


async def test_scoped_reset_recovers_only_owned_lanes_then_global_gets_the_rest(
    store: MessageStore,
) -> None:
    # Shard 1 owns channels {IB_A, IB_LOOP_A} + destination {OB_X}: its scoped reset recovers
    # exactly its four rows (one per stage); shard 2's rows stay INFLIGHT untouched.
    rows = await _seed_all_lanes(store)
    owned = OwnedLanes(channels=frozenset({"IB_A", "IB_LOOP_A"}), destinations=frozenset({"OB_X"}))
    recovered = await store.reset_stale_inflight(owned=owned)
    assert recovered == 4
    for label, rid in rows.items():
        want = OutboxStatus.PENDING.value if label in OWNED_A_X else OutboxStatus.INFLIGHT.value
        assert await _row_status(store, rid) == want, label
    # owned=None default remains the global recovery: everything left over is re-pended.
    assert await store.reset_stale_inflight() == len(rows) - 4
    for rid in rows.values():
        assert await _row_status(store, rid) == OutboxStatus.PENDING.value


async def test_global_default_recovers_all_stages_and_lanes(store: MessageStore) -> None:
    rows = await _seed_all_lanes(store)
    assert await store.reset_stale_inflight() == len(rows)
    for label, rid in rows.items():
        assert await _row_status(store, rid) == OutboxStatus.PENDING.value, label


async def test_empty_owned_sets_match_nothing(store: MessageStore) -> None:
    # "Recovering no lanes" must never widen into "recovering all lanes": an empty set skips its
    # stages entirely (no IN () statement) — zero rows recovered, everything still INFLIGHT.
    rows = await _seed_all_lanes(store)
    empty = OwnedLanes(channels=frozenset(), destinations=frozenset())
    assert await store.reset_stale_inflight(owned=empty) == 0
    for label, rid in rows.items():
        assert await _row_status(store, rid) == OutboxStatus.INFLIGHT.value, label


async def test_stage_composes_with_owned(store: MessageStore) -> None:
    # stage='outbound' + owned: only the OWNED outbound lane is touched — the non-owned outbound
    # lane AND the owned channel's ingress/routed/response rows all stay INFLIGHT.
    rows = await _seed_all_lanes(store)
    owned = OwnedLanes(channels=frozenset({"IB_A", "IB_LOOP_A"}), destinations=frozenset({"OB_X"}))
    assert await store.reset_stale_inflight(stage=Stage.OUTBOUND.value, owned=owned) == 1
    for label, rid in rows.items():
        want = OutboxStatus.PENDING.value if label == "outbound_X" else OutboxStatus.INFLIGHT.value
        assert await _row_status(store, rid) == want, label


async def test_owned_channel_does_not_recover_outbound_and_vice_versa(
    store: MessageStore,
) -> None:
    # Cross-keying guard: a name owned as a CHANNEL never matches the outbound stage's
    # destination_name lane, and a name owned as a DESTINATION never matches ingress.
    ingress_id = await _seed_inflight_ingress(store, "SHARED_NAME")
    outbound_id = await _seed_inflight_outbound(store, "IB_OTHER", "SHARED_NAME")
    # Owned only as a channel → the ingress row recovers, the same-named outbound lane does not.
    owned = OwnedLanes(channels=frozenset({"SHARED_NAME"}), destinations=frozenset())
    assert await store.reset_stale_inflight(owned=owned) == 1
    assert await _row_status(store, ingress_id) == OutboxStatus.PENDING.value
    assert await _row_status(store, outbound_id) == OutboxStatus.INFLIGHT.value


async def test_chunking_over_500_owned_names(store: MessageStore) -> None:
    # 600 owned channel names (> _RESET_LANE_CHUNK=500), only one of which actually exists:
    # the chunked IN statements still find the seeded row, and the count is exact.
    rid = await _seed_inflight_ingress(store, "IB_REAL_LANE")
    other = await _seed_inflight_ingress(store, "IB_NOT_OWNED")
    names = {f"IB_GHOST_{i:04d}" for i in range(599)} | {"IB_REAL_LANE"}
    assert len(names) == 600
    owned = OwnedLanes(channels=frozenset(names), destinations=frozenset())
    assert await store.reset_stale_inflight(owned=owned) == 1
    assert await _row_status(store, rid) == OutboxStatus.PENDING.value
    assert await _row_status(store, other) == OutboxStatus.INFLIGHT.value


def test_owned_lane_scope_stage_keying() -> None:
    # outbound keys on destination_name/destinations; ingress/routed/response on channel_id/channels.
    owned = OwnedLanes(channels=frozenset({"c"}), destinations=frozenset({"d"}))
    assert owned_lane_scope(Stage.OUTBOUND.value, owned) == ("destination_name", owned.destinations)
    for st in (Stage.INGRESS, Stage.ROUTED, Stage.RESPONSE):
        assert owned_lane_scope(st.value, owned) == ("channel_id", owned.channels)
