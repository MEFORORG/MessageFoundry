# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Staged pipeline (ADR 0001): the ingress stage + ACK-on-receipt (Step A) and the routed-stage split
(Step B) — the two transactional handoffs (route_handoff/transform_handoff), the finalizer as the
single disposition authority, per-stage recovery, the multi-handler disposition flow, the outbox→queue
+ handler_name migrations, and the three-stage write amplification.

These exercise the store-level staged semantics directly; the full listener→router-worker→transform-
worker→delivery-worker path is covered end-to-end in test_wiring_engine.py / test_wiring_serve.py.
"""

from __future__ import annotations

import base64
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from messagefoundry.config.models import AckAfter
from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    Registry,
    WiringError,
    inbound,
)
from messagefoundry.store.crypto import PREFIX, make_cipher
from messagefoundry.store.store import MessageStatus, MessageStore, OutboxStatus, Stage

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "staged.db")
    yield s
    await s.close()


async def _claim_ingress(store: MessageStore, channel: str):
    return await store.claim_next_fifo(channel, stage=Stage.INGRESS.value)


# --- ingress stage + ACK-on-receipt boundary --------------------------------


async def test_enqueue_ingress_creates_message_and_ingress_row(store: MessageStore) -> None:
    mid = await store.enqueue_ingress(
        channel_id="IB", raw=RAW, control_id="MSG1", message_type="ADT^A01"
    )
    msg = await store.get_message(mid)
    assert msg["status"] == MessageStatus.RECEIVED.value  # the ACK-on-receipt disposition
    assert msg["raw"] == RAW and msg["control_id"] == "MSG1"
    # Exactly one ingress queue row, no outbound rows yet (routing hasn't happened).
    cur = await store._db.execute(
        "SELECT stage, status, destination_name FROM queue WHERE message_id=?", (mid,)
    )
    rows = await cur.fetchall()
    assert len(rows) == 1
    assert rows[0]["stage"] == Stage.INGRESS.value
    assert rows[0]["status"] == OutboxStatus.PENDING.value
    assert rows[0]["destination_name"] is None
    assert await store.outbox_for(mid) == []  # the per-destination view excludes the ingress row
    assert [e["event"] for e in await store.events_for(mid)] == ["received"]


# --- transactional handoff (claim → produce-next → complete) -----------------


async def test_handoff_produces_outbound_rows_and_completes_ingress(store: MessageStore) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    assert item is not None
    ok = await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "pa"), ("OB_B", "pb")],
        disposition=MessageStatus.ROUTED,
    )
    assert ok is True
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    # Ingress row consumed; two outbound rows now pending.
    assert await _claim_ingress(store, "IB") is None
    ob = {r["destination_name"]: r for r in await store.outbox_for(mid)}
    assert set(ob) == {"OB_A", "OB_B"}
    assert all(r["stage"] == Stage.OUTBOUND.value for r in ob.values())
    assert "routed" in [e["event"] for e in await store.events_for(mid)]


@pytest.mark.parametrize("disposition", [MessageStatus.FILTERED, MessageStatus.UNROUTED])
async def test_handoff_no_deliveries_sets_disposition_and_no_outbound(
    store: MessageStore, disposition: MessageStatus
) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    assert item is not None
    await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        disposition=disposition,
    )
    assert (await store.get_message(mid))["status"] == disposition.value
    assert await store.outbox_for(mid) == []


async def test_handoff_is_atomic_rolls_back_leaving_ingress_recoverable(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A crash mid-handoff (after producing outbound rows, before commit) must roll the WHOLE step
    # back — no partial handoff: the ingress row survives (recoverable) and zero outbound rows leak.
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    assert item is not None

    async def boom(*a: object, **k: object) -> None:
        raise RuntimeError("event insert failed")

    monkeypatch.setattr(store, "_event", boom)
    with pytest.raises(RuntimeError):
        await store.handoff(
            ingress_id=item.id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB_A", "pa")],
            disposition=MessageStatus.ROUTED,
        )
    # Rolled back: no outbound rows, and the ingress row is still present and recoverable.
    assert await store.outbox_for(mid) == []
    monkeypatch.undo()
    recovered = await store.reset_stale_inflight(stage=Stage.INGRESS.value)
    assert recovered == 1  # the inflight ingress row reverted to pending
    again = await _claim_ingress(store, "IB")
    assert again is not None and again.id == item.id


async def test_handoff_idempotent_against_worker_restart(store: MessageStore) -> None:
    # If a prior run completed the handoff then died before the worker observed it, re-running the
    # handoff for the same ingress row is a no-op — no duplicate outbound rows.
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    assert item is not None
    assert await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "pa")],
        disposition=MessageStatus.ROUTED,
    )
    # Second call: the ingress row is gone (not inflight) → no-op, no second outbound row.
    again = await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "dup")],
        disposition=MessageStatus.ROUTED,
    )
    assert again is False
    assert len(await store.outbox_for(mid)) == 1


# --- finalizer edge cases (count-and-log disposition flow) -------------------


async def test_routed_message_finalizes_processed_after_delivery(store: MessageStore) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "pa")],
        disposition=MessageStatus.ROUTED,
    )
    out = await store.claim_next_fifo("OB_A")
    await store.mark_done(out.id)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_filtered_message_not_flipped_to_processed(store: MessageStore) -> None:
    # A FILTERED/UNROUTED message has zero outbound rows; nothing must ever finalize it to PROCESSED.
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    await store.handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[],
        disposition=MessageStatus.FILTERED,
    )
    # Directly poke the finalizer (as a stray call would) — disposition must be preserved.
    await store._maybe_finalize_message(mid, now=1.0)
    await store._db.commit()
    assert (await store.get_message(mid))["status"] == MessageStatus.FILTERED.value


async def test_dead_ingress_row_finalizes_message_error(store: MessageStore) -> None:
    # An ingress row dead-lettered (a processing/poison failure) with no outbound rows → message ERROR.
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    await store.dead_letter_now(item.id, "router/handler error: boom")
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


# --- per-stage recovery ------------------------------------------------------


async def test_reset_stale_inflight_recovers_all_stages(store: MessageStore) -> None:
    # An inflight ingress row AND an inflight outbound row both revert to pending in one all-stages call.
    mid1 = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    await _claim_ingress(store, "IB")  # leaves an inflight ingress row
    mid2 = await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB_A", "p")])
    await store.claim_next_fifo("OB_A")  # leaves an inflight outbound row
    recovered = await store.reset_stale_inflight()  # stage=None → every stage
    assert recovered == 2
    assert await _claim_ingress(store, "IB") is not None  # ingress reclaimable
    assert await store.claim_next_fifo("OB_A") is not None  # outbound reclaimable
    assert {mid1, mid2}  # both messages still present


async def test_reset_stale_inflight_scoped_to_one_stage(store: MessageStore) -> None:
    await store.enqueue_ingress(channel_id="IB", raw=RAW)
    await _claim_ingress(store, "IB")
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB_A", "p")])
    await store.claim_next_fifo("OB_A")
    # Scope to outbound only: the inflight ingress row stays inflight.
    assert await store.reset_stale_inflight(stage=Stage.OUTBOUND.value) == 1
    assert await _claim_ingress(store, "IB") is None  # still inflight (not recovered)


# --- dead_letter_missing_destinations must ignore ingress rows ---------------


async def test_dead_letter_missing_destinations_ignores_ingress_rows(store: MessageStore) -> None:
    # Ingress rows carry a NULL destination_name by design; the orphan sweep must not mistake them
    # for removed-outbound orphans and dead-letter live, ACKed-but-unprocessed messages.
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    killed = await store.dead_letter_missing_destinations(
        set(), now=5.0
    )  # no valid outbounds at all
    assert killed == 0  # the ingress row is untouched
    assert (await store.get_message(mid))["status"] == MessageStatus.RECEIVED.value
    item = await _claim_ingress(store, "IB")
    assert item is not None  # still claimable — not dead-lettered


# --- per-stage pending depth (buildup detection) -----------------------------


async def test_pending_depth_is_stage_aware(store: MessageStore) -> None:
    await store.enqueue_ingress(channel_id="IB", raw=RAW)
    await store.enqueue_ingress(channel_id="IB", raw=RAW)
    await store.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB_A", "p")])
    in_depth, in_oldest = await store.pending_depth("IB", stage=Stage.INGRESS.value)
    out_depth, _ = await store.pending_depth("OB_A", stage=Stage.OUTBOUND.value)
    assert in_depth == 2 and in_oldest is not None  # ingress lane keyed by channel_id
    assert out_depth == 1  # outbound lane keyed by destination_name


# --- Step B: routed stage schema + lane key ----------------------------------


async def _insert_routed_row(
    store: MessageStore, message_id: str, channel: str, handler: str
) -> str:
    """Insert one routed-stage row directly (route_handoff arrives in the next layer)."""
    rid = f"routed-{handler}-{message_id[:6]}"
    await store._db.execute(
        "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
        " payload, status, attempts, next_attempt_at, created_at, updated_at)"
        " VALUES (?,?,?,?,NULL,?,?,?,0,?,?,?)",
        (
            rid,
            message_id,
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
    return rid


async def test_routed_stage_lane_keyed_by_channel(store: MessageStore) -> None:
    # A routed-stage row is claimed/counted by channel_id (per-inbound FIFO into transform), like
    # ingress — NOT by destination_name. It carries handler_name (the handler the transform runs).
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    await _insert_routed_row(store, mid, "IB", "h_adt")
    # Depth/oldest for the routed lane keys on channel_id; a handler-name key matches nothing.
    depth, oldest = await store.pending_depth("IB", stage=Stage.ROUTED.value)
    assert depth == 1 and oldest is not None
    assert (await store.pending_depth("h_adt", stage=Stage.ROUTED.value))[0] == 0
    # Claim by channel: the item surfaces handler_name + the (decrypted) raw payload.
    item = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
    assert item is not None
    assert item.stage == Stage.ROUTED.value and item.handler_name == "h_adt"
    assert item.destination_name is None and item.payload == RAW


async def test_handler_name_column_added_to_step_a_db(tmp_path: Path) -> None:
    # A Step-A DB's `queue` table predates handler_name; opening it under Step B must ALTER the column
    # in (NULL on the existing ingress/outbound rows) without disturbing them.
    path = tmp_path / "stepa.db"
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE messages (id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, received_at REAL NOT NULL,
          source_type TEXT, control_id TEXT, message_type TEXT, raw TEXT NOT NULL, status TEXT NOT NULL,
          error TEXT, summary TEXT, metadata TEXT);
        -- Step-A queue shape: has `stage`, but NO `handler_name` column.
        CREATE TABLE queue (id TEXT PRIMARY KEY, message_id TEXT NOT NULL REFERENCES messages(id),
          stage TEXT NOT NULL, channel_id TEXT NOT NULL, destination_name TEXT, payload TEXT NOT NULL,
          status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL,
          last_error TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL);
        CREATE TABLE message_events (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT NOT NULL,
          ts REAL NOT NULL, event TEXT NOT NULL, destination TEXT, detail TEXT);
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT,
          action TEXT NOT NULL, channel_id TEXT, detail TEXT, row_hash TEXT);
        CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, auth_provider TEXT NOT NULL,
          display_name TEXT, email TEXT, disabled INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL,
          updated_at REAL NOT NULL, last_login_at REAL, password_hash TEXT, password_changed_at REAL,
          must_change_password INTEGER NOT NULL DEFAULT 0, failed_attempts INTEGER NOT NULL DEFAULT 0,
          locked_until REAL);
        INSERT INTO messages VALUES ('m1','IB',1.0,'mllp','C','ADT^A01','RAW','routed',NULL,NULL,NULL);
        INSERT INTO queue VALUES ('o1','m1','outbound','IB','OB_A','p','pending',0,0.0,NULL,1.0,1.0);
        """
    )
    con.commit()
    con.close()
    store = await MessageStore.open(path)
    try:
        cols = {
            r["name"]
            for r in await (await store._db.execute("PRAGMA table_info(queue)")).fetchall()
        }
        assert "handler_name" in cols  # ALTER-ed in on open
        # The pre-existing outbound row is intact and carries a NULL handler_name.
        item = await store.claim_next_fifo("OB_A")
        assert item is not None and item.handler_name is None and item.payload == "p"
    finally:
        await store.close()


# --- Step B: route_handoff + transform_handoff (split router/transform) -------


async def _route(
    store: MessageStore, channel: str, handlers: list[str], disposition: MessageStatus
) -> str:
    """enqueue_ingress → claim the ingress row → route_handoff (one routed row per handler)."""
    mid = await store.enqueue_ingress(channel_id=channel, raw=RAW)
    item = await _claim_ingress(store, channel)
    assert item is not None
    await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id=channel,
        handlers=[(h, RAW) for h in handlers],
        disposition=disposition,
    )
    return mid


async def _claim_routed(store: MessageStore, channel: str):
    return await store.claim_next_fifo(channel, stage=Stage.ROUTED.value)


async def _transform(store: MessageStore, channel: str, deliveries: list[tuple[str, str]]) -> str:
    """claim the next routed row for ``channel`` → transform_handoff with ``deliveries``."""
    item = await _claim_routed(store, channel)
    assert item is not None
    await store.transform_handoff(
        routed_id=item.id,
        message_id=item.message_id,
        channel_id=channel,
        deliveries=deliveries,
    )
    return item.message_id


async def test_route_handoff_produces_routed_rows_and_completes_ingress(
    store: MessageStore,
) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    assert item is not None
    ok = await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("h1", RAW), ("h2", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    assert ok is True
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    assert await _claim_ingress(store, "IB") is None  # ingress consumed
    # One routed row per handler, in handler-list order (rowid), each carrying handler_name; no outbound.
    cur = await store._db.execute(
        "SELECT stage, handler_name, destination_name FROM queue WHERE message_id=? ORDER BY rowid",
        (mid,),
    )
    rows = await cur.fetchall()
    assert [(r["stage"], r["handler_name"]) for r in rows] == [
        (Stage.ROUTED.value, "h1"),
        (Stage.ROUTED.value, "h2"),
    ]
    assert all(r["destination_name"] is None for r in rows)
    assert await store.outbox_for(mid) == []
    assert [e["event"] for e in await store.events_for(mid)] == ["received", "routed"]


async def test_routed_fifo_preserves_multimessage_order(store: MessageStore) -> None:
    # The serial transform worker relies on a load-bearing invariant: two messages M1 then M2 on the
    # same inbound, each routed to [h1, h2], drain through the routed stage in strict arrival order —
    # M1.h1, M1.h2, M2.h1, M2.h2. `created_at` advances per route_handoff (across messages) and `rowid`
    # breaks the tie within a handoff (= handler-list insertion order). Explicit now= keeps it
    # independent of wall-clock resolution.
    m1 = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    i1 = await _claim_ingress(store, "IB")
    assert i1 is not None
    await store.route_handoff(
        ingress_id=i1.id,
        message_id=m1,
        channel_id="IB",
        handlers=[("h1", RAW), ("h2", RAW)],
        disposition=MessageStatus.ROUTED,
        now=1.0,
    )
    m2 = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=2.0)
    i2 = await _claim_ingress(store, "IB")
    assert i2 is not None
    await store.route_handoff(
        ingress_id=i2.id,
        message_id=m2,
        channel_id="IB",
        handlers=[("h1", RAW), ("h2", RAW)],
        disposition=MessageStatus.ROUTED,
        now=2.0,
    )
    # Drain all four routed rows FIFO; the (message, handler) sequence must be strict arrival order.
    seq = []
    for _ in range(4):
        item = await _claim_routed(store, "IB")
        assert item is not None
        seq.append((item.message_id, item.handler_name))
    assert seq == [(m1, "h1"), (m1, "h2"), (m2, "h1"), (m2, "h2")]
    assert await _claim_routed(store, "IB") is None


async def test_outbound_fifo_clamps_created_at_on_backward_clock(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    # A backward wall-clock step must not let a later delivery sort ahead of an earlier one:
    # _fifo_created_at clamps the new row's created_at up to the lane's max, so FIFO claim order
    # follows ARRIVAL order, not the regressed clock.
    m1 = await store.enqueue_message(
        channel_id="IB", raw=RAW, deliveries=[("OB", "first")], now=100.0
    )
    with caplog.at_level("WARNING"):
        m2 = await store.enqueue_message(
            channel_id="IB", raw=RAW, deliveries=[("OB", "second")], now=50.0
        )  # clock stepped BACK
    assert any("clock regression" in r.message for r in caplog.records)  # warned on the clamp
    # The second delivery's ordering timestamp was clamped up to the lane max (>= 100), not left at 50.
    assert (await store.outbox_for(m2))[0]["created_at"] >= 100.0
    # FIFO still claims the earlier-arrived delivery first.
    head1 = await store.claim_next_fifo("OB")
    assert head1 is not None and head1.payload == "first"
    await store.mark_done(head1.id)
    head2 = await store.claim_next_fifo("OB")
    assert head2 is not None and head2.payload == "second"
    assert {m1, m2}  # two distinct messages


async def test_ingress_fifo_clamps_created_at_on_backward_clock(store: MessageStore) -> None:
    # Same protection on the per-inbound ingress lane (channel_id-keyed): a backward clock step on the
    # second arrival must not let it be routed before the first.
    m1 = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    m2 = await store.enqueue_ingress(channel_id="IB", raw=RAW, now=50.0)  # clock stepped back
    first = await _claim_ingress(store, "IB")
    assert first is not None and first.message_id == m1  # arrival order, not clock order
    second = await _claim_ingress(store, "IB")
    assert second is not None and second.message_id == m2


async def test_route_handoff_no_handlers_sets_unrouted(store: MessageStore) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    assert item is not None
    await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        handlers=[],
        disposition=MessageStatus.UNROUTED,
    )
    assert (await store.get_message(mid))["status"] == MessageStatus.UNROUTED.value
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM queue WHERE message_id=?", (mid,))
    assert (await cur.fetchone())["n"] == 0  # ingress consumed, no routed rows


async def test_route_handoff_idempotent_against_restart(store: MessageStore) -> None:
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
    again = await store.route_handoff(  # ingress row gone → no-op, no duplicate routed row
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
    assert (await cur.fetchone())["n"] == 1


async def test_route_handoff_atomic_rolls_back_leaving_ingress_recoverable(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    assert item is not None

    async def boom(*a: object, **k: object) -> None:
        raise RuntimeError("event insert failed")

    monkeypatch.setattr(store, "_event", boom)
    with pytest.raises(RuntimeError):
        await store.route_handoff(
            ingress_id=item.id,
            message_id=mid,
            channel_id="IB",
            handlers=[("h", RAW)],
            disposition=MessageStatus.ROUTED,
        )
    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM queue WHERE message_id=? AND stage=?",
        (mid, Stage.ROUTED.value),
    )
    assert (await cur.fetchone())["n"] == 0  # no routed rows leaked
    monkeypatch.undo()
    assert await store.reset_stale_inflight(stage=Stage.INGRESS.value) == 1
    again = await _claim_ingress(store, "IB")
    assert again is not None and again.id == item.id


async def test_transform_handoff_produces_outbound_and_consumes_routed(store: MessageStore) -> None:
    mid = await _route(store, "IB", ["h"], MessageStatus.ROUTED)
    item = await _claim_routed(store, "IB")
    assert item is not None and item.handler_name == "h" and item.payload == RAW
    ok = await store.transform_handoff(
        routed_id=item.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "pa"), ("OB_B", "pb")],
    )
    assert ok is True
    assert await _claim_routed(store, "IB") is None  # routed consumed
    assert {r["destination_name"] for r in await store.outbox_for(mid)} == {"OB_A", "OB_B"}
    assert (await store.get_message(mid))[
        "status"
    ] == MessageStatus.ROUTED.value  # outbound pending
    assert [e["event"] for e in await store.events_for(mid)] == [
        "received",
        "routed",
        "transformed",
    ]


async def test_transform_handoff_idempotent_against_restart(store: MessageStore) -> None:
    mid = await _route(store, "IB", ["h"], MessageStatus.ROUTED)
    item = await _claim_routed(store, "IB")
    assert item is not None
    assert await store.transform_handoff(
        routed_id=item.id, message_id=mid, channel_id="IB", deliveries=[("OB_A", "pa")]
    )
    again = await store.transform_handoff(  # routed row gone → no-op
        routed_id=item.id, message_id=mid, channel_id="IB", deliveries=[("OB_A", "dup")]
    )
    assert again is False
    assert len(await store.outbox_for(mid)) == 1


# --- disposition matrix (finalizer is the single authority) ------------------


async def test_single_handler_filters_collapses_to_filtered(store: MessageStore) -> None:
    # One handler, zero deliveries → the last routed row is consumed and nothing delivered → FILTERED.
    mid = await _route(store, "IB", ["h"], MessageStatus.ROUTED)
    await _transform(store, "IB", [])  # handler filtered everything
    assert (await store.get_message(mid))["status"] == MessageStatus.FILTERED.value
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM queue WHERE message_id=?", (mid,))
    assert (await cur.fetchone())["n"] == 0  # no rows linger


async def test_two_handlers_both_filter_collapses_to_filtered(store: MessageStore) -> None:
    mid = await _route(store, "IB", ["h1", "h2"], MessageStatus.ROUTED)
    await _transform(store, "IB", [])  # h1 filters
    assert (await store.get_message(mid))[
        "status"
    ] == MessageStatus.ROUTED.value  # h2 still pending
    await _transform(store, "IB", [])  # h2 filters → now FILTERED
    assert (await store.get_message(mid))["status"] == MessageStatus.FILTERED.value


async def test_two_handlers_one_delivers_one_filters_processed_after_delivery(
    store: MessageStore,
) -> None:
    mid = await _route(store, "IB", ["h1", "h2"], MessageStatus.ROUTED)
    await _transform(store, "IB", [("OB_A", "p")])  # h1 delivers
    assert (await store.get_message(mid))[
        "status"
    ] == MessageStatus.ROUTED.value  # h2 still pending
    await _transform(store, "IB", [])  # h2 filters
    assert (await store.get_message(mid))[
        "status"
    ] == MessageStatus.ROUTED.value  # OB_A still pending
    out = await store.claim_next_fifo("OB_A")
    assert out is not None
    await store.mark_done(out.id)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_finalizer_not_premature_with_pending_routed_sibling(store: MessageStore) -> None:
    # The core premature-finalize guard: H1 delivers AND its outbound is delivered, but H2's routed
    # row is still pending → the message must NOT finalize PROCESSED until H2 is done too.
    mid = await _route(store, "IB", ["h1", "h2"], MessageStatus.ROUTED)
    await _transform(store, "IB", [("OB_A", "p")])  # h1 → OB_A
    out = await store.claim_next_fifo("OB_A")
    assert out is not None
    await store.mark_done(out.id)  # OB_A delivered, but H2 routed row still pending
    assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value  # NOT processed
    await _transform(store, "IB", [("OB_B", "p")])  # h2 → OB_B
    out2 = await store.claim_next_fifo("OB_B")
    assert out2 is not None
    await store.mark_done(out2.id)
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value


async def test_dead_routed_with_delivered_sibling_is_error(store: MessageStore) -> None:
    # H1 delivers (outbound DONE); H2's transform fails (routed row dead-lettered) → message ERROR
    # (a failure anywhere is real, even though H1 delivered).
    mid = await _route(store, "IB", ["h1", "h2"], MessageStatus.ROUTED)
    await _transform(store, "IB", [("OB_A", "p")])  # h1 delivers
    out = await store.claim_next_fifo("OB_A")
    assert out is not None
    await store.mark_done(out.id)
    h2 = await _claim_routed(store, "IB")
    assert h2 is not None
    await store.dead_letter_now(h2.id, "transform error")  # h2 fails
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


async def test_single_dead_routed_row_is_error(store: MessageStore) -> None:
    mid = await _route(store, "IB", ["h"], MessageStatus.ROUTED)
    item = await _claim_routed(store, "IB")
    assert item is not None
    await store.dead_letter_now(item.id, "transform error")
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


# --- per-stage recovery + missing-handler sweep + replay ---------------------


async def test_reset_stale_inflight_recovers_routed_stage(store: MessageStore) -> None:
    mid = await _route(store, "IB", ["h"], MessageStatus.ROUTED)
    claimed = await _claim_routed(
        store, "IB"
    )  # leaves an inflight routed row (crash before transform)
    assert claimed is not None
    assert await store.reset_stale_inflight(stage=Stage.ROUTED.value) == 1
    again = await _claim_routed(store, "IB")
    assert again is not None and again.id == claimed.id and again.handler_name == "h"
    # ...and it transforms cleanly to outbound after recovery.
    await store.transform_handoff(
        routed_id=again.id, message_id=mid, channel_id="IB", deliveries=[("OB_A", "p")]
    )
    assert {r["destination_name"] for r in await store.outbox_for(mid)} == {"OB_A"}


async def test_dead_letter_missing_handlers_kills_orphan_routed_rows(store: MessageStore) -> None:
    mid = await _route(store, "IB", ["gone"], MessageStatus.ROUTED)  # handler no longer registered
    killed = await store.dead_letter_missing_handlers({"present"})
    assert killed == 1
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value
    # A routed row for a still-present handler is untouched; ingress/outbound rows ignored entirely.
    await _route(store, "IB", ["present"], MessageStatus.ROUTED)
    await store.enqueue_ingress(channel_id="IB", raw=RAW)  # an ingress row (NULL handler_name)
    assert await store.dead_letter_missing_handlers({"present"}) == 0


async def test_replay_dead_routed_row_does_not_repend_delivered_sibling(
    store: MessageStore,
) -> None:
    # M2: a message with a delivered outbound (H1) AND a dead routed row (H2). replay must re-pend
    # ONLY the dead routed row — never the already-DONE outbound row (which would re-deliver).
    mid = await _route(store, "IB", ["h1", "h2"], MessageStatus.ROUTED)
    await _transform(store, "IB", [("OB_A", "p")])  # h1 → OB_A
    out = await store.claim_next_fifo("OB_A")
    assert out is not None
    await store.mark_done(out.id)  # OB_A delivered
    h2 = await _claim_routed(store, "IB")
    assert h2 is not None
    await store.dead_letter_now(h2.id, "transform error")  # h2 routed dead → message ERROR
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value

    assert await store.replay(mid) == 1  # only the dead routed row re-pended
    # The delivered outbound row stays DONE (not re-pended → not re-delivered).
    ob = {r["destination_name"]: r["status"] for r in await store.outbox_for(mid)}
    assert ob == {"OB_A": OutboxStatus.DONE.value}
    # Back in the route/transform path (a routed row pending again).
    assert (await store.get_message(mid))["status"] == MessageStatus.RECEIVED.value
    assert await _claim_routed(store, "IB") is not None


# --- outbox→queue migration --------------------------------------------------


async def test_legacy_outbox_migrates_to_queue_with_encryption(tmp_path: Path) -> None:
    # A pre-staged-pipeline DB (legacy `outbox` table, NOT NULL destination_name, possibly-plaintext
    # payload) must fold into the generic `queue` table as stage='outbound' on open — and the
    # encryption back-fill (now keyed on `queue`) must still encrypt the migrated payload at rest.
    path = tmp_path / "legacy.db"
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE messages (id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, received_at REAL NOT NULL,
          source_type TEXT, control_id TEXT, message_type TEXT, raw TEXT NOT NULL, status TEXT NOT NULL,
          error TEXT, summary TEXT, metadata TEXT);
        CREATE TABLE outbox (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, channel_id TEXT NOT NULL,
          destination_name TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL, last_error TEXT,
          created_at REAL NOT NULL, updated_at REAL NOT NULL);
        CREATE TABLE message_events (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT NOT NULL,
          ts REAL NOT NULL, event TEXT NOT NULL, destination TEXT, detail TEXT);
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT,
          action TEXT NOT NULL, channel_id TEXT, detail TEXT, row_hash TEXT);
        CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, auth_provider TEXT NOT NULL,
          display_name TEXT, email TEXT, disabled INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL,
          updated_at REAL NOT NULL, last_login_at REAL, password_hash TEXT, password_changed_at REAL,
          must_change_password INTEGER NOT NULL DEFAULT 0, failed_attempts INTEGER NOT NULL DEFAULT 0,
          locked_until REAL);
        INSERT INTO messages VALUES ('m1','IB',1.0,'mllp','C','ADT^A01','RAW','routed',NULL,NULL,NULL);
        INSERT INTO outbox VALUES ('o1','m1','IB','OB_A','PLAINPAYLOAD','pending',0,0.0,NULL,1.0,1.0);
        """
    )
    con.commit()
    con.close()

    key = base64.b64encode(b"\x00" * 32).decode()
    store = await MessageStore.open(path, cipher=make_cipher(key))
    try:
        tables = {
            r[0]
            for r in await (
                await store._db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            ).fetchall()
        }
        assert "outbox" not in tables and "queue" in tables
        ob = await store.outbox_for("m1")
        assert len(ob) == 1 and ob[0]["stage"] == Stage.OUTBOUND.value
        # The migrated payload was plaintext; the back-fill encrypted it on `queue` (decrypts back).
        item = await store.claim_next_fifo("OB_A")
        assert item is not None and item.payload == "PLAINPAYLOAD"
        on_disk = sqlite3.connect(path).execute("SELECT payload FROM queue").fetchone()[0]
        assert str(on_disk).startswith(PREFIX)  # encrypted at rest after migration
    finally:
        await store.close()


# --- write amplification (the ADR's Step-A decision gate) --------------------


async def test_write_amplification_persistent_row_footprint(store: MessageStore) -> None:
    """Pin the staged-pipeline write amplification as a regression guard (docs/benchmarks/
    step-b-write-amplification.md). Driving the full three-stage flow (enqueue_ingress → route_handoff
    → transform_handoff), each of the transient ingress and routed rows is consumed at its handoff, so
    the *persistent* queue footprint is exactly N outbound rows (the raw is never kept twice at rest),
    and the message_events trail is 'received' → 'routed' → 'transformed' (one transformed per
    handler)."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    await store.route_handoff(
        ingress_id=item.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await _claim_routed(store, "IB")
    assert routed is not None
    await store.transform_handoff(
        routed_id=routed.id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB_A", "pa"), ("OB_B", "pb")],
    )
    # Persistent footprint: exactly N outbound rows, NO leftover ingress/routed row (no permanent dup).
    cur = await store._db.execute(
        "SELECT stage, COUNT(*) AS n FROM queue WHERE message_id=? GROUP BY stage", (mid,)
    )
    by_stage = {r["stage"]: r["n"] for r in await cur.fetchall()}
    assert by_stage == {
        Stage.OUTBOUND.value: 2
    }  # ingress + routed consumed, only outbound persists
    events = [e["event"] for e in await store.events_for(mid)]
    assert events == ["received", "routed", "transformed"]  # disposition logged as it flows


# --- ack_after wiring (Step A: INGEST only; DELIVERED rejected) --------------


def test_ack_after_defaults_to_ingest() -> None:
    assert AckAfter.INGEST.value == "ingest"
    # The InboundConnection default is None (inherit the global [inbound].ack_after, itself INGEST).
    reg = Registry()
    with _active(reg):
        inbound("IB", ConnectionSpec(ConnectorType.MLLP, {"port": 2575}), router="r")
    assert reg.inbound["IB"].ack_after is None


def test_ack_after_delivered_rejected_at_wiring() -> None:
    reg = Registry()
    with _active(reg):
        with pytest.raises(WiringError, match="ack_after='delivered' is not yet implemented"):
            inbound(
                "IB",
                ConnectionSpec(ConnectorType.MLLP, {"port": 2575}),
                router="r",
                ack_after=AckAfter.DELIVERED,
            )


async def test_ack_after_delivered_global_default_rejected_at_start(tmp_path: Path) -> None:
    # A connection inheriting a global [inbound].ack_after='delivered' (its own ack_after=None) is
    # NOT caught at wiring (ack_after is None there) — only the runtime resolve+guard catches it.
    # This is the sole defense for that path, so it gets a test. Per ADR 0031 the guard still fires
    # loud, but start() now ISOLATES the offending inbound (degraded + alerted) instead of crashing
    # the whole engine; a direct start_inbound() call still raises so the operator sees the error.
    from messagefoundry.config.wiring import InboundConnection
    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    s = await MessageStore.open(tmp_path / "x.db")
    try:
        reg = Registry()
        reg.add_inbound(
            InboundConnection(
                "IB", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path)}), router="r"
            )
        )
        reg.add_router("r", lambda m: [])
        runner = RegistryRunner(reg, s, ack_after_default=AckAfter.DELIVERED)
        await runner.start()  # does NOT crash — the offending inbound is isolated
        try:
            assert runner.running
            assert not runner.inbound_running("IB")
            reason = runner.connection_failed("IB")
            assert reason and "not yet implemented" in reason
            # the guard is still the sole defense and still fires loud for a direct caller:
            with pytest.raises(WiringError, match="not yet implemented"):
                await runner.start_inbound("IB")
        finally:
            await runner.stop()
    finally:
        await s.close()


async def test_replay_of_ingress_dead_message_requeues_at_ingress(store: MessageStore) -> None:
    # The documented recovery for an ingress (processing) failure: per-message store.replay re-queues
    # the dead ingress row and returns the message to RECEIVED (back at ingress, awaiting routing) —
    # NOT ROUTED, since no outbound rows exist.
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    await store.dead_letter_now(item.id, "router/handler error")
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value
    assert await store.replay(mid) == 1
    assert (await store.get_message(mid))["status"] == MessageStatus.RECEIVED.value
    assert await _claim_ingress(store, "IB") is not None  # ingress row re-queued, reclaimable


async def test_replay_dead_ignores_ingress_rows(store: MessageStore) -> None:
    # Bulk DLQ replay (replay_dead) is outbound-scoped to match the DLQ view; a dead INGRESS row is
    # invisible to list_dead and must NOT be touched by replay_dead.
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    item = await _claim_ingress(store, "IB")
    await store.dead_letter_now(item.id, "router/handler error")
    assert await store.count_dead() == 0  # the dead ingress row is not in the DLQ view
    assert await store.replay_dead() == 0  # ...and bulk replay leaves it alone
    assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value


async def test_engine_refuses_backend_without_ingest_stage(tmp_path: Path) -> None:
    # Fail loud at start (not per-message): a store backend that doesn't implement the staged ingress
    # path (SQL Server, gated on BACKLOG #1) must be rejected, not trap the first message.
    from messagefoundry.pipeline.engine import Engine

    s = await MessageStore.open(tmp_path / "x.db")
    s.supports_ingest_stage = False  # simulate a non-staged backend
    try:
        engine = Engine(s)
        engine.add_registry(Registry())
        with pytest.raises(RuntimeError, match="staged ingress pipeline"):
            await engine.start()
    finally:
        await s.close()


async def test_migration_skips_orphan_outbox_rows(tmp_path: Path) -> None:
    # A legacy outbox row whose message_id has no messages row (insertable only with foreign_keys off)
    # is SKIPPED on migration — it must not abort open() with an opaque FK error.
    path = tmp_path / "legacy.db"
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE messages (id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, received_at REAL NOT NULL,
          source_type TEXT, control_id TEXT, message_type TEXT, raw TEXT NOT NULL, status TEXT NOT NULL,
          error TEXT, summary TEXT, metadata TEXT);
        CREATE TABLE outbox (id TEXT PRIMARY KEY, message_id TEXT NOT NULL REFERENCES messages(id),
          channel_id TEXT NOT NULL, destination_name TEXT NOT NULL, payload TEXT NOT NULL,
          status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL,
          last_error TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL);
        CREATE TABLE message_events (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT NOT NULL,
          ts REAL NOT NULL, event TEXT NOT NULL, destination TEXT, detail TEXT);
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT,
          action TEXT NOT NULL, channel_id TEXT, detail TEXT, row_hash TEXT);
        CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, auth_provider TEXT NOT NULL,
          display_name TEXT, email TEXT, disabled INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL,
          updated_at REAL NOT NULL, last_login_at REAL, password_hash TEXT, password_changed_at REAL,
          must_change_password INTEGER NOT NULL DEFAULT 0, failed_attempts INTEGER NOT NULL DEFAULT 0,
          locked_until REAL);
        INSERT INTO messages VALUES ('m1','IB',1.0,'mllp','C','ADT^A01','RAW','routed',NULL,NULL,NULL);
        INSERT INTO outbox VALUES ('o1','m1','IB','OB_A','p','pending',0,0.0,NULL,1.0,1.0);
        INSERT INTO outbox VALUES ('o2','GHOST','IB','OB_A','p','pending',0,0.0,NULL,1.0,1.0);
        """
    )
    con.commit()
    con.close()
    store = await MessageStore.open(path)  # must NOT raise FOREIGN KEY constraint failed
    try:
        cur = await store._db.execute("SELECT id FROM queue")
        ids = {r["id"] for r in await cur.fetchall()}
        assert ids == {"o1"}  # the valid row migrated; the orphan was skipped, not fatal
    finally:
        await store.close()


@contextmanager
def _active(reg: Registry) -> Iterator[None]:
    """Make ``reg`` the active declaration target for ``inbound()``/``outbound()`` calls (what
    ``load_config`` does via its internal ``_loading`` context), then restore the previous target."""
    from messagefoundry.config import wiring

    prev = wiring._active
    wiring._active = reg
    try:
        yield
    finally:
        wiring._active = prev
