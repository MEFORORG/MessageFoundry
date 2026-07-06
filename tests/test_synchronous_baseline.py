# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""B7 — SQLite ``synchronous`` durability-mode baseline + observability.

Two things are asserted here:

1. **Observability** — :meth:`MessageStore.db_status` surfaces the configured ``synchronous`` mode
   read-only (``"normal"`` / ``"full"``), the field a status reader / load run records to know which
   durability mode it measured. The server backends report ``None`` (it is a SQLite-only knob).

2. **Parity** — NORMAL vs FULL is a *durability/timing* relaxation, **never a behaviour change**. The
   same message workload driven through the full staged pipeline (ingress → route → transform →
   delivery → finalizer) under each mode produces a **byte-identical** outcome: same ``claim_next_fifo``
   FIFO order, same outbound rows, same terminal finalizer disposition. If these ever diverge, NORMAL
   would not be a safe shipped default — so this is the gate that pins the "no behaviour difference".

The pipeline is driven at the store level exactly as ``test_staged_pipeline.py`` does (the
listener→router-worker→transform-worker→delivery-worker path is covered end-to-end elsewhere).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.store.store import MessageStatus, MessageStore, Stage

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"


# --- observability: db_status().synchronous reflects the configured mode -----


@pytest.mark.parametrize(
    "configured,expected",
    [("NORMAL", "normal"), ("normal", "normal"), ("FULL", "full"), ("full", "full")],
)
async def test_db_status_reports_configured_synchronous(
    tmp_path: Path, configured: str, expected: str
) -> None:
    store = await MessageStore.open(tmp_path / "sync.db", synchronous=configured)
    try:
        status = await store.db_status()
        # Reported in the lowercase settings vocabulary, independent of the input casing.
        assert status.synchronous == expected
        # And it matches what the connection actually applied (PRAGMA synchronous: 1=NORMAL, 2=FULL).
        cur = await store._db.execute("PRAGMA synchronous")
        applied = (await cur.fetchone())[0]
        assert applied == (1 if expected == "normal" else 2)
    finally:
        await store.close()


# --- parity: NORMAL vs FULL is byte-identical message handling ---------------


async def _drive_pipeline(store: MessageStore) -> dict[str, object]:
    """Run a deterministic mixed workload through the full staged pipeline and capture the observable
    outcome (FIFO claim order, outbound rows, terminal dispositions, events). ``now=`` is pinned so the
    capture is independent of wall-clock resolution and the result is comparable across two stores."""
    # Three messages on one inbound, each routed to two handlers, exercising every terminal
    # disposition: M1 both handlers deliver (→ PROCESSED), M2 both handlers filter (→ FILTERED),
    # M3 routes to no handler (→ UNROUTED). Deterministic now= so created_at ordering is reproducible.
    m1 = await store.enqueue_ingress(channel_id="IB", raw=RAW, control_id="M1", now=1.0)
    i1 = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert i1 is not None
    await store.route_handoff(
        ingress_id=i1.id,
        message_id=m1,
        channel_id="IB",
        handlers=[("h1", RAW), ("h2", RAW)],
        disposition=MessageStatus.ROUTED,
        now=1.0,
    )

    m2 = await store.enqueue_ingress(channel_id="IB", raw=RAW, control_id="M2", now=2.0)
    i2 = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert i2 is not None
    await store.route_handoff(
        ingress_id=i2.id,
        message_id=m2,
        channel_id="IB",
        handlers=[("h1", RAW), ("h2", RAW)],
        disposition=MessageStatus.ROUTED,
        now=2.0,
    )

    m3 = await store.enqueue_ingress(channel_id="IB", raw=RAW, control_id="M3", now=3.0)
    i3 = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert i3 is not None
    await store.route_handoff(
        ingress_id=i3.id,
        message_id=m3,
        channel_id="IB",
        handlers=[],  # no handler matched → UNROUTED
        disposition=MessageStatus.UNROUTED,
        now=3.0,
    )

    # Drain the routed stage in strict FIFO order, recording the (message, handler) sequence. M1's
    # handlers deliver to a destination; M2's handlers filter (zero deliveries). The sequence is the
    # load-bearing per-lane FIFO invariant.
    routed_order: list[tuple[str, str | None]] = []
    deliver = {m1: True, m2: False}
    while True:
        item = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
        if item is None:
            break
        routed_order.append((item.message_id, item.handler_name))
        deliveries = [(f"OB_{item.handler_name}", item.payload)] if deliver[item.message_id] else []
        await store.transform_handoff(
            routed_id=item.id,
            message_id=item.message_id,
            channel_id="IB",
            deliveries=deliveries,
            now=10.0,
        )

    # Deliver every outbound row FIFO per destination and mark it done, driving the finalizer to the
    # terminal disposition. Record the outbound claim order (destination + control id) per lane.
    outbound_order: list[tuple[str, str]] = []
    for dest in ("OB_h1", "OB_h2"):
        while True:
            out = await store.claim_next_fifo(dest)
            if out is None:
                break
            outbound_order.append((dest, out.payload))
            await store.mark_done(out.id, now=20.0)

    # Capture the terminal state per message: disposition, the per-destination outbox view (sorted for
    # a stable comparison), and the event trail.
    def _outbox_view(rows: list[dict[str, object]]) -> list[tuple[object, object, object]]:
        return sorted((r["destination_name"], r["stage"], r["status"]) for r in rows)

    async def _control_id(mid: str) -> str:
        msg = await store.get_message(mid)
        assert msg is not None
        return str(msg["control_id"])

    messages: dict[str, dict[str, object]] = {}
    for mid in (m1, m2, m3):
        msg = await store.get_message(mid)
        assert msg is not None
        messages[str(msg["control_id"])] = {
            "status": msg["status"],
            "outbox": _outbox_view(await store.outbox_for(mid)),
            "events": [e["event"] for e in await store.events_for(mid)],
        }

    # Re-key the FIFO orders by control_id so two stores (with different message-id UUIDs) compare.
    routed_by_cid: list[tuple[str, str | None]] = [
        (await _control_id(mid), h) for mid, h in routed_order
    ]
    return {
        "routed_order": routed_by_cid,
        "outbound_order": outbound_order,
        "messages": messages,
    }


async def test_synchronous_normal_vs_full_byte_identical(tmp_path: Path) -> None:
    """NORMAL and FULL must produce byte-identical message handling — same FIFO order, same outbound
    rows, same terminal dispositions. The only difference between the two is durability/fsync timing."""
    normal_store = await MessageStore.open(tmp_path / "normal.db", synchronous="NORMAL")
    full_store = await MessageStore.open(tmp_path / "full.db", synchronous="FULL")
    try:
        # Sanity: the two stores really are in different durability modes (else the parity is vacuous).
        assert (await normal_store.db_status()).synchronous == "normal"
        assert (await full_store.db_status()).synchronous == "full"

        normal_outcome = await _drive_pipeline(normal_store)
        full_outcome = await _drive_pipeline(full_store)
    finally:
        await normal_store.close()
        await full_store.close()

    # FIFO claim order — identical across modes.
    assert normal_outcome["routed_order"] == full_outcome["routed_order"]
    assert normal_outcome["outbound_order"] == full_outcome["outbound_order"]
    # Terminal dispositions + outbound rows + event trail — identical across modes.
    assert normal_outcome["messages"] == full_outcome["messages"]

    # And the expected dispositions actually landed (so the parity isn't comparing two broken runs).
    statuses = {cid: m["status"] for cid, m in normal_outcome["messages"].items()}
    assert statuses == {
        "M1": MessageStatus.PROCESSED.value,
        "M2": MessageStatus.FILTERED.value,
        "M3": MessageStatus.UNROUTED.value,
    }
