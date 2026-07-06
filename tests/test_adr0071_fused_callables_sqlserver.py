# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0071 B5 PR2 — live SQL Server tests for the fused CPU-stage + store-handoff callables.

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env), like
``test_sqlserver_sync_handoff.py``. Drives ``RegistryRunner._fused_route_and_handoff`` /
``_fused_transform_and_handoff`` DIRECTLY (they are DEAD CODE in PR2 — not yet wired into
``_process_*_item``; PR3 owns the dispatch) against a real SQL Server, proving:

* activation on live SS opens the per-stage synchronous handoff pools + fusing executors, and teardown
  closes them (``_fusion_active`` flips True→False, ``sync_handoff_pool`` KeyErrors after stop);
* a fused route/transform hop persists the **byte-identical** queue rows the async
  ``route_handoff`` / ``transform_handoff`` produce, and returns the right result record (names /
  deliveries / applied-state / wake targets / no exceptions);
* the sync twin never mutates the loop-owned state cache — ``applied_state`` is returned for the loop
  to ``publish_state_cache``.

Requires the ``sqlserver`` extra (aioodbc + pyodbc + ODBC Driver 18)."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, AsyncIterator

import pytest

from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
    SetState,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, Stage

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


@pytest.fixture
async def store() -> AsyncIterator[Any]:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    async with s._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in (
            "message_events",
            "state",
            "queue",
            "response",
            "delivered_keys",
            "outbox",
            "messages",
        ):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    yield s
    await s.close()


def _reg() -> Registry:
    """IB (HL7V2) → router r → handler h (Send OB1 + SetState) → outbound OB1. The fused callables read
    the router/handler/outbound from this registry; no connectors are ever built (nothing binds)."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-in", "pattern": "*.hl7"}),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB1", ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-out"})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [Send("OB1", "OUTBODY"), SetState("stFused", "k", {"v": 7})])
    return reg


async def _runner_with_fusion(store: Any) -> RegistryRunner:
    runner = RegistryRunner(
        _reg(), store, fuse_thread_hops=True, claim_mode="pooled", pooled_fusing_workers=1
    )
    runner._loop = asyncio.get_running_loop()
    runner._fusion_active = await runner._activate_fusion()
    assert runner._fusion_active is True, "fusion must activate on live SQL Server"
    return runner


async def _ingress_and_claim(store: Any, channel: str, raw: str, now: float) -> tuple[str, Any]:
    mid = await store.enqueue_ingress(channel_id=channel, raw=raw, now=now)
    ing = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value, now=now)
    assert ing is not None and ing.stage == Stage.INGRESS.value
    return mid, ing


async def _route_and_claim(store: Any, channel: str, raw: str, now: float) -> tuple[str, Any]:
    mid, ing = await _ingress_and_claim(store, channel, raw, now)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id=channel,
        handlers=[("h", raw)],
        disposition=MessageStatus.ROUTED,
        now=now,
    )
    rtd = await store.claim_next_fifo(channel, stage=Stage.ROUTED.value, now=now)
    assert rtd is not None and rtd.stage == Stage.ROUTED.value
    return mid, rtd


async def _queue_rows(store: Any, mid: str) -> list[dict[str, Any]]:
    rows = await store._fetchall(
        "SELECT stage, channel_id, destination_name, handler_name, payload, status, attempts,"
        " next_attempt_at, created_at, updated_at FROM queue WHERE message_id=? ORDER BY seq",
        (mid,),
    )
    for r in rows:
        if r["payload"]:
            r["payload"] = store._cipher.decrypt(r["payload"])
    return rows


async def _events(store: Any, mid: str) -> list[tuple[Any, Any, Any]]:
    return [(e["event"], e["destination"], e["detail"]) for e in await store.events_for(mid)]


# --- activation + teardown on live SS -------------------------------------------------------------


async def test_activate_and_teardown_fusion_on_live_ss(store: Any) -> None:
    runner = RegistryRunner(
        _reg(), store, fuse_thread_hops=True, claim_mode="pooled", pooled_fusing_workers=2
    )
    runner._loop = asyncio.get_running_loop()
    runner._fusion_active = await runner._activate_fusion()
    assert runner._fusion_active is True
    # Both per-stage executors were built and both sync handoff pools opened at the fusing width.
    assert runner._fuse_route_executor is not None
    assert runner._fuse_transform_executor is not None
    assert store.sync_handoff_pool(Stage.ROUTED.value).size == 2
    assert store.sync_handoff_pool(Stage.OUTBOUND.value).size == 2
    # Teardown (stop() runs the fusing-executor shutdown + closes the sync pools; a reload would NOT).
    await runner.stop()
    assert runner._fusion_active is False
    assert runner._fuse_route_executor is None and runner._fuse_transform_executor is None
    with pytest.raises(KeyError):
        store.sync_handoff_pool(Stage.ROUTED.value)


# --- fused route: byte-identical to the async route_handoff ---------------------------------------


async def test_fused_route_persists_like_async(store: Any) -> None:
    runner = await _runner_with_fusion(store)
    try:
        # async control on channel IBA
        mid_a, ing_a = await _ingress_and_claim(store, "IBA", RAW, now=100.0)
        assert await store.route_handoff(
            ingress_id=ing_a.id,
            message_id=mid_a,
            channel_id="IBA",
            handlers=[("h", ing_a.payload)],
            disposition=MessageStatus.ROUTED,
            now=100.0,
        )
        # fused route on channel IB (the registry inbound), same now
        mid_b, ing_b = await _ingress_and_claim(store, "IB", RAW, now=100.0)
        result = await runner._fused_route_and_handoff(
            "IB", runner.registry.inbound["IB"], ing_b, now=100.0
        )
        # result record
        assert result.route_exc is None and result.handoff_exc is None
        assert result.handed_off is True
        assert result.names == ["h"]
        assert result.disposition is MessageStatus.ROUTED
        assert result.wake_target == "IB"
        # byte-identical persisted rows + events + status
        assert (await store.get_message(mid_a))["status"] == MessageStatus.ROUTED.value
        assert (await store.get_message(mid_b))["status"] == MessageStatus.ROUTED.value
        rows_a = await _queue_rows(store, mid_a)
        rows_b = await _queue_rows(store, mid_b)
        for r in rows_a + rows_b:
            del r["channel_id"]
        assert rows_a == rows_b
        assert [r["handler_name"] for r in rows_a] == ["h"]
        assert await _events(store, mid_a) == await _events(store, mid_b)
    finally:
        await runner.stop()


async def test_fused_route_unrouted_when_no_handler(store: Any) -> None:
    # A router that selects no handlers → UNROUTED disposition, no ROUTED lane wake, no routed rows.
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-in", "pattern": "*.hl7"}),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB1", ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-out"})
        )
    )
    reg.add_router("r", lambda m: [])
    reg.add_handler("h", lambda m: Send("OB1", "OUTBODY"))
    runner = RegistryRunner(
        reg, store, fuse_thread_hops=True, claim_mode="pooled", pooled_fusing_workers=1
    )
    runner._loop = asyncio.get_running_loop()
    runner._fusion_active = await runner._activate_fusion()
    try:
        mid, ing = await _ingress_and_claim(store, "IB", RAW, now=100.0)
        result = await runner._fused_route_and_handoff("IB", reg.inbound["IB"], ing, now=100.0)
        assert result.route_exc is None and result.handoff_exc is None
        assert result.names == []
        assert result.disposition is MessageStatus.UNROUTED
        assert result.wake_target is None
        assert (await store.get_message(mid))["status"] == MessageStatus.UNROUTED.value
        routed = [r for r in await _queue_rows(store, mid) if r["stage"] == Stage.ROUTED.value]
        assert routed == []
    finally:
        await runner.stop()


# --- fused transform: byte-identical outbound rows + applied-state for publish --------------------


async def test_fused_transform_persists_like_async(store: Any) -> None:
    runner = await _runner_with_fusion(store)
    try:
        # async control on IBA — distinct state namespace so the two runs don't overwrite each other's
        # state row (the fused twin's is asserted un-published below, exactly like the PR1 twin test).
        mid_a, rtd_a = await _route_and_claim(store, "IBA", RAW, now=100.0)
        assert await store.transform_handoff(
            routed_id=rtd_a.id,
            message_id=mid_a,
            channel_id="IBA",
            deliveries=[("OB1", "OUTBODY")],
            state_ops=[("stAsync", "k", {"v": 7})],
            now=100.0,
        )
        # fused transform on IB (handler h → Send OB1 + SetState stFused/k)
        mid_b, rtd_b = await _route_and_claim(store, "IB", RAW, now=100.0)
        result = await runner._fused_transform_and_handoff(
            "IB", runner.registry.inbound["IB"], rtd_b, now=100.0
        )
        assert result.xform_exc is None and result.handoff_exc is None
        assert result.deliveries == [("OB1", "OUTBODY")]
        assert result.pt_deliveries == []
        assert result.applied_state == [(("stFused", "k"), {"v": 7})]
        assert result.outbound_wakes == ("OB1",)
        assert result.ingress_wakes == ()

        # The sync twin must NOT have published to the loop-owned cache; the loop does via publish.
        assert ("stFused", "k") not in dict(store.state_view())
        store.publish_state_cache(result.applied_state)
        assert dict(store.state_view())[("stFused", "k")] == {"v": 7}

        # Byte-identical OUTBOUND rows (channel_id differs by construction: IBA vs IB).
        ob_a = [r for r in await _queue_rows(store, mid_a) if r["stage"] == Stage.OUTBOUND.value]
        ob_b = [r for r in await _queue_rows(store, mid_b) if r["stage"] == Stage.OUTBOUND.value]
        for r in ob_a + ob_b:
            del r["channel_id"]
        assert ob_a == ob_b and len(ob_a) == 1
        assert (await store.get_message(mid_a))["status"] == (await store.get_message(mid_b))[
            "status"
        ]

        # The fused state row persisted (decrypted) equals the async one.
        sf = await store._fetchone(
            "SELECT value FROM state WHERE namespace=? AND [key]=?", ("stFused", "k")
        )
        sa = await store._fetchone(
            "SELECT value FROM state WHERE namespace=? AND [key]=?", ("stAsync", "k")
        )
        assert json.loads(store._cipher.decrypt(sf["value"])) == json.loads(
            store._cipher.decrypt(sa["value"])
        )
    finally:
        await runner.stop()
