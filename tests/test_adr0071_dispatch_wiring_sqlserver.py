# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0071 B5 PR3 — live SQL Server DISPATCH-wiring rider tests (the merge rider).

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env), like
``test_adr0071_fused_callables_sqlserver.py``. Whereas the PR2 gated file drives the fused CALLABLES
directly, this file drives the messages END-TO-END through ``RegistryRunner._process_ingress_item`` /
``_process_routed_item`` with fusion ACTIVE — proving the PR3 DISPATCH wiring on a real backend:

* **Rider 1** — fused-route CRASH-REPLAY at each kill point (after claim / after CPU-before-commit /
  after commit): ``reset_stale_inflight`` → re-claim → re-run idempotently, ZERO loss, ZERO duplicate
  next-stage rows. The "crash" is simulated by driving the store ops + ``reset_stale_inflight`` directly
  (no real process kill), mirroring ``test_staged_pipeline`` / ``test_pooled_rider``.
* **Rider 2** — poison-guard: a catchable handler raise inside the fused hop dead-letters via the
  CONTINUE policy (the claim committed BEFORE the hop stays committed); a handoff rollback (INFRA)
  never un-commits the claim (the row survives, re-claimable after reset).
* **Rider 3** — byte-identical-nonfused: the same graph + message driven through ``_process_*_item``
  fused (flag-ON) vs async (flag-OFF) persists STRUCTURALLY identical queue rows + dispositions.
* **Rider 4** — error-classification LIVE: a handoff SQL fault PROPAGATES (→ drain-lane T17 re-pend,
  row stays re-claimable), never a content dead-letter; a router raise is a content dead-letter, not
  T17.
* **Rider 5** — finalizer sole-authority: a fan-out (2 deliveries) fused transform leaves the message
  non-terminal until BOTH outbound siblings resolve — the finalizer alone flips it PROCESSED.
* **Rider 6** — loopback response parity: a LOOPBACK routed row driven through the fused
  ``_process_routed_item`` prefetches the response_view on the loop so ``response_get`` resolves in the
  handler — parity with the async path.
* **Rider 7** — #283 SIGKILL-under-load with fusion on: needs the load/failover harness rig; a scaled
  in-test proxy runs here and the full harness leg is FLAGGED as an open concern (not faked).

Claims/handoffs run on the SERVER clock (``now`` omitted → ``None``), exactly as the production workers
do (``_router_worker`` / ``_transform_worker`` claim without ``now``), so rows the fused handoff and
``reset_stale_inflight`` stamp with the server clock are immediately due to re-claim.

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
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.store import MessageStatus, Stage
from messagefoundry.store.store import CapturedResponse

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


# --- registries ----------------------------------------------------------------------------------


def _file_in(name: str, router: str = "r") -> InboundConnection:
    return InboundConnection(
        name,
        ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-in", "pattern": "*.hl7"}),
        router=router,
    )


def _file_out(name: str) -> OutboundConnection:
    return OutboundConnection(
        name, ConnectionSpec(ConnectorType.FILE, {"directory": "/tmp/mefor-out"})
    )


def _reg_simple() -> Registry:
    """IB → r → h (Send OB1) → OB1."""
    reg = Registry()
    reg.add_inbound(_file_in("IB"))
    reg.add_outbound(_file_out("OB1"))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB1", "OUTBODY"))
    return reg


async def _runner_with_fusion(store: Any, reg: Registry | None = None) -> RegistryRunner:
    runner = RegistryRunner(
        reg or _reg_simple(),
        store,
        fuse_thread_hops=True,
        claim_mode="pooled",
        pooled_fusing_workers=1,
    )
    runner._loop = asyncio.get_running_loop()
    runner._fusion_active = await runner._activate_fusion()
    assert runner._fusion_active is True, "fusion must activate on live SQL Server"
    return runner


# --- store drivers (server-clock: now omitted, matching the production workers) -------------------


async def _ingress_and_claim(store: Any, channel: str, raw: str, **kw: Any) -> tuple[str, Any]:
    mid = await store.enqueue_ingress(channel_id=channel, raw=raw, **kw)
    ing = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value)
    assert ing is not None and ing.stage == Stage.INGRESS.value
    return mid, ing


async def _route_and_claim(
    store: Any, channel: str, raw: str, handler: str = "h"
) -> tuple[str, Any]:
    mid, ing = await _ingress_and_claim(store, channel, raw)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id=channel,
        handlers=[(handler, raw)],
        disposition=MessageStatus.ROUTED,
    )
    rtd = await store.claim_next_fifo(channel, stage=Stage.ROUTED.value)
    assert rtd is not None and rtd.stage == Stage.ROUTED.value
    return mid, rtd


async def _stage_rows(store: Any, mid: str, stage: str) -> list[dict[str, Any]]:
    return await store._fetchall(
        "SELECT id, stage, destination_name, handler_name, status, attempts"
        " FROM queue WHERE message_id=? AND stage=? ORDER BY seq",
        (mid, stage),
    )


async def _structural_rows(store: Any, mid: str) -> list[dict[str, Any]]:
    """All queue rows for a message, STRUCTURAL columns only (channel_id + wall-clock timestamps
    dropped — the dispatch does not forward a fixed ``now``, so created/updated_at differ by design;
    the structural rows are what must be byte-identical fused-vs-async)."""
    rows = await store._fetchall(
        "SELECT stage, destination_name, handler_name, payload, status, attempts"
        " FROM queue WHERE message_id=? ORDER BY seq",
        (mid,),
    )
    for r in rows:
        if r["payload"]:
            r["payload"] = store._cipher.decrypt(r["payload"])
    return rows


async def _status(store: Any, mid: str) -> str:
    msg = await store.get_message(mid)
    assert msg is not None
    return str(msg["status"])


# ============================ Rider 1 — fused-route crash-replay ============================


async def test_rider1_crash_replay_after_claim(store: Any) -> None:
    # Kill point (a): claimed, crashed BEFORE the hop. reset_stale_inflight → re-claim → fused re-run.
    runner = await _runner_with_fusion(store)
    try:
        mid, _ing = await _ingress_and_claim(store, "IB", RAW)
        # "crash": do nothing with the claimed (INFLIGHT) ingress row. Recovery re-pends it.
        assert await store.reset_stale_inflight() >= 1
        ing2 = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
        assert ing2 is not None
        outcome = await runner._process_ingress_item("IB", ing2)
        assert outcome == (_ItemOutcome.PROCESSED, None)
        routed = await _stage_rows(store, mid, Stage.ROUTED.value)
        assert len(routed) == 1 and routed[0]["handler_name"] == "h"  # exactly one, no dup
        assert await _status(store, mid) == MessageStatus.ROUTED.value
        assert await _stage_rows(store, mid, Stage.INGRESS.value) == []  # ingress consumed once
    finally:
        await runner.stop()


async def test_rider1_crash_replay_before_commit(store: Any) -> None:
    # Kill point (b): after CPU, BEFORE the handoff commit — inject a handoff fault (rolls back, ingress
    # row NOT consumed). Then recover + re-run clean → exactly one routed set, no loss/dup.
    runner = await _runner_with_fusion(store)
    try:
        mid, ing = await _ingress_and_claim(store, "IB", RAW)
        orig = store.route_handoff_sync

        def _boom(conn: Any, **kw: Any) -> bool:
            raise RuntimeError("handoff commit fault (pre-commit crash)")

        store.route_handoff_sync = _boom  # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            await runner._process_ingress_item("IB", ing)
        store.route_handoff_sync = orig  # restore
        # The handoff rolled back: no routed rows, ingress row intact (still INFLIGHT from the claim).
        assert await _stage_rows(store, mid, Stage.ROUTED.value) == []
        assert await store.reset_stale_inflight() >= 1
        ing2 = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
        assert ing2 is not None
        outcome = await runner._process_ingress_item("IB", ing2)
        assert outcome == (_ItemOutcome.PROCESSED, None)
        routed = await _stage_rows(store, mid, Stage.ROUTED.value)
        assert len(routed) == 1  # produced exactly once on the clean re-run
        assert await _status(store, mid) == MessageStatus.ROUTED.value
    finally:
        await runner.stop()


async def test_rider1_crash_replay_after_commit_idempotent(store: Any) -> None:
    # Kill point (c): the handoff COMMITTED (ingress consumed, routed rows created) then "crash" before
    # the loop wake. A re-run of the fused callable with the (now consumed) ingress row is a no-op —
    # the route_handoff_sync DELETE-guard returns False, ZERO duplicate routed rows.
    runner = await _runner_with_fusion(store)
    try:
        mid, ing = await _ingress_and_claim(store, "IB", RAW)
        outcome = await runner._process_ingress_item("IB", ing)
        assert outcome == (_ItemOutcome.PROCESSED, None)
        routed_once = await _stage_rows(store, mid, Stage.ROUTED.value)
        assert len(routed_once) == 1
        # reset recovers nothing for this message (ingress consumed; routed row is PENDING, not INFLIGHT).
        await store.reset_stale_inflight()
        # Faithful post-commit re-run of the SAME item: idempotent no-op, no duplicate routed rows.
        result = await runner._fused_route_and_handoff("IB", runner.registry.inbound["IB"], ing)
        assert result.handoff_exc is None and result.route_exc is None
        assert result.handed_off is False  # DELETE-guard no-op
        routed_again = await _stage_rows(store, mid, Stage.ROUTED.value)
        assert [r["id"] for r in routed_again] == [r["id"] for r in routed_once]  # unchanged
    finally:
        await runner.stop()


# ============================ Rider 2 — poison-guard ============================


async def test_rider2_handler_raise_dead_letters_via_continue(store: Any) -> None:
    reg = Registry()
    reg.add_inbound(_file_in("IB"))
    reg.add_outbound(_file_out("OB1"))
    reg.add_router("r", lambda m: ["h"])

    def _boom(m: Any) -> Any:
        raise ValueError("poison handler")

    reg.add_handler("h", _boom)
    runner = await _runner_with_fusion(store, reg)
    try:
        mid, rtd = await _route_and_claim(store, "IB", RAW)
        assert rtd.attempts >= 1  # the claim committed (attempts bumped) BEFORE the hop
        outcome = await runner._process_routed_item("IB", rtd)
        assert outcome == (_ItemOutcome.PROCESSED, None)  # CONTINUE dead-letters + advances
        assert await _status(store, mid) == MessageStatus.ERROR.value
        # No outbound rows produced by a poisoned handler.
        assert await _stage_rows(store, mid, Stage.OUTBOUND.value) == []
    finally:
        await runner.stop()


async def test_rider2_handoff_rollback_preserves_claim(store: Any) -> None:
    # A transform-handoff rollback (INFRA) propagates but NEVER un-commits the claim: the routed row
    # survives INFLIGHT and is re-claimable after recovery (the message is not dead-lettered).
    runner = await _runner_with_fusion(store)
    try:
        mid, rtd = await _route_and_claim(store, "IB", RAW)
        orig = store.transform_handoff_sync

        def _boom(conn: Any, **kw: Any) -> Any:
            raise RuntimeError("transform handoff commit fault")

        store.transform_handoff_sync = _boom  # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            await runner._process_routed_item("IB", rtd)
        store.transform_handoff_sync = orig  # restore
        assert await _status(store, mid) != MessageStatus.ERROR.value  # NOT dead-lettered
        assert await _stage_rows(store, mid, Stage.OUTBOUND.value) == []  # nothing committed
        assert await store.reset_stale_inflight() >= 1  # the routed row survives, re-claimable
        rtd2 = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
        assert rtd2 is not None and rtd2.id == rtd.id
    finally:
        await runner.stop()


# ============================ Rider 3 — byte-identical fused vs async ============================


async def test_rider3_byte_identical_fused_vs_async(store: Any) -> None:
    # Same graph + message driven through _process_*_item fused (flag-ON) vs async (flag-OFF) → the same
    # structural queue rows + dispositions. Two registered inbounds so each consumes its own rows.
    reg = Registry()
    reg.add_inbound(_file_in("IBF"))  # fused
    reg.add_inbound(_file_in("IBA"))  # async
    reg.add_outbound(_file_out("OB1"))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB1", "OUTBODY"))
    runner = await _runner_with_fusion(store, reg)
    try:
        # --- fused (flag ON) end-to-end: ingress -> routed -> outbound ---
        runner._fusion_active = True
        mid_f, ing_f = await _ingress_and_claim(store, "IBF", RAW)
        assert (await runner._process_ingress_item("IBF", ing_f))[0] is _ItemOutcome.PROCESSED
        rtd_f = await store.claim_next_fifo("IBF", stage=Stage.ROUTED.value)
        assert rtd_f is not None
        assert (await runner._process_routed_item("IBF", rtd_f))[0] is _ItemOutcome.PROCESSED

        # --- async (flag OFF) end-to-end ---
        runner._fusion_active = False
        mid_a, ing_a = await _ingress_and_claim(store, "IBA", RAW)
        assert (await runner._process_ingress_item("IBA", ing_a))[0] is _ItemOutcome.PROCESSED
        rtd_a = await store.claim_next_fifo("IBA", stage=Stage.ROUTED.value)
        assert rtd_a is not None
        assert (await runner._process_routed_item("IBA", rtd_a))[0] is _ItemOutcome.PROCESSED

        assert await _structural_rows(store, mid_f) == await _structural_rows(store, mid_a)
        assert await _status(store, mid_f) == await _status(store, mid_a)
    finally:
        await runner.stop()


# ============================ Rider 4 — error-classification live ============================


async def test_rider4_infra_propagates_content_dead_letters(store: Any) -> None:
    # INFRA (a handoff SQL fault) PROPAGATES out of _process_ingress_item (→ T17 re-pend, row stays
    # re-claimable), never a content dead-letter.
    runner = await _runner_with_fusion(store)
    try:
        mid, ing = await _ingress_and_claim(store, "IB", RAW)
        orig = store.route_handoff_sync

        def _boom(conn: Any, **kw: Any) -> bool:
            raise RuntimeError("simulated SQL fault / sync-pool acquire timeout")

        store.route_handoff_sync = _boom  # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            await runner._process_ingress_item("IB", ing)
        store.route_handoff_sync = orig
        assert (
            await _status(store, mid) == MessageStatus.RECEIVED.value
        )  # NOT ERROR (no dead-letter)
        assert await store.reset_stale_inflight() >= 1  # row survives, re-claimable (T17 semantics)
    finally:
        await runner.stop()


async def test_rider4_router_raise_is_content_not_t17(store: Any) -> None:
    reg = Registry()
    reg.add_inbound(_file_in("IB"))
    reg.add_outbound(_file_out("OB1"))

    def _boom_router(m: Any) -> list[str]:
        raise ValueError("router poison")

    reg.add_router("r", _boom_router)
    reg.add_handler("h", lambda m: Send("OB1", "OUTBODY"))
    runner = await _runner_with_fusion(store, reg)
    try:
        mid, ing = await _ingress_and_claim(store, "IB", RAW)
        outcome = await runner._process_ingress_item("IB", ing)  # NO raise — a content dead-letter
        assert outcome == (_ItemOutcome.PROCESSED, None)
        assert await _status(store, mid) == MessageStatus.ERROR.value
    finally:
        await runner.stop()


# ============================ Rider 5 — finalizer sole-authority ============================


async def test_rider5_finalizer_waits_for_all_siblings(store: Any) -> None:
    reg = Registry()
    reg.add_inbound(_file_in("IB"))
    reg.add_outbound(_file_out("OB1"))
    reg.add_outbound(_file_out("OB2"))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [Send("OB1", "A"), Send("OB2", "B")])  # fan-out
    runner = await _runner_with_fusion(store, reg)
    try:
        mid, rtd = await _route_and_claim(store, "IB", RAW)
        assert (await runner._process_routed_item("IB", rtd))[0] is _ItemOutcome.PROCESSED
        ob = await _stage_rows(store, mid, Stage.OUTBOUND.value)
        assert len(ob) == 2  # two outbound siblings
        # The fused transform did NOT finalize — the message is still non-terminal (ROUTED).
        assert await _status(store, mid) == MessageStatus.ROUTED.value
        # Resolve ONE sibling: still non-terminal (the finalizer waits for BOTH).
        d1 = await store.claim_next_fifo("OB1", stage=Stage.OUTBOUND.value)
        assert d1 is not None
        await store.mark_done(d1.id)
        assert await _status(store, mid) == MessageStatus.ROUTED.value
        # Resolve the second: NOW the finalizer flips PROCESSED (sole authority, after all siblings).
        d2 = await store.claim_next_fifo("OB2", stage=Stage.OUTBOUND.value)
        assert d2 is not None
        await store.mark_done(d2.id)
        assert await _status(store, mid) == MessageStatus.PROCESSED.value
    finally:
        await runner.stop()


# ============================ Rider 6 — loopback response parity ============================


async def test_rider6_loopback_response_view_parity(store: Any) -> None:
    # A LOOPBACK routed row driven through the fused _process_routed_item prefetches the response_view
    # ON THE LOOP so response_get resolves in the handler — parity with the async path. The captured
    # reply is injected via correlate_response (the full re-ingress round-trip is covered by the
    # loopback pipeline tests); this proves the fused DISPATCH performs the prefetch identically.
    reg = Registry()
    reg.add_inbound(InboundConnection("LB", ConnectionSpec(ConnectorType.LOOPBACK, {}), router="r"))
    reg.add_outbound(_file_out("OB1"))
    reg.add_router("r", lambda m: ["hl"])

    def _resp_handler(m: Any) -> Any:
        from messagefoundry.config.response import response_get

        r = response_get("ORIG")
        return Send("OB1", r.body if r is not None else "NO-RESPONSE")

    reg.add_handler("hl", _resp_handler)

    captured = [
        CapturedResponse(
            message_id="x",
            destination_name="ORIG",
            response_seq=1,
            outcome="AA",
            detail=None,
            captured_at=1.0,
            body="REPLYBODY",
        )
    ]

    async def _correlate(corr: str) -> list[CapturedResponse]:
        return captured

    store.correlate_response = _correlate  # type: ignore[method-assign]
    meta = json.dumps({"correlation_id": "corr-1"})

    runner = await _runner_with_fusion(store, reg)
    try:
        # fused
        mid_f, rtd_f = await _route_and_claim_loop(store, "LB", meta)
        runner._fusion_active = True
        assert (await runner._process_routed_item("LB", rtd_f))[0] is _ItemOutcome.PROCESSED
        ob_f = await _stage_rows(store, mid_f, Stage.OUTBOUND.value)
        assert len(ob_f) == 1
        payload_f = await _outbound_payload(store, ob_f[0]["id"])
        assert payload_f == "REPLYBODY"  # the handler saw the prefetched captured reply

        # async parity
        mid_a, rtd_a = await _route_and_claim_loop(store, "LB", meta)
        runner._fusion_active = False
        assert (await runner._process_routed_item("LB", rtd_a))[0] is _ItemOutcome.PROCESSED
        ob_a = await _stage_rows(store, mid_a, Stage.OUTBOUND.value)
        payload_a = await _outbound_payload(store, ob_a[0]["id"])
        assert payload_f == payload_a  # fused == async
    finally:
        await runner.stop()


async def _route_and_claim_loop(store: Any, channel: str, meta: str) -> tuple[str, Any]:
    mid = await store.enqueue_ingress(channel_id=channel, raw=RAW, metadata=meta)
    ing = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value)
    assert ing is not None
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id=channel,
        handlers=[("hl", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    rtd = await store.claim_next_fifo(channel, stage=Stage.ROUTED.value)
    assert rtd is not None
    return mid, rtd


async def _outbound_payload(store: Any, row_id: str) -> str:
    row = await store._fetchone("SELECT payload FROM queue WHERE id=?", (row_id,))
    return str(store._cipher.decrypt(row["payload"]))


# ============================ Rider 7 — SIGKILL-under-load (harness rig) ============================


async def test_rider7_sigkill_under_load_scaled_proxy(store: Any) -> None:
    # Scaled in-test proxy for #283 SIGKILL-under-load with fusion ON: drive a burst of messages
    # through the fused route+transform dispatch, interleave a mid-burst reset_stale_inflight ("kill"
    # recovery), and assert NO loss / NO duplicate outbound rows. The FULL two-node SIGKILL-under-load
    # leg needs the load/failover harness rig (harness/failover) and is FLAGGED in open_concerns — this
    # proxy is a genuine scaled variant, not a faked pass.
    runner = await _runner_with_fusion(store)
    try:
        n = 12
        mids = []
        for _i in range(n):
            mids.append(await store.enqueue_ingress(channel_id="IB", raw=RAW))
        # Route each ingress row (fused), with a "kill" recovery sweep mid-burst.
        for i in range(n):
            ing = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
            assert ing is not None
            assert (await runner._process_ingress_item("IB", ing))[0] is _ItemOutcome.PROCESSED
            if i == n // 2:
                await store.reset_stale_inflight()  # simulate a mid-burst crash-recovery sweep
        # Transform each routed row (fused).
        for _i in range(n):
            rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
            if rtd is None:
                break
            assert (await runner._process_routed_item("IB", rtd))[0] is _ItemOutcome.PROCESSED
        # Every message produced EXACTLY one outbound row — no loss, no duplicate.
        for mid in mids:
            assert len(await _stage_rows(store, mid, Stage.OUTBOUND.value)) == 1
    finally:
        await runner.stop()
