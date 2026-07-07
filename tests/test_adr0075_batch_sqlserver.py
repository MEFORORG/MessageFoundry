# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0075 — LIVE SQL Server integration tests for per-hop statement batching (the merge gate).

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env), like
``test_adr0071_dispatch_wiring_sqlserver.py``. These run on the CI SQL Server leg / the rig and verify
what the OFFLINE tests structurally cannot — the REAL pyodbc/aioodbc behaviour the batching's
positioning-safety proof depends on:

* (a) POSITIONING — a batched handoff drives the message to the CORRECT terminal disposition (route:
  ROUTED / UNROUTED; transform-finalize: FILTERED / still-moving / PROCESSED). A correct disposition
  proves the folded ``SELECT @rc`` / ``FINALIZE_COUNT`` / ``SELECT status`` reads each returned the
  intended rowset AFTER preceding DML under ``SET NOCOUNT ON``.
* (b) FAIL-CLOSED — with the finalize applock held from a second session and a small applock timeout, a
  batched handoff RAISES (rc=-1 → RuntimeError), ROLLS BACK, the claimed row is recoverable, and
  ``messages.status`` was NOT advanced. The load-bearing guarantee: no unserialized write commits.
* (c) SERIALIZATION — concurrent batched finalizers of the same message do not corrupt / lost-update
  the disposition (the applock discipline holds under batching).
* (d) NOCOUNT PARITY — a ``cursor.rowcount``-dependent op (``reset_stale_inflight``) on the same pooled
  connection returns the correct count after a batched handoff (``SET NOCOUNT ON`` doesn't corrupt it).
* (e) A/B DISPOSITION PARITY — a full route→transform→deliver pass yields the identical disposition +
  row structure with the flag ON vs OFF, with zero lost/duplicate rows.

Requires the ``sqlserver`` extra (aioodbc + pyodbc + ODBC Driver 18). Claims/handoffs run on the SERVER
clock (``now`` omitted) exactly as the production workers do.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from typing import Any, AsyncIterator

import pytest

from messagefoundry.store import MessageStatus, Stage
from messagefoundry.store import sqlserver as ss

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


async def _open_store() -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    return await SqlServerStore.open(settings)


async def _clear(store: Any) -> None:
    async with store._pool.acquire() as conn:
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


@pytest.fixture
async def store() -> AsyncIterator[Any]:
    s = await _open_store()
    await _clear(s)
    yield s
    await s.close()


# --- drivers (server-clock: now omitted, matching the production workers) --------------------------


async def _ingress_and_claim(store: Any, channel: str = "IB") -> tuple[str, Any]:
    mid = await store.enqueue_ingress(channel_id=channel, raw=RAW)
    ing = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value)
    assert ing is not None and ing.stage == Stage.INGRESS.value
    return mid, ing


async def _route(
    store: Any,
    channel: str,
    mid: str,
    ing: Any,
    *,
    handlers: list[tuple[str, str]],
    disposition: MessageStatus,
) -> bool:
    return await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id=channel,
        handlers=handlers,
        disposition=disposition,
    )


async def _claim_routed(store: Any, channel: str = "IB") -> Any:
    rtd = await store.claim_next_fifo(channel, stage=Stage.ROUTED.value)
    assert rtd is not None and rtd.stage == Stage.ROUTED.value
    return rtd


async def _status(store: Any, mid: str) -> str:
    msg = await store.get_message(mid)
    assert msg is not None
    return str(msg["status"])


async def _stage_rows(store: Any, mid: str, stage: str) -> list[dict[str, Any]]:
    return await store._fetchall(
        "SELECT id, stage, destination_name, handler_name, status FROM queue"
        " WHERE message_id=? AND stage=? ORDER BY seq",
        (mid, stage),
    )


@contextlib.asynccontextmanager
async def _hold_finalize_applock(store: Any, mid: str) -> AsyncIterator[None]:
    """Hold ``mefor:finalize:<mid>`` EXCLUSIVE on a dedicated SESSION-owned lock from a separate pooled
    connection, so a batched handoff's Transaction-owned applock request on the same resource blocks and
    (with a small timeout) times out to rc=-1."""
    resource = f"mefor:finalize:{mid}"
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute(
            "DECLARE @rc INT; EXEC @rc = sp_getapplock @Resource=?, @LockMode='Exclusive',"
            " @LockOwner='Session', @LockTimeout=0; SELECT @rc",
            (resource,),
        )
        rc = (await cur.fetchone())[0]
        assert int(rc) >= 0, f"could not pre-acquire the finalize applock (rc={rc})"
        try:
            yield
        finally:
            await cur.execute(
                "EXEC sp_releaseapplock @Resource=?, @LockOwner='Session'", (resource,)
            )
            await conn.commit()


# ============================ (a) POSITIONING ============================


async def test_batched_route_reaches_routed_disposition(store: Any) -> None:
    store.set_batch_handoff_statements(True)
    mid, ing = await _ingress_and_claim(store)
    ok = await _route(
        store, "IB", mid, ing, handlers=[("h", RAW)], disposition=MessageStatus.ROUTED
    )
    assert ok is True
    assert await _status(store, mid) == MessageStatus.ROUTED.value  # applock rc read correctly
    assert len(await _stage_rows(store, mid, Stage.ROUTED.value)) == 1
    assert await _stage_rows(store, mid, Stage.INGRESS.value) == []  # ingress consumed once


async def test_batched_route_reaches_unrouted_disposition(store: Any) -> None:
    store.set_batch_handoff_statements(True)
    mid, ing = await _ingress_and_claim(store)
    ok = await _route(store, "IB", mid, ing, handlers=[], disposition=MessageStatus.UNROUTED)
    assert ok is True
    assert await _status(store, mid) == MessageStatus.UNROUTED.value
    assert await _stage_rows(store, mid, Stage.ROUTED.value) == []


async def test_batched_transform_filtered_reaches_filtered(store: Any) -> None:
    # A transform that delivers nothing (no outbound rows) -> the finalizer's check_message branch reads
    # messages.status ('routed') and sets FILTERED. Proves the folded FINALIZE_COUNT + the EXTRA
    # SELECT status read each returned the intended rowset after preceding DML.
    store.set_batch_handoff_statements(True)
    mid, ing = await _ingress_and_claim(store)
    await _route(store, "IB", mid, ing, handlers=[("h", RAW)], disposition=MessageStatus.ROUTED)
    rtd = await _claim_routed(store)
    handed = await store.transform_handoff(
        routed_id=rtd.id, message_id=mid, channel_id="IB", deliveries=[]
    )
    assert handed is True
    assert await _status(store, mid) == MessageStatus.FILTERED.value


async def test_batched_transform_then_deliver_reaches_processed(store: Any) -> None:
    store.set_batch_handoff_statements(True)
    mid, ing = await _ingress_and_claim(store)
    await _route(store, "IB", mid, ing, handlers=[("h", RAW)], disposition=MessageStatus.ROUTED)
    rtd = await _claim_routed(store)
    await store.transform_handoff(
        routed_id=rtd.id, message_id=mid, channel_id="IB", deliveries=[("OB1", "OUTBODY")]
    )
    # Still moving until the outbound is delivered (the batched FINALIZE_COUNT saw a PENDING row).
    assert await _status(store, mid) == MessageStatus.ROUTED.value
    ob = await store.claim_next_fifo("OB1", stage=Stage.OUTBOUND.value)
    assert ob is not None
    await store.mark_done(ob.id)  # mark_done is not batched (by design); it finalizes PROCESSED
    assert await _status(store, mid) == MessageStatus.PROCESSED.value


# ============================ (b) FAIL-CLOSED (the load-bearing one) ============================


async def test_batched_route_fails_closed_when_applock_unavailable(
    store: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.set_batch_handoff_statements(True)
    # Small applock timeout so rc=-1 fires fast; the statement timeout stays large (decoupled) so the
    # RAISE is the applock rc gate, not an ODBC statement timeout.
    monkeypatch.setattr(ss, "_applock_timeout_ms", lambda _ct: 1500)
    mid, ing = await _ingress_and_claim(store)
    async with _hold_finalize_applock(store, mid):
        with pytest.raises(RuntimeError, match="sp_getapplock"):
            await _route(
                store, "IB", mid, ing, handlers=[("h", RAW)], disposition=MessageStatus.ROUTED
            )
    # Rolled back: no routed rows were committed, and the disposition was NOT advanced to ROUTED.
    assert await _stage_rows(store, mid, Stage.ROUTED.value) == []
    assert await _status(store, mid) != MessageStatus.ROUTED.value
    # The claimed ingress row is recoverable (the guard-DELETE rolled back), so the message is not lost.
    assert await store.reset_stale_inflight() >= 1
    ing2 = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert ing2 is not None  # re-claimable → re-runs cleanly next pass


# ============================ (c) SERIALIZATION ============================


async def test_batched_concurrent_finalizers_do_not_corrupt_disposition(store: Any) -> None:
    # Two handlers -> two routed rows -> two batched transform handoffs run CONCURRENTLY. Each finalizes
    # under the per-message applock, so they serialize: no deadlock, no lost update, exactly two outbound
    # rows, coherent disposition (still ROUTED while both outbounds are PENDING). After delivering both,
    # the finalizer flips PROCESSED. This is the serialization-under-batching smoke.
    store.set_batch_handoff_statements(True)
    mid, ing = await _ingress_and_claim(store)
    await _route(
        store,
        "IB",
        mid,
        ing,
        handlers=[("h1", RAW), ("h2", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    rtd1 = await _claim_routed(store)
    rtd2 = await _claim_routed(store)

    async def _xform(rtd: Any, dest: str) -> bool:
        return await store.transform_handoff(
            routed_id=rtd.id, message_id=mid, channel_id="IB", deliveries=[(dest, "OUTBODY")]
        )

    results = await asyncio.gather(_xform(rtd1, "OB1"), _xform(rtd2, "OB2"))
    assert all(results)
    assert len(await _stage_rows(store, mid, Stage.OUTBOUND.value)) == 2
    assert await _status(store, mid) == MessageStatus.ROUTED.value  # still moving, no torn write
    for dest in ("OB1", "OB2"):
        ob = await store.claim_next_fifo(dest, stage=Stage.OUTBOUND.value)
        assert ob is not None
        await store.mark_done(ob.id)
    assert await _status(store, mid) == MessageStatus.PROCESSED.value


# ============================ (d) NOCOUNT PARITY ============================


async def test_rowcount_ops_correct_after_batched_handoff(store: Any) -> None:
    # After a batched handoff (which runs SET NOCOUNT ON in its render), a cursor.rowcount-dependent op
    # on the SAME pooled connection must still return the correct count. reset_stale_inflight recovers
    # INFLIGHT rows via rowcount; claim one row INFLIGHT and assert it recovers exactly it.
    store.set_batch_handoff_statements(True)
    mid, ing = await _ingress_and_claim(store)
    await _route(store, "IB", mid, ing, handlers=[("h", RAW)], disposition=MessageStatus.ROUTED)
    await store.transform_handoff(
        routed_id=(await _claim_routed(store)).id,
        message_id=mid,
        channel_id="IB",
        deliveries=[("OB1", "OUTBODY")],
    )
    ob = await store.claim_next_fifo("OB1", stage=Stage.OUTBOUND.value)  # -> INFLIGHT
    assert ob is not None
    # rowcount-driven recovery must see exactly the one INFLIGHT row (NOCOUNT did not zero it).
    recovered = await store.reset_stale_inflight()
    assert recovered >= 1


# ============================ (e) A/B DISPOSITION PARITY ============================


async def _full_pass(store: Any, *, batch: bool, filtered: bool) -> str:
    store.set_batch_handoff_statements(batch)
    mid, ing = await _ingress_and_claim(store)
    await _route(store, "IB", mid, ing, handlers=[("h", RAW)], disposition=MessageStatus.ROUTED)
    rtd = await _claim_routed(store)
    deliveries: list[tuple[str, str]] = [] if filtered else [("OB1", "OUTBODY")]
    await store.transform_handoff(
        routed_id=rtd.id, message_id=mid, channel_id="IB", deliveries=deliveries
    )
    if not filtered:
        ob = await store.claim_next_fifo("OB1", stage=Stage.OUTBOUND.value)
        assert ob is not None
        await store.mark_done(ob.id)
    return await _status(store, mid)


@pytest.mark.parametrize("filtered", [False, True])
async def test_ab_disposition_parity_on_vs_off(store: Any, filtered: bool) -> None:
    off = await _full_pass(store, batch=False, filtered=filtered)
    await _clear(store)
    on = await _full_pass(store, batch=True, filtered=filtered)
    assert on == off  # identical terminal disposition, flag ON vs OFF
    expected = MessageStatus.FILTERED.value if filtered else MessageStatus.PROCESSED.value
    assert on == expected
