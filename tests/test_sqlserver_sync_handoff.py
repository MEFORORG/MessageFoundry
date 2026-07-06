# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0071 B5 PR1 — live SQL Server tests for the synchronous fused-handoff twins.

**Gated**: skipped unless ``MEFOR_TEST_SQLSERVER`` is set (plus ``MEFOR_STORE_*`` connection env), like
``test_sqlserver_store.py``. Proves the sync twins (``route_handoff_sync`` / ``transform_handoff_sync``,
driven by a dedicated synchronous pyodbc pool) produce **byte-identical** persisted rows to the async
handoffs against a real SQL Server, plus the DELETE-guard idempotency, the finite ``conn.timeout``, and
the PT re-ingress branch end-to-end. Requires the ``sqlserver`` extra (aioodbc + pyodbc + ODBC Driver
18).
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator

import pytest

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


async def _ingress_and_claim(store: Any, channel: str, raw: str, now: float) -> tuple[str, Any]:
    mid = await store.enqueue_ingress(channel_id=channel, raw=raw, now=now)
    ing = await store.claim_next_fifo(channel, stage=Stage.INGRESS.value, now=now)
    assert ing is not None and ing.stage == Stage.INGRESS.value
    return mid, ing


async def _queue_rows(store: Any, mid: str) -> list[dict[str, Any]]:
    """The message's queue rows with decrypted payloads, minus the random id + IDENTITY seq — so async
    and sync rows are comparable byte-for-byte (both driven with the same ``now``)."""
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


# --- the dedicated synchronous pyodbc pool --------------------------------------------------------


async def test_sync_pool_conn_timeout_is_finite(store: Any) -> None:
    pool = store.open_sync_handoff_pool("routed", 2)
    try:
        assert pool.size == 2
        ct = store._settings.command_timeout
        assert ct > 0
        assert pool.conn_timeout == ct
        with pool.acquire(timeout=5) as conn:
            # A finite per-statement timeout (seconds), independent of the login timeout — never 0/None
            # (0 would be "wait forever", which the ct==0 refusal prevents up front).
            assert conn.timeout == ct
            assert conn.timeout not in (0, None)
        # sync_handoff_pool() returns the same registered pool.
        assert store.sync_handoff_pool("routed") is pool
    finally:
        store.close_sync_handoff_pool()
    # Closed + dropped: a fresh lookup raises.
    with pytest.raises(KeyError):
        store.sync_handoff_pool("routed")


async def test_reopen_replaces_prior_pool(store: Any) -> None:
    p1 = store.open_sync_handoff_pool("routed", 1)
    p2 = store.open_sync_handoff_pool("routed", 2)
    assert p1 is not p2
    assert store.sync_handoff_pool("routed") is p2
    assert p2.size == 2
    store.close_sync_handoff_pool()


async def test_sync_pool_discards_broken_connection(store: Any) -> None:
    """A connection broken mid-handoff (here: closed while the acquire block raises, mirroring a
    twin's re-raised handoff_exc) is DISCARDED and the slot lazily reconnected — the next acquire gets
    a fresh WORKING connection, never the poisoned one, and the slot count stays stable."""
    pool = store.open_sync_handoff_pool("routed", 1)
    try:
        broken_conn = None
        with pytest.raises(RuntimeError):
            with pool.acquire(timeout=5) as conn:
                broken_conn = conn
                conn.close()  # simulate a mid-handoff connection death (blip / restart / killed session)
                raise RuntimeError("boom")  # the sync twins re-raise on fault -> the slot is broken
        assert pool.size == 1  # slot count unchanged (refilled, not shrunk)
        # The poisoned connection was not re-circulated: the next borrower gets a fresh, usable one.
        with pool.acquire(timeout=5) as conn2:
            assert conn2 is not broken_conn
            cur = conn2.cursor()
            try:
                cur.execute("SELECT 1")
                assert cur.fetchone()[0] == 1
            finally:
                cur.close()
    finally:
        store.close_sync_handoff_pool()


# --- byte-identical: sync twin vs async handoff ---------------------------------------------------


async def test_route_handoff_sync_byte_identical_to_async(store: Any) -> None:
    handlers = [("H1", "p1"), ("H2", "p2")]

    # async
    mid_a, ing_a = await _ingress_and_claim(store, "IB", RAW, now=100.0)
    assert await store.route_handoff(
        ingress_id=ing_a.id,
        message_id=mid_a,
        channel_id="IB",
        handlers=handlers,
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )

    # sync (dedicated pyodbc connection)
    mid_b, ing_b = await _ingress_and_claim(store, "IB", RAW, now=100.0)
    pool = store.open_sync_handoff_pool("routed", 1)
    with pool.acquire(timeout=5) as conn:
        assert store.route_handoff_sync(
            conn,
            ingress_id=ing_b.id,
            message_id=mid_b,
            channel_id="IB",
            handlers=handlers,
            disposition=MessageStatus.ROUTED,
            now=100.0,
        )

    assert (await store.get_message(mid_a))["status"] == MessageStatus.ROUTED.value
    assert (await store.get_message(mid_b))["status"] == MessageStatus.ROUTED.value
    rows_a = await _queue_rows(store, mid_a)
    rows_b = await _queue_rows(store, mid_b)
    assert rows_a == rows_b
    assert [r["handler_name"] for r in rows_a] == ["H1", "H2"]  # 2 routed rows, handler-list order
    assert await _events(store, mid_a) == await _events(store, mid_b)


async def test_transform_handoff_sync_byte_identical_to_async(store: Any) -> None:
    async def _route(channel: str) -> tuple[str, Any]:
        mid, ing = await _ingress_and_claim(store, channel, RAW, now=100.0)
        await store.route_handoff(
            ingress_id=ing.id,
            message_id=mid,
            channel_id=channel,
            handlers=[("H", RAW)],
            disposition=MessageStatus.ROUTED,
            now=100.0,
        )
        rtd = await store.claim_next_fifo(channel, stage=Stage.ROUTED.value, now=100.0)
        return mid, rtd

    # async transform (state key stA)
    mid_a, rtd_a = await _route("IBA")
    assert await store.transform_handoff(
        routed_id=rtd_a.id,
        message_id=mid_a,
        channel_id="IBA",
        deliveries=[("OB1", "body")],
        state_ops=[("stA", "k", {"v": 1})],
        now=100.0,
    )

    # sync transform (state key stB) — same shape, distinct state key so they don't overwrite
    mid_b, rtd_b = await _route("IBB")
    pool = store.open_sync_handoff_pool("outbound", 1)
    with pool.acquire(timeout=5) as conn:
        handed_off, applied = store.transform_handoff_sync(
            conn,
            routed_id=rtd_b.id,
            message_id=mid_b,
            channel_id="IBB",
            deliveries=[("OB1", "body")],
            state_ops=[("stB", "k", {"v": 1})],
            now=100.0,
        )
    assert handed_off is True
    assert applied == [(("stB", "k"), {"v": 1})]

    # The sync twin must NOT have touched the loop-owned cache; publish does.
    assert ("stB", "k") not in dict(store.state_view())
    store.publish_state_cache(applied)
    assert dict(store.state_view())[("stB", "k")] == {"v": 1}

    # Byte-identical outbound rows + events + status.
    assert (await store.get_message(mid_a))["status"] == (await store.get_message(mid_b))["status"]
    # Compare only the outbound-stage rows (channel_id differs by construction: IBA vs IBB).
    ob_a = [r for r in await _queue_rows(store, mid_a) if r["stage"] == Stage.OUTBOUND.value]
    ob_b = [r for r in await _queue_rows(store, mid_b) if r["stage"] == Stage.OUTBOUND.value]
    for r in ob_a + ob_b:
        del r["channel_id"]
    assert ob_a == ob_b and len(ob_a) == 1
    assert [e[0] for e in await _events(store, mid_a)] == [
        e[0] for e in await _events(store, mid_b)
    ]

    # The persisted state rows (decrypted) are equal.
    sa = await store._fetchone(
        "SELECT value FROM state WHERE namespace=? AND [key]=?", ("stA", "k")
    )
    sb = await store._fetchone(
        "SELECT value FROM state WHERE namespace=? AND [key]=?", ("stB", "k")
    )
    assert json.loads(store._cipher.decrypt(sa["value"])) == json.loads(
        store._cipher.decrypt(sb["value"])
    )


# --- DELETE-guard idempotency (False / (False, []) on a re-run) ------------------------------------


async def test_route_handoff_sync_idempotent_on_rerun(store: Any) -> None:
    mid, ing = await _ingress_and_claim(store, "IB", RAW, now=100.0)
    pool = store.open_sync_handoff_pool("routed", 2)
    kw = dict(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H1", "p")],
        disposition=MessageStatus.ROUTED,
    )
    with pool.acquire(timeout=5) as c1:
        assert store.route_handoff_sync(c1, now=100.0, **kw) is True
    with pool.acquire(timeout=5) as c2:
        # ingress row already consumed -> idempotent no-op
        assert store.route_handoff_sync(c2, now=100.0, **kw) is False
    # Exactly the 2 routed rows from the single successful run (no duplicate next-stage rows).
    routed = [r for r in await _queue_rows(store, mid) if r["stage"] == Stage.ROUTED.value]
    assert len(routed) == 1


async def test_transform_handoff_sync_idempotent_on_rerun(store: Any) -> None:
    mid, ing = await _ingress_and_claim(store, "IB", RAW, now=100.0)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("H", RAW)],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    rtd = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value, now=100.0)
    pool = store.open_sync_handoff_pool("outbound", 2)
    tkw = dict(routed_id=rtd.id, message_id=mid, channel_id="IB", deliveries=[("OB1", "b")])
    with pool.acquire(timeout=5) as c1:
        ok, applied = store.transform_handoff_sync(c1, now=100.0, **tkw)
        assert ok is True and applied == []
    with pool.acquire(timeout=5) as c2:
        ok2, applied2 = store.transform_handoff_sync(c2, now=100.0, **tkw)
        assert ok2 is False and applied2 == []
    outbound = [r for r in await _queue_rows(store, mid) if r["destination_name"] == "OB1"]
    assert len(outbound) == 1  # exactly one outbound row (no duplicate from the re-run)


# --- PT re-ingress via the sync twin (functional end-to-end) --------------------------------------


async def test_transform_handoff_sync_pt_reingress_produces_child(store: Any) -> None:
    mid, ing = await _ingress_and_claim(store, "IB_REAL", "MSH|parent", now=100.0)
    await store.route_handoff(
        ingress_id=ing.id,
        message_id=mid,
        channel_id="IB_REAL",
        handlers=[("h1", "MSH|parent")],
        disposition=MessageStatus.ROUTED,
        now=100.0,
    )
    rtd = await store.claim_next_fifo("IB_REAL", stage=Stage.ROUTED.value, now=100.0)
    pool = store.open_sync_handoff_pool("outbound", 1)
    with pool.acquire(timeout=5) as conn:
        ok, applied = store.transform_handoff_sync(
            conn,
            routed_id=rtd.id,
            message_id=mid,
            channel_id="IB_REAL",
            deliveries=[],
            pt_deliveries=[("PT_NEXT", "MSH|child")],
            now=110.0,
        )
    assert ok is True and applied == []
    # Parent finalizes PROCESSED (a done PT marker; no in-flight rows) — not FILTERED.
    assert (await store.get_message(mid))["status"] == MessageStatus.PROCESSED.value
    # Child: a distinct content-addressed message on the PT channel, RECEIVED, correlated.
    from messagefoundry.store.store import MessageStore

    child_id = MessageStore._passthrough_message_id(rtd.id, "PT_NEXT", "MSH|child")
    child = await store.get_message(child_id)
    assert child is not None and child["status"] == MessageStatus.RECEIVED.value
    assert child["source_type"] == "passthrough" and child["raw"] == "MSH|child"
    meta = json.loads(child["metadata"])
    assert meta["correlation_id"] == mid and meta["correlation_depth"] == 1
    depth, _ = await store.pending_depth("PT_NEXT", stage=Stage.INGRESS.value)
    assert depth == 1
