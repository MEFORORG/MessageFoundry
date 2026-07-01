# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0058 — worker-level batch-claim cases (T5 byte-identity, T7 in-batch head-of-line) over SQLite.

These drive the RegistryRunner's router/transform workers directly (a controlled inbound + router +
handler) to prove:

* **T5 (N=1 byte-identity):** at ``fifo_claim_batch=1`` (default) the workers call ``claim_next_fifo``
  and **never** ``claim_next_fifo_batch`` — the batch method is dead code, the single-claim path is
  byte-identical.
* **T7 (in-batch head-of-line / FIFO order):** at ``fifo_claim_batch>1`` a backlog is drained by one
  batch claim, each row processed in strict FIFO order, one handoff per row — same outputs as N=1.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    OutboundConnection,
    Registry,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage
from messagefoundry.store.store import MessageStatus

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "batchw.db")
    yield s
    await s.close()


def _registry(outdir: Path) -> Registry:
    """An inbound 'IB' → router 'r' (routes to handler 'h') → handler 'h' (delivers to outbound 'OB')."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(outdir)}),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection("OB", ConnectionSpec(ConnectorType.FILE, {"directory": str(outdir)}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [])  # filtering handler is fine; we only assert routing/order
    return reg


# --- T5: N=1 byte-identity — the batch method is never invoked ---------------


async def test_t5_n1_uses_single_claim_never_batch(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg = _registry(tmp_path)
    runner = RegistryRunner(reg, store, fifo_claim_batch=1)  # default OFF

    single_calls = {"n": 0}
    batch_calls = {"n": 0}
    real_single = store.claim_next_fifo
    real_batch = store.claim_next_fifo_batch

    async def spy_single(*a, **k):  # type: ignore[no-untyped-def]
        single_calls["n"] += 1
        return await real_single(*a, **k)

    async def spy_batch(*a, **k):  # type: ignore[no-untyped-def]
        batch_calls["n"] += 1
        return await real_batch(*a, **k)

    monkeypatch.setattr(store, "claim_next_fifo", spy_single)
    monkeypatch.setattr(store, "claim_next_fifo_batch", spy_batch)

    # Land one ingress row and run the router worker through one claim+route.
    await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0)
    await _drain_router(runner, "IB", store)

    assert single_calls["n"] >= 1  # the single claim drove the route
    assert batch_calls["n"] == 0  # the batch method was NEVER invoked at N=1 (byte-identical)


# --- T7: batch mode drains a backlog in FIFO order, one handoff per row -------


async def test_t7_batch_mode_routes_backlog_in_order(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg = _registry(tmp_path)
    runner = RegistryRunner(reg, store, fifo_claim_batch=8)

    batch_calls = {"n": 0}
    real_batch = store.claim_next_fifo_batch

    async def spy_batch(*a, **k):  # type: ignore[no-untyped-def]
        batch_calls["n"] += 1
        return await real_batch(*a, **k)

    monkeypatch.setattr(store, "claim_next_fifo_batch", spy_batch)

    # Land 5 ingress rows; one batch claim should route all 5 in order.
    mids = []
    for i in range(5):
        mids.append(await store.enqueue_ingress(channel_id="IB", raw=RAW, now=100.0 + i))
    await _drain_router(runner, "IB", store)

    assert batch_calls["n"] >= 1  # the batch claim path drove routing
    # All 5 routed (each has a routed-stage row now), in order — the ingress lane is drained.
    assert await store.claim_next_fifo("IB", now=500.0, stage=Stage.INGRESS.value) is None
    for mid in mids:
        assert (await store.get_message(mid))["status"] == MessageStatus.ROUTED.value
    # The routed rows came out in FIFO order (handler 'h' rows, oldest-first).
    cur = await store._db.execute(
        "SELECT message_id FROM queue WHERE stage=? AND channel_id=? ORDER BY created_at, rowid",
        (Stage.ROUTED.value, "IB"),
    )
    routed_order = [r["message_id"] for r in await cur.fetchall()]
    assert routed_order == mids  # strict FIFO, no re-sort


async def _drain_router(runner: RegistryRunner, name: str, store: MessageStore) -> None:
    """Run the router worker until the ingress lane is empty, then signal stop so it returns. Drives the
    real claim → route_only → route_handoff path one batch at a time."""
    import asyncio

    task = asyncio.ensure_future(runner._router_worker(name))
    try:
        # Poll until the ingress lane is drained (no PENDING ingress rows for this channel).
        for _ in range(200):
            cur = await store._db.execute(
                "SELECT COUNT(*) AS c FROM queue WHERE stage=? AND channel_id=? AND status=?",
                (Stage.INGRESS.value, name, "pending"),
            )
            row = await cur.fetchone()
            if row["c"] == 0:
                break
            await asyncio.sleep(0.01)
    finally:
        runner._stop.set()
        runner._ingress_work.set()
        try:
            await asyncio.wait_for(task, timeout=2.0)
        except (TimeoutError, asyncio.CancelledError):
            task.cancel()
