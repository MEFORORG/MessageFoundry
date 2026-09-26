# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0157 Inc 2 / BACKLOG #1497: a per-lane worker that STOPS mid-batch no longer strands its tail.

Two layers. The worker releases its own tail as it returns (``_release_tail_on_stop``), and a
reload re-pends whatever a RETURNED worker still left in flight
(``RegistryRunner._recover_stopped_worker_residue``), never touching a lane whose worker is live.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import InternalErrorPolicy, OrderingMode, RetryPolicy
from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    Registry,
)
from messagefoundry.pipeline.cluster import NullCoordinator
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _ItemOutcome
from messagefoundry.store import MessageStatus, MessageStore, Stage
from tests.test_ownership_scoped_reset import (
    _row_status,
    _seed_inflight_ingress,
    _seed_inflight_outbound,
)

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "inc2.db")
    yield s
    await s.close()


async def _inflight_ingress(store: MessageStore, channel: str) -> list[str]:
    cur = await store._db.execute(
        "SELECT id FROM queue WHERE stage='ingress' AND channel_id=? AND status='inflight'",
        (channel,),
    )
    return [str(r["id"]) for r in await cur.fetchall()]


async def _wait_until(pred: Callable[[], Awaitable[bool]], timeout: float = 5.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if await pred():
            return True
        await asyncio.sleep(0.02)
    return await pred()


async def _done(task: asyncio.Task[None] | None) -> bool:
    return task is not None and task.done()


async def _returned_task() -> asyncio.Task[None]:
    task = asyncio.create_task(asyncio.sleep(0))
    await task
    return task


def _route_h(m: object) -> list[str]:
    return ["h"]


def _registry(
    inbox: Path,
    route: Callable[..., list[str]] = _route_h,
    names: tuple[str, ...] = ("IB", "IB_LIVE"),
    handler: Callable[..., list[object]] = lambda m: [],
) -> Registry:
    """Inbounds on one router: IB (the lane under test) and IB_LIVE (the live-worker control)."""
    reg = Registry()
    for name in names:
        d = inbox / name
        d.mkdir(parents=True, exist_ok=True)
        reg.add_inbound(
            InboundConnection(
                name,
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(d), "pattern": "*.hl7", "poll_seconds": 0.05},
                ),
                router="r",
            )
        )
    reg.add_router("r", route)
    reg.add_handler("h", handler)  # the default filters: most tests are about ingress only
    return reg


async def _halt_ib_under_stop(
    store: MessageStore, tmp_path: Path
) -> tuple[RegistryRunner, dict[str, bool], list[str]]:
    """Start a runner whose router raises on IB. Under the STOP policy IB's router worker takes all
    three seeded rows in one batch, fails the head and returns. Returns the runner, the poison
    switch and the three message ids."""
    poisoned = {"on": True}

    def route(m: object) -> list[str]:
        if poisoned["on"]:
            raise RuntimeError("router content fault")
        return ["h"]

    mids = [await store.enqueue_ingress(channel_id="IB", raw=RAW) for _ in range(3)]
    runner = RegistryRunner(
        _registry(tmp_path / "in", route),
        store,
        claim_mode="per_lane",
        fifo_claim_batch=4,
        poll_interval=0.02,
        internal_error_default=InternalErrorPolicy.STOP,
        delivery_defaults=RetryPolicy(max_attempts=None, backoff_seconds=0.01),
    )
    await runner.start()
    assert await _wait_until(lambda: _done(runner._router_workers.get("IB"))), (
        "IB's router worker never halted under the STOP policy"
    )
    return runner, poisoned, mids


async def _ib_drained(store: MessageStore, mids: list[str]) -> bool:
    for mid in mids:
        msg = await store.get_message(mid)
        if msg is None or msg["status"] == MessageStatus.RECEIVED.value:
            return False
    return True


async def test_a_stopping_worker_releases_its_tail(store: MessageStore, tmp_path: Path) -> None:
    """Layer 1. The halt leaves nothing INFLIGHT, with no reload, and an operator-style re-arm (the
    door that re-arms the worker without a reload) drains all three in order."""
    runner, poisoned, mids = await _halt_ib_under_stop(store, tmp_path)
    try:
        assert await _inflight_ingress(store, "IB") == []
        poisoned["on"] = False
        await runner.restart_inbound("IB")
        assert await _wait_until(lambda: _ib_drained(store, mids)), await _inflight_ingress(
            store, "IB"
        )
    finally:
        await runner.stop()


async def test_reload_recovers_a_tail_the_stopping_worker_failed_to_release(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Layer 2, end to end on the real reload. The worker's own release fails, so the tail stays
    INFLIGHT; the operator fixes the router and reloads, as the STOP log line tells them to, and
    every IB message then leaves ingress. The controls: a row on a LIVE worker's lane and a row on
    a lane no registry names must both stay INFLIGHT."""
    real_release = store.release_claimed

    async def failing_release(*a: object, **k: object) -> None:
        raise RuntimeError("store blip on release")

    monkeypatch.setattr(store, "release_claimed", failing_release)
    # Claimed before any worker exists, so each stands for a row held mid-send by its lane's owner.
    live_row = await _seed_inflight_ingress(store, "IB_LIVE")
    sibling_row = await _seed_inflight_ingress(store, "SIBLING")
    runner, poisoned, mids = await _halt_ib_under_stop(store, tmp_path)
    try:
        assert len(await _inflight_ingress(store, "IB")) == 2  # the precondition: stranded
        assert not runner._router_workers["IB_LIVE"].done()
        monkeypatch.setattr(store, "release_claimed", real_release)

        poisoned["on"] = False
        await runner.reload(runner.registry)

        assert await _wait_until(lambda: _ib_drained(store, mids)), await _inflight_ingress(
            store, "IB"
        )
        assert await _row_status(store, live_row) == "inflight"
        assert await _row_status(store, sibling_row) == "inflight"
    finally:
        await runner.stop()


async def test_a_worker_whose_inbound_was_removed_releases_its_tail(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other way a worker returns mid-batch: a reload removed its inbound. It re-pends the head
    and exits, and the tail must be PENDING at once, not INFLIGHT until a restart. (ADR 0157 first
    scoped reload recovery to the OLD registry's names; the reload that restores IB would not have
    had IB in it.)"""
    batch_sizes: list[int] = []
    real_batch = store.claim_next_fifo_batch

    async def spy_batch(*a: Any, **k: Any) -> Any:
        got = await real_batch(*a, **k)
        if a and a[0] == "IB":
            batch_sizes.append(len(got))
        return got

    monkeypatch.setattr(store, "claim_next_fifo_batch", spy_batch)
    runner = RegistryRunner(
        _registry(tmp_path / "in"),
        store,
        claim_mode="per_lane",
        fifo_claim_batch=4,
        # Long, so the idle worker cannot poll between the enqueues below and claim them one at a
        # time; it wakes once, on the explicit set, and takes all three in one batch.
        poll_interval=30.0,
    )
    await runner.start()
    try:
        await runner.reload(_registry(tmp_path / "in", names=("IB_LIVE",)))
        await asyncio.sleep(0.05)  # let the reload's own wake be consumed by an empty claim
        for _ in range(3):
            await store.enqueue_ingress(channel_id="IB", raw=RAW)
        runner._ingress_work.set()
        assert await _wait_until(lambda: _done(runner._router_workers.get("IB")))
        # The precondition: one claim took all three, so there WAS a tail to release.
        assert 3 in batch_sizes, batch_sizes
        cur = await store._db.execute(
            "SELECT status, COUNT(*) AS n FROM queue WHERE stage='ingress' AND channel_id='IB'"
            " GROUP BY status"
        )
        assert {r["status"]: r["n"] for r in await cur.fetchall()} == {"pending": 3}
    finally:
        await runner.stop()


async def _seed_pending_routed(
    store: MessageStore, channel: str, handler: str, n: int
) -> list[str]:
    """``n`` PENDING routed rows on ``channel`` (same direct insert as
    test_ownership_scoped_reset's ``_seed_inflight_routed``, without the claim)."""
    ids = []
    for i in range(n):
        mid = await store.enqueue_ingress(channel_id=f"{channel}_SRC", raw=RAW)
        rid = f"routed-{channel}-{i}"
        await store._db.execute(
            "INSERT INTO queue (id, message_id, stage, channel_id, destination_name, handler_name,"
            " payload, status, attempts, next_attempt_at, created_at, updated_at)"
            " VALUES (?,?,?,?,NULL,?,?,'pending',0,0.0,?,?)",
            (rid, mid, Stage.ROUTED.value, channel, handler, store._cipher.encrypt(RAW), i, i),
        )
        await store._db.commit()
        ids.append(rid)
    return ids


async def test_a_stopping_transform_worker_releases_its_tail(
    store: MessageStore, tmp_path: Path
) -> None:
    """The transform worker's STOP path, driven directly: the handler raises on the first of three
    batch-claimed routed rows, the STOP policy fails that head, and the worker returns. The other
    two must be PENDING, and their claim's ``attempts`` increment undone."""

    def boom(m: object) -> list[object]:
        raise RuntimeError("handler content fault")

    reg = _registry(tmp_path / "in", names=("IB",), handler=boom)
    runner = RegistryRunner(
        reg,
        store,
        claim_mode="per_lane",
        fifo_claim_batch=4,
        internal_error_default=InternalErrorPolicy.STOP,
    )
    ids = await _seed_pending_routed(store, "IB", "h", 3)
    await asyncio.wait_for(runner._transform_worker("IB"), 5.0)

    cur = await store._db.execute(
        "SELECT id, status, attempts FROM queue WHERE stage='routed' AND channel_id='IB'"
    )
    got = {r["id"]: (r["status"], r["attempts"]) for r in await cur.fetchall()}
    assert got[ids[1]] == ("pending", 0) and got[ids[2]] == ("pending", 0), got


async def test_only_a_worker_that_returned_has_its_lane_recovered(
    store: MessageStore,
) -> None:
    """The backstop's scope, one worker state per lane, on the inbound router map and the outbound
    delivery map. Only a normal RETURN recovers its lane:

    * alive -- its rows may be mid-send; re-pending them is a duplicate and a FIFO break;
    * raised -- its done-callback respawns it, so a new worker may be claiming on that lane;
    * cancelled -- only teardown cancels, and teardown recovers at the next start.
    """
    park = asyncio.Event()

    async def _raises() -> None:
        raise RuntimeError("boom")

    async def _parks() -> None:
        await park.wait()

    async def _tasks() -> dict[str, asyncio.Task[None]]:
        tasks = {
            "RAISE": asyncio.create_task(_raises()),
            "LIVE": asyncio.create_task(_parks()),
            "CANCEL": asyncio.create_task(_parks()),
        }
        tasks["CANCEL"].cancel()
        await asyncio.gather(tasks["RAISE"], tasks["CANCEL"], return_exceptions=True)
        return {"RET": await _returned_task(), **tasks}

    runner = RegistryRunner(Registry(), store, claim_mode="per_lane")
    router, delivery = await _tasks(), await _tasks()
    runner._router_workers.update({f"IB_{k}": t for k, t in router.items()})
    runner._workers.update({f"OB_{k}": t for k, t in delivery.items()})
    rows = {f"IB_{k}": await _seed_inflight_ingress(store, f"IB_{k}") for k in router}
    rows |= {f"OB_{k}": await _seed_inflight_outbound(store, "IB_ANY", f"OB_{k}") for k in delivery}

    try:
        recovered = await runner._recover_stopped_worker_residue()
        got = {lane: await _row_status(store, rid) for lane, rid in rows.items()}
        assert got == {
            "IB_RET": "pending",
            "IB_RAISE": "inflight",
            "IB_LIVE": "inflight",
            "IB_CANCEL": "inflight",
            "OB_RET": "pending",
            "OB_RAISE": "inflight",
            "OB_LIVE": "inflight",
            "OB_CANCEL": "inflight",
        }
        assert recovered == 2
    finally:
        park.set()
        await asyncio.gather(router["LIVE"], delivery["LIVE"])


async def test_a_lane_the_outbound_dispatcher_holds_is_not_touched(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pooled mode keeps UNORDERED outbound lanes on a worker (ADR 0066 D4). If the OUTBOUND
    dispatcher nonetheless holds a lane whose worker has returned -- the partition bug
    ``_spawn_worker`` refuses on -- the dispatcher may be the one holding those rows, so the
    backstop leaves the lane alone."""

    class _HoldingDispatcher:
        def phase(self, name: str) -> str | None:
            return "processing" if name == "OB_HELD" else None

    runner = RegistryRunner(Registry(), store, claim_mode="per_lane")
    runner._workers.update({"OB_HELD": await _returned_task(), "OB_FREE": await _returned_task()})
    monkeypatch.setitem(runner._dispatchers, Stage.OUTBOUND, _HoldingDispatcher())  # type: ignore[arg-type]
    held_row = await _seed_inflight_outbound(store, "IB_ANY", "OB_HELD")
    free_row = await _seed_inflight_outbound(store, "IB_ANY", "OB_FREE")

    assert await runner._recover_stopped_worker_residue() == 1
    assert await _row_status(store, held_row) == "inflight"
    assert await _row_status(store, free_row) == "pending"


async def test_a_failed_backstop_does_not_fail_the_reload(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Best effort, like the #1611 re-pend: a store error in the backstop must not fail or roll back
    a routine reload. Driven through reload() itself, with a returned worker in scope so the reset
    is really attempted."""
    attempts: list[str | None] = []

    async def _boom(*a: object, stage: str | None = None, **k: object) -> int:
        attempts.append(stage)
        raise RuntimeError("store down")

    runner = RegistryRunner(
        _registry(tmp_path / "in", names=("IB",)), store, claim_mode="per_lane", poll_interval=30.0
    )
    await runner.start()
    try:
        runner._workers["OB_RET"] = await _returned_task()
        monkeypatch.setattr(store, "reset_stale_inflight", _boom)
        await runner.reload(_registry(tmp_path / "in", names=("IB",)))
        assert attempts == [Stage.OUTBOUND.value]  # the reset ran, and failed
        assert "IB" in runner._sources  # and intake came back up regardless
    finally:
        await runner.stop()


async def _seed_pending_outbound(store: MessageStore, dest: str, n: int) -> None:
    for _ in range(n):
        await store.enqueue_message(channel_id="IB_ANY", raw=RAW, deliveries=[(dest, RAW)])


def _stop_on_first_item(
    store: MessageStore,
) -> Callable[..., Awaitable[tuple[_ItemOutcome, float | None]]]:
    """A delivery body that resolves the head and returns STOPPED, as every STOPPED path does."""

    async def fake(name: str, item: Any) -> tuple[_ItemOutcome, float | None]:
        await store.mark_failed(item.id, "stop", RetryPolicy(max_attempts=None))
        return _ItemOutcome.STOPPED, None

    return fake


async def _outbound_rows(store: MessageStore, dest: str) -> list[tuple[str, int]]:
    cur = await store._db.execute(
        "SELECT status, attempts FROM queue WHERE stage='outbound' AND destination_name=?"
        " ORDER BY rowid",
        (dest,),
    )
    return [(str(r["status"]), int(r["attempts"])) for r in await cur.fetchall()]


async def test_a_stopping_delivery_worker_releases_its_unordered_tail(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The delivery worker's STOP path on an UNORDERED lane, whose claim_ready batch is the only
    delivery claim with a multi-row tail. The head is failed by the body; the two rows behind it
    must come back PENDING with the claim's ``attempts`` increment undone."""
    runner = RegistryRunner(
        Registry(), store, claim_mode="per_lane", ordering_default=OrderingMode.UNORDERED
    )
    await _seed_pending_outbound(store, "OB", 3)
    monkeypatch.setattr(runner, "_process_delivery_item", _stop_on_first_item(store))
    await asyncio.wait_for(runner._delivery_worker("OB"), 5.0)

    rows = await _outbound_rows(store, "OB")
    assert rows.count(("pending", 0)) == 2, rows
    assert all(status != "inflight" for status, _ in rows), rows


class _Follower(NullCoordinator):
    def is_leader(self) -> bool:
        return False


async def test_a_node_that_is_not_leader_releases_and_resets_nothing(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both layers stand down off the leader. An ex-leader's rows belong to the successor's
    promotion recovery, which may already have re-claimed them, and both writes are unfenced."""
    runner = RegistryRunner(
        Registry(),
        store,
        claim_mode="per_lane",
        ordering_default=OrderingMode.UNORDERED,
        coordinator=_Follower(),
    )
    await _seed_pending_outbound(store, "OB", 3)
    monkeypatch.setattr(runner, "_process_delivery_item", _stop_on_first_item(store))
    await asyncio.wait_for(runner._delivery_worker("OB"), 5.0)
    assert [s for s, _ in await _outbound_rows(store, "OB")].count("inflight") == 2

    runner._workers["OB"] = await _returned_task()
    assert await runner._recover_stopped_worker_residue() == 0
    assert [s for s, _ in await _outbound_rows(store, "OB")].count("inflight") == 2
