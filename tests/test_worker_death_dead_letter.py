# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A row that kills its stage worker every time it is processed is dead-lettered (vault BACKLOG
#4607 step 6; owner ruling 2026-11-04, "Yes, dead-letter it").

A ``BaseException`` that is not an ``Exception`` passes every worker loop's ``except Exception``
and ends the worker. Before this, nothing counted it: the row stayed in flight, came back at the
next start with the same content, and killed the next worker too. The count is the row's
``attempts``, which the claim raises and a death never lowers, so it survives the worker's death,
a respawn and a restart. Both claim modes reach the same per-item bodies: the per_lane loops call
``_process_*_item`` and the pooled dispatcher calls the ``_dispatch_*`` adapters around them."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _kills_the_worker
from messagefoundry.store import MessageStore, OutboxItem, Stage
from messagefoundry.store.store import MessageStatus

FAR = time.time() + 10_000.0  # a claim clock past every backoff these tests write


class _Kill(BaseException):
    """Not an ``Exception``: what ends a stage worker rather than taking its fault arm."""


def _hl7(control_id: str) -> str:
    return f"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|{control_id}|P|2.5.1\r"


def _registry(tmp_path: Path, *, router: Any = None, handler: Any = None) -> Registry:
    """IB -> r -> h -> OB. The file directories exist so a started runner can bind them."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir(exist_ok=True)
    outdir.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 5.0},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection("OB", ConnectionSpec(ConnectorType.FILE, {"directory": str(outdir)}))
    )
    reg.add_router("r", router or (lambda m: ["h"]))
    reg.add_handler("h", handler or (lambda m: Send("OB", m)))
    return reg


def _runner(reg: Registry, store: MessageStore, claim_mode: str) -> RegistryRunner:
    return RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        claim_mode=claim_mode,
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
    )


def _kill_on(control_id: str, calls: list[str] | None = None) -> Callable[[Message], list[str]]:
    def router(m: Message) -> list[str]:
        if calls is not None:
            calls.append(m.control_id or "")
        if m.control_id == control_id:
            raise _Kill
        return ["h"]

    return router


Drive = Callable[[str, OutboxItem], Awaitable[Any]]


def _driver(runner: RegistryRunner, claim_mode: str, stage: str) -> Drive:
    """The per_lane loops call the per-item body; the pooled dispatcher calls the adapter around it."""
    attr = f"_process_{stage}_item" if claim_mode == "per_lane" else f"_dispatch_{stage}"
    return getattr(runner, attr)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "death.db")
    yield s
    await s.close()


async def _row(store: MessageStore, mid: str, stage: Stage) -> tuple[str, int]:
    cur = await store._db.execute(
        "SELECT status, attempts FROM queue WHERE message_id=? AND stage=?", (mid, stage.value)
    )
    row = await cur.fetchone()
    assert row is not None
    return str(row["status"]), int(row["attempts"])


async def _status(store: MessageStore, mid: str) -> str:
    fetched = await store.get_message(mid)
    assert fetched is not None
    return str(fetched["status"])


async def _claim(store: MessageStore, lane: str, stage: Stage, now: float = FAR) -> OutboxItem:
    item = await store.claim_next_fifo(lane, now, stage=stage.value)
    assert item is not None
    return item


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_row_that_kills_the_router_worker_every_time_is_dead_lettered(
    tmp_path: Path, store: MessageStore, claim_mode: str
) -> None:
    runner = _runner(_registry(tmp_path, router=_kill_on("KILL")), store, claim_mode)
    drive = _driver(runner, claim_mode, "ingress")
    killer = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
    after = await store.enqueue_ingress(channel_id="IB", raw=_hl7("OK"))

    for attempt in range(1, wiring_runner._WORKER_DEATH_LIMIT):
        item = await _claim(store, "IB", Stage.INGRESS)
        assert item.message_id == killer  # nothing overtook the killer
        with pytest.raises(_Kill):
            await drive("IB", item)
        assert await _row(store, killer, Stage.INGRESS) == ("pending", attempt)
        # The re-pended head still holds its lane: a claim before its backoff takes no row.
        assert await store.claim_next_fifo("IB", time.time(), stage=Stage.INGRESS.value) is None
        assert await _status(store, after) == MessageStatus.RECEIVED.value

    item = await _claim(store, "IB", Stage.INGRESS)
    assert item.message_id == killer
    with pytest.raises(_Kill):  # the death still goes on; respawning is #4607 steps 1, 2 and 5
        await drive("IB", item)
    assert await _row(store, killer, Stage.INGRESS) == ("dead", wiring_runner._WORKER_DEATH_LIMIT)
    assert await _status(store, killer) == MessageStatus.ERROR.value

    # The next row is the one after it, untouched by the dead-lettering, and it routes.
    item = await _claim(store, "IB", Stage.INGRESS)
    assert item.message_id == after and item.attempts == 1
    await drive("IB", item)
    assert await _status(store, after) == MessageStatus.ROUTED.value


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_single_death_then_a_clean_pass_is_not_dead_lettered(
    tmp_path: Path, store: MessageStore, claim_mode: str
) -> None:
    deaths = {"n": 0}

    def router(m: Message) -> list[str]:
        if deaths["n"] == 0:
            deaths["n"] += 1
            raise _Kill
        return ["h"]

    runner = _runner(_registry(tmp_path, router=router), store, claim_mode)
    drive = _driver(runner, claim_mode, "ingress")
    mid = await store.enqueue_ingress(channel_id="IB", raw=_hl7("ONCE"))

    with pytest.raises(_Kill):
        await drive("IB", await _claim(store, "IB", Stage.INGRESS))
    assert await _row(store, mid, Stage.INGRESS) == ("pending", 1)

    await drive("IB", await _claim(store, "IB", Stage.INGRESS))
    assert await _status(store, mid) == MessageStatus.ROUTED.value
    cur = await store._db.execute("SELECT COUNT(*) AS c FROM queue WHERE status='dead'")
    fetched = await cur.fetchone()
    assert fetched is not None and fetched["c"] == 0


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_row_that_kills_the_transform_worker_every_time_is_dead_lettered(
    tmp_path: Path, store: MessageStore, claim_mode: str
) -> None:
    def handler(m: Message) -> Any:
        raise _Kill

    runner = _runner(_registry(tmp_path, handler=handler), store, claim_mode)
    drive = _driver(runner, claim_mode, "routed")
    mid = await store.enqueue_ingress(channel_id="IB", raw=_hl7("XFORM"))
    await runner._process_ingress_item("IB", await _claim(store, "IB", Stage.INGRESS))

    for attempt in range(1, wiring_runner._WORKER_DEATH_LIMIT + 1):
        with pytest.raises(_Kill):
            await drive("IB", await _claim(store, "IB", Stage.ROUTED))
        expected = "dead" if attempt == wiring_runner._WORKER_DEATH_LIMIT else "pending"
        assert await _row(store, mid, Stage.ROUTED) == (expected, attempt)
    assert await _status(store, mid) == MessageStatus.ERROR.value


class _KillingConnector:
    async def send(self, payload: str) -> None:
        raise _Kill

    async def aclose(self) -> None:
        return None


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_delivery_death_is_a_failed_attempt_under_the_lanes_retry_policy(
    tmp_path: Path, store: MessageStore, claim_mode: str
) -> None:
    """An outbound row's ``attempts`` already counts its failed sends, so a death there is one more
    failed attempt and the lane's own ``max_attempts`` dead-letters it."""
    runner = _runner(_registry(tmp_path), store, claim_mode)
    runner._retry["OB"] = RetryPolicy(max_attempts=2, backoff_seconds=0.01)
    runner._destinations["OB"] = _KillingConnector()  # type: ignore[assignment]
    drive = _driver(runner, claim_mode, "delivery")
    mid = await store.enqueue_ingress(channel_id="IB", raw=_hl7("SEND"))
    await runner._process_ingress_item("IB", await _claim(store, "IB", Stage.INGRESS))
    routed = await store.claim_next_fifo("IB", FAR, stage=Stage.ROUTED.value)
    if routed is not None:  # the inline fast path may have transformed at ingress already
        await runner._process_routed_item("IB", routed)

    with pytest.raises(_Kill):
        await drive("OB", await _claim(store, "OB", Stage.OUTBOUND))
    assert await _row(store, mid, Stage.OUTBOUND) == ("pending", 1)
    with pytest.raises(_Kill):
        await drive("OB", await _claim(store, "OB", Stage.OUTBOUND))
    assert await _row(store, mid, Stage.OUTBOUND) == ("dead", 2)
    assert await _status(store, mid) == MessageStatus.ERROR.value


async def test_a_store_fault_while_counting_leaves_the_row_in_flight_and_the_death_raised(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(_registry(tmp_path, router=_kill_on("KILL")), store, "per_lane")
    mid = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))

    async def broken(*a: Any, **k: Any) -> Any:
        raise RuntimeError("store down")

    monkeypatch.setattr(store, "mark_failed", broken)
    with pytest.raises(_Kill):  # the store fault never replaces the death
        await runner._process_ingress_item("IB", await _claim(store, "IB", Stage.INGRESS))
    assert await _row(store, mid, Stage.INGRESS) == ("inflight", 1)


@pytest.mark.parametrize(
    ("exc", "counted"),
    [
        (_Kill(), True),
        (KeyboardInterrupt(), True),
        (SystemExit(0), True),
        (ValueError("an ordinary fault"), False),
        (asyncio.CancelledError(), False),
        (GeneratorExit(), False),
    ],
)
def test_only_a_death_is_counted(exc: BaseException, counted: bool) -> None:
    """Cancellation is a stop or a teardown, and a closed coroutine cannot await the write; an
    ``Exception`` already takes the worker's own fault arm."""
    assert _kills_the_worker(exc) is counted


async def test_a_live_per_lane_worker_dead_letters_the_killer_and_drains_the_lane_in_order(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end in per_lane mode: the router worker dies on the killer each pass, its supervisor
    respawns it, the re-pend's wake re-drives the row, and the third death dead-letters it with no
    restart. The next message is routed only after that, so nothing overtook the killer."""
    monkeypatch.setattr(
        wiring_runner,
        "_WORKER_DEATH_RETRY",
        RetryPolicy(max_attempts=wiring_runner._WORKER_DEATH_LIMIT, backoff_seconds=0.01),
    )
    calls: list[str] = []
    killer = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
    after = await store.enqueue_ingress(channel_id="IB", raw=_hl7("OK"))
    runner = _runner(_registry(tmp_path, router=_kill_on("KILL", calls)), store, "per_lane")
    await runner.start()
    try:
        deadline = time.monotonic() + 10.0
        while await _status(store, after) == MessageStatus.RECEIVED.value:
            assert time.monotonic() < deadline, calls
            await asyncio.sleep(0.02)
        assert calls[: wiring_runner._WORKER_DEATH_LIMIT + 1] == ["KILL"] * 3 + ["OK"]
        assert await _status(store, killer) == MessageStatus.ERROR.value
        assert await _row(store, killer, Stage.INGRESS) == ("dead", 3)
    finally:
        await runner.stop()
