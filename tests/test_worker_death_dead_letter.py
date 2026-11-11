# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A row that kills its stage worker every time it is processed is dead-lettered (vault BACKLOG
#4607 step 6; owner ruling 2026-11-04, "Yes, dead-letter it").

A ``BaseException`` that is not an ``Exception`` passes every worker loop's ``except Exception``
and ends the worker. Before this nothing counted it: the row stayed in flight, came back at the
next start with the same content and killed the next worker too. An ingress, routed or response
row now counts each death in its own ``worker_deaths`` column, which no claim raises and no
release or ``reset_stale_inflight`` lowers, so a batch tail claimed beside the dying row is never
counted. An outbound row counts the death as a failed send under the lane's own retry policy
(owner ruling 2026-11-11). ``KeyboardInterrupt``, ``SystemExit``, ``CancelledError`` and
``GeneratorExit`` are never counted. Both claim modes reach the same per-item bodies: the per_lane
loops call ``_process_*_item`` and the pooled dispatcher calls the ``_dispatch_*`` adapters."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from collections.abc import Awaitable, Callable, Coroutine
from pathlib import Path
from typing import Any, cast

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
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    _kills_the_worker,
    _records_worker_death,
)
from messagefoundry.store import MessageStore, OutboxItem, OutboxStatus, Stage
from messagefoundry.store.store import MessageStatus
from tests._store_audit import no_operator_audit

FAR = time.time() + 10_000.0  # a claim clock past every backoff these tests write
LIMIT = wiring_runner._WORKER_DEATH_LIMIT


class _Kill(BaseException):
    """Not an ``Exception``, and none of the four the owner ruled out: what kills a stage worker."""


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


async def _row(store: MessageStore, mid: str, stage: Stage) -> tuple[str, int, int]:
    """``(status, attempts, worker_deaths)`` of the message's row at ``stage``."""
    cur = await store._db.execute(
        "SELECT status, attempts, worker_deaths FROM queue WHERE message_id=? AND stage=?",
        (mid, stage.value),
    )
    row = await cur.fetchone()
    assert row is not None
    return str(row["status"]), int(row["attempts"]), int(row["worker_deaths"])


async def _status(store: MessageStore, mid: str) -> str:
    fetched = await store.get_message(mid)
    assert fetched is not None
    return str(fetched["status"])


async def _claim(store: MessageStore, lane: str, stage: Stage, now: float = FAR) -> OutboxItem:
    item = await store.claim_next_fifo(lane, now, stage=stage.value)
    assert item is not None
    return item


async def _restart(store: MessageStore) -> None:
    """The next start's recovery: what brings a dead worker's in-flight row back (#4607 steps 1,
    2 and 5 would do it without a restart)."""
    await store.reset_stale_inflight()


def _spy_stopped(runner: RegistryRunner, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    stopped: list[str] = []
    monkeypatch.setattr(
        runner._alert_sink, "connection_stopped", lambda name, *, detail: stopped.append(name)
    )
    return stopped


async def _dead_rows(store: MessageStore) -> int:
    cur = await store._db.execute("SELECT COUNT(*) AS c FROM queue WHERE status='dead'")
    fetched = await cur.fetchone()
    assert fetched is not None
    return int(fetched["c"])


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_row_that_kills_the_router_worker_every_time_is_dead_lettered(
    tmp_path: Path, store: MessageStore, claim_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(_registry(tmp_path, router=_kill_on("KILL")), store, claim_mode)
    stopped = _spy_stopped(runner, monkeypatch)
    drive = _driver(runner, claim_mode, "ingress")
    killer = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
    after = await store.enqueue_ingress(channel_id="IB", raw=_hl7("OK"))

    for death in range(1, LIMIT + 1):
        item = await _claim(store, "IB", Stage.INGRESS)
        assert item.message_id == killer  # back at its lane position after each restart
        with pytest.raises(_Kill):  # the death still goes on; respawning is #4607 steps 1, 2, 5
            await drive("IB", item)
        if death < LIMIT:
            # Below the cap only the count is written: the row is in flight, as the death left it.
            assert await _row(store, killer, Stage.INGRESS) == ("inflight", death, death)
            await _restart(store)
    assert await _row(store, killer, Stage.INGRESS) == ("dead", LIMIT, LIMIT)
    assert await _status(store, killer) == MessageStatus.ERROR.value
    # A pooled serializer is not respawned, so each death pages the lane it leaves stopped.
    assert stopped == (["IB"] * LIMIT if claim_mode == "pooled" else [])

    # The next row is the one after it, untouched by the dead-lettering, and it routes.
    assert await _status(store, after) == MessageStatus.RECEIVED.value
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
    assert await _row(store, mid, Stage.INGRESS) == ("inflight", 1, 1)
    await _restart(store)

    await drive("IB", await _claim(store, "IB", Stage.INGRESS))
    assert await _status(store, mid) == MessageStatus.ROUTED.value
    assert await _dead_rows(store) == 0


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

    for death in range(1, LIMIT + 1):
        with pytest.raises(_Kill):
            await drive("IB", await _claim(store, "IB", Stage.ROUTED))
        assert await _row(store, mid, Stage.ROUTED) == (
            "dead" if death == LIMIT else "inflight",
            death,
            death,
        )
        await _restart(store)
    assert await _status(store, mid) == MessageStatus.ERROR.value


async def test_a_batch_tail_claimed_beside_a_dying_row_is_not_counted(
    tmp_path: Path, store: MessageStore
) -> None:
    """Finding (A) of the earlier cut: a batch claim raises ``attempts`` on every row it takes, so a
    count kept there let an innocent tail inherit the killer's deaths. ``worker_deaths`` is raised
    for the dying row alone. The tail's ``attempts`` reaching the cap shows what the old count
    would have done to it."""
    runner = _runner(_registry(tmp_path, router=_kill_on("KILL")), store, "per_lane")
    killer = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
    tail = await store.enqueue_ingress(channel_id="IB", raw=_hl7("TAIL"))

    for death in range(1, LIMIT + 1):
        batch = await store.claim_next_fifo_batch("IB", FAR, stage=Stage.INGRESS.value, limit=2)
        assert [i.message_id for i in batch] == [killer, tail]
        with pytest.raises(_Kill):
            await runner._process_ingress_item("IB", batch[0])
        assert await _row(store, tail, Stage.INGRESS) == ("inflight", death, 0)
        await _restart(store)
    assert (await _row(store, killer, Stage.INGRESS))[0] == "dead"
    assert await _row(store, tail, Stage.INGRESS) == ("pending", LIMIT, 0)

    item = await _claim(store, "IB", Stage.INGRESS)
    assert item.message_id == tail
    await runner._process_ingress_item("IB", item)
    assert await _status(store, tail) == MessageStatus.ROUTED.value


async def test_the_count_survives_recovery_and_a_claim_never_raises_it(
    store: MessageStore,
) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=_hl7("SURVIVE"))
    item = await _claim(store, "IB", Stage.INGRESS)
    counted = await store.record_worker_death(item.id, LIMIT, "router worker killed by _Kill")
    assert (counted.deaths, counted.dead) == (1, False)
    await store.reset_stale_inflight()
    assert await _row(store, mid, Stage.INGRESS) == ("pending", 1, 1)
    await _claim(store, "IB", Stage.INGRESS)
    assert await _row(store, mid, Stage.INGRESS) == ("inflight", 2, 1)


async def test_a_row_not_in_flight_is_not_counted(store: MessageStore) -> None:
    mid = await store.enqueue_ingress(channel_id="IB", raw=_hl7("PENDING"))
    cur = await store._db.execute("SELECT id FROM queue WHERE message_id=?", (mid,))
    fetched = await cur.fetchone()
    assert fetched is not None
    counted = await store.record_worker_death(str(fetched["id"]), 1, "router worker killed")
    assert (counted.deaths, counted.dead) == (0, False)
    assert await _row(store, mid, Stage.INGRESS) == ("pending", 0, 0)


async def test_a_replay_resets_the_count_with_attempts(store: MessageStore) -> None:
    """An operator's replay gives the row a fresh budget, as it does ``attempts``."""
    mid = await store.enqueue_ingress(channel_id="IB", raw=_hl7("REPLAY"))
    for _ in range(LIMIT):
        item = await _claim(store, "IB", Stage.INGRESS)
        await store.record_worker_death(item.id, LIMIT, "router worker killed by _Kill")
        await store.reset_stale_inflight()
    assert await _row(store, mid, Stage.INGRESS) == ("dead", LIMIT, LIMIT)
    assert await store.replay(mid, audit=no_operator_audit) == 1
    assert await _row(store, mid, Stage.INGRESS) == ("pending", 0, 0)


class _KillingConnector:
    async def send(self, payload: str) -> None:
        raise _Kill

    async def aclose(self) -> None:
        return None


async def _to_outbound(runner: RegistryRunner, store: MessageStore, raw: str) -> str:
    mid = await store.enqueue_ingress(channel_id="IB", raw=raw)
    await runner._process_ingress_item("IB", await _claim(store, "IB", Stage.INGRESS))
    routed = await store.claim_next_fifo("IB", FAR, stage=Stage.ROUTED.value)
    if routed is not None:  # the inline fast path may have transformed at ingress already
        await runner._process_routed_item("IB", routed)
    return mid


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_delivery_death_is_capped_by_the_lanes_retry_policy(
    tmp_path: Path, store: MessageStore, claim_mode: str
) -> None:
    """An outbound death counts as a failed send under the lane's own policy (owner ruling
    2026-11-11): its count is ``attempts``, and its cap the lane's ``max_attempts``."""
    runner = _runner(_registry(tmp_path), store, claim_mode)
    runner._retry["OB"] = RetryPolicy(max_attempts=2, backoff_seconds=0.01)
    runner._destinations["OB"] = _KillingConnector()  # type: ignore[assignment]
    drive = _driver(runner, claim_mode, "delivery")
    mid = await _to_outbound(runner, store, _hl7("SEND"))

    with pytest.raises(_Kill):
        await drive("OB", await _claim(store, "OB", Stage.OUTBOUND))
    assert await _row(store, mid, Stage.OUTBOUND) == ("inflight", 1, 0)
    await _restart(store)
    with pytest.raises(_Kill):
        await drive("OB", await _claim(store, "OB", Stage.OUTBOUND))
    assert await _row(store, mid, Stage.OUTBOUND) == ("dead", 2, 0)
    assert await _status(store, mid) == MessageStatus.ERROR.value


async def test_a_retry_forever_lane_never_dead_letters_on_a_death(
    tmp_path: Path, store: MessageStore
) -> None:
    runner = _runner(_registry(tmp_path), store, "per_lane")
    runner._retry["OB"] = RetryPolicy(max_attempts=None)
    runner._destinations["OB"] = _KillingConnector()  # type: ignore[assignment]
    mid = await _to_outbound(runner, store, _hl7("FOREVER"))
    for death in range(1, LIMIT + 2):
        with pytest.raises(_Kill):
            await runner._process_delivery_item("OB", await _claim(store, "OB", Stage.OUTBOUND))
        assert await _row(store, mid, Stage.OUTBOUND) == ("inflight", death, 0)
        await _restart(store)


async def test_a_death_after_the_send_was_marked_done_leaves_it_done(
    tmp_path: Path, store: MessageStore
) -> None:
    """Finding (B) of the earlier cut: at the cap ``mark_failed``'s DEAD branch had no status term,
    so a death after ``mark_done`` turned a delivered row DEAD and its message ERROR."""
    runner = _runner(_registry(tmp_path), store, "per_lane")
    runner._retry["OB"] = RetryPolicy(max_attempts=1)
    mid = await store.enqueue_message(channel_id="IB", raw=_hl7("DONE"), deliveries=[("OB", "p")])
    item = await _claim(store, "OB", Stage.OUTBOUND)
    assert await store.mark_done(item.id)
    await runner._record_worker_death("delivery", "OB", item, _Kill())
    assert (await _row(store, mid, Stage.OUTBOUND))[0] == OutboxStatus.DONE.value
    assert await _status(store, mid) == MessageStatus.PROCESSED.value
    assert await _dead_rows(store) == 0


@pytest.mark.parametrize(
    "status", [OutboxStatus.DONE.value, OutboxStatus.DEAD.value, OutboxStatus.CANCELLED.value]
)
async def test_mark_failed_at_its_cap_leaves_a_resolved_row_as_it_is(
    store: MessageStore, status: str
) -> None:
    mid = await store.enqueue_message(channel_id="IB", raw=_hl7("RES"), deliveries=[("OB", "p")])
    item = await _claim(store, "OB", Stage.OUTBOUND)
    await store._db.execute("UPDATE queue SET status=? WHERE id=?", (status, item.id))
    await store._db.commit()
    outcome = await store.mark_failed(item.id, "late", RetryPolicy(max_attempts=1))
    assert outcome.dead == 0
    assert (await _row(store, mid, Stage.OUTBOUND))[0] == status


async def test_mark_failed_at_its_cap_still_dead_letters_a_pending_row(store: MessageStore) -> None:
    """ADR 0157 C2's case: a lease sweep re-pended the row under a slow send, and the send's own
    terminal write must still land."""
    mid = await store.enqueue_message(channel_id="IB", raw=_hl7("SWEPT"), deliveries=[("OB", "p")])
    item = await _claim(store, "OB", Stage.OUTBOUND)
    await store.reset_stale_inflight()
    outcome = await store.mark_failed(item.id, "exhausted", RetryPolicy(max_attempts=1))
    assert outcome.dead == 1
    assert (await _row(store, mid, Stage.OUTBOUND))[0] == OutboxStatus.DEAD.value


async def test_a_store_fault_leaves_the_row_in_flight_and_the_death_raised(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(_registry(tmp_path, router=_kill_on("KILL")), store, "per_lane")
    mid = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))

    async def broken(*a: Any, **k: Any) -> Any:
        raise RuntimeError("store down")

    monkeypatch.setattr(store, "record_worker_death", broken)
    with pytest.raises(_Kill):  # the store fault never replaces the death
        await runner._process_ingress_item("IB", await _claim(store, "IB", Stage.INGRESS))
    assert await _row(store, mid, Stage.INGRESS) == ("inflight", 1, 0)


@pytest.mark.parametrize(
    ("exc", "counted"),
    [
        (_Kill(), True),
        (KeyboardInterrupt(), False),
        (SystemExit(0), False),
        (asyncio.CancelledError(), False),
        (GeneratorExit(), False),
        (ValueError("an ordinary fault"), False),
    ],
)
def test_only_a_death_is_counted(exc: BaseException, counted: bool) -> None:
    """Owner ruling 2026-11-11: ``KeyboardInterrupt`` and ``SystemExit`` end the process for a
    reason that is not the row's; a cancellation is a stop or a teardown, and a closed coroutine
    cannot await the write. An ``Exception`` already takes the worker's own fault arm."""
    assert _kills_the_worker(exc) is counted


@pytest.mark.parametrize(
    ("exc", "counted"),
    [
        (_Kill(), True),  # the positive control: the same path does count a death
        (KeyboardInterrupt(), False),
        (SystemExit(0), False),
        (asyncio.CancelledError(), False),
        (GeneratorExit(), False),
    ],
)
def test_an_excluded_exception_passes_the_body_wrapper_uncounted(
    exc: BaseException, counted: bool
) -> None:
    """Driven by hand, off any event loop: a ``KeyboardInterrupt`` raised inside a task would end
    the test run itself. Nothing here suspends, so one ``send`` runs the wrapper to its raise."""
    recorded: list[str] = []

    class _Runner:
        async def _record_worker_death(self, *args: Any) -> None:
            recorded.append("counted")

    async def body(self: Any, name: str, item: Any) -> Any:
        raise exc

    wrapped = _records_worker_death("router")(body)
    coro = cast(Coroutine[Any, Any, Any], wrapped(_Runner(), "IB", object()))  # type: ignore[arg-type]
    with pytest.raises(type(exc)):
        coro.send(None)
    assert recorded == (["counted"] if counted else [])


async def test_the_migration_adds_the_column_to_an_existing_store(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    s = await MessageStore.open(path)
    mid = await s.enqueue_ingress(channel_id="IB", raw=_hl7("OLD"))
    await s.close()
    with sqlite3.connect(path) as conn:  # a store from before the column
        conn.execute("ALTER TABLE queue DROP COLUMN worker_deaths")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(queue)")}
    conn.close()
    assert "worker_deaths" not in cols

    s = await MessageStore.open(path)
    try:
        assert await _row(s, mid, Stage.INGRESS) == ("pending", 0, 0)
        item = await _claim(s, "IB", Stage.INGRESS)
        counted = await s.record_worker_death(item.id, LIMIT, "router worker killed by _Kill")
        assert counted.deaths == 1
    finally:
        await s.close()


async def test_a_live_per_lane_engine_dead_letters_the_killer_across_restarts(
    tmp_path: Path, store: MessageStore
) -> None:
    """End to end in per_lane mode: each start re-claims the killer, its router worker dies, and
    the start on which the count reaches the cap dead-letters it. The next message routes at once,
    as it did before this change, since the killer is left in flight below the cap."""
    calls: list[str] = []
    killer = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
    after = await store.enqueue_ingress(channel_id="IB", raw=_hl7("OK"))
    reg = _registry(tmp_path, router=_kill_on("KILL", calls))
    for death in range(1, LIMIT + 1):
        await _restart(store)  # the engine's start runs this before the runner's
        runner = _runner(reg, store, "per_lane")
        await runner.start()
        try:
            deadline = time.monotonic() + 10.0
            while (await _row(store, killer, Stage.INGRESS))[2] < death:
                assert time.monotonic() < deadline, calls
                await asyncio.sleep(0.02)
            while await _status(store, after) == MessageStatus.RECEIVED.value:
                assert time.monotonic() < deadline, calls
                await asyncio.sleep(0.02)
        finally:
            await runner.stop()
    assert calls.count("KILL") == LIMIT
    assert await _row(store, killer, Stage.INGRESS) == ("dead", LIMIT, LIMIT)
    assert await _status(store, killer) == MessageStatus.ERROR.value
