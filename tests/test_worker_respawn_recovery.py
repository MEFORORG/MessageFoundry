# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A per-lane worker that dies re-pends exactly the rows it held before its replacement claims (vault
BACKLOG #1611 step 2, #4607 steps 1, 2 and 5, per-lane half; owner ruling 2026-11-15, holder-exact
per-lane recovery).

A ``BaseException`` that is not an ``Exception`` passes a worker loop's ``except Exception``, so the
fault arm's re-pend never ran: the supervisor respawned the worker, the dead worker's claimed row
stayed in flight until the next start, and the replacement claimed the row after it, a per-lane
FIFO break. The claimed ids now live in a per-task record the supervisor reads, and the replacement
task re-pends them before its first claim.

Every live test here goes red on the code before this change: there the killed row never moves
again without a restart, so the wait for it times out. The live-holder test also checks that a
healthy worker's in-flight row is left alone, which a lane-wide or age-based reset would break."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import BatchConfig, ConnectorType, RetryPolicy
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline import stage_dispatcher, wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage
from messagefoundry.store.store import MessageStatus
from messagefoundry.transports.base import DeliveryError, NegativeAckError

LIMIT = wiring_runner._WORKER_DEATH_LIMIT


class _Kill(BaseException):
    """Not an ``Exception``, and none of the four the owner ruled out: what kills a stage worker."""


def _hl7(control_id: str) -> str:
    return f"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|{control_id}|P|2.5.1\r"


def _control_id(payload: str) -> str:
    """MSH-10 of a synthetic test message, read only to name what the recorder saw."""
    return payload.split("\r", 1)[0].split("|")[9]


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "respawn.db")
    yield s
    await s.close()


@pytest.fixture(autouse=True)
def _fast_backoffs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stage_dispatcher, "_REPEND_RETRY_CAP_SECONDS", 0.05)
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.02)
    monkeypatch.setattr(wiring_runner, "_REPEND_RETRY_CAP_SECONDS", 0.05)


def _registry(
    tmp_path: Path,
    *,
    router: Any = None,
    handler: Any = None,
) -> Registry:
    """IB -> r -> h -> OB. The inbox is its own empty directory, so the listener picks up nothing."""
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


class _Recorder:
    """Stands in for OB's connector: records each send's control id in order, and can kill the
    worker on one control id, a set number of times, or hold a send until released."""

    def __init__(self, *, kill: str | None = None, kills: int = 1, hold: str | None = None) -> None:
        self.sent: list[str] = []
        self.attempts: list[str] = []
        self._kill, self._kills = kill, kills
        self._hold = hold
        self.holding = asyncio.Event()
        self.release = asyncio.Event()

    async def send(self, payload: str, **_: Any) -> None:
        cid = _control_id(payload)
        self.attempts.append(cid)
        if cid == self._kill and self._kills > 0:
            self._kills -= 1
            raise _Kill
        if cid == self._hold:
            self.holding.set()
            await self.release.wait()
        self.sent.append(cid)

    async def aclose(self) -> None:
        return None


async def _until(pred: Callable[[], Awaitable[bool]], *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out waiting for condition")


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


async def _settled(store: MessageStore, mid: str) -> str:
    """The message's status once the finalizer has decided it. The recorder notes a send before
    its ``send`` returns, and the delivery worker's ``mark_done`` (which runs the finalizer) comes
    after that, so a read straight after a wait on ``recorder.sent`` can still see ``routed``. The
    status is returned rather than awaited for, so an assertion on it names the value it saw."""

    async def decided() -> bool:
        return await _status(store, mid) not in (
            MessageStatus.RECEIVED.value,
            MessageStatus.ROUTED.value,
        )

    await _until(decided)
    return await _status(store, mid)


async def _started(reg: Registry, store: MessageStore, recorder: _Recorder) -> RegistryRunner:
    runner = RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        claim_mode="per_lane",
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    # After start, which builds both from the registry.
    runner._retry["OB"] = RetryPolicy(max_attempts=LIMIT, backoff_seconds=0.02)
    runner._destinations["OB"] = recorder  # type: ignore[assignment]
    return runner


def _kill_once_in(where: str, kills: dict[str, int]) -> dict[str, Any]:
    """A router or handler that kills its worker the first time it sees KILL."""

    def maybe_kill(m: Message) -> None:
        if m.control_id == "KILL" and kills.get(where, 0) == 0:
            kills[where] = 1
            raise _Kill

    def router(m: Message) -> list[str]:
        maybe_kill(m)
        return ["h"]

    def handler(m: Message) -> Any:
        maybe_kill(m)
        return Send("OB", m)

    return {"router": router} if where == "router" else {"handler": handler}


@pytest.mark.parametrize("stage", ["router", "transform", "delivery-send", "delivery-pace"])
async def test_a_killed_worker_recovers_its_row_without_a_restart_in_fifo_order(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    """KILL then OK on one lane; the worker holding KILL dies once by a ``BaseException``. KILL is
    delivered first, then OK, with no restart. ``delivery-pace`` kills the delivery worker outside
    its per-item body, where no death is recorded, so only the supervisor's re-pend frees the row;
    ``delivery-send`` kills it in the send, where the death is a failed send under the lane's
    policy. On the code before this change KILL stays in flight and only OK is delivered."""
    kills: dict[str, int] = {}
    recorder = _Recorder(kill="KILL" if stage == "delivery-send" else None)
    reg = _registry(
        tmp_path, **(_kill_once_in(stage, kills) if stage in ("router", "transform") else {})
    )
    if stage == "delivery-pace":
        real_pace = RegistryRunner._pace_outbound
        paced: list[int] = []

        async def kill_first_pace(self: RegistryRunner, name: str) -> None:
            paced.append(1)
            if len(paced) == 1:
                raise _Kill
            await real_pace(self, name)

        monkeypatch.setattr(RegistryRunner, "_pace_outbound", kill_first_pace)
    runner = await _started(reg, store, recorder)
    try:
        killer = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
        after = await store.enqueue_ingress(channel_id="IB", raw=_hl7("OK"))
        runner.notify_work()

        async def both_sent() -> bool:
            return len(recorder.sent) >= 2

        await _until(both_sent)
        assert recorder.sent == ["KILL", "OK"]  # FIFO: the re-pended head first
        assert await _settled(store, killer) == MessageStatus.PROCESSED.value
        assert await _settled(store, after) == MessageStatus.PROCESSED.value
        if stage in ("router", "transform"):
            assert kills == {stage: 1}
        if stage == "delivery-pace":
            assert len(paced) >= 2  # the kill, then the replacement's pass
        if stage == "delivery-send":
            assert recorder.attempts[:2] == ["KILL", "KILL"]  # nothing sent between them
    finally:
        await runner.stop()


async def test_a_live_holders_row_is_not_re_pended(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The delivery worker is mid-send on HELD while the router worker dies on KILL. The router's
    replacement re-pends only what the dead task held: KILL routes, and HELD stays in flight with
    its single send still running. A lane-wide or stage-wide reset would put HELD back to pending
    under its live holder. On the code before this change KILL never routes, so the wait for it
    times out."""
    kills: dict[str, int] = {}
    recorder = _Recorder(hold="HELD")
    reg = _registry(tmp_path, **_kill_once_in("router", kills))
    held = await store.enqueue_message(
        channel_id="IB", raw=_hl7("HELD"), deliveries=[("OB", _hl7("HELD"))]
    )
    runner = await _started(reg, store, recorder)
    try:
        runner.notify_work()
        await asyncio.wait_for(recorder.holding.wait(), timeout=10.0)
        reschedules: list[list[str]] = []
        real = store.reschedule_claimed

        async def spy(ids: Any, *a: Any, **k: Any) -> Any:
            reschedules.append(list(ids))
            return await real(ids, *a, **k)

        monkeypatch.setattr(store, "reschedule_claimed", spy)
        killer = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
        runner.notify_work()

        async def killer_routed() -> bool:
            return await _status(store, killer) != MessageStatus.RECEIVED.value

        await _until(killer_routed)
        assert kills == {"router": 1}
        assert (await _row(store, held, Stage.OUTBOUND))[0] == "inflight"  # the live holder's
        assert recorder.attempts == ["HELD"]  # sent once, still in its send
        held_ids = {
            str(r["id"])
            for r in await (
                await store._db.execute("SELECT id FROM queue WHERE message_id=?", (held,))
            ).fetchall()
        }
        assert reschedules and all(not (set(ids) & held_ids) for ids in reschedules)
        recorder.release.set()

        async def both_sent() -> bool:
            return len(recorder.sent) >= 2

        await _until(both_sent)
        assert recorder.sent == ["HELD", "KILL"]
    finally:
        recorder.release.set()
        await runner.stop()


@pytest.mark.parametrize("stage", ["router", "delivery"])
async def test_a_poison_row_is_dead_lettered_at_its_third_death_without_a_restart(
    tmp_path: Path, store: MessageStore, stage: str
) -> None:
    """KILL kills its worker every time. The respawn re-pends it, the replacement re-claims it, and
    the third death dead-letters it, in one start; then OK goes through. It is never re-pended
    past the cap: exactly ``LIMIT`` attempts on it. An ingress row counts in ``worker_deaths``; an
    outbound row counts a failed send against the lane's ``max_attempts`` (``LIMIT`` here). On the
    code before this change one start saw one death and KILL stayed in flight."""
    calls: list[str] = []

    def router(m: Message) -> list[str]:
        calls.append(m.control_id or "")
        if stage == "router" and m.control_id == "KILL":
            raise _Kill
        return ["h"]

    recorder = _Recorder(kill="KILL" if stage == "delivery" else None, kills=10 * LIMIT)
    runner = await _started(_registry(tmp_path, router=router), store, recorder)
    try:
        killer = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
        after = await store.enqueue_ingress(channel_id="IB", raw=_hl7("OK"))
        runner.notify_work()

        async def after_sent() -> bool:
            return "OK" in recorder.sent

        await _until(after_sent)
        assert await _settled(store, killer) == MessageStatus.ERROR.value
        if stage == "router":
            # attempts stays 1: each re-pend undoes its claim's increment, as the fault arm's does.
            assert await _row(store, killer, Stage.INGRESS) == ("dead", 1, LIMIT)
            assert calls == ["KILL"] * LIMIT + ["OK"]  # FIFO: OK only after KILL's last death
        else:
            assert await _row(store, killer, Stage.OUTBOUND) == ("dead", LIMIT, 0)
            assert recorder.attempts == ["KILL"] * LIMIT + ["OK"]
        assert recorder.sent == ["OK"]
        assert await _settled(store, after) == MessageStatus.PROCESSED.value
        await asyncio.sleep(0.2)  # a re-pend past the cap would re-claim it by now
        assert calls.count("KILL") == (LIMIT if stage == "router" else 1)
        assert recorder.attempts.count("KILL") == (LIMIT if stage == "delivery" else 0)
    finally:
        await runner.stop()


async def test_a_store_fault_during_the_re_pend_holds_the_lane_and_loses_nothing(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The replacement's re-pend fails twice. It is retried while the replacement holds the lane
    (the fault arm's hold-and-retry), so OK is not claimed past KILL, and both are delivered in
    order once the store heals. On the code before this change no re-pend is attempted at all."""
    kills: dict[str, int] = {}
    recorder = _Recorder()
    calls: list[int] = []
    real = store.reschedule_claimed

    async def flaky(*a: Any, **k: Any) -> Any:
        calls.append(1)
        if len(calls) <= 2:
            raise RuntimeError("simulated store fault in reschedule_claimed")
        return await real(*a, **k)

    monkeypatch.setattr(store, "reschedule_claimed", flaky)
    runner = await _started(_registry(tmp_path, **_kill_once_in("router", kills)), store, recorder)
    try:
        killer = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
        after = await store.enqueue_ingress(channel_id="IB", raw=_hl7("OK"))
        runner.notify_work()

        async def both_sent() -> bool:
            return len(recorder.sent) >= 2

        await _until(both_sent)
        assert recorder.sent == ["KILL", "OK"]
        assert len(calls) >= 3  # two failures, then the write that landed
        assert await _settled(store, killer) == MessageStatus.PROCESSED.value
        assert await _settled(store, after) == MessageStatus.PROCESSED.value
    finally:
        await runner.stop()


async def test_a_worker_that_returns_or_is_cancelled_hands_on_nothing(store: MessageStore) -> None:
    """Only a worker that died by an exception has its rows taken by the spawn that replaces it. A
    return has resolved or released its rows (or left them for the reload backstop), and only
    teardown cancels."""
    runner = RegistryRunner(
        Registry(), store, claim_mode="per_lane", egress=EgressSettings(deny_by_default=False)
    )

    async def hold_then(end: str) -> None:
        runner._held_rows().ids.append("row-1")
        if end == "raise":
            raise _Kill
        if end == "cancel":
            await asyncio.sleep(10)

    tasks: dict[str, asyncio.Task[None]] = {}
    for end in ("return", "raise", "cancel"):
        tasks[end] = asyncio.create_task(hold_then(end))
    await asyncio.sleep(0)
    tasks["cancel"].cancel()
    await asyncio.gather(*tasks.values(), return_exceptions=True)
    assert runner._take_dead_rows(tasks["return"]) is None
    assert runner._take_dead_rows(tasks["cancel"]) is None
    taken = runner._take_dead_rows(tasks["raise"])
    assert taken is not None and taken.ids == ["row-1"]
    assert runner._take_dead_rows(tasks["raise"]) is None  # taken once


@pytest.mark.parametrize("per_lane", [True, False])
async def test_a_death_inside_a_batch_hands_the_extras_to_the_respawn(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch, per_lane: bool
) -> None:
    """A batching outbound coalesces rows past the head inside its body. A death there skips the
    worker's fault arm, so the batch guard must put the extras in the worker's held list for the
    respawn to re-pend; otherwise they stay in flight while the next batch claims past them. The
    pooled path (no ``extras_out``) is held: the death goes on and nothing is re-pended there. On
    the code before this change the per-lane list stays empty."""
    runner = RegistryRunner(
        _registry(tmp_path),
        store,
        claim_mode="per_lane",
        egress=EgressSettings(deny_by_default=False),
    )
    for _ in range(3):
        await store.enqueue_message(
            channel_id="IB", raw=_hl7("B"), deliveries=[("OB", "p")], now=1.0
        )
    head = await store.claim_next_fifo("OB", now=2.0)
    assert head is not None
    extras: list[str] = []

    async def coalesce_then_die(name: str, cfg: Any, items: list[Any]) -> Any:
        for _ in range(2):
            more = await store.claim_next_fifo(name, now=2.0)
            assert more is not None
            items.append(more)
            extras.append(more.id)
        raise _Kill

    monkeypatch.setattr(runner, "_deliver_coalesced_batch", coalesce_then_die)
    held: list[str] = [head.id]
    with pytest.raises(_Kill):
        await runner._process_delivery_batch(
            "OB",
            head,
            BatchConfig(max_count=3, max_wait_ms=1),
            extras_out=held if per_lane else None,
        )
    assert held == ([head.id, *extras] if per_lane else [head.id])
    # The extras are left for the respawn on the per-lane path. The head is charged with the death
    # there, a failed send that re-pends it with its attempts kept, so a poison head reaches the
    # lane's cap; the pooled half writes nothing.
    assert await store.inflight_by_lane(stage=Stage.OUTBOUND.value) == {
        "OB": (2, 2.0) if per_lane else (3, 2.0)
    }
    cur = await store._db.execute("SELECT status, attempts FROM queue WHERE id=?", (head.id,))
    row = await cur.fetchone()
    assert row is not None
    assert (str(row["status"]), int(row["attempts"])) == (
        ("pending", 1) if per_lane else ("inflight", 1)
    )


async def test_a_repeated_death_no_row_is_charged_with_stops_re_pending_at_the_cap(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """KILL kills the router every time, and the store fails every death count, so no row is
    charged with the death and no row cap applies. The respawn re-pends KILL until the lane's
    count of such deaths reaches ``LIMIT``; the death that reaches it leaves KILL in flight for the
    next start, as main did, and the replacement goes on to OK. On the code before this bound KILL
    is re-pended and re-claimed every backoff with no end, so OK is never routed."""
    calls: list[str] = []

    def router(m: Message) -> list[str]:
        calls.append(m.control_id or "")
        if m.control_id == "KILL":
            raise _Kill
        return ["h"]

    async def count_fails(*_: Any, **__: Any) -> Any:
        raise RuntimeError("simulated store fault in record_worker_death")

    monkeypatch.setattr(store, "record_worker_death", count_fails)
    recorder = _Recorder()
    runner = await _started(_registry(tmp_path, router=router), store, recorder)
    try:
        killer = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
        after = await store.enqueue_ingress(channel_id="IB", raw=_hl7("OK"))
        runner.notify_work()

        async def after_sent() -> bool:
            return "OK" in recorder.sent

        await _until(after_sent, timeout=5.0)
        await asyncio.sleep(0.2)  # a re-pend past the cap would re-claim KILL by now
        assert calls == ["KILL"] * LIMIT + ["OK"]
        assert (await _row(store, killer, Stage.INGRESS))[0] == "inflight"  # for the next start
        assert await _settled(store, after) == MessageStatus.PROCESSED.value
    finally:
        await runner.stop()


async def test_a_repeated_death_outside_the_item_body_stops_re_pending_at_the_cap(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every pacing wait kills the delivery worker, outside its per-item body, where no death is
    recorded. The row is re-pended and re-claimed until ``LIMIT`` such deaths, then left in flight,
    and the replacement claims nothing more. On the code before this bound the pace is re-run every
    backoff with no end."""
    paced: list[int] = []

    async def always_kill(self: RegistryRunner, name: str) -> None:
        paced.append(1)
        raise _Kill

    monkeypatch.setattr(RegistryRunner, "_pace_outbound", always_kill)
    recorder = _Recorder()
    mid = await store.enqueue_message(
        channel_id="IB", raw=_hl7("KILL"), deliveries=[("OB", _hl7("KILL"))]
    )
    runner = await _started(_registry(tmp_path), store, recorder)
    try:
        runner.notify_work()

        async def capped() -> bool:
            return len(paced) >= LIMIT

        await _until(capped, timeout=5.0)
        await asyncio.sleep(0.3)  # a re-pend past the cap would have paced again by now
        assert len(paced) == LIMIT
        assert (await _row(store, mid, Stage.OUTBOUND))[0] == "inflight"
        assert recorder.attempts == []
    finally:
        await runner.stop()


async def test_a_death_after_a_failed_send_does_not_mark_the_row_failed_twice(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """KILL's first send fails, so the body sends it through ``mark_failed``; then the worker dies
    after that, in the lane-health note. The death must not send the row through ``mark_failed``
    a second time, which would repeat the failed event and restart the backoff. KILL is retried and
    delivered. On the code before this guard ``mark_failed`` runs twice for that one death."""
    recorder = _Recorder()
    real_send = recorder.send
    fails = {"KILL": 1}

    async def fail_first(payload: str, **k: Any) -> None:
        cid = _control_id(payload)
        if fails.get(cid, 0) > 0:
            fails[cid] -= 1
            recorder.attempts.append(cid)
            raise DeliveryError("simulated transport failure")
        await real_send(payload, **k)

    recorder.send = fail_first  # type: ignore[method-assign]
    kills = [1]

    def kill_once(self: RegistryRunner, name: str, message_id: str, exc: BaseException) -> None:
        if kills:
            kills.pop()
            raise _Kill

    monkeypatch.setattr(RegistryRunner, "_note_lane_unhealthy", kill_once)
    marked: list[str] = []
    real_mark = store.mark_failed

    async def spy(outbox_id: str, *a: Any, **k: Any) -> Any:
        marked.append(outbox_id)
        return await real_mark(outbox_id, *a, **k)

    monkeypatch.setattr(store, "mark_failed", spy)
    mid = await store.enqueue_message(
        channel_id="IB", raw=_hl7("KILL"), deliveries=[("OB", _hl7("KILL"))]
    )
    runner = await _started(_registry(tmp_path), store, recorder)
    try:
        runner.notify_work()

        async def delivered() -> bool:
            return "KILL" in recorder.sent

        await _until(delivered, timeout=5.0)
        assert not kills  # the worker did die after the failed send
        assert len(marked) == 1  # one failed send, one mark_failed
        assert recorder.attempts == ["KILL", "KILL"]

        async def marked_done() -> bool:  # mark_done runs after the send returns
            return (await _row(store, mid, Stage.OUTBOUND))[0] != "inflight"

        await _until(marked_done, timeout=5.0)
        status, attempts, _ = await _row(store, mid, Stage.OUTBOUND)
        assert (status, attempts) == ("done", 2)
    finally:
        await runner.stop()


@pytest.mark.parametrize(
    ("case", "leader_now", "epoch_now", "re_pends"),
    [
        ("still-leads", True, 7, True),
        ("demoted", False, None, False),  # current_epoch clears on a demotion
        ("gate-first", False, 7, False),  # the cached gate drops before the epoch clears
        ("moved", True, 8, False),  # another node led since
    ],
)
async def test_a_respawn_on_a_node_that_no_longer_leads_does_not_re_pend(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    leader_now: bool,
    epoch_now: int | None,
    re_pends: bool,
) -> None:
    """The dead task claimed its row leading under epoch 7. The respawn's re-pend is a deferred
    write for a task that is gone, so it is sent only while this node still leads under that
    lease; otherwise the row stays in flight for the leader's recovery and the replacement runs at
    once. ``still-leads`` is the positive control. On the code before this check ``demoted`` and
    ``gate-first`` re-pend: ``RependFence.moved`` reads False when ``current_epoch`` is ``None`` or
    unchanged, and the hold always sends its first write."""
    runner = RegistryRunner(
        Registry(), store, claim_mode="per_lane", egress=EgressSettings(deny_by_default=False)
    )
    mid = await store.enqueue_ingress(channel_id="IB", raw=_hl7("KILL"))
    item = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert item is not None
    fence = stage_dispatcher.RependFence(lambda: leader_now, lambda: epoch_now, True, 7)
    dead = wiring_runner._HeldRows([item.id], fence=fence, charged=True)
    reschedules: list[list[str]] = []
    real = store.reschedule_claimed

    async def spy(ids: Any, *a: Any, **k: Any) -> Any:
        reschedules.append(list(ids))
        return await real(ids, *a, **k)

    monkeypatch.setattr(store, "reschedule_claimed", spy)
    ran: list[str] = []

    async def work(name: str) -> None:
        ran.append(name)

    await runner._recover_then_run("router", "IB", dead, work)
    assert ran == ["IB"]  # the replacement runs on every path
    assert reschedules == ([[item.id]] if re_pends else [])
    assert (await _row(store, mid, Stage.INGRESS))[0] == ("pending" if re_pends else "inflight")


async def test_a_death_after_a_row_is_handed_back_does_not_mark_it_failed(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """KILL's send hits a permanent credential fault, so the body releases it un-errored and stops
    the lane; then the worker dies in the stop alert, after the release. The row is unsent and
    already PENDING, so the death must not send it through ``mark_failed``, which would add a
    backoff and an error to it. The replacement meets the same fault and stops the lane again. On
    the code before this guard the death marks the released row failed."""
    recorder = _Recorder()

    async def credential_fault(payload: str, **_: Any) -> None:
        recorder.attempts.append(_control_id(payload))
        raise NegativeAckError(
            "simulated auth rejection", code="AR", permanent=True, credential_fault=True
        )

    recorder.send = credential_fault  # type: ignore[method-assign]
    marked: list[str] = []
    real_mark = store.mark_failed

    async def spy(outbox_id: str, *a: Any, **k: Any) -> Any:
        marked.append(outbox_id)
        return await real_mark(outbox_id, *a, **k)

    monkeypatch.setattr(store, "mark_failed", spy)
    mid = await store.enqueue_message(
        channel_id="IB", raw=_hl7("KILL"), deliveries=[("OB", _hl7("KILL"))]
    )
    runner = await _started(_registry(tmp_path), store, recorder)
    stops: list[str] = []
    kills = [1]

    def kill_once(name: str, *, detail: str = "") -> None:
        stops.append(name)
        if kills:
            kills.pop()
            raise _Kill

    monkeypatch.setattr(runner._alert_sink, "connection_stopped", kill_once)
    try:
        runner.notify_work()

        async def stopped_again() -> bool:
            return len(stops) >= 2

        await _until(stopped_again, timeout=5.0)
        assert not kills  # the worker did die after the release
        assert marked == []  # no failed send for a row nobody sent
        assert recorder.attempts == ["KILL", "KILL"]
        cur = await store._db.execute(
            "SELECT status, attempts, last_error FROM queue WHERE message_id=? AND stage=?",
            (mid, Stage.OUTBOUND.value),
        )
        row = await cur.fetchone()
        assert row is not None
        assert (row["status"], row["attempts"], row["last_error"]) == ("pending", 0, None)
    finally:
        await runner.stop()
