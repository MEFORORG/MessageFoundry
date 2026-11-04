# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A worker or serializer killed by a ``BaseException`` mid-handoff no longer strands its row
(BACKLOG #4607, the open remainder of #1611).

The worker loops and the pooled serializer catch ``Exception`` only, so a ``BaseException`` that
is not one kills the task with its claimed row INFLIGHT. Before #4607 a per-lane worker's
replacement then drained the row's successors past it, and a pooled serializer was not replaced at
all: its lane stayed PROCESSING until a restart. Each test kills the task while a SECOND message is
already pending behind the first on the same lane, so a replacement that claimed before re-pending
the first would deliver the second first, and asserts delivery order, nothing left in flight, and
that no restart was involved."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.config.models import BatchConfig
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import stage_dispatcher, wiring_runner
from messagefoundry.pipeline.stage_dispatcher import (
    HoldResult,
    LaneResultKind,
    RependFence,
    _LaneOutcome,
    _LanePhase,
    _LaneState,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _LaneClaims
from messagefoundry.store import MessageStore, Stage
from tests.test_backlog1611_inflight_watch import (
    RAW,
    _bare_dispatcher,
    _claimed_ingress_row,
    _ingress_inflight,
    _registry,
)
from tests.test_task_resilience import (
    _control_ids,
    _hl7,
    _inflight_rows,
    _pending_at,
    _start_runner,
    _until,
    _until_async,
    _until_delivered,
)


class _Kill(BaseException):
    """Not an ``Exception``, so no worker's ``except Exception`` arm catches it."""


class _Killer:
    """Wrap one handoff: the first ``kills`` calls carrying message A block on ``gate`` and then
    raise :class:`_Kill`; every other call goes through. Blocking first is what lets the test queue
    message B behind A before A's worker dies."""

    def __init__(self, real: Callable[..., Awaitable[Any]], marker: str, kills: int = 1) -> None:
        self.real = real
        self.marker = marker
        self.kills = kills
        self.fired = 0
        self.reached = asyncio.Event()
        self.gate = asyncio.Event()

    def carries_a(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> bool:
        return self.marker in repr(args) + repr(kwargs)

    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if self.fired < self.kills and self.carries_a(args, kwargs):
            self.fired += 1
            self.reached.set()
            await self.gate.wait()
            raise _Kill("injected kill")  # one message: a changed cause is never held back
        return await self.real(*args, **kwargs)


def _shorten_backoffs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only to keep the tests fast: the re-pend dates the row one backoff ahead."""
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.05)
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 0.05)
    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_BACKOFF_BASE_SECONDS", 0.05)


# (worker kind, the runner dict holding it, its key, the stage B must be pending at, the site).
_PER_LANE_SITES = [
    ("router", "_router_workers", "IB", Stage.INGRESS, "route_handoff"),
    ("transform", "_transform_workers", "IB", Stage.ROUTED, "transform_handoff"),
    ("delivery", "_workers", "OB", Stage.OUTBOUND, "send"),
]


def _install_killer(
    store: MessageStore,
    collector: Any,
    site: str,
    monkeypatch: pytest.MonkeyPatch,
    kills: int,
) -> _Killer:
    # Every handoff carries the payload (route_handoff its handlers' copies, transform_handoff its
    # deliveries, send the frame itself), and only A's carries A's control id.
    target = collector if site == "send" else store
    killer = _Killer(getattr(target, site), "M4607A", kills)
    monkeypatch.setattr(target, site, killer)
    return killer


async def _queue_a_then_b(
    runner: RegistryRunner, store: MessageStore, killer: _Killer, stage: Stage
) -> None:
    """Ingest A, hold it at the kill site, ingest B, and wait until B is pending on A's lane."""
    ib = runner.registry.inbound["IB"]
    await runner._handle_inbound(ib, _hl7("M4607A"))
    await asyncio.wait_for(killer.reached.wait(), timeout=5.0)
    await runner._handle_inbound(ib, _hl7("M4607B"))

    async def _b_waiting() -> bool:
        return await _pending_at(store, stage) >= 1

    await _until_async(_b_waiting, timeout=5.0)


@pytest.mark.parametrize(("kind", "attr", "key", "stage", "site"), _PER_LANE_SITES)
async def test_a_per_lane_worker_killed_mid_handoff_is_replaced_and_its_row_is_not_overtaken(
    kind: str,
    attr: str,
    key: str,
    stage: Stage,
    site: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Closing step 1: the replacement re-pends the row the dead worker held, before its first
    claim. Without it the replacement claims B, delivers it, and A stays INFLIGHT until a restart."""
    _shorten_backoffs(monkeypatch)
    store, runner, collector = await _start_runner(tmp_path, "per_lane")
    try:
        workers = getattr(runner, attr)
        first = workers[key]
        killer = _install_killer(store, collector, site, monkeypatch, kills=1)
        await _queue_a_then_b(runner, store, killer, stage)
        killer.gate.set()

        await _until(first.done, timeout=5.0)
        assert isinstance(first.exception(), _Kill)
        await _until_delivered(store, 2)
        assert _control_ids(collector) == ["M4607A", "M4607B"]
        assert await _inflight_rows(store) == 0
        replacement = workers[key]
        assert replacement is not first and not replacement.done()  # respawned, no restart
        assert runner.running
    finally:
        await runner.stop()
        await store.close()


@pytest.mark.parametrize(("kind", "attr", "key", "stage", "site"), _PER_LANE_SITES[:1])
async def test_a_row_that_kills_each_replacement_holds_its_lane_and_logs_on_a_backoff(
    kind: str,
    attr: str,
    key: str,
    stage: Stage,
    site: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Each replacement inherits the row from the worker before it, so a row that kills four
    workers in a row is still never overtaken. The deaths are one run: its traceback is logged on
    the 1st, 2nd and 4th, not on every death, and a settled pass closes it with a line. A run that
    reaches ``infra_fault_stop_after`` deaths pages ``lane_stuck`` once, since no other alert sees a
    lane whose row is re-pended at every respawn."""
    caplog.set_level(logging.WARNING, logger="messagefoundry.pipeline.wiring_runner")
    _shorten_backoffs(monkeypatch)
    store, runner, collector = await _start_runner(tmp_path, "per_lane")
    try:
        pages: list[str] = []
        monkeypatch.setattr(runner, "_infra_fault_stop_after", 3)
        monkeypatch.setattr(
            runner._alert_sink, "lane_stuck", lambda name, *, detail: pages.append(name)
        )
        killer = _install_killer(store, collector, site, monkeypatch, kills=4)
        await _queue_a_then_b(runner, store, killer, stage)
        killer.gate.set()

        await _until_delivered(store, 2, timeout=15.0)
        assert killer.fired == 4
        assert _control_ids(collector) == ["M4607A", "M4607B"]
        assert await _inflight_rows(store) == 0
        deaths = [
            r
            for r in caplog.records
            if "exited unexpectedly; respawning" in r.getMessage() and r.exc_info is not None
        ]
        assert [r.getMessage().rsplit(": ", 1)[-1] for r in deaths] == ["1)", "2)", "4)"]
        assert any("respawn recovered after 4" in r.getMessage() for r in caplog.records)
        assert pages == [key]
    finally:
        await runner.stop()
        await store.close()


@pytest.mark.parametrize(
    ("stage", "site"),
    [(Stage.INGRESS, "route_handoff"), (Stage.OUTBOUND, "send")],
    ids=lambda v: getattr(v, "value", v),
)
async def test_a_pooled_serializer_killed_mid_handoff_is_respawned_and_its_lane_drains_in_order(
    stage: Stage, site: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Closing step 2: a serializer killed by a ``BaseException`` is respawned. Without it the lane
    stays PROCESSING with its slot held and A INFLIGHT, so neither message is delivered."""
    _shorten_backoffs(monkeypatch)
    store, runner, collector = await _start_runner(tmp_path, "pooled")
    try:
        dispatcher = runner._dispatchers[stage]
        lane = "IB" if stage is Stage.INGRESS else "OB"
        killer = _install_killer(store, collector, site, monkeypatch, kills=1)
        await _queue_a_then_b(runner, store, killer, stage)
        dead = dispatcher._lane_tasks[lane]
        killer.gate.set()

        await _until(dead.done, timeout=5.0)
        assert isinstance(dead.exception(), _Kill)
        await _until_delivered(store, 2)
        assert _control_ids(collector) == ["M4607A", "M4607B"]
        assert await _inflight_rows(store) == 0
        assert dispatcher.busy_violations == 0
        assert dispatcher.slots_free == dispatcher._max_processing_lanes
        assert dispatcher._states[lane].serializer_deaths.count == 0
    finally:
        await runner.stop()
        await store.close()


async def test_a_row_that_kills_every_pooled_serializer_stops_its_lane_under_the_stop_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A row that kills every serializer at its head is bounded as a T17 fault is: each recovery is
    a zero-progress infra fault, so ``infra_fault_stop_after`` of them STOP the lane with its row
    PENDING, not INFLIGHT, and nothing behind it is delivered."""
    _shorten_backoffs(monkeypatch)
    store, runner, collector = await _start_runner(tmp_path, "pooled")
    try:
        dispatcher = runner._dispatchers[Stage.INGRESS]
        monkeypatch.setattr(dispatcher, "_infra_fault_stop_after", 3)
        killer = _install_killer(store, collector, "route_handoff", monkeypatch, kills=99)
        await _queue_a_then_b(runner, store, killer, Stage.INGRESS)
        killer.gate.set()

        await _until(lambda: dispatcher.stopped("IB"), timeout=10.0)
        assert killer.fired == 3
        assert collector.deliveries == []
        assert await _inflight_rows(store) == 0
        assert await _pending_at(store, Stage.INGRESS) == 2
        assert dispatcher.slots_free == dispatcher._max_processing_lanes
    finally:
        await runner.stop()
        await store.close()


async def test_rows_a_dying_serializer_noted_beyond_its_prefix_are_re_pended_with_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batching outbound claims its coalesced members itself, outside the serializer's prefix.
    When a ``BaseException`` kills it, the body records them (``note_held``) and the replacement
    dates them with the prefix; a fresh claim starts with none. The supervisor is handed the
    claimed rows' ids only, never the items, so a replacement waiting out its backoff holds no
    payload."""
    store, runner, _ = await _start_runner(tmp_path, "pooled")
    try:
        dispatcher = runner._dispatchers[Stage.OUTBOUND]
        st = dispatcher._states["OB"]
        dispatcher.note_held("OB", ["extra-1", "extra-2"])
        _, dated, released = dispatcher._dead_serializer_outcome("OB", ["head-1"])
        assert dated == ["head-1", "extra-1", "extra-2"]
        assert released == []
        started: list[tuple[str, list[str]]] = []

        def capture(lane: str, body: Any, ids: list[str], fence: RependFence) -> None:
            body.close()
            started.append((lane, ids))

        monkeypatch.setattr(dispatcher, "_start_serializer", capture)
        item: Any = SimpleNamespace(id="head-1")
        dispatcher._spawn_serializer("OB", [item])
        assert st.held_extra_ids == []
        assert started == [("OB", ["head-1"])]
    finally:
        await runner.stop()
        await store.close()


async def test_a_replacement_takes_over_where_its_dead_serializer_stopped(tmp_path: Path) -> None:
    """A replacement repeats a body that had finished, so a STOP it died re-pending stays a STOP
    and its tail is released, not dated. A body that died part way through its prefix made
    progress when it was past the first row, so the recovery does not escalate the lane's streak,
    and only the rows from the one it died on are dated."""
    store, runner, _ = await _start_runner(tmp_path, "pooled")
    try:
        dispatcher = runner._dispatchers[Stage.INGRESS]
        st = dispatcher._states["IB"]
        ids = [f"r{n}" for n in range(3)]
        st.drained = (_LaneOutcome(LaneResultKind.STOP, made_progress=True), ["r1", "r2"], None)
        outcome, dated, released = dispatcher._dead_serializer_outcome("IB", ids)
        assert outcome.kind is LaneResultKind.STOP
        assert (dated, released) == ([], ["r1", "r2"])

        st.drained = None
        st.drain_index = 1
        st.infra_error_streak = 5
        outcome, dated, released = dispatcher._dead_serializer_outcome("IB", ids)
        assert outcome.kind is LaneResultKind.RETRY and outcome.is_infra_fault
        assert outcome.made_progress
        assert (dated, released) == (["r1", "r2"], [])
    finally:
        await runner.stop()
        await store.close()


# --- the round-3 review repairs -------------------------------------------------------------------


class _Flap:
    """A lease this node holds under one epoch throughout, whose ``is_leader`` reads False for the
    first ``lost`` reads and True after (a flap), or False forever with ``lost=None``."""

    def __init__(self, lost: int | None, epoch: int = 1) -> None:
        self.lost = lost
        self.reads = 0
        self.epoch = epoch

    def is_leader(self) -> bool:
        self.reads += 1
        return self.lost is not None and self.reads > self.lost

    def fence(self) -> RependFence:
        return RependFence(self.is_leader, lambda: self.epoch, True, 1)


async def _recover_per_lane(
    runner: RegistryRunner,
    monkeypatch: pytest.MonkeyPatch,
    fence: RependFence,
    *,
    stop_after_sleeps: int | None = None,
) -> tuple[list[list[str]], list[list[str]], list[float]]:
    """Run a per-lane replacement over one inherited row, recording its re-pends, the ids the
    worker it then runs starts with, and its sleeps."""
    sent: list[list[str]] = []
    ran: list[list[str]] = []
    sleeps: list[float] = []

    async def repend(kind: str, name: str, ids: list[str], **_: Any) -> HoldResult:
        sent.append(list(ids))
        return HoldResult.LANDED

    async def run(name: str, *, claims: _LaneClaims) -> None:
        ran.append(list(claims.ids))

    async def sleep(delay: float) -> bool:
        sleeps.append(delay)
        if stop_after_sleeps is not None and len(sleeps) >= stop_after_sleeps:
            runner._stop.set()
        await asyncio.sleep(0)
        return runner._stop.is_set()

    monkeypatch.setattr(runner, "_repend_claimed_on_fault", repend)
    monkeypatch.setattr(runner, "_stop_or_sleep", sleep)
    await asyncio.wait_for(
        runner._recover_then_run("router", "IB", _LaneClaims(["r1"], fence), run), timeout=5.0
    )
    return sent, ran, sleeps


@pytest.mark.parametrize("case", ["flap", "superseded", "stopped-while-not-leading"])
async def test_a_per_lane_replacement_holds_its_lane_while_not_the_leader(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3-1. The replacement's re-pend is a retry of the dead worker's, not its first write, so it
    is fenced as a hold's retries are, and it waits on the fence as they do. A False leadership
    read under an unchanged lease (a flap) is waited out and the re-pend is sent: before the
    repair one False read dropped the rows and the worker claimed past them. A node that leads
    under another lease sends none, since a successor may hold them, and the worker runs. A stop
    while it waits leaves them in flight and runs no worker, so nothing overtakes them."""
    _shorten_backoffs(monkeypatch)
    store, runner, _ = await _start_runner(tmp_path, "per_lane")
    try:
        if case == "flap":
            sent, ran, _ = await _recover_per_lane(runner, monkeypatch, _Flap(lost=2).fence())
            assert (sent, ran) == ([["r1"]], [[]])
        elif case == "superseded":
            sent, ran, _ = await _recover_per_lane(runner, monkeypatch, _Flap(0, epoch=2).fence())
            assert (sent, ran) == ([], [[]])
        else:
            sent, ran, _ = await _recover_per_lane(
                runner, monkeypatch, _Flap(lost=None).fence(), stop_after_sleeps=3
            )
            assert (sent, ran) == ([], [])
    finally:
        await runner.stop()
        await store.close()


async def test_a_per_lane_replacement_sleeps_out_its_re_pend_before_its_first_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3-3. The re-pend dates the rows one backoff ahead and arms no wake, so a worker that
    claimed at once would find nothing and wait on its lane's idle backstop, up to 30 s with
    per-lane wake on. The replacement sleeps the backoff out first, as the except arm does."""
    _shorten_backoffs(monkeypatch)
    store, runner, _ = await _start_runner(tmp_path, "per_lane")
    try:
        leading = RependFence(lambda: True, lambda: 1, True, 1)
        sent, ran, sleeps = await _recover_per_lane(runner, monkeypatch, leading)
        assert (sent, ran) == ([["r1"]], [[]])
        assert sleeps == [wiring_runner._WORKER_ERROR_BACKOFF_SECONDS]
    finally:
        await runner.stop()
        await store.close()


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "r3.db")
    yield s
    await s.close()


def _processing_dispatcher(
    store: MessageStore, **kwargs: Any
) -> tuple[stage_dispatcher.StageDispatcher, _LaneState]:
    """A bare INGRESS dispatcher whose lane IB is PROCESSING with its slot consumed, as a dead
    serializer leaves it."""
    dispatcher = _bare_dispatcher(store, **kwargs)
    st = _LaneState(phase=_LanePhase.PROCESSING, slot_held=True)
    dispatcher._states["IB"] = st
    dispatcher._slots_free -= 1
    return dispatcher, st


@pytest.mark.parametrize("case", ["flap", "stopped-while-not-leading"])
async def test_a_pooled_replacement_holds_its_lane_while_not_the_leader(
    case: str, db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3-2, R3-5 and R3-6. A flap under an unchanged lease is waited out and the dead
    serializer's row is re-pended: before the repair the row was left INFLIGHT under the same
    epoch and the lane parked, so a later row could overtake it. A stop while it waits leaves the
    row in flight, and quiesce no longer reports zero rows INFLIGHT. The replacement returns its
    slot on entry, since it holds no payload."""
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 0.01)
    flap = _Flap(lost=2 if case == "flap" else None)
    dispatcher, _ = _processing_dispatcher(db)
    monkeypatch.setattr(dispatcher, "_park", lambda lane, st, until: None)
    row = await _claimed_ingress_row(db)
    task = asyncio.ensure_future(
        dispatcher._run_lane("IB", [], fence=flap.fence(), recover_ids=[row])
    )
    await _until(lambda: flap.reads >= 1)
    assert dispatcher.slots_free == dispatcher._max_processing_lanes  # returned on entry
    if case == "flap":
        await asyncio.wait_for(task, timeout=5.0)
        assert await _ingress_inflight(db) == 0  # re-pended, so nothing can overtake it
        assert dispatcher._stranded_on_stop == set()
        return
    await _until(lambda: flap.reads >= 3)
    dispatcher._stop.set()
    await asyncio.wait_for(task, timeout=5.0)
    assert await _ingress_inflight(db) == 1  # no write sent while not the leader
    assert dispatcher._stranded_on_stop == {"IB"}
    dispatcher._running = True
    assert await dispatcher.quiesce(0.1) is False


async def test_a_stop_during_a_pooled_respawn_backoff_is_counted_against_quiesce(
    db: MessageStore,
) -> None:
    """R3-5. A recovery still in its respawn backoff when a demotion's stop lands sends no write,
    so its row stays INFLIGHT; quiesce must not then report zero rows INFLIGHT."""
    dispatcher, _ = _processing_dispatcher(db)
    row = await _claimed_ingress_row(db)
    fence = RependFence(lambda: True, lambda: 1, True, 1)
    task = asyncio.ensure_future(
        dispatcher._run_lane("IB", [], fence=fence, recover_ids=[row], delay=30.0)
    )
    await asyncio.sleep(0.05)
    dispatcher._stop.set()
    await asyncio.wait_for(task, timeout=5.0)
    assert await _ingress_inflight(db) == 1
    dispatcher._running = True
    assert await dispatcher.quiesce(0.1) is False


@pytest.mark.parametrize("streak", [0, 2], ids=["deaths-only", "streak-at-bound"])
async def test_the_death_page_does_not_duplicate_the_recoverys_own_bound(
    streak: int, db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3-4. A run of ``infra_fault_stop_after`` deaths pages ``lane_stuck`` once, from the
    supervisor, when the deaths alone reach the bound. When the recovery about to run is the
    zero-progress fault that brings the streak to that bound, its own STOP or page is the alert,
    and the supervisor sends none: before the repair both fired in the same cycle."""
    pages: list[str] = []
    sink = SimpleNamespace(lane_stuck=lambda lane, *, detail: pages.append(lane))
    dispatcher, st = _processing_dispatcher(db, alert_sink=sink, infra_fault_stop_after=3)
    st.infra_error_streak = streak
    monkeypatch.setattr(
        dispatcher, "_start_serializer", lambda lane, body, ids, fence: body.close()
    )
    fence = RependFence(lambda: True, lambda: 1, True, 1)

    async def die() -> None:
        raise _Kill("injected kill")

    for _ in range(3):
        dead = asyncio.ensure_future(die())
        with pytest.raises(_Kill):
            await dead
        dispatcher._on_lane_task_done("IB", ["r1"], fence, dead)
    assert st.serializer_deaths.count == 3
    if streak == 0:
        assert pages == ["IB"] and st.lane_stuck_alerted
    else:
        assert pages == [] and not st.lane_stuck_alerted


async def test_a_replacement_for_a_serializer_that_died_in_its_transition_counts_the_streak_once(
    db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3-7. A serializer that dies inside its terminal transition, after ``_apply_retry`` counted
    its fault, is replayed by its replacement. The replay puts the streak back to what that
    transition found, so the fault is counted once, not twice."""
    _shorten_backoffs(monkeypatch)
    dispatcher, st = _processing_dispatcher(db)
    row = await _claimed_ingress_row(db)
    head = _LaneOutcome(LaneResultKind.RETRY, 1.0, is_infra_fault=True, made_progress=False)
    st.drained = (head, [], (row, 1.0))
    parks: list[float | None] = []

    def park(lane: str, st: Any, until: float | None) -> None:
        parks.append(until)
        if len(parks) == 1:
            raise _Kill("injected kill inside the terminal transition")

    monkeypatch.setattr(dispatcher, "_park", park)
    fence = RependFence(lambda: True, lambda: 1, True, 1)
    with pytest.raises(_Kill):
        await dispatcher._run_lane("IB", [], fence=fence, recover_ids=[row])
    assert st.infra_error_streak == 1
    assert st.phase is _LanePhase.PROCESSING  # the transition died before the park
    await dispatcher._run_lane("IB", [], fence=fence, recover_ids=[row])
    assert st.infra_error_streak == 1
    assert len(parks) == 2


async def test_resume_lane_starts_a_fresh_run_of_serializer_deaths(db: MessageStore) -> None:
    """R3-12. An operator resume re-arms a paused lane with a fresh run of serializer deaths, as
    it starts a fresh claimer-death budget, so the next death is not paced or paged as a repeat."""
    dispatcher = _bare_dispatcher(db)
    st = _LaneState(phase=_LanePhase.PAUSED)
    st.serializer_deaths = st.serializer_deaths.record(
        logging.getLogger("test"), _Kill("x"), "death", level=logging.DEBUG
    )
    assert st.serializer_deaths.count == 1
    dispatcher._states["IB"] = st
    dispatcher.resume_lane("IB")
    assert st.serializer_deaths.count == 0


@pytest.mark.parametrize("mode", ["per_lane", "pooled"])
async def test_a_batch_killed_by_a_base_exception_hands_its_extras_on(
    mode: str, db: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3-15. A ``BaseException`` that kills a batching outbound after it coalesced its extras
    sends no write, and hands the extras to whoever re-pends the dead task's rows: the per-lane
    worker's claimed list, or the pooled serializer's ``note_held``."""
    runner = RegistryRunner(_registry(tmp_path), db, egress=EgressSettings(deny_by_default=False))
    for _ in range(3):
        await db.enqueue_message(channel_id="IB", raw=RAW, deliveries=[("OB", "p")], now=1.0)
    head = await db.claim_next_fifo("OB", now=2.0)
    assert head is not None
    coalesced: list[str] = []

    async def coalesce_then_die(name: str, cfg: Any, items: list[Any]) -> Any:
        for _ in range(2):
            more = await db.claim_next_fifo(name, now=2.0)
            assert more is not None
            items.append(more)
            coalesced.append(more.id)
        raise _Kill("injected kill after coalescing")

    monkeypatch.setattr(runner, "_deliver_coalesced_batch", coalesce_then_die)
    noted: list[tuple[str, list[str]]] = []
    if mode == "pooled":
        out: Any = SimpleNamespace(note_held=lambda lane, ids: noted.append((lane, list(ids))))
        monkeypatch.setitem(runner._dispatchers, Stage.OUTBOUND, out)
    extras_out: list[str] | None = [head.id] if mode == "per_lane" else None
    cfg = BatchConfig(max_count=3, max_wait_ms=1)
    with pytest.raises(_Kill):
        await runner._process_delivery_batch("OB", head, cfg, extras_out=extras_out)
    if mode == "per_lane":
        assert extras_out == [head.id, *coalesced] and noted == []
    else:
        assert noted == [("OB", coalesced)]
    assert await db.inflight_by_lane(stage=Stage.OUTBOUND.value) == {"OB": (3, 2.0)}
