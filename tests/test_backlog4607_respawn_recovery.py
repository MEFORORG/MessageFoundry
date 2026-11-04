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
from messagefoundry.log_backoff import FailureRun
from messagefoundry.pipeline import stage_dispatcher, wiring_runner
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.stage_dispatcher import (
    HoldResult,
    LaneResultKind,
    RependFence,
    _LaneOutcome,
    _LanePhase,
    _LaneState,
    wait_to_retry,
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


def _leading() -> RependFence:
    """A fence this node leads under throughout."""
    return RependFence.capture(lambda: True, lambda: 1)


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
        leading = _leading()
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


@pytest.mark.parametrize("case", ["flap", "paused-during-a-flap", "stopped-while-not-leading"])
async def test_a_pooled_replacement_holds_its_lane_while_not_the_leader(
    case: str, db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R3-2, R3-5 and R3-6. A flap under an unchanged lease is waited out and the dead
    serializer's row is re-pended: before the repair the row was left INFLIGHT under the same
    epoch and the lane parked, so a later row could overtake it. A stop while it waits leaves the
    row in flight, and quiesce no longer reports zero rows INFLIGHT. A pause does not end the
    wait: no write has been sent, so a lane paused then would read quiesced with the row INFLIGHT
    and claim past it on resume. The replacement returns its slot on entry, since it holds no
    payload."""
    monkeypatch.setattr(stage_dispatcher, "_LANE_ERROR_BACKOFF_SECONDS", 0.01)
    flap = _Flap(lost=None if case == "stopped-while-not-leading" else 2)
    dispatcher, st = _processing_dispatcher(db)
    st.pause_pending = case == "paused-during-a-flap"
    monkeypatch.setattr(dispatcher, "_to_paused", lambda lane, st: None)
    monkeypatch.setattr(dispatcher, "_park", lambda lane, st, until: None)
    row = await _claimed_ingress_row(db)
    task = asyncio.ensure_future(
        dispatcher._run_lane("IB", [], fence=flap.fence(), recover_ids=[row])
    )
    await _until(lambda: flap.reads >= 1)
    assert dispatcher.slots_free == dispatcher._max_processing_lanes  # returned on entry
    if case != "stopped-while-not-leading":
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
    fence = _leading()
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
    and the supervisor sends none: before the repair both fired in the same cycle. If that
    recovery dies before it can alert, the next death pages, and only once."""
    pages: list[str] = []
    sink = SimpleNamespace(lane_stuck=lambda lane, *, detail: pages.append(lane))
    dispatcher, st = _processing_dispatcher(db, alert_sink=sink, infra_fault_stop_after=3)
    st.infra_error_streak = streak
    monkeypatch.setattr(
        dispatcher, "_start_serializer", lambda lane, body, ids, fence: body.close()
    )
    fence = _leading()

    async def die() -> None:
        raise _Kill("injected kill")

    async def deaths(n: int) -> None:
        for _ in range(n):
            dead = asyncio.ensure_future(die())
            with pytest.raises(_Kill):
                await dead
            dispatcher._on_lane_task_done("IB", ["r1"], fence, dead)

    await deaths(3)
    assert st.serializer_deaths.count == 3
    if streak == 0:
        assert pages == ["IB"] and st.lane_stuck_alerted
    else:
        assert pages == [] and not st.lane_stuck_alerted
    await deaths(2)  # the recoveries expected to alert died first
    assert pages == ["IB"] and st.lane_stuck_alerted


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
    fence = _leading()
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


async def _dead_task() -> asyncio.Task[None]:
    async def die() -> None:
        raise _Kill("injected kill")

    task = asyncio.ensure_future(die())
    with pytest.raises(_Kill):
        await task
    return task


async def test_only_a_serializer_still_holding_its_lane_at_a_stop_is_counted_against_quiesce(
    db: MessageStore,
) -> None:
    """A serializer that dies during a stop after its terminal transition moved the lane out of
    PROCESSING holds nothing, so it is not counted against quiesce; one still PROCESSING is."""
    dispatcher, st = _processing_dispatcher(db)
    dispatcher._stop.set()
    st.phase = _LanePhase.PARKED
    dispatcher._on_lane_task_done("IB", ["r1"], _leading(), await _dead_task())
    assert dispatcher._stranded_on_stop == set()
    st.phase = _LanePhase.PROCESSING
    dispatcher._on_lane_task_done("IB", ["r1"], _leading(), await _dead_task())
    assert dispatcher._stranded_on_stop == {"IB"}


async def test_a_dropped_lane_record_reports_a_strand_only_for_a_worker_that_died(
    db: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A worker that returned handed its rows back, whatever its record still lists, so dropping
    the record of a lane this node will not run says nothing; a dead worker's rows are reported.
    A replacement that first runs after the stop reports the rows it inherited too."""
    caplog.set_level(logging.WARNING, logger="messagefoundry.pipeline.wiring_runner")
    runner = RegistryRunner(_registry(tmp_path), db, egress=EgressSettings(deny_by_default=False))

    async def ret() -> None:
        return None

    returned = asyncio.ensure_future(ret())
    await returned
    runner._lane_claims[("delivery", "OB")] = _LaneClaims(["r1"])
    runner._drop_lane_claims("delivery", "OB", returned)
    assert "stay in flight" not in caplog.text
    runner._lane_claims[("delivery", "OB")] = _LaneClaims(["r1"])
    runner._drop_lane_claims("delivery", "OB", await _dead_task())
    assert caplog.text.count("stay in flight until the next start") == 1

    runner._stop.set()

    async def run(name: str, *, claims: _LaneClaims) -> None:
        raise AssertionError("no worker runs after a stop")

    await runner._recover_then_run("router", "IB", _LaneClaims(["r1"], _leading()), run)
    assert caplog.text.count("stay in flight until the next start") == 2


# --- the round-4 review repairs -------------------------------------------------------------------


async def test_a_zero_delay_wait_reads_a_stop_that_is_already_set(tmp_path: Path) -> None:
    """R4-2. ``_stop_or_sleep(0.0)`` is the first wait of a fenced not-the-leader hold
    (:func:`wait_to_retry`). Before the repair ``wait_for`` cancelled the stop's wait before it ran,
    so the wait read "not stopped" with the stop set, and a replacement whose leadership read True
    again sent its re-pend during the teardown."""
    db = await MessageStore.open(tmp_path / "r4-2.db")
    try:
        runner = RegistryRunner(
            _registry(tmp_path), db, egress=EgressSettings(deny_by_default=False)
        )
        assert await runner._stop_or_sleep(0.0) is False
        runner._stop.set()
        assert await runner._stop_or_sleep(0.0) is True
        held = await wait_to_retry(
            0.0,
            poll=0.01,
            sleep=runner._stop_or_sleep,
            fence=_leading(),
            abandon=None,
            not_leader=lambda: None,
        )
        assert held is HoldResult.STOPPED  # None would send the write
    finally:
        await db.close()


def test_the_logged_lane_stuck_line_does_not_name_a_policy_the_page_may_not_be_under(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """R4-7. ``lane_stuck`` now also pages a run of worker deaths, under ``stop`` as well as
    ``retry_forever``, so the default sink's line no longer hardcodes ``(retry_forever)``; the
    detail names the case, and the retry_forever pages carry it in their own detail."""
    caplog.set_level(logging.WARNING, logger="messagefoundry.pipeline.alerts")
    LoggingAlertSink().lane_stuck("IB", detail="router worker died 3 times with no pass settling")
    (record,) = [r for r in caplog.records if "lane_stuck" in r.getMessage()]
    assert "retry_forever" not in record.getMessage()
    assert "router worker died 3 times" in record.getMessage()


@pytest.mark.parametrize("apart", [False, True], ids=["close-together", "far-apart"])
async def test_per_lane_deaths_far_apart_start_a_new_run(
    apart: bool, db: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R4-4. An idle lane never settles a pass, so before the repair every death on it joined one
    run: rare unrelated deaths added up to a respawn backoff and finally a ``lane_stuck`` page. A
    death :data:`_DEATH_RUN_QUIET_SECONDS` after the run's last now starts a new run; deaths close
    together, as a row that kills every worker brings them, still add up and page once."""
    runner = RegistryRunner(_registry(tmp_path), db, egress=EgressSettings(deny_by_default=False))
    pages: list[str] = []
    monkeypatch.setattr(runner, "_infra_fault_stop_after", 3)
    monkeypatch.setattr(
        runner._alert_sink, "lane_stuck", lambda name, *, detail: pages.append(name)
    )
    claims = _LaneClaims()
    runner._lane_claims[("router", "IB")] = claims
    gap = wiring_runner._DEATH_RUN_QUIET_SECONDS + (1.0 if apart else -1.0)
    for _ in range(3):
        runner._log_worker_death("router", "IB", await _dead_task())
        claims.last_death -= gap  # the next death comes `gap` after this one

    assert claims.deaths.count == (1 if apart else 3)
    assert pages == ([] if apart else ["IB"])


def _dead_run(n: int) -> Any:
    """A run of ``n`` deaths, as a supervisor records it."""
    run = FailureRun()
    for _ in range(n):
        run = run.record(logging.getLogger("test"), _Kill("x"), "death", level=logging.DEBUG)
    return run


@pytest.mark.parametrize("written", [False, True], ids=["head-in-flight", "head-written"])
async def test_a_pooled_serializer_that_died_after_writing_its_head_recovers_as_progress(
    written: bool, db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R4-3. ``drain_index`` moves past a row only when the body returns, so a serializer that
    died after the head's terminal write replayed as a zero-progress fault: under ``stop`` a lane
    that delivered at every death was STOPped at ``infra_fault_stop_after``, and its run of deaths
    never closed. The replacement now reads whether the head is still in flight; one that is not
    was written, so the recovery made progress and the run ends. A head still in flight is the
    zero-progress fault it was."""
    dispatcher, st = _processing_dispatcher(db, infra_fault_stop_after=3)
    st.infra_error_streak = 2
    st.serializer_deaths = _dead_run(2)
    # A written head is no longer in flight; an id the store never claimed reads the same.
    ids = ["written-row"] if written else [await _claimed_ingress_row(db)]
    outcomes: list[_LaneOutcome] = []
    monkeypatch.setattr(
        dispatcher, "_apply_retry", lambda lane, st, outcome: outcomes.append(outcome)
    )
    await dispatcher._run_lane("IB", [], fence=_leading(), recover_ids=ids)
    (outcome,) = outcomes
    assert outcome.made_progress is written
    assert st.serializer_deaths.count == (0 if written else 2)
    assert await _ingress_inflight(db) == 0  # the in-flight head was re-pended either way


@pytest.mark.parametrize(
    "case", ["row-in-flight", "one-written-one-in-flight", "every-row-written"]
)
async def test_a_per_lane_worker_that_died_after_writing_its_rows_closes_its_run_of_deaths(
    case: str, db: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R4-3, per-lane half. A per-lane run of deaths closed only on a settled pass, so a worker
    that died after delivering its row, every time, read as stuck on it: backed off, and paged at
    the bound. The replacement now reads whether any row it inherited is still in flight; with
    none, the row it died on was written too, so the run closes. Round 6 (U1/U2): a router batch
    is handed off strictly in order, so one row written and one still in flight closes it too;
    the delivery half, where that reading is not progress, is
    ``test_only_an_ordered_per_lane_batch_counts_fewer_rows_in_flight_as_progress``."""
    runner = RegistryRunner(_registry(tmp_path), db, egress=EgressSettings(deny_by_default=False))
    # A written row is no longer in flight; an id the store never claimed reads the same.
    ids = ["written-row"]
    if case != "every-row-written":
        ids.insert(0, await _claimed_ingress_row(db))
    if case == "row-in-flight":
        ids.pop()
    sleeps: list[float] = []

    async def sleep(delay: float) -> bool:
        sleeps.append(delay)
        return False

    async def repend(kind: str, name: str, ids: list[str], **_: Any) -> HoldResult:
        return HoldResult.LANDED

    async def run(name: str, *, claims: _LaneClaims) -> None:
        return None

    monkeypatch.setattr(runner, "_stop_or_sleep", sleep)
    monkeypatch.setattr(runner, "_repend_claimed_on_fault", repend)
    claims = _LaneClaims(ids, _leading(), deaths=_dead_run(3))
    await asyncio.wait_for(runner._recover_then_run("router", "IB", claims, run), timeout=5.0)
    assert claims.deaths.count == (3 if case == "row-in-flight" else 0)
    backoff = wiring_runner._WORKER_ERROR_BACKOFF_SECONDS
    assert sleeps == [backoff, backoff, backoff]  # the repeat-death backoff runs before the read


# --- the round-5 review repairs (this branch's own round-4 changes) -------------------------------


def _capture_retries(
    dispatcher: stage_dispatcher.StageDispatcher, monkeypatch: pytest.MonkeyPatch
) -> list[_LaneOutcome]:
    outcomes: list[_LaneOutcome] = []
    monkeypatch.setattr(
        dispatcher, "_apply_retry", lambda lane, st, outcome: outcomes.append(outcome)
    )
    return outcomes


async def test_a_written_extra_does_not_drop_a_head_still_in_flight_from_the_re_pend(
    db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R5-2a. The in-flight count says a row was written, never which: a batching outbound writes
    its kept members before it dead-letters a refused head. A replacement that read the head as
    written left it out of the re-pend, INFLIGHT, and the lane claimed past it. Every row is
    re-pended now. Round 2 (R5-4): such a reading is not progress either, or a head that kills
    every serializer beside a member written on its own would reset its streak at every death
    and never reach the STOP or the page."""
    dispatcher, st = _processing_dispatcher(db)
    st.serializer_deaths = _dead_run(2)
    head = await _claimed_ingress_row(db)
    dispatcher.note_held("IB", ["written-extra"])
    outcomes = _capture_retries(dispatcher, monkeypatch)
    await dispatcher._run_lane("IB", [], fence=_leading(), recover_ids=[head])
    assert await _ingress_inflight(db) == 0  # the head was re-pended
    (outcome,) = outcomes
    assert not outcome.made_progress
    assert st.serializer_deaths.count == 2


async def test_a_replayed_full_drain_ends_the_run_of_serializer_deaths(
    db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R5-5. A serializer that drained its whole batch and died in its terminal transition
    survived its body, but its replacement replayed an outcome with ``made_progress`` False, so
    the run stayed open and could page a lane that delivered every row."""
    dispatcher, st = _processing_dispatcher(db)
    st.serializer_deaths = _dead_run(2)
    st.drained = (_LaneOutcome(None), [], None)
    monkeypatch.setattr(dispatcher, "_lane_done", lambda lane, st, claimed_full: None)
    await dispatcher._run_lane("IB", [], fence=_leading(), recover_ids=["drained-row"])
    assert st.serializer_deaths.count == 0


async def test_a_reading_after_a_recovery_wrote_is_not_taken_as_progress(
    db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R5-2b. A replacement whose re-pend landed, and which then died before its terminal
    transition, left the rows pending; the next replacement read that as the dead body's
    progress, reset the streak and closed the run, so the stop bound and the page were never
    reached. A recovery marks that it sent a write, and the next one reads zero progress."""
    dispatcher, st = _processing_dispatcher(db, infra_fault_stop_after=3)
    st.serializer_deaths = _dead_run(2)
    st.recovery_wrote = True
    outcomes = _capture_retries(dispatcher, monkeypatch)
    await dispatcher._run_lane("IB", [], fence=_leading(), recover_ids=["re-pended-row"])
    (outcome,) = outcomes
    assert not outcome.made_progress
    assert st.serializer_deaths.count == 2


async def test_a_stop_during_the_in_flight_read_sends_no_write(
    db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R5-1. The read came after the fence check, so a re-pend went out a whole store round trip
    behind it, during a teardown or after a lease change. It now comes first, and a stop during
    it ends the recovery with the row in flight and the lane counted against quiesce."""
    dispatcher, _ = _processing_dispatcher(db)
    row = await _claimed_ingress_row(db)

    async def read_then_stop(lane: str, ids: list[str]) -> int:
        dispatcher._stop.set()
        return 1

    monkeypatch.setattr(dispatcher, "_dead_rows_in_flight", read_then_stop)
    await dispatcher._run_lane("IB", [], fence=_leading(), recover_ids=[row])
    assert await _ingress_inflight(db) == 1
    assert dispatcher._stranded_on_stop == {"IB"}


async def test_a_recovery_with_nothing_in_flight_does_not_back_off(
    db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R5-6. A serializer that died after writing every row it held left nothing to re-pend, yet
    its replacement parked the lane for an infra backoff, dropping a wake that came meanwhile. It
    now parks it until now."""
    dispatcher, _ = _processing_dispatcher(db)
    outcomes = _capture_retries(dispatcher, monkeypatch)
    before = dispatcher._clock()
    await dispatcher._run_lane("IB", [], fence=_leading(), recover_ids=["written-row"])
    (outcome,) = outcomes
    assert outcome.made_progress
    assert outcome.park_until is not None
    assert before <= outcome.park_until <= dispatcher._clock()


async def test_a_per_lane_reading_after_a_replacement_sent_its_re_pend_is_not_progress(
    db: MessageStore, tmp_path: Path
) -> None:
    """R5-2b, per-lane half: a replacement that died after its re-pend was sent hands the next one
    rows that read as written; they are not taken as the dead worker's progress."""
    runner = RegistryRunner(_registry(tmp_path), db, egress=EgressSettings(deny_by_default=False))
    claims = _LaneClaims(["re-pended-row"], _leading(), deaths=_dead_run(3), repend_sent=True)
    assert not await runner._dead_worker_wrote("router", "IB", claims)
    claims.repend_sent = False
    assert await runner._dead_worker_wrote("router", "IB", claims)


# --- the round-6 review repairs (U1/U2, U5, U8) ---------------------------------------------------


async def _claimed_ingress_rows(store: MessageStore, n: int) -> list[str]:
    """``n`` rows of lane IB claimed at INGRESS as one ordered batch."""
    for _ in range(n):
        await store.enqueue_ingress(channel_id="IB", raw=RAW, now=1.0)
    items = await store.claim_next_fifo_batch("IB", stage=Stage.INGRESS.value, limit=n, now=2.0)
    assert len(items) == n
    return [it.id for it in items]


@pytest.mark.parametrize("case", ["head-written", "head-in-flight", "head-written-beside-an-extra"])
async def test_a_pooled_prefix_that_wrote_the_row_it_died_on_recovers_as_progress(
    case: str, db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """U1/U2 (round 6). A pooled prefix of 2 or more whose serializer wrote the row it died on and
    then died read as zero progress, because only an empty in-flight reading counted, so under
    ``stop`` a lane that wrote one row at every death was STOPped. The body drains the prefix in
    order, so fewer rows in flight than it held from ``drain_index`` on means that row was
    written: the recovery made progress, the run of deaths closes, and the rows it had not
    reached are released. Beside a noted coalesced row the count says nothing about which row
    was written, so that reading stays the zero-progress fault it was."""
    dispatcher, st = _processing_dispatcher(db, infra_fault_stop_after=3)
    st.serializer_deaths = _dead_run(2)
    if case == "head-in-flight":
        ids = await _claimed_ingress_rows(db, 2)
    else:
        ids = ["written-row", *await _claimed_ingress_rows(db, 1)]
    if case == "head-written-beside-an-extra":
        dispatcher.note_held("IB", ["coalesced-row"])
    outcomes = _capture_retries(dispatcher, monkeypatch)
    await dispatcher._run_lane("IB", [], fence=_leading(), recover_ids=ids)
    (outcome,) = outcomes
    progress = case == "head-written"
    assert outcome.made_progress is progress
    assert st.serializer_deaths.count == (0 if progress else 2)
    assert await _ingress_inflight(db) == 0  # every row it held is pending again either way


@pytest.mark.parametrize(
    ("kind", "progress"), [("router", True), ("transform", True), ("delivery", False)]
)
async def test_only_an_ordered_per_lane_batch_counts_fewer_rows_in_flight_as_progress(
    kind: str, progress: bool, db: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """U1/U2 (round 6), per-lane half. A router or transform batch is handed off in order one row
    at a time, so a dead worker holding two rows with one still in flight wrote the one it died
    on. A delivery batch is an unordered claim or a batching outbound's coalesced rows, where a
    row written beside the one that kills the worker says nothing, so only none in flight
    counts."""
    runner = RegistryRunner(_registry(tmp_path), db, egress=EgressSettings(deny_by_default=False))
    name = "OB" if kind == "delivery" else "IB"

    async def one_in_flight(*, stage: str) -> dict[str, tuple[int, float]]:
        return {name: (1, 0.0)}

    monkeypatch.setattr(db, "inflight_by_lane", one_in_flight)
    claims = _LaneClaims(["r1", "r2"], _leading(), deaths=_dead_run(3))
    assert await runner._dead_worker_wrote(kind, name, claims) is progress
    claims.ids = ["r1"]  # the control: one row held and one in flight is not written, any kind
    assert await runner._dead_worker_wrote(kind, name, claims) is False


async def test_an_unordered_pass_that_never_reached_the_poison_row_keeps_the_run_open(
    db: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """U5 (round 6). On an unordered lane fresh rows sort ahead of a re-pended poison row, so a
    pass that settled without reaching it closed the run of deaths at every death: no backoff,
    no page, and a traceback at every death. A settled unordered pass now closes the run only once
    it has resolved every row the run's deaths held in common; the poison row, which every death
    held, never is, so the deaths add up and page once. An ordered pass still closes it."""
    runner = RegistryRunner(_registry(tmp_path), db, egress=EgressSettings(deny_by_default=False))
    pages: list[str] = []
    monkeypatch.setattr(runner, "_infra_fault_stop_after", 3)
    monkeypatch.setattr(
        runner._alert_sink, "lane_stuck", lambda name, *, detail: pages.append(name)
    )
    claims = _LaneClaims()
    runner._lane_claims[("delivery", "OB")] = claims
    for fresh in ("f1", "f2", "f3"):
        claims.ids[:] = [fresh, "poison"]  # the fresh row is written, then the poison row kills
        runner._log_worker_death("delivery", "OB", await _dead_task())
        claims.ids[:] = [f"{fresh}-next"]  # a later pass of fresh rows only, which settles
        claims.settle("delivery", "OB", ordered=False)
    assert claims.deaths.count == 3
    assert claims.suspects == {"poison"}
    assert pages == ["OB"]
    claims.ids[:] = ["poison"]  # the control: a pass that resolves it closes the run
    claims.settle("delivery", "OB", ordered=False)
    assert (claims.deaths.count, claims.suspects) == (0, set())
    claims.ids[:] = ["f9", "poison"]
    runner._log_worker_death("delivery", "OB", await _dead_task())
    claims.ids[:] = ["f9-next"]
    claims.settle("delivery", "OB")  # an ordered pass closes it whatever it resolved
    assert claims.deaths.count == 0


async def test_a_pooled_replacement_that_owes_no_write_does_not_wait_on_leadership(
    db: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """U8 (round 6). A replacement whose dead serializer had written every row it held owes no
    write, yet it held its lane in the not-the-leader wait, stalling it until this node led again
    or stopped. It now reads the fence only when it owes a write."""
    flap = _Flap(lost=None)  # never the leader again
    dispatcher, _ = _processing_dispatcher(db)
    outcomes = _capture_retries(dispatcher, monkeypatch)
    await asyncio.wait_for(
        dispatcher._run_lane("IB", [], fence=flap.fence(), recover_ids=["written-row"]),
        timeout=5.0,
    )
    (outcome,) = outcomes
    assert outcome.made_progress
    assert flap.reads == 0
