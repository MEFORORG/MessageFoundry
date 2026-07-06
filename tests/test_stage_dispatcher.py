# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0066 §8 row 5 — the pooled-mode ``StageDispatcher`` state-machine unit tests.

These are the **only** caller of :mod:`messagefoundry.pipeline.stage_dispatcher` (it is unwired in
PR3). Each test asserts an exact per-lane transition (ADR 0066 §4.2 T1–T21) and the two tripwires the
FIFO guard now rests on outside the SQL layer: ``busy_violations == 0`` (the one-consumer-per-lane
invariant) and no concurrent double-dispatch of a lane.

Backend-parametrized exactly like ``tests/test_claim_fifo_heads.py`` (SQLite always; SQL Server /
Postgres gated on ``MEFOR_TEST_*`` — the merge rider makes row 5 run on the live SS + PG CI legs), so
the stub ``process_item`` performs the **real** head store write per outcome (RESOLVED leaves the
claimed row INFLIGHT; RETRY ``mark_failed``s; STOP leaves the head INFLIGHT) — the SS/PG legs then
exercise a faithful queue, not a fiction.

**Clock model (subtle, load-bearing).** The dispatcher drives ALL its time decisions off the injected
:class:`ManualClock` — the claim's due-ness (it passes ``now=clock()`` to ``claim_fifo_heads``), the
sweep's head-due comparison, and the park/backoff timers — so timing is fully deterministic with no
wall-clock reliance. Seeded values are therefore chosen relative to the test's ManualClock base:

* rows that must be claimable are seeded with a ``now`` below the ManualClock base (e.g. ``100.0``
  under base ``1000.0``) — due against the (single) clock;
* a ``mark_failed`` re-pend is computed off ``clock()``, so once the park timer fires and the clock
  has advanced past ``next_attempt_at`` the re-claim is genuinely due;
* a head that must read **not-due** is either seeded above the clock base (the not-due-sweep case) or
  re-pended into the future by ``mark_failed`` (the ``PARKED``-discarded-on-restart case); advancing
  the clock past its deadline is all it takes to make it due again — no wall-clock, no direct edits.
"""

from __future__ import annotations

import asyncio
import os
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable, cast

import pytest

from messagefoundry.config.models import RetryPolicy
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.stage_dispatcher import (
    LaneItemResult,
    LaneResultKind,
    StageDispatcher,
    _LanePhase,
)
from messagefoundry.store import ClaimedHeads, MessageStore, OutboxItem, OutboxStatus, Stage

RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))


# --- backend-parametrized store fixture (mirrors test_claim_fifo_heads.py) ------------------------


async def _open_sqlite(tmp_path: Path) -> MessageStore:
    return await MessageStore.open(tmp_path / "heads.db")


async def _open_sqlserver(tmp_path: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    s = await SqlServerStore.open(settings)
    async with s._pool.acquire() as conn:
        cur = await conn.cursor()
        for table in (
            "message_events",
            "queue",
            "response",
            "delivered_keys",
            "outbox",
            "messages",
        ):
            await cur.execute(f"DELETE FROM {table}")
        await conn.commit()
    return s


async def _open_postgres(tmp_path: Path) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    settings = load_settings(environ=os.environ).store
    s = await PostgresStore.open(settings)
    async with s._pool.acquire() as conn:
        await conn.execute(
            "TRUNCATE message_events, queue, response, delivered_keys, messages"
            " RESTART IDENTITY CASCADE"
        )
    await s._load_state_cache()
    await s._load_reference_cache()
    return s


@pytest.fixture(params=["sqlite", "sqlserver", "postgres"])
async def store(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[Any]:
    backend = request.param
    if backend == "sqlserver" and not _SQLSERVER_ON:
        pytest.skip("set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the SQL Server case")
    if backend == "postgres" and not _POSTGRES_ON:
        pytest.skip("set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres case")
    opener = {"sqlite": _open_sqlite, "sqlserver": _open_sqlserver, "postgres": _open_postgres}[
        backend
    ]
    s = await opener(tmp_path)
    s._test_backend = backend  # tag so a test can branch on backend-specific access
    try:
        yield s
    finally:
        await s.close()


# --- cross-backend direct-SQL helpers (mirrors test_claim_fifo_heads.py) --------------------------


def _pg_sql(sql: str) -> str:
    out: list[str] = []
    n = 0
    for ch in sql:
        if ch == "?":
            n += 1
            out.append(f"${n}")
        else:
            out.append(ch)
    return "".join(out)


async def _query(store: Any, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    backend = store._test_backend
    if backend == "sqlite":
        cur = await store._db.execute(sql, params)
        return [dict(r) for r in await cur.fetchall()]
    if backend == "postgres":
        async with store._pool.acquire() as conn:
            return [dict(r) for r in await conn.fetch(_pg_sql(sql), *params)]
    return list(await store._fetchall(sql, params))  # sqlserver


async def _lane_rows(store: Any, lane: str) -> list[dict[str, Any]]:
    """INGRESS queue rows for one lane, in lane FIFO order (rowid on SQLite, seq elsewhere)."""
    order = "rowid" if store._test_backend == "sqlite" else "seq"
    return await _query(
        store,
        f"SELECT id, message_id, status, attempts, next_attempt_at FROM queue"
        f" WHERE stage=? AND channel_id=? ORDER BY {order}",
        (Stage.INGRESS.value, lane),
    )


async def _seed(store: Any, lane: str, times: list[float]) -> list[str]:
    """Enqueue one ingress row per timestamp; return message ids in seed (FIFO) order."""
    mids: list[str] = []
    for t in times:
        mids.append(await store.enqueue_ingress(channel_id=lane, raw=RAW, now=t))
    return mids


# --- deterministic clock + scheduler seam (O4) ----------------------------------------------------


class _ManualHandle:
    """A ``loop.call_later``-shaped handle: only ``.cancel()`` is exercised by the dispatcher."""

    __slots__ = ("fire_at", "cb", "cancelled")

    def __init__(self, fire_at: float, cb: Callable[[], object]) -> None:
        self.fire_at = fire_at
        self.cb = cb
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


class ManualClock:
    """Injected ``clock`` + ``call_later`` so park/sweep timing is deterministic (no wall-clock sleeps
    for timer logic). ``advance`` fires every due, non-cancelled timer synchronously — the dispatcher's
    ``_on_lane_timer`` callbacks are sync — then the caller ``_settle()``s to let the real claimer /
    serializer asyncio tasks run."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start
        self._armed: list[_ManualHandle] = []

    def time(self) -> float:
        return self.now

    def call_later(self, delay: float, cb: Callable[[], object]) -> asyncio.TimerHandle:
        handle = _ManualHandle(self.now + max(0.0, delay), cb)
        self._armed.append(handle)
        return cast("asyncio.TimerHandle", handle)

    def advance(self, dt: float) -> None:
        self.now += dt
        # Fire due timers one at a time, re-scanning so a callback that arms a follow-up timer is
        # handled in order. Park/backoff timers are always future (fire_at > now), so this terminates;
        # the cap is a defensive guard only.
        for _ in range(100_000):
            due = [h for h in self._armed if not h.cancelled and h.fire_at <= self.now]
            if not due:
                break
            due.sort(key=lambda h: h.fire_at)
            handle = due[0]
            self._armed.remove(handle)
            handle.cb()

    @property
    def armed(self) -> list[_ManualHandle]:
        return [h for h in self._armed if not h.cancelled]


# --- recording AlertSink + process_item stub ------------------------------------------------------


class RecordingAlertSink(LoggingAlertSink):
    """A full :class:`AlertSink` (subclasses the logging default) that records ``connection_stopped``
    and (ADR 0070) ``lane_stuck``."""

    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []
        self.stuck: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))

    def lane_stuck(self, name: str, *, detail: str) -> None:
        self.stuck.append((name, detail))


@dataclass
class _Dispatch:
    lane: str
    item_id: str
    message_id: str
    attempts: int


class RecordingStub:
    """The injected ``process_item`` body. Performs the REAL head store write per outcome (D2) and
    records each ``(lane, item)`` dispatch so a test can assert per-lane FIFO + no concurrent
    double-dispatch. Supports per-lane sequential outcome queues, a callable outcome policy, and an
    optional gate (an ``asyncio.Event``) to pin a lane in PROCESSING."""

    def __init__(self, store: Any, clock: Callable[[], float]) -> None:
        self._store = store
        self._clock = clock
        self.records: list[_Dispatch] = []
        self._outcomes: dict[str, list[str]] = {}
        self._policy: Callable[[str, OutboxItem], str] | None = None
        self._gates: dict[str, asyncio.Event] = {}
        self._active: set[str] = set()  # lanes with an in-flight dispatch — concurrency guard
        self.concurrency_violations = 0
        self.last_retry_until: dict[str, float] = {}

    def program(self, lane: str, outcomes: list[str]) -> None:
        self._outcomes[lane] = list(outcomes)

    def set_policy(self, policy: Callable[[str, OutboxItem], str]) -> None:
        self._policy = policy

    def gate(self, lane: str, ev: asyncio.Event) -> None:
        self._gates[lane] = ev

    def _next_outcome(self, lane: str, item: OutboxItem) -> str:
        queue = self._outcomes.get(lane)
        if queue:
            return queue.pop(0)
        if self._policy is not None:
            return self._policy(lane, item)
        return "RESOLVED"

    async def __call__(self, lane: str, item: OutboxItem) -> LaneItemResult:
        if (
            lane in self._active
        ):  # a second serializer entered this lane concurrently — invariant break
            self.concurrency_violations += 1
        self._active.add(lane)
        try:
            self.records.append(_Dispatch(lane, item.id, item.message_id, item.attempts))
            gate = self._gates.get(lane)
            if gate is not None:
                await gate.wait()  # hold the lane in PROCESSING until the test releases it
            kind = self._next_outcome(lane, item)
            if kind == "RAISE":
                raise RuntimeError(f"process_item boom on {lane}/{item.message_id}")  # T17 path
            if kind == "RESOLVED":
                # The claim already made the row INFLIGHT; leaving it there is the faithful "the body
                # took ownership" stand-in (claim_fifo_heads only claims PENDING, so it is not re-claimed).
                return LaneItemResult(LaneResultKind.RESOLVED)
            if kind == "RETRY":
                nxt = await self._store.mark_failed(
                    item.id, "retry", RetryPolicy(), now=self._clock()
                )
                assert nxt is not None  # default RetryPolicy retries forever → always a float
                self.last_retry_until[lane] = nxt
                return LaneItemResult(LaneResultKind.RETRY, retry_until=nxt)
            # STOP — leave the head INFLIGHT (recovered by reset_stale_inflight in production).
            return LaneItemResult(LaneResultKind.STOP)
        finally:
            self._active.discard(lane)


class _ClaimShim:
    """Wraps the real store, delegating everything (``list_fifo_lanes`` / ``release_claimed`` /
    ``mark_failed`` / ``enqueue_ingress`` / …) EXCEPT ``claim_fifo_heads``, which it intercepts ONCE for
    ``lane`` to unit-test a dispatcher claim-outcome branch the real store only reaches via the intricate
    OUTBOUND H2 path (T10 ``rearm``) or a genuine wake/claim race (T11 EMPTY+dirty)."""

    def __init__(
        self, real: Any, lane: str, *, mode: str, block: asyncio.Event | None = None
    ) -> None:
        self._real = real
        self._lane = lane
        self._mode = mode  # "rearm_once" | "empty_block_once"
        self._block = block
        self._fired = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)  # delegate every non-overridden attribute/method

    async def claim_fifo_heads(
        self, stage: str, lanes: Any, now: float | None = None, *, per_lane_limit: int = 1
    ) -> ClaimedHeads:
        if not self._fired and self._lane in lanes:
            self._fired = True
            if self._mode == "rearm_once":  # T10: head consumed in-store → lane in rearm, no items
                return ClaimedHeads(by_lane={}, rearm=frozenset({self._lane}))
            if self._block is not None:
                await (
                    self._block.wait()
                )  # hold the lane in CLAIMING (T11 wake-during-CLAIMING window)
            return ClaimedHeads(by_lane={}, rearm=frozenset())  # EMPTY
        result = await self._real.claim_fifo_heads(stage, lanes, now, per_lane_limit=per_lane_limit)
        return cast("ClaimedHeads", result)


# --- async settling helpers -----------------------------------------------------------------------

_HUGE_SWEEP = 3600.0  # disable the periodic (real-time) sweep; drive discovery explicitly


async def _settle(rounds: int = 8) -> None:
    """Yield enough (with a little real time) for the claimer/serializer tasks + aiosqlite worker-thread
    round-trips to complete. Not "timer logic" — park/sweep timing is the ManualClock's job."""
    for _ in range(rounds):
        await asyncio.sleep(0.005)


async def _wait_until(pred: Callable[[], bool], timeout: float = 8.0) -> bool:
    """Poll ``pred`` (letting async work run) until true or ``timeout``. Robust against aiosqlite thread
    latency without fixed-iteration flakiness."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if pred():
            return True
        await asyncio.sleep(0.003)
    return pred()


def _make(
    store: Any,
    stub: RecordingStub,
    provider: set[str],
    *,
    per_lane_limit: int = 8,
    claimers_per_stage: int = 1,
    max_processing_lanes: int = 256,
    claim_lane_chunk: int = 200,
    clock: ManualClock,
    alert_sink: RecordingAlertSink | None = None,
    on_lane_paused: Callable[[str], None] | None = None,
    infra_fault_policy: str = "stop",
    infra_fault_stop_after: int = 10,
    infra_fault_backoff_cap: float = 60.0,
) -> StageDispatcher:
    return StageDispatcher(
        Stage.INGRESS,
        store,
        process_item=stub,
        lane_provider=lambda: set(provider),
        per_lane_limit=per_lane_limit,
        claimers_per_stage=claimers_per_stage,
        max_processing_lanes=max_processing_lanes,
        claim_lane_chunk=claim_lane_chunk,
        sweep_interval=_HUGE_SWEEP,
        clock=clock.time,
        call_later=clock.call_later,
        alert_sink=alert_sink or RecordingAlertSink(),
        on_lane_paused=on_lane_paused,
        infra_fault_policy=infra_fault_policy,
        infra_fault_stop_after=infra_fault_stop_after,
        infra_fault_backoff_cap=infra_fault_backoff_cap,
    )


def _first_occurrence_order(
    records: list[_Dispatch], lane: str, index_of: dict[str, int]
) -> list[int]:
    """The seed-indices of a lane's rows in the order they were FIRST dispatched."""
    seen: set[int] = set()
    order: list[int] = []
    for rec in records:
        if rec.lane != lane:
            continue
        idx = index_of[rec.message_id]
        if idx not in seen:
            seen.add(idx)
            order.append(idx)
    return order


# --- tests ----------------------------------------------------------------------------------------


async def test_single_lane_prefix_oldest_first_each_once(store: Any) -> None:
    """Claims a lane's whole contiguous prefix in one shot (per_lane_limit=8), dispatches strictly
    oldest-first, each row exactly once, busy_violations==0, lane ends IDLE."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_PREFIX"
    mids = await _seed(store, lane, [100.0, 101.0, 102.0, 103.0, 104.0])
    d = _make(store, stub, {lane}, clock=mc)
    await d.start()
    try:
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        assert [r.message_id for r in stub.records] == mids  # oldest-first, each once
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
        assert d.processing_lanes == 0
        assert d.slots_free == 256
    finally:
        await d.stop()
    assert d.running is False


async def test_multi_lane_drains_with_per_lane_order(store: Any) -> None:
    """Several lanes seeded → all drain; per-lane order intact; busy_violations==0."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lanes = {f"IB_M{i}" for i in range(5)}
    seeded: dict[str, list[str]] = {}
    for i, lane in enumerate(sorted(lanes)):
        seeded[lane] = await _seed(store, lane, [100.0 + i, 101.0 + i, 102.0 + i])
    d = _make(store, stub, lanes, clock=mc)
    await d.start()
    try:
        assert await _wait_until(
            lambda: all(d.phase(x) == _LanePhase.IDLE for x in lanes) and d.processing_lanes == 0
        )
        for lane, mids in seeded.items():
            got = [r.message_id for r in stub.records if r.lane == lane]
            assert got == mids  # per-lane FIFO
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


async def test_create_or_stick_unknown_lane(store: Any) -> None:
    """T1: mark_ready on a never-registered/seeded lane creates the state READY (create-or-stick);
    once work exists it is claimed."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "NEW_LANE"
    d = _make(
        store, stub, set(), clock=mc
    )  # empty registry: only mark_ready can introduce the lane
    await d.start()
    try:
        assert d.phase(lane) is None  # unknown before the wake
        mids = await _seed(store, lane, [100.0, 101.0])
        d.mark_ready(lane)
        assert d.phase(lane) == _LanePhase.READY  # T1 create-or-stick — synchronous, pre-settle
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        assert [r.message_id for r in stub.records] == mids
        assert d.busy_violations == 0
    finally:
        await d.stop()


async def test_park_then_unpark_on_timer(store: Any) -> None:
    """T15→T18: a RETRY head parks the lane at ``park_until == nxt`` and arms an exact timer; advancing
    the ManualClock past nxt fires the timer → the lane unparks, re-claims, and the head is retried."""
    mc = ManualClock(1000.0)  # small base → mark_failed's next_attempt lands far below real time
    stub = RecordingStub(store, mc.time)
    lane = "IB_PARK"
    mids = await _seed(store, lane, [100.0])
    stub.program(lane, ["RETRY", "RESOLVED"])  # first pass parks, second resolves
    d = _make(store, stub, {lane}, clock=mc)
    await d.start()
    try:
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        nxt = stub.last_retry_until[lane]
        assert d.park_until(lane) == nxt
        assert len([r for r in stub.records if r.lane == lane]) == 1  # dispatched once so far

        mc.advance((nxt - mc.now) + 1.0)  # past the park deadline → fires the park timer
        await _settle()
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        got = [r.message_id for r in stub.records if r.lane == lane]
        assert got == [mids[0], mids[0]]  # retried: the same head dispatched a second time
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


async def test_parked_discarded_on_restart_sweep_reclaims(store: Any) -> None:
    """PARKED state is discarded on restart: a fresh dispatcher's seed-all-READY finds the (still
    backing-off) head → EMPTY → lane IDLE (never PROCESSING); the fresh sweep's head-due timer (armed
    at start) is the SOLE post-restart re-claim path once the backoff elapses."""
    mc = ManualClock(1000.0)
    lane = "IB_RESTART"

    stub1 = RecordingStub(store, mc.time)
    stub1.program(
        lane, ["RETRY"]
    )  # re-pends the head into the future (next_attempt = 1000 + backoff)
    mid = (await _seed(store, lane, [100.0]))[0]
    d1 = _make(store, stub1, {lane}, clock=mc)
    await d1.start()
    assert await _wait_until(lambda: d1.phase(lane) == _LanePhase.PARKED)
    park_until = d1.park_until(lane)
    assert park_until is not None and park_until > mc.now  # backoff deadline is in the future
    await d1.stop()
    assert (
        d1.phase(lane) is None
    )  # PARKED state cleared on teardown — nothing carries to the restart

    # Fresh dispatcher over the SAME store — the still-not-due head must NOT be re-claimed by seed-all.
    stub2 = RecordingStub(store, mc.time)
    stub2.program(lane, ["RESOLVED"])
    d2 = _make(store, stub2, {lane}, clock=mc)
    await d2.start()
    try:
        assert await _wait_until(lambda: d2.phase(lane) == _LanePhase.IDLE)
        await _settle()
        assert stub2.records == []  # not-due head → seed-all-READY claims EMPTY → lane IDLE
        assert d2.processing_lanes == 0
        # d2's OWN immediate sweep armed the head-due re-claim timer (no d1 park timer survived).
        assert lane in d2._timer_deadline
        assert d2._timer_deadline[lane] == pytest.approx(park_until)

        # The backoff elapses: advancing the clock past the head's due time fires the SWEEP-armed timer
        # (the sole post-restart re-claim path), which re-readies the now-due head for the claimer.
        mc.advance((park_until - mc.now) + 1.0)
        await _settle()
        assert await _wait_until(lambda: [r.message_id for r in stub2.records] == [mid])
        assert d2.busy_violations == 0
    finally:
        await d2.stop()


async def test_stop_releases_tail_alerts_then_rearms(store: Any) -> None:
    """T16→T19: a STOP head halts the lane (STOPPED), releases the unprocessed tail (back to PENDING,
    attempts restored), and fires connection_stopped; notify_work re-arms the lane → it re-claims the
    released tail."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    alert = RecordingAlertSink()
    lane = "IB_STOP"
    mids = await _seed(store, lane, [100.0, 101.0, 102.0])
    stub.program(lane, ["STOP", "RESOLVED", "RESOLVED"])  # head STOPs; tail resolves after re-arm
    d = _make(store, stub, {lane}, clock=mc, alert_sink=alert)
    await d.start()
    try:
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.STOPPED)
        # The unprocessed tail was release_claimed'd: PENDING with the claim's +1 attempt undone.
        rows = await _lane_rows(store, lane)
        by_mid = {r["message_id"]: r for r in rows}
        for tail_mid in mids[1:]:
            assert by_mid[tail_mid]["status"] == OutboxStatus.PENDING.value
            assert by_mid[tail_mid]["attempts"] == 0
        assert by_mid[mids[0]]["status"] == OutboxStatus.INFLIGHT.value  # head left INFLIGHT
        assert alert.stopped == [(lane, "ingress lane stopped")]
        assert [r.message_id for r in stub.records] == [mids[0]]  # only the head dispatched so far

        d.notify_work()  # recovery broadcast: STOPPED → READY (override the stop)
        await _settle()
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        # The released tail re-claimed in order; the stranded head is not re-dispatched.
        assert [r.message_id for r in stub.records] == [mids[0], mids[1], mids[2]]
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


async def test_wake_during_processing_sets_dirty_then_rereadies(store: Any) -> None:
    """T5/T14: a wake that lands while a lane is PROCESSING sets the dirty bit; at lane_done the lane
    re-readies (immediate re-claim) instead of going straight to IDLE."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_DIRTY"
    await _seed(store, lane, [100.0])
    gate = asyncio.Event()
    stub.gate(lane, gate)  # pin the lane in PROCESSING
    d = _make(store, stub, {lane}, clock=mc)
    await d.start()
    try:
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PROCESSING)
        d.mark_ready(lane)  # T5 — wake during PROCESSING
        assert d.is_dirty(lane) is True
        gate.set()  # resolve → lane_done sees dirty → re-ready → claim EMPTY → IDLE
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        assert d.busy_violations == 0
    finally:
        await d.stop()


@pytest.mark.parametrize("k", [1, 2])
async def test_slot_budget_exactness(store: Any, k: int) -> None:
    """max_processing_lanes=2 caps concurrent PROCESSING at 2 across 4 gated lanes; slots_free never
    negative; conservation slots_free + processing_lanes == 2 at rest; releasing the gate drains the
    rest. Exercised at claimers_per_stage 1 AND 2."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lanes = {f"IB_SLOT{i}" for i in range(4)}
    gate = asyncio.Event()  # shared: whichever lanes are claimed first hold in PROCESSING
    for lane in lanes:
        await _seed(store, lane, [100.0])
        stub.gate(lane, gate)
    d = _make(store, stub, lanes, claimers_per_stage=k, max_processing_lanes=2, clock=mc)
    await d.start()
    try:
        assert await _wait_until(lambda: d.processing_lanes == 2)
        await _settle()
        assert d.processing_lanes == 2  # budget cap holds
        assert d.slots_free == 0
        assert d.slots_free + d.processing_lanes == 2  # conservation at rest (no claim in flight)

        gate.set()  # release → first wave resolves → slots free → remaining 2 claimed + drained
        assert await _wait_until(
            lambda: all(d.phase(x) == _LanePhase.IDLE for x in lanes) and d.processing_lanes == 0
        )
        assert d.slots_free == 2
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


async def test_teardown_cancels_cleanly(store: Any) -> None:
    """With a live PROCESSING lane + an armed park timer, stop() cancels/gathers cleanly (no leaked
    tasks) and clears state."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane_proc, lane_park = "IB_TD_PROC", "IB_TD_PARK"
    await _seed(store, lane_proc, [100.0])
    await _seed(store, lane_park, [100.0])
    gate = asyncio.Event()  # never set → lane_proc stays PROCESSING until cancelled
    stub.gate(lane_proc, gate)
    stub.program(lane_park, ["RETRY"])  # → PARKED with an armed timer
    d = _make(store, stub, {lane_proc, lane_park}, clock=mc)
    await d.start()
    assert await _wait_until(
        lambda: (
            d.phase(lane_proc) == _LanePhase.PROCESSING and d.phase(lane_park) == _LanePhase.PARKED
        )
    )
    assert lane_park in d._timers  # a park timer is armed
    await d.stop()  # must not raise / leak the gated serializer or the timer
    assert d.running is False
    assert d.phase(lane_proc) is None and d.phase(lane_park) is None  # state cleared post-gather
    assert d.processing_lanes == 0
    assert d.slots_free == 256
    assert d.busy_violations == 0


async def test_sweep_readies_due_lane_and_arms_timer_for_not_due(store: Any) -> None:
    """The clock-driven sweep discovers a due lane via list_fifo_lanes and claims it (no producer
    wake); a not-due head yields an armed timer, never an immediate claim."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    due_lane, not_due_lane = "IB_SWEEP_DUE", "IB_SWEEP_ND"
    not_due_at = 6000.0  # > the ManualClock base (1000) → not-due to both the claim and the sweep
    await _seed(store, not_due_lane, [not_due_at])
    d = _make(store, stub, {due_lane, not_due_lane}, clock=mc)
    await (
        d.start()
    )  # seed-all-READY claims EMPTY for both (due_lane unseeded, not_due head not due)
    try:
        assert await _wait_until(
            lambda: (
                d.phase(due_lane) == _LanePhase.IDLE and d.phase(not_due_lane) == _LanePhase.IDLE
            )
        )
        # The immediate sweep armed a timer for the not-due head at its exact due time.
        assert not_due_lane in d._timer_deadline
        assert d._timer_deadline[not_due_lane] == pytest.approx(not_due_at)

        # Work arrives on the due lane WITHOUT a producer wake — only the sweep can discover it.
        due_mids = await _seed(store, due_lane, [100.0, 101.0])
        await d._run_sweep_once()
        await _settle()
        assert await _wait_until(lambda: d.phase(due_lane) == _LanePhase.IDLE)
        assert [r.message_id for r in stub.records if r.lane == due_lane] == due_mids
        # The not-due lane was never claimed; its timer is still armed.
        assert [r for r in stub.records if r.lane == not_due_lane] == []
        assert not_due_lane in d._timer_deadline
        assert d._timer_deadline[not_due_lane] == pytest.approx(not_due_at)
        assert d.busy_violations == 0
    finally:
        await d.stop()


async def test_busy_violation_soak_200_lanes(store: Any) -> None:
    """200-lane soak: a randomized (fixed-seed) mix of RESOLVED/RETRY/STOP outcomes + random gate holds,
    driven by a randomized interleave of mark_ready / clock advances / sweeps / notify_work. Asserts
    busy_violations==0, no concurrent double-dispatch, every seeded row dispatched, and per-lane FIFO
    (first-dispatch order) preserved. (RETRY legitimately RE-dispatches a head, so "no double-dispatch"
    is the concurrency invariant — never two consumers on one lane at once — not "≤1 dispatch/row".)"""
    rng = random.Random(0xC0FFEE)
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)

    lanes = [f"IB_SOAK_{i:03d}" for i in range(200)]
    provider = set(lanes)
    seeded: dict[str, list[str]] = {}
    index_of: dict[str, int] = {}
    for lane in lanes:
        n = rng.randint(1, 3)
        mids = await _seed(store, lane, [100.0 + j for j in range(n)])
        seeded[lane] = mids
        for j, mid in enumerate(mids):
            index_of[mid] = j

    retry_rows = {mid for mids in seeded.values() for mid in mids if rng.random() < 0.15}
    stop_lanes = {lane for lane, mids in seeded.items() if len(mids) >= 2 and rng.random() < 0.10}
    gated = {lane for lane in lanes if rng.random() < 0.20}
    retry_fired: set[str] = set()
    stop_fired: set[str] = set()

    def policy(lane: str, item: OutboxItem) -> str:
        # Terminating by construction: each lane STOPs at most once (its head, first dispatch), each row
        # RETRYs at most once, everything else RESOLVES.
        if lane in stop_lanes and lane not in stop_fired:
            stop_fired.add(lane)
            return "STOP"
        if item.message_id in retry_rows and item.message_id not in retry_fired:
            retry_fired.add(item.message_id)
            return "RETRY"
        return "RESOLVED"

    stub.set_policy(policy)
    gate = asyncio.Event()
    for lane in gated:
        stub.gate(lane, gate)

    d = _make(store, stub, provider, max_processing_lanes=32, clock=mc)
    await d.start()
    try:
        for it in range(60):
            action = rng.randint(0, 3)
            if action == 0:
                for lane in rng.sample(lanes, k=rng.randint(1, 20)):
                    d.mark_ready(lane)
            elif action == 1:
                mc.advance(rng.uniform(1.0, 30.0))  # fire park timers
            elif action == 2:
                await d._run_sweep_once()
            else:
                d.notify_work()
            if it == 12:
                gate.set()  # release the held lanes partway through
            await _settle(rounds=2)

        # Force-drain to quiescence. Each round KICKS (notify_work re-arms STOPPED/PARKED lanes;
        # advancing the clock EVERY round makes every backed-off head due — a RETRY re-pended mid-drain
        # parks at clock()+backoff, so the clock must keep moving or its tail strands behind a frozen
        # park timer; the sweep discovers re-pends), then lets the claimer drain the re-armed lanes to
        # IDLE via a QUIET poll (no re-ready during the poll, so it actually converges instead of the
        # notify_work treadmill re-queueing all 200 lanes faster than one settle can drain them). A
        # retry that fires during the quiet poll simply parks and is picked up by the next kick; retry
        # budgets are finite (each row retries once), so this terminates.
        gate.set()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 30.0
        drained = False

        def _quiescent() -> bool:
            return d.processing_lanes == 0 and all(
                d.phase(x) in (None, _LanePhase.IDLE) for x in lanes
            )

        while loop.time() < deadline:
            d.notify_work()
            mc.advance(1_000_000.0)
            await d._run_sweep_once()
            if await _wait_until(_quiescent, timeout=3.0):
                drained = True
                break
        assert drained, "soak did not reach quiescence"

        # --- invariants ---
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
        dispatched = {r.message_id for r in stub.records}
        assert dispatched == set(index_of)  # every seeded row was dispatched
        for lane, mids in seeded.items():
            order = _first_occurrence_order(stub.records, lane, index_of)
            assert order == list(range(len(mids)))  # per-lane FIFO on first dispatch
    finally:
        await d.stop()


async def test_t17_raising_body_releases_head_and_tail_no_overtake(store: Any) -> None:
    """T17 (the CONFIRMED FIFO-bug guard): a body that RAISES on the head releases ``items[i:]`` — the
    unhandled head AND its tail — back to PENDING (the head is NEVER stranded INFLIGHT) and PARKS the
    lane ~1s; the timer then re-claims head-first, so the head's successful dispatch precedes any
    successor and no row is lost. FAILS against the old ``items[1:]`` release (head stranded INFLIGHT,
    successors overtake it)."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_RAISE"
    mids = await _seed(store, lane, [100.0, 101.0, 102.0])
    stub.program(
        lane, ["RAISE", "RESOLVED", "RESOLVED", "RESOLVED"]
    )  # head raises, then all resolve
    # Drive the claim via mark_ready with an EMPTY lane_provider (mirrors T10/T11) rather than
    # seeding IB_RAISE into the provider. With provider={lane}, start()'s immediate sweep OWNS this
    # lane and can race the serializer: the RAISE path's release_claimed restores the head's ORIGINAL
    # (past-due) next_attempt_at while the lane parks until clock()+1s, so a sweep landing just after
    # the park sees a DUE head and UNPARKS the lane (the T18 backstop keys off the head's
    # next_attempt_at, not park_until) — it re-claims and RESOLVES the whole prefix to IDLE. That
    # DESTROYS (not merely delays) the intermediate PARKED + all-PENDING state this test inspects, so
    # no wait can recover it; it is deterministic on the slow 2-vCPU SS-2025 CI runner (where the
    # startup sweep's list_fifo_lanes is slow enough to land after the park). Keeping IB_RAISE out of
    # the provider excludes it from the sweep's owned set, so the lane parks deterministically. Every
    # assertion below is unchanged and stays non-vacuous — the timer-driven re-claim, the discriminating
    # all-PENDING store check, and the no-overtake order all still hold (and still fail on the old
    # items[1:] release that stranded the head INFLIGHT).
    d = _make(store, stub, set(), clock=mc)
    await d.start()
    try:
        d.mark_ready(lane)  # claim WITHOUT the startup sweep owning the lane (see the note above)
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        park_until = d.park_until(lane)
        assert park_until is not None
        assert park_until == pytest.approx(1001.0)  # clock() + _LANE_ERROR_BACKOFF_SECONDS (1.0)
        # THE discriminating store assertion: head + tail are ALL back to PENDING (head NOT stranded
        # INFLIGHT) with attempts restored — this is what the old items[1:] release got wrong.
        rows = await _lane_rows(store, lane)
        assert [r["status"] for r in rows] == [OutboxStatus.PENDING.value] * 3
        assert [r["attempts"] for r in rows] == [0, 0, 0]
        assert [r.message_id for r in stub.records] == [mids[0]]  # only the raising dispatch so far

        mc.advance((park_until - mc.now) + 1.0)  # past the backoff → re-claim, head-first
        await _settle()
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        # Head re-claimed and resolved BEFORE any successor's dispatch — no overtake, nothing lost.
        assert [r.message_id for r in stub.records] == [mids[0], mids[0], mids[1], mids[2]]
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


async def test_t10_rearm_reready_then_reclaim(store: Any) -> None:
    """T10: a claim whose lane comes back in ``ClaimedHeads.rearm`` (head consumed in-store) re-readies
    the lane (CLAIMING→READY, NOT IDLE) so the next claim drains it. A ``_ClaimShim`` returns ``rearm``
    once; the lane is kept OUT of the registry so no sweep can rescue a broken (→IDLE) transition."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_REARM"
    mids = await _seed(store, lane, [100.0, 101.0])
    shim = _ClaimShim(store, lane, mode="rearm_once")
    d = _make(shim, stub, set(), clock=mc)
    await d.start()
    try:
        d.mark_ready(lane)  # first claim → rearm → MUST re-ready (not IDLE); second claim drains it
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        assert [r.message_id for r in stub.records] == mids  # only reachable via the T10 re-claim
        assert d.busy_violations == 0
    finally:
        await d.stop()


async def test_t11_wake_during_claiming_empty_dirty_rereadies(store: Any) -> None:
    """T11 (distinct from T4/T5): a wake landing while the lane is CLAIMING sets dirty; an EMPTY claim
    for a dirty lane re-readies (immediate re-claim), never falling through to IDLE. A ``_ClaimShim``
    blocks the first claim in CLAIMING then returns EMPTY; the lane is kept OUT of the registry so a
    broken (→IDLE) transition cannot be masked by the sweep."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_CLAIMWAKE"
    mids = await _seed(store, lane, [100.0])
    blocker = asyncio.Event()
    shim = _ClaimShim(store, lane, mode="empty_block_once", block=blocker)
    d = _make(shim, stub, set(), clock=mc)
    await d.start()
    try:
        d.mark_ready(lane)
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.CLAIMING)
        d.mark_ready(lane)  # T4 — wake DURING the (blocked) claim
        assert d.is_dirty(lane) is True
        blocker.set()  # the first claim returns EMPTY → EMPTY+dirty must re-ready (T11), not go IDLE
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        assert [
            r.message_id for r in stub.records
        ] == mids  # re-claim happened (else records empty)
        assert d.busy_violations == 0
    finally:
        await d.stop()


async def test_small_claim_chunk_covers_remainder(store: Any) -> None:
    """SF2 — the ``claim_lane_chunk`` clamp: a chunk (3) smaller than the ready set (7) drains every
    lane across successive claimer passes (the ready-deque holds the remainder); none stranded."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lanes = {f"IB_CHUNK{i}" for i in range(7)}
    seeded: dict[str, str] = {}
    for lane in lanes:
        seeded[lane] = (await _seed(store, lane, [100.0]))[0]
    d = _make(store, stub, lanes, claim_lane_chunk=3, clock=mc)
    await d.start()
    try:
        assert await _wait_until(
            lambda: all(d.phase(x) == _LanePhase.IDLE for x in lanes) and d.processing_lanes == 0
        )
        dispatched = {r.message_id for r in stub.records}
        assert dispatched == set(seeded.values())  # all 7 rows dispatched, none stranded
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


# --- ADR 0070: bounding a persistent pooled T17 infra fault --------------------------------------
#
# All lanes below are kept OUT of the lane_provider (empty set) and driven via mark_ready + explicit
# ManualClock advances so the startup/periodic sweep never OWNS them and cannot race the serializer —
# the same isolation the confirmed-bug test above relies on. Under fix A the T17 head is re-pended
# NOT-due, so the ONLY re-claim path is the park timer fired by advancing the clock past the deadline.


class _MarkSpy:
    """Wraps the real store, delegating everything, but COUNTS ``mark_failed`` / ``dead_letter_now`` so a
    test can assert the T17 machinery path never touches the content dead-letter ledger (ADR 0070 §5)."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self.mark_failed_calls = 0
        self.dead_letter_calls = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    async def mark_failed(self, *args: Any, **kwargs: Any) -> Any:
        self.mark_failed_calls += 1
        return await self._real.mark_failed(*args, **kwargs)

    async def dead_letter_now(self, *args: Any, **kwargs: Any) -> Any:
        self.dead_letter_calls += 1
        return await self._real.dead_letter_now(*args, **kwargs)


def _always_raise(lane: str, item: OutboxItem) -> str:
    return "RAISE"


async def _advance_past_park(d: StageDispatcher, mc: ManualClock, lane: str) -> None:
    """Advance the ManualClock just past ``lane``'s current park deadline so its park timer fires,
    re-claiming the (not-due) faulting head → the next infra fault. Settles the async work after."""
    pu = d.park_until(lane)
    assert pu is not None, f"expected {lane} PARKED with a deadline"
    mc.advance((pu - mc.now) + 0.5)
    await _settle()


async def _drive_infra_faults_until_stop(
    d: StageDispatcher, mc: ManualClock, lane: str, *, budget: int
) -> None:
    """Drive an always-faulting lane to STOPPED by repeatedly firing its park timer, bounded by
    ``budget`` iterations (a guard against a non-terminating loop if the bound regressed)."""
    for _ in range(budget):
        assert await _wait_until(lambda: d.phase(lane) in (_LanePhase.PARKED, _LanePhase.STOPPED))
        if d.phase(lane) == _LanePhase.STOPPED:
            return
        await _advance_past_park(d, mc, lane)
    raise AssertionError(f"{lane} did not STOP within {budget} faults")


async def test_adr0070_1_stop_policy_bounds_deterministic_infra_head(store: Any) -> None:
    """ADR 0070 test 1 (stop): a head that always raises T17 reaches STOPPED after EXACTLY
    ``infra_fault_stop_after`` consecutive zero-progress faults, emits ONE connection_stopped naming
    stage+lane+streak, and performs NO store terminal write — the head stays PENDING (fix A), never
    DEAD, attempts never inflated (the G6 ceiling is untouched)."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    stub.set_policy(_always_raise)
    alert = RecordingAlertSink()
    lane = "IB_INFRA_STOP"
    await _seed(store, lane, [100.0])
    d = _make(store, stub, set(), clock=mc, alert_sink=alert, infra_fault_stop_after=4)
    await d.start()
    try:
        d.mark_ready(lane)  # first claim → first infra fault
        await _drive_infra_faults_until_stop(d, mc, lane, budget=8)
        assert d.phase(lane) == _LanePhase.STOPPED
        assert d.infra_error_streak(lane) == 4  # reached the configured threshold exactly
        assert len([r for r in stub.records if r.lane == lane]) == 4  # exactly 4 faults, no more
        # Exactly one connection_stopped, naming the stage + streak.
        assert len(alert.stopped) == 1
        name, detail = alert.stopped[0]
        assert name == lane
        assert "ingress" in detail and "4 consecutive" in detail
        # NO terminal store write: the head is still PENDING (preserved by fix A), never DEAD, and its
        # attempts are back to baseline (the claim's +1 undone by each reschedule — never inflated).
        rows = await _lane_rows(store, lane)
        assert [r["status"] for r in rows] == [OutboxStatus.PENDING.value]
        assert rows[0]["attempts"] == 0
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


async def test_adr0070_1_retry_forever_never_stops_alerts_stuck(store: Any) -> None:
    """ADR 0070 test 1 (retry_forever): the same always-raising head NEVER STOPs and NEVER dead-letters
    — it parks at capped backoff forever and emits the throttled ``lane_stuck`` alert ONCE, the first
    time the streak crosses the stuck horizon. No connection_stopped ever fires."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    stub.set_policy(_always_raise)
    alert = RecordingAlertSink()
    lane = "IB_INFRA_FOREVER"
    await _seed(store, lane, [100.0])
    d = _make(
        store,
        stub,
        set(),
        clock=mc,
        alert_sink=alert,
        infra_fault_policy="retry_forever",
        infra_fault_stop_after=4,  # the stuck horizon (never a STOP under retry_forever)
    )
    await d.start()
    try:
        d.mark_ready(lane)
        for _ in range(7):  # well past the horizon
            assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
            assert d.phase(lane) != _LanePhase.STOPPED  # never terminal
            await _advance_past_park(d, mc, lane)
        # WAIT for the post-advance retry cycle (unpark → claim → re-fault → re-park) to settle back to
        # PARKED — instant-asserting it flakes on the real SS/PG backends, where the store round-trip
        # outlasts _advance_past_park's fixed _settle() and catches the lane mid-cycle in PROCESSING
        # (mirrors test 9's post-loop _wait_until). The invariant under test is unchanged: still PARKED,
        # never STOPPED.
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        assert d.infra_error_streak(lane) >= 7  # streak keeps accruing (drives the backoff)
        assert alert.stopped == []  # never STOPs
        assert len(alert.stuck) == 1  # throttled: emitted ONCE at the horizon crossing
        assert alert.stuck[0][0] == lane and "retry_forever" in alert.stuck[0][1]
        # Still no terminal store write — the good message is preserved PENDING.
        rows = await _lane_rows(store, lane)
        assert rows[0]["status"] == OutboxStatus.PENDING.value
    finally:
        await d.stop()


async def test_adr0070_2_transient_infra_fault_self_heals(store: Any) -> None:
    """ADR 0070 test 2: a head that raises k < threshold times then succeeds resets the streak to 0 on
    the resolving pass; the lane never STOPs and never fires connection_stopped."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    alert = RecordingAlertSink()
    lane = "IB_TRANSIENT"
    mid = (await _seed(store, lane, [100.0]))[0]
    stub.program(lane, ["RAISE", "RAISE", "RESOLVED"])  # k=2 faults, then heal
    d = _make(store, stub, set(), clock=mc, alert_sink=alert, infra_fault_stop_after=10)
    await d.start()
    try:
        d.mark_ready(lane)  # fault 1
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        assert d.infra_error_streak(lane) == 1
        await _advance_past_park(d, mc, lane)  # fault 2
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        assert d.infra_error_streak(lane) == 2
        await _advance_past_park(d, mc, lane)  # resolves → clean drain
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        assert d.infra_error_streak(lane) == 0  # streak reset on the resolving pass
        assert alert.stopped == []  # never STOPped
        assert [r.message_id for r in stub.records] == [mid, mid, mid]  # head retried head-first
    finally:
        await d.stop()


async def test_adr0070_3_streak_reset_scoping_sharp_edge(store: Any) -> None:
    """ADR 0070 test 3 (THE sharp edge): the streak ACCRUES across a PARKED park-timer ``_unpark`` (it
    must NOT reset there, or the ``stop`` threshold never accrues and the ~4×/s spin silently returns),
    then STOPs; and it resets ONLY on the STOPPED→``notify_work`` resume. A single always-faulting lane
    with ``stop_after=3`` proves both: the streak climbs 1→2→3 across park-timer unparks (reset there
    would pin it at 1 forever), and drops to 0 on the reload broadcast."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    stub.set_policy(_always_raise)
    lane = "IB_SCOPE"
    await _seed(store, lane, [100.0])
    d = _make(store, stub, set(), clock=mc, infra_fault_stop_after=3)
    await d.start()
    try:
        d.mark_ready(lane)  # fault 1
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        assert d.infra_error_streak(lane) == 1

        await _advance_past_park(d, mc, lane)  # park-timer unpark → fault 2
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        assert d.infra_error_streak(lane) == 2  # ACCRUED across the park-timer unpark (not reset)

        await _advance_past_park(d, mc, lane)  # park-timer unpark → fault 3 == threshold → STOP
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.STOPPED)
        assert d.infra_error_streak(lane) == 3

        d.notify_work()  # STOPPED→READY reload resume — the ONLY reset path for a stopped lane
        await _settle()
        assert d.infra_error_streak(lane) == 0  # reset on resume
        assert d.phase(lane) != _LanePhase.STOPPED
    finally:
        await d.stop()


async def test_adr0070_3b_streak_resets_on_forward_progress(store: Any) -> None:
    """ADR 0070 test 3 (companion): a forward-progress fault (``i>0`` — the batched-prefix case where
    the head RESOLVED and a later item raised) RESETS the streak, distinct from the head-of-line-blocked
    (``i==0``) fault that accrues it. Round 1 faults at the head (streak→1); round 2 resolves the head
    then faults at ``i==1`` → the streak resets to 0."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_FWDPROG"
    mids = await _seed(store, lane, [100.0, 101.0])
    # Round 1: head (row0) raises at i=0. Round 2: row0 RESOLVES, row1 raises at i=1 (forward progress).
    stub.program(lane, ["RAISE", "RESOLVED", "RAISE", "RESOLVED"])
    d = _make(store, stub, set(), clock=mc, per_lane_limit=8, infra_fault_stop_after=10)
    await d.start()
    try:
        d.mark_ready(lane)  # round 1: i==0 head fault
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        assert d.infra_error_streak(lane) == 1  # zero-progress fault accrued

        await _advance_past_park(d, mc, lane)  # round 2: head RESOLVES, row1 raises at i==1
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        assert d.infra_error_streak(lane) == 0  # forward-progress fault RESET the streak
        assert mids[0] in {r.message_id for r in stub.records}
    finally:
        await d.stop()


async def test_adr0070_4_fifo_head_first_after_stop(store: Any) -> None:
    """ADR 0070 test 4: on T17 the released set is ``items[i:]`` (head re-pended + tail released, both
    PENDING — never ``items[1:]`` which strands the head INFLIGHT); after STOP the faulting head keeps
    position 0 / lowest rowid and is re-claimed BEFORE any sibling on reload."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_FIFO_STOP"
    mids = await _seed(store, lane, [100.0, 101.0, 102.0])
    # Only the head raises; a head-of-line-blocked lane never reaches the tail until the head clears.
    healed = {"on": False}

    def policy(lane_: str, item: OutboxItem) -> str:
        if healed["on"]:
            return "RESOLVED"
        return "RAISE" if item.message_id == mids[0] else "RESOLVED"

    stub.set_policy(policy)
    d = _make(store, stub, set(), clock=mc, per_lane_limit=8, infra_fault_stop_after=2)
    await d.start()
    try:
        d.mark_ready(lane)
        await _drive_infra_faults_until_stop(d, mc, lane, budget=6)
        assert d.phase(lane) == _LanePhase.STOPPED
        # The whole failed set items[i:] is back to PENDING — the head NOT stranded INFLIGHT.
        rows = await _lane_rows(store, lane)
        assert [r["status"] for r in rows] == [OutboxStatus.PENDING.value] * 3
        assert [r["attempts"] for r in rows] == [0, 0, 0]
        assert [r["message_id"] for r in rows] == mids  # head keeps position 0 / lowest rowid
        head_next = rows[0]["next_attempt_at"]

        # Reload + heal: the preserved head is re-claimed head-first, before any sibling.
        healed["on"] = True
        mc.advance((head_next - mc.now) + 1.0)  # make the re-pended head due again
        n_before = len(stub.records)
        d.notify_work()
        await _settle()
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        resumed = [r.message_id for r in stub.records[n_before:]]
        assert resumed == mids  # head first, then the tail — strict FIFO, no overtake
        assert d.busy_violations == 0
    finally:
        await d.stop()


async def test_adr0070_5_content_ledger_untouched_by_infra_episode(store: Any) -> None:
    """ADR 0070 test 5: the T17 machinery path never calls ``mark_failed`` / ``dead_letter_now`` and
    never inflates ``attempts`` / the G6 ceiling — an infra outage cannot trip the content dead-letter
    path. Asserted across a multi-fault infra episode with a call-counting store spy."""
    mc = ManualClock(1000.0)
    spy = _MarkSpy(store)
    stub = RecordingStub(spy, mc.time)
    stub.set_policy(_always_raise)
    lane = "IB_LEDGER"
    await _seed(store, lane, [100.0])
    d = _make(spy, stub, set(), clock=mc, infra_fault_stop_after=3)
    await d.start()
    try:
        d.mark_ready(lane)
        await _drive_infra_faults_until_stop(d, mc, lane, budget=6)
        assert d.phase(lane) == _LanePhase.STOPPED
        # The infra path is off the content ledger entirely.
        assert spy.mark_failed_calls == 0
        assert spy.dead_letter_calls == 0
        rows = await _lane_rows(store, lane)
        assert rows[0]["status"] == OutboxStatus.PENDING.value  # never DEAD
        assert rows[0]["attempts"] == 0  # attempts never inflated across the episode
    finally:
        await d.stop()


async def test_adr0070_6_spin_collapses_to_backoff(store: Any) -> None:
    """ADR 0070 test 6 (fix A): with the head re-pended NOT-due, ``list_fifo_lanes`` reports it not-due
    and the sweep's T21 else-branch arms an exact re-claim timer instead of UNPARKING — so repeated
    sweeps between backoff deadlines drive NO busy re-claim (the ~4×/s spin is gone). The old plain
    release left the head past-due, so the sweep re-readied it every pass — this test fails against it."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    stub.set_policy(_always_raise)
    lane = "IB_SPIN"
    prov: set[str] = set()  # start OUT of the provider so the fault is deterministic
    await _seed(store, lane, [100.0])
    d = _make(store, stub, prov, clock=mc, infra_fault_stop_after=50)
    await d.start()
    try:
        d.mark_ready(lane)  # one infra fault → head re-pended not-due
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        park_until = d.park_until(lane)
        assert park_until is not None and park_until > mc.now  # future deadline

        # THE fix-A store fact: list_fifo_lanes reports the head NOT-due (> now). The old release left
        # it past-due (<= now), which is exactly what re-readied it ~4×/s.
        lanes = await store.list_fifo_lanes(Stage.INGRESS.value, now=mc.now)
        head_due = {ln: due for ln, due in lanes}[lane]
        assert head_due > mc.now
        assert head_due == pytest.approx(park_until)

        # Now let the sweep OWN the lane and run it repeatedly WITHOUT advancing the clock: the not-due
        # head must arm a timer (T21 else-branch), never ready/unpark, never re-dispatch.
        prov.add(lane)
        n_before = len(stub.records)
        for _ in range(3):
            await d._run_sweep_once()
            await _settle()
        assert d.phase(lane) == _LanePhase.PARKED  # never re-readied by the sweep
        assert len(stub.records) == n_before  # NO busy re-claim between deadlines — spin collapsed
        assert lane in d._timer_deadline  # armed via the T21 else-branch
        assert d._timer_deadline[lane] == pytest.approx(head_due)
    finally:
        await d.stop()


async def test_adr0070_7_reload_resumes_idempotently(store: Any) -> None:
    """ADR 0070 test 7: a STOPPED lane, after ``notify_work``, re-arms with the streak reset to 0 and
    re-runs the PRESERVED head; it re-STOPs cleanly after another full threshold window if the fault
    persists (zero data loss), and DRAINS if the cause is fixed."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    healed = {"on": False}
    stub.set_policy(lambda lane_, item: "RESOLVED" if healed["on"] else "RAISE")
    lane = "IB_RELOAD"
    mid = (await _seed(store, lane, [100.0]))[0]
    d = _make(store, stub, set(), clock=mc, infra_fault_stop_after=3)
    await d.start()
    try:
        d.mark_ready(lane)
        await _drive_infra_faults_until_stop(d, mc, lane, budget=6)
        assert d.phase(lane) == _LanePhase.STOPPED
        rows = await _lane_rows(store, lane)
        assert rows[0]["status"] == OutboxStatus.PENDING.value  # head preserved

        # Reload while STILL faulting: advance past the re-pended head's deadline, resume, re-STOP.
        mc.advance((rows[0]["next_attempt_at"] - mc.now) + 1.0)
        d.notify_work()
        await _settle()
        assert (
            d.infra_error_streak(lane) == 0 or d.phase(lane) != _LanePhase.STOPPED
        )  # reset on resume
        await _drive_infra_faults_until_stop(d, mc, lane, budget=6)
        assert d.phase(lane) == _LanePhase.STOPPED  # re-STOPs cleanly, no data loss
        rows = await _lane_rows(store, lane)
        assert rows[0]["status"] == OutboxStatus.PENDING.value  # head STILL preserved (zero loss)
        assert rows[0]["attempts"] == 0

        # Now fix the cause: reload → the preserved head drains.
        healed["on"] = True
        mc.advance((rows[0]["next_attempt_at"] - mc.now) + 1.0)
        d.notify_work()
        await _settle()
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        assert mid in {
            r.message_id for r in stub.records
        }  # the SAME preserved head, finally delivered
    finally:
        await d.stop()


async def test_adr0070_8_correlated_outage_single_reload_rearms_all(store: Any) -> None:
    """ADR 0070 test 8: N lanes STOP under one (store-down-style) root cause; each emits its own
    connection_stopped (ADR-0044 durable dedup collapses them to one operator signal downstream), and a
    SINGLE ``notify_work`` reload broadcast re-arms ALL of them with the streak reset."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    stub.set_policy(_always_raise)  # the shared root cause: every lane's handoff raises
    alert = RecordingAlertSink()
    lanes = [f"IB_OUTAGE_{i}" for i in range(4)]
    for lane in lanes:
        await _seed(store, lane, [100.0])
    d = _make(store, stub, set(), clock=mc, alert_sink=alert, infra_fault_stop_after=2)
    await d.start()
    try:
        for lane in lanes:
            d.mark_ready(lane)
        # Drive every lane to STOP (stop_after=2 → two faults each). GENEROUSLY bounded, not a fixed
        # round count: the slow SQL Server 2025 async needs more advance/settle rounds than
        # SQLite/SS-2022 to march all four lanes through both faults + the STOP latch. Each round fires
        # the (due) park timers and settles; once a lane STOPs it stays STOPPED, so the loop just needs
        # enough rounds for the slowest lane — 30 is far past the ~2 a fast backend takes.
        for _ in range(30):
            if all(d.phase(ln) == _LanePhase.STOPPED for ln in lanes):
                break
            mc.advance(120.0)  # past every lane's capped backoff → fire all park timers
            await _settle(rounds=20)
        assert all(d.phase(ln) == _LanePhase.STOPPED for ln in lanes)
        # Each stopped lane emitted its own connection_stopped (the dedup is downstream, ADR 0044).
        assert {name for name, _ in alert.stopped} == set(lanes)

        # The shared root cause CLEARS (e.g. the store recovers); a single reload re-arms every stopped
        # lane. Clearing the fault BEFORE the reload is load-bearing: with the always-raise policy still
        # active a re-armed lane can immediately re-fault and re-accrue the streak, racing the streak==0
        # check — deterministically lost on the slower SQL Server backend (where the head's capped
        # backoff can already be due when the reload lands).
        stub.set_policy(lambda _lane, _item: "RESOLVED")
        d.notify_work()  # ONE reload broadcast re-arms every stopped lane at once
        await _settle()
        for lane in lanes:
            assert d.phase(lane) != _LanePhase.STOPPED  # re-armed off STOPPED
        # Reset + clean drain is stable now (no re-fault): every streak back to 0.
        assert await _wait_until(lambda: all(d.infra_error_streak(ln) == 0 for ln in lanes))
        assert d.busy_violations == 0
    finally:
        await d.stop()


async def test_adr0070_9_content_retry_is_not_an_infra_fault(store: Any) -> None:
    """ADR 0070 test 9 (sharp edge 2 — the discriminator): a repeated CONTENT retry (the body
    ``mark_failed``s its head — a message-content re-pend, ``i==0`` / ``made_progress=False``) must NOT
    be counted as a T17 machinery/infra fault, so it never accrues ``infra_error_streak`` and never
    trips the infra STOP — the ADR's "content ledger untouched by an infra episode" guarantee. With
    ``stop_after=3``, driving SIX consecutive content retries (twice past the infra threshold) keeps the
    streak at 0 and the lane PARKED/retrying, never STOPPED, with no ``connection_stopped``.

    Non-vacuous: an ``is_infra_fault=True`` mutant on the content-RETRY return would accrue the streak
    and STOP the lane on message-content poison at the 3rd retry — this test would then fail on the
    streak/STOP/alert assertions."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    stub.set_policy(
        lambda _lane, _item: "RETRY"
    )  # every pass is a content mark_failed, never an infra raise
    lane = "IB_CONTENT_RETRY"
    alert = RecordingAlertSink()
    await _seed(store, lane, [100.0])
    d = _make(store, stub, set(), clock=mc, alert_sink=alert, infra_fault_stop_after=3)
    await d.start()
    try:
        d.mark_ready(lane)  # content retry 1
        for n in range(6):  # drive 6 content retries — twice past stop_after=3
            assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
            assert d.infra_error_streak(lane) == 0, (
                f"content retry accrued the infra streak after retry {n + 1}"
            )
            assert d.phase(lane) != _LanePhase.STOPPED
            await _advance_past_park(d, mc, lane)  # park-timer unpark → next content retry
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        assert d.infra_error_streak(lane) == 0
        assert d.phase(lane) != _LanePhase.STOPPED
        assert alert.stopped == []  # the infra STOP never fired on message-content poison
    finally:
        await d.stop()


async def test_wakeless_backlog_drains_greedily_not_sweep_gated(store: Any) -> None:
    """T13b regression (failover-recovery drain): a wake-less single-lane backlog — a promoted node's
    recovered residue, seed/sweep-sourced with NO producer wakes — must drain at the CLAIM rate, not one
    row per ``sweep_interval``. With ``sweep_interval`` deliberately LARGE (5s), the old one-row-per-sweep
    behavior would need ~N×5s = 100s to clear N=20 rows (and strand them in any bounded drain window); the
    greedy T13b re-arm clears them in well under a second off the start-time seed. Assert full drain within
    a budget far below the sweep-gated floor, so a regression (losing T13b) fails as a timeout."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_Load_ADT"
    n = 20
    mids = await _seed(
        store, lane, [100.0 + i for i in range(n)]
    )  # ingress rows (create the message FKs)

    d = StageDispatcher(
        Stage.INGRESS,
        store,
        process_item=stub,
        lane_provider=lambda: {lane},
        per_lane_limit=1,  # the shipped default (fifo_claim_batch=1) — every claim is a "full" batch
        sweep_interval=5.0,  # LARGE: sweep-gated draining would need ~n×5s; greedy T13b ignores it
        clock=mc.time,
    )
    await d.start()  # seed-all-READY (woken=False), NO explicit producer wake
    try:
        # 8s budget << the ~100s a sweep-gated (1 row / 5s) drain would take: only the greedy re-arm passes.
        # (RESOLVED leaves each claimed row INFLIGHT, so the stub records exactly one dispatch per row.)
        assert await _wait_until(lambda: len(stub.records) >= n, timeout=8.0), (
            "wake-less backlog did not drain greedily"
        )
        assert [
            r.message_id for r in stub.records if r.lane == lane
        ] == mids  # per-lane FIFO preserved
        remaining, _ = await store.pending_depth(lane, stage=Stage.INGRESS.value)
        assert remaining == 0, f"backlog left {remaining} pending"
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


# --- connection controls: operator PAUSE / RESUME (PR3 engine layer) -----------------------------
#
# A NEW distinct _LanePhase.PAUSED (never STOPPED, which notify_work/reload resurrect). Pause is
# COOPERATIVE — a mid-episode (CLAIMING/PROCESSING) lane sets pause_pending and reaches PAUSED only
# after its <=1 in-flight head finishes, so ZERO rows strand INFLIGHT (the require-stopped precondition)
# and the two tripwires (busy_violations==0 + slots conservation) hold by construction.


async def test_pause_lane_synchronous_phases_conserve_slots(store: Any) -> None:
    """pause_lane from each SYNCHRONOUSLY-reachable phase (unknown/None, IDLE, PARKED, STOPPED) lands the
    lane in PAUSED, cancels any park timer, fires on_lane_paused once, and keeps busy_violations==0 +
    the conservation law (slots_free + processing_lanes == max at rest, no reserved)."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    hits: list[str] = []
    d = _make(store, stub, set(), clock=mc, on_lane_paused=hits.append)
    await d.start()
    try:
        # None: pause an unknown/never-registered lane -> create PAUSED (a first wake can't arm it).
        d.pause_lane("NEW")
        assert d.paused("NEW") is True and d.phase("NEW") == _LanePhase.PAUSED

        # IDLE: drain a lane to IDLE, then pause.
        idle_lane = "IB_IDLE"
        await _seed(store, idle_lane, [100.0])
        d.mark_ready(idle_lane)
        assert await _wait_until(lambda: d.phase(idle_lane) == _LanePhase.IDLE)
        d.pause_lane(idle_lane)
        assert d.phase(idle_lane) == _LanePhase.PAUSED

        # PARKED: RETRY -> PARKED (timer armed), then pause -> timer cancelled, PAUSED.
        park_lane = "IB_PARK"
        await _seed(store, park_lane, [100.0])
        stub.program(park_lane, ["RETRY"])
        d.mark_ready(park_lane)
        assert await _wait_until(lambda: d.phase(park_lane) == _LanePhase.PARKED)
        assert park_lane in d._timers
        d.pause_lane(park_lane)
        assert d.phase(park_lane) == _LanePhase.PAUSED
        assert park_lane not in d._timers  # the park backoff timer was cancelled

        # STOPPED: content-STOP -> STOPPED, then pause overrides it (operator intent wins).
        stop_lane = "IB_STOP"
        await _seed(store, stop_lane, [100.0])
        stub.program(stop_lane, ["STOP"])
        d.mark_ready(stop_lane)
        assert await _wait_until(lambda: d.phase(stop_lane) == _LanePhase.STOPPED)
        d.pause_lane(stop_lane)
        assert d.phase(stop_lane) == _LanePhase.PAUSED

        await _settle()
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
        assert d.processing_lanes == 0
        assert d.slots_free + d.processing_lanes == 256  # conservation at rest (reserved == 0)
        assert d.paused_count == 4
        assert hits == [
            "NEW",
            idle_lane,
            park_lane,
            stop_lane,
        ]  # fired once each on reaching PAUSED
    finally:
        await d.stop()


async def test_pause_ready_lane_pinned_by_full_slots(store: Any) -> None:
    """pause_lane on a READY lane (pinned by a full slot budget) -> PAUSED; the stale ready-deque entry
    is skipped at _assemble_chunk (phase != READY) once a slot frees, so it is never claimed/drained."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    busy_lane, ready_lane = "IB_BUSY", "IB_READY"
    await _seed(store, busy_lane, [100.0])
    await _seed(store, ready_lane, [100.0])
    gate = asyncio.Event()
    stub.gate(busy_lane, gate)  # holds busy_lane in PROCESSING, consuming the only slot
    d = _make(store, stub, set(), max_processing_lanes=1, clock=mc)
    await d.start()
    try:
        d.mark_ready(busy_lane)
        assert await _wait_until(lambda: d.phase(busy_lane) == _LanePhase.PROCESSING)
        assert d.slots_free == 0
        d.mark_ready(ready_lane)  # no free slot -> sits READY on the claimer's deque
        assert await _wait_until(lambda: d.phase(ready_lane) == _LanePhase.READY)
        d.pause_lane(ready_lane)
        assert d.phase(ready_lane) == _LanePhase.PAUSED

        gate.set()  # busy_lane resolves + frees the slot; the stale READY entry is skipped as non-READY
        assert await _wait_until(lambda: d.phase(busy_lane) == _LanePhase.IDLE)
        await _settle()
        assert d.phase(ready_lane) == _LanePhase.PAUSED  # never re-armed
        assert [r for r in stub.records if r.lane == ready_lane] == []  # never dispatched
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


async def test_pause_while_processing_defers_then_mark_ready_cannot_drain(store: Any) -> None:
    """THE T14-trap correctness assertion: pause_lane on a PROCESSING lane defers (pause_pending); the
    <=1 in-flight head finishes, then the terminal transition routes the lane to PAUSED (NOT _lane_done's
    re-ready/IDLE) EVEN THOUGH a producer keeps calling mark_ready mid-pause — so the NEXT queued row is
    NEVER drained while paused. Resume then drains it head-first (per-lane FIFO)."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_PROC_PAUSE"
    mids = await _seed(store, lane, [100.0, 101.0])  # head + a successor
    gate = asyncio.Event()
    stub.gate(lane, gate)  # pin the lane in PROCESSING on the head
    hits: list[str] = []
    d = _make(store, stub, set(), per_lane_limit=1, clock=mc, on_lane_paused=hits.append)
    await d.start()
    try:
        d.mark_ready(lane)
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PROCESSING)
        d.pause_lane(lane)  # lands mid-PROCESSING -> pause_pending, phase STILL PROCESSING
        assert d.phase(lane) == _LanePhase.PROCESSING
        assert hits == []  # not yet quiesced (the head is still in flight)
        d.mark_ready(
            lane
        )  # producer wakes mid-pause: set dirty — must NOT re-arm at lane_done (T14)
        d.mark_ready(lane)
        assert d.is_dirty(lane) is True
        gate.set()  # head finishes -> terminal transition sees pause_pending -> PAUSED (skip _lane_done)
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PAUSED)
        assert hits == [lane]  # fired exactly once, on reaching PAUSED
        await _settle()
        assert [r.message_id for r in stub.records] == [
            mids[0]
        ]  # ONLY the head — successor NOT drained
        assert d.phase(lane) == _LanePhase.PAUSED  # stayed paused despite the mark_ready wakes
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
        assert d.slots_free == 256  # the PROCESSING slot was released at the terminal transition

        # Resume: the retained successor drains head-first (FIFO), nothing reordered.
        d.resume_lane(lane)
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        assert [r.message_id for r in stub.records] == [mids[0], mids[1]]
    finally:
        await d.stop()


async def test_resume_cancels_pending_pause_mid_processing_drains_successor(store: Any) -> None:
    """THE restart-during-active-delivery wedge guard: pause_lane on a PROCESSING lane defers
    (``pause_pending`` set, phase STILL PROCESSING); a resume_lane landing WHILE the head is still
    in-flight (a ``restart_outbound`` stop+start in ONE lock span) CANCELS the not-yet-landed pause. When
    the in-flight item then resolves, the terminal transition sees ``pause_pending`` cleared and takes the
    NORMAL _lane_done path — the lane returns to IDLE and DRAINS the successor, never wedging in PAUSED
    with nothing left to re-arm it. on_lane_paused NEVER fires; busy_violations==0."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_RESUME_MIDEP"
    mids = await _seed(store, lane, [100.0, 101.0])  # head + a successor
    gate = asyncio.Event()
    stub.gate(lane, gate)  # pin the lane in PROCESSING on the head
    hits: list[str] = []
    d = _make(store, stub, set(), clock=mc, on_lane_paused=hits.append)
    await d.start()
    try:
        d.mark_ready(lane)
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PROCESSING)
        d.pause_lane(lane)  # lands mid-PROCESSING -> pause_pending set, phase STILL PROCESSING
        assert d.phase(lane) == _LanePhase.PROCESSING
        assert d._states[lane].pause_pending is True

        # Resume WHILE still mid-episode: cancels the not-yet-landed pause; the episode resumes normally.
        d.resume_lane(lane)
        assert d._states[lane].pause_pending is False
        assert d.phase(lane) == _LanePhase.PROCESSING  # still draining the in-flight head

        gate.set()  # head resolves -> terminal transition sees pause_pending cleared -> NOT PAUSED
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        assert d.paused(lane) is False
        assert hits == []  # on_lane_paused never fired (the pause was cancelled before landing)
        # The successor DRAINED in the same episode (the lane did not wedge), in FIFO order.
        assert [r.message_id for r in stub.records] == [mids[0], mids[1]]
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


async def test_pause_while_claiming_empty_routes_to_paused(store: Any) -> None:
    """The CLAIMING->empty-claim edge with pause_pending routes STRAIGHT to PAUSED (never a claimable
    IDLE / a re-ready): a _ClaimShim pins the lane in CLAIMING; pause_lane sets pause_pending; the
    blocked claim then returns EMPTY -> the empty-claim branch routes it to PAUSED, releasing the
    reserved slot and firing on_lane_paused."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_CLAIM_PAUSE"
    await _seed(store, lane, [100.0])
    blocker = asyncio.Event()
    shim = _ClaimShim(store, lane, mode="empty_block_once", block=blocker)
    hits: list[str] = []
    d = _make(shim, stub, set(), clock=mc, on_lane_paused=hits.append)
    await d.start()
    try:
        d.mark_ready(lane)
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.CLAIMING)
        d.pause_lane(
            lane
        )  # lands during the (blocked) claim -> pause_pending, phase STILL CLAIMING
        assert d.phase(lane) == _LanePhase.CLAIMING
        assert hits == []
        assert d.slots_free == 255  # the reserved CLAIMING slot is still held
        blocker.set()  # the claim returns EMPTY -> pause_pending routes to PAUSED (not IDLE / re-ready)
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PAUSED)
        assert hits == [lane]
        await _settle()
        assert d.phase(lane) == _LanePhase.PAUSED  # never dropped to a claimable IDLE
        assert stub.records == []  # nothing was dispatched (the claim was empty)
        assert d.slots_free == 256  # the reserved slot was released on the way to PAUSED
        assert d.busy_violations == 0
    finally:
        await d.stop()


async def test_on_lane_paused_fires_once_and_idempotent(store: Any) -> None:
    """on_lane_paused fires EXACTLY when a lane reaches PAUSED — once for an immediate (idle) pause; a
    repeat pause_lane on an already-PAUSED lane does NOT re-fire (idempotent); a fresh pause AFTER a
    resume fires again (a new episode)."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    hits: list[str] = []
    d = _make(store, stub, set(), clock=mc, on_lane_paused=hits.append)
    await d.start()
    try:
        d.pause_lane("L")  # unknown -> create PAUSED + fire
        assert hits == ["L"]
        d.pause_lane("L")  # idempotent -> no re-fire
        assert hits == ["L"]
        d.resume_lane("L")  # PAUSED -> IDLE/READY (a new episode may pause again)
        d.pause_lane("L")  # fires again
        assert hits == ["L", "L"]
    finally:
        await d.stop()


async def test_notify_work_does_not_resurrect_paused_lane(store: Any) -> None:
    """notify_work (a /config/reload or DR broadcast) must NEVER re-arm a deliberately operator-PAUSED
    lane — THE reload-survival fix. A paused lane with queued rows stays PAUSED across repeated
    notify_work + a producer wake and dispatches nothing; resume then drains the retained rows FIFO."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_NW_PAUSE"
    await _seed(store, lane, [100.0, 101.0])  # drained on start-seed
    d = _make(store, stub, {lane}, clock=mc)  # in the provider so notify_work names it
    await d.start()
    try:
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        n0 = len(stub.records)
        d.pause_lane(lane)
        assert d.phase(lane) == _LanePhase.PAUSED
        more = await _seed(store, lane, [102.0, 103.0])  # undelivered work behind the pause
        d.mark_ready(lane)  # transform-handoff-style wake on the paused lane (the pooled wake-leak)
        for _ in range(3):
            d.notify_work()  # reload / DR broadcasts (each also requests a sweep)
            await _settle()
        assert d.phase(lane) == _LanePhase.PAUSED  # NEVER resurrected
        assert len(stub.records) == n0  # nothing dispatched while paused

        d.resume_lane(lane)  # now the retained rows drain, in FIFO order
        assert await _wait_until(lambda: {r.message_id for r in stub.records} >= set(more))
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


async def test_sweep_leaves_paused_lane_halted(store: Any) -> None:
    """The clock-driven sweep leaves a PAUSED lane halted even when its head is DUE — only resume_lane
    re-arms it (distinct from a PARKED lane the sweep unparks when the backoff elapses)."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_SWEEP_PAUSE"
    prov: set[str] = set()  # start OUT of the provider so start()'s seed never drains the lane
    await _seed(store, lane, [100.0])  # a due head (below the clock base)
    d = _make(store, stub, prov, clock=mc)
    await d.start()
    try:
        d.pause_lane(lane)  # create PAUSED
        assert d.phase(lane) == _LanePhase.PAUSED
        prov.add(lane)  # now the sweep OWNS the lane and will see its DUE head
        for _ in range(3):
            await d._run_sweep_once()
            await _settle()
        assert d.phase(lane) == _LanePhase.PAUSED  # halted (the due head is ignored while paused)
        assert stub.records == []  # never dispatched

        d.resume_lane(lane)  # only resume re-arms it
        assert await _wait_until(lambda: len(stub.records) == 1)
        assert d.busy_violations == 0
    finally:
        await d.stop()


async def test_resume_resweeps_backed_off_head_then_drains(store: Any) -> None:
    """resume_lane re-arms from the head AND requests an immediate sweep: a head that backed off
    (RETRY-re-pended NOT-due) while paused is re-swept on resume — the claim finds nothing (IDLE) but
    the immediate sweep arms an exact re-claim timer, so once the backoff elapses the head drains. Never
    stranded until the next periodic sweep (disabled here)."""
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lane = "IB_RESUME_RETRY"
    mid = (await _seed(store, lane, [100.0]))[0]
    stub.program(lane, ["RETRY", "RESOLVED"])  # first pass parks (backs off), then resolves
    d = _make(store, stub, {lane}, clock=mc)
    await d.start()
    try:
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.PARKED)
        nxt = stub.last_retry_until[lane]
        assert nxt > mc.now  # the backoff deadline is in the future
        d.pause_lane(lane)  # PARKED -> PAUSED, park timer cancelled
        assert d.phase(lane) == _LanePhase.PAUSED
        assert lane not in d._timers

        d.resume_lane(
            lane
        )  # head still NOT due -> claim EMPTY -> IDLE; the immediate sweep arms a timer
        assert await _wait_until(lambda: d.phase(lane) == _LanePhase.IDLE)
        assert lane in d._timer_deadline
        assert d._timer_deadline[lane] == pytest.approx(nxt)  # armed at the head's exact due time
        assert (
            len([r for r in stub.records if r.lane == lane]) == 1
        )  # only the RETRY dispatch so far

        mc.advance((nxt - mc.now) + 1.0)  # backoff elapses -> the sweep-armed timer drains the head
        await _settle()
        assert await _wait_until(lambda: [r.message_id for r in stub.records] == [mid, mid])
        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
    finally:
        await d.stop()


async def test_pause_resume_soak_busy_violations(store: Any) -> None:
    """Connection-controls soak: a randomized interleave of pause_lane / resume_lane across many lanes
    (mixed with mark_ready / sweeps / notify_work / clock advances) keeps busy_violations==0 and
    concurrency_violations==0, and — once every lane is resumed — force-drains every seeded row in
    per-lane FIFO order (a pause/resume must never reorder or lose a row)."""
    rng = random.Random(0x5EED)
    mc = ManualClock(1000.0)
    stub = RecordingStub(store, mc.time)
    lanes = [f"IB_PR_{i:03d}" for i in range(60)]
    provider = set(lanes)
    seeded: dict[str, list[str]] = {}
    index_of: dict[str, int] = {}
    for lane in lanes:
        n = rng.randint(1, 3)
        mids = await _seed(store, lane, [100.0 + j for j in range(n)])
        seeded[lane] = mids
        for j, mid in enumerate(mids):
            index_of[mid] = j

    d = _make(store, stub, provider, max_processing_lanes=16, clock=mc)
    await d.start()
    try:
        for _ in range(50):
            action = rng.randint(0, 4)
            if action == 0:
                for lane in rng.sample(lanes, k=rng.randint(1, 10)):
                    d.mark_ready(lane)
            elif action == 1:
                mc.advance(rng.uniform(1.0, 30.0))  # fire park timers
            elif action == 2:
                await d._run_sweep_once()
            elif action == 3:
                d.notify_work()
            else:  # pause a few actually-running lanes / resume a few actually-paused lanes
                for lane in rng.sample(lanes, k=rng.randint(1, 6)):
                    d.pause_lane(lane)
                currently_paused = [x for x in lanes if d.paused(x)]
                if currently_paused:
                    for lane in rng.sample(currently_paused, k=min(len(currently_paused), 3)):
                        d.resume_lane(lane)
            await _settle(rounds=2)
            assert d.busy_violations == 0  # the one-consumer-per-lane invariant holds every step
            assert stub.concurrency_violations == 0

        # Resume EVERY lane that is (or has just become) paused — settle between rounds so a lane that
        # only just reached PAUSED (a pause_pending that quiesced) is resumed too (resume_lane no-ops on
        # a not-yet-PAUSED lane). Then force-drain to quiescence (mirrors the main soak's kick loop).
        for _ in range(6):
            await _settle(rounds=2)
            still = [x for x in lanes if d.paused(x)]
            if not still:
                break
            for x in still:
                d.resume_lane(x)
        assert not any(d.paused(x) for x in lanes)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + 30.0
        drained = False

        def _quiescent() -> bool:
            return d.processing_lanes == 0 and all(
                d.phase(x) in (None, _LanePhase.IDLE) for x in lanes
            )

        while loop.time() < deadline:
            d.notify_work()
            mc.advance(1_000_000.0)
            await d._run_sweep_once()
            if await _wait_until(_quiescent, timeout=3.0):
                drained = True
                break
        assert drained, "pause/resume soak did not reach quiescence"

        assert d.busy_violations == 0
        assert stub.concurrency_violations == 0
        dispatched = {r.message_id for r in stub.records}
        assert dispatched == set(index_of)  # every seeded row eventually dispatched
        for lane, mids in seeded.items():
            order = _first_occurrence_order(stub.records, lane, index_of)
            assert order == list(range(len(mids)))  # per-lane FIFO on first dispatch, across pauses
    finally:
        await d.stop()
