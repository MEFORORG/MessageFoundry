# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-connection active-window scheduler (#147, ADR 0095): the RegistryRunner honors a per-connection
time-of-day / day-of-week ``Schedule`` to AUTO-START a connection on entering an active window and
cleanly STOP (park) it on leaving — reusing the SAME start/stop lifecycle the API uses. The clock is
injectable so window boundaries are deterministic in tests. A connection with no schedule is byte-
identical always-on (no scheduler task). Also covers the Schedule model semantics (same-day span,
past-midnight wrap, maintenance invert, IANA timezone, validation)."""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime, time
from pathlib import Path

import pytest

from messagefoundry.config.models import (
    ActiveWindow,
    ConnectorType,
    InternalErrorPolicy,
    Schedule,
)
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    Send,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.store.store import Stage
from messagefoundry.transports.base import NegativeAckError

# 2026-07-13 is a Monday (datetime.weekday() == 0).
MON = 0
_WEEKDAYS = frozenset({0, 1, 2, 3, 4})


def _utc(y: int, mo: int, d: int, h: int, mi: int = 0) -> datetime:
    return datetime(y, mo, d, h, mi, tzinfo=UTC)


class _Clock:
    """A settable UTC clock injected as the runner's ``schedule_clock``."""

    def __init__(self, now: datetime) -> None:
        self._now = now

    def set(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


async def _wait_until(predicate, timeout: float = 2.0) -> None:  # type: ignore[no-untyped-def]
    async def _poll() -> None:
        while not predicate():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(_poll(), timeout)


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "sched.db")
    yield s
    await s.close()


# === Schedule model ==========================================================


def _weekday_window() -> Schedule:
    return Schedule(
        windows=[ActiveWindow(days=_WEEKDAYS, start=time(8, 0), end=time(17, 0), timezone="UTC")]
    )


def test_same_day_window_membership() -> None:
    s = _weekday_window()
    assert s.is_active(_utc(2026, 7, 13, 9))  # Mon 09:00 — inside
    assert not s.is_active(_utc(2026, 7, 13, 7))  # Mon 07:00 — before open
    assert not s.is_active(_utc(2026, 7, 13, 17))  # end-exclusive
    assert not s.is_active(_utc(2026, 7, 18, 9))  # Saturday — not a scheduled weekday


def test_past_midnight_wrap() -> None:
    # Mon 22:00 → 06:00 wraps past midnight, anchored on the Monday it opened.
    s = Schedule(
        windows=[ActiveWindow(days={MON}, start=time(22, 0), end=time(6, 0), timezone="UTC")]
    )
    assert s.is_active(_utc(2026, 7, 13, 23))  # Mon evening — inside
    assert s.is_active(_utc(2026, 7, 14, 5))  # Tue 05:00 — morning tail of the Mon window
    assert not s.is_active(_utc(2026, 7, 14, 7))  # Tue 07:00 — past the tail
    assert not s.is_active(_utc(2026, 7, 13, 21))  # Mon 21:00 — before it opens


def test_maintenance_invert() -> None:
    # invert=True → the windows are DOWNTIME: parked inside, up outside.
    s = Schedule(windows=_weekday_window().windows, invert=True)
    assert not s.is_active(_utc(2026, 7, 13, 9))  # inside the maintenance window → down
    assert s.is_active(_utc(2026, 7, 13, 7))  # outside → up


def test_timezone_is_evaluated_locally() -> None:
    # A New-York window: 13:00 UTC = 09:00 EDT (summer) is inside 08:00–17:00 local.
    s = Schedule(
        windows=[ActiveWindow(days={MON}, start=time(8), end=time(17), timezone="America/New_York")]
    )
    assert s.is_active(_utc(2026, 7, 13, 13))  # 09:00 EDT
    assert not s.is_active(_utc(2026, 7, 13, 3))  # 23:00 EDT Sunday


def test_model_validation() -> None:
    with pytest.raises(ValueError):
        ActiveWindow(days={MON}, start=time(8), end=time(8), timezone="UTC")  # start == end
    with pytest.raises(ValueError):
        ActiveWindow(days={MON}, start=time(8), end=time(9), timezone="Nowhere/Nope")  # bad tz
    with pytest.raises(ValueError):
        ActiveWindow(days={9}, start=time(8), end=time(9), timezone="UTC")  # weekday out of range


# === runner scheduler ========================================================


async def test_no_schedule_is_always_on(store: MessageStore) -> None:
    # A connection with no schedule creates NO scheduler task and is always-on (byte-identical).
    reg = Registry()
    reg.add_inbound(build_inbound_connection("in_plain", MLLP(port=_free_port()), router="r"))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        assert runner.inbound_running("in_plain")
        assert runner._schedule_workers == {}  # no scheduler task spawned
    finally:
        await runner.stop()


async def test_reconcile_starts_in_window_and_parks_out(store: MessageStore) -> None:
    # A single deterministic reconcile step: active+not-running → start; not-active+running → park.
    schedule = _weekday_window()
    clock = _Clock(_utc(2026, 7, 13, 9))  # Mon 09:00 — inside the window
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection("in_sched", MLLP(port=_free_port()), router="r", schedule=schedule)
    )
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(reg, store, poll_interval=0.02, schedule_clock=clock.now)
    await runner.start()
    try:
        assert runner.inbound_running("in_sched")  # auto_start + inside window → up
        # Leave the window → the next reconcile parks it (clean stop).
        clock.set(_utc(2026, 7, 13, 18))
        await runner._reconcile_schedule("in_sched", "inbound", schedule)
        assert not runner.inbound_running("in_sched")
        # Re-enter the window → reconcile starts it again.
        clock.set(_utc(2026, 7, 14, 10))  # Tue 10:00 — inside
        await runner._reconcile_schedule("in_sched", "inbound", schedule)
        assert runner.inbound_running("in_sched")
    finally:
        await runner.stop()


async def test_scheduler_task_autonomously_parks_out_of_window(store: MessageStore) -> None:
    # Drive the actual scheduler LOOP (short tick): starting OUTSIDE the window, the task parks the
    # auto-started listener on its own; moving INSIDE brings it back up.
    schedule = _weekday_window()
    clock = _Clock(_utc(2026, 7, 13, 20))  # Mon 20:00 — OUTSIDE the 08:00–17:00 window
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection("in_sched", MLLP(port=_free_port()), router="r", schedule=schedule)
    )
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(
        reg, store, poll_interval=0.02, schedule_clock=clock.now, schedule_tick=0.02
    )
    await runner.start()
    try:
        assert ("inbound", "in_sched") in runner._schedule_workers
        # The scheduler autonomously parks the out-of-window listener that auto_start bound.
        await _wait_until(lambda: not runner.inbound_running("in_sched"))
        # Move into the window → the scheduler brings it up.
        clock.set(_utc(2026, 7, 14, 9))  # Tue 09:00 — inside
        await _wait_until(lambda: runner.inbound_running("in_sched"))
        # Back out → parked again.
        clock.set(_utc(2026, 7, 14, 20))
        await _wait_until(lambda: not runner.inbound_running("in_sched"))
    finally:
        await runner.stop()


async def test_outbound_schedule_pauses_and_resumes_delivery(
    store: MessageStore, tmp_path: Path
) -> None:
    # An outbound schedule reuses start_outbound/stop_outbound: parking PAUSEs delivery (retaining the
    # queue), the window resumes it.
    schedule = _weekday_window()
    clock = _Clock(_utc(2026, 7, 13, 20))  # outside → parked
    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_FILE",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path), "filename": "x.hl7"}),
            schedule=schedule,
        )
    )
    runner = RegistryRunner(
        reg, store, poll_interval=0.02, schedule_clock=clock.now, schedule_tick=0.02
    )
    await runner.start()
    try:
        await _wait_until(lambda: not runner.outbound_running("OB_FILE"))  # parked (paused)
        clock.set(_utc(2026, 7, 14, 9))  # inside → resume
        await _wait_until(lambda: runner.outbound_running("OB_FILE"))
    finally:
        await runner.stop()


async def test_dual_role_name_gets_one_scheduler_per_direction(
    store: MessageStore, tmp_path: Path
) -> None:
    # BACKLOG #1819: the registry keeps inbounds and outbounds in separate tables, so one name can be
    # both. When both halves declare a schedule, each needs its own scheduler task. Keyed by bare name,
    # the inbound's task claimed the slot and the outbound's schedule silently never ran: the
    # outbound stayed up outside its window, with no log line saying why.
    # The halves get OPPOSITE calendars (the outbound's is the maintenance inverse), so a task that
    # read the other half's schedule, or drove the other half's lifecycle, would show up as both
    # halves moving together instead of apart.
    in_schedule = _weekday_window()
    out_schedule = Schedule(windows=in_schedule.windows, invert=True)
    clock = _Clock(_utc(2026, 7, 13, 20))  # Mon 20:00 - inbound out of window, outbound in it
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "SHARED", MLLP(port=_free_port()), router="r", schedule=in_schedule
        )
    )
    reg.add_router("r", lambda m: [])
    reg.add_outbound(
        build_outbound_connection(
            "SHARED",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path), "filename": "x.hl7"}),
            schedule=out_schedule,
        )
    )
    runner = RegistryRunner(
        reg, store, poll_interval=0.02, schedule_clock=clock.now, schedule_tick=0.02
    )
    await runner.start()
    try:
        # One task per (direction, name), not one per name.
        assert set(runner._schedule_workers) == {("inbound", "SHARED"), ("outbound", "SHARED")}
        tasks = list(runner._schedule_workers.values())
        await _wait_until(
            lambda: not runner.inbound_running("SHARED") and runner.outbound_running("SHARED")
        )
        clock.set(_utc(2026, 7, 14, 9))  # Tue 09:00 - inbound in window, outbound parked
        await _wait_until(
            lambda: runner.inbound_running("SHARED") and not runner.outbound_running("SHARED")
        )
        # Tue 20:00 - the outbound's scheduler must RESUME it (start branch, not auto_start at boot)
        # while the inbound's parks, so each half's start and park branch has run at least once.
        clock.set(_utc(2026, 7, 14, 20))
        await _wait_until(
            lambda: not runner.inbound_running("SHARED") and runner.outbound_running("SHARED")
        )
    finally:
        await runner.stop()
    # Stop clears the map BEFORE it cancels, so an empty map alone proves nothing about the tasks.
    assert runner._schedule_workers == {}
    assert all(t.done() for t in tasks)


# === an operator-required STOP outranks the calendar ========================
#
# A lane halted by a #109 credential fault or the internal-error STOP policy must stay halted across a
# window close and the next window open, until an operator starts it. Before this, the close PAUSED the
# lane and the open RESUMED it, so a bad credential was re-tried at every window open: the partner
# lockout the STOP exists to prevent. #1819 gave each half of a dual-role name its own scheduler, which
# exposed the outbound half to the same gap the inbound half already had.

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r"
_IN_WINDOW = _utc(2026, 7, 13, 9)  # Mon 09:00
_OUT_OF_WINDOW = _utc(2026, 7, 13, 18)  # Mon 18:00
_NEXT_WINDOW = _utc(2026, 7, 14, 9)  # Tue 09:00


class _StopSink(LoggingAlertSink):
    """Records each ``connection_stopped`` name, so a test can wait for the STOP to have happened."""

    def __init__(self) -> None:
        self.stopped: list[str] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append(name)


class _CredentialFaultDestination:
    """Every send is refused as a PERMANENT credential fault, and each attempt is counted: a second
    attempt is a re-authentication the STOP was meant to prevent."""

    capture_response = False

    def __init__(self) -> None:
        self.sends = 0

    async def send(self, payload: str) -> None:
        self.sends += 1
        raise NegativeAckError(
            "bad password", code="remotefile", permanent=True, credential_fault=True
        )

    async def aclose(self) -> None:
        pass


class _CollectingDestination:
    capture_response = False

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, payload: str) -> None:
        self.sent.append(payload)

    async def aclose(self) -> None:
        pass


async def _start_credential_fault_rig(
    store: MessageStore, tmp_path: Path, claim_mode: str, clock: _Clock, schedule: Schedule
) -> tuple[RegistryRunner, _CredentialFaultDestination]:
    """A running runner whose scheduled outbound has just STOPPED on a credential fault, in window."""
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB_FEED", MLLP(port=_free_port()), router="r"))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB_SCHED", m))
    reg.add_outbound(
        build_outbound_connection(
            "OB_SCHED",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path), "filename": "x.hl7"}),
            schedule=schedule,
        )
    )
    sink = _StopSink()
    runner = RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        schedule_clock=clock.now,
        claim_mode=claim_mode,
        alert_sink=sink,
    )
    await runner.start()
    try:
        faulty = _CredentialFaultDestination()
        runner._destinations["OB_SCHED"] = faulty  # type: ignore[assignment]
        await store.enqueue_ingress(channel_id="IB_FEED", raw=RAW)
        runner.notify_work()
        await _wait_until(lambda: "OB_SCHED" in sink.stopped)
        assert faulty.sends == 1
    except BaseException:
        await runner.stop()
        raise
    return runner, faulty


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_credential_fault_stop_is_not_resumed_by_the_next_window(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> None:
    schedule = _weekday_window()
    clock = _Clock(_IN_WINDOW)
    runner, faulty = await _start_credential_fault_rig(store, tmp_path, claim_mode, clock, schedule)
    try:
        clock.set(_OUT_OF_WINDOW)  # the window closes...
        await runner._reconcile_schedule("OB_SCHED", "outbound", schedule)
        clock.set(_NEXT_WINDOW)  # ...and the next one opens
        await runner._reconcile_schedule("OB_SCHED", "outbound", schedule)
        await asyncio.sleep(0.3)  # time for a re-armed lane to claim the retained row

        assert faulty.sends == 1  # no second authentication attempt

        # Control: an operator restart lifts the hold, and the calendar owns the lane again. The
        # retained row delivers, then an ordinary close parks the lane and the next open resumes it.
        good = _CollectingDestination()
        runner._destinations["OB_SCHED"] = good  # type: ignore[assignment]
        await runner.restart_outbound("OB_SCHED")
        await _wait_until(lambda: len(good.sent) == 1)
        clock.set(_utc(2026, 7, 14, 18))
        await runner._reconcile_schedule("OB_SCHED", "outbound", schedule)
        assert not runner.outbound_running("OB_SCHED")
        clock.set(_utc(2026, 7, 15, 9))
        await runner._reconcile_schedule("OB_SCHED", "outbound", schedule)
        assert runner.outbound_running("OB_SCHED")
    finally:
        await runner.stop()


async def test_a_pooled_broadcast_that_re_arms_a_stopped_lane_ends_its_hold(
    store: MessageStore, tmp_path: Path
) -> None:
    # A pooled notify_work broadcast (replay, DR failback) re-arms every STOPPED lane by design. The
    # hold must end with it: a hold that outlived the re-arm would skip the next window close, and
    # the running lane would then deliver outside its window.
    schedule = _weekday_window()
    clock = _Clock(_IN_WINDOW)
    runner, faulty = await _start_credential_fault_rig(store, tmp_path, "pooled", clock, schedule)
    try:
        assert ("outbound", "OB_SCHED") in runner._stop_held
        # The record lands before the lane reaches STOPPED; a broadcast in that gap re-arms nothing.
        out = runner._dispatchers[Stage.OUTBOUND]
        await _wait_until(lambda: out.stopped("OB_SCHED"))
        runner.notify_work()
        assert ("outbound", "OB_SCHED") not in runner._stop_held
        await _wait_until(lambda: faulty.sends == 2)  # the broadcast really did re-arm it
    finally:
        await runner.stop()


def _raising_router(m: object) -> list[str]:
    raise RuntimeError("router bug")


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_content_stop_is_not_resumed_by_the_next_window(
    store: MessageStore, claim_mode: str
) -> None:
    # The inbound twin. A credential fault is an outbound-only signal, so the inbound's
    # operator-required STOP is the internal-error STOP policy on a router fault.
    schedule = _weekday_window()
    clock = _Clock(_IN_WINDOW)
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection("IB_SCHED", MLLP(port=_free_port()), router="r", schedule=schedule)
    )
    reg.add_router("r", _raising_router)
    sink = _StopSink()
    runner = RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        schedule_clock=clock.now,
        claim_mode=claim_mode,
        internal_error_default=InternalErrorPolicy.STOP,
        alert_sink=sink,
    )
    await runner.start()
    try:
        assert runner.inbound_running("IB_SCHED")
        await store.enqueue_ingress(channel_id="IB_SCHED", raw=RAW)
        runner.notify_work()
        await _wait_until(lambda: "IB_SCHED" in sink.stopped)

        clock.set(_OUT_OF_WINDOW)  # the close still parks the listener: intake stays in its window
        await runner._reconcile_schedule("IB_SCHED", "inbound", schedule)
        assert not runner.inbound_running("IB_SCHED")
        clock.set(_NEXT_WINDOW)  # the next open must not bring the halted lane back
        await runner._reconcile_schedule("IB_SCHED", "inbound", schedule)

        assert not runner.inbound_running("IB_SCHED")
        if claim_mode == "per_lane":  # and the router worker the STOP returned was not respawned
            assert runner._router_workers["IB_SCHED"].done()

        # Control: once the router is fixed and an operator starts the inbound, the calendar owns it
        # again, and an ordinary close parks it and the next open brings it back.
        runner.registry.routers["r"] = lambda m: []
        await runner.start_inbound("IB_SCHED")
        assert runner.inbound_running("IB_SCHED")
        clock.set(_utc(2026, 7, 14, 18))
        await runner._reconcile_schedule("IB_SCHED", "inbound", schedule)
        assert not runner.inbound_running("IB_SCHED")
        clock.set(_utc(2026, 7, 15, 9))
        await runner._reconcile_schedule("IB_SCHED", "inbound", schedule)
        assert runner.inbound_running("IB_SCHED")
    finally:
        await runner.stop()


def test_schedule_field_defaults_none_and_plumbs() -> None:
    # None (always-on) by default; an explicit Schedule threads through both factories.
    ic = build_inbound_connection("a", MLLP(port=1), router="r")
    assert ic.schedule is None
    sched = _weekday_window()
    ic2 = build_inbound_connection("b", MLLP(port=2), router="r", schedule=sched)
    assert ic2.schedule is sched
    oc = build_outbound_connection(
        "c",
        ConnectionSpec(ConnectorType.FILE, {"directory": ".", "filename": "x"}),
        schedule=sched,
    )
    assert oc.schedule is sched
