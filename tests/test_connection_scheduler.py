# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-connection active-window scheduler (#147, ADR 0095): the RegistryRunner honors a per-connection
time-of-day / day-of-week ``Schedule`` to AUTO-START a connection on entering an active window and
cleanly STOP (park) it on leaving — reusing the SAME start/stop lifecycle the API uses. The clock is
injectable so window boundaries are deterministic in tests. A connection with no schedule is byte-
identical always-on (no scheduler task). Also covers the Schedule model semantics (same-day span,
past-midnight wrap, maintenance invert, IANA timezone, validation)."""

from __future__ import annotations

import asyncio
import socket
from datetime import datetime, time, timezone
from pathlib import Path

import pytest

from messagefoundry.config.models import ActiveWindow, ConnectorType, Schedule
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    Registry,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore

# 2026-07-13 is a Monday (datetime.weekday() == 0).
MON = 0
_WEEKDAYS = frozenset({0, 1, 2, 3, 4})


def _utc(y: int, mo: int, d: int, h: int, mi: int = 0) -> datetime:
    return datetime(y, mo, d, h, mi, tzinfo=timezone.utc)


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
        assert "in_sched" in runner._schedule_workers
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
