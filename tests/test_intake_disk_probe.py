# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The intake monitor's disk probe is single-flight (BACKLOG #5767).

A worker thread blocked on a hung volume cannot be cancelled, so a probe per tick would fill the
default executor that routing and transforms share. Every probe here is a fake that blocks on an
event; none measures a real disk.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.config.settings import StoreBackend
from messagefoundry.pipeline import intake_bound
from messagefoundry.pipeline.intake_bound import DISK_REASON, IntakeBoundMonitor
from messagefoundry.pipeline.retention import DiskFloorReading
from messagefoundry.store import Store
from messagefoundry.transports.base import IntakeGate

MIB = 1 << 20
FLOOR_MIB = 1024
LOW_MIB = 100
HIGH_MIB = 4096
_LOGGER = "messagefoundry.pipeline.intake_bound"
_HEALTHY_TIMEOUT = 30.0


class _Probe:
    """Stands in for ``read_disk_floor``. Each call fixes its outcome when it STARTS, so a call that
    hung still carries the reading from before the test moved the disk."""

    def __init__(self) -> None:
        self.free_mib = HIGH_MIB
        self.error: Exception | None = None
        self.hang = False
        self.release = threading.Event()
        self._lock = threading.Lock()
        self.started = 0
        self.finished = 0
        self.running = 0

    def __call__(self, path: str, floor_mb: int) -> DiskFloorReading:
        with self._lock:
            self.started += 1
            self.running += 1
            free_mib, error, hang = self.free_mib, self.error, self.hang
        try:
            if hang:
                assert self.release.wait(30.0), "the test never released its hung probe"
            if error is not None:
                raise error
            return DiskFloorReading(
                probed=path, free_bytes=free_mib * MIB, floor_bytes=floor_mb * MIB
            )
        finally:
            with self._lock:
                self.running -= 1
                self.finished += 1

    async def finish_hung(self) -> None:
        """Let every hung call end, and give its completion time to reach the event loop."""
        self.hang = False
        self.release.set()
        for _ in range(1000):
            if self.finished == self.started:
                break
            await asyncio.sleep(0.005)
        assert self.finished == self.started
        await asyncio.sleep(0.05)


class _Store:
    backend = StoreBackend.SQLITE

    def __init__(self, path: Path) -> None:
        self.path = str(path)


@pytest.fixture
def probe(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Probe]:
    fake = _Probe()
    monkeypatch.setattr(intake_bound, "read_disk_floor", fake)
    # Long, so a healthy probe on a loaded runner never reads as timed out; _tick_into_hang
    # shortens it for the one tick that must time out.
    monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", _HEALTHY_TIMEOUT)
    yield fake
    fake.release.set()  # a failing test must not leave a thread for the loop's teardown to join


def _disk_monitor(
    tmp_path: Path, gate: IntakeGate, *, check_seconds: float = 1.0
) -> IntakeBoundMonitor:
    return IntakeBoundMonitor(
        cast(Store, _Store(tmp_path / "s.db")),
        gate,
        min_free_disk_mb=FLOOR_MIB,
        check_seconds=check_seconds,
    )


async def _tick_into_hang(
    monitor: IntakeBoundMonitor, probe: _Probe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One tick whose probe hangs and times out. Returns only once the probe has entered the fake,
    so the outcome it fixed at entry is the one the test set before this call."""
    expected = probe.started + 1
    probe.hang = True
    monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", 0.05)
    await monitor.check_once()
    monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", _HEALTHY_TIMEOUT)
    for _ in range(2000):
        if probe.started >= expected:
            break
        await asyncio.sleep(0.005)
    assert probe.started == expected, "control: the hung probe really started"


async def test_a_hung_probe_across_many_ticks_runs_one_thread(
    tmp_path: Path, probe: _Probe, monkeypatch: pytest.MonkeyPatch
) -> None:
    monitor = _disk_monitor(tmp_path, IntakeGate())
    await _tick_into_hang(monitor, probe, monkeypatch)
    for _ in range(8):
        await monitor.check_once()
    await asyncio.sleep(0.05)  # a queued extra probe would have entered the fake by now
    assert probe.started == 1, "a tick started a probe while an earlier one was still blocked"
    await probe.finish_hung()


async def test_a_late_high_reading_does_not_release_a_held_pause(
    tmp_path: Path, probe: _Probe, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    probe.free_mib = LOW_MIB
    await monitor.check_once()
    assert gate.reasons == {DISK_REASON}, "control: the pause is held"

    probe.free_mib = HIGH_MIB
    await _tick_into_hang(monitor, probe, monkeypatch)  # leaves a probe that will report HIGH
    probe.free_mib = LOW_MIB
    await probe.finish_hung()
    assert gate.reasons == {DISK_REASON}, "a result nobody was waiting for released the pause"

    await monitor.check_once()
    assert probe.started == 3, "the tick after a dropped result measures afresh"
    assert gate.reasons == {DISK_REASON}, "the stale HIGH reading was used instead of the new one"


async def test_a_late_low_reading_does_not_newly_hold(
    tmp_path: Path, probe: _Probe, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    probe.free_mib = LOW_MIB
    await _tick_into_hang(monitor, probe, monkeypatch)
    probe.free_mib = HIGH_MIB
    await probe.finish_hung()
    assert gate.is_open, "a result nobody was waiting for started a pause"
    await monitor.check_once()
    assert probe.started == 2 and gate.is_open


async def test_a_result_landing_during_a_later_tick_is_not_consumed(
    tmp_path: Path, probe: _Probe, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    probe.free_mib = LOW_MIB
    await monitor.check_once()
    probe.free_mib = HIGH_MIB
    await _tick_into_hang(monitor, probe, monkeypatch)
    # The thread ends, and the very next tick runs before its completion reaches the loop.
    probe.hang = False
    probe.release.set()
    while probe.finished < probe.started:
        threading.Event().wait(0.001)  # blocks the loop on purpose, so no completion is delivered
    await monitor.check_once()
    assert gate.reasons == {DISK_REASON}, "a later tick consumed an earlier tick's reading"
    assert probe.started == 2, "a tick started a probe before the earlier one had been cleared"
    await probe.finish_hung()


async def test_a_late_failure_is_neither_logged_nor_left_unretrieved(
    tmp_path: Path,
    probe: _Probe,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    late = OSError("late failure")
    unhandled: list[dict[str, Any]] = []
    # The loop is session-scoped, so the handler goes back, and only this test's error counts.
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _, ctx: unhandled.append(ctx))
    try:
        monitor = _disk_monitor(tmp_path, IntakeGate())
        probe.error = late
        with caplog.at_level(logging.DEBUG, logger=_LOGGER):
            await _tick_into_hang(monitor, probe, monkeypatch)
            await probe.finish_hung()
            gc.collect()  # an unretrieved exception is reported when its task is collected
            await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous)
    assert not [ctx for ctx in unhandled if ctx.get("exception") is late]
    assert not [r for r in caplog.records if r.exc_info and r.exc_info[1] is late]


async def test_recovery_once_the_hung_probe_finishes(
    tmp_path: Path, probe: _Probe, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    probe.free_mib = LOW_MIB
    await monitor.check_once()
    await _tick_into_hang(monitor, probe, monkeypatch)
    for _ in range(3):
        await monitor.check_once()
    assert gate.reasons == {DISK_REASON}, "an unmeasured disk is not evidence that it recovered"
    await probe.finish_hung()
    probe.free_mib = HIGH_MIB
    await monitor.check_once()
    assert gate.is_open, "the first probe after the hang ended must be able to release"


async def test_a_probe_failing_inside_its_own_tick_logs_once_with_its_cause(
    tmp_path: Path, probe: _Probe, caplog: pytest.LogCaptureFixture
) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    probe.free_mib = LOW_MIB
    await monitor.check_once()
    probe.error = OSError("own tick")
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        await monitor.check_once()
        await monitor.check_once()
    failures = [r for r in caplog.records if r.exc_info and r.exc_info[0] is OSError]
    assert len(failures) == 1, "one WARNING per failing streak, carrying the cause"
    assert gate.reasons == {DISK_REASON}


async def test_stop_does_not_wait_for_a_hung_probe(tmp_path: Path, probe: _Probe) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate, check_seconds=0.01)
    probe.hang = True  # the fixture's long timeout puts the stop inside the tick's wait
    monitor.start()
    for _ in range(400):
        if probe.started:
            break
        await asyncio.sleep(0.005)
    assert probe.started == 1
    await asyncio.wait_for(monitor.stop(), 2.0)
    assert gate.is_open
    assert probe.running == 1, "control: the probe really was still blocked through the stop"
    await probe.finish_hung()
