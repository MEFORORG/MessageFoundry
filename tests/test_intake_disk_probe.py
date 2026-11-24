# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The intake monitor's disk probe runs on its own bounded daemon thread (BACKLOG #5767).

A thread blocked on a hung volume cannot be cancelled, so a probe per tick on the default executor
could fill the pool that routing and transforms share. Every probe here is a fake that blocks on an
event; none measures a real disk.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import subprocess
import sys
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from messagefoundry.config.settings import StoreBackend
from messagefoundry.pipeline import intake_bound
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.intake_bound import DISK_REASON, IntakeBoundMonitor
from messagefoundry.pipeline.retention import DiskFloorReading
from messagefoundry.store import Store
from messagefoundry.transports.base import IntakeGate

MIB = 1 << 20
FLOOR_MIB = 1024
LOW_MIB = 100
HIGH_MIB = 4096
CAP = 4
_LOGGER = "messagefoundry.pipeline.intake_bound"
_HEALTHY_TIMEOUT = 30.0
#: Past any stuck limit the monitor could use, so one step always makes a live probe replaceable.
_PAST_STUCK_LIMIT = 3600.0


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
        self.peak = 0
        self.threads: list[threading.Thread] = []

    def __call__(self, path: str, floor_mb: int) -> DiskFloorReading:
        with self._lock:
            self.started += 1
            self.running += 1
            self.peak = max(self.peak, self.running)
            self.threads.append(threading.current_thread())
            free_mib, error, hang = self.free_mib, self.error, self.hang
        try:
            if hang:
                assert self.release.wait(60.0), "the test never released its hung probe"
            if error is not None:
                raise error
            return DiskFloorReading(
                probed=path, free_bytes=free_mib * MIB, floor_bytes=floor_mb * MIB
            )
        finally:
            with self._lock:
                self.running -= 1
                self.finished += 1

    async def wait_started(self, count: int) -> None:
        """Wait for ``count`` calls to have entered the fake: a thread is scheduled when it is."""
        for _ in range(2000):
            if self.started >= count:
                return
            await asyncio.sleep(0.005)
        raise AssertionError(f"only {self.started} of {count} probes started")

    async def finish_hung(self, monitor: IntakeBoundMonitor) -> None:
        """Let every hung call end, retired threads exit, and each completion reach the loop."""
        self.hang = False
        self.release.set()
        for _ in range(2000):
            # At most the current worker stays alive, idle, once its completion has been delivered.
            alive = {t for t in self.threads if t.daemon and t.is_alive()}
            worker = getattr(monitor, "_probe_worker", None)
            settled = worker is None or worker.busy_since is None
            if self.finished == self.started and len(alive) <= 1 and settled:
                break
            await asyncio.sleep(0.005)
        else:
            raise AssertionError("a released probe did not finish and settle")
        self.release = threading.Event()


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _Sink(LoggingAlertSink):
    """Counts the pause alerts. Every other event logs."""

    def __init__(self) -> None:
        self.paused = 0

    def intake_paused(
        self, name: str, *, reason: str, value: int, limit: int, store_kind: str
    ) -> None:
        self.paused += 1

    def intake_resumed(
        self, name: str, *, reason: str, value: int, limit: int, store_kind: str
    ) -> None:
        pass


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
    fake.release.set()  # a failing test must not leave a blocked thread behind


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    fake = _Clock()
    monkeypatch.setattr(intake_bound, "_monotonic", fake)
    return fake


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


def test_a_hung_probe_takes_no_default_executor_worker(
    tmp_path: Path, probe: _Probe, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its own loop, so the default executor can be one worker: one stolen worker then shows."""

    async def body() -> int:
        asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))
        monitor = _disk_monitor(tmp_path, IntakeGate())
        probe.hang = True
        monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", 0.02)
        try:
            for _ in range(12):
                await monitor.check_once()
                clock.now += _PAST_STUCK_LIMIT
            await asyncio.sleep(0.05)
            assert probe.running >= 1, "control: a probe really is blocked"
            return await asyncio.wait_for(asyncio.to_thread(lambda: 7), 2.0)
        finally:
            probe.release.set()

    assert asyncio.run(body()) == 7
    assert probe.threads and all(t.daemon for t in probe.threads)


async def test_the_abandoned_count_never_exceeds_the_cap_and_logs_once(
    tmp_path: Path,
    probe: _Probe,
    clock: _Clock,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monitor = _disk_monitor(tmp_path, IntakeGate())
    probe.hang = True
    monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", 0.02)
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        for _ in range(CAP * 5):
            await monitor.check_once()
            clock.now += _PAST_STUCK_LIMIT
    await probe.wait_started(CAP)
    await asyncio.sleep(0.05)  # a probe past the cap would have entered the fake by now
    assert probe.started == CAP, "probes must stop starting at the cap"
    assert probe.peak == CAP
    at_cap = [r for r in caplog.records if "stopped starting" in r.getMessage()]
    assert len(at_cap) == 1, "the cap is logged once"
    await probe.finish_hung(monitor)


async def test_no_replacement_before_the_stuck_limit(
    tmp_path: Path, probe: _Probe, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monitor = _disk_monitor(tmp_path, IntakeGate())
    await _tick_into_hang(monitor, probe, monkeypatch)
    for _ in range(8):
        await monitor.check_once()
    await asyncio.sleep(0.05)
    assert probe.started == 1, "a tick started a probe while the live one was inside its limit"
    await probe.finish_hung(monitor)


async def test_a_working_probe_after_a_hang_releases_a_held_pause(
    tmp_path: Path, probe: _Probe, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    probe.free_mib = LOW_MIB
    await monitor.check_once()
    assert gate.reasons == {DISK_REASON}, "control: the pause is held"
    await _tick_into_hang(monitor, probe, monkeypatch)
    assert gate.reasons == {DISK_REASON}, "an unmeasured disk is not evidence it recovered"

    probe.hang, probe.free_mib = False, HIGH_MIB
    clock.now += _PAST_STUCK_LIMIT
    await monitor.check_once()
    assert probe.running == 1, "control: the first probe is still blocked"
    assert gate.is_open, "a working probe after a hang must release the pause"
    await probe.finish_hung(monitor)


async def test_a_working_probe_after_a_hang_pauses_on_a_full_disk(
    tmp_path: Path, probe: _Probe, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    await _tick_into_hang(monitor, probe, monkeypatch)
    assert gate.is_open

    probe.hang, probe.free_mib = False, LOW_MIB
    clock.now += _PAST_STUCK_LIMIT
    await monitor.check_once()
    assert probe.running == 1, "control: the first probe is still blocked"
    assert gate.reasons == {DISK_REASON}, "a filling disk must still raise a pause after a hang"
    await probe.finish_hung(monitor)


async def test_probing_resumes_once_a_stuck_thread_exits_at_the_cap(
    tmp_path: Path,
    probe: _Probe,
    clock: _Clock,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    probe.free_mib = LOW_MIB
    await monitor.check_once()
    probe.hang = True
    monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", 0.02)
    for _ in range(CAP * 3):
        await monitor.check_once()
        clock.now += _PAST_STUCK_LIMIT
    await probe.wait_started(1 + CAP)
    assert probe.started == 1 + CAP, "control: the monitor reached the cap"
    assert gate.reasons == {DISK_REASON}

    await probe.finish_hung(monitor)
    monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", _HEALTHY_TIMEOUT)
    probe.free_mib = HIGH_MIB
    await monitor.check_once()
    assert gate.is_open, "probing must resume once a stuck thread has exited"

    # A later streak that reaches the cap is logged again.
    probe.hang = True
    monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", 0.02)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        for _ in range(CAP * 3):
            await monitor.check_once()
            clock.now += _PAST_STUCK_LIMIT
    assert len([r for r in caplog.records if "stopped starting" in r.getMessage()]) == 1
    await probe.finish_hung(monitor)


async def _reach_cap(
    monitor: IntakeBoundMonitor,
    probe: _Probe,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe.hang = True
    expected = probe.started + CAP
    monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", 0.02)
    for _ in range(CAP * 3):
        await monitor.check_once()
        clock.now += _PAST_STUCK_LIMIT
    await probe.wait_started(expected)
    monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", _HEALTHY_TIMEOUT)


async def test_running_again_is_logged_only_after_the_replacement_started(
    tmp_path: Path,
    probe: _Probe,
    clock: _Clock,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(_: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    monitor = _disk_monitor(tmp_path, IntakeGate())
    await _reach_cap(monitor, probe, clock, monkeypatch)
    await probe.finish_hung(monitor)
    with caplog.at_level(logging.INFO, logger=_LOGGER):
        with monkeypatch.context() as patch:
            patch.setattr(threading.Thread, "start", refuse)
            await monitor.check_once()
        assert not [r for r in caplog.records if "running again" in r.getMessage()]
        await monitor.check_once()
    assert len([r for r in caplog.records if "running again" in r.getMessage()]) == 1


async def test_a_finalizer_failure_leaves_no_unowned_thread(
    tmp_path: Path, probe: _Probe, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_: object) -> None:
        raise MemoryError("no finalizer")

    before = set(threading.enumerate())
    monitor = _disk_monitor(tmp_path, IntakeGate())
    with monkeypatch.context() as patch:
        patch.setattr(intake_bound, "weakref", SimpleNamespace(finalize=refuse))
        await monitor.check_once()  # must not raise
    started = [t for t in set(threading.enumerate()) - before if t.name == "intake-disk-probe"]
    assert not started, "a probe thread started with nothing owning it"
    assert probe.started == 0


async def test_a_dead_worker_drops_its_finalizer(tmp_path: Path, probe: _Probe) -> None:
    monitor = _disk_monitor(tmp_path, IntakeGate())
    await monitor.check_once()
    dead = cast(Any, monitor)._probe_worker
    dead.inbox.put(None)
    await asyncio.to_thread(dead.thread.join, 10.0)
    assert not dead.thread.is_alive(), "control: the worker died"
    assert dead.close.alive, "control: its finalizer is still registered"
    await monitor.check_once()
    assert not dead.close.alive, "a dead worker's finalizer stayed registered"
    assert probe.started == 2, "a replacement worker measured"
    await monitor.stop()


async def test_at_the_cap_a_held_pause_keeps_reminding_and_an_open_gate_claims_no_pause(
    tmp_path: Path, probe: _Probe, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``intake_paused`` is the only disk alert, and it says intake IS paused. With the gate open
    that would be false, so the cap raises none; a held pause keeps its reminders."""

    def monitor_on(gate: IntakeGate, sink: _Sink) -> IntakeBoundMonitor:
        return IntakeBoundMonitor(
            cast(Store, _Store(tmp_path / "s.db")),
            gate,
            min_free_disk_mb=FLOOR_MIB,
            alert_sink=sink,
        )

    open_sink = _Sink()
    open_monitor = monitor_on(IntakeGate(), open_sink)
    await _reach_cap(open_monitor, probe, clock, monkeypatch)
    assert open_sink.paused == 0, "an open gate must not report a pause"
    await probe.finish_hung(open_monitor)

    held_sink = _Sink()
    gate = IntakeGate()
    held = monitor_on(gate, held_sink)
    probe.free_mib = LOW_MIB
    await held.check_once()
    assert gate.reasons == {DISK_REASON} and held_sink.paused == 1, "control: the pause is held"
    await _reach_cap(held, probe, clock, monkeypatch)
    at_cap = held_sink.paused
    assert at_cap > 1, "control: reminders ran on the way to the cap"
    clock.now += _PAST_STUCK_LIMIT
    await held.check_once()
    assert held_sink.paused == at_cap + 1, "a held pause must keep reminding at the cap"
    await probe.finish_hung(held)


async def test_healthy_ticks_reuse_one_thread(tmp_path: Path, probe: _Probe) -> None:
    """``Thread.start`` blocks the event loop until the thread runs, so a tick must not pay it."""
    monitor = _disk_monitor(tmp_path, IntakeGate())
    for _ in range(5):
        await monitor.check_once()
    assert probe.started == 5
    assert len(set(probe.threads)) == 1, "a healthy tick started a new thread"
    await monitor.stop()
    for _ in range(2000):
        if not probe.threads[0].is_alive():
            break
        await asyncio.sleep(0.005)
    assert not probe.threads[0].is_alive(), "stop must retire an idle worker"


async def test_a_thread_start_failure_is_an_unmeasured_tick(
    tmp_path: Path, probe: _Probe, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(_: threading.Thread) -> None:
        raise MemoryError("no thread")

    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    probe.free_mib = LOW_MIB
    await monitor.check_once()
    await monitor.stop()
    gate.hold(DISK_REASON)
    probe.free_mib = HIGH_MIB  # a measurement here would release, so the assertion can differ
    started = probe.started
    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, "start", refuse)
        await monitor.check_once()  # must not raise
    assert probe.started == started, "control: no probe ran"
    assert gate.reasons == {DISK_REASON}, "an unmeasured tick leaves the pause as it was"


async def test_a_monitor_dropped_without_stop_ends_its_idle_thread(
    tmp_path: Path, probe: _Probe
) -> None:
    monitor = _disk_monitor(tmp_path, IntakeGate())
    await monitor.check_once()
    thread = probe.threads[0]
    assert thread.is_alive(), "control: the idle worker is running"
    del monitor
    gc.collect()
    await asyncio.to_thread(thread.join, 10.0)
    assert not thread.is_alive(), "a dropped monitor left its idle probe thread running"


async def test_a_late_high_reading_does_not_release_a_held_pause(
    tmp_path: Path, probe: _Probe, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    probe.free_mib = LOW_MIB
    await monitor.check_once()
    assert gate.reasons == {DISK_REASON}, "control: the pause is held"

    probe.free_mib = HIGH_MIB
    await _tick_into_hang(monitor, probe, monkeypatch)  # leaves a probe that will report HIGH
    probe.free_mib = LOW_MIB
    await probe.finish_hung(monitor)
    assert gate.reasons == {DISK_REASON}, "a result nobody was waiting for released the pause"

    await monitor.check_once()
    assert probe.started == 3, "the tick after a dropped result measures afresh"
    assert gate.reasons == {DISK_REASON}, "the stale HIGH reading was used instead of the new one"


async def test_a_late_low_reading_does_not_newly_hold(
    tmp_path: Path, probe: _Probe, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    probe.free_mib = LOW_MIB
    await _tick_into_hang(monitor, probe, monkeypatch)
    probe.free_mib = HIGH_MIB
    await probe.finish_hung(monitor)
    assert gate.is_open, "a result nobody was waiting for started a pause"
    await monitor.check_once()
    assert probe.started == 2 and gate.is_open


async def test_a_late_failure_is_not_logged_as_unretrieved(
    tmp_path: Path,
    probe: _Probe,
    clock: _Clock,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    late = OSError("late failure")
    unhandled: list[dict[str, Any]] = []
    # The loop can be shared, so the handler goes back, and only this test's error counts.
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _, ctx: unhandled.append(ctx))
    try:
        monitor = _disk_monitor(tmp_path, IntakeGate())
        probe.error = late
        with caplog.at_level(logging.INFO, logger=_LOGGER):
            await _tick_into_hang(monitor, probe, monkeypatch)
            await probe.finish_hung(monitor)
            gc.collect()  # an unretrieved exception is reported when its future is collected
            await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous)
    assert not [ctx for ctx in unhandled if ctx.get("exception") is late]
    assert not [r for r in caplog.records if r.exc_info and r.exc_info[1] is late]


async def test_normal_ticks_measure_each_tick(tmp_path: Path, probe: _Probe) -> None:
    gate = IntakeGate()
    monitor = _disk_monitor(tmp_path, gate)
    await monitor.check_once()
    assert gate.is_open
    probe.free_mib = LOW_MIB
    await monitor.check_once()
    assert gate.reasons == {DISK_REASON}
    probe.free_mib = FLOOR_MIB + 1  # inside the hysteresis band: the pause holds
    await monitor.check_once()
    assert gate.reasons == {DISK_REASON}
    probe.free_mib = HIGH_MIB
    await monitor.check_once()
    assert gate.is_open
    assert probe.started == 4, "every normal tick takes its own measurement"
    await probe.finish_hung(monitor)


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
    await probe.finish_hung(monitor)


_EXIT_SCRIPT = """
import asyncio, os, threading
from messagefoundry.config.settings import StoreBackend
from messagefoundry.pipeline import intake_bound
from messagefoundry.transports.base import IntakeGate

entered = threading.Event()
def never_returns(path, floor_mb):
    entered.set()
    threading.Event().wait()

class S:
    backend = StoreBackend.SQLITE
    path = os.path.join(os.getcwd(), "s.db")

async def main():
    intake_bound.read_disk_floor = never_returns
    intake_bound.PROBE_TIMEOUT_SECONDS = 0.05
    await intake_bound.IntakeBoundMonitor(S(), IntakeGate(), min_free_disk_mb=1).check_once()
    assert entered.wait(10.0)

asyncio.run(main())
print("exited")
"""


def test_a_probe_that_never_returns_does_not_block_process_exit(tmp_path: Path) -> None:
    done = subprocess.run(
        [sys.executable, "-c", _EXIT_SCRIPT],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "exited" in done.stdout
