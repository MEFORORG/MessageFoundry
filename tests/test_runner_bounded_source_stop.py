# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runner's plain (SHUTDOWN) source stop is concurrent and bounded (BACKLOG #1620).

``RegistryRunner.stop()`` used to await each ``source.stop()`` in turn with no bound, so one source
blocked on a dead share held shutdown (and ``_reload_lock``) for as long as the share call ran, and N
slow sources cost N times one. The plain path now reuses the demotion mechanism: one deadline over
all stops, and a stop that misses it is abandoned into ``_pending_source_stops`` rather than cut,
then settled under the existing settle bound once the rest of teardown is done.

The bound limits how long the runner waits. A stop blocked in ``asyncio.to_thread`` keeps its thread
until the call returns; the blocking sources below release theirs at the end of each test.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Iterator

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import Stage

# Both the first deadline and the SHUTDOWN settle read this constant, so the worst case is two.
_BOUND = 0.4


class _Source:
    """A stand-in source. ``mode`` picks what ``stop()`` does."""

    def __init__(self, name: str, events: list[str], mode: str, release: threading.Event) -> None:
        self.name = name
        self.events = events
        self.mode = mode
        self.release = release

    async def stop(self) -> None:
        self.events.append(f"start:{self.name}")
        if self.mode == "blocked":
            # A share call that ignores the stop: a worker thread asyncio cannot interrupt.
            await asyncio.to_thread(self.release.wait, 10)
        elif self.mode == "slow":
            await asyncio.sleep(_BOUND * 0.6)
        elif self.mode == "late":
            await asyncio.sleep(_BOUND * 1.4)  # misses the first deadline, beats the settle
        elif self.mode == "fails":
            raise OSError("share went away")
        self.events.append(f"end:{self.name}")


class _Dispatcher:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def stop(self) -> None:
        self.events.append("dispatchers")


@pytest.fixture
def release() -> Iterator[threading.Event]:
    event = threading.Event()
    yield event
    event.set()  # free any worker thread a blocked stop left behind


@pytest.fixture(autouse=True)
def _short_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wiring_runner, "_PENDING_STOP_SETTLE_SECONDS", _BOUND)


def _runner(events: list[str], release: threading.Event, **modes: str) -> RegistryRunner:
    runner = RegistryRunner(Registry(), store=None, egress=EgressSettings(deny_by_default=False))  # type: ignore[arg-type]
    for name, mode in modes.items():
        runner._sources[name] = _Source(name, events, mode, release)  # type: ignore[assignment]
    runner._dispatchers[Stage.INGRESS] = _Dispatcher(events)  # type: ignore[assignment]
    return runner


async def test_two_blocked_stops_are_bounded_and_concurrent(
    release: threading.Event, caplog: pytest.LogCaptureFixture
) -> None:
    """Mutation: restore the serial unbounded loop. Red: stop() waits on the thread (10 s)."""
    events: list[str] = []
    runner = _runner(events, release, IB_A="blocked", IB_B="blocked")

    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.stop()
    elapsed = time.monotonic() - started

    # One deadline for both, then one settle: two bounds, not two per source.
    assert elapsed < _BOUND * 2.75, f"stop() took {elapsed:.2f}s against a {_BOUND}s bound"
    assert sorted(events[:2]) == ["start:IB_A", "start:IB_B"], "the stops did not start together"
    assert "dispatchers" in events
    text = caplog.text
    assert "did not finish within" in text and "IB_A, IB_B" in text
    assert runner._sources == {} and runner._pending_source_stops == []


async def test_healthy_slow_stops_run_in_parallel_before_the_dispatchers(
    release: threading.Event, caplog: pytest.LogCaptureFixture
) -> None:
    """Two stops that each take 0.6 of the bound finish inside one bound, before the dispatchers
    stop (ADR 0066 D3)."""
    events: list[str] = []
    runner = _runner(events, release, IB_A="slow", IB_B="slow")

    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.stop()
    elapsed = time.monotonic() - started

    assert elapsed < _BOUND * 1.1, f"serial would be {_BOUND * 1.2:.2f}s; took {elapsed:.2f}s"
    assert sorted(events[2:4]) == ["end:IB_A", "end:IB_B"]
    assert events[-1] == "dispatchers"
    assert "did not finish within" not in caplog.text


async def test_a_stop_that_misses_the_deadline_is_not_cut_and_finishes(
    release: threading.Event,
) -> None:
    """A stop past the first deadline is parked, not cancelled, so a File or Database stop waiting
    out a store call is not cut there; it finishes inside the settle."""
    events: list[str] = []
    runner = _runner(events, release, IB_LATE="late")

    await runner.stop()

    assert "end:IB_LATE" in events, "the late stop was cancelled at the first deadline"
    assert events.index("dispatchers") < events.index("end:IB_LATE")


async def test_control_healthy_stops_complete_and_a_failure_is_logged(
    release: threading.Event, caplog: pytest.LogCaptureFixture
) -> None:
    events: list[str] = []
    runner = _runner(events, release, IB_OK="ok", IB_BAD="fails")

    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.stop()  # a failed source stop no longer aborts the rest of teardown

    assert "end:IB_OK" in events
    assert events[-1] == "dispatchers"
    assert "inbound 'IB_BAD' stop() failed" in caplog.text and "OSError" in caplog.text
    assert "did not finish within" not in caplog.text


async def test_a_cancelled_stop_parks_its_source_stops(release: threading.Event) -> None:
    events: list[str] = []
    runner = _runner(events, release, IB_A="blocked")

    task = asyncio.create_task(runner._stop_sources_shutdown())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert [t.get_name() for t in runner._pending_source_stops] == ["shutdown-stop:IB_A"]
    release.set()
    await runner._settle_pending_source_stops()
    assert runner._pending_source_stops == []
