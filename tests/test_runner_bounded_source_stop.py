# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runner's plain source stop is concurrent and bounded (BACKLOG #1620).

``RegistryRunner.stop()`` used to await each ``source.stop()`` in turn with no bound, so one source
blocked on a dead share held shutdown (and ``_reload_lock``) for as long as the share call ran, and N
slow sources cost N times one. The demotion path was already bounded; the plain path now shares its
deadline. ``stop_inbound`` is bounded the same way and still raises the source's own stop error.

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
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import Stage

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


def _runner(
    events: list[str], release: threading.Event, **modes: str
) -> tuple[RegistryRunner, dict[str, _Source]]:
    runner = RegistryRunner(Registry(), store=None, egress=EgressSettings(deny_by_default=False))  # type: ignore[arg-type]
    sources = {name: _Source(name, events, mode, release) for name, mode in modes.items()}
    runner._sources.update(sources)  # type: ignore[arg-type]
    return runner, sources


async def test_two_blocked_stops_cost_one_bound_not_two(
    release: threading.Event, caplog: pytest.LogCaptureFixture
) -> None:
    """Mutation: restore the serial unbounded loop. Red: stop() waits on the thread (10 s)."""
    events: list[str] = []
    runner, _ = _runner(events, release, IB_A="blocked", IB_B="blocked")
    runner._dispatchers[Stage.INGRESS] = _Dispatcher(events)  # type: ignore[assignment]

    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.stop()
    elapsed = time.monotonic() - started

    assert elapsed < _BOUND * 1.75, f"stop() took {elapsed:.2f}s against a {_BOUND}s bound"
    # Both began before either was given up on: concurrent, not one after the other.
    assert events[:2] == ["start:IB_A", "start:IB_B"] or events[:2] == ["start:IB_B", "start:IB_A"]
    # ADR 0066 D3: the dispatchers stop only after the source phase is over.
    assert events[-1] == "dispatchers"
    text = caplog.text
    assert "did not finish within" in text and "IB_A" in text and "IB_B" in text
    assert runner._sources == {}


async def test_healthy_slow_stops_run_in_parallel(
    release: threading.Event, caplog: pytest.LogCaptureFixture
) -> None:
    """Two stops that each take 0.6 of the bound finish inside one bound, and both complete."""
    events: list[str] = []
    runner, _ = _runner(events, release, IB_A="slow", IB_B="slow")

    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.stop()
    elapsed = time.monotonic() - started

    assert elapsed < _BOUND * 1.1, f"serial would be {_BOUND * 1.2:.2f}s; took {elapsed:.2f}s"
    assert sorted(e for e in events if e.startswith("end:")) == ["end:IB_A", "end:IB_B"]
    assert "did not finish within" not in caplog.text


async def test_control_healthy_stops_complete_and_a_failure_is_logged(
    release: threading.Event, caplog: pytest.LogCaptureFixture
) -> None:
    events: list[str] = []
    runner, _ = _runner(events, release, IB_OK="ok", IB_BAD="fails")
    runner._dispatchers[Stage.INGRESS] = _Dispatcher(events)  # type: ignore[assignment]

    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.stop()  # a failed source stop no longer aborts the rest of teardown

    assert "end:IB_OK" in events
    assert events[-1] == "dispatchers"
    assert "'IB_BAD': stop() failed" in caplog.text and "OSError" in caplog.text
    assert "did not finish within" not in caplog.text


async def test_stop_inbound_is_bounded(release: threading.Event) -> None:
    events: list[str] = []
    runner, _ = _runner(events, release, IB_A="blocked")

    started = time.monotonic()
    await runner.stop_inbound("IB_A")

    assert time.monotonic() - started < _BOUND * 1.75
    assert "IB_A" not in runner._sources


async def test_stop_inbound_still_raises_the_sources_own_error(release: threading.Event) -> None:
    events: list[str] = []
    runner, _ = _runner(events, release, IB_BAD="fails")

    with pytest.raises(OSError, match="share went away"):
        await runner.stop_inbound("IB_BAD")


async def test_a_cancelled_stop_leaves_no_stop_task_behind(release: threading.Event) -> None:
    events: list[str] = []
    runner, sources = _runner(events, release, IB_A="blocked")

    task = asyncio.create_task(runner._stop_sources_bounded(list(sources.items())))  # type: ignore[arg-type]
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0)
    leftover: list[Any] = [
        t for t in asyncio.all_tasks() if t.get_name().startswith("stop:") and not t.done()
    ]
    assert leftover == []
