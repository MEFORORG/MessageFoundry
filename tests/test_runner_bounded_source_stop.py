# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runner's plain (SHUTDOWN) source stop runs the stops concurrently (BACKLOG #1620).

``RegistryRunner.stop()`` used to await each ``source.stop()`` in turn, so N slow sources cost N
times one. They now run together, every one is still joined before the dispatchers stop (ADR 0066
D3), and a failed stop is logged rather than aborting the rest of teardown.

The runner deliberately adds no bound of its own: cutting or abandoning a stop there would let
start() rebind over a source still releasing its port or poll task. Each source's own stop() is
the bound; FileSource's is tests/test_file_source_bounded_stop.py.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import asyncio
import logging
import time

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import Stage

_STOP_SECONDS = 0.5


class _Source:
    """A stand-in source. ``mode`` picks what ``stop()`` does."""

    def __init__(self, name: str, events: list[str], mode: str) -> None:
        self.name = name
        self.events = events
        self.mode = mode

    async def stop(self) -> None:
        self.events.append(f"start:{self.name}")
        if self.mode == "slow":
            await asyncio.sleep(_STOP_SECONDS)
        elif self.mode == "fails":
            raise OSError("share went away")
        self.events.append(f"end:{self.name}")


class _Dispatcher:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def stop(self) -> None:
        self.events.append("dispatchers")


def _runner(events: list[str], **modes: str) -> RegistryRunner:
    runner = RegistryRunner(Registry(), store=None, egress=EgressSettings(deny_by_default=False))  # type: ignore[arg-type]
    for name, mode in modes.items():
        runner._sources[name] = _Source(name, events, mode)  # type: ignore[assignment]
    runner._dispatchers[Stage.INGRESS] = _Dispatcher(events)  # type: ignore[assignment]
    return runner


async def test_slow_stops_run_concurrently_and_finish_before_the_dispatchers() -> None:
    """Mutation: restore the serial loop. Red: three stops take three times one (1.5 s)."""
    events: list[str] = []
    runner = _runner(events, IB_A="slow", IB_B="slow", IB_C="slow")

    started = time.monotonic()
    await runner.stop()
    elapsed = time.monotonic() - started

    # One stop is 0.5 s and serial is 1.5 s; the cap sits between them with room for a slow runner.
    assert elapsed < _STOP_SECONDS * 2, f"three 0.5 s stops took {elapsed:.2f}s"
    assert sorted(events[:3]) == ["start:IB_A", "start:IB_B", "start:IB_C"]
    # ADR 0066 D3: every stop is joined before the dispatchers stop. Nothing is cut or abandoned.
    assert sorted(events[3:6]) == ["end:IB_A", "end:IB_B", "end:IB_C"]
    assert events[-1] == "dispatchers"
    assert runner._sources == {} and runner._pending_source_stops == []


async def test_a_failed_stop_is_logged_and_teardown_continues(
    caplog: pytest.LogCaptureFixture,
) -> None:
    events: list[str] = []
    runner = _runner(events, IB_OK="ok", IB_BAD="fails")

    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.stop()  # before this, the OSError escaped and skipped the rest of teardown

    assert "end:IB_OK" in events
    assert events[-1] == "dispatchers"
    assert "'IB_BAD': stop() failed" in caplog.text and "OSError" in caplog.text
    assert runner._sources == {}


async def test_control_healthy_stops_log_nothing(caplog: pytest.LogCaptureFixture) -> None:
    events: list[str] = []
    runner = _runner(events, IB_A="ok", IB_B="ok")

    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.stop()

    assert sorted(e for e in events if e.startswith("end:")) == ["end:IB_A", "end:IB_B"]
    assert "stop() failed" not in caplog.text
