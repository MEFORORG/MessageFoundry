# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runner's plain (SHUTDOWN) source stop runs the stops concurrently (BACKLOG #1620).

``RegistryRunner.stop()`` used to await each ``source.stop()`` in turn, so N slow sources cost N
times one. They now run together, every one is still joined before the dispatchers stop (ADR 0066
D3), and a failed stop is logged rather than aborting the rest of teardown. The failed inbound is
then kept as residual state and its error re-raised, so the next stop() or start() retries it.

The runner deliberately adds no bound of its own: cutting or abandoning a stop there would let
start() rebind over a source still releasing its port or poll task. Each source's own stop() is
the bound; FileSource's is tests/test_file_source_bounded_stop.py.

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import Stage

_RENDEZVOUS_SECONDS = 5.0  # only ever waited out when the stops run serially


class _Source:
    """A stand-in source. ``mode`` picks what ``stop()`` does."""

    def __init__(
        self, name: str, events: list[str], mode: str, barrier: asyncio.Barrier | None = None
    ) -> None:
        self.name = name
        self.events = events
        self.mode = mode
        self.barrier = barrier
        self.stop_calls = 0

    async def stop(self) -> None:
        self.stop_calls += 1
        self.events.append(f"start:{self.name}")
        if self.mode == "slow":
            assert self.barrier is not None
            # Every stop must be in flight at once to pass this rendezvous; a serial loop never does.
            await asyncio.wait_for(self.barrier.wait(), _RENDEZVOUS_SECONDS)
        elif self.mode == "fails":
            raise OSError("share went away")
        elif self.mode == "fails_once":
            if self.stop_calls == 1:
                raise OSError("shutdown raised")
        elif self.mode == "hangs":
            await asyncio.Event().wait()
        self.events.append(f"end:{self.name}")


class _Dispatcher:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def stop(self) -> None:
        self.events.append("dispatchers")


def _runner(events: list[str], **modes: str) -> RegistryRunner:
    runner = RegistryRunner(Registry(), store=None, egress=EgressSettings(deny_by_default=False))  # type: ignore[arg-type]
    slow = sum(mode == "slow" for mode in modes.values())
    barrier = asyncio.Barrier(slow) if slow else None
    for name, mode in modes.items():
        runner._sources[name] = _Source(name, events, mode, barrier)  # type: ignore[assignment]
    runner._dispatchers[Stage.INGRESS] = _Dispatcher(events)  # type: ignore[assignment]
    return runner


async def test_slow_stops_run_concurrently_and_finish_before_the_dispatchers() -> None:
    """Mutation: restore the serial loop. Red: the first stop waits alone at a three-party barrier
    and times out, so stop() raises TimeoutError."""
    events: list[str] = []
    runner = _runner(events, IB_A="slow", IB_B="slow", IB_C="slow")

    await runner.stop()

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

    # Before #1620 the OSError escaped at once and skipped the rest of teardown. It still escapes,
    # but only after the rest has run.
    with (
        caplog.at_level(logging.WARNING, logger=wiring_runner.log.name),
        pytest.raises(OSError, match="share went away"),
    ):
        await runner.stop()

    assert "end:IB_OK" in events
    assert events[-1] == "dispatchers"
    assert "'IB_BAD': stop() failed" in caplog.text and "OSError" in caplog.text
    assert runner._dispatchers == {}
    # Mutation: drop the restore. Red: the failed inbound is forgotten and never stopped again.
    assert list(runner._sources) == ["IB_BAD"]
    assert runner.has_residual_state and not runner.running


async def test_a_failed_stop_is_retried_by_the_next_stop() -> None:
    """DicomSource.stop() keeps its server when the shutdown raised, so the next stop() can retry it.
    The runner must call that next stop() on the same instance."""
    events: list[str] = []
    runner = _runner(events, IB_DICOM="fails_once")
    source = runner._sources["IB_DICOM"]

    with pytest.raises(OSError):
        await runner.stop()
    assert runner._sources == {"IB_DICOM": source}

    await runner.stop()

    assert source.stop_calls == 2  # type: ignore[attr-defined]
    assert runner._sources == {} and not runner.has_residual_state


async def test_an_outer_cancel_propagates_and_leaves_the_sources_residual() -> None:
    """ADR 0157 D7: a cancelled teardown must surface the cancel and leave _sources populated, so
    start() re-runs teardown instead of building over a listener that may still be bound."""
    events: list[str] = []
    runner = _runner(events, IB_HANG="hangs", IB_OK="ok")

    task = asyncio.create_task(runner.stop())
    while "start:IB_HANG" not in events:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert set(runner._sources) == {"IB_HANG", "IB_OK"}
    assert not runner.running


async def test_control_healthy_stops_log_nothing(caplog: pytest.LogCaptureFixture) -> None:
    events: list[str] = []
    runner = _runner(events, IB_A="ok", IB_B="ok")

    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.stop()

    assert sorted(e for e in events if e.startswith("end:")) == ["end:IB_A", "end:IB_B"]
    assert "stop() failed" not in caplog.text
