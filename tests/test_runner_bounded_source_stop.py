# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runner's plain (SHUTDOWN) source stop runs the stops concurrently (BACKLOG #1620).

``RegistryRunner.stop()`` used to await each inbound's ``stop()`` in turn, so N slow inbounds cost
N times one. They now run together, and every one is still joined before the dispatchers stop. A
failed stop is logged and re-raised once every stop is joined, before the dispatchers stop: its
listener may still be live, so the drain side is kept as residual state, and the next stop() or
start() retries it, as the serial loop left it (ADR 0157 Amendment B).

The runner deliberately adds no bound of its own: cutting or abandoning a stop there would let
start() rebind over an inbound still releasing its port or poll task. Each inbound's own stop() is
the bound; FileSource's is tests/test_file_source_bounded_stop.py. The one exception is a
teardown cancelled from outside: the in-flight stops get a bounded grace, then are cut, and a
second cancel cuts at once (ADR 0157 Amendment B).

Deliberately ASCII-only: pytest echoes a failing body to a cp1252 console on Windows.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable

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
        self,
        name: str,
        events: list[str],
        mode: str,
        barrier: asyncio.Barrier | None = None,
        gate: asyncio.Event | None = None,
    ) -> None:
        self.name = name
        self.events = events
        self.mode = mode
        self.barrier = barrier
        self.gate = gate
        self.stop_calls = 0

    async def stop(self) -> None:
        self.stop_calls += 1
        self.events.append(f"start:{self.name}")
        try:
            await self._body()
        except asyncio.CancelledError:
            self.events.append(f"cut:{self.name}")
            if self.mode == "fails_when_cut":
                raise OSError("port release failed") from None
            if self.mode == "slow_cut":
                assert self.gate is not None
                # Cleanup that outlives the cut AND a re-cancel, as one inside a thread or a
                # store call does. The test sets the gate in a finally, so this always ends.
                while not self.gate.is_set():
                    with contextlib.suppress(asyncio.CancelledError):
                        await self.gate.wait()
                self.events.append(f"cut_done:{self.name}")
            raise
        self.events.append(f"end:{self.name}")

    async def _body(self) -> None:
        if self.mode == "slow":
            assert self.barrier is not None
            # Every stop must be in flight at once to pass this rendezvous; a serial loop never does.
            await asyncio.wait_for(self.barrier.wait(), _RENDEZVOUS_SECONDS)
        elif self.mode == "fails":
            raise OSError("share went away")
        elif self.mode == "fails_once":
            if self.stop_calls == 1:
                raise OSError("shutdown raised")
        elif self.mode == "slow_cut":
            if self.stop_calls == 1:
                await asyncio.Event().wait()
        elif self.mode in ("hangs", "fails_when_cut"):
            await asyncio.Event().wait()
        elif self.mode == "self_cancels":
            raise asyncio.CancelledError
        elif self.mode == "gated":
            assert self.gate is not None
            await self.gate.wait()


class _Dispatcher:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def stop(self) -> None:
        self.events.append("dispatchers")


class _Destination:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def aclose(self) -> None:
        self.events.append("aclose")


async def _park() -> None:
    await asyncio.Event().wait()


def _runner(events: list[str], gate: asyncio.Event | None = None, **modes: str) -> RegistryRunner:
    runner = RegistryRunner(Registry(), store=None, egress=EgressSettings(deny_by_default=False))  # type: ignore[arg-type]
    slow = sum(mode == "slow" for mode in modes.values())
    barrier = asyncio.Barrier(slow) if slow else None
    for name, mode in modes.items():
        runner._sources[name] = _Source(name, events, mode, barrier, gate)  # type: ignore[assignment]
    runner._dispatchers[Stage.INGRESS] = _Dispatcher(events)  # type: ignore[assignment]
    return runner


async def test_slow_stops_run_concurrently_and_finish_before_the_dispatchers() -> None:
    """Mutation: restore the serial loop. Red: the first stop waits alone at a three-party barrier
    and times out, so stop() raises TimeoutError."""
    events: list[str] = []
    runner = _runner(events, IB_A="slow", IB_B="slow", IB_C="slow")

    await runner.stop()

    assert sorted(events[:3]) == ["start:IB_A", "start:IB_B", "start:IB_C"]
    # Every stop is joined before the dispatchers stop. Nothing is cut or abandoned.
    assert sorted(events[3:6]) == ["end:IB_A", "end:IB_B", "end:IB_C"]
    assert events[-1] == "dispatchers"
    assert runner._sources == {} and runner._pending_source_stops == []


async def test_a_failed_stop_keeps_the_drain_side(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A failed stop may leave its listener live, still ACKing into the store. Teardown must not
    clear the drain side under it. Mutation: run the rest of teardown before the raise (head
    8bf008396). Red: the dispatchers are stopped and cleared. Mutation: wait with
    return_when=FIRST_EXCEPTION. Red: stop() raises while IB_OK is still stopping."""
    events: list[str] = []
    gate = asyncio.Event()
    runner = _runner(events, gate, IB_OK="gated", IB_BAD="fails")
    worker: asyncio.Task[None] = asyncio.create_task(_park())
    runner._workers["OB_X"] = worker
    runner._destinations["OB_X"] = _Destination(events)  # type: ignore[assignment]

    try:
        with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
            task = asyncio.create_task(runner.stop())
            await _started(events, "IB_OK", "IB_BAD")
            await _yield()
            assert not task.done()  # every stop is joined before the failure is raised
            gate.set()
            with pytest.raises(OSError, match="share went away"):
                await task

        assert "end:IB_OK" in events
        assert "'IB_BAD': stop() failed" in caplog.text and "OSError" in caplog.text
        # The whole drain side survives: dispatchers, workers, destinations.
        assert "dispatchers" not in events and "aclose" not in events
        assert list(runner._dispatchers) == [Stage.INGRESS]
        assert runner._workers == {"OB_X": worker} and not worker.done()
        assert list(runner._destinations) == ["OB_X"]
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
    # Only the inbound that may still be live stays registered; IB_OK's listener is closed.
    assert set(runner._sources) == {"IB_BAD"}
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


async def test_a_stop_that_ends_cancelled_is_raised_as_a_runtime_error() -> None:
    """Nobody cancelled this teardown, so it must not raise CancelledError: the graph supervisor
    would read that as its own cancel and exit. Mutation: re-raise the CancelledError. Red: the
    raise is a CancelledError, not a RuntimeError."""
    events: list[str] = []
    runner = _runner(events, IB_ODD="self_cancels", IB_OK="ok")

    with pytest.raises(RuntimeError, match=r"'IB_ODD': stop\(\) ended cancelled"):
        await runner.stop()

    assert "end:IB_OK" in events and "dispatchers" not in events
    assert set(runner._sources) == {"IB_ODD"}


async def _started(events: list[str], *names: str) -> None:
    async def spin() -> None:
        while not all(f"start:{name}" in events for name in names):
            await asyncio.sleep(0)

    await asyncio.wait_for(spin(), _RENDEZVOUS_SECONDS)  # a regression fails, never hangs


async def _until(condition: Callable[[], bool]) -> None:
    while not condition():
        await asyncio.sleep(0)


async def _yield(turns: int = 5) -> None:
    for _ in range(turns):
        await asyncio.sleep(0)


async def test_an_outer_cancel_lets_the_in_flight_stops_finish() -> None:
    """ADR 0157 Amendment B. Mutation: await gather() over the stops again. Red: the cancel cuts
    both stops at once, so neither records end: and both record cut:."""
    events: list[str] = []
    gate = asyncio.Event()
    runner = _runner(events, gate, IB_A="gated", IB_B="gated")

    task = asyncio.create_task(runner.stop())
    await _started(events, "IB_A", "IB_B")
    task.cancel()
    await _yield()
    assert not task.done()  # the grace holds the cancel back while the stops run
    gate.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert sorted(e for e in events if e.startswith(("end:", "cut:"))) == ["end:IB_A", "end:IB_B"]
    assert "dispatchers" not in events  # the rest of teardown never ran
    # Both stopped cleanly, so neither stays registered; the drain side is still residual state,
    # so start() re-runs teardown instead of building over it.
    assert runner._sources == {}
    assert runner.has_residual_state and not runner.running


async def test_an_outer_cancel_cuts_a_hung_stop_after_the_grace(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The grace is bounded, so one wedged stop cannot hang asyncio.run's shutdown. Mutation: wait
    with no timeout. Red: the task never finishes and wait_for times out."""
    monkeypatch.setattr(wiring_runner, "_CANCELLED_STOP_GRACE_SECONDS", 0.05)
    events: list[str] = []
    runner = _runner(events, IB_HANG="hangs", IB_OK="ok")

    task = asyncio.create_task(runner.stop())
    await _started(events, "IB_HANG", "IB_OK")
    task.cancel()
    with (
        caplog.at_level(logging.WARNING, logger=wiring_runner.log.name),
        pytest.raises(asyncio.CancelledError),
    ):
        await asyncio.wait_for(task, _RENDEZVOUS_SECONDS)

    assert "end:IB_OK" in events and "cut:IB_HANG" in events
    assert "cut 1 inbound stop(s) still running after the 0.1s grace" in caplog.text
    assert set(runner._sources) == {"IB_HANG"}
    assert not runner.running


async def test_a_second_outer_cancel_cuts_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mutation: drop the CancelledError arm around the grace wait. Red: the second cancel escapes
    with the hung stop never cancelled, so cut:IB_HANG is missing."""
    monkeypatch.setattr(wiring_runner, "_CANCELLED_STOP_GRACE_SECONDS", 60.0)
    events: list[str] = []
    runner = _runner(events, IB_HANG="hangs")

    task = asyncio.create_task(runner.stop())
    await _started(events, "IB_HANG")
    task.cancel()
    await _yield()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, _RENDEZVOUS_SECONDS)

    assert "cut:IB_HANG" in events
    assert set(runner._sources) == {"IB_HANG"}


async def test_two_coalesced_cancels_cut_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two cancel() calls in one loop turn reach the coroutine as ONE CancelledError. Mutation: drop
    the cancelling() > 1 check. Red: the grace is waited out and wait_for times out."""
    monkeypatch.setattr(wiring_runner, "_CANCELLED_STOP_GRACE_SECONDS", 60.0)
    events: list[str] = []
    runner = _runner(events, IB_HANG="hangs")

    task = asyncio.create_task(runner.stop())
    await _started(events, "IB_HANG")
    task.cancel()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, _RENDEZVOUS_SECONDS)

    assert "cut:IB_HANG" in events
    assert set(runner._sources) == {"IB_HANG"}


async def test_a_cancel_the_task_already_carried_does_not_skip_the_grace() -> None:
    """stop() run from cleanup after a swallowed cancel: cancelling() is already 1. Mutation:
    compare cancelling() > 1 with no baseline. Red: the first cancel here cuts both stops."""
    events: list[str] = []
    gate = asyncio.Event()
    runner = _runner(events, gate, IB_A="gated", IB_B="gated")

    async def cleanup_after_a_cancel() -> None:
        with contextlib.suppress(asyncio.CancelledError):  # swallowed without uncancel()
            await asyncio.Event().wait()
        await runner.stop()

    task = asyncio.create_task(cleanup_after_a_cancel())
    await _yield()
    task.cancel()
    await _started(events, "IB_A", "IB_B")
    task.cancel()
    await _yield()
    assert not task.done()
    gate.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert sorted(e for e in events if e.startswith(("end:", "cut:"))) == ["end:IB_A", "end:IB_B"]


async def test_a_failure_before_an_outer_cancel_is_logged_by_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The cancel path still retrieves, names and redacts a stop that had already failed."""
    events: list[str] = []
    gate = asyncio.Event()
    runner = _runner(events, gate, IB_BAD="fails", IB_A="gated")

    task = asyncio.create_task(runner.stop())
    await _started(events, "IB_BAD", "IB_A")
    task.cancel()
    await _yield()
    gate.set()
    with (
        caplog.at_level(logging.WARNING, logger=wiring_runner.log.name),
        pytest.raises(asyncio.CancelledError),
    ):
        await task

    assert "'IB_BAD': stop() failed" in caplog.text and "OSError" in caplog.text
    assert set(runner._sources) == {"IB_BAD"}


async def test_a_third_cancel_still_joins_the_cut_stops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A third cancel lands while the cut stops are being joined. gather forwards it to them but
    still resolves only once each has finished, so stop() cannot return with one running and no
    later stop() can overlap it. A pin, not a fix: it is green on head 8bf008396 too. Mutation:
    drop the gather of the cut stops. Red: stop() returns while the cut
    stop is still running."""
    monkeypatch.setattr(wiring_runner, "_CANCELLED_STOP_GRACE_SECONDS", 60.0)
    events: list[str] = []
    gate = asyncio.Event()
    runner = _runner(events, gate, IB_DICOM="slow_cut")
    source = runner._sources["IB_DICOM"]

    try:
        first = asyncio.create_task(runner.stop())
        await _started(events, "IB_DICOM")
        first.cancel()
        first.cancel()  # coalesced: cut at once
        await asyncio.wait_for(_until(lambda: "cut:IB_DICOM" in events), _RENDEZVOUS_SECONDS)
        first.cancel()  # lands in the join of the cut stop
        await _yield()
        assert not first.done()  # still joining the cut stop
        gate.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(first, _RENDEZVOUS_SECONDS)
        assert "cut_done:IB_DICOM" in events
    finally:
        gate.set()  # a failure must not leave the cut stop absorbing cancels forever

    await runner.stop()

    assert events.index("cut_done:IB_DICOM") < events.index("end:IB_DICOM")
    assert source.stop_calls == 2  # type: ignore[attr-defined]
    assert runner._sources == {}


async def test_an_outer_cancel_still_reports_a_stop_cancelled_by_someone_else(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The cancel path counts a stop that ended cancelled without the runner cutting it. Mutation:
    skip every cancelled task there. Red: IB_ODD is never reported."""
    events: list[str] = []
    gate = asyncio.Event()
    runner = _runner(events, gate, IB_ODD="self_cancels", IB_A="gated")

    task = asyncio.create_task(runner.stop())
    await _started(events, "IB_ODD", "IB_A")
    task.cancel()
    await _yield()
    gate.set()
    with (
        caplog.at_level(logging.WARNING, logger=wiring_runner.log.name),
        pytest.raises(asyncio.CancelledError),
    ):
        await task

    assert "1 inbound stop(s) were cancelled by something other than this teardown" in caplog.text
    assert set(runner._sources) == {"IB_ODD"}


async def test_a_cut_stop_that_fails_while_cut_is_still_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A cut stop whose cancellation handling raises a real error must not vanish into the cut
    count. Mutation: skip every task the runner cut. Red: the OSError is never logged."""
    monkeypatch.setattr(wiring_runner, "_CANCELLED_STOP_GRACE_SECONDS", 60.0)
    events: list[str] = []
    runner = _runner(events, IB_DICOM="fails_when_cut")

    task = asyncio.create_task(runner.stop())
    await _started(events, "IB_DICOM")
    task.cancel()
    task.cancel()
    with (
        caplog.at_level(logging.WARNING, logger=wiring_runner.log.name),
        pytest.raises(asyncio.CancelledError),
    ):
        await asyncio.wait_for(task, _RENDEZVOUS_SECONDS)

    assert "'IB_DICOM': stop() failed" in caplog.text and "port release failed" in caplog.text
    assert set(runner._sources) == {"IB_DICOM"}


async def test_control_healthy_stops_log_nothing(caplog: pytest.LogCaptureFixture) -> None:
    events: list[str] = []
    runner = _runner(events, IB_A="ok", IB_B="ok")

    with caplog.at_level(logging.WARNING, logger=wiring_runner.log.name):
        await runner.stop()

    assert sorted(e for e in events if e.startswith("end:")) == ["end:IB_A", "end:IB_B"]
    assert "stop() failed" not in caplog.text
