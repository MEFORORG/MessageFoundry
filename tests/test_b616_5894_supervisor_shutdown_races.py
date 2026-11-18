# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Supervisor shutdown races: a cancel during a spawn, and a second cancel during the drain.

Each signal handler calls ``runner.cancel()`` on the supervisor task directly, so both races are
a cancellation of :meth:`Supervisor.run` at an awkward moment. The tests inject a fake spawn and a
fake process, so no real subprocess is launched."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import pytest

from messagefoundry.pipeline.supervisor import ShardSpec, Supervisor
from tests.test_supervisor import _spec


class _Proc:
    """A stand-in for asyncio's Process. ``terminate()`` is only recorded, so the child keeps
    running until ``kill()``; that makes the drain wait out its grace and then force it."""

    pid = 4242

    def __init__(self, *, exit_on_terminate: bool = False) -> None:
        self.returncode: int | None = None
        self._exited = asyncio.Event()
        self._exit_on_terminate = exit_on_terminate
        self.terminated = asyncio.Event()
        self.killed = False

    def _finish(self, rc: int) -> None:
        if self.returncode is None:
            self.returncode = rc
            self._exited.set()

    async def wait(self) -> int:
        await self._exited.wait()
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        self.terminated.set()
        if self._exit_on_terminate:
            self._finish(-15)

    def kill(self) -> None:
        self.killed = True
        self._finish(-9)


def _spawner(
    fn: Callable[[ShardSpec], Awaitable[_Proc]],
) -> Callable[[ShardSpec], Awaitable[asyncio.subprocess.Process]]:
    """As tests/test_supervisor.py's, for this file's fake, which answers every call Supervisor
    makes on a process."""
    return fn  # type: ignore[return-value]


@pytest.mark.asyncio
async def test_cancel_while_a_child_is_being_spawned_still_drains_that_child() -> None:
    # The process exists before the spawn's await returns, as with a real launch whose fork has
    # happened. A cancel landing in that window must not lose the child.
    proc = _Proc(exit_on_terminate=True)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        entered.set()
        await release.wait()
        return proc

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=5.0)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(entered.wait(), 5)
    runner.cancel()
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(runner, 5)
    assert proc.terminated.is_set()
    assert proc.returncode is not None


@pytest.mark.asyncio
async def test_second_cancel_during_the_drain_does_not_strand_the_child() -> None:
    proc = _Proc()
    started = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        started.set()
        return proc

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.2)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(started.wait(), 5)
    await asyncio.sleep(0)
    runner.cancel()  # first signal
    await asyncio.wait_for(proc.terminated.wait(), 5)
    runner.cancel()  # second signal, while the drain waits out the grace
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(runner, 5)
    assert proc.killed
    assert proc.returncode == -9


@pytest.mark.asyncio
async def test_cancel_during_a_stop_drain_still_forces_the_child_then_raises() -> None:
    proc = _Proc()
    started = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        started.set()
        return proc

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.2)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(started.wait(), 5)
    await asyncio.sleep(0)
    sup.stop()
    await asyncio.wait_for(proc.terminated.wait(), 5)
    runner.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(runner, 5)
    assert proc.killed
