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

    def __init__(
        self,
        *,
        exit_on_terminate: bool = False,
        exit_on_kill: bool = True,
        terminate_error: BaseException | None = None,
    ) -> None:
        self.returncode: int | None = None
        self._exited = asyncio.Event()
        self._exit_on_terminate = exit_on_terminate
        self._exit_on_kill = exit_on_kill
        self._terminate_error = terminate_error
        self.terminated = asyncio.Event()
        self.waiting = asyncio.Event()
        self.killed = False

    def _finish(self, rc: int) -> None:
        if self.returncode is None:
            self.returncode = rc
            self._exited.set()

    async def wait(self) -> int:
        self.waiting.set()
        await self._exited.wait()
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        self.terminated.set()
        if self._terminate_error is not None:
            raise self._terminate_error
        if self._exit_on_terminate:
            self._finish(-15)

    def kill(self) -> None:
        self.killed = True
        if self._exit_on_kill:
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

    async def spawn(spec: ShardSpec) -> _Proc:
        return proc

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.2)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(proc.waiting.wait(), 5)
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

    async def spawn(spec: ShardSpec) -> _Proc:
        return proc

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.2)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(proc.waiting.wait(), 5)
    sup.stop()
    await asyncio.wait_for(proc.terminated.wait(), 5)
    runner.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(runner, 5)
    assert proc.killed


@pytest.mark.asyncio
async def test_a_failed_drain_is_raised_not_swallowed() -> None:
    # A terminate() that raises (Windows can refuse one) aborts the drain. That failure must reach
    # the caller, not end as a clean shutdown with a child still running.
    proc = _Proc(terminate_error=PermissionError("refused"))

    async def spawn(spec: ShardSpec) -> _Proc:
        return proc

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.2)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(proc.waiting.wait(), 5)
    sup.stop()
    with pytest.raises(PermissionError):
        await asyncio.wait_for(runner, 5)


@pytest.mark.asyncio
async def test_a_cancel_during_the_drain_after_a_watcher_failed_raises_cancelled() -> None:
    # restart=False: shard "b"'s launch raises, so run() drains shard "a". A shutdown signal during
    # that drain is still owed to the caller, which treats CancelledError as a shutdown.
    proc = _Proc()

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "b":
            await proc.waiting.wait()
            raise OSError("no file handles")
        return proc

    sup = Supervisor(
        [_spec("a"), _spec("b", 1)], spawn=_spawner(spawn), restart=False, terminate_grace=0.2
    )
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(proc.terminated.wait(), 5)
    runner.cancel()
    with pytest.raises(asyncio.CancelledError) as caught:
        await asyncio.wait_for(runner, 5)
    assert isinstance(caught.value.__cause__, OSError)
    assert proc.killed


@pytest.mark.asyncio
async def test_a_child_that_outlives_the_kill_does_not_hang_the_drain() -> None:
    proc = _Proc(exit_on_kill=False)

    async def spawn(spec: ShardSpec) -> _Proc:
        return proc

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.1)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(proc.waiting.wait(), 5)
    sup.stop()
    await asyncio.wait_for(runner, 5)
    assert proc.killed
    assert proc.returncode is None
