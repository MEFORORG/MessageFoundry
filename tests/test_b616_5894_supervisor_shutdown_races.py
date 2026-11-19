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

from messagefoundry.pipeline.supervisor import (
    ShardDrainError,
    ShardSpec,
    Supervisor,
    _run_supervisor,
)
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
        kill_error: BaseException | None = None,
    ) -> None:
        self.returncode: int | None = None
        self._exited = asyncio.Event()
        self._exit_on_terminate = exit_on_terminate
        self._exit_on_kill = exit_on_kill
        self._terminate_error = terminate_error
        self._kill_error = kill_error
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
        if self._kill_error is not None:
            raise self._kill_error
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
async def test_a_failed_drain_is_raised_and_still_stops_the_siblings() -> None:
    # Engine shard "a" refuses both the stop request and the kill (Windows can refuse either). That
    # must reach the caller, not end as a clean shutdown, and must not stop "b" being drained.
    a = _Proc(terminate_error=PermissionError("refused"), kill_error=PermissionError("refused"))
    b = _Proc(exit_on_terminate=True)

    async def spawn(spec: ShardSpec) -> _Proc:
        return a if spec.shard == "a" else b

    sup = Supervisor([_spec("a"), _spec("b", 1)], spawn=_spawner(spawn), terminate_grace=0.2)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(a.waiting.wait(), 5)
    await asyncio.wait_for(b.waiting.wait(), 5)
    sup.stop()
    with pytest.raises(ShardDrainError) as caught:
        await asyncio.wait_for(runner, 5)
    assert isinstance(caught.value.__cause__, PermissionError)
    assert b.terminated.is_set()
    assert b.returncode == -15


@pytest.mark.asyncio
async def test_a_refused_stop_request_falls_through_to_the_kill() -> None:
    proc = _Proc(terminate_error=PermissionError("refused"))

    async def spawn(spec: ShardSpec) -> _Proc:
        return proc

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.1)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(proc.waiting.wait(), 5)
    sup.stop()
    await asyncio.wait_for(runner, 5)
    assert proc.killed
    assert proc.returncode == -9


@pytest.mark.asyncio
async def test_a_cancel_during_the_drain_after_a_watcher_failed_raises_cancelled() -> None:
    # restart=False: engine shard "b"'s launch raises, so run() drains "a". A shutdown signal during
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
    # The drain gives up on it after the grace, and says so rather than ending as a clean shutdown.
    proc = _Proc(exit_on_kill=False)

    async def spawn(spec: ShardSpec) -> _Proc:
        return proc

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.1)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(proc.waiting.wait(), 5)
    sup.stop()
    with pytest.raises(RuntimeError, match="still running"):
        await asyncio.wait_for(runner, 5)
    assert proc.killed
    assert proc.returncode is None


@pytest.mark.asyncio
async def test_a_fatal_watcher_exit_is_not_replaced_by_a_cancel_during_the_drain() -> None:
    class _Fatal(BaseException):
        pass

    proc = _Proc()

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "b":
            await proc.waiting.wait()
            raise _Fatal
        return proc

    sup = Supervisor([_spec("a"), _spec("b", 1)], spawn=_spawner(spawn), terminate_grace=0.2)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(proc.terminated.wait(), 5)
    runner.cancel()
    with pytest.raises(_Fatal):
        await asyncio.wait_for(runner, 5)
    assert proc.killed


@pytest.mark.asyncio
async def test_a_cancel_during_a_launch_that_never_returns_still_ends_run() -> None:
    # Engine shard "b"'s spawn never returns. A shutdown signal must still end run() once the
    # grace runs out, drain the sibling "a" that did start, and report "b" as possibly stranded.
    a = _Proc(exit_on_terminate=True)
    hung = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "b":
            hung.set()
            await asyncio.Event().wait()
        return a

    sup = Supervisor([_spec("a"), _spec("b", 1)], spawn=_spawner(spawn), terminate_grace=0.2)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(a.waiting.wait(), 5)
    await asyncio.wait_for(hung.wait(), 5)
    runner.cancel()
    with pytest.raises(ShardDrainError, match="launch abandoned"):
        await asyncio.wait_for(runner, 5)
    assert a.terminated.is_set()
    assert a.returncode == -15


@pytest.mark.asyncio
async def test_an_abandoned_launch_that_returns_late_has_its_child_killed() -> None:
    late = _Proc()
    hung = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        hung.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.sleep(0.05)  # a spawn that finishes its fork despite the cancel
        return late

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.1)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(hung.wait(), 5)
    runner.cancel()
    with pytest.raises(ShardDrainError):
        await asyncio.wait_for(runner, 5)
    for _ in range(50):
        if late.killed:
            break
        await asyncio.sleep(0.02)
    assert late.killed


@pytest.mark.asyncio
async def test_a_failed_drain_exits_3_not_the_crash_loop_code() -> None:
    proc = _Proc(terminate_error=PermissionError("refused"), kill_error=PermissionError("refused"))

    async def spawn(spec: ShardSpec) -> _Proc:
        return proc

    specs = [_spec("default")]
    sup = Supervisor(specs, spawn=_spawner(spawn), terminate_grace=0.1)
    code = asyncio.create_task(_run_supervisor(sup, specs, install_signal_handlers=False))
    await asyncio.wait_for(proc.waiting.wait(), 5)
    sup.stop()
    assert await asyncio.wait_for(code, 5) == 3


async def _no_wait(delay: float) -> None:
    pass


@pytest.mark.asyncio
async def test_a_failed_drain_outranks_every_engine_shard_crash_looping() -> None:
    # Engine shard "a" trips the crash-loop breaker; "b" stays up and cannot be stopped. With both
    # counted as tripped the crash-loop code 1 is due, and the drain failure's 3 must still win.
    stuck = _Proc(terminate_error=PermissionError("refused"), kill_error=PermissionError("refused"))
    tripped = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "a":
            crash = _Proc()
            crash._finish(1)
            return crash
        return stuck

    specs = [_spec("a"), _spec("b", 1)]
    sup = Supervisor(
        specs, spawn=_spawner(spawn), terminate_grace=0.1, crash_loop_limit=1, sleep=_no_wait
    )
    code = asyncio.create_task(_run_supervisor(sup, specs, install_signal_handlers=False))
    await asyncio.wait_for(stuck.waiting.wait(), 5)
    for _ in range(100):
        if sup.crash_looped:
            tripped.set()
            break
        await asyncio.sleep(0.01)
    assert tripped.is_set()
    sup.crash_looped.add("b")  # as if "b" had tripped too
    sup.stop()
    assert await asyncio.wait_for(code, 5) == 3


@pytest.mark.asyncio
async def test_a_fatal_watcher_exit_propagates_even_when_the_drain_fails() -> None:
    class _Fatal(BaseException):
        pass

    stuck = _Proc(terminate_error=PermissionError("refused"), kill_error=PermissionError("refused"))

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "b":
            await stuck.waiting.wait()
            raise _Fatal
        return stuck

    sup = Supervisor([_spec("a"), _spec("b", 1)], spawn=_spawner(spawn), terminate_grace=0.1)
    with pytest.raises(_Fatal) as caught:
        await asyncio.wait_for(sup.run(), 5)
    assert isinstance(caught.value.__cause__, ShardDrainError)


@pytest.mark.asyncio
async def test_a_real_kill_failure_is_the_cause_ahead_of_an_abandoned_launch() -> None:
    stuck = _Proc(terminate_error=PermissionError("refused"), kill_error=PermissionError("refused"))
    hung = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "b":
            hung.set()
            await asyncio.Event().wait()
        return stuck

    sup = Supervisor([_spec("a"), _spec("b", 1)], spawn=_spawner(spawn), terminate_grace=0.1)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(stuck.waiting.wait(), 5)
    await asyncio.wait_for(hung.wait(), 5)
    runner.cancel()
    with pytest.raises(ShardDrainError, match="2 engine shard") as caught:
        await asyncio.wait_for(runner, 5)
    assert isinstance(caught.value.__cause__, PermissionError)


def test_a_non_finite_terminate_grace_is_refused() -> None:
    with pytest.raises(ValueError, match="terminate_grace"):
        Supervisor([_spec("default")], terminate_grace=float("inf"))
