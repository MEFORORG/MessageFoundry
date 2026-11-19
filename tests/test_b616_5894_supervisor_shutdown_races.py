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


async def _hang_honouring_cancel() -> None:
    await asyncio.Event().wait()


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_launch_that_honours_the_cancel_is_not_exit_3() -> None:
    # Engine shard "b"'s spawn never returns but honours a cancel, as asyncio's own launch does.
    # The drain cancels it, and since no child can remain, the shutdown is clean: exit 0, not 3.
    a = _Proc(exit_on_terminate=True)
    hung = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "b":
            hung.set()
            await _hang_honouring_cancel()
        return a

    specs = [_spec("a"), _spec("b", 1)]
    sup = Supervisor(specs, spawn=_spawner(spawn), terminate_grace=0.1)
    code = asyncio.create_task(_run_supervisor(sup, specs, install_signal_handlers=False))
    await asyncio.wait_for(a.waiting.wait(), 5)
    await asyncio.wait_for(hung.wait(), 5)
    sup.stop()  # a stop alone ends run(), the hung launch notwithstanding
    assert await asyncio.wait_for(code, 5) == 0
    assert a.terminated.is_set()
    assert a.returncode == -15
    assert not sup._launches


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_plain_future_launch_that_never_resolves_is_cancelled_and_not_exit_3() -> None:
    pending: list[asyncio.Future[_Proc]] = []

    def spawn(spec: ShardSpec) -> asyncio.Future[_Proc]:
        fut: asyncio.Future[_Proc] = asyncio.get_running_loop().create_future()
        pending.append(fut)
        return fut

    specs = [_spec("default")]
    sup = Supervisor(specs, spawn=_spawner(spawn), terminate_grace=0.1)
    code = asyncio.create_task(_run_supervisor(sup, specs, install_signal_handlers=False))
    for _ in range(100):
        if pending:
            break
        await asyncio.sleep(0.01)
    assert pending
    sup.stop()
    assert await asyncio.wait_for(code, 5) == 0
    assert pending[0].cancelled()
    assert not sup._launches


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_launch_that_ignores_the_cancel_past_the_grace_is_exit_3_and_returns() -> None:
    # The launch outlives its cancellation, so its child may exist: exit 3. And supervise must
    # still return rather than wait on the launch.
    a = _Proc(exit_on_terminate=True)
    hung = asyncio.Event()
    release = asyncio.Event()
    late = _Proc()

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "b":
            hung.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    continue  # ignores every cancel
            return late
        return a

    specs = [_spec("a"), _spec("b", 1)]
    sup = Supervisor(specs, spawn=_spawner(spawn), terminate_grace=0.1)
    try:
        runner = asyncio.create_task(sup.run())
        await asyncio.wait_for(a.waiting.wait(), 5)
        await asyncio.wait_for(hung.wait(), 5)
        runner.cancel()
        with pytest.raises(ShardDrainError, match="still running") as caught:
            await asyncio.wait_for(runner, 5)
        assert "cancelled at shutdown" in str(caught.value)
        assert a.returncode == -15
        # The supervisor still holds the stranded launch, so it is not garbage-collected.
        assert len(sup._launches) == 1
    finally:
        release.set()  # let the launch end, so the test leaves no pending task behind
    await asyncio.wait_for(asyncio.gather(*sup._launches), 5)


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_launch_that_ignores_the_cancel_past_the_grace_exits_3() -> None:
    release = asyncio.Event()
    hung = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        hung.set()
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                continue
        return _Proc(exit_on_terminate=True)

    specs = [_spec("default")]
    sup = Supervisor(specs, spawn=_spawner(spawn), terminate_grace=0.1)
    try:
        code = asyncio.create_task(_run_supervisor(sup, specs, install_signal_handlers=False))
        await asyncio.wait_for(hung.wait(), 5)
        sup.stop()
        assert await asyncio.wait_for(code, 5) == 3
    finally:
        release.set()
    await asyncio.wait_for(asyncio.gather(*sup._launches), 5)


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_run_refuses_to_start_while_a_launch_from_an_earlier_run_is_pending() -> None:
    release = asyncio.Event()
    hung = asyncio.Event()
    proc = _Proc(exit_on_terminate=True)

    async def spawn(spec: ShardSpec) -> _Proc:
        hung.set()
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                continue
        return proc

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.1)
    try:
        runner = asyncio.create_task(sup.run())
        await asyncio.wait_for(hung.wait(), 5)
        sup.stop()
        with pytest.raises(ShardDrainError):
            await asyncio.wait_for(runner, 5)
        # The next run would blame itself for the old launch, so it refuses instead.
        with pytest.raises(RuntimeError, match="still pending"):
            await asyncio.wait_for(sup.run(), 5)
    finally:
        release.set()
    await asyncio.wait_for(asyncio.gather(*sup._launches), 5)
    # Once the old launch has ended, a run starts, and stops cleanly.
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(proc.waiting.wait(), 5)
    sup.stop()
    await asyncio.wait_for(runner, 5)
    assert sup.drain_failure is None


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_launch_returning_within_the_grace_gets_the_graceful_stop() -> None:
    proc = _Proc(exit_on_terminate=True)
    hung = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        hung.set()
        await asyncio.sleep(0.05)
        return proc

    specs = [_spec("default")]
    sup = Supervisor(specs, spawn=_spawner(spawn), terminate_grace=5.0)
    code = asyncio.create_task(_run_supervisor(sup, specs, install_signal_handlers=False))
    await asyncio.wait_for(hung.wait(), 5)
    sup.stop()
    assert await asyncio.wait_for(code, 5) == 0
    assert proc.terminated.is_set()
    assert not proc.killed


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_child_a_launch_returns_after_its_cancel_is_killed_and_waited() -> None:
    late = _Proc()
    hung = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        hung.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.sleep(0.02)  # a spawn that finishes its fork despite the cancel
        return late

    sup = Supervisor([_spec("default")], spawn=_spawner(spawn), terminate_grace=0.1)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(hung.wait(), 5)
    runner.cancel()
    # The kill ended it, so no child remains and this is not a drain failure.
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(runner, 5)
    assert late.killed
    assert late.waiting.is_set()
    assert late.returncode == -9
    assert not late.terminated.is_set()
    assert not sup._launches


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


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_some_engine_shards_tripped_and_a_failed_drain_exits_3() -> None:
    # Engine shard "a" trips the crash-loop breaker; "b" stays up and cannot be stopped. The drain
    # failure's 3 is what the caller gets, with the crash loop still logged.
    stuck = _Proc(terminate_error=PermissionError("refused"), kill_error=PermissionError("refused"))

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
            break
        await asyncio.sleep(0.01)
    assert sup.crash_looped == {"a"}
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


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_real_kill_failure_is_the_cause_ahead_of_a_stranded_launch() -> None:
    stuck = _Proc(terminate_error=PermissionError("refused"), kill_error=PermissionError("refused"))
    hung = asyncio.Event()
    release = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "b":
            hung.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    continue
        return stuck

    sup = Supervisor([_spec("a"), _spec("b", 1)], spawn=_spawner(spawn), terminate_grace=0.1)
    try:
        runner = asyncio.create_task(sup.run())
        await asyncio.wait_for(stuck.waiting.wait(), 5)
        await asyncio.wait_for(hung.wait(), 5)
        runner.cancel()
        with pytest.raises(ShardDrainError, match="2 engine shard") as caught:
            await asyncio.wait_for(runner, 5)
        assert isinstance(caught.value.__cause__, PermissionError)
    finally:
        release.set()
    await asyncio.wait_for(asyncio.gather(*sup._launches), 5)


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_launch_raising_a_fatal_exit_mid_drain_still_drains_every_child() -> None:
    # Finding 1: engine shard "b"'s launch raises a BaseException while the drain settles it.
    # The drain must still force "a", which ignores the stop request, record "b" as stranded,
    # and only then raise the fatal exit.
    class _Fatal(BaseException):
        pass

    a = _Proc()
    hung = asyncio.Event()
    go = asyncio.Event()

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "b":
            hung.set()
            await go.wait()
            raise _Fatal
        return a

    sup = Supervisor([_spec("a"), _spec("b", 1)], spawn=_spawner(spawn), terminate_grace=0.2)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(a.waiting.wait(), 5)
    await asyncio.wait_for(hung.wait(), 5)
    sup.stop()
    await asyncio.wait_for(a.terminated.wait(), 5)
    go.set()
    with pytest.raises(_Fatal):
        await asyncio.wait_for(runner, 5)
    assert a.killed
    assert a.returncode == -9
    assert sup.drain_failure is not None
    assert "raised" in str(sup.drain_failure)


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_drain_cut_short_by_a_cancel_of_its_own_task_exits_3() -> None:
    # Finding 2: asyncio.run's teardown cancels every task, the drain's own included. The child
    # that ignored its stop request is still running, so the exit is 3, not a clean 0.
    proc = _Proc()

    async def spawn(spec: ShardSpec) -> _Proc:
        return proc

    specs = [_spec("default")]
    sup = Supervisor(specs, spawn=_spawner(spawn), terminate_grace=5.0)
    code = asyncio.create_task(_run_supervisor(sup, specs, install_signal_handlers=False))
    await asyncio.wait_for(proc.waiting.wait(), 5)
    sup.stop()
    await asyncio.wait_for(proc.terminated.wait(), 5)
    drains = [t for t in asyncio.all_tasks() if t.get_coro().__qualname__ == "Supervisor._drain"]  # type: ignore[union-attr]
    assert len(drains) == 1
    drains[0].cancel()
    assert await asyncio.wait_for(code, 5) == 3
    assert proc.returncode is None


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_cancelled_runner_after_a_failed_drain_exits_3() -> None:
    # The outcome is read from the supervisor, so how run() ended does not decide the code.
    proc = _Proc(terminate_error=PermissionError("refused"), kill_error=PermissionError("refused"))

    async def spawn(spec: ShardSpec) -> _Proc:
        return proc

    specs = [_spec("default")]
    sup = Supervisor(specs, spawn=_spawner(spawn), terminate_grace=0.1)
    code = asyncio.create_task(_run_supervisor(sup, specs, install_signal_handlers=False))
    await asyncio.wait_for(proc.waiting.wait(), 5)
    for task in asyncio.all_tasks():
        if task.get_name() == "supervisor":
            task.cancel()
    assert await asyncio.wait_for(code, 5) == 3


def test_a_non_finite_terminate_grace_is_refused() -> None:
    with pytest.raises(ValueError, match="terminate_grace"):
        Supervisor([_spec("default")], terminate_grace=float("inf"))


@pytest.mark.timeout(30)
@pytest.mark.asyncio
async def test_a_fatal_watcher_exit_is_not_replaced_when_the_drain_task_is_cancelled() -> None:
    # The drain's own task is cancelled, as asyncio.run's teardown does, while it waits out the
    # grace on a child that ignored its stop request. The watcher's fatal exit still propagates,
    # not the drain's CancelledError.
    class _Fatal(BaseException):
        pass

    proc = _Proc()

    async def spawn(spec: ShardSpec) -> _Proc:
        if spec.shard == "b":
            await proc.waiting.wait()
            raise _Fatal
        return proc

    sup = Supervisor([_spec("a"), _spec("b", 1)], spawn=_spawner(spawn), terminate_grace=5.0)
    runner = asyncio.create_task(sup.run())
    await asyncio.wait_for(proc.terminated.wait(), 5)
    drains = [t for t in asyncio.all_tasks() if t.get_coro().__qualname__ == "Supervisor._drain"]  # type: ignore[union-attr]
    assert len(drains) == 1
    drains[0].cancel()
    with pytest.raises(_Fatal):
        await asyncio.wait_for(runner, 5)
    assert proc.returncode is None
