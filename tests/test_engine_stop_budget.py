# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3191 item 3: engine.stop() holds the waits it budgets inside the time it is handed.

The managed API lifespan hands engine.stop() the bound its step gets. ``pipeline.engine._StopBudget``
names the waits that bound shortens. With no budget each keeps its fixed bound, as before."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.api import app as app_module
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import engine as engine_module
from messagefoundry.pipeline import remote_debug_watch
from messagefoundry.pipeline.crl_reload import CrlReloadRunner
from messagefoundry.pipeline.engine import Engine


class _DrainRecorder:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    async def drain_state(self, timeout: float) -> None:
        self.timeouts.append(timeout)


class _CrlRecorder:
    stop_timeout_seconds = 10.0

    def __init__(self) -> None:
        self.timeouts: list[float | None] = []

    async def stop(self, *, timeout: float | None = None) -> None:
        self.timeouts.append(timeout)


class _WatchRecorder:
    def __init__(self) -> None:
        self.deadlines: list[remote_debug_watch.StopDeadline | None] = []

    async def stop(self, *, deadline: remote_debug_watch.StopDeadline | None = None) -> None:
        self.deadlines.append(deadline)


async def _hangs() -> None:
    await asyncio.Event().wait()


async def _ignores_one_cancel() -> None:
    """A pass whose driver call takes as long to unwind a cancel as it took to hang."""
    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.Event().wait()
    await asyncio.Event().wait()


async def _engine(tmp_path: Path) -> Engine:
    return await Engine.create(
        tmp_path / "stop.db", egress_settings=EgressSettings(deny_by_default=False)
    )


async def _stop(eng: Engine, **kwargs: Any) -> None:
    """engine.stop(), closing the store if the stop raised, so a failing test cannot leave the
    store's non-daemon worker holding the test process open."""
    try:
        await eng.stop(**kwargs)
    except BaseException:
        await eng.store.close()
        raise


def _attach(eng: Engine) -> tuple[_DrainRecorder, _CrlRecorder, _WatchRecorder]:
    drain, crl, watch = _DrainRecorder(), _CrlRecorder(), _WatchRecorder()
    eng._alert_sink = drain  # type: ignore[assignment]
    eng._crl_reload_runner = crl  # type: ignore[assignment]
    eng._remote_debug_watch = watch  # type: ignore[assignment]
    return drain, crl, watch


async def test_a_hung_graph_supervisor_keeps_its_fixed_wait_under_a_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stop budget does not shorten the supervisor's wait: a hung reconcile gets its fixed
    bound, as on main, however little budget the stop is handed. The bound is lowered here only to
    keep the test short."""
    monkeypatch.setattr(engine_module, "_GRAPH_SUPERVISOR_STOP_SECONDS", 1.0)
    eng = await _engine(tmp_path)
    await eng.drain_config_writes(0.0)
    supervisor = asyncio.ensure_future(_hangs())
    eng._graph_supervisor = supervisor
    began = time.monotonic()
    await _stop(eng, budget_seconds=0.1)
    took = time.monotonic() - began
    assert supervisor.cancelled()
    assert took >= 0.95, took


def test_the_supervisor_wait_is_mains_fixed_ten_seconds() -> None:
    assert engine_module._GRAPH_SUPERVISOR_STOP_SECONDS == 10.0


async def test_under_a_budget_the_budgeted_waits_are_shortened_to_fit(tmp_path: Path) -> None:
    eng = await _engine(tmp_path)
    drain, crl, watch = _attach(eng)
    loop = asyncio.get_running_loop()
    began = loop.time()
    await _stop(eng, budget_seconds=2.0)
    [crl_wait] = crl.timeouts
    [watch_deadline] = watch.deadlines
    [drain_wait] = drain.timeouts
    assert crl_wait is not None and watch_deadline is not None
    close = engine_module._STOP_CLOSE_ALLOWANCE_SECONDS
    floor = engine_module._STOP_WAIT_FLOOR_SECONDS
    share = engine_module._STOP_WAIT_SHARE_SECONDS
    # The gate is open, so the full config-write drain is kept back for.
    watch_kept = close + share + engine_module._CONFIG_WRITE_DRAIN_SECONDS
    # Past what is kept, the CRL wait is at its floor: the budget is all spoken for.
    assert crl_wait == pytest.approx(floor)
    assert watch_deadline.loop_time == pytest.approx(began + 2.0 - watch_kept, abs=0.05)
    # The stand-ins return at once, so the drain sees nearly the whole budget left.
    assert 2.0 - close - 0.5 <= drain_wait <= 2.0 - close


async def test_a_closed_idle_config_gate_keeps_nothing_back_for_its_drain(tmp_path: Path) -> None:
    """The managed lifespan closes the gate before engine.stop(); with no write running, the late
    drain returns at once, so the waits before it get that time."""
    eng = await _engine(tmp_path)
    _drain, crl, _watch = _attach(eng)
    await eng.drain_config_writes(0.0)
    await _stop(eng, budget_seconds=2.0)
    [crl_wait] = crl.timeouts
    kept = (
        engine_module._STOP_CLOSE_ALLOWANCE_SECONDS
        + 2 * engine_module._STOP_WAIT_SHARE_SECONDS
        + remote_debug_watch.STOP_FLOOR_SECONDS
    )
    assert crl_wait is not None
    assert 2.0 - kept - 0.5 <= crl_wait <= 2.0 - kept


async def test_a_budget_with_room_leaves_every_fixed_bound_as_it_was(tmp_path: Path) -> None:
    eng = await _engine(tmp_path)
    drain, crl, watch = _attach(eng)
    await _stop(eng, budget_seconds=60.0)
    assert crl.timeouts == [crl.stop_timeout_seconds]
    assert drain.timeouts == [engine_module._ALERT_STATE_DRAIN_SECONDS]
    [deadline] = watch.deadlines
    assert deadline is not None


async def test_with_no_budget_every_wait_keeps_its_fixed_bound(tmp_path: Path) -> None:
    eng = await _engine(tmp_path)
    drain, crl, watch = _attach(eng)
    await _stop(eng)
    assert crl.timeouts == [crl.stop_timeout_seconds]
    assert watch.deadlines == [None]
    assert drain.timeouts == [engine_module._ALERT_STATE_DRAIN_SECONDS]


def test_the_budget_never_lengthens_a_wait_past_its_fixed_bound() -> None:
    async def _check() -> None:
        budget = engine_module._StopBudget(0.0)
        assert budget.wait(0.05, kept=1.0) == 0.05
        assert budget.wait(5.0, kept=1.0) == engine_module._STOP_WAIT_FLOOR_SECONDS

    asyncio.run(_check())


def test_the_time_kept_after_the_crl_wait_fits_the_engine_reserve() -> None:
    """The CRL runner's wait comes second, after the retention runner's (see the retention test
    below), so it keeps back the most of the waits after it. With the managed lifespan's closed gate
    and a write still running, the late drain's fixed bound is kept; the CRL wait must still get
    more than its floor inside the reserve."""
    kept = (
        engine_module._STOP_CLOSE_ALLOWANCE_SECONDS
        + engine_module._CONFIG_WRITE_LATE_DRAIN_SECONDS
        + 2 * engine_module._STOP_WAIT_SHARE_SECONDS
        + remote_debug_watch.STOP_FLOOR_SECONDS
    )
    assert kept + engine_module._STOP_WAIT_FLOOR_SECONDS < app_module._ENGINE_STOP_RESERVE_SECONDS


class _RetentionRecorder:
    stop_timeout_seconds = 5.0

    def __init__(self) -> None:
        self.timeouts: list[float | None] = []

    async def stop(self, *, timeout: float | None = None) -> None:
        self.timeouts.append(timeout)


async def test_the_retention_stop_is_held_inside_the_budget(tmp_path: Path) -> None:
    """BACKLOG #6526: the retention runner's stop is the first budgeted wait, so it keeps back
    the CRL wait's share and everything that wait keeps."""
    eng = await _engine(tmp_path)
    _attach(eng)
    retention = _RetentionRecorder()
    eng._retention_runner = retention  # type: ignore[assignment]
    await eng.drain_config_writes(0.0)
    await _stop(eng, budget_seconds=3.0)
    [wait] = retention.timeouts
    kept = (
        engine_module._STOP_CLOSE_ALLOWANCE_SECONDS
        + 3 * engine_module._STOP_WAIT_SHARE_SECONDS
        + remote_debug_watch.STOP_FLOOR_SECONDS
    )
    assert wait is not None
    # 3 s, so the lower bound is above zero and the assertion can fail on a wait cut to the floor.
    assert 0.0 < 3.0 - kept - 0.5 <= wait <= 3.0 - kept


async def test_with_no_budget_the_retention_stop_keeps_its_fixed_bound(tmp_path: Path) -> None:
    eng = await _engine(tmp_path)
    _attach(eng)
    retention = _RetentionRecorder()
    eng._retention_runner = retention  # type: ignore[assignment]
    await _stop(eng)
    assert retention.timeouts == [retention.stop_timeout_seconds]


def test_the_time_kept_after_the_retention_wait_fits_the_engine_reserve() -> None:
    """The retention wait now comes first, so it keeps back the most: the CRL wait's share on
    top of what the CRL wait keeps. It must still get more than its floor inside the reserve."""
    kept = (
        engine_module._STOP_CLOSE_ALLOWANCE_SECONDS
        + engine_module._CONFIG_WRITE_LATE_DRAIN_SECONDS
        + 3 * engine_module._STOP_WAIT_SHARE_SECONDS
        + remote_debug_watch.STOP_FLOOR_SECONDS
    )
    assert kept + engine_module._STOP_WAIT_FLOOR_SECONDS < app_module._ENGINE_STOP_RESERVE_SECONDS


async def test_the_managed_lifespan_hands_engine_stop_its_bound() -> None:
    """Before BACKLOG #3191 the step called engine.stop() with nothing, so no wait inside it
    knew the window."""
    seen: list[float | None] = []

    async def _fake_stop(*, budget_seconds: float | None = None) -> None:
        seen.append(budget_seconds)

    state = SimpleNamespace(
        outliving_operations=object(),
        upload_store=object(),
        approval_gate=object(),
        connscale_executor=None,
    )
    part: Any = object()
    steps = app_module._managed_teardown_steps(
        SimpleNamespace(state=state),  # type: ignore[arg-type]
        SimpleNamespace(stop=_fake_stop),  # type: ignore[arg-type]
        part,
        part,
        background=[],
        upload_retention_runner=part,
        security_notifier=part,
        remove_security_signals=lambda: None,
        notifier=part,
    )
    [step] = [s for s in steps if s.label == "engine.stop()"]
    await step.run(3.25)
    assert seen == [3.25]


async def test_the_remote_debug_watch_ends_both_waits_by_its_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A last pass that hangs, and then hangs again unwinding its cancel, is let go by the deadline,
    not after twice the module's fixed bound."""
    monkeypatch.setattr(remote_debug_watch, "_STOP_SECONDS", 30.0)
    store: Any = object()
    watch = remote_debug_watch.RemoteDebugRefusalWatch(store, read=lambda: 0)
    task = asyncio.ensure_future(_ignores_one_cancel())
    watch._task = task
    loop = asyncio.get_running_loop()
    began = loop.time()
    try:
        await watch.stop(deadline=remote_debug_watch.StopDeadline(began + 0.4))
        assert loop.time() - began < 2.0
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_the_crl_runner_abandons_a_hung_pass_at_the_timeout_it_is_handed() -> None:
    runner = CrlReloadRunner(stop_timeout_seconds=30.0)
    runner._task = asyncio.ensure_future(_hangs())
    began = time.monotonic()
    await runner.stop(timeout=0.2)
    assert time.monotonic() - began < 2.0


async def _unwinds_slowly(release: asyncio.Event) -> None:
    """A pass whose cancel lands only once ``release`` is set."""
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        await release.wait()
        raise


async def test_a_cancel_during_the_crl_runner_first_wait_propagates_as_on_main(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The budget changes only the CRL runner's timeout, not its cancel handling, which stays
    main's: a cancel of the caller during the wait for the pass cancels the pass and is raised,
    and the stop-time resolve does not run (measured on main 72ac872c9cd)."""
    runner = CrlReloadRunner(stop_timeout_seconds=30.0)
    resolved: list[bool] = []
    monkeypatch.setattr(runner, "_resolve", lambda _keys, _why: resolved.append(True))
    pass_task = asyncio.ensure_future(_hangs())
    runner._task = pass_task
    stopping = asyncio.ensure_future(runner.stop(timeout=30.0))
    try:
        await asyncio.sleep(0.1)
        assert not stopping.done()
        stopping.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stopping
        await asyncio.sleep(0)
        assert pass_task.cancelled()
        assert resolved == []
    finally:
        pass_task.cancel()
        await asyncio.gather(pass_task, return_exceptions=True)


async def test_a_cancel_of_engine_stop_during_the_crl_first_wait_leaves_as_on_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """As on main, the CRL stop comes before engine.stop()'s guarded teardown, so a cancel there
    leaves engine.stop() at once and the store is not closed (measured on main 72ac872c9cd). This
    pins main's behaviour, which this PR keeps; it is not a property to preserve."""
    eng = await _engine(tmp_path)
    runner = CrlReloadRunner(stop_timeout_seconds=30.0)
    pass_task = asyncio.ensure_future(_hangs())
    runner._task = pass_task
    eng._crl_reload_runner = runner
    closed: list[bool] = []
    real_close = eng.store.close

    async def _close() -> None:
        closed.append(True)
        await real_close()

    monkeypatch.setattr(eng.store, "close", _close)
    stopping = asyncio.ensure_future(eng.stop(budget_seconds=60.0))
    try:
        await asyncio.sleep(0.1)
        assert not stopping.done()
        stopping.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stopping
        await asyncio.sleep(0)
        assert pass_task.cancelled()
        assert closed == []
    finally:
        pass_task.cancel()
        await asyncio.gather(pass_task, return_exceptions=True)
        if not closed:
            await real_close()


async def test_the_crl_runner_stop_does_not_raise_its_own_cancel_of_the_pass() -> None:
    """The control: the stop's own cancel of a pass that outran the timeout is not raised, however
    long the cancel takes to land."""
    release = asyncio.Event()
    asyncio.get_running_loop().call_later(0.2, release.set)
    runner = CrlReloadRunner(stop_timeout_seconds=30.0)
    pass_task = asyncio.ensure_future(_unwinds_slowly(release))
    runner._task = pass_task
    await asyncio.wait_for(runner.stop(timeout=0.05), 5.0)
    assert pass_task.cancelled()


async def test_the_watch_warning_says_a_pass_that_outlived_its_cancel_may_still_run(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A pass still running after the cancel's wait can outlive the store's close, so the
    WARNING must not say it was cancelled."""
    store: Any = object()
    watch = remote_debug_watch.RemoteDebugRefusalWatch(store, read=lambda: 0)
    task = asyncio.ensure_future(_ignores_one_cancel())
    watch._task = task
    deadline = remote_debug_watch.StopDeadline(asyncio.get_running_loop().time() + 0.3)
    try:
        with caplog.at_level(logging.WARNING, logger=remote_debug_watch.__name__):
            await watch.stop(deadline=deadline)
        assert not task.done()
        [record] = [r for r in caplog.records if "remote-debug refusal watch" in r.getMessage()]
        message = record.getMessage()
        assert "may still be running when the store closes" in message
        assert "was cancelled" not in message
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_the_watch_warning_says_a_pass_whose_cancel_landed_was_cancelled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store: Any = object()
    watch = remote_debug_watch.RemoteDebugRefusalWatch(store, read=lambda: 0)
    task = asyncio.ensure_future(_hangs())
    watch._task = task
    deadline = remote_debug_watch.StopDeadline(asyncio.get_running_loop().time() + 0.3)
    try:
        with caplog.at_level(logging.WARNING, logger=remote_debug_watch.__name__):
            await watch.stop(deadline=deadline)
        assert task.cancelled()
        [record] = [r for r in caplog.records if "remote-debug refusal watch" in r.getMessage()]
        assert "was cancelled" in record.getMessage()
        assert "may still be running" not in record.getMessage()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def test_the_watch_deadline_and_the_crl_timeout_are_typed_apart() -> None:
    """The watch takes an event-loop time and the CRL runner a relative timeout. A relative timeout
    passed as the deadline would silently give each wait the floor, so the deadline is its own
    type. The tests' mypy leg runs with warn_unused_ignores, so each ignore below fails that leg if
    the swapped call it sits on ever type-checks."""

    async def _swapped(
        watch: remote_debug_watch.RemoteDebugRefusalWatch, runner: CrlReloadRunner
    ) -> None:
        await watch.stop(deadline=1.5)  # type: ignore[arg-type]
        await runner.stop(timeout=remote_debug_watch.StopDeadline(1.5))  # type: ignore[arg-type]

    assert not isinstance(remote_debug_watch.StopDeadline(1.5), float)
    assert callable(_swapped)
