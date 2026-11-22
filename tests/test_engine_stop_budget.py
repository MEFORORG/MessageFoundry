# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3191 item 3: engine.stop() holds the waits it budgets inside the time it is handed.

The managed API lifespan hands engine.stop() the bound its step gets. ``pipeline.engine._StopBudget``
names the waits that bound shortens. With no budget each keeps its fixed bound, as before."""

from __future__ import annotations

import asyncio
import contextlib
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
        self.deadlines: list[float | None] = []

    async def stop(self, *, deadline: float | None = None) -> None:
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


async def test_a_hung_graph_supervisor_is_cut_inside_the_stop_budget(tmp_path: Path) -> None:
    """On main the supervisor got a fixed 10 s whatever the stop had left, so a hung reconcile alone
    took the stop past NSSM's window. The bound here leaves slack for the steps the budget does not
    hold, which is still far short of 10 s."""
    eng = await _engine(tmp_path)
    supervisor = asyncio.ensure_future(_hangs())
    eng._graph_supervisor = supervisor
    began = time.monotonic()
    await _stop(eng, budget_seconds=2.5)
    took = time.monotonic() - began
    assert supervisor.cancelled()
    assert took < 6.0, took


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
    # The gate is open, so the full config-write drain is kept back for.
    watch_kept = close + floor + engine_module._CONFIG_WRITE_DRAIN_SECONDS
    # Past what is kept, the CRL wait is at its floor: the budget is all spoken for.
    assert crl_wait == pytest.approx(floor)
    assert watch_deadline == pytest.approx(began + 2.0 - watch_kept, abs=0.05)
    # The stand-ins return at once, so the drain sees nearly the whole budget left.
    assert 2.0 - close - 0.2 <= drain_wait <= 2.0 - close


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
        + engine_module._STOP_WAIT_FLOOR_SECONDS
        + 2 * remote_debug_watch.STOP_FLOOR_SECONDS
    )
    assert crl_wait is not None
    assert 2.0 - kept - 0.2 <= crl_wait <= 2.0 - kept


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


def test_the_time_kept_after_the_supervisor_fits_the_engine_reserve() -> None:
    """The supervisor's wait is the first budgeted one, so what it keeps back is the most any wait
    keeps. With the managed lifespan's closed gate and a write still running, the late drain's
    fixed bound is kept; the supervisor must still get more than its floor inside the reserve."""
    kept = (
        engine_module._STOP_CLOSE_ALLOWANCE_SECONDS
        + engine_module._CONFIG_WRITE_LATE_DRAIN_SECONDS
        + 2 * engine_module._STOP_WAIT_FLOOR_SECONDS
        + 2 * remote_debug_watch.STOP_FLOOR_SECONDS
    )
    assert kept + engine_module._STOP_WAIT_FLOOR_SECONDS < app_module._ENGINE_STOP_RESERVE_SECONDS


async def test_the_managed_lifespan_hands_engine_stop_its_bound() -> None:
    """On main the step called engine.stop() with nothing, so no wait inside it knew the window."""
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
        await watch.stop(deadline=began + 0.4)
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
