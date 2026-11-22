# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3191 item 3: engine.stop() holds the waits it budgets inside the time it is handed.

The managed API lifespan hands engine.stop() the bound its step gets. Under it the graph
supervisor's exit, the CRL reload runner's stop, the remote-debug refusal watch's stop and the
alert-state drain are each shortened only as far as the stop's remaining time needs. With no budget
each keeps its fixed bound, as before."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.api import app as app_module
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import engine as engine_module
from messagefoundry.pipeline import remote_debug_watch
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
        self.timeouts: list[float | None] = []

    @staticmethod
    def stop_seconds() -> float:
        return 5.0

    async def stop(self, *, timeout: float | None = None) -> None:
        self.timeouts.append(timeout)


async def _hangs() -> None:
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
    took the stop past NSSM's window."""
    eng = await _engine(tmp_path)
    supervisor = asyncio.ensure_future(_hangs())
    eng._graph_supervisor = supervisor
    began = time.monotonic()
    await _stop(eng, budget_seconds=2.5)
    took = time.monotonic() - began
    assert supervisor.cancelled()
    assert took < 2.5, took


async def test_under_a_budget_the_budgeted_waits_are_shortened_to_fit(tmp_path: Path) -> None:
    eng = await _engine(tmp_path)
    drain, crl, watch = _attach(eng)
    await _stop(eng, budget_seconds=2.0)
    [crl_wait] = crl.timeouts
    [watch_wait] = watch.timeouts
    [drain_wait] = drain.timeouts
    assert crl_wait is not None and watch_wait is not None
    assert crl_wait < crl.stop_timeout_seconds
    assert watch_wait < watch.stop_seconds()
    assert drain_wait < engine_module._ALERT_STATE_DRAIN_SECONDS
    # Each is bounded by what is left of the budget once the steps after it are kept their time.
    # The stand-ins return at once, so each sees close to the whole budget left.
    close = engine_module._STOP_CLOSE_ALLOWANCE_SECONDS
    late = engine_module._CONFIG_WRITE_LATE_DRAIN_SECONDS
    floor = engine_module._STOP_WAIT_FLOOR_SECONDS
    watch_kept = close + floor + late
    assert crl_wait <= 2.0 - (watch_kept + floor)
    assert 2 * watch_wait <= 2.0 - watch_kept
    assert drain_wait <= 2.0 - close


async def test_a_budget_with_room_leaves_every_fixed_bound_as_it_was(tmp_path: Path) -> None:
    eng = await _engine(tmp_path)
    drain, crl, watch = _attach(eng)
    await _stop(eng, budget_seconds=60.0)
    assert crl.timeouts == [crl.stop_timeout_seconds]
    assert watch.timeouts == [watch.stop_seconds()]
    assert drain.timeouts == [engine_module._ALERT_STATE_DRAIN_SECONDS]


async def test_with_no_budget_every_wait_keeps_its_fixed_bound(tmp_path: Path) -> None:
    eng = await _engine(tmp_path)
    drain, crl, watch = _attach(eng)
    await eng.stop()
    assert crl.timeouts == [crl.stop_timeout_seconds]
    assert watch.timeouts == [watch.stop_seconds()]
    assert drain.timeouts == [engine_module._ALERT_STATE_DRAIN_SECONDS]


def test_the_time_kept_after_the_supervisor_fits_the_engine_reserve() -> None:
    """The supervisor's wait is the first budgeted one, so what it keeps back for the rest is the
    most any wait keeps. It must leave the supervisor more than its floor inside the reserve."""
    kept = (
        engine_module._STOP_CLOSE_ALLOWANCE_SECONDS
        + engine_module._CONFIG_WRITE_LATE_DRAIN_SECONDS
        + 3 * engine_module._STOP_WAIT_FLOOR_SECONDS
    )
    assert kept + engine_module._STOP_WAIT_FLOOR_SECONDS < app_module._ENGINE_STOP_RESERVE_SECONDS


async def test_the_managed_lifespan_hands_engine_stop_its_bound() -> None:
    """On main the step called engine.stop() with nothing, so no wait inside it knew the window."""
    seen: list[float | None] = []

    async def _stop(*, budget_seconds: float | None = None) -> None:
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
        SimpleNamespace(stop=_stop),  # type: ignore[arg-type]
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


async def test_the_remote_debug_watch_bounds_both_waits_by_the_timeout_it_is_handed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A last pass that hangs is cut at the handed bound, not at the module's fixed one."""
    monkeypatch.setattr(remote_debug_watch, "_STOP_SECONDS", 30.0)
    store: Any = object()
    watch = remote_debug_watch.RemoteDebugRefusalWatch(store, read=lambda: 0)
    watch._task = asyncio.ensure_future(_hangs())
    began = time.monotonic()
    await watch.stop(timeout=0.2)
    assert time.monotonic() - began < 2.0
