# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3191: the API lifespans' shutdown runs every step whatever the steps before it did.

Three findings from engine PR 2115. A cancel delivered mid-teardown skipped the drains after the one
it interrupted. engine.stop() and the security notifier's close sat unguarded, so a raise in one
skipped the rest. And the lifespan create_app(engine=...) installs drained only the approval gate.
The whole shutdown also has to fit NSSM's graceful-stop window.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api import app as app_module
from messagefoundry.api import create_app, create_managed_app
from messagefoundry.api.app import _run_teardown, _TeardownStep
from messagefoundry.config.settings import ApprovalsSettings, EgressSettings
from messagefoundry.pipeline import engine as engine_module
from messagefoundry.pipeline.engine import Engine

_WAIT_S = 10.0
_REPO = Path(__file__).resolve().parents[1]


async def _hang(_bound: float) -> None:
    await asyncio.Event().wait()


def _record(calls: list[str], name: str) -> Callable[[float], Awaitable[None]]:
    async def _step(_bound: float) -> None:
        calls.append(name)

    return _step


class _Fatal(BaseException):
    """A BaseException a task carries as its result, unlike KeyboardInterrupt, which asyncio
    re-raises out of the event loop itself."""


# --- _run_teardown, the step runner -------------------------------------------------------------


async def test_a_step_that_raises_does_not_skip_the_next() -> None:
    calls: list[str] = []

    async def _boom(_bound: float) -> None:
        calls.append("boom")
        raise RuntimeError("PROBE: deliberate step failure")

    await _run_teardown(
        [_TeardownStep("boom", 0.1, _boom), _TeardownStep("next", 0.1, _record(calls, "next"))],
        1.0,
    )
    assert calls == ["boom", "next"]


async def test_a_step_that_raises_while_it_is_built_does_not_skip_the_next() -> None:
    calls: list[str] = []

    def _raises_at_once(_bound: float) -> Awaitable[None]:
        raise AttributeError("PROBE: an attribute the step reads is gone")

    await _run_teardown(
        [
            _TeardownStep("raises at once", 0.1, _raises_at_once),
            _TeardownStep("stop", 0.1, _record(calls, "stop"), bounded=False),
        ],
        1.0,
    )
    assert calls == ["stop"]


async def test_a_base_exception_runs_the_later_steps_then_is_raised() -> None:
    calls: list[str] = []

    async def _fatal(_bound: float) -> None:
        raise _Fatal

    with pytest.raises(_Fatal):
        await _run_teardown(
            [
                _TeardownStep("fatal", 0.1, _fatal),
                _TeardownStep("stop", 0.1, _record(calls, "stop"), bounded=False),
            ],
            1.0,
        )
    assert calls == ["stop"]


async def test_a_cancel_reaches_no_step_and_propagates_after_the_last() -> None:
    """The step running when the cancel lands finishes its own work, the later steps run, and only
    then is the cancel raised."""
    calls: list[str] = []
    entered, release = asyncio.Event(), asyncio.Event()

    async def _first(_bound: float) -> None:
        entered.set()
        await release.wait()
        calls.append("first finished")

    task = asyncio.create_task(
        _run_teardown(
            [
                _TeardownStep("first", 0.1, _first),
                _TeardownStep("second", 0.1, _record(calls, "second")),
                _TeardownStep("third", 0.1, _record(calls, "third")),
            ],
            # Long enough that the bound cannot end the first step during the test.
            60.0,
        )
    )
    await asyncio.wait_for(entered.wait(), _WAIT_S)
    task.cancel()
    await asyncio.sleep(0.05)
    assert not task.done(), "the cancel cut the running step short"
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, _WAIT_S)
    assert calls == ["first finished", "second", "third"]


async def test_a_step_that_overruns_is_cut_and_every_later_step_keeps_its_floor() -> None:
    bounds: dict[str, float] = {}

    async def _hangs(bound: float) -> None:
        bounds["hangs"] = bound
        await asyncio.Event().wait()

    async def _later(bound: float) -> None:
        bounds["later"] = bound

    started = time.monotonic()
    await _run_teardown(
        [_TeardownStep("hangs", 0.02, _hangs), _TeardownStep("later", 0.1, _later)], 0.3
    )
    elapsed = time.monotonic() - started
    # The hanging step got the budget less the later floor, not the whole budget.
    assert bounds["hangs"] == pytest.approx(0.2, abs=0.05)
    assert bounds["later"] >= 0.1
    assert elapsed < 0.3 + app_module._CUT_GRACE_SECONDS + 0.25


async def test_a_step_that_ignores_its_cut_is_left_running(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The bound is hard: a step that swallows its cancel and goes on waiting is left behind after
    the cut grace, and the teardown moves on. How it later ends is still logged."""
    calls: list[str] = []
    release = asyncio.Event()

    async def _stubborn(_bound: float) -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await release.wait()
            raise RuntimeError("PROBE: failed after the teardown moved on") from None

    started = time.monotonic()
    with caplog.at_level(logging.ERROR, logger="messagefoundry.api.app"):
        await _run_teardown(
            [
                _TeardownStep("stubborn", 0.05, _stubborn),
                _TeardownStep("after", 0.05, _record(calls, "after")),
            ],
            0.2,
        )
        elapsed = time.monotonic() - started
        assert calls == ["after"]
        assert elapsed < 0.2 + app_module._CUT_GRACE_SECONDS + 0.25
        release.set()
        for _ in range(50):
            if any("after the teardown moved on" in r.getMessage() for r in caplog.records):
                break
            await asyncio.sleep(0.01)
    assert any("after the teardown moved on" in r.getMessage() for r in caplog.records)


async def test_an_unbounded_step_runs_to_completion_through_a_cancel() -> None:
    calls: list[str] = []
    entered, release = asyncio.Event(), asyncio.Event()

    async def _stop(_bound: float) -> None:
        entered.set()
        await release.wait()
        calls.append("stop finished")

    task = asyncio.create_task(
        _run_teardown(
            [
                _TeardownStep("stop", 0.1, _stop, bounded=False),
                _TeardownStep("after", 0.1, _record(calls, "after")),
            ],
            # Shorter than the stop takes: an unbounded step is never cut by the budget either.
            0.01,
        )
    )
    await asyncio.wait_for(entered.wait(), _WAIT_S)
    task.cancel()
    await asyncio.sleep(0.05)
    assert not task.done(), "the unbounded step was cut short"
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, _WAIT_S)
    assert calls == ["stop finished", "after"]


async def test_a_step_that_ends_cancelled_on_its_own_is_not_taken_for_a_cancel() -> None:
    """A CancelledError nobody asked for is a step failure: raising it at the end would cancel the
    caller's shutdown for no reason."""
    calls: list[str] = []

    async def _cancels_itself(_bound: float) -> None:
        inner = asyncio.ensure_future(asyncio.sleep(10))
        inner.cancel()
        await inner

    # Returns rather than raising: nobody cancelled the caller.
    await _run_teardown(
        [
            _TeardownStep("cancels itself", 0.1, _cancels_itself),
            _TeardownStep("after", 0.1, _record(calls, "after")),
        ],
        1.0,
    )
    assert calls == ["after"]


def test_the_shutdown_budget_fits_the_nssm_stop_window() -> None:
    """The install script's AppStopMethodConsole is the window. The budget, plus uvicorn's own drain
    bound where serve sets one (BACKLOG #3256), must leave room in it for the interpreter to exit."""
    script = (_REPO / "scripts" / "service" / "install-service.ps1").read_text(encoding="utf-8")
    match = re.search(r"AppStopMethodConsole\s+(\d+)", script)
    assert match is not None, "the install script no longer sets AppStopMethodConsole"
    window = int(match.group(1)) / 1000.0
    import messagefoundry.__main__ as cli

    shutdown = app_module._SHUTDOWN_BUDGET_SECONDS + cli._UVICORN_DRAIN_SECONDS
    assert shutdown + 1.0 <= window
    assert app_module._ENGINE_STOP_RESERVE_SECONDS < app_module._SHUTDOWN_BUDGET_SECONDS


# --- the managed lifespan -----------------------------------------------------------------------


def _managed(db_path: Path) -> Any:
    return create_managed_app(
        db_path=db_path, egress_settings=EgressSettings(deny_by_default=False)
    )


class _Spies:
    """Swap each teardown step the managed app runs for a recorder, keeping the real engine.stop()
    so the test can still stop the engine if the teardown never did."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.real_stop: Callable[[], Awaitable[None]] | None = None

    def attach(self, app: Any) -> None:
        calls = self.calls
        engine = app.state.engine
        real_stop = self.real_stop = engine.stop

        async def _outliving(timeout: float = 0.0, *, grace: float = 0.0) -> list[str]:
            calls.append("outliving")
            return []

        async def _approvals(timeout: float = 0.0) -> list[str]:
            calls.append("approvals")
            return []

        async def _flush(store: Any) -> None:
            calls.append("flush")

        async def _stop() -> None:
            calls.append("stop")
            await real_stop()

        class _Executor:
            def shutdown(self, wait: bool) -> None:
                calls.append("executor")

        app.state.outliving_operations.drain = _outliving
        app.state.approval_gate.drain = _approvals
        app.state.summary_auditor.flush = _flush
        app.state.connscale_executor = _Executor()
        engine.stop = _stop

    async def stop_if_needed(self) -> None:
        if self.real_stop is not None and "stop" not in self.calls:
            await self.real_stop()


async def test_a_cancel_during_the_first_drain_still_runs_every_later_step(tmp_path: Path) -> None:
    app = _managed(tmp_path / "cancel.db")
    spies = _Spies()
    entered, leave, draining, release = (asyncio.Event() for _ in range(4))

    async def _held(timeout: float = 0.0, *, grace: float = 0.0) -> list[str]:
        draining.set()
        await release.wait()
        spies.calls.append("outliving finished")
        return []

    async def _run() -> None:
        async with app.router.lifespan_context(app):
            spies.attach(app)
            app.state.outliving_operations.drain = _held
            entered.set()
            await leave.wait()

    task = asyncio.create_task(_run())
    try:
        await asyncio.wait_for(entered.wait(), _WAIT_S)
        leave.set()
        await asyncio.wait_for(draining.wait(), _WAIT_S)
        task.cancel()
        await asyncio.sleep(0.05)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, _WAIT_S)
    finally:
        await spies.stop_if_needed()
    assert spies.calls == ["outliving finished", "approvals", "flush", "stop", "executor"]


async def test_an_engine_stop_that_raises_does_not_skip_the_steps_after_it(
    tmp_path: Path,
) -> None:
    app = _managed(tmp_path / "stop-raises.db")
    spies = _Spies()
    try:
        async with app.router.lifespan_context(app):
            spies.attach(app)
            real_stop = spies.real_stop
            assert real_stop is not None

            async def _stop_raises() -> None:
                spies.calls.append("stop")
                await real_stop()
                raise RuntimeError("PROBE: deliberate engine.stop() failure")

            app.state.engine.stop = _stop_raises
    finally:
        await spies.stop_if_needed()
    assert spies.calls == ["outliving", "approvals", "flush", "stop", "executor"]


async def test_the_retention_runner_s_stop_waits_less_than_its_step_s_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runner's own stop wait is longer than its teardown step's bound. The lifespan hands it a
    share of that bound, so its wait ends, and it cancels its own sweep, before the step is cut."""
    pytest.importorskip("psutil")
    from messagefoundry import uploads as uploads_module
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.uploads import UploadRetentionRunner

    bounds: list[float] = []
    timeouts: list[float | None] = []
    real_invoke, real_stop = app_module._invoke, UploadRetentionRunner.stop

    async def _invoke(run: Callable[[float], Awaitable[object]], bound: float) -> object:
        bounds.append(bound)
        return await real_invoke(run, bound)

    async def _stop(self: UploadRetentionRunner, timeout: float | None = None) -> None:
        timeouts.append(timeout)
        await real_stop(self, timeout)

    monkeypatch.setattr(app_module, "_invoke", _invoke)
    monkeypatch.setattr(UploadRetentionRunner, "stop", _stop)
    settings = StoreSettings(path=str(tmp_path / "runner.db"), uploads_dir=str(tmp_path / "up"))
    app = create_managed_app(
        store_settings=settings, egress_settings=EgressSettings(deny_by_default=False)
    )
    async with app.router.lifespan_context(app):
        assert app.state.upload_store is not None
    # The runner's stop is the first step.
    [timeout] = timeouts
    assert timeout is not None
    assert timeout == pytest.approx(bounds[0] * app_module._INNER_SHARE)
    assert timeout < bounds[0]
    # The premise: even with fewer steps than serve runs, the share is the shorter of the two waits.
    assert timeout < uploads_module._DEFAULT_STOP_TIMEOUT_SECONDS


async def test_the_managed_teardown_drains_config_writes_under_its_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #2945 under BACKLOG #3191: the config-write drain is a budgeted step before
    engine.stop(), handed a share of its bound, and engine.stop() then does not run its own fixed
    wait as well, which would spend time past the budget."""
    labels: list[str] = []
    bounds: list[float] = []
    real_run, real_invoke = app_module._run_teardown, app_module._invoke

    async def _run(steps: list[_TeardownStep], budget: float) -> None:
        labels.extend(step.label for step in steps)
        await real_run(steps, budget)

    async def _invoke(run: Callable[[float], Awaitable[object]], bound: float) -> object:
        bounds.append(bound)
        return await real_invoke(run, bound)

    monkeypatch.setattr(app_module, "_run_teardown", _run)
    monkeypatch.setattr(app_module, "_invoke", _invoke)
    app = _managed(tmp_path / "config-drain.db")
    calls: list[tuple[str, float | None]] = []
    async with app.router.lifespan_context(app):
        engine: Engine = app.state.engine
        real_drain, real_stop = engine.drain_config_writes, engine.stop

        async def _drain(timeout: float) -> None:
            calls.append(("drain", timeout))
            await real_drain(timeout)

        async def _stop() -> None:
            calls.append(("stop", None))
            await real_stop()

        async def _in_flight_write() -> dict[str, object] | None:
            # Stands in for a write whose caller went: it lands after the teardown began.
            await asyncio.sleep(0.3)
            calls.append(("write landed", None))
            return None

        write = asyncio.ensure_future(_in_flight_write())
        engine._config_writes.add(write)
        write.add_done_callback(engine._config_writes.discard)
        monkeypatch.setattr(engine, "drain_config_writes", _drain)
        monkeypatch.setattr(engine, "stop", _stop)
    step = labels.index("the config-write drain")
    assert step < labels.index("engine.stop()")
    # The drain waited for the write before engine.stop() ran, and engine.stop() read the closed
    # gate and drained again with only the late wait, not its own fixed one.
    assert [name for name, _ in calls] == ["drain", "write landed", "stop", "drain"], calls
    assert calls[0][1] == pytest.approx(bounds[step] * app_module._INNER_SHARE)
    assert calls[3][1] == engine_module._CONFIG_WRITE_LATE_DRAIN_SECONDS
    assert engine_module._CONFIG_WRITE_LATE_DRAIN_SECONDS < app_module._ENGINE_STOP_RESERVE_SECONDS
    assert engine._config_writes_closed


async def test_the_teardown_is_bounded_when_every_drain_hangs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every drain before engine.stop() hangs, and the whole teardown still ends within the budget,
    the cut graces and what the real engine.stop() takes. The budget just covers the floors of the
    steps that apply here, as the shipped one covers the managed set's."""
    budget = 3.75
    monkeypatch.setattr(app_module, "_SHUTDOWN_BUDGET_SECONDS", budget)
    monkeypatch.setattr(app_module, "_ENGINE_STOP_RESERVE_SECONDS", 0.2)
    app = _managed(tmp_path / "bounded.db")
    spies = _Spies()
    stop_took: list[float] = []
    try:
        async with app.router.lifespan_context(app):
            spies.attach(app)
            real_stop = spies.real_stop
            assert real_stop is not None

            async def _hangs(*_a: Any, **_k: Any) -> list[str]:
                await asyncio.Event().wait()
                return []

            async def _timed_stop() -> None:
                spies.calls.append("stop")
                began = time.monotonic()
                await real_stop()
                stop_took.append(time.monotonic() - began)

            engine: Engine = app.state.engine

            async def _config_drain_hangs(_timeout: float) -> None:
                # The lifespan's drain hangs. engine.stop()'s late drain, called once the gate is
                # closed, returns at once, as the real one does with no write running.
                if engine._config_writes_closed:
                    return
                engine._config_writes_closed = True
                await asyncio.Event().wait()

            app.state.outliving_operations.drain = _hangs
            app.state.approval_gate.drain = _hangs
            app.state.summary_auditor.flush = _hangs
            monkeypatch.setattr(engine, "drain_config_writes", _config_drain_hangs)
            app.state.engine.stop = _timed_stop
            started = time.monotonic()
        elapsed = time.monotonic() - started
    finally:
        await spies.stop_if_needed()
    assert spies.calls == ["stop", "executor"]
    graces = 4 * app_module._CUT_GRACE_SECONDS
    assert elapsed < budget + graces + stop_took[0] + 0.5, f"teardown took {elapsed:.2f}s"


# --- the embedded lifespan (create_app(engine=...)) ---------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "embedded.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


_ON = ApprovalsSettings(enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=0.0)


async def test_the_embedded_app_runs_the_same_drains_at_shutdown(engine: Engine) -> None:
    app = create_app(engine, approvals=_ON)
    calls: list[str] = []

    async def _outliving(timeout: float = 0.0, *, grace: float = 0.0) -> list[str]:
        calls.append("outliving")
        return []

    async def _approvals(timeout: float = 0.0) -> list[str]:
        calls.append("approvals")
        return []

    class _Auth:
        """Joined, never closed: the caller owns the service."""

        async def drain_background(self) -> None:
            calls.append("lock notices")

    async with app.router.lifespan_context(app):
        app.state.outliving_operations.drain = _outliving
        app.state.approval_gate.drain = _approvals
        app.state.auth = _Auth()
    assert calls == ["outliving", "approvals", "lock notices"]


async def test_the_embedded_app_flushes_the_open_summary_window_before_its_engine_stops(
    engine: Engine,
) -> None:
    """The row lands before the app's shutdown returns, so before the caller stops its engine."""
    app = create_app(engine, approvals=_ON)
    async with app.router.lifespan_context(app):
        await app.state.summary_auditor.note(engine.store, "checker", None, 3, time.time())
        assert await engine.store.list_audit(action="summary_access") == []
    rows = await engine.store.list_audit(action="summary_access")
    assert len(rows) == 1
