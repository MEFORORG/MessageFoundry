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
import math
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.api import app as app_module
from messagefoundry.api import create_app, create_managed_app
from messagefoundry.config.settings import ApprovalsSettings, EgressSettings
from messagefoundry.pipeline import engine as engine_module
from messagefoundry.pipeline import teardown as shutdown_steps
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.teardown import TeardownStep as _TeardownStep
from messagefoundry.pipeline.teardown import run_teardown as _run_teardown

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
    assert elapsed < 0.3 + shutdown_steps.CUT_GRACE_SECONDS + 0.25


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
    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.teardown"):
        await _run_teardown(
            [
                _TeardownStep("stubborn", 0.05, _stubborn),
                _TeardownStep("after", 0.05, _record(calls, "after")),
            ],
            0.2,
        )
        elapsed = time.monotonic() - started
        assert calls == ["after"]
        assert elapsed < 0.2 + shutdown_steps.CUT_GRACE_SECONDS + 0.25
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


#: The managed lifespan's shutdown steps, every optional one present, in the order they run.
_MANAGED_ORDER = [
    "the upload retention runner's stop",
    "the store-reading tasks",
    "the long-operations drain",
    "the upload straggler drain",
    "the approval request- and outcome-write drain",
    "the lock-notice drain",
    "the summary-access flush (a cut loses the unwritten windows' audit rows)",
    "the config-write drain",
    "the security notifier's close",
    "the security-signal removal",
    "engine.stop()",
    "the instrumented executor's shutdown",
    "the alert notifier's close",
]


def _every_managed_step(*, harness: bool) -> list[_TeardownStep]:
    """The real managed step list with every optional part present. The parts are stand-ins,
    because building the list calls none of them; ``harness`` adds the harness-only executor."""
    state = SimpleNamespace(
        outliving_operations=object(),
        upload_store=object(),
        approval_gate=object(),
        connscale_executor=SimpleNamespace(shutdown=lambda wait: None) if harness else None,
    )
    app: Any = SimpleNamespace(state=state)
    part: Any = object()
    return app_module._managed_teardown_steps(
        app,
        part,
        part,
        part,
        background=[],
        upload_retention_runner=part,
        security_notifier=part,
        remove_security_signals=lambda: None,
        notifier=part,
    )


def test_the_shutdown_budget_fits_the_nssm_stop_window() -> None:
    """The install script's AppStopMethodConsole is the window. Every wait the stop can make is
    summed at its worst, from the real step lists, so a new step is counted without anyone
    remembering to; the harness-only executor is not counted.

    uvicorn drains for at most its own bound where serve sets one (BACKLOG #3256). The lifespan's
    steps take at most the larger of its budget and their floors, plus a cut grace for every bounded
    step, since each can be cut (vault BACKLOG #3740 item 15). engine.stop() is one of those steps,
    never cut and handed a bound no shorter than its reserve, so it adds nothing past that bound
    once the reserve covers its own floors and cut graces (BACKLOG #3191 item 3). Not counted, at
    least: what a step that is never cut takes past its floor (the store-reading reap, the store's
    close), and what the interpreter waits for as it exits (a cut step still unwinding, a worker
    thread). The 1 s left over is all the room they have."""
    script = (_REPO / "scripts" / "service" / "install-service.ps1").read_text(encoding="utf-8")
    match = re.search(r"AppStopMethodConsole\s+(\d+)", script)
    assert match is not None, "the install script no longer sets AppStopMethodConsole"
    window = int(match.group(1)) / 1000.0
    import messagefoundry.__main__ as cli

    grace = shutdown_steps.CUT_GRACE_SECONDS
    # Building the list calls nothing, so an engine that never ran __init__ is enough.
    engine_steps = object.__new__(Engine)._stop_steps()
    assert [step.label for step in engine_steps if not step.bounded] == ["the store's close"]
    engine_worst = sum(step.floor for step in engine_steps)
    engine_worst += sum(step.bounded for step in engine_steps) * grace
    assert engine_worst <= app_module._ENGINE_STOP_RESERVE_SECONDS, engine_worst

    app_steps = _every_managed_step(harness=False)
    floors = sum(step.floor for step in app_steps)
    assert floors <= app_module._SHUTDOWN_BUDGET_SECONDS, floors
    lifespan = max(app_module._SHUTDOWN_BUDGET_SECONDS, floors)
    lifespan += sum(step.bounded for step in app_steps) * grace
    shutdown = cli._UVICORN_DRAIN_SECONDS + lifespan
    assert shutdown + 1.0 <= window + 1e-9, (shutdown, window)
    assert app_module._ENGINE_STOP_RESERVE_SECONDS < app_module._SHUTDOWN_BUDGET_SECONDS


def test_the_managed_steps_are_built_in_their_pinned_order() -> None:
    """Vault BACKLOG #3740 item 16: the order is read off the list the lifespan runs, not off fakes
    that record their own calls. At least these constraints depend on it: the drains run while the
    store is open, the lock notices before the security notifier that sends their mail, and the
    alert notifier last, after engine.stop()."""
    assert [step.label for step in _every_managed_step(harness=True)] == _MANAGED_ORDER


async def test_the_managed_lifespan_runs_its_real_steps_in_the_pinned_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same order, from the steps a real managed app runs at shutdown, none of them replaced."""
    from messagefoundry.config.settings import StoreSettings

    ran: list[str] = []
    labels: dict[int, str] = {}
    real_run, real_invoke = shutdown_steps.run_teardown, shutdown_steps._invoke

    async def _run(steps: list[_TeardownStep], budget: float) -> None:
        labels.update((id(step.run), step.label) for step in steps)
        await real_run(steps, budget)

    async def _invoke(run: Callable[[float], Awaitable[object]], bound: float) -> object:
        # engine.stop()'s own steps run through it too, under labels of their own.
        if id(run) in labels:
            ran.append(labels[id(run)])
        return await real_invoke(run, bound)

    monkeypatch.setattr(app_module, "_run_teardown", _run)
    monkeypatch.setattr(shutdown_steps, "_invoke", _invoke)
    settings = StoreSettings(path=str(tmp_path / "order.db"), uploads_dir=str(tmp_path / "up"))
    app = create_managed_app(
        store_settings=settings, egress_settings=EgressSettings(deny_by_default=False)
    )
    async with app.router.lifespan_context(app):
        pass
    assert ran == [label for label in _MANAGED_ORDER if label in ran]
    # The control: the steps this app builds did run, the upload ones among them.
    assert {"the upload retention runner's stop", "the upload straggler drain"} <= set(ran)
    assert {"the long-operations drain", "engine.stop()"} <= set(ran)


async def test_the_long_operations_drain_splits_its_share_by_its_named_wait_share(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vault BACKLOG #3740 item 17: the split is read off ``_OUTLIVING_WAIT_SHARE``, the one place
    that states it and why it is not the drain defaults' ratio, rather than a literal quarter."""
    monkeypatch.setattr(app_module, "_OUTLIVING_WAIT_SHARE", 0.5)
    monkeypatch.setattr(app_module, "OUTLIVING_DRAIN_SECONDS", 10.0)
    monkeypatch.setattr(app_module, "CANCEL_GRACE_SECONDS", 10.0)
    calls: list[tuple[float, float]] = []

    class _Operations:
        async def drain(self, timeout: float, *, grace: float) -> list[str]:
            calls.append((timeout, grace))
            return []

    app: Any = SimpleNamespace(state=SimpleNamespace(outliving_operations=_Operations()))
    [step] = app_module._app_drain_steps(app, None, None, owns_auth=False)
    await step.run(2.5)
    [(wait, grace)] = calls
    share = 2.5 * shutdown_steps.INNER_SHARE
    assert (wait, grace) == pytest.approx((share / 2, share / 2))


async def test_a_stuck_non_upload_operation_does_not_hold_the_upload_straggler_drain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3740 item 6: the upload drain settles the ``upload.create`` operations, at
    least one kind whose arm starts an upload removal, and not a DR change or reload still rolling
    back at shutdown, which would hold the step for its whole wait share, about 1.3 s here,
    although its only straggler had finished at 0.2 s."""
    from messagefoundry.api.app import _app_drain_steps
    from messagefoundry.api.outlive import OutlivingOperations
    from messagefoundry.store.crypto import generate_key, make_cipher
    from messagefoundry.uploads import UploadStore

    monkeypatch.setattr(app_module, "OUTLIVING_DRAIN_SECONDS", 0.05)
    monkeypatch.setattr(app_module, "CANCEL_GRACE_SECONDS", 0.1)
    uploads = UploadStore(tmp_path / "uploads", make_cipher(generate_key()), max_bytes=4096)
    outliving = OutlivingOperations()
    release = asyncio.Event()

    async def _stuck_rollback() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await release.wait()  # a DR hook reap that outlasts the drain's grace
            raise

    caller = asyncio.ensure_future(outliving.run(_stuck_rollback(), "DR activate"))
    finished: list[float] = []
    began = time.monotonic()

    async def _ledger_call() -> None:
        await asyncio.sleep(0.2)
        finished.append(time.monotonic() - began)

    straggler = asyncio.ensure_future(_ledger_call())
    uploads._hold(straggler)
    await asyncio.sleep(0)
    try:
        app: Any = SimpleNamespace(
            state=SimpleNamespace(outliving_operations=outliving, upload_store=uploads)
        )
        await _run_teardown(_app_drain_steps(app, None, None, owns_auth=False), 2.6)
        elapsed = time.monotonic() - began
        assert finished, "the straggler was cancelled before its 0.2 s"
        assert outliving.inflight == ["DR activate"], "the control: the DR arm is still running"
        assert elapsed < 1.1, f"the upload drain waited on the DR arm: {elapsed:.2f}s"
    finally:
        release.set()
        await asyncio.gather(caller, straggler, return_exceptions=True)


async def test_a_removal_a_cancelled_create_row_starts_late_is_drained_before_the_teardown_ends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3740 item 6. The long-operations drain cancels an ``upload.create`` row whose
    unwind outlasts that drain's grace, as a rollback queued behind a slow statement does. The
    row's arm then removes the stored file. Red before: the upload straggler drain found nothing
    held yet, returned at once, and the removal began after the teardown had moved on, so the
    file was still stored when the teardown ended."""
    from messagefoundry.api.app import _app_drain_steps, _record_upload_create
    from messagefoundry.api.outlive import OutlivingOperations
    from messagefoundry.store.crypto import generate_key, make_cipher
    from messagefoundry.uploads import UploadStore

    monkeypatch.setattr(app_module, "OUTLIVING_DRAIN_SECONDS", 0.05)
    monkeypatch.setattr(app_module, "CANCEL_GRACE_SECONDS", 0.1)
    uploads = UploadStore(tmp_path / "uploads", make_cipher(generate_key()), max_bytes=4096)
    meta = await uploads.save(data=b"x\n", filename="a.txt", uploader="op", uploader_id="u-op")
    writing = asyncio.Event()

    class _SlowUnwind:
        async def record_audit(self, action: str, **_kwargs: Any) -> None:
            if action != "upload.create":
                return  # any later row, such as one for the removal itself
            writing.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await asyncio.sleep(0.3)  # longer than the drain's wait and grace together
                raise

    outliving = OutlivingOperations()
    store: Any = _SlowUnwind()
    row = _record_upload_create(
        store,
        uploads,
        meta,
        actor="op",
        client=None,
    )
    caller = asyncio.ensure_future(outliving.run(row, app_module._UPLOAD_CREATE_OPERATION))
    try:
        await asyncio.wait_for(writing.wait(), _WAIT_S)
        assert await uploads.list_files(), "the control: the pair is stored"
        app: Any = SimpleNamespace(
            state=SimpleNamespace(outliving_operations=outliving, upload_store=uploads)
        )
        await _run_teardown(_app_drain_steps(app, None, None, owns_auth=False), 2.6)
        assert await uploads.list_files() == [], "the removal had not run when the teardown ended"
        assert not list((tmp_path / "uploads").glob("*.blob"))
    finally:
        await asyncio.gather(caller, return_exceptions=True)
        # Red, the arm is still running: let it finish before tmp_path goes.
        for _ in range(100):
            if not outliving.inflight and not uploads._stragglers:
                break
            await asyncio.sleep(0.02)


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
        self.real_stop: Callable[..., Awaitable[None]] | None = None

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

        async def _stop(**kwargs: Any) -> None:
            calls.append("stop")
            await real_stop(**kwargs)

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

            async def _stop_raises(**kwargs: Any) -> None:
                spies.calls.append("stop")
                await real_stop(**kwargs)
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
    real_invoke, real_stop = shutdown_steps._invoke, UploadRetentionRunner.stop

    async def _invoke(run: Callable[[float], Awaitable[object]], bound: float) -> object:
        bounds.append(bound)
        return await real_invoke(run, bound)

    async def _stop(self: UploadRetentionRunner, timeout: float | None = None) -> None:
        timeouts.append(timeout)
        await real_stop(self, timeout)

    monkeypatch.setattr(shutdown_steps, "_invoke", _invoke)
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
    assert timeout == pytest.approx(bounds[0] * shutdown_steps.INNER_SHARE)
    assert timeout < bounds[0]
    # The premise: even with fewer steps than serve runs, the share is the shorter of the two waits.
    assert timeout < uploads_module._DEFAULT_STOP_TIMEOUT_SECONDS


async def test_the_managed_teardown_drains_config_writes_under_its_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2623 under BACKLOG #3191: the config-write drain is a budgeted step before
    engine.stop(), handed a share of its bound, and engine.stop() then does not run its own fixed
    wait as well, which would spend time past the budget."""
    labels: list[str] = []
    bounds: list[float] = []
    real_run, real_invoke = shutdown_steps.run_teardown, shutdown_steps._invoke

    async def _run(steps: list[_TeardownStep], budget: float) -> None:
        labels.extend(step.label for step in steps)
        await real_run(steps, budget)

    async def _invoke(run: Callable[[float], Awaitable[object]], bound: float) -> object:
        bounds.append(bound)
        return await real_invoke(run, bound)

    monkeypatch.setattr(app_module, "_run_teardown", _run)
    monkeypatch.setattr(shutdown_steps, "_invoke", _invoke)
    app = _managed(tmp_path / "config-drain.db")
    calls: list[tuple[str, float | None]] = []
    async with app.router.lifespan_context(app):
        engine: Engine = app.state.engine
        real_drain, real_stop = engine.drain_config_writes, engine.stop

        async def _drain(timeout: float) -> None:
            calls.append(("drain", timeout))
            await real_drain(timeout)

        async def _stop(**kwargs: Any) -> None:
            calls.append(("stop", None))
            await real_stop(**kwargs)

        async def _in_flight_write() -> None:
            # Stands in for a write whose caller went: it lands after the teardown began.
            await asyncio.sleep(0.3)
            calls.append(("write landed", None))

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
    assert calls[0][1] == pytest.approx(bounds[step] * shutdown_steps.INNER_SHARE)
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

            async def _timed_stop(**kwargs: Any) -> None:
                spies.calls.append("stop")
                began = time.monotonic()
                await real_stop(**kwargs)
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
    graces = 4 * shutdown_steps.CUT_GRACE_SECONDS
    assert elapsed < budget + graces + stop_took[0] + 0.5, f"teardown took {elapsed:.2f}s"


# --- engine.stop() under a budget (BACKLOG #3191 item 3) -----------------------------------------


async def _bare_engine(path: Path) -> Engine:
    return await Engine.create(
        path, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )


def _record_close(engine: Engine, calls: list[str]) -> None:
    real_close = engine.store.close

    async def _close() -> None:
        calls.append("close")
        await real_close()

    engine.store.close = _close  # type: ignore[method-assign]


def _share_of_first_step(engine: Engine, budget: float) -> float:
    """The first step's bound under ``budget``: what is left once the cut graces and every later
    step's floor are taken out, as Engine.stop and run_teardown compute it."""
    steps = engine._stop_steps()
    graces = sum(step.bounded for step in steps) * shutdown_steps.CUT_GRACE_SECONDS
    return max(steps[0].floor, budget - graces - sum(step.floor for step in steps[1:]))


async def test_the_managed_lifespan_hands_engine_stop_its_bound(tmp_path: Path) -> None:
    app = _managed(tmp_path / "handed.db")
    budgets: list[float | None] = []
    async with app.router.lifespan_context(app):
        engine: Engine = app.state.engine
        real_stop = engine.stop

        async def _stop(*, budget_seconds: float | None = None) -> None:
            budgets.append(budget_seconds)
            await real_stop(budget_seconds=budget_seconds)

        engine.stop = _stop  # type: ignore[method-assign]
    [budget] = budgets
    assert budget is not None
    assert app_module._ENGINE_STOP_RESERVE_SECONDS <= budget <= app_module._SHUTDOWN_BUDGET_SECONDS


async def test_a_hung_graph_supervisor_does_not_push_engine_stop_past_its_share(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A supervisor that never exits on its own is cancelled at its share of the budget, and every
    later step, the store's close among them, still runs, inside the budget."""
    engine = await _bare_engine(tmp_path / "hung-supervisor.db")
    calls: list[str] = []
    _record_close(engine, calls)
    cancelled_at: list[float] = []

    async def _hung_supervisor() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled_at.append(time.monotonic())
            raise

    supervisor = asyncio.ensure_future(_hung_supervisor())
    engine._graph_supervisor = supervisor
    budget = app_module._ENGINE_STOP_RESERVE_SECONDS
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.engine"):
        began = time.monotonic()
        await asyncio.wait_for(engine.stop(budget_seconds=budget), _WAIT_S)
        elapsed = time.monotonic() - began
    assert supervisor.cancelled()
    assert calls == ["close"]
    assert elapsed < budget, f"engine.stop() took {elapsed:.2f}s"
    share = _share_of_first_step(engine, budget)
    # Its own wait ended it, inside its share, so the teardown never had to cut it.
    [at] = cancelled_at
    assert at - began <= share * shutdown_steps.INNER_SHARE + 0.25, (at - began, share)
    assert any("graph supervisor did not exit" in r.getMessage() for r in caplog.records)


async def test_a_supervisor_that_ignores_its_cancel_is_cut_and_the_stop_goes_on(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The cut is the backstop for a supervisor its own wait cannot end: the step is cut and logged,
    and the stop still closes the store inside the budget."""
    engine = await _bare_engine(tmp_path / "stubborn-supervisor.db")
    calls: list[str] = []
    _record_close(engine, calls)
    release = asyncio.Event()

    async def _stubborn() -> None:
        while not release.is_set():
            try:
                await release.wait()
            except asyncio.CancelledError:
                continue

    supervisor = asyncio.ensure_future(_stubborn())
    engine._graph_supervisor = supervisor
    budget = app_module._ENGINE_STOP_RESERVE_SECONDS
    try:
        with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.teardown"):
            began = time.monotonic()
            await asyncio.wait_for(engine.stop(budget_seconds=budget), _WAIT_S)
            elapsed = time.monotonic() - began
    finally:
        release.set()
        await asyncio.wait_for(supervisor, _WAIT_S)
        # The cut step the teardown moved on from ends once its supervisor does.
        if left := set(shutdown_steps._left_running):
            await asyncio.wait(left, timeout=_WAIT_S)
    assert calls == ["close"]
    assert elapsed < budget, f"engine.stop() took {elapsed:.2f}s"
    messages = [r.getMessage() for r in caplog.records]
    assert any("the graph supervisor's exit did not finish within" in m for m in messages), messages


async def test_a_hung_graph_stop_is_cut_and_the_later_steps_still_run(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    engine = await _bare_engine(tmp_path / "hung-graph.db")
    calls: list[str] = []
    _record_close(engine, calls)

    async def _hung_stop(**_kwargs: Any) -> None:
        calls.append("graph stop")
        await asyncio.Event().wait()

    async def _drain(timeout: float) -> None:
        calls.append("config drain")

    # A cut graph stop leaves its sources registered, as the real runner's does.
    engine._registry_runner = SimpleNamespace(  # type: ignore[assignment]
        stop=_hung_stop, has_residual_state=True
    )
    engine.drain_config_writes = _drain  # type: ignore[method-assign]
    engine.on_graph_stopped = lambda: calls.append("graph-stopped clear")

    async def _release_lease() -> None:
        calls.append("lease released")

    # Released, the lease would let a standby recover rows this graph may still be delivering.
    engine._coordinator.stop = _release_lease  # type: ignore[method-assign]
    budget = app_module._ENGINE_STOP_RESERVE_SECONDS
    with caplog.at_level(logging.ERROR):
        began = time.monotonic()
        await asyncio.wait_for(engine.stop(budget_seconds=budget), _WAIT_S)
        elapsed = time.monotonic() - began
    # No clear says a graph that may still be serving has gone.
    assert calls == ["graph stop", "config drain", "close"]
    assert elapsed < budget, f"engine.stop() took {elapsed:.2f}s"
    messages = [r.getMessage() for r in caplog.records]
    assert any("the graph's stop did not finish within" in m for m in messages), messages
    assert any("the graph did not stop" in m for m in messages), messages
    assert any("keeps its cluster lease" in m for m in messages), messages


async def test_a_graph_that_stopped_gets_its_graph_stopped_clear_under_a_budget(
    tmp_path: Path,
) -> None:
    """The control for the test above: with the graph stopped, the clear is raised and the lease
    released."""
    engine = await _bare_engine(tmp_path / "stopped-graph.db")
    calls: list[str] = []
    _record_close(engine, calls)
    engine.on_graph_stopped = lambda: calls.append("graph-stopped clear")

    async def _release_lease() -> None:
        calls.append("lease released")

    engine._coordinator.stop = _release_lease  # type: ignore[method-assign]
    await asyncio.wait_for(
        engine.stop(budget_seconds=app_module._ENGINE_STOP_RESERVE_SECONDS), _WAIT_S
    )
    assert calls == ["graph-stopped clear", "lease released", "close"]


class _FakeRunner:
    """A background runner's stop, recorded. ``fail`` makes it raise."""

    def __init__(
        self, name: str, calls: list[tuple[str, float | None]], *, fail: bool = False
    ) -> None:
        self.name, self.calls, self.fail = name, calls, fail

    async def stop(self, timeout: float | None = None) -> None:
        self.calls.append((self.name, timeout))
        if self.fail:
            raise RuntimeError(f"PROBE: {self.name} failed to stop")


async def test_the_background_runners_all_stop_and_only_the_stopped_are_forgotten(
    tmp_path: Path,
) -> None:
    """Every runner's stop runs, whichever fails, the first failure is raised once they all ran,
    and a runner whose stop failed stays known, so the next stop() retries it. With no budget the
    CRL runner keeps its own wait."""
    engine = await _bare_engine(tmp_path / "runners.db")
    calls: list[tuple[str, float | None]] = []
    retention = _FakeRunner("retention", calls, fail=True)
    crl = _FakeRunner("crl", calls)
    forward = _FakeRunner("log forward", calls, fail=True)
    engine._retention_runner = retention  # type: ignore[assignment]
    engine._crl_reload_runner = crl  # type: ignore[assignment]
    engine._log_forward_watch = forward  # type: ignore[assignment]
    try:
        with pytest.raises(RuntimeError, match="retention"):
            await engine._stop_background_runners(math.inf)
        assert sorted(name for name, _ in calls) == ["crl", "log forward", "retention"]
        assert ("crl", math.inf) in calls
        assert engine._crl_reload_runner is None
        assert id(engine._log_forward_watch) == id(forward)
    finally:
        engine._retention_runner = engine._log_forward_watch = None
        await engine.stop()


async def test_under_a_budget_the_crl_runner_s_wait_is_a_share_of_its_step(
    tmp_path: Path,
) -> None:
    engine = await _bare_engine(tmp_path / "crl-share.db")
    calls: list[tuple[str, float | None]] = []
    engine._crl_reload_runner = _FakeRunner("crl", calls)  # type: ignore[assignment]
    budget = app_module._ENGINE_STOP_RESERVE_SECONDS
    await asyncio.wait_for(engine.stop(budget_seconds=budget), _WAIT_S)
    [(name, timeout)] = calls
    assert name == "crl" and timeout is not None
    assert timeout < budget


async def test_engine_stop_with_no_budget_raises_the_first_failure_as_before(
    tmp_path: Path,
) -> None:
    engine = await _bare_engine(tmp_path / "no-budget.db")

    async def _boom(**_kwargs: Any) -> None:
        raise RuntimeError("PROBE: deliberate graph stop failure")

    real_runner = engine._registry_runner
    engine._registry_runner = SimpleNamespace(  # type: ignore[assignment]
        stop=_boom, has_residual_state=True
    )
    try:
        with pytest.raises(RuntimeError, match="PROBE"):
            await engine.stop()
    finally:
        # Closes the store whatever the assertion did, so its worker thread cannot wedge the run.
        engine._registry_runner = real_runner
        await engine.stop()


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
