# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A refused sandbox worker raises one ``sandbox_worker_refused`` alert (vault BACKLOG #2724).

Owner ruling 2026-10-16: alert, keep dead-letter. A worker whose config module bytes differ from the
ones the engine loaded refuses. Since vault BACKLOG #2596 a worker runs the snapshot it is sent, so an
edit on disk no longer reaches it, and these tests send the worker the edited bytes to provoke the
refusal. The message in hand still fails as before;
these tests pin that an operator is also told, once per refusal and not once per message, and that
the alert carries fixed words and no message content.

Synthetic HL7 only.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import pickle
import threading
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.config.run_context import RunContext
from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    EgressSettings,
)
from messagefoundry.config.snapshot import read_config_snapshot
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink, sandbox_worker_refused_detail
from messagefoundry.pipeline.dryrun import transform_one
from messagefoundry.pipeline.sandbox import (
    GraphShape,
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
    SandboxSessionClosed,
    SandboxWorkerRefused,
    graph_shape,
)
from messagefoundry.pipeline.stage_dispatcher import LaneResultKind, StageDispatcher
from messagefoundry.pipeline.wiring_runner import RegistryRunner, SandboxRefusalOvertaken
from messagefoundry.redaction import safe_text
from messagefoundry.store import Stage
from messagefoundry.store.store import MessageStore
from tests.test_alert_sinks import _drain as _drain_transports
from tests.test_alert_sinks import _RecordingTransport
from tests.test_alert_state import _drain as _drain_state
from tests.test_alert_state import _RecordingStore
from tests.test_sandbox import RAW
from tests.test_sandbox_graph_parity import _GRAPH, _VARIABLE
from tests.test_task_resilience import _OneRowThenFaultStore, _until

#: A digest for a graph built here: the runner refuses a worker mode beside a config dir for a
#: graph with none (BACKLOG #5334), and these tests are about the alert, not that refusal.
_SOME_DIGEST = "0" * 64

#: A value of the message's own that must never reach an alert.
_BODY_MARKER = "DOE^JANE"
assert _BODY_MARKER in RAW


class _Recorder:
    """Records ``sandbox_worker_refused`` and nothing else; any other alert is a test failure."""

    def __init__(self) -> None:
        self.refused: list[tuple[str, bool]] = []

    def sandbox_worker_refused(self, name: str, *, content_only: bool) -> None:
        self.refused.append((name, content_only))


@pytest.fixture
def edited_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A config the engine loaded, whose Handler body was then edited on disk with no reload."""
    monkeypatch.delenv(_VARIABLE, raising=False)
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "graph.py").write_text(_GRAPH, encoding="utf-8")
    return cfg


def _edit(cfg: Path) -> None:
    (cfg / "graph.py").write_text(_GRAPH.replace('"COUNT="', '"EDITED="'), encoding="utf-8")


def _loaded_then_sent_edited(cfg: Path) -> Registry:
    """A graph loaded from ``cfg`` whose snapshot, the bytes its sandbox workers are sent, is then
    a read of the edited file: a worker that runs other bytes than the engine loaded."""
    registry = load_config(cfg)
    _edit(cfg)
    registry.config_snapshot = read_config_snapshot(cfg, strict=True)
    return registry


def _runner(registry: Registry, store: MessageStore, cfg: Path, sink: Any) -> RegistryRunner:
    return RegistryRunner(
        registry,
        store,
        sandbox_policy=SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0),
        sandbox_config_source=(str(cfg), None),
        egress=EgressSettings(deny_by_default=False),
        alert_sink=sink,
    )


async def test_the_first_refusal_alerts_once_and_later_messages_do_not(
    edited_config: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Through the runner's own dispatch chokepoint: the refusal still raises (the message still
    fails and dead-letters under the policy), the alert fires on the first, and the cached
    refusals for the next messages on the same inbound raise no second alert. The whole refusal,
    digests included, is logged once."""
    registry = _loaded_then_sent_edited(edited_config)
    sink = _Recorder()
    store = await MessageStore.open(tmp_path / "refusal.db")
    try:
        runner = _runner(registry, store, edited_config, cast(Any, sink))
        try:
            with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.wiring_runner"):
                for _ in range(3):
                    with pytest.raises(SandboxWorkerRefused):
                        await runner._off_loop_sandboxed(
                            "IB_PARITY",
                            transform_one,
                            registry,
                            "h_0",
                            RAW,
                            run_context=RunContext(),
                        )
            assert sink.refused == [("IB_PARITY", True)]
        finally:
            await runner._close_sandbox_sessions()
    finally:
        await store.close()
    (line,) = [
        r.getMessage() for r in caplog.records if "sandbox worker for inbound" in r.getMessage()
    ]
    assert line.startswith("inbound 'IB_PARITY': sandbox worker for inbound 'IB_PARITY' refused")
    assert "the worker loaded" in line and _BODY_MARKER not in line


async def test_a_swap_to_an_equal_registry_keeps_one_alert_and_no_more(
    edited_config: Path, tmp_path: Path
) -> None:
    """The session's refusal cache and the runner's alert gate together (BACKLOG #6830): the first
    refusal alerts once; a swap to an equal but new registry, with the session kept, is the same
    graph to both, so the later messages are refused from the cache and raise no second alert."""
    registry = _loaded_then_sent_edited(edited_config)
    sink = _Recorder()
    store = await MessageStore.open(tmp_path / "swap.db")
    try:
        runner = _runner(registry, store, edited_config, cast(Any, sink))
        try:
            session = runner._sandbox_for("IB_PARITY")
            assert session is not None
            for swap in (False, True, False):
                if swap:
                    before = runner._engine_graph_shape()
                    runner.registry = copy.copy(registry)
                    assert runner._engine_graph_shape() == before
                    assert runner._engine_graph_shape() is not before
                with pytest.raises(SandboxWorkerRefused):
                    await runner._off_loop_sandboxed(
                        "IB_PARITY", transform_one, registry, "h_0", RAW, run_context=RunContext()
                    )
            assert runner._sandbox_for("IB_PARITY") is session
            assert session._generation == 1  # one worker, refused once; the rest were cache hits
            assert sink.refused == [("IB_PARITY", True)]
        finally:
            await runner._close_sandbox_sessions()
    finally:
        await store.close()


async def test_a_refusal_reached_through_the_closed_session_retry_alerts(tmp_path: Path) -> None:
    """The retry after a reload closed the session mid-dispatch is inside the alerting arm too."""
    registry = Registry(code_digest=_SOME_DIGEST)
    sink = _Recorder()
    calls: list[int] = []

    def dispatch(_registry: Registry, *, sandbox: Any) -> None:
        calls.append(1)
        if len(calls) == 1:
            raise SandboxSessionClosed("closed")
        raise SandboxWorkerRefused("refused", first=True, content_only=False)

    store = await MessageStore.open(tmp_path / "retry.db")
    try:
        runner = _runner(registry, store, tmp_path, cast(Any, sink))
        try:
            with pytest.raises(SandboxWorkerRefused):
                await runner._off_loop_sandboxed("IB_X", dispatch, registry)
        finally:
            await runner._close_sandbox_sessions()
    finally:
        await store.close()
    assert len(calls) == 2
    assert sink.refused == [("IB_X", False)]


async def test_a_refusal_alerts_only_against_a_graph_equal_to_the_served_one(
    tmp_path: Path,
) -> None:
    """A refusal from the live session alerts only when the graph it was compared with equals the
    one served (BACKLOG #6830). Against an unequal graph, as after a direct swap of the registry
    with the session kept, it is overtaken: it is retried once, since the registry is still the
    one served, and then raised as a close, which the worker re-pends, with no alert and no
    dead-letter. Against an equal object that is not the served one it alerts, since the
    session's by-value cache raises no later first refusal for it."""
    registry = Registry(code_digest=_SOME_DIGEST)
    sink = _Recorder()
    compared: list[GraphShape] = []

    def dispatch(_registry: Registry, *, sandbox: Any) -> None:
        raise SandboxWorkerRefused("refused", first=True, content_only=True, graph=compared[0])

    store = await MessageStore.open(tmp_path / "stale.db")
    try:
        runner = _runner(registry, store, tmp_path, cast(Any, sink))
        try:
            compared.append(graph_shape(Registry(code_digest="1" * 64)))  # not the served graph
            with pytest.raises(SandboxSessionClosed) as closed:
                await runner._off_loop_sandboxed("IB_X", dispatch, registry)
            assert isinstance(closed.value.__cause__, SandboxWorkerRefused)
            assert sink.refused == []
            # An equal graph is the same graph (BACKLOG #6830): the refusal still stands, so it
            # alerts, as the session's by-value cache will not raise another first refusal.
            compared[0] = graph_shape(registry)
            assert compared[0] is not runner._engine_graph_shape()
            with pytest.raises(SandboxWorkerRefused):
                await runner._off_loop_sandboxed("IB_X", dispatch, registry)
            assert sink.refused == [("IB_X", True)]
            sink.refused.clear()
            # CONTROL: the same refusal against the graph being served does alert.
            compared[0] = runner._engine_graph_shape()
            with pytest.raises(SandboxWorkerRefused):
                await runner._off_loop_sandboxed("IB_X", dispatch, registry)
            assert sink.refused == [("IB_X", True)]
        finally:
            await runner._close_sandbox_sessions()
    finally:
        await store.close()


@pytest.mark.parametrize("cached", [False, True], ids=["first", "cached"])
@pytest.mark.parametrize("cleared", [False, True], ids=["cause_stands", "reload_cleared_it"])
async def test_a_refusal_straddling_a_reload_to_an_equal_graph_re_pends(
    tmp_path: Path, cleared: bool, cached: bool
) -> None:
    """A refusal, first or cached, whose session a reload to an equal graph discarded while it ran
    is a close, not a refusal (BACKLOG #6830): it raises :class:`SandboxSessionClosed`, which the
    worker re-pends, so it neither alerts nor dead-letters. The message's next run, on a fresh
    session, compares again. Where the cause stands, its refusal is the one alert; where the reload
    cleared it (the content-only case: the worker now runs the reloaded bytes), it is delivered
    and no alert is left open."""
    registry = Registry(code_digest=_SOME_DIGEST)
    sink = _Recorder()
    calls: list[Any] = []
    runner: RegistryRunner | None = None

    def dispatch(_registry: Registry, *, sandbox: Any) -> None:
        assert runner is not None
        calls.append(sandbox)
        if len(calls) == 1:
            compared = runner._engine_graph_shape()
            runner._sandbox_sessions.clear()  # the reload drops the sessions, then closes them
            runner.registry = copy.copy(registry)  # an equal graph, a new object
            assert runner._engine_graph_shape() == compared
            raise SandboxWorkerRefused(
                "refused", first=not cached, content_only=True, graph=compared
            )
        if not cleared:
            raise SandboxWorkerRefused(
                "refused", first=True, content_only=True, graph=runner._engine_graph_shape()
            )

    store = await MessageStore.open(tmp_path / "straddle.db")
    try:
        runner = _runner(registry, store, tmp_path, cast(Any, sink))
        try:
            with pytest.raises(SandboxSessionClosed) as closed:
                await runner._off_loop_sandboxed("IB_X", dispatch, registry)
            assert isinstance(closed.value.__cause__, SandboxWorkerRefused)
            assert sink.refused == []
            assert len(calls) == 1  # another graph is served, so re-pended rather than retried
            # The re-pended message's next run reads the registry afresh.
            if cleared:
                await runner._off_loop_sandboxed("IB_X", dispatch, runner.registry)
                assert sink.refused == []
            else:
                with pytest.raises(SandboxWorkerRefused):
                    await runner._off_loop_sandboxed("IB_X", dispatch, runner.registry)
                assert sink.refused == [("IB_X", True)]
            assert calls[0] is not calls[1]  # the second run was on a fresh session
        finally:
            await runner._close_sandbox_sessions()
    finally:
        await store.close()


def _refused_then_reloaded(
    runner: RegistryRunner, loop: asyncio.AbstractEventLoop, *, stop: bool
) -> Any:
    """``transform_one``, with a reload that re-applies the same registry, as ``reload(None)`` or a
    rollback does, landing after the first dispatch's real worker refused and before that refusal
    reaches the loop. ``stop`` sets the runner stopping first, as a shutdown that overlaps it."""
    runs: list[Any] = []

    def call(*args: Any, sandbox: SandboxSession | None = None, **kwargs: Any) -> Any:
        runs.append(sandbox)
        try:
            return transform_one(*args, sandbox=sandbox, **kwargs)
        except SandboxWorkerRefused:
            if len(runs) == 1:
                if stop:
                    loop.call_soon_threadsafe(runner._stop.set)
                asyncio.run_coroutine_threadsafe(runner._close_sandbox_sessions(), loop).result(30)
            raise

    call.runs = runs  # type: ignore[attr-defined]
    return call


async def test_a_refusal_straddling_a_same_registry_reload_alerts_once(
    edited_config: Path, tmp_path: Path
) -> None:
    """A real refusal whose session a same-registry reload discarded while it ran (BACKLOG #6830).
    The registry is still served, so the dispatch is retried at once on a fresh session, whose
    worker compares again and refuses: that refusal is the one alert, and the message fails on it.
    Before, the first refusal was dropped from the alert as stale and still dead-lettered the
    message, so no alert was raised until some later message came."""
    registry = _loaded_then_sent_edited(edited_config)
    sink = _Recorder()
    store = await MessageStore.open(tmp_path / "same.db")
    try:
        runner = _runner(registry, store, edited_config, cast(Any, sink))
        try:
            call = _refused_then_reloaded(runner, asyncio.get_running_loop(), stop=False)
            with pytest.raises(SandboxWorkerRefused) as refused:
                await runner._off_loop_sandboxed(
                    "IB_PARITY", call, registry, "h_0", RAW, run_context=RunContext()
                )
            assert refused.value.first
            assert sink.refused == [("IB_PARITY", True)]
            first, second = call.runs
            assert first is not None and second is not None
            assert first is not second and first._closed and not second._closed
            assert first._proc is None and second._proc is None  # no worker ever came up
            assert runner._sandbox_for("IB_PARITY") is second
            # The next message is refused from the serving session's cache: no second alert.
            with pytest.raises(SandboxWorkerRefused):
                await runner._off_loop_sandboxed(
                    "IB_PARITY", transform_one, registry, "h_0", RAW, run_context=RunContext()
                )
            assert sink.refused == [("IB_PARITY", True)]
        finally:
            await runner._close_sandbox_sessions()
    finally:
        await store.close()


async def test_a_refusal_overtaken_by_a_graph_change_alerts_when_the_graph_returns(
    edited_config: Path, tmp_path: Path
) -> None:
    """A refusal overtaken only by a graph change, with the session kept (a swap of the registry
    with no reload), discards that session (BACKLOG #6830). Kept, its refusal cache would hold the
    overtaken refusal, so once an equal graph was served again the message's rerun would be
    refused from that cache, as not first, and dead-lettered with no alert ever raised."""
    registry = _loaded_then_sent_edited(edited_config)
    sink = _Recorder()
    runner: RegistryRunner | None = None

    def call(*args: Any, sandbox: SandboxSession | None = None, **kwargs: Any) -> Any:
        try:
            return transform_one(*args, sandbox=sandbox, **kwargs)
        except SandboxWorkerRefused:
            assert runner is not None
            runner.registry = Registry(code_digest="1" * 64)  # an unequal graph, session kept
            raise

    store = await MessageStore.open(tmp_path / "graph_change.db")
    try:
        runner = _runner(registry, store, edited_config, cast(Any, sink))
        try:
            session = runner._sandbox_for("IB_PARITY")
            assert session is not None
            with pytest.raises(SandboxSessionClosed):
                await runner._off_loop_sandboxed(
                    "IB_PARITY", call, registry, "h_0", RAW, run_context=RunContext()
                )
            assert sink.refused == []
            assert "IB_PARITY" not in runner._sandbox_sessions
            await _detached_closes(runner)  # the close runs off the worker (BACKLOG #6830)
            assert session._closed
            runner.registry = copy.copy(registry)  # an equal graph is served again
            with pytest.raises(SandboxWorkerRefused) as refused:
                await runner._off_loop_sandboxed(
                    "IB_PARITY",
                    transform_one,
                    runner.registry,
                    "h_0",
                    RAW,
                    run_context=RunContext(),
                )
            assert refused.value.first
            assert sink.refused == [("IB_PARITY", True)]
        finally:
            await runner._close_sandbox_sessions()
    finally:
        await store.close()


async def test_a_failed_close_of_an_overtaken_session_still_re_pends(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The graph-overtaken branch closes the session it discards. A close that raises is logged
    and the refusal is still raised as a close, so the message is re-pended rather than
    dead-lettered as a Router or Handler fault (BACKLOG #6830)."""
    registry = Registry(code_digest=_SOME_DIGEST)
    sink = _Recorder()
    other = graph_shape(Registry(code_digest="1" * 64))

    def dispatch(_registry: Registry, *, sandbox: Any) -> None:
        raise SandboxWorkerRefused("refused", first=True, content_only=False, graph=other)

    def failing_close() -> None:
        raise OSError("close failed")

    store = await MessageStore.open(tmp_path / "close_fails.db")
    try:
        runner = _runner(registry, store, tmp_path, cast(Any, sink))
        try:
            session = runner._sandbox_for("IB_X")
            assert session is not None
            session.close = failing_close  # type: ignore[method-assign]
            with (
                caplog.at_level(logging.DEBUG, logger="messagefoundry.pipeline.wiring_runner"),
                pytest.raises(SandboxSessionClosed) as closed,
            ):
                await runner._off_loop_sandboxed("IB_X", dispatch, registry)
            assert isinstance(closed.value, SandboxRefusalOvertaken)
            assert isinstance(closed.value.__cause__, SandboxWorkerRefused)
            assert sink.refused == []
            with caplog.at_level(logging.DEBUG, logger="messagefoundry.pipeline.wiring_runner"):
                await _detached_closes(runner)  # the close runs off the worker
            warned = [
                r.getMessage()
                for r in caplog.records
                if r.name == "messagefoundry.pipeline.wiring_runner"
                and r.levelno == logging.WARNING
                and "could not close the sandbox session" in r.getMessage()
            ]
            assert len(warned) == 1 and "'IB_X'" in warned[0] and "OSError" in warned[0], warned
        finally:
            runner._sandbox_sessions.clear()
            await runner._close_sandbox_sessions()
    finally:
        await store.close()


async def test_a_slow_close_of_an_overtaken_session_does_not_hold_the_dispatch(
    tmp_path: Path,
) -> None:
    """The graph-overtaken branch closes the session it discards OFF the inbound's worker
    (BACKLOG #6830): the dispatch re-pends at once while the close still runs, so a slow close
    cannot stall routing or transform. The close is not dropped: it is tracked with the detached
    closes the teardown of :meth:`RegistryRunner.stop` waits for. A reload's session close does
    not wait for it, since a reload holds its lock with every listener unbound."""
    registry = Registry(code_digest=_SOME_DIGEST)
    sink = _Recorder()
    other = graph_shape(Registry(code_digest="1" * 64))
    release = threading.Event()
    closed = threading.Event()

    def dispatch(_registry: Registry, *, sandbox: Any) -> None:
        raise SandboxWorkerRefused("refused", first=True, content_only=False, graph=other)

    def slow_close() -> None:
        assert release.wait(30)
        closed.set()

    store = await MessageStore.open(tmp_path / "slow_close.db")
    try:
        runner = _runner(registry, store, tmp_path, cast(Any, sink))
        try:
            session = runner._sandbox_for("IB_X")
            assert session is not None
            session.close = slow_close  # type: ignore[method-assign]
            before = set(runner._lookup_close_tasks)
            with pytest.raises(SandboxSessionClosed):
                await asyncio.wait_for(runner._off_loop_sandboxed("IB_X", dispatch, registry), 5)
            assert not closed.is_set()  # the dispatch came back with the close still running
            assert "IB_X" not in runner._sandbox_sessions
            pending = set(runner._lookup_close_tasks) - before
            # Tracked, so the stop teardown waits for them: one per discarded session, the first
            # and the one its immediate retry made, since the registry is still the one served.
            assert len(pending) == 2
            # A reload's session close returns without waiting on it, with a session to close.
            assert runner._sandbox_for("IB_X") is not None
            await asyncio.wait_for(runner._close_sandbox_sessions(), 5)
            assert "IB_X" not in runner._sandbox_sessions
            assert not closed.is_set()
            release.set()
            await asyncio.wait_for(asyncio.wait(pending), 10)
            assert closed.is_set()
            assert not pending & runner._lookup_close_tasks  # dropped once it ended
        finally:
            release.set()
            runner._sandbox_sessions.clear()
            await runner._close_sandbox_sessions()
    finally:
        await store.close()


@pytest.mark.parametrize(
    ("worker_attr", "body_attr", "stage"),
    [
        ("_router_worker", "_process_ingress_item", Stage.INGRESS.value),
        ("_transform_worker", "_process_routed_batch", Stage.ROUTED.value),
    ],
    ids=["router", "transform"],
)
@pytest.mark.parametrize("overtaken", [True, False], ids=["overtaken", "control_closed_twice"])
async def test_an_overtaken_refusal_re_pends_with_no_error_traceback(
    worker_attr: str,
    body_attr: str,
    stage: str,
    overtaken: bool,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An overtaken refusal that reaches the worker's fault arm is re-pended with one INFO line and
    no ERROR traceback (BACKLOG #6830): what overtook it is a reload, not a fault. The back-off
    stays. CONTROL: any other close that reaches the arm, such as a dispatch closed twice, is still
    an infrastructure fault, logged at ERROR with its traceback, so the instrument can see one."""
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.01)
    store = _OneRowThenFaultStore(stage)
    runner = RegistryRunner(
        Registry(),
        store,  # type: ignore[arg-type]
        poll_interval=0.02,
        claim_mode="per_lane",
        egress=EgressSettings(deny_by_default=False),
    )
    runner._running = True

    async def raiser(*a: Any, **k: Any) -> Any:
        if overtaken:
            raise SandboxRefusalOvertaken("overtaken") from SandboxWorkerRefused(
                "refused", first=True, content_only=False
            )
        raise SandboxSessionClosed("closed twice")

    monkeypatch.setattr(runner, body_attr, raiser)
    slept: list[float] = []
    real_sleep = runner._stop_or_sleep

    async def recording_sleep(seconds: float) -> bool:
        slept.append(seconds)
        return await real_sleep(seconds)

    monkeypatch.setattr(runner, "_stop_or_sleep", recording_sleep)
    with caplog.at_level(logging.DEBUG, logger=wiring_runner.log.name):
        task = asyncio.ensure_future(getattr(runner, worker_attr)("IB"))
        try:
            await _until(lambda: store.rescheduled and slept, timeout=5.0)
        finally:
            runner._stop.set()
            for ev in (runner._work, runner._ingress_work, runner._routed_work):
                ev.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert store.rescheduled[0] == ["row-1"]  # re-pended either way
    assert slept[0] == wiring_runner._WORKER_ERROR_BACKOFF_SECONDS  # and the back-off stays
    records = [r for r in caplog.records if r.name == wiring_runner.log.name]
    assert records  # the arm wrote something, so the absence checks below are over a real log
    errors = [r for r in records if r.levelno >= logging.ERROR or r.exc_info]
    if overtaken:
        assert errors == [], [r.getMessage() for r in errors]
        assert any(
            r.levelno == logging.INFO and "'IB'" in r.getMessage() and "overtaken" in r.getMessage()
            for r in records
        ), [r.getMessage() for r in records]
    else:
        assert any(r.levelno >= logging.ERROR and r.exc_info for r in errors)


@pytest.mark.parametrize("overtaken", [True, False], ids=["overtaken", "control_infra_fault"])
def test_the_pooled_dispatcher_logs_an_overtaken_refusal_without_a_traceback(
    overtaken: bool, caplog: pytest.LogCaptureFixture
) -> None:
    """The default claim mode, pooled (BACKLOG #6830): an overtaken refusal escaping the per-item
    body is logged at INFO with no traceback, and is still a T17 infra fault in every other way, so
    the infra-fault STOP bound still holds if it never stops. CONTROL: any other exception there is
    logged at ERROR with its traceback."""
    dispatcher = StageDispatcher(
        Stage.INGRESS,
        cast(Any, None),
        process_item=cast(Any, None),
        lane_provider=set,
        per_lane_limit=1,
        clock=lambda: 1000.0,
    )
    exc: Exception = (
        SandboxRefusalOvertaken("overtaken") if overtaken else SandboxSessionClosed("closed twice")
    )
    items = [cast(Any, type("Row", (), {"id": f"row-{n}"})()) for n in (1, 2)]
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.pipeline.stage_dispatcher"):
        outcome, tail, head = dispatcher._infra_fault_outcome("IB", items, 0, exc)
    assert tail == ["row-2"] and head is not None and head[0] == "row-1"
    assert outcome.kind is LaneResultKind.RETRY and outcome.park_until == head[1]
    records = [r for r in caplog.records if r.name == "messagefoundry.pipeline.stage_dispatcher"]
    assert records
    assert outcome.is_infra_fault and not outcome.hand_back  # counted toward the STOP
    if overtaken:
        assert all(r.levelno == logging.INFO and not r.exc_info for r in records)
    else:
        assert any(r.levelno >= logging.ERROR and r.exc_info for r in records)


async def _detached_closes(runner: RegistryRunner) -> None:
    """Wait for the detached closes the runner tracks for its stop teardown."""
    if runner._lookup_close_tasks:
        _done, pending = await asyncio.wait(set(runner._lookup_close_tasks), timeout=30)
        assert not pending, "a detached close never ended"


async def test_a_refusal_straddling_a_reload_under_stop_re_pends_and_alerts_on_its_rerun(
    edited_config: Path, tmp_path: Path
) -> None:
    """As above, with the runner stopping: nothing is retried while it stops, so the refusal is
    raised as a close and the row is re-pended, with no alert and no dead-letter. The alert is not
    lost: it comes from the message's own rerun, with no other message needed."""
    registry = _loaded_then_sent_edited(edited_config)
    sink = _Recorder()
    store = await MessageStore.open(tmp_path / "stop.db")
    try:
        runner = _runner(registry, store, edited_config, cast(Any, sink))
        try:
            call = _refused_then_reloaded(runner, asyncio.get_running_loop(), stop=True)
            with pytest.raises(SandboxSessionClosed):
                await runner._off_loop_sandboxed(
                    "IB_PARITY", call, registry, "h_0", RAW, run_context=RunContext()
                )
            assert sink.refused == []
            assert len(call.runs) == 1
            # The re-pended row's rerun, once the engine serves again.
            runner._stop.clear()
            with pytest.raises(SandboxWorkerRefused):
                await runner._off_loop_sandboxed(
                    "IB_PARITY", transform_one, registry, "h_0", RAW, run_context=RunContext()
                )
            assert sink.refused == [("IB_PARITY", True)]
        finally:
            await runner._close_sandbox_sessions()
    finally:
        await store.close()


def test_the_refusal_survives_a_copy_and_a_pickle() -> None:
    exc = SandboxWorkerRefused("refused", first=True, content_only=True)
    for clone in (copy.copy(exc), pickle.loads(pickle.dumps(exc))):
        assert (str(clone), clone.first, clone.content_only) == ("refused", True, True)


def test_only_the_comparing_spawn_is_marked_first(edited_config: Path) -> None:
    serving = graph_shape(load_config(edited_config))
    _edit(edited_config)
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0),
        inbound="IB_PARITY",
        config_dir=edited_config,
        env=None,
        graph=lambda: serving,
    )
    try:
        with pytest.raises(SandboxWorkerRefused) as first:
            session._spawn()
        with pytest.raises(SandboxWorkerRefused) as cached:
            session._spawn()
    finally:
        session.close()
    assert (first.value.first, first.value.content_only) == (True, True)
    assert (cached.value.first, cached.value.content_only) == (False, True)


async def test_the_shipped_notifier_carries_fixed_words_and_no_body(
    edited_config: Path, tmp_path: Path
) -> None:
    """What an operator's webhook receives and what the alert list shows. The CONTROL is the
    refusal itself, which the engine log carries: it names what differs."""
    registry = _loaded_then_sent_edited(edited_config)
    transport, state = _RecordingTransport("webhook"), _RecordingStore()
    sink = NotifierAlertSink([transport], store=cast(Any, state))
    store = await MessageStore.open(tmp_path / "notifier.db")
    try:
        runner = _runner(registry, store, edited_config, sink)
        try:
            with pytest.raises(SandboxWorkerRefused) as refused:
                await runner._off_loop_sandboxed(
                    "IB_PARITY", transform_one, registry, "h_0", RAW, run_context=RunContext()
                )
        finally:
            await runner._close_sandbox_sessions()
        await _drain_state(sink)
        await _drain_transports(sink)
    finally:
        await store.close()

    assert "config module content" in str(refused.value)
    (event,) = transport.events
    (row,) = state.upserts
    assert set(event) == {"type", "connection", "detail", "ts", "severity"}
    assert (event["type"], event["connection"]) == ("sandbox_worker_refused", "IB_PARITY")
    assert event["detail"] == row["reason"] == sandbox_worker_refused_detail(content_only=True)
    for carrier in (repr(event), repr(state.upserts)):
        assert _BODY_MARKER not in carrier
        assert "MSH|" not in carrier


def test_the_detail_names_the_cause_and_the_remedy_first() -> None:
    edited = sandbox_worker_refused_detail(content_only=True)
    names = sandbox_worker_refused_detail(content_only=False)
    # The alert instance's reason column keeps what this bound leaves (docs/PHI.md section 8).
    kept_edited, kept_names = safe_text(edited, limit=200), safe_text(names, limit=200)
    assert "Reload the config." in kept_edited and "other config module bytes" in kept_edited
    assert "pass_environment" not in edited
    # A worker runs the engine's snapshot, so a disk edit is no cause and a reload no remedy.
    assert "changed on disk" not in edited + names
    assert "reload" not in names.lower()
    # Settings load refuses a MEFOR_* name in that setting, and a Handler can read what is listed,
    # so the remedy says neither belongs there. The impact still fits within the bound.
    assert "list it in [sandbox].pass_environment (no MEFOR_* name, no secret) and restart" in (
        kept_names
    )
    assert "fails at routing or transform" in kept_names


def test_the_logging_sink_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().sandbox_worker_refused("IB_PARITY", content_only=True)
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    assert record.getMessage().startswith(
        "ALERT sandbox_worker_refused: inbound 'IB_PARITY': The worker ran other config module"
    )


def test_a_rule_can_route_it_but_not_restart_on_it() -> None:
    assert "sandbox_worker_refused" in _ALERT_EVENT_TYPES
    assert "sandbox_worker_refused" not in _ALERT_CONTROL_EVENT_TYPES
