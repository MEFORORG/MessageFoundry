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
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.redaction import safe_text
from messagefoundry.store.store import MessageStore
from tests.test_alert_sinks import _drain as _drain_transports
from tests.test_alert_sinks import _RecordingTransport
from tests.test_alert_state import _drain as _drain_state
from tests.test_alert_state import _RecordingStore
from tests.test_sandbox import RAW
from tests.test_sandbox_graph_parity import _GRAPH, _VARIABLE

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
