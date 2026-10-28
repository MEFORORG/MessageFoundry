# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1741 act 3: an inbound's bind-failure alert resolves itself once the inbound genuinely
starts (ADR 0031 section 1, ADR 0044 D2).

The raise already existed: ``_record_failed`` raises ``connection_stopped(name, "failed to start:
...")``. This file pins the inverse, ``connection_started``, end to end through the real notifier
and the real ``alert_instance`` table, and pins where it must NOT fire. Alerts key on the bare
connection name while the runner's failure records key on direction (#1813), so an inbound that
comes up must not resolve the alert its outbound namesake still holds open."""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import (
    _ALERT_EVENT_TYPES,
    AlertRule,
    AlertSeverity,
    EgressSettings,
    EscalationTier,
)
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    OutboundConnection,
    Registry,
    build_inbound_connection,
    env,
)
from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "started.db")
    yield s
    await s.close()


@pytest.fixture
def held_port() -> Iterator[tuple[int, socket.socket]]:
    """A port an external process holds, as the bind failure the row measured."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    try:
        yield int(s.getsockname()[1]), s
    finally:
        s.close()


async def _settle(sink: NotifierAlertSink, tasks: set[asyncio.Task[None]] | None = None) -> None:
    # Only the still-running tasks: a done task leaves the set through a callback that a gather of
    # finished tasks never yields to (tests/test_ad_user_account_control.py says why). The state
    # writes unless another task set is named.
    while pending := [t for t in (sink._state_tasks if tasks is None else tasks) if not t.done()]:
        await asyncio.gather(*pending)


async def _open(store: MessageStore) -> set[tuple[str, str]]:
    return {
        (i.event_type, i.connection)
        for i in await store.list_active_alert_instances(allowed_channels=None)
    }


def _registry(port: int, *, outbound_namesake: bool = False) -> Registry:
    reg = Registry()
    reg.add_inbound(build_inbound_connection("SHARED", MLLP(port=port), router="r"))
    reg.add_router("r", lambda m: [])
    if outbound_namesake:
        # env() with no value fails to BUILD at start: the outbound's own open cause.
        reg.add_outbound(
            OutboundConnection(
                "SHARED", ConnectionSpec(ConnectorType.FILE, {"directory": env("d")})
            )
        )
    return reg


def _runner(
    reg: Registry, store: MessageStore, sink: object, *, claim_mode: str = "pooled"
) -> RegistryRunner:
    return RegistryRunner(
        reg,
        store,
        poll_interval=0.02,
        claim_mode=claim_mode,
        env_values={},
        alert_sink=sink,  # type: ignore[arg-type]
        egress=EgressSettings(deny_by_default=False),
    )


async def test_bind_failure_alert_resolves_when_the_inbound_starts(
    store: MessageStore, held_port: tuple[int, socket.socket]
) -> None:
    port, blocker = held_port
    sink = NotifierAlertSink([], store=store)
    runner = _runner(_registry(port), store, sink)
    await runner.start()
    try:
        assert runner.inbound_failed("SHARED")
        await _settle(sink)
        # The raise reaches an alert_instance row: one exists wherever a notifier does (PHI.md row 8).
        assert await _open(store) == {("connection_stopped", "SHARED")}
        blocker.close()  # the operator frees the port
        await runner.start_inbound("SHARED", operator=True)
        assert runner.inbound_running("SHARED")
        await _settle(sink)
        assert await _open(store) == set()
    finally:
        await runner.stop()


async def test_outbound_namesake_failure_keeps_the_alert_open(
    store: MessageStore, held_port: tuple[int, socket.socket]
) -> None:
    # The dual-role case: the outbound of the same name failed to start, and the alert row for the
    # bare name cannot say which half raised it. The inbound coming up resolves nothing.
    port, blocker = held_port
    sink = NotifierAlertSink([], store=store)
    runner = _runner(_registry(port, outbound_namesake=True), store, sink)
    await runner.start()
    try:
        assert runner.outbound_failed("SHARED") and runner.inbound_failed("SHARED")
        blocker.close()
        await runner.start_inbound("SHARED", operator=True)
        assert runner.inbound_running("SHARED")
        await _settle(sink)
        assert await _open(store) == {("connection_stopped", "SHARED")}
    finally:
        await runner.stop()


class _Recording(LoggingAlertSink):
    def __init__(self) -> None:
        self.started: list[str] = []
        self.stopped: list[str] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append(name)

    def connection_started(self, name: str) -> None:
        self.started.append(name)


async def test_a_held_outbound_halt_keeps_the_inbound_namesake_from_resolving(
    store: MessageStore, tmp_path: Path
) -> None:
    # The outbound halted at run time: a STOP site raises connection_stopped and records the hold,
    # which is what _hold_for_operator does at every outbound STOP. A restart of the inbound of the
    # same name must leave that alert open, and so must a paused outbound.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("SHARED", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(
        OutboundConnection(
            "SHARED", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "out")})
        )
    )
    sink = _Recording()
    runner = _runner(reg, store, sink)
    await runner.start()
    try:
        assert sink.started == ["SHARED"]  # a clean start emits once, after the workers spawned
        runner._hold_for_operator("SHARED", "outbound")
        await runner.restart_inbound("SHARED", operator=True)
        assert runner.inbound_running("SHARED")
        assert sink.started == ["SHARED"]
        runner._release_operator_hold("SHARED", "outbound")
        runner._outbound_paused.add("SHARED")
        await runner.restart_inbound("SHARED", operator=True)
        assert sink.started == ["SHARED"]
        runner._outbound_paused.discard("SHARED")
        await runner.restart_inbound("SHARED", operator=True)
        assert sink.started == ["SHARED", "SHARED"]
    finally:
        await runner.stop()


async def test_a_held_inbound_halt_or_log_refusal_does_not_emit(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    sink = _Recording()
    runner = _runner(reg, store, sink)
    await runner.start()
    try:
        sink.started.clear()
        # Pooled (the default): a start re-arms no STOPPED lane, so a router STOP's hold stays and
        # the inbound is listening over stages that are not draining.
        runner._hold_for_operator("IB", "inbound")
        await runner.restart_inbound("IB", operator=True)
        assert runner.inbound_running("IB") and sink.started == []
        runner._release_operator_hold("IB", "inbound")
        # A lane a dispatcher STOPPED on its own account, with no hold (a leadership-loss STOP).
        d = next(iter(runner._dispatchers.values()))
        monkeypatch.setattr(d, "stopped", lambda key: key == "IB")
        await runner.restart_inbound("IB", operator=True)
        assert sink.started == []
        monkeypatch.undo()
        # The log is still unwritable: the start undoes its own bind and must resolve nothing.
        monkeypatch.setattr(runner, "_resume_inbound_processing", lambda name: False)
        monkeypatch.setattr(runner, "_log_write_refused_restart", lambda name: None)
        await runner.restart_inbound("IB", operator=True)
        assert not runner.inbound_running("IB")
        assert sink.started == []
    finally:
        await runner.stop()


async def test_reload_emits_after_commit_and_a_rollback_drops_its_starts(
    store: MessageStore, held_port: tuple[int, socket.socket], monkeypatch: pytest.MonkeyPatch
) -> None:
    port, blocker = held_port
    sink = _Recording()
    runner = _runner(_registry(port), store, sink)
    await runner.start()
    try:
        assert runner.inbound_failed("SHARED") and sink.started == []
        blocker.close()

        async def _boom(*_a: object, **_k: object) -> None:
            raise RuntimeError("step 3 failed")

        # A reload that binds the failed inbound and then rolls back leaves it down, so its start
        # must resolve nothing.
        monkeypatch.setattr(runner, "_reconcile_outbounds", _boom)
        with pytest.raises(RuntimeError, match="step 3 failed"):
            await runner.reload(_registry(port))
        assert not runner.inbound_running("SHARED")
        assert sink.started == []
        assert runner._started_pending is None
        monkeypatch.undo()
        await runner.reload(_registry(port))
        assert runner.inbound_running("SHARED")
        assert sink.started == ["SHARED"]
        assert runner._started_pending is None
    finally:
        await runner.stop()


def test_connection_started_is_an_auto_resolve_inverse_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    assert _AUTO_RESOLVE["connection_started"] == "connection_stopped"
    # Inverses need no page, so no rule may target one (config/settings.py).
    assert "connection_started" not in _ALERT_EVENT_TYPES
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().connection_started("IB")
        LoggingAlertSink().connection_stopped("IB", detail="failed to start: x")
    lines = [r.getMessage() for r in caplog.records]
    assert lines == ["ALERT connection_stopped: connection 'IB' stopped: failed to start: x"]


async def test_per_lane_emits_only_when_the_start_respawns_the_halted_workers(
    store: MessageStore,
) -> None:
    # per_lane: a router STOP returns its worker, and the start that respawns it releases the hold.
    # While the workers are alive the hold is live, so the start must resolve nothing.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    sink = _Recording()
    runner = _runner(reg, store, sink, claim_mode="per_lane")
    await runner.start()
    try:
        assert sink.started == ["IB"]
        runner._hold_for_operator("IB", "inbound")
        await runner.restart_inbound("IB", operator=True)
        assert sink.started == ["IB"]  # both workers alive: nothing re-armed, the hold stands
        # The halt: the router worker has returned, as a STOP makes it.
        task = runner._router_workers["IB"]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await runner.restart_inbound("IB", operator=True)
        assert ("inbound", "IB") not in runner._stop_held
        assert sink.started == ["IB", "IB"]
    finally:
        await runner.stop()


class _ClusterNode:
    """Any coordinator but the single-node one: the leader, so intake is not gated off."""

    def is_leader(self) -> bool:
        return True

    def is_clustered(self) -> bool:
        return True


async def test_a_clustered_node_or_unowned_namesake_resolves_nothing(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The alert row is in the store every process shares; another process's causes are invisible.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("SHARED", MLLP(port=0), router="r"))
    reg.add_inbound(build_inbound_connection("ALONE", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    reg.add_outbound(
        OutboundConnection(
            "SHARED", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "out")})
        )
    )
    sink = _Recording()
    runner = _runner(reg, store, sink)
    await runner.start()
    try:
        sink.started.clear()
        # Another engine shard owns the namesake outbound. An inbound with no namesake is not
        # held back by where its bare name would hash.
        monkeypatch.setattr(runner, "_owns_destination", lambda name: False)
        await runner.restart_inbound("SHARED", operator=True)
        await runner.restart_inbound("ALONE", operator=True)
        assert sink.started == ["ALONE"]
        sink.started.clear()
        monkeypatch.undo()
        monkeypatch.setattr(runner, "_coordinator", _ClusterNode())
        await runner.restart_inbound("SHARED", operator=True)
        assert sink.started == []
        monkeypatch.undo()
        await runner.restart_inbound("SHARED", operator=True)
        assert sink.started == ["SHARED"]
    finally:
        await runner.stop()


class _RecordingTransport:
    # The shape tests/test_alert_escalation.py uses.
    name = "webhook"

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.events.append(event)


async def test_a_restart_driven_crash_loop_still_reaches_its_escalation_tier(
    store: MessageStore,
) -> None:
    # Review note 1 on BACKLOG #1741: the inverse resolves the instance every cycle, and a resolve
    # that reset the occurrence count would restart a restart_inbound crash loop at the base tier
    # each time, so an after_count tier is never reached. Each cycle is the per_lane router STOP
    # (hold + the worker returning + its connection_stopped), the rule's restart, and the start's
    # connection_started.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    rule = AlertRule(
        event_type="connection_stopped",
        connection="IB",
        severity=AlertSeverity.WARNING,
        cooldown_seconds=0.001,  # the floor is above 0; each cycle waits it out below
        control_action="restart_inbound",
        escalate=[EscalationTier(after_count=3, severity=AlertSeverity.CRITICAL)],
    )
    pages = _RecordingTransport()
    sink = NotifierAlertSink([pages], rules=[rule], store=store)
    runner = _runner(reg, store, sink, claim_mode="per_lane")
    restarts: list[str] = []
    go = asyncio.Event()  # holds each restart until the cycle has read the open instance

    async def _control(action: str, target: str, *, default_target: bool) -> None:
        assert action == "restart_inbound"
        restarts.append(target)
        await go.wait()
        go.clear()
        await runner.restart_inbound(target)

    sink.set_control_callback(_control)
    sink.start()
    await runner.start()
    try:
        tiers: list[int] = []
        for _ in range(4):
            await asyncio.sleep(0.01)
            runner._hold_for_operator("IB", "inbound")
            task = runner._router_workers["IB"]
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            sink.connection_stopped("IB", detail="router halted on internal error")
            await _settle(sink)
            open_tiers = [
                i.escalation_tier
                for i in await store.list_active_alert_instances(allowed_channels=None)
            ]
            go.set()
            await _settle(sink, sink._control_tasks)
            await _settle(sink)
            assert runner.inbound_running("IB") and await _open(store) == set()
            tiers.extend(open_tiers)
        assert restarts == ["IB"] * 4
        # The tier the durable instance records is the tier the loop has reached.
        assert tiers == [0, 0, 1, 1]
    finally:
        await runner.stop()
        await sink.aclose()
    assert [e["severity"] for e in pages.events] == ["warning", "warning", "critical", "critical"]


async def test_only_the_rules_own_restart_keeps_the_count() -> None:
    # The sink-level contract: a connection_started raised while this sink's restart_inbound of the
    # inbound runs keeps the escalation count; any other start, a restart_outbound and every other
    # inverse reset it, as ADR 0133 D1 says. The suspend entry is dropped either way.
    class _Resolve:
        async def resolve_alert_instances_for(self, **_kw: object) -> int:
            return 0

    sink = NotifierAlertSink([], store=_Resolve())  # type: ignore[arg-type]
    seen: list[int | None] = []

    async def _control(action: str, target: str, *, default_target: bool) -> None:
        sink.connection_started(target)  # the start inside the restart
        seen.append(sink._occurrences.get("connection_stopped:IB"))

    for action, kept in (("restart_inbound", 5), ("restart_outbound", None)):
        sink._occurrences["connection_stopped:IB"] = 5
        sink._suspended["connection_stopped:IB"] = 1e12
        await sink._run_control(_control, action, "IB", default_target=True)
        assert seen.pop() == kept
        assert "connection_stopped:IB" not in sink._suspended
    assert sink._restarting == {}
    # A start nobody's rule asked for: an operator start after a fix.
    sink.connection_started("IB")
    assert "connection_stopped:IB" not in sink._occurrences
    sink._occurrences["connection_error:OB"] = 5
    sink.connection_restored("OB")
    assert "connection_error:OB" not in sink._occurrences
    await _settle(sink)
