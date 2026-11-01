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
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry.api.app import _alert_control_action
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
from messagefoundry.pipeline.sharding import owner_shard_of_destination
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
    # same name must leave that alert open, and so must an operator-style pause, which is what a
    # #122 halt's pause of the outbound looks like.
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
        assert sink.started == []  # an engine start() resolves nothing
        runner._hold_for_operator("SHARED", "outbound")
        await runner.restart_inbound("SHARED", operator=True)
        assert runner.inbound_running("SHARED")
        assert sink.started == []
        runner._release_operator_hold("SHARED", "outbound")
        await runner.stop_outbound("SHARED")
        await runner.restart_inbound("SHARED", operator=True)
        assert sink.started == []
        await runner.start_outbound("SHARED")
        await runner.restart_inbound("SHARED", operator=True)
        assert sink.started == ["SHARED"]
        # A build that failed as the outbound left the DR park is a cause.
        runner._dr_unbuilt["SHARED"] = True
        await runner.restart_inbound("SHARED", operator=True)
        assert sink.started == ["SHARED"]
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


async def test_neither_a_reload_nor_its_rollback_resolves_a_bind_failure(
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

        # A reload is an engine door, as start() is (the Lander's hold on PR 2603): neither a
        # rolled-back nor a committed one resolves, so the alert stays open as it does on main
        # until an operator starts or restarts the inbound.
        monkeypatch.setattr(runner, "_reconcile_outbounds", _boom)
        with pytest.raises(RuntimeError, match="step 3 failed"):
            await runner.reload(_registry(port))
        assert not runner.inbound_running("SHARED")
        assert sink.started == []
        monkeypatch.undo()
        await runner.reload(_registry(port))
        assert runner.inbound_running("SHARED")
        assert sink.started == []
        await runner.restart_inbound("SHARED", operator=True)
        assert sink.started == ["SHARED"]
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
        assert sink.started == []
        runner._hold_for_operator("IB", "inbound")
        await runner.restart_inbound("IB", operator=True)
        assert sink.started == []  # both workers alive: nothing re-armed, the hold stands
        # The halt: the router worker has returned, as a STOP makes it.
        task = runner._router_workers["IB"]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await runner.restart_inbound("IB", operator=True)
        assert ("inbound", "IB") not in runner._stop_held
        assert sink.started == ["IB"]
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
        # Another engine shard owns the bare name as an outbound lane. That holds back an inbound
        # with no namesake in this registry too: one a reload dropped here can still STOP there.
        monkeypatch.setattr(runner, "_owns_destination", lambda name: False)
        await runner.restart_inbound("SHARED", operator=True)
        await runner.restart_inbound("ALONE", operator=True)
        assert sink.started == []
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
    # BACKLOG #1741: the start inside the restart a connection_stopped rule dispatched for its own
    # inbound resolves nothing, so a rule-driven crash loop behaves as it did before the inverse
    # existed: the instance stays open, its count climbs to the after_count tier, and a suspend
    # holds across cycles. Each cycle is the per_lane router STOP (hold + the worker returning + its
    # connection_stopped) and the rule's restart, whose start raises no connection_started.
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

    async def _control(action: str, target: str, *, default_target: bool) -> None:
        assert action == "restart_inbound"
        restarts.append(target)
        await runner.restart_inbound(target)

    async def _cycle() -> int:
        await asyncio.sleep(0.01)
        runner._hold_for_operator("IB", "inbound")
        task = runner._router_workers["IB"]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        sink.connection_stopped("IB", detail="router halted on internal error")
        await _settle(sink, sink._control_tasks)
        await _settle(sink)
        assert runner.inbound_running("IB")
        # The restart's own start resolved nothing: one open instance, counting every cycle.
        (inst,) = await store.list_active_alert_instances(allowed_channels=None)
        assert (inst.event_type, inst.connection) == ("connection_stopped", "IB")
        return int(inst.escalation_tier)

    sink.set_control_callback(_control)
    sink.start()
    await runner.start()
    try:
        tiers = [await _cycle() for _ in range(4)]
        assert restarts == ["IB"] * 4
        # The tier the durable instance records is the tier the loop has reached.
        assert tiers == [0, 0, 1, 1]
        assert sink._occurrences["connection_stopped:IB"] == 4
        # A muted crash loop stays muted: the restart's start keeps the suspend entry.
        until = time.time() + 3600
        sink.suspend("connection_stopped", "IB", until=until)
        for _ in range(2):
            await _cycle()
            assert sink._suspended.get("connection_stopped:IB") == until
        assert restarts == ["IB"] * 6
        # An operator start nobody's rule asked for still resolves it, and drops the count.
        await runner.restart_inbound("IB", operator=True)
        await _settle(sink)
        assert await _open(store) == set()
        assert "connection_stopped:IB" not in sink._occurrences
        assert "connection_stopped:IB" not in sink._suspended
    finally:
        try:
            await runner.stop()
        finally:
            await sink.aclose()
    # Two muted cycles paged nothing.
    assert [e["severity"] for e in pages.events] == ["warning", "warning", "critical", "critical"]


async def test_a_connection_started_always_resolves_and_drops_the_count() -> None:
    # The sink resolves every connection_started it sees; whether a start raises one is the
    # runner's (only an operator's start or restart, AlertSink.connection_started).
    resolved: list[tuple[object, object]] = []

    class _Resolve:
        async def upsert_alert_instance(self, **_kw: object) -> None:
            return None

        async def resolve_alert_instances_for(self, **kw: object) -> int:
            resolved.append((kw["event_type"], kw["connection"]))
            return 0

    sink = NotifierAlertSink([], store=_Resolve())  # type: ignore[arg-type]
    sink.connection_stopped("IB", detail="router halted")
    assert sink._occurrences["connection_stopped:IB"] == 1
    # A connection_started reaching the sink always resolves, dropping the count (ADR 0133 D1).
    sink.connection_started("IB")
    assert "connection_stopped:IB" not in sink._occurrences
    sink._occurrences["connection_error:OB"] = 5
    sink.connection_restored("OB")
    assert "connection_error:OB" not in sink._occurrences
    await _settle(sink)
    assert resolved == [("connection_stopped", "IB"), ("connection_error", "OB")]


async def test_a_bare_inbound_start_never_resolves_a_prefixed_stand_in() -> None:
    # connection_stopped is also raised under stand-in keys no connection name can hold. An inbound
    # start of the same bare name resolves only the bare-name instance.
    resolved: list[object] = []

    class _Resolve:
        async def upsert_alert_instance(self, **_kw: object) -> None:
            return None

        async def resolve_alert_instances_for(self, **kw: object) -> int:
            resolved.append(kw["connection"])
            return 0

    sink = NotifierAlertSink([], store=_Resolve())  # type: ignore[arg-type]
    for stand_in in ("reference:IB", "fhir_lookup:IB", "cluster:transform-state"):
        sink.connection_stopped(stand_in, detail="failed")
    sink.connection_started("IB")
    await _settle(sink)
    assert resolved == ["IB"]
    assert {"connection_stopped:reference:IB", "connection_stopped:fhir_lookup:IB"} <= set(
        sink._occurrences
    )


async def test_a_non_operator_restart_raises_no_start_even_after_a_start_failure(
    store: MessageStore, held_port: tuple[int, socket.socket]
) -> None:
    # An alert rule's restart, or any other engine door's, resolves nothing, even when it is the
    # restart that recovers the inbound's recorded start failure (BACKLOG #1741).
    port, blocker = held_port
    sink = _Recording()
    runner = _runner(_registry(port), store, sink)
    await runner.start()
    try:
        assert runner.inbound_failed("SHARED") and sink.started == []
        blocker.close()
        await runner.restart_inbound("SHARED")
        assert runner.inbound_running("SHARED") and runner.inbound_failed("SHARED") is None
        assert sink.started == []
    finally:
        await runner.stop()


def _engine_control(runner: RegistryRunner) -> Any:
    """The control callback ``create_managed_app`` wires, over a bare runner."""
    engine = SimpleNamespace(registry_runner=runner)

    async def _control(action: str, target: str, **kw: Any) -> None:
        await _alert_control_action(engine, action, target, **kw)  # type: ignore[arg-type]

    return _control


@pytest.mark.parametrize("cooldown", [0.001, 3600.0])
async def test_a_rule_restart_after_a_start_failure_keeps_the_instance_open_and_counting(
    store: MessageStore, cooldown: float
) -> None:
    # A start failure a connection_stopped rule answers with restart_inbound: the restart brings
    # the inbound up and resolves nothing, so a flapping bind keeps ONE open instance whose count
    # climbs to its after_count tier, and inside the cooldown a recurrence stays throttled on that
    # same instance, as on main. When a rule's restart could resolve, the count reset to 1 every
    # cycle and a throttled recurrence opened a fresh instance that was never paged.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    rule = AlertRule(
        event_type="connection_stopped",
        connection="IB",
        severity=AlertSeverity.WARNING,
        cooldown_seconds=cooldown,
        control_action="restart_inbound",
        escalate=[EscalationTier(after_count=3, severity=AlertSeverity.CRITICAL)],
    )
    pages = _RecordingTransport()
    sink = NotifierAlertSink([pages], rules=[rule], store=store)
    runner = _runner(reg, store, sink)
    sink.set_control_callback(_engine_control(runner))
    sink.start()
    await runner.start()
    try:
        ids: set[int] = set()
        counts: list[int] = []
        tiers: list[int] = []
        for _ in range(4):
            await asyncio.sleep(0.01)  # outlasts the short cooldown
            # The bind failure start() records: the inbound is recorded failed, then alerted.
            runner._record_failed("IB", OSError("port in use"), kind="inbound")
            await _settle(sink, sink._control_tasks)
            await _settle(sink)
            (inst,) = await store.list_active_alert_instances(allowed_channels=None)
            ids.add(inst.id)
            counts.append(int(inst.count))
            tiers.append(int(inst.escalation_tier))
        assert runner.inbound_running("IB")
        # The durable instance reaches its tier whether or not the cooldown throttles the pages.
        assert len(ids) == 1 and counts == [1, 2, 3, 4] and tiers == [0, 0, 1, 1]
        if cooldown < 1:
            assert runner.inbound_failed("IB") is None  # each restart recovered the start failure
    finally:
        try:
            await runner.stop()
        finally:
            await sink.aclose()
    expected = ["warning", "warning", "critical", "critical"] if cooldown < 1 else ["warning"]
    assert [e["severity"] for e in pages.events] == expected


async def test_an_operator_restart_during_a_rule_restart_ends_the_cooldown(
    store: MessageStore,
) -> None:
    # A rule's restart is in flight when an operator restarts the inbound. The operator's resolve
    # fully resets the instance, cooldown included, so the next stop is a new incident that pages.
    # When an in-flight rule restart kept the cooldown, that stop was never paged.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    rule = AlertRule(
        event_type="connection_stopped",
        connection="IB",
        cooldown_seconds=3600.0,
        control_action="restart_inbound",
    )
    pages = _RecordingTransport()
    sink = NotifierAlertSink([pages], rules=[rule], store=store)
    runner = _runner(reg, store, sink)
    gate = asyncio.Event()
    inner = _engine_control(runner)

    async def _control(action: str, target: str, **kw: Any) -> None:
        await gate.wait()  # the rule's restart is in flight until the gate opens
        await inner(action, target, **kw)

    sink.set_control_callback(_control)
    sink.start()
    await runner.start()
    try:
        sink.connection_stopped("IB", detail="router halted on internal error")
        for _ in range(5):
            await asyncio.sleep(0)
        assert sink._control_tasks  # in flight
        await runner.restart_inbound("IB", operator=True)
        await _settle(sink)
        assert await _open(store) == set()
        sink.connection_stopped("IB", detail="router halted on internal error")  # a new incident
        gate.set()
        await _settle(sink, sink._control_tasks)
        await _settle(sink)
        assert await _open(store) == {("connection_stopped", "IB")}
    finally:
        try:
            await runner.stop()
        finally:
            await sink.aclose()
    assert len(pages.events) == 2


async def test_an_operator_start_of_a_listening_inbound_resolves(store: MessageStore) -> None:
    # An open connection_stopped whose cause is gone while the inbound is still listening: the
    # operator's Start finds it up and resolves it. An engine door's start of it does not. On
    # an earlier cut the Start returned before the emit, so nothing could clear the instance.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    sink = NotifierAlertSink([], store=store)
    runner = _runner(reg, store, sink)
    await runner.start()
    try:
        sink.connection_stopped("IB", detail="router halted on internal error")
        await _settle(sink)
        await runner.start_inbound("IB")
        await _settle(sink)
        assert await _open(store) == {("connection_stopped", "IB")}
        await runner.start_inbound("IB", operator=True)
        await _settle(sink)
        assert runner.inbound_running("IB")
        assert await _open(store) == set()
        # A STOP's live hold still holds back the Start of a listening inbound.
        sink.connection_stopped("IB", detail="router halted on internal error")
        runner._hold_for_operator("IB", "inbound")
        await runner.start_inbound("IB", operator=True)
        await _settle(sink)
        assert await _open(store) == {("connection_stopped", "IB")}
    finally:
        await runner.stop()


async def test_an_operator_start_while_the_rules_restart_waits_resolves(
    store: MessageStore,
) -> None:
    # The rule's restart is queued behind the reload lock while an operator's start, holding it,
    # brings the inbound up. That start resolves the alert; the restart's own start resolves
    # nothing. An engine door's start would resolve nothing.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    rule = AlertRule(
        event_type="connection_stopped", connection="IB", control_action="restart_inbound"
    )
    sink = NotifierAlertSink([], rules=[rule], store=store)
    runner = _runner(reg, store, sink)
    sink.set_control_callback(_engine_control(runner))
    await runner.start()
    try:
        await _settle(sink)
        async with runner._reload_lock:
            await runner._stop_inbound_unsafe("IB")
            sink.connection_stopped("IB", detail="router halted on internal error")
            for _ in range(5):
                await asyncio.sleep(0)  # the restart is now waiting for the lock
            assert sink._control_tasks
            await runner._resolving_start("IB", resolve=True)  # start_inbound(operator=True)
        await _settle(sink, sink._control_tasks)
        await _settle(sink)
        assert runner.inbound_running("IB")
        assert await _open(store) == set()
    finally:
        await runner.stop()


async def test_a_queued_rule_restart_whose_start_fails_records_and_alerts(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The rule's restart waits on the reload lock while an operator's start resolves the alert.
    # The restart then stops the healthy inbound, and its start fails with an error that is not a
    # refused CA. The inbound must read failed, with a new open connection_stopped instance: on an
    # earlier cut only a WARNING was logged, so the stopped inbound had no record and no alert.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    rule = AlertRule(
        event_type="connection_stopped", connection="IB", control_action="restart_inbound"
    )
    sink = NotifierAlertSink([], rules=[rule], store=store)
    runner = _runner(reg, store, sink)
    sink.set_control_callback(_engine_control(runner))

    async def _bind_fails(name: str) -> None:
        raise OSError("cannot bind: address in use")

    await runner.start()
    try:
        await _settle(sink)
        async with runner._reload_lock:
            await runner._stop_inbound_unsafe("IB")
            sink.connection_stopped("IB", detail="router halted on internal error")
            for _ in range(5):
                await asyncio.sleep(0)  # the restart is now waiting for the lock
            assert sink._control_tasks
            await runner._resolving_start("IB", resolve=True)  # start_inbound(operator=True)
            await _settle(sink)
            assert await _open(store) == set()
            monkeypatch.setattr(runner, "_start_inbound_unsafe", _bind_fails)
        await _settle(sink, sink._control_tasks)
        await _settle(sink)
        assert not runner.inbound_running("IB")
        assert runner.inbound_failed("IB")
        (inst,) = await store.list_active_alert_instances(allowed_channels=None)
        assert (inst.event_type, inst.connection) == ("connection_stopped", "IB")
        # One record, one alert: the rule this alert fires again finds the record and stays quiet.
        assert int(inst.count) == 1
    finally:
        await runner.stop()


async def test_a_rule_restart_of_a_name_this_runner_does_not_hold_records_nothing(
    store: MessageStore,
) -> None:
    # Another engine shard's inbound, or a typo in control_target: the restart is refused as
    # before, and records no failure and raises no alert for an inbound that never failed here.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    sink = NotifierAlertSink([], store=store)
    runner = _runner(reg, store, sink)
    await runner.start()
    try:
        with pytest.raises(KeyError):
            await runner.restart_inbound("IB_OTHER_SHARD")
        await _settle(sink)
        assert runner.inbound_failed("IB_OTHER_SHARD") is None
        assert await _open(store) == set()
    finally:
        await runner.stop()


@pytest.mark.parametrize("park", ["deployed", "auto_start"])
async def test_a_deliberately_parked_outbound_namesake_does_not_block_the_resolve(
    store: MessageStore, held_port: tuple[int, socket.socket], tmp_path: Path, park: str
) -> None:
    # A deployed=False or auto_start=False park of the outbound of the same name raises no
    # connection_stopped, so it is no cause, and must not hold the inbound's bind-failure alert open.
    port, blocker = held_port
    reg = _registry(port)
    reg.add_outbound(
        OutboundConnection(
            "SHARED",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "out")}),
            deployed=park != "deployed",
            auto_start=park != "auto_start",
        )
    )
    sink = NotifierAlertSink([], store=store)
    runner = _runner(reg, store, sink)
    await runner.start()
    try:
        assert runner.inbound_failed("SHARED") and not runner.outbound_running("SHARED")
        await _settle(sink)
        assert await _open(store) == {("connection_stopped", "SHARED")}
        blocker.close()
        await runner.start_inbound("SHARED", operator=True)
        assert runner.inbound_running("SHARED")
        await _settle(sink)
        assert await _open(store) == set()
    finally:
        await runner.stop()


async def test_a_stop_after_an_auto_resolve_pages_and_acts_inside_the_cooldown(
    store: MessageStore,
) -> None:
    # A stop that returns after connection_started resolved the last one is a new incident, so it
    # pages and dispatches its rule's restart at once, at the base tier, as a first occurrence
    # does. A repeat while the instance is still open stays throttled for the cooldown, as before.
    rule = AlertRule(
        event_type="connection_stopped",
        connection="IB",
        severity=AlertSeverity.WARNING,
        control_action="restart_inbound",
        control_target="OTHER",  # a restart that makes no start for IB
        escalate=[EscalationTier(after_count=2, severity=AlertSeverity.CRITICAL)],
    )
    pages = _RecordingTransport()
    sink = NotifierAlertSink([pages], realert_seconds=3600.0, rules=[rule], store=store)
    restarts: list[str] = []

    async def _control(action: str, target: str, *, default_target: bool) -> None:
        restarts.append(target)

    sink.set_control_callback(_control)
    sink.start()
    try:
        sink.connection_stopped("IB", detail="router halted on internal error")
        sink.connection_stopped("IB", detail="router halted on internal error")  # still open
        await _settle(sink, sink._control_tasks)
        sink.connection_started("IB")
        sink.connection_stopped("IB", detail="router halted on internal error")  # new incident
        await _settle(sink, sink._control_tasks)
        await _settle(sink)
        assert await _open(store) == {("connection_stopped", "IB")}
    finally:
        await sink.aclose()
    assert restarts == ["OTHER", "OTHER"]
    assert [e["severity"] for e in pages.events] == ["warning", "warning"]


async def test_rules_restarting_each_others_inbound_keep_the_cooldown(
    store: MessageStore,
) -> None:
    # Two connection_stopped rules that restart each other's inbound. No rule restart raises
    # connection_started, so neither ends a cooldown, and the pair stays at one page and one
    # restart per cooldown (ADR 0128 section 4).
    reg = Registry()
    for name in ("IB_A", "IB_B"):
        reg.add_inbound(build_inbound_connection(name, MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    rules = [
        AlertRule(
            event_type="connection_stopped",
            connection=src,
            control_action="restart_inbound",
            control_target=dst,
        )
        for src, dst in (("IB_A", "IB_B"), ("IB_B", "IB_A"))
    ]
    pages = _RecordingTransport()
    sink = NotifierAlertSink([pages], realert_seconds=3600.0, rules=rules, store=store)
    runner = _runner(reg, store, sink)
    inner = _engine_control(runner)
    restarts: list[str] = []

    async def _control(action: str, target: str, **kw: Any) -> None:
        restarts.append(target)
        await inner(action, target, **kw)

    sink.set_control_callback(_control)
    sink.start()
    await runner.start()
    try:
        for name in ("IB_A", "IB_B", "IB_A", "IB_B"):
            sink.connection_stopped(name, detail="router halted on internal error")
            await _settle(sink, sink._control_tasks)
        await _settle(sink)
        assert runner.inbound_running("IB_A") and runner.inbound_running("IB_B")
        assert await _open(store) == {
            ("connection_stopped", "IB_A"),
            ("connection_stopped", "IB_B"),
        }
    finally:
        try:
            await runner.stop()
        finally:
            await sink.aclose()
    assert restarts == ["IB_B", "IB_A"]
    assert [e["connection"] for e in pages.events] == ["IB_A", "IB_B"]


async def test_an_internal_stage_stop_stays_open_across_a_fresh_start_and_a_reload(
    store: MessageStore,
) -> None:
    # The Lander's hold on PR 2603: an engine start() or a committed reload is not an operator's
    # recovery. A fresh process sees none of an earlier run's causes, so a recurring router STOP an
    # earlier run left open keeps its instance and its count, as it does on main. Only an
    # operator's start or restart resolves it.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    # The earlier run: the router halted twice and the alert opened.
    first = NotifierAlertSink([], store=store)
    for _ in range(2):
        first.connection_stopped("IB", detail="router halted on internal error")
    await _settle(first)
    (before,) = await store.list_active_alert_instances(allowed_channels=None)
    # The service restarts: a new sink and runner over the same store.
    sink = NotifierAlertSink([], store=store)
    runner = _runner(reg, store, sink)
    await runner.start()
    try:
        assert runner.inbound_running("IB")
        await _settle(sink)
        assert await _open(store) == {("connection_stopped", "IB")}
        await runner.reload(reg)
        assert runner.inbound_running("IB")
        await _settle(sink)
        # An engine door's start under the lock, as the scheduler's or a rollback's is.
        async with runner._reload_lock:
            await runner._stop_inbound_unsafe("IB")
            await runner._start_inbound_unsafe("IB")
        await _settle(sink)
        (after,) = await store.list_active_alert_instances(allowed_channels=None)
        assert (after.id, after.event_type, after.connection, after.count) == (
            before.id,
            "connection_stopped",
            "IB",
            2,
        )
        await runner.restart_inbound("IB", operator=True)
        await _settle(sink)
        assert await _open(store) == set()
    finally:
        await runner.stop()


def _name_owned_by(owner: str, universe: tuple[str, ...]) -> str:
    for i in range(1000):
        if owner_shard_of_destination(name := f"IB_{i}", universe) == owner:
            return name
    raise AssertionError("no name hashes to the owner")  # pragma: no cover


async def test_a_dropped_outbound_namesake_owned_by_another_engine_shard_keeps_its_stop_open(
    store: MessageStore,
) -> None:
    # A reload dropped the outbound of this name from this engine shard's registry, but its queued
    # rows still drain on the engine shard that owns the lane, whose STOP raised connection_stopped
    # into the shared store. This engine shard cannot see that cause, so an operator start of the inbound
    # of the same name must not resolve it. On an earlier cut the ownership check ran only for an
    # outbound in this registry, so the start resolved the other engine shard's stop.
    universe = ("a", "b")
    name = _name_owned_by("b", universe)
    reg = Registry()
    reg.add_inbound(build_inbound_connection(name, MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    reg.shard_id, reg.all_shard_ids = "a", universe
    sink = NotifierAlertSink([], store=store)
    runner = _runner(reg, store, sink)
    await runner.start()
    try:
        assert name not in runner.registry.outbound and not runner._owns_destination(name)
        sink.connection_stopped(
            name, detail="outbound halted on internal error"
        )  # engine shard b's
        await _settle(sink)
        await runner.start_inbound(name, operator=True)
        assert runner.inbound_running(name)
        await _settle(sink)
        assert await _open(store) == {("connection_stopped", name)}
        assert sink._occurrences[f"connection_stopped:{name}"] == 1
    finally:
        await runner.stop()


@pytest.fixture
def one_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    """One attempt per resolve. These tests pin how a FAILED resolve settles, and since BACKLOG
    #3756 a resolve fails only once its last attempt does; with one, a store call is a resolve."""
    monkeypatch.setattr(NotifierAlertSink, "_INVERSE_RETRY_DELAYS", ())


@pytest.mark.usefixtures("one_attempt")
async def test_a_failed_resolve_leaves_the_count_cooldown_and_suspend_in_place() -> None:
    # connection_started clears the in-memory state at once, so a stop emitted before the write
    # lands pages. When the durable resolve then fails, the row is still open, so the cooldown,
    # count and suspend entry come back, with the in-between stop's count added. On an earlier cut
    # they stayed cleared: memory said resolved while the row stayed open.
    class _FailingResolve:
        async def upsert_alert_instance(self, **_kw: object) -> None:
            return None

        async def resolve_alert_instances_for(self, **_kw: object) -> int:
            raise OSError("store unavailable")

    key = "connection_stopped:IB"
    sink = NotifierAlertSink([], realert_seconds=3600.0, store=_FailingResolve())  # type: ignore[arg-type]
    sink.connection_stopped("IB", detail="router halted")
    sink.connection_stopped("IB", detail="router halted")
    until = time.time() + 3600
    sink.suspend("connection_stopped", "IB", until=until)
    last = sink._last_sent[key]
    sink.connection_started("IB")
    assert key not in sink._occurrences and key not in sink._last_sent
    await _settle(sink)
    assert sink._occurrences[key] == 2
    assert sink._last_sent[key] == last
    assert sink._suspended[key] == until
    # A stop between the clear and the failure bumped the still-open row, so it adds to the count,
    # and the cooldown it set is the newer one.
    sink.connection_started("IB")
    sink.connection_stopped("IB", detail="router halted")
    newer = sink._last_sent[key]
    await _settle(sink)
    assert sink._occurrences[key] == 3
    assert sink._last_sent[key] == newer
    assert sink._suspended[key] == until


class _FlakyResolve:
    """Fails the store calls named in ``fail`` (1-based call order) and lands the rest. Under the
    ``one_attempt`` fixture each call is one resolve."""

    def __init__(self, *fail: int) -> None:
        self.fail = set(fail)
        self.calls = 0

    async def upsert_alert_instance(self, **_kw: object) -> None:
        return None

    async def resolve_alert_instances_for(self, **_kw: object) -> int:
        self.calls += 1
        if self.calls in self.fail:
            raise OSError("store unavailable")
        return 1


def _primed(store: object) -> NotifierAlertSink:
    sink = NotifierAlertSink([], realert_seconds=3600.0, store=store)  # type: ignore[arg-type]
    sink.connection_stopped("IB", detail="router halted")
    sink.connection_stopped("IB", detail="router halted")
    sink.suspend("connection_stopped", "IB", until=time.time() + 3600)
    return sink


@pytest.mark.usefixtures("one_attempt")
async def test_a_failed_resolve_hands_its_state_to_a_later_one_that_lands() -> None:
    # Two operator starts in quick succession: the first resolve fails, the second, queued behind
    # it, closes the row. Nothing comes back, so the next stop is a new incident that pages.
    key = "connection_stopped:IB"
    sink = _primed(_FlakyResolve(1))
    sink.connection_started("IB")
    sink.connection_started("IB")
    await _settle(sink)
    assert key not in sink._occurrences
    assert key not in sink._last_sent
    assert key not in sink._suspended
    assert sink._pending_clears == {}
    # Both fail: the second takes the first's state over and puts it all back.
    sink = _primed(_FlakyResolve(1, 2))
    sink.connection_started("IB")
    sink.connection_started("IB")
    await _settle(sink)
    assert sink._occurrences[key] == 2 and key in sink._last_sent and key in sink._suspended
    assert sink._pending_clears == {}


@pytest.mark.usefixtures("one_attempt")
async def test_an_operator_resolve_or_resume_before_a_failed_resolve_stays_in_force() -> None:
    key = "connection_stopped:IB"
    sink = _primed(_FlakyResolve(1))
    sink.connection_started("IB")
    sink.forget("connection_stopped", "IB")  # the operator resolved it by hand meanwhile
    await _settle(sink)
    assert key not in sink._occurrences and key not in sink._suspended
    sink = _primed(_FlakyResolve(1))
    sink.connection_started("IB")
    sink.resume("connection_stopped", "IB")
    await _settle(sink)
    assert key not in sink._suspended
    assert sink._occurrences[key] == 2


async def test_a_resolve_cancelled_before_it_runs_puts_the_state_back() -> None:
    key = "connection_stopped:IB"
    sink = _primed(_FlakyResolve())
    sink.connection_started("IB")
    for task in list(sink._state_tasks):
        task.cancel()
    await asyncio.gather(*sink._state_tasks, return_exceptions=True)
    await asyncio.sleep(0)
    assert sink._occurrences[key] == 2 and key in sink._last_sent and key in sink._suspended
    assert sink._pending_clears == {}


async def test_a_landed_resolve_settles_earlier_clears_and_drops_an_in_flight_suspend() -> None:
    # The first start's resolve is cancelled before it runs, but only after the second start's
    # resolve has landed and closed the row: nothing comes back. A suspend set while the landed
    # resolve was in flight muted the row it closed, so it goes with it.
    key = "connection_stopped:IB"
    sink = _primed(_FlakyResolve())
    sink.connection_started("IB")
    first = next(iter(sink._state_tasks))
    sink.connection_started("IB")
    cleared = sink._pending_clears[key][0]
    sink.suspend("connection_stopped", "IB", until=time.time() + 3600)
    sink._resolve_settled(key, sink._pending_clears[key][1], landed=True)
    sink._resolve_settled(key, cleared, landed=False)  # the late cancel of the first
    assert key not in sink._occurrences and key not in sink._last_sent
    assert key not in sink._suspended
    assert sink._pending_clears == {}
    first.cancel()
    await asyncio.gather(*sink._state_tasks, return_exceptions=True)
    assert sink._pending_clears == {} and key not in sink._occurrences
