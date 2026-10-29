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
from messagefoundry.pipeline.alerts import START_FAILURE_DETAIL, LoggingAlertSink
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
        assert runner._resolving_starts == set()
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

    async def _control(
        action: str, target: str, *, default_target: bool, resolve_stop: bool = False
    ) -> None:
        assert action == "restart_inbound" and not resolve_stop
        restarts.append(target)
        await runner.restart_inbound(target, resolve_stop=resolve_stop)

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


async def test_only_the_rules_restart_after_its_own_start_failure_resolves() -> None:
    # The sink-level contract: only the restart_inbound a connection_stopped of the same inbound
    # dispatched for that inbound's start failure carries resolve_stop=True. A restart after a halt,
    # or one another alert type drove, does not. The sink itself resolves every connection_started
    # it sees; whether a start raises one is the runner's (RegistryRunner.restart_inbound).
    resolved: list[tuple[object, object]] = []

    class _Resolve:
        async def upsert_alert_instance(self, **_kw: object) -> None:
            return None

        async def resolve_alert_instances_for(self, **kw: object) -> int:
            resolved.append((kw["event_type"], kw["connection"]))
            return 0

    rules = [
        AlertRule(event_type=t, connection="IB", control_action="restart_inbound")
        for t in ("connection_stopped", "queue_buildup")
    ]
    sink = NotifierAlertSink([], rules=rules, store=_Resolve())  # type: ignore[arg-type]
    flags: list[bool] = []

    async def _control(
        action: str, target: str, *, default_target: bool, resolve_stop: bool = False
    ) -> None:
        flags.append(resolve_stop)

    sink.set_control_callback(_control)
    sink.connection_stopped("IB", detail="router halted")
    sink.queue_buildup("IB", depth=10, oldest_age_seconds=1.0)
    await _settle(sink, sink._control_tasks)
    assert flags == [False, False]
    # A start failure is no crash loop: the restart that recovers it resolves. A fresh sink, so
    # the cooldown on the first connection_stopped does not swallow this one.
    other = NotifierAlertSink([], rules=rules)
    other.set_control_callback(_control)
    other.connection_stopped("IB", detail=f"{START_FAILURE_DETAIL} port in use")
    await _settle(other, other._control_tasks)
    assert flags == [False, False, True]

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


async def test_restart_inbound_with_resolve_stop_off_raises_no_start(
    store: MessageStore,
) -> None:
    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    sink = _Recording()
    runner = _runner(reg, store, sink)
    await runner.start()
    try:
        sink.started.clear()
        await runner.restart_inbound("IB", resolve_stop=False)
        assert runner.inbound_running("IB") and sink.started == []
        assert runner._resolving_starts == set()
        # An engine door's restart resolves nothing, and nor does a rule's resolving one once the
        # inbound is no longer recorded failed: the start failure it answered is gone.
        await runner.restart_inbound("IB")
        await runner.restart_inbound("IB", resolve_stop=True)
        assert sink.started == []
        assert runner._resolving_starts == set()
    finally:
        await runner.stop()


async def test_a_rules_resolving_restart_resolves_a_start_failure_still_recorded(
    store: MessageStore, held_port: tuple[int, socket.socket]
) -> None:
    port, blocker = held_port
    sink = _Recording()
    runner = _runner(_registry(port), store, sink)
    await runner.start()
    try:
        assert runner.inbound_failed("SHARED") and sink.started == []
        blocker.close()
        await runner.restart_inbound("SHARED", resolve_stop=True)
        assert runner.inbound_running("SHARED") and sink.started == ["SHARED"]
    finally:
        await runner.stop()


@pytest.mark.parametrize(("control_target", "resolves"), [("IB", True), ("OTHER", False)])
async def test_a_rule_naming_its_own_inbound_resolves_its_start_failure_too(
    control_target: str, resolves: bool
) -> None:
    # A rule that names its own inbound as control_target answers that inbound's start failure as
    # the default target does; one that names another connection resolves nothing, so two rules
    # restarting each other's inbound keep counting.
    rule = AlertRule(
        event_type="connection_stopped",
        connection="IB",
        control_action="restart_inbound",
        control_target=control_target,
    )
    sink = NotifierAlertSink([], rules=[rule])
    calls: list[tuple[str, bool]] = []

    async def _control(
        action: str, target: str, *, default_target: bool, resolve_stop: bool = False
    ) -> None:
        assert default_target is False
        calls.append((target, resolve_stop))

    sink.set_control_callback(_control)
    sink.connection_stopped("IB", detail=f"{START_FAILURE_DETAIL} port in use")
    await _settle(sink, sink._control_tasks)
    assert calls == [(control_target, resolves)]


async def test_an_operator_start_while_the_rules_restart_waits_resolves(
    store: MessageStore,
) -> None:
    # The rule's restart is queued behind the reload lock while another door, holding it, brings
    # the inbound up. An operator's start is a genuine recovery, so the alert resolves; only the
    # start the restart itself makes is skipped. An engine door's start would resolve nothing.
    from types import SimpleNamespace

    from messagefoundry.api.app import _alert_control_action

    reg = Registry()
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=0), router="r"))
    reg.add_router("r", lambda m: [])
    rule = AlertRule(
        event_type="connection_stopped", connection="IB", control_action="restart_inbound"
    )
    sink = NotifierAlertSink([], rules=[rule], store=store)
    runner = _runner(reg, store, sink)
    engine = SimpleNamespace(registry_runner=runner)

    async def _control(action: str, target: str, **kw: Any) -> None:
        await _alert_control_action(engine, action, target, **kw)  # type: ignore[arg-type]

    sink.set_control_callback(_control)
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

    async def _control(
        action: str, target: str, *, default_target: bool, resolve_stop: bool = False
    ) -> None:
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
    # Two connection_stopped rules that restart each other's inbound. Neither restart resolves, so
    # the runner raises no connection_started for it; this pins the sink's second guard, for a
    # connection_started that arrives while such a restart is in flight, as an operator's start
    # can. It must not end a cooldown, or the pair would page and restart at the halt cadence (ADR
    # 0128 section 4).
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
    restarts: list[str] = []

    async def _control(
        action: str, target: str, *, default_target: bool, resolve_stop: bool = False
    ) -> None:
        assert not resolve_stop
        restarts.append(target)
        sink.connection_started(target)

    sink.set_control_callback(_control)
    sink.start()
    try:
        for name in ("IB_A", "IB_B", "IB_A", "IB_B"):
            sink.connection_stopped(name, detail="router halted on internal error")
            await _settle(sink, sink._control_tasks)
        await _settle(sink)
        assert sink._control_starts == {}
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
