# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Alert-triggered connection-control action (#144, ADR 0128): a firing rule dispatches an injected
async control callback (restart_inbound/restart_outbound) off the delivery worker, never-raise,
throttled with the notification, independent of transport suppression, and whitelisted at config-load."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import AlertRule
from messagefoundry.pipeline.alert_sinks import AlertRuleSet, NotifierAlertSink


class _Control:
    """Records (action, target) calls; can be told to raise (never-raise contract)."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail = fail

    async def __call__(self, action: str, target: str) -> None:
        self.calls.append((action, target))
        if self.fail:
            raise RuntimeError("restart rejected")


class _RecordingTransport:
    def __init__(self, name: str = "webhook") -> None:
        self.name = name
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.events.append(event)


async def _drain(sink: NotifierAlertSink) -> None:
    sink.start()
    await asyncio.sleep(0)
    await sink.aclose()
    for _ in range(10):
        if not sink._control_tasks:
            break
        await asyncio.gather(*list(sink._control_tasks), return_exceptions=True)
        await asyncio.sleep(0)


# --- model validation --------------------------------------------------------


def test_control_action_whitelist() -> None:
    AlertRule(control_action="restart_inbound")  # ok
    AlertRule(control_action="restart_outbound")  # ok
    with pytest.raises(ValidationError, match="control_action must be one of"):
        AlertRule(control_action="delete_everything")
    assert AlertRule().control_action is None  # default = notify only


def test_decide_carries_control() -> None:
    rules = AlertRuleSet(
        [
            AlertRule(
                event_type="connection_stopped",
                control_action="restart_outbound",
                control_target="OB_OTHER",
            )
        ]
    )
    d = rules.decide({"type": "connection_stopped", "connection": "OB_X"})
    assert d.control_action == "restart_outbound"
    assert d.control_target == "OB_OTHER"


# --- dispatch behaviour ------------------------------------------------------


async def test_control_fires_with_default_target() -> None:
    cb = _Control()
    t = _RecordingTransport()
    rule = AlertRule(event_type="connection_stopped", control_action="restart_outbound")
    sink = NotifierAlertSink([t], rules=[rule])
    sink.set_control_callback(cb)
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    # default target = the event's own connection; the notification still fires alongside.
    assert cb.calls == [("restart_outbound", "OB_X")]
    assert len(t.events) == 1


async def test_control_explicit_target() -> None:
    cb = _Control()
    rule = AlertRule(
        event_type="queue_buildup", control_action="restart_inbound", control_target="IB_FEED"
    )
    sink = NotifierAlertSink([_RecordingTransport()], rules=[rule])
    sink.set_control_callback(cb)
    sink.queue_buildup("OB_X", depth=1, oldest_age_seconds=1.0)
    await _drain(sink)
    assert cb.calls == [("restart_inbound", "IB_FEED")]


async def test_control_throttled_with_notification() -> None:
    cb = _Control()
    rule = AlertRule(event_type="connection_stopped", control_action="restart_outbound")
    sink = NotifierAlertSink([_RecordingTransport()], realert_seconds=10_000.0, rules=[rule])
    sink.set_control_callback(cb)
    sink.connection_stopped("OB_X", detail="boom")
    sink.connection_stopped("OB_X", detail="boom again")  # throttled → no second restart
    await _drain(sink)
    assert cb.calls == [("restart_outbound", "OB_X")]  # exactly once per cooldown


async def test_control_fires_even_when_notification_suppressed() -> None:
    # transports=[] = QUIET auto-remediation: restart, no page.
    cb = _Control()
    t = _RecordingTransport()
    rule = AlertRule(
        event_type="connection_stopped", transports=[], control_action="restart_outbound"
    )
    sink = NotifierAlertSink([t], rules=[rule])
    sink.set_control_callback(cb)
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    assert cb.calls == [("restart_outbound", "OB_X")]  # remediated
    assert t.events == []  # but NOT paged (suppressed)


async def test_control_never_raises() -> None:
    # A rejected/hung restart must never break alerting — the sink swallows it.
    cb = _Control(fail=True)
    t = _RecordingTransport()
    rule = AlertRule(event_type="connection_stopped", control_action="restart_outbound")
    sink = NotifierAlertSink([t], rules=[rule])
    sink.set_control_callback(cb)
    sink.connection_stopped("OB_X", detail="boom")  # must not raise
    await _drain(sink)
    assert cb.calls == [("restart_outbound", "OB_X")]  # it ran; the raise was swallowed
    assert len(t.events) == 1  # the notification still fired


async def test_no_callback_is_noop() -> None:
    # A control_action rule with no callback wired must not crash — it logs + no-ops.
    rule = AlertRule(event_type="connection_stopped", control_action="restart_outbound")
    sink = NotifierAlertSink([_RecordingTransport()], rules=[rule])
    sink.connection_stopped("OB_X", detail="boom")  # no callback set → no-op
    await _drain(sink)
    assert sink._control_tasks == set()


async def test_no_control_action_never_dispatches() -> None:
    # A plain rule (no control_action) never touches the callback — byte-identical to pre-#144.
    cb = _Control()
    sink = NotifierAlertSink([_RecordingTransport()])
    sink.set_control_callback(cb)
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    assert cb.calls == []


async def test_callback_maps_action_to_runner_restart() -> None:
    # Mirror the api/app.py wiring: the injected callback routes the action string to the matching
    # RegistryRunner restart method. Proves the contract the lifespan relies on.
    class _FakeRunner:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        async def restart_inbound(self, name: str) -> None:
            self.calls.append(("restart_inbound", name))

        async def restart_outbound(self, name: str) -> None:
            self.calls.append(("restart_outbound", name))

    rr = _FakeRunner()

    async def _alert_control(action: str, target: str) -> None:
        if action == "restart_inbound":
            await rr.restart_inbound(target)
        elif action == "restart_outbound":
            await rr.restart_outbound(target)

    rule = AlertRule(event_type="connection_stopped", control_action="restart_outbound")
    sink = NotifierAlertSink([_RecordingTransport()], rules=[rule])
    sink.set_control_callback(_alert_control)
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    assert rr.calls == [("restart_outbound", "OB_X")]
