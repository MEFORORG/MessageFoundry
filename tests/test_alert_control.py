# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Alert-triggered connection-control action (#144, ADR 0128): a firing rule dispatches an injected
async control callback (restart_inbound/restart_outbound) off the delivery worker, never-raise,
throttled with the notification, independent of transport suppression, and whitelisted at config-load."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    AlertRule,
)
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
    AlertRule(event_type="connection_stopped", control_action="restart_inbound")  # ok
    AlertRule(event_type="connection_stopped", control_action="restart_outbound")  # ok
    with pytest.raises(ValidationError, match="control_action must be one of"):
        AlertRule(event_type="connection_stopped", control_action="delete_everything")
    assert AlertRule().control_action is None  # default = notify only


# --- BACKLOG #1898: control_action only on a connection-scoped event type -----------------------

_NON_CONNECTION_TYPES = sorted(_ALERT_EVENT_TYPES - _ALERT_CONTROL_EVENT_TYPES)


def test_the_control_types_are_rule_targetable_and_exclude_content_match() -> None:
    assert _ALERT_CONTROL_EVENT_TYPES <= _ALERT_EVENT_TYPES
    # No engine caller yet, and once a Handler calls it, message content would pick the restart.
    assert "content_match" not in _ALERT_CONTROL_EVENT_TYPES
    # The refused population is real, so the parametrized refusal below is not vacuous.
    assert len(_NON_CONNECTION_TYPES) >= 20


def test_any_plus_control_action_is_refused() -> None:
    with pytest.raises(ValidationError, match="connection-scoped event_type"):
        AlertRule(control_action="restart_outbound")  # event_type defaults to "any"
    with pytest.raises(ValidationError, match="connection-scoped event_type"):
        AlertRule(event_type="any", connection="OB_*", control_action="restart_inbound")


@pytest.mark.parametrize("event_type", _NON_CONNECTION_TYPES)
def test_a_non_connection_type_plus_control_action_is_refused(event_type: str) -> None:
    AlertRule(event_type=event_type)  # the type itself is fine without a control action
    with pytest.raises(ValidationError, match="connection-scoped event_type"):
        AlertRule(event_type=event_type, control_action="restart_outbound")


@pytest.mark.parametrize("event_type", sorted(_ALERT_CONTROL_EVENT_TYPES))
def test_a_connection_type_plus_control_action_is_accepted(event_type: str) -> None:
    rule = AlertRule(event_type=event_type, control_action="restart_inbound")
    assert rule.control_action == "restart_inbound"


def test_the_refusal_names_the_rule_and_the_type_and_not_the_target() -> None:
    with pytest.raises(ValidationError) as caught:
        AlertRule(
            id="page-admins",
            event_type="administrator_granted",
            control_action="restart_outbound",
            control_target="OB_SECRETIVE_NAME",
        )
    # The refusal's own message. pydantic's rendering appends the raw input, which no validator
    # message controls, and the rule fields it echoes are operator config, not secrets.
    [error] = caught.value.errors()
    text = str(error["msg"])
    assert "'page-admins'" in text
    assert "'administrator_granted'" in text
    assert "OB_SECRETIVE_NAME" not in text


def test_control_target_needs_an_action_and_a_connection_name() -> None:
    AlertRule(
        event_type="connection_stopped", control_action="restart_inbound", control_target="IB_FEED"
    )  # ok
    with pytest.raises(ValidationError, match="control_target without a control_action"):
        AlertRule(event_type="connection_stopped", control_target="IB_FEED")
    # "" would fall back to the event's own key at dispatch; the others can only fail there.
    for bad in ("", "user:admin", "IB FEED", "../IB_FEED"):
        with pytest.raises(ValidationError, match="not a connection name"):
            AlertRule(
                event_type="connection_stopped",
                control_action="restart_inbound",
                control_target=bad,
            )


def _unvalidated_catch_all(**kw: Any) -> AlertRule:
    # A rule built past the load validator, as a caller outside AlertRule's loader could.
    return AlertRule.model_construct(event_type="any", connection="*", **kw)


async def test_the_dispatch_guard_skips_a_stand_in_event_with_control_target_set() -> None:
    cb = _Control()
    t = _RecordingTransport()
    rule = _unvalidated_catch_all(control_action="restart_outbound", control_target="OB_REAL")
    sink = NotifierAlertSink([t], rules=[rule])
    sink.set_control_callback(cb)
    # storage_threshold puts a DB path in `connection`; a cert label fits the name grammar.
    sink.storage_threshold("/var/lib/mefor.db", size_bytes=2, limit_bytes=1)
    sink.cert_expiry("OB_REAL", path="/etc/ob.pem", not_after="2026-10-01", days_remaining=1)
    await _drain(sink)
    assert cb.calls == []  # nothing restarted, not the target and not the stand-in
    assert len(t.events) == 2  # the notifications still fire


async def test_the_dispatch_guard_still_restarts_on_a_connection_event() -> None:
    # Control arm for the guard above: the same unvalidated catch-all rule, a connection event.
    cb = _Control()
    rule = _unvalidated_catch_all(control_action="restart_outbound", control_target=None)
    sink = NotifierAlertSink([_RecordingTransport()], rules=[rule])
    sink.set_control_callback(cb)
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    assert cb.calls == [("restart_outbound", "OB_X")]


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
