# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Alerting rules engine (ADR 0014): rule matching, severity tagging, per-rule transport routing,
suppression, per-rule cooldown, the unconfigured-transport guard, and AlertRule model validation."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import AlertRule, AlertSeverity, AlertsSettings
from messagefoundry.pipeline.alert_sinks import (
    AlertRuleSet,
    NotifierAlertSink,
    notifier_from_settings,
)


class _RecordingTransport:
    def __init__(self, name: str) -> None:
        self.name = name
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any]) -> None:
        self.events.append(event)


async def _drain(sink: NotifierAlertSink) -> None:
    sink.start()
    await asyncio.sleep(0)
    await sink.aclose()


# --- AlertRuleSet.decide (pure matching) -------------------------------------


def test_no_rules_is_default_decision() -> None:
    d = AlertRuleSet([]).decide({"type": "connection_stopped", "connection": "OB_X"})
    assert d.severity == "warning"
    assert d.transports is None  # all transports
    assert d.cooldown_seconds is None  # global throttle


def test_event_type_and_glob_match() -> None:
    rules = AlertRuleSet(
        [
            AlertRule(
                event_type="connection_stopped", connection="OB_*", severity=AlertSeverity.CRITICAL
            ),
        ]
    )
    assert (
        rules.decide({"type": "connection_stopped", "connection": "OB_ACME"}).severity == "critical"
    )
    # wrong event type → no match → default
    assert rules.decide({"type": "queue_buildup", "connection": "OB_ACME"}).severity == "warning"
    # glob miss → default
    assert (
        rules.decide({"type": "connection_stopped", "connection": "IB_ACME"}).severity == "warning"
    )


def test_any_event_type_matches_all() -> None:
    rules = AlertRuleSet(
        [AlertRule(connection="OB_X", severity=AlertSeverity.INFO)]
    )  # event_type "any"
    for etype in ("connection_stopped", "queue_buildup", "storage_threshold"):
        assert rules.decide({"type": etype, "connection": "OB_X"}).severity == "info"


def test_depth_threshold_only_matches_queue_buildup_over_depth() -> None:
    rules = AlertRuleSet(
        [AlertRule(event_type="queue_buildup", min_depth=100, severity=AlertSeverity.CRITICAL)]
    )
    assert (
        rules.decide({"type": "queue_buildup", "connection": "OB_X", "depth": 500}).severity
        == "critical"
    )
    # under the depth threshold → no match
    assert (
        rules.decide({"type": "queue_buildup", "connection": "OB_X", "depth": 5}).severity
        == "warning"
    )


def test_oldest_seconds_threshold() -> None:
    # severity=CRITICAL gives the rule a non-default outcome so match vs no-match is distinguishable
    # (an all-default rule's decision is byte-identical to the no-match default — see decide()).
    rules = AlertRuleSet(
        [
            AlertRule(
                event_type="queue_buildup",
                min_oldest_seconds=300.0,
                severity=AlertSeverity.CRITICAL,
            )
        ]
    )
    over = {"type": "queue_buildup", "connection": "OB_X", "depth": 1, "oldest_age_seconds": 600.0}
    under = {"type": "queue_buildup", "connection": "OB_X", "depth": 1, "oldest_age_seconds": 10.0}
    assert rules.decide(over).severity == "critical"  # at/over the age threshold → match
    assert rules.decide(under).severity == "warning"  # below → no match → default


def test_oldest_seconds_zero_boundary_matches() -> None:
    # min_oldest_seconds=0.0 is valid (ge=0, unlike min_depth's ge=1) and an age of exactly 0.0
    # matches (0.0 < 0.0 is False, so the guard doesn't reject it).
    rules = AlertRuleSet(
        [
            AlertRule(
                event_type="queue_buildup", min_oldest_seconds=0.0, severity=AlertSeverity.CRITICAL
            )
        ]
    )
    e = {"type": "queue_buildup", "connection": "OB_X", "depth": 1, "oldest_age_seconds": 0.0}
    assert rules.decide(e).severity == "critical"


def test_depth_and_oldest_are_conjunctive() -> None:
    # Both thresholds on one rule are AND-combined — an event must clear BOTH to match (the AlertRule
    # docstring's "all conditions must hold"; every match condition on a rule narrows, never widens).
    rules = AlertRuleSet(
        [
            AlertRule(
                event_type="queue_buildup",
                min_depth=100,
                min_oldest_seconds=300.0,
                severity=AlertSeverity.CRITICAL,
            )
        ]
    )
    base = {"type": "queue_buildup", "connection": "OB_X"}
    assert rules.decide({**base, "depth": 500, "oldest_age_seconds": 600.0}).severity == "critical"
    assert (
        rules.decide({**base, "depth": 500, "oldest_age_seconds": 10.0}).severity == "warning"
    )  # age short
    assert (
        rules.decide({**base, "depth": 5, "oldest_age_seconds": 600.0}).severity == "warning"
    )  # depth short


def test_threshold_rule_does_not_apply_to_non_queue_buildup() -> None:
    # A depth/age threshold on an event_type="any" rule must NOT match a non-queue_buildup event
    # (you can't be "over depth" on a stopped/storage event) — it falls through to the default.
    depth_rule = AlertRuleSet([AlertRule(min_depth=100, severity=AlertSeverity.CRITICAL)])
    age_rule = AlertRuleSet([AlertRule(min_oldest_seconds=10.0, severity=AlertSeverity.CRITICAL)])
    for rules in (depth_rule, age_rule):
        assert (
            rules.decide({"type": "storage_threshold", "connection": "/db"}).severity == "warning"
        )
        assert (
            rules.decide({"type": "connection_stopped", "connection": "OB_X"}).severity == "warning"
        )


def test_connection_glob_is_case_sensitive() -> None:
    # fnmatchcase, not fnmatch — a regression to case-insensitive matching (the Windows fnmatch
    # default) would silently broaden which connections a rule catches; pin it.
    rules = AlertRuleSet([AlertRule(connection="OB_*", severity=AlertSeverity.CRITICAL)])
    assert (
        rules.decide({"type": "connection_stopped", "connection": "OB_ACME"}).severity == "critical"
    )
    assert (
        rules.decide({"type": "connection_stopped", "connection": "ob_acme"}).severity == "warning"
    )


def test_later_rule_matches_after_earlier_glob_and_type_miss() -> None:
    # First rule misses on BOTH event_type and glob; a broader second rule then decides — proves the
    # fall-through is condition-agnostic, not just depth-driven (as in test_first_matching_rule_wins).
    rules = AlertRuleSet(
        [
            AlertRule(
                event_type="queue_buildup",
                connection="OB_CRITICAL_*",
                severity=AlertSeverity.CRITICAL,
            ),
            AlertRule(connection="OB_*", severity=AlertSeverity.INFO),
        ]
    )
    assert rules.decide({"type": "connection_stopped", "connection": "OB_OTHER"}).severity == "info"


def test_first_matching_rule_wins() -> None:
    rules = AlertRuleSet(
        [
            AlertRule(event_type="queue_buildup", min_depth=1000, severity=AlertSeverity.CRITICAL),
            AlertRule(event_type="queue_buildup", severity=AlertSeverity.INFO),
        ]
    )
    assert (
        rules.decide({"type": "queue_buildup", "connection": "OB_X", "depth": 5000}).severity
        == "critical"
    )
    assert (
        rules.decide({"type": "queue_buildup", "connection": "OB_X", "depth": 5}).severity == "info"
    )


# --- NotifierAlertSink with rules --------------------------------------------


async def test_severity_is_tagged_on_the_event() -> None:
    t = _RecordingTransport("webhook")
    rule = AlertRule(event_type="connection_stopped", severity=AlertSeverity.CRITICAL)
    sink = NotifierAlertSink([t], rules=[rule])
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    assert t.events[0]["severity"] == "critical"
    assert "_transports" not in t.events[0]  # internal routing key is popped before send


async def test_rule_routes_to_a_transport_subset() -> None:
    web, email = _RecordingTransport("webhook"), _RecordingTransport("email")
    rule = AlertRule(event_type="queue_buildup", transports=["webhook"])  # webhook only
    sink = NotifierAlertSink([web, email], rules=[rule])
    sink.queue_buildup("OB_X", depth=1, oldest_age_seconds=1.0)
    await _drain(sink)
    assert len(web.events) == 1 and len(email.events) == 0


async def test_empty_transports_suppresses() -> None:
    t = _RecordingTransport("webhook")
    rule = AlertRule(event_type="queue_buildup", connection="OB_NOISY", transports=[])  # suppress
    sink = NotifierAlertSink([t], rules=[rule])
    sink.queue_buildup("OB_NOISY", depth=1, oldest_age_seconds=1.0)  # suppressed
    sink.queue_buildup("OB_OTHER", depth=1, oldest_age_seconds=1.0)  # no rule → default → fires
    await _drain(sink)
    assert [e["connection"] for e in t.events] == ["OB_OTHER"]


async def test_rule_cooldown_overrides_global() -> None:
    t = _RecordingTransport("webhook")
    rule = AlertRule(event_type="queue_buildup", cooldown_seconds=10_000.0)
    sink = NotifierAlertSink([t], realert_seconds=0.0, rules=[rule])  # global = no throttle
    sink.queue_buildup("OB_X", depth=1, oldest_age_seconds=1.0)
    sink.queue_buildup("OB_X", depth=2, oldest_age_seconds=2.0)  # throttled by the rule's cooldown
    await _drain(sink)
    assert len(t.events) == 1


async def test_unmatched_event_still_fires_all_transports() -> None:
    # Adding a rule must never silently silence an event it doesn't name.
    web, email = _RecordingTransport("webhook"), _RecordingTransport("email")
    rule = AlertRule(event_type="connection_stopped", transports=["webhook"])
    sink = NotifierAlertSink([web, email], rules=[rule])
    sink.queue_buildup("OB_X", depth=1, oldest_age_seconds=1.0)  # no rule matches → default = all
    await _drain(sink)
    assert len(web.events) == 1 and len(email.events) == 1


# --- notifier_from_settings --------------------------------------------------


def test_factory_passes_rules() -> None:
    settings = AlertsSettings(
        webhook_url="https://hooks.example/x",
        rules=[AlertRule(event_type="connection_stopped", severity=AlertSeverity.CRITICAL)],
    )
    sink = notifier_from_settings(settings)
    assert sink is not None
    d = sink._rules.decide({"type": "connection_stopped", "connection": "OB_X"})
    assert d.severity == "critical"


def test_factory_rejects_rule_to_unconfigured_transport() -> None:
    # email isn't configured, but a rule routes to it → fail loud at config time.
    settings = AlertsSettings(
        webhook_url="https://hooks.example/x",
        rules=[AlertRule(event_type="queue_buildup", transports=["email"])],
    )
    with pytest.raises(ValueError, match="unconfigured transport"):
        notifier_from_settings(settings)


# --- AlertRule model validation ----------------------------------------------


def test_rule_rejects_unknown_event_type() -> None:
    with pytest.raises(ValidationError, match="event_type"):
        AlertRule(event_type="exploded")


def test_rule_rejects_unknown_transport() -> None:
    with pytest.raises(ValidationError, match="transports must be a subset"):
        AlertRule(transports=["pager"])


def test_rule_rejects_bad_severity_and_bounds() -> None:
    with pytest.raises(ValidationError):
        AlertRule(severity="loud")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        AlertRule(min_depth=0)  # must be >= 1
    with pytest.raises(ValidationError):
        AlertRule(cooldown_seconds=0)  # must be > 0
    with pytest.raises(ValidationError):
        AlertRule(extra_field="x")  # type: ignore[call-arg]  # extra="forbid"
