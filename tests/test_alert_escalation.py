# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Alert escalation tiers, schedule-aware rules, and content-triggered alerts (BACKLOG #81, ADR 0133).

Covers: occurrence-driven escalation over the base rule (severity/transports climb by count, persisted
tier), schedule-aware `decide` (a scheduled rule applies only in its window), and the PHI-free
`content_match` event whose re-emit (a transform re-run) folds idempotently into one instance via the
existing (event_type, connection) throttle/dedup — the purity / at-least-once reconciliation.
"""

from __future__ import annotations

import asyncio
import datetime
from datetime import time as dtime
from pathlib import Path
from typing import Any

from messagefoundry.config.models import ActiveWindow, Schedule
from messagefoundry.config.settings import AlertRule, AlertSeverity, EscalationTier
from messagefoundry.pipeline.alert_sinks import AlertRuleSet, NotifierAlertSink
from messagefoundry.store.store import MessageStore


class _RecordingTransport:
    def __init__(self, name: str) -> None:
        self.name = name
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.events.append(event)


async def _drain(sink: NotifierAlertSink) -> None:
    sink.start()
    await asyncio.sleep(0)
    await sink.aclose()


async def _drain_state(sink: NotifierAlertSink) -> None:
    # Let the fire-and-forget state-observer tasks the sink scheduled run to completion.
    for _ in range(10):
        if not sink._state_tasks:
            break
        await asyncio.gather(*list(sink._state_tasks), return_exceptions=True)
        await asyncio.sleep(0)


class _EscStore:
    """Records the (severity, escalation_tier) the sink hands the store per emit (#81)."""

    def __init__(self) -> None:
        self.upserts: list[tuple[str, int]] = []

    async def upsert_alert_instance(
        self,
        *,
        event_type: str,
        connection: str,
        severity: str,
        reason: str | None = None,
        escalation_tier: int = 0,
        now: float | None = None,
    ) -> None:
        self.upserts.append((severity, escalation_tier))

    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = None
    ) -> int:
        return 0

    async def list_active_alert_instances(self, *, limit: int = 200) -> list[Any]:
        return []


# --- AC-1: occurrence-driven escalation --------------------------------------


async def test_escalates_by_occurrence_count() -> None:
    # AC-1: the base rule is warning; once the instance has fired >= 3 times it escalates to critical and
    # routes to the webhook only. The escalated severity + tier are what the transport/store see.
    t = _RecordingTransport("webhook")
    store = _EscStore()
    rule = AlertRule(
        event_type="connection_error",
        connection="*",
        severity=AlertSeverity.WARNING,
        escalate=[
            EscalationTier(after_count=3, severity=AlertSeverity.CRITICAL, transports=["webhook"])
        ],
    )
    sink = NotifierAlertSink([t], realert_seconds=0.0, rules=[rule], store=store)
    for _ in range(4):
        sink.connection_error("OB_X", kind="connection_lost", detail="x")
    await _drain_state(sink)
    await _drain(sink)
    # occurrences 1,2 -> base warning (tier 0); 3,4 -> critical (tier 1)
    assert [e["severity"] for e in t.events] == ["warning", "warning", "critical", "critical"]
    assert store.upserts == [
        ("warning", 0),
        ("warning", 0),
        ("critical", 1),
        ("critical", 1),
    ]


async def test_escalation_highest_satisfied_tier_wins() -> None:
    # Two tiers: the highest one whose after_count is crossed applies (tiers may be given out of order).
    t = _RecordingTransport("webhook")
    rule = AlertRule(
        event_type="queue_buildup",
        connection="*",
        severity=AlertSeverity.INFO,
        escalate=[
            EscalationTier(after_count=5, severity=AlertSeverity.CRITICAL),
            EscalationTier(after_count=2, severity=AlertSeverity.WARNING),
        ],
    )
    sink = NotifierAlertSink([t], realert_seconds=0.0, rules=[rule])
    for _ in range(5):
        sink.queue_buildup("OB_X", depth=1, oldest_age_seconds=1.0)
    await _drain(sink)
    # 1->info, 2..4->warning (tier after_count=2), 5->critical (tier after_count=5)
    assert [e["severity"] for e in t.events] == [
        "info",
        "warning",
        "warning",
        "warning",
        "critical",
    ]


# --- AC-2: schedule-aware decide ---------------------------------------------


def test_schedule_aware_decide() -> None:
    # AC-2: a rule with a Monday 09:00-17:00 UTC window applies only inside it; outside, the event falls to
    # the default decision (warning, all transports).
    sched = Schedule(
        windows=[
            ActiveWindow(days=frozenset({0}), start=dtime(9, 0), end=dtime(17, 0), timezone="UTC")
        ]
    )
    rule = AlertRule(
        event_type="connection_stopped",
        connection="*",
        severity=AlertSeverity.CRITICAL,
        schedule=sched,
    )
    rs = AlertRuleSet([rule])
    event = {"type": "connection_stopped", "connection": "OB_X"}
    # 2024-01-01 is a Monday.
    inside = datetime.datetime(2024, 1, 1, 10, 0, tzinfo=datetime.UTC).timestamp()
    outside = datetime.datetime(2024, 1, 1, 20, 0, tzinfo=datetime.UTC).timestamp()
    assert rs.decide(event, inside).severity == "critical"  # rule matched (in window)
    assert (
        rs.decide(event, outside).severity == "warning"
    )  # default (rule not applied out of window)


def test_content_label_routing() -> None:
    # A rule can route a content_match event by its (non-PHI) label.
    rule = AlertRule(
        event_type="content_match",
        connection="*",
        severity=AlertSeverity.CRITICAL,
        content_label="STAT",
    )
    rs = AlertRuleSet([rule])
    assert rs.decide({"type": "content_match", "connection": "IB_X", "label": "STAT"}).severity == (
        "critical"
    )
    # a different label does not match this rule → default
    assert (
        rs.decide({"type": "content_match", "connection": "IB_X", "label": "routine"}).severity
        == "warning"
    )


# --- AC-3 / AC-4: content-triggered alerts + purity reconciliation -----------


async def test_content_match_event_is_phi_free() -> None:
    # AC-3: content_match carries ONLY connection + label + optional rule id — never a matched field value.
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t])
    sink.content_match("IB_LAB", label="STAT order", rule_id="R1")
    await _drain(sink)
    (e,) = t.events
    assert e["type"] == "content_match" and e["connection"] == "IB_LAB"
    assert e["label"] == "STAT order" and e["rule_id"] == "R1"
    # the whole payload is a CLOSED non-PHI key set — no message body / matched value can be present.
    assert set(e) <= {"type", "connection", "label", "rule_id", "ts", "severity"}


async def test_content_match_reemit_is_idempotent(tmp_path: Path) -> None:
    # AC-4: a transform RE-RUN re-emits content_match for the same (connection); the (event_type,
    # connection) upsert folds it into the ONE open instance (count bumps, no 2nd row) — the purity /
    # at-least-once reconciliation (ADR 0133 D3).
    store = await MessageStore.open(tmp_path / "a.db")
    try:
        sink = NotifierAlertSink([], store=store, realert_seconds=0.0)
        sink.content_match("IB_LAB", label="STAT")
        sink.content_match("IB_LAB", label="STAT")  # the at-least-once re-run
        await _drain_state(sink)
        rows = await store.list_active_alert_instances()
        assert len(rows) == 1
        assert rows[0].event_type == "content_match" and rows[0].count == 2
        assert rows[0].reason == "STAT"  # the non-PHI label, never a matched value
    finally:
        await store.close()
