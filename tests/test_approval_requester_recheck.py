# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 8.3.2 at the dual-control release (BACKLOG #289, one of the four builds BACKLOG #1154 names).

A held request is released minutes or hours after it was made. The requester's authority can be
withdrawn in between, so ``ApprovalGate.approve`` re-reads it at release. Each withdrawal shape
below must refuse the release, leave the row pending, write an ``approval.stale_requester`` audit
row and raise an ``approval_stale_requester`` alert. The happy path must still execute.

The same file covers the second half of the limb: the directory reconciler's two audited outcomes
now raise alerts from the API-lifespan task.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.app import (
    _alert_reconcile_plan,
    _build_approval_gate,
    _directory_reconciler,
    _requester_identity_resolver,
)
from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.reconcile import ReconcilePlan, SessionRevocation
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import _ALERT_EVENT_TYPES, AlertRule, AlertSeverity
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alert_sinks import AlertRuleSet, NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink

# The provisioning helpers are shared with the gate's own suite rather than copied, so a change to
# what a provisioned operator is (scope grant, rotation clear) lands once.
from tests.test_alert_sinks import _drain, _RecordingTransport
from tests.test_approvals import ON, _add, _service, _token

STALE = "the requester no longer holds the authority"


class _Sink(LoggingAlertSink):
    """Records the three new alert events; everything else falls through to the logging default."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def approval_stale_requester(self, approval_id: str, *, operation: str, reason: str) -> None:
        self.events.append(
            ("approval_stale_requester", approval_id, {"operation": operation, "reason": reason})
        )

    def ad_reconcile_aborted(self, name: str, *, reason: str, probed: int, detail: str) -> None:
        self.events.append(
            ("ad_reconcile_aborted", name, {"reason": reason, "probed": probed, "detail": detail})
        )

    def ad_session_revoked(self, name: str, *, reason: str) -> None:
        self.events.append(("ad_session_revoked", name, {"reason": reason}))


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "recheck.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _client_with_sink(
    engine: Engine, service: AuthService, sink: _Sink
) -> tuple[httpx.AsyncClient, ApprovalGate]:
    """A real app whose gate is rebuilt with a recording sink, through the SAME wiring functions the
    app uses, so the late-bound resolver is exercised rather than stubbed."""
    app = create_app(engine, auth=service, approvals=ON)
    gate = _build_approval_gate(
        engine, ON, resolve_identity=_requester_identity_resolver(app), alert_sink=sink
    )
    app.state.approval_gate = gate
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    return client, gate


async def _hold_replay(
    c: httpx.AsyncClient, headers: dict[str, str], body: dict[str, Any] | None = None
) -> str:
    r = await c.post("/dead-letters/replay", headers=headers, json=body or {})
    assert r.status_code == 202, r.text
    return str(r.json()["approval_id"])


async def _assert_refused(
    engine: Engine, c: httpx.AsyncClient, approval_id: str, sink: _Sink, reason: str
) -> None:
    r = await c.post(f"/approvals/{approval_id}/approve", headers=await _token(c, "checker"))
    assert r.status_code == 409, r.text
    assert STALE in r.json()["detail"]
    # Refused BEFORE the transition: the row is still pending and nothing executed.
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "pending"
    assert await engine.store.list_audit(action="approval.approved") == []
    # The durable record, attributed to the approver who tried.
    rows = await engine.store.list_audit(action="approval.stale_requester")
    assert len(rows) == 1
    assert str(rows[0]["actor"]) == "checker"
    detail = json.loads(str(rows[0]["detail"]))
    assert detail["approval_id"] == approval_id
    assert detail["reason"] == reason
    assert detail["requester"] == "maker"
    # The page.
    assert sink.events == [
        (
            "approval_stale_requester",
            approval_id,
            {"operation": "dead_letter_replay", "reason": reason},
        )
    ]


# --- the refusal cases -----------------------------------------------------------------------


async def test_a_deleted_requester_is_refused(engine: Engine) -> None:
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    await _add(service, "checker", Role.ADMINISTRATOR)
    sink = _Sink()
    c, _ = _client_with_sink(engine, service, sink)
    async with c:
        approval_id = await _hold_replay(c, await _token(c, "maker"))
        await service.delete_user(maker, actor="test")
        await _assert_refused(engine, c, approval_id, sink, "requester_missing")


async def test_a_disabled_requester_is_refused(engine: Engine) -> None:
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    await _add(service, "checker", Role.ADMINISTRATOR)
    sink = _Sink()
    c, _ = _client_with_sink(engine, service, sink)
    async with c:
        approval_id = await _hold_replay(c, await _token(c, "maker"))
        await service.update_user(maker, display_name=None, email=None, disabled=True, actor="test")
        await _assert_refused(engine, c, approval_id, sink, "requester_disabled")


async def test_a_requester_whose_permission_was_revoked_is_refused(engine: Engine) -> None:
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    await _add(service, "checker", Role.ADMINISTRATOR)
    sink = _Sink()
    c, _ = _client_with_sink(engine, service, sink)
    async with c:
        approval_id = await _hold_replay(c, await _token(c, "maker"))
        # Demoted to a role without messages:replay between the request and the release.
        await service.set_roles(maker, [Role.VIEWER.value], actor="test")
        identity = await service.identity_for_user_id(maker)
        assert identity is not None and not identity.has(Permission.MESSAGES_REPLAY)
        await _assert_refused(engine, c, approval_id, sink, "requester_lacks_permission")


async def test_a_requester_whose_channel_scope_was_narrowed_is_refused(engine: Engine) -> None:
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    await _add(service, "checker", Role.ADMINISTRATOR)
    sink = _Sink()
    c, _ = _client_with_sink(engine, service, sink)
    async with c:
        approval_id = await _hold_replay(c, await _token(c, "maker"), {"channel_id": "IB_ACME_ADT"})
        # The permission survives; the scope that let the requester target this channel does not.
        await service.set_channel_scope(maker, ["IB_OTHER_ADT"], actor="test")
        identity = await service.identity_for_user_id(maker)
        assert identity is not None and identity.has(Permission.MESSAGES_REPLAY)
        await _assert_refused(engine, c, approval_id, sink, "requester_out_of_scope")


# --- the happy path, and the fail-closed default -----------------------------------------------


async def test_a_requester_still_in_good_standing_is_released(engine: Engine) -> None:
    """The positive control for the four refusals above: the same wiring, with nothing withdrawn,
    releases and executes. Without it a gate that refused everything would pass them all."""
    service = await _service(engine)
    await _add(service, "maker", Role.OPERATOR)
    await _add(service, "checker", Role.ADMINISTRATOR)
    sink = _Sink()
    c, _ = _client_with_sink(engine, service, sink)
    async with c:
        approval_id = await _hold_replay(c, await _token(c, "maker"), {"channel_id": "IB_ACME_ADT"})
        r = await c.post(f"/approvals/{approval_id}/approve", headers=await _token(c, "checker"))
        assert r.status_code == 200, r.text
        assert r.json()["result"] == {"requeued": 0}
    assert sink.events == []
    assert await engine.store.list_audit(action="approval.stale_requester") == []


async def test_a_gate_with_no_resolver_refuses_rather_than_trusting(engine: Engine) -> None:
    """A gate built without a way to re-read the requester must not fall back to executing."""
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    sink = _Sink()
    gate = ApprovalGate(engine.store, ON, alert_sink=sink)
    ran: list[Mapping[str, Any]] = []

    async def _record(p: Mapping[str, Any]) -> dict[str, Any]:
        ran.append(p)
        return {}

    gate.register("dead_letter_replay", "replay", _record, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker
    )
    assert approval_id is not None
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert caught.value.status == 409
    assert ran == []
    assert sink.events[0][2]["reason"] == "requester_unverifiable"


async def test_the_live_purge_registration_requires_an_unscoped_requester(engine: Engine) -> None:
    """The purge registration carries the route's scope rule, not only its permission. Read off the
    gate the app actually builds, so a registration that drops ``in_scope`` reds here."""
    service = await _service(engine)
    scoped = await _add(service, "scoped", Role.OPERATOR)
    await service.set_channel_scope(scoped, ["IB_ACME_ADT"], actor="test")
    app = create_app(engine, auth=service, approvals=ON)
    gate: ApprovalGate = app.state.approval_gate
    identity = await service.identity_for_user_id(scoped)
    assert identity is not None and identity.has(Permission.MESSAGES_PURGE)
    op = gate._ops["connection_purge"]
    assert op.permission is Permission.MESSAGES_PURGE
    assert op.in_scope is not None and op.in_scope(identity, {"name": "OB_X"}) is False
    unscoped = await service.identity_for_user_id(await _add(service, "wide", Role.OPERATOR))
    assert unscoped is not None and op.in_scope(unscoped, {"name": "OB_X"}) is True
    assert gate._ops["config_reload"].permission is Permission.CONFIG_DEPLOY


# --- the directory reconciler's alerts ---------------------------------------------------------


class _FakeAuth:
    def __init__(self, plan: ReconcilePlan, alert: str | None = None) -> None:
        self._plan = plan
        self.directory_reconcile_alert = alert
        self.passes = 0

    async def reconcile_directory_sessions(self) -> ReconcilePlan:
        self.passes += 1
        return self._plan


def test_a_breaker_trip_raises_the_aborted_alert() -> None:
    sink = _Sink()
    plan = ReconcilePlan(probed=12, aborted="mass_revoke_breaker")
    _alert_reconcile_plan(plan, _FakeAuth(plan, "breaker TRIPPED"), sink)  # type: ignore[arg-type]
    assert sink.events == [
        (
            "ad_reconcile_aborted",
            "directory-reconciler",
            {"reason": "mass_revoke_breaker", "probed": 12, "detail": "breaker TRIPPED"},
        )
    ]


def test_a_directory_outage_raises_nothing() -> None:
    """Audited as auth.ad_reconcile_skipped, not aborted: the accounts are fine, so nobody is paged."""
    sink = _Sink()
    plan = ReconcilePlan(probed=3, unavailable=3, aborted="directory_unavailable")
    _alert_reconcile_plan(plan, _FakeAuth(plan), sink)  # type: ignore[arg-type]
    assert sink.events == []


def test_each_revocation_raises_its_own_alert() -> None:
    sink = _Sink()
    plan = ReconcilePlan(
        revocations=(
            SessionRevocation("u1", "alice", reason="directory_absent"),
            SessionRevocation("u2", "bob", reason="roles_changed", role_ids=("viewer",)),
        ),
        probed=10,
    )
    _alert_reconcile_plan(plan, _FakeAuth(plan), sink)  # type: ignore[arg-type]
    assert sink.events == [
        ("ad_session_revoked", "alice", {"reason": "directory_absent"}),
        ("ad_session_revoked", "bob", {"reason": "roles_changed"}),
    ]


async def test_the_lifespan_reconciler_task_raises_the_alerts() -> None:
    """The loop itself hands each finished pass to the alerting, not only the helper in isolation."""
    sink = _Sink()
    plan = ReconcilePlan(
        revocations=(SessionRevocation("u1", "alice", reason="directory_absent"),), probed=1
    )
    auth = _FakeAuth(plan)
    task = asyncio.create_task(_directory_reconciler(auth, 0.001, sink))  # type: ignore[arg-type]
    try:
        for _ in range(500):
            if sink.events:
                break
            await asyncio.sleep(0.005)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert auth.passes >= 1
    assert sink.events[0] == ("ad_session_revoked", "alice", {"reason": "directory_absent"})


# --- the three event types are real, routable alert types --------------------------------------


@pytest.mark.parametrize(
    "event_type", ["approval_stale_requester", "ad_reconcile_aborted", "ad_session_revoked"]
)
def test_the_new_event_types_are_rule_targetable(event_type: str) -> None:
    # A name emitted by a sink but missing from _ALERT_EVENT_TYPES is silently un-targetable,
    # because AlertRule rejects it at config load.
    assert event_type in _ALERT_EVENT_TYPES
    rules = AlertRuleSet([AlertRule(event_type=event_type, severity=AlertSeverity.CRITICAL)])
    assert rules.decide({"type": event_type, "connection": "x"}).severity == "critical"
    assert rules.decide({"type": "connection_stopped", "connection": "x"}).severity == "warning"


async def test_the_notifier_carries_each_event_with_no_params_or_secrets() -> None:
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t])
    sink.approval_stale_requester("a1", operation="dead_letter_replay", reason="requester_disabled")
    sink.ad_reconcile_aborted(
        "directory-reconciler", reason="mass_revoke_breaker", probed=9, detail="breaker TRIPPED"
    )
    sink.ad_session_revoked("alice", reason="directory_absent")
    await _drain(sink)
    by_type = {e["type"]: e for e in t.events}
    assert set(by_type) == {
        "approval_stale_requester",
        "ad_reconcile_aborted",
        "ad_session_revoked",
    }
    stale = by_type["approval_stale_requester"]
    assert stale["connection"] == "a1" and stale["reason"] == "requester_disabled"
    # The captured params and the requester's name stay in the store and the audit log, not the page.
    assert not any(k in stale for k in ("params", "requester", "password", "token"))
    assert by_type["ad_reconcile_aborted"]["probed"] == 9
    assert by_type["ad_session_revoked"]["connection"] == "alice"
