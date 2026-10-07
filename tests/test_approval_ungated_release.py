# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A held request cannot be released once dual control no longer applies to its operation.

Found by Builder b197-D: ``ApprovalGate.approve`` checked neither ``[approvals].enabled`` nor
whether the operation was still in ``[approvals].operations``. So a request held while dual control
was on could still be released after an operator turned it off, running under a control the
deployment no longer applies. Now the release is refused with 409, an
``approval.no_longer_gated`` audit row says why, and the request stays pending until it is
rejected or expires.

The gate runs over a real SQLite store. Each test holds the request under one gate and tries to
release it under a second gate over the same store, which is what a restart with changed
``[approvals]`` settings gives.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.auth import Role
from messagefoundry.auth.permissions import Permission
from messagefoundry.config.settings import ApprovalsSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.store.store import MessageStore
from tests._pending_approval_store_contract import _REQUESTER_ID, _resolve, _StandingStore

_OP = "dead_letter_replay"
_ON = ApprovalsSettings(enabled=True, operations=[_OP], min_dwell_seconds=0.0)


class _Sink(LoggingAlertSink):
    def __init__(self) -> None:
        self.lost: list[tuple[str, str]] = []

    def audit_write_failed(self, name: str, *, action: str) -> None:
        self.lost.append((name, action))


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "ungated.db")
    yield s
    await s.close()


def _gate(
    store: Any, settings: ApprovalsSettings, runs: list[str], sink: _Sink | None = None
) -> ApprovalGate:
    gate = ApprovalGate(_StandingStore(store), settings, resolve_identity=_resolve, alert_sink=sink)

    async def _execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        runs.append("ran")
        return {"requeued": 0}

    gate.register(_OP, "op", _execute, permission=Permission.MESSAGES_REPLAY)
    return gate


async def _held(store: Any) -> str:
    approval_id = await _gate(store, _ON, []).guard(
        _OP, {}, requester="maker", requester_user_id=_REQUESTER_ID
    )
    assert approval_id is not None
    return approval_id


async def _status(store: MessageStore, approval_id: str) -> str:
    row = await store.get_pending_approval(approval_id)
    assert row is not None
    return str(row["status"])


@pytest.mark.parametrize(
    ("settings", "reason", "says"),
    [
        (
            ApprovalsSettings(enabled=False, operations=[_OP], min_dwell_seconds=0.0),
            "approvals_disabled",
            "[approvals].enabled",
        ),
        (
            ApprovalsSettings(enabled=True, operations=["connection_purge"], min_dwell_seconds=0.0),
            "operation_not_gated",
            "[approvals].operations",
        ),
    ],
    ids=["dual-control-off", "operation-removed"],
)
async def test_a_release_after_dual_control_stops_applying_is_refused(
    store: MessageStore, settings: ApprovalsSettings, reason: str, says: str
) -> None:
    approval_id = await _held(store)
    runs: list[str] = []
    gate = _gate(store, settings, runs)
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert caught.value.status == 409
    # The wording tells the approver why, and what to do instead.
    assert says in caught.value.detail and "Reject it" in caught.value.detail
    assert runs == []
    assert await _status(store, approval_id) == "pending"
    rows = await store.list_audit(action="approval.no_longer_gated")
    assert len(rows) == 1 and str(rows[0]["actor"]) == "checker"
    assert json.loads(str(rows[0]["detail"])) == {
        "approval_id": approval_id,
        "operation": _OP,
        "requester": "maker",
        "reason": reason,
    }
    assert await store.list_audit(action="approval.release_attempted") == []
    # The approver can still clear it: a reject does not depend on the gating.
    await gate.reject(approval_id, approver="checker")
    assert await _status(store, approval_id) == "rejected"


async def test_the_same_request_releases_while_dual_control_still_applies(
    store: MessageStore,
) -> None:
    """The control for the refusal above: same store, same request, settings unchanged."""
    approval_id = await _held(store)
    runs: list[str] = []
    await _gate(store, _ON, runs).approve(
        approval_id, approver="checker", approver_user_id="checker-id"
    )
    assert runs == ["ran"] and await _status(store, approval_id) == "approved"
    assert await store.list_audit(action="approval.no_longer_gated") == []


async def test_a_refusal_whose_audit_row_fails_still_answers_409_and_pages(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    approval_id = await _held(store)
    real = store._append_audit_row

    async def _append(action: str, **kwargs: Any) -> Any:
        if action == "approval.no_longer_gated":
            raise sqlite3.OperationalError("disk I/O error")
        return await real(action, **kwargs)

    monkeypatch.setattr(store, "_append_audit_row", _append)
    sink = _Sink()
    runs: list[str] = []
    gate = _gate(store, ApprovalsSettings(enabled=False), runs, sink)
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert caught.value.status == 409
    assert runs == [] and await _status(store, approval_id) == "pending"
    assert sink.lost == [(f"approval:{approval_id}", "approval.no_longer_gated")]


async def test_the_approve_route_answers_409_after_dual_control_is_turned_off(
    tmp_path: Path,
) -> None:
    """At the route, across what a restart with ``[approvals].enabled = false`` gives: a new app
    over the same store."""
    from tests.test_approvals import ON, _add, _client, _request_replay, _service, _token

    engine = await Engine.create(
        tmp_path / "route.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        service = await _service(engine)
        await _add(service, "op", Role.OPERATOR)
        await _add(service, "approver", Role.ADMINISTRATOR)
        async with _client(engine, service, ON) as c:
            held = await _request_replay(c, await _token(c, "op"))
            assert held.status_code == 202
            approval_id = held.json()["approval_id"]
        async with _client(engine, service, ApprovalsSettings(enabled=False)) as c:
            admin = await _token(c, "approver")
            r = await c.post(f"/approvals/{approval_id}/approve", headers=admin)
            assert r.status_code == 409
            assert "[approvals].enabled" in r.json()["detail"]
            rejected = await c.post(f"/approvals/{approval_id}/reject", headers=admin)
            assert rejected.status_code == 200
        assert len(await engine.store.list_audit(action="approval.no_longer_gated")) == 1
    finally:
        await engine.stop()
