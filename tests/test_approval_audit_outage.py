# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2255: the approval gate during an audit or store outage.

Engine PR 1607's review named five findings in the gate's audit contract that #1940 did not carry.
This file pins the three that are code: a refusal's own audit row, and a status write the store
refuses, answer a mapped status rather than a raw 500 (finding 3), and every audit row the gate
loses raises the ``audit_write_failed`` alert (finding 4).

The gate runs over a real SQLite store. Only the faults are injected, by a wrapper that fails the
named audit actions or status writes with the error a full disk gives.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.auth.permissions import Permission
from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    AlertRule,
    ApprovalsSettings,
)
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.store.store import MessageStore
from tests._pending_approval_store_contract import _resolve, _StandingStore

_REQUESTER_ID = "outage-requester-id"
_APPROVER_ID = "outage-approver-id"
_FAULT = "disk I/O error"


class _Faulty(_StandingStore):
    """The real store, failing the named audit actions and the status writes to the named states."""

    def __init__(
        self,
        store: Any,
        *,
        audit_fails: tuple[str, ...] = (),
        decide_fails: tuple[str, ...] = (),
        requester_gone: bool = False,
    ) -> None:
        super().__init__(store)
        self.audit_fails = audit_fails
        self.decide_fails = decide_fails
        self.requester_gone = requester_gone

    async def record_audit(self, action: str, **kw: Any) -> None:
        if action in self.audit_fails:
            raise sqlite3.OperationalError(_FAULT)
        await self._store.record_audit(action, **kw)

    async def decide_pending_approval(self, approval_id: str, **kw: Any) -> bool:
        if kw["status"] in self.decide_fails:
            raise sqlite3.OperationalError(_FAULT)
        return bool(await self._store.decide_pending_approval(approval_id, **kw))

    async def get_user(self, user_id: str) -> Any:
        if self.requester_gone and user_id == _REQUESTER_ID:
            return None
        return await super().get_user(user_id)


class _Sink(LoggingAlertSink):
    def __init__(self) -> None:
        self.lost: list[tuple[str, str]] = []
        self.too_early: list[str] = []
        self.stale: list[str] = []

    def audit_write_failed(self, name: str, *, action: str) -> None:
        self.lost.append((name, action))

    def approval_too_early(self, name: str, *, operation: str) -> None:
        self.too_early.append(name)

    def approval_stale_requester(self, approval_id: str, *, operation: str, reason: str) -> None:
        self.stale.append(reason)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "outage.db")
    yield s
    await s.close()


def _gate(
    store: Any, sink: _Sink, *, min_dwell: float = 0.0, runs: list[str] | None = None
) -> ApprovalGate:
    settings = ApprovalsSettings(
        enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=min_dwell
    )
    gate = ApprovalGate(store, settings, resolve_identity=_resolve, alert_sink=sink)

    async def _execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        if runs is not None:
            runs.append("ran")
        return {"requeued": 0}

    gate.register("dead_letter_replay", "op", _execute, permission=Permission.MESSAGES_REPLAY)
    return gate


async def _request(gate: ApprovalGate) -> str:
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=_REQUESTER_ID
    )
    assert approval_id is not None
    return approval_id


async def _status(store: MessageStore, approval_id: str) -> str:
    row = await store.get_pending_approval(approval_id)
    assert row is not None
    return str(row["status"])


# --- finding 3: refusals and status writes answer a mapped status, never a raw 500 ---------------


async def test_a_too_early_refusal_whose_audit_row_fails_still_answers_409(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """Before the fix the failed approval.too_early write raised out of approve as a raw 500, and
    the too-early alert never fired."""
    sink = _Sink()
    runs: list[str] = []
    gate = _gate(
        _Faulty(store, audit_fails=("approval.too_early",)), sink, min_dwell=60.0, runs=runs
    )
    approval_id = await _request(gate)
    with (
        caplog.at_level(logging.ERROR, logger="messagefoundry.api.approvals"),
        pytest.raises(ApprovalError) as caught,
    ):
        await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
    assert caught.value.status == 409 and caught.value.headers is not None
    assert runs == [] and await _status(store, approval_id) == "pending"
    assert sink.too_early == [f"approval:{approval_id}"]
    assert sink.lost == [(f"approval:{approval_id}", "approval.too_early")]
    lost = [r for r in caplog.records if "approval.too_early audit row failed" in r.getMessage()]
    assert len(lost) == 1 and lost[0].levelno == logging.ERROR
    assert approval_id in lost[0].getMessage()  # the lost detail is in the log line


async def test_a_stale_requester_refusal_whose_audit_row_fails_still_answers_409(
    store: MessageStore,
) -> None:
    """Before the fix the failed approval.stale_requester write raised a raw 500 and skipped the
    stale-requester alert, which is the page this refusal exists to raise."""
    sink = _Sink()
    runs: list[str] = []
    gate = _gate(
        _Faulty(store, audit_fails=("approval.stale_requester",), requester_gone=True),
        sink,
        runs=runs,
    )
    approval_id = await _request(gate)
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
    assert caught.value.status == 409
    assert runs == [] and await _status(store, approval_id) == "pending"
    assert sink.stale == ["requester_missing"]
    assert sink.lost == [(f"approval:{approval_id}", "approval.stale_requester")]


async def test_a_claim_the_store_refuses_answers_503_and_runs_nothing(
    store: MessageStore,
) -> None:
    """The claim's status write raising used to escape approve as a raw 500."""
    sink = _Sink()
    runs: list[str] = []
    gate = _gate(_Faulty(store, decide_fails=("executing",)), sink, runs=runs)
    approval_id = await _request(gate)
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
    assert caught.value.status == 503 and "did not run" in caught.value.detail
    assert runs == [] and await _status(store, approval_id) == "pending"
    # The control: the same request releases once the store accepts the claim.
    healthy = _gate(_StandingStore(store), sink, runs=runs)
    await healthy.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
    assert runs == ["ran"] and await _status(store, approval_id) == "approved"


async def test_a_rejection_the_store_refuses_answers_503_and_stays_pending(
    store: MessageStore,
) -> None:
    sink = _Sink()
    gate = _gate(_Faulty(store, decide_fails=("rejected",)), sink)
    approval_id = await _request(gate)
    with pytest.raises(ApprovalError) as caught:
        await gate.reject(approval_id, approver="checker")
    assert caught.value.status == 503
    assert await _status(store, approval_id) == "pending"


async def test_a_rejection_whose_audit_row_fails_still_rejects_and_pages(
    store: MessageStore,
) -> None:
    """The row has moved, so a raw 500 would report a rejection that happened as a failure."""
    sink = _Sink()
    gate = _gate(_Faulty(store, audit_fails=("approval.rejected",)), sink)
    approval_id = await _request(gate)
    out = await gate.reject(approval_id, approver="checker")
    assert out["rejected_by"] == "checker"
    assert await _status(store, approval_id) == "rejected"
    assert sink.lost == [(f"approval:{approval_id}", "approval.rejected")]


async def test_a_resolution_the_store_refuses_answers_503(store: MessageStore) -> None:
    """``_record_resolution``'s status write raising used to be a raw 500."""
    sink = _Sink()
    approval_id = await _request(_gate(store, sink))
    assert await store.decide_pending_approval(
        approval_id, status="executing", approver="releaser", decided_at=1.0
    )
    assert await store.decide_pending_approval(
        approval_id,
        status="interrupted",
        approver="releaser",
        decided_at=2.0,
        from_status="executing",
    )
    gate = _gate(_Faulty(store, decide_fails=("resolved_applied",)), sink)
    with pytest.raises(ApprovalError) as caught:
        await gate.resolve_interrupted(
            approval_id,
            outcome="effects_applied",
            resolver="resolver",
            resolver_user_id="outage-resolver-id",
        )
    assert caught.value.status == 503
    assert await _status(store, approval_id) == "interrupted"


# --- finding 4: every lost audit row pages -------------------------------------------------------


async def test_a_lost_approval_approved_row_pages(store: MessageStore) -> None:
    sink = _Sink()
    runs: list[str] = []
    gate = _gate(_Faulty(store, audit_fails=("approval.approved",)), sink, runs=runs)
    approval_id = await _request(gate)
    await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
    assert runs == ["ran"] and await _status(store, approval_id) == "approved"
    assert sink.lost == [(f"approval:{approval_id}", "approval.approved")]


async def test_a_refused_release_row_pages_as_well_as_answering_503(store: MessageStore) -> None:
    sink = _Sink()
    gate = _gate(_Faulty(store, audit_fails=("approval.release_attempted",)), sink)
    approval_id = await _request(gate)
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
    assert caught.value.status == 503
    assert sink.lost == [(f"approval:{approval_id}", "approval.release_attempted")]


async def test_a_failed_compensation_still_writes_its_audit_row(store: MessageStore) -> None:
    """The compensation's status write and audit row used to share one try, so a failed status
    write also dropped the approval.failed row. It is now attempted on its own, and says the row
    did not move."""
    sink = _Sink()
    settings = ApprovalsSettings(
        enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=0.0
    )
    gate = ApprovalGate(
        _Faulty(store, decide_fails=("failed",)),
        settings,
        resolve_identity=_resolve,
        alert_sink=sink,
    )

    async def _raises(_p: Mapping[str, Any]) -> dict[str, Any]:
        raise RuntimeError("executor exploded")

    gate.register("dead_letter_replay", "op", _raises, permission=Permission.MESSAGES_REPLAY)
    approval_id = await _request(gate)
    with pytest.raises(RuntimeError, match="executor exploded"):
        await gate.approve(approval_id, approver="checker", approver_user_id=_APPROVER_ID)
    rows = await store.list_audit(action="approval.failed")
    assert len(rows) == 1
    assert json.loads(str(rows[0]["detail"]))["compensated"] is False


async def test_the_audit_write_failed_alert_is_routable_and_phi_free() -> None:
    """A name a sink emits but the settings registry lacks is silently un-targetable by a rule."""
    assert "audit_write_failed" in _ALERT_EVENT_TYPES
    assert "audit_write_failed" not in _ALERT_CONTROL_EVENT_TYPES
    AlertRule(event_type="audit_write_failed")  # a rule may target it


async def test_the_notifier_emits_audit_write_failed_keyed_on_the_request() -> None:
    sink = NotifierAlertSink([])
    events: list[dict[str, Any]] = []
    sink._emit = events.append  # type: ignore[method-assign,assignment]
    sink.audit_write_failed("approval:abc", action="approval.approved")
    assert events == [
        {
            "type": "audit_write_failed",
            "connection": "approval:abc",
            "action": "approval.approved",
            "reason": "the approval.approved audit row was not written",
        }
    ]


def test_the_logging_sink_logs_audit_write_failed(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        LoggingAlertSink().audit_write_failed("approval:abc", action="approval.approved")
    assert any(
        "ALERT audit_write_failed" in r.getMessage() and "approval.approved" in r.getMessage()
        for r in caplog.records
    )
