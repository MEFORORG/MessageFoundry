# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""WP-L3-04: dual-control (maker-checker) approval for high-value actions (ASVS 2.3.5).

The replay endpoint stands in for a gated high-value action (it needs no configured graph). With
``[approvals]`` off it executes inline; on it is held for a *distinct* second approver who releases it.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import json
import logging
import sqlite3
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType, RetryPolicy
from messagefoundry.config.settings import ApprovalsSettings, AuthSettings, EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import OutboxStatus
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
# min_dwell_seconds=0: these tests request and release within milliseconds, which the shipped 2.0 s
# floor (ASVS 2.4.2) would refuse. The floor has its own suite, tests/test_approval_min_dwell.py.
ON = ApprovalsSettings(
    enabled=True, operations=["dead_letter_replay", "connection_purge"], min_dwell_seconds=0.0
)
OFF = ApprovalsSettings(enabled=False)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "approvals.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    # Approvals is a step-up admin flow, not an MFA test: pin require_mfa=False so the BACKLOG #187
    # secure default (require_mfa now ON) doesn't 403 the request before the approval path is exercised.
    service = AuthService(
        engine.store, AuthSettings(admin_write_min_interval_seconds=0, require_mfa=False)
    )
    await service.initialize()
    return service


def _client(
    engine: Engine, service: AuthService, approvals: ApprovalsSettings
) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, approvals=approvals)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> str:
    """Provision a usable local operator; returns the immutable ``users.id`` (BACKLOG #1540 keys the
    self-approval refusal on it, so the rename tests below need it)."""
    uid = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(uid)  # clear forced first-login rotation (WP-L3-12)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    return uid


async def _token(c: httpx.AsyncClient, username: str) -> dict[str, str]:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return {"Authorization": f"Bearer {r.json()['token']}"}


async def _request_replay(c: httpx.AsyncClient, headers: dict[str, str]) -> httpx.Response:
    return await c.post("/dead-letters/replay", headers=headers, json={})


async def test_disabled_executes_inline(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service, OFF) as c:
        r = await _request_replay(c, await _token(c, "op"))
        assert r.status_code == 200 and "requeued" in r.json()  # ran inline, not held


async def test_high_value_action_is_held_pending(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    async with _client(engine, service, ON) as c:
        r = await _request_replay(c, await _token(c, "op"))
        assert r.status_code == 202
        body = r.json()
        assert body["status"] == "pending_approval" and body["operation"] == "dead_letter_replay"
        # the approver sees it in their queue, attributed to the requester
        admin = await _token(c, "approver")
        pending = (await c.get("/approvals", headers=admin)).json()["approvals"]
        assert any(a["id"] == body["approval_id"] and a["requester"] == "op" for a in pending)


async def test_requester_cannot_approve_their_own_request(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "admin1", Role.ADMINISTRATOR)  # admins can both request and approve
    await _add(service, "admin2", Role.ADMINISTRATOR)
    async with _client(engine, service, ON) as c:
        a1 = await _token(c, "admin1")
        approval_id = (await _request_replay(c, a1)).json()["approval_id"]
        # dual-control: the requester is not a valid second approver
        assert (await c.post(f"/approvals/{approval_id}/approve", headers=a1)).status_code == 403
        # ...but a distinct approver can release it, and the captured op executes
        a2 = await _token(c, "admin2")
        ok = await c.post(f"/approvals/{approval_id}/approve", headers=a2)
        assert ok.status_code == 200
        outcome = ok.json()
        assert outcome["requested_by"] == "admin1" and outcome["approved_by"] == "admin2"
        assert outcome["result"] == {"requeued": 0}  # executed on release
        # a second approval of the same (now decided) request is refused
        assert (await c.post(f"/approvals/{approval_id}/approve", headers=a2)).status_code == 409


async def test_release_executes_and_audits_both_identities(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    async with _client(engine, service, ON) as c:
        approval_id = (await _request_replay(c, await _token(c, "op"))).json()["approval_id"]
        admin = await _token(c, "approver")
        assert (await c.post(f"/approvals/{approval_id}/approve", headers=admin)).status_code == 200
    audited = {(str(r["action"]), str(r["actor"])) for r in await engine.store.list_audit(limit=50)}
    assert ("approval.requested", "op") in audited  # the maker
    assert ("approval.approved", "approver") in audited  # the distinct checker


async def test_reject_does_not_execute(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    async with _client(engine, service, ON) as c:
        approval_id = (await _request_replay(c, await _token(c, "op"))).json()["approval_id"]
        admin = await _token(c, "approver")
        rej = await c.post(f"/approvals/{approval_id}/reject", headers=admin)
        assert rej.status_code == 200 and rej.json()["rejected_by"] == "approver"
        # a rejected request can no longer be approved and is gone from the queue
        assert (await c.post(f"/approvals/{approval_id}/approve", headers=admin)).status_code == 409
        assert (await c.get("/approvals", headers=admin)).json()["approvals"] == []
    audited = {(str(r["action"]), str(r["actor"])) for r in await engine.store.list_audit(limit=50)}
    assert ("approval.rejected", "approver") in audited


async def test_viewer_cannot_use_approval_routes(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "viewer", Role.VIEWER)  # holds no approvals:approve
    async with _client(engine, service, ON) as c:
        vw = await _token(c, "viewer")
        assert (await c.get("/approvals", headers=vw)).status_code == 403
        assert (await c.post("/approvals/anything/approve", headers=vw)).status_code == 403


async def test_expired_or_unknown_requests_are_refused(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "approver", Role.ADMINISTRATOR)
    # forge a pending request whose expiry is already in the past
    await engine.store.create_pending_approval(
        approval_id="cafebabecafebabecafebabecafebabe",
        operation="dead_letter_replay",
        params="{}",
        requester="op",
        requester_user_id="op-id",
        requested_at=1.0,
        expires_at=2.0,
    )
    async with _client(engine, service, ON) as c:
        admin = await _token(c, "approver")
        expired = await c.post("/approvals/cafebabecafebabecafebabecafebabe/approve", headers=admin)
        assert expired.status_code == 409 and "expired" in expired.json()["detail"]
        # WELL-FORMED but absent -- a malformed id is a 422 at validation, before the route.
        assert (
            await c.post("/approvals/feedfacefeedfacefeedfacefeedface/approve", headers=admin)
        ).status_code == 404
        # an expired request is also absent from the pending queue
        assert (await c.get("/approvals", headers=admin)).json()["approvals"] == []


async def test_purge_dual_control_skips_running_outbound(engine: Engine, tmp_path: Path) -> None:
    # Findings #1/#4/#11 — the LOAD-BEARING dual-control guard. A purge held while the outbound was
    # stopped, then RELEASED after the operator re-started the outbound, must cancel NOTHING: the
    # require-quiesced re-check lives inside the `_purge` approval executor (ApprovalGate.approve runs it
    # directly and has already claimed the row as 'executing', so it returns a fail-closed SKIP rather
    # than raising, which would record a retryable precondition miss as a failed operation).
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    inbox = tmp_path / "in"
    inbox.mkdir()
    (tmp_path / "out").mkdir()
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "out")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB", m))
    engine.add_registry(reg)
    await engine.start()
    rr = engine.registry_runner
    assert rr is not None

    # Stop OB (idle lane → quiesces), then queue a delivery it retains PENDING while paused.
    await rr.stop_outbound("OB")
    for _ in range(200):
        if rr.outbound_quiesced("OB"):
            break
        await asyncio.sleep(0.02)
    assert rr.outbound_quiesced("OB") is True
    mid = await engine.store.enqueue_message(
        channel_id="in1", raw=ADT, deliveries=[("OB", ADT)], source_type="file"
    )

    async with _client(engine, service, ON) as c:
        op = await _token(c, "op")
        held = await c.post("/connections/OB/purge", headers=op)
        assert (
            held.status_code == 202
        )  # dual-control holds it (OB was quiesced, so it passed the 409)
        approval_id = held.json()["approval_id"]
        # The operator RE-STARTS the outbound during the approval window (the race the guard closes).
        await rr.start_outbound("OB")
        assert rr.outbound_quiesced("OB") is False
        admin = await _token(c, "approver")
        ok = await c.post(f"/approvals/{approval_id}/approve", headers=admin)
        assert ok.status_code == 200
        # The executor re-checked quiescence at release and REFUSED — a skip result, not a cancel.
        assert ok.json()["result"] == {"cancelled": 0, "skipped": "outbound running"}

    # Nothing was cancelled: the message's outbox row is never in the CANCELLED state (queue intact).
    statuses = {r["status"] for r in await engine.store.outbox_for(mid)}
    assert OutboxStatus.CANCELLED.value not in statuses
    # The distinct approver's release is still audited (the skip lands in approval.approved).
    audited = {(str(r["action"]), str(r["actor"])) for r in await engine.store.list_audit(limit=50)}
    assert ("approval.approved", "approver") in audited


def test_settings_validator_rejects_unknown_operation() -> None:
    with pytest.raises(ValueError, match="unknown operation"):
        ApprovalsSettings(operations=["not_a_real_op"])


# --- BACKLOG #1646: the released replay writes its own dead_letter_replay row ------------------
#
# approval.approved attributes both identities and the count, but the executor wrote NO
# `dead_letter_replay` row -- so an auditor filtering on the ACTION NAME saw only the ungated
# replays, where _record_reload_audit was given exactly that parity for config_reload. The queries
# below filter on the action name deliberately: that IS the auditor's query this row is about.


async def _dead_letter(engine: Engine) -> None:
    """Seed one message and fail its only delivery, so a replay has something to re-queue.

    LOAD-BEARING. `_request_replay` on its own posts against an engine holding no dead letters, so
    `requeued` is 0, the guarded audit write never runs, and an assertion on top of it would pass
    whether or not the executor writes the row."""
    await engine.store.enqueue_message(
        channel_id="ch1", raw=ADT, deliveries=[("archive", ADT)], source_type="file"
    )
    item = (await engine.store.claim_ready())[0]
    await engine.store.mark_failed(item.id, "boom", RetryPolicy(max_attempts=1))


async def _release_a_replay(engine: Engine) -> httpx.Response:
    """Provision a requester and a DISTINCT approver, hold a replay, and return the release."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    async with _client(engine, service, ON) as c:
        approval_id = (await _request_replay(c, await _token(c, "op"))).json()["approval_id"]
        admin = await _token(c, "approver")
        return await c.post(f"/approvals/{approval_id}/approve", headers=admin)


async def test_released_replay_is_audited_under_its_own_action_name(engine: Engine) -> None:
    await _dead_letter(engine)
    ok = await _release_a_replay(engine)
    assert ok.status_code == 200
    # POSITIVE CONTROL: something was actually re-queued, so the guarded write really did run.
    assert ok.json()["result"] == {"requeued": 1}

    rows = await engine.store.list_audit(action="dead_letter_replay")
    assert len(rows) == 1
    row = rows[0]
    # The REQUESTER owns the action -- matching the inline row. The approver's half of the ceremony
    # is on approval.approved, which is where the second identity belongs.
    assert str(row["actor"]) == "op"
    assert json.loads(str(row["detail"])) == {"destination_name": None, "requeued": 1}
    # ADR 0150: `client` is the address of the ACTOR NAMED IN THE ROW. That actor is the requester,
    # while the request in flight belongs to the approver, so no address is in scope here.
    assert row["client"] is None


async def test_released_replay_that_requeues_nothing_writes_no_row(engine: Engine) -> None:
    """The write is GUARDED on requeued, matching the inline route: this action name means PHI was
    actually re-transmitted (review M-4). The zero-effect release is not thereby lost --
    approval.approved carries the executor's own {"requeued": 0} result."""
    ok = await _release_a_replay(engine)  # no dead letters seeded
    assert ok.status_code == 200 and ok.json()["result"] == {"requeued": 0}

    assert await engine.store.list_audit(action="dead_letter_replay") == []
    approved = (await engine.store.list_audit(action="approval.approved"))[0]
    assert json.loads(str(approved["detail"]))["result"] == {"requeued": 0}


async def test_a_pending_replay_with_no_captured_requester_still_releases(engine: Engine) -> None:
    """A request persisted BEFORE the guard began capturing `requester` carries no such key. Reading
    it with ``p["requester"]`` would raise KeyError inside the executor, and ApprovalGate.approve
    would compensate that into a 'failed' row (ASVS 2.3.3) -- recording an operation that ran, and
    re-queued PHI, as one that did not. The row is written with a NULL actor instead: no literal is
    safe (a username could be "unknown"), and the requester is still named on approval.approved."""
    await _dead_letter(engine)
    service = await _service(engine)
    await _add(service, "approver", Role.ADMINISTRATOR)
    # A REAL requester: approve() re-validates the requester at release (ASVS 8.3.2), and this
    # test is about the missing params key, not about a requester who no longer exists.
    op_id = await _add(service, "op", Role.OPERATOR)
    await engine.store.create_pending_approval(
        approval_id="cafebabecafebabecafebabecafebabe",
        operation="dead_letter_replay",
        params="{}",  # the pre-#1646 shape: scope keys absent, and no requester
        requester="op",
        requester_user_id=op_id,
        requested_at=time.time(),
        expires_at=None,
    )
    async with _client(engine, service, ON) as c:
        ok = await c.post(
            "/approvals/cafebabecafebabecafebabecafebabe/approve",
            headers=await _token(c, "approver"),
        )
        assert ok.status_code == 200  # NOT a 500 from a KeyError the gate compensated
        assert ok.json()["result"] == {"requeued": 1}

    rows = await engine.store.list_audit(action="dead_letter_replay")
    assert len(rows) == 1 and rows[0]["actor"] is None
    approved = (await engine.store.list_audit(action="approval.approved"))[0]
    assert json.loads(str(approved["detail"]))["requester"] == "op"
    # The row the gate writes on a compensated failure must be absent: the operation did run.
    assert await engine.store.list_audit(action="approval.failed") == []


# --- ASVS 2.3.3: the released-but-unexecuted compensating transition ---------------------------
#
# approve() claims the row ('executing' since BACKLOG #1562) BEFORE running the executor, and that
# ordering is load-bearing (it guards the double-approve race). The gap this closes is what happens
# when the executor then raises: without compensation the row is left claimed for an operation that
# never happened, AND no approval.approved row is written either, so the store carries a released
# approval with no recorded outcome at all.


async def _gate_with_failing_op(engine: Engine) -> tuple[ApprovalGate, RuntimeError, str]:
    # The maker is a REAL, enabled user holding the permission, because approve() re-validates the
    # requester (ASVS 8.3.2) before it reaches the executor these tests are about.
    service = await _service(engine)
    maker_id = await _add(service, "maker", Role.OPERATOR)
    gate = ApprovalGate(engine.store, ON, resolve_identity=service.identity_for_user_id)
    boom = RuntimeError("executor exploded")

    async def _raises(_p: Mapping[str, Any]) -> dict[str, Any]:
        raise boom

    gate.register(
        "dead_letter_replay",
        "Replay dead-lettered deliveries",
        _raises,
        permission=Permission.MESSAGES_REPLAY,
    )
    return gate, boom, maker_id


async def test_raising_executor_rolls_the_row_to_failed(engine: Engine) -> None:
    """The row must NOT be left claimed for an operation that did not run."""
    gate, boom, maker_id = await _gate_with_failing_op(engine)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker_id
    )
    assert approval_id is not None

    # The original executor error still reaches the caller -- compensation must not swallow it.
    with pytest.raises(RuntimeError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert caught.value is boom

    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None
    assert str(row["status"]) == "failed"  # pre-fix this read 'approved'


async def test_raising_executor_audits_the_failure_against_both_identities(
    engine: Engine,
) -> None:
    gate, _, maker_id = await _gate_with_failing_op(engine)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker_id
    )
    assert approval_id is not None
    with pytest.raises(RuntimeError):
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")

    rows = await engine.store.list_audit(limit=50)
    audited = {(str(r["action"]), str(r["actor"])) for r in rows}
    assert ("approval.requested", "maker") in audited  # the maker's half survives
    assert ("approval.failed", "checker") in audited  # the checker's half records the failure
    # A success row must NOT be written for an operation that raised.
    assert ("approval.approved", "checker") not in audited

    failed = next(r for r in rows if str(r["action"]) == "approval.failed")
    detail = json.loads(str(failed["detail"]))
    assert detail["operation"] == "dead_letter_replay"
    assert detail["requester"] == "maker"
    assert detail["compensated"] is True
    assert detail["stage"] == "execute"  # the executor ran and raised (BACKLOG #1562)
    # The exception TYPE is recorded, never its message: executor text can carry connection names,
    # paths or params, and the audit log is not a PHI sink.
    assert detail["error"] == "RuntimeError"
    assert "exploded" not in str(failed["detail"])


async def test_compensation_cannot_clobber_an_already_rejected_row(engine: Engine) -> None:
    """The compensating transition is guarded on 'executing' (BACKLOG #1562), so it can only ever
    move a row this gate itself claimed -- never one another caller rejected or expired."""
    gate, _, maker_id = await _gate_with_failing_op(engine)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker_id
    )
    assert approval_id is not None
    await gate.reject(approval_id, approver="checker")

    moved = await engine.store.decide_pending_approval(
        approval_id,
        status="failed",
        approver="checker",
        decided_at=0.0,
        from_status="executing",
    )
    assert moved is False
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None
    assert str(row["status"]) == "rejected"


# --- BACKLOG #1940: the audit row and the executed operation must agree ---------------------------
#
# approval.approved was written only AFTER the executor ran, outside its try. An audit log that
# refused writes let the operation complete with no record of the release and handed the approver a
# 500. The executors had the mirror defect: their own trailing audit row raised after the action ran,
# and the gate compensated an operation that DID run to 'failed'. The fault is injected per action
# name, so every other audit write (the login, the request) still lands.


def _fail_audit_for(monkeypatch: pytest.MonkeyPatch, engine: Engine, *actions: str) -> None:
    real = engine.store.record_audit

    async def _record(action: str, **kwargs: Any) -> None:
        if action in actions:
            raise sqlite3.OperationalError("disk I/O error")
        await real(action, **kwargs)

    monkeypatch.setattr(engine.store, "record_audit", _record)


async def _gate_with_spy_op(engine: Engine) -> tuple[ApprovalGate, list[Mapping[str, Any]], str]:
    service = await _service(engine)
    maker_id = await _add(service, "maker", Role.OPERATOR)
    gate = ApprovalGate(engine.store, ON, resolve_identity=service.identity_for_user_id)
    calls: list[Mapping[str, Any]] = []

    async def _spy(p: Mapping[str, Any]) -> dict[str, Any]:
        calls.append(p)
        return {"requeued": 3}

    gate.register(
        "dead_letter_replay",
        "Replay dead-lettered deliveries",
        _spy,
        permission=Permission.MESSAGES_REPLAY,
    )
    return gate, calls, maker_id


async def test_an_audit_log_that_refuses_the_release_stops_the_operation(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pre-fix the executor ran first and the audit write raised after it, so the operation
    completed with no approval row. Now the release row is written first, and its failure stops
    the approve before anything moves."""
    gate, calls, maker_id = await _gate_with_spy_op(engine)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker_id
    )
    assert approval_id is not None
    _fail_audit_for(monkeypatch, engine, "approval.release_attempted", "approval.approved")

    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert caught.value.status == 503
    assert "did not run" in caught.value.detail
    assert calls == []  # pre-fix: the operation ran
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "pending"  # retryable, not stranded

    # Once the audit log accepts writes again, the same request releases normally.
    monkeypatch.undo()
    outcome = await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert outcome["result"] == {"requeued": 3} and len(calls) == 1


async def test_the_refused_release_is_a_503_at_the_route(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The route maps the refusal to a clear 503, not a 500, and the replay does not run."""
    await _dead_letter(engine)
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    async with _client(engine, service, ON) as c:
        approval_id = (await _request_replay(c, await _token(c, "op"))).json()["approval_id"]
        admin = await _token(c, "approver")
        _fail_audit_for(monkeypatch, engine, "approval.release_attempted", "approval.approved")
        r = await c.post(f"/approvals/{approval_id}/approve", headers=admin)
        assert r.status_code == 503
        assert "still pending" in r.json()["detail"]
    # The dead letter was not re-queued: nothing ran, and the request did not move.
    assert len(await engine.store.list_dead(limit=10, allowed_channels=None)) == 1
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "pending"
    assert await engine.store.list_audit(action="approval.release_attempted") == []


async def test_a_release_row_whose_commit_failed_never_commits_later(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PR 1607 review finding 3. The 503 tells the approver the release row is absent. The fault is
    injected at the COMMIT, so the INSERT really ran. SQLite leaves a transaction open when its
    COMMIT fails, and a store that did not roll it back would hand it to the next writer, whose
    COMMIT made the refused row durable after all. The next writer here is the re-approve's own
    release row, so a leaked row shows up as a second one."""
    gate, calls, maker_id = await _gate_with_spy_op(engine)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker_id
    )
    assert approval_id is not None
    store = engine.store
    real_record, real_commit = store.record_audit, store._commit  # type: ignore[attr-defined]
    armed = False

    async def _record(action: str, **kwargs: Any) -> None:
        nonlocal armed
        armed = action == "approval.release_attempted"
        try:
            await real_record(action, **kwargs)
        finally:
            armed = False

    async def _commit() -> None:
        if armed:
            raise sqlite3.OperationalError("database is locked")
        await real_commit()

    monkeypatch.setattr(store, "record_audit", _record)
    monkeypatch.setattr(store, "_commit", _commit)
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert caught.value.status == 503 and calls == []

    monkeypatch.undo()
    outcome = await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert outcome["result"] == {"requeued": 3} and len(calls) == 1
    assert len(await store.list_audit(action="approval.release_attempted")) == 1


async def test_a_release_that_loses_to_a_reject_runs_nothing(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The documented cost of writing the release row first. A reject that lands between that row
    and the transition wins: the approve is refused, nothing runs, and the release row stands
    alone with no approved or failed row after it."""
    gate, calls, maker_id = await _gate_with_spy_op(engine)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker_id
    )
    assert approval_id is not None
    real = engine.store.record_audit

    async def _reject_right_after_the_release_row(action: str, **kwargs: Any) -> None:
        await real(action, **kwargs)
        if action == "approval.release_attempted":
            monkeypatch.undo()  # so the reject's own audit write goes straight through
            await gate.reject(approval_id, approver="other-checker")

    monkeypatch.setattr(engine.store, "record_audit", _reject_right_after_the_release_row)
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert caught.value.status == 409
    assert calls == []
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "rejected"
    actions = [str(r["action"]) for r in await engine.store.list_audit(limit=50)]
    assert actions.count("approval.release_attempted") == 1
    assert "approval.approved" not in actions and "approval.failed" not in actions


async def test_a_failed_approved_row_after_the_operation_ran_still_reports_success(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The operation has run, so a 500 would invite a second, duplicate request. The release row
    written before it already names both identities."""
    gate, calls, maker_id = await _gate_with_spy_op(engine)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker_id
    )
    assert approval_id is not None
    _fail_audit_for(monkeypatch, engine, "approval.approved")

    with caplog.at_level(logging.ERROR, logger="messagefoundry.api.approvals"):
        outcome = await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert outcome["result"] == {"requeued": 3} and len(calls) == 1
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "approved"
    released = await engine.store.list_audit(action="approval.release_attempted")
    assert len(released) == 1 and str(released[0]["actor"]) == "checker"
    assert json.loads(str(released[0]["detail"]))["requester"] == "maker"
    assert any(
        r.levelno == logging.ERROR and "approval.approved audit row failed" in r.getMessage()
        for r in caplog.records
    )


async def test_a_failed_replay_audit_row_is_not_compensated_to_failed(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The executor's own dead_letter_replay row fails AFTER the deliveries were re-queued. Pre-fix
    the raise reached the gate's compensation and the row read 'failed' for a replay that ran."""
    await _dead_letter(engine)
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    async with _client(engine, service, ON) as c:
        approval_id = (await _request_replay(c, await _token(c, "op"))).json()["approval_id"]
        admin = await _token(c, "approver")
        _fail_audit_for(monkeypatch, engine, "dead_letter_replay")
        with caplog.at_level(logging.ERROR, logger="messagefoundry.api.app"):
            ok = await c.post(f"/approvals/{approval_id}/approve", headers=admin)
        assert ok.status_code == 200
        assert ok.json()["result"] == {"requeued": 1}  # the replay really ran

    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "approved"
    assert await engine.store.list_audit(action="approval.failed") == []
    assert len(await engine.store.list_audit(action="approval.approved")) == 1
    assert any(
        r.levelno == logging.ERROR and "dead_letter_replay audit row failed" in r.getMessage()
        for r in caplog.records
    )


async def test_a_normal_release_writes_one_release_row_and_one_approved_row(
    engine: Engine,
) -> None:
    """CONTROL for the fault tests above: with a healthy audit log, one release runs the operation
    once and writes each approval row once, in order."""
    gate, calls, maker_id = await _gate_with_spy_op(engine)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker_id
    )
    assert approval_id is not None
    await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert len(calls) == 1
    actions = [str(r["action"]) for r in await engine.store.list_audit(limit=50)]
    assert actions.count("approval.release_attempted") == 1
    assert actions.count("approval.approved") == 1
    # list_audit is newest-first: the release row precedes the approved row in the chain.
    assert actions.index("approval.approved") < actions.index("approval.release_attempted")


async def test_pending_approval_store_contract(engine: Engine) -> None:
    """The SQLite leg of the shared ``requester_user_id`` store contract (BACKLOG #1540).

    The same body runs against live PostgreSQL and SQL Server, so the one round-trip the three SQL
    bodies owe is asserted once rather than worded three times."""
    from tests._pending_approval_store_contract import _assert_pending_approval_contract

    await _assert_pending_approval_contract(engine.store)


# --- BACKLOG #1562: a release is 'executing' until its outcome is known ---------------------------
# The SQLite legs of the shared release-outcome contract. The same bodies run against live
# PostgreSQL and SQL Server, because the settling transitions are each backend's own SQL.


async def test_release_reads_executing_while_it_runs_then_approved(engine: Engine) -> None:
    from tests._pending_approval_store_contract import _assert_release_success_contract

    await _assert_release_success_contract(engine.store)


async def test_raising_release_ends_failed_not_executing(engine: Engine) -> None:
    from tests._pending_approval_store_contract import _assert_release_failure_contract

    await _assert_release_failure_contract(engine.store)


async def test_cancelled_release_ends_interrupted_with_its_own_audit_row(engine: Engine) -> None:
    from tests._pending_approval_store_contract import _assert_release_cancel_contract

    await _assert_release_cancel_contract(engine.store)


# The cancel WINDOWS. Each test below holds one store write open, cancels the approve inside it, then
# lets the write finish. The row must still end in the outcome that actually happened.

_WAIT_S = 10.0


async def _eventually(check: Any) -> None:
    """Wait, bounded, for a shielded write that finishes after its caller was cancelled."""
    deadline = time.monotonic() + _WAIT_S
    while not await check():
        assert time.monotonic() < deadline, "the shielded write never finished"
        await asyncio.sleep(0.01)


def _held_store(engine: Engine, action: str, *, approver_changed: bool = False) -> Any:
    """The real store, with the FIRST call matching ``action`` held open until ``release`` is set.

    ``action`` is an audit action name, or ``decide:<status>`` for a status write. With
    ``approver_changed`` the approver account reads as created after the request, so the release
    is flagged (BACKLOG #315) and the provenance write runs in approve()'s ``finally``."""
    from tests._pending_approval_store_contract import _StandingStore

    class _Held(_StandingStore):
        entered = asyncio.Event()
        release = asyncio.Event()

        async def _hold(self, name: str) -> None:
            if name == action and not self.entered.is_set():
                self.entered.set()
                await self.release.wait()

        async def decide_pending_approval(self, approval_id: str, **kw: Any) -> bool:
            await self._hold(f"decide:{kw['status']}")
            return bool(await self._store.decide_pending_approval(approval_id, **kw))

        async def record_audit(self, audit_action: str, **kw: Any) -> Any:
            await self._hold(audit_action)
            return await self._store.record_audit(audit_action, **kw)

        async def get_user(self, _user_id: str) -> Any:
            user = await super().get_user(_user_id)
            if approver_changed:
                user.created_at = time.time() + 3600.0
            return user

    return _Held(engine.store)


async def _cancel_inside(
    store: Any,
    execute: Any,
    *,
    while_held: Callable[[str], Awaitable[None]] | None = None,
) -> tuple[str, list[str]]:
    """Run approve() over ``store``, cancel it once the held write is entered, release the write,
    and return the approval id plus whether the executor started. ``while_held`` runs with the
    approval id while the write is held, before the cancel."""
    from tests._pending_approval_store_contract import _resolve

    ran: list[str] = []

    async def _wrapped(p: Mapping[str, Any]) -> dict[str, Any]:
        ran.append("started")
        return dict(await execute(p))

    gate = ApprovalGate(store, ON, resolve_identity=_resolve)
    gate.register("dead_letter_replay", "op", _wrapped, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id="maker-id"
    )
    assert approval_id is not None
    task = asyncio.create_task(
        gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    )
    await asyncio.wait_for(store.entered.wait(), _WAIT_S)
    if while_held is not None:
        await while_held(approval_id)
    # cancel() cancels the wait the task is parked on at once, so releasing the held write straight
    # after still lands the cancellation inside it. Released BEFORE awaiting the task, because a
    # cancel during the claim makes approve() wait for the claim to land before it re-raises.
    task.cancel()
    store.release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, _WAIT_S)
    return approval_id, ran


async def _status_of(engine: Engine, approval_id: str) -> str:
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None
    return str(row["status"])


async def _runs(_p: Mapping[str, Any]) -> dict[str, Any]:
    return {"ran": True}


async def test_cancel_while_recording_success_still_records_approved(engine: Engine) -> None:
    """The executor RETURNED, so the operation ran; a cancel that lands while that outcome is being
    written must not strand the row in 'executing'. The caller still sees the cancellation."""
    store = _held_store(engine, "decide:approved")
    approval_id, _ = await _cancel_inside(store, _runs)

    async def _settled() -> bool:
        return bool(await engine.store.list_audit(action="approval.approved"))

    await _eventually(_settled)
    assert await _status_of(engine, approval_id) == "approved"
    assert len(await engine.store.list_audit(action="approval.approved")) == 1
    assert await engine.store.list_audit(action="approval.interrupted") == []


async def test_cancel_in_the_provenance_write_still_records_approved(engine: Engine) -> None:
    """A FLAGGED release (BACKLOG #315) writes its provenance row in approve()'s ``finally``. A
    cancel landing there must not skip the settle: the operation ran, so the row ends 'approved'."""
    store = _held_store(engine, "approval.approver_provenance", approver_changed=True)
    approval_id, ran = await _cancel_inside(store, _runs)
    assert ran == ["started"]

    async def _flagged() -> bool:
        return bool(await engine.store.list_audit(action="approval.approver_provenance"))

    await _eventually(_flagged)
    assert await _status_of(engine, approval_id) == "approved"
    assert len(await engine.store.list_audit(action="approval.approved")) == 1


async def test_a_second_cancel_cannot_cancel_the_interrupted_record(engine: Engine) -> None:
    """A cancellation re-delivered while 'interrupted' is being written (a request timeout inside a
    middleware task group can do this) must not cancel the record of the first one."""
    store = _held_store(engine, "decide:interrupted")
    never = asyncio.Event()

    async def _hangs(_p: Mapping[str, Any]) -> dict[str, Any]:
        await never.wait()
        return {"ran": True}

    # The first cancel lands in the executor; the second while the interrupted write is held.
    from tests._pending_approval_store_contract import _resolve

    gate = ApprovalGate(store, ON, resolve_identity=_resolve)
    gate.register("dead_letter_replay", "op", _hangs, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id="maker-id"
    )
    assert approval_id is not None
    task = asyncio.create_task(
        gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    )

    async def _executing() -> bool:
        return await _status_of(engine, approval_id) == "executing"

    await _eventually(_executing)
    task.cancel()
    await asyncio.wait_for(store.entered.wait(), _WAIT_S)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, _WAIT_S)
    store.release.set()

    async def _recorded() -> bool:
        return bool(await engine.store.list_audit(action="approval.interrupted"))

    await _eventually(_recorded)
    assert await _status_of(engine, approval_id) == "interrupted"


async def test_cancel_during_the_claim_settles_to_failed_and_never_runs(engine: Engine) -> None:
    """Cancelled while claiming. The claim still commits, and nothing ran, so the known outcome is
    'failed' -- not a row stranded in 'executing' that nobody can reject or release."""
    store = _held_store(engine, "decide:executing")
    approval_id, ran = await _cancel_inside(store, _runs)

    async def _failed() -> bool:
        return bool(await engine.store.list_audit(action="approval.failed"))

    await _eventually(_failed)
    assert ran == []  # the executor never started
    assert await _status_of(engine, approval_id) == "failed"
    failed = json.loads(str((await engine.store.list_audit(action="approval.failed"))[0]["detail"]))
    assert failed["error"] == "CancelledError" and failed["stage"] == "claim"
    assert await engine.store.list_audit(action="approval.approved") == []


async def test_a_failed_approved_write_still_writes_the_audit_row(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The operation RAN. If moving the row to 'approved' fails, approval.approved is still written,
    the failure is logged at ERROR, and the approver still gets success: a 500 would invite a new
    request that runs the operation twice (BACKLOG #1940's reasoning, applied to the status write).
    The row is left 'executing', never 'failed'."""
    from tests._pending_approval_store_contract import _resolve, _StandingStore

    class _SettleFails(_StandingStore):
        async def decide_pending_approval(self, approval_id: str, **kw: Any) -> bool:
            if kw["status"] == "approved":
                raise OSError("store unreachable")
            return bool(await self._store.decide_pending_approval(approval_id, **kw))

    gate = ApprovalGate(_SettleFails(engine.store), ON, resolve_identity=_resolve)
    gate.register("dead_letter_replay", "op", _runs, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id="maker-id"
    )
    assert approval_id is not None
    with caplog.at_level(logging.ERROR, logger="messagefoundry.api.approvals"):
        outcome = await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert outcome["result"] == {"ran": True}
    assert len(await engine.store.list_audit(action="approval.approved")) == 1
    assert await engine.store.list_audit(action="approval.failed") == []
    assert await _status_of(engine, approval_id) == "executing"
    assert any(
        r.levelno == logging.ERROR
        and approval_id in r.getMessage()
        and "moving the row to 'approved' failed" in r.getMessage()
        for r in caplog.records
    )


# --- BACKLOG #1540: the self-approval refusal keys on users.id, not on the username --------
# BACKLOG #1532 made `users.username` directory-writable, so the stored `requester` and the live
# `approver` are two snapshots of a mutable value taken up to `[approvals].expiry_hours` apart.
# Comparing them fails in BOTH directions, so both directions are pinned here. The session token is
# deliberately NOT re-issued after the rename: `identity_for_token` rebuilds the Identity from the
# live users row, which is exactly how the reconciler's new name reaches the approve endpoint.


async def test_renamed_requester_still_cannot_approve_their_own_request(engine: Engine) -> None:
    """The FALSE ACCEPT. Pre-fix, a requester renamed inside the approval window compared unequal to
    their own stored name, passed the refusal, and released their own gated action."""
    service = await _service(engine)
    jdoe_id = await _add(service, "jdoe", Role.ADMINISTRATOR)
    async with _client(engine, service, ON) as c:
        jdoe = await _token(c, "jdoe")
        approval_id = (await _request_replay(c, jdoe)).json()["approval_id"]
        # The directory renames the requester mid-window; the engine copies the new name down.
        assert await engine.store.set_user_username(jdoe_id, "jdoe2", expected_username="jdoe")
        # POSITIVE CONTROL, and it is what makes the 403 below evidence of anything. The stored
        # `requester` and the approver's LIVE username must actually DIFFER at this point -- if they
        # did not, a username comparison would refuse too and the assertion could pass under the very
        # bug this test exists to catch. `identity_for_token` rebuilds the Identity from the users
        # row, so the renamed row IS what the approve endpoint sees on the unchanged session token.
        row = await engine.store.get_pending_approval(approval_id)
        assert row is not None and str(row["requester"]) == "jdoe"
        renamed = await engine.store.get_user(jdoe_id)
        assert renamed is not None and renamed.username == "jdoe2"

        r = await c.post(f"/approvals/{approval_id}/approve", headers=jdoe)
        assert r.status_code == 403  # pre-fix: 200, and the operation ran
        assert "your own request" in r.json()["detail"]
        # Still pending: a refused self-approval must not consume the request.
        row = await engine.store.get_pending_approval(approval_id)
        assert row is not None and str(row["status"]) == "pending"


async def test_a_new_user_holding_the_freed_username_can_approve(engine: Engine) -> None:
    """The FALSE REFUSAL, the reverse of the test above. Once a rename frees the name, a DIFFERENT
    person can be given it; pre-fix their approval was refused as a self-approval it is not."""
    service = await _service(engine)
    jdoe_id = await _add(service, "jdoe", Role.ADMINISTRATOR)
    async with _client(engine, service, ON) as c:
        approval_id = (await _request_replay(c, await _token(c, "jdoe"))).json()["approval_id"]
        assert await engine.store.set_user_username(jdoe_id, "jdoe2", expected_username="jdoe")
        await _add(service, "jdoe", Role.ADMINISTRATOR)  # a second person inherits the freed name
        ok = await c.post(f"/approvals/{approval_id}/approve", headers=await _token(c, "jdoe"))
        assert ok.status_code == 200  # pre-fix: 403
        outcome = ok.json()
        assert outcome["result"] == {"requeued": 0}  # the captured operation actually executed
        # Both labels read "jdoe" because `requester` is the pre-rename DISPLAY snapshot and the
        # approver now holds that same name. They are two different people, and the ids the refusal
        # compared say so -- which is the whole point of keying on the id.
        assert outcome["requested_by"] == "jdoe" and outcome["approved_by"] == "jdoe"


async def test_a_request_with_no_requester_id_is_refused_fail_closed(engine: Engine) -> None:
    """A row carrying NULL `requester_user_id` -- the shape the ALTER-in migration leaves behind --
    cannot be checked for self-approval, so it is refused rather than falling back to the name.

    The refusal is a DISTINCT 409, not the 403: a stale row is not an accusation of self-approval,
    and the message has to tell the operator the remedy (re-request), which 403 does not."""
    service = await _service(engine)
    await _add(service, "approver", Role.ADMINISTRATOR)
    await _add(service, "jdoe", Role.ADMINISTRATOR)
    async with _client(engine, service, ON) as c:
        approval_id = (await _request_replay(c, await _token(c, "jdoe"))).json()["approval_id"]
        # Strip the id to model a row written before the column existed.
        store = engine.store
        assert isinstance(store, MessageStore)  # this reach-in is SQLite-specific
        await store._db.execute(
            "UPDATE pending_approvals SET requester_user_id = NULL WHERE id = ?", (approval_id,)
        )
        await store._db.commit()
        stale = await c.post(
            f"/approvals/{approval_id}/approve", headers=await _token(c, "approver")
        )
        assert stale.status_code == 409
        detail = stale.json()["detail"]
        assert "reject it and request the operation again" in detail
        assert "your own request" not in detail  # must not read as a self-approval accusation
        # Fail-closed means the row is untouched, not silently consumed.
        row = await engine.store.get_pending_approval(approval_id)
        assert row is not None and str(row["status"]) == "pending"
        # And the id is what the refusal turned on -- the requester's NAME is still present.
        assert str(row["requester"]) == "jdoe"


# --- BACKLOG #1562 part B: resolving an interrupted release ----------------------------------------
# Owner ruling 2026-09-26: any holder of approvals:approve, with a fresh step-up, never the requester,
# records "effects applied" or "not applied". Audited, never re-runs, listed beside pending approvals.


async def test_interrupted_resolution_store_contract(engine: Engine) -> None:
    """The SQLite leg of the shared resolution contract; the server legs run the same body."""
    from tests._pending_approval_store_contract import _assert_interrupted_resolution_contract

    await _assert_interrupted_resolution_contract(engine.store)


def _app_client(
    engine: Engine, service: AuthService, runs: list[str]
) -> tuple[ApprovalGate, httpx.AsyncClient]:
    """A client over the real app, with the replay executor swapped for one that records each run,
    so a test can prove a resolve never runs the operation."""
    app = create_app(engine, auth=service, approvals=ON)
    gate: ApprovalGate = app.state.approval_gate

    async def _counts(_p: Mapping[str, Any]) -> dict[str, Any]:
        runs.append("ran")
        return {"requeued": 0}

    gate.register("dead_letter_replay", "replay", _counts, permission=Permission.MESSAGES_REPLAY)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    return gate, client


async def _interrupted_row(engine: Engine, requester: str, requester_user_id: str) -> str:
    """Forge the row an interrupted release leaves: claimed as 'executing' by 'releaser', then cut off.
    Forged through the store's own transitions, so the row has exactly the shape the gate writes."""
    approval_id = uuid4().hex
    await engine.store.create_pending_approval(
        approval_id=approval_id,
        operation="dead_letter_replay",
        params="{}",
        requester=requester,
        requester_user_id=requester_user_id,
        requested_at=time.time() - 60.0,
        expires_at=None,
    )
    assert await engine.store.decide_pending_approval(
        approval_id, status="executing", approver="releaser", decided_at=time.time() - 30.0
    )
    assert await engine.store.decide_pending_approval(
        approval_id,
        status="interrupted",
        approver="releaser",
        decided_at=time.time() - 20.0,
        from_status="executing",
    )
    return approval_id


def _resolve_url(approval_id: str) -> str:
    return f"/approvals/{approval_id}/resolve"


async def test_get_approvals_lists_interrupted_beside_pending(engine: Engine) -> None:
    """Pre-part-B an interrupted row was absent from GET /approvals, so nobody could find it."""
    service = await _service(engine)
    op_id = await _add(service, "op", Role.OPERATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    runs: list[str] = []
    _gate, c = _app_client(engine, service, runs)
    async with c:
        pending_id = (await _request_replay(c, await _token(c, "op"))).json()["approval_id"]
        interrupted_id = await _interrupted_row(engine, "op", op_id)
        listed = (await c.get("/approvals", headers=await _token(c, "approver"))).json()
    # Pending first, then interrupted, as GET /approvals documents.
    assert [(a["id"], a["status"]) for a in listed["approvals"]] == [
        (pending_id, "pending"),
        (interrupted_id, "interrupted"),
    ]
    by_id = {a["id"]: a for a in listed["approvals"]}
    assert by_id[interrupted_id]["approver"] == "releaser"
    assert by_id[interrupted_id]["decided_at"] is not None
    assert by_id[interrupted_id]["requester"] == "op"


async def test_a_row_cut_off_between_the_two_reads_is_listed_once(engine: Engine) -> None:
    """GET /approvals reads pending, then interrupted. A release cut off between the two reads
    appears in both; it must be listed once, as interrupted, its later status."""
    service = await _service(engine)
    op_id = await _add(service, "op", Role.OPERATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    runs: list[str] = []
    gate, c = _app_client(engine, service, runs)
    async with c:
        approval_id = await _interrupted_row(engine, "op", op_id)
        cut_off = (await gate.list_interrupted())[0]
        stale = {**cut_off, "status": "pending", "approver": None, "decided_at": None}

        async def _stale_pending() -> list[dict[str, Any]]:
            return [stale]

        gate.list_pending = _stale_pending  # type: ignore[method-assign]
        listed = (await c.get("/approvals", headers=await _token(c, "approver"))).json()
    assert [(a["id"], a["status"]) for a in listed["approvals"]] == [(approval_id, "interrupted")]


@pytest.mark.parametrize(
    ("outcome", "status"),
    [("effects_applied", "resolved_applied"), ("effects_not_applied", "resolved_not_applied")],
)
async def test_resolve_records_the_outcome_audits_it_and_never_runs(
    engine: Engine, outcome: str, status: str
) -> None:
    service = await _service(engine)
    op_id = await _add(service, "op", Role.OPERATOR)
    await _add(service, "resolver", Role.ADMINISTRATOR)
    runs: list[str] = []
    _gate, c = _app_client(engine, service, runs)
    async with c:
        approval_id = await _interrupted_row(engine, "op", op_id)
        cut_off = await engine.store.get_pending_approval(approval_id)
        assert cut_off is not None
        interrupted_at = float(cut_off["decided_at"])
        admin = await _token(c, "resolver")
        r = await c.post(_resolve_url(approval_id), headers=admin, json={"outcome": outcome})
        assert r.status_code == 200, r.text
        assert r.json() == {
            "operation": "dead_letter_replay",
            "requested_by": "op",
            "approved_by": "releaser",
            "resolved_by": "resolver",
            "outcome": outcome,
            "status": status,
        }
        # Resolved rows leave the open queue.
        listed = (await c.get("/approvals", headers=admin)).json()["approvals"]
        assert all(a["id"] != approval_id for a in listed)
        # A second resolve finds nothing interrupted to resolve.
        again = await c.post(_resolve_url(approval_id), headers=admin, json={"outcome": outcome})
        assert again.status_code == 409
    assert await _status_of(engine, approval_id) == status
    assert runs == [], "a resolve must never run the operation"
    assert await engine.store.list_audit(action="approval.approved") == []
    expected = {
        "approval_id": approval_id,
        "operation": "dead_letter_replay",
        "requester": "op",
        "approver": "releaser",
        "outcome": outcome,
        "status": status,
        "interrupted_at": interrupted_at,
    }
    # The row's decided_at is now the resolution time; the audit rows keep the cut-off time.
    resolved_row = await engine.store.get_pending_approval(approval_id)
    assert resolved_row is not None and float(resolved_row["decided_at"]) != interrupted_at
    for action in ("approval.resolve_attempted", "approval.resolved"):
        rows = await engine.store.list_audit(action=action)
        assert len(rows) == 1, action
        assert str(rows[0]["actor"]) == "resolver"
        assert json.loads(str(rows[0]["detail"])) == expected
    # The attempt row is written BEFORE the move (list_audit is newest-first).
    actions = [str(r["action"]) for r in await engine.store.list_audit(limit=50)]
    assert actions.index("approval.resolved") < actions.index("approval.resolve_attempted")


async def test_requester_cannot_resolve_their_own_interrupted_request(engine: Engine) -> None:
    service = await _service(engine)
    maker_id = await _add(service, "maker", Role.ADMINISTRATOR)  # holds approvals:approve itself
    await _add(service, "other", Role.ADMINISTRATOR)
    runs: list[str] = []
    _gate, c = _app_client(engine, service, runs)
    async with c:
        approval_id = await _interrupted_row(engine, "maker", maker_id)
        own = await c.post(
            _resolve_url(approval_id),
            headers=await _token(c, "maker"),
            json={"outcome": "effects_applied"},
        )
        assert own.status_code == 403
        assert "your own request" in own.json()["detail"]
        assert await _status_of(engine, approval_id) == "interrupted"
        # Positive control: the same request, the same body, a different approver.
        ok = await c.post(
            _resolve_url(approval_id),
            headers=await _token(c, "other"),
            json={"outcome": "effects_applied"},
        )
        assert ok.status_code == 200
    assert [str(r["actor"]) for r in await engine.store.list_audit(action="approval.resolved")] == [
        "other"
    ]


async def test_resolve_requires_a_fresh_step_up(engine: Engine) -> None:
    """Approve and reject are require_paced; resolve is require_step_up, per the owner ruling."""
    from messagefoundry.auth.tokens import hash_token

    service = await _service(engine)
    op_id = await _add(service, "op", Role.OPERATOR)
    await _add(service, "resolver", Role.ADMINISTRATOR)
    runs: list[str] = []
    _gate, c = _app_client(engine, service, runs)
    async with c:
        approval_id = await _interrupted_row(engine, "op", op_id)
        admin = await _token(c, "resolver")
        token = admin["Authorization"].removeprefix("Bearer ")
        await service.store.mark_session_reauthed(hash_token(token), now=0.0)  # window elapsed
        stale = await c.post(
            _resolve_url(approval_id), headers=admin, json={"outcome": "effects_applied"}
        )
        assert stale.status_code == 403
        assert stale.headers.get("X-Step-Up-Required") == "1"
        assert await _status_of(engine, approval_id) == "interrupted"
        # Positive control: re-prove the password, and the same session may resolve.
        reauth = await c.post("/me/reauth", headers=admin, json={"password": PW})
        assert reauth.status_code == 200, reauth.text
        # A successful elevation re-keys the session (ASVS 7.2.4); carry the new bearer.
        rotated = {"Authorization": f"Bearer {reauth.json()['token']}"}
        ok = await c.post(
            _resolve_url(approval_id), headers=rotated, json={"outcome": "effects_applied"}
        )
        assert ok.status_code == 200, ok.text


async def test_resolve_requires_the_approve_permission(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)  # fresh login, but no approvals:approve
    runs: list[str] = []
    _gate, c = _app_client(engine, service, runs)
    async with c:
        approval_id = await _interrupted_row(engine, "maker", "maker-id")
        r = await c.post(
            _resolve_url(approval_id),
            headers=await _token(c, "op"),
            json={"outcome": "effects_not_applied"},
        )
        assert r.status_code == 403
        assert r.headers.get("X-Step-Up-Required") is None  # refused on permission, not step-up
    assert await _status_of(engine, approval_id) == "interrupted"
    assert await engine.store.list_audit(action="approval.resolved") == []


async def test_resolve_refuses_a_row_that_is_not_interrupted(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "resolver", Role.ADMINISTRATOR)
    runs: list[str] = []
    _gate, c = _app_client(engine, service, runs)
    async with c:
        admin = await _token(c, "resolver")
        pending_id = (await _request_replay(c, await _token(c, "op"))).json()["approval_id"]
        r = await c.post(
            _resolve_url(pending_id), headers=admin, json={"outcome": "effects_applied"}
        )
        assert r.status_code == 409
        assert "only an interrupted request can be resolved" in r.json()["detail"]
        # An approved row is refused too, and resolving it did not run it a second time.
        assert (await c.post(f"/approvals/{pending_id}/approve", headers=admin)).status_code == 200
        assert runs == ["ran"]
        r = await c.post(
            _resolve_url(pending_id), headers=admin, json={"outcome": "effects_applied"}
        )
        assert r.status_code == 409
        unknown = await c.post(
            _resolve_url("0" * 32), headers=admin, json={"outcome": "effects_applied"}
        )
        assert unknown.status_code == 404
        bad = await c.post(_resolve_url(pending_id), headers=admin, json={"outcome": "rerun"})
        assert bad.status_code == 422
    assert runs == ["ran"]
    assert await _status_of(engine, pending_id) == "approved"
    assert await engine.store.list_audit(action="approval.resolved") == []


async def test_a_resolve_that_loses_the_race_answers_409(engine: Engine) -> None:
    """Two resolvers read 'interrupted' at once; the store's guard lets only one record an outcome.
    Driven by a stale read, so the second resolver passes the status check and meets the guard."""
    from tests._pending_approval_store_contract import _resolve

    approval_id = await _interrupted_row(engine, "maker", "maker-id")
    stale = await engine.store.get_pending_approval(approval_id)

    class _StaleRead:
        def __getattr__(self, name: str) -> Any:
            return getattr(engine.store, name)

        async def get_pending_approval(self, _approval_id: str) -> Any:
            return stale

    gate = ApprovalGate(_StaleRead(), ON, resolve_identity=_resolve)
    first = await gate.resolve_interrupted(
        approval_id, outcome="effects_applied", resolver="a", resolver_user_id="a-id"
    )
    assert first["status"] == "resolved_applied"
    with pytest.raises(ApprovalError) as caught:
        await gate.resolve_interrupted(
            approval_id, outcome="effects_not_applied", resolver="b", resolver_user_id="b-id"
        )
    assert (
        caught.value.status == 409 and "another operator resolved it first" in caught.value.detail
    )
    assert await _status_of(engine, approval_id) == "resolved_applied"
    assert len(await engine.store.list_audit(action="approval.resolved")) == 1
    # The loser got as far as its attempt row; the row's status says who won.
    attempted = await engine.store.list_audit(action="approval.resolve_attempted")
    assert sorted(str(r["actor"]) for r in attempted) == ["a", "b"]


class _AuditRefuses:
    """The real store, with one audit action refused."""

    def __init__(self, store: Any, refused: str) -> None:
        self._store = store
        self._refused = refused

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    async def record_audit(self, action: str, **kw: Any) -> Any:
        if action == self._refused:
            raise OSError("audit log unreachable")
        return await self._store.record_audit(action, **kw)


async def test_a_refused_attempt_row_leaves_the_request_interrupted(engine: Engine) -> None:
    """The audit log must accept the resolution BEFORE the row moves (BACKLOG #1940's shape), so a
    refused attempt row answers 503 and changes nothing."""
    from tests._pending_approval_store_contract import _resolve

    approval_id = await _interrupted_row(engine, "maker", "maker-id")
    before = await engine.store.get_pending_approval(approval_id)
    assert before is not None
    store = _AuditRefuses(engine.store, "approval.resolve_attempted")
    gate = ApprovalGate(store, ON, resolve_identity=_resolve)
    with pytest.raises(ApprovalError) as caught:
        await gate.resolve_interrupted(
            approval_id, outcome="effects_applied", resolver="a", resolver_user_id="a-id"
        )
    assert caught.value.status == 503 and "still interrupted" in caught.value.detail
    after = await engine.store.get_pending_approval(approval_id)
    assert after is not None
    assert str(after["status"]) == "interrupted"
    assert float(after["decided_at"]) == float(before["decided_at"])  # never written
    assert await engine.store.list_audit(action="approval.resolved") == []


async def test_a_failed_resolved_row_still_resolves_and_is_logged(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """Once the row has moved, a failed approval.resolved write must not turn into an error: the
    attempt row already names the resolver and the outcome. The loss is logged at ERROR."""
    from tests._pending_approval_store_contract import _resolve

    approval_id = await _interrupted_row(engine, "maker", "maker-id")
    store = _AuditRefuses(engine.store, "approval.resolved")
    gate = ApprovalGate(store, ON, resolve_identity=_resolve)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.api.approvals"):
        out = await gate.resolve_interrupted(
            approval_id, outcome="effects_not_applied", resolver="a", resolver_user_id="a-id"
        )
    assert out["status"] == "resolved_not_applied"
    assert await _status_of(engine, approval_id) == "resolved_not_applied"
    attempted = await engine.store.list_audit(action="approval.resolve_attempted")
    assert [str(r["actor"]) for r in attempted] == ["a"]
    assert json.loads(str(attempted[0]["detail"]))["outcome"] == "effects_not_applied"
    assert any(
        r.levelno == logging.ERROR
        and approval_id in r.getMessage()
        # Names the resolver: in a same-outcome race this line is what says who won.
        and "resolver a moved the row" in r.getMessage()
        and "approval.resolved audit row failed" in r.getMessage()
        for r in caplog.records
    )


async def test_a_cancel_during_the_status_write_still_records_the_resolution(
    engine: Engine,
) -> None:
    """The status write and approval.resolved run shielded. A cancel landing in the status write
    (a request timeout can do this) must not leave the row moved with no approval.resolved row."""
    from tests._pending_approval_store_contract import _resolve

    approval_id = await _interrupted_row(engine, "maker", "maker-id")
    store = _held_store(engine, "decide:resolved_applied")
    gate = ApprovalGate(store, ON, resolve_identity=_resolve)
    task = asyncio.create_task(
        gate.resolve_interrupted(
            approval_id, outcome="effects_applied", resolver="a", resolver_user_id="a-id"
        )
    )
    await asyncio.wait_for(store.entered.wait(), _WAIT_S)
    task.cancel()
    store.release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, _WAIT_S)

    async def _recorded() -> bool:
        return bool(await engine.store.list_audit(action="approval.resolved"))

    await _eventually(_recorded)
    assert await _status_of(engine, approval_id) == "resolved_applied"


# --- BACKLOG #2087: a shielded outcome write logs once, is per gate, and is drained at shutdown ---
# asyncio.shield reported a write that raised after its caller was cancelled through the loop's
# exception handler, and the gate logged the same failure again. So these count the gate's log
# records AND every call to the loop's exception handler.
#
# Which handler is installed depends on test order. The tests share one session loop, and any
# create_managed_app lifespan earlier on it installs the engine's last-resort handler
# (install_loop_exception_handler) and never removes it. That handler logs to its own logger, not
# 'asyncio'. So each test installs a capturing handler of its own rather than trusting a logger name.

_REPORTING_LOGGERS = ("messagefoundry.api.approvals", "asyncio")


def _reports(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r for r in caplog.records if r.name in _REPORTING_LOGGERS and r.levelno >= logging.WARNING
    ]


@contextlib.contextmanager
def _loop_reports() -> Iterator[list[dict[str, Any]]]:
    """Capture every call to the running loop's exception handler, then restore the previous one."""
    loop = asyncio.get_running_loop()
    # Collect first, so garbage left by EARLIER tests on the shared loop reports to the previous
    # handler and is not counted against this one.
    gc.collect()
    previous = loop.get_exception_handler()
    seen: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, context: seen.append(context))
    try:
        yield seen
    finally:
        loop.set_exception_handler(previous)


def _described(loop_reports: list[dict[str, Any]]) -> list[str]:
    """Each captured loop report as its message plus the exception, so a failure names the cause."""
    return [f"{c.get('message')}: {c.get('exception')!r}" for c in loop_reports]


async def _reported_after(caplog: pytest.LogCaptureFixture, text: str) -> list[logging.LogRecord]:
    """Wait for the gate's own line naming ``text``, then a little longer, so a SECOND report of the
    same failure would have had time to arrive before the caller counts them. Run it inside
    :func:`_loop_reports`, so a report through the loop's exception handler is captured too."""
    deadline = time.monotonic() + _WAIT_S
    while not any(text in r.getMessage() for r in _reports(caplog)):
        assert time.monotonic() < deadline, f"no report naming {text!r}"
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.1)
    # "Task exception was never retrieved" is reported only when the task is collected, so collect
    # before counting, or an error nobody read would still count as one report.
    gc.collect()
    await asyncio.sleep(0)
    return _reports(caplog)


async def test_a_cancelled_claim_that_fails_is_logged_once(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """Cancelled while claiming, and the claim then raises. The settle logs the failure; asyncio
    must not report it a second time as an exception in a shielded future."""
    from tests._pending_approval_store_contract import _StandingStore

    class _ClaimFails(_StandingStore):
        entered = asyncio.Event()
        release = asyncio.Event()

        async def decide_pending_approval(self, approval_id: str, **kw: Any) -> bool:
            if kw["status"] == "executing":
                self.entered.set()
                await self.release.wait()
                raise OSError("store unreachable")
            return bool(await self._store.decide_pending_approval(approval_id, **kw))

    with caplog.at_level(logging.WARNING), _loop_reports() as loop_reports:
        approval_id, ran = await _cancel_inside(_ClaimFails(engine.store), _runs)
        reports = await _reported_after(caplog, "its claim failed")
    assert _described(loop_reports) == []
    assert len(reports) == 1, [f"{r.name}: {r.getMessage()}" for r in reports]
    assert reports[0].levelno == logging.ERROR and approval_id in reports[0].getMessage()
    assert ran == []
    assert await _status_of(engine, approval_id) == "pending"


async def test_a_cancelled_resolve_that_loses_the_race_logs_one_warning(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """PR 1636's item 5. A resolve whose caller was cancelled, and whose status write then loses to
    another operator, raises the gate's own 409. That is an expected refusal: one WARNING, no ERROR,
    and no second report from asyncio."""
    from tests._pending_approval_store_contract import _resolve

    approval_id = await _interrupted_row(engine, "maker", "maker-id")
    store = _held_store(engine, "decide:resolved_applied")
    gate = ApprovalGate(store, ON, resolve_identity=_resolve)
    with caplog.at_level(logging.WARNING), _loop_reports() as loop_reports:
        task = asyncio.create_task(
            gate.resolve_interrupted(
                approval_id, outcome="effects_applied", resolver="a", resolver_user_id="a-id"
            )
        )
        await asyncio.wait_for(store.entered.wait(), _WAIT_S)
        # Another operator resolves it while this status write is held, so the write then loses.
        assert await engine.store.decide_pending_approval(
            approval_id,
            status="resolved_not_applied",
            approver="releaser",
            decided_at=time.time(),
            from_status="interrupted",
        )
        task.cancel()
        store.release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, _WAIT_S)
        reports = await _reported_after(caplog, "another operator resolved it first")
    assert _described(loop_reports) == []
    assert len(reports) == 1, [f"{r.name}: {r.getMessage()}" for r in reports]
    assert reports[0].levelno == logging.WARNING and approval_id in reports[0].getMessage()
    assert reports[0].exc_info is None
    assert await _status_of(engine, approval_id) == "resolved_not_applied"


async def test_a_cancelled_claim_that_loses_the_race_settles_nothing(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """Cancelled while claiming, and a reject lands first, so the claim returns False. Nothing ran and
    nothing was claimed: the row stays 'rejected', no approval.failed is written, nothing is logged."""
    store = _held_store(engine, "decide:executing")

    async def _reject(approval_id: str) -> None:
        assert await engine.store.decide_pending_approval(
            approval_id, status="rejected", approver="other", decided_at=time.time()
        )

    with caplog.at_level(logging.WARNING), _loop_reports() as loop_reports:
        # approve() waits for the settle before it re-raises, so the settle is done on return.
        approval_id, ran = await _cancel_inside(store, _runs, while_held=_reject)
        await asyncio.sleep(0.1)
        gc.collect()
        await asyncio.sleep(0)
    assert ran == []
    assert await _status_of(engine, approval_id) == "rejected"
    assert await engine.store.list_audit(action="approval.failed") == []
    assert _reports(caplog) == []
    assert _described(loop_reports) == []


async def _orphan_a_held_approved_write(engine: Engine) -> tuple[ApprovalGate, Any, str]:
    """Cancel an approve while its 'approved' status write is held, and leave the write held."""
    from tests._pending_approval_store_contract import _resolve

    store = _held_store(engine, "decide:approved")
    gate = ApprovalGate(store, ON, resolve_identity=_resolve)
    gate.register("dead_letter_replay", "op", _runs, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id="maker-id"
    )
    assert approval_id is not None
    task = asyncio.create_task(
        gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    )
    await asyncio.wait_for(store.entered.wait(), _WAIT_S)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, _WAIT_S)
    return gate, store, approval_id


async def test_drain_waits_for_a_write_whose_caller_was_cancelled(engine: Engine) -> None:
    gate, store, approval_id = await _orphan_a_held_approved_write(engine)
    drain = asyncio.create_task(gate.drain(timeout=_WAIT_S))
    await asyncio.sleep(0.05)
    assert not drain.done(), "the drain returned while the write was still held"
    store.release.set()
    assert await asyncio.wait_for(drain, _WAIT_S) == []
    # No polling: the drain returned only once the whole outcome write had finished.
    assert await _status_of(engine, approval_id) == "approved"
    assert len(await engine.store.list_audit(action="approval.approved")) == 1


async def test_drain_is_bounded_and_scoped_to_its_own_gate(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The deadline returns the approval ids still running and logs them. A second gate holds none
    of the first gate's writes, which a module-wide set could not tell apart."""
    from tests._pending_approval_store_contract import _resolve

    gate, store, approval_id = await _orphan_a_held_approved_write(engine)
    other = ApprovalGate(engine.store, ON, resolve_identity=_resolve)
    assert await asyncio.wait_for(other.drain(timeout=_WAIT_S), 1.0) == []
    with caplog.at_level(logging.ERROR, logger="messagefoundry.api.approvals"):
        assert await gate.drain(timeout=0.05) == [approval_id]
    assert any(
        r.levelno == logging.ERROR
        and approval_id in r.getMessage()
        and "still running" in r.getMessage()
        for r in caplog.records
    )
    store.release.set()
    assert await gate.drain(timeout=_WAIT_S) == []
    assert await _status_of(engine, approval_id) == "approved"


async def test_drain_also_waits_for_a_write_started_while_it_waits(engine: Engine) -> None:
    gate = ApprovalGate(engine.store, ON)
    first_go, second_go = asyncio.Event(), asyncio.Event()
    finished: list[str] = []

    async def _write(name: str, go: asyncio.Event) -> None:
        await go.wait()
        finished.append(name)

    first = asyncio.create_task(gate._shielded(_write("first", first_go), "a1"))
    await asyncio.sleep(0)
    drain = asyncio.create_task(gate.drain(timeout=_WAIT_S))
    await asyncio.sleep(0)
    second = asyncio.create_task(gate._shielded(_write("second", second_go), "a2"))
    await asyncio.sleep(0)
    first_go.set()
    await asyncio.sleep(0.05)
    assert not drain.done(), "the drain returned while a write started during it was running"
    second_go.set()
    assert await asyncio.wait_for(drain, _WAIT_S) == []
    assert finished == ["first", "second"]
    await asyncio.gather(first, second)


async def _probe_rows(db_path: Path) -> list[Any]:
    """Read the audit through a second store, after the app's own store has closed."""
    from messagefoundry.store import open_store, sqlite_settings

    store = await open_store(sqlite_settings(db_path), keyless_chain_refusal=None)
    try:
        return list(await store.list_audit(action="approval.drain_probe"))
    finally:
        await store.close()


async def _run_an_orphaned_write_through_shutdown(db_path: Path, *, drained: bool) -> None:
    """Start a slow shielded write inside the managed lifespan, cancel its caller, then shut down."""
    from messagefoundry.api import create_managed_app

    app = create_managed_app(db_path=db_path, egress_settings=EgressSettings(deny_by_default=False))
    finished = asyncio.Event()
    # Undrained, the write is held until the lifespan has exited, so the control cannot pass by a
    # slow teardown. Drained, it sleeps briefly, and the drain has to wait for it.
    after_exit = asyncio.Event()
    async with app.router.lifespan_context(app):
        gate: ApprovalGate = app.state.approval_gate
        store = app.state.engine.store
        if not drained:

            async def _no_drain(timeout: float = 0.0) -> list[str]:
                return []

            gate.drain = _no_drain  # type: ignore[method-assign]

        async def _slow_write() -> None:
            try:
                if drained:
                    await asyncio.sleep(0.3)
                else:
                    await after_exit.wait()
                await store.record_audit("approval.drain_probe", actor="checker")
            finally:
                finished.set()

        caller = asyncio.create_task(gate._shielded(_slow_write(), "probe-id"))
        await asyncio.sleep(0)
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
    # Undrained, the write is still running here; let it meet the closed store and finish.
    after_exit.set()
    await asyncio.wait_for(finished.wait(), _WAIT_S)
    await asyncio.sleep(0.05)


async def test_shutdown_drains_an_orphaned_write_before_the_store_closes(tmp_path: Path) -> None:
    db_path = tmp_path / "drained.db"
    await _run_an_orphaned_write_through_shutdown(db_path, drained=True)
    assert len(await _probe_rows(db_path)) == 1, "the write did not land before the store closed"


async def test_the_drain_assertion_can_fail(tmp_path: Path) -> None:
    """Control: with the drain neutralised the same write misses the store, so the test above is
    measuring the drain and not a write that was always fast enough."""
    db_path = tmp_path / "undrained.db"
    await _run_an_orphaned_write_through_shutdown(db_path, drained=False)
    assert await _probe_rows(db_path) == []


async def test_a_drain_failure_does_not_skip_engine_stop(tmp_path: Path) -> None:
    """The drain runs BEFORE engine.stop(), and a drain that raises must not skip the stop, or the
    store's non-daemon worker keeps the process alive."""
    from messagefoundry.api import create_managed_app

    app = create_managed_app(
        db_path=tmp_path / "boom.db", egress_settings=EgressSettings(deny_by_default=False)
    )
    calls: list[str] = []
    real_stop: list[Any] = []
    try:
        async with app.router.lifespan_context(app):
            engine = app.state.engine
            real_stop.append(engine.stop)
            gate: ApprovalGate = app.state.approval_gate

            async def _boom(timeout: float = 0.0) -> list[str]:
                calls.append("drain")
                raise RuntimeError("PROBE: deliberate drain failure")

            async def _spy_stop() -> None:
                calls.append("stop")
                await real_stop[0]()

            gate.drain = _boom  # type: ignore[method-assign]
            engine.stop = _spy_stop
    finally:
        if real_stop and "stop" not in calls:
            await real_stop[0]()
    assert calls == ["drain", "stop"]
