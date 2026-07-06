# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WP-L3-04: dual-control (maker-checker) approval for high-value actions (ASVS 2.3.5).

The replay endpoint stands in for a gated high-value action (it needs no configured graph). With
``[approvals]`` off it executes inline; on it is held for a *distinct* second approver who releases it.
"""

from __future__ import annotations

import asyncio

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import ApprovalsSettings, AuthSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import OutboxStatus

PW = "a-strong-test-passphrase"
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
ON = ApprovalsSettings(enabled=True, operations=["dead_letter_replay", "connection_purge"])
OFF = ApprovalsSettings(enabled=False)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "approvals.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


def _client(
    engine: Engine, service: AuthService, approvals: ApprovalsSettings
) -> httpx.AsyncClient:
    app = create_app(engine, auth=service, approvals=approvals)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    uid = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(uid)  # clear forced first-login rotation (WP-L3-12)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )


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
        approval_id="expired1",
        operation="dead_letter_replay",
        params="{}",
        requester="op",
        requested_at=1.0,
        expires_at=2.0,
    )
    async with _client(engine, service, ON) as c:
        admin = await _token(c, "approver")
        expired = await c.post("/approvals/expired1/approve", headers=admin)
        assert expired.status_code == 409 and "expired" in expired.json()["detail"]
        assert (await c.post("/approvals/nope/approve", headers=admin)).status_code == 404
        # an expired request is also absent from the pending queue
        assert (await c.get("/approvals", headers=admin)).json()["approvals"] == []


async def test_purge_dual_control_skips_running_outbound(engine: Engine, tmp_path: Path) -> None:
    # Findings #1/#4/#11 — the LOAD-BEARING dual-control guard. A purge held while the outbound was
    # stopped, then RELEASED after the operator re-started the outbound, must cancel NOTHING: the
    # require-quiesced re-check lives inside the `_purge` approval executor (ApprovalGate.approve runs it
    # directly and has already flipped the row to 'approved', so it returns a fail-closed SKIP rather
    # than raising, which would strand the row approved-but-unexecuted).
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
