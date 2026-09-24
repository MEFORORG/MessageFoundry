# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""WP-L3-04: dual-control (maker-checker) approval for high-value actions (ASVS 2.3.5).

The replay endpoint stands in for a gated high-value action (it needs no configured graph). With
``[approvals]`` off it executes inline; on it is held for a *distinct* second approver who releases it.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.approvals import ApprovalGate
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType, RetryPolicy
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
    # Approvals is a step-up admin flow, not an MFA test: pin require_mfa=False so the BACKLOG #187
    # secure default (require_mfa now ON) doesn't 403 the request before the approval path is exercised.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
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
    uid = await service.create_local_user(
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
        uid, password_hash=user.password_hash, must_change_password=False
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
# approve() moves the row to 'approved' BEFORE running the executor, and that ordering is
# load-bearing (it guards the double-approve race). The gap this closes is what happens when the
# executor then raises: without compensation the row is left asserting an operation that never
# happened, AND no approval.approved row is written either, so the store carries a released
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


async def test_raising_executor_rolls_the_row_out_of_approved(engine: Engine) -> None:
    """The row must NOT be left at 'approved' for an operation that did not run."""
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
    # The exception TYPE is recorded, never its message: executor text can carry connection names,
    # paths or params, and the audit log is not a PHI sink.
    assert detail["error"] == "RuntimeError"
    assert "exploded" not in str(failed["detail"])


async def test_compensation_cannot_clobber_an_already_rejected_row(engine: Engine) -> None:
    """The compensating transition is guarded on 'approved', so it can only ever move a row this
    gate itself released -- never one another caller rejected or expired."""
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
        from_status="approved",
    )
    assert moved is False
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None
    assert str(row["status"]) == "rejected"


async def test_pending_approval_store_contract(engine: Engine) -> None:
    """The SQLite leg of the shared ``requester_user_id`` store contract (BACKLOG #1540).

    The same body runs against live PostgreSQL and SQL Server, so the one round-trip the three SQL
    bodies owe is asserted once rather than worded three times."""
    from tests._pending_approval_store_contract import _assert_pending_approval_contract

    await _assert_pending_approval_contract(engine.store)


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
        await engine.store.set_user_username(jdoe_id, "jdoe2")
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
        await engine.store.set_user_username(jdoe_id, "jdoe2")
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
        await engine.store._db.execute(
            "UPDATE pending_approvals SET requester_user_id = NULL WHERE id = ?", (approval_id,)
        )
        await engine.store._db.commit()
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
