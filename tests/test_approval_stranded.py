# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1562 residuals: a release stranded in ``executing``, and what a restart makes of one.

- The operator's way out (residual 1, owner-delegated decision d20261029T205247402-81159c):
  ``GET /approvals/executing`` lists every ``executing`` release, and
  ``POST /approvals/{id}/interrupt`` moves one to ``interrupted`` after judging its owner in three
  tiers: live in this process, a cluster node's heartbeat, or an operator's attestation. An
  unpinned cluster node's old claims (residual 4) read as a lapsed heartbeat.
- The restart keeps the claim time in ``decided_at`` (residual 6) and reads other owners' rows
  apart from its own (residual 7). It claims no outcome from the audit trail: residual 3 was
  dropped by Manager decision d20261109T215156567-4334fc, since ``list_audit`` checks no row MAC.
  A second app over the same engine leaves the first app's live releases alone (residual 5).
- The interrupt refuses the original requester and reads ``attest_owner_stopped`` strictly (the
  same decision).
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import approvals as approvals_module
from messagefoundry.api import create_app
from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.auth import Permission, Role
from messagefoundry.config.settings import ApprovalsSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import ANY_CLAIM_OWNER, AuditAppend, AuditVerdict
from tests._bound_proof import reproving_transport
from tests._pending_approval_store_contract import _APPROVER as APPROVER
from tests._pending_approval_store_contract import _REQUESTER_ID as REQUESTER_ID
from tests._pending_approval_store_contract import (
    _audit_rows_for,
    _claimed_directly,
    _resolve,
    _StandingStore,
)
from tests.test_approvals import PW, _add, _service, _token

ON = ApprovalsSettings(enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=0.0)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "stranded.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


def _liveness(fresh: bool | None = None, *, fails: bool = False) -> Any:
    """A heartbeat reader answering ``fresh`` for every node, recording what it was asked."""
    asked: list[str] = []

    async def _read(node_id: str) -> bool | None:
        asked.append(node_id)
        if fails:
            raise OSError("PROBE: nodes table unreachable")
        return fresh

    _read.asked = asked  # type: ignore[attr-defined]
    return _read


def _gate(engine: Engine, *, owner: str = "engine", liveness: Any = None) -> ApprovalGate:
    return ApprovalGate(
        _StandingStore(engine.store),
        ON,
        resolve_identity=_resolve,
        claim_owner=owner,
        node_liveness=liveness,
    )


async def _row(engine: Engine, approval_id: str) -> Any:
    found = await engine.store.get_pending_approval(approval_id)
    assert found is not None
    return found


async def _audit(engine: Engine, action: str, approval_id: str) -> list[Any]:
    return await _audit_rows_for(engine.store, action, approval_id)


async def _running_release(
    gate: ApprovalGate,
) -> tuple[str, asyncio.Task[dict[str, Any]], asyncio.Event]:
    """A release ``gate`` is running now: its executor holds until the returned event is set."""
    entered, leave = asyncio.Event(), asyncio.Event()

    async def _blocks(_p: Mapping[str, Any]) -> dict[str, Any]:
        entered.set()
        await leave.wait()
        return {"ran": True}

    gate.register("dead_letter_replay", "op", _blocks, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id="maker-id"
    )
    assert approval_id is not None
    release = asyncio.create_task(
        gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    )
    await entered.wait()
    return approval_id, release, leave


async def _stranded(engine: Engine, owner: str | None) -> str:
    return await _claimed_directly(engine.store, claim_owner=owner, claimed_at=time.time() - 30.0)


# --- the store guard the interrupt writes through ----------------------------------------------


async def test_a_move_guarded_on_the_claim_owner_lands_only_on_that_owner(engine: Engine) -> None:
    store = engine.store
    owned = await _stranded(engine, "node:a")
    unowned = await _stranded(engine, None)

    async def _move(approval_id: str, guard: Any) -> bool:
        return await store.decide_pending_approval(
            approval_id,
            status="interrupted",
            approver=APPROVER,
            decided_at=1.0,
            from_status="executing",
            from_claim_owner=guard,
        )

    assert not await _move(owned, "node:b")
    assert not await _move(owned, None), "None guards on no owner, not on any owner"
    assert not await _move(unowned, "node:a")
    assert str((await _row(engine, owned))["status"]) == "executing"
    assert await _move(owned, "node:a")
    assert await _move(unowned, None)
    # The default guards nothing, as every caller before this change relied on.
    third = await _stranded(engine, "shard:x")
    assert await _move(third, ANY_CLAIM_OWNER)


async def test_the_sibling_scan_reads_only_other_owners_rows(engine: Engine) -> None:
    """Residual 7: own and unowned rows are left out in SQL, so they cannot fill the cap."""
    store = engine.store
    mine = await _stranded(engine, "engine")
    legacy = await _stranded(engine, None)
    sibling = await _stranded(engine, "shard:other")
    others = {str(r["id"]) for r in await store.list_executing_approvals(not_claimed_by="engine")}
    assert others == {sibling}
    every = {str(r["id"]) for r in await store.list_executing_approvals()}
    assert {mine, legacy, sibling} <= every
    with pytest.raises(ValueError):
        await store.list_executing_approvals(claim_owner="engine", not_claimed_by="engine")


async def test_the_restart_scans_siblings_with_the_owner_filter(engine: Engine) -> None:
    """Residual 7, at the gate: the sibling read passes this process's owner to exclude, and its
    own rows past the cap of an unfiltered read no longer hide a sibling's."""
    calls: list[dict[str, Any]] = []

    class _Spy(_StandingStore):
        async def list_executing_approvals(self, **kw: Any) -> Any:
            calls.append(kw)
            if "claim_owner" in kw:
                return []  # our own row stays 'executing', as one whose move failed does
            # The cap at one row: unfiltered, the oldest row, ours, would be all a scan saw.
            return await self._store.list_executing_approvals(**{**kw, "limit": 1})

    await _claimed_directly(engine.store, claim_owner="engine", claimed_at=1_000.0)
    sibling = await _claimed_directly(engine.store, claim_owner="shard:b", claimed_at=2_000.0)
    gate = ApprovalGate(_Spy(engine.store), ON, resolve_identity=_resolve, claim_owner="engine")
    found = await gate.reconcile_after_restart()
    assert {"not_claimed_by": "engine"} in calls
    assert found.foreign == (sibling,)


async def test_a_failed_sibling_read_keeps_the_moved_rows(
    engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """The sibling read runs after this process's rows moved. When it fails, those moves are
    still returned and announced, and the failure is logged on its own."""
    mine = await _claimed_directly(engine.store, claim_owner="engine", claimed_at=1_000.0)
    await _claimed_directly(engine.store, claim_owner="shard:b", claimed_at=2_000.0)

    class _SiblingReadFails(_StandingStore):
        async def list_executing_approvals(self, **kw: Any) -> Any:
            if "not_claimed_by" in kw:
                raise OSError("PROBE: sibling read failed")
            return await self._store.list_executing_approvals(**kw)

    gate = ApprovalGate(
        _SiblingReadFails(engine.store), ON, resolve_identity=_resolve, claim_owner="engine"
    )
    with caplog.at_level(logging.WARNING, logger="messagefoundry.api.approvals"):
        found = await gate.reconcile_after_restart()
    assert found.interrupted == (mine,) and found.foreign == ()
    assert str((await _row(engine, mine))["status"]) == "interrupted"
    messages = [r.getMessage() for r in caplog.records]
    assert any("now 'interrupted'" in m and mine in m for m in messages), messages
    assert any("reading other claim owners" in m for m in messages), messages


# --- the restart (residual 6; residual 3 dropped) ------------------------------------------------


async def _outcome_row(engine: Engine, action: str, approval_id: str, *, actor: str) -> None:
    await engine.store.record_audit(
        action, actor=actor, detail=json.dumps({"approval_id": approval_id, "result": {}})
    )


@pytest.mark.parametrize("action", ["approval.approved", "approval.failed"])
async def test_a_restart_claims_no_outcome_from_the_trail(engine: Engine, action: str) -> None:
    """Residual 3 is dropped (decision d20261109T215156567-4334fc): an outcome row in the trail,
    read through list_audit whose row MAC nobody checks, never settles a leftover release. It
    moves to 'interrupted', keeping its claim time, and an operator records what happened."""
    approval_id = await _stranded(engine, "engine")
    claimed_at = float((await _row(engine, approval_id))["decided_at"])
    await _outcome_row(engine, action, approval_id, actor=APPROVER)

    # A chain that verifies under a held key: the strongest trail the dropped settle trusted.
    class _Keyed(_StandingStore):
        async def verify_audit_chain(self, **_kw: Any) -> Any:
            return AuditVerdict(True, "clean")

    gate = ApprovalGate(_Keyed(engine.store), ON, resolve_identity=_resolve)
    found = await gate.reconcile_after_restart()
    assert found.interrupted == (approval_id,)
    row = await _row(engine, approval_id)
    assert str(row["status"]) == "interrupted"
    assert float(row["decided_at"]) == claimed_at, "the claim time is kept (residual 6)"
    [interrupted] = await _audit(engine, "approval.interrupted", approval_id)
    detail = json.loads(str(interrupted["detail"]))
    assert detail["reason"] == "engine_restart" and str(interrupted["actor"]) == "system"


async def test_a_restart_never_reads_the_audit_trail(engine: Engine) -> None:
    """Nothing in the reconcile reads the trail now, so a chain walk or a trail read that would
    fail cannot hold up or abort the start."""
    approval_id = await _stranded(engine, "engine")

    reads: list[str] = []

    class _NoTrail(_StandingStore):
        async def verify_audit_chain(self, **kw: Any) -> Any:
            reads.append("verify_audit_chain")
            return await self._store.verify_audit_chain(**kw)

        async def list_audit(self, **kw: Any) -> Any:
            reads.append("list_audit")
            return await self._store.list_audit(**kw)

    gate = ApprovalGate(_NoTrail(engine.store), ON, resolve_identity=_resolve)
    assert (await gate.reconcile_after_restart()).interrupted == (approval_id,)
    assert reads == []


async def test_a_second_app_leaves_the_first_apps_live_release_executing(engine: Engine) -> None:
    """Residual 5: a second create_app lifespan over the same engine reconciles under the same
    owner, so it used to take the first app's running release for a leftover and move it to
    'interrupted'. A release any gate in this process is running is left alone, and the second
    app's interrupt route refuses it. Control: a row left over from before still moves."""
    first = create_app(engine, approvals=ON)
    async with first.router.lifespan_context(first):
        gate: ApprovalGate = first.state.approval_gate
        # The gate's account reads, answered without provisioning users, as the contract does.
        gate._store = _StandingStore(engine.store)
        gate._resolve_identity = _resolve
        live, release, leave = await _running_release(gate)
        leftover = await _stranded(engine, "engine")
        try:
            second = create_app(engine, approvals=ON)
            async with second.router.lifespan_context(second):
                assert str((await _row(engine, live))["status"]) == "executing"
                assert str((await _row(engine, leftover))["status"]) == "interrupted"
                # Nor does the second app's interrupt route take the live release.
                with pytest.raises(ApprovalError) as refused:
                    await second.state.approval_gate.interrupt_stranded(
                        live,
                        actor="operator",
                        actor_user_id="operator-id",
                        attest_owner_stopped=True,
                    )
                assert refused.value.status == 409
                assert "is running this release now" in refused.value.detail
                assert str((await _row(engine, live))["status"]) == "executing"
        finally:
            leave.set()
        await asyncio.wait_for(release, 10.0)
    assert str((await _row(engine, live))["status"]) == "approved"


class _SettlesFail(_StandingStore):
    """Both of _settle's writes fail, so the release ends with its row still 'executing'."""

    async def decide_pending_approval(self, approval_id: str, **kw: Any) -> bool:
        if kw["status"] == "approved":
            raise OSError("PROBE: store unreachable")
        return bool(await self._store.decide_pending_approval(approval_id, **kw))


async def _claim_left_unsettled(gate: ApprovalGate) -> str:
    """A release ``gate`` claims and runs, whose outcome it never records."""
    gate.register("dead_letter_replay", "op", _runs, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id="maker-id"
    )
    assert approval_id is not None
    await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert approval_id not in gate._releasing, "the release has ended"
    return approval_id


async def _runs(_p: Mapping[str, Any]) -> dict[str, Any]:
    return {"ran": True}


async def test_a_second_app_recovers_an_unsettled_claim_no_gate_runs(engine: Engine) -> None:
    """As on main: a claim of this life that no gate runs any more (both settle writes failed) is
    moved to 'interrupted' by a second app's start, with reason engine_restart. Only a release a
    gate in this process is running is left alone."""
    first = create_app(engine, approvals=ON)
    async with first.router.lifespan_context(first):
        gate1: ApprovalGate = first.state.approval_gate
        gate1._store = _SettlesFail(engine.store)
        gate1._resolve_identity = _resolve
        unsettled = await _claim_left_unsettled(gate1)
        assert str((await _row(engine, unsettled))["status"]) == "executing"
        second = create_app(engine, approvals=ON)
        async with second.router.lifespan_context(second):
            assert str((await _row(engine, unsettled))["status"]) == "interrupted"
    [row] = await _audit(engine, "approval.interrupted", unsettled)
    assert json.loads(str(row["detail"]))["reason"] == "engine_restart"


async def test_a_release_running_over_another_store_object_is_not_reconciled(
    engine: Engine,
) -> None:
    """Residual 5: a release a gate in this process is running is left alone even when that gate
    was built over a different store object for the same database, as the interrupt route leaves
    it. Control: a row no gate in this process runs still moves."""
    wrapped = _gate(engine)  # built over a _StandingStore, a store object of its own
    live, release, leave = await _running_release(wrapped)
    leftover = await _stranded(engine, "engine")
    try:
        found = await ApprovalGate(engine.store, ON).reconcile_after_restart()
        assert found.interrupted == (leftover,)
        assert str((await _row(engine, live))["status"]) == "executing"
    finally:
        leave.set()
        await asyncio.wait_for(release, 10.0)


# --- GET /approvals/executing and the three tiers (residuals 1 and 4) ------------------------------


async def test_the_listing_judges_each_owner(engine: Engine) -> None:
    liveness = _liveness(False)
    node = await _stranded(engine, "node:gone-host:123:abcd1234")
    shard = await _stranded(engine, "shard:b")
    plain = await _stranded(engine, "engine")
    unowned = await _stranded(engine, None)
    gate = _gate(engine, owner="node:me", liveness=liveness)

    listed = {r["id"]: r for r in await gate.list_executing()}
    assert listed[node]["liveness"] == "owner_heartbeat_lapsed"
    assert listed[node]["interrupt"] == "allowed"
    for approval_id in (shard, plain, unowned):
        assert listed[approval_id]["liveness"] == "attestation_required"
        assert listed[approval_id]["interrupt"] == "needs_attestation"
    assert listed[node]["claim_owner"] == "node:gone-host:123:abcd1234"
    assert listed[node]["approver"] == APPROVER and listed[node]["this_process"] is False
    assert "params" not in listed[node]
    assert liveness.asked == ["gone-host:123:abcd1234"]  # one read per node per listing


async def test_a_lapsed_node_heartbeat_lets_the_interrupt_move_the_row(engine: Engine) -> None:
    """Residual 4: an unpinned node comes back under a new id; its old claim reads as lapsed."""
    approval_id = await _stranded(engine, "node:old-random-id")
    claimed_at = float((await _row(engine, approval_id))["decided_at"])
    gate = _gate(engine, owner="node:new-random-id", liveness=_liveness(False))
    out = await gate.interrupt_stranded(
        approval_id, actor="operator", actor_user_id="operator-id", client="10.0.0.9"
    )
    assert out["status"] == "interrupted" and out["liveness"] == "owner_heartbeat_lapsed"
    row = await _row(engine, approval_id)
    assert str(row["status"]) == "interrupted" and str(row["approver"]) == APPROVER
    assert float(row["decided_at"]) == claimed_at
    [audit] = await _audit(engine, "approval.interrupted", approval_id)
    assert str(audit["actor"]) == "operator" and str(audit["client"]) == "10.0.0.9"
    detail = json.loads(str(audit["detail"]))
    assert detail["reason"] == "operator_interrupt"
    assert detail["liveness"] == "owner_heartbeat_lapsed"
    assert detail["owner_stopped_attested"] is False
    assert detail["claim_owner"] == "node:old-random-id" and detail["claimed_at"] == claimed_at
    # It now takes the ordinary resolve path.
    resolved = await gate.resolve_interrupted(
        approval_id,
        outcome="effects_not_applied",
        resolver="operator",
        resolver_user_id="operator-id",
    )
    assert resolved["status"] == "resolved_not_applied"


@pytest.mark.parametrize(
    ("liveness", "status", "verdict"),
    [
        (_liveness(True), 409, "owner_heartbeat_fresh"),
        (_liveness(fails=True), 503, "owner_heartbeat_unreadable"),
        (_liveness(None), 409, "owner_heartbeat_unavailable"),
        (None, 409, "owner_heartbeat_unavailable"),
    ],
)
async def test_a_node_owner_that_may_be_live_is_refused(
    engine: Engine, liveness: Any, status: int, verdict: str
) -> None:
    approval_id = await _stranded(engine, "node:peer")
    gate = _gate(engine, owner="node:me", liveness=liveness)
    [listed] = [r for r in await gate.list_executing() if r["id"] == approval_id]
    assert listed["liveness"] == verdict and listed["interrupt"] == "refused"
    with pytest.raises(ApprovalError) as refused:
        await gate.interrupt_stranded(
            approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
        )
    assert refused.value.status == status
    assert str((await _row(engine, approval_id))["status"]) == "executing"
    assert await _audit(engine, "approval.interrupted", approval_id) == []


@pytest.mark.parametrize("owner", ["shard:b", "engine", None, "something-unrecognised", "node:"])
async def test_an_owner_with_no_heartbeat_needs_an_attestation(
    engine: Engine, owner: str | None
) -> None:
    approval_id = await _stranded(engine, owner)
    gate = _gate(engine, owner="shard:a", liveness=_liveness(False))
    with pytest.raises(ApprovalError) as refused:
        await gate.interrupt_stranded(approval_id, actor="operator", actor_user_id="operator-id")
    assert refused.value.status == 409 and "attest_owner_stopped" in refused.value.detail
    assert str((await _row(engine, approval_id))["status"]) == "executing"
    out = await gate.interrupt_stranded(
        approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
    )
    assert out["liveness"] == "attestation_required"
    [audit] = await _audit(engine, "approval.interrupted", approval_id)
    assert json.loads(str(audit["detail"]))["owner_stopped_attested"] is True
    assert str((await _row(engine, approval_id))["status"]) == "interrupted"


async def test_a_release_running_in_this_process_is_refused(engine: Engine) -> None:
    """Tier one: this gate's own live release, under an owner the attestation would pass."""
    gate = _gate(engine)
    approval_id, release, leave = await _running_release(gate)
    try:
        [listed] = [r for r in await gate.list_executing() if r["id"] == approval_id]
        assert listed["liveness"] == "releasing_here" and listed["this_process"] is True
        with pytest.raises(ApprovalError) as refused:
            await gate.interrupt_stranded(
                approval_id,
                actor="operator",
                actor_user_id="operator-id",
                attest_owner_stopped=True,
            )
        assert refused.value.status == 409
    finally:
        leave.set()
        await release
    assert str((await _row(engine, approval_id))["status"]) == "approved"
    # Control: once the release is done, the gate no longer counts it as running.
    assert approval_id not in gate._releasing


async def test_a_lost_claim_does_not_untrack_the_release_that_won(engine: Engine) -> None:
    """A second approve that reads the row as pending, then loses the claim to the running one,
    leaves that one tracked."""

    class _StaleRead(_StandingStore):
        stale: Any = None

        async def get_pending_approval(self, approval_id: str) -> Any:
            if self.stale is not None:
                return self.stale
            return await self._store.get_pending_approval(approval_id)

    store = _StaleRead(engine.store)
    gate = ApprovalGate(store, ON, resolve_identity=_resolve, claim_owner="engine")
    entered, leave = asyncio.Event(), asyncio.Event()

    async def _blocks(_p: Mapping[str, Any]) -> dict[str, Any]:
        entered.set()
        await leave.wait()
        return {"ran": True}

    gate.register("dead_letter_replay", "op", _blocks, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id="maker-id"
    )
    assert approval_id is not None
    store.stale = await engine.store.get_pending_approval(approval_id)  # read while pending
    winner = asyncio.create_task(
        gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    )
    await entered.wait()
    try:
        with pytest.raises(ApprovalError) as lost:
            await gate.approve(approval_id, approver="other", approver_user_id="other-id")
        assert lost.value.detail == "request was already decided", "it reached the claim"
        assert gate._releasing[approval_id] == 1
    finally:
        store.stale = None
        leave.set()
        await winner
    assert approval_id not in gate._releasing


async def test_a_release_stays_tracked_until_its_outcome_write_ends(engine: Engine) -> None:
    """A cancelled approve leaves its outcome write running, and the release counts as running
    here until that write ends; an interrupt's own write never does."""
    entered, leave, write_held, write_go = (asyncio.Event() for _ in range(4))

    class _SlowOutcome(_StandingStore):
        async def decide_pending_approval(self, approval_id: str, **kw: Any) -> bool:
            if kw.get("status") == "approved":
                write_held.set()
                await write_go.wait()
            return bool(await self._store.decide_pending_approval(approval_id, **kw))

    gate = ApprovalGate(_SlowOutcome(engine.store), ON, resolve_identity=_resolve)

    async def _blocks(_p: Mapping[str, Any]) -> dict[str, Any]:
        entered.set()
        await leave.wait()
        return {"ran": True}

    gate.register("dead_letter_replay", "op", _blocks, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id="maker-id"
    )
    assert approval_id is not None
    release = asyncio.create_task(
        gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    )
    await entered.wait()
    leave.set()
    await write_held.wait()
    release.cancel()
    with pytest.raises(asyncio.CancelledError):
        await release
    assert approval_id in gate._releasing, "the outcome write is still running"
    with pytest.raises(ApprovalError) as refused:
        await gate.interrupt_stranded(
            approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
        )
    assert refused.value.status == 409
    write_go.set()
    await gate.drain()
    assert approval_id not in gate._releasing
    assert str((await _row(engine, approval_id))["status"]) == "approved"


async def test_an_interrupt_in_flight_does_not_read_as_a_release(engine: Engine) -> None:
    held, go = asyncio.Event(), asyncio.Event()

    class _SlowMove(_StandingStore):
        async def decide_pending_approval(self, approval_id: str, **kw: Any) -> bool:
            if kw.get("status") == "interrupted":
                held.set()
                await go.wait()
            return bool(await self._store.decide_pending_approval(approval_id, **kw))

    approval_id = await _stranded(engine, "shard:b")
    gate = ApprovalGate(_SlowMove(engine.store), ON, resolve_identity=_resolve)
    first = asyncio.create_task(
        gate.interrupt_stranded(
            approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
        )
    )
    await held.wait()
    try:
        [listed] = [r for r in await gate.list_executing() if r["id"] == approval_id]
        assert listed["liveness"] == "attestation_required"
    finally:
        go.set()
        await first


@pytest.mark.parametrize("combined_raises", [False, True])
async def test_an_outcome_whose_row_was_interrupted_elsewhere(
    engine: Engine,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    combined_raises: bool,
) -> None:
    """An operator interrupt from another process moves the row while this process still runs
    the release. The combined outcome write then finds the row moved, and the outcome row is
    written alone. Where that combined write RAISES instead, main's read-back (vault BACKLOG
    #3193 N1) decides: the row reads back moved by another caller, so no row is written alone
    and the lost detail is logged."""
    entered, leave = asyncio.Event(), asyncio.Event()

    class _InterruptedMeanwhile(_StandingStore):
        async def decide_pending_approval(self, approval_id: str, **kw: Any) -> bool:
            if combined_raises and kw.get("status") == "approved" and kw.get("audit") is not None:
                raise OSError("PROBE: combined write failed")
            return bool(await self._store.decide_pending_approval(approval_id, **kw))

    gate = ApprovalGate(_InterruptedMeanwhile(engine.store), ON, resolve_identity=_resolve)

    async def _blocks(_p: Mapping[str, Any]) -> dict[str, Any]:
        entered.set()
        await leave.wait()
        return {"ran": True}

    gate.register("dead_letter_replay", "op", _blocks, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id="maker-id"
    )
    assert approval_id is not None
    release = asyncio.create_task(
        gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    )
    await entered.wait()
    # Another process's operator interrupts it. That process sees none of this one's releases.
    monkeypatch.setattr(approvals_module, "_releasing_in_process", lambda _id: False)
    elsewhere = _gate(engine, owner="shard:other")
    await elsewhere.interrupt_stranded(
        approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
    )
    leave.set()
    with caplog.at_level(logging.ERROR, logger="messagefoundry.api.approvals"):
        await release
    assert str((await _row(engine, approval_id))["status"]) == "interrupted"
    approved = await _audit(engine, "approval.approved", approval_id)
    if combined_raises:
        assert approved == []
        [lost] = [r.getMessage() for r in caplog.records if "Lost detail" in r.getMessage()]
        assert "'interrupted'" in lost
    else:
        [row] = approved
        assert str(row["actor"]) == "checker"


async def test_a_cut_off_release_whose_interrupted_write_committed_writes_one_row(
    engine: Engine,
) -> None:
    """Decision d20261109T215156567-4334fc, the duplicate interrupted row: the combined
    'interrupted' write COMMITS and its reply is lost. The read-back finds the row at
    'interrupted' with this write's own decision time, so no second approval.interrupted row,
    with recorded=false, is written beside the first. An operator interrupt or a restart keeps
    the claim time, so its move cannot be mistaken for this one."""

    class _ReplyLost(_StandingStore):
        async def decide_pending_approval(self, approval_id: str, **kw: Any) -> bool:
            moved = bool(await self._store.decide_pending_approval(approval_id, **kw))
            audit: AuditAppend | None = kw.get("audit")
            if audit is not None and audit.action == "approval.interrupted":
                raise sqlite3.OperationalError("PROBE: connection reset after COMMIT")
            return moved

    approval_id = await _stranded(engine, "engine")
    gate = ApprovalGate(_ReplyLost(engine.store), ON, resolve_identity=_resolve)
    await gate._record_interrupted_execution(
        approval_id,
        operation="dead_letter_replay",
        approver=APPROVER,
        requester="r",
        client=None,
    )
    assert str((await _row(engine, approval_id))["status"]) == "interrupted"
    [only] = await _audit(engine, "approval.interrupted", approval_id)
    assert json.loads(str(only["detail"]))["recorded"] is True


async def test_an_interrupt_of_a_row_not_executing_answers_409(engine: Engine) -> None:
    approval_id = await _stranded(engine, "shard:b")
    gate = _gate(engine)
    await gate.interrupt_stranded(
        approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
    )
    with pytest.raises(ApprovalError) as again:
        await gate.interrupt_stranded(
            approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
        )
    assert again.value.status == 409
    assert len(await _audit(engine, "approval.interrupted", approval_id)) == 1
    with pytest.raises(ApprovalError) as missing:
        await gate.interrupt_stranded(
            "0" * 32, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
        )
    assert missing.value.status == 404


async def test_an_interrupt_whose_audit_row_is_refused_moves_nothing(engine: Engine) -> None:
    approval_id = await _stranded(engine, "shard:b")

    class _AuditRefused(_StandingStore):
        async def decide_pending_approval(self, approval_id: str, **kw: Any) -> bool:
            audit: AuditAppend | None = kw.get("audit")
            if audit is not None and audit.action == "approval.interrupted":
                raise OSError("PROBE: audit log unreachable")
            return bool(await self._store.decide_pending_approval(approval_id, **kw))

    gate = ApprovalGate(_AuditRefused(engine.store), ON, resolve_identity=_resolve)
    with pytest.raises(ApprovalError) as fault:
        await gate.interrupt_stranded(
            approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
        )
    assert fault.value.status == 503
    assert str((await _row(engine, approval_id))["status"]) == "executing"


async def test_the_requester_cannot_interrupt_their_own_release(engine: Engine) -> None:
    """Decision d20261109T215156567-4334fc: an interrupt rests on its actor's word, so the
    requester is refused, as on the resolve it leads to, attested or not, and keyed on the user
    id rather than the name."""
    approval_id = await _stranded(engine, "shard:b")
    gate = _gate(engine)
    for attest in (False, True):
        with pytest.raises(ApprovalError) as refused:
            await gate.interrupt_stranded(
                approval_id,
                actor="renamed-requester",
                actor_user_id=REQUESTER_ID,
                attest_owner_stopped=attest,
            )
        assert refused.value.status == 403
    assert str((await _row(engine, approval_id))["status"]) == "executing"
    assert await _audit(engine, "approval.interrupted", approval_id) == []
    # Control: anyone else with the same attestation moves it.
    out = await gate.interrupt_stranded(
        approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
    )
    assert out["status"] == "interrupted"


async def test_a_release_with_no_requester_id_cannot_be_interrupted(engine: Engine) -> None:
    """Fail closed, as the resolve does: with no requester id the requester cannot be told
    apart from anyone else."""
    approval_id = "f" * 32
    await engine.store.create_pending_approval(
        approval_id=approval_id,
        operation="dead_letter_replay",
        params="{}",
        requester="maker",
        requester_user_id="",
        requested_at=time.time() - 31.0,
        expires_at=None,
    )
    assert await engine.store.decide_pending_approval(
        approval_id,
        status="executing",
        approver=APPROVER,
        decided_at=time.time() - 30.0,
        claim_owner="shard:b",
    )
    with pytest.raises(ApprovalError) as refused:
        await _gate(engine).interrupt_stranded(
            approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
        )
    assert refused.value.status == 409 and "requester id" in refused.value.detail
    assert str((await _row(engine, approval_id))["status"]) == "executing"


# --- the routes ------------------------------------------------------------------------------------


async def test_the_routes_list_and_interrupt_a_stranded_release(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    await _add(service, "approver", Role.ADMINISTRATOR)
    app = create_app(engine, auth=service, approvals=ON)
    c = httpx.AsyncClient(transport=reproving_transport(PW, app=app), base_url="http://t")
    async with c:
        approval_id = await _stranded(engine, "shard:gone")
        op = await _token(c, "op")
        assert (await c.get("/approvals/executing", headers=op)).status_code == 403
        assert (
            await c.post(f"/approvals/{approval_id}/interrupt", headers=op, json={})
        ).status_code == 403
        admin = await _token(c, "approver")
        listed = await c.get("/approvals/executing", headers=admin)
        assert listed.status_code == 200, listed.text
        [entry] = [a for a in listed.json()["approvals"] if a["id"] == approval_id]
        assert entry["claim_owner"] == "shard:gone" and entry["interrupt"] == "needs_attestation"
        unattested = await c.post(f"/approvals/{approval_id}/interrupt", headers=admin)
        assert unattested.status_code == 409, unattested.text
        done = await c.post(
            f"/approvals/{approval_id}/interrupt",
            headers=admin,
            json={"attest_owner_stopped": True},
        )
        assert done.status_code == 200, done.text
        assert done.json()["status"] == "interrupted"
        # It now shows in GET /approvals as interrupted, ready for a resolve.
        queue = (await c.get("/approvals", headers=admin)).json()["approvals"]
        assert [a["status"] for a in queue if a["id"] == approval_id] == ["interrupted"]
        stray = await c.post(
            f"/approvals/{approval_id}/interrupt", headers=admin, json={"surprise": 1}
        )
        assert stray.status_code == 422, "the body refuses an unknown field"
        # Strict: only JSON true attests (decision d20261109T215156567-4334fc).
        other = await _stranded(engine, "shard:gone")
        for loose in ("yes", "true", 1, "1", "on"):
            coerced = await c.post(
                f"/approvals/{other}/interrupt",
                headers=admin,
                json={"attest_owner_stopped": loose},
            )
            assert coerced.status_code == 422, (loose, coerced.text)
        assert str((await _row(engine, other))["status"]) == "executing"


async def test_the_interrupt_requires_a_fresh_step_up(engine: Engine) -> None:
    from messagefoundry.auth.tokens import hash_token

    service = await _service(engine)
    await _add(service, "approver", Role.ADMINISTRATOR)
    app = create_app(engine, auth=service, approvals=ON)
    c = httpx.AsyncClient(transport=reproving_transport(PW, app=app), base_url="http://t")
    async with c:
        approval_id = await _stranded(engine, "shard:gone")
        admin = await _token(c, "approver")
        token = admin["Authorization"].removeprefix("Bearer ")
        await service.store.mark_session_reauthed(hash_token(token), now=0.0)  # window elapsed
        stale = await c.post(
            f"/approvals/{approval_id}/interrupt",
            headers=admin,
            json={"attest_owner_stopped": True},
        )
        assert stale.status_code == 403
        assert stale.headers.get("X-Step-Up-Required") == "1"
        assert str((await _row(engine, approval_id))["status"]) == "executing"


async def test_the_app_reads_the_cluster_heartbeats(engine: Engine) -> None:
    """The wiring's heartbeat reader: an engine that is not a cluster node reads none, so a node's
    release is refused as unavailable rather than guessed at."""
    gate: ApprovalGate = create_app(engine, approvals=ON).state.approval_gate
    approval_id = await _stranded(engine, "node:peer")
    with pytest.raises(ApprovalError) as refused:
        await gate.interrupt_stranded(
            approval_id, actor="operator", actor_user_id="operator-id", attest_owner_stopped=True
        )
    assert refused.value.status == 409 and "reads no cluster heartbeats" in refused.value.detail
