# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend store contract for ``pending_approvals.requester_user_id`` (BACKLOG #1540).

The dual-control self-approval refusal keys on this column, so a backend that fails to carry it does
not degrade -- ``ApprovalGate.approve`` reads NULL and refuses EVERY release fail-closed, which turns
dual control off for that store while every request still returns a plausible 202.

``tests/test_store_schema_hash.py`` pins the DDL **text** on all three backends, and that is not the
same assertion. The DDL check cannot see a typo in the ``INSERT`` or ``SELECT`` column list, and this
change rewrote both on all three backends -- a column named correctly in ``CREATE TABLE`` and omitted
from the ``SELECT`` projection reads back as absent, which is indistinguishable from the migration
never having run. This body round-trips the value through the real store object instead, so the
PostgreSQL and SQL Server legs execute their own SQL rather than having it read.

Deliberately **extra-free**: it imports nothing outside the core package and the store object it is
handed, so the live server legs can import it inside a test function.

The second half is the **release outcome** contract (BACKLOG #1562). ``ApprovalGate.approve`` claims
a row as ``executing`` and settles it to ``approved``, ``failed`` or ``interrupted``, each through a
``decide_pending_approval`` guarded on ``from_status="executing"``. That guard is backend SQL, so the
real gate runs over each real store here. Only the two account reads are stubbed (see
:class:`_StandingStore`), because they are not what this contract is about.

The third half is the **resolution** contract (BACKLOG #1562 part B): ``list_interrupted_approvals``
and the ``from_status="interrupted"`` guard a resolve writes through, again backend SQL.

The fourth half is the **restart reconcile** contract (BACKLOG #1562): the claim writes the
``claim_owner`` column, ``list_executing_approvals`` reads it back, and a gate at startup moves only
its own ``executing`` rows (and unowned ones) to ``interrupted``, never a sibling's.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping
from types import SimpleNamespace
from typing import Any

import pytest

#: Distinct from the username on purpose. A backend that returned the name where the id belongs --
#: the exact confusion #1540 exists to remove -- would pass a check that let the two be equal.
_REQUESTER = "contract-requester-name"
_REQUESTER_ID = "contract-requester-id-0001"


async def _assert_pending_approval_contract(store: Any) -> None:
    """The behaviour every backend owes the requester-id column.

    Round-trips a request through ``create_pending_approval`` -> ``get_pending_approval`` and pins
    that the id survives, is surfaced under its own key, and is not conflated with the display name.
    """
    approval_id = "contractapproval0000000000000001"
    await store.create_pending_approval(
        approval_id=approval_id,
        operation="dead_letter_replay",
        params="{}",
        requester=_REQUESTER,
        requester_user_id=_REQUESTER_ID,
        requested_at=1_000.0,
        expires_at=None,
    )
    try:
        row = await store.get_pending_approval(approval_id)
        assert row is not None

        # The authorization key survived the write and the read. `is not None` alone would pass on a
        # backend that wrote the NAME into this column, so compare the value.
        assert str(row["requester_user_id"]) == _REQUESTER_ID
        # ...and the display label is still its own column, unchanged.
        assert str(row["requester"]) == _REQUESTER
        # The two must not be the same value; keying on an id that is really a name fixes nothing.
        assert str(row["requester_user_id"]) != str(row["requester"])

        # The pending queue projects the display label only -- the id is read on the approve path via
        # get_pending_approval. Pinned so a backend adding it to this projection is a deliberate act.
        listed = await store.list_pending_approvals(now=1_001.0)
        mine = [r for r in listed if str(r["id"]) == approval_id]
        assert len(mine) == 1
        assert str(mine[0]["requester"]) == _REQUESTER
    finally:
        # Leave the table as it was found; the server legs share one database across tests.
        await store.decide_pending_approval(
            approval_id, status="rejected", approver="contract-cleanup", decided_at=1_002.0
        )


# --- vault BACKLOG #2255: a transition and its audit row are one write -----------------------------


class _AppendFails(Exception):
    pass


async def _audit_rows_for(store: Any, action: str, approval_id: str) -> list[Any]:
    return [
        r
        for r in await store.list_audit(action=action, limit=500)
        if json.loads(str(r["detail"])).get("approval_id") == approval_id
    ]


async def _assert_transition_audit_contract(store: Any) -> None:
    """``create_pending_approval`` and ``decide_pending_approval`` append their ``audit`` row in the
    SAME transaction, on this backend's own SQL.

    The fault is injected at the append every audit write on every backend goes through, so the
    rollback asserted here is the backend's own, not a wrapper declining to call it. Each backend's
    ``_append_audit_row`` takes a different first argument, hence the catch-all signature."""
    from uuid import uuid4

    from messagefoundry.store.store import AuditAppend

    approval_id, lost_id = uuid4().hex, uuid4().hex

    def row(action: str, for_id: str = approval_id) -> Any:
        return AuditAppend(action, actor=_APPROVER, detail=json.dumps({"approval_id": for_id}))

    async def _raises(*_args: Any, **_kwargs: Any) -> Any:
        raise _AppendFails("audit append refused")

    def request(for_id: str) -> Any:
        return store.create_pending_approval(
            approval_id=for_id,
            operation="dead_letter_replay",
            params=json.dumps({"contract": for_id}),
            requester=_REQUESTER,
            requester_user_id=_REQUESTER_ID,
            requested_at=1_000.0,
            expires_at=None,
            audit=row("approval.requested", for_id),
        )

    real_append = store._append_audit_row
    try:
        assert await request(approval_id) == approval_id
        assert len(await _audit_rows_for(store, "approval.requested", approval_id)) == 1

        # A failed append rolls the INSERT back: no request is held without its row.
        store._append_audit_row = _raises
        with pytest.raises(_AppendFails):
            await request(lost_id)
        # ...and a failed append rolls a transition back: the row is still pending.
        with pytest.raises(_AppendFails):
            await store.decide_pending_approval(
                approval_id,
                status="executing",
                approver=_APPROVER,
                decided_at=1_001.0,
                audit=row("approval.release_attempted"),
            )
        store._append_audit_row = real_append
        assert await store.get_pending_approval(lost_id) is None
        assert await _status(store, approval_id) == "pending"
        assert await _audit_rows_for(store, "approval.release_attempted", approval_id) == []

        # A transition that matches no row writes no row.
        assert not await store.decide_pending_approval(
            approval_id,
            status="approved",
            approver=_APPROVER,
            decided_at=1_002.0,
            from_status="executing",
            audit=row("approval.approved"),
        )
        assert await _audit_rows_for(store, "approval.approved", approval_id) == []

        # The control: one that matches moves the row and writes exactly one.
        assert await store.decide_pending_approval(
            approval_id,
            status="rejected",
            approver=_APPROVER,
            decided_at=1_003.0,
            audit=row("approval.rejected"),
        )
        assert await _status(store, approval_id) == "rejected"
        rejected = await _audit_rows_for(store, "approval.rejected", approval_id)
        assert len(rejected) == 1 and str(rejected[0]["actor"]) == _APPROVER
    finally:
        store._append_audit_row = real_append
        # Leave the table as it was found; the server legs share one database across tests.
        await store.decide_pending_approval(
            approval_id, status="rejected", approver="contract-cleanup", decided_at=1_004.0
        )


# --- vault BACKLOG #2445: a repeat request joins the open one ---------------------------------------


async def _assert_repeat_request_contract(store: Any) -> None:
    """``create_pending_approval(on_repeat=...)`` files ONE request for one requester, operation and
    params while it is open, on this backend's own SQL, including when the repeats race.

    The params carry a fresh nonce, so rows other tests leave in a shared server table cannot
    match, and the cleanup rejects every row this body files."""
    from uuid import uuid4

    from messagefoundry.store.store import AuditAppend

    params = json.dumps({"contract_repeat": uuid4().hex})
    filed: set[str] = set()

    def requested(for_id: str) -> Any:
        return AuditAppend(
            "approval.requested", actor=_REQUESTER, detail=json.dumps({"approval_id": for_id})
        )

    def repeated(existing: str) -> Any:
        return AuditAppend(
            "approval.request_repeated",
            actor=_REQUESTER,
            detail=json.dumps({"approval_id": existing}),
        )

    async def request(*, requester_user_id: str = _REQUESTER_ID, now: float = 1_000.0) -> str:
        approval_id = uuid4().hex
        held = str(
            await store.create_pending_approval(
                approval_id=approval_id,
                operation="dead_letter_replay",
                params=params,
                requester=_REQUESTER,
                requester_user_id=requester_user_id,
                requested_at=now,
                expires_at=now + 60.0,
                audit=requested(approval_id),
                on_repeat=repeated,
            )
        )
        filed.add(held)
        return held

    try:
        first = await request()
        assert await request() == first
        # The race, within ONE process: every concurrent repeat joins one request. On SQLite and SQL
        # Server the in-process lock already serializes these calls, so this arm cannot show the
        # database-level serialization that holds ACROSS processes; that rests on the SQL itself
        # (one INSERT ... WHERE NOT EXISTS, or a read under the audit lock). Postgres has no
        # in-process lock here, so on that leg this arm does exercise the database's own.
        raced = await asyncio.gather(*(request() for _ in range(6)))
        assert set(raced) == {first}
        assert len(await _audit_rows_for(store, "approval.requested", first)) == 1
        assert len(await _audit_rows_for(store, "approval.request_repeated", first)) == 7

        # Another requester, or the same one after the request expired, files a new one.
        other = await request(requester_user_id="contract-other-requester-id")
        assert other != first
        later = await request(now=1_061.0)
        assert later not in (first, other)

        # Once the open request is decided, a repeat files a new one too.
        assert await store.decide_pending_approval(
            later, status="rejected", approver=_APPROVER, decided_at=1_062.0
        )
        assert await request(now=1_063.0) not in (first, other, later)
    finally:
        for approval_id in filed:
            await store.decide_pending_approval(
                approval_id, status="rejected", approver="contract-cleanup", decided_at=1_100.0
            )


# --- BACKLOG #1562: the release outcome ------------------------------------------------------------

_APPROVER = "contract-approver-name"
_APPROVER_ID = "contract-approver-id-0001"
#: Bounds every wait below, so a regression hangs for seconds rather than for the suite timeout.
_WAIT_S = 10.0


class _StandingStore:
    """The real store, except for the two ACCOUNT reads the gate makes before it releases.

    ``approve`` re-reads the requester (ASVS 8.3.2) and the approver (BACKLOG #315) through
    ``get_user``. Provisioning real users on the shared server databases would need per-backend
    cleanup and would test nothing this contract is about, so ``get_user`` answers an enabled
    account with no credential change. Every approval and audit call reaches the real store."""

    def __init__(self, store: Any) -> None:
        self._store = store

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    async def get_user(self, _user_id: str) -> Any:
        return SimpleNamespace(
            disabled=False, created_at=None, password_changed_at=None, totp_enrolled_at=None
        )


class _AnyPermission:
    """A resolved requester who still holds every permission."""

    def has(self, _permission: Any) -> bool:
        return True


async def _resolve(_user_id: str) -> Any:
    return _AnyPermission()


def _gate(
    store: Any,
    execute: Callable[[Mapping[str, Any]], Awaitable[dict[str, Any]]],
    *,
    claim_owner: str = "engine",
) -> Any:
    from messagefoundry.api.approvals import ApprovalGate
    from messagefoundry.auth.permissions import Permission
    from messagefoundry.config.settings import ApprovalsSettings

    settings = ApprovalsSettings(
        enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=0.0
    )
    gate = ApprovalGate(
        _StandingStore(store), settings, resolve_identity=_resolve, claim_owner=claim_owner
    )
    gate.register(
        "dead_letter_replay", "contract op", execute, permission=Permission.MESSAGES_REPLAY
    )
    return gate


async def _request(gate: Any) -> str:
    """A fresh request. The params carry a nonce, so a repeat never joins an open request another
    test left in a shared server table (vault BACKLOG #2445); the executors ignore it."""
    from uuid import uuid4

    approval_id = await gate.guard(
        "dead_letter_replay",
        {"contract_nonce": uuid4().hex},
        requester=_REQUESTER,
        requester_user_id=_REQUESTER_ID,
    )
    assert approval_id is not None
    return str(approval_id)


async def _status(store: Any, approval_id: str) -> str:
    row = await store.get_pending_approval(approval_id)
    assert row is not None
    return str(row["status"])


_OUTCOME_ACTIONS = ("approval.approved", "approval.failed", "approval.interrupted")


async def _audit_actions(store: Any, approval_id: str) -> list[str]:
    """This request's outcome audit actions. Read per action, from the request's own time, and
    filtered on the id, because the server legs share one log: a plain newest-N read could miss this
    request's row under load and turn an absence assertion vacuous."""
    row = await store.get_pending_approval(approval_id)
    assert row is not None
    since = float(row["requested_at"]) - 1.0
    found: list[str] = []
    for action in _OUTCOME_ACTIONS:
        for r in await store.list_audit(action=action, since=since, limit=500):
            if json.loads(str(r["detail"])).get("approval_id") == approval_id:
                found.append(action)
    return found


async def _assert_release_success_contract(store: Any) -> None:
    """The row reads ``executing`` WHILE the executor runs, and ``approved`` once it returns.

    Pre-#1562 the executor saw ``approved``: the status asserted an outcome before there was one."""
    seen: list[str] = []
    approval_id = ""

    async def _observes(_p: Mapping[str, Any]) -> dict[str, Any]:
        seen.append(await _status(store, approval_id))
        return {"ran": True}

    gate = _gate(store, _observes)
    approval_id = await _request(gate)
    out = await gate.approve(approval_id, approver=_APPROVER, approver_user_id=_APPROVER_ID)
    assert out["result"] == {"ran": True}
    assert seen == ["executing"]
    assert await _status(store, approval_id) == "approved"
    actions = await _audit_actions(store, approval_id)
    assert "approval.approved" in actions
    assert "approval.failed" not in actions and "approval.interrupted" not in actions


async def _assert_release_failure_contract(store: Any) -> None:
    """A raising executor ends ``failed``, never stranded in ``executing``.

    This is the compensation's ``from_status`` guard. Left on ``approved`` it would match no row once
    the claim writes ``executing``, and the row would silently stay ``executing``."""

    class _Boom(RuntimeError):
        pass

    async def _raises(_p: Mapping[str, Any]) -> dict[str, Any]:
        raise _Boom("executor exploded")

    gate = _gate(store, _raises)
    approval_id = await _request(gate)
    with pytest.raises(_Boom):
        await gate.approve(approval_id, approver=_APPROVER, approver_user_id=_APPROVER_ID)
    assert await _status(store, approval_id) == "failed"
    actions = await _audit_actions(store, approval_id)
    assert "approval.failed" in actions
    assert "approval.approved" not in actions and "approval.interrupted" not in actions


async def _assert_release_cancel_contract(store: Any) -> None:
    """A release cancelled mid-execute ends ``interrupted`` with its own audit row.

    Pre-#1562 it stayed ``approved`` with no outcome row: unretryable, unrejectable, and absent from
    the pending list. ``interrupted`` says the outcome is unknown; nothing re-runs it."""
    started = asyncio.Event()
    never = asyncio.Event()

    async def _hangs(_p: Mapping[str, Any]) -> dict[str, Any]:
        started.set()
        await never.wait()
        return {"ran": True}

    gate = _gate(store, _hangs)
    approval_id = await _request(gate)
    task = asyncio.create_task(
        gate.approve(approval_id, approver=_APPROVER, approver_user_id=_APPROVER_ID)
    )
    await asyncio.wait_for(started.wait(), _WAIT_S)
    assert await _status(store, approval_id) == "executing"
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, _WAIT_S)
    assert await _status(store, approval_id) == "interrupted"
    actions = await _audit_actions(store, approval_id)
    assert actions.count("approval.interrupted") == 1
    assert "approval.approved" not in actions and "approval.failed" not in actions
    interrupted = [
        r
        for r in await store.list_audit(action="approval.interrupted", limit=500)
        if json.loads(str(r["detail"])).get("approval_id") == approval_id
    ]
    assert str(interrupted[0]["actor"]) == _APPROVER
    detail = json.loads(str(interrupted[0]["detail"]))
    assert detail["requester"] == _REQUESTER and detail["recorded"] is True


async def _assert_release_outcome_contract(store: Any) -> None:
    """All three release outcomes, for a server leg that runs them as one test."""
    await _assert_release_success_contract(store)
    await _assert_release_failure_contract(store)
    await _assert_release_cancel_contract(store)


# --- BACKLOG #1562 part B: resolving an interrupted release ----------------------------------------

_RESOLVER = "contract-resolver-name"
_RESOLVER_ID = "contract-resolver-id-0001"


async def _interrupt(store: Any, runs: list[str]) -> tuple[Any, str]:
    """A gate over ``store`` and a request of its, cut off mid-run so it reads ``interrupted``.
    ``runs`` records each time the executor starts."""
    never = asyncio.Event()
    started = asyncio.Event()

    async def _hangs(_p: Mapping[str, Any]) -> dict[str, Any]:
        runs.append("started")
        started.set()
        await never.wait()
        return {"ran": True}

    gate = _gate(store, _hangs)
    approval_id = await _request(gate)
    task = asyncio.create_task(
        gate.approve(approval_id, approver=_APPROVER, approver_user_id=_APPROVER_ID)
    )
    await asyncio.wait_for(started.wait(), _WAIT_S)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, _WAIT_S)
    assert await _status(store, approval_id) == "interrupted"
    return gate, approval_id


#: Wider than the store's default cap, because the server legs share one table and the list is
#: oldest-first: leftover interrupted rows from earlier tests would otherwise push this one out.
_LIST_LIMIT = 10_000


async def _resolved_rows(
    store: Any, approval_id: str, action: str = "approval.resolved"
) -> list[Any]:
    return [
        r
        for r in await store.list_audit(action=action, limit=500)
        if json.loads(str(r["detail"])).get("approval_id") == approval_id
    ]


async def _assert_interrupted_resolution_contract(store: Any) -> None:
    """An interrupted row is listed apart from the pending queue, and a resolve moves it to a
    terminal status through this backend's ``from_status="interrupted"`` guard, once.

    Pre-part-B there was no listing and no transition out of ``interrupted`` at all."""
    from messagefoundry.api.approvals import ApprovalError

    for outcome, status in (
        ("effects_applied", "resolved_applied"),
        ("effects_not_applied", "resolved_not_applied"),
    ):
        runs: list[str] = []
        gate, approval_id = await _interrupt(store, runs)

        # Listed as interrupted, with who released it and when it was cut off; NOT in the pending
        # queue, so "pending" still means awaiting a second approver.
        listed = [
            r
            for r in await store.list_interrupted_approvals(limit=_LIST_LIMIT)
            if str(r["id"]) == approval_id
        ]
        assert len(listed) == 1
        assert str(listed[0]["status"]) == "interrupted"
        assert str(listed[0]["approver"]) == _APPROVER
        assert listed[0]["decided_at"] is not None
        pending = await store.list_pending_approvals(now=float(listed[0]["requested_at"]))
        assert all(str(r["id"]) != approval_id for r in pending)

        out = await gate.resolve_interrupted(
            approval_id, outcome=outcome, resolver=_RESOLVER, resolver_user_id=_RESOLVER_ID
        )
        assert out["status"] == status and out["resolved_by"] == _RESOLVER
        assert out["approved_by"] == _APPROVER and out["requested_by"] == _REQUESTER

        row = await store.get_pending_approval(approval_id)
        assert row is not None
        assert str(row["status"]) == status
        # The row keeps who RELEASED it; the resolver lives in the audit row.
        assert str(row["approver"]) == _APPROVER
        assert runs == ["started"], "a resolve must never run the operation again"

        # This backend's guard: a second transition out of 'interrupted' moves nothing.
        assert not await store.decide_pending_approval(
            approval_id,
            status="resolved_applied",
            approver="contract-second",
            decided_at=2_000.0,
            from_status="interrupted",
        )
        assert await _status(store, approval_id) == status
        with pytest.raises(ApprovalError) as caught:
            await gate.resolve_interrupted(
                approval_id, outcome=outcome, resolver=_RESOLVER, resolver_user_id=_RESOLVER_ID
            )
        assert caught.value.status == 409

        # Gone from the interrupted listing once resolved.
        assert all(
            str(r["id"]) != approval_id
            for r in await store.list_interrupted_approvals(limit=_LIST_LIMIT)
        )

        expected = {
            "approval_id": approval_id,
            "operation": "dead_letter_replay",
            "requester": _REQUESTER,
            "approver": _APPROVER,
            "outcome": outcome,
            "status": status,
            # The status write replaced decided_at, so the audit rows carry the cut-off time.
            "interrupted_at": float(listed[0]["decided_at"]),
        }
        audited = await _resolved_rows(store, approval_id)
        assert len(audited) == 1
        assert str(audited[0]["actor"]) == _RESOLVER
        assert json.loads(str(audited[0]["detail"])) == expected
        # The move and its row are one write on this backend (vault BACKLOG #2255), so there is
        # no separate attempt row before it.
        assert await _resolved_rows(store, approval_id, "approval.resolve_attempted") == []
        # Resolving writes no second outcome row: the trail still says the release was cut off.
        actions = await _audit_actions(store, approval_id)
        assert actions == ["approval.interrupted"]

    await _assert_interrupted_listing_is_oldest_first(store)


async def _assert_interrupted_listing_is_oldest_first(store: Any) -> None:
    """Interrupted rows never expire, so the capped listing is OLDEST request first: newest first
    would hide the longest-waiting rows past the cap for good. Written straight through the store's
    own transitions, with requested_at values chosen far apart."""
    ids = {"older": "contractinterruptedolder00000001", "newer": "contractinterruptednewer00000001"}
    for name, requested_at in (("newer", 20.0), ("older", 10.0)):  # inserted newest first
        await store.create_pending_approval(
            approval_id=ids[name],
            operation="dead_letter_replay",
            params="{}",
            requester=_REQUESTER,
            requester_user_id=_REQUESTER_ID,
            requested_at=requested_at,
            expires_at=None,
        )
        assert await store.decide_pending_approval(
            ids[name], status="executing", approver=_APPROVER, decided_at=requested_at + 1.0
        )
        assert await store.decide_pending_approval(
            ids[name],
            status="interrupted",
            approver=_APPROVER,
            decided_at=requested_at + 2.0,
            from_status="executing",
        )
    try:
        order = [
            str(r["id"])
            for r in await store.list_interrupted_approvals(limit=_LIST_LIMIT)
            if str(r["id"]) in ids.values()
        ]
        assert order == [ids["older"], ids["newer"]]
        # And the cap keeps the oldest. The server legs share the table, so the one row a limit of
        # 1 returns is at least as old as ours rather than necessarily ours.
        first = await store.list_interrupted_approvals(limit=1)
        assert len(first) == 1 and float(first[0]["requested_at"]) <= 10.0
    finally:
        # Leave no interrupted rows behind: they would sit at the head of this listing for good.
        for approval_id in ids.values():
            await store.decide_pending_approval(
                approval_id,
                status="resolved_not_applied",
                approver=_APPROVER,
                decided_at=3_000.0,
                from_status="interrupted",
            )


# --- BACKLOG #1562: the claim owner, and the startup reconcile it makes safe ----------------------


async def _executing_row(store: Any, approval_id: str) -> Any | None:
    mine = [r for r in await store.list_executing_approvals() if str(r["id"]) == approval_id]
    assert len(mine) <= 1
    return mine[0] if mine else None


async def _claimed_directly(store: Any, *, claim_owner: str | None, claimed_at: float) -> str:
    """A row left ``executing`` the way a process that died mid-run leaves it: claimed through the
    store's own guarded update, and never settled."""
    from uuid import uuid4

    approval_id = uuid4().hex
    await store.create_pending_approval(
        approval_id=approval_id,
        operation="dead_letter_replay",
        params=json.dumps({"contract_nonce": approval_id}),
        requester=_REQUESTER,
        requester_user_id=_REQUESTER_ID,
        requested_at=claimed_at - 1.0,
        expires_at=None,
    )
    assert await store.decide_pending_approval(
        approval_id,
        status="executing",
        approver=_APPROVER,
        decided_at=claimed_at,
        claim_owner=claim_owner,
    )
    return approval_id


async def _assert_claim_records_its_owner(store: Any) -> None:
    """The claim writes the gate's owner in the same update that moves the row to ``executing``,
    and ``list_executing_approvals`` reads it back. The settled row leaves that listing."""
    from uuid import uuid4

    owner = f"contract-owner-{uuid4().hex}"
    seen: list[Any] = []
    approval_id = ""

    async def _observes(_p: Mapping[str, Any]) -> dict[str, Any]:
        row = await _executing_row(store, approval_id)
        seen.append(None if row is None else row["claim_owner"])
        return {"ran": True}

    gate = _gate(store, _observes, claim_owner=owner)
    approval_id = await _request(gate)
    assert await _executing_row(store, approval_id) is None, "a pending row is not executing"
    await gate.approve(approval_id, approver=_APPROVER, approver_user_id=_APPROVER_ID)
    assert seen == [owner]
    assert await _status(store, approval_id) == "approved"
    assert await _executing_row(store, approval_id) is None


async def _never_runs(_p: Mapping[str, Any]) -> dict[str, Any]:
    raise AssertionError("a restart reconcile must never run an operation")


async def _assert_restart_reconcile_contract(store: Any) -> None:
    """At startup a gate moves the ``executing`` rows it owns, and rows with no owner, to
    ``interrupted`` with an ``approval.interrupted`` row in the same write. A row another owner
    holds is left ``executing``: that owner may be a live sibling still running it."""
    from uuid import uuid4

    await _assert_claim_records_its_owner(store)

    mine_owner, sibling_owner = f"contract-me-{uuid4().hex}", f"contract-sib-{uuid4().hex}"
    mine = await _claimed_directly(store, claim_owner=mine_owner, claimed_at=5_000.0)
    sibling = await _claimed_directly(store, claim_owner=sibling_owner, claimed_at=5_001.0)
    legacy = await _claimed_directly(store, claim_owner=None, claimed_at=5_002.0)
    # Every row a reconcile here moves, including rows another test left with no owner, so the
    # cleanup below resolves them all rather than leaving them at the head of the listing.
    swept: set[str] = set()
    try:
        listed = {str(r["id"]): r for r in await store.list_executing_approvals()}
        assert str(listed[mine]["claim_owner"]) == mine_owner
        assert str(listed[sibling]["claim_owner"]) == sibling_owner
        assert listed[legacy]["claim_owner"] is None
        assert float(listed[mine]["decided_at"]) == 5_000.0
        # The owner filter runs in this backend's SQL: own rows and unowned ones, never a sibling's.
        owned = {str(r["id"]) for r in await store.list_executing_approvals(claim_owner=mine_owner)}
        assert mine in owned and legacy in owned and sibling not in owned

        restarted = _gate(store, _never_runs, claim_owner=mine_owner)
        found = await restarted.reconcile_after_restart()
        swept.update(found.interrupted)
        # Subsets, not equality: the server legs share one table, and another test may have left a
        # row with no owner behind.
        assert mine in found.interrupted and legacy in found.interrupted
        assert sibling in found.foreign and sibling not in found.interrupted
        assert found.unsettled == ()
        assert await _status(store, mine) == "interrupted"
        assert await _status(store, legacy) == "interrupted"
        assert await _status(store, sibling) == "executing", "a sibling's live release was moved"

        for approval_id, owner in ((mine, mine_owner), (legacy, None)):
            rows = await _resolved_rows(store, approval_id, "approval.interrupted")
            assert len(rows) == 1
            assert str(rows[0]["actor"]) == "system"
            detail = json.loads(str(rows[0]["detail"]))
            assert detail["reason"] == "engine_restart" and detail["recorded"] is True
            assert detail["claim_owner"] == owner and detail["approver"] == _APPROVER
            row = await store.get_pending_approval(approval_id)
            assert row is not None and str(row["approver"]) == _APPROVER
        assert await _resolved_rows(store, sibling, "approval.interrupted") == []

        # A second start moves nothing more and writes no second row.
        again = await restarted.reconcile_after_restart()
        swept.update(again.interrupted)
        assert mine not in again.interrupted and legacy not in again.interrupted
        assert len(await _resolved_rows(store, mine, "approval.interrupted")) == 1

        # The sibling settles its own row when IT restarts.
        sibling_gate = _gate(store, _never_runs, claim_owner=sibling_owner)
        assert sibling in (await sibling_gate.reconcile_after_restart()).interrupted
        assert await _status(store, sibling) == "interrupted"

        # The reconciled row takes the ordinary resolve path; nothing re-runs.
        out = await restarted.resolve_interrupted(
            mine, outcome="effects_not_applied", resolver=_RESOLVER, resolver_user_id=_RESOLVER_ID
        )
        assert out["status"] == "resolved_not_applied" and out["approved_by"] == _APPROVER
    finally:
        # Leave nothing executing or interrupted behind on a shared server table.
        for approval_id in {mine, sibling, legacy} | swept:
            for from_status in ("executing", "interrupted"):
                await store.decide_pending_approval(
                    approval_id,
                    status="resolved_not_applied",
                    approver=_APPROVER,
                    decided_at=6_000.0,
                    from_status=from_status,
                )
