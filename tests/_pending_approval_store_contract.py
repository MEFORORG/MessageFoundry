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


def _gate(store: Any, execute: Callable[[Mapping[str, Any]], Awaitable[dict[str, Any]]]) -> Any:
    from messagefoundry.api.approvals import ApprovalGate
    from messagefoundry.auth.permissions import Permission
    from messagefoundry.config.settings import ApprovalsSettings

    settings = ApprovalsSettings(
        enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=0.0
    )
    gate = ApprovalGate(_StandingStore(store), settings, resolve_identity=_resolve)
    gate.register(
        "dead_letter_replay", "contract op", execute, permission=Permission.MESSAGES_REPLAY
    )
    return gate


async def _request(gate: Any) -> str:
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester=_REQUESTER, requester_user_id=_REQUESTER_ID
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
        }
        audited = await _resolved_rows(store, approval_id)
        assert len(audited) == 1
        assert str(audited[0]["actor"]) == _RESOLVER
        assert json.loads(str(audited[0]["detail"])) == expected
        # One attempt row, written before the move. The second resolve above is refused on the
        # status check, before it writes one.
        attempted = await _resolved_rows(store, approval_id, "approval.resolve_attempted")
        assert len(attempted) == 1
        assert str(attempted[0]["actor"]) == _RESOLVER
        assert json.loads(str(attempted[0]["detail"])) == expected
        # Resolving writes no second outcome row: the trail still says the release was cut off.
        actions = await _audit_actions(store, approval_id)
        assert actions == ["approval.interrupted"]
