# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Dual-control (maker-checker) approval workflow for high-value actions (ASVS 2.3.5).

Optional and **deny-by-default** (``[approvals]``, off unless enabled). When a gated operation is
invoked it is **not executed inline**: a pending request (operation key + JSON params + requester) is
persisted, and a **distinct** second user holding ``approvals:approve`` must release it — the requester
can never approve their own (enforced server-side). On approval the captured operation is re-executed
and **both identities** land in the hash-chained audit log. A request older than
``[approvals].expiry_hours`` can no longer be approved.

The registry (op key -> executor) is populated by the API wiring, where the engine is in scope; this
module owns only the generic hold/approve/reject mechanics over the ``pending_approvals`` store table.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from messagefoundry.config.settings import ApprovalsSettings
from messagefoundry.store.base import Store

#: An executor re-runs a captured operation on approval, returning a small JSON-able result summary.
Executor = Callable[[Mapping[str, Any]], Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class _Operation:
    key: str
    label: str  # human description, surfaced in the pending list + audit
    execute: Executor


class ApprovalError(Exception):
    """A pending-approval decision could not be made. ``status`` is the HTTP code the API should map
    to (404 unknown, 409 already-decided/expired, 403 self-approval)."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class ApprovalGate:
    """Holds the registry of approvable operations and the hold/approve/reject mechanics. One instance
    per app; created with the live store + the resolved ``[approvals]`` settings."""

    def __init__(self, store: Store, settings: ApprovalsSettings) -> None:
        self._store = store
        self._settings = settings
        self._ops: dict[str, _Operation] = {}

    def register(self, key: str, label: str, execute: Executor) -> None:
        self._ops[key] = _Operation(key=key, label=label, execute=execute)

    def _gated(self, operation: str) -> bool:
        return self._settings.enabled and operation in self._settings.operations

    async def guard(
        self, operation: str, params: Mapping[str, Any], *, requester: str
    ) -> str | None:
        """Call at the start of a gated endpoint, **after** the requester's own permission/scope checks
        pass. If dual-control is active for ``operation``, persist a pending request, audit
        ``approval.requested``, and return its **id** (the endpoint should respond 202). Otherwise
        return ``None`` — the endpoint executes inline exactly as before."""
        if not self._gated(operation):
            return None
        now = time.time()
        approval_id = uuid4().hex
        expires_at = (
            None if self._settings.expiry_hours == 0 else now + self._settings.expiry_hours * 3600.0
        )
        await self._store.create_pending_approval(
            approval_id=approval_id,
            operation=operation,
            params=json.dumps(dict(params), sort_keys=True),
            requester=requester,
            requested_at=now,
            expires_at=expires_at,
        )
        await self._store.record_audit(
            "approval.requested",
            actor=requester,
            detail=json.dumps({"approval_id": approval_id, "operation": operation}),
        )
        return approval_id

    async def list_pending(self) -> list[dict[str, Any]]:
        rows = await self._store.list_pending_approvals(now=time.time())
        return [
            {
                "id": str(r["id"]),
                "operation": str(r["operation"]),
                "label": self._label(str(r["operation"])),
                "requester": str(r["requester"]),
                "requested_at": float(r["requested_at"]),
                "expires_at": (None if r["expires_at"] is None else float(r["expires_at"])),
            }
            for r in rows
        ]

    async def approve(self, approval_id: str, *, approver: str) -> dict[str, Any]:
        """Release a pending request: the captured operation is re-executed and both identities are
        audited. Refuses self-approval (the requester is not a valid second approver)."""
        row = await self._require_pending(approval_id)
        if str(row["requester"]) == approver:
            raise ApprovalError(403, "you cannot approve your own request")
        operation = str(row["operation"])
        op = self._ops.get(operation)
        if (
            op is None
        ):  # registered op was removed between request and approval — refuse, stay pending
            raise ApprovalError(409, f"operation '{operation}' is no longer available")
        # Transition to 'approved' FIRST (atomic, guards a double-approve race); only then execute.
        if not await self._store.decide_pending_approval(
            approval_id, status="approved", approver=approver, decided_at=time.time()
        ):
            raise ApprovalError(409, "request was already decided")
        params = json.loads(str(row["params"]))
        result = await op.execute(params)
        await self._store.record_audit(
            "approval.approved",
            actor=approver,
            detail=json.dumps(
                {
                    "approval_id": approval_id,
                    "operation": operation,
                    "requester": str(row["requester"]),
                    "result": result,
                }
            ),
        )
        return {
            "operation": operation,
            "requested_by": str(row["requester"]),
            "approved_by": approver,
            "result": result,
        }

    async def reject(self, approval_id: str, *, approver: str) -> dict[str, Any]:
        """Decline a pending request without executing it (audited). Any ``approvals:approve`` holder
        may reject — including the requester cancelling their own."""
        row = await self._require_pending(approval_id)
        if not await self._store.decide_pending_approval(
            approval_id, status="rejected", approver=approver, decided_at=time.time()
        ):
            raise ApprovalError(409, "request was already decided")
        operation = str(row["operation"])
        await self._store.record_audit(
            "approval.rejected",
            actor=approver,
            detail=json.dumps(
                {
                    "approval_id": approval_id,
                    "operation": operation,
                    "requester": str(row["requester"]),
                }
            ),
        )
        return {
            "operation": operation,
            "requested_by": str(row["requester"]),
            "rejected_by": approver,
        }

    async def _require_pending(self, approval_id: str) -> Any:
        row = await self._store.get_pending_approval(approval_id)
        if row is None:
            raise ApprovalError(404, "no such approval request")
        if str(row["status"]) != "pending":
            raise ApprovalError(409, f"request is already {row['status']}")
        expires_at = row["expires_at"]
        if expires_at is not None and float(expires_at) <= time.time():
            raise ApprovalError(409, "request has expired")
        return row

    def _label(self, operation: str) -> str:
        op = self._ops.get(operation)
        return op.label if op is not None else operation
