# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Dual-control (maker-checker) approval workflow for high-value actions (ASVS 2.3.5).

Optional and **deny-by-default** (``[approvals]``, off unless enabled). When a gated operation is
invoked it is **not executed inline**: a pending request (operation key + JSON params + requester) is
persisted, and a **distinct** second user holding ``approvals:approve`` must release it — the requester
can never approve their own (enforced server-side). On approval the captured operation is re-executed
and **both identities** land in the hash-chained audit log. A request older than
``[approvals].expiry_hours`` can no longer be approved.

A request YOUNGER than ``[approvals].min_dwell_seconds`` cannot be approved yet (ASVS 2.4.2). The expiry
is a ceiling; this is the floor. The refusal is a 409 with an ``approval.too_early`` audit row, and the
request stays pending. Nothing retries it: the approver must approve again. Where the default comes
from, and what the floor does not do, is stated once in docs/SECURITY.md under "Dual-control approval
for high-value actions".

On release the **requester** is re-validated too (ASVS 8.3.2). The request is refused, audited and
alerted if the requester no longer exists, is disabled, no longer holds the permission the operation
requires, or has left the channel scope it needs. Authority is read at release rather than remembered
from the request, because it can be withdrawn inside the ``expiry_hours`` window.

The check reads the ENGINE's copy of the account: the ``users`` row and its stored roles and scope.
For a directory (AD) requester that copy lags the directory. The reconciler revokes an absent
principal's sessions without disabling the row, and it re-diffs roles only for principals holding a
live session. So a directory-side disable, delete or demotion is seen here only once it has reached
the engine's row. Probing the directory at release is not built.

The gate cannot prove the approver is a second person (BACKLOG #315); what it flags instead is
stated once, on :meth:`ApprovalGate._flag_approver_provenance`.

The registry (op key -> executor) is populated by the API wiring, where the engine is in scope; this
module owns only the generic hold/approve/reject mechanics over the ``pending_approvals`` store table.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from messagefoundry.auth.identity import Identity
from messagefoundry.auth.permissions import Permission
from messagefoundry.config.settings import ApprovalsSettings
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.store.base import Store

log = logging.getLogger(__name__)

#: An executor re-runs a captured operation on approval, returning a small JSON-able result summary.
Executor = Callable[[Mapping[str, Any]], Awaitable[dict[str, Any]]]

#: Resolves a ``users.id`` to its CURRENT :class:`Identity` (roles, custom-role overlay, channel scope),
#: or ``None`` when it cannot. Injected rather than imported so this module never reaches the auth
#: service directly. The API wiring late-binds it, because the service is attached after the gate.
IdentityResolver = Callable[[str], Awaitable[Identity | None]]

#: Whether a re-resolved requester may still act on THESE captured params. This is the channel-scope
#: half of an operation's authority, which a fixed permission cannot express.
ScopeCheck = Callable[[Identity, Mapping[str, Any]], bool]


@dataclass(frozen=True)
class _Operation:
    key: str
    label: str  # human description, surfaced in the pending list + audit
    execute: Executor
    #: The permission the operation's own endpoint demands of the requester. Re-checked at release.
    permission: Permission
    #: Optional scope predicate over the captured params, re-checked at release beside ``permission``.
    in_scope: ScopeCheck | None = None


class ApprovalError(Exception):
    """A pending-approval decision could not be made. ``status`` is the HTTP code the API should map
    to — at least 404 unknown, 409 already-decided/expired/unapprovable, 403 self-approval."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class ApprovalGate:
    """Holds the registry of approvable operations and the hold/approve/reject mechanics. One instance
    per app; created with the live store + the resolved ``[approvals]`` settings."""

    def __init__(
        self,
        store: Store,
        settings: ApprovalsSettings,
        *,
        resolve_identity: IdentityResolver | None = None,
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._settings = settings
        self._ops: dict[str, _Operation] = {}
        # Wall-clock seconds, injectable so a test can drive the expiry ceiling and the dwell floor.
        self._clock = clock
        # With no resolver the requester's permissions cannot be re-read, so approve() refuses every
        # release (fail closed) rather than executing on authority it could not check.
        self._resolve_identity = resolve_identity
        self._alert_sink: AlertSink = alert_sink if alert_sink is not None else LoggingAlertSink()

    def register(
        self,
        key: str,
        label: str,
        execute: Executor,
        *,
        permission: Permission,
        in_scope: ScopeCheck | None = None,
    ) -> None:
        """Register an approvable operation. ``permission`` is REQUIRED, so no operation can become
        approvable without naming the authority its requester must still hold at release."""
        self._ops[key] = _Operation(
            key=key, label=label, execute=execute, permission=permission, in_scope=in_scope
        )

    def _gated(self, operation: str) -> bool:
        return self._settings.enabled and operation in self._settings.operations

    async def guard(
        self,
        operation: str,
        params: Mapping[str, Any],
        *,
        requester: str,
        requester_user_id: str,
        client: str | None = None,
    ) -> str | None:
        """Call at the start of a gated endpoint, **after** the requester's own permission/scope checks
        pass. If dual-control is active for ``operation``, persist a pending request, audit
        ``approval.requested``, and return its **id** (the endpoint should respond 202). Otherwise
        return ``None`` — the endpoint executes inline exactly as before.

        ``requester_user_id`` is the requester's immutable ``users.id`` and is what
        :meth:`approve` compares; ``requester`` is the display/audit label (BACKLOG #1540)."""
        if not self._gated(operation):
            return None
        # Enforce the write half of the invariant here, matching `create_upload`'s guard on
        # `uploader_id`: a row persisted without an owner id is unapprovable, and refusing it at the
        # write boundary turns that into a caller bug instead of a request nobody can ever release.
        if not requester_user_id:
            raise ValueError(
                "requester_user_id is required (a request with no owner id is unapprovable)"
            )
        now = self._clock()
        approval_id = uuid4().hex
        expires_at = (
            None if self._settings.expiry_hours == 0 else now + self._settings.expiry_hours * 3600.0
        )
        await self._store.create_pending_approval(
            approval_id=approval_id,
            operation=operation,
            params=json.dumps(dict(params), sort_keys=True),
            requester=requester,
            requester_user_id=requester_user_id,
            requested_at=now,
            expires_at=expires_at,
        )
        await self._store.record_audit(
            "approval.requested",
            actor=requester,
            detail=json.dumps({"approval_id": approval_id, "operation": operation}),
            client=client,  # ADR 0150: the requester's own address
        )
        return approval_id

    async def list_pending(self) -> list[dict[str, Any]]:
        rows = await self._store.list_pending_approvals(now=self._clock())
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

    async def approve(
        self,
        approval_id: str,
        *,
        approver: str,
        approver_user_id: str,
        client: str | None = None,
    ) -> dict[str, Any]:
        """Release a pending request: the captured operation is re-executed and both identities are
        audited. Refuses self-approval (the requester is not a valid second approver). Also refuses a
        request whose requester no longer holds the authority it needs (:meth:`_requester_standing`),
        and one younger than ``[approvals].min_dwell_seconds`` (409, ``approval.too_early``).

        **The refusal compares user ids, never usernames (BACKLOG #1540).** The stored ``requester``
        and the live ``approver`` are two snapshots of a directory-writable name, taken up to
        ``[approvals].expiry_hours`` apart (``users.username`` became mutable in BACKLOG #1532), so a
        name comparison is wrong in both directions: a requester renamed inside the window passes the
        refusal and releases their own request, and whoever is later given the freed name is refused
        as a self-approver they are not. ``users.id`` never changes, so it is the key."""
        row = await self._require_pending(approval_id)
        requester_user_id = row["requester_user_id"]
        if not requester_user_id:
            # Fail closed. A request with no recorded requester id cannot be checked for
            # self-approval, and the stored NAME is not a usable fallback — after a rename it may
            # belong to somebody else, so comparing it would key the refusal on the wrong person.
            # Deliberately NOT the 403 text below: this is a stale row, not an accusation.
            #
            # FALSY, not `is None`. An empty id would otherwise pass this check and then compare
            # unequal below, silently switching the refusal off for that row — the same shape the
            # read side of the upload-ownership check guards against with `bool(meta.uploader_id)`.
            raise ApprovalError(
                409,
                "this request predates requester-id attribution and can no longer be approved — "
                "reject it and request the operation again",
            )
        if str(requester_user_id) == approver_user_id:
            raise ApprovalError(403, "you cannot approve your own request")
        operation = str(row["operation"])
        op = self._ops.get(operation)
        if (
            op is None
        ):  # registered op was removed between request and approval — refuse, stay pending
            raise ApprovalError(409, f"operation '{operation}' is no longer available")
        # ASVS 2.4.2: the FLOOR on the request's age, beside the expiry CEILING in _require_pending.
        # Here, inside approve(), because every release path calls this method, so no caller can skip
        # it. Checked BEFORE the transition, so the row stays pending and the approver can simply
        # approve again.
        #
        # The age compares two WALL-CLOCK readings, and they can come from two engine processes that
        # share one store. Skew cuts both ways. A clock BEHIND the requester's reads as too young and
        # fails closed until it catches up. A clock AHEAD reads as older than it is and fails OPEN by
        # the size of the skew, and so does a forward clock step. Stamping both ends from the store's
        # own clock would close that; it is not built.
        #
        # `min_dwell > 0` first, so a floor of 0 really is "no floor". Without it a clock reading even
        # 1 ms behind requested_at gives a negative age, and `age < 0.0` would refuse the approve.
        min_dwell = self._settings.min_dwell_seconds
        age = self._clock() - float(row["requested_at"])
        if min_dwell > 0 and age < min_dwell:
            await self._store.record_audit(
                "approval.too_early",
                actor=approver,
                detail=json.dumps(
                    {
                        "approval_id": approval_id,
                        "operation": operation,
                        "requester": str(row["requester"]),
                        "age_seconds": round(age, 3),
                        "min_dwell_seconds": min_dwell,
                    }
                ),
                client=client,  # ADR 0150: the approver's address, matching this row's actor
            )
            # The real remaining wait, not the floor: when this clock is behind the requester's, the
            # wait is longer than the floor, and saying "less than 2 seconds old" would mislead.
            wait = math.ceil(min_dwell - age)
            raise ApprovalError(
                409,
                f"this request is too new to approve (the minimum is {min_dwell} seconds); "
                f"review it and approve it again in {wait} second(s)",
            )
        params = json.loads(str(row["params"]))
        # ASVS 8.3.2: the requester's authority is re-read NOW. It was checked when the request was
        # made, and it can be withdrawn at any point inside the expiry window: the user deleted or
        # disabled, a role removed, a channel scope narrowed. It reads the engine's copy of the
        # account, so a directory-side change counts once it reaches that copy (module docstring). Checked
        # BEFORE the transition, so a refused request stays pending, like a removed operation above.
        # It can still be rejected, or released later if the requester's authority is restored.
        reason = await self._requester_standing(str(requester_user_id), op, params)
        if reason is not None:
            await self._refuse_stale_requester(
                approval_id,
                operation=op,
                approver=approver,
                requester=str(row["requester"]),
                reason=reason,
                client=client,
            )
            raise ApprovalError(
                409,
                "the requester no longer holds the authority this operation requires; reject the "
                "request, and have an authorized user request it again if it is still needed",
            )
        # Transition to 'approved' FIRST (atomic, guards a double-approve race); only then execute.
        if not await self._store.decide_pending_approval(
            approval_id, status="approved", approver=approver, decided_at=self._clock()
        ):
            raise ApprovalError(409, "request was already decided")
        # BACKLOG #315 (b): after the transition, so only a release that really happened is flagged,
        # and before the executor, so the flag lands even when the executor fails.
        await self._flag_approver_provenance(
            approval_id,
            operation=operation,
            approver=approver,
            approver_user_id=approver_user_id,
            requester=str(row["requester"]),
            requested_at=float(row["requested_at"]),
            client=client,
        )
        try:
            result = await op.execute(params)
        except Exception as exc:
            # ASVS 2.3.3 COMPENSATING TRANSITION. The row moved to 'approved' BEFORE the executor ran
            # (that ordering is load-bearing — it guards the double-approve race — and must stay). If
            # the executor raises, the row would otherwise be stranded asserting an operation that
            # never happened, and no approval.approved row is written either, so the store would carry
            # an approval with no outcome at all. Roll it to 'failed' and audit the failure against
            # both identities, then re-raise so the caller still sees the error.
            #
            # `except Exception` is deliberate and is not a swallow: ANY executor failure has to
            # compensate, and the original is re-raised below. BaseException (notably CancelledError)
            # is intentionally NOT caught — a cancelled approve must not be recorded as a failure.
            await self._compensate_failed_execution(
                approval_id,
                operation=operation,
                approver=approver,
                requester=str(row["requester"]),
                error=exc,
                client=client,
            )
            raise
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
            # ADR 0150: the APPROVER's address — matching this row's actor. The requester's own
            # address is on their earlier approval.requested row, so dual control records both
            # halves of the ceremony from two independently-attributed hosts.
            client=client,
        )
        return {
            "operation": operation,
            "requested_by": str(row["requester"]),
            "approved_by": approver,
            "result": result,
        }

    async def _requester_standing(
        self, requester_user_id: str, op: _Operation, params: Mapping[str, Any]
    ) -> str | None:
        """``None`` when the requester may still perform ``op`` on ``params``. Otherwise a closed-set
        reason slug for the audit row and the alert.

        Existence and the disabled flag come from the store row, not from the resolved identity. The
        resolver deliberately resolves a disabled user too (it also serves the permission inspector),
        so it cannot say "disabled" on its own."""
        user = await self._store.get_user(requester_user_id)
        if user is None:
            return "requester_missing"
        if user.disabled:
            return "requester_disabled"
        if self._resolve_identity is None:
            return "requester_unverifiable"
        identity = await self._resolve_identity(requester_user_id)
        if identity is None:  # deleted between the two reads, or no auth service is bound
            return "requester_unverifiable"
        if not identity.has(op.permission):
            return "requester_lacks_permission"
        if op.in_scope is not None and not op.in_scope(identity, params):
            return "requester_out_of_scope"
        return None

    async def _refuse_stale_requester(
        self,
        approval_id: str,
        *,
        operation: _Operation,
        approver: str,
        requester: str,
        reason: str,
        client: str | None,
    ) -> None:
        """Audit and alert a release refused on the requester's standing. The audit row goes first:
        it is the durable record, and the alert is best-effort by the sink's own contract."""
        await self._store.record_audit(
            "approval.stale_requester",
            actor=approver,
            detail=json.dumps(
                {
                    "approval_id": approval_id,
                    "operation": operation.key,
                    "requester": requester,
                    "reason": reason,
                    "permission": operation.permission.value,
                }
            ),
            client=client,  # ADR 0150: the approver's address, matching this row's actor
        )
        try:
            self._alert_sink.approval_stale_requester(
                approval_id, operation=operation.key, reason=reason
            )
        except Exception:  # noqa: BLE001 - a sink that breaks its never-raise contract must not
            # turn the documented 409 into a 500. The audit row above is already written.
            log.exception("approval %s: the stale-requester alert failed to emit", approval_id)

    async def _flag_approver_provenance(
        self,
        approval_id: str,
        *,
        operation: str,
        approver: str,
        approver_user_id: str,
        requester: str,
        requested_at: float,
        client: str | None,
    ) -> None:
        """Audit and alert a release whose APPROVER account changed after the request was made
        (BACKLOG #315 limb b). It never refuses.

        **Why this exists.** Every approver is an Administrator, and every Administrator can create a
        new account or reset another one's password and second factor. So one Administrator can mint
        or take over the "second" approver. No check here can prove two accounts are two people, and
        the id compare in :meth:`approve` is not meant to. This makes the cheap routes loud instead.
        The account's ``created_at`` catches a minted account. ``password_changed_at`` and
        ``totp_enrolled_at`` catch a takeover of an existing one, which writes no ``user.created`` row.

        **Why it never refuses.** An approver minted or taken over BEFORE the request passes all three
        comparisons, so a refusal would stop only the careless attacker. It would also refuse an honest
        directory approver, whose engine row is created on first sign-in. So it flags every account
        type the same way.

        **It must not break a release.** A failure to read or record is logged, and the release
        continues, because this is a detection signal on an action the gate already allowed."""
        try:
            user = await self._store.get_user(approver_user_id)
        except Exception:  # noqa: BLE001 - detection only; the release must not fail on it
            log.exception(
                "approval %s: could not read the approver account to check it", approval_id
            )
            return
        if user is None:
            return
        # Strictly after: a stamp equal to requested_at is the same instant, not a later change.
        changed = [
            slug
            for slug, stamp in (
                ("account_created", user.created_at),
                ("password_changed", user.password_changed_at),
                ("totp_enrolled", user.totp_enrolled_at),
            )
            if stamp is not None and stamp > requested_at
        ]
        if not changed:
            return
        try:
            await self._store.record_audit(
                "approval.approver_provenance",
                actor=approver,
                detail=json.dumps(
                    {
                        "approval_id": approval_id,
                        "operation": operation,
                        "requester": requester,
                        "changed": changed,
                    }
                ),
                client=client,  # ADR 0150: the approver's address, matching this row's actor
            )
        except Exception:  # noqa: BLE001 - see the docstring; the release continues
            log.exception("approval %s: the approver-provenance audit row failed", approval_id)
        try:
            self._alert_sink.approval_approver_provenance(
                f"approval:{approval_id}", operation=operation, changed=tuple(changed)
            )
        except Exception:  # noqa: BLE001 - a sink that breaks its never-raise contract
            log.exception("approval %s: the approver-provenance alert failed to emit", approval_id)

    async def _compensate_failed_execution(
        self,
        approval_id: str,
        *,
        operation: str,
        approver: str,
        requester: str,
        error: BaseException,
        client: str | None,
    ) -> None:
        """Roll a released-but-unexecuted request back out of ``approved`` (ASVS 2.3.3).

        Best effort by construction: the caller re-raises the ORIGINAL executor error either way, so
        a store that is itself unreachable here must not mask the error that actually explains the
        failure. A compensation failure is logged loudly rather than swallowed."""
        try:
            # Guarded on 'approved' so this can never clobber a row another caller rejected or
            # expired, and so a re-drive of the same failure is idempotent (second call moves 0 rows).
            moved = await self._store.decide_pending_approval(
                approval_id,
                status="failed",
                approver=approver,
                decided_at=self._clock(),
                from_status="approved",
            )
            await self._store.record_audit(
                "approval.failed",
                actor=approver,
                detail=json.dumps(
                    {
                        "approval_id": approval_id,
                        "operation": operation,
                        "requester": requester,
                        # The type, never the message: an executor's exception text can carry
                        # connection names, paths or params, and the audit log is not a PHI sink.
                        "error": type(error).__name__,
                        "compensated": moved,
                    }
                ),
                client=client,
            )
        except Exception:  # noqa: BLE001 - see the docstring; the original error must win
            log.exception(
                "approval %s: executor failed AND the compensating transition failed; the row may "
                "still read 'approved' for an operation that did not run",
                approval_id,
            )

    async def reject(
        self, approval_id: str, *, approver: str, client: str | None = None
    ) -> dict[str, Any]:
        """Decline a pending request without executing it (audited). Any ``approvals:approve`` holder
        may reject — including the requester cancelling their own."""
        row = await self._require_pending(approval_id)
        if not await self._store.decide_pending_approval(
            approval_id, status="rejected", approver=approver, decided_at=self._clock()
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
            client=client,  # ADR 0150: the rejecting approver's address
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
        if expires_at is not None and float(expires_at) <= self._clock():
            raise ApprovalError(409, "request has expired")
        return row

    def _label(self, operation: str) -> str:
        op = self._ops.get(operation)
        return op.label if op is not None else operation
