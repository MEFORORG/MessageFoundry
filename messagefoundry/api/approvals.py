# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Dual-control (maker-checker) approval workflow for high-value actions (ASVS 2.3.5).

Optional and **deny-by-default** (``[approvals]``, off unless enabled). When a gated operation is
invoked it is **not executed inline**: a pending request (operation key + JSON params + requester) is
persisted, and a **distinct** second user holding ``approvals:approve`` must release it — the requester
can never approve their own (enforced server-side). On approval the captured operation is re-executed
and **both identities** land in the hash-chained audit log. A request older than
``[approvals].expiry_hours`` can no longer be approved.

A release claims the row as ``executing`` before it runs the operation, then settles it to
``approved`` (it ran), ``failed`` (it did not complete) or ``interrupted`` (cancelled mid-run, outcome
unknown, never retried). BACKLOG #1562; :meth:`ApprovalGate.approve` carries the reasoning. An
operator later records an ``interrupted`` row's effects as applied or not applied
(:meth:`ApprovalGate.resolve_interrupted`), which never re-runs the operation.

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
stated once, on :meth:`ApprovalGate._approver_changes`.

The registry (op key -> executor) is populated by the API wiring, where the engine is in scope; this
module owns only the generic hold/approve/reject mechanics over the ``pending_approvals`` store table.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from collections.abc import Awaitable, Callable, Coroutine, Mapping
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

#: What an operator records for an ``interrupted`` release, mapped to the terminal status it writes
#: (BACKLOG #1562 part B). Each status fits the SQL Server column, which is NVARCHAR(20).
RESOLVE_OUTCOMES: Mapping[str, str] = {
    "effects_applied": "resolved_applied",
    "effects_not_applied": "resolved_not_applied",
}


#: Tasks started by :func:`_shielded`. Held here because a caller that was cancelled no longer holds
#: one, and the event loop keeps only a weak reference to a running task.
_SHIELDED: set[asyncio.Task[Any]] = set()


def _log_orphaned_write(task: asyncio.Task[Any], approval_id: str) -> None:
    """Log a shielded write whose caller was cancelled, since nothing else will read its error."""
    if task.cancelled():
        log.error("approval %s: a shielded outcome write was cancelled", approval_id)
        return
    error = task.exception()
    if error is not None:
        log.error(
            "approval %s: a shielded outcome write failed after its caller was cancelled",
            approval_id,
            exc_info=error,
        )


async def _shielded[T](coro: Coroutine[Any, Any, T], approval_id: str) -> T:
    """Await ``coro`` so that cancelling the CALLER does not cancel it (BACKLOG #1562).

    A cancellation delivered while this awaits reaches the caller at once, and the write finishes on
    its own. Once the caller is gone nothing would read the write's error, so it is logged with the
    approval id. The set holding the task is module-wide and nothing drains it at shutdown; a write
    still running when the store closes fails and is logged."""
    task = asyncio.ensure_future(coro)
    _SHIELDED.add(task)
    task.add_done_callback(_SHIELDED.discard)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        task.add_done_callback(lambda t: _log_orphaned_write(t, approval_id))
        raise


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
    to — at least 404 unknown, 409 already-decided/expired/unapprovable, 403 self-approval, and 503
    when the audit log refuses the release row (the operation is then not run)."""

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
        """Requests awaiting a second approver: ``pending`` and unexpired."""
        rows = await self._store.list_pending_approvals(now=self._clock())
        return [self._queue_entry(r) for r in rows]

    async def list_interrupted(self) -> list[dict[str, Any]]:
        """Releases cut off mid-run and awaiting an operator's record of what happened
        (:meth:`resolve_interrupted`). They do not expire."""
        rows = await self._store.list_interrupted_approvals()
        return [self._queue_entry(r) for r in rows]

    def _queue_entry(self, r: Any) -> dict[str, Any]:
        return {
            "id": str(r["id"]),
            "operation": str(r["operation"]),
            "label": self._label(str(r["operation"])),
            "requester": str(r["requester"]),
            "requested_at": float(r["requested_at"]),
            "expires_at": (None if r["expires_at"] is None else float(r["expires_at"])),
            "status": str(r["status"]),
            "approver": (None if r["approver"] is None else str(r["approver"])),
            "decided_at": (None if r["decided_at"] is None else float(r["decided_at"])),
        }

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
        as a self-approver they are not. ``users.id`` never changes, so it is the key.

        **The audit log must accept the release before the operation runs (BACKLOG #1940).** An
        ``approval.release_attempted`` row is written first; if that write fails the approve is
        refused with 503 and the request stays pending. Once the operation has run, neither
        outcome write raises: a failed ``executing`` to ``approved`` status write, or a failed
        ``approval.approved`` audit write, is logged at ERROR and the release still reports success.
        A failed status write may leave the row ``executing``; see
        :meth:`_record_approved_execution`."""
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
        # BACKLOG #315 (b): READ the approver's account now, before the transition, so no store read
        # sits between the transition and the executor. The flag is written in the `finally` below.
        changed = await self._approver_changes(approver_user_id, float(row["requested_at"]))
        requester = str(row["requester"])
        # BACKLOG #1940: prove the audit log can record this release BEFORE anything moves. The
        # approval.approved row is written only after the executor has run, so an audit log that
        # refused writes would otherwise let a replay or reload complete with no record of the
        # release. This row names both identities, so a completed operation always has one. It sits
        # before the claim so that a refusal leaves the request exactly as it was: still pending,
        # nothing executed, and the approver can simply approve again.
        #
        # What it costs: at least a release that then loses the double-approve race, meets a
        # concurrent reject, is cancelled before its claim commits, or whose claim raises, leaves
        # this row with no outcome row (approval.approved, approval.failed or approval.interrupted)
        # after it. That is why it says ATTEMPTED. The request row's status, and the winner's own
        # rows, say what won.
        try:
            await self._store.record_audit(
                "approval.release_attempted",
                actor=approver,
                detail=json.dumps(
                    {
                        "approval_id": approval_id,
                        "operation": operation,
                        "requester": requester,
                    }
                ),
                client=client,  # ADR 0150: the approver's address, matching this row's actor
            )
        except Exception as exc:  # noqa: BLE001 - every store backend raises its own type
            log.exception(
                "approval %s: the audit log refused the release row, so the operation was not run "
                "and the request is still pending",
                approval_id,
            )
            raise ApprovalError(
                503,
                "the audit log could not record this release, so the operation did not run and the "
                "request is still pending; approve it again once the audit log accepts writes",
            ) from exc
        # Claim the row FIRST (atomic, guards a double-approve race); only then execute. The claim
        # moves it to 'executing', not 'approved' (BACKLOG #1562): 'approved' is written only once the
        # executor has returned, so the status never asserts an outcome the gate has not seen.
        claim = asyncio.ensure_future(
            self._store.decide_pending_approval(
                approval_id, status="executing", approver=approver, decided_at=self._clock()
            )
        )
        try:
            claimed = await asyncio.shield(claim)
        except asyncio.CancelledError:
            # Cancelled while claiming. The UPDATE can still commit, and the row would then sit in
            # 'executing' for an operation that never started. Settle it once the claim lands. The
            # approve waits for that settle before it re-raises, on purpose, like the interrupted
            # record below: the record lands before the caller answers. A second cancel stops the
            # wait, not the settle.
            await _shielded(
                self._settle_cancelled_claim(
                    claim,
                    approval_id,
                    operation=operation,
                    approver=approver,
                    requester=requester,
                    client=client,
                ),
                approval_id,
            )
            raise
        if not claimed:
            raise ApprovalError(409, "request was already decided")
        try:
            result = await op.execute(params)
        except asyncio.CancelledError:
            # BACKLOG #1562. The approve was cancelled while the executor ran -- at least a request
            # timeout (RequestTimeoutMiddleware) does this. The executor may have finished none, some
            # or all of its effects, so the outcome is UNKNOWN: record 'interrupted', never 'failed'
            # (which says the operation did not happen) and never 'approved'. Nothing retries it; a
            # blind re-run of an operation that may already have run is worse than the stuck row.
            # Shielded, so a cancellation re-delivered here cannot cancel the record of the first one.
            await _shielded(
                self._record_interrupted_execution(
                    approval_id,
                    operation=operation,
                    approver=approver,
                    requester=requester,
                    client=client,
                ),
                approval_id,
            )
            raise
        except Exception as exc:
            # ASVS 2.3.3 COMPENSATING TRANSITION. The row was claimed BEFORE the executor ran (that
            # ordering is load-bearing -- it guards the double-approve race -- and must stay). If the
            # executor raises, the row would otherwise be stranded in 'executing' for an operation
            # that did not complete, with no outcome recorded. Roll it to 'failed' and audit the
            # failure against both identities, then re-raise so the caller still sees the error.
            #
            # `except Exception` is deliberate and is not a swallow: ANY executor failure has to
            # compensate, and the original is re-raised below. CancelledError is handled above,
            # because a cancelled approve has an unknown outcome and must not be recorded as a failure.
            # Shielded for the same reason as the interrupted record above.
            await _shielded(
                self._compensate_failed_execution(
                    approval_id,
                    operation=operation,
                    approver=approver,
                    requester=requester,
                    error=exc,
                    client=client,
                ),
                approval_id,
            )
            raise
        else:
            # The executor returned, so the operation ran. Settled HERE, in `else`, because `else`
            # runs before `finally`: a cancellation landing in the provenance write below must not
            # skip it. Shielded (BACKLOG #1562): a cancellation that lands while the outcome is being
            # written must not leave the row in 'executing' for an operation that completed. The
            # caller still sees the cancellation; the record completes.
            await _shielded(
                self._record_approved_execution(
                    approval_id,
                    operation=operation,
                    approver=approver,
                    requester=requester,
                    result=result,
                    client=client,
                ),
                approval_id,
            )
        finally:
            # After the transition, so only a release that really happened is flagged, and in a
            # `finally`, so the flag lands whether the executor succeeded, failed or was cancelled.
            # On success it now lands AFTER approval.approved (the settle is in `else`), so a
            # stalled settle delays the flag; that is the price of the settle not being skipped.
            # Shielded: a cancellation re-delivered here (a request timeout inside a middleware task
            # group) would otherwise cancel the audit write too, on exactly the release it describes.
            if changed:
                await _shielded(
                    self._flag_approver_provenance(
                        approval_id,
                        operation=operation,
                        approver=approver,
                        requester=requester,
                        changed=changed,
                        client=client,
                    ),
                    approval_id,
                )
        return {
            "operation": operation,
            "requested_by": requester,
            "approved_by": approver,
            "result": result,
        }

    async def _record_approved_execution(
        self,
        approval_id: str,
        *,
        operation: str,
        approver: str,
        requester: str,
        result: dict[str, Any],
        client: str | None,
    ) -> None:
        """Move a completed release from ``executing`` to ``approved`` and write ``approval.approved``.

        The operation has run by the time this is called, so NEITHER write raises (BACKLOG #1940's
        reasoning, applied to both). A 500 would tell the approver the release failed, and a new
        request would then run the operation a second time. A failed STATUS write is logged at ERROR
        with the approval id and the row may be left ``executing``. The audit
        row is still attempted. A failed AUDIT write is logged at ERROR with the lost detail; the
        ``approval.release_attempted`` row written before the claim already records the release
        against both identities."""
        try:
            # Guarded on 'executing', so it can only move the row this call claimed.
            if not await self._store.decide_pending_approval(
                approval_id,
                status="approved",
                approver=approver,
                decided_at=self._clock(),
                from_status="executing",
            ):
                log.warning(
                    "approval %s: the operation ran but the row was no longer 'executing', so it "
                    "was not moved to 'approved'",
                    approval_id,
                )
        except Exception:  # noqa: BLE001 - the operation already ran; see the docstring
            log.exception(
                "approval %s: operation '%s' RAN, but moving the row to 'approved' failed; it may "
                "still read 'executing'. The failure is not raised, because the operation ran",
                approval_id,
                operation,
            )
        # BACKLOG #1940: the operation HAS run by this point, so a failed audit write here must not
        # turn into an error. A 500 would tell the approver the release failed, and a re-request
        # would run a replay or a reload a second time. The approval.release_attempted row already
        # records the release against both identities. What is lost is the result summary, so the
        # loss is logged at ERROR, result included (the executors return counts and step names,
        # never message content).
        #
        # The detail is built OUTSIDE the try, so a result that cannot be serialized is still a
        # loud programming error rather than a line blaming the audit log.
        approved_detail = json.dumps(
            {
                "approval_id": approval_id,
                "operation": operation,
                "requester": requester,
                "result": result,
            }
        )
        try:
            await self._store.record_audit(
                "approval.approved",
                actor=approver,
                detail=approved_detail,
                # ADR 0150: the APPROVER's address — matching this row's actor. The requester's own
                # address is on their earlier approval.requested row, so dual control records both
                # halves of the ceremony from two independently-attributed hosts.
                client=client,
            )
        except Exception:  # noqa: BLE001 - see above; the operation already ran
            log.exception(
                "approval %s: operation '%s' RAN, but its approval.approved audit row failed; the "
                "approval.release_attempted row still records the release. Lost detail: %s",
                approval_id,
                operation,
                approved_detail,
            )

    async def _settle_cancelled_claim(
        self,
        claim: asyncio.Future[bool],
        approval_id: str,
        *,
        operation: str,
        approver: str,
        requester: str,
        client: str | None,
    ) -> None:
        """Settle a claim whose approve was cancelled before the executor started (BACKLOG #1562).

        If the claim committed, nothing ran, so the outcome is known: ``failed``, through the same
        compensation as a raising executor, with ``CancelledError`` as the recorded error type. If
        it did not commit, the row is still ``pending`` and there is nothing to settle."""
        try:
            claimed = await claim
        except Exception:  # noqa: BLE001 - the caller's cancellation is re-raised either way
            log.exception(
                "approval %s: the approve was cancelled and its claim failed", approval_id
            )
            return
        if claimed:
            await self._compensate_failed_execution(
                approval_id,
                operation=operation,
                approver=approver,
                requester=requester,
                error=asyncio.CancelledError(),
                client=client,
                stage="claim",
            )

    async def _record_interrupted_execution(
        self,
        approval_id: str,
        *,
        operation: str,
        approver: str,
        requester: str,
        client: str | None,
    ) -> None:
        """Move a cancelled release from ``executing`` to ``interrupted`` and audit it (BACKLOG #1562).

        ``interrupted`` means the outcome is unknown: the executor may have finished none, some or all
        of its effects. The audit row is ``approval.interrupted``, so the trail tells an operation that
        ran (``approval.approved``) apart from one that was cut off. Best effort, like
        :meth:`_compensate_failed_execution`: the caller re-raises the cancellation either way."""
        try:
            # Guarded on 'executing' so it can only move the row this call claimed.
            moved = await self._store.decide_pending_approval(
                approval_id,
                status="interrupted",
                approver=approver,
                decided_at=self._clock(),
                from_status="executing",
            )
            await self._store.record_audit(
                "approval.interrupted",
                actor=approver,
                detail=json.dumps(
                    {
                        "approval_id": approval_id,
                        "operation": operation,
                        "requester": requester,
                        "recorded": moved,
                    }
                ),
                client=client,  # ADR 0150: the approver's address, matching this row's actor
            )
        except Exception:  # noqa: BLE001 - the cancellation is re-raised by the caller either way
            log.exception(
                "approval %s: execution was cancelled AND recording it failed; the row may still "
                "read 'executing' for an operation whose outcome is unknown",
                approval_id,
            )

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

    async def _approver_changes(self, approver_user_id: str, requested_at: float) -> list[str]:
        """Which of the approver account's credential facts changed AFTER the request (BACKLOG #315
        limb b): a closed-set slug each for ``created_at``, ``password_changed_at`` and
        ``totp_enrolled_at``. Empty when none did, or when the account cannot be read.

        **Why this exists.** One Administrator can mint or take over a second approver account, and no
        check can prove two accounts are two people (docs/SECURITY.md, "Dual-control approval").
        ``created_at`` catches a minted account; the other two catch a takeover of an existing one,
        which writes no ``user.created`` row. The result only FLAGS the release. A refusal would stop
        only an attacker careless enough to mint AFTER the request, and would refuse an honest
        directory approver whose engine row is created at first sign-in.

        **What reads wrong.** ``requested_at`` is this gate's clock and the account stamps are the
        store writer's, so the clock skew described at the dwell floor shifts this comparison too.
        And a login that rehashes a password after an argon2 parameter change restamps
        ``password_changed_at``, so the first release by each approver after such a change is flagged
        with no credential change behind it.

        **It must not block a release.** A read failure is logged and reads as "nothing changed"."""
        try:
            user = await self._store.get_user(approver_user_id)
        except Exception:  # noqa: BLE001 - detection only; the release must not fail on it
            log.exception("could not read approver account %s to check it", approver_user_id)
            return []
        if user is None:
            return []
        # Strictly after: a stamp equal to requested_at is the same instant, not a later change.
        return [
            slug
            for slug, stamp in (
                ("account_created", user.created_at),
                ("password_changed", user.password_changed_at),
                ("totp_enrolled", user.totp_enrolled_at),
            )
            if stamp is not None and stamp > requested_at
        ]

    async def _flag_approver_provenance(
        self,
        approval_id: str,
        *,
        operation: str,
        approver: str,
        requester: str,
        changed: list[str],
        client: str | None,
    ) -> None:
        """Audit and alert a release whose approver account changed after the request
        (:meth:`_approver_changes`). Best effort: the release has already happened."""
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
        stage: str = "execute",
    ) -> None:
        """Roll a released request that did not complete out of ``executing`` (ASVS 2.3.3).

        ``stage`` says where it stopped: ``execute`` when the executor raised, ``claim`` when the
        approve was cancelled while claiming and the executor never started (BACKLOG #1562).

        Best effort by construction: the caller re-raises the ORIGINAL error either way, so a store
        that is itself unreachable here must not mask the error that actually explains the failure.
        A compensation failure is logged loudly rather than swallowed."""
        try:
            # Guarded on 'executing' so this can never clobber a row another caller rejected or
            # expired, and so a re-drive of the same failure is idempotent (second call moves 0 rows).
            moved = await self._store.decide_pending_approval(
                approval_id,
                status="failed",
                approver=approver,
                decided_at=self._clock(),
                from_status="executing",
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
                        "stage": stage,
                        "compensated": moved,
                    }
                ),
                client=client,
            )
        except Exception:  # noqa: BLE001 - see the docstring; the original error must win
            log.exception(
                "approval %s: the release did not complete (stage %s) AND the compensating "
                "transition failed; the row may still read 'executing'",
                approval_id,
                stage,
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

    async def resolve_interrupted(
        self,
        approval_id: str,
        *,
        outcome: str,
        resolver: str,
        resolver_user_id: str,
        client: str | None = None,
    ) -> dict[str, Any]:
        """Record what happened to an ``interrupted`` release (BACKLOG #1562 part B).

        An interrupted release may have done none, some or all of its work, and only a person who has
        checked the operation's own effects can say which. ``outcome`` is that person's record:
        ``effects_applied`` or ``effects_not_applied`` (:data:`RESOLVE_OUTCOMES`). The row moves to
        the matching terminal status and an ``approval.resolved`` audit row names the resolver.

        **The operation is never run again.** This method never calls an executor. A blind re-run of
        an operation that may already have run is the failure the ``interrupted`` status exists to
        prevent; an operator who finds the effects missing requests the operation afresh, through the
        ordinary dual-control path.

        **Who may resolve (owner ruling 2026-09-26).** Any holder of ``approvals:approve`` with a
        fresh step-up (the route's gate), except the original requester. The refusal compares user
        ids, like the self-approval refusal in :meth:`approve` (BACKLOG #1540). The approver who
        released the request may resolve it.

        The row keeps the releasing approver in its ``approver`` column, because that column says who
        released it. The resolver is recorded only in the audit row.

        The status write and the audit row run shielded, as one unit: a cancel cannot leave a
        resolved row with no audit row. If the audit log refuses the row, the status write is undone
        and the call answers 503."""
        status = RESOLVE_OUTCOMES.get(outcome)
        if status is None:
            raise ApprovalError(422, f"unknown outcome '{outcome}'")
        row = await self._store.get_pending_approval(approval_id)
        if row is None:
            raise ApprovalError(404, "no such approval request")
        current = str(row["status"])
        if current != "interrupted":
            raise ApprovalError(
                409, f"request is {current}; only an interrupted request can be resolved"
            )
        requester_user_id = row["requester_user_id"]
        if not requester_user_id:
            # Fail closed, for the reason approve() gives: with no id there is no way to tell the
            # requester apart from anyone else, and the stored name is not a usable key.
            raise ApprovalError(
                409,
                "this request has no recorded requester id, so it cannot be checked for "
                "self-resolution and cannot be resolved here",
            )
        if str(requester_user_id) == resolver_user_id:
            raise ApprovalError(403, "you cannot resolve your own request")
        return await _shielded(
            self._record_resolution(
                approval_id,
                row=row,
                outcome=outcome,
                status=status,
                resolver=resolver,
                client=client,
            ),
            approval_id,
        )

    async def _record_resolution(
        self,
        approval_id: str,
        *,
        row: Any,
        outcome: str,
        status: str,
        resolver: str,
        client: str | None,
    ) -> dict[str, Any]:
        """The status write and its audit row for :meth:`resolve_interrupted`."""
        releaser = None if row["approver"] is None else str(row["approver"])
        interrupted_at = float(row["decided_at"]) if row["decided_at"] is not None else None
        operation = str(row["operation"])
        requester = str(row["requester"])
        # Guarded on 'interrupted', so two resolvers cannot both record an outcome.
        if not await self._store.decide_pending_approval(
            approval_id,
            status=status,
            approver=releaser,
            decided_at=self._clock(),
            from_status="interrupted",
        ):
            raise ApprovalError(409, "request was already resolved")
        try:
            await self._store.record_audit(
                "approval.resolved",
                actor=resolver,
                detail=json.dumps(
                    {
                        "approval_id": approval_id,
                        "operation": operation,
                        "requester": requester,
                        "approver": releaser,
                        "outcome": outcome,
                        "status": status,
                    }
                ),
                client=client,  # ADR 0150: the resolver's address, matching this row's actor
            )
        except Exception as exc:  # noqa: BLE001 - every store backend raises its own type
            # A resolution with no audit row would be an unattributed change to a dual-control
            # record. Undo the status write, guarded on the status just written, so it can only move
            # the row this call moved.
            try:
                restored = await self._store.decide_pending_approval(
                    approval_id,
                    status="interrupted",
                    approver=releaser,
                    decided_at=interrupted_at if interrupted_at is not None else self._clock(),
                    from_status=status,
                )
            except Exception:  # noqa: BLE001 - the 503 below is raised either way
                log.exception("approval %s: undoing an unaudited resolution failed", approval_id)
                restored = False
            if restored:
                log.error(
                    "approval %s: the audit log refused the resolution row, so the request was "
                    "put back to 'interrupted'",
                    approval_id,
                    exc_info=exc,
                )
                raise ApprovalError(
                    503,
                    "the audit log could not record this resolution, so the request is still "
                    "interrupted; resolve it again once the audit log accepts writes",
                ) from exc
            log.error(
                "approval %s: the audit log refused the resolution row AND the row could not be "
                "put back; it reads '%s' with no approval.resolved audit row",
                approval_id,
                status,
                exc_info=exc,
            )
            raise ApprovalError(
                503,
                f"the audit log could not record this resolution, and the request could not be "
                f"put back: it now reads '{status}' with no audit record of who resolved it",
            ) from exc
        return {
            "operation": operation,
            "requested_by": requester,
            "approved_by": releaser,
            "resolved_by": resolver,
            "outcome": outcome,
            "status": status,
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
