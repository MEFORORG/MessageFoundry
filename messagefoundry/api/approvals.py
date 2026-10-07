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
(:meth:`ApprovalGate.resolve_interrupted`), which never re-runs the operation. The claim records
which engine process owns the release, and at that process's next start
:meth:`ApprovalGate.reconcile_after_restart` moves any row it left ``executing`` to ``interrupted``.

A request YOUNGER than ``[approvals].min_dwell_seconds`` cannot be approved yet (ASVS 2.4.2). The expiry
is a ceiling; this is the floor. The refusal is a 409 with a ``Retry-After`` header naming the
remaining wait, an ``approval.too_early`` audit row and an ``approval_too_early`` alert, and the
request stays pending. Nothing retries it: the approver must approve again. Where the default comes
from, and what the floor does not do, is stated once in docs/SECURITY.md under "Dual-control approval
for high-value actions".

On release the **requester** is re-validated too (ASVS 8.3.2). The request is refused, audited and
alerted if the requester no longer exists, is disabled, no longer holds the permission the operation
requires, or has left the channel scope it needs. Authority is read at release rather than remembered
from the request, because it can be withdrawn inside the ``expiry_hours`` window.

The check reads the ENGINE's copy of the account: the ``users`` row and its stored roles and scope.
For a directory (AD) requester that copy lags the directory. ``docs/SECURITY.md`` states which
directory changes reach the engine's row, and when, under *Dual-control approval for high-value
actions*. Probing the directory at release is not built.

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
from typing import Any, NoReturn
from uuid import uuid4

from messagefoundry.auth.identity import Identity
from messagefoundry.auth.permissions import Permission
from messagefoundry.config.settings import ApprovalsSettings
from messagefoundry.controlchars import scrub_log_argument
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.redaction import json_loads_or_refusal
from messagefoundry.store.base import Store
from messagefoundry.store.store import AuditAppend

log = logging.getLogger(__name__)

#: An executor re-runs a captured operation on approval, returning a small JSON-able result summary.
#:
#: **A raise means the operation did not complete.** The gate compensates it to ``failed``. So an
#: executor raises only BEFORE its effects happen, and after them it reports trouble in its result
#: instead. In particular, a domain audit row it writes after acting must be fail-soft (BACKLOG
#: #1940). A row that commits WITH the effect, as the released replay's does (BACKLOG #2624), may
#: raise: a failed append rolls the effect back, so the operation did not complete. The gate does
#: not write either row for it: the row is the one the operation's inline route writes, built from
#: detail only the executor holds, and the inline route shares the writer (vault BACKLOG #2255,
#: finding 1).
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


#: How long :meth:`ApprovalGate.drain` waits for outcome writes still running at shutdown. It shares
#: NSSM's 15 s graceful-stop window (AppStopMethodConsole in scripts/service/install-service.ps1)
#: with the upload runner's 5 s stop, which runs first, and engine.stop() still has to run after it.
#: One outcome write is a status update and an audit row, so a few seconds is ample.
DRAIN_TIMEOUT_SECONDS = 3.0

#: The claim owner of an engine that is neither an engine shard nor a cluster node (BACKLOG #1562).
#: Fixed, so a plain ``serve`` recognises its own claims after a restart. Two such engines over one
#: store would share it; that layout is unsupported for other reasons too (``__main__`` says why).
DEFAULT_CLAIM_OWNER = "engine"

#: How many open requests :meth:`ApprovalGate.rejoin` reads, newest first. A repeat whose request
#: sits further back is not found there and falls through to the proof and :meth:`ApprovalGate.guard`,
#: whose own repeat rule still joins it; only the proof-free path is lost.
REJOIN_SCAN_LIMIT = 1000


@dataclass(frozen=True)
class RestartReconciliation:
    """What :meth:`ApprovalGate.reconcile_after_restart` found. Each field lists approval ids."""

    #: Rows this process had claimed in its previous life, now ``interrupted``.
    interrupted: tuple[str, ...]
    #: Rows this process owns whose move failed. They stay ``executing`` until the next start.
    unsettled: tuple[str, ...]
    #: Rows another claim owner holds. Left alone: the owner may be alive and running them.
    foreign: tuple[str, ...]


def _stored_params(approval_id: str, raw: Any) -> dict[str, Any] | None:
    """A row's captured params, or ``None`` when the stored value is not a JSON object. The one
    decoder for the queue (BACKLOG #2458) and for :meth:`ApprovalGate.approve`, so the two agree on
    what is readable: the queue lists such a row as unreadable, and approve refuses it with a 409.
    Logged by id and a content-free hint only, because the value may be anything."""
    params, refusal = json_loads_or_refusal(str(raw))
    if refusal is not None or not isinstance(params, dict):
        log.warning(
            "approval %s: its stored params are not a JSON object (%s)",
            approval_id,
            refusal or "not an object",
        )
        return None
    return params


def _log_orphaned_write(task: asyncio.Future[Any], approval_id: str) -> None:
    """Log a shielded write whose caller was cancelled, since nothing else will read its error.

    Reading the error here also marks it retrieved, so asyncio does not report it again."""
    if task.cancelled():
        log.error("approval %s: a shielded outcome write was cancelled", approval_id)
        return
    error = task.exception()
    if isinstance(error, ApprovalError) and error.status == 409:
        # A conflict the gate raises on purpose, such as a resolve that lost the race to another
        # operator. The row's status already says what won, so it is not an ERROR.
        log.warning(
            "approval %s: a shielded outcome write was refused after its caller was cancelled "
            "(%d): %s",
            approval_id,
            error.status,
            error.detail,
        )
    elif error is not None:
        log.error(
            "approval %s: a shielded outcome write failed after its caller was cancelled",
            approval_id,
            exc_info=error,
        )


async def _outlive_caller[T](task: asyncio.Future[T]) -> T:
    """Await ``task`` so that cancelling the CALLER does not cancel it.

    Not ``asyncio.shield``. When a shield's caller is cancelled and the task later raises, the shield
    reports the error itself through the loop's exception handler ("exception in shielded future").
    The gate logs that error too, so one failure was logged twice (BACKLOG #2087). ``asyncio.wait``
    never cancels what it waits on and reports nothing, so the gate's own log line is the only one."""
    await asyncio.wait((task,))
    return task.result()


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
    when the store refuses a write the decision needs before anything runs: the release row, the
    claim, a rejection or a resolution (vault BACKLOG #2255)."""

    def __init__(self, status: int, detail: str, *, headers: dict[str, str] | None = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        #: Response headers the API should send with the refusal, such as ``Retry-After``.
        self.headers = headers


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
        claim_owner: str | Callable[[], str] = DEFAULT_CLAIM_OWNER,
    ) -> None:
        self._store = store
        self._settings = settings
        # Written on every claim, and read back by reconcile_after_restart (BACKLOG #1562). It must
        # be the same across a restart of this engine process and differ between processes that
        # share the store; the API wiring passes Engine.instance_identity. A callable is read on
        # first use and then fixed, so an app built before its engine has loaded a sharded graph
        # still claims under the shard's name, and the owner never changes mid-life.
        self._claim_owner_source = claim_owner
        self._claim_owner_value = claim_owner if isinstance(claim_owner, str) else None
        self._ops: dict[str, _Operation] = {}
        # Wall-clock seconds, injectable so a test can drive the expiry ceiling and the dwell floor.
        self._clock = clock
        # With no resolver the requester's permissions cannot be re-read, so approve() refuses every
        # release (fail closed) rather than executing on authority it could not check.
        self._resolve_identity = resolve_identity
        self._alert_sink: AlertSink = alert_sink if alert_sink is not None else LoggingAlertSink()
        # Outcome writes started by _shielded, mapped to their approval id. Held here because a
        # caller that was cancelled no longer holds one, and the event loop keeps only a weak
        # reference to a running task. Per gate rather than per module (BACKLOG #2087), so drain()
        # sees only this gate's writes and no set outlives the loop its tasks ran on.
        self._inflight: dict[asyncio.Future[Any], str] = {}

    async def _shielded[T](self, coro: Coroutine[Any, Any, T], approval_id: str) -> T:
        """Await ``coro`` so that cancelling the CALLER does not cancel it (BACKLOG #1562).

        A cancellation delivered while this awaits reaches the caller at once, and the write finishes
        on its own. Once the caller is gone nothing would read the write's error, so it is logged
        once, with the approval id. :meth:`drain` waits for a write still running at shutdown."""
        task = asyncio.ensure_future(coro)
        self._inflight[task] = approval_id
        task.add_done_callback(self._forget)
        try:
            return await _outlive_caller(task)
        except asyncio.CancelledError:
            task.add_done_callback(lambda t: _log_orphaned_write(t, approval_id))
            raise

    def _forget(self, task: asyncio.Future[Any]) -> None:
        self._inflight.pop(task, None)

    @property
    def claim_owner(self) -> str:
        """The claim owner this gate writes and reconciles under (BACKLOG #1562)."""
        if self._claim_owner_value is None:
            source = self._claim_owner_source
            self._claim_owner_value = source if isinstance(source, str) else source()
        return self._claim_owner_value

    async def drain(self, timeout: float = DRAIN_TIMEOUT_SECONDS) -> list[str]:
        """Wait up to ``timeout`` seconds for outcome writes still running (BACKLOG #2087).

        The managed lifespan calls this before ``engine.stop()`` closes the store. A write whose
        caller was cancelled, such as by a request timeout, then lands instead of meeting a closed
        store. Returns the approval ids of any writes still running at the deadline, and logs them
        at ERROR. Nothing is cancelled: a write that outlives the drain meets the closing store, and
        its own failure is logged. ``create_app(engine=...)`` gives its app a lifespan that calls
        this at shutdown; a caller that passes its own lifespan calls it itself, before it stops
        the engine.

        It re-reads the set until it is empty, so a write started while it waits is drained too."""
        deadline = asyncio.get_running_loop().time() + timeout
        stuck: list[str] = []
        while self._inflight:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                stuck = sorted(self._inflight.values())
                break
            _done, still = await asyncio.wait(list(self._inflight), timeout=remaining)
            if still:
                stuck = sorted(self._inflight[t] for t in still)
                break
        if stuck:
            log.error(
                "approvals: %d outcome write(s) still running after %.1fs at shutdown, so they may "
                "fail when the store closes; approval ids: %s",
                len(stuck),
                timeout,
                ", ".join(stuck),
            )
        return stuck

    async def reconcile_after_restart(self) -> RestartReconciliation:
        """Move this process's leftover ``executing`` rows to ``interrupted`` (BACKLOG #1562).

        Call it once at startup, before the API serves approvals, and once per engine process: a
        second app over the same engine would take this process's live releases for leftovers. A
        row this process claimed in its previous life and never settled is a release whose outcome
        the gate never recorded. At least three things leave one: the process died mid-run, both of
        :meth:`_settle`'s writes failed (the operation ran), or a claim committed but its reply was
        lost (nothing ran). The audit trail may say which; the status does not, so each such row
        moves to ``interrupted``
        with an ``approval.interrupted`` audit row in the SAME write (vault BACKLOG #2255), whose
        ``reason`` is ``engine_restart``. Nothing re-runs: an operator records what happened through
        :meth:`resolve_interrupted`, exactly as for a release cut off by a cancel.

        **Only this process's rows.** Engine shards and cluster nodes share one store, so an
        ``executing`` row may be a sibling's release still running. A row moves only when its
        ``claim_owner`` is this gate's. Any other row is left alone and logged at WARNING, with its
        owner and claim time. If that owner never comes back, the row stays ``executing``: the
        gate cannot tell a dead owner from a slow one, so it does not guess on a timer.

        **A row with no owner is treated as this process's.** Only a claim made before the
        ``claim_owner`` column existed has none. Nothing was deployed then (CLAUDE.md section 0),
        so such a row can only be left over from a development store.

        A move that fails is logged and skipped. The row stays ``executing`` and the next start
        tries again; writing the status alone would leave an ``interrupted`` row with no audit row
        saying why. A failed READ raises, for the caller to log."""
        me = self.claim_owner
        interrupted: list[str] = []
        unsettled: list[str] = []
        # Filtered in SQL, so other owners' stranded rows cannot push ours past the read's cap.
        for row in await self._store.list_executing_approvals(claim_owner=me):
            approval_id = str(row["id"])
            owner = row["claim_owner"]
            approver = None if row["approver"] is None else str(row["approver"])
            detail = json.dumps(
                {
                    "approval_id": approval_id,
                    "operation": str(row["operation"]),
                    "requester": str(row["requester"]),
                    "approver": approver,
                    "claim_owner": None if owner is None else str(owner),
                    "claimed_at": (None if row["decided_at"] is None else float(row["decided_at"])),
                    "reason": "engine_restart",
                    "recorded": True,
                }
            )
            try:
                # Guarded on 'executing' and written back with the releasing approver, as the
                # resolve path does: the column says who released the request.
                moved = await self._store.decide_pending_approval(
                    approval_id,
                    status="interrupted",
                    approver=approver,
                    decided_at=self._clock(),
                    from_status="executing",
                    audit=AuditAppend("approval.interrupted", actor="system", detail=detail),
                )
            except Exception:  # noqa: BLE001 - every store backend raises its own type
                log.exception(
                    "approval %s: could not mark this process's leftover 'executing' release "
                    "interrupted; it stays 'executing' and the next start tries again",
                    approval_id,
                )
                unsettled.append(approval_id)
                continue
            if moved:
                interrupted.append(approval_id)
            else:
                log.info(
                    "approval %s: settled by another caller between the read and the move",
                    approval_id,
                )
        foreign: list[str] = []
        for row in await self._store.list_executing_approvals():
            owner = row["claim_owner"]
            if owner is None or str(owner) == me:
                continue  # a row of ours whose move failed, already logged above
            foreign.append(str(row["id"]))
            log.warning(
                "approval %s: still 'executing' under claim owner %s since %s. This process is "
                "%s, so it leaves the row alone; it moves to 'interrupted' only when an engine "
                "with that owner starts, which an unpinned cluster node never does",
                row["id"],
                owner,
                row["decided_at"],
                me,
            )
        if interrupted:
            log.warning(
                "approvals: %d release(s) this process claimed before it restarted never recorded "
                "an outcome, so they are now 'interrupted'. Check each operation's effects and "
                "record them through POST /approvals/{id}/resolve; approval ids: %s",
                len(interrupted),
                ", ".join(interrupted),
            )
        return RestartReconciliation(tuple(interrupted), tuple(unsettled), tuple(foreign))

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

    @property
    def settings(self) -> ApprovalsSettings:
        """A copy of the ``[approvals]`` this gate was built with. ``GET /security/posture`` names a
        loosened dwell or expiry from it (BACKLOG #2489). A copy, so a reader cannot change what the
        gate enforces. A request already pending keeps the deadline stamped when it was made."""
        return self._settings.model_copy(deep=True)

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
        :meth:`approve` compares; ``requester`` is the display/audit label (BACKLOG #1540).

        **A repeat files nothing (vault BACKLOG #2445).** When the same requester already has an
        OPEN request for this operation with identical captured params, that request's id is
        returned, so the endpoint answers the same 202. An ``approval.request_repeated`` row names
        the requester and the request they were pointed at. Two such calls racing land on one
        request: the store makes the check and the insert one serialized step.

        **A repeat that reaches here has already paid its step-up.** The JSON purge and reload
        routes take a single-use proof bound to their action (vault BACKLOG #2625). A request that
        brought no proof calls :meth:`rejoin` BEFORE the proof is demanded, so there a repeat of an
        open request is answered without one and never gets this far. A repeat still arrives here
        with a spent proof in at least three cases: a JSON repeat that brought a proof, a console
        purge or reload, whose gate demands a proof on every request, and a repeat that races the
        first request's commit.

        **A different requester gets their own request.** The requester of record is the person
        whose authority :meth:`approve` re-checks (ASVS 8.3.2), and the executors attribute their
        rows to the name captured in the params. Folding a second person into the first one's
        request would let their ask ride on someone else's standing, and point their 202 at a
        request they do not own and could release as its checker. An approver sees both requests,
        each with its own requester. Two of the three gated operations capture the requester in
        their params already, so for them the params would differ anyway.

        Every approver sees ``params`` in the queue; :class:`~messagefoundry.api.models.PendingApprovalInfo`
        states what they may carry (BACKLOG #2458)."""
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
        detail = json.dumps({"approval_id": approval_id, "operation": operation})
        repeat_of: list[str] = []

        def _repeat(existing: str) -> AuditAppend:
            repeat_of.append(existing)
            return AuditAppend(
                "approval.request_repeated",
                actor=requester,
                detail=json.dumps({"approval_id": existing, "operation": operation}),
                client=client,  # ADR 0150: the requester's own address
            )

        try:
            # vault BACKLOG #2255: the request and its approval.requested row are one write, so no
            # releasable request exists without the row that says who asked for it.
            held = await self._store.create_pending_approval(
                approval_id=approval_id,
                operation=operation,
                params=json.dumps(dict(params), sort_keys=True),
                requester=requester,
                requester_user_id=requester_user_id,
                requested_at=now,
                expires_at=expires_at,
                audit=AuditAppend(
                    "approval.requested",
                    actor=requester,
                    detail=detail,
                    client=client,  # ADR 0150: the requester's own address
                ),
                on_repeat=_repeat,
            )
        except Exception:
            # Still raised. A write that failed before its COMMIT held nothing, but a COMMIT that
            # landed before the error (a lost reply, a driver timeout) holds the request and its
            # row, and a retry the repeat rule misses files a second one; docs/SECURITY.md lists
            # the cases. Logged and paged, since the error alone reaches only this caller. A
            # cancel (the request timeout) is a BaseException and skips this block entirely. A
            # repeat's lost row is keyed on the request it named, which stays held.
            lost_id, action = (
                (repeat_of[-1], "approval.request_repeated")
                if repeat_of
                else (approval_id, "approval.requested")
            )
            log.exception(
                "approval %s: the write carrying its %s audit row failed. The request is still "
                "held under this id if this was a repeat. It is also held, with that row, if the "
                "COMMIT landed before the error. Lost detail: actor=%s operation=%s",
                lost_id,
                action,
                scrub_log_argument(requester),  # CodeQL py/log-injection; see scrub_log_argument
                operation,
            )
            self._alert_lost_audit(lost_id, action)
            raise
        if held != approval_id:
            log.info(
                "approval %s: a repeat %s request by %s joined it; nothing new is held",
                held,
                operation,
                scrub_log_argument(requester),
            )
        return held

    async def rejoin(
        self,
        operation: str,
        params: Mapping[str, Any],
        *,
        requester: str,
        requester_user_id: str,
        client: str | None = None,
    ) -> str | None:
        """Point a repeat at the requester's OPEN request, filing nothing (vault BACKLOG #2625).

        Returns the id :meth:`guard` would join this request to, after writing the same
        ``approval.request_repeated`` row, or ``None`` when there is no such request, or dual
        control does not gate ``operation``. ``None`` means the caller goes on to its step-up proof
        and then :meth:`guard`. The match is :meth:`guard`'s: same operation, same captured params,
        same ``requester_user_id``, pending and unexpired, oldest first.

        It exists so a route can answer a repeat BEFORE it demands an action-bound proof. Returning
        an id here never runs anything and never holds anything new, so a caller who already has an
        open request needs no new proof to be told its id again. Its permissions, pacing, MFA and
        the rest of its gate still apply. A first request still needs the proof, because this finds
        nothing for it.

        **The read and the audit row are two steps, not one.** A request approved, rejected or
        expired between them is still named in the 202. Nothing new runs or is held because of it.
        The read also covers only the newest :data:`REJOIN_SCAN_LIMIT` open requests; past that, the
        repeat needs a proof, and :meth:`guard` then joins it."""
        if not self._gated(operation) or not requester_user_id:
            return None
        wanted = json.dumps(dict(params), sort_keys=True)
        rows = await self._store.list_pending_approvals(now=self._clock(), limit=REJOIN_SCAN_LIMIT)
        matches = [
            r
            for r in rows
            if str(r["operation"]) == operation
            and str(r["params"]) == wanted
            and str(r["requester_user_id"] or "") == requester_user_id
        ]
        if not matches:
            return None
        held = str(min(matches, key=lambda r: float(r["requested_at"]))["id"])
        try:
            await self._store.record_audit(
                "approval.request_repeated",
                actor=requester,
                detail=json.dumps({"approval_id": held, "operation": operation}),
                client=client,  # ADR 0150: the requester's own address
            )
        except Exception:
            log.exception(
                "approval %s: the approval.request_repeated row for a repeat %s request failed. "
                "The request is still held under this id. Lost detail: actor=%s",
                held,
                operation,
                scrub_log_argument(requester),  # CodeQL py/log-injection; see scrub_log_argument
            )
            self._alert_lost_audit(held, "approval.request_repeated")
            raise
        log.info(
            "approval %s: a repeat %s request by %s rejoined it before its step-up; nothing new is "
            "held",
            held,
            operation,
            scrub_log_argument(requester),
        )
        return held

    async def list_pending(self, *, caller_user_id: str | None = None) -> list[dict[str, Any]]:
        """Requests awaiting a second approver: ``pending`` and unexpired. ``caller_user_id`` marks
        the caller's own requests (``caller_is_requester``)."""
        rows = await self._store.list_pending_approvals(now=self._clock())
        return [self._queue_entry(r, caller_user_id) for r in rows]

    async def list_interrupted(self, *, caller_user_id: str | None = None) -> list[dict[str, Any]]:
        """Releases cut off mid-run and awaiting an operator's record of what happened
        (:meth:`resolve_interrupted`). They do not expire. ``caller_user_id`` as for
        :meth:`list_pending`."""
        rows = await self._store.list_interrupted_approvals()
        return [self._queue_entry(r, caller_user_id) for r in rows]

    def _queue_entry(self, r: Any, caller_user_id: str | None) -> dict[str, Any]:
        operation = str(r["operation"])
        return {
            # BACKLOG #2460: keyed on the immutable id, like the refusals it predicts (#1540), so a
            # page can hide Approve from the requester. A row with no id never matches; approve
            # refuses it anyway.
            "caller_is_requester": bool(caller_user_id)
            and str(r["requester_user_id"] or "") == caller_user_id,
            "id": str(r["id"]),
            "operation": operation,
            "label": self._label(operation),
            "params": _stored_params(str(r["id"]), r["params"]),
            "requester": str(r["requester"]),
            "requested_at": float(r["requested_at"]),
            "expires_at": (None if r["expires_at"] is None else float(r["expires_at"])),
            "status": str(r["status"]),
            "approver": (None if r["approver"] is None else str(r["approver"])),
            "decided_at": (None if r["decided_at"] is None else float(r["decided_at"])),
            # The same test approve() refuses on (approval.no_longer_gated), so a page can stop
            # offering a release the gate would refuse. Read now, like the refusal it predicts.
            "gated": self._gated(operation),
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
        one younger than ``[approvals].min_dwell_seconds`` (409, ``approval.too_early``), and one
        whose operation dual control no longer gates (409, ``approval.no_longer_gated``;
        :meth:`_refuse_ungated`).

        **The refusal compares user ids, never usernames (BACKLOG #1540).** The stored ``requester``
        and the live ``approver`` are two snapshots of a directory-writable name, taken up to
        ``[approvals].expiry_hours`` apart (``users.username`` became mutable in BACKLOG #1532), so a
        name comparison is wrong in both directions: a requester renamed inside the window passes the
        refusal and releases their own request, and whoever is later given the freed name is refused
        as a self-approver they are not. ``users.id`` never changes, so it is the key.

        **The audit log must accept the release before the operation runs (BACKLOG #1940).** The
        claim (``pending`` to ``executing``) and its ``approval.release_attempted`` row are ONE
        write (vault BACKLOG #2255). If it fails the approve is refused with 503, nothing runs, and
        the request stays pending. Once the operation has run, the outcome write does not raise; see
        :meth:`_settle`.

        **The writes on this path answer a mapped status in a store outage (vault BACKLOG #2255).** A
        refusal's own audit row (``approval.too_early``, ``approval.stale_requester``,
        ``approval.no_longer_gated``) that fails to write is logged and the refusal still answers
        409, since it runs nothing. A release whose approver account changed after the request
        writes ``approval.approver_provenance``. That row is soft too, and pages if it fails. It is
        written whether the operation succeeded, failed or was cut off. Many failed writes on this path also page
        ``audit_write_failed``, but not all of them. docs/SECURITY.md, in its approvals section,
        names at least the ones that do and at least the ones that do not. That list is not closed,
        and the code is the authority. The store READS here (the request row, the
        requester's account) are not mapped, so a store that refuses reads can still answer a raw
        500.

        **Who writes the post-execution audit row.** The gate writes ``approval.approved``; an
        executor writes the domain row its inline route writes too (``dead_letter_replay``,
        ``config_reload``), because only it holds that row's detail and the inline route shares the
        writer. An executor must therefore not raise once its effects have happened, since a raise
        reads as "did not complete" and is compensated to ``failed``; see :data:`Executor`."""
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
        if not self._gated(operation):
            # Dual control was turned off for this operation after the request was held. Releasing
            # it now would run a held request under a control the deployment no longer applies,
            # and the request's own configured shape (who must approve, how old) says nothing
            # about that. Fail closed: refuse, stay pending until it expires or is rejected.
            await self._refuse_ungated(approval_id, row, approver=approver, client=client)
        params = _stored_params(approval_id, row["params"])
        if params is None:
            # The queue lists such a row as "unreadable" (BACKLOG #2458). Refuse it as a 409 that
            # leaves the row pending for a reject, rather than a 500 from a bare parse. Before the
            # dwell floor, so a row that can never be released writes no too-early row or alert.
            raise ApprovalError(409, "request parameters are unreadable; reject it instead")
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
            # vault BACKLOG #2255: a refusal runs nothing, so an audit log that refuses this row
            # must not turn the documented 409 into a 500. The loss is logged and paged instead.
            await self._record_audit_soft(
                approval_id,
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
                context="the release was refused",
            )
            # BACKLOG #287: page on it too. An approve inside the floor is faster than the published
            # human-timing figure, so it may be a script. Best effort, after the durable audit row.
            # A NEGATIVE age is a clock behind the requester's, not a fast approver, so it pages
            # nothing; the audit row still records it. A small positive skew cannot be told apart.
            if age >= 0:
                try:
                    self._alert_sink.approval_too_early(
                        f"approval:{approval_id}", operation=operation
                    )
                except Exception:  # noqa: BLE001 - a sink that breaks its never-raise contract
                    # must not turn the documented 409 into a 500. The audit row is already attempted.
                    log.exception("approval %s: the too-early alert failed to emit", approval_id)
            # The real remaining wait, not the floor: when this clock is behind the requester's, the
            # wait is longer than the floor, and saying "less than 2 seconds old" would mislead.
            # age < min_dwell here, so the ceiling is at least 1 and Retry-After is never 0.
            wait = math.ceil(min_dwell - age)
            raise ApprovalError(
                409,
                f"this request is too new to approve (the minimum is {min_dwell} seconds); "
                f"review it and approve it again in {wait} second(s)",
                headers={"Retry-After": str(wait)},
            )
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
        # Claim the row FIRST (atomic, guards a double-approve race); only then execute. The claim
        # moves it to 'executing', not 'approved' (BACKLOG #1562): 'approved' is written only once the
        # executor has returned, so the status never asserts an outcome the gate has not seen.
        #
        # BACKLOG #1940, vault BACKLOG #2255: the claim and its approval.release_attempted row are
        # ONE write, so the audit log has accepted the release before anything runs, and a claimed
        # row always has it. The row names both identities, so a completed operation always has a
        # record even if approval.approved is lost later. A claim that loses the race, or meets a
        # reject, moves nothing and writes no row. A fault answers 503 and nothing has run. A
        # claim whose COMMIT landed before the fault was reported can still leave the row
        # 'executing' with nothing run; reconcile_after_restart moves it to 'interrupted' at this
        # process's next start, and the claim owner written here is how it knows the row is ours.
        attempted = AuditAppend(
            "approval.release_attempted",
            actor=approver,
            detail=json.dumps(
                {"approval_id": approval_id, "operation": operation, "requester": requester}
            ),
            client=client,  # ADR 0150: the approver's address, matching this row's actor
        )
        claim = asyncio.ensure_future(
            self._store.decide_pending_approval(
                approval_id,
                status="executing",
                approver=approver,
                decided_at=self._clock(),
                audit=attempted,
                claim_owner=self.claim_owner,
            )
        )
        try:
            claimed = await _outlive_caller(claim)
        except asyncio.CancelledError:
            # Cancelled while claiming. The UPDATE can still commit, and the row would then sit in
            # 'executing' for an operation that never started. Settle it once the claim lands. The
            # approve waits for that settle before it re-raises, on purpose, like the interrupted
            # record below: the record lands before the caller answers. A second cancel stops the
            # wait, not the settle.
            await self._shielded(
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
        except Exception as exc:  # noqa: BLE001 - every store backend raises its own type
            # Mapped here rather than inside the claim's future: a cancelled claim's settle logs
            # its own fault, and the same fault must be logged once (BACKLOG #2087).
            raise self._store_fault(
                approval_id,
                exc,
                what="claim",
                action=attempted.action,
                retry=(
                    "The operation did not run. If the request still reads pending, approve it "
                    "again once the store accepts writes"
                ),
            ) from exc
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
            await self._shielded(
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
            await self._shielded(
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
            await self._shielded(
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
                await self._shielded(
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
        """Move a completed release from ``executing`` to ``approved`` with its
        ``approval.approved`` row (:meth:`_settle`).

        The operation has run by the time this is called, so nothing here raises (BACKLOG #1940). A
        500 would tell the approver the release failed, and a new request would then run the
        operation a second time. If ``approval.approved`` is lost, what is lost is the result
        summary: the ``approval.release_attempted`` row written with the claim already records the
        release against both identities. The loss is logged at ERROR, result included (the
        executors return counts and step names, never message content)."""
        await self._settle(
            approval_id,
            status="approved",
            action="approval.approved",
            approver=approver,
            # Serialized before any write, so a result that cannot be serialized is still a loud
            # programming error rather than a line blaming the audit log.
            fields={
                "approval_id": approval_id,
                "operation": operation,
                "requester": requester,
                "result": result,
            },
            flag=None,
            # ADR 0150: the APPROVER's address, matching this row's actor. The requester's own
            # address is on their earlier approval.requested row, so dual control records both
            # halves of the ceremony from two independently-attributed hosts.
            client=client,
            context=f"operation '{operation}' RAN (approval.release_attempted still records it)",
        )

    async def _settle(
        self,
        approval_id: str,
        *,
        status: str,
        action: str,
        approver: str,
        fields: dict[str, Any],
        flag: str | None,
        client: str | None,
        context: str,
    ) -> None:
        """Move a claimed row out of ``executing`` to ``status``, with its ``action`` audit row in
        the SAME write (vault BACKLOG #2255). Never raises: by now the operation has run, or its
        outcome is unknown, and the caller's own answer must stand.

        The write is guarded on ``executing``, so it can only move the row this release claimed.

        **When the combined write fails**, the status is written alone, so an audit outage never
        leaves the row ``executing``. If that status write finds the row already moved, the method
        stops there. The combined write most likely committed. No second row is written, and
        nothing pages. Otherwise the audit row is written alone. If that fails as well, the loss is
        logged at ERROR with the detail and pages ``audit_write_failed``. If the status
        write fails too, the row may still read ``executing`` until this process restarts, when
        :meth:`reconcile_after_restart` moves it to ``interrupted`` (BACKLOG #2087 limb 4).

        ``flag`` names a detail field that records whether the row moved: ``True`` when it moved
        with this row, ``False`` when another caller had already moved it, and ``None`` when the
        status write failed."""

        def detail(moved: bool | None) -> str:
            # default=str: a result json cannot encode must not raise here, before the status
            # moves, after the operation ran. That would strand the row 'executing'.
            return json.dumps(fields if flag is None else {**fields, flag: moved}, default=str)

        combined = AuditAppend(action, actor=approver, detail=detail(True), client=client)
        moved: bool | None
        try:
            moved = await self._store.decide_pending_approval(
                approval_id,
                status=status,
                approver=approver,
                decided_at=self._clock(),
                from_status="executing",
                audit=combined,
            )
        except Exception:  # noqa: BLE001 - the outcome stands; see the docstring
            log.exception(
                "approval %s: %s, but writing the '%s' status with its %s row failed; writing the "
                "status alone",
                approval_id,
                context,
                status,
                action,
            )
            moved = await self._settle_status_only(approval_id, status=status, approver=approver)
            if moved is False:
                # Nothing else should move a row out of 'executing' while this process runs (the
                # restart reconcile runs once, before its first claim), so the likeliest cause:
                # the combined write COMMITTED and only its reply was lost: its row is then already
                # in the log, and writing another would duplicate the outcome with a false flag.
                log.error(
                    "approval %s: %s; the combined write most likely committed, so no second %s "
                    "row is written. Check the audit log for it",
                    approval_id,
                    context,
                    action,
                )
                return
        else:
            if moved:
                return
            log.warning(
                "approval %s: %s, but the row was no longer 'executing', so it was not moved to "
                "'%s'",
                approval_id,
                context,
                status,
            )
        # The row has no audit row yet: it did not move with one. This is the only record left.
        await self._record_audit_soft(
            approval_id,
            action,
            actor=approver,
            detail=detail(moved),
            client=client,
            context=context,
        )

    async def _settle_status_only(
        self, approval_id: str, *, status: str, approver: str
    ) -> bool | None:
        """The status half of :meth:`_settle`, written alone. ``None`` when the write fails, which
        is logged; ``False`` says another caller moved the row first, so the two must differ."""
        try:
            return await self._store.decide_pending_approval(
                approval_id,
                status=status,
                approver=approver,
                decided_at=self._clock(),
                from_status="executing",
            )
        except Exception:  # noqa: BLE001 - the caller's outcome stands either way
            log.exception(
                "approval %s: writing the '%s' status alone failed too; the row may still read "
                "'executing' until this engine restarts and marks it interrupted",
                approval_id,
                status,
            )
            return None

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
                "approval %s: the approve was cancelled and its claim failed, so its "
                "approval.release_attempted row was not written",
                approval_id,
            )
            # The claim carries its audit row, so a failed claim lost that row too; page it, as
            # the uncancelled path does through _store_fault.
            self._alert_lost_audit(approval_id, "approval.release_attempted")
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
        ran (``approval.approved``) apart from one that was cut off. Its ``recorded`` field says
        whether the row moved (:meth:`_settle`). The caller re-raises the cancellation either way."""
        await self._settle(
            approval_id,
            status="interrupted",
            action="approval.interrupted",
            approver=approver,
            fields={"approval_id": approval_id, "operation": operation, "requester": requester},
            flag="recorded",
            client=client,  # ADR 0150: the approver's address, matching this row's actor
            context="the release was cut off mid-run",
        )

    async def _record_audit_soft(
        self,
        approval_id: str,
        action: str,
        *,
        actor: str,
        detail: str,
        client: str | None,
        context: str,
    ) -> None:
        """Write one of the gate's audit rows without letting a failed write raise.

        For a row whose answer stands whether or not it lands: a refusal, which runs nothing and
        leaves the request pending, or an outcome the gate has already settled. Before vault
        BACKLOG #2255 a failed write at the refusals turned a documented 409 into a raw 500. The
        loss is logged at ERROR with ``context`` and the detail, and paged."""
        try:
            await self._store.record_audit(action, actor=actor, detail=detail, client=client)
        except Exception:  # noqa: BLE001 - every store backend raises its own type
            log.exception(
                "approval %s: %s, but its %s audit row failed. Lost detail: %s",
                approval_id,
                context,
                action,
                # The detail names the requester. It is JSON, so the scrub leaves it byte-identical;
                # it is here for CodeQL py/log-injection, which cannot see that.
                scrub_log_argument(detail),
            )
            self._alert_lost_audit(approval_id, action)

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
        it is the durable record, and the alert is best-effort by the sink's own contract. A failed
        audit write does not stop the refusal or the alert (vault BACKLOG #2255)."""
        await self._record_audit_soft(
            approval_id,
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
            context="the release was refused",
        )
        try:
            self._alert_sink.approval_stale_requester(
                approval_id, operation=operation.key, reason=reason
            )
        except Exception:  # noqa: BLE001 - a sink that breaks its never-raise contract must not
            # turn the documented 409 into a 500. The audit row above is already attempted.
            log.exception("approval %s: the stale-requester alert failed to emit", approval_id)

    async def _refuse_ungated(
        self, approval_id: str, row: Any, *, approver: str, client: str | None
    ) -> NoReturn:
        """Refuse a release whose operation dual control no longer gates, and say why.

        Either ``[approvals].enabled`` is now off, or the operation has left
        ``[approvals].operations``. The audit row is ``approval.no_longer_gated``, written soft like
        the other refusals: it runs nothing, so a lost row must not turn the 409 into a 500. The
        request stays ``pending``; the approver rejects it, or it expires."""
        operation = str(row["operation"])
        if not self._settings.enabled:
            reason, why = "approvals_disabled", "dual control is now off ([approvals].enabled)"
        else:
            reason, why = (
                "operation_not_gated",
                f"'{operation}' is no longer in [approvals].operations",
            )
        await self._record_audit_soft(
            approval_id,
            "approval.no_longer_gated",
            actor=approver,
            detail=json.dumps(
                {
                    "approval_id": approval_id,
                    "operation": operation,
                    "requester": str(row["requester"]),
                    "reason": reason,
                }
            ),
            client=client,  # ADR 0150: the approver's address, matching this row's actor
            context="the release was refused",
        )
        raise ApprovalError(
            409,
            f"{why}, so this held request can no longer be released. Reject it. If the operation "
            "is still needed, run it again: it now runs without a second approver",
        )

    def _alert_lost_audit(self, approval_id: str, action: str) -> None:
        """Page on an audit row the gate could not write (vault BACKLOG #2255).

        The caller logs the loss itself, with whatever detail it holds. This only raises the
        ``audit_write_failed`` alert, and is best effort by the sink's own contract."""
        try:
            self._alert_sink.audit_write_failed(f"approval:{approval_id}", action=action)
        except Exception:  # noqa: BLE001 - a sink that breaks its never-raise contract
            log.exception("approval %s: the audit_write_failed alert failed to emit", approval_id)

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
        await self._record_audit_soft(
            approval_id,
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
            context="the release went ahead",
        )
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

        Best effort by construction (:meth:`_settle`): the caller re-raises the ORIGINAL error either
        way, so a store that is itself unreachable here must not mask the error that actually
        explains the failure. The ``executing`` guard means this can never clobber a row another
        caller rejected or expired, and a re-drive of the same failure moves nothing. The
        ``compensated`` field says whether the row moved."""
        await self._settle(
            approval_id,
            status="failed",
            action="approval.failed",
            approver=approver,
            fields={
                "approval_id": approval_id,
                "operation": operation,
                "requester": requester,
                # The type, never the message: an executor's exception text can carry
                # connection names, paths or params, and the audit log is not a PHI sink.
                "error": type(error).__name__,
                "stage": stage,
            },
            flag="compensated",
            client=client,
            context=f"the release did not complete (stage {stage})",
        )

    async def reject(
        self, approval_id: str, *, approver: str, client: str | None = None
    ) -> dict[str, Any]:
        """Decline a pending request without executing it (audited). Any ``approvals:approve`` holder
        may reject — including the requester cancelling their own.

        The move and its ``approval.rejected`` row are ONE write (vault BACKLOG #2255), so a
        rejected row always says who rejected it. If that write fails the call answers 503, pages
        ``audit_write_failed``, and the request stays pending: reject it again once the store
        accepts writes."""
        row = await self._require_pending(approval_id)
        operation = str(row["operation"])
        moved = await self._decide_or_503(
            approval_id,
            what="rejection",
            retry="If the request still reads pending, reject it again once the store accepts writes",
            status="rejected",
            approver=approver,
            audit=AuditAppend(
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
            ),
        )
        if not moved:
            raise ApprovalError(409, "request was already decided")
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

        **The move and its ``approval.resolved`` row are ONE write (vault BACKLOG #2255)**, so a
        resolved row always names its resolver and the outcome they recorded. If that write fails
        the call answers 503, pages ``audit_write_failed``, and the row stays ``interrupted``. A
        resolver who loses a race to another moves nothing and writes no row; the row's status, and
        the winner's ``approval.resolved``, say what won.

        The status write replaces ``decided_at``, so the audit row carries the cut-off time as
        ``interrupted_at``.

        The write runs shielded, so a cancel cannot leave it half done."""
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
        releaser = None if row["approver"] is None else str(row["approver"])
        detail = json.dumps(
            {
                "approval_id": approval_id,
                "operation": str(row["operation"]),
                "requester": str(row["requester"]),
                "approver": releaser,
                "outcome": outcome,
                "status": status,
                "interrupted_at": (None if row["decided_at"] is None else float(row["decided_at"])),
            }
        )
        await self._shielded(
            self._record_resolution(
                approval_id,
                status=status,
                releaser=releaser,
                resolver=resolver,
                detail=detail,
                client=client,
            ),
            approval_id,
        )
        return {
            "operation": str(row["operation"]),
            "requested_by": str(row["requester"]),
            "approved_by": releaser,
            "resolved_by": resolver,
            "outcome": outcome,
            "status": status,
        }

    async def _record_resolution(
        self,
        approval_id: str,
        *,
        status: str,
        releaser: str | None,
        resolver: str,
        detail: str,
        client: str | None,
    ) -> None:
        """The guarded status write, with ``approval.resolved``, for :meth:`resolve_interrupted`."""
        # Guarded on 'interrupted', so two resolvers cannot both record an outcome. The releaser is
        # written back unchanged: the column says who released the request.
        moved = await self._decide_or_503(
            approval_id,
            what="resolution",
            retry=(
                "If the request still reads interrupted, resolve it again once the store accepts "
                "writes"
            ),
            status=status,
            approver=releaser,
            from_status="interrupted",
            audit=AuditAppend(
                "approval.resolved",
                actor=resolver,
                detail=detail,
                client=client,  # ADR 0150: the resolver's address, matching this row's actor
            ),
        )
        if not moved:
            raise ApprovalError(
                409, "request is no longer interrupted; another operator resolved it first"
            )

    async def _decide_or_503(
        self,
        approval_id: str,
        *,
        what: str,
        retry: str,
        status: str,
        approver: str | None,
        audit: AuditAppend,
        from_status: str = "pending",
    ) -> bool:
        """``decide_pending_approval`` with its audit row in the same write, and a fault answered
        as 503 rather than a raw 500 (vault BACKLOG #2255). Used where nothing has run yet, so a
        refusal is the right answer. ``what`` names the decision in the log and the detail;
        ``retry`` tells the caller what to do once the store accepts writes."""
        try:
            return await self._store.decide_pending_approval(
                approval_id,
                status=status,
                approver=approver,
                decided_at=self._clock(),
                from_status=from_status,
                audit=audit,
            )
        except Exception as exc:  # noqa: BLE001 - every store backend raises its own type
            raise self._store_fault(
                approval_id, exc, what=what, action=audit.action, retry=retry
            ) from exc

    def _store_fault(
        self, approval_id: str, exc: Exception, *, what: str, action: str, retry: str
    ) -> ApprovalError:
        """Log and page a fault on a status write made before anything ran, and return the 503
        that answers it (vault BACKLOG #2255). The status and its ``action`` audit row are one
        write, so usually neither landed. A COMMIT can land despite the error, and docs/SECURITY.md
        lists at least those cases. The store cannot say which of the two refused. So this pages
        ``audit_write_failed`` for any fault on that write, a pool timeout included: the row is
        most likely lost, whatever the cause. The ERROR line beside it carries the exception, not
        the row's detail. ``what`` names the decision in the log and the detail; ``retry`` tells
        the caller what to do."""
        log.error(
            "approval %s: the store failed to record the %s and its %s audit row",
            approval_id,
            what,
            action,
            exc_info=exc,
        )
        self._alert_lost_audit(approval_id, action)
        return ApprovalError(503, f"the store could not record this {what}. {retry}")

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
