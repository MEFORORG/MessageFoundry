# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The wire models of the stranded-release routes, ``GET /approvals/executing`` and
``POST /approvals/{approval_id}/interrupt`` (BACKLOG #1562).

A module of their own rather than a part of :mod:`messagefoundry.api.models`: the web console does
not render them, so they stay out of the console seam, and the rest of the approvals queue's
models keep their own home. :meth:`messagefoundry.api.approvals.ApprovalGate.interrupt_stranded`
states what each liveness value means and which ones refuse.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from messagefoundry.api.request_model import RequestModel

#: What ``ApprovalGate.interrupt_stranded`` judges of a release's owner, under the owner-delegated
#: decision of 2026-10-29 (d20261029T205247402-81159c), in three tiers: the release is live in THIS
#: process; or a cluster node owns it, and its heartbeat decides; or its owner is a name no
#: heartbeat covers, which only an operator's recorded attestation can vouch is stopped. One type
#: for the gate and the wire, so the route cannot answer a value its model refuses.
OwnerLiveness = Literal[
    "releasing_here",
    "owner_heartbeat_fresh",
    "owner_heartbeat_unreadable",
    "owner_heartbeat_unavailable",
    "owner_heartbeat_lapsed",
    "attestation_required",
]


class ExecutingApprovalInfo(BaseModel):
    """One release still claimed as ``executing``. ``claimed_at`` is when it was claimed;
    ``interrupt`` is what an interrupt would answer now: ``refused``, ``needs_attestation`` or
    ``allowed``. Params are not listed."""

    id: str
    operation: str
    operation_label: str
    requester: str
    approver: str | None = None
    requested_at: float
    claimed_at: float | None = None
    claim_owner: str | None = None
    this_process: bool
    liveness: OwnerLiveness
    interrupt: Literal["refused", "needs_attestation", "allowed"]


class ExecutingApprovalList(BaseModel):
    approvals: list[ExecutingApprovalInfo]


class ApprovalInterruptRequest(RequestModel):
    """``attest_owner_stopped`` is the operator's word that the process owning the claim is not
    running. Only an owner with no heartbeat to read needs it; the audit row records it either
    way."""

    attest_owner_stopped: bool = False


class ApprovalInterruptResult(BaseModel):
    """A stranded release now ``interrupted``, awaiting ``POST /approvals/{id}/resolve``."""

    operation: str
    requested_by: str
    approved_by: str | None = None
    claim_owner: str | None = None
    liveness: OwnerLiveness
    status: Literal["interrupted"]
