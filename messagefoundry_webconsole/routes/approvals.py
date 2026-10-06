# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Approvals page and its approve, reject and resolve actions (ASVS 2.3.5, BACKLOG #1982,
#2460)."""

from __future__ import annotations

from typing import Any, get_args

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import (
    ApprovalDecisionResult,
    ApprovalList,
    ApprovalResolveRequest,
    ResolveOutcome,
)
from messagefoundry.api.validation import ResourceId
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import assert_same_origin, register_ui_action, require_ui, require_ui_step_up

# BACKLOG #2460: the resolve is a body-less POST whose outcome rides the PATH, so /ui/reauth may
# re-POST it after a stale step-up window, the way a dead-letter replay or a purge is re-POSTed.
register_ui_action(
    rf"^/ui/approvals/[^/?#]+/resolve/({'|'.join(get_args(ResolveOutcome))})$",
    Permission.APPROVALS_APPROVE,
)


def _refused(exc: HTTPException) -> HTMLResponse:
    """A handler refusal as a page, keyed by the engine's status, carrying its headers (a too-new
    request's ``Retry-After``). The detail is the engine's fixed refusal text, never PHI."""
    return HTMLResponse(
        pages.approval_refused(exc.status_code, str(exc.detail)),
        status_code=exc.status_code,
        headers=exc.headers,
    )


def register(app: FastAPI, deps: UiDeps) -> None:
    """``GET /ui/approvals`` and the approve, reject and resolve POSTs.

    Each calls its JSON handler directly, which SKIPS that handler's own gate:
    ``require(APPROVALS_APPROVE)`` on the list, ``require_paced(APPROVALS_APPROVE)`` on approve and
    reject, ``require_step_up(APPROVALS_APPROVE)`` on resolve. So each route asserts
    ``approvals:approve`` through ``require_ui``, which also paces a /ui write per actor (BACKLOG
    #287) and checks provenance before it charges, and the resolve through ``require_ui_step_up``,
    which asks for the same fresh re-proof the JSON resolve does. The POSTs call
    ``assert_same_origin`` inline as well, as every /ui write does.

    The identity is passed through unchanged, because the self-approval and self-resolution
    refusals live in the gate and key on ``identity.user_id`` (BACKLOG #1540). The id takes the JSON
    route's own ``ResourceId`` type, since calling the handler directly skips its path validation
    too.

    Approve and reject are not registered with ``register_ui_action``: that registry serves the
    step-up re-auth continuation, and plain ``require_ui`` never routes through ``/ui/reauth``. The
    resolve is registered above, because its gate does."""
    core = deps.core

    @app.get("/ui/approvals", response_class=HTMLResponse)
    async def ui_approvals(
        identity: Identity = Depends(require_ui(Permission.APPROVALS_APPROVE)),
        gate: Any = Depends(deps.get_gate),
        m: str = Query("", max_length=32),
    ) -> HTMLResponse:
        try:
            listing: ApprovalList = await core.list_approvals(identity=identity, gate=gate)
        except HTTPException as exc:
            return _refused(exc)
        return HTMLResponse(pages.approvals_page(listing, notice=m))

    @app.post("/ui/approvals/{approval_id}/approve")
    async def ui_approve(
        approval_id: ResourceId,
        request: Request,
        identity: Identity = Depends(require_ui(Permission.APPROVALS_APPROVE)),
        gate: Any = Depends(deps.get_gate),
    ) -> Response:
        assert_same_origin(request)
        try:
            result: ApprovalDecisionResult = await core.approve_action(
                approval_id, request, identity=identity, gate=gate
            )
        except HTTPException as exc:
            return _refused(exc)
        return HTMLResponse(pages.approval_approved(result))

    @app.post("/ui/approvals/{approval_id}/reject")
    async def ui_reject(
        approval_id: ResourceId,
        request: Request,
        identity: Identity = Depends(require_ui(Permission.APPROVALS_APPROVE)),
        gate: Any = Depends(deps.get_gate),
    ) -> Response:
        assert_same_origin(request)
        try:
            await core.reject_action(approval_id, request, identity=identity, gate=gate)
        except HTTPException as exc:
            return _refused(exc)
        return RedirectResponse("/ui/approvals?m=rejected", status_code=303)

    @app.post("/ui/approvals/{approval_id}/resolve/{outcome}")
    async def ui_resolve(
        approval_id: ResourceId,
        outcome: ResolveOutcome,
        request: Request,
        identity: Identity = Depends(require_ui_step_up(Permission.APPROVALS_APPROVE)),
        gate: Any = Depends(deps.get_gate),
    ) -> Response:
        # BACKLOG #2460: record what an interrupted release did. Never re-runs the operation; the
        # gate refuses the requester and any row that is not interrupted.
        assert_same_origin(request)
        try:
            await core.resolve_action(
                approval_id,
                ApprovalResolveRequest(outcome=outcome),
                request,
                identity=identity,
                gate=gate,
            )
        except HTTPException as exc:
            return _refused(exc)
        return RedirectResponse(f"/ui/approvals?m={outcome}", status_code=303)
