# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L3b: outbound queue purge (step-up + dual-control) + the bulk connection-control surface."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import parse_qsl

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import (
    PendingApprovalResponse,
)
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    assert_same_origin,
    register_ui_action,
    require_ui,
    require_ui_step_up,
)

_log = logging.getLogger(__name__)

# L3b: the queue purge is step-up-gated, so register it in the write-action allow-list — this is
# the first extension of the registry L0b introduced (the step-up re-auth may auto-retry the
# body-less POST because both params, name + scope, live in the PATH).
register_ui_action(r"^/ui/connections/[^/?#]+/purge/(top|all)$", Permission.MESSAGES_PURGE)
# The bulk purge CONFIRM page is a step-up-UNLOCK GET form (like content-search / create-user): a
# stale step-up 303s to /ui/reauth and, after re-verification, 303-GET-redirects BACK to it (the
# ?dest/?scope query is deliberately NOT carried across — the operator re-selects on the fresh
# page; fail-safe for a destructive op). auto_retry=False so it is never re-POSTed body-less.
register_ui_action(
    r"^/ui/connections/purge-confirm$",
    Permission.MESSAGES_PURGE,
    auto_retry=False,
    unlock=True,
)


def register(app: FastAPI, deps: UiDeps) -> None:
    """L3b: outbound queue purge (soft-cancel an outbound's queued deliveries) + the bulk
    connection-control surface. Purge is step-up-gated (require_ui_step_up → /ui/reauth) +
    dual-control (may hold for a second approver) and acts on an OUTBOUND, so a channel-scoped user
    is refused; bulk-control mirrors the per-name control primitive (CONNECTIONS_CONTROL, no
    step-up). The literal bulk paths are registered BEFORE the ``{name}/purge/{scope}`` route so a
    literal always wins over the path-param route."""
    core = deps.core

    @app.post("/ui/connections/bulk-control")
    async def ui_bulk_control(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.CONNECTIONS_CONTROL)),
    ) -> HTMLResponse:
        # Bulk Start/Stop/Restart over selected rows (both roles). require_ui re-asserts
        # CONNECTIONS_CONTROL (the dual-role handler's own Depends is skipped on a direct call).
        # Each `sel` is an encoded _row_key; dispatch per unique control target (a multi-edge
        # outbound → one destination name → fires once), capturing each per-target failure so one
        # bad target never aborts the batch. Undecodable sels render the fixed label, never bytes.
        assert_same_origin(request)
        pairs = parse_qsl((await request.body()).decode("utf-8", "replace"))
        action = next((v for k, v in pairs if k == "action"), "")
        if action not in ("start", "stop", "restart"):
            raise HTTPException(404, "unknown control action")
        outcomes: list[tuple[str | None, str]] = []
        seen: set[tuple[str, str]] = set()
        for key, value in pairs:
            if key != "sel":
                continue
            decoded = pages.decode_row_key(value)
            if decoded is None:
                outcomes.append((None, "not applied"))
                continue
            role, channel_id, destination = decoded
            name = channel_id if role == "source" else destination
            if not name:  # a destination row with no destination name is malformed
                outcomes.append((None, "not applied"))
                continue
            # Dedupe per (role, name): a multi-edge outbound is controlled once, but a same-named
            # source and destination are two distinct control targets — never collapsed to one.
            if (role, name) in seen:
                continue
            seen.add((role, name))
            try:
                result = await core.dual_role_control(engine, identity, name, action, role=role)
                outcomes.append((name, f"applied (running={result['running']})"))
            except HTTPException as exc:
                outcomes.append((name, f"{exc.status_code}: {exc.detail}"))
            except Exception:  # noqa: BLE001 - capture-and-continue; one bad target never aborts the batch
                _log.exception("bulk control %s failed for %r", action, name)
                outcomes.append((name, "error"))
        return HTMLResponse(pages.bulk_control_result(action, outcomes))

    @app.get("/ui/connections/purge-confirm", response_class=HTMLResponse)
    async def ui_purge_confirm(
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_PURGE)),
        dest: list[str] | None = Query(None),
        scope: str = Query("all", max_length=8),
    ) -> HTMLResponse:
        # Step-up-unlock confirm page for the bulk purge. A channel-scoped user can't purge a
        # shared outbound (mirrors purge_connection); validate the scope (404, not 422, matching
        # the per-name route); then RE-DERIVE eligibility from LIVE quiescence — intersect the
        # requested ?dest with rr.outbound_quiesced(d), dropping anything since-started / not-yet-
        # quiesced. On a stale step-up, require_ui_step_up already 303'd to /ui/reauth and the
        # unlock flow GET-redirects back here WITHOUT the query, so dest is empty → nothing pre-
        # armed (the operator re-selects). The confirm form POSTs to /ui/connections/purge-bulk.
        if identity.allowed_channels is not None:
            await core.audit_channel_denied(engine, identity, None)
            raise HTTPException(
                403, "channel-scoped users cannot purge a shared outbound connection"
            )
        if scope not in ("top", "all"):
            raise HTTPException(404, "unknown purge scope")
        rr = engine.registry_runner
        eligible: list[str] = []
        seen_dest: set[str] = set()
        for d in dest or []:
            if d in seen_dest:
                continue
            seen_dest.add(d)
            if rr is not None and rr.outbound_quiesced(d):
                eligible.append(d)
        return HTMLResponse(pages.purge_confirm(eligible, scope))

    @app.post("/ui/connections/purge-bulk")
    async def ui_purge_bulk(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.MESSAGES_PURGE,
                reauth_next=lambda _r: "/ui/connections/purge-confirm",
            )
        ),
        gate: Any = Depends(deps.get_gate),
    ) -> HTMLResponse:
        # The body-carrying bulk purge. require_ui_step_up re-asserts MESSAGES_PURGE + the step-up
        # window (mapping a stale window's re-auth to the confirm UNLOCK page, never a body-less
        # re-POST). Validate the scope BEFORE fan-out (a directly-called purge_connection skips its
        # own Query pattern, so an unvalidated scope would silently become purge-all). Then, per
        # UNIQUE dest, call purge_connection DIRECTLY (its require_step_up Depends is skipped, so
        # the 409 require-quiesced guard + the ApprovalGate dual-control run per dest), capturing
        # PurgeResult / PendingApprovalResponse / HTTPException(403/404/409) — one bad dest never
        # aborts the batch.
        assert_same_origin(request)
        pairs = parse_qsl((await request.body()).decode("utf-8", "replace"))
        scope = next((v for k, v in pairs if k == "scope"), "all")
        if scope not in ("top", "all"):
            raise HTTPException(404, "unknown purge scope")
        outcomes: list[tuple[str | None, str]] = []
        seen_dest: set[str] = set()
        for key, value in pairs:
            if key != "dest":
                continue
            if value in seen_dest:
                continue
            seen_dest.add(value)
            try:
                result = await core.purge_connection(
                    value,
                    Response(),
                    engine=engine,
                    scope=scope,
                    identity=identity,
                    gate=gate,
                )
                if isinstance(result, PendingApprovalResponse):
                    outcomes.append((value, f"held for approval ({result.approval_id})"))
                else:
                    outcomes.append((value, f"purged {result.cancelled}"))
            except HTTPException as exc:
                outcomes.append((value, f"{exc.status_code}: {exc.detail}"))
            except Exception:  # noqa: BLE001 - capture-and-continue; one bad dest never aborts the batch
                _log.exception("bulk purge failed for %r", value)
                outcomes.append((value, "error"))
        return HTMLResponse(pages.purge_result(scope, outcomes))

    @app.post("/ui/connections/{name}/purge/{scope}")
    async def ui_purge_connection(
        name: str,
        scope: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_PURGE)),
        gate: Any = Depends(deps.get_gate),
    ) -> Response:
        assert_same_origin(request)
        if scope not in ("top", "all"):
            raise HTTPException(404, "unknown purge scope")
        result = await core.purge_connection(
            name, Response(), engine=engine, scope=scope, identity=identity, gate=gate
        )
        if isinstance(result, PendingApprovalResponse):
            return HTMLResponse(pages.purge_pending(result))
        return RedirectResponse("/ui", status_code=303)
