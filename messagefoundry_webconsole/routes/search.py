# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""content-search: a step-up-unlock GET page over the JSON search_messages handler (ADR 0046 #51)."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    register_ui_action,
    require_ui_step_up,
)

# content-search (ADR 0046 #51): the search PAGE is step-up-gated (bulk-PHI decrypt), so register
# it as an UNLOCK form — a stale step-up 303s to /ui/reauth and GET-redirects back to the fresh
# search form (the L0c step-up-to-unlock primitive; the PHI-shaped search term is a GET query, so
# it is deliberately NOT carried across the redirect — the operator re-enters it in the window).
register_ui_action(
    r"^/ui/messages/search$", Permission.MESSAGES_READ, auto_retry=False, unlock=True
)


def register(app: FastAPI, deps: UiDeps) -> None:
    """content-search: a step-up-unlock GET page over the JSON search_messages handler."""
    core = deps.core

    @app.get("/ui/messages/search", response_class=HTMLResponse)
    async def ui_message_search(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_READ)),
        content: str | None = Query(None, max_length=512),
        field_path: str | None = Query(None, max_length=32),
        field_value: str | None = Query(None, max_length=512),
        target: str = Query("both", pattern="^(raw|summary|both)$"),
        channel_id: str | None = Query(None, max_length=256),
        status_filter: str | None = Query(None, alias="status", max_length=64),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        limit: int = Query(50, ge=1, le=500),
    ) -> HTMLResponse:
        # A criterion is required to search; with none, render the bare form (no decrypt/audit).
        # A field_path alone is a valid presence-test search (matches make_spec/row_matches),
        # so it counts as a criterion too — keeping /ui at parity with the JSON API.
        has_criteria = bool(content) or bool(field_value) or bool(field_path)
        shared = dict(
            content=content or "",
            field_path=field_path or "",
            field_value=field_value or "",
            target=target,
            channel_id=channel_id or "",
            status=status_filter or "",
            message_type=message_type or "",
            control_id=control_id or "",
        )
        if not has_criteria:
            return HTMLResponse(pages.message_search(None, **shared))
        try:
            # Call the JSON handler directly (its require_step_up Depends is skipped —
            # require_ui_step_up above re-asserted it); pass every param explicitly.
            results = await core.search_messages(
                request,
                engine=engine,
                identity=identity,
                content=content,
                field_path=field_path,
                field_value=field_value,
                target=target,
                channel_id=channel_id,
                status=status_filter,
                message_type=message_type,
                control_id=control_id,
                limit=limit,
                scan_limit=deps.default_scan_limit,
            )
        except HTTPException as exc:
            if exc.status_code == 400:  # make_spec rejected the criteria — re-render the form
                return HTMLResponse(
                    pages.message_search(None, error=str(exc.detail), **shared),
                    status_code=400,
                )
            raise
        return HTMLResponse(pages.message_search(results, **shared))
