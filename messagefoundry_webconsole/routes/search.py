# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""content-search: a step-up-unlock GET page over the JSON search_messages handler (ADR 0046 #51),
plus saved / layered filter presets (BACKLOG #151, ADR 0136)."""

from __future__ import annotations

import contextlib
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import SearchPresetCreateRequest, SearchPresetCriteria
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    assert_same_origin,
    register_ui_action,
    require_ui,
    require_ui_step_up,
)
from ._common import _form_pairs

# content-search (ADR 0046 #51): the search PAGE is step-up-gated (bulk-PHI decrypt), so register
# it as an UNLOCK form — a stale step-up 303s to /ui/reauth and GET-redirects back to the fresh
# search form (the L0c step-up-to-unlock primitive; the PHI-shaped search term is a GET query, so
# it is deliberately NOT carried across the redirect — the operator re-enters it in the window).
register_ui_action(
    r"^/ui/messages/search$", Permission.MESSAGES_READ, auto_retry=False, unlock=True
)
# The layered run (ADR 0136) is likewise a step-up-gated GET that composes + decrypts; register it as
# an UNLOCK form too. Its query carries only preset IDS (never the PHI needle — that's server-composed
# from the encrypted column), so the deliberate-drop posture is preserved.
register_ui_action(
    r"^/ui/messages/search/layered$", Permission.MESSAGES_READ, auto_retry=False, unlock=True
)


def register(app: FastAPI, deps: UiDeps) -> None:
    """content-search + saved/layered presets over the JSON handlers (ADR 0046 / 0136)."""
    core = deps.core

    async def _presets(engine: Any, identity: Identity, request: Request) -> list[Any]:
        return list(
            (
                await core.list_search_presets(engine=engine, identity=identity, request=request)
            ).presets
        )

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
        preset_list = await _presets(engine, identity, request)
        shared = dict(  # noqa: C408
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
            return HTMLResponse(pages.message_search(None, presets=preset_list, **shared))
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
                    pages.message_search(
                        None, error=str(exc.detail), presets=preset_list, **shared
                    ),
                    status_code=400,
                )
            raise
        return HTMLResponse(pages.message_search(results, presets=preset_list, **shared))

    @app.post("/ui/messages/search/presets")
    async def ui_save_preset(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_READ)),
    ) -> Response:
        # Same-origin; step-up (persists a possibly-PHI criteria). Body-carrying, so it re-opens via the
        # search page's unlock form on a stale step-up rather than being auto-retried.
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        criteria = SearchPresetCriteria(
            content=form.get("content") or None,
            field_path=form.get("field_path") or None,
            field_value=form.get("field_value") or None,
            target=form.get("target")
            if form.get("target") in ("raw", "summary", "both")
            else "both",  # type: ignore[arg-type]
            channel_id=form.get("channel_id") or None,
            status=form.get("status") or None,
            message_type=form.get("message_type") or None,
            control_id=form.get("control_id") or None,
            limit=50,
        )
        try:
            body = SearchPresetCreateRequest(name=form.get("name", ""), criteria=criteria)
            await core.create_search_preset(
                body=body, engine=engine, identity=identity, request=request
            )
        except HTTPException as exc:
            preset_list = await _presets(engine, identity, request)
            return HTMLResponse(
                pages.message_search(None, error=str(exc.detail), presets=preset_list),
                status_code=exc.status_code,
            )
        except ValueError:  # pydantic validation (e.g. empty name)
            preset_list = await _presets(engine, identity, request)
            return HTMLResponse(
                pages.message_search(None, error="a preset name is required", presets=preset_list),
                status_code=400,
            )
        return RedirectResponse("/ui/messages/search", status_code=303)

    @app.post("/ui/messages/search/presets/{preset_id}/delete")
    async def ui_delete_preset(
        preset_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_READ)),
    ) -> Response:
        # Deleting your own preset is low-risk metadata (no step-up); same-origin CSRF guard.
        assert_same_origin(request)
        # A missing preset (already deleted) → the redirect just re-renders the list.
        with contextlib.suppress(HTTPException):
            await core.delete_search_preset(
                preset_id, engine=engine, identity=identity, request=request
            )
        return RedirectResponse("/ui/messages/search", status_code=303)

    @app.get("/ui/messages/search/layered", response_class=HTMLResponse)
    async def ui_layered_search(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_READ)),
        presets: list[str] | None = Query(None),
    ) -> HTMLResponse:
        preset_list = await _presets(engine, identity, request)
        ids = ",".join(p for p in (presets or []) if p)
        if not ids:
            return HTMLResponse(
                pages.message_search(
                    None, error="select at least one preset to layer", presets=preset_list
                ),
                status_code=400,
            )
        try:
            results = await core.layered_search(
                request,
                engine=engine,
                identity=identity,
                presets=ids,
                limit=50,
                scan_limit=deps.default_scan_limit,
            )
        except HTTPException as exc:
            if exc.status_code in (400, 404):
                return HTMLResponse(
                    pages.message_search(None, error=str(exc.detail), presets=preset_list),
                    status_code=exc.status_code,
                )
            raise
        return HTMLResponse(pages.message_search(results, presets=preset_list))
