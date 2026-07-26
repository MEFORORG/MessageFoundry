# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Offline uploaded-logs /ui routes (BACKLOG #125/#126, ADR 0134).

Upload / list / browse / resend / delete over the engine's uploaded-logs CoreHandlers (seam v7). The
console never touches the filesystem or the store directly — it calls the audited JSON handlers by
reference and re-asserts the equivalent permission/step-up via ``require_ui*``. The browse GET (which
decrypts PHI) is step-up-gated + registered as an UNLOCK action (like content search); delete is a
step-up, body-less, auto-retryable POST behind a confirm step; upload is a same-origin multipart POST
(no step-up — a body-carrying POST can't survive the re-auth redirect, and browsing PHI is the gated
surface). Resend is a same-origin POST on top of the already-stepped-up browse page.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import UploadResendRequest
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    assert_same_origin,
    register_ui_action,
    require_ui,
    require_ui_step_up,
)
from ._common import _form_pairs

# The browse GET decrypts PHI (step-up), so register it as an UNLOCK form — a stale step-up 303s to
# /ui/reauth and GET-redirects back to the browse page (the PHI-shaped filter is a GET query, so it is
# deliberately NOT carried across the redirect). The delete POST is body-less + step-up, so it may be
# auto-retried after re-auth. Upload/resend are same-origin require_ui POSTs (not registered).
register_ui_action(
    r"^/ui/uploaded-logs/file/[^/?#]+$", Permission.FILES_BROWSE, auto_retry=False, unlock=True
)
register_ui_action(r"^/ui/uploaded-logs/file/[^/?#]+/delete$", Permission.FILES_DELETE)


def register(app: FastAPI, deps: UiDeps) -> None:
    core = deps.core

    @app.get("/ui/uploaded-logs", response_class=HTMLResponse)
    async def ui_uploaded_logs(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.FILES_BROWSE)),
    ) -> HTMLResponse:
        data = await core.list_uploaded_files(request, engine=engine, identity=identity)
        return HTMLResponse(pages.uploaded_logs(data))

    @app.get("/ui/uploaded-logs/upload", response_class=HTMLResponse)
    async def ui_uploaded_logs_upload_form(
        request: Request,
        _identity: Identity = Depends(require_ui(Permission.FILES_UPLOAD)),
    ) -> HTMLResponse:
        return HTMLResponse(pages.uploaded_logs_upload())

    @app.post("/ui/uploaded-logs/upload")
    async def ui_uploaded_logs_upload(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.FILES_UPLOAD)),
    ) -> Response:
        # Same-origin CSRF defense-in-depth on top of the SameSite cookie. No step-up: a multipart body
        # POST can't survive the re-auth redirect (browsing the PHI is the step-up-gated surface).
        assert_same_origin(request)
        try:
            await core.upload_file(request, engine=engine, identity=identity)
        except HTTPException as exc:
            return HTMLResponse(
                pages.uploaded_logs_upload(error=str(exc.detail)), status_code=exc.status_code
            )
        return RedirectResponse("/ui/uploaded-logs", status_code=303)

    @app.get("/ui/uploaded-logs/file/{file_id}", response_class=HTMLResponse)
    async def ui_uploaded_log_browse(
        file_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.FILES_BROWSE)),
        content: str | None = Query(None, max_length=512),
        field_path: str | None = Query(None, max_length=32),
        field_value: str | None = Query(None, max_length=512),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        limit: int = Query(200, ge=1, le=500),
    ) -> Response:
        shared = dict(  # noqa: C408
            content=content or "",
            field_path=field_path or "",
            field_value=field_value or "",
            message_type=message_type or "",
            control_id=control_id or "",
        )

        async def _browse(c: str | None, fp: str | None, fv: str | None) -> Any:
            return await core.browse_uploaded_file(
                request,
                file_id=file_id,
                engine=engine,
                identity=identity,
                content=c,
                field_path=fp,
                field_value=fv,
                target="both",
                message_type=message_type,
                control_id=control_id,
                limit=limit,
                offset=0,
            )

        try:
            result = await _browse(content, field_path, field_value)
        except HTTPException as exc:
            if exc.status_code == 404:  # bad/absent id (incl. path-traversal) → back to the list
                return RedirectResponse("/ui/uploaded-logs", status_code=303)
            if exc.status_code == 400:  # bad content criteria → re-render metadata-only + the error
                result = await _browse(None, None, None)
                return HTMLResponse(
                    pages.uploaded_log_detail(result, error=str(exc.detail), **shared),
                    status_code=400,
                )
            raise
        return HTMLResponse(pages.uploaded_log_detail(result, **shared))

    @app.post("/ui/uploaded-logs/file/{file_id}/resend")
    async def ui_uploaded_log_resend(
        file_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.FILES_BROWSE)),
    ) -> Response:
        # Same-origin; the browse page it posts from is already step-up-gated, so the operator is fresh.
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        try:
            body = UploadResendRequest(index=int(form.get("index", "")), to=form.get("to", ""))
        except (ValueError, TypeError):
            raise HTTPException(400, "index and to are required") from None
        await core.resend_uploaded_message(
            request, file_id=file_id, body=body, engine=engine, identity=identity
        )
        return RedirectResponse(f"/ui/uploaded-logs/file/{file_id}", status_code=303)

    @app.get("/ui/uploaded-logs/file/{file_id}/delete-confirm", response_class=HTMLResponse)
    async def ui_uploaded_log_delete_confirm(
        file_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.FILES_DELETE)),
    ) -> Response:
        # The confirm step (BACKLOG #126). Show the filename so the operator confirms the right file; a
        # bad/absent id (path-traversal) 404s at the browse handler, so read metadata via list here.
        data = await core.list_uploaded_files(request, engine=engine, identity=identity)
        match = next((f for f in data.files if f.file_id == file_id), None)
        if match is None:
            return RedirectResponse("/ui/uploaded-logs", status_code=303)
        return HTMLResponse(pages.uploaded_log_delete_confirm(file_id, match.filename))

    @app.post("/ui/uploaded-logs/file/{file_id}/delete")
    async def ui_uploaded_log_delete(
        file_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.FILES_DELETE)),
    ) -> Response:
        assert_same_origin(request)
        try:
            await core.delete_uploaded_file(
                request, file_id=file_id, engine=engine, identity=identity
            )
        except HTTPException as exc:
            if exc.status_code == 404:
                return RedirectResponse("/ui/uploaded-logs", status_code=303)
            raise
        return RedirectResponse("/ui/uploaded-logs", status_code=303)
