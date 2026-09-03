# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Offline uploaded-logs /ui routes (BACKLOG #125/#126, ADR 0134).

Upload / list / browse / resend / delete over the engine's uploaded-logs CoreHandlers (seam v7). The
console never touches the filesystem or the store directly — it calls the audited JSON handlers by
reference and re-asserts the equivalent permission/step-up via ``require_ui*``. The browse GET (which
decrypts PHI) is step-up-gated + registered as an UNLOCK action (like content search); delete is a
step-up, body-less, auto-retryable POST behind a confirm step; upload is a same-origin multipart POST
(no step-up — a body-carrying POST can't survive the re-auth redirect, and browsing PHI is the gated
surface). Resend is a step-up POST behind a body-less confirm step, its message index and target inbound
carried in the query so the confirm URL is a valid re-auth continuation (BACKLOG #1227).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import UploadedMessageSearchRequest, UploadResendRequest
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
# /ui/reauth and GET-redirects back to the browse page. The PHI-shaped filter now travels in the POST
# body of .../filter (BACKLOG #1184) and so cannot cross the redirect at all. The delete POST is
# body-less + step-up, so it may be auto-retried after re-auth. Upload/filter are same-origin POSTs
# (not registered); the resend POST is not registered either — its ``reauth_next`` maps it to the
# confirm page below, the same shape the /filter POST and messages' edit-resend use.
register_ui_action(
    r"^/ui/uploaded-logs/file/[^/?#]+$", Permission.FILES_BROWSE, auto_retry=False, unlock=True
)
register_ui_action(r"^/ui/uploaded-logs/file/[^/?#]+/delete$", Permission.FILES_DELETE)
# The resend confirm page (BACKLOG #1227). QUERY-TOLERANT ON PURPOSE, and the only such pattern in
# this registry — every other one forbids ``?`` by construction via ``[^/?#]+``. It has to be:
# ``reauth_next`` puts ``?index=N&to=NAME`` into ``next``, and ``lookup_ui_action`` /
# ``is_unlock_action`` fullmatch the RAW value, so a path-only pattern matches nothing and dead-ends
# the whole flow at /ui with both parameters silently gone. ``auto_retry=False`` because it is a GET;
# ``unlock=True`` so re-auth 303-GET-redirects back here with the parameters intact.
# KEEP THE OPTIONAL GROUP rather than pinning ``\?index=\d+&to=...``: this form also fullmatches the
# bare route TEMPLATE, which is what keeps the R1 coverage guard in test_webui.py able to see this
# entry. A stricter pattern would not match the template and would make that guard silently vacuous
# here — green, and covering nothing.
register_ui_action(
    r"^/ui/uploaded-logs/file/[^/?#]+/resend-confirm(\?[^#]*)?$",
    Permission.FILES_BROWSE,
    auto_retry=False,
    unlock=True,
)

_log = logging.getLogger(__name__)

#: Where a REFUSED mutation lands: the uploaded-logs LIST page, never the detail page the POST came
#: from. Two properties make it the only correct target, and both are load-bearing.
#:
#: 1. The detail GET is step-up-gated AND registered as an unlock action above, so once the step-up
#:    window goes stale it 303s to /ui/reauth — which deliberately does NOT carry the query string
#:    back (the browse filter is a GET query that can hold PHI-shaped search terms). A flag aimed at
#:    the detail page is therefore DROPPED in exactly that window, landing the operator on a plain
#:    detail page: byte-identical to what a SUCCESSFUL resend produces. The list route is a plain
#:    ``require_ui(FILES_BROWSE)`` — no step-up, and no registered action — so the flag survives.
#: 2. Success never goes here. A resend's success 303s to the detail page and a delete's success 303s
#:    to the bare list URL, so neither can be confused with a flagged failure.
_FAILED_TARGET = "/ui/uploaded-logs"

#: The outcome codes the LIST page accepts (console convention: ``?e=<code>``, allow-listed and mapped
#: to fixed text, exactly as the login page does). Each is a BOOLEAN FLAG naming one cause, nothing
#: more. Every cause below is caller-influenced — the target inbound name and the message index come
#: from the resend form body, the file id from the path, and ``exc.detail`` quotes them back — so
#: reflecting any of it into the query string would put attacker-supplied text in the URL, the referrer
#: chain, every proxy log, and finally the rendered HTML. A fixed code cannot carry a payload.
RESEND_FAILED_CODE = "resend_failed"
RESEND_DENIED_CODE = "resend_denied"
RESEND_STOPPED_CODE = "resend_stopped"
DELETE_FAILED_CODE = "delete_failed"

#: The fixed text each code maps to. The 404 one names the three causes the operator can act on WITHOUT
#: distinguishing an owner denial (ASVS 8.2.2) from an absent file — the engine answers 404 for both
#: deliberately, so this one sentence has to cover both and must not split them.
RESEND_FAILED_NOTICE = (
    "That resend did not run — nothing was injected. The file, the message number or the target "
    "inbound connection was not found. Check them and try again."
)
RESEND_DENIED_NOTICE = (
    "That resend did not run — nothing was injected. You are not authorized to inject into that "
    "inbound connection."
)
RESEND_STOPPED_NOTICE = (
    "That resend did not run — nothing was injected. The target inbound connection is registered but "
    "not running. Start it, then try again."
)
DELETE_FAILED_NOTICE = (
    "That delete did not run — nothing was removed. The file was not found. It may already be gone."
)

#: The allow-list itself: an EXACT-match lookup from code to fixed module text. ``e`` is compared, never
#: rendered — an unrecognized value maps to no banner at all rather than being echoed.
_LIST_NOTICES: dict[str, str] = {
    RESEND_FAILED_CODE: RESEND_FAILED_NOTICE,
    RESEND_DENIED_CODE: RESEND_DENIED_NOTICE,
    RESEND_STOPPED_CODE: RESEND_STOPPED_NOTICE,
    DELETE_FAILED_CODE: DELETE_FAILED_NOTICE,
}

#: Which code each refused-resend status becomes. The engine distinguishes a denied TARGET channel
#: (403) from a registered-but-stopped inbound (409) from a not-found file/inbound/index (404), and
#: each is separately actionable — collapsing them would tell the operator something untrue for two of
#: the three. Anything outside this map is not a refusal this route knows how to explain, so it is
#: re-raised rather than reported as one of these.
_RESEND_CODES: dict[int, str] = {
    403: RESEND_DENIED_CODE,
    404: RESEND_FAILED_CODE,
    409: RESEND_STOPPED_CODE,
}

#: A file id is minted as ``secrets.token_hex(16)``. The path segment reaching these routes is
#: CALLER-SUPPLIED and percent-decoded, so it can carry CR/LF and forge a log line; the engine rejects
#: a malformed id but only after this module has already decided to log. So a value that is not the
#: minted shape is logged as a fixed placeholder instead. This is a log-injection guard, not a second
#: copy of the path-traversal rule — that one stays in ``UploadStore._paths``.
_MINTED_FILE_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")


def _log_file_id(file_id: str) -> str:
    return file_id if _MINTED_FILE_ID_RE.match(file_id) else "malformed"


def _refused(code: str) -> RedirectResponse:
    """The 303 a refused mutation answers with: :data:`_FAILED_TARGET` carrying one allow-listed code."""
    return RedirectResponse(f"{_FAILED_TARGET}?e={code}", status_code=303)


def register(app: FastAPI, deps: UiDeps) -> None:
    core = deps.core

    @app.get("/ui/uploaded-logs", response_class=HTMLResponse)
    async def ui_uploaded_logs(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.FILES_BROWSE)),
        e: str | None = Query(None, max_length=32),
        # BACKLOG #1152: the listing is paged. Declared with the SAME bounds as the JSON route, so a
        # hand-typed /ui query answers 422 here rather than reaching the handler with a value the
        # engine would clamp differently -- the console must not be the looser of the two doors.
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> HTMLResponse:
        data = await core.list_uploaded_files(
            request, engine=engine, identity=identity, limit=limit, offset=offset
        )
        # The refused-mutation banner. An EXACT-key lookup in the allow-list, so the rendered string is
        # always one this module wrote — `e` itself is never rendered, echoed, or passed on, and an
        # unrecognized value yields no banner rather than reflected text.
        return HTMLResponse(pages.uploaded_logs(data, error=_LIST_NOTICES.get(e or "", "")))

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

    async def _render_browse(
        file_id: str,
        request: Request,
        engine: Any,
        identity: Identity,
        *,
        content: str | None,
        field_path: str | None,
        field_value: str | None,
        message_type: str | None,
        control_id: str | None,
        limit: int,
        error: str = "",
        status_code: int = 200,
    ) -> Response:
        """Render one uploaded file's browse page for a given filter — shared by the GET page render
        and by the POST that filters on a needle (BACKLOG #1184)."""
        # No outcome banner here: this page is step-up-gated, so a flag aimed at it is dropped whenever
        # the window is stale (see :data:`_FAILED_TARGET`). Every refused mutation reports on the list.
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

        # `error` means the criteria never validated, so there is nothing to search ON. Browse
        # metadata-only, but keep the typed values in `shared` so the form is not silently
        # blanked -- the same shape the HTTPException 400 arm below already uses.
        try:
            result = await _browse(
                *((None, None, None) if error else (content, field_path, field_value))
            )
        except HTTPException as exc:
            if exc.status_code == 404:  # bad/absent id (incl. path-traversal) → back to the list
                return RedirectResponse("/ui/uploaded-logs", status_code=303)
            if exc.status_code == 400:  # bad content criteria → re-render metadata-only + the error
                # The engine parses the criteria BEFORE it authorizes the file, so this arm is reached
                # without the file ever having been reachable. The retry drops the criteria and so runs
                # far enough to 404 — on a denied owner check (ASVS 8.2.2) or an absent/traversal id —
                # and that 404 must take the SAME 303 as above rather than escaping this except block
                # as raw JSON in the HTML plane.
                try:
                    result = await _browse(None, None, None)
                except HTTPException as retry_exc:
                    if retry_exc.status_code == 404:
                        return RedirectResponse("/ui/uploaded-logs", status_code=303)
                    raise
                return HTMLResponse(
                    pages.uploaded_log_detail(result, error=str(exc.detail), **shared),
                    status_code=400,
                )
            raise
        return HTMLResponse(
            pages.uploaded_log_detail(result, error=error, **shared), status_code=status_code
        )

    @app.get("/ui/uploaded-logs/file/{file_id}", response_class=HTMLResponse)
    async def ui_uploaded_log_browse(
        file_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.FILES_BROWSE)),
        field_path: str | None = Query(None, max_length=32),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        limit: int = Query(200, ge=1, le=500),
    ) -> Response:
        """The file's message list, filtered by the criteria that are safe on a URL (BACKLOG #1184).

        ``content`` and ``field_value`` are gone from this signature for the reason the content-search
        page states: a GET form writes the typed term into the address bar, browser history and every
        access log on the way. The filter form now POSTs to ``.../filter``, so a link still carrying
        ``?content=`` lists the whole file rather than filtering — the term is ignored, not honoured."""
        return await _render_browse(
            file_id,
            request,
            engine,
            identity,
            content=None,
            field_path=field_path,
            field_value=None,
            message_type=message_type,
            control_id=control_id,
            limit=limit,
        )

    @app.post("/ui/uploaded-logs/file/{file_id}/filter", response_class=HTMLResponse)
    async def ui_uploaded_log_filter(
        file_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.FILES_BROWSE,
                reauth_next=lambda r: r.url.path.removesuffix("/filter"),
            )
        ),
    ) -> Response:
        """Filter the browse listing on criteria carried in the request BODY (BACKLOG #1184).

        A path of its own because the browse page is a registered ``unlock`` action, which the console
        refuses to serve as a POST; ``reauth_next`` sends a stale-step-up bounce back to that page, the
        documented continuation for a body-carrying POST."""
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        try:
            # The engine's own body model for this route, so a posted form is bounded exactly as the
            # JSON API bounds it — no second, drifting copy of the field lengths.
            criteria = UploadedMessageSearchRequest(
                content=form.get("content") or None,
                field_path=form.get("field_path") or None,
                field_value=form.get("field_value") or None,
                message_type=form.get("message_type") or None,
                control_id=form.get("control_id") or None,
                limit=200,  # the form carries no page-size control; same default the GET declares
                offset=0,
            )
        except ValueError:  # pydantic: a criterion is longer than its bound
            # REFUSE, do not answer with the whole file. Returning 200 with every criterion dropped
            # and the inputs blanked reads to an operator as "your filter matched everything", which
            # is the opposite of what happened -- and it silently discarded their valid criteria too.
            # The sibling POST /ui/messages/search/run answers 400 with a banner, and the GET this
            # replaced answered 422; this arm was the only one that swallowed it (BACKLOG #1184).
            return await _render_browse(
                file_id,
                request,
                engine,
                identity,
                content=form.get("content") or None,
                field_path=form.get("field_path") or None,
                field_value=form.get("field_value") or None,
                message_type=form.get("message_type") or None,
                control_id=form.get("control_id") or None,
                limit=200,
                error="a filter criterion is longer than that field allows",
                status_code=400,
            )
        return await _render_browse(
            file_id,
            request,
            engine,
            identity,
            content=criteria.content,
            field_path=criteria.field_path,
            field_value=criteria.field_value,
            message_type=criteria.message_type,
            control_id=criteria.control_id,
            limit=criteria.limit,
        )

    @app.post("/ui/uploaded-logs/file/{file_id}/resend")
    async def ui_uploaded_log_resend(
        file_id: str,
        request: Request,
        index: int = Query(..., ge=0),
        to: str = Query(..., min_length=1, max_length=256),
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.FILES_BROWSE,
                reauth_next=lambda r: (
                    f"/ui/uploaded-logs/file/{r.path_params['file_id']}/resend-confirm"
                    f"?{r.url.query}"
                ),
            )
        ),
    ) -> Response:
        # BACKLOG #1227. The old premise here was "the browse page it posts from is already
        # step-up-gated, so the operator is fresh" — and NOTHING enforced that arrival path, so a form
        # left open past the window still posted. The freshness is now re-asserted ON THIS ROUTE,
        # because the console calls the engine handler BY REFERENCE across the CoreHandlers seam and
        # the engine's own ``require_step_up`` Depends never runs for a /ui caller.
        #
        # The two parameters ride the QUERY, not the body, so this POST is body-less and therefore
        # auto-retryable across the re-auth redirect — the same property that lets delete work. That
        # is the OPPOSITE choice from connection_writes.py's purge, which deliberately drops its
        # query: losing ``index``/``to`` here strands an operator mid-task, and neither value is
        # destructive or PHI-shaped. ``to`` is a connection name, i.e. a structural locator, which the
        # engine already writes to the audit store by name on every resend.
        #
        # Bounds live on the Query params now: the request body no longer passes through
        # UploadResendRequest's own Field(ge=0) / max_length=256 before reaching us.
        assert_same_origin(request)
        body = UploadResendRequest(index=index, to=to)
        try:
            await core.resend_uploaded_message(
                request, file_id=file_id, body=body, engine=engine, identity=identity
            )
        except HTTPException as exc:
            # A refused resend must not answer with the SUCCESS response, which is a bare 303 to the
            # detail page. Failing with the byte-identical answer to succeeding tells the operator a
            # message was injected when none was. So a refusal goes to :data:`_FAILED_TARGET` carrying
            # one allow-listed code, and the code is all that travels: `exc.detail` quotes the caller's
            # own inbound name and index back, and reflecting that into the URL or the HTML is an XSS
            # sink fed by the form body. All three of 403/404/409 are handled rather than re-raised
            # because an escaping HTTPException renders as application/json inside the HTML console,
            # with that same caller-supplied name quoted in it.
            code = _RESEND_CODES.get(exc.status_code)
            if code is None:
                raise
            # And the refusal is recorded SERVER-SIDE, so it survives whatever the browser does with
            # the redirect. file_id (shape-checked) + status only: the inbound name, the index and
            # `exc.detail` are caller-supplied text, and putting those in a log is log injection.
            _log.warning(
                "uploaded-log resend refused: file_id=%s status=%d",
                _log_file_id(file_id),
                exc.status_code,
            )
            return _refused(code)
        return RedirectResponse(f"/ui/uploaded-logs/file/{file_id}", status_code=303)

    @app.get("/ui/uploaded-logs/file/{file_id}/resend-confirm", response_class=HTMLResponse)
    async def ui_uploaded_log_resend_confirm(
        file_id: str,
        request: Request,
        index: int = Query(..., ge=0),
        to: str = Query(..., min_length=1, max_length=256),
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.FILES_BROWSE)),
    ) -> Response:
        # The confirm step for resend (BACKLOG #1227), mirroring the delete confirm below. It is
        # PLAIN require_ui, not step-up: this page is the re-auth CONTINUATION, so gating it with
        # step-up would bounce the operator straight back to /ui/reauth in a loop.
        #
        # It exists so the POST can be body-less. The selection lives in THIS page's own URL rather
        # than in server-side state, which is why the shape beats stashing the message body across
        # re-auth: nothing is stored, so no message body gains a new lifetime or a new deletion
        # question (CLAUDE.md section 9).
        #
        # Metadata read via list, exactly as delete-confirm does — a bad or absent id 404s at the
        # browse handler, and this route must not disclose one file's existence to a non-owner.
        data = await core.list_uploaded_files(request, engine=engine, identity=identity)
        match = next((f for f in data.files if f.file_id == file_id), None)
        if match is None:
            return RedirectResponse("/ui/uploaded-logs", status_code=303)
        return HTMLResponse(pages.uploaded_log_resend_confirm(file_id, match.filename, index, to))

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
            # Same shape as the resend refusal one function up: the success is a bare 303 to the list,
            # so answering a REFUSED delete with that same 303 tells the operator the file was deleted
            # when it was not — including on an ASVS 8.2.2 owner denial, which the engine answers 404
            # so it stays indistinguishable from an absent file. The flag is what separates the two,
            # and the WARNING carries the record server-side (file_id shape-checked + status only).
            if exc.status_code == 404:
                _log.warning(
                    "uploaded-log delete refused: file_id=%s status=%d",
                    _log_file_id(file_id),
                    exc.status_code,
                )
                return _refused(DELETE_FAILED_CODE)
            raise
        return RedirectResponse("/ui/uploaded-logs", status_code=303)
