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
from messagefoundry.api.security import enforce_phi_read_pacing
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
# search form (the L0c step-up-to-unlock primitive). The PHI-shaped term now travels in the POST body
# of /ui/messages/search/run (BACKLOG #1184), which cannot survive a redirect at all, so the operator
# re-enters it in the fresh window — the same posture as before, now enforced by the shape.
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

    async def _render_search(
        request: Request,
        engine: Any,
        identity: Identity,
        *,
        content: str | None,
        field_path: str | None,
        field_value: str | None,
        target: str,
        channel_id: str | None,
        status_filter: str | None,
        message_type: str | None,
        control_id: str | None,
        limit: int,
    ) -> HTMLResponse:
        """Render the search page for one set of criteria — shared by the GET form render and by the
        POST that runs a needle-bearing search (BACKLOG #1184). Everything below this line is identical
        for both; only where the criteria CAME FROM differs, which is the whole point of the split."""
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
            # BACKLOG #1025: this bare-form render returns WITHOUT reaching core.search_messages,
            # whose body charges the per-actor read budget. Charge here — only on the short-circuit
            # branch — so the render is under the same budget as a real search WITHOUT double-charging
            # it (429 + Retry-After when the actor is over budget).
            enforce_phi_read_pacing(request, identity)
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

    @app.get("/ui/messages/search", response_class=HTMLResponse)
    async def ui_message_search(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        # No gate-level phi= here (BACKLOG #1025): require_ui_step_up charges the budget in the
        # dependency, i.e. on EVERY request, but a criteria-bearing search already charges once inside
        # core.search_messages (its body calls enforce_phi_read_pacing, app.py) — so a gate-level phi=
        # would spend the same per-actor bucket twice on the real-search path. The genuinely-unpaced
        # path is only the bare-form render, which is charged explicitly in its branch below.
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_READ)),
        field_path: str | None = Query(None, max_length=32),
        target: str = Query("both", pattern="^(raw|summary|both)$"),
        channel_id: str | None = Query(None, max_length=256),
        status_filter: str | None = Query(None, alias="status", max_length=64),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        limit: int = Query(50, ge=1, le=500),
    ) -> HTMLResponse:
        """The search FORM, plus a field-path-only search (BACKLOG #1184, ASVS 14.2.1).

        ``content`` and ``field_value`` are gone from this signature. A GET form puts whatever the
        operator typed into the address bar, browser history, the engine access log and any proxy log in
        front of it — and a patient identifier is exactly what gets typed here. The form now POSTs to
        ``/ui/messages/search/run``, so an old bookmark carrying ``?content=`` renders the bare form
        rather than searching: the term is ignored, not honoured. ``field_path`` stays because it is a
        structural locator (``PID-3``), which is why the audit records it by value and never the needle."""
        return await _render_search(
            request,
            engine,
            identity,
            content=None,
            field_path=field_path,
            field_value=None,
            target=target,
            channel_id=channel_id,
            status_filter=status_filter,
            message_type=message_type,
            control_id=control_id,
            limit=limit,
        )

    @app.post("/ui/messages/search/run", response_class=HTMLResponse)
    async def ui_message_search_run(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        # Same no-gate-phi= reasoning as the GET above: this arm always reaches core.search_messages,
        # which charges the per-actor read budget in its own body. The one branch that does NOT reach it
        # — the invalid-criteria re-render — charges inline, exactly as the bare-form branch does.
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.MESSAGES_READ, reauth_next=lambda _r: "/ui/messages/search"
            )
        ),
    ) -> HTMLResponse:
        """Run a search whose criteria arrive in the request BODY (BACKLOG #1184).

        A path of its own rather than a POST on the form page: an ``unlock`` action is a GET form the
        re-auth flow 303-GET-redirects to, and the console refuses to serve a POST at such a path
        (``test_write_action_method_matches_its_continuation``). ``reauth_next`` therefore points a
        stale-step-up bounce at the form page — the documented continuation for a body-carrying POST —
        which also drops the typed term, the same deliberate posture the GET form had."""
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        try:
            # SearchPresetCriteria carries the SAME bounds as the JSON route's Query declarations, so a
            # posted form is validated exactly as a query string was. Reusing a model the console
            # already imports leaves the engine seam untouched.
            criteria = SearchPresetCriteria(
                content=form.get("content") or None,
                field_path=form.get("field_path") or None,
                field_value=form.get("field_value") or None,
                target=form.get("target")  # type: ignore[arg-type]
                if form.get("target") in ("raw", "summary", "both")
                else "both",
                channel_id=form.get("channel_id") or None,
                status=form.get("status") or None,
                message_type=form.get("message_type") or None,
                control_id=form.get("control_id") or None,
                limit=50,  # the form carries no page-size control; same default the GET declares
            )
        except ValueError:  # pydantic: a criterion is longer than its bound
            enforce_phi_read_pacing(request, identity)  # this arm never reaches the paced handler
            preset_list = await _presets(engine, identity, request)
            return HTMLResponse(
                pages.message_search(
                    None,
                    error="a search criterion is longer than that field allows",
                    presets=preset_list,
                ),
                status_code=400,
            )
        return await _render_search(
            request,
            engine,
            identity,
            content=criteria.content,
            field_path=criteria.field_path,
            field_value=criteria.field_value,
            target=criteria.target,
            channel_id=criteria.channel_id,
            status_filter=criteria.status,
            message_type=criteria.message_type,
            control_id=criteria.control_id,
            limit=criteria.limit,
        )

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
        try:
            # Inside the try, unlike before. The criteria model enforces the API's own input rules
            # (BACKLOG #1108), so a criterion that breaks one raises HERE; built outside, that
            # exception left the route as a 500 instead of the form's own error.
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
        except ValueError:  # pydantic: an empty name, or a criterion that breaks its input rule
            # The message says WHICH field is at fault only in the generic sense. pydantic's own text
            # quotes the offending value, and that value is form input on a PHI-shaped page, so it is
            # never rendered.
            preset_list = await _presets(engine, identity, request)
            return HTMLResponse(
                pages.message_search(
                    None,
                    error="a preset name is required, and each criterion must be a valid value",
                    presets=preset_list,
                ),
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
        # No gate-level phi= here, as on ui_message_search (BACKLOG #1025): the composed run already
        # charges once inside core.layered_search, so a gate-level phi= would double-charge that path.
        # The no-preset 400 re-render is the only unpaced path, charged explicitly in its branch below.
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_READ)),
        presets: list[str] | None = Query(None),
    ) -> HTMLResponse:
        preset_list = await _presets(engine, identity, request)
        ids = ",".join(p for p in (presets or []) if p)
        if not ids:
            # BACKLOG #1025, as on ui_message_search: this no-preset 400 re-render returns before
            # core.layered_search (which charges the budget in its own body), so charge here — only on
            # this short-circuit branch — to bring it under the per-actor read budget without
            # double-charging the composed-run path.
            enforce_phi_read_pacing(request, identity)
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
