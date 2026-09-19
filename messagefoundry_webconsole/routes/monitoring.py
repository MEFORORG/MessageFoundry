# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""L1a: read-only monitoring pages (alerts + event log)."""

from __future__ import annotations

from typing import Any, TypedDict

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    require_ui,
)
from ._common import ACTIVE_ALERTS_LIMIT, UI_BODY_FILTER_RULES, FilterRefused, check_filters


class _EventFilters(TypedDict):
    """The event-log filter values echoed back into the form, keyed as ``pages.events`` names them.

    A TypedDict rather than a plain dict so mypy still matches each key to its named parameter
    through the ``**`` -- the same reason ``routes.core._MsgFilters`` is one.
    """

    connection: str
    kind: str


def register(app: FastAPI, deps: UiDeps) -> None:
    """L1a: read-only monitoring pages (alerts + event log). Reuses the metadata-only JSON
    handlers (no PHI, no step-up) — ADR 0065, BACKLOG #75 phase 1."""
    core = deps.core

    @app.get("/ui/alerts", response_class=HTMLResponse)
    async def ui_alerts(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui(Permission.MONITORING_READ, Permission.MONITORING_DIAGNOSE)
        ),
    ) -> HTMLResponse:
        # Active instances need monitoring:diagnose, rules need monitoring:read — the page
        # requires BOTH (fail-closed), then calls the handlers directly (their own gates are
        # skipped, so require_ui re-asserts the permissions the same way the other /ui routes do).
        # Pass every param explicitly: calling the handler directly (not via Depends) leaves
        # its Query(...) defaults unresolved, so limit must be a real int here.
        instances = await core.list_active_alerts(
            engine=engine, identity=identity, limit=ACTIVE_ALERTS_LIMIT
        )
        config = await core.alerts_rules(request, _user=identity)
        return HTMLResponse(pages.alerts(instances, config))

    @app.get("/ui/events", response_class=HTMLResponse)
    async def ui_events(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
        # Body-validated rather than annotated, as on ui_messages: `connection` is a free-text input
        # on this page's own filter form, so a refusal has to come back as the form carrying what the
        # operator typed. `kind` rides the same request from a select, and splitting the two shapes
        # across one form is what BACKLOG #1740 avoided here.
        connection: str | None = Query(None, max_length=256),
        kind: str | None = Query(None, max_length=64),
    ) -> HTMLResponse:
        # L6b (#75 parity): expose the JSON handler's event-kind filter (a single kind from
        # the fixed dropdown → a one-element kinds list; blank/unknown = no filter).
        echo = _EventFilters(connection=connection or "", kind=kind or "")
        try:
            check_filters(UI_BODY_FILTER_RULES["/ui/events"], echo)
        except FilterRefused as exc:
            # No rows: the filter was never applied, and a table under a refusal banner would read
            # as the result of the filter the operator typed.
            return HTMLResponse(pages.events([], error=exc.message, **echo), status_code=400)
        kinds = [kind] if kind else None
        rows = await core.list_connection_events(
            engine=engine,
            identity=identity,
            connection=connection,
            kind=kinds,
            since=None,
            limit=100,
            request=request,
        )
        return HTMLResponse(pages.events(rows, **echo))

    async def _flow_data(request: Request, engine: Any, identity: Identity) -> tuple[Any, Any]:
        """Fetch the two read-only monitoring:read sources for the Flow & trends page (BACKLOG #76):
        the status-colored graph (from the Registry edges) + the metrics-history ring. Their own
        ``Depends`` gates are skipped on a direct call, so ``require_ui`` re-asserted the permission."""
        graph = await core.graph_edges(engine=engine, identity=identity)
        history = await core.metrics_history(request, _user=identity)
        return graph, history

    @app.get("/ui/monitoring", response_class=HTMLResponse)
    async def ui_monitoring(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
    ) -> HTMLResponse:
        # #76: the status-colored by-name data-flow graph + the historical queue-trend chart, both
        # inline SVG (CSP script-src 'self'). Read-only, metadata only — no message body.
        graph, history = await _flow_data(request, engine, identity)
        return HTMLResponse(pages.flow_and_trends(graph, history))

    @app.get("/ui/monitoring/live", response_class=HTMLResponse)
    async def ui_monitoring_live(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        # activity=False (ASVS 14.3.1): the Flow page's auto-refresh is timer-driven, not user activity.
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ, activity=False)),
    ) -> HTMLResponse:
        # The poll target app.js swaps into the page's [data-mf-fragment] container (server-rendered,
        # already-escaped) so the graph's live status colours + the trend refresh without a WebSocket.
        graph, history = await _flow_data(request, engine, identity)
        return HTMLResponse(pages.flow_and_trends_fragment(graph, history))
