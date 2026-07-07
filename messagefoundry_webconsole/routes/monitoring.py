# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L1a: read-only monitoring pages (alerts + event log)."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    require_ui,
)


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
        instances = await core.list_active_alerts(engine=engine, identity=identity, limit=200)
        config = await core.alerts_rules(request, _user=identity)
        return HTMLResponse(pages.alerts(instances, config))

    @app.get("/ui/events", response_class=HTMLResponse)
    async def ui_events(
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
        connection: str | None = Query(None, max_length=256),
        kind: str | None = Query(None, max_length=64),
    ) -> HTMLResponse:
        # L6b (#75 parity): expose the JSON handler's event-kind filter (a single kind from
        # the fixed dropdown → a one-element kinds list; blank/unknown = no filter).
        kinds = [kind] if kind else None
        rows = await core.list_connection_events(
            engine=engine,
            identity=identity,
            connection=connection,
            kind=kinds,
            since=None,
            limit=100,
        )
        return HTMLResponse(pages.events(rows, connection=connection or "", kind=kind or ""))
