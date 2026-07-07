# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L1b: read-only engine status page (engine/store metrics, security posture, cluster + DR state)."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    require_ui,
)


def register(app: FastAPI, deps: UiDeps) -> None:
    """L1b: read-only engine status page (engine/store metrics, effective security posture,
    cluster + DR state). Reuses the monitoring:read JSON handlers — no PHI, no step-up."""
    core = deps.core

    @app.get("/ui/status", response_class=HTMLResponse)
    async def ui_status(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
    ) -> HTMLResponse:
        sys_status = await core.system_status(request, engine=engine, _user=identity)
        posture = await core.security_posture(request, engine=engine, identity=identity)
        cluster = await core.cluster_status(engine=engine, _user=identity)
        nodes = await core.cluster_nodes(engine=engine, _user=identity)
        dr = await core.dr_status(engine=engine, _user=identity)
        svc = await core.service_status(request, _user=identity)
        return HTMLResponse(pages.status(sys_status, posture, cluster, nodes, dr, svc))
