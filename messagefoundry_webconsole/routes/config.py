# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L3c: config-deploy — reload the engine's already-configured graph from its own startup dir."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import HTMLResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import (
    PendingApprovalResponse,
    ReloadRequest,
)
from messagefoundry.auth import Identity, Permission

from .. import pages
from .._auth import (
    assert_same_origin,
    register_ui_action,
    require_ui,
    require_ui_step_up,
)

# L3c: config reload is step-up-gated, so register it in the write-action allow-list (body-less
# POST, no path params — the /ui/reauth flow may auto-retry it after step-up).
register_ui_action(r"^/ui/config/reload$", Permission.CONFIG_DEPLOY)


def register(app: FastAPI, deps: UiDeps) -> None:
    """L3c: config-deploy — reload the engine's ALREADY-CONFIGURED graph from its own startup dir.
    STRICTLY within #26: no module editor, no filesystem picker, no dry-run diff. The reload is
    step-up-gated (CONFIG_DEPLOY) + dual-control; it passes a fixed ReloadRequest() so config_dir
    is ALWAYS the server startup dir (never user input) and dry_run is False."""
    core = deps.core

    @app.get("/ui/config", response_class=HTMLResponse)
    async def ui_config(
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
    ) -> HTMLResponse:
        prov = await core.config_provenance(engine=engine, _user=identity)
        return HTMLResponse(pages.config_page(prov))

    @app.post("/ui/config/reload")
    async def ui_config_reload(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.CONFIG_DEPLOY)),
        gate: Any = Depends(deps.get_gate),
    ) -> HTMLResponse:
        assert_same_origin(request)
        # Bright line: a FIXED request — config_dir=None (the server's startup dir) + dry_run=False.
        # The /ui never lets the browser choose a path (the loader executes Python).
        result = await core.reload_config(
            ReloadRequest(config_dir=None, dry_run=False),
            Response(),
            engine=engine,
            user=identity,
            gate=gate,
        )
        if isinstance(result, PendingApprovalResponse):
            return HTMLResponse(pages.reload_pending(result))
        return HTMLResponse(pages.reload_result(result))
