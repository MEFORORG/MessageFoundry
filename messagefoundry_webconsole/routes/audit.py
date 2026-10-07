# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""L1c: read-only audit trail + self-service security events."""

from __future__ import annotations

from fastapi import Depends, FastAPI, Query
from fastapi.responses import HTMLResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.service import AuthService

from .. import pages
from .._auth import (
    require_ui,
)
from .._service import _service

#: How many rows each page shows by default. Both pages are paged by ``offset`` against a total
#: (BACKLOG #2438), so this is a page size and not a cap on what the operator can reach.
#:
#: TWO CONSTANTS, NOT ONE, though they hold the same number today: these are unrelated listings --
#: the whole estate's audit trail, and one user's own account history -- and a single name would
#: make resizing one silently resize the other.
_AUDIT_PAGE = 200
_SECURITY_EVENTS_PAGE = 200


def register(app: FastAPI, deps: UiDeps) -> None:
    """L1c: read-only audit trail + self-service security events."""
    admin = deps.admin

    @app.get("/ui/audit", response_class=HTMLResponse)
    async def ui_audit(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui(Permission.AUDIT_READ)),
        limit: int = Query(_AUDIT_PAGE, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> HTMLResponse:
        data = await admin.list_audit(service=service, _=identity, limit=limit, offset=offset)
        return HTMLResponse(pages.audit_log(data))

    @app.get("/ui/security-events", response_class=HTMLResponse)
    async def ui_security_events(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui()),
        limit: int = Query(_SECURITY_EVENTS_PAGE, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> HTMLResponse:
        data = await admin.my_security_events(
            service=service, identity=identity, limit=limit, offset=offset
        )
        return HTMLResponse(pages.security_events(data))
