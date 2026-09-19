# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""L1c: read-only audit trail + self-service security events."""

from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.service import AuthService

from .. import pages
from .._auth import (
    require_ui,
)
from .._service import _service

#: How many rows each of these two pages asks for. NEITHER PAGES: the store's ``list_audit`` and
#: ``list_security_events`` take a limit and no offset, so this number IS the page, and there is no
#: second one to reach (BACKLOG #1743). Named once and handed to the page builder as well as to the
#: query, so the sentence the operator reads states the bound that actually ran -- a page that
#: re-declared it would go quietly wrong the day one of the two moved.
_WINDOW = 200


def register(app: FastAPI, deps: UiDeps) -> None:
    """L1c: read-only audit trail + self-service security events."""
    admin = deps.admin

    @app.get("/ui/audit", response_class=HTMLResponse)
    async def ui_audit(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui(Permission.AUDIT_READ)),
    ) -> HTMLResponse:
        data = await admin.list_audit(service=service, _=identity, limit=_WINDOW)
        return HTMLResponse(pages.audit_log(data, limit=_WINDOW))

    @app.get("/ui/security-events", response_class=HTMLResponse)
    async def ui_security_events(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui()),
    ) -> HTMLResponse:
        data = await admin.my_security_events(service=service, identity=identity, limit=_WINDOW)
        return HTMLResponse(pages.security_events(data, limit=_WINDOW))
