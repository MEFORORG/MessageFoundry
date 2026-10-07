# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""L1c: read-only audit trail + self-service security events."""

from __future__ import annotations

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.validation import (
    AUDIT_EXPORT_DEFAULT_LIMIT,
    AUDIT_EXPORT_MAX_LIMIT,
    PAGE_BIND_MAX,
    ActionFilter,
    ActorFilter,
    EpochSeconds,
)
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
        offset: int = Query(0, ge=0, le=PAGE_BIND_MAX),
        as_of: EpochSeconds | None = Query(None),
    ) -> HTMLResponse:
        data = await admin.list_audit(
            service=service, _=identity, limit=limit, offset=offset, as_of=as_of
        )
        return HTMLResponse(
            pages.audit_log(
                data,
                export_limit=AUDIT_EXPORT_DEFAULT_LIMIT
                if identity.has(Permission.AUDIT_EXPORT)
                else None,
            )
        )

    # The audit CSV from the console session (BACKLOG #2446). GET /audit/export reads only a bearer
    # header, and an account that signs in only through OIDC gets a cookie session and never a
    # bearer, so without this route such an auditor had no export at all. It calls the engine's own
    # handler, so the CSV, its lock-row exclusion, its audit.export row and its X-Audit-Withheld
    # header are that route's. The filters are declared with the same types GET /audit/export uses,
    # because an in-process call skips the handler's own validation. Every argument is passed
    # explicitly, for the reason _audit_ui_list gives about Query sentinels.
    @app.get("/ui/audit/export")
    async def ui_audit_export(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui(Permission.AUDIT_EXPORT)),
        limit: int = Query(AUDIT_EXPORT_DEFAULT_LIMIT, ge=1, le=AUDIT_EXPORT_MAX_LIMIT),
        actor: ActorFilter | None = Query(None),
        action: ActionFilter | None = Query(None),
        since: EpochSeconds | None = Query(None),
        until: EpochSeconds | None = Query(None),
    ) -> StreamingResponse:
        response: StreamingResponse = await admin.export_audit(
            request=request,
            service=service,
            identity=identity,
            format="csv",
            limit=limit,
            actor=actor,
            action=action,
            since=since,
            until=until,
        )
        return response

    @app.get("/ui/security-events", response_class=HTMLResponse)
    async def ui_security_events(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui()),
        limit: int = Query(_SECURITY_EVENTS_PAGE, ge=1, le=1000),
        offset: int = Query(0, ge=0, le=PAGE_BIND_MAX),
        as_of: EpochSeconds | None = Query(None),
    ) -> HTMLResponse:
        data = await admin.my_security_events(
            service=service, identity=identity, limit=limit, offset=offset, as_of=as_of
        )
        return HTMLResponse(pages.security_events(data))
