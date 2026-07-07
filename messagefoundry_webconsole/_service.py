# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The console's own :class:`AuthService` provider dependency.

A trivial re-implementation of ``api.auth_routes._service`` (get + enabled-check reading
``app.state``) so the package never imports ``auth_routes`` — which would form a
package → auth_routes → package cycle. Identical semantics: absent/disabled auth → 503.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, status

from messagefoundry.api.security import get_auth
from messagefoundry.auth.service import AuthService


def _service(request: Request) -> AuthService:
    auth = get_auth(request)
    if auth is None or not auth.enabled:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "authentication is not enabled")
    return auth
