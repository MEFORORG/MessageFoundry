# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``mount_ui(app, deps)`` — the single entrypoint ``create_app`` calls to graft the web console onto
the engine's FastAPI app, same-origin (Option B, ADR 0065).

It (1) re-asserts the engine seam (belt-and-suspenders — the engine already asserted before building
``deps``), (2) installs the three always-on app.state hooks the JSON engine reads when serve_ui is on
(the /ui CSP, the browser-cookie WS authorizer, the server-rendered connections fragment), (3) mounts
the package's own static assets, and (4) registers every /ui route in a fixed, test-pinned order.

The route modules are imported at THIS module's import time (eager), so every module-level
``register_ui_action`` has fired before serving — the write-action registry is a single authoritative
module-global (``_auth._UI_WRITE_ACTIONS``). NOTE (review fix): there is deliberately NO mount-time
"every step-up route has a registry entry" self-check — that is a FALSE invariant (body-carrying
step-up POSTs map their stale-window redirect via ``reauth_next`` to a DIFFERENT registered unlock
page, so they intentionally have no own entry). Registry/route completeness is backstopped by the
moved tests + a golden route-table test instead.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from messagefoundry.api._ui_seam import UiDeps

from . import STATIC_DIR, assert_engine_seam
from . import _auth, pages
from ._security import UiSecurityHeadersMiddleware
from .routes import (
    account,
    admin,
    audit,
    config,
    connection_writes,
    core,
    monitoring,
    monitoring_writes,
    search,
    sso,
    status,
)

# Fixed registration order, pinned by the golden route-table test. This reproduces the pre-extraction
# order: add_auth_routes registered its admin/account/audit /ui routes first, then create_app's
# _UI_REGISTRARS (search FIRST so the literal /ui/messages/search beats /ui/messages/{id}; the literal
# bulk/purge-confirm paths are registered before {name}/purge/{scope} WITHIN connection_writes).
_REGISTRARS = (
    admin,
    account,
    audit,
    search,
    core,
    monitoring,
    status,
    monitoring_writes,
    connection_writes,
    config,
    sso,
)


def mount_ui(app: FastAPI, deps: UiDeps) -> None:
    """Mount the entire /ui web console onto ``app``, wiring the moved routes to the injected
    ``deps`` bundle. Idempotent registrations (append-by-pattern) make a re-mount across create_app()
    calls a no-op."""
    assert_engine_seam(deps.engine_seam)
    # Always-on seams the JSON engine reads when serve_ui is on (Option B Phase 0): the /ui CSP
    # (co-versioned with app.js/app.css), the browser-cookie WS authorizer (CSWSH-guarded), and the
    # server-rendered connections fragment pushed over /ws/stats. With the console absent these stay
    # unset, so the security-headers middleware and /ws/stats take their JSON-only fallbacks.
    app.state.ui_csp = _auth.UI_CSP
    app.state.ui_ws_authorize = _auth.authorize_ui_ws
    app.state.ui_connections_render = pages.connections_fragment

    app.mount("/ui/static", StaticFiles(directory=str(STATIC_DIR)), name="ui-static")

    for module in _REGISTRARS:
        module.register(app, deps)

    # Install the /ui browser-security hardening LAST so Starlette makes it the OUTERMOST middleware
    # (added after the engine's security-headers middleware): its response send-wrapper runs last and
    # thus owns the effective-https /ui CSP/COOP/reporting headers, while deferring to the engine's
    # static app.state.ui_csp untouched over cleartext loopback (byte-identity). Guarded so a re-mount
    # of the SAME app (the idempotency contract above) does not stack a second, nonce-conflicting copy.
    # See :mod:`._security`.
    if not any(getattr(m, "cls", None) is UiSecurityHeadersMiddleware for m in app.user_middleware):
        app.add_middleware(UiSecurityHeadersMiddleware)
