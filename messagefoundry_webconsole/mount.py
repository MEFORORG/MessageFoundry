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

from messagefoundry.api._ui_seam import UiDeps

from . import STATIC_DIR, _auth, assert_engine_seam, pages
from ._security import UiFetchMetadataMiddleware, UiSecurityHeadersMiddleware
from ._static import AllowlistedStaticFiles
from .routes import (
    account,
    admin,
    audit,
    config,
    connection_writes,
    core,
    monitoring,
    monitoring_writes,
    oidc,
    search,
    sso,
    status,
    uploaded_logs,
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
    uploaded_logs,
    monitoring,
    status,
    monitoring_writes,
    connection_writes,
    config,
    sso,
    # Self-gating: registers nothing unless [auth].oidc_enabled, so the golden route table
    # is unchanged for the default-off build (ADR 0142 AC-1). Tail placement is safe --
    # both paths are literal, with no {param} sibling anywhere in the table to shadow.
    oidc,
)


def mount_ui(app: FastAPI, deps: UiDeps) -> None:
    """Mount the entire /ui web console onto ``app``, wiring the moved routes to the injected
    ``deps`` bundle.

    Route registration is append-by-pattern and the security middleware is explicitly guarded, so a
    re-mount of the SAME app does not stack a second, nonce-conflicting copy of it. The static mount
    is NOT guarded — ``create_app`` builds a fresh ``FastAPI`` per call, so it is never re-mounted in
    practice; a re-mount would simply shadow with an identical entry."""
    assert_engine_seam(deps.engine_seam)
    # Always-on seams the JSON engine reads when serve_ui is on (Option B Phase 0): the /ui CSP
    # (co-versioned with app.js/app.css), the browser-cookie WS authorizer (CSWSH-guarded), and the
    # server-rendered connections fragment pushed over /ws/stats. With the console absent these stay
    # unset, so the security-headers middleware and /ws/stats take their JSON-only fallbacks.
    app.state.ui_csp = _auth.UI_CSP
    app.state.ui_ws_authorize = _auth.authorize_ui_ws
    app.state.ui_connections_render = pages.connections_fragment

    # ASVS 13.4.7: the console's asset tier serves ONLY allow-listed extensions. A bare StaticFiles
    # serves any regular file under the directory, and this directory IS the working tree under the
    # editable dev/CI install — so a stray .map/backup/.env is otherwise an unauthenticated 200. Any
    # future static mount must use AllowlistedStaticFiles too; the allowlist governs the mount, not
    # the process. See :mod:`._static`.
    app.mount("/ui/static", AllowlistedStaticFiles(directory=str(STATIC_DIR)), name="ui-static")

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

    # BACKLOG #1122 (ASVS 3.5.3): the cross-site refusal lifted from a route dependency to middleware,
    # because /ui/static is a Mount rather than an APIRoute -- a dependency never runs for it, so the
    # asset tier was the one /ui surface the per-route check could not reach. Same re-mount guard as
    # above, and the same append-by-pattern contract.
    if not any(getattr(m, "cls", None) is UiFetchMetadataMiddleware for m in app.user_middleware):
        app.add_middleware(UiFetchMetadataMiddleware)
