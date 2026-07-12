# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-response /ui browser-security hardening (ADR 0065 §hardening / BACKLOG #192, ASVS 5.0 L3).

A self-contained, /ui-scoped ASGI middleware the web console installs on the mounted app (in
:func:`.mount.mount_ui`, before uvicorn serves). It OWNS the browser-security response headers for the
/ui HTML surface WITHOUT touching the engine (``api/app.py`` is out of this lane's scope):

* a **per-response nonce CSP** — ``script-src 'nonce-<random>' 'strict-dynamic'`` (3.4.7/3.4.8), minted
  fresh per response and stamped into the ``<script>`` tag via the :mod:`._html` nonce ContextVar so the
  tag and header always match;
* **Cross-Origin-Opener-Policy: same-origin** (process isolation) and
  **Cross-Origin-Resource-Policy: same-origin**;
* **CSP reporting** — ``report-to``/``report-uri`` pointing at ``POST /ui/csp-report`` plus the modern
  ``Reporting-Endpoints`` header (3.7.5).

**Loopback byte-identity (hard rule).** All of the above is NEW behavior and engages ONLY in an
effective-https context (scheme https/wss OR the operator's ``exposure_protected`` declaration —
:func:`._auth.effective_https`, read-only) and only while the org opt-out
(:func:`._auth.browser_hardening_enabled`) is unset. Over cleartext loopback the middleware is a strict
no-op: it binds no nonce and mutates no header, so the engine's existing static ``app.state.ui_csp``
response is emitted byte-for-byte as before. This is why the engine's ``app.state.ui_csp`` seam is left
set (option (b) in the lane brief): the middleware only OVERRIDES it off-loopback and defers to it on
loopback — no per-request engine-side switch exists, so the console must own the conditional here.

**Proxy-TLS keying.** This middleware reads ``scope['scheme']`` at the OUTERMOST layer, which precedes
any inner proxy-headers scheme rewrite. Exactly like the engine's ``_cookie_secure``, a proxy that
terminates TLS and forwards cleartext to the engine must therefore declare
``app.state.exposure_protected`` to engage the nonce CSP (a forwarded ``X-Forwarded-Proto=https`` alone
is NOT seen here). When ``exposure_protected`` is unset in such a deployment the engine's inner static
self-CSP (``app.state.ui_csp``) remains the floor on every /ui response — the surface is never left
unprotected, only un-upgraded — so the cookie-and-CSP posture stays consistent with the engine's own
exposure model rather than diverging from it.

**Middleware ordering.** ``mount_ui`` adds this AFTER the engine's ``@app.middleware("http")``
security-headers middleware, so Starlette makes it the OUTERMOST layer (``add_middleware`` inserts at
index 0): on the response path its ``send`` wrapper runs LAST and thus overrides the engine's static CSP
with the nonce CSP for effective-https /ui responses. It is a PURE ASGI middleware (not
``BaseHTTPMiddleware``) specifically so the nonce ContextVar it binds before calling downstream
propagates into the route that renders the page — ``BaseHTTPMiddleware`` runs the endpoint in a detached
task that a var set inside its own ``dispatch`` would not reach, but a var set by an OUTER pure-ASGI
middleware before the base layer runs is copied into that task and IS visible.

**Browser-support contract (defined fallback).** These are all defense-in-depth headers a conformant
modern browser honors; an older client that ignores ``Cross-Origin-Opener-Policy`` /
``Reporting-Endpoints`` / nonce sources simply DEGRADES to the prior same-origin posture — the
``SameSite=Strict`` session cookie, ``frame-ancestors 'none'``, and the ``Sec-Fetch`` / ``Origin`` checks
in :mod:`._auth` — and never hard-fails a request. There is deliberately NO
``Cross-Origin-Embedder-Policy: require-corp``: COEP gates EVERY subresource on an explicit CORP/CORS
opt-in and would break the same-origin ``/ui/static`` assets and the ``data:`` images the /ui CSP already
allows, for no isolation gain on a surface that embeds no cross-origin content.
"""

from __future__ import annotations

import secrets

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ._auth import browser_hardening_enabled, effective_https
from ._html import reset_csp_nonce, set_csp_nonce

#: The route (registered in :mod:`.routes.core`) the browser POSTs CSP violation reports to, and the
#: ``Reporting-Endpoints`` group name that references it.
CSP_REPORT_PATH = "/ui/csp-report"
CSP_REPORT_GROUP = "mf-csp"

#: Cross-origin isolation headers set on every effective-https /ui HTML response.
COOP_VALUE = "same-origin"
CORP_VALUE = "same-origin"

_NONCE_BYTES = 16  # secrets.token_urlsafe(16) -> 22 url-safe chars, ample CSP nonce entropy


def build_ui_csp(nonce: str) -> str:
    """The /ui CSP for an effective-https response: the static self-only base with ``script-src``
    upgraded to a per-response nonce + ``strict-dynamic`` (3.4.7/3.4.8) and CSP reporting wired to
    :data:`CSP_REPORT_PATH`. ``strict-dynamic`` intentionally drops the host allowlist for scripts —
    only the nonce'd first-party ``app.js`` (and anything it loads) runs; there is no inline script."""
    return (
        f"default-src 'self'; script-src 'nonce-{nonce}' 'strict-dynamic'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'; object-src 'none'; "
        f"report-uri {CSP_REPORT_PATH}; report-to {CSP_REPORT_GROUP}"
    )


def _is_ui_html_path(path: str) -> bool:
    """The engine's exact /ui-HTML scope: a /ui path that is not a /ui/static asset."""
    return (path == "/ui" or path.startswith("/ui/")) and not path.startswith("/ui/static")


class UiSecurityHeadersMiddleware:
    """Pure-ASGI /ui browser-security hardening (see the module docstring)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not _is_ui_html_path(scope.get("path", "")):
            await self.app(scope, receive, send)
            return
        app_state = getattr(scope.get("app"), "state", None)
        if not browser_hardening_enabled() or not effective_https(
            app_state, scope.get("scheme", "http")
        ):
            # Cleartext loopback / opt-out: strict no-op -> the engine's static /ui CSP response stands
            # byte-for-byte (loopback byte-identity; the org opt-out reverts every scheme).
            await self.app(scope, receive, send)
            return
        nonce = secrets.token_urlsafe(_NONCE_BYTES)
        csp = build_ui_csp(nonce)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = csp
                headers["Cross-Origin-Opener-Policy"] = COOP_VALUE
                headers["Cross-Origin-Resource-Policy"] = CORP_VALUE
                headers["Reporting-Endpoints"] = f'{CSP_REPORT_GROUP}="{CSP_REPORT_PATH}"'
            await send(message)

        token = set_csp_nonce(nonce)
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            reset_csp_nonce(token)
