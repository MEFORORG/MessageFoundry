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

**Secure-context engagement (loopback + effective-https).** All of the above is NEW behavior. It
engages in an effective-https context (scheme https/wss OR the operator's ``exposure_protected``
declaration — :func:`._auth.effective_https`, read-only) **OR a loopback secure-context**
(``http://127.0.0.1`` — a W3C *potentially-trustworthy* origin, signalled by ``app.state.loopback``;
ADR 0143), and only while the org opt-out (:func:`._auth.browser_hardening_enabled`) is unset — the
combined gate is :func:`._auth.security_headers_context`. On loopback the http-safe headers (nonce-CSP /
COOP / CORP / Reporting) engage, but the session cookie's Secure / ``__Host-`` prefix still requires
real https (:func:`._auth.effective_https`) so login is not broken over cleartext loopback (Chrome /
Safari reject a Secure / ``__Host-`` cookie over http); HSTS likewise stays off on loopback (the engine
emits it only over real https / ``exposure_protected``). Where the middleware is a strict no-op — the
org opt-out, or a cleartext NON-loopback context with no ``exposure_protected`` — it binds no nonce and
mutates no header, so the engine's existing static ``app.state.ui_csp`` response is emitted
byte-for-byte. This is why the engine's ``app.state.ui_csp`` seam is left set (option (b) in the lane
brief): the middleware only OVERRIDES it in a secure context and defers to it otherwise — no per-request
engine-side switch exists, so the console must own the conditional here.

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
``Cross-Origin-Resource-Policy`` / ``Reporting-Endpoints`` / nonce sources / ``SameSite`` simply
DEGRADES to the prior same-origin posture — the ``SameSite=Strict`` session cookie,
``frame-ancestors 'none'``, and the ``Sec-Fetch`` / ``Origin`` checks in :mod:`._auth` — and never
hard-fails a request. There is deliberately NO ``Cross-Origin-Embedder-Policy: require-corp``: COEP
gates EVERY subresource on an explicit CORP/CORS opt-in and would break the same-origin ``/ui/static``
assets and the ``data:`` images the /ui CSP already allows, for no isolation gain on a surface that
embeds no cross-origin content.

**Which relied-on features are actively DETECTED, and which degrade silently (ASVS 3.7.5).** The
contract above is only testable if it says, per feature, what the console does when the feature is
absent. Three sets are enumerated below, each entry in exactly one bucket — detected-and-warned, or
degrades-silently-with-a-named compensating control:

1. every **browser-security response header** that reaches a ``/ui`` response — including the ones
   emitted by the ENGINE's own security-headers middleware (``api/app.py``) rather than by this one;
2. every **client-side browser security feature the console feature-detects** in its own scripts
   (``static/app.js`` and the nonce'd shell scripts in :mod:`._html`);
3. the **session cookie's security attributes** (``__Host-`` prefix / ``Secure`` / ``HttpOnly`` /
   ``SameSite``), which no page script can observe at all.

This list is the in-code source of truth the runbook's operator-facing copy mirrors, and a CI guard
(``test_ui_csp_canary.py``) derives all three sets from the CODE — the header writes, the
``window.<Feature>`` reads, and the ``set_cookie`` attributes — and fails if any member is missing
HERE, so a newly-shipped header, detect or cookie attribute cannot slip in unbucketed. Anything
OUTSIDE those three sets is outside the claim.

The parallel check that the RUNBOOK still mirrors this list skips wherever
``docs/security/OFF-LOOPBACK-DEPLOYMENT.md`` is absent, which is every public checkout — that path is
deny-listed by design. So the runbook can drift from this list without anything going red outside a
tree that carries it. Said plainly because this paragraph previously claimed both halves ran: they
were one test each, the runbook accessor was reached FIRST, and its skip took the code-side check
down with it, so the enumeration shipping in this wheel was checked by nothing at all (BACKLOG
#1124). The two are now separate tests — the code-side one passes publicly, the runbook one skips.

* **Secure transport context** — DETECTED and WARNED. The nonce'd page-shell script reads
  ``window.isSecureContext``; false raises a visible ``role="alert"`` banner
  (:mod:`._html`). Correctly inert on the loopback posture, where ``http://127.0.0.1`` IS a secure
  context; it exists for the proxy-TLS mismatch the engine cannot see server-side.
* **CSP enforcement** (``Content-Security-Policy`` honoured at all) — DETECTED and WARNED. The shell
  loads an UN-NONCED external canary (``/ui/static/csp-probe.js``); an enforcing browser refuses it
  under ``script-src 'nonce-…' 'strict-dynamic'`` so its global stays undefined, while a browser that
  does not enforce CSP runs it and the nonce'd detect raises a second ``role="alert"`` banner. This is
  an ACTIVE detect that fires on the default deployment: the flag can only be set when the policy is
  not being applied. Its expected violation reports are filtered out of the log by SAME-ORIGIN
  blocked-URL path, per report entry — never per batch — so a real violation delivered in the same
  Reporting-API POST still warns (:mod:`.routes.core`).
* **CSP nonce-source support / script execution** — DETECTED and WARNED, by the INVERSE detect. A
  browser that ENFORCES CSP but does not understand ``'nonce-…'``/``'strict-dynamic'`` has no valid
  script source and blocks EVERY script — app.js, both detects above, and the ASVS 14.3.1 session
  watchdog — so no script-raised banner could render (the same is true with JavaScript disabled). The
  shell therefore SERVER-renders a ``role="alert"`` banner (id ``mf-scripts-blocked-banner``) that a
  nonce'd mark script removes from view (via an ``<html>`` class app.css keys on) on a healthy
  client: fail-visible, no flash, and it stands exactly when scripts do not run. **Named residual:**
  the ASVS 14.3.1 session watchdog is one of the blocked scripts, so a timed-out tab keeps its
  rendered PHI page until the operator navigates. Compensating: everything the blocked scripts carry
  is client-side BELT — the server still refuses every subsequent request (idle + absolute expiry,
  RBAC and auditing are untouched), the expiry redirect still carries ``Clear-Site-Data``, and every
  /ui HTML response is ``Cache-Control: no-store``.
* **``window.PublicKeyCredential`` (WebAuthn passkeys)** — DETECTED and WARNED. ``static/app.js``
  reads it before wiring either passkey ceremony; when it is absent the button is DISABLED and the
  status line says so in place ("This browser does not support passkeys." on enrolment, "…— use your
  password/code." on the step-up leg), so the operator is told rather than left clicking a control
  that silently does nothing. Compensating: a passkey is an ALTERNATIVE factor, never the only one —
  the TOTP and password legs are untouched, so a browser without WebAuthn can still enroll MFA,
  complete a step-up and sign in. (The RP-configuration failures — the ``[webauthn]`` extra absent, or
  no resolvable RP id — are a SERVER-side fail-closed notice, not a browser-support case.)
* **Session-cookie security attributes — ``__Host-`` prefix / ``Secure`` / ``HttpOnly``** — DEGRADE
  SILENTLY, necessarily: ``HttpOnly`` is precisely what stops a page script from reading the cookie,
  so none of the three is observable client-side (``SameSite`` has its own row below for the same
  reason). Compensating: they are only ever SET where a browser will honour them — the ``__Host-``
  prefix and ``Secure`` key on :func:`._auth.effective_https`, so cleartext loopback keeps the plain
  ``mf_session`` rather than a cookie the browser would silently reject and thereby break login —
  session termination is SERVER-side (revoke + ``Clear-Site-Data``, never cookie deletion alone), and
  every state-changing /ui POST carries the server-side ``Sec-Fetch-Site``/``Origin`` check, so a
  browser that ignores the attributes still cannot be driven cross-site with the cookie.
* **``Cross-Origin-Opener-Policy``** — DEGRADES SILENTLY, by necessity. No browser API exposes COOP
  enforcement to the page. ``window.crossOriginIsolated`` is NOT a COOP detect — it additionally
  requires COEP, which is deliberately not set (above), so reading it would render a false "degraded"
  banner in every browser. The compensating posture is that COOP is pure defense-in-depth here: /ui
  opens no cross-origin windows and embeds no cross-origin content, so its absence costs process
  isolation only, and ``frame-ancestors 'none'`` still blocks framing.
* **``Cross-Origin-Resource-Policy``** — DEGRADES SILENTLY, same rationale: no client-observable API,
  and /ui serves no resource intended for cross-origin embedding.
* **``Reporting-Endpoints``** — DEGRADES SILENTLY. It only routes violation reports, so a client that
  ignores it costs telemetry, never a control; the legacy ``report-uri`` directive is emitted
  alongside it, so most such clients still deliver reports.
* **``SameSite=Strict`` on the session cookie** — DEGRADES SILENTLY, with a compensating control that
  makes the degradation non-fatal rather than merely unwarned: a page script cannot read an HttpOnly
  cookie's SameSite attribute, so the absence is undetectable client-side, but every state-changing
  ``/ui`` POST — including the unauthenticated ``/ui/login`` and the gate-less ``/ui/logout`` — carries
  an explicit server-side ``Sec-Fetch-Site``/``Origin`` check (:func:`._auth.assert_same_origin`,
  ASVS 3.5.1). A browser that ignores SameSite therefore still cannot mount CSRF against /ui.
* **``Clear-Site-Data``** (ASVS 14.3.1; emitted by :mod:`._auth` on every login redirect and by
  :mod:`.routes.core` on logout and the post-termination login render) — DEGRADES SILENTLY; Safari
  has no support. Compensating: it is only the Back/bfcache belt. The session is revoked SERVER-side,
  the cookie is explicitly deleted, every /ui HTML response carries ``Cache-Control: no-store``, and
  the 14.3.1 watchdog blanks the rendered document synchronously before navigating away.
* **``Cache-Control: no-store``** on /ui HTML and PHI JSON (engine middleware) — DEGRADES SILENTLY: a
  page script cannot observe another response's cache treatment. Compensating: ``Clear-Site-Data`` on
  session termination, the watchdog's document blanking, and the server refusing every request the
  resurrected page would make.
* **``X-Content-Type-Options: nosniff``** (engine middleware) — DEGRADES SILENTLY. Compensating: the
  /ui static mount serves ONLY ``.css``/``.js`` from a fixed directory with correct MIME types (ASVS
  13.4.7, :mod:`._static`), and no user-supplied file is ever served from the /ui origin.
* **``X-Frame-Options: DENY``** (engine middleware) — DEGRADES SILENTLY, and is pure legacy
  redundancy: the CSP's ``frame-ancestors 'none'`` is the modern control and every browser that
  honours the nonce CSP honours it.
* **``Referrer-Policy: no-referrer``** (engine middleware) — DEGRADES SILENTLY. Compensating: the same
  policy is ALSO carried in-document by ``<meta name="referrer" content="no-referrer">`` in every page
  shell (:func:`._html.page`), /ui URLs carry opaque ids only (never PHI), and ``/ui`` links off-site
  nowhere.
* **``Strict-Transport-Security``** (engine middleware, effective-https only) — DEGRADES SILENTLY.
  Compensating: TLS is terminated by the documented reverse proxy, which is configured to redirect
  cleartext, and the ``window.isSecureContext`` banner above makes a cleartext hop visible to the
  operator.
"""

from __future__ import annotations

import secrets

from starlette.datastructures import MutableHeaders
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ._auth import _CROSS_ORIGIN_FETCH, browser_hardening_enabled, security_headers_context
from ._html import reset_csp_nonce, set_csp_nonce

#: The route (registered in :mod:`.routes.core`) the browser POSTs CSP violation reports to, and the
#: ``Reporting-Endpoints`` group name that references it.
CSP_REPORT_PATH = "/ui/csp-report"
CSP_REPORT_GROUP = "mf-csp"

#: Cross-origin isolation headers set on every effective-https /ui HTML response.
COOP_VALUE = "same-origin"
CORP_VALUE = "same-origin"

#: Every browser-security response header :class:`UiSecurityHeadersMiddleware` writes. Declared here
#: so the ASVS 3.7.5 degrade-contract guard can read the emitted set from CODE instead of a literal in
#: the test; the guard also re-derives it from the ``send_wrapper`` source, so this tuple cannot drift
#: away from what is actually emitted (see ``test_ui_csp_canary.py``).
#:
#: Deliberately a DECLARATION with no runtime consumer — the middleware writes the headers directly so
#: the emitting code stays readable in one place. Its consumer is the contract guard, and its job is
#: to be the thing that guard compares the source against; do not "clean it up" into the send_wrapper.
SECURITY_HEADER_NAMES: tuple[str, ...] = (
    "Content-Security-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Reporting-Endpoints",
)

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


def _is_ui_fetch_scope(path: str) -> bool:
    """Every /ui path INCLUDING the static mount -- deliberately WIDER than :func:`_is_ui_html_path`.

    The asset tier is exactly what a per-route validator cannot reach: ``/ui/static`` is mounted as a
    Starlette ``Mount``, not registered as an ``APIRoute``, so a route dependency never runs for it.
    THAT GAP IS THE REASON THIS CHECK IS MIDDLEWARE RATHER THAN A DEPENDENCY, so excluding the mount
    here would remove its only purpose. The narrower predicate above is correct for CSP headers, which
    only apply to HTML; do not collapse the two.
    """
    return path == "/ui" or path.startswith("/ui/")


#: A cross-site request that is a SAFE TOP-LEVEL NAVIGATION is allowed -- an intranet link into the
#: console is one, and so is the OIDC callback, where the IdP's redirect back is cross-site BY
#: CONSTRUCTION. METHOD is part of safe: a cross-site navigation carrying a POST is a CSRF form
#: submission, and no supported flow makes one.
_SAFE_NAVIGATION_METHODS = frozenset({"GET", "HEAD"})
#: ``object``/``embed`` pull a subresource into someone else's page while still reporting
#: ``Sec-Fetch-Mode: navigate``. That is framing, not navigation, so it does not get the carve-out.
_FRAMING_DESTINATIONS = frozenset({"object", "embed"})


class UiFetchMetadataMiddleware:
    """Refuse a /ui request the BROWSER ITSELF labels cross-site (BACKLOG #1371, ASVS 3.5.3).

    It shares its membership set with ``_auth``'s per-route cross-site check, lifted to middleware so
    it ALSO covers the ``/ui/static`` Mount that route dependencies cannot see -- but it is NOT that
    check at a wider scope. The per-route helper guards hand-picked routes where nothing legitimate
    EVER arrives cross-site; applying that bare set to every /ui request would add top-level
    NAVIGATIONS, which those callers never see.

    **A CROSS-SITE TOP-LEVEL NAVIGATION IS LEGITIMATE AND MUST PASS.** An intranet link into the
    console is one; so is the OIDC callback. Without reading ``Sec-Fetch-Mode`` as well, every real
    SSO login would 403 while every hermetic test still passed.

    **ABSENT IS ALLOWED, AND THAT IS THE LOAD-BEARING HALF.** ``Sec-Fetch-Site`` is browser-populated:
    an old browser, an out-of-band reporting agent, and every non-browser client omit it entirely.
    Failing closed on absence would refuse the shipped Windows tray's own ``GET /ui`` probe, which
    builds its client with no headers at all. So this rejects only a header that is PRESENT and says
    cross-site or same-site.

    **403, NEVER 404.** The tray classifies 404 as DISABLED and every other status as ENABLED, so a
    404 here would make it report a healthy console as switched off. A later "return 404 rather than
    disclose the route" hardening pass would look like an improvement and silently break the tray.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not _is_ui_fetch_scope(scope.get("path", "")):
            await self.app(scope, receive, send)
            return
        # Read from the raw scope rather than building a Request: this runs for every /ui asset, and
        # header names on the wire are lower-cased bytes by ASGI contract.
        site = mode = dest = None
        for key, value in scope.get("headers") or ():
            if key == b"sec-fetch-site":
                site = value.decode("latin-1")
            elif key == b"sec-fetch-mode":
                mode = value.decode("latin-1")
            elif key == b"sec-fetch-dest":
                dest = value.decode("latin-1")
        if site is None or site not in _CROSS_ORIGIN_FETCH:
            await self.app(scope, receive, send)
            return
        if (
            mode == "navigate"
            and str(scope.get("method", "")).upper() in _SAFE_NAVIGATION_METHODS
            and dest not in _FRAMING_DESTINATIONS
        ):
            await self.app(scope, receive, send)
            return
        await PlainTextResponse("cross-site request rejected", status_code=403)(
            scope, receive, send
        )


class UiSecurityHeadersMiddleware:
    """Pure-ASGI /ui browser-security hardening (see the module docstring)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not _is_ui_html_path(scope.get("path", "")):
            await self.app(scope, receive, send)
            return
        app_state = getattr(scope.get("app"), "state", None)
        if not browser_hardening_enabled() or not security_headers_context(
            app_state, scope.get("scheme", "http")
        ):
            # Opt-out, or a cleartext NON-loopback context with no exposure_protected: strict no-op ->
            # the engine's static /ui CSP response stands byte-for-byte (the org opt-out reverts every
            # scheme; a loopback secure-context now ENGAGES the http-safe headers via
            # security_headers_context, ADR 0143 — see the module docstring).
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
