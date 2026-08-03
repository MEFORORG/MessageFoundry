# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""W4-5 (ADR 0142): the browser federated-login legs — OIDC authorization-code + PKCE, default-OFF.

Three routes, all unauthenticated, modelled closely on ``routes/sso.py``:

* ``GET /ui/oidc/start`` renders the ASVS 3.7.3 "you are leaving this site" interstitial and stages
  **nothing** — when the IdP is inside ``[security].organization_domains`` it delegates straight to
  the POST leg instead.
* ``POST /ui/oidc/start`` mints a server-side flow, drops an opaque flow id in a short-lived
  ``__Host-`` cookie, and 303s the browser to the IdP.
* ``GET /ui/oidc/callback`` re-binds cookie + ``state``, redeems the code, and lands the session.

**Registration is self-gating.** ``register`` returns before declaring either route unless
``[auth].oidc_enabled`` is set, so with federation off the two paths are not in the route table at all
and ``tests/golden/ui_routes.txt`` is unchanged — that unchanged golden IS the AC-1 proof.

Two deliberate departures a reviewer will want to check rather than "fix":

* **No same-origin assertion on the CALLBACK leg**, and that carve-out is specific to it.
  ``assert_same_origin`` rejects any request whose ``Sec-Fetch-Site`` is ``cross-site``, and the IdP's
  redirect back here is *legitimately* a top-level cross-site navigation. Adding it there would 403
  every real federated login while every hermetic test still passed (test clients send no
  ``Sec-Fetch`` headers). ``routes/sso.py`` does not call it either.
  ⛔ **The START legs are the opposite case and DO assert it** (ASVS 3.5.1). They are reached from our
  own login page or our own interstitial form — never legitimately cross-site. Without the assertion
  the 3.7.3 GET/POST split merely MOVES the drive-by sign-in hole from the GET to the POST: a
  cross-site ``<form method=post>`` is still ``Sec-Fetch-Mode: navigate``, so the navigate check does
  not stop it. The first version of that split shipped without the assertion and its commit message
  claimed otherwise; this is the correction. A bookmarked or typed navigation is unaffected —
  ``Sec-Fetch-Site: none`` is not cross-site, and a request carrying neither header raises nothing.
* **The callback returns 200 + a meta refresh, never a 303.** See :func:`pages.oidc_landing`.

Ordering rule inherited from ``sso.py``: **every audit-writing branch sits behind the rate limiter.**
Both legs are unauthenticated, so an attacker looping them would otherwise be an unbounded
audit_log-write amplifier. The availability and rate-limit rejects therefore write no audit row.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.security import get_auth
from messagefoundry.auth.oidc import FlowCacheFullError, FlowError

from .. import pages
from .._auth import (
    assert_same_origin,
    clear_oidc_flow_cookie,
    oidc_flow_cookie_name,
    set_oidc_flow_cookie,
    set_session_cookie,
)
from .._external import is_allowlisted, is_external, is_idn_disguised

_log = logging.getLogger(__name__)

#: Service-side reject reasons mapped to the login page's allow-listed short codes. Anything not in
#: here collapses to ``oidc_failed`` — an unrecognised slug must never become a reflected error code.
_REASON_TO_CODE = {
    "state_unknown": "flow_binding_missing",
    "state_mismatch": "flow_binding_missing",
    "mfa_claim_missing": "sso_mfa_required",
}


def _fail(request: Request, code: str) -> Response:
    """A terminal callback failure: 303 to the login page AND clear the single-use flow cookie."""
    resp = RedirectResponse(f"/ui/login?e={code}", status_code=303)
    clear_oidc_flow_cookie(resp, request)
    return resp


def register(app: FastAPI, deps: UiDeps) -> None:
    """Register the federated-login legs — ONLY when ``[auth].oidc_enabled`` is set.

    The gate reads ``deps.oidc_enabled`` (static CONFIG), not ``oidc_available`` (the advisory,
    non-sticky runtime health flag): the route table is fixed at app construction, and gating it on a
    value that changes when an IdP blips would make the surface appear and disappear across restarts.

    It also must NOT read ``app.state.auth``. Under ``messagefoundry serve`` the app is built by
    ``create_managed_app``, which attaches the AuthService inside the **lifespan** — long after
    ``mount_ui`` has fixed the route table — so an ``app.state.auth`` gate registers nothing in
    production while passing every test that constructs the app with ``auth=`` directly.
    """
    if not deps.oidc_enabled:
        return

    def _interstitial_needed() -> bool:
        """Does the configured IdP sit outside the organization (ASVS 3.7.3)?

        Decided ENTIRELY from configuration — never from request input. The destination shown to the
        operator, and the decision to show it at all, both come from ``deps``; a version of this that
        took the URL from the request would make the interstitial an open redirect, which is strictly
        worse than not having one.
        """
        if not deps.external_link_interstitial:
            return False
        host = deps.oidc_authorization_host
        if not host:
            # Unknown destination is not a reason to skip the warning.
            return True
        url = f"https://{host}/"
        if is_allowlisted(url, deps.external_link_allowlist):
            return False
        return is_external(url, deps.organization_domains)

    @app.get("/ui/oidc/start")
    async def ui_oidc_interstitial(request: Request) -> Response:
        """ASVS 3.7.3: interpose "you are leaving this site", with a cancel, before the IdP hop.

        **No flow is staged here.** The old GET minted a PKCE flow and redirected in one step; the
        flow now starts only when the operator confirms. Two things fall out of that: the bounded
        flow cache cannot be drained by anyone who can cause a GET (it REJECTS when full, so that was
        a login-DoS lever), and the confirm step is a POST behind the console's same-origin check —
        which also closes the standing hole where any external page could start a federated sign-in
        just by linking here.

        When the IdP is INSIDE ``organization_domains`` this page is skipped and the POST leg runs
        directly, because ASVS asks about destinations outside the application's CONTROL and an
        operator's own AD FS is not one.
        """
        auth = get_auth(request)
        if auth is None or not auth.oidc_enabled:
            return RedirectResponse("/ui/login?e=oidc_unavailable", status_code=303)
        if not _interstitial_needed():
            return await ui_oidc_start(request)
        host = deps.oidc_authorization_host or "(not configured)"
        return HTMLResponse(
            pages.leaving_site(
                destination_host=host,
                continue_action="/ui/oidc/start",
                idn_disguised=is_idn_disguised(f"https://{host}/"),
                cancel_href="/ui/login",
                purpose="Continuing will take you to your organization's sign-in provider.",
            ),
            status_code=200,
        )

    @app.post("/ui/oidc/start")
    async def ui_oidc_start(request: Request) -> Response:
        """Confirmed: mint the flow and hand the browser to the IdP.

        ⚠️ **The rate-limit branch below must stay INSIDE this decorated handler.**
        ``tests/test_security_doc_rate_limits.py`` reads the console's throttle shapes by walking the
        AST of *decorated* route functions and looking for an ``allow_login_attempt`` branch. Hoisting
        this body into a plain helper — which the first draft of the 3.7.3 split did — leaves the
        limiter working and makes the gate blind to it, so the documented per-route breach shape
        silently stops being checked. A control the checker cannot see is the failure mode this
        codebase keeps rediscovering; the duplication of one ``await`` in the GET leg is cheaper.
        """
        # ⛔ ASVS 3.5.1 — FIRST STATEMENT, and it must stay first. This is a document-initiated form
        # POST from our own interstitial, so unlike the callback leg it is NEVER legitimately
        # cross-site and the module docstring's "no same-origin assertion on either leg" carve-out
        # does NOT extend here.
        #
        # Without it the 3.7.3 split MOVES the drive-by sign-in hole from GET to POST rather than
        # closing it: a cross-site <form method=post> is still `Sec-Fetch-Mode: navigate`, so the
        # navigate check below waves it through and a foreign page can still mint a flow and bounce
        # the operator to the IdP. The first version of this change shipped without it and its commit
        # message claimed the opposite — corrected here.
        #
        # Ordering note: this precedes the rate limiter deliberately, and does not violate the
        # module's "every audit-writing branch sits behind the limiter" rule — it raises 403 and
        # writes NO audit row, so it cannot be used as an audit-log amplifier.
        assert_same_origin(request)
        auth = get_auth(request)
        if auth is None or not auth.oidc_enabled:
            # Disabled: redirect WITHOUT auditing — the sso.py anti-flood carve-out. Note this reads
            # oidc_enabled, not oidc_available: AC-8 requires recovery without an engine restart, so
            # the start leg ALWAYS attempts and a degraded IdP is discovered per-request.
            return RedirectResponse("/ui/login?e=oidc_unavailable", status_code=303)
        client = request.client.host if request.client else None
        if not auth.allow_login_attempt(client):
            # A _log.warning, never an audit — parity with sso.py, so exhaustion writes zero DB rows.
            _log.warning("federated sign-in rate limit exceeded for %s", client or "<unknown>")
            return RedirectResponse("/ui/login?e=rate_limited", status_code=303)
        mode = request.headers.get("Sec-Fetch-Mode")
        if mode is not None and mode != "navigate":
            # A non-navigation fetch of a login leg is drive-by probing. Audited (behind the limiter).
            await auth.audit_oidc_reject("non_navigation_fetch")
            return RedirectResponse("/ui/login?e=oidc_failed", status_code=303)
        public_origin = getattr(request.app.state, "public_origin", None)
        if not public_origin:
            # The redirect_uri is derived from public_origin, never from the Host header — a
            # client-forwardable Host would let an attacker steer where the IdP sends the code.
            _log.warning("federated sign-in unavailable: [api].public_origin is not set")
            return RedirectResponse("/ui/login?e=oidc_unavailable", status_code=303)
        try:
            flow_id, authorization_url = await auth.begin_oidc_login(
                client=client, public_origin=public_origin
            )
        except FlowCacheFullError:
            # The bounded flow cache REJECTS rather than evicts (evict-oldest would make a start-leg
            # flood a login DoS). That is a flood signal, so it is logged, not audited per request.
            _log.warning("federated flow cache is full; refusing new sign-in for %s", client or "?")
            return RedirectResponse("/ui/login?e=rate_limited", status_code=303)
        except FlowError:
            await auth.audit_oidc_reject("start_failed")
            return RedirectResponse("/ui/login?e=oidc_failed", status_code=303)
        resp = RedirectResponse(authorization_url, status_code=303)
        set_oidc_flow_cookie(resp, flow_id, request=request, max_age=auth.oidc_flow_ttl_seconds)
        return resp

    @app.get("/ui/oidc/callback")
    async def ui_oidc_callback(
        request: Request,
        code: str | None = Query(None, max_length=4096),
        state: str | None = Query(None, max_length=512),
        error: str | None = Query(None, max_length=64),
    ) -> Response:
        # `error_description` is deliberately NOT accepted: it is free-form IdP/attacker text, and the
        # bounded lengths above let FastAPI reject an oversized query string before any handler runs.
        auth = get_auth(request)
        if auth is None or not auth.oidc_enabled:
            return RedirectResponse("/ui/login?e=oidc_unavailable", status_code=303)
        client = request.client.host if request.client else None
        if not auth.allow_login_attempt(client):
            # The limiter runs on BOTH legs (ADR 0142): the callback is equally unauthenticated.
            _log.warning("federated callback rate limit exceeded for %s", client or "<unknown>")
            return RedirectResponse("/ui/login?e=rate_limited", status_code=303)
        mode = request.headers.get("Sec-Fetch-Mode")
        if mode is not None and mode != "navigate":
            await auth.audit_oidc_reject("non_navigation_fetch")
            return _fail(request, "oidc_failed")
        # NOTE: no assert_same_origin here. Sec-Fetch-Site on this leg is legitimately "cross-site".

        flow_id = request.cookies.get(oidc_flow_cookie_name(request))
        if not flow_id:
            # AC-7: without the browser-binding cookie the request is refused even when state and
            # code are otherwise valid — server-side `state` alone would let whoever presents a valid
            # (state, code) pair have the session minted into THEIR browser.
            await auth.audit_oidc_reject("flow_binding_missing")
            return _fail(request, "flow_binding_missing")
        if error is not None:
            # The IdP reported a failure. Audit a fixed slug; never the IdP's own string.
            await auth.audit_oidc_reject("idp_error")
            return _fail(request, "oidc_failed")
        if not code or not state:
            await auth.audit_oidc_reject("malformed_callback")
            return _fail(request, "oidc_failed")

        outcome = await auth.complete_oidc_login(
            flow_id=flow_id,
            state=state,
            code=code,
            client=client,
            public_origin=getattr(request.app.state, "public_origin", "") or "",
        )
        if not outcome.ok or outcome.token is None:
            # complete_oidc_login already audited the closed-set reason; map it to an allow-listed
            # short code, defaulting to the generic one so an unrecognised slug is never reflected.
            return _fail(request, _REASON_TO_CODE.get(outcome.reason or "", "oidc_failed"))
        resp = HTMLResponse(pages.oidc_landing(), status_code=200)
        set_session_cookie(resp, outcome.token, request=request)
        clear_oidc_flow_cookie(resp, request)
        return resp
