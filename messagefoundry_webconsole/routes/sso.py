# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L5c (ADR 0068 §9): the browser Kerberos SSO challenge route — RFC 4559, Kerberos-only single-leg."""

from __future__ import annotations

import base64
import binascii
import logging

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.security import get_auth

from .. import pages
from .._auth import (
    set_session_cookie,
)

_log = logging.getLogger(__name__)


def register(app: FastAPI, deps: UiDeps) -> None:
    """L5c (ADR 0068 §9): the browser Kerberos SSO challenge route — RFC 4559,
    Kerberos-only SINGLE-LEG, off by default ([auth].kerberos_enabled, experimental)."""

    @app.get("/ui/sso")
    async def ui_sso(request: Request) -> Response:
        auth = get_auth(request)
        if auth is None or not auth.kerberos_available:
            # Disabled/degraded: redirect WITHOUT auditing (review carve-out, ADR 0068 §9).
            # There is no rate limiter in front of this branch, so auditing a token-bearing
            # attempt here would be an unbounded unauthenticated DB-write amplifier — the
            # exact anti-flood invariant the JSON rate-limit path preserves. The attempt is
            # a no-op (SSO is off); its visibility is the operator-facing serve-time state.
            return RedirectResponse("/ui/login?e=sso_unavailable", status_code=303)
        header = request.headers.get("Authorization", "")
        if not header.startswith("Negotiate "):
            # The RFC 4559 challenge leg — deliberately NOT rate-limited: every
            # unauthenticated SSO navigation produces one 401 before the browser attaches
            # its token; throttling it would self-lock normal traffic (ADR 0068 §9). The
            # HTML body keeps a browser without SSO configured from dead-ending.
            return HTMLResponse(
                pages.sso_challenge(),
                status_code=401,
                headers={"WWW-Authenticate": "Negotiate"},
            )
        # Token-bearing leg. The rate limiter runs FIRST (review fix, ADR 0068 §9): it
        # bounds EVERY downstream audit write to the limiter's rate, so an attacker looping
        # token requests can't amplify into unbounded audit_log growth. The rate-limit
        # reject itself is a _log.warning (NOT an audit) — parity with the JSON
        # _rate_limited path's anti-flood posture — so exhaustion writes zero DB rows.
        client = request.client.host if request.client else None
        if not auth.allow_login_attempt(client):
            _log.warning("SSO rate limit exceeded for %s", client or "<unknown>")
            return RedirectResponse("/ui/login?e=rate_limited", status_code=303)
        # Cross-site hygiene — an audited SSO reject (AUTH-K-AUDIT), now behind the limiter
        # so the audit is bounded: a non-navigation fetch is drive-by ambient-auth probing.
        # A cross-site TOP-LEVEL navigation is allowed (intranet links keep working; the
        # residual harm of a forced navigation is self-login only — server-minted token, no
        # fixation, ADR 0068 §9 threat model).
        mode = request.headers.get("Sec-Fetch-Mode")
        if mode is not None and mode != "navigate":
            await auth.audit_kerberos_reject("non_navigation_fetch")
            return RedirectResponse("/ui/login?e=sso_failed", status_code=303)
        try:
            token_bytes = base64.b64decode(header[len("Negotiate ") :], validate=True)
        except (binascii.Error, ValueError):
            await auth.audit_kerberos_reject("malformed_token")
            return RedirectResponse("/ui/login?e=sso_failed", status_code=303)
        # seed_reauth=False (ADR 0068 §9): the SSO proof is AMBIENT — the session must not
        # be born with a free step-up window; the first sensitive action forces the
        # directory-password step-up at /ui/reauth. ONE session per navigation into this
        # route (the resync side effect fires here, never per page).
        outcome = await auth.authenticate_kerberos(token_bytes, client=client, seed_reauth=False)
        if not outcome.ok or outcome.token is None:
            # authenticate_kerberos audited the reject. NEVER a second 401 — no challenge
            # loops (Kerberos-only single-leg is a hard line; an NTLM NegTokenInit from an
            # IP-hosted/SPN-less URL, an expired ticket, or an unknown principal all land
            # here). The single-leg helper deliberately discards the acceptor's out_token —
            # no mutual-auth response header (SECURITY.md's "no mutual authentication"; ADR
            # 0068 §9 records this as the current posture).
            return RedirectResponse("/ui/login?e=sso_failed", status_code=303)
        resp = RedirectResponse("/ui", status_code=303)
        set_session_cookie(resp, outcome.token, secure=deps.cookie_secure(request))
        return resp
