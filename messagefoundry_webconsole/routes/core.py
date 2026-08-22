# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Core /ui pages: login/logout, dashboard, messages + parse-tree, dead-letters, replay, and the step-up re-auth flow (GET/POST /ui/reauth + the WebAuthn leg) — the sole consumer of the write-action registry (ADR 0065)."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import ValidationError

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import (
    DeadLetterReplayRequest,
    EditResendRequest,
    PendingApprovalResponse,
)
from messagefoundry.api.security import get_auth
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.service import AuthService, MfaStatus
from messagefoundry.auth.tokens import hash_token
from messagefoundry.parsing import HL7PeekError, parse_tree

from .. import pages
from .._auth import (
    CLEAR_SITE_DATA_HEADER,
    CLEAR_SITE_DATA_VALUE,
    WEBAUTHN_EXTRA_MISSING_NOTICE,
    WEBAUTHN_RP_CHANGED_NOTICE,
    WEBAUTHN_RP_MISSING_NOTICE,
    allow_reauth_attempt,
    assert_not_cross_site,
    assert_same_origin,
    clear_session_cookie,
    is_unlock_action,
    login_redirect_response,
    lookup_ui_action,
    register_ui_action,
    require_ui,
    require_ui_step_up,
    session_token,
    set_session_cookie,
    webauthn_rp,
)
from .._html import CSP_PROBE_SRC
from .._service import _service

_log = logging.getLogger(__name__)

#: Login-page outcome codes that mean "a session just ended" and therefore carry Clear-Site-Data.
#: The header itself (and every server-driven expiry redirect that carries it) lives in
#: :mod:`.._auth` — see :data:`.._auth.CLEAR_SITE_DATA_VALUE`. ``pwchanged`` belongs here for the same
#: reason as ``loggedout``: a password change revokes EVERY session for the user. It is belt — the
#: 303 that sends the browser here already carries the header via ``clear_session_cookie`` — but a
#: browser can reach this landing by another route (Back, a bookmark) with the cookie already gone,
#: which is exactly the case ``_has_stale_session_cookie`` below cannot detect.
_CLEAR_SITE_DATA_LOGIN_CODES = frozenset({"expired", "loggedout", "pwchanged"})

#: How many report bodies of one CSP violation BATCH the WARNING line summarises before it is
#: truncated to a count. The reports are attacker-influenceable, so the log line is bounded.
_CSP_REPORT_SUMMARY_MAX = 5

# Edit-and-resubmit (ADR 0090 §9, BACKLOG #153). The GET editor page is the step-up `unlock`
# continuation (a GET form the re-auth flow can 303-GET-redirect back to); the body-carrying POST
# `/edit-resend` is deliberately NOT a registered continuation — its `reauth_next` maps a stale-window
# step-up to this /edit page, so the operator re-submits inside a fresh window (mirrors /ui/users).
register_ui_action(
    r"^/ui/messages/[^/?#]+/edit$", Permission.MESSAGES_EDIT, auto_retry=False, unlock=True
)


def _csp_report_bodies(doc: object) -> list[dict[str, object]] | None:
    """Normalize either wired delivery shape to the LIST of report bodies it carries, or ``None`` when
    the payload is not an object at all: the legacy ``report-uri`` body
    (``{"csp-report": {"document-uri": ..., "violated-directive": ..., "blocked-uri": ...}}``, always
    exactly one) and the modern Reporting-API ``report-to`` batch (a top-level ARRAY whose entries
    carry a ``body`` dict keyed ``documentURL``/``effectiveDirective``/``blockedURL``,
    ``application/reports+json``). Never raises on hostile input — the report is
    attacker-influenceable DATA, never instructions.

    Returning every entry rather than the first is LOAD-BEARING (ASVS 3.7.5). The Reporting API
    batches per endpoint, and the enforcement canary provokes one report per page load on every
    conforming browser, so a genuine violation raised on the same page load arrives in the SAME POST,
    behind the canary. A first-entry-only view classified that batch by the canary and dropped the real
    violation to DEBUG — the exact detection hole the external-canary design exists to avoid.
    """
    if isinstance(doc, list):
        bodies: list[dict[str, object]] = []
        for entry in doc:
            if isinstance(entry, dict):
                body = entry.get("body", entry)
                if isinstance(body, dict):
                    bodies.append(body)
        return bodies
    if isinstance(doc, dict):
        inner = doc.get("csp-report", doc)
        return [inner] if isinstance(inner, dict) else []
    return None


def _csp_report_summary(report: dict[str, object]) -> str:
    """A bounded, PHI-free one-line summary of ONE CSP violation report body (either delivery shape).
    Returns ``"empty"`` when nothing usable is present."""
    # Accept both the hyphenated report-uri keys and the camelCase report-to keys, labelling the
    # summary by the stable report-uri name in either case.
    field_specs = (
        ("document-uri", "documentURL"),
        ("violated-directive", "effectiveDirective"),
        ("blocked-uri", "blockedURL"),
    )
    fields: list[str] = []
    for legacy_key, modern_key in field_specs:
        value = report.get(legacy_key)
        if value is None:
            value = report.get(modern_key)
        if value:
            fields.append(f"{legacy_key}={str(value)[:256]}")
    return "; ".join(fields) or "empty"


def _request_origin(request: Request) -> str | None:
    """This deployment's own ORIGIN (``scheme://host[:port]``, lowercased) for a same-origin
    comparison, or ``None`` when it cannot be established.

    Follows the precedence of ``_auth._origin_matches`` — ``[api].public_origin`` is authoritative
    when configured (the off-loopback case behind a proxy that may not preserve ``Host``), else the
    request's own ``Host`` header — but, unlike that function's Host-only fallback, it also carries the
    SCHEME. A violation report's blocked URL is absolute, so the scheme IS observable here, and
    ``http://<our-host>/ui/static/csp-probe.js`` on an https deployment is NOT our canary. Behind a
    TLS-terminating proxy that neither sets ``public_origin`` nor rewrites ``scope['scheme']`` the
    comparison simply fails and the canary's own reports WARN instead of being filtered — noisier,
    never quieter, which is the only safe direction for a filter on a security log.
    """
    public_origin: str | None = getattr(request.app.state, "public_origin", None)
    if public_origin:
        parts = urlsplit(public_origin)
        if not parts.scheme or not parts.netloc:
            return None
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}"
    host = request.headers.get("host")
    return f"{request.url.scheme.lower()}://{host.lower()}" if host else None


def _is_expected_csp_probe_report(report: dict[str, object], origin: str | None) -> bool:
    """Whether THIS report body is the one violation the 3.7.5 enforcement canary is designed to
    provoke — a conforming browser refusing OUR OWN un-nonced ``/ui/static/csp-probe.js``.

    The match is SAME-ORIGIN — scheme AND ``host[:port]`` — plus same-path, and nothing else. The path
    alone is not sufficient: it is attacker-selectable on an attacker-hosted payload, so a host-blind
    match would let ``https://evil.example/ui/static/csp-probe.js`` — an injected script load a real
    CSP blocked — be filed as the expected canary and dropped to DEBUG. ``origin`` is this
    deployment's own ``scheme://host[:port]`` (:func:`_request_origin`); a relative ``blocked-uri``
    (some browsers report a bare path) is same-origin by construction, and an absolute URL must match
    it case-insensitively. Unknown origin fails CLOSED — the report warns.

    Being an external script rather than an inline one is what makes any filtering safe at all: a
    blocked INLINE canary reports ``blocked-uri: "inline"`` with the same directive and document as a
    blocked injected inline script, so any filter wide enough to drop the canary would also drop the
    report a real XSS attempt produces. Directive naming is deliberately NOT part of the match
    (browsers report ``script-src-elem`` or ``script-src`` depending on version), and neither is the
    document URI (every /ui page emits the canary, so it discriminates nothing).
    """
    blocked = report.get("blocked-uri")
    if blocked is None:
        blocked = report.get("blockedURL")
    if not isinstance(blocked, str):
        return False
    parts = urlsplit(blocked)
    # Compare paths: browsers report the absolute URL, but tolerate a bare path too. Query/fragment are
    # stripped so a cache-buster can never smuggle a non-probe URL past the match.
    if parts.path != CSP_PROBE_SRC:
        return False
    if not parts.netloc:
        return True
    return origin is not None and f"{parts.scheme.lower()}://{parts.netloc.lower()}" == origin


async def _has_stale_session_cookie(request: Request, auth: AuthService | None) -> bool:
    """Whether this request presents a session cookie that no longer authenticates (ASVS 14.3.1).

    A first-time visitor carries no cookie and gets an ordinary login form; a browser arriving with a
    dead ``mf_session`` is landing AFTER a termination — idle/absolute expiry, revoke, admin disable —
    and its cached PHI pages must be dropped even when the redirect that sent it here was not ours
    (a bookmark, a Back navigation, or a client that never ran the watchdog). Validated with
    ``activity=False``: probing a dead session must not be treated as user activity.
    """
    token = session_token(request)
    if not token:
        return False
    if auth is None or not auth.enabled:
        return True  # a cookie with no auth configured can never authenticate
    return await auth.identity_for_token(token, activity=False) is None


def register(app: FastAPI, deps: UiDeps) -> None:
    """Register the phase-0 /ui routes (login, dashboard, messages, dead-letters, replay,
    reauth). Runs first in ``_UI_REGISTRARS``; a page lane adds its own
    ``_register_<area>(app)`` + one tuple entry below, so parallel lanes never edit this
    shared block (ADR 0065 §multi-session-build)."""
    core = deps.core

    @app.get("/ui/session-status")
    async def ui_session_status(
        request: Request,
        service: AuthService = Depends(_service),
        # activity=False (ASVS 14.3.1) is LOAD-BEARING: this probe is the client watchdog's heartbeat,
        # so refreshing the idle clock from it would make the watchdog keep the very session alive it
        # exists to notice the end of. No permission is required beyond a live session — every
        # authenticated page needs it, including a must-change-confined one.
        # allow_mfa_pending is MANDATORY, not a convenience: the confinement page at /ui/mfa carries
        # the same watchdog, so gating this probe would 303 it to /ui/mfa on every heartbeat and the
        # page would fight its own poll.
        identity: Identity = Depends(
            require_ui(allow_must_change=True, allow_mfa_pending=True, activity=False)
        ),
    ) -> JSONResponse:
        """The session watchdog's heartbeat (ASVS 14.3.1).

        Reaching this AT ALL is the liveness signal — ``require_ui`` 303s to the login page the moment
        the session is idle-expired, absolute-expired or revoked, and the client treats that redirect
        as termination. The body carries the ABSOLUTE deadline as **remaining seconds**, never a
        wall-clock the client would have to trust against its own (possibly wrong, possibly
        adversary-set) system time, and it is read from the session RECORD rather than computed from
        ``[auth].session_absolute_hours`` — a federated session's deadline may be capped lower by the
        IdP's ``id_token.exp``, so settings arithmetic would over-state it.

        ``expires_secs`` is null when the record cannot be resolved; the client then relies on the
        server verdict and its stale-contact bound alone rather than inventing a deadline.
        """
        remaining: int | None = None
        token = session_token(request)
        if token:
            # The SAME indexed point-lookup ``identity_for_token`` just did (``require_ui`` above),
            # not a per-user session listing: this probe runs every 30s in every open console tab, and
            # ``list_sessions`` is an unindexed scan on all three backends.
            record = await service.store.get_session(hash_token(token))
            if record is not None:
                remaining = max(0, int(record.expires_at - datetime.now(UTC).timestamp()))
        return JSONResponse({"expires_secs": remaining})

    @app.get("/ui/login", response_class=HTMLResponse)
    async def ui_login_form(
        request: Request, e: str | None = Query(None, max_length=32)
    ) -> HTMLResponse:
        auth = get_auth(request)
        # The AD password FORM follows the login pathway, not the directory bind: an operator who
        # turned the pathway off keeps the bind up for SSO/OIDC, and offering a form that will be
        # refused is just a worse error (BACKLOG #1137). getattr degrades against an older engine
        # carrying only the fused flag, the same precedent as oidc_available below.
        ad_enabled = auth is not None and bool(
            getattr(auth, "ad_password_login_enabled", auth.ad_enabled)
        )
        sso_enabled = auth is not None and auth.kerberos_available
        # getattr: an older engine (seam < 10) has no oidc_available property at all, and a bare
        # attribute read would AttributeError rather than degrade (the exposure_protected
        # precedent). oidc_available, not oidc_enabled -- the LINK should disappear while the IdP
        # is known-down, even though the start leg still attempts per-request (AC-8).
        oidc_enabled = bool(getattr(auth, "oidc_available", False))
        resp = HTMLResponse(
            pages.login(
                e, ad_enabled=ad_enabled, sso_enabled=sso_enabled, oidc_enabled=oidc_enabled
            )
        )
        # ASVS 14.3.1: this render IS the post-termination landing page when either the outcome code
        # says so (the watchdog's ?e=expired, the redirect target of POST /ui/logout, or the
        # server's own expiry redirect) OR the browser still presents a session cookie that no
        # longer authenticates — a stale cookie IS a terminated session, whatever URL it landed on.
        # Tell the browser to drop that session's cached representations so Back / bfcache cannot
        # resurrect a PHI page whose session no longer exists.
        if e in _CLEAR_SITE_DATA_LOGIN_CODES or await _has_stale_session_cookie(request, auth):
            resp.headers[CLEAR_SITE_DATA_HEADER] = CLEAR_SITE_DATA_VALUE
        return resp

    @app.post("/ui/login")
    async def ui_login(request: Request) -> Response:
        # ASVS 3.5.1 — FIRST statement, ahead of the per-address login budget below: a cross-site
        # credential POST is refused having spent no rate-limit token and run no password verify. The
        # unauthenticated leg is exactly where SameSite=Strict supplies nothing (there is no session
        # cookie yet), so this origin check is the only login-CSRF control available here.
        assert_same_origin(request)
        auth = get_auth(request)
        if auth is None or not auth.enabled:
            raise HTTPException(503, "authentication is not configured")
        client = request.client.host if request.client else None
        if not auth.allow_login_attempt(client):
            raise HTTPException(429, "too many login attempts", headers={"Retry-After": "30"})
        # Parse the urlencoded login form with stdlib — the engine has no python-multipart dep, so
        # Form()/request.form() would fail; a same-origin login POST is always urlencoded here.
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")))
        # L5b (ADR 0068 §8): browser AD-password login rides the SAME auth.login seam as the
        # JSON surface — allow-listed provider values only; absent stays LOCAL (regression-
        # pinned). ONE session is minted per form POST, so the AD role-resync/revocation side
        # effect fires once at login, never per navigation.
        provider_value = form.get("provider", "local")
        if provider_value not in ("local", "ad"):
            return RedirectResponse("/ui/login?e=bad", status_code=303)
        outcome = await auth.login(
            form.get("username", ""),
            form.get("password", ""),
            provider=AuthProvider.AD if provider_value == "ad" else AuthProvider.LOCAL,
            client=client,
        )
        if not outcome.ok or outcome.token is None:
            return RedirectResponse("/ui/login?e=bad", status_code=303)
        # A must-change account goes straight to the browser rotation page (L4b) — every other
        # /ui route would bounce it there anyway (require_ui). An MFA-pending session lands on the
        # second-factor page for the same reason (ASVS 6.3.3). Order matches the server-side gates:
        # must_change first, since a fresh account is BOTH and can only rotate.
        #
        # UX only — require_ui is what actually enforces, and it covers the other two cookie-minting
        # legs (Kerberos SSO, the OIDC callback) without either needing this branch.
        if outcome.must_change_password:
            target = "/ui/account/password"
        elif outcome.mfa_required:
            target = "/ui/mfa"
        else:
            target = "/ui"
        resp = RedirectResponse(target, status_code=303)
        set_session_cookie(resp, outcome.token, request=request)
        return resp

    @app.post("/ui/logout")
    async def ui_logout(request: Request) -> Response:
        # ASVS 3.5.1 — FIRST statement, before the session is revoked below. This route deliberately
        # carries NO Depends gate (so a must-change-confined session can still sign itself out — the
        # affordance ASVS 7.4.4 makes visible), which means the origin check is the only
        # request-provenance control it will ever have: without it a cross-site POST the browser
        # attaches the cookie to would forcibly terminate the operator's session.
        #
        # IT ALSO CHARGES NO WRITE BUDGET, AND THAT IS DELIBERATE (BACKLOG #287). Having no Depends
        # gate, it never reaches `require_ui`, where every other non-GET /ui route now spends
        # `allow_admin_write`. Do not "correct" that: a throttled logout is a signed-in operator who
        # cannot sign out, which is the 7.4.4 affordance failing exactly when someone is trying to
        # end a session they no longer trust. Signing out is also not the operation a write budget
        # exists to bound — it REMOVES authority rather than exercising it. Written down because an
        # unwritten right answer is indistinguishable from an oversight, and this one now sits
        # conspicuously alone.
        assert_same_origin(request)
        auth = get_auth(request)
        token = session_token(request)
        if auth is not None and token:
            await auth.logout(token)
        resp = RedirectResponse("/ui/login?e=loggedout", status_code=303)
        # ASVS 14.3.1: revoking server-side and deleting the cookie leaves the browser's CACHED
        # representations of the operator's PHI pages behind, which Back / bfcache can resurrect.
        # ``clear_session_cookie`` emits Clear-Site-Data itself — cookie deletion IS the termination,
        # so the two cannot be written apart (see its docstring for the scope rationale).
        clear_session_cookie(resp, request)
        return resp

    @app.get("/ui", response_class=HTMLResponse)
    async def ui_dashboard(
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
    ) -> HTMLResponse:
        rows = await core.list_connections(engine=engine, identity=identity)
        return HTMLResponse(pages.dashboard(rows))

    @app.get("/ui/connections", response_class=HTMLResponse)
    async def ui_connections(
        engine: Any = Depends(deps.get_engine),
        # activity=False (ASVS 14.3.1): the dashboard's 5s live-table refresh is timer-driven, not
        # user activity — it must not keep an abandoned tab's session alive.
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ, activity=False)),
    ) -> HTMLResponse:
        rows = await core.list_connections(engine=engine, identity=identity)
        return HTMLResponse(pages.connections_fragment(rows))

    @app.get("/ui/connection/{name}", response_class=HTMLResponse)
    async def ui_connection_details(
        name: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
    ) -> HTMLResponse:
        # Compose the detail view from existing monitoring handlers (no new PHI surface): find the row in
        # the (already channel-scoped) connection list, then its recent events. A singular /ui/connection/
        # path avoids colliding with the /ui/connections/{purge-confirm,...} action routes.
        rows = await core.list_connections(engine=engine, identity=identity)
        row = next((r for r in rows if r.name == name), None)
        if row is None:
            raise HTTPException(404, "connection not found")
        # Events are recorded + RBAC-scoped by the RAW connection name (channel_id for a source,
        # destination for an outbound), NOT the composite display name — pass the raw name so the events
        # actually match and a channel-scoped operator isn't spuriously denied (+ audited) on their own.
        events_key = (
            row.destination if (row.role == "destination" and row.destination) else row.channel_id
        )
        try:
            # Pass EVERY param explicitly: called directly (not over HTTP), any FastAPI Query(...) default
            # left unfilled arrives as a Query object (kind would reach the store un-iterable → 500).
            events = await core.list_connection_events(
                engine=engine,
                identity=identity,
                connection=events_key,
                kind=None,
                since=None,
                limit=50,
                request=request,
            )
        except HTTPException:
            events = []  # still show the connection's info + stats if events are RBAC-scoped out
        return HTMLResponse(pages.connection_details(row, events))

    @app.get("/ui/messages", response_class=HTMLResponse)
    async def ui_messages(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_READ, phi=True)),
        channel_id: str | None = Query(None, max_length=256),
        status_filter: str | None = Query(None, alias="status", max_length=64),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        received_from: str | None = Query(None, max_length=32),  # datetime-local (UTC)
        received_to: str | None = Query(None, max_length=32),
        defer: bool = Query(False),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> HTMLResponse:
        # Arriving pre-filled from a connection name (defer=1) with no explicit dates → default a 1-day
        # window (UTC). The operator adjusts and clicks Search (a plain submit, no defer) to run it.
        if defer and not received_from and not received_to:
            now = datetime.now(UTC)
            received_from = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
            received_to = now.strftime("%Y-%m-%dT%H:%M")

        def _epoch(value: str | None) -> float | None:
            if not value:
                return None
            try:
                return datetime.fromisoformat(value).replace(tzinfo=UTC).timestamp()
            except ValueError:
                return None  # a malformed datetime-local simply drops that bound

        if defer:
            # Form-only landing: pre-filled, NOT run until the operator submits (#4b).
            return HTMLResponse(
                pages.messages(
                    None,
                    deferred=True,
                    channel_id=channel_id or "",
                    status=status_filter or "",
                    message_type=message_type or "",
                    control_id=control_id or "",
                    received_from=received_from or "",
                    received_to=received_to or "",
                )
            )

        data = await core.list_messages(
            request,
            engine=engine,
            identity=identity,
            channel_id=channel_id,
            status=status_filter,
            message_type=message_type,
            control_id=control_id,
            received_from=_epoch(received_from),
            received_to=_epoch(received_to),
            limit=limit,
            offset=offset,
        )
        return HTMLResponse(
            pages.messages(
                data,
                channel_id=channel_id or "",
                status=status_filter or "",
                message_type=message_type or "",
                control_id=control_id or "",
                received_from=received_from or "",
                received_to=received_to or "",
            )
        )

    @app.get("/ui/messages/{message_id}", response_class=HTMLResponse)
    async def ui_message_detail(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_VIEW_RAW, phi=True)),
    ) -> HTMLResponse:
        detail = await core.get_message(message_id, request, engine=engine, identity=identity)
        return HTMLResponse(pages.message_detail(detail))

    @app.get("/ui/messages/{message_id}/parse-tree", response_class=HTMLResponse)
    async def ui_message_parse_tree(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_VIEW_RAW, phi=True)),
    ) -> HTMLResponse:
        # Reuse the single audited PHI path (get_message → record_view + record_audit), then render
        # the tree server-side via the pure parsing lib. Non-HL7 bodies (X12/DICOM/binary) have no
        # HL7 tree — surface that rather than 500. No new PHI egress beyond the audited raw fetch.
        detail = await core.get_message(message_id, request, engine=engine, identity=identity)
        try:
            nodes = parse_tree(detail.raw)
        except HL7PeekError as exc:
            return HTMLResponse(pages.parse_tree_unavailable(message_id, str(exc)))
        return HTMLResponse(pages.parse_tree_page(message_id, nodes))

    @app.get("/ui/messages/{message_id}/attachments/{attachment_id}")
    async def ui_download_attachment(
        message_id: str,
        attachment_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_VIEW_RAW, phi=True)),
    ) -> Response:
        # Reuse the engine's single audited download path (linkage + channel-scope 404 guard +
        # record_view + attachment_download audit), then hand its Response straight to the browser. A
        # top-level GET nav can't carry the bearer token, so the /ui gate re-asserts view_raw via the
        # session cookie; the engine handler does the same PHI audit as the JSON API route.
        result: Response = await core.download_attachment(
            message_id, attachment_id, engine=engine, identity=identity, request=request
        )
        return result

    @app.get("/ui/dead-letters", response_class=HTMLResponse)
    async def ui_dead_letters(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_READ, phi=True)),
        channel_id: str | None = Query(None, max_length=256),
        destination_name: str | None = Query(None, max_length=256),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> HTMLResponse:
        data = await core.list_dead_letters(
            request,
            engine=engine,
            identity=identity,
            channel_id=channel_id,
            destination_name=destination_name,
            limit=limit,
            offset=offset,
        )
        return HTMLResponse(pages.dead_letters(data))

    # Safe operator actions (M2): inbound connection start/stop/restart. These reuse the JSON
    # control handlers (require CONNECTIONS_CONTROL + the per-channel _control_guard), and add
    # assert_same_origin as CSRF defense-in-depth on top of the SameSite=Strict cookie (a
    # cross-site POST carries no cookie, so require_ui already 303s). No step-up gate applies to
    # start/stop/restart (unlike replay, which is require_step_up and lands with the browser MFA
    # flow in a later milestone). Each redirects back to the dashboard.
    async def _ui_control(
        request: Request,
        name: str,
        engine: Any,
        identity: Identity,
        action: Callable[..., Any],
    ) -> Response:
        assert_same_origin(request)
        # ADR 0150: the console mounts IN-PROCESS on the engine's own app, so this Request is the
        # BROWSER's — forwarding it attributes the row to the operator's host, not the engine.
        await action(name, engine=engine, identity=identity, request=request)
        return RedirectResponse("/ui", status_code=303)

    @app.post("/ui/connections/{name}/start")
    async def ui_start_connection(
        name: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.CONNECTIONS_CONTROL)),
    ) -> Response:
        return await _ui_control(request, name, engine, identity, core.start_connection)

    @app.post("/ui/connections/{name}/stop")
    async def ui_stop_connection(
        name: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.CONNECTIONS_CONTROL)),
    ) -> Response:
        return await _ui_control(request, name, engine, identity, core.stop_connection)

    @app.post("/ui/connections/{name}/restart")
    async def ui_restart_connection(
        name: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.CONNECTIONS_CONTROL)),
    ) -> Response:
        return await _ui_control(request, name, engine, identity, core.restart_connection)

    # Sensitive action (M2b): single-message replay. It is require_step_up in the JSON API, so the
    # /ui route uses require_ui_step_up — which, if the session hasn't recently stepped up, 303s the
    # browser to /ui/reauth?next=<this action> instead of returning a 403 header the browser can't
    # act on. After re-auth the browser auto-retries this POST (now inside the step-up window).
    @app.post("/ui/messages/{message_id}/replay")
    async def ui_replay_message(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_REPLAY)),
    ) -> Response:
        assert_same_origin(request)
        await core.replay_message(message_id, engine=engine, identity=identity, request=request)
        return RedirectResponse(f"/ui/messages/{message_id}", status_code=303)

    # Edit-and-resubmit (ADR 0090 §9, BACKLOG #153). GET renders the editor (a COPY of the raw); the
    # step-up gate opens it inside a fresh window (unlock continuation). The origin row is only READ
    # here (the audited get_message path); nothing is written until the operator POSTs /edit-resend.
    #
    # view_raw is required ALONGSIDE edit (BACKLOG #324) because the editor inherently DISPLAYS the
    # body: it renders `detail.raw` into the textarea and ships a second pristine copy in
    # `data-original`. `messages:edit` stays mintable on a custom role (ADR 0045 D1 is unchanged), so
    # without this a role meaning "may resubmit, must not read" would read raw PHI here — the read
    # permission its grant deliberately withheld. Such a role is still mintable and still resubmits
    # via the API; it simply cannot open this editor, which is correct: you cannot edit-and-resend
    # without seeing what you are editing. phi=True charges the per-actor PHI-read budget, matching
    # the sibling raw views above (message detail, parse-tree, attachment download).
    @app.get("/ui/messages/{message_id}/edit", response_class=HTMLResponse)
    async def ui_message_edit(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(Permission.MESSAGES_EDIT, Permission.MESSAGES_VIEW_RAW, phi=True)
        ),
    ) -> HTMLResponse:
        detail = await core.get_message(message_id, request, engine=engine, identity=identity)
        # A fresh per-open idempotency token: a double-submit of THIS rendered form is an idempotent
        # no-op; re-opening the editor mints a new token (a genuine second resubmit).
        return HTMLResponse(pages.message_edit(detail, uuid4().hex))

    # Same two-permission gate as the GET (BACKLOG #324), because this verb ALSO renders the body: the
    # `_reject` arm below re-reads the origin via the audited `core.get_message` and re-ships the
    # PRISTINE stored copy through `data_original`. Gating it on `messages:edit` alone would leave the
    # rejection path as an unauthorized read of exactly the body the GET now refuses. phi=True for the
    # same reason — otherwise the reject path is an UNTHROTTLED channel for re-reading stored bodies
    # while the equivalent GET is throttled.
    @app.post("/ui/messages/{message_id}/edit-resend")
    async def ui_message_edit_resend(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.MESSAGES_EDIT,
                Permission.MESSAGES_VIEW_RAW,
                phi=True,
                # Stale-window step-up on this body-carrying POST → re-open the /edit form (fresh
                # window), never the POST path (a re-POST would drop the edited body).
                reauth_next=lambda r: r.url.path.removesuffix("/edit-resend") + "/edit",
            )
        ),
    ) -> Response:
        assert_same_origin(request)
        # Parse the urlencoded resubmit form with stdlib — the engine has no python-multipart dep, so
        # Form()/request.form() would fail (mirrors the /ui/login + /ui/reauth POST parsing above).
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")))
        raw = str(form.get("raw", ""))
        idem = str(form.get("idempotency_key", "")).strip()
        mode = str(form.get("mode", "reroute"))
        to = str(form.get("to", "")).strip()

        async def _reject(msg: str) -> HTMLResponse:
            # Re-render the editor preserving the operator's edits (raw_value) AND their destination
            # choice (mode + to) — so a rejected direct send doesn't silently reset to re-route and drop
            # the typed outbound (review #153-4). The audited get_message re-read is the same PHI path
            # the GET used. NEVER echo the edited body in the error text.
            detail = await core.get_message(message_id, request, engine=engine, identity=identity)
            return HTMLResponse(
                pages.message_edit(
                    detail, idem or uuid4().hex, raw_value=raw, error=msg, mode=mode, to=to
                ),
                status_code=400,
            )

        if mode == "direct" and not to:
            return await _reject(
                "choose an outbound connection for a direct send, or re-route instead"
            )
        try:
            body = EditResendRequest(
                raw=raw,
                idempotency_key=idem,
                reroute=(mode != "direct"),
                to=(to if mode == "direct" else None),
            )
        except ValidationError:
            # PHI-safe: a bad edited body must never be echoed — a generic message only.
            return await _reject("invalid input")
        try:
            result = await core.edit_resend_message(
                message_id, body=body, engine=engine, identity=identity, request=request
            )
        except HTTPException as exc:
            # str(exc.detail) carries ids only (the endpoint never interpolates the body).
            return await _reject(str(exc.detail))
        # Land on the NEW correlated child (re-route) so the operator sees the resubmit flow; the direct
        # path lands back on the origin (which now carries the new outbound row). The ORIGINAL is intact.
        target = result.new_message_id if (result.reroute and result.new_message_id) else message_id
        return RedirectResponse(f"/ui/messages/{target}", status_code=303)

    async def _reauth_webauthn_state(
        request: Request,
        auth: AuthService,
        token: str | None,
        mfa: MfaStatus,
        satisfied: bool,
    ) -> tuple[str | None, str | None]:
        """(assertion-options JSON, fail-closed notice) for the reauth page's passkey leg.

        Options are freshly staged per render (the prior challenge is single-use — ADR 0068
        decision 1(e): the passkey button must survive a failed password/code attempt). The
        notice is the legible dead-end copy when ceremonies can't run (extra absent /
        rp unavailable) — never a redirect loop."""
        if satisfied or not mfa.webauthn_enrolled:
            return None, None
        if not auth.webauthn_available():
            return None, WEBAUTHN_EXTRA_MISSING_NOTICE
        rp = webauthn_rp(request)
        if rp is None:
            return None, WEBAUTHN_RP_MISSING_NOTICE
        options = await auth.begin_webauthn_assertion(token, rp_id=rp[0])
        if options is None:
            # Enrolled, but every credential was minted under a DIFFERENT rp_id (the
            # origin-migration case, ADR 0068 §7) — a legible dead-end naming the
            # admin-reset recovery, never a bare password form with a misleading
            # "complete the passkey prompt" error (PR-A review finding).
            return None, WEBAUTHN_RP_CHANGED_NOTICE
        return options, None

    @app.get("/ui/mfa", response_class=HTMLResponse)
    async def ui_mfa_form(request: Request) -> Response:
        """The ASVS 6.3.3 confinement page for an MFA-pending browser session.

        Carries NO ``require_ui`` dependency on purpose — the gate 303s every pending session here, so
        a gated version of this page would redirect to itself. Auth is done by hand instead, in the
        SAME order the gate uses, so the two cannot disagree.

        A separate route rather than a reuse of ``/ui/reauth``: that page 303s to /ui unless ``next``
        names a registered write action, and its POST always demands the password — which an operator
        proved seconds earlier at sign-in.
        """
        auth = get_auth(request)
        token = session_token(request)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or identity is None:
            return login_redirect_response()
        if identity.must_change_password:
            # must_change outranks MFA, mirroring require()/require_ui: a fresh account is both, and
            # only rotation is reachable until it happens.
            return RedirectResponse("/ui/account/password", status_code=303)
        if await auth.mfa_satisfied(token):
            return RedirectResponse("/ui", status_code=303)  # idempotent: nothing owed
        mfa = await auth.mfa_status(identity)
        if not (mfa.enabled or mfa.webauthn_enrolled):
            # Required but NOTHING enrolled: there is no factor to ask for. Reuse the existing
            # enroll-first bounce rather than rendering a form that cannot be answered — this is
            # what keeps a fresh account from bouncing between the gate and an empty page.
            return RedirectResponse("/ui/account?m=enroll_first", status_code=303)
        wa_options, wa_notice = await _reauth_webauthn_state(request, auth, token, mfa, False)
        return HTMLResponse(
            pages.mfa_gate(
                totp_enrolled=mfa.enabled,
                webauthn_options=wa_options,
                webauthn_notice=wa_notice,
            )
        )

    @app.post("/ui/mfa")
    async def ui_mfa_submit(request: Request) -> Response:
        assert_same_origin(request)
        auth = get_auth(request)
        token = session_token(request)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or not token or identity is None:
            return login_redirect_response()
        if identity.must_change_password:
            return RedirectResponse("/ui/account/password", status_code=303)
        client = request.client.host if request.client else None
        if not allow_reauth_attempt(auth, identity, client):
            # Same per-ACTOR ceremony budget the reauth/password flows draw on, so code-guessing
            # here cannot outrun it either.
            # Retry-After: 30 matches POST /ui/reauth, the sibling ceremony on the SAME per-actor
            # budget — a different hint for the same limiter would just misreport when it clears.
            raise HTTPException(429, "too many attempts", headers={"Retry-After": "30"})
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")))
        if await auth.verify_mfa(token, form.get("code", ""), client=client):
            return RedirectResponse("/ui", status_code=303)
        mfa = await auth.mfa_status(identity)
        wa_options, wa_notice = await _reauth_webauthn_state(request, auth, token, mfa, False)
        # The submitted code is NOT echoed back — it is a bearer credential, and verify_mfa has
        # already audited the failure. Generic copy: the form cannot say whether the code was
        # wrong or expired without narrowing a guess.
        return HTMLResponse(
            pages.mfa_gate(
                totp_enrolled=mfa.enabled,
                error="That code wasn't accepted. Try again.",
                webauthn_options=wa_options,
                webauthn_notice=wa_notice,
            ),
            status_code=400,
        )

    @app.get("/ui/reauth", response_class=HTMLResponse)
    async def ui_reauth_form(
        request: Request,
        next_: str = Query("", alias="next", max_length=512),
    ) -> Response:
        # next MUST be a registered /ui action — a body-less POST the re-auth may auto-retry
        # (is_safe_ui_action) OR a GET admin form page it may unlock (is_unlock_action). Never an
        # arbitrary URL (anti open-redirect) — an unregistered next bounces to /ui.
        action = lookup_ui_action(next_)
        if action is None:
            return RedirectResponse("/ui", status_code=303)
        auth = get_auth(request)
        token = session_token(request)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or identity is None:
            # The session ended under the operator (expiry / revoke) — a post-termination landing
            # like any other, so it carries Clear-Site-Data + the explanatory code (14.3.1).
            return login_redirect_response()
        if identity.must_change_password:
            # Mirror require_ui's confinement: a must-change session can only rotate (L4b).
            return RedirectResponse("/ui/account/password", status_code=303)
        mfa = await auth.mfa_status(identity)
        if mfa.required and not (mfa.enabled or mfa.webauthn_enrolled) and action.step_up:
            # A full-step-up action a required-but-UNENROLLED session (no factor of EITHER
            # kind — ADR 0068 decision 1(a)) can NEVER satisfy — send it to enroll instead
            # of a password form that would loop straight back. Enrollment itself is
            # step_up=False (below).
            return RedirectResponse("/ui/account?m=enroll_first", status_code=303)
        # The rendering splits BY FACTOR (decision 1(b)): the TOTP code field renders iff
        # TOTP is enrolled (a required-but-unenrolled account can never produce a code —
        # demanding one would deadlock, L4b); the passkey hook renders iff WebAuthn is
        # enrolled — a WebAuthn-only user sees password + passkey, never an unanswerable
        # code field; a both-enrolled user sees both, either satisfies.
        satisfied = await auth.mfa_satisfied(token)
        mfa_needed = not satisfied and mfa.enabled
        wa_options, wa_notice = await _reauth_webauthn_state(request, auth, token, mfa, satisfied)
        return HTMLResponse(
            pages.reauth(
                next_,
                mfa_needed=mfa_needed,
                webauthn_options=wa_options,
                webauthn_notice=wa_notice,
            )
        )

    @app.post("/ui/reauth")
    async def ui_reauth(request: Request) -> Response:
        assert_same_origin(request)
        auth = get_auth(request)
        token = session_token(request)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or not token or identity is None:
            return login_redirect_response()  # session ended mid-ceremony — see ui_reauth_form
        if identity.must_change_password:
            # Mirror require_ui's confinement: a must-change session can only rotate (L4b).
            return RedirectResponse("/ui/account/password", status_code=303)
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")))
        next_ = form.get("next", "")
        action = lookup_ui_action(next_)
        if action is None:
            return RedirectResponse("/ui", status_code=303)
        mfa = await auth.mfa_status(identity)
        if mfa.required and not (mfa.enabled or mfa.webauthn_enrolled) and action.step_up:
            # See ui_reauth_form: a full-step-up action this session can never satisfy (no
            # factor of EITHER kind — ADR 0068 decision 1(a)) — send it to enroll rather
            # than loop. Checked BEFORE the rate limiter so a correct password isn't burned
            # into a 429 (the review's silent-loop finding; the ordering pin covers the
            # generalized condition too).
            return RedirectResponse("/ui/account?m=enroll_first", status_code=303)
        satisfied = await auth.mfa_satisfied(token)
        if not satisfied and not mfa.enabled and mfa.webauthn_enrolled:
            # ADR 0068 decision 1(d): a WebAuthn-ONLY user's password form can never satisfy
            # MFA by itself — the passkey leg (POST /ui/reauth/webauthn) must run first.
            # Checked BEFORE the rate limiter (parallel to the anti-loop check) so a
            # password-first submission burns no limiter slot and no password verify runs
            # before the ceremony. Never "Invalid code." — the user has no code to type.
            wa_options, wa_notice = await _reauth_webauthn_state(
                request, auth, token, mfa, satisfied
            )
            return HTMLResponse(
                pages.reauth(
                    next_,
                    mfa_needed=False,
                    webauthn_options=wa_options,
                    webauthn_notice=wa_notice,
                    error=wa_notice
                    or "Complete the passkey prompt first, then re-enter your password.",
                ),
                status_code=400,
            )
        client = request.client.host if request.client else None
        if not allow_reauth_attempt(auth, identity, client):  # per-ACTOR, not the sign-in budget
            raise HTTPException(429, "too many attempts", headers={"Retry-After": "30"})
        # Satisfy whichever factor is pending — TOTP first (mirrors require_step_up), then
        # password. The code is only demanded from a user with an ENROLLED authenticator
        # (decision 1(c): the code branch keys on TOTP enrollment alone — a WebAuthn-only
        # user is never asked for a code): a required-but-unenrolled account reaches this
        # page on its way to enrolling (L4b) and has nothing to type — its enrollment routes
        # gate on the password step-up alone (require_ui_reauth_only), exactly like the JSON
        # require_reauth_only. Error re-renders re-stage FRESH assertion options (decision
        # 1(e)): the prior challenge was single-use, and the passkey button must survive a
        # failed password/code attempt.
        mfa_enrolled = mfa.enabled
        if mfa_enrolled and not satisfied:
            code = form.get("code", "").strip()
            if not code or not await auth.verify_mfa(token, code, client=client):
                wa_options, wa_notice = await _reauth_webauthn_state(
                    request, auth, token, mfa, await auth.mfa_satisfied(token)
                )
                return HTMLResponse(
                    pages.reauth(
                        next_,
                        mfa_needed=True,
                        webauthn_options=wa_options,
                        webauthn_notice=wa_notice,
                        error="Invalid code.",
                    )
                )
        # 7.5.1 (ADR 0077): mint the single-use grant bound to this continuation's action. action.action
        # is None for every non-factor continuation (replay/purge/config/create-user), so reauth mints
        # nothing there and those flows stay byte-identical; the factor-binding lanes tag their action.
        if not await auth.reauth(
            identity, form.get("password", ""), token=token, client=client, purpose=action.action
        ):
            still_unsatisfied = not await auth.mfa_satisfied(token)
            wa_options, wa_notice = await _reauth_webauthn_state(
                request, auth, token, mfa, not still_unsatisfied
            )
            return HTMLResponse(
                pages.reauth(
                    next_,
                    mfa_needed=mfa_enrolled and still_unsatisfied,
                    webauthn_options=wa_options,
                    webauthn_notice=wa_notice,
                    error="Incorrect password.",
                )
            )
        # Fully stepped up. Hand control back per the action's continuation style:
        #  - an unlock target is a GET admin form → 303-GET-redirect so it re-opens inside the now
        #    fresh window; the operator then submits the body-carrying POST (incl. a create-user
        #    password) once, never crossing /ui/reauth (the stateless confirm-after-step-up path).
        #  - otherwise it is a body-less POST action → auto-retry it via the same-origin submit form.
        if is_unlock_action(next_):
            return RedirectResponse(next_, status_code=303)
        return HTMLResponse(pages.reauth_continue(next_))

    # ADR 0068 decision 6: the browser passkey leg of step-up. A cookie-authed JSON POST
    # (the sanctioned /ui carve — the cookie stays confined to /ui deps; bearer_token()
    # is untouched) that verifies an assertion and stamps the session's MFA leg ONLY —
    # the operator still submits POST /ui/reauth (password) for reauth_at + the WP-L3-13
    # client re-anchor. NOT registered as a continuation (body-carrying JSON — part of the
    # step-up mechanism itself). MFA-pending sessions pass (the assertion IS the proof);
    # must-change confinement is mirrored manually like both /ui/reauth handlers.
    @app.post("/ui/reauth/webauthn")
    async def ui_reauth_webauthn(request: Request) -> Response:
        assert_same_origin(request)
        auth = get_auth(request)
        token = session_token(request)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or not token or identity is None:
            return JSONResponse({"ok": False, "error": "session expired"}, status_code=401)
        if identity.must_change_password:
            # Mirror require_ui's confinement: a must-change session can only rotate (L4b).
            return JSONResponse({"ok": False, "error": "password change required"}, status_code=403)
        rp = webauthn_rp(request)
        if rp is None:
            return JSONResponse({"ok": False, "error": "rp_unavailable"}, status_code=409)
        client = request.client.host if request.client else None
        if not allow_reauth_attempt(auth, identity, client):  # per-ACTOR, not the sign-in budget
            return JSONResponse(
                {"ok": False, "error": "too many attempts"},
                status_code=429,
                headers={"Retry-After": "30"},
            )
        try:
            body = await request.json()
            response_json = json.dumps(body["response"])
        except (ValueError, KeyError, TypeError):
            return JSONResponse({"ok": False, "error": "malformed request"}, status_code=400)
        ok = await auth.finish_webauthn_assertion(
            token, response_json, client=client, rp_id=rp[0], origin=rp[1]
        )
        if not ok:
            return JSONResponse(
                {"ok": False, "error": "passkey verification failed"}, status_code=400
            )
        return JSONResponse({"ok": True})

    # Bulk dead-letter replay (M3): re-queue ALL dead deliveries for one channel. Like message
    # replay it is require_step_up (→ require_ui_step_up, which 303s to /ui/reauth on a stale
    # step-up; the channel is in the PATH so the auto-retry re-POST carries it — no lost body).
    # Reuses the JSON replay_dead_letters handler, so the dual-control approval gate applies: when
    # it holds the op for a second approver, surface that instead of redirecting.
    async def _ui_dl_replay(
        request: Request,
        channel_id: str | None,
        destination_name: str | None,
        engine: Any,
        identity: Identity,
        gate: Any,
    ) -> Response:
        assert_same_origin(request)
        # channel_id=None ⇒ every channel (the all-channels scope, L6b); the JSON handler
        # pre-checks scope and refuses a channel-scoped user before mutating anything.
        result = await core.replay_dead_letters(
            DeadLetterReplayRequest(channel_id=channel_id, destination_name=destination_name),
            Response(),
            engine=engine,
            identity=identity,
            gate=gate,
            request=request,
        )
        if isinstance(result, PendingApprovalResponse):
            return HTMLResponse(pages.dead_letter_pending(result))
        return RedirectResponse("/ui/dead-letters", status_code=303)

    # L6b (#75 parity): replay ALL dead deliveries across every channel in one action (the
    # desktop's null-scope "Replay all"). Declared before the {channel_id} routes; the
    # literal `replay-all` can't be a channel id (it has no `/replay` suffix). Same
    # step-up + dual-control gate; the JSON handler still denies channel-scoped users.
    @app.post("/ui/dead-letters/replay-all")
    async def ui_replay_all_dead_letters(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_REPLAY)),
        gate: Any = Depends(deps.get_gate),
    ) -> Response:
        return await _ui_dl_replay(request, None, None, engine, identity, gate)

    @app.post("/ui/dead-letters/{channel_id}/replay")
    async def ui_replay_dead_letters(
        channel_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_REPLAY)),
        gate: Any = Depends(deps.get_gate),
    ) -> Response:
        # All dead deliveries for the channel (every destination).
        return await _ui_dl_replay(request, channel_id, None, engine, identity, gate)

    @app.post("/ui/dead-letters/{channel_id}/{destination_name}/replay")
    async def ui_replay_dead_letters_dest(
        channel_id: str,
        destination_name: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_REPLAY)),
        gate: Any = Depends(deps.get_gate),
    ) -> Response:
        # Just the dead deliveries for this (channel, destination).
        return await _ui_dl_replay(request, channel_id, destination_name, engine, identity, gate)

    @app.post("/ui/csp-report")
    async def ui_csp_report(request: Request) -> Response:
        # ASVS 3.5.1 — FIRST statement. The THIRD unguarded /ui POST is disposed of here, with the
        # NARROW guard rather than the full same-origin check, because the two are not interchangeable
        # on a report sink: `report-uri` delivery is document-initiated (Sec-Fetch-Site: same-origin),
        # but Reporting-API (`report-to`) delivery is made OUT OF BAND by the user agent's reporting
        # agent — no Sec-Fetch-* headers, possibly `Origin: null` — so assert_same_origin's Origin
        # fallback would 403 every modern report and silently blind the 3.7.5 canary. The property that
        # actually matters here is preserved: a report a FOREIGN site's CSP aimed at this endpoint
        # (log amplification) is refused. The residual exposure of the header-less path is bounded by
        # construction — the sink is unauthenticated, non-state-changing and observation-only: it
        # parses defensively, never echoes or acts on the body, logs one bounded PHI-free summary and
        # 204s, under the engine's 1 MiB request-body cap.
        assert_not_cross_site(request)
        # Browser-delivered CSP violation report (ASVS 3.7.5). UNAUTHENTICATED and non-mutating: a
        # browser attaches no session credential to a report POST, and this only observes. The body is
        # attacker-influenceable DATA (never instructions) — parse it defensively, log a BOUNDED,
        # PHI-free summary at WARNING (the /ui surface carries no message bodies in its URLs), and 204.
        # Never echo or act on the report. Both the legacy report-uri body and the modern report-to
        # ARRAY (the wired Reporting-Endpoints header) are normalized by ``_csp_report_bodies``.
        client = request.client.host if request.client else "<unknown>"
        raw = await request.body()
        if not raw:
            _log.warning("CSP violation report from %s: %s", client, "empty")
            return Response(status_code=204)
        try:
            doc = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            _log.warning("CSP violation report from %s: %s", client, "malformed-json")
            return Response(status_code=204)
        bodies = _csp_report_bodies(doc)
        if bodies is None:
            _log.warning("CSP violation report from %s: %s", client, "non-object")
            return Response(status_code=204)
        # Partition the BATCH, never classify it by one entry. The canary fires once per page load on
        # every conforming browser and the Reporting API batches per endpoint, so a real violation
        # raised on the same page load arrives in the same POST alongside the canary's report. Only
        # the canary's own entries are dropped to DEBUG (so it never floods the operational log); a
        # batch containing ANY other blocked URL — including "inline", the shape a real XSS attempt
        # produces — still WARNS, and the warning summarises the REAL entries, not the canary.
        origin = _request_origin(request)
        real = [b for b in bodies if not _is_expected_csp_probe_report(b, origin)]
        canary_count = len(bodies) - len(real)
        if canary_count:
            _log.debug("CSP enforcement canary blocked as designed (%d report(s))", canary_count)
        if real or not bodies:
            # Bounded on BOTH axes — per-field (256 chars, in the summariser), per-batch (the first
            # few entries) and overall (1024 chars) — so a hostile flood cannot inflate the log.
            shown = " | ".join(_csp_report_summary(b) for b in real[:_CSP_REPORT_SUMMARY_MAX])
            if len(real) > _CSP_REPORT_SUMMARY_MAX:
                shown += f" (+{len(real) - _CSP_REPORT_SUMMARY_MAX} more)"
            _log.warning("CSP violation report from %s: %s", client, (shown or "empty")[:1024])
        return Response(status_code=204)
