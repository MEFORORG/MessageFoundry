# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Core /ui pages: login/logout, dashboard, messages + parse-tree, dead-letters, replay, and the step-up re-auth flow (GET/POST /ui/reauth + the WebAuthn leg) — the sole consumer of the write-action registry (ADR 0065)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import (
    DeadLetterReplayRequest,
    PendingApprovalResponse,
)
from messagefoundry.api.security import get_auth
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.service import AuthService, MfaStatus
from messagefoundry.parsing import HL7PeekError, parse_tree

from .. import pages
from .._auth import (
    COOKIE_NAME,
    WEBAUTHN_EXTRA_MISSING_NOTICE,
    WEBAUTHN_RP_CHANGED_NOTICE,
    WEBAUTHN_RP_MISSING_NOTICE,
    assert_same_origin,
    clear_session_cookie,
    is_unlock_action,
    lookup_ui_action,
    require_ui,
    require_ui_step_up,
    set_session_cookie,
    webauthn_rp,
)


def register(app: FastAPI, deps: UiDeps) -> None:
    """Register the phase-0 /ui routes (login, dashboard, messages, dead-letters, replay,
    reauth). Runs first in ``_UI_REGISTRARS``; a page lane adds its own
    ``_register_<area>(app)`` + one tuple entry below, so parallel lanes never edit this
    shared block (ADR 0065 §multi-session-build)."""
    core = deps.core

    @app.get("/ui/login", response_class=HTMLResponse)
    async def ui_login_form(
        request: Request, e: str | None = Query(None, max_length=32)
    ) -> HTMLResponse:
        auth = get_auth(request)
        ad_enabled = auth is not None and auth.ad_enabled
        sso_enabled = auth is not None and auth.kerberos_available
        return HTMLResponse(pages.login(e, ad_enabled=ad_enabled, sso_enabled=sso_enabled))

    @app.post("/ui/login")
    async def ui_login(request: Request) -> Response:
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
        # /ui route would bounce it there anyway (require_ui).
        target = "/ui/account/password" if outcome.must_change_password else "/ui"
        resp = RedirectResponse(target, status_code=303)
        set_session_cookie(resp, outcome.token, secure=deps.cookie_secure(request))
        return resp

    @app.post("/ui/logout")
    async def ui_logout(request: Request) -> Response:
        auth = get_auth(request)
        token = request.cookies.get(COOKIE_NAME)
        if auth is not None and token:
            await auth.logout(token)
        resp = RedirectResponse("/ui/login?e=loggedout", status_code=303)
        clear_session_cookie(resp)
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
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
    ) -> HTMLResponse:
        rows = await core.list_connections(engine=engine, identity=identity)
        return HTMLResponse(pages.connections_fragment(rows))

    @app.get("/ui/connection/{name}", response_class=HTMLResponse)
    async def ui_connection_details(
        name: str,
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
        await action(name, engine=engine, identity=identity)
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
        await core.replay_message(message_id, engine=engine, identity=identity)
        return RedirectResponse(f"/ui/messages/{message_id}", status_code=303)

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
        token = request.cookies.get(COOKIE_NAME)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or identity is None:
            return RedirectResponse("/ui/login", status_code=303)
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
        token = request.cookies.get(COOKIE_NAME)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or not token or identity is None:
            return RedirectResponse("/ui/login", status_code=303)
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
        if not auth.allow_login_attempt(client):
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
        if not await auth.reauth(identity, form.get("password", ""), token=token, client=client):
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
        token = request.cookies.get(COOKIE_NAME)
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
        if not auth.allow_login_attempt(client):
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
