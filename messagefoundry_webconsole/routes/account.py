# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L4b/L5a/L6b self-service account surface: change-password, TOTP MFA lifecycle, WebAuthn passkeys, and session management."""

from __future__ import annotations

import json

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import ValidationError

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.auth_models import (
    PasswordChangeRequest,
)
from messagefoundry.auth import Identity
from messagefoundry.auth import webauthn as webauthn_mod
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token

from .. import pages
from .._auth import (
    session_token,
    WEBAUTHN_EXTRA_MISSING_NOTICE,
    WEBAUTHN_RP_MISSING_NOTICE,
    assert_same_origin,
    clear_session_cookie,
    register_ui_action,
    require_ui,
    require_ui_reauth_only,
    require_ui_step_up,
    webauthn_rp,
)
from .._service import _service
from ._common import _client, _form_pairs, _rate_limited

# --- L4b: self-service account (change password + TOTP MFA lifecycle) -------
# Self-scoped actions: any authenticated session acts on ITS OWN credential, so the registry
# entries carry permission=None (enforcement is the require_ui* dependency on each route).
# MFA enroll/disable are body-less POSTs → auto_retry; the confirm-code POST is body-carrying,
# so its standalone GET form registers as the unlock re-entry point. The change-password POST
# is in NEITHER registry: it has no step-up gate (the current password in the body IS the
# proof), so no re-auth continuation ever needs to reach it.
# enroll + confirm are password-only (require_ui_reauth_only) — step_up=False so the /ui/reauth
# flow knows a required-but-unenrolled session CAN complete them (it is the enrollment path);
# disable needs the full step-up (require_ui_step_up), so it keeps step_up=True (default).
register_ui_action(r"^/ui/account/mfa/enroll$", None, step_up=False)
register_ui_action(r"^/ui/account/mfa/disable$", None)
register_ui_action(r"^/ui/account/mfa/confirm$", None, step_up=False, auto_retry=False, unlock=True)
# --- L5a: WebAuthn passkeys (ADR 0068, WP-14b) -------------------------------
# Self-scoped actions (permission=None — enforcement is each route's require_ui* dep).
# enroll is the TOTP-enroll twin: a body-less POST returning HTML, gated on the password-
# only re-proof (require_ui_reauth_only — WP-14: a stolen pre-MFA cookie must never bind
# an attacker's passkey) and registered step_up=False so the enroll_first anti-loop knows
# a required-but-unenrolled session CAN complete it. delete is the body-less path-param
# auto-retry shape behind the FULL step-up. The verify route is a body-carrying JSON POST
# — NEVER registered as a continuation (hard invariant); its require_ui_reauth_only maps a
# stale-window 303 to the REGISTERED enroll action (the #745 ui_mfa_verify precedent).
register_ui_action(r"^/ui/account/webauthn/enroll$", None, step_up=False)
register_ui_action(r"^/ui/account/webauthn/[^/?#]+/delete$", None)


def register(app: FastAPI, deps: UiDeps) -> None:
    """L4b/L5a/L6b self-service account surface: change-password, TOTP MFA lifecycle, WebAuthn passkeys, and session management."""
    admin = deps.admin

    # Post-redirect notices (allow-listed codes only — never reflected text).
    _ACCOUNT_NOTICES = {
        "mfa_off": "MFA disabled.",
        "enroll_first": (
            "That action requires MFA — enroll an authenticator (TOTP app or passkey) to continue."
        ),
        "passkey_added": "Passkey added.",
        "passkey_removed": "Passkey removed.",
    }

    async def _account_response(
        service: AuthService,
        identity: Identity,
        request: Request,
        *,
        notice: str | None = None,
        error: str | None = None,
        status_code: int = 200,
    ) -> HTMLResponse:
        mfa = await admin.my_mfa(service=service, identity=identity)
        # L5a passkey rows (plain mappings — the pages module never touches the store); the
        # "usable" flag compares each credential's mint-time rp_id to the CURRENT RP identity
        # (an origin migration renders old credentials visibly unusable, ADR 0068 §7).
        rp = webauthn_rp(request)
        creds = await service.store.list_webauthn_credentials(identity.user_id)
        passkeys = [
            {
                "label": c.label,
                "created_at": c.created_at,
                "last_used_at": c.last_used_at,
                "backed_up": c.backed_up,
                "usable": rp is not None and c.rp_id == rp[0],
                "credential_id_hash": c.credential_id_hash,
            }
            for c in creds
        ]
        wa_notice: str | None = None
        if not service.webauthn_available():
            wa_notice = WEBAUTHN_EXTRA_MISSING_NOTICE
        elif rp is None:
            wa_notice = WEBAUTHN_RP_MISSING_NOTICE
        return HTMLResponse(
            pages.account_page(
                admin.current_user(identity),
                mfa,
                notice=notice,
                error=error,
                passkeys=passkeys,
                webauthn_notice=wa_notice,
            ),
            status_code=status_code,
        )

    @app.get("/ui/account", response_class=HTMLResponse)
    async def ui_account(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui()),
        m: str | None = Query(None, max_length=32),
    ) -> HTMLResponse:
        return await _account_response(
            service, identity, request, notice=_ACCOUNT_NOTICES.get(m or "")
        )

    @app.get("/ui/account/password", response_class=HTMLResponse)
    async def ui_account_password_form(
        identity: Identity = Depends(require_ui(allow_must_change=True)),
    ) -> HTMLResponse:
        # `forced` comes from the SERVER-side flag, never a query param (unspoofable).
        return HTMLResponse(pages.password_page(forced=identity.must_change_password))

    @app.post("/ui/account/password")
    async def ui_account_password(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui(allow_must_change=True)),
    ) -> Response:
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        forced = identity.must_change_password

        def _retry(message: str, code: int = 400) -> HTMLResponse:
            # Passwords are NEVER echoed back — the re-rendered form is always empty.
            return HTMLResponse(pages.password_page(forced=forced, error=message), status_code=code)

        if form.get("new_password", "") != form.get("new_password2", ""):
            return _retry("the new passwords do not match")
        try:
            body = PasswordChangeRequest(
                current_password=form.get("current_password", ""),
                new_password=form.get("new_password", ""),
            )
            await admin.change_password(
                body=body, request=request, service=service, identity=identity
            )
        except ValidationError:
            return _retry("invalid input")
        except HTTPException as exc:
            if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                raise  # rate-limited — keep the Retry-After semantics
            return _retry(str(exc.detail), exc.status_code)
        # Changed: the service revoked every session (incl. this cookie) — sign in again.
        resp = RedirectResponse("/ui/login?e=pwchanged", status_code=303)
        clear_session_cookie(resp, request)
        return resp

    @app.post("/ui/account/mfa/enroll")
    async def ui_mfa_enroll(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_reauth_only()),
    ) -> Response:
        assert_same_origin(request)
        try:
            enroll = await admin.enroll_mfa(service=service, identity=identity)
        except HTTPException as exc:
            # AD account / already enrolled — surface on the account page.
            return await _account_response(
                service, identity, request, error=str(exc.detail), status_code=400
            )
        # The staged secret renders ONCE (with the confirm form); it is inert until confirmed.
        return HTMLResponse(pages.mfa_enroll_page(enroll.secret, enroll.otpauth_uri))

    @app.get("/ui/account/mfa/confirm", response_class=HTMLResponse)
    async def ui_mfa_confirm_form(
        _identity: Identity = Depends(require_ui_reauth_only()),
    ) -> HTMLResponse:
        # The unlock re-entry point: the secret is already staged server-side (and in the user's
        # authenticator), so this form only collects the code — the secret is never re-shown.
        return HTMLResponse(pages.mfa_confirm_page())

    @app.post("/ui/account/mfa/verify")
    async def ui_mfa_verify(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(
            require_ui_reauth_only(reauth_next=lambda _r: "/ui/account/mfa/confirm")
        ),
    ) -> Response:
        assert_same_origin(request)
        # The JSON confirm_mfa handler reads the HEADER bearer token (absent on a cookie request),
        # so this route drives the SERVICE directly with the cookie session token — the same
        # cookie-vs-header split ui_login/ui_reauth already handle. Semantics match the JSON
        # handler: rate-limited like login; wrong code changes nothing.
        client = _client(request)
        if not service.allow_login_attempt(client):
            raise _rate_limited(request, "mfa-confirm")
        token = session_token(request)
        if not token:  # pragma: no cover - require_ui already authenticated this cookie
            return RedirectResponse("/ui/login", status_code=303)
        form = dict(await _form_pairs(request))
        code = form.get("code", "").strip()
        try:
            codes = await service.confirm_mfa_enrollment(identity, code, token=token, client=client)
        except ValueError as exc:
            # No enrollment staged / not a local account — back to the account page.
            return await _account_response(
                service, identity, request, error=str(exc), status_code=400
            )
        if codes is None:
            return HTMLResponse(pages.mfa_confirm_page(error="Invalid code."), status_code=400)
        # Activated: the recovery codes render ONCE — never re-fetchable.
        return HTMLResponse(pages.mfa_recovery_page(codes))

    @app.post("/ui/account/mfa/disable")
    async def ui_mfa_disable(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up()),
    ) -> Response:
        assert_same_origin(request)
        await admin.disable_my_mfa(request=request, service=service, identity=identity)
        return RedirectResponse("/ui/account?m=mfa_off", status_code=303)

    # --- L6b: self-service session management (#75 parity — desktop sessions.py twin) ---
    # Managing one's OWN sessions is cookie-authenticated self-service (require_ui), no step-up:
    # the caller is already authenticated and acting only on their own sessions. The JSON
    # my_sessions/revoke_my_other_sessions handlers read the HEADER bearer to identify the
    # current session, absent on a cookie request — so these drive the SERVICE directly with the
    # cookie session token (the ui_mfa_verify cookie-vs-header pattern). No registry entry: these
    # never route through /ui/reauth (not step-up actions).
    _SESSION_NOTICES = {
        "revoked": "Session revoked.",
        "signed_out_others": "Signed out of your other sessions.",
    }

    @app.get("/ui/account/sessions", response_class=HTMLResponse)
    async def ui_account_sessions(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui()),
        m: str | None = Query(None, max_length=32),
    ) -> HTMLResponse:
        current = hash_token(session_token(request) or "")
        sessions = await service.list_sessions(identity.user_id)
        rows = [
            {
                "id": s.token_hash,
                "created_at": s.created_at,
                "last_used_at": s.last_used_at,
                "expires_at": s.expires_at,
                "client": s.client,
                "current": s.token_hash == current,
            }
            for s in sessions
        ]
        return HTMLResponse(pages.sessions_page(rows, notice=_SESSION_NOTICES.get(m or "")))

    @app.post("/ui/account/sessions/{session_id}/revoke")
    async def ui_revoke_session(
        session_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui()),
    ) -> Response:
        assert_same_origin(request)
        # Ownership-checked in the service; an unknown/foreign id is a silent no-op (never
        # confirms another user's session id). Revoking the CURRENT session logs the caller
        # out — the next request finds no session and 303s to login.
        await service.revoke_own_session(identity, session_id, actor=identity.username)
        return RedirectResponse("/ui/account/sessions?m=revoked", status_code=303)

    @app.post("/ui/account/sessions/revoke-others")
    async def ui_revoke_other_sessions(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui()),
    ) -> Response:
        assert_same_origin(request)
        current = hash_token(session_token(request) or "")
        await service.revoke_other_sessions(identity, current, actor=identity.username)
        return RedirectResponse("/ui/account/sessions?m=signed_out_others", status_code=303)

    _RP_NAME = "MessageFoundry"

    @app.post("/ui/account/webauthn/enroll")
    async def ui_webauthn_enroll(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_reauth_only()),
    ) -> Response:
        assert_same_origin(request)
        if not service.webauthn_available():
            return await _account_response(
                service,
                identity,
                request,
                error=WEBAUTHN_EXTRA_MISSING_NOTICE,
                status_code=400,
            )
        rp = webauthn_rp(request)
        if rp is None:
            # Fail closed, legibly (ADR 0068 §7): 409 + the shared notice on the account page.
            return await _account_response(
                service,
                identity,
                request,
                error=WEBAUTHN_RP_MISSING_NOTICE,
                status_code=409,
            )
        token = session_token(request)
        if not token:  # pragma: no cover - require_ui_reauth_only authenticated this cookie
            return RedirectResponse("/ui/login", status_code=303)
        try:
            options = await service.begin_webauthn_registration(
                identity, token=token, rp_id=rp[0], rp_name=_RP_NAME
            )
        except ValueError as exc:  # AD account
            return await _account_response(
                service, identity, request, error=str(exc), status_code=400
            )
        except webauthn_mod.ChallengeCacheFullError as exc:
            return await _account_response(
                service, identity, request, error=str(exc), status_code=503
            )
        # The creation options render ONCE in a data-* hook (CSP: no inline script).
        return HTMLResponse(pages.webauthn_enroll_page(options))

    @app.post("/ui/account/webauthn/verify")
    async def ui_webauthn_verify(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(
            require_ui_reauth_only(reauth_next=lambda _r: "/ui/account/webauthn/enroll")
        ),
    ) -> Response:
        assert_same_origin(request)
        rp = webauthn_rp(request)
        if rp is None:
            return JSONResponse({"ok": False, "error": "rp_unavailable"}, status_code=409)
        token = session_token(request)
        if not token:  # pragma: no cover - require_ui_reauth_only authenticated this cookie
            return JSONResponse({"ok": False, "error": "session expired"}, status_code=401)
        try:
            body = await request.json()
            response_json = json.dumps(body["response"])
            label = str(body.get("label", ""))
        except (ValueError, KeyError, TypeError):
            return JSONResponse({"ok": False, "error": "malformed request"}, status_code=400)
        try:
            ok = await service.finish_webauthn_registration(
                identity,
                response_json,
                label=label,
                token=token,
                client=_client(request),
                rp_id=rp[0],
                origin=rp[1],
            )
        except ValueError as exc:
            # Service-authored, safe messages only (expired ceremony / duplicate label or
            # credential / bad label / AD) — never reflected input.
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
        if not ok:
            return JSONResponse(
                {"ok": False, "error": "passkey verification failed"}, status_code=400
            )
        return JSONResponse({"ok": True, "redirect": "/ui/account?m=passkey_added"})

    @app.post("/ui/account/webauthn/{credential_id_hash}/delete")
    async def ui_webauthn_delete(
        credential_id_hash: str,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up()),
    ) -> Response:
        assert_same_origin(request)
        try:
            removed = await service.delete_webauthn_credential(
                identity, credential_id_hash, client=_client(request)
            )
        except ValueError as exc:  # last-required-factor refusal
            return await _account_response(
                service, identity, request, error=str(exc), status_code=400
            )
        if not removed:
            return await _account_response(
                service, identity, request, error="No such passkey.", status_code=404
            )
        return RedirectResponse("/ui/account?m=passkey_removed", status_code=303)
