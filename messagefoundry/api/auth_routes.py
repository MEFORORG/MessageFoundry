# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Authentication + user-administration routes, registered onto the app by :func:`add_auth_routes`.

Kept out of ``app.py`` to keep that file focused on the engine surface. Every route here is
deny-by-default: it depends on ``require(...)`` for the relevant permission (login/logout/me are the
only unauthenticated or self-scoped ones).
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from urllib.parse import parse_qsl

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import ValidationError

# NOTE: messagefoundry.api.webui is deliberately NOT imported at module scope (ADR 0065 / Option B
# Phase 0). It is a GUARDED, lazy import inside the serve_ui branch below, so this module imports and
# the engine boots with the web console ABSENT. The serve_ui /ui admin pages require it.
from messagefoundry.api.auth_models import (
    AdGroupMap,
    AdGroupMapEntry,
    AdGroupScopeEntry,
    AdGroupScopeMap,
    AuditEntry,
    AuditList,
    ChannelScope,
    CurrentUser,
    CustomRoleInfo,
    CustomRoleRequest,
    LoginRequest,
    LoginResponse,
    MfaConfirmRequest,
    MfaConfirmResponse,
    MfaEnrollResponse,
    MfaStatusResponse,
    MfaVerifyRequest,
    PasswordChangeRequest,
    PasswordResetResponse,
    ProvidersInfo,
    ReauthRequest,
    RoleInfo,
    RolesUpdateRequest,
    SecurityEventInfo,
    SecurityEventsList,
    SessionInfo,
    SessionList,
    SimpleMessage,
    UserCreateRequest,
    UserSummary,
    UserUpdateRequest,
)
from messagefoundry.api.security import (
    bearer_token,
    get_auth,
    require,
    require_reauth_only,
    require_step_up,
)
from messagefoundry.auth import (
    BUILTIN_ROLE_PERMISSIONS,
    ROLE_METADATA,
    AuthProvider,
    Identity,
    Permission,
    Role,
)
from messagefoundry.auth import webauthn as webauthn_mod
from messagefoundry.auth.permissions import CUSTOM_ROLE_FORBIDDEN_PERMISSIONS, CustomRoleError
from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.store.store import SessionRecord, UserRecord

_VALID_ROLE_IDS = {role.value for role in Role}

_log = logging.getLogger(__name__)


def _session_info(session: SessionRecord, current_token_hash: str) -> SessionInfo:
    """Project a stored session into the self-service view, flagging the caller's current one (WP-10)."""
    return SessionInfo(
        id=session.token_hash,
        created_at=session.created_at,
        last_used_at=session.last_used_at,
        expires_at=session.expires_at,
        client=session.client,
        current=session.token_hash == current_token_hash,
    )


def _rate_limited(request: Request, label: str) -> HTTPException:
    """Log a throttled (HTTP 429) attempt so password-spraying is no longer silent (ASVS 16.3.3),
    then return the exception to raise. We log (the rotating general log) rather than write an
    audit_log row per rejection so a sustained flood can't amplify into unbounded DB growth — the
    per-account ``auth.login_failed``/``auth.login_locked`` events already provide the audit trail."""
    _log.warning("rate-limited %s attempt from client=%s", label, _client(request))
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts; please retry later")


def _service(request: Request) -> AuthService:
    auth = get_auth(request)
    if auth is None or not auth.enabled:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "authentication is not enabled")
    return auth


def _client(request: Request) -> str | None:
    # Already proxy-aware: uvicorn runs with forwarded_allow_ips = settings.api.trusted_proxies
    # (__main__.py; defaults to [] = trust nothing), so behind a declared trusted proxy this resolves
    # to the real client. The per-IP login limiter remains in-process and bypassable by pure source-IP
    # rotation from a directly-reachable attacker (SEC-024) — the real brute-force bounds are the
    # global ceiling + per-account argon2 lockout (applied to both the password and MFA factors).
    return request.client.host if request.client else None


def _current_user(identity: Identity) -> CurrentUser:
    return CurrentUser(
        user_id=identity.user_id,
        username=identity.username,
        auth_provider=identity.auth_provider.value,
        roles=sorted(r.value for r in identity.roles),
        permissions=sorted(p.value for p in identity.permissions),
    )


def _login_response(
    token: str, identity: Identity, must_change: bool, *, mfa_required: bool = False
) -> LoginResponse:
    return LoginResponse(
        token=token,
        must_change_password=must_change,
        mfa_required=mfa_required,
        user=_current_user(identity),
    )


def _parse_channel_scope(raw: str | None) -> list[str] | None:
    """Decode the stored ``channel_scope`` JSON to a list (None = all; malformed → empty list)."""
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(c) for c in value] if isinstance(value, list) else []


def _user_summary(user: UserRecord, role_ids: list[str]) -> UserSummary:
    return UserSummary(
        id=user.id,
        username=user.username,
        auth_provider=user.auth_provider,
        display_name=user.display_name,
        email=user.email,
        disabled=user.disabled,
        roles=sorted(role_ids),
        channel_scope=_parse_channel_scope(user.channel_scope),
    )


async def _validate_roles(service: AuthService, roles: list[str]) -> None:
    """Reject any role id that is neither a fixed built-in nor an existing custom role (ADR 0045) —
    so a user can be assigned a custom role, but never a non-existent / mistyped id (deny-by-default)."""
    unknown = set(roles) - _VALID_ROLE_IDS
    if unknown:
        custom_ids = {r.id for r in await service.list_custom_roles()}
        unknown -= custom_ids
    if unknown:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"unknown role(s): {', '.join(sorted(unknown))}"
        )


def add_auth_routes(app: FastAPI, *, serve_ui: bool = False) -> None:
    """Register the auth + user-administration JSON routes; with ``serve_ui`` also the /ui admin pages.

    The /ui admin surface (L4a, ADR 0065) lives at the END of this function — not in ``app.py``'s
    ``_UI_REGISTRARS`` — because it reuses these **nested** JSON handlers directly (the same pattern the
    other /ui routes use with ``app.py``'s handlers), and closures are only reachable from in here.
    """
    # --- authentication ------------------------------------------------------

    @app.get("/auth/providers", response_model=ProvidersInfo)
    async def providers(
        request: Request, service: AuthService = Depends(_service)
    ) -> ProvidersInfo:
        # kerberos reflects AVAILABILITY (enabled AND the boot preflight passed, ADR 0068 §9)
        # so a native client can hide its SSO affordance when the acceptor is degraded.
        return ProvidersInfo(local=True, ad=service.ad_enabled, kerberos=service.kerberos_available)

    @app.post("/auth/login", response_model=LoginResponse)
    async def login(
        body: LoginRequest, request: Request, service: AuthService = Depends(_service)
    ) -> LoginResponse:
        if not service.allow_login_attempt(_client(request)):
            raise _rate_limited(request, "login")
        try:
            provider = AuthProvider(body.provider)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown provider") from None
        outcome = await service.login(
            body.username, body.password, provider=provider, client=_client(request)
        )
        if not outcome.ok or outcome.token is None or outcome.identity is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
        return _login_response(
            outcome.token,
            outcome.identity,
            outcome.must_change_password,
            mfa_required=outcome.mfa_required,
        )

    @app.post("/auth/negotiate", response_model=LoginResponse)
    async def negotiate(
        request: Request, service: AuthService = Depends(_service)
    ) -> LoginResponse:
        if not service.allow_login_attempt(_client(request)):
            raise _rate_limited(request, "negotiate")
        header = request.headers.get("Authorization", "")
        if not header.startswith("Negotiate "):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing SPNEGO token")
        try:
            token_bytes = base64.b64decode(header[len("Negotiate ") :], validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid SPNEGO token") from None
        outcome = await service.authenticate_kerberos(token_bytes, client=_client(request))
        if not outcome.ok or outcome.token is None or outcome.identity is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "SSO authentication failed")
        return _login_response(outcome.token, outcome.identity, outcome.must_change_password)

    @app.post("/auth/logout", response_model=SimpleMessage)
    async def logout(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require()),
    ) -> SimpleMessage:
        await service.logout(bearer_token(request), actor=identity.username)
        return SimpleMessage(detail="logged out")

    @app.get("/auth/me", response_model=CurrentUser)
    async def me(identity: Identity = Depends(require())) -> CurrentUser:
        return _current_user(identity)

    @app.post("/me/password", response_model=SimpleMessage)
    async def change_password(
        body: PasswordChangeRequest,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require()),
    ) -> SimpleMessage:
        if not service.allow_login_attempt(_client(request)):
            raise _rate_limited(request, "password-change")
        if identity.auth_provider is AuthProvider.AD:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "AD passwords are managed in Active Directory"
            )
        if not await service.verify_current_password(identity, body.current_password):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "current password is incorrect")
        violations = await service.change_password(
            identity, body.new_password, client=_client(request)
        )
        if violations:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "password must " + "; ".join(violations)
            )
        return SimpleMessage(detail="password changed; please sign in again")

    @app.post("/me/reauth", response_model=SimpleMessage)
    async def reauth(
        body: ReauthRequest,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require()),
    ) -> SimpleMessage:
        """Step-up re-verification (ASVS 7.5.3): re-prove the current credential to refresh this
        session's step-up window so it may perform highly sensitive operations for the configured
        period. Rate-limited like the password change; a failure is a 403 and performs nothing."""
        if not service.allow_login_attempt(_client(request)):
            raise _rate_limited(request, "reauth")
        token = bearer_token(request)
        if token is None or not await service.reauth(
            identity, body.password, token=token, client=_client(request)
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "re-verification failed")
        return SimpleMessage(detail="re-verified")

    # --- MFA: native TOTP second factor (WP-14, ASVS 6.3.3) ------------------

    @app.post("/auth/mfa-verify", response_model=SimpleMessage)
    async def mfa_verify(
        body: MfaVerifyRequest,
        request: Request,
        service: AuthService = Depends(_service),
        _: Identity = Depends(require()),
    ) -> SimpleMessage:
        """Satisfy the current session's second factor with a TOTP code or a single-use recovery code.
        Authenticated but **not** step-up/MFA-gated (this is *how* a session becomes MFA-satisfied);
        rate-limited like login. A wrong code is a 401 and changes nothing."""
        if not service.allow_login_attempt(_client(request)):
            raise _rate_limited(request, "mfa-verify")
        token = bearer_token(request)
        if token is None or not await service.verify_mfa(token, body.code, client=_client(request)):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
        return SimpleMessage(detail="verified")

    @app.get("/me/mfa", response_model=MfaStatusResponse)
    async def my_mfa(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require()),
    ) -> MfaStatusResponse:
        """The caller's current MFA posture (enabled, enrolled-at, recovery codes left, required)."""
        st = await service.mfa_status(identity)
        return MfaStatusResponse(
            enabled=st.enabled,
            enrolled_at=st.enrolled_at,
            recovery_codes_remaining=st.recovery_codes_remaining,
            required=st.required,
            webauthn_enrolled=st.webauthn_enrolled,
        )

    @app.post("/me/mfa/enroll", response_model=MfaEnrollResponse)
    async def enroll_mfa(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_reauth_only()),
    ) -> MfaEnrollResponse:
        """Begin TOTP enrollment: stage a secret and return it + the ``otpauth://`` URI for the QR.
        Gated by a recent **password** step-up (not MFA — you may have none yet); not active until
        confirmed via ``/me/mfa/confirm``."""
        if identity.auth_provider is AuthProvider.AD:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "AD accounts use directory MFA, not an engine TOTP"
            )
        try:
            enroll = await service.begin_mfa_enrollment(identity)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        return MfaEnrollResponse(secret=enroll.secret, otpauth_uri=enroll.otpauth_uri)

    @app.post("/me/mfa/confirm", response_model=MfaConfirmResponse)
    async def confirm_mfa(
        body: MfaConfirmRequest,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_reauth_only()),
    ) -> MfaConfirmResponse:
        """Confirm a staged enrollment by proving a live TOTP code; activates MFA and returns the
        single-use recovery codes (shown **once** — save them). A wrong code is a 400."""
        if not service.allow_login_attempt(_client(request)):
            raise _rate_limited(request, "mfa-confirm")
        token = bearer_token(request)
        if token is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
        try:
            codes = await service.confirm_mfa_enrollment(
                identity, body.code, token=token, client=_client(request)
            )
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        if codes is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
        return MfaConfirmResponse(recovery_codes=codes)

    @app.delete("/me/mfa", response_model=SimpleMessage)
    async def disable_my_mfa(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up()),
    ) -> SimpleMessage:
        """Self-service: turn off the caller's TOTP MFA. Step-up gated — you prove your current factor
        (a TOTP or recovery code via ``/auth/mfa-verify``) and a recent password."""
        await service.disable_mfa(identity, client=_client(request))
        return SimpleMessage(detail="MFA disabled")

    # --- self-service session inventory (WP-10, ASVS 7.5.2/7.4.5) -------------

    @app.get("/me/sessions", response_model=SessionList)
    async def my_sessions(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require()),
    ) -> SessionList:
        current = hash_token(bearer_token(request) or "")
        sessions = await service.list_sessions(identity.user_id)
        return SessionList(sessions=[_session_info(s, current) for s in sessions])

    @app.get("/me/security-events", response_model=SecurityEventsList)
    async def my_security_events(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require()),
        limit: int = Query(100, ge=1, le=1000),
    ) -> SecurityEventsList:
        """The caller's own security-event history (WP-L3-05, ASVS 6.3.5/6.3.7): the audited ``auth.*``
        actions on their account (sign-ins, lockouts, password changes), most-recent-first. The
        out-of-band email push complements this for events the user should learn of without logging in
        (and for admin-initiated changes, whose audit actor is the admin)."""
        rows = await service.security_events_for(identity.username, limit=limit)
        return SecurityEventsList(events=[SecurityEventInfo(**r) for r in rows])

    @app.delete("/me/sessions/{session_id}", response_model=SimpleMessage)
    async def revoke_my_session(
        session_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require()),
    ) -> SimpleMessage:
        # Ownership-checked in the service: a 404 (not 403) avoids confirming another user's session id.
        if not await service.revoke_own_session(identity, session_id, actor=identity.username):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such session")
        return SimpleMessage(detail="session revoked")

    @app.delete("/me/sessions", response_model=SimpleMessage)
    async def revoke_my_other_sessions(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require()),
    ) -> SimpleMessage:
        current = hash_token(bearer_token(request) or "")
        revoked = await service.revoke_other_sessions(identity, current, actor=identity.username)
        return SimpleMessage(detail=f"signed out {revoked} other session(s)")

    # --- roles + user administration -----------------------------------------

    @app.get("/roles", response_model=list[RoleInfo])
    async def list_roles(
        service: AuthService = Depends(_service),
        _: Identity = Depends(require(Permission.USERS_READ)),
    ) -> list[RoleInfo]:
        out: list[RoleInfo] = []
        for role in Role:
            label, description = ROLE_METADATA[role]
            out.append(
                RoleInfo(
                    id=role.value,
                    display_name=label,
                    description=description,
                    permissions=sorted(p.value for p in BUILTIN_ROLE_PERMISSIONS[role]),
                    builtin=True,
                )
            )
        # Custom (admin-defined) roles overlay the built-ins (ADR 0045) — list them alongside so the
        # admin UI renders the full assignable set. Permissions are defensively decoded by the service.
        for custom in await service.list_custom_roles():
            out.append(
                RoleInfo(
                    id=custom.id,
                    display_name=custom.display_name,
                    description=custom.description,
                    permissions=sorted(p.value for p in custom.permissions),
                    builtin=False,
                )
            )
        return out

    @app.get("/roles/custom", response_model=list[CustomRoleInfo])
    async def list_custom_roles(
        service: AuthService = Depends(_service),
        _: Identity = Depends(require(Permission.USERS_READ)),
    ) -> list[CustomRoleInfo]:
        return [
            CustomRoleInfo(
                id=r.id,
                display_name=r.display_name,
                description=r.description,
                permissions=sorted(p.value for p in r.permissions),
            )
            for r in await service.list_custom_roles()
        ]

    @app.post("/roles/custom", response_model=CustomRoleInfo, status_code=status.HTTP_201_CREATED)
    async def create_custom_role(
        body: CustomRoleRequest,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> CustomRoleInfo:
        try:
            role = await service.create_custom_role(
                display_name=body.display_name,
                description=body.description,
                permissions=body.permissions,
                actor=identity.username,
            )
        except CustomRoleError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        return CustomRoleInfo(
            id=role.id,
            display_name=role.display_name,
            description=role.description,
            permissions=sorted(p.value for p in role.permissions),
        )

    @app.put("/roles/custom/{role_id}", response_model=CustomRoleInfo)
    async def update_custom_role(
        role_id: str,
        body: CustomRoleRequest,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> CustomRoleInfo:
        try:
            role = await service.update_custom_role(
                role_id,
                display_name=body.display_name,
                description=body.description,
                permissions=body.permissions,
                actor=identity.username,
            )
        except CustomRoleError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        return CustomRoleInfo(
            id=role.id,
            display_name=role.display_name,
            description=role.description,
            permissions=sorted(p.value for p in role.permissions),
        )

    @app.delete("/roles/custom/{role_id}", response_model=SimpleMessage)
    async def delete_custom_role(
        role_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        try:
            await service.delete_custom_role(role_id, actor=identity.username)
        except ValueError as exc:
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
        return SimpleMessage(detail="custom role deleted")

    @app.get("/users", response_model=list[UserSummary])
    async def list_users(
        service: AuthService = Depends(_service),
        _: Identity = Depends(require(Permission.USERS_READ)),
    ) -> list[UserSummary]:
        summaries: list[UserSummary] = []
        for user in await service.store.list_users():
            role_ids = await service.store.get_user_role_ids(user.id)
            summaries.append(_user_summary(user, role_ids))
        return summaries

    @app.post("/users", response_model=UserSummary, status_code=status.HTTP_201_CREATED)
    async def create_user(
        body: UserCreateRequest,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> UserSummary:
        await _validate_roles(service, body.roles)
        if await service.store.get_user_by_username(body.username) is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
        violations = service.password_violations(body.password, username=body.username)
        if violations:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "password must " + "; ".join(violations)
            )
        user_id = await service.create_local_user(
            username=body.username,
            password=body.password,
            display_name=body.display_name,
            email=body.email,
            roles=body.roles,
            actor=identity.username,
        )
        user = await service.store.get_user(user_id)
        assert user is not None
        return _user_summary(user, sorted(body.roles))

    @app.patch("/users/{user_id}", response_model=SimpleMessage)
    async def update_user(
        user_id: str,
        body: UserUpdateRequest,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        current = await service.store.get_user(user_id)
        if current is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        if body.disabled and user_id == identity.user_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot disable your own account")
        # SEC-015: disabling is a lock-out path equivalent to stripping the admin role — apply the
        # same last-admin guard the roles endpoint enforces, so an admin can't disable every other
        # admin and erase the dual-admin safeguard. (is_last_enabled_admin only fires when the target
        # IS the sole enabled admin, so this no-ops for non-admins and non-last admins.)
        if (
            "disabled" in body.model_fields_set
            and body.disabled
            and await service.is_last_enabled_admin(user_id)
        ):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "cannot disable the last administrator"
            )
        # PATCH is partial: only fields actually present in the body should change. Omitted
        # display_name/email keep their current value (the store sets them unconditionally, so a
        # partial PATCH would otherwise NULL them); an explicit null still clears (review M-20).
        supplied = body.model_fields_set
        await service.update_user(
            user_id,
            display_name=body.display_name if "display_name" in supplied else current.display_name,
            email=body.email if "email" in supplied else current.email,
            disabled=body.disabled if "disabled" in supplied else None,
            actor=identity.username,
        )
        return SimpleMessage(detail="updated")

    @app.delete("/users/{user_id}", response_model=SimpleMessage)
    async def delete_user(
        user_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        if user_id == identity.user_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot delete your own account")
        if await service.store.get_user(user_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        # SEC-015: deleting the last enabled admin is the same lock-out path — guard it for symmetry
        # with the roles/disable endpoints (no-ops unless the target is the sole enabled admin).
        if await service.is_last_enabled_admin(user_id):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot delete the last administrator")
        await service.delete_user(user_id, actor=identity.username)
        return SimpleMessage(detail="deleted")

    @app.delete("/users/{user_id}/sessions", response_model=SimpleMessage)
    async def admin_revoke_user_sessions(
        user_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        """Force-sign-out: revoke all of a user's sessions (e.g. after a compromise or offboarding)."""
        if await service.store.get_user(user_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        revoked = await service.revoke_sessions_for_user(user_id, actor=identity.username)
        return SimpleMessage(detail=f"revoked {revoked} session(s)")

    @app.put("/users/{user_id}/roles", response_model=SimpleMessage)
    async def set_user_roles(
        user_id: str,
        body: RolesUpdateRequest,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        await _validate_roles(service, body.roles)
        user = await service.store.get_user(user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        if user.auth_provider == AuthProvider.AD.value:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "AD users get roles from the AD-group map"
            )
        if Role.ADMINISTRATOR.value not in body.roles and await service.is_last_enabled_admin(
            user_id
        ):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot remove the last administrator")
        await service.set_roles(user_id, body.roles, actor=identity.username)
        return SimpleMessage(detail="roles updated")

    @app.post("/users/{user_id}/reset-password", response_model=PasswordResetResponse)
    async def reset_user_password(
        user_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> PasswordResetResponse:
        """Admin password reset (ASVS 6.4.6 / WP-L3-12): issue a one-time, must-change credential the
        administrator never keeps. Returned **once** for out-of-band delivery; the affected user is also
        notified by email. Use change-password for your own account."""
        if user_id == identity.user_id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "use change-password for your own account"
            )
        try:
            temp = await service.admin_reset_password(user_id, actor=identity.username)
        except ValueError as exc:
            detail = str(exc)
            code = (
                status.HTTP_404_NOT_FOUND
                if detail == "no such user"
                else status.HTTP_400_BAD_REQUEST
            )
            raise HTTPException(code, detail) from exc
        return PasswordResetResponse(temp_password=temp)

    @app.post("/users/{user_id}/reset-mfa", response_model=SimpleMessage)
    async def reset_user_mfa(
        user_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        """Admin MFA reset (lost authenticator + no recovery codes): clear the user's TOTP enrollment
        and revoke their sessions so they re-enroll. The acting admin is itself step-up + MFA gated."""
        try:
            await service.admin_reset_mfa(user_id, actor=identity.username)
        except ValueError as exc:
            detail = str(exc)
            code = (
                status.HTTP_404_NOT_FOUND
                if detail == "no such user"
                else status.HTTP_400_BAD_REQUEST
            )
            raise HTTPException(code, detail) from exc
        return SimpleMessage(detail="MFA reset")

    @app.get("/users/{user_id}/channel-scope", response_model=ChannelScope)
    async def get_channel_scope(
        user_id: str,
        service: AuthService = Depends(_service),
        _: Identity = Depends(require(Permission.USERS_MANAGE)),
    ) -> ChannelScope:
        user = await service.store.get_user(user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        return ChannelScope(channels=_parse_channel_scope(user.channel_scope))

    @app.put("/users/{user_id}/channel-scope", response_model=SimpleMessage)
    async def set_channel_scope(
        user_id: str,
        body: ChannelScope,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        """Set a user's per-channel RBAC scope (``channels: null`` = all). Administrators are always
        all-channels, so a scope set on one has no effect."""
        if await service.store.get_user(user_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        await service.set_channel_scope(user_id, body.channels, actor=identity.username)
        return SimpleMessage(detail="channel scope updated")

    # --- AD group -> role mapping --------------------------------------------

    @app.get("/ad-group-map", response_model=AdGroupMap)
    async def get_ad_group_map(
        service: AuthService = Depends(_service),
        _: Identity = Depends(require(Permission.USERS_MANAGE)),
    ) -> AdGroupMap:
        rows = await service.store.list_ad_group_role_map()
        return AdGroupMap(
            entries=[AdGroupMapEntry(ad_group=r["ad_group"], role=r["role_id"]) for r in rows]
        )

    @app.put("/ad-group-map", response_model=SimpleMessage)
    async def set_ad_group_map(
        body: AdGroupMap,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        await _validate_roles(service, [e.role for e in body.entries])
        await service.set_ad_group_map(
            [(e.ad_group, e.role) for e in body.entries], actor=identity.username
        )
        return SimpleMessage(detail="ad-group map updated")

    @app.get("/ad-group-scope-map", response_model=AdGroupScopeMap)
    async def get_ad_group_scope_map(
        service: AuthService = Depends(_service),
        _: Identity = Depends(require(Permission.USERS_MANAGE)),
    ) -> AdGroupScopeMap:
        rows = await service.store.list_ad_group_scope_map()
        return AdGroupScopeMap(
            entries=[AdGroupScopeEntry(ad_group=r["ad_group"], channel=r["channel"]) for r in rows]
        )

    @app.put("/ad-group-scope-map", response_model=SimpleMessage)
    async def set_ad_group_scope_map(
        body: AdGroupScopeMap,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_step_up(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        await service.set_ad_group_scope_map(
            [(e.ad_group, e.channel) for e in body.entries], actor=identity.username
        )
        return SimpleMessage(detail="ad-group scope map updated")

    # --- audit ---------------------------------------------------------------

    @app.get("/audit", response_model=AuditList)
    async def list_audit(
        service: AuthService = Depends(_service),
        _: Identity = Depends(require(Permission.AUDIT_READ)),
        limit: int = Query(100, ge=1, le=1000),
    ) -> AuditList:
        rows = await service.store.list_audit(limit=limit)
        return AuditList(
            entries=[
                AuditEntry(
                    ts=r["ts"],
                    actor=r["actor"],
                    action=r["action"],
                    channel_id=r["channel_id"],
                    detail=r["detail"],
                )
                for r in rows
            ]
        )

    # --- /ui admin surface (L4a, ADR 0065; #75 phase 4) ------------------------
    # Registered ONLY when [api].serve_ui is on. These routes are CLIENTS of the nested JSON handlers
    # above (called directly, skipping their Depends gates) — so each /ui route re-asserts the EXACT
    # permission its handler uses via require_ui/require_ui_step_up, adds assert_same_origin CSRF on
    # every POST, and passes every handler param explicitly (a directly-called handler never resolves
    # its Query()/Body() defaults). Every admin write below is require_step_up(USERS_MANAGE) in the
    # JSON API, so the /ui analogues all use require_ui_step_up(USERS_MANAGE):
    #  * body-less, URL-complete actions (delete, reset-password, reset-mfa, revoke-sessions, custom-
    #    role delete) register as auto_retry — the re-auth flow may re-POST them.
    #  * body-carrying actions (create user, profile/roles/scope, custom roles, AD maps) can NOT be
    #    re-POSTed; their FORM PAGES register as `unlock` targets instead (the L0c primitive), and the
    #    POSTs map their stale-step-up redirect to that form via reauth_next — so no body (and no
    #    password) ever crosses /ui/reauth.
    if serve_ui:
        # GUARDED, lazy import (Option B Phase 0): the web console is an optional package required only
        # when serve_ui is on. add_auth_routes runs UNCONDITIONALLY from create_app, so this module must
        # import with the console absent; a missing install fails LOUD at startup here. (The absent path
        # is exercised by tests/test_webconsole_absent.py, which shadows the import.)
        try:
            from messagefoundry.api import webui
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "serve_ui requires the web console (messagefoundry.api.webui / the "
                "messagefoundry-webconsole package) which could not be imported"
            ) from exc

        webui.register_ui_action(
            r"^/ui/users/new$", Permission.USERS_MANAGE, auto_retry=False, unlock=True
        )
        webui.register_ui_action(
            r"^/ui/users/[^/?#]+$", Permission.USERS_MANAGE, auto_retry=False, unlock=True
        )
        webui.register_ui_action(
            r"^/ui/users/[^/?#]+/(reset-password|reset-mfa|revoke-sessions|delete)$",
            Permission.USERS_MANAGE,
        )
        webui.register_ui_action(
            r"^/ui/roles/new$", Permission.USERS_MANAGE, auto_retry=False, unlock=True
        )
        webui.register_ui_action(
            r"^/ui/roles/[^/?#]+/edit$", Permission.USERS_MANAGE, auto_retry=False, unlock=True
        )
        webui.register_ui_action(r"^/ui/roles/custom/[^/?#]+/delete$", Permission.USERS_MANAGE)
        webui.register_ui_action(
            r"^/ui/ad-groups$", Permission.USERS_MANAGE, auto_retry=False, unlock=True
        )

        # Custom roles may grant any catalog permission EXCEPT the carved-out escalation primitives
        # (ADR 0045 D1) — don't offer what the service will refuse.
        _role_catalog = sorted(
            p.value for p in Permission if p not in CUSTOM_ROLE_FORBIDDEN_PERMISSIONS
        )

        async def _form_pairs(request: Request) -> list[tuple[str, str]]:
            # stdlib urlencoded-form parsing (no python-multipart dep), like /ui/login. Pair order is
            # preserved so repeated fields (checkboxes, map rows) can be collected positionally.
            # keep_blank_values=True is LOAD-BEARING for the paired-row AD-map forms: a browser posts
            # blank fields (ad_group=, role=) for empty/half-filled rows, and dropping them (the
            # parse_qsl default) shifts the positional pairing so a role from one row silently binds
            # to a group from another — an RBAC mis-grant. With blanks kept, every row contributes
            # exactly one value per field and the row-wise "if g and r" filters drop incomplete rows
            # as intended. Scalar readers are unaffected (dict(pairs).get(k, "") yields "" either way;
            # checkbox values are never blank).
            return parse_qsl(
                (await request.body()).decode("utf-8", "replace"), keep_blank_values=True
            )

        async def _user_detail(
            user_id: str,
            service: AuthService,
            identity: Identity,
            *,
            error: str | None = None,
            status_code: int = 200,
        ) -> HTMLResponse:
            user = await service.store.get_user(user_id)
            if user is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
            role_ids = await service.store.get_user_role_ids(user.id)
            all_roles = await list_roles(service=service, _=identity)
            return HTMLResponse(
                webui.pages.user_detail_page(_user_summary(user, role_ids), all_roles, error=error),
                status_code=status_code,
            )

        # --- users: pages ---------------------------------------------------

        @app.get("/ui/users", response_class=HTMLResponse)
        async def ui_users(
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui(Permission.USERS_READ)),
        ) -> HTMLResponse:
            users = await list_users(service=service, _=identity)
            return HTMLResponse(webui.pages.users_page(users))

        # Declared BEFORE /ui/users/{user_id} so the literal segment wins the route match.
        @app.get("/ui/users/new", response_class=HTMLResponse)
        async def ui_user_new(
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_step_up(Permission.USERS_MANAGE)),
        ) -> HTMLResponse:
            roles = await list_roles(service=service, _=identity)
            return HTMLResponse(webui.pages.user_new_page(roles))

        @app.get("/ui/users/{user_id}", response_class=HTMLResponse)
        async def ui_user_detail(
            user_id: str,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_step_up(Permission.USERS_MANAGE)),
        ) -> HTMLResponse:
            return await _user_detail(user_id, service, identity)

        # --- users: actions ---------------------------------------------------

        @app.post("/ui/users")
        async def ui_user_create(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(
                webui.require_ui_step_up(
                    Permission.USERS_MANAGE, reauth_next=lambda _r: "/ui/users/new"
                )
            ),
        ) -> Response:
            webui.assert_same_origin(request)
            pairs = await _form_pairs(request)
            form = dict(pairs)
            roles = [v for k, v in pairs if k == "roles"]
            try:
                body = UserCreateRequest(
                    username=form.get("username", "").strip(),
                    password=form.get("password", ""),
                    display_name=form.get("display_name", "").strip() or None,
                    email=form.get("email", "").strip() or None,
                    roles=roles,
                )
                created = await create_user(body=body, service=service, identity=identity)
            except (ValidationError, HTTPException) as exc:
                detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
                all_roles = await list_roles(service=service, _=identity)
                # Re-render preserving the NON-SECRET fields only — the password is never echoed.
                return HTMLResponse(
                    webui.pages.user_new_page(
                        all_roles,
                        error=detail,
                        username=form.get("username", "").strip(),
                        display_name=form.get("display_name", "").strip(),
                        email=form.get("email", "").strip(),
                        checked=roles,
                    ),
                    status_code=400,
                )
            return RedirectResponse(f"/ui/users/{created.id}", status_code=303)

        @app.post("/ui/users/{user_id}/update")
        async def ui_user_update(
            user_id: str,
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(
                webui.require_ui_step_up(
                    Permission.USERS_MANAGE,
                    reauth_next=lambda r: r.url.path.removesuffix("/update"),
                )
            ),
        ) -> Response:
            webui.assert_same_origin(request)
            form = dict(await _form_pairs(request))
            try:
                # An HTML form always posts the full profile picture, so every field is set explicitly
                # ("" clears to None; an absent checkbox means enabled) — the PATCH partial semantics of
                # the JSON handler don't apply to a form submit.
                body = UserUpdateRequest(
                    display_name=form.get("display_name", "").strip() or None,
                    email=form.get("email", "").strip() or None,
                    disabled="disabled" in form,
                )
                await update_user(user_id, body=body, service=service, identity=identity)
            except (ValidationError, HTTPException) as exc:
                if isinstance(exc, HTTPException) and exc.status_code == status.HTTP_404_NOT_FOUND:
                    raise
                detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
                return await _user_detail(user_id, service, identity, error=detail, status_code=400)
            return RedirectResponse(f"/ui/users/{user_id}", status_code=303)

        @app.post("/ui/users/{user_id}/roles")
        async def ui_user_roles(
            user_id: str,
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(
                webui.require_ui_step_up(
                    Permission.USERS_MANAGE,
                    reauth_next=lambda r: r.url.path.removesuffix("/roles"),
                )
            ),
        ) -> Response:
            webui.assert_same_origin(request)
            pairs = await _form_pairs(request)
            roles = [v for k, v in pairs if k == "roles"]
            try:
                body = RolesUpdateRequest(roles=roles)
                await set_user_roles(user_id, body=body, service=service, identity=identity)
            except (ValidationError, HTTPException) as exc:
                if isinstance(exc, HTTPException) and exc.status_code == status.HTTP_404_NOT_FOUND:
                    raise
                detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
                return await _user_detail(user_id, service, identity, error=detail, status_code=400)
            return RedirectResponse(f"/ui/users/{user_id}", status_code=303)

        @app.post("/ui/users/{user_id}/channel-scope")
        async def ui_user_channel_scope(
            user_id: str,
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(
                webui.require_ui_step_up(
                    Permission.USERS_MANAGE,
                    reauth_next=lambda r: r.url.path.removesuffix("/channel-scope"),
                )
            ),
        ) -> Response:
            webui.assert_same_origin(request)
            form = dict(await _form_pairs(request))
            names = [ln.strip() for ln in form.get("channels", "").splitlines() if ln.strip()]
            # The tri-state scope_mode keeps deny-all ([]) distinguishable from all-channels (None) —
            # an empty textarea alone must never widen a stored deny-all scope (review PR2-M3).
            # Absent (a pre-tri-state cached form) defaults to "list"; any OTHER value is a
            # hand-crafted post — refused rather than guessed (deny-by-default).
            mode = form.get("scope_mode", "list")
            if mode not in ("all", "list", "none"):
                return await _user_detail(
                    user_id, service, identity, error="unknown scope mode", status_code=400
                )
            if mode == "list" and not names:
                return await _user_detail(
                    user_id,
                    service,
                    identity,
                    error=(
                        "list at least one connection, or choose the all-channels / "
                        "no-channels scope instead"
                    ),
                    status_code=400,
                )
            channels = None if mode == "all" else ([] if mode == "none" else names)
            try:
                body = ChannelScope(channels=channels)
                await set_channel_scope(user_id, body=body, service=service, identity=identity)
            except (ValidationError, HTTPException) as exc:
                if isinstance(exc, HTTPException) and exc.status_code == status.HTTP_404_NOT_FOUND:
                    raise
                detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
                return await _user_detail(user_id, service, identity, error=detail, status_code=400)
            return RedirectResponse(f"/ui/users/{user_id}", status_code=303)

        @app.post("/ui/users/{user_id}/reset-password")
        async def ui_user_reset_password(
            user_id: str,
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_step_up(Permission.USERS_MANAGE)),
        ) -> Response:
            webui.assert_same_origin(request)
            try:
                result = await reset_user_password(user_id, service=service, identity=identity)
            except HTTPException as exc:
                if exc.status_code == status.HTTP_404_NOT_FOUND:
                    raise
                return await _user_detail(
                    user_id, service, identity, error=str(exc.detail), status_code=400
                )
            user = await service.store.get_user(user_id)
            username = user.username if user is not None else user_id
            # The one-time credential is rendered ONCE for out-of-band delivery — never logged/stored.
            return HTMLResponse(webui.pages.temp_password_page(username, result.temp_password))

        @app.post("/ui/users/{user_id}/reset-mfa")
        async def ui_user_reset_mfa(
            user_id: str,
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_step_up(Permission.USERS_MANAGE)),
        ) -> Response:
            webui.assert_same_origin(request)
            try:
                await reset_user_mfa(user_id, service=service, identity=identity)
            except HTTPException as exc:
                if exc.status_code == status.HTTP_404_NOT_FOUND:
                    raise
                return await _user_detail(
                    user_id, service, identity, error=str(exc.detail), status_code=400
                )
            return RedirectResponse(f"/ui/users/{user_id}", status_code=303)

        @app.post("/ui/users/{user_id}/revoke-sessions")
        async def ui_user_revoke_sessions(
            user_id: str,
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_step_up(Permission.USERS_MANAGE)),
        ) -> Response:
            webui.assert_same_origin(request)
            await admin_revoke_user_sessions(user_id, service=service, identity=identity)
            return RedirectResponse(f"/ui/users/{user_id}", status_code=303)

        @app.post("/ui/users/{user_id}/delete")
        async def ui_user_delete(
            user_id: str,
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_step_up(Permission.USERS_MANAGE)),
        ) -> Response:
            webui.assert_same_origin(request)
            try:
                await delete_user(user_id, service=service, identity=identity)
            except HTTPException as exc:
                if exc.status_code == status.HTTP_404_NOT_FOUND:
                    raise
                return await _user_detail(
                    user_id, service, identity, error=str(exc.detail), status_code=400
                )
            return RedirectResponse("/ui/users", status_code=303)

        # --- roles ------------------------------------------------------------

        @app.get("/ui/roles", response_class=HTMLResponse)
        async def ui_roles(
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui(Permission.USERS_READ)),
        ) -> HTMLResponse:
            roles = await list_roles(service=service, _=identity)
            return HTMLResponse(webui.pages.roles_page(roles))

        @app.get("/ui/roles/new", response_class=HTMLResponse)
        async def ui_role_new(
            _identity: Identity = Depends(webui.require_ui_step_up(Permission.USERS_MANAGE)),
        ) -> HTMLResponse:
            return HTMLResponse(webui.pages.role_form_page(_role_catalog))

        @app.get("/ui/roles/{role_id}/edit", response_class=HTMLResponse)
        async def ui_role_edit(
            role_id: str,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_step_up(Permission.USERS_MANAGE)),
        ) -> HTMLResponse:
            # Only CUSTOM roles are editable; a built-in (or unknown) id is a 404, mirroring the JSON API.
            for info in await list_custom_roles(service=service, _=identity):
                if info.id == role_id:
                    return HTMLResponse(webui.pages.role_form_page(_role_catalog, role=info))
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such custom role")

        @app.post("/ui/roles/custom")
        async def ui_role_create(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(
                webui.require_ui_step_up(
                    Permission.USERS_MANAGE, reauth_next=lambda _r: "/ui/roles/new"
                )
            ),
        ) -> Response:
            webui.assert_same_origin(request)
            pairs = await _form_pairs(request)
            form = dict(pairs)
            perms = [v for k, v in pairs if k == "permissions"]
            try:
                body = CustomRoleRequest(
                    display_name=form.get("display_name", "").strip(),
                    description=form.get("description", "").strip() or None,
                    permissions=perms,
                )
                await create_custom_role(body=body, service=service, identity=identity)
            except (ValidationError, HTTPException) as exc:
                detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
                return HTMLResponse(
                    webui.pages.role_form_page(
                        _role_catalog,
                        error=detail,
                        display_name=form.get("display_name", "").strip(),
                        description=form.get("description", "").strip(),
                        checked=perms,
                    ),
                    status_code=400,
                )
            return RedirectResponse("/ui/roles", status_code=303)

        @app.post("/ui/roles/custom/{role_id}/update")
        async def ui_role_update(
            role_id: str,
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(
                webui.require_ui_step_up(
                    Permission.USERS_MANAGE,
                    reauth_next=lambda r: f"/ui/roles/{r.path_params['role_id']}/edit",
                )
            ),
        ) -> Response:
            webui.assert_same_origin(request)
            pairs = await _form_pairs(request)
            form = dict(pairs)
            perms = [v for k, v in pairs if k == "permissions"]
            try:
                body = CustomRoleRequest(
                    display_name=form.get("display_name", "").strip(),
                    description=form.get("description", "").strip() or None,
                    permissions=perms,
                )
                await update_custom_role(role_id, body=body, service=service, identity=identity)
            except (ValidationError, HTTPException) as exc:
                if isinstance(exc, HTTPException) and exc.status_code == status.HTTP_404_NOT_FOUND:
                    raise
                detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
                current = CustomRoleInfo(
                    id=role_id,
                    display_name=form.get("display_name", "").strip(),
                    description=form.get("description", "").strip() or None,
                    permissions=perms,
                )
                return HTMLResponse(
                    webui.pages.role_form_page(_role_catalog, role=current, error=detail),
                    status_code=400,
                )
            return RedirectResponse("/ui/roles", status_code=303)

        @app.post("/ui/roles/custom/{role_id}/delete")
        async def ui_role_delete(
            role_id: str,
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_step_up(Permission.USERS_MANAGE)),
        ) -> Response:
            webui.assert_same_origin(request)
            await delete_custom_role(role_id, service=service, identity=identity)
            return RedirectResponse("/ui/roles", status_code=303)

        # --- AD group mappings --------------------------------------------------

        async def _ad_groups_response(
            service: AuthService,
            identity: Identity,
            *,
            error: str | None = None,
            status_code: int = 200,
        ) -> HTMLResponse:
            gmap = await get_ad_group_map(service=service, _=identity)
            smap = await get_ad_group_scope_map(service=service, _=identity)
            roles = await list_roles(service=service, _=identity)
            return HTMLResponse(
                webui.pages.ad_groups_page(gmap.entries, smap.entries, roles, error=error),
                status_code=status_code,
            )

        @app.get("/ui/ad-groups", response_class=HTMLResponse)
        async def ui_ad_groups(
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_step_up(Permission.USERS_MANAGE)),
        ) -> HTMLResponse:
            return await _ad_groups_response(service, identity)

        @app.post("/ui/ad-groups/map")
        async def ui_ad_group_map(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(
                webui.require_ui_step_up(
                    Permission.USERS_MANAGE, reauth_next=lambda _r: "/ui/ad-groups"
                )
            ),
        ) -> Response:
            webui.assert_same_origin(request)
            pairs = await _form_pairs(request)
            # Paired row inputs, zipped positionally (browsers submit fields in DOM order); a row with
            # an empty group or unselected role is a blank filler row — dropped. The PUT-equivalent JSON
            # handler replaces the whole map, so the surviving rows ARE the new map.
            groups = [v.strip() for k, v in pairs if k == "ad_group"]
            role_ids = [v.strip() for k, v in pairs if k == "role"]
            try:
                body = AdGroupMap(
                    entries=[
                        AdGroupMapEntry(ad_group=g, role=r)
                        for g, r in zip(groups, role_ids, strict=True)
                        if g and r
                    ]
                )
                await set_ad_group_map(body=body, service=service, identity=identity)
            except (ValidationError, ValueError, HTTPException) as exc:
                detail = str(exc.detail) if isinstance(exc, HTTPException) else "invalid input"
                return await _ad_groups_response(service, identity, error=detail, status_code=400)
            return RedirectResponse("/ui/ad-groups", status_code=303)

        @app.post("/ui/ad-groups/scope-map")
        async def ui_ad_group_scope_map(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(
                webui.require_ui_step_up(
                    Permission.USERS_MANAGE, reauth_next=lambda _r: "/ui/ad-groups"
                )
            ),
        ) -> Response:
            webui.assert_same_origin(request)
            pairs = await _form_pairs(request)
            groups = [v.strip() for k, v in pairs if k == "ad_group"]
            channels = [v.strip() for k, v in pairs if k == "channel"]
            try:
                body = AdGroupScopeMap(
                    entries=[
                        AdGroupScopeEntry(ad_group=g, channel=c)
                        for g, c in zip(groups, channels, strict=True)
                        if g and c
                    ]
                )
                await set_ad_group_scope_map(body=body, service=service, identity=identity)
            except (ValidationError, ValueError, HTTPException) as exc:
                detail = str(exc.detail) if isinstance(exc, HTTPException) else "invalid input"
                return await _ad_groups_response(service, identity, error=detail, status_code=400)
            return RedirectResponse("/ui/ad-groups", status_code=303)

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
        webui.register_ui_action(r"^/ui/account/mfa/enroll$", None, step_up=False)
        webui.register_ui_action(r"^/ui/account/mfa/disable$", None)
        webui.register_ui_action(
            r"^/ui/account/mfa/confirm$", None, step_up=False, auto_retry=False, unlock=True
        )

        # Post-redirect notices (allow-listed codes only — never reflected text).
        _ACCOUNT_NOTICES = {
            "mfa_off": "MFA disabled.",
            "enroll_first": (
                "That action requires MFA — enroll an authenticator (TOTP app or passkey) "
                "to continue."
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
            mfa = await my_mfa(service=service, identity=identity)
            # L5a passkey rows (plain mappings — the pages module never touches the store); the
            # "usable" flag compares each credential's mint-time rp_id to the CURRENT RP identity
            # (an origin migration renders old credentials visibly unusable, ADR 0068 §7).
            rp = webui.webauthn_rp(request)
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
                wa_notice = webui.WEBAUTHN_EXTRA_MISSING_NOTICE
            elif rp is None:
                wa_notice = webui.WEBAUTHN_RP_MISSING_NOTICE
            return HTMLResponse(
                webui.pages.account_page(
                    _current_user(identity),
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
            identity: Identity = Depends(webui.require_ui()),
            m: str | None = Query(None, max_length=32),
        ) -> HTMLResponse:
            return await _account_response(
                service, identity, request, notice=_ACCOUNT_NOTICES.get(m or "")
            )

        @app.get("/ui/account/password", response_class=HTMLResponse)
        async def ui_account_password_form(
            identity: Identity = Depends(webui.require_ui(allow_must_change=True)),
        ) -> HTMLResponse:
            # `forced` comes from the SERVER-side flag, never a query param (unspoofable).
            return HTMLResponse(webui.pages.password_page(forced=identity.must_change_password))

        @app.post("/ui/account/password")
        async def ui_account_password(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui(allow_must_change=True)),
        ) -> Response:
            webui.assert_same_origin(request)
            form = dict(await _form_pairs(request))
            forced = identity.must_change_password

            def _retry(message: str, code: int = 400) -> HTMLResponse:
                # Passwords are NEVER echoed back — the re-rendered form is always empty.
                return HTMLResponse(
                    webui.pages.password_page(forced=forced, error=message), status_code=code
                )

            if form.get("new_password", "") != form.get("new_password2", ""):
                return _retry("the new passwords do not match")
            try:
                body = PasswordChangeRequest(
                    current_password=form.get("current_password", ""),
                    new_password=form.get("new_password", ""),
                )
                await change_password(
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
            webui.clear_session_cookie(resp)
            return resp

        @app.post("/ui/account/mfa/enroll")
        async def ui_mfa_enroll(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_reauth_only()),
        ) -> Response:
            webui.assert_same_origin(request)
            try:
                enroll = await enroll_mfa(service=service, identity=identity)
            except HTTPException as exc:
                # AD account / already enrolled — surface on the account page.
                return await _account_response(
                    service, identity, request, error=str(exc.detail), status_code=400
                )
            # The staged secret renders ONCE (with the confirm form); it is inert until confirmed.
            return HTMLResponse(webui.pages.mfa_enroll_page(enroll.secret, enroll.otpauth_uri))

        @app.get("/ui/account/mfa/confirm", response_class=HTMLResponse)
        async def ui_mfa_confirm_form(
            _identity: Identity = Depends(webui.require_ui_reauth_only()),
        ) -> HTMLResponse:
            # The unlock re-entry point: the secret is already staged server-side (and in the user's
            # authenticator), so this form only collects the code — the secret is never re-shown.
            return HTMLResponse(webui.pages.mfa_confirm_page())

        @app.post("/ui/account/mfa/verify")
        async def ui_mfa_verify(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(
                webui.require_ui_reauth_only(reauth_next=lambda _r: "/ui/account/mfa/confirm")
            ),
        ) -> Response:
            webui.assert_same_origin(request)
            # The JSON confirm_mfa handler reads the HEADER bearer token (absent on a cookie request),
            # so this route drives the SERVICE directly with the cookie session token — the same
            # cookie-vs-header split ui_login/ui_reauth already handle. Semantics match the JSON
            # handler: rate-limited like login; wrong code changes nothing.
            client = _client(request)
            if not service.allow_login_attempt(client):
                raise _rate_limited(request, "mfa-confirm")
            token = request.cookies.get(webui.COOKIE_NAME)
            if not token:  # pragma: no cover - require_ui already authenticated this cookie
                return RedirectResponse("/ui/login", status_code=303)
            form = dict(await _form_pairs(request))
            code = form.get("code", "").strip()
            try:
                codes = await service.confirm_mfa_enrollment(
                    identity, code, token=token, client=client
                )
            except ValueError as exc:
                # No enrollment staged / not a local account — back to the account page.
                return await _account_response(
                    service, identity, request, error=str(exc), status_code=400
                )
            if codes is None:
                return HTMLResponse(
                    webui.pages.mfa_confirm_page(error="Invalid code."), status_code=400
                )
            # Activated: the recovery codes render ONCE — never re-fetchable.
            return HTMLResponse(webui.pages.mfa_recovery_page(codes))

        @app.post("/ui/account/mfa/disable")
        async def ui_mfa_disable(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_step_up()),
        ) -> Response:
            webui.assert_same_origin(request)
            await disable_my_mfa(request=request, service=service, identity=identity)
            return RedirectResponse("/ui/account?m=mfa_off", status_code=303)

        # --- L1c: audit trail + self-service security events (read-only) ------------
        # Both reuse the nested JSON handlers directly; each re-asserts the SAME gate its handler uses
        # (audit:read for the full trail; a valid session for one's own events). No step-up, no writes.

        @app.get("/ui/audit", response_class=HTMLResponse)
        async def ui_audit(
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui(Permission.AUDIT_READ)),
        ) -> HTMLResponse:
            data = await list_audit(service=service, _=identity, limit=200)
            return HTMLResponse(webui.pages.audit_log(data))

        @app.get("/ui/security-events", response_class=HTMLResponse)
        async def ui_security_events(
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui()),
        ) -> HTMLResponse:
            data = await my_security_events(service=service, identity=identity, limit=200)
            return HTMLResponse(webui.pages.security_events(data))

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
            identity: Identity = Depends(webui.require_ui()),
            m: str | None = Query(None, max_length=32),
        ) -> HTMLResponse:
            current = hash_token(request.cookies.get(webui.COOKIE_NAME) or "")
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
            return HTMLResponse(
                webui.pages.sessions_page(rows, notice=_SESSION_NOTICES.get(m or ""))
            )

        @app.post("/ui/account/sessions/{session_id}/revoke")
        async def ui_revoke_session(
            session_id: str,
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui()),
        ) -> Response:
            webui.assert_same_origin(request)
            # Ownership-checked in the service; an unknown/foreign id is a silent no-op (never
            # confirms another user's session id). Revoking the CURRENT session logs the caller
            # out — the next request finds no session and 303s to login.
            await service.revoke_own_session(identity, session_id, actor=identity.username)
            return RedirectResponse("/ui/account/sessions?m=revoked", status_code=303)

        @app.post("/ui/account/sessions/revoke-others")
        async def ui_revoke_other_sessions(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui()),
        ) -> Response:
            webui.assert_same_origin(request)
            current = hash_token(request.cookies.get(webui.COOKIE_NAME) or "")
            await service.revoke_other_sessions(identity, current, actor=identity.username)
            return RedirectResponse("/ui/account/sessions?m=signed_out_others", status_code=303)

        # --- L5a: WebAuthn passkeys (ADR 0068, WP-14b) -------------------------------
        # Self-scoped actions (permission=None — enforcement is each route's require_ui* dep).
        # enroll is the TOTP-enroll twin: a body-less POST returning HTML, gated on the password-
        # only re-proof (require_ui_reauth_only — WP-14: a stolen pre-MFA cookie must never bind
        # an attacker's passkey) and registered step_up=False so the enroll_first anti-loop knows
        # a required-but-unenrolled session CAN complete it. delete is the body-less path-param
        # auto-retry shape behind the FULL step-up. The verify route is a body-carrying JSON POST
        # — NEVER registered as a continuation (hard invariant); its require_ui_reauth_only maps a
        # stale-window 303 to the REGISTERED enroll action (the #745 ui_mfa_verify precedent).
        webui.register_ui_action(r"^/ui/account/webauthn/enroll$", None, step_up=False)
        webui.register_ui_action(r"^/ui/account/webauthn/[^/?#]+/delete$", None)

        _RP_NAME = "MessageFoundry"

        @app.post("/ui/account/webauthn/enroll")
        async def ui_webauthn_enroll(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(webui.require_ui_reauth_only()),
        ) -> Response:
            webui.assert_same_origin(request)
            if not service.webauthn_available():
                return await _account_response(
                    service,
                    identity,
                    request,
                    error=webui.WEBAUTHN_EXTRA_MISSING_NOTICE,
                    status_code=400,
                )
            rp = webui.webauthn_rp(request)
            if rp is None:
                # Fail closed, legibly (ADR 0068 §7): 409 + the shared notice on the account page.
                return await _account_response(
                    service,
                    identity,
                    request,
                    error=webui.WEBAUTHN_RP_MISSING_NOTICE,
                    status_code=409,
                )
            token = request.cookies.get(webui.COOKIE_NAME)
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
            return HTMLResponse(webui.pages.webauthn_enroll_page(options))

        @app.post("/ui/account/webauthn/verify")
        async def ui_webauthn_verify(
            request: Request,
            service: AuthService = Depends(_service),
            identity: Identity = Depends(
                webui.require_ui_reauth_only(reauth_next=lambda _r: "/ui/account/webauthn/enroll")
            ),
        ) -> Response:
            webui.assert_same_origin(request)
            rp = webui.webauthn_rp(request)
            if rp is None:
                return JSONResponse({"ok": False, "error": "rp_unavailable"}, status_code=409)
            token = request.cookies.get(webui.COOKIE_NAME)
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
            identity: Identity = Depends(webui.require_ui_step_up()),
        ) -> Response:
            webui.assert_same_origin(request)
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
