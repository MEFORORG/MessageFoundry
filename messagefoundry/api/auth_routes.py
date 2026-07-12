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
import csv
import io
import json
import logging
from collections.abc import Iterator

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

# The /ui admin pages moved to the messagefoundry_webconsole package (Option B, ADR 0065); this module
# no longer imports the console at all. It returns an engine-side AdminHandlers bundle (leaf type in
# api._ui_seam — never the console package), so it imports and the engine boots with the console ABSENT.
from messagefoundry.api._ui_seam import AdminHandlers
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
    UserPermissions,
    UserSummary,
    UserUpdateRequest,
)
from messagefoundry.api.security import (
    bearer_token,
    get_auth,
    require,
    require_reauth_only_action,
    require_step_up,
    require_step_up_action,
)
from messagefoundry.auth import (
    BUILTIN_ROLE_PERMISSIONS,
    ROLE_METADATA,
    AuthProvider,
    Identity,
    Permission,
    Role,
)
from messagefoundry.auth.permissions import CustomRoleError
from messagefoundry.auth.service import (
    STEP_UP_ACTION_MFA_CONFIRM,
    STEP_UP_ACTION_MFA_DISABLE,
    STEP_UP_ACTION_MFA_ENROLL,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.store.store import SessionRecord, UserRecord

_VALID_ROLE_IDS = {role.value for role in Role}

_log = logging.getLogger(__name__)


# Leading characters that make a spreadsheet treat a CSV cell as a formula (=, +, -, @) or that can
# smuggle one past a leading-whitespace trim (TAB/CR/LF). See OWASP "CSV Injection" / CWE-1236.
_CSV_FORMULA_TRIGGERS = frozenset("=+-@\t\r\n")


def _csv_safe(value: object) -> object:
    """Neutralize spreadsheet formula injection (CWE-1236) in a CSV cell.

    A compliance officer opening ``audit-export.csv`` in Excel/Sheets would otherwise let a
    user-influenced field (actor/detail/…) starting with ``= + - @`` — or a leading TAB/CR/LF ahead of
    one — execute as a formula/DDE payload. If the (whitespace-stripped) string begins with such a
    trigger, prefix a single apostrophe so the spreadsheet renders it as literal text. Non-strings and
    benign strings pass through unchanged."""
    if not isinstance(value, str) or not value:
        return value
    # A raw leading TAB/CR/LF is itself a trigger; ``=+-@`` count even behind ordinary leading spaces.
    if value[0] in _CSV_FORMULA_TRIGGERS or value.lstrip()[:1] in _CSV_FORMULA_TRIGGERS:
        return "'" + value
    return value


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


def add_auth_routes(app: FastAPI) -> AdminHandlers:
    """Register the auth + user-administration JSON routes and RETURN the admin handler bundle.

    The /ui admin/account/audit pages themselves live in the ``messagefoundry_webconsole`` package now
    (Option B, ADR 0065) — they reuse these **nested** JSON handlers directly, so this function returns
    an engine-side :class:`AdminHandlers` bundle of references to them (plus the ``_user_summary`` /
    ``_current_user`` DTO projections) that ``create_app`` injects into ``mount_ui``. The concrete
    :class:`AdminHandlers` type lives in the engine leaf ``api._ui_seam`` (never the console package),
    so this function — called UNCONDITIONALLY from ``create_app`` — imports with the console absent.
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
            identity,
            body.password,
            token=token,
            client=_client(request),
            # ADR 0077: bind the fresh proof to the action the caller named (the value the 403 handed
            # back in X-Step-Up-Action). None => refresh only the session window, as before.
            purpose=body.purpose,
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
        identity: Identity = Depends(require_reauth_only_action(STEP_UP_ACTION_MFA_ENROLL)),
    ) -> MfaEnrollResponse:
        """Begin TOTP enrollment: stage a secret and return it + the ``otpauth://`` URI for the QR.
        Gated by a fresh **password** step-up BOUND to this enroll action (ADR 0077 — not MFA, you may
        have none yet; and not the shared login window, so a hijacked session can't bind a factor); not
        active until confirmed via ``/me/mfa/confirm``."""
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
        identity: Identity = Depends(require_reauth_only_action(STEP_UP_ACTION_MFA_CONFIRM)),
    ) -> MfaConfirmResponse:
        """Confirm a staged enrollment by proving a live TOTP code; activates MFA and returns the
        single-use recovery codes (shown **once** — save them). A wrong code is a 400. Gated by a fresh
        password step-up BOUND to this confirm action (ADR 0077), independent of the enroll grant."""
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
        identity: Identity = Depends(require_step_up_action(STEP_UP_ACTION_MFA_DISABLE)),
    ) -> SimpleMessage:
        """Self-service: turn off the caller's TOTP MFA. Step-up gated — you prove your current factor
        (a TOTP or recovery code via ``/auth/mfa-verify``) and a fresh password BOUND to this disable
        action (ADR 0077): a hijacked session inside the login window can't silently strip MFA."""
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

    @app.get("/users/{user_id}/permissions", response_model=UserPermissions)
    async def get_user_permissions(
        user_id: str,
        service: AuthService = Depends(_service),
        _: Identity = Depends(require(Permission.USERS_READ)),
    ) -> UserPermissions:
        """Effective-permission inspector (BACKLOG #177): resolve the FLATTENED effective permission
        set — built-in-role ∪ custom-role ∪ extras — for an arbitrary user id, for RBAC
        troubleshooting. Reuses the same ``Identity.build`` flattening path ``/auth/me`` uses for the
        caller (via :meth:`AuthService.identity_for_user_id`) rather than re-deriving the union.
        Gated like ``/users`` (``USERS_READ``, deny-by-default); a non-existent user id 404s."""
        resolved = await service.identity_for_user_id(user_id)
        if resolved is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        # The flattened Identity carries only built-in Roles; list the actual held role ids (built-in +
        # custom:) so an operator can see WHERE a grant came from, mirroring _user_summary.
        role_ids = await service.store.get_user_role_ids(user_id)
        return UserPermissions(
            user_id=resolved.user_id,
            username=resolved.username,
            roles=sorted(role_ids),
            permissions=sorted(p.value for p in resolved.permissions),
        )

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

    async def _audit_list(
        service: AuthService,
        *,
        limit: int = 100,
        actor: str | None = None,
        action: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> AuditList:
        # Plain-default core shared by the HTTP route below and the webconsole seam wrapper. Every value
        # is passed as a keyword to the store, which binds it as a SQL parameter across all three backends
        # (BACKLOG #170) — filters are never string-interpolated into the query.
        rows = await service.store.list_audit(
            limit=limit, actor=actor, action=action, since=since, until=until
        )
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

    @app.get("/audit", response_model=AuditList)
    async def list_audit(
        service: AuthService = Depends(_service),
        _: Identity = Depends(require(Permission.AUDIT_READ)),
        limit: int = Query(100, ge=1, le=1000),
        actor: str | None = Query(None, max_length=256),
        action: str | None = Query(None, max_length=128),
        since: float | None = Query(
            None, description="inclusive lower bound on the epoch-float ts"
        ),
        until: float | None = Query(
            None, description="inclusive upper bound on the epoch-float ts"
        ),
    ) -> AuditList:
        return await _audit_list(
            service, limit=limit, actor=actor, action=action, since=since, until=until
        )

    async def _audit_ui_list(*, service: AuthService, _: Identity, limit: int = 100) -> AuditList:
        # The webconsole /ui/audit page invokes this seam callable DIRECTLY (not through FastAPI), so its
        # defaults MUST be plain values — a route Query(...) sentinel must never reach the store bind
        # (BACKLOG #170 regression guard: 'type Query is not supported'). The UI shows the full trail;
        # filter + CSV export are the JSON GET /audit surface. AUDIT_READ is enforced by the webconsole
        # route's own require_ui dependency, so this wrapper carries no auth dependency of its own.
        return await _audit_list(service, limit=limit)

    @app.get("/audit/export")
    async def export_audit(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require(Permission.AUDIT_EXPORT)),
        format: str = Query("csv", pattern="^csv$"),
        limit: int = Query(10000, ge=1, le=1_000_000),
        actor: str | None = Query(None, max_length=256),
        action: str | None = Query(None, max_length=128),
        since: float | None = Query(
            None, description="inclusive lower bound on the epoch-float ts"
        ),
        until: float | None = Query(
            None, description="inclusive upper bound on the epoch-float ts"
        ),
    ) -> StreamingResponse:
        """Stream the filtered audit trail as a downloadable CSV report (BACKLOG #170), so a compliance
        officer can produce a scoped, offline audit report without a downstream SIEM.

        Same filters and the same parameterized store query as ``GET /audit``, gated by the dedicated
        ``audit:export`` permission. Only PHI-safe audit metadata is emitted — ``ts, actor, action,
        channel_id, detail`` — the exact columns ``GET /audit`` already returns; the audit writers store
        only filter shapes / counts / ids in ``detail`` (never a raw message body), so no PHI leaves on
        this path. The export itself is recorded as an ``audit.export`` event (who, which filter, how
        many rows)."""
        rows = await service.store.list_audit(
            limit=limit, actor=actor, action=action, since=since, until=until
        )
        # Record the export as its own audit event BEFORE streaming — the detail is metadata only (the
        # applied filter + row count), never a message body.
        await service.store.record_audit(
            "audit.export",
            actor=identity.username,
            detail=json.dumps(
                {
                    "format": "csv",
                    "count": len(rows),
                    "filter": {
                        "actor": actor,
                        "action": action,
                        "since": since,
                        "until": until,
                        "limit": limit,
                    },
                }
            ),
        )

        def _iter_csv() -> Iterator[str]:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["ts", "actor", "action", "channel_id", "detail"])
            yield buf.getvalue()
            for r in rows:
                buf.seek(0)
                buf.truncate(0)
                # Neutralize spreadsheet formula injection (CWE-1236) in every string cell before it
                # reaches the CSV a compliance officer may open in Excel/Sheets.
                writer.writerow(
                    _csv_safe(c)
                    for c in (r["ts"], r["actor"], r["action"], r["channel_id"], r["detail"])
                )
                yield buf.getvalue()

        return StreamingResponse(
            _iter_csv(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="audit-export.csv"'},
        )

    # The /ui admin/account/audit pages moved to messagefoundry_webconsole (Option B, ADR 0065). Return
    # the engine-side AdminHandlers bundle of references to the nested JSON handlers above (+ the two
    # sync DTO projections); create_app injects it into mount_ui when serve_ui is on.
    return AdminHandlers(
        list_roles=list_roles,
        list_users=list_users,
        list_custom_roles=list_custom_roles,
        create_user=create_user,
        update_user=update_user,
        set_user_roles=set_user_roles,
        set_channel_scope=set_channel_scope,
        reset_user_password=reset_user_password,
        reset_user_mfa=reset_user_mfa,
        admin_revoke_user_sessions=admin_revoke_user_sessions,
        delete_user=delete_user,
        create_custom_role=create_custom_role,
        update_custom_role=update_custom_role,
        delete_custom_role=delete_custom_role,
        get_ad_group_map=get_ad_group_map,
        get_ad_group_scope_map=get_ad_group_scope_map,
        set_ad_group_map=set_ad_group_map,
        set_ad_group_scope_map=set_ad_group_scope_map,
        my_mfa=my_mfa,
        change_password=change_password,
        enroll_mfa=enroll_mfa,
        disable_my_mfa=disable_my_mfa,
        list_audit=_audit_ui_list,
        my_security_events=my_security_events,
        user_summary=_user_summary,
        current_user=_current_user,
    )
