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

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status

from messagefoundry.api.auth_models import (
    AdGroupMap,
    AdGroupMapEntry,
    AdGroupScopeEntry,
    AdGroupScopeMap,
    AuditEntry,
    AuditList,
    ChannelScope,
    CurrentUser,
    LoginRequest,
    LoginResponse,
    PasswordChangeRequest,
    ProvidersInfo,
    RoleInfo,
    RolesUpdateRequest,
    SessionInfo,
    SessionList,
    SimpleMessage,
    UserCreateRequest,
    UserSummary,
    UserUpdateRequest,
)
from messagefoundry.api.security import bearer_token, get_auth, require
from messagefoundry.auth import (
    BUILTIN_ROLE_PERMISSIONS,
    ROLE_METADATA,
    AuthProvider,
    Identity,
    Permission,
    Role,
)
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
    return request.client.host if request.client else None


def _current_user(identity: Identity) -> CurrentUser:
    return CurrentUser(
        user_id=identity.user_id,
        username=identity.username,
        auth_provider=identity.auth_provider.value,
        roles=sorted(r.value for r in identity.roles),
        permissions=sorted(p.value for p in identity.permissions),
    )


def _login_response(token: str, identity: Identity, must_change: bool) -> LoginResponse:
    return LoginResponse(
        token=token, must_change_password=must_change, user=_current_user(identity)
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


def _validate_roles(roles: list[str]) -> None:
    unknown = sorted(set(roles) - _VALID_ROLE_IDS)
    if unknown:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown role(s): {', '.join(unknown)}")


def add_auth_routes(app: FastAPI) -> None:
    # --- authentication ------------------------------------------------------

    @app.get("/auth/providers", response_model=ProvidersInfo)
    async def providers(
        request: Request, service: AuthService = Depends(_service)
    ) -> ProvidersInfo:
        return ProvidersInfo(local=True, ad=service.ad_enabled, kerberos=service.kerberos_enabled)

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
        return _login_response(outcome.token, outcome.identity, outcome.must_change_password)

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
        violations = await service.change_password(identity, body.new_password)
        if violations:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "password must " + "; ".join(violations)
            )
        return SimpleMessage(detail="password changed; please sign in again")

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
    async def list_roles(_: Identity = Depends(require(Permission.USERS_READ))) -> list[RoleInfo]:
        out: list[RoleInfo] = []
        for role in Role:
            label, description = ROLE_METADATA[role]
            out.append(
                RoleInfo(
                    id=role.value,
                    display_name=label,
                    description=description,
                    permissions=sorted(p.value for p in BUILTIN_ROLE_PERMISSIONS[role]),
                )
            )
        return out

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
        identity: Identity = Depends(require(Permission.USERS_MANAGE)),
    ) -> UserSummary:
        _validate_roles(body.roles)
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
        identity: Identity = Depends(require(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        current = await service.store.get_user(user_id)
        if current is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        if body.disabled and user_id == identity.user_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot disable your own account")
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
        identity: Identity = Depends(require(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        if user_id == identity.user_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot delete your own account")
        if await service.store.get_user(user_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        await service.delete_user(user_id, actor=identity.username)
        return SimpleMessage(detail="deleted")

    @app.delete("/users/{user_id}/sessions", response_model=SimpleMessage)
    async def admin_revoke_user_sessions(
        user_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require(Permission.USERS_MANAGE)),
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
        identity: Identity = Depends(require(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        _validate_roles(body.roles)
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
        identity: Identity = Depends(require(Permission.USERS_MANAGE)),
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
        identity: Identity = Depends(require(Permission.USERS_MANAGE)),
    ) -> SimpleMessage:
        _validate_roles([e.role for e in body.entries])
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
        identity: Identity = Depends(require(Permission.USERS_MANAGE)),
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
