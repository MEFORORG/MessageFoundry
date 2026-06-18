# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pydantic request/response models for the auth + user-administration endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field

# Upper bounds on free-text request fields (API-INPUT): reject absurd inputs before they reach the
# store or argon2. Generous vs any legitimate value; the password cap also bounds argon2 work.
_NAME_MAX = 256
_PASSWORD_MAX = 1024
_GROUP_MAX = 512


class LoginRequest(BaseModel):
    username: str = Field(max_length=_NAME_MAX)
    password: str = Field(max_length=_PASSWORD_MAX)
    provider: str = Field("local", max_length=16)  # 'local' | 'ad'


class CurrentUser(BaseModel):
    user_id: str
    username: str
    auth_provider: str
    roles: list[str]
    permissions: list[str]


class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    must_change_password: bool = False
    # The password was accepted but a second factor is still required before sensitive operations
    # (WP-14): the client should prompt for a TOTP / recovery code and POST /auth/mfa-verify.
    mfa_required: bool = False
    user: CurrentUser


class ProvidersInfo(BaseModel):
    """What the login screen should offer."""

    local: bool = True
    ad: bool = False
    kerberos: bool = False


class UserSummary(BaseModel):
    id: str
    username: str
    auth_provider: str
    display_name: str | None = None
    email: str | None = None
    disabled: bool
    roles: list[str]
    channel_scope: list[str] | None = None  # per-channel RBAC: allowed connections; None = all


class ChannelScope(BaseModel):
    """A user's per-channel RBAC scope. ``None`` = all channels; a list = exactly those connections."""

    channels: list[str] | None = Field(default=None, max_length=512)


class UserCreateRequest(BaseModel):
    username: str = Field(max_length=_NAME_MAX)
    password: str = Field(max_length=_PASSWORD_MAX)
    display_name: str | None = Field(default=None, max_length=_NAME_MAX)
    email: str | None = Field(default=None, max_length=_NAME_MAX)
    roles: list[str] = Field(default=[], max_length=64)


class UserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=_NAME_MAX)
    email: str | None = Field(default=None, max_length=_NAME_MAX)
    disabled: bool | None = None


class RolesUpdateRequest(BaseModel):
    roles: list[str] = Field(max_length=64)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(max_length=_PASSWORD_MAX)
    new_password: str = Field(max_length=_PASSWORD_MAX)


class ReauthRequest(BaseModel):
    """Step-up re-verification (ASVS 7.5.3): the caller re-supplies their current credential to refresh
    the session's step-up window before a highly sensitive operation."""

    password: str = Field(max_length=_PASSWORD_MAX)


class PasswordResetResponse(BaseModel):
    """The result of an admin password reset (ASVS 6.4.6): a one-time credential returned **once** for
    the administrator to convey out-of-band. The user must change it on first login."""

    temp_password: str
    must_change_password: bool = True


# --- MFA: native TOTP second factor (WP-14, ASVS 6.3.3) ----------------------


class MfaVerifyRequest(BaseModel):
    """Satisfy a session's second factor with a TOTP code **or** a single-use recovery code."""

    code: str = Field(max_length=64)


class MfaEnrollResponse(BaseModel):
    """A staged (not-yet-active) TOTP enrollment: the base32 secret + the ``otpauth://`` URI the
    console renders as a QR. Returned once; the secret is not active until confirmed."""

    secret: str
    otpauth_uri: str


class MfaConfirmRequest(BaseModel):
    """Confirm a staged enrollment by proving a live TOTP code from the authenticator app."""

    code: str = Field(max_length=16)


class MfaConfirmResponse(BaseModel):
    """The one-time single-use recovery codes minted on enrollment — shown **once** for the user to
    save (lost-authenticator escape hatch)."""

    recovery_codes: list[str]


class MfaStatusResponse(BaseModel):
    """The caller's current MFA posture for ``GET /me/mfa``."""

    enabled: bool
    enrolled_at: float | None = None
    recovery_codes_remaining: int = 0
    required: bool = False


class RoleInfo(BaseModel):
    id: str
    display_name: str
    description: str | None = None
    permissions: list[str]


class AdGroupMapEntry(BaseModel):
    ad_group: str = Field(max_length=_GROUP_MAX)
    role: str = Field(max_length=64)


class AdGroupMap(BaseModel):
    entries: list[AdGroupMapEntry]


class AdGroupScopeEntry(BaseModel):
    """Maps an AD group to one allowed channel; channel ``*`` = all channels (per-channel RBAC C3)."""

    ad_group: str = Field(max_length=_GROUP_MAX)
    channel: str = Field(max_length=_NAME_MAX)


class AdGroupScopeMap(BaseModel):
    entries: list[AdGroupScopeEntry]


class AuditEntry(BaseModel):
    ts: float
    actor: str | None = None
    action: str
    channel_id: str | None = None
    detail: str | None = None


class AuditList(BaseModel):
    entries: list[AuditEntry]


class SimpleMessage(BaseModel):
    detail: str


class SessionInfo(BaseModel):
    """One active session in the self-service inventory (WP-10). ``id`` is the session's ``token_hash``
    (a one-way hash of the opaque token, safe to expose) — pass it to ``DELETE /me/sessions/{id}``."""

    id: str
    created_at: float
    last_used_at: float
    expires_at: float
    client: str | None = None
    current: bool = False


class SessionList(BaseModel):
    sessions: list[SessionInfo]


class SecurityEventInfo(BaseModel):
    """One entry in the caller's security-event history (WP-L3-05, ASVS 6.3.5/6.3.7) — a view over the
    audited ``auth.*`` actions. ``detail`` is the audit log's JSON metadata (PHI-free)."""

    ts: float
    action: str  # e.g. auth.login_success / auth.login_locked / auth.password_changed
    detail: str | None = None


class SecurityEventsList(BaseModel):
    events: list[SecurityEventInfo]
