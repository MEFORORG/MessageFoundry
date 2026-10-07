# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pydantic request/response models for the auth + user-administration endpoints.

A model the API parses out of a REQUEST BODY subclasses
:class:`~messagefoundry.api.request_model.RequestModel`, which refuses unknown keys; a response
model stays on ``BaseModel`` so a client reading a newer engine tolerates a field it has not learned
yet. That module states the split and why it is directional -- read it before moving a class between
the two bases.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from messagefoundry.api.request_model import RequestModel
from messagefoundry.api.validation import (
    MAX_MAP_ENTRIES,
    ChannelScopeEntry,
    PermissionId,
    RoleId,
)
from messagefoundry.auth.totp import DEFAULT_DIGITS as TOTP_DIGITS

# Upper bounds on free-text request fields (API-INPUT): reject absurd inputs before they reach the
# store or argon2. Generous vs any legitimate value; the password cap also bounds argon2 work.
# The ITEM rules for the id-shaped lists below live in `api/validation.py`, with the rest of the
# operator API's input rules (BACKLOG #1108, docs/API-INPUT-VALIDATION.md).
_NAME_MAX = 256
_PASSWORD_MAX = 1024
_GROUP_MAX = 512
# A session token is 43 URL-safe characters (auth/tokens.py); the cap only refuses absurd input.
_TOKEN_MAX = 256


class CredentialReply(BaseModel):
    """A response model whose body carries a live credential: a session token, a staged TOTP seed,
    recovery codes or a temporary password (ASVS 7.2.4 delivery, 14.2.2; BACKLOG #2372).

    Subclassing this is what serves the reply ``Cache-Control: no-store``. The engine's route class
    adds the no-store step to every route whose response model is one of these
    (``security.AuthenticatedBeforeBodyRoute``), so a new route returning one cannot forget it.
    ``tests/test_credential_reply_no_store.py`` fails when a response model carries a credential
    field name and does not subclass this."""


class LoginRequest(RequestModel):
    username: str = Field(max_length=_NAME_MAX)
    password: str = Field(max_length=_PASSWORD_MAX)
    provider: str = Field(default="local", max_length=16)  # 'local' | 'ad'
    #: The raw session token this sign-in REPLACES in the caller, if any (ASVS 7.2.4, BACKLOG
    #: #2096). Not the session ``id`` that ``/me/sessions`` shows, which is the token's hash: a
    #: value that names no session ends nothing, and the sign-in still succeeds. On success the
    #: engine ends it as ``AuthService._issue_session`` describes.
    supersedes: str | None = Field(default=None, max_length=_TOKEN_MAX)
    # ADR 0197 (BACKLOG #1131): the optional authenticator code of the COMBINED sign-in, the password
    # and a TOTP code in one request. Absent means today's two-step flow, unchanged. Bounded to the
    # TOTP digit count; the engine treats a blank one as absent. No response gains a field.
    totp_code: str | None = Field(default=None, max_length=TOTP_DIGITS, pattern=r"^[0-9]*$")


class CurrentUser(BaseModel):
    user_id: str
    username: str
    auth_provider: str
    roles: list[str]
    permissions: list[str]


class LoginResponse(CredentialReply):
    token: str
    token_type: str = "bearer"
    must_change_password: bool = False
    # The password was accepted but a second factor is still required before ANY authorized route
    # (WP-14): the client should prompt for a TOTP / recovery code and POST /auth/mfa-verify.
    mfa_required: bool = False
    user: CurrentUser
    #: BACKLOG #1141 (ASVS 6.4.5): when ``must_change_password`` is set, the Unix instant the
    #: temporary credential this login used stops working, so a client can tell its holder. It is
    #: ``AuthService.initial_credential_deadline`` over the stored ``password_changed_at``, the value
    #: the login gate refuses on. ``None`` when no change is owed or the expiry setting is 0.
    credential_expires_at: float | None = None


class ProvidersInfo(BaseModel):
    """What the login screen should offer."""

    local: bool = True
    ad: bool = False
    kerberos: bool = False
    #: Federated (OIDC) sign-in AVAILABILITY, matching `kerberos` above: enabled AND the IdP
    #: is not currently known-down (ADR 0142). Defaults False, so an older client that never
    #: reads it is unaffected.
    oidc: bool = False


class UserLockState(BaseModel):
    """One account's two ADR 0197 locks, as an administrator reads them (BACKLOG #1131, 6.1.1).

    The other field names are the store's columns, reported as stored. ``sign_in_locked`` and
    ``second_step_locked`` are computed by the engine at read time with the login gate's own test,
    so a lock that has lapsed reads False with its old expiry still shown. A sign-in that a live
    lock refuses is not counted; a failure the lock does not refuse still is (a re-proof, or a
    straggler from a parallel burst), so a count can pass the threshold. After a lock lapses the
    counts are history: the next failure restarts that count at 1 (``next_lockout_state``). Read-only: no route takes this
    model, and ending a lock early stays with the administrator password reset and the host-gated
    ``messagefoundry admin-unlock`` (ADR 0171).
    """

    sign_in_locked: bool
    locked_until: float | None = None
    failed_attempts: int = 0
    lock_cycles: int = 0
    second_step_locked: bool
    second_step_locked_until: float | None = None
    second_step_failed_attempts: int = 0
    second_step_lock_cycles: int = 0


class UserSummary(BaseModel):
    id: str
    username: str
    auth_provider: str
    display_name: str | None = None
    #: The account's PROFILE address. On a directory account this is a mirror the next AD/OIDC login
    #: overwrites, so it is not where a security notice goes -- see ``notify_email`` (BACKLOG #1139).
    email: str | None = None
    #: READ-ONLY: the engine-owned address every out-of-band security notice is sent to. No directory
    #: sync writes it, and no request can clear it -- it is repointed by setting ``notify_email`` on a
    #: PATCH. Setting ``email`` does not move it (BACKLOG #1139, ADR 0182 Amendment A).
    #: Surfaced so an operator can see where notices actually go; without it the split is invisible.
    #: Defaults None, so an older client that never reads it is unaffected.
    notify_email: str | None = None
    disabled: bool
    roles: list[str]
    #: Per-channel RBAC, as STORED: the allowed connection names, ``["*"]`` for the explicit
    #: all-channels grant, or ``None`` when nobody has set a scope — which denies (BACKLOG #1152).
    channel_scope: list[str] | None = None
    #: Who last wrote ``channel_scope`` (BACKLOG #1958): ``"ad"`` for the AD login sync,
    #: ``"manual"`` for an administrator, ``None`` when no scope writer has run. The rule it decides
    #: is on ``UserRecord.channel_scope_source``. Without it an administrator cannot see that saving
    #: a directory scope makes it manual. Typed ``str`` rather than the store's ``Literal`` so an
    #: older client reading a newer engine tolerates a value it has not learned yet.
    channel_scope_source: str | None = None
    #: BACKLOG #1141 (ASVS 6.4.5): while the account still holds an admin-issued must-change
    #: credential, the Unix instant it stops working. The create-user response and the console's
    #: user page carry it, both behind users:manage, so the administrator who conveys the initial
    #: password can convey its deadline. ``GET /users`` needs only users:read and leaves it ``None``.
    #: Same source as the login gate. ``None`` once the holder sets their own password.
    credential_expires_at: float | None = None
    #: BACKLOG #1131 (ASVS 6.1.1): the account's sign-in and second-step locks. Only a
    #: ``users:manage`` caller gets them, which is Administrator-only (ADR 0045 D1); ``GET /users``
    #: sends everyone else ``None``. Which accounts are under attack, and how hard, is a target
    #: list. ``None`` therefore means NOT SHOWN TO YOU, never "not locked": a
    #: caller who is shown lock state gets an object for every account, unlocked ones included.
    lock_state: UserLockState | None = None


class FederatedIdentityView(BaseModel):
    """One account's federated binding, as the console's federated-identity screen renders it
    (BACKLOG #1143 / #295, ADR 0184 slice B).

    A view of its own rather than two more fields on :class:`UserSummary`. That model is what
    ``GET /users`` returns under users:read, where the pair must not appear, and a field that is
    always ``None`` there would read as "not linked" to any client that trusts it.

    ``issuer`` and ``subject`` are the stored pair; either one set counts as linked, as it does in
    :meth:`AuthService.unbind_federated_subject`. ``bind_issuer`` is the issuer a bind would use,
    ``[auth].oidc_issuer``, or ``None`` when it is unset and every bind is refused.
    ``has_directory_object_id`` says whether the account carries its immutable directory id; a bind
    is refused without one (BACKLOG #1143 slice C). A flag rather than the id, which the screen has
    no use for.
    """

    user_id: str
    username: str
    auth_provider: str
    issuer: str | None = None
    subject: str | None = None
    bind_issuer: str | None = None
    has_directory_object_id: bool = False

    @property
    def linked(self) -> bool:
        return self.issuer is not None or self.subject is not None


class UserPermissions(BaseModel):
    """The FLATTENED effective permission set for an arbitrary user (BACKLOG #177 inspector).

    ``permissions`` is the union built-in-role ∪ custom-role ∪ extras — the same set every
    authorization check consults. ``roles`` lists the role ids the user actually holds (built-in +
    ``custom:``-prefixed) for troubleshooting *where* a grant came from. Both are sorted."""

    user_id: str
    username: str
    roles: list[str]
    permissions: list[str]


class ChannelScope(RequestModel):
    """A user's per-channel RBAC scope: a list of exactly those connections.

    ``["*"]`` is the explicit all-channels grant. ``None`` clears the scope back to unset, and unset
    DENIES every channel (BACKLOG #1152, ASVS 8.2.2) — it is not the wide value it used to be, so a
    client that sends null to widen a scope now narrows it to nothing. Administrators are
    all-channels by role, so a scope set on one has no effect either way.

    A member is a connection name or that one token, which is why this list is typed
    ``ChannelScopeEntry`` and not ``ConnectionName``; ``api/validation.py`` states the rule and why
    the token stops here rather than widening the connection-name rule everything else uses."""

    channels: list[ChannelScopeEntry] | None = Field(default=None, max_length=512)
    #: WRITE-ONLY explicit intent (BACKLOG #2098, owner ruling 2026-09-27): who the caller believes
    #: last wrote the stored scope, as ``UserSummary.channel_scope_source`` reports it. REQUIRED as
    #: ``"ad"`` to save over a directory scope, because the save makes it manual and the login sync
    #: then never withdraws it; when sent, a stored source that differs answers 409. Omitted, it
    #: changes nothing for a scope the directory does not own. ONE EXCEPTION to "as it reports it"
    #: (BACKLOG #2252): where it reports null on an AD account with a stored scope, send ``"ad"``;
    #: ``AuthService.set_channel_scope`` says why. ``exclude=True`` keeps it out of the
    #: GET payload: this class is also the reader an older client validates that payload with, and it
    #: forbids a key it does not know.
    expected_source: Literal["ad", "manual"] | None = Field(default=None, exclude=True)


class UserCreateRequest(RequestModel):
    """``POST /users``. THERE IS NO PASSWORD FIELD (ADR 0197 Amendment A, N-B2 part 1): the engine
    generates the new account's credential and returns it once, in :class:`UserCreatedResponse`.
    ``RequestModel`` refuses an unknown key, so a caller still sending ``password`` gets 422 rather
    than a credential it believes it chose."""

    username: str = Field(max_length=_NAME_MAX)
    display_name: str | None = Field(default=None, max_length=_NAME_MAX)
    #: REQUIRED (BACKLOG #2018, ASVS 6.3.7). It seeds both the profile address and ``notify_email``,
    #: where every security notice goes. An account born without one is told nothing about a change
    #: made to it before its holder's first sign-in, an administrator's password reset included. The
    #: service refuses a blank value or anything but one plain mailbox, with the check the PATCH
    #: route applies to ``notify_email``.
    email: str = Field(max_length=_NAME_MAX)
    roles: list[RoleId] = Field(default=[], max_length=64)


class DirectoryUserCreateRequest(RequestModel):
    """``POST /users/directory``: create a directory (AD) account's mirror row by name, with no
    sign-in (BACKLOG #2021).

    The row's ``objectGUID``, display name and ``mail`` come from a service-account directory
    lookup, so there is deliberately no field for them, and the model refuses an unknown key with
    422: a caller cannot choose which directory identity a row claims.

    ``notify_email`` is not identity. It is required when the directory supplies no usable ``mail``
    and refused when it does, so the row is never born without an address and an administrator
    cannot point the holder's notices away from the directory's (ASVS 6.3.7).
    """

    username: str = Field(min_length=1, max_length=_NAME_MAX)
    notify_email: str | None = Field(default=None, max_length=_NAME_MAX)


class UserUpdateRequest(RequestModel):
    display_name: str | None = Field(default=None, max_length=_NAME_MAX)
    #: The PROFILE address. It does not move ``notify_email`` (BACKLOG #1139, ADR 0182 Amendment A).
    email: str | None = Field(default=None, max_length=_NAME_MAX)
    disabled: bool | None = None
    #: The engine-owned address security notices go to. Omitted leaves it as it is. A value moves it
    #: and notifies the address it moves away from. It must be one plain mailbox, and an explicit
    #: null or a blank value is refused, because the address can be repointed but never cleared.
    notify_email: str | None = Field(default=None, max_length=_NAME_MAX)


class RolesUpdateRequest(RequestModel):
    roles: list[RoleId] = Field(max_length=64)


class ExpectedFederatedPair(RequestModel):
    """The federated pair a caller saw, which a bind or unbind must still find (BACKLOG #2026).
    ``DELETE /users/{user_id}/federated-identity`` takes it as its whole body, and the ``PUT`` body
    :class:`FederatedIdentityRequest` extends it.

    Both fields are REQUIRED and may be ``null``, for a half the caller saw unset. The engine acts
    only if the account still holds exactly this pair, and otherwise answers 409 with nothing
    changed. So an administrator working from a stale read cannot remove a binding another
    administrator wrote after that read. The console's federated-identity screen shows the pair and
    posts it back; a JSON caller reads it from ``GET /users/{user_id}/federated-identity``
    (BACKLOG #2331).

    The issuer bound is 256 characters. ``[auth].oidc_issuer`` is refused at load beyond 256 UTF-16
    units, the width of the narrowest issuer column (SQL Server ``NVARCHAR(256)``), and no character
    takes fewer than one unit, so every issuer a bind can store fits this bound (BACKLOG #2331). The
    subject bound is the one :class:`FederatedIdentityRequest` puts on ``sub``.
    """

    expected_issuer: str | None = Field(max_length=256)
    expected_subject: str | None = Field(max_length=255)


class FederatedIdentityRequest(ExpectedFederatedPair):
    """``PUT /users/{user_id}/federated-identity``: the IdP ``sub`` to bind (BACKLOG #1143), plus
    the pair the caller saw (BACKLOG #2026), both ``null`` for an account it saw unbound.

    No issuer field: the service binds under the configured ``[auth].oidc_issuer``, the only issuer
    whose tokens the claims ladder accepts. 255 is OpenID Connect Core's own ceiling on ``sub``, and
    fits the narrowest backend column (SQL Server ``NVARCHAR(256)``).
    """

    subject: str = Field(min_length=1, max_length=255)


class PasswordChangeRequest(RequestModel):
    current_password: str = Field(max_length=_PASSWORD_MAX)
    new_password: str = Field(max_length=_PASSWORD_MAX)


class NotifyEmailRequest(RequestModel):
    """``POST /me/notify-email``: the address that fills a missing notification address (BACKLOG
    #1139). Same bound as ``UserCreateRequest.email``; blank is refused by the service."""

    email: str = Field(max_length=_NAME_MAX)


class ReauthRequest(RequestModel):
    """Step-up re-verification (ASVS 7.5.3): the caller re-supplies their current credential to refresh
    the session's step-up window before a highly sensitive operation."""

    password: str = Field(max_length=_PASSWORD_MAX)
    # ADR 0077: optionally BIND this fresh proof to a single durable-takeover action (the value the
    # 403 handed back in `X-Step-Up-Action`), minting a single-use per-action grant instead of only
    # refreshing the session window. Bounded length — it is an opaque action tag, never reflected;
    # an unknown tag simply fails closed (nothing consumes it, so the action re-prompts).
    purpose: str | None = Field(default=None, max_length=64)


class UserCreatedResponse(UserSummary, CredentialReply):
    """``POST /users``: the new account, plus its engine-generated credential, returned **once** for
    the administrator to convey out-of-band (ADR 0197 Amendment A, AC-A2). The holder must enrol an
    authenticator app, then replace it, at first sign-in. Wrong passwords arm no sign-in lock while
    it stands, so nobody who merely knows the username can lock the account before that."""

    temp_password: str
    must_change_password: bool = True


class MfaResetResponse(CredentialReply):
    """``POST /users/{id}/reset-mfa``: the factor reset, and on a LOCAL account the generated
    credential it issued in the same call (ADR 0197 Amendment A, N-B2 part 5, AC-A4), returned
    **once**. ``None`` on a directory account, which has no engine password. ``expires_at`` is the
    same deadline :class:`PasswordResetResponse` carries."""

    detail: str
    temp_password: str | None = None
    expires_at: float | None = None


class PasswordResetResponse(CredentialReply):
    """The result of an admin password reset (ASVS 6.4.6): a one-time credential returned **once** for
    the administrator to convey out-of-band. The user must change it on first login."""

    temp_password: str
    must_change_password: bool = True
    #: BACKLOG #1141 (ASVS 6.4.5): the Unix instant this credential stops working, so the renewal
    #: instruction ships WITH the credential on the one artifact that reaches the issuing
    #: administrator. It is ``AuthService.initial_credential_deadline`` over the stored
    #: ``password_changed_at`` — the same value the login gate refuses on, never a second
    #: computation. ``None`` when ``[auth].initial_password_expiry_hours`` is 0, which is the
    #: documented value that genuinely removes the deadline.
    expires_at: float | None = None


# --- MFA: native TOTP second factor (WP-14, ASVS 6.3.3) ----------------------


class MfaVerifyRequest(RequestModel):
    """Satisfy a session's second factor with a TOTP code **or** a single-use recovery code."""

    code: str = Field(max_length=64)


class MfaEnrollResponse(CredentialReply):
    """A staged (not-yet-active) TOTP enrollment: the base32 secret + the ``otpauth://`` URI the
    console renders as a QR. Returned once; the secret is not active until confirmed."""

    secret: str
    otpauth_uri: str


class MfaConfirmRequest(RequestModel):
    """Confirm a staged enrollment by proving a live TOTP code from the authenticator app."""

    code: str = Field(max_length=16)


class MfaConfirmResponse(CredentialReply):
    """The one-time single-use recovery codes minted on enrollment — shown **once** for the user to
    save (lost-authenticator escape hatch), plus the rotated session token.

    ``token`` is the caller's NEW bearer token: confirming an enrolment elevates the session, and
    ASVS 7.2.4 re-keys it on every elevation, so the token the client authenticated this very call
    with has stopped working. A client that ignores this field has locked itself out."""

    recovery_codes: list[str]
    token: str


class ElevatedResponse(CredentialReply):
    """A ceremony that RAISED the session's authentication state, and the token it was re-keyed to.

    ``token`` is the caller's NEW bearer token (ASVS 7.2.4). The one the request carried no longer
    authenticates, so a client MUST adopt this or it has just ended its own session. The responses
    carrying this field are sent ``Cache-Control: no-store`` — a body holding a live session token
    must not sit in a shared cache."""

    detail: str
    token: str


class MfaStatusResponse(BaseModel):
    """The caller's current MFA posture for ``GET /me/mfa``.

    ``enabled`` stays == TOTP-enabled (the desktop console's boolean view is untouched);
    ``webauthn_enrolled`` is the ADR 0068 additive field (defaulted, so an older client's decode
    is unaffected). ``required`` accounts for either factor being enrolled."""

    enabled: bool
    enrolled_at: float | None = None
    recovery_codes_remaining: int = 0
    required: bool = False
    webauthn_enrolled: bool = False


class RoleInfo(BaseModel):
    id: str
    display_name: str
    description: str | None = None
    permissions: list[str]
    #: True for the six fixed built-in roles, False for an admin-defined custom role (ADR 0045).
    builtin: bool = True


class CustomRoleRequest(RequestModel):
    """Create/update an admin-defined custom role (ADR 0045): a named SUBSET of the existing Permission
    catalog. The engine validates the subset (recognized perms only, non-empty, no carved-out
    escalation primitive) and rejects otherwise."""

    display_name: str = Field(max_length=_NAME_MAX)
    description: str | None = Field(default=None, max_length=_NAME_MAX)
    permissions: list[PermissionId] = Field(max_length=64)


class CustomRoleInfo(BaseModel):
    id: str
    display_name: str
    description: str | None = None
    permissions: list[str]


class AdGroupMapEntry(RequestModel):
    ad_group: str = Field(max_length=_GROUP_MAX)
    role: str = Field(max_length=64)


class AdGroupMap(RequestModel):
    entries: list[AdGroupMapEntry] = Field(max_length=MAX_MAP_ENTRIES)


class AdGroupScopeEntry(RequestModel):
    """Maps an AD group to one allowed channel; channel ``*`` = all channels (per-channel RBAC C3)."""

    ad_group: str = Field(max_length=_GROUP_MAX)
    channel: str = Field(max_length=_NAME_MAX)


class AdGroupScopeMap(RequestModel):
    entries: list[AdGroupScopeEntry] = Field(max_length=MAX_MAP_ENTRIES)


class AuditEntry(BaseModel):
    ts: float
    actor: str | None = None
    action: str
    channel_id: str | None = None
    detail: str | None = None
    #: The caller's network address, or None for an engine-internal write (ADR 0150). The "from where"
    #: that lets an incident responder trace an entry to a host; None means no client was in scope.
    client: str | None = None


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
