# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""AuthService — orchestrates authentication, sessions, role resolution, and first-run bootstrap.

Pure engine-side code (no FastAPI): the API layer composes it. It ties together the store (users,
roles, sessions, audit), password hashing/policy, opaque session tokens, and the LDAP/Kerberos
authenticators. Local and AD users share one identity model; an AD user's roles are re-synced from
their directory groups on every login, so :meth:`identity_for_token` can resolve everyone uniformly
from ``user_roles``.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import os
import secrets
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar
from uuid import uuid4

from messagefoundry.auth import totp
from messagefoundry.auth import webauthn
from messagefoundry.auth.identity import AuthProvider, Identity
from messagefoundry.auth.ldap import AdPrincipal, LdapAuthenticator, LdapError, kerberos_principal
from messagefoundry.auth.notifications import (
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    ADMIN_NEW_IP,
    EMAIL_CHANGED,
    LOGIN_AFTER_FAILURES,
    MFA_DISABLED,
    MFA_ENABLED,
    PASSWORD_CHANGED,
    PASSWORD_RESET,
    ROLES_CHANGED,
    SUSPICIOUS_LOGIN_FAILURE_THRESHOLD,
    SecurityEvent,
    SecurityNotifier,
)
from messagefoundry.auth.passwords import hash_password, needs_rehash, verify_password
from messagefoundry.auth.permissions import (
    CUSTOM_ROLE_ID_PREFIX,
    ROLE_METADATA,
    Permission,
    Role,
    decode_custom_role_permissions,
    is_custom_role_id,
    validate_custom_role_permissions,
)
from messagefoundry.auth.policy import PasswordPolicy, _operator_corpus
from messagefoundry.auth.ratelimit import SlidingWindowRateLimiter
from messagefoundry.auth.tokens import hash_bytes, hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.base import AdminStore
from messagefoundry.store.store import SessionRecord, UserRecord, WebAuthnCredential

_log = logging.getLogger(__name__)

#: The account created on first run when the store has no users (HIPAA unique-user bootstrap).
BOOTSTRAP_USERNAME = "admin"


def _warn_if_corpus_unreadable(path: str | None) -> None:
    """Eagerly load (and cache) an operator breach corpus at startup so a misconfigured path surfaces
    as a clear warning rather than silently disabling the check on every later password change."""
    if not path:
        return
    try:
        entries, hashed = _operator_corpus(path)
    except OSError as exc:
        _log.warning(
            "password_breach_corpus_file %r could not be read (%s); the larger breach corpus is "
            "disabled (the bundled top-10k list still applies)",
            path,
            exc,
        )
        return
    _log.info(
        "loaded operator breach corpus from %r (%d %s entries)",
        path,
        len(entries),
        "hashed" if hashed else "plaintext",
    )


#: A fixed argon2 hash used to equalize login timing for unknown/disabled accounts (anti-enumeration).
_DUMMY_PASSWORD_HASH = hash_password("mf-login-timing-equalizer")

#: Cap on concurrent argon2 hashes/verifies so an unauthenticated login flood can't exhaust the
#: thread-pool executor (and starve all login/AD/password work). Argon2 is deliberately CPU-heavy.
_ARGON2_MAX_CONCURRENCY = max(2, min(8, os.cpu_count() or 2))

# Bound on the per-process new-client-IP dedup cache (WP-L3-13). It only debounces the audit/notify
# side effects of the 8.4.2 signal; the step-up decision never depends on it, so eviction is harmless.
_NEW_IP_DEDUP_MAX = 4096

# Global safety bound on outstanding single-use per-action step-up grants (ADR 0077). Each grant is
# consumed on the next matching sensitive request (or expires with the step-up window), so the live set
# is normally tiny; this only caps a pathological accumulation. On overflow the OLDEST grant is evicted
# (fail-safe: a dropped grant just re-prompts, never a bypass), mirroring `_new_ip_seen`'s self-eviction.
_ACTION_STEP_UP_GRANT_MAX = 4096

# Action identifiers for the per-action step-up grants (ADR 0077). Named constants so the JSON API deps
# and the tests all reference the SAME grant string (a typo would only ever fail closed — an unmatched
# grant re-prompts — but the shared constants keep the wiring legible). Only the JSON factor-binding
# routes that are actually gated are defined here; WebAuthn register/verify and the browser /ui twins
# stay on the legacy session-window step-up (deferred to a Wave-1 follow-on, see ADR 0077 residuals).
STEP_UP_ACTION_MFA_ENROLL = "mfa_enroll"
STEP_UP_ACTION_MFA_CONFIRM = "mfa_confirm"
STEP_UP_ACTION_MFA_DISABLE = "mfa_disable"

_T = TypeVar("_T")


@dataclass(frozen=True)
class LoginOutcome:
    """Result of a login attempt. ``error`` is for logs/audit — never leak the reason to clients."""

    ok: bool
    token: str | None = None
    identity: Identity | None = None
    must_change_password: bool = False
    error: str | None = None
    #: The password was accepted but the session still needs a second factor (TOTP / recovery code)
    #: before it may perform step-up (sensitive) operations — the client should prompt for a code and
    #: call ``POST /auth/mfa-verify`` (WP-14, ASVS 6.3.3). Always False for an MFA-delegated AD login.
    mfa_required: bool = False


@dataclass(frozen=True)
class MfaEnrollment:
    """A staged (not-yet-confirmed) TOTP enrollment: the base32 secret to render as a QR + the
    ``otpauth://`` URI. Returned **once**; confirmed by proving a live code."""

    secret: str
    otpauth_uri: str


@dataclass(frozen=True)
class MfaStatus:
    """A local user's current MFA posture, for ``GET /me/mfa``.

    ``enabled`` stays == TOTP-enabled on the wire (the desktop console's boolean view is
    untouched); ``webauthn_enrolled`` is the ADR 0068 additive field — ``required`` accounts for
    EITHER factor being enrolled (enrolled-any-factor ⇒ always required)."""

    enabled: bool
    enrolled_at: float | None
    recovery_codes_remaining: int
    required: bool
    webauthn_enrolled: bool = False


@dataclass(frozen=True)
class BootstrapAdmin:
    """Credentials for the one-time bootstrap admin (printed once, then must be changed)."""

    username: str
    password: str


@dataclass(frozen=True)
class CustomRoleInfo:
    """An admin-defined custom role and its resolved permission subset (ADR 0045)."""

    id: str
    display_name: str
    description: str | None
    permissions: frozenset[Permission]


def _row_builtin(row: Any) -> bool:
    """Whether a ``roles`` row is a built-in. Tolerant of each backend's truthy representation of the
    ``builtin`` column (SQLite ``int`` 0/1, Postgres ``bool``, SQL Server ``bit``)."""
    return bool(row["builtin"])


def _roles_from_ids(ids: Iterable[str]) -> frozenset[Role]:
    """Map stored role ids to :class:`Role`; silently drop unknown ids (deny-by-default)."""
    out: set[Role] = set()
    for rid in ids:
        try:
            out.add(Role(rid))
        except ValueError:
            continue
    return frozenset(out)


def _json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True)


def _allowed_channels(user: UserRecord, roles: frozenset[Role]) -> frozenset[str] | None:
    """Resolve a user's per-channel RBAC scope to a frozenset, or ``None`` for all channels.

    Administrators are always all-channels. A NULL ``channel_scope`` is all; a JSON list is exactly
    those connections; anything malformed is treated as **no** channels (deny-by-default)."""
    if Role.ADMINISTRATOR in roles or user.channel_scope is None:
        return None
    try:
        names = json.loads(user.channel_scope)
    except (ValueError, TypeError):
        return frozenset()
    if not isinstance(names, list):
        return frozenset()
    return frozenset(str(n) for n in names)


class AuthService:
    """Authentication + RBAC orchestration over an :class:`AuthStore` and the configured directory."""

    def __init__(
        self,
        store: AdminStore,
        settings: AuthSettings,
        *,
        ldap: LdapAuthenticator | None = None,
        security_notifier: SecurityNotifier | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        self.enabled = settings.enabled
        # Out-of-band security-event push (ASVS 6.3.5/6.3.7), injected by the API lifespan. None = no
        # email push (the audited /me/security-events feed still records everything). Best-effort.
        self._security_notifier = security_notifier
        self._policy = PasswordPolicy(
            min_length=settings.password_min_length,
            require_uppercase=settings.password_require_uppercase,
            require_lowercase=settings.password_require_lowercase,
            require_digit=settings.password_require_digit,
            require_symbol=settings.password_require_symbol,
            check_breached=settings.password_check_breached,
            check_context=settings.password_check_context,
            check_username=settings.password_check_username,
            breach_corpus_file=settings.password_breach_corpus_file,
            lockout_threshold=settings.lockout_threshold,
            lockout_minutes=settings.lockout_minutes,
        )
        _warn_if_corpus_unreadable(settings.password_breach_corpus_file)
        if ldap is not None:
            self._ldap: LdapAuthenticator | None = ldap
        elif settings.ad_enabled:
            self._ldap = LdapAuthenticator(settings)
        else:
            self._ldap = None
        # Instance-scoped (one event loop per AuthService) so it never crosses loops in tests.
        self._argon2_sem = asyncio.Semaphore(_ARGON2_MAX_CONCURRENCY)
        self._login_limiter: SlidingWindowRateLimiter | None = (
            SlidingWindowRateLimiter(
                per_key=settings.login_rate_limit_per_ip,
                glob=settings.login_rate_limit_global,
                window_seconds=settings.login_rate_limit_window_seconds,
            )
            if settings.login_rate_limit_enabled
            else None
        )
        # Per-actor anti-automation throttle for the PHI-read endpoints (WP-8, ASVS 2.4.1).
        self._phi_read_limiter: SlidingWindowRateLimiter | None = (
            SlidingWindowRateLimiter(
                per_key=settings.phi_read_rate_limit_per_actor,
                glob=settings.phi_read_rate_limit_global,
                window_seconds=settings.phi_read_rate_limit_window_seconds,
            )
            if settings.phi_read_rate_limit_enabled
            else None
        )
        # Per-actor anti-automation pacing for the state-changing admin surface (BACKLOG #193, ASVS
        # 2.4.2). Built like _phi_read_limiter but consulted from the step-up gate for NON-GET sensitive
        # ops. glob=0 (no cross-actor dimension): one operator's write burst must never throttle
        # another's, and a single unified engine has no need for a global write ceiling here.
        self._admin_write_limiter: SlidingWindowRateLimiter | None = (
            SlidingWindowRateLimiter(
                per_key=settings.admin_write_rate_limit_per_actor,
                glob=0,
                window_seconds=settings.admin_write_rate_limit_window_seconds,
            )
            if settings.admin_write_rate_limit_enabled
            else None
        )
        # Per-process dedup of the WP-L3-13 new-client-IP audit/notify side effects: token_hash → the
        # last new client address already flagged for that session. Bounded (_NEW_IP_DEDUP_MAX).
        self._new_ip_seen: dict[str, str] = {}
        # In-flight WebAuthn ceremony challenges (ADR 0068 §2): bounded, TTL'd, process-local —
        # the rate-limiter precedent (single API process is structural). Keys are token-hashes the
        # SERVICE computes; the cache module never sees a session token.
        self._webauthn_challenges = webauthn.ChallengeCache()
        # Single-use per-action step-up grants (ADR 0077): (token_hash, action) -> monotonic deadline.
        # Bounded, TTL'd, process-local — the same shape as the WebAuthn ceremony cache above (and the
        # same accepted per-process caveat). Minted ONLY by reauth(purpose=...) — never by login or
        # verify_mfa — so a login-seeded step-up window can't authorize a durable factor-binding action.
        self._action_step_up_grants: dict[tuple[str, str], float] = {}
        # Boot-time Kerberos acceptor preflight outcome (ADR 0068 §9): None = usable (or the
        # preflight never ran); a reason string = browser SSO degraded until restart.
        self._kerberos_unavailable_reason: str | None = None

    async def _argon2(self, fn: Callable[..., _T], *args: Any) -> _T:
        """Run a (CPU-heavy) argon2 hash/verify off-thread under the concurrency cap."""
        async with self._argon2_sem:
            return await asyncio.to_thread(fn, *args)

    def allow_login_attempt(self, client: str | None) -> bool:
        """Rate-limit gate for the unauthenticated auth surface (AUTH-RATE). True = proceed."""
        if self._login_limiter is None:
            return True
        return self._login_limiter.allow(client or "unknown")

    def allow_phi_read(self, actor: str) -> bool:
        """Per-actor anti-automation gate for the PHI-read endpoints (WP-8, ASVS 2.4.1). True =
        proceed; False = throttle. Always True when the limiter is disabled."""
        if self._phi_read_limiter is None:
            return True
        return self._phi_read_limiter.allow(actor)

    def allow_admin_write(self, actor: str) -> bool:
        """Per-actor anti-automation pacing for the state-changing admin surface (BACKLOG #193, ASVS
        2.4.2). True = proceed; False = throttle. Always True when the limiter is disabled."""
        if self._admin_write_limiter is None:
            return True
        return self._admin_write_limiter.allow(actor)

    @property
    def policy(self) -> PasswordPolicy:
        return self._policy

    @property
    def ad_enabled(self) -> bool:
        return self._ldap is not None

    @property
    def action_step_up_required(self) -> bool:
        """Whether the durable-takeover routes gate on a per-action step-up grant (ADR 0077, default)
        vs. the legacy session-window step-up. Drives the ``require_step_up_action`` /
        ``require_reauth_only_action`` fallback so an org can opt out via
        ``[auth].require_action_step_up = false``."""
        return self._settings.require_action_step_up

    @property
    def kerberos_enabled(self) -> bool:
        return self._settings.kerberos_enabled and self._ldap is not None

    @property
    def kerberos_available(self) -> bool:
        """``kerberos_enabled`` AND the boot-time acceptor preflight (when run) passed. Drives
        /auth/providers' ``kerberos`` flag, the /ui/login SSO link, and GET /ui/sso — a degraded
        acceptor turns browser SSO off legibly instead of failing per-request. Boot-once: a
        transient DC/SPN failure at start sticks until restart (ADR 0068 §9 open item). The JSON
        /auth/negotiate deliberately keeps its per-request attempt (additive-only)."""
        return self.kerberos_enabled and self._kerberos_unavailable_reason is None

    def mark_kerberos_unavailable(self, reason: str) -> None:
        """Record a failed boot-time SPNEGO acceptor preflight (app lifespan, ADR 0068 §9)."""
        self._kerberos_unavailable_reason = reason

    async def audit_kerberos_reject(self, reason: str) -> None:
        """AUTH-K-AUDIT for route-level SSO rejects that never reach ``authenticate_kerberos``
        (cross-site hygiene, rate-limit exhaustion, malformed base64) — every reject path of a
        Windows-SSO attempt must be visible to a defender."""
        await self._kerberos_reject_audit("<kerberos>", reason)

    # --- lifecycle -----------------------------------------------------------

    async def initialize(self) -> BootstrapAdmin | None:
        """Seed the built-in roles and, on an empty store, create the bootstrap admin. Also retires an
        unclaimed bootstrap that became superseded/expired while the service was down (WP-3)."""
        await self._seed_roles()
        created = await self._ensure_bootstrap_admin()
        await self._retire_superseded_bootstrap()
        return created

    async def _seed_roles(self) -> None:
        for role in Role:
            label, description = ROLE_METADATA[role]
            await self._store.upsert_role(
                role_id=role.value, display_name=label, description=description, builtin=True
            )

    async def _ensure_bootstrap_admin(self) -> BootstrapAdmin | None:
        if await self._store.count_users() > 0:
            return None
        password = self._generate_policy_password()
        user_id = uuid4().hex
        await self._store.create_user(
            user_id=user_id,
            username=BOOTSTRAP_USERNAME,
            auth_provider=AuthProvider.LOCAL.value,
            display_name="Bootstrap Administrator",
            password_hash=await self._argon2(hash_password, password),
            must_change_password=True,
        )
        await self._store.set_user_roles(
            user_id, [Role.ADMINISTRATOR.value], assigned_by="bootstrap"
        )
        await self._audit("auth.bootstrap_admin_created", actor="bootstrap")
        return BootstrapAdmin(username=BOOTSTRAP_USERNAME, password=password)

    def _generate_policy_password(self) -> str:
        """A random password that satisfies the active policy — so the printed bootstrap credential
        is held to the same bar operators are. ``token_urlsafe(n)`` yields ~1.33·n chars (so length is
        guaranteed ≥ ``min_length``); the loop covers the astronomically-unlikely breach/context hit
        or an opt-in character-class requirement a given token happens to miss."""
        length = max(16, self._policy.min_length)
        for _ in range(16):
            candidate = secrets.token_urlsafe(length)
            if not self._policy.violations(candidate):
                return candidate
        return secrets.token_urlsafe(length) + "aA1!"  # defensive: satisfies any class requirement

    async def _other_enabled_admin_exists(self, exclude_id: str) -> bool:
        """True iff some enabled administrator other than ``exclude_id`` exists."""
        for user in await self._store.list_users():
            if user.disabled or user.id == exclude_id:
                continue
            if Role.ADMINISTRATOR.value in await self._store.get_user_role_ids(user.id):
                return True
        return False

    async def _retire_superseded_bootstrap(self, now: float | None = None) -> None:
        """Disable the first-run bootstrap admin once it's no longer needed (WP-3): when a **second**
        administrator exists, or — while still **unclaimed** (never password-changed) — once its expiry
        window lapses. Only ever touches an unclaimed bootstrap (``must_change_password`` still set): if
        the operator changed its password it is a normal admin account and is left alone, so this can't
        lock out a legitimate single-admin deployment."""
        now = time.time() if now is None else now
        boot = await self._store.get_user_by_username(BOOTSTRAP_USERNAME)
        if boot is None or boot.disabled or not boot.must_change_password:
            return  # gone, already disabled, or claimed (a real account now)
        expiry_hours = self._settings.bootstrap_expiry_hours
        expired = expiry_hours > 0 and now >= boot.created_at + expiry_hours * 3600
        superseded = await self._other_enabled_admin_exists(boot.id)
        if not (expired or superseded):
            return
        await self._store.set_user_disabled(boot.id, disabled=True)
        await self._store.revoke_user_sessions(boot.id)
        await self._audit(
            "auth.bootstrap_admin_retired",
            actor="system",
            detail=_json({"reason": "superseded" if superseded else "expired"}),
        )

    # --- login ---------------------------------------------------------------

    async def login(
        self,
        username: str,
        password: str,
        *,
        provider: AuthProvider = AuthProvider.LOCAL,
        client: str | None = None,
    ) -> LoginOutcome:
        if provider is AuthProvider.AD:
            return await self._login_ad(username, password, client=client)
        return await self._login_local(username, password, client=client)

    async def _login_local(
        self, username: str, password: str, *, client: str | None
    ) -> LoginOutcome:
        # Enforce bootstrap expiry/supersession before the credential check: an unclaimed bootstrap
        # that lapsed (or was superseded) is disabled here, so the disabled-account path below refuses
        # it like any other invalid login (WP-3). Scoped to the bootstrap username to keep normal
        # logins free of the extra lookups.
        if username == BOOTSTRAP_USERNAME:
            await self._retire_superseded_bootstrap()
        user = await self._store.get_user_by_username(username)
        if user is None or user.auth_provider != AuthProvider.LOCAL.value or user.disabled:
            # Equalize timing with the real-password path so a missing/disabled/AD account is not
            # distinguishable from a wrong password (defeats username enumeration via latency).
            await self._argon2(verify_password, _DUMMY_PASSWORD_HASH, password)
            await self._audit(
                "auth.login_failed",
                actor=username,
                detail=_json({"provider": "local", "reason": "unknown_or_disabled"}),
            )
            return LoginOutcome(ok=False, error="invalid credentials")
        now = time.time()
        if user.locked_until is not None and now < user.locked_until:
            await self._argon2(verify_password, _DUMMY_PASSWORD_HASH, password)
            await self._audit("auth.login_locked", actor=username)
            return LoginOutcome(ok=False, error="account locked")
        if user.password_hash is None or not await self._argon2(
            verify_password, user.password_hash, password
        ):
            attempts, just_locked = await self._register_failure(user, now)
            await self._audit(
                "auth.login_failed",
                actor=username,
                detail=_json({"provider": "local", "reason": "bad_password"}),
            )
            if just_locked:
                await self._notify_security(
                    ACCOUNT_LOCKED,
                    username=user.username,
                    email=user.email,
                    client=client,
                    detail={"failed_attempts": attempts},
                )
            return LoginOutcome(ok=False, error="invalid credentials")
        if await asyncio.to_thread(needs_rehash, user.password_hash):
            await self._store.set_password(
                user.id,
                password_hash=await self._argon2(hash_password, password),
                must_change_password=user.must_change_password,
            )
        prior_failures = user.failed_attempts  # captured before record_login_success resets it
        await self._store.record_login_success(user.id, now=now)
        identity = await self._build_identity(user)
        # A second factor (TOTP / recovery code / passkey) is pending for an enrolled user — or an
        # Administrator when require_mfa is on. Issue the session un-MFA'd; the client completes via
        # /auth/mfa-verify (or the browser passkey leg at /ui/reauth, ADR 0068).
        mfa_required = self._mfa_required_for(
            user, identity.roles, second_factor_enrolled=await self._second_factor_enrolled(user)
        )
        token = await self._issue_session(user.id, client, mfa_verified=not mfa_required)
        await self._audit(
            "auth.login_success",
            actor=user.username,
            detail=_json({"provider": "local", "mfa_required": mfa_required}),
        )
        if prior_failures >= SUSPICIOUS_LOGIN_FAILURE_THRESHOLD:
            # A successful login right after a run of failures is the classic compromised/attacked
            # signal (ASVS 6.3.5) — notify the owner out-of-band so they can react if it wasn't them.
            await self._notify_security(
                LOGIN_AFTER_FAILURES,
                username=user.username,
                email=user.email,
                client=client,
                detail={"failed_attempts": prior_failures},
            )
        return LoginOutcome(
            ok=True,
            token=token,
            identity=identity,
            must_change_password=user.must_change_password,
            mfa_required=mfa_required,
        )

    async def _register_failure(self, user: UserRecord, now: float) -> tuple[int, bool]:
        """Record a failed attempt; return ``(attempts, just_locked)``. ``just_locked`` is True only on
        the attempt that crosses the threshold (the caller reaches here only when not already locked),
        so it fires exactly one lockout notification per lockout."""
        # A lapsed lockout window restarts the counter, so one post-lockout failure cannot re-lock
        # immediately (and the stale lock is cleared whenever the count is back below threshold).
        prior = (
            0
            if (user.locked_until is not None and now >= user.locked_until)
            else user.failed_attempts
        )
        attempts = prior + 1
        locked_until = (
            now + self._policy.lockout_minutes * 60
            if attempts >= self._policy.lockout_threshold
            else None
        )
        await self._store.record_login_failure(
            user.id, failed_attempts=attempts, locked_until=locked_until, now=now
        )
        return attempts, locked_until is not None

    async def _login_ad(self, username: str, password: str, *, client: str | None) -> LoginOutcome:
        if self._ldap is None:
            return LoginOutcome(ok=False, error="AD authentication is not configured")
        try:
            principal = await asyncio.to_thread(self._ldap.authenticate, username, password)
        except LdapError as exc:
            await self._audit(
                "auth.login_error",
                actor=username,
                detail=_json({"provider": "ad", "error": str(exc)}),
            )
            return LoginOutcome(ok=False, error="directory unavailable")
        if principal is None:
            await self._audit("auth.login_failed", actor=username, detail=_json({"provider": "ad"}))
            return LoginOutcome(ok=False, error="invalid credentials")
        return await self._complete_ad_login(principal, client)

    async def authenticate_kerberos(
        self, token: bytes, *, client: str | None = None, seed_reauth: bool = True
    ) -> LoginOutcome:
        # Audit every reject path so blocked/failed Windows-SSO attempts are not invisible to a
        # defender (AUTH-K-AUDIT). A sentinel actor is used until the principal is known.
        if self._ldap is None or not self._settings.kerberos_enabled:
            await self._kerberos_reject_audit("<kerberos>", "not_configured")
            return LoginOutcome(ok=False, error="Windows SSO is not configured")
        try:
            username = await asyncio.to_thread(kerberos_principal, token, self._settings)
            if username is None:
                await self._kerberos_reject_audit("<kerberos>", "no_principal")
                return LoginOutcome(ok=False, error="SSO authentication failed")
            principal = await asyncio.to_thread(self._ldap.resolve_principal, username)
        except LdapError as exc:
            await self._audit(
                "auth.login_error",
                actor="<kerberos>",
                detail=_json({"provider": "ad", "mech": "kerberos", "error": str(exc)}),
            )
            return LoginOutcome(ok=False, error="directory unavailable")
        if principal is None:
            await self._kerberos_reject_audit(username, "not_in_directory")
            return LoginOutcome(ok=False, error="user not found in directory")
        return await self._complete_ad_login(principal, client, seed_reauth=seed_reauth)

    async def _kerberos_reject_audit(self, actor: str, reason: str) -> None:
        await self._audit(
            "auth.login_failed",
            actor=actor,
            detail=_json({"provider": "ad", "mech": "kerberos", "reason": reason}),
        )

    async def _complete_ad_login(
        self, principal: AdPrincipal, client: str | None, *, seed_reauth: bool = True
    ) -> LoginOutcome:
        existing = await self._store.get_user_by_username(principal.username)
        if existing is not None and existing.auth_provider != AuthProvider.AD.value:
            # Never let an AD login adopt/overwrite a like-named LOCAL account (provider confusion).
            await self._audit(
                "auth.login_failed",
                actor=principal.username,
                detail=_json({"provider": "ad", "reason": "local_account_conflict"}),
            )
            return LoginOutcome(ok=False, error="account conflict")
        user = await self._upsert_ad_user(principal)
        role_ids = sorted(await self._store.roles_for_ad_groups(principal.groups))
        previous = set(await self._store.get_user_role_ids(user.id))
        await self._store.set_user_roles(user.id, role_ids, assigned_by="ad-sync")
        if set(role_ids) != previous:
            # Directory-side role change (often a downgrade): revoke the user's other live sessions
            # so stale elevated tokens don't linger until expiry (AUTH-AD-REVOKE). The new session
            # is issued below, after this, so the current login is unaffected.
            await self._store.revoke_user_sessions(user.id)
            await self._audit(
                "auth.ad_roles_resynced",
                actor=user.username,
                detail=_json({"from": sorted(previous), "to": role_ids}),
            )
            # A directory-pushed privilege change is the same privilege change to the same user as a
            # local one, so notify the affected user out-of-band too (ASVS 6.3.7), matching set_roles().
            # Best-effort; the change is also visible in the audited /me/security-events feed.
            await self._notify_security(
                ROLES_CHANGED,
                username=user.username,
                email=user.email,
                client=client,
                detail={"roles": role_ids},
            )
        await self._store.record_login_success(user.id)
        ad_roles = _roles_from_ids(role_ids)
        ad_custom_permissions = await self._custom_permissions_for_ids(role_ids)
        user = await self._sync_ad_channel_scope(user, ad_roles, principal.groups)
        identity = Identity.build(
            user_id=user.id,
            username=user.username,
            auth_provider=AuthProvider.AD,
            roles=ad_roles,
            allowed_channels=_allowed_channels(user, ad_roles),
            extra_permissions=ad_custom_permissions,
        )
        # AD/Kerberos MFA is delegated to the directory (Entra Conditional Access / MFA proxy), so the
        # session is MFA-satisfied at issuance — an engine TOTP is never prompted for a directory login.
        token = await self._issue_session(
            user.id, client, mfa_verified=True, seed_reauth=seed_reauth
        )
        await self._audit(
            "auth.login_success",
            actor=user.username,
            detail=_json({"provider": "ad", "roles": role_ids}),
        )
        return LoginOutcome(ok=True, token=token, identity=identity)

    async def _sync_ad_channel_scope(
        self, user: UserRecord, roles: frozenset[Role], groups: Iterable[str]
    ) -> UserRecord:
        """Persist a user's AD-group-derived per-channel scope (C3) so it's durable for later
        requests (mirrors role sync). Administrators are always all-channels. If no group mapping
        matches, the per-user scope is left untouched — opt-in, so it never clobbers a manual scope
        or the all-channels default. Returns the (possibly refreshed) user record."""
        if Role.ADMINISTRATOR in roles:
            return user
        channels = await self._store.channels_for_ad_groups(groups)
        if not channels:
            return user
        specific = sorted(c for c in channels if c != "*")
        scope_json = None if "*" in channels else _json(specific)
        if user.channel_scope == scope_json:
            return user
        await self._store.set_user_channel_scope(user.id, scope_json)
        await self._store.revoke_user_sessions(
            user.id
        )  # drop stale-scope tokens (new one issued after)
        await self._audit(
            "auth.ad_scope_resynced",
            actor=user.username,
            detail=_json({"channels": "*" if scope_json is None else specific}),
        )
        return await self._store.get_user(user.id) or user

    async def _upsert_ad_user(self, principal: AdPrincipal) -> UserRecord:
        existing = await self._store.get_user_by_username(principal.username)
        if existing is None:
            user_id = uuid4().hex
            await self._store.create_user(
                user_id=user_id,
                username=principal.username,
                auth_provider=AuthProvider.AD.value,
                display_name=principal.display_name,
                email=principal.email,
            )
        else:
            user_id = existing.id
            await self._store.update_user_profile(
                user_id, display_name=principal.display_name, email=principal.email
            )
        user = await self._store.get_user(user_id)
        assert user is not None  # just upserted
        return user

    # --- sessions ------------------------------------------------------------

    async def _issue_session(
        self,
        user_id: str,
        client: str | None,
        *,
        mfa_verified: bool,
        seed_reauth: bool | None = None,
    ) -> str:
        token = mint_token()
        token_hash = hash_token(token)
        expires_at = time.time() + self._settings.session_absolute_hours * 3600
        await self._store.create_session(
            token_hash=token_hash,
            user_id=user_id,
            expires_at=expires_at,
            client=client,
            # Seed the step-up window from login ONLY for a fully-authenticated session. An MFA-pending
            # session gets no step-up freshness, so enrolling a first authenticator (or any step-up op)
            # requires an explicit password re-verify — a stolen pre-MFA token can't ride login's
            # freshness to bind an attacker-controlled authenticator (WP-14).
            # seed_reauth=False overrides that for browser Kerberos SSO (ADR 0068 §9): the session's
            # proof is AMBIENT, so it must not be born with a free step-up window — the first
            # sensitive action forces the directory-password step-up.
            seed_reauth=mfa_verified if seed_reauth is None else seed_reauth,
        )
        if mfa_verified:
            # No second factor pending (MFA not required for this user, or delegated to AD/Kerberos):
            # mark the session's 2nd factor satisfied at issuance so the step-up gate never blocks it.
            # An MFA-required local login leaves it NULL until POST /auth/mfa-verify (WP-14).
            await self._store.mark_session_mfa_verified(token_hash)
        cap = self._settings.max_sessions_per_user
        if cap and cap > 0:
            # Evict the oldest sessions beyond the cap (the just-created one is newest, so survives).
            await self._store.enforce_session_cap(user_id, keep=cap)
        return token

    async def identity_for_token(
        self, token: str | None, *, activity: bool = True
    ) -> Identity | None:
        """Validate a bearer token (existence, revocation, clock, absolute + idle timeout) and
        resolve the caller's :class:`Identity`.

        ``activity=True`` (the default, for user-driven requests) refreshes the session's idle
        clock; pass ``activity=False`` for background re-checks (e.g. a long-lived WebSocket) so a
        passively-polled token still ages out against real user activity (AUTH-IDLE).
        """
        if not token:
            return None
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return None
        now = time.time()
        # Fail closed on a backward wall-clock step (NTP step-back, VM snapshot revert): a session
        # stamped in the "future" can't be aged correctly, so revoke rather than silently revive an
        # already-expired one or reset its idle window (AUTH-CLOCK).
        if now < session.created_at or now < session.last_used_at:
            await self._store.revoke_session(session.token_hash, now=now)
            return None
        if now > session.expires_at:
            await self._store.revoke_session(session.token_hash, now=now)
            return None
        if now - session.last_used_at > self._settings.session_idle_timeout_minutes * 60:
            await self._store.revoke_session(session.token_hash, now=now)
            return None
        if activity:
            await self._store.touch_session(session.token_hash, now=now)
        user = await self._store.get_user(session.user_id)
        if user is None or user.disabled:
            return None
        return await self._build_identity(user)

    async def identity_for_username(self, username: str) -> Identity | None:
        """Resolve a username directly to its :class:`Identity` (roles + custom-role overlay), or
        ``None`` when the user is unknown or disabled — WITHOUT a bearer session.

        Used by the mTLS-client-cert → principal path (#200, ADR 0002): a VERIFIED peer cert whose
        subject maps (via ``[api].tls_client_cert_identities``) to a username is resolved here to the
        principal whose RBAC then authorizes the service-to-service request. A disabled account grants
        no identity (fail-closed), exactly as the token path treats it (:meth:`identity_for_token`)."""
        user = await self._store.get_user_by_username(username)
        if user is None or user.disabled:
            return None
        return await self._build_identity(user)

    async def identity_for_user_id(self, user_id: str) -> Identity | None:
        """Resolve a user id directly to its :class:`Identity` (roles + custom-role overlay), or
        ``None`` when no such user exists — WITHOUT a bearer session.

        Used by the effective-permission inspector (BACKLOG #177): an admin resolves the FLATTENED
        effective permission set (built-in-role ∪ custom-role ∪ extras) for an arbitrary user via the
        same :meth:`Identity.build` path :meth:`identity_for_token` uses for the caller. Unlike the
        token / username auth paths, a *disabled* user still resolves here — the point is to inspect a
        user's grants for troubleshooting (including a locked-out account), not to authenticate them."""
        user = await self._store.get_user(user_id)
        if user is None:
            return None
        return await self._build_identity(user)

    async def logout(self, token: str | None, *, actor: str | None = None) -> None:
        if token:
            await self._store.revoke_session(hash_token(token))
            # Emit the documented auth.logout event (SECURITY.md, ASVS 16.3.3) — previously the
            # session was revoked silently, contradicting the doc and leaving a gap in the trail.
            await self._audit("auth.logout", actor=actor)

    # --- session inventory + targeted revoke (WP-10, ASVS 7.5.2/7.4.5) -------

    async def list_sessions(self, user_id: str) -> list[SessionRecord]:
        """A user's active sessions — the self-service session inventory."""
        return await self._store.list_sessions(user_id)

    async def revoke_own_session(self, identity: Identity, session_id: str, *, actor: str) -> bool:
        """Revoke one of ``identity``'s **own** sessions by id (its ``token_hash``). Returns ``False``
        if the session doesn't exist or isn't the caller's — so the API answers 404 without revealing
        or letting a user touch another's session. Audited."""
        session = await self._store.get_session(session_id)
        if session is None or session.user_id != identity.user_id:
            return False
        await self._store.revoke_session(session_id)
        await self._audit(
            "auth.session_revoked",
            actor=actor,
            detail=_json({"scope": "self", "session": session_id[:12]}),
        )
        return True

    async def revoke_other_sessions(
        self, identity: Identity, current_token_hash: str, *, actor: str
    ) -> int:
        """Revoke all of ``identity``'s sessions **except** the caller's current one ("sign out
        everywhere else"). Returns the count revoked. Audited when any were revoked."""
        revoked = await self._store.revoke_user_sessions(
            identity.user_id, except_token_hash=current_token_hash
        )
        if revoked:
            await self._audit(
                "auth.session_revoked",
                actor=actor,
                detail=_json({"scope": "self_others", "count": revoked}),
            )
        return revoked

    async def revoke_sessions_for_user(self, user_id: str, *, actor: str) -> int:
        """Admin: revoke **all** of a user's sessions (force sign-out everywhere). Returns the count.
        Audited."""
        revoked = await self._store.revoke_user_sessions(user_id)
        await self._audit(
            "auth.session_revoked",
            actor=actor,
            detail=_json({"scope": "admin", "user_id": user_id, "count": revoked}),
        )
        return revoked

    async def _custom_permissions_for_ids(self, role_ids: Iterable[str]) -> frozenset[Permission]:
        """Resolve the permission overlay for any custom (``custom:``-prefixed) role ids the user holds
        (ADR 0045 D3). Each is looked up in the ``roles`` table and its persisted ``permissions`` JSON
        defensively decoded (unknown/forbidden values dropped — deny-by-default). A built-in id, an
        unknown id, or a row with no permissions contributes nothing."""
        granted: set[Permission] = set()
        for rid in role_ids:
            if not is_custom_role_id(rid):
                continue
            row = await self._store.get_role(rid)
            if row is None:
                continue  # custom role deleted since assignment → grants nothing (deny-by-default)
            granted |= decode_custom_role_permissions(row["permissions"])
        return frozenset(granted)

    async def _build_identity(self, user: UserRecord) -> Identity:
        role_ids = await self._store.get_user_role_ids(user.id)
        roles = _roles_from_ids(role_ids)
        custom_permissions = await self._custom_permissions_for_ids(role_ids)
        provider = (
            AuthProvider(user.auth_provider)
            if user.auth_provider in (AuthProvider.LOCAL.value, AuthProvider.AD.value)
            else AuthProvider.LOCAL
        )
        return Identity.build(
            user_id=user.id,
            username=user.username,
            auth_provider=provider,
            roles=roles,
            must_change_password=user.must_change_password,
            allowed_channels=_allowed_channels(user, roles),
            extra_permissions=custom_permissions,
        )

    # --- password management -------------------------------------------------

    def password_violations(self, password: str, *, username: str | None = None) -> list[str]:
        return self._policy.violations(password, username=username)

    async def verify_current_password(self, identity: Identity, password: str) -> bool:
        """True iff ``password`` matches the local user's stored hash (self-service reauth)."""
        user = await self._store.get_user(identity.user_id)
        if user is None or user.password_hash is None:
            return False
        return await self._argon2(verify_password, user.password_hash, password)

    async def reauth(
        self,
        identity: Identity,
        password: str,
        *,
        token: str,
        client: str | None = None,
        purpose: str | None = None,
    ) -> bool:
        """Step-up re-verification (ASVS 7.5.3): re-prove the caller's credential and, on success,
        refresh the current session's ``reauth_at`` so it may perform highly sensitive operations for
        the configured window. Local accounts re-verify the password (argon2); **AD accounts do a live
        re-bind** against the directory so AD operators aren't locked out. Always audited.

        ``purpose`` (ADR 0077) additionally mints a **single-use, action-bound** step-up grant for that
        named action, so a durable-takeover route (TOTP enroll/confirm, disable-MFA) can require a fresh
        proof tied to *it* rather than riding the broad session window. It is purely
        additive — the session-window refresh above is unchanged (the broad admin/replay/config routes
        keep using it), and the grant is minted ONLY here, never by login or ``verify_mfa``."""
        if identity.auth_provider is AuthProvider.AD:
            ok = await self._reauth_ad(identity.username, password)
        else:
            ok = await self.verify_current_password(identity, password)
        if ok:
            # Re-anchor the session to the address it re-verified from, so a forced step-up triggered
            # by a roamed/new client IP (WP-L3-13) clears once the caller re-proves from there.
            await self._store.mark_session_reauthed(hash_token(token), client=client)
            if purpose is not None:
                # Bind THIS fresh proof to the single action named by `purpose` (single-use), so a broad
                # login-seeded window can never authorize a factor-binding action (ASVS 7.5.1 / 8.2.4).
                self._grant_action_step_up(hash_token(token), purpose)
        await self._audit(
            "auth.reauth",
            actor=identity.username,
            detail=_json({"ok": ok, "provider": identity.auth_provider.value, "purpose": purpose}),
        )
        return ok

    def _grant_action_step_up(self, token_hash: str, action: str) -> None:
        """Mint a single-use per-action step-up grant (ADR 0077), bounded + TTL'd, process-local.

        The deadline reuses ``[auth].step_up_max_age_seconds`` so a minted-but-unconsumed grant expires
        on the same clock as the session window. On the global-bound overflow the OLDEST grant is
        evicted (fail-safe: a dropped grant just re-prompts, never a bypass)."""
        now = time.monotonic()
        self._prune_action_step_up_grants(now)
        key = (token_hash, action)
        if key not in self._action_step_up_grants and (
            len(self._action_step_up_grants) >= _ACTION_STEP_UP_GRANT_MAX
        ):
            oldest = min(self._action_step_up_grants, key=self._action_step_up_grants.__getitem__)
            del self._action_step_up_grants[oldest]
        self._action_step_up_grants[key] = now + self._settings.step_up_max_age_seconds

    def _prune_action_step_up_grants(self, now: float) -> None:
        """Drop expired per-action grants (monotonic clock — a wall-clock step can't widen the window)."""
        expired = [k for k, deadline in self._action_step_up_grants.items() if deadline <= now]
        for key in expired:
            del self._action_step_up_grants[key]

    async def has_action_step_up(self, token: str | None, action: str) -> bool:
        """Whether the caller holds a fresh step-up grant BOUND to ``action`` — and **consume** it
        (single-use). ADR 0077. A grant is minted only by ``reauth(purpose=action)`` (POST /me/reauth
        or /ui/reauth), never by login or ``verify_mfa``, so a login-seeded step-up window cannot bind a
        new authenticator. Returns False for a missing token / no grant / an expired grant."""
        if not token:
            return False
        now = time.monotonic()
        self._prune_action_step_up_grants(now)
        # pop = single-use: the grant is gone whether or not it was still live (a stale pop is harmless).
        deadline = self._action_step_up_grants.pop((hash_token(token), action), None)
        return deadline is not None and deadline > now

    async def _reauth_ad(self, username: str, password: str) -> bool:
        """Re-verify an AD credential via a live directory re-bind (no session adopted)."""
        if self._ldap is None:
            return False
        try:
            principal = await asyncio.to_thread(self._ldap.authenticate, username, password)
        except LdapError:
            return False
        return principal is not None

    async def has_recent_step_up(self, token: str | None) -> bool:
        """Whether the caller's session re-verified its credential within
        ``[auth].step_up_max_age_seconds`` (login is the first verification) — the gate for sensitive
        operations (ASVS 7.5.3)."""
        if not token:
            return False
        session = await self._store.get_session(hash_token(token))
        if session is None or session.reauth_at is None:
            return False
        return (time.time() - session.reauth_at) <= self._settings.step_up_max_age_seconds

    @staticmethod
    def _same_host(a: str, b: str) -> bool:
        """Whether two client addresses denote the same host: an exact match, **or** both loopback (so a
        dual-stack box that presents ``::1`` on one connection and ``127.0.0.1`` on another is treated as
        one host — this keeps the loopback default a genuine no-op rather than a string mismatch).
        Unparseable values fall back to exact match."""
        if a == b:
            return True
        try:
            return ipaddress.ip_address(a).is_loopback and ipaddress.ip_address(b).is_loopback
        except ValueError:
            return False

    def _remember_new_ip(self, token_hash: str, client_ip: str) -> None:
        """Record the last new client IP flagged for a session — best-effort, per-process dedup of the
        audit/notify side effects only. Bounded so session/address churn can't grow it without limit;
        the step-up decision never depends on this cache (eviction only risks one extra audit row)."""
        if len(self._new_ip_seen) >= _NEW_IP_DEDUP_MAX and token_hash not in self._new_ip_seen:
            self._new_ip_seen.pop(next(iter(self._new_ip_seen)))
        self._new_ip_seen[token_hash] = client_ip

    async def flag_new_client_ip(
        self, token: str | None, client_ip: str | None, *, path: str
    ) -> bool:
        """Admin-interface contextual-risk signal (ASVS 8.4.2, WP-L3-13): return ``True`` when this
        sensitive request arrives from a client address that differs from the one the caller's session
        last verified from. On the **first** observation of a given (session, address) it emits an
        ``auth.admin_action_new_ip`` audit event + a best-effort out-of-band notice; **repeat** hits from
        the same un-cleared address still return ``True`` (so the step-up stays forced) but only log to
        the rotating ops log — so a token replayed in a tight loop from one address cannot inflate the
        audit table / notification channel (mirrors the ``_rate_limited`` precedent). The step-up
        dependencies treat ``True`` as "force a fresh step-up"; a successful re-verify (``POST
        /me/reauth`` **or** ``/auth/mfa-verify``) re-anchors the session to the new address (see
        :meth:`reauth` / :meth:`verify_mfa`), so the signal clears and the caller proceeds. It is
        **advisory + step-up-forcing only** — it never changes an authorization decision and never
        blocks the non-admin request path.

        Disabled (returns ``False`` with no side effects) unless ``[auth].admin_new_ip_step_up`` is on,
        so loopback behavior is byte-identical by default; and even on, a single-host loopback session
        never trips it because the request and the session resolve to the same loopback host (IPv4 or
        IPv6 — see :meth:`_same_host`)."""
        if not self._settings.admin_new_ip_step_up or not token:
            return False
        token_hash = hash_token(token)
        session = await self._store.get_session(token_hash)
        if session is None or session.revoked_at is not None:
            return False
        # No baseline address (older session / unknown login source) or the same host → not new. A
        # session with no recorded address is not penalized, to avoid spurious admin friction.
        if not session.client or not client_ip or self._same_host(client_ip, session.client):
            return False
        # New address → force a step-up (return True unconditionally). Emit the audit + notice once per
        # (session, address); suppress repeats from the same un-cleared address so a replayed token
        # cannot amplify the audit log / notifications.
        if self._new_ip_seen.get(token_hash) == client_ip:
            _log.warning(
                "admin action from already-flagged new client IP (repeat suppressed): path=%s", path
            )
            return True
        self._remember_new_ip(token_hash, client_ip)
        user = await self._store.get_user(session.user_id)
        username = user.username if user is not None else session.user_id
        await self._audit(
            "auth.admin_action_new_ip",
            actor=username,
            detail=_json({"path": path, "known_ip": session.client, "seen_ip": client_ip}),
        )
        await self._notify_security(
            ADMIN_NEW_IP,
            username=username,
            email=user.email if user is not None else None,
            client=client_ip,
            detail={"known_ip": session.client},
        )
        return True

    async def change_password(
        self,
        identity: Identity,
        new_password: str,
        *,
        must_change: bool = False,
        client: str | None = None,
    ) -> list[str]:
        """Set a local user's password (after policy check) and revoke their other sessions.

        Returns policy violations (empty list = changed). No-op-safe for AD identities at the API
        layer, which rejects password changes for AD users before calling this.
        """
        violations = self._policy.violations(new_password, username=identity.username)
        if violations:
            return violations
        await self._store.set_password(
            identity.user_id,
            password_hash=await self._argon2(hash_password, new_password),
            must_change_password=must_change,
        )
        await self._store.revoke_user_sessions(identity.user_id)
        await self._audit("auth.password_changed", actor=identity.username)
        user = await self._store.get_user(identity.user_id)
        await self._notify_security(
            PASSWORD_CHANGED,
            username=identity.username,
            email=user.email if user is not None else None,
            client=client,
        )
        return []

    # --- MFA: native TOTP second factor (local accounts, WP-14, ASVS 6.3.3) --

    async def _second_factor_enrolled(self, user: UserRecord) -> bool:
        """Any second factor enrolled — TOTP **or** ≥1 WebAuthn passkey (ADR 0068 decision 5). The
        store round-trip only runs when TOTP alone doesn't already answer."""
        return user.totp_enabled or await self._store.has_webauthn_credentials(user.id)

    def _mfa_required_for(
        self, user: UserRecord, roles: frozenset[Role], *, second_factor_enrolled: bool
    ) -> bool:
        """Whether ``user`` must satisfy a second factor. **Local accounts only** — AD/Kerberos MFA is
        delegated to the directory. An enrolled user (either factor — the caller pre-resolves
        ``second_factor_enrolled`` via :meth:`_second_factor_enrolled`, keeping this hot boolean
        logic sync and the store round-trip visible at each call site) always must; an un-enrolled
        user must when ``[auth].require_mfa`` is on and they hold the Administrator role (the chosen
        enforcement target — regular users opt in by enrolling)."""
        if user.auth_provider != AuthProvider.LOCAL.value:
            return False
        if second_factor_enrolled:
            return True
        return self._settings.require_mfa and Role.ADMINISTRATOR in roles

    async def mfa_satisfied(self, token: str | None) -> bool:
        """Whether the caller's session has met its second-factor requirement — True when the session
        is MFA-verified, **or** when MFA isn't required for this user. Composed with
        :meth:`has_recent_step_up` by the API to gate sensitive operations (WP-14). A required-but-
        unverified session returns False, so the step-up routes 403 until ``POST /auth/mfa-verify``."""
        if not token:
            return False
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return False
        if session.mfa_verified_at is not None:
            return True
        user = await self._store.get_user(session.user_id)
        if user is None:
            return False
        roles = _roles_from_ids(await self._store.get_user_role_ids(user.id))
        # The extra store read only executes for sessions not already MFA-verified (the
        # mfa_verified_at early-return above short-circuits the common case).
        enrolled = await self._second_factor_enrolled(user)
        return not self._mfa_required_for(user, roles, second_factor_enrolled=enrolled)

    async def begin_mfa_enrollment(self, identity: Identity) -> MfaEnrollment:
        """Stage a fresh TOTP secret for a local user and return it + the ``otpauth://`` URI for the
        QR. Not active until proven via :meth:`confirm_mfa_enrollment`. Raises :class:`ValueError` for
        an AD account or when MFA is already enabled (disable it first to re-enroll)."""
        user = await self._store.get_user(identity.user_id)
        if user is None or user.auth_provider != AuthProvider.LOCAL.value:
            raise ValueError("only local users can enroll a TOTP authenticator")
        if user.totp_enabled:
            raise ValueError("MFA is already enabled; disable it before re-enrolling")
        secret = totp.generate_secret()
        await self._store.set_totp_secret(identity.user_id, secret=secret)
        await self._audit("auth.mfa_enroll_started", actor=identity.username)
        return MfaEnrollment(secret=secret, otpauth_uri=totp.otpauth_uri(secret, identity.username))

    async def confirm_mfa_enrollment(
        self, identity: Identity, code: str, *, token: str, client: str | None = None
    ) -> list[str] | None:
        """Confirm a staged enrollment by proving a live TOTP code. On success: activate MFA, mint the
        single-use recovery codes (returned **once**, plaintext, for the user to save), mark the
        current session MFA-verified, audit + notify. Returns the recovery codes, or ``None`` when the
        code was wrong. Raises :class:`ValueError` if no enrollment is staged / the user isn't local."""
        user = await self._store.get_user(identity.user_id)
        if user is None or user.auth_provider != AuthProvider.LOCAL.value:
            raise ValueError("only local users can enroll a TOTP authenticator")
        secret = await self._store.get_totp_secret(identity.user_id)
        if not secret:
            raise ValueError("no enrollment in progress")
        # Verify the enrollment proof under the SAME configured clock-skew window as a login (BACKLOG
        # #187): default 0 = strict current-step only. Enrolling under the same window a login uses
        # avoids the trap of a skewed-clock authenticator that confirms enrollment yet then fails every
        # login (the mismatch surfaces at enroll time instead).
        if not totp.verify_totp(secret, code.strip(), window=self._settings.totp_skew_steps):
            await self._audit(
                "auth.mfa_failed", actor=identity.username, detail=_json({"phase": "enroll"})
            )
            return None
        plain = totp.generate_recovery_codes(self._settings.mfa_recovery_code_count)
        hashes = [await self._argon2(hash_password, c) for c in plain]
        await self._store.enable_totp(identity.user_id, recovery_code_hashes=hashes)
        await self._store.mark_session_mfa_verified(hash_token(token))
        await self._audit("auth.mfa_enrolled", actor=identity.username)
        await self._notify_security(
            MFA_ENABLED, username=user.username, email=user.email, client=client
        )
        return plain

    async def verify_mfa(self, token: str | None, code: str, *, client: str | None = None) -> bool:
        """Validate a TOTP code (or a single-use recovery code) for the caller's session and, on
        success, mark the session's second factor satisfied. Always audited; the API gates this behind
        the login rate limiter. Returns False (never raises) for any invalid input."""
        if not token:
            return False
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return False
        user = await self._store.get_user(session.user_id)
        if user is None or user.disabled or not user.totp_enabled:
            return False
        now = time.time()
        # Per-account lockout covers the SECOND factor too (parity with the password path): a run of
        # wrong codes locks the account, so MFA guessing isn't bounded only by the shared per-IP login
        # limiter (which IP-rotation can sidestep). A locked account is refused before any verify.
        if user.locked_until is not None and now < user.locked_until:
            await self._audit(
                "auth.mfa_failed", actor=user.username, detail=_json({"reason": "locked"})
            )
            return False
        if await self._verify_second_factor(user, code):
            # The 2nd factor is now satisfied; also seed the step-up window (the session has completed
            # password + MFA) and clear the failure counter. (Initial enrollment has no factor to verify,
            # so this never fires there — keeping the enrollment step-up gate honest, WP-14.)
            await self._store.mark_session_mfa_verified(hash_token(token))
            # Re-anchor the session to the address that completed the second factor (parity with
            # reauth), so an MFA-required admin who roamed clears the WP-L3-13 new-client-IP signal with
            # one credential proof rather than being forced into a separate password step-up.
            await self._store.mark_session_reauthed(hash_token(token), client=client)
            await self._store.record_login_success(user.id, now=now)
            await self._audit("auth.mfa_verified", actor=user.username)
            return True
        # Wrong code: register the failure through the SAME machinery the password path uses, so the
        # per-account lockout + ACCOUNT_LOCKED notification fire on sustained MFA guessing.
        attempts, just_locked = await self._register_failure(user, now)
        await self._audit("auth.mfa_failed", actor=user.username)
        if just_locked:
            await self._notify_security(
                ACCOUNT_LOCKED,
                username=user.username,
                email=user.email,
                client=client,
                detail={"failed_attempts": attempts},
            )
        return False

    async def _verify_second_factor(self, user: UserRecord, code: str) -> bool:
        """True iff ``code`` is the user's current TOTP **or** an unused recovery code (consumed on
        match). TOTP is checked first (fast, no argon2); recovery codes are argon2id-hashed and
        single-use. Codes never collide (TOTP is 6 digits; recovery codes are dashed alphanumerics)."""
        code = code.strip()
        if not code:
            return False
        secret = await self._store.get_totp_secret(user.id)
        if secret:
            # Clock-skew window is operator-configurable (BACKLOG #187; ASVS 6.5.5). Default
            # totp_skew_steps=0 accepts only the current 30 s step (strict, tightest replay window);
            # 1/2 is the documented opt-out restoring RFC-6238 network-delay tolerance. verify_totp_step
            # still clamps a tolerated fast-clock future code to the current step (SEC-014), so a wider
            # window never advances the single-use high-water mark past now.
            matched_step = totp.verify_totp_step(
                secret, code, window=self._settings.totp_skew_steps
            )
            if matched_step is not None:
                # Single-use within the step window (ASVS 6.5.1): the store advances the user's
                # highest-consumed time-step atomically, so a code captured and replayed inside its
                # ~30 s verify window resolves to a non-greater step and is rejected. Mirrors the
                # recovery-code compare-and-set; a genuine code always advances the step as time
                # moves forward, so a legitimate later login is unaffected. verify_totp_step clamps a
                # tolerated future (fast-clock) code to the CURRENT step (SEC-014), so consuming it
                # can't advance the high-water mark past now and lock the user out of their own next
                # legitimate code.
                return await self._store.consume_totp_step(user.id, matched_step)
        normalized = code.upper()  # recovery codes are minted uppercase
        hashes = await self._store.get_recovery_code_hashes(user.id)
        for h in hashes:
            if await self._argon2(verify_password, h, normalized):
                # Atomic compare-and-delete: only the caller that actually removes the hash wins, so a
                # concurrent verify of the same single-use code can't double-spend it (WP-14).
                return await self._store.consume_recovery_code_hash(user.id, h)
        return False

    async def disable_mfa(self, identity: Identity, *, client: str | None = None) -> None:
        """Self-service: turn off the caller's TOTP MFA (the API gates this behind step-up). Audited +
        the user is notified out-of-band (ASVS 6.3.7)."""
        user = await self._store.get_user(identity.user_id)
        await self._store.disable_totp(identity.user_id)
        await self._audit(
            "auth.mfa_disabled", actor=identity.username, detail=_json({"scope": "self"})
        )
        await self._notify_security(
            MFA_DISABLED,
            username=identity.username,
            email=user.email if user is not None else None,
            client=client,
        )

    async def admin_reset_mfa(self, user_id: str, *, actor: str) -> None:
        """Admin: clear a user's MFA — TOTP **and** every WebAuthn passkey (lost authenticator + no
        recovery path; ADR 0068 extends this to credentials) — and revoke their sessions so they
        re-enroll. The always-available recovery for a locked-out passkey user. Raises
        :class:`ValueError` for an unknown or non-local user."""
        user = await self._store.get_user(user_id)
        if user is None:
            raise ValueError("no such user")
        if user.auth_provider != AuthProvider.LOCAL.value:
            raise ValueError("only local users have MFA to reset")
        await self._store.disable_totp(user_id)
        removed = await self._store.delete_all_webauthn_credentials(user_id)
        await self._store.revoke_user_sessions(user_id)
        await self._audit(
            "auth.mfa_reset",
            actor=actor,
            detail=_json(
                {
                    "user_id": user_id,
                    "username": user.username,
                    "webauthn_credentials_removed": removed,
                }
            ),
        )
        await self._notify_security(
            MFA_DISABLED, username=user.username, email=user.email, detail={"reset": True}
        )

    async def mfa_status(self, identity: Identity) -> MfaStatus:
        """The caller's current MFA posture for ``GET /me/mfa``."""
        user = await self._store.get_user(identity.user_id)
        if user is None:
            return MfaStatus(
                enabled=False, enrolled_at=None, recovery_codes_remaining=0, required=False
            )
        remaining = (
            len(await self._store.get_recovery_code_hashes(identity.user_id))
            if user.totp_enabled
            else 0
        )
        webauthn_enrolled = await self._store.has_webauthn_credentials(identity.user_id)
        return MfaStatus(
            enabled=user.totp_enabled,
            enrolled_at=user.totp_enrolled_at,
            recovery_codes_remaining=remaining,
            required=self._mfa_required_for(
                user,
                identity.roles,
                second_factor_enrolled=user.totp_enabled or webauthn_enrolled,
            ),
            webauthn_enrolled=webauthn_enrolled,
        )

    # --- MFA: WebAuthn passkeys second factor (local accounts, WP-14b / ADR 0068) ---

    def webauthn_available(self) -> bool:
        """Whether the optional ``[webauthn]`` extra is installed (the UI hides the passkey surface
        with a message — never a crash — when it isn't)."""
        return webauthn.available()

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64url_decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    #: Ceremony-miss message — names the LB-stickiness caveat so a multi-node operator can
    #: self-diagnose intermittent failures (ADR 0068 §2).
    _CEREMONY_EXPIRED = (
        "passkey ceremony expired or not found — start it again (on a multi-node deployment "
        "behind a load balancer, begin and finish must reach the same node)"
    )
    _WEBAUTHN_LABEL_MAX = 100  # matches the column cap (ADR 0068 §4)

    async def begin_webauthn_registration(
        self, identity: Identity, *, token: str, rp_id: str, rp_name: str
    ) -> str:
        """Stage a passkey registration ceremony; returns the browser creation-options JSON. The
        API gates this behind the password-only re-proof (``require_ui_reauth_only`` — WP-14: a
        stolen pre-MFA cookie must never bind an attacker's passkey). Raises :class:`ValueError`
        for an AD account (parity with :meth:`begin_mfa_enrollment`); a full challenge cache
        raises :class:`webauthn.ChallengeCacheFullError` (cause-naming, rendered legibly)."""
        user = await self._store.get_user(identity.user_id)
        if user is None or user.auth_provider != AuthProvider.LOCAL.value:
            raise ValueError("only local users can enroll a passkey")
        existing = await self._store.list_webauthn_credentials(identity.user_id)
        challenge = webauthn.new_challenge()
        options = webauthn.registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=user.id,
            user_name=user.username,
            challenge=challenge,
            exclude_credential_ids=[self._b64url_decode(c.credential_id) for c in existing],
        )
        self._webauthn_challenges.put((hash_token(token), "register"), user.id, challenge)
        await self._audit("auth.webauthn_enroll_started", actor=identity.username)
        return options

    async def finish_webauthn_registration(
        self,
        identity: Identity,
        response_json: str,
        *,
        label: str,
        token: str,
        client: str | None = None,
        rp_id: str,
        origin: str,
    ) -> bool:
        """Verify an attestation response and persist the passkey. Returns ``False`` when the
        response fails verification (audited — parity with a wrong TOTP code); raises
        :class:`ValueError` for flow errors with safe, renderable messages (AD account, bad label,
        expired ceremony, duplicate label/credential). On success the enrolling session is marked
        MFA-verified (exact :meth:`confirm_mfa_enrollment` parity) — **no recovery codes are
        minted** (ADR 0068 decision 5)."""
        user = await self._store.get_user(identity.user_id)
        if user is None or user.auth_provider != AuthProvider.LOCAL.value:
            raise ValueError("only local users can enroll a passkey")
        label = label.strip()
        if not label or len(label) > self._WEBAUTHN_LABEL_MAX:
            raise ValueError("label must be 1-100 characters")
        pending = self._webauthn_challenges.pop((hash_token(token), "register"))
        if pending is None or pending.user_id != user.id:
            raise ValueError(self._CEREMONY_EXPIRED)
        try:
            result = webauthn.verify_registration(
                response_json=response_json,
                challenge=pending.challenge,
                rp_id=rp_id,
                origin=origin,
            )
        except webauthn.WebAuthnVerificationError:
            await self._audit(
                "auth.webauthn_failed", actor=identity.username, detail=_json({"phase": "enroll"})
            )
            return False
        credential_id_hash = hash_bytes(result.credential_id)
        if await self._store.get_webauthn_credential(credential_id_hash) is not None:
            raise ValueError("this passkey is already enrolled")
        now = time.time()
        cred = WebAuthnCredential(
            credential_id_hash=credential_id_hash,
            credential_id=self._b64url_encode(result.credential_id),
            user_id=user.id,
            rp_id=rp_id,
            public_key=self._b64url_encode(result.public_key),
            sign_count=result.sign_count,
            transports=result.transports,
            device_type=result.device_type,
            backed_up=result.backed_up,
            label=label,
            aaguid=result.aaguid,
            created_at=now,
        )
        try:
            await self._store.add_webauthn_credential(cred)
        except Exception as exc:
            # The concurrent duplicate-label race (ADR 0068 §4): each backend raises its own
            # integrity class (sqlite3.IntegrityError / asyncpg UniqueViolationError / pyodbc
            # IntegrityError) — rendered as the same legible error as a pre-checked duplicate.
            mro = "".join(t.__name__ for t in type(exc).__mro__)
            if "Integrity" in mro or "UniqueViolation" in mro:
                raise ValueError("label already in use") from exc
            raise
        # Parity with confirm_mfa_enrollment: the enrolling session is now MFA-verified (it just
        # proved possession of the freshly-bound authenticator).
        await self._store.mark_session_mfa_verified(hash_token(token))
        await self._audit(
            "auth.webauthn_enrolled", actor=identity.username, detail=_json({"label": label})
        )
        await self._notify_security(
            MFA_ENABLED, username=user.username, email=user.email, client=client
        )
        return True

    async def begin_webauthn_assertion(self, token: str | None, *, rp_id: str) -> str | None:
        """Stage an assertion ceremony for the caller's session; returns the browser request-options
        JSON, or ``None`` when the user has no credentials minted under the CURRENT ``rp_id``
        (an origin migration renders old credentials visibly unusable — ADR 0068 §7). Allowed for
        MFA-pending sessions: the assertion is exactly what proves the second factor."""
        if not token:
            return None
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return None
        creds = [
            c
            for c in await self._store.list_webauthn_credentials(session.user_id)
            if c.rp_id == rp_id
        ]
        if not creds:
            return None
        challenge = webauthn.new_challenge()
        options = webauthn.assertion_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credential_ids=[self._b64url_decode(c.credential_id) for c in creds],
        )
        self._webauthn_challenges.put((hash_token(token), "assert"), session.user_id, challenge)
        return options

    async def finish_webauthn_assertion(
        self,
        token: str | None,
        response_json: str,
        *,
        client: str | None = None,
        rp_id: str,
        origin: str,
    ) -> bool:
        """Verify an assertion for the caller's session; on success mark the session's second
        factor satisfied — **`mfa_verified` ONLY** (ADR 0068 decision 1: ``reauth_at`` + the
        WP-L3-13 client re-anchor come from the password leg of ``POST /ui/reauth``, never from
        the assertion — the loop-class defense). Returns ``False`` (never raises) for any invalid
        input, always audited. **Deliberate divergence from :meth:`verify_mfa`** (recorded in ADR
        0068): assertion failures do NOT feed ``_register_failure`` — signatures are not guessable
        secrets and a flaky authenticator must not lock the account; abuse is bounded by the
        route's ``allow_login_attempt`` gate + cookie-holder-only reachability + these audits."""
        if not token:
            return False
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return False
        user = await self._store.get_user(session.user_id)
        if user is None or user.disabled:
            return False
        now = time.time()
        # A locked account is refused BEFORE any verify (verify_mfa parity).
        if user.locked_until is not None and now < user.locked_until:
            await self._audit(
                "auth.webauthn_failed", actor=user.username, detail=_json({"reason": "locked"})
            )
            return False
        pending = self._webauthn_challenges.pop((hash_token(token), "assert"))
        if pending is None or pending.user_id != user.id:
            await self._audit(
                "auth.webauthn_failed", actor=user.username, detail=_json({"reason": "expired"})
            )
            return False
        try:
            raw_id = webauthn.credential_id_from_response(response_json)
        except webauthn.WebAuthnVerificationError:
            await self._audit(
                "auth.webauthn_failed", actor=user.username, detail=_json({"reason": "malformed"})
            )
            return False
        cred = await self._store.get_webauthn_credential(hash_bytes(raw_id))
        if cred is None or cred.user_id != user.id or cred.rp_id != rp_id:
            # Unknown credential, another user's, or minted under a different origin — same
            # refusal either way (no oracle distinguishing the three).
            await self._audit(
                "auth.webauthn_failed",
                actor=user.username,
                detail=_json({"reason": "unknown_credential"}),
            )
            return False
        try:
            new_count = webauthn.verify_assertion(
                response_json=response_json,
                challenge=pending.challenge,
                rp_id=rp_id,
                origin=origin,
                public_key=self._b64url_decode(cred.public_key),
                current_sign_count=cred.sign_count,
            )
        except webauthn.WebAuthnVerificationError as exc:
            # py_webauthn's own counter-regression rejection IS a clone signal (ADR 0068 §4).
            clone = "sign count" in str(exc).lower()
            await self._audit(
                "auth.webauthn_clone_suspected" if clone else "auth.webauthn_failed",
                actor=user.username,
                detail=_json({"label": cred.label}) if clone else None,
            )
            return False
        if not await self._store.update_webauthn_sign_count(
            cred.credential_id_hash, expected=cred.sign_count, new=new_count, used_at=now
        ):
            # CAS miss: a concurrent assertion consumed the same counter — the clone signal.
            await self._audit(
                "auth.webauthn_clone_suspected",
                actor=user.username,
                detail=_json({"label": cred.label}),
            )
            return False
        await self._store.mark_session_mfa_verified(hash_token(token))
        await self._audit("auth.webauthn_verified", actor=user.username)
        return True

    async def delete_webauthn_credential(
        self, identity: Identity, credential_id_hash: str, *, client: str | None = None
    ) -> bool:
        """Self-service: remove one of the caller's own passkeys (the API gates this behind the
        full step-up). Returns ``False`` for an unknown/foreign credential (self-scoped). Raises
        :class:`ValueError` when this is the last remaining second factor while MFA is still
        required — "enroll another factor first" (ADR 0068 decision 5). Deleting the last factor
        when NOT required fires the MFA_DISABLED-class notification (ASVS 6.3.7 parity)."""
        user = await self._store.get_user(identity.user_id)
        if user is None:
            return False
        creds = await self._store.list_webauthn_credentials(identity.user_id)
        target = next((c for c in creds if c.credential_id_hash == credential_id_hash), None)
        if target is None:
            return False
        last_second_factor = len(creds) == 1 and not user.totp_enabled
        if last_second_factor and self._mfa_required_for(
            user, identity.roles, second_factor_enrolled=False
        ):
            raise ValueError(
                "this is your last second factor and MFA is required for your account — "
                "enroll another factor first"
            )
        if not await self._store.delete_webauthn_credential(identity.user_id, credential_id_hash):
            return False  # pragma: no cover - raced with a concurrent delete of the same row
        await self._audit(
            "auth.webauthn_removed", actor=identity.username, detail=_json({"label": target.label})
        )
        if last_second_factor:
            await self._notify_security(
                MFA_DISABLED,
                username=user.username,
                email=user.email,
                client=client,
                detail={"factor": "webauthn"},
            )
        return True

    # --- administration (audited) -------------------------------------------

    @property
    def store(self) -> AdminStore:
        """Read access to the backing store for admin list/read endpoints (users + audit)."""
        return self._store

    async def security_events_for(self, username: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """The caller's own security-event history (audited ``auth.*`` actions, most-recent-first) for
        ``GET /me/security-events`` — normalized to plain dicts so the API doesn't see backend Row
        types. PHI-free (the audit ``detail`` carries metadata only)."""
        rows = await self._store.security_events_for_user(username, limit=limit)
        return [
            {"ts": float(r["ts"]), "action": str(r["action"]), "detail": r["detail"]} for r in rows
        ]

    async def create_local_user(
        self,
        *,
        username: str,
        password: str,
        display_name: str | None,
        email: str | None,
        roles: Sequence[str],
        actor: str,
    ) -> str:
        user_id = uuid4().hex
        await self._store.create_user(
            user_id=user_id,
            username=username,
            auth_provider=AuthProvider.LOCAL.value,
            display_name=display_name,
            email=email,
            password_hash=await self._argon2(hash_password, password),
            # Admin-set the credential is a one-time temp: force rotation on first login so the
            # operator never sets a lasting password the user keeps (ASVS 6.4.6 / WP-L3-12).
            must_change_password=True,
        )
        await self._store.set_user_roles(user_id, roles, assigned_by=actor)
        await self._audit(
            "user.created", actor=actor, detail=_json({"username": username, "roles": list(roles)})
        )
        # If this created a second administrator, retire the now-redundant bootstrap admin (WP-3).
        await self._retire_superseded_bootstrap()
        return user_id

    async def update_user(
        self,
        user_id: str,
        *,
        display_name: str | None,
        email: str | None,
        disabled: bool | None,
        actor: str,
    ) -> None:
        before = await self._store.get_user(user_id)  # capture old email/disabled for notifications
        await self._store.update_user_profile(user_id, display_name=display_name, email=email)
        if disabled is not None:
            await self._store.set_user_disabled(user_id, disabled=disabled)
            if disabled:
                await self._store.revoke_user_sessions(user_id)
        await self._audit("user.updated", actor=actor, detail=_json({"user_id": user_id}))
        if before is not None:
            if email is not None and email != before.email:
                # Notify the OLD address — so the legitimate owner is alerted even if an attacker (or a
                # mistaken admin) repointed the account's email to one they control (ASVS 6.3.7).
                await self._notify_security(
                    EMAIL_CHANGED,
                    username=before.username,
                    email=before.email,
                    detail={"new_email": email},
                )
            if disabled and not before.disabled:
                await self._notify_security(
                    ACCOUNT_DISABLED, username=before.username, email=before.email
                )

    async def delete_user(self, user_id: str, *, actor: str) -> None:
        await self._store.delete_user(user_id)
        await self._audit("user.deleted", actor=actor, detail=_json({"user_id": user_id}))

    async def set_roles(self, user_id: str, roles: Sequence[str], *, actor: str) -> None:
        user = await self._store.get_user(user_id)  # for the notification address
        await self._store.set_user_roles(user_id, roles, assigned_by=actor)
        await self._store.revoke_user_sessions(user_id)  # re-resolve permissions on next login
        await self._audit(
            "user.roles_changed",
            actor=actor,
            detail=_json({"user_id": user_id, "roles": list(roles)}),
        )
        if user is not None:
            await self._notify_security(
                ROLES_CHANGED,
                username=user.username,
                email=user.email,
                detail={"roles": list(roles)},
            )

    # --- custom RBAC roles (ADR 0045, gated by USERS_MANAGE) -----------------

    async def list_custom_roles(self) -> list[CustomRoleInfo]:
        """Every admin-defined custom role with its (defensively-decoded) permission set. Built-in rows
        are excluded — they resolve from ``BUILTIN_ROLE_PERMISSIONS``, not the ``permissions`` column."""
        out: list[CustomRoleInfo] = []
        for row in await self._store.list_roles():
            if _row_builtin(row):
                continue
            perms = decode_custom_role_permissions(row["permissions"])
            out.append(
                CustomRoleInfo(
                    id=str(row["id"]),
                    display_name=str(row["display_name"]),
                    description=(None if row["description"] is None else str(row["description"])),
                    permissions=frozenset(perms),
                )
            )
        return out

    async def create_custom_role(
        self,
        *,
        display_name: str,
        description: str | None,
        permissions: Sequence[str],
        actor: str,
    ) -> CustomRoleInfo:
        """Define a new custom role: a named SUBSET of the existing ``Permission`` catalog (ADR 0045).

        The permission set is validated (recognized catalog perms only, non-empty, no carved-out
        escalation primitive); a :class:`CustomRoleError` is raised otherwise. The role id is namespaced
        with ``custom:`` so it can never collide with a built-in. Audited (records the permission
        *names*, never PHI)."""
        perms = validate_custom_role_permissions(permissions)  # raises CustomRoleError
        role_id = CUSTOM_ROLE_ID_PREFIX + uuid4().hex
        await self._store.upsert_role(
            role_id=role_id,
            display_name=display_name,
            description=description,
            builtin=False,
            permissions=_json([p.value for p in perms]),
        )
        await self._audit(
            "role.created",
            actor=actor,
            detail=_json({"role_id": role_id, "permissions": [p.value for p in perms]}),
        )
        return CustomRoleInfo(
            id=role_id,
            display_name=display_name,
            description=description,
            permissions=frozenset(perms),
        )

    async def update_custom_role(
        self,
        role_id: str,
        *,
        display_name: str,
        description: str | None,
        permissions: Sequence[str],
        actor: str,
    ) -> CustomRoleInfo:
        """Edit a custom role's name/description/permission set. Validates the new permission subset and
        rejects editing a built-in (or unknown) role. A permission *reduction* takes effect immediately:
        every user holding the role has their live sessions revoked so a narrowed set can't linger on an
        active token (ADR 0045 D3, mirroring :meth:`set_roles`). Audited. Raises :class:`ValueError` for
        an unknown/built-in role and :class:`CustomRoleError` for an invalid permission set."""
        existing = await self._store.get_role(role_id)
        if existing is None or _row_builtin(existing):
            raise ValueError("no such custom role")
        perms = validate_custom_role_permissions(permissions)  # raises CustomRoleError
        await self._store.upsert_role(
            role_id=role_id,
            display_name=display_name,
            description=description,
            builtin=False,
            permissions=_json([p.value for p in perms]),
        )
        await self._revoke_sessions_for_role(role_id)
        await self._audit(
            "role.updated",
            actor=actor,
            detail=_json({"role_id": role_id, "permissions": [p.value for p in perms]}),
        )
        return CustomRoleInfo(
            id=role_id,
            display_name=display_name,
            description=description,
            permissions=frozenset(perms),
        )

    async def delete_custom_role(self, role_id: str, *, actor: str) -> None:
        """Delete a custom role; its user/AD-group assignments are removed in the same transaction, and
        every assigned user's live sessions are revoked so the now-gone permissions don't linger on an
        active token. Raises :class:`ValueError` for an unknown or built-in role. Audited."""
        existing = await self._store.get_role(role_id)
        if existing is None or _row_builtin(existing):
            raise ValueError("no such custom role")
        await self._revoke_sessions_for_role(role_id)  # before the rows are gone
        await self._store.delete_custom_role(role_id)
        await self._audit("role.deleted", actor=actor, detail=_json({"role_id": role_id}))

    async def _revoke_sessions_for_role(self, role_id: str) -> None:
        """Revoke the live sessions of every user currently holding ``role_id`` so a permission
        reduction / role deletion re-resolves on their next request (ADR 0045 D3)."""
        for user in await self._store.list_users():
            if role_id in await self._store.get_user_role_ids(user.id):
                await self._store.revoke_user_sessions(user.id)

    async def admin_reset_password(self, user_id: str, *, actor: str) -> str:
        """Admin-initiated password reset (ASVS 6.4.6 / WP-L3-12). Generate a CSPRNG one-time password
        through the active policy, set it with ``must_change_password`` (forces a change on first
        login), and revoke the user's sessions. Returns the one-time credential **once** so the caller
        can convey it out-of-band — the administrator never sets a lasting password the user keeps. The
        affected user is also notified out-of-band by email. Raises :class:`ValueError` for an unknown
        user or a non-local (AD) account; the API maps these to 4xx."""
        user = await self._store.get_user(user_id)
        if user is None:
            raise ValueError("no such user")
        if user.auth_provider != AuthProvider.LOCAL.value:
            raise ValueError("only local users have a password to reset")
        temp = self._generate_policy_password()
        await self._store.set_password(
            user_id,
            password_hash=await self._argon2(hash_password, temp),
            must_change_password=True,
        )
        await self._store.revoke_user_sessions(user_id)  # invalidate any live sessions on reset
        await self._audit(
            "auth.password_reset",
            actor=actor,
            detail=_json({"user_id": user_id, "username": user.username}),
        )
        await self._notify_security(PASSWORD_RESET, username=user.username, email=user.email)
        return temp

    async def set_channel_scope(
        self, user_id: str, channels: Sequence[str] | None, *, actor: str
    ) -> None:
        """Set a user's per-channel RBAC scope (``None`` = all). Revokes their sessions so the new
        scope takes effect immediately, and audits the change."""
        scope_json = None if channels is None else _json(sorted(set(channels)))
        await self._store.set_user_channel_scope(user_id, scope_json)
        await self._store.revoke_user_sessions(user_id)
        await self._audit(
            "user.channel_scope_changed",
            actor=actor,
            detail=_json(
                {
                    "user_id": user_id,
                    "channels": None if channels is None else sorted(set(channels)),
                }
            ),
        )

    async def is_last_enabled_admin(self, user_id: str) -> bool:
        """True iff ``user_id`` is an enabled administrator and the only one remaining.

        Guards the role-removal path so the deployment can never be left with no usable admin
        account (the bootstrap admin only regenerates against a fully empty users table).
        """
        admins: set[str] = set()
        for user in await self._store.list_users():
            if user.disabled:
                continue
            if Role.ADMINISTRATOR.value in await self._store.get_user_role_ids(user.id):
                admins.add(user.id)
        return admins == {user_id}

    async def set_ad_group_map(self, entries: Sequence[tuple[str, str]], *, actor: str) -> None:
        await self._store.set_ad_group_role_map(entries)
        await self._audit(
            "ad_group_map.updated", actor=actor, detail=_json({"count": len(entries)})
        )

    async def set_ad_group_scope_map(
        self, entries: Sequence[tuple[str, str]], *, actor: str
    ) -> None:
        """Replace the AD-group → channel-scope map (C3). Takes effect on each AD user's next login."""
        await self._store.set_ad_group_scope_map(entries)
        await self._audit(
            "ad_group_scope_map.updated", actor=actor, detail=_json({"count": len(entries)})
        )

    # --- audit ---------------------------------------------------------------

    async def audit_permission_denied(
        self, identity: Identity, permission: Permission, path: str
    ) -> None:
        await self._audit(
            "auth.permission_denied",
            actor=identity.username,
            detail=_json({"permission": permission.value, "path": path}),
        )

    async def audit_permission_granted(
        self, identity: Identity, permission: Permission, path: str
    ) -> None:
        """Twin of :meth:`audit_permission_denied` for the authorization-GRANT side (BACKLOG #195a,
        ASVS 16.3.2). The API layer emits this ONLY for the sensitive / state-changing surface (never on
        a read or a poll — see the ``_GRANT_AUDIT_PERMISSIONS`` scope in ``api/security.py``), so the
        hash-chained audit log records who was allowed to perform a sensitive op without being flooded by
        console polling or the /ws/stats feed."""
        await self._audit(
            "auth.permission_granted",
            actor=identity.username,
            detail=_json({"permission": permission.value, "path": path}),
        )

    async def _audit(
        self, action: str, *, actor: str | None = None, detail: str | None = None
    ) -> None:
        await self._store.record_audit(action, actor=actor, detail=detail)

    async def _notify_security(
        self,
        event_type: str,
        *,
        username: str,
        email: str | None,
        client: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Best-effort out-of-band security-event push (ASVS 6.3.5/6.3.7). A missing notifier or a
        notifier failure is swallowed (logged) — a notification must never break a login or an admin
        action. The event is also already in the audit log (the /me/security-events feed)."""
        if self._security_notifier is None:
            return
        try:
            await self._security_notifier.notify(
                SecurityEvent(
                    event_type=event_type,
                    username=username,
                    email=email,
                    client_ip=client,
                    detail=detail or {},
                )
            )
        except Exception:  # noqa: BLE001 - best-effort; never propagate into auth
            _log.warning(
                "security-event notification failed (%s for %s)",
                event_type,
                username,
                exc_info=True,
            )
