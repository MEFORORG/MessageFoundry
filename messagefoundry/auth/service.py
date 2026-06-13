"""AuthService — orchestrates authentication, sessions, role resolution, and first-run bootstrap.

Pure engine-side code (no FastAPI): the API layer composes it. It ties together the store (users,
roles, sessions, audit), password hashing/policy, opaque session tokens, and the LDAP/Kerberos
authenticators. Local and AD users share one identity model; an AD user's roles are re-synced from
their directory groups on every login, so :meth:`identity_for_token` can resolve everyone uniformly
from ``user_roles``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar
from uuid import uuid4

from messagefoundry.auth.identity import AuthProvider, Identity
from messagefoundry.auth.ldap import AdPrincipal, LdapAuthenticator, LdapError, kerberos_principal
from messagefoundry.auth.passwords import hash_password, needs_rehash, verify_password
from messagefoundry.auth.permissions import ROLE_METADATA, Permission, Role
from messagefoundry.auth.policy import PasswordPolicy, _operator_corpus
from messagefoundry.auth.ratelimit import SlidingWindowRateLimiter
from messagefoundry.auth.tokens import hash_token, mint_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.base import AdminStore
from messagefoundry.store.store import SessionRecord, UserRecord

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

_T = TypeVar("_T")


@dataclass(frozen=True)
class LoginOutcome:
    """Result of a login attempt. ``error`` is for logs/audit — never leak the reason to clients."""

    ok: bool
    token: str | None = None
    identity: Identity | None = None
    must_change_password: bool = False
    error: str | None = None


@dataclass(frozen=True)
class BootstrapAdmin:
    """Credentials for the one-time bootstrap admin (printed once, then must be changed)."""

    username: str
    password: str


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
        self, store: AdminStore, settings: AuthSettings, *, ldap: LdapAuthenticator | None = None
    ) -> None:
        self._store = store
        self._settings = settings
        self.enabled = settings.enabled
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

    @property
    def policy(self) -> PasswordPolicy:
        return self._policy

    @property
    def ad_enabled(self) -> bool:
        return self._ldap is not None

    @property
    def kerberos_enabled(self) -> bool:
        return self._settings.kerberos_enabled and self._ldap is not None

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
            await self._register_failure(user, now)
            await self._audit(
                "auth.login_failed",
                actor=username,
                detail=_json({"provider": "local", "reason": "bad_password"}),
            )
            return LoginOutcome(ok=False, error="invalid credentials")
        if await asyncio.to_thread(needs_rehash, user.password_hash):
            await self._store.set_password(
                user.id,
                password_hash=await self._argon2(hash_password, password),
                must_change_password=user.must_change_password,
            )
        await self._store.record_login_success(user.id, now=now)
        identity = await self._build_identity(user)
        token = await self._issue_session(user.id, client)
        await self._audit(
            "auth.login_success", actor=user.username, detail=_json({"provider": "local"})
        )
        return LoginOutcome(
            ok=True,
            token=token,
            identity=identity,
            must_change_password=user.must_change_password,
        )

    async def _register_failure(self, user: UserRecord, now: float) -> None:
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
        self, token: bytes, *, client: str | None = None
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
        return await self._complete_ad_login(principal, client)

    async def _kerberos_reject_audit(self, actor: str, reason: str) -> None:
        await self._audit(
            "auth.login_failed",
            actor=actor,
            detail=_json({"provider": "ad", "mech": "kerberos", "reason": reason}),
        )

    async def _complete_ad_login(self, principal: AdPrincipal, client: str | None) -> LoginOutcome:
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
        await self._store.record_login_success(user.id)
        ad_roles = _roles_from_ids(role_ids)
        user = await self._sync_ad_channel_scope(user, ad_roles, principal.groups)
        identity = Identity.build(
            user_id=user.id,
            username=user.username,
            auth_provider=AuthProvider.AD,
            roles=ad_roles,
            allowed_channels=_allowed_channels(user, ad_roles),
        )
        token = await self._issue_session(user.id, client)
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

    async def _issue_session(self, user_id: str, client: str | None) -> str:
        token = mint_token()
        expires_at = time.time() + self._settings.session_absolute_hours * 3600
        await self._store.create_session(
            token_hash=hash_token(token), user_id=user_id, expires_at=expires_at, client=client
        )
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

    async def _build_identity(self, user: UserRecord) -> Identity:
        role_ids = await self._store.get_user_role_ids(user.id)
        roles = _roles_from_ids(role_ids)
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

    async def change_password(
        self, identity: Identity, new_password: str, *, must_change: bool = False
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
        return []

    # --- administration (audited) -------------------------------------------

    @property
    def store(self) -> AdminStore:
        """Read access to the backing store for admin list/read endpoints (users + audit)."""
        return self._store

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
        await self._store.update_user_profile(user_id, display_name=display_name, email=email)
        if disabled is not None:
            await self._store.set_user_disabled(user_id, disabled=disabled)
            if disabled:
                await self._store.revoke_user_sessions(user_id)
        await self._audit("user.updated", actor=actor, detail=_json({"user_id": user_id}))

    async def delete_user(self, user_id: str, *, actor: str) -> None:
        await self._store.delete_user(user_id)
        await self._audit("user.deleted", actor=actor, detail=_json({"user_id": user_id}))

    async def set_roles(self, user_id: str, roles: Sequence[str], *, actor: str) -> None:
        await self._store.set_user_roles(user_id, roles, assigned_by=actor)
        await self._store.revoke_user_sessions(user_id)  # re-resolve permissions on next login
        await self._audit(
            "user.roles_changed",
            actor=actor,
            detail=_json({"user_id": user_id, "roles": list(roles)}),
        )

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

    async def _audit(
        self, action: str, *, actor: str | None = None, detail: str | None = None
    ) -> None:
        await self._store.record_audit(action, actor=actor, detail=detail)
