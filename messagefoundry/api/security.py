# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""FastAPI authentication + authorization dependencies (deny-by-default).

``require(*permissions)`` is a dependency factory applied to every protected route. Once an enabled
:class:`AuthService` is wired (the ``serve`` path) it enforces the bearer token plus the listed
permissions. When **no** AuthService is attached the behaviour is **fail-closed**: the route is
denied unless the app was explicitly built with ``allow_no_auth=True`` (the in-process embedding /
local-dev opt-in), in which case it returns a full-access *system* identity. This prevents an
``create_app(engine)`` that is accidentally served from silently granting unauthenticated full
access (SYS-1). ``authorize_ws`` is the WebSocket equivalent (it returns ``None`` instead of
raising, so the caller can close the socket cleanly).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from fastapi import HTTPException, Request, WebSocket, status

from messagefoundry.api.tls_client_cert import MF_CLIENT_PEERCERT_STATE_KEY
from messagefoundry.auth import AuthProvider, Identity, Permission, Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.tls_policy import HopDisposition

log = logging.getLogger(__name__)

# ADR 0083: cert-identity carries NO second factor / session / step-up, so it must never authorize a
# PHI-view route. require_service_cert refuses to gate any route that asks for one of these — a
# defense-in-depth guard so an operator can't wire a service cert onto the PHI surface (see the resolver).
_PHI_VIEW_PERMISSIONS: frozenset[Permission] = frozenset(
    {Permission.MESSAGES_VIEW_SUMMARY, Permission.MESSAGES_VIEW_RAW}
)

# Identity used when auth is explicitly disabled via allow_no_auth (embedding/dev): full access.
_SYSTEM_IDENTITY = Identity.build(
    user_id="system", username="system", auth_provider=AuthProvider.LOCAL, roles=list(Role)
)

# While an account is flagged to rotate its password, only these self-service routes stay reachable.
_MUST_CHANGE_EXEMPT_PATHS = frozenset({"/auth/logout", "/auth/me", "/me/password"})

# BACKLOG #195a (ASVS 16.3.2): the permissions whose authorization GRANT is worth an audit row — the
# sensitive / state-changing / config / user-mgmt surface. A grant is recorded ONLY when a route's
# required permission is one of these, a deliberate and documented deviation from "audit every
# authorization decision": require()/authorize_ws fire on EVERY protected request (console polling +
# the /ws/stats feed), so auditing every read grant would flood the hash-chained audit log. The
# read/monitoring permissions are therefore excluded, and the PHI-view grants
# (MESSAGES_VIEW_SUMMARY / _VIEW_RAW) are excluded too because the PHI-access audit path already records
# those accesses (dedupe). The set is transport-agnostic so it holds identically for HTTP and the
# WebSocket; on HTTP a further method != "GET" guard drops a polled sensitive-permission READ (e.g.
# GET /approvals, which carries APPROVALS_APPROVE).
_GRANT_AUDIT_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.MESSAGES_REPLAY,
        Permission.MESSAGES_RESEND,
        Permission.MESSAGES_EDIT,
        Permission.MESSAGES_PURGE,
        Permission.CONNECTIONS_CONTROL,
        Permission.CONNECTIONS_TEST,
        Permission.DR_OPERATE,
        Permission.CONFIG_DEPLOY,
        Permission.CONFIG_VALIDATE,
        Permission.CODE_EDIT,
        Permission.SERVICE_CONFIGURE,
        Permission.USERS_MANAGE,
        Permission.APPROVALS_APPROVE,
    }
)


def _grant_audit_permission(permissions: tuple[Permission, ...]) -> Permission | None:
    """The first sensitive permission whose GRANT should be audited (BACKLOG #195a), or ``None`` when
    the route requires only read/monitoring permissions (no grant audit — the documented 16.3.2
    read-polling deviation). Returning a single permission keeps the grant to ONE audit row per request
    even on a multi-permission route."""
    for permission in permissions:
        if permission in _GRANT_AUDIT_PERMISSIONS:
            return permission
    return None


def get_auth(request: Request) -> AuthService | None:
    """The attached :class:`AuthService`, or ``None`` when auth is not configured."""
    auth: AuthService | None = getattr(request.app.state, "auth", None)
    return auth


def _allow_no_auth(app_state: object) -> bool:
    """Whether this app explicitly opted out of auth (embedding/dev). Default: fail-closed."""
    return bool(getattr(app_state, "allow_no_auth", False))


def bearer_token(request: Request) -> str | None:
    """Extract a ``Bearer`` token from the Authorization header, if present."""
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer ") :].strip() or None
    return None


def _client_ip(request: Request) -> str | None:
    """The caller's client address, matching how login records it on the session (``_client`` in
    ``auth_routes``). Used by the WP-L3-13 new-client-IP risk signal so the comparison is
    apples-to-apples. Behind a declared trusted proxy this already resolves to the real client:
    uvicorn runs with ``forwarded_allow_ips = settings.api.trusted_proxies`` (``__main__.py``;
    defaults to ``[]`` = trust nothing), and an off-loopback proxied bind is gated to require it. The
    residual is the inherent limit that an in-process per-IP limiter cannot stop pure source-IP
    rotation by a directly-reachable attacker (SEC-024)."""
    return request.client.host if request.client else None


def require(*permissions: Permission) -> Callable[[Request], Awaitable[Identity]]:
    """Build a dependency that authenticates the caller and asserts each of ``permissions``."""

    async def dependency(request: Request) -> Identity:
        auth = get_auth(request)
        if auth is None or not auth.enabled:
            if _allow_no_auth(request.app.state):
                return _SYSTEM_IDENTITY
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "authentication is not configured"
            )
        identity = await auth.identity_for_token(bearer_token(request))
        if identity is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
        if identity.must_change_password and request.url.path not in _MUST_CHANGE_EXEMPT_PATHS:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "password change required")
        for permission in permissions:
            if not identity.has(permission):
                await auth.audit_permission_denied(identity, permission, request.url.path)
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, f"missing permission: {permission.value}"
                )
        # BACKLOG #195a (ASVS 16.3.2): record the authorization GRANT for the sensitive/state-changing
        # surface only — a NON-GET request whose required permission is in _GRANT_AUDIT_PERMISSIONS. The
        # method guard drops the polled GET /approvals (which carries APPROVALS_APPROVE); the permission
        # set drops every read/monitoring grant (console polling would otherwise flood the audit chain)
        # and the PHI-view grants (already recorded by the PHI-access audit path). See the constant.
        if request.method != "GET":
            audited = _grant_audit_permission(permissions)
            if audited is not None:
                await auth.audit_permission_granted(identity, audited, request.url.path)
        return identity

    return dependency


# --- mTLS client-cert → Identity resolver (#200, ADR 0083) -------------------------------------------
# Beside require(): resolve a VERIFIED client certificate's subject/SAN to a MessageFoundry Identity via
# the [api].tls_client_cert_identities allow-list, so a service-to-service caller can authenticate with a
# pinned mTLS cert instead of a bearer token. DENY-BY-DEFAULT: an unmapped/spoofed subject → no identity.
# This is ADDITIVE and does NOT touch require()/the bearer path — the cert-identity plane is admitted ONLY
# by require_service_cert (below), which is cert-only and PHI-fenced, so it can never bypass the session /
# step-up / MFA controls. Activated by the scope-populating shim in api/tls_client_cert (ADR 0083).


def _cert_name_candidates(peercert: Mapping[str, Any]) -> list[str]:
    """The qualified subject/SAN names of a ``ssl.getpeercert()`` dict, in match order (#200).

    Yields ``"CN:<commonName>"`` for each subject commonName RDN and ``"SAN:<type>:<value>"`` for each
    subjectAltName entry (e.g. ``"SAN:DNS:svc.internal"``). These are the exact keys an operator lists
    in ``[api].tls_client_cert_identities`` — qualifying the name space (CN vs SAN, SAN type) means a
    spoofed commonName can never collide with a pinned DNS SAN."""
    candidates: list[str] = []
    for rdn in peercert.get(
        "subject", ()
    ):  # subject = tuple of RDNs; each RDN = tuple of (attr, value)
        for pair in rdn:
            if len(pair) == 2 and pair[0] == "commonName":
                candidates.append(f"CN:{pair[1]}")
    for pair in peercert.get("subjectAltName", ()):
        if len(pair) == 2:
            candidates.append(f"SAN:{pair[0]}:{pair[1]}")
    return candidates


def client_cert_principal(
    peercert: Mapping[str, Any] | None, cert_map: Mapping[str, str]
) -> str | None:
    """The mapped MessageFoundry username for a verified peer cert, or ``None`` (deny-by-default) (#200).

    Pure: given a ``ssl.getpeercert()`` dict (only ever populated by ``ssl`` AFTER the chain verified
    against ``[api].tls_client_ca_file``) and the operator allow-list, return the first
    subject/SAN candidate present in the map. An empty/absent cert, an empty map, or a subject with no
    listed name all return ``None`` — an unmapped or spoofed-CN cert resolves to NO identity."""
    if not peercert or not cert_map:
        return None
    for candidate in _cert_name_candidates(peercert):
        principal = cert_map.get(candidate)
        if principal:
            return principal
    return None


def peer_cert_from_request(request: Request) -> Mapping[str, Any] | None:
    """Best-effort read of the verified peer certificate (``getpeercert()`` shape) for this request.

    ACTIVATED PATH (ADR 0083): the scope-populating shim (``api/tls_client_cert``) stashes the verified
    peer cert under ``scope['state'][MF_CLIENT_PEERCERT_STATE_KEY]`` at ``connection_made`` — read that
    first. Stock uvicorn (no shim) places neither that key nor a transport in the scope, so this returns
    ``None`` and the resolver stays deny-by-default; the fallback below also reads
    ``scope['transport'].get_extra_info('ssl_object').getpeercert()`` for a directly-TLS-extension-capable
    server. Either way an unmapped/spoofed subject resolves to no identity."""
    # Preferred: the in-process shim's per-connection state key (only ever set by us, never client-settable).
    state = request.scope.get("state")
    if isinstance(state, Mapping):
        stashed = state.get(MF_CLIENT_PEERCERT_STATE_KEY)
        if isinstance(stashed, Mapping) and stashed:
            return stashed
    # Fallback: a server/shim that puts the transport directly in scope['transport'].
    transport = request.scope.get("transport")
    get_extra_info = getattr(transport, "get_extra_info", None)
    if get_extra_info is None:
        return None
    ssl_object = get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    try:
        cert = ssl_object.getpeercert()
    except ValueError:
        return None  # TLS handshake not complete — no verified cert yet
    # getpeercert() returns {} when the peer presented no cert (or CERT_OPTIONAL passthrough); treat that
    # as "no cert" so client_cert_principal denies rather than matching an empty subject.
    result: Mapping[str, Any] | None = cert or None
    return result


async def resolve_client_cert_identity(request: Request) -> Identity | None:
    """Resolve the request's verified client cert to an :class:`Identity`, or ``None`` (#200, ADR 0002 §4 / ADR 0083).

    Reads the allow-list off ``app.state.tls_client_cert_identities`` and the attached
    :class:`AuthService`, extracts the peer cert (:func:`peer_cert_from_request`), maps its subject/SAN
    to a username (:func:`client_cert_principal`), and resolves that principal to an Identity. Returns
    ``None`` — DENY-BY-DEFAULT — when cert-identity is unconfigured, auth is disabled, no cert is
    presented, the subject is unmapped/spoofed, or the mapped account is unknown/disabled."""
    cert_map: Mapping[str, str] = getattr(request.app.state, "tls_client_cert_identities", {}) or {}
    if not cert_map:
        return None  # feature off (empty map) — byte-identical to no cert-identity
    auth = get_auth(request)
    if auth is None or not auth.enabled:
        return None
    principal = client_cert_principal(peer_cert_from_request(request), cert_map)
    if principal is None:
        return None  # unmapped / spoofed subject → deny-by-default
    return await auth.identity_for_username(principal)


def require_service_cert(*permissions: Permission) -> Callable[[Request], Awaitable[Identity]]:
    """Authorize a **non-interactive service-to-service** route by a VERIFIED mTLS client cert (ADR 0083).

    This is the ONLY sanctioned way to admit a cert-mapped principal, and it is deliberately fenced apart
    from the bearer/session path — a cert-identity carries full RBAC but **no second factor, no session,
    and no step-up**, so it must never flow through :func:`require` / :func:`require_step_up`:

    - **cert-only** — authenticates solely via :func:`resolve_client_cert_identity` (never a bearer
      token), so it can neither satisfy nor be satisfied by the interactive step-up / MFA controls. A
      caller with only a bearer token gets 401 here; a caller with only a cert gets 401 on any bearer
      route. The two identity planes never cross.
    - **deny-by-default** — no cert-identity map configured, no / spoofed / unmapped cert, or a disabled
      account all resolve to no identity → 401 (the caller never learns whether the subject exists).
    - **PHI-fenced** — refuses at construction to gate a PHI-view permission (:data:`_PHI_VIEW_PERMISSIONS`);
      a cert-identity must never authorize patient data because there is no step-up to gate it. A
      misconfiguration fails **loud** at app build, not silently at request time.

    None of :func:`require`'s session concerns (must-change, step-up, MFA, per-actor throttles) apply —
    they are meaningless for an attested service hop."""
    phi = _PHI_VIEW_PERMISSIONS.intersection(permissions)
    if phi:
        # Fail at route-definition (app construction), so a PHI-on-cert wiring can never reach production.
        raise ValueError(
            "require_service_cert must not gate PHI-view permissions "
            f"{sorted(p.value for p in phi)} — a cert-identity has no step-up/MFA and must never "
            "authorize PHI (ADR 0083)"
        )

    async def dependency(request: Request) -> Identity:
        identity = await resolve_client_cert_identity(request)
        if identity is None:
            # No subject in the message (no cert / unmapped) — never echo the presented subject (could be
            # attacker-chosen); a generic 401 keeps the deny-by-default surface uniform.
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "client certificate not authorized")
        for permission in permissions:
            if not identity.has(permission):
                log.warning(
                    "service-cert authz denied: actor=%s path=%s missing=%s",
                    identity.username,
                    request.url.path,
                    permission.value,
                )
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, f"missing permission: {permission.value}"
                )
        return identity

    return dependency


def enforce_phi_read_hop(request: Request) -> None:
    """Refuse to emit PHI over an insecure API serve hop (#200 residual, ADR 0092 data-path guard).

    The serve-start exposed-gate already refuses a prod-PHI cleartext bind, but this is the RESPONSE-path
    defense-in-depth: :func:`create_app` derived the API serve-hop :class:`HopDisposition` once (keyed on
    the instance posture + whether the serve hop is loopback / in-process TLS / proxy-terminated) and
    stashed it on ``app.state``. When it is :attr:`~HopDisposition.REFUSE` — a production-PHI instance
    whose serve hop is NOT proven secure — a PHI-read is refused with a PHI-free 403 rather than putting a
    body / summary on the clear. ALLOW / WARN (the loopback-dev / non-prod-PHI / synthetic / TLS cases)
    return silently, so a legitimate lane is byte-identical. Unset (an app built before this seam) → ALLOW.

    Call it from the PHI-read routes (folded into :func:`require_phi_read`; the step-up search route calls
    it directly). It reads only ``app.state`` — no I/O, no PHI — so it is safe on every request."""
    disposition = getattr(request.app.state, "phi_read_hop_disposition", HopDisposition.ALLOW)
    if disposition is HopDisposition.REFUSE:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "PHI read refused: this production-PHI instance's API serve hop is not proven secure "
            "(no loopback bind, in-process TLS, or declared TLS-terminating proxy), so PHI is not "
            "emitted over it (posture-keyed refusal, #200/ADR 0092). Configure [api].tls_cert_file "
            "or [api].tls_terminated_upstream (+ trusted_proxies).",
        )


def require_phi_read(*permissions: Permission) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require`, plus a **per-actor anti-automation throttle** for the PHI-read endpoints
    (`/messages`, `/messages/{id}`, `/dead-letters`) — bounds scripted PHI harvesting beyond the
    pagination + access-audit controls (ASVS 2.4.1). A throttled read is **logged** (not silent) and
    returns 429. No throttle on the embedding/no-auth path (there's no per-actor identity to key on).

    It also enforces the #200 API PHI-read DATA-PATH guard (:func:`enforce_phi_read_hop`) before any
    identity work, so a production-PHI instance serving over an insecure hop refuses to emit PHI."""
    base = require(*permissions)

    async def dependency(request: Request) -> Identity:
        enforce_phi_read_hop(request)
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None and not auth.allow_phi_read(identity.user_id):
            log.warning(
                "PHI-read throttled (anti-automation): actor=%s path=%s",
                identity.username,
                request.url.path,
            )
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "too many requests; please slow down",
                headers={"Retry-After": "10"},
            )
        return identity

    return dependency


def require_step_up(*permissions: Permission) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require`, plus **step-up re-verification** (ASVS 7.5.3): the caller's session must
    have re-proved its credential — at login or via ``POST /me/reauth`` — within
    ``[auth].step_up_max_age_seconds``. Gates the highly sensitive admin / replay / config flows; a
    stale session is refused with 403 (the console then prompts to re-authenticate and retries). The
    embedding/no-auth path is unaffected (there is no session to step up)."""
    base = require(*permissions)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None and auth.enabled:
            token = bearer_token(request)
            # BACKLOG #193 (ASVS 2.4.2): per-actor anti-automation pacing on the state-changing admin
            # surface. Scoped to NON-GET so the sole step-up GET (/messages/search) is exempt while
            # every purge/replay/config write is paced. Checked BEFORE the MFA/step-up gates, so a
            # throttled write is refused early; the floor clears human use and a legit
            # 403 → /me/reauth → retry burst (only two writes). Logged (not silent) → 429 + Retry-After.
            if request.method != "GET" and not auth.allow_admin_write(identity.user_id):
                log.warning(
                    "admin-write throttled (anti-automation): actor=%s path=%s",
                    identity.username,
                    request.url.path,
                )
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "too many requests; please slow down",
                    headers={"Retry-After": "1"},
                )
            # Second factor first (WP-14, ASVS 6.3.3): an MFA-required session that has not verified
            # its TOTP / recovery code cannot perform a sensitive op until it does. A distinct header
            # tells the console to prompt for a code rather than a password reauth.
            if not await auth.mfa_satisfied(token):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "multi-factor verification required; POST /auth/mfa-verify then retry",
                    headers={"X-MFA-Required": "1"},
                )
            # Contextual-risk layer (WP-L3-13, ASVS 8.4.2): a sensitive admin action from a client IP
            # the session has not verified from forces a fresh step-up (and audits + notifies). A
            # successful POST /me/reauth re-anchors the session to the new IP, so this then clears.
            new_ip = await auth.flag_new_client_ip(
                token, _client_ip(request), path=request.url.path
            )
            if new_ip or not await auth.has_recent_step_up(token):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "step-up re-verification required; POST /me/reauth then retry",
                    headers={"X-Step-Up-Required": "1"},
                )
        return identity

    return dependency


def require_reauth_only(*permissions: Permission) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require_step_up` but with **only** the password step-up — **not** the MFA gate.

    Used by the MFA *enrollment* endpoints: a user enrolling their first second factor (or a
    ``require_mfa`` administrator who has not enrolled yet) cannot satisfy an MFA gate, so a
    :func:`require_step_up` there would deadlock. Re-proving the password still defends a stolen
    session from silently enrolling an attacker-controlled authenticator (WP-14)."""
    base = require(*permissions)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None and auth.enabled:
            token = bearer_token(request)
            # Same new-client-IP contextual-risk layer as require_step_up (WP-L3-13); the MFA gate is
            # intentionally skipped here (enrollment would otherwise deadlock — see the docstring).
            new_ip = await auth.flag_new_client_ip(
                token, _client_ip(request), path=request.url.path
            )
            if new_ip or not await auth.has_recent_step_up(token):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "step-up re-verification required; POST /me/reauth then retry",
                    headers={"X-Step-Up-Required": "1"},
                )
        return identity

    return dependency


async def _action_step_up_ok(auth: AuthService, token: str | None, action: str) -> bool:
    """The step-up decision for a per-action route (ADR 0077): when action-binding is enforced
    (default), a fresh **single-use grant BOUND to** ``action`` (consumed here); when the org opted
    out (``[auth].require_action_step_up = false``), the legacy session-window recency. Split out so
    ``require_step_up_action`` and ``require_reauth_only_action`` share one place for the fallback."""
    if auth.action_step_up_required:
        return await auth.has_action_step_up(token, action)
    return await auth.has_recent_step_up(token)


def require_step_up_action(
    action: str, *permissions: Permission
) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require_step_up`, but the step-up must be a fresh proof **bound to** ``action``
    (single-use), not the shared session window (ADR 0077; ASVS 7.5.1 / 8.2.4). Keeps the MFA gate —
    used for the durable-takeover op that still requires the current second factor (**disable-MFA**): a
    hijacked session inside the login window can neither satisfy MFA it lacks nor reuse a broad window.

    On a stale/missing grant it 403s with ``X-Step-Up-Required`` **and** ``X-Step-Up-Action: <action>``,
    so the console echoes the action back as ``POST /me/reauth {"purpose": …}``. When the org opts out
    it falls back to the legacy session-window behaviour."""
    base = require(*permissions)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None and auth.enabled:
            token = bearer_token(request)
            if not await auth.mfa_satisfied(token):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "multi-factor verification required; POST /auth/mfa-verify then retry",
                    headers={"X-MFA-Required": "1"},
                )
            # `new_ip` is checked first so a short-circuit leaves the single-use grant UNCONSUMED on a
            # forced-step-up (the grant is only popped when we actually reach the action check).
            new_ip = await auth.flag_new_client_ip(
                token, _client_ip(request), path=request.url.path
            )
            if new_ip or not await _action_step_up_ok(auth, token, action):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "step-up re-verification required; POST /me/reauth then retry",
                    headers={"X-Step-Up-Required": "1", "X-Step-Up-Action": action},
                )
        return identity

    return dependency


def require_reauth_only_action(
    action: str, *permissions: Permission
) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require_reauth_only` (password step-up, **no** MFA gate) but the proof must be bound
    to ``action`` (single-use) — the action-scoped analogue for the **factor-enrollment** routes (TOTP
    enroll/confirm) a required-but-unenrolled session must still be able to reach
    (an MFA gate there would deadlock — WP-14). Re-proving the password still defends a hijacked session
    from binding an attacker authenticator, and now that proof is tied to *this* action, not the login
    window (ADR 0077). Same ``X-Step-Up-Action`` header + org opt-out as :func:`require_step_up_action`."""
    base = require(*permissions)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None and auth.enabled:
            token = bearer_token(request)
            new_ip = await auth.flag_new_client_ip(
                token, _client_ip(request), path=request.url.path
            )
            if new_ip or not await _action_step_up_ok(auth, token, action):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "step-up re-verification required; POST /me/reauth then retry",
                    headers={"X-Step-Up-Required": "1", "X-Step-Up-Action": action},
                )
        return identity

    return dependency


async def optional_identity(request: Request) -> Identity | None:
    """Best-effort caller identity that **never raises** — for read-only, non-PHI endpoints (e.g.
    ``GET /ai/policy``) that must answer even to a tokenless client, while still reporting the
    caller's RBAC when a valid token is present.

    Returns the full-access system identity when auth is disabled-with-``allow_no_auth`` (embedding/
    dev); ``None`` when auth is unconfigured/fail-closed or the token is missing/invalid. The
    ``must_change_password`` gate is intentionally *not* applied — this surfaces non-sensitive policy,
    not PHI."""
    auth = get_auth(request)
    if auth is None or not auth.enabled:
        return _SYSTEM_IDENTITY if _allow_no_auth(request.app.state) else None
    return await auth.identity_for_token(bearer_token(request))


def ws_token(websocket: WebSocket) -> str | None:
    """Extract a WebSocket bearer token from the Authorization header.

    Header-only: the legacy ``?token=`` query-string fallback was removed because a session token in
    a URL leaks into proxy/access logs and the Referer header (ASVS Session Management; API-3). The
    console already sends the token via the ``Authorization`` header."""
    header = websocket.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer ") :].strip() or None
    return None


def _ws_origin_allowed(websocket: WebSocket) -> bool:
    """Whether the WebSocket handshake's ``Origin`` is acceptable (ASVS 4.4.2).

    A native (non-browser) client like the desktop console sends **no** ``Origin`` header — that is
    allowed. A browser always sends one; it is allowed only if listed in ``[api].ws_allowed_origins``
    (default empty → every browser Origin is rejected). This blocks cross-site WebSocket hijacking
    at the handshake, before ``accept()``."""
    origin = websocket.headers.get("origin")
    if not origin:
        return True  # native client (no browser Origin) — the only shipped client
    allowed = getattr(websocket.app.state, "ws_allowed_origins", ()) or ()
    return origin in allowed


async def authorize_ws(websocket: WebSocket, *permissions: Permission) -> Identity | None:
    """Authorize a WebSocket upgrade: validate the ``Origin`` (4.4.2), then the bearer token from the
    Authorization header and the listed permissions.

    Returns the :class:`Identity` on success, or ``None`` if auth fails (caller should close).
    """
    if not _ws_origin_allowed(websocket):
        return None  # cross-site / disallowed browser Origin — reject before accept()
    auth: AuthService | None = getattr(websocket.app.state, "auth", None)
    if auth is None or not auth.enabled:
        return _SYSTEM_IDENTITY if _allow_no_auth(websocket.app.state) else None
    identity = await auth.identity_for_token(ws_token(websocket))
    if identity is None:
        return None
    if identity.must_change_password:
        return None  # a not-yet-rotated account is locked out of the WS too (mirrors require())
    for permission in permissions:
        if not identity.has(permission):
            # Audit the denial like the HTTP require() path does, so a revoked/under-privileged
            # user probing the stats feed leaves a trail too (review low-9).
            await auth.audit_permission_denied(identity, permission, websocket.url.path)
            return None
    # BACKLOG #195a (ASVS 16.3.2): audit the grant for the sensitive surface only. The shipped stats
    # feed (/ws/stats) requires MONITORING_READ, which is deliberately NOT in _GRANT_AUDIT_PERMISSIONS,
    # so a reconnecting/polling console never floods the audit chain; a future sensitive WS is audited
    # by the same rule (authorize_ws runs once per connection, not per message, so it can't flood).
    audited = _grant_audit_permission(permissions)
    if audited is not None:
        await auth.audit_permission_granted(identity, audited, websocket.url.path)
    return identity
