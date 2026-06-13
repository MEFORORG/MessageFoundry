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
from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request, WebSocket, status

from messagefoundry.auth import AuthProvider, Identity, Permission, Role
from messagefoundry.auth.service import AuthService

log = logging.getLogger(__name__)

# Identity used when auth is explicitly disabled via allow_no_auth (embedding/dev): full access.
_SYSTEM_IDENTITY = Identity.build(
    user_id="system", username="system", auth_provider=AuthProvider.LOCAL, roles=list(Role)
)

# While an account is flagged to rotate its password, only these self-service routes stay reachable.
_MUST_CHANGE_EXEMPT_PATHS = frozenset({"/auth/logout", "/auth/me", "/me/password"})


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
        return identity

    return dependency


def require_phi_read(*permissions: Permission) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require`, plus a **per-actor anti-automation throttle** for the PHI-read endpoints
    (`/messages`, `/messages/{id}`, `/dead-letters`) — bounds scripted PHI harvesting beyond the
    pagination + access-audit controls (ASVS 2.4.1). A throttled read is **logged** (not silent) and
    returns 429. No throttle on the embedding/no-auth path (there's no per-actor identity to key on)."""
    base = require(*permissions)

    async def dependency(request: Request) -> Identity:
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
    return identity
