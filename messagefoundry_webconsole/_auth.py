# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Cookie-based auth for the /ui ops dashboard, CONFINED to /ui (ADR 0065 §3).

``require_ui(*perms, phi=...)`` mirrors ``api.security.require`` / ``require_phi_read`` but reads the
``mf_session`` HttpOnly cookie **instead of** the ``Authorization`` header. It is used **only** by /ui
HTML routes. The shared ``bearer_token()`` stays header-only, so a JSON API route presented with only
the cookie still 401s (the hard boundary the security review flagged, test-enforced): the cookie is not
a JSON-API credential and SameSite is never the sole CSRF defense for the JSON API.
"""

from __future__ import annotations

import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

from fastapi import HTTPException, Request, Response, WebSocket, status

from messagefoundry.api.security import get_auth
from messagefoundry.auth import Identity, Permission

__all__ = [
    "BROWSER_HARDENING_OPT_OUT_ENV",
    "COOKIE_NAME",
    "HOST_COOKIE_NAME",
    "UI_CSP",
    "UiWriteAction",
    "assert_same_origin",
    "authorize_ui_ws",
    "browser_hardening_enabled",
    "clear_session_cookie",
    "effective_https",
    "is_safe_ui_action",
    "is_unlock_action",
    "lookup_ui_action",
    "register_ui_action",
    "require_ui",
    "require_ui_reauth_only",
    "require_ui_step_up",
    "session_cookie_name",
    "session_token",
    "set_session_cookie",
]

COOKIE_NAME = "mf_session"

#: The ``__Host-`` prefixed session cookie name, used ONLY in an effective-https context (ADR 0065
#: §hardening / BACKLOG #192, ASVS 3.4.3). A browser REJECTS a ``__Host-`` cookie unless it is Secure +
#: Path=/ + carries no Domain — all three hold here — so the prefix is a browser-enforced binding of the
#: session to THIS exact host over TLS. Over cleartext loopback the plain :data:`COOKIE_NAME` is kept
#: (byte-identity): ``__Host-`` can never be set without Secure, which cleartext cannot carry.
HOST_COOKIE_NAME = "__Host-mf_session"

#: Org opt-out for the #192 /ui browser hardening. DEFAULT is hardening ON (secure-by-default); set this
#: env truthy to REVERT the /ui surface to the pre-#192 posture — plain :data:`COOKIE_NAME` (still Secure
#: over https, so transport security is never downgraded) + the engine's static self-CSP, and no
#: per-response nonce / COOP / CSP-reporting. The escape hatch for a legacy proxy/browser that cannot
#: tolerate ``__Host-``/nonce-CSP, per the secure-by-default-with-explicit-opt-out rule.
BROWSER_HARDENING_OPT_OUT_ENV = "MEFOR_WEBCONSOLE_DISABLE_BROWSER_HARDENING"


def browser_hardening_enabled() -> bool:
    """Whether the #192 /ui browser hardening is active (default ``True``). Disabled only by an explicit
    truthy :data:`BROWSER_HARDENING_OPT_OUT_ENV`."""
    return os.environ.get(BROWSER_HARDENING_OPT_OUT_ENV, "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    )


def effective_https(app_state: object, scheme: str) -> bool:
    """Whether this connection is an EFFECTIVE-https context — the single signal the cookie name +
    Secure flag + the /ui security-header hardening all key on (ADR 0065 §hardening / #192).

    Mirrors the engine's ``api.app._cookie_secure`` decision READ-ONLY: the per-request/handshake scheme
    is https/wss, OR the operator declared the browser-facing scheme https via
    ``app.state.exposure_protected`` (set once in ``create_app`` — the proxy-TLS case where a request
    that omits ``X-Forwarded-Proto`` would otherwise read as cleartext). Reads only the public
    ``app.state`` attribute the engine already exposes; imports no engine module.
    """
    return scheme in ("https", "wss") or bool(getattr(app_state, "exposure_protected", False))


def session_cookie_name(conn: Request | WebSocket) -> str:
    """The session cookie name for this connection: ``__Host-mf_session`` in an effective-https context
    (unless the org opt-out is set), else the plain ``mf_session`` (unchanged over cleartext loopback —
    byte-identity). The ONE resolver every set/clear/read site threads through, so the name a response
    writes and the name a later request reads always agree."""
    if effective_https(conn.app.state, conn.url.scheme) and browser_hardening_enabled():
        return HOST_COOKIE_NAME
    return COOKIE_NAME


def session_token(conn: Request | WebSocket) -> str | None:
    """Read the session token from whichever cookie name applies to this connection's scheme."""
    return conn.cookies.get(session_cookie_name(conn))


# Strict, self-only CSP for the /ui surface — no 'unsafe-eval'/'unsafe-inline' (ADR 0065 §5). The only
# script is the first-party /ui/static/app.js (no inline script, no on* handlers), so 'self' suffices.
# Everything (script/style/font/img) is served from /ui/static, same origin.
UI_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'; object-src 'none'"
)

# Sec-Fetch-Site values that mean the request did NOT originate from our own origin — rejected on
# state-changing /ui POSTs (M2). "same-site" (a sibling subdomain) is rejected too: /ui is strictly
# same-origin. "same-origin" and "none" (a user-initiated navigation) are allowed.
_CROSS_ORIGIN_FETCH = frozenset({"cross-site", "same-site"})


def _login_redirect(note: str = "") -> HTTPException:
    """A 303 redirect (as an exception, to short-circuit a dependency) to the /ui login page."""
    location = "/ui/login" + (f"?e={note}" if note else "")
    return HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": location})


def require_ui(
    *permissions: Permission, phi: bool = False, allow_must_change: bool = False
) -> Callable[[Request], Awaitable[Identity]]:
    """Authenticate a /ui request from the session cookie and assert ``permissions``.

    ``phi=True`` also applies the same per-actor anti-automation throttle as ``require_phi_read`` (the
    /ui PHI views call the JSON handlers directly, which skips their own ``Depends`` gate, so this
    dependency must re-apply the equivalent permission + throttle — otherwise a cookie session could
    read PHI it lacks the permission/quota for). Unauthenticated/expired → 303 to the login page;
    forbidden → 403; throttled → 429.

    A ``must_change_password`` account is 303'd to the browser change-password page (L4b) from every
    /ui route — ``allow_must_change=True`` is set ONLY by that page's own GET/POST (so the rotation
    can actually happen; anything else would loop).
    """

    async def dependency(request: Request) -> Identity:
        auth = get_auth(request)
        if auth is None or not auth.enabled:
            # The browser UI always needs a real session — no allow_no_auth shortcut here.
            raise _login_redirect()
        identity = await auth.identity_for_token(session_token(request))
        if identity is None:
            raise _login_redirect()
        if identity.must_change_password and not allow_must_change:
            # A flagged account can go nowhere but the change-password page (L4b) until it rotates.
            raise HTTPException(
                status.HTTP_303_SEE_OTHER, headers={"Location": "/ui/account/password"}
            )
        for permission in permissions:
            if not identity.has(permission):
                await auth.audit_permission_denied(identity, permission, request.url.path)
                raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
        if phi and not auth.allow_phi_read(identity.user_id):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "too many requests; please slow down",
                headers={"Retry-After": "10"},
            )
        return identity

    return dependency


def _origin_matches(app_state: object, origin: str, host: str | None) -> bool:
    """Whether the browser ``Origin`` is our own origin (ADR 0065 off-loopback defaults).

    When ``[api].public_origin`` is configured — the off-loopback case, behind a reverse proxy that may
    not preserve ``Host`` — it is **authoritative** (exact, normalized match). Otherwise (loopback, or a
    Host-preserving proxy) fall back to comparing the ``Origin`` host[:port] to the request ``Host``.
    """
    public_origin: str | None = getattr(app_state, "public_origin", None)
    if public_origin:
        # Scheme + host are case-INSENSITIVE (RFC 6454 §4 / RFC 3986 §3.2.2). Canonicalize the incoming
        # Origin the same way the validator canonicalizes public_origin (lowercased), so a case variant
        # is treated as the same origin — fail-closed either way, but this avoids rejecting a legit
        # browser (browsers lowercase the host) or a mixed-case configured public_origin.
        parts = urlsplit(origin)
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}" == public_origin
    return host is not None and urlsplit(origin).netloc.lower() == host.lower()


def assert_same_origin(request: Request) -> None:
    """Reject a cross-site state-changing /ui request — CSRF defense-in-depth (M2, ADR 0065 §M2).

    The **primary** CSRF defense is the SameSite=Strict session cookie: a cross-site POST carries no
    ``mf_session`` cookie, so ``require_ui`` already fails it (303 to login) before any action runs.
    This adds an explicit origin check on top: modern browsers send ``Sec-Fetch-Site`` on every request
    (reject ``cross-site``/``same-site``); for older clients that omit it, fall back to comparing the
    ``Origin`` to our own origin (``[api].public_origin`` when set, else the request ``Host``). A
    same-origin form POST (the only way the /ui buttons submit) passes both. Token-free — so it needs no
    crypto import (avoids the ASVS 11.1.3 inventory gate).
    """
    sec_fetch_site = request.headers.get("sec-fetch-site")
    if sec_fetch_site is not None:
        if sec_fetch_site in _CROSS_ORIGIN_FETCH:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "cross-site request rejected")
        return
    origin = request.headers.get("origin")
    if origin and not _origin_matches(request.app.state, origin, request.headers.get("host")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cross-origin request rejected")


@dataclass(frozen=True, slots=True)
class UiWriteAction:
    """One registered state-changing /ui action (ADR 0065 §multi-session-build): the anchored path
    pattern it is served at, the RBAC permission it needs, whether it requires a fresh step-up, and how
    the step-up re-auth flow hands control back to it after a successful re-verification.

    Exactly one continuation style applies:

    * ``auto_retry`` — a URL-complete, **body-less POST** the re-auth flow may **re-POST** (auto-submit)
      once the window is fresh (replay, purge, config-reload). The re-POST carries no body, so every
      parameter must live in the PATH.
    * ``unlock`` — a **GET form page** (L4a admin forms) the re-auth flow may **303-GET-redirect** to
      after step-up, so the form re-opens inside a fresh window and the operator submits the body-carrying
      POST (incl. a create-user password) in a single request that never crosses ``/ui/reauth``. This is
      the stateless confirm-after-step-up primitive: no body — and no password — is ever preserved across
      the redirect.

    The two are mutually exclusive (``__post_init__`` enforces it): a GET page must never be auto-POSTed,
    and a POST action must never be GET-redirected to.
    """

    path_re: re.Pattern[str]
    # None = a self-scoped account action (L4b): any authenticated session may continue it after
    # re-auth — there is no RBAC permission beyond holding a valid (re-verified) session. The field is
    # descriptive either way: enforcement lives in each route's require_ui* dependency, and the
    # continuation gates (is_safe_ui_action / is_unlock_action) match on pattern + flags only.
    permission: Permission | None
    step_up: bool = True
    auto_retry: bool = True
    unlock: bool = False

    def __post_init__(self) -> None:
        # Guard against a mis-registration that would let the re-auth flow POST-auto-submit a GET form
        # page (or GET-redirect to a state-changing POST): the continuation branch keys off these flags.
        if self.auto_retry and self.unlock:
            raise ValueError("a /ui action cannot be both auto_retry (POST) and unlock (GET)")


# The write-action registry — the extensible replacement for the former single ``_SAFE_UI_ACTION_RE``
# literal. A write-page lane registers its action (co-located with its route, or here) instead of editing
# a central allow-list, so parallel lanes never collide. This is also the ONLY source of truth for which
# actions the step-up re-auth flow may hand control back to (see ``is_safe_ui_action``): the gate that
# stops the re-auth becoming an open POST/redirect gadget.
_UI_WRITE_ACTIONS: list[UiWriteAction] = []


def register_ui_action(
    pattern: str,
    permission: Permission | None,
    *,
    step_up: bool = True,
    auto_retry: bool = True,
    unlock: bool = False,
) -> UiWriteAction:
    """Register a state-changing /ui action into the write-action registry. Idempotent by ``pattern``.

    ``pattern`` MUST be a fully-anchored regex for the exact path (e.g. ``r"^/ui/alerts/[^/?#]+/ack$"``).
    ``auto_retry`` entries are the only paths the step-up re-auth may **re-POST** — keep it ``True`` only
    for body-less actions whose params all live in the PATH. ``unlock`` entries are **GET form pages** the
    re-auth may **303-GET-redirect** to after step-up (the confirm-after-step-up primitive for
    body-carrying admin forms); register those as ``auto_retry=False, unlock=True`` (the two are mutually
    exclusive — :class:`UiWriteAction` rejects both).
    """
    action = UiWriteAction(re.compile(pattern), permission, step_up, auto_retry, unlock)
    if not any(a.path_re.pattern == action.path_re.pattern for a in _UI_WRITE_ACTIONS):
        _UI_WRITE_ACTIONS.append(action)
    return action


# Phase-0 replay actions (migrated verbatim from the former _SAFE_UI_ACTION_RE): a single message, all
# dead deliveries for one channel, or the dead deliveries for one (channel, destination). All params are
# in the PATH (opaque ids / channel + destination names, each a single slash/query/fragment-free
# segment), so the body-less auto-retry re-POST carries everything it needs.
register_ui_action(r"^/ui/messages/[^/?#]+/replay$", Permission.MESSAGES_REPLAY)
register_ui_action(r"^/ui/dead-letters/[^/?#]+(/[^/?#]+)?/replay$", Permission.MESSAGES_REPLAY)
# L6b (#75 parity): replay ALL dead deliveries across EVERY channel — a body-less step-up POST, so
# the /ui/reauth flow may auto-retry it. The literal `replay-all` segment is NOT matched by the
# per-channel pattern above (it has no `/replay` suffix), so it needs its own allow-list entry.
register_ui_action(r"^/ui/dead-letters/replay-all$", Permission.MESSAGES_REPLAY)


def is_safe_ui_action(next_path: str | None) -> bool:
    """Whether ``next_path`` is a same-origin /ui action the re-auth flow may auto-retry.

    Rejects any ``..`` outright: a segment like ``CH/..`` is normalized by the browser before the POST, so
    it must never be treated as a valid retry target (defense-in-depth over the anchored patterns). Then
    scans the write-action registry for an ``auto_retry`` entry whose anchored pattern fully matches — so a
    write-page lane extends the allow-list by *registering* its action, never by editing this function.
    """
    if not next_path or ".." in next_path:
        return False
    return any(
        action.auto_retry and action.path_re.fullmatch(next_path) for action in _UI_WRITE_ACTIONS
    )


def lookup_ui_action(next_path: str | None) -> UiWriteAction | None:
    """The registered continuation action ``next_path`` resolves to (auto_retry OR unlock), or None.

    Used by the /ui/reauth flow to read an action's metadata — notably ``step_up``: a ``step_up=False``
    continuation is password-only (require_ui_reauth_only, e.g. MFA enrollment), so a required-but-
    unenrolled session can complete it; a ``step_up=True`` continuation needs the full step-up (MFA
    leg), which such a session can NEVER satisfy — the flow sends it to enroll instead of looping. Same
    ``..`` guard as the boolean gates.
    """
    if not next_path or ".." in next_path:
        return None
    for action in _UI_WRITE_ACTIONS:
        if (action.auto_retry or action.unlock) and action.path_re.fullmatch(next_path):
            return action
    return None


def is_unlock_action(next_path: str | None) -> bool:
    """Whether ``next_path`` is a registered /ui **GET form page** the re-auth may 303-GET-redirect to.

    The GET analogue of :func:`is_safe_ui_action`: it gates the confirm-after-step-up primitive so the
    re-auth flow can only redirect back to a form page a lane explicitly registered (``unlock=True``),
    never to an arbitrary URL. Same ``..`` rejection (a normalized ``/..`` segment is never a valid
    target) and same append-only registry as the only source of truth — a lane opts a form page in by
    *registering* it, not by editing this function.
    """
    if not next_path or ".." in next_path:
        return False
    return any(
        action.unlock and action.path_re.fullmatch(next_path) for action in _UI_WRITE_ACTIONS
    )


def _reauth_redirect(request: Request, next_path: str | None = None) -> HTTPException:
    """303 a browser to the /ui re-auth page, remembering the action to continue with.

    ``next_path`` (when given) overrides the default of this request's own path — used by body-carrying
    POST actions to point the re-auth at their **unlock form page** instead of the POST path (which is
    deliberately not a registered continuation). Either way the value is only ever *acted on* after
    ``/ui/reauth`` re-validates it against the write-action registry, so a bad override fails closed.
    """
    nxt = quote(next_path if next_path is not None else request.url.path, safe="/")
    return HTTPException(status.HTTP_303_SEE_OTHER, headers={"Location": f"/ui/reauth?next={nxt}"})


def require_ui_step_up(
    *permissions: Permission,
    reauth_next: Callable[[Request], str] | None = None,
) -> Callable[[Request], Awaitable[Identity]]:
    """Authenticate a /ui request, assert ``permissions``, AND require a fresh step-up — the cookie-world
    analogue of ``api.security.require_step_up`` for sensitive /ui actions (replay).

    The /ui action routes call the JSON handlers directly, which SKIPS the handler's own
    ``require_step_up`` gate — so this dependency re-applies the exact same checks (MFA satisfied +
    recent password step-up + new-client-IP contextual risk) that ``require_step_up`` does. The only
    difference is the *response*: instead of a 403 with ``X-MFA-Required``/``X-Step-Up-Required`` (which
    a browser can't act on), it **redirects** to the /ui re-auth page carrying ``next=<this action>`` so
    the browser can re-authenticate and auto-retry.

    ``reauth_next`` overrides *which* continuation the re-auth page is pointed at. A **body-carrying**
    POST (create-user, set-roles) cannot be auto-retried (the re-POST would carry no body) and its POST
    path is deliberately not a registered continuation — so it maps the redirect to its **unlock form
    page** (e.g. ``POST /ui/users`` → ``/ui/users/new``): after re-verification the browser is GET-
    redirected to the form, which re-opens inside a fresh window for a clean re-submit. The mapped value
    gets no trust: ``/ui/reauth`` still validates it against the write-action registry (fail-closed).
    """
    base = require_ui(*permissions)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)  # cookie auth + permission (+ must-change gate)
        auth = get_auth(request)
        if auth is None or not auth.enabled:  # pragma: no cover - base already handled this
            raise _login_redirect()
        token = session_token(request)
        nxt = reauth_next(request) if reauth_next is not None else None
        # Second factor first (mirrors require_step_up): an MFA-required session must have verified TOTP.
        if not await auth.mfa_satisfied(token):
            raise _reauth_redirect(request, nxt)
        # Contextual risk + password step-up window: a new client IP or a stale window forces re-auth.
        client = request.client.host if request.client else None
        new_ip = await auth.flag_new_client_ip(token, client, path=request.url.path)
        if new_ip or not await auth.has_recent_step_up(token):
            raise _reauth_redirect(request, nxt)
        return identity

    return dependency


def require_ui_reauth_only(
    *permissions: Permission,
    reauth_next: Callable[[Request], str] | None = None,
) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require_ui_step_up` but with **only** the password step-up — **not** the MFA gate;
    the cookie-world analogue of ``api.security.require_reauth_only``.

    Used by the browser MFA *enrollment* routes (L4b): a user enrolling their first second factor (or
    a ``require_mfa`` account that has not enrolled yet) cannot satisfy an MFA gate, so
    ``require_ui_step_up`` there would deadlock. Re-proving the password still defends a stolen cookie
    session from silently enrolling an attacker-controlled authenticator (WP-14). Same contextual
    new-client-IP layer; a stale window 303s to /ui/reauth (which only asks for a TOTP code when one
    is actually enrolled).
    """
    base = require_ui(*permissions)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)  # cookie auth + permission (+ must-change gate)
        auth = get_auth(request)
        if auth is None or not auth.enabled:  # pragma: no cover - base already handled this
            raise _login_redirect()
        token = session_token(request)
        client = request.client.host if request.client else None
        new_ip = await auth.flag_new_client_ip(token, client, path=request.url.path)
        if new_ip or not await auth.has_recent_step_up(token):
            raise _reauth_redirect(
                request, reauth_next(request) if reauth_next is not None else None
            )
        return identity

    return dependency


async def authorize_ui_ws(
    websocket: WebSocket, *permissions: Permission
) -> tuple[Identity | None, str | None]:
    """Authorize a **same-origin browser** WebSocket handshake via the ``mf_session`` cookie.

    Browsers cannot set the ``Authorization`` header on a WebSocket handshake (and the ``?token=`` query
    fallback was removed for ASVS), so the browser's only header-free credential is the cookie the
    handshake carries. Returns ``(identity, token)`` for an authorized same-origin browser, else
    ``(None, None)`` — the caller then falls back to the native (header) ``authorize_ws`` path.

    **CSWSH defense (two independent layers):** (1) the handshake ``Origin`` must be same-origin as the
    ``Host`` — a cross-site page's WS is rejected here; (2) ``mf_session`` is ``SameSite=Strict``, so a
    cross-site-initiated handshake carries **no** cookie at all. A native client sends no ``Origin``, so
    this returns ``(None, None)`` and does not interfere with the header path.
    """
    origin = websocket.headers.get("origin")
    if not origin:
        return None, None  # native client (no Origin) — the header path handles it
    if not _origin_matches(websocket.app.state, origin, websocket.headers.get("host")):
        return None, None  # cross-origin browser handshake (CSWSH) — reject
    token = session_token(websocket)
    if not token:
        return None, None
    auth = getattr(websocket.app.state, "auth", None)
    if auth is None or not auth.enabled:
        return None, None
    identity = await auth.identity_for_token(token)
    if identity is None or identity.must_change_password:
        return None, None
    for permission in permissions:
        if not identity.has(permission):
            return None, None
    return identity, token


def set_session_cookie(response: Response, token: str, *, request: Request) -> None:
    """Set the confined session cookie: HttpOnly + SameSite=Strict, Path=/, and — in an effective-https
    context (and unless the org opt-out is set) — the ``__Host-`` prefixed name (ADR 0065 §hardening /
    #192, ASVS 3.4.3). Secure is ALWAYS set when the effective scheme is https, even under the opt-out
    (transport security is never downgraded). Over cleartext loopback this is byte-identical to the
    pre-#192 cookie (``mf_session``, no Secure). Path=/ (not /ui) so a future same-origin WebSocket
    handshake at the root can carry it (M2); the cookie is only ever *read* by ``require_ui`` on /ui
    routes, never by the JSON API deps.
    """
    secure = effective_https(request.app.state, request.url.scheme)
    name = HOST_COOKIE_NAME if (secure and browser_hardening_enabled()) else COOKIE_NAME
    response.set_cookie(
        name,
        token,
        httponly=True,
        samesite="strict",
        secure=secure,
        path="/",
    )


def clear_session_cookie(response: Response, request: Request) -> None:
    """Delete the session cookie (logout). Pairs with a server-side ``AuthService.logout`` revoke.

    Deletes whichever name this scheme uses (:func:`session_cookie_name`). Over cleartext loopback this
    stays byte-identical to the pre-#192 clear (``delete_cookie(COOKIE_NAME, path="/")``); the
    ``__Host-`` deletion additionally carries Secure so the browser accepts the expiry (a ``__Host-``
    cookie is only writable — expiry included — over a Secure connection)."""
    name = session_cookie_name(request)
    if name == COOKIE_NAME:
        response.delete_cookie(COOKIE_NAME, path="/")
    else:
        response.delete_cookie(name, path="/", secure=True, httponly=True, samesite="strict")


# --- L5a: WebAuthn RP identity (ADR 0068 §7) --------------------------------------

#: Legible fail-closed copy, shared by every affected surface (account page, enroll flow, reauth
#: page) so the operator sees ONE consistent message + recovery path — never a redirect loop.
WEBAUTHN_RP_MISSING_NOTICE = (
    "Passkeys are unavailable: [api].public_origin is not set — contact your administrator."
)
WEBAUTHN_EXTRA_MISSING_NOTICE = (
    "Passkeys are unavailable on this install (the [webauthn] extra is not installed) — "
    "contact your administrator."
)
WEBAUTHN_RP_CHANGED_NOTICE = (
    "Your passkeys were enrolled under a different origin and are unusable here — contact your "
    "administrator to reset your MFA so you can re-enroll."
)


def webauthn_rp(request: Request) -> tuple[str, str] | None:
    """The WebAuthn RP identity for this deployment: ``(rp_id, expected_origin)`` or ``None``.

    ``[api].public_origin`` is AUTHORITATIVE when set (it is already the validated, normalized
    origin the /ui CSRF + CSWSH checks match against — never a second origin knob). Unset, the
    request URL is used ONLY when ``create_app`` marked request-derivation safe (loopback bind
    with no reverse proxy declared — the browser connected directly, so the request Host is what
    it actually used, not proxy-rewritable). Anywhere else this returns ``None`` and ceremonies
    FAIL CLOSED: behind a declared proxy the Host header is client-forwardable, and anchoring the
    rp_id to it would defeat exactly the phishing resistance WebAuthn exists to add (the red-team
    CRITICAL repair — keyed on the proxy declaration, never the bind host alone).
    """
    public_origin = getattr(request.app.state, "public_origin", None)
    if public_origin:
        host = urlsplit(public_origin).hostname
        return (host, public_origin) if host else None
    if getattr(request.app.state, "webauthn_rp_from_request", False):
        host = request.url.hostname
        if not host:
            return None
        return (host, f"{request.url.scheme}://{request.url.netloc}")
    return None
